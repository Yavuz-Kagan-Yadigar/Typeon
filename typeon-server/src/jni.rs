//! Android sunucu uygulamasının JNI kabuğu.
//!
//! Sadece `cfg(target_os = "android")` altında derlenir; Linux daemon'ı
//! (`src/bin/typeon-server.rs`) bu dosyaya hiç dokunmaz.
//!
//! ## Mimari
//!
//! `ServerCore` kendi tokio görevinde `run()` içinde döner. Arayüz saniyede
//! bir durum sorar — `ServerCore`'a kilit koymak döngüyü durdururdu, bu
//! yüzden döngü her turda ucuz bir anlık görüntü (`ServerShared`) tazeliyor
//! ve arayüz onu okuyor.
//!
//! Yönetim işlemleri (davet üret, cihaz listele/iptal et) veritabanına
//! AYRI bir bağlantıyla erişir. SQLite WAL modunda birden fazla bağlantıyı
//! sorunsuz destekliyor (bkz. `Store::open`), dolayısıyla ana döngüyü hiç
//! bloklamadan çalışıyorlar.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring};
use jni::JNIEnv;
use log::info;

use crate::{now_ms, CoreSignal, ServerConfig, ServerCore, ServerShared};
use crate::store::{EnrollmentState, Store};

struct Control {
    shared: Arc<ServerShared>,
    /// Yönetim işlemleri için AYRI bağlantı — bkz. modül notu.
    store: Store,
    data_dir: PathBuf,
    /// Defter #24: blob'lar harici bir birimde olabilir (`startServer`
    /// `blobDir` parametresi) — disk kullanımı bu dizini de saymalı.
    blob_dir: PathBuf,
    /// Defter #11: `stopServer` bunu tetikleyerek `run_until`'ı sonlandırır.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// bkz. `ServerCore::set_net_changed_rx` — `notifyNetworkChanged` bunu iter.
    net_changed: tokio::sync::mpsc::UnboundedSender<CoreSignal>,
}

lazy_static::lazy_static! {
    static ref RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    static ref CONTROL: Mutex<Option<Control>> = Mutex::new(None);
    /// Held for the whole of `startServer` and `stopServer`. Without it two
    /// starts both passed the `CONTROL` check (the second one, Tor-less,
    /// replaced the working server), and a stop during a start was a no-op.
    static ref START_STOP: Mutex<()> = Mutex::new(());
    /// The loop task of the last started server. `stopServer` only signals it;
    /// the next `startServer` waits for it to end.
    static ref LAST_RUN: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);
}

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|v| v.into()).unwrap_or_default()
}

fn out(env: &mut JNIEnv, s: String) -> jstring {
    env.new_string(s).map(|v| v.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// Sunucuyu başlatır. Yeniden çağrılırsa no-op (foreground service
/// `START_STICKY` ile yeniden başlatılabiliyor).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_startServer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data_dir: JString<'local>,
    node_mode: jboolean,
    name: JString<'local>,
    storage_budget_bytes: jni::sys::jlong,
    blob_dir: JString<'local>,
) -> jstring {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("TypeonServer"),
    );

    let dir = jstr(&mut env, &data_dir);
    let server_name = jstr(&mut env, &name);
    let node = node_mode != 0;

    let _serial = START_STOP.lock().unwrap_or_else(|p| p.into_inner());
    {
        let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_some() {
            let peer = guard.as_ref().and_then(|c| c.shared.peer_id.lock().ok().map(|p| p.clone()));
            return out(&mut env, peer.unwrap_or_default());
        }
    }

    let mut config = ServerConfig::new(PathBuf::from(&dir));
    config.node_mode = node;
    // Yalnızca BLOBLAR taşınabilir; kimlik ve Tor durumu dahilide kalır
    // (bkz. `ServerConfig.blob_dir`).
    let blobs = jstr(&mut env, &blob_dir);
    if !blobs.is_empty() {
        config.blob_dir = PathBuf::from(&blobs);
    }
    // Kotaları cihazın GERÇEK boş alanından türet.
    //
    // Varsayılanlar bir VPS için yazılmıştı: kayıt BAŞINA 256 MB posta +
    // 1 GB arşiv + 4 GB blob. Beş cihazla 26 GB eder ve gerçekten oldu —
    // testte tabletin 22 GB'lık diski doldu, sunucu 751 MB biriktirdi,
    // yeni bir APK bile kurulamadı (`INSTALL_FAILED_INSUFFICIENT_STORAGE`).
    // Telefonda sunucunun kendi diskini yiyip cihazı kullanılamaz hâle
    // getirmesi kabul edilemez.
    if storage_budget_bytes > 0 {
        let budget = storage_budget_bytes as u64;
        // Bu denetimde bulundu: `ServerConfig.total_storage_budget_bytes`
        // yazılmış, `handle_blob_put`/`handle_authenticated` tarafından
        // okunuyor — ama HİÇBİR yerde SET EDİLMİYORDU (`ServerConfig::new`
        // `None` bırakıyor, ne burası ne de headless daemon dolduruyordu).
        // Yani defter #23'ün kurduğu TOPLAM tavan tamamen ölüydü ve
        // yalnızca kayıt BAŞINA kotalar uygulanıyordu — yani tam olarak o
        // maddenin düzeltmek için yazıldığı hata (8 yerine 20 cihaz
        // kaydolduğunda gerçek tavan bütçenin 2,5 katına çıkıyor) hâlâ
        // yürürlükteydi.
        config.total_storage_budget_bytes = Some(budget);
        // Bütçe, beklenen kayıt sayısına bölünür; biri diğerlerinin payını
        // yiyemesin. Bölüşüm kabaca kullanım oranına göre: bloblar en
        // hacimli, posta en küçük.
        const EXPECTED_DEVICES: u64 = 8;
        let per_device = (budget / EXPECTED_DEVICES).max(8 * 1024 * 1024);
        config.limits.max_blob_bytes = per_device * 6 / 10;
        config.limits.max_archive_bytes = per_device * 3 / 10;
        config.limits.max_mail_bytes = per_device / 10;
        info!(
            "Disk bütçesi {} MB — cihaz başına kota: blob {} MB, arşiv {} MB, posta {} MB",
            budget / (1024 * 1024),
            config.limits.max_blob_bytes / (1024 * 1024),
            config.limits.max_archive_bytes / (1024 * 1024),
            config.limits.max_mail_bytes / (1024 * 1024)
        );
    }
    if !server_name.is_empty() {
        config.server_name = server_name;
    }

    let _guard = RUNTIME.enter();
    // Found on device (2026-09-18): toggling the relay/DHT switch restarts the
    // server 600 ms after `stopServer`, which only signals the old loop. The old
    // arti client still held its state lock, so the new one failed with "Onion
    // service başlatılamadı: local resource (port, lockfile, etc.) already in use"
    // and the server had no address until toggled again. Wait for the old loop
    // (and the Tor client it owns) to be dropped first.
    let previous = LAST_RUN.lock().unwrap_or_else(|p| p.into_inner()).take();
    if let Some(handle) = previous {
        if RUNTIME.block_on(tokio::time::timeout(std::time::Duration::from_secs(20), handle)).is_err() {
            log::warn!("Önceki sunucu döngüsü 20 sn içinde kapanmadı, yine de başlatılıyor");
        }
    }
    let mut core = match ServerCore::new(config.clone()) {
        Ok(c) => c,
        Err(e) => return out(&mut env, format!("Error: {e}")),
    };
    let shared = Arc::new(ServerShared::default());
    core.attach_shared(shared.clone());
    let peer_id = core.local_peer_id().to_string();

    let store = match Store::open(&PathBuf::from(&dir).join("typeon_server.db")) {
        Ok(s) => s,
        Err(e) => return out(&mut env, format!("Error: {e}")),
    };

    let blob_dir = config.blob_dir.clone();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let (net_tx, net_rx) = tokio::sync::mpsc::unbounded_channel::<CoreSignal>();
    core.set_net_changed_rx(net_rx);
    // `run_until` consumes the core: when it returns, the Tor client is dropped.
    let handle = RUNTIME.spawn(async move {
        // `oneshot` gönderen düşerse de sonlanır — kanal hatası da bir
        // kapatma sinyali sayılır.
        if let Err(e) = core.run_until(async { let _ = stop_rx.await; }).await {
            log::error!("Sunucu döngüsü durdu: {e}");
        }
        log::info!("Sunucu döngüsü sonlandı.");
    });
    *LAST_RUN.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);

    *CONTROL.lock().unwrap_or_else(|p| p.into_inner()) = Some(Control {
        shared,
        store,
        data_dir: PathBuf::from(dir),
        blob_dir,
        shutdown: Some(stop_tx),
        net_changed: net_tx,
    });
    out(&mut env, peer_id)
}

/// Ağ arayüzü değiştiğinde (Wi-Fi kopup gelme, hücresele geçiş) çağrılır —
/// bkz. `ServerService` `ConnectivityManager` geri çağrısı. Çekirdek
/// çalışmıyorsa no-op.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_notifyNetworkChanged<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(c) = guard.as_ref() {
        let _ = c.net_changed.send(CoreSignal::NetworkChanged);
    }
}

/// Sunucuyu GERÇEKTEN durdurur (defter #11) — `run_until`'ı sonlandırır ve
/// `CONTROL`'ü boşaltır. Bundan sonraki `startServer` çağrısı TEMİZ bir
/// kurulum yapar, yani node modu / blob dizini / disk bütçesi değişiklikleri
/// nihayet uygulanabiliyor (önceden `startServer` çalışan bir çekirdek
/// varken no-op olduğu için süreç öldürülmeden hiçbiri etkili olmuyordu).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_stopServer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let _serial = START_STOP.lock().unwrap_or_else(|p| p.into_inner());
    let taken = CONTROL.lock().unwrap_or_else(|p| p.into_inner()).take();
    if let Some(tx) = taken.and_then(|mut control| control.shutdown.take()) {
        let _ = tx.send(());
    }
    // Wait until the loop has really ended: the caller may move or delete the
    // blob files next. On a timeout the handle stays for `startServer`.
    // `LAST_RUN` is not held across the wait: `serverStatus` locks it too.
    let running = LAST_RUN.lock().unwrap_or_else(|p| p.into_inner()).take();
    if let Some(mut handle) = running {
        if RUNTIME.block_on(tokio::time::timeout(std::time::Duration::from_secs(20), &mut handle)).is_err() {
            log::warn!("Sunucu döngüsü 20 sn içinde kapanmadı");
            *LAST_RUN.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
        }
    }
    info!("Sunucu durduruldu (JNI).");
    out(&mut env, "OK".to_string())
}

/// Arayüzün saniyede bir çektiği durum. `{peer_id, tor, addresses, stats}`
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_serverStatus<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    // The loop task ended on its own (a panic is swallowed by tokio): report
    // it and clear the state, so the next `startServer` is not a no-op.
    let dead = LAST_RUN.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map_or(false, |h| h.is_finished());
    let mut guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
    if dead {
        guard.take();
    }
    let Some(control) = guard.as_ref() else {
        return out(&mut env, r#"{"running":false}"#.to_string());
    };
    let peer_id = control.shared.peer_id.lock().map(|p| p.clone()).unwrap_or_default();
    let tor = control.shared.tor_status.lock().map(|p| p.clone()).unwrap_or_default();
    // Özel ağ adresleri koda GİRMEZ (bkz. `ServerCore::invite_addrs`) —
    // başka bir ağdaki alıcı için ulaşılamazlar ve iç ağ yapısını sızdırırlar.
    let addrs: Vec<String> = control
        .shared
        .addrs
        .lock()
        .map(|a| a.iter().filter(|x| !crate::is_private_multiaddr(x)).cloned().collect())
        .unwrap_or_default();
    let stats = control.shared.stats.lock().map(|s| s.clone()).unwrap_or_default();
    // Active ones: a revoked device stays in the list (dimmed, so it can
    // still be blocked) but is not a device of this server any more.
    let devices = control.store.list_enrollments().iter().filter(|e| e.state != EnrollmentState::Revoked).count();
    let json = serde_json::json!({
        "running": true,
        "peer_id": peer_id,
        "tor": tor,
        "addresses": addrs,
        "devices": devices,
        "deposits": stats.deposits,
        "fetches": stats.fetches,
        "archive_puts": stats.archive_puts,
        "chunks_served": stats.blob_chunks_served,
        "rejected": stats.rejected,
    });
    drop(guard);
    out(&mut env, json.to_string())
}

/// Sunucunun KALICI katılım kodu — bir kez yayımlanır, sınırsız kişi
/// katılır (bkz. `ServerCore::join_code`). `rotate = true` ise eski kod
/// geçersizleşir ve yenisi döner.
///
/// Neden `ServerCore::join_code` doğrudan çağrılmıyor: `ServerCore` ağ
/// görevinin İÇİNDE, JNI tarafında yalnızca `shared` + `store` görünür.
/// Adres filtresi (`is_private_multiaddr`) bu yüzden burada TEKRARLANIYOR —
/// bkz. `ServerCore::invite_addrs`: özel ağ adresleri koda girmez, çünkü
/// başka bir ağdaki alıcı için ulaşılamazlar ve iç ağ yapısını sızdırırlar.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_joinCode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    rotate: jni::sys::jboolean,
) -> jstring {
    let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(control) = guard.as_ref() else {
        return out(&mut env, "Error: sunucu çalışmıyor".to_string());
    };
    let addrs: Vec<String> = control
        .shared
        .addrs
        .lock()
        .map(|a| a.iter().filter(|x| !crate::is_private_multiaddr(x)).cloned().collect())
        .unwrap_or_default();
    if addrs.is_empty() {
        return out(
            &mut env,
            "Error: sunucunun henüz ulaşılabilir bir adresi yok (Tor açılıyor olabilir)".to_string(),
        );
    }
    match crate::public_join_token(&control.store, rotate != 0) {
        Ok(token) => {
            let code = p2p_messenger::server_proto::format_server_invite(&addrs, &token);
            drop(guard);
            out(&mut env, code)
        }
        Err(e) => out(&mut env, format!("Error: {e}")),
    }
}

/// `[{enrollment_id, peer_id, state, bytes_mail, bytes_archive, bytes_blob}]`
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_listDevices<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(control) = guard.as_ref() else {
        return out(&mut env, "[]".to_string());
    };
    let arr: Vec<serde_json::Value> = control
        .store
        .list_enrollments()
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "enrollment_id": hex::encode(&e.enrollment_id),
                "peer_id": e.peer_id,
                "revoked": e.state == EnrollmentState::Revoked,
                "blocked": control.store.is_key_blocked(&e.enroll_pk),
                "bytes_mail": e.bytes_mail,
                "bytes_archive": e.bytes_archive,
                "bytes_blob": e.bytes_blob,
            })
        })
        .collect();
    let json = serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string());
    drop(guard);
    out(&mut env, json)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_revokeDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    enrollment_id: JString<'local>,
) -> jstring {
    let id_hex = jstr(&mut env, &enrollment_id);
    let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(control) = guard.as_ref() else {
        return out(&mut env, "Error: sunucu çalışmıyor".to_string());
    };
    let Ok(id) = hex::decode(&id_hex) else {
        return out(&mut env, "Error: geçersiz kimlik".to_string());
    };
    let res = control.store.revoke_enrollment(&id);
    let _ = control.net_changed.send(CoreSignal::EnrollmentsChanged);
    drop(guard);
    match res {
        Ok(()) => out(&mut env, "OK".to_string()),
        Err(e) => out(&mut env, format!("Error: {e}")),
    }
}

/// Disk kullanımı (bayt) — arayüzdeki depolama satırı için.
/// Bir kaydı ENGELLER: iptalden farklı olarak kayıt ANAHTARINA konur, yani
/// o cihaz taze bir davetle bile geri dönemez (bkz. `Store::block_enrollment_key`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_blockDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    enrollment_id: JString<'local>,
) -> jstring {
    let id_hex = jstr(&mut env, &enrollment_id);
    let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(control) = guard.as_ref() else {
        return out(&mut env, "Error: sunucu çalışmıyor".to_string());
    };
    let Ok(id) = hex::decode(&id_hex) else {
        return out(&mut env, "Error: geçersiz kimlik".to_string());
    };
    let Some(existing) = control.store.enrollment_by_id(&id) else {
        return out(&mut env, "Error: kayıt bulunamadı".to_string());
    };
    let blocked = control.store.block_enrollment_key(&existing.enroll_pk, now_ms());
    let revoked = control.store.revoke_enrollment(&id);
    // The block is keyed on a key the device makes itself: with the old
    // public code it would enroll again under a new key.
    let _ = crate::public_join_token(&control.store, true);
    let _ = control.net_changed.send(CoreSignal::EnrollmentsChanged);
    drop(guard);
    match (blocked, revoked) {
        (Ok(()), Ok(())) => out(&mut env, "OK".to_string()),
        (Err(e), _) | (_, Err(e)) => out(&mut env, format!("Error: {e}")),
    }
}

/// Engeli kaldırır — cihaz taze bir davetle yeniden kaydolabilir hâle gelir.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_unblockDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    enrollment_id: JString<'local>,
) -> jstring {
    let id_hex = jstr(&mut env, &enrollment_id);
    let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(control) = guard.as_ref() else {
        return out(&mut env, "Error: sunucu çalışmıyor".to_string());
    };
    let Ok(id) = hex::decode(&id_hex) else {
        return out(&mut env, "Error: geçersiz kimlik".to_string());
    };
    if let Some(existing) = control.store.enrollment_by_id(&id) {
        control.store.unblock_enrollment_key(&existing.enroll_pk);
    }
    drop(guard);
    out(&mut env, "OK".to_string())
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_diskUsage<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(control) = guard.as_ref() else {
        return out(&mut env, "0".to_string());
    };
    let dir = control.data_dir.clone();
    // Defter #24: burası `data_dir/blobs`'u sabit varsayıyordu, oysa
    // `startServer` blob dizinini harici bir birime yönlendirebiliyor —
    // kullanıcı SD kartı seçtiğinde blob'lar HİÇ sayılmıyor, arayüzdeki
    // kullanım neredeyse sıfır görünüyordu.
    let blobs = control.blob_dir.clone();
    drop(guard);
    let mut total = 0u64;
    let mut sum_dir = |d: &PathBuf| {
        if let Ok(entries) = std::fs::read_dir(d) {
            for e in entries.flatten() {
                if let Ok(m) = e.metadata() {
                    total += m.len();
                }
            }
        }
    };
    sum_dir(&dir);
    if blobs != dir {
        sum_dir(&blobs);
    }
    out(&mut env, total.to_string())
}
