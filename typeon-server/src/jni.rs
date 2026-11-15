//! JNI shell of the Android server app.
//!
//! Compiled only under `cfg(target_os = "android")`. The Linux daemon (`src/bin/typeon-server.rs`) does not touch this
//! file.
//!
//! ## Architecture
//!
//! `ServerCore` runs `run()` in its own tokio task. The UI asks for status every second. A lock on `ServerCore` would
//! stall the loop, so the loop refreshes a cheap snapshot (`ServerShared`) on every turn, and the UI reads that.
//!
//! Management operations (create invites, list or revoke devices) use a SEPARATE database connection. SQLite WAL mode
//! supports several connections safely (see `Store::open`), so they never block the main loop.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jstring};
use jni::JNIEnv;
use log::info;

use crate::{now_ms, CoreSignal, ServerConfig, ServerCore, ServerShared};
use crate::store::{EnrollmentState, Store};

struct Control {
    shared: Arc<ServerShared>,
    /// Separate connection for management operations. See the module note.
    store: Store,
    data_dir: PathBuf,
    /// Blobs may sit on external storage (`startServer`'s `blobDir` parameter), so disk usage must count that directory too.
    blob_dir: PathBuf,
    /// `stopServer` triggers this to end `run_until`.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// See `ServerCore::set_net_changed_rx`. `notifyNetworkChanged` pushes to it.
    net_changed: tokio::sync::mpsc::UnboundedSender<CoreSignal>,
    /// For `checkUpdate`. Weak: a stopped server must drop its Tor client (arti state lock) for the next start.
    tor: std::sync::Weak<p2p_messenger::update::TorClientRt>,
}

lazy_static::lazy_static! {
    static ref RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    static ref CONTROL: Mutex<Option<Control>> = Mutex::new(None);
    /// Held for the whole of `startServer` and `stopServer`. Without it, two starts could both pass the `CONTROL` check
    /// (the second one, without Tor, would replace the working server), and a stop during a start did nothing.
    static ref START_STOP: Mutex<()> = Mutex::new(());
    /// The loop task of the last started server. `stopServer` only signals it. The next `startServer` waits for it to end.
    static ref LAST_RUN: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);
}

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    // An empty string falls back to a default (for example `blob_dir`). A failed read must at least show up in the log.
    env.get_string(s).map(|v| v.into()).unwrap_or_else(|e| {
        log::warn!("JNI dizesi okunamadı, boş sayıldı: {e}");
        // A pending Java exception aborts the next JNI call.
        let _ = env.exception_clear();
        String::new()
    })
}

fn out(env: &mut JNIEnv, s: String) -> jstring {
    // `null` only when the JVM is out of memory. The pending `OutOfMemoryError` is then thrown in Kotlin on return.
    env.new_string(s).map(|v| v.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// Runs an export's body. A panic becomes an `Error:` answer instead of unwinding into the JVM, which would abort the
/// whole server app.
fn guarded<'local>(env: &mut JNIEnv<'local>, body: impl FnOnce(JNIEnv<'local>) -> jstring) -> jstring {
    // SAFETY: same thread and same frame. `env` is not used while `body` runs.
    let inner = unsafe { env.unsafe_clone() };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(inner)))
        .unwrap_or_else(|p| {
            let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned());
            log::error!("JNI çağrısında panic: {}", msg.as_deref().unwrap_or("?"));
            out(env, "Error: internal error (panic)".to_string())
        })
}

/// SQLCipher raw key (32 bytes) for the server DB. Call before `startServer`. An empty array means a plain DB. Returns
/// "ok" or "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_setDbKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
) -> jstring {
    guarded(&mut env, |mut env| {
        // A failed read is an error, never "empty means plain DB".
        let raw = match env.convert_byte_array(&key) {
            Ok(v) => zeroize::Zeroizing::new(v),
            Err(e) => {
                let _ = env.exception_clear();
                return out(&mut env, format!("Error: DB key: {e}"));
            }
        };
        let r = if raw.is_empty() {
            crate::store::set_db_key(None);
            "ok".to_string()
        } else {
            match <[u8; 32]>::try_from(raw.as_slice()) {
                Ok(k) => {
                    crate::store::set_db_key(Some(zeroize::Zeroizing::new(k)));
                    "ok".to_string()
                }
                Err(_) => "Error: DB key must be 32 bytes".to_string(),
            }
        };
        out(&mut env, r)
    })
}

/// Debug APKs only (`ServerLib` init): a release installs no logger, so nothing reaches logcat.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_enableLogging<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("TypeonServer"),
    );
}

/// Starts the server. Calling it again is a no-op (the foreground service can restart with `START_STICKY`). If the
/// previous loop is still shutting down, returns `Error:`.
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
    guarded(&mut env, |mut env| {
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
        // Only the BLOBS can be moved. Identity and Tor state stay internal (see `ServerConfig.blob_dir`).
        let blobs = jstr(&mut env, &blob_dir);
        if !blobs.is_empty() {
            config.blob_dir = PathBuf::from(&blobs);
        }
        // Derive the quotas from the device's REAL free space.
        //
        // The defaults were written for a VPS: per enrollment 256 MB of mail, 1 GB of archive and 4 GB of blobs. Five
        // devices come to 26 GB, and that actually happened. In a test, a tablet's 22 GB disk filled up, the server
        // had stored 751 MB, and not even a new APK could be installed (`INSTALL_FAILED_INSUFFICIENT_STORAGE`). A server
        // that eats the phone's own disk and makes the device unusable is not acceptable.
        if storage_budget_bytes > 0 {
            let budget = storage_budget_bytes as u64;
                        // `ServerConfig.total_storage_budget_bytes` was written and read by `handle_blob_put` and
                        // `handle_authenticated`, but was NEVER SET anywhere. `ServerConfig::new` leaves it `None`, and neither this file
                        // nor the headless daemon filled it in. So the total ceiling was dead code, and only the per-record quotas applied.
                        // With 20 enrolled devices instead of 8, the real ceiling was 2.5 times the budget.
            config.total_storage_budget_bytes = Some(budget);
            // The budget is divided by the expected enrollment count, so no single device takes everyone else's share. The
            // split is roughly by usage: blobs are the largest, mail the smallest.
            // The quota share and the enrollment cap are one number: more devices than shares would put the sum of the quotas
            // over the budget.
            const EXPECTED_DEVICES: u64 = 16;
            config.max_enrollments = EXPECTED_DEVICES as u32;
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
                // Toggling the relay / DHT switch restarts the server 600 ms after `stopServer`, which only signals the old loop.
                // The old arti client still held its state lock, so the new one failed with "Onion service could not start: local
                // resource (port, lockfile, etc.) already in use", and the server had no address until toggled again. Wait for the old
                // loop (and the Tor client it owns) to be dropped first.
        let previous = LAST_RUN.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(mut handle) = previous {
            if RUNTIME.block_on(async { tokio::time::timeout(std::time::Duration::from_secs(20), &mut handle).await }).is_err() {
                // Starting anyway would run a second core on the same DB and Tor state.
                log::warn!("Önceki sunucu döngüsü 20 sn içinde kapanmadı, başlatılmadı");
                *LAST_RUN.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
                return out(&mut env, "Error: previous server still shutting down, retry shortly".to_string());
            }
        }
        let mut core = match ServerCore::new(config.clone()) {
            Ok(c) => c,
            Err(e) => return out(&mut env, format!("Error: {e}")),
        };
        let shared = Arc::new(ServerShared::default());
        core.attach_shared(shared.clone());
        let peer_id = core.local_peer_id().to_string();
        let tor = Arc::downgrade(&core.tor_client());

        let store = match Store::open(&PathBuf::from(&dir).join("typeon_server.db")) {
            Ok(s) => s,
            Err(e) => return out(&mut env, format!("Error: {e}")),
        };

        let blob_dir = config.blob_dir.clone();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (net_tx, net_rx) = tokio::sync::mpsc::unbounded_channel::<CoreSignal>();
        core.set_net_changed_rx(net_rx);
        // `run_until` consumes the core. When it returns, the Tor client is dropped.
        let handle = RUNTIME.spawn(async move {
            // The `oneshot` also ends if the sender is dropped. A channel error counts as a shutdown signal.
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
            tor,
        });
        out(&mut env, peer_id)
    })
}

/// Called when the network interface changes (Wi-Fi drops and returns, or a switch to cellular). See the
/// `ServerService` `ConnectivityManager` callback. No-op if the core is not running.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_notifyNetworkChanged<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    let _ = std::panic::catch_unwind(|| {
        let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = guard.as_ref() {
            let _ = c.net_changed.send(CoreSignal::NetworkChanged);
        }
    });
}

/// Really stops the server. Ends `run_until` and empties `CONTROL`. The next `startServer` does a CLEAN setup, so changes
/// to node mode, the blob directory or the disk budget finally take effect. Before this, `startServer` was a no-op while a
/// core was running, so none of those changes applied without killing the process.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_stopServer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    guarded(&mut env, |mut env| {
        let _serial = START_STOP.lock().unwrap_or_else(|p| p.into_inner());
        let taken = CONTROL.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(tx) = taken.and_then(|mut control| control.shutdown.take()) {
            let _ = tx.send(());
        }
        // Wait until the loop has really ended. The caller may move or delete the blob files next. On a timeout the handle
        // stays for `startServer`. `LAST_RUN` is not held across the wait, because `serverStatus` locks it too.
        let running = LAST_RUN.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(mut handle) = running {
            if RUNTIME.block_on(async { tokio::time::timeout(std::time::Duration::from_secs(20), &mut handle).await }).is_err() {
                log::warn!("Sunucu döngüsü 20 sn içinde kapanmadı");
                *LAST_RUN.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
                return out(&mut env, "Error: server loop did not stop within 20 s".to_string());
            }
        }
        info!("Sunucu durduruldu (JNI).");
        out(&mut env, "OK".to_string())
    })
}

/// Status polled by the UI once a second. `{peer_id, tor, addresses, stats}`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_serverStatus<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    guarded(&mut env, |mut env| {
        // The loop task ended on its own (tokio swallows a panic). Report it and clear the state, so the next
        // `startServer` is not a no-op.
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
        // Private-network addresses are NOT included (see `ServerCore::invite_addrs`). A recipient on another network
        // cannot reach them, and they leak the internal network layout.
        let addrs: Vec<String> = control
            .shared
            .addrs
            .lock()
            .map(|a| a.iter().filter(|x| p2p_messenger::server_proto::is_onion_server_addr(x)).cloned().collect())
            .unwrap_or_default();
        let stats = control.shared.stats.lock().map(|s| s.clone()).unwrap_or_default();
        // Active ones only. A revoked device stays in the list (dimmed, so it can still be blocked) but is no longer a
        // device of this server.
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
    })
}

/// The server's PERMANENT join code. Published once, and unlimited people can join with it (see
/// `ServerCore::join_code`). With `rotate = true`, the old code becomes invalid and a new one is returned.
///
/// Why `ServerCore::join_code` is not called directly: `ServerCore` lives INSIDE the network task. On the JNI side only
/// `shared` and `store` are visible. So the address filter (`is_onion_server_addr`) is repeated here. See
/// `ServerCore::invite_addrs`: private-network addresses are kept out of codes, because a recipient on another network
/// cannot reach them and they leak the internal network layout.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_joinCode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    rotate: jni::sys::jboolean,
) -> jstring {
    guarded(&mut env, |mut env| {
        let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
        let Some(control) = guard.as_ref() else {
            return out(&mut env, "Error: server not running".to_string());
        };
        let addrs: Vec<String> = control
            .shared
            .addrs
            .lock()
            .map(|a| a.iter().filter(|x| p2p_messenger::server_proto::is_onion_server_addr(x)).cloned().collect())
            .unwrap_or_default();
        if addrs.is_empty() {
            return out(
                &mut env,
                "Error: server has no reachable address yet (Tor may be starting)".to_string(),
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
    })
}

/// `[{enrollment_id, peer_id, state, bytes_mail, bytes_archive, bytes_blob}]`
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_listDevices<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    guarded(&mut env, |mut env| {
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
    })
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_revokeDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    enrollment_id: JString<'local>,
) -> jstring {
    guarded(&mut env, |mut env| {
        let id_hex = jstr(&mut env, &enrollment_id);
        let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
        let Some(control) = guard.as_ref() else {
            return out(&mut env, "Error: server not running".to_string());
        };
        let Ok(id) = hex::decode(&id_hex) else {
            return out(&mut env, "Error: invalid id".to_string());
        };
        let res = control.store.revoke_enrollment(&id);
        // As with a block: under the old public code the revoked device would enroll again at once under a fresh key and PeerId.
        if res.is_ok() {
            let _ = crate::public_join_token(&control.store, true);
        }
        let _ = control.net_changed.send(CoreSignal::EnrollmentsChanged);
        drop(guard);
        match res {
            Ok(()) => out(&mut env, "OK".to_string()),
            Err(e) => out(&mut env, format!("Error: {e}")),
        }
    })
}

/// Blocks an enrollment. Like a revoke, the block is put on the enrollment KEY (revoke also blocks; see
/// `Store::revoke_enrollment`). It also returns the join code, because a device that makes a new key and PeerId could
/// otherwise re-enroll with the old code.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_blockDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    enrollment_id: JString<'local>,
) -> jstring {
    guarded(&mut env, |mut env| {
        let id_hex = jstr(&mut env, &enrollment_id);
        let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
        let Some(control) = guard.as_ref() else {
            return out(&mut env, "Error: server not running".to_string());
        };
        let Ok(id) = hex::decode(&id_hex) else {
            return out(&mut env, "Error: invalid id".to_string());
        };
        let Some(existing) = control.store.enrollment_by_id(&id) else {
            return out(&mut env, "Error: record not found".to_string());
        };
        let blocked = control.store.block_enrollment_key(&existing.enroll_pk, now_ms());
        let revoked = control.store.revoke_enrollment(&id);
        // The block is keyed on a key the device makes itself. With the old public code it would enroll again under a new key.
        let _ = crate::public_join_token(&control.store, true);
        let _ = control.net_changed.send(CoreSignal::EnrollmentsChanged);
        drop(guard);
        match (blocked, revoked) {
            (Ok(()), Ok(())) => out(&mut env, "OK".to_string()),
            (Err(e), _) | (_, Err(e)) => out(&mut env, format!("Error: {e}")),
        }
    })
}

/// Lifts a block, so the device can enroll again with a fresh invite.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_unblockDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    enrollment_id: JString<'local>,
) -> jstring {
    guarded(&mut env, |mut env| {
        let id_hex = jstr(&mut env, &enrollment_id);
        let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
        let Some(control) = guard.as_ref() else {
            return out(&mut env, "Error: server not running".to_string());
        };
        let Ok(id) = hex::decode(&id_hex) else {
            return out(&mut env, "Error: invalid id".to_string());
        };
        let Some(existing) = control.store.enrollment_by_id(&id) else {
            return out(&mut env, "Error: record not found".to_string());
        };
        control.store.unblock_enrollment_key(&existing.enroll_pk);
        drop(guard);
        out(&mut env, "OK".to_string())
    })
}

/// Disk usage in bytes, for the storage row in the UI.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_diskUsage<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    guarded(&mut env, |mut env| {
        let guard = CONTROL.lock().unwrap_or_else(|p| p.into_inner());
        let Some(control) = guard.as_ref() else {
            return out(&mut env, "0".to_string());
        };
        let dir = control.data_dir.clone();
        // This used to assume `data_dir/blobs`. But `startServer` can point the blob directory at an external volume. When
        // the user chose an SD card, blobs were NOT counted at all, and the UI showed almost zero usage.
        let blobs = control.blob_dir.clone();
        drop(guard);
        // Whole trees (Tor state, WAL and so on). The blob directory is counted once, even when it sits inside the data dir.
        fn tree_bytes(d: &std::path::Path, skip: &std::path::Path) -> u64 {
            let Ok(entries) = std::fs::read_dir(d) else { return 0 };
            entries
                .flatten()
                .filter(|e| e.path() != skip)
                // `file_type` does not follow symlinks, so there is no loop.
                .map(|e| match e.file_type() {
                    Ok(t) if t.is_dir() => tree_bytes(&e.path(), skip),
                    Ok(_) => e.metadata().map_or(0, |m| m.len()),
                    Err(_) => 0,
                })
                .sum()
        }
        let mut total = tree_bytes(&dir, &blobs);
        if blobs != dir {
            total += tree_bytes(&blobs, &dir);
        }
        out(&mut env, total.to_string())
    })
}

/// Self-update (see `p2p_messenger::update`). Blocking, network: call off the main thread. Returns the verified
/// APK path, `""` when up to date or checked within the day, or `"Error: ..."`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_server_ServerLib_checkUpdate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    dir: JString<'local>,
    current: JString<'local>,
    force: jboolean,
) -> jstring {
    guarded(&mut env, |mut env| {
        let dir = jstr(&mut env, &dir);
        let current = jstr(&mut env, &current);
        let tor = CONTROL.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(|c| c.tor.upgrade());
        let Some(tor) = tor else { return out(&mut env, "Error: server not running".to_string()) };
        let result = RUNTIME.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(3600),
                p2p_messenger::update::check(&tor, std::path::Path::new(&dir), &current, "typeon-server-{v}.apk", force != 0, false),
            )
            .await
            .unwrap_or_else(|_| Err("update check timed out".to_string()))
        });
        drop(tor);
        out(&mut env, match result {
            Ok(Some((_, path))) => path.to_string_lossy().into_owned(),
            Ok(None) => String::new(),
            Err(e) => format!("Error: {e}"),
        })
    })
}
