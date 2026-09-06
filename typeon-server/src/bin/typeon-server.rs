//! Typeon sunucusu — headless Linux daemon'ı.
//!
//! Gerçekçi dağıtım budur: her zaman açık, ulaşılabilir bir VPS. Android
//! sunucu uygulaması (bkz. `p2p_messenger_android_server/`) aynı çekirdeği
//! kullanır ama işletim sistemi onu bellek baskısı altında öldürebilir —
//! oradaki senaryo "evde duran yedek bir telefon", "üretim" değil.
//!
//! Kullanım:
//!
//! ```text
//! typeon-server run                          # sunucuyu çalıştır
//! typeon-server join-code                    # KALICI katılım kodu (herkes)
//! typeon-server join-code rotate             # kodu döndür, eskisini iptal et
//! typeon-server invite new [etiket] [adet]   # tek/az kullanımlık davet kodu
//! typeon-server invite list
//! typeon-server devices list
//! typeon-server devices revoke <enrollment_id_hex>
//! typeon-server address                      # ilan edilen adresler
//! ```
//!
//! Yapılandırma ortam değişkenlerinden okunur — bir yapılandırma dosyası
//! biçimi icat etmeye gerek yok, systemd zaten `Environment=` ile bunu
//! doğal olarak yapıyor:
//!
//! - `TYPEON_SERVER_DIR`   (varsayılan `~/.local/share/typeon-server`)
//! - `TYPEON_SERVER_PORT`  (Tor açıkken yok sayılır)
//! - `TYPEON_SERVER_TOR`   (`0` ile kapatılır; varsayılan açık)
//! - `TYPEON_SERVER_NODE`  (`1` ile Kad Server + Circuit Relay v2 hizmeti)
//! - `TYPEON_SERVER_NAME`
//! - `TYPEON_SERVER_BUDGET_BYTES` (sunucunun kullanabileceği TOPLAM disk;
//!   ayarlanmazsa sınırsız — kayıt başına kotalar yine geçerli)

use std::path::PathBuf;

use typeon_server::{now_ms, ServerConfig, ServerCore};

fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TYPEON_SERVER_DIR") {
        return PathBuf::from(dir);
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(".local/share")
        });
    base.join("typeon-server")
}

fn env_flag(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => !(v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("no")),
        Err(_) => default,
    }
}

fn build_config() -> ServerConfig {
    let mut cfg = ServerConfig::new(data_dir());
    cfg.tor_enabled = env_flag("TYPEON_SERVER_TOR", true);
    cfg.node_mode = env_flag("TYPEON_SERVER_NODE", false);
    if let Ok(port) = std::env::var("TYPEON_SERVER_PORT") {
        if let Ok(p) = port.parse() {
            cfg.listen_port = p;
        }
    }
    if let Ok(name) = std::env::var("TYPEON_SERVER_NAME") {
        cfg.server_name = name;
    }
    // Bu denetimde bulundu: `total_storage_budget_bytes` okunuyor ama hiçbir
    // yerde set edilmiyordu, yani sunucunun TOPLAM disk tavanı (defter #23)
    // ölü koddu — yalnızca kayıt başına kotalar uygulanıyordu ve N kayıtla
    // gerçek kullanım N × kota'ya çıkabiliyordu. Bir VPS'te sınırsız kalmak
    // makul bir varsayılan (bu yüzden `None`), ama küçük bir diskte
    // operatörün bir tavan koyabilmesi gerekiyor.
    if let Ok(v) = std::env::var("TYPEON_SERVER_BUDGET_BYTES") {
        match v.trim().parse::<u64>() {
            Ok(bytes) if bytes > 0 => cfg.total_storage_budget_bytes = Some(bytes),
            _ => eprintln!("TYPEON_SERVER_BUDGET_BYTES yok sayıldı (pozitif bir bayt sayısı bekleniyor): {v}"),
        }
    }
    cfg
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("run");

    match cmd {
        "run" => run().await,
        // Yönetim komutları sunucuyu AYAĞA KALDIRIR (davet kodu, ilan
        // edilecek adresi içermek zorunda ve o adres ancak dinleme
        // başladıktan sonra biliniyor). Tor açıkken onion adresinin
        // görünmesi bootstrap'ı bekler, bu yüzden kısa bir tolerans var.
        "join-code" => join_code(&args[1..]).await,
        "invite" => invite(&args[1..]).await,
        "devices" => devices(&args[1..]),
        "address" => address().await,
        "help" | "--help" | "-h" => usage(),
        other => {
            eprintln!("Bilinmeyen komut: {other}\n");
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    eprintln!(
        "typeon-server <komut>\n\n\
         run                                 Sunucuyu çalıştır (varsayılan)\n\
         join-code                           Kalıcı katılım kodu (sınırsız kişi)\n\
         join-code rotate                    Katılım kodunu döndür (eskisi geçersiz)\n\
         invite new [etiket] [adet] [gün]    Davet kodu üret (adet 0 = sınırsız)\n\
         invite list                         Davetleri listele\n\
         devices list                        Kayıtlı cihazlar\n\
         devices revoke <enrollment_id>      Bir cihazın kaydını iptal et\n\
         address                             İlan edilen adresler\n"
    );
}

async fn run() {
    let core = match ServerCore::new(build_config()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Sunucu başlatılamadı: {e}");
            std::process::exit(1);
        }
    };
    println!("peer_id: {}", core.local_peer_id());
    if let Err(e) = core.run().await {
        eprintln!("Sunucu hatası: {e}");
        std::process::exit(1);
    }
}

/// Sunucuyu kaldırır ve bir dinleme adresi görünene kadar bekler.
///
/// Tor açıkken onion adresi arti'nin bootstrap'ını bekler; bu 30-60 sn
/// sürebilir. Adres olmadan üretilen bir davet kodu kimseye yaramaz, bu
/// yüzden beklemek doğru davranış — sessizce eksik bir kod basmaktansa.
async fn boot_and_wait_for_address(max_wait_s: u64) -> ServerCore {
    let mut core = match ServerCore::new(build_config()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Sunucu başlatılamadı: {e}");
            std::process::exit(1);
        }
    };
    let deadline = now_ms() + (max_wait_s * 1000) as i64;
    while core.advertised_addrs().is_empty() && now_ms() < deadline {
        core.pump_for(std::time::Duration::from_millis(500)).await;
    }
    core
}

/// Kullanıcı isteği: tek bir kodun HERKESE dağıtılabilmesi. `invite new`
/// her çağrıda YENİ bir kod üretir ve jetonu bir daha gösteremez; bu komut
/// AYNI kalıcı kodu döner (bkz. `ServerCore::join_code`).
async fn join_code(args: &[String]) {
    let rotate = matches!(args.first().map(String::as_str), Some("rotate") | Some("yenile"));
    let core = boot_and_wait_for_address(90).await;
    let res = if rotate { core.rotate_join_code() } else { core.join_code() };
    match res {
        Ok(code) => {
            println!("{code}");
            if rotate {
                eprintln!("\nKod döndürüldü — ESKİ kod artık geçersiz. Kayıtlı cihazlar etkilenmez.");
            }
            eprintln!("\nBu kodu istemcide Ayarlar > Sunucular > Sunucu ekle bölümüne yapıştırın.");
            eprintln!("Sınırsız kişi aynı kodla katılabilir; saatlik kayıt tavanı sel koruması olarak durur.");
        }
        Err(e) => {
            eprintln!("Katılım kodu alınamadı: {e}");
            std::process::exit(1);
        }
    }
}

async fn invite(args: &[String]) {
    match args.first().map(String::as_str) {
        Some("new") | None => {
            let label = args.get(1).cloned().unwrap_or_else(|| "davet".to_string());
            // 0 (ya da negatif) = SINIRSIZ — bkz. `Store::create_invite`.
            let uses: i64 = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(1);
            let days: i64 = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(7);
            let core = boot_and_wait_for_address(90).await;
            match core.create_invite(&label, uses, days * 24 * 60 * 60 * 1000) {
                Ok(code) => {
                    println!("{code}");
                    eprintln!("\nBu kodu istemcide Ayarlar > Sunucular > Sunucu ekle bölümüne yapıştırın.");
                    let uses_txt = if uses <= 0 { "sınırsız".to_string() } else { uses.to_string() };
                    eprintln!("Kullanım hakkı: {uses_txt}, geçerlilik: {days} gün.");
                }
                Err(e) => {
                    eprintln!("Davet üretilemedi: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("list") => {
            let core = match ServerCore::new(build_config()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Açılamadı: {e}");
                    std::process::exit(1);
                }
            };
            let now = now_ms();
            for (label, uses, expires, valid) in core.store().list_invites(now) {
                println!(
                    "{:<20} kalan={:<9} bitiş={:<15} {}",
                    label,
                    if uses < 0 { "sınırsız".to_string() } else { uses.to_string() },
                    if expires == 0 { "yok".to_string() } else { expires.to_string() },
                    if valid { "geçerli" } else { "geçersiz" }
                );
            }
        }
        Some(other) => {
            eprintln!("Bilinmeyen invite alt komutu: {other}");
            std::process::exit(2);
        }
    }
}

fn devices(args: &[String]) {
    let core = match ServerCore::new(build_config()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Açılamadı: {e}");
            std::process::exit(1);
        }
    };
    match args.first().map(String::as_str) {
        Some("list") | None => {
            for e in core.store().list_enrollments() {
                println!(
                    "{} peer={} durum={:?} posta={}B arşiv={}B dosya={}B",
                    hex::encode(&e.enrollment_id),
                    e.peer_id,
                    e.state,
                    e.bytes_mail,
                    e.bytes_archive,
                    e.bytes_blob
                );
            }
        }
        Some("revoke") => {
            let Some(id_hex) = args.get(1) else {
                eprintln!("Kullanım: devices revoke <enrollment_id_hex>");
                std::process::exit(2);
            };
            let Ok(id) = hex::decode(id_hex) else {
                eprintln!("Geçersiz enrollment_id (hex bekleniyor)");
                std::process::exit(2);
            };
            match core.store().revoke_enrollment(&id) {
                Ok(()) => println!("İptal edildi: {id_hex}"),
                Err(e) => {
                    eprintln!("İptal edilemedi: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some(other) => {
            eprintln!("Bilinmeyen devices alt komutu: {other}");
            std::process::exit(2);
        }
    }
}

async fn address() {
    let core = boot_and_wait_for_address(90).await;
    println!("peer_id: {}", core.local_peer_id());
    println!("tor: {}", core.tor_status());
    for addr in core.advertised_addrs() {
        println!("{addr}");
    }
}
