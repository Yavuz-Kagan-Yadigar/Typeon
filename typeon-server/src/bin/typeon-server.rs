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
//! - `TYPEON_SERVER_NODE`  (`1` ile Kad Server + Circuit Relay v2 hizmeti)
//! - `TYPEON_SERVER_NAME`
//! - `TYPEON_SERVER_BUDGET_BYTES` (total disk the server may use; default
//!   `DEFAULT_BUDGET_BYTES`, 16 GiB)
//! - `TYPEON_SERVER_DB_KEY` (optional 64-hex SQLCipher key; a plain DB is migrated)
//! - `TYPEON_SERVER_MAX_DEVICES` (most enrolled devices; default 64)

use std::path::PathBuf;

use typeon_server::store::Store;
use typeon_server::{now_ms, ServerConfig, ServerCore};

/// Total disk budget when `TYPEON_SERVER_BUDGET_BYTES` is not set. The
/// library default (64 devices x per-device quotas = 336 GiB) let enrolled
/// clients fill a small VPS disk.
const DEFAULT_BUDGET_BYTES: u64 = 16 * 1024 * 1024 * 1024;

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
    // Only a known word counts; "" or a typo keeps the default (and says so).
    match std::env::var(key).map(|v| v.trim().to_ascii_lowercase()) {
        Ok(v) if ["1", "true", "yes", "on"].contains(&v.as_str()) => true,
        Ok(v) if ["0", "false", "no", "off"].contains(&v.as_str()) => false,
        Ok(v) => {
            eprintln!("{key}={v:?} anlaşılmadı, varsayılan ({default}) kullanılıyor");
            default
        }
        Err(_) => default,
    }
}

fn build_config() -> ServerConfig {
    let mut cfg = ServerConfig::new(data_dir());
    cfg.node_mode = env_flag("TYPEON_SERVER_NODE", false);
    if let Ok(name) = std::env::var("TYPEON_SERVER_NAME") {
        cfg.server_name = name;
    }
    // Bu denetimde bulundu: `total_storage_budget_bytes` okunuyor ama hiçbir
    // yerde set edilmiyordu, yani sunucunun TOPLAM disk tavanı
    // ölü koddu — yalnızca kayıt başına kotalar uygulanıyordu ve N kayıtla
    // gerçek kullanım N × kota'ya çıkabiliyordu.
    cfg.total_storage_budget_bytes = Some(DEFAULT_BUDGET_BYTES);
    match std::env::var("TYPEON_SERVER_BUDGET_BYTES") {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(bytes) if bytes > 0 => cfg.total_storage_budget_bytes = Some(bytes),
            _ => eprintln!("TYPEON_SERVER_BUDGET_BYTES yok sayıldı (pozitif bir bayt sayısı bekleniyor): {v}"),
        },
        Err(_) => eprintln!(
            "TYPEON_SERVER_BUDGET_BYTES yok: disk bütçesi {} GiB. Diskinize göre ayarlayın.",
            DEFAULT_BUDGET_BYTES >> 30
        ),
    }
    if let Ok(v) = std::env::var("TYPEON_SERVER_MAX_DEVICES") {
        match v.trim().parse::<u32>() {
            Ok(n) if n > 0 => cfg.max_enrollments = n,
            _ => eprintln!("TYPEON_SERVER_MAX_DEVICES ignored (a positive number is expected): {v}"),
        }
    }
    cfg
}

/// Management commands open ONLY the database. Building a `ServerCore` here
/// started a second Tor client on the state dir the daemon holds locked: the
/// command waited 90 s and failed while the server was running. The address a
/// code needs is the one the daemon last wrote to the DB.
fn open_store() -> Store {
    match Store::open(&data_dir().join("typeon_server.db")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Açılamadı: {e}");
            std::process::exit(1);
        }
    }
}

/// A CLI number: absent = `default`, unparsable = usage error (not `default`).
fn arg_num(args: &[String], index: usize, default: i64) -> i64 {
    match args.get(index).map(|v| v.parse::<i64>()) {
        None => default,
        Some(Ok(n)) => n,
        Some(Err(_)) => {
            eprintln!("Sayı bekleniyor: {}", args[index]);
            std::process::exit(2);
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Optional SQLCipher key (64 hex chars); a plain DB is migrated on first use.
    // `TYPEON_SERVER_DB_KEY_FILE` (a 0600 file, or systemd `LoadCredential`)
    // is preferred: an environment variable stays readable in
    // /proc/<pid>/environ and in a unit file.
    let from_file = std::env::var("TYPEON_SERVER_DB_KEY_FILE").ok().map(|path| {
        std::env::remove_var("TYPEON_SERVER_DB_KEY_FILE");
        match std::fs::read_to_string(&path) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("TYPEON_SERVER_DB_KEY_FILE: {e}");
                std::process::exit(1);
            }
        }
    });
    if let Some(k) = from_file.or_else(|| std::env::var("TYPEON_SERVER_DB_KEY").ok()) {
        let k = zeroize::Zeroizing::new(k);
        // Keep the key out of any child process environment.
        std::env::remove_var("TYPEON_SERVER_DB_KEY");
        match typeon_server::store::parse_hex_db_key(k.trim()) {
            Ok(key) => typeon_server::store::set_db_key(Some(key)),
            Err(e) => {
                eprintln!("TYPEON_SERVER_DB_KEY: {e}");
                std::process::exit(1);
            }
        }
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("run");

    match cmd {
        "run" => run().await,
        "join-code" => join_code(&args[1..]),
        "invite" => invite(&args[1..]),
        "devices" => devices(&args[1..]),
        "address" => address(),
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
         devices revoke <enrollment_id>      Bir cihazın kaydını iptal et ve engelle\n\
         devices unblock <enrollment_id>     Engeli kaldır (cihaz yeniden kaydolabilir)\n\
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

/// Kullanıcı isteği: tek bir kodun HERKESE dağıtılabilmesi. `invite new`
/// her çağrıda YENİ bir kod üretir ve jetonu bir daha gösteremez; bu komut
/// AYNI kalıcı kodu döner (bkz. `ServerCore::join_code`).
fn join_code(args: &[String]) {
    let rotate = matches!(args.first().map(String::as_str), Some("rotate") | Some("yenile"));
    match typeon_server::join_code(&open_store(), rotate) {
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

fn invite(args: &[String]) {
    match args.first().map(String::as_str) {
        Some("new") | None => {
            let label = args.get(1).cloned().unwrap_or_else(|| "davet".to_string());
            // 0 (ya da negatif) = SINIRSIZ — bkz. `Store::create_invite`.
            let uses = arg_num(args, 2, 1);
            let days = arg_num(args, 3, 7);
            if days < 1 {
                eprintln!("Gün sayısı en az 1 olmalı: {days}");
                std::process::exit(2);
            }
            // An overflow wrapped negative, which means "never expires".
            let Some(ttl_ms) = days.checked_mul(24 * 60 * 60 * 1000) else {
                eprintln!("Gün sayısı çok büyük: {days}");
                std::process::exit(2);
            };
            match typeon_server::create_invite(&open_store(), &label, uses, ttl_ms) {
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
            for (label, uses, expires, valid) in open_store().list_invites(now_ms()) {
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
    let store = open_store();
    match args.first().map(String::as_str) {
        Some("list") | None => {
            for e in store.list_enrollments() {
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
            match store.revoke_enrollment(&id) {
                Ok(()) => {
                    // the public join code changes too, or the
                    // revoked device enrolls again under a fresh key.
                    let _ = typeon_server::public_join_token(&store, true);
                    println!("İptal edildi: {id_hex} (herkese açık katılım kodu yenilendi)");
                }
                Err(e) => {
                    eprintln!("İptal edilemedi: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("unblock") => {
            let Some(e) = args.get(1).and_then(|h| hex::decode(h).ok()).and_then(|id| store.enrollment_by_id(&id)) else {
                eprintln!("Kullanım: devices unblock <enrollment_id_hex>");
                std::process::exit(2);
            };
            store.unblock_enrollment_key(&e.enroll_pk);
            println!("Engel kaldırıldı");
        }
        Some(other) => {
            eprintln!("Bilinmeyen devices alt komutu: {other}");
            std::process::exit(2);
        }
    }
}

fn address() {
    match typeon_server::advertised_addrs(&open_store()) {
        Ok(addrs) => addrs.iter().for_each(|a| println!("{a}")),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
