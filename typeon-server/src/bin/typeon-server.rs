//! Typeon server: headless Linux daemon.
//!
//! This is the intended deployment: an always-on, reachable VPS. The Android server app (see
//! `p2p_messenger_android_server/`) uses the same core, but the OS may kill it under memory pressure. That
//! setup is "a spare phone at home", not production.
//!
//! Usage:
//!
//! ```text
//! typeon-server run                          # run the server
//! typeon-server join-code                    # join code for everyone, valid 3 days
//! typeon-server join-code rotate             # rotate the code, invalidating the old one
//! typeon-server invite new [label] [uses]    # single- or few-use invite code
//! typeon-server invite list
//! typeon-server devices list
//! typeon-server devices revoke <enrollment_id_hex>
//! typeon-server address                      # advertised addresses
//! ```
//!
//! Global options (any position, they win over the environment variables below):
//!
//! - `--dir <path>`      data directory, same as `TYPEON_SERVER_DIR`
//! - `--storage <size>`  total disk budget, same as `TYPEON_SERVER_BUDGET_BYTES`. Bytes, or a number with a
//!   K/M/G/T suffix (powers of 1024), e.g. `20G`.
//!
//! Configuration also comes from environment variables. No config file format is needed, because systemd already
//! handles `Environment=` naturally:
//!
//! - `TYPEON_SERVER_DIR`   (default `~/.local/share/typeon-server`)
//! - `TYPEON_SERVER_NODE`  (`1` enables the Kademlia server and Circuit Relay v2 service)
//! - `TYPEON_SERVER_NAME`
//! - `TYPEON_SERVER_BUDGET_BYTES` (total disk the server may use, same syntax as `--storage`; default
//!   `DEFAULT_BUDGET_BYTES`, 16 GiB)
//! - `TYPEON_SERVER_DB_KEY` (optional 64-hex SQLCipher key; a plain DB is migrated)
//! - `TYPEON_SERVER_MAX_DEVICES` (maximum enrolled devices; default 64)

use std::path::PathBuf;
use std::sync::OnceLock;

use typeon_server::store::Store;
use typeon_server::{now_ms, ServerConfig, ServerCore};

/// Total disk budget when `TYPEON_SERVER_BUDGET_BYTES` is not set. The library default (64 devices times the
/// per-device quotas, 336 GiB) would let enrolled clients fill a small VPS disk.
const DEFAULT_BUDGET_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// `--dir`, set once in `main` before anything reads the data directory.
static DIR_FLAG: OnceLock<PathBuf> = OnceLock::new();
/// `--storage`, already parsed to bytes.
static STORAGE_FLAG: OnceLock<u64> = OnceLock::new();

/// `"20G"`, `"512M"`, `"1.5T"` or plain bytes. Suffixes are powers of 1024; a trailing `B`/`iB` is allowed.
fn parse_size(text: &str) -> Option<u64> {
    let t = text.trim().to_ascii_uppercase();
    let t = t.strip_suffix("IB").or_else(|| t.strip_suffix('B')).unwrap_or(&t);
    let (num, shift) = match t.chars().last()? {
        'K' => (&t[..t.len() - 1], 10),
        'M' => (&t[..t.len() - 1], 20),
        'G' => (&t[..t.len() - 1], 30),
        'T' => (&t[..t.len() - 1], 40),
        _ => (t, 0),
    };
    let num = num.trim();
    let bytes = match num.parse::<u64>() {
        Ok(n) => n.checked_mul(1u64 << shift)?,
        Err(_) => {
            let f = num.parse::<f64>().ok()?;
            let b = f * (1u64 << shift) as f64;
            if !b.is_finite() || b < 0.0 || b >= u64::MAX as f64 {
                return None;
            }
            b as u64
        }
    };
    (bytes > 0).then_some(bytes)
}

/// Removes `--dir`/`--storage` (as `--x v` or `--x=v`) from `args` and records them. A bad value is a usage error.
fn take_global_flags(args: &mut Vec<String>) {
    let mut i = 0;
    while i < args.len() {
        let (name, inline) = match args[i].split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (args[i].clone(), None),
        };
        if name != "--dir" && name != "--storage" {
            i += 1;
            continue;
        }
        args.remove(i);
        let value = match inline {
            Some(v) => v,
            None if i < args.len() => args.remove(i),
            None => {
                eprintln!("{name} bir değer bekliyor");
                std::process::exit(2);
            }
        };
        if name == "--dir" {
            let _ = DIR_FLAG.set(PathBuf::from(value));
        } else {
            match parse_size(&value) {
                Some(b) => {
                    let _ = STORAGE_FLAG.set(b);
                }
                None => {
                    eprintln!("--storage anlaşılmadı (örnek: 20G, 512M, 1073741824): {value}");
                    std::process::exit(2);
                }
            }
        }
    }
}

fn data_dir() -> PathBuf {
    if let Some(dir) = DIR_FLAG.get() {
        return dir.clone();
    }
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
    // Only a known word counts. An empty string or a typo keeps the default, and the daemon says so.
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
        // `total_storage_budget_bytes` used to be read but never set anywhere. The server's total disk ceiling was dead code. Only
        // per-record quotas applied, so N records could grow real usage to N times the quota.
    cfg.total_storage_budget_bytes = Some(DEFAULT_BUDGET_BYTES);
    match (STORAGE_FLAG.get(), std::env::var("TYPEON_SERVER_BUDGET_BYTES")) {
        (Some(&bytes), _) => cfg.total_storage_budget_bytes = Some(bytes),
        (None, Ok(v)) => match parse_size(&v) {
            Some(bytes) => cfg.total_storage_budget_bytes = Some(bytes),
            None => eprintln!("TYPEON_SERVER_BUDGET_BYTES yok sayıldı (örnek: 20G, 512M, bayt sayısı): {v}"),
        },
        (None, Err(_)) => eprintln!(
            "--storage / TYPEON_SERVER_BUDGET_BYTES yok: disk bütçesi {} GiB. Diskinize göre ayarlayın.",
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

/// Management commands open ONLY the database. Building a `ServerCore` here started a second Tor client on the state
/// directory the daemon holds locked. The command then waited 90 s and failed while the server was running. The address a
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

/// A CLI number: absent means `default`. Unparsable is a usage error, not `default`.
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

    // Optional SQLCipher key (64 hex characters). A plain DB is migrated on first use.
    // `TYPEON_SERVER_DB_KEY_FILE` (a 0600 file, or systemd `LoadCredential`) is preferred: an environment variable stays
    // readable in /proc/<pid>/environ and in a unit file.
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

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    take_global_flags(&mut args);
    let cmd = args.first().map(String::as_str).unwrap_or("run");

    match cmd {
        "run" => run().await,
        "join-code" => join_code(&args[1..]),
        "invite" => invite(&args[1..]),
        "devices" => devices(&args[1..]),
        "address" => address(),
        "updates" => updates(&args[1..]),
        "version" | "--version" | "-V" => println!("typeon-server {}", env!("CARGO_PKG_VERSION")),
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
         address                             İlan edilen adresler\n\
         updates beta on|off                 Beta sürümleri de otomatik kur (varsayılan kapalı)\n\
         version                             Sürüm\n\n\
         Genel seçenekler (her komutta):\n\
         --dir <yol>                         Veri dizini (TYPEON_SERVER_DIR)\n\
         --storage <boyut>                   Toplam disk bütçesi, örn. 20G, 512M (TYPEON_SERVER_BUDGET_BYTES)\n"
    );
}

async fn run() {
    let cfg = build_config();
    println!(
        "dir: {}  storage: {} MiB",
        data_dir().display(),
        cfg.total_storage_budget_bytes.unwrap_or(0) >> 20
    );
    let core = match ServerCore::new(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Sunucu başlatılamadı: {e}");
            std::process::exit(1);
        }
    };
    println!("peer_id: {}", core.local_peer_id());
    tokio::spawn(update_loop(std::sync::Arc::downgrade(&core.tor_client())));
    if let Err(e) = core.run().await {
        eprintln!("Sunucu hatası: {e}");
        std::process::exit(1);
    }
}

/// Requirement: one code must be shareable with EVERYONE. `invite new` creates a NEW code on every call, and the token
/// cannot be shown again. This command returns the SAME code until it expires (3 days) (see `ServerCore::join_code`).
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
            // 0 (or negative) means UNLIMITED. See `Store::create_invite`.
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
                    // the public join code changes too, or the revoked device enrolls again under a fresh key.
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

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1073741824"), Some(1 << 30));
        assert_eq!(parse_size("20G"), Some(20 << 30));
        assert_eq!(parse_size("20gib"), Some(20 << 30));
        assert_eq!(parse_size("512M"), Some(512 << 20));
        assert_eq!(parse_size("1.5T"), Some(3 << 39));
        assert_eq!(parse_size(" 4k "), Some(4096));
        assert_eq!(parse_size("0"), None);
        assert_eq!(parse_size("-1G"), None);
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("99999999999T"), None);
    }
}

fn update_dir() -> PathBuf {
    data_dir().join("update")
}

fn updates(args: &[String]) {
    let dir = update_dir();
    let on = match args {
        [b, v] if b == "beta" && v == "on" => true,
        [b, v] if b == "beta" && v == "off" => false,
        [] => {
            let beta = p2p_messenger::update::beta_enabled(&dir);
            println!("auto-update: on, channel: {}", if beta { "beta" } else { "stable" });
            return;
        }
        _ => {
            eprintln!("updates beta on|off");
            std::process::exit(2);
        }
    };
    if let Err(e) = p2p_messenger::update::set_beta(&dir, on) {
        eprintln!("{}: {e}", dir.display());
        std::process::exit(1);
    }
}

/// Exit code that makes systemd (`Restart=on-failure`) start the server again, through the unit's
/// `ExecStartPre` that installs a staged binary.
const EXIT_UPDATE: i32 = 75;
/// Name the unit's `ExecStartPre` looks for when the binary itself is read-only (`ProtectSystem=strict`).
const STAGED: &str = "typeon-server.staged";

/// Once Tor had time to bootstrap, then hourly; `update::check` keeps it to one real check a day.
async fn update_loop(tor: std::sync::Weak<p2p_messenger::update::TorClientRt>) {
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    loop {
        if let Some(tor) = tor.upgrade() {
            let dir = update_dir();
            match p2p_messenger::update::check(&tor, &dir, env!("CARGO_PKG_VERSION"), "typeon-server-linux", false, true).await {
                Ok(Some((version, path))) => apply_update(&version, &path),
                Ok(None) => {}
                Err(e) => log::warn!("update check: {e}"),
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

fn apply_update(version: &str, path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let systemd = std::env::var_os("INVOCATION_ID").is_some();
    let replace = || -> std::io::Result<()> {
        let exe = std::env::current_exe()?;
        let tmp = exe.with_extension("new");
        std::fs::copy(path, &tmp)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&tmp, &exe).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    };
    match replace() {
        Ok(()) => {
            let _ = std::fs::remove_file(path);
            log::info!("update: installed {version}");
        }
        Err(e) if systemd => {
            if let Err(e2) = std::fs::rename(path, update_dir().join(STAGED)) {
                log::warn!("update: cannot replace binary ({e}) nor stage it ({e2})");
                return;
            }
            log::info!("update: {version} staged for the unit's ExecStartPre ({e})");
        }
        Err(e) => {
            log::warn!("update: {version} downloaded to {} but the binary is not writable ({e})", path.display());
            return;
        }
    }
    if systemd {
        log::info!("update: exiting so systemd restarts into {version}");
        std::process::exit(EXIT_UPDATE);
    }
    log::info!("update: {version} takes effect at the next start");
}
