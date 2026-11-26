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
//! - `TYPEON_SERVER_DB_KEY` (optional 64-hex SQLCipher key; a plain DB is migrated), or `TYPEON_SERVER_DB_KEY_FILE`
//!   to read the key from a file
//! - `TYPEON_SERVER_MAX_DEVICES` (maximum enrolled devices; default 16). The budget is split over this many devices.

use std::path::PathBuf;
use std::sync::OnceLock;

use typeon_server::store::Store;
use typeon_server::{now_ms, ServerConfig, ServerCore};

/// Total disk budget when `TYPEON_SERVER_BUDGET_BYTES` is not set. The library default (16 devices times the
/// per-device quotas, 84 GiB) would let enrolled clients fill a small VPS disk.
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
                eprintln!("{name} expects a value");
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
                    eprintln!("--storage not understood (example: 20G, 512M, 1073741824): {value}");
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
            eprintln!("{key}={v:?} not understood, using default ({default})");
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
    // Sets the total disk ceiling. Without it only the per-record quotas apply, and N records could grow real usage to
    // N times the quota.
    cfg.total_storage_budget_bytes = Some(DEFAULT_BUDGET_BYTES);
    match (STORAGE_FLAG.get(), std::env::var("TYPEON_SERVER_BUDGET_BYTES")) {
        (Some(&bytes), _) => cfg.total_storage_budget_bytes = Some(bytes),
        (None, Ok(v)) => match parse_size(&v) {
            Some(bytes) => cfg.total_storage_budget_bytes = Some(bytes),
            None => eprintln!("TYPEON_SERVER_BUDGET_BYTES ignored (example: 20G, 512M, byte count): {v}"),
        },
        (None, Err(_)) => eprintln!(
            "--storage / TYPEON_SERVER_BUDGET_BYTES not set: disk budget {} GiB. Adjust it for your disk.",
            DEFAULT_BUDGET_BYTES >> 30
        ),
    }
    if let Ok(v) = std::env::var("TYPEON_SERVER_MAX_DEVICES") {
        match v.trim().parse::<u32>() {
            Ok(n) if n > 0 => cfg.max_enrollments = n,
            _ => eprintln!("TYPEON_SERVER_MAX_DEVICES ignored (a positive number is expected): {v}"),
        }
    }
    // Per-device quotas from the budget, as on Android. The library defaults (5.25 GiB a device) let 16 devices claim
    // 84 GiB of a 16 GiB budget.
    if let Some(budget) = cfg.total_storage_budget_bytes {
        cfg.apply_storage_budget(budget);
    }
    cfg
}

/// Management commands open ONLY the database. Building a `ServerCore` here would start a second Tor client on the state
/// directory the daemon holds locked. The address a code needs is the one the daemon last wrote to the DB.
fn open_store() -> Store {
    match Store::open(&data_dir().join("typeon_server.db")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Could not open: {e}");
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
            eprintln!("Number expected: {}", args[index]);
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
        "install-staged" => install_staged(),
        "version" | "--version" | "-V" => println!("typeon-server {}", env!("CARGO_PKG_VERSION")),
        "help" | "--help" | "-h" => usage(),
        other => {
            eprintln!("Unknown command: {other}\n");
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    eprintln!(
        "typeon-server <command>\n\n\
         run                                 Run the server (default)\n\
         join-code                           Permanent join code (unlimited people)\n\
         join-code rotate                    Rotate the join code (old one becomes invalid)\n\
         invite new [label] [uses] [days]    Create an invite code (uses 0 = unlimited)\n\
         invite list                         List invites\n\
         devices list                        Enrolled devices\n\
         devices revoke <enrollment_id>      Revoke a device enrollment and block it\n\
         devices unblock <enrollment_id>     Remove the block (device can enroll again)\n\
         address                             Advertised addresses\n\
         updates beta on|off                 Also auto-install beta versions (default off)\n\
         install-staged                      Install the downloaded signed update (systemd ExecStartPre, root)\n\
         version                             Version\n\n\
         Global options (for every command):\n\
         --dir <path>                          Data directory (TYPEON_SERVER_DIR)\n\
         --storage <size>                  Total disk budget, e.g. 20G, 512M (TYPEON_SERVER_BUDGET_BYTES)\n\n\
         Tor bridges (environment, read by `run`):\n\
         Bridges are a fallback: used only when Direct is blocked.\n\
         TYPEON_SERVER_BRIDGES_FILE=<path>               obfs4 bridge lines, one per line (unset: Tor built-in bridges)\n\
         TYPEON_SERVER_SNOWFLAKE_FILE=<path>             Snowflake bridge lines, one per line (unset: Tor built-in bridges)\n\
         TYPEON_SERVER_PT_DIR=<dir>                      lyrebird, obfs4 + snowflake (default: next to this binary)\n\
         TYPEON_SERVER_TOR_ALWAYS_BRIDGE=1               start on the bridge, never try Direct first\n"
    );
}

/// Tor bridges from the environment (see `usage`). A bridge is a fallback: Direct first, a bridge once
/// Direct is blocked (core `tor::watch_bridge_fallback`). A bad setting stops the server.
fn apply_tor_transport() {
    let read = |name: &str| match std::env::var(name) {
        Ok(path) => std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("{name}: {e}");
            std::process::exit(1);
        }),
        Err(_) => String::new(),
    };
    let obfs4 = read("TYPEON_SERVER_BRIDGES_FILE");
    let snowflake = read("TYPEON_SERVER_SNOWFLAKE_FILE");
    let pt_dir = std::env::var("TYPEON_SERVER_PT_DIR").unwrap_or_default();
    let always = std::env::var("TYPEON_SERVER_TOR_ALWAYS_BRIDGE").is_ok_and(|v| v.trim() == "1");
    if let Err(e) = p2p_messenger::tor::set_transport(&snowflake, &obfs4, &pt_dir, always) {
        eprintln!("Tor bridges: {e}");
        std::process::exit(1);
    }
    if !p2p_messenger::tor::pt_available(&pt_dir) {
        eprintln!("warning: no PT binary (lyrebird): no Tor bridge fallback{}", if always { "; Tor cannot connect" } else { "" });
    }
}

async fn run() {
    let cfg = build_config();
    println!(
        "dir: {}  storage: {} MiB",
        data_dir().display(),
        cfg.total_storage_budget_bytes.unwrap_or(0) >> 20
    );
    apply_tor_transport();
    let core = match ServerCore::new(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Server could not be started: {e}");
            std::process::exit(1);
        }
    };
    println!("peer_id: {}", core.local_peer_id());
    tokio::spawn(update_loop(std::sync::Arc::downgrade(&core.tor_client())));
    if let Err(e) = core.run().await {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    }
}

/// One code shareable with everyone: this returns the SAME code until it expires (3 days). `invite new` creates a new
/// code on every call, and an invite token cannot be shown again (only its hash is stored).
fn join_code(args: &[String]) {
    let rotate = matches!(args.first().map(String::as_str), Some("rotate") | Some("yenile"));
    match typeon_server::join_code(&open_store(), rotate) {
        Ok(code) => {
            println!("{code}");
            if rotate {
                eprintln!("\nCode rotated — OLD code is no longer valid. Enrolled devices are not affected.");
            }
            eprintln!("\nPaste this code in the client under Settings > Servers > Add server.");
            eprintln!("Unlimited people can join with the same code; the hourly registration cap acts as flood protection.");
        }
        Err(e) => {
            eprintln!("Join code could not be retrieved: {e}");
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
                eprintln!("Number of days must be at least 1: {days}");
                std::process::exit(2);
            }
            // Checked: an overflow would wrap negative, and a negative expiry would mean "never expires".
            let Some(ttl_ms) = days.checked_mul(24 * 60 * 60 * 1000) else {
                eprintln!("Number of days too large: {days}");
                std::process::exit(2);
            };
            match typeon_server::create_invite(&open_store(), &label, uses, ttl_ms) {
                Ok(code) => {
                    println!("{code}");
                    eprintln!("\nPaste this code in the client under Settings > Servers > Add server.");
                    let uses_txt = if uses <= 0 { "unlimited".to_string() } else { uses.to_string() };
                    eprintln!("Uses: {uses_txt}, valid for: {days} days.");
                }
                Err(e) => {
                    eprintln!("Invite could not be created: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("list") => {
            for (label, uses, expires, valid) in open_store().list_invites(now_ms()) {
                println!(
                    "{:<20} left={:<9} expires={:<15} {}",
                    label,
                    if uses < 0 { "unlimited".to_string() } else { uses.to_string() },
                    if expires == 0 { "none".to_string() } else { expires.to_string() },
                    if valid { "valid" } else { "invalid" }
                );
            }
        }
        Some(other) => {
            eprintln!("Unknown invite subcommand: {other}");
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
                    "{} peer={} status={:?} mail={}B archive={}B files={}B",
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
                eprintln!("Usage: devices revoke <enrollment_id_hex>");
                std::process::exit(2);
            };
            let Ok(id) = hex::decode(id_hex) else {
                eprintln!("Invalid enrollment_id (hex expected)");
                std::process::exit(2);
            };
            match store.revoke_enrollment(&id) {
                Ok(()) => {
                    // the public join code changes too, or the revoked device enrolls again under a fresh key.
                    let _ = typeon_server::public_join_token(&store, true);
                    println!("Revoked: {id_hex} (public join code rotated)");
                }
                Err(e) => {
                    eprintln!("Could not revoke: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("unblock") => {
            let Some(e) = args.get(1).and_then(|h| hex::decode(h).ok()).and_then(|id| store.enrollment_by_id(&id)) else {
                eprintln!("Usage: devices unblock <enrollment_id_hex>");
                std::process::exit(2);
            };
            store.unblock_enrollment_key(&e.enroll_pk);
            println!("Block removed");
        }
        Some(other) => {
            eprintln!("Unknown devices subcommand: {other}");
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
const ASSET: &str = "typeon-server-linux";

/// Once Tor had time to bootstrap, then hourly; `update::check` keeps it to one real check a day.
async fn update_loop(tor: std::sync::Weak<p2p_messenger::update::TorClientRt>) {
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    loop {
        if let Some(tor) = tor.upgrade() {
            let dir = update_dir();
            match p2p_messenger::update::check(&tor, &dir, env!("CARGO_PKG_VERSION"), ASSET, false, true).await {
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

/// Root `ExecStartPre` step of the unit. The staged files are written by the sandboxed service user, so
/// nothing in them is trusted: the binary is installed only when the owner's offline release signature
/// covers its hash and it is not older than the running binary (a beta may go back to a release).
/// Always exits 0, so a refused file leaves the server starting on the binary it has.
fn install_staged() {
    use sha2::Digest;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use p2p_messenger::update;
    let dir = update_dir();
    let staged = dir.join(STAGED);
    // Regular files only: a symlink or FIFO planted by the service user is not followed.
    if !std::fs::symlink_metadata(&staged).is_ok_and(|m| m.is_file()) {
        let _ = std::fs::remove_file(&staged);
        return;
    }
    let result = (|| -> Result<String, String> {
        let regular = |name: &str| -> Result<Vec<u8>, String> {
            let path = dir.join(name);
            let meta = std::fs::symlink_metadata(&path).map_err(|e| format!("{name}: {e}"))?;
            if !meta.is_file() || meta.len() > 512 * 1024 * 1024 {
                return Err(format!("{name}: not a regular file of sane size"));
            }
            std::fs::read(&path).map_err(|e| format!("{name}: {e}"))
        };
        let msg = regular(update::SIGNED_FILE)?;
        let sig = String::from_utf8(regular(update::SIG_FILE)?).map_err(|_| "signature not text")?;
        let (tag, sums) = update::verify_release(&msg, &sig)?;
        let want = update::sums_hash(&sums, ASSET).ok_or("signed sums do not list the server binary")?;
        let bin = regular(STAGED)?;
        if hex::encode(sha2::Sha256::digest(&bin)) != want {
            return Err("staged binary does not match the signed hash".into());
        }
        let version = tag.trim_start_matches('v').to_string();
        let current = env!("CARGO_PKG_VERSION");
        if !(update::is_newer(&version, current) || (current.contains('-') && !version.contains('-'))) {
            return Err(format!("{version} is not newer than {current}"));
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let tmp = exe.with_extension("new");
        let _ = std::fs::remove_file(&tmp);
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o755).open(&tmp)?;
            f.write_all(&bin)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &exe)
        };
        write().map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })?;
        Ok(version)
    })();
    let _ = std::fs::remove_file(&staged);
    match result {
        Ok(v) => eprintln!("install-staged: installed {v}"),
        Err(e) => eprintln!("install-staged: refused: {e}"),
    }
}
