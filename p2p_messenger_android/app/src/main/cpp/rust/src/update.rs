//! Self-update. Once a day every app (Android client and server, Linux Flatpak, Windows, headless server)
//! looks at the GitHub releases of the project, over Tor, and downloads its own asset when a newer version
//! is out. Installing it is left to the platform (PackageInstaller, `flatpak install`, a replace script).
//!
//! - The release list is the Atom feed (`releases.atom`): it has no API rate limit (Tor exits share the
//!   60 requests/hour of the unauthenticated API) and lists pre-releases too.
//! - A tag with a `-` (`v7.4.0-beta.1`) is a beta. Without the beta flag only plain versions count.
//! - The download is checked against the release's `SHA256SUMS`. TLS uses the webpki roots, not the OS store.
//! - State lives in one directory per app: `beta` (flag file), `last-check` (stamp), the verified download.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arti_client::TorClient;
use futures::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use sha2::{Digest, Sha256};
use tor_rtcompat::tokio::TokioRustlsRuntime;

const REPO: &str = "Yavuz-Kagan-Yadigar/Typeon";
/// Below a day, so a daily scheduler that fires a little early does not skip a whole day.
const CHECK_EVERY: Duration = Duration::from_secs(20 * 3600);
const MAX_ASSET_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SMALL_BYTES: u64 = 1024 * 1024;

pub type TorClientRt = TorClient<TokioRustlsRuntime>;
pub type Tor = Arc<TorClientRt>;

pub fn beta_enabled(dir: &Path) -> bool {
    dir.join("beta").exists()
}

pub fn set_beta(dir: &Path, on: bool) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    // A changed channel should be looked at now, not tomorrow.
    let _ = std::fs::remove_file(dir.join("last-check"));
    if on {
        std::fs::write(dir.join("beta"), b"")
    } else {
        match std::fs::remove_file(dir.join("beta")) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// `(major, minor, patch, pre)`; `pre` empty for a release. Orders like semver for the tags this project uses.
fn parse_version(v: &str) -> Option<(Vec<u64>, Option<String>)> {
    let v = v.trim().trim_start_matches('v');
    let (num, pre) = match v.split_once('-') {
        Some((n, p)) => (n, Some(p.to_string())),
        None => (v, None),
    };
    let nums: Option<Vec<u64>> = num.split('.').map(|p| p.parse().ok()).collect();
    Some((nums?, pre))
}

fn pre_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (mut x, mut y) = (a.split('.'), b.split('.'));
    loop {
        match (x.next(), y.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(p), Some(q)) => {
                let o = match (p.parse::<u64>(), q.parse::<u64>()) {
                    (Ok(m), Ok(n)) => m.cmp(&n),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                    (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                    _ => p.cmp(q),
                };
                if o.is_ne() {
                    return o;
                }
            }
        }
    }
}

/// True when `candidate` is a later version than `current`.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (Some((cn, cp)), Some((un, up))) = (parse_version(candidate), parse_version(current)) else { return false };
    match cn.cmp(&un) {
        std::cmp::Ordering::Equal => match (cp, up) {
            (None, Some(_)) => true,
            (Some(c), Some(u)) => pre_cmp(&c, &u).is_gt(),
            _ => false,
        },
        o => o.is_gt(),
    }
}

/// Tags in the feed that the channel allows, newest first. The feed also lists bare tags whose release is
/// not published yet (CI still building), so the caller falls back down this list.
fn pick_tags(atom: &str, beta: bool) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for part in atom.split("/releases/tag/").skip(1) {
        let tag = part.split(['"', '<', '\'']).next().unwrap_or("");
        if tag.is_empty() || parse_version(tag).is_none() || (!beta && tag.contains('-')) || tags.iter().any(|t| t == tag) {
            continue;
        }
        tags.push(tag.to_string());
    }
    tags.sort_by(|a, b| if is_newer(a, b) { std::cmp::Ordering::Less } else if is_newer(b, a) { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Equal });
    tags
}

/// Any single network step (connect, handshake, one read) that stalls this long fails the check; the next
/// tick retries on a fresh circuit. Without it a dead circuit held the check for the whole hour.
const IDLE: Duration = Duration::from_secs(120);

async fn idle<T, E: std::fmt::Display>(what: &str, f: impl std::future::Future<Output = Result<T, E>>) -> Result<T, String> {
    match tokio::time::timeout(IDLE, f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: stalled for {} s", IDLE.as_secs())),
    }
}

/// Plain HTTP/1.1 GET over Tor and TLS. Follows redirects to GitHub hosts only. The body goes to `sink`.
async fn get(tor: &Tor, url: &str, max: u64, sink: &mut (dyn FnMut(&[u8]) -> Result<(), String> + Send)) -> Result<(), String> {
    let mut url = url.to_string();
    for _ in 0..5 {
        let rest = url.strip_prefix("https://").ok_or("only https")?;
        let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
        let host = host.to_string();
        if !(host == "github.com" || host.ends_with(".github.com") || host.ends_with(".githubusercontent.com")) {
            return Err(format!("redirect to foreign host {host}"));
        }
        // A fresh circuit per request: a retry must not land on the same dead exit again, and update
        // traffic shares no circuit with anything else.
        let mut prefs = arti_client::StreamPrefs::new();
        prefs.set_isolation(arti_client::IsolationToken::new());
        let stream = idle(&format!("tor connect {host}"), tor.connect_with_prefs((host.as_str(), 443), &prefs)).await?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
        let mut tls = idle(&format!("tls {host}"), futures_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream)).await?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: typeon-updater\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        idle("write", tls.write_all(request.as_bytes())).await?;
        idle("write", tls.flush()).await?;
        let mut reader = BufReader::new(tls);

        let mut status = 0u16;
        let mut location = None;
        let mut length: Option<u64> = None;
        let mut chunked = false;
        let mut line = String::new();
        for i in 0..100 {
            line.clear();
            if idle("read", reader.read_line(&mut line)).await? == 0 {
                return Err("connection closed in headers".into());
            }
            let l = line.trim_end();
            if i == 0 {
                status = l.split(' ').nth(1).and_then(|s| s.parse().ok()).ok_or("bad status line")?;
                continue;
            }
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':') {
                let v = v.trim();
                match k.trim().to_ascii_lowercase().as_str() {
                    "location" => location = Some(v.to_string()),
                    "content-length" => length = v.parse().ok(),
                    "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                    _ => {}
                }
            }
        }
        if (300..400).contains(&status) {
            let loc = location.ok_or("redirect without location")?;
            url = if loc.starts_with('/') { format!("https://{host}{loc}") } else { loc };
            continue;
        }
        if status != 200 {
            return Err(format!("HTTP {status} for {url}"));
        }
        if length.is_some_and(|l| l > max) {
            return Err("response too large".into());
        }
        let mut total = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        let mut take = |n: usize, buf: &[u8], total: &mut u64| -> Result<(), String> {
            *total += n as u64;
            if *total > max {
                return Err("response too large".into());
            }
            sink(&buf[..n])
        };
        if chunked {
            loop {
                line.clear();
                idle("read", reader.read_line(&mut line)).await?;
                let size = u64::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16).map_err(|_| "bad chunk size")?;
                if size == 0 {
                    break;
                }
                let mut left = size;
                while left > 0 {
                    let want = left.min(buf.len() as u64) as usize;
                    idle("read", reader.read_exact(&mut buf[..want])).await?;
                    take(want, &buf, &mut total)?;
                    left -= want as u64;
                }
                line.clear();
                idle("read", reader.read_line(&mut line)).await?;
            }
        } else {
            loop {
                if length.is_some_and(|l| total >= l) {
                    break;
                }
                let n = idle("read", reader.read(&mut buf)).await?;
                if n == 0 {
                    break;
                }
                take(n, &buf, &mut total)?;
            }
            if length.is_some_and(|l| total != l) {
                return Err("truncated body".into());
            }
        }
        return Ok(());
    }
    Err("too many redirects".into())
}

async fn get_text(tor: &Tor, url: &str) -> Result<String, String> {
    let mut body = Vec::new();
    get(tor, url, MAX_SMALL_BYTES, &mut |b| {
        body.extend_from_slice(b);
        Ok(())
    })
    .await?;
    String::from_utf8(body).map_err(|e| e.to_string())
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
    Some(hex::encode(hasher.finalize()))
}

/// Looks for a newer release and downloads `asset` from it into `dir`. `asset` names the release file, with
/// `{v}` standing for the version (`typeon-client-{v}.apk`). Returns the verified file and its version, or
/// `None` when this app is up to date or was checked less than a day ago (`force` skips that wait).
pub async fn check(tor: &Tor, dir: &Path, current: &str, asset: &str, force: bool) -> Result<Option<(String, PathBuf)>, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let stamp = dir.join("last-check");
    if !force {
        let fresh = std::fs::metadata(&stamp)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < CHECK_EVERY);
        if fresh {
            return Ok(None);
        }
    }
    let beta = beta_enabled(dir);
    let atom = get_text(tor, &format!("https://github.com/{REPO}/releases.atom")).await?;
    // The newest release that has our asset. A tag without one (release not published yet, or a build that
    // left this platform out) is skipped, and the stamp is not written so the next tick looks again.
    // ponytail: a bare tag that never gets a release keeps the check hourly; fine at two small requests.
    let mut found = None;
    let mut skipped = false;
    for tag in pick_tags(&atom, beta).into_iter().filter(|t| is_newer(t, current)) {
        let version = tag.trim_start_matches('v').to_string();
        let name = asset.replace("{v}", &version);
        let base = format!("https://github.com/{REPO}/releases/download/{tag}");
        let sums = match get_text(tor, &format!("{base}/SHA256SUMS")).await {
            Ok(s) => s,
            Err(e) if e.starts_with("HTTP 404") => {
                skipped = true;
                continue;
            }
            Err(e) => return Err(e),
        };
        let want = sums.lines().find_map(|l| {
            let (hash, file) = l.split_once(char::is_whitespace)?;
            (file.trim().trim_start_matches('*') == name).then(|| hash.to_ascii_lowercase())
        });
        match want {
            Some(want) => {
                found = Some((tag, version, name, base, want));
                break;
            }
            None => skipped = true,
        }
    }
    let Some((tag, version, name, base, want)) = found else {
        if !skipped {
            let _ = std::fs::write(&stamp, b"");
        }
        return Ok(None);
    };

    let target = dir.join(format!("{version}-{name}"));
    if sha256_file(&target).as_deref() != Some(want.as_str()) {
        // Old downloads are dead weight once a newer one is wanted.
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let n = e.file_name();
                if n != "beta" && n != "last-check" {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        let part = dir.join(format!("{name}.part"));
        let mut file = std::fs::File::create(&part).map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        log::info!("update: downloading {name} ({tag})");
        let result = get(tor, &format!("{base}/{name}"), MAX_ASSET_BYTES, &mut |b| {
            hasher.update(b);
            std::io::Write::write_all(&mut file, b).map_err(|e| e.to_string())
        })
        .await;
        drop(file);
        let got = hex::encode(hasher.finalize());
        if let Err(e) = result.and_then(|()| if got == want { Ok(()) } else { Err(format!("{name}: SHA-256 mismatch")) }) {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
        std::fs::rename(&part, &target).map_err(|e| e.to_string())?;
    }
    // The switch may have gone off during a download that takes minutes: no beta for a stable-only app.
    if version.contains('-') && !beta_enabled(dir) {
        return Ok(None);
    }
    let _ = std::fs::write(&stamp, b"");
    log::info!("update: {tag} ready at {}", target.display());
    Ok(Some((version, target)))
}

/// Blocking form for the client apps (JNI, desktop): uses the core's running Tor client.
pub fn check_blocking(dir: &str, current: &str, asset: &str, force: bool) -> Result<Option<(String, PathBuf)>, String> {
    let tor = crate::catch_panic(|| crate::core_lock_read().tor.as_ref().map(|t| t.client.clone()))
        .map_err(|e| e)?
        .ok_or("Tor is not running")?;
    crate::RUNTIME.block_on(async {
        tokio::time::timeout(Duration::from_secs(3600), check(&tor, Path::new(dir), current, asset, force))
            .await
            .map_err(|_| "update check timed out".to_string())?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(is_newer("7.4.0", "7.3.1"));
        assert!(is_newer("v7.10.0", "7.9.9"));
        assert!(!is_newer("7.3.1", "7.3.1"));
        assert!(is_newer("7.4.0", "7.4.0-beta.2"));
        assert!(!is_newer("7.4.0-beta.2", "7.4.0"));
        assert!(is_newer("7.4.0-beta.10", "7.4.0-beta.9"));
        assert!(is_newer("7.4.0-beta.1", "7.3.1"));
        assert!(!is_newer("junk", "7.3.1"));
    }

    #[test]
    fn channel() {
        let atom = r#"<link href="https://github.com/x/y/releases/tag/v7.4.0-beta.1"/>
            <link href="https://github.com/x/y/releases/tag/v7.3.1"/><link href="https://github.com/x/y/releases/tag/v7.3.0"/>"#;
        assert_eq!(pick_tags(atom, false), ["v7.3.1", "v7.3.0"]);
        assert_eq!(pick_tags(atom, true), ["v7.4.0-beta.1", "v7.3.1", "v7.3.0"]);
    }

    /// Real GitHub over real Tor: `TYPEON_UPDATE_LIVE=<dir> cargo test --lib update::tests::live -- --ignored`.
    #[test]
    #[ignore]
    fn live() {
        let dir = PathBuf::from(std::env::var("TYPEON_UPDATE_LIVE").expect("TYPEON_UPDATE_LIVE"));
        crate::RUNTIME.block_on(async {
            let cfg = arti_client::config::TorClientConfigBuilder::from_directories(dir.join("state"), dir.join("cache"))
                .build()
                .unwrap();
            let client = TorClient::with_runtime(TokioRustlsRuntime::current().unwrap())
                .config(cfg)
                .create_bootstrapped()
                .await
                .unwrap();
            let tor = Arc::new(client);
            let beta = std::env::var("TYPEON_UPDATE_BETA").is_ok();
            set_beta(&dir.join("u"), beta).unwrap();
            let asset = std::env::var("TYPEON_UPDATE_ASSET").unwrap_or("typeon-server.service".into());
            let got = check(&tor, &dir.join("u"), "0.0.1", &asset, true).await.unwrap();
            println!("{got:?}");
            assert!(got.is_some());
        });
    }
}
