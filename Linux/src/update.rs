//! Self-update for the Flatpak and Windows builds. The core checks GitHub releases once a day over Tor and
//! downloads the verified asset (see `p2p_messenger::update`); this side installs it and restarts Typeon.
//!
//! - Flatpak: `flatpak install --bundle` on the host through `flatpak-spawn` (needs the
//!   `org.freedesktop.Flatpak` talk-name), then `flatpak run` again.
//! - Windows: a hidden PowerShell waits for this process to exit, unpacks the zip over the install
//!   directory and starts Typeon again in the tray.
//!
//! Not installed during a call; the download waits for the next hourly tick.

use crate::i18n::t;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use gtk::glib;
use gtk::prelude::*;

use crate::app::{self, App};

#[cfg(windows)]
const ASSET: &str = "typeon-windows-{v}.zip";
#[cfg(not(windows))]
const ASSET: &str = "typeon-linux-{v}.flatpak";

pub fn dir() -> PathBuf {
    glib::user_data_dir().join("typeon").join("update")
}

thread_local! {
    /// A verified download that waits for the call to end or for the user.
    static PENDING: RefCell<Option<(String, PathBuf)>> = const { RefCell::new(None) };
    /// The "Restart to update" toast is on screen.
    static ASKING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Marker left by a failed Windows install, so that version is not retried daily.
fn failed_marker(version: &str) -> PathBuf {
    dir().join(format!("failed-{version}"))
}

/// The only builds with an installer path. A plain `cargo run` must never replace itself.
fn supported() -> bool {
    cfg!(windows) || Path::new("/.flatpak-info").exists()
}

pub fn start(app: &Rc<App>) {
    if !supported() {
        return;
    }
    let first = app.clone();
    // First look once Tor had time to bootstrap, then hourly; the core keeps it to one real check a day.
    glib::timeout_add_seconds_local_once(300, move || tick(&first));
    let app = app.clone();
    glib::timeout_add_seconds_local(3600, move || {
        tick(&app);
        glib::ControlFlow::Continue
    });
}

/// Installed version, newest on GitHub, and what the core is doing (the core's `status` file).
pub fn status_text() -> String {
    let installed = env!("CARGO_PKG_VERSION");
    let raw = std::fs::read_to_string(dir().join("status")).unwrap_or_default();
    let raw = raw.trim();
    let (github, state) = raw.split_once(' ').unwrap_or((if raw.is_empty() { "-" } else { raw }, ""));
    let word = if raw.is_empty() {
        t("Not checked yet").to_string()
    } else if let Some(e) = state.strip_prefix("error") {
        tf!("Last check failed: {}", e.trim())
    } else if let Some(mb) = state.strip_prefix("downloading") {
        tf!("Downloading… {} MB", mb.trim())
    } else if github == installed {
        t("Up to date").to_string()
    } else if state == "waiting" {
        t("New release is still being built").to_string()
    } else if state == "ready" {
        t("Downloaded, installing").to_string()
    } else {
        t("Up to date").to_string()
    };
    tf!("Installed: {} · GitHub: {} · {}", installed, github, word)
}

/// Runs a check now, for a changed channel (`set_beta` removed the day stamp).
pub fn tick(app: &Rc<App>) {
    if let Some((version, path)) = PENDING.with(|p| p.borrow_mut().take()) {
        return install(app, version, path);
    }
    let app = app.clone();
    app::run_in_background(
        || p2p_messenger::update::check_blocking(&dir().to_string_lossy(), env!("CARGO_PKG_VERSION"), ASSET, false, true),
        move |result| match result {
            Ok(Some((version, path))) => install(&app, version, path),
            Ok(None) => {}
            Err(error) => log::warn!("update check: {error}"),
        },
    );
}

fn install(app: &Rc<App>, version: String, path: PathBuf) {
    if crate::ui::call::active() {
        PENDING.with(|p| *p.borrow_mut() = Some((version, path)));
        return;
    }
    if failed_marker(&version).exists() {
        log::warn!("update: {version} failed to install before; waiting for a newer release");
        return;
    }
    // A visible window may hold a draft, a recording or an open dialog: ask.
    // Hidden (Windows tray) installs at once.
    if app.window().is_some_and(|window| window.is_visible()) {
        PENDING.with(|p| *p.borrow_mut() = Some((version.clone(), path)));
        if !ASKING.with(|a| a.replace(true)) {
            ask_restart(app, &version);
        }
        return;
    }
    install_now(app, version, path);
}

/// One toast until it is dismissed; a dismissed one is asked again on the next hourly tick.
fn ask_restart(app: &Rc<App>, version: &str) {
    let Some(overlay) = app.toasts.borrow().clone() else {
        ASKING.with(|a| a.set(false));
        return;
    };
    let toast = adw::Toast::builder()
        .title(glib::markup_escape_text(&tf!("Typeon {} is ready to install", version)).as_str())
        .button_label(t("Restart"))
        .timeout(0)
        .build();
    let restart = app.clone();
    toast.connect_button_clicked(move |_| {
        if let Some((version, path)) = PENDING.with(|p| p.borrow_mut().take()) {
            if crate::ui::call::active() {
                PENDING.with(|p| *p.borrow_mut() = Some((version, path)));
            } else {
                install_now(&restart, version, path);
            }
        }
    });
    toast.connect_dismissed(|_| ASKING.with(|a| a.set(false)));
    overlay.add_toast(toast);
}

fn install_now(app: &Rc<App>, version: String, path: PathBuf) {
    log::info!("update: installing {version} from {}", path.display());
    let app = app.clone();
    app::run_in_background(
        move || platform_install(&path, &version),
        move |result| match result {
            // The new build is started by the installer side; this one leaves.
            Ok(()) => app.application.quit(),
            Err(error) => {
                log::warn!("update: {error}");
                app.toast(&tf!("Update failed: {}", error));
            }
        },
    );
}

#[cfg(not(windows))]
fn platform_install(bundle: &Path, _version: &str) -> Result<(), String> {
    use std::process::Command;
    // The installation this sandbox runs from: a user install must not ask for root, a system one has to.
    let info = std::fs::read_to_string("/.flatpak-info").unwrap_or_default();
    let scope = if info.lines().any(|l| l.starts_with("app-path=/var/") || l.starts_with("app-path=/usr/")) {
        "--system"
    } else {
        "--user"
    };
    let commit = || {
        Command::new("flatpak-spawn")
            .args(["--host", "flatpak", "info", scope, "--show-commit", "com.p2p.messenger.Typeon"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    let before = commit();
    let status = Command::new("flatpak-spawn")
        .args(["--host", "flatpak", "install", scope, "-y", "--noninteractive", "--reinstall", "--bundle"])
        .arg(bundle)
        .status()
        .map_err(|e| format!("flatpak-spawn: {e}"))?;
    // Seen on flatpak 1.18: the new commit is deployed, then removing the old deploy fails with
    // "Directory not empty" and the exit code says failure. What counts is the active commit.
    if !status.success() && commit() == before {
        return Err(tf!("flatpak install exited with {}", status));
    }
    let _ = std::fs::remove_file(bundle);
    // Single instance: the new one must start after this one is gone.
    Command::new("flatpak-spawn")
        .args([
            "--host",
            "sh",
            "-c",
            // Detached on the host: flatpak-spawn returns at once, so this sandbox can end. A waiting
            // flatpak-spawn kept the old instance listed by `flatpak ps` for as long as the new one ran.
            "setsid sh -c 'i=0; while [ $i -lt 60 ] && flatpak ps --columns=application | grep -qx com.p2p.messenger.Typeon; \
             do sleep 1; i=$((i+1)); done; exec flatpak run com.p2p.messenger.Typeon' >/dev/null 2>&1 </dev/null &",
        ])
        .spawn()
        .map_err(|e| tf!("restart: {}", e))?;
    Ok(())
}

#[cfg(windows)]
fn platform_install(zip: &Path, version: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // ...\Typeon\bin\typeon.exe; the zip holds the same `Typeon\` tree.
    let root = exe.parent().and_then(Path::parent).ok_or(t("no install dir"))?;
    // Unpacked under Program Files, say: the copy would fail after this process quit.
    let probe = root.join(".typeon-update-probe");
    std::fs::write(&probe, b"").map_err(|e| tf!("install folder is not writable: {}", e))?;
    let _ = std::fs::remove_file(&probe);
    let quote = |p: &Path| format!("'{}'", p.to_string_lossy().replace('\'', "''"));
    let staging = dir().join("unpacked");
    // Typeon starts again whatever happens (finally); a failed copy leaves a
    // marker so this version is not retried every day.
    let script = format!(
        "$ErrorActionPreference='Stop'; Wait-Process -Id {pid} -ErrorAction SilentlyContinue; \
         try {{ \
         if (Test-Path {s}) {{ Remove-Item -Recurse -Force {s} }}; \
         Expand-Archive -Force -LiteralPath {z} -DestinationPath {s}; \
         Copy-Item -Recurse -Force (Join-Path {s} 'Typeon\\*') {r}; \
         Remove-Item -Recurse -Force {s}; Remove-Item -Force {z} \
         }} catch {{ Set-Content -LiteralPath {f} -Value $_.ToString() }} \
         finally {{ Start-Process -FilePath {e} -ArgumentList '{bg}' }}",
        pid = std::process::id(),
        s = quote(&staging),
        z = quote(zip),
        r = quote(root),
        f = quote(&failed_marker(version)),
        e = quote(&exe),
        bg = crate::win::BACKGROUND_ARG,
    );
    std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("powershell: {e}"))?;
    Ok(())
}
