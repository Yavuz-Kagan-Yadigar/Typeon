//! Self-update for the Flatpak and Windows builds. The core checks GitHub releases once a day over Tor and
//! downloads the verified asset (see `p2p_messenger::update`); this side installs it and restarts Typeon.
//!
//! - Flatpak: `flatpak install --bundle` on the host through `flatpak-spawn` (needs the
//!   `org.freedesktop.Flatpak` talk-name), then `flatpak run` again.
//! - Windows: a hidden PowerShell waits for this process to exit, unpacks the zip over the install
//!   directory and starts Typeon again in the tray.
//!
//! Not installed during a call; the download waits for the next hourly tick.

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
    /// A verified download that waits for the call to end.
    static PENDING: RefCell<Option<(String, PathBuf)>> = const { RefCell::new(None) };
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

fn tick(app: &Rc<App>) {
    if let Some((version, path)) = PENDING.with(|p| p.borrow_mut().take()) {
        return install(app, version, path);
    }
    let app = app.clone();
    app::run_in_background(
        || p2p_messenger::update::check_blocking(&dir().to_string_lossy(), env!("CARGO_PKG_VERSION"), ASSET, false),
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
    log::info!("update: installing {version} from {}", path.display());
    let app = app.clone();
    app::run_in_background(
        move || platform_install(&path),
        move |result| match result {
            // The new build is started by the installer side; this one leaves.
            Ok(()) => app.application.quit(),
            Err(error) => {
                log::warn!("update: {error}");
                app.toast(&format!("Update failed: {error}"));
            }
        },
    );
}

#[cfg(not(windows))]
fn platform_install(bundle: &Path) -> Result<(), String> {
    use std::process::Command;
    // The installation this sandbox runs from: a user install must not ask for root, a system one has to.
    let info = std::fs::read_to_string("/.flatpak-info").unwrap_or_default();
    let scope = if info.lines().any(|l| l.starts_with("app-path=/var/") || l.starts_with("app-path=/usr/")) {
        "--system"
    } else {
        "--user"
    };
    let status = Command::new("flatpak-spawn")
        .args(["--host", "flatpak", "install", scope, "-y", "--noninteractive", "--reinstall", "--bundle"])
        .arg(bundle)
        .status()
        .map_err(|e| format!("flatpak-spawn: {e}"))?;
    if !status.success() {
        return Err(format!("flatpak install exited with {status}"));
    }
    let _ = std::fs::remove_file(bundle);
    // Single instance: the new one must start after this one is gone.
    Command::new("flatpak-spawn")
        .args([
            "--host",
            "sh",
            "-c",
            "i=0; while [ $i -lt 60 ] && flatpak ps --columns=application | grep -qx com.p2p.messenger.Typeon; \
             do sleep 1; i=$((i+1)); done; exec flatpak run com.p2p.messenger.Typeon",
        ])
        .spawn()
        .map_err(|e| format!("restart: {e}"))?;
    Ok(())
}

#[cfg(windows)]
fn platform_install(zip: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // ...\Typeon\bin\typeon.exe; the zip holds the same `Typeon\` tree.
    let root = exe.parent().and_then(Path::parent).ok_or("no install dir")?;
    let quote = |p: &Path| format!("'{}'", p.to_string_lossy().replace('\'', "''"));
    let staging = dir().join("unpacked");
    let script = format!(
        "$ErrorActionPreference='Stop'; Wait-Process -Id {pid} -ErrorAction SilentlyContinue; \
         if (Test-Path {s}) {{ Remove-Item -Recurse -Force {s} }}; \
         Expand-Archive -Force -LiteralPath {z} -DestinationPath {s}; \
         Copy-Item -Recurse -Force (Join-Path {s} 'Typeon\\*') {r}; \
         Remove-Item -Recurse -Force {s}; Remove-Item -Force {z}; \
         Start-Process -FilePath {e} -ArgumentList '{bg}'",
        pid = std::process::id(),
        s = quote(&staging),
        z = quote(zip),
        r = quote(root),
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
