//! Typeon for Linux — a native desktop client that joins an existing Typeon
//! account as a **secondary device**.
//!
//! It is not a reimplementation. The entire protocol — hybrid post-quantum
//! handshake, double ratchet, SQLite archive, libp2p and Tor transport,
//! multi-device linking — is the exact crate the Android app ships, linked in
//! process (see `Cargo.toml` and that crate's `api` module). What lives here is
//! the user interface, the local vault, and the desktop plumbing the phone gets
//! from Android services.
//!
//! It deliberately cannot create an account. See `ui::onboarding`.

// Windows release: a GUI program, no console window next to it. Debug builds
// and the `console` feature keep it so `RUST_LOG=info` output is visible.
#![cfg_attr(all(windows, not(debug_assertions), not(feature = "console")), windows_subsystem = "windows")]

#[macro_use]
mod i18n;
mod app;
#[cfg_attr(windows, path = "audio_win.rs")]
mod audio;
mod call_media;
mod core;
mod font;
#[cfg_attr(windows, path = "keyring_win.rs")]
mod keyring;
mod prefs;
mod qr;
mod secrets;
mod theme;
mod ui;
mod update;
mod util;
#[cfg(windows)]
mod win;

use i18n::t;
use std::path::PathBuf;

use adw::prelude::*;
use gtk::glib;

const APP_ID: &str = "com.p2p.messenger.Typeon";

fn main() -> glib::ExitCode {
    // Show the core's `log` output. Without this, connection, ratchet and
    // server diagnostics were dropped silently. The desktop had no
    // equivalent of the logcat output on Android.
    // Debug builds default to `warn`, release builds log nothing. `RUST_LOG=info` shows more in either.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(if cfg!(debug_assertions) { "warn" } else { "off" })).init();

    // GTK closures unwind into C and abort; leave a trace before that happens.
    // (Only the file and line are written, never the panic message.)
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        eprintln!("typeon: panic at {location}");
        let log = glib::user_data_dir().join("typeon").join("crash.log");
        if let Ok(mut file) = util::owner_only(std::fs::OpenOptions::new().create(true).append(true)).open(log) {
            use std::io::Write;
            let _ = writeln!(file, "{} panic at {location}", util::now_ms());
        }
    }));

    let mut builder = adw::Application::builder().application_id(APP_ID);
    // Typeon is single-instance by default: launching it again raises the
    // window you already have. `TYPEON_ALLOW_MULTIPLE=1` opts out, which is
    // what you want when running a second profile via `XDG_DATA_HOME` — two
    // identities, two data directories, two windows.
    // Only with an explicit `XDG_DATA_HOME`: two processes on the SAME data
    // directory would corrupt the archive.
    if std::env::var("TYPEON_ALLOW_MULTIPLE").as_deref() == Ok("1")
        && std::env::var_os("XDG_DATA_HOME").is_some()
    {
        builder = builder.flags(gtk::gio::ApplicationFlags::NON_UNIQUE);
    }
    let application = builder.build();

    application.connect_activate(activate);
    // Windows: the autostart entry starts Typeon straight into the tray. The
    // flag is ours, not GApplication's, so it is taken out of argv here.
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == win::BACKGROUND_ARG) {
            START_HIDDEN.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        return application.run_with_args(&args[..1]);
    }
    #[cfg(not(windows))]
    application.run()
}

/// Decrypted attachment copies do not outlive the session. The directory
/// itself stays: the core writes into it.
fn sweep_plain_cache(data_dir: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(data_dir.join("attachments/plain_cache")) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Holds an OS lock (`flock` / `LockFileEx`) on `instance.lock` for the whole
/// process. False only when another process holds it.
static INSTANCE_LOCK: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

fn lock_data_dir(data_dir: &std::path::Path) -> bool {
    if INSTANCE_LOCK.lock().map_or(false, |l| l.is_some()) {
        return true;
    }
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(data_dir.join("instance.lock"))
    {
        Ok(file) => file,
        Err(error) => {
            eprintln!("typeon: no instance lock: {error}");
            return true;
        }
    };
    match file.try_lock() {
        Ok(()) => {
            if let Ok(mut l) = INSTANCE_LOCK.lock() {
                *l = Some(file);
            }
            true
        }
        Err(std::fs::TryLockError::WouldBlock) => false,
        Err(std::fs::TryLockError::Error(error)) => {
            eprintln!("typeon: no instance lock: {error}");
            true
        }
    }
}

/// Erases the data directory after `core::shutdown`. Windows cannot delete an open file, and the
/// instance lock is held open for the whole process, so it is released first. Then every file is
/// removed one by one, so a file still held (e.g. by an arti task) does not keep the database and
/// the keys on disk, and the tree goes last, with short retries for files closed mid-walk.
pub(crate) fn erase_data_dir(data_dir: &std::path::Path) -> std::io::Result<()> {
    if let Ok(mut l) = INSTANCE_LOCK.lock() {
        l.take();
    }
    fn remove_files(dir: &std::path::Path) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                remove_files(&path);
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    let mut result = std::fs::remove_dir_all(data_dir);
    for wait_ms in [200, 500, 1000] {
        if result.is_ok() || !data_dir.exists() {
            return Ok(());
        }
        remove_files(data_dir);
        std::thread::sleep(std::time::Duration::from_millis(wait_ms));
        result = std::fs::remove_dir_all(data_dir);
    }
    result
}

/// Windows `--background`: the first window stays hidden in the tray.
#[cfg(windows)]
static START_HIDDEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn activate(application: &adw::Application) {
    // A second `activate` (someone launching Typeon again) should raise the
    // existing window, not build a whole second stack on top of the same
    // database.
    if let Some(existing) = application.active_window() {
        existing.present();
        return;
    }
    call_media::prewarm();

    let data_dir = data_directory();
    // 0700 on the one directory everything lives under: settings, the
    // database and decrypted attachments are then closed to other local users
    // whatever mode the files inside were created with.
    let created = std::fs::create_dir_all(&data_dir).and_then(|_| util::set_mode(&data_dir, 0o700));
    if let Err(error) = created {
        eprintln!("typeon: cannot create {}: {error}", data_dir.display());
        return;
    }
    // Before the first translated text. Arabic also mirrors the layout.
    i18n::apply(prefs::Prefs::load(&data_dir).language.as_deref());

    // Backstop for single-instance mode, which needs a session bus (GLib on
    // Windows falls back to non-unique without one). Two cores on one data
    // directory would share a PeerId and race on ratchet state and the archive.
    if !lock_data_dir(&data_dir) {
        show_blocking_error(
            application,
            t("Typeon is already running"),
            t("Another Typeon process is using this profile. Open it from its window or the tray."),
        );
        return;
    }
    // A crash or kill skips the shutdown-time sweep below; clear what it left.
    sweep_plain_cache(&data_dir);

    // Hard requirement, checked before the database is even opened: on Linux
    // this device's secret keys are sealed with a key held in KDE Wallet or
    // GNOME Keyring. With neither available there is no safe place to put that
    // key, so Typeon says so and stops rather than quietly degrading to a file
    // anyone running as this user could read.
    // The probe can block for many seconds on a locked wallet, so it runs off
    // the GTK thread; `hold` keeps the app alive until the window exists, and
    // STARTING stops a second `activate` building a second stack.
    static STARTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if STARTING.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    let hold = application.hold();
    // a window has to exist while the probe blocks — that wait is
    // exactly when the user is staring at the launcher. A bare spinner
    // splash is enough; the real boot (below, in the probe's completion
    // handler) replaces it.
    let splash = adw::Window::builder()
        .application(application)
        .title("Typeon")
        .default_width(280)
        .default_height(140)
        .resizable(false)
        .build();
    let splash_status = adw::StatusPage::builder()
        .title(t("Starting Typeon"))
        .description(t("Checking the system keyring…"))
        .build();
    let splash_spinner = gtk::Spinner::new();
    splash_spinner.set_spinning(true);
    splash_status.set_child(Some(&splash_spinner));
    splash.set_content(Some(&splash_status));
    splash.present();
    let application_owned = application.clone();
    app::run_in_background(keyring::ensure_available, move |probe| {
    // Only the probe is guarded: a later activate (window closed) builds again.
    STARTING.store(false, std::sync::atomic::Ordering::Release);
    let _hold = hold;
    let application = &application_owned;
    // The splash has served its purpose — closed on the happy and the error
    // path alike (the UI-test early returns close it first thing, too).
    splash.close();
    let backend = match probe {
        Ok(backend) => backend,
        Err(reason) => {
            eprintln!("typeon: {} — {}", reason.heading(), reason.detail());
            show_blocking_error(application, &reason.heading(), &reason.detail());
            return;
        }
    };

    // The database is encrypted under a key from the vault, so it is opened
    // in `ui::onboarding`, once the vault is.

    let preferences = prefs::Prefs::load(&data_dir);
    let app = app::App::new(application.clone(), data_dir, preferences, backend);

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Typeon")
        .default_width(1080)
        .default_height(720)
        .build();

    let toasts = adw::ToastOverlay::new();
    window.set_content(Some(&toasts));

    *app.window.borrow_mut() = Some(window.clone());
    *app.toasts.borrow_mut() = Some(toasts.clone());

    // Android flushes the delivery-retry queue whenever the app comes to the
    // foreground (`P2PApplication`). The desktop equivalent is the window
    // becoming active. Without it, anything waiting on the exponential backoff
    // can sit for up to two minutes even though the user is right there with a
    // working connection — which is exactly what "sync arrives very late"
    // feels like.
    window.connect_is_active_notify(|window| {
        if window.is_active() {
            // Takes the core lock (a poll round can hold it for seconds):
            // never on the GTK thread, and one at a time.
            static BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !BUSY.swap(true, std::sync::atomic::Ordering::AcqRel) {
                std::thread::spawn(|| {
                    core::retry_all_pending_now();
                    BUSY.store(false, std::sync::atomic::Ordering::Release);
                });
            }
        }
    });

    // Deferred read-state must not be lost on exit. `application.quit()`
    // (SIGTERM, self-update, menu Quit) emits no close-request, so the flush
    // and sweep run at shutdown, on every platform.
    {
        let app = app.clone();
        application.connect_shutdown(move |_| {
            app.prefs.borrow_mut().flush();
            sweep_plain_cache(&app.data_dir);
        });
    }
    // Windows: closing the window keeps Typeon running in the tray (the tray
    // icon in win.rs; a click on it presents this hidden window). Quit is in
    // the main menu; the close-time work then runs at shutdown.
    #[cfg(windows)]
    {
        window.set_hide_on_close(true);
        std::mem::forget(application.hold());
        {
            let app = app.clone();
            window.connect_close_request(move |_| {
                app.prefs.borrow_mut().flush();
                glib::Propagation::Proceed
            });
        }
        application.connect_shutdown(|_| win::remove_tray());
        // Our own tray icon (Open / Quit menu), there from the start. GLib's
        // notification backend adds its icon only when a notification shows.
        {
            let window = window.clone();
            let application = application.clone();
            let app = app.clone();
            win::install_tray(move |action| match action {
                win::TrayAction::Open => window.present(),
                win::TrayAction::Quit => application.quit(),
                // Logoff / shutdown: the process is killed once this returns,
                // so the shutdown work runs here, synchronously.
                win::TrayAction::EndSession => {
                    // Runs inside a Win32 dispatch: never panic on a live borrow.
                    if let Ok(mut prefs) = app.prefs.try_borrow_mut() {
                        prefs.flush();
                    }
                    sweep_plain_cache(&app.data_dir);
                    core::announce_offline();
                    win::remove_tray();
                }
            });
        }
    }

    // Peers stop dialing this device until it connects again (phones kept
    // building Tor circuits to a closed desktop). The goodbye can wait for
    // the core lock and then up to 2.5 s: hide the windows first, so Quit
    // does not look stuck.
    application.connect_shutdown(|application| {
        for window in application.windows() {
            window.set_visible(false);
        }
        if let Some(display) = gtk::gdk::Display::default() {
            display.flush();
        }
        core::announce_offline();
    });
    // Session logout sends SIGTERM: quit cleanly, so the goodbye goes out.
    #[cfg(unix)]
    {
        let application = application.clone();
        glib::unix_signal_add_local(15 /* SIGTERM */, move || {
            application.quit();
            glib::ControlFlow::Break
        });
    }

    ui::settings::apply_theme(&app);
    #[cfg(windows)]
    let hidden = START_HIDDEN.swap(false, std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(windows))]
    let hidden = false;
    if !hidden {
        window.present();
    }

    // Development aid: render a conversation's worth of sample bubbles without
    // needing a linked device and a real peer. Bubble sizing is fiddly enough
    // (see `chat::BUBBLE_MAX_WIDTH`) to be worth being able to look at directly.
    //   TYPEON_UI_TEST=bubbles TYPEON_ALLOW_MULTIPLE=1 typeon
    #[cfg(debug_assertions)]
    match std::env::var("TYPEON_UI_TEST").as_deref() {
        Ok("bubbles") => {
            toasts.set_child(Some(&ui::chat::demo_bubbles()));
            return;
        }
        Ok("settings") => {
            ui::settings::present(&app);
            return;
        }
        Ok("prompt") => {
            // Exercises `widgets::dialog_field`, the same spacing the unlock
            // prompt uses.
            ui::dialogs::add_contact(&app);
            return;
        }
        Ok("settings-appearance") => {
            ui::settings::present_page(&app, Some("appearance"));
            return;
        }
        _ => {}
    }

    // Decides between first-run linking, resuming an unfinished pairing, and
    // going straight to the main window.
    ui::onboarding::start(&app, &toasts);
    });
}

/// `$XDG_DATA_HOME/typeon`. The core is handed this directory and puts its
/// database, attachment blobs and Tor state inside it, exactly as it uses
/// Android's `filesDir`.
fn data_directory() -> PathBuf {
    glib::user_data_dir().join("typeon")
}

/// A window whose only job is to explain why Typeon will not start. Shown
/// instead of the main UI, never alongside it — closing it quits.
fn show_blocking_error(application: &adw::Application, heading: &str, detail: &str) {
    let quit = gtk::Button::builder()
        .label(t("Quit"))
        .halign(gtk::Align::Center)
        .build();
    quit.add_css_class("pill");
    quit.add_css_class("suggested-action");

    let status = adw::StatusPage::builder()
        .icon_name("channel-insecure-symbolic")
        .title(heading)
        .description(detail)
        .child(&quit)
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(
        &gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&status)
            .build(),
    ));

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Typeon")
        .default_width(620)
        .default_height(520)
        .content(&toolbar)
        .build();

    let application = application.clone();
    quit.connect_clicked(move |_| application.quit());
    window.present();
}
