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

mod app;
mod audio;
mod call_media;
mod core;
mod font;
mod keyring;
mod prefs;
mod qr;
mod secrets;
mod theme;
mod ui;
mod util;

use std::path::PathBuf;

use adw::prelude::*;
use gtk::glib;

const APP_ID: &str = "com.p2p.messenger.Typeon";

fn main() -> glib::ExitCode {
    // Çekirdeğin `log` çıktısını görünür kıl. Bu olmadan bağlantı, ratchet
    // ve sunucu akışına dair her teşhis satırı sessizce kayboluyordu —
    // Android'de logcat'e giden bilginin masaüstünde hiçbir karşılığı yoktu.
    // Varsayılan `warn`: normal çalışmada sessiz, `RUST_LOG=info` ile açılır.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    // GTK closures unwind into C and abort; leave a trace before that happens.
    // (Message text is never in a panic payload we write: location + type only.)
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        eprintln!("typeon: panic at {location}");
        let log = glib::user_data_dir().join("typeon").join("crash.log");
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
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
    application.run()
}

fn activate(application: &adw::Application) {
    // A second `activate` (someone launching Typeon again) should raise the
    // existing window, not build a whole second stack on top of the same
    // database.
    if let Some(existing) = application.active_window() {
        existing.present();
        return;
    }

    let data_dir = data_directory();
    // 0700 on the one directory everything lives under: settings, the
    // database and decrypted attachments are then closed to other local users
    // whatever mode the files inside were created with.
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let created = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&data_dir)
        .and_then(|_| std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)));
    if let Err(error) = created {
        eprintln!("typeon: cannot create {}: {error}", data_dir.display());
        return;
    }

    // Hard requirement, checked before the database is even opened: this
    // device's secret keys are sealed with a key held in KDE Wallet or GNOME
    // Keyring. With neither available there is no safe place to put that key,
    // so Typeon says so and stops rather than quietly degrading to a file
    // anyone running as this user could read.
    // H134: the probe can block for many seconds on a locked wallet, so it
    // runs off the GTK thread; `hold` keeps the app alive until the window
    // exists, and STARTING stops a second `activate` building a second stack.
    static STARTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if STARTING.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    let hold = application.hold();
    // H134: a window has to exist while the probe blocks — that wait is
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
        .title("Starting Typeon")
        .description("Checking the system keyring…")
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

    // Deferred read-state must not be lost on exit.
    {
        let app = app.clone();
        window.connect_close_request(move |_| {
            app.prefs.borrow_mut().flush();
            // Decrypted attachment copies do not outlive the session. The
            // directory itself stays: the core writes into it.
            if let Ok(entries) = std::fs::read_dir(app.data_dir.join("attachments/plain_cache")) {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
            glib::Propagation::Proceed
        });
    }

    ui::settings::apply_theme(&app);
    window.present();

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
        .label("Quit")
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
