//! Launch sequence and device linking.
//!
//! This client can be a full account in its own right or a secondary device on
//! an existing one — the same three choices the Android app offers on first
//! launch:
//!
//! * **New account** — generates an identity that belongs to this computer.
//!   Other devices can later be linked *to* it.
//! * **Link to an existing device** (spec §1.5) — generates its own keypair,
//!   shows a device-link QR, and waits to be adopted. The other device signs a
//!   `DeviceAdd`, ships a full sync and announces us to every contact; its
//!   secret key never moves. Afterwards the two are independent — contacts fan
//!   messages out to both.
//! * **Restore from a recovery file** — rebuilds a previous identity from its
//!   encrypted backup.
//!
//! Routing on launch:
//!   no vault                     -> welcome (three choices)
//!   vault, awaiting_link, unlinked -> unlock -> link QR (resumes a pairing)
//!   otherwise                    -> unlock -> main window

use std::path::Path;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::app::{self, App};
use crate::core;
use crate::qr;
use crate::secrets::{self, Vault};
use crate::ui;
use zeroize::Zeroize;

/// A passphrase String that zeroizes itself when dropped — including on the
/// `?` early returns of the restore/unlock flows, where a manual
/// `passphrase.zeroize()` before every exit would be easy to forget.
struct WipeOnDrop(String);

impl std::ops::Deref for WipeOnDrop {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl Drop for WipeOnDrop {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Entry point from `main`. Decides which of the three routes above applies and
/// drives it to the main window.
pub fn start(app: &Rc<App>, host: &adw::ToastOverlay) {
    if !secrets::exists(&app.data_dir) {
        host.set_child(Some(&framed(&welcome_page(app, host))));
        return;
    }

    // A vault exists. Unlock it (prompting only if it is passphrase-sealed),
    // hand the secrets to the core, then continue by link state.
    //
    // Separate clones for the continuation: `unlock` borrows its first two
    // arguments for the duration of the call, so the closure cannot move the
    // same bindings it is handed.
    let app_after = app.clone();
    let host_after = host.clone();
    unlock(app, host, move |vault| {
        if !core::init_database(&app_after.data_dir.to_string_lossy(), &vault.skipped_key) {
            fatal(
                &app_after,
                &host_after,
                "Could not open the database",
                "The vault opened but the database did not. Check that the data directory is \
                 writable and has free space. If the database was made with another vault it \
                 cannot be read any more.",
            );
            return;
        }
        if !core::load_secret_bundle(&vault.identity_bundle) {
            fatal(
                &app_after,
                &host_after,
                "Could not load this device's keys",
                "The vault opened but the core rejected the key bundle. The file is probably \
                 damaged — remove the data directory and link this device again.",
            );
            return;
        }
        finish_boot(&app_after, &host_after, vault);
    });
}

// --- route 1: first run ---

fn welcome_page(app: &Rc<App>, host: &adw::ToastOverlay) -> gtk::Widget {
    let name_row = adw::EntryRow::builder().title("Device name").build();
    name_row.set_text(&hostname_guess());

    let passphrase_row = adw::PasswordEntryRow::builder()
        .title("Extra passphrase (optional)")
        .build();

    let description = format!(
        "This device's keys are sealed with a key held in {}, so copying the file off this \
         machine is not enough to open it. Leave the passphrase empty for a phone-like launch \
         with no prompt; setting one adds a second factor on top of the wallet (Argon2id) and \
         is asked for every launch.",
        app.keyring_backend.display_name()
    );

    let options = adw::PreferencesGroup::builder()
        .description(description.as_str())
        .build();
    options.add(&name_row);
    options.add(&passphrase_row);

    // Desktops are secondary devices only (owner decision): no new account and
    // no recovery-file restore here, both would make this computer a primary
    // that the other devices then depend on while it is switched off.
    let link = gtk::Button::builder()
        .label("Link to my phone")
        .build();
    link.add_css_class("suggested-action");
    link.add_css_class("pill");

    let actions = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(10)
        .build();
    actions.append(&link);

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(24)
        .build();
    content.append(&options);
    content.append(&actions);

    // AdwStatusPage clamps its own title and description but not its child, so
    // without this the explanatory text runs the full width of the window while
    // the heading above it stays narrow. A width *request* would not do: it
    // sets a minimum, which then fights the window's own minimum width.
    let clamped = adw::Clamp::builder()
        .maximum_size(460)
        .tightening_threshold(400)
        .child(&content)
        .build();

    let page = adw::StatusPage::builder()
        .icon_name("system-users-symbolic")
        .title("Welcome to Typeon")
        .description(
            "This computer joins the account on your phone as a linked device. Create the \
             account on the phone first.",
        )
        .child(&clamped)
        .build();

    let read_fields = {
        let name_row = name_row.clone();
        let passphrase_row = passphrase_row.clone();
        move || {
            let text = name_row.text().to_string();
            let name = if text.trim().is_empty() {
                hostname_guess()
            } else {
                text.trim().to_string()
            };
            (name, passphrase_row.text().to_string())
        }
    };

    {
        let app = app.clone();
        let host = host.clone();
        link.connect_clicked(move |button| {
            let (name, passphrase) = read_fields();
            start_fresh_identity(&app, &host, button, &name, &passphrase);
        });
    }

    page.upcast()
}

/// First run: the database is made before the vault exists, under the key the
/// vault then carries as `skipped_key`. One key per process, so a retry after
/// a failed attempt still matches the database that is already open.
fn open_fresh_database(app: &Rc<App>) -> Option<[u8; 32]> {
    use rand::RngCore;
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let first = KEY.get().is_none();
    let key = *KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    });
    let dir = app.data_dir.to_string_lossy();
    if core::init_database(&dir, &key) {
        return Some(key);
    }
    // A database from a first run that ended before its vault was written:
    // its key lived in that process only, so nothing can open it again, and
    // it blocked every later setup. Only before this process made one.
    if !first || secrets::exists(&app.data_dir) {
        return None;
    }
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(app.data_dir.join(format!("p2p_messenger.db{suffix}")));
    }
    core::init_database(&dir, &key).then_some(key)
}

/// Enables or disables all three start buttons at once (they share a parent box),
/// so no second create, link or restore can run while the vault is being saved.
fn set_actions_sensitive(button: &gtk::Button, on: bool) {
    match button.parent() {
        Some(parent) => parent.set_sensitive(on),
        None => button.set_sensitive(on),
    }
}

/// Generates this device's own keys and persists them, waiting to be adopted
/// by the phone's account (`awaiting_link`).
fn start_fresh_identity(
    app: &Rc<App>,
    host: &adw::ToastOverlay,
    button: &gtk::Button,
    device_name: &str,
    passphrase: &str,
) {
    // Quick, but the button must not be clickable twice — a second identity
    // would orphan the first.
    set_actions_sensitive(&button, false);

    let Some(storage_key) = open_fresh_database(app) else {
        set_actions_sensitive(&button, true);
        app.toast("Could not open the database.");
        return;
    };

    if let Err(error) = core::create_identity(device_name) {
        set_actions_sensitive(&button, true);
        app.toast(&format!("Could not create device keys: {}", error));
        return;
    }

    let bundle = core::take_pending_secret_bundle();
    if bundle.is_empty() {
        set_actions_sensitive(&button, true);
        app.toast("The core returned no key bundle — nothing was saved.");
        return;
    }

    let mut vault = Vault::new(bundle);
    vault.skipped_key = storage_key;
    // Sealing the vault runs Argon2id: off the main thread.
    // The flag goes to disk BEFORE the vault: a kill in between would otherwise
    // leave a vault with `awaiting_link` false, i.e. a pending link silently
    // turned into a standalone account. Without a vault the flag is unused.
    {
        let mut prefs = app.prefs.borrow_mut();
        prefs.device_name = device_name.to_string();
        prefs.awaiting_link = true;
        prefs.save();
    }
    let (app, host, button) = (app.clone(), host.clone(), button.clone());
    let data_dir = app.data_dir.clone();
    // Wiped when the worker closure ends, not left on the heap after it.
    let passphrase = WipeOnDrop(passphrase.to_string());
    app::run_in_background(
        move || secrets::save(&data_dir, &vault, &passphrase).map(|()| vault),
        move |result| {
            let vault = match result {
                Ok(vault) => vault,
                Err(error) => {
                    // Without a persisted vault the identity would be lost on exit, so this
                    // is fatal rather than a warning.
                    set_actions_sensitive(&button, true);
                    app.toast(&format!("Could not write the vault: {}", error));
                    return;
                }
            };
            finish_boot(&app, &host, vault);
        },
    );
}

// --- route 2: unlock an existing vault ---

fn unlock(app: &Rc<App>, host: &adw::ToastOverlay, on_open: impl FnOnce(Vault) + 'static) {
    if !secrets::is_passphrase_protected(&app.data_dir) {
        // wallet round-trip, off the GTK thread.
        let data_dir = app.data_dir.clone();
        let (app, host) = (app.clone(), host.clone());
        app::run_in_background(
            move || secrets::load(&data_dir, ""),
            move |result| match result {
                Ok(vault) => on_open(vault),
                Err(error) => fatal(&app, &host, "Could not read the vault", &error),
            },
        );
        return;
    }
    prompt_passphrase(app, on_open);
}

fn prompt_passphrase(app: &Rc<App>, on_open: impl FnOnce(Vault) + 'static) {
    let entry = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .activates_default(true)
        .build();

    let Some(window) = app.window() else { return };
    let dialog = adw::MessageDialog::new(
        Some(&window),
        Some("Unlock Typeon"),
        Some("This device's keys are sealed with your passphrase."),
    );
    dialog.set_extra_child(Some(&crate::ui::widgets::dialog_field(&entry)));
    dialog.add_response("quit", "Quit");
    dialog.add_response("unlock", "Unlock");
    dialog.set_default_response(Some("unlock"));
    dialog.set_close_response("quit");
    dialog.set_response_appearance("unlock", adw::ResponseAppearance::Suggested);

    // `connect_response` takes an `Fn`, but the continuation is `FnOnce`, and a
    // wrong passphrase has to leave the dialog up for another try. The RefCell
    // lets us move the continuation out on the one response that consumes it.
    let on_open = std::rc::Rc::new(std::cell::RefCell::new(Some(on_open)));
    let app = app.clone();
    dialog.connect_response(None, move |dialog, response| {
        if response != "unlock" {
            app.application.quit();
            return;
        }
        // Argon2id (64 MiB x 3) + the wallet round-trip froze the GTK
        // thread for up to seconds, so the check runs on a worker.
        let passphrase = WipeOnDrop(entry.text().to_string());
        let data_dir = app.data_dir.clone();
        dialog.set_sensitive(false);
        let (dialog, entry, app, on_open) =
            (dialog.clone(), entry.clone(), app.clone(), on_open.clone());
        app::run_in_background(
            move || secrets::load(&data_dir, &passphrase),
            move |result| match result {
                Ok(vault) => {
                    dialog.set_visible(false);
                    let continuation = on_open.borrow_mut().take();
                    if let Some(continuation) = continuation {
                        continuation(vault);
                    }
                }
                Err(error) => {
                    // Keep the dialog up so a typo costs one keystroke, not a
                    // relaunch.
                    dialog.set_sensitive(true);
                    app.toast(&error);
                    entry.set_text("");
                }
            },
        );
    });
    dialog.present();
}

// --- shared tail: keys -> network -> link state ---

/// Hands the two symmetric keys to the core, starts the network, then routes to
/// either the link screen or the main window.
fn finish_boot(app: &Rc<App>, host: &adw::ToastOverlay, vault: Vault) {
    // Both are needed regardless of node mode: the archive key also protects
    // history learned from a peer, and the skipped-key cache is what makes
    // out-of-order and delayed messages decryptable at all.
    core::set_history_key(&vault.history_key);
    core::set_skipped_key_encryption_key(&vault.skipped_key);
    // Archive root key — decrypts history stored on a server. Deliberately
    // NOT generated here (see `secrets::ensure_archive_key`): a device that
    // invented its own key before hearing from a sibling would upload an
    // archive its other devices could not read. It arrives either from a
    // sibling over the encrypted sync channel or from a recovery file.
    match secrets::load_archive_key(&app.data_dir) {
        Ok(Some(ark)) => {
            core::set_archive_root_key(&ark);
        }
        Ok(None) => {}
        Err(e) => eprintln!("could not read the archive root key: {e}"),
    }
    // The vault has done its job; the core holds what it needs now.
    drop(vault);

    if let Ok(identity_id) = core::own_identity_id() {
        *app.own_identity_id.borrow_mut() = identity_id;
    }

    host.set_child(Some(&framed(&spinner_page("Starting the network…"))));

    let (node_mode, tor_enabled, storage_limit) = {
        let prefs = app.prefs.borrow();
        (
            prefs.node_mode,
            prefs.tor_enabled,
            prefs.history_storage_limit_bytes,
        )
    };

    let app = app.clone();
    let host = host.clone();
    // Tor bootstrap makes this take a while; on the main thread it would show
    // as a frozen window.
    app::run_in_background(
        move || core::start_network(node_mode, tor_enabled),
        move |result| {
            if let Err(error) = result {
                app.toast(&format!("Network start failed: {}. Restart Typeon to try again.", error));
            }
            core::set_history_storage_limit_bytes(storage_limit);
            app.refresh_caches();
            app::start_poll_loop(&app);
            // Anything queued from a previous run should go out as soon as the
            // swarm is up, rather than waiting for the first backoff tick.
            // The link QR is only for a device that asked to be adopted and
            // has not been yet. A standalone or restored account goes straight
            // in, and so does an already-adopted secondary.
            // Both core calls take the lock the poll thread now holds: off main.
            let awaiting = app.prefs.borrow().awaiting_link;
            app::run_in_background(
                move || {
                    core::retry_all_pending_now();
                    awaiting && !core::is_secondary_device()
                },
                move |show_link| {
                    if show_link {
                        host.set_child(Some(&framed(&link_page(&app, &host))));
                    } else {
                        ui::window::build_main(&app, &host);
                    }
                },
            );
        },
    );
}

// --- route 3: show the link QR and wait to be adopted ---

fn link_page(app: &Rc<App>, host: &adw::ToastOverlay) -> gtk::Widget {
    let qr_slot = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .halign(gtk::Align::Center)
        .width_request(320)
        .height_request(320)
        .build();

    let status = gtk::Label::builder()
        .label("Preparing a link code…")
        .wrap(true)
        .justify(gtk::Justification::Center)
        .build();
    status.add_css_class("dim-label");

    let spinner = gtk::Spinner::new();
    spinner.start();

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .halign(gtk::Align::Center)
        .build();
    content.append(&qr_slot);
    content.append(&spinner);
    content.append(&status);
    // A pending link can be months old (the phone side long gone): without
    // this the only way back to the setup choices was deleting files by hand.
    content.append(&erase_button(app, "Cancel linking and start over"));

    let page = adw::StatusPage::builder()
        .title("Scan this from your phone")
        .description(
            "On the device that already has your account, open Typeon → Settings → Linked \
             devices → Link a device, and scan this code. Your phone keeps its secret key; this \
             computer gets its own.",
        )
        .child(&content)
        .build();

    // The QR cannot be built until the swarm reports a listen address, so this
    // retries rather than failing outright (same pattern as the Android
    // LinkDeviceActivity and the contact QR).
    // Core calls below run off the GTK thread (shared core lock); one in
    // flight at a time.
    {
        let qr_slot = qr_slot.clone();
        let status = status.clone();
        let attempts = Rc::new(std::cell::Cell::new(0u32));
        let in_flight = Rc::new(std::cell::Cell::new(false));
        let page = page.downgrade();
        glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
            if qr_slot.first_child().is_some() || page.upgrade().map_or(true, |p| p.root().is_none()) {
                return glib::ControlFlow::Break;
            }
            if in_flight.replace(true) {
                return glib::ControlFlow::Continue;
            }
            // Past the cap the timer stops (checked before `attempts` moves below).
            let give_up = attempts.get() >= 60;
            let (qr_slot, status, attempts, in_flight) =
                (qr_slot.clone(), status.clone(), attempts.clone(), in_flight.clone());
            app::run_in_background(
                || {
                    let payload = core::build_device_link_request();
                    let code = if payload.is_empty() { String::new() } else { core::device_link_code(&payload) };
                    // Debug builds only: lets a test approve the link from adb
                    // (Android debug `debug_qr_hex`) without a camera.
                    #[cfg(debug_assertions)]
                    if !payload.is_empty() && std::env::var_os("TYPEON_DEBUG_LINK").is_some() {
                        eprintln!("LINK_QR_HEX={}", payload.iter().map(|b| format!("{b:02x}")).collect::<String>());
                    }
                    (payload, code)
                },
                move |(payload, code)| {
                    in_flight.set(false);
                    if qr_slot.first_child().is_some() {
                        return;
                    }
                    if payload.is_empty() {
                        attempts.set(attempts.get() + 1);
                        if attempts.get() >= 60 {
                            status.set_label(
                                "The network is not reachable yet — no listening address was \
                                 established. Check your connection, then restart Typeon.",
                            );
                            // Stops the timer: `attempts` past the cap never retries.
                        }
                        return;
                    }
                    match qr::qr_widget(&payload) {
                        Some(widget) => {
                            qr_slot.append(&widget);
                            // The phone shows the same code in its confirm dialog.
                            status.set_label(&format!(
                                "Waiting for your phone to scan this…\n\nCompare code: {}\nYour phone shows the same code before you approve.",
                                code
                            ));
                        }
                        None => status.set_label("Could not render the link code."),
                    }
                },
            );
            if give_up {
                glib::ControlFlow::Break
            } else {
                glib::ControlFlow::Continue
            }
        });
    }

    // Adoption arrives asynchronously (mutual IdentityExchange, then a signed
    // DeviceAdd and a full sync), so poll for it exactly as Android does.
    {
        let app = app.clone();
        let host = host.clone();
        let in_flight = Rc::new(std::cell::Cell::new(false));
        let page = page.downgrade();
        glib::timeout_add_seconds_local(2, move || {
            // Page replaced/destroyed: nothing left to adopt into.
            if page.upgrade().map_or(true, |p| p.root().is_none()) {
                return glib::ControlFlow::Break;
            }
            if in_flight.replace(true) {
                return glib::ControlFlow::Continue;
            }
            let (app, host, in_flight) = (app.clone(), host.clone(), in_flight.clone());
            app::run_in_background(
                || {
                    let secondary = core::is_secondary_device();
                    (secondary, if secondary { core::own_identity_id().ok() } else { None })
                },
                move |(secondary, identity_id)| {
                in_flight.set(false);
                if !secondary {
                    return;
                }
                if let Some(identity_id) = identity_id {
                    *app.own_identity_id.borrow_mut() = identity_id;
                }
                {
                    let mut prefs = app.prefs.borrow_mut();
                    prefs.awaiting_link = false;
                    prefs.save();
                }
                app.refresh_caches();
                app.toast("This computer is now linked to your account.");
                ui::window::build_main(&app, &host);
                },
            );
            glib::ControlFlow::Continue
        });
    }

    page.upcast()
}

// --- small shared pieces ---

/// Onboarding pages sit directly in the window with no header bar of their
/// own, and libadwaita windows draw their own frame: without this there is no
/// title, no close/minimise button and nothing to drag (Windows has no
/// server-side decoration to fall back on). The main UI brings its own header.
fn framed(page: &impl IsA<gtk::Widget>) -> gtk::Widget {
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(page));
    toolbar.upcast()
}

fn spinner_page(message: &str) -> gtk::Widget {
    let spinner = gtk::Spinner::new();
    spinner.set_size_request(32, 32);
    spinner.start();
    adw::StatusPage::builder()
        .title(message)
        .child(&spinner)
        .build()
        .upcast()
}

fn fatal(app: &Rc<App>, host: &adw::ToastOverlay, title: &str, detail: &str) {
    let quit = gtk::Button::builder().label("Quit").build();
    quit.add_css_class("pill");
    {
        let application = app.application.clone();
        quit.connect_clicked(move |_| application.quit());
    }

    let logout = erase_button(app, "Log out and erase this device");

    let actions = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(10)
        .halign(gtk::Align::Center)
        .build();
    actions.append(&quit);
    actions.append(&logout);

    host.set_child(Some(&framed(
        &adw::StatusPage::builder()
            .icon_name("dialog-error-symbolic")
            .title(title)
            .description(detail)
            .child(&actions)
            .build(),
    )));
}

/// The one escape hatch out of onboarding: confirm, then the same wipe as
/// `settings::confirm_logout`. A fresh launch lands on the welcome page.
fn erase_button(app: &Rc<App>, label: &str) -> gtk::Button {
    // Every fatal state here is an unreadable or rejected vault, and the only
    // way forward is the one the message spells out: erase this device's data
    // and set it up again. The welcome screen has no way back to this — there
    // is no main window and no Settings — so the escape hatch has to live on
    // the error screen itself. Same wipe as `settings::confirm_logout`:
    // keyring key first, then the whole data directory, then quit (the core
    // still holds the identity in memory and the poll thread, if it started,
    // is running against files that are about to vanish).
    let logout = gtk::Button::builder().label(label).build();
    logout.add_css_class("pill");
    logout.add_css_class("destructive-action");
    {
        let app = app.clone();
        logout.connect_clicked(move |_| {
            let app = app.clone();
            // `confirm` takes `&app` and its accept closure moves `app`, both
            // in the same call. The borrow would still be alive while the
            // closure tries to move `app`. So the closure gets its own clone.
            let on_confirm_app = app.clone();
            crate::ui::dialogs::confirm(
                &app,
                "Erase this device?",
                "This device's identity, every message and every downloaded attachment on this \
                 computer are deleted, along with the key held in your system keyring. Your other \
                 devices keep working. Without a recovery file this cannot be undone.",
                "Erase",
                true,
                move || {
                    // `.clone()`, not a move: `dialogs::confirm` takes an
                    // `Fn` accept closure, not `FnOnce`. The closure cannot move
                    // captured values out, it can only borrow or clone them.
                    crate::ui::settings::erase_profile_and_quit(&on_confirm_app);
                },
            );
        });
    }
    logout
}

/// A sensible default device name — this is what the phone will list under
/// "Linked devices", so the machine's hostname is the most recognisable thing.
/// Placeholder hostnames are not: "localhost.localdomain" tells the user
/// nothing about which computer they just linked.
fn hostname_guess() -> String {
    let host = glib::host_name().to_string();
    let bare = host.split('.').next().unwrap_or("").trim().to_string();
    if bare.is_empty() || bare.eq_ignore_ascii_case("localhost") {
        "Linux desktop".to_string()
    } else {
        bare
    }
}

/// Kept next to the vault helpers so the settings screen can re-seal without
/// duplicating the "what does an empty passphrase mean" rule.
pub fn reseal_vault(data_dir: &Path, current: &str, new_passphrase: &str) -> Result<(), String> {
    let vault = secrets::load(data_dir, current)?;
    secrets::change_passphrase(data_dir, &vault, new_passphrase)
}
