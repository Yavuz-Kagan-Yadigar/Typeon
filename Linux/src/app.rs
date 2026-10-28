//! Shared application state, the poll loop, and the event bus.
//!
//! The core exposes exactly one channel for everything that happens
//! asynchronously: `poll_network()`, which must be called about once a second
//! because it is also what drives the libp2p swarm forward. The Android app
//! runs it on a dedicated `HandlerThread`; this does the same on a plain
//! `std::thread`, because a slow round (a large history sync, a group fan-out,
//! SQLite under load) must never stall the GTK main loop.
//!
//! Decoded events come back over an `async_channel` and are replayed on the
//! main thread to whichever views have registered interest — the desktop
//! equivalent of `P2PService.listeners`.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

// libadwaita's prelude re-exports gtk's (which re-exports gio's and glib's),
// so this one glob covers every widget trait used here.
use adw::prelude::*;
use gtk::gio;
use gtk::glib;

use crate::core::{self, ContactSummary, GroupSummary};
use crate::font;
use crate::prefs::Prefs;
use crate::util;

/// One decoded `poll_network` event. The core emits these as JSON objects with
/// a `"type"` discriminator; the payload shape varies per type, so this keeps
/// the raw value around and offers typed accessors instead of modelling ~35
/// variants that only the core decides.
#[derive(Debug, Clone)]
pub struct Event {
    pub kind: String,
    pub value: serde_json::Value,
}

impl Event {
    pub fn string(&self, key: &str) -> String {
        self.value
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    }

    /// `None` for both a missing key and an explicit JSON `null` — the core
    /// uses `null` for "not applicable" (e.g. `group_id` on a 1:1 event).
    pub fn optional(&self, key: &str) -> Option<String> {
        self.value
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    pub fn number(&self, key: &str) -> u64 {
        self.value.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
    }

    pub fn flag(&self, key: &str) -> bool {
        self.value.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
    }
}

type Listener = Rc<dyn Fn(&Event)>;

/// See `start_poll_loop`/`stop_poll_loop`: set once when a remote unlink
/// (`self_revoked`) is about to erase the data directory, so the poll thread
/// stops driving the core against deleted files. Never cleared — the only
/// safe continuation after an unlink is quitting the process.
static POLL_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Ask the poll thread to exit before its next round. The current round (if
/// one is mid-flight) still finishes — on Linux deleting files under an open
/// SQLite handle is safe, this just stops *new* rounds from starting.
pub fn stop_poll_loop() {
    POLL_STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub struct App {
    pub application: adw::Application,
    pub data_dir: PathBuf,
    pub prefs: RefCell<Prefs>,
    /// Which secret store sealed this device's vault — shown in Settings so
    /// the user can see where their key actually lives.
    pub keyring_backend: crate::keyring::Backend,
    /// Raw hex identity id of this device's own identity — needed to tell
    /// "my" group messages from other members'.
    pub own_identity_id: RefCell<String>,

    listeners: RefCell<Vec<(u64, Listener)>>,
    next_listener_id: Cell<u64>,
    /// One `core_panic` banner per process: the core reports a caught panic
    /// with a fresh event every time one happens, which would otherwise stack
    /// notifications for a single dead core (H132).
    core_panic_reported: Cell<bool>,

    /// The conversation currently on screen (peer fingerprint, or
    /// `"group:<id>"`). Notifications are suppressed for it, exactly as
    /// `P2PService.activeConversationId` does.
    pub active_conversation: RefCell<Option<String>>,

    /// True while the idle lock is up (see `ui::window::idle_lock`): the
    /// window shows a lock page, so an open conversation is NOT being
    /// looked at and a new message must still raise a notification.
    pub locked: Cell<bool>,

    pub window: RefCell<Option<adw::ApplicationWindow>>,
    pub toasts: RefCell<Option<adw::ToastOverlay>>,

    /// Refreshed on a slow timer so notification text and chat rows can resolve
    /// a fingerprint or identity id to a human name without hitting the core
    /// (and its global lock) per event.
    pub contacts: RefCell<Vec<ContactSummary>>,
    pub groups: RefCell<Vec<GroupSummary>>,

    /// Loads custom `.ttf`/`.otf` fonts, registers them with the system font
    /// database, and tracks the active one — the desktop counterpart of
    /// `FontOverride` / `ThemePrefs.CustomFont` on Android.
    pub font_manager: RefCell<font::FontManager>,
}

impl App {
    pub fn new(
        application: adw::Application,
        data_dir: PathBuf,
        prefs: Prefs,
        keyring_backend: crate::keyring::Backend,
    ) -> Rc<Self> {
        Rc::new(Self {
            application,
            data_dir: data_dir.clone(),
            prefs: RefCell::new(prefs),
            keyring_backend,
            own_identity_id: RefCell::new(String::new()),
            listeners: RefCell::new(Vec::new()),
            next_listener_id: Cell::new(1),
            core_panic_reported: Cell::new(false),
            active_conversation: RefCell::new(None),
            locked: Cell::new(false),
            window: RefCell::new(None),
            toasts: RefCell::new(None),
            contacts: RefCell::new(Vec::new()),
            groups: RefCell::new(Vec::new()),
            font_manager: RefCell::new(font::FontManager::new(data_dir.clone())),
        })
    }

    // --- custom fonts ---

    /// Id for a newly imported custom font (epoch-ms timestamp — sortable).
    pub fn new_custom_font_id(&self) -> String {
        util::now_ms().to_string()
    }

    /// Path for a custom font file by id.
    pub fn custom_font_path(&self, id: &str) -> PathBuf {
        self.data_dir.join(format!("custom_font_{id}.ttf"))
    }

    /// Import a font file (from a `content://` URI on Android or a system path
    /// on desktop), store it in the data directory, and register it.
    pub fn import_font(&self, path: &str, display_name: &str) -> Result<(), String> {
        let id = self.new_custom_font_id();
        let target = self.custom_font_path(&id);

        // Copy the font file to the data directory.
        std::fs::copy(path, &target).map_err(|e| format!("Failed to copy font: {e}"))?;

        // Persist in prefs.
        {
            let mut prefs = self.prefs.borrow_mut();
            prefs.custom_fonts.insert(id.clone(), display_name.to_string());
            prefs.active_custom_font_id = Some(id.clone());
            prefs.save();
        }

        Ok(())
    }

    /// Set the active custom font by id (None = back to built-in/system font).
    pub fn set_active_custom_font(&self, id: Option<&str>) {
        {
            let mut prefs = self.prefs.borrow_mut();
            prefs.active_custom_font_id = id.map(String::from);
            prefs.save();
        }
        self.font_manager.borrow_mut().set_active(id.map(String::from));
    }

    /// Get all custom fonts sorted by id (oldest first).
    pub fn list_custom_fonts(&self) -> Vec<font::CustomFont> {
        let mut fonts = self.font_manager.borrow_mut().discover();
        // `discover` only knows file ids; the names the user saw live in prefs.
        let prefs = self.prefs.borrow();
        for font in &mut fonts {
            if let Some(name) = prefs.custom_fonts.get(&font.id) {
                font.display_name = name.clone();
            }
        }
        fonts
    }

    /// Get the active custom font's id.
    pub fn active_custom_font_id(&self) -> Option<String> {
        self.prefs.borrow().active_custom_font_id.clone()
    }

    // --- event bus ---

    /// Registers `handler` for the lifetime of `owner`. Tying it to a widget
    /// rather than handing back a guard means a view that gets popped off the
    /// navigation stack cannot leave a stale listener firing into freed state.
    pub fn subscribe(
        self: &Rc<Self>,
        owner: &impl IsA<gtk::Widget>,
        handler: impl Fn(&Event) + 'static,
    ) {
        let id = self.next_listener_id.get();
        self.next_listener_id.set(id + 1);
        self.listeners.borrow_mut().push((id, Rc::new(handler)));

        let app = Rc::downgrade(self);
        owner.as_ref().connect_destroy(move |_| {
            if let Some(app) = app.upgrade() {
                app.listeners.borrow_mut().retain(|(other, _)| *other != id);
            }
        });
    }

    fn dispatch(self: &Rc<Self>, raw: &str) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
            eprintln!("typeon: dropped an unparsable event: {}", raw.chars().take(120).collect::<String>());
            return;
        };
        let kind = value
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if kind.is_empty() || kind == "noop" {
            return;
        }
        // M-180: the core caught a panic (a single bad packet does it too):
        // logged only, nothing restarts on it.
        if kind == "core_panic" {
            log::error!("core caught a panic (see the core log)");
            // H132/M146: on Android the service restarts a dead core; here the
            // window just kept looking alive while sends, receives and
            // downloads were silently dead until a manual restart. Say so —
            // once per process, prominently.
            if !self.core_panic_reported.replace(true) {
                let notification = gio::Notification::new("Typeon");
                notification.set_body(Some(
                    "The messaging core hit an internal error and stopped working. \
                     Please restart Typeon.",
                ));
                notification.set_priority(gio::NotificationPriority::Urgent);
                self.application
                    .send_notification(Some("core-panic"), &notification);
                self.toast(
                    "The messaging core hit an internal error and stopped working. \
                     Please restart Typeon.",
                );
            }
            return;
        }
        let event = Event { kind, value };

        self.apply_side_effects(&event);

        // Snapshot first: a handler may add or remove listeners (opening a
        // chat from a notification, say) and that must not invalidate the
        // iteration or re-enter the RefCell.
        let handlers: Vec<Listener> = self
            .listeners
            .borrow()
            .iter()
            .map(|(_, handler)| handler.clone())
            .collect();
        for handler in handlers {
            handler(&event);
        }
    }

    /// Everything that must happen for an event regardless of which view (if
    /// any) is open — the counterpart of `P2PService.maybeNotify`.
    fn apply_side_effects(self: &Rc<Self>, event: &Event) {
        match event.kind.as_str() {
            // External AI-review fix (AI2-G, self-revocation): the primary
            // device revoked THIS device. The core already wiped its DB tables
            // + attachments and is now inert; here we finish the job the way
            // `confirm_logout` (ui/settings.rs) does — drop the keyring vault
            // key and remove the whole data directory (vault.bin + db file
            // included), tell the user, then stop the process. The poll thread
            // is still running against a now-deleted database, so quitting is
            // the only safe finish; a fresh launch lands on onboarding.
            "sync" => self.persist_archive_key_if_new(),
            "call" => crate::ui::call::on_event(self, event),
            "self_revoked" => {
                // Stop the poll thread before erasing the files it works on
                // (it would otherwise keep polling a deleted database until
                // the process exits).
                stop_poll_loop();
                let profile = self.data_dir.to_string_lossy().to_string();
                if let Err(error) = crate::keyring::delete_key(&profile) {
                    eprintln!("typeon: could not remove the vault key after remote unlink: {error}");
                }
                // Defter #27: dizin silme, uygulamanın kapanmasıyla AYNI
                // ana alındı. `stop_poll_loop` yalnızca bir bayrak set
                // ediyor (anket iş parçacığı 1 sn'ye kadar uyuyor olabilir)
                // ve Rust çekirdeği — swarm, tokio görevleri, AÇIK SQLite
                // bağlantısı — çalışmaya devam ediyor. Dizin hemen silinip
                // uygulama kullanıcı "OK"a basana kadar açık kalınca,
                // çekirdek silinmiş bir dizine yazmayı sürdürüyordu. Kasa
                // anahtarı (asıl kritik olan) yukarıda ZATEN silindi.
                let data_dir = self.data_dir.clone();
                let app_quit = self.application.clone();
                let erase_and_quit = move || {
                    // Recursive delete is unbounded blocking: off the GTK thread.
                    run_in_background(
                        move || std::fs::remove_dir_all(&data_dir),
                        move |result| {
                            if let Err(error) = result {
                                eprintln!("typeon: could not erase data dir after remote unlink: {error}");
                            }
                            app_quit.quit();
                        },
                    );
                };
                if let Some(window) = self.window() {
                    let dialog = adw::MessageDialog::new(
                        Some(&window),
                        Some("This device was unlinked"),
                        Some(
                            "Your account removed this device. Its local identity, messages and \
                             attachments have been erased from this computer. Your other devices \
                             keep working.",
                        ),
                    );
                    dialog.add_response("ok", "OK");
                    dialog.set_default_response(Some("ok"));
                    dialog.set_close_response("ok");
                    let erase_and_quit = std::cell::RefCell::new(Some(erase_and_quit));
                    dialog.connect_response(None, move |_, _| {
                        if let Some(f) = erase_and_quit.borrow_mut().take() {
                            f();
                        }
                    });
                    dialog.present();
                } else {
                    erase_and_quit();
                }
            }
            // A sibling device of mine read this conversation; treat it as read
            // here too so the chat list agrees across my devices.
            "read_state_sync" => {
                let conversation = event.string("conversation");
                let read_at = event.number("read_at");
                self.prefs
                    .borrow_mut()
                    .mark_read_at(&conversation, read_at);
                // Found in this audit: the chat list was corrected but a
                // notification already on screen for that conversation was
                // left standing, so reading a chat on the phone left the
                // desktop still showing "you have a new message" for it.
                // `notify_if_away` uses the conversation id as the
                // notification id precisely so it can be addressed later.
                self.application.withdraw_notification(&conversation);
            }
            "message" => {
                let peer = event.string("peer");
                if !peer.is_empty() {
                    self.notify_if_away(&peer, &self.contact_name(&peer), &event.string("text"));
                }
            }
            "group_message" => {
                let group_id = event.string("group_id");
                if !group_id.is_empty() {
                    let title = self.group_name(&group_id);
                    let sender = self.identity_name(&event.string("sender_identity_id"));
                    if event.value.get("mentions_me").and_then(|v| v.as_bool()).unwrap_or(false) {
                        let title = format!("{} mentioned you in {}", sender, title);
                        self.notify_if_away_as(&format!("group:{}", group_id), &title, &event.string("text"), true);
                    } else {
                        let body = format!("{}: {}", sender, event.string("text"));
                        self.notify_if_away(&format!("group:{}", group_id), &title, &body);
                    }
                }
            }
            // Attachments notify too — a photo arriving with no alert at all
            // was a real gap on Android before this was added there.
            "file_offer" => {
                let label = util::attachment_label(
                    &event.string("mime_type"),
                    &event.string("file_name"),
                    event.flag("sticker"),
                );
                match event.optional("group_id") {
                    Some(group_id) => {
                        let title = self.group_name(&group_id);
                        let sender = self.identity_name(&event.string("sender_identity_id"));
                        self.notify_if_away(
                            &format!("group:{}", group_id),
                            &title,
                            &format!("{}: {}", sender, label),
                        );
                    }
                    None => {
                        let peer = event.string("peer");
                        if !peer.is_empty() {
                            self.notify_if_away(&peer, &self.contact_name(&peer), &label);
                        }
                    }
                }
            }
            // Contact/group membership changed under us — keep the name caches
            // honest so the next event resolves correctly.
            // Defter #17: Android bunu bir toast'a bağlıyordu, Linux hiç
            // işlemiyordu — masaüstünde KALICI el sıkışma hatası tamamen
            // sessizdi (kullanıcı "mesaj gitmiyor" der, arayüzde hiçbir
            // ipucu yok).
            // Kullanıcı kararı (2026-08-27): tanınmayan cihaz uyarısı artık
            // sessiz değil — çekirdek bir olay yayınlıyor, burada masaüstü
            // bildirimi olarak gösteriliyor. Kabul/reddet/engelle seçimi
            // kişiler ekranındaki uyarı satırından yapılıyor.
            "device_alert" => {
                let who = event.string("contact_display_name");
                let code = event.string("device_short_code");
                self.notify_always(
                    &format!("device-alert:{who}:{code}"),
                    "Unverified device",
                    &format!("{who} is writing from a device you have not verified ({code})."),
                );
            }
            "pairing_failed" => {
                if event.string("reason") == "contact_limit" {
                    self.toast("Pairing failed: your contact list is full.");
                }
            }
            "history_restore_incomplete" => {
                self.toast("The server did not send all of the history. Try again later.");
            }
            "account_deleted" => {
                let name = event.string("display_name");
                let name = if name.is_empty() { self.contact_name(&event.string("peer")) } else { name };
                let body = format!("{name} deleted their account");
                self.toast(&body);
                self.notify_always(&format!("account-deleted:{}", event.string("peer")), "Typeon", &body);
            }
            "handshake_failed" => {
                let who = self.contact_name(&event.string("peer"));
                self.toast(&format!(
                    "{who}: secure session could not be set up — the other side may be on an incompatible version."
                ));
            }
            // Defter #16: reddedilen bir grup güncellemesi kullanıcıya
            // görünmeliydi; hiçbir istemci dinlemiyordu.
            "group_update_failed" => {
                let name = self.group_name(&event.string("group_id"));
                self.toast(&format!("{name}: a group update was rejected and not applied."));
            }
            "device_change" | "device_linked" | "group_updated" | "member_left"
            | "profile_update" => {
                // `device_linked` is also one of the two moments the archive
                // root key can arrive from a sibling — see
                // `persist_archive_key_if_new`. It has to be called here
                // rather than in its own arm, because match arms do not fall
                // through and this arm already claims the event.
                self.persist_archive_key_if_new();
                self.refresh_caches();
            }
            _ => {}
        }
    }

    /// Stores the archive root key on disk the first time it appears.
    ///
    /// A secondary device receives it from a sibling over the encrypted sync
    /// channel, long after the vault passphrase has left memory. The core
    /// holds it in memory only, so without this the key would have to be
    /// re-learned on every launch — and a restart before the next sync would
    /// leave the server-side archive unreadable on this machine.
    fn persist_archive_key_if_new(self: &Rc<Self>) {
        // H125: this runs inside the event dispatcher, so `core::archive_root_key()`
        // used to take the shared core lock on the GTK thread on every affected
        // event — a poll round holding the lock stalled the whole UI. The key
        // comparison and the file write are just as safe off-thread.
        let data_dir = self.data_dir.clone();
        run_in_background(
            || core::archive_root_key(),
            move |ark| {
                // Also when the key changed: the primary device replaces it
                // when it revokes a device.
                if let Some(ark) = ark {
                    if matches!(crate::secrets::load_archive_key(&data_dir), Ok(Some(k)) if k == ark) {
                        return;
                    }
                    if let Err(e) = crate::secrets::store_archive_key(&data_dir, &ark) {
                        eprintln!("could not store the archive root key: {e}");
                    }
                }
            },
        );
    }

    /// Sohbet açık olsa bile gösterilen bildirim — güvenlik uyarıları
    /// (bkz. `device_alert`) kullanıcının nerede olduğuna bakmadan
    /// görünmeli.
    fn notify_always(self: &Rc<Self>, id: &str, title: &str, body: &str) {
        let notification = gio::Notification::new(title);
        notification.set_body(Some(body));
        notification.set_priority(gio::NotificationPriority::High);
        self.application.send_notification(Some(id), &notification);
    }

    fn notify_if_away(self: &Rc<Self>, conversation_id: &str, title: &str, body: &str) {
        self.notify_if_away_as(conversation_id, title, body, false);
    }

    /// `mention`: a group message that @mentions me, shown at high priority.
    fn notify_if_away_as(self: &Rc<Self>, conversation_id: &str, title: &str, body: &str, mention: bool) {
        let is_open = self
            .active_conversation
            .borrow()
            .as_deref()
            .map(|open| open == conversation_id)
            .unwrap_or(false);
        let is_focused = self
            .window
            .borrow()
            .as_ref()
            .map(|window| window.is_active())
            .unwrap_or(false);
        // Visible and focused means the user is already looking at it.
        // A locked window is not: the content is hidden behind the lock
        // page, so a message that arrives then must still be announced.
        if is_open && is_focused && !self.locked.get() {
            return;
        }

        // The setting hides who wrote and what: the title is a contact or
        // group name.
        let (title, body) = if self.prefs.borrow().hide_notification_content {
            ("Typeon", if mention { "You were mentioned in a group" } else { "New message" })
        } else {
            (title, body)
        };
        let notification = gio::Notification::new(title);
        notification.set_body(Some(body));
        notification.set_priority(if mention { gio::NotificationPriority::High } else { gio::NotificationPriority::Normal });
        // One notification id per conversation, so a burst of messages
        // replaces itself instead of stacking up a wall of popups.
        self.application
            .send_notification(Some(conversation_id), &notification);
    }

    // --- name resolution ---

    pub fn refresh_caches(self: &Rc<Self>) {
        let app = self.clone();
        run_in_background(
            || (core::list_contacts(), core::list_groups()),
            move |(contacts, groups)| {
                *app.contacts.borrow_mut() = contacts;
                *app.groups.borrow_mut() = groups;
            },
        );
    }

    /// Contacts are keyed by identity, but events carry a device fingerprint,
    /// so this checks the active device of each contact. A fingerprint we have
    /// no contact for falls back to its short form.
    pub fn contact_name(&self, fingerprint: &str) -> String {
        for contact in self.contacts.borrow().iter() {
            if contact.active_device_fingerprint.as_deref() == Some(fingerprint) {
                return contact.display_name.clone();
            }
        }
        util::short_fingerprint(fingerprint)
    }

    pub fn identity_name(&self, identity_id: &str) -> String {
        if identity_id.is_empty() {
            return String::new();
        }
        if *self.own_identity_id.borrow() == identity_id {
            return "You".to_string();
        }
        for contact in self.contacts.borrow().iter() {
            if contact.identity_id == identity_id {
                return contact.display_name.clone();
            }
        }
        util::short_fingerprint(identity_id)
    }

    pub fn group_name(&self, group_id: &str) -> String {
        for group in self.groups.borrow().iter() {
            if group.group_id == group_id {
                return group.name.clone();
            }
        }
        "Group".to_string()
    }

    /// Avatar bytes for a contact, looked up by identity id.
    pub fn identity_avatar(&self, identity_id: &str) -> Option<String> {
        self.contacts
            .borrow()
            .iter()
            .find(|contact| contact.identity_id == identity_id)
            .and_then(|contact| contact.avatar_hex.clone())
    }

    // --- UI helpers ---

    pub fn toast(&self, message: &str) {
        if let Some(overlay) = self.toasts.borrow().as_ref() {
            // Toast titles are Pango markup; callers pass peer-chosen names.
            overlay.add_toast(adw::Toast::new(&gtk::glib::markup_escape_text(message)));
        }
    }

    pub fn window(&self) -> Option<adw::ApplicationWindow> {
        self.window.borrow().clone()
    }
}

/// Starts the once-a-second poll on a worker thread and pumps its output into
/// the main loop. Also drives the periodic name-cache refresh.
pub fn start_poll_loop(app: &Rc<App>) {
    let (sender, receiver) = async_channel::bounded::<Vec<String>>(64);

    std::thread::spawn(move || loop {
        // A remote unlink (`self_revoked`) deletes the whole data directory;
        // the poll loop must stop touching the (now-gone) database first —
        // see `stop_poll_loop`.
        if POLL_STOP.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        // This call is not just a mailbox drain — it is what advances the
        // swarm, retries pending messages and services downloads, so it has to
        // run on every tick even when nothing comes back.
        let events = core::poll_network();
        if !events.is_empty() && sender.send_blocking(events).is_err() {
            // Receiver gone: the app is shutting down.
            break;
        }
        // Returns early on swarm activity or when the UI touches the core
        // (e.g. a sent message), so traffic is not held back to the next tick.
        core::wait_for_network_activity(1000);
    });

    let dispatcher = app.clone();
    glib::spawn_future_local(async move {
        while let Ok(batch) = receiver.recv().await {
            for raw in batch {
                dispatcher.dispatch(&raw);
            }
        }
    });

    let refresher = app.clone();
    glib::timeout_add_seconds_local(15, move || {
        refresher.refresh_caches();
        // Read-state marking is deferred (see `Prefs::flush`); this is where it
        // actually reaches disk.
        refresher.prefs.borrow_mut().flush();
        glib::ControlFlow::Continue
    });

    // R-06: power-save for the core's keepalive ladder (20 s -> 60 s) and its
    // radio-window coalescing — the state Android feeds from the app lifecycle
    // (`P2PLib.setPowerSave`), which the desktop client never reported. The
    // window hookup lives in `main.rs` (`connect_is_active_notify`); this
    // watcher is what carries the "gone for a minute" part, reading the very
    // same `is_active` state the notification path already uses. Active again
    // => off at once, inactive for `POWER_SAVE_AFTER_IDLE_MS` => on. Every
    // core call goes to a worker thread — never the GTK thread.
    const POWER_SAVE_AFTER_IDLE_MS: u64 = 60_000;
    let power_saving = Cell::new(false);
    let inactive_since = Cell::new(0u64);
    let saver = app.clone();
    glib::timeout_add_seconds_local(10, move || {
        let active = saver.window().map(|window| window.is_active()).unwrap_or(false);
        let now = util::now_ms();
        if active {
            inactive_since.set(0);
            if power_saving.replace(false) {
                set_power_save(false);
            }
        } else if inactive_since.get() == 0 {
            inactive_since.set(now);
        } else if !power_saving.get() && now.saturating_sub(inactive_since.get()) >= POWER_SAVE_AFTER_IDLE_MS {
            power_saving.set(true);
            set_power_save(true);
        }
        glib::ControlFlow::Continue
    });

    // The Android client force-reconnects immediately on a network change
    // (Wi-Fi <-> cellular, VPN toggling) instead of waiting for the ~15s
    // periodic reconnect sweep or a ping failure to notice a dead connection
    // (see `P2PService.observeNetworkChangesForReconnect`/`notifyNetworkChanged`).
    // This desktop client had no equivalent: without a foreground-service
    // model to keep things warm, it relied entirely on the slower generic
    // path, so switching networks/waking from suspend here took noticeably
    // longer to recover than on Android. `gio::NetworkMonitor` is GLib's
    // idiomatic source for exactly this signal.
    let monitor = gio::NetworkMonitor::default();
    // R-06: the same monitor reports whether the link is metered — the state
    // Android feeds from ConnectivityManager (`P2PLib.setMeteredNetwork`).
    // Once at startup, then every time the flag flips. The core call takes the
    // lock, so `set_metered` moves it to a worker thread.
    set_metered(monitor.is_network_metered());
    monitor.connect_network_metered_notify(|monitor| {
        set_metered(monitor.is_network_metered());
    });
    monitor.connect_network_changed(|_monitor, available| {
        if available {
            // Off the GTK main loop: this takes the core's global lock and
            // can start a dial round — exactly why the Android side runs it
            // on a background thread (`notifyNetworkChangedInBackground`).
            // Inline it would freeze the UI whenever a poll round holds the
            // lock at the same moment.
            // One worker at a time; events arriving meanwhile coalesce into
            // one more run (a flapping link no longer stacks lock waiters).
            use std::sync::atomic::{AtomicBool, Ordering};
            static BUSY: AtomicBool = AtomicBool::new(false);
            static AGAIN: AtomicBool = AtomicBool::new(false);
            if BUSY.swap(true, Ordering::AcqRel) {
                AGAIN.store(true, Ordering::Release);
            } else {
                std::thread::spawn(|| loop {
                    core::notify_network_changed();
                    if !AGAIN.swap(false, Ordering::AcqRel) {
                        BUSY.store(false, Ordering::Release);
                        // An event landing right after the check above.
                        if AGAIN.load(Ordering::Acquire) && !BUSY.swap(true, Ordering::AcqRel) {
                            continue;
                        }
                        break;
                    }
                });
            }
        }
    });
    // Leaked deliberately: this connection must outlive `start_poll_loop`
    // (there is exactly one, made once at startup, for the app's entire
    // lifetime) — dropping the local wrapper here would only be safe if some
    // other owner were guaranteed to keep the underlying GObject singleton
    // alive, which the API does not promise.
    std::mem::forget(monitor);
}

/// R-06: power-save on/off for the core (see `core::set_power_save`) —
/// driven by the window watcher in `start_poll_loop`, and cheap enough for a
/// signal handler (`main.rs` `connect_is_active_notify`) to call directly.
/// Takes the core lock, so it never runs on the GTK thread itself.
pub fn set_power_save(enabled: bool) {
    std::thread::spawn(move || core::set_power_save(enabled));
}

/// R-06: metered link or not (see `core::set_metered`) — worker thread for
/// the same reason as `set_power_save`.
pub fn set_metered(metered: bool) {
    std::thread::spawn(move || core::set_metered(metered));
}

/// Runs `work` off the main thread and hands the result back on it. Used for
/// the handful of core calls that are genuinely slow — network start, file
/// encryption, recovery export — so the window never freezes.
pub fn run_in_background<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
    then: impl FnOnce(T) + 'static,
) {
    let (sender, receiver) = async_channel::bounded::<T>(1);
    std::thread::spawn(move || {
        let _ = sender.send_blocking(work());
    });
    glib::spawn_future_local(async move {
        if let Ok(result) = receiver.recv().await {
            then(result);
        }
    });
}

