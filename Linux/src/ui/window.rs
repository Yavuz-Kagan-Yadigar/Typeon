//! The main window: a sidebar holding the Chats/Contacts lists, and a content
//! pane holding the open conversation.
//!
//! This is the one place the layout deliberately departs from the phone. The
//! Android app is a stack of full-screen activities with a bottom nav bar;
//! that would waste most of a desktop window. `AdwNavigationSplitView` gives
//! the list and the conversation side by side on a wide window and collapses
//! back to the phone's push/pop behaviour on a narrow one, so nothing is lost.
//! Everything below the layout — every feature, every core call — matches.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;
use zeroize::Zeroize;

use crate::app::App;
use crate::core;
use crate::i18n::t;
use crate::ui::{chat, chats, contacts, dialogs, settings, widgets};
use crate::util;

/// What the content pane is showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conversation {
    Direct {
        /// Canonical peer device fingerprint — the archive/chat key.
        fingerprint: String,
        /// Contact id, needed for clear-history / delete-contact.
        contact_id: String,
        identity_id: String,
        name: String,
    },
    Group {
        group_id: String,
        name: String,
    },
}

impl Conversation {
    /// The read-state / active-conversation key, matching the core's own
    /// convention (`"group:<id>"` for groups, bare fingerprint for 1:1).
    pub fn key(&self) -> String {
        match self {
            Conversation::Direct { fingerprint, .. } => fingerprint.clone(),
            Conversation::Group { group_id, .. } => format!("group:{}", group_id),
        }
    }

    pub fn title(&self) -> String {
        match self {
            Conversation::Direct { name, .. } => name.clone(),
            Conversation::Group { name, .. } => name.clone(),
        }
    }
}

pub struct MainUi {
    pub app: Rc<App>,
    pub split: adw::NavigationSplitView,
    /// Lets the chat list highlight the open row and lets a re-open of the
    /// same conversation be a no-op instead of a jarring rebuild.
    pub open: RefCell<Option<Conversation>>,
    /// The chats list's rebuild hook (weak; `chats::build` owns it). Local
    /// actions (send, edit, delete, forward, read) emit no core event, so
    /// they call `refresh_chats` themselves.
    pub chats_refresh: RefCell<Option<std::rc::Weak<dyn Fn()>>>,
}

impl MainUi {
    pub fn refresh_chats(&self) {
        let refresh = self.chats_refresh.borrow().as_ref().and_then(|weak| weak.upgrade());
        if let Some(refresh) = refresh {
            refresh();
        }
    }

    pub fn open_conversation(self: &Rc<Self>, conversation: Conversation) {
        if self.open.borrow().as_ref() == Some(&conversation) {
            self.split.set_show_content(true);
            return;
        }
        let page = chat::build(self, &conversation);
        self.split.set_content(Some(&page));
        self.split.set_show_content(true);
        *self.open.borrow_mut() = Some(conversation);
    }

    /// Called when the open conversation stops existing (contact deleted,
    /// group left) so the content pane does not keep pointing at nothing.
    pub fn close_conversation(self: &Rc<Self>) {
        *self.open.borrow_mut() = None;
        *self.app.active_conversation.borrow_mut() = None;
        self.split.set_content(Some(&placeholder_page(self)));
        self.split.set_show_content(false);
    }

    /// `close_conversation`, but only when `conversation` is the open one.
    pub fn close_if_open(self: &Rc<Self>, conversation: &Conversation) {
        let open = self.open.borrow().as_ref().map(Conversation::key);
        if open == Some(conversation.key()) {
            self.close_conversation();
        }
    }

    /// Rebuilds the open chat page when it shows `conversation` (after its
    /// history was cleared, say).
    pub fn reload_if_open(self: &Rc<Self>, conversation: &Conversation) {
        let open = self.open.borrow().clone();
        if let Some(open) = open.filter(|open| open.key() == conversation.key()) {
            *self.open.borrow_mut() = None;
            self.open_conversation(open);
        }
    }

    /// Toggles the chat-list sidebar between shown and collapsed.
    /// The split view handles drag-to-resize (300-420px) by itself. This
    /// toggle lets the user hide the sidebar completely, whatever the window
    /// width. `collapsed` is not tied to a breakpoint, so the sidebar never
    /// collapses on its own.
    /// `collapsed=true` with `show_content=true` hides the chat list and lets
    /// the content fill the window. The toggle button is also added to the
    /// content headers, so the sidebar can be shown again.
    pub fn toggle_sidebar(self: &Rc<Self>) {
        let collapsing = !self.split.is_collapsed();
        self.split.set_collapsed(collapsing);
        if collapsing {
            self.split.set_show_content(true);
        }
    }
}

/// See `MainUi::toggle_sidebar`. The button goes into the sidebar's own
/// header and into every content page header (chat view and the "nothing
/// selected" placeholder). Without it there is no way to show the sidebar
/// again once it is collapsed. The icon and tooltip update when
/// `split.collapsed` changes.
pub(crate) fn sidebar_toggle_button(main: &Rc<MainUi>) -> gtk::Button {
    let button = gtk::Button::builder().build();
    button.add_css_class("flat");

    // One icon instead of a directional pair. This name is present in every
    // Adwaita icon theme. The direction comes from the tooltip and the
    // pressed or unpressed look of the button.
    button.set_icon_name("sidebar-show-symbolic");
    // Weak refs both ways: the handler lives on `split`, the button inside
    // it — strong captures would be a cycle that leaks every chat page.
    let sync = {
        let split = main.split.downgrade();
        let button = button.downgrade();
        move || {
            let (Some(split), Some(button)) = (split.upgrade(), button.upgrade()) else { return };
            let collapsed = split.is_collapsed();
            button.set_tooltip_text(Some(if collapsed { t("Show chat list") } else { t("Collapse chat list") }));
        }
    };
    sync();
    let handler = main.split.connect_collapsed_notify(move |_| sync());
    // A new button is made per chat page; drop the handler with it.
    let handler = RefCell::new(Some(handler));
    let split = main.split.downgrade();
    button.connect_destroy(move |_| {
        if let (Some(split), Some(id)) = (split.upgrade(), handler.borrow_mut().take()) {
            split.disconnect(id);
        }
    });

    let main = main.clone();
    button.connect_clicked(move |_| main.toggle_sidebar());
    button
}

pub fn build_main(app: &Rc<App>, host: &adw::ToastOverlay) {
    let split = adw::NavigationSplitView::builder()
        .min_sidebar_width(300.0)
        .max_sidebar_width(420.0)
        .sidebar_width_fraction(0.32)
        .build();

    let main = Rc::new(MainUi {
        app: app.clone(),
        split: split.clone(),
        open: RefCell::new(None),
        chats_refresh: RefCell::new(None),
    });

    split.set_sidebar(Some(&sidebar(&main)));
    split.set_content(Some(&placeholder_page(&main)));
    host.set_child(Some(&split));

    // A device-change alert is a security decision the user must make before
    // trusting new keys, so it is checked on a timer and shown modally —
    // the same treatment MainActivity gives it.
    dialogs::watch_device_alerts(app);

    // a passphrase-sealed vault re-locks itself after 10 minutes
    // without input. The gate is installed either way: the passphrase can
    // be added or removed in Settings at any time, and the watcher checks
    // the vault before it locks.
    idle_lock(app, host);
}

// --- M172: idle re-lock ---

/// Ten minutes of no user input re-locks the window. A constant, not a
/// setting: the owner decision was "a setting only if trivial".
const IDLE_LOCK_MS: u64 = crate::app::IDLE_LOCK_MS;

/// How often the idle watcher looks. Cheap: a timestamp comparison, plus a
/// nine-byte read of the vault header.
const IDLE_TICK_SECONDS: u32 = 15;

/// Puts a lock page over the main UI when the vault is passphrase-sealed and
/// the user has been idle for `IDLE_LOCK_MS`.
///
/// The content is not torn down: a `GtkStack` above the live UI swaps in the
/// lock page. Detaching the conversation tree instead would make every
/// per-chat timer break on its `root().is_none()` guard (see `ui/chat/mod.rs`),
/// while a page that is merely not visible is simply skipped.
///
/// The core keeps running the whole time: messages still arrive, and
/// notifications still follow the hide-content setting (`App::notify_if_away`
/// treats a locked window as "not looking at it"). The passphrase is
/// re-verified with `secrets::load` off the GTK thread, exactly as
/// `onboarding::prompt_passphrase` does — Argon2id (64 MiB x 3) plus the
/// wallet round-trip froze the UI for seconds when it ran inline.
fn idle_lock(app: &Rc<App>, host: &adw::ToastOverlay) {
    let Some(window) = app.window() else { return };
    let main = window.clone();

    // --- the lock page ---
    let error = gtk::Label::builder().wrap(true).build();
    error.add_css_class("error");

    let entry = gtk::PasswordEntry::builder().show_peek_icon(true).build();
    entry.set_placeholder_text(Some(t("Passphrase")));

    let unlock = gtk::Button::builder().label(t("Unlock")).build();
    unlock.add_css_class("suggested-action");
    unlock.add_css_class("pill");

    // Without this the user would be stuck: the lock page replaces the whole
    // window content, so the header bar (and its close button) is gone too.
    let quit = gtk::Button::builder().label(t("Quit Typeon")).build();
    quit.add_css_class("flat");

    let form = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .build();
    form.append(&entry);
    form.append(&unlock);
    form.append(&error);
    form.append(&quit);

    let lock_page = adw::StatusPage::builder()
        .icon_name("system-lock-screen-symbolic")
        .title(t("Typeon is locked"))
        .description(
            t("Ten minutes without input. Messages keep arriving — enter your \
             passphrase to continue."),
        )
        .child(&adw::Clamp::builder().maximum_size(420).child(&form).build())
        .build();

    // --- the stack: the live UI under, the lock page over it ---
    let stack = gtk::Stack::new();
    // The window lets go of `host` first — `add_child` reparents, and a
    // widget cannot have two parents.
    window.set_content(Some(&stack));
    stack.add_child(host);
    stack.set_visible_child(host);
    // Its own header bar: the lock page covers the main UI's, and without one
    // the window has no title, buttons or drag area (on Windows nothing else
    // draws a frame).
    let lock_view = adw::ToolbarView::new();
    lock_view.add_top_bar(&adw::HeaderBar::new());
    lock_view.set_content(Some(&lock_page));
    stack.add_child(&lock_view);

    // --- activity ---
    // Any input event that reaches the window counts, watched in the capture
    // phase: the composer stops some key events of its own (see `ui/chat/composer.rs`)
    // and a bubble-phase controller would never see those.
    let activity = Rc::new(Cell::new(util::now_ms()));
    {
        let activity = activity.clone();
        let app = app.clone();
        let controller = gtk::EventControllerLegacy::new();
        controller.set_propagation_phase(gtk::PropagationPhase::Capture);
        controller.connect_event(move |_, _| {
            let now = util::now_ms();
            activity.set(now);
            app.last_input.set(now);
            glib::Propagation::Proceed
        });
        window.add_controller(controller);
    }
    {
        // Coming back to the window counts as being there: the user may
        // have been working in another window (Settings) the whole time,
        // and that window's input never reaches this one.
        let activity = activity.clone();
        let app = app.clone();
        window.connect_is_active_notify(move |window| {
            if window.is_active() {
                let now = util::now_ms();
                activity.set(now);
                app.last_input.set(now);
            }
        });
    }

    // Whether the lock page is up, and the windows it put away.
    let locked = Rc::new(Cell::new(false));
    let hidden = Rc::new(RefCell::new(Vec::<gtk::Window>::new()));

    // A window shown while locked (a dialog from a late async callback, a
    // viewer) goes away at once and comes back on unlock, like the ones the
    // watcher hid. The call window stays: `ui::call` hides the caller there.
    {
        let (locked, hidden, main) = (locked.clone(), hidden.clone(), main.clone());
        app.application.connect_window_added(move |_, added| {
            let (locked, hidden, main) = (locked.clone(), hidden.clone(), main.clone());
            added.connect_visible_notify(move |other| {
                if locked.get()
                    && other.is_visible()
                    && !is_same_window(other, &main)
                    && !crate::ui::call::is_call_window(other)
                {
                    other.set_visible(false);
                    hidden.borrow_mut().push(other.clone());
                }
            });
        });
    }

    // --- unlock ---
    let try_unlock: Rc<dyn Fn()> = {
        let app = app.clone();
        let entry = entry.clone();
        let unlock = unlock.clone();
        let error = error.clone();
        let stack = stack.clone();
        let host = host.clone();
        let activity = activity.clone();
        let locked = locked.clone();
        let hidden = hidden.clone();
        Rc::new(move || {
            let mut passphrase = entry.text().to_string();
            if passphrase.is_empty() {
                error.set_text(t("Enter your passphrase."));
                return;
            }
            let data_dir = app.data_dir.clone();
            entry.set_sensitive(false);
            unlock.set_sensitive(false);
            error.set_text("");
            let (app, entry, unlock, error, stack, host, activity, locked, hidden) = (
                app.clone(),
                entry.clone(),
                unlock.clone(),
                error.clone(),
                stack.clone(),
                host.clone(),
                activity.clone(),
                locked.clone(),
                hidden.clone(),
            );
            // The core loaded its keys at boot, so this `load` only proves
            // the passphrase — the fresh vault is dropped as soon as it
            // arrives.
            crate::app::run_in_background(
                move || {
                    let result = crate::secrets::load(&data_dir, &passphrase).err();
                    passphrase.zeroize();
                    result
                },
                move |failure| {
                    entry.set_sensitive(true);
                    unlock.set_sensitive(true);
                    match failure {
                        Some(message) => {
                            error.set_text(&message);
                            // A typo costs one keystroke, not a retype.
                            entry.set_text("");
                        }
                        None => {
                            error.set_text("");
                            stack.set_visible_child(&host);
                            // Unlocked first: the windows shown again below
                            // must not be caught by the lock's own hook.
                            app.locked.set(false);
                            activity.set(util::now_ms());
                            app.last_input.set(util::now_ms());
                            locked.set(false);
                            let away = std::mem::take(&mut *hidden.borrow_mut());
                            for other in away {
                                other.set_visible(true);
                            }
                        }
                    }
                },
            );
        })
    };
    {
        let try_unlock = try_unlock.clone();
        entry.connect_activate(move |_| try_unlock());
    }
    {
        let try_unlock = try_unlock;
        unlock.connect_clicked(move |_| try_unlock());
    }
    {
        let app = app.clone();
        quit.connect_clicked(move |_| app.application.quit());
    }

    // --- the watcher ---
    let watcher = {
        let app = app.clone();
        let activity = activity.clone();
        let locked = locked.clone();
        let stack = stack.clone();
        let lock_view = lock_view.clone();
        let hidden = hidden.clone();
        let main = main.clone();
        move || {
            if locked.get() {
                return glib::ControlFlow::Continue;
            }
            let now = util::now_ms();
            if now.saturating_sub(activity.get()) < IDLE_LOCK_MS {
                return glib::ControlFlow::Continue;
            }
            // Working in another window (Settings, a call) is not idle time.
            if app
                .application
                .windows()
                .iter()
                .any(|other| other.is_active() && !is_same_window(other, &main))
            {
                activity.set(now);
                return glib::ControlFlow::Continue;
            }
            // A wallet-only vault has no second factor: there is nothing to
            // re-verify, so there is no gate either. The passphrase can be
            // added or removed in Settings at any time, so this is checked
            // here and not once at startup.
            if !crate::secrets::is_passphrase_protected(&app.data_dir) {
                activity.set(now);
                return glib::ControlFlow::Continue;
            }
            // Everything but the main window goes away: a modal Settings
            // window on top of the lock page would be a dead end. A live
            // call keeps its window — the call is not idle.
            let away: Vec<gtk::Window> = app
                .application
                .windows()
                .into_iter()
                .filter(|other| {
                    other.is_visible()
                        && !is_same_window(other, &main)
                        && !crate::ui::call::is_call_window(other)
                })
                .collect();
            for other in &away {
                other.set_visible(false);
            }
            *hidden.borrow_mut() = away;
            app.locked.set(true);
            locked.set(true);
            stack.set_visible_child(&lock_view);
            // Decrypted attachment copies must not sit on disk behind the
            // lock page, as Android's AppLock empties them too.
            crate::app::run_in_background(|| dialogs::clear_decrypted_cache(), |()| {});
            glib::ControlFlow::Continue
        }
    };
    glib::timeout_add_seconds_local(IDLE_TICK_SECONDS, watcher);
}

/// Whether two windows are the same one (`gtk::Application::windows` hands
/// out `gtk::Window`s, the main window is an `adw::ApplicationWindow`).
fn is_same_window(one: &gtk::Window, other: &adw::ApplicationWindow) -> bool {
    // GObject identity (gtk-rs `PartialEq` compares the object pointer), not
    // the address of the two Rust wrappers, which never match.
    one == other.upcast_ref::<gtk::Window>()
}

fn sidebar(main: &Rc<MainUi>) -> adw::NavigationPage {
    let stack = adw::ViewStack::new();
    stack.add_titled_with_icon(
        &chats::build(main),
        Some("chats"),
        t("Chats"),
        "user-available-symbolic",
    );
    stack.add_titled_with_icon(
        &contacts::build(main),
        Some("contacts"),
        t("Contacts"),
        "system-users-symbolic",
    );

    let switcher = adw::ViewSwitcher::builder()
        .stack(&stack)
        .policy(adw::ViewSwitcherPolicy::Wide)
        .build();

    let header = adw::HeaderBar::builder().title_widget(&switcher).build();
    header.pack_end(&menu_button(main));
    header.pack_start(&status_indicator(&main.app));
    header.pack_start(&sidebar_toggle_button(main));

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&stack));

    adw::NavigationPage::builder()
        .title("Typeon")
        .child(&toolbar)
        .build()
}

/// The "nothing selected" content pane.
fn placeholder_page(main: &Rc<MainUi>) -> adw::NavigationPage {
    let status = adw::StatusPage::builder()
        .icon_name("mail-unread-symbolic")
        .title(t("No conversation open"))
        .description(t("Pick a chat on the left, or add a contact to start one."))
        .build();

    let header = adw::HeaderBar::new();
    // See `MainUi::toggle_sidebar`. When the sidebar is collapsed
    // (`collapsed=true`) this page is shown, so this button is the only way
    // back to the sidebar.
    header.pack_start(&sidebar_toggle_button(main));

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&status));

    adw::NavigationPage::builder()
        .title("Typeon")
        .child(&toolbar)
        .build()
}

/// Live connection state, the desktop version of `ConnectionStatus.current()`:
/// a coloured dot plus a short summary, both derived from the same decision so
/// they can never disagree.
fn status_indicator(app: &Rc<App>) -> gtk::Box {
    let dot = gtk::Label::new(Some("●"));
    let text = gtk::Label::new(Some(t("Connecting…")));
    text.add_css_class("caption");
    text.add_css_class("dim-label");

    let row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .tooltip_text(t("This device's own network status"))
        .build();
    row.append(&dot);
    row.append(&text);

    let paint = {
        let dot = dot.clone();
        let text = text.clone();
        move |status: core::OwnStatus| {
            // Tor is the only transport: with it off the network never starts.
            let (css_class, label) = if !status.tor_enabled {
                ("error", t("Network off (Tor disabled in Settings)"))
            } else {
                match status.tor_status.as_str() {
                    "ready" => (
                        "success",
                        if status.node_mode {
                            t("Connected via Tor · node")
                        } else {
                            t("Connected via Tor")
                        },
                    ),
                    "failed" => ("error", t("Tor failed")),
                    _ => ("warning", t("Starting Tor…")),
                }
            };

            for stale in ["success", "warning", "error"] {
                dot.remove_css_class(stale);
            }
            dot.add_css_class(css_class);
            text.set_label(label);
        }
    };
    // Off the GTK thread: the core lock is shared with the poll thread.
    let paint = Rc::new(paint);
    // one query in flight at a time — a poll round holding the core lock
    // for seconds no longer stacks a waiting thread every 2 s.
    let in_flight = Rc::new(std::cell::Cell::new(false));
    let refresh = move || {
        if in_flight.replace(true) {
            return;
        }
        let paint = paint.clone();
        let in_flight = in_flight.clone();
        crate::app::run_in_background(core::own_status, move |status| {
            in_flight.set(false);
            paint(status)
        });
    };

    refresh();
    let app = app.clone();
    let row_weak = row.downgrade();
    glib::timeout_add_seconds_local(2, move || {
        // Gone -> stop; hidden, minimized or in the background -> no thread
        // + core round-trip.
        let Some(row) = row_weak.upgrade() else { return glib::ControlFlow::Break };
        if row.is_mapped() && app.window().is_some_and(|window| window.is_active()) {
            refresh();
        }
        glib::ControlFlow::Continue
    });

    row
}

fn menu_button(main: &Rc<MainUi>) -> gtk::MenuButton {
    let (popover, items) = widgets::menu_popover();

    #[allow(unused_mut)]
    let mut entries: Vec<(&str, &str, Box<dyn Fn(&Rc<MainUi>)>)> = vec![
        (
            "list-add-symbolic",
            t("New group"),
            Box::new(|main: &Rc<MainUi>| dialogs::create_group(main)),
        ),
        (
            "contact-new-symbolic",
            t("Add contact"),
            Box::new(|main: &Rc<MainUi>| dialogs::add_contact(&main.app)),
        ),
        (
            "view-reveal-symbolic",
            t("My contact code"),
            Box::new(|main: &Rc<MainUi>| dialogs::show_own_code(&main.app)),
        ),
        (
            "phonelink-symbolic",
            t("Linked devices"),
            Box::new(|main: &Rc<MainUi>| dialogs::linked_devices(&main.app)),
        ),
        (
            "document-send-symbolic",
            t("Pending messages"),
            Box::new(|main: &Rc<MainUi>| dialogs::pending_messages(&main.app)),
        ),
        (
            "preferences-system-symbolic",
            t("Settings"),
            Box::new(|main: &Rc<MainUi>| settings::present(&main.app)),
        ),
    ];
    // Windows: closing the window only hides it to the tray.
    #[cfg(windows)]
    entries.push((
        "application-exit-symbolic",
        t("Quit"),
        Box::new(|main: &Rc<MainUi>| main.app.application.quit()),
    ));

    for (icon, label, action) in entries {
        let button = widgets::menu_item(icon, label);
        let main = main.clone();
        let popover = popover.clone();
        button.connect_clicked(move |_| {
            popover.popdown();
            action(&main);
        });
        items.append(&button);
    }

    gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .tooltip_text(t("Main menu"))
        .popover(&popover)
        .build()
}
