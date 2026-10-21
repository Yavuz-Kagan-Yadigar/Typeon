//! The main window: a sidebar holding the Chats/Contacts lists, and a content
//! pane holding the open conversation.
//!
//! This is the one place the layout deliberately departs from the phone. The
//! Android app is a stack of full-screen activities with a bottom nav bar;
//! that would waste most of a desktop window. `AdwNavigationSplitView` gives
//! the list and the conversation side by side on a wide window and collapses
//! back to the phone's push/pop behaviour on a narrow one, so nothing is lost.
//! Everything below the layout — every feature, every core call — matches.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::app::App;
use crate::core;
use crate::ui::{chat, chats, contacts, dialogs, settings, widgets};

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
}

impl MainUi {
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

    /// Spec dışı, kullanıcı isteği ("bir left bar with chat list, ve onu
    /// resize/fully close edecek bir dragable bar"): drag-to-resize
    /// (300-420px arası) `AdwNavigationSplitView`'a zaten yerleşik — ekstra
    /// kod gerektirmiyor. Eksik olan tek şey, pencere genişliğinden BAĞIMSIZ
    /// olarak kullanıcının kendi isteğiyle kenar çubuğunu TAMAMEN
    /// kapatabilmesiydi (`collapsed` alanı burada hiçbir `AdwBreakpoint`'e
    /// bağlı değil, yani otomatik daralmıyor — bkz. dosya başı notu, bu
    /// zaten amaçlanan davranış değil, sadece hiç kullanılmamış bir alan).
    /// `collapsed=true` + `show_content=true`: sohbet listesi tamamen
    /// gizlenir, içerik tüm pencereyi kaplar; tekrar açmak için bkz.
    /// `sidebar_toggle_button` (içerik başlıklarına da eklenir, aksi halde
    /// kenar çubuğu kapatıldıktan sonra geri açacak hiçbir yol kalmazdı).
    pub fn toggle_sidebar(self: &Rc<Self>) {
        let collapsing = !self.split.is_collapsed();
        self.split.set_collapsed(collapsing);
        if collapsing {
            self.split.set_show_content(true);
        }
    }
}

/// bkz. `MainUi::toggle_sidebar` dokümantasyonu. Kenar çubuğunun KENDİ
/// başlığına VE her içerik sayfasının başlığına (sohbet ekranı + "hiçbir
/// şey seçili değil" yer tutucusu) eklenir — aksi halde kenar çubuğu
/// kapatıldıktan sonra geri açacak hiçbir yol kalmaz. `split.collapsed`
/// değişince (bu düğmeden ya da ileride eklenecek bir `AdwBreakpoint`'ten)
/// simge/ipucu kendiliğinden güncellenir.
pub(crate) fn sidebar_toggle_button(main: &Rc<MainUi>) -> gtk::Button {
    let button = gtk::Button::builder().build();
    button.add_css_class("flat");

    // Tek bir simge yeterli (yönlü bir çift yerine) — Adwaita ikon
    // temasında HER sürümde bulunması garanti olan tek bu ad; hangi yönde
    // olduğu ipucu metninden ve düğmenin basılı/basılı-değil görünümünden
    // zaten anlaşılıyor.
    button.set_icon_name("sidebar-show-symbolic");
    // Weak refs both ways: the handler lives on `split`, the button inside
    // it — strong captures would be a cycle that leaks every chat page.
    let sync = {
        let split = main.split.downgrade();
        let button = button.downgrade();
        move || {
            let (Some(split), Some(button)) = (split.upgrade(), button.upgrade()) else { return };
            let collapsed = split.is_collapsed();
            button.set_tooltip_text(Some(if collapsed { "Show chat list" } else { "Collapse chat list" }));
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
    });

    split.set_sidebar(Some(&sidebar(&main)));
    split.set_content(Some(&placeholder_page(&main)));
    host.set_child(Some(&split));

    // A device-change alert is a security decision the user must make before
    // trusting new keys, so it is checked on a timer and shown modally —
    // the same treatment MainActivity gives it.
    dialogs::watch_device_alerts(app);
}

fn sidebar(main: &Rc<MainUi>) -> adw::NavigationPage {
    let stack = adw::ViewStack::new();
    stack.add_titled_with_icon(
        &chats::build(main),
        Some("chats"),
        "Chats",
        "user-available-symbolic",
    );
    stack.add_titled_with_icon(
        &contacts::build(main),
        Some("contacts"),
        "Contacts",
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
        .title("No conversation open")
        .description("Pick a chat on the left, or add a contact to start one.")
        .build();

    let header = adw::HeaderBar::new();
    // bkz. `MainUi::toggle_sidebar` — kenar çubuğu kapalıyken geri açacak
    // tek yol bu, çünkü bu sayfa TAM DA kenar çubuğu görünmediğinde
    // (`collapsed=true`) görünür durumda.
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
    let text = gtk::Label::new(Some("Connecting…"));
    text.add_css_class("caption");
    text.add_css_class("dim-label");

    let row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .tooltip_text("This device's own network status")
        .build();
    row.append(&dot);
    row.append(&text);

    let paint = {
        let dot = dot.clone();
        let text = text.clone();
        move |status: core::OwnStatus| {
            let (css_class, label) = if status.tor_enabled {
                match status.tor_status.as_str() {
                    "ready" => (
                        "success",
                        if status.node_mode {
                            "Connected via Tor · node"
                        } else {
                            "Connected via Tor"
                        },
                    ),
                    "failed" => ("error", "Tor failed"),
                    _ => ("warning", "Starting Tor…"),
                }
            } else if status.connected_peers > 0 {
                (
                    "success",
                    if status.node_mode {
                        "Connected · node"
                    } else {
                        "Connected"
                    },
                )
            } else {
                ("warning", "Reconnecting…")
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
    // H130: one query in flight at a time — a poll round holding the core lock
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
    let _ = app;
    let row_weak = row.downgrade();
    glib::timeout_add_seconds_local(2, move || {
        // Gone -> stop; hidden/minimized -> no thread + core round-trip.
        let Some(row) = row_weak.upgrade() else { return glib::ControlFlow::Break };
        if row.is_mapped() {
            refresh();
        }
        glib::ControlFlow::Continue
    });

    row
}

fn menu_button(main: &Rc<MainUi>) -> gtk::MenuButton {
    let (popover, items) = widgets::menu_popover();

    let entries: Vec<(&str, &str, Box<dyn Fn(&Rc<MainUi>)>)> = vec![
        (
            "list-add-symbolic",
            "New group",
            Box::new(|main: &Rc<MainUi>| dialogs::create_group(main)),
        ),
        (
            "contact-new-symbolic",
            "Add contact",
            Box::new(|main: &Rc<MainUi>| dialogs::add_contact(&main.app)),
        ),
        (
            "view-reveal-symbolic",
            "My contact code",
            Box::new(|main: &Rc<MainUi>| dialogs::show_own_code(&main.app)),
        ),
        (
            "phonelink-symbolic",
            "Linked devices",
            Box::new(|main: &Rc<MainUi>| dialogs::linked_devices(&main.app)),
        ),
        (
            "document-send-symbolic",
            "Pending messages",
            Box::new(|main: &Rc<MainUi>| dialogs::pending_messages(&main.app)),
        ),
        (
            "preferences-system-symbolic",
            "Settings",
            Box::new(|main: &Rc<MainUi>| settings::present(&main.app)),
        ),
    ];

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
        .tooltip_text("Main menu")
        .popover(&popover)
        .build()
}
