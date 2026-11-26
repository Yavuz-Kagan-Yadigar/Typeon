//! The Chats list: contacts and groups on one timeline, newest first, pinned
//! rows on top — the desktop counterpart of `ChatsFragment`.
//!
//! Rows are rebuilt wholesale rather than diffed. The list is bounded by the
//! contact cap (500) and a rebuild is a handful of SQLite reads, so the
//! machinery a `ListAdapter`/`DiffUtil` equivalent would need buys nothing
//! here — and rebuilding keeps "what is on screen" trivially in sync with
//! "what the core says", which is where list bugs actually come from.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::core;
use crate::i18n::t;
use crate::ui::dialogs;
use crate::ui::window::{Conversation, MainUi};
use crate::util;

/// One row's worth of resolved state.
struct Row {
    conversation: Conversation,
    /// Pin key: the contact id for 1:1 (stable across device changes),
    /// `"group:<id>"` for groups — exactly the keys `ChatsFragment` uses.
    pin_key: String,
    subtitle: String,
    timestamp: u64,
    /// The newest item came from someone else: only then can the chat be
    /// unread (my own message, sent from the phone, is not).
    incoming: bool,
    unread: bool,
    pinned: bool,
    avatar_hex: Option<String>,
    is_founder: bool,
    /// Empty until the pairing handshake completes; such a contact cannot be
    /// messaged yet and the row says so instead of opening a dead chat.
    ready: bool,
}

pub fn build(main: &Rc<MainUi>) -> gtk::Widget {
    let search = gtk::SearchEntry::builder()
        .placeholder_text(t("Search chats"))
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .build();

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("navigation-sidebar");

    let empty = adw::StatusPage::builder()
        .icon_name("system-users-symbolic")
        .title(t("No chats yet"))
        .description(t("Add a contact from the main menu to start talking."))
        .build();

    let stack = gtk::Stack::new();
    let scroller = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&list)
        .build();
    stack.add_named(&scroller, Some("list"));
    stack.add_named(&empty, Some("empty"));

    let container = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();
    container.append(&search);
    container.append(&stack);

    let query = Rc::new(RefCell::new(String::new()));

    // `refresh_cell` owns `refresh` (set below), and `refresh` hands
    // itself to newly built rows through it — a strong `refresh_cell` capture
    // inside the closure would close the cycle `refresh` → `refresh_cell` →
    // `refresh` and leak one closure graph per app run. So the closure only
    // carries a Weak; the strong owner at page lifetime is the event
    // subscription further down (`subscribe` keeps its handler until the
    // container widget is destroyed), which is exactly as long as rows can
    // still ask to be rebuilt.
    let refresh_cell: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));
    let refresh_cell_weak = std::rc::Rc::downgrade(&refresh_cell);

    let refresh: Rc<dyn Fn()> = {
        let main = main.clone();
        let list = list.clone();
        let stack = stack.clone();
        let query = query.clone();
        let generation = Rc::new(std::cell::Cell::new(0u64));
        // A burst of events collapses into one rebuild.
        let pending = Rc::new(std::cell::Cell::new(false));
        Rc::new(move || {
            if pending.replace(true) {
                return;
            }
            let pending = pending.clone();
            let main = main.clone();
            let list = list.clone();
            let stack = stack.clone();
            let query = query.clone();
            let refresh_cell = refresh_cell_weak.clone();
            let generation = generation.clone();
            glib::timeout_add_local_once(std::time::Duration::from_millis(150), move || {
                pending.set(false);
                // Only the newest request may paint: a slow older one finishing
                // late would put stale rows on screen.
                let mine = generation.get() + 1;
                generation.set(mine);
                let own_identity = main.app.own_identity_id.borrow().clone();
                crate::app::run_in_background(move || collect_rows(&own_identity), move |mut rows| {
                    if generation.get() != mine {
                        return;
                    }
                    apply_prefs(&main, &mut rows);
                    let needle = query.borrow().to_lowercase();
                    let visible: Vec<&Row> = rows
                        .iter()
                        .filter(|row| {
                            needle.is_empty()
                                || row.conversation.title().to_lowercase().contains(&needle)
                        })
                        .collect();

                    // The rebuild must not throw the reader back to the top.
                    let adjustment = list
                        .parent()
                        .and_then(|viewport| viewport.parent())
                        .and_downcast::<gtk::ScrolledWindow>()
                        .map(|scroller| scroller.vadjustment());
                    let offset = adjustment.as_ref().map(|a| a.value());
                    while let Some(child) = list.first_child() {
                        list.remove(&child);
                    }
                    // The cell is filled right after this closure is created
                    // (below). If it is empty, fall back to a no-op refresh:
                    // a panic inside a GTK callback aborts the process. A pin
                    // toggle then only moves prefs; the next event or 30 s
                    // tick repaints the list.
                    let self_refresh: Rc<dyn Fn()> = refresh_cell
                        .upgrade()
                        .and_then(|cell| cell.borrow().clone())
                        .unwrap_or_else(|| Rc::new(|| {}));
                    for row in &visible {
                        list.append(&build_row(&main, row, self_refresh.clone()));
                    }
                    stack.set_visible_child_name(if visible.is_empty() { "empty" } else { "list" });
                    if let (Some(adjustment), Some(offset)) = (adjustment, offset) {
                        glib::idle_add_local_once(move || adjustment.set_value(offset));
                    }
                });
            });
        })
    };
    *refresh_cell.borrow_mut() = Some(refresh.clone());
    *main.chats_refresh.borrow_mut() = Some(Rc::downgrade(&refresh));

    {
        let refresh = refresh.clone();
        let query = query.clone();
        search.connect_search_changed(move |entry| {
            *query.borrow_mut() = entry.text().to_string();
            refresh();
        });
    }

    refresh();

    // Content changes arrive as events (below), and the stamps are absolute
    // clock times, so this 30 s tick is only a backstop for anything the event
    // list misses. A shorter tick would re-query every conversation (two
    // SQLite reads each) against the core lock the poll thread holds.
    {
        let refresh = refresh.clone();
        let container = container.downgrade();
        glib::timeout_add_seconds_local(30, move || {
            // Torn down -> stop; hidden (other tab / minimized) -> skip.
            let Some(container) = container.upgrade() else { return glib::ControlFlow::Break };
            if container.is_mapped() {
                refresh();
            }
            glib::ControlFlow::Continue
        });
    }
    {
        let refresh = refresh.clone();
        // page-lifetime owner of `refresh_cell` (see the comment above).
        // Without it the last strong reference dies with `build()`'s local,
        // `upgrade()` in the refresh callback returns None, and rows would be
        // built without a way to rebuild themselves (pin toggles).
        let refresh_cell = refresh_cell.clone();
        main.app.subscribe(&container, move |event| {
            let _ = &refresh_cell;
            if matches!(
                event.kind.as_str(),
                "message"
                    | "group_message"
                    | "sibling_message"
                    | "sibling_group_message"
                    | "file_offer"
                    | "sibling_file"
                    | "file_complete"
                    | "edit"
                    | "delete"
                    | "group_edit"
                    | "group_delete"
                    | "group_updated"
                    | "member_left"
                    | "profile_update"
                    | "device_linked"
                    | "history_backfilled"
                    | "sync"
                    | "read_state_sync"
                    | "call"
            ) {
                refresh();
            }
        });
    }

    container.upcast()
}

/// Core reads only — runs off the GTK thread (the core lock is shared with the
/// poll thread, and this is about 2 queries per conversation). `unread`/`pinned`
/// come from prefs, which live on the main thread; `apply_prefs` fills them.
fn collect_rows(own_identity: &str) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();

    for contact in core::list_contacts() {
        let fingerprint = contact.active_device_fingerprint.clone().unwrap_or_default();
        let ready = !fingerprint.is_empty();
        let newest = if ready { newest_direct(&fingerprint) } else { None };
        let (subtitle, timestamp, incoming) = match newest {
            Some((text, at, incoming)) => (text, at, incoming),
            None if ready => (t("No messages yet").to_string(), 0, false),
            None => (t("Pairing… waiting for the other device").to_string(), 0, false),
        };
        rows.push(Row {
            incoming,
            unread: false,
            pinned: false,
            pin_key: contact.contact_id.clone(),
            conversation: Conversation::Direct {
                fingerprint,
                contact_id: contact.contact_id,
                identity_id: contact.identity_id,
                name: contact.display_name,
            },
            subtitle,
            timestamp,
            avatar_hex: contact.avatar_hex,
            is_founder: false,
            ready,
        });
    }

    for group in core::list_groups() {
        let read_key = format!("group:{}", group.group_id);
        let newest = newest_group(&group.group_id, own_identity);
        let member_count = group.member_identity_ids.len();
        let (subtitle, timestamp, incoming) = match newest {
            Some((text, at, incoming)) => (text, at, incoming),
            None => (
                tf!("Members: {}", member_count),
                0,
                false,
            ),
        };
        rows.push(Row {
            incoming,
            unread: false,
            pinned: false,
            pin_key: read_key.clone(),
            conversation: Conversation::Group {
                group_id: group.group_id,
                name: group.name,
            },
            subtitle,
            timestamp,
            avatar_hex: group.avatar_hex,
            is_founder: group.is_founder,
            ready: true,
        });
    }

    rows
}

fn apply_prefs(main: &Rc<MainUi>, rows: &mut Vec<Row>) {
    let prefs = main.app.prefs.borrow();
    for row in rows.iter_mut() {
        let key = match &row.conversation {
            Conversation::Direct { fingerprint, .. } => fingerprint.clone(),
            Conversation::Group { group_id, .. } => format!("group:{}", group_id),
        };
        row.unread = row.incoming && row.timestamp > 0 && row.timestamp > prefs.last_read_at(&key);
        row.pinned = prefs.is_pinned(&row.pin_key);
    }

    // Pinned first, then most recent activity — `ChatsFragment` sorts the same
    // way, and a stable order matters because the whole list is rebuilt.
    rows.sort_by(|a, b| {
        b.pinned
            .cmp(&a.pinned)
            .then(b.timestamp.cmp(&a.timestamp))
            .then_with(|| a.conversation.title().cmp(&b.conversation.title()))
    });
}

/// Newest activity in a 1:1 chat — a text message or an attachment, whichever
/// is later. Uses the archive's local `timestamp` (receive time), not the
/// sender's `sent_at_ms`: unread state is compared against a locally recorded
/// "when I last looked", so a peer with a fast clock must not be able to make
/// old messages look new.
/// The bool: the newest item was received, not sent by me.
fn newest_direct(fingerprint: &str) -> Option<(String, u64, bool)> {
    let mut newest: Option<(String, u64, bool)> = None;

    if let Some(message) = core::message_history(fingerprint, 1).into_iter().next_back() {
        let text = if message.is_deleted {
            t("Message deleted").to_string()
        } else {
            util::preview_text(&message.text, 64)
        };
        let sent = message.direction == "sent";
        let text = if sent {
            tf!("You: {}", text)
        } else {
            text
        };
        newest = Some((text, message.timestamp, !sent));
    }

    // Only the newest file, not the whole (up to 500-row) listing.
    if let Some(attachment) = core::list_attachments_before(fingerprint, u64::MAX, 1)
        .into_iter()
        .max_by_key(|a| a.created_at)
    {
        let later = newest.as_ref().map(|(_, at, _)| attachment.created_at > *at).unwrap_or(true);
        if later {
            let label = util::attachment_label(&attachment.mime_type, &attachment.file_name, attachment.sticker);
            let sent = attachment.direction == "sent";
            let label = if sent {
                tf!("You: {}", label)
            } else {
                label
            };
            newest = Some((label, attachment.created_at, !sent));
        }
    }

    newest
}

fn newest_group(group_id: &str, own_identity: &str) -> Option<(String, u64, bool)> {
    let mut newest: Option<(String, u64, bool)> = None;

    if let Some(message) = core::group_message_history(group_id, 1).into_iter().next_back() {
        let text = if message.is_deleted {
            t("Message deleted").to_string()
        } else {
            util::preview_text(&message.text, 64)
        };
        let mine = message.direction == "sent"
            || message.sender_identity_id.as_deref().is_some_and(|id| !id.is_empty() && id == own_identity);
        newest = Some((text, message.timestamp, !mine));
    }

    if let Some(attachment) = core::list_group_attachments_before(group_id, u64::MAX, 1)
        .into_iter()
        .max_by_key(|a| a.created_at)
    {
        let later = newest.as_ref().map(|(_, at, _)| attachment.created_at > *at).unwrap_or(true);
        if later {
            newest = Some((
                util::attachment_label(&attachment.mime_type, &attachment.file_name, attachment.sticker),
                attachment.created_at,
                attachment.direction != "sent",
            ));
        }
    }

    newest
}

fn build_row(main: &Rc<MainUi>, row: &Row, refresh: Rc<dyn Fn()>) -> gtk::ListBoxRow {
    let avatar = adw::Avatar::new(40, Some(&row.conversation.title()), true);
    if let Some(texture) = row.avatar_hex.as_deref().and_then(util::texture_from_hex) {
        avatar.set_custom_image(Some(&texture));
    }

    let action_row = adw::ActionRow::builder()
        .title(glib::markup_escape_text(&row.conversation.title()).as_str())
        .subtitle(glib::markup_escape_text(&row.subtitle).as_str())
        .activatable(true)
        .build();
    action_row.add_prefix(&avatar);

    let meta = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .valign(gtk::Align::Center)
        .build();

    let stamp = gtk::Label::new(Some(&util::format_list_time(row.timestamp)));
    stamp.add_css_class("caption");
    stamp.add_css_class("dim-label");
    stamp.set_halign(gtk::Align::End);
    meta.append(&stamp);

    let badges = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(4)
        .halign(gtk::Align::End)
        .build();
    if row.pinned {
        let pin = gtk::Image::from_icon_name("view-pin-symbolic");
        pin.add_css_class("dim-label");
        badges.append(&pin);
    }
    if row.unread {
        let dot = gtk::Label::new(Some("●"));
        dot.add_css_class("accent");
        badges.append(&dot);
    }
    meta.append(&badges);
    action_row.add_suffix(&meta);

    if row.ready {
        let main = main.clone();
        let conversation = row.conversation.clone();
        action_row.connect_activated(move |_| {
            main.open_conversation(conversation.clone());
        });
    } else {
        action_row.set_activatable(false);
        action_row.set_sensitive(false);
    }

    // Right-click / long-press menu: pin, plus the destructive options that
    // differ between a contact, a group you founded and a group you only
    // joined (a founder cannot leave — they delete for everyone).
    let gesture = gtk::GestureClick::new();
    // GDK's secondary (right) button. Spelled numerically because the
    // bindings only expose the constant through the `ffi` module.
    gesture.set_button(3);
    {
        let main = main.clone();
        // Weak: the controller lives on the row, a strong ref would be a cycle
        // that leaks every rebuilt row (and its avatar texture).
        let anchor = action_row.downgrade();
        let conversation = row.conversation.clone();
        let pin_key = row.pin_key.clone();
        let pinned = row.pinned;
        let is_founder = row.is_founder;
        let refresh = refresh.clone();
        gesture.connect_pressed(move |_, _, x, y| {
            let Some(anchor) = anchor.upgrade() else { return };
            dialogs::chat_context_menu(
                &main,
                &anchor,
                &conversation,
                &pin_key,
                pinned,
                is_founder,
                x,
                y,
                refresh.clone(),
            );
        });
    }
    action_row.add_controller(gesture);

    // `AdwActionRow` *is* a `GtkListBoxRow`, so it goes into the list directly.
    // A row wrapped in another `GtkListBoxRow` would never be activated, because
    // `GtkListBox` only activates its own direct children.
    action_row.upcast()
}
