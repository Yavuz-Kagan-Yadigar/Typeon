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
    unread: bool,
    pinned: bool,
    avatar_hex: Option<String>,
    is_group: bool,
    is_founder: bool,
    /// Empty until the pairing handshake completes; such a contact cannot be
    /// messaged yet and the row says so instead of opening a dead chat.
    ready: bool,
}

pub fn build(main: &Rc<MainUi>) -> gtk::Widget {
    let search = gtk::SearchEntry::builder()
        .placeholder_text("Search chats")
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
        .title("No chats yet")
        .description("Add a contact from the main menu to start talking.")
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

    // `build_row` needs a way to ask for a rebuild (a pinned/unpinned chat has
    // to reorder immediately, not wait for the next event or the 30s
    // backstop tick), which means passing `refresh` down into the very
    // closure that constructs it — a plain `Rc<dyn Fn()>` cannot capture
    // itself by name before it exists, so it is boxed behind a cell that gets
    // filled in right after.
    let refresh_cell: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));

    let refresh: Rc<dyn Fn()> = {
        let main = main.clone();
        let list = list.clone();
        let stack = stack.clone();
        let query = query.clone();
        let refresh_cell = refresh_cell.clone();
        let generation = Rc::new(std::cell::Cell::new(0u64));
        Rc::new(move || {
            let main = main.clone();
            let list = list.clone();
            let stack = stack.clone();
            let query = query.clone();
            let refresh_cell = refresh_cell.clone();
            // Only the newest request may paint: a slow older one finishing
            // late would put stale rows on screen.
            let mine = generation.get() + 1;
            generation.set(mine);
            let generation = generation.clone();
            crate::app::run_in_background(collect_rows, move |mut rows| {
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

                while let Some(child) = list.first_child() {
                    list.remove(&child);
                }
                let self_refresh = refresh_cell
                    .borrow()
                    .clone()
                    .expect("refresh_cell is filled in immediately after this closure is created");
                for row in &visible {
                    list.append(&build_row(&main, row, self_refresh.clone()));
                }
                stack.set_visible_child_name(if visible.is_empty() { "empty" } else { "list" });
            });
        })
    };
    *refresh_cell.borrow_mut() = Some(refresh.clone());

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
    // clock times, so this slow tick is only a backstop for anything the event
    // list misses. It used to run every 5s, which re-queried every conversation
    // in the list — two SQLite round-trips each — against the same global core
    // lock the poll thread holds.
    {
        let refresh = refresh.clone();
        glib::timeout_add_seconds_local(30, move || {
            refresh();
            glib::ControlFlow::Continue
        });
    }
    {
        let refresh = refresh.clone();
        main.app.subscribe(&container, move |event| {
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
            ) {
                refresh();
            }
        });
    }

    container.upcast()
}

/// Core reads only — runs off the GTK thread (the core lock is shared with the
/// poll thread, and this is 2-4 queries per conversation). `unread`/`pinned`
/// come from prefs, which live on the main thread; `apply_prefs` fills them.
fn collect_rows() -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();

    for contact in core::list_contacts() {
        let fingerprint = contact.active_device_fingerprint.clone().unwrap_or_default();
        let ready = !fingerprint.is_empty();
        let newest = if ready { newest_direct(&fingerprint) } else { None };
        let (subtitle, timestamp) = match newest {
            Some((text, at)) => (text, at),
            None if ready => ("No messages yet".to_string(), 0),
            None => ("Pairing… waiting for the other device".to_string(), 0),
        };
        rows.push(Row {
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
            is_group: false,
            is_founder: false,
            ready,
        });
    }

    for group in core::list_groups() {
        let read_key = format!("group:{}", group.group_id);
        let newest = newest_group(&group.group_id);
        let member_count = group.member_identity_ids.len();
        let (subtitle, timestamp) = match newest {
            Some((text, at)) => (text, at),
            None => (
                format!(
                    "{} member{}",
                    member_count,
                    if member_count == 1 { "" } else { "s" }
                ),
                0,
            ),
        };
        rows.push(Row {
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
            is_group: true,
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
        row.unread = row.timestamp > 0 && row.timestamp > prefs.last_read_at(&key);
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
fn newest_direct(fingerprint: &str) -> Option<(String, u64)> {
    let mut newest: Option<(String, u64)> = None;

    if let Some(message) = core::message_history(fingerprint, 1).into_iter().next_back() {
        let text = if message.is_deleted {
            "Message deleted".to_string()
        } else {
            util::preview_text(&message.text, 64)
        };
        let text = if message.direction == "sent" {
            format!("You: {}", text)
        } else {
            text
        };
        newest = Some((text, message.timestamp));
    }

    if let Some(attachment) = core::list_attachments_brief(fingerprint)
        .into_iter()
        .max_by_key(|a| a.created_at)
    {
        let later = newest.as_ref().map(|(_, at)| attachment.created_at > *at).unwrap_or(true);
        if later {
            let label = util::attachment_label(&attachment.mime_type, &attachment.file_name);
            let label = if attachment.direction == "sent" {
                format!("You: {}", label)
            } else {
                label
            };
            newest = Some((label, attachment.created_at));
        }
    }

    newest
}

fn newest_group(group_id: &str) -> Option<(String, u64)> {
    let mut newest: Option<(String, u64)> = None;

    if let Some(message) = core::group_message_history(group_id, 1).into_iter().next_back() {
        let text = if message.is_deleted {
            "Message deleted".to_string()
        } else {
            util::preview_text(&message.text, 64)
        };
        newest = Some((text, message.timestamp));
    }

    if let Some(attachment) = core::list_group_attachments_brief(group_id)
        .into_iter()
        .max_by_key(|a| a.created_at)
    {
        let later = newest.as_ref().map(|(_, at)| attachment.created_at > *at).unwrap_or(true);
        if later {
            newest = Some((
                util::attachment_label(&attachment.mime_type, &attachment.file_name),
                attachment.created_at,
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
        let anchor = action_row.clone();
        let conversation = row.conversation.clone();
        let pin_key = row.pin_key.clone();
        let pinned = row.pinned;
        let is_group = row.is_group;
        let is_founder = row.is_founder;
        let refresh = refresh.clone();
        gesture.connect_pressed(move |_, _, x, y| {
            dialogs::chat_context_menu(
                &main,
                &anchor,
                &conversation,
                &pin_key,
                pinned,
                is_group,
                is_founder,
                x,
                y,
                refresh.clone(),
            );
        });
    }
    action_row.add_controller(gesture);

    // `AdwActionRow` *is* a `GtkListBoxRow`, so it goes into the list directly.
    // Wrapping it in another `GtkListBoxRow` was the bug that stopped chats
    // from opening: `GtkListBox` only activates its own direct children, so the
    // nested row never emitted `activated` and the click went nowhere.
    action_row.upcast()
}
