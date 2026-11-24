//! App event handling for an open chat: incoming messages, edits, deletes, status, typing.

use super::*;

impl ChatView {
    pub(super) fn handle_event(self: &Rc<Self>, event: &Event) {
        let own_identity = self.app().own_identity_id.borrow().clone();
        if event.kind == "whiteboard" {
            self.whiteboard.handle_event(event);
            return;
        }

        match (&self.conversation, event.kind.as_str()) {
            (Conversation::Direct { fingerprint, .. }, "account_deleted")
                if event.string("peer") == *fingerprint =>
            {
                self.lock_account_deleted();
            }
            // --- incoming text ---
            (Conversation::Direct { fingerprint, .. }, "message")
                if event.string("peer") == *fingerprint =>
            {
                self.insert_entry(
                    Entry {
                        // `""` here would collide with every other
                        // id-less event on the empty key (see `fresh_local_id`).
                        id: nonempty_or(event.optional("message_id"), self.fresh_local_id()),
                        mine: false,
                        sender_identity: String::new(),
                        text: event.string("text"),
                        order_key: nonzero_or(event.number("sent_at_ms"), util::now_ms()),
                        status: None,
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: None,
                        reply_id: event.optional("reply_to_message_id"),
                        deleted: false,
                        edited: false,
                        attachment: None,
                        seen_by: Vec::new(),
                        reactions: String::new(),
                        expire: event_expiry(event),
                    },
                    true,
                );
                self.mark_read_if_watched();
            }
            (Conversation::Group { group_id, .. }, "group_message")
                if event.string("group_id") == *group_id =>
            {
                let sender = event.string("sender_identity_id");
                self.insert_entry(
                    Entry {
                        // see `fresh_local_id`.
                        id: nonempty_or(
                            event.optional("group_message_local_id"),
                            nonempty_or(event.optional("message_id"), self.fresh_local_id()),
                        ),
                        mine: sender == own_identity,
                        sender_identity: sender,
                        text: event.string("text"),
                        order_key: nonzero_or(event.number("sent_at_ms"), util::now_ms()),
                        status: None,
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: event.optional("reply_to_sender_identity_id"),
                        reply_id: event.optional("reply_to_message_id"),
                        deleted: false,
                        edited: false,
                        attachment: None,
                        seen_by: Vec::new(),
                        reactions: String::new(),
                        expire: event_expiry(event),
                    },
                    true,
                );
                self.mark_read_if_watched();
            }

            // The core logged a "Missed call" row for this chat: it counts
            // as read while the chat is open, like any incoming message.
            (Conversation::Direct { fingerprint, .. }, "call")
                if event.flag("missed") && event.string("peer") == *fingerprint =>
            {
                self.mark_read_if_watched();
            }

            // --- my own message, echoed from another of my devices ---
            (Conversation::Direct { fingerprint, .. }, "sibling_message")
                if event.string("peer") == *fingerprint =>
            {
                self.insert_entry(
                    Entry {
                        // see `fresh_local_id`.
                        id: nonempty_or(event.optional("message_id"), self.fresh_local_id()),
                        mine: true,
                        sender_identity: own_identity,
                        text: event.string("text"),
                        order_key: nonzero_or(event.number("sent_at_ms"), util::now_ms()),
                        status: Some("sent".to_string()),
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: None,
                        reply_id: event.optional("reply_to_message_id"),
                        deleted: false,
                        edited: false,
                        attachment: None,
                        seen_by: Vec::new(),
                        reactions: String::new(),
                        expire: event_expiry(event),
                    },
                    true,
                );
            }
            (Conversation::Group { group_id, .. }, "sibling_group_message")
                if event.string("group_id") == *group_id =>
            {
                self.insert_entry(
                    Entry {
                        // see `fresh_local_id`.
                        id: nonempty_or(
                            event.optional("group_message_local_id"),
                            nonempty_or(event.optional("message_id"), self.fresh_local_id()),
                        ),
                        mine: true,
                        sender_identity: own_identity,
                        text: event.string("text"),
                        order_key: nonzero_or(event.number("sent_at_ms"), util::now_ms()),
                        status: Some("sent".to_string()),
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: event.optional("reply_to_sender_identity_id"),
                        reply_id: event.optional("reply_to_message_id"),
                        deleted: false,
                        edited: false,
                        attachment: None,
                        seen_by: Vec::new(),
                        reactions: String::new(),
                        expire: event_expiry(event),
                    },
                    true,
                );
            }

            // --- edits and deletes, from either side ---
            (Conversation::Direct { fingerprint, .. }, "edit")
                if event.string("peer") == *fingerprint =>
            {
                self.apply_edit(&event.string("message_id"), &event.string("text"));
            }
            (Conversation::Direct { fingerprint, .. }, "delete")
                if event.string("peer") == *fingerprint =>
            {
                self.apply_delete(&event.string("message_id"));
            }
            (Conversation::Group { group_id, .. }, "group_edit")
                if event.string("group_id") == *group_id =>
            {
                self.apply_edit(&event.string("message_id"), &event.string("text"));
            }
            (Conversation::Group { group_id, .. }, "group_delete")
                if event.string("group_id") == *group_id =>
            {
                self.apply_delete(&event.string("message_id"));
            }

            // --- delivery state on my own bubbles ---
            (_, "status") | (_, "ack") => {
                let id = event.string("message_id");
                let status = if event.kind == "ack" {
                    "sent".to_string()
                } else {
                    event.string("status")
                };
                self.apply_status(&id, &status);
            }
            (_, "reaction") if self.event_belongs_here(event) => {
                self.apply_reactions(&event.string("message_id"), &event.string("reactions"));
            }
            // Read boundary (ReadStateSync): every message it covers, oldest
            // first. Only the newest one can carry the seen-by row.
            (_, "seen_bulk") if self.event_belongs_here(event) => {
                let ids = event.value.get("message_ids").and_then(|v| v.as_array());
                if let Some(id) = ids.and_then(|ids| ids.iter().rev().find_map(|v| v.as_str())) {
                    self.refresh_seen(id);
                }
            }
            (_, "seen") => {
                let id = nonempty_or(
                    event.optional("group_message_local_id"),
                    event.string("message_id"),
                );
                self.refresh_seen(&id);
            }

            // --- typing ---
            (Conversation::Direct { fingerprint, .. }, "typing")
                if event.string("peer") == *fingerprint =>
            {
                self.show_typing(event.flag("is_typing"), None);
            }
            (Conversation::Group { group_id, .. }, "typing")
                if event.optional("group_id").as_deref() == Some(group_id.as_str()) =>
            {
                let who = self.app().identity_name(&event.string("sender_identity_id"));
                self.show_typing(event.flag("is_typing"), Some(who));
            }

            // --- attachments ---
            // a full `reload()` per offer — every core round-trip it
            // implies, run for each file in a burst — is gone; the attachment
            // bubble is built in place instead, with exactly the fields the
            // reload's `fetch_page` merge would have produced (it merges
            // attachments on the first page from the very row the core just
            // wrote for this event, so pre-`reload()` this insert already
            // matches). `file_progress`/`file_complete` then drive the card
            // by `file_id` as before.
            // Ticks: attachment bubbles carry no delivery status (same as the
            // archive merge, which sets `status: None`) — see `fetch_page`.
            (_, "file_offer" | "sibling_file") if self.event_belongs_here(event) => {
                let attachment = Some(Attachment {
                    file_id: event.string("file_id"),
                    file_name: event.string("file_name"),
                    mime: event.string("mime_type"),
                    total_size: event.number("total_size"),
                    // The peer column: the canonical chat key for 1:1, the
                    // sending member's device in a group — matches
                    // `list_attachments`' `peer_device_fingerprint`.
                    source_fingerprint: event.string("peer"),
                    status: if event.flag("complete") {
                        "complete".to_string()
                    } else if event.flag("auto_downloading") {
                        "downloading".to_string()
                    } else {
                        "offered".to_string()
                    },
                    preview_hex: event.optional("preview_hex"),
                    bytes_done: 0,
                    duration_ms: u32::try_from(event.number("duration_ms"))
                        .ok()
                        .filter(|ms| *ms > 0),
                    sticker: event.flag("sticker"),
                });
                self.insert_entry(
                    Entry {
                        id: event.string("file_id"),
                        // A sibling echo is my own outgoing file, arrived via
                        // another of my devices.
                        mine: event.kind == "sibling_file",
                        sender_identity: event.string("sender_identity_id"),
                        text: event.string("caption"),
                        // The sender's send time, as texts use it.
                        order_key: nonzero_or(event.number("sent_at_ms"), util::now_ms()),
                        status: None,
                        reply_preview: event.optional("reply_to_preview"),
                        reply_sender: event.optional("reply_to_sender_identity_id"),
                        reply_id: event.optional("reply_to_message_id"),
                        deleted: false,
                        edited: false,
                        attachment,
                        seen_by: Vec::new(),
                        reactions: String::new(),
                        expire: event_expiry(event),
                    },
                    true,
                );
            }
            (_, "file_progress") => {
                self.apply_progress(
                    &event.string("file_id"),
                    event.number("bytes_done"),
                    event.number("bytes_total"),
                );
            }
            (_, "file_complete") => {
                self.apply_attachment_state(&event.string("file_id"), "complete", None);
            }
            (_, "file_failed") => {
                let reason = event.string("error");
                self.apply_attachment_state(&event.string("file_id"), "failed", Some(reason));
            }
            // The file was deleted locally (eviction from the storage limit, or the message was deleted).
            // Without this arm the bubble kept looking "complete".
            (_, "file_evicted") => {
                self.apply_attachment_state(&event.string("file_id"), "offered", None);
            }

            // --- bulk history changes: rebuild rather than patch ---
            (_, "history_sync") | (_, "older_history") | (_, "older_group_history") => {
                if self.event_belongs_here(event) {
                    self.reset_fetch_history();
                    self.reload();
                }
            }
            // `history_backfilled` is the one bulk event that may arrive
            // UNADDRESSED: a sibling backfill spanning several conversations
            // has no single `peer`/`group_id` to name (see the core's
            // `SiblingHistoryResponse` arm). `event_belongs_here` returns
            // false for that shape, so this reload never happened — new
            // history landed in the database and the open chat kept showing
            // the old view until it was closed and reopened. An unaddressed
            // one now reloads unconditionally; an addressed one (the server
            // archive restore) still has to match.
            (_, "history_backfilled") => {
                let unaddressed = event.optional("group_id").is_none()
                    && event.string("peer").is_empty();
                self.reset_fetch_history();
                if unaddressed || self.event_belongs_here(event) {
                    self.reload();
                }
            }

            (Conversation::Group { group_id, .. }, "group_updated" | "member_left")
                if event.string("group_id") == *group_id =>
            {
                self.app().refresh_caches();
                self.refresh_subtitle();
            }

            _ => {}
        }
    }

    /// Whether an event with a `peer`/`group_id` pair addresses this view.
    /// `file_*` and history events use both fields inconsistently (a 1:1 file
    /// event has no `group_id` at all), so this checks whichever is present.
    pub(super) fn event_belongs_here(&self, event: &Event) -> bool {
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => {
                event.optional("group_id").is_none() && event.string("peer") == *fingerprint
            }
            Conversation::Group { group_id, .. } => {
                event.optional("group_id").as_deref() == Some(group_id.as_str())
            }
        }
    }

    pub(super) fn apply_edit(&self, id: &str, new_text: &str) {
        self.main.refresh_chats();
        if let Some(bubble) = self.bubbles.borrow().get(id) {
            {
                let mut entry = bubble.entry.borrow_mut();
                entry.text = new_text.to_string();
                entry.edited = true;
            }
            bubble.text.set_markup(&display_text(&bubble.entry.borrow()));
            self.search_lower.borrow_mut().clear();
            bubble.edited.set(true);
            bubble.meta.set_markup(&format_meta(bubble.order_key, bubble.status.borrow().as_deref(), true));
        }
    }

    pub(super) fn apply_delete(&self, id: &str) {
        self.main.refresh_chats();
        if let Some(bubble) = self.bubbles.borrow().get(id) {
            // The "Forwarded" label and the inline quote sit beside the text in the same column; a reload builds a deleted bubble without them.
            if let Some(column) = bubble.text.parent() {
                let mut child = column.first_child();
                while let Some(widget) = child {
                    child = widget.next_sibling();
                    if widget.has_css_class("forwarded-label") || widget.has_css_class("quote-block") {
                        widget.set_visible(false);
                    }
                }
            }
            bubble.entry.borrow_mut().deleted = true;
            bubble.text.set_markup("Message deleted");
            self.search_lower.borrow_mut().clear();
            bubble.text.add_css_class("dim-label");
            bubble.text.set_visible(true);
            // An attachment bubble's card is a separate widget from `text` —
            // see the `attachment_widgets` field doc for why this half is the
            // one that actually makes a deletion visible for those.
            if let Some(widgets) = &bubble.attachment_widgets {
                widgets.set_visible(false);
            }
            bubble.seen_row.set_visible(false);
        }
    }

    pub(super) fn apply_status(&self, id: &str, status: &str) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(id) else { return };
        if !bubble.mine {
            return;
        }
        // Never downgrade: the end-to-end Ack ("delivered") is a stronger
        // promise than "sent", and the events can arrive out of order — a
        // late "sent" must not pull the double tick back to one.
        if bubble.status.borrow().as_deref() == Some("delivered")
            && matches!(status, "sent" | "pending")
        {
            return;
        }
        *bubble.status.borrow_mut() = Some(status.to_string());
        bubble.entry.borrow_mut().status = Some(status.to_string());
        bubble
            .meta
            .set_markup(&format_meta(bubble.order_key, Some(status), bubble.edited.get()));
    }

    /// A seen receipt for one of my messages: the core has stored it, so
    /// the full viewer list is read back (off the GTK thread).
    pub(super) fn refresh_seen(self: &Rc<Self>, id: &str) {
        if !self.bubbles.borrow().get(id).is_some_and(|bubble| bubble.mine) {
            return;
        }
        let (view, id) = (self.clone(), id.to_string());
        let message_id = id.clone();
        crate::app::run_in_background(
            move || core::list_seen_by(&message_id),
            move |viewers| view.show_seen_by(&id, viewers),
        );
    }

    /// Seen-by avatars, like the phone: only under my newest seen message,
    /// the last `SEEN_AVATARS` viewers, the rest as "+N".
    pub(super) fn show_seen_by(&self, id: &str, viewers: Vec<core::SeenEntry>) {
        if viewers.is_empty() {
            return;
        }
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(id) else { return };
        if !bubble.mine || bubble.entry.borrow().deleted {
            return;
        }
        let previous = self.seen_shown.borrow().clone();
        if let Some(shown) = previous.as_deref().filter(|shown| *shown != id).and_then(|shown| bubbles.get(shown)) {
            if shown.order_key > bubble.order_key {
                return;
            }
            shown.seen_row.set_visible(false);
        }
        let row = &bubble.seen_row;
        while let Some(child) = row.first_child() {
            row.remove(&child);
        }
        let hidden = viewers.len().saturating_sub(SEEN_AVATARS);
        for viewer in &viewers[hidden..] {
            let name = self.app().identity_name(&viewer.identity_id);
            let avatar = adw::Avatar::new(16, Some(&name), true);
            if let Some(texture) = self.app().identity_avatar(&viewer.identity_id).as_deref().and_then(util::texture_from_hex) {
                avatar.set_custom_image(Some(&texture));
            }
            row.append(&avatar);
        }
        if hidden > 0 {
            let more = gtk::Label::new(Some(&format!("+{hidden}")));
            more.add_css_class("caption");
            more.add_css_class("dim-label");
            row.append(&more);
        }
        row.set_visible(true);
        bubble.entry.borrow_mut().seen_by = viewers;
        *self.seen_shown.borrow_mut() = Some(id.to_string());
    }

    /// Who saw a message and when, read fresh from the core.
    pub(super) fn show_seen_list(self: &Rc<Self>, id: &str) {
        let (view, message_id) = (self.clone(), id.to_string());
        crate::app::run_in_background(
            move || core::list_seen_by(&message_id),
            move |viewers| {
                let body = viewers
                    .iter()
                    .rev()
                    .map(|viewer| {
                        format!(
                            "{}  {}, {}",
                            view.app().identity_name(&viewer.identity_id),
                            util::format_day_separator(viewer.seen_at_ms),
                            util::format_bubble_time(viewer.seen_at_ms),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let Some(window) = view.app().window() else { return };
                let dialog = adw::MessageDialog::new(Some(&window), Some("Seen by"), Some(if body.is_empty() { "Nobody yet" } else { body.as_str() }));
                dialog.add_response("close", "Close");
                dialog.set_close_response("close");
                dialog.present();
            },
        );
    }

    /// Shows/hides the typing bubble and (re)arms its auto-hide timeout — see
    /// the `typing_clear_source` field doc for why the timeout exists at all.
    pub(super) fn show_typing(self: &Rc<Self>, typing: bool, who: Option<String>) {
        if let Some(source) = self.typing_clear_source.borrow_mut().take() {
            source.remove();
        }
        if !typing {
            self.typing_indicator.set_reveal_child(false);
            return;
        }
        self.typing_indicator_label.set_label(&match who {
            Some(name) if !name.is_empty() => format!("{} is typing…", name),
            _ => "typing…".to_string(),
        });
        self.typing_indicator.set_reveal_child(true);

        let view = self.clone();
        let source = glib::timeout_add_seconds_local(TYPING_INDICATOR_TIMEOUT_S, move || {
            view.typing_indicator.set_reveal_child(false);
            *view.typing_clear_source.borrow_mut() = None;
            glib::ControlFlow::Break
        });
        *self.typing_clear_source.borrow_mut() = Some(source);
    }

}
