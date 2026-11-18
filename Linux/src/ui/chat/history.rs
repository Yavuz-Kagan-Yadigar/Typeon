//! History paging: reload, older pages, server history fetch, trimming.

use super::*;

// --- history ---

impl ChatView {
    /// Full rebuild from the local archive. Used on open and whenever an event
    /// changes history in a way that cannot be patched in place (a peer's
    /// history sync, a sibling backfill).
    pub(super) fn reload(self: &Rc<Self>) {
        let generation = self.load_gen.get() + 1;
        self.load_gen.set(generation);
        // Cleared now, not in the callback: the scroll handler must not
        // restart this reload on every tick while it runs.
        self.trimmed_bottom.set(false);
        let conversation = self.conversation.clone();
        let own_identity = self.app().own_identity_id.borrow().clone();
        let view = self.clone();
        // The core lock is shared with the poll thread; on the GTK thread this
        // read froze the window whenever a poll round was running.
        crate::app::run_in_background(
            move || fetch_page(&conversation, &own_identity, None, 0, None),
            move |page| {
                if view.load_gen.get() != generation {
                    return;
                }
                // Keep a reader of old messages where they are; only a view
                // already at the bottom follows to the newest.
                let adjustment = view.scroller.vadjustment();
                let distance_from_bottom = adjustment.upper() - adjustment.page_size() - adjustment.value();
                let at_bottom = distance_from_bottom < 80.0;
                while let Some(child) = view.messages.first_child() {
                    view.messages.remove(&child);
                }
                view.bubbles.borrow_mut().clear();
                view.order.borrow_mut().clear();
                view.search_lower.borrow_mut().clear();
                view.search_matches.borrow_mut().clear();
                view.search_index.set(0);
                view.exhausted_locally.set(false);
                view.oldest_timestamp.set(page.oldest);
                view.oldest_attachment_timestamp.set(page.oldest_attachment);

                let mut entries = page.entries;
                entries.sort_by_key(|entry| entry.order_key);
                for entry in entries {
                    view.insert_entry(entry, false);
                }
                view.refresh_day_separators();
                if at_bottom {
                    view.scroll_to_bottom();
                } else {
                    glib::idle_add_local_once(move || {
                        adjustment.set_value(adjustment.upper() - adjustment.page_size() - distance_from_bottom);
                    });
                }
            },
        );
    }

    /// The "Fetch older history" button. The rows arrive later with a
    /// `history_backfilled` event, which reloads the chat.
    pub(super) fn fetch_server_history(self: &Rc<Self>) {
        let (chat_key, is_group) = match &self.conversation {
            Conversation::Direct { fingerprint, .. } => (fingerprint.clone(), false),
            Conversation::Group { group_id, .. } => (group_id.clone(), true),
        };
        let before = self.order.borrow().first().map(|(key, _)| *key).unwrap_or(0);
        self.fetch_history.set_sensitive(false);
        self.fetch_history.set_label("Requested…");
        let view = self.clone();
        crate::app::run_in_background(
            move || core::fetch_server_history(&chat_key, is_group, before as i64),
            move |result| match result {
                Err(error) => {
                    view.reset_fetch_history();
                    view.app().toast(&error);
                }
                // No reply (server offline, nothing older): the button comes back.
                Ok(()) => {
                    glib::timeout_add_local_once(std::time::Duration::from_secs(20), move || view.reset_fetch_history());
                }
            },
        );
    }

    /// Shows a file I just sent: its archive row as a bubble, or a reload
    /// when the row could not be found.
    pub(super) fn show_sent_attachment(self: &Rc<Self>, entry: Option<Entry>) {
        match entry {
            Some(entry) => self.insert_entry(entry, true),
            None => self.reload(),
        }
    }

    /// Re-places the day separators from `order`: one above the first bubble
    /// of each day. Cheap (bubbles stay, only the few labels change), so it
    /// runs after every insert batch, older pages and live messages too.
    pub(super) fn refresh_day_separators(&self) {
        let mut child = self.messages.first_child();
        while let Some(widget) = child {
            child = widget.next_sibling();
            if widget.has_css_class("day-separator") {
                self.messages.remove(&widget);
            }
        }
        let order = self.order.borrow();
        let bubbles = self.bubbles.borrow();
        let mut previous: Option<(u64, gtk::Widget)> = None;
        for (key, id) in order.iter() {
            let Some(bubble) = bubbles.get(id) else { continue };
            if util::is_new_day(previous.as_ref().map_or(0, |(day, _)| *day), *key) {
                let separator = day_separator(*key);
                self.messages.insert_child_after(&separator, previous.as_ref().map(|(_, root)| root));
            }
            previous = Some((*key, bubble.root.clone()));
        }
    }

    pub(super) fn reset_fetch_history(&self) {
        self.fetch_history.set_sensitive(true);
        self.fetch_history.set_label(FETCH_HISTORY_LABEL);
    }

    pub(super) fn load_older(self: &Rc<Self>) {
        if self.loading_older.get() || self.exhausted_locally.get() {
            return;
        }
        let cursor = self.oldest_timestamp.get();
        if cursor == 0 {
            return;
        }
        self.loading_older.set(true);
        self.older_spinner.set_visible(true);
        self.older_spinner.start();

        let generation = self.load_gen.get();
        let conversation = self.conversation.clone();
        let own_identity = self.app().own_identity_id.borrow().clone();
        // The files page on their own cursor (the core keeps them in their own
        // table): the older ones come in below the oldest file on screen.
        let attachment_cursor = self.oldest_attachment_timestamp.get();
        let view = self.clone();
        crate::app::run_in_background(
            move || {
                // Local archive only: scrolling sends nothing to the network.
                fetch_page(
                    &conversation,
                    &own_identity,
                    Some(cursor as i64),
                    cursor,
                    Some(attachment_cursor),
                )
            },
            move |page| {
                view.loading_older.set(false);
                view.older_spinner.stop();
                view.older_spinner.set_visible(false);
                if view.load_gen.get() != generation {
                    return; // a reload replaced the timeline meanwhile
                }
                let mut older = page.entries;
                if older.is_empty() {
                    view.exhausted_locally.set(true);
                    return;
                }
                view.oldest_timestamp.set(page.oldest);
                if page.oldest_attachment > 0 {
                    view.oldest_attachment_timestamp.set(page.oldest_attachment);
                }
                older.sort_by_key(|entry| entry.order_key);

                // Preserve the reading position. Rows go in above and may come
                // off below, so neither end is a fixed reference: the old top
                // row is. Its offset to the viewport is restored after the
                // next layout pass (positions are stale until then).
                let adjustment = view.scroller.vadjustment();
                // A bubble, not a day separator: those are rebuilt below.
                let anchor = view
                    .order
                    .borrow()
                    .first()
                    .and_then(|(_, id)| view.bubbles.borrow().get(id).map(|bubble| bubble.root.clone()));
                let offset = anchor
                    .as_ref()
                    .and_then(|row| row.compute_bounds(&view.messages))
                    .map(|bounds| adjustment.value() - bounds.y() as f64);
                for entry in older {
                    view.insert_entry(entry, false);
                }
                // Above the cap, drop the newest bubbles (far below the
                // reader), so the view settles at ~MAX_BUBBLES while the page
                // just loaded stays.
                view.trim_newest();
                view.refresh_day_separators();
                let messages = view.messages.clone();
                glib::idle_add_local_once(move || {
                    if let (Some(row), Some(offset)) = (anchor, offset) {
                        if let Some(bounds) = row.compute_bounds(&messages) {
                            adjustment.set_value(bounds.y() as f64 + offset);
                        }
                    }
                });
            },
        );
    }

    /// Drops the newest bubbles once more than `MAX_BUBBLES` are alive, then
    /// prunes day separators left stranded at the bottom. Sets
    /// `trimmed_bottom`: the scroll handler reloads the newest page when the
    /// reader gets back down there.
    pub(super) fn trim_newest(self: &Rc<Self>) {
        let evicted: Vec<String> = {
            let mut order = self.order.borrow_mut();
            let keep = order.len().min(MAX_BUBBLES);
            if keep == order.len() {
                return;
            }
            order.drain(keep..).map(|(_, id)| id).collect()
        };
        self.trimmed_bottom.set(true);

        {
            let mut bubbles = self.bubbles.borrow_mut();
            for id in &evicted {
                if let Some(bubble) = bubbles.remove(id) {
                    self.messages.remove(&bubble.root);
                }
            }
        }
        // The search index refers to bubble ids; keep only what survived, so
        // a match jump can never land on a removed bubble.
        self.search_matches.borrow_mut().retain(|id| {
            !evicted.iter().any(|gone| gone == id)
        });
        self.search_lower.borrow_mut().retain(|id, _| {
            !evicted.iter().any(|gone| gone == id)
        });

        // Trailing separators lost the bubbles they introduced.
        while let Some(last) = self.messages.last_child() {
            if !last.has_css_class("day-separator") {
                break;
            }
            self.messages.remove(&last);
        }
    }
}

/// One page of a conversation: the merged timeline plus the two cursors the
/// next page starts from.
pub(super) struct Page {
    pub(super) entries: Vec<Entry>,
    /// Oldest message timestamp on the page — the message paging cursor.
    pub(super) oldest: u64,
    /// Oldest attachment timestamp on the page — the attachment paging
    /// cursor (the core keeps the files in their own table, so they page on
    /// their own). Zero when the page carried no attachment.
    pub(super) oldest_attachment: u64,
}

/// Reads one page of messages *and* attachments and merges them onto a
/// single timeline — the core stores them separately but the user sees one
/// conversation.
/// `before` is the message cursor (`None` = the newest page), and
/// `attachment_before` the attachment one: the `created_at` of the oldest
/// attachment already on screen (`None` = take the newest ones).
pub(super) fn fetch_page(
    conversation: &Conversation,
    own_identity: &str,
    before: Option<i64>,
    mut oldest: u64,
    attachment_before: Option<u64>,
) -> Page {
    // (cursor clock, is a file, entry): the merged page is cut by the clock
    // the two archive cursors compare, see the cut below.
    let mut rows: Vec<(u64, bool, Entry)> = Vec::new();
    let peer_fingerprint = match conversation {
        Conversation::Direct { fingerprint, .. } => fingerprint.clone(),
        Conversation::Group { .. } => String::new(),
    };

    let archived = match (conversation, before) {
        (Conversation::Direct { fingerprint, .. }, None) => {
            core::message_history(fingerprint, PAGE_SIZE)
        }
        (Conversation::Direct { fingerprint, .. }, Some(cursor)) => {
            core::message_history_before(fingerprint, cursor, PAGE_SIZE)
        }
        (Conversation::Group { group_id, .. }, None) => {
            core::group_message_history(group_id, PAGE_SIZE)
        }
        (Conversation::Group { group_id, .. }, Some(cursor)) => {
            core::group_message_history_before(group_id, cursor, PAGE_SIZE)
        }
    };

    for message in archived {
        let sender_identity = message.sender_identity_id.clone().unwrap_or_default();
        let mine = message.direction == "sent"
            || (!sender_identity.is_empty() && sender_identity == own_identity);
        rows.push((message.timestamp, false, Entry {
            id: message.message_id.clone().unwrap_or_else(|| {
                // Pre-`message_id` rows exist in old archives; a synthetic
                // key keeps them renderable, they just cannot be targeted
                // by an edit or a receipt.
                format!("legacy:{}:{}", message.timestamp, rows.len())
            }),
            mine,
            sender_identity,
            text: message.text.clone(),
            order_key: if message.sent_at_ms > 0 {
                message.sent_at_ms
            } else {
                message.timestamp
            },
                        // A missing status is an archive row from before the column existed. Treating it as delivered is the safe reading.
                        // Ticks describe delivery of MY messages. A received one has none. "delivered" is the core's end-to-end Ack, a
                        // state between "sent" and "seen" (see `format_meta`).
            status: mine.then(|| message.status.clone().unwrap_or_else(|| "sent".to_string())),
            reply_preview: message.reply_to_preview.clone(),
            reply_sender: message.reply_to_sender_identity_id.clone(),
            deleted: message.is_deleted,
            edited: message.is_edited,
            attachment: None,
            seen: mine && !message.seen_by.is_empty(),
            reactions: message.reactions.clone(),
        }));
    }

    // Attachments live in their own table in the core, so they page on a
    // cursor of their own: below the oldest file on screen, or the newest
    // ones while no file is on screen yet (everything not on screen is older
    // than what is, see the cut below).
    let attachment_cursor = attachment_before.filter(|&c| c > 0).unwrap_or(u64::MAX);
    let listed: Vec<core::AttachmentSummary> = match conversation {
        Conversation::Direct { fingerprint, .. } => {
            core::list_attachments_before(fingerprint, attachment_cursor, PAGE_SIZE as usize)
        }
        Conversation::Group { group_id, .. } => {
            core::list_group_attachments_before(group_id, attachment_cursor, PAGE_SIZE as usize)
        }
    };
    for attachment in listed {
        rows.push((attachment.created_at, true, attachment_entry(&attachment, &peer_fingerprint)));
    }

    // Keep the newest PAGE_SIZE of texts and files together. What is cut off
    // is older than everything kept, so the next older page reads it again.
    // The cut never splits a millisecond: the cursors are strict `<`.
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    if let Some(&(floor, _, _)) = rows.get(PAGE_SIZE as usize - 1) {
        rows.retain(|row| row.0 >= floor);
    }

    let mut oldest_attachment = 0u64;
    let mut entries = Vec::with_capacity(rows.len());
    for (clock, is_file, entry) in rows {
        let cursor = if is_file { &mut oldest_attachment } else { &mut oldest };
        if *cursor == 0 || clock < *cursor {
            *cursor = clock;
        }
        entries.push(entry);
    }
    // No text kept (a page of files only): the texts not on screen are all
    // older than the oldest file kept, so page them from there.
    if oldest == 0 {
        oldest = oldest_attachment;
    }

    Page {
        entries,
        oldest,
        oldest_attachment,
    }
}

/// The file I just sent, as a timeline entry. `id` is the send result; the
/// newest file I sent is the fallback when no row carries that id. Core
/// reads: off the GTK thread.
pub(super) fn sent_attachment_entry(conversation: &Conversation, id: &str) -> Option<Entry> {
    let (rows, peer) = match conversation {
        Conversation::Direct { fingerprint, .. } => {
            (core::list_attachments_before(fingerprint, u64::MAX, 5), fingerprint.clone())
        }
        Conversation::Group { group_id, .. } => {
            (core::list_group_attachments_before(group_id, u64::MAX, 5), String::new())
        }
    };
    let row = rows.iter().find(|row| row.file_id == id).or_else(|| {
        rows.iter().filter(|row| row.direction == "sent").max_by_key(|row| row.created_at)
    })?;
    Some(attachment_entry(row, &peer))
}

/// One archive attachment row as a timeline entry — the core keeps the files
/// in their own table, but the user sees them inside the conversation.
pub(super) fn attachment_entry(attachment: &core::AttachmentSummary, peer_fingerprint: &str) -> Entry {
    let sender_identity = attachment.sender_identity_id.clone().unwrap_or_default();
    // In a group the file belongs to the member who sent it, so the row
    // carries that member's device; in a 1:1 the conversation key is it.
    let source = if attachment.peer_device_fingerprint.is_empty() {
        peer_fingerprint.to_string()
    } else {
        attachment.peer_device_fingerprint.clone()
    };
    Entry {
        id: attachment.file_id.clone(),
        mine: attachment.direction == "sent",
        sender_identity,
        text: attachment.caption.clone(),
        // The sender's send time (the core falls back to `created_at`), the same clock as texts.
        order_key: if attachment.sent_at_ms > 0 { attachment.sent_at_ms } else { attachment.created_at },
        status: None,
        reply_preview: attachment.reply_to_preview.clone().filter(|p| !p.is_empty()),
        reply_sender: attachment.reply_to_sender_identity_id.clone(),
        deleted: false,
        edited: false,
        attachment: Some(Attachment {
            file_id: attachment.file_id.clone(),
            file_name: attachment.file_name.clone(),
            mime: attachment.mime_type.clone(),
            total_size: attachment.total_size,
            source_fingerprint: source,
            status: attachment.status.clone(),
            preview_hex: attachment.preview_hex.clone(),
            bytes_done: attachment.bytes_transferred,
            duration_ms: attachment.duration_ms,
            sticker: attachment.sticker,
        }),
                // Attachments have no persistent "seen" source (see the `Entry.seen` note: the `message_seen` table is keyed on
                // `messages.message_id`, not on `files`). Same as before: attachments never show "seen".
        seen: false,
        reactions: String::new(),
    }
}
