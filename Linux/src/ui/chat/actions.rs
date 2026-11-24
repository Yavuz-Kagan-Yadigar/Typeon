//! Per-message actions: context menu, forward, edit, delete, reply, seen, read state.

use super::*;

impl ChatView {
    pub(super) fn bubble_menu(self: &Rc<Self>, anchor: &gtk::Box, entry: &Entry, x: f64, y: f64) {
        let (popover, items) = crate::ui::widgets::menu_popover();
        popover.set_parent(anchor);
        popover.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
        popover.connect_closed(|popover| popover.unparent());

        let mut actions: Vec<(&str, String, bool, Box<dyn Fn()>)> = Vec::new();
        // Disappearing: nothing that copies it out (copy, reply quote, forward, save, add sticker).
        let locked = entry.expire.is_some();

        if !entry.deleted && !entry.id.starts_with("legacy:") {
            let view = self.clone();
            let entry = entry.clone();
            let anchor = anchor.clone();
            actions.push((
                "face-smile-symbolic",
                "React".to_string(),
                false,
                Box::new(move || view.pick_reaction(&anchor, &entry)),
            ));
        }

        if !entry.deleted && !entry.reactions.is_empty() {
            let view = self.clone();
            let entry = entry.clone();
            actions.push((
                "view-list-symbolic",
                "Reactions".to_string(),
                false,
                Box::new(move || view.show_reactions(&entry)),
            ));
        }

        // The JPEG XL as it came; opening it gives a PNG.
        if let Some(attachment) = entry.attachment.as_ref().filter(|a| !locked && !entry.deleted && !a.sticker && a.file_name.to_lowercase().ends_with(".jxl")) {
            let view = self.clone();
            let (file_id, name) = (attachment.file_id.clone(), attachment.file_name.clone());
            actions.push((
                "document-save-symbolic",
                "Save as JPEG XL".to_string(),
                false,
                Box::new(move || {
                    let (view, file_id, name) = (view.clone(), file_id.clone(), name.clone());
                    app::run_in_background(
                        move || core::attachment_original_path(&file_id),
                        move |result| match result {
                            Ok(path) => crate::ui::media::save_copy(view.app(), &path, &name),
                            Err(error) => view.app().toast(&format!("Could not save: {}", error)),
                        },
                    );
                }),
            ));
        }

        // Stickers are not offered: sent as a file they would lose the sticker look.
        if !locked && !entry.deleted && !entry.id.starts_with("legacy:") && !entry.attachment.as_ref().is_some_and(|a| a.sticker) {
            let view = self.clone();
            let entry = entry.clone();
            actions.push((
                "mail-forward-symbolic",
                "Forward".to_string(),
                false,
                Box::new(move || view.forward(&entry)),
            ));
        }

        // A group message some members' devices missed: send it to just those.
        if self.is_group() && entry.mine && !entry.deleted && entry.attachment.is_none()
            && matches!(entry.status.as_deref(), Some("failed") | Some("pending"))
        {
            let view = self.clone();
            let id = entry.id.clone();
            actions.push((
                "view-refresh-symbolic",
                "Send again".to_string(),
                false,
                Box::new(move || {
                    let Conversation::Group { group_id, .. } = &view.conversation else { return };
                    let (gid, lid, view) = (group_id.clone(), id.clone(), view.clone());
                    let done_id = id.clone();
                    app::run_in_background(
                        move || core::retry_group_message_copies(&gid, &lid),
                        move |result| match result {
                            1 => view.apply_status(&done_id, "sent"),
                            0 => view.app().toast("Nothing to send again"),
                            _ => view.app().toast("Could not send it again"),
                        },
                    );
                }),
            ));
        }

        if !locked && !entry.deleted && entry.attachment.is_none() {
            {
                let view = self.clone();
                let entry = entry.clone();
                actions.push((
                    "mail-reply-sender-symbolic",
                    "Reply".to_string(),
                    false,
                    Box::new(move || view.start_reply(&entry)),
                ));
            }
            {
                let text = entry.text.clone();
                let anchor = anchor.clone();
                actions.push((
                    "edit-copy-symbolic",
                    "Copy".to_string(),
                    false,
                    Box::new(move || anchor.clipboard().set_text(&text)),
                ));
            }
        }

        if let Some(attachment) = entry.attachment.as_ref().filter(|a| !locked && a.sticker && !entry.mine && !entry.deleted) {
            let view = self.clone();
            let file_id = attachment.file_id.clone();
            actions.push((
                "list-add-symbolic",
                "Add to my stickers".to_string(),
                false,
                Box::new(move || {
                    let (view, file_id) = (view.clone(), file_id.clone());
                    app::run_in_background(
                        move || core::save_received_sticker(&file_id),
                        move |result| match result {
                            Ok(_) => view.app().toast("Added to your stickers"),
                            Err(error) => view.app().toast(&format!("Could not add the sticker: {}", error)),
                        },
                    );
                }),
            ));
        }

        if entry.mine && !entry.deleted && !entry.id.starts_with("legacy:") {
            // Edit is offered for text only: the protocol's `Edit` content is plain text, and a locked (disappearing) message
            // would show its hidden text in the dialog.
            if entry.attachment.is_none() && !locked {
                let view = self.clone();
                let entry = entry.clone();
                actions.push((
                    "document-edit-symbolic",
                    "Edit".to_string(),
                    false,
                    Box::new(move || view.edit_message(&entry)),
                ));
            }
            // Delete also works for attachments: the core purges the local file (`purge_attachment_if_exists`).
            {
                let view = self.clone();
                let entry = entry.clone();
                actions.push((
                    "edit-delete-symbolic",
                    "Delete".to_string(),
                    true,
                    Box::new(move || view.delete_message(&entry)),
                ));
            }
        }

        for (icon, label, destructive, action) in actions {
            let button = crate::ui::widgets::menu_item(icon, label.as_str());
            if destructive {
                button.add_css_class("destructive-action");
            }
            let popover = popover.clone();
            button.connect_clicked(move |_| {
                popover.popdown();
                action();
            });
            items.append(&button);
        }

        if items.first_child().is_some() {
            popover.popup();
        } else {
            popover.unparent();
        }
    }
}

// --- sending ---

impl ChatView {
    /// The contact deleted their account: grey out the whole composer bar and
    /// say why in the header. The core refuses the sends anyway.
    pub(super) fn lock_account_deleted(&self) {
        self.account_deleted.set(true);
        if let Some(bar) = self.composer.parent().and_then(|scroller| scroller.parent()) {
            bar.set_sensitive(false);
        }
        self.subtitle.set_label("Deleted their account · messages can't be sent");
    }

    /// Sends a copy of `entry` (text, or the file with its caption) to a chat
    /// picked from a list, marked "Forwarded" like Android does.
    pub(super) fn forward(self: &Rc<Self>, entry: &Entry) {
        // The lists take the core lock: read off the GTK thread.
        let (view, entry) = (self.clone(), entry.clone());
        app::run_in_background(
            || (core::list_contacts(), core::list_groups()),
            move |(contacts, groups)| view.forward_to(&entry, contacts, groups),
        );
    }

    fn forward_to(self: &Rc<Self>, entry: &Entry, contacts: Vec<core::ContactSummary>, groups: Vec<core::GroupSummary>) {
        let Some(window) = self.app().window() else { return };
        let mut targets: Vec<(String, Conversation)> = contacts
            .into_iter()
            .filter_map(|c| {
                let fp = c.active_device_fingerprint.clone()?;
                Some((c.display_name.clone(), Conversation::Direct { fingerprint: fp, contact_id: c.contact_id, identity_id: c.identity_id, name: c.display_name }))
            })
            .collect();
        targets.extend(groups.into_iter().map(|g| (format!("👥 {}", g.name), Conversation::Group { group_id: g.group_id, name: g.name })));
        targets.sort_by_key(|(name, _)| name.to_lowercase());

        let list = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).build();
        list.add_css_class("boxed-list");
        for (name, _) in &targets {
            list.append(&adw::ActionRow::builder().title(name.as_str()).activatable(true).build());
        }
        let scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .min_content_height(320)
            .child(&list)
            .build();
        let dialog = adw::MessageDialog::new(Some(&window), Some("Forward to…"), None);
        dialog.set_extra_child(Some(&scroller));
        dialog.add_response("cancel", "Cancel");
        dialog.set_close_response("cancel");

        let (app, entry, dialog_ref, view) = (self.app().clone(), entry.clone(), dialog.clone(), self.clone());
        list.connect_row_activated(move |_, row| {
            dialog_ref.close();
            let Some((_, target)) = targets.get(row.index() as usize).cloned() else { return };
            let (app, entry, view) = (app.clone(), entry.clone(), view.clone());
            let target_key = target.key();
            app::run_in_background(
                {
                    let entry = entry.clone();
                    move || -> Result<(), String> {
                        match &entry.attachment {
                            None => {
                                let text = util::forward_mark(&entry.text);
                                match &target {
                                    Conversation::Direct { fingerprint, .. } => core::send_message(fingerprint, &text, None, None, None).map(|_| ()),
                                    Conversation::Group { group_id, .. } => core::send_group_message(group_id, &text, None, None, None, Vec::new(), None).map(|_| ()),
                                }
                            }
                            Some(a) => {
                                let path = core::attachment_plaintext_path(&a.file_id)?;
                                // The core opens a JPEG XL as PNG: the name follows the file.
                                let name = std::path::Path::new(&path).extension()
                                    .filter(|ext| !a.file_name.to_lowercase().ends_with(&format!(".{}", ext.to_string_lossy().to_lowercase())))
                                    .map_or(a.file_name.clone(), |ext| format!("{}.{}", a.file_name, ext.to_string_lossy()));
                                let mime = util::guess_mime(&name);
                                let caption = util::forward_mark(&entry.text);
                                let preview = util::is_image(&mime).then(|| util::scaled_jpeg(&path, 480, 85)).flatten();
                                let duration = a.duration_ms;
                                match &target {
                                    Conversation::Direct { fingerprint, .. } => core::prepare_and_send_file(fingerprint, &path, &name, &mime, preview, duration, caption, None, None).map(|_| ()),
                                    Conversation::Group { group_id, .. } => core::prepare_and_send_group_file(group_id, &path, &name, &mime, preview, duration, caption, None, None, None).map(|_| ()),
                                }
                            }
                        }
                    }
                },
                move |result| match result {
                    Ok(()) => {
                        app.toast("Forwarded");
                        // No core event for a local send: show it in the open chat and the list.
                        if target_key == view.conversation.key() {
                            view.reload();
                        }
                        view.main.refresh_chats();
                    }
                    Err(error) => app.toast(&format!("Could not forward: {}", error)),
                },
            );
        });
        dialog.present();
    }

    pub(super) fn edit_message(self: &Rc<Self>, entry: &Entry) {
        let view = self.clone();
        let entry = entry.clone();
        let Some(window) = self.app().window() else { return };

        let field = gtk::Entry::builder()
            .text(&entry.text)
            .activates_default(true)
            .build();
        let dialog = adw::MessageDialog::new(Some(&window), Some("Edit message"), None);
        dialog.set_extra_child(Some(&crate::ui::widgets::dialog_field(&field)));
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("save", "Save");
        dialog.set_default_response(Some("save"));
        dialog.set_close_response("cancel");
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
        dialog.connect_response(None, move |_, response| {
            if response != "save" {
                return;
            }
            let new_text = field.text().to_string().trim().to_string();
            if new_text.is_empty() || new_text == entry.text {
                return;
            }
            let (direct, target) = match &view.conversation {
                Conversation::Direct { fingerprint, .. } => (true, fingerprint.clone()),
                Conversation::Group { group_id, .. } => (false, group_id.clone()),
            };
            let (id, text) = (entry.id.clone(), new_text.clone());
            let (view, done_id) = (view.clone(), entry.id.clone());
            crate::app::run_in_background(
                move || {
                    if direct {
                        core::edit_message(&target, &id, &text).map(|_| ())
                    } else {
                        core::edit_group_message(&target, &id, &text)
                    }
                },
                move |outcome| match outcome {
                    Ok(()) => view.apply_edit(&done_id, &new_text),
                    Err(error) => view.app().toast(&format!("Edit failed: {}", error)),
                },
            );
        });
        dialog.present();
    }

    pub(super) fn delete_message(self: &Rc<Self>, entry: &Entry) {
        let view = self.clone();
        let entry = entry.clone();
        dialogs::confirm(
            self.app(),
            "Delete this message?",
            "It is removed for everyone in this conversation.",
            "Delete",
            true,
            move || {
                let (direct, target) = match &view.conversation {
                    Conversation::Direct { fingerprint, .. } => (true, fingerprint.clone()),
                    Conversation::Group { group_id, .. } => (false, group_id.clone()),
                };
                let id = entry.id.clone();
                let (view, done_id) = (view.clone(), entry.id.clone());
                crate::app::run_in_background(
                    move || {
                        if direct {
                            core::delete_message(&target, &id).map(|_| ())
                        } else {
                            core::delete_group_message(&target, &id)
                        }
                    },
                    move |outcome| match outcome {
                        Ok(()) => view.apply_delete(&done_id),
                        Err(error) => view.app().toast(&format!("Delete failed: {}", error)),
                    },
                );
            },
        );
    }

    pub(super) fn start_reply(self: &Rc<Self>, entry: &Entry) {
        let preview = util::preview_text(&entry.text, 120);
        let sender = if self.is_group() {
            Some(entry.sender_identity.clone()).filter(|s| !s.is_empty())
        } else {
            None
        };
        self.set_reply(entry.id.clone(), preview, sender);
        self.composer.grab_focus();
    }

    /// Shows the reply bar for (id, preview, sender) — also used to put a
    /// reply back after a failed send.
    pub(super) fn set_reply(&self, id: String, preview: String, sender: Option<String>) {
        self.reply_label
            .set_label(&format!("Replying to: {}", util::preview_text(&preview, 80)));
        self.reply_bar.set_reveal_child(true);
        self.reply_island.add_css_class("active");
        *self.reply_to.borrow_mut() = Some((id, preview, sender));
    }

    pub(super) fn clear_reply(&self) {
        *self.reply_to.borrow_mut() = None;
        self.reply_bar.set_reveal_child(false);
        self.reply_island.remove_css_class("active");
    }

    pub(super) fn send_seen(self: &Rc<Self>, entry: &Entry) {
        match &self.conversation {
                        // 1:1: a read boundary (ReadStateSync) is used instead of a single `Seen`. The other side applies it to this message
                        // too, and it is delivered reliably. A burst of reads is collected in one packet. Even when the whole history passes
                        // through this path during `reload()`, only one packet goes out.
            Conversation::Direct { fingerprint, .. } => {
                if self.watermark_pending.replace(true) {
                    return;
                }
                let view = self.clone();
                let fingerprint = fingerprint.clone();
                glib::timeout_add_local_once(std::time::Duration::from_millis(700), move || {
                    view.watermark_pending.set(false);
                    let now = util::now_ms();
                    bg_serial(move || core::sync_read_state(&fingerprint, "", now));
                });
            }
            Conversation::Group { .. } => {
                // A group receipt goes back to the original sender's device
                // with the local id they can map to their own bubble.
                // Collected and sent from ONE worker per 700 ms burst, not a
                // thread per bubble.
                if let Some(sender) = self.sender_device(&entry.sender_identity) {
                    self.seen_batch.borrow_mut().push((sender, entry.id.clone()));
                    if self.watermark_pending.replace(true) {
                        return;
                    }
                    let view = self.clone();
                    glib::timeout_add_local_once(std::time::Duration::from_millis(700), move || {
                        view.watermark_pending.set(false);
                        let batch = std::mem::take(&mut *view.seen_batch.borrow_mut());
                        bg_serial(move || {
                            for (sender, id) in batch {
                                core::send_seen_receipt(&sender, &id, Some(id.clone()));
                            }
                        });
                    });
                }
            }
        }
    }

    /// Resolves a group member's identity to the device we would message.
    pub(super) fn sender_device(&self, identity_id: &str) -> Option<String> {
        self.app()
            .contacts
            .borrow()
            .iter()
            .find(|contact| contact.identity_id == identity_id)
            .and_then(|contact| contact.active_device_fingerprint.clone())
    }

    /// The user is looking at this chat: page on screen, window shown,
    /// focused, not minimised, not locked, not idle.
    pub(super) fn is_watched(&self) -> bool {
        self.messages.is_mapped() && self.app().is_watching()
    }

    /// Per incoming message: marks the chat read now, or once the user is
    /// back (see `flush_deferred_reads`).
    pub(super) fn mark_read_if_watched(&self) {
        if self.is_watched() {
            self.mark_read();
        } else {
            self.read_deferred.set(true);
        }
    }

    /// Sends the receipts and the read mark held while nobody was looking,
    /// once someone is. Cheap when nothing waits; called from a 2 s timer.
    pub(super) fn flush_deferred_reads(self: &Rc<Self>) {
        if !self.read_deferred.get() && self.seen_deferred.borrow().is_empty() {
            return;
        }
        if !self.is_watched() {
            return;
        }
        let entries = std::mem::take(&mut *self.seen_deferred.borrow_mut());
        for entry in &entries {
            self.send_seen(entry);
        }
        if self.read_deferred.replace(false) {
            self.mark_read();
        }
    }

    /// Local only. Cheap enough to call per incoming message.
    pub(super) fn mark_read(&self) {
        let key = self.conversation.key();
        self.app().prefs.borrow_mut().mark_read_now(&key);
        self.main.refresh_chats();
    }

    /// Local, *and* tells my other devices so this chat is not left unread on
    /// the phone. Kept separate from `mark_read` because it puts a reliable
    /// message on the wire — doing that per arriving message (rather than on
    /// open and close, as the Android activities do) would be pure noise.
    pub(super) fn mark_read_and_sync(&self) {
        self.mark_read();
        let now = util::now_ms();
        let (fingerprint, group_id) = match &self.conversation {
            Conversation::Direct { fingerprint, .. } => (fingerprint.clone(), String::new()),
            Conversation::Group { group_id, .. } => (String::new(), group_id.clone()),
        };
        bg_serial(move || core::sync_read_state(&fingerprint, &group_id, now));
    }
}
