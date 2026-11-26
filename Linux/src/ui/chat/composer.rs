//! Composer: text send, voice recording, attachment and sticker sending, typing.

use super::*;

pub(super) fn composer_bar(view: &Rc<ChatView>) -> gtk::Box {
    let bar = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(6)
        .margin_end(6)
        .build();

    let attach = gtk::Button::builder()
        .icon_name("mail-attachment-symbolic")
        .tooltip_text("Send a file")
        .valign(gtk::Align::End)
        .build();
    attach.add_css_class("flat");
    {
        let view = view.clone();
        attach.connect_clicked(move |_| view.pick_attachment());
    }

    let sticker = gtk::Button::builder()
        .icon_name("face-smile-symbolic")
        .tooltip_text("Stickers")
        .valign(gtk::Align::End)
        .build();
    sticker.add_css_class("flat");
    {
        let view = view.clone();
        sticker.connect_clicked(move |button| view.sticker_picker(button));
    }

    let record = gtk::Button::builder()
        .icon_name("audio-input-microphone-symbolic")
        .tooltip_text("Record a voice message")
        .valign(gtk::Align::End)
        .build();
    record.add_css_class("flat");
    let record_time = gtk::Label::new(None);
    record_time.add_css_class("caption");
    record_time.set_visible(false);

    // Discard, as opposed to the mic button's stop-and-send. Only visible while
    // recording: a voice message you did not mean to make should be throwable
    // away without sending it first.
    let record_cancel = gtk::Button::builder()
        .icon_name("window-close-symbolic")
        .tooltip_text("Discard this recording")
        .valign(gtk::Align::End)
        .build();
    record_cancel.add_css_class("flat");
    record_cancel.set_visible(false);
    if !crate::audio::is_available() {
        // No capture backend (ffmpeg on Linux, GStreamer on Windows) — say so rather than failing on click.
        record.set_sensitive(false);
        record.set_tooltip_text(Some(
            "Voice messages need ffmpeg installed (it captures through PipeWire).",
        ));
    } else {
        let view = view.clone();
        let record_time = record_time.clone();
        let record_cancel = record_cancel.clone();
        record.connect_clicked(move |button| {
            view.toggle_recording(button, &record_time, &record_cancel);
        });
    }
    {
        let view = view.clone();
        let record_time = record_time.clone();
        let record_button = record.clone();
        record_cancel.connect_clicked(move |cancel| {
            view.cancel_recording(&record_button, &record_time, cancel);
        });
    }

    let entry_scroller = gtk::ScrolledWindow::builder()
        .hexpand(true)
        .max_content_height(140)
        .propagate_natural_height(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&view.composer)
        .build();
    entry_scroller.add_css_class("composer-input");
    // `border-radius` on the scrolled window's own CSS node rounds its box,
    // but does not by itself clip children — the `TextView` inside paints its
    // own opaque background edge to edge regardless, which is why this still
    // rendered as a plain rectangle. `Overflow::Hidden` is what actually
    // clips the child to the rounded box.
    entry_scroller.set_overflow(gtk::Overflow::Hidden);

    let send = view.send_button.clone();
    send.add_css_class("suggested-action");
    send.add_css_class("circular");
    {
        let view = view.clone();
        send.connect_clicked(move |_| view.send());
    }
    // The icon shows the disappearing mode (picked with the header clock).
    load_disappear_mode(view);

    // Enter sends, Shift+Enter inserts a newline — the convention every
    // desktop chat client uses.
    let keys = gtk::EventControllerKey::new();
    {
        let view = view.clone();
        keys.connect_key_pressed(move |_, key, _, state| {
            let is_enter = key == gtk::gdk::Key::Return || key == gtk::gdk::Key::KP_Enter;
            if is_enter && !state.contains(gtk::gdk::ModifierType::SHIFT_MASK) {
                view.send();
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
    }
    view.composer.add_controller(keys);

    {
        // Take the buffer out first: `view.composer.buffer()` as the receiver
        // of a call whose argument moves `view` would borrow and move the same
        // binding in one expression.
        let buffer = view.composer.buffer();
        let view = view.clone();
        buffer.connect_changed(move |buffer| {
            view.set_typing(buffer.char_count() > 0);
        });
    }

    bar.append(&attach);
    bar.append(&sticker);
    bar.append(&record);
    bar.append(&record_cancel);
    bar.append(&record_time);
    bar.append(&entry_scroller);
    bar.append(&send);
    bar
}

impl ChatView {
    pub(super) fn send(self: &Rc<Self>) {
        if self.account_deleted.get() {
            return;
        }
        let buffer = self.composer.buffer();
        let (start, end) = buffer.bounds();
        let text = buffer.text(&start, &end, false).to_string();
        let text = text.trim().to_string();
        if text.is_empty() {
            return;
        }

        let reply = self.reply_to.borrow().clone();
        // Put back with the text if the send fails.
        let reply_restore = reply.clone();
        let (reply_id, reply_preview, reply_sender) = match reply {
            Some((id, preview, sender)) => (Some(id), Some(preview), sender),
            None => (None, None, None),
        };

        let own_identity = self.app().own_identity_id.borrow().clone();
        let now = util::now_ms();
        // The chat's disappearing mode (see `disappear.rs`); the core stamps the message with it too.
        // Explicit, even 0: the core then sends exactly what this bubble shows.
        let mode = self.disappear_mode.get();
        let expire_secs = Some(mode).filter(|secs| *secs > 0);

        // Composer clears first; the core call runs off the GTK thread and the
        // bubble appears on its result. A failed send puts the text back.
        buffer.set_text("");
        self.clear_reply();
        self.set_typing(false);

        let view = self.clone();
        let restore = text.clone();
        let preview_for_core = reply_preview.clone();
        let reply_sender_for_core = reply_sender.clone();
        let reply_id_entry = reply_id.clone();
        let make_entry = move |id: String, status: String| Entry {
            id,
            mine: true,
            sender_identity: own_identity,
            text: restore.clone(),
            order_key: now,
            status: Some(status),
            reply_preview: reply_preview.clone(),
            reply_sender: reply_sender.clone(),
            reply_id: reply_id_entry.clone(),
            deleted: false,
            edited: false,
            attachment: None,
            seen_by: Vec::new(),
            reactions: String::new(),
            expire: expire_secs.map(|secs| (secs, now + secs as u64 * 1000)),
            relayed_by: None,
        };
        let done = move |view: Rc<Self>, result: Result<Entry, String>, text: String| match result {
            Ok(entry) => view.insert_entry(entry, true),
            Err(error) => {
                view.app().toast(&format!("Could not send: {}", error));
                let buffer = view.composer.buffer();
                let (start, end) = buffer.bounds();
                if buffer.text(&start, &end, false).is_empty() {
                    buffer.set_text(&text);
                    if view.reply_to.borrow().is_none() {
                        if let Some((id, preview, sender)) = reply_restore.clone() {
                            view.set_reply(id, preview, sender);
                        }
                    }
                }
            }
        };
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => {
                let fingerprint = fingerprint.clone();
                let sent_text = text.clone();
                // One worker for every send, so quick messages reach the core
                // (and the peer) in the order they were typed.
                serial_in_background(
                    move || core::send_message(&fingerprint, &sent_text, reply_id, preview_for_core, Some(mode)).map(|r| (r.message_id, r.status)),
                    move |result| {
                        let result = result.map(|(id, status)| make_entry(id, status));
                        done(view, result, text);
                    },
                );
            }
            Conversation::Group { group_id, .. } => {
                // @mentions: members (not me) whose "@Name" is in the text.
                let app = self.app();
                let candidates: Vec<(String, String)> = app
                    .groups
                    .borrow()
                    .iter()
                    .find(|group| group.group_id == *group_id)
                    .map(|group| group.member_identity_ids.clone())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|id| *app.own_identity_id.borrow() != *id)
                    .map(|id| {
                        let name = app.identity_name(&id);
                        (id, name)
                    })
                    .collect();
                let mentions = mentioned_ids(&text, &candidates);
                let group_id = group_id.clone();
                let sent_text = text.clone();
                serial_in_background(
                    move || {
                        core::send_group_message(&group_id, &sent_text, reply_id, preview_for_core, reply_sender_for_core, mentions, Some(mode))
                    },
                    move |result| {
                        // A group send fans out to every member; the core reports
                        // no single status, so it shows as sent and the pending
                        // queue owns the retries.
                        let result = result.map(|id| make_entry(id, "sent".to_string()));
                        done(view, result, text);
                    },
                );
            }
        }
    }

    /// Restores the composer to its idle look. Shared so stop, discard and
    /// failure paths cannot drift apart and leave the bar stuck mid-recording.
    pub(super) fn reset_recording_ui(button: &gtk::Button, timer: &gtk::Label, cancel: &gtk::Button) {
        button.set_icon_name("audio-input-microphone-symbolic");
        button.remove_css_class("destructive-action");
        button.add_css_class("flat");
        button.set_tooltip_text(Some("Record a voice message"));
        timer.set_visible(false);
        cancel.set_visible(false);
    }

    /// Throws away an in-progress recording without sending it.
    pub(super) fn cancel_recording(
        self: &Rc<Self>,
        button: &gtk::Button,
        timer: &gtk::Label,
        cancel: &gtk::Button,
    ) {
        if let Some(recording) = self.recording.borrow_mut().take() {
            recording.cancel();
            self.app().toast("Recording discarded.");
        }
        Self::reset_recording_ui(button, timer, cancel);
    }

    /// Starts or finishes a voice message.
    pub(super) fn toggle_recording(
        self: &Rc<Self>,
        button: &gtk::Button,
        timer: &gtk::Label,
        cancel: &gtk::Button,
    ) {
        let active = self.recording.borrow().is_some();
        if !active {
            match crate::audio::Recording::start() {
                Ok(recording) => {
                    *self.recording.borrow_mut() = Some(recording);
                    button.set_icon_name("media-playback-stop-symbolic");
                    button.add_css_class("destructive-action");
                    button.remove_css_class("flat");
                    button.set_tooltip_text(Some("Stop and send"));
                    timer.set_visible(true);
                    timer.set_label("0:00");
                    cancel.set_visible(true);

                    // Tick the elapsed time, and stop ticking as soon as the
                    // recording ends (or the view goes away).
                    let view = self.clone();
                    let timer = timer.clone();
                    glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
                        // Chat page gone (switched/closed): this timer keeps the
                        // view alive, so `Drop` never runs — stop the mic here.
                        if timer.root().is_none() {
                            if let Some(recording) = view.recording.borrow_mut().take() {
                                recording.cancel();
                            }
                            return glib::ControlFlow::Break;
                        }
                        let elapsed = match view.recording.borrow().as_ref() {
                            Some(recording) => recording.elapsed_ms(),
                            None => return glib::ControlFlow::Break,
                        };
                        let seconds = elapsed / 1000;
                        timer.set_label(&format!("{}:{:02}", seconds / 60, seconds % 60));
                        glib::ControlFlow::Continue
                    });
                }
                Err(error) => self.app().toast(&format!("Could not record: {}", error)),
            }
            return;
        }

        // Stop: restore the composer first so the UI never looks stuck while
        // the recorder finalises and the file is encrypted.
        Self::reset_recording_ui(button, timer, cancel);

        let Some(recording) = self.recording.borrow_mut().take() else {
            return;
        };
        // Under 0.8 s it is almost always a mis-click.
        if recording.elapsed_ms() < 800 {
            recording.cancel();
            self.app().toast("Too short — hold on a moment longer.");
            return;
        }

        // The microphone stops now, not when the caption is answered:
        // nothing said while the dialog is up may end up in the message.
        // `finish` waits for the recorder to write the file trailer, so it runs off the
        // GTK thread; the caption is asked once the file is final.
        // A voice message goes through the same flow as photos and files: an
        // optional caption, plus the active reply if there is one.
        let reply = self.reply_to.borrow().clone();
        let (reply_id, reply_preview, reply_sender) = match reply {
            Some((id, preview, sender)) => (Some(id), Some(preview), sender),
            None => (None, None, None),
        };

        let view = self.clone();
        app::run_in_background(
            move || recording.finish(),
            move |finished| {
                let (path, duration_ms) = match finished {
                    Ok(done) => done,
                    Err(error) => {
                        view.app().toast(&format!("Voice message failed: {}", error));
                        return;
                    }
                };
                let app = view.app().clone();
                let conversation = view.conversation.clone();
                let send_view = view.clone();
                view.prompt_attachment_caption(false, move |caption, _| {
                    let view = send_view.clone();
                    let app = app.clone();
                    let conversation = conversation.clone();
                    let reply_id = reply_id.clone();
                    let reply_preview = reply_preview.clone();
                    let reply_sender = reply_sender.clone();
                    let path = path.clone();
                    app.toast("Sending voice message…");
                    app::run_in_background(
                        move || {
                            let source = path.to_string_lossy().to_string();
                            let name = format!("voice-{}.ogg", crate::util::now_ms());
                            let outcome = match &conversation {
                                Conversation::Direct { fingerprint, .. } => core::prepare_and_send_file(
                                    fingerprint,
                                    &source,
                                    &name,
                                    "audio/ogg",
                                    None,
                                    Some(duration_ms),
                                    caption,
                                    reply_id,
                                    reply_preview,
                                )
                                .map(|receipt| receipt.message_id),
                                Conversation::Group { group_id, .. } => core::prepare_and_send_group_file(
                                    group_id,
                                    &source,
                                    &name,
                                    "audio/ogg",
                                    None,
                                    Some(duration_ms),
                                    caption,
                                    reply_id,
                                    reply_preview,
                                    reply_sender,
                                ),
                            };
                            // The core copies and encrypts the file, so the raw capture is
                            // no longer needed either way.
                            let _ = std::fs::remove_file(&path);
                            outcome.map(|id| super::history::sent_attachment_entry(&conversation, &id))
                        },
                        move |result| match result {
                            Ok(entry) => {
                                view.clear_reply();
                                view.show_sent_attachment(entry);
                            }
                            Err(error) => app.toast(&format!("Voice message failed: {}", error)),
                        },
                    );
                });
            },
        );
    }

        /// Asks for an optional caption right before a file or voice message is sent (same design as Android
        /// `ChatActivity.promptAttachmentCaption`). There is no separate step for the reply. If the screen already holds an active
        /// reply (see `reply_to`), the attachment is sent with it. This dialog asks only for the caption. There is deliberately no
        /// real "cancel" path: the file is already chosen or recorded, and "Skip" keeps sending with an empty caption (the same
        /// behaviour as on Android).
    pub(super) fn prompt_attachment_caption(self: &Rc<Self>, offer_hi_res: bool, on_confirm: impl FnOnce(String, bool) + 'static) {
        let Some(window) = self.app().window() else {
            on_confirm(String::new(), false);
            return;
        };
        let field = gtk::Entry::builder()
            .placeholder_text("Add a caption (optional)")
            .activates_default(true)
            .build();
        let dialog = adw::MessageDialog::new(Some(&window), Some("Add a caption?"), None);
        let hi_res = gtk::CheckButton::with_label("Hi-res (lossless)");
        if offer_hi_res {
            let column = gtk::Box::new(gtk::Orientation::Vertical, 6);
            column.append(&crate::ui::widgets::dialog_field(&field));
            column.append(&hi_res);
            dialog.set_extra_child(Some(&column));
        } else {
            dialog.set_extra_child(Some(&crate::ui::widgets::dialog_field(&field)));
        }
        dialog.add_response("skip", "Skip");
        dialog.add_response("send", "Send");
        dialog.set_default_response(Some("send"));
        dialog.set_close_response("skip");
        dialog.set_response_appearance("send", adw::ResponseAppearance::Suggested);
                // The standard pattern that bridges the `Fn` that `connect_response` expects with the `FnOnce` we have (the voice
                // recording's finisher: `Recording::finish` CONSUMES `self`, so the closure wrapping it cannot be called more than once):
                // put the `FnOnce` in a `RefCell<Option<_>>`. When the signal fires (in practice only once), `take()` takes it out and
                // calls it. A second firing (which should not happen) is a silent no-op.
        let on_confirm = std::cell::RefCell::new(Some(on_confirm));
        dialog.connect_response(None, move |_, response| {
            let caption = if response == "send" {
                field.text().to_string().trim().to_string()
            } else {
                String::new()
            };
            if let Some(f) = on_confirm.borrow_mut().take() {
                f(caption, hi_res.is_active());
            }
        });
        dialog.present();
    }

    pub(super) fn pick_attachment(self: &Rc<Self>) {
        let Some(window) = self.app().window() else { return };
        let dialog = gtk::FileDialog::builder().modal(false).title("Send a file").build();
        let view = self.clone();
        dialog.open(Some(&window), gio::Cancellable::NONE, move |result| {
            let Ok(file) = result else { return };
            let Some(path) = file.path() else { return };
            let send_view = view.clone();
            let offer_hi_res = file.basename().is_some_and(|name| util::is_image(&util::guess_mime(&name.to_string_lossy())));
            view.prompt_attachment_caption(offer_hi_res, move |caption, hi_res| send_view.send_attachment(&path, caption, hi_res));
        });
    }

    pub(super) fn send_attachment(self: &Rc<Self>, path: &std::path::Path, caption: String, hi_res: bool) {
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let mime = util::guess_mime(&file_name);
        let source = path.to_path_buf();

        // Photos travel with a small cover so the receiver sees something
        // before downloading. Video previews would need a decoder we do not
        // ship, so those go without — the receiver still gets a file card.
        // Decoded in the worker below, never on the GTK thread.
        let want_preview = util::is_image(&mime);

                // See the `prompt_attachment_caption` doc. If the screen already holds an active reply (the
                // same logic as a text message, see `send_message`), the attachment goes with it.
        let reply = self.reply_to.borrow().clone();
        let (reply_id, reply_preview, reply_sender) = match reply {
            Some((id, preview, sender)) => (Some(id), Some(preview), sender),
            None => (None, None, None),
        };

        let conversation = self.conversation.clone();
        let view = self.clone();
        let app = self.app().clone();
        app.toast(&format!("Encrypting {}…", file_name));

        // Encryption rewrites the whole file; on a 4 GB attachment this is very
        // much not instant.
        app::run_in_background(
            move || {
                let preview = if want_preview {
                    util::scaled_jpeg(&source.to_string_lossy(), 480, 85)
                } else {
                    None
                };
                let tmp_dir = crate::data_directory().join("attachments/plain_cache");
                let (sent, file_name, mime) = util::prepare_outgoing(&source, &file_name, &mime, hi_res, &tmp_dir);
                // Judged by content, not the extension: the core strips only
                // JPEG/PNG/JPEG XL/WebP; any other media left as it is asks first.
                let unscrubbed = sent == source
                    && !util::core_scrubs_magic(&source)
                    && (util::is_video(&mime)
                        || (util::is_image(&mime) && mime != "image/svg+xml")
                        || util::media_magic(&source));
                (preview, sent, source, file_name, mime, unscrubbed)
            },
            move |(preview, sent, source, file_name, mime, unscrubbed)| {
                let app_for_send = app.clone();
                let send = move || {
                    app::run_in_background(
                        move || {
                            let sent_path = sent.to_string_lossy().to_string();
                            let outcome = match &conversation {
                                Conversation::Direct { fingerprint, .. } => core::prepare_and_send_file(
                                    fingerprint, &sent_path, &file_name, &mime, preview, None,
                                    caption, reply_id, reply_preview,
                                )
                                .map(|receipt| receipt.message_id),
                                Conversation::Group { group_id, .. } => core::prepare_and_send_group_file(
                                    group_id, &sent_path, &file_name, &mime, preview, None,
                                    caption, reply_id, reply_preview, reply_sender,
                                ),
                            };
                            if sent != source {
                                let _ = std::fs::remove_file(&sent);
                            }
                            outcome.map(|id| super::history::sent_attachment_entry(&conversation, &id))
                        },
                        move |result| match result {
                            // The bubble is built from the archive row, as a
                            // restart would show it; no full reload.
                            Ok(entry) => {
                                view.clear_reply();
                                view.show_sent_attachment(entry);
                            }
                            Err(error) => app_for_send.toast(&format!("Could not send the file: {}", error)),
                        },
                    );
                };
                if unscrubbed {
                    // Same contract as Android: never send location and device
                    // metadata without asking.
                    let send = std::cell::RefCell::new(Some(send));
                    dialogs::confirm(
                        &app,
                        "Send with metadata?",
                        "The metadata (location, device, time) of this file could not be removed. Send it anyway?",
                        "Send anyway",
                        true,
                        move || {
                            if let Some(send) = send.borrow_mut().take() {
                                send();
                            }
                        },
                    );
                } else {
                    send();
                }
            },
        );
    }

    /// My stickers in a popover: click sends, right click opens the sticker
    /// menu (favorite, folders, delete), "Add" imports a picture. Folders come
    /// first; a folder shows only its stickers, Back or Escape leaves it. The
    /// pictures are converted one by one off the GTK thread and stop when the
    /// popover closes or shows something else.
    pub(super) fn sticker_picker(self: &Rc<Self>, anchor: &gtk::Button) {
        let popover = gtk::Popover::new();
        popover.set_parent(anchor);
        popover.connect_closed(|popover| popover.unparent());

        let grid = gtk::FlowBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .max_children_per_line(5)
            .min_children_per_line(5)
            .homogeneous(true)
            // Rows keep their own height. Filling the scroller's minimum height stretched a single row (and the folder button
            // in it) into a tall pill.
            .valign(gtk::Align::Start)
            .build();
        let scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .min_content_width(380)
            .min_content_height(320)
            .child(&grid)
            .build();
        let add = gtk::Button::builder().label("Add from file…").build();
        {
            let (view, popover) = (self.clone(), popover.clone());
            add.connect_clicked(move |_| {
                popover.popdown();
                view.import_sticker();
            });
        }
        let fetch = gtk::Button::builder().label("Fetch stickers from phone").build();
        {
            let (app, popover) = (self.app().clone(), popover.clone());
            fetch.connect_clicked(move |_| {
                popover.popdown();
                let app = app.clone();
                app::run_in_background(core::request_stickers_from_phone, move |result| match result {
                    Ok(()) => app.toast("Asked your phone: stickers arrive in the background"),
                    Err(error) => app.toast(&format!("Could not ask your phone: {}", error)),
                });
            });
        }
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        buttons.set_homogeneous(true);
        buttons.append(&add);
        buttons.append(&fetch);
        let header = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let column = gtk::Box::new(gtk::Orientation::Vertical, 6);
        column.append(&header);
        column.append(&scroller);
        column.append(&buttons);
        popover.set_child(Some(&column));

        let picker = Rc::new(StickerPopover {
            popover: popover.clone(),
            grid,
            header,
            folder: RefCell::new(None),
            folders: RefCell::new(Vec::new()),
            generation: Cell::new(0),
        });
        // The only strong reference: every other closure holds the picker weakly. Without it the
        // picker was dropped when this function returned, so the loader stopped and the grid stayed empty.
        {
            let keep = RefCell::new(Some(picker.clone()));
            popover.connect_closed(move |_| {
                keep.take();
            });
        }
        // Escape in a folder goes back to all stickers; at the top it closes.
        // Weak: the popover owns this closure, and the picker owns the popover.
        let keys = gtk::EventControllerKey::new();
        keys.set_propagation_phase(gtk::PropagationPhase::Capture);
        {
            let (view, weak) = (self.clone(), Rc::downgrade(&picker));
            keys.connect_key_pressed(move |_, key, _, _| {
                let Some(picker) = weak.upgrade() else { return glib::Propagation::Proceed };
                if key == gtk::gdk::Key::Escape && picker.folder.borrow().is_some() {
                    picker.folder.replace(None);
                    view.fill_sticker_picker(&picker);
                    return glib::Propagation::Stop;
                }
                glib::Propagation::Proceed
            });
        }
        popover.add_controller(keys);
        self.fill_sticker_picker(&picker);
        popover.popup();
    }

    /// Fills the popover again if it is still open (after a folder change).
    fn refill_sticker_picker(self: &Rc<Self>, weak: &std::rc::Weak<StickerPopover>) {
        if let Some(picker) = weak.upgrade() {
            if picker.popover.parent().is_some() {
                self.fill_sticker_picker(&picker);
            }
        }
    }

    /// The header (New folder, or Back / Rename / Delete in a folder), then
    /// the folders (at the top only) and the stickers shown.
    fn fill_sticker_picker(self: &Rc<Self>, picker: &Rc<StickerPopover>) {
        let generation = picker.generation.get() + 1;
        picker.generation.set(generation);
        while let Some(child) = picker.grid.first_child() {
            picker.grid.remove(&child);
        }
        while let Some(child) = picker.header.first_child() {
            picker.header.remove(&child);
        }
        let open = picker.folder.borrow().clone();
        let weak = Rc::downgrade(picker);
        match &open {
            None => {
                let new = gtk::Button::builder().label("New folder…").build();
                let (view, weak) = (self.clone(), weak.clone());
                new.connect_clicked(move |_| {
                    let (view_for_name, weak) = (view.clone(), weak.clone());
                    dialogs::prompt(view.app(), "New folder", "", "Folder name", "", "Create", move |name| {
                        let (view, weak) = (view_for_name.clone(), weak.clone());
                        app::run_in_background(move || core::create_sticker_folder(&name), move |result| match result {
                            Ok(_) => {
                                view.app().toast("Folder created");
                                view.refill_sticker_picker(&weak);
                            }
                            Err(error) => view.app().toast(&format!("Could not create the folder: {}", error)),
                        });
                    });
                });
                picker.header.append(&new);
            }
            Some(folder) => {
                let back = gtk::Button::builder().label(format!("‹ {}", folder.name)).hexpand(true).build();
                {
                    let (view, weak) = (self.clone(), weak.clone());
                    back.connect_clicked(move |_| {
                        let Some(picker) = weak.upgrade() else { return };
                        picker.folder.replace(None);
                        view.fill_sticker_picker(&picker);
                    });
                }
                let rename = gtk::Button::builder().label("Rename folder").build();
                {
                    let (view, weak, folder) = (self.clone(), weak.clone(), folder.clone());
                    rename.connect_clicked(move |_| {
                        let (view_for_name, weak, id) = (view.clone(), weak.clone(), folder.id);
                        dialogs::prompt(view.app(), "Rename folder", "", "Folder name", &folder.name, "Rename", move |name| {
                            let (view, weak, shown) = (view_for_name.clone(), weak.clone(), name.clone());
                            app::run_in_background(move || core::rename_sticker_folder(id, &name), move |result| match result {
                                Ok(()) => {
                                    if let Some(picker) = weak.upgrade() {
                                        if let Some(open) = picker.folder.borrow_mut().as_mut() {
                                            open.name = shown;
                                        }
                                    }
                                    view.refill_sticker_picker(&weak);
                                }
                                Err(error) => view.app().toast(&format!("Could not rename the folder: {}", error)),
                            });
                        });
                    });
                }
                let delete = gtk::Button::builder().label("Delete folder").build();
                delete.add_css_class("destructive-action");
                {
                    let (view, weak, folder) = (self.clone(), weak.clone(), folder.clone());
                    delete.connect_clicked(move |_| {
                        let (view_for_delete, weak, id) = (view.clone(), weak.clone(), folder.id);
                        let body = format!("The folder \"{}\" is removed. Its stickers stay.", folder.name);
                        dialogs::confirm(view.app(), "Delete this folder?", &body, "Delete", true, move || {
                            let (view, weak) = (view_for_delete.clone(), weak.clone());
                            app::run_in_background(move || core::delete_sticker_folder(id), move |result| match result {
                                Ok(()) => {
                                    if let Some(picker) = weak.upgrade() {
                                        picker.folder.replace(None);
                                    }
                                    view.refill_sticker_picker(&weak);
                                }
                                Err(error) => view.app().toast(&format!("Could not delete the folder: {}", error)),
                            });
                        });
                    });
                }
                picker.header.append(&back);
                picker.header.append(&rename);
                picker.header.append(&delete);
            }
        }

        // Listed and decoded off the GTK thread: the list takes the core
        // lock, and a big GIF froze the window.
        // ponytail: the grid shows an animated sticker's first frame.
        let (tx, rx) = async_channel::unbounded::<StickerLoad>();
        let shown = open.as_ref().map(|f| f.id);
        std::thread::spawn(move || {
            let folders = core::list_sticker_folders();
            let only: Option<HashSet<String>> =
                shown.map(|id| folders.iter().find(|f| f.id == id).map(|f| f.stickers.iter().cloned().collect()).unwrap_or_default());
            let stickers: Vec<core::StickerEntry> =
                core::list_stickers().into_iter().filter(|s| only.as_ref().map_or(true, |only| only.contains(&s.id))).collect();
            let load = |sticker: &core::StickerEntry| {
                let path = if sticker.animated { core::sticker_first_frame(&sticker.id) } else { core::sticker_plain_path(&sticker.id) };
                path.ok().and_then(|p| gtk::gdk::Texture::from_filename(p).ok())
            };
            // Folder previews: the first four stickers of each folder, in grid
            // order. Decoded once; the grid below reuses them.
            let mut decoded: HashMap<String, Option<gtk::gdk::Texture>> = HashMap::new();
            let mut previews: Vec<Vec<gtk::gdk::Texture>> = Vec::new();
            if shown.is_none() {
                for folder in &folders {
                    let mut textures = Vec::new();
                    for sticker in stickers.iter().filter(|s| folder.stickers.contains(&s.id)) {
                        if textures.len() == 4 {
                            break;
                        }
                        if let Some(texture) = decoded.entry(sticker.id.clone()).or_insert_with(|| load(sticker)) {
                            textures.push(texture.clone());
                        }
                    }
                    previews.push(textures);
                }
            }
            if tx.send_blocking(StickerLoad::Folders(folders, previews)).is_err() {
                return;
            }
            if stickers.is_empty() {
                let _ = tx.send_blocking(StickerLoad::Empty);
            }
            for sticker in stickers {
                let texture = decoded.remove(&sticker.id).unwrap_or_else(|| load(&sticker));
                if tx.send_blocking(StickerLoad::Sticker(sticker.id, sticker.favorite, texture)).is_err() {
                    break; // popover closed or refilled
                }
            }
        });
        let view = self.clone();
        glib::spawn_future_local(async move {
            while let Ok(item) = rx.recv().await {
                let Some(picker) = weak.upgrade() else { break };
                if picker.generation.get() != generation || picker.popover.parent().is_none() {
                    break;
                }
                match item {
                    StickerLoad::Folders(folders, previews) => {
                        let open = picker.folder.borrow().as_ref().map(|f| f.id);
                        match open {
                            // The folder is gone (deleted meanwhile): back to the top.
                            Some(id) if !folders.iter().any(|f| f.id == id) => {
                                picker.folder.replace(None);
                                view.fill_sticker_picker(&picker);
                                break;
                            }
                            Some(_) => {}
                            None => {
                                for (i, folder) in folders.iter().enumerate() {
                                    let textures = previews.get(i).map(Vec::as_slice).unwrap_or_default();
                                    picker.grid.append(&view.sticker_folder_cell(&picker, folder, textures));
                                }
                            }
                        }
                        picker.folders.replace(folders);
                    }
                    StickerLoad::Empty => {
                        let text = if open.is_some() { "No stickers in this folder" } else { "No stickers yet" };
                        picker.grid.append(&gtk::Label::new(Some(text)));
                    }
                    StickerLoad::Sticker(id, favorite, Some(texture)) => {
                        picker.grid.append(&view.sticker_cell(&picker, id, favorite, &texture));
                    }
                    StickerLoad::Sticker(_, _, None) => {}
                }
            }
        });
    }

    /// A folder: up to four of its stickers in a 2×2 grid under its name;
    /// an empty folder shows the folder icon.
    fn sticker_folder_cell(
        self: &Rc<Self>,
        picker: &Rc<StickerPopover>,
        folder: &core::StickerFolder,
        previews: &[gtk::gdk::Texture],
    ) -> gtk::Button {
        let label = gtk::Label::builder()
            .label(format!("{} ({})", folder.name, folder.stickers.len()))
            .justify(gtk::Justification::Center)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .max_width_chars(8)
            .valign(gtk::Align::End)
            .build();
        let child = gtk::Overlay::new();
        if previews.is_empty() {
            let icon = gtk::Label::new(Some("📁"));
            icon.set_size_request(64, 64);
            child.set_child(Some(&icon));
        } else {
            let grid = gtk::Grid::builder().row_homogeneous(true).column_homogeneous(true).build();
            grid.set_size_request(64, 64);
            for (i, texture) in previews.iter().enumerate() {
                let picture = gtk::Picture::for_paintable(texture);
                picture.set_content_fit(gtk::ContentFit::Contain);
                picture.set_size_request(32, 32);
                grid.attach(&picture, (i % 2) as i32, (i / 2) as i32, 1, 1);
            }
            child.set_child(Some(&grid));
            label.add_css_class("osd");
        }
        child.add_overlay(&label);
        let button = gtk::Button::builder().child(&child).tooltip_text(folder.name.as_str()).build();
        button.set_size_request(64, 64);
        let (view, weak, folder) = (self.clone(), Rc::downgrade(picker), folder.clone());
        button.connect_clicked(move |_| {
            let Some(picker) = weak.upgrade() else { return };
            picker.folder.replace(Some(folder.clone()));
            view.fill_sticker_picker(&picker);
        });
        button
    }

    /// A sticker: click sends, right click opens its menu.
    fn sticker_cell(self: &Rc<Self>, picker: &Rc<StickerPopover>, id: String, favorite: bool, texture: &gtk::gdk::Texture) -> gtk::Button {
        let picture = gtk::Picture::for_paintable(texture);
        picture.set_size_request(64, 64);
        picture.set_content_fit(gtk::ContentFit::Contain);
        let button = gtk::Button::builder().child(&picture).build();
        button.add_css_class("flat");
        {
            let (view, id, popover) = (self.clone(), id.clone(), picker.popover.clone());
            button.connect_clicked(move |_| {
                popover.popdown();
                view.send_sticker(&id);
            });
        }
        let right = gtk::GestureClick::builder().button(gtk::gdk::BUTTON_SECONDARY).build();
        {
            let (view, weak, button_ref) = (self.clone(), Rc::downgrade(picker), button.downgrade());
            let favorite = Rc::new(Cell::new(favorite));
            right.connect_pressed(move |_, _, x, y| {
                let (Some(picker), Some(button)) = (weak.upgrade(), button_ref.upgrade()) else { return };
                view.sticker_menu(&picker, &button, &id, &favorite, x, y);
            });
        }
        button.add_controller(right);
        button
    }

    fn sticker_menu(
        self: &Rc<Self>,
        picker: &Rc<StickerPopover>,
        button: &gtk::Button,
        id: &str,
        favorite: &Rc<Cell<bool>>,
        x: f64,
        y: f64,
    ) {
        let (menu, items) = crate::ui::widgets::menu_popover();
        menu.set_parent(button);
        menu.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
        menu.connect_closed(|menu| menu.unparent());
        let app = self.app().clone();
        // The cell leaves the grid: deleted, or taken out of the shown folder.
        let hide = {
            let button = button.clone();
            move || button.parent().unwrap_or_else(|| button.clone().upcast()).set_visible(false)
        };

        let fav = crate::ui::widgets::menu_item("starred-symbolic", if favorite.get() { "Unfavorite" } else { "Favorite" });
        {
            let (id, favorite, menu, app) = (id.to_string(), favorite.clone(), menu.clone(), app.clone());
            fav.connect_clicked(move |_| {
                menu.popdown();
                let want = !favorite.get();
                let (id, favorite, app) = (id.clone(), favorite.clone(), app.clone());
                app::run_in_background(
                    move || core::set_sticker_favorite(&id, want),
                    move |result| match result {
                        // Shown first from the next opening on.
                        Ok(()) => favorite.set(want),
                        Err(error) => app.toast(&format!("Could not change the sticker: {}", error)),
                    },
                );
            });
        }
        items.append(&fav);

        let to_folder = crate::ui::widgets::menu_item("folder-symbolic", "Add to folder…");
        {
            let (view, picker, button, id, menu) = (self.clone(), picker.clone(), button.clone(), id.to_string(), menu.clone());
            to_folder.connect_clicked(move |_| {
                menu.popdown();
                view.sticker_folder_menu(&picker, &button, &id);
            });
        }
        items.append(&to_folder);

        if let Some(folder) = picker.folder.borrow().clone() {
            let out = crate::ui::widgets::menu_item("list-remove-symbolic", "Remove from folder");
            let (id, menu, app, hide) = (id.to_string(), menu.clone(), app.clone(), hide.clone());
            out.connect_clicked(move |_| {
                menu.popdown();
                let (ids, app, hide) = (vec![id.clone()], app.clone(), hide.clone());
                app::run_in_background(
                    move || core::remove_stickers_from_folder(folder.id, &ids),
                    move |result| match result {
                        Ok(()) => hide(),
                        Err(error) => app.toast(&format!("Could not remove the sticker from the folder: {}", error)),
                    },
                );
            });
            items.append(&out);
        }

        let delete = crate::ui::widgets::menu_item("edit-delete-symbolic", "Delete");
        delete.add_css_class("destructive-action");
        {
            let (id, menu) = (id.to_string(), menu.clone());
            delete.connect_clicked(move |_| {
                menu.popdown();
                let (id, app, hide) = (id.clone(), app.clone(), hide.clone());
                dialogs::confirm(&app.clone(), "Delete this sticker?", "It is removed from all your devices.", "Delete", true, move || {
                    let (id, app, hide) = (id.clone(), app.clone(), hide.clone());
                    app::run_in_background(
                        move || core::delete_sticker(&id),
                        move |result| match result {
                            Ok(()) => hide(),
                            Err(error) => app.toast(&format!("Could not delete the sticker: {}", error)),
                        },
                    );
                });
            });
        }
        items.append(&delete);
        menu.popup();
    }

    /// "Add to folder…": every folder, then "New folder…".
    fn sticker_folder_menu(self: &Rc<Self>, picker: &Rc<StickerPopover>, button: &gtk::Button, id: &str) {
        let (menu, items) = crate::ui::widgets::menu_popover();
        menu.set_parent(button);
        menu.connect_closed(|menu| menu.unparent());
        let app = self.app().clone();
        let add = {
            let (id, app, view, weak) = (id.to_string(), app.clone(), self.clone(), Rc::downgrade(picker));
            move |folder_id: i64, name: String| {
                let (ids, app, view, weak) = (vec![id.clone()], app.clone(), view.clone(), weak.clone());
                app::run_in_background(
                    move || core::add_stickers_to_folder(folder_id, &ids),
                    move |result| match result {
                        Ok(()) => {
                            app.toast(&format!("Added to {}", name));
                            // The folder cell's count and preview are read at fill time.
                            view.refill_sticker_picker(&weak);
                        }
                        Err(error) => app.toast(&format!("Could not add the sticker to the folder: {}", error)),
                    },
                );
            }
        };
        for folder in picker.folders.borrow().iter() {
            let item = crate::ui::widgets::menu_item("folder-symbolic", &folder.name);
            let (add, menu, folder_id, name) = (add.clone(), menu.clone(), folder.id, folder.name.clone());
            item.connect_clicked(move |_| {
                menu.popdown();
                add(folder_id, name.clone());
            });
            items.append(&item);
        }
        let new = crate::ui::widgets::menu_item("folder-new-symbolic", "New folder…");
        {
            let menu = menu.clone();
            new.connect_clicked(move |_| {
                menu.popdown();
                let (add, app_for_create) = (add.clone(), app.clone());
                dialogs::prompt(&app, "New folder", "", "Folder name", "", "Create", move |name| {
                    let (add, app) = (add.clone(), app_for_create.clone());
                    let folder_name = name.clone();
                    app::run_in_background(move || core::create_sticker_folder(&name), move |result| match result {
                        Ok(folder_id) => add(folder_id, folder_name),
                        Err(error) => app.toast(&format!("Could not create the folder: {}", error)),
                    });
                });
            });
        }
        items.append(&new);
        menu.popup();
    }

    pub(super) fn send_sticker(self: &Rc<Self>, sticker_id: &str) {
        let (target, group) = match &self.conversation {
            Conversation::Direct { fingerprint, .. } => (fingerprint.clone(), false),
            Conversation::Group { group_id, .. } => (group_id.clone(), true),
        };
        let reply = self.reply_to.borrow().clone();
        let id = sticker_id.to_string();
        let view = self.clone();
        let conversation = self.conversation.clone();
        app::run_in_background(
            move || {
                core::send_sticker(&target, group, &id, reply)
                    .map(|id| super::history::sent_attachment_entry(&conversation, &id))
            },
            move |result| match result {
                Ok(entry) => {
                    view.clear_reply();
                    view.show_sent_attachment(entry);
                }
                Err(error) => view.app().toast(&format!("Could not send the sticker: {}", error)),
            },
        );
    }

    pub(super) fn import_sticker(self: &Rc<Self>) {
        let Some(window) = self.app().window() else { return };
        let filter = gtk::FileFilter::new();
        filter.set_name(Some("Pictures"));
        filter.add_pixbuf_formats();
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        filters.append(&filter);
        let dialog = gtk::FileDialog::builder().modal(false).title("Add a sticker").filters(&filters).build();
        let app = self.app().clone();
        dialog.open(Some(&window), gio::Cancellable::NONE, move |result| {
            let Ok(file) = result else { return };
            let Some(path) = file.path() else { return };
            app::run_in_background(
                move || {
                    let (rgba, w, h) = util::image_rgba(&path.to_string_lossy(), 600)
                        .ok_or_else(|| "this picture cannot be read".to_string())?;
                    core::import_sticker_rgba(rgba, w, h)
                },
                move |result| match result {
                    Ok(_) => app.toast("Added to your stickers"),
                    Err(error) => app.toast(&format!("Could not add the sticker: {}", error)),
                },
            );
        });
    }

    /// Fire-and-forget; only sent on a false<->true transition, never per
    /// keystroke.
    pub(super) fn set_typing(&self, typing: bool) {
        if typing {
            self.last_typing_sent.set(util::now_ms());
        }
        if self.typing_active.get() == typing {
            return;
        }
        self.typing_active.set(typing);
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => {
                let fingerprint = fingerprint.clone();
                bg_serial(move || core::send_typing_indicator(&fingerprint, typing));
            }
            Conversation::Group { group_id, .. } => {
                let group_id = group_id.clone();
                bg_serial(move || core::send_group_typing_indicator(&group_id, typing));
            }
        }
    }

}

// --- live updates ---

/// One worker runs the fire-and-forget core calls (typing, read sync, seen
/// receipts) in order: no thread per transition, and a typing "false" can no
/// longer overtake its "true".
pub(super) fn bg_serial(job: impl FnOnce() + Send + 'static) {
    type Job = Box<dyn FnOnce() + Send>;
    static TX: std::sync::OnceLock<std::sync::mpsc::Sender<Job>> = std::sync::OnceLock::new();
    let tx = TX.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        std::thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                job();
            }
        });
        tx
    });
    let _ = tx.send(Box::new(job));
}

/// `run_in_background` on the `bg_serial` worker: jobs reach the core in
/// the order they were started, and `then` gets each result on the GTK thread.
pub(super) fn serial_in_background<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
    then: impl FnOnce(T) + 'static,
) {
    let (sender, receiver) = async_channel::bounded::<T>(1);
    bg_serial(move || {
        let _ = sender.send_blocking(work());
    });
    glib::spawn_future_local(async move {
        if let Ok(result) = receiver.recv().await {
            then(result);
        }
    });
}

/// Ids of the members whose "@Name" is in `text`. The name must end at a
/// non-letter/digit or the end of the text ("@Alice" does not mention "Al");
/// at each '@' only the longest matching name counts.
pub(super) fn mentioned_ids(text: &str, candidates: &[(String, String)]) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for (at, _) in text.match_indices('@') {
        let rest = &text[at + 1..];
        let hits: Vec<&(String, String)> = candidates
            .iter()
            .filter(|(_, name)| {
                !name.is_empty()
                    && rest.starts_with(name.as_str())
                    && !rest[name.len()..].chars().next().is_some_and(char::is_alphanumeric)
            })
            .collect();
        let longest = hits.iter().map(|(_, name)| name.len()).max();
        for (id, name) in hits {
            if Some(name.len()) == longest && !ids.contains(id) {
                ids.push(id.clone());
            }
        }
    }
    ids
}

/// The open sticker popover: the folder it shows, and a generation that stops
/// an older fill's loader.
pub(super) struct StickerPopover {
    popover: gtk::Popover,
    grid: gtk::FlowBox,
    header: gtk::Box,
    folder: RefCell<Option<core::StickerFolder>>,
    /// Every folder, for "Add to folder…".
    folders: RefCell<Vec<core::StickerFolder>>,
    generation: Cell<u64>,
}

/// What the sticker loader thread sends, in this order.
enum StickerLoad {
    /// The folders and, at the top level, each folder's preview pictures.
    Folders(Vec<core::StickerFolder>, Vec<Vec<gtk::gdk::Texture>>),
    Empty,
    Sticker(String, bool, Option<gtk::gdk::Texture>),
}
