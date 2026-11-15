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
        // No ffmpeg, no capture — say so rather than failing on click.
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

    let send = gtk::Button::builder()
        .icon_name("document-send-symbolic")
        .tooltip_text("Send")
        .valign(gtk::Align::End)
        .build();
    send.add_css_class("suggested-action");
    send.add_css_class("circular");
    {
        let view = view.clone();
        send.connect_clicked(move |_| view.send());
    }

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
        let (reply_id, reply_preview, reply_sender) = match reply {
            Some((id, preview, sender)) => (Some(id), Some(preview), sender),
            None => (None, None, None),
        };

        let own_identity = self.app().own_identity_id.borrow().clone();
        let now = util::now_ms();

        // Composer clears first; the core call runs off the GTK thread and the
        // bubble appears on its result. A failed send puts the text back.
        buffer.set_text("");
        self.clear_reply();
        self.set_typing(false);

        let view = self.clone();
        let restore = text.clone();
        let preview_for_core = reply_preview.clone();
        let reply_sender_for_core = reply_sender.clone();
        let make_entry = move |id: String, status: String| Entry {
            id,
            mine: true,
            sender_identity: own_identity,
            text: restore.clone(),
            order_key: now,
            status: Some(status),
            reply_preview: reply_preview.clone(),
            reply_sender: reply_sender.clone(),
            deleted: false,
            edited: false,
            attachment: None,
            seen: false,
            reactions: String::new(),
        };
        let done = move |view: Rc<Self>, result: Result<Entry, String>, text: String| match result {
            Ok(entry) => view.insert_entry(entry, true),
            Err(error) => {
                view.app().toast(&format!("Could not send: {}", error));
                let buffer = view.composer.buffer();
                let (start, end) = buffer.bounds();
                if buffer.text(&start, &end, false).is_empty() {
                    buffer.set_text(&text);
                }
            }
        };
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => {
                let fingerprint = fingerprint.clone();
                let sent_text = text.clone();
                crate::app::run_in_background(
                    move || core::send_message(&fingerprint, &sent_text, reply_id, preview_for_core).map(|r| (r.message_id, r.status)),
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
                crate::app::run_in_background(
                    move || {
                        core::send_group_message(&group_id, &sent_text, reply_id, preview_for_core, reply_sender_for_core, mentions)
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
        // ffmpeg finalises and the file is encrypted.
        Self::reset_recording_ui(button, timer, cancel);

        let Some(recording) = self.recording.borrow_mut().take() else {
            return;
        };
        // Below about a second it is almost always a mis-click.
        if recording.elapsed_ms() < 800 {
            recording.cancel();
            self.app().toast("Too short — hold on a moment longer.");
            return;
        }

                // See the `prompt_attachment_caption` note at the top of the file. A voice message goes through the same flow as photos
                // and files: an optional caption, plus the active reply if there is one.
        let reply = self.reply_to.borrow().clone();
        let (reply_id, reply_preview, reply_sender) = match reply {
            Some((id, preview, sender)) => (Some(id), Some(preview), sender),
            None => (None, None, None),
        };

        let view = self.clone();
        let app = self.app().clone();
        let conversation = self.conversation.clone();
        self.prompt_attachment_caption(false, move |caption, _| {
            let view = view.clone();
            let app = app.clone();
            let conversation = conversation.clone();
            let reply_id = reply_id.clone();
            let reply_preview = reply_preview.clone();
            let reply_sender = reply_sender.clone();
            app.toast("Sending voice message…");
            app::run_in_background(
                move || {
                    let (path, duration_ms) = recording.finish()?;
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
                    outcome
                },
                move |result| match result {
                    Ok(_) => {
                        view.clear_reply();
                        view.reload();
                    }
                    Err(error) => app.toast(&format!("Voice message failed: {}", error)),
                },
            );
        });
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
        let dialog = gtk::FileDialog::builder().title("Send a file").build();
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

                // See the `prompt_attachment_caption` note at the top of the file. If the screen already holds an active reply (the
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
                            outcome
                        },
                        move |result| match result {
                            // The attachment row comes from the archive, so a reload is the
                            // simplest way to show it exactly as a restart would.
                            Ok(_) => {
                                view.clear_reply();
                                view.reload();
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

    /// My stickers in a popover: click sends, right click deletes, "Add"
    /// imports a picture. Rebuilt on every open; the pictures are converted
    /// one by one off the GTK thread and stop when the popover closes.
    pub(super) fn sticker_picker(self: &Rc<Self>, anchor: &gtk::Button) {
        let popover = gtk::Popover::new();
        popover.set_parent(anchor);
        popover.connect_closed(|popover| popover.unparent());

        let grid = gtk::FlowBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .max_children_per_line(5)
            .min_children_per_line(5)
            .homogeneous(true)
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
                match core::request_stickers_from_phone() {
                    Ok(()) => app.toast("Asked your phone: stickers arrive in the background"),
                    Err(error) => app.toast(&format!("Could not ask your phone: {}", error)),
                }
            });
        }
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        buttons.set_homogeneous(true);
        buttons.append(&add);
        buttons.append(&fetch);
        let column = gtk::Box::new(gtk::Orientation::Vertical, 6);
        column.append(&scroller);
        column.append(&buttons);
        popover.set_child(Some(&column));

        let stickers = core::list_stickers();
        if stickers.is_empty() {
            grid.append(&gtk::Label::new(Some("No stickers yet")));
        }
        // Decoded here too, not on the GTK thread: a big GIF froze the window.
        // ponytail: the grid shows an animated sticker's first frame.
        let (tx, rx) = async_channel::unbounded::<(String, bool, Option<gtk::gdk::Texture>)>();
        std::thread::spawn(move || {
            for sticker in stickers {
                let path = if sticker.animated { core::sticker_first_frame(&sticker.id) } else { core::sticker_plain_path(&sticker.id) };
                let texture = path.ok().and_then(|p| gtk::gdk::Texture::from_filename(p).ok());
                if tx.send_blocking((sticker.id, sticker.favorite, texture)).is_err() {
                    break; // popover closed
                }
            }
        });
        let view = self.clone();
        let (grid_for_load, popover_for_load) = (grid.clone(), popover.clone());
        glib::spawn_future_local(async move {
            while let Ok((id, favorite, texture)) = rx.recv().await {
                if popover_for_load.parent().is_none() {
                    break;
                }
                let Some(texture) = texture else { continue };
                let picture = gtk::Picture::for_paintable(&texture);
                picture.set_size_request(64, 64);
                picture.set_content_fit(gtk::ContentFit::Contain);
                let button = gtk::Button::builder().child(&picture).build();
                button.add_css_class("flat");
                {
                    let (view, id, popover) = (view.clone(), id.clone(), popover_for_load.clone());
                    button.connect_clicked(move |_| {
                        popover.popdown();
                        view.send_sticker(&id);
                    });
                }
                let right = gtk::GestureClick::builder().button(gtk::gdk::BUTTON_SECONDARY).build();
                {
                    let (view, id, button_ref) = (view.clone(), id.clone(), button.clone());
                    let favorite = Rc::new(Cell::new(favorite));
                    right.connect_pressed(move |_, _, x, y| {
                        let (menu, items) = crate::ui::widgets::menu_popover();
                        menu.set_parent(&button_ref);
                        menu.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
                        menu.connect_closed(|menu| menu.unparent());
                        let fav = crate::ui::widgets::menu_item(
                            "starred-symbolic",
                            if favorite.get() { "Unfavorite" } else { "Favorite" },
                        );
                        {
                            let (id, favorite, menu, app) = (id.clone(), favorite.clone(), menu.clone(), view.app().clone());
                            fav.connect_clicked(move |_| {
                                menu.popdown();
                                let want = !favorite.get();
                                match core::set_sticker_favorite(&id, want) {
                                    // Shown first from the next opening on.
                                    Ok(()) => favorite.set(want),
                                    Err(error) => app.toast(&format!("Could not change the sticker: {}", error)),
                                }
                            });
                        }
                        let delete = crate::ui::widgets::menu_item("edit-delete-symbolic", "Delete");
                        delete.add_css_class("destructive-action");
                        items.append(&fav);
                        items.append(&delete);
                        let (id, button_ref, menu_ref) = (id.clone(), button_ref.clone(), menu.clone());
                        let app = view.app().clone();
                        delete.connect_clicked(move |_| {
                        menu_ref.popdown();
                        let (id, button_ref, app, owner) = (id.clone(), button_ref.clone(), app.clone(), app.clone());
                        dialogs::confirm(&owner, "Delete this sticker?", "It is removed from all your devices.", "Delete", true, move || {
                            let (id, button_ref, app) = (id.clone(), button_ref.clone(), app.clone());
                            app::run_in_background(
                                move || core::delete_sticker(&id),
                                move |result| match result {
                                    Ok(()) => button_ref.parent().unwrap_or_else(|| button_ref.clone().upcast()).set_visible(false),
                                    Err(error) => app.toast(&format!("Could not delete the sticker: {}", error)),
                                },
                            );
                        });
                        });
                        menu.popup();
                    });
                }
                button.add_controller(right);
                grid_for_load.append(&button);
            }
        });
        popover.popup();
    }

    pub(super) fn send_sticker(self: &Rc<Self>, sticker_id: &str) {
        let (target, group) = match &self.conversation {
            Conversation::Direct { fingerprint, .. } => (fingerprint.clone(), false),
            Conversation::Group { group_id, .. } => (group_id.clone(), true),
        };
        let reply = self.reply_to.borrow().clone();
        let id = sticker_id.to_string();
        let view = self.clone();
        app::run_in_background(
            move || core::send_sticker(&target, group, &id, reply),
            move |result| match result {
                Ok(_) => {
                    view.clear_reply();
                    view.reload();
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
        let dialog = gtk::FileDialog::builder().title("Add a sticker").filters(&filters).build();
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
