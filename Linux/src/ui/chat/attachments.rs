//! Attachment bubbles: files, stickers, voice player, downloads, overview.

use super::*;

impl ChatView {
    /// Returns the attachment block plus the live state later `file_*`
    /// events and click handlers need. Voice messages (an audio MIME type)
    /// get an inline play/pause + seek player, matching the Android voice
    /// bubble; everything else gets a generic file card.
    pub(super) fn build_attachment(self: &Rc<Self>, attachment: &Attachment) -> (gtk::Box, Rc<AttachmentState>) {
        // Only an actual voice message gets the inline player. A plain audio
        // FILE the user attached from their file manager has no duration, and
        // rendering it as a player produced a bubble with no filename, no
        // size and an empty label — the recipient could not even tell what it
        // was. The sender puts `duration_ms` in the FileOffer for real voice
        // notes, so this still shows the player for one that has not been
        // downloaded yet.
        if attachment.sticker {
            self.build_sticker(attachment)
        } else if util::is_audio(&attachment.mime) && attachment.duration_ms.unwrap_or(0) > 0 {
            self.build_voice_player(attachment)
        } else {
            self.build_generic_attachment(attachment)
        }
    }

    /// A sticker: just the picture, no name, size or button (it downloads
    /// on its own). An animated one plays through `load_sticker`.
    pub(super) fn build_sticker(self: &Rc<Self>, attachment: &Attachment) -> (gtk::Box, Rc<AttachmentState>) {
        let block = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let picture = gtk::Picture::new();
        picture.set_size_request(160, 160);
        picture.set_content_fit(gtk::ContentFit::Contain);
        picture.add_css_class("sticker");
        // A Picture asks for its image's own size (up to 600 px): capped.
        block.append(&adw::Clamp::builder().maximum_size(160).tightening_threshold(160).child(&picture).build());
        let state = Rc::new(AttachmentState {
            file_id: attachment.file_id.clone(),
            file_name: attachment.file_name.clone(),
            mime: attachment.mime.clone(),
            total_size: attachment.total_size,
            source_fingerprint: attachment.source_fingerprint.clone(),
            status: RefCell::new(attachment.status.clone()),
            bytes_done: Cell::new(attachment.bytes_done),
            download_started_at: Cell::new(0),
            status_label: None,
            progress: None,
            eta: None,
            action: None,
            voice: None,
            sticker: Some(picture),
        });
        if attachment.status == "complete" {
            load_sticker(&state);
        }
        // An offered or failed sticker (download cap, failure, eviction)
        // downloads on click; otherwise it would stay blank forever.
        let click = gtk::GestureClick::new();
        let view = self.clone();
        let click_state = state.clone();
        click.connect_released(move |_, _, _, _| {
            let status = click_state.status.borrow().clone();
            if status != "complete" && status != "downloading" {
                view.start_download(&click_state, None);
            }
        });
        block.add_controller(click);
        (block, state)
    }

    pub(super) fn build_generic_attachment(self: &Rc<Self>, attachment: &Attachment) -> (gtk::Box, Rc<AttachmentState>) {
        let block = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .build();

        // A preview thumbnail is shipped with the offer, so a photo is visible
        // before anyone downloads anything.
        if let Some(texture) = attachment
            .preview_hex
            .as_deref()
            .and_then(util::texture_from_hex)
        {
            let image = gtk::Picture::for_paintable(&texture);
            image.set_size_request(240, 180);
            image.set_content_fit(gtk::ContentFit::Cover);
            image.add_css_class("attachment-preview");
            block.append(&image);
        }

        let display_name = if attachment.file_name.is_empty() {
            util::attachment_label(&attachment.mime, "", false)
        } else {
            attachment.file_name.clone()
        };
        let name = gtk::Label::builder()
            .label(display_name.as_str())
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::Middle)
            .max_width_chars(34)
            .build();
        block.append(&name);

        let status_label = gtk::Label::builder()
            .label(attachment_status_text(attachment).as_str())
            .xalign(0.0)
            .build();
        status_label.add_css_class("caption");
        block.append(&status_label);

        let progress = gtk::ProgressBar::new();
        progress.set_visible(attachment.status == "downloading");
        if attachment.total_size > 0 {
            progress.set_fraction(attachment.bytes_done as f64 / attachment.total_size as f64);
        }
        block.append(&progress);

        // Hidden until there is enough data to estimate a rate from — see
        // `util::format_eta` — rather than flashing a misleading "0s left".
        let eta = gtk::Label::new(None);
        eta.add_css_class("caption");
        eta.add_css_class("dim-label");
        eta.set_visible(false);
        block.append(&eta);

        let action = gtk::Button::builder()
            .label(action_label(&attachment.status, attachment.bytes_done).as_str())
            .halign(gtk::Align::Start)
            .build();
        action.set_visible(attachment.status != "downloading");
        block.append(&action);

        let state = Rc::new(AttachmentState {
            file_id: attachment.file_id.clone(),
            file_name: attachment.file_name.clone(),
            mime: attachment.mime.clone(),
            total_size: attachment.total_size,
            source_fingerprint: attachment.source_fingerprint.clone(),
            status: RefCell::new(attachment.status.clone()),
            bytes_done: Cell::new(attachment.bytes_done),
            download_started_at: Cell::new(0),
            status_label: Some(status_label),
            progress: Some(progress),
            eta: Some(eta),
            action: Some(action.clone()),
            voice: None,
            sticker: None,
        });

        {
            let view = self.clone();
            let state = state.clone();
            action.connect_clicked(move |button| view.attachment_action(&state, button));
        }

        (block, state)
    }

    /// An inline voice-message player: a play/pause button plus a seek scale
    /// that doubles as a download-progress bar before the file is here.
    pub(super) fn build_voice_player(self: &Rc<Self>, attachment: &Attachment) -> (gtk::Box, Rc<AttachmentState>) {
        let block = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(10)
            .build();

        let play_button = gtk::Button::builder()
            .icon_name("media-playback-start-symbolic")
            .valign(gtk::Align::Center)
            .build();
        play_button.add_css_class("flat");
        play_button.add_css_class("circular");

        let column = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .hexpand(true)
            .valign(gtk::Align::Center)
            .build();

        // `hexpand` alone only means "take extra space if any is going" — it
        // does not make the *bubble itself* wide. `place_bubble`'s clamp sizes
        // to the content's natural width, and a `GtkScale` with nothing else
        // in the row demanding room has a natural width close to zero, so the
        // whole bubble (and the slider inside it) rendered tiny. It also
        // tripped a GTK warning ("slider reported min height/width -2, but
        // sizes must be >= 0") — a near-zero allocation is exactly the
        // pathological case where GTK's own min-size arithmetic for the
        // slider handle underflows. A concrete minimum width fixes both.
        let slider = gtk::Scale::builder()
            .orientation(gtk::Orientation::Horizontal)
            .hexpand(true)
            .width_request(180)
            .draw_value(false)
            .build();

        let duration_label = gtk::Label::builder().xalign(0.0).build();
        duration_label.add_css_class("caption");
        duration_label.add_css_class("dim-label");

        column.append(&slider);
        column.append(&duration_label);
        block.append(&play_button);
        block.append(&column);

        let state = Rc::new(AttachmentState {
            file_id: attachment.file_id.clone(),
            file_name: attachment.file_name.clone(),
            mime: attachment.mime.clone(),
            total_size: attachment.total_size,
            source_fingerprint: attachment.source_fingerprint.clone(),
            status: RefCell::new(attachment.status.clone()),
            bytes_done: Cell::new(attachment.bytes_done),
            download_started_at: Cell::new(0),
            status_label: None,
            progress: None,
            eta: None,
            action: None,
            voice: Some(VoicePlayer {
                play_button: play_button.clone(),
                slider: slider.clone(),
                duration_label,
                media: RefCell::new(None),
                duration_ms: Cell::new(attachment.duration_ms.unwrap_or(0)),
            }),
            sticker: None,
        });
        render_voice_state(&state);

        {
            let view = self.clone();
            let state = state.clone();
            play_button.connect_clicked(move |_| view.voice_play_clicked(&state));
        }
        {
            let view = self.clone();
            let state = state.clone();
            slider.connect_change_value(move |_, _, value| {
                view.voice_seek(&state, value);
                glib::Propagation::Proceed
            });
        }

        (block, state)
    }

    /// Download when it is not here yet, open when it is. `state` is shared
    /// with the widgets `file_*` events update, so this always sees the
    /// attachment's current status rather than a stale build-time snapshot.
    pub(super) fn attachment_action(self: &Rc<Self>, state: &Rc<AttachmentState>, button: &gtk::Button) {
        if *state.status.borrow() == "complete" {
            self.open_attachment(state);
            return;
        }
        self.start_download(state, Some(button.clone()));
    }

    pub(super) fn open_attachment(self: &Rc<Self>, state: &Rc<AttachmentState>) {
        let app = self.app().clone();
        let file_id = state.file_id.clone();
        let mime = state.mime.clone();
        let name = if state.file_name.is_empty() {
            util::attachment_label(&state.mime, "", false)
        } else {
            state.file_name.clone()
        };
        // Decryption copies the whole file, so it must not run on the main
        // thread — a large video would freeze the window outright.
        app::run_in_background(
            move || core::attachment_plaintext_path(&file_id),
            move |result| match result {
                Ok(path) => crate::ui::media::open(&app, &path, &mime, &name),
                Err(error) => app.toast(&tf!("Could not open the file: {}", error)),
            },
        );
    }

        /// Starts a download from the core. `core::download_file` takes the global core mutex, which the poll thread can hold for
        /// seconds. So the inline call used to freeze the whole window (and every voice player with it) whenever the poller was in
        /// the middle of a round. The work closure carries only Send data. The widget state is touched only in `then`, which
        /// `run_in_background` runs back on the GTK thread. `hide_on_start` (the generic card's "Download" button) is hidden only on
        /// a confirmed start. A failed start leaves the button visible, so there is still a way to retry.
    pub(super) fn start_download(self: &Rc<Self>, state: &Rc<AttachmentState>, hide_on_start: Option<gtk::Button>) {
        state.download_started_at.set(util::now_ms());
        let file_id = state.file_id.clone();
        let source_fingerprint = state.source_fingerprint.clone();
        let view = self.clone();
        let state = state.clone();
        crate::app::run_in_background(
            move || core::download_file(&file_id, &source_fingerprint),
            move |result| match result {
                Ok(()) => {
                    // The file finished while the start was in flight: keep its complete state.
                    if *state.status.borrow() == "complete" {
                        return;
                    }
                    if let Some(button) = &hide_on_start {
                        button.set_visible(false);
                    }
                    *state.status.borrow_mut() = "downloading".to_string();
                    if let Some(status) = &state.status_label {
                        status.set_label(t("Downloading…"));
                    }
                    if let Some(progress) = &state.progress {
                        progress.set_visible(true);
                    }
                    render_voice_state(&state);
                }
                // A failed start emits no events at all, so the caller must
                // reflect that immediately or the row spins forever.
                Err(error) => {
                    state.download_started_at.set(0);
                    view.app().toast(&tf!("Download failed: {}", error));
                }
            },
        );
    }

    /// Play/pause a voice message, downloading it first if it is not here yet.
    pub(super) fn voice_play_clicked(self: &Rc<Self>, state: &Rc<AttachmentState>) {
        if *state.status.borrow() != "complete" {
            self.start_download(state, None);
            return;
        }
        let Some(voice) = &state.voice else { return };
        if let Some(media) = voice.media.borrow().clone() {
            media.set_playing(!media.is_playing());
            return;
        }

        // Not loaded yet: only one voice message plays at a time (matching
        // Android), so pause whatever else is going before decrypting this
        // one — decryption happens off the main thread since it copies the
        // whole file.
        self.pause_other_voices(&state.file_id);
        let view = self.clone();
        let file_id = state.file_id.clone();
        let state = state.clone();
        app::run_in_background(
            move || core::attachment_plaintext_path(&file_id),
            move |result| match result {
                Ok(path) => view.start_voice_playback(&state, &path),
                Err(error) => view.app().toast(&tf!("Could not play the voice message: {}", error)),
            },
        );
    }

    pub(super) fn pause_other_voices(&self, except_file_id: &str) {
        for bubble in self.bubbles.borrow().values() {
            let Some(state) = &bubble.attachment else { continue };
            if state.file_id == except_file_id {
                continue;
            }
            if let Some(voice) = &state.voice {
                if let Some(media) = voice.media.borrow().as_ref() {
                    if media.is_playing() {
                        media.pause();
                    }
                }
            }
        }
    }

    /// Seeking an unplayed slider is a no-op — pressing play first is the one
    /// extra step this leaves on the table (see `VoicePlayer::media` doc).
    pub(super) fn voice_seek(&self, state: &Rc<AttachmentState>, position: f64) {
        let Some(voice) = &state.voice else { return };
        if let Some(media) = voice.media.borrow().as_ref() {
            media.seek(position.max(0.0) as i64);
        }
    }

    /// Creates the `GtkMediaFile` for a just-decrypted voice message and wires
    /// its notify signals to the slider/label/play-button, the same pattern
    /// the in-app video/audio viewer's transport bar uses.
    pub(super) fn start_voice_playback(self: &Rc<Self>, state: &Rc<AttachmentState>, path: &str) {
        let Some(voice) = &state.voice else { return };
        if !crate::ui::media::playable_media(path) {
            self.app().toast(t("This voice message is not a playable audio file"));
            return;
        }
        let media = gtk::MediaFile::for_filename(path);

        {
            let button = voice.play_button.clone();
            media.connect_playing_notify(move |media| {
                button.set_icon_name(if media.is_playing() {
                    "media-playback-pause-symbolic"
                } else {
                    "media-playback-start-symbolic"
                });
            });
        }
        {
            let slider = voice.slider.clone();
            media.connect_duration_notify(move |media| {
                slider.set_range(0.0, (media.duration().max(0) as f64).max(1.0));
            });
        }
        {
            let slider = voice.slider.clone();
            let label = voice.duration_label.clone();
            media.connect_timestamp_notify(move |media| {
                let timestamp = media.timestamp().max(0);
                slider.set_value(timestamp as f64);
                let duration = media.duration().max(0);
                label.set_label(&util::format_duration_us((duration - timestamp).max(0)));
            });
        }
        {
            let app = self.app().clone();
            media.connect_error_notify(move |media| {
                if media.error().is_some() {
                    app.toast(t("Could not play the voice message."));
                }
            });
        }

        media.set_playing(true);
        *voice.media.borrow_mut() = Some(media);
    }

}

impl ChatView {
    pub(super) fn apply_progress(&self, file_id: &str, done: u64, total: u64) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(file_id) else { return };
        let Some(state) = &bubble.attachment else { return };

        state.bytes_done.set(done);
        if state.download_started_at.get() == 0 {
            state.download_started_at.set(util::now_ms());
        }

        if let Some(voice) = &state.voice {
            // Before completion the slider doubles as a download-progress
            // bar; once complete it means something else (playback position)
            // and progress events stop arriving for it anyway.
            if *state.status.borrow() != "complete" {
                voice.slider.set_range(0.0, total.max(1) as f64);
                voice.slider.set_value(done as f64);
            }
            return;
        }

        if let Some(progress) = &state.progress {
            progress.set_visible(true);
            if total > 0 {
                progress.set_fraction(done as f64 / total as f64);
            }
        }
        if let Some(status) = &state.status_label {
            status.set_label(&tf!(
                "{} of {}",
                util::human_size(done),
                util::human_size(total)
            ));
        }
        if let Some(eta) = &state.eta {
            match util::format_eta(state.download_started_at.get(), done, total) {
                Some(text) => {
                    eta.set_label(&text);
                    eta.set_visible(true);
                }
                None => eta.set_visible(false),
            }
        }
        if let Some(action) = &state.action {
            action.set_visible(false);
        }
    }

    pub(super) fn apply_attachment_state(&self, file_id: &str, new_status: &str, detail: Option<String>) {
        let bubbles = self.bubbles.borrow();
        let Some(bubble) = bubbles.get(file_id) else { return };
        let Some(state) = &bubble.attachment else { return };

        *state.status.borrow_mut() = new_status.to_string();
        // A retry after a failure (or of a stalled download) starts its own
        // fresh ETA measurement rather than inheriting the last attempt's.
        if new_status != "downloading" {
            state.download_started_at.set(0);
        }

        if state.voice.is_some() {
            render_voice_state(state);
            return;
        }
        if state.sticker.is_some() {
            if new_status == "complete" {
                load_sticker(state);
            } else if new_status == "offered" || new_status == "failed" {
                // Evicted or failed: no stale picture.
                if let Some(picture) = &state.sticker {
                    picture.set_filename(None::<&str>);
                }
            }
            return;
        }

        if let Some(progress) = &state.progress {
            progress.set_visible(false);
        }
        if let Some(eta) = &state.eta {
            eta.set_visible(false);
        }
        if let Some(status) = &state.status_label {
            status.set_label(&match (new_status, detail) {
                ("complete", _) => t("Downloaded").to_string(),
                ("failed", Some(reason)) => tf!("Failed: {}", reason),
                ("failed", None) => t("Failed").to_string(),
                (other, _) => other.to_string(),
            });
        }
        if let Some(action) = &state.action {
            action.set_visible(true);
            action.set_label(&action_label(new_status, state.bytes_done.get()));
        }
    }

}

pub(super) fn attachments_overview(view: &Rc<ChatView>) {
    let Some(window) = view.app().window() else { return };
    let conversation = view.conversation.clone();
    let window = window.clone();

    // The attachment listing is a core query — off the GTK thread, like every
    // core call here. The window itself is built when the rows come back.
    app::run_in_background(
        move || match &conversation {
            Conversation::Direct { fingerprint, .. } => core::list_attachments(fingerprint),
            Conversation::Group { group_id, .. } => core::list_group_attachments(group_id),
        },
        move |attachments| {
            let group = adw::PreferencesGroup::builder()
                .title(t("Files in this conversation"))
                .build();
            if attachments.is_empty() {
                group.add(&adw::ActionRow::builder().title(t("Nothing shared yet")).build());
            }
            for attachment in attachments {
                let subtitle = format!(
                    "{} · {} · {}",
                    util::human_size(attachment.total_size),
                    match attachment.status.as_str() {
                        "offered" => t("offered"),
                        "downloading" => t("downloading"),
                        "complete" => t("complete"),
                        "failed" => t("failed"),
                        other => other,
                    },
                    util::format_list_time(attachment.created_at)
                );
                group.add(
                    &adw::ActionRow::builder()
                        .title(glib::markup_escape_text(&attachment.file_name).as_str())
                        .subtitle(subtitle.as_str())
                        .build(),
                );
            }

            let page = adw::PreferencesPage::new();
            page.add(&group);
            let toolbar = adw::ToolbarView::new();
            toolbar.add_top_bar(&adw::HeaderBar::new());
            toolbar.set_content(Some(&page));

            adw::Window::builder()
                .modal(true)
                .transient_for(&window)
                .title(t("Attachments"))
                .default_width(480)
                .default_height(480)
                .content(&toolbar)
                .build()
                .present();
        },
    );
}

pub(super) fn attachment_status_text(attachment: &Attachment) -> String {
    match attachment.status.as_str() {
        "offered" => util::human_size(attachment.total_size),
        "downloading" => tf!(
            "{} of {}",
            util::human_size(attachment.bytes_done),
            util::human_size(attachment.total_size)
        ),
        "complete" => tf!("{} · downloaded", util::human_size(attachment.total_size)),
        "failed" => t("Failed").to_string(),
        other => other.to_string(),
    }
}

/// The label of an attachment's action button.
/// A download that already moved some bytes is RESUMED, not started over. The core keeps `bytes_transferred` and continues
/// from there (see `Attachment.bytes_done`), so the button says so.
pub(super) fn action_label(status: &str, bytes_done: u64) -> String {
    match status {
        "complete" => t("Open").to_string(),
        "failed" if bytes_done > 0 => t("Resume").to_string(),
        "failed" => t("Retry").to_string(),
        _ => t("Download").to_string(),
    }
}

/// Redraws a voice player's slider/label/play-icon for its current status —
/// shared by the initial build and every later status change so they cannot
/// drift apart. Only handles the *static* pre-/post-playback presentation;
/// once a `GtkMediaFile` exists, its own notify signals (wired in
/// `ChatView::start_voice_playback`) own the slider and label instead.
pub(super) fn render_voice_state(state: &AttachmentState) {
    let Some(voice) = &state.voice else { return };
    let status = state.status.borrow().clone();
    if status == "complete" {
        voice.slider.set_sensitive(true);
        // Slider unit is microseconds, like `GtkMediaFile` timestamps/seek.
        let duration = voice.duration_ms.get().max(1) as f64 * 1000.0;
        voice.slider.set_range(0.0, duration);
        voice.slider.set_value(0.0);
        voice.play_button.set_icon_name("media-playback-start-symbolic");
        voice.duration_label.set_label(&util::format_duration_ms(voice.duration_ms.get() as i64));
    } else {
        voice.slider.set_sensitive(false);
        voice.slider.set_range(0.0, state.total_size.max(1) as f64);
        voice.slider.set_value(if status == "downloading" {
            state.bytes_done.get() as f64
        } else {
            0.0
        });
        voice.play_button.set_icon_name("media-playback-start-symbolic");
        voice.duration_label.set_label(&match status.as_str() {
            "failed" => t("Failed").to_string(),
            "downloading" => t("Downloading…").to_string(),
            _ => {
                let ms = voice.duration_ms.get();
                if ms > 0 {
                    util::format_duration_ms(ms as i64)
                } else {
                    String::new()
                }
            }
        });
    }
}

/// Shows a downloaded sticker. Frames are decoded off the GTK thread (a big
/// animated sticker froze the window); an animated one plays three times and
/// stops on its last frame, as on Android (a looping sticker kept the whole
/// chat redrawing).
pub(super) fn load_sticker(state: &Rc<AttachmentState>) {
    let Some(picture) = state.sticker.clone() else { return };
    let file_id = state.file_id.clone();
    // One decode at a time: an animated sticker's frames are up to ~140 MB
    // of RGBA, and a chat full of them decoded all at once.
    // ponytail: frames kept at full size (600 px) while shown at 160 px.
    type Job = Box<dyn FnOnce() + Send>;
    static TX: std::sync::OnceLock<std::sync::mpsc::Sender<Job>> = std::sync::OnceLock::new();
    let queue = TX.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        std::thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                job();
            }
        });
        tx
    });
    let (tx, rx) = async_channel::bounded(1);
    let _ = queue.send(Box::new(move || {
        let _ = tx.send_blocking(sticker_frames(&file_id));
    }));
    glib::spawn_future_local(async move {
        if let Ok(frames) = rx.recv().await {
            play_sticker(picture, frames);
        }
    });
}

/// Largest still sticker decoded (a 2048 x 2048 canvas, 16 MB of RGBA).
const MAX_STICKER_PIXELS: i64 = 2048 * 2048;

/// The sticker's frames as textures with their durations in ms.
pub(super) fn sticker_frames(file_id: &str) -> Vec<(gtk::gdk::Texture, u32)> {
    use gtk::gdk;
    match core::attachment_jxl_frames(file_id) {
        Ok((width, height, frames)) => frames
            .into_iter()
            .map(|(rgba, ms)| {
                let texture = gdk::MemoryTexture::new(
                    width as i32,
                    height as i32,
                    gdk::MemoryFormat::R8g8b8a8,
                    &glib::Bytes::from_owned(rgba),
                    width as usize * 4,
                );
                (texture.upcast(), ms)
            })
            .collect(),
        // Not a JPEG XL (an older sticker): one still picture. The file is
        // the sender's: a common format and a sticker-sized canvas only, read
        // from the header before anything is decoded.
        Err(_) => core::attachment_plaintext_path(file_id)
            .ok()
            .filter(|path| {
                crate::ui::media::image_ok(path)
                    .is_some_and(|(w, h)| i64::from(w) * i64::from(h) <= MAX_STICKER_PIXELS)
            })
            .and_then(|path| gdk::Texture::from_filename(path).ok())
            .map(|texture| vec![(texture, 0)])
            .unwrap_or_default(),
    }
}

pub(super) const STICKER_PLAYS: usize = 3;

pub(super) fn play_sticker(picture: gtk::Picture, frames: Vec<(gtk::gdk::Texture, u32)>) {
    fn step(picture: gtk::Picture, frames: Rc<Vec<(gtk::gdk::Texture, u32)>>, i: usize) {
        let (texture, ms) = &frames[i % frames.len()];
        picture.set_paintable(Some(texture));
        if i + 1 >= frames.len() * STICKER_PLAYS {
            return; // the frames go; the picture keeps the last one
        }
        let delay = std::time::Duration::from_millis(u64::from((*ms).max(20)));
        glib::timeout_add_local_once(delay, move || step(picture, frames, i + 1));
    }
    if !frames.is_empty() {
        step(picture, Rc::new(frames), 0);
    }
}
