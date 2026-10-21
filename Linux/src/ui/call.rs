//! The call window — outgoing ring, incoming ring, in call; 1:1 and group,
//! voice and video. The desktop twin of Android `CallActivity`: all call state
//! lives in the core, this polls `core::call_state()` twice a second and
//! renders it, so there is no second state machine here to drift.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gdk, gio, glib};

use crate::app::{App, Event};
use crate::call_media::{CallMedia, Frame};
use crate::core::{self, CallState};
use crate::ui::window::Conversation;

thread_local! {
    /// At most one call at a time, like the core.
    static CURRENT: RefCell<Option<Rc<CallUi>>> = const { RefCell::new(None) };
}

struct Tile {
    root: gtk::Overlay,
    picture: gtk::Picture,
    name: gtk::Label,
    mic_off: gtk::Image,
    /// Shown instead of the picture while the camera is off (and in voice calls).
    avatar: adw::Avatar,
    peer: RefCell<String>,
}

struct CallUi {
    app: Rc<App>,
    window: adw::Window,
    title: gtk::Label,
    status: gtk::Label,
    grid: gtk::FlowBox,
    self_view: gtk::Picture,
    accept: gtk::Button,
    hangup: gtk::Button,
    mute: gtk::ToggleButton,
    camera: gtk::ToggleButton,
    tiles: RefCell<HashMap<u8, Tile>>,
    media: RefCell<Option<CallMedia>>,
    state: RefCell<String>,
    video: Cell<bool>,
    /// Our own call not created yet (start_call still in flight).
    starting: Cell<bool>,
    /// Saw a non-idle state once — only then does "idle" mean "ended".
    seen: Cell<bool>,
    closing: Cell<bool>,
    ring_beeps: Cell<u32>,
}

/// From a chat header: ring the peer or every member of the group.
pub fn place(app: &Rc<App>, conversation: &Conversation, video: bool) {
    if CURRENT.with(|c| c.borrow().is_some()) {
        app.toast("A call is already in progress");
        return;
    }
    let ui = CallUi::open(app, video);
    ui.starting.set(true);
    ui.status.set_text("Calling…");
    ui.title.set_text(&conversation.title());
    let target = conversation.clone();
    let weak = Rc::downgrade(&ui);
    glib::spawn_future_local(async move {
        let result = gio::spawn_blocking(move || match target {
            Conversation::Direct { fingerprint, .. } => core::start_call(&fingerprint, video),
            Conversation::Group { group_id, .. } => core::start_group_call(&group_id, video),
        })
        .await
        .unwrap_or_else(|_| Err("call failed".into()));
        let Some(ui) = weak.upgrade() else { return };
        ui.starting.set(false);
        if let Err(e) = result {
            ui.app.toast(&e);
            ui.close();
        }
    });
}

/// `"call"` events from the poll loop: an incoming invite opens the window.
pub fn on_event(app: &Rc<App>, event: &Event) {
    if event.string("action") != "invite" || CURRENT.with(|c| c.borrow().is_some()) {
        return;
    }
    let video = event.value.get("video").and_then(|v| v.as_bool()).unwrap_or(false);
    let ui = CallUi::open(app, video);
    let name = event.string("name");
    ui.title.set_text(&name);
    ui.status.set_text(if video { "Incoming video call" } else { "Incoming voice call" });
    // Same setting as message notifications: no caller name on a lock screen.
    let hide = app.prefs.borrow().hide_notification_content;
    let notification = gio::Notification::new(if hide { "Typeon" } else { name.as_str() });
    notification.set_body(Some(if video { "Incoming video call" } else { "Incoming voice call" }));
    notification.set_priority(gio::NotificationPriority::Urgent);
    app.application.send_notification(Some("call"), &notification);
}

impl CallUi {
    fn open(app: &Rc<App>, video: bool) -> Rc<Self> {
        install_css();
        let window = adw::Window::builder()
            .title("Call")
            .default_width(760)
            .default_height(560)
            .build();
        if let Some(parent) = app.window() {
            window.set_transient_for(Some(&parent));
        }
        window.add_css_class("call-window");

        let title = gtk::Label::new(None);
        title.add_css_class("title-1");
        let status = gtk::Label::new(None);
        status.add_css_class("dim-label");
        let header = gtk::Box::new(gtk::Orientation::Vertical, 4);
        header.set_margin_top(18);
        header.append(&title);
        header.append(&status);

        let grid = gtk::FlowBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .homogeneous(true)
            .min_children_per_line(1)
            .max_children_per_line(3)
            .row_spacing(8)
            .column_spacing(8)
            .vexpand(true)
            .hexpand(true)
            .build();
        let self_view = gtk::Picture::builder()
            .content_fit(gtk::ContentFit::Cover)
            .width_request(200)
            .height_request(150)
            .halign(gtk::Align::End)
            .valign(gtk::Align::End)
            .margin_end(12)
            .margin_bottom(12)
            .visible(false)
            .build();
        self_view.add_css_class("call-self");
        let stage = gtk::Overlay::new();
        stage.set_child(Some(&grid));
        stage.add_overlay(&self_view);
        stage.set_margin_start(12);
        stage.set_margin_end(12);
        stage.set_margin_top(12);

        let mute = gtk::ToggleButton::builder().icon_name("microphone-sensitivity-high-symbolic").tooltip_text("Mute").visible(false).build();
        let camera = gtk::ToggleButton::builder().icon_name("camera-video-symbolic").tooltip_text("Camera").active(true).visible(false).build();
        let accept = gtk::Button::builder().icon_name("call-start-symbolic").tooltip_text("Answer").visible(false).build();
        accept.add_css_class("call-accept");
        let hangup = gtk::Button::builder().icon_name("call-stop-symbolic").tooltip_text("Hang up").build();
        hangup.add_css_class("call-hangup");
        for b in [mute.upcast_ref::<gtk::Widget>(), camera.upcast_ref(), accept.upcast_ref(), hangup.upcast_ref()] {
            b.add_css_class("circular");
            b.add_css_class("call-button");
        }
        let controls = gtk::Box::new(gtk::Orientation::Horizontal, 18);
        controls.set_halign(gtk::Align::Center);
        controls.set_margin_top(12);
        controls.set_margin_bottom(18);
        controls.append(&mute);
        controls.append(&camera);
        controls.append(&accept);
        controls.append(&hangup);

        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        content.append(&adw::HeaderBar::builder().show_title(false).build());
        content.append(&header);
        content.append(&stage);
        content.append(&controls);
        window.set_content(Some(&content));

        let ui = Rc::new(CallUi {
            app: app.clone(),
            window,
            title,
            status,
            grid,
            self_view,
            accept,
            hangup,
            mute,
            camera,
            tiles: RefCell::new(HashMap::new()),
            media: RefCell::new(None),
            state: RefCell::new("idle".into()),
            video: Cell::new(video),
            starting: Cell::new(false),
            seen: Cell::new(false),
            closing: Cell::new(false),
            ring_beeps: Cell::new(0),
        });
        CURRENT.with(|c| *c.borrow_mut() = Some(ui.clone()));

        let weak = Rc::downgrade(&ui);
        ui.accept.connect_clicked(move |b| {
            b.set_sensitive(false);
            if weak.upgrade().is_some() {
                glib::spawn_future_local(async {
                    let _ = gio::spawn_blocking(core::accept_call).await;
                });
            }
        });
        let weak = Rc::downgrade(&ui);
        ui.hangup.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.hang_up();
            }
        });
        let weak = Rc::downgrade(&ui);
        ui.mute.connect_toggled(move |b| {
            let Some(ui) = weak.upgrade() else { return };
            if let Some(m) = ui.media.borrow().as_ref() {
                m.set_muted(b.is_active());
            }
            b.set_icon_name(if b.is_active() { "microphone-disabled-symbolic" } else { "microphone-sensitivity-high-symbolic" });
        });
        let weak = Rc::downgrade(&ui);
        ui.camera.connect_toggled(move |b| {
            let Some(ui) = weak.upgrade() else { return };
            if let Some(m) = ui.media.borrow().as_ref() {
                m.set_camera(b.is_active());
                b.set_active(m.camera_on());
            }
            ui.self_view.set_visible(b.is_active());
            b.set_icon_name(if b.is_active() { "camera-video-symbolic" } else { "camera-disabled-symbolic" });
        });
        // Closing the window any other way than Hang up must not leave a
        // zombie call ringing or holding the microphone on the other side.
        let weak = Rc::downgrade(&ui);
        ui.window.connect_close_request(move |_| {
            if let Some(ui) = weak.upgrade() {
                if !ui.closing.get() {
                    ui.hang_up();
                }
            }
            glib::Propagation::Proceed
        });

        let weak = Rc::downgrade(&ui);
        glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
            let Some(ui) = weak.upgrade() else { return glib::ControlFlow::Break };
            if ui.closing.get() {
                return glib::ControlFlow::Break;
            }
            let weak = Rc::downgrade(&ui);
            glib::spawn_future_local(async move {
                let Ok(state) = gio::spawn_blocking(core::call_state).await else { return };
                if let Some(ui) = weak.upgrade() {
                    ui.render(&state);
                }
            });
            glib::ControlFlow::Continue
        });
        ui.window.present();
        ui
    }

    fn render(self: &Rc<Self>, s: &CallState) {
        if self.closing.get() {
            return;
        }
        let new = if s.state.is_empty() { "idle" } else { s.state.as_str() };
        if new != "idle" {
            self.seen.set(true);
            if self.media.borrow().is_none() && !self.starting.get() {
                self.video.set(s.video);
            }
        }
        let old = self.state.replace(new.to_string());
        if old != new {
            self.on_state_changed(new, s);
        }
        if new == "idle" {
            return;
        }
        if !s.name.is_empty() {
            self.title.set_text(&s.name);
        }
        match new {
            "outgoing" => self.status.set_text("Calling…"),
            "incoming" => {
                self.status.set_text(if self.video.get() { "Incoming video call" } else { "Incoming voice call" });
                // No ringtone file in the runtime: the display bell, every 2 s.
                let n = self.ring_beeps.get() + 1;
                self.ring_beeps.set(n);
                if n % 4 == 1 {
                    gtk::prelude::WidgetExt::display(&self.window).beep();
                }
            }
            "active" => {
                let secs = s.now.saturating_sub(s.connected_at) / 1000;
                let path = match &s.media {
                    Some(m) if m.direct_links > 0 && m.via_direct > 0 => "peer-to-peer",
                    Some(m) if m.relay_links > 0 => "via server",
                    _ => "connecting",
                };
                self.status.set_text(&format!("{:02}:{:02} · {}", secs / 60, secs % 60, path));
                self.sync_tiles(s);
            }
            _ => {}
        }
        let incoming = new == "incoming";
        let active = new == "active";
        self.accept.set_visible(incoming);
        self.hangup.set_tooltip_text(Some(if incoming { "Decline" } else { "Hang up" }));
        self.mute.set_visible(active);
        self.camera.set_visible(active && self.video.get());
    }

    fn on_state_changed(self: &Rc<Self>, new: &str, s: &CallState) {
        match new {
            "active" => {
                self.app.application.withdraw_notification("call");
                self.start_media();
            }
            "idle" => {
                self.app.application.withdraw_notification("call");
                self.stop_media();
                if !self.seen.get() && self.starting.get() {
                    return; // our own call not created yet
                }
                self.status.set_text(match s.reason.as_str() {
                    "rejected" => "Declined",
                    "busy" => "Busy",
                    "no_answer" => "No answer",
                    "missed" => "Missed call",
                    _ => "Call ended",
                });
                self.accept.set_visible(false);
                let weak = Rc::downgrade(self);
                glib::timeout_add_local_once(std::time::Duration::from_millis(1500), move || {
                    if let Some(ui) = weak.upgrade() {
                        ui.close();
                    }
                });
            }
            _ => {}
        }
    }

    fn start_media(self: &Rc<Self>) {
        if self.media.borrow().is_some() {
            return;
        }
        let (tx, rx) = async_channel::bounded::<Frame>(8);
        match CallMedia::start(self.video.get(), tx) {
            Ok(media) => {
                self.self_view.set_visible(media.camera_on());
                self.camera.set_active(media.camera_on());
                *self.media.borrow_mut() = Some(media);
            }
            Err(e) => {
                self.app.toast(&format!("Audio/video unavailable: {e}"));
                return;
            }
        }
        let weak = Rc::downgrade(self);
        glib::spawn_future_local(async move {
            while let Ok(frame) = rx.recv().await {
                let Some(ui) = weak.upgrade() else { break };
                let bytes = glib::Bytes::from_owned(frame.rgba);
                let texture = gdk::MemoryTexture::new(
                    frame.width as i32,
                    frame.height as i32,
                    gdk::MemoryFormat::R8g8b8a8,
                    &bytes,
                    frame.stride,
                );
                match frame.slot {
                    None => ui.self_view.set_paintable(Some(&texture)),
                    Some(slot) => {
                        if let Some(tile) = ui.tiles.borrow().get(&slot) {
                            tile.picture.set_paintable(Some(&texture));
                        }
                    }
                }
            }
        });
    }

    fn stop_media(&self) {
        // H131/M147: dropping joins the media threads (the rx worker can sit
        // in a 200 ms `core::call_recv`, the audio/video senders in 100 ms
        // `try_pull_sample` polls), which froze the GTK thread through every
        // hangup and every remote end. `CallMedia` is plain `Send` data
        // (Arc + join handles + GStreamer objects), so hand the teardown to a
        // worker thread instead — the core owns the call state either way.
        if let Some(media) = self.media.borrow_mut().take() {
            std::thread::spawn(move || drop(media));
        }
        self.self_view.set_visible(false);
        for (_, tile) in self.tiles.borrow_mut().drain() {
            self.grid.remove(&tile.root);
        }
    }

    /// One tile per joined participant, keyed by media slot.
    fn sync_tiles(&self, s: &CallState) {
        let live: HashMap<u8, &core::CallParticipant> = s
            .participants
            .iter()
            .filter(|p| p.joined)
            .filter_map(|p| p.slot.map(|slot| (slot, p)))
            .collect();
        let mut tiles = self.tiles.borrow_mut();
        let gone: Vec<u8> = tiles.keys().filter(|k| !live.contains_key(k)).copied().collect();
        for slot in gone {
            if let Some(tile) = tiles.remove(&slot) {
                self.grid.remove(&tile.root);
            }
            if let Some(m) = self.media.borrow().as_ref() {
                m.drop_slot(slot);
            }
        }
        for (slot, p) in live {
            let tile = tiles.entry(slot).or_insert_with(|| {
                let tile = new_tile(self.video.get());
                self.grid.insert(&tile.root, -1);
                tile
            });
            tile.name.set_text(&p.name);
            // Muted participants get a mic-off icon before their name.
            tile.mic_off.set_visible(p.muted);
            let showing_video = self.video.get() && !p.video_off;
            tile.picture.set_visible(showing_video);
            tile.avatar.set_visible(!showing_video);
            if *tile.peer.borrow() != p.peer {
                *tile.peer.borrow_mut() = p.peer.clone();
                tile.avatar.set_text(Some(&p.name));
                let picture = self.app.contacts.borrow().iter()
                    .find(|c| c.active_device_fingerprint.as_deref().is_some_and(|f| f == p.peer || f == p.fp))
                    .and_then(|c| c.avatar_hex.as_deref().and_then(crate::util::texture_from_hex));
                tile.avatar.set_custom_image(picture.as_ref());
            }
        }
        // Accent frame around whoever is speaking.
        if let Some(m) = self.media.borrow().as_ref() {
            for (slot, tile) in tiles.iter() {
                if m.is_speaking(*slot) {
                    tile.root.add_css_class("call-speaking");
                } else {
                    tile.root.remove_css_class("call-speaking");
                }
            }
        }
        // Two or more remote people: a 2-wide grid rather than a tall column.
        self.grid.set_min_children_per_line(if tiles.len() >= 2 { 2 } else { 1 });
    }

    fn hang_up(self: &Rc<Self>) {
        glib::spawn_future_local(async {
            let _ = gio::spawn_blocking(core::end_call).await;
        });
        self.close();
    }

    fn close(&self) {
        if self.closing.replace(true) {
            return;
        }
        self.app.application.withdraw_notification("call");
        self.stop_media();
        self.window.close();
        CURRENT.with(|c| c.borrow_mut().take());
    }
}

fn new_tile(video: bool) -> Tile {
    let picture = gtk::Picture::builder()
        .content_fit(gtk::ContentFit::Contain)
        .hexpand(true)
        .vexpand(true)
        .visible(video)
        .build();
    let name = gtk::Label::new(None);
    name.add_css_class(if video { "heading" } else { "title-2" });
    let mic_off = gtk::Image::from_icon_name("microphone-disabled-symbolic");
    mic_off.set_visible(false);
    let label = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    label.append(&mic_off);
    label.append(&name);
    label.add_css_class("call-label");
    if video {
        label.set_halign(gtk::Align::Start);
        label.set_valign(gtk::Align::End);
        label.set_margin_start(10);
        label.set_margin_bottom(10);
    } else {
        // Below the profile picture, which sits in the middle of the tile.
        label.set_halign(gtk::Align::Center);
        label.set_valign(gtk::Align::End);
        label.set_margin_bottom(10);
    }
    let backdrop = gtk::Box::new(gtk::Orientation::Vertical, 0);
    backdrop.append(&picture);
    let avatar = adw::Avatar::new(112, None, true);
    avatar.set_halign(gtk::Align::Center);
    avatar.set_valign(gtk::Align::Center);
    avatar.set_visible(!video);
    let root = gtk::Overlay::new();
    root.set_child(Some(&backdrop));
    root.add_overlay(&avatar);
    root.add_overlay(&label);
    root.add_css_class("call-tile");
    root.set_size_request(240, 180);
    Tile { root, picture, name, mic_off, avatar, peer: RefCell::new(String::new()) }
}

fn install_css() {
    thread_local!(static DONE: Cell<bool> = const { Cell::new(false) });
    if DONE.with(|d| d.replace(true)) {
        return;
    }
    let css = gtk::CssProvider::new();
    css.load_from_data(
        ".call-tile { background: #18181c; border-radius: 12px; }
         .call-tile.call-speaking { box-shadow: inset 0 0 0 3px @accent_bg_color; }
         .call-self { border-radius: 10px; }
         .call-label { color: white; background: alpha(black, 0.45); border-radius: 8px; padding: 4px 10px; }
         .call-button { min-width: 56px; min-height: 56px; }
         .call-accept { background: #2ea043; color: white; }
         .call-hangup { background: #d32f2f; color: white; }",
    );
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(&display, &css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
    }
}
