//! Disappearing messages on the desktop: the chat's disappearing mode (header clock button), the pulsing accent edge, the time-left
//! line and the slide-out when the time is up. While the mode is on, everything sent in the chat (text, files, voice, stickers)
//! carries the timer; the core stamps it. The core keeps its own clock for the archive (`expire_due`); this file only draws.
//! A received message counts down from when it is on screen here, never from when it was sent, so a late delivery does not
//! shorten it.

use super::*;

/// The timer choices, in seconds, with their labels (the same stops as the phone).
const DISAPPEAR_STOPS: [(u32, &str); 7] = [
    (30, "30 seconds"),
    (5 * 60, "5 minutes"),
    (3600, "1 hour"),
    (8 * 3600, "8 hours"),
    (24 * 3600, "1 day"),
    (7 * 24 * 3600, "1 week"),
    (28 * 24 * 3600, "4 weeks"),
];
/// Steps of the edge pulse; theme.rs has a `dpulse-N` class for each.
pub(crate) const DISAPPEAR_PULSE_STEPS: i32 = 8;

thread_local! {
    /// The stop picked last, offered first next time.
    static LAST_STOP: Cell<usize> = const { Cell::new(2) };
}

/// `(timer seconds, expiry ms)` of a live message event; None for an ordinary message.
pub(super) fn event_expiry(event: &Event) -> Option<(u32, u64)> {
    let secs = u32::try_from(event.number("expire_secs")).ok().filter(|s| *s > 0)?;
    let at = nonzero_or(event.number("expire_at_ms"), util::now_ms() + secs as u64 * 1000);
    Some((secs, at))
}

/// Time left, never more than the timer: a received message not on screen yet holds a later cap (see the core's `first_expiry`).
fn left_ms((secs, at): (u32, u64), now: u64) -> u64 {
    at.saturating_sub(now).min(secs as u64 * 1000)
}

/// "42 s", "12 min", "5 h", "3 days", rounded up.
pub(super) fn format_left(ms: u64) -> String {
    let s = ms.div_ceil(1000);
    match s {
        0..=59 => format!("⏱ {s} s"),
        60..=3599 => format!("⏱ {} min", s.div_ceil(60)),
        3600..=86_399 => format!("⏱ {} h", s.div_ceil(3600)),
        _ => format!("⏱ {} days", s.div_ceil(86_400)),
    }
}

/// The time-left line of a new disappearing bubble.
pub(super) fn expire_label(entry: &Entry) -> Option<gtk::Label> {
    let expire = entry.expire.filter(|_| !entry.deleted)?;
    let label = gtk::Label::builder()
        .label(format_left(left_ms(expire, util::now_ms())).as_str())
        .xalign(if entry.mine { 1.0 } else { 0.0 })
        .build();
    label.add_css_class("caption");
    label.add_css_class("disappear-time");
    Some(label)
}

/// Loads the chat's mode, so the Send button shows it from the start.
pub(super) fn load_disappear_mode(view: &Rc<ChatView>) {
    let weak = Rc::downgrade(view);
    let (peer, group) = view.chat_keys();
    app::run_in_background(
        move || core::disappear_mode(&peer, &group),
        move |secs| {
            if let Some(view) = weak.upgrade() {
                view.disappear_mode.set(secs);
                show_mode(&view.send_button, secs);
            }
        },
    );
}

/// The chat header's clock: turns the mode off at once when it is on, else opens the disappearing-mode picker.
pub(super) fn disappear_button(view: &Rc<ChatView>) -> gtk::Button {
    let button = gtk::Button::builder().icon_name("alarm-symbolic").tooltip_text("Disappearing messages").build();
    let view = Rc::downgrade(view);
    button.connect_clicked(move |button| {
        let Some(view) = view.upgrade() else { return };
        if view.disappear_mode.get() > 0 {
            view.set_disappear_mode(0);
            view.app().toast("Disappearing messages off");
        } else {
            view.pick_disappear_mode(button);
        }
    });
    button
}

/// The Send button tells whether the chat's messages disappear.
fn show_mode(button: &gtk::Button, secs: u32) {
    match DISAPPEAR_STOPS.iter().find(|(s, _)| *s == secs) {
        Some((_, label)) => {
            button.set_icon_name("alarm-symbolic");
            button.set_tooltip_text(Some(&format!("Send · disappears {label} after it is read")));
        }
        None => {
            button.set_icon_name("document-send-symbolic");
            button.set_tooltip_text(Some("Send"));
        }
    }
}

impl ChatView {
    /// `(peer fingerprint, group id)` as the core takes them: one of the two is empty.
    pub(super) fn chat_keys(&self) -> (String, String) {
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => (fingerprint.clone(), String::new()),
            Conversation::Group { group_id, .. } => (String::new(), group_id.clone()),
        }
    }

    /// Sets the chat's mode (0 = off). Turned on with text typed: that goes out now, disappearing.
    fn set_disappear_mode(self: &Rc<Self>, secs: u32) {
        self.disappear_mode.set(secs);
        show_mode(&self.send_button, secs);
        let (peer, group) = self.chat_keys();
        bg_serial(move || core::set_disappear_mode(&peer, &group, secs));
        if secs > 0 && self.composer.buffer().char_count() > 0 {
            self.send();
        }
    }

    /// The picker (mode off only, see `disappear_button`): a slider over `DISAPPEAR_STOPS`, Turn on (and send what is typed).
    fn pick_disappear_mode(self: &Rc<Self>, anchor: &gtk::Button) {
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(8)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(8)
            .margin_end(8)
            .width_request(280)
            .build();
        let title = gtk::Label::builder().label("Disappearing messages").xalign(0.0).build();
        title.add_css_class("heading");
        let stop = LAST_STOP.with(Cell::get).min(DISAPPEAR_STOPS.len() - 1);
        let value = gtk::Label::builder().label(DISAPPEAR_STOPS[stop].1).xalign(0.0).build();
        value.add_css_class("disappear-time");
        let scale = gtk::Scale::with_range(gtk::Orientation::Horizontal, 0.0, (DISAPPEAR_STOPS.len() - 1) as f64, 1.0);
        scale.set_draw_value(false);
        scale.set_round_digits(0);
        for i in 0..DISAPPEAR_STOPS.len() {
            scale.add_mark(i as f64, gtk::PositionType::Bottom, None);
        }
        scale.set_value(stop as f64);
        {
            let value = value.clone();
            scale.connect_value_changed(move |scale| {
                let i = (scale.value().round() as usize).min(DISAPPEAR_STOPS.len() - 1);
                value.set_label(DISAPPEAR_STOPS[i].1);
            });
        }
        let hint = gtk::Label::builder()
            .label("Everything you send in this chat disappears after it is read. It can't be copied or forwarded. Desktops show only a placeholder: it is read on the phone.")
            .xalign(0.0)
            .wrap(true)
            .max_width_chars(36)
            .build();
        hint.add_css_class("caption");
        hint.add_css_class("dim-label");
        let buttons = gtk::Box::builder().spacing(6).halign(gtk::Align::End).build();
        let on = gtk::Button::builder().label("Turn on").build();
        on.add_css_class("suggested-action");
        buttons.append(&on);
        content.append(&title);
        content.append(&value);
        content.append(&scale);
        content.append(&hint);
        content.append(&buttons);

        let popover = gtk::Popover::builder().child(&content).build();
        popover.set_parent(anchor);
        popover.connect_closed(|popover| {
            let popover = popover.clone();
            glib::idle_add_local_once(move || popover.unparent());
        });
        {
            let (view, popover, scale) = (Rc::downgrade(self), popover.downgrade(), scale.clone());
            on.connect_clicked(move |_| {
                let i = (scale.value().round() as usize).min(DISAPPEAR_STOPS.len() - 1);
                LAST_STOP.with(|last| last.set(i));
                if let Some(popover) = popover.upgrade() {
                    popover.popdown();
                }
                if let Some(view) = view.upgrade() {
                    view.set_disappear_mode(DISAPPEAR_STOPS[i].0);
                }
            });
        }
        popover.popup();
        on.grab_focus();
    }

    /// Runs the edge pulse and the time-left lines while disappearing bubbles are on screen, about 12 times a second like the
    /// call pill (`header.rs`): a CSS animation would redraw at the frame clock rate. Stops when none is left or the view is
    /// hidden; the chat's 2 s timer starts it again.
    pub(super) fn start_disappear_tick(self: &Rc<Self>) {
        if !self.messages.is_mapped() || self.disappear_ticking.replace(true) {
            return;
        }
        let view = Rc::downgrade(self);
        let last_step = Cell::new(-1);
        let last_second = Cell::new(0u64);
        glib::timeout_add_local(std::time::Duration::from_millis(80), move || {
            let Some(view) = view.upgrade() else { return glib::ControlFlow::Break };
            if !view.messages.is_mapped() || !view.disappear_step(&last_step, &last_second) {
                view.disappear_ticking.set(false);
                return glib::ControlFlow::Break;
            }
            glib::ControlFlow::Continue
        });
    }

    /// One tick. False: no disappearing bubble is left.
    fn disappear_step(self: &Rc<Self>, last_step: &Cell<i32>, last_second: &Cell<u64>) -> bool {
        let now = util::now_ms();
        let t = (glib::monotonic_time() / 1000 % 1600) as f64 / 1600.0;
        let pulse = 0.5 - 0.5 * (2.0 * std::f64::consts::PI * t).cos();
        let step = (pulse * (DISAPPEAR_PULSE_STEPS - 1) as f64).round() as i32;
        let old_step = last_step.replace(step);
        let new_second = last_second.replace(now / 1000) != now / 1000;
        let watched = self.is_watched();
        let (mut any, mut started, mut gone) = (false, false, Vec::new());
        for (id, bubble) in self.bubbles.borrow().iter() {
            let Some(label) = &bubble.expire_label else { continue };
            let mut entry = bubble.entry.borrow_mut();
            let Some((secs, mut at)) = entry.expire else { continue };
            if entry.deleted {
                // Deleted by hand: a plain placeholder from now on.
                entry.expire = None;
                label.set_visible(false);
                bubble.skin.remove_css_class("disappear");
                bubble.skin.remove_css_class(&format!("dpulse-{old_step}"));
                continue;
            }
            any = true;
            // On screen now: a received message starts counting down (the core does the same, see `start_disappear_countdown`).
            let full = now + secs as u64 * 1000;
            if watched && !bubble.mine && at > full {
                at = full;
                entry.expire = Some((secs, at));
                started = true;
            }
            if at <= now {
                gone.push(id.clone());
                continue;
            }
            if step != old_step {
                bubble.skin.remove_css_class(&format!("dpulse-{old_step}"));
                bubble.skin.add_css_class(&format!("dpulse-{step}"));
            }
            if new_second || started {
                label.set_label(&format_left(left_ms((secs, at), now)));
            }
        }
        if started {
            let (fingerprint, group_id) = self.chat_keys();
            bg_serial(move || core::start_disappear_countdown(&fingerprint, &group_id));
        }
        for id in gone {
            self.slide_out(&id);
        }
        any
    }

    /// Slides a bubble off to its own side, then drops it. Its row is gone from the archive too (or will be on the core's next
    /// sweep), so nothing brings it back.
    fn slide_out(self: &Rc<Self>, id: &str) {
        let Some(bubble) = self.bubbles.borrow_mut().remove(id) else { return };
        {
            let mut order = self.order.borrow_mut();
            if let Some(index) = order.iter().position(|(_, i)| i == id) {
                order.remove(index);
                // It closed a run: the bubble before it shows the time again.
                if bubble.meta.is_visible() && index > 0 {
                    if let Some(previous) = self.bubbles.borrow().get(&order[index - 1].1) {
                        previous.meta.set_visible(true);
                    }
                }
            }
        }
        self.search_matches.borrow_mut().retain(|i| i != id);
        self.search_lower.borrow_mut().remove(id);
        let root = bubble.root.clone();
        root.add_css_class(if bubble.mine { "msg-gone-mine" } else { "msg-gone" });
        let view = Rc::downgrade(self);
        glib::timeout_add_local_once(std::time::Duration::from_millis(320), move || {
            let Some(view) = view.upgrade() else { return };
            if root.parent().is_some() {
                view.messages.remove(&root);
            }
            view.refresh_day_separators();
        });
    }
}
