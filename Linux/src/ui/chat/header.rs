//! Chat header bar: title, subtitle, call buttons and the chat menu.

use super::*;

pub(super) fn build_header(
    view: &Rc<ChatView>,
    subtitle: &gtk::Label,
    search_bar: &gtk::Revealer,
    search_entry: &gtk::SearchEntry,
) -> adw::HeaderBar {
    let title = gtk::Label::new(Some(&view.conversation.title()));
    title.add_css_class("heading");

    let title_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .halign(gtk::Align::Center)
        .build();
    title_box.append(&title);
    title_box.append(subtitle);

    let header = adw::HeaderBar::builder().title_widget(&title_box).build();
        // See `MainUi::toggle_sidebar`. If the sidebar was hidden, a way to show it again is needed while a chat is open too
        // (the same pattern as the placeholder page).
    header.pack_start(&crate::ui::window::sidebar_toggle_button(&view.main));

    let (popover, items) = crate::ui::widgets::menu_popover();

    let mut entries: Vec<(&str, Box<dyn Fn(&Rc<ChatView>)>)> = Vec::new();
    if view.is_group() {
        entries.push(("Members", Box::new(group_members)));
        entries.push(("Invite a contact", Box::new(group_invite)));
        entries.push(("Set group picture", Box::new(group_picture)));
    }
    entries.push((
        "Attachments",
        Box::new(|view: &Rc<ChatView>| attachments_overview(view)),
    ));
    {
        let bar = search_bar.clone();
        let entry = search_entry.clone();
        entries.push((
            "Search in chat",
            Box::new(move |_: &Rc<ChatView>| {
                let opening = !bar.reveals_child();
                bar.set_reveal_child(opening);
                if opening {
                    entry.grab_focus();
                }
            }),
        ));
    }

    for (label, action) in entries {
        let button = gtk::Button::builder().label(label).build();
        button.add_css_class("flat");
        if let Some(child) = button.child().and_downcast::<gtk::Label>() {
            child.set_xalign(0.0);
        }
        let view = view.clone();
        let popover = popover.clone();
        button.connect_clicked(move |_| {
            popover.popdown();
            action(&view);
        });
        items.append(&button);
    }

    header.pack_end(
        &gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .popover(&popover)
            .build(),
    );
    header.pack_end(view.whiteboard.toggle_button());
    let mut call_buttons = Vec::new();
    for (icon, tip, video) in [("camera-video-symbolic", "Video call", true), ("call-start-symbolic", "Voice call", false)] {
        let button = gtk::Button::builder().icon_name(icon).tooltip_text(tip).build();
        let view = view.clone();
        button.connect_clicked(move |_| crate::ui::call::place(&view.main.app, &view.conversation, video));
        header.pack_end(&button);
        call_buttons.push(button);
    }
    if let Conversation::Group { group_id, .. } = &view.conversation {
        header.pack_end(&attend_pill(view, group_id.clone(), call_buttons));
    }
    header
}

/// A call runs in this group and this device is not in it: an accent pill
/// replaces the two call buttons and joins it (`core::start_group_call`
/// joins a running call). Same as Android's `action_attend_call`.
fn attend_pill(view: &Rc<ChatView>, group_id: String, call_buttons: Vec<gtk::Button>) -> gtk::Button {
    let icon = gtk::Image::from_icon_name("call-start-symbolic");
    let content = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    content.append(&icon);
    content.append(&gtk::Label::new(Some("Attend")));
    let pill = gtk::Button::builder().child(&content).tooltip_text("Join the call running in this group").visible(false).build();
    pill.add_css_class("pill");
    pill.add_css_class("suggested-action");
    let video = Rc::new(Cell::new(false));
    {
        let view = view.clone();
        let video = video.clone();
        pill.connect_clicked(move |_| crate::ui::call::place(&view.main.app, &view.conversation, video.get()));
    }
    let pulsing = Rc::new(Cell::new(false));
    // Fades in and out. A CSS animation redraws at the frame clock rate; this
    // steps about 12 times a second and stops while the pill is not on screen.
    let pulse: Rc<dyn Fn(&gtk::Button)> = {
        let pulsing = pulsing.clone();
        Rc::new(move |pill: &gtk::Button| {
            if pulsing.get() || !pill.is_mapped() {
                return;
            }
            pulsing.set(true);
            let weak = pill.downgrade();
            let pulsing = pulsing.clone();
            glib::timeout_add_local(std::time::Duration::from_millis(80), move || {
                let Some(pill) = weak.upgrade().filter(|p| p.is_mapped()) else {
                    pulsing.set(false);
                    if let Some(p) = weak.upgrade() {
                        p.set_opacity(1.0);
                    }
                    return glib::ControlFlow::Break;
                };
                let t = (glib::monotonic_time() / 1000 % 1600) as f64 / 1600.0;
                pill.set_opacity(0.4 + 0.3 * (1.0 + (2.0 * std::f64::consts::PI * t).cos()));
                glib::ControlFlow::Continue
            });
        })
    };
    {
        let pulse = pulse.clone();
        pill.connect_map(move |pill| pulse(pill));
    }
    let refresh: Rc<dyn Fn()> = {
        let weak = pill.downgrade();
        Rc::new(move || {
            let gid = group_id.clone();
            let weak = weak.clone();
            let (icon, video, buttons, pulse) = (icon.clone(), video.clone(), call_buttons.clone(), pulse.clone());
            crate::app::run_in_background(
                move || core::group_call_offer(&gid),
                move |offer| {
                    let Some(pill) = weak.upgrade() else { return };
                    video.set(offer == 2);
                    icon.set_icon_name(Some(if offer == 2 { "camera-video-symbolic" } else { "call-start-symbolic" }));
                    for b in &buttons {
                        b.set_visible(offer == 0);
                    }
                    pill.set_visible(offer != 0);
                    if offer != 0 {
                        pulse(&pill);
                    }
                },
            );
        })
    };
    refresh();
    let gid = match &view.conversation {
        Conversation::Group { group_id, .. } => group_id.clone(),
        _ => String::new(),
    };
    view.main.app.subscribe(&pill, move |event| {
        if (event.kind == "group_call_offer" && event.string("group_id") == gid) || event.kind == "call_state" {
            refresh();
        }
    });
    pill
}

impl ChatView {
    pub(super) fn refresh_subtitle(self: &Rc<Self>) {
        match &self.conversation {
            Conversation::Direct { fingerprint, .. } => {
                let fingerprint = fingerprint.clone();
                let view = self.clone();
                crate::app::run_in_background(
                    move || {
                        if core::is_peer_connected(&fingerprint) {
                            "Connected"
                        } else if core::has_active_session(&fingerprint) {
                            "Offline · messages will be delivered later"
                        } else {
                            "Connecting…"
                        }
                    },
                    move |label| {
                        if !view.account_deleted.get() {
                            view.subtitle.set_label(label);
                        }
                    },
                );
            }
            Conversation::Group { group_id, .. } => {
                let count = self
                    .app()
                    .groups
                    .borrow()
                    .iter()
                    .find(|group| group.group_id == *group_id)
                    .map(|group| group.member_identity_ids.len())
                    .unwrap_or(0);
                if !self.account_deleted.get() {
                    self.subtitle
                        .set_label(&format!("{} member{}", count, if count == 1 { "" } else { "s" }));
                }
            }
        }
    }

}
