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
    for (icon, tip, video) in [("camera-video-symbolic", "Video call", true), ("call-start-symbolic", "Voice call", false)] {
        let button = gtk::Button::builder().icon_name(icon).tooltip_text(tip).build();
        let view = view.clone();
        button.connect_clicked(move |_| crate::ui::call::place(&view.main.app, &view.conversation, video));
        header.pack_end(&button);
    }
    header
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
