//! Group dialogs: members, invite, group picture.

use super::*;

// --- group management ---

pub(super) fn group_members(view: &Rc<ChatView>) {
    let Conversation::Group { group_id, name } = &view.conversation else {
        return;
    };
    let Some(window) = view.app().window() else { return };

    let group_summary = view
        .app()
        .groups
        .borrow()
        .iter()
        .find(|group| group.group_id == *group_id)
        .cloned();
    let Some(summary) = group_summary else { return };

    let list = adw::PreferencesGroup::builder().title("Members").build();
    for identity in &summary.member_identity_ids {
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&view.app().identity_name(identity)).as_str())
            .subtitle(util::short_fingerprint(identity).as_str())
            .build();
        if let Some(texture) = view
            .app()
            .identity_avatar(identity)
            .as_deref()
            .and_then(util::texture_from_hex)
        {
            let avatar = adw::Avatar::new(32, None, true);
            avatar.set_custom_image(Some(&texture));
            row.add_prefix(&avatar);
        }
        // Only the founder can remove people, and never themselves.
        if summary.is_founder && *identity != summary.founder_identity_id {
            let remove = gtk::Button::builder()
                .icon_name("list-remove-symbolic")
                .valign(gtk::Align::Center)
                .tooltip_text("Remove from group")
                .build();
            remove.add_css_class("flat");
            let view = view.clone();
            let group_id = group_id.clone();
            let identity = identity.clone();
            remove.connect_clicked(move |_| {
                let (group_id, identity, view) = (group_id.clone(), identity.clone(), view.clone());
                crate::app::run_in_background(
                    move || core::remove_from_group(&group_id, &identity),
                    move |removed| {
                        if removed {
                            view.app().toast("Member removed.");
                            view.app().refresh_caches();
                        } else {
                            view.app().toast("Could not remove that member.");
                        }
                    },
                );
            });
            row.add_suffix(&remove);
        }
        list.add(&row);
    }

    // The founder can re-send the current group state to every member — the
    // fix for a member whose group update never arrived. The core rejects it
    // for anyone but the founder, so the button only exists for the founder.
    let mut resend_row = None;
    if summary.is_founder {
        let resend = adw::ActionRow::builder()
            .title("Resend group to everyone")
            .subtitle("Sends the current group state to every member again.")
            .build();
        let resend_button = gtk::Button::builder()
            .label("Resend")
            .valign(gtk::Align::Center)
            .build();
        {
            let view = view.clone();
            let group_id = group_id.clone();
            resend_button.connect_clicked(move |_| {
                let (view, group_id) = (view.clone(), group_id.clone());
                // The core call takes the shared core lock — off the GTK
                // thread, so a slow poll round cannot stall the window.
                crate::app::run_in_background(
                    move || core::resend_group_to_all(&group_id),
                    move |result| match result {
                        Ok(()) => view.app().toast("Group state sent to everyone."),
                        Err(error) => view.app().toast(&error),
                    },
                );
            });
        }
        resend.add_suffix(&resend_button);
        resend_row = Some(resend);
    }

    let page = adw::PreferencesPage::new();
    page.add(&list);
    if let Some(resend) = resend_row {
        let actions = adw::PreferencesGroup::builder().title("Group").build();
        actions.add(&resend);
        page.add(&actions);
    }
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));

    adw::Window::builder()
        .modal(true)
        .transient_for(&window)
        .title(name.as_str())
        .default_width(420)
        .default_height(480)
        .content(&toolbar)
        .build()
        .present();
}

pub(super) fn group_invite(view: &Rc<ChatView>) {
    let Conversation::Group { group_id, .. } = &view.conversation else {
        return;
    };
    let Some(window) = view.app().window() else { return };

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");

    let already: Vec<String> = view
        .app()
        .groups
        .borrow()
        .iter()
        .find(|group| group.group_id == *group_id)
        .map(|group| group.member_identity_ids.clone())
        .unwrap_or_default();
    let group_id = group_id.clone();
    let view = view.clone();
    let rows_list = list.clone();

    app::run_in_background(
        core::list_contacts,
        move |contacts| {
            for contact in contacts {
                if already.contains(&contact.identity_id) {
                    continue;
                }
                let row = adw::ActionRow::builder()
                    .title(glib::markup_escape_text(&contact.display_name).as_str())
                    .activatable(true)
                    .build();
                let view = view.clone();
                let group_id = group_id.clone();
                let identity = contact.identity_id.clone();
                row.connect_activated(move |row| {
                    let view = view.clone();
                    let group_id = group_id.clone();
                    let identity = identity.clone();
                    let row = row.clone();
                    // Sending the invitation takes the shared core lock — off
                    // the GTK thread, so a slow poll round cannot stall it.
                    crate::app::run_in_background(
                        move || core::invite_to_group(&group_id, &identity),
                        move |invited| {
                            if invited {
                                view.app().toast("Invitation sent.");
                                view.app().refresh_caches();
                                row.set_sensitive(false);
                            } else {
                                view.app().toast("Could not invite that contact.");
                            }
                        },
                    );
                });
                rows_list.append(&row);
            }
        },
    );

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    content.append(&list);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(
        &gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&content)
            .build(),
    ));

    adw::Window::builder()
        .modal(true)
        .transient_for(&window)
        .title("Invite to group")
        .default_width(400)
        .default_height(480)
        .content(&toolbar)
        .build()
        .present();
}

pub(super) fn group_picture(view: &Rc<ChatView>) {
    let Conversation::Group { group_id, .. } = &view.conversation else {
        return;
    };
    let Some(window) = view.app().window() else { return };

    let dialog = gtk::FileDialog::builder().modal(false).title("Choose a group picture").build();
    let view = view.clone();
    let group_id = group_id.clone();
    dialog.open(Some(&window), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let source = path.to_string_lossy().to_string();
        let view = view.clone();
        let group_id = group_id.clone();
        app::run_in_background(
            move || match util::scaled_jpeg(&source, 720, 85) {
                Some(jpeg) => core::set_group_profile_picture(&group_id, Some(jpeg)),
                None => Err("That file is not an image Typeon can read.".to_string()),
            },
            move |result| match result {
                // Only the founder may set it; the core enforces that.
                Ok(()) => {
                    view.app().toast("Group picture updated.");
                    view.app().refresh_caches();
                }
                Err(error) => view.app().toast(&error),
            },
        );
    });
}
