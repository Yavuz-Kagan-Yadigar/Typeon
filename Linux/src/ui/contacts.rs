//! The Contacts list — every paired identity, whether or not it has messages.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::core;
use crate::i18n::t;
use crate::ui::dialogs;
use crate::ui::window::{Conversation, MainUi};
use crate::util;

pub fn build(main: &Rc<MainUi>) -> gtk::Widget {
    let search = gtk::SearchEntry::builder()
        .placeholder_text(t("Search contacts"))
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .build();

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("navigation-sidebar");

    let empty = adw::StatusPage::builder()
        .icon_name("contact-new-symbolic")
        .title(t("No contacts"))
        .description(
            t("Contacts pair face to face. Use \"My contact code\" in the menu and have the other \
             person scan or paste it — or paste theirs with \"Add contact\"."),
        )
        .build();

    let stack = gtk::Stack::new();
    stack.add_named(
        &gtk::ScrolledWindow::builder()
            .vexpand(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&list)
            .build(),
        Some("list"),
    );
    stack.add_named(&empty, Some("empty"));

    let add = gtk::Button::builder()
        .label(t("Add contact"))
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .build();
    add.add_css_class("suggested-action");
    {
        let app = main.app.clone();
        add.connect_clicked(move |_| dialogs::add_contact(&app));
    }

    let container = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();
    container.append(&search);
    container.append(&stack);
    container.append(&add);

    let query = Rc::new(RefCell::new(String::new()));
    // Core reads (contacts, blocked ids, safety codes) happen off the GTK
    // thread into `data`; typing in the search box only re-filters it.
    let data: Rc<RefCell<Vec<(core::ContactSummary, bool, String)>>> = Rc::new(RefCell::new(Vec::new()));
    // Rows re-read the list after their own actions (block, trust, ...).
    // Weak here, owned by the event subscription below (see `chats::build`).
    let refresh_cell: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));
    let refresh_weak = Rc::downgrade(&refresh_cell);
    let render: Rc<dyn Fn()> = {
        let main = main.clone();
        let list = list.clone();
        let stack = stack.clone();
        let query = query.clone();
        let data = data.clone();
        Rc::new(move || {
            let needle = query.borrow().to_lowercase();
            while let Some(child) = list.first_child() {
                list.remove(&child);
            }
            let refresh: Rc<dyn Fn()> = refresh_weak
                .upgrade()
                .and_then(|cell| cell.borrow().clone())
                .unwrap_or_else(|| Rc::new(|| {}));
            for (contact, blocked, code) in data.borrow().iter() {
                if !needle.is_empty() && !contact.display_name.to_lowercase().contains(&needle) {
                    continue;
                }
                list.append(&build_row(&main, contact, *blocked, code.clone(), refresh.clone()));
            }
            stack.set_visible_child_name(if list.first_child().is_none() { "empty" } else { "list" });
        })
    };
    let refresh: Rc<dyn Fn()> = {
        let render = render.clone();
        let data = data.clone();
        let generation = Rc::new(std::cell::Cell::new(0u64));
        let pending = Rc::new(std::cell::Cell::new(false));
        Rc::new(move || {
            // Burst of events -> one rebuild.
            if pending.replace(true) {
                return;
            }
            let (render, data, generation, pending) = (render.clone(), data.clone(), generation.clone(), pending.clone());
            glib::timeout_add_local_once(std::time::Duration::from_millis(150), move || {
                pending.set(false);
                let mine = generation.get() + 1;
                generation.set(mine);
                crate::app::run_in_background(
                    || {
                        let blocked = core::list_blocked_identities();
                        core::list_contacts()
                            .into_iter()
                            .map(|contact| {
                                let is_blocked = blocked.contains(&contact.identity_id);
                                let code = if contact.added_via_group {
                                    core::contact_safety_code(&contact.identity_id)
                                } else {
                                    String::new()
                                };
                                (contact, is_blocked, code)
                            })
                            .collect::<Vec<_>>()
                    },
                    move |rows| {
                        if generation.get() != mine {
                            return;
                        }
                        *data.borrow_mut() = rows;
                        render();
                    },
                );
            });
        })
    };

    *refresh_cell.borrow_mut() = Some(refresh.clone());

    {
        let render = render.clone();
        let query = query.clone();
        search.connect_search_changed(move |entry| {
            *query.borrow_mut() = entry.text().to_string();
            render();
        });
    }

    refresh();
    {
        let refresh = refresh.clone();
        let container = container.downgrade();
        glib::timeout_add_seconds_local(30, move || {
            // Torn down -> stop; hidden (other tab / minimized) -> skip.
            let Some(container) = container.upgrade() else { return glib::ControlFlow::Break };
            if container.is_mapped() {
                refresh();
            }
            glib::ControlFlow::Continue
        });
    }
    {
        let refresh = refresh.clone();
        let refresh_cell = refresh_cell.clone();
        main.app.subscribe(&container, move |event| {
            let _ = &refresh_cell;
            // `sync`: contacts paired on the phone arrive in its DeviceSync.
            if matches!(
                event.kind.as_str(),
                "profile_update" | "device_change" | "device_linked" | "address_announce" | "sync"
            ) {
                refresh();
            }
        });
    }

    container.upcast()
}

fn build_row(
    main: &Rc<MainUi>,
    contact: &core::ContactSummary,
    blocked: bool,
    safety_code: String,
    refresh: Rc<dyn Fn()>,
) -> gtk::ListBoxRow {
    let fingerprint = contact.active_device_fingerprint.clone().unwrap_or_default();
    let ready = !fingerprint.is_empty();

    let subtitle = if !ready {
        t("Pairing not finished yet").to_string()
    } else if contact.added_via_group {
        // Vouched for by a group founder rather than verified face to face —
        // worth saying out loud, since the whole trust model here is TOFU.
        t("Added through a group · not verified in person").to_string()
    } else {
        util::short_fingerprint(&contact.identity_id)
    };

    let avatar = adw::Avatar::new(40, Some(&contact.display_name), true);
    if let Some(texture) = contact.avatar_hex.as_deref().and_then(util::texture_from_hex) {
        avatar.set_custom_image(Some(&texture));
    }

    let row = adw::ActionRow::builder()
        .title(glib::markup_escape_text(&contact.display_name).as_str())
        .subtitle(glib::markup_escape_text(&subtitle).as_str())
        .activatable(ready)
        .build();
    row.add_prefix(&avatar);

    if contact.added_via_group {
        let warning = gtk::Image::from_icon_name("dialog-warning-symbolic");
        warning.set_tooltip_text(Some(
            t("This contact was introduced by a group founder. Verify their safety number in \
             person before treating it as authenticated."),
        ));
        row.add_suffix(&warning);
    }

    let revoke = gtk::Button::builder()
        .icon_name("action-unavailable-symbolic")
        .tooltip_text(t("Revoke this contact's current device"))
        .valign(gtk::Align::Center)
        .build();
    revoke.add_css_class("flat");
    if ready {
        let app = main.app.clone();
        let contact_id = contact.contact_id.clone();
        let name = contact.display_name.clone();
        let device = fingerprint.clone();
        let refresh = refresh.clone();
        revoke.connect_clicked(move |_| {
            let app_inner = app.clone();
            let contact_id = contact_id.clone();
            let device = device.clone();
            let refresh = refresh.clone();
            dialogs::confirm(
                &app,
                t("Revoke this device?"),
                &tf!(
                    "Stops accepting anything from {}'s current device — for example if they \
                     told you it was stolen. The contact and history stay; they can re-pair \
                     from a new device.",
                    name
                ),
                t("Revoke"),
                true,
                move || {
                    let app_inner = app_inner.clone();
                    let contact_id = contact_id.clone();
                    let device = device.clone();
                    let refresh = refresh.clone();
                    crate::app::run_in_background(
                        move || core::revoke_contact_device(&contact_id, &device),
                        move |result| {
                            match result {
                                Ok(()) => app_inner.toast(t("Device revoked.")),
                                Err(error) => app_inner.toast(&error),
                            }
                            refresh();
                        },
                    );
                },
            );
        });
        row.add_suffix(&revoke);
    }

    // Blocking targets the identity, so no packet is accepted from any of its
    // devices. While blocked, the same spot shows an "Unblock" button.
    if blocked {
        let unblock = gtk::Button::builder()
            .icon_name("object-select-symbolic")
            .tooltip_text(t("Unblock this person"))
            .valign(gtk::Align::Center)
            .build();
        unblock.add_css_class("flat");
        let app = main.app.clone();
        let identity_id = contact.identity_id.clone();
        let refresh = refresh.clone();
        unblock.connect_clicked(move |_| {
            let app = app.clone();
            let identity_id = identity_id.clone();
            let refresh = refresh.clone();
            crate::app::run_in_background(
                move || core::unblock_identity(&identity_id),
                move |()| {
                    app.toast(t("Unblocked."));
                    refresh();
                },
            );
        });
        row.add_suffix(&unblock);
    } else {
        let block = gtk::Button::builder()
            .icon_name("avatar-default-symbolic")
            .tooltip_text(t("Block this person"))
            .valign(gtk::Align::Center)
            .build();
        block.add_css_class("flat");
        let app = main.app.clone();
        let identity_id = contact.identity_id.clone();
        let name = contact.display_name.clone();
        let refresh = refresh.clone();
        block.connect_clicked(move |_| {
            let app_inner = app.clone();
            let identity_id = identity_id.clone();
            let refresh = refresh.clone();
            dialogs::confirm(
                &app,
                t("Block this person?"),
                &tf!(
                    "No message or file from any device of {} will be accepted, and nothing \
                     will be sent to them. You can unblock them later from this list.",
                    name
                ),
                t("Block"),
                true,
                move || {
                    let app_inner = app_inner.clone();
                    let identity_id = identity_id.clone();
                    let refresh = refresh.clone();
                    crate::app::run_in_background(
                        move || core::block_identity(&identity_id),
                        move |result| {
                            match result {
                                Ok(()) => app_inner.toast(t("Blocked.")),
                                Err(error) => app_inner.toast(&error),
                            }
                            refresh();
                        },
                    );
                },
            );
        });
        row.add_suffix(&block);
    }

    // A contact met through a group is not fully trusted by default. The
    // encryption is the same either way. Only the trust indicator differs, so
    // the button shows only while that indicator is set.
    if contact.added_via_group {
        let trust = gtk::Button::builder()
            .icon_name("security-high-symbolic")
            .tooltip_text(t("Mark as verified in person"))
            .valign(gtk::Align::Center)
            .build();
        trust.add_css_class("flat");
        let app = main.app.clone();
        let contact_id = contact.contact_id.clone();
        let name = contact.display_name.clone();
        let refresh = refresh.clone();
        // "Verified" does not exchange keys. Keys are already in use
        // end to end. What is missing is confirming that the keys really
        // belong to this contact. Only the user can do that, by comparing the
        // safety code over another channel. So the code is shown inside the
        // dialog.
        trust.connect_clicked(move |_| {
            let app_inner = app.clone();
            let contact_id = contact_id.clone();
            let refresh = refresh.clone();
            let body = if safety_code.is_empty() {
                tf!(
                    "You met {} through a group, not face to face. Only do this if you have \
                     confirmed their security code another way.",
                    name
                )
            } else {
                tf!(
                    "You met {} through a group, not face to face.\n\nSecurity code: {}\n\n\
                     Compare it with them over a different channel — a call, or in person. \
                     If it matches, the keys are genuinely theirs.",
                    name, util::ltr(&safety_code)
                )
            };
            dialogs::confirm(
                &app,
                t("Mark as verified?"),
                &body,
                t("Mark verified"),
                false,
                move || {
                    let app_inner = app_inner.clone();
                    let contact_id = contact_id.clone();
                    let refresh = refresh.clone();
                    crate::app::run_in_background(
                        move || core::trust_contact(&contact_id),
                        move |result| {
                            match result {
                                Ok(()) => app_inner.toast(t("Marked as verified.")),
                                Err(error) => app_inner.toast(&error),
                            }
                            refresh();
                        },
                    );
                },
            );
        });
        row.add_suffix(&trust);
    }

    if ready {
        let main = main.clone();
        let conversation = Conversation::Direct {
            fingerprint,
            contact_id: contact.contact_id.clone(),
            identity_id: contact.identity_id.clone(),
            name: contact.display_name.clone(),
        };
        row.connect_activated(move |_| main.open_conversation(conversation.clone()));
    }

    // See the note in `chats::build_row` — an AdwActionRow must be a direct
    // child of the GtkListBox or it never gets activated.
    row.upcast()
}
