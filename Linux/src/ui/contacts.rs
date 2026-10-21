//! The Contacts list — every paired identity, whether or not it has messages.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::core;
use crate::ui::dialogs;
use crate::ui::window::{Conversation, MainUi};
use crate::util;

pub fn build(main: &Rc<MainUi>) -> gtk::Widget {
    let search = gtk::SearchEntry::builder()
        .placeholder_text("Search contacts")
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
        .title("No contacts")
        .description(
            "Contacts pair face to face. Use \"My contact code\" in the menu and have the other \
             person scan or paste it — or paste theirs with \"Add contact\".",
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
        .label("Add contact")
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
            for (contact, blocked, code) in data.borrow().iter() {
                if !needle.is_empty() && !contact.display_name.to_lowercase().contains(&needle) {
                    continue;
                }
                list.append(&build_row(&main, contact, *blocked, code.clone()));
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
        main.app.subscribe(&container, move |event| {
            if matches!(
                event.kind.as_str(),
                "profile_update" | "device_change" | "device_linked" | "address_announce"
            ) {
                refresh();
            }
        });
    }

    container.upcast()
}

fn build_row(main: &Rc<MainUi>, contact: &core::ContactSummary, blocked: bool, safety_code: String) -> gtk::ListBoxRow {
    let fingerprint = contact.active_device_fingerprint.clone().unwrap_or_default();
    let ready = !fingerprint.is_empty();

    let subtitle = if !ready {
        "Pairing not finished yet".to_string()
    } else if contact.added_via_group {
        // Vouched for by a group founder rather than verified face to face —
        // worth saying out loud, since the whole trust model here is TOFU.
        "Added through a group · not verified in person".to_string()
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
            "This contact was introduced by a group founder. Verify their safety number in \
             person before treating it as authenticated.",
        ));
        row.add_suffix(&warning);
    }

    let revoke = gtk::Button::builder()
        .icon_name("action-unavailable-symbolic")
        .tooltip_text("Revoke this contact's current device")
        .valign(gtk::Align::Center)
        .build();
    revoke.add_css_class("flat");
    if ready {
        let app = main.app.clone();
        let contact_id = contact.contact_id.clone();
        let name = contact.display_name.clone();
        let device = fingerprint.clone();
        revoke.connect_clicked(move |_| {
            let app_inner = app.clone();
            let contact_id = contact_id.clone();
            let device = device.clone();
            dialogs::confirm(
                &app,
                "Revoke this device?",
                &format!(
                    "Stops accepting anything from {}'s current device — for example if they \
                     told you it was stolen. The contact and history stay; they can re-pair \
                     from a new device.",
                    name
                ),
                "Revoke",
                true,
                move || match core::revoke_contact_device(&contact_id, &device) {
                    Ok(()) => app_inner.toast("Device revoked."),
                    Err(error) => app_inner.toast(&error),
                },
            );
        });
        row.add_suffix(&revoke);
    }

    // Engel kimliği hedefler (hiçbir cihazından paket kabul edilmez).
    // Engelliyse aynı yerde "Engeli kaldır" düğmesi durur.
    if blocked {
        let unblock = gtk::Button::builder()
            .icon_name("object-select-symbolic")
            .tooltip_text("Unblock this person")
            .valign(gtk::Align::Center)
            .build();
        unblock.add_css_class("flat");
        let app = main.app.clone();
        let identity_id = contact.identity_id.clone();
        unblock.connect_clicked(move |_| {
            core::unblock_identity(&identity_id);
            app.toast("Unblocked.");
        });
        row.add_suffix(&unblock);
    } else {
        let block = gtk::Button::builder()
            .icon_name("avatar-default-symbolic")
            .tooltip_text("Block this person")
            .valign(gtk::Align::Center)
            .build();
        block.add_css_class("flat");
        let app = main.app.clone();
        let identity_id = contact.identity_id.clone();
        let name = contact.display_name.clone();
        block.connect_clicked(move |_| {
            let app_inner = app.clone();
            let identity_id = identity_id.clone();
            dialogs::confirm(
                &app,
                "Block this person?",
                &format!(
                    "No message or file from any device of {} will be accepted, and nothing \
                     will be sent to them. You can unblock them later from this list.",
                    name
                ),
                "Block",
                true,
                move || match core::block_identity(&identity_id) {
                    Ok(()) => app_inner.toast("Blocked."),
                    Err(error) => app_inner.toast(&error),
                },
            );
        });
        row.add_suffix(&block);
    }

    // Grup üzerinden tanışılan kişiye TAM güven verme (kullanıcı kararı):
    // şifreleme zaten aynıydı, değişen yalnızca güven göstergesi — bu yüzden
    // düğme SADECE o işaret duruyorken görünüyor.
    if contact.added_via_group {
        let trust = gtk::Button::builder()
            .icon_name("security-high-symbolic")
            .tooltip_text("Mark as verified in person")
            .valign(gtk::Align::Center)
            .build();
        trust.add_css_class("flat");
        let app = main.app.clone();
        let contact_id = contact.contact_id.clone();
        let name = contact.display_name.clone();
        // Kullanıcı sorusu (2026-08-28): "güven" arkada anahtar alışverişi
        // YAPMIYOR — anahtarlar zaten uçtan uca kullanımda. Eksik olan tek
        // şey, o anahtarların gerçekten bu kişiye ait olduğunun
        // DOĞRULANMASI; bunu ancak kullanıcı başka bir kanaldan
        // karşılaştırarak yapabilir. O yüzden kod pencerenin İÇİNDE.
        trust.connect_clicked(move |_| {
            let app_inner = app.clone();
            let contact_id = contact_id.clone();
            let body = if safety_code.is_empty() {
                format!(
                    "You met {} through a group, not face to face. Only do this if you have \
                     confirmed their security code another way.",
                    name
                )
            } else {
                format!(
                    "You met {} through a group, not face to face.\n\nSecurity code: {}\n\n\
                     Compare it with them over a different channel — a call, or in person. \
                     If it matches, the keys are genuinely theirs.",
                    name, safety_code
                )
            };
            dialogs::confirm(
                &app,
                "Mark as verified?",
                &body,
                "Mark verified",
                false,
                move || match core::trust_contact(&contact_id) {
                    Ok(()) => app_inner.toast("Marked as verified."),
                    Err(error) => app_inner.toast(&error),
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
