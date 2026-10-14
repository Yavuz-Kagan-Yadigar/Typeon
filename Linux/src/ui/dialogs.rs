//! Modal flows that do not deserve a screen of their own: context menus,
//! confirmations, pairing, linked devices, the pending-message queue and the
//! security alert that fires when a contact's device keys change.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::app::App;
use crate::core;
use crate::qr;
use crate::ui::window::{Conversation, MainUi};
use crate::util;

/// Two-button confirmation. `destructive` styles the accept button red and is
/// what every irreversible action here uses.
pub fn confirm(
    app: &Rc<App>,
    heading: &str,
    body: &str,
    accept_label: &str,
    destructive: bool,
    on_accept: impl Fn() + 'static,
) {
    let Some(window) = app.window() else { return };
    let dialog = adw::MessageDialog::new(Some(&window), Some(heading), Some(body));
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("accept", accept_label);
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");
    dialog.set_response_appearance(
        "accept",
        if destructive {
            adw::ResponseAppearance::Destructive
        } else {
            adw::ResponseAppearance::Suggested
        },
    );
    dialog.connect_response(None, move |_, response| {
        if response == "accept" {
            on_accept();
        }
    });
    dialog.present();
}

/// Single-line text prompt; `on_submit` gets the trimmed text.
fn prompt(
    app: &Rc<App>,
    heading: &str,
    body: &str,
    placeholder: &str,
    initial: &str,
    accept_label: &str,
    on_submit: impl Fn(String) + 'static,
) {
    let Some(window) = app.window() else { return };
    let entry = gtk::Entry::builder()
        .placeholder_text(placeholder)
        .text(initial)
        .activates_default(true)
        .build();

    let dialog = adw::MessageDialog::new(Some(&window), Some(heading), Some(body));
    dialog.set_extra_child(Some(&crate::ui::widgets::dialog_field(&entry)));
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("accept", accept_label);
    dialog.set_default_response(Some("accept"));
    dialog.set_close_response("cancel");
    dialog.set_response_appearance("accept", adw::ResponseAppearance::Suggested);
    dialog.connect_response(None, move |_, response| {
        if response != "accept" {
            return;
        }
        let text = entry.text().to_string().trim().to_string();
        if !text.is_empty() {
            on_submit(text);
        }
    });
    dialog.present();
}

// --- chat list context menu ---

#[allow(clippy::too_many_arguments)]
pub fn chat_context_menu(
    main: &Rc<MainUi>,
    anchor: &impl IsA<gtk::Widget>,
    conversation: &Conversation,
    pin_key: &str,
    pinned: bool,
    is_group: bool,
    is_founder: bool,
    x: f64,
    y: f64,
    // Pinning is a local `Prefs` change with no core event behind it, so
    // without this the chat list only picked the new order/badge up on its
    // next 30s backstop tick or the next app launch — the caller passes its
    // own list-rebuild closure so this can ask for one immediately.
    on_pin_toggled: Rc<dyn Fn()>,
) {
    let (popover, items) = crate::ui::widgets::menu_popover();
    popover.set_has_arrow(false);
    popover.set_parent(anchor.as_ref());
    popover.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
    // A popover parented to a row must be unparented when it closes, or GTK
    // warns and the row keeps it alive forever.
    popover.connect_closed(|popover| popover.unparent());

    let mut entries: Vec<(&str, String, bool, Box<dyn Fn()>)> = Vec::new();

    {
        let main = main.clone();
        let pin_key = pin_key.to_string();
        let on_pin_toggled = on_pin_toggled.clone();
        entries.push((
            "view-pin-symbolic",
            if pinned { "Unpin chat" } else { "Pin chat" }.to_string(),
            false,
            Box::new(move || {
                main.app.prefs.borrow_mut().set_pinned(&pin_key, !pinned);
                on_pin_toggled();
            }),
        ));
    }

    match conversation {
        Conversation::Direct {
            contact_id, name, ..
        } => {
            {
                let main = main.clone();
                let contact_id = contact_id.clone();
                let name = name.clone();
                entries.push((
                    "user-trash-symbolic",
                    "Clear chat history".to_string(),
                    true,
                    Box::new(move || {
                        let main = main.clone();
                        let contact_id = contact_id.clone();
                        confirm(
                            &main.app.clone(),
                            "Clear this chat?",
                            &format!(
                                "Deletes the local messages and attachments for {}. You stay \
                                 paired and can keep messaging.",
                                name
                            ),
                            "Clear",
                            true,
                            move || match core::clear_chat_history(&contact_id) {
                                Ok(()) => main.app.toast("Chat history cleared."),
                                Err(error) => main.app.toast(&error),
                            },
                        );
                    }),
                ));
            }
            {
                let main = main.clone();
                let contact_id = contact_id.clone();
                let name = name.clone();
                entries.push((
                    "edit-delete-symbolic",
                    "Delete contact".to_string(),
                    true,
                    Box::new(move || {
                        let main = main.clone();
                        let contact_id = contact_id.clone();
                        confirm(
                            &main.app.clone(),
                            "Delete this contact?",
                            &format!(
                                "Removes {} completely, including the ratchet session. You will \
                                 need a fresh QR or manual pairing to message them again.",
                                name
                            ),
                            "Delete",
                            true,
                            move || match core::delete_contact(&contact_id) {
                                Ok(()) => {
                                    main.close_conversation();
                                    main.app.toast("Contact deleted.");
                                }
                                Err(error) => main.app.toast(&error),
                            },
                        );
                    }),
                ));
            }
        }
        Conversation::Group { group_id, name } => {
            let main = main.clone();
            let group_id = group_id.clone();
            let name = name.clone();
            // The founder cannot leave — for them the only exit is deleting the
            // group for everyone (see the core's `leave_group`).
            let label = if is_founder {
                "Delete group for everyone"
            } else {
                "Leave group"
            };
            entries.push((
                "edit-delete-symbolic",
                label.to_string(),
                true,
                Box::new(move || {
                    let main = main.clone();
                    let group_id = group_id.clone();
                    let body = if is_founder {
                        format!("\"{}\" is removed for every member. This cannot be undone.", name)
                    } else {
                        format!(
                            "You leave \"{}\". The founder is told, and the group disappears from \
                             this device.",
                            name
                        )
                    };
                    confirm(
                        &main.app.clone(),
                        if is_founder { "Delete this group?" } else { "Leave this group?" },
                        &body,
                        if is_founder { "Delete" } else { "Leave" },
                        true,
                        move || {
                            let outcome = if is_founder {
                                core::delete_group(&group_id)
                            } else {
                                core::leave_group(&group_id)
                            };
                            match outcome {
                                Ok(()) => {
                                    main.close_conversation();
                                    main.app.toast("Done.");
                                }
                                Err(error) => main.app.toast(&error),
                            }
                        },
                    );
                }),
            ));
        }
    }
    let _ = is_group;

    for (icon, label, destructive, action) in entries {
        let button = crate::ui::widgets::menu_item(icon, label.as_str());
        if destructive {
            button.add_css_class("destructive-action");
        }
        let popover = popover.clone();
        button.connect_clicked(move |_| {
            popover.popdown();
            action();
        });
        items.append(&button);
    }

    popover.popup();
}

// --- pairing ---

/// Adds a contact from a pasted manual code. There is no camera path here on
/// purpose: a desktop rarely has a usable one, and the manual code carries the
/// exact same payload as the QR (`identity|fingerprint|nonce|name|rendezvous`).
pub fn add_contact(app: &Rc<App>) {
    let app_for_submit = app.clone();
    prompt(
        app,
        "Add a contact",
        "Paste the code from the other person's \"My contact code\" screen.",
        "identity|fingerprint|nonce|name|/ip4/…",
        "",
        "Add",
        move |text| match core::process_manual_entry(&text) {
            Ok(peer) => {
                app_for_submit.refresh_caches();
                app_for_submit.toast(&format!(
                    "Pairing with {} — this finishes once both devices are reachable.",
                    peer.device_name
                ));
            }
            Err(error) => app_for_submit.toast(&format!("Could not add contact: {}", error)),
        },
    );
}

/// Shows this device's own pairing QR and manual code, so someone else can add
/// us. The rendezvous address is only known once the swarm is listening, hence
/// the retry.
pub fn show_own_code(app: &Rc<App>) {
    let Some(window) = app.window() else { return };

    let qr_slot = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .halign(gtk::Align::Center)
        .width_request(280)
        .height_request(280)
        .build();

    let code_label = gtk::Label::builder()
        .label("Waiting for a network address…")
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .selectable(true)
        .xalign(0.0)
        .build();
    code_label.add_css_class("monospace");
    code_label.add_css_class("caption");

    let copy = gtk::Button::builder()
        .label("Copy code")
        .halign(gtk::Align::Center)
        .sensitive(false)
        .build();
    copy.add_css_class("pill");

    let short_code = core::identity_short_code().unwrap_or_default();
    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    content.append(&qr_slot);
    if !short_code.is_empty() {
        let safety = gtk::Label::new(Some(&format!("Safety number: {}", short_code)));
        safety.add_css_class("dim-label");
        content.append(&safety);
    }
    content.append(&code_label);
    content.append(&copy);

    let header = adw::HeaderBar::new();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(
        &gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&content)
            .build(),
    ));

    let dialog = adw::Window::builder()
        .modal(true)
        .transient_for(&window)
        .title("My contact code")
        .default_width(420)
        .default_height(620)
        .content(&toolbar)
        .build();

    {
        let qr_slot = qr_slot.clone();
        let code_label = code_label.clone();
        let copy = copy.clone();
        let dialog = dialog.clone();
        let attempts = std::cell::Cell::new(0u32);
        glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
            if !dialog.is_visible() {
                return glib::ControlFlow::Break;
            }
            let address = core::node_address();
            if address.is_empty() {
                attempts.set(attempts.get() + 1);
                if attempts.get() >= 40 {
                    code_label.set_label("No listening address yet — check your connection.");
                    return glib::ControlFlow::Break;
                }
                return glib::ControlFlow::Continue;
            }
            let manual = core::manual_add_code(&address);
            if !manual.is_empty() {
                code_label.set_label(&manual);
                copy.set_sensitive(true);
                let manual_for_copy = manual.clone();
                // Take the button from the callback argument rather than
                // capturing a clone — capturing would make the button own a
                // closure that owns the button.
                copy.connect_clicked(move |button| {
                    button.clipboard().set_text(&manual_for_copy);
                });
            }
            let payload = core::generate_qr_packet(&address);
            if let Some(widget) = qr::qr_widget(&payload) {
                qr_slot.append(&widget);
            }
            glib::ControlFlow::Break
        });
    }

    dialog.present();
}

// --- groups ---

pub fn create_group(main: &Rc<MainUi>) {
    let main = main.clone();
    prompt(
        &main.app.clone(),
        "New group",
        "Members are invited afterwards, from inside the group.",
        "Group name",
        "",
        "Create",
        move |name| match core::create_group(&name) {
            Ok(group_id) => {
                main.app.refresh_caches();
                main.open_conversation(Conversation::Group { group_id, name });
            }
            Err(error) => main.app.toast(&format!("Could not create the group: {}", error)),
        },
    );
}

// --- linked devices (spec 1.5 / 1.6) ---

pub fn linked_devices(app: &Rc<App>) {
    let Some(window) = app.window() else { return };

    let group = adw::PreferencesGroup::builder()
        .title("Devices on your account")
        .description(
            "Each device holds its own keys. Revoking one stops every contact from accepting \
             anything signed by it.",
        )
        .build();

    let page = adw::PreferencesPage::new();
    page.add(&group);

    let header = adw::HeaderBar::new();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&page));

    let dialog = adw::Window::builder()
        .modal(true)
        .transient_for(&window)
        .title("Linked devices")
        .default_width(480)
        .default_height(420)
        .content(&toolbar)
        .build();

    let rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::new(RefCell::new(Vec::new()));
    let rebuild: Rc<dyn Fn()> = {
        let app = app.clone();
        let group = group.clone();
        let rows = rows.clone();
        Rc::new(move || {
            for row in rows.borrow_mut().drain(..) {
                group.remove(&row);
            }
            for device in core::list_linked_devices() {
                let subtitle = format!(
                    "{}{}{}",
                    util::short_fingerprint(&device.device_fingerprint),
                    if device.is_this_device { " · this computer" } else { "" },
                    if device.is_active { "" } else { " · revoked" },
                );
                let row = adw::ActionRow::builder()
                    .title(glib::markup_escape_text(&device.device_name).as_str())
                    .subtitle(subtitle.as_str())
                    .build();

                if device.is_active && !device.is_this_device {
                    let revoke = gtk::Button::builder()
                        .label("Revoke")
                        .valign(gtk::Align::Center)
                        .build();
                    revoke.add_css_class("destructive-action");
                    let app = app.clone();
                    let fingerprint = device.device_fingerprint.clone();
                    let name = device.device_name.clone();
                    revoke.connect_clicked(move |_| {
                        let app_inner = app.clone();
                        let fingerprint = fingerprint.clone();
                        confirm(
                            &app,
                            "Revoke this device?",
                            &format!(
                                "\"{}\" can no longer send or receive on your account. A signed \
                                 revocation goes out to every contact.",
                                name
                            ),
                            "Revoke",
                            true,
                            move || match core::revoke_linked_device(&fingerprint) {
                                Ok(()) => app_inner.toast("Device revoked."),
                                Err(error) => app_inner.toast(&error),
                            },
                        );
                    });
                    row.add_suffix(&revoke);
                }

                group.add(&row);
                rows.borrow_mut().push(row);
            }
        })
    };

    rebuild();
    {
        let rebuild = rebuild.clone();
        let dialog = dialog.clone();
        glib::timeout_add_seconds_local(3, move || {
            if !dialog.is_visible() {
                return glib::ControlFlow::Break;
            }
            rebuild();
            glib::ControlFlow::Continue
        });
    }

    dialog.present();
}

// --- pending (unacknowledged) messages ---

pub fn pending_messages(app: &Rc<App>) {
    let Some(window) = app.window() else { return };

    let group = adw::PreferencesGroup::builder()
        .title("Waiting for delivery confirmation")
        .description(
            "These are retried automatically with a growing backoff. \"Retry now\" only moves \
             the next attempt forward.",
        )
        .build();

    let page = adw::PreferencesPage::new();
    page.add(&group);

    let header = adw::HeaderBar::new();
    let retry_all = gtk::Button::builder().label("Retry all").build();
    header.pack_end(&retry_all);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&page));

    let dialog = adw::Window::builder()
        .modal(true)
        .transient_for(&window)
        .title("Pending messages")
        .default_width(560)
        .default_height(480)
        .content(&toolbar)
        .build();

    let rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::new(RefCell::new(Vec::new()));
    let placeholder = adw::ActionRow::builder()
        .title("Nothing pending")
        .subtitle("Every message has been acknowledged.")
        .build();
    group.add(&placeholder);

    let rebuild: Rc<dyn Fn()> = {
        let app = app.clone();
        let group = group.clone();
        let rows = rows.clone();
        let placeholder = placeholder.clone();
        Rc::new(move || {
            for row in rows.borrow_mut().drain(..) {
                group.remove(&row);
            }
            let pending = core::list_pending_messages();
            placeholder.set_visible(pending.is_empty());

            for message in pending {
                let target = if message.device_name.is_empty() {
                    util::short_fingerprint(&message.peer_device_fingerprint)
                } else {
                    message.device_name.clone()
                };
                let subtitle = format!(
                    "to {} · sent {}",
                    target,
                    util::format_list_time(message.original_sent_at)
                );
                let row = adw::ActionRow::builder()
                    .title(glib::markup_escape_text(&util::preview_text(&message.text, 70)).as_str())
                    .subtitle(glib::markup_escape_text(&subtitle).as_str())
                    .build();

                let buttons = gtk::Box::builder()
                    .orientation(gtk::Orientation::Horizontal)
                    .spacing(6)
                    .valign(gtk::Align::Center)
                    .build();

                let retry = gtk::Button::builder().label("Retry now").build();
                {
                    let app = app.clone();
                    let message_id = message.message_id.clone();
                    retry.connect_clicked(move |_| {
                        core::retry_pending_message_now(&message_id);
                        app.toast("Retrying now.");
                    });
                }
                buttons.append(&retry);

                let cancel = gtk::Button::builder().label("Give up").build();
                cancel.add_css_class("destructive-action");
                {
                    let app = app.clone();
                    let message_id = message.message_id.clone();
                    cancel.connect_clicked(move |_| {
                        core::cancel_pending_message(&message_id);
                        app.toast("Message abandoned.");
                    });
                }
                buttons.append(&cancel);

                row.add_suffix(&buttons);
                group.add(&row);
                rows.borrow_mut().push(row);
            }
        })
    };

    {
        let app = app.clone();
        let rebuild = rebuild.clone();
        retry_all.connect_clicked(move |_| {
            core::retry_all_pending_now();
            app.toast("Retrying everything now.");
            rebuild();
        });
    }

    rebuild();
    {
        let rebuild = rebuild.clone();
        let dialog = dialog.clone();
        glib::timeout_add_seconds_local(3, move || {
            if !dialog.is_visible() {
                return glib::ControlFlow::Break;
            }
            rebuild();
            glib::ControlFlow::Continue
        });
    }

    dialog.present();
}

// --- device-change alerts (spec 2.2, TOFU) ---

/// Polls for pending "this contact is using a new device" alerts and shows one
/// modal at a time. Tracking which fingerprint is on screen matters: without it
/// a user who steps away accumulates a stack of identical non-dismissable
/// dialogs, and a peer could deliberately spam the flow — which would train
/// people to click through the one security prompt that must not be reflexive.
pub fn watch_device_alerts(app: &Rc<App>) {
    let showing: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let app = app.clone();
    glib::timeout_add_seconds_local(5, move || {
        if showing.borrow().is_some() {
            return glib::ControlFlow::Continue;
        }
        let Some(alert) = core::list_pending_device_alerts().into_iter().next() else {
            return glib::ControlFlow::Continue;
        };
        let Some(window) = app.window() else {
            return glib::ControlFlow::Continue;
        };

        *showing.borrow_mut() = Some(alert.new_device_fingerprint.clone());

        let body = format!(
            "{} is now messaging from a device you have not seen before.\n\nNew safety number: \
             {}\nKnown: {}\n\nAccept only if they told you they added or replaced a device. If \
             not, this could be someone impersonating them.",
            alert.contact_display_name,
            alert.new_device_short_code,
            if alert.known_device_short_codes.is_empty() {
                "none".to_string()
            } else {
                alert.known_device_short_codes.join(", ")
            }
        );

        let dialog = adw::MessageDialog::new(
            Some(&window),
            Some("A contact's device changed"),
            Some(&body),
        );
        dialog.add_response("reject", "Reject");
        dialog.add_response("accept", "Accept");
        dialog.set_default_response(Some("reject"));
        dialog.set_close_response("reject");
        dialog.set_response_appearance("reject", adw::ResponseAppearance::Destructive);

        let app_for_response = app.clone();
        let showing_for_response = showing.clone();
        let fingerprint = alert.new_device_fingerprint.clone();
        dialog.connect_response(None, move |_, response| {
            if response == "accept" {
                core::accept_device_alert(&fingerprint);
                app_for_response.toast("New device accepted.");
            } else {
                core::reject_device_alert(&fingerprint);
                app_for_response.toast("New device rejected.");
            }
            app_for_response.refresh_caches();
            *showing_for_response.borrow_mut() = None;
        });
        dialog.present();

        glib::ControlFlow::Continue
    });
}
