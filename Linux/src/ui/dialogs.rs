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
                let conversation = conversation.clone();
                entries.push((
                    "user-trash-symbolic",
                    "Clear chat history".to_string(),
                    true,
                    Box::new(move || {
                        let main = main.clone();
                        let contact_id = contact_id.clone();
                        let conversation = conversation.clone();
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
                            move || {
                                let main = main.clone();
                                let contact_id = contact_id.clone();
                                let conversation = conversation.clone();
                                // Core calls take the shared core lock the poll
                                // thread can hold for seconds — off the GTK thread.
                                crate::app::run_in_background(
                                    move || core::clear_chat_history(&contact_id),
                                    move |result| match result {
                                        Ok(()) => {
                                            main.reload_if_open(&conversation);
                                            main.app.toast("Chat history cleared.");
                                        }
                                        Err(error) => main.app.toast(&error),
                                    },
                                );
                            },
                        );
                    }),
                ));
            }
            {
                let main = main.clone();
                let contact_id = contact_id.clone();
                let name = name.clone();
                let conversation = conversation.clone();
                entries.push((
                    "edit-delete-symbolic",
                    "Delete contact".to_string(),
                    true,
                    Box::new(move || {
                        let main = main.clone();
                        let contact_id = contact_id.clone();
                        let conversation = conversation.clone();
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
                            move || {
                                let main = main.clone();
                                let contact_id = contact_id.clone();
                                let conversation = conversation.clone();
                                crate::app::run_in_background(
                                    move || core::delete_contact(&contact_id),
                                    move |result| match result {
                                        Ok(()) => {
                                            main.close_if_open(&conversation);
                                            main.refresh_chats();
                                            main.app.toast("Contact deleted.");
                                        }
                                        Err(error) => main.app.toast(&error),
                                    },
                                );
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
            let conversation = conversation.clone();
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
                    let conversation = conversation.clone();
                    let body = if is_founder {
                        format!("\"{}\" is removed for every member. This cannot be undone.", name)
                    } else {
                        format!(
                            "You leave \"{}\". The founder is told, and the group disappears from \
                             all your linked devices.",
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
                            let main = main.clone();
                            let group_id = group_id.clone();
                            let conversation = conversation.clone();
                            crate::app::run_in_background(
                                move || if is_founder {
                                    core::delete_group(&group_id)
                                } else {
                                    core::leave_group(&group_id)
                                },
                                move |result| match result {
                                    Ok(()) => {
                                        main.close_if_open(&conversation);
                                        main.refresh_chats();
                                        main.app.toast("Done.");
                                    }
                                    Err(error) => main.app.toast(&error),
                                },
                            );
                        },
                    );
                }),
            ));
        }
    }

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
        move |text| {
            // Core lock — the poll thread can hold it for seconds — so the
            // manual-entry processing runs off the GTK thread and the UI only
            // reports the result (H125 pattern).
            let app = app_for_submit.clone();
            crate::app::run_in_background(
                move || core::process_manual_entry(&text),
                move |result| match result {
                    Ok(peer) => {
                        app.refresh_caches();
                        app.toast(&format!(
                            "Pairing with {} — this finishes once both devices are reachable.",
                            peer.device_name
                        ));
                    }
                    Err(error) => app.toast(&format!("Could not add contact: {}", error)),
                },
            );
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

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    content.append(&qr_slot);
    // Core lock: filled in from a worker, hidden until it arrives.
    let safety = gtk::Label::new(None);
    safety.add_css_class("dim-label");
    safety.set_visible(false);
    content.append(&safety);
    crate::app::run_in_background(
        || core::identity_short_code().unwrap_or_default(),
        move |short_code| {
            if !short_code.is_empty() {
                safety.set_label(&format!("Safety number: {}", short_code));
                safety.set_visible(true);
            }
        },
    );
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
        let in_flight = Rc::new(std::cell::Cell::new(false));
        glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
            if !dialog.is_visible() {
                return glib::ControlFlow::Break;
            }
            // The core lock can be held for seconds: query off the GTK thread.
            if in_flight.replace(true) {
                return glib::ControlFlow::Continue;
            }
            let (qr_slot, code_label, copy, in_flight) =
                (qr_slot.clone(), code_label.clone(), copy.clone(), in_flight.clone());
            let attempts_now = attempts.get() + 1;
            attempts.set(attempts_now);
            crate::app::run_in_background(
                || {
                    let address = core::node_address();
                    if address.is_empty() {
                        return None;
                    }
                    let manual = core::manual_add_code(&address);
                    let payload = core::generate_qr_packet(&address);
                    Some((manual, payload))
                },
                move |found| {
                    in_flight.set(false);
                    let Some((manual, payload)) = found else {
                        if attempts_now >= 40 {
                            code_label.set_label("No listening address yet — check your connection.");
                            // give up: the flag stays set, later ticks are no-ops.
                            in_flight.set(true);
                        }
                        return;
                    };
                    in_flight.set(true); // done: no more queries
                    if !manual.is_empty() {
                        code_label.set_label(&manual);
                        copy.set_sensitive(true);
                        // Take the button from the callback argument rather
                        // than capturing a clone — capturing would make the
                        // button own a closure that owns the button.
                        copy.connect_clicked(move |button| {
                            // The pairing code is a 24 h bearer secret: mark it
                            // so clipboard managers do not record/preview it.
                            let text = gtk::gdk::ContentProvider::for_value(&manual.to_value());
                            let hint = gtk::gdk::ContentProvider::for_bytes("x-kde-passwordManagerHint", &glib::Bytes::from_static(b"secret"));
                            let _ = button.clipboard().set_content(Some(&gtk::gdk::ContentProvider::new_union(&[text, hint])));
                        });
                    }
                    if let Some(widget) = qr::qr_widget(&payload) {
                        qr_slot.append(&widget);
                    }
                },
            );
            glib::ControlFlow::Continue
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
        move |name| {
            // Core lock: off the GTK thread.
            let main = main.clone();
            let work_name = name.clone();
            crate::app::run_in_background(
                move || core::create_group(&work_name),
                move |result| match result {
                    Ok(group_id) => {
                        main.app.refresh_caches();
                        main.open_conversation(Conversation::Group { group_id, name });
                    }
                    Err(error) => main.app.toast(&format!("Could not create the group: {}", error)),
                },
            );
        },
    );
}

// --- linked devices (spec 1.5 / 1.6) ---

pub fn linked_devices(app: &Rc<App>) {
    let Some(window) = app.window() else { return };

    let group = adw::PreferencesGroup::builder()
        .title("Devices on your account")
        .description(
            "Each device holds its own keys. Revoke a device from your phone.",
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
            let app = app.clone();
            let group = group.clone();
            let rows = rows.clone();
            // The core read takes the shared core lock; a poll round can hold
            // it for seconds, so it never runs on the GTK thread — not even
            // from this 3-second timer (see `watch_device_alerts`).
            crate::app::run_in_background(core::list_linked_devices, move |devices| {
                for row in rows.borrow_mut().drain(..) {
                    group.remove(&row);
                }
                for device in devices {
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

                    // No "Revoke": only the phone (primary device) can revoke; a desktop is secondary.

                    // A revoked device only lingers in the list: hide it here.
                    if !device.is_active {
                        let forget = gtk::Button::builder().label("Remove from list").valign(gtk::Align::Center).build();
                        let app = app.clone();
                        let fingerprint = device.device_fingerprint.clone();
                        forget.connect_clicked(move |_| {
                            let (app, fingerprint) = (app.clone(), fingerprint.clone());
                            crate::app::run_in_background(
                                move || core::forget_revoked_linked_device(&fingerprint),
                                move |result| {
                                    if let Err(error) = result {
                                        app.toast(&error);
                                    }
                                },
                            );
                        });
                        row.add_suffix(&forget);
                    }

                    group.add(&row);
                    rows.borrow_mut().push(row);
                }
            });
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
            let app = app.clone();
            let group = group.clone();
            let rows = rows.clone();
            let placeholder = placeholder.clone();
            // Same core-lock rule as `linked_devices` above: the read runs off
            // the GTK thread, the row rebuild comes back on it.
            crate::app::run_in_background(core::list_pending_messages, move |pending| {
                for row in rows.borrow_mut().drain(..) {
                    group.remove(&row);
                }
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
                            let app = app.clone();
                            let message_id = message_id.clone();
                            crate::app::run_in_background(
                                move || core::retry_pending_message_now(&message_id),
                                move |_| app.toast("Retrying now."),
                            );
                        });
                    }
                    buttons.append(&retry);

                    let cancel = gtk::Button::builder().label("Give up").build();
                    cancel.add_css_class("destructive-action");
                    {
                        let app = app.clone();
                        let message_id = message.message_id.clone();
                        cancel.connect_clicked(move |_| {
                            let (app_done, message_id) = (app.clone(), message_id.clone());
                            confirm(
                                &app,
                                "Give up on this message?",
                                "It is removed from the queue and never sent.",
                                "Give up",
                                true,
                                move || {
                                    let (app, message_id) = (app_done.clone(), message_id.clone());
                                    crate::app::run_in_background(
                                        move || core::cancel_pending_message(&message_id),
                                        move |_| app.toast("Message abandoned."),
                                    );
                                },
                            );
                        });
                    }
                    buttons.append(&cancel);

                    row.add_suffix(&buttons);
                    group.add(&row);
                    rows.borrow_mut().push(row);
                }
            });
        })
    };

    {
        let app = app.clone();
        let rebuild = rebuild.clone();
        retry_all.connect_clicked(move |_| {
            // The core fan-out takes the shared core lock — off the GTK thread.
            let app = app.clone();
            let rebuild = rebuild.clone();
            crate::app::run_in_background(
                core::retry_all_pending_now,
                move |()| {
                    app.toast("Retrying everything now.");
                    rebuild();
                },
            );
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

/// Shows pending "this contact is using a new device" alerts, one
/// modal at a time. Tracking which fingerprint is on screen matters: without it
/// a user who steps away accumulates a stack of identical non-dismissable
/// dialogs, and a peer could deliberately spam the flow — which would train
/// people to click through the one security prompt that must not be reflexive.
pub fn watch_device_alerts(app: &Rc<App>) {
    let watch = Rc::new(AlertWatch {
        app: app.clone(),
        showing: RefCell::new(None),
        in_flight: std::cell::Cell::new(false),
        again: std::cell::Cell::new(false),
        retry_armed: std::cell::Cell::new(false),
    });
    // Driven by the core's `device_alert` event, plus one look now for
    // alerts left from an earlier run. No timer while nothing is pending.
    check_device_alerts(&watch);
    if let Some(window) = app.window() {
        app.subscribe(&window, move |event| {
            if event.kind == "device_alert" {
                check_device_alerts(&watch);
            }
        });
    }
}

struct AlertWatch {
    app: Rc<App>,
    /// The alert on screen, if any.
    showing: RefCell<Option<String>>,
    in_flight: std::cell::Cell<bool>,
    /// An event came while a read was in flight: read again after it.
    again: std::cell::Cell<bool>,
    /// A retry timer is waiting for the idle lock to lift.
    retry_armed: std::cell::Cell<bool>,
}

fn check_device_alerts(watch: &Rc<AlertWatch>) {
    // Nothing about contacts may show over the lock page: look again once
    // it is gone.
    if watch.app.locked.get() {
        if !watch.retry_armed.replace(true) {
            let watch = watch.clone();
            glib::timeout_add_local_once(std::time::Duration::from_secs(5), move || {
                watch.retry_armed.set(false);
                check_device_alerts(&watch);
            });
        }
        return;
    }
    // One alert on screen at a time; the next one is read after its answer.
    if watch.showing.borrow().is_some() {
        return;
    }
    if watch.in_flight.replace(true) {
        watch.again.set(true);
        return;
    }
    // The core read runs off the GTK thread (shared core lock).
    let watch = watch.clone();
    crate::app::run_in_background(core::list_pending_device_alerts, move |alerts| {
        watch.in_flight.set(false);
        if watch.again.replace(false) {
            check_device_alerts(&watch);
            return;
        }
        let app = watch.app.clone();
        let Some(alert) = alerts.into_iter().next() else { return };
        let Some(window) = app.window() else { return };
        if watch.showing.borrow().is_some() {
            return;
        }
        if app.locked.get() {
            check_device_alerts(&watch);
            return;
        }

        *watch.showing.borrow_mut() = Some(alert.new_device_fingerprint.clone());

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

        let fingerprint = alert.new_device_fingerprint.clone();
        dialog.connect_response(None, move |_, response| {
            // A security decision must not take the core lock on the GTK
            // thread: a poll round would freeze exactly this dialog.
            let accepting = response == "accept";
            let fingerprint = fingerprint.clone();
            let watch = watch.clone();
            crate::app::run_in_background(
                move || {
                    if accepting {
                        core::accept_device_alert(&fingerprint);
                    } else {
                        core::reject_device_alert(&fingerprint);
                    }
                },
                move |()| {
                    watch.app.toast(if accepting {
                        "New device accepted."
                    } else {
                        "New device rejected."
                    });
                    watch.app.refresh_caches();
                    *watch.showing.borrow_mut() = None;
                    // More may be queued behind this one.
                    check_device_alerts(&watch);
                },
            );
        });
        dialog.present();
    });
}

/// Empties `attachments/plain_cache` (decrypted copies), except the desktop's
/// own live temp files: a voice capture (`voice-*`), a scrubbed outgoing copy
/// (`out-*`) and the core's sticker conversion (`.sticker-*`) changed in the
/// last 15 minutes. Deleting those would break a recording or a send in
/// progress. Blocking: call it off the GTK thread.
pub fn clear_decrypted_cache() {
    let dir = crate::data_directory().join("attachments/plain_cache");
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let live = ["voice-", "out-", ".sticker-"].iter().any(|prefix| name.starts_with(prefix))
            && entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age < std::time::Duration::from_secs(15 * 60));
        if live {
            continue;
        }
        let path = entry.path();
        let _ = if path.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
    }
}

/// Settings → Storage, as on Android: what this device keeps, and per chat
/// "remove local files" (downloadable again) or "delete older than" (messages
/// and files, this device only). Nothing here touches the other devices.
pub fn storage(app: &Rc<App>) {
    let Some(window) = app.window() else { return };
    let page = adw::PreferencesPage::new();
    let header = adw::HeaderBar::new();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&page));
    let dialog = adw::Window::builder()
        .modal(true)
        .transient_for(&window)
        .title("Storage")
        .default_width(520)
        .default_height(620)
        .content(&toolbar)
        .build();
    let groups: Rc<RefCell<Vec<adw::PreferencesGroup>>> = Rc::new(RefCell::new(Vec::new()));
    let rebuild: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));
    let build: Rc<dyn Fn()> = {
        let (app, page, groups, rebuild) = (app.clone(), page.clone(), groups.clone(), rebuild.clone());
        Rc::new(move || {
            let (app, page, groups, rebuild) = (app.clone(), page.clone(), groups.clone(), rebuild.clone());
            crate::app::run_in_background(core::storage_usage, move |usage| {
                for group in groups.borrow_mut().drain(..) {
                    page.remove(&group);
                }
                let again = move || {
                    if let Some(f) = rebuild.borrow().clone() {
                        f();
                    }
                };
                let again: Rc<dyn Fn()> = Rc::new(again);

                let totals = adw::PreferencesGroup::builder().title("On this device").build();
                for (title, bytes) in [
                    ("Messages (database)", usage.db_bytes),
                    ("Files and media", usage.attachments_bytes),
                    ("Voice messages", usage.voice_bytes),
                    ("Stickers", usage.stickers_bytes),
                ] {
                    totals.add(&adw::ActionRow::builder().title(title).subtitle(util::human_size(bytes).as_str()).build());
                }
                let cache = adw::ActionRow::builder()
                    .title("Decrypted cache")
                    .subtitle(util::human_size(usage.cache_bytes).as_str())
                    .build();
                let clear = gtk::Button::builder().label("Clear").valign(gtk::Align::Center).build();
                {
                    let again = again.clone();
                    clear.connect_clicked(move |_| {
                        let again = again.clone();
                        crate::app::run_in_background(clear_decrypted_cache, move |()| again());
                    });
                }
                cache.add_suffix(&clear);
                totals.add(&cache);
                page.add(&totals);
                groups.borrow_mut().push(totals);

                let chats = adw::PreferencesGroup::builder()
                    .title("Chats")
                    .description("Removing files keeps the messages; a file can be downloaded again while its sender still has it.")
                    .build();
                for chat in usage.chats {
                    let row = adw::ActionRow::builder()
                        .title(glib::markup_escape_text(&chat.name).as_str())
                        .subtitle(format!("{} · {} files", util::human_size(chat.bytes), chat.count).as_str())
                        .build();
                    if chat.count > 0 {
                        let remove = gtk::Button::builder().icon_name("edit-clear-all-symbolic").tooltip_text("Remove this chat's files from this device").valign(gtk::Align::Center).build();
                        remove.add_css_class("flat");
                        let (app, chat, again) = (app.clone(), chat.clone(), again.clone());
                        remove.connect_clicked(move |_| {
                            let (app2, chat, again) = (app.clone(), chat.clone(), again.clone());
                            confirm(&app, "Remove these files?", &format!("{} of files from \"{}\" leave this device. The messages stay.", util::human_size(chat.bytes), chat.name), "Remove", true, move || {
                                let (app, chat, again) = (app2.clone(), chat.clone(), again.clone());
                                crate::app::run_in_background(
                                    move || {
                                        // Paged: one listing is capped at 500 rows. A page
                                        // never splits a millisecond, so the oldest row's
                                        // time is a safe cursor.
                                        let mut ids: Vec<String> = Vec::new();
                                        let mut cursor = u64::MAX;
                                        loop {
                                            let files = if chat.kind == "group" {
                                                core::list_group_attachments_before(&chat.id, cursor, 500)
                                            } else {
                                                core::list_attachments_before(&chat.id, cursor, 500)
                                            };
                                            let Some(oldest) = files.iter().map(|f| f.created_at).min() else { break };
                                            let full = files.len() >= 500;
                                            ids.extend(files.into_iter().filter(|f| f.status == "complete").map(|f| f.file_id));
                                            if !full || oldest >= cursor {
                                                break;
                                            }
                                            cursor = oldest;
                                        }
                                        core::remove_local_attachments(&ids)
                                    },
                                    move |result| {
                                        if let Err(error) = result {
                                            app.toast(&error);
                                        }
                                        again();
                                    },
                                );
                            });
                        });
                        row.add_suffix(&remove);
                    }
                    let prune = gtk::DropDown::from_strings(&["Delete older than…", "1 week", "1 month", "3 months", "6 months", "1 year"]);
                    prune.set_valign(gtk::Align::Center);
                    {
                        let (app, chat, again) = (app.clone(), chat.clone(), again.clone());
                        prune.connect_selected_notify(move |dd| {
                            let days: i64 = match dd.selected() { 1 => 7, 2 => 30, 3 => 91, 4 => 182, 5 => 365, _ => return };
                            dd.set_selected(0);
                            let before = util::now_ms() as i64 - days * 86_400_000;
                            let (app, chat, again) = (app.clone(), chat.clone(), again.clone());
                            crate::app::run_in_background(
                                {
                                    let chat = chat.clone();
                                    move || core::chat_prune_stats(&chat.kind, &chat.id, before)
                                },
                                move |stats| {
                                    if stats.del_msg_count == 0 && stats.del_att_bytes == 0 {
                                        app.toast("Nothing that old in this chat");
                                        return;
                                    }
                                    let app2 = app.clone();
                                    confirm(&app, "Delete older items?", &format!("{} messages and {} of files from \"{}\" are deleted on this device.", stats.del_msg_count, util::human_size(stats.del_att_bytes), chat.name), "Delete", true, move || {
                                        let (app, chat, again) = (app2.clone(), chat.clone(), again.clone());
                                        crate::app::run_in_background(
                                            move || core::prune_chat_before(&chat.kind, &chat.id, before),
                                            move |result| {
                                                if let Err(error) = result {
                                                    app.toast(&error);
                                                }
                                                again();
                                            },
                                        );
                                    });
                                },
                            );
                        });
                    }
                    row.add_suffix(&prune);
                    chats.add(&row);
                }
                page.add(&chats);
                groups.borrow_mut().push(chats);
            });
        })
    };
    *rebuild.borrow_mut() = Some(build.clone());
    build();
    dialog.present();
}
