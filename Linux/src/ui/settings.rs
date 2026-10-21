//! Settings — the desktop form of `SettingsFragment`.
//!
//! Network, profile, appearance and the two security actions that are specific
//! to this being a desktop: changing the vault passphrase, and exporting a
//! recovery file for *this* device's keys.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::gio;

use crate::app::{self, App};
use crate::core;
use crate::secrets;
use crate::ui::{dialogs, onboarding};
use crate::util;

pub fn present(app: &Rc<App>) {
    present_page(app, None);
}

/// Opens Settings on a specific page. Used by `TYPEON_UI_TEST=settings-<page>`
/// to look at a page without having to click through to it.
pub fn present_page(app: &Rc<App>, page: Option<&str>) {
    let Some(window) = app.window() else { return };

    // One Settings window: a server add/remove re-presents the page, so
    // close the previous one instead of stacking another.
    thread_local! {
        static CURRENT: RefCell<Option<adw::PreferencesWindow>> = const { RefCell::new(None) };
    }
    if let Some(previous) = CURRENT.with(|c| c.borrow_mut().take()) {
        previous.close();
    }

    let preferences = adw::PreferencesWindow::builder()
        .modal(true)
        .transient_for(&window)
        .search_enabled(false)
        .default_width(600)
        .default_height(760)
        .build();

    preferences.add(&network_page(app));
    preferences.add(&appearance_page(app));
    preferences.add(&security_page(app));
    if let Some(page) = page {
        preferences.set_visible_page_name(page);
    }
    preferences.present();
    CURRENT.with(|c| *c.borrow_mut() = Some(preferences));
}

fn network_page(app: &Rc<App>) -> adw::PreferencesPage {
    let page = adw::PreferencesPage::builder()
        .title("Network")
        .icon_name("network-wireless-symbolic")
        .build();

    let connectivity = adw::PreferencesGroup::builder().title("Connectivity").build();

    let tor = adw::SwitchRow::builder()
        .title("Route through Tor")
        .subtitle(
            "Publishes a persistent .onion address so people can reach you from behind CGNAT. \
             Takes effect the next time Typeon starts — a live swarm cannot gain a transport.",
        )
        .active(app.prefs.borrow().tor_enabled)
        .build();
    {
        let app = app.clone();
        tor.connect_active_notify(move |row| {
            let mut prefs = app.prefs.borrow_mut();
            prefs.tor_enabled = row.is_active();
            prefs.save();
            drop(prefs);
            app.toast("Tor setting applies after a restart.");
        });
    }
    connectivity.add(&tor);

    let node = adw::SwitchRow::builder()
        .title("Node mode")
        .subtitle(
            "Archive this device's traffic locally and relay for others. Without it, nothing is \
             kept on disk and history has to be fetched from a peer.",
        )
        .active(app.prefs.borrow().node_mode)
        .build();
    {
        let app = app.clone();
        node.connect_active_notify(move |row| {
            let enabled = row.is_active();
            let mut prefs = app.prefs.borrow_mut();
            prefs.node_mode = enabled;
            prefs.save();
            drop(prefs);
            // Unlike Tor this one is live — the core takes it immediately.
            std::thread::spawn(move || core::set_node_mode(enabled));
        });
    }
    connectivity.add(&node);
    page.add(&connectivity);

    let storage = adw::PreferencesGroup::builder()
        .title("Storage")
        .description("Only enforced in node mode. Lowering the limit deletes the oldest files at once.")
        .build();

    let limit_mb = (app.prefs.borrow().history_storage_limit_bytes / (1024 * 1024)) as f64;
    let limit = adw::SpinRow::with_range(100.0, 32768.0, 100.0);
    limit.set_title("History and attachment limit (MB)");
    limit.set_value(limit_mb);
    {
        let app = app.clone();
        limit.connect_value_notify(move |row| {
            let bytes = (row.value() as u64) * 1024 * 1024;
            let mut prefs = app.prefs.borrow_mut();
            prefs.history_storage_limit_bytes = bytes;
            prefs.save();
            drop(prefs);
            std::thread::spawn(move || core::set_history_storage_limit_bytes(bytes));
        });
    }
    storage.add(&limit);
    page.add(&storage);

    let relays = adw::PreferencesGroup::builder()
        .title("Relays")
        .description(
            "A Circuit Relay v2 address you run or trust. This is the one reliable way for two \
             people on different networks to pair when they share no relay history.",
        )
        .build();

    let relay_row = adw::EntryRow::builder()
        .title("/ip4/…/tcp/4001/p2p/12D3Koo…")
        .show_apply_button(true)
        .build();
    {
        let app = app.clone();
        relay_row.connect_apply(move |row| {
            let address = row.text().to_string();
            if address.trim().is_empty() {
                return;
            }
            let (app, row) = (app.clone(), row.clone());
            let address = address.trim().to_string();
            app::run_in_background(
                move || core::add_known_relay_address(&address),
                move |result| match result {
                    Ok(()) => {
                        app.toast("Relay added.");
                        row.set_text("");
                    }
                    Err(error) => app.toast(&format!("Rejected: {}", error)),
                },
            );
        });
    }
    relays.add(&relay_row);

    let reconnect = adw::ActionRow::builder()
        .title("Reconnect now")
        .subtitle("Retries every known device immediately, ignoring the backoff.")
        .build();
    let reconnect_button = gtk::Button::builder()
        .label("Reconnect")
        .valign(gtk::Align::Center)
        .build();
    {
        let app = app.clone();
        reconnect_button.connect_clicked(move |_| {
            std::thread::spawn(|| {
                core::notify_network_changed();
                core::retry_all_pending_now();
            });
            app.toast("Reconnecting.");
        });
    }
    reconnect.add_suffix(&reconnect_button);
    relays.add(&reconnect);
    page.add(&relays);

    page.add(&servers_group(app));

    page
}

/// Sunucular (store-and-forward).
///
/// Rölelerden AYRI bir grup olması kasıtlı: bir röle hiçbir şey SAKLAMAZ,
/// sadece iki taraf da o anda bağlıyken canlı bir devre kurar. Sunucu ise
/// alıcı çevrimdışıyken zarfı diske yazar ve geri döndüğünde teslim eder.
/// Kullanıcı için görünen fark tam olarak budur; tek bir "adres ekle"
/// kutusunda birleştirmek yanlış beklenti yaratırdı.
fn servers_group(app: &Rc<App>) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder()
        .title("Servers")
        .description(
            "A server holds your messages while the other person is offline and delivers them when \
             they come back. It never sees them: they stay end-to-end encrypted and are sealed a \
             second time before being stored. Unlike a relay, a server actually stores — a relay \
             only forwards while both sides are online.",
        )
        .build();

    for entry in core::list_servers() {
        group.add(&server_row(app, &entry));
    }

    let add_row = adw::EntryRow::builder()
        .title("typeon-server:/dns/…onion/tcp/…/p2p/…#token")
        .show_apply_button(true)
        .build();
    {
        let app = app.clone();
        add_row.connect_apply(move |row| {
            let code = row.text().to_string();
            if code.trim().is_empty() {
                return;
            }
            let (app, row) = (app.clone(), row.clone());
            let code = code.trim().to_string();
            app::run_in_background(
                move || core::add_server(&code),
                move |result| match result {
                    Ok(()) => {
                        app.toast("Server added. Connecting…");
                        row.set_text("");
                        // Satır listesi yeniden çizilsin diye pencereyi tazele.
                        present_page(&app, Some("Network"));
                    }
                    Err(error) => app.toast(&format!("Rejected: {}", error)),
                },
            );
        });
    }
    group.add(&add_row);

    group
}

fn server_row(app: &Rc<App>, entry: &core::ServerEntry) -> adw::ExpanderRow {
    let title = if entry.name.is_empty() { entry.address.clone() } else { entry.name.clone() };
    // Kayıt (enrollment), operatörün yayımladığı katılım koduyla yapılır;
    // başarısız olursa sebebi burada görünür.
    let subtitle = match (&entry.last_error, entry.connected, entry.enrolled) {
        (Some(err), _, _) if !err.is_empty() => err.clone(),
        (_, true, true) => "Connected".to_string(),
        (_, true, false) => "Not enrolled".to_string(),
        _ => "Connecting…".to_string(),
    };
    let row = adw::ExpanderRow::builder()
        .title(gtk::glib::markup_escape_text(&title).as_str())
        .subtitle(gtk::glib::markup_escape_text(&subtitle).as_str())
        .build();

    let route = adw::SwitchRow::builder()
        .title("Route messages through this server")
        .active(entry.route_messages)
        .build();
    {
        let app = app.clone();
        let id = entry.server_id.clone();
        route.connect_active_notify(move |row| {
            let (app, id, on) = (app.clone(), id.clone(), row.is_active());
            app::run_in_background(
                move || core::set_server_routing(&id, on),
                move |result| {
                    if let Err(e) = result {
                        app.toast(&format!("Failed: {}", e));
                    }
                },
            );
        });
    }
    row.add_row(&route);

    let history = adw::SwitchRow::builder()
        .title("Store history on this server")
        .subtitle(
            "Lets a new device load your old messages. Unlike live messages this backup is not \
             forward-secret: whoever gets the archive key can read everything uploaded so far.",
        )
        .active(entry.store_history)
        .build();
    {
        let app = app.clone();
        let id = entry.server_id.clone();
        history.connect_active_notify(move |row| {
            if row.is_active() {
                // The archive root key is generated ONLY here — see
                // `secrets::ensure_archive_key`. Generating it at first launch
                // would mean a device that had not yet heard from its sibling
                // uploads an archive the others cannot read.
                match crate::secrets::ensure_archive_key(&app.data_dir) {
                    Ok(ark) => {
                        core::set_archive_root_key(&ark);
                    }
                    Err(e) => {
                        app.toast(&format!("Could not prepare the archive key: {}", e));
                        row.set_active(false);
                        return;
                    }
                }
            }
            let (app, id, on) = (app.clone(), id.clone(), row.is_active());
            app::run_in_background(
                move || core::set_server_history(&id, on),
                move |result| {
                    if let Err(e) = result {
                        app.toast(&format!("Failed: {}", e));
                    }
                },
            );
        });
    }
    row.add_row(&history);

    // For a device set up from scratch: the scroll-up flow assumes the
    // conversation is already on screen, but here there are no messages yet
    // and nothing to scroll.
    let restore = adw::ActionRow::builder()
        .title("Load my history from this server")
        .subtitle("Needed after restoring from a recovery file or linking this device.")
        .build();
    let restore_button = gtk::Button::builder().label("Load").valign(gtk::Align::Center).build();
    {
        let app = app.clone();
        restore_button.connect_clicked(move |_| {
            let app = app.clone();
            app::run_in_background(core::restore_server_history, move |result| match result {
                Ok(n) => app.toast(&format!("Loading history for {} conversations.", n)),
                Err(e) => app.toast(&format!("Failed: {}", e)),
            });
        });
    }
    restore.add_suffix(&restore_button);
    row.add_row(&restore);

    let remove = adw::ActionRow::builder().title("Remove this server").build();
    let remove_button = gtk::Button::builder()
        .label("Remove")
        .valign(gtk::Align::Center)
        .css_classes(vec!["destructive-action".to_string()])
        .build();
    {
        let app = app.clone();
        let id = entry.server_id.clone();
        remove_button.connect_clicked(move |_| {
            let (app, id) = (app.clone(), id.clone());
            app::run_in_background(
                move || core::remove_server(&id),
                move |result| match result {
                    Ok(()) => {
                        app.toast("Server removed.");
                        present_page(&app, Some("Network"));
                    }
                    Err(e) => app.toast(&format!("Failed: {}", e)),
                },
            );
        });
    }
    remove.add_suffix(&remove_button);
    row.add_row(&remove);

    row
}

/// Which colour preference a row edits. An enum rather than a pair of
/// closures per row: the three rows are otherwise identical, and this keeps
/// "read it" and "write it" next to each other where they cannot drift.
#[derive(Clone, Copy)]
enum ColorSlot {
    Accent,
    Background,
    Foreground,
}

impl ColorSlot {
    fn set(self, prefs: &mut crate::prefs::Prefs, value: Option<String>) {
        match self {
            ColorSlot::Accent => prefs.accent_color = value,
            ColorSlot::Background => prefs.background_color = value,
            ColorSlot::Foreground => prefs.foreground_color = value,
        }
    }
}

#[derive(Clone, Copy)]
enum ScaleSlot {
    Text,
    Ui,
}

impl ScaleSlot {
    fn get(self, prefs: &crate::prefs::Prefs) -> f64 {
        match self {
            ScaleSlot::Text => prefs.text_scale,
            ScaleSlot::Ui => prefs.ui_scale,
        }
    }

    fn set(self, prefs: &mut crate::prefs::Prefs, value: f64) {
        match self {
            ScaleSlot::Text => prefs.text_scale = value,
            ScaleSlot::Ui => prefs.ui_scale = value,
        }
    }

    fn bounds(self) -> (f64, f64) {
        match self {
            ScaleSlot::Text => (crate::prefs::TEXT_SCALE_MIN, crate::prefs::TEXT_SCALE_MAX),
            ScaleSlot::Ui => (crate::prefs::UI_SCALE_MIN, crate::prefs::UI_SCALE_MAX),
        }
    }
}

/// Built-in font choices — generic CSS families resolve on any desktop via
/// fontconfig, so nothing has to be bundled.
const BUILT_IN_FONTS: [(&str, Option<&str>); 5] = [
    ("System default", None),
    ("Sans", Some("sans-serif")),
    ("Serif", Some("serif")),
    ("Monospace", Some("monospace")),
    ("Cantarell", Some("Cantarell")),
];

/// Rebuild the font selector model (built-in fonts + custom fonts +
/// "Import a font" at the top).
fn rebuild_font_model(app: &Rc<App>, active_id: Option<&str>, font_row: &adw::ComboRow) {
    let custom_fonts = app.list_custom_fonts();

    // Build labels: [0]="Load a custom font …", [1..]=built-in fonts,
    // [built-in+1..]=custom fonts.
    let mut labels: Vec<String> = vec!["Load a custom font…".to_string()];
    labels.extend(BUILT_IN_FONTS.iter().map(|(l, _)| l.to_string()));
    labels.extend(custom_fonts.iter().map(|f| f.display_name.clone()));

    font_row.set_model(Some(&gtk::StringList::new(
        &labels.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    )));

    // Determine which index is currently active.
    let active_idx = if let Some(aid) = active_id {
        if let Some(pos) = custom_fonts.iter().position(|f| f.id == aid) {
            // Built-in fonts count + 1 for "Load…", then the custom font index.
            Some(BUILT_IN_FONTS.len() + 1 + pos)
        } else {
            None
        }
    } else {
        // Check if a built-in font is active.
        let current_family = &app.prefs.borrow().font_family;
        BUILT_IN_FONTS
            .iter()
            .position(|(_, value)| value.map(|s| s.to_string()) == *current_family)
            .map(|i| i + 1) // +1 for "Load…" option
    };

    font_row.set_selected(active_idx.unwrap_or(0) as u32);
}

fn appearance_page(app: &Rc<App>) -> adw::PreferencesPage {
    let page = adw::PreferencesPage::builder()
        .title("Appearance")
        .name("appearance")
        .icon_name("applications-graphics-symbolic")
        .build();

    // --- colour scheme ---
    let scheme_group = adw::PreferencesGroup::builder().title("Theme").build();
    let theme = adw::ComboRow::builder().title("Colour scheme").build();
    theme.set_model(Some(&gtk::StringList::new(&["Follow system", "Light", "Dark"])));
    theme.set_selected(match app.prefs.borrow().dark_mode {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
    {
        let app = app.clone();
        theme.connect_selected_notify(move |row| {
            let choice = match row.selected() {
                1 => Some(false),
                2 => Some(true),
                _ => None,
            };
            {
                let mut prefs = app.prefs.borrow_mut();
                prefs.dark_mode = choice;
                prefs.save();
            }
            apply_theme(&app);
        });
    }
    scheme_group.add(&theme);
    page.add(&scheme_group);

    // --- colours ---
    let colours = adw::PreferencesGroup::builder()
        .title("Colours")
        .description(
            "The accent seeds a full Material 3 tonal palette — surfaces, containers and states are all derived from it. Background and text override the two roles that palette would otherwise pick for you.",
        )
        .build();
    colours.add(&color_row(
        app,
        ColorSlot::Accent,
        "Accent",
        "Seeds the whole palette.",
    ));
    colours.add(&color_row(
        app,
        ColorSlot::Background,
        "Background",
        "Window surface. Cards and popovers are stepped off it.",
    ));
    colours.add(&color_row(
        app,
        ColorSlot::Foreground,
        "Text",
        "Foreground colour on those surfaces.",
    ));
    page.add(&colours);

    // --- sizes ---
    let sizes = adw::PreferencesGroup::builder()
        .title("Size")
        .description(
            "Text scales the font only. Interface scales everything — spacing and controls as well — through the toolkit's own density setting, so it stacks on top.",
        )
        .build();
    sizes.add(&scale_row(app, ScaleSlot::Text, "Text size"));
    sizes.add(&scale_row(app, ScaleSlot::Ui, "Interface size"));
    page.add(&sizes);

    // --- font ---
    let typography = adw::PreferencesGroup::builder().title("Typography").build();
    let font = adw::ComboRow::builder().title("Font").build();

    rebuild_font_model(&app, app.active_custom_font_id().as_deref(), &font);

    {
        let app = app.clone();
        font.connect_selected_notify(move |row| {
            // `row` itself, not a captured clone: a self-capture would be a
            // reference cycle that leaks the row.
            let font_for_closure = row;
            let idx = row.selected() as usize;
            if idx == 0 {
                // "Load a custom font…" — open file picker.
                pick_font(&app, font_for_closure);
            } else if idx <= BUILT_IN_FONTS.len() {
                // Built-in font selected (idx 1..=5 → index 0..4).
                let choice = BUILT_IN_FONTS
                    .get(idx - 1)
                    .and_then(|(_, value)| value.map(str::to_string));
                {
                    let mut prefs = app.prefs.borrow_mut();
                    prefs.font_family = choice;
                    prefs.active_custom_font_id = None;
                    prefs.save();
                }
                rebuild_font_model(&app, None, font_for_closure);
                apply_theme(&app);
            } else {
                // Custom font selected (idx > BUILT_IN_FONTS.len() + 1).
                let custom_fonts = app.list_custom_fonts();
                let custom_idx = idx - 1 - BUILT_IN_FONTS.len();
                if let Some(cf) = custom_fonts.get(custom_idx) {
                    app.set_active_custom_font(Some(&cf.id));
                    rebuild_font_model(&app, Some(&cf.id), font_for_closure);
                    apply_theme(&app);
                }
            }
        });
    }

    // "Load…" button next to the font selector.
    let load_button = gtk::Button::builder()
        .label("Load…")
        .valign(gtk::Align::Center)
        .build();
    {
        let app = app.clone();
        let font_for_button = font.downgrade();
        load_button.connect_clicked(move |_| {
            if let Some(font) = font_for_button.upgrade() {
                pick_font(&app, &font);
            }
        });
    }
    font.add_suffix(&load_button);

    typography.add(&font);
    page.add(&typography);

    // --- wallpaper ---
    let wallpaper_group = adw::PreferencesGroup::builder()
        .title("Chat wallpaper")
        .description("Drawn behind the message bubbles.")
        .build();
    let wallpaper = adw::ActionRow::builder()
        .title("Background image")
        .subtitle(
            app.prefs
                .borrow()
                .chat_wallpaper
                .clone()
                .unwrap_or_else(|| "None".to_string())
                .as_str(),
        )
        .build();
    let choose_wallpaper = gtk::Button::builder()
        .label("Choose…")
        .valign(gtk::Align::Center)
        .build();
    {
        let app = app.clone();
        // Weak: the button is a suffix of this row.
        let wallpaper = wallpaper.downgrade();
        choose_wallpaper.connect_clicked(move |_| {
            if let Some(wallpaper) = wallpaper.upgrade() {
                pick_wallpaper(&app, &wallpaper);
            }
        });
    }
    wallpaper.add_suffix(&choose_wallpaper);
    let clear_wallpaper = gtk::Button::builder()
        .icon_name("edit-undo-symbolic")
        .tooltip_text("Remove")
        .valign(gtk::Align::Center)
        .build();
    clear_wallpaper.add_css_class("flat");
    {
        let app = app.clone();
        let wallpaper = wallpaper.downgrade();
        clear_wallpaper.connect_clicked(move |_| {
            {
                let mut prefs = app.prefs.borrow_mut();
                prefs.chat_wallpaper = None;
                prefs.save();
            }
            if let Some(wallpaper) = wallpaper.upgrade() {
                wallpaper.set_subtitle("None");
            }
            apply_theme(&app);
        });
    }
    wallpaper.add_suffix(&clear_wallpaper);
    wallpaper_group.add(&wallpaper);
    page.add(&wallpaper_group);

    page
}

fn pick_wallpaper(app: &Rc<App>, row: &adw::ActionRow) {
    let Some(window) = app.window() else { return };
    let dialog = gtk::FileDialog::builder()
        .title("Choose a chat wallpaper")
        .build();
    let app = app.clone();
    let row = row.clone();
    dialog.open(Some(&window), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let path = path.to_string_lossy().to_string();
        {
            let mut prefs = app.prefs.borrow_mut();
            prefs.chat_wallpaper = Some(path.clone());
            prefs.save();
        }
        row.set_subtitle(&path);
        apply_theme(&app);
    });
}

/// Open a file picker for `.ttf`/`.otf` font files.
fn pick_font(app: &Rc<App>, font_row: &adw::ComboRow) {
    let Some(window) = app.window() else { return };
    let dialog = gtk::FileDialog::builder()
        .title("Choose a font file")
        .build();

    let app = app.clone();
    let font_row = font_row.clone();
    dialog.open(Some(&window), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let path = path.to_string_lossy().to_string();

        // Get the display name from the file stem.
        let display_name = std::path::Path::new(&path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Custom")
            .to_string();

        if let Err(e) = app.import_font(&path, &display_name) {
            app.toast(&format!("Failed to load font: {e}"));
            return;
        }

        // Reload the font list and select the newly imported font.
        app.font_manager.borrow_mut().discover();
        rebuild_font_model(&app, app.active_custom_font_id().as_deref(), &font_row);
        apply_theme(&app);
    });
}

/// A colour row: swatch button plus a reset back to the palette default.
fn color_row(app: &Rc<App>, slot: ColorSlot, title: &str, subtitle: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(subtitle)
        .build();

    let picker = gtk::ColorDialogButton::new(Some(gtk::ColorDialog::new()));
    picker.set_valign(gtk::Align::Center);
    {
        // Seed the swatch with what is actually in use, not the widget's own
        // default — an untouched row otherwise shows a colour that appears
        // nowhere in the app.
        let dark = adw::StyleManager::default().is_dark();
        let appearance =
            crate::theme::Appearance::from_prefs(&app.prefs.borrow(), dark, base_font_pt(), None);
        let (accent, background, foreground) = crate::theme::effective_colors(&appearance);
        let current = match slot {
            ColorSlot::Accent => accent,
            ColorSlot::Background => background,
            ColorSlot::Foreground => foreground,
        };
        if let Ok(rgba) = current.parse::<gtk::gdk::RGBA>() {
            picker.set_rgba(&rgba);
        }
    }
    {
        let app = app.clone();
        picker.connect_rgba_notify(move |button| {
            let rgba = button.rgba();
            let hex = format!(
                "#{:02x}{:02x}{:02x}",
                (rgba.red() * 255.0).round() as u8,
                (rgba.green() * 255.0).round() as u8,
                (rgba.blue() * 255.0).round() as u8
            );
            {
                let mut prefs = app.prefs.borrow_mut();
                slot.set(&mut prefs, Some(hex));
                prefs.save();
            }
            apply_theme(&app);
        });
    }
    row.add_suffix(&picker);

    let reset = gtk::Button::builder()
        .icon_name("edit-undo-symbolic")
        .tooltip_text("Back to the palette default")
        .valign(gtk::Align::Center)
        .build();
    reset.add_css_class("flat");
    {
        let app = app.clone();
        reset.connect_clicked(move |_| {
            {
                let mut prefs = app.prefs.borrow_mut();
                slot.set(&mut prefs, None);
                prefs.save();
            }
            apply_theme(&app);
        });
    }
    row.add_suffix(&reset);
    row
}

/// A slider row showing its value as a percentage, matching the Android
/// sliders' range and 5% steps.
fn scale_row(app: &Rc<App>, slot: ScaleSlot, title: &str) -> adw::ActionRow {
    const STEP: f64 = 0.05;
    let (min, max) = slot.bounds();
    let current = slot.get(&app.prefs.borrow());

    let value_label = gtk::Label::new(Some(&format!("{}%", (current * 100.0).round() as i32)));
    value_label.add_css_class("dim-label");
    value_label.set_width_chars(5);

    let scale = gtk::Scale::with_range(gtk::Orientation::Horizontal, min, max, STEP);
    scale.set_value(current);
    scale.set_draw_value(false);
    scale.set_hexpand(true);
    scale.set_size_request(220, -1);
    scale.set_valign(gtk::Align::Center);

    {
        let app = app.clone();
        let value_label = value_label.clone();
        // `value-changed` fires continuously while dragging. Snapping to the
        // 5% step and skipping repeats keeps that from rebuilding the whole
        // stylesheet on every pixel of travel.
        let last = std::cell::Cell::new(current);
        scale.connect_value_changed(move |scale| {
            let snapped = ((scale.value() / STEP).round() * STEP).clamp(min, max);
            if (snapped - last.get()).abs() < STEP / 2.0 {
                return;
            }
            last.set(snapped);
            value_label.set_label(&format!("{}%", (snapped * 100.0).round() as i32));
            {
                let mut prefs = app.prefs.borrow_mut();
                slot.set(&mut prefs, snapped);
                prefs.save();
            }
            apply_theme(&app);
        });
    }

    let row = adw::ActionRow::builder().title(title).build();
    row.add_suffix(&scale);
    row.add_suffix(&value_label);
    row
}

fn security_page(app: &Rc<App>) -> adw::PreferencesPage {
    let page = adw::PreferencesPage::builder()
        .title("Security")
        .icon_name("channel-secure-symbolic")
        .build();

    let identity = adw::PreferencesGroup::builder().title("This device").build();
    identity.add(
        &adw::ActionRow::builder()
            .title("Safety number")
            .subtitle(core::identity_short_code().unwrap_or_default().as_str())
            .build(),
    );
    let devices = adw::ActionRow::builder()
        .title("Linked devices")
        .subtitle("Every device on your account, and which one this is.")
        .activatable(true)
        .build();
    {
        let app = app.clone();
        devices.connect_activated(move |_| dialogs::linked_devices(&app));
    }
    identity.add(&devices);
    let hide_content = adw::SwitchRow::builder()
        .title("Hide message content in notifications")
        .subtitle("Notifications say \"New message\" without the sender or the text.")
        .active(app.prefs.borrow().hide_notification_content)
        .build();
    {
        let app = app.clone();
        hide_content.connect_active_notify(move |row| {
            let mut prefs = app.prefs.borrow_mut();
            prefs.hide_notification_content = row.is_active();
            prefs.save();
        });
    }
    identity.add(&hide_content);
    page.add(&identity);

    let profile = adw::PreferencesGroup::builder().title("Profile").build();

    // User request (2026-09-04): the account name was fixed forever at the
    // device name typed during onboarding. Changing it here notifies every
    // contact over the same ratchet channel the profile picture uses, so
    // contacts that are offline get it when they return.
    let name_row = adw::EntryRow::builder()
        .title("Account name")
        .show_apply_button(true)
        .build();
    name_row.set_text(&core::display_name());
    {
        let app = app.clone();
        name_row.connect_apply(move |row| {
            let name = row.text().to_string();
            if name.trim().is_empty() {
                return;
            }
            let app = app.clone();
            let name = name.trim().to_string();
            // Fan-out encrypts once per contact — same reason the profile
            // picture calls go through the background helper.
            app::run_in_background(
                move || core::set_display_name(&name),
                move |result| match result {
                    Ok(()) => app.toast("Name changed. Contacts are being notified."),
                    Err(error) => app.toast(&error),
                },
            );
        });
    }
    profile.add(&name_row);

    let picture = adw::ActionRow::builder()
        .title("Profile picture")
        .subtitle("Sent to every contact you have paired with.")
        .build();

    let choose = gtk::Button::builder()
        .label("Choose…")
        .valign(gtk::Align::Center)
        .build();
    {
        let app = app.clone();
        choose.connect_clicked(move |_| pick_profile_picture(&app));
    }
    picture.add_suffix(&choose);

    let clear = gtk::Button::builder()
        .label("Remove")
        .valign(gtk::Align::Center)
        .build();
    {
        let app = app.clone();
        clear.connect_clicked(move |_| {
            let app = app.clone();
            // Removal broadcasts a ProfileUpdate to everyone, so it is not
            // instant either.
            app::run_in_background(
                move || core::set_own_profile_picture(None),
                move |result| match result {
                    Ok(()) => app.toast("Profile picture removed."),
                    Err(error) => app.toast(&error),
                },
            );
        });
    }
    picture.add_suffix(&clear);
    profile.add(&picture);
    page.add(&profile);

    let vault_description = format!(
        "This device's own keys live in a file in your data directory, sealed with a key that \
         exists only inside {}. Typeon will not start if that store is unavailable.",
        app.keyring_backend.display_name()
    );
    let vault = adw::PreferencesGroup::builder()
        .title("Local vault")
        .description(vault_description.as_str())
        .build();

    vault.add(
        &adw::ActionRow::builder()
            .title("Sealed by")
            .subtitle(app.keyring_backend.display_name())
            .build(),
    );

    let protected = secrets::is_passphrase_protected(&app.data_dir);
    let passphrase = adw::ActionRow::builder()
        .title(if protected {
            "Change or remove the extra passphrase"
        } else {
            "Add an extra passphrase"
        })
        .subtitle(if protected {
            "Wallet key plus a passphrase — both are needed to open the vault."
        } else {
            "Wallet key only. Adding a passphrase asks for it on every launch."
        })
        .activatable(true)
        .build();
    {
        let app = app.clone();
        passphrase.connect_activated(move |_| change_passphrase(&app, protected));
    }
    vault.add(&passphrase);

    let recovery = adw::ActionRow::builder()
        .title("Export a recovery file")
        .subtitle(
            "A passphrase-protected backup of this device's keys. It restores this device — it \
             does not move your account.",
        )
        .activatable(true)
        .build();
    {
        let app = app.clone();
        recovery.connect_activated(move |_| export_recovery(&app));
    }
    vault.add(&recovery);
    page.add(&vault);

    let danger = adw::PreferencesGroup::builder()
        .title("Account")
        .description(
            "Logging out erases this device's identity, message archive and attachments from this computer. It does not touch your other devices, and it cannot be undone without a recovery file.",
        )
        .build();
    let logout = adw::ActionRow::builder()
        .title("Log out and erase this device")
        .activatable(true)
        .build();
    logout.add_css_class("error");
    {
        let app = app.clone();
        logout.connect_activated(move |_| confirm_logout(&app));
    }
    danger.add(&logout);
    let delete_account = adw::ActionRow::builder()
        .title("Delete account")
        .subtitle("Tells every contact and group the account is gone, wipes your linked devices, then erases this device")
        .activatable(true)
        .build();
    delete_account.add_css_class("error");
    {
        let app = app.clone();
        delete_account.connect_activated(move |_| confirm_delete_account(&app));
    }
    danger.add(&delete_account);
    page.add(&danger);

    page
}

/// Deletes the account everywhere: the core sends `AccountDeleted` to every
/// contact and sibling device, we wait (bounded) for the acks so offline
/// contacts at least get it deposited on a server, then erase like logout.
fn confirm_delete_account(app: &Rc<App>) {
    // The core refuses it on a linked device; say why instead of failing late.
    let root = core::own_identity_id().ok().is_some_and(|id| {
        core::list_linked_devices().iter().any(|d| d.is_this_device && d.device_fingerprint == id)
    });
    if !root {
        app.toast("Only the primary device can delete the account.");
        return;
    }
    let app_for_action = app.clone();
    dialogs::confirm(
        app,
        "Delete your account?",
        "All your contacts and groups are told this account was deleted, and they can no longer message you. Your linked devices are wiped too. This cannot be undone.",
        "Delete account",
        true,
        move || {
            app_for_action.toast("Notifying your contacts…");
            let app_done = app_for_action.clone();
            app::run_in_background(
                || {
                    if core::delete_account() >= 0 {
                        let deadline = util::now_ms() + 15_000;
                        while util::now_ms() < deadline && core::account_deletion_pending() != 0 {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                        }
                    }
                },
                move |()| erase_profile_and_quit(&app_done),
            );
        },
    );
}

fn erase_profile_and_quit(app: &Rc<App>) {
    // Keyring first: if the data directory went but the key stayed, a later
    // profile in the same directory would find a key that opens nothing.
    let profile = app.data_dir.to_string_lossy().to_string();
    if let Err(error) = crate::keyring::delete_key(&profile) {
        eprintln!("typeon: could not remove the vault key: {error}");
    }
    if let Err(error) = std::fs::remove_dir_all(&app.data_dir) {
        app.toast(&format!("Could not erase the data directory: {error}"));
        return;
    }
    // The core still holds the identity in memory and the poll thread is still
    // running against a database that no longer exists, so stop the process.
    app.application.quit();
}

/// Wipes the profile. Deliberately two-step and explicit about what survives.
fn confirm_logout(app: &Rc<App>) {
    let app_for_action = app.clone();
    dialogs::confirm(
        app,
        "Erase this device?",
        "The identity, every message and every downloaded attachment on this computer are deleted, along with the key held in your system keyring. Your other devices keep working, and contacts keep talking to them. Without a recovery file this cannot be undone.",
        "Erase",
        true,
        move || erase_profile_and_quit(&app_for_action),
    );
}

// --- actions ---

fn pick_profile_picture(app: &Rc<App>) {
    let Some(window) = app.window() else { return };
    let dialog = gtk::FileDialog::builder().title("Choose a profile picture").build();
    let app = app.clone();
    dialog.open(Some(&window), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        // 720p/85% — the same budget the phone uses, so the bytes that reach
        // a contact look the same whichever device sent them.
        let source = path.to_string_lossy().to_string();
        let app_inner = app.clone();
        app::run_in_background(
            move || match util::scaled_jpeg(&source, 720, 85) {
                Some(jpeg) => core::set_own_profile_picture(Some(jpeg)),
                None => Err("That file is not an image Typeon can read.".to_string()),
            },
            move |result| match result {
                Ok(()) => app_inner.toast("Profile picture updated."),
                Err(error) => app_inner.toast(&error),
            },
        );
    });
}

fn change_passphrase(app: &Rc<App>, currently_protected: bool) {
    let Some(window) = app.window() else { return };

    let current = gtk::PasswordEntry::builder().show_peek_icon(true).build();
    current.set_placeholder_text(Some("Current passphrase"));
    let next = gtk::PasswordEntry::builder().show_peek_icon(true).build();
    next.set_placeholder_text(Some("New passphrase (empty removes it)"));

    let fields = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(8)
        .build();
    if currently_protected {
        fields.append(&current);
    }
    fields.append(&next);

    let dialog = adw::MessageDialog::new(
        Some(&window),
        Some("Extra passphrase"),
        Some(
            "This is a second factor on top of the system keyring, not a replacement for it — \
             the vault stays sealed either way. Leaving the new passphrase empty goes back to \
             keyring-only, with no prompt on launch.",
        ),
    );
    dialog.set_extra_child(Some(&crate::ui::widgets::dialog_field(&fields)));
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("apply", "Apply");
    dialog.set_default_response(Some("apply"));
    dialog.set_close_response("cancel");
    dialog.set_response_appearance("apply", adw::ResponseAppearance::Suggested);

    let app = app.clone();
    dialog.connect_response(None, move |_, response| {
        if response != "apply" {
            return;
        }
        let old = if currently_protected {
            current.text().to_string()
        } else {
            String::new()
        };
        // Two Argon2id derivations: off the main thread.
        let data_dir = app.data_dir.clone();
        let new = next.text().to_string();
        let removing = new.is_empty();
        let app = app.clone();
        app::run_in_background(
            move || onboarding::reseal_vault(&data_dir, &old, &new),
            move |result| match result {
                Ok(()) => app.toast(if removing { "Passphrase removed." } else { "Passphrase updated." }),
                Err(error) => app.toast(&error),
            },
        );
    });
    dialog.present();
}

fn export_recovery(app: &Rc<App>) {
    let app_for_prompt = app.clone();
    let Some(window) = app.window() else { return };

    let entry = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .activates_default(true)
        .build();
    let dialog = adw::MessageDialog::new(
        Some(&window),
        Some("Export a recovery file"),
        Some("Choose a passphrase. The file is hardened with Argon2id and is useless without it."),
    );
    dialog.set_extra_child(Some(&crate::ui::widgets::dialog_field(&entry)));
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("export", "Export");
    dialog.set_default_response(Some("export"));
    dialog.set_close_response("cancel");
    dialog.set_response_appearance("export", adw::ResponseAppearance::Suggested);

    dialog.connect_response(None, move |_, response| {
        if response != "export" {
            return;
        }
        let passphrase = entry.text().to_string();
        if passphrase.is_empty() {
            app_for_prompt.toast("A recovery file without a passphrase would protect nothing.");
            return;
        }
        // The core refuses it too, but its export call returns no reason.
        if passphrase.chars().count() < p2p_messenger::RECOVERY_PASSPHRASE_MIN_CHARS {
            app_for_prompt.toast("The passphrase must have at least 12 characters.");
            return;
        }
        let app = app_for_prompt.clone();
        // Argon2id is deliberately slow — off the main thread it goes.
        app::run_in_background(
            move || core::export_recovery(&passphrase),
            move |bytes| {
                if bytes.is_empty() {
                    app.toast("Export failed.");
                    return;
                }
                save_recovery_bytes(&app, bytes);
            },
        );
    });
    dialog.present();
}

fn save_recovery_bytes(app: &Rc<App>, bytes: Vec<u8>) {
    let Some(window) = app.window() else { return };
    let dialog = gtk::FileDialog::builder()
        .title("Save recovery file")
        .initial_name("typeon-recovery.bin")
        .build();
    let app = app.clone();
    dialog.save(Some(&window), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        // Every long-term key is in this file: owner-only from the first byte.
        // Fresh temp file (`create_new` => the 0600 mode really applies), checked
        // chmod, fsync, then rename over the target.
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut tmp_name = path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp_name);
        let _ = std::fs::remove_file(&tmp);
        // A USB stick (FAT/exFAT) has no Unix permissions: the file is still
        // written (it is passphrase-encrypted), but the user is told.
        let mut private = true;
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut file| {
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
                private = file.metadata()?.permissions().mode() & 0o077 == 0;
                file.write_all(&bytes)?;
                file.sync_all()
            })
            .and_then(|()| std::fs::rename(&tmp, &path));
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        match written {
            Ok(()) if private => app.toast(&format!("Recovery file written to {}", path.display())),
            Ok(()) => app.toast(&format!(
                "Recovery file written to {}. This drive cannot make it private: anyone with access can copy it (it stays passphrase-protected)",
                path.display()
            )),
            Err(error) => app.toast(&format!("Could not write the file: {}", error)),
        }
    });
}

// --- theming ---

/// Applies the saved appearance: colour scheme, Material 3 palette, text size
/// and overall density. Called at startup and whenever any of them changes.
///
/// Providers are additive on a GdkDisplay and there is no "replace" call, so
/// re-applying would stack a new one on top of the last every time a slider
/// moves. The previous provider is therefore removed first — otherwise a few
/// minutes of fiddling in Settings leaves dozens of stylesheets live and the
/// oldest ones still winning wherever the newest is silent.
pub fn apply_theme(app: &Rc<App>) {
    thread_local! {
        static ACTIVE: RefCell<Option<gtk::CssProvider>> = const { RefCell::new(None) };
    }

    let manager = adw::StyleManager::default();
    manager.set_color_scheme(match app.prefs.borrow().dark_mode {
        Some(true) => adw::ColorScheme::ForceDark,
        Some(false) => adw::ColorScheme::ForceLight,
        None => adw::ColorScheme::Default,
    });

    let Some(display) = gtk::gdk::Display::default() else {
        return;
    };

    // Density first: it is a GtkSettings property, not CSS, and it also
    // changes what a "pt" resolves to — so the stylesheet below is built after
    // it is in place.
    let ui_scale = app.prefs.borrow().ui_scale;
    apply_ui_scale(ui_scale);

    // Discover custom fonts, register the active one with the system font
    // database, and extract its CSS family name.
    {
        let mut fm = app.font_manager.borrow_mut();
        fm.discover();
        let active_id = app.active_custom_font_id();
        fm.set_active(active_id);
    }
    let custom_font_family = {
        let mut fm = app.font_manager.borrow_mut();
        fm.register_active()
    };

    let dark = manager.is_dark();
    let appearance =
        crate::theme::Appearance::from_prefs(&app.prefs.borrow(), dark, base_font_pt(), custom_font_family);
    let css = crate::theme::stylesheet(&appearance);

    // Dev aid: the generated sheet is ~400 lines of interpolated text and a
    // wrong brace in it fails silently. `TYPEON_DUMP_CSS=1` prints it.
    if std::env::var("TYPEON_DUMP_CSS").is_ok() {
        eprintln!("---CSS-START---\n{css}\n---CSS-END---");
    }
    let provider = gtk::CssProvider::new();
    // A malformed rule makes GTK silently drop it and keep going, which is very
    // hard to spot from the rendering alone — surface it instead.
    provider.connect_parsing_error(|_, section, error| {
        eprintln!("typeon: CSS error at {}: {}", section.to_str(), error);
    });
    // `load_from_string` is GTK 4.12; these bindings target the 4.10 baseline,
    // where the equivalent already takes a plain `&str`.
    provider.load_from_data(&css);

    ACTIVE.with(|active| {
        if let Some(previous) = active.borrow_mut().take() {
            gtk::style_context_remove_provider_for_display(&display, &previous);
        }
        // USER, not APPLICATION. libadwaita 1.6+ ships its own accent-colour
        // provider (the desktop's system accent), and it sits above
        // APPLICATION — so at that priority the palette reached hand-styled
        // widgets like the chat bubbles but stock ones such as switches and
        // check buttons kept the system accent, which looked like a bug.
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_USER,
        );
        *active.borrow_mut() = Some(provider);
    });
}

/// The desktop's own font size in points, which the text-size slider scales.
/// Starting from the system font rather than a hardcoded number means 100%
/// looks like every other app on the machine.
fn base_font_pt() -> f64 {
    gtk::Settings::default()
        .and_then(|settings| settings.gtk_font_name())
        .and_then(|font| {
            font.rsplit_once(' ')
                .and_then(|(_, size)| size.parse::<f64>().ok())
        })
        .filter(|size| *size > 0.0)
        .unwrap_or(11.0)
}

/// Density, via the toolkit's own scaling knob. `gtk-xft-dpi` is in 1024ths of
/// a DPI; the machine's current value is captured once so a HiDPI desktop is
/// scaled relative to its own setting rather than reset to 96.
fn apply_ui_scale(scale: f64) {
    use std::sync::OnceLock;
    static BASE_DPI: OnceLock<i32> = OnceLock::new();

    let Some(settings) = gtk::Settings::default() else {
        return;
    };
    let base = *BASE_DPI.get_or_init(|| {
        let current = settings.gtk_xft_dpi();
        if current > 0 {
            current
        } else {
            96 * 1024
        }
    });
    settings.set_gtk_xft_dpi(((base as f64) * scale).round() as i32);
}

