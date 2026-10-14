//! In-app viewer for photos, video and voice messages.
//!
//! Images are drawn with gdk-pixbuf, which is part of GTK and always present.
//!
//! Audio and video need a *media backend* — a separate GTK module
//! (`libmedia-gstreamer.so`) that not every distribution installs, and which is
//! genuinely absent on some. There is no build-time way to know, so the viewer
//! creates the `GtkMediaFile` and watches its `error` property: if playback
//! cannot start, the pane swaps itself for an explanation and a button that
//! hands the file to the desktop's own player. That is much better than a
//! silent black rectangle, which is what a naive playback pane gives you.

use std::cell::Cell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::gdk_pixbuf;
use gtk::gio;
use gtk::glib;

use crate::app::App;
use crate::util;

/// Zoom bounds for the image viewer's scroll-to-zoom.
const MIN_ZOOM: f64 = 0.2;
const MAX_ZOOM: f64 = 8.0;
/// Largest image the viewer decodes: 64 megapixels is 256 MB of RGBA.
const MAX_IMAGE_PIXELS: i64 = 64_000_000;

/// Opens `path` in a viewer window, choosing the pane by MIME type. Anything
/// that is not an image, video or audio file is handed straight to the desktop.
pub fn open(app: &Rc<App>, path: &str, mime: &str, title: &str) {
    if !(util::is_image(mime) || util::is_video(mime) || util::is_audio(mime)) {
        // The sender picks the extension: handing it to the default app could
        // run a `.exe` (wine), `.jar` or `.desktop` in one click. Only known
        // document types are launched; anything else is offered as a save.
        if is_safe_to_launch(path) {
            launch_externally(app, path);
        } else {
            save_copy(app, path, title);
        }
        return;
    }

    let Some(parent) = app.window() else { return };

    let header = adw::HeaderBar::new();
    let external = gtk::Button::builder()
        .icon_name("external-link-symbolic")
        .tooltip_text("Open with the system application")
        .build();
    {
        let app = app.clone();
        let path = path.to_string();
        external.connect_clicked(move |_| launch_externally(&app, &path));
    }
    header.pack_end(&external);

    let save = gtk::Button::builder()
        .icon_name("document-save-symbolic")
        .tooltip_text("Save a copy")
        .build();
    {
        let app = app.clone();
        let path = path.to_string();
        let name = title.to_string();
        save.connect_clicked(move |_| save_copy(&app, &path, &name));
    }
    header.pack_end(&save);

    let content: gtk::Widget = if util::is_image(mime) {
        image_pane(path)
    } else {
        playback_pane(app, path, util::is_video(mime))
    };

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&content));

    adw::Window::builder()
        .transient_for(&parent)
        .title(title)
        .default_width(900)
        .default_height(640)
        .content(&toolbar)
        .build()
        .present();
}

/// A photo, scrollable to pan and mouse-wheel-scrollable to zoom.
///
/// The picture is given an explicit size in image pixels scaled by the
/// current zoom, rather than living at `hexpand`/`vexpand`+`Contain` as a
/// plain unzoomed viewer would: `GtkScrolledWindow` only offers scrollbars
/// (and, here, the drag-to-pan below) once its child's natural size exceeds
/// the viewport, so the size request *is* what makes zooming past 100%
/// scrollable at all.
fn image_pane(path: &str) -> gtk::Widget {
    // Header only, nothing is decoded here. The file is the sender's: the
    // decoder is picked from its content, so only the common formats are let
    // through, and a canvas large enough to exhaust memory is refused.
    let natural_size = gdk_pixbuf::Pixbuf::file_info(path).and_then(|(format, width, height)| {
        let known = matches!(format.name().as_deref(), Some("jpeg" | "png" | "gif" | "webp"));
        (known && width as i64 * height as i64 <= MAX_IMAGE_PIXELS).then_some((width, height))
    });
    let Some((natural_w, natural_h)) = natural_size else {
        return adw::StatusPage::builder()
            .icon_name("dialog-warning-symbolic")
            .title("Cannot show this image here")
            .description("Its format is not supported or it is too large. Use \"Save a copy\".")
            .build()
            .upcast();
    };

    let picture = gtk::Picture::for_filename(path);
    picture.set_can_shrink(true);
    // Fit, never crop: a viewer that silently cuts the edges off a photo is
    // worse than one that letterboxes it.
    picture.set_content_fit(gtk::ContentFit::Contain);
    picture.set_halign(gtk::Align::Center);
    picture.set_valign(gtk::Align::Center);

    let scroller = gtk::ScrolledWindow::builder()
        .hexpand(true)
        .vexpand(true)
        .child(&picture)
        .build();

    let zoom = Rc::new(Cell::new(1.0f64));
    let scroll = gtk::EventControllerScroll::new(gtk::EventControllerScrollFlags::VERTICAL);
    {
        let picture = picture.clone();
        let zoom = zoom.clone();
        scroll.connect_scroll(move |_, _dx, dy| {
            // Scroll up (dy < 0) zooms in, matching every other app that
            // treats the wheel this way (image viewers, maps, browsers).
            let factor = if dy < 0.0 { 1.1 } else { 1.0 / 1.1 };
            let next = (zoom.get() * factor).clamp(MIN_ZOOM, MAX_ZOOM);
            zoom.set(next);
            picture.set_size_request(
                (natural_w as f64 * next).round() as i32,
                (natural_h as f64 * next).round() as i32,
            );
            glib::Propagation::Stop
        });
    }
    scroller.add_controller(scroll);

    // Once zoomed in, most of the image sits outside the viewport; a plain
    // `GtkScrolledWindow` only pans via its scrollbars or touch, so a drag
    // gesture is the desktop-mouse equivalent.
    let drag = gtk::GestureDrag::new();
    let drag_origin = Rc::new(Cell::new((0.0, 0.0)));
    {
        let scroller = scroller.clone();
        let drag_origin = drag_origin.clone();
        drag.connect_drag_begin(move |_, _, _| {
            drag_origin.set((scroller.hadjustment().value(), scroller.vadjustment().value()));
        });
    }
    {
        let scroller = scroller.clone();
        drag.connect_drag_update(move |_, offset_x, offset_y| {
            let (start_h, start_v) = drag_origin.get();
            scroller.hadjustment().set_value(start_h - offset_x);
            scroller.vadjustment().set_value(start_v - offset_y);
        });
    }
    scroller.add_controller(drag);

    scroller.upcast()
}

/// Audio or video, with transport controls underneath.
///
/// This deliberately does not use `GtkVideo` or `GtkMediaControls`: `GtkVideo`
/// ships its *own* built-in transport bar with no property to turn it off
/// ("Shows a GtkMediaStream with media controls", straight from its docs), so
/// pairing it with a second `GtkMediaControls` — what this used to do — drew
/// two seekbars stacked on top of each other. A bare `GtkPicture` painting the
/// stream (`GtkMediaStream` implements `GdkPaintable`) shows only the frames,
/// and `transport_bar` below is the one and only set of controls, custom-built
/// so it can also offer the ±5s skip Android has that `GtkMediaControls` does
/// not. Variable playback speed is left out: `GtkMediaStream` has no
/// playback-rate API to hook into (checked against the GTK 4 headers), and
/// reaching it would mean bypassing this widget for a hand-rolled GStreamer
/// pipeline — a much larger change than this viewer warrants.
fn playback_pane(app: &Rc<App>, path: &str, is_video: bool) -> gtk::Widget {
    let media = gtk::MediaFile::for_filename(path);

    let stack = gtk::Stack::new();
    stack.set_hexpand(true);
    stack.set_vexpand(true);

    let column = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();

    if is_video {
        let picture = gtk::Picture::new();
        picture.set_paintable(Some(&media));
        picture.set_can_shrink(true);
        picture.set_content_fit(gtk::ContentFit::Contain);
        picture.set_hexpand(true);
        picture.set_vexpand(true);
        column.append(&picture);
    } else {
        // A voice message has nothing to show, so give it something: a big
        // icon so the window does not look broken.
        let icon = gtk::Image::from_icon_name("audio-x-generic-symbolic");
        icon.set_pixel_size(96);
        icon.set_vexpand(true);
        icon.add_css_class("dim-label");
        column.append(&icon);
    }

    column.append(&transport_bar(&media));
    stack.add_named(&column, Some("player"));

    // The fallback pane, shown only if the backend turns out to be missing.
    let missing = adw::StatusPage::builder()
        .icon_name("dialog-warning-symbolic")
        .title("Cannot play this here")
        .description(
            "No GTK media backend is installed, so audio and video cannot be played inside \
             Typeon. Install one — on openSUSE the GStreamer backend ships with GTK's media \
             module — or use the button below to open the file in your usual player.",
        )
        .build();
    let open_external = gtk::Button::builder()
        .label("Open externally")
        .halign(gtk::Align::Center)
        .build();
    open_external.add_css_class("pill");
    open_external.add_css_class("suggested-action");
    {
        let app = app.clone();
        let path = path.to_string();
        open_external.connect_clicked(move |_| launch_externally(&app, &path));
    }
    missing.set_child(Some(&open_external));
    stack.add_named(&missing, Some("missing"));
    stack.set_visible_child_name("player");

    // Autoplay, then watch for the backend failing. `error` is only set once
    // playback is actually attempted, which is why this cannot be a simple
    // capability check up front.
    media.set_playing(true);
    {
        let stack = stack.clone();
        media.connect_error_notify(move |media| {
            if media.error().is_some() {
                stack.set_visible_child_name("missing");
            }
        });
    }
    // A backend-less GtkMediaFile fails immediately and may have done so
    // before the handler above was connected.
    if media.error().is_some() {
        stack.set_visible_child_name("missing");
    }

    stack.upcast()
}

/// Five seconds, in the microseconds `GtkMediaStream` measures time in.
const SKIP_US: i64 = 5_000_000;

/// Play/pause, ±5s skip, a seek scale with elapsed/remaining labels, and
/// volume — driven entirely off `media`'s own notify signals, the same way
/// `GtkMediaControls` drives itself, so this stays correct no matter what
/// starts, stops or seeks the stream.
fn transport_bar(media: &gtk::MediaFile) -> gtk::Widget {
    let bar = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .build();

    let skip_back = gtk::Button::from_icon_name("media-skip-backward-symbolic");
    skip_back.add_css_class("flat");
    skip_back.set_tooltip_text(Some("Back 5 seconds"));

    let play_pause = gtk::Button::from_icon_name("media-playback-pause-symbolic");
    play_pause.add_css_class("flat");
    play_pause.add_css_class("circular");

    let skip_forward = gtk::Button::from_icon_name("media-skip-forward-symbolic");
    skip_forward.add_css_class("flat");
    skip_forward.set_tooltip_text(Some("Forward 5 seconds"));

    let elapsed = gtk::Label::new(Some("0:00"));
    elapsed.add_css_class("caption");
    elapsed.add_css_class("dim-label");

    let remaining = gtk::Label::new(Some("-0:00"));
    remaining.add_css_class("caption");
    remaining.add_css_class("dim-label");

    // A concrete minimum width, not just `hexpand` — see the identical note
    // on the voice player's seek scale in chat.rs, which is where this
    // actually got noticed (a near-zero-width `GtkScale` both renders as a
    // barely visible sliver and trips a GTK size-arithmetic warning).
    let seek = gtk::Scale::builder()
        .orientation(gtk::Orientation::Horizontal)
        .hexpand(true)
        .width_request(180)
        .draw_value(false)
        .build();
    seek.set_range(0.0, 1.0);

    let volume = gtk::VolumeButton::new();
    volume.set_value(media.volume());

    {
        let media = media.clone();
        play_pause.connect_clicked(move |_| media.set_playing(!media.is_playing()));
    }
    {
        let media = media.clone();
        skip_back.connect_clicked(move |_| media.seek((media.timestamp() - SKIP_US).max(0)));
    }
    {
        let media = media.clone();
        skip_forward.connect_clicked(move |_| {
            let ceiling = media.duration().max(0);
            media.seek((media.timestamp() + SKIP_US).min(ceiling));
        });
    }
    {
        let media = media.clone();
        volume.connect_value_changed(move |_, value| media.set_volume(value));
    }
    {
        let button = play_pause.clone();
        media.connect_playing_notify(move |media| {
            button.set_icon_name(if media.is_playing() {
                "media-playback-pause-symbolic"
            } else {
                "media-playback-start-symbolic"
            });
        });
    }
    {
        let seek = seek.clone();
        media.connect_duration_notify(move |media| {
            seek.set_range(0.0, (media.duration().max(0) as f64).max(1.0));
        });
    }
    {
        let seek = seek.clone();
        let elapsed = elapsed.clone();
        let remaining = remaining.clone();
        media.connect_timestamp_notify(move |media| {
            let timestamp = media.timestamp().max(0);
            seek.set_value(timestamp as f64);
            elapsed.set_label(&util::format_duration_us(timestamp));
            let duration = media.duration().max(0);
            remaining.set_label(&format!("-{}", util::format_duration_us((duration - timestamp).max(0))));
        });
    }
    {
        let media = media.clone();
        seek.connect_change_value(move |_, _, value| {
            let ceiling = media.duration().max(0) as f64;
            media.seek(value.clamp(0.0, ceiling) as i64);
            glib::Propagation::Proceed
        });
    }

    bar.append(&skip_back);
    bar.append(&play_pause);
    bar.append(&skip_forward);
    bar.append(&elapsed);
    bar.append(&seek);
    bar.append(&remaining);
    bar.append(&volume);
    bar.upcast()
}

fn is_safe_to_launch(path: &str) -> bool {
    const DOCUMENTS: &[&str] = &[
        "pdf", "txt", "md", "csv", "rtf", "odt", "ods", "odp", "doc", "docx", "xls", "xlsx",
        "ppt", "pptx", "epub", "zip", "7z", "tar", "gz", "xz", "bz2",
        "jpg", "jpeg", "png", "gif", "webp", "heic", "mp4", "webm", "mkv", "mov", "mp3", "m4a",
        "ogg", "opus", "wav", "flac", "aac",
    ];
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| DOCUMENTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn launch_externally(app: &Rc<App>, path: &str) {
    // The viewer's "open with the system application" button lands here too,
    // and the MIME type is only the sender's claim — so check again.
    if !is_safe_to_launch(path) {
        app.toast("This file type is not opened directly. Use \"Save a copy\".");
        return;
    }
    // The other program runs outside Typeon and outside Tor: a document can
    // fetch remote content and give away this computer's address. One click
    // on a received file must not be enough for that.
    let app_for_launch = app.clone();
    let path = path.to_string();
    crate::ui::dialogs::confirm(
        app,
        "Open in another application?",
        "The file opens in your system's default application, which does not use Tor. A \
         document can load content from the internet and reveal your network address to its \
         author. Only open files from people you trust.",
        "Open",
        false,
        move || {
            let uri = gio::File::for_path(&path).uri();
            if gio::AppInfo::launch_default_for_uri(&uri, gio::AppLaunchContext::NONE).is_err() {
                app_for_launch
                    .toast(&format!("No application is registered for this file. It is at {path}"));
            }
        },
    );
}

/// Copies the decrypted attachment somewhere the user chooses. The plaintext
/// copy the core produced lives in its own directory and is not meant to be
/// browsed to.
fn save_copy(app: &Rc<App>, path: &str, suggested_name: &str) {
    let Some(window) = app.window() else { return };
    // The core opens a JPEG XL as PNG: the copy is a PNG and is named so.
    let png_name;
    let suggested_name = match suggested_name.strip_suffix(".jxl") {
        Some(base) if path.ends_with(".png") => {
            png_name = format!("{base}.png");
            png_name.as_str()
        }
        _ => suggested_name,
    };
    let dialog = gtk::FileDialog::builder()
        .title("Save a copy")
        .initial_name(suggested_name)
        .build();

    let app = app.clone();
    let source = path.to_string();
    dialog.save(Some(&window), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let Some(target) = file.path() else { return };
        match std::fs::copy(&source, &target) {
            Ok(_) => app.toast(&format!("Saved to {}", target.display())),
            Err(error) => app.toast(&format!("Could not save: {error}")),
        }
    });
}
