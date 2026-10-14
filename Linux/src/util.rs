//! Small shared helpers: clock, time formatting, image decode/encode, MIME
//! guessing, byte sizes.

use gtk::gdk;
use gtk::gdk_pixbuf;
use gtk::glib;
use gtk::prelude::*;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Decodes JPEG/PNG bytes (avatars, attachment previews) into something a GTK
/// widget can paint. `PixbufLoader` rather than `Texture::from_bytes` so this
/// keeps working on the GTK 4.6 baseline the bindings target.
pub fn texture_from_bytes(bytes: &[u8]) -> Option<gdk::Texture> {
    if bytes.is_empty() {
        return None;
    }
    // Peer-supplied bytes: every client sends JPEG, so no other decoder is
    // reachable, and a header that announces a huge canvas is refused before
    // any pixel buffer is allocated (a zero size makes the loader fail).
    let loader = gdk_pixbuf::PixbufLoader::with_type("jpeg").ok()?;
    loader.connect_size_prepared(|loader, width, height| {
        if width > 4096 || height > 4096 {
            loader.set_size(0, 0);
        }
    });
    if loader.write(bytes).is_err() {
        // `close` must still be called or the loader logs a warning on drop.
        let _ = loader.close();
        return None;
    }
    if loader.close().is_err() {
        return None;
    }
    let pixbuf = loader.pixbuf()?;
    Some(gdk::Texture::for_pixbuf(&pixbuf))
}

/// Hex-encoded image bytes as the core sends them (`avatar_hex`,
/// `preview_hex`) — JSON cannot carry raw binary.
pub fn texture_from_hex(hex_string: &str) -> Option<gdk::Texture> {
    let bytes = hex::decode(hex_string).ok()?;
    texture_from_bytes(&bytes)
}

/// Re-encodes an image file as a JPEG no larger than `max_dimension` on its
/// long edge — the same shape of preview the Android app attaches to photo
/// messages (480p) and profile pictures (720p).
pub fn scaled_jpeg(path: &str, max_dimension: i32, quality: u8) -> Option<Vec<u8>> {
    let pixbuf = gdk_pixbuf::Pixbuf::from_file(path).ok()?;
    let (width, height) = (pixbuf.width(), pixbuf.height());
    let longest = width.max(height);
    let scaled = if longest > max_dimension && longest > 0 {
        let ratio = max_dimension as f64 / longest as f64;
        pixbuf.scale_simple(
            ((width as f64 * ratio).round() as i32).max(1),
            ((height as f64 * ratio).round() as i32).max(1),
            gdk_pixbuf::InterpType::Bilinear,
        )?
    } else {
        pixbuf
    };
    let quality = quality.to_string();
    scaled
        .save_to_bufferv("jpeg", &[("quality", quality.as_str())])
        .ok()
}

/// Chat-list style stamp: time for today, "Yesterday", otherwise a date.
pub fn format_list_time(timestamp_ms: u64) -> String {
    if timestamp_ms == 0 {
        return String::new();
    }
    let Ok(when) = glib::DateTime::from_unix_local((timestamp_ms / 1000) as i64) else {
        return String::new();
    };
    let Ok(now) = glib::DateTime::now_local() else {
        return String::new();
    };
    let same_day = when.year() == now.year() && when.day_of_year() == now.day_of_year();
    if same_day {
        return when.format("%H:%M").map(|s| s.to_string()).unwrap_or_default();
    }
    let yesterday = now.add_days(-1).ok();
    if let Some(yesterday) = yesterday {
        if when.year() == yesterday.year() && when.day_of_year() == yesterday.day_of_year() {
            return "Yesterday".to_string();
        }
    }
    when.format("%d.%m.%Y").map(|s| s.to_string()).unwrap_or_default()
}

/// Bubble stamp — always the clock, the day separator carries the date.
pub fn format_bubble_time(timestamp_ms: u64) -> String {
    if timestamp_ms == 0 {
        return String::new();
    }
    glib::DateTime::from_unix_local((timestamp_ms / 1000) as i64)
        .ok()
        .and_then(|d| d.format("%H:%M").ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// Header shown above the first message of each day.
pub fn format_day_separator(timestamp_ms: u64) -> String {
    if timestamp_ms == 0 {
        return String::new();
    }
    glib::DateTime::from_unix_local((timestamp_ms / 1000) as i64)
        .ok()
        .and_then(|d| d.format("%e %B %Y").ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// True when the two stamps fall on different calendar days.
pub fn is_new_day(previous_ms: u64, current_ms: u64) -> bool {
    if previous_ms == 0 {
        return true;
    }
    let (Ok(a), Ok(b)) = (
        glib::DateTime::from_unix_local((previous_ms / 1000) as i64),
        glib::DateTime::from_unix_local((current_ms / 1000) as i64),
    ) else {
        return false;
    };
    a.year() != b.year() || a.day_of_year() != b.day_of_year()
}

/// Formats a millisecond duration as `m:ss` — voice message length, media
/// playback position.
pub fn format_duration_ms(ms: i64) -> String {
    let total_seconds = ms.max(0) / 1000;
    format!("{}:{:02}", total_seconds / 60, total_seconds % 60)
}

/// Formats a `GtkMediaStream` timestamp/duration (microseconds) as `m:ss`.
pub fn format_duration_us(us: i64) -> String {
    format_duration_ms(us / 1000)
}

/// A download's remaining time, from the average rate seen so far
/// (bytes done / elapsed) rather than the instantaneous rate — steadier on a
/// fluctuating P2P link. `None` while there is not yet enough data to
/// estimate, rather than showing a misleading "0s left".
pub fn format_eta(started_at_ms: u64, bytes_done: u64, total_size: u64) -> Option<String> {
    if started_at_ms == 0 || bytes_done == 0 {
        return None;
    }
    let elapsed_ms = now_ms().saturating_sub(started_at_ms);
    if elapsed_ms < 1000 {
        return None;
    }
    let remaining = total_size.saturating_sub(bytes_done);
    if remaining == 0 {
        return None;
    }
    let bytes_per_ms = bytes_done as f64 / elapsed_ms as f64;
    if bytes_per_ms <= 0.0 {
        return None;
    }
    let eta_seconds = (remaining as f64 / bytes_per_ms / 1000.0) as u64;
    Some(if eta_seconds >= 60 {
        format!("{}:{:02} left", eta_seconds / 60, eta_seconds % 60)
    } else {
        format!("{}s left", eta_seconds.max(1))
    })
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    }
}

/// Enough of a MIME table for the core to route previews and for the receiving
/// Android client to categorise the attachment. Anything unrecognised travels
/// as a plain file, which is always safe.
pub fn guess_mime(file_name: &str) -> String {
    let extension = file_name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();
    let mime = match extension.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        "mp4" | "m4v" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "m4a" | "aac" => "audio/aac",
        "pdf" => "application/pdf",
        "txt" | "log" | "md" => "text/plain",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "xz" => "application/x-xz",
        "zst" => "application/zstd",
        "7z" => "application/x-7z-compressed",
        "tar" => "application/x-tar",
        _ => "application/octet-stream",
    };
    mime.to_string()
}

pub fn is_image(mime: &str) -> bool {
    mime.starts_with("image/")
}

pub fn is_video(mime: &str) -> bool {
    mime.starts_with("video/")
}

pub fn is_audio(mime: &str) -> bool {
    mime.starts_with("audio/")
}

/// Short label for an attachment in a chat-list preview or a notification —
/// mirrors `P2PService.attachmentNotificationLabel`.
pub fn attachment_label(mime: &str, file_name: &str) -> String {
    if is_image(mime) {
        "📷 Photo".to_string()
    } else if is_video(mime) {
        "🎬 Video".to_string()
    } else if is_audio(mime) {
        "🎤 Voice message".to_string()
    } else if !file_name.is_empty() {
        format!("📎 {}", file_name)
    } else {
        "📎 File".to_string()
    }
}

/// Trims a message down to a one-line preview for chat rows and reply chips.
pub fn preview_text(text: &str, max_chars: usize) -> String {
    let single_line = text.replace('\n', " ");
    let trimmed = single_line.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    let cut: String = trimmed.chars().take(max_chars).collect();
    format!("{}…", cut.trim_end())
}

/// Fingerprints are long hex; the UI only ever shows the head of one.
pub fn short_fingerprint(fingerprint: &str) -> String {
    fingerprint.chars().take(12).collect()
}
