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
/// keeps working on the GTK 4.6 baseline the bindings target. Returns the
/// texture plus its decoded pixel cost (`width × height × channels`) — the
/// hex-image cache budgets by it (see `texture_from_hex`).
fn decoded_texture(bytes: &[u8]) -> Option<(gdk::Texture, usize)> {
    if bytes.is_empty() {
        return None;
    }
    // Peer-supplied bytes: every client sends JPEG, so no other decoder is
    // reachable, and a header that announces a huge canvas is refused before
    // any pixel buffer is allocated. `set_size(0, 0)` would mean "natural
    // size" (no abort), so shrink the decode to 1x1 instead and drop the result.
    let loader = gdk_pixbuf::PixbufLoader::with_type("jpeg").ok()?;
    let too_big = std::rc::Rc::new(std::cell::Cell::new(false));
    {
        let too_big = too_big.clone();
        loader.connect_size_prepared(move |loader, width, height| {
            if width > 4096 || height > 4096 {
                too_big.set(true);
                loader.set_size(1, 1);
            }
        });
    }
    if loader.write(bytes).is_err() {
        // `close` must still be called or the loader logs a warning on drop.
        let _ = loader.close();
        return None;
    }
    if loader.close().is_err() || too_big.get() {
        return None;
    }
    let pixbuf = loader.pixbuf()?;
    let cost = pixbuf.width() as usize * pixbuf.height() as usize * pixbuf.n_channels() as usize;
    Some((gdk::Texture::for_pixbuf(&pixbuf), cost))
}

pub fn texture_from_bytes(bytes: &[u8]) -> Option<gdk::Texture> {
    decoded_texture(bytes).map(|(texture, _)| texture)
}

/// Hex-encoded image bytes as the core sends them (`avatar_hex`,
/// `preview_hex`) — JSON cannot carry raw binary.
pub fn texture_from_hex(hex_string: &str) -> Option<gdk::Texture> {
    use std::hash::{Hash, Hasher};
    // Lists rebuild on every event; decode each distinct image once.
    // GTK main thread only (the textures are not Send), hence thread_local.
    // H126: an entry-count cap alone let 256 distinct large previews pin
    // ~17 GB of decoded GdkTexture, so the cache also tracks a byte budget —
    // both caps are checked before every insert and evict everything at once
    // (the same wholesale-evict policy the count cap always used).
    const CACHE_MAX_ENTRIES: usize = 256;
    /// The largest texture the decoder above can produce is a 4096² frame
    /// (~67 MB RGBA); the budget still fits two of those.
    const CACHE_BYTE_BUDGET: usize = 128 * 1024 * 1024;
    thread_local! {
        static CACHE: std::cell::RefCell<std::collections::HashMap<u64, (Option<gdk::Texture>, usize)>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hex_string.hash(&mut hasher);
    let key = hasher.finish();
    if let Some(hit) = CACHE.with(|c| c.borrow().get(&key).map(|(texture, _)| texture.clone())) {
        return hit;
    }
    let texture = hex::decode(hex_string).ok().and_then(|bytes| decoded_texture(&bytes));
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        let total: usize = c.values().map(|(_, cost)| *cost).sum();
        let new_cost = texture.as_ref().map(|(_, cost)| *cost).unwrap_or(0);
        if c.len() >= CACHE_MAX_ENTRIES || total + new_cost > CACHE_BYTE_BUDGET {
            c.clear();
        }
        c.insert(key, (texture.as_ref().map(|(t, _)| t.clone()), new_cost));
    });
    texture.map(|(t, _)| t)
}

/// Re-encodes an image file as a JPEG no larger than `max_dimension` on its
/// long edge — the same shape of preview the Android app attaches to photo
/// messages (480p) and profile pictures (720p).
pub fn scaled_jpeg(path: &str, max_dimension: i32, quality: u8) -> Option<Vec<u8>> {
    // Header first, then decode at the target size: a 100 MP photo is never
    // fully materialised. M161/H147: profile pictures and outgoing previews
    // also cap the canvas at the same 64 MP `send` path enforces — a 500 MP
    // image would otherwise be ~2 GB of RGBA in `Pixbuf::from_file`.
    let (_, width, height) = gdk_pixbuf::Pixbuf::file_info(path)?;
    if i64::from(width) * i64::from(height) > 64_000_000 {
        log::warn!("scaled_jpeg: refusing a {width}x{height} image (over the 64 MP cap)");
        return None;
    }
    let longest = width.max(height);
    let scaled = if longest > max_dimension && longest > 0 {
        gdk_pixbuf::Pixbuf::from_file_at_scale(path, max_dimension, max_dimension, true).ok()?
    } else {
        gdk_pixbuf::Pixbuf::from_file(path).ok()?
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
        "jxl" => "image/jxl",
        "heic" | "heif" => "image/heic",
        "avif" => "image/avif",
        "tif" | "tiff" => "image/tiff",
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
pub fn attachment_label(mime: &str, file_name: &str, sticker: bool) -> String {
    if sticker {
        "🙂 Sticker".to_string()
    } else if is_image(mime) {
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

/// What an outgoing file becomes before it is encrypted, same rules as the
/// Android `util.OutgoingMedia`: an image becomes JPEG quality 90 (hi-res: a
/// JPEG goes as it is, anything else becomes lossless JPEG XL), upright and
/// without metadata; GIF, animated WebP and images with transparent pixels go
/// as they are. A video is copied into a new container without metadata.
/// Anything that fails goes out unchanged. Returns (path, name, mime); the
/// path is `source` or a new file in `tmp_dir` that the caller deletes.
pub fn prepare_outgoing(
    source: &std::path::Path,
    name: &str,
    mime: &str,
    hi_res: bool,
    tmp_dir: &std::path::Path,
) -> (std::path::PathBuf, String, String) {
    let out = tmp_dir.join(format!("out-{}", glib::uuid_string_random()));
    // A vector image would be rasterized: it goes as it is, as on Android.
    let converted = if is_image(mime) && mime != "image/svg+xml" {
        image_for_sending(source, name, hi_res, &out)
    } else if is_video(mime) {
        let ext = name.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("mp4");
        let out = out.with_extension(ext);
        let ok = std::process::Command::new("ffmpeg")
            .args(["-hide_banner", "-loglevel", "error", "-y", "-i"])
            .arg(source)
            .args(["-map", "0:v?", "-map", "0:a?", "-dn", "-sn", "-map_metadata", "-1", "-map_chapters", "-1"])
            .args(["-fflags", "+bitexact", "-flags:v", "+bitexact", "-flags:a", "+bitexact", "-c", "copy"])
            .arg(&out)
            .stdin(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !ok {
            log::warn!("ffmpeg remux failed or missing: {name} goes out with its metadata");
            let _ = std::fs::remove_file(&out);
        }
        ok.then(|| (out, name.to_string(), mime.to_string()))
    } else {
        None
    };
    if converted.is_none() {
        let _ = std::fs::remove_file(&out);
    }
    converted.unwrap_or_else(|| (source.to_path_buf(), name.to_string(), mime.to_string()))
}

fn image_for_sending(
    source: &std::path::Path,
    name: &str,
    hi_res: bool,
    out: &std::path::Path,
) -> Option<(std::path::PathBuf, String, String)> {
    use std::io::Read;
    let mut head = [0u8; 256];
    let read = std::fs::File::open(source).ok()?.read(&mut head).ok()?;
    let head = &head[..read];
    let animated_webp = head.len() > 20
        && &head[0..4] == b"RIFF"
        && &head[8..16] == b"WEBPVP8X"
        && head[20] & 0x02 != 0;
    if head.starts_with(b"GIF8")
        || animated_webp
        || is_image_sequence(head)
        || is_animated_png(head, source)
        || (hi_res && head.starts_with(&[0xFF, 0xD8, 0xFF]))
    {
        return None;
    }
    let (_, info_w, info_h) = gdk_pixbuf::Pixbuf::file_info(source)?;
    if info_w as u64 * info_h as u64 > 64_000_000 {
        return None;
    }
    let pixbuf = gdk_pixbuf::Pixbuf::from_file(source).ok()?;
    let icc = pixbuf.option("icc-profile");
    let pixbuf = pixbuf.apply_embedded_orientation().unwrap_or(pixbuf);
    let (width, height) = (pixbuf.width() as usize, pixbuf.height() as usize);
    let channels = pixbuf.n_channels() as usize;
    if (width * height) as u64 > 64_000_000 || pixbuf.bits_per_sample() != 8 || channels < 3 {
        return None;
    }
    let base = name.rsplit_once('.').map_or(name, |(base, _)| base);
    let save_jpeg = |jpeg: &gdk_pixbuf::Pixbuf| {
        let mut options = vec![("quality", "90")];
        if let Some(icc) = icc.as_deref() {
            options.push(("icc-profile", icc));
        }
        jpeg.savev(out, "jpeg", &options).ok()?;
        Some((out.to_path_buf(), format!("{base}.jpg"), "image/jpeg".to_string()))
    };
    if !hi_res && !pixbuf.has_alpha() {
        return save_jpeg(&pixbuf);
    }
    let stride = pixbuf.rowstride() as usize;
    let bytes = pixbuf.read_pixel_bytes();
    // M170: gdk-pixbuf promises rowstride >= width * channels and a buffer
    // long enough for every row, so the per-row slice cannot go out of
    // bounds — checking instead of trusting keeps a malformed pixbuf from
    // panicking inside this worker.
    if height > 0 && bytes.len() < (height - 1) * stride + width * channels {
        return None;
    }
    let mut rgba = Vec::with_capacity(width * height * 4);
    for y in 0..height {
        for px in bytes[y * stride..y * stride + width * channels].chunks_exact(channels) {
            rgba.extend_from_slice(&px[..3]);
            rgba.push(if channels == 4 { px[3] } else { 255 });
        }
    }
    drop(bytes);
    drop(pixbuf);
    let opaque = rgba.chunks_exact(4).all(|px| px[3] == 255);
    if !hi_res {
        if !opaque {
            return None;
        }
        let rgb: Vec<u8> = rgba.chunks_exact(4).flat_map(|px| [px[0], px[1], px[2]]).collect();
        drop(rgba);
        let rgb = gdk_pixbuf::Pixbuf::from_bytes(
            &glib::Bytes::from_owned(rgb),
            gdk_pixbuf::Colorspace::Rgb,
            false,
            8,
            width as i32,
            height as i32,
            (width * 3) as i32,
        );
        return save_jpeg(&rgb);
    }
    crate::core::encode_jxl_lossless(&mut rgba, width as u32, height as u32, !opaque, out.to_str()?).ok()?;
    Some((out.to_path_buf(), format!("{base}.jxl"), "image/jxl".to_string()))
}

/// HEIF/AVIF image sequence: an `ftyp` brand msf1, hevs or avis.
fn is_image_sequence(head: &[u8]) -> bool {
    if head.len() < 12 || &head[4..8] != b"ftyp" {
        return false;
    }
    let size = (u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize).clamp(8, head.len());
    head[8..size].chunks_exact(4).any(|brand| matches!(brand, b"msf1" | b"hevs" | b"avis"))
}

/// APNG: an `acTL` chunk before the first `IDAT`.
fn is_animated_png(head: &[u8], source: &std::path::Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    if head.len() < 8 || &head[1..4] != b"PNG" {
        return false;
    }
    let Ok(mut file) = std::fs::File::open(source) else { return false };
    let mut pos = 8u64;
    let mut chunk = [0u8; 8];
    while file.seek(SeekFrom::Start(pos)).is_ok() && file.read_exact(&mut chunk).is_ok() {
        match &chunk[4..8] {
            b"acTL" => return true,
            b"IDAT" | b"IEND" => return false,
            _ => pos += 12 + u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn animation_is_detected() {
        let mut seq = vec![0, 0, 0, 24];
        seq.extend_from_slice(b"ftypmif1\0\0\0\0mif1msf1");
        assert!(is_image_sequence(&seq));
        seq[20..24].copy_from_slice(b"heic");
        assert!(!is_image_sequence(&seq));

        let dir = std::env::temp_dir().join(format!("typeon-apng-{}", std::process::id()));
        let png = |chunks: &[&[u8; 4]]| {
            let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
            for c in chunks {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(*c);
                out.extend_from_slice(&[0; 5]);
            }
            out
        };
        for (chunks, animated) in [(&[b"IHDR", b"acTL", b"IDAT"][..], true), (&[b"IHDR", b"IDAT", b"acTL"][..], false)] {
            let data = png(chunks);
            std::fs::write(&dir, &data).unwrap();
            assert_eq!(is_animated_png(&data, &dir), animated);
        }
        let _ = std::fs::remove_file(&dir);
    }
}
