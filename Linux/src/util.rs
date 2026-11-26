//! Small shared helpers: clock, time formatting, image decode/encode, MIME
//! guessing, byte sizes.

use crate::i18n::t;
use gtk::gdk;
use gtk::gdk_pixbuf;
use gtk::glib;
use gtk::prelude::*;

/// Creates the file owner-only (0600) on Unix. On Windows files under the
/// user's profile already carry an owner-only ACL, so nothing is set.
pub fn owner_only(options: &mut std::fs::OpenOptions) -> &mut std::fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// chmod on Unix, no-op on Windows (see `owner_only`).
pub fn set_mode(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// Whether the file at `path` is closed to other local users. Unix: no
/// group/other bits. Windows: it lies inside the user's profile directory
/// (inherited owner-only ACL); a USB stick or another drive is not private.
/// A failed check proves nothing: `true`.
pub fn is_private(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).map(|meta| meta.permissions().mode() & 0o077 == 0).unwrap_or(true)
    }
    #[cfg(windows)]
    {
        match (std::fs::canonicalize(path), std::fs::canonicalize(glib::home_dir())) {
            (Ok(file), Ok(home)) => file.starts_with(home),
            _ => true,
        }
    }
}

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

/// Hex-encoded image bytes as the core sends them (`avatar_hex`,
/// `preview_hex`) — JSON cannot carry raw binary.
pub fn texture_from_hex(hex_string: &str) -> Option<gdk::Texture> {
    use std::hash::{Hash, Hasher};
    // Lists rebuild on every event; decode each distinct image once.
    // GTK main thread only (the textures are not Send), hence thread_local.
    // an entry-count cap alone let 256 distinct large previews pin
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

/// A picture as tightly packed RGBA, at most `max_side` a side (aspect kept),
/// for a sticker import. ponytail: an animated GIF/WebP keeps its first frame.
pub fn image_rgba(path: &str, max_side: i32) -> Option<(Vec<u8>, u32, u32)> {
    let (_, width, height) = gdk_pixbuf::Pixbuf::file_info(path)?;
    if i64::from(width) * i64::from(height) > 64_000_000 {
        return None;
    }
    let pixbuf = if width.max(height) > max_side {
        gdk_pixbuf::Pixbuf::from_file_at_scale(path, max_side, max_side, true).ok()?
    } else {
        gdk_pixbuf::Pixbuf::from_file(path).ok()?
    };
    let pixbuf = pixbuf.add_alpha(false, 0, 0, 0).ok()?;
    let (w, h, stride) = (pixbuf.width() as usize, pixbuf.height() as usize, pixbuf.rowstride() as usize);
    let bytes = pixbuf.read_pixel_bytes();
    let mut rgba = Vec::with_capacity(w * h * 4);
    for row in 0..h {
        rgba.extend_from_slice(bytes.get(row * stride..row * stride + w * 4)?);
    }
    Some((rgba, w as u32, h as u32))
}

/// Android's "Forwarded" mark (Forward.kt `MARK`): invisible characters at
/// the start of a text or caption, no protocol field.
pub const FORWARD_MARK: &str = "\u{2064}\u{2063}";

pub fn forward_mark(text: &str) -> String {
    format!("{FORWARD_MARK}{}", text.strip_prefix(FORWARD_MARK).unwrap_or(text))
}

/// (forwarded, text without the mark).
pub fn split_forwarded(text: &str) -> (bool, &str) {
    match text.strip_prefix(FORWARD_MARK) {
        Some(rest) => (true, rest),
        None => (false, text),
    }
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
            return t("Yesterday").to_string();
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
        tf!("{} left", format!("{}:{:02}", eta_seconds / 60, eta_seconds % 60))
    } else {
        tf!("{}s left", eta_seconds.max(1))
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
        t("🙂 Sticker").to_string()
    } else if is_image(mime) {
        t("📷 Photo").to_string()
    } else if is_video(mime) {
        t("🎬 Video").to_string()
    } else if is_audio(mime) {
        t("🎤 Voice message").to_string()
    } else if !file_name.is_empty() {
        format!("📎 {}", file_name)
    } else {
        t("📎 File").to_string()
    }
}

/// Android inline quotes (util/Quote.kt) travel in the text as
/// `\u{2062}\u{2064} id \u{2063} preview \u{2064}\u{2062}`: shown as "> preview".
/// A malformed marker stays as it is; later ones are still converted.
/// Same rule as Quote.kt's MARKER: an id of 1..=128 non-space, non-delimiter
/// chars and a preview with no delimiters.
fn marker_ok(id: &str, preview: &str) -> bool {
    let delim = |c: char| ('\u{2062}'..='\u{2064}').contains(&c);
    let n = id.chars().count();
    (1..=128).contains(&n) && !id.chars().any(|c| c.is_whitespace() || delim(c)) && !preview.chars().any(delim)
}

pub fn quote_plain(text: &str) -> String {
    quote_render(text, |_, quote| format!("> {quote}"), |plain| plain.to_string())
}

/// URI prefix of a quote link in bubble markup; the quoted message id follows.
pub const QUOTE_LINK: &str = "quote:";

/// Same walk as `quote_plain`, but as Pango markup for a bubble label: the
/// quoted preview is a dimmed italic line behind a vertical bar, a link to the
/// quoted message (`QUOTE_LINK`); everything else is escaped plain text.
pub fn quote_markup(text: &str) -> String {
    quote_render(
        text,
        |id, quote| format!(
            "<a href=\"{}{}\"><span alpha=\"70%\"><i>\u{258E} {}</i></span></a>",
            QUOTE_LINK,
            glib::markup_escape_text(id),
            glib::markup_escape_text(&unquote_preview(quote)),
        ),
        |plain| glib::markup_escape_text(plain).to_string(),
    )
}

/// Preview on one line, without the "> " of a quote it was itself quoting
/// (the phone puts the already-flattened text in the marker).
fn unquote_preview(preview: &str) -> String {
    preview.replace('\n', " ").trim_start_matches(|c| c == '>' || c == ' ').to_string()
}

/// A quote marker at the very start of the text, split off: the quoted
/// message id and preview (for a block of its own above the bubble text) and
/// the rest of the text. `None` when the text does not begin with a
/// well-formed marker.
pub fn split_leading_quote(text: &str) -> (Option<(String, String)>, &str) {
    const START: &str = "\u{2062}\u{2064}";
    const END: &str = "\u{2064}\u{2062}";
    // Whitespace before the marker (a newline typed first) must not hide it.
    if let Some(body) = text.trim_start().strip_prefix(START) {
        if let (Some(sep), Some(end)) = (body.find('\u{2063}'), body.find(END)) {
            let (id, preview) = (&body[..sep], &body[sep + '\u{2063}'.len_utf8()..end]);
            if sep < end && marker_ok(id, preview) {
                let rest = &body[end + END.len()..];
                return (Some((id.to_string(), unquote_preview(preview))), rest.strip_prefix('\n').unwrap_or(rest));
            }
        }
    }
    (None, text)
}

fn quote_render(text: &str, quote: impl Fn(&str, &str) -> String, plain: impl Fn(&str) -> String) -> String {
    const START: &str = "\u{2062}\u{2064}";
    const END: &str = "\u{2064}\u{2062}";
    let mut out = String::new();
    let mut rest = text;
    while let Some(a) = rest.find(START) {
        let body = &rest[a + START.len()..];
        match (body.find('\u{2063}'), body.find(END)) {
            (Some(sep), Some(end)) if sep < end && marker_ok(&body[..sep], &body[sep + '\u{2063}'.len_utf8()..end]) => {
                out.push_str(&plain(&rest[..a]));
                out.push_str(&quote(&body[..sep], &body[sep + '\u{2063}'.len_utf8()..end].replace('\n', " ")));
                rest = &body[end + END.len()..];
            }
            _ => {
                out.push_str(&plain(&rest[..a + START.len()]));
                rest = body;
            }
        }
    }
    out.push_str(&plain(rest));
    out
}

#[cfg(test)]
mod quote_tests {
    #[test]
    fn plain() {
        let q = "\u{2062}\u{2064}m1\u{2063}Alıntı1\u{2064}\u{2062}";
        assert_eq!(super::quote_plain(&format!("{q}\nCevap1")), "> Alıntı1\nCevap1");
        assert_eq!(super::quote_plain("plain"), "plain");
        // A broken marker before a good one: the good one still converts.
        let broken = "\u{2062}\u{2064}x";
        assert_eq!(super::quote_plain(&format!("{broken} {q}")), format!("{broken} > Alıntı1"));
    }
}

/// Trims a message down to a one-line preview for chat rows and reply chips.
pub fn preview_text(text: &str, max_chars: usize) -> String {
    let single_line = quote_plain(text).replace('\n', " ");
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
    // gdk-pixbuf promises rowstride >= width * channels and a buffer
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

fn file_head(path: &std::path::Path) -> Vec<u8> {
    use std::io::Read;
    let mut head = Vec::with_capacity(16);
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.take(16).read_to_end(&mut head);
    }
    head
}

/// JPEG, PNG, JPEG XL or WebP: the core strips their metadata itself (same magics as
/// `attachments::encrypt_file_to_disk_with`).
fn scrubbed_by_core(h: &[u8]) -> bool {
    h.starts_with(&[0xFF, 0xD8])
        || h.starts_with(b"\x89PNG\r\n\x1a\n")
        || h.starts_with(&[0xFF, 0x0A])
        || h.starts_with(b"\0\0\0\x0CJXL ")
        || (h.len() >= 12 && &h[..4] == b"RIFF" && &h[8..12] == b"WEBP")
}

/// ISO-BMFF (MP4/MOV/3GP/HEIC/AVIF), TIFF, Matroska/WebM or AVI, whatever the extension.
fn is_media_magic(h: &[u8]) -> bool {
    (h.len() >= 8 && &h[4..8] == b"ftyp")
        || h.starts_with(b"II*\0")
        || h.starts_with(b"MM\0*")
        || h.starts_with(&[0x1A, 0x45, 0xDF, 0xA3])
        || (h.len() >= 12 && &h[..4] == b"RIFF" && &h[8..12] == b"AVI ")
}

pub fn core_scrubs_magic(path: &std::path::Path) -> bool {
    scrubbed_by_core(&file_head(path))
}

pub fn media_magic(path: &std::path::Path) -> bool {
    is_media_magic(&file_head(path))
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
    fn magic_is_by_content() {
        assert!(scrubbed_by_core(&[0xFF, 0xD8, 0xFF, 0xE1]));
        assert!(scrubbed_by_core(b"RIFF\0\0\0\0WEBPVP8 "));
        assert!(!scrubbed_by_core(b"RIFF\0\0\0\0AVI LIST"));
        assert!(is_media_magic(b"RIFF\0\0\0\0AVI LIST"));
        assert!(is_media_magic(b"\0\0\0\x18ftypheic"));
        assert!(is_media_magic(b"II*\0\x08\0\0\0"));
        assert!(is_media_magic(&[0x1A, 0x45, 0xDF, 0xA3, 0x9F]));
        assert!(!is_media_magic(b"%PDF-1.7"));
    }

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
