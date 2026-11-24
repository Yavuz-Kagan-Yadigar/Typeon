//! File, sticker and attachment work that runs with the core lock released.

use super::*;


/// See `P2PCore::begin_outgoing_file` for the reason the work is split. Encrypting a file that can take gigabytes must not hold the GLOBAL core
/// lock, so it runs here, between two short locked phases. The JNI and `api` wrappers call this instead of one long locked call.
/// Shared skeleton of the two wrappers below: begin (locked), encrypt (unlocked), finish (locked). If any step fails, nothing of the file stays
/// behind: neither the `.enc` nor the `files` row / queued server upload that `finish` may already have written (a row marked 'complete' for a
/// deleted `.enc` made the attachment undownloadable forever).
pub(crate) fn encrypt_then_finish<T>(source_path: &str, group_id: Option<&str>, finish: impl FnOnce(&mut P2PCore, String, [u8; 32], u64, String, Vec<u8>) -> Result<T, String>) -> Result<T, String> {
    let (file_id, file_key, dest_path) = core_lock().begin_outgoing_file(source_path, group_id)?;
    // The chunk hashes for the offer are read back from the `.enc` here, still
    // without the lock (see `FileOffer.chunk_hashes`).
    let encrypted = attachments::encrypt_file_to_disk_with(std::path::Path::new(source_path), &dest_path, &file_key, attachments::FILE_CHUNK_SIZE_V2)
        .and_then(|(total_size, sha256_hex)| {
            let total_chunks = attachments::total_chunks_with(total_size, attachments::FILE_CHUNK_SIZE_V2);
            let hashes = attachments::chunk_hashes_of(&dest_path, total_chunks, attachments::FILE_CHUNK_SIZE_V2)?;
            Ok((total_size, sha256_hex, hashes))
        });
    let (total_size, sha256_hex, chunk_hashes) = match encrypted {
        Ok(v) => v,
        Err(e) => {
            // Do not leave a half-written `.enc` behind (there is no DB record for it).
            let _ = std::fs::remove_file(&dest_path);
            return Err(e);
        }
    };
    let mut core = core_lock();
    let result = finish(&mut *core, file_id.clone(), file_key, total_size, sha256_hex, chunk_hashes);
    if result.is_err() {
        core.discard_outgoing_file(&file_id);
        let _ = std::fs::remove_file(&dest_path);
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_and_send_file_unlocked(peer_device_fingerprint: String, source_path: String, file_name: String, mime_type: String, preview_jpeg: Option<Vec<u8>>, duration_ms: Option<u32>, caption: String, reply_to_message_id: Option<String>, reply_to_preview: Option<String>) -> Result<(String, String), String> {
    encrypt_then_finish(&source_path, None, |core, file_id, file_key, total_size, sha256_hex, chunk_hashes| {
        core.finish_outgoing_file(peer_device_fingerprint, file_id, file_key, total_size, sha256_hex, chunk_hashes, file_name, mime_type, preview_jpeg, duration_ms, caption, reply_to_message_id, reply_to_preview, None)
    })
}

/// See `prepare_and_send_file_unlocked`. The group counterpart.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_and_send_group_file_unlocked(group_id: String, source_path: String, file_name: String, mime_type: String, preview_jpeg: Option<Vec<u8>>, duration_ms: Option<u32>, caption: String, reply_to_message_id: Option<String>, reply_to_preview: Option<String>, reply_to_sender_identity_id: Option<String>) -> Result<String, String> {
    let gid = group_id.clone();
    encrypt_then_finish(&source_path, Some(&gid), |core, file_id, file_key, total_size, sha256_hex, chunk_hashes| {
        core.finish_outgoing_group_file(group_id, file_id, file_key, total_size, sha256_hex, chunk_hashes, file_name, mime_type, preview_jpeg, duration_ms, caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, None)
    })
}

/// `wa:` / `jxl:` + 64 lowercase hex: the only origin ids kept or matched.
pub(crate) fn valid_sticker_origin(o: &str) -> bool {
    o.strip_prefix("wa:").or_else(|| o.strip_prefix("jxl:"))
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Sends sticker `sticker_id` from my store to a contact (`peer` = device
/// fingerprint) or a group (`group_id`), as an attachment with `sticker` set.
/// `reply_to` = (quoted message id, preview, quoted sender identity id for a
/// group). Returns the attachment's file id.
pub(crate) fn send_sticker_unlocked(peer: Option<String>, group_id: Option<String>, sticker_id: &str, reply_to: Option<(String, String, Option<String>)>) -> Result<String, String> {
    // The wire origin is the content id only (`jxl:<sha256>`, which the
    // receiver checks against the offer's hash); a `wa:` id stays local.
    let tmp = core_lock_read().decrypt_sticker_to_tmp(sticker_id)?;
    let origin = Some(format!("jxl:{sticker_id}"));
    let source = tmp.to_string_lossy().to_string();
    let (reply_id, reply_preview, reply_sender) = match reply_to {
        Some((id, preview, sender)) => (Some(id), Some(preview), sender),
        None => (None, None, None),
    };
    let result = match (peer, group_id) {
        (Some(peer), None) => encrypt_then_finish(&source, None, |core, file_id, file_key, total_size, sha256_hex, chunk_hashes| {
            core.finish_outgoing_file(peer, file_id, file_key, total_size, sha256_hex, chunk_hashes, "sticker.jxl".into(), "image/jxl".into(), None, None, String::new(), reply_id, reply_preview, origin).map(|r| r.0)
        }),
        (None, Some(gid)) => encrypt_then_finish(&source, Some(&gid.clone()), |core, file_id, file_key, total_size, sha256_hex, chunk_hashes| {
            core.finish_outgoing_group_file(gid, file_id, file_key, total_size, sha256_hex, chunk_hashes, "sticker.jxl".into(), "image/jxl".into(), None, None, String::new(), reply_id, reply_preview, reply_sender, origin)
        }),
        _ => Err("peer or group".to_string()),
    };
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Encodes RGBA frames (`width` x `height`, at most 600 px a side, already
/// scaled by the caller) as a sticker and stores it. Returns the sticker id.
pub(crate) fn import_sticker_frames_unlocked(mut frames: Vec<Vec<u8>>, width: u32, height: u32, delays_ms: &[u32], origin: Option<String>) -> Result<String, String> {
    if width == 0 || height == 0 || width > attachments::STICKER_MAX_SIDE || height > attachments::STICKER_MAX_SIDE {
        return Err("Sticker must be at most 600 px a side".to_string());
    }
    let has_alpha = frames.iter().any(|f| f.chunks_exact(4).any(|p| p[3] != 255));
    let tmp = core_lock_read().attachments_dir()?.join("plain_cache").join(format!(".sticker-{}.jxl", uuid::Uuid::new_v4()));
    let encoded = attachments::encode_jxl_sticker(&mut frames, width, height, delays_ms, has_alpha, &tmp);
    let result = encoded.and_then(|()| core_lock().store_sticker(&tmp, true, origin.as_deref()));
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Copies a received (complete) attachment into my sticker store.
pub(crate) fn save_received_sticker_unlocked(file_id: &str) -> Result<String, String> {
    let (file_key, sha256_hex, enc_path, decrypted_path) = core_lock().begin_attachment_decrypt(file_id)?;
    let tmp = decrypted_path.with_file_name(format!(".sticker-{}.jxl", uuid::Uuid::new_v4()));
    let chunk_size = core_lock().file_chunk_size(file_id);
    // A peer's origin is not trusted: the saved copy is keyed by its content.
    let result = attachments::decrypt_file_from_disk_with(&enc_path, &tmp, &file_key, &sha256_hex, chunk_size)
        .and_then(|()| core_lock().store_sticker(&tmp, true, None));
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Conversions (sticker PNG/GIF, JPEG XL first frames and pictures) are kept
/// encrypted in `attachments/sticker_cache/<kind>.<owner>.<salt>.<sha256>.cache`:
/// AppLock empties `plain_cache` at every lock, and without this copy each
/// unlock converted every sticker again. `owner` is the sticker id or the
/// attachment's file id; `out` is the conversion's path in `plain_cache`.
pub(crate) fn conversion_cache_dir(out: &std::path::Path) -> Option<std::path::PathBuf> {
    Some(out.parent()?.parent()?.join("sticker_cache"))
}

/// Derived from the source's file key, never the key itself: its chunk
/// nonces are already used for the source. A random salt per cache file means
/// no two cache files share a key either.
pub(crate) fn conversion_cache_key(file_key: &[u8; 32], salt: &[u8], kind: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<sha2::Sha256>::new(Some(salt), file_key)
        .expand(format!("typeon sticker cache {kind}").as_bytes(), &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output");
    key
}

/// The cache files of `owner` whose kind passes `kind_ok`.
pub(crate) fn conversion_cache_files(dir: &std::path::Path, owner: &str, kind_ok: impl Fn(&str) -> bool) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    entries.flatten().map(|e| e.path()).filter(|p| {
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let parts: Vec<&str> = name.split('.').collect();
        parts.len() == 5 && kind_ok(parts[0]) && parts[1] == owner && parts[4] == "cache"
    }).collect()
}

/// Puts `out` back from its cache copy; false when there is none. A copy that
/// does not decrypt is removed.
pub(crate) fn restore_conversion(out: &std::path::Path, kind: &str, owner: &str, file_key: &[u8; 32]) -> bool {
    let Some(dir) = conversion_cache_dir(out) else { return false };
    for path in conversion_cache_files(&dir, owner, |k| k == kind) {
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let parts: Vec<&str> = name.split('.').collect();
        let tmp = out.with_file_name(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let decrypted = hex::decode(parts[2]).map_err(|e| e.to_string()).and_then(|salt| {
            attachments::decrypt_file_from_disk_with(&path, &tmp, &conversion_cache_key(file_key, &salt, kind), parts[3], attachments::FILE_CHUNK_SIZE_V2)
        });
        if decrypted.is_err() {
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(&path);
            continue;
        }
        if std::fs::rename(&tmp, out).is_ok() {
            return true;
        }
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    false
}

/// Keeps an encrypted copy of the conversion `out`, replacing an older one.
/// A failure only costs a conversion after the next lock.
pub(crate) fn keep_conversion(out: &std::path::Path, kind: &str, owner: &str, file_key: &[u8; 32]) {
    // A hi-res photo's PNG would be a second full-size copy the Storage screen
    // does not show: 4 MB. A sticker's GIF is often bigger, and converting it
    // again after every start was the slow part of the picker: 64 MB.
    let cap: u64 = if kind.starts_with("sticker-") { 64 << 20 } else { 4 << 20 };
    if std::fs::metadata(out).map_or(true, |m| m.len() > cap) {
        return;
    }
    let Some(dir) = conversion_cache_dir(out) else { return };
    let _ = std::fs::create_dir_all(&dir);
    for old in conversion_cache_files(&dir, owner, |k| k == kind) {
        let _ = std::fs::remove_file(old);
    }
    let mut salt = [0u8; 16];
    {
        use rand::RngCore;
        OsRng.fill_bytes(&mut salt);
    }
    let tmp = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let r = attachments::encrypt_file_to_disk_with(out, &tmp, &conversion_cache_key(file_key, &salt, kind), attachments::FILE_CHUNK_SIZE_V2)
        .and_then(|(_, sha)| std::fs::rename(&tmp, dir.join(format!("{kind}.{owner}.{}.{sha}.cache", hex::encode(salt)))).map_err(|e| e.to_string()));
    if let Err(e) = r {
        warn!("Conversion not cached ({kind}): {e}");
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Removes `owner`'s cache files whose kind starts with `family`
/// (`"sticker-"` or `"att-"`).
pub(crate) fn remove_cached_conversions(attachments_dir: &std::path::Path, family: &str, owner: &str) {
    for path in conversion_cache_files(&attachments_dir.join("sticker_cache"), owner, |k| k.starts_with(family)) {
        let _ = std::fs::remove_file(path);
    }
}

/// A sticker as a viewable file: PNG, or GIF when animated. Cached in the
/// attachments' `plain_cache` (wiped at start, like theirs) and, encrypted,
/// in `sticker_cache`.
pub(crate) fn sticker_plain_path_unlocked(id: &str) -> Result<String, String> {
    // Paths and key under the lock; every file operation after it is released.
    let (animated, cache, enc_path, file_key) = {
        let core = core_lock_read();
        let animated = core.sticker_animated(id)?;
        (animated, core.attachments_dir()?.join("plain_cache"), core.sticker_enc_path(id)?, core.sticker_file_key(id)?)
    };
    let out = cache.join(if animated { format!("anim-{id}.gif") } else { format!("sticker-{id}.png") });
    if out.exists() {
        return Ok(out.to_string_lossy().to_string());
    }
    let kind = if animated { "sticker-gif" } else { "sticker-png" };
    if restore_conversion(&out, kind, id, &file_key) {
        return Ok(out.to_string_lossy().to_string());
    }
    let tmp = decrypt_sticker_file(&enc_path, &file_key, &cache, id)?;
    let conv = out.with_file_name(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let converted = if animated { attachments::jxl_to_gif(&tmp, &conv) } else { attachments::jxl_to_png(&tmp, &conv) };
    let _ = std::fs::remove_file(&tmp);
    let result = converted.and_then(|()| std::fs::rename(&conv, &out).map_err(|e| e.to_string()));
    if result.is_err() {
        let _ = std::fs::remove_file(&conv);
    } else {
        keep_conversion(&out, kind, id, &file_key);
    }
    result.map(|()| out.to_string_lossy().to_string())
}

/// A sticker's first frame as PNG (fast placeholder while the GIF converts).
pub(crate) fn sticker_first_frame_unlocked(id: &str) -> Result<String, String> {
    let (cache, enc_path, file_key) = {
        let core = core_lock_read();
        (core.attachments_dir()?.join("plain_cache"), core.sticker_enc_path(id)?, core.sticker_file_key(id)?)
    };
    let out = cache.join(format!("first-{id}.png"));
    if out.exists() {
        return Ok(out.to_string_lossy().to_string());
    }
    if restore_conversion(&out, "sticker-first", id, &file_key) {
        return Ok(out.to_string_lossy().to_string());
    }
    let tmp = decrypt_sticker_file(&enc_path, &file_key, &cache, id)?;
    let r = attachments::convert_cached(&tmp, &out, attachments::jxl_to_png);
    let _ = std::fs::remove_file(&tmp);
    if r.is_ok() {
        keep_conversion(&out, "sticker-first", id, &file_key);
    }
    r.map(|()| out.to_string_lossy().to_string())
}

/// `P2PCore::decrypt_sticker_to_tmp` without the core lock: sticker `id` (its content hash) decrypted to a fresh
/// temporary `.jxl` in `cache`; the caller removes it.
fn decrypt_sticker_file(enc_path: &std::path::Path, file_key: &[u8; 32], cache: &std::path::Path, id: &str) -> Result<std::path::PathBuf, String> {
    let _ = std::fs::create_dir_all(cache);
    let tmp = cache.join(format!(".sticker-{}.jxl", uuid::Uuid::new_v4()));
    attachments::decrypt_file_from_disk_with(enc_path, &tmp, file_key, id, attachments::FILE_CHUNK_SIZE_V2)?;
    Ok(tmp)
}

/// A JPEG XL attachment's first frame as PNG (`first-<sha256>.png`).
pub(crate) fn attachment_first_frame_unlocked(file_id: &str) -> Result<String, String> {
    let (file_key, sha256_hex, enc_path, decrypted_path) = core_lock().begin_attachment_decrypt(file_id)?;
    if !decrypted_path.extension().map_or(false, |e| e.eq_ignore_ascii_case("jxl")) {
        return Err("not a JPEG XL".to_string());
    }
    let out = decrypted_path.with_file_name(format!("first-{sha256_hex}.png"));
    if out.exists() || restore_conversion(&out, "att-first", file_id, &file_key) {
        return Ok(out.to_string_lossy().to_string());
    }
    let tmp = decrypted_path.with_file_name(format!(".first-{}.jxl", uuid::Uuid::new_v4()));
    let chunk_size = core_lock().file_chunk_size(file_id);
    let r = attachments::decrypt_file_from_disk_with(&enc_path, &tmp, &file_key, &sha256_hex, chunk_size)
        .and_then(|()| attachments::convert_cached(&tmp, &out, attachments::jxl_to_png));
    let _ = std::fs::remove_file(&tmp);
    if r.is_ok() {
        keep_conversion(&out, "att-first", file_id, &file_key);
    }
    r.map(|()| out.to_string_lossy().to_string())
}

/// A JPEG XL attachment as it came, for "Save as JPEG XL":
/// `plain_cache/orig-{file_id}.jxl`. Not `{file_id}.jxl`, which
/// `attachment_plaintext_path_unlocked` reads as "would not convert".
/// Same tmp + atomic rename; `remove_attachment_copy` removes it.
pub(crate) fn attachment_original_path_unlocked(file_id: &str) -> Result<String, String> {
    let (file_key, sha256_hex, enc_path, decrypted_path) = core_lock().begin_attachment_decrypt(file_id)?;
    if !decrypted_path.extension().map_or(false, |e| e.eq_ignore_ascii_case("jxl")) {
        return Err("not a JPEG XL".to_string());
    }
    let out = decrypted_path.with_file_name(format!("orig-{}.jxl", file_id));
    if !out.exists() {
        let tmp = out.with_file_name(format!(".orig-{}.jxl", uuid::Uuid::new_v4()));
        let chunk_size = core_lock().file_chunk_size(file_id);
        let r = attachments::decrypt_file_from_disk_with(&enc_path, &tmp, &file_key, &sha256_hex, chunk_size)
            .and_then(|()| std::fs::rename(&tmp, &out).map_err(|e| e.to_string()));
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        r?;
    }
    Ok(out.to_string_lossy().to_string())
}

/// The frames of a JPEG XL attachment (`attachments::jxl_frames_rgba`). Decrypted to its own temporary file,
/// not to the "Save as JPEG XL" copy, which a save may be reading at the same time.
pub(crate) fn attachment_jxl_frames_unlocked(file_id: &str) -> Result<(u32, u32, Vec<(Vec<u8>, u32)>), String> {
    let (file_key, sha256_hex, enc_path, decrypted_path) = core_lock().begin_attachment_decrypt(file_id)?;
    if !decrypted_path.extension().map_or(false, |e| e.eq_ignore_ascii_case("jxl")) {
        return Err("not a JPEG XL".to_string());
    }
    let tmp = decrypted_path.with_file_name(format!(".frames-{}.jxl", uuid::Uuid::new_v4()));
    let chunk_size = core_lock().file_chunk_size(file_id);
    let frames = attachments::decrypt_file_from_disk_with(&enc_path, &tmp, &file_key, &sha256_hex, chunk_size)
        .and_then(|()| attachments::jxl_frames_rgba(&tmp));
    let _ = std::fs::remove_file(&tmp);
    frames
}

/// See `P2PCore::begin_attachment_decrypt`. The same lock-splitting pattern, for the full-file decryption after a download. Concurrency: two
/// concurrent calls for the same file must not write the same cache path. So each decrypts to its own unique temporary path first, then an
/// atomic `rename` puts it in place (the second call's rename wins; both contents are identical).
pub(crate) fn attachment_plaintext_path_unlocked(file_id: &str) -> Result<String, String> {
    let (file_key, sha256_hex, enc_path, decrypted_path) = core_lock().begin_attachment_decrypt(file_id)?;
    // A JPEG XL ("hi-res" image) is handed out as PNG, because no viewer of ours
    // reads JPEG XL. An animated one is handed out as GIF instead.
    let jxl = decrypted_path.extension().map_or(false, |e| e.eq_ignore_ascii_case("jxl"));
    // Named by content hash: identical animations share one conversion.
    let gif_path = decrypted_path.with_file_name(format!("anim-{sha256_hex}.gif"));
    if jxl && gif_path.exists() {
        return Ok(gif_path.to_string_lossy().to_string());
    }
    let plain_path = if jxl { decrypted_path.with_extension("png") } else { decrypted_path.clone() };
    // A JPEG XL that would not convert is kept as it came.
    if jxl && !plain_path.exists() && decrypted_path.exists() {
        return Ok(decrypted_path.to_string_lossy().to_string());
    }
    // After an AppLock purge: the conversion from its encrypted cache copy.
    if jxl && !plain_path.exists() {
        if restore_conversion(&gif_path, "att-gif", file_id, &file_key) {
            return Ok(gif_path.to_string_lossy().to_string());
        }
        restore_conversion(&plain_path, "att-png", file_id, &file_key);
    }
    if !plain_path.exists() {
        info!(
            "get_attachment_plaintext_path: {} not in cache, decrypting from {}",
            plain_path.display(), enc_path.display()
        );
        let tmp_path = plain_path.with_file_name(format!(
            ".{}.tmp-{}",
            plain_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| file_id.to_string()),
            uuid::Uuid::new_v4()
        ));
        let chunk_size = core_lock().file_chunk_size(file_id);
        if let Err(e) = attachments::decrypt_file_from_disk_with(&enc_path, &tmp_path, &file_key, &sha256_hex, chunk_size) {
            error!("get_attachment_plaintext_path: decrypt_file_from_disk failed (file_id={}): {}", file_id, e);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
        if jxl {
            let animated = attachments::jxl_is_animated(&tmp_path);
            let (ext, out_path) = if animated { ("gif", &gif_path) } else { ("png", &plain_path) };
            let mut conv_tmp = tmp_path.clone().into_os_string();
            conv_tmp.push(format!(".{ext}"));
            let conv_tmp = std::path::PathBuf::from(conv_tmp);
            let converted = if animated { attachments::jxl_to_gif(&tmp_path, &conv_tmp) } else { attachments::jxl_to_png(&tmp_path, &conv_tmp) };
            if let Err(e) = converted {
                warn!("JPEG XL not converted, kept as it is ({}): {}", file_id, e);
                let _ = std::fs::remove_file(&conv_tmp);
                if let Err(e) = std::fs::rename(&tmp_path, &decrypted_path) {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(e.to_string());
                }
                return Ok(decrypted_path.to_string_lossy().to_string());
            }
            let _ = std::fs::remove_file(&tmp_path);
            if let Err(e) = std::fs::rename(&conv_tmp, out_path) {
                let _ = std::fs::remove_file(&conv_tmp);
                return Err(e.to_string());
            }
            if attachment_gone(file_id, out_path) {
                return Err("Attachment removed".to_string());
            }
            keep_conversion(out_path, if animated { "att-gif" } else { "att-png" }, file_id, &file_key);
            if animated {
                return Ok(gif_path.to_string_lossy().to_string());
            }
        } else if let Err(e) = std::fs::rename(&tmp_path, &plain_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.to_string());
        } else if attachment_gone(file_id, &plain_path) {
            return Err("Attachment removed".to_string());
        }
    }
    info!("get_attachment_plaintext_path: file_id={} -> {}", file_id, plain_path.display());
    Ok(plain_path.to_string_lossy().to_string())
}

/// Checks that the attachment still exists after a decrypt that ran without the
/// lock. If it was deleted (or evicted) meanwhile, the plaintext just written is
/// removed too, or it would stay in `plain_cache` with no row to remove it.
fn attachment_gone(file_id: &str, written: &std::path::Path) -> bool {
    let present = crate::core_lock_read().db.as_ref().map_or(true, |c| {
        c.query_row("SELECT 1 FROM files WHERE file_id = ?1 AND status = 'complete'", params![file_id], |_| Ok(())).is_ok()
    });
    if !present {
        let _ = std::fs::remove_file(written);
    }
    !present
}
