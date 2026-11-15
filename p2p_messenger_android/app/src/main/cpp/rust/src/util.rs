//! Small free helpers: id/path checks, signing inputs, time, multiaddr and group helpers.

use super::*;


/// Checks that a `file_id` is safe to use as a file path.
///
/// `FileOffer.file_id` comes entirely from the REMOTE peer, and `enc_path_for` used it directly in the path
/// `<files>/attachments/{file_id}.enc`, with no validation. The server side has had the equivalent check (`is_safe_id`) from the start,
/// but the client did not. A matched contact (or a group member) could then:
///   * `file_id = "../identity_secret"`: the `remove_file` call at the start of `download_file` deletes the victim's
///     `identity_secret.enc`, which destroys the identity. `history_key.enc` and `skipped_key_enc.enc` can be deleted the same way.
///   * Write attacker-chosen bytes to an arbitrary path: later chunks are written to that path and authenticated with the attacker's own `file_key`.
/// This was triggered without user action when Node mode was on (`receive_file_offer` starts the download as soon as the offer arrives).
///
/// Our own ids are UUIDs (hex and dashes), so they pass this check.
pub(crate) fn is_safe_file_id(id: &str) -> bool {
    // Lower case only, same rule as the server's `is_safe_id`: ids are our own
    // lower-case UUIDs, and on a case-insensitive volume `AB` and `ab` are one
    // file. A peer's offer with another spelling is refused here, before it
    // could be uploaded to a server that refuses it too.
    !id.is_empty()
        && id.len() <= 128
        && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// The 8-byte author tag every group message id starts with (as 16 hex
/// characters): a hash of the group, the author's identity id and the rest
/// of the id. Text ids are `<tag>-<uuid>`; file ids carry it through the
/// blob upload secret (`<tag><blob_id_hash_hex>`, see `blob_upload_secret`).
/// A receiver recomputes it from the authenticated sender, or from a history
/// row's author, so no member can make an id that collides with another
/// member's message. The rest is hashed in so a file's tag, which a
/// server sees in the blob id, differs per file and links no two of an
/// author's files.
pub(crate) fn group_msg_tag(group_id: &str, author_identity_id: &str, rest: &str) -> [u8; 8] {
    use sha2::Digest as _;
    let h = sha2::Sha256::new_with_prefix(b"typeon-group-msg-id-v2")
        .chain_update(group_id.as_bytes())
        .chain_update([0u8])
        .chain_update(author_identity_id.as_bytes())
        .chain_update([0u8])
        .chain_update(rest.as_bytes())
        .finalize();
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&h[..8]);
    tag
}

/// Whether group message id `id` was made by `author_identity_id` in `group_id`. The id starts with that author's `group_msg_tag`.
pub(crate) fn group_msg_id_bound(group_id: &str, author_identity_id: &str, id: &str) -> bool {
    match (id.get(..16), id.get(16..)) {
        (Some(tag), Some(rest)) if !rest.is_empty() => tag == hex::encode(group_msg_tag(group_id, author_identity_id, rest)),
        _ => false,
    }
}

/// A group reply that names the quoted author must quote an id of that author. Otherwise the wrong name is shown and the reply is dropped.
pub(crate) fn group_reply_bound(group_id: &str, reply_to_message_id: Option<&str>, reply_to_sender_identity_id: Option<&str>) -> bool {
    match (reply_to_message_id, reply_to_sender_identity_id) {
        (Some(id), Some(author)) => group_msg_id_bound(group_id, author, id),
        _ => true,
    }
}

/// Guarantees that the extension derived from `file_name` contains no path separator (same attack surface as `is_safe_file_id`).
/// `begin_attachment_decrypt` builds the plaintext cache path as `{file_id}{ext}`, and `ext` comes from the peer's file name.
/// `file_name = "x./../../y"` yields the extension `/../../y`, which escapes the directory even when `file_id` is clean.
pub(crate) fn safe_extension(file_name: &str) -> String {
    match file_name.rsplit_once('.') {
        Some((_, ext))
            if !ext.is_empty()
                && ext.len() <= 16
                && ext.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            format!(".{}", ext)
        }
        _ => String::new(),
    }
}

/// Size on disk in bytes of one file, or 0 if it does not exist (see `storage_usage`).
pub(crate) fn disk_size(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Total size of the files in a directory, including subdirectories. If `ext_filter` is given, only files with that extension are counted.
/// `attachments/` also holds `plain_cache`. Its plaintext copies are NOT `.enc` and must not count toward attachment size.
pub(crate) fn dir_size(dir: &std::path::Path, ext_filter: Option<&str>) -> u64 {
    let mut total = 0u64;
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(current) = dirs.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => dirs.push(path),
                Ok(_) => {
                    if let Some(ext) = ext_filter {
                        if path.extension().map(|e| e.to_string_lossy() != ext).unwrap_or(true) {
                            continue;
                        }
                    }
                    total += disk_size(&path);
                }
                Err(_) => {}
            }
        }
    }
    total
}

/// Makes the `file_name` sent by the peer harmless before it is DISPLAYED or USED as a file name.
///
/// This field is fully remote-controlled and flows to two places:
///   * The Android "save to Downloads / P2P" path (the API 26-28 branch) does `File(p2pDir, fileName)`. A name such as
///     `"../../DCIM/Camera/IMG_0001.jpg"` would write to an arbitrary path in shared storage.
///   * The chat bubble on both clients. Unicode bidi override characters (U+202E RIGHT-TO-LEFT OVERRIDE and relatives) visually reverse the
///     extension: `"fatura\u{202E}kpa.pdf"` is displayed as `"faturafdp.apk"`. This is the classic extension spoof.
///
/// Rule: path separators and drive/root markers are dropped. Control characters and bidi formatting characters are dropped. Leading dots are
/// dropped (`".."` or a hidden file). The length is capped. If nothing is left, the result is `"file"`.
/// The extension is KEPT, so `safe_extension` and the MIME mapping keep working.
/// Characters that draw nothing or reorder the text around them: bidi controls, zero-width and blank fillers, line/paragraph
/// separators, soft hyphen, tag characters. With one of them, a name can look empty or look like another contact's name.
pub(crate) fn is_invisible_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x061C | 0x115F | 0x1160 | 0x180E | 0x3164 | 0xFFA0 | 0xFEFF
        | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x2069 | 0xE0000..=0xE007F | 0xE0100..=0xE01EF)
}

pub(crate) fn safe_file_name(name: &str) -> String {
    // Bytes, not chars: ext4/F2FS NAME_MAX is 255 bytes, and 120 CJK or emoji chars exceed it. Leave room for a " (1)" suffix.
    const MAX_FILE_NAME_LEN: usize = 200;
    let cleaned: String = name
        .chars()
        .filter(|c| {
            !matches!(c, '/' | '\\' | ':')
                && !c.is_control()
                && !is_invisible_char(*c)
        })
        .collect();
    // Dots and spaces are stripped together (". .x" would otherwise leave ".x", a hidden file).
    let cleaned = cleaned.trim_start_matches(|c: char| c == '.' || c.is_whitespace()).trim_end().to_string();
    if cleaned.is_empty() {
        return "file".to_string();
    }
    if cleaned.len() <= MAX_FILE_NAME_LEN {
        return cleaned;
    }
    // Truncate long names, but keep the extension (ASCII, at most 17 bytes).
    let ext = safe_extension(&cleaned);
    let mut keep = MAX_FILE_NAME_LEN.saturating_sub(ext.len());
    while !cleaned.is_char_boundary(keep) {
        keep -= 1;
    }
    format!("{}{}", cleaned[..keep].trim_end(), ext)
}

#[cfg(test)]
mod safe_file_name_tests {
    #[test]
    fn caps_bytes_at_char_boundary() {
        let n = super::safe_file_name(&format!("{}.pdf", "界".repeat(150)));
        assert!(n.len() <= 200 && n.ends_with(".pdf"));
        assert_eq!(super::safe_file_name("a.txt"), "a.txt");
    }
}

/// Maximum accepted size of a profile or group photo.
///
/// Two reasons, both real:
///   * Outgoing: the avatar travels inside a ratchet-encrypted `ProfileUpdate` / `GroupChange::AvatarUpdate` packet, subject to gossipsub's
///     1 MB `max_transmit_size`. A group update also carries a ~4 KB `member_devices` proof per member. An avatar over the limit fails with
///     `MessageTooLarge` (a permanent error), which means the group photo can never be changed.
///   * Incoming: the peer could send a 900 KB JPEG, which was then written to the DB permanently for each contact or group. Nothing checked it.
///
/// 256 KiB is well above what our clients PRODUCE (720p / 85%, typically 60-200 KB) and well below the limit itself.
pub(crate) const MAX_AVATAR_BYTES: usize = 256 * 1024;

/// Largest Argon2 memory cost `import_recovery` accepts from a file: 128 MiB (2x export).
pub(crate) const MAX_RECOVERY_ARGON2_M_COST_KIB: u32 = 128 * 1024;
/// Largest recovery file the apps import (Android `MAX_RECOVERY_FILE_BYTES`).
pub(crate) const MAX_RECOVERY_FILE_BYTES: usize = 64 * 1024 * 1024;
/// Chats over that size: only this many newest messages go into the file.
pub(crate) const RECOVERY_TRIMMED_MESSAGES: usize = 6500;

/// Maximum length of an account name, in CHARACTERS (not bytes).
///
/// The name is now incoming network data: the peer chooses it, and it is written into the contact list. An unbounded name could overflow
/// the contact row or be used to spoof notification text.
pub(crate) const MAX_DISPLAY_NAME_CHARS: usize = 48;

/// Makes an account name displayable: trims whitespace, removes CONTROL characters (including line breaks), and truncates to
/// `MAX_DISPLAY_NAME_CHARS`. Returns `None` if nothing is left.
///
/// Removing line breaks is a security measure, not cosmetic. An embedded `\n` in a one-line contact row could produce a fake second line
/// in the notification or chat header (for example "...verified").
pub(crate) fn sanitize_display_name(name: &str) -> Option<String> {
    // Bidi override/embedding/isolate and zero-width characters go too (same
    // set as `safe_file_name`): U+202E lets a contact show a reversed name in
    // the contact list and in notifications.
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_char(*c))
        .collect();
    // Trim first, so leading spaces do not use up the length budget.
    let cut: String = cleaned.trim().chars().take(MAX_DISPLAY_NAME_CHARS).collect();
    let trimmed = cut.trim_end();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

/// @mention ids of a group text: current members only (minus `skip`, the
/// sender), deduplicated, at most 32.
pub(crate) fn filter_mentions(group: &Group, skip: Option<&str>, mut ids: Vec<String>) -> Vec<String> {
    ids.retain(|id| Some(id.as_str()) != skip && group.is_member(id));
    let mut seen = std::collections::HashSet::new();
    ids.retain(|id| seen.insert(id.clone()));
    ids.truncate(32);
    ids
}

/// `create_group` makes `group-<16 hex>`; 16..=48 hex accepted.
pub(crate) fn is_group_id(id: &str) -> bool {
    id.strip_prefix("group-").map_or(false, |t| (16..=48).contains(&t.len()) && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// A device fingerprint (and an identity id, which is the first device's
/// fingerprint): hex of a SHA3-256.
pub(crate) fn is_fingerprint_hex(s: &str) -> bool {
    // Lowercase only: every computed fingerprint is lowercase and all maps
    // compare the strings exactly. The uppercase form of a known id made a
    // second contact and slipped past the block list.
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Input to the `HandshakeInit` signature. It includes the tag and the recipient's fingerprint.
/// Protocol break: the older format did not bind the recipient, which allowed replay DoS. Older versions are intentionally incompatible.
/// The two prekey ids are also included (which of the recipient's keys the secret is encapsulated to, and which prekey the sender used),
/// so a relay cannot change either. The tag was bumped, and older versions do not verify.
pub(crate) fn handshake_signing_input(x25519_pub: &[u8], kyber_pub: &[u8], kyber_ct: &[u8], timestamp: u64, recipient_fp: &str, recipient_prekey_id: u64, sender_prekey_id: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + x25519_pub.len() + kyber_pub.len() + kyber_ct.len() + 24 + recipient_fp.len() + 12);
    out.extend_from_slice(b"p2pmsg-v0.4-handshake");
    for field in [x25519_pub, kyber_pub, kyber_ct, recipient_fp.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&recipient_prekey_id.to_be_bytes());
    out.extend_from_slice(&sender_prekey_id.to_be_bytes());
    out
}

/// Signed bytes of a `MessagePacket`. They include the RECIPIENT device, so a packet sent to M could not also verify at B.
/// Without that binding, three such replays made B drop its healthy session with A (`note_undecryptable`).
/// Versions before this one signed only the header and ciphertext, and the two cannot exchange messages. This is a deliberate protocol break.
///
/// Tagged and length-framed, like `handshake_signing_input`.
///
/// `header` is the raw header bytes as sent (`SignedHeader::raw`), not a re-encoding. Older versions do not verify.
pub(crate) fn packet_signing_input(header: &[u8], ciphertext: &[u8], recipient_fp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + header.len() + ciphertext.len() + recipient_fp.len());
    out.extend_from_slice(b"p2pmsg-v0.6-packet");
    for field in [header, ciphertext, recipient_fp.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// ChaCha20-Poly1305 with a fresh random nonce: (ciphertext, nonce). The one
/// place local rows are sealed (history, skipped keys, ratchet state, file keys).
pub(crate) fn seal_with(key: &[u8; 32], plaintext: &[u8]) -> Option<(Vec<u8>, [u8; 12])> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use rand::RngCore;
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).ok()?;
    Some((ciphertext, nonce))
}

/// See `P2PCore::heal_founder_chain`: the version of the transfer that made
/// `current_founder` founder (0 if it founded the group).
pub(crate) fn founder_transfer_floor(local_chain: &[packet::FounderTransfer], current_founder: &str) -> u32 {
    local_chain.iter()
        .filter(|t| t.to_identity == current_founder)
        .map(|t| t.version)
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod founder_floor_tests {
    fn t(version: u32, from: &str, to: &str) -> crate::packet::FounderTransfer {
        crate::packet::FounderTransfer {
            group_id: "g".into(), version, from_identity: from.into(), to_identity: to.into(),
            signed_by_device: "d".into(), signature: vec![], signature_pq: vec![],
        }
    }

    /// A group id names one founder; another identity does not match it.
    #[test]
    fn group_id_names_its_founder() {
        let id = super::P2PCore::group_id_for_founder("aa", "0123456789abcdef");
        assert_eq!(id.len(), 54);
        assert_eq!(id.get(6..22), Some("0123456789abcdef"));
        assert_ne!(id, super::P2PCore::group_id_for_founder("bb", "0123456789abcdef"));
    }

    /// A packet signed for one recipient must not verify for another.
    #[test]
    fn packet_signature_covers_the_recipient() {
        let header = crate::packet::MessagePacketHeader {
            sender_identity_id: "i".into(), sender_device_fingerprint: "d".into(), message_id: "m".into(),
            ratchet_pubkey: vec![1], message_number: 0, prev_chain_length: 0, rotation_kyber_ciphertext: None,
            sent_at_ms: 0,
        };
        let header = crate::packet::SignedHeader::new(header).unwrap();
        let to_b = super::packet_signing_input(header.raw(), b"ct", "bbbb");
        let to_c = super::packet_signing_input(header.raw(), b"ct", "cccc");
        assert_ne!(to_b, to_c);
        let (sealed, nonce) = super::seal_with(&[7u8; 32], b"x").unwrap();
        assert!(sealed != b"x" && nonce != [0u8; 12]);
    }

    /// F -> A (v5), A -> F (v9): F is founder again, and the v5 transfer must
    /// be below the floor so a replay of it cannot move the founder back to A.
    #[test]
    fn replayed_old_transfer_is_below_the_floor() {
        let chain = [t(5, "F", "A"), t(9, "A", "F")];
        assert_eq!(super::founder_transfer_floor(&chain, "F"), 9);
        assert_eq!(super::founder_transfer_floor(&chain, "A"), 5);
        // The original founder, never handed the group: nothing is too old.
        assert_eq!(super::founder_transfer_floor(&[], "F"), 0);
    }
}

/// An id as log lines print it: 8 characters, enough to tell devices apart
/// in a test log. The last 8 of a libp2p `PeerId`, whose text always starts
/// with the same key-type prefix; the first 8 of anything else.
pub(crate) fn log_id<T: std::fmt::Display + ?Sized>(id: &T) -> String {
    let s = id.to_string();
    let n = s.chars().count();
    if s.starts_with("12D3KooW") {
        s.chars().skip(n.saturating_sub(8)).collect()
    } else {
        s.chars().take(8).collect()
    }
}

pub(crate) fn current_time_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// milliseconds on CLOCK_BOOTTIME: keeps counting through suspend and
/// never steps with the wall clock. Only for in-memory timers (backoffs,
/// retry/rate windows, keepalive); never stored, never compared with a peer's
/// clock or a `current_time_ms` value. +1 day so a `0` "never" reads as long ago.
#[cfg(windows)]
pub(crate) fn mono_ms() -> u64 {
    // GetTickCount64 is monotonic and, like CLOCK_BOOTTIME, keeps counting
    // through sleep (QueryUnbiasedInterruptTime would not).
    extern "system" {
        fn GetTickCount64() -> u64;
    }
    // SAFETY: no arguments, no preconditions.
    let ms = unsafe { GetTickCount64() };
    ms + 86_400_000
}

#[cfg(not(windows))]
pub(crate) fn mono_ms() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid out-pointer; CLOCK_BOOTTIME exists on Linux and Android.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000 + 86_400_000
}

// --- Helper functions ---

/// One `contacts` row per identity, enforced by the database. Rows that
/// share an identity are reduced to one first: the row that knows the most
/// devices wins (then the latest device change, then the newest row), since
/// the device list is what a contact row is for; name and avatar come back
/// with the next profile update. Chats hang on device fingerprints, not on
/// the contact row, so no message is lost with the row that goes.
pub(crate) const CONTACTS_ONE_ROW_PER_IDENTITY_SQL: &str = "
    DELETE FROM contacts
     WHERE COALESCE(trusted_identity_id, '') != ''
       AND rowid NOT IN (
           SELECT rowid FROM (
               SELECT rowid, ROW_NUMBER() OVER (
                   PARTITION BY trusted_identity_id
                   ORDER BY CASE WHEN json_valid(known_devices_json)
                                 THEN json_array_length(known_devices_json) ELSE -1 END DESC,
                            COALESCE(last_device_change, 0) DESC,
                            rowid DESC
               ) AS place
               FROM contacts
               WHERE COALESCE(trusted_identity_id, '') != ''
           ) WHERE place = 1
       );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_identity
        ON contacts(trusted_identity_id) WHERE COALESCE(trusted_identity_id, '') != '';
";

/// A time the sender chose may not lie in the future: such a message sorted
/// below everything written after it. An older time stays (restored history).
pub(crate) fn clamp_received_times(content: &mut MessageContent, now: u64) {
    match content {
        MessageContent::Text { sent_at_ms, .. } => *sent_at_ms = (*sent_at_ms).min(now),
        // Stored as i64 and compared for staleness: a future (or >= 2^63)
        // stamp blocked every later edit/reaction of that message.
        MessageContent::Edit { edited_at_ms, .. } => *edited_at_ms = (*edited_at_ms).min(now),
        MessageContent::Reaction { reacted_at_ms, .. } => *reacted_at_ms = (*reacted_at_ms).min(now),
        MessageContent::HistorySyncResponse { messages, .. } => {
            for m in messages.iter_mut() {
                m.timestamp = m.timestamp.min(now);
                m.sent_at_ms = m.sent_at_ms.min(now);
            }
        }
        _ => {}
    }
}

/// `export_recovery` refuses a shorter passphrase. The clients check it
/// first, to say so: the export call itself returns no reason.
pub const RECOVERY_PASSPHRASE_MIN_CHARS: usize = 12;

/// Signed in place of the text when the author deletes a group message, so a
/// deletion is not the signature of an empty text.
pub(crate) const GROUP_TOMBSTONE: &str = "\u{0}typeon-group-deleted";

/// The pending packet id an incoming payload answers (a history answer or an
/// Ack), so a rotation it carries does not resend that packet.
pub(crate) fn answered_pending_id(payload: &[u8]) -> Option<String> {
    match MessageContent::from_cbor(payload).ok()? {
        MessageContent::HistorySyncResponse { request_id, .. } => Some(request_id),
        MessageContent::Ack { target_message_id } => Some(target_message_id),
        _ => None,
    }
}

/// the archive row id of a group text copy (`None` for anything else).
/// every member device carries ~4 KB of keys (+ a proof); past the 1 MiB
/// envelope cap the update fails `MessageTooLarge` per member. 64 KiB for
/// the packet around it (header, hybrid signatures, encryption).
pub(crate) fn check_group_update_size(update: &GroupUpdate) -> Result<(), String> {
    if ciborium_bytes(update)?.len() + 64 * 1024 > MAX_ENVELOPE_BYTES {
        return Err("Group update too large (too many members/devices)".to_string());
    }
    Ok(())
}

pub(crate) fn group_row_id(content: &MessageContent) -> Option<&str> {
    match content {
        MessageContent::Text { group_id: Some(_), group_message_local_id: Some(l), .. } => Some(l.as_str()),
        _ => None,
    }
}

/// What the author of a group message signs (`sign_group_author`). Length
/// prefixes keep two different field splits from giving the same bytes.
/// The send time is not in it: receivers store their own.
pub(crate) fn group_author_statement(group_id: &str, message_id: &str, author_identity_id: &str, device_fp: &str, text: &str) -> Vec<u8> {
    let mut out = b"typeon-group-author-v1".to_vec();
    for part in [group_id, message_id, author_identity_id, device_fp, text] {
        out.extend_from_slice(&(part.len() as u64).to_le_bytes());
        out.extend_from_slice(part.as_bytes());
    }
    out
}

/// Fixed-window counter: counts and allows unless `cap` was reached in the
/// current `RATE_LIMIT_WINDOW_MS` window.
pub(crate) fn window_allow(slot: &mut (u64, u32), cap: u32) -> bool {
    let now = mono_ms();
    if now.saturating_sub(slot.0) > RATE_LIMIT_WINDOW_MS {
        *slot = (now, 0);
    }
    if slot.1 >= cap {
        return false;
    }
    slot.1 += 1;
    true
}

/// The source with the most entries in a full buffer (the one to evict from).
/// Server mail (`None`) is not one source but many senders, and it is already
/// acked at the server: it goes only when no peer-sourced entry is left.
pub(crate) fn busiest_source(sources: impl Iterator<Item = Option<PeerId>>) -> Option<PeerId> {
    let mut counts: HashMap<PeerId, usize> = HashMap::new();
    for s in sources.flatten() {
        *counts.entry(s).or_default() += 1;
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(s, _)| s)
}

/// Changes whenever a first-contact secret row (`pn:`/`pk:`/`pt:`, the shown
/// codes, the group master) is written through `meta_put`/`meta_del`; part of the `first_contact_secrets` cache key.
pub(crate) static FIRST_CONTACT_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn bump_first_contact_gen(k: &str) {
    if k.starts_with("pn:") || k.starts_with("pk:") || k.starts_with("pt:") || k == "pairing_nonces" || k == "own_gfc" {
        FIRST_CONTACT_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub(crate) fn ciborium_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// CRITICAL: `start_network` used to generate a RANDOM, temporary libp2p identity (and therefore a new `PeerId`) with
/// `Keypair::generate_ed25519()` on every process start. That was one root cause of "after a full restart I have to scan the QR again":
/// a known contact's `PeerId` (see `device_to_peer_id`) became invalid on every restart, because the other side had changed its own `PeerId` too.
/// The identity is now persisted at `{app_files_dir}/libp2p_identity.key` (protobuf encoding), generated once and kept.
/// This file is not encrypted (unlike the Android Keystore). That is a deliberate scope decision: it is a transport identity only,
/// separate from the E2E identity and session keys that protect message content (see IdentityManager). Leaking it does not expose message content.
/// It only allows impersonating the device at the network layer. It sits in app-private storage, at the same trust level as the public keys
/// in the same DB file.
pub(crate) fn load_or_generate_libp2p_keypair(app_files_dir: &str) -> libp2p::identity::Keypair {
    let path = format!("{}/libp2p_identity.key", app_files_dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
                return kp;
            }
            error!("libp2p_identity.key is corrupt, generating new identity");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        // The file may be intact despite an I/O error, so it is not overwritten: every contact's stored address carries its PeerId. Use a key for this run only.
        Err(e) => {
            error!("libp2p_identity.key could not be read ({}), temporary identity for this run", e);
            return libp2p::identity::Keypair::generate_ed25519();
        }
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    match kp.to_protobuf_encoding() {
        Ok(bytes) => {
            // Temp file with owner-only permissions, then rename. A crash during a plain write would leave exactly the corrupt file that is replaced
            // by a new identity above. On desktop the key was also readable by other users.
            let tmp = format!("{}.tmp", path);
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let written = opts.open(&tmp)
                .and_then(|mut f| { use std::io::Write; f.write_all(&bytes)?; f.sync_all() })
                .and_then(|_| std::fs::rename(&tmp, &path));
            if let Err(e) = written {
                error!("libp2p_identity.key could not be written (used in this process but not persistent): {}", e);
            }
        }
        Err(e) => error!("libp2p keypair encode edilemedi: {}", e),
    }
    kp
}

/// Connection path quality, higher is better: 0 = relay circuit, 1 = Tor (onion dial, or the loopback address an inbound onion connection shows).
pub(crate) fn conn_path_rank(addr: &Multiaddr) -> u8 {
    use libp2p::multiaddr::Protocol;
    let relayed = addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
        // an inbound relayed connection reports only `/p2p/<peer>`
        || matches!(addr.iter().next(), Some(Protocol::P2p(_)) | None);
    if relayed {
        return 0;
    }
    let onion = addr.iter().any(|p| match p {
        Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) | Protocol::Dnsaddr(h) => h.ends_with(".onion"),
        Protocol::Onion(..) | Protocol::Onion3(_) => true,
        _ => false,
    });
    // Onion-only: a direct clearnet path is NO LONGER preferred.
    // Clearnet used to be 2 and onion 1 (the real IP was preferred for speed). Now only onion (and loopback from our own onion service)
    // is preferred, and clearnet drops to the same lowest level as relay (0). `DialReject` means clearnet connections are never made at all.
    // This level only guarantees that a clearnet path, if one appears anyway, never ranks above onion.
    if onion || is_loopback_multiaddr(addr) { 1 } else { 0 }
}

/// The peer an address leads to: the LAST `/p2p`. In a relay circuit address
/// (`/.../p2p/<relay>/p2p-circuit/p2p/<peer>`) the first one is the relay.
/// Returning it made `try_reconnect_device` see "already connected" (to the
/// server relay), so a device last reached over a circuit was never redialed.
pub(crate) fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().filter_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    }).last()
}

/// Loopback addresses such as 127.0.0.1 / ::1 can never be dialed from another device. `get_node_address` avoids selecting them as the QR or
/// rendezvous address (a real LAN address is preferred when one exists).
pub(crate) fn is_loopback_multiaddr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

/// RFC 1918 private ranges (10/8, 172.16/12, 192.168/16), the usual home and office Wi-Fi address format, detected with the stdlib's
/// `Ipv4Addr::is_private()`. Mobile carrier addresses (including CGNAT, for example 100.64/10) are NOT in this range. `get_node_address`
/// uses this distinction to pick the interface a peer on the same Wi-Fi can actually dial.
pub(crate) fn is_private_lan_multiaddr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_private(),
        _ => false,
    })
}

/// Detects whether an address is a `.onion` (Tor) address. See the `device_onion_addr` field docs.
/// The same logic as the private `onion_host_port` in tor.rs is needed here too, because that function is private to the `tor` module.
/// Network-robustness fix: a device paired over Tor, on the same LAN as another device, could only keep talking to it through the node (not directly)
/// after switching to mobile data.
pub(crate) fn is_onion_multiaddr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Dns(h) | libp2p::multiaddr::Protocol::Dns4(h) | libp2p::multiaddr::Protocol::Dns6(h) => {
            h.ends_with(".onion")
        }
        libp2p::multiaddr::Protocol::Onion3(_) => true,
        _ => false,
    })
}

/// Both signature fields are now REQUIRED. Before, either could be empty and that part was silently skipped, so a classical-only or
/// PQ-only signed packet was accepted. No caller exploited this, but the function did not enforce it. A hybrid security guarantee
/// must not silently fall back to classical signatures if a caller ever passes an empty `sig_pq` by mistake.
pub(crate) fn verify_hybrid_signature(message: &[u8], sig_classical: &[u8], sig_pq: &[u8], sender: &DeviceRecord) -> Result<(), String> {
    verify_hybrid_signature_with(message, sig_classical, sig_pq, &sender.sign_pubkey_ed25519, &sender.sign_pubkey_mldsa)
}

pub(crate) fn verify_hybrid_signature_with(message: &[u8], sig_classical: &[u8], sig_pq: &[u8], pubkey_ed25519: &[u8], pubkey_mldsa: &[u8]) -> Result<(), String> {
    if sig_classical.is_empty() || sig_pq.is_empty() {
        return Err("Hybrid signature requires both classical and post-quantum components".to_string());
    }
    let pk_bytes: [u8; 32] = pubkey_ed25519.try_into().map_err(|_| "Bad Ed25519 key length")?;
    let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| "Bad Ed25519 key")?;
    let sig_bytes: [u8; 64] = sig_classical.to_vec().try_into().map_err(|_| "Bad signature length")?;
    let sig = Ed25519Signature::from_bytes(&sig_bytes);
    // Strict: no second valid encoding of one signature.
    pk.verify_strict(message, &sig).map_err(|_| "Ed25519 verification failed")?;

    let pk_encoded: EncodedVerifyingKey<MlDsa87> = pubkey_mldsa.try_into().map_err(|_| "Bad ML-DSA key")?;
    let pk = MlDsaVerifyingKey::<MlDsa87>::decode(&pk_encoded);
    let sig_encoded: EncodedSignature<MlDsa87> = sig_pq.try_into().map_err(|_| "Bad PQ signature")?;
    let sig = MlDsaSignature::<MlDsa87>::decode(&sig_encoded).ok_or("Bad PQ signature")?;
    pk.verify(message, &sig).map_err(|_| "ML-DSA verification failed")?;
    Ok(())
}

/// The bytes covered by a `GroupUpdate` signature: one CBOR tuple with a domain tag. The name, member list, and member keys are included
/// (a relay could otherwise change them), and so are the signer fields.
///
/// Protocol break: earlier versions concatenated the fields with no length prefixes, and `signed_by` / `signed_by_device` were not signed.
/// A client with the old format rejects updates from a new one, and the other way round.
#[allow(clippy::too_many_arguments)]
pub(crate) fn group_update_signing_input(
    group_id: &str,
    new_version: u32,
    change: &GroupChange,
    group_name: &str,
    members: &[String],
    member_devices: &[GroupMemberDevice],
    signed_by: &str,
    signed_by_device: &str,
) -> Result<Vec<u8>, String> {
    ciborium_bytes(&(
        "typeon-group-update-v2", group_id, new_version, change, group_name,
        members, member_devices, signed_by, signed_by_device,
    ))
}

/// what decides between two updates of the same group version (the
/// larger wins on every member). Covers the state, not `member_devices`:
/// a full and a delta copy of one update are the same update.
pub(crate) fn group_tie_hash(u: &GroupUpdate) -> Result<Vec<u8>, String> {
    let bytes = ciborium_bytes(&("typeon-group-tie-v1", &u.group_id, u.new_version, &u.change, &u.group_name, &u.members, &u.signed_by))?;
    Ok(<sha2::Sha256 as sha2::Digest>::digest(&bytes).to_vec())
}

pub(crate) fn sign_group_update(
    group_id: &str,
    new_version: u32,
    change: &GroupChange,
    group_name: &str,
    members: &[String],
    member_devices: &[GroupMemberDevice],
    member_device_proofs: &[packet::DeviceAddProof],
    signed_by: &str,
    signed_by_device: &str,
    own_keys: &DeviceKeys,
    founder_chain: &[packet::FounderTransfer],
) -> Result<GroupUpdate, String> {
    let to_sign = group_update_signing_input(
        group_id, new_version, change, group_name, members, member_devices, signed_by, signed_by_device,
    )?;
    // GroupUpdate now uses the SAME hybrid signature model (Ed25519 + ML-DSA) as MessagePacket and HandshakeInit.
    // Before, it was signed ONLY with classical Ed25519, so a quantum-capable attacker could forge the founder's authority
    // (adding and removing members, renaming, changing the avatar).
    let sig_classical: Ed25519Signature = own_keys.sign_sk_ed25519.sign(&to_sign);
    let sig_pq: MlDsaSignature<MlDsa87> = own_keys.sign_sk_mldsa.sign(&to_sign);
    Ok(GroupUpdate {
        group_id: group_id.to_string(),
        new_version,
        change: change.clone(),
        group_name: group_name.to_string(),
        members: members.to_vec(),
        member_devices: member_devices.to_vec(),
        // Not in `to_sign`: see `GroupUpdate.member_device_proofs`.
        member_device_proofs: member_device_proofs.to_vec(),
        signed_by: signed_by.to_string(),
        signed_by_device: signed_by_device.to_string(),
        signature: sig_classical.to_bytes().to_vec(),
        signature_pq: sig_pq.encode().to_vec(),
        // See `packet::FounderTransfer`. It is NOT covered by the outer signature (each entry carries its own hybrid signature). That is why
        // it is not added to the `to_sign` block above. Adding it would break signature verification on an older sender/receiver pair that does not know this field.
        founder_chain: founder_chain.to_vec(),
    })
}

pub(crate) trait OptionGroupExt {
    fn cloned_group(self) -> Result<Group, String>;
}
impl OptionGroupExt for Option<&Group> {
    fn cloned_group(self) -> Result<Group, String> {
        self.cloned().ok_or_else(|| "Group not found".to_string())
    }
}
