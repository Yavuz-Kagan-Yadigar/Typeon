//! Attachment offers, chunked downloads and serving chunks.

use super::*;

impl P2PCore {

    /// No separate `attachment_key` is generated. We reuse `skipped_key_encryption_key` (see its docs), which is always loaded regardless
    /// of node mode. This lets the sender keep its own encrypted copy of the file (the `file_key` is always stored encrypted on disk, even
    /// with node mode off) without a new Keystore key or lifecycle class on the Kotlin side. The same KEK keeps wrapping other small secrets
    /// (skipped message keys, ratchet state, and now file keys) with fresh nonces.
    pub(crate) fn wrap_file_key(&self, file_key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let enc_key = self.skipped_key_encryption_key.ok_or("File key not loaded yet")?;
        let (encrypted, nonce_bytes) = seal_with(&enc_key, file_key.as_slice()).ok_or("File key encryption failed")?;
        Ok((encrypted, nonce_bytes.to_vec()))
    }

    pub(crate) fn unwrap_file_key(&self, encrypted: &[u8], nonce_bytes: &[u8]) -> Result<[u8; 32], String> {
        let enc_key = self.skipped_key_encryption_key.ok_or("File key not loaded yet")?;
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key).map_err(|_| "Invalid key")?;
        if nonce_bytes.len() != 12 {
            return Err("Bad nonce length".to_string());
        }
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, encrypted).map_err(|_| "File key decryption failed")?;
        plaintext.as_slice().try_into().map_err(|_| "Bad file key length".to_string())
    }

    /// Encrypts a file the user picked (Kotlin must already have copied it to a local path; content:// URIs are not handled here, see P2PLib.kt),
    /// writes it to disk, adds the sender's own record to the `files` table (the sender always keeps a copy, independent of node mode), and sends
    /// the peer a `FileOffer` metadata message.
    /// KNOWN LIMIT: `encrypt_file_to_disk` is bounded-memory but SYNCHRONOUS: the `CORE` lock is held for the whole call. For a very large
    /// (GB-scale) file, `pollNetwork` and other JNI calls can be delayed for that time. Messaging itself is not broken, only deferred by seconds
    /// or tens of seconds. A fully asynchronous design (separate worker thread + channel) is out of scope for now.
    /// Fix: file encryption now runs outside the lock. The old single-piece `prepare_and_send_file`/`prepare_and_send_group_file` ran the
    /// ChaCha20 encryption of up to 4 GB while holding the GLOBAL core lock. `poll_events` could not run during that time (the swarm was not
    /// polled, incoming keepalive requests went unanswered), and peers dropped the connection as half-open after ~20-30 s. Sending a large video
    /// effectively took the node offline.
    /// Now there are three phases: `begin_outgoing_file` (short, locked: validation, id and key generation), the encryption itself (unlocked, see
    /// the free function `prepare_and_send_file_unlocked` at the end of this file), and `finish_outgoing_file`/`finish_outgoing_group_file` (short,
    /// locked: DB record and FileOffer send).
    ///
    /// The `skipped_key_encryption_key` check runs early (before encryption) on purpose: otherwise key wrapping would fail after GBs were
    /// processed, leaving an orphan `.enc` on disk with no DB row. The size check is here for the same reason.
    pub(crate) fn begin_outgoing_file(&self, source_path: &str, group_id: Option<&str>) -> Result<(String, [u8; 32], std::path::PathBuf), String> {
        if self.skipped_key_encryption_key.is_none() {
            return Err("File key not loaded yet, try again shortly".to_string());
        }
        if let Some(gid) = group_id {
            // Group not present locally: do not start encryption at all.
            if !self.groups.contains_key(gid) {
                return Err("Unknown group".to_string());
            }
        }
        let source_size = std::fs::metadata(source_path).map(|m| m.len()).map_err(|e| e.to_string())?;
        if source_size > MAX_ATTACHMENT_SIZE {
            return Err(format!(
                "File too large ({} bytes) — max size {} bytes (4GB)",
                source_size, MAX_ATTACHMENT_SIZE
            ));
        }
        // `enforce_history_storage_limit` would evict this very file right
        // after it is stored, and the offer would go out for a file nobody
        // can download.
        if self.node_mode_enabled && source_size > self.history_storage_limit_bytes {
            return Err("File too large for storage limit".to_string());
        }

        let mut file_key = [0u8; 32];
        {
            use rand::RngCore;
            OsRng.fill_bytes(&mut file_key);
        }
        // The id is the hash of the server upload secret (see
        // `blob_upload_secret`), so no recipient can claim the server blob.
        // In a group it starts with our author tag, which members check
        // (`group_msg_tag`); a 1:1 file gets a random one.
        // The group tag is made from the id's hash part, so it differs per
        // file.
        let secret_rest = self.blob_upload_secret(&file_key, &[0u8; 8]).ok_or_else(|| "History key not loaded".to_string())?;
        let hash_hex = server_proto::blob_id_hash_hex(&secret_rest[server_proto::BLOB_TAG_LEN..]);
        let tag: [u8; 8] = match group_id {
            Some(gid) => group_msg_tag(gid, &self.my_identity_id().ok_or("No identity")?, &hash_hex),
            None => { use rand::RngCore; let mut t = [0u8; 8]; OsRng.fill_bytes(&mut t); t }
        };
        let file_id = self
            .blob_upload_secret(&file_key, &tag)
            .and_then(|secret| server_proto::blob_id_for_upload_secret(&secret))
            .ok_or_else(|| "History key not loaded".to_string())?;

        let _ = std::fs::create_dir_all(self.attachments_dir()?);
        let dest_path = self.enc_path_for(&file_id)?;
        Ok((file_id, file_key, dest_path))
    }

    /// See `begin_outgoing_file`: the final locked phase (1:1). Encryption already finished in the unlocked phase. Here the key is wrapped,
    /// the DB record is written, and the `FileOffer` is sent.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_outgoing_file(&mut self, peer_device_fingerprint: String, file_id: String, file_key: [u8; 32], total_size: u64, sha256_hex: String, chunk_hashes: Vec<u8>, file_name: String, mime_type: String, preview_jpeg: Option<Vec<u8>>, duration_ms: Option<u32>, caption: String, reply_to_message_id: Option<String>, reply_to_preview: Option<String>, sticker_origin: Option<String>) -> Result<(String, String), String> {
        let sticker = sticker_origin.is_some();
        let (encrypted_key, key_nonce) = self.wrap_file_key(&file_key)?;
        if let Some(conn) = &self.db {
            // The column list has 18 entries, matching VALUES. `caption`, `reply_to_message_id` and `reply_to_preview` were in VALUES but missing from the column list. SQLite rejects the mismatch and `let _ =` hid the error, so the sender never stored its own 1:1 attachment. `serve_chunk_request` then answered "no record" and the bubble vanished on reopen. Keep the two lists in step.
            let res = conn.execute(
                "INSERT OR REPLACE INTO files
                 (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size,
                  sha256_hex, encrypted_file_key, key_nonce, status, bytes_transferred, created_at, preview_jpeg, duration_ms, chunk_size,
                  caption, reply_to_message_id, reply_to_preview, sticker, sticker_origin, chunk_hashes, sent_at_ms)
                 VALUES (?1, ?2, 'sent', ?3, ?4, ?5, ?6, ?7, ?8, 'complete', ?5, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?9)",
                params![
                    file_id, peer_device_fingerprint, file_name, mime_type, total_size as i64,
                    sha256_hex, encrypted_key, key_nonce, current_time_ms() as i64, preview_jpeg, duration_ms,
                    attachments::FILE_CHUNK_SIZE_V2 as i64,
                    caption, reply_to_message_id, reply_to_preview, sticker, sticker_origin.clone(), chunk_hashes,
                ],
            );
            // See the note above: this INSERT used to fail silently. The failure is logged now, so it cannot slip by unnoticed.
            // Without the row we cannot serve the file: sending the offer anyway gave the recipient an attachment it could never download.
            if let Err(e) = res {
                error!("finish_outgoing_file: could not write `files` row (file_id={}): {}", file_id, e);
                return Err(format!("Could not write file record: {}", e));
            }
        }
        // Our own sent file also counts toward total storage. See the `enforce_history_storage_limit` note.
        self.enforce_history_storage_limit();

        let content = MessageContent::FileOffer {
            group_id: None,
            file_id: file_id.clone(),
            file_name,
            mime_type,
            total_size,
            file_key,
            sha256_hex,
            preview_jpeg,
            duration_ms,
            chunk_size: Some(attachments::FILE_CHUNK_SIZE_V2 as u32),
            chunk_hashes,
            caption: caption.clone(),
            reply_to_message_id: reply_to_message_id.clone(),
            reply_to_preview: reply_to_preview.clone(),
            // In 1:1 the replied-to sender's id is not carried separately: the peer is one person (same rule as
            // `Text.reply_to_sender_identity_id`).
            reply_to_sender_identity_id: None,
            sticker,
            sticker_origin,
        };
        // If a server is configured (see `server_client`), upload the encrypted file there too. Recipients already speak the filexfer protocol
        // that the server serves, so nothing changes on their side: the server is just an always-on source peer.
        self.queue_blob_upload(&file_id, &file_key, attachments::total_chunks_with(total_size, attachments::FILE_CHUNK_SIZE_V2));
        // Under the file id, as a 1:1 text goes under its bubble id: status events, the Ack and "retry now" then name the bubble.
        let (_, status) = self.send_message_content_inner(peer_device_fingerprint.clone(), &content, None, Some(file_id.clone()), None, None)?;
        // Same as `send_message`: the contact's other devices plus my own siblings.
        self.fanout_extra_copies(&peer_device_fingerprint, &content);
        self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::File { offer: Box::new(content) });
        Ok((file_id, status))
    }

    /// Undoes what `finish_outgoing_file` / `finish_outgoing_group_file` wrote
    /// before they failed: the caller (`encrypt_then_finish`) deletes the
    /// `.enc`, so a 'complete' row and a queued server upload would point at a
    /// file that no longer exists.
    pub(crate) fn discard_outgoing_file(&mut self, file_id: &str) {
        self.finish_blob_upload(file_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM files WHERE file_id = ?1 AND direction = 'sent'", params![file_id]);
        }
    }

    /// Group counterpart of `prepare_and_send_file`. The file is encrypted and written to disk ONCE: `file_id`/`file_key` are SHARED among all
    /// members (see the `serve_chunk_request` note: a download request looks only at `file_id` and does not check the requester's identity, so
    /// serving the same `.enc` blob to N members works naturally, with no extra mechanism).
    /// Same pattern as `archive_group_message`/`send_group_message`: FIRST write our own archive row (once, outside the fan-out loop), THEN send
    /// a `FileOffer` to each member separately.
    /// See `begin_outgoing_file`: the final locked phase (group). Validation (the group exists) was done in the first locked phase. Here the
    /// group is checked again, since it may have been deleted during the unlocked encryption. In that case a clean error is returned, and the
    /// `.enc` is removed by the calling free function.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_outgoing_group_file(&mut self, group_id: String, file_id: String, file_key: [u8; 32], total_size: u64, sha256_hex: String, chunk_hashes: Vec<u8>, file_name: String, mime_type: String, preview_jpeg: Option<Vec<u8>>, duration_ms: Option<u32>, caption: String, reply_to_message_id: Option<String>, reply_to_preview: Option<String>, reply_to_sender_identity_id: Option<String>, sticker_origin: Option<String>) -> Result<String, String> {
        let sticker = sticker_origin.is_some();
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        let (encrypted_key, key_nonce) = self.wrap_file_key(&file_key)?;
        if let Some(conn) = &self.db {
            // See `finish_outgoing_file` (1:1), same bug: the column list (17) was shorter than the VALUES list (21), so the sender could not write
            // its `files` row for group attachments. The column list now has 21 entries: `caption`, `reply_to_message_id`, `reply_to_preview` and
            // `reply_to_sender_identity_id` were added.
            let res = conn.execute(
                "INSERT OR REPLACE INTO files
                 (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size,
                  sha256_hex, encrypted_file_key, key_nonce, status, bytes_transferred, created_at, preview_jpeg, duration_ms, group_id, sender_identity_id, chunk_size,
                  caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, chunk_hashes, sent_at_ms)
                 VALUES (?1, '', 'sent', ?2, ?3, ?4, ?5, ?6, ?7, 'complete', ?4, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?8)",
                params![
                    file_id, file_name, mime_type, total_size as i64,
                    sha256_hex, encrypted_key, key_nonce, current_time_ms() as i64, preview_jpeg, duration_ms,
                    group_id, own_identity_id, attachments::FILE_CHUNK_SIZE_V2 as i64,
                    caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin.clone(), chunk_hashes,
                ],
            );
            if let Err(e) = res {
                error!("finish_outgoing_group_file: could not write `files` row (file_id={}): {}", file_id, e);
                return Err(format!("Could not write file record: {}", e));
            }
        }
        self.enforce_history_storage_limit();

        let content = MessageContent::FileOffer {
            group_id: Some(group_id.clone()),
            file_id: file_id.clone(),
            file_name,
            mime_type,
            total_size,
            file_key,
            sha256_hex,
            preview_jpeg,
            duration_ms,
            chunk_size: Some(attachments::FILE_CHUNK_SIZE_V2 as u32),
            chunk_hashes,
            caption: caption.clone(),
            reply_to_message_id: reply_to_message_id.clone(),
            reply_to_preview: reply_to_preview.clone(),
            reply_to_sender_identity_id: reply_to_sender_identity_id.clone(),
            sticker,
            sticker_origin,
        };
        for member_identity_id in group.other_members(&own_identity_id) {
            // Like every other group send: all active devices, queued when no
            // device is known yet, skipped for deleted accounts.
            self.send_group_message_to_member(&group_id, &member_identity_id, &content);
        }
        self.echo_group_to_siblings(&group_id, SiblingEchoBody::File { offer: Box::new(content) });
        // See the same hook in `finish_outgoing_file`.
        self.queue_blob_upload(&file_id, &file_key, attachments::total_chunks_with(total_size, attachments::FILE_CHUNK_SIZE_V2));
        Ok(file_id)
    }

    /// Handles an incoming `FileOffer`: adds a recipient row to the `files` table. If node mode is on, the download starts at once. If it is off,
    /// only the metadata stays visible and the user must tap "Download".
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn receive_file_offer(&mut self, peer_fp: &str, sender_identity_id: &str, group_id: Option<String>, file_id: &str, file_name: &str, mime_type: &str, total_size: u64, file_key: &[u8; 32], sha256_hex: &str, preview_jpeg: &Option<Vec<u8>>, duration_ms: Option<u32>, chunk_size: Option<u32>, chunk_hashes: &[u8], caption: &str, reply_to_message_id: Option<&str>, reply_to_preview: Option<&str>, reply_to_sender_identity_id: Option<&str>, sticker: bool, sticker_origin: Option<&str>, sent_at_ms: u64) -> serde_json::Value {
        // The sender's clock, not later than ours (as for texts); 0 = unknown, now.
        let sent_at_ms = match sent_at_ms { 0 => current_time_ms(), t => t.min(current_time_ms()) };
        // `MAX_ATTACHMENT_SIZE`
        // Before, this was enforced ONLY on the send side (`prepare_and_send_file`/`prepare_and_send_group_file`). The RECEIVER did not check the
        // `total_size` the other side sent. A malicious or broken peer could send a `total_size` near `u64::MAX` and trigger the `total_size as i64`
        // conversion below (which wraps negative and writes a bad column value), and the `total_size + FILE_CHUNK_SIZE - 1` sum in
        // `attachments::total_chunks_with` (which can silently wrap in release builds). Both would write a corrupt row to `files`. The same upper
        // limit now applies on the receive side too. An oversized offer is rejected without writing any DB row.
        // The peer's chunk size becomes buffer sizes and file offsets here.
        if chunk_size.map_or(false, |c| !attachments::chunk_size_ok(c as usize)) {
            warn!("FileOffer REJECTED: invalid chunk size {:?} (sender: {})", chunk_size, crate::log_id(&peer_fp));
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Invalid chunk size"
            });
        }
        // `file_id` comes from the other side and becomes a file path shortly after. Validate it FIRST (see `is_safe_file_id`).
        if !is_safe_file_id(file_id) {
            warn!(
                "FileOffer REJECTED: file_id not safe as a path (sender: {}, id: {:?})",
                crate::log_id(&peer_fp), file_id
            );
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Invalid file id"
            });
        }
        // The `INSERT OR REPLACE` below has a problem: if the other side sends back the `file_id` of a file we sent to it (it knows the id because
        // we offered it), our `direction='sent'` row was overwritten as 'received'. Result: our own outgoing row was lost, `serve_chunk_request`
        // returned `NotFound` (the state is not 'complete'), so the OTHER recipients waiting on that file could not download it either. And if a
        // download was started, `download_file`'s `remove_file` deleted our own encrypted `.enc`.
        // The row is stored and passed to the UI as received.
        if sha256_hex.len() != 64 || !sha256_hex.bytes().all(|b| b.is_ascii_hexdigit())
            || mime_type.len() > 255 || caption.len() > 64 * 1024
            || preview_jpeg.as_ref().map_or(false, |p| p.len() > 512 * 1024)
        {
            warn!("FileOffer REJECTED: fields invalid or too large (sender: {})", crate::log_id(&peer_fp));
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Invalid file offer"
            });
        }
        let existing: Option<(String, Option<String>, Option<String>)> = self.db.as_ref().and_then(|conn| {
            conn.query_row(
                "SELECT direction, sender_identity_id, group_id FROM files WHERE file_id = ?1",
                params![file_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).ok()
        });
        let mut existing_direction = existing.as_ref().map(|e| e.0.clone());
        // Any existing row is final. A repeated offer (lost Ack) reset a
        // finished download to 'offered'; an offer from another chat with a
        // known file_id replaced the row's key and made the file unreadable.
        if let Some((_, row_sender, row_group)) = existing.as_ref().filter(|e| e.0 == "received") {
            // The same offer again. From somebody else, or in another chat,
            // it is another file under a taken id: a member that saw a group
            // offer first could send its own under that id, and the real one
            // was then dropped without a trace. Shown as failed instead.
            if row_sender.as_deref().map_or(true, |s| s == sender_identity_id) && *row_group == group_id {
                return serde_json::json!({"type": "noop"});
            }
            // A group file id carries its author's tag (`group_msg_tag`), a 1:1 id does not: a 1:1 row under such an id was taken by
            // someone who copied it. The real group offer replaces it.
            let author_bound = group_id.as_deref().map_or(false, |gid| group_msg_id_bound(gid, sender_identity_id, file_id));
            if author_bound && row_group.is_none() {
                warn!("FileOffer: 1:1 row under a group file id replaced by the author's offer (id: {})", file_id);
                self.delete_attachment_file(file_id);
                existing_direction = None;
            }
        }
        if existing_direction.is_some() && existing.as_ref().map_or(false, |e| e.0 == "received") {
            warn!("FileOffer REJECTED: file_id collides with another sender's file (sender: {}, id: {})", crate::log_id(&peer_fp), file_id);
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "File id collision"
            });
        }
        let collides_with_own_outgoing = existing_direction.is_some();
        if collides_with_own_outgoing {
            warn!(
                "FileOffer REJECTED: file_id collides with our OUTGOING file (sender: {}, id: {})",
                crate::log_id(&peer_fp), file_id
            );
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "File id collision"
            });
        }
        if total_size > MAX_ATTACHMENT_SIZE {
            warn!(
                "FileOffer rejected: total_size ({}) exceeds MAX_ATTACHMENT_SIZE ({}) (sender: {})",
                total_size, MAX_ATTACHMENT_SIZE, crate::log_id(&peer_fp)
            );
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "File size exceeds allowed maximum"
            });
        }
        // One hash per chunk group, signed with the offer: every chunk is
        // checked against it (`handle_chunk_response`). No list, no download.
        let offer_chunks = attachments::total_chunks_with(total_size, chunk_size.map_or(attachments::FILE_CHUNK_SIZE, |c| c as usize));
        if chunk_hashes.len() != attachments::chunk_hashes_len(offer_chunks) {
            warn!("FileOffer REJECTED: chunk hash list missing or wrong length (sender: {})", crate::log_id(&peer_fp));
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Invalid file offer"
            });
        }
        // `file_name` is controlled by the remote side and is used as both file name and displayed text. This is the single entry point: `safe_file_name` sanitises it before anything is written to the DB, so both clients and the "save to Downloads" flow are protected.
        let file_name = safe_file_name(file_name);
        let file_name = file_name.as_str();
        // 8 running downloads, at most 4 from one sender (one contact could otherwise take the whole budget). The rest stay "offered".
        // Stickers are small and shown at once: fetched in any node mode.
        // A peer's `sticker` flag forces a download, but only for a real sticker file.
        let sticker = sticker && total_size <= attachments::MAX_STICKER_BYTES
            && mime_type == "image/jxl" && file_name.to_ascii_lowercase().ends_with(".jxl");
        // Only the content id (`jxl:<offer sha>`) is kept: a reuse below is
        // checked against that hash; a peer-claimed `wa:` id is not checkable.
        let sticker_origin = sticker_origin.filter(|o| sticker && valid_sticker_origin(o) && o.strip_prefix("jxl:") == Some(sha256_hex));
        // Running downloads are charged at their declared size: each offer
        // alone fitting the limit let 8 of them overshoot it together.
        // Failed partials stay on disk for resume: counted too, or offers that are never served to the end filled the disk past the limit.
        let failed_on_disk: u64 = self.db.as_ref().and_then(|c| c.query_row(
            "SELECT COALESCE(SUM(bytes_transferred), 0) FROM files WHERE status = 'failed' AND direction = 'received'",
            [], |r| r.get::<_, i64>(0),
        ).ok()).unwrap_or(0).max(0) as u64;
        let in_flight: u64 = self.active_downloads.values().map(|d| d.total_size).sum::<u64>().saturating_add(failed_on_disk);
        let auto_download_requested = (sticker
                || self.node_mode_enabled && in_flight.saturating_add(total_size) <= self.history_storage_limit_bytes)
            && self.active_downloads.len() < 8
            && self.active_downloads.values().filter(|d| d.peer_device_fingerprint == peer_fp).count() < 4;
        // If the row cannot be written (e.g. the encryption key is not loaded yet), we continue as "offered". Reporting "downloading" without a DB
        // row would leave the Kotlin UI stuck forever on a file that `download_file` can never find (see the file-end note).
        let row_written = match self.wrap_file_key(file_key) {
            Ok((encrypted_key, key_nonce)) => {
                let status = if auto_download_requested { "downloading" } else { "offered" };
                let ok = if let Some(conn) = &self.db {
                    conn.execute(
                        "INSERT OR REPLACE INTO files
                         (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size,
                          sha256_hex, encrypted_file_key, key_nonce, status, bytes_transferred, created_at, preview_jpeg, duration_ms, group_id, sender_identity_id, chunk_size,
                          caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, chunk_hashes, sent_at_ms)
                         VALUES (?1, ?2, 'received', ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
                        params![
                            file_id, peer_fp, file_name, mime_type, total_size as i64,
                            sha256_hex, encrypted_key, key_nonce, status, current_time_ms() as i64, preview_jpeg, duration_ms,
                            group_id, sender_identity_id,
                            // `None`: an offer from a sender that did not set a chunk size:
                            // legacy default of 256 KiB (see `FileOffer.chunk_size`).
                            chunk_size.map(|v| v as i64).unwrap_or(attachments::FILE_CHUNK_SIZE as i64),
                            caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, chunk_hashes,
                            sent_at_ms as i64,
                        ],
                    ).is_ok()
                } else {
                    false
                };
                ok
            }
            Err(e) => {
                error!("Could not wrap file key for FileOffer: {}", e);
                false
            }
        };

        // Before, a failure of `download_file` here (e.g. because `device_to_peer_id` has no entry for this peer yet) was only logged. The caller
        // (Kotlin) always saw "auto_downloading": true, and the UI stayed stuck on "Downloading" forever: the download never reached
        // `active_downloads`, so it never produced an error or completion event. Now the real result is reported in the `auto_downloading` field.
        // No row: no bubble either (it failed on tap and was gone on reload).
        // The caller sends no Ack for this, so the offer comes again.
        if !row_written {
            return serde_json::json!({"type": "noop"});
        }
        // A sticker already in my store (same content hash): made here, no transfer.
        let reused = match sticker_origin {
            Some(_) => {
                let chunk = chunk_size.map_or(attachments::FILE_CHUNK_SIZE, |c| c as usize);
                let r = self.reuse_local_sticker(file_id, file_key, chunk, sha256_hex);
                if r.is_ok() {
                    self.attachment_events.push(serde_json::json!({"type": "file_complete", "peer": self.canonical_peer_key(peer_fp), "file_id": file_id}).to_string());
                }
                r.is_ok()
            }
            None => false,
        };
        let auto_downloading = !reused && auto_download_requested && {
            match self.download_file(file_id.to_string(), peer_fp.to_string()) {
                Ok(()) => true,
                Err(e) => {
                    error!("Could not start automatic file download (node mode on): {}", e);
                    if let Some(conn) = &self.db {
                        let _ = conn.execute("UPDATE files SET status = 'failed' WHERE file_id = ?1", params![file_id]);
                    }
                    self.attachment_events.push(serde_json::json!({"type": "file_failed", "peer": self.canonical_peer_key(peer_fp), "file_id": file_id, "error": e}).to_string());
                    false
                }
            }
        };

        // The 1:1 live event is emitted under the CANONICAL chat device, so it shows in the right chat even if it came from the contact's secondary
        // device. A group event is routed by `group_id`, so `peer` does not matter there.
        let chat_peer = if group_id.is_none() { self.canonical_peer_key(peer_fp) } else { peer_fp.to_string() };
        serde_json::json!({
            // `sender_identity_id` is included in group attachments so the notification can say who sent it (see the P2PService.maybeNotify
            // "file_offer" branch). In 1:1, `peer` is enough.
            "type": "file_offer", "peer": chat_peer, "sender_identity_id": sender_identity_id,
            "group_id": group_id, "file_id": file_id, "sent_at_ms": sent_at_ms,
            "file_name": file_name, "mime_type": mime_type, "total_size": total_size,
            "auto_downloading": auto_downloading, "complete": reused, "sticker": sticker,
            // Hex-encoded, since JSON cannot carry raw binary. For a small preview (typically a few tens of KB), hex is about 37% larger than base64,
            // which does not matter. The existing `hex` crate is used to avoid adding a new dependency.
            "preview_hex": preview_jpeg.as_ref().map(|p| hex::encode(p)),
            "duration_ms": duration_ms,
            // Include the caption that comes with the attachment, and the replied-to message context if there is one. The attachment bubble shows
            // these the same way as text messages.
            "caption": caption,
            "reply_to_message_id": reply_to_message_id,
            "reply_to_preview": reply_to_preview,
            "reply_to_sender_identity_id": reply_to_sender_identity_id,
        })
    }

    /// Restarts downloads for files from `reconnected` devices whose download is partial or failed, so the file arrives once the source is back. Only received files in state 'downloading' that are no longer in `active_downloads` (the process died or gave up), or 'failed', are touched. 'offered' files the user has not started are left alone.
    /// `server_back`: a server was just enrolled, so any partial download may have its blob there, and every row is a candidate.
    /// A row without chunk hashes (an offer made before they existed) is never a candidate: `download_file` refuses it every time.
    pub(crate) fn resume_incomplete_downloads_for(&mut self, reconnected: &std::collections::HashSet<String>, server_back: bool) {
        if reconnected.is_empty() && !server_back { return; }
        let candidates: Vec<(String, String, u64)> = {
            let conn = match &self.db { Some(c) => c, None => return };
            let mut stmt = match conn.prepare(
                "SELECT file_id, peer_device_fingerprint, total_size FROM files \
                 WHERE status IN ('downloading','failed') AND direction = 'received' \
                 AND length(chunk_hashes) > 0 AND auto_resumes < ?1"
            ) { Ok(s) => s, Err(_) => return };
            stmt.query_map(params![MAX_AUTO_RESUMES], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? as u64)))
                .map(|it| it.flatten().collect())
                .unwrap_or_default()
        };
        for (file_id, owner_fp, total_size) in candidates {
            // If the source (the sender device stored in the row) was not just connected, leave it alone: it is still unreachable, and a dial
            // attempt would be pointless.
            if !server_back && !reconnected.contains(&owner_fp) { continue; }
            if self.active_downloads.contains_key(&file_id) { continue; }
            // The caps of `receive_file_offer`: 8 running, 4 per sender, and
            // the storage limit. The rest waits for a later reconnect or a tap.
            if self.active_downloads.len() >= 8 { break; }
            if self.active_downloads.values().filter(|d| d.peer_device_fingerprint == owner_fp).count() >= 4 { continue; }
            let in_flight: u64 = self.active_downloads.values().map(|d| d.total_size).sum();
            if in_flight.saturating_add(total_size) > self.history_storage_limit_bytes { continue; }
            // Once per process run, unless the download has made progress since (see `handle_chunk_response`). A file that fails every time would
            // otherwise restart on every reconnect of its owner. After that it waits for a tap.
            if !self.auto_resumed_downloads.insert(file_id.clone()) { continue; }
            // Counted on disk too: a file whose source is gone for good (deleted, blob expired) was tried again, with a dial per member
            // device, at every start and server enrol. After MAX_AUTO_RESUMES it waits for a tap; progress resets the count.
            if let Some(conn) = &self.db {
                let _ = conn.execute("UPDATE files SET auto_resumes = auto_resumes + 1 WHERE file_id = ?1", params![file_id]);
            }
            info!("Partial download resumed, source reconnected: file_id={} source={}", file_id, crate::log_id(&owner_fp));
            if let Err(e) = self.download_file(file_id.clone(), owner_fp.clone()) {
                warn!("Download could not resume on reconnect: file_id={} {}", file_id, e);
            }
        }
    }

    /// Starts or resumes a file download (on the user's tap, or automatically when node mode is on). No-op if it is already downloading or complete.
    pub(crate) fn download_file(&mut self, file_id: String, peer_device_fingerprint: String) -> Result<(), String> {
        self.download_file_with(file_id, peer_device_fingerprint, None)
    }

    /// `scanned`: the chunks a background scan of the partial file found intact (see the resume block).
    fn download_file_with(&mut self, file_id: String, peer_device_fingerprint: String, scanned: Option<std::collections::HashSet<u32>>) -> Result<(), String> {
        // A partial file being scanned off the lock: that scan starts the download when it is done.
        if scanned.is_none() && RESUME_SCANS.lock().map_or(false, |s| s.contains(&file_id)) {
            return Ok(());
        }
        info!("download_file called: file_id={} peer={}", file_id, crate::log_id(&peer_device_fingerprint));
        if self.active_downloads.contains_key(&file_id) {
            info!("download_file: {} already downloading, no-op", file_id);
            return Ok(());
        }
        // without a swarm no chunk is ever requested; the UI showed
        // "downloading" for 10 min instead of an error.
        if self.swarm.is_none() {
            return Err("Network not started yet".to_string());
        }
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let row: Option<(u64, Vec<u8>, Vec<u8>, String, String, Option<String>, Option<Vec<u8>>)> = conn.query_row(
            "SELECT total_size, encrypted_file_key, key_nonce, status, peer_device_fingerprint, group_id, chunk_hashes FROM files WHERE file_id = ?1",
            params![file_id],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, String>(4)?, r.get(5)?, r.get(6)?)),
        ).ok();
        let (total_size, encrypted_key, key_nonce, status, owner_fp, group_id, chunk_hashes) = row.ok_or("Unknown file_id")?;
        let chunk_hashes = chunk_hashes.unwrap_or_default();
        // Multi-device (1.7.1): download from the REAL owner (the sender device stored in the row). The caller may have passed the chat's CANONICAL
        // device, but the file may have come from another device of that person, which does not have it. A request to the canonical device's PeerId
        // would then be wasted. If the owner in the row is empty, fall back to the caller.
        let peer_device_fingerprint = if owner_fp.is_empty() { peer_device_fingerprint } else { owner_fp };
        if status == "complete" {
            info!("download_file: {} already complete, no-op", file_id);
            return Ok(());
        }
        let file_key = self.unwrap_file_key(&encrypted_key, &key_nonce)?;

        // If a server is configured (see `server_client`), the file may also be there. This closes a gap where, before, if the
        // original sender was offline, the download silently timed out after 10 minutes and failed.
        let server_peers = self.ready_server_peers();
        let peer_id = match self.device_to_peer_id.get(&peer_device_fingerprint) {
            Some(pid) => *pid,
            None => *server_peers.first().ok_or(
                "No direct packet received from this contact yet, peer is not reachable right now",
            )?,
        };
        let cached_addr = self.peer_id_to_addr.get(&peer_id).cloned();
        let already_connected = self.swarm.as_ref().map(|s| s.is_connected(&peer_id)).unwrap_or(false);
        info!(
            "download_file: peer_id={} known, cached address={:?}, swarm already connected={}",
            crate::log_id(&peer_id), cached_addr, already_connected
        );
        if let Some(addr) = cached_addr.clone() {
            if let Some(swarm) = &mut self.swarm {
                swarm.add_peer_address(peer_id, addr);
            }
        }
        // Requests use `dial_with_relay_fallback`, like every messaging and handshake reconnect path. A bare `add_peer_address` only adds the address to the swarm's book. It starts no dial and tries no circuit through known relays, so a peer behind NAT would fail at once. Gossipsub can spread messages without a direct link, but this request-response protocol needs a real connection.
        if !already_connected {
            self.dial_with_relay_fallback(peer_id, cached_addr);
        }

        // The chunk size comes from the offer and is stored in the `files` row;
        // we must use the SAME step as the sender (see `file_chunk_size`).
        let chunk_size = self.file_chunk_size(&file_id);
        let total_chunks = attachments::total_chunks_with(total_size, chunk_size);
        // A row without the offer's chunk hashes (an offer from before they
        // existed) cannot be checked chunk by chunk: not downloaded.
        if chunk_hashes.len() != attachments::chunk_hashes_len(total_chunks) {
            return Err("Chunk hash list not found for this file, request again from sender".to_string());
        }
        let per_hash = attachments::chunks_per_hash(total_chunks);
        let enc_path = self.enc_path_for(&file_id)?;
        let _ = std::fs::create_dir_all(self.attachments_dir()?);
        // Resume: every chunk group that a previous attempt left on disk and that matches its hash in the offer is kept, wherever it is in the file.
        // The rest is fetched again. A big partial file is hashed on its own thread, not under the core lock (a multi-GB scan stalled the poll loop);
        // the thread comes back here with the result.
        let received_chunks = match scanned {
            Some(set) => set,
            None if std::fs::metadata(&enc_path).map_or(0, |m| m.len()) > RESUME_SCAN_OFF_LOCK_BYTES => {
                if let Ok(mut scans) = RESUME_SCANS.lock() {
                    scans.push(file_id.clone());
                }
                std::thread::spawn(move || {
                    let set = scan_resumable(&enc_path, &chunk_hashes, per_hash, total_chunks, chunk_size);
                    let _guard = crate::RUNTIME.enter();
                    let mut core = crate::core_lock();
                    if let Ok(mut scans) = RESUME_SCANS.lock() {
                        scans.retain(|f| f != &file_id);
                    }
                    if let Err(e) = core.download_file_with(file_id.clone(), peer_device_fingerprint, Some(set)) {
                        warn!("download_file {}: {}", file_id, e);
                    }
                });
                return Ok(());
            }
            None => scan_resumable(&enc_path, &chunk_hashes, per_hash, total_chunks, chunk_size),
        };
        let resumed_bytes: u64 = received_chunks.iter().map(|&i| attachments::chunk_plain_len(total_size, chunk_size, i)).sum();
        let resumed = (0..total_chunks).find(|i| !received_chunks.contains(i)).unwrap_or(total_chunks);
        if !received_chunks.is_empty() {
            info!("download_file: {} resuming from where it stopped, {}/{} chunks on disk", file_id, received_chunks.len(), total_chunks);
        }

        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET status = 'downloading', bytes_transferred = ?2 WHERE file_id = ?1", params![file_id, resumed_bytes as i64]);
        }

        // If this is a group file, collect the other members' known/active devices (EXCLUDING the main source) as alternative candidates. See the
        // `DownloadState.alt_source_peer_ids` docs. We do not know who really has the file, so all of them are candidates. Those that do not have it
        // just return `NotFound` at once (harmless).
        let alt_source_peer_ids: std::collections::VecDeque<PeerId> = match &group_id {
            Some(gid) => self.groups.get(gid)
                .map(|g| g.member_identity_ids())
                .unwrap_or_default()
                .into_iter()
                .flat_map(|member_id| self.active_devices_for_identity(&member_id))
                .filter(|fp| fp != &peer_device_fingerprint)
                .filter_map(|fp| self.device_to_peer_id.get(&fp).copied())
                .collect(),
            // 1:1: my own siblings. In the echo of a file my sibling sent, the row's owner is the contact, but the file itself is on the sibling.
            None => self.sibling_active_devices()
                .into_iter()
                .filter(|fp| fp != &peer_device_fingerprint)
                .filter_map(|fp| self.device_to_peer_id.get(&fp).copied())
                .collect(),
        };
        // Servers go FIRST: a server is always on by definition, not a peer device. If the file is not there either, `serve_chunk_request` answers
        // `NotFound` at once, so a wrong guess costs one round trip.
        let mut alt_source_peer_ids = alt_source_peer_ids;
        for sp in server_peers.into_iter().rev() {
            if sp != peer_id {
                alt_source_peer_ids.push_front(sp);
            }
        }

        self.active_downloads.insert(file_id.clone(), DownloadState {
            chunk_hashes,
            per_hash,
            pending_chunks: std::collections::HashMap::new(),
            bad_sources: std::collections::HashSet::new(),
            peer_id,
            peer_device_fingerprint: peer_device_fingerprint.clone(),
            total_size,
            total_chunks,
            next_chunk_index: resumed,
            bytes_done: resumed_bytes,
            file_key,
            enc_path,
            last_progress_at: current_time_ms(),
            last_retry_at: current_time_ms(),
            alt_source_peer_ids,
            retries_on_current_source: 0,
            inflight_chunks: std::collections::HashSet::new(),
            received_chunks,
            window: DOWNLOAD_WINDOW_START,
            chunk_sent_at: std::collections::HashMap::new(),
            rtt_min: u64::MAX,
            started_at: current_time_ms(),
            chunk_size,
            retry_at: 0,
        });
        self.request_next_chunk(&file_id);
        Ok(())
    }

    /// Requests the next chunk. When the sequence is done (`next_chunk_index >= total_chunks`), counts the download as complete. Network robustness
    /// fix: if this is a RETRY (see `retry_or_give_up_download`; a request for the same `next_chunk_index` may already have been sent), the OLD
    /// request id is cleared from `download_request_ids` FIRST. Otherwise a late old response or error could be applied to the WRONG chunk (data
    /// corruption), even after `next_chunk_index` has moved on.
    pub(crate) fn request_next_chunk(&mut self, file_id: &str) {
        // The completion condition now looks at the number of chunks RECEIVED. `next_chunk_index` is only the contiguous water level (see `received_chunks`).
        let done = match self.active_downloads.get(file_id) {
            Some(s) => s.received_chunks.len() as u32 >= s.total_chunks,
            None => return,
        };
        if done {
            self.finalize_download(file_id);
            return;
        }
        // Fill the pipeline: request the first `window` missing chunks at once. With a single chunk in flight, speed was locked to the round-trip
        // time. A fixed, too-deep window, on the other hand, choked the pipe (see `DOWNLOAD_WINDOW_START`).
        let (want, peer): (Vec<u32>, PeerId) = match self.active_downloads.get(file_id) {
            Some(s) => {
                let mut v = Vec::new();
                // Everything below the contiguous mark is already here.
                for idx in s.next_chunk_index..s.total_chunks {
                    if v.len() + s.inflight_chunks.len() >= s.window {
                        break;
                    }
                    if s.received_chunks.contains(&idx) || s.inflight_chunks.contains(&idx) || s.pending_chunks.contains_key(&idx) {
                        continue;
                    }
                    v.push(idx);
                }
                (v, s.peer_id)
            }
            None => return,
        };
        if want.is_empty() {
            return;
        }
        let mut issued: Vec<(request_response::OutboundRequestId, u32)> = Vec::new();
        if let Some(swarm) = &mut self.swarm {
            for idx in want {
                let request_id = swarm.behaviour_mut().file_chunks.send_request(
                    &peer, FileChunkRequest { file_id: file_id.to_string(), chunk_index: idx },
                );
                issued.push((request_id, idx));
            }
        }
        let now = current_time_ms();
        for (request_id, idx) in issued {
            if let Some(s) = self.active_downloads.get_mut(file_id) {
                s.inflight_chunks.insert(idx);
                s.chunk_sent_at.insert(idx, now);
            }
            self.download_request_ids.insert(request_id, (file_id.to_string(), idx));
        }
    }

    /// Moves the download to its next alternative source (see
    /// `DownloadState.alt_source_peer_ids`) and dials it. `None`: no candidate
    /// left, nothing changed. The caller asks for the chunks again
    /// (`request_next_chunk`).
    pub(crate) fn switch_to_alt_source(&mut self, file_id: &str) -> Option<PeerId> {
        // The list is built when the download starts: a server that was not
        // connected yet (the app had just started) was never tried, and a
        // file whose sender is offline retried that sender for 10 minutes.
        let ready = self.ready_server_peers();
        let s = self.active_downloads.get_mut(file_id)?;
        if s.alt_source_peer_ids.is_empty() {
            s.alt_source_peer_ids.extend(ready.into_iter().filter(|p| *p != s.peer_id && !s.bad_sources.contains(p)));
        }
        // A source that served a chunk not matching the offer's hashes is
        // never picked again in this attempt.
        let next_peer = loop {
            let p = s.alt_source_peer_ids.pop_front()?;
            if !s.bad_sources.contains(&p) {
                break p;
            }
        };
        s.peer_id = next_peer;
        s.retries_on_current_source = 0;
        // Requests sent to the old source will never arrive. If they are not cleared, those indices count as "in flight" forever and the window
        // never refills.
        s.inflight_chunks.clear();
        s.chunk_sent_at.clear();
        // The capacity of the new source is unknown, so the window and the base latency measurement start over.
        s.window = DOWNLOAD_WINDOW_START;
        s.rtt_min = u64::MAX;
        // Up to `window` requests are still open at the old source. Their late
        // answers (it usually says NotFound to each) must not count against
        // the new source: every one of them switched the source again, and a
        // download that ran fine used up its candidates and failed.
        self.download_request_ids.retain(|_, (fid, _)| fid != file_id);
        let already_connected = self.swarm.as_ref().map(|s| s.is_connected(&next_peer)).unwrap_or(false);
        if !already_connected {
            // With its address: relays alone never reached a member we share
            // no connected relay with.
            let direct = self.peer_id_to_addr.get(&next_peer).cloned();
            self.dial_with_relay_fallback(next_peer, direct);
        }
        Some(next_peer)
    }

    /// Called when a chunk request stalled (`check_stalled_downloads`) or an explicit `OutboundFailure` arrives from libp2p. If
    /// `DOWNLOAD_GIVE_UP_TIMEOUT_MS` has not passed since the LAST REAL progress (`last_progress_at`), the SAME chunk is requested again
    /// (`request_next_chunk`). Everything should be retried until acknowledged, up to a long timeout of ~10 min. Once that has passed, the download
    /// really gives up and is counted as failed.
    pub(crate) fn retry_or_give_up_download(&mut self, file_id: &str, reason: &str) {
        let now = current_time_ms();
        let elapsed_since_progress = match self.active_downloads.get(file_id) {
            Some(s) => now.saturating_sub(s.last_progress_at),
            None => return,  // the download was already removed or cancelled
        };
        if elapsed_since_progress > DOWNLOAD_GIVE_UP_TIMEOUT_MS {
            error!(
                "Download made no progress for {} min, giving up: file_id={} ({})",
                DOWNLOAD_GIVE_UP_TIMEOUT_MS / 60_000, file_id, reason
            );
            self.fail_download(file_id, reason);
            return;
        }
        // The current source has not made progress several times in a row AND an alternative candidate exists (see
        // `DownloadState.alt_source_peer_ids`): switch to the next candidate instead of polling the same source forever.
        const RETRIES_BEFORE_SOURCE_SWITCH: u32 = 2;
        let over_limit = {
            let s = match self.active_downloads.get_mut(file_id) { Some(s) => s, None => return };
            s.last_retry_at = now;
            s.retries_on_current_source += 1;
            s.retries_on_current_source > RETRIES_BEFORE_SOURCE_SWITCH
        };
        let old_peer = self.active_downloads.get(file_id).map(|s| s.peer_id);
        let switched_to = if over_limit { self.switch_to_alt_source(file_id) } else { None };
        // A silent source may only be offline for a minute: it goes back to
        // the end of the list, so the candidates rotate and are not used up.
        if let (Some(_), Some(old), Some(s)) = (switched_to, old_peer, self.active_downloads.get_mut(file_id)) {
            s.alt_source_peer_ids.push_back(old);
        }
        if let Some(next_peer) = switched_to {
            warn!(
                "Download got no reply from current source {} times, switching to an ALTERNATIVE source: file_id={} new_peer={}",
                RETRIES_BEFORE_SOURCE_SWITCH, file_id, crate::log_id(&next_peer)
            );
        }
        info!("Download temporarily unresponsive ({}), re-requesting chunks: file_id={}", reason, file_id);
        // In-flight requests stalled (no reply, or the source changed). If they are not cleared, those indices stay in `inflight_chunks` forever,
        // the pipeline window never refills, and the download silently stops. Asking again is safe: if the same chunk arrives twice,
        // `handle_chunk_response` ignores the second one via the `received_chunks` check.
        if let Some(st) = self.active_downloads.get_mut(file_id) {
            st.inflight_chunks.clear();
            st.chunk_sent_at.clear();
            // A stall means the pipe may be congested, so halve the window (see `DOWNLOAD_WINDOW_MIN`). If the SOURCE changed, the window was already
            // reset to its start value above, so the new source is not penalised for the old one's congestion.
            if switched_to.is_none() {
                st.window = (st.window / 2).max(DOWNLOAD_WINDOW_MIN);
            }
        }
        self.download_request_ids.retain(|_, (fid, _)| fid != file_id);
        self.request_next_chunk(file_id);
    }

    /// Fills the `"peer"` field of `file_progress`/`file_complete`/`file_failed` events. It looks first in `active_downloads` (if not yet removed),
    /// otherwise (e.g. the download already finished) in the `files` table. Returns an empty string if nothing is found. The event is still
    /// emitted, but the Kotlin side cannot match it. If there is no DB row at all, there is a bigger problem.
    /// The value is the chat key (the canonical device) that the screen listens on, not the device the file came from.
    pub(crate) fn peer_for_file(&self, file_id: &str) -> String {
        if let Some(state) = self.active_downloads.get(file_id) {
            return self.canonical_peer_key(&state.peer_device_fingerprint);
        }
        self.db.as_ref().and_then(|conn| {
            conn.query_row(
                "SELECT peer_device_fingerprint FROM files WHERE file_id = ?1",
                params![file_id],
                |r| r.get::<_, String>(0),
            ).ok()
        }).map(|fp| self.canonical_peer_key(&fp)).unwrap_or_default()
    }

    pub(crate) fn finalize_download(&mut self, file_id: &str) {
        let peer_fp = self.peer_for_file(file_id);
        info!("finalize_download: file_id={} peer={} marked status='complete', emitting file_complete event", file_id, crate::log_id(&peer_fp));
        if let Some(s) = self.active_downloads.get(file_id) {
            let secs = current_time_ms().saturating_sub(s.started_at) as f64 / 1000.0;
            if secs > 0.0 {
                info!(
                    "Download complete: {} chunks, {} bytes, {:.1} s, {:.0} KB/s, last window {}",
                    s.total_chunks, s.bytes_done, secs,
                    (s.bytes_done as f64 / 1024.0) / secs, s.window
                );
            }
        }
        // Every chunk already matched the signed offer's `chunk_hashes`, so the
        // file is the sender's; its plaintext SHA-256 is checked again on
        // every open (`decrypt_file_from_disk_with`).
        let Some(mut state) = self.active_downloads.remove(file_id) else { return };
        // A zero-byte file has no chunk, so no chunk write made its `.enc`:
        // every open failed with "No such file".
        if state.total_chunks == 0 {
            if let Ok(p) = self.enc_path_for(file_id) {
                let _ = std::fs::File::create(p);
            }
        }
        // Chunks are written without a sync each (`write_verified_chunk_at_with`): one sync before the row says complete.
        if let Ok(p) = self.enc_path_for(file_id) {
            let _ = std::fs::OpenOptions::new().write(true).open(p).and_then(|f| f.sync_data());
        }
        // the peer's `sticker` flag forced this download and
        // makes the chat decode it on sight. Only a real sticker keeps it:
        // its headers must say at most `STICKER_MAX_SIDE` a side.
        let flagged = self.db.as_ref().map_or(false, |c| {
            c.query_row("SELECT sticker FROM files WHERE file_id = ?1", params![file_id], |r| r.get::<_, i64>(0)).unwrap_or(0) != 0
        });
        if flagged {
            let side_ok = self.enc_path_for(file_id).ok()
                .and_then(|p| attachments::read_plain_chunk_with(&p, 0, &state.file_key, state.chunk_size).ok())
                .and_then(|head| attachments::jxl_head(&head))
                .map_or(false, |(w, h, _)| w <= attachments::STICKER_MAX_SIDE && h <= attachments::STICKER_MAX_SIDE);
            if !side_ok {
                warn!("Sticker-marked file is not a sticker, mark removed: {}", file_id);
                if let Some(conn) = &self.db {
                    let _ = conn.execute("UPDATE files SET sticker = 0, sticker_origin = NULL WHERE file_id = ?1", params![file_id]);
                }
            }
        }
        zeroize::Zeroize::zeroize(&mut state.file_key);
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET status = 'complete' WHERE file_id = ?1", params![file_id]);
        }
        self.attachment_events.push(serde_json::json!({"type": "file_complete", "peer": peer_fp, "file_id": file_id}).to_string());
        // Node mode may have downloaded this file AUTOMATICALLY (see receive_file_offer). See the `enforce_history_storage_limit` note.
        self.enforce_history_storage_limit();
    }

    pub(crate) fn fail_download(&mut self, file_id: &str, reason: &str) {
        let peer_fp = self.peer_for_file(file_id);
        // The partial `.enc` stays for the next attempt to resume from (`download_file`). Its size on disk goes into `bytes_transferred`, which the
        // quota counts for 'failed' rows too.
        if let Some(mut state) = self.active_downloads.remove(file_id) {
            zeroize::Zeroize::zeroize(&mut state.file_key);
        }
        self.download_request_ids.retain(|_, (fid, _)| fid != file_id);
        let on_disk = self.enc_path_for(file_id).ok()
            .and_then(|p| std::fs::metadata(p).ok())
            .map_or(0, |m| m.len());
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET status = 'failed', bytes_transferred = ?2 WHERE file_id = ?1", params![file_id, on_disk as i64]);
        }
        error!("File download failed ({}): {}", file_id, reason);
        self.attachment_events.push(serde_json::json!({"type": "file_failed", "peer": peer_fp, "file_id": file_id, "error": reason}).to_string());
    }

    /// Called from `poll_events` every turn. See the `DOWNLOAD_STALL_TIMEOUT_MS` docs. If a download exceeds this time without any progress or failure
    /// event (typically: the TCP dial never resolved, because both devices are behind NAT and not directly reachable), the SAME chunk is re-requested
    /// automatically (see `retry_or_give_up_download`). Only after `DOWNLOAD_GIVE_UP_TIMEOUT_MS` (10 min) is it really counted as failed, so the UI
    /// never shows "Downloading" forever.
    pub(crate) fn check_stalled_downloads(&mut self) {
        let now = current_time_ms();
        // see `DownloadState.retry_at`: only the missing chunks, the requests
        // still in flight are kept.
        let due: Vec<String> = self.active_downloads.iter_mut()
            .filter(|(_, s)| s.retry_at != 0 && now >= s.retry_at)
            .map(|(id, s)| { s.retry_at = 0; id.clone() })
            .collect();
        for file_id in due {
            self.request_next_chunk(&file_id);
        }
        // See `DownloadState.last_retry_at`. This field, not `last_progress_at`, spaces retries out at a reasonable interval (otherwise the same chunk
        // would be requested again on every `poll_events` turn).
        let stalled: Vec<String> = self.active_downloads.iter()
            .filter(|(_, s)| now.saturating_sub(s.last_retry_at) > DOWNLOAD_STALL_TIMEOUT_MS)
            .map(|(id, _)| id.clone())
            .collect();
        for file_id in stalled {
            self.retry_or_give_up_download(&file_id, "Connection timed out — peer did not respond");
        }
    }

    /// A chunk `peer` served did not match the offer's `chunk_hashes` (or its
    /// AEAD): `peer` is not asked again in this attempt. When it is the
    /// current source the download moves to the next one, or fails when none
    /// is left; the chunks that matched stay on disk for the next attempt.
    pub(crate) fn drop_bad_source(&mut self, file_id: &str, peer: PeerId, reason: &str) {
        let Some(s) = self.active_downloads.get_mut(file_id) else { return };
        s.bad_sources.insert(peer);
        if s.peer_id != peer {
            self.request_next_chunk(file_id);
            return;
        }
        match self.switch_to_alt_source(file_id) {
            Some(next) => {
                warn!("Chunk verification failed ({}), source dropped, switching to an ALTERNATIVE source: file_id={} new_peer={}", reason, file_id, crate::log_id(&next));
                self.request_next_chunk(file_id);
            }
            None => self.fail_download(file_id, reason),
        }
    }

    /// Called from the `FileChunks` event arm of `poll_events`. Handles an incoming chunk response.
    pub(crate) fn handle_chunk_response(&mut self, file_id: &str, chunk_index: u32, response: FileChunkResponse) {
        let data = match response {
            FileChunkResponse::Chunk { data } => data,
            FileChunkResponse::NotFound => {
                // Not retried on the same source. A "not found" from a peer is definitive: the device does not have the file, and repeating the request gives the same answer. This is the opposite of `retry_or_give_up_download`, which handles temporary network errors.
                //
                // A group file moves on to the next alternative source at once (see `DownloadState.alt_source_peer_ids`). The download gives up only when all candidates are exhausted.
                //
                // Server and peer differ: a SERVER's "not found" can mean "not yet", because the sender may still be uploading the blob chunk by chunk (see `server_blob_uploads`). Only a peer's "not found" is final (see `server_client`).
                let from_server = self
                    .active_downloads
                    .get(file_id)
                    .map(|s| s.peer_id)
                    .map(|p| self.is_server_peer(&p))
                    .unwrap_or(false);
                let old_peer = self.active_downloads.get(file_id).map(|s| s.peer_id);
                let next_peer = self.switch_to_alt_source(file_id);
                // A server's "not yet" goes back to the end of the list (once:
                // not while another server is still in it): members that say
                // "no" in a row must not use up the candidates while the
                // upload is still running. Back at the server with the list
                // empty, the throttled arm below takes over.
                if let (true, Some(_), Some(old)) = (from_server, next_peer, old_peer) {
                    let server_left = self.active_downloads.get(file_id)
                        .map_or(true, |s| s.alt_source_peer_ids.iter().any(|p| self.is_server_peer(p)));
                    if !server_left {
                        if let Some(s) = self.active_downloads.get_mut(file_id) {
                            s.alt_source_peer_ids.push_back(old);
                        }
                    }
                }
                match next_peer {
                    Some(peer) => {
                        warn!("Source file/chunk not found, switching to an ALTERNATIVE source: file_id={} new_peer={}", file_id, crate::log_id(&peer));
                        self.request_next_chunk(file_id);
                    }
                    None if from_server => {
                        // Time-limited retry (see `DOWNLOAD_GIVE_UP_TIMEOUT_MS`, 10 min): if the upload finishes, the download recovers on its own. If not, it
                        // still gives up. We do not treat this as a permanent error.
                        // Not at once: the server answers in about a second, and that caused a request loop at round-trip rate for the whole 10 min. One probe
                        // request is sent every `DOWNLOAD_RETRY_DELAY_MS` (`check_stalled_downloads`). The window grows again with the first chunk.
                        if let Some(s) = self.active_downloads.get_mut(file_id) {
                            s.inflight_chunks.remove(&chunk_index);
                            s.chunk_sent_at.remove(&chunk_index);
                            s.window = DOWNLOAD_WINDOW_MIN;
                            s.retry_at = current_time_ms() + DOWNLOAD_RETRY_DELAY_MS;
                        }
                        info!("File not ready on server yet (upload may still be running): file_id={}", file_id);
                    }
                    None => {
                        self.fail_download(file_id, "File/chunk not found on peer");
                    }
                }
                return;
            }
            // the server's rate limit. Same source, later.
            FileChunkResponse::Busy => {
                if let Some(s) = self.active_downloads.get_mut(file_id) {
                    s.inflight_chunks.remove(&chunk_index);
                    s.chunk_sent_at.remove(&chunk_index);
                    s.window = DOWNLOAD_WINDOW_MIN;
                    s.retry_at = current_time_ms() + DOWNLOAD_RETRY_DELAY_MS;
                }
                return;
            }
        };
        let (enc_path, file_key, total_chunks, chunk_size, total_size, per_hash, peer, expected) = match self.active_downloads.get(file_id) {
            Some(s) => {
                let entry = (chunk_index / s.per_hash) as usize * 32;
                let expected: [u8; 32] = match s.chunk_hashes.get(entry..entry + 32) {
                    Some(h) => h.try_into().unwrap_or([0; 32]),
                    None => return, // index past the file: not one we asked for
                };
                (s.enc_path.clone(), s.file_key, s.total_chunks, s.chunk_size, s.total_size, s.per_hash, s.peer_id, expected)
            }
            None => return,  // a cancelled download, or one that was dropped for another reason. Ignore it silently.
        };
        // A chunk that is already here (or waits for the rest of its group) is
        // not written again: a second copy could differ.
        if self.active_downloads.get(file_id).map_or(false, |s| s.received_chunks.contains(&chunk_index) || s.pending_chunks.contains_key(&chunk_index)) {
            if let Some(s) = self.active_downloads.get_mut(file_id) {
                s.inflight_chunks.remove(&chunk_index);
                s.chunk_sent_at.remove(&chunk_index);
            }
            self.request_next_chunk(file_id);
            return;
        }
        // Write the chunk at its OWN offset (not appended), since chunks arrive out of order in the pipeline. AEAD verification happens before the
        // write, so an `Auth` error writes nothing to disk.
        // Every chunk has its exact length (only the last one is short). A longer last chunk would leave bytes past the end that a correct copy
        // written later does not overwrite.
        let exact_len = attachments::chunk_plain_len(total_size, chunk_size, chunk_index) as usize + 16;
        // With one chunk per hash entry the chunk is checked against the
        // signed offer before anything is written. Every group member holds
        // the file key, so the AEAD alone does not say the sender made it.
        let written = if data.len() != exact_len {
            Err(attachments::ChunkAppendError::Auth(format!("Chunk {} does not have its length", chunk_index)))
        } else if per_hash == 1 && <sha2::Sha256 as sha2::Digest>::digest(&data)[..] != expected[..] {
            Err(attachments::ChunkAppendError::Auth(format!("Chunk {} does not match the offer's hash", chunk_index)))
        } else {
            attachments::write_verified_chunk_at_with(&enc_path, chunk_index, &data, &file_key, chunk_size)
        };
        let plaintext_len = match written {
            Ok(n) => n,
            // A forged or broken chunk: nothing was written. Its source is not
            // asked again in this attempt; the chunk comes from the next one.
            Err(attachments::ChunkAppendError::Auth(e)) => {
                self.drop_bad_source(file_id, peer, &e);
                return;
            }
            // Disk write error: the `.enc` may be partly written, so consistency is not guaranteed. A retry resumes only from chunk groups that match
            // their hash (`download_file`).
            Err(attachments::ChunkAppendError::Io(e)) => { self.fail_download(file_id, &e); return; }
        };
        // The chunks this answer makes good, with their plaintext length.
        let mut verified: Vec<(u32, u64)> = vec![(chunk_index, plaintext_len as u64)];
        if per_hash > 1 {
            // A file with more chunks than hash entries: the chunk waits on
            // disk until its whole group is here, then the group is checked.
            let first = chunk_index - chunk_index % per_hash;
            let count = per_hash.min(total_chunks - first);
            let group_in = {
                let Some(s) = self.active_downloads.get_mut(file_id) else { return };
                s.pending_chunks.insert(chunk_index, (peer, plaintext_len));
                (first..first + count).all(|i| s.pending_chunks.contains_key(&i))
            };
            verified.clear();
            if group_in {
                let ok = attachments::enc_range_hash(&enc_path, first, count, chunk_size).is_ok_and(|h| h == expected);
                let Some(s) = self.active_downloads.get_mut(file_id) else { return };
                let group: Vec<(u32, PeerId, usize)> = (first..first + count)
                    .filter_map(|i| s.pending_chunks.remove(&i).map(|(p, n)| (i, p, n)))
                    .collect();
                if ok {
                    verified = group.iter().map(|&(i, _, n)| (i, n as u64)).collect();
                } else {
                    // The group is fetched again. Its source is known only when
                    // one source served all of it; a mixed group is just
                    // fetched again (from the current source alone, so a
                    // forger that is the current source is caught next time).
                    s.inflight_chunks.remove(&chunk_index);
                    s.chunk_sent_at.remove(&chunk_index);
                    let reason = format!("Chunks {}..{} do not match the offer's hash", first, first + count);
                    if group.iter().all(|&(_, p, _)| p == group[0].1) {
                        self.drop_bad_source(file_id, group[0].1, &reason);
                    } else {
                        warn!("{} (several sources), fetched again: file_id={}", reason, file_id);
                        self.request_next_chunk(file_id);
                    }
                    return;
                }
            }
        }

        let mut emit_progress = false;
        let mut all_done = false;
        if let Some(state) = self.active_downloads.get_mut(file_id) {
            state.inflight_chunks.remove(&chunk_index);
            // Adaptive window: grow it when the round trip is below the target. If it is above the target the link is saturated, and growing it would
            // only inflate the buffer (see `DOWNLOAD_RTT_TARGET_MS`).
            if let Some(sent_at) = state.chunk_sent_at.remove(&chunk_index) {
                let rtt = current_time_ms().saturating_sub(sent_at);
                state.rtt_min = state.rtt_min.min(rtt.max(DOWNLOAD_RTT_FLOOR_MS));
                let queue_ok = rtt <= state.rtt_min.saturating_mul(DOWNLOAD_RTT_GROW_FACTOR);
                if queue_ok && rtt < DOWNLOAD_RTT_CEILING_MS && state.window < DOWNLOAD_WINDOW_MAX {
                    state.window += 1;
                }
            }
            // The same chunk arrived twice (retry race): do not count the bytes twice.
            //
            // Bug: there was a `return` here that also SKIPPED the `request_next_chunk` at the end of the function. The chunk had just been removed
            // from `inflight_chunks`, so each duplicate chunk narrowed the pipeline window by one, and no new request was opened. With enough duplicates
            // in a row, the window emptied and the download stalled until the stall timer (`DOWNLOAD_STALL_TIMEOUT_MS`, 105 s) fired. The bookkeeping is
            // now skipped but the flow continues.
            // A chunk in a group that is still waiting for the rest is progress too, but only checked chunks are counted as received.
            let mut duplicate = true;
            for &(i, n) in &verified {
                if state.received_chunks.insert(i) {
                    duplicate = false;
                    state.bytes_done += n;
                }
            }
            if !duplicate || (per_hash > 1 && verified.is_empty()) {
                // `next_chunk_index` is now the CONTIGUOUS water level. With out-of-order chunks, "highest + 1" would silently skip a gap.
                while state.received_chunks.contains(&state.next_chunk_index) {
                    state.next_chunk_index += 1;
                }
                state.last_progress_at = current_time_ms();
                // Progress is not a stall (`check_stalled_downloads`).
                state.last_retry_at = state.last_progress_at;
                // Progress was made, so the next reconnect may resume it again.
                self.auto_resumed_downloads.remove(file_id);
            }
            all_done = state.received_chunks.len() as u32 >= total_chunks;
            // The current source is really working (see the `retries_on_current_source` docs), so the source-switch counter is reset.
            state.retries_on_current_source = 0;
            // Report progress every ~8 chunks (about 2 MB) or at the last chunk. An event per chunk (4 GB / 256 KB = 16384 events) would needlessly
            // bloat the array returned by `pollNetwork`.
            emit_progress = !duplicate && (state.received_chunks.len() % 8 == 0 || all_done);
            if emit_progress {
                if let Some(conn) = &self.db {
                    let _ = conn.execute("UPDATE files SET bytes_transferred = ?1, auto_resumes = 0 WHERE file_id = ?2", params![state.bytes_done as i64, file_id]);
                }
            }
        }
        if emit_progress {
            if let Some(state) = self.active_downloads.get(file_id) {
                let ev = serde_json::json!({
                    "type": "file_progress", "peer": self.canonical_peer_key(&state.peer_device_fingerprint), "file_id": file_id,
                    "bytes_done": state.bytes_done, "bytes_total": state.total_size
                }).to_string();
                self.attachment_events.push(ev);
            }
        }
        if all_done {
            self.finalize_download(file_id);
        } else {
            self.request_next_chunk(file_id);
        }
    }

    /// Access rule for `serve_chunk_request`. See the long note there.
    ///
    /// `row_peer_fp` = `files.peer_device_fingerprint` (in 1:1, the device on the OTHER side of the chat; in a group, the device of the member who
    /// offered the file). `row_group_id` is set when the file is a group attachment.
    ///
    /// Allowed:
    /// - Our configured servers: we upload blobs there and they re-serve them to other members (see `server_flush_blobs`). Blocking them here
    ///   would break our own store-and-forward path.
    /// - Sibling devices of our own identity (multi-device, 1.7).
    /// - Group attachment: the requester's identity must be a MEMBER of that group (a removed member loses access immediately).
    /// - 1:1 attachment: the requester's identity must be the SAME as the other party's identity in the row (that person may also have another device).
    ///
    /// ACCEPTED LIMIT: `device_to_peer_id` is filled only when we receive a packet signed by that device. If a group member has never sent us
    /// anything, we do not know its PeerId. That member, when it tries us as a candidate in a multi-source download, gets `NotFound`. This is
    /// harmless: the real sender and (if any) the server are still sources, and the mapping is set up the first time that member sends a message to
    /// the group. Loosening this would mean trusting a PeerId whose authority cannot be proven.
    pub(crate) fn may_serve_file_to(&self, peer: PeerId, row_peer_fp: &str, row_group_id: Option<&str>) -> bool {
        if self.is_server_peer(&peer) {
            return true;
        }
        // A verified PeerId -> known device mapping. A device's PeerId is recorded only when we receive a packet signed by it (see
        // `record_peer_id_if_known`), so this mapping cannot be forged.
        let requester_fp = self.device_to_peer_id.iter()
            .find(|(_, pid)| **pid == peer)
            .map(|(fp, _)| fp.clone());
        let Some(requester_fp) = requester_fp else { return false };
        if self.is_blocked_device(&requester_fp) {
            return false;
        }
        let Some(requester_identity) = self.known_remote_devices.get(&requester_fp)
            .filter(|d| d.is_active)
            .map(|d| d.identity_id.clone())
        else {
            return false;
        };
        if self.my_identity_id().as_deref() == Some(requester_identity.as_str()) {
            return true;
        }
        match row_group_id {
            Some(gid) => self.groups.get(gid)
                .map(|g| g.is_member(&requester_identity))
                .unwrap_or(false),
            None => self.known_remote_devices.get(row_peer_fp)
                .map(|d| d.identity_id == requester_identity)
                .unwrap_or(false),
        }
    }

    /// The RESPONDER side of the `request_response` request: asks for one chunk of a file that this device sent, or fully downloaded and re-serves.
    /// `serve_chunk_request` within a byte budget per (peer, file) and day: `CHUNK_SERVE_FILE_MULTIPLE` times the file plus 16 MiB. The rate
    /// limit alone let an authorized peer make this device upload the same file in a loop. Past the budget: `Busy`.
    pub(crate) fn serve_chunk_request_budgeted(&mut self, peer: PeerId, request: &FileChunkRequest) -> FileChunkResponse {
        const DAY_MS: u64 = 24 * 60 * 60 * 1000;
        let now = mono_ms();
        let total: u64 = self.db.as_ref().and_then(|c| c.query_row(
            "SELECT total_size FROM files WHERE file_id = ?1", params![request.file_id], |r| r.get::<_, i64>(0),
        ).ok()).unwrap_or(0).max(0) as u64;
        let budget = total.saturating_mul(CHUNK_SERVE_FILE_MULTIPLE).saturating_add(16 * 1024 * 1024);
        if self.chunk_bytes_served.len() > 4096 {
            self.chunk_bytes_served.retain(|_, (start, _)| now.saturating_sub(*start) < DAY_MS);
            if self.chunk_bytes_served.len() > 8192 {
                self.chunk_bytes_served.clear();
            }
        }
        let key = (peer, request.file_id.clone());
        let used = match self.chunk_bytes_served.get(&key) {
            Some((start, used)) if now.saturating_sub(*start) < DAY_MS => *used,
            _ => 0,
        };
        if used >= budget {
            return FileChunkResponse::Busy;
        }
        let response = self.serve_chunk_request(peer, request);
        if let FileChunkResponse::Chunk { data } = &response {
            let entry = self.chunk_bytes_served.entry(key).or_insert((now, 0));
            if now.saturating_sub(entry.0) >= DAY_MS {
                *entry = (now, 0);
            }
            entry.1 = entry.1.saturating_add(data.len() as u64);
        }
        response
    }

    pub(crate) fn serve_chunk_request(&self, peer: PeerId, request: &FileChunkRequest) -> FileChunkResponse {
        debug!("serve_chunk_request: file_id={} chunk={} request received", request.file_id, request.chunk_index);
        let row = self.db.as_ref().and_then(|conn| {
            conn.query_row(
                "SELECT status, peer_device_fingerprint, group_id FROM files WHERE file_id = ?1",
                params![request.file_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)),
            ).ok()
        });
        let Some((status, row_peer_fp, row_group_id)) = row else {
            error!("serve_chunk_request: no record for file_id={} — not found, returning NotFound", request.file_id);
            return FileChunkResponse::NotFound;
        };
        if status != "complete" {
            error!("serve_chunk_request: file_id={} status is not 'complete' — returning NotFound", request.file_id);
            return FileChunkResponse::NotFound;
        }
        // Authorization: the requester must resolve, via its Noise-authenticated `PeerId`, to a known device, and must be a legitimate counterpart of the file. Without this, anyone who knew or guessed a `file_id` could fetch the encrypted chunks. The `NotFound`/`Chunk` split also answered "do you have this file". The bytes are encrypted with `file_key`, but a group file's key is shared by all members (see `finish_outgoing_group_file`), so a removed member could still fetch with the old key.
        if !self.may_serve_file_to(peer, &row_peer_fp, row_group_id.as_deref()) {
            warn!(
                "serve_chunk_request REJECTED: {} is not an authorized peer for this file (file_id={})",
                crate::log_id(&peer), request.file_id
            );
            return FileChunkResponse::NotFound;
        }
        let enc_path = match self.enc_path_for(&request.file_id) {
            Ok(p) => p,
            Err(_) => return FileChunkResponse::NotFound,
        };
        let chunk_size = self.file_chunk_size(&request.file_id);
        match attachments::read_chunk_from_disk_with(&enc_path, request.chunk_index, chunk_size) {
            Ok(Some(data)) => {
                debug!("serve_chunk_request: file_id={} chunk={} answering with {} bytes", request.file_id, request.chunk_index, data.len());
                FileChunkResponse::Chunk { data }
            }
            other => {
                error!("serve_chunk_request: file_id={} chunk={} could not be read from disk: {:?}", request.file_id, request.chunk_index, other.err());
                FileChunkResponse::NotFound
            }
        }
    }

    /// Lists the known attachments in a chat (see the `listAttachments` JNI export). Only records known in this process or written to the DB are
    /// returned. A file offered while node mode was off and never downloaded is written to the DB anyway (per the rule in `receive_file_offer`), so
    /// metadata stays visible after a restart too. Only the download needs to be repeated.
    // The newest `MAX_LISTED_ATTACHMENTS` (each row carries its preview JPEG as hex, all under the core lock); older ones: `list_attachments_page`.
    pub(crate) fn list_attachments(&self, peer_device_fingerprint: &str) -> Vec<AttachmentSummary> {
        self.list_attachments_opt(peer_device_fingerprint, true, None, MAX_LISTED_ATTACHMENTS)
    }

    /// Returns the `limit` newest attachments created before `before_ms`, oldest first.
    pub(crate) fn list_attachments_page(&self, peer_device_fingerprint: &str, before_ms: u64, limit: usize) -> Vec<AttachmentSummary> {
        self.list_attachments_opt(peer_device_fingerprint, true, Some(before_ms), limit.min(MAX_LISTED_ATTACHMENTS))
    }

    /// `with_preview: false` leaves the preview JPEG in the database. The chat list asks every few seconds and only wants the newest row's label.
    pub(crate) fn list_attachments_opt(&self, peer_device_fingerprint: &str, with_preview: bool, before_ms: Option<u64>, limit: usize) -> Vec<AttachmentSummary> {
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };
        // Multi-device (1.7.1): a contact's attachments may have come from ANY of that person's devices, so they are merged under ONE chat. Instead of
        // an exact match on `peer_device_fingerprint`, ALL known device fingerprints of that identity are accepted. For a single-device contact this
        // reduces to that one fingerprint, so behaviour is unchanged. Download still goes to the file's REAL owner (see download_file: it downloads
        // from the owning device in the row).
        // `group_id IS NULL`: a group file offer is also stored under the sending member's `peer_device_fingerprint`. Without this filter a group
        // attachment would leak into that member's 1:1 attachment history.
        let mut device_fps: Vec<String> = self.known_remote_devices.get(peer_device_fingerprint)
            .map(|d| d.identity_id.clone())
            .map(|id| self.known_remote_devices.values()
                .filter(|d| d.identity_id == id)
                .map(|d| d.device_fingerprint.clone())
                .collect::<Vec<_>>())
            .unwrap_or_default();
        if device_fps.is_empty() { device_fps.push(peer_device_fingerprint.to_string()); }
        let placeholders = (1..=device_fps.len()).map(|i| format!("?{}", i)).collect::<Vec<_>>().join(",");
        // The page never splits a millisecond: every row sharing the oldest
        // row's `created_at` comes with it, or the next `< before_ms` page
        // skipped the rest of them.
        let filter = format!(
            "peer_device_fingerprint IN ({}) AND group_id IS NULL AND created_at < {}",
            placeholders, before_ms.map_or(i64::MAX, |b| b.min(i64::MAX as u64) as i64)
        );
        let sql = format!(
            "SELECT file_id, file_name, mime_type, total_size, direction, status, bytes_transferred, created_at, preview_jpeg, duration_ms, caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, COALESCE(NULLIF(sent_at_ms, 0), created_at), send_status
             FROM files WHERE {f} AND created_at >= COALESCE(
                 (SELECT created_at FROM files WHERE {f} ORDER BY created_at DESC LIMIT 1 OFFSET {o}), {min})
             ORDER BY created_at DESC",
            f = filter, o = limit.max(1) - 1, min = -1
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                warn!("Could not prepare attachment list query: {}", e);
                return Vec::new();
            }
        };
        let params_dyn: Vec<&dyn rusqlite::ToSql> = device_fps.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        // Previews up to 512 KiB each, 500 rows, as hex. Older rows past the budget come without one.
        let mut preview_budget = PAGE_MAX_BYTES;
        let rows = stmt.query_map(params_dyn.as_slice(), |r| {
            let preview: Option<Vec<u8>> = if with_preview { r.get(8)? } else { None };
            let preview = preview.filter(|p| p.len() <= preview_budget).inspect(|p| preview_budget -= p.len());
            let duration: Option<i64> = r.get(9)?;
            let file_id: String = r.get(0)?;
            let mut status: String = r.get(5)?;
            // `active_downloads` lives in process memory. If the process is killed and restarted (e.g. the app is fully closed), rows left as
            // "downloading" in the DB would never receive live progress again. Tapping them is a no-op (see ChatActivity.onAttachmentClicked), so they
            // would show "Downloading" forever. A download that is really in progress must have an entry in `active_downloads`. Otherwise the state is
            // treated as "failed" (retryable).
            if status == "downloading" && !self.active_downloads.contains_key(&file_id) {
                status = "failed".to_string();
            }
            Ok(AttachmentSummary {
                file_id,
                file_name: r.get(1)?,
                mime_type: r.get(2)?,
                total_size: r.get::<_, i64>(3)? as u64,
                direction: r.get(4)?,
                status,
                bytes_transferred: r.get::<_, i64>(6)? as u64,
                created_at: r.get::<_, i64>(7)? as u64,
                preview_hex: preview.map(|p| hex::encode(p)),
                duration_ms: duration.map(|d| d as u32),
                peer_device_fingerprint: String::new(),
                sender_identity_id: None,
                caption: r.get::<_, Option<String>>(10)?.unwrap_or_default(),
                reply_to_message_id: r.get(11)?,
                reply_to_preview: r.get(12)?,
                reply_to_sender_identity_id: r.get(13)?,
                sticker: r.get(14)?,
                sent_at_ms: r.get::<_, i64>(15)?.max(0) as u64,
                send_status: r.get(16)?,
            })
        });
        newest_first_rows(rows)
    }

    /// Group counterpart of `list_attachments`: filters by `group_id` (same pattern as `load_group_message_history`). Attachments in a group can come
    /// from DIFFERENT senders, so the `peer_device_fingerprint`/`sender_identity_id` fields are filled here (unlike 1:1). That lets `download_file`
    /// know where to download from, and lets the sender's name be shown.
    pub(crate) fn list_group_attachments(&self, group_id: &str) -> Vec<AttachmentSummary> {
        self.list_group_attachments_opt(group_id, true, None, MAX_LISTED_ATTACHMENTS)
    }

    /// See `list_attachments_page`.
    pub(crate) fn list_group_attachments_page(&self, group_id: &str, before_ms: u64, limit: usize) -> Vec<AttachmentSummary> {
        self.list_group_attachments_opt(group_id, true, Some(before_ms), limit.min(MAX_LISTED_ATTACHMENTS))
    }

    /// See `list_attachments_opt`.
    pub(crate) fn list_group_attachments_opt(&self, group_id: &str, with_preview: bool, before_ms: Option<u64>, limit: usize) -> Vec<AttachmentSummary> {
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };
        let mut stmt = match conn.prepare(
            "SELECT file_id, file_name, mime_type, total_size, direction, status, bytes_transferred, created_at, preview_jpeg, duration_ms, peer_device_fingerprint, sender_identity_id, caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, COALESCE(NULLIF(sent_at_ms, 0), created_at), send_status
             FROM files WHERE group_id = ?1 AND created_at < ?2 AND created_at >= COALESCE(
                 (SELECT created_at FROM files WHERE group_id = ?1 AND created_at < ?2 ORDER BY created_at DESC LIMIT 1 OFFSET ?3), ?4)
             ORDER BY created_at DESC"
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("Could not prepare attachment list query: {}", e);
                return Vec::new();
            }
        };
        let before = before_ms.map_or(i64::MAX, |b| b.min(i64::MAX as u64) as i64);
        // See `list_attachments_opt`: the oldest millisecond is never split.
        let mut preview_budget = PAGE_MAX_BYTES;
        let rows = stmt.query_map(params![group_id, before, limit.max(1) as i64 - 1, -1i64], |r| {
            let preview: Option<Vec<u8>> = if with_preview { r.get(8)? } else { None };
            let preview = preview.filter(|p| p.len() <= preview_budget).inspect(|p| preview_budget -= p.len());
            let duration: Option<i64> = r.get(9)?;
            let file_id: String = r.get(0)?;
            let mut status: String = r.get(5)?;
            if status == "downloading" && !self.active_downloads.contains_key(&file_id) {
                status = "failed".to_string();
            }
            Ok(AttachmentSummary {
                file_id,
                file_name: r.get(1)?,
                mime_type: r.get(2)?,
                total_size: r.get::<_, i64>(3)? as u64,
                direction: r.get(4)?,
                status,
                bytes_transferred: r.get::<_, i64>(6)? as u64,
                created_at: r.get::<_, i64>(7)? as u64,
                preview_hex: preview.map(|p| hex::encode(p)),
                duration_ms: duration.map(|d| d as u32),
                peer_device_fingerprint: r.get(10)?,
                sender_identity_id: r.get(11)?,
                caption: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
                reply_to_message_id: r.get(13)?,
                reply_to_preview: r.get(14)?,
                reply_to_sender_identity_id: r.get(15)?,
                sticker: r.get(16)?,
                sent_at_ms: r.get::<_, i64>(17)?.max(0) as u64,
                send_status: r.get(18)?,
            })
        });
        newest_first_rows(rows)
    }

    /// Returns the path to a decrypted (plaintext) copy of a completed attachment. If there is none yet (first open), it decrypts the file from disk
    /// first. KNOWN LIMIT: `decrypt_file_from_disk` is synchronous and bounded-memory, but for a large file it can still take a while. The Kotlin
    /// side must call it OFF the main thread (see P2PLib.kt docs).
    /// Same lock-splitting reason as `begin_outgoing_file`: decrypting a whole large attachment can take minutes, and it used to run under the global
    /// lock. This is the SHORT locked phase: it reads the metadata from the DB, unwraps the key, and returns the path pair. The actual
    /// `decrypt_file_from_disk` runs unlocked in `attachment_plaintext_path_unlocked`.
    pub(crate) fn begin_attachment_decrypt(&self, file_id: &str) -> Result<([u8; 32], String, std::path::PathBuf, std::path::PathBuf), String> {
        info!("get_attachment_plaintext_path called: file_id={}", file_id);
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let (encrypted_key, key_nonce, sha256_hex, status, file_name): (Vec<u8>, Vec<u8>, String, String, String) = conn.query_row(
            "SELECT encrypted_file_key, key_nonce, sha256_hex, status, file_name FROM files WHERE file_id = ?1",
            params![file_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).map_err(|e| format!("Unknown file_id ({}): {}", file_id, e))?;
        info!("get_attachment_plaintext_path: file_id={} DB status='{}'", file_id, status);
        if status != "complete" {
            return Err(format!("File not complete yet (status: {})", status));
        }
        let file_key = self.unwrap_file_key(&encrypted_key, &key_nonce)?;

        // See `safe_extension`: the extension is derived from the file name the other side sent, and cannot carry a path separator.
        let ext = safe_extension(&file_name);
        let plain_path = self.attachments_dir()?.join("plain_cache").join(format!("{}{}", file_id, ext));
        let enc_path = self.enc_path_for(file_id)?;
        Ok((file_key, sha256_hex, enc_path, plain_path))
    }
}

/// Partial downloads larger than this are scanned for intact chunks off the core lock.
const RESUME_SCAN_OFF_LOCK_BYTES: u64 = 32 * 1024 * 1024;
/// File ids whose partial file a background thread is scanning.
static RESUME_SCANS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// The chunks of a partial `.enc` file whose hash group matches the offer's `chunk_hashes`, wherever they are.
fn scan_resumable(enc_path: &std::path::Path, chunk_hashes: &[u8], per_hash: u32, total_chunks: u32, chunk_size: usize) -> std::collections::HashSet<u32> {
    let mut received = std::collections::HashSet::new();
    if !enc_path.exists() {
        return received;
    }
    for (entry, want) in chunk_hashes.chunks_exact(32).enumerate() {
        let first = entry as u32 * per_hash;
        let count = per_hash.min(total_chunks - first);
        if attachments::enc_range_hash(enc_path, first, count, chunk_size).is_ok_and(|h| h[..] == *want) {
            received.extend(first..first + count);
        }
    }
    received
}
