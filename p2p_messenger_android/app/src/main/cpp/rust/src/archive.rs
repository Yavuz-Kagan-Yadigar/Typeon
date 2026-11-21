//! History requests, the message archive, edits/deletes on it and history loads.

use super::*;

impl P2PCore {

    /// Drops the unanswered chat-open `HistorySyncRequest`s (no window) to
    /// one device for one chat (`group_id`: None = the 1:1 chat): the newest
    /// request does the same work, and each one is retried and deposited
    /// until it is answered. A press window is never dropped here.
    pub(crate) fn cancel_pending_history_requests(&mut self, peer_device_fingerprint: &str, group_id: Option<&str>) {
        let stale: Vec<String> = self.awaiting_confirmation.iter()
            .filter(|(_, p)| p.peer_device_fingerprint == peer_device_fingerprint)
            .filter(|(_, p)| matches!(
                &p.regen_content,
                Some(MessageContent::HistorySyncRequest { group_id: g, before_timestamp: None, .. }) if g.as_deref() == group_id
            ))
            .map(|(id, _)| id.clone())
            .collect();
        // only the retry stops. The request stays solicited, so an
        // answer already on its way is still taken (it was discarded and
        // acked, a lost page); it ages out after 7 days (see the
        // `HistorySyncRequest` arm of `send_message_content_inner`).
        for id in stale {
            self.awaiting_confirmation.remove(&id);
            self.remove_durable_retry(&id);
        }
    }

    /// Called when a chat screen finds no local history on a device with node mode off (see ChatActivity `loadHistoryIfAvailable`). Sends an encrypted
    /// `HistorySyncRequest` to the chat peer. The reply arrives asynchronously, as a `{"type":"history_sync",...}` event in a later `pollNetwork` turn.
    pub(crate) fn request_history_sync(&mut self, peer_device_fingerprint: String, limit: u32) -> Result<(), String> {
        // A chat open sends a `HistorySyncRequest`, which is on the `regen_content` list. Without cancellation, every open adds a pending row that is re-sent for up to 7 days until a `HistorySyncResponse` arrives, even if the peer is offline. Before sending a new request, cancel the pending full-sync request (`before_timestamp: None`) to this peer. The newest one does the same job.
        self.cancel_pending_history_requests(&peer_device_fingerprint, None);
        let content = MessageContent::HistorySyncRequest { limit, before_timestamp: None, group_id: None, after_timestamp: None };
        self.send_message_content(peer_device_fingerprint, &content, None).map(|_| ())
    }

    /// Called when the chat history is scrolled to the top and the LOCAL archive is exhausted (see `getMessageHistoryBefore`). Asks the chat peer directly for messages
    /// older than `before_timestamp`. The reply arrives asynchronously (see the `HistorySyncResponse` arm: if `before_timestamp` is set, it produces an "older_history" event).
    ///
    /// The window `[after, before)` of a "Fetch older history" press. Older presses are not cancelled: each asks for its own window.
    pub(crate) fn request_older_history(&mut self, peer_device_fingerprint: &str, before: i64, after: i64) -> Result<(), String> {
        let content = MessageContent::HistorySyncRequest {
            limit: HISTORY_SYNC_MAX_MESSAGES, before_timestamp: Some(before), group_id: None, after_timestamp: Some(after),
        };
        self.send_message_content(peer_device_fingerprint.to_string(), &content, None).map(|_| ())
    }

    /// Group counterpart of `request_older_history`. Group messages are pairwise fan-out, so there is no single authority. The request goes to ALL reachable other
    /// members (same fan-out pattern as `send_group_message`). The first reply fills the gap. Later replies are silently ignored by the `message_exists_with_id`
    /// check (see there).
    pub(crate) fn request_older_group_history(&mut self, group_id: &str, before: i64, after: i64) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        let content = MessageContent::HistorySyncRequest {
            limit: HISTORY_SYNC_MAX_MESSAGES, before_timestamp: Some(before), group_id: Some(group_id.to_string()), after_timestamp: Some(after),
        };
        // Not every member: each answers up to 512 KiB and pages on its own, and all but the first answer bring almost nothing new.
        // The founder and the longest-standing members hold the oldest rows; unreachable ones are passed over.
        const ASKED_PER_PRESS: usize = 3;
        let mut members: Vec<&crate::group::GroupMember> = group.members.iter().filter(|m| m.identity_id != own_identity_id).collect();
        members.sort_by_key(|m| (m.identity_id != group.founder_identity_id, m.added_at));
        let members: Vec<String> = members.into_iter().map(|m| m.identity_id.clone()).collect();
        let mut asked = 0usize;
        for member_identity_id in members {
            if asked >= ASKED_PER_PRESS {
                break;
            }
            if let Some(peer_fp) = self.resolve_active_device_for_identity(&member_identity_id) {
                if self.send_message_content(peer_fp, &content, None).is_ok() {
                    asked += 1;
                }
            }
        }
        if asked > 0 {
            Ok(())
        } else {
            Err("No reachable group member".to_string())
        }
    }

    /// See the "older" arm of `HistorySyncResponse`. Checks whether a message (by its stable `message_id`) is already in the local archive. Used in OLD-PAGE merging,
    /// where the "newer than the latest timestamp" threshold would work in the WRONG direction (paging deliberately fetches OLDER messages).
    /// `message_exists_with_id` is scoped to one chat. The id is chosen by the peer, so a global match would let a 1:1 message suppress a group message with the
    /// same id (and the reverse).
    pub(crate) fn message_exists_in_chat(&self, message_id: &str, group_id: Option<&str>, chat_key: &str) -> bool {
        let Some(conn) = &self.db else { return false };
        match group_id {
            Some(gid) => conn.query_row(
                "SELECT 1 FROM messages WHERE message_id = ?1 AND group_id = ?2 LIMIT 1",
                params![message_id, gid], |_| Ok(()),
            ),
            None => conn.query_row(
                "SELECT 1 FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL LIMIT 1",
                params![message_id, chat_key], |_| Ok(()),
            ),
        }.is_ok()
    }

    pub(crate) fn file_row_exists(&self, file_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row("SELECT 1 FROM files WHERE file_id = ?1 LIMIT 1", params![file_id], |_| Ok(())).is_ok()
        })
    }

    /// A row from a history backfill was inserted with `timestamp = now`.
    /// Paging and ordering use that column, so give it the row's real time.
    /// Only in the chat it was inserted into: the id is the peer's choice, and
    /// unscoped it moved a row of any other chat back to a time of its liking.
    pub(crate) fn backdate_archived(&self, group_id: Option<&str>, chat_key: &str, message_id: Option<&str>, timestamp: u64) {
        let (Some(conn), Some(mid)) = (&self.db, message_id) else { return };
        // Above i64::MAX the cast wraps negative and the row sorts first.
        if timestamp == 0 || timestamp > i64::MAX as u64 { return; }
        let _ = conn.execute(
            "UPDATE messages SET timestamp = ?1 WHERE message_id = ?2 AND timestamp > ?1
             AND group_id IS ?3 AND (?3 IS NOT NULL OR peer_device_fingerprint = ?4)",
            params![timestamp as i64, mid, group_id, chat_key],
        );
    }

    /// Marks a 1:1 row as taken from the contact's history answer: its place in the past is the contact's word only.
    pub(crate) fn mark_synced(&self, chat_key: &str, message_id: Option<&str>) {
        let (Some(conn), Some(mid)) = (&self.db, message_id) else { return };
        let _ = conn.execute(
            "UPDATE messages SET via_sync = 1 WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
            params![mid, chat_key],
        );
    }

    pub(crate) fn is_synced(&self, chat_key: &str, message_id: Option<&str>) -> bool {
        let (Some(conn), Some(mid)) = (&self.db, message_id) else { return false };
        conn.query_row(
            "SELECT via_sync FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
            params![mid, chat_key],
            |r| r.get::<_, i64>(0),
        ).map_or(false, |v| v != 0)
    }

    /// Is `target_message_id` a message or attachment WE sent in this chat?
    /// The only rows a sibling's echoed Edit/Delete may touch (the 1:1 rule of
    /// `message_owned_by_sender`, mirrored): a linked device could otherwise
    /// rewrite or delete what contacts wrote, on every sibling.
    pub(crate) fn own_sent_target(&self, group_id: Option<&str>, chat_key: &str, target_message_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row(
                "SELECT 1 FROM messages WHERE message_id = ?1 AND direction = 'sent'
                   AND group_id IS ?2 AND (?2 IS NOT NULL OR peer_device_fingerprint = ?3)
                 UNION ALL
                 SELECT 1 FROM files WHERE file_id = ?1 AND direction = 'sent' AND group_id IS ?2
                 LIMIT 1",
                params![target_message_id, group_id, chat_key], |_| Ok(()),
            ).is_ok()
        })
    }

    /// A sibling echoed an Edit (`new_text` Some) or a Delete (None) of a message this device does not have yet. It is stored (text sealed) and acked, and applied
    /// when the message is archived (`apply_pending_sibling_ops`). Returns false if it could not be stored, and the caller then sends no Ack.
    /// ponytail: no index on target_message_id. The table holds a few rows; add one if it ever grows.
    pub(crate) fn remember_sibling_op(&self, target_message_id: &str, new_text: Option<&str>, edited_at_ms: u64) -> bool {
        const KEEP_MS: i64 = 30 * 24 * 60 * 60 * 1000;
        let Some(conn) = &self.db else { return false };
        let sealed = match new_text {
            Some(t) => match self.seal_local_blob(t.as_bytes()) {
                Some(b) => Some(b),
                None => return false,
            },
            None => None,
        };
        let now = current_time_ms() as i64;
        let _ = conn.execute("DELETE FROM pending_sibling_ops WHERE created_at < ?1", params![now - KEEP_MS]);
        conn.execute(
            "INSERT INTO pending_sibling_ops (target_message_id, new_text, edited_at_ms, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![target_message_id, sealed, edited_at_ms as i64, now],
        ).is_ok()
    }

    /// see `remember_sibling_op`. Called when one of OUR messages is archived.
    /// Edits first, by stamp; a delete last.
    pub(crate) fn apply_pending_sibling_ops(&mut self, group_id: Option<&str>, chat_key: &str, target_message_id: &str) {
        let ops: Vec<(i64, Option<Vec<u8>>, i64)> = {
            let Some(conn) = &self.db else { return };
            let Ok(mut stmt) = conn.prepare(
                "SELECT id, new_text, edited_at_ms FROM pending_sibling_ops
                 WHERE target_message_id = ?1 ORDER BY new_text IS NULL, edited_at_ms"
            ) else { return };
            let rows: Vec<(i64, Option<Vec<u8>>, i64)> = stmt
                .query_map(params![target_message_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map(|it| it.flatten().collect())
                .unwrap_or_default();
            rows
        };
        for (row_id, sealed, edited_at_ms) in ops {
            // Each row goes once it applies: one that cannot be opened now
            // (key not loaded) stays until its `KEEP_MS` expiry.
            let event = match sealed {
                Some(blob) => {
                    let Some(text) = self.open_local_blob(&blob).and_then(|p| String::from_utf8(p).ok()) else { continue };
                    self.delete_pending_sibling_op(row_id);
                    self.apply_edit_to_archive(group_id, chat_key, target_message_id, &text, edited_at_ms.max(0) as u64);
                    match group_id {
                        Some(gid) => serde_json::json!({"type": "group_edit", "group_id": gid, "message_id": target_message_id, "text": text}),
                        None => serde_json::json!({"type": "edit", "peer": chat_key, "message_id": target_message_id, "text": text}),
                    }
                }
                None => {
                    self.delete_pending_sibling_op(row_id);
                    self.apply_delete_to_archive(group_id, chat_key, target_message_id);
                    if let Some(gid) = group_id {
                        self.sign_own_group_tombstone(gid, target_message_id);
                    }
                    match group_id {
                        Some(gid) => serde_json::json!({"type": "group_delete", "group_id": gid, "message_id": target_message_id}),
                        None => serde_json::json!({"type": "delete", "peer": chat_key, "message_id": target_message_id}),
                    }
                }
            };
            self.attachment_events.push(event.to_string());
        }
    }

    pub(crate) fn delete_pending_sibling_op(&self, row_id: i64) {
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM pending_sibling_ops WHERE id = ?1", params![row_id]);
        }
    }

    /// see `remember_sibling_op` — a file whose delete came before its offer.
    pub(crate) fn take_pending_sibling_delete(&self, target_message_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.execute(
                "DELETE FROM pending_sibling_ops WHERE target_message_id = ?1 AND new_text IS NULL",
                params![target_message_id],
            ).map_or(false, |n| n > 0)
        })
    }

    /// see `process_group_update` (late AvatarUpdate): the version of the last
    /// avatar change applied to a group.
    pub(crate) fn group_avatar_version(&self, group_id: &str) -> u32 {
        self.db.as_ref()
            .and_then(|conn| conn.query_row(
                "SELECT v FROM app_meta WHERE k = ?1", params![format!("gav:{}", group_id)],
                |r| r.get::<_, i64>(0),
            ).ok())
            .map_or(0, |v| v.max(0) as u32)
    }

    pub(crate) fn set_group_avatar_version(&self, group_id: &str, version: u32) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO app_meta (k, v) VALUES (?1, ?2)",
                params![format!("gav:{}", group_id), version as i64],
            );
        }
    }

    /// A row just archived from a peer's history answer: carry over its
    /// deleted and edited marks (the text is already the current one).
    pub(crate) fn apply_synced_message_flags(&mut self, group_id: Option<&str>, chat_key: &str, m: &SyncedMessage) {
        let Some(mid) = m.message_id.as_deref() else { return };
        if m.is_deleted {
            self.apply_delete_to_archive(group_id, chat_key, mid);
        }
        if m.is_edited {
            self.mark_synced_message_edited(group_id, chat_key, mid);
        }
    }

    /// See `outstanding_history_requests`: removes a request from the record.
    pub(crate) fn forget_history_request(&mut self, request_id: &str) {
        self.outstanding_history_requests.remove(request_id);
        self.history_answered_by.remove(request_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM app_meta WHERE k = ?1", params![format!("hsr:{}", request_id)]);
        }
    }

    /// `message_exists_with_id` among the 1:1 rows received from the
    /// identity of `sender_fp` only. The id is the peer's choice: a global
    /// match let another chat's row re-ack a packet that was never stored.
    pub(crate) fn received_from_sender(&self, message_id: &str, sender_fp: &str) -> bool {
        if self.own_devices.contains_key(sender_fp) {
            return self.message_exists_with_id(message_id);
        }
        let Some(conn) = &self.db else { return false };
        let Some(identity) = self.known_remote_devices.get(sender_fp).map(|d| d.identity_id.clone()) else { return false };
        self.known_remote_devices.values().filter(|d| d.identity_id == identity).any(|d| conn.query_row(
            "SELECT 1 FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND direction = 'received' LIMIT 1",
            params![message_id, d.device_fingerprint], |_| Ok(()),
        ).is_ok())
    }

    /// `message_exists_in_chat` for the 1:1 chat with `identity_id`: under any of its devices, either direction.
    pub(crate) fn message_exists_with_identity(&self, message_id: &str, identity_id: &str) -> bool {
        let Some(conn) = &self.db else { return false };
        self.known_remote_devices.values().filter(|d| d.identity_id == identity_id).any(|d| conn.query_row(
            "SELECT 1 FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL LIMIT 1",
            params![message_id, d.device_fingerprint], |_| Ok(()),
        ).is_ok())
    }

    pub(crate) fn message_exists_with_id(&self, message_id: &str) -> bool {
        let conn = match &self.db {
            Some(c) => c,
            None => return false,
        };
        conn.query_row("SELECT 1 FROM messages WHERE message_id = ?1 LIMIT 1", params![message_id], |_| Ok(())).is_ok()
    }

    /// Adds a message to the local archive. Callers: (1) live 1:1 traffic; (2) `HistorySyncResponse`, which makes history learned through sync permanent locally (see the receive_message note). If `history_key` is not loaded yet (Kotlin has not unwrapped it from the Keystore), the call is skipped. Archiving is best-effort and never blocks messaging.
    ///
    /// `message_id` and `status` are stored in the row. A DB read after a reopen must return the real state, not assume "sent". Status updates are written to the same row via `set_message_status`.
    /// `reply_to_message_id` / `reply_to_preview` (see the packet.rs `MessageContent::Text.reply_to_message_id` docs) are persisted in the row, so a reply preview survives a history reload.
    pub(crate) fn archive_message(&mut self, peer_device_fingerprint: &str, direction: &str, plaintext: &[u8], message_id: Option<&str>, status: Option<&str>, reply_to_message_id: Option<&str>, reply_to_preview: Option<&str>, sent_at_ms: u64) -> Result<(), String> {
        self.archive_message_exp(peer_device_fingerprint, direction, plaintext, message_id, status, reply_to_message_id, reply_to_preview, sent_at_ms, None)
    }

    /// `archive_message` for a row that may disappear (`expire_secs`, see `first_expiry`). A disappearing row never goes to the server archive.
    pub(crate) fn archive_message_exp(&mut self, peer_device_fingerprint: &str, direction: &str, plaintext: &[u8], message_id: Option<&str>, status: Option<&str>, reply_to_message_id: Option<&str>, reply_to_preview: Option<&str>, sent_at_ms: u64, expire_secs: Option<u32>) -> Result<(), String> {
        // The sender's clock: not later than ours, or its messages sort into
        // the future (and land in an archive bucket nobody probes).
        let sent_at_ms = sent_at_ms.min(current_time_ms());
        let key = match &self.history_key {
            Some(k) => *k,
            None => {
                // Silently dropping this caused a real bug. On the Linux client, incoming messages were decrypted without error but were never written to the archive, so
                // the UI showed "No messages yet" and the chat did not even open. Finding the cause took hours, because this line was missing.
                warn!(
                    "History key not loaded — message NOT written to archive (peer={}, direction={})",
                    crate::log_id(&peer_device_fingerprint), direction
                );
                return Err("history key not loaded".to_string());
            }
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Err("DB not open".to_string()),
        };

        let (encrypted, nonce_bytes) = seal_with(&key, plaintext).ok_or("History encryption failed")?;

        let sent_col: Option<i64> = if sent_at_ms > 0 { Some(sent_at_ms as i64) } else { None };
        // a row with this id is already there (UNIQUE index): nothing new.
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO messages (peer_device_fingerprint, direction, encrypted_blob, nonce, timestamp, message_id, status, reply_to_message_id, reply_to_preview, sent_at_ms, expire_secs, expire_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![peer_device_fingerprint, direction, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64, message_id, status, reply_to_message_id, reply_to_preview, sent_col,
                expire_secs, expire_secs.map(|s| first_expiry(direction, s))],
        ).map_err(|e| e.to_string())?;
        if inserted == 0 {
            return Ok(());
        }

        // Server archive (see `server_client::queue_archive_record`): the SAME row as written to the local archive, but re-encrypted with `archive_key` for upload to the
        // server. If history storage on the server is off, the function returns at once.
        //
        // The server archive is keyed by IDENTITY, not by device fingerprint, so that readability survives when the contact changes device.
        if let Some(mid) = message_id.filter(|_| expire_secs.is_none()) {
            let conv_key = self.identity_id_for_device(peer_device_fingerprint);
            if let Some(conv_key) = conv_key {
                let archived = ArchivedMessage {
                    direction: direction.to_string(),
                    text: String::from_utf8_lossy(plaintext).to_string(),
                    timestamp: current_time_ms(),
                    sent_at_ms,
                    status: status.map(|s| s.to_string()),
                    sender_identity_id: None,
                    message_id: Some(mid.to_string()),
                    reply_to_message_id: reply_to_message_id.map(|s| s.to_string()),
                    reply_to_preview: reply_to_preview.map(|s| s.to_string()),
                    reply_to_sender_identity_id: None,
                    is_deleted: false,
                    is_edited: false,
                    via_sync: false,
                    // A newly received or sent message cannot have reactions or seen info yet. See `ArchivedMessage.reactions` / `seen_by`.
                    reactions: String::new(),
                    seen_by: String::new(),
                    author_proof: None,
                    mentions_me: false,
                    expire_secs: None,
                    expire_at_ms: None,
                };
                if let Ok(cbor) = ciborium_bytes(&archived) {
                    // `rev` from our clock, as every later revision: with the
                    // sender's clock ahead, edits and deletes were lower
                    // revisions and the server kept the original.
                    let now = current_time_ms();
                    self.queue_archive_record(&conv_key, mid, now, if sent_at_ms > 0 { sent_at_ms } else { now }, cbor);
                }
            }
        }
        if direction == "sent" {
            if let Some(mid) = message_id {
                self.apply_pending_sibling_ops(None, peer_device_fingerprint, mid);
            }
        }
        Ok(())
    }

    /// Disappearing messages: starts the countdown of the received rows of one chat. Each row goes `expire_secs` after now, or earlier if it
    /// already would (the unread cap, or an earlier read). So a repeat call never extends a timer. `group_id` set: that group; else the 1:1
    /// rows under `chat_keys`. Only for a chat on THIS device's screen: a sibling's read does not start it, since a desktop shows only a
    /// placeholder and the phone has not shown the message yet.
    pub(crate) fn start_expiry(&self, group_id: Option<&str>, chat_keys: [&str; 2]) {
        let Some(conn) = &self.db else { return };
        if let Err(e) = conn.execute(
            "UPDATE messages SET expire_at_ms = MIN(expire_at_ms, ?1 + expire_secs * 1000)
             WHERE expire_at_ms IS NOT NULL AND direction = 'received' AND is_deleted = 0
               AND CASE WHEN ?2 IS NOT NULL THEN group_id = ?2
                        ELSE (group_id IS NULL OR group_id = '') AND peer_device_fingerprint IN (?3, ?4) END",
            params![current_time_ms() as i64, group_id, chat_keys[0], chat_keys[1]],
        ) {
            error!("Disappearing timer could not start: {}", e);
        }
        // Attachments: a 1:1 file row is under the device that sent it, so any device of the same person.
        if let Err(e) = conn.execute(
            "UPDATE files SET expire_at_ms = MIN(expire_at_ms, ?1 + expire_secs * 1000)
             WHERE expire_at_ms IS NOT NULL AND expire_secs > 0 AND direction = 'received' AND status != 'expired'
               AND CASE WHEN ?2 IS NOT NULL THEN group_id = ?2
                        ELSE group_id IS NULL AND (peer_device_fingerprint IN (?3, ?4) OR peer_device_fingerprint IN (
                            SELECT device_fingerprint FROM remote_devices WHERE identity_id =
                                (SELECT identity_id FROM remote_devices WHERE device_fingerprint = ?3))) END",
            params![current_time_ms() as i64, group_id, chat_keys[0], chat_keys[1]],
        ) {
            error!("Disappearing file timer could not start: {}", e);
        }
    }

    fn disappear_key(&self, peer_fp: &str, group_id: &str) -> String {
        if group_id.is_empty() {
            format!("dm:{}", self.canonical_peer_key(peer_fp))
        } else {
            format!("dm:group:{group_id}")
        }
    }

    /// The chat's disappearing mode (held Send button): every message sent in it, text or file, carries this timer. None = off.
    /// This device only: my other devices keep their own setting.
    pub(crate) fn disappear_mode(&self, peer_fp: &str, group_id: &str) -> Option<u32> {
        packet::disappear_secs(self.meta_str(&self.disappear_key(peer_fp, group_id)).and_then(|v| v.parse().ok()))
    }

    /// `secs` 0 (or out of range) turns the mode off.
    pub(crate) fn set_disappear_mode(&self, peer_fp: &str, group_id: &str, secs: u32) {
        let key = self.disappear_key(peer_fp, group_id);
        match packet::disappear_secs(Some(secs)) {
            Some(s) => self.meta_put(&key, &s.to_string()),
            None => self.meta_del(&key),
        }
    }

    /// Writes a file row's timer (see `first_expiry`). Returns its `expire_at_ms`; None for an ordinary file.
    pub(crate) fn set_file_expiry(&self, file_id: &str, direction: &str, expire_secs: Option<u32>) -> Option<u64> {
        let secs = packet::disappear_secs(expire_secs)?;
        let at = first_expiry(direction, secs);
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET expire_secs = ?1, expire_at_ms = ?2 WHERE file_id = ?3", params![secs, at, file_id]);
        }
        Some(at as u64)
    }

    /// `set_file_expiry`, and the same two fields in the UI event.
    pub(crate) fn stamp_file_expiry(&self, ev: &mut serde_json::Value, file_id: &str, direction: &str, expire_secs: Option<u32>) {
        if let Some(at) = self.set_file_expiry(file_id, direction, expire_secs) {
            ev["expire_secs"] = packet::disappear_secs(expire_secs).into();
            ev["expire_at_ms"] = at.into();
        }
    }

    /// The chat is on screen: its received disappearing messages start counting down now, on this device's clock. Nothing is sent.
    /// `peer_fp` for a 1:1 chat, `group_id` (non-empty) for a group.
    pub(crate) fn start_expiry_on_screen(&self, peer_fp: &str, group_id: &str) {
        if group_id.is_empty() {
            let canon = self.canonical_peer_key(peer_fp);
            self.start_expiry(None, [peer_fp, &canon]);
        } else {
            self.start_expiry(Some(group_id), ["", ""]);
        }
    }

    /// Removes every disappearing row whose time is up, on this device only: nothing is sent, the peer's copy has its own timer. The row
    /// stays as a tombstone (`apply_delete_to_archive`), so a late duplicate or a history answer cannot bring it back, and the UI hides it
    /// (`expiry_filter`). Its reactions and seen marks go too. Cheap when nothing is due: an indexed lookup.
    pub(crate) fn expire_due(&mut self) {
        let Some(conn) = &self.db else { return };
        let due: Vec<(Option<String>, String, String)> = conn
            .prepare("SELECT group_id, peer_device_fingerprint, message_id FROM messages WHERE expire_at_ms <= ?1 AND message_id IS NOT NULL")
            .and_then(|mut st| st.query_map(params![current_time_ms() as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map(|rows| rows.flatten().collect()))
            .unwrap_or_default();
        for (group_id, fp, mid) in due {
            let scope = group_id.unwrap_or_default();
            self.apply_delete_to_archive(Some(scope.as_str()).filter(|g| !g.is_empty()), &fp, &mid);
            if let Some(conn) = &self.db {
                // NULL: off the index, so the next sweep does not see it again.
                let _ = conn.execute(
                    "UPDATE messages SET expire_at_ms = NULL, is_deleted = 1 WHERE message_id = ?1 AND expire_secs IS NOT NULL AND COALESCE(group_id, '') = ?2",
                    params![mid, scope],
                );
                let _ = conn.execute("DELETE FROM message_reactions WHERE message_id = ?1", params![mid]);
                let _ = conn.execute("DELETE FROM message_seen WHERE message_id = ?1", params![mid]);
            }
        }
        self.expire_due_files();
    }

    /// Attachments whose time is up. My own sent file goes in two steps: first off my screen (its decrypted copies too), while the
    /// encrypted `.enc` stays for a receiver that was offline and has not downloaded it yet (the receiver's timer only starts when it
    /// sees it); at the unread cap the `.enc` goes as well. A received file goes at once. The row stays as a tombstone (`status =
    /// 'expired'`): a repeated offer then finds it and is dropped (`receive_file_offer`).
    fn expire_due_files(&mut self) {
        let Some(conn) = &self.db else { return };
        let now = current_time_ms() as i64;
        let due: Vec<(String, String, String, i64, u32)> = conn
            .prepare("SELECT file_id, direction, status, created_at, expire_secs FROM files WHERE expire_at_ms <= ?1 AND expire_secs IS NOT NULL")
            .and_then(|mut st| st.query_map(params![now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).map(|rows| rows.flatten().collect()))
            .unwrap_or_default();
        for (file_id, direction, status, created_at, secs) in due {
            let cap_end = created_at + packet::DISAPPEAR_MAX_SECS as i64 * 1000;
            let keep_for_receivers = direction == "sent" && secs > 0 && status == "complete" && cap_end > now;
            if keep_for_receivers {
                self.remove_attachment_plain(&file_id);
            } else {
                self.remove_attachment_copy(&file_id);
                self.finish_blob_upload(&file_id);
            }
            let Some(conn) = &self.db else { return };
            let _ = if keep_for_receivers {
                conn.execute(
                    "UPDATE files SET expire_secs = 0, expire_at_ms = ?1, caption = '', preview_jpeg = NULL WHERE file_id = ?2",
                    params![cap_end, file_id],
                )
            } else {
                conn.execute(
                    "UPDATE files SET status = 'expired', expire_at_ms = NULL, caption = '', preview_jpeg = NULL, reply_to_preview = NULL WHERE file_id = ?1",
                    params![file_id],
                )
            };
            let _ = conn.execute("DELETE FROM message_reactions WHERE message_id = ?1", params![file_id]);
            let _ = conn.execute("DELETE FROM message_seen WHERE message_id = ?1", params![file_id]);
        }
    }

    /// Returns the `identity_id` of a device fingerprint's owner. Needed for the chat key of the server archive. See the note in `archive_message`.
    pub(crate) fn identity_id_for_device(&self, device_fingerprint: &str) -> Option<String> {
        self.known_remote_devices
            .get(device_fingerprint)
            .map(|d| d.identity_id.clone())
    }

    /// Adds a group message to the local archive: the group counterpart of `archive_message`. `peer_device_fingerprint` is deliberately written as an empty string
    /// (a "this is not a DM" marker that keeps the NOT NULL constraint); the real key is `group_id`. Before, group messages were either NEVER archived (received ones,
    /// see the receive_message Text/group_id note), or archived under the WRONG key (sent ones: each recipient's 1:1 `peer_device_fingerprint`, a SEPARATE row for each
    /// copy of the N-way fan-out). The second could never be read back as real group history, and if that recipient was also a 1:1 contact, it leaked into that
    /// contact's DM history (`load_message_history` filters ONLY by `peer_device_fingerprint`). Now EVERY group message (sent or received) is archived as ONE row,
    /// keyed by `group_id`.
    /// `reply_to_message_id` / `reply_to_preview` / `reply_to_sender_identity_id`: same note as `archive_message`. The group counterpart also carries the
    /// replied-to message's sender `identity_id` (see the packet.rs `reply_to_sender_identity_id` note).
    /// Signs a group message as its author, with this device's hybrid key (Ed25519 and ML-DSA-87, like every other signature here). The result travels with the
    /// message and is stored by every member: `"<device fingerprint>:<Ed25519 hex>:<ML-DSA hex>"`.
    // ponytail: hex text, about 9.4 KB per message (the ML-DSA signature is 4.6 KB raw). Make the field bytes if the size of group packets and history pages matters.
    pub(crate) fn sign_group_author(&self, group_id: &str, message_id: &str, text: &str) -> Result<String, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.my_identity_id().ok_or("No identity")?;
        let keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let statement = group_author_statement(group_id, message_id, &own_identity_id, &own_fp, text);
        let sig_c: Ed25519Signature = keys.sign_sk_ed25519.sign(&statement);
        let sig_pq: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&statement);
        Ok(format!("{}:{}:{}", own_fp, hex::encode(sig_c.to_bytes()), hex::encode(sig_pq.encode().to_vec())))
    }

    /// Whether `proof` is a hybrid signature by a device of
    /// `author_identity_id` over exactly this group message. Both halves must
    /// verify. A revoked device counts only for rows dated before its
    /// `revoked_at`: its old messages stay valid.
    pub(crate) fn group_author_proof_valid(&self, group_id: &str, message_id: &str, author_identity_id: &str, text: &str, sent_at_ms: u64, proof: Option<&str>) -> bool {
        let mut parts = proof.unwrap_or("").splitn(3, ':');
        let (Some(device_fp), Some(sig_c), Some(sig_pq)) = (parts.next(), parts.next(), parts.next()) else { return false };
        // a revoked device's proof only for a row dated before its revoke.
        // A group member that is not a contact keeps its revokes in `orv:`.
        let revoked_at = self.contacts.values()
            .filter(|c| c.trusted_identity_id == author_identity_id)
            .find_map(|c| c.revoked_at(device_fp))
            .or_else(|| self.non_contact_revoke(author_identity_id, device_fp).flatten());
        if revoked_at.map_or(false, |r| sent_at_ms == 0 || sent_at_ms >= r) {
            return false;
        }
        let (Ok(sig_c), Ok(sig_pq)) = (hex::decode(sig_c), hex::decode(sig_pq)) else { return false };
        // Own devices (this one and the siblings) or a known device of the author.
        let device = self.own_devices.get(device_fp).or_else(|| self.known_remote_devices.get(device_fp));
        let Some(device) = device.filter(|d| d.identity_id == author_identity_id) else { return false };
        // Another identity's revoked device with no time known to date its
        // proofs against: none counts.
        if !device.is_active && revoked_at.is_none() && !self.own_devices.contains_key(device_fp) {
            return false;
        }
        verify_hybrid_signature(
            &group_author_statement(group_id, message_id, author_identity_id, device_fp, text),
            &sig_c, &sig_pq, device,
        ).is_ok()
    }

    /// The stored proof of a group row, to hand on with history.
    /// Scoped to the group: ids are the sender's choice and may repeat in another one.
    pub(crate) fn group_author_proof(&self, group_id: &str, message_id: &str) -> Option<String> {
        self.db.as_ref()?.query_row(
            "SELECT author_proof FROM messages WHERE message_id = ?1 AND group_id = ?2",
            params![message_id, group_id], |r| r.get::<_, Option<String>>(0),
        ).ok().flatten()
    }

    /// After an edit: stores `proof` when it signs the row as it is stored
    /// NOW (the edit may have been stale and not applied). `apply_edit_to_archive`
    /// cleared the old proof, so a row without a matching one is not handed on.
    pub(crate) fn adopt_group_author_proof(&mut self, group_id: &str, message_id: &str, proof: Option<&str>) {
        let Some(proof) = proof else { return };
        let Some(key) = self.history_key else { return };
        let row: Option<(Option<String>, Vec<u8>, Vec<u8>, bool, i64)> = self.db.as_ref().and_then(|c| c.query_row(
            "SELECT sender_identity_id, encrypted_blob, nonce, COALESCE(is_deleted, 0), COALESCE(NULLIF(sent_at_ms, 0), timestamp) FROM messages WHERE message_id = ?1 AND group_id = ?2",
            params![message_id, group_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).ok());
        let Some((Some(author), blob, nonce, deleted, sent_at)) = row else { return };
        if nonce.len() != 12 { return }
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(&key) else { return };
        let Ok(plain) = cipher.decrypt(Nonce::from_slice(&nonce), blob.as_slice()) else { return };
        let Ok(text) = String::from_utf8(plain) else { return };
        // A deleted row is signed as a deletion, not as an empty text.
        let text = if deleted { GROUP_TOMBSTONE.to_string() } else { text };
        if !self.group_author_proof_valid(group_id, message_id, &author, &text, sent_at.max(0) as u64, Some(proof)) {
            return;
        }
        let Some(conn) = &self.db else { return };
        if let Err(e) = conn.execute(
            "UPDATE messages SET author_proof = ?1 WHERE message_id = ?2 AND group_id = ?3",
            params![proof, message_id, group_id],
        ) {
            warn!("author_proof could not be stored ({}): {}", message_id, e);
            return;
        }
        self.requeue_archive_row(Some(group_id), "", message_id);
    }

    /// A sibling deleted our group message: this device signs the deletion
    /// too, so the row it hands on with history is taken.
    pub(crate) fn sign_own_group_tombstone(&mut self, group_id: &str, message_id: &str) {
        match self.sign_group_author(group_id, message_id, GROUP_TOMBSTONE) {
            Ok(proof) => self.adopt_group_author_proof(group_id, message_id, Some(&proof)),
            Err(e) => warn!("Group tombstone could not be signed ({}): {}", message_id, e),
        }
    }

    pub(crate) fn archive_group_message(&mut self, group_id: &str, sender_identity_id: &str, direction: &str, plaintext: &[u8], message_id: Option<&str>, reply_to_message_id: Option<&str>, reply_to_preview: Option<&str>, reply_to_sender_identity_id: Option<&str>, sent_at_ms: u64, author_proof: Option<&str>) -> Result<(), String> {
        self.archive_group_message_exp(group_id, sender_identity_id, direction, plaintext, message_id, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sent_at_ms, author_proof, None)
    }

    /// Group twin of `archive_message_exp`.
    pub(crate) fn archive_group_message_exp(&mut self, group_id: &str, sender_identity_id: &str, direction: &str, plaintext: &[u8], message_id: Option<&str>, reply_to_message_id: Option<&str>, reply_to_preview: Option<&str>, reply_to_sender_identity_id: Option<&str>, sent_at_ms: u64, author_proof: Option<&str>, expire_secs: Option<u32>) -> Result<(), String> {
        // The sender's clock: not later than ours, or its messages sort into
        // the future (and land in an archive bucket nobody probes).
        let sent_at_ms = sent_at_ms.min(current_time_ms());
        let key = match &self.history_key {
            Some(k) => *k,
            None => return Err("history key not loaded".to_string()),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Err("DB not open".to_string()),
        };

        let (encrypted, nonce_bytes) = seal_with(&key, plaintext).ok_or("History encryption failed")?;

        let sent_col: Option<i64> = if sent_at_ms > 0 { Some(sent_at_ms as i64) } else { None };
        // see `archive_message`.
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO messages (peer_device_fingerprint, direction, encrypted_blob, nonce, timestamp, group_id, sender_identity_id, message_id, status, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sent_at_ms, author_proof, expire_secs, expire_at_ms)
             VALUES ('', ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'sent', ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![direction, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64, group_id, sender_identity_id, message_id, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sent_col, author_proof,
                expire_secs, expire_secs.map(|s| first_expiry(direction, s))],
        ).map_err(|e| e.to_string())?;
        if inserted == 0 {
            return Ok(());
        }

        // See the same hook in `archive_message`. In a group, the chat key is directly the `group_id`.
        if let Some(mid) = message_id.filter(|_| expire_secs.is_none()) {
            let archived = ArchivedMessage {
                direction: direction.to_string(),
                text: String::from_utf8_lossy(plaintext).to_string(),
                timestamp: current_time_ms(),
                sent_at_ms,
                status: None,
                sender_identity_id: Some(sender_identity_id.to_string()),
                message_id: Some(mid.to_string()),
                reply_to_message_id: reply_to_message_id.map(|s| s.to_string()),
                reply_to_preview: reply_to_preview.map(|s| s.to_string()),
                reply_to_sender_identity_id: reply_to_sender_identity_id.map(|s| s.to_string()),
                is_deleted: false,
                is_edited: false,
                via_sync: false,
                // A newly received or sent message cannot have reactions or seen info yet. See `ArchivedMessage.reactions` / `seen_by`.
                reactions: String::new(),
                seen_by: String::new(),
                author_proof: author_proof.map(|p| p.to_string()),
                mentions_me: false,
                expire_secs: None,
                expire_at_ms: None,
            };
            if let Ok(cbor) = ciborium_bytes(&archived) {
                // see `archive_message`.
                let now = current_time_ms();
                self.queue_archive_record(group_id, mid, now, if sent_at_ms > 0 { sent_at_ms } else { now }, cbor);
            }
        }
        if direction == "sent" {
            if let Some(mid) = message_id {
                self.apply_pending_sibling_ops(Some(group_id), "", mid);
            }
        }
        Ok(())
    }

    /// Whether `target_message_id` in our archive was originally authored by
    /// `sender_identity_id`, for a Delete/Edit that just arrived FROM that
    /// sender. 1:1: the archived row's `direction` must be `"received"`
    /// (i.e. the peer sent it to us — a peer can never own our own "sent"
    /// row). Group: the row's `sender_identity_id` column must match. If the
    /// row isn't found at all, ownership is denied (fail closed). Without
    /// this check, any paired contact/group member could edit or delete an
    /// arbitrary message just by knowing/guessing its id, including one they
    /// never sent.
    pub(crate) fn message_owned_by_sender(&self, group_id: Option<&str>, peer_device_fingerprint: &str, sender_identity_id: &str, target_message_id: &str) -> bool {
        let conn = match &self.db {
            Some(c) => c,
            None => return false,
        };
        match group_id {
            Some(gid) => {
                let row_sender: Option<String> = conn.query_row(
                    "SELECT sender_identity_id FROM messages WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid], |r| r.get(0),
                ).ok();
                row_sender.as_deref() == Some(sender_identity_id)
            }
            None => {
                // The chat key must be that sender's chat: any device of the
                // identity may edit, a device of another identity never.
                if self.canonical_device_for_identity(sender_identity_id).as_deref() != Some(peer_device_fingerprint) {
                    return false;
                }
                let direction: Option<String> = conn.query_row(
                    "SELECT direction FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint], |r| r.get(0),
                ).ok();
                direction.as_deref() == Some("received")
            }
        }
    }

    /// See `pending_edits_deletes`. Checks, WITHOUT any ownership or authority check, whether the target of an Edit/Delete exists in the archive at all (as a message
    /// OR as a file). This is needed to tell apart the state "no row" (the Text has not arrived yet, so buffer it) from "a row exists but belongs to someone else"
    /// (a real, permanent rejection).
    pub(crate) fn edit_or_delete_target_exists(&self, target_message_id: &str) -> bool {
        if self.message_exists_with_id(target_message_id) {
            return true;
        }
        self.db.as_ref().map(|conn| {
            conn.query_row("SELECT 1 FROM files WHERE file_id = ?1 LIMIT 1", params![target_message_id], |_| Ok(())).is_ok()
        }).unwrap_or(false)
    }

    /// `edit_or_delete_target_exists` in the chat the Edit/Delete is for
    /// (the group, or the sender's 1:1 chat). A row with that id in another
    /// chat made the edit "rejected" and acked instead of buffered.
    pub(crate) fn edit_target_in_chat(&self, target_message_id: &str, group_id: Option<&str>, peer_fp: &str) -> bool {
        let chat_key = self.canonical_peer_key(peer_fp);
        if self.message_exists_in_chat(target_message_id, group_id, &chat_key) {
            return true;
        }
        let Some(conn) = &self.db else { return false };
        match group_id {
            Some(gid) => conn.query_row(
                "SELECT 1 FROM files WHERE file_id = ?1 AND group_id = ?2 LIMIT 1",
                params![target_message_id, gid], |_| Ok(()),
            ).is_ok(),
            // A 1:1 file row keeps the device it came from or went to.
            None => conn.query_row(
                "SELECT peer_device_fingerprint FROM files WHERE file_id = ?1 AND group_id IS NULL",
                params![target_message_id], |r| r.get::<_, String>(0),
            ).map_or(false, |fp| self.canonical_peer_key(&fp) == chat_key),
        }
    }

    /// Buffers an Edit/Delete whose target is NOT YET in the archive. See the `pending_edits_deletes` field and `EARLY_EDIT_DELETE_TTL_MS` docs. It deliberately sends NO
    /// Ack: the sender's `awaiting_confirmation` retry keeps this packet alive until the target `Text` is archived and `replay_buffered_edits_deletes` runs (or the TTL
    /// expires). Limited to `MAX_EARLY_EDITS_DELETES_PER_TARGET` per target (the oldest is dropped), so a malicious peer cannot consume unbounded memory.
    pub(crate) fn buffer_edit_or_delete(&mut self, target_message_id: &str, peer_fp: &str, sender_identity_id: &str, packet_message_id: &str, content: MessageContent) {
        let now = current_time_ms();
        // The per-target cap alone left the number of targets open: a peer
        // could park one edit per invented message id.
        // not acked, so the sender's retry tries again later.
        if self.pending_edits_deletes.len() >= 512 && !self.pending_edits_deletes.contains_key(target_message_id) {
            warn!("Early Edit buffer full (target count) — skipped (target={})", target_message_id);
            return;
        }
        // And per sender: one contact filled all 512 with invented targets
        // and everybody else's early edits were dropped.
        if self.pending_edits_deletes.values().flatten().filter(|e| e.1 == peer_fp).count() >= 64 {
            warn!("Early Edit buffer full (sender) — skipped (target={})", target_message_id);
            return;
        }
        // And in bytes: the counts alone let edits of about 1 MiB text each park hundreds of MB. ponytail: scan per buffered packet. Fine at these caps.
        let edit_bytes = |c: &MessageContent| match c { MessageContent::Edit { new_text, .. } => new_text.len(), _ => 0 };
        let held: usize = self.pending_edits_deletes.values().flatten().map(|e| edit_bytes(&e.4)).sum();
        if held + edit_bytes(&content) > 16 * 1024 * 1024 {
            warn!("Early Edit buffer full (bytes) — skipped (target={})", target_message_id);
            return;
        }
        let buf = self.pending_edits_deletes.entry(target_message_id.to_string()).or_default();
        // A re-encrypted retry of a packet already buffered: it would push a
        // real entry out at the cap.
        if buf.iter().any(|(_, _, _, id, _)| id == packet_message_id) {
            return;
        }
        if buf.len() >= MAX_EARLY_EDITS_DELETES_PER_TARGET {
            // The sender's own oldest goes, never another member's. With none
            // of its own buffered it is not taken: unacked, it comes again.
            let Some(i) = buf.iter().position(|e| e.1 == peer_fp) else {
                warn!("Early Edit buffer full for target {}, not buffered", target_message_id);
                return;
            };
            buf.remove(i);
        }
        buf.push((now, peer_fp.to_string(), sender_identity_id.to_string(), packet_message_id.to_string(), content));
        info!(
            "Target message not in archive yet (target={}) — Edit/Delete buffered, will retry when Text is archived ({} waiting)",
            target_message_id, buf.len()
        );
    }

    /// Called immediately AFTER a `Text` / group `Text` is archived successfully (see the receive_message Text arms). If there are buffered Edit/Delete packets for that
    /// target (see `pending_edits_deletes`), they are applied again IN ARRIVAL ORDER. The events produced are added to `attachment_events` (the same pattern as
    /// `replay_early_packets`: `poll_events` drains it and forwards it to Kotlin/Linux).
    pub(crate) fn replay_buffered_edits_deletes(&mut self, target_message_id: &str) {
        let buffered = match self.pending_edits_deletes.remove(target_message_id) {
            Some(b) if !b.is_empty() => b,
            _ => return,
        };
        info!("Target message now in archive (target={}) — retrying {} buffered Edit/Delete", target_message_id, buffered.len());
        for entry in buffered {
            // The same chat check the live path makes: a Text
            // with this id in another chat consumed, failed and dropped the
            // entry. Put back until its own chat holds the target.
            let group_id = match &entry.4 {
                MessageContent::Edit { group_id, .. } | MessageContent::Delete { group_id, .. } => group_id.clone(),
                _ => None,
            };
            if !self.edit_target_in_chat(target_message_id, group_id.as_deref(), &entry.1) {
                self.pending_edits_deletes.entry(target_message_id.to_string()).or_default().push(entry);
                continue;
            }
            let (_, peer_fp, sender_identity_id, packet_message_id, content) = entry;
            let event = self.apply_edit_or_delete_content(&peer_fp, &sender_identity_id, &packet_message_id, content);
            self.attachment_events.push(event.to_string());
        }
    }

    /// Called from `poll_events`. Clears buffered Edit/Delete packets whose target never arrives, once they expire (see `EARLY_EDIT_DELETE_TTL_MS`).
    pub(crate) fn prune_pending_edits_deletes(&mut self) {
        let now = current_time_ms();
        // Dropped entries are acked: the target never came (e.g. the chat was
        // deleted here), and unacked the sender resent them for 7 days.
        let mut expired: Vec<(String, String)> = Vec::new();
        self.pending_edits_deletes.retain(|_, buf| {
            buf.retain(|(t, peer_fp, _, packet_id, _)| {
                let keep = now.saturating_sub(*t) <= EARLY_EDIT_DELETE_TTL_MS;
                if !keep {
                    expired.push((peer_fp.clone(), packet_id.clone()));
                }
                keep
            });
            !buf.is_empty()
        });
        for (peer_fp, packet_id) in expired {
            self.send_ack(&peer_fp, &packet_id);
        }
    }

    /// Actually APPLIES Edit/Delete content: the ownership and authority check, the archive update, the Ack and event production (see `message_owned_by_sender`).
    /// Called both for live packets whose target already exists and from `replay_buffered_edits_deletes` (for buffered packets). Keeping it in one place guarantees
    /// that both call paths behave IDENTICALLY.
    pub(crate) fn apply_edit_or_delete_content(&mut self, peer_fp: &str, sender_identity_id: &str, packet_message_id: &str, content: MessageContent) -> serde_json::Value {
        // 1:1 archive rows are written under the CANONICAL device key (receive_message Text arm), so the ownership check, archive update and UI event use the same key. Otherwise an Edit or Delete from a non-canonical device would never find its target row. The Ack goes to the real sender device (`peer_fp`), over the ratchet established with that device.
        let chat_key = self.canonical_peer_key(peer_fp);
        // Authorship of the row is not enough in a group: a removed member
        // could still rewrite or delete its old messages for everyone. A group
        // not held yet follows the Text rule: its row was taken under it, so
        // the edit of that row is taken too (its GroupUpdate may be on its way).
        // A group target must also carry the sender's author tag
        // (`group_msg_tag`): only the author can edit or delete it.
        let ex_member = match &content {
            MessageContent::Edit { group_id: Some(gid), target_message_id, .. } | MessageContent::Delete { group_id: Some(gid), target_message_id, .. } =>
                !self.sender_may_post_to_group(gid, sender_identity_id) || !group_msg_id_bound(gid, sender_identity_id, target_message_id),
            _ => false,
        };
        if ex_member {
            self.send_ack(peer_fp, packet_message_id);
            warn!("Group Edit/Delete rejected (sender is not a member or target is not theirs): {}", packet_message_id);
            return serde_json::json!({"type": "noop"});
        }
        match content {
            MessageContent::Edit { target_message_id, new_text, group_id, edited_at_ms, author_proof } => {
                // Without this check, any paired contact/group member could
                // edit an arbitrary message (including one they never sent)
                // just by knowing/guessing its id — see
                // `message_owned_by_sender` docs.
                let owns_message = self.message_owned_by_sender(group_id.as_deref(), &chat_key, sender_identity_id, &target_message_id);
                // Acked once stored (as a Text is): acked first, an edit that
                // came before the history key was lost for good. The event
                // only for an edit that was applied: a stale one, arriving
                // late, showed the older text until reload.
                let mut applied = false;
                if owns_message {
                    match self.apply_edit_to_archive(group_id.as_deref(), &chat_key, &target_message_id, &new_text, edited_at_ms) {
                        None => return serde_json::json!({"type": "noop"}),
                        Some(a) => applied = a,
                    }
                    if let (Some(gid), true) = (group_id.as_deref(), applied) {
                        self.adopt_group_author_proof(gid, &target_message_id, author_proof.as_deref());
                    }
                }
                self.send_ack(peer_fp, packet_message_id);
                if owns_message && !applied {
                    return serde_json::json!({"type": "noop"});
                }
                match (&group_id, owns_message) {
                    (Some(gid), true) => serde_json::json!({"type": "group_edit", "group_id": gid, "message_id": target_message_id, "text": new_text}),
                    (None, true) => serde_json::json!({"type": "edit", "peer": chat_key, "message_id": target_message_id, "text": new_text}),
                    // See instead of publishing a type that no client handles, a diagnostic log plus `noop`.
                    (_, false) => {
                        warn!("Edit rejected (ownership not verified): {}", packet_message_id);
                        serde_json::json!({"type": "noop"})
                    }
                }
            }
            MessageContent::Delete { target_message_id, group_id, author_proof } => {
                // Same ownership rule as Edit (see `message_owned_by_sender`)
                // — otherwise any paired contact could delete an unrelated
                // message/attachment just by guessing/knowing its id.
                let owns_message = self.message_owned_by_sender(group_id.as_deref(), &chat_key, sender_identity_id, &target_message_id);
                // Acked once applied, as an Edit is: without the history key the text cannot be wiped here nor the
                // server copy tombstoned (`requeue_archive_row`), and an early Ack left both for good.
                if owns_message && self.history_key.is_none() {
                    self.ask_resend(peer_fp, packet_message_id);
                    return serde_json::json!({"type": "noop"});
                }
                // `direction = 'received'`/`sender_identity_id` match: this
                // sender must be the one who originally SENT us the file —
                // otherwise they could delete a file WE sent THEM (which
                // lives in our own "sent" row for that same DM/group).
                let owns_file = match &group_id {
                    // Membership: `ex_member` above.
                    Some(gid) => self.db.as_ref().map(|conn| {
                        conn.query_row(
                            "SELECT 1 FROM files WHERE file_id = ?1 AND group_id = ?2 AND sender_identity_id = ?3",
                            params![target_message_id, gid, sender_identity_id], |_| Ok(()),
                        ).is_ok()
                    }).unwrap_or(false),
                    None => self.db.as_ref().map(|conn| {
                        conn.query_row(
                            // By identity: the peer may delete from another of its
                            // devices than the one that sent the file. The device
                            // column is kept for rows older than `sender_identity_id`.
                            "SELECT 1 FROM files WHERE file_id = ?1 AND (sender_identity_id = ?3 OR peer_device_fingerprint = ?2) AND group_id IS NULL AND direction = 'received'",
                            params![target_message_id, peer_fp, sender_identity_id], |_| Ok(()),
                        ).is_ok()
                    }).unwrap_or(false),
                };
                if owns_file {
                    self.purge_attachment_if_exists(&target_message_id);
                }
                if owns_message {
                    self.apply_delete_to_archive(group_id.as_deref(), &chat_key, &target_message_id);
                    if let Some(gid) = group_id.as_deref() {
                        self.adopt_group_author_proof(gid, &target_message_id, author_proof.as_deref());
                    }
                }
                self.send_ack(peer_fp, packet_message_id);
                match (&group_id, owns_message || owns_file) {
                    (Some(gid), true) => serde_json::json!({"type": "group_delete", "group_id": gid, "message_id": target_message_id}),
                    (None, true) => serde_json::json!({"type": "delete", "peer": chat_key, "message_id": target_message_id}),
                    // See same reason.
                    (_, false) => {
                        warn!("Delete rejected (ownership not verified): {}", packet_message_id);
                        serde_json::json!({"type": "noop"})
                    }
                }
            }
            _ => serde_json::json!({"type": "noop"}),
        }
    }

    /// Re-encrypts `new_text` and overwrites the archived copy of
    /// `target_message_id` in place, so an edit survives chat reopen/app
    /// restart instead of only updating the live in-memory adapter. Scoped
    /// by peer/group so it can only ever touch a row that already belongs to
    /// that 1:1/group conversation (see `message_owned_by_sender` for the
    /// caller-side authorization check on the receive path).
    pub(crate) fn apply_edit_to_archive(&mut self, group_id: Option<&str>, peer_device_fingerprint: &str, target_message_id: &str, new_text: &str, edited_at_ms: u64) -> Option<bool> {
        // None: nothing could be stored (key, DB). Some(false): a stale edit.
        let key = self.history_key?;
        let conn = self.db.as_ref()?;
        // Out-of-order check: the edit timestamp stored with the target row is compared. If the incoming edit is older (both values non-zero), it is stale, having arrived after a newer one, and is ignored. Otherwise it would replace the newest text with an older one. If `edited_at_ms == 0` (no ordering info) or `stored == 0` (first edit), it is applied unconditionally.
        let (stored_edit_ts, deleted): (u64, bool) = {
            let read = |r: &rusqlite::Row| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?));
            let row = match group_id {
                Some(gid) => conn.query_row(
                    "SELECT edit_ts, is_deleted FROM messages WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid], read,
                ),
                None => conn.query_row(
                    "SELECT edit_ts, is_deleted FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint], read,
                ),
            };
            row.map(|(ts, del)| (ts as u64, del != 0)).unwrap_or((0, false))
        };
        // An Edit that arrives after the Delete of the same message must not
        // write the text back into the tombstone.
        if deleted {
            info!("Edit to a deleted message ignored (target={})", target_message_id);
            return Some(false);
        }
        if edited_at_ms != 0 && stored_edit_ts != 0 && edited_at_ms <= stored_edit_ts {
            info!(
                "Stale Edit ignored (target={} incoming_ts={} <= stored_ts={})",
                target_message_id, edited_at_ms, stored_edit_ts
            );
            return Some(false);
        }
        let (encrypted, nonce_bytes) = seal_with(&key, new_text.as_bytes())?;
        // `edit_ts`: keep the timestamp of the most recently applied edit. The check above uses it to judge whether the next (possibly out-of-order) edit is stale. It works
        // like `GREATEST`: the value only moves forward when the incoming timestamp is larger (a 0 keeps the current value, since we only get here when "apply" was decided).
        let new_edit_ts = std::cmp::max(edited_at_ms, stored_edit_ts) as i64;
        let updated = match group_id {
            Some(gid) => conn.execute(
                "UPDATE messages SET encrypted_blob = ?1, nonce = ?2, is_edited = 1, edit_ts = ?3, author_proof = NULL WHERE message_id = ?4 AND group_id = ?5",
                params![encrypted, nonce_bytes.to_vec(), new_edit_ts, target_message_id, gid],
            ),
            None => conn.execute(
                "UPDATE messages SET encrypted_blob = ?1, nonce = ?2, is_edited = 1, edit_ts = ?3 WHERE message_id = ?4 AND peer_device_fingerprint = ?5 AND group_id IS NULL",
                params![encrypted, nonce_bytes.to_vec(), new_edit_ts, target_message_id, peer_device_fingerprint],
            ),
        };
        updated.ok()?;
        // Also reflect this to the server's history. See `requeue_archive_row`. Without it, the server archive would keep storing the UNEDITED version of the message, and a
        // new device would see the old text.
        self.requeue_archive_row(group_id, peer_device_fingerprint, target_message_id);
        Some(true)
    }


    /// Re-uploads an archive row that was changed locally (edited or deleted) to the server archive.
    ///
    /// Without this, history on the server would show a new device the UNEDITED version of messages. Even a deleted message would come back. The protocol solves this
    /// with `ArchiveRecord.rev`: the server accepts only a HIGHER revision for the same `record_id`.
    ///
    /// The `rev` is the wall clock. The first upload used `sent_at_ms` (a moment in the past), so an edit or delete always produces a larger value. If two devices of
    /// the same identity upload the same row, the higher revision wins. This is the same behaviour as the local archive's own last-write-wins rule (see `edit_ts`).
    pub(crate) fn requeue_archive_row(&mut self, group_id: Option<&str>, peer_device_fingerprint: &str, target_message_id: &str) {
        let Some(key) = self.history_key else { return };
        if self.archive_root_key.is_none() {
            return;
        }
        let Some(conn) = &self.db else { return };
        // A disappearing row never reached the server archive (see `archive_message_exp`); its edit or expiry must not upload it now.
        if conn.query_row("SELECT 1 FROM messages WHERE message_id = ?1 AND expire_secs IS NOT NULL", params![target_message_id], |_| Ok(())).is_ok() {
            return;
        }

        let row: Option<(Vec<u8>, Vec<u8>, String, Option<i64>, Option<String>, i64, i64, Option<String>, Option<String>, Option<String>)> =
            match group_id {
                Some(gid) => conn.query_row(
                    "SELECT encrypted_blob, nonce, direction, sent_at_ms, sender_identity_id, is_edited, is_deleted, \
                            reply_to_message_id, reply_to_preview, reply_to_sender_identity_id \
                     FROM messages WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
                ),
                None => conn.query_row(
                    "SELECT encrypted_blob, nonce, direction, sent_at_ms, sender_identity_id, is_edited, is_deleted, \
                            reply_to_message_id, reply_to_preview, reply_to_sender_identity_id \
                     FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
                ),
            }
            .ok();
        let Some((blob, nonce_bytes, direction, sent_col, sender_identity_id, is_edited, is_deleted, r_id, r_prev, r_sender)) = row
        else {
            return;
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(&key) else { return };
        if nonce_bytes.len() != 12 { return; } // `from_slice` panics
        let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&nonce_bytes), blob.as_slice()) else { return };

        let sent_at_ms = sent_col.unwrap_or(0).max(0) as u64;
        let archived = ArchivedMessage {
            direction,
            text: String::from_utf8_lossy(&plaintext).to_string(),
            timestamp: current_time_ms(),
            sent_at_ms,
            status: None,
            sender_identity_id,
            message_id: Some(target_message_id.to_string()),
            reply_to_message_id: r_id,
            reply_to_preview: r_prev,
            reply_to_sender_identity_id: r_sender,
            is_deleted: is_deleted != 0,
            is_edited: is_edited != 0,
            via_sync: false,
            // See `ArchivedMessage.reactions` / `seen_by`. An edit re-archives this row, so both are read fresh, so that reactions and seen info accumulated up to that
            // point are not lost.
            reactions: self.reactions_summary(target_message_id),
            seen_by: self.seen_by_json(target_message_id),
            author_proof: group_id.and_then(|gid| self.group_author_proof(gid, target_message_id)),
            mentions_me: false,
            expire_secs: None,
            expire_at_ms: None,
        };
        let Ok(cbor) = ciborium_bytes(&archived) else { return };

        let conv_key = match group_id {
            Some(gid) => Some(gid.to_string()),
            None => self.identity_id_for_device(peer_device_fingerprint),
        };
        if let Some(conv_key) = conv_key {
            self.queue_archive_record(&conv_key, target_message_id, current_time_ms(), sent_at_ms, cbor);
        }
    }

    /// Soft-deletes the archived copy of `target_message_id` (see
    /// `apply_edit_to_archive` — same scoping rationale).
    pub(crate) fn apply_delete_to_archive(&mut self, group_id: Option<&str>, peer_device_fingerprint: &str, target_message_id: &str) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        // The text goes too. Only the flag was set: the ciphertext stayed in
        // the row and was uploaded again, in full, to the server archive.
        if let Some((blob, nonce)) = self.history_key.and_then(|k| seal_with(&k, b"")) {
            let _ = match group_id {
                Some(gid) => conn.execute(
                    "UPDATE messages SET encrypted_blob = ?1, nonce = ?2, reply_to_preview = NULL, author_proof = NULL WHERE message_id = ?3 AND group_id = ?4",
                    params![blob, nonce.to_vec(), target_message_id, gid],
                ),
                None => conn.execute(
                    "UPDATE messages SET encrypted_blob = ?1, nonce = ?2, reply_to_preview = NULL WHERE message_id = ?3 AND peer_device_fingerprint = ?4 AND group_id IS NULL",
                    params![blob, nonce.to_vec(), target_message_id, peer_device_fingerprint],
                ),
            };
        }
        match group_id {
            Some(gid) => {
                let _ = conn.execute(
                    "UPDATE messages SET is_deleted = 1 WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid],
                );
            }
            None => {
                let _ = conn.execute(
                    "UPDATE messages SET is_deleted = 1 WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint],
                );
            }
        }
        // Replies that quote it kept its text in `reply_to_preview`, here and in their archived copies.
        // In this chat only: the id is the peer's choice, and in 1:1 this used to run over every chat (previews of replies to a same-id message elsewhere).
        let quoting: Vec<(String, String)> = conn
            .prepare("SELECT message_id, peer_device_fingerprint FROM messages WHERE reply_to_message_id = ?1 AND group_id IS ?2 AND (?2 IS NOT NULL OR peer_device_fingerprint = ?3) AND reply_to_preview IS NOT NULL AND message_id IS NOT NULL")
            .and_then(|mut st| st.query_map(params![target_message_id, group_id, peer_device_fingerprint], |r| Ok((r.get(0)?, r.get(1)?))).map(|rows| rows.flatten().collect()))
            .unwrap_or_default();
        let _ = conn.execute("UPDATE messages SET reply_to_preview = NULL WHERE reply_to_message_id = ?1 AND group_id IS ?2 AND (?2 IS NOT NULL OR peer_device_fingerprint = ?3)", params![target_message_id, group_id, peer_device_fingerprint]);
        // A file row is under the device that sent it, not the chat key: any
        // device of the same identity.
        let _ = conn.execute(
            "UPDATE files SET reply_to_preview = NULL WHERE reply_to_message_id = ?1 AND group_id IS ?2
             AND (?2 IS NOT NULL OR peer_device_fingerprint = ?3 OR peer_device_fingerprint IN (
                 SELECT device_fingerprint FROM remote_devices WHERE identity_id =
                     (SELECT identity_id FROM remote_devices WHERE device_fingerprint = ?3)))",
            params![target_message_id, group_id, peer_device_fingerprint],
        );
        // See the same hook in `apply_edit_to_archive`. A deleted message's copy on the server must be tombstoned too, or it would come back on a new device.
        self.requeue_archive_row(group_id, peer_device_fingerprint, target_message_id);
        for (message_id, fp) in quoting {
            self.requeue_archive_row(group_id, &fp, &message_id);
        }
    }

    /// When a history-sync row is archived FRESH (this device had no copy of it; see the same pattern at the `apply_delete_to_archive` call sites), the responder's
    /// `is_edited` flag is also set here if it is set on the responder side. Unlike `apply_edit_to_archive`, it does NOT re-encrypt the text. The fresh archive write
    /// already stored `SyncedMessage.text` (the responder's CURRENT, edited content). The flag is only set here, so that it does not go missing.
    /// The stored text, deleted and edited marks of a group row (decrypted). None: no row, no key, or it does not open.
    pub(crate) fn group_row_text(&self, group_id: &str, message_id: &str) -> Option<(String, bool, bool)> {
        let key = self.history_key?;
        let (blob, nonce, deleted, edited): (Vec<u8>, Vec<u8>, bool, bool) = self.db.as_ref()?.query_row(
            "SELECT encrypted_blob, nonce, is_deleted, is_edited FROM messages WHERE message_id = ?1 AND group_id = ?2",
            params![message_id, group_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).ok()?;
        if nonce.len() != 12 {
            return None;
        }
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
        let plain = cipher.decrypt(Nonce::from_slice(&nonce), blob.as_slice()).ok()?;
        Some((String::from_utf8(plain).ok()?, deleted, edited))
    }

    /// A row just restored from the server archive takes the record's deleted/edited marks. The text is already the record's (empty for a
    /// tombstone), so nothing is re-encrypted or uploaded again.
    pub(crate) fn mark_restored_flags(&self, group_id: Option<&str>, chat_key: &str, message_id: &str, deleted: bool, edited: bool) {
        if !deleted && !edited {
            return;
        }
        let Some(conn) = &self.db else { return };
        let _ = conn.execute(
            "UPDATE messages SET is_deleted = MAX(is_deleted, ?1), is_edited = MAX(is_edited, ?2)
             WHERE message_id = ?3 AND group_id IS ?4 AND (?4 IS NOT NULL OR peer_device_fingerprint = ?5)",
            params![deleted as i64, edited as i64, message_id, group_id, chat_key],
        );
    }

    pub(crate) fn mark_synced_message_edited(&mut self, group_id: Option<&str>, peer_device_fingerprint: &str, target_message_id: &str) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        match group_id {
            Some(gid) => {
                let _ = conn.execute(
                    "UPDATE messages SET is_edited = 1 WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid],
                );
            }
            None => {
                let _ = conn.execute(
                    "UPDATE messages SET is_edited = 1 WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint],
                );
            }
        }
    }

    /// Decrypts and returns the message history with a contact (the newest `limit` messages, oldest first). Returns an empty list if `history_key` is missing.
    pub(crate) fn load_message_history(&self, peer_device_fingerprint: &str, limit: u32, before_timestamp: Option<i64>) -> Vec<ArchivedMessage> {
        self.load_message_history_opt(peer_device_fingerprint, limit, before_timestamp, true)
    }

    /// `with_marks: false` skips the reactions and seen-by lookups (two
    /// queries per row): the history-sync answer does not send them.
    pub(crate) fn load_message_history_opt(&self, peer_device_fingerprint: &str, limit: u32, before_timestamp: Option<i64>, with_marks: bool) -> Vec<ArchivedMessage> {
        self.load_message_history_q(peer_device_fingerprint, limit, before_timestamp, None, with_marks, false)
    }

    /// only rows archived after `after_timestamp` (the newest one the
    /// UI holds), newest `limit` of them.
    pub(crate) fn load_message_history_since(&self, peer_device_fingerprint: &str, after_timestamp: i64, limit: u32) -> Vec<ArchivedMessage> {
        self.load_message_history_q(peer_device_fingerprint, limit, None, Some(after_timestamp), true, false)
    }

    /// `sent_clock`: the cursors compare send time (falling back to arrival)
    /// instead of arrival; see `load_history_fetch_page`.
    pub(crate) fn load_message_history_q(&self, peer_device_fingerprint: &str, limit: u32, before_timestamp: Option<i64>, after_timestamp: Option<i64>, with_marks: bool, sent_clock: bool) -> Vec<ArchivedMessage> {
        let key = match &self.history_key {
            Some(k) => *k,
            None => return Vec::new(),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        // `before_timestamp`: see `request_older_history`. If set, it is infinite-scroll paging (messages older than this timestamp). If `None`, the current behaviour
        // applies (the newest `limit` messages).
        //
        // The cursor is a timestamp only, and a history sync archives a whole batch within one millisecond. A plain `LIMIT` that cut through such a batch lost the rest of
        // it, because the next page asks for `timestamp < boundary`. So the page runs to the end of the millisecond of its `limit`-th row (the subquery), and can be a few
        // rows longer than `limit`.
        // ponytail: the page size is not exact. A (timestamp, id) cursor through JNI and both UIs is the upgrade if that ever matters.
        if limit == 0 {
            return Vec::new();
        }
        let t = if sent_clock { "COALESCE(NULLIF(sent_at_ms,0), timestamp)" } else { "timestamp" };
        let e = expiry_filter(with_marks);
        let mut stmt = match conn.prepare(&format!(
            "SELECT direction, encrypted_blob, nonce, timestamp, message_id, status, reply_to_message_id, reply_to_preview, is_deleted, is_edited, COALESCE(NULLIF(sent_at_ms,0), timestamp), via_sync, expire_secs, expire_at_ms FROM messages
             WHERE peer_device_fingerprint = ?1 AND {t} < ?3 AND {t} > ?4 {e}
               AND {t} >= COALESCE((SELECT {t} FROM messages
                    WHERE peer_device_fingerprint = ?1 AND {t} < ?3 AND {t} > ?4 {e}
                    ORDER BY {t} DESC, id DESC LIMIT 1 OFFSET ?2 - 1), 0)
             ORDER BY {t} DESC, id DESC"
        )) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map(params![peer_device_fingerprint, limit, before_timestamp.unwrap_or(i64::MAX), after_timestamp.unwrap_or(i64::MIN)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Option<u32>>(12)?,
                row.get::<_, Option<i64>>(13)?,
            ))
        });

        let mut results = Vec::new();
        let (mut page_budget, mut page_cut) = (PAGE_MAX_BYTES, None);
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (direction, encrypted_blob, nonce_bytes, timestamp, message_id, status, reply_to_message_id, reply_to_preview, is_deleted, is_edited, eff_sent, via_sync, expire_secs, expire_at_ms) = row;
                // bounded in bytes, not rows only (500 texts near 1 MiB
                // each went into one JNI string); never mid-millisecond.
                if page_bytes_full(&mut page_budget, &mut page_cut, if sent_clock { eff_sent } else { timestamp }, encrypted_blob.len()) {
                    break;
                }
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_blob.as_slice()) {
                    if let Ok(text) = String::from_utf8(plaintext) {
                        // Compute the digests first: `message_id` is MOVED inside the push.
                        let reactions_for_row = if with_marks { self.reactions_summary(message_id.as_deref().unwrap_or("")) } else { String::new() };
                        // See `ArchivedMessage.seen_by`. Same pattern as `reactions`: read fresh HERE (from the persistent `message_seen` table), not from the live event.
                        let seen_by_for_row = if with_marks { self.seen_by_json(message_id.as_deref().unwrap_or("")) } else { String::new() };
                        results.push(ArchivedMessage {
                            direction,
                            text,
                            timestamp: timestamp as u64,
                            sent_at_ms: eff_sent as u64,
                            status,
                            sender_identity_id: None,
                            message_id,
                            reply_to_message_id,
                            reply_to_preview,
                            reply_to_sender_identity_id: None,
                            is_deleted: is_deleted != 0,
                            is_edited: is_edited != 0,
                            via_sync: via_sync != 0,
                            reactions: reactions_for_row,
                            seen_by: seen_by_for_row,
                            author_proof: None,
                            mentions_me: false,
                            expire_secs,
                            expire_at_ms: expire_at_ms.map(|v| v.max(0) as u64),
                        });
                    }
                }
            }
        }
        results.reverse(); // eskiden yeniye
        results
    }

    /// The timestamp of the newest message ARCHIVED locally for this peer (`None` if the archive is empty or there is no DB). Used while processing a
    /// `HistorySyncResponse`, to avoid archiving AGAIN the messages we already have (see the receive_message note). Otherwise the same rows would be duplicated on every
    /// chat open (sync is always attempted now). Does not need `history_key`: only the timestamp is read, the encrypted content is not decrypted.
    pub(crate) fn latest_archived_timestamp(&self, peer_device_fingerprint: &str) -> Option<i64> {
        let conn = self.db.as_ref()?;
        conn.query_row(
            "SELECT MAX(timestamp) FROM messages WHERE peer_device_fingerprint = ?1",
            params![peer_device_fingerprint],
            |row| row.get::<_, Option<i64>>(0),
        ).ok().flatten()
    }

    /// Decrypts and returns a group's message history: the group counterpart of `load_message_history`, filtering by `group_id` (see the `archive_group_message` note: it is
    /// no longer filtered WRONGLY by `peer_device_fingerprint`).
    pub(crate) fn load_group_message_history(&self, group_id: &str, limit: u32, before_timestamp: Option<i64>) -> Vec<ArchivedMessage> {
        self.load_group_message_history_opt(group_id, limit, before_timestamp, true)
    }

    /// `with_marks: false` skips the reactions and seen-by lookups (two
    /// queries per row): the history-sync answer does not send them.
    pub(crate) fn load_group_message_history_opt(&self, group_id: &str, limit: u32, before_timestamp: Option<i64>, with_marks: bool) -> Vec<ArchivedMessage> {
        self.load_group_message_history_q(group_id, limit, before_timestamp, None, with_marks, false)
    }

    /// group twin of `load_message_history_since`.
    pub(crate) fn load_group_message_history_since(&self, group_id: &str, after_timestamp: i64, limit: u32) -> Vec<ArchivedMessage> {
        self.load_group_message_history_q(group_id, limit, None, Some(after_timestamp), true, false)
    }

    /// The rows of a `HistorySyncResponse` we keep, before any is written.
    /// In 1:1 only the peer's own ("sent") rows. A reply to the user's
    /// "Fetch older history" press, known by OUR request's window (never the
    /// response's word), keeps only rows sent inside that window and is the
    /// only one that may bring back rows below the history floor: any other
    /// reply (the chat-open sync) drops what the user cleared, pruned or
    /// deleted with the contact. For a press returns its window
    /// `(before, after)` and the oldest row inside it before the 1:1
    /// direction cut (where a follow-up page continues).
    pub(crate) fn filter_history_reply(&self, request_id: &str, group_id: Option<&str>, sender_identity_id: &str, messages: &mut Vec<SyncedMessage>) -> Option<((i64, i64), Option<i64>)> {
        let window = self.outstanding_history_requests.get(request_id).and_then(|e| e.3);
        // Same clock as `prune_chat_before`.
        let sent_at = |m: &SyncedMessage| (if m.sent_at_ms != 0 { m.sent_at_ms } else { m.timestamp }) as i64;
        let mut oldest = None;
        let floor = match window {
            Some((before, after)) => {
                messages.retain(|m| (after..before).contains(&sent_at(m)));
                oldest = messages.iter().map(sent_at).min();
                0
            }
            None => self.history_floor(group_id.unwrap_or(sender_identity_id)) as i64,
        };
        messages.retain(|m| (group_id.is_some() || m.direction == "sent") && sent_at(m) >= floor);
        window.map(|w| (w, oldest))
    }

    /// One "Fetch older history" page of a chat (`group_id`, else the 1:1
    /// chat under `peer_device_fingerprint`): the newest `limit` rows sent in
    /// `[after, before)`, oldest first, without marks.
    pub(crate) fn load_history_fetch_page(&self, peer_device_fingerprint: &str, group_id: Option<&str>, limit: u32, before: i64, after: i64) -> Vec<ArchivedMessage> {
        // `after_timestamp` of the queries is exclusive.
        let after = Some(after.saturating_sub(1));
        match group_id {
            Some(g) => self.load_group_message_history_q(g, limit, Some(before), after, false, true),
            None => self.load_message_history_q(peer_device_fingerprint, limit, Some(before), after, false, true),
        }
    }

    /// the chat list's previews under one lock: per contact (key: identity id) and per group, the newest message and newest attachment.
    pub(crate) fn chat_list_previews(&self) -> serde_json::Value {
        // The chat orders by sent time, so the preview must too. SQL picks the row (no decryption), and only its arrival millisecond is loaded.
        // ponytail: rows sharing that millisecond (a history-sync batch) are all decrypted. A (timestamp, id) cursor is the upgrade if that matters.
        fn newest_sent(rows: Vec<ArchivedMessage>) -> Option<ArchivedMessage> {
            rows.into_iter().max_by_key(|m| if m.sent_at_ms > 0 { m.sent_at_ms } else { m.timestamp })
        }
        let preview_arrival = |column: &str, id: &str| -> Option<i64> {
            self.db.as_ref()?.query_row(
                &format!("SELECT timestamp FROM messages WHERE {column} = ?1
                          ORDER BY COALESCE(NULLIF(sent_at_ms,0), timestamp) DESC, timestamp DESC, id DESC LIMIT 1"),
                params![id], |r| r.get(0),
            ).ok()
        };
        let my_id = self.my_identity_id();
        let mut contacts = serde_json::Map::new();
        for c in self.contacts.values() {
            if my_id.as_deref() == Some(c.trusted_identity_id.as_str()) { continue; }
            let Some(fp) = self.canonical_device_for_identity(&c.trusted_identity_id) else { continue };
            contacts.insert(c.trusted_identity_id.clone(), serde_json::json!({
                "peer": fp,
                "message": preview_arrival("peer_device_fingerprint", &fp)
                    .and_then(|t| newest_sent(self.load_message_history_opt(&fp, 1, Some(t + 1), false))),
                // Limit 1: the rows come oldest first, so `next()` of 500 was the oldest.
                "attachment": self.list_attachments_opt(&fp, false, None, 1).into_iter().next(),
            }));
        }
        let mut groups = serde_json::Map::new();
        for gid in self.groups.keys() {
            groups.insert(gid.clone(), serde_json::json!({
                "message": preview_arrival("group_id", gid)
                    .and_then(|t| newest_sent(self.load_group_message_history_opt(gid, 1, Some(t + 1), false))),
                "attachment": self.list_group_attachments_opt(gid, false, None, 1).into_iter().next(),
            }));
        }
        serde_json::json!({ "contacts": contacts, "groups": groups })
    }

    pub(crate) fn load_group_message_history_q(&self, group_id: &str, limit: u32, before_timestamp: Option<i64>, after_timestamp: Option<i64>, with_marks: bool, sent_clock: bool) -> Vec<ArchivedMessage> {
        let key = match &self.history_key {
            Some(k) => *k,
            None => return Vec::new(),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        // See the same `before_timestamp` note in `load_message_history`.
        if limit == 0 {
            return Vec::new();
        }
        let t = if sent_clock { "COALESCE(NULLIF(sent_at_ms,0), timestamp)" } else { "timestamp" };
        let e = expiry_filter(with_marks);
        let mut stmt = match conn.prepare(&format!(
            "SELECT direction, encrypted_blob, nonce, timestamp, message_id, sender_identity_id, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, is_deleted, is_edited, COALESCE(NULLIF(sent_at_ms,0), timestamp), mentions_me, status, expire_secs, expire_at_ms FROM messages
             WHERE group_id = ?1 AND {t} < ?3 AND {t} > ?4 {e}
               AND {t} >= COALESCE((SELECT {t} FROM messages
                    WHERE group_id = ?1 AND {t} < ?3 AND {t} > ?4 {e}
                    ORDER BY {t} DESC, id DESC LIMIT 1 OFFSET ?2 - 1), 0)
             ORDER BY {t} DESC, id DESC"
        )) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map(params![group_id, limit, before_timestamp.unwrap_or(i64::MAX), after_timestamp.unwrap_or(i64::MIN)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<u32>>(14)?,
                row.get::<_, Option<i64>>(15)?,
            ))
        });

        let mut results = Vec::new();
        let (mut page_budget, mut page_cut) = (PAGE_MAX_BYTES, None);
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (direction, encrypted_blob, nonce_bytes, timestamp, message_id, sender_identity_id, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, is_deleted, is_edited, eff_sent, mentions_me, row_status, expire_secs, expire_at_ms) = row;
                // bounded in bytes, not rows only (500 texts near 1 MiB
                // each went into one JNI string); never mid-millisecond.
                if page_bytes_full(&mut page_budget, &mut page_cut, if sent_clock { eff_sent } else { timestamp }, encrypted_blob.len()) {
                    break;
                }
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_blob.as_slice()) {
                    if let Ok(text) = String::from_utf8(plaintext) {
                        // Compute the digests first: `message_id` is MOVED inside the push.
                        let reactions_for_row = if with_marks { self.reactions_summary(message_id.as_deref().unwrap_or("")) } else { String::new() };
                        // See `ArchivedMessage.seen_by`. Especially important for GROUPS (user: "not reliable, especially in groups"): the multi-member "who saw it" list
                        // is now read fresh here, from the persistent `message_seen` table.
                        let seen_by_for_row = if with_marks { self.seen_by_json(message_id.as_deref().unwrap_or("")) } else { String::new() };
                        results.push(ArchivedMessage {
                            direction,
                            text,
                            timestamp: timestamp as u64,
                            sent_at_ms: eff_sent as u64,
                            // The row's own status (delivered, error), not always "sent".
                            status: Some(row_status.unwrap_or_else(|| "sent".to_string())),
                            sender_identity_id,
                            message_id,
                            reply_to_message_id,
                            reply_to_preview,
                            reply_to_sender_identity_id,
                            is_deleted: is_deleted != 0,
                            is_edited: is_edited != 0,
                            via_sync: false,
                            reactions: reactions_for_row,
                            seen_by: seen_by_for_row,
                            author_proof: None,
                            mentions_me: mentions_me != 0,
                            expire_secs,
                            expire_at_ms: expire_at_ms.map(|v| v.max(0) as u64),
                        });
                    }
                }
            }
        }
        results.reverse(); // eskiden yeniye
        results
    }

    /// Every change of `message_status` is also written to the archived row. The next `load_message_history` then returns the real state, even after an app restart. If the row is not archived yet (for example `history_key` was not loaded), the UPDATE affects 0 rows. That is harmless: a later archive write stores the current state.
    pub(crate) fn set_message_status(&mut self, message_id: &str, status: MessageSendStatus) {
        // The map is read once, right after the send (`send_message_content_inner`). The row in `messages` is the record.
        // ponytail: a crude bound. Drop the map and return the status from the publish call instead.
        if self.message_status.len() >= 10_000 {
            self.message_status.clear();
        }
        self.message_status.insert(message_id.to_string(), status);
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                // Only our own rows carry a send status. The ids are the sender's choice, and a received row may share one.
                // See 'delivered' is final. A late copy's publish or failure must not turn it back into sent or error.
                "UPDATE messages SET status = ?1 WHERE message_id = ?2 AND direction = 'sent' AND status != 'delivered'",
                params![status.as_str(), message_id],
            );
            // My 1:1 file offer goes out under its file id (`finish_outgoing_file`): its bubble keeps the status across a reload.
            let _ = conn.execute(
                "UPDATE files SET send_status = ?1 WHERE file_id = ?2 AND direction = 'sent' AND COALESCE(send_status, '') != 'delivered'",
                params![status.as_str(), message_id],
            );
        }
    }

    // ---------------------------------------------------------------
    // Skipped-message-key persistence (Double Ratchet out-of-order message support). See the `skipped_keys` field docs in ratchet.rs.
    // ---------------------------------------------------------------

    /// Encrypts a skipped key (the key for a message number skipped in a device-pair session) with the key loaded from the Keystore, and writes it to the DB. Called when
    /// the "Greater" branch of `ratchet.rs decrypt` produces a new skipped key. If the key is not loaded (Kotlin has not called `setSkippedKeyEncryptionKey` yet), it is
    /// silently skipped. In that case the skipped key stays in memory only (the old behaviour).
    pub(crate) fn persist_skipped_key(&self, peer_device_fingerprint: &str, message_number: u32, key: &[u8; 32]) -> Result<(), String> {
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return Ok(()),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Ok(()),
        };

        let (encrypted, nonce_bytes) = seal_with(&enc_key, key.as_slice()).ok_or("Skipped-key encryption failed")?;

        conn.execute(
            "INSERT OR REPLACE INTO skipped_message_keys (peer_device_fingerprint, message_number, encrypted_key, nonce, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![peer_device_fingerprint, message_number, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Deleted from the DB when a skipped key is used (once the message is decrypted), since it is no longer needed. The Double Ratchet's single-use message key principle
    /// applies to the on-disk copy too.
    pub(crate) fn delete_persisted_skipped_key(&self, peer_device_fingerprint: &str, message_number: u32) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1 AND message_number = ?2",
                params![peer_device_fingerprint, message_number],
            );
        }
    }

    /// Decrypts and returns the (not yet used) skipped keys stored in the DB for a device-pair session. Called by `load_ratchet_states_from_db`. The returned map is assigned
    /// to the restored `DeviceRatchetState.skipped_keys` field.
    pub(crate) fn load_skipped_keys_from_db(&self, peer_device_fingerprint: &str) -> HashMap<u32, [u8; 32]> {
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return HashMap::new(),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return HashMap::new(),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&enc_key) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };

        // a key older than the old-chain limit is dropped, not loaded.
        let cutoff = current_time_ms().saturating_sub(ratchet::OLD_RECV_MAX_AGE_MS) as i64;
        let _ = conn.execute(
            "DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1 AND created_at < ?2",
            params![peer_device_fingerprint, cutoff],
        );
        let mut stmt = match conn.prepare(
            "SELECT message_number, encrypted_key, nonce FROM skipped_message_keys WHERE peer_device_fingerprint = ?1"
        ) {
            Ok(s) => s,
            Err(_) => return HashMap::new(),
        };

        let rows = stmt.query_map(params![peer_device_fingerprint], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
        });

        let mut results = HashMap::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (message_number, encrypted_key, nonce_bytes) = row;
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_key.as_slice()) {
                    if let Ok(key_bytes) = <[u8; 32]>::try_from(plaintext.as_slice()) {
                        results.insert(message_number, key_bytes);
                    }
                }
            }
        }
        results
    }

    /// Deletes ALL skipped keys stored on disk for a device pair. When a rotation happens (`perform_dh_ratchet`/`apply_rotation`, see ratchet.rs), the skipped keys of the
    /// old chain are meaningless, so they must be cleared from disk too, together with the in-memory `skipped_keys.clear()`.
    pub(crate) fn clear_persisted_skipped_keys(&self, peer_device_fingerprint: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1",
                params![peer_device_fingerprint],
            );
        }
    }
}

/// The first `expire_at_ms` of a disappearing row (local clock). My own message counts from now. A received one counts from when it is read
/// (`start_expiry`); until then it holds the unread cap, so a message never opened does not stay for ever.
pub(crate) fn first_expiry(direction: &str, secs: u32) -> i64 {
    let secs = if direction == "sent" { secs } else { packet::DISAPPEAR_MAX_SECS };
    current_time_ms() as i64 + secs as i64 * 1000
}

/// The history-query clause for disappearing rows. A gone row (expired, or its tombstone) is never shown. Without `with_marks` the
/// query feeds a history answer, a recovery copy or a chat preview: a disappearing row is left out of those entirely.
fn expiry_filter(with_marks: bool) -> String {
    if with_marks {
        format!("AND NOT (expire_secs IS NOT NULL AND (is_deleted = 1 OR expire_at_ms <= {}))", current_time_ms())
    } else {
        "AND expire_secs IS NULL".to_string()
    }
}
