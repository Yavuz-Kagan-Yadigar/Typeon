//! Sealed local blobs, ratchet and skipped-key persistence, durable retries.

use super::*;

impl P2PCore {

    /// Persists `self.ratchets[peer_device_fingerprint]` (if present) to disk, encrypted. It repeats the AEAD pattern of `persist_skipped_key`
    /// exactly, with the same `skipped_key_encryption_key` and the same framing.
    /// If `skipped_key_encryption_key` is not loaded yet (Kotlin has not called `setSkippedKeyEncryptionKey`), the call is silently skipped.
    /// Like archiving, this is best-effort and never blocks messaging (the in-memory state is already current).
    /// Seals with `skipped_key_encryption_key` (12-byte nonce prefix + ChaCha20-Poly1305), the same key and framing as
    /// `persist_ratchet_state` / `persist_skipped_key`.
    ///
    /// This key is used because the `setSkippedKeyEncryptionKey` JNI call runs `load_servers_from_db` right AFTER it fills the field,
    /// so the key is certainly available when the queue is read from disk. `history_key` cannot be used here: Kotlin loads it
    /// later, after SkippedKeyManager.
    pub(crate) fn seal_local_blob(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        let (ciphertext, nonce_bytes) = seal_with(&self.skipped_key_encryption_key?, plaintext)?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Some(out)
    }

    /// The inverse of `seal_local_blob`. `None` (no key, damaged, or never sealed): the caller drops the bytes and never uses them as plaintext.
    pub(crate) fn open_local_blob(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        if sealed.len() <= 12 {
            return None;
        }
        let key = self.skipped_key_encryption_key?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
        cipher.decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..]).ok()
    }

    /// `false`: the write failed (disk full, SQLITE_BUSY). A sender must not publish then: after a restart the same message key and nonce
    /// would be used again. With no DB or no key it returns `true`, because there is nothing to fall behind.
    /// `durable`: the commit is synced (FULL). Needed whenever the send chain may have moved (a send, a rotation, a new session).
    /// A plain receive moves only the receive side: a lost commit there only means a redelivered packet decrypts again.
    pub(crate) fn persist_ratchet_state(&self, peer_device_fingerprint: &str, durable: bool) -> bool {
        let state = match self.ratchets.get(peer_device_fingerprint) {
            Some(s) => s,
            None => return true,
        };
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return true,
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return true,
        };

        let persistable = state.to_persistable();
        // Root, chain and ratchet secret keys are wiped when dropped.
        let plaintext = match ciborium_bytes(&persistable) {
            Ok(b) => zeroize::Zeroizing::new(b),
            Err(e) => { error!("Ratchet state could not be serialized: {}", e); return false; }
        };

        let Some((encrypted, nonce_bytes)) = seal_with(&enc_key, plaintext.as_slice()) else {
            error!("Ratchet state could not be encrypted");
            return false;
        };

        // With WAL and synchronous=NORMAL, a commit that returned can still be lost on power loss. The send chain would then roll back,
        // and the next message would reuse a key and nonce. This commit is synced (FULL: the WAL is synced at commit). The rest of the database
        // keeps NORMAL. Inside an open transaction the pragma is left alone.
        let durable = durable && conn.is_autocommit();
        if durable {
            let _ = conn.pragma_update(None, "synchronous", "FULL");
        }
        let written = conn.execute(
            "INSERT OR REPLACE INTO ratchet_states (peer_device_fingerprint, encrypted_state, nonce, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![peer_device_fingerprint, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64],
        );
        if durable {
            let _ = conn.pragma_update(None, "synchronous", "NORMAL");
        }
        if let Err(e) = &written {
            error!("Ratchet state could not be written ({}): {}", crate::log_id(&peer_device_fingerprint), e);
        }
        written.is_ok()
    }

    /// Runs `write` (several statements) as one transaction, synced at commit when `durable` (see `persist_ratchet_state`). `write` returns
    /// `false` to roll everything back. Inside an open transaction it simply runs.
    pub(crate) fn in_synced_transaction(&self, durable: bool, write: impl FnOnce(&Self) -> bool) -> bool {
        let Some(conn) = &self.db else { return write(self) };
        if !conn.is_autocommit() {
            return write(self);
        }
        if durable {
            let _ = conn.pragma_update(None, "synchronous", "FULL");
        }
        let ok = match conn.unchecked_transaction() {
            Ok(tx) => write(self) && tx.commit().is_ok(),
            Err(e) => {
                error!("Ratchet state transaction could not start: {}", e);
                false
            }
        };
        if durable {
            let _ = conn.pragma_update(None, "synchronous", "NORMAL");
        }
        ok
    }

    /// `persist_ratchet_state` plus the removal of the peer's skipped-key rows, in one transaction. After a rotation or a new
    /// session the rows belong to the replaced chain: a stop between two separate writes loaded them as keys of the new chain.
    pub(crate) fn persist_ratchet_state_replacing_skipped(&self, peer_device_fingerprint: &str) -> bool {
        self.in_synced_transaction(true, |core| {
            let ok = core.persist_ratchet_state(peer_device_fingerprint, true);
            if ok {
                core.clear_persisted_skipped_keys(peer_device_fingerprint);
            }
            ok
        })
    }

    /// Restores ALL ratchet sessions stored in the DB into `self.ratchets`, at app start (after `skipped_key_encryption_key` is loaded;
    /// see the JNI `setSkippedKeyEncryptionKey`). This lets conversations continue after a process restart (app update, background kill)
    /// without a new handshake. Before this, the state was memory-only and was lost on every process restart (see the note at the end of the file).
    /// Loads the persisted sessions and opens the send gate (`ratchets_loaded`).
    /// Called once the skipped-key / ratchet storage key has arrived: loads everything sealed with it. One implementation for JNI and `api.rs`
    /// (they had drifted apart). A second call with the same key does nothing: a reload would roll live sessions back to their stored state.
    pub(crate) fn install_skipped_key(&mut self, key: [u8; 32]) {
        if self.skipped_key_encryption_key == Some(key) && self.ratchets_loaded {
            return;
        }
        self.skipped_key_encryption_key = Some(key);
        self.load_ratchet_states_from_db();
        self.load_pending_durable_retries_from_db();
        self.load_pending_group_messages_from_db();
        self.requeue_unresolved_group_syncs();
        self.load_servers_from_db();
    }

    pub(crate) fn load_ratchet_states_from_db(&mut self) {
        let (rows, unopened) = self.load_ratchet_states_from_db_inner();
        // If stored sessions exist and none of them opens, the key is wrong: the gate stays shut. Otherwise the next send would replace them
        // one by one. A single bad row among good ones is dropped, as before.
        if rows > 0 && unopened == rows {
            error!("No session state could be decrypted ({} rows): wrong key, send gate closed", rows);
            self.attachment_events.push(serde_json::json!({"type": "session_load_failed", "rows": rows}).to_string());
            return;
        }
        if self.skipped_key_encryption_key.is_some() && self.db.is_some() {
            self.ratchets_loaded = true;
        }
    }

    /// (rows read, rows that did not open).
    pub(crate) fn load_ratchet_states_from_db_inner(&mut self) -> (usize, usize) {
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return (0, 0),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return (0, 0),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&enc_key) {
            Ok(c) => c,
            Err(_) => return (0, 0),
        };

        let mut stmt = match conn.prepare(
            "SELECT peer_device_fingerprint, encrypted_state, nonce FROM ratchet_states"
        ) {
            Ok(s) => s,
            Err(_) => return (0, 0),
        };

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
        });

        let mut loaded: Vec<(String, DeviceRatchetState)> = Vec::new();
        let (mut read, mut unopened) = (0usize, 0usize);
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (peer_fp, encrypted, nonce_bytes) = row;
                read += 1;
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                let plaintext = match cipher.decrypt(nonce, encrypted.as_slice()) {
                    Ok(p) => zeroize::Zeroizing::new(p),
                    Err(_) => { unopened += 1; error!("Ratchet state could not be decrypted ({}), skipping", crate::log_id(&peer_fp)); continue; }
                };
                let persistable: ratchet::SerializableRatchetState = match ciborium::from_reader(plaintext.as_slice()) {
                    Ok(p) => p,
                    Err(e) => { error!("Ratchet state could not be parsed ({}): {}", crate::log_id(&peer_fp), e); continue; }
                };
                let skipped_keys = self.load_skipped_keys_from_db(&peer_fp);
                match DeviceRatchetState::from_persistable(persistable, skipped_keys) {
                    Ok(mut state) => {
                        state.expire_old_recv(current_time_ms());
                        loaded.push((peer_fp, state))
                    }
                    Err(e) => error!("Ratchet state could not be rebuilt ({}): {}", crate::log_id(&peer_fp), e),
                }
            }
        }
        for (peer_fp, state) in loaded {
            self.ratchets.insert(peer_fp, state);
        }
        (read, unopened)
    }

    /// Pending Edit / Delete / GroupUpdate messages and other outgoing control packets used to live ONLY in memory (`awaiting_confirmation`).
    /// A full process kill (the OS killing the app, not just being backgrounded) lost them. They are now written to the existing encrypted
    /// SQLite DB, instead of a separate temp file with its own format and cleanup logic. Ratchet state lives in the same DB too.
    /// Only entries with `regen_content` set (see that field's docs) are written here.
    ///
    /// Note: `Text` and `HistorySyncRequest` used to be excluded. `Text` is now in `regen_content`, so it is protected against process death too.
    /// Multi-device control messages (SiblingEcho / DeviceSync / DeviceAddNotice, and others) are also written here now. Before, a restart
    /// silently deleted the entire pending sibling sync queue.
    /// `original_sent_at`: the moment the message FIRST entered the queue, not `current_time_ms()`. This function used to stamp
    /// `current_time_ms()` on every write, but the column is read back by `load_pending_durable_retries_from_db` as `original_sent_at`.
    /// So the `TEXT_RETRY_GIVE_UP_MS` window (7 days) was reset on every app start and every `regen` refresh (every 25 minutes). The result:
    /// a message to a peer that no longer existed was retried forever, and the user was never told "not delivered". Now the real start time is
    /// carried along, so the 7-day ceiling actually applies.
    /// `sent`: the envelope already published and the chain stamp it was encrypted under. A restart then offers the same bytes again
    /// instead of re-encrypting and re-signing every row (see `load_pending_durable_retries_from_db`).
    pub(crate) fn persist_durable_retry(&self, message_id: &str, peer_device_fingerprint: &str, content: &MessageContent, original_sent_at: u64, sent: Option<(&NetworkEnvelope, &str)>) {
        let conn = match &self.db { Some(c) => c, None => return };
        // Sealed like `server_archive_queue`. It used to be plain CBOR, so every sent message sat readable on disk until acked.
        let content_cbor = match ciborium_bytes(content).map(|b| self.seal_local_blob(&b)) {
            Ok(Some(b)) => b,
            Ok(None) => { error!("Persistent retry record could not be serialized: no encryption key"); return; }
            Err(e) => { error!("Persistent retry record could not be serialized: {}", e); return; }
        };
        let sent_cbor: Option<Vec<u8>> = sent.and_then(|s| ciborium_bytes(&s).ok()).and_then(|b| self.seal_local_blob(&b));
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO pending_durable_retries (message_id, peer_device_fingerprint, content_cbor, created_at, local_message_id, sent_cbor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![message_id, peer_device_fingerprint, content_cbor, original_sent_at as i64, group_row_id(content), sent_cbor],
        ) {
            // The memory copy still retries. Only a process death loses it now.
            error!("Persistent retry record could not be written ({}): {}", message_id, e);
        }
    }

    /// See `persist_durable_retry`. When an entry is acked (Ack), or is refreshed and saved again under a NEW message_id, the OLD row must also be
    /// removed. Otherwise the next process start resends both the old and the new record (a DOUBLE SEND). So this must be called at every point
    /// where an entry is removed from or replaced in `awaiting_confirmation`.
    pub(crate) fn remove_durable_retry(&self, message_id: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM pending_durable_retries WHERE message_id = ?1", params![message_id]);
        }
    }

    /// See `remove_durable_retry`. When a device or contact is removed entirely (see the `awaiting_confirmation.retain` call sites),
    /// ALL durable rows for that device are cleared too.
    pub(crate) fn remove_durable_retries_for_peer(&mut self, peer_device_fingerprint: &str) {
        let mut ids: Vec<String> = Vec::new();
        if let Some(conn) = &self.db {
            if let Ok(mut stmt) = conn.prepare("SELECT message_id FROM pending_durable_retries WHERE peer_device_fingerprint = ?1") {
                if let Ok(rows) = stmt.query_map(params![peer_device_fingerprint], |r| r.get::<_, String>(0)) {
                    ids.extend(rows.flatten());
                }
            }
            let _ = conn.execute("DELETE FROM pending_durable_retries WHERE peer_device_fingerprint = ?1", params![peer_device_fingerprint]);
        }
        // Nothing retries them any more.
        self.fail_orphaned_sends(&ids);
    }

    /// Our 1:1 messages whose retry was dropped without an Ack. A row left `pending` showed the clock icon forever, with no event.
    /// It is now set to `error`, and the screen is told. `sent` and `error` rows stay.
    pub(crate) fn fail_orphaned_sends(&mut self, message_ids: &[String]) {
        for id in message_ids {
            let Some(conn) = &self.db else { return };
            let peer: Option<String> = conn.query_row(
                "SELECT peer_device_fingerprint FROM messages WHERE message_id = ?1 AND direction = 'sent' AND status = 'pending'
                   AND (group_id IS NULL OR group_id = '')",
                params![id], |r| r.get(0),
            ).ok();
            let Some(peer) = peer else { continue };
            self.set_message_status(id, MessageSendStatus::Failed);
            self.attachment_events.push(serde_json::json!({
                "type": "status", "peer": self.canonical_peer_key(&peer), "message_id": id, "status": "error"
            }).to_string());
        }
    }

    /// See the `pending_group_messages` field docs. Every message queued for a member is also written to the persistent DB, as one row per message.
    /// Several rows per member is normal. They are kept in ORDER by the `id` column.
    pub(crate) fn persist_pending_group_message(&self, group_id: &str, member_identity_id: &str, content: &MessageContent) {
        let conn = match &self.db { Some(c) => c, None => return };
        // Sealed like `server_archive_queue`. It used to be plain CBOR, so every sent message sat readable on disk until acked.
        let content_cbor = match ciborium_bytes(content).map(|b| self.seal_local_blob(&b)) {
            Ok(Some(b)) => b,
            Ok(None) => { error!("Persistent group message queue record could not be serialized: no encryption key"); return; }
            Err(e) => { error!("Persistent group message queue record could not be serialized: {}", e); return; }
        };
        if let Err(e) = conn.execute(
            "INSERT INTO pending_group_messages (group_id, member_identity_id, content_cbor, created_at, local_message_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![group_id, member_identity_id, content_cbor, current_time_ms() as i64, group_row_id(content)],
        ) {
            error!("Persistent group message queue record could not be written (group={}): {}", group_id, e);
        }
    }

    /// See `persist_pending_group_message`. When the in-memory queue exceeds `MAX_PENDING_GROUP_MESSAGES_PER_MEMBER` and drops its oldest entry,
    /// the OLDEST row for that member/group on disk is also dropped (same order, `id ASC`), keeping the two in sync.
    pub(crate) fn remove_oldest_persisted_pending_group_message(&self, group_id: &str, member_identity_id: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM pending_group_messages WHERE id = (
                    SELECT id FROM pending_group_messages
                    WHERE group_id = ?1 AND member_identity_id = ?2
                    ORDER BY id ASC LIMIT 1
                 )",
                params![group_id, member_identity_id],
            );
        }
    }

    /// See `persist_pending_group_message`. When a member is resolved and the queue is fully drained (see `group_sync_sweep`), ALL remaining
    /// durable rows for that member/group are cleared.
    pub(crate) fn remove_persisted_pending_group_messages(&self, group_id: &str, member_identity_id: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM pending_group_messages WHERE group_id = ?1 AND member_identity_id = ?2",
                params![group_id, member_identity_id],
            );
        }
    }

    /// See `remove_persisted_pending_group_messages`. When a group is removed entirely (see `remove_group_locally`), ALL durable rows
    /// for that group are cleared too.
    pub(crate) fn remove_persisted_pending_group_messages_for_group(&self, group_id: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM pending_group_messages WHERE group_id = ?1", params![group_id]);
        }
    }

    /// Called at app start, at the same point as `load_pending_durable_retries_from_db`. It restores every queued group message still on disk into
    /// the in-memory `pending_group_messages`, in ORDER (`id ASC`). The queue no longer disappears on process death.
    pub(crate) fn load_pending_group_messages_from_db(&mut self) {
        // Rows are sealed with this key. Without it they failed to parse as CBOR and were deleted: the whole queue, silently.
        if self.skipped_key_encryption_key.is_none() {
            return;
        }
        let mut loaded: Vec<(String, String, Vec<u8>, i64)> = Vec::new();
        {
            let conn = match &self.db { Some(c) => c, None => return };
            let mut stmt = match conn.prepare(
                "SELECT group_id, member_identity_id, content_cbor, id FROM pending_group_messages ORDER BY id ASC"
            ) {
                Ok(s) => s,
                Err(_) => return,
            };
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, i64>(3)?))
            });
            if let Ok(rows) = rows {
                for row in rows.flatten() {
                    loaded.push(row);
                }
            }
        }
        if loaded.is_empty() {
            return;
        }
        let mut count = 0usize;
        for (group_id, member_identity_id, content_cbor, row_id) in loaded {
            // A row that does not open (wrong or stale key) is kept, as in the durable-retry twin. Only opened bytes that do not parse are dropped.
            let Some(plain) = self.open_local_blob(&content_cbor) else { continue };
            let content: MessageContent = match ciborium::from_reader(plain.as_slice()) {
                Ok(c) => c,
                Err(e) => {
                    // Dropped like the durable-retry twin. If left in place, it would be read again on every start, and the "oldest row" eviction
                    // would then remove it instead of the entry evicted from memory.
                    error!("Persistent group message queue record could not be parsed, dropping row: {}", e);
                    if let Some(conn) = &self.db {
                        let _ = conn.execute("DELETE FROM pending_group_messages WHERE id = ?1", params![row_id]);
                    }
                    continue;
                }
            };
            self.pending_group_messages.entry((group_id, member_identity_id)).or_default().push(content);
            count += 1;
        }
        info!("Restored {} entries from persistent group message queue", count);
    }

    /// Called at app start, at exactly the same moment as the ratchet states (see the JNI `setSkippedKeyEncryptionKey`. Without ratchets we
    /// cannot encrypt or send anyway). It reads every durable retry row left on disk and resends EACH ONE as a fresh packet
    /// (`send_message_content`: new message_id, new ratchet step). The old row is deleted FIRST (see `remove_durable_retry`, to prevent a double
    /// send). `send_message_content` then writes its own NEW row again through `publish_with_ack_tracking`.
    /// `pending_group_syncs` is memory only. After a restart, the current state is signed again (`sign_group_resync`) for each member of a group
    /// we founded whose device is still unknown. `group_sync_sweep` delivers it once the device resolves.
    pub(crate) fn requeue_unresolved_group_syncs(&mut self) {
        // The Delete / removal notices kept by `send_group_update_to_member`.
        let kept: Vec<(String, String)> = self.db.as_ref().and_then(|c| {
            let mut stmt = c.prepare("SELECT k, v FROM app_meta WHERE k >= 'pgs:' AND k < 'pgs;'").ok()?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).ok()?;
            Some(rows.flatten().collect())
        }).unwrap_or_default();
        for (k, v) in kept {
            // "<first queued ms>:<sealed hex>" (`send_group_update_to_member`).
            let (since, sealed_hex) = v.split_once(':').and_then(|(t, h)| t.parse::<u64>().ok().map(|t| (t, h))).unwrap_or((0, v.as_str()));
            if current_time_ms().saturating_sub(since) > TEXT_RETRY_GIVE_UP_MS {
                self.meta_del(&k);
                continue;
            }
            let update = hex::decode(sealed_hex).ok()
                .and_then(|b| self.open_local_blob(&b))
                .and_then(|p| ciborium::from_reader::<GroupUpdate, _>(p.as_slice()).ok());
            let member = k.rsplit(':').next().unwrap_or("").to_string();
            // A row that does not open (wrong key passed once) is kept.
            if self.deleted_identities.contains(&member) {
                self.meta_del(&k);
            } else if let Some(u) = update {
                self.pending_group_syncs.insert((u.group_id.clone(), member), u);
            }
        }
        let (Ok(own_fp), Some(own_identity_id)) = (self.get_active_own_device_fingerprint(), self.my_identity_id()) else { return };
        // Checked once, and reported, instead of silently returning inside the loop.
        if !self.own_device_keys.contains_key(&own_fp) {
            error!("Group syncs could not be requeued: no own device keys");
            return;
        }
        let founded: Vec<Group> = self.groups.values()
            .filter(|g| g.founder_identity_id == own_identity_id && g.version > 0)
            .cloned()
            .collect();
        for group in founded {
            for member in group.other_members(&own_identity_id) {
                if !self.active_devices_for_identity(&member).is_empty() || self.deleted_identities.contains(&member) {
                    continue;
                }
                if let Ok(update) = self.sign_group_resync(&group) {
                    self.pending_group_syncs.insert((group.group_id.clone(), member), update);
                }
            }
        }
    }

    pub(crate) fn load_pending_durable_retries_from_db(&mut self) {
        // CRITICAL: the DB read (conn / stmt / rows) lives in its OWN block. The calls below (`self.send_message_content`, `self.remove_durable_retry`)
        // borrow ALL of `self`, so the `conn` borrow (derived from `&self.db`) must end BEFORE this block closes. Otherwise the compiler reports
        // "cannot borrow `*self` as mutable because it is also borrowed as immutable". The reason is the rusqlite `Rows` / `MappedRows` Drop
        // implementation: NLL cannot shorten that borrow on its own, because it depends on the last use.
        // See `load_pending_group_messages_from_db`, which is also called from `touch_device_seen` at any time.
        if self.skipped_key_encryption_key.is_none() {
            return;
        }
        let mut loaded: Vec<(String, String, Vec<u8>, u64, Option<Vec<u8>>)> = Vec::new();
        let mut expired: Vec<String> = Vec::new();
        {
            let conn = match &self.db { Some(c) => c, None => return };
            // Expired rows first. Past the 7-day give-up, nothing retries them, and they were read again on every start.
            let cutoff = current_time_ms().saturating_sub(TEXT_RETRY_GIVE_UP_MS) as i64;
            // Their messages are marked failed below.
            if let Ok(mut stmt) = conn.prepare("SELECT message_id FROM pending_durable_retries WHERE created_at < ?1") {
                if let Ok(rows) = stmt.query_map(params![cutoff], |r| r.get::<_, String>(0)) {
                    expired.extend(rows.flatten());
                }
            }
            if let Err(e) = conn.execute("DELETE FROM pending_durable_retries WHERE created_at < ?1", params![cutoff]) {
                error!("Expired persistent retry records could not be deleted: {}", e);
            }
            // Read the keys of every row first (small), then the oldest 1000 that would really be sent now. A plain `LIMIT 1000` read rows of stale
            // devices or rows already in memory, and the rest never came through.
            // ponytail: 1000 per load. The rest come on the next load.
            let mut heads: Vec<(String, String, u64)> = Vec::new();
            {
                let mut stmt = match conn.prepare(
                    "SELECT message_id, peer_device_fingerprint, created_at FROM pending_durable_retries ORDER BY created_at"
                ) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)? as u64))
                });
                if let Ok(rows) = rows {
                    heads.extend(rows.flatten());
                }
            }
            for (message_id, peer_fp, created_at) in heads.into_iter()
                .filter(|(id, fp, _)| !self.awaiting_confirmation.contains_key(id) && self.device_recently_seen(fp))
                .take(1000)
            {
                let blob: Option<(Vec<u8>, Option<Vec<u8>>)> = conn.query_row(
                    "SELECT content_cbor, sent_cbor FROM pending_durable_retries WHERE message_id = ?1",
                    params![message_id], |r| Ok((r.get(0)?, r.get(1)?)),
                ).ok();
                if let Some((blob, sent)) = blob {
                    loaded.push((message_id, peer_fp, blob, created_at, sent));
                }
            }
        }
        // An expired entry still in memory is failed by the age arm of the retry loop.
        expired.retain(|id| !self.awaiting_confirmation.contains_key(id));
        self.fail_orphaned_sends(&expired);
        if loaded.is_empty() {
            return;
        }
        info!("Restoring {} entries from persistent retry queue", loaded.len());
        for (message_id, peer_fp, content_cbor, created_at, sent_cbor) in loaded {
            // CRITICAL (delivery guarantee): the row is NOT deleted here. `remove_durable_retry` used to be called BEFORE the resend ("a fresh send
            // will replace it anyway"). But if `send_message_content_inner` returns `Err` ("No ratchet session", "Missing own keys", "No identity",
            // all quite likely right after launch), the replacement never happens. Neither the disk row nor the in-memory `awaiting_confirmation` entry
            // remained, and the message was lost PERMANENTLY. The error log said "the normal retry loop will take over", but there was nothing left
            // for it to take over. Preventing exactly this scenario is why the table exists.
            //
            // No delete is needed. `persist_durable_retry` uses `INSERT OR REPLACE`, so on success the row is refreshed under the same primary key.
            // On the error path it stays in place and is retried on the next start.
            if self.awaiting_confirmation.contains_key(&message_id) {
                continue;
            }
            // See `STALE_PEER_RETRY_HORIZON_MS`. On a real device (tablet + Redmi), hundreds of rows were resent to ghost sibling devices on every start.
            // That caused a visible startup delay, and the queue never shrank. The row is still NOT deleted (see the note above). It is only skipped
            // in this pass.
            // Same test as the reload trigger (`last_seen == 0` is not stale).
            if !self.device_recently_seen(&peer_fp) {
                continue;
            }
            // A decrypt failure (a wrong key passed once, or a keychain hiccup) is not a corrupt row. Keep it for the next load.
            let Some(plain) = self.open_local_blob(&content_cbor) else {
                warn!("Durable retry row {} could not be decrypted, kept", message_id);
                continue;
            };
            let content: MessageContent = match ciborium::from_reader(plain.as_slice()) {
                Ok(c) => c,
                Err(e) => {
                    // A corrupt row is NOT retried (it would fail the same way on every start). Deleting it is the only case that should delete a row.
                    error!("Persistent retry record could not be parsed, dropping row ({}): {}", message_id, e);
                    self.remove_durable_retry(&message_id);
                    continue;
                }
            };
            // A parked group copy is resent only while the device's identity is still a member. A removed member would otherwise get it forever.
            let group_id = match &content {
                MessageContent::Text { group_id: Some(g), .. }
                | MessageContent::Edit { group_id: Some(g), .. }
                | MessageContent::Delete { group_id: Some(g), .. }
                | MessageContent::Reaction { group_id: Some(g), .. } => Some(g.clone()),
                _ => None,
            };
            if let Some(gid) = group_id {
                let member = self.known_remote_devices.get(&peer_fp)
                    .map_or(true, |d| self.groups.get(&gid).map_or(false, |g| g.is_member(&d.identity_id)));
                if !member {
                    info!("Durable retry row {} dropped: device left group {}", message_id, gid);
                    self.remove_durable_retry(&message_id);
                    continue;
                }
            }
            // Re-queued messages keep their original `message_id` and first-queued time (`original_sent_at`). A new id would leave the archived bubble on the old id,
            // so Ack and status events never reached it, and `init_db` turned 'pending' into 'error' at startup. Receivers also dedup on the same id.
            let known = self.known_remote_devices.contains_key(&peer_fp);
            // The backoff reaches its cap (15 + 30 + 60 s) long before most restores. Do not restart it at 15 s after every process kill.
            let interval = (current_time_ms().saturating_sub(created_at) > ACK_RETRY_MAX_MS).then_some(ACK_RETRY_MAX_MS);
            // The envelope already published, still on the current chain: it goes back into the queue as it is, due now, and
            // `retry_unconfirmed_messages` offers it at its normal pace. No ratchet step, no signature, no new server copy.
            let sent: Option<(NetworkEnvelope, String)> = sent_cbor.as_deref()
                .and_then(|b| self.open_local_blob(b))
                .and_then(|p| ciborium::from_reader(p.as_slice()).ok());
            if let Some((envelope, stamp)) = sent {
                if !stamp.is_empty() && stamp == self.chain_stamp_for(&peer_fp) {
                    let now = current_time_ms();
                    let retry_interval_ms = interval.unwrap_or(ACK_RETRY_INITIAL_MS);
                    self.awaiting_confirmation.insert(message_id.clone(), PendingConfirmation {
                        suspect_probed: false,
                        direct_delivered: false,
                        chain_stamp: stamp,
                        peer_device_fingerprint: peer_fp,
                        envelope,
                        next_retry_at: now,
                        retry_interval_ms,
                        first_sent_at: now,
                        original_sent_at: created_at,
                        last_attempt_at: now,
                        regen_content: Some(content),
                    });
                    continue;
                }
            }
            if let Err(e) = self.send_message_content_inner(
                peer_fp, &content, None,
                Some(message_id.clone()), Some(created_at), interval,
            ) {
                error!("Resend from persistent queue temporarily failed (normal retry loop will take over): {}", e);
                // A device that is gone never gets it, and the row would stay forever.
                if !known {
                    self.remove_durable_retry(&message_id);
                    self.fail_orphaned_sends(std::slice::from_ref(&message_id));
                }
            }
        }
    }
}
