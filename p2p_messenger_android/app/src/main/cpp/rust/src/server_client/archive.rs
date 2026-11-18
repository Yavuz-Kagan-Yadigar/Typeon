//! Server history archive: archive key, upload queue, fetch, merge, purge.

use super::*;

impl P2PCore {
    /// Every conversation that can have buckets on the server.
    pub(super) fn archive_conv_keys(&self) -> Vec<String> {
        // The archive key of 1:1 chats is the other side's `identity_id`, not the local `contact_id` (see the
        // `server_archive_bucket` note). Keyed by identity, so the archive stays readable when the other side
        // changes device.
        let mut conv_keys: Vec<String> = self.groups.keys().cloned().collect();
        conv_keys.extend(self.contacts.values().map(|c| c.trusted_identity_id.clone()));
        // And every conversation ever archived: a contact or group deleted since then still has buckets on the server.
        if let Some(conn) = &self.db {
            if let Ok(mut stmt) = conn.prepare("SELECT conv_key FROM server_archived_convs") {
                if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                    conv_keys.extend(rows.flatten());
                }
            }
        }
        conv_keys.sort();
        conv_keys.dedup();
        conv_keys
    }

    /// Requests deletion of our entire archive on the server.
    ///
    /// Buckets are per conversation and per month (see `server_seal::server_archive_bucket`), so to know what to
    /// delete, we generate the last 36 months for every conversation we know. Deleting a bucket that does not exist
    /// is a no-op on the server. Generating an extra ID costs nothing, while missing one would leave archive residue.
    pub(crate) fn purge_server_archive(&mut self, server_id: &str) {
        let conv_keys = self.archive_conv_keys();
        self.purge_archive_convs(server_id, &conv_keys);
    }

    /// One conversation's archive on every server (for a deleted contact), and its queued uploads, which would
    /// otherwise put it back. Best effort: an unreachable server keeps it until its TTL. The `server_archived_convs`
    /// row stays, so a later whole-server purge still covers it.
    pub(crate) fn purge_conv_archive(&mut self, conv_key: &str) {
        self.server_archive_queue.retain(|e| e.conv_key != conv_key);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM server_archive_queue WHERE conv_key = ?1", params![conv_key]);
        }
        let server_ids: Vec<String> = self.servers.iter().map(|s| s.server_id.clone()).collect();
        for sid in server_ids {
            self.purge_archive_convs(&sid, &[conv_key.to_string()]);
        }
    }

    pub(super) fn purge_archive_convs(&mut self, server_id: &str, conv_keys: &[String]) {
        let Some(ark) = self.archive_root_key else { return };
        let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id) else { return };

        let now = current_time_ms();
        let buckets: Vec<String> = conv_keys.iter().flat_map(|c| archive_purge_secrets(&ark, c, now)).collect();
        if buckets.is_empty() {
            return;
        }
        // One request must not exceed 1 MiB (see the `MAX_DEPOSIT_BYTES` note: the same wire cap applies to every
        // request). 500: the server refuses a list longer than its 512-mailbox cap.
        let cap = self.server_rt.get(server_id).map_or(1, Self::mailbox_cap).min(500);
        for chunk in buckets.chunks(cap) {
            let req = ServerRequest::ArchivePurge { purge_secrets: chunk.to_vec() };
            if self.send_server_request(peer_id, req).is_none() {
                warn!("Could not send archive delete request: {}", crate::log_id(server_id));
                return;
            }
        }
    }

    /// History written while no server stored it was never queued. Queue all local rows, or a restored device
    /// shows a gap up to today. Restarts the paged `maybe_archive_backfill` from the newest row. It runs one slice
    /// per sweep until it reaches the oldest.
    pub(crate) fn backfill_server_archive(&mut self) {
        self.meta_put("ark_backfill", "1");
        self.server_sweep_at = 0;
    }

    pub(super) fn send_archive_fetch(
        &mut self,
        peer_id: PeerId,
        server_id: String,
        conv_key: String,
        group: bool,
        bucket: String,
        before: Option<(u64, String)>,
        rest: Vec<String>,
        window: Option<(u64, u64)>,
        next: Vec<(String, bool)>,
        pages: u32,
    ) {
        let req = ServerRequest::ArchiveFetch {
            bucket: bucket.clone(),
            before_ms: before.as_ref().map(|b| b.0),
            before_id: before.as_ref().and_then(|b| (!b.1.is_empty()).then(|| b.1.clone())),
            max_items: MAX_FETCH_BATCH_ITEMS,
            max_bytes: MAX_FETCH_BATCH_BYTES,
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(
                id,
                ServerInflight::ArchiveFetch { server_id, conv_key, group, bucket_more: Some(bucket), rest, window, next, cursor: before, pages },
            );
        } else if let Some((before, _)) = window {
            self.reopen_fetch_cursor(&conv_key, before);
        }
    }

    /// A full restore walks its conversations one at a time. Probing all of them at once meant one 512 KiB chain per conversation on one Tor circuit.
    pub(super) fn probe_next_conversation(&mut self, peer_id: PeerId, server_id: String, mut next: Vec<(String, bool)>) {
        let Some(ark) = self.archive_root_key else { return };
        if next.is_empty() {
            return;
        }
        let (conv_key, group) = next.remove(0);
        let req = ServerRequest::ArchiveProbe { buckets: archive_buckets(&ark, &conv_key, current_time_ms()) };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::ArchiveProbe { server_id, conv_key, group, window: None, next });
        }
    }

}

// ---------------------------------------------------------------------------
// Archive (history): upload, fetch, merge
// ---------------------------------------------------------------------------
//
// Why mailbox envelopes cannot serve as history: ratchet message keys are forward secret, and they are deleted after
// use. Skipped keys are limited (`MAX_SKIPPED_KEYS`) and pruned on rotation. An envelope from last week can therefore
// no longer be decrypted by ANYONE, including the intended recipient. A newly linked device never had those keys at all.
// So history is re-encrypted under a SEPARATE, long-lived key.

impl P2PCore {
    /// Loads the root archive key (ARK).
    ///
    /// Not to be confused with `history_key`. That one is per DEVICE, random, and NOT in the recovery file. It only
    /// encrypts the local archive on disk. The ARK belongs to the IDENTITY: every device of the same identity must be able
    /// to read it, so it also goes to sibling devices in `SyncPayload` and into the recovery file.
    pub(crate) fn set_archive_root_key(&mut self, key: &[u8]) -> bool {
        let Ok(k) = <[u8; 32]>::try_from(key) else { return false };
        self.archive_root_key = Some(k);
        self.reconcile_archive_key(true);
        self.server_sweep_at = 0;  // // backfill runs in slices from the sweep
        true
    }

    /// History written while a history server was set but no archive key was loaded was never queued. Queue it once the
    /// key is here. One slice (200 rows) per sweep, newest first, down to the oldest row. The `ark_backfill` marker holds
    /// "<next id bound>,<rows done>" ("1" = not started), so it resumes across sweeps and restarts.
    pub(crate) fn maybe_archive_backfill(&mut self) {
        const SLICE: i64 = 200;
        if self.archive_root_key.is_none() || !self.servers.iter().any(|s| s.store_history) {
            return;
        }
        // Wait for the upload to drain: a full queue drops its oldest entries.
        if self.server_archive_queue.len() >= MAX_SERVER_ARCHIVE_QUEUE / 2 {
            return;
        }
        let Some(marker) = self.meta_str("ark_backfill") else { return };
        let (mut bound, mut done) = marker
            .split_once(',')
            .and_then(|(b, d)| Some((b.parse::<i64>().ok()?, d.parse::<i64>().ok()?)))
            .unwrap_or((i64::MAX, 0));
        let Some(conn) = &self.db else { return };
        let Ok(mut stmt) = conn.prepare(
            "SELECT id, message_id, group_id, peer_device_fingerprint FROM messages \
             WHERE message_id IS NOT NULL AND id < ?1 ORDER BY id DESC LIMIT ?2",
        ) else { return };
        let rows: Vec<(i64, String, Option<String>, String)> = stmt
            .query_map(params![bound, SLICE], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map(|it| it.flatten().collect())
            .unwrap_or_default();
        drop(stmt);
        let n = rows.len() as i64;
        for (id, mid, gid, fp) in rows {
            bound = id;
            self.requeue_archive_row(gid.as_deref(), &fp, &mid);
        }
        done += n;
        if n < SLICE {
            self.meta_del("ark_backfill");
        } else {
            self.meta_put("ark_backfill", &format!("{bound},{done}"));
            self.server_sweep_at = 0;
        }
    }

    pub(crate) fn archive_root_key_bytes(&self) -> Option<Vec<u8>> {
        self.archive_root_key.map(|k| k.to_vec())
    }

    // The archive key state that the core keeps in `app_meta` (hex strings):
    //   ark          the key in force, when the core changed it itself. It wins over the client's key file until the client
    //                loads the same key, which proves the file was written.
    //   ark_retired  SHA-256 of every replaced key (64 hex chars each). Never taken again.
    //   ark_todo     a rotation whose sync to siblings and backfill are not done yet.
    //   ark_purge    replaced keys (comma list) whose buckets are still on the server.

    /// The key the core changed itself (rotation, sibling sync) wins over the one the client loaded. The client stores it on an
    /// event that can be lost.
    pub(super) fn reconcile_archive_key(&mut self, from_client: bool) {
        let Some(stored) =
            self.meta_str("ark").and_then(|h| hex::decode(h).ok()).and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return;
        };
        if self.archive_root_key == Some(stored) {
            if from_client {
                self.meta_del("ark");
            }
            return;
        }
        self.archive_root_key = Some(stored);
        // The client stores the key on this event.
        self.attachment_events.push(serde_json::json!({"type": "sync"}).to_string());
    }

    pub(super) fn archive_key_retired(&self, key: &[u8; 32]) -> bool {
        let hash = hex::encode(Sha256::digest(key));
        self.meta_str("ark_retired").map_or(false, |r| r.as_bytes().chunks(64).any(|c| c == hash.as_bytes()))
    }

    /// Stores a key change in one statement, so a crash leaves all of it or none. `rotation`: this device made the new key. It
    /// also syncs and backfills.
    pub(super) fn persist_archive_key_change(&self, new: &[u8; 32], old: Option<&[u8; 32]>, rotation: bool) {
        let Some(conn) = &self.db else { return };
        let mut retired = self.meta_str("ark_retired").unwrap_or_default();
        let mut purge = self.meta_str("ark_purge").unwrap_or_default();
        if let Some(old) = old {
            retired.push_str(&hex::encode(Sha256::digest(old)));
            if !purge.is_empty() {
                purge.push(',');
            }
            purge.push_str(&hex::encode(old));
        }
        // The old buckets are purged by every device that replaces a key. Only the device that rotated syncs and backfills (`ark_todo`).
        let todo = if rotation { ", ('ark_todo', '1')" } else { "" };
        let head = "INSERT OR REPLACE INTO app_meta (k, v) VALUES ('ark', ?1), ('ark_retired', ?2)";
        let result = if purge.is_empty() {
            conn.execute(&format!("{head}{todo}"), params![hex::encode(new), retired])
        } else {
            conn.execute(&format!("{head}, ('ark_purge', ?3){todo}"), params![hex::encode(new), retired, purge])
        };
        if let Err(e) = result {
            error!("Could not write archive key change: {}", e);
        }
    }

    /// A revoked device holds the key. The new key is on disk before anything is sent. The rest (sync, backfill, purge of the
    /// old buckets) resumes from `app_meta` after a crash or without network.
    pub(crate) fn rotate_archive_root_key(&mut self) {
        use rand::RngCore;
        let Some(old) = self.archive_root_key else { return };
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        self.persist_archive_key_change(&key, Some(&old), true);
        self.archive_root_key = Some(key);
        self.attachment_events.push(serde_json::json!({"type": "sync"}).to_string());
        self.resume_archive_rotation();
    }

    /// Step 2 of a rotation: the new key goes to the remaining own devices, and the newest local rows are queued again, to be sealed under the new key.
    pub(super) fn resume_archive_rotation(&mut self) {
        if self.meta_str("ark_todo").is_none() {
            return;
        }
        self.sync_to_siblings();
        if self.servers.iter().any(|s| s.store_history) {
            self.backfill_server_archive();
        }
        self.meta_del("ark_todo");
    }

    /// Step 3 of a rotation: deletes what the server holds under replaced keys. Runs each sweep until the server has confirmed every bucket.
    // ponytail: the buckets of the last 36 months, as `purge_server_archive`.
    pub(super) fn purge_retired_archive(&mut self, server_id: &str, peer_id: PeerId) {
        let Some(keys) = self.meta_str("ark_purge") else { return };
        let now = current_time_ms();
        if self.server_rt.get(server_id).map_or(false, |r| mono_ms() < r.purge_retry_at)
            || self.server_inflight.values().any(|i| matches!(i, ServerInflight::ArchivePurge { .. }))
        {
            return;
        }
        // No answer or an error: try again after a while, not on each sweep.
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.purge_retry_at = mono_ms() + SERVER_DEPOSIT_BACKOFF_MS;
        }
        let conv_keys = self.archive_conv_keys();
        let mut rest = Vec::new();
        for h in keys.split(',') {
            let Some(old) = hex::decode(h).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else { continue };
            for c in &conv_keys {
                rest.extend(archive_purge_secrets(&old, c, now));
            }
        }
        self.send_archive_purge(peer_id, server_id.to_string(), keys, rest);
    }

    /// One chunk at a time. With nothing left, the replaced keys are dropped.
    pub(super) fn send_archive_purge(&mut self, peer_id: PeerId, server_id: String, keys: String, mut rest: Vec<String>) {
        if rest.is_empty() {
            // A rotation since this run started added a key: the next sweep purges again.
            if self.meta_str("ark_purge").as_deref() == Some(keys.as_str()) {
                self.meta_del("ark_purge");
            }
            return;
        }
        // 500: the server refuses a list longer than its 512-mailbox cap.
        let cap = self.server_rt.get(&server_id).map_or(1, Self::mailbox_cap).min(500);
        let tail = rest.split_off(rest.len().min(cap));
        let req = ServerRequest::ArchivePurge { purge_secrets: rest };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::ArchivePurge { server_id, keys, rest: tail });
        }
    }

    /// Takes the key a sibling sent. Only the primary device revokes, so only its key replaces one we hold. A replaced key is
    /// never taken again: an older sync can arrive after a newer one. Returns true when the key changed.
    pub(crate) fn adopt_archive_key(&mut self, key: &[u8], from_primary: bool) -> bool {
        let Ok(key) = <[u8; 32]>::try_from(key) else { return false };
        let old = self.archive_root_key;
        if old == Some(key) || (old.is_some() && !from_primary) || self.archive_key_retired(&key) {
            return false;
        }
        self.persist_archive_key_change(&key, old.as_ref(), false);
        self.archive_root_key = Some(key);
        self.server_sweep_at = 0;  // // backfill runs in slices from the sweep
        true
    }

    /// Records `rev` as seen for this record. Returns false when a higher revision was seen before: the record is a rollback
    /// and must not be merged.
    // ponytail: one row per archived message, pruned only with the last server (`remove_server`), bounded like the history itself.
    pub(super) fn note_archive_rev(&self, conv_key: &str, record_id: &str, rev: u64) -> bool {
        let Some(conn) = &self.db else { return true };
        let rev = rev.min(i64::MAX as u64) as i64;
        let known: i64 = conn
            .query_row(
                "SELECT rev FROM server_archive_revs WHERE conv_key = ?1 AND record_id = ?2",
                params![conv_key, record_id],
                |r| r.get(0),
            )
            .unwrap_or(-1);
        if rev < known {
            return false;
        }
        if rev > known {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_archive_revs (conv_key, record_id, rev) VALUES (?1, ?2, ?3)",
                params![conv_key, record_id, rev],
            );
        }
        true
    }

    /// Is history storage on the server enabled?
    pub(super) fn history_server(&self) -> Option<String> {
        self.servers
            .iter()
            .find(|s| {
                s.store_history
                    && self.server_rt.get(&s.server_id).map(|r| r.connected && r.enrolled).unwrap_or(false)
            })
            .map(|s| s.server_id.clone())
    }

    /// Called when a local archive row is written. It queues the same row for upload to the server.
    ///
    /// `rev`: an edit or delete uploads with the SAME `record_id` and a higher revision, and the server overwrites the older
    /// copy. That is exactly what the existing `HistorySyncResponse` mechanism cannot do (correct a late Edit in the past).
    pub(crate) fn queue_archive_record(
        &mut self,
        conv_key: &str,
        record_id: &str,
        rev: u64,
        sent_at_ms: u64,
        plaintext: Vec<u8>,
    ) {
        // With no server, or history storage off, nothing is queued. Otherwise a disabled feature would quietly grow the disk.
        if !self.servers.iter().any(|s| s.store_history) {
            return;
        }
        if self.archive_root_key.is_none() {
            // Queued once the key arrives (`maybe_archive_backfill`).
            if self.meta_str("ark_backfill").is_none() {
                self.meta_put("ark_backfill", "1");
            }
            return;
        }
        // The server must not hand back a revision older than this one.
        self.note_archive_rev(conv_key, record_id, rev);
        let entry = PendingArchive {
            conv_key: conv_key.to_string(),
            record_id: record_id.to_string(),
            rev,
            // The bucket comes from this. A peer's clock far ahead put the record where no probe or purge would look.
            sent_at_ms: sent_at_ms.min(current_time_ms()),
            plaintext,
        };
        // This column used to store the message body as PLAINTEXT. Every body in the `messages` table is encrypted with
        // `history_key`, so the at-rest encryption was bypassed for exactly this table. The queue normally drains quickly,
        // but after `remove_server` (no connected history server left) the rows stayed on disk as plaintext indefinitely.
        // If `seal_local_blob` is not available (the key is not loaded yet), the row is not written at all. The copy in
        // memory is still sent in this turn.
        if let Some(conn) = &self.db {
            let _ = conn.execute("INSERT OR IGNORE INTO server_archived_convs (conv_key) VALUES (?1)", params![entry.conv_key]);
        }
        let stored = self.seal_local_blob(&entry.plaintext);
        if let (Some(conn), Some(blob)) = (&self.db, stored) {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_archive_queue (record_id, conv_key, rev, sent_at_ms, plaintext, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![entry.record_id, entry.conv_key, entry.rev as i64, entry.sent_at_ms as i64, blob, current_time_ms() as i64],
            );
        }
        // If an older revision of the same record is waiting in the queue, replace it.
        if let Some(existing) = self.server_archive_queue.iter_mut().find(|e| e.record_id == entry.record_id) {
            *existing = entry;
        } else {
            self.server_archive_queue.push(entry);
            // History server down for a long time: the queue does not grow without end.
            let over = self.server_archive_queue.len().saturating_sub(MAX_SERVER_ARCHIVE_QUEUE);
            if over > 0 {
                warn!("Archive queue full, oldest {} records will not reach server", over);
                self.drop_archive_queue_head(over);
            }
        }
    }

    /// Uploads the queued archive records in batches.
    pub(super) fn server_flush_archive(&mut self, server_id: &str, peer_id: PeerId) {
        if self.server_archive_queue.is_empty() {
            return;
        }
        let Some(ark) = self.archive_root_key else { return };
        // Quota or rate error: wait (own backoff, see `archive_backoff_until`), not once per sweep.
        if self.server_rt.get(server_id).map_or(false, |r| mono_ms() < r.archive_backoff_until) {
            return;
        }
        // If an `ArchivePut` is already in flight, wait. Sending them in order keeps the server's `rev` comparison predictable.
        if self.server_inflight.values().any(|i| matches!(i, ServerInflight::ArchivePut { .. })) {
            return;
        }

        // One request goes to ONE bucket (a bucket is a conversation plus a period). So we gather the entries that match the
        // bucket of the record at the head of the queue.
        let head = self.server_archive_queue[0].clone();
        let epoch = server_seal::archive_epoch_for(head.sent_at_ms);
        let Ok(bucket) = server_seal::server_archive_bucket(&ark, &head.conv_key, epoch) else { return };

        let mut records = Vec::new();
        let mut consumed = 0usize;
        let mut sealed_bytes = 0usize;
        // Half the wire cap. An oversized request fails as a whole and would be re-sent unchanged.
        let budget = MAX_DEPOSIT_BYTES / 2;
        for entry in self.server_archive_queue.iter() {
            if records.len() >= SERVER_ARCHIVE_BATCH {
                break;
            }
            if entry.conv_key != head.conv_key || server_seal::archive_epoch_for(entry.sent_at_ms) != epoch {
                // A different bucket: this batch ends here. The queue order is kept.
                break;
            }
            // The server sees an ID that only this identity can link to the message. The real ID travels inside the sealed record.
            let wire_id = archive_wire_id(&ark, &entry.conv_key, &entry.record_id);
            match server_seal::seal_archive_record(
                &ark,
                &entry.conv_key,
                &wire_id,
                entry.rev,
                &bucket,
                archive_wire_ms(entry.sent_at_ms),
                &entry.plaintext,
            ) {
                // A record that alone breaks the budget never goes. It leaves with this batch (counted in `consumed`) and is dropped.
                Ok(sealed) if sealed.len() > budget => {
                    warn!("Archive record too large for server, skipped: {} bytes", sealed.len());
                }
                // Checked with this record included. The next batch starts with it.
                Ok(sealed) if sealed_bytes + sealed.len() > budget => break,
                Ok(sealed) => {
                    sealed_bytes += sealed.len();
                    records.push(ArchiveRecord {
                        record_id: wire_id,
                        rev: entry.rev,
                        sent_at_ms: archive_wire_ms(entry.sent_at_ms),
                        sealed,
                    })
                }
                Err(e) => {
                    warn!("Could not seal archive record: {}", e);
                }
            }
            consumed += 1;
        }
        if records.is_empty() {
            // Sealing failed for all of them. Do not let that block the queue.
            self.drop_archive_queue_head(consumed.max(1));
            return;
        }
        // Every consumed entry, including the ones that could not be sealed, leaves with the batch.
        let sent: Vec<(String, u64)> =
            self.server_archive_queue[..consumed].iter().map(|e| (e.record_id.clone(), e.rev)).collect();
        let req = ServerRequest::ArchivePut { bucket, records };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight
                .insert(id, ServerInflight::ArchivePut { server_id: server_id.to_string(), records: sent });
        }
    }

    /// Removes exactly these `(record_id, rev)` entries. An entry edited while its batch was in flight carries a newer `rev` and stays queued.
    pub(super) fn drop_archive_records(&mut self, records: &[(String, u64)]) {
        for (record_id, rev) in records {
            self.server_archive_queue.retain(|e| !(e.record_id == *record_id && e.rev == *rev));
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "DELETE FROM server_archive_queue WHERE record_id = ?1 AND rev = ?2",
                    params![record_id, *rev as i64],
                );
            }
        }
    }

    pub(super) fn drop_archive_queue_head(&mut self, count: usize) {
        let n = count.min(self.server_archive_queue.len());
        for entry in self.server_archive_queue.drain(..n) {
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "DELETE FROM server_archive_queue WHERE record_id = ?1",
                    params![entry.record_id],
                );
            }
        }
    }

    /// Asks the server for an older page on "scroll up, show me older".
    ///
    /// This is the THIRD source of the existing multi-source design. `request_older_history` asks the peer,
    /// `request_older_sibling_history` asks my other device, and this asks the server. All three go out in parallel. Replies
    /// are deduplicated by `message_id`, and whichever arrives first fills the gap.
    ///
    /// The window `[after, before)` of a "Fetch older history" press: every page of it, from the buckets that reach it. A
    /// full restore of the same conversation may run alongside it. A full restore respects the history floor. This chain
    /// does not, inside its window.
    /// Returns whether the request went out.
    pub(super) fn request_older_server_history(&mut self, conv_key: &str, group: bool, before: u64, after: u64) -> bool {
        let Some(ark) = self.archive_root_key else { return false };
        let Some(server_id) = self.history_server() else { return false };
        let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { return false };
        // Monthly buckets (see `server_archive_bucket`): the month of `before` and the months before it.
        let buckets = archive_buckets(&ark, conv_key, before);
        let req = ServerRequest::ArchiveProbe { buckets };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(
                id,
                ServerInflight::ArchiveProbe {
                    server_id,
                    conv_key: conv_key.to_string(),
                    group,
                    window: Some((before, after)),
                    next: Vec::new(),
                },
            );
            return true;
        }
        false
    }

    /// If a press's server chain failed, the cursor goes back up to the window's end. The next press then asks every source for
    /// that window again (rows are deduplicated by id), instead of skipping the server's part of it for good.
    pub(super) fn reopen_fetch_window(&self, inflight: &ServerInflight) {
        if let ServerInflight::ArchiveProbe { conv_key, window: Some((before, _)), .. }
        | ServerInflight::ArchiveFetch { conv_key, window: Some((before, _)), .. } = inflight
        {
            self.reopen_fetch_cursor(conv_key, *before);
        }
    }

    /// Drops the running "Fetch older history" chains of a conversation (`forget_history_fetch`). Their late pages are then
    /// unexpected and dropped. A full restore chain stays; it respects the history floor.
    pub(crate) fn drop_archive_page_chains(&mut self, conv_key: &str) {
        self.server_inflight.retain(|_, f| !matches!(f,
            ServerInflight::ArchiveProbe { conv_key: c, window: Some(_), .. }
            | ServerInflight::ArchiveFetch { conv_key: c, window: Some(_), .. } if c == conv_key));
    }

    /// The single "fetch older history" action, on user action only. Scrolling up reads the local archive and never comes
    /// here. One press asks every source (the chat peer(s), the own connected devices, the server archive when a history
    /// server and the archive key exist) for the same window: one `HISTORY_FETCH_WINDOW_MS` older than the chat's cursor
    /// (`history_fetch_cursor`), which then moves to the window's start. The cursor never comes from the arriving rows, so
    /// an empty month still moves it, and a backdated row cannot pin it. `chat_key`: the peer device fingerprint, or the group
    /// ID. `_before_ms` (the oldest row on screen) is not used: the cursor is kept here.
    pub(crate) fn fetch_server_history(&mut self, chat_key: &str, is_group: bool, _before_ms: u64) -> Result<(), String> {
        let conv_key = if is_group {
            if !self.groups.contains_key(chat_key) {
                return Err("Group not found".to_string());
            }
            chat_key.to_string()
        } else {
            self.identity_id_for_device(chat_key).ok_or("This device's identity is unknown")?
        };
        let before = if is_group {
            self.history_fetch_cursor(&conv_key, "", Some(chat_key))
        } else {
            self.history_fetch_cursor(&conv_key, &self.canonical_peer_key(chat_key), None)
        };
        let after = before.saturating_sub(crate::HISTORY_FETCH_WINDOW_MS);
        // Budget before the requests: a fast answer may already want a follow-up.
        self.history_fetch_pages.insert(conv_key.clone(), crate::HISTORY_FETCH_MAX_PAGES);
        let (b, a) = (before as i64, after as i64);
        // One unreachable source is not an error: the others remain.
        let sent = if is_group {
            let peers = self.request_older_group_history(chat_key, b, a).is_ok();
            self.request_older_sibling_history(None, Some(chat_key), b, a, None).is_ok() | peers
        } else {
            let peer = self.request_older_history(chat_key, b, a).is_ok();
            self.request_older_sibling_history(Some(&conv_key), None, b, a, None).is_ok() | peer
        };
        // Returns false at once without the archive key or a history server.
        let sent = self.request_older_server_history(&conv_key, is_group, before, after) | sent;
        if !sent {
            // Nothing went out: the month stays for the next press.
            self.history_fetch_pages.remove(&conv_key);
            return Err("Can't reach a history source over the network".to_string());
        }
        self.meta_put(&format!("hfetch:{}", conv_key), &after.to_string());
        Ok(())
    }

    /// Downloads the WHOLE server archive. For a device freshly set up or recovered.
    ///
    /// Why a separate flow: `request_older_server_history` covers "I scrolled up in this chat", so it assumes the chat is
    /// already visible. On a device set up from a recovery file, contacts and groups come back, but NO messages, and the
    /// user has nothing to scroll. This function probes the last 36 months of buckets of every known conversation with ONE
    /// `ArchiveProbe`, and fetches the buckets that hold data.
    ///
    /// `ListArchiveConversations` is deliberately NOT used. Letting the server list our conversations would mean it keeps a
    /// persistent conversation index. We can generate the buckets ourselves, and probing an absent bucket is a no-op on the server.
    pub(crate) fn restore_all_server_history(&mut self) -> Result<u32, String> {
        if self.archive_root_key.is_none() {
            return Err("Root archive key not found — this device cannot decrypt history on the server".to_string());
        }
        let Some(server_id) = self.history_server() else {
            return Err("Not found: no connected server stores history".to_string());
        };
        let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else {
            return Err("No network connection to server".to_string());
        };

        let mut convs: Vec<(String, bool)> = self.groups.keys().map(|g| (g.clone(), true)).collect();
        convs.extend(self.contacts.values().map(|c| (c.trusted_identity_id.clone(), false)));
        if convs.is_empty() {
            return Ok(0);
        }

        let asked = convs.len() as u32;
        self.probe_next_conversation(peer_id, server_id, convs);
        Ok(asked)
    }

    /// Merges an archive page from the server into the LOCAL archive.
    ///
    /// Same rule as the existing `HistorySyncResponse` merge: presence is checked by `message_id`, not by a timestamp threshold
    /// (a timestamp check works in the wrong direction for paginated requests).
    /// `window`: a page of the user's "Fetch older history" press `(before, after)`. Only its rows sent inside the window are kept.
    /// They may come back below the history floor, which then moves down to the oldest row written.
    pub(super) fn merge_server_archive(&mut self, conv_key: &str, group: bool, bucket: &str, records: Vec<ArchiveRecord>, window: Option<(u64, u64)>) {
        let Some(ark) = self.archive_root_key else { return };
        let mut merged = 0usize;
        let mut opened: Vec<(ArchiveRecord, crate::ArchivedMessage)> = Vec::new();
        for rec in records {
            let plaintext = match server_seal::open_archive_record(
                &ark,
                conv_key,
                &rec.record_id,
                rec.rev,
                bucket,
                rec.sent_at_ms,
                &rec.sealed,
            ) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Could not decrypt server archive record: {}", e);
                    continue;
                }
            };
            let archived: crate::ArchivedMessage = match ciborium::from_reader(plaintext.as_slice()) {
                Ok(a) => a,
                Err(e) => {
                    warn!("Could not parse server archive record: {}", e);
                    continue;
                }
            };
            opened.push((rec, archived));
        }
        // A press keeps only rows sent inside its window. The server pages by the hour-floored wire time, so a page reaches a
        // little past both ends. Those extra rows belong to the neighbouring windows. Only rows inside the window may come back
        // below the history floor.
        let floor = match window {
            Some((before, after)) => {
                opened.retain(|(_, a)| {
                    let at = if a.sent_at_ms != 0 { a.sent_at_ms } else { a.timestamp };
                    (after..before).contains(&at)
                });
                0
            }
            None => self.history_floor(conv_key),
        };
        let mut oldest_written: Option<u64> = None;
        for (rec, archived) in opened {
            // The wire ID is keyed (`archive_wire_id`). The real ID is inside the sealed record, and it must be the one the wire ID was made from.
            let Some(record_id) = archived.message_id.clone()
                .filter(|mid| archive_wire_id(&ark, conv_key, mid) == rec.record_id)
            else {
                warn!("Server archive record identity mismatch, skipped");
                continue;
            };
            // Checked after the tag verification: an unauthenticated `rev` must not be stored.
            if !self.note_archive_rev(conv_key, &record_id, rec.rev) {
                warn!("Server archive record rejected: older revision than seen");
                continue;
            }
            // Per chat, as `archive.rs` does: a sibling-crafted record must not hide a row of another chat.
            let exists = if group {
                self.message_exists_in_chat(&record_id, Some(conv_key), "")
            } else {
                self.message_exists_with_identity(&record_id, conv_key)
            };
            if exists {
                continue;
            }
            // Cleared or pruned by the user (`history_floor`). `conv_key` is the identity ID or group ID the floor is kept under.
            let at = if archived.sent_at_ms != 0 { archived.sent_at_ms } else { archived.timestamp };
            if at < floor {
                continue;
            }
            let result = if group {
                self.archive_group_message(
                    conv_key,
                    archived.sender_identity_id.as_deref().unwrap_or(""),
                    &archived.direction,
                    archived.text.as_bytes(),
                    Some(&record_id),
                    archived.reply_to_message_id.as_deref(),
                    archived.reply_to_preview.as_deref(),
                    archived.reply_to_sender_identity_id.as_deref(),
                    archived.sent_at_ms,
                    archived.author_proof.as_deref(),
                )
            } else {
                // The server archive is keyed by IDENTITY (`conv_key` = identity_id), but the local archive is keyed by DEVICE
                // fingerprint. We write to the other side's current active device. The chat key, as elsewhere
                // (`canonical_device_for_identity`): under another device the rows would be stored where the chat never looks.
                match self.canonical_device_for_identity(conv_key) {
                    Some(fp) => self.archive_message(
                        &fp,
                        &archived.direction,
                        archived.text.as_bytes(),
                        Some(&record_id),
                        archived.status.as_deref(),
                        archived.reply_to_message_id.as_deref(),
                        archived.reply_to_preview.as_deref(),
                        archived.sent_at_ms,
                    ),
                    None => Err("Could not resolve active device for this identity: unknown peer device".to_string()),
                }
            };
            match result {
                Ok(()) => {
                    // The record's deleted/edited marks (a delete re-uploads the row as a tombstone).
                    let chat_key = if group { String::new() } else { self.canonical_device_for_identity(conv_key).unwrap_or_default() };
                    self.mark_restored_flags(group.then_some(conv_key), &chat_key, &record_id, archived.is_deleted, archived.is_edited);
                    merged += 1;
                    oldest_written = Some(oldest_written.map_or(at, |o| o.min(at)));
                }
                Err(e) => warn!("Could not write server archive row: {}", e),
            }
        }
        // The user fetched rows back. From the oldest one written on, they are no longer "cleared".
        if let (Some(_), Some(o)) = (window, oldest_written) {
            self.lower_history_floor(conv_key, o);
        }
        if merged > 0 {
            // This event reached NO client. Two separate causes. (a) The type `older_history` /
            // `older_group_history` was chosen, but the contract of those two events requires a `messages` ARRAY, which was not
            // present here. Android's `applyOlderHistory` returned at once if `messages` was missing. (b) The address field was
            // written as `conversation`, but routing looks at `peer` (1:1) and `group_id` (group). Android's `isForThisPeer` filter
            // and Linux's `event_belongs_here` both dropped this event SILENTLY. The result: history restored from the server was
            // written to the DB, but did not appear in the open chat. For the user, history simply was not coming back from the server.
            //
            // Now the bulk-change event `history_backfilled` (both clients know it, meaning "refresh the screen") is published with
            // the correct address field. For 1:1, the server archive is keyed by identity while the local chat key is per device, so
            // the same translation as the `merge` path is applied.
            let mut event = serde_json::json!({
                "type": "history_backfilled", "count": merged, "source": "server"
            });
            if group {
                event["group_id"] = serde_json::json!(conv_key);
            } else if let Some(fp) = self.canonical_device_for_identity(conv_key) {
                event["peer"] = serde_json::json!(fp);
            }
            self.attachment_events.push(event.to_string());
        }
    }
}

/// The archive buckets of one conversation: the month of `newest_ms` and the 35 before it. Purge, scroll-up and full restore must agree on this window.
pub(super) fn archive_buckets(ark: &[u8; 32], conv_key: &str, newest_ms: u64) -> Vec<String> {
    let newest = server_seal::archive_epoch_for(newest_ms);
    (newest.saturating_sub(35)..=newest)
        .rev()
        .filter_map(|epoch| server_seal::server_archive_bucket(ark, conv_key, epoch).ok())
        .collect()
}

/// The purge secrets of the same buckets as `archive_buckets` (see `ServerRequest::ArchivePurge`).
pub(super) fn archive_purge_secrets(ark: &[u8; 32], conv_key: &str, newest_ms: u64) -> Vec<String> {
    let newest = server_seal::archive_epoch_for(newest_ms);
    (newest.saturating_sub(35)..=newest)
        .rev()
        .filter_map(|epoch| server_seal::server_archive_purge_secret(ark, conv_key, epoch).ok())
        .collect()
}

/// The `sent_at_ms` the server sees, floored to the hour (same epoch as the exact time). Restore orders by the time inside the sealed record.
pub(super) fn archive_wire_ms(sent_at_ms: u64) -> u64 {
    sent_at_ms - sent_at_ms % 3_600_000
}

/// The record ID the server sees: keyed with the archive key, so the two ends of a chat (each with its own key) store one message under
/// unrelated IDs. The real ID is inside the sealed record (`ArchivedMessage.message_id`).
pub(super) fn archive_wire_id(ark: &[u8; 32], conv_key: &str, record_id: &str) -> String {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(conv_key.as_bytes()), ark);
    let info = [b"typeon-archive-record-id:".as_slice(), record_id.as_bytes()].concat();
    let mut out = [0u8; 16];
    // 16 bytes is far below the HKDF output limit, so this cannot fail.
    let _ = hk.expand(&info, &mut out);
    hex::encode(out)
}
