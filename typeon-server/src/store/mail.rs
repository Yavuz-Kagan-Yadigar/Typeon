//! Mailboxes: registration, deposit, fetch, ack, expiry, byte accounting.

use super::*;

impl Store {
    // -----------------------------------------------------------------
    // Mailbox
    // -----------------------------------------------------------------

    /// Tests: every id comes with a proof made by one shared key.
    #[cfg(test)]
    pub fn register_mailboxes(&self, owner: &[u8], add: &[String], drop: &[String], now: i64, max: u32) -> Result<Vec<String>, String> {
        let proofs: Vec<(String, Vec<u8>)> = add.iter().map(|id| (id.clone(), b"test-key".to_vec())).collect();
        self.register_mailboxes_proved(owner, add, drop, &proofs, now, max).map(|(refused, _)| refused)
    }

    /// Returns `Ok` with the ids of `add` that were refused (mailbox quota, or the proof key's reader slots full and
    /// in use), and then the ids that need a proof but came without one. The other ids are registered. One refused id
    /// does not cost the batch.
    ///
    /// `proofs`: (mailbox id, hash of the mailbox key) for each `MailboxProof` whose signature the caller verified. An
    /// id the owner already reads needs none. A new reader row keeps its proof key (`MAX_READERS_PER_KEY`).
    pub fn register_mailboxes_proved(
        &self,
        owner: &[u8],
        add: &[String],
        drop: &[String],
        proofs: &[(String, Vec<u8>)],
        now: i64,
        max: u32,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        // One transaction: an eviction without the newcomer's row would lose a reader.
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let mut refused = Vec::new();
        let mut unproven = Vec::new();
        // Counted once, then kept up to date below. A query per id scanned the owner's rows for every id.
        let mut count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM mailbox_readers WHERE owner = ?1", params![owner], |r| r.get(0))
            .unwrap_or(0);
        for id in add {
                        // If already registered, skip the counter check. The call must be idempotent.
                        //
                        // The query does not filter by `owner`, but `mailbox_readers` is multi-reader (see the schema note). So a box
                        // another party registered counted as "already there" for this client too, and the `max_mailboxes` quota was
                        // skipped. Both sides of a ratchet box register it, so this is the NORMAL case, not an edge case, and the quota
                        // must still apply on the second side.
            let exists: bool = self
                .conn
                .query_row(
                    "SELECT 1 FROM mailbox_readers WHERE mailbox_id = ?1 AND owner = ?2",
                    params![id, owner],
                    |_| Ok(true),
                )
                .optional()
                .ok()
                .flatten()
                .unwrap_or(false);
            if !exists && count >= max as i64 {
                refused.push(id.clone());
                continue;
            }
            // A new reader needs a proof. There is at most `MAX_READERS_PER_KEY` readers per proof key, so one key cannot
            // fill another's slots.
            let mut reader_key: Option<&Vec<u8>> = None;
            if !exists {
                let Some((_, key_hash)) = proofs.iter().find(|(m, _)| m == id) else {
                    unproven.push(id.clone());
                    continue;
                };
                // A key-bound id has exactly one key, the one it is derived from. Knowing the id is not enough to read the box.
                if id.starts_with(server_proto::KEY_BOUND_MAILBOX_PREFIX) && *id != server_proto::key_bound_mailbox_id(key_hash) {
                    refused.push(id.clone());
                    continue;
                }
                reader_key = Some(key_hash);
                let readers: i64 = self
                    .conn
                    .query_row(
                        "SELECT COUNT(*) FROM mailbox_readers WHERE mailbox_id = ?1 AND key_hash = ?2",
                        params![id, key_hash],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                // The slots of this key are full. The newcomer holds the same secret, so it is one of those ends (a restored
                // device under a new enrollment). The same-key reader seen longest ago makes room, but only once it has been
                // idle for `READER_EVICT_IDLE_MS` (its own requests or its last Register). A reader in use is never displaced.
                if readers >= MAX_READERS_PER_KEY {
                    let stale: Option<(Vec<u8>, i64)> = self
                        .conn
                        .query_row(
                            "SELECT r.owner, MAX(r.last_seen_at, COALESCE(e.last_seen_at, 0)) AS seen
                               FROM mailbox_readers r LEFT JOIN enrollments e ON e.enrollment_id = r.owner
                              WHERE r.mailbox_id = ?1 AND r.key_hash = ?2 ORDER BY seen ASC LIMIT 1",
                            params![id, key_hash],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()
                        .map_err(|e| e.to_string())?;
                    let Some((stale, _)) = stale.filter(|(_, seen)| now - seen >= READER_EVICT_IDLE_MS) else {
                        refused.push(id.clone());
                        continue;
                    };
                    let _ = self
                        .conn
                        .execute("DELETE FROM mailbox_readers WHERE mailbox_id = ?1 AND owner = ?2", params![id, stale]);
                    let _ = self
                        .conn
                        .execute("DELETE FROM mail_acks WHERE mailbox_id = ?1 AND owner = ?2", params![id, stale]);
                    let _ = self.delete_fully_acked(id);
                }
            }
            // The record is now MULTI-READER (see the `mailbox_readers` schema note). Both sides of a ratchet box register
            // it, and one registration does not overwrite the other. A reader keeps its key.
            self.conn
                .execute(
                    "INSERT INTO mailbox_readers (mailbox_id, owner, created_at, last_seen_at, key_hash)
                     VALUES (?1, ?2, ?3, ?3, ?4)
                     ON CONFLICT(mailbox_id, owner) DO UPDATE SET last_seen_at = ?3",
                    params![id, owner, now, reader_key],
                )
                .map_err(|e| e.to_string())?;
            if !exists {
                count += 1;
            }
        }
        for id in drop {
            // Only the OWNER can remove it. Not a reader: nothing changed, and the cleanup below scans the whole box.
            let left = self
                .conn
                .execute("DELETE FROM mailbox_readers WHERE mailbox_id = ?1 AND owner = ?2", params![id, owner])
                .unwrap_or(0);
            if left == 0 {
                continue;
            }
            // A departing reader must not keep items waiting. Its own ack still counts in this cleanup, and then its
            // cursor is dropped.
            let _ = self.delete_fully_acked(id);
            let _ = self
                .conn
                .execute("DELETE FROM mail_acks WHERE mailbox_id = ?1 AND owner = ?2", params![id, owner]);
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok((refused, unproven))
    }

    /// A deposit only makes sense when someone other than the depositor reads the box on an active enrollment.
    /// Otherwise the item can only expire.
    pub fn mailbox_has_other_reader(&self, mailbox_id: &str, depositor: &[u8]) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM mailbox_readers r JOIN enrollments e ON e.enrollment_id = r.owner
                 WHERE r.mailbox_id = ?1 AND r.owner != ?2 AND e.state = 'active' LIMIT 1",
                params![mailbox_id, depositor],
                |_| Ok(true),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    pub fn mailbox_is_registered(&self, mailbox_id: &str) -> bool {
        self.conn
            .query_row("SELECT 1 FROM mailbox_readers WHERE mailbox_id = ?1", params![mailbox_id], |_| Ok(true))
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// Row count for mailbox capacity: rows that NO reader has acknowledged yet. Rows that stay until the TTL because
    /// another reader (for example a stranger that never acks) has not acknowledged them are not counted. Otherwise that
    /// reader could fill the box and block all new deliveries.
    /// ponytail: these rows still count toward the byte quota (`recount_mail_bytes`). Malicious readers can hold the
    /// disk up to the quota for the TTL.
    #[cfg(test)]
    pub fn mailbox_item_count(&self, mailbox_id: &str) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM mail m WHERE m.mailbox_id = ?1
                   AND NOT EXISTS (SELECT 1 FROM mail_acks a
                                   WHERE a.mailbox_id = m.mailbox_id AND a.owner != m.depositor
                                     AND a.through_seq >= m.seq)",
                params![mailbox_id],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Same as `mailbox_item_count`, for one depositor's rows only. Capacity is per depositor: one sender (who cannot
    /// read the box) filling it stops nobody else's mail.
    pub fn depositor_item_count(&self, mailbox_id: &str, depositor: &[u8]) -> i64 {
        self.depositor_usage(mailbox_id, depositor).0
    }

    /// (rows, bytes) of one depositor in one box that no other reader has acknowledged yet. A row that only a silent
    /// reader still holds does not count, or that reader would fill the sender's capacity. Walks
    /// `idx_mail_box_depositor`, not the `sealed` blobs.
    pub fn depositor_usage(&self, mailbox_id: &str, depositor: &[u8]) -> (i64, i64) {
        self.conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(m.byte_len), 0) FROM mail m WHERE m.mailbox_id = ?1 AND m.depositor = ?2
                   AND NOT EXISTS (SELECT 1 FROM mail_acks a
                                   WHERE a.mailbox_id = m.mailbox_id AND a.owner != m.depositor
                                     AND a.through_seq >= m.seq)",
                params![mailbox_id, depositor],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or((i64::MAX, i64::MAX))
    }

        /// If the SAME bytes from the same depositor are already in this box, no new row is opened. The existing `seq` is
        /// returned.
        ///
        /// Client-side de-duplication used to recognise only `Message` envelopes. A `Handshake` was re-deposited about once
        /// a second (about 15 KB each). That filled the depositor's `bytes_mail` quota within hours and locked all
        /// store-and-forward traffic for that device (see `deposit_dedup_key` in the client). The client now de-duplicates
        /// every kind. This check is the second line of defence: an old or buggy client cannot inflate the server.
        ///
        /// Dropping the repeat is safe: the recipient already de-duplicates by `message_id`, and an identical second copy
        /// carries no information.
    #[cfg(test)]
    pub fn deposit(&self, mailbox_id: &str, sealed: &[u8], depositor: &[u8], now: i64, ttl_ms: i64) -> Result<u64, String> {
        self.deposit_written(mailbox_id, sealed, depositor, now, ttl_ms).map(|(seq, _)| seq)
    }

    /// `deposit`, plus whether a new row was written (`false` for a repeat). Only a new row is charged to the disk total.
    pub fn deposit_written(&self, mailbox_id: &str, sealed: &[u8], depositor: &[u8], now: i64, ttl_ms: i64) -> Result<(u64, bool), String> {
        // Matched by hash, from the index. Comparing `sealed` itself read every same-length blob of this depositor in the
        // box on each deposit.
        let hash = Sha256::digest(sealed);
        if let Ok(existing) = self.conn.query_row(
            "SELECT seq FROM mail WHERE mailbox_id = ?1 AND depositor = ?2 AND sealed_hash = ?3 LIMIT 1",
            params![mailbox_id, depositor, hash.as_slice()],
            |row| row.get::<_, i64>(0),
        ) {
            // Refresh the TTL. If the sender keeps re-sending, the recipient has not received it yet, so the copy must not
            // expire early.
            let _ = self.conn.execute(
                "UPDATE mail SET expires_at_ms = ?1 WHERE mailbox_id = ?2 AND seq = ?3",
                params![now + ttl_ms, mailbox_id, existing],
            );
            return Ok((existing as u64, false));
        }
        // Row and charge together. A swallowed charge would under-count the quota.
        let charge = mail_row_bytes(mailbox_id, sealed) as i64;
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let seq: i64 = self
            .conn
            .query_row(
                "INSERT INTO mail_seq (mailbox_id, last)
                 VALUES (?1, COALESCE((SELECT v FROM meta WHERE k = 'mail_seq_base'), 0) + 1)
                 ON CONFLICT(mailbox_id) DO UPDATE SET last = last + 1
                 RETURNING last",
                params![mailbox_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "INSERT INTO mail (seq, mailbox_id, sealed, byte_len, deposited_at_ms, expires_at_ms, depositor, sealed_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![seq, mailbox_id, sealed, charge, now, now + ttl_ms, depositor, hash.as_slice()],
            )
            .map_err(|e| e.to_string())?;
        let seq = seq as u64;
        // The quota is charged to the DEPOSITOR, not the box owner. A spam sender uses up its own quota. Nobody can fill
        // a victim's box to deny it service.
        self.conn
            .execute(
                "UPDATE enrollments SET bytes_mail = bytes_mail + ?1 WHERE enrollment_id = ?2",
                params![charge, depositor],
            )
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok((seq, true))
    }

    /// Fetches the items after the cursor. Stops before `max_bytes` or `max_items` is exceeded. The rest comes in the
    /// next round (`more`).
    ///
    /// `requester`: the requester's enrollment id. Envelopes the requester ITSELF deposited are NOT returned. Both sides
    /// of a ratchet box write and read it, so without this filter each side would download its own outgoing traffic. It
    /// cannot decrypt that (the send and receive chains differ), and the log fills with "cannot decrypt" errors. Bandwidth
    /// and CPU are wasted.
    pub fn fetch(&self, requester: &[u8], cursors: &[(String, u64)], max_items: u32, max_bytes: u32) -> (Vec<MailItem>, bool) {
        let mut items = Vec::new();
        let mut total = 0usize;
        let mut more = false;

        // Only a reader that REGISTERED the box can read it.
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT m.seq, m.deposited_at_ms, m.sealed FROM mail m INDEXED BY idx_mail_reader
             WHERE m.mailbox_id = ?1 AND m.seq > ?2 AND m.depositor != ?3
               AND EXISTS (SELECT 1 FROM mailbox_readers r
                           WHERE r.mailbox_id = m.mailbox_id AND r.owner = ?3)
             ORDER BY m.seq",
        ) else {
            return (items, false);
        };
        for (mailbox_id, after_seq) in cursors {
            if items.len() as u32 >= max_items || total >= max_bytes as usize {
                more = true;
                break;
            }
            let rows = stmt.query_map(params![mailbox_id, (*after_seq).min(i64::MAX as u64) as i64, requester], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?))
            });
            let Ok(rows) = rows else { continue };
            for (seq, deposited_at_ms, sealed) in rows.flatten() {
                // The first item always goes out, even over `max_bytes`. Otherwise an item larger than the batch cap blocks
                // its mailbox (zero items, `more` forever) until the TTL.
                if items.len() as u32 >= max_items || (!items.is_empty() && total + sealed.len() > max_bytes as usize) {
                    more = true;
                    break;
                }
                total += sealed.len();
                items.push(MailItem {
                    mailbox_id: mailbox_id.clone(),
                    seq: seq as u64,
                    deposited_at_ms: deposited_at_ms as u64,
                    sealed,
                });
            }
        }
        (items, more)
    }

    /// Counts the items in `mailbox_id` that `reader` has not acknowledged (and did not deposit itself), capped at 2:
    /// the caller only asks "exactly one?" (see `ServerRequest::Push`), and runs this per deposit.
    pub fn unacked_for(&self, mailbox_id: &str, reader: &[u8]) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM (SELECT 1 FROM mail m INDEXED BY idx_mail_reader WHERE m.mailbox_id = ?1 AND m.depositor != ?2
                   AND m.seq > COALESCE((SELECT a.through_seq FROM mail_acks a
                                         WHERE a.mailbox_id = ?1 AND a.owner = ?2), 0)
                   LIMIT 2)",
                params![mailbox_id, reader],
                |r| r.get(0),
            )
            .unwrap_or(i64::MAX)
    }

    /// Cumulative ack: moves `acker`'s cursor in the box, then deletes what every active registered reader other than
    /// the depositor has acknowledged (`delete_fully_acked`). The depositor's own ack never deletes its deposit.
    pub fn ack(&self, mailbox_id: &str, through_seq: u64, acker: &[u8]) -> Result<usize, String> {
        // Only a reader that REGISTERED the box can acknowledge.
        let is_reader = self
            .conn
            .query_row(
                "SELECT 1 FROM mailbox_readers WHERE mailbox_id = ?1 AND owner = ?2",
                params![mailbox_id, acker],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or(false);
        if !is_reader {
            return Ok(0);
        }
        // Clamped to what the box holds. An ack of a future seq would otherwise cover every later item too.
        let moved = self
            .conn
            .execute(
                "INSERT INTO mail_acks (mailbox_id, owner, through_seq)
                 VALUES (?1, ?2, MIN(?3, COALESCE((SELECT MAX(seq) FROM mail WHERE mailbox_id = ?1), 0)))
                 ON CONFLICT(mailbox_id, owner) DO UPDATE SET through_seq = excluded.through_seq
                 WHERE excluded.through_seq > mail_acks.through_seq",
                params![mailbox_id, acker, through_seq.min(i64::MAX as u64) as i64],
            )
            .map_err(|e| e.to_string())?;
        // The cursor did not move: nothing new to delete. The delete scans the whole box, and a repeated ack ran it 512
        // times per request.
        if moved == 0 {
            return Ok(0);
        }
        self.delete_fully_acked(mailbox_id)
    }

    /// One `Ack` request: the highest `seq` per box only (each moved cursor runs `delete_fully_acked`), in one
    /// transaction (one commit, not one per entry). Any failure fails the whole request, so the client acks again.
    pub fn ack_many(&self, acks: &[(String, u64)], acker: &[u8]) -> Result<usize, String> {
        let mut top: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        for (mailbox, seq) in acks {
            let e = top.entry(mailbox.as_str()).or_insert(0);
            *e = (*e).max(*seq);
        }
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let mut deleted = 0;
        for (mailbox, seq) in top {
            deleted += self.ack(mailbox, seq, acker)?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(deleted)
    }

    /// Deletes the rows that every registered reader OTHER than the depositor has acknowledged (and at least one of them
    /// really has). A reader that has not acknowledged (for example a stranger registered to the box) keeps the row until
    /// the TTL, but cannot delete someone else's mail.
    pub(super) fn delete_fully_acked(&self, mailbox_id: &str) -> Result<usize, String> {
        self.conn
            .execute(
                "DELETE FROM mail WHERE mailbox_id = ?1
                   AND EXISTS (SELECT 1 FROM mail_acks a
                               WHERE a.mailbox_id = mail.mailbox_id AND a.owner != mail.depositor
                                 AND a.through_seq >= mail.seq)
                   AND NOT EXISTS (SELECT 1 FROM mailbox_readers r
                                   WHERE r.mailbox_id = mail.mailbox_id AND r.owner != mail.depositor
                                     AND EXISTS (SELECT 1 FROM enrollments e
                                                 WHERE e.enrollment_id = r.owner AND e.state = 'active')
                                     AND COALESCE((SELECT a.through_seq FROM mail_acks a
                                                   WHERE a.mailbox_id = r.mailbox_id AND a.owner = r.owner), 0) < mail.seq)",
                params![mailbox_id],
            )
            .map_err(|e| e.to_string())
    }

    /// Deletes expired delivery items. A safety net on top of acks: a recipient that never comes back must not let the box
    /// grow forever. See `ServerRequest::Cancel`: the sender withdraws its OWN undelivered packet. The `depositor = ?3`
    /// condition is critical: you can delete only what you deposited, never someone else's.
    pub fn cancel_own_deposits(&self, mailbox_id: &str, seqs: &[u64], depositor: &[u8]) -> usize {
        let mut removed = 0usize;
        // One commit for the whole request, not one fsync per `seq`.
        let tx = self.conn.unchecked_transaction().ok();
        for seq in seqs {
            removed += self
                .conn
                .execute(
                    "DELETE FROM mail WHERE mailbox_id = ?1 AND seq = ?2 AND depositor = ?3",
                    params![mailbox_id, (*seq).min(i64::MAX as u64) as i64, depositor],
                )
                .unwrap_or(0);
        }
        if let Some(tx) = tx {
            if tx.commit().is_err() {
                return 0;
            }
        }
        removed
    }

    pub fn sweep_expired_mail(&self, now: i64) -> usize {
        // Reader rows of owners whose enrollment was deleted or revoked can no longer acknowledge. `delete_fully_acked` no
        // longer counts them. Re-evaluate the boxes so that waiting mail is released.
        let mut orphaned: Vec<String> = Vec::new();
        if let Ok(mut st) = self.conn.prepare(
            "SELECT DISTINCT mailbox_id FROM mailbox_readers
             WHERE owner NOT IN (SELECT enrollment_id FROM enrollments WHERE state = 'active')",
        ) {
            if let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) {
                orphaned.extend(rows.flatten());
            }
        }
        let _ = self.conn.execute(
            "DELETE FROM mailbox_readers WHERE owner NOT IN (SELECT enrollment_id FROM enrollments WHERE state = 'active')",
            [],
        );
        // Counted in the result, so the caller recounts the depositors' quota.
        let mut removed = 0;
        for mailbox in &orphaned {
            removed += self.delete_fully_acked(mailbox).unwrap_or(0);
        }
        let _ = self.conn.execute(
            "DELETE FROM mail_acks WHERE NOT EXISTS (SELECT 1 FROM mailbox_readers r
                WHERE r.mailbox_id = mail_acks.mailbox_id AND r.owner = mail_acks.owner)",
            [],
        );
        removed
            + self
                .conn
                .execute("DELETE FROM mail WHERE expires_at_ms <= ?1", params![now])
                .unwrap_or(0)
    }

    /// Subtracts the bytes of deleted delivery items from their depositors' quotas. Called after `ack` and
    /// `sweep_expired_mail`. Otherwise the quota only grows, and an active user would get locked out of the server within
    /// a few months.
    pub fn recount_mail_bytes(&self) {
        let _ = self.conn.execute_batch(
            "UPDATE enrollments SET bytes_mail =
                COALESCE((SELECT SUM(byte_len) FROM mail WHERE mail.depositor = enrollments.enrollment_id), 0);",
        );
    }

    /// Drops metadata nobody needs any more: `mail_seq` rows of boxes with no mail and no reader, and enrollments
    /// idle since `idle_before` that own nothing. A pruned box's counter folds into `mail_seq_base`, so a box written
    /// again later starts above every cursor a client may still hold for it. Revoked rows stay (their key is blocked
    /// through them).
    pub fn prune_dead_rows(&self, idle_before: i64) {
        let dead = "SELECT s.mailbox_id FROM mail_seq s
                    WHERE NOT EXISTS (SELECT 1 FROM mail m WHERE m.mailbox_id = s.mailbox_id)
                      AND NOT EXISTS (SELECT 1 FROM mailbox_readers r WHERE r.mailbox_id = s.mailbox_id)";
        let Ok(tx) = self.conn.unchecked_transaction() else { return };
        let top: Option<i64> = self
            .conn
            .query_row(&format!("SELECT MAX(last) FROM mail_seq WHERE mailbox_id IN ({dead})"), [], |r| r.get::<_, Option<i64>>(0))
            .ok()
            .flatten();
        if let Some(top) = top {
            let _ = self.conn.execute(
                "INSERT OR REPLACE INTO meta (k, v) VALUES ('mail_seq_base',
                     MAX(COALESCE((SELECT v FROM meta WHERE k = 'mail_seq_base'), 0), ?1))",
                params![top],
            );
            let _ = self.conn.execute(&format!("DELETE FROM mail_seq WHERE mailbox_id IN ({dead})"), []);
        }
        let _ = self.conn.execute(
            "DELETE FROM enrollments WHERE state = 'active' AND last_seen_at < ?1
               AND NOT EXISTS (SELECT 1 FROM mail WHERE mail.depositor = enrollments.enrollment_id)
               AND NOT EXISTS (SELECT 1 FROM archive WHERE archive.owner = enrollments.enrollment_id)
               AND NOT EXISTS (SELECT 1 FROM blobs WHERE blobs.owner = enrollments.enrollment_id)
               AND NOT EXISTS (SELECT 1 FROM mailbox_readers WHERE mailbox_readers.owner = enrollments.enrollment_id)",
            params![idle_before],
        );
        let _ = tx.commit();
    }

}
