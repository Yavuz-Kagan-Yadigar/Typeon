//! Invites, enrollments and blocked enrollment keys.

use super::*;

impl Store {
    // -----------------------------------------------------------------
    // Invites and enrollment
    // -----------------------------------------------------------------

    /// Creates an invite. `uses <= 0` means UNLIMITED (stored as `-1`).
    ///
    /// Requirement: several people must be able to join from one QR code or link. Before, each new person needed the
    /// operator to send the server a fresh code. Invites were single-use, and the Android server UI pinned them to
    /// `uses=1`. An unlimited invite can be published once (poster, message, web page) and then anyone can join on
    /// their own. The Sybil gate is not lost, it MOVES: the token itself no longer gates, the hourly enrollment cap in
    /// `ServerCore::handle_enroll` (`MAX_PUBLIC_ENROLLMENTS_PER_HOUR`) does, and the operator can rotate the code at
    /// any time (`rotate_join_code`).
    pub fn create_invite(&self, token_hash: &[u8], label: &str, uses: i64, expires_at: i64, now: i64) -> Result<(), String> {
        let uses = if uses <= 0 { -1 } else { uses };
        self.conn
            .execute(
                "INSERT OR REPLACE INTO invites (token_hash, label, uses_left, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![token_hash, label, uses, expires_at, now],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Deletes an invite. `rotate_join_code` uses it to invalidate the old public code.
    pub fn delete_invite(&self, token_hash: &[u8]) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM invites WHERE token_hash = ?1", params![token_hash])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Remaining uses: `Some(-1)` unlimited, `Some(0)` used up, `None` no such invite, or it has expired.
    pub fn invite_uses_left(&self, token_hash: &[u8], now: i64) -> Option<i64> {
        self.conn
            .query_row(
                "SELECT uses_left FROM invites WHERE token_hash = ?1 AND (expires_at = 0 OR expires_at > ?2)",
                params![token_hash, now],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Enrollments opened in (`since`, `now`]: the public code's hourly cap. Rows dated after `now` (the clock was
    /// stepped back) are not counted. They once froze the cap until the clock caught up.
    pub fn count_enrollments_since(&self, since: i64, now: i64) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM enrollments WHERE enrolled_at > ?1 AND enrolled_at <= ?2",
                params![since, now],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Active enrollments seen at or after `idle_before`. A sleeping one (see `sleep_idle_enrollments`) holds no place
    /// under the cap.
    pub fn count_active_enrollments(&self, idle_before: i64) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM enrollments WHERE state = 'active' AND last_seen_at >= ?1",
                params![idle_before],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Like `count_active_enrollments`, for the enrollments that came in with one invite.
    pub fn count_active_enrollments_by_invite(&self, invite_hash: &[u8], idle_before: i64) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM enrollments WHERE invite_hash = ?1 AND state = 'active' AND last_seen_at >= ?2",
                params![invite_hash, idle_before],
                |r| r.get(0),
            )
            .unwrap_or(i64::MAX)
    }

    /// Puts active enrollments last seen before `before` to sleep: their
    /// reader rows go, and mail in boxes nobody reads any more goes with them.
    /// The row, its key and its quota counters stay, so the device comes back
    /// with `Rebind` (or its old PeerId), which refreshes `last_seen_at`.
    /// Returns the mail rows removed; the caller recounts the depositors.
    pub fn sleep_idle_enrollments(&self, before: i64) -> usize {
        let sleepers = "SELECT enrollment_id FROM enrollments WHERE state = 'active' AND last_seen_at < ?1";
        let Ok(tx) = self.conn.unchecked_transaction() else { return 0 };
        // Mail stays while any reader that is awake still has the box.
        let removed = self
            .conn
            .execute(
                &format!(
                    "DELETE FROM mail WHERE mailbox_id IN (SELECT mailbox_id FROM mailbox_readers WHERE owner IN ({sleepers}))
                       AND NOT EXISTS (SELECT 1 FROM mailbox_readers r
                                       WHERE r.mailbox_id = mail.mailbox_id AND r.owner NOT IN ({sleepers})
                                         AND r.owner != mail.depositor
                                         AND r.owner IN (SELECT enrollment_id FROM enrollments WHERE state = 'active'))"
                ),
                params![before],
            )
            .unwrap_or(0);
        let _ = self.conn.execute(&format!("DELETE FROM mailbox_readers WHERE owner IN ({sleepers})"), params![before]);
        let _ = tx.commit();
        removed
    }

    pub fn list_invites(&self, now: i64) -> Vec<(String, i64, i64, bool)> {
        let mut stmt = match self.conn.prepare("SELECT label, uses_left, expires_at FROM invites ORDER BY created_at DESC") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| {
            let label: String = r.get(0)?;
            // `uses_left` is now a signed value: `-1` means unlimited (see `create_invite`). Converting it to `u32`
            // would turn it into about 4 billion.
            let uses: i64 = r.get(1)?;
            let exp: i64 = r.get(2)?;
            Ok((label, uses, exp, uses != 0 && (exp == 0 || exp > now)))
        });
        rows.map(|it| it.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    /// Consumes one use of an invite. Returns `true` if it was valid.
    ///
    /// Decrementing the use counter and creating the enrollment must happen in the SAME call chain. Otherwise two
    /// concurrent `Enroll` requests could spend a single-use token twice. `UPDATE ... WHERE uses_left > 0` is one
    /// atomic statement, so the race is closed at the SQLite level.
    pub fn consume_invite(&self, token_hash: &[u8], now: i64) -> Result<bool, String> {
        let changed = self
            .conn
            .execute(
                // `uses_left = -1` is UNLIMITED: consumed but not decremented (see `create_invite`). The `<> 0` check
                // separates used-up (0) from unlimited (-1) in one expression.
                "UPDATE invites SET uses_left = CASE WHEN uses_left < 0 THEN uses_left ELSE uses_left - 1 END
                 WHERE token_hash = ?1 AND uses_left <> 0 AND (expires_at = 0 OR expires_at > ?2)",
                params![token_hash, now],
            )
            .map_err(|e| e.to_string())?;
        Ok(changed > 0)
    }

    /// Consumes one invite use and writes the enrollment: both or neither. `Ok(false)`: the invite is spent, expired
    /// or gone.
    pub fn enroll_with_invite(&self, token_hash: &[u8], now: i64, e: &Enrollment) -> Result<bool, String> {
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        if !self.consume_invite(token_hash, now)? {
            return Ok(false);
        }
        self.insert_enrollment(e)?;
        self.conn
            .execute("UPDATE enrollments SET invite_hash = ?1 WHERE enrollment_id = ?2", params![token_hash, e.enrollment_id])
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn insert_enrollment(&self, e: &Enrollment) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO enrollments
                 (enrollment_id, enroll_pk, enroll_pk_pq, peer_id, state, enrolled_at, last_seen_at, bytes_mail, bytes_archive, bytes_blob)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    e.enrollment_id, e.enroll_pk, e.enroll_pk_pq, e.peer_id, e.state.as_str(),
                    e.enrolled_at, e.last_seen_at, e.bytes_mail, e.bytes_archive, e.bytes_blob
                ],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn enrollment_by_peer(&self, peer_id: &str) -> Option<Enrollment> {
        self.row_to_enrollment("SELECT enrollment_id, enroll_pk, enroll_pk_pq, peer_id, state, enrolled_at, last_seen_at, bytes_mail, bytes_archive, bytes_blob FROM enrollments WHERE peer_id = ?1", peer_id)
    }

    pub fn enrollment_by_id(&self, enrollment_id: &[u8]) -> Option<Enrollment> {
        self.conn
            .query_row(
                "SELECT enrollment_id, enroll_pk, enroll_pk_pq, peer_id, state, enrolled_at, last_seen_at, bytes_mail, bytes_archive, bytes_blob FROM enrollments WHERE enrollment_id = ?1",
                params![enrollment_id],
                Self::map_enrollment,
            )
            .optional()
            .ok()
            .flatten()
    }

    pub(super) fn row_to_enrollment(&self, sql: &str, key: &str) -> Option<Enrollment> {
        self.conn
            .query_row(sql, params![key], Self::map_enrollment)
            .optional()
            .ok()
            .flatten()
    }

    pub(super) fn map_enrollment(r: &rusqlite::Row) -> rusqlite::Result<Enrollment> {
        let state: String = r.get(4)?;
        Ok(Enrollment {
            enrollment_id: r.get(0)?,
            enroll_pk: r.get(1)?,
            enroll_pk_pq: r.get(2)?,
            peer_id: r.get(3)?,
            state: EnrollmentState::parse(&state),
            enrolled_at: r.get(5)?,
            last_seen_at: r.get(6)?,
            bytes_mail: r.get(7)?,
            bytes_archive: r.get(8)?,
            bytes_blob: r.get(9)?,
        })
    }

    /// `Rebind`: moves an existing enrollment to a new `PeerId`.
    pub fn rebind_enrollment(&self, enrollment_id: &[u8], new_peer_id: &str, now: i64) -> Result<(), String> {
        // If ANOTHER enrollment is already bound to the same PeerId, release it first. `peer_id` is UNIQUE, and the
        // INSERT would otherwise collide (a reinstalled device can regenerate the same libp2p key). The placeholder is
        // unique per row: a shared '' broke the index on the second collision. One transaction: a failed second UPDATE
        // would leave the device unbound.
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "UPDATE enrollments SET peer_id = 'unbound:' || hex(enrollment_id) WHERE peer_id = ?1 AND enrollment_id != ?2",
                params![new_peer_id, enrollment_id],
            )
            .map_err(|e| e.to_string())?;
        let n = self
            .conn
            .execute(
                "UPDATE enrollments SET peer_id = ?1, last_seen_at = ?2 WHERE enrollment_id = ?3",
                params![new_peer_id, now, enrollment_id],
            )
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Record not found".to_string());
        }
        tx.commit().map_err(|e| e.to_string())
    }

    /// Revoke is a block: the enroll key goes on the block list, and the row stays. So `handle_enroll` finds the
    /// blocked key for this PeerId too.
    pub fn revoke_enrollment(&self, enrollment_id: &[u8]) -> Result<(), String> {
        // One transaction: a blocked key with the row still 'active' would leave the device fully served.
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO blocked_keys (enroll_pk, blocked_at)
                 SELECT enroll_pk, CAST(strftime('%s','now') AS INTEGER) * 1000 FROM enrollments WHERE enrollment_id = ?1",
                params![enrollment_id],
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .execute("UPDATE enrollments SET state = 'revoked' WHERE enrollment_id = ?1", params![enrollment_id])
            .map_err(|e| e.to_string())
            .and_then(|n| if n == 0 { Err("Record not found".to_string()) } else { Ok(()) })?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn list_enrollments(&self) -> Vec<Enrollment> {
        let mut stmt = match self.conn.prepare(
            "SELECT enrollment_id, enroll_pk, enroll_pk_pq, peer_id, state, enrolled_at, last_seen_at, bytes_mail, bytes_archive, bytes_blob FROM enrollments ORDER BY enrolled_at",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], Self::map_enrollment)
            .map(|it| it.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    pub fn touch_enrollment(&self, enrollment_id: &[u8], now: i64) {
        let _ = self.conn.execute(
            "UPDATE enrollments SET last_seen_at = ?1 WHERE enrollment_id = ?2",
            params![now, enrollment_id],
        );
    }

    /// Puts an enroll key on the block list: no new enrollment with it. See `revoke_enrollment`, which does the same for
    /// the enrollment's key.
    pub fn block_enrollment_key(&self, enroll_pk: &[u8], now: i64) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO blocked_keys (enroll_pk, blocked_at) VALUES (?1, ?2)",
                params![enroll_pk, now],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn unblock_enrollment_key(&self, enroll_pk: &[u8]) {
        let _ = self
            .conn
            .execute("DELETE FROM blocked_keys WHERE enroll_pk = ?1", params![enroll_pk]);
    }

    pub fn is_key_blocked(&self, enroll_pk: &[u8]) -> bool {
        self.conn
            .query_row("SELECT 1 FROM blocked_keys WHERE enroll_pk = ?1", params![enroll_pk], |_| Ok(true))
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

}
