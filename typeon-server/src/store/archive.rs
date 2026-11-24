//! History archive buckets: put, probe, fetch, purge, expiry.

use super::*;

impl Store {
    /// Deletes archive rows not written for `ARCHIVE_TTL_MS`. Quotas are recounted.
    pub fn sweep_expired_archive(&self, now: i64) -> usize {
        let cutoff = now - ARCHIVE_TTL_MS;
        let mut owners: Vec<Vec<u8>> = Vec::new();
        if let Ok(mut st) = self.conn.prepare("SELECT DISTINCT owner FROM archive WHERE updated_at < ?1") {
            if let Ok(rows) = st.query_map(params![cutoff], |r| r.get::<_, Vec<u8>>(0)) {
                owners.extend(rows.flatten());
            }
        }
        let n = self.conn.execute("DELETE FROM archive WHERE updated_at < ?1", params![cutoff]).unwrap_or(0);
        if n > 0 {
            self.recount_archive_bytes(&owners);
        }
        n
    }

    // -----------------------------------------------------------------
    // Archive
    // -----------------------------------------------------------------

    /// Stores or overwrites records.
    ///
    /// `WHERE excluded.rev > archive.rev`: an edit or delete carries the SAME `record_id` and overwrites the old row with a
    /// higher `rev`. The same rule also collapses N devices uploading the same record into one row.
    ///
    /// The last writer becomes `owner` and pays for the row (see `archive_row_bytes`).
    pub fn archive_put(&self, bucket: &str, records: &[ArchiveRecord], owner: &[u8], now: i64) -> Result<u64, String> {
        let mut newest = 0u64;
        // One transaction: one WAL commit per batch, all or nothing. The charge moves by the delta of each row written, in
        // the same transaction. A `SUM` over all of the writer's rows per request would be a full scan on the event loop.
        // The sweep recounts.
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        for rec in records {
            // Skipped, not refused: the client drops what was answered `Ok`. One over-long id must not block its archive
            // queue.
            if rec.record_id.len() > 128 {
                continue;
            }
            let old = self.conn.query_row(
                "SELECT owner, byte_len FROM archive WHERE bucket = ?1 AND record_id = ?2",
                params![bucket, rec.record_id],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
            ).ok();
            let bytes = archive_row_bytes(rec) as i64;
            let written = self.conn
                .execute(
                    "INSERT INTO archive (bucket, record_id, rev, sent_at_ms, sealed, byte_len, owner, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(bucket, record_id) DO UPDATE SET
                        rev = excluded.rev, sent_at_ms = excluded.sent_at_ms,
                        sealed = excluded.sealed, byte_len = excluded.byte_len,
                        owner = excluded.owner, updated_at = excluded.updated_at
                     WHERE excluded.rev > archive.rev",
                    params![bucket, rec.record_id, rec.rev.min(i64::MAX as u64) as i64, rec.sent_at_ms.min(i64::MAX as u64) as i64, rec.sealed, bytes, owner, now],
                )
                .map_err(|e| e.to_string())?;
            if written > 0 {
                if let Some((old_owner, old_bytes)) = &old {
                    self.conn
                        .execute(
                            "UPDATE enrollments SET bytes_archive = MAX(0, bytes_archive - ?1) WHERE enrollment_id = ?2",
                            params![old_bytes, old_owner],
                        )
                        .map_err(|e| e.to_string())?;
                }
                self.conn
                    .execute(
                        "UPDATE enrollments SET bytes_archive = bytes_archive + ?1 WHERE enrollment_id = ?2",
                        params![bytes, owner],
                    )
                    .map_err(|e| e.to_string())?;
            }
            newest = newest.max(rec.rev);
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(newest)
    }

    /// Only the owners whose rows changed are recounted (an overwrite or purge changes what another enrollment is charged).
    /// Recounting every enrollment would scan the whole archive on each request.
    pub(super) fn recount_archive_bytes(&self, owners: &[Vec<u8>]) {
        for owner in owners {
            let _ = self.conn.execute(
                "UPDATE enrollments SET bytes_archive =
                    COALESCE((SELECT SUM(byte_len) FROM archive WHERE archive.owner = ?1), 0)
                 WHERE enrollment_id = ?1",
                params![owner],
            );
        }
    }

    pub fn archive_probe(&self, buckets: &[String]) -> Vec<BucketStat> {
        let mut out = Vec::new();
        // A repeated id is one scan, and the count stops at a cap: full scans of a large bucket would hold the event
        // loop. MIN and MAX come from `idx_archive_page`.
        let mut seen = std::collections::HashSet::new();
        for b in buckets {
            if !seen.insert(b.as_str()) {
                continue;
            }
            let row = self.conn.query_row(
                "SELECT (SELECT COUNT(*) FROM (SELECT 1 FROM archive WHERE bucket = ?1 LIMIT 65536)),
                        COALESCE((SELECT MIN(sent_at_ms) FROM archive WHERE bucket = ?1), 0),
                        COALESCE((SELECT MAX(sent_at_ms) FROM archive WHERE bucket = ?1), 0)",
                params![b],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            );
            if let Ok((count, oldest, newest)) = row {
                if count > 0 {
                    out.push(BucketStat {
                        bucket: b.clone(),
                        count: count as u32,
                        oldest_ms: oldest as u64,
                        newest_ms: newest as u64,
                    });
                }
            }
        }
        out
    }

    /// Pages backwards, newest first. `before: None` returns the newest page.
    ///
    /// The cursor is the last record the client received, `(sent_at_ms, record_id)`. Clients send `sent_at_ms` floored to
    /// the hour, so many records share one value, and a page can end inside such a group.
    pub fn archive_fetch(&self, bucket: &str, before: Option<(u64, &str)>, max_items: u32, max_bytes: u32) -> (Vec<ArchiveRecord>, bool) {
        let (before_ms, before_id) = match before {
            Some((ms, id)) => (ms.min(i64::MAX as u64) as i64, id),
            None => (i64::MAX, ""),
        };
        let mut stmt = match self.conn.prepare(
            "SELECT record_id, rev, sent_at_ms, sealed FROM archive
             WHERE bucket = ?1 AND (sent_at_ms < ?2 OR (sent_at_ms = ?2 AND record_id < ?3))
             ORDER BY sent_at_ms DESC, record_id DESC",
        ) {
            Ok(s) => s,
            Err(_) => return (Vec::new(), false),
        };
        let rows = stmt.query_map(params![bucket, before_ms, before_id], |r| {
            Ok(ArchiveRecord {
                record_id: r.get(0)?,
                rev: r.get::<_, i64>(1)? as u64,
                sent_at_ms: r.get::<_, i64>(2)? as u64,
                sealed: r.get(3)?,
            })
        });
        let Ok(rows) = rows else { return (Vec::new(), false) };

        let mut out: Vec<ArchiveRecord> = Vec::new();
        let mut total = 0usize;
        for rec in rows.flatten() {
            // `!out.is_empty()`: the first record always goes out. Otherwise one record over `max_bytes` would hide
            // everything older in its bucket.
            if !out.is_empty() && (out.len() as u32 >= max_items || total + rec.sealed.len() > max_bytes as usize) {
                return (out, true);
            }
            total += rec.sealed.len();
            out.push(rec);
        }
        (out, false)
    }

    /// Deletes whole buckets, whoever uploaded the rows. The bucket id is the capability, as it is for `archive_fetch` and
    /// for overwriting a record. A chat deleted on one linked device is deleted for all of them.
    pub fn archive_purge(&self, buckets: &[String]) -> usize {
        let mut n = 0;
        let mut owners: Vec<Vec<u8>> = Vec::new();
        for b in buckets {
            if let Ok(mut st) = self.conn.prepare("SELECT DISTINCT owner FROM archive WHERE bucket = ?1") {
                if let Ok(rows) = st.query_map(params![b], |r| r.get::<_, Vec<u8>>(0)) {
                    for o in rows.flatten() {
                        if !owners.contains(&o) {
                            owners.push(o);
                        }
                    }
                }
            }
            n += self.conn.execute("DELETE FROM archive WHERE bucket = ?1", params![b]).unwrap_or(0);
        }
        self.recount_archive_bytes(&owners);
        n
    }

}
