//! Blob (attachment) storage bookkeeping.

use super::*;

impl Store {
    /// See the note on the upload stride: it is fixed by the first chunk.
    pub fn blob_set_chunk_size(&self, blob_id: &str, chunk_size: u32) {
        let _ = self.conn.execute(
            "UPDATE blobs SET chunk_size = ?2 WHERE blob_id = ?1 AND chunk_size = 0",
            params![blob_id, chunk_size as i64],
        );
    }

    // -----------------------------------------------------------------
    // Blob (file attachment)
    // -----------------------------------------------------------------

    pub fn blob_begin(&self, blob_id: &str, owner: &[u8], total_chunks: u32, now: i64) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO blobs (blob_id, owner, total_chunks, received_chunks, byte_len, complete, created_at, last_served_at)
                 VALUES (?1, ?2, ?3, 0, 0, 0, ?4, ?4)
                 ON CONFLICT(blob_id) DO NOTHING",
                params![blob_id, owner, total_chunks as i64, now],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Has this chunk arrived before? (Retransmission is possible in the pipeline.)
    pub fn blob_has_chunk(&self, blob_id: &str, chunk_index: u32) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM blob_chunks WHERE blob_id = ?1 AND chunk_index = ?2",
                params![blob_id, chunk_index as i64],
                |_| Ok(true),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    pub fn blob_record_chunk(&self, blob_id: &str, chunk_index: u32, len: usize) -> Result<(), String> {
        // `received_chunks` is a COUNT of distinct chunks, not a high-water mark. Chunks may arrive out of order (the
        // pipeline can have several `BlobPut`s in flight), and a re-sent chunk must not advance the count.
        // Chunk recording is idempotent: if the same index arrives again (connection dropped, client re-sent), neither the
        // count nor the bytes go up twice.
        let inserted = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO blob_chunks (blob_id, chunk_index, byte_len) VALUES (?1, ?2, ?3)",
                params![blob_id, chunk_index as i64, len as i64],
            )
            .map_err(|e| e.to_string())?;
        if inserted == 0 {
            return Ok(());
        }
        // A new distinct chunk (the insert above took): one more. A COUNT(*) here scanned every earlier chunk row, O(n^2)
        // over an upload.
        self.conn
            .execute(
                "UPDATE blobs SET byte_len = byte_len + ?2, received_chunks = received_chunks + 1
                 WHERE blob_id = ?1",
                params![blob_id, len as i64],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Returns `Err` also when no row matched (gone, or chunks missing). The caller must not answer `Ok` for a blob that
    /// will never be served.
    pub fn blob_finish(&self, blob_id: &str, enc_sha256: &[u8], now: i64) -> Result<(), String> {
        let n = self
            .conn
            .execute(
                "UPDATE blobs SET complete = 1, enc_sha256 = ?2, last_served_at = ?3
                 WHERE blob_id = ?1 AND received_chunks >= total_chunks",
                params![blob_id, enc_sha256, now],
            )
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Blob not completed (missing chunk or row)".to_string());
        }
        Ok(())
    }

    pub fn blob_state(&self, blob_id: &str) -> Option<BlobState> {
        self.conn
            .query_row(
                "SELECT blob_id, owner, total_chunks, received_chunks, byte_len, complete, chunk_size FROM blobs WHERE blob_id = ?1",
                params![blob_id],
                |r| {
                    Ok(BlobState {
                        blob_id: r.get(0)?,
                        owner: r.get(1)?,
                        total_chunks: r.get::<_, i64>(2)? as u32,
                        received_chunks: r.get::<_, i64>(3)? as u32,
                        byte_len: r.get(4)?,
                        complete: r.get::<_, i64>(5)? != 0,
                        chunk_size: r.get::<_, i64>(6)?.max(0) as u32,
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn blob_touch(&self, blob_id: &str, now: i64) {
        let _ = self.conn.execute("UPDATE blobs SET last_served_at = ?2 WHERE blob_id = ?1", params![blob_id, now]);
    }

    /// `true` if `owner` owned the blob. The caller then removes the file.
    pub fn blob_delete(&self, blob_id: &str, owner: &[u8]) -> bool {
        let owned = self.blob_state(blob_id).map_or(false, |s| s.owner == owner);
        if owned {
            self.blob_forget(blob_id);
        }
        owned
    }

    /// Returns the blob ids to delete. The caller removes the files.
    ///
    /// Two rules. Completed blobs live for `blob_ttl_ms` after their LAST SERVE, so a file still being downloaded keeps
    /// living. Unfinished uploads are dropped 24 hours after their last chunk (`blob_touch` per chunk).
    pub fn blobs_to_gc(&self, now: i64, ttl_ms: i64) -> Vec<String> {
        let mut stmt = match self.conn.prepare(
            "SELECT blob_id FROM blobs
             WHERE (complete = 1 AND last_served_at + ?1 <= ?2)
                OR (complete = 0 AND last_served_at + 86400000 <= ?2)
             LIMIT 512",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![ttl_ms, now], |r| r.get::<_, String>(0))
            .map(|it| it.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    /// The one way a blob leaves the DB. It refunds the owner exactly the bytes charged (`byte_len`, not the file length:
    /// a sparse file is far longer than what was paid for), and drops the chunk rows with the blob row.
    pub fn blob_forget(&self, blob_id: &str) {
        let _ = self.conn.execute(
            "UPDATE enrollments SET bytes_blob = MAX(0, bytes_blob - (SELECT byte_len FROM blobs WHERE blob_id = ?1))
             WHERE enrollment_id = (SELECT owner FROM blobs WHERE blob_id = ?1)",
            params![blob_id],
        );
        // Chunk rows first: a crash between the two leaves a blob row without chunks (swept later), never stale chunk
        // rows that a new blob with the same id would inherit.
        let _ = self.conn.execute("DELETE FROM blob_chunks WHERE blob_id = ?1", params![blob_id]);
        let _ = self.conn.execute("DELETE FROM blobs WHERE blob_id = ?1", params![blob_id]);
    }

    /// Blob rows (files on disk) that `owner` holds.
    pub fn blob_count(&self, owner: &[u8]) -> i64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM blobs WHERE owner = ?1", params![owner], |r| r.get(0))
            .unwrap_or(i64::MAX)
    }

    // -----------------------------------------------------------------
    // Quota
    // -----------------------------------------------------------------

    /// Blob charge = what the rows record. Undoes a charge whose chunk row failed to write (see `handle_blob_put`).
    pub fn recount_blob_bytes(&self) {
        let _ = self.conn.execute_batch(
            "UPDATE enrollments SET bytes_blob =
                COALESCE((SELECT SUM(byte_len) FROM blobs WHERE blobs.owner = enrollments.enrollment_id), 0);",
        );
    }

    pub fn add_blob_bytes(&self, owner: &[u8], delta: i64) {
        let _ = self.conn.execute(
            "UPDATE enrollments SET bytes_blob = MAX(0, bytes_blob + ?1) WHERE enrollment_id = ?2",
            params![delta, owner],
        );
    }

}
