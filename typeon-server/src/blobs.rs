//! Blob upload, hashing and chunk serving.

use super::*;

impl ServerCore {
    // -----------------------------------------------------------------
    // Blobs
    // -----------------------------------------------------------------

    pub(super) fn blob_path(&self, blob_id: &str) -> PathBuf {
        // `blob_id` comes from the client. Callers check it with `is_safe_id` first; `sanitize_id` keeps a
        // `../` out of the path.
        self.config.blob_dir.join(format!("{}.enc", sanitize_id(blob_id)))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_blob_put(
        &mut self,
        e: &Enrollment,
        limits: &ServerLimits,
        blob_id: String,
        chunk_index: u32,
        total_chunks: u32,
        chunk_size: u32,
        data: Vec<u8>,
        now: i64,
    ) -> ServerResponse {
        if !is_safe_id(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if data.len() > server_proto::MAX_BLOB_CHUNK_BYTES
            || chunk_size as u64 + 16 > server_proto::MAX_BLOB_CHUNK_BYTES as u64
        {
            return ServerResponse::Err(ServerErrorCode::TooLarge);
        }
        // Checked before any row exists: a `total_chunks` of 0 would otherwise mint a row per request.
        if chunk_index >= total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // The offset comes from the client's `chunk_index` and `chunk_size`. Left unbounded, a 1-byte chunk at a
        // huge offset would extend the file by terabytes. Only 1 byte would be charged, and on a filesystem without
        // sparse file support the disk would fill. The end of the file must not exceed the device's blob quota.
        let stride = if chunk_size == 0 { attachments::FILE_CHUNK_SIZE as u64 } else { chunk_size as u64 };
        let offset = chunk_index as u64 * (stride + 16);
        if offset + data.len() as u64 > limits.max_blob_bytes {
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Charged: how far this write extends the file, not `data.len()`. A 1-byte chunk at a far offset allocates
        // the whole gap on a volume without sparse files (an SD card), and would cost only 1 byte of quota.
        let path = self.blob_path(&blob_id);
        let file_len = std::fs::metadata(&path).map_or(0, |m| m.len());
        // Only a pipeline's depth past the end. Further out, one tiny chunk would charge (and on a volume without sparse
        // files, write) gigabytes of gap in one request.
        if offset > file_len + BLOB_PUT_AHEAD_CHUNKS * (stride + 16) {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // At least one row's worth: a 0-byte chunk still costs a DB row (and, for a new blob, a file).
        let growth = (offset + data.len() as u64).saturating_sub(file_len).max(BLOB_CHUNK_MIN_CHARGE);
        if e.bytes_blob.max(0) as u64 + growth > limits.max_blob_bytes {
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // The per-device quota alone is not enough: the shares together can exceed the disk. The total budget is
        // checked here as well.
        if self.total_budget_exceeded(growth as usize, false) {
            warn!("Total disk budget full, blob chunk rejected");
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Ownership: only the record that started a blob may write to it. A row is created only for an id nobody
        // holds. The second read also covers a first attempt whose insert failed (busy DB).
        if self.store.blob_state(&blob_id).is_none() {
            // Bytes are capped above. This caps files (inodes) and rows.
            if self.store.blob_count(&e.enrollment_id) >= MAX_BLOBS_PER_ENROLLMENT {
                return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
            }
            if let Err(msg) = self.store.blob_begin(&blob_id, &e.enrollment_id, total_chunks, now) {
                error!("blob_begin: {msg}");
                return ServerResponse::Err(ServerErrorCode::Internal);
            }
        }
        let Some(state) = self.store.blob_state(&blob_id) else {
            return ServerResponse::Err(ServerErrorCode::Internal);
        };
        if state.owner != e.enrollment_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // A verified blob is final. Another chunk (or a new stride) would let `serve_blob_get` hand out bytes the hash
        // never covered.
        if state.complete {
            return ServerResponse::Ok;
        }
        if chunk_index >= state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // The stride is fixed by the first chunk (`blob_set_chunk_size`). Another one would write where `serve_blob_get`
        // does not read.
        if (state.chunk_size != 0 || state.received_chunks > 0) && state.chunk_size != chunk_size {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // Same reason while `BlobFinish` is hashing the file.
        if self.blob_hashing.contains_key(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        // Already written: a repeat of the same chunk is idempotent.
        if self.store.blob_has_chunk(&blob_id, chunk_index) {
            return ServerResponse::Ok;
        }

        // Positional write, not an append. An append would force chunks to arrive strictly in order, so the client
        // could only send one chunk per round trip. The `.enc` format has a fixed stride (see
        // `attachments::read_chunk_from_disk`), so writing at an offset is safe.
        use std::io::{Seek, SeekFrom, Write};
        // The stride is stored WITH the blob. `serve_blob_get` must read with the same value.
        self.store.blob_set_chunk_size(&blob_id, chunk_size);
        let write = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .and_then(|mut f| {
                f.seek(SeekFrom::Start(offset))?;
                f.write_all(&data)
            });
        if let Err(err) = write {
            error!("Blob could not be written: {err}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        // The bytes are on disk, so they are charged even if the bookkeeping below fails. The resent chunk then grows
        // nothing and pays only the minimum. Such a failure over-charges the owner by `growth` until the next sweep's
        // `recount_blob_bytes`.
        self.store.add_blob_bytes(&e.enrollment_id, growth as i64);
        self.note_total_written(growth as usize);
        // An upload in progress is not garbage (see `Store::blobs_to_gc`).
        self.store.blob_touch(&blob_id, now);
        if let Err(msg) = self.store.blob_record_chunk(&blob_id, chunk_index, growth as usize) {
            error!("blob_record_chunk: {msg}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        ServerResponse::Ok
    }

    pub(super) fn handle_blob_finish(
        &mut self,
        e: &Enrollment,
        blob_id: String,
        total_chunks: u32,
        enc_sha256: Vec<u8>,
    ) -> ServerResponse {
        if !is_safe_id(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // Row gone (swept after a long offline spell): the client starts over.
        let Some(state) = self.store.blob_state(&blob_id) else {
            return ServerResponse::Err(ServerErrorCode::BlobIncomplete);
        };
        if state.owner != e.enrollment_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if state.complete {
            return ServerResponse::Ok;
        }
        // The stored count is the upload's. The client's own number only has to agree with it.
        if total_chunks != state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if state.received_chunks < state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BlobIncomplete);
        }
        if !self.blob_hashing.contains_key(&blob_id) && self.blob_hashing.len() >= MAX_HASH_JOBS {
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        // Placeholder: the caller sees `hash_job` and answers through `start_blob_hash` and `finish_blob_hash` instead.
        self.hash_job = Some((blob_id, enc_sha256));
        ServerResponse::Ok
    }

    /// Hashes the ENCRYPTED bytes on the blocking pool. The server cannot read the content, but it never serves a
    /// truncated upload. A blob can be up to `max_blob_bytes` (GiBs), so the hash must not run in the event loop.
    pub(super) fn start_blob_hash(&mut self, blob_id: String, enc_sha256: Vec<u8>, channel: ResponseChannel<ServerResponse>) {
        let waiters = self.blob_hashing.entry(blob_id.clone()).or_default();
        if waiters.len() >= MAX_HASH_WAITERS {
            let busy = ServerResponse::Err(ServerErrorCode::RateLimited);
            let _ = self.swarm.behaviour_mut().server_rpc.send_response(channel, busy);
            return;
        }
        waiters.push(channel);
        // A repeated `BlobFinish` waits for the running hash and starts none.
        if waiters.len() > 1 {
            return;
        }
        let path = self.blob_path(&blob_id);
        let tx = self.hash_tx.clone();
        tokio::spawn(async move {
            let hashed = tokio::task::spawn_blocking(move || hash_file_streaming(&path)).await.ok().flatten();
            let _ = tx.send((blob_id, enc_sha256, hashed));
        });
    }

    pub(super) fn finish_blob_hash(&mut self, (blob_id, enc_sha256, hashed): HashDone) {
        let response = match hashed {
            Some(actual) if actual == enc_sha256 => match self.store.blob_finish(&blob_id, &enc_sha256, now_ms()) {
                Ok(()) => ServerResponse::Ok,
                Err(msg) => {
                    error!("blob_finish: {msg}");
                    ServerResponse::Err(ServerErrorCode::Internal)
                }
            },
            Some(_) => {
                warn!("Blob hash mismatch, rejected: {}…", blob_id.get(..6).unwrap_or(""));
                self.drop_blob(&blob_id);
                ServerResponse::Err(ServerErrorCode::BadHash)
            }
            // Unreadable file: the same finish fails the same way.
            None => {
                warn!("Blob could not be read, rejected: {}…", blob_id.get(..6).unwrap_or(""));
                self.drop_blob(&blob_id);
                ServerResponse::Err(ServerErrorCode::BadHash)
            }
        };
        for channel in self.blob_hashing.remove(&blob_id).unwrap_or_default() {
            let _ = self.swarm.behaviour_mut().server_rpc.send_response(channel, response.clone());
        }
    }

    /// Removes a blob file, then its row and charge. If the file cannot be removed, it keeps its row and charge
    /// (the next GC tries again). Refunding it would let files outside every budget grow.
    pub(super) fn drop_blob(&self, blob_id: &str) {
        match std::fs::remove_file(self.blob_path(blob_id)) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                warn!("Blob file could not be deleted ({}…): {err}", blob_id.get(..6).unwrap_or(""));
            }
            _ => self.store.blob_forget(blob_id),
        }
    }

    /// `BlobGet`: serves one file chunk to any peer, enrolled or not. It comes on the client's anonymous connection
    /// (throwaway PeerId), so the server cannot tell which enrollment downloads an upload. The file id is the
    /// authorisation: a hash of the uploader's secret, known only to the file's recipients.
    ///
    /// `read_chunk_from_disk_with` reads the `.enc` file AS IT IS, because the disk format is the wire format. The
    /// server encrypts, decrypts and re-frames nothing.
    ///
    /// Limits: `CHUNKS_PER_MINUTE` per connection, and one global bucket for all chunk requests together
    /// (`CHUNK_BUCKET_CAP`), since PeerIds are free. Both run before any disk read. The global bucket is taken only for
    /// a file that exists: requests for unknown ids would otherwise use it up and stop every real download. Refusals
    /// log at debug only, so a request loop does not fill the journal.
    pub(super) fn serve_blob_get(&mut self, peer: PeerId, file_id: String, chunk_index: u32) -> ServerResponse {
        if !self.check_rate(peer, true, 1) {
            debug!("File chunk request rejected (rate limit)");
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        if !is_safe_id(&file_id) {
            return ServerResponse::Err(ServerErrorCode::NotFound);
        }
        // A partial upload is never served. On `NotFound` the client switches to another source at once
        // (see `handle_chunk_response` in the core).
        let Some(state) = self.store.blob_state(&file_id).filter(|s| s.complete) else {
            return ServerResponse::Err(ServerErrorCode::NotFound);
        };
        if !anon_bucket_take_with(&mut self.chunk_bucket, mono_ms(), CHUNK_BUCKET_CAP, CHUNK_REFILL_PER_MS) {
            debug!("File chunk request rejected (server-wide chunk budget)");
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        // Touched once per download (chunk 0), not once per chunk, which would be a DB write per chunk.
        if chunk_index == 0 {
            self.store.blob_touch(&file_id, now_ms());
        }
        // The stride is the one `handle_blob_put` stored with the blob (from `BlobPut.chunk_size`). A fixed
        // stride here would read from the wrong offsets.
        match attachments::read_chunk_from_disk_with(&self.blob_path(&file_id), chunk_index, state.chunk_size as usize) {
            Ok(Some(data)) => {
                self.stats.blob_chunks_served += 1;
                // A download in progress keeps its anonymous connection (see `UNENROLLED_GRACE_MS`).
                if let Some(c) = self.conns.get_mut(&peer) {
                    c.last_anon_at = mono_ms();
                }
                ServerResponse::Chunk { data }
            }
            _ => ServerResponse::Err(ServerErrorCode::NotFound),
        }
    }

}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hashes a file with SHA-256 without loading it fully into memory.
pub(super) fn hash_file_streaming(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    // The chunks were written without a sync. The blob is marked complete right after this hash, so its bytes must
    // be on disk first, or a power loss leaves a "verified" blob of zeros.
    if let Err(err) = file.sync_data() {
        warn!("Blob could not be synced: {err}");
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().to_vec())
}
