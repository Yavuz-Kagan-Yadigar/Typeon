//! Blob upload, hashing and chunk serving.

use super::*;

impl ServerCore {
    // -----------------------------------------------------------------
    // Blobs
    // -----------------------------------------------------------------

    pub(super) fn blob_path(&self, blob_id: &str) -> PathBuf {
        // `blob_id` comes from the client. It must be checked as hex/alphanumeric BEFORE it is used as a file path.
        // Otherwise `../` could write outside the directory.
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
        // Before any row exists: `total_chunks: 0` used to mint a free row per request.
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
        // Quotas used to be applied only per record. The budget is split by a fixed `EXPECTED_DEVICES = 8`, so with
        // 20 devices enrolled the real ceiling was 2.5 times the budget. Disk-full on a tablet is exactly what this
        // mechanism exists to prevent. The total is checked now too.
        if self.total_budget_exceeded(growth as usize, false) {
            warn!("Total disk budget full, blob chunk rejected");
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Ownership: only the record that started a blob may write to it. A row is created only for an id nobody
        // holds. The second read also covers a first attempt that failed (busy DB), which used to skip this check.
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
        // A verified blob is final. Another chunk (or a new stride) would let `serve_chunk` hand out bytes the hash
        // never covered.
        if state.complete {
            return ServerResponse::Ok;
        }
        if chunk_index >= state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // The stride is fixed by the first chunk (`blob_set_chunk_size`). Another one would write where `serve_chunk`
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

        // Positional write, not an append. Appending required chunks to arrive strictly in order. The client could
        // then send only one chunk at a time, and throughput was limited to chunk/round-trip. A 10 MB upload measured
        // about 12 KB/s over Tor. The `.enc` format has a fixed stride (see `attachments::read_chunk_from_disk`), so
        // writing at an offset is safe.
        use std::io::{Seek, SeekFrom, Write};
        // The stride is stored WITH the blob. `serve_chunk` must read with the same value.
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
    /// truncated upload. A blob can be up to `max_blob_bytes` (GiBs). Inside the event loop it stalled every client
    /// for the duration.
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

    /// Serves a file chunk.
    ///
    /// The server counterpart of `serve_chunk_request` in the core. It is deliberately almost identical:
    /// `read_chunk_from_disk` reads the `.enc` file AS IT IS, because the disk format is the wire format. The server
    /// encrypts, decrypts and re-frames nothing.
    pub(super) fn serve_chunk(
        &mut self,
        peer: PeerId,
        req: FileChunkRequest,
        channel: ResponseChannel<FileChunkResponse>,
    ) {
                // This path is entirely separate from `handle_request`. It is a distinct request_response behaviour, called
                // straight from `handle_swarm_event`, and it used to sit outside the enrollment check (`authenticate`). So ANY peer
                // speaking this protocol, including an unenrolled stranger in node mode, could fetch chunks as soon as it knew or
                // guessed a `blob_id`. The bytes are encrypted with `file_key`, so content did not leak directly. But the
                // `NotFound` / `Chunk` split answered "does this file exist on the server" as an oracle, and it let a stranger
                // cause unlimited disk and CPU work. The core had the same problem (`may_serve_file_to`), which was closed earlier.
                // The server counterpart had been missed.
                //
                // Legitimate clients are not affected. `ready_server_peers` (client) uses a server as a source only when it is
                // `connected && enrolled`, so a download always arrives here with an enrolled `PeerId`.
                //
                // Rate limit: its own budget (`CHUNKS_PER_MINUTE`, 10/s), separate from the RPC budget. Tor carries about one
                // chunk a second, so only a request loop reaches it. An enrolled peer over budget gets `Busy` (back off, same
                // source). An unenrolled one gets `NotFound`.
        // The rate check first, for every peer: it is in memory, while the enrollment lookup is a query. Refusals log at
        // debug only, or a request loop fills the journal.
        let reply = if !self.check_rate(peer, true, 1) {
            Some(FileChunkResponse::Busy)
        } else if self.active(peer).is_none() {
            Some(FileChunkResponse::NotFound)
        } else {
            None
        };
        if let Some(reply) = reply {
            debug!("File chunk request rejected (rate limit or unregistered peer)");
            self.stats.rejected += 1;
            let _ = self.swarm.behaviour_mut().file_chunks.send_response(channel, reply);
            return;
        }
        let response = if !is_safe_id(&req.file_id) {
            FileChunkResponse::NotFound
        } else {
            match self.store.blob_state(&req.file_id) {
                Some(state) if state.complete => {
                    // Once per download keeps the blob alive. Once per chunk was a DB write for each of thousands of chunks.
                    if req.chunk_index == 0 {
                        self.store.blob_touch(&req.file_id, now_ms());
                    }
                    // This branch used to call `read_chunk_from_disk` with a fixed 256 KiB stride. `handle_blob_put`
                    // takes the stride FROM THE CLIENT (`BlobPut.chunk_size`) and writes by it. The moment the two
                    // diverged, every blob was read from the wrong offsets. That is the same bug that had spoiled a
                    // speed measurement. The stride is now stored with the blob.
                    match attachments::read_chunk_from_disk_with(
                        &self.blob_path(&req.file_id),
                        req.chunk_index,
                        state.chunk_size as usize,
                    ) {
                        Ok(Some(data)) => {
                            self.stats.blob_chunks_served += 1;
                            FileChunkResponse::Chunk { data }
                        }
                        _ => FileChunkResponse::NotFound,
                    }
                }
                // A partial upload is NEVER served. When the client sees `NotFound`, it switches to another source
                // immediately (see `handle_chunk_response`, which deliberately does not retry).
                _ => FileChunkResponse::NotFound,
            }
        };
        let _ = self.swarm.behaviour_mut().file_chunks.send_response(channel, response);
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
