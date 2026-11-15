//! Attachment (blob) uploads to the server.

use super::*;

impl P2PCore {
    /// A queued blob upload that a server can take now: a routing server, connected, enrolled, and not in deposit
    /// backoff.
    pub(crate) fn blob_upload_can_run(&self) -> bool {
        let now = mono_ms();
        !self.server_blob_uploads.is_empty()
            && self.servers.iter().any(|s| {
                s.route_messages
                    && self.server_rt.get(&s.server_id).map_or(false, |r| r.connected && r.enrolled && now >= r.deposit_backoff_until)
            })
    }

}

// ---------------------------------------------------------------------------
// File attachments
// ---------------------------------------------------------------------------
//
// Nothing for DOWNLOADS lives here, on purpose. The server serves the `/p2pmessenger/filexfer/1.0.0` protocol that clients
// already speak, so an attachment on the server is just another source peer. The existing download state machine (sequential
// chunks, `append_verified_chunk`, `alt_source_peer_ids` rotation, `retry_or_give_up_download`, whole-file SHA-256 check)
// runs unchanged. Only UPLOADS are new, because filexfer has no upload verb.

impl P2PCore {
    /// The secret a file's server blob is uploaded with. Its hash (`server_proto::blob_id_for_upload_secret`) is the file ID.
    /// Derived from the local history key and `file_key`. Recipients hold `file_key` but not the history key, so they cannot
    /// claim the blob first. It starts with `tag` (the author tag, `group_msg_tag`), which the ID shows in the clear.
    pub(crate) fn blob_upload_secret(&self, file_key: &[u8; 32], tag: &[u8]) -> Option<Vec<u8>> {
        if tag.len() != server_proto::BLOB_TAG_LEN {
            return None;
        }
        let key = self.history_key.as_ref()?;
        let hash = Sha256::new_with_prefix(b"typeon-blob-upload-v1").chain_update(key).chain_update(file_key).finalize();
        let mut secret = tag.to_vec();
        secret.extend_from_slice(&hash[..server_proto::BLOB_UPLOAD_SECRET_LEN - server_proto::BLOB_TAG_LEN]);
        Some(secret)
    }

    /// Queues an encrypted file for upload to the server.
    pub(crate) fn queue_blob_upload(&mut self, file_id: &str, file_key: &[u8; 32], total_chunks: u32) {
        if !self.servers.iter().any(|s| s.route_messages) {
            return;
        }
        if self.server_blob_uploads.iter().any(|u| u.file_id == file_id) {
            return;
        }
        // The tag is the first 16 hex characters of the ID (`blob_id_for_upload_secret`).
        let Some(tag) = file_id.get(..server_proto::BLOB_TAG_LEN * 2).and_then(|t| hex::decode(t).ok()) else { return };
        let Some(upload_secret) = self.blob_upload_secret(file_key, &tag) else { return };
        // A file ID that is not the hash of this secret (one not made by `begin_outgoing_file`) cannot be uploaded under its own name.
        if server_proto::blob_id_for_upload_secret(&upload_secret).as_deref() != Some(file_id) {
            return;
        }
        let up = PendingBlobUpload {
            file_id: file_id.to_string(),
            upload_secret,
            next_chunk: 0,
            total_chunks,
            // The hash of the encrypted bytes is computed in `sha256_file` at `BlobFinish` time, so the file is not read through
            // once more here. (A struct field existed for it, but was never written, only read from disk and dropped, so it was
            // removed. The `server_blob_uploads.enc_sha256` column stays for schema compatibility, and is written empty.)
            inflight: HashSet::new(),
            done: HashSet::new(),
            window: BLOB_WINDOW_START,
            rtt_min: u64::MAX,
            server_id: None,
            enc_sha256: None,
            hashing: None,
            restarts: 0,
        };
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_blob_uploads (file_id, next_chunk, total_chunks, enc_sha256, created_at, upload_secret)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![up.file_id, up.next_chunk as i64, up.total_chunks as i64, Vec::<u8>::new(), current_time_ms() as i64, up.upload_secret],
            );
        }
        self.server_blob_uploads.push(up);
    }

    /// Uploads the next chunks of the head upload, up to its window in flight.
    pub(super) fn server_flush_blobs(&mut self, server_id: &str, peer_id: PeerId) {
        // Quota or rate error on a chunk: wait, as `Deposit` does.
        if self.server_rt.get(server_id).map_or(false, |r| mono_ms() < r.deposit_backoff_until) {
            return;
        }
        // Progress counts for one server only (see `PendingBlobUpload.server_id`). After a restart the server is not remembered
        // (`None`): start over, or the chunks could end up split between two servers. The server is stored with the upload, so
        // a restart resumes from the stored watermark at the same server.
        let Some(head) = self.server_blob_uploads.first_mut() else { return };
        if head.server_id.as_deref() != Some(server_id) {
            head.inflight.clear();
            head.done.clear();
            head.next_chunk = 0;
            head.server_id = Some(server_id.to_string());
            let file_id = head.file_id.clone();
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE server_blob_uploads SET server_id = ?2, next_chunk = 0 WHERE file_id = ?1",
                    params![file_id, server_id],
                );
            }
        }
        let Some(up) = self.server_blob_uploads.first().cloned() else { return };
        let Ok(path) = self.enc_path_for(&up.file_id) else { return };

        // Pipeline: up to `BLOB_PIPELINE_DEPTH` chunks may be in flight at once. With one chunk in flight, speed was limited by chunk size / round trip.
        if up.done.len() < up.total_chunks as usize {
            // `.enc` uses FIXED steps; the step is per file (see `file_chunk_size`).
            let chunk_size = self.file_chunk_size(&up.file_id);
            let mut sent = 0usize;
            for idx in 0..up.total_chunks {
                if up.inflight.len() + sent >= up.window {
                    break;
                }
                if up.done.contains(&idx) || up.inflight.contains(&idx) {
                    continue;
                }
                let data = match crate::attachments::read_chunk_from_disk_with(&path, idx, chunk_size) {
                    Ok(Some(d)) => d,
                    _ => {
                        self.finish_blob_upload(&up.file_id);
                        return;
                    }
                };
                let req = ServerRequest::BlobPut {
                    upload_secret: up.upload_secret.clone(),
                    chunk_index: idx,
                    chunk_size: chunk_size as u32,
                    total_chunks: up.total_chunks,
                    data,
                };
                if let Some(id) = self.send_server_request(peer_id, req) {
                    if let Some(u) = self.server_blob_uploads.first_mut() {
                        u.inflight.insert(idx);
                    }
                    self.server_inflight.insert(
                        id,
                        ServerInflight::BlobPut {
                            server_id: server_id.to_string(),
                            blob_id: up.file_id.clone(),
                            chunk_index: idx,
                            total_chunks: up.total_chunks,
                            sent_at: mono_ms(),
                        },
                    );
                    sent += 1;
                }
            }
            return;
        }

        // All chunks are acknowledged: seal. One finish in flight, and the hash (a full read of up to 4 GiB under the core lock)
        // is taken once. ponytail: that single read still stalls the poll loop for a multi-GB file. Hash on a blocking task if it shows.
        let finishing = self
            .server_inflight
            .values()
            .any(|i| matches!(i, ServerInflight::BlobFinish { blob_id, .. } if *blob_id == up.file_id));
        if up.next_chunk >= up.total_chunks && !finishing {
            // The hash runs on its own thread. The sweep comes back for it.
            let hashed = match (&up.enc_sha256, &up.hashing) {
                (Some(h), _) => Some(Some(h.clone())),
                (None, Some(cell)) => cell.get().cloned(),
                (None, None) => {
                    let cell = std::sync::Arc::new(std::sync::OnceLock::new());
                    let (c, p) = (cell.clone(), path.clone());
                    std::thread::spawn(move || {
                        let _ = c.set(sha256_file(&p));
                    });
                    if let Some(u) = self.server_blob_uploads.first_mut() {
                        u.hashing = Some(cell);
                    }
                    None
                }
            };
            let enc_sha256 = match hashed {
                Some(Some(h)) => h,
                // The file cannot be read: abandon the upload. The direct peer path keeps serving it.
                Some(None) => {
                    self.finish_blob_upload(&up.file_id);
                    return;
                }
                // Still hashing: `server_sweep` looks again on each turn.
                None => return,
            };
            if let Some(u) = self.server_blob_uploads.first_mut() {
                u.enc_sha256 = Some(enc_sha256.clone());
                u.hashing = None;
            }
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE server_blob_uploads SET enc_sha256 = ?2 WHERE file_id = ?1",
                    params![up.file_id, enc_sha256],
                );
            }
            let req = ServerRequest::BlobFinish {
                upload_secret: up.upload_secret.clone(),
                total_chunks: up.total_chunks,
                enc_sha256,
            };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(
                    id,
                    ServerInflight::BlobFinish { server_id: server_id.to_string(), blob_id: up.file_id.clone() },
                );
            }
        }
    }

    pub(super) fn advance_blob_upload(&mut self, file_id: &str, chunk_index: u32, _total: u32, server_id: &str) {
        // A late `Ok` from a server the upload has since left does not count.
        if let Some(up) = self
            .server_blob_uploads
            .iter_mut()
            .find(|u| u.file_id == file_id && u.server_id.as_deref() == Some(server_id))
        {
            up.inflight.remove(&chunk_index);
            up.done.insert(chunk_index);
            // `next_chunk` is now the watermark of contiguously acknowledged chunks. If the process dies, the upload resumes from
            // here. Chunks are acknowledged out of order in the pipeline, so "highest + 1" would be WRONG: a gap in between would
            // be silently skipped. It moves forward only from the last watermark: `done` only grows (a reset also sets `next_chunk`
            // to 0), so nothing below it can be missing.
            let mut watermark = up.next_chunk;
            while up.done.contains(&watermark) {
                watermark += 1;
            }
            up.next_chunk = watermark;
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE server_blob_uploads SET next_chunk = ?2 WHERE file_id = ?1",
                    params![file_id, watermark as i64],
                );
            }
        }
        // Refill the window without waiting: the blob path only, not a full sweep per acknowledged chunk. Only for the server the
        // head upload goes to (`server_flush_blobs` would move it to this one).
        let head_here = self.server_blob_uploads.first().is_some_and(|u| u.server_id.as_deref() == Some(server_id));
        if let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id).filter(|_| head_here) {
            self.server_flush_blobs(server_id, peer_id);
        }
    }

    /// The server lost the upload (swept while we were offline, or chunks missing): send every chunk again. Gives up after a few
    /// rounds, so a server that keeps losing it cannot loop the upload forever.
    pub(super) fn restart_blob_upload(&mut self, file_id: &str, server_id: &str) {
        const MAX_BLOB_RESTARTS: u8 = 3;
        let Some(up) = self
            .server_blob_uploads
            .iter_mut()
            .find(|u| u.file_id == file_id && u.server_id.as_deref() == Some(server_id))
        else {
            return;
        };
        if up.restarts >= MAX_BLOB_RESTARTS {
            warn!("Server lost blob again and again, upload dropped: {}", file_id);
            self.finish_blob_upload(file_id);
            return;
        }
        up.restarts += 1;
        up.inflight.clear();
        up.done.clear();
        up.next_chunk = 0;
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE server_blob_uploads SET next_chunk = 0 WHERE file_id = ?1", params![file_id]);
        }
        self.server_sweep_at = 0;
    }

    /// Gives an upload up. Chunks already on a server are deleted there (`BlobDelete`), or they hold its quota until the 24 h sweep.
    pub(crate) fn finish_blob_upload(&mut self, file_id: &str) {
        let started = self.server_blob_uploads.iter().find(|u| u.file_id == file_id).and_then(|u| {
            u.server_id.clone().filter(|_| !u.done.is_empty() || !u.inflight.is_empty()).map(|sid| (sid, u.upload_secret.clone()))
        });
        if let Some((peer_id, upload_secret)) =
            started.and_then(|(sid, secret)| self.server_rt.get(&sid).and_then(|r| r.peer_id).map(|p| (p, secret)))
        {
            let _ = self.send_server_request(peer_id, ServerRequest::BlobDelete { upload_secret });
        }
        self.forget_blob_upload(file_id);
    }

    /// Drops an upload from the queue (done, or given up).
    pub(super) fn forget_blob_upload(&mut self, file_id: &str) {
        self.server_blob_uploads.retain(|u| u.file_id != file_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM server_blob_uploads WHERE file_id = ?1", params![file_id]);
        }
    }
}

/// SHA-256 of a whole file, without holding it in memory (attachments can reach 4 GiB, see `MAX_ATTACHMENT_SIZE`).
pub(super) fn sha256_file(path: &std::path::Path) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
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
