//! Rate limits, verify budgets, storage budget and signature checks.

use super::*;

impl ServerCore {
        /// Checks whether `incoming` more bytes would exceed the server's TOTAL disk budget.
        ///
        /// The budget used to be enforced only in `handle_blob_put`. Mail and archive were limited per record only, so a
        /// server with enough records (or just enough users) could use far more than the budget. Disk-full on a phone or
        /// tablet is exactly what this mechanism exists to prevent. Blobs are the largest consumer, but not the only one:
        /// 30-day TTL mail and the archive grow too.
    pub(super) fn total_budget_exceeded(&self, incoming: usize) -> bool {
        let Some(total_budget) = self.config.total_storage_budget_bytes else {
            return false;
        };
        // The sum reads every mail, archive and blob row: at most once per `TOTAL_CACHE_MS`, with the bytes written
        // since then added on top (`note_total_written`).
        let mono = mono_ms();
        let (mut at, mut total) = self.total_cache.get();
        if at == 0 || mono.saturating_sub(at) > TOTAL_CACHE_MS {
            total = self.store.total_stored_bytes().max(0) as u64;
            at = mono.max(1);
            self.total_cache.set((at, total));
        }
        total.saturating_add(incoming as u64) > total_budget
    }

    /// Adds bytes that were actually written to the cached total. Only written bytes count. A refused or no-op
    /// request would otherwise charge the cache, and one device could block everyone else's writes.
    pub(super) fn note_total_written(&self, bytes: usize) {
        let (at, total) = self.total_cache.get();
        if at != 0 {
            self.total_cache.set((at, total.saturating_add(bytes as u64)));
        }
    }

    /// `chunk`: a file-chunk request, counted against `CHUNKS_PER_MINUTE` instead of the RPC limit. `cost`: see `request_cost`.
    pub(super) fn check_rate(&mut self, peer: PeerId, chunk: bool, cost: u32) -> bool {
        let limit = self.config.limits.requests_per_minute;
        let now = mono_ms();
        let entry = self.conns.entry(peer).or_insert(ConnState {
            challenge: None,
            window_start: now,
            requests_in_window: 0,
            chunks_in_window: 0,
            connected_at: now,
            enroll_verifies: (0, 0),
            register_verifies: (0, 0),
        });
        if now.saturating_sub(entry.window_start) > RATE_WINDOW_MS {
            entry.window_start = now;
            entry.requests_in_window = 0;
            entry.chunks_in_window = 0;
        }
        if chunk {
            entry.chunks_in_window += 1;
            return entry.chunks_in_window <= CHUNKS_PER_MINUTE;
        }
        entry.requests_in_window = entry.requests_in_window.saturating_add(cost);
        entry.requests_in_window <= limit
    }

    /// Charges `checks` to the peer's share and to `pool`'s server-wide window. `Enroll` and `Rebind` share the
    /// per-peer share, not the pool.
    pub(super) fn verify_budget(&mut self, peer: PeerId, pool: VerifyPool, checks: u32) -> bool {
        let now = mono_ms();
        let conn = self.conns.entry(peer).or_insert(ConnState {
            challenge: None,
            window_start: now,
            requests_in_window: 0,
            chunks_in_window: 0,
            connected_at: now,
            enroll_verifies: (0, 0),
            register_verifies: (0, 0),
        });
        match pool {
            VerifyPool::Register => charge_verify(&mut conn.register_verifies, &mut self.register_verify_window, now, checks, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE),
            VerifyPool::Enroll => charge_verify(&mut conn.enroll_verifies, &mut self.verify_window, now, checks, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE),
            VerifyPool::Rebind => charge_verify(&mut conn.enroll_verifies, &mut self.rebind_verify_window, now, checks, ENROLL_VERIFIES_PER_PEER, REBIND_VERIFIES_PER_MINUTE),
        }
    }

}

/// Hybrid signature verification, with the same contract as the core's `verify_hybrid_signature`: BOTH must pass,
/// and a missing part is rejected.
pub(super) fn verify_hybrid(pk: &[u8], pk_pq: &[u8], message: &[u8], sig: &[u8], sig_pq: &[u8]) -> bool {
    if sig.is_empty() || sig_pq.is_empty() {
        return false;
    }
    if !verify_ed25519(pk, message, sig) {
        return false;
    }
    let Ok(pk_encoded): Result<&EncodedVerifyingKey<MlDsa87>, _> = pk_pq.try_into() else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa87>::decode(pk_encoded);
    let Ok(sig_encoded): Result<&EncodedSignature<MlDsa87>, _> = sig_pq.try_into() else {
        return false;
    };
    let Some(parsed) = MlDsaSignature::<MlDsa87>::decode(sig_encoded) else {
        return false;
    };
    vk.verify(message, &parsed).is_ok()
}

/// Cost of a request against `ServerLimits.requests_per_minute`: one, plus one per 8 list elements (each is a query
/// on the event loop). An `ArchivePut` also pays one per 64 KiB of record bytes. A `MailboxProof` is a hybrid verify,
/// and so is `Enroll` and `Rebind`.
pub(super) fn request_cost(req: &ServerRequest) -> u32 {
    let n = match req {
        ServerRequest::Enroll { .. } | ServerRequest::Rebind { .. } => return 30,
        ServerRequest::Register { add, drop, proofs } => add.len() + drop.len() + 64 * proofs.len(),
        ServerRequest::Fetch { cursors: list, .. } | ServerRequest::Ack { acks: list } => list.len(),
        ServerRequest::Cancel { seqs, .. } => seqs.len(),
        // Bytes count too. The codec caps a request at 1 MiB, so 16 extra units per full request keeps count-only
        // cheating (few big records) priced.
        ServerRequest::ArchivePut { records, .. } => {
            records.len() + records.iter().map(|r| r.sealed.len()).sum::<usize>() / (64 * 1024) * 8
        }
        ServerRequest::ArchiveProbe { buckets } | ServerRequest::ArchivePurge { purge_secrets: buckets } => buckets.len(),
        _ => 0,
    };
    1u32.saturating_add(u32::try_from(n / 8).unwrap_or(u32::MAX))
}

/// Constant-time byte comparison. The challenge is a per-connection secret.
pub(super) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(super) fn verify_ed25519(pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let Ok(pk_bytes): Result<[u8; 32], _> = pubkey.try_into() else { return false };
    let Ok(sig_bytes): Result<[u8; 64], _> = sig.try_into() else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else { return false };
    // Strict, as the client verifies: a non-canonical signature passed here and failed there.
    vk.verify_strict(message, &Signature::from_bytes(&sig_bytes)).is_ok()
}

/// Checks identifiers before they are used as file paths.
///
/// `blob_id` and `file_id` come from the client. Embedded in a path unchecked, `../../` could read or write outside
/// the data directory.
///
/// No upper-case letters: on a case-insensitive blob volume (FAT/exFAT SD card), `AB12` and `ab12` are one file but
/// two DB rows, so a second uploader overwrote the first one's blob. Client ids are lowercase hex and UUIDs.
pub(super) fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

pub(super) fn sanitize_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(128)
        .collect()
}

/// Charges `checks` to a peer's share and to the server-wide pool. Each is a (window start `mono_ms`, checks) over
/// `RATE_WINDOW_MS`. A refused charge costs nothing, so a peer over its share cannot drain the pool for others.
pub(super) fn charge_verify(peer: &mut (u64, u32), pool: &mut (u64, u32), now: u64, checks: u32, peer_limit: u32, pool_limit: u32) -> bool {
    for w in [&mut *peer, &mut *pool] {
        if w.0 == 0 || now.saturating_sub(w.0) > RATE_WINDOW_MS {
            *w = (now.max(1), 0);
        }
    }
    if peer.1.saturating_add(checks) > peer_limit || pool.1.saturating_add(checks) > pool_limit {
        return false;
    }
    peer.1 += checks;
    pool.1 += checks;
    true
}
