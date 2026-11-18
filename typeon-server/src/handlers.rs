//! Request handlers: hello, enroll, rebind, authenticated requests, owner notifies.

use super::*;

impl ServerCore {
    // -----------------------------------------------------------------
    // Request handling
    // -----------------------------------------------------------------

    pub(super) fn handle_request(&mut self, peer: PeerId, req: ServerRequest) -> ServerResponse {
        if !self.check_rate(peer, false, request_cost(&req)) {
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }

        match req {
            ServerRequest::Hello { version } => self.handle_hello(peer, version),
            ServerRequest::Enroll { version, invite_token, enroll_pk, enroll_pk_pq, challenge, ts_ms, sig, sig_pq } => {
                self.handle_enroll(peer, version, invite_token, enroll_pk, enroll_pk_pq, challenge, ts_ms, sig, sig_pq)
            }
            ServerRequest::Rebind { enrollment_id, ts_ms, sig, sig_pq } => {
                self.handle_rebind(peer, enrollment_id, ts_ms, sig, sig_pq)
            }

            // --- Enrollment is REQUIRED from here on ---
            other => {
                let Some(e) = self.authenticate(peer) else {
                    self.stats.rejected += 1;
                    return ServerResponse::Err(ServerErrorCode::NotEnrolled);
                };
                if e.state == EnrollmentState::Revoked {
                    self.stats.rejected += 1;
                    return ServerResponse::Err(ServerErrorCode::Revoked);
                }
                self.handle_authenticated(peer, &e, other)
            }
        }
    }

    pub(super) fn handle_hello(&mut self, peer: PeerId, version: u16) -> ServerResponse {
        if version != SERVER_PROTOCOL_VERSION {
            return ServerResponse::Err(ServerErrorCode::Unsupported);
        }
        let mut challenge = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        // Only an ACTIVE enrollment counts as registered.
        //
        // This used to be `.is_some()`, and that locked a revoked device out for good. The client saw
        // `Welcome.enrolled = true`, skipped the `Enroll` step, and every request then returned `Revoked` from
        // `authenticate` (state == Revoked). The user saw "The operator revoked the enrollment" on a freshly added
        // device, and it never recovered. The revoke key also blocks re-enrollment (see `Store::revoke_enrollment`):
        // the client goes to `Enroll` and gets `Revoked` until the operator lifts the block.
        let enrollment_id = self
            .store
            .enrollment_by_peer(&peer.to_string())
            .filter(|e| e.state == EnrollmentState::Active)
            .map(|e| e.enrollment_id);
        let enrolled = enrollment_id.is_some();
        if let Some(c) = self.conns.get_mut(&peer) {
            c.challenge = Some(challenge.clone());
        }
        ServerResponse::Welcome {
            version: SERVER_PROTOCOL_VERSION,
            challenge,
            enrolled,
            enrollment_id,
            limits: self.config.limits.clone(),
            server_name: self.config.server_name.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_enroll(
        &mut self,
        peer: PeerId,
        version: u16,
        invite_token: Vec<u8>,
        enroll_pk: Vec<u8>,
        enroll_pk_pq: Vec<u8>,
        client_challenge: Vec<u8>,
        ts_ms: u64,
        sig: Vec<u8>,
        sig_pq: Vec<u8>,
    ) -> ServerResponse {
        if version != SERVER_PROTOCOL_VERSION {
            return ServerResponse::Err(ServerErrorCode::Unsupported);
        }
        let now = now_ms();
        if (now as u64).abs_diff(ts_ms) > server_proto::ENROLL_MAX_SKEW_MS {
            return ServerResponse::Err(ServerErrorCode::Stale);
        }
        // Cheap gate before the hybrid verify (ML-DSA-87 is the expensive step, and PeerIds are free): no usable
        // invite, no signature check.
        let hash = Sha256::digest(&invite_token);
        if matches!(self.store.invite_uses_left(hash.as_slice(), now), None | Some(0)) {
            return ServerResponse::Err(ServerErrorCode::BadInvite);
        }
        // The challenge is single-use (`take`). Otherwise an observer could capture the signature and replay it.
        // It is random and per connection, so removing it from memory is enough.
        let Some(challenge) = self.conns.get_mut(&peer).and_then(|c| c.challenge.take()) else {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        };
        // The challenge the client signed must be the one WE issued.
        if !ct_eq(&client_challenge, &challenge) {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        if !self.verify_budget(peer, VerifyPool::Enroll, 1) {
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }

        let signing_input = server_proto::enroll_signing_input(
            version,
            &self.local_peer_id().to_string(),
            &peer.to_string(),
            &invite_token,
            &enroll_pk,
            &enroll_pk_pq,
            &challenge,
            ts_ms,
        );
        // HYBRID: both must pass. A classical signature alone would let a harvest-now-break-later attacker forge
        // registrations in the future.
        if !verify_hybrid(&enroll_pk, &enroll_pk_pq, &signing_input, &sig, &sig_pq) {
            // A failed attempt costs one use of a counted invite. Otherwise a leaked code stayed a free verify oracle.
            // The unlimited join code has no uses to spend (`verify_budget` bounds it).
            let _ = self.store.consume_invite(hash.as_slice(), now);
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        // Operator decision: revoke means block. Both block the enrollment KEY, so the same device cannot enroll
        // again even with a new invite. Only a new PeerId with a new key (a reinstall) gets through. This is an
        // operator control, not an absolute ban. The check happens AFTER signature verification. Blocking before the
        // key is proven to belong to this device would let someone block another device by writing its key.
        // The key this PeerId enrolled with before counts too. The device makes its enroll key itself, so a fresh
        // one alone must not lift a block.
        let prev = self.store.enrollment_by_peer(&peer.to_string());
        if self.store.is_key_blocked(&enroll_pk)
            || prev.as_ref().map_or(false, |p| self.store.is_key_blocked(&p.enroll_pk))
        {
            warn!("Registration with a blocked key rejected");
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }

        // The Sybil gate for the public (unlimited) join code is NOT the single use of the token. That property was
        // dropped on purpose (see `join_code`). This check replaces it: an unlimited code cannot open new enrollments
        // once the last hour's enrollment count reaches `MAX_PUBLIC_ENROLLMENTS_PER_HOUR`. The window counts ALL
        // enrollments, including those opened with a counted invite. The aim is to limit the server's enrollment
        // rate, not one code. The cap is well above the join rate of a real group, and low for an automated flood.
        // The operator can close the code at once with `rotate_join_code`. The cap is checked BEFORE the counter is
        // consumed, so a refused attempt must not spend the invite's use.
        if self.store.invite_uses_left(hash.as_slice(), now) == Some(-1) {
            let since = now - 60 * 60 * 1000;
            if self.store.count_enrollments_since(since, now) >= MAX_PUBLIC_ENROLLMENTS_PER_HOUR {
                warn!("Public enrollment code exceeded the hourly cap, registration rejected");
                self.stats.rejected += 1;
                return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
            }
            // One holder of an unlimited code cannot take every place: the code gets three quarters of them.
            let allowance = (self.config.max_enrollments as i64 * 3 / 4).max(1);
            if !prev.as_ref().map_or(false, |p| p.state == EnrollmentState::Active)
                && self.store.count_active_enrollments_by_invite(hash.as_slice(), now - ENROLLMENT_IDLE_MS) >= allowance
            {
                warn!("Public enrollment code used up its share of device places, registration rejected");
                self.stats.rejected += 1;
                return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
            }
        }
        // A PeerId that enrolls again takes no new place.
        if !prev.as_ref().map_or(false, |p| p.state == EnrollmentState::Active)
            && self.store.count_active_enrollments(now - ENROLLMENT_IDLE_MS) >= self.config.max_enrollments as i64
        {
            warn!("Enrollment refused: the server holds its maximum number of devices");
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // If the same PeerId enrolls again (`peer_id` is UNIQUE, insert with `OR REPLACE`), inherit the old identity
        // and quota counters. Otherwise a new `enrollment_id` with zeroed counters would leave the existing
        // mail/archive/blob rows ownerless and reset the quota.
        let enrollment_id = match &prev {
            Some(p) => p.enrollment_id.clone(),
            None => {
                let mut id = vec![0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut id);
                id
            }
        };
        let e = Enrollment {
            enrollment_id: enrollment_id.clone(),
            enroll_pk,
            enroll_pk_pq,
            peer_id: peer.to_string(),
            state: EnrollmentState::Active,
            enrolled_at: prev.as_ref().map_or(now, |p| p.enrolled_at),
            last_seen_at: now,
            bytes_mail: prev.as_ref().map_or(0, |p| p.bytes_mail),
            bytes_archive: prev.as_ref().map_or(0, |p| p.bytes_archive),
            bytes_blob: prev.as_ref().map_or(0, |p| p.bytes_blob),
        };
        // One transaction. A failed insert must not cost the invite its use.
        match self.store.enroll_with_invite(hash.as_slice(), now, &e) {
            Ok(true) => {}
            Ok(false) => return ServerResponse::Err(ServerErrorCode::BadInvite),
            Err(msg) => {
                error!("Registration could not be written: {msg}");
                return ServerResponse::Err(ServerErrorCode::Internal);
            }
        }
        self.stats.enrollments += 1;
        debug!("New registration: {}", hex::encode(&enrollment_id));
        ServerResponse::Enrolled { enrollment_id, limits: self.config.limits.clone() }
    }

    pub(super) fn handle_rebind(
        &mut self,
        peer: PeerId,
        enrollment_id: Vec<u8>,
        ts_ms: u64,
        sig: Vec<u8>,
        sig_pq: Vec<u8>,
    ) -> ServerResponse {
        let now = now_ms();
        if (now as u64).abs_diff(ts_ms) > server_proto::ENROLL_MAX_SKEW_MS {
            return ServerResponse::Err(ServerErrorCode::Stale);
        }
        // The same single-use challenge as `Enroll`. Without it (and the caller's PeerId) in the signed bytes, a
        // captured Rebind could be replayed to move the enrollment to someone else within the skew window.
        let Some(challenge) = self.conns.get_mut(&peer).and_then(|c| c.challenge.take()) else {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        };
        let Some(existing) = self.store.enrollment_by_id(&enrollment_id) else {
            return ServerResponse::Err(ServerErrorCode::NotEnrolled);
        };
        let per_id = self.rebind_by_enrollment.entry(enrollment_id.clone()).or_insert((0, 0));
        let mut no_pool = (0, 0);
        if !charge_verify(per_id, &mut no_pool, mono_ms(), 1, ENROLL_VERIFIES_PER_PEER, u32::MAX)
            || !self.verify_budget(peer, VerifyPool::Rebind, 1)
        {
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        let input = server_proto::rebind_signing_input(
            &enrollment_id,
            &self.local_peer_id().to_string(),
            &peer.to_string(),
            &challenge,
            ts_ms,
        );
        if !verify_hybrid(&existing.enroll_pk, &existing.enroll_pk_pq, &input, &sig, &sig_pq) {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        // After the signature check, so only the key holder learns the id is revoked.
        if existing.state == EnrollmentState::Revoked {
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }
        // A blocked key cannot rebind either (see `handle_enroll`).
        if self.store.is_key_blocked(&existing.enroll_pk) {
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }
        if let Err(msg) = self.store.rebind_enrollment(&enrollment_id, &peer.to_string(), now) {
            error!("Rebind could not be written: {msg}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        ServerResponse::Enrolled { enrollment_id, limits: self.config.limits.clone() }
    }

    /// Resolves the enrollment from the `PeerId` that Noise PROVED. No field the packet CLAIMS is trusted. This
    /// is the same reason the core rate-limits by `PeerId` rather than by `sender_device_fingerprint`.
    pub(super) fn authenticate(&self, peer: PeerId) -> Option<Enrollment> {
        self.store.enrollment_by_peer(&peer.to_string())
    }

    /// Like `authenticate`, but only for an enrollment the operator has not revoked. Read from the DB every time:
    /// revoke and block arrive over another connection (JNI or CLI) while the peer stays connected.
    pub(super) fn active(&self, peer: PeerId) -> Option<Enrollment> {
        self.authenticate(peer).filter(|e| e.state == EnrollmentState::Active)
    }

    pub(super) fn handle_authenticated(&mut self, peer: PeerId, e: &Enrollment, req: ServerRequest) -> ServerResponse {
        let now = now_ms();
        // `last_seen_at` is for the operator, not a write per request.
        if now - e.last_seen_at > 60_000 {
            self.store.touch_enrollment(&e.enrollment_id, now);
        }
        let limits = self.config.limits.clone();

        // Each list element costs a query inside the event loop.
        let boxes = limits.max_mailboxes as usize;
        let too_long = match &req {
            ServerRequest::Register { add, drop, proofs } => {
                add.len().max(drop.len()) > boxes || proofs.len() > server_proto::MAX_REGISTER_PROOFS
            }
            ServerRequest::Fetch { cursors, .. } => cursors.len() > boxes,
            ServerRequest::Ack { acks } => acks.len() > boxes,
            ServerRequest::ArchiveProbe { buckets } | ServerRequest::ArchivePurge { purge_secrets: buckets } => buckets.len() > boxes,
            ServerRequest::Cancel { seqs, .. } => seqs.len() > boxes,
            ServerRequest::ArchivePut { records, .. } => records.len() > server_proto::MAX_ARCHIVE_PUT_RECORDS,
            _ => false,
        };
        if too_long {
            return ServerResponse::Err(ServerErrorCode::TooLarge);
        }
        // Every mailbox and bucket id the server stores or looks up. Client ids always pass, so a failure means a
        // hostile request.
        let bad_id = match &req {
            ServerRequest::Register { add, drop, .. } => add.iter().chain(drop.iter()).any(|id| !is_safe_id(id)),
            ServerRequest::Fetch { cursors: list, .. } | ServerRequest::Ack { acks: list } => {
                list.iter().any(|(id, _)| !is_safe_id(id))
            }
            ServerRequest::ArchiveProbe { buckets } => buckets.iter().any(|id| !is_safe_id(id)),
            ServerRequest::ArchivePurge { purge_secrets } => {
                purge_secrets.iter().any(|s| server_proto::archive_bucket_for_purge_secret(s).is_none())
            }
            ServerRequest::Deposit { mailbox: id, .. }
            | ServerRequest::Cancel { mailbox: id, .. }
            | ServerRequest::ArchivePut { bucket: id, .. }
            | ServerRequest::ArchiveFetch { bucket: id, .. } => !is_safe_id(id),
            _ => false,
        };
        if bad_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }

        match req {
            ServerRequest::Register { add, drop, proofs } => {
                // Only a proof for an id in `add` is verified, and only one with a valid signature reaches the store.
                // Each proof is a hybrid verify. Without a server-wide budget, 64 enrollments times 64 proofs would pin
                // the CPU.
                let checks = proofs.iter().filter(|p| add.contains(&p.mailbox)).count() as u32;
                if checks > 0 && !self.verify_budget(peer, VerifyPool::Register, checks) {
                    return ServerResponse::Err(ServerErrorCode::RateLimited);
                }
                let me = self.swarm.local_peer_id().to_string();
                let proved: Vec<(String, Vec<u8>)> = proofs
                    .iter()
                    .filter(|p| add.contains(&p.mailbox))
                    .filter(|p| {
                        let input = server_proto::register_signing_input(&p.mailbox, &e.enrollment_id, &me);
                        verify_hybrid(&p.pk, &p.pk_pq, &input, &p.sig, &p.sig_pq)
                    })
                    .map(|p| (p.mailbox.clone(), server_proto::mailbox_key_hash(&p.pk, &p.pk_pq).to_vec()))
                    .collect();
                // A proof that did not verify is a refusal, not `proof_needed`. The client would send the same bytes again.
                let bad_proof = proofs.iter().filter(|p| add.contains(&p.mailbox)).count().saturating_sub(proved.len());
                let registered = self.store.register_mailboxes_proved(&e.enrollment_id, &add, &drop, &proved, now, limits.max_mailboxes);
                let (refused, unproven) = match registered {
                    Ok((refused, unproven)) => {
                        let (bad, unproven): (Vec<String>, Vec<String>) =
                            unproven.into_iter().partition(|id| proofs.iter().any(|p| &p.mailbox == id));
                        (refused.into_iter().chain(bad).collect::<Vec<String>>(), unproven)
                    }
                    Err(msg) => {
                        error!("Register could not be written: {msg}");
                        return ServerResponse::Err(ServerErrorCode::Internal);
                    }
                };
                let interest = self.live_interest.entry(peer).or_default();
                for id in add {
                    if !refused.contains(&id) && !unproven.contains(&id) {
                        interest.insert(id);
                    }
                }
                for id in &drop {
                    interest.remove(id);
                }
                // Every id not named is registered. Each named one says why (see `ServerResponse::Registered`).
                if unproven.is_empty() && refused.is_empty() {
                    return ServerResponse::Ok;
                }
                if !refused.is_empty() {
                    warn!("Register: {} box(es) rejected (quota, reader limit or key), {} proof(s) not verified", refused.len(), bad_proof);
                }
                ServerResponse::Registered { proof_needed: unproven, refused }
            }

            ServerRequest::Deposit { mailbox, sealed } => {
                if sealed.len() > limits.max_item_bytes as usize || sealed.len() > MAX_DEPOSIT_BYTES {
                    return ServerResponse::Err(ServerErrorCode::TooLarge);
                }
                // Depositing into a mailbox that is not registered tells the client "this recipient is not on my
                // server". That sends the traffic straight to gossipsub, so no round trip is wasted on every message.
                if !self.store.mailbox_has_other_reader(&mailbox, &e.enrollment_id) {
                    return ServerResponse::Err(ServerErrorCode::UnknownMailbox);
                }
                // Only this request's own counter. A full blob quota must not stop the device from messaging.
                if e.bytes_mail as u64 > limits.max_mail_bytes {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // See `total_budget_exceeded`. The per-record quota alone does not protect the device's disk.
                let row_bytes = store::mail_row_bytes(&mailbox, &sealed);
                if self.total_budget_exceeded(row_bytes, true) {
                    warn!("Total disk budget full, delivery rejected");
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // Per depositor (see `depositor_usage`). A box full of someone else's deposits must not refuse ours. The
                // byte share keeps one unreachable reader from taking the depositor's whole quota, which would stop its
                // mail to every other box too.
                let (rows, bytes) = self.store.depositor_usage(&mailbox, &e.enrollment_id);
                if rows >= limits.max_items_per_mailbox as i64
                    || bytes.max(0) as u64 + row_bytes as u64 > limits.max_mail_bytes / MAIL_BOX_SHARE
                {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // What one depositor pushes into one box per window, acknowledged or not. Acks free the quota within
                // seconds, so without this a sender could make a reader download junk without end.
                let mono = mono_ms();
                let win = self.deposit_window.entry((peer, mailbox.clone())).or_insert((mono, 0));
                if mono.saturating_sub(win.0) > DEPOSIT_WINDOW_MS {
                    *win = (mono, 0);
                }
                if win.1 + row_bytes as u64 > DEPOSIT_BYTES_PER_BOX_WINDOW {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                match self.store.deposit_written(&mailbox, &sealed, &e.enrollment_id, now, limits.mailbox_ttl_ms as i64) {
                    // A repeat wrote nothing: no charge, no push.
                    Ok((seq, false)) => ServerResponse::Deposited { seq },
                    Ok((seq, true)) => {
                        if let Some(win) = self.deposit_window.get_mut(&(peer, mailbox.clone())) {
                            win.1 += row_bytes as u64;
                        }
                        self.note_total_written(row_bytes);
                        self.stats.deposits += 1;
                        let item = MailItem { mailbox_id: mailbox.clone(), seq, deposited_at_ms: now as u64, sealed };
                        self.notify_owner_of(&mailbox, peer, item);
                        ServerResponse::Deposited { seq }
                    }
                    Err(msg) => {
                        error!("Deposit could not be written: {msg}");
                        ServerResponse::Err(ServerErrorCode::Internal)
                    }
                }
            }

            ServerRequest::Fetch { cursors, max_items, max_bytes } => {
                self.notified.remove(&peer);
                let (items, more) = self.store.fetch(
                    &e.enrollment_id,
                    &cursors,
                    // 0 would answer an empty batch with `more` forever.
                    max_items.clamp(1, MAX_FETCH_BATCH_ITEMS),
                    max_bytes.clamp(1, MAX_FETCH_BATCH_BYTES),
                );
                self.stats.fetches += 1;
                ServerResponse::Batch { items, more }
            }

            ServerRequest::Ack { acks } => {
                match self.store.ack_many(&acks, &e.enrollment_id) {
                    Ok(deleted) => {
                        if deleted > 0 {
                            // Quota must not only grow. Delivered bytes are charged back to the depositor's account.
                            self.mail_recount_due = true;
                        }
                        ServerResponse::Ok
                    }
                    // `Ok` would make the client keep its cursor and never ack these items again.
                    Err(msg) => {
                        error!("Ack could not be written: {msg}");
                        ServerResponse::Err(ServerErrorCode::Internal)
                    }
                }
            }

            // See `ServerRequest::Cancel`. The sender withdraws its own undelivered packet. The ownership check is in
            // the query itself: `depositor = requester`.
            ServerRequest::Cancel { mailbox, seqs } => {
                let removed = self.store.cancel_own_deposits(&mailbox, &seqs, &e.enrollment_id);
                if removed > 0 {
                    self.mail_recount_due = true;
                    info!("Sender withdrew {} packets", removed);
                }
                ServerResponse::Ok
            }

            ServerRequest::ArchivePut { bucket, records } => {
                if records.iter().any(|r| r.sealed.len() > MAX_DEPOSIT_BYTES) {
                    return ServerResponse::Err(ServerErrorCode::TooLarge);
                }
                if e.bytes_archive as u64 > limits.max_archive_bytes {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // See `total_budget_exceeded`. Unlike mail, the archive has no TTL: once written it stays until an
                // `ArchivePurge` arrives. It is the largest contributor to the total ceiling.
                let incoming: usize = records.iter().map(store::archive_row_bytes).sum();
                if self.total_budget_exceeded(incoming, false) {
                    warn!("Total disk budget full, archive write rejected");
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                match self.store.archive_put(&bucket, &records, &e.enrollment_id, now) {
                    Ok(_) => {
                        self.note_total_written(incoming);
                        self.stats.archive_puts += 1;
                        ServerResponse::Ok
                    }
                    Err(msg) => {
                        error!("ArchivePut could not be written: {msg}");
                        ServerResponse::Err(ServerErrorCode::Internal)
                    }
                }
            }

            ServerRequest::ArchiveProbe { buckets } => {
                ServerResponse::ArchiveProbed { present: self.store.archive_probe(&buckets) }
            }

            ServerRequest::ArchiveFetch { bucket, before_ms, before_id, max_items, max_bytes } => {
                let (records, more) = self.store.archive_fetch(
                    &bucket,
                    before_ms.map(|ms| (ms, before_id.as_deref().unwrap_or(""))),
                    max_items.clamp(1, MAX_FETCH_BATCH_ITEMS),
                    max_bytes.clamp(1, MAX_FETCH_BATCH_BYTES),
                );
                ServerResponse::ArchiveBatch { records, more }
            }

            // Only the archive key's holders know a secret; the bucket id alone (which the server and anyone it
            // tells know) deletes nothing.
            ServerRequest::ArchivePurge { purge_secrets } => {
                let buckets: Vec<String> =
                    purge_secrets.iter().filter_map(|s| server_proto::archive_bucket_for_purge_secret(s)).collect();
                self.store.archive_purge(&buckets);
                ServerResponse::Ok
            }

            // The id is the hash of the uploader's secret (see `server_proto::blob_id_for_upload_secret`). A
            // FileOffer recipient knows only the id, so it cannot claim the blob first.
            ServerRequest::BlobPut { upload_secret, chunk_index, total_chunks, chunk_size, data } => {
                let Some(blob_id) = server_proto::blob_id_for_upload_secret(&upload_secret) else {
                    return ServerResponse::Err(ServerErrorCode::BadDirection);
                };
                self.handle_blob_put(e, &limits, blob_id, chunk_index, total_chunks, chunk_size, data, now)
            }

            ServerRequest::BlobFinish { upload_secret, total_chunks, enc_sha256 } => {
                let Some(blob_id) = server_proto::blob_id_for_upload_secret(&upload_secret) else {
                    return ServerResponse::Err(ServerErrorCode::BadDirection);
                };
                self.handle_blob_finish(e, blob_id, total_chunks, enc_sha256)
            }

            ServerRequest::BlobDelete { upload_secret } => {
                if let Some(blob_id) = server_proto::blob_id_for_upload_secret(&upload_secret) {
                    if self.store.blob_state(&blob_id).map_or(false, |s| s.owner == e.enrollment_id) {
                        self.drop_blob(&blob_id);
                    }
                }
                ServerResponse::Ok
            }

            // Types a client may never send to the server.
            ServerRequest::Hello { .. }
            | ServerRequest::Enroll { .. }
            | ServerRequest::Rebind { .. }
            | ServerRequest::Notify
            | ServerRequest::Push { .. } => ServerResponse::Err(ServerErrorCode::BadDirection),
        }
    }

    // -----------------------------------------------------------------
    // Push (Notify) and sweep
    // -----------------------------------------------------------------

    /// If a CONNECTED peer is listening on the mailbox, tells it "mail is waiting".
    ///
    /// Without this the client would have to poll with `Fetch` constantly, which means battery drain on a phone.
    /// The payload is not carried here. The client runs `Fetch` in its own cycle, so cursor logic stays intact.
    pub(super) fn notify_owner_of(&mut self, mailbox: &str, depositor: PeerId, item: MailItem) {
        let targets: Vec<PeerId> = self
            .live_interest
            .iter()
            .filter(|(peer, boxes)| **peer != depositor && boxes.contains(mailbox))
            .map(|(peer, _)| *peer)
            .collect();
        for peer in targets {
            // Revoked or blocked while connected: nothing more is pushed.
            let Some(reader) = self.active(peer) else { continue };
            // See `ServerRequest::Push`. Inline only when nothing older is pending for this reader, so the client
            // cannot skip an item.
            let inline = item.sealed.len() <= PUSH_INLINE_MAX
                && self.store.unacked_for(mailbox, &reader.enrollment_id) == 1;
            // One `Notify` until the peer fetches. A deposit flood would otherwise wake the reader's radio once per item.
            if !inline {
                if self.notified.contains_key(&peer) {
                    continue;  // `resend_notifies` repeats it
                }
                self.notified.insert(peer, (mono_ms(), 0));
            }
            let req = if inline { ServerRequest::Push { item: item.clone() } } else { ServerRequest::Notify };
            self.swarm.behaviour_mut().server_rpc.send_request(&peer, req);
        }
    }

    /// Repeats the `Notify` of every connected reader that has not fetched since its last one (see
    /// `NOTIFY_RESEND_MS`, doubling after each unanswered one up to 16 times that). Called every tick (5 s).
    pub(super) fn resend_notifies(&mut self) {
        let now = mono_ms();
        let due: Vec<(PeerId, u32)> = self.notified.iter()
            .filter(|(_, (sent, tries))| now.saturating_sub(*sent) >= NOTIFY_RESEND_MS << (*tries).min(4))
            .map(|(peer, (_, tries))| (*peer, *tries))
            .collect();
        for (peer, tries) in due {
            if self.active(peer).is_none() || !self.swarm.is_connected(&peer) {
                self.notified.remove(&peer);
                continue;
            }
            self.notified.insert(peer, (now, tries.saturating_add(1)));
            debug!("Notify yinelendi (Fetch gelmedi): {peer}");
            self.swarm.behaviour_mut().server_rpc.send_request(&peer, ServerRequest::Notify);
        }
    }

}
