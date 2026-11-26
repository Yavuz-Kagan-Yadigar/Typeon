//! Mailboxes: registration with proofs, deposits, fetch, acks, holds.

use super::*;

impl P2PCore {
    // -----------------------------------------------------------------
    // Bucket IDs
    // -----------------------------------------------------------------

    /// Every store-and-forward mailbox this device reads: id -> the secret its `Register` proof is made from
    /// (`mailbox_proof`), and the key that opens its envelopes (`MailboxKey`).
    ///
    /// The single source for `Register`, `Fetch`, and opening a batch.
    ///
    /// A first-contact mailbox is made from a pairing secret (`first_contact_secrets`), one mailbox per secret.
    /// Its proof key comes from this device's signing key. Someone who holds the code can compute the id but still
    /// cannot register it.
    pub(super) fn own_server_mailboxes(&self) -> HashMap<String, (Vec<u8>, MailboxKey)> {
        let mut idx = HashMap::new();
        if let Some(fp) = &self.own_mailbox_topic_fp {
            if let Some(keys) = self.own_device_keys.get(fp) {
                let owner_secret = keys.sign_sk_ed25519.to_bytes().to_vec();
                for secret in self.first_contact_secrets() {
                    idx.insert(server_seal::first_contact_mailbox_id(&secret, fp), (owner_secret.clone(), MailboxKey::FirstContact(secret)));
                }
            }
        }
        for (peer_fp, state) in &self.ratchets {
            // Only the box this device reads: the peer's mail to us. Our mail to the peer goes to ITS inbound box,
            // which we never register.
            let Some((mailbox, secret)) = self.session_mailbox(peer_fp, true) else { continue };
            // Rotation window: the other side may still seal with the OLD root key if it has not applied our last
            // rotation yet.
            let mut keys = vec![state.root_handle_now()];
            keys.extend(state.prev_root_key.clone());
            idx.insert(mailbox, (secret.to_vec(), MailboxKey::Session(keys, peer_fp.clone())));
        }
        idx
    }

    /// A server mailbox of the session with `peer_fp`, and its secret (proof key and deposit secret come from it).
    /// `inbound`: the box this device reads (the peer deposits there); otherwise the peer's inbound box, where this
    /// device deposits. Stable for the session: derived from the ratchet's `mailbox_seed` (fixed at the hybrid
    /// handshake, see `server_seal::session_inbox_secret`), not from the rotating root key. The id is made from the
    /// proof key (`key_bound_mailbox_id`). No session, no mailbox.
    /// PROTOCOL BREAK: older clients used one shared box per pair.
    pub(super) fn session_mailbox(&self, peer_fp: &str, inbound: bool) -> Option<(String, [u8; 32])> {
        let own_fp = self.own_mailbox_topic_fp.as_ref()?;
        let seed = &self.ratchets.get(peer_fp)?.mailbox_seed;
        let (recipient, sender) = if inbound { (own_fp.as_str(), peer_fp) } else { (peer_fp, own_fp.as_str()) };
        // Memoized: one HKDF and one id derivation per session on every sweep, fetch answer and push. Keyed by the
        // seed and both fingerprints in direction order, so a new session misses.
        let tag: [u8; 32] = Sha256::new()
            .chain_update(seed)
            .chain_update(recipient.as_bytes())
            .chain_update([0u8])
            .chain_update(sender.as_bytes())
            .finalize()
            .into();
        if let Some(hit) = SESSION_MAILBOX_MEMO.lock().ok()?.get_or_insert_with(HashMap::new).get(&tag) {
            return Some(hit.clone());
        }
        let secret = server_seal::session_inbox_secret(seed, recipient, sender).ok()?;
        let id = key_bound_mailbox_id(&secret)?;
        let mut memo = SESSION_MAILBOX_MEMO.lock().ok()?;
        let memo = memo.get_or_insert_with(HashMap::new);
        // ponytail: dropped whole past 4096 entries, like `key_bound_mailbox_id`.
        if memo.len() >= 4096 {
            wipe_memo_secrets(memo);
            memo.clear();
        }
        // Two threads can miss the same tag: the copy replaced here is zeroed too.
        if let Some((_, mut old)) = memo.insert(tag, (id.clone(), secret)) {
            zeroize::Zeroize::zeroize(&mut old);
        }
        Some((id, secret))
    }

    /// The `MailboxProof` of `mailbox` for this enrollment at `server_id`. `deposit_secret`: the box's, if anyone
    /// deposits to it (not a call relay box).
    pub(super) fn mailbox_proof(
        secret: &[u8],
        mailbox: &str,
        enrollment_id: &[u8],
        server_id: &str,
        deposit_secret: Option<&[u8; 32]>,
    ) -> Option<server_proto::MailboxProof> {
        let (signing, signing_pq) = mailbox_proof_keys(secret, mailbox)?;
        let input = server_proto::register_signing_input(mailbox, enrollment_id, server_id);
        let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
        Some(server_proto::MailboxProof {
            mailbox: mailbox.to_string(),
            pk: signing.verifying_key().to_bytes().to_vec(),
            pk_pq: signing_pq.verifying_key().encode().to_vec(),
            sig: signing.sign(&input).to_bytes().to_vec(),
            sig_pq: sig_pq.encode().to_vec(),
            deposit_verifier: deposit_secret.map_or_else(Vec::new, |d| server_proto::deposit_verifier(d).to_vec()),
        })
    }

    /// The deposit secret of one of this device's boxes (`own_server_mailboxes` entry): from the session's inbound
    /// secret, or from the pairing secret of a first-contact box (which the sender holds too).
    pub(super) fn own_deposit_secret(mailbox: &str, proof_secret: &[u8], key: &MailboxKey) -> Option<[u8; 32]> {
        let base = match key {
            MailboxKey::FirstContact(secret) => secret.as_slice(),
            MailboxKey::Session(..) => proof_secret,
        };
        server_seal::deposit_secret(base, mailbox).ok()
    }

    /// `Register` for `add`, with a proof for each ID of `prove` (at most `typeon_crypto::server_proto::MAX_REGISTER_PROOFS`; the server asks
    /// again for the rest).
    pub(super) fn send_register(&mut self, server_id: &str, peer_id: PeerId, mut add: Vec<String>, drop: Vec<String>, prove: &[String]) {
        let enrollment_id = self.servers.iter().find(|s| s.server_id == server_id).and_then(|s| s.enrollment_id.clone());
        let proofs: Vec<server_proto::MailboxProof> = match &enrollment_id {
            // Mailbox secrets are fetched only when there is something to prove.
            Some(eid) if !prove.is_empty() => {
                // id -> (proof secret, deposit secret). A call relay box takes no deposits.
                let mut secrets: HashMap<String, (Vec<u8>, Option<[u8; 32]>)> = self
                    .own_server_mailboxes()
                    .into_iter()
                    .map(|(id, (secret, key))| {
                        let deposit = Self::own_deposit_secret(&id, &secret, &key);
                        (id, (secret, deposit))
                    })
                    .collect();
                secrets.extend(crate::call::relay_listen_keys().into_iter().filter_map(|k| Some((key_bound_mailbox_id(&k)?, (k, None)))));
                prove.iter()
                    .take(server_proto::MAX_REGISTER_PROOFS)
                    .filter_map(|id| {
                        let (secret, deposit) = secrets.get(id)?;
                        Self::mailbox_proof(secret, id, eid, server_id, deposit.as_ref())
                    })
                    .collect()
            }
            _ => Vec::new(),
        };
        // An ID that needs a proof and got none (over the cap, or no longer our mailbox) waits for the next sweep.
        // Sent bare, the server would ask for the proof again, endlessly.
        add.retain(|id| !prove.contains(id) || proofs.iter().any(|p| &p.mailbox == id));
        if add.is_empty() && drop.is_empty() {
            return;
        }
        info!("Server mailbox registration: +{} -{} (proof: {})", add.len(), drop.len(), proofs.len());
        let (ids, dropped) = (add.clone(), drop.clone());
        if let Some(id) = self.send_server_request(peer_id, ServerRequest::Register { add, drop, proofs }) {
            self.server_inflight.insert(id, ServerInflight::Register { server_id: server_id.to_string(), ids, dropped });
        }
    }

    // -----------------------------------------------------------------
    // Sending
    // -----------------------------------------------------------------

    /// Tries to deposit the envelope to every server that is routing and connected.
    ///
    /// The deposit goes over the server's anonymous connection (`anon.rs`), never the enrollment one, into the
    /// TARGET's inbound box, with that box's deposit secret.
    ///
    /// `true` means it was deposited to at least one server (the RPC is queued). The caller (`try_publish_raw`)
    /// counts that as sent. The end-to-end guarantee is still the peer's `Ack`.
    pub(crate) fn try_server_deposit(
        &mut self,
        target_fp: &str,
        topic: &str,
        envelope: &NetworkEnvelope,
        bytes: &[u8],
        first_attempt_at: u64,
    ) -> bool {
        if self.servers.is_empty() {
            return false;
        }
        // Checked before the seal: a held packet is retried each queue turn.
        let lazy_hold = self.lazy_deposit_held(envelope);
        if lazy_hold && self.anon_conns.is_empty() {
            return false;
        }
        // A first-contact topic names only the public fingerprint. Its mailbox ID needs the pairing secret we hold
        // for the target. With no secret there is no server path (the direct path still applies).
        //
        // Everything sent to that mailbox (Handshake, IdentityExchange, and a Message before a session exists) is
        // sealed with that secret and, when the target's device record is known, to its KEM keys. The server sees
        // no first-contact identity metadata. A session mailbox is sealed with the session's root key. Otherwise the
        // header's `sender_device_fingerprint` would be readable on the server.
        // The deposit secret comes from the secret the box is made from: the pairing secret, or the session secret
        // of the target's inbound box.
        let sealed = if topic.starts_with("p2p_msg_") {
            let Some(secret) = self.first_contact_secret_for(target_fp) else { return false };
            let mailbox = server_seal::first_contact_mailbox_id(&secret, target_fp);
            let kem = self.known_remote_devices.get(target_fp)
                .filter(|d| d.kem_pubkey_x25519.len() == 32 && d.kem_pubkey_mlkem.len() == 1568)
                .map(|d| (d.kem_pubkey_x25519.as_slice(), d.kem_pubkey_mlkem.as_slice()));
            let deposit = server_seal::deposit_secret(&secret, &mailbox);
            let sealed = server_seal::seal_first_contact(&secret, &mailbox, kem, bytes);
            deposit.and_then(|d| sealed.map(|s| (mailbox, d, s)))
        } else {
            // Only a `Message` goes to a session topic (see `try_publish_raw_via`).
            let NetworkEnvelope::Message(m) = envelope else { return false };
            let Some((mailbox, box_secret)) = self.session_mailbox(target_fp, false) else { return false };
            let root = self.ratchets.get(target_fp).map(|r| match &r.prev_root_key {
                Some(prev) if m.header.rotation_kyber_ciphertext.is_some() => prev.clone(),
                _ => r.root_handle_now(),
            });
            match root {
                Some(root_key) => {
                    let deposit = server_seal::deposit_secret(&box_secret, &mailbox);
                    let sealed = server_seal::seal_envelope(&root_key, &mailbox, &m.header.sender_device_fingerprint, bytes);
                    deposit.and_then(|d| sealed.map(|s| (mailbox, d, s)))
                }
                None => Err("no ratchet session key".to_string()),
            }
        };
        let (mailbox, deposit_secret, sealed) = match sealed {
            Ok(v) => v,
            Err(e) => {
                warn!("Could not seal envelope, skipping server: {}", e);
                return false;
            }
        };

        if sealed.len() > MAX_DEPOSIT_BYTES {
            // Wire cap (`typeon_crypto::server_proto::MAX_DEPOSIT_BYTES`). It is better not to try and to fall back to the direct path than to send a
            // silently truncated, corrupt packet.
            warn!("Envelope exceeds server cap ({} bytes), direct path only", sealed.len());
            return false;
        }

        // See `SERVER_DEPOSIT_BACKOFF_MS`. A server that refused a deposit for quota or rate reasons gets no new
        // deposits for a while. Otherwise every poll turn would produce the same error, a busy loop.
        let now_ms = mono_ms();
        let candidates: Vec<String> = self
            .servers
            .iter()
            .filter(|s| s.route_messages)
            .filter(|s| {
                self.server_rt
                    .get(&s.server_id)
                    .map(|r| r.connected && r.enrolled && now_ms >= r.deposit_backoff_until
                        // The server's own item limit. Over it the answer is TooLarge, which used to back off
                        // every deposit.
                        && r.limits.as_ref().map_or(true, |l| sealed.len() as u64 <= l.max_item_bytes as u64))
                    .unwrap_or(false)
            })
            // "Not on this server" and "mailbox full here" are remembered per server, so one server's answer does not
            // close the others.
            .filter(|s| {
                self.server_unknown_mailboxes
                    .get(&(s.server_id.clone(), mailbox.clone()))
                    .map_or(true, |until| now_ms >= *until)
            })
            .map(|s| s.server_id.clone())
            .collect();
        if candidates.is_empty() {
            // Once a minute. Every retry of every pending packet comes through here.
            static LAST_LOG_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            if now_ms.saturating_sub(LAST_LOG_MS.load(std::sync::atomic::Ordering::Relaxed)) >= 60_000 {
                LAST_LOG_MS.store(now_ms, std::sync::atomic::Ordering::Relaxed);
                info!(
                    "Server skipped (no connected+registered server for this mailbox; {} configured)",
                    self.servers.len()
                );
            }
            return false;
        }

        // A `Message` ID is per mailbox. A group text goes to every member under one ID, and the second member's
        // copy was skipped as already done.
        let dedup_key = match envelope {
            NetworkEnvelope::Message(_) => format!("{}|{}", mailbox, deposit_dedup_key(envelope, bytes)),
            _ => deposit_dedup_key(envelope, bytes),
        };
        // Withdraws this copy (`cancel_server_deposit`). Per box and message, so the server cannot match copies across
        // boxes by it.
        let Ok(cancel_secret) = server_seal::cancel_secret(&deposit_secret, &dedup_key) else { return false };
        let cancel_secret = CancelSecret::new(cancel_secret);
        let mut any = false;
        for server_id in candidates {
            // Already on this server's disk: re-deposit (see `P2PCore.server_deposited`). We still count it as
            // deposited. For the caller the result is the same, and the envelope is on the server.
            if self.already_deposited(&server_id, &dedup_key) {
                any = true;
                continue;
            }
            if lazy_hold && !self.anon_conns.contains_key(&server_id) {
                continue;
            }
            let req = ServerRequest::Deposit {
                mailbox: mailbox.clone(),
                deposit_secret: deposit_secret.to_vec(),
                cancel_hash: server_proto::cancel_hash(cancel_secret.bytes()).to_vec(),
                sealed: sealed.clone(),
            };
            // The envelope TYPE goes into the log. Without it, a loop of the same two envelopes being deposited
            // forever cannot be traced. On a real device this happened, and the type had to be guessed (handshake?
            // IdentityExchange? DeviceAddNotice?).
            info!(
                "Handing to server: mailbox={} bytes={} type={}",
                mailbox_log_id(&mailbox),
                sealed.len(),
                envelope_kind(envelope)
            );
            let inflight = ServerInflight::Deposit {
                server_id: server_id.clone(),
                mailbox: mailbox.clone(),
                envelope: envelope.clone(),
                target_fp: target_fp.to_string(),
                first_attempt_at,
                dedup_key: dedup_key.clone(),
                cancel_secret: cancel_secret.clone(),
                cancelled: false,
            };
            if self.anon_send(&server_id, req, inflight) {
                // Mark NOW, before the reply. The reply over Tor takes seconds, and in that window
                // `awaiting_confirmation` deposited the same envelope again (measured on a device: the same message_id
                // twice, 5.7 s apart). If the deposit fails, `handle_server_failure` reverts the mark. The mark is now
                // independent of the envelope type (see `deposit_dedup_key`).
                self.note_server_deposit(&server_id, &dedup_key);
                any = true;
            }
        }
        any
    }

    /// See `lazy_deposit_held`. Bounded: past 1024 entries, those older than any hold are dropped.
    pub(crate) fn note_lazy_deposit(&mut self, message_id: &str) {
        let now = mono_ms();
        if self.lazy_deposits.len() >= 1024 {
            self.lazy_deposits.retain(|_, t| now.saturating_sub(*t) < crate::LAZY_DEPOSIT_MAX_AGE_MS);
        }
        self.lazy_deposits.entry(message_id.to_string()).or_insert(now);
    }

    /// Battery: a non-urgent packet (`note_lazy_deposit`: Seen, ReadStateSync, typing) sent while the app is in
    /// radio-saver mode does not open an anonymous connection (a Tor circuit) at once. It goes to a server whose
    /// anonymous connection is open anyway (an urgent deposit's burst: messages, acks, handshakes, call signals, edits,
    /// deletes), or at most `LAZY_DEPOSIT_HOLD_MS` later. With the screen in use nothing is held. No timer: the pending
    /// queue tries it again on its own turns.
    pub(crate) fn lazy_deposit_held(&self, envelope: &NetworkEnvelope) -> bool {
        let NetworkEnvelope::Message(m) = envelope else { return false };
        let Some(&first) = self.lazy_deposits.get(&m.header.message_id) else { return false };
        self.radio_saver() && mono_ms().saturating_sub(first) < crate::LAZY_DEPOSIT_HOLD_MS
    }

    /// See `P2PCore.server_deposited`. Records a successful deposit and bounds the map.
    pub(crate) fn note_server_deposit(&mut self, server_id: &str, dedup_key: &str) {
        let now = current_time_ms();
        self.server_deposited.insert((server_id.to_string(), dedup_key.to_string()), now);
        if self.server_deposited.len() > MAX_SERVER_DEPOSIT_MEMORY {
            self.server_deposited
                .retain(|_, t| now.saturating_sub(*t) < SERVER_DEPOSIT_MEMORY_MS);
            // If still full (all entries recent), drop the oldest.
            if self.server_deposited.len() > MAX_SERVER_DEPOSIT_MEMORY {
                let mut by_age: Vec<((String, String), u64)> =
                    self.server_deposited.iter().map(|(k, v)| (k.clone(), *v)).collect();
                by_age.sort_by_key(|(_, t)| *t);
                let drop_count = by_age.len() - MAX_SERVER_DEPOSIT_MEMORY;
                for (k, _) in by_age.into_iter().take(drop_count) {
                    self.server_deposited.remove(&k);
                }
            }
        }
    }

    /// Has this envelope already been deposited to this server recently?
    pub(super) fn already_deposited(&self, server_id: &str, dedup_key: &str) -> bool {
        let key = (server_id.to_string(), dedup_key.to_string());
        self.server_deposited
            .get(&key)
            .map(|t| current_time_ms().saturating_sub(*t) < SERVER_DEPOSIT_MEMORY_MS)
            .unwrap_or(false)
    }

    /// Forgets the "already deposited to this server" memory for a `message_id`.
    ///
    /// `already_deposited`
    /// looked only at `message_id`, not at the ciphertext. A regenerated copy (see `retry_unconfirmed_messages` and
    /// `regen_pending_for_peer`) keeps the SAME `message_id` but has a COMPLETELY NEW ciphertext. The old memory
    /// therefore blocked that fresh copy from the server for up to 7 days (see `SERVER_DEPOSIT_MEMORY_MS`). The server,
    /// where the recipient could reach it while offline, kept only the OLD copy, which could no longer be decrypted
    /// after a ratchet rotation. The fresh copy went only over the direct path, which fails when the recipient is offline.
    /// Clearing the memory on regeneration lets the new ciphertext reach the mailbox. If the recipient gets both
    /// copies, `message_exists_with_id` deduplicates them.
    ///
    /// When a user cancels a pending message, the server copy is also WITHDRAWN.
    /// Before, cancel cleared only the local queue. If the packet had been deposited, it stayed on the server for
    /// up to 14 days (the mailbox TTL) while the recipient was offline and was eventually delivered. So "I changed my mind" had no effect.
    /// The server deletes the row only for the cancel secret its `Deposit` committed to, so nobody else can delete it.
    pub(crate) fn cancel_server_deposit(&mut self, message_id: &str) {
        // No location yet for a Deposit still in flight: flag it, and the `Deposited` arm withdraws it.
        for inflight in self.anon_inflight_mut() {
            if let ServerInflight::Deposit { envelope: NetworkEnvelope::Message(m), cancelled, .. } = inflight {
                if m.header.message_id == message_id {
                    *cancelled = true;
                }
            }
        }
        // Keyed `(server, "mailbox|message_id")`: one entry per target. The entry stays until the server answers
        // (`ServerInflight::Cancel`), so a cancel lost with its connection is sent again (`resend_cancels`).
        let targets: Vec<(String, String)> = self
            .server_deposit_locations
            .iter_mut()
            .filter(|((_, key), _)| location_message_id(key) == message_id)
            .map(|(k, loc)| {
                loc.cancelling = true;
                k.clone()
            })
            .collect();
        for (server_id, key) in targets {
            self.send_cancel(&server_id, &key);
        }
    }

    /// `ServerRequest::Cancel` for the location `key` (`server_deposit_locations`) over the anonymous connection, like
    /// the deposit it withdraws. Not twice at once.
    pub(super) fn send_cancel(&mut self, server_id: &str, key: &str) {
        let k = (server_id.to_string(), key.to_string());
        let Some(loc) = self.server_deposit_locations.get(&k) else { return };
        let req = ServerRequest::Cancel { mailbox: loc.mailbox.clone(), seq: loc.seq, cancel_secret: loc.cancel.bytes().to_vec() };
        let busy = self.anon_inflight_mut().any(|i| matches!(i, ServerInflight::Cancel { server_id: s, key: kk } if *s == k.0 && *kk == k.1));
        if !busy {
            self.anon_send(server_id, req, ServerInflight::Cancel { server_id: k.0, key: k.1 });
        }
    }

    /// Cancels the server never answered: sent again, at the server sweep, to a server ready for deposits.
    pub(super) fn resend_cancels(&mut self) {
        let now = mono_ms();
        let due: Vec<(String, String)> = self
            .server_deposit_locations
            .iter()
            .filter(|((sid, _), loc)| {
                loc.cancelling
                    && self.server_rt.get(sid).map_or(false, |r| r.connected && r.enrolled && now >= r.deposit_backoff_until)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for (sid, key) in due {
            self.send_cancel(&sid, &key);
        }
    }

    /// Only the "already deposited" marks: the old copy is still on the server, and a cancel must still find it.
    pub(crate) fn forget_server_deposit(&mut self, message_id: &str) {
        self.server_deposited.retain(|(_, key), _| location_message_id(key) != message_id);
    }

    pub(super) fn server_fetch(&mut self, server_id: &str, peer_id: PeerId, own_ids: &HashSet<String>) {
        // Nothing is taken before the storage keys are loaded: a fetched item would wait in `deferred_incoming`,
        // where it can be evicted. Nor while fetched mail waits for its rate budget: the backlog stays one batch.
        if !self.storage_keys_ready() || self.server_mail_deferred() {
            return;
        }
        // If a `Fetch` is already in flight, do not send a second one (see `ServerRuntime.fetch_inflight`).
        if self.server_rt.get(server_id).map(|r| r.fetch_inflight).unwrap_or(false) {
            return;
        }
        // Cursors of mailboxes that are no longer ours (a deleted session or contact).
        let stale: Vec<(String, String)> = self
            .server_cursors
            .keys()
            .filter(|(sid, mb)| sid == server_id && !own_ids.contains(mb))
            .cloned()
            .collect();
        for key in stale {
            self.server_cursors.remove(&key);
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1 AND mailbox_id = ?2", params![key.0, key.1]);
            }
        }
        // The same stable part `server_sweep` registers when over the cap. Refused IDs are skipped there too, or a
        // registered ID past them fell out of every `Fetch`.
        let (cap, refused) = self.server_rt.get(server_id).map_or((1, HashSet::new()), |rt| (Self::mailbox_cap(rt), rt.refused.clone()));
        let mut ids: Vec<&String> = own_ids.iter().filter(|id| !refused.contains(*id)).collect();
        ids.sort();
        ids.truncate(cap);
        let cursors: Vec<(String, u64)> = ids
            .into_iter()
            .map(|mb| {
                let seq = self.server_cursors.get(&(server_id.to_string(), mb.clone())).copied().unwrap_or(0);
                (mb.clone(), seq)
            })
            .collect();
        if cursors.is_empty() {
            return;
        }
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.fetch_due_at = mono_ms() + SERVER_FETCH_SWEEP_INTERVAL_MS;
        }
        let req = ServerRequest::Fetch {
            cursors,
            max_items: MAX_FETCH_BATCH_ITEMS,
            max_bytes: MAX_FETCH_BATCH_BYTES,
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::Fetch { server_id: server_id.to_string() });
            // Set only for a request that actually went out. Set before a failed send, it stayed true, and nothing was
            // fetched until the next reconnect.
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.fetch_inflight = true;
            }
        }
    }

    /// The server's mailbox cap (from the `Welcome`/`Enrolled` limits, or the protocol default before those). A longer
    /// list is refused whole.
    pub(super) fn mailbox_cap(rt: &ServerRuntime) -> usize {
        rt.limits.as_ref().map_or_else(|| ServerLimits::default().max_mailboxes, |l| l.max_mailboxes).max(1) as usize
    }

    /// Acks what the batches of earlier calls brought, once that mail has gone through `process_incoming_envelope`.
    /// `poll_events` calls this after its incoming loop. `drive_server_sync` calls it too, for the turns before.
    /// Acked before processing, a crash in between would lose the only copy.
    pub(crate) fn commit_server_fetches(&mut self) {
        // Fetched mail still waits for its rate budget. Acked now, a crash before it is processed would lose it.
        if self.server_mail_deferred() {
            return;
        }
        let now = mono_ms();
        // This turn's items were processed. Failures were reported (`server_item_failed`). Held and passed items that
        // the cursor went past are done.
        let cursors = &self.server_cursors;
        // Items still deferred (keys not ready) keep their record, so a later failure can still hold them
        // (`server_item_failed`).
        let deferred: std::collections::HashSet<[u8; 32]> =
            self.deferred_incoming.iter().filter(|(s, _)| s.is_none()).map(|(_, r)| Sha256::digest(r).into()).collect();
        let mut refetch = false;
        for (sid, rt) in self.server_rt.iter_mut() {
            rt.taken.retain(|d, _| deferred.contains(d));
            let below = |mb: &String, seq: u64| cursors.get(&(sid.clone(), mb.clone())).map_or(true, |c| *c < seq);
            // A held item the cursor went past was processed: its mailbox is healthy again.
            let cleared: Vec<String> = rt.held.iter().filter(|(mb, (seq, _))| !below(*mb, *seq)).map(|(mb, _)| mb.clone()).collect();
            for mb in &cleared {
                rt.hold_strikes.remove(mb);
            }
            rt.held.retain(|mb, (seq, _)| below(mb, *seq));
            rt.passed.retain(|(mb, seq)| below(mb, *seq));
            // This turn's items are processed, so a rotation they carried is applied: fetch the held item again now.
            if std::mem::take(&mut rt.refetch_now) {
                rt.fetch_due_at = 0;
                refetch = true;
            }
        }
        if refetch {
            self.server_sweep_at = 0;
        }
        let due: Vec<String> = self
            .server_rt
            .iter()
            .filter(|(_, rt)| !rt.unacked.is_empty() && rt.connected && rt.enrolled && now >= rt.ack_retry_at)
            .map(|(sid, _)| sid.clone())
            .collect();
        for sid in due {
            // One Ack in flight per server: a late `Ok` cannot persist an older position after a newer one.
            if self.server_inflight.values().any(|i| matches!(i, ServerInflight::Ack { .. }) && i.server_id() == sid) {
                continue;
            }
            let Some(rt) = self.server_rt.get_mut(&sid) else { continue };
            let Some(peer_id) = rt.peer_id else { continue };
            let cap = Self::mailbox_cap(rt);
            let keys: Vec<String> = rt.unacked.keys().take(cap).cloned().collect();
            let acks: Vec<(String, u64)> = keys.into_iter().filter_map(|k| rt.unacked.remove_entry(&k)).collect();
            match self.send_server_request(peer_id, ServerRequest::Ack { acks: acks.clone() }) {
                Some(id) => {
                    self.server_inflight.insert(id, ServerInflight::Ack { server_id: sid, acks });
                }
                None => self.restage_acks(&sid, acks),
            }
        }
    }

    /// An `Ack` that did not go through: retry after one sweep interval.
    pub(super) fn restage_acks(&mut self, server_id: &str, acks: Vec<(String, u64)>) {
        let Some(rt) = self.server_rt.get_mut(server_id) else { return };
        for (mailbox, seq) in acks {
            let e = rt.unacked.entry(mailbox).or_insert(0);
            *e = (*e).max(seq);
        }
        rt.ack_retry_at = mono_ms() + SERVER_SWEEP_INTERVAL_MS;
    }

    /// `seq` of `mailbox` did not open, or failed to process. `true`: it holds the mailbox's cursor (not acked, so
    /// the server keeps it). `false`: it has failed for `SERVER_HOLD_GRACE_MS` and is passed over for good.
    pub(crate) fn hold_server_item(&mut self, server_id: &str, mailbox: &str, seq: u64, now: u64) -> bool {
        let Some(rt) = self.server_rt.get_mut(server_id) else { return false };
        let strikes = rt.hold_strikes.get(mailbox).copied().unwrap_or(0);
        let e = rt.held.entry(mailbox.to_string()).or_insert((seq, now));
        // A lower item holds the cursor: this one waits behind it and must not restart that item's timer. Otherwise
        // two failing items would keep resetting each other.
        if seq > e.0 {
            return true;
        }
        if seq < e.0 {
            *e = (seq, now);
        }
        // `SERVER_HOLD_MAX_STRIKES` passes in a row: this mailbox gets no more grace until a hold clears.
        if strikes < SERVER_HOLD_MAX_STRIKES && now.saturating_sub(e.1) < SERVER_HOLD_GRACE_MS {
            return true;
        }
        warn!("Server item could not be opened/processed, skipping (mailbox={}, strikes={})", mailbox_log_id(mailbox), strikes);
        rt.held.remove(mailbox);
        rt.passed.insert((mailbox.to_string(), seq));
        *rt.hold_strikes.entry(mailbox.to_string()).or_insert(0) += 1;
        false
    }

    /// 5 min, doubling to 30 min while the server keeps refusing or not answering deposits. A `Deposited` resets it.
    pub(super) fn back_off_deposits(rt: &mut ServerRuntime) {
        rt.deposit_backoff_until = mono_ms()
            + (SERVER_DEPOSIT_BACKOFF_MS << rt.deposit_failures.min(3)).min(SERVER_DEPOSIT_BACKOFF_MAX_MS);
        rt.deposit_failures = rt.deposit_failures.saturating_add(1);
    }

    /// A fetch soon for a held item, not at the next safety sweep.
    pub(super) fn refetch_held(&mut self, server_id: &str, now: u64) {
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.fetch_due_at = rt.fetch_due_at.min(now + SERVER_HOLD_REFETCH_MS);
        }
    }

    /// Was the fetched item `raw` (as handed to `incoming` this turn) taken from a mailbox only `sender_fp` fills? A session
    /// mailbox is sealed with the session root key and the sender's fingerprint, so its other end is proven. A first-contact
    /// mailbox counts only when its secret is the pairing code we hold for that device (`pn:`/`pk:`), not a code shown to anyone
    /// or a group secret every member has: such a mailbox proves nothing either way (`None`). `None` too: not an item of this turn.
    pub(crate) fn server_item_sender(&self, raw: &[u8], sender_fp: &str) -> Option<bool> {
        let digest: [u8; 32] = Sha256::digest(raw).into();
        let carrier = self.server_rt.values().find_map(|rt| rt.taken.get(&digest).map(|(_, _, c)| c))?;
        Some(match carrier {
            ItemCarrier::Session(peer_fp) => peer_fp == sender_fp,
            ItemCarrier::FirstContact(secret) => {
                if !self.stored_pairing_secrets(sender_fp).contains(&**secret) {
                    return None;
                }
                true
            }
        })
    }

    /// `process_incoming_envelope` failed on a fetched item (`raw`, as handed to `incoming`). Its mailbox's cursor
    /// goes back before it, so this turn's Ack does not let the server delete it. It is fetched again
    /// (`hold_server_item`). `poll_events` calls this for each `Err` of a packet with no source peer.
    pub(crate) fn server_item_failed(&mut self, raw: &[u8]) {
        let digest: [u8; 32] = Sha256::digest(raw).into();
        let found = self.server_rt.iter_mut().find_map(|(sid, rt)| rt.taken.remove(&digest).map(|t| (sid.clone(), t)));
        let Some((server_id, (mailbox, seq, _))) = found else { return };
        let now = mono_ms();
        if !self.hold_server_item(&server_id, &mailbox, seq, now) {
            return;
        }
        let key = (server_id.clone(), mailbox.clone());
        if let Some(c) = self.server_cursors.get_mut(&key) {
            *c = (*c).min(seq - 1);
        }
        if let Some(rt) = self.server_rt.get_mut(&server_id) {
            if let Some(e) = rt.unacked.get_mut(&mailbox) {
                *e = (*e).min(seq - 1);
            }
        }
        self.refetch_held(&server_id, now);
    }

    /// Immediately hands an envelope that could not be deposited to the server back to the publish path.
    pub(super) fn requeue_failed_deposit(&mut self, inflight: &ServerInflight) {
        if let ServerInflight::Deposit { envelope, target_fp, first_attempt_at, cancelled, .. } = inflight {
            // Withdrawn by the user, or confirmed in the meantime: nothing to resend.
            if *cancelled {
                return;
            }
            let envelope = envelope.clone();
            let target_fp = target_fp.clone();
            // NOT `publish_envelope`: that one queues the entry with `current_time_ms()`, and would reset the envelope's age on
            // every server round trip. See the `first_attempt_at` note of `ServerInflight::Deposit`. This is the second half of the endless queue cycle.
            if let Err(e) = self.publish_envelope_at(&target_fp, &envelope, *first_attempt_at) {
                warn!("Server failed, re-publish also failed right away (queued): {}", e);
            }
        }
        if let ServerInflight::BlobPut { blob_id, chunk_index, server_id, .. } = inflight {
            // Drop from the in-flight set. It is requested again on the next turn.
            if let Some(up) = self.server_blob_uploads.iter_mut().find(|u| u.file_id == *blob_id) {
                up.inflight.remove(chunk_index);
                // Timeout or error means the path was overloaded. Halve the window. Backing off is necessary before retries eat
                // the bandwidth and push throughput lower still (measured: with a fixed window of 16, throughput fell from 180 KB/s to about 50 KB/s).
                up.window = (up.window / 2).max(BLOB_WINDOW_MIN);
                warn!("Chunk timeout/error — window set to {}", up.window);
            }
            // One of the parallel circuits may have died: a dead connection swallows 1/N of the requests. Do not decide on a
            // single event. One timeout on Tor is noise (see `note_bulk_timeout`). Only the server this chunk went to is affected.
            if let Some(p) = self.server_rt.get(server_id).and_then(|r| r.peer_id) {
                self.note_bulk_timeout(p);
            }
        }
    }

}

/// See `session_mailbox`. Holds mailbox proof secrets, so `wipe_all_local_state` clears it.
static SESSION_MAILBOX_MEMO: std::sync::Mutex<Option<HashMap<[u8; 32], (String, [u8; 32])>>> = std::sync::Mutex::new(None);

pub(crate) fn clear_session_mailbox_memo() {
    if let Ok(mut memo) = SESSION_MAILBOX_MEMO.lock() {
        if let Some(entries) = memo.as_mut() {
            wipe_memo_secrets(entries);
        }
        *memo = None;
    }
}

/// Zeroes the proof secrets before the memo entries are dropped.
fn wipe_memo_secrets(memo: &mut HashMap<[u8; 32], (String, [u8; 32])>) {
    for (_, secret) in memo.values_mut() {
        zeroize::Zeroize::zeroize(secret);
    }
}

/// A mailbox ID is a read capability. Logs show 24 bits of its hash, never a part of the ID itself.
/// The signing keys of a mailbox's `Register` proof (`server_seal::mailbox_proof_seeds`).
pub(super) fn mailbox_proof_keys(secret: &[u8], mailbox: &str) -> Option<(SigningKey, MlDsaSigningKey<MlDsa87>)> {
    let (seed, seed_pq) = server_seal::mailbox_proof_seeds(secret, mailbox).ok()?;
    let seed_pq: ml_dsa::Seed = seed_pq.as_slice().try_into().ok()?;
    Some((SigningKey::from_bytes(&seed), MlDsaSigningKey::<MlDsa87>::from_seed(&seed_pq)))
}

/// The server ID of a mailbox whose readers all hold `secret` (a session box: the session secret; a call relay box: the pair key).
/// It is a hash of the box's proof key (`server_proto::key_bound_mailbox_id`). The sender, who holds the same secret, computes it too.
/// The server refuses a `Register` from any other key, so knowing the ID does not make a reader.
///
/// Memoized per secret: an ML-DSA-87 key is derived for each, and this runs for every session on each sweep, fetch and deposit.
// ponytail: the memo is dropped whole past 4096 entries. Use an LRU if a device ever holds that many live sessions.
pub(crate) fn key_bound_mailbox_id(secret: &[u8]) -> Option<String> {
    static MEMO: std::sync::Mutex<Option<HashMap<[u8; 32], String>>> = std::sync::Mutex::new(None);
    let tag: [u8; 32] = Sha256::digest(secret).into();
    if let Some(id) = MEMO.lock().ok()?.get_or_insert_with(HashMap::new).get(&tag) {
        return Some(id.clone());
    }
    let (signing, signing_pq) = mailbox_proof_keys(secret, server_proto::KEY_BOUND_MAILBOX_PREFIX)?;
    let hash = server_proto::mailbox_key_hash(&signing.verifying_key().to_bytes(), &signing_pq.verifying_key().encode());
    let id = server_proto::key_bound_mailbox_id(&hash);
    let mut memo = MEMO.lock().ok()?;
    let memo = memo.get_or_insert_with(HashMap::new);
    if memo.len() >= 4096 {
        memo.clear();
    }
    memo.insert(tag, id.clone());
    Some(id)
}

pub(super) fn mailbox_log_id(id: &str) -> String {
    hex::encode(&Sha256::digest(id.as_bytes())[..3])
}

/// Short type name of an envelope, for logging. See `try_server_deposit`.
/// The "have I already deposited this envelope to this server?" key.
///
/// Before this was fixed, `already_deposited` and `note_server_deposit` recognized only the `NetworkEnvelope::Message` arm (`m.header.message_id`)
/// and returned `false` for every other type. `Handshake` and `IdentityExchange` cannot enter `awaiting_confirmation`, so their only safety net was
/// the `pending_envelopes` queue, which is retried on EVERY poll turn. They were re-deposited to the server about once a second. Each was about 15 KB,
/// so the depositor's `bytes_mail` quota (256 MB) filled within a few hours. From then on every server delivery of that device, to ANY peer, got
/// `QuotaExceeded`. Secondary devices were hit hardest, since reaching them almost always goes through a fresh handshake or the server.
///
/// For `Message` the key is still the `message_id` (so the same message re-serialized is also deduplicated). For other types it is a digest of the
/// envelope bytes, which is stable because the queue retries by cloning the same envelope.
pub(crate) fn deposit_dedup_key(envelope: &NetworkEnvelope, bytes: &[u8]) -> String {
    match envelope {
        NetworkEnvelope::Message(m) => m.header.message_id.clone(),
        _ => {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            format!("raw:{}", hex::encode(&hasher.finalize()[..16]))
        }
    }
}

pub(crate) fn envelope_kind(envelope: &NetworkEnvelope) -> String {
    match envelope {
        NetworkEnvelope::Handshake(_) => "Handshake".to_string(),
        NetworkEnvelope::IdentityExchange(_) => "IdentityExchange".to_string(),
        NetworkEnvelope::Message(m) => format!("Message/{}", m.header.message_id.chars().take(8).collect::<String>()),
    }
}
