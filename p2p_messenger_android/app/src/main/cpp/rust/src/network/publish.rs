//! Publishing envelopes with ack tracking, retries and the pending-message queue.

use super::*;

impl P2PCore {
    /// Raw gossip publish only. Does not queue or update state. Shared by `publish_envelope`
    /// (first attempt) and the retry loop in `poll_events` (later attempts).
    ///
    /// Reliability: the error is typed now. `MessageTooLarge` (gossipsub `max_transmit_size`
    /// exceeded) is permanent: the same bytes can never succeed, however often they are
    /// retried. Before, every error counted as transient and was retried for up to 2 days,
    /// and the user was never told "failed". Also, while `swarm` did not exist yet, publish
    /// silently returned `Ok(())`, marking messages sent without publishing anything. It now
    /// returns a Transient error honestly, and the retry queues take over.
    ///
    /// `first_attempt_at`: time of this envelope's first publish attempt. The server path
    /// carries it into `ServerInflight::Deposit`, so after a server error the envelope
    /// re-queues with the SAME expiry (see there, and the `timeout` calculation in the
    /// `poll_events` retry loop).
    pub(crate) fn try_publish_raw(
        &mut self,
        target_device_fingerprint: &str,
        envelope: &NetworkEnvelope,
        first_attempt_at: u64,
    ) -> Result<(), PublishFailure> {
        self.try_publish_raw_via(target_device_fingerprint, envelope, first_attempt_at, true)
    }

    /// See `ENVELOPE_PROTOCOL`. `false` = no mapped peer and no swarm. The target is the
    /// mapped PeerId of the device. For an IdentityExchange or Handshake only, it is the
    /// connection the IdentityExchange came in on.
    pub(super) fn direct_peer_for(&self, fp: &str, envelope: &NetworkEnvelope) -> Option<PeerId> {
        self.device_to_peer_id.get(fp).copied().or_else(|| match envelope {
            NetworkEnvelope::IdentityExchange(_) | NetworkEnvelope::Handshake(_) => self.pairing_reply_peer.get(fp).copied(),
            _ => None,
        })
    }

    pub(crate) fn send_envelope_direct(&mut self, fp: &str, envelope: &NetworkEnvelope, bytes: Vec<u8>, first_attempt_at: u64, retried: bool) -> bool {
        let (Some(pid), Some(swarm)) = (self.direct_peer_for(fp, envelope), self.swarm.as_mut()) else { return false };
        let request_id = swarm.behaviour_mut().envelopes.send_request(&pid, EnvelopeRequest { bytes });
        self.envelopes_inflight.insert(request_id, (fp.to_string(), envelope.clone(), first_attempt_at, retried));
        true
    }

    /// `allow_direct = false`: the `ENVELOPE_PROTOCOL` attempt already failed,
    /// so use gossipsub/server.
    pub(crate) fn try_publish_raw_via(
        &mut self,
        target_device_fingerprint: &str,
        envelope: &NetworkEnvelope,
        first_attempt_at: u64,
        allow_direct: bool,
    ) -> Result<(), PublishFailure> {
        // Blocking is a one-way check. Incoming packets were dropped and no dial was made, but the send path had no check at all:
        // `announce_address_to_all_contacts`, `set_own_profile_picture`, group fan-out and the queue kept sending packets to a blocked
        // contact, which leaked our address and online status.
        //
        // This is the single exit point of all outgoing envelopes (message, edit, delete, ack, handshake, identity, file offer,
        // group update). Returns `Permanent` so the retry queue never takes the envelope.
        if self.is_blocked_device(target_device_fingerprint) {
            return Err(PublishFailure::Permanent(
                "Recipient is blocked; not sent".to_string(),
            ));
        }
        if self.known_remote_devices.get(target_device_fingerprint)
            .map_or(false, |d| self.deleted_identities.contains(&d.identity_id))
        {
            return Err(PublishFailure::Permanent("Recipient deleted their account; not sent".to_string()));
        }
        let bytes = ciborium_bytes(envelope).map_err(PublishFailure::Permanent)?;
        // Every path caps at 1 MiB (gossipsub `max_transmit_size`, the cbor
        // request-response default, the server). The direct path has no check
        // of its own: it reported "sent" and the request then failed, again
        // on every retry for days.
        // Headroom: gossipsub measures the whole protobuf frame (topic, seqno,
        // ...) against the cap, so an envelope of exactly 1 MiB never went out.
        if bytes.len() + 4096 > MAX_ENVELOPE_BYTES {
            return Err(PublishFailure::Permanent(format!("Envelope too large ({} bytes)", bytes.len())));
        }
        let mailbox_topic = || format!("p2p_msg_{}", target_device_fingerprint);
        // A ratchet session normally routes by the rotating topic derived from `root_key` (see `topic_for_root_key`). Two exceptions
        // use the mailbox topic (`p2p_msg_<fingerprint>`) instead, because the peer cannot yet derive the rotating topic:
        //
        // 1. `Handshake` and `IdentityExchange` always use the mailbox topic, even when a ratchet record exists. `initiate_handshake_with`
        //    inserts the ratchet into `self.ratchets` before publishing HandshakeInit, so a plain lookup would wrongly pick the rotating
        //    topic. The peer does not have the root key yet and cannot subscribe to it.
        // 2. A `Message` that announces a rotation (`rotation_kyber_ciphertext` set) uses the topic of the previous root key (`prev_root_key`).
        //    The peer cannot learn the new root key before it receives this packet. Ordinary messages use the current `root_key` topic.
        let topic = match envelope {
            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => mailbox_topic(),
            NetworkEnvelope::Message(packet) if packet.header.rotation_kyber_ciphertext.is_some() => {
                match self.ratchets.get(target_device_fingerprint).and_then(|r| r.prev_root_key.as_ref()) {
                    Some(prev_root_key) => Self::topic_for_root_key(prev_root_key),
                    None => mailbox_topic(),
                }
            }
            _ => match self.ratchets.get(target_device_fingerprint) {
                Some(ratchet) => Self::topic_for_root_key(&ratchet.root_handle_now()),
                None => mailbox_topic(),
            },
        };
        // Server path (see `server_client`). Topic choice stays as above. The server uses a blinded form of the same topic string as the
        // mailbox id. So both exceptions above carry over to the server path as well.
        let topic_str = topic;
        // If a live libp2p connection exists (LAN, Tor or relay), try that path first. The server copy is kept only if the envelope is
        // still unacknowledged at the first retry (`ACK_RETRY_INITIAL_MS`). Before, with a server configured, two phones on the same LAN
        // uploaded every message over Tor to the server for the first 30 s (about 15 KB per message plus a Tor round trip).
        // The guarantee is unchanged: without an Ack, the envelope falls back to the server.
        // Handshake, IdentityExchange and rotation announcements always go by both paths (`critical` below).
        let direct = self.direct_peer_for(target_device_fingerprint, envelope)
            .map_or(false, |p| self.swarm.as_ref().map_or(false, |s| s.is_connected(&p)));
        let critical = self.call_signal_sending || match envelope {
            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => true,
            NetworkEnvelope::Message(m) => m.header.rotation_kyber_ciphertext.is_some(),
        };
        let unconfirmed_past_first_retry = match envelope {
            NetworkEnvelope::Message(m) => self.awaiting_confirmation.get(&m.header.message_id)
                .map_or(false, |pc| current_time_ms().saturating_sub(pc.first_sent_at) >= ACK_SUSPECT_MS),
            _ => false,
        };
        let mut deposited = (!direct || critical || unconfirmed_past_first_retry)
            && self.try_server_deposit(target_device_fingerprint, &topic_str, envelope, &bytes, first_attempt_at);
        // See `ENVELOPE_PROTOCOL`. Failure falls back to gossipsub/server in
        // `poll_events` (`EnvelopeEventLocal::Failed`).
        if direct && allow_direct && self.send_envelope_direct(target_device_fingerprint, envelope, bytes.clone(), first_attempt_at, false) {
            return Ok(());
        }
        // No direct path, or it failed: the server copy is the delivery
        // (gossipsub is gone, ). Without one the envelope is queued.
        if !deposited && direct {
            deposited = self.try_server_deposit(target_device_fingerprint, &topic_str, envelope, &bytes, first_attempt_at);
        }
        if deposited {
            Ok(())
        } else {
            Err(PublishFailure::Transient("Not found: no connection to target and server copy could not be left".to_string()))
        }
    }

    /// Publishes any envelope (Handshake, IdentityExchange, Message, GroupUpdate, ...) to the peer's gossip topic. Right after the first
    /// connection the gossip mesh may not exist yet, and the publish fails with `InsufficientPeers` or `NoPeersSubscribedToTopic`.
    /// Every failed envelope is queued in `pending_envelopes`. `poll_events` resends the SAME envelope each turn (no re-encryption and
    /// no re-signing). This is one central mechanism for all envelope types, replacing per-caller queues that did not cover
    /// HandshakeInit. For a `Message`, `message_status` is updated too (the UI shows send and error icons from it).
    pub(crate) fn publish_envelope(&mut self, target_device_fingerprint: &str, envelope: &NetworkEnvelope) -> Result<(), String> {
        self.publish_envelope_at(target_device_fingerprint, envelope, current_time_ms())
    }

    /// Adds to `pending_envelopes` unless the same envelope is already queued for this target. Keys are cached per entry, so only
    /// the new one is encoded.
    pub(crate) fn enqueue_pending(&mut self, queued: QueuedEnvelope) {
        let already_queued = queued.key.is_some()
            && self.pending_envelopes.iter().any(|q| q.target == queued.target && q.key == queued.key);
        if !already_queued {
            self.pending_envelopes.push(queued);
        }
    }

    /// Like `publish_envelope`, but the caller sets the envelope's age counter. The server-failure requeue path passes the ORIGINAL
    /// time. See `server_client::requeue_failed_deposit`.
    pub(crate) fn publish_envelope_at(
        &mut self,
        target_device_fingerprint: &str,
        envelope: &NetworkEnvelope,
        first_attempt_at: u64,
    ) -> Result<(), String> {
        match self.try_publish_raw(target_device_fingerprint, envelope, first_attempt_at) {
            Err(PublishFailure::Permanent(e)) => {
                // See `PublishFailure`. A retry can never succeed, so do not queue it. Mark Failed now and notify the UI.
                if let NetworkEnvelope::Message(m) = envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                    self.attachment_events.push(serde_json::json!({
                        "type": "status", "peer": self.canonical_peer_key(target_device_fingerprint),
                        "message_id": m.header.message_id, "status": "error"
                    }).to_string());
                }
                Err(e)
            }
            Err(PublishFailure::Transient(e)) => {
                if let NetworkEnvelope::Message(m) = envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Pending);
                }
                // If the same envelope is already queued for this target, do not add a second copy. Each server round trip
                // left one more copy, and the queue (and the redeposit every second) grew exponentially.
                // `NetworkEnvelope` does not derive `PartialEq` (packets hold raw bytes). So identity uses the deduplication key the
                // server path already uses.
                self.enqueue_pending(QueuedEnvelope::new(target_device_fingerprint.to_string(), envelope.clone(), first_attempt_at));
                Err(e)
            }
            Ok(()) => {
                if let NetworkEnvelope::Message(m) = envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                }
                Ok(())
            }
        }
    }

    /// Like `publish_envelope`: it tries once right away and updates the status the same way. Unlike that function, it keeps
    /// re-sending the packet after the first attempt, even on success, until the peer acknowledges it. There is no upper time limit,
    /// unlike `pending_envelopes`.
    ///
    /// `original_sent_at_override` and `retry_interval_ms_override` are `Some` ONLY when called from a `regen_content` regeneration
    /// (see the age branch of `retry_unconfirmed_messages`). They keep the message's first queue time and the backoff reached so far.
    /// Without them, each 25-minute regeneration reset `retry_interval_ms` to `ACK_RETRY_INITIAL_MS` (15 s). A peer offline for days would
    /// then see a 15 s, 30 s, 60 s, 120 s burst every 25 minutes. A message already at the `ACK_RETRY_MAX_MS` (120 s) ceiling now stays
    /// there across regenerations: a steady, predictable pulse of about two minutes.
    pub(crate) fn publish_with_ack_tracking(
        &mut self,
        target_device_fingerprint: &str,
        message_id: &str,
        envelope: NetworkEnvelope,
        regen_content: Option<MessageContent>,
        original_sent_at_override: Option<u64>,
        retry_interval_ms_override: Option<u64>,
    ) {
        let now = current_time_ms();
        match self.try_publish_raw(target_device_fingerprint, &envelope, now) {
            Ok(()) => {
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                }
            }
            // See `PublishFailure`. A permanent error (for example `MessageTooLarge`) must not enter the acknowledgement queue.
            // Mark it Failed now and notify the UI, since a retry can never succeed.
            Err(PublishFailure::Permanent(e)) => {
                error!("Send PERMANENTLY failed (will not retry): {}", e);
                // A refresh of an entry that is already tracked: drop the old
                // entry too, or it stays due and is re-encrypted every turn.
                self.awaiting_confirmation.remove(message_id);
                self.remove_durable_retry(message_id);
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                    self.attachment_events.push(serde_json::json!({
                        "type": "status", "peer": self.canonical_peer_key(target_device_fingerprint),
                        "message_id": m.header.message_id, "status": "error"
                    }).to_string());
                }
                return;
            }
            Err(PublishFailure::Transient(e)) => {
                error!("First send attempt failed (will retry until confirmed): {}", e);
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Pending);
                }
            }
        }
        // The entry is also written to the encrypted DB, so it survives a process kill. Written by reference before the move
        // into the struct. The real start time is stored, not `now`. Otherwise the 7-day give-up window would reset on every refresh.
        let original_sent_at = original_sent_at_override.unwrap_or(now);
        // The packet is stamped with the chain generation it was encrypted under.
        let chain_stamp = self.chain_stamp_for(target_device_fingerprint);
        if let Some(content) = &regen_content {
            self.persist_durable_retry(message_id, target_device_fingerprint, content, original_sent_at, Some((&envelope, chain_stamp.as_str())));
        }
        let retry_interval_ms = retry_interval_ms_override.unwrap_or(ACK_RETRY_INITIAL_MS);
        self.awaiting_confirmation.insert(message_id.to_string(), PendingConfirmation {
            suspect_probed: false,
            direct_delivered: false,
            chain_stamp,
            peer_device_fingerprint: target_device_fingerprint.to_string(),
            envelope,
            next_retry_at: now + retry_interval_ms,
            retry_interval_ms,
            first_sent_at: now,
            original_sent_at,
            last_attempt_at: now,
            regen_content,
        });
    }

    /// Called from `poll_events`. Re-publishes every due entry of `awaiting_confirmation` (without re-encrypting) and grows the next
    /// retry interval exponentially, capped at `ACK_RETRY_MAX_MS`.
    pub(crate) fn retry_unconfirmed_messages(&mut self) {
        // Revoked devices whose last notice had time to go out.
        if !self.revoked_disconnects.is_empty() {
            let now = mono_ms();
            let (due, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.revoked_disconnects).into_iter().partition(|(_, at)| now >= *at);
            self.revoked_disconnects = keep;
            if let Some(swarm) = &mut self.swarm {
                for (peer, _) in due {
                    let _ = swarm.disconnect_peer_id(peer);
                }
            }
        }
        // `poll_events` calls this every turn. Unlike `reconnect_sweep`, `group_sync_sweep` and `periodic_storage_sweep`, this function
        // had no interval check. With an empty `awaiting_confirmation` map, the usual idle case, the filter, map, collect and sort below
        // still allocated and scanned on every turn.
        if self.awaiting_confirmation.is_empty() {
            return;
        }
        let now = current_time_ms();
        // Runs the scan below (whole map, HKDF per peer, sort) at most once a second, not on every poll turn.
        if now.saturating_sub(self.last_unconfirmed_retry_at) < 1_000 {
            return;
        }
        self.last_unconfirmed_retry_at = now;
        // See `KeepAliveState.suspect`. If a connection we think is alive gives no Ack within `ACK_SUSPECT_MS`, probe it now.
        let mut suspects: Vec<PeerId> = Vec::new();
        let mut early_deposit: Vec<(String, NetworkEnvelope)> = Vec::new();
        for p in self.awaiting_confirmation.values_mut() {
            if !p.suspect_probed && !p.direct_delivered && now.saturating_sub(p.first_sent_at) >= ACK_SUSPECT_MS {
                p.suspect_probed = true;
                early_deposit.push((p.peer_device_fingerprint.clone(), p.envelope.clone()));
                if let Some(pid) = self.device_to_peer_id.get(&p.peer_device_fingerprint) {
                    suspects.push(*pid);
                }
            }
        }
        for pid in suspects {
            self.mark_connection_suspect(pid, false);
        }
        // A packet sent directly but unacknowledged within `ACK_SUSPECT_MS` is also left on the server, without waiting for the first
        // 15 s retry (`ACK_RETRY_INITIAL_MS`). If the sender goes offline meanwhile, the message is on the server. Gossip would not
        // re-send the same bytes anyway (it reports `Duplicate`).
        for (fp, envelope) in early_deposit {
            // Server copy only (`allow_direct = false`). The direct copy is in flight, and `try_publish_raw` already sent the envelope once.
            if self.is_connected_to_device(&fp) && !self.ready_server_peers().is_empty() {
                if let Err(PublishFailure::Transient(e) | PublishFailure::Permanent(e)) = self.try_publish_raw_via(&fp, &envelope, now, false) {
                    warn!("Early server copy for suspect peer {} failed: {}", crate::log_id(&fp), e);
                }
            }
        }
        // Important: `awaiting_confirmation` is a `HashMap`. Rust's std `HashMap` uses a randomly seeded hasher (DoS resistance), so the `.iter()`
        // order has nothing to do with composition order. When several messages queue up while the user is offline, a random order could change on
        // every turn. The requirement is that messages not yet sent are retried in composition order. `original_sent_at` is in every
        // `PendingConfirmation`, so sorting `due_ids` by it is enough. A `BTreeMap` would have touched every `.get`, `.get_mut`, `.remove` and
        // `.insert` call site.
        //
        // Fix: the chain generation stamp (see `PendingConfirmation.chain_stamp`) was checked only for in-order packets. A packet whose generation
        // had changed stayed in retry with ciphertext the peer could no longer decrypt, until its backoff (up to 2 minutes) expired. Refreshing
        // right away on a generation change now works as intended.
        //
        // The stamp is computed once per peer (one HKDF step, `topic_for_root_key`), not once per message.
        let mut stamp_cache: HashMap<String, String> = HashMap::new();
        // Unique first: one String per peer, not one per held message.
        let peers: Vec<String> = self
            .awaiting_confirmation
            .values()
            .map(|p| p.peer_device_fingerprint.as_str())
            .collect::<std::collections::HashSet<&str>>()
            .into_iter()
            .map(str::to_owned)
            .collect();
        for fp in peers {
            if !stamp_cache.contains_key(&fp) {
                let stamp = self.chain_stamp_for(&fp);
                stamp_cache.insert(fp, stamp);
            }
        }
        // Radio saver: retries wait for the window like every other periodic job. They used to run on their own clock (5 s doubling to 120 s), so
        // one connected peer that never acks kept the LTE radio up all the time: an 8 KB envelope re-sent every minute or two, for days (measured:
        // radio 74 % of a 10-minute screen-off run). A packet queued in the last minute is still sent at once.
        let hold_retries = self.radio_saver() && !self.radio_window_open;
        let mut due_ids: Vec<(String, u64)> = self.awaiting_confirmation.iter()
            .filter(|(_, p)| {
                // `next_retry_at == 0`: the peer just connected or subscribed,
                // so the radio is up anyway.
                if hold_retries && p.next_retry_at != 0 && now.saturating_sub(p.original_sent_at) > 60_000 {
                    return false;
                }
                if p.next_retry_at <= now {
                    return true;
                }
                match stamp_cache.get(&p.peer_device_fingerprint) {
                    Some(current) => {
                        !current.is_empty() && !p.chain_stamp.is_empty() && current != &p.chain_stamp
                    }
                    None => false,
                }
            })
            .map(|(id, p)| (id.clone(), p.original_sent_at))
            .collect();
        // `original_sent_at`: `first_sent_at` is reset by every regeneration,
        // which sent a regenerated message to the back of the queue.
        due_ids.sort_by_key(|(_, original_sent_at)| *original_sent_at);
        for (message_id, _) in due_ids {
            let (peer_fp, envelope, first_sent_at, original_sent_at, retry_interval_ms, regen_content, chain_stamp) = match self.awaiting_confirmation.get(&message_id) {
                Some(p) => (
                    p.peer_device_fingerprint.clone(), p.envelope.clone(), p.first_sent_at,
                    p.original_sent_at, p.retry_interval_ms, p.regen_content.clone(), p.chain_stamp.clone(),
                ),
                None => continue,
            };
            // Regenerated earlier in this loop (a rotation or handshake redo
            // of an earlier id re-encrypted every pending packet of the
            // peer): `stamp_cache` is older than that, so it would be sent a
            // second time.
            if first_sent_at >= now {
                continue;
            }
            // See `PendingConfirmation.chain_stamp`: if the session generation changed, the packet is re-encrypted on the current chain.
            // The stamp is computed once per peer (see `stamp_cache`), not once per message.
            let stale_chain = match stamp_cache.get(&peer_fp) {
                Some(current) => !current.is_empty() && !chain_stamp.is_empty() && current != &chain_stamp,
                None => false,
            };
            // The real give-up limit is `original_sent_at` (when the message first entered the queue, stable across refreshes).
            let give_up_for_real = now.saturating_sub(original_sent_at) > TEXT_RETRY_GIVE_UP_MS;
            // Age alone, same chain generation: the peer can still open these bytes (it keeps a replaced receive chain for 7 days), and
            // the server already holds them. They are offered again unchanged. Re-encrypting here made a new signed copy and a new server
            // deposit every 25 minutes for 7 days. A peer that cannot open them asks for a fresh copy (`ResendRequest`).
            // Only a lost handshake needs a new session: `maybe_redo_handshake` checks that (it throttles itself) and regenerates every
            // pending packet of the peer when it really replaced the session.
            if !stale_chain && !give_up_for_real && now.saturating_sub(first_sent_at) > MAX_UNCONFIRMED_AGE_MS {
                self.maybe_redo_handshake(&peer_fp);
                if self.awaiting_confirmation.get(&message_id).map_or(true, |p| p.first_sent_at >= now) {
                    continue;
                }
            } else if stale_chain || give_up_for_real {
                // Sync packets past the give-up limit leave quietly: there is no bubble to mark.
                if give_up_for_real && matches!(regen_content, Some(
                    MessageContent::SiblingEcho { .. } | MessageContent::ReadStateSync { .. }
                    | MessageContent::DeviceSync(_) | MessageContent::WbDigest { .. })) {
                    info!("Packet {} (sync -> {}) left without refresh", message_id, &peer_fp[..peer_fp.len().min(8)]);
                    self.awaiting_confirmation.remove(&message_id);
                    self.remove_durable_retry(&message_id);
                    continue;
                }
                if !give_up_for_real {
                    // Clone (not move) so `regen_content` is still available below for the give-up event.
                    if let Some(content) = regen_content.clone() {
                        // Messages should be retried for up to about 7 days, even plain Text, until the peer acknowledges them. Resending the same
                        // stale ciphertext is pointless. Instead the original plaintext is re-encrypted with a FRESH ratchet step, keeping the same
                        // `message_id` and `original_sent_at` (see `send_message_content_inner`). The UI bubble and the `awaiting_confirmation` entry
                        // stay continuous. The pending-messages screen lists only Text, so this log line is the only place the other kinds show up.
                        let kind = content.kind();
                        warn!("Packet {} ({} -> {}) encrypted under a replaced chain, REFRESHING and retrying with the SAME id",
                            message_id, kind, &peer_fp[..peer_fp.len().min(8)]);
                        if let Err(e) = self.send_message_content_inner(
                            peer_fp.clone(), &content, None,
                            Some(message_id.clone()), Some(original_sent_at), Some(retry_interval_ms),
                        ) {
                            // Fix: the log said "permanently given up", but nothing was given up. The entry stayed due, because
                            // `next_retry_at <= now`, and every `poll_events` turn (once a second) tried to regenerate it again.
                            // That went on for two days, with a ratchet step on every turn. Now the backoff is pushed forward: retries
                            // continue at a reasonable pace, and the `TEXT_RETRY_GIVE_UP_MS` ceiling still applies.
                            error!("Refresh send attempt failed, will retry with backoff: {}", e);
                            if let Some(pending) = self.awaiting_confirmation.get_mut(&message_id) {
                                pending.retry_interval_ms =
                                    (pending.retry_interval_ms * 2).min(ACK_RETRY_MAX_MS);
                                pending.next_retry_at = current_time_ms() + pending.retry_interval_ms;
                                pending.last_attempt_at = current_time_ms();
                                // A stale stamp makes the entry due every turn,
                                // past the backoff just set. Without it the
                                // age path decides.
                                pending.chain_stamp.clear();
                            }
                        }
                        continue;
                    }
                }
                self.awaiting_confirmation.remove(&message_id);
                self.remove_durable_retry(&message_id);
                // Marked failed: the relay copy must not deliver it later.
                self.cancel_server_deposit(&message_id);
                // Types without `regen_content` (for example HistorySyncResponse), and anything past `TEXT_RETRY_GIVE_UP_MS`, are marked
                // Failed. The user can resend them manually.
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                    // Same fix as the Ack arm: resolve the real target from regen_content.
                    if let Some(content) = &regen_content {
                        self.note_group_copy_failed(content, &peer_fp);
                    }
                    let (event_message_id, event_group_id) = match &regen_content {
                        Some(MessageContent::Edit { target_message_id: real_target, group_id, .. }) =>
                            (real_target.clone(), group_id.clone()),
                        Some(MessageContent::Delete { target_message_id: real_target, group_id, .. }) =>
                            (real_target.clone(), group_id.clone()),
                        // As in `cancel_pending_message`: the group bubble is keyed
                        // by the group-wide id. With the packet id and no
                        // `group_id` no screen could match this event.
                        Some(MessageContent::Text { group_id: Some(gid), group_message_local_id, .. }) =>
                            (group_message_local_id.clone().unwrap_or_else(|| m.header.message_id.clone()), Some(gid.clone())),
                        _ => (m.header.message_id.clone(), None),
                    };
                    // A copy to another device of the peer may have been acked: a delivered bubble keeps its mark.
                    let delivered = self.sent_row_delivered(&event_message_id);
                    let mut status_event = serde_json::json!({
                        "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                        "message_id": event_message_id, "status": "error"
                    });
                    if let Some(gid) = event_group_id {
                        status_event["group_id"] = serde_json::Value::String(gid);
                    }
                    if !delivered {
                        self.attachment_events.push(status_event.to_string());
                    }
                }
                if give_up_for_real {
                    error!("Packet {} not confirmed for {} ms (TEXT_RETRY_GIVE_UP_MS), giving up for good", message_id, TEXT_RETRY_GIVE_UP_MS);
                } else {
                    error!("Packet {} encrypted under a replaced chain and cannot be regenerated, giving up", message_id);
                }
                continue;
            }
            match self.try_publish_raw(&peer_fp, &envelope, current_time_ms()) {
                Ok(()) => {
                    if let NetworkEnvelope::Message(m) = &envelope {
                        // A group bubble is keyed by the group-wide id, as in
                        // the give-up arm above; the packet id matched no row.
                        let (row_id, row_group) = match &regen_content {
                            Some(MessageContent::Text { group_id: Some(gid), group_message_local_id: Some(local), .. }) =>
                                (local.clone(), Some(gid.clone())),
                            _ => (m.header.message_id.clone(), None),
                        };
                        // The bubble shows the error mark until told otherwise.
                        // A group row left "pending" when every copy was only queued (`send_group_message_with_status`) turns "sent" too.
                        let was_failed = self.db.as_ref().map_or(false, |c| c.query_row(
                            "SELECT 1 FROM messages WHERE message_id = ?1 AND (status = ?2 OR (?3 IS NOT NULL AND status = 'pending')) AND direction = 'sent'
                               AND (?3 IS NULL OR group_id = ?3)",
                            params![row_id, MessageSendStatus::Failed.as_str(), row_group], |_| Ok(())).is_ok());
                        if was_failed {
                            let mut ev = serde_json::json!({
                                "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                                "message_id": row_id, "status": "sent"
                            });
                            if let Some(gid) = &row_group {
                                ev["group_id"] = serde_json::Value::String(gid.clone());
                                if let Some(conn) = &self.db {
                                    let _ = conn.execute(
                                        "UPDATE messages SET status = 'sent' WHERE message_id = ?1 AND group_id = ?2 AND direction = 'sent' AND status IN (?3, 'pending')",
                                        params![row_id, gid, MessageSendStatus::Failed.as_str()],
                                    );
                                }
                            }
                            self.attachment_events.push(ev.to_string());
                        }
                        self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                    }
                }
                // See `PublishFailure`. A permanent error means this envelope can never be published again. Do not let it keep the queue busy.
                Err(PublishFailure::Permanent(e)) => {
                    error!("Pending packet {} dropped with PERMANENT publish error: {}", message_id, e);
                    self.awaiting_confirmation.remove(&message_id);
                    self.remove_durable_retry(&message_id);
                    if let NetworkEnvelope::Message(m) = &envelope {
                        self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                        if !self.sent_row_delivered(&m.header.message_id) {
                            self.attachment_events.push(serde_json::json!({
                                "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                                "message_id": m.header.message_id, "status": "error"
                            }).to_string());
                        }
                    }
                    continue;
                }
                Err(PublishFailure::Transient(_)) => {
                    // Retried silently on the next turn. It is not marked Failed yet, because the user asked for "keep trying until acknowledged".
                }
            }
            if let Some(pending) = self.awaiting_confirmation.get_mut(&message_id) {
                // The "last attempt" time shown in the pending-messages list in Settings (see `list_pending_messages`).
                pending.last_attempt_at = current_time_ms();
                pending.retry_interval_ms = (pending.retry_interval_ms * 2).min(ACK_RETRY_MAX_MS);
                pending.next_retry_at = current_time_ms() + pending.retry_interval_ms;
            }
        }
    }

    /// Our sent row `id` is already marked delivered (another device of the peer acked a copy).
    pub(crate) fn sent_row_delivered(&self, id: &str) -> bool {
        self.db.as_ref().map_or(false, |c| c.query_row(
            "SELECT 1 FROM messages WHERE message_id = ?1 AND direction = 'sent' AND status = 'delivered'",
            params![id], |_| Ok(())).is_ok())
    }

    /// The peer decrypted `message_id` but could not take it yet, or cannot decrypt our copy (its key is spent): it asks for a fresh copy
    /// (`MessageContent::ResendRequest`). A byte-identical retry can never decrypt again. The gap grows with the message's age (a quarter of
    /// it, 30 s to 25 min), so a packet the peer keeps refusing is re-encrypted no more often than the old fixed 25-minute refresh.
    pub(crate) fn regen_on_request(&mut self, peer_fp: &str, message_id: &str) {
        let now = current_time_ms();
        let Some(p) = self.awaiting_confirmation.get(message_id) else { return };
        if p.peer_device_fingerprint != peer_fp {
            return;
        }
        let Some(content) = p.regen_content.clone() else { return };
        let age = now.saturating_sub(p.original_sent_at);
        if age > TEXT_RETRY_GIVE_UP_MS || now.saturating_sub(p.first_sent_at) < (age / 4).clamp(30_000, MAX_UNCONFIRMED_AGE_MS) {
            return;
        }
        let (original_sent_at, retry_interval_ms) = (p.original_sent_at, p.retry_interval_ms);
        info!("Peer asked for a fresh copy of {} ({} -> {})", crate::log_id(message_id), content.kind(), crate::log_id(peer_fp));
        if let Err(e) = self.send_message_content_inner(
            peer_fp.to_string(), &content, None,
            Some(message_id.to_string()), Some(original_sent_at), Some(retry_interval_ms),
        ) {
            warn!("Fresh copy on request failed (normal retry continues): {}", e);
        }
    }

    /// Fix for "messages that cross a rotation stay stuck for 25 minutes": a DH or KEM rotation just happened in the session with this peer,
    /// either triggered by us or as a reply to the peer's rotation. Every packet still pending in `awaiting_confirmation` for this peer was
    /// encrypted under the OLD chain and can no longer be decrypted (see `MAX_UNCONFIRMED_AGE_MS`). Before, those packets were resent
    /// unchanged until the 25-minute age limit. Now the rotation takes effect at once. Packets carrying `regen_content` are re-encrypted
    /// under the fresh chain right away, keeping the same `message_id`, `original_sent_at` and backoff. Packets without it (Ack, Seen,
    /// HistorySyncResponse) cannot be regenerated, and losing them is harmless: an unacknowledged original is resent anyway, and a response
    /// is refreshed when the request is retried. They are dropped quietly.
    pub(crate) fn regen_pending_for_peer(&mut self, peer_fp: &str) {
        let mut regen: Vec<(String, MessageContent, u64, u64)> = Vec::new();
        let mut drop_ids: Vec<String> = Vec::new();
        for (id, p) in &self.awaiting_confirmation {
            if p.peer_device_fingerprint != peer_fp || self.regen_skip_id.as_ref() == Some(id) {
                continue;
            }
            if !matches!(p.envelope, NetworkEnvelope::Message(_)) {
                continue;
            }
            match &p.regen_content {
                Some(c) => regen.push((id.clone(), c.clone(), p.original_sent_at, p.retry_interval_ms)),
                None => drop_ids.push(id.clone()),
            }
        }
        if regen.is_empty() && drop_ids.is_empty() {
            return;
        }
        info!(
            "Pending packets renewed after rotation (peer={}): {} packets re-encrypted with fresh chain, {} unrecoverable packets dropped",
            crate::log_id(&peer_fp), regen.len(), drop_ids.len()
        );
        for id in drop_ids {
            // reported like the age arm of `retry_unconfirmed_messages`
            // (FileOffer/ProfileUpdate/HistorySync… cannot be re-encrypted).
            if let Some(NetworkEnvelope::Message(m)) = self.awaiting_confirmation.remove(&id).map(|p| p.envelope) {
                warn!("Rotation: packet {} could not be regenerated, dropped (Failed)", crate::log_id(&id));
                self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                self.attachment_events.push(serde_json::json!({
                    "type": "status", "peer": self.canonical_peer_key(&peer_fp), "message_id": m.header.message_id, "status": "error"
                }).to_string());
            }
            self.remove_durable_retry(&id);
        }
        for (id, content, original_sent_at, retry_interval_ms) in regen {
            if let Err(e) = self.send_message_content_inner(
                peer_fp.to_string(), &content, None,
                Some(id.clone()), Some(original_sent_at), Some(retry_interval_ms),
            ) {
                error!("Re-encryption after rotation failed (normal age-expiry path takes over): {}", e);
                // See `retry_unconfirmed_messages`: or the stale stamp retries it every turn.
                if let Some(pending) = self.awaiting_confirmation.get_mut(&id) {
                    pending.chain_stamp.clear();
                }
            }
        }
    }

    /// Called when the app comes to the foreground (Kotlin `P2PApplication` foreground detection, plus the JNI `retryAllPendingNow`). It pulls
    /// the next retry time (`next_retry_at`) of every pending message forward to now, without waiting for the natural exponential backoff
    /// (up to 120 s). `awaiting_confirmation` holds only entries within `TEXT_RETRY_GIVE_UP_MS` (7 days). Older ones were already removed by
    /// the age branch of `retry_unconfirmed_messages`, so no extra age filter is needed here. The actual send attempt happens on the next
    /// `poll_events` turn (once a second, already driven by Kotlin) through the normal `retry_unconfirmed_messages` path. No network I/O
    /// happens here: only a timestamp moves, which is gentle on the battery.
    pub(crate) fn retry_all_pending_now(&mut self) {
        let now = current_time_ms();
        for pending in self.awaiting_confirmation.values_mut() {
            pending.next_retry_at = now;
        }
    }

    /// Manual "Retry now" for ONE row of the pending-messages list in Settings. Same mechanism as `retry_all_pending_now`, but only for
    /// this message. No send happens here (same battery reason). It only pulls `next_retry_at` to now, and the next `poll_events` turn
    /// (once a second, already running) makes the real attempt.
    pub(crate) fn retry_pending_message_now(&mut self, message_id: &str) -> Result<(), String> {
        let pending = self.awaiting_confirmation.get_mut(message_id).ok_or("Pending message not found")?;
        pending.next_retry_at = current_time_ms();
        Ok(())
    }

    /// See `PendingMessageSummary`.
    pub(crate) fn list_pending_messages(&self) -> Vec<PendingMessageSummary> {
        self.awaiting_confirmation.iter().filter_map(|(message_id, p)| {
            match &p.regen_content {
                Some(MessageContent::Text { group_id, text, .. }) => Some(PendingMessageSummary {
                    message_id: message_id.clone(),
                    peer_device_fingerprint: p.peer_device_fingerprint.clone(),
                    // See `PendingMessageSummary.device_name`.
                    device_name: self.known_remote_devices.get(&p.peer_device_fingerprint)
                        .map(|d| d.device_name.clone())
                        .unwrap_or_default(),
                    contact_name: self.known_remote_devices.get(&p.peer_device_fingerprint)
                        .and_then(|d| self.contacts.values().find(|c| c.trusted_identity_id == d.identity_id))
                        .map(|c| c.display_name.clone())
                        .unwrap_or_default(),
                    group_id: group_id.clone(),
                    text: text.clone(),
                    original_sent_at: p.original_sent_at,
                    last_attempt_at: p.last_attempt_at,
                }),
                // Edit, Delete and GroupUpdate (and the other kinds without `regen_content`, such as HistorySyncRequest and FileOffer) are not
                // messages the user wrote. The UI has no separate row for them, so they are skipped here.
                _ => None,
            }
        }).collect()
    }

    /// Cancel button for one row of the pending-messages list in Settings. Drops the message permanently, so it is never retried: it is marked
    /// Failed, and the user can resend it from the chat screen through the existing `retryMessage` flow.
    pub(crate) fn cancel_pending_message(&mut self, message_id: &str) -> Result<(), String> {
        let pending = self.awaiting_confirmation.remove(message_id).ok_or("Pending message not found")?;
        self.remove_durable_retry(message_id);
        // See `cancel_server_deposit`. Cancelling must also withdraw the server copy. Otherwise "I changed my mind" had no effect, and the
        // packet could still be delivered 30 days later.
        self.cancel_server_deposit(message_id);
        if let NetworkEnvelope::Message(m) = &pending.envelope {
            self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
            // Same fix as the Ack arm.
            if let Some(content) = &pending.regen_content {
                self.note_group_copy_failed(content, &pending.peer_device_fingerprint);
            }
            let (event_message_id, event_group_id) = match &pending.regen_content {
                Some(MessageContent::Edit { target_message_id: real_target, group_id, .. }) =>
                    (real_target.clone(), group_id.clone()),
                Some(MessageContent::Delete { target_message_id: real_target, group_id, .. }) =>
                    (real_target.clone(), group_id.clone()),
                // A group text: the bubble is keyed by the group-wide id. Without `group_id` the event would be taken for a 1:1 status.
                Some(MessageContent::Text { group_id: Some(gid), group_message_local_id, .. }) =>
                    (group_message_local_id.clone().unwrap_or_else(|| m.header.message_id.clone()), Some(gid.clone())),
                _ => (m.header.message_id.clone(), None),
            };
            let mut status_event = serde_json::json!({
                "type": "status", "peer": self.canonical_peer_key(&pending.peer_device_fingerprint),
                "message_id": event_message_id, "status": "error"
            });
            if let Some(gid) = event_group_id {
                status_event["group_id"] = serde_json::Value::String(gid);
            }
            self.attachment_events.push(status_event.to_string());
        }
        Ok(())
    }

}
