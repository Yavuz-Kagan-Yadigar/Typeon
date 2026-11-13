//! Sending messages, reactions, seen receipts, edits/deletes, acks and typing.

use super::*;

impl P2PCore {

    /// Common body of `send_message`, `edit_message` and `delete_message`. All three go through the same ratchet-encrypted `MessagePacket` path.
    /// Only the `MessageContent` type after decryption differs. Edit and delete use this shared path (not a separate envelope), so they get the
    /// same end-to-end encryption and signing.
    /// `archive_plaintext`: `Some` only for plain text messages. Edit and delete are not mirrored into the local (node-mode) archive yet (see the
    /// note at the end of the file).
    /// On success returns the `message_id`. The caller (Kotlin) can keep it as the target for a later edit or delete.
    /// Returns `(message_id, status)`. Status is "sent" (delivered at once) or "pending" (queued, retried in the background). See `MessageSendStatus`.
    pub(crate) fn send_message_content(&mut self, peer_device_fingerprint: String, content: &MessageContent, archive_plaintext: Option<&[u8]>) -> Result<(String, String), String> {
        self.send_message_content_inner(peer_device_fingerprint, content, archive_plaintext, None, None, None)
    }

    /// See `send_message_content`, the main body. The last three parameters are `Some(...)` only when `retry_unconfirmed_messages` re-sends through
    /// its `regen_content` path. While a message is retried with fresh ciphertext (up to `TEXT_RETRY_GIVE_UP_MS`), they keep the SAME `message_id`
    /// (so the same UI bubble and `awaiting_confirmation` entry), the timestamp of the first queueing, and the backoff already reached (see the
    /// `publish_with_ack_tracking` notes; so it does not reset to 15 s on every refresh). For a normal new send all three are `None`, and behaviour
    /// is unchanged.
    pub(crate) fn send_message_content_inner(
        &mut self,
        peer_device_fingerprint: String,
        content: &MessageContent,
        archive_plaintext: Option<&[u8]>,
        message_id_override: Option<String>,
        original_sent_at_override: Option<u64>,
        retry_interval_ms_override: Option<u64>,
    ) -> Result<(String, String), String> {
        if !self.ratchets_loaded {
            return Err("Oturum durumu henüz yüklenmedi".to_string()); // see `initiate_handshake_with`
        }
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();

        // `message_id_override` set = this is a REFRESH (regen, or a restore from the durable queue): a brand-new ciphertext is produced under the
        // same id. See `forget_server_deposit`. The server remembers only the message_id, not the ciphertext. If that memory is not cleared, the
        // fresh copy is never deposited on the server, which is the only reachable place while the peer is offline.
        // Only a refresh carries `original_sent_at_override`. A fresh 1:1 text also pins its id (`send_message`), but is not a refresh.
        if let (Some(mid), Some(_)) = (&message_id_override, original_sent_at_override) {
            self.forget_server_deposit(mid);
            // A refresh means the peer has confirmed nothing for 25 minutes. That includes the chance that our handshake never arrived at all
            // (see `maybe_redo_handshake`).
            let prev = self.regen_skip_id.replace(mid.clone());
            self.maybe_redo_handshake(&peer_device_fingerprint);
            self.regen_skip_id = prev;
        }

        // On the send path, if there is no live connection to the peer, reconnect right away. The gossipsub publish then succeeds as soon as the
        // connection is up (via the `pending_envelopes` retry), without waiting for the next `reconnect_sweep` round.
        self.ensure_connected(&peer_device_fingerprint);

        if !self.ratchets.contains_key(&peer_device_fingerprint) {
            // `initiate_handshake_with` creates the ratchet state BEFORE the publish attempt (see that function). So even if the HandshakeInit's own
            // send (like `publish_envelope` below) fails transiently, we do not stop here: the state exists, and we can keep encrypting and sending the
            // real message. If the HandshakeInit itself failed, `publish_envelope` already added it to the retry queue.
            if let Err(e) = self.initiate_handshake_with(&peer_device_fingerprint) {
                error!("Handshake gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
            }
            // KNOWN GAP (carried over from an earlier design): the handshake and the message are sent back to back, and gossipsub gives no ordering guarantee.
        }

        // Note: these two flags used to be computed AFTER packet construction. They now come before the rotation decision (the rotation gating below
        // needs them). Their meaning is unchanged (see the long notes at the publish choice point below).
        let needs_delivery_confirmation = matches!(
            content,
            MessageContent::Text { .. }
                | MessageContent::Edit { .. }
                | MessageContent::Delete { .. }
                | MessageContent::Reaction { .. }
                | MessageContent::HistorySyncRequest { .. }
                | MessageContent::HistorySyncResponse { .. }
                | MessageContent::FileOffer { .. }
                | MessageContent::GroupUpdate(_)
                | MessageContent::LeaveGroupRequest { .. }
                | MessageContent::GroupSyncRequest { .. }
                | MessageContent::ProfileUpdate { .. }
                | MessageContent::DeviceLinkGrant { .. }
                | MessageContent::DeviceAddNotice { .. }
                | MessageContent::DeviceRevokeNotice(_)
                | MessageContent::FirstContactSecret { .. }
                | MessageContent::DeviceSync(_)
                | MessageContent::SiblingEcho { .. }
                | MessageContent::ReadStateSync { .. }
                | MessageContent::SiblingHistoryRequest { .. }
                | MessageContent::AccountDeleted { .. }
                | MessageContent::WbDigest { .. }
        );

        // Fix (lost rotation announcement): rotation is triggered ONLY when content that is retried until acknowledged (by the peer's Ack) is sent.
        // Before, ANY content could trigger it. If the announcement rode on a `TypingIndicator` (never retried) or an `Ack` (limited retries) and that
        // packet was lost, the peer never learned the new root key or topic, and the session broke for good. Extra safety: even without a fresh
        // rotation, an announcement of a previous, not-yet-confirmed rotation (`pending_rotation_ct`, see ratchet.rs) is attached to EVERY outgoing
        // packet. The receiver handles it idempotently (see the double-apply guard in `respond_to_rotation`), and `try_publish_raw` sends these packets
        // on the OLD topic the peer still listens on.
        // A responder leaves the handshake chain before it sends anything at all, Ack included (see `respond` in ratchet.rs). That chain is a function
        // of the HandshakeInit alone. The announcement is repeated on every packet until confirmed, so it may ride an unreliable one.
        let fresh_responder = self.ratchets.get(&peer_device_fingerprint).map_or(false, |s| s.is_fresh_responder());
        // a peer that only reads sends `Seen` (and `ReadStateSync`,
        // in the list above); it takes its rotation turn on them too, or it
        // never heals. The announcement repeats on every packet until confirmed.
        let rotation_turn = needs_delivery_confirmation || matches!(content, MessageContent::Seen { .. });
        let fresh_rotation_ct = if rotation_turn || fresh_responder {
            self.maybe_rotate_ratchet(&peer_device_fingerprint)?
        } else {
            None
        };
        if fresh_rotation_ct.is_some() {
            // See `regen_pending_for_peer`: we just rotated, so pending packets for this peer (encrypted under the old chain, which can never be decrypted
            // now) are regenerated at once on the fresh chain. This message is encrypted on the fresh chain below anyway.
            let prev = std::mem::replace(&mut self.regen_skip_id, message_id_override.clone());
            self.regen_pending_for_peer(&peer_device_fingerprint);
            self.regen_skip_id = prev;
        }
        let rotation_kyber_ciphertext = match fresh_rotation_ct {
            Some(ct) => Some(ct),
            None => self
                .ratchets
                .get(&peer_device_fingerprint)
                .and_then(|s| s.pending_rotation_ct.clone()),
        };

        // Before `encrypt_next`: an Err after it leaves a used message number
        // and an orphan `hsr:` row.
        if !self.own_device_keys.contains_key(&own_fp) {
            return Err("Missing own keys".to_string());
        }
        let state = self.ratchets.get_mut(&peer_device_fingerprint).ok_or("No ratchet session")?;
        // Note: `own_ratchet_pubkeys()` is called AFTER rotation (`maybe_rotate_ratchet` has already run), so if a rotation happened, the NEW public
        // keys are read here. They are sent only with a rotation announcement: the receiver reads them from no other packet, and they were 1.6 KB of
        // every message, ack and typing indicator.
        let ratchet_pubkey = match rotation_kyber_ciphertext {
            Some(_) => state.own_ratchet_pubkeys().to_bytes()?,
            None => Vec::new(),
        };
        let content_bytes = ciborium_bytes(content)?;
        let message_id = message_id_override.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        // the header is built first; its raw bytes are the AEAD's
        // associated data and what the signature covers.
        let (message_number, prev_chain_length) = state.next_send_numbers();
        let header = packet::SignedHeader::new(MessagePacketHeader {
            sender_identity_id: own_identity_id,
            sender_device_fingerprint: own_fp.clone(),
            message_id: message_id.clone(),
            ratchet_pubkey,
            message_number,
            prev_chain_length,
            rotation_kyber_ciphertext,
            sent_at_ms: current_time_ms(),
        })?;
        // Rollback copy: a state that cannot be saved must not burn the
        // message number (nothing is published with it).
        let snapshot = state.clone();
        let (ciphertext, used_number, used_prev) = state.encrypt_next(&content_bytes, header.raw())?;
        if (used_number, used_prev) != (message_number, prev_chain_length) {
            self.ratchets.insert(peer_device_fingerprint.clone(), snapshot);
            return Err("Ratchet numbers moved under the header".to_string());
        }
        // `encrypt_next` advances ck_send/send_message_number on every call. The state is persisted on every message so the disk copy does not go
        // stale. (If a rotation happened, `maybe_rotate_ratchet` already wrote it above. This second write is harmless and idempotent.)
        if !self.persist_ratchet_state(&peer_device_fingerprint) {
            self.ratchets.insert(peer_device_fingerprint.clone(), snapshot);
            return Err("Oturum durumu yazılamadı, paket gönderilmedi".to_string());
        }
        drop(snapshot);

        if let MessageContent::HistorySyncRequest { group_id, before_timestamp, after_timestamp, .. } = content {
            let now = current_time_ms();
            // The reply arrives within the request's retry lifetime. Anything older is dropped.
            let stale: Vec<String> = self.outstanding_history_requests.iter()
                .filter(|(_, (_, _, at, _))| now.saturating_sub(*at) >= TEXT_RETRY_GIVE_UP_MS)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &stale {
                self.forget_history_request(id);
            }
            let target_identity = if group_id.is_none() {
                self.identity_id_for_device(&peer_device_fingerprint)
            } else {
                None
            };
            let entry = (target_identity, group_id.clone(), now, before_timestamp.zip(*after_timestamp));
            // Also written to disk: if the process dies while the reply waits on the server mailbox, it must not be rejected as unsolicited at startup.
            if let Some(conn) = &self.db {
                if let Ok(json) = serde_json::to_string(&entry) {
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO app_meta (k, v) VALUES (?1, ?2)",
                        params![format!("hsr:{}", message_id), json],
                    );
                }
            }
            self.outstanding_history_requests.insert(message_id.clone(), entry);
        }
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let to_sign = packet_signing_input(header.raw(), &ciphertext, &peer_device_fingerprint);
        let sig_classical: Ed25519Signature = own_keys.sign_sk_ed25519.sign(&to_sign);
        let sig_pq: MlDsaSignature<MlDsa87> = own_keys.sign_sk_mldsa.sign(&to_sign);

        let packet = MessagePacket {
            header,
            ciphertext,
            signature_classical: sig_classical.to_bytes().to_vec(),
            signature_pq: sig_pq.encode().to_vec(),
        };

        // Previously, messages were archived ONLY on devices with node mode on (the user's setting at that time). The user has now explicitly asked for
        // every device (node or not) to keep its own chat history persisted and encrypted locally. Node mode now only affects helping peers with
        // history-sync requests (see HistorySyncRequest) and the relay service, not whether this device keeps its own history.
        // The network packet is already end-to-end encrypted. This is a SEPARATE "encryption at rest" layer (see archive_message: `history_key` is now
        // always loaded regardless of node mode, see P2PService/MessageHistoryManager).
        // Fix (pending messages showed as sent after reopening): `message_id` and the initial status are now written together with the row. It starts
        // as `Pending`, and the real publish attempt (`publish_with_ack_tracking`/`publish_envelope`) then updates the SAME row to Sent/Failed via
        // `set_message_status`. So a reload (app or chat screen reopened) shows the real state, instead of always assuming "sent". Note: group messages
        // (`send_group_message`) pass `archive_plaintext: None` here (see that function's note). They archive themselves as ONE row with
        // `archive_group_message`, before the fan-out loop. Otherwise every fan-out copy would create its own row here.
        if let Some(plaintext) = archive_plaintext {
            // See packet.rs `MessageContent::Text.reply_to_message_id`. Our own sent message's archive row must also carry the reply info (if any).
            // Otherwise, even on our own bubble, the "replying to whom" info would be lost after a reload.
            let (reply_to_id, reply_to_prev, sent_at) = match content {
                MessageContent::Text { reply_to_message_id, reply_to_preview, sent_at_ms, .. } => {
                    (reply_to_message_id.as_deref(), reply_to_preview.as_deref(), *sent_at_ms)
                }
                _ => (None, None, 0),
            };
            // Not sent when our own copy cannot be kept: the peer would hold
            // a message our history never has. The skipped number is harmless.
            if let Err(e) = self.archive_message(&peer_device_fingerprint, "sent", plaintext, Some(&message_id), Some(MessageSendStatus::Pending.as_str()), reply_to_id, reply_to_prev, sent_at) {
                error!("Gönderilen mesaj arşive yazılamadı, gönderilmedi: {}", e);
                return Err(format!("Mesaj kaydedilemedi: {}", e));
            }
        }

        // Reliable delivery, as requested by the user: Text (outside groups), Edit, Delete and HistorySyncRequest are re-sent INDEFINITELY until the peer
        // confirms (Ack or HistorySyncResponse). See the `awaiting_confirmation` docs. A successful local gossipsub `publish()` does not guarantee that
        // the peer received it. The one-shot or time-limited `publish_envelope`/`pending_envelopes` was not enough: some messages, edits and deletes were
        // silently treated as "sent" without ever reaching the peer. Other content types (Ack, HistorySyncResponse, FileOffer, group messages) keep the
        // old behaviour (one-shot, short retries). Ack is never acknowledged itself (endless-loop risk). The N-way group fan-out would complicate this
        // mechanism (a known limit, can be extended later).
        // FileOffer is included too: if this packet is lost (the same network unreliability), the recipient never learns a file was offered, and the
        // attachment bubble never appears. The file chunk transfer (request_response, attachments.rs) has its own reliability (chunk-level retries), but
        // it does not cover this METADATA message. That is a separate issue.
        //
        // Fix (lost group messages): `Text { group_id: Some(_), .. }` is now covered here too. Before, group text was deliberately left out, on the
        // reasoning that the N-way fan-out complicates things. But the fan-out already makes a SEPARATE `send_message_content` call per member (its own
        // message_id and target peer_fp), so this mechanism applies to each copy like a single 1:1 send. Nothing complicated, just an oversight. The
        // receiver now also sends an Ack (see the receive_message Text/group_id arm).
        //
        // Fix (every message should be retried until acknowledged): `ProfileUpdate` (the receiver already sent an Ack, but it was never on this list)
        // and `HistorySyncResponse` (the receiver now also sends an Ack back, see receive_message) are now here too.
        // Deliberately NOT here: `Ack`/`Seen` (never acknowledged themselves, to avoid an endless ack-of-ack loop; sent once, see
        // `reack_if_already_handled`), and `TypingIndicator` (see the packet.rs note: retrying a signal that goes stale within seconds, for minutes,
        // has no value. It would only show a wrong or old "typing" indicator).
        // (`needs_delivery_confirmation` was moved UP from here, since the rotation gating needs it before packet construction. The scope list and the
        // reasons are unchanged: DeviceLinkGrant is critical (if lost, the secondary never adopts), SiblingEcho/ReadStateSync must be reliable for sibling
        // sync, and SiblingHistoryRequest was never acked before.)
        // Ack/Seen are sent once (if the publish fails transiently, `pending_envelopes` retries). Before, they were repeated unconditionally 9 times
        // (~10.6 min): dozens of unneeded packets per message, and with a server up, each one was a separate Deposit. A lost Ack is now compensated by
        // the sender's own retry plus `reack_if_already_handled`. The reliable path for "seen" is `ReadStateSync`.
        // Per user feedback (the case of a person who did not open the internet for 6 hours, later extended to plain Text): when `MAX_UNCONFIRMED_AGE_MS`
        // passes, these types do not give up. They are re-encrypted fresh and retried up to `TEXT_RETRY_GIVE_UP_MS`. See the
        // `PendingConfirmation.regen_content` docs.
        //
        // Per user feedback (cross-device sync between devices on the same account is slow and late, and many messages get lost): multi-device control
        // messages are now in this list too. Before, they were not, and that was the direct cause of silent, PERMANENT losses. These types were retried
        // until acknowledged, but ALWAYS with the SAME ciphertext. If a sibling device stayed offline longer than `MAX_UNCONFIRMED_AGE_MS` (~25 min),
        // e.g. a phone in a pocket all afternoon, the ratchet rotation in between deletes the receiver's skipped-key cache for that chain, and the packet
        // can NEVER be decrypted again. The retry kept trying something cryptographically impossible, then was left as "Failed". For the user, this
        // meant "most messages never reached the other device".
        //
        // Instead, they are re-encrypted with a FRESH ratchet step under the SAME `message_id` (see `message_id_override`). The receiver already dedups
        // on `message_id`, so no double archive is made, and they survive up to `TEXT_RETRY_GIVE_UP_MS` (7 days). `Ack`/`Seen`/`TypingIndicator` are
        // deliberately excluded (see the notes above). `HistorySyncResponse` is retried but not re-encrypted: it is a bulk reply. If it is lost, the
        // request is asked again, and re-encrypting it for days is not worth it.
        // `HistorySyncRequest` and `LeaveGroupRequest` were NOT on this list before. With `regen_content` = `None`, `publish_with_ack_tracking` does NOT
        // write this entry to disk with `persist_durable_retry` (see its call site). So if the process is killed or restarted before the peer confirms,
        // the in-memory `awaiting_confirmation` entry is lost for good, and the packet is NEVER retried: a silent permanent loss.
        let regen_content = matches!(
            content,
            MessageContent::Text { .. }
                | MessageContent::Edit { .. }
                | MessageContent::Delete { .. }
                | MessageContent::Reaction { .. }
                | MessageContent::GroupUpdate(_)
                | MessageContent::SiblingEcho { .. }
                | MessageContent::DeviceSync(_)
                | MessageContent::DeviceLinkGrant { .. }
                | MessageContent::DeviceAddNotice { .. }
                | MessageContent::DeviceRevokeNotice(_)
                | MessageContent::FirstContactSecret { .. }
                | MessageContent::ReadStateSync { .. }
                | MessageContent::ProfileUpdate { .. }
                | MessageContent::FileOffer { .. }
                | MessageContent::HistorySyncRequest { .. }
                | MessageContent::LeaveGroupRequest { .. }
                | MessageContent::GroupSyncRequest { .. }
                | MessageContent::AccountDeleted { .. }
                | MessageContent::WbDigest { .. }
        ).then(|| content.clone());
        if needs_delivery_confirmation {
            self.publish_with_ack_tracking(
                &peer_device_fingerprint, &message_id, NetworkEnvelope::Message(packet), regen_content,
                original_sent_at_override, retry_interval_ms_override,
            );
        } else if let Err(e) = self.publish_envelope(&peer_device_fingerprint, &NetworkEnvelope::Message(packet)) {
            error!("Mesaj gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
        }
        let status = self.message_status.remove(&message_id).unwrap_or(MessageSendStatus::Pending);
        Ok((message_id, status.as_str().to_string()))
    }

    /// `reply_to_message_id` / `reply_to_preview`: user request (WhatsApp-style swipe-to-reply). See the packet.rs `MessageContent::Text.reply_to_message_id`
    /// docs. The Kotlin side already knows the text of the message it shows, so it passes the (truncated) summary here. The Rust side does no archive lookup.
    pub(crate) fn send_message(&mut self, peer_device_fingerprint: String, plaintext: String, reply_to_message_id: Option<String>, reply_to_preview: Option<String>) -> Result<(String, String), String> {
        if self.known_remote_devices.get(&peer_device_fingerprint)
            .map_or(false, |d| self.deleted_identities.contains(&d.identity_id))
        {
            return Err("Bu kişi hesabını sildi".to_string());
        }
        // See packet.rs `MessageContent::Text.sent_at_ms`: it is stamped HERE, once, on first write. `regen_content` refreshes (see
        // `retry_unconfirmed_messages` in network.rs) clone the `content` that already contains this value and re-encrypt it unchanged.
        let sent_at_ms = current_time_ms();
        // Multi-device (1.7.1): like group messages, 1:1 messages also get a STABLE conversation-level id (`conv_id`). ALL fan-out copies carry the same
        // `group_message_local_id`. So an edit, delete or "seen" (whether the recipient has one device or many) applies to the SAME bubble on every
        // device. The main copy's packet header `message_id` is also pinned to `conv_id` (`message_id_override`), so the delivery ack, the send status and
        // the UI bubble all share ONE id. Fan-out copies get their own (different) packet id for their own Acks, but the `conv_id` in the content is shared.
        let conv_id = uuid::Uuid::new_v4().to_string();
        let content = MessageContent::Text {
            group_id: None, text: plaintext.clone(), group_message_local_id: Some(conv_id.clone()), sent_at_ms,
            reply_to_message_id: reply_to_message_id.clone(), reply_to_preview: reply_to_preview.clone(),
            reply_to_sender_identity_id: None, author_proof: None, mentions: Vec::new(),
        };
        info!("Metin gönderiliyor: id={} peer={}", &conv_id[..8], &peer_device_fingerprint[..8.min(peer_device_fingerprint.len())]);
        let result = self.send_message_content_inner(
            peer_device_fingerprint.clone(), &content, Some(plaintext.as_bytes()), Some(conv_id.clone()), None, None,
        );
        // Echo to my own siblings too (with the same conv_id).
        if result.is_ok() {
            // Only after the primary copy: on Err there is no row and no
            // retry entry here, and the other devices would get a text the
            // sender does not have.
            self.fanout_extra_copies(&peer_device_fingerprint, &content);
            self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::Text {
                message_id: conv_id.clone(), text: plaintext, sent_at_ms,
                reply_to_message_id, reply_to_preview, reply_to_sender_identity_id: None,
            });
        }
        result
    }

    /// Multi-device (1.7.1): after a 1:1 message is sent to the contact's PRIMARY device, it is also sent separately (each with its own ratchet) to the
    /// contact's OTHER active devices. No-op for single-device contacts (behaviour unchanged). Nothing is archived here: the main send already archived one row.
    pub(crate) fn fanout_extra_copies(&mut self, primary_fp: &str, content: &MessageContent) {
        for fp in self.fanout_targets(primary_fp) {
            if fp == primary_fp { continue; }
            if let Err(e) = self.send_message_content(fp.clone(), content, None) {
                error!("Çoklu-cihaz fan-out kopyası ({}) başarısız: {}", crate::log_id(&fp), e);
            }
        }
    }

    /// The reactions of `reactors` (at most one row each) on `message_id`.
    pub(crate) fn reactions_of(&self, message_id: &str, reactors: [&str; 2]) -> Vec<(String, String, u64)> {
        let Some(conn) = &self.db else { return Vec::new() };
        conn.prepare("SELECT reactor_identity_id, emoji, reacted_at_ms FROM message_reactions WHERE message_id = ?1 AND reactor_identity_id IN (?2, ?3)")
            .and_then(|mut stmt| stmt.query_map(params![message_id, reactors[0], reactors[1]], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)?.max(0) as u64)))?.collect())
            .unwrap_or_default()
    }

    /// a history page's reactions, for the rows `event["messages"]` kept
    /// (after the floor, direction and author checks). The responder's own
    /// are taken. Mine only to restore one I have no row for (a new device),
    /// on a row I have, stamped in the past: the responder could otherwise
    /// forge, freeze (huge stamp) or erase (empty emoji) my reactions.
    pub(crate) fn apply_synced_reactions(&self, event: &mut serde_json::Value, reactions: &HashMap<String, Vec<(String, String, u64)>>, group_id: Option<&str>, sender_identity_id: &str) {
        let own_id = self.my_identity_id();
        let now = current_time_ms();
        let Some(rows) = event["messages"].as_array_mut() else { return };
        for row in rows {
            let Some(mid) = row["message_id"].as_str().map(str::to_string) else { continue };
            let Some(list) = reactions.get(&mid) else { continue };
            let mut changed = false;
            for (reactor, emoji, at) in list {
                if emoji.len() > 64 || !self.reaction_fits_chat(&mid, group_id, sender_identity_id) {
                    continue;
                }
                let take = reactor == sender_identity_id
                    || (Some(reactor) == own_id.as_ref() && !emoji.is_empty() && *at > 0 && *at <= now + 60_000
                        && self.db.as_ref().is_some_and(|c| c.query_row(
                            "SELECT (EXISTS(SELECT 1 FROM messages WHERE message_id = ?1) OR EXISTS(SELECT 1 FROM files WHERE file_id = ?1))
                               AND NOT EXISTS(SELECT 1 FROM message_reactions WHERE message_id = ?1 AND reactor_identity_id = ?2)",
                            params![mid, reactor], |r| r.get::<_, bool>(0),
                        ).unwrap_or(false)));
                if take {
                    changed |= self.apply_reaction(&mid, reactor, emoji, *at);
                }
            }
            if changed {
                row["reactions"] = self.reactions_summary(&mid).into();
            }
        }
    }

    /// Writes the emoji a person left on a message to the local archive.
    ///
    /// ONE reaction per person: `INSERT OR REPLACE` puts the new emoji in place of the old one, and an empty `emoji` row deletes it. The `reacted_at_ms`
    /// guard follows the same reasoning as `apply_edit_to_archive`: gossipsub gives no ordering guarantee, so two reactions from the same person changed
    /// quickly can arrive out of order. An OLDER one must not overwrite a newer one. Packets with no timestamp (older versions) are applied unconditionally.
    /// `false`: the row could not be written (a received reaction is then not acked).
    pub(crate) fn apply_reaction(&self, target_message_id: &str, reactor_identity_id: &str, emoji: &str, reacted_at_ms: u64) -> bool {
        // no DB is not "applied".
        let Some(conn) = &self.db else { return false };
        if reacted_at_ms > 0 {
            let previous: Option<i64> = conn
                .query_row(
                    "SELECT reacted_at_ms FROM message_reactions WHERE message_id = ?1 AND reactor_identity_id = ?2",
                    params![target_message_id, reactor_identity_id],
                    |row| row.get(0),
                )
                .ok();
            if let Some(prev) = previous {
                if prev as u64 > reacted_at_ms { return true; }
            }
        }
        // A removal stays as a row with an empty emoji: its stamp is what stops
        // an older add, delivered later, from bringing the reaction back.
        match conn.execute(
            "INSERT OR REPLACE INTO message_reactions (message_id, reactor_identity_id, emoji, reacted_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![target_message_id, reactor_identity_id, emoji, reacted_at_ms.min(i64::MAX as u64) as i64],
        ) {
            Ok(_) => true,
            Err(e) => { error!("Tepki yazılamadı: {}", e); false }
        }
    }

    /// False only if `target_message_id` is a row of ANOTHER chat than the one
    /// the reaction claims. An unknown target passes: the message may still be
    /// on its way.
    pub(crate) fn reaction_fits_chat(&self, target_message_id: &str, group_id: Option<&str>, sender_identity_id: &str) -> bool {
        let Some(conn) = &self.db else { return true };
        let row: Option<(Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT group_id, peer_device_fingerprint FROM messages WHERE message_id = ?1
                 UNION ALL
                 SELECT group_id, peer_device_fingerprint FROM files WHERE file_id = ?1
                 LIMIT 1",
                params![target_message_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        // Not here yet (the reaction arrived before its message): allowed, but not under an id of any length. And not without limit: each invented id left
        // a row for good.
        // ponytail: scans the reactor's rows; index reactor_identity_id if the table grows.
        let Some((row_group, row_peer)) = row else {
            let pending: i64 = conn.query_row(
                "SELECT COUNT(*) FROM message_reactions r WHERE r.reactor_identity_id = ?1
                   AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.message_id = r.message_id)
                   AND NOT EXISTS (SELECT 1 FROM files f WHERE f.file_id = r.message_id)",
                params![sender_identity_id], |r| r.get(0),
            ).unwrap_or(0);
            return target_message_id.len() <= 128 && pending < 64;
        };
        match (row_group.filter(|g| !g.is_empty()), group_id) {
            (Some(g), Some(claimed)) => g == claimed,
            (None, None) => row_peer
                .and_then(|fp| self.identity_id_for_device(&fp))
                .as_deref() == Some(sender_identity_id),
            _ => false,
        }
    }

    /// Ready-to-display summary of a message's reactions, e.g. `"👍2 ❤️"`. A single reaction shows no count (WhatsApp style). Sorted by count first, then
    /// by emoji, so the same data produces the SAME string on every device.
    pub(crate) fn reactions_summary(&self, target_message_id: &str) -> String {
        let Some(conn) = &self.db else { return String::new() };
        let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        if let Ok(mut stmt) = conn.prepare("SELECT emoji FROM message_reactions WHERE message_id = ?1 AND emoji != ''") {
            if let Ok(rows) = stmt.query_map(params![target_message_id], |row| row.get::<_, String>(0)) {
                for emoji in rows.flatten() {
                    *counts.entry(emoji).or_insert(0) += 1;
                }
            }
        }
        if counts.is_empty() { return String::new() }
        let mut pairs: Vec<(String, u32)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        pairs
            .iter()
            .map(|(emoji, n)| if *n > 1 { format!("{}{}", emoji, n) } else { emoji.clone() })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// User request ("tapping the reaction pill opens a list of who reacted with what"): returns a message's reactions PER PERSON:
    /// `[{"identity_id": "...", "emoji": "👍"}, ...]`. `reactions_summary` deliberately gives only totals (for the pill next to the bubble). This separate
    /// read is needed for who reacted with what. Newest reaction at the top, as WhatsApp does.
    pub(crate) fn list_reactions(&self, target_message_id: &str) -> String {
        let Some(conn) = &self.db else { return "[]".to_string() };
        let mut out = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT reactor_identity_id, emoji FROM message_reactions
             WHERE message_id = ?1 AND emoji != '' ORDER BY reacted_at_ms DESC"
        ) {
            if let Ok(rows) = stmt.query_map(params![target_message_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                // `is_me`: the "You" label is computed on the Kotlin side, which would need our own `identity_id`, and no JNI exposes it. Doing the comparison
                // here, where the identity is already known, is the right place and adds no new API surface.
                let own = self.identity.as_ref().map(|i| i.identity_id.as_str()).unwrap_or("");
                for (identity_id, emoji) in rows.flatten() {
                    let is_me = identity_id == own;
                    out.push(serde_json::json!({
                        "identity_id": identity_id, "emoji": emoji, "is_me": is_me
                    }));
                }
            }
        }
        serde_json::to_string(&out).unwrap_or_else(|_| "[]".to_string())
    }

    /// See the `message_seen` table docs. Persists a "seen" receipt when one arrives (1:1 or group). `message_id` has the same column and meaning in
    /// both cases (see `load_message_history`/`load_group_message_history`). Same out-of-order protection as `apply_reaction`: an older timestamp does not
    /// overwrite a newer record from the same viewer.
    /// `viewer`: could the viewer have seen MY sent `message_id`? In 1:1, the message's other party must be the viewer. In a group, the viewer must be a
    /// member of that group. Otherwise any person could mark my messages in other chats as "seen".
    pub(crate) fn may_mark_seen(&self, message_id: &str, viewer_identity_id: &str) -> bool {
        let Some(conn) = &self.db else { return false };
        let row: Option<(Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT group_id, peer_device_fingerprint FROM messages
                 WHERE message_id = ?1 AND direction = 'sent'
                 UNION ALL
                 SELECT group_id, peer_device_fingerprint FROM files
                 WHERE file_id = ?1 AND direction = 'sent'
                 LIMIT 1",
                params![message_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        match row {
            Some((Some(gid), _)) if !gid.is_empty() => {
                self.groups.get(&gid).map_or(false, |g| g.is_member(viewer_identity_id))
            }
            Some((_, Some(fp))) => self.identity_id_for_device(&fp).as_deref() == Some(viewer_identity_id),
            _ => false,
        }
    }

    pub(crate) fn apply_seen_receipt(&self, message_id: &str, viewer_identity_id: &str, seen_at_ms: u64) {
        let Some(conn) = &self.db else { return };
        if seen_at_ms > 0 {
            let previous: Option<i64> = conn
                .query_row(
                    "SELECT seen_at_ms FROM message_seen WHERE message_id = ?1 AND viewer_identity_id = ?2",
                    params![message_id, viewer_identity_id],
                    |row| row.get(0),
                )
                .ok();
            if let Some(prev) = previous {
                if prev as u64 > seen_at_ms { return; }
            }
        }
        let _ = conn.execute(
            "INSERT OR REPLACE INTO message_seen (message_id, viewer_identity_id, seen_at_ms) VALUES (?1, ?2, ?3)",
            params![message_id, viewer_identity_id, seen_at_ms as i64],
        );
    }

    /// See `ArchivedMessage.seen_by`: who has seen a message, in the same JSON shape as `list_reactions` (`[{"identity_id":..,"seen_at_ms":..}]`),
    /// embedded in each history row. The FIRST viewer is at the top (the same ordering as WhatsApp's group read list).
    pub(crate) fn seen_by_json(&self, message_id: &str) -> String {
        if message_id.is_empty() { return "[]".to_string() }
        let Some(conn) = &self.db else { return "[]".to_string() };
        let mut out = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT viewer_identity_id, seen_at_ms FROM message_seen
             WHERE message_id = ?1 ORDER BY seen_at_ms ASC"
        ) {
            if let Ok(rows) = stmt.query_map(params![message_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for (identity_id, seen_at_ms) in rows.flatten() {
                    out.push(serde_json::json!({
                        "identity_id": identity_id, "seen_at_ms": seen_at_ms
                    }));
                }
            }
        }
        serde_json::to_string(&out).unwrap_or_else(|_| "[]".to_string())
    }

    /// Puts a reaction on a message in a 1:1 chat (empty `emoji` = remove my own reaction). Same four-step pattern as `edit_message`: send to the peer,
    /// fan out to the contact's other devices, apply to the local archive, echo to my own siblings.
    pub(crate) fn react_to_message(&mut self, peer_device_fingerprint: String, target_message_id: String, emoji: String) -> Result<String, String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        // One timestamp, identical in all copies. See `edit_message` for the same reason.
        let reacted_at_ms = current_time_ms();
        let content = MessageContent::Reaction {
            target_message_id: target_message_id.clone(),
            emoji: emoji.clone(),
            group_id: None,
            reacted_at_ms,
        };
        // Not applied locally if nothing could even be queued for the peer.
        self.send_message_content(peer_device_fingerprint.clone(), &content, None)?;
        self.fanout_extra_copies(&peer_device_fingerprint, &content);
        self.apply_reaction(&target_message_id, &own_identity_id, &emoji, reacted_at_ms);
        self.requeue_archive_row(None, &peer_device_fingerprint, &target_message_id);
        self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::Reaction {
            target_message_id: target_message_id.clone(), emoji, reacted_at_ms,
        });
        Ok(self.reactions_summary(&target_message_id))
    }

    /// Group counterpart of `react_to_message` (same fan-out pattern as `edit_group_message`).
    pub(crate) fn react_to_group_message(&mut self, group_id: String, target_message_id: String, emoji: String) -> Result<String, String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        let reacted_at_ms = current_time_ms();
        let content = MessageContent::Reaction {
            target_message_id: target_message_id.clone(),
            emoji: emoji.clone(),
            group_id: Some(group_id.clone()),
            reacted_at_ms,
        };
        for member_identity_id in group.other_members(&own_identity_id) {
            self.send_group_message_to_member(&group_id, &member_identity_id, &content);
        }
        self.apply_reaction(&target_message_id, &own_identity_id, &emoji, reacted_at_ms);
        self.requeue_archive_row(Some(&group_id), "", &target_message_id);
        self.echo_group_to_siblings(&group_id, SiblingEchoBody::Reaction {
            target_message_id: target_message_id.clone(), emoji, reacted_at_ms,
        });
        Ok(self.reactions_summary(&target_message_id))
    }

    /// Edits a message. `target_message_id` is the `MessagePacketHeader.message_id` of the message to edit (the value returned when it was sent). If the
    /// peer has already seen a message with that `message_id`, it must update the UI (see ChatActivity).
    pub(crate) fn edit_message(&mut self, peer_device_fingerprint: String, target_message_id: String, new_text: String) -> Result<(String, String), String> {
        // Out-of-order Edit protection (see `apply_edit_to_archive`): all copies (the packet to the peer, the multi-device fan-out, sibling echoes and the
        // local archive) must carry the SAME timestamp, so every device makes the same ordering decision. So it is generated ONCE and shared.
        let edited_at_ms = current_time_ms();
        let content = MessageContent::Edit { target_message_id: target_message_id.clone(), new_text: new_text.clone(), group_id: None, edited_at_ms, author_proof: None };
        // `?` first: an edit that could not even be queued must not show as
        // done here and on the siblings while the peer keeps the old text.
        let result = Ok(self.send_message_content(peer_device_fingerprint.clone(), &content, None)?);
        self.fanout_extra_copies(&peer_device_fingerprint, &content);
        self.apply_edit_to_archive(None, &peer_device_fingerprint, &target_message_id, &new_text, edited_at_ms);
        self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::Edit {
            target_message_id: target_message_id.clone(), new_text: new_text.clone(), edited_at_ms,
        });
        result
    }

    /// Deletes a message (sends a "delete" notice to the peer). Also purges the local attachment file, if any (see `purge_attachment_if_exists`).
    /// Deleting a message that is still queued withdraws every copy that has not been confirmed (peer devices, siblings, server deposits). Without this,
    /// the text was still delivered, notification and all, and only then deleted. The Delete itself still goes out for copies that did arrive.
    pub(crate) fn withdraw_unsent(&mut self, target_message_id: &str) {
        let ids: Vec<String> = self.awaiting_confirmation.iter()
            .filter(|(id, p)| id.as_str() == target_message_id || match &p.regen_content {
                Some(MessageContent::Text { group_message_local_id: Some(g), .. }) => g == target_message_id,
                Some(MessageContent::SiblingEcho { body: SiblingEchoBody::Text { message_id, .. }, .. }) => message_id == target_message_id,
                _ => false,
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.awaiting_confirmation.remove(&id);
            self.remove_durable_retry(&id);
            self.cancel_server_deposit(&id);
        }
        // Copies still waiting for an unresolved member device. Only the
        // Text row itself (`group_row_id`); queued Edit/Delete entries stay.
        for queue in self.pending_group_messages.values_mut() {
            queue.retain(|c| group_row_id(c) != Some(target_message_id));
        }
        self.pending_group_messages.retain(|_, q| !q.is_empty());
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM pending_group_messages WHERE local_message_id = ?1",
                params![target_message_id],
            );
        }
    }

    pub(crate) fn delete_message(&mut self, peer_device_fingerprint: String, target_message_id: String) -> Result<(String, String), String> {
        let content = MessageContent::Delete { target_message_id: target_message_id.clone(), group_id: None, author_proof: None };
        // `?` first, like `edit_message`: nothing is deleted here unless the
        // delete could at least be queued for the peer.
        let result = Ok(self.send_message_content(peer_device_fingerprint.clone(), &content, None)?);
        self.withdraw_unsent(&target_message_id);
        self.fanout_extra_copies(&peer_device_fingerprint, &content);
        self.purge_attachment_if_exists(&target_message_id);
        self.apply_delete_to_archive(None, &peer_device_fingerprint, &target_message_id);
        self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::Delete {
            target_message_id: target_message_id.clone(),
        });
        result
    }

    /// Group counterpart of `edit_message`: same fan-out pattern as `send_group_message`/`request_older_group_history`. `target_group_message_local_id` is
    /// the `Text.group_message_local_id` of the group message to edit. Kotlin already uses THIS as the `messageId` of its bubble (see the GroupChatActivity note).
    pub(crate) fn edit_group_message(&mut self, group_id: String, target_group_message_local_id: String, new_text: String) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        // See `edit_message`: all copies carry the same ordering timestamp.
        let edited_at_ms = current_time_ms();
        let content = MessageContent::Edit {
            target_message_id: target_group_message_local_id.clone(),
            new_text: new_text.clone(),
            group_id: Some(group_id.clone()),
            edited_at_ms,
            author_proof: Some(self.sign_group_author(&group_id, &target_group_message_local_id, &new_text)?),
        };
        let others = group.other_members(&own_identity_id);
        let mut sent_to_any = others.is_empty(); // alone in the group: nobody to tell
        for member_identity_id in others {
            if self.send_group_message_to_member(&group_id, &member_identity_id, &content) {
                sent_to_any = true;
            }
        }
        if !sent_to_any {
            return Err("Ulaşılabilir grup üyesi yok".to_string());
        }
        self.apply_edit_to_archive(Some(&group_id), "", &target_group_message_local_id, &new_text, edited_at_ms);
        self.echo_group_to_siblings(&group_id, SiblingEchoBody::Edit {
            target_message_id: target_group_message_local_id.clone(), new_text: new_text.clone(), edited_at_ms,
        });
        Ok(())
    }

    /// See the note on `edit_group_message`: the group counterpart of `delete_message`. Also purges the local attachment file, if any.
    pub(crate) fn delete_group_message(&mut self, group_id: String, target_group_message_local_id: String) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        let tombstone = self.sign_group_author(&group_id, &target_group_message_local_id, GROUP_TOMBSTONE)?;
        let content = MessageContent::Delete {
            target_message_id: target_group_message_local_id.clone(),
            group_id: Some(group_id.clone()),
            author_proof: Some(tombstone.clone()),
        };
        let others = group.other_members(&own_identity_id);
        let mut sent_to_any = others.is_empty(); // alone in the group: nobody to tell
        for member_identity_id in others {
            if self.send_group_message_to_member(&group_id, &member_identity_id, &content) {
                sent_to_any = true;
            }
        }
        if !sent_to_any {
            return Err("Ulaşılabilir grup üyesi yok".to_string());
        }
        self.withdraw_unsent(&target_group_message_local_id);
        self.purge_attachment_if_exists(&target_group_message_local_id);
        self.apply_delete_to_archive(Some(&group_id), "", &target_group_message_local_id);
        self.adopt_group_author_proof(&group_id, &target_group_message_local_id, Some(&tombstone));
        self.echo_group_to_siblings(&group_id, SiblingEchoBody::Delete {
            target_message_id: target_group_message_local_id.clone(),
        });
        Ok(())
    }
}

impl P2PCore {

    /// See `MessageContent::Ack` (packet.rs). Sent back to the sender when a Text (outside groups), Edit, Delete or HistorySyncRequest is processed
    /// successfully. Fire-and-forget: this call itself goes through the normal short-lived `pending_envelopes`-based path of `send_message_content`. The
    /// Ack itself is NOT added to `awaiting_confirmation` (endless-loop risk, see the packet.rs note). If it is lost, the sender's retry falls through to
    /// `reack_if_already_handled`.
    pub(crate) fn send_ack(&mut self, peer_device_fingerprint: &str, target_message_id: &str) {
        let now = current_time_ms();
        if self.recently_acked.len() >= RECENTLY_ACKED_MAX_ENTRIES {
            self.recently_acked.retain(|_, (_, at)| now.saturating_sub(*at) < MAX_UNCONFIRMED_AGE_MS);
            if self.recently_acked.len() >= RECENTLY_ACKED_MAX_ENTRIES {
                // Drop the busiest peer's entries, not everyone's: one
                // flooding contact no longer wipes the re-ack memory of all.
                let mut per_peer: HashMap<&str, usize> = HashMap::new();
                for (peer, _) in self.recently_acked.values() {
                    *per_peer.entry(peer.as_str()).or_default() += 1;
                }
                let busiest = per_peer.into_iter().max_by_key(|(_, n)| *n).map(|(p, _)| p.to_string());
                if let Some(busiest) = busiest {
                    self.recently_acked.retain(|_, (peer, _)| *peer != busiest);
                }
            }
        }
        self.recently_acked.insert(target_message_id.to_string(), (peer_device_fingerprint.to_string(), now));
        let queue = self.outbound_acks.entry(peer_device_fingerprint.to_string()).or_default();
        if !queue.iter().any(|id| id == target_message_id) {
            queue.push(target_message_id.to_string());
        }
    }

    /// Applies an Ack (encrypted `MessageContent::Ack` or `AckBatchRequest`). The pending packet MUST really have been queued for this peer. Otherwise any
    /// peer could cancel a pending packet bound for another peer with a forged Ack using a known `message_id`. `None` = not applied.
    pub(crate) fn apply_incoming_ack(&mut self, peer_fp: &str, target_message_id: &str) -> Option<serde_json::Value> {
        let owned_by_this_peer = self.awaiting_confirmation.get(target_message_id)
            .map(|p| p.peer_device_fingerprint == peer_fp)
            .unwrap_or(false);
        if !owned_by_this_peer {
            return None;
        }
        let regen_content = self.awaiting_confirmation.get(target_message_id)
            .and_then(|p| p.regen_content.clone());
        self.awaiting_confirmation.remove(target_message_id);
        self.remove_durable_retry(target_message_id);
        // Acked over one path while a copy is still out on another: forget
        // the copy. Its late failure took it for an untracked envelope,
        // queued it, and the queue then reported "sent" or "error" for a
        // message the peer already has.
        let acked = |e: &NetworkEnvelope| matches!(e, NetworkEnvelope::Message(m) if m.header.message_id == target_message_id);
        self.envelopes_inflight.retain(|_, (_, e, _, _)| !acked(e));
        self.pending_envelopes.retain(|q| !acked(&q.envelope));
        // A text acked by a device of the peer (not one of our siblings) counts as delivered. The bubble id is the conversation-wide id shared by the
        // copies to every device.
        if let Some(MessageContent::Text { group_id, group_message_local_id, .. }) = &regen_content {
            let from_peer = self.known_remote_devices.get(peer_fp)
                .map_or(true, |d| self.my_identity_id().as_deref() != Some(d.identity_id.as_str()));
            let bubble_id = group_message_local_id.clone().unwrap_or_else(|| target_message_id.to_string());
            let changed = from_peer && self.db.as_ref().map_or(false, |c| c.execute(
                "UPDATE messages SET status = 'delivered' WHERE message_id = ?1 AND direction = 'sent' AND status != 'delivered'",
                params![bubble_id],
            ).map_or(false, |n| n > 0));
            if changed {
                // 1:1: the chat's canonical device, as the bubble's screen knows it.
                let peer = if group_id.is_some() { peer_fp.to_string() } else { self.canonical_peer_key(peer_fp) };
                let mut ev = serde_json::json!({
                    "type": "status", "peer": peer, "message_id": bubble_id,
                    "status": MessageSendStatus::Delivered.as_str(),
                });
                if let Some(gid) = group_id {
                    ev["group_id"] = serde_json::Value::String(gid.clone());
                }
                self.attachment_events.push(ev.to_string());
            }
        }
        let (event_message_id, event_group_id) = match &regen_content {
            Some(MessageContent::Edit { target_message_id: real_target, group_id, .. }) =>
                (real_target.clone(), group_id.clone()),
            Some(MessageContent::Delete { target_message_id: real_target, group_id, .. }) =>
                (real_target.clone(), group_id.clone()),
            // The UI knows a file bubble by `file_id`, not by the packet id.
            Some(MessageContent::FileOffer { file_id, group_id, .. }) =>
                (file_id.clone(), group_id.clone()),
            _ => (target_message_id.to_string(), None),
        };
        Some(match event_group_id {
            Some(gid) => serde_json::json!({"type": "ack", "peer": peer_fp, "group_id": gid, "message_id": event_message_id}),
            // 1:1: keyed like the chat screen, see the `status` event above.
            None => serde_json::json!({"type": "ack", "peer": self.canonical_peer_key(peer_fp), "message_id": event_message_id}),
        })
    }

    /// Encrypted packet path for an Ack, used when there is no live connection or the batch request failed (see `ACK_PROTOCOL`). If a server is configured,
    /// the Ack is left there.
    pub(crate) fn send_ack_message(&mut self, peer_device_fingerprint: &str, target_message_id: &str) {
        let content = MessageContent::Ack { target_message_id: target_message_id.to_string() };
        if let Err(e) = self.send_message_content(peer_device_fingerprint.to_string(), &content, None) {
            error!("Ack gönderilemedi: {}", e);
        }
    }

    /// Empties the `send_ack` queue: one `AckBatchRequest` to a peer with a live connection, encrypted Ack packets to the others. Called at the end of
    /// `poll_events`, so Acks produced in that turn leave in the same turn.
    pub(crate) fn flush_outbound_acks(&mut self) {
        if self.outbound_acks.is_empty() {
            return;
        }
        let queued = std::mem::take(&mut self.outbound_acks);
        for (fp, ids) in queued {
            let connected_peer = self.device_to_peer_id.get(&fp).copied()
                .filter(|p| self.swarm.as_ref().map_or(false, |s| s.is_connected(p)));
            match (connected_peer, self.swarm.as_mut()) {
                (Some(peer), Some(swarm)) => {
                    info!("Ack: {} adet toplu istekle (peer={})", ids.len(), crate::log_id(&fp));
                    for chunk in ids.chunks(ACK_BATCH_MAX) {
                        let request_id = swarm.behaviour_mut().acks.send_request(&peer, AckBatchRequest { ids: chunk.to_vec() });
                        self.ack_batches_inflight.insert(request_id, (fp.clone(), chunk.to_vec()));
                    }
                }
                _ => {
                    info!("Ack: {} adet şifreli paketle, canlı bağlantı yok (peer={})", ids.len(), crate::log_id(&fp));
                    for id in &ids {
                        self.send_ack_message(&fp, id);
                    }
                }
            }
        }
    }

    /// For a repeated `Message` that cannot be decrypted, or is byte-identical: if we already processed and acked this packet, resend the Ack. The sender
    /// only retries if our Ack never reached it, so this compensates for a lost Ack. The archive check covers messages that survive a restart.
    /// `recently_acked` covers types that are not archived (ReadStateSync, SiblingEcho, GroupUpdate, ...). The signature was already verified by the
    /// caller, and the sender must match.
    /// Ack for a Text, and a durable note of the packet id when the row is archived under ANOTHER id (group texts and fan-out copies use the
    /// conversation-wide id). `reack_if_already_handled` finds a replayed packet by its packet id. After a restart, `recently_acked` is empty and the row
    /// lookup missed these, so the sender resent for ~25 min.
    pub(crate) fn ack_text_packet(&mut self, peer_fp: &str, packet_id: &str, archived_as: Option<&str>) {
        self.send_ack(peer_fp, packet_id);
        if archived_as == Some(packet_id) {
            return;
        }
        if let Some(conn) = &self.db {
            let now = current_time_ms() as i64;
            // Pruned in `periodic_storage_sweep`, not per ack.
            let _ = conn.execute("INSERT OR REPLACE INTO acked_packets (packet_id, acked_at) VALUES (?1, ?2)", params![packet_id, now]);
        }
    }

    pub(crate) fn packet_was_acked(&self, packet_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row("SELECT 1 FROM acked_packets WHERE packet_id = ?1", params![packet_id], |_| Ok(())).is_ok()
        })
    }

    pub(crate) fn reack_if_already_handled(&mut self, header: &MessagePacketHeader) -> bool {
        let peer = header.sender_device_fingerprint.clone();
        let mid = header.message_id.clone();
        let recent = self.recently_acked.get(&mid)
            .map_or(false, |(p, at)| *p == peer && current_time_ms().saturating_sub(*at) < MAX_UNCONFIRMED_AGE_MS);
        if !recent && !self.received_from_sender(&mid, &peer) && !self.packet_was_acked(&mid) {
            return false;
        }
        // one re-ack per id per 5 s. The sender's retries are 15 s
        // apart or more; faster copies are replays (or the same packet over
        // another path), and each re-ack costs an encrypt + sign + send.
        let just_acked = self.recently_acked.get(&mid)
            .map_or(false, |(p, at)| *p == peer && current_time_ms().saturating_sub(*at) < 5_000);
        if just_acked {
            return true;
        }
        self.send_ack(&peer, &mid);
        true
    }

    /// User request: a "seen" notice, same pattern as `send_ack` (see the packet.rs `Seen` note). Unlike `Ack` it is NOT automatic. The Kotlin side must call
    /// it when the message is actually shown on screen (see ChatActivity/GroupChatActivity).
    pub(crate) fn send_seen(&mut self, peer_device_fingerprint: &str, target_message_id: &str, group_message_local_id: Option<String>) -> bool {
        let content = MessageContent::Seen {
            target_message_id: target_message_id.to_string(),
            group_message_local_id,
        };
        match self.send_message_content(peer_device_fingerprint.to_string(), &content, None) {
            Ok(_) => true,
            Err(e) => {
                error!("Görüldü bildirimi gönderilemedi: {}", e);
                false
            }
        }
    }

    /// "Typing..." indicator. See `MessageContent::TypingIndicator` (packet.rs). Not archived, not put in the reliable delivery queue. Fire-and-forget.
    pub(crate) fn send_typing_indicator(&mut self, peer_device_fingerprint: String, is_typing: bool) -> Result<(), String> {
        // With no live connection, do not send at all. Otherwise the message would be left on the server, and the recipient would fetch a stale "typing"
        // minutes later (measured on a device: 2 x ~8 KB per text to an offline recipient). No session: sending would start a handshake just for "typing".
        if !self.is_connected_to_device(&peer_device_fingerprint) || !self.has_active_session(&peer_device_fingerprint) {
            return Ok(());
        }
        let content = MessageContent::TypingIndicator { is_typing, group_id: None };
        self.send_message_content(peer_device_fingerprint, &content, None).map(|_| ())
    }

    /// Whether there is a live libp2p connection to this device right now (LAN, Tor or relay).
    pub(crate) fn is_connected_to_device(&self, device_fingerprint: &str) -> bool {
        self.device_to_peer_id.get(device_fingerprint)
            .map_or(false, |p| self.swarm.as_ref().map_or(false, |s| s.is_connected(p)))
    }

    /// Group version of `send_typing_indicator`, fanned out like
    /// `edit_group_message`/`delete_group_message`. Uses
    /// `resolve_active_device_for_identity` directly instead of the queuing
    /// `send_group_message_to_member` — a stale typing state delivered
    /// minutes later once a device resolves has no value.
    pub(crate) fn send_group_typing_indicator(&mut self, group_id: String, is_typing: bool) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        let content = MessageContent::TypingIndicator { is_typing, group_id: Some(group_id.clone()) };
        for member_identity_id in group.other_members(&own_identity_id) {
            if let Some(peer_fp) = self.resolve_active_device_for_identity(&member_identity_id)
                .filter(|fp| self.is_connected_to_device(fp) && self.has_active_session(fp))
            {
                if let Err(e) = self.send_message_content(peer_fp, &content, None) {
                    error!("Grup yazıyor göstergesi bir üyeye gönderilemedi: {}", e);
                }
            }
        }
        Ok(())
    }
}
