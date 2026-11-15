//! `receive_message` and the dispatch of decrypted content.

use super::*;

impl P2PCore {

    pub(crate) fn receive_message(&mut self, source: Option<PeerId>, packet: &MessagePacket) -> Result<String, String> {
        let sender = self.known_remote_devices.get(&packet.header.sender_device_fingerprint).cloned()
            .ok_or("Unknown sender device; cannot verify signatures")?;
        // Same sender-identity check as in `process_handshake_init`.
        if !sender.is_active {
            self.answer_revoked_sibling(&sender.device_fingerprint);
            return Err("Sender device has been revoked".to_string());
        }

        // The signature only proves that the `sender` DEVICE signed this packet. It does not prove that `sender_identity_id` in the header
        // belongs to that device. The device-to-identity link is recorded at pairing (TOFU, `DeviceRecord.identity_id`). If the header value
        // is not checked against it, a paired device could write another person's identity_id and impersonate that person in group messages
        // (see the group_message arm), or redirect a `ProfileUpdate` to another contact and overwrite that contact's avatar (see the
        // ProfileUpdate arm, which trusted this field through `identity_to_contact`). A mismatch rejects the whole packet.
        if packet.header.sender_identity_id != sender.identity_id {
            return Err("sender_identity_id does not match the signing device's stored identity".to_string());
        }

        let to_verify = packet_signing_input(packet.header.raw(), &packet.ciphertext, &self.get_active_own_device_fingerprint()?);
        verify_hybrid_signature(&to_verify, &packet.signature_classical, &packet.signature_pq, &sender)?;


        // Ratchet rotation sync: if the sender triggered a DH/KEM rotation with this message (`rotation_kyber_ciphertext` is set),
        // call `respond_to_rotation` to derive the same new keys on our side. If empty (normal message, no rotation), nothing is done.
        // `ratchet_pubkey` is sent with every message but only changes on rotation, so ignoring it otherwise is safe.
        // The ratchet applies the rotation only if the packet then decrypts on the new chain (see `decrypt` in ratchet.rs). The header is
        // not bound to the recipient: if a rotated packet sent to B were replayed to C, applying the rotation first would break C's session.
        // The state is written at once when the packet's rotation was applied.
        let rotated;
        // Rollback copy: if the advanced state cannot be saved, memory goes
        // back to it and the packet fails (no archive, no Ack), so the
        // sender's retry decrypts again instead of being lost.
        let mut snapshot: Option<DeviceRatchetState>;
        let decrypted = {
            let state = self.ratchets.get_mut(&packet.header.sender_device_fingerprint)
                .ok_or("No ratchet session for sender")?;
            snapshot = Some(state.clone());
            let new_peer_keys = packet.header.rotation_kyber_ciphertext.as_ref()
                .and_then(|_| RatchetPublicKeys::from_bytes(&packet.header.ratchet_pubkey).ok());
            let rotation = new_peer_keys.as_ref().zip(packet.header.rotation_kyber_ciphertext.as_deref());
            let result = state.decrypt(&packet.ciphertext, packet.header.message_number, rotation, current_time_ms(), packet.header.raw());
            rotated = result.as_ref().map_or(false, |(_, changes)| changes.rotated);
            result
        };
        if rotated {
            // The old topic is not dropped right away (the sender may still publish there). It is dropped at the next rotation.
            // Skipped keys of the old chain move into the state (`old_recv`). New keys derived by this decryption are written to the table
            // below. State first: the table rows are written only once the state holding them is on disk.
            if !self.persist_ratchet_state(&packet.header.sender_device_fingerprint) {
                if let Some(s) = snapshot.take() {
                    self.ratchets.insert(packet.header.sender_device_fingerprint.clone(), s);
                }
                return Err("Ratchet state could not be saved".to_string());
            }
            // The rotated state is on disk now: a later failure must not roll
            // memory back behind it.
            snapshot = None;
            self.clear_persisted_skipped_keys(&packet.header.sender_device_fingerprint);
            // Pending packets encrypted under the old chain are resent at once on the fresh chain, except the one this packet answers:
            // that one is closed below, and resending it would make the peer answer it a second time.
            let answered = decrypted.as_ref().ok().and_then(|(p, _)| answered_pending_id(p.as_slice()));
            let prev = self.regen_skip_id.clone();
            if answered.is_some() {
                self.regen_skip_id = answered;
            }
            self.regen_pending_for_peer(&packet.header.sender_device_fingerprint);
            self.regen_skip_id = prev;
        }
        let (payload_bytes, skipped_changes) = match decrypted {
            Ok(v) => v,
            Err(e) => {
                // Observed on two phones: an ack deadlock. Repeated `Message N not found in skipped-key cache (already decrypted, or evicted)`
                // errors in both directions for minutes. The loop: the SAME envelope arrives twice (normal here, since gossipsub and the server
                // both carry it, see `should_shadow_on_gossipsub`). The first copy is decrypted, archived and acked. The second copy arrives after
                // the chain has moved on and the skipped key for that message number is already consumed, so it cannot be decrypted. Without
                // decryption, `message_id` cannot be read, so the packet cannot be deduplicated, so no Ack is sent. The sender keeps retrying the
                // same envelope, which never decrypts, so the state stays locked. The lock only breaks when `MAX_UNCONFIRMED_AGE_MS` (~25 min)
                // passes and `regen_content` produces a fresh ciphertext. Both phones spent those 25 minutes on signature checks and radio traffic.
                // Breaking the lock does not need decryption. `MessagePacketHeader` is signed but NOT encrypted (see `send_message_content_inner`:
                // the signature covers `header ‖ ciphertext`, and the header travels in clear) and carries `message_id` in clear. The signature
                // was already verified at this point, so the field is trusted. If a message with that id IS in our archive, we processed this
                // packet before, and we can resend the Ack to stop the sender.
                // Deliberately narrow: an Ack is sent only when the archive really holds the message. If the key was truly lost (cache overflow
                // or rotation), the message is not in the archive, no Ack is sent, and the existing behaviour (retry with fresh encryption after
                // 25 min) stays. An undelivered message is never acked by mistake.
                if self.reack_if_already_handled(&packet.header) {
                    info!(
                        "Undecryptable packet already processed (id={}) — duplicate delivery, Ack re-sent (otherwise sender retries for ~25 min for nothing)",
                        packet.header.message_id
                    );
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // A number already consumed on the current chain is an old or
                // duplicate packet (e.g. resent after an app restart, when
                // `recently_acked` is empty again), not a sign of diverged sessions.
                // Nor is a packet made before this session was set up or last
                // rotated (`sent_at_ms` is signed): a captured old packet,
                // replayed three times, made us drop the live session, again
                // every two minutes.
                let session_since = self.ratchets.get(&packet.header.sender_device_fingerprint).map_or(0, |s| s.last_rotation);
                if !matches!(e, ratchet::RatchetError::KeyNotFound(_)) && packet.header.sent_at_ms >= session_since {
                    self.note_undecryptable(&packet.header.sender_device_fingerprint);
                }
                return Err(e.to_string());
            }
        };
        // The connection is mapped only now. A valid signature proves who WROTE the packet, not who DELIVERED it. Any contact holding an old
        // packet of this device could replay it to get its own PeerId mapped here, then take our direct sends to the device and fake AckBatch
        // receipts. A replayed or cross-addressed packet never decrypts.
        self.record_peer_id_if_known(source, &packet.header.sender_device_fingerprint);
        self.undecryptable_from.remove(&packet.header.sender_device_fingerprint);
        let state = self.ratchets.get_mut(&packet.header.sender_device_fingerprint)
            .ok_or("No ratchet session for sender")?;
        // If we triggered the rotation (`pending_rotation_ct`, ratchet.rs), a packet that decrypts on the NEW chain from the peer proves the
        // peer applied the rotation, so the announcement no longer needs to be added to every packet. A packet of the chain before the rotation
        // (`old_chain`) proves nothing: the peer sent it before it knew.
        if !skipped_changes.old_chain && state.pending_rotation_ct.take().is_some() {
            info!(
                "Rotation applied by peer (peer={}) — stopping announcement repeats",
                crate::log_id(&packet.header.sender_device_fingerprint)
            );
        }
        // Write skipped-key changes to disk (encrypted with the Keystore). Before the ratchet state: a crash in between must not leave the
        // advanced counter on disk without the keys it skipped.
        let mut saved = true;
        for (msg_num, key) in &skipped_changes.added {
            if let Err(e) = self.persist_skipped_key(&packet.header.sender_device_fingerprint, *msg_num, key) {
                error!("Could not write skipped key to disk: {}", e);
                saved = false;
                break;
            }
        }
        // `decrypt` advances ck_recv/recv_message_number on every call, so keep the disk copy current. If the write fails, memory is rolled
        // back and the packet fails: the retry must still find the key it needs.
        if saved {
            saved = self.persist_ratchet_state(&packet.header.sender_device_fingerprint);
        }
        if !saved {
            if let Some(s) = snapshot.take() {
                self.ratchets.insert(packet.header.sender_device_fingerprint.clone(), s);
            }
            return Err("Ratchet state could not be saved".to_string());
        }
        drop(snapshot);
        // Used keys go only after the state that no longer needs them is on disk.
        for msg_num in &skipped_changes.used {
            self.delete_persisted_skipped_key(&packet.header.sender_device_fingerprint, *msg_num);
        }
        // Only now: for a stale device this resends its parked rows, and any
        // send before the state above was on disk could be rolled back to
        // `snapshot`, reusing the message keys it spent.
        self.touch_device_seen(&packet.header.sender_device_fingerprint);

        let peer_fp = packet.header.sender_device_fingerprint.clone();
        let sender_identity_id = packet.header.sender_identity_id.clone();
        let message_id = packet.header.message_id.clone();
        // Parsed only after the ratchet is on disk. A variant this version
        // does not know is acked: a retry can never parse either.
        let content: MessageContent = match MessageContent::from_cbor(payload_bytes.as_slice()) {
            Ok(c) => c,
            Err(e) => {
                warn!("Could not parse packet content (id={}): {}", message_id, e);
                self.send_ack(&peer_fp, &message_id);
                return Ok(serde_json::json!({"type": "noop"}).to_string());
            }
        };
        let mut content = content;
        // The send time as the author sent it, for the revoke check of a group
        // author proof: clamped to now, a future stamp from a device revoked
        // later than now read as "sent before the revoke".
        let signed_sent_at_ms = match &content { MessageContent::Text { sent_at_ms, .. } => *sent_at_ms, _ => 0 };
        clamp_received_times(&mut content, current_time_ms());
        self.dispatch_received_content(source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms)
    }

    /// The decrypted content of a received packet, acted on. Content for a
    /// group we do not hold yet (its GroupUpdate may still be on the way) is
    /// held in memory (`unknown_group_held`) instead of being archived, and
    /// goes through here again, membership checked, once the group is known.
    pub(crate) fn dispatch_received_content(&mut self, source: Option<PeerId>, peer_fp: String, sender_identity_id: String, message_id: String, content: MessageContent, signed_sent_at_ms: u64) -> Result<String, String> {
        let held_gid = match &content {
            MessageContent::Text { group_id: Some(g), .. }
            | MessageContent::FileOffer { group_id: Some(g), .. }
            | MessageContent::Reaction { group_id: Some(g), .. } => Some(g.clone()),
            _ => None,
        };
        if let Some(gid) = held_gid.filter(|g| !self.groups.contains_key(g)) {
            if is_group_id(&gid) && !self.group_removed_locally(&gid) {
                // No Ack: dropped here (cap, age, restart), the sender's retry
                // brings it again.
                let now = current_time_ms();
                self.unknown_group_held.retain(|_, b| {
                    b.retain(|e| now.saturating_sub(e.0) <= UNKNOWN_GROUP_HOLD_TTL_MS);
                    !b.is_empty()
                });
                let room = self.unknown_group_held.contains_key(&gid) || self.unknown_group_held.len() < UNKNOWN_GROUP_HOLD_GROUPS;
                let buf = self.unknown_group_held.get(&gid);
                let dup = buf.map_or(false, |b| b.iter().any(|e| e.4 == message_id));
                let full = buf.map_or(false, |b| b.len() >= UNKNOWN_GROUP_HOLD_PER_GROUP);
                // Per sender and in bytes too, as `buffer_edit_or_delete`: one
                // contact with invented group ids held all slots and up to
                // ~1 GiB of text.
                let held_bytes = |c: &MessageContent| match c {
                    MessageContent::Text { text, .. } => text.len(),
                    MessageContent::FileOffer { preview_jpeg, caption, .. } => preview_jpeg.as_ref().map_or(0, |p| p.len()) + caption.len(),
                    _ => 0,
                };
                let all = self.unknown_group_held.values().flatten();
                let sender_full = all.clone().filter(|e| e.2 == peer_fp).count() >= UNKNOWN_GROUP_HOLD_PER_GROUP;
                let bytes_full = all.map(|e| held_bytes(&e.5)).sum::<usize>() + held_bytes(&content) > 16 * 1024 * 1024;
                if room && !dup && !full && !sender_full && !bytes_full {
                    self.unknown_group_held.entry(gid).or_default()
                        .push((now, source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms));
                }
            } else if is_group_id(&gid) {
                // A group removed here: final until a GroupUpdate adds us
                // again. Acked, as for a contact removed here, or the sender
                // retried it for 7 days.
                self.send_ack(&peer_fp, &message_id);
            }
            return Ok(serde_json::json!({"type": "noop"}).to_string());
        }
        let result = self.dispatch_received_content_inner(source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms);
        self.replay_unknown_group_held();
        result
    }

    /// Replays the held content of every group that is known now (see
    /// `dispatch_received_content`). Each entry is checked like a live one:
    /// a sender that is not a member is refused.
    pub(crate) fn replay_unknown_group_held(&mut self) {
        let ready: Vec<String> = self.unknown_group_held.keys().filter(|g| self.groups.contains_key(*g)).cloned().collect();
        for gid in ready {
            let Some(buf) = self.unknown_group_held.remove(&gid) else { continue };
            for (_, source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms) in buf {
                match self.dispatch_received_content(source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms) {
                    Ok(event) => self.attachment_events.push(event),
                    Err(e) => warn!("Could not process held group packet (group={}): {}", gid, e),
                }
            }
        }
    }

    pub(crate) fn dispatch_received_content_inner(&mut self, source: Option<PeerId>, peer_fp: String, sender_identity_id: String, message_id: String, content: MessageContent, signed_sent_at_ms: u64) -> Result<String, String> {
        // Multi-device: the sender may have several devices. The local chat/archive key is merged under that person's stable canonical device
        // (see `canonical_peer_key`). Replies such as ACK/Seen still go to the real sender `peer_fp` (over the ratchet with that device). Only the
        // local archive key and the "peer" field sent to the UI are canonicalised. For single-device contacts `chat_key == peer_fp` (no change).
        let chat_key = self.canonical_peer_key(&peer_fp);

        // Every line that `pollNetwork` returns to the Kotlin side is now a JSON event tagged `{"type":...}`, not plain text (see
        // P2PService/ChatActivity). This carries edit/delete through the same String channel (without changing the JNI signature) and tells
        // the UI WHICH peer a message belongs to. Before, that was never passed on: with several chats open, each incoming message went to
        // whichever ChatActivity was open, not to the right one.
        let event = match content {
            MessageContent::Text { group_id: None, text, group_message_local_id, sent_at_ms, reply_to_message_id, reply_to_preview, .. } => {
                // Multi-device: a STABLE conversation id. `group_message_local_id` if present (the SAME in all fan-out copies from the sender),
                // otherwise (older sender) the id in the packet header. Archive, UI, edit, delete and seen all use this. ACK uses the packet's
                // OWN `message_id` (per-device delivery).
                let display_id = group_message_local_id.clone().unwrap_or_else(|| message_id.clone());
                // Double archive: the SAME logical message can arrive twice. The `regen_content` refresh sends a FRESH (decryptable) ciphertext
                // with the SAME id after a lost Ack, and the persistent queue resends after a restart. This arm used to dedup nothing, so each
                // repeat made a separate archive row (the UI hid it, but archive/history sync kept copying the pairs). Ack is still sent: that is
                // the only way the sender's retry stops.
                info!("Text received: id={} source={}", display_id.chars().take(8).collect::<String>(), if source.is_some() { "p2p" } else { "server" });
                if self.message_exists_in_chat(&display_id, None, &chat_key) {
                    self.ack_text_packet(&peer_fp, &message_id, Some(&display_id));
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // See the same note in send_message_content. Each device now keeps its own history encrypted locally, regardless of node mode.
                // The Ack is sent only if the archive write was made PERMANENT. Otherwise (a transient failure such as a full disk or DB error)
                // the sender would be told "received, no retry" while the message is stored nowhere. Without an Ack, the sender's
                // `awaiting_confirmation` mechanism (see its docs) retries automatically.
                match self.archive_message(&chat_key, "received", text.as_bytes(), Some(&display_id), None, reply_to_message_id.as_deref(), reply_to_preview.as_deref(), sent_at_ms) {
                    Ok(()) => {
                        self.ack_text_packet(&peer_fp, &message_id, Some(&display_id));
                        // See `pending_edits_deletes`. If an Edit/Delete for this message arrived BEFORE the Text (gossipsub gives no ordering),
                        // apply it now.
                        self.replay_buffered_edits_deletes(&display_id);
                    }
                    Err(e) => {
                        // No event either: the UI would show a message that is
                        // gone on reload, and show it again when the retry lands.
                        error!("Could not archive message, Ack deferred (sender will retry): {}", e);
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                }
                // `sent_at_ms` is the send time on the SENDER's device. The receiving side can show both the local receive time and the real send
                // time, e.g. "10:42 (sent at: 10:41)" (see ChatActivity/SimpleChatAdapter). 0 = old or unknown version; the Kotlin side then skips
                // the bracketed display (see the `sent_at_ms` note in packet.rs).
                // Reply field (WhatsApp-style): see the `MessageContent::Text.reply_to_message_id` docs in packet.rs. The live event carries it
                // too, so an open screen draws the message correctly at once, without waiting for an archive write or reload.
                serde_json::json!({
                    "type": "message", "peer": chat_key, "message_id": display_id, "text": text, "sent_at_ms": sent_at_ms,
                    "reply_to_message_id": reply_to_message_id, "reply_to_preview": reply_to_preview
                })
            }
            MessageContent::Text { group_id: Some(gid), text, group_message_local_id, sent_at_ms, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, author_proof, mentions } => {
                // Group integration: this is one pairwise fan-out copy of a group message. It carries `group_id` AND the sender's `identity_id`
                // (required in a group, unlike 1:1, since several people are in it), so GroupChatActivity can route it to the right chat.
                // `group_message_local_id` is the id Kotlin must send back when marking a message "seen" (see Seen). `message_id` means nothing to
                // the sender (see packet.rs). Only this shared id is common across the N copies.
                // Before, this arm archived NOTHING: a received group message was passed to Kotlin only as a temporary JSON event in this one
                // `pollNetwork` turn. If the screen was not open, or the process restarted, the message was lost for good.
                // `group_message_local_id` is the same across all N copies, so it is the archive id instead of `message_id`, and the "seen" match
                // after a reload still works.
                // Double archive fix, same dedup as the 1:1 Text arm: `group_message_local_id` is stable across fan-out copies and repeats, so it
                // is the dedup key. Without it (older sender) no dedup is possible and the old behaviour stays. Ack is still sent.
                // See `sender_may_post_to_group`. A removed member (or someone with no link to the group) could get a message this far: it went
                // into the archive and looked like a legitimate group message. No Ack is sent here: a member that is legitimately added will have
                // its retry accepted once the `GroupUpdate` reaches us.
                if !self.sender_may_post_to_group(&gid, &sender_identity_id) {
                    warn!(
                        "Group message REJECTED: sender is not a member of this group (group={}, sender={})",
                        gid, crate::log_id(&sender_identity_id)
                    );
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // The id must carry the sender's author tag (`group_msg_tag`):
                // then no other member can hold it, and a row already under
                // it is this sender's own copy (a duplicate).
                if !group_message_local_id.as_deref().map_or(false, |id| group_msg_id_bound(&gid, &sender_identity_id, id)) {
                    warn!(
                        "Group message refused: id not bound to its author (group={}, sender={})",
                        gid, crate::log_id(&sender_identity_id)
                    );
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                let (reply_to_message_id, reply_to_preview, reply_to_sender_identity_id) =
                    if group_reply_bound(&gid, reply_to_message_id.as_deref(), reply_to_sender_identity_id.as_deref()) {
                        (reply_to_message_id, reply_to_preview, reply_to_sender_identity_id)
                    } else {
                        (None, None, None)
                    };
                let already_archived = group_message_local_id.as_deref()
                    .map(|id| self.message_exists_in_chat(id, Some(gid.as_str()), ""))
                    .unwrap_or(false);
                if already_archived {
                    self.ack_text_packet(&peer_fp, &message_id, group_message_local_id.as_deref());
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // Kept only when it checks out: other members hand it on with
                // the group history as the proof of who wrote this.
                let author_proof = author_proof.filter(|p| {
                    group_message_local_id.as_deref().map_or(false, |mid| self.group_author_proof_valid(&gid, mid, &sender_identity_id, &text, signed_sent_at_ms, Some(p.as_str())))
                });
                let archived_ok = self.archive_group_message(&gid, &sender_identity_id, "received", text.as_bytes(), group_message_local_id.as_deref(), reply_to_message_id.as_deref(), reply_to_preview.as_deref(), reply_to_sender_identity_id.as_deref(), sent_at_ms, author_proof.as_deref()).is_ok();
                let mentions_me = self.group_mentions_me(&gid, mentions);
                if archived_ok && mentions_me {
                    if let (Some(conn), Some(mid)) = (&self.db, group_message_local_id.as_deref()) {
                        let _ = conn.execute("UPDATE messages SET mentions_me = 1 WHERE group_id = ?1 AND message_id = ?2", params![gid, mid]);
                    }
                }
                // Group text messages never got an Ack before. See `needs_delivery_confirmation`: group messages were deliberately left out of
                // this mechanism. That meant the sender's `awaiting_confirmation` retry loop could never fire for them, and the single
                // `publish_envelope` (which gave up silently after 20 s) was the ONLY guarantee. If a recipient was briefly unreachable (sleep,
                // background, a short NAT or network change), the message was lost SILENTLY. With 3 members, each fan-out copy needs its own
                // dial, so a member busy or asleep at that moment lost messages systematically.
                // Now the SAME Ack mechanism as everything else is used (see the `needs_delivery_confirmation` note, which now covers group text).
                // The Ack is sent only if the archive write was made permanent (see the same note in the 1:1 Text arm). Otherwise the sender's
                // retry carries on.
                if archived_ok {
                    self.ack_text_packet(&peer_fp, &message_id, group_message_local_id.as_deref());
                    // See `pending_edits_deletes`. If an Edit/Delete for this group Text arrived BEFORE it, apply it now. In a group context
                    // `target_message_id` is the `group_message_local_id` (see the edit_group_message/delete_group_message note). Without it (older
                    // sender) nothing could have been buffered, so this is skipped.
                    if let Some(local_id) = &group_message_local_id {
                        self.replay_buffered_edits_deletes(local_id);
                    }
                } else {
                    error!("Could not archive group message, Ack deferred (sender will retry)");
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                serde_json::json!({
                    "type": "group_message", "group_id": gid, "peer": peer_fp,
                    "sender_identity_id": sender_identity_id,
                    "message_id": message_id, "text": text,
                    "group_message_local_id": group_message_local_id,
                    "sent_at_ms": sent_at_ms,
                    "reply_to_message_id": reply_to_message_id, "reply_to_preview": reply_to_preview,
                    "reply_to_sender_identity_id": reply_to_sender_identity_id,
                    "mentions_me": mentions_me
                })
            }
            MessageContent::Edit { target_message_id, new_text, group_id, edited_at_ms, author_proof } => {
                // Gossipsub gives no ordering guarantee, so an Edit can arrive before the Text it targets. The target row is then absent from the archive, which is not the same as belonging to someone else. Such an Edit is buffered (see `pending_edits_deletes`). Otherwise `message_owned_by_sender` would find no target, reject the packet permanently, and the Text would never get the edit.
                if self.edit_target_in_chat(&target_message_id, group_id.as_deref(), &peer_fp) {
                    self.apply_edit_or_delete_content(&peer_fp, &sender_identity_id, &message_id,
                        MessageContent::Edit { target_message_id, new_text, group_id, edited_at_ms, author_proof })
                } else {
                    self.buffer_edit_or_delete(&target_message_id, &peer_fp, &sender_identity_id, &message_id,
                        MessageContent::Edit { target_message_id: target_message_id.clone(), new_text, group_id, edited_at_ms, author_proof });
                    serde_json::json!({"type": "noop"})
                }
            }
            MessageContent::Delete { target_message_id, group_id, author_proof } => {
                // See the Edit arm above.
                if self.edit_target_in_chat(&target_message_id, group_id.as_deref(), &peer_fp) {
                    self.apply_edit_or_delete_content(&peer_fp, &sender_identity_id, &message_id,
                        MessageContent::Delete { target_message_id, group_id, author_proof })
                } else {
                    self.buffer_edit_or_delete(&target_message_id, &peer_fp, &sender_identity_id, &message_id,
                        MessageContent::Delete { target_message_id: target_message_id.clone(), group_id, author_proof });
                    serde_json::json!({"type": "noop"})
                }
            }
            MessageContent::Reaction { target_message_id, emoji, group_id, reacted_at_ms } => {
                // `Reaction` is in `needs_delivery_confirmation`: the sender retries it for 7 days until acked. It is acked once written or
                // rejected for good. It is NOT acked when the write failed (the retry brings it back), nor from a non-member of a known group (as
                // with group Text: a member we do not know of yet is taken once its GroupUpdate arrives).
                // See `sender_may_post_to_group`. Same gap as group Text/FileOffer; reactions are archived too (reactions table).
                if let Some(gid) = &group_id {
                    if !self.sender_may_post_to_group(gid, &sender_identity_id) {
                        warn!(
                            "Group reaction REJECTED: sender is not a member of this group (group={}, sender={})",
                            gid, crate::log_id(&sender_identity_id)
                        );
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                }
                // The target must be a message of the chat the reaction names:
                // `group_id: None` skipped the membership check above, and any
                // contact could react on a group message whose id it knew.
                if emoji.len() > 64 || !self.reaction_fits_chat(&target_message_id, group_id.as_deref(), &sender_identity_id) {
                    warn!("Reaction REJECTED: target not in this chat or emoji too long (sender={})", crate::log_id(&sender_identity_id));
                    self.send_ack(&peer_fp, &message_id);
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                if !self.apply_reaction(&target_message_id, &sender_identity_id, &emoji, reacted_at_ms) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                self.send_ack(&peer_fp, &message_id);
                self.requeue_archive_row(group_id.as_deref(), &chat_key, &target_message_id);
                let summary = self.reactions_summary(&target_message_id);
                match &group_id {
                    Some(gid) => serde_json::json!({
                        "type": "reaction", "group_id": gid,
                        "message_id": target_message_id, "reactions": summary
                    }),
                    None => serde_json::json!({
                        "type": "reaction", "peer": chat_key,
                        "message_id": target_message_id, "reactions": summary
                    }),
                }
            }
            MessageContent::HistorySyncRequest { limit, before_timestamp, group_id, after_timestamp } => {
                // `load_message_history`/`load_group_message_history` return an empty list when `history_key` was never loaded or the archive is empty, so no separate `node_mode_enabled` check is needed. This is a control packet, not a user message, so it is not written to our archive (archive_plaintext: None, see send_message_content).
                // The `limit` in the request comes from the other side. Row count and total text bytes are capped, so the reply stays under gossipsub's 1 MB `max_transmit_size` (see `PublishFailure`). The cut-off part is fetched later with a paging request (before_timestamp).
                // Group history goes only to someone who is a member now. Otherwise anyone who knew the `group_id`, such as a removed member, could page through the history, including messages sent after their removal.
                if let Some(gid) = &group_id {
                    if !self.groups.get(gid).map_or(false, |g| g.is_member(&sender_identity_id)) {
                        warn!("Group history request REJECTED: sender is not a member (group={}, sender={})", gid, crate::log_id(&sender_identity_id));
                        // Ack: the request is in `needs_delivery_confirmation`, and no reply will come, otherwise the sender would retry for days.
                        self.send_ack(&peer_fp, &message_id);
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                }
                // One answer per device per 2 s (a page is asked for by a
                // scroll). Each answer is up to 512 KiB, tracked and retried
                // until acknowledged: a few hundred requests from a peer that
                // never acks held hundreds of MB.
                // A shed request is NOT acked and does not restart the window:
                // the requester's retry gets the answer a little later.
                let now = current_time_ms();
                if self.history_answered_at.len() > 1000 {
                    self.history_answered_at.retain(|_, t| now.saturating_sub(*t) < 2_000);
                }
                if self.history_answered_at.get(&peer_fp).map_or(false, |t| now.saturating_sub(*t) < 2_000) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // and at most HISTORY_SYNC_BYTES_PER_WINDOW of rows per
                // device per minute, shed the same way.
                const HISTORY_SYNC_WINDOW_MS: u64 = 60_000;
                const HISTORY_SYNC_BYTES_PER_WINDOW: usize = 2 * 1024 * 1024;
                if self.history_sent_bytes.len() > 1000 {
                    self.history_sent_bytes.retain(|_, (start, _)| now.saturating_sub(*start) < HISTORY_SYNC_WINDOW_MS);
                }
                if self.history_sent_bytes.get(&peer_fp).map_or(false, |(start, sent)| now.saturating_sub(*start) < HISTORY_SYNC_WINDOW_MS && *sent >= HISTORY_SYNC_BYTES_PER_WINDOW) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                self.history_answered_at.insert(peer_fp.clone(), now);
                let limit = limit.min(HISTORY_SYNC_MAX_MESSAGES);
                // Multi-device fix: our 1:1 archive is under the CANONICAL device key (see `canonical_peer_key` and the Text arm). A request from a
                // non-canonical device of the requester must also find the same chat history.
                // A "Fetch older history" press gets only rows sent in its window `[after, before)`, at most one window long. The chat-open sync
                // (no `before_timestamp`) is unchanged. A group member gets history from at most one day before it was added (its latest add,
                // `GroupMember.added_at`, our local time of that update), never older. Our own other devices get everything. A missing or zero
                // `added_at` counts as now.
                const GROUP_HISTORY_BEFORE_JOIN_MS: u64 = 24 * 60 * 60 * 1000;
                let history_floor: Option<u64> = group_id.as_ref().and_then(|gid| {
                    if self.my_identity_id().as_deref() == Some(sender_identity_id.as_str()) {
                        return None;
                    }
                    let added = self.groups.get(gid)
                        .and_then(|g| g.members.iter().find(|m| m.identity_id == sender_identity_id))
                        .map(|m| m.added_at)
                        .filter(|t| *t > 0)
                        .unwrap_or(now);
                    Some(added.saturating_sub(GROUP_HISTORY_BEFORE_JOIN_MS))
                });
                let window = before_timestamp.map(|b| {
                    let min_after = b.saturating_sub(HISTORY_FETCH_WINDOW_MS as i64);
                    let after = after_timestamp.map_or(min_after, |a| a.max(min_after));
                    (b, history_floor.map_or(after, |f| after.max(f as i64)))
                });
                let mut history = match (&group_id, window) {
                    (_, Some((before, after))) if before <= after => Vec::new(),
                    (gid, Some((before, after))) => self.load_history_fetch_page(&chat_key, gid.as_deref(), limit, before, after),
                    (Some(gid), None) => self.load_group_message_history_opt(gid, limit, None, false),
                    (None, None) => self.load_message_history_opt(&chat_key, limit, None, false),
                };
                // Rows count as pre-join if we got them before the floor OR
                // their author sent them before it (a row we fetched late).
                let raw_loaded = history.len();
                if let Some(f) = history_floor {
                    history.retain(|m| m.timestamp >= f && (m.sent_at_ms == 0 || m.sent_at_ms >= f));
                }
                let loaded = history.len();
                // `history` is oldest first and the requester pages backwards
                // from the oldest row it gets, so the budget must cut the OLD
                // end: walk from the newest. The newest row is always sent, or
                // one oversized row would end the paging for good.
                let mut text_budget: usize = HISTORY_SYNC_MAX_TEXT_BYTES;
                let mut first = true;
                // Group rows go out with their author's signature. It is far
                // larger than most texts, so it counts toward the budget.
                if let Some(gid) = &group_id {
                    for m in history.iter_mut() {
                        m.author_proof = m.message_id.as_deref().and_then(|id| self.group_author_proof(gid, id));
                    }
                }
                // Reactions: only the requester's and mine (the only ones it
                // takes), and they count toward the budget too.
                let own_id = self.my_identity_id().unwrap_or_default();
                let mut kept: Vec<(ArchivedMessage, Vec<(String, String, u64)>)> = history.into_iter().rev()
                    .map(|m| {
                        let r = m.message_id.as_deref().map(|id| self.reactions_of(id, [sender_identity_id.as_str(), own_id.as_str()])).unwrap_or_default();
                        (m, r)
                    })
                    .take_while(|(m, r)| {
                        let cost = m.text.len() + m.author_proof.as_ref().map_or(0, |p| p.len())
                            + r.iter().map(|(who, emoji, _)| who.len() + emoji.len() + 16).sum::<usize>();
                        let is_first = std::mem::take(&mut first);
                        if cost > text_budget && !is_first {
                            return false;
                        }
                        text_budget = text_budget.saturating_sub(cost);
                        true
                    })
                    .collect();
                kept.reverse();
                // Rows of the window were cut: the requester asks for the rest.
                // `raw_loaded`: a full page before the filter may still have more; a page the filter emptied has no row to page from.
                let more = window.is_some() && !kept.is_empty() && (raw_loaded as u32 >= limit || kept.len() < loaded);
                let messages: Vec<SyncedMessage> = kept.into_iter()
                    .map(|(m, reactions)| SyncedMessage {
                        reactions,
                        direction: m.direction, text: m.text, timestamp: m.timestamp,
                        sender_identity_id: m.sender_identity_id, message_id: m.message_id,
                        sent_at_ms: m.sent_at_ms, is_deleted: m.is_deleted, is_edited: m.is_edited,
                        author_proof: m.author_proof,
                    })
                    .collect();
                // `request_id` carries the REQUEST's own `message_id`, so the requester can match this reply to its `awaiting_confirmation` entry
                // and take it out of the retry queue (see packet.rs).
                let response = MessageContent::HistorySyncResponse {
                    request_id: message_id.clone(), messages, group_id: group_id.clone(), more,
                };
                if let Err(e) = self.send_message_content(peer_fp.clone(), &response, None) {
                    error!("HistorySyncResponse could not be sent: {}", e);
                    // nothing went out, the window is not used up.
                    self.history_answered_at.remove(&peer_fp);
                } else {
                    let used = HISTORY_SYNC_MAX_TEXT_BYTES - text_budget;
                    let entry = self.history_sent_bytes.entry(peer_fp.clone()).or_insert((now, 0));
                    if now.saturating_sub(entry.0) >= HISTORY_SYNC_WINDOW_MS {
                        *entry = (now, 0);
                    }
                    entry.1 += used;
                }
                // No client handles this event, and none needs to: the other side asking for history is not something the user has to see.
                // Logged for diagnostics, and emitted to the stream as `noop`.
                info!("History sync requested (peer={}, group={:?})", crate::log_id(&peer_fp), group_id);
                serde_json::json!({"type": "noop"})
            }
            MessageContent::HistorySyncResponse { request_id, messages, group_id, more } => {
                // A group request is open to every member, but each answers once.
                let answered_before = self.history_answered_by.get(&request_id).is_some_and(|s| s.contains(&sender_identity_id));
                let solicited = !answered_before && match self.outstanding_history_requests.get(&request_id) {
                    Some((target_identity, req_group, _, _)) if *req_group == group_id => match &group_id {
                        Some(gid) => self.groups.get(gid).map_or(false, |g| g.is_member(&sender_identity_id)),
                        None => target_identity.as_deref() == Some(sender_identity_id.as_str()),
                    },
                    _ => false,
                };
                if !solicited {
                    // The Ack is still sent: otherwise the responder would retry for nothing.
                    self.send_ack(&peer_fp, &message_id);
                    // A member answering its own request again (it got a
                    // resent copy) is handled already, not unsolicited.
                    if answered_before {
                        debug!("HistorySyncResponse already taken from this member (peer={}, request_id={})", crate::log_id(&peer_fp), request_id);
                    } else {
                        warn!("Unsolicited HistorySyncResponse REJECTED (peer={}, request_id={})", crate::log_id(&peer_fp), request_id);
                    }
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // The request is closed and the response acked only AFTER the
                // rows are on disk (see the end of this arm): a failed write
                // leaves both open, the responder's retry is still solicited.
                // An archive write failure sets this.
                let mut write_failed = false;
                // No more rows than could be asked for. In 1:1 only the
                // peer's own messages: nothing proves who wrote a row, and
                // every row the peer marked "received" became a message WE
                // sent, backdated, on all our devices. Our own messages come
                // back from a sibling or from our server archive.
                let mut messages = messages;
                messages.truncate(HISTORY_SYNC_MAX_MESSAGES as usize);
                // reactions ride along; applied at the end, only on the rows
                // that passed the filters below (see `apply_synced_reactions`).
                let mut reactions: HashMap<String, Vec<(String, String, u64)>> = HashMap::new();
                for m in messages.iter_mut() {
                    if let Some(mid) = m.message_id.clone() {
                        let mut r = std::mem::take(&mut m.reactions);
                        r.truncate(64);
                        reactions.insert(mid, r);
                    }
                }
                let floor_key = group_id.clone().unwrap_or_else(|| sender_identity_id.clone());
                let press = self.filter_history_reply(&request_id, group_id.as_deref(), &sender_identity_id, &mut messages);
                // Send time of the oldest row written (a press lowers the floor to it).
                let mut oldest_written: Option<u64> = None;
                // `group_id` is the one we asked with (`solicited`); the page
                // kind comes from our request (`press`), never the
                // responder's word. A group answer went down the 1:1 arm
                // below: unfiltered, unsigned rows, archived into our 1:1
                // chat as sent by us.
                let mut event = if group_id.is_some() || press.is_some() {
                    // Infinite scroll: this is an OLDER PAGE reply. The usual "newer than the latest timestamp" threshold would work in the WRONG
                    // direction here (this paging deliberately fetches older messages), so a `message_id` existence check is used instead.
                    match &group_id {
                        Some(gid) => {
                            let own_identity_id = self.identity.as_ref().map(|i| i.identity_id.clone());
                            let merged: Vec<serde_json::Value> = messages.into_iter().filter_map(|mut m| {
                                // For "sent", the sender is the RESPONDER itself (already known from the packet header, `sender_identity_id`).
                                // For "received", the real sender is taken from the responder's own archive (see the SyncedMessage note in packet.rs).
                                let actual_sender = if m.direction == "sent" {
                                    Some(sender_identity_id.clone())
                                } else {
                                    m.sender_identity_id.clone()
                                };
                                let our_direction = if actual_sender == own_identity_id { "sent" } else { "received" };
                                // A row the responder did not write itself is
                                // taken only with its author's signature: the
                                // responder could otherwise put any text under
                                // any name, ours included.
                                let author = actual_sender.clone().unwrap_or_default();
                                // A deleted row has no text: its author signed
                                // the deletion instead.
                                if m.is_deleted {
                                    m.text.clear();
                                }
                                let signed_text = if m.is_deleted { GROUP_TOMBSTONE } else { m.text.as_str() };
                                let signed = m.message_id.as_deref().map_or(false, |mid| {
                                    self.group_author_proof_valid(gid, mid, &author, signed_text, if m.sent_at_ms != 0 { m.sent_at_ms } else { m.timestamp }, m.author_proof.as_deref())
                                });
                                if !signed {
                                    m.author_proof = None;
                                    if m.direction != "sent" {
                                        warn!("Group history row skipped: author signature missing or invalid (group={}, author={})", gid, crate::log_id(&author));
                                        return None;
                                    }
                                }
                                // A row without an id cannot be deduped: it was
                                // never archived, but shown again on every page.
                                let Some(mid) = m.message_id.clone() else { return None };
                                // The id must carry its author's tag
                                // (`group_msg_tag`): no other member can then
                                // have taken it, so a row already under it is
                                // this author's and a duplicate.
                                if !group_msg_id_bound(gid, &author, &mid) {
                                    warn!("Group history row skipped: identity not bound to author (group={}, author={})", gid, crate::log_id(&author));
                                    return None;
                                }
                                if !self.message_exists_in_chat(&mid, Some(gid.as_str()), "") {
                                    // NOTE: `SyncedMessage` (see packet.rs) does not carry reply info yet. Old messages that arrive via history
                                    // sync are archived without a reply preview for now (a known, accepted scope limit).
                                    // Not shown when it is not on disk: it would vanish on reload.
                                    if let Err(e) = self.archive_group_message(gid, &author, our_direction, m.text.as_bytes(), Some(&mid), None, None, None, m.sent_at_ms, m.author_proof.as_deref()) {
                                        error!("Could not archive group history row: {}", e);
                                        write_failed = true;
                                        return None;
                                    }
                                    self.backdate_archived(Some(gid.as_str()), "", m.message_id.as_deref(), m.timestamp);
                                    let at = if m.sent_at_ms != 0 { m.sent_at_ms } else { m.timestamp };
                                    oldest_written = Some(oldest_written.map_or(at, |o| o.min(at)));
                                    // We do not have this row, so it is archived fresh. If the responder marked it deleted, we mark it deleted
                                    // too. Otherwise a deleted message comes back on this device (e.g. a newly added secondary device, or an old
                                    // page we never had) as if it had never been deleted.
                                    self.apply_synced_message_flags(Some(gid), "", &m);
                                    // The delete above cleared the proof.
                                    if let (true, Some(mid)) = (m.is_deleted, m.message_id.as_deref()) {
                                        self.adopt_group_author_proof(gid, mid, m.author_proof.as_deref());
                                    }
                                }
                                Some(serde_json::json!({
                                    "direction": our_direction, "text": m.text, "timestamp": m.timestamp, "sent_at_ms": m.sent_at_ms,
                                    "sender_identity_id": actual_sender, "reactions": m.message_id.as_deref().map(|id| self.reactions_summary(id)).unwrap_or_default(), "message_id": m.message_id, "is_deleted": m.is_deleted, "is_edited": m.is_edited
                                }))
                            }).collect();
                            serde_json::json!({"type": "older_group_history", "group_id": gid, "messages": merged})
                        }
                        None => {
                            let merged: Vec<serde_json::Value> = messages.into_iter().filter_map(|m| {
                                let our_direction = if m.direction == "sent" { "received" } else { "sent" };
                                // See the group arm: id-less rows are skipped.
                                let mid = m.message_id.as_deref()?;
                                if !self.message_exists_in_chat(mid, None, &chat_key) {
                                    // See the same note in archive_group_message above (SyncedMessage does not carry reply info yet).
                                    // Multi-device fix: archive under the CANONICAL chat key (same as the live Text arm). If `peer_fp` is not
                                    // canonical, the rows landed in a separate chat the UI never reads.
                                    if let Err(e) = self.archive_message(&chat_key, our_direction, m.text.as_bytes(), Some(mid), None, None, None, m.sent_at_ms) {
                                        error!("Could not archive history row: {}", e);
                                        write_failed = true;
                                        return None;
                                    }
                                    self.backdate_archived(None, &chat_key, Some(mid), m.timestamp);
                                    self.mark_synced(&chat_key, Some(mid));
                                    let at = if m.sent_at_ms != 0 { m.sent_at_ms } else { m.timestamp };
                                    oldest_written = Some(oldest_written.map_or(at, |o| o.min(at)));
                                    // See the group arm above: mirror the responder's deleted flag on this first archive too.
                                    self.apply_synced_message_flags(None, &chat_key, &m);
                                }
                                Some(serde_json::json!({"direction": our_direction, "text": m.text, "timestamp": m.timestamp, "sent_at_ms": m.sent_at_ms, "reactions": m.message_id.as_deref().map(|id| self.reactions_summary(id)).unwrap_or_default(), "message_id": m.message_id, "is_deleted": m.is_deleted, "is_edited": m.is_edited, "via_sync": self.is_synced(&chat_key, m.message_id.as_deref())}))
                            }).collect();
                            serde_json::json!({"type": "older_history", "peer": chat_key, "messages": merged})
                        }
                    }
                } else {
                    // Existing behaviour (UNCHANGED): chat-open sync. The `messages` direction came from the RESPONDER's point of view (the node
                    // holding the archive). It must be flipped for our screen: their "sent" is our "received", and their "received" is our "sent".
                    // Previously synced messages were only added to this screen's in-memory list and left no permanent record, so history had to be
                    // fetched from the network again on every chat open. Now EVERY device (node or not, see send_message_content and the live Text
                    // arm above) archives its own live traffic locally. Here, `latest_archived_timestamp` writes ONLY the messages we do NOT yet have
                    // (newer ones). Otherwise each chat open (sync is always attempted now) would add the same rows again as duplicates.
                    // Multi-device fix: the threshold, the archive and the event all use the CANONICAL chat key (see the pagination arm's note).
                    let already_have_since = self.latest_archived_timestamp(&chat_key);
                    let flipped: Vec<serde_json::Value> = messages.into_iter().filter_map(|m| {
                        let our_direction = if m.direction == "sent" { "received" } else { "sent" };
                        // Before, dedup used ONLY the timestamp threshold, and archiving passed `message_id: None`. So rows from this path could never
                        // be looked up by `message_id` (a later sync could not dedup them, see `message_exists_with_id`). Now `message_id`, when
                        // present, is used both for dedup and for the permanent record, as in the pagination path (`before_timestamp.is_some()`).
                        let already_exists = m.message_id.as_deref()
                            .map(|mid| self.message_exists_in_chat(mid, None, &chat_key))
                            .unwrap_or(false);
                        // The clock test is only for rows without an id. With an
                        // id, `already_exists` decides: the test dropped exactly
                        // the gap messages (older than our newest row).
                        let is_new = !already_exists
                            && (m.message_id.is_some() || already_have_since.map(|t| m.timestamp > t as u64).unwrap_or(true));
                        if is_new {
                            if let Err(e) = self.archive_message(&chat_key, our_direction, m.text.as_bytes(), m.message_id.as_deref(), None, None, None, m.sent_at_ms) {
                                error!("Could not archive history row: {}", e);
                                write_failed = true;
                                return None;
                            }
                            self.backdate_archived(None, &chat_key, m.message_id.as_deref(), m.timestamp);
                            self.mark_synced(&chat_key, m.message_id.as_deref());
                            // We do not have this row, so it is archived fresh. If the responder marked it deleted, it is marked deleted here too.
                            self.apply_synced_message_flags(None, &chat_key, &m);
                        }
                        Some(serde_json::json!({"direction": our_direction, "text": m.text, "timestamp": m.timestamp, "sent_at_ms": m.sent_at_ms, "reactions": m.message_id.as_deref().map(|id| self.reactions_summary(id)).unwrap_or_default(), "message_id": m.message_id, "is_deleted": m.is_deleted, "is_edited": m.is_edited, "via_sync": self.is_synced(&chat_key, m.message_id.as_deref())}))
                    }).collect();
                    serde_json::json!({"type": "history_sync", "peer": chat_key, "messages": flipped})
                };
                self.apply_synced_reactions(&mut event, &reactions, group_id.as_deref(), &sender_identity_id);
                if let Some(((_, after), oldest)) = press {
                    // The user fetched rows back: from the oldest one written
                    // on they are not "cleared" any more.
                    if let Some(o) = oldest_written {
                        self.lower_history_floor(&floor_key, o);
                    }
                    // The responder cut its page: ask it for the older rest of
                    // the window (`HISTORY_FETCH_MAX_PAGES`).
                    // `o + 1`: rows sent in the same ms as `o` may be the
                    // ones cut; rows asked for twice dedup by id. Not sent
                    // (budget out, or the budget was lost in a restart): the
                    // next press asks for the rest.
                    if let (true, Some(o), false) = (more, oldest, write_failed) {
                        if o > after {
                            let sent = self.take_fetch_page(&floor_key) && {
                                let content = MessageContent::HistorySyncRequest {
                                    limit: HISTORY_SYNC_MAX_MESSAGES, before_timestamp: Some(o + 1), group_id: group_id.clone(), after_timestamp: Some(after),
                                };
                                self.send_message_content(peer_fp.clone(), &content, None).is_ok()
                            };
                            if !sent { self.reopen_fetch_cursor(&floor_key, o as u64 + 1) }
                        }
                    }
                }
                if write_failed {
                    // No Ack: the responder retries; rows already written dedup by id.
                    return Ok(event.to_string());
                }
                self.awaiting_confirmation.remove(&request_id);
                self.remove_durable_retry(&request_id);
                // 1:1: one answer per request. The entry used to stay for 7
                // days and the same peer could answer it again and again.
                // Group: the same request goes to every member, so it stays
                // open for the others (rows dedup by id; the stale sweep in
                // `send_message_content` drops it after TEXT_RETRY_GIVE_UP_MS).
                if group_id.is_none() {
                    self.forget_history_request(&request_id);
                } else {
                    self.history_answered_by.entry(request_id.clone()).or_default().insert(sender_identity_id.clone());
                }
                // The responder's `HistorySyncResponse` is in
                // `needs_delivery_confirmation`: it retries until this Ack.
                self.send_ack(&peer_fp, &message_id);
                event
            }
            MessageContent::FileOffer {
                group_id, file_id, file_name, mime_type, total_size, file_key, sha256_hex,
                preview_jpeg, duration_ms, chunk_size, chunk_hashes,
                caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin,
            } => {
                // See `sender_may_post_to_group`. Same gap as the group Text arm, and worse here: an accepted offer starts an AUTOMATIC download in
                // node mode, so an unauthorised sender got direct access to the recipient's disk and bandwidth.
                if let Some(gid) = &group_id {
                    if !self.sender_may_post_to_group(gid, &sender_identity_id) {
                        warn!(
                            "Group file offer REJECTED: sender is not a member of this group (group={}, sender={})",
                            gid, crate::log_id(&sender_identity_id)
                        );
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                    // The file id is the group message id: it must carry the
                    // sender's author tag, as a Text id does (`group_msg_tag`).
                    if !group_msg_id_bound(gid, &sender_identity_id, &file_id) {
                        warn!(
                            "Group file offer refused: id not bound to its author (group={}, sender={})",
                            gid, crate::log_id(&sender_identity_id)
                        );
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                }
                let reply_ok = group_id.as_deref().map_or(true, |g| group_reply_bound(g, reply_to_message_id.as_deref(), reply_to_sender_identity_id.as_deref()));
                let (reply_to_message_id, reply_to_preview, reply_to_sender_identity_id) =
                    if reply_ok { (reply_to_message_id, reply_to_preview, reply_to_sender_identity_id) } else { (None, None, None) };
                let ev = self.receive_file_offer(
                    &peer_fp, &sender_identity_id, group_id, &file_id, &file_name, &mime_type,
                    total_size, &file_key, &sha256_hex, &preview_jpeg, duration_ms, chunk_size, &chunk_hashes,
                    &caption, reply_to_message_id.as_deref(), reply_to_preview.as_deref(),
                    reply_to_sender_identity_id.as_deref(), sticker, sticker_origin.as_deref(),
                );
                // "noop" with no row = the row could not be written (key or DB
                // not ready): no Ack, the sender offers again. Every other
                // outcome is final (stored, duplicate, rejected).
                if ev["type"] != "noop" || self.file_row_exists(&file_id) {
                    self.send_ack(&peer_fp, &message_id);
                }
                ev
            }
            MessageContent::Ack { target_message_id } => {
                // The peer received a Text/Edit/Delete/HistorySyncRequest we sent. We can stop retrying that packet (see `awaiting_confirmation`).
                // `target_message_id` here is the acked packet's own id. For a `Text` it equals the UI bubble id, but for Edit/Delete it is a separate,
                // random packet id, not the message being edited/deleted. Look up `regen_content` (the original content) before removing, so the
                // emitted event can carry the real target id.
                // Check that the acked packet really was queued for THIS peer. Otherwise any peer could cancel a pending packet bound for another
                // peer with a forged Ack using a known or guessed `message_id` (missing session binding).
                match self.apply_incoming_ack(&peer_fp, &target_message_id) {
                    Some(ev) => ev,
                    None => return Ok(serde_json::json!({"type": "noop"}).to_string()),
                }
            }
            MessageContent::Seen { target_message_id, group_message_local_id } => {
                // See packet.rs `Seen`. This is a read receipt, not delivery (Ack). It is not acked itself (same endless-loop reasoning as Ack).
                // Seen used to be non-persistent: nothing was written here, and the JSON below was an event that existed only while the chat screen
                // was OPEN. Every "seen" arriving while the app was in the background or the screen off was lost for good (see the `message_seen`
                // table docs). The `message_id` column means the same as in the Ack path: `group_message_local_id` for group messages,
                // `target_message_id` for 1:1 (see `load_message_history`/`load_group_message_history`).
                let seen_key = group_message_local_id.clone().unwrap_or_else(|| target_message_id.clone());
                if !self.may_mark_seen(&seen_key, &sender_identity_id) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                self.apply_seen_receipt(&seen_key, &sender_identity_id, current_time_ms());
                // So the seen state reaches the server archive as well. The
                // packet names no group: the row does.
                let seen_group: Option<String> = self.db.as_ref().and_then(|c| {
                    c.query_row("SELECT group_id FROM messages WHERE message_id = ?1", params![seen_key], |r| r.get::<_, Option<String>>(0)).ok().flatten()
                });
                self.requeue_archive_row(seen_group.as_deref(), &chat_key, &seen_key);
                serde_json::json!({
                    "type": "seen", "peer": chat_key,
                    "sender_identity_id": sender_identity_id,
                    "message_id": target_message_id,
                    "group_message_local_id": group_message_local_id
                })
            }
            MessageContent::Call { call_id, action, group_id, video, media_key, stream_id, sent_at_ms, participants } => {
                self.handle_call_signal(&peer_fp, &sender_identity_id, call_id, action, group_id, video, media_key, stream_id, sent_at_ms, participants)
            }
            // Whiteboard — see `whiteboard`. Only the digest is acked (it is
            // the one reliable packet); the handlers check who may touch
            // which board.
            MessageContent::WbOps { group_id, conversation_identity_id, strokes, erased, sigs } => {
                self.wb_on_ops(&peer_fp, group_id, conversation_identity_id, strokes, erased, sigs)
            }
            MessageContent::WbDigest { group_id, conversation_identity_id, pages } => {
                self.send_ack(&peer_fp, &message_id);
                self.wb_on_digest(&peer_fp, group_id, conversation_identity_id, pages)
            }
            MessageContent::WbPageRequest { group_id, conversation_identity_id, pages } => {
                self.wb_on_page_request(&peer_fp, group_id, conversation_identity_id, pages)
            }
            MessageContent::WbPage { group_id, conversation_identity_id, page, authors, strokes, tombstones, sigs } => {
                self.wb_on_page(&peer_fp, group_id, conversation_identity_id, page, authors, strokes, tombstones, sigs)
            }
            MessageContent::TypingIndicator { is_typing, group_id } => {
                if group_id.as_ref().map_or(false, |gid| !self.sender_may_post_to_group(gid, &sender_identity_id)) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // Deliberately: not archived, no Ack sent (see
                // packet.rs note): the value goes stale within seconds, so retry/ack traffic is pointless.
                // `sender_identity_id` identifies which member is typing (needed for groups).
                match &group_id {
                    Some(gid) => serde_json::json!({
                        "type": "typing", "group_id": gid, "peer": peer_fp,
                        "sender_identity_id": sender_identity_id, "is_typing": is_typing
                    }),
                    None => serde_json::json!({
                        "type": "typing", "peer": chat_key,
                        "sender_identity_id": sender_identity_id, "is_typing": is_typing
                    }),
                }
            }
            MessageContent::ProfileUpdate { avatar_jpeg, display_name } => {
                self.send_ack(&peer_fp, &message_id);
                // See `MAX_AVATAR_BYTES`. The incoming direction used to have no limit: the other side could write any number of bytes into each
                // contact row. The Ack is still sent (so it does not retry), only the avatar is ignored. The stored one stays, and the name in the
                // same packet is still taken.
                let avatar_too_big = avatar_jpeg.as_ref().map_or(false, |a| a.len() > MAX_AVATAR_BYTES);
                if avatar_too_big {
                    warn!(
                        "ProfileUpdate avatar too large ({} bytes), ignored (sender: {})",
                        avatar_jpeg.as_ref().map_or(0, |a| a.len()), crate::log_id(&peer_fp)
                    );
                }
                // The contact's display name follows the peer's name when it changes. `None` means the packet carries no name (an older version), and the current name is kept. An empty or control-character name is ignored (see `sanitize_display_name`).
                // From one of my own devices, the packet means MY photo changed (`set_own_profile_picture`). The name travels with DeviceSync.
                if self.my_identity_id().as_deref() == Some(sender_identity_id.as_str()) {
                    if let (Some(conn), false) = (&self.db, avatar_too_big) {
                        if let Err(e) = conn.execute(
                            "UPDATE identities SET avatar_jpeg = ?1 WHERE id = ?2",
                            params![avatar_jpeg, sender_identity_id],
                        ) {
                            error!("Could not save profile photo: {}", e);
                        }
                    }
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                let new_name = display_name.as_deref().and_then(sanitize_display_name);
                let mut renamed_from: Option<String> = None;
                let mut shown_avatar = if avatar_too_big { None } else { avatar_jpeg.clone() };
                if let Some(cid) = self.identity_to_contact.get(&sender_identity_id).cloned() {
                    if let Some(c) = self.contacts.get_mut(&cid) {
                        if avatar_too_big {
                            shown_avatar = c.avatar_jpeg.clone();
                        } else {
                            c.avatar_jpeg = avatar_jpeg.clone();
                        }
                        if let Some(n) = &new_name {
                            if &c.display_name != n {
                                renamed_from = Some(c.display_name.clone());
                                c.display_name = n.clone();
                            }
                        }
                    }
                    if let Some(c) = self.contacts.get(&cid) {
                        self.persist_contact(c);
                    }
                }
                serde_json::json!({
                    "type": "profile_update", "peer": chat_key,
                    "avatar_hex": shown_avatar.as_ref().map(|a| hex::encode(a)),
                    // The UI can show that the name really changed, so both the old and new name are passed (the same name being re-announced is
                    // normal: every photo change carries this packet too).
                    "display_name": new_name,
                    "previous_display_name": renamed_from
                })
            }
            MessageContent::GroupUpdate(update) => {
                // now arrives over the ratchet-encrypted channel (see the packet.rs note). The OUTER packet (`MessagePacket`) already has a
                // hybrid-verified sender (`sender_identity_id`/`peer_fp`), and this does NOT require that sender to equal `update.signed_by`. For
                // example a non-founder member may also relay this packet pairwise (there is no relay in this code base yet). The real authority
                // check is the group's own `update.signature`/`signature_pq` verification inside `process_group_update` (also hybrid) and the
                // `signed_by == founder` rule. The outer packet signature only guarantees transport integrity.
                let group_id = update.group_id.clone();
                match self.process_group_update(&update) {
                    Ok(()) => {
                        self.send_ack(&peer_fp, &message_id);
                        self.give_founder_contact_secret(&update, &sender_identity_id, &peer_fp);
                        serde_json::json!({"type": "group_updated", "peer": peer_fp, "group_id": group_id})
                    }
                    Err(e) => {
                        error!("Could not process GroupUpdate: {}", e);
                        // Only an unknown signer can be cured by a later packet.
                        // Every other error is final: without the Ack the
                        // sender resent the same update for 7 days.
                        if e != "Unknown signer device" {
                            self.send_ack(&peer_fp, &message_id);
                        }
                        serde_json::json!({"type": "group_update_failed", "peer": peer_fp, "group_id": group_id, "error": e})
                    }
                }
            }
            MessageContent::GroupSyncRequest { group_id } => {
                // A member (or one of my own other devices) lacks devices of the group: the founder re-sends the whole state to it, at most every
                // 10 minutes per member.
                self.send_ack(&peer_fp, &message_id);
                let me = self.my_identity_id().unwrap_or_default();
                let group = self.groups.get(&group_id)
                    .filter(|g| g.founder_identity_id == me && g.is_member(&sender_identity_id))
                    .cloned();
                let key = format!("gsq:{}:{}", group_id, sender_identity_id);
                let now = current_time_ms();
                if let Some(g) = group {
                    if now.saturating_sub(self.meta_u64(&key)) >= 10 * 60 * 1000 {
                        match self.sign_group_resync(&g) {
                            Ok(update) => {
                                self.meta_put(&key, &now.to_string());
                                self.send_group_update_to_member(&group_id, &sender_identity_id, &update);
                            }
                            Err(e) => warn!("Could not answer GroupSyncRequest: {}", e),
                        }
                    }
                }
                serde_json::json!({"type": "noop"})
            }
            MessageContent::LeaveGroupRequest { group_id } => {
                // See `leave_group`. We act on this request only if we really are this group's founder (`remove_from_group` checks that itself, so a
                // device that is not the founder and gets it by mistake rejects it silently and the group state stays intact). The Ack is sent in
                // EVERY case: the leaving member's request has at least reached US, so `awaiting_confirmation` can stop retrying (even if we cannot
                // process it, e.g. we are not this group's founder, retrying would not help).
                self.send_ack(&peer_fp, &message_id);
                if let Err(e) = self.remove_from_group(&group_id, &sender_identity_id, false) {
                    error!("Could not process LeaveGroupRequest (group={}, leaving={}): {}", group_id, crate::log_id(&sender_identity_id), e);
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                serde_json::json!({"type": "member_left", "group_id": group_id, "identity_id": sender_identity_id})
            }
            MessageContent::AddressAnnounce { multiaddr } => {
                // See packet.rs `AddressAnnounce`. This is a full multiaddr (`.../p2p/<peer_id>` included), in the form `remember_device_addr` expects
                // (it also writes `.onion` to `device_onion_addr`). No Ack is sent and nothing is archived, for the same reason as `TypingIndicator`:
                // this is a snapshot of "my best current address", and the sender re-sends it periodically when Tor becomes ready or the network
                // changes (see callers of `announce_address_to_all_contacts`). Endless ack waiting has no value here.
                // Only the sender's own onion address: a contact must not point us at a stranger to dial again and again. A PeerId other than the
                // one we know for the device (or any, when none is known) counts only when the device delivered this itself over that PeerId's
                // connection (a restored device has a new one).
                let announced = multiaddr.parse::<Multiaddr>().ok()
                    .filter(is_onion_multiaddr)
                    .and_then(|m| extract_peer_id(&m));
                let own_pid = announced.filter(|pid| {
                    self.device_to_peer_id.get(&peer_fp).map_or(false, |known| known == pid) || source == Some(*pid)
                });
                if own_pid.is_some() {
                    self.remember_device_addr(&peer_fp, &multiaddr);
                } else {
                    warn!("AddressAnnounce ignored (not onion or a different PeerId): {}", crate::log_id(&peer_fp));
                }
                serde_json::json!({"type": "address_announce", "peer": peer_fp})
            }
            // Multi-device: the primary accepted this (secondary) device into its identity. `peer_fp` = sender = primary.
            MessageContent::DeviceLinkGrant { identity_id, device_add, sync, nonce } => {
                // Acked once adopted: acked first, a failure here lost the
                // grant and the link never completed.
                match self.adopt_device_link(&peer_fp, &identity_id, &device_add, &sync, &nonce) {
                    Ok(linked) => {
                        self.send_ack(&peer_fp, &message_id);
                        if linked { serde_json::json!({"type": "device_linked", "identity_id": identity_id}) } else { serde_json::json!({"type": "noop"}) }
                    }
                    Err(e) => {
                        error!("DeviceLinkGrant not accepted: {}", e);
                        // Past the link window no retry can be adopted (a new
                        // QR has a new nonce): acked, or it came for 7 days.
                        if current_time_ms() > self.link_request_open_until {
                            self.send_ack(&peer_fp, &message_id);
                        }
                        serde_json::json!({"type": "noop"})
                    }
                }
            }
            // Multi-device: a new device was added to an identity. Verify the signature with that identity's known active device.
            MessageContent::DeviceAddNotice { device_add, device } => {
                self.send_ack(&peer_fp, &message_id);
                match self.apply_device_add_notice(&device_add, &device, &sender_identity_id) {
                    Ok(()) => serde_json::json!({"type": "device_change", "identity_id": device_add.identity_id}),
                    Err(e) => { error!("DeviceAddNotice rejected: {}", e); serde_json::json!({"type": "noop"}) }
                }
            }
            // Multi-device: signed device revocation.
            MessageContent::DeviceRevokeNotice(revoke) => {
                // The Ack is sent FIRST: after a self-revoke wipes the ratchet we can no longer produce an Ack, but the device starting the revoke
                // should still learn that this device got the notice.
                self.send_ack(&peer_fp, &message_id);
                match self.apply_device_revoke_notice(&revoke, &peer_fp) {
                    // This device's OWN revocation: local state is fully wiped. The UI must, on receiving this, also delete the Keystore/vault secret
                    // and return to onboarding (see `wipe_all_local_state`). `self_revoked` is already queued by `apply_device_revoke_notice`.
                    Ok(true) => serde_json::json!({"type": "noop"}),
                    Ok(false) => serde_json::json!({"type": "device_change", "identity_id": revoke.identity_id}),
                    Err(e) => { error!("DeviceRevokeNotice rejected: {}", e); serde_json::json!({"type": "noop"}) }
                }
            }
            // Multi-device: delta sync from a sibling device. Accept ONLY if the sender is one of my own identity's devices.
            MessageContent::DeviceSync(sync) => {
                self.send_ack(&peer_fp, &message_id);
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if from_sibling {
                    // If the sibling device gave us the root archive key (ARK), adopt it. Without it the history on the server cannot be DECRYPTED on
                    // this device. If we already have an ARK, do NOT touch it: two devices may have been set up at the same time and generated
                    // different keys, and silently overwriting it would make the old archive unreadable. The primary's key replaces ours (it rotates
                    // the key when it revokes a device); see `adopt_archive_key`.
                    if let Some(ark) = &sync.archive_root_key {
                        let had_key = self.archive_root_key.is_some();
                        if self.adopt_archive_key(ark, my_id_now.as_deref() == Some(peer_fp.as_str())) {
                            info!("Root archive key received from sibling device");
                            // Rows written before the first key came were never
                            // queued. Not after a rotation: the primary uploads
                            // the history again, this device does not.
                            if !had_key && self.servers.iter().any(|s| s.store_history) {
                                self.backfill_server_archive();
                            }
                        }
                    }
                    let learned = self.import_sync_payload(&sync);
                    // Introduce ourselves to newly learned contacts (so they know this device too), handing them our keys reliably.
                    let own_dev = self.own_synced_device();
                    let own_da = self.own_device_add.clone();
                    for id in &learned {
                        for fp in self.active_devices_for_identity(id) {
                            let _ = self.send_identity_exchange(&fp);
                            if let (Some(da), Some(dev)) = (own_da.clone(), own_dev.clone()) {
                                let _ = self.send_message_content(fp, &MessageContent::DeviceAddNotice { device_add: da, device: dev }, None);
                            }
                        }
                    }
                    serde_json::json!({"type": "sync"})
                } else {
                    serde_json::json!({"type": "noop"})
                }
            }
            // Multi-device: "read" sync from a sibling.
            MessageContent::ReadStateSync { conversation_identity_id, group_id, read_at_ms } => {
                // Ack UNCONDITIONALLY (see the DeviceSync arm, same pattern): this is now reliably delivered, and there is no point endlessly
                // re-checking a rejected sync. A small hint message: if it is lost, the chat just shows as unread on the other device, which is
                // better than endless traffic.
                self.send_ack(&peer_fp, &message_id);
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if from_sibling {
                    // Translate to the local chat key: group -> "group:<id>", 1:1 -> the contact's canonical device (the chat key on this device).
                    // Kotlin applies this to ReadStatePrefs.
                    let conversation = if let Some(gid) = group_id {
                        format!("group:{}", gid)
                    } else if let Some(id) = conversation_identity_id {
                        self.canonical_device_for_identity(&id).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    if conversation.is_empty() {
                        serde_json::json!({"type": "noop"})
                    } else {
                        serde_json::json!({"type": "read_state_sync", "conversation": conversation, "read_at": read_at_ms})
                    }
                } else {
                    // A read watermark from the other side is a bulk seen receipt, with the sender as the reader. See `apply_incoming_read_watermark`.
                    let viewer = self.known_remote_devices.get(&peer_fp).map(|d| d.identity_id.clone());
                    match viewer {
                        Some(viewer_id) => {
                            let affected = self.apply_incoming_read_watermark(
                                &peer_fp, group_id.as_deref(), &viewer_id, read_at_ms,
                            );
                            if affected.is_empty() {
                                serde_json::json!({"type": "noop"})
                            } else {
                                // Seen state reaches the server archive once per
                                // batch, on its newest message (oldest first).
                                if let Some(newest) = affected.last() {
                                    self.requeue_archive_row(group_id.as_deref(), &chat_key, newest);
                                }
                                serde_json::json!({
                                    "type": "seen_bulk",
                                    "peer": peer_fp,
                                    // For 1:1 use `null` (not an empty string): the ChatActivity listener treats an event with `!isNull("group_id")`
                                    // as a group event and drops it.
                                    "group_id": group_id.clone(),
                                    "viewer_identity_id": viewer_id,
                                    "up_to_ms": read_at_ms,
                                    "message_ids": affected,
                                })
                            }
                        }
                        None => serde_json::json!({"type": "noop"}),
                    }
                }
            }
            // Multi-device: a message/edit/delete sent from my other device, shown here too as "sent".
            MessageContent::SiblingEcho { conversation_identity_id, group_id, body } => {
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if !from_sibling {
                    serde_json::json!({"type": "noop"})
                } else {
                    let own_id = my_id_now.clone().unwrap_or_default();
                    // Local chat key for 1:1 (the canonical device on this device).
                    let chat_key = conversation_identity_id.as_ref()
                        .and_then(|id| self.canonical_device_for_identity(id));
                    // A contact deleted on this device only: there is nowhere
                    // to store the echo, ever. Unacked, the sibling sent each
                    // one again for 7 days.
                    if group_id.is_none() && chat_key.is_none()
                        && conversation_identity_id.as_deref().map_or(false, |id| self.contact_removed_locally(id))
                    {
                        self.send_ack(&peer_fp, &message_id);
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                    // Acked after the body is handled, and not at all when it
                    // could not be stored (contact not synced, archive error):
                    // the sibling then sends again.
                    let mut ack = true;
                    let ev = match body {
                        SiblingEchoBody::Text { message_id: mid, text, sent_at_ms, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id } => {
                            // Double archive fix, same dedup as the 1:1 and group Text arms: a sibling's `regen_content` refresh or restart resend can
                            // bring the same echo a second time. The Ack is sent below (`ack`).
                            // In this chat: with the global check, a member who saw the id could send any text under it first, and the echo was dropped as a duplicate.
                            let dup = match (&group_id, &chat_key) {
                                (Some(gid), _) => self.message_exists_in_chat(&mid, Some(gid.as_str()), ""),
                                (None, Some(ck)) => self.message_exists_in_chat(&mid, None, ck),
                                _ => false,
                            };
                            // A group left on this device gets no new rows.
                            if dup || group_id.as_ref().map_or(false, |gid| !self.groups.contains_key(gid)) {
                                serde_json::json!({"type": "noop"})
                            } else if let Some(gid) = &group_id {
                                ack = self.archive_group_message(gid, &own_id, "sent", text.as_bytes(), Some(&mid),
                                    reply_to_message_id.as_deref(), reply_to_preview.as_deref(), reply_to_sender_identity_id.as_deref(), sent_at_ms, None).is_ok();
                                serde_json::json!({
                                    "type": "sibling_group_message", "group_id": gid, "message_id": mid,
                                    "text": text, "sent_at_ms": sent_at_ms, "sender_identity_id": own_id,
                                    "reply_to_message_id": reply_to_message_id, "reply_to_preview": reply_to_preview,
                                    "reply_to_sender_identity_id": reply_to_sender_identity_id
                                })
                            } else if let Some(ck) = &chat_key {
                                ack = self.archive_message(ck, "sent", text.as_bytes(), Some(&mid),
                                    Some(MessageSendStatus::Sent.as_str()), reply_to_message_id.as_deref(), reply_to_preview.as_deref(), sent_at_ms).is_ok();
                                serde_json::json!({
                                    "type": "sibling_message", "peer": ck, "message_id": mid, "text": text,
                                    "sent_at_ms": sent_at_ms, "reply_to_message_id": reply_to_message_id,
                                    "reply_to_preview": reply_to_preview
                                })
                            } else {
                                ack = false;
                                serde_json::json!({"type": "noop"})
                            }
                        }
                        SiblingEchoBody::Edit { target_message_id, new_text, edited_at_ms } => {
                            if !self.edit_or_delete_target_exists(&target_message_id) {
                                // Stored and acked; applied when the message comes.
                                ack = self.remember_sibling_op(&target_message_id, Some(&new_text), edited_at_ms);
                                serde_json::json!({"type": "noop"})
                            } else if !self.own_sent_target(group_id.as_deref(), chat_key.as_deref().unwrap_or(""), &target_message_id) {
                                warn!("Sibling Edit ignored: target is not a message we sent ({})", target_message_id);
                                serde_json::json!({"type": "noop"})
                            } else if let Some(gid) = &group_id {
                                self.apply_edit_to_archive(Some(gid), "", &target_message_id, &new_text, edited_at_ms);
                                serde_json::json!({"type": "group_edit", "group_id": gid, "message_id": target_message_id, "text": new_text})
                            } else if let Some(ck) = &chat_key {
                                self.apply_edit_to_archive(None, ck, &target_message_id, &new_text, edited_at_ms);
                                serde_json::json!({"type": "edit", "peer": ck, "message_id": target_message_id, "text": new_text})
                            } else {
                                serde_json::json!({"type": "noop"})
                            }
                        }
                        SiblingEchoBody::Reaction { target_message_id, emoji, reacted_at_ms } => {
                            // The echo is MY reaction, so the reacting identity is `own_id` (my own), not the sibling device's id (both are the same identity).
                            // Same checks as the contact arm; a 1:1 row's chat is the conversation identity, not mine.
                            let chat_identity = if group_id.is_some() { own_id.as_str() } else { conversation_identity_id.as_deref().unwrap_or("") };
                            if emoji.len() > 64 || !self.reaction_fits_chat(&target_message_id, group_id.as_deref(), chat_identity) {
                                warn!("Sibling reaction ignored: target not in this chat or emoji too long");
                                serde_json::json!({"type": "noop"})
                            } else if !self.apply_reaction(&target_message_id, &own_id, &emoji, reacted_at_ms) {
                                ack = false; // write failed: the sibling sends it again
                                serde_json::json!({"type": "noop"})
                            } else if let Some(gid) = &group_id {
                                let summary = self.reactions_summary(&target_message_id);
                                serde_json::json!({"type": "reaction", "group_id": gid, "message_id": target_message_id, "reactions": summary})
                            } else if let Some(ck) = &chat_key {
                                let summary = self.reactions_summary(&target_message_id);
                                serde_json::json!({"type": "reaction", "peer": ck, "message_id": target_message_id, "reactions": summary})
                            } else {
                                serde_json::json!({"type": "noop"})
                            }
                        }
                        SiblingEchoBody::File { offer } => match *offer {
                            MessageContent::FileOffer {
                                file_id, file_name, mime_type, total_size, file_key, sha256_hex,
                                preview_jpeg, duration_ms, chunk_size, chunk_hashes,
                                caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, ..
                            } => {
                                // The same echo a second time (regen/restart): if the row exists, leave it alone. `receive_file_offer`'s INSERT OR REPLACE
                                // would reset a completed download.
                                let exists = self.db.as_ref().map_or(false, |c| {
                                    c.query_row("SELECT 1 FROM files WHERE file_id = ?1", params![file_id], |_| Ok(())).is_ok()
                                });
                                if exists || self.take_pending_sibling_delete(&file_id) {
                                    serde_json::json!({"type": "noop"})
                                } else if group_id.is_none() && chat_key.is_none() {
                                    ack = false;
                                    serde_json::json!({"type": "noop"})
                                } else {
                                    let mut ev = self.receive_file_offer(
                                        &peer_fp, &own_id, group_id.clone(), &file_id, &file_name, &mime_type,
                                        total_size, &file_key, &sha256_hex, &preview_jpeg, duration_ms, chunk_size, &chunk_hashes,
                                        &caption, reply_to_message_id.as_deref(), reply_to_preview.as_deref(),
                                        reply_to_sender_identity_id.as_deref(), sticker, sticker_origin.as_deref(),
                                    );
                                    if ev["type"] == "file_offer" {
                                        // The row is my outgoing offer. In a group the source sibling stays as is. In 1:1 the column is the chat key (so the
                                        // file is listed in the right chat), and on re-download `download_file` adds the siblings as candidates.
                                        let peer_col = if group_id.is_some() { peer_fp.clone() } else { chat_key.clone().unwrap_or_default() };
                                        if let Some(conn) = &self.db {
                                            let _ = conn.execute(
                                                "UPDATE files SET direction = 'sent', peer_device_fingerprint = ?1 WHERE file_id = ?2",
                                                params![peer_col, file_id],
                                            );
                                        }
                                        ev["type"] = "sibling_file".into();
                                        ev["peer"] = peer_col.into();
                                    } else if ev["type"] == "noop" {
                                        ack = false; // row not written, see `receive_file_offer`
                                    }
                                    ev
                                }
                            }
                            _ => serde_json::json!({"type": "noop"}),
                        },
                        SiblingEchoBody::Sticker { jxl, origin, id, part, parts } => 'sticker: {
                            // A part of a big sticker: kept until all are here.
                            let jxl = if parts > 1 {
                                match self.add_sticker_part(&id, part, parts, jxl) {
                                    Ok(Some(whole)) => whole,
                                    Ok(None) => break 'sticker serde_json::json!({"type": "noop"}),
                                    Err(e) => {
                                        warn!("Sibling sticker chunk dropped: {}", e);
                                        break 'sticker serde_json::json!({"type": "noop"});
                                    }
                                }
                            } else {
                                jxl
                            };
                            // Not a sticker at all: final (acked). Anything else
                            // (keys not loaded, disk, DB): sent again.
                            let mut not_a_sticker = false;
                            let stored = self.attachments_dir().and_then(|dir| {
                                let tmp = dir.join("plain_cache").join(format!(".sticker-{}.jxl", uuid::Uuid::new_v4()));
                                let r = std::fs::write(&tmp, &jxl).map_err(|e| e.to_string()).and_then(|()| {
                                    let r = self.store_sticker(&tmp, false, origin.as_deref());
                                    not_a_sticker = r.is_err() && attachments::sticker_check(&tmp).is_err();
                                    r
                                });
                                let _ = std::fs::remove_file(&tmp);
                                r
                            });
                            match stored {
                                Ok(id) => serde_json::json!({"type": "stickers_changed", "added": id}),
                                Err(e) => {
                                    warn!("Could not store sibling sticker: {}", e);
                                    ack = not_a_sticker;
                                    serde_json::json!({"type": "noop"})
                                }
                            }
                        }
                        SiblingEchoBody::StickersRequest { have } => {
                            // Only the root device answers (a desktop's request
                            // reaches every sibling). Off the core lock: one
                            // decrypt + send per sticker, the lock taken each time.
                            // One sending thread per sibling: a burst of requests must not start one each.
                            static SENDING_TO: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
                            let busy = SENDING_TO.lock().map_or(true, |mut s| {
                                let busy = s.contains(&peer_fp);
                                if !busy {
                                    s.push(peer_fp.clone());
                                }
                                busy
                            });
                            if busy {
                                info!("Sticker request from sibling {}: already sending", crate::log_id(&peer_fp));
                            } else if self.own_device_add.is_none() {
                                let have: std::collections::HashSet<String> = have.into_iter().collect();
                                let ids: Vec<String> = self.sticker_ids().into_iter().filter(|id| !have.contains(id)).collect();
                                info!("Sticker request from sibling {}: sending {}", crate::log_id(&peer_fp), ids.len());
                                let to = peer_fp.clone();
                                std::thread::spawn(move || {
                                    let _guard = crate::RUNTIME.enter();
                                    for id in ids {
                                        crate::core_lock().send_sticker_to_sibling(&to, &id);
                                    }
                                    if let Ok(mut s) = SENDING_TO.lock() {
                                        s.retain(|f| f != &to);
                                    }
                                });
                            } else if let Ok(mut s) = SENDING_TO.lock() {
                                s.retain(|f| f != &peer_fp);
                            }
                            serde_json::json!({"type": "noop"})
                        }
                        SiblingEchoBody::StickerRemoved { id } => match self.delete_sticker(&id, false) {
                            Ok(()) => serde_json::json!({"type": "stickers_changed", "removed": id}),
                            Err(e) => {
                                warn!("Could not delete sibling sticker: {}", e);
                                // A bad id is final; a DB error is sent again.
                                ack = self.sticker_enc_path(&id).is_err();
                                serde_json::json!({"type": "noop"})
                            }
                        },
                        SiblingEchoBody::ContactRemoved { identity_id } => {
                            match self.identity_to_contact.get(&identity_id).cloned() {
                                Some(cid) => match self.delete_contact(&cid, false) {
                                    Ok(()) => serde_json::json!({"type": "device_change", "identity_id": identity_id}),
                                    Err(e) => {
                                        warn!("Could not delete sibling contact: {}", e);
                                        ack = false; // DB error: the sibling sends again.
                                        serde_json::json!({"type": "noop"})
                                    }
                                },
                                None => serde_json::json!({"type": "noop"}),
                            }
                        }
                        SiblingEchoBody::GroupLeft => match &group_id {
                            Some(gid) if self.groups.contains_key(gid) => {
                                self.remove_group_locally(gid);
                                serde_json::json!({"type": "group_updated", "group_id": gid})
                            }
                            _ => serde_json::json!({"type": "noop"}),
                        },
                        SiblingEchoBody::Delete { target_message_id } => {
                            // Deleting a message on the primary also removes the attached file from disk (see `delete_message`/`delete_group_message`,
                            // the same call). But this sibling-echo arm used to update only the archive row, so on the secondary device the file stayed
                            // on disk for good (a leak, never cleaned up).
                            if !self.edit_or_delete_target_exists(&target_message_id) {
                                ack = self.remember_sibling_op(&target_message_id, None, 0);
                                serde_json::json!({"type": "noop"})
                            } else if !self.own_sent_target(group_id.as_deref(), chat_key.as_deref().unwrap_or(""), &target_message_id) {
                                warn!("Sibling Delete ignored: target is not a message we sent ({})", target_message_id);
                                serde_json::json!({"type": "noop"})
                            } else {
                                self.purge_attachment_if_exists(&target_message_id);
                                if let Some(gid) = &group_id {
                                    self.apply_delete_to_archive(Some(gid), "", &target_message_id);
                                    self.sign_own_group_tombstone(gid, &target_message_id);
                                    serde_json::json!({"type": "group_delete", "group_id": gid, "message_id": target_message_id})
                                } else if let Some(ck) = &chat_key {
                                    self.apply_delete_to_archive(None, ck, &target_message_id);
                                    serde_json::json!({"type": "delete", "peer": ck, "message_id": target_message_id})
                                } else {
                                    serde_json::json!({"type": "noop"})
                                }
                            }
                        }
                    };
                    if ack {
                        self.send_ack(&peer_fp, &message_id);
                    }
                    ev
                }
            }
            // Multi-device: history back-fill request from a sibling.
            MessageContent::FirstContactSecret { secret, group_id } => {
                self.send_ack(&peer_fp, &message_id);
                // Kept only by the founder of that group: only it forwards the secret.
                let me = self.my_identity_id().unwrap_or_default();
                let founder_of = self.groups.get(&group_id)
                    .map_or(false, |g| g.founder_identity_id == me && g.is_member(&sender_identity_id));
                if secret.len() == 16 && founder_of {
                    self.meta_put(&format!("gf:{}:{}", peer_fp, group_id), &hex::encode(&secret));
                }
                serde_json::json!({"type": "noop"})
            }
            MessageContent::AccountDeleted { .. } => {
                self.send_ack(&peer_fp, &message_id);
                let my_id_now = self.my_identity_id();
                let from_sibling = my_id_now.as_deref() == Some(sender_identity_id.as_str());
                // Only the identity's first device deletes the account (see
                // `verify_device_auth`): a stolen secondary wiped the others,
                // and made every contact drop the identity.
                if peer_fp != sender_identity_id {
                    warn!("AccountDeleted did not come from primary device, ignored (peer={})", crate::log_id(&peer_fp));
                    serde_json::json!({"type": "noop"})
                } else if from_sibling {
                    // The account was deleted from one of my other devices: this device is deleted too (the UI cleans up files and restarts with `self_revoked`).
                    warn!("Account deleted from sibling device (peer={}) — wiping local state", crate::log_id(&peer_fp));
                    self.wipe_all_local_state();
                    serde_json::json!({"type": "self_revoked"})
                } else {
                    let display_name = self.identity_to_contact.get(&sender_identity_id)
                        .and_then(|cid| self.contacts.get(cid))
                        .map(|c| c.display_name.clone())
                        .unwrap_or_default();
                    let group_ids = self.apply_account_deleted(&sender_identity_id);
                    info!("Contact deleted their account: {} ({} groups)", crate::log_id(&sender_identity_id), group_ids.len());
                    serde_json::json!({
                        "type": "account_deleted", "peer": chat_key,
                        "identity_id": sender_identity_id,
                        "display_name": display_name,
                        "group_ids": group_ids,
                    })
                }
            }
            MessageContent::SiblingHistoryRequest { per_conversation_limit, conversation_identity_id, group_id, before_timestamp, since_timestamp, after_timestamp } => {
                // Ack widened (network robustness fix): this packet was never acked before. The only guarantee was the periodic re-trigger with a
                // 5-minute debounce (see `request_sibling_backfill`), so a lost request could go unnoticed for up to 5 minutes. Same reasoning as
                // `LeaveGroupRequest`: the Ack is sent in EVERY case, the request has at least reached US, and the sender's `awaiting_confirmation`
                // retry can stop (even if no reply can be produced or sent, e.g. the sender is no longer a real sibling).
                self.send_ack(&peer_fp, &message_id);
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if from_sibling {
                    // A "Fetch older history" window: one window, at most 30 days.
                    let window = before_timestamp.zip(after_timestamp)
                        .map(|(b, a)| (b, a.max(b.saturating_sub(HISTORY_FETCH_WINDOW_MS as i64))));
                    let limit = per_conversation_limit.min(if window.is_some() { HISTORY_SYNC_MAX_MESSAGES } else { SIBLING_BACKFILL_PER_CONVERSATION });
                    let (entries, more) = self.build_sibling_history_response(limit, conversation_identity_id.as_deref(), group_id.as_deref(), before_timestamp, since_timestamp, window);
                    // The echo is the request's own window, not the clamped one.
                    let resp = MessageContent::SiblingHistoryResponse { entries, window: before_timestamp.zip(after_timestamp), more };
                    if let Err(e) = self.send_message_content(peer_fp.clone(), &resp, None) {
                        error!("SiblingHistoryResponse could not be sent: {}", e);
                    }
                }
                serde_json::json!({"type": "noop"})
            }
            // Multi-device: history sent by a sibling; archive it.
            MessageContent::SiblingHistoryResponse { entries, window, more } => {
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if !from_sibling {
                    serde_json::json!({"type": "noop"})
                } else {
                    // Sibling backfill has no paging: `request_older_sibling_history` sends a request narrowed to ONE chat, so the reply (if any) also
                    // contains entries from that ONE chat. Detect that and, if a chat is open on screen, shape the reply the SAME way as
                    // `older_history`/`older_group_history` so it merges right away (Kotlin/Linux already know these two event types, so no new
                    // consumer is needed). The old general "history_backfilled" notice stays for the automatic/broad `request_sibling_backfill`
                    // reply (several or mixed chats).
                    let single_group: Option<String> = {
                        let gids: std::collections::HashSet<&str> = entries.iter().filter_map(|e| e.group_id.as_deref()).collect();
                        if gids.len() == 1 && entries.iter().all(|e| e.group_id.is_some()) {
                            gids.into_iter().next().map(|s| s.to_string())
                        } else {
                            None
                        }
                    };
                    let single_conversation: Option<String> = if single_group.is_none() {
                        let ids: std::collections::HashSet<&str> = entries.iter().filter_map(|e| e.conversation_identity_id.as_deref()).collect();
                        if ids.len() == 1 && entries.iter().all(|e| e.conversation_identity_id.is_some()) {
                            ids.into_iter().next().map(|s| s.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    // NOTE: `SiblingHistoryEntry` does not carry a separate local receive time (unlike `ArchivedMessage.timestamp`). `sent_at_ms` is
                    // already the "effective" value that `load_message_history` produces with `COALESCE(NULLIF(sent_at_ms,0), timestamp)`, so it can
                    // safely be used for the `timestamp` field too.
                    let (merged, press_chat) = self.apply_sibling_reply(&peer_fp, window, more, entries);
                    // Decided by the request, not by the shape of the answer
                    //no window and no press it answers, while
                    // a backfill request is open, is the unscoped backfill,
                    // also when all its rows belong to one chat.
                    let backfill = window.is_none() && press_chat.is_none()
                        && self.sibling_backfill_since.get(&peer_fp).map_or(false, |s| s.0 > 0);
                    // A press answer is about its chat, empty or not.
                    let (single_group, single_conversation) = match press_chat {
                        Some(c) if self.groups.contains_key(&c) => (Some(c), None),
                        Some(c) => (None, Some(c)),
                        None if backfill => (None, None),
                        None => (single_group, single_conversation),
                    };
                    // an answer to the unscoped backfill (an empty one
                    // too) moves this sibling's watermark.
                    if backfill {
                        if let Some(state) = self.sibling_backfill_since.get_mut(&peer_fp) {
                            if state.0 > 0 {
                                *state = (0, state.0);
                            }
                        }
                    }
                    if let Some(gid) = single_group {
                        serde_json::json!({"type": "older_group_history", "group_id": gid, "messages": merged})
                    } else if let Some(id) = single_conversation {
                        match self.canonical_device_for_identity(&id) {
                            Some(ck) => serde_json::json!({"type": "older_history", "peer": ck, "messages": merged}),
                            None => serde_json::json!({"type": "history_backfilled"}),
                        }
                    } else {
                        serde_json::json!({"type": "history_backfilled"})
                    }
                }
            }
        };
        Ok(event.to_string())
    }
}
