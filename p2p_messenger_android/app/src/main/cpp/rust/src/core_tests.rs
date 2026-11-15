//! Crate-level tests, many of them scanning the core source (see `CORE_SRC`).

use super::*;
/// Checks in the source text that `wipe_all_local_state` skips NO field.
/// Why this test exists: the function was once left incomplete (server tables, then key material and the contact pairing maps). Adding a new field and forgetting to add it to the wipe is a SILENT bug: a remotely revoked device keeps its data, and
/// nobody notices. This test requires that every field of `P2PCore` appears either in the wipe body, or in the justified exemption list below.
#[cfg(test)]
mod wipe_coverage_tests {
    /// Fields that carry NO identity or contact information, so they need no deleting.
    /// Each one is either plain configuration, a timer, or runtime state that is correct by construction after a rebuild.
    const EXEMPT: &[&str] = &[
        "db",  // connection itself. Tables are emptied with SQL.
        "swarm",  // network stack. Carries no identity.
        "tor", "tor_enabled", "tor_was_ready",
        "own_listen_addrs",  // our OWN addresses
        "node_mode_enabled", "history_storage_limit_bytes", "power_save",
        "metered", "radio_window_at", "radio_window_open", "tor_dormant", "tor_wake_at", "resync_since", // network state / timers
        "app_files_dir",
        "known_relay_peers",  // public relay addresses
        "relay_listeners",  // swarm listener ids. Rebuilt together with the network.
        "fast_reconnect_until",  // timers
        "peer_conns",  // connection ids. Rebuilt together with the network.
        "conn_rank",                     // same, per connection id
        "unknown_inbound",               // same, per connection id
        "server_rpc_timeouts",           // connection health counter
        "advertised_onion",              // our own address; rebuilt with the network
        "ratchets_loaded",               // load gate; the key stays loaded across a wipe
        "server_sweep_at", "blob_rtt_sum", "blob_rtt_count",
        "last_reconnect_sweep_at", "last_pending_flush_at", "last_sibling_backfill_at",
        "last_network_change_at", "network_change_pending", "last_unconfirmed_retry_at",
        "last_sibling_roster_sync_at", "last_group_sync_sweep_at", "durable_reload_at",
        "last_storage_sweep_at",
        // Only "when did we last prune": carries no identity. The map itself (`recent_inbound_digests`) is cleared in `wipe_all_local_state`.
        "last_inbound_dedup_prune_at",
        "stream_control",                // swarm handle, rebuilt with the network
        "call_stats_logged_at",          // log timer
        "call_signal_sending",           // transient send flag
        "regen_skip_id",                 // transient, set during one send
    ];

    #[test]
    fn every_field_is_wiped_or_explicitly_exempt() {
        let src = crate::CORE_SRC;
        // Walk the struct body LINE BY LINE. A `}` inside a doc comment must not end the scan early,
        // so only a line that is a lone `}` counts as the closing brace.
        let mut fields = Vec::new();
        let mut inside = false;
        for line in src.lines() {
            if !inside {
                if line.trim_start().starts_with("struct P2PCore {") {
                    inside = true;
                }
                continue;
            }
            if line == "}" {
                break;
            }
            // A field with a trailing comment still counts.
            let t = line.trim_start().split("//").next().unwrap_or("").trim_end();
            if t.is_empty() || !t.ends_with(',') {
                continue;
            }
            if let Some((name, _)) = t.split_once(':') {
                let name = name.trim();
                if !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
                {
                    fields.push(name.to_string());
                }
            }
        }
        assert!(fields.len() > 50, "field parsing broken: {} fields found", fields.len());

        // Two traps at once:
        //   1) Doc comments in the file mention this name, so a plain search would first hit one of them.
        //   2) This test's own source is inside the file read by `include_str!`. If the needle were written
        //      out plainly here, `find` would hit this test's own string first. So the needle is built from parts.
        let needle = format!("    pub(crate) fn wipe_all_{}(&mut self)", "local_state");
        let wstart = src.find(&needle).expect("wipe tanimi bulunamadi");
        let wbody = &src[wstart..];
        let wend = wbody.find("\n    }\n").expect("wipe sonu bulunamadi");
        let wbody = &wbody[..wend];

        let mut missing = Vec::new();
        for f in &fields {
            if EXEMPT.contains(&f.as_str()) {
                continue;
            }
            // The field must appear as `self.<field>`. The `self.` prefix is required so that it does not match
            // SQL table names. (This was hit once: `device_onion_addr` was thought wiped because it occurs inside
            // the SQL name `device_onion_addrs`.)
            if !wbody.contains(&format!("self.{}", f)) {
                missing.push(f.clone());
            }
        }
        assert!(
            missing.is_empty(),
            "wipe_all_local_state su alanlari atliyor: {:?}\n             Ya temizleyin ya da gerekcesiyle EXEMPT listesine ekleyin.",
            missing
        );
    }

    /// The same check for SQL tables: `message_reactions` and `message_seen`
    /// (other people's identity ids) were created and never added to the wipe.
    #[test]
    fn every_table_is_wiped() {
        let lib = crate::CORE_SRC;
        let needle = format!("    pub(crate) fn wipe_all_{}(&mut self)", "local_state");
        let wbody = &lib[lib.find(&needle).expect("wipe tanimi bulunamadi")..];
        let wbody = &wbody[..wbody.find("\n    }\n").expect("wipe sonu bulunamadi")];
        // Built from parts: see the trap described in the test above.
        let marker = ["CREATE TABLE IF NOT", " EXISTS "].concat();
        let mut missing = Vec::new();
        for src in [
            lib,
            include_str!("server_client/mod.rs"),
            include_str!("server_client/connection.rs"),
            include_str!("server_client/mailbox.rs"),
            include_str!("server_client/archive.rs"),
            include_str!("server_client/blobs.rs"),
            include_str!("whiteboard.rs"),
        ] {
            for part in src.split(marker.as_str()).skip(1) {
                let table: String = part.chars().take_while(|c| c.is_ascii_lowercase() || *c == '_').collect();
                if !table.is_empty() && !wbody.contains(&format!("\"{}\"", table)) {
                    missing.push(table);
                }
            }
        }
        assert!(missing.is_empty(), "wipe_all_local_state su tablolari atliyor: {:?}", missing);
    }
}

#[cfg(test)]
mod review_oct2026_tests {
    use super::*;

    #[test]
    fn display_name_drops_bidi_and_trims_before_the_length_cut() {
        assert_eq!(sanitize_display_name("ali\u{202E}ce\u{200B}").as_deref(), Some("alice"));
        assert_eq!(sanitize_display_name(" \u{2066}\n "), None);
        let padded = format!("   {}", "x".repeat(60));
        assert_eq!(sanitize_display_name(&padded).map(|n| n.chars().count()), Some(MAX_DISPLAY_NAME_CHARS));
    }

    #[test]
    fn a_received_time_is_never_in_the_future() {
        let mut content = MessageContent::Text {
            text: "t".into(), group_id: None, group_message_local_id: None, sent_at_ms: 5_000,
            reply_to_message_id: None, reply_to_preview: None, reply_to_sender_identity_id: None, author_proof: None, mentions: Vec::new(),
        };
        clamp_received_times(&mut content, 1_000);
        assert!(matches!(content, MessageContent::Text { sent_at_ms: 1_000, .. }));
        clamp_received_times(&mut content, 9_000);
        assert!(matches!(content, MessageContent::Text { sent_at_ms: 1_000, .. }), "an older time stays");
    }

    #[test]
    fn deleting_a_queued_message_withdraws_its_unsent_copies() {
        let mut core = P2PCore::new();
        let packet = MessagePacket {
            header: crate::packet::SignedHeader::new(MessagePacketHeader {
                sender_identity_id: String::new(), sender_device_fingerprint: String::new(), message_id: String::new(),
                ratchet_pubkey: Vec::new(), message_number: 0, prev_chain_length: 0, rotation_kyber_ciphertext: None, sent_at_ms: 0,
            }).unwrap(),
            ciphertext: Vec::new(), signature_classical: Vec::new(), signature_pq: Vec::new(),
        };
        let text = |conv: &str| MessageContent::Text {
            text: "t".into(), group_id: None, group_message_local_id: Some(conv.into()), sent_at_ms: 0,
            reply_to_message_id: None, reply_to_preview: None, reply_to_sender_identity_id: None, author_proof: None, mentions: Vec::new(),
        };
        let echo = |mid: &str| MessageContent::SiblingEcho {
            conversation_identity_id: None, group_id: None,
            body: SiblingEchoBody::Text { message_id: mid.into(), text: "t".into(), sent_at_ms: 0, reply_to_message_id: None, reply_to_preview: None, reply_to_sender_identity_id: None },
        };
        for (id, content) in [("conv", text("conv")), ("copy", text("conv")), ("echo", echo("conv")), ("other", text("keep"))] {
            core.awaiting_confirmation.insert(id.into(), PendingConfirmation {
                suspect_probed: false, direct_delivered: false, chain_stamp: String::new(), peer_device_fingerprint: String::new(),
                envelope: NetworkEnvelope::Message(packet.clone()), next_retry_at: 0, retry_interval_ms: 0,
                first_sent_at: 0, original_sent_at: 0, last_attempt_at: 0, regen_content: Some(content),
            });
        }
        core.withdraw_unsent("conv");
        let left: Vec<&String> = core.awaiting_confirmation.keys().collect();
        assert_eq!(left, vec!["other"]);
    }

    #[test]
    fn a_short_recovery_passphrase_is_refused() {
        let err = P2PCore::new().export_recovery("elevenchars".to_string()).unwrap_err();
        assert!(err.contains("12"), "{err}");
        let err = P2PCore::new().export_recovery("twelve chars".to_string()).unwrap_err();
        assert!(!err.contains("12"), "long enough: fails later, for the missing identity ({err})");
    }

    #[test]
    fn recovery_file_with_a_huge_argon2_cost_is_rejected() {
        let file = ciborium_bytes(&RecoveryFile {
            kdf: "argon2id".into(), argon2_m_cost: u32::MAX, argon2_t_cost: 2, argon2_p_cost: 1,
            ciphertext: Vec::new(), nonce: Vec::new(), salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
        }).unwrap();
        let err = P2PCore::new().import_recovery(&file, "x", "n".to_string()).unwrap_err();
        assert!(err.contains("Argon2 parameters"), "{err}");
    }

    #[test]
    fn pairing_rejects_malformed_and_own_codes() {
        let mut core = P2PCore::new();
        let id = "a".repeat(64);
        let fp = "b".repeat(64);
        assert!(core.register_contact_from_pairing("not-hex".into(), fp.clone(), "x".into()).is_err());
        assert!(core.register_contact_from_pairing(id.clone(), "short".into(), "x".into()).is_err());
        core.register_contact_from_pairing(id.clone(), fp.clone(), "Ali\u{202E}".into()).unwrap();
        // Same first 16 characters, another identity: a second contact, not a replacement.
        let twin = format!("{}{}", "a".repeat(16), "c".repeat(48));
        core.register_contact_from_pairing(twin.clone(), "d".repeat(64), "Eve".into()).unwrap();
        assert_eq!(core.contacts.len(), 2);
        let first = &core.contacts[&core.identity_to_contact[&id]];
        assert_eq!(first.trusted_identity_id, id);
        assert_eq!(first.display_name, "Ali");
        assert!(first.is_known_active(&fp));
    }

    #[test]
    fn scanned_code_cannot_add_a_device_to_a_known_contact() {
        let mut core = P2PCore::new();
        let (id, fp, other) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        core.register_contact_from_pairing(id.clone(), fp.clone(), "Bob".into()).unwrap();
        // A known identity with a device it does not list.
        assert!(core.register_contact_from_pairing(id.clone(), other.clone(), "Mallory".into()).is_err());
        // The uppercase form of a known id is not a second contact.
        assert!(core.register_contact_from_pairing(id.to_uppercase(), other.clone(), "x".into()).is_err());
        assert_eq!(core.contacts.len(), 1);
        let cid = core.identity_to_contact[&id].clone();
        // Revoked by the user: scanning again brings it back. Revoked by its owner: never.
        core.contacts.get_mut(&cid).unwrap().revoke_device(&fp, 1);
        core.register_contact_from_pairing(id.clone(), fp.clone(), "Bob".into()).unwrap();
        assert!(core.contacts[&cid].is_known_active(&fp));
        core.contacts.get_mut(&cid).unwrap().revoke_device_by_owner(&fp, 2);
        assert!(core.register_contact_from_pairing(id.clone(), fp.clone(), "Bob".into()).is_err());
        assert!(!core.contacts[&cid].is_known_active(&fp));
    }

    #[test]
    fn device_add_signature_is_not_a_device_revoke() {
        assert_ne!(
            P2PCore::device_auth_signing_bytes("id", "subject", "actor", false),
            P2PCore::device_auth_signing_bytes("id", "subject", "actor", true),
        );
    }

    #[test]
    fn rejected_device_alert_is_not_raised_again() {
        let mut core = P2PCore::new();
        let (id, fp, other) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        core.register_contact_from_pairing(id.clone(), fp, "Bob".into()).unwrap();
        assert_eq!(core.evaluate_sender_device(&id, &other, false, "x", false), DeviceCheckOutcome::UnverifiedNewDeviceAlert);
        assert_eq!(core.pending_device_alerts.len(), 1);
        core.reject_pending_device_alert(&other);
        core.attachment_events.clear();
        assert_eq!(core.evaluate_sender_device(&id, &other, false, "x", false), DeviceCheckOutcome::UnverifiedNewDeviceAlert);
        assert!(core.pending_device_alerts.is_empty() && core.attachment_events.is_empty());
    }

    #[test]
    fn stranger_becomes_a_contact_only_with_the_nonce_of_a_shown_code() {
        let mut core = P2PCore::new();
        let (id, fp) = ("a".repeat(64), "b".repeat(64));
        assert_eq!(core.evaluate_sender_device(&id, &fp, false, "x", false), DeviceCheckOutcome::UnverifiedNewDeviceAlert);
        assert!(core.contacts.is_empty() && core.pending_device_alerts.is_empty());
        assert_eq!(core.evaluate_sender_device(&id, &fp, false, "x", true), DeviceCheckOutcome::NewContactTofu);
        assert_eq!(core.contacts.len(), 1);
    }

    #[test]
    fn pairing_proof_needs_the_issued_nonce_and_the_senders_own_fingerprint() {
        let mut me = P2PCore::new();
        let peer_fp = "b".repeat(64);
        // The peer read the link code `me` shows (that nonce is in memory).
        me.link_request_nonce = vec![7; 16];
        me.link_request_open_until = current_time_ms() + 60_000;
        let with = |pairing_proof: Vec<u8>| IdentityExchange {
            identity_id: peer_fp.clone(),
            device_fingerprint: peer_fp.clone(),
            device_name: "P".into(),
            sign_pubkey_ed25519: Vec::new(),
            sign_pubkey_mldsa: Vec::new(),
            kem_pubkey_x25519: Vec::new(),
            kem_pubkey_mlkem: Vec::new(),
            device_add: None,
            revokes: Vec::new(),
            device_add_signer: None,
            pairing_proof,
            link_consent: Vec::new(),
            link_consent_pq: Vec::new(),
            prekey: None,
            timestamp: 0,
            signature: Vec::new(),
            signature_pq: Vec::new(),
        };
        // No proof, another nonce, the right nonce taken over by another device.
        assert!(!me.pairing_proof_valid(&with(Vec::new())));
        assert!(!me.pairing_proof_valid(&with(packet::pairing_nonce_proof(&[8; 16], &peer_fp))));
        assert!(!me.pairing_proof_valid(&with(packet::pairing_nonce_proof(&[7; 16], &"c".repeat(64)))));
        let good = with(packet::pairing_nonce_proof(&[7; 16], &peer_fp));
        assert!(me.pairing_proof_valid(&good));
        // A device with a contact already: the link code makes no further one.
        assert_eq!(me.evaluate_sender_device(&"d".repeat(64), &"e".repeat(64), false, "x", true), DeviceCheckOutcome::NewContactTofu);
        assert!(!me.pairing_proof_valid(&good));
        // The code is no longer shown.
        me.link_request_open_until = 0;
        assert!(!me.pairing_proof_valid(&good));
    }

    #[test]
    fn identity_claim_of_a_secondary_needs_the_root_signed_add() {
        let (mut primary, mut secondary) = (P2PCore::new(), P2PCore::new());
        let (root_id, _) = primary.generate_identity("P".into()).unwrap();
        let (sec_fp, _) = secondary.generate_identity("S".into()).unwrap();
        let rec = secondary.own_devices[&sec_fp].clone();
        let (consent, consent_pq) = secondary.sign_link_consent(&root_id).unwrap();
        let mut ix = IdentityExchange {
            identity_id: root_id.clone(),
            device_fingerprint: sec_fp.clone(),
            device_name: "S".into(),
            sign_pubkey_ed25519: rec.sign_pubkey_ed25519,
            sign_pubkey_mldsa: rec.sign_pubkey_mldsa,
            kem_pubkey_x25519: rec.kem_pubkey_x25519,
            kem_pubkey_mlkem: rec.kem_pubkey_mlkem,
            device_add: Some(primary.sign_device_add(&sec_fp, &consent, &consent_pq).unwrap()),
            revokes: Vec::new(),
            device_add_signer: primary.own_synced_device(),
            pairing_proof: Vec::new(),
            link_consent: Vec::new(),
            link_consent_pq: Vec::new(),
            prekey: None,
            timestamp: 0,
            signature: Vec::new(),
            signature_pq: Vec::new(),
        };
        let mut stranger = P2PCore::new();
        let (stranger_fp, _) = stranger.generate_identity("X".into()).unwrap();
        ix.timestamp = current_time_ms();
        let keys = &secondary.own_device_keys[&sec_fp];
        let to_sign = packet::identity_exchange_signing_input(
            &ix.identity_id, &ix.device_fingerprint, &ix.device_name, &ix.pairing_proof, &stranger_fp, ix.timestamp, &ix.revokes,
        );
        let sig_classical: Ed25519Signature = keys.sign_sk_ed25519.sign(&to_sign);
        let sig_pq: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&to_sign);
        ix.signature = sig_classical.to_bytes().to_vec();
        ix.signature_pq = sig_pq.encode().to_vec();
        // Both signatures are deterministic: a resent IdentityExchange stays
        // byte-identical, which the server deposit dedup relies on.
        let again: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&to_sign);
        assert_eq!(again.encode().to_vec(), ix.signature_pq);
        assert!(P2PCore::identity_proved_by_root(&ix));
        // The first device's signature alone, and with the consent of a
        // device other than the added one (here: its own).
        let (root_c, root_c_pq) = primary.sign_link_consent(&root_id).unwrap();
        for (c, c_pq) in [(Vec::new(), Vec::new()), (root_c, root_c_pq)] {
            let squat = IdentityExchange { device_add: Some(primary.sign_device_add(&sec_fp, &c, &c_pq).unwrap()), ..ix.clone() };
            assert!(!P2PCore::identity_proved_by_root(&squat));
        }
        // A stranger accepts it only with the proof, and never a bare claim.
        stranger.link_request_open_until = current_time_ms() + 60_000; // pairing open
        let bare = IdentityExchange { device_add: None, device_add_signer: None, ..ix.clone() };
        let refused = stranger.process_identity_exchange(None, &bare).unwrap_err();
        assert!(!refused.contains("signature"), "refused for the claim, not the signature: {refused}");
        // The device signs its name and identity: a relay cannot change them,
        // and an unsigned packet (a version before the signature) is refused.
        for forged in [
            IdentityExchange { device_name: "Mallory".into(), ..ix.clone() },
            IdentityExchange { identity_id: sec_fp.clone(), ..ix.clone() },
            IdentityExchange { signature: Vec::new(), signature_pq: Vec::new(), ..ix.clone() },
            // signed for another recipient, or at another time.
            IdentityExchange { timestamp: ix.timestamp - 1, ..ix.clone() },
        ] {
            assert!(stranger.process_identity_exchange(None, &forged).unwrap_err().contains("signature"));
        }
        // addressed to the stranger, so another device refuses it; and
        // one older than the window is refused before the signature.
        let mut other = P2PCore::new();
        other.generate_identity("O".into()).unwrap();
        other.link_request_open_until = current_time_ms() + 60_000;
        assert!(other.process_identity_exchange(None, &ix).unwrap_err().contains("signature"));
        let old = IdentityExchange { timestamp: ix.timestamp - HANDSHAKE_MAX_AGE_MS - 1, ..ix.clone() };
        assert!(stranger.process_identity_exchange(None, &old).unwrap_err().contains("window"));
        // The secondary's own keys as "signer": they do not hash to the identity id.
        let own = IdentityExchange { device_add_signer: secondary.own_synced_device(), ..ix.clone() };
        assert!(stranger.process_identity_exchange(None, &own).is_err());
        assert!(stranger.contacts.is_empty());
        // An add for another device does not carry over.
        ix.device_add = Some(primary.sign_device_add(&"c".repeat(64), &consent, &consent_pq).unwrap());
        assert!(!P2PCore::identity_proved_by_root(&ix));
    }

    /// Only the root device may sign a device add or revoke. Any other active device must be rejected, including a revoke of the first device.
    #[test]
    fn only_the_first_device_adds_and_revokes() {
        let (mut primary, mut secondary, mut me) = (P2PCore::new(), P2PCore::new(), P2PCore::new());
        let (root_id, _) = primary.generate_identity("P".into()).unwrap();
        let (sec_fp, _) = secondary.generate_identity("S".into()).unwrap();
        me.known_remote_devices.insert(root_id.clone(), primary.own_devices[&root_id].clone());
        let mut sec = secondary.own_devices[&sec_fp].clone();
        sec.identity_id = root_id.clone();
        me.known_remote_devices.insert(sec_fp.clone(), sec);

        let add = primary.sign_device_add(&sec_fp, &[], &[]).unwrap();
        assert!(me.verify_device_auth(&add.identity_id, &add.new_device_fingerprint, &add.added_by, &add.signature, &add.signature_pq, false).is_ok());
        let revoke = primary.sign_device_revoke(&sec_fp).unwrap();
        assert!(me.verify_device_auth(&revoke.identity_id, &revoke.revoked_device_fingerprint, &revoke.revoked_by, &revoke.signature, &revoke.signature_pq, true).is_ok());

        // The root's valid revoke of a device held under another identity.
        me.known_remote_devices.get_mut(&sec_fp).unwrap().identity_id = "d".repeat(64);
        assert!(me.verify_device_auth(&revoke.identity_id, &revoke.revoked_device_fingerprint, &revoke.revoked_by, &revoke.signature, &revoke.signature_pq, true).is_err());

        // The secondary, with valid signatures of its own: revoking the first
        // device, and adding a third one.
        let keys = &secondary.own_device_keys[&sec_fp];
        for (subject, is_revoke) in [(root_id.clone(), true), ("c".repeat(64), false)] {
            let msg = P2PCore::device_auth_signing_bytes(&root_id, &subject, &sec_fp, is_revoke);
            let sig_c: Ed25519Signature = keys.sign_sk_ed25519.sign(&msg);
            let sig_pq: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&msg);
            assert!(me.verify_device_auth(&root_id, &subject, &sec_fp, &sig_c.to_bytes().to_vec(), &sig_pq.encode().to_vec(), is_revoke).is_err());
        }
    }

    /// The founder's own handover update must be accepted by every receiver. Otherwise the group is left without a working founder.
    #[test]
    fn founder_handover_is_accepted_and_heals_a_member_that_missed_it() {
        let mut cores: Vec<P2PCore> = (0..4).map(|_| P2PCore::new()).collect();
        let ids: Vec<String> = cores.iter_mut().enumerate()
            .map(|(i, c)| c.generate_identity(format!("d{i}")).unwrap().0).collect();
        // Everybody knows everybody's device.
        let recs: Vec<DeviceRecord> = cores.iter().zip(&ids).map(|(c, id)| c.own_devices[id].clone()).collect();
        for (i, c) in cores.iter_mut().enumerate() {
            for (j, r) in recs.iter().enumerate() {
                if i != j { c.known_remote_devices.insert(r.device_fingerprint.clone(), r.clone()); }
            }
        }
        let gid = "group-0123456789abcdef".to_string();
        let mut g = Group::new(gid.clone(), "g".into(), ids[0].clone(), 1);
        g.sync_members(&ids, 1);
        g.version = 1;
        for c in cores.iter_mut() { c.groups.insert(gid.clone(), g.clone()); }

        // A (0) hands over to B (1); C (2) gets the update, D (3) misses it.
        cores[0].transfer_group_founder(&gid, &ids[1]).unwrap();
        let mut pre = g.clone();
        pre.founder_chain = cores[0].groups[&gid].founder_chain.clone();
        let handover = cores[0].sign_group_change(&pre, &GroupChange::TransferFounder(ids[1].clone())).unwrap();
        for i in [1, 2] {
            cores[i].process_group_update(&handover).unwrap();
            assert_eq!(cores[i].groups[&gid].founder_identity_id, ids[1], "core {i}");
            assert_eq!(cores[i].groups[&gid].version, 2);
        }
        // B's next update carries the chain: D follows it.
        let next = cores[1].sign_group_change(&cores[1].groups[&gid].clone(), &GroupChange::AvatarUpdate(None)).unwrap();
        cores[3].process_group_update(&next).unwrap();
        assert_eq!(cores[3].groups[&gid].founder_identity_id, ids[1]);
        // A forged chain entry signed by a plain member is not stored.
        assert!(cores[3].groups[&gid].founder_chain.iter().all(|t| t.from_identity == ids[0]));
    }

    /// Covers three fixes: two updates of one version end the same on every member; an update carries only new devices; secrets are per group.
    #[test]
    fn same_version_updates_converge_and_carry_only_new_devices() {
        let base = std::env::temp_dir().join(format!("typeon-tie-{}", std::process::id()));
        let mut cores: Vec<P2PCore> = (0..4).map(|i| {
            let d = base.join(i.to_string());
            std::fs::create_dir_all(&d).unwrap();
            let mut c = P2PCore::new();
            c.init_db(d.to_str().unwrap(), &[1u8; 32]).unwrap();
            c
        }).collect();
        let ids: Vec<String> = cores.iter_mut().enumerate()
            .map(|(i, c)| c.generate_identity(format!("d{i}")).unwrap().0).collect();
        let recs: Vec<DeviceRecord> = cores.iter().zip(&ids).map(|(c, id)| c.own_devices[id].clone()).collect();
        for (i, c) in cores.iter_mut().enumerate() {
            for (j, r) in recs.iter().enumerate() {
                if i != j { c.known_remote_devices.insert(r.device_fingerprint.clone(), r.clone()); }
            }
        }
        let gid = "group-0123456789abcdef".to_string();
        let mut g = Group::new(gid.clone(), "g".into(), ids[0].clone(), 1);
        g.sync_members(&ids, 1);
        g.version = 1;
        for c in cores.iter_mut() { c.groups.insert(gid.clone(), g.clone()); }

        // Two version-2 updates of the founder identity (two founder devices).
        let u1 = cores[0].sign_group_change(&g, &GroupChange::Remove(ids[3].clone())).unwrap();
        let u2 = cores[0].sign_group_change(&g, &GroupChange::AvatarUpdate(None)).unwrap();
        assert_eq!(u1.member_devices.len(), 3, "first update: every device");
        assert_eq!(u2.member_devices.len(), 1, "then only the one not sent yet");
        assert!(cores[0].sign_group_change(&g, &GroupChange::AvatarUpdate(None)).unwrap().member_devices.is_empty());
        assert_eq!(cores[0].sign_group_resync(&g).unwrap().member_devices.len(), 4, "a resync carries all");
        for (i, order) in [(1, [&u1, &u2]), (2, [&u2, &u1])] {
            for u in order { cores[i].process_group_update(u).unwrap(); }
            cores[i].process_group_update(order[0]).unwrap();
        }
        let members = |c: &P2PCore| { let mut m = c.groups[&gid].member_identity_ids(); m.sort(); m };
        assert_eq!(members(&cores[1]), members(&cores[2]));
        assert_eq!(cores[1].groups[&gid].version, 2);
        assert_eq!(cores[2].groups[&gid].version, 2);

        // one first-contact secret per group, registered while in it.
        let other = "group-fedcba9876543210";
        assert_ne!(cores[1].own_group_contact_secret(&gid), cores[1].own_group_contact_secret(other));
        assert!(cores[1].first_contact_secrets().contains(&cores[1].own_group_contact_secret(&gid)));
        assert!(!cores[1].first_contact_secrets().contains(&cores[1].own_group_contact_secret(other)));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn deleting_a_contact_keeps_the_keys_of_a_group_member() {
        let mut cores: Vec<P2PCore> = (0..3).map(|_| P2PCore::new()).collect();
        let ids: Vec<String> = cores.iter_mut().enumerate()
            .map(|(i, c)| c.generate_identity(format!("d{i}")).unwrap().0).collect();
        let recs: Vec<DeviceRecord> = cores.iter().zip(&ids).map(|(c, id)| c.own_devices[id].clone()).collect();
        for (i, c) in cores.iter_mut().enumerate() {
            for (j, r) in recs.iter().enumerate() {
                if i != j { c.known_remote_devices.insert(r.device_fingerprint.clone(), r.clone()); }
            }
        }
        // B (1) founded the group; C (2) has B as a contact and deletes it.
        let gid = "group-0123456789abcdef".to_string();
        let mut g = Group::new(gid.clone(), "g".into(), ids[1].clone(), 1);
        g.sync_members(&ids, 1);
        g.version = 1;
        for c in cores.iter_mut() { c.groups.insert(gid.clone(), g.clone()); }
        cores[2].register_contact_from_pairing(ids[1].clone(), ids[1].clone(), "b".into()).unwrap();
        let cid = cores[2].identity_to_contact[&ids[1]].clone();
        cores[2].delete_contact(&cid, false).unwrap();
        assert!(cores[2].known_remote_devices.contains_key(&ids[1]));
        assert!(cores[2].contacts[&cid].added_via_group);

        // B hands the group to A: C still has the keys to verify it.
        cores[1].transfer_group_founder(&gid, &ids[0]).unwrap();
        let mut pre = g.clone();
        pre.founder_chain = cores[1].groups[&gid].founder_chain.clone();
        let handover = cores[1].sign_group_change(&pre, &GroupChange::TransferFounder(ids[0].clone())).unwrap();
        cores[2].process_group_update(&handover).unwrap();
        assert_eq!(cores[2].groups[&gid].founder_identity_id, ids[0]);

        // No shared group left: the delete takes the keys too.
        cores[2].groups.clear();
        cores[2].delete_contact(&cid, false).unwrap();
        assert!(!cores[2].known_remote_devices.contains_key(&ids[1]));
        assert!(cores[2].contacts.is_empty());
    }

    #[test]
    fn vouched_device_must_be_bound_to_its_identity() {
        let (mut primary, mut secondary, mut me) = (P2PCore::new(), P2PCore::new(), P2PCore::new());
        let (root_id, _) = primary.generate_identity("P".into()).unwrap();
        let (sec_fp, _) = secondary.generate_identity("S".into()).unwrap();
        let rec = secondary.own_devices[&sec_fp].clone();
        // "This key is that identity's", on the founder's word alone.
        let claim = GroupMemberDevice {
            identity_id: root_id.clone(),
            device_fingerprint: sec_fp.clone(),
            device_name: "S".into(),
            sign_pubkey_ed25519: rec.sign_pubkey_ed25519,
            sign_pubkey_mldsa: rec.sign_pubkey_mldsa,
            kem_pubkey_x25519: rec.kem_pubkey_x25519,
            kem_pubkey_mlkem: rec.kem_pubkey_mlkem,
            last_addr: None,
            first_contact_secret: Vec::new(),
        };
        me.adopt_vouched_member_devices(&[claim.clone()], &[]);
        assert!(me.contacts.is_empty() && me.known_remote_devices.is_empty());
        let proof = packet::DeviceAddProof {
            device_add: primary.sign_device_add(&sec_fp, &[], &[]).unwrap(),
            signer: primary.own_synced_device().unwrap(),
        };
        // Signed by the first device only: any identity could claim the key.
        me.adopt_vouched_member_devices(&[claim.clone()], &[proof.clone()]);
        assert!(me.contacts.is_empty() && me.known_remote_devices.is_empty());
        let (consent, consent_pq) = secondary.sign_link_consent(&root_id).unwrap();
        let proof = packet::DeviceAddProof {
            device_add: primary.sign_device_add(&sec_fp, &consent, &consent_pq).unwrap(),
            ..proof
        };
        me.adopt_vouched_member_devices(&[claim], &[proof]);
        assert_eq!(me.known_remote_devices[&sec_fp].identity_id, root_id);
        assert_eq!(me.contacts.len(), 1);
    }

    #[test]
    fn sync_payload_is_cut_into_parts() {
        let mut core = P2PCore::new();
        for i in 0..150 {
            let (id, fp) = (format!("{:064x}", i), format!("{:064x}", 1000 + i));
            core.register_contact_from_pairing(id.clone(), fp.clone(), "c".into()).unwrap();
            core.known_remote_devices.insert(fp.clone(), DeviceRecord {
                device_fingerprint: fp, identity_id: id,
                sign_pubkey_ed25519: vec![], sign_pubkey_mldsa: vec![], kem_pubkey_x25519: vec![], kem_pubkey_mlkem: vec![],
                device_name: String::new(), is_active: true, last_seen: 0,
            });
        }
        let parts = core.build_sync_payloads();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts.iter().map(|p| p.contacts.len()).sum::<usize>(), 150);
        assert!(parts.iter().all(|p| p.contacts.iter().map(|c| c.devices.len()).sum::<usize>() <= 100));
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    fn core_on_disk(dir: &std::path::Path) -> P2PCore {
        let mut core = P2PCore::new();
        core.init_db(dir.to_str().unwrap(), &[1u8; 32]).unwrap();
        core.history_key = Some([2u8; 32]);
        core.skipped_key_encryption_key = Some([3u8; 32]);
        core
    }

    #[test]
    fn unknown_group_room_fails_closed() {
        let gid = "group-0123456789abcdef";
        assert!(!P2PCore::new().unknown_group_has_room(gid), "no DB: no room");
        let dir = std::env::temp_dir().join(format!("typeon-gidroom-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let core = core_on_disk(&dir);
        assert!(core.unknown_group_has_room(gid));
        core.db.as_ref().unwrap().execute_batch("DROP TABLE groups").unwrap();
        assert!(!core.unknown_group_has_room(gid), "query error: no room");
    }

    /// duplicates from an older build are merged at start, then the
    /// UNIQUE index makes a second archive of one id a no-op.
    #[test]
    fn message_ids_are_deduped_and_unique() {
        let dir = std::env::temp_dir().join(format!("typeon-dedupe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        {
            let c = core.db.as_ref().unwrap();
            c.execute_batch("DROP INDEX idx_messages_msgid_unique;
                INSERT INTO messages (peer_device_fingerprint, direction, encrypted_blob, nonce, timestamp, message_id) VALUES ('p', 'sent', x'00', x'00', 1, 'd');
                INSERT INTO messages (peer_device_fingerprint, direction, encrypted_blob, nonce, timestamp, message_id, is_deleted) VALUES ('p', 'sent', x'00', x'00', 2, 'd', 1);
                INSERT INTO messages (peer_device_fingerprint, direction, encrypted_blob, nonce, timestamp, message_id, group_id) VALUES ('', 'sent', x'00', x'00', 3, 'd', 'g');").unwrap();
        }
        core.db = None;
        let mut core = core_on_disk(&dir);
        let count = |core: &P2PCore| core.db.as_ref().unwrap()
            .query_row("SELECT COUNT(*), MAX(is_deleted) FROM messages WHERE message_id = 'd' AND group_id IS NULL", [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).unwrap();
        assert_eq!(count(&core), (1, 1), "the deleted copy is kept");
        core.archive_message("p", "sent", b"x", Some("d"), Some("sent"), None, None, 5).unwrap();
        assert_eq!(count(&core).0, 1);
        let groups: i64 = core.db.as_ref().unwrap().query_row("SELECT COUNT(*) FROM messages WHERE message_id = 'd' AND group_id = 'g'", [], |r| r.get(0)).unwrap();
        assert_eq!(groups, 1, "another scope keeps its own row");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_recovery_file_brings_back_contacts_and_chats() {
        let base = std::env::temp_dir().join(format!("typeon-recovery-{}", std::process::id()));
        let (da, db, dp) = (base.join("a"), base.join("b"), base.join("peer"));
        for d in [&da, &db, &dp] { std::fs::create_dir_all(d).unwrap(); }
        let mut a = core_on_disk(&da);
        let mut peer = core_on_disk(&dp);
        a.generate_identity("a".into()).unwrap();
        let pid = peer.generate_identity("p".into()).unwrap().0;
        let rec = peer.own_devices[&pid].clone();
        a.known_remote_devices.insert(rec.device_fingerprint.clone(), rec.clone());
        a.persist_remote_device(&rec);
        a.register_contact_from_pairing(pid.clone(), pid.clone(), "p".into()).unwrap();
        a.archive_message(&pid, "sent", b"hello", Some("m1"), Some("sent"), None, None, 5).unwrap();
        a.archive_message(&pid, "received", b"hi back", Some("m2"), None, Some("m1"), Some("hello"), 6).unwrap();

        let file = a.export_recovery("long enough passphrase".into()).unwrap();
        let mut b = core_on_disk(&db);
        b.import_recovery(&file, "long enough passphrase", "b".into()).unwrap();
        assert!(b.identity_to_contact.contains_key(&pid), "contact restored");
        let rows = b.load_message_history_opt(&pid, 10, None, false);
        let texts: Vec<&str> = rows.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(texts, ["hello", "hi back"]);
        assert_eq!(rows[1].direction, "received");
        assert_eq!(rows[1].reply_to_message_id.as_deref(), Some("m1"));

        // Over the size cap only the newest rows go in.
        a.archive_message(&pid, "sent", b"third", Some("m3"), Some("sent"), None, None, 7).unwrap();
        a.backdate_archived(None, &pid, Some("m1"), 1);
        a.backdate_archived(None, &pid, Some("m2"), 2);
        a.backdate_archived(None, &pid, Some("m3"), 3);
        let mut data = a.recovery_data();
        data.keep_newest(2);
        let kept: Vec<&str> = data.chats.iter().flat_map(|(_, _, r)| r.iter().map(|m| m.text.as_str())).collect();
        assert_eq!(kept, ["hi back", "third"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// a history page may not forge, freeze or erase my reactions, nor
    /// react on rows the filters dropped.
    #[test]
    fn synced_reactions_only_for_kept_rows_and_mine_only_restored() {
        let dir = std::env::temp_dir().join(format!("typeon-syncreact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        let me = core.generate_identity("me".into()).unwrap().0;
        let gid = "group-0123456789abcdef".to_string();
        core.groups.insert(gid.clone(), Group::new(gid.clone(), "g".into(), me.clone(), 1));
        for id in ["m1", "m2", "m3", "m4"] {
            core.archive_group_message(&gid, "peer", "received", b"x", Some(id), None, None, None, 1, None).unwrap();
        }
        assert!(core.apply_reaction("m3", &me, "A", 10));
        let r = |who: &str, emoji: &str, at: u64| (who.to_string(), emoji.to_string(), at);
        let reactions: HashMap<String, Vec<(String, String, u64)>> = [
            ("m1".to_string(), vec![r("peer", "P", 5), r("other", "Q", 5), r(&me, "", 5)]),
            ("m2".to_string(), vec![r(&me, "B", u64::MAX)]),
            ("m3".to_string(), vec![r(&me, "C", 20)]),
            ("m4".to_string(), vec![r("peer", "D", 5)]),
        ].into_iter().collect();
        let mut event = serde_json::json!({"messages": [{"message_id": "m1"}, {"message_id": "m2"}, {"message_id": "m3"}]});
        core.apply_synced_reactions(&mut event, &reactions, Some(gid.as_str()), "peer");
        let all = |id: &str| -> Vec<(String, String)> {
            let c = core.db.as_ref().unwrap();
            let mut st = c.prepare("SELECT reactor_identity_id, emoji FROM message_reactions WHERE message_id = ?1 ORDER BY reactor_identity_id").unwrap();
            st.query_map(params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().flatten().collect()
        };
        assert_eq!(all("m1"), vec![("peer".to_string(), "P".to_string())], "responder's own only; my erase refused");
        assert!(all("m2").is_empty(), "stamp in the future");
        assert_eq!(all("m3"), vec![(me.clone(), "A".to_string())], "mine only restored, never replaced");
        assert!(all("m4").is_empty(), "row not kept by the filters");
        assert_eq!(event["messages"][0]["reactions"], "P");
        let mut event = serde_json::json!({"messages": [{"message_id": "m2"}]});
        let ok: HashMap<String, Vec<(String, String, u64)>> = [("m2".to_string(), vec![r(&me, "B", 5)])].into_iter().collect();
        core.apply_synced_reactions(&mut event, &ok, Some(gid.as_str()), "peer");
        assert_eq!(all("m2"), vec![(me, "B".to_string())], "a missing one of mine is restored");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// @mentions: only my own id flags the message, and ids of non-members
    /// are dropped.
    #[test]
    fn mentions_me_only_for_own_id_and_members() {
        let dir = std::env::temp_dir().join(format!("typeon-mention-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        let me = core.generate_identity("me".into()).unwrap().0;
        let gid = "group-0123456789abcdef".to_string();
        let mut g = Group::new(gid.clone(), "g".into(), "peer".into(), 1);
        g.members.push(group::GroupMember { identity_id: me.clone(), added_at: 1, added_by: "peer".into() });
        assert_eq!(filter_mentions(&g, None, vec!["stranger".into(), me.clone(), me.clone(), "peer".into()]), vec![me.clone(), "peer".to_string()]);
        assert_eq!(filter_mentions(&g, Some("peer"), vec!["peer".into()]), Vec::<String>::new(), "sender dropped");
        core.groups.insert(gid.clone(), g);
        assert!(core.group_mentions_me(&gid, vec!["peer".into(), me.clone()]));
        assert!(!core.group_mentions_me(&gid, vec!["peer".into(), "stranger".into()]));
        assert!(!core.group_mentions_me("group-ffffffffffffffff", vec![me.clone()]), "unknown group");
        core.groups.get_mut(&gid).unwrap().members.retain(|m| m.identity_id != me);
        assert!(!core.group_mentions_me(&gid, vec![me]), "not a member any more");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cleared group's rows (and the reactions on its files) stay gone:
    /// a sibling's automatic backfill of older rows is refused by the floor.
    /// Only the sibling's answer that echoes an open press window brings
    /// them back, once, and the floor goes down to the oldest row written.
    #[test]
    fn cleared_group_history_does_not_come_back() {
        let dir = std::env::temp_dir().join(format!("typeon-gclear-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("attachments")).unwrap();
        let mut core = core_on_disk(&dir);
        let gid = "group-0123456789abcdef".to_string();
        core.groups.insert(gid.clone(), Group::new(gid.clone(), "g".into(), "me".into(), 1));
        core.archive_group_message(&gid, "x", "received", b"old", Some("m1"), None, None, None, 1, None).unwrap();
        core.db.as_ref().unwrap().execute_batch(&format!(
            "INSERT INTO files (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size, sha256_hex, encrypted_file_key, key_nonce, status, created_at, group_id)
             VALUES ('f1', 'p', 'received', 'a.jpg', 'image/jpeg', 9, '', x'00', x'00', 'complete', 1, '{gid}');")).unwrap();
        assert!(core.apply_reaction("f1", "x", "A", 1));
        core.clear_group_history(&gid).unwrap();
        let reactions: i64 = core.db.as_ref().unwrap().query_row("SELECT COUNT(*) FROM message_reactions", [], |r| r.get(0)).unwrap();
        assert_eq!(reactions, 0, "file reactions go too");
        let entry = |id: &str, at: u64| SiblingHistoryEntry {
            conversation_identity_id: None, group_id: Some(gid.clone()), direction: "received".into(), text: "t".into(),
            message_id: id.into(), sender_identity_id: Some("x".into()), reply_to_message_id: None, reply_to_preview: None,
            reply_to_sender_identity_id: None, sent_at_ms: at, author_proof: None, file: None, reactions: Vec::new(),
        };
        core.apply_sibling_history("", vec![entry("m1", 1), entry("m2", current_time_ms() + 1_000)], false);
        assert!(!core.message_exists_in_chat("m1", Some(gid.as_str()), ""), "cleared row stays gone");
        assert!(core.message_exists_in_chat("m2", Some(gid.as_str()), ""), "a newer row still arrives");
        // No window, or a window no press of ours opened to this sibling: automatic.
        core.sibling_fetch_open.insert(("sib".into(), 1_000, 0), (gid.clone(), current_time_ms()));
        for (from, window) in [("sib", None), ("sib", Some((2_000, 0))), ("other", Some((1_000, 0)))] {
            let (_, chat) = core.apply_sibling_reply(from, window, false, vec![entry("m1", 1)]);
            assert!(chat.is_none());
            assert!(!core.message_exists_in_chat("m1", Some(gid.as_str()), ""), "{from} {window:?}: floor holds");
        }
        // The echo of the open press: rows inside its window come back.
        let (rows, chat) = core.apply_sibling_reply("sib", Some((1_000, 0)), false, vec![entry("m1", 1), entry("m3", 1_000)]);
        assert_eq!(chat.as_deref(), Some(gid.as_str()));
        assert_eq!(rows.len(), 1, "a row at the window's end is outside it");
        assert!(core.message_exists_in_chat("m1", Some(gid.as_str()), ""), "fetched back by the user");
        assert_eq!(core.history_floor(&gid), 1, "floor lowered to the oldest row written");
        // Consumed: the same echo again is automatic.
        assert!(core.sibling_fetch_open.is_empty());
        core.apply_sibling_reply("sib", Some((1_000, 0)), false, vec![entry("m4", 2)]);
        assert!(core.message_exists_in_chat("m4", Some(gid.as_str()), ""), "above the lowered floor anyway");
        core.apply_sibling_reply("sib", Some((1_000, 0)), false, vec![entry("m5", 0)]);
        assert!(!core.message_exists_in_chat("m5", Some(gid.as_str()), ""), "no open press, floor holds");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sibling's history answer carries attachments and reactions: the
    /// file row arrives with its date and voice length, and a reaction lands
    /// on a text row the requester already had.
    #[test]
    fn sibling_history_carries_files_and_reactions() {
        let gid = "group-0123456789abcdef".to_string();
        let mk = |name: &str| {
            let dir = std::env::temp_dir().join(format!("typeon-sibfile-{}-{}", name, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("attachments")).unwrap();
            let mut core = core_on_disk(&dir);
            core.groups.insert(gid.clone(), Group::new(gid.clone(), "g".into(), "me".into(), 1));
            core.archive_group_message(&gid, "x", "received", b"hi", Some("m1"), None, None, None, 5, None).unwrap();
            core
        };
        let (a, mut b) = (mk("a"), mk("b"));
        let (key, nonce) = a.wrap_file_key(&[7u8; 32]).unwrap();
        a.db.as_ref().unwrap().execute(
            "INSERT INTO files (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size, sha256_hex,
               encrypted_file_key, key_nonce, status, created_at, group_id, sender_identity_id, chunk_hashes, duration_ms)
             VALUES ('f1', 'p', 'received', 'v.ogg', 'audio/ogg', 9, ?1, ?2, ?3, 'complete', 42, ?4, 'x', ?5, 9000)",
            params!["ab".repeat(32), key, nonce, gid, vec![0u8; attachments::chunk_hashes_len(1)]],
        ).unwrap();
        assert!(a.apply_reaction("m1", "x", "A", 3));
        assert!(a.apply_reaction("f1", "x", "B", 4));
        let (entries, _) = a.build_sibling_history_response(50, None, Some(&gid), None, None, None);
        b.apply_sibling_history("sib", entries, false);
        let row: (String, i64, Option<i64>) = b.db.as_ref().unwrap().query_row(
            "SELECT direction, created_at, duration_ms FROM files WHERE file_id = 'f1'", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(row, ("received".to_string(), 42, Some(9000)));
        assert_eq!(b.reactions_summary("m1"), "A");
        assert_eq!(b.reactions_summary("f1"), "B");
    }

    /// A press pages back from its cursor. Attachments and reactions of rows
    /// already here (an earlier press brought their text) still come.
    #[test]
    fn sibling_press_brings_newer_files_and_reactions() {
        let gid = "group-0123456789abcdef".to_string();
        let mk = |name: &str| {
            let dir = std::env::temp_dir().join(format!("typeon-sibnewer-{}-{}", name, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("attachments")).unwrap();
            let mut core = core_on_disk(&dir);
            core.groups.insert(gid.clone(), Group::new(gid.clone(), "g".into(), "me".into(), 1));
            core.archive_group_message(&gid, "x", "received", b"hi", Some("m1"), None, None, None, 5_000, None).unwrap();
            core
        };
        let (a, mut b) = (mk("a"), mk("b"));
        let (key, nonce) = a.wrap_file_key(&[7u8; 32]).unwrap();
        a.db.as_ref().unwrap().execute(
            "INSERT INTO files (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size, sha256_hex,
               encrypted_file_key, key_nonce, status, created_at, group_id, sender_identity_id, chunk_hashes, duration_ms)
             VALUES ('f1', 'p', 'received', 'v.ogg', 'audio/ogg', 9, ?1, ?2, ?3, 'complete', 6000, ?4, 'x', ?5, 9000)",
            params!["ab".repeat(32), key, nonce, gid, vec![0u8; attachments::chunk_hashes_len(1)]],
        ).unwrap();
        assert!(a.apply_reaction("m1", "x", "A", 3));
        // B's cursor is already below both rows: the window [0, 1000).
        let (before, after) = (1_000i64, 0i64);
        let (entries, more) = a.build_sibling_history_response(200, None, Some(&gid), Some(before), None, Some((before, after)));
        assert!(entries.iter().all(|e| e.text.is_empty()), "no text past the window");
        b.sibling_fetch_open.insert(("sib".into(), before, after), (gid.clone(), current_time_ms()));
        let (merged, chat) = b.apply_sibling_reply("sib", Some((before, after)), more, entries);
        assert_eq!(chat.as_deref(), Some(gid.as_str()));
        assert!(merged.is_empty(), "no empty bubbles");
        assert_eq!(b.reactions_summary("m1"), "A");
        let n: i64 = b.db.as_ref().unwrap().query_row("SELECT COUNT(*) FROM files WHERE file_id = 'f1'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        let n: i64 = b.db.as_ref().unwrap().query_row("SELECT COUNT(*) FROM messages WHERE group_id = ?1", params![gid], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "a reaction carrier writes no row");
    }

    /// A cleared 1:1 chat's rows stay gone: a sibling's automatic backfill
    /// and the peer's chat-open sync are refused by the floor. The peer's
    /// answer to the user's "Fetch older history" press keeps exactly its
    /// window, below the floor too; a clear forgets the press, so its late
    /// answer is refused.
    #[test]
    fn cleared_chat_history_does_not_come_back() {
        let dir = std::env::temp_dir().join(format!("typeon-cclear-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("attachments")).unwrap();
        let mut core = core_on_disk(&dir);
        let mut c = Contact::new("c1".into(), "Alice".into(), "id1".into());
        c.add_device_unverified("dev1".into(), 1);
        core.contacts.insert("c1".into(), c);
        core.identity_to_contact.insert("id1".into(), "c1".into());
        core.archive_message("dev1", "received", b"old", Some("m1"), None, None, None, 1).unwrap();
        core.clear_chat_history("c1").unwrap();
        assert!(!core.message_exists_in_chat("m1", None, "dev1"));
        let entry = |id: &str, at: u64| SiblingHistoryEntry {
            conversation_identity_id: Some("id1".into()), group_id: None, direction: "received".into(), text: "t".into(),
            message_id: id.into(), sender_identity_id: None, reply_to_message_id: None, reply_to_preview: None,
            reply_to_sender_identity_id: None, sent_at_ms: at, author_proof: None, file: None, reactions: Vec::new(),
        };
        core.apply_sibling_history("", vec![entry("m1", 1), entry("m2", current_time_ms() + 1_000)], false);
        assert!(!core.message_exists_in_chat("m1", None, "dev1"), "cleared row stays gone");
        assert!(core.message_exists_in_chat("m2", None, "dev1"), "a newer row still arrives");

        let floor = core.history_floor("id1");
        let day = 24 * 60 * 60 * 1000;
        let synced = |id: &str, at: u64| SyncedMessage {
            direction: "sent".into(), text: "t".into(), timestamp: at, sender_identity_id: None,
            message_id: Some(id.into()), sent_at_ms: at, is_deleted: false, is_edited: false,
            author_proof: None, reactions: Vec::new(),
        };
        let page = || vec![synced("old", floor - 100 * day), synced("a", floor - 40 * day), synced("b", floor - 20 * day), synced("new", floor + 1)];
        // Chat-open sync (no cursor) and a reply to no request of ours: floor holds.
        core.outstanding_history_requests.insert("auto".into(), (Some("id1".into()), None, current_time_ms(), None));
        for id in ["auto", "unknown"] {
            let mut rows = page();
            assert_eq!(core.filter_history_reply(id, None, "id1", &mut rows), None);
            let ids: Vec<_> = rows.iter().map(|m| m.message_id.clone().unwrap()).collect();
            assert_eq!(ids, ["new"], "{id}: only rows above the floor");
        }
        // The press [floor - 30d, floor): only rows sent inside the window.
        let (before, after) = (floor as i64, (floor - 30 * day) as i64);
        core.outstanding_history_requests.insert("press".into(), (Some("id1".into()), None, current_time_ms(), Some((before, after))));
        let mut rows = page();
        let press = core.filter_history_reply("press", None, "id1", &mut rows);
        let ids: Vec<_> = rows.iter().map(|m| m.message_id.clone().unwrap()).collect();
        assert_eq!(ids, ["b"]);
        assert_eq!(press, Some(((before, after), Some((floor - 20 * day) as i64))));
        core.lower_history_floor("id1", floor - 20 * day);
        assert_eq!(core.history_floor("id1"), floor - 20 * day, "fetched rows are not cleared any more");
        core.lower_history_floor("id1", floor);
        assert_eq!(core.history_floor("id1"), floor - 20 * day, "lowering never raises");
        // A clear forgets the open press: its late answer is unsolicited.
        // The new floor is "now": in the same millisecond as the first clear
        // the `floor + 1` row of `page()` would still be at or above it.
        std::thread::sleep(std::time::Duration::from_millis(2));
        core.clear_chat_history("c1").unwrap();
        assert!(!core.outstanding_history_requests.contains_key("press"));
        assert!(core.outstanding_history_requests.contains_key("auto"), "a chat-open sync stays");
        let mut rows = page();
        assert_eq!(core.filter_history_reply("press", None, "id1", &mut rows), None);
        assert!(rows.is_empty(), "nothing below the new floor");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// "Delete older than" removes old rows and the reactions on old files,
    /// and raises (never lowers) the history floor to the cut-off.
    #[test]
    fn pruned_chat_rows_go_and_raise_the_floor() {
        let dir = std::env::temp_dir().join(format!("typeon-prune-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("attachments")).unwrap();
        let mut core = core_on_disk(&dir);
        let gid = "group-0123456789abcdef".to_string();
        core.groups.insert(gid.clone(), Group::new(gid.clone(), "g".into(), "me".into(), 1));
        core.archive_group_message(&gid, "x", "received", b"old", Some("m1"), None, None, None, 100, None).unwrap();
        core.archive_group_message(&gid, "x", "received", b"new", Some("m2"), None, None, None, 300, None).unwrap();
        core.db.as_ref().unwrap().execute_batch(&format!(
            "INSERT INTO files (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size, sha256_hex, encrypted_file_key, key_nonce, status, created_at, group_id)
             VALUES ('f1', 'p', 'received', 'a.jpg', 'image/jpeg', 9, '', x'00', x'00', 'complete', 100, '{gid}');")).unwrap();
        assert!(core.apply_reaction("f1", "x", "A", 1));
        core.prune_chat_before("group", &gid, 200).unwrap();
        assert!(!core.message_exists_in_chat("m1", Some(gid.as_str()), ""));
        assert!(core.message_exists_in_chat("m2", Some(gid.as_str()), ""));
        let left: i64 = core.db.as_ref().unwrap().query_row(
            "SELECT (SELECT COUNT(*) FROM message_reactions) + (SELECT COUNT(*) FROM files)", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 0, "old file and its reactions go");
        assert_eq!(core.history_floor(&gid), 200);
        core.prune_chat_before("group", &gid, 150).unwrap();
        assert_eq!(core.history_floor(&gid), 200, "never lowered by a prune");
        // The automatic backfill keeps the pruned row out; the user's press brings it back.
        let entry = SiblingHistoryEntry {
            conversation_identity_id: None, group_id: Some(gid.clone()), direction: "received".into(), text: "old".into(),
            message_id: "m1".into(), sender_identity_id: Some("x".into()), reply_to_message_id: None, reply_to_preview: None,
            reply_to_sender_identity_id: None, sent_at_ms: 100, author_proof: None, file: None, reactions: Vec::new(),
        };
        core.apply_sibling_history("", vec![entry.clone()], false);
        assert!(!core.message_exists_in_chat("m1", Some(gid.as_str()), ""));
        // A prune forgets the press opened before it.
        core.sibling_fetch_open.insert(("sib".into(), 200, 0), (gid.clone(), current_time_ms()));
        core.prune_chat_before("group", &gid, 150).unwrap();
        core.apply_sibling_reply("sib", Some((200, 0)), false, vec![entry.clone()]);
        assert!(!core.message_exists_in_chat("m1", Some(gid.as_str()), ""), "late answer after the prune");
        core.sibling_fetch_open.insert(("sib".into(), 200, 0), (gid.clone(), current_time_ms()));
        core.apply_sibling_reply("sib", Some((200, 0)), false, vec![entry]);
        assert!(core.message_exists_in_chat("m1", Some(gid.as_str()), ""), "pruned row fetched back");
        assert_eq!(core.history_floor(&gid), 100, "floor down to the row written, not the window start");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The responder's "Fetch older history" page: the rows sent inside the
    /// requested window, by send time, not by arrival.
    #[test]
    fn history_fetch_page_is_the_requested_window() {
        let dir = std::env::temp_dir().join(format!("typeon-fetchpage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        let gid = "group-0123456789abcdef".to_string();
        core.groups.insert(gid.clone(), Group::new(gid.clone(), "g".into(), "me".into(), 1));
        let day: u64 = 24 * 60 * 60 * 1000;
        let now = 1_000 * day;
        for (id, d) in [("o1", 300u64), ("o2", 330), ("o3", 340), ("o4", 365), ("n1", 930), ("n2", 950)] {
            core.archive_group_message(&gid, "x", "received", b"t", Some(id), None, None, None, d * day, None).unwrap();
            core.archive_message("p", "received", b"t", Some(&format!("p{id}")), None, None, None, d * day).unwrap();
        }
        // Arrival is later than sending: the page goes by send time.
        core.db.as_ref().unwrap().execute("UPDATE messages SET timestamp = ?1", params![now as i64]).unwrap();
        let ids = |rows: Vec<ArchivedMessage>| rows.into_iter().map(|m| m.message_id.unwrap()).collect::<Vec<_>>();
        let g = |before: u64, after: u64| ids(core.load_history_fetch_page("", Some(&gid), 200, before as i64, after as i64));
        assert_eq!(g(now, now - 70 * day), ["n1", "n2"]);
        assert!(g(930 * day, 900 * day).is_empty(), "an empty month is empty, no gap skipping");
        assert_eq!(g(366 * day, 336 * day), ["o3", "o4"]);
        assert_eq!(g(340 * day, 330 * day), ["o2"], "start inclusive, end exclusive");
        assert_eq!(ids(core.load_history_fetch_page("p", None, 1, 366 * day as i64, 300 * day as i64)), ["po4"], "the newest rows of a capped window");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A device that said it is going offline (keepalive `bye`) is never
    /// dialed, even forced, until the park mark is cleared by its connection.
    #[test]
    fn parked_device_is_not_dialed() {
        let dir = std::env::temp_dir().join(format!("typeon-parked-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        let fp = "ab".repeat(32);
        let pid = libp2p::PeerId::random();
        core.device_last_addr.insert(fp.clone(), format!("/ip4/127.0.0.1/tcp/1/p2p/{pid}"));
        core.meta_put(&format!("parked:{fp}"), "1");
        assert!(!core.try_reconnect_device(&fp, false));
        assert!(!core.try_reconnect_device(&fp, true));
        core.meta_del(&format!("parked:{fp}"));
        assert!(core.try_reconnect_device(&fp, true), "unparked: dialed again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One press = one fixed window back from the chat's cursor. The first
    /// cursor ignores 1970 and bad-clock rows, a stored one wins over rows
    /// that arrive later. A press that reaches no source returns an error and
    /// keeps the cursor. A clear or prune resets it.
    #[test]
    fn history_fetch_cursor_moves_one_window_per_press() {
        let dir = std::env::temp_dir().join(format!("typeon-fetchcursor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        let gid = "group-0123456789abcdef".to_string();
        core.groups.insert(gid.clone(), Group::new(gid.clone(), "g".into(), "me".into(), 1));
        let day: u64 = 24 * 60 * 60 * 1000;
        let w = HISTORY_FETCH_WINDOW_MS;
        let now = current_time_ms();
        let key = format!("hfetch:{gid}");
        let cursor = |core: &P2PCore| core.meta_str(&key).and_then(|v| v.parse::<u64>().ok());
        let next = |core: &P2PCore| core.history_fetch_cursor(&gid, "", Some(&gid));
        // An empty chat starts at now. No member, sibling or server: nothing
        // goes out, so the month is not consumed.
        assert!(next(&core).abs_diff(now) < 60_000);
        assert_eq!(error_code(&core.fetch_server_history(&gid, true, 0).unwrap_err()), "NETWORK");
        assert_eq!(cursor(&core), None);
        assert!(!core.history_fetch_pages.contains_key(&gid));
        // Rows: the oldest real one 10 days back; a 1970 row and a bad-clock
        // row 400 days back (both arrived now) do not count.
        for (id, sent) in [("a", now - 10 * day), ("b", now - 2 * day), ("z", 1), ("bad", now - 400 * day)] {
            core.archive_group_message(&gid, "x", "received", b"t", Some(id), None, None, None, sent, None).unwrap();
        }
        assert_eq!(next(&core), now - 10 * day);
        // A press that went out stored its window start; a backdated row
        // arriving later cannot pin it.
        let first = now - 10 * day - w;
        core.meta_put(&key, &first.to_string());
        core.archive_group_message(&gid, "x", "received", b"t", Some("backdated"), None, None, None, 5, None).unwrap();
        assert_eq!(next(&core), first);
        assert!(core.fetch_server_history(&gid, true, now).is_err());
        assert_eq!(cursor(&core), Some(first), "nothing sent: cursor kept");
        core.clear_group_history(&gid).unwrap();
        assert_eq!(cursor(&core), None, "a clear resets the cursor");
        core.meta_put(&key, &first.to_string());
        core.prune_chat_before("group", &gid, (now - 5 * day) as i64).unwrap();
        assert_eq!(cursor(&core), None, "a prune resets the cursor");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sibling's cut press page whose follow-up cannot be sent (no
    /// connected sibling, budget out, or the press was lost in a restart)
    /// puts the cursor back up, so the next press asks for the rest. The
    /// follow-up window ends at `o + 1`: rows in the same ms as `o` count.
    #[test]
    fn unsent_follow_up_reopens_the_fetch_cursor() {
        let dir = std::env::temp_dir().join(format!("typeon-fetchreopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        let gid = "group-0123456789abcdef".to_string();
        core.groups.insert(gid.clone(), Group::new(gid.clone(), "g".into(), "me".into(), 1));
        let key = format!("hfetch:{gid}");
        let cursor = |core: &P2PCore| core.meta_str(&key).and_then(|v| v.parse::<u64>().ok());
        let entry = |id: &str, at: u64| SiblingHistoryEntry {
            conversation_identity_id: None, group_id: Some(gid.clone()), direction: "received".into(), text: "t".into(),
            message_id: id.into(), sender_identity_id: Some("x".into()), reply_to_message_id: None, reply_to_preview: None,
            reply_to_sender_identity_id: None, sent_at_ms: at, author_proof: None, file: None, reactions: Vec::new(),
        };
        // Press [100, 1000), cursor at 100. A cut page down to 500, budget
        // left but no sibling connected: cursor back up to 501.
        core.meta_put(&key, "100");
        core.history_fetch_pages.insert(gid.clone(), HISTORY_FETCH_MAX_PAGES);
        core.sibling_fetch_open.insert(("sib".into(), 1_000, 100), (gid.clone(), current_time_ms()));
        core.apply_sibling_reply("sib", Some((1_000, 100)), true, vec![entry("m1", 500), entry("m2", 900)]);
        assert_eq!(cursor(&core), Some(501));
        // Budget out (or lost in a restart): the same.
        core.meta_put(&key, "100");
        core.history_fetch_pages.clear();
        core.sibling_fetch_open.insert(("sib".into(), 1_000, 100), (gid.clone(), current_time_ms()));
        core.apply_sibling_reply("sib", Some((1_000, 100)), true, vec![entry("m3", 400)]);
        assert_eq!(cursor(&core), Some(401));
        // The page reached the window start: nothing left, cursor stays.
        core.meta_put(&key, "100");
        core.sibling_fetch_open.insert(("sib".into(), 1_000, 100), (gid.clone(), current_time_ms()));
        core.apply_sibling_reply("sib", Some((1_000, 100)), true, vec![entry("m4", 100)]);
        assert_eq!(cursor(&core), Some(100));
        // The echo of a press this device forgot (restart): the whole window again.
        core.apply_sibling_reply("sib", Some((1_000, 100)), false, vec![entry("m5", 300)]);
        assert_eq!(cursor(&core), Some(1_000));
        // Never lowered, and no cursor (cleared chat) stays none.
        core.apply_sibling_reply("sib", Some((600, 100)), false, vec![entry("m6", 300)]);
        assert_eq!(cursor(&core), Some(1_000));
        core.meta_del(&key);
        core.apply_sibling_reply("sib", Some((600, 100)), false, vec![entry("m7", 300)]);
        assert_eq!(cursor(&core), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// the preview is the newest by sent time even when 60 older-sent
    /// rows arrived after it (history sync).
    #[test]
    fn chat_preview_is_newest_sent_however_far_back_it_arrived() {
        let dir = std::env::temp_dir().join(format!("typeon-preview-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        let gid = "group-0123456789abcdef".to_string();
        core.groups.insert(gid.clone(), Group::new(gid.clone(), "g".into(), "me".into(), 1));
        core.archive_group_message(&gid, "x", "received", b"new", Some("n"), None, None, None, 5_000, None).unwrap();
        for i in 0..60 {
            core.archive_group_message(&gid, "x", "received", b"old", Some(&format!("o{i}")), None, None, None, 10 + i, None).unwrap();
        }
        core.db.as_ref().unwrap().execute("UPDATE messages SET timestamp = id", []).unwrap();
        let p = core.chat_list_previews();
        assert_eq!(p["groups"][&gid]["message"]["text"], "new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn storage_usage_counts_local_copies_and_removal_keeps_the_row() {
        let dir = std::env::temp_dir().join(format!("typeon-storage-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("attachments")).unwrap();
        std::fs::create_dir_all(dir.join("stickers")).unwrap();
        let mut core = core_on_disk(&dir);
        core.db.as_ref().unwrap().execute_batch(
            "INSERT INTO files (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size, sha256_hex, encrypted_file_key, key_nonce, status, created_at, duration_ms, group_id)
             VALUES ('img', 'p', 'received', 'a.jpg', 'image/jpeg', 9, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', x'00', x'00', 'complete', 1, NULL, 'g'),
                    ('voc', 'p', 'received', 'v.ogg', 'audio/ogg', 9, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', x'00', x'00', 'complete', 2, 500, 'g'),
                    ('gone', 'p', 'received', 'b.jpg', 'image/jpeg', 9, '', x'00', x'00', 'offered', 3, NULL, 'g'),
                    ('mine', 'p', 'sent', 'c.jpg', 'image/jpeg', 9, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', x'00', x'00', 'complete', 4, NULL, 'g');").unwrap();
        std::fs::create_dir_all(dir.join("attachments/plain_cache")).unwrap();
        for h in ["a", "b"] {
            std::fs::write(dir.join(format!("attachments/plain_cache/anim-{}.gif", h.repeat(64))), [0u8; 1]).unwrap();
            std::fs::write(dir.join(format!("attachments/plain_cache/first-{}.png", h.repeat(64))), [0u8; 1]).unwrap();
        }
        std::fs::write(dir.join("attachments/mine.enc"), [0u8; 50]).unwrap();
        std::fs::write(dir.join("attachments/img.enc"), [0u8; 100]).unwrap();
        std::fs::write(dir.join("attachments/voc.enc"), [0u8; 30]).unwrap();
        std::fs::write(dir.join("stickers/s.enc"), [0u8; 7]).unwrap();
        let u = core.storage_usage();
        assert_eq!((u["attachments_bytes"].as_u64(), u["voice_bytes"].as_u64(), u["stickers_bytes"].as_u64()), (Some(150), Some(30), Some(7)));
        assert_eq!((u["chats"][0]["bytes"].as_u64(), u["chats"][0]["count"].as_u64()), (Some(130), Some(2)), "no local copy / sent: not counted");
        assert!(core.remove_local_attachment("mine").is_err(), "my sent file is the only source");
        assert!(dir.join("attachments/mine.enc").exists());

        core.remove_local_attachment("img").unwrap();
        assert!(!dir.join("attachments/img.enc").exists());
        let status: String = core.db.as_ref().unwrap().query_row("SELECT status FROM files WHERE file_id = 'img'", [], |r| r.get(0)).unwrap();
        assert_eq!(status, "offered");
        assert_eq!(core.storage_usage()["chats"][0]["bytes"].as_u64(), Some(30));
        assert!(core.remove_local_attachment("nope").is_err());
        // Hash-named conversions: gone with the last copy, kept while shared.
        let cache = |h: &str| dir.join(format!("attachments/plain_cache/anim-{}.gif", h.repeat(64)));
        assert!(!cache("a").exists() && !dir.join(format!("attachments/plain_cache/first-{}.png", "a".repeat(64))).exists());
        core.remove_local_attachment("voc").unwrap();
        assert!(cache("b").exists(), "'mine' has the same content");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn big_sticker_parts_round_trip() {
        let dir = std::env::temp_dir().join(format!("typeon-stk-parts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        let whole: Vec<u8> = (0..STICKER_SYNC_MAX_BYTES * 2 + 5).map(|i| i as u8).collect();
        let id = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&whole));
        let bodies = crate::storage::sticker_echo_parts(&id, &whole, None);
        assert_eq!(bodies.len(), 3);
        let mut got = None;
        for body in bodies.into_iter().rev() {
            let SiblingEchoBody::Sticker { jxl, id, part, parts, .. } = body else { panic!() };
            got = core.add_sticker_part(&id, part, parts, jxl).unwrap();
        }
        assert_eq!(got.as_deref(), Some(&whole[..]), "out-of-order parts put back together");
        assert!(core.add_sticker_part(&id, 0, 2, vec![1]).unwrap().is_none());
        assert!(core.add_sticker_part(&id, 1, 2, vec![2]).is_err(), "wrong hash refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sticker_offer_with_known_origin_completes_locally() {
        let dir = std::env::temp_dir().join(format!("typeon-stk-origin-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("attachments/plain_cache")).unwrap();
        let mut core = core_on_disk(&dir);
        let jxl = dir.join("s.jxl");
        let mut frame = vec![200u8; 8 * 8 * 4];
        attachments::encode_jxl_sticker(std::slice::from_mut(&mut frame), 8, 8, &[], false, &jxl).unwrap();
        let wa = format!("wa:{}", "ab".repeat(32));
        let id = core.store_sticker(&jxl, false, Some(&wa)).unwrap();
        assert_eq!(core.store_sticker(&jxl, false, Some(&wa)).unwrap(), id, "same origin kept once");
        let plain = std::fs::read(&jxl).unwrap();
        assert_eq!(id, hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&plain)));

        let key = [9u8; 32];
        let offer = |core: &mut P2PCore, fid: &str, sha: &str, origin: &str| {
            core.receive_file_offer("peer", "ident", None, fid, "s.jxl", "image/jxl", 5, &key, sha, &None, None, Some(attachments::FILE_CHUNK_SIZE_V2 as u32), &[0u8; 32], "", None, None, None, true, Some(origin));
        };
        let status = |core: &P2PCore, fid: &str| -> String {
            core.db.as_ref().unwrap().query_row("SELECT status FROM files WHERE file_id = ?1", params![fid], |r| r.get(0)).unwrap()
        };
        let jid = format!("jxl:{id}");
        offer(&mut core, "known", &id, &jid);
        let (status_known, sha, total, origin): (String, String, i64, Option<String>) = core.db.as_ref().unwrap().query_row(
            "SELECT status, sha256_hex, total_size, sticker_origin FROM files WHERE file_id = 'known'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
        assert_eq!((status_known.as_str(), total as usize, origin.as_deref()), ("complete", plain.len(), Some(jid.as_str())));
        assert_eq!(sha, id);
        assert!(core.active_downloads.is_empty());
        assert!(core.attachment_events.iter().any(|e| e.contains("file_complete") && e.contains("known")));
        let (k, sha, enc, _) = core.begin_attachment_decrypt("known").unwrap();
        let out = dir.join("out.jxl");
        attachments::decrypt_file_from_disk_with(&enc, &out, &k, &sha, attachments::FILE_CHUNK_SIZE_V2).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plain);

        // A peer-claimed `wa:` id, or a `jxl:` id not matching the offer's
        // hash, is not trusted: no local copy is made.
        offer(&mut core, "wa", &"0".repeat(64), &wa);
        assert_ne!(status(&core, "wa"), "complete");
        offer(&mut core, "lie", &"0".repeat(64), &jid);
        assert_ne!(status(&core, "lie"), "complete");
        assert!(!dir.join("attachments/lie.enc").exists());
        // An earlier received attachment is not a source either.
        offer(&mut core, "other", &"1".repeat(64), &format!("jxl:{}", "1".repeat(64)));
        assert_ne!(status(&core, "other"), "complete");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sticker_conversion_survives_plain_cache_purge_encrypted() {
        let dir = std::env::temp_dir().join(format!("typeon-stk-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = core_on_disk(&dir);
        let jxl = dir.join("s.jxl");
        let mut frame = vec![120u8; 8 * 8 * 4];
        attachments::encode_jxl_sticker(std::slice::from_mut(&mut frame), 8, 8, &[], false, &jxl).unwrap();
        let id = core.store_sticker(&jxl, false, None).unwrap();
        let key = core.sticker_file_key(&id).unwrap();
        let plain = dir.join("attachments/plain_cache");
        let out = plain.join(format!("first-{id}.png"));
        let cache = dir.join("attachments/sticker_cache");

        // Convert once (as `sticker_first_frame_unlocked` does) and keep it.
        assert!(!restore_conversion(&out, "sticker-first", &id, &key));
        let tmp = core.decrypt_sticker_to_tmp(&id).unwrap();
        attachments::convert_cached(&tmp, &out, attachments::jxl_to_png).unwrap();
        std::fs::remove_file(&tmp).unwrap();
        keep_conversion(&out, "sticker-first", &id, &key);
        let png = std::fs::read(&out).unwrap();
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 1);
        let stored = std::fs::read(&conversion_cache_files(&cache, &id, |_| true)[0]).unwrap();
        assert!(!stored.starts_with(b"\x89PNG"), "stored encrypted");

        // AppLock purge: served from the encrypted copy, same bytes.
        std::fs::remove_dir_all(&plain).unwrap();
        std::fs::create_dir_all(&plain).unwrap();
        assert!(!restore_conversion(&out, "sticker-png", &id, &key), "per kind");
        assert!(restore_conversion(&out, "sticker-first", &id, &key));
        assert_eq!(std::fs::read(&out).unwrap(), png);

        // Deleting the sticker removes its cache; a wipe removes the directory.
        std::fs::remove_file(&out).unwrap();
        assert!(!restore_conversion(&out, "sticker-first", &id, &[7u8; 32]), "another key does not open it");
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0, "an unreadable copy is dropped");
        std::fs::write(&out, &png).unwrap();
        keep_conversion(&out, "sticker-first", &id, &key);
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 1);
        core.delete_sticker(&id, false).unwrap();
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0);
        core.wipe_all_local_state();
        assert!(!cache.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::{RateVerdict, RATE_LIMIT_MAX_ESTABLISHED, RATE_LIMIT_MAX_PER_WINDOW};

    /// Delivery guarantee (the user asked that every message be received): if an unknown peer exceeds the cap, the packet is DROPPED. That is our
    /// main protection against the cost of signature verification. But if a peer with a verified identity and an established session exceeds
    /// the cap, the packet is NOT dropped; it is DEFERRED. This prevents losing the queued messages of a peer that was offline for a week.
    /// This test locks the relationship between the constants. The decision logic itself lives in `rate_verdict`, and it needs a `P2PCore`,
    /// so it cannot run here.
    #[test]
    fn established_peers_get_a_far_higher_ceiling() {
        assert!(
            RATE_LIMIT_MAX_ESTABLISHED > RATE_LIMIT_MAX_PER_WINDOW,
            "kurulmus oturumu olan es daha genis bir tavan almali"
        );
        // 600 per 10-second window is 60 per second. That is plenty to catch up on a backed-up queue.
        assert!(RATE_LIMIT_MAX_ESTABLISHED >= 600);
    }

    /// The three outcomes must stay distinct. If "defer" and "drop" were treated as the same thing, the whole fix would be meaningless.
    #[test]
    fn defer_is_not_drop() {
        assert_ne!(RateVerdict::Defer, RateVerdict::Drop);
        assert_ne!(RateVerdict::Allow, RateVerdict::Defer);
    }
}

#[cfg(test)]
mod path_safety_tests {
    use super::{is_safe_file_id, safe_extension};

    /// `FileOffer.file_id` comes from the remote peer and becomes a file path. When these checks pass,
    /// `enc_path_for` cannot leave the directory.
    #[test]
    fn traversal_shaped_file_ids_are_rejected() {
        assert!(!is_safe_file_id("../identity_secret"));
        assert!(!is_safe_file_id("../../history_key"));
        assert!(!is_safe_file_id("a/b"));
        assert!(!is_safe_file_id("a\\b"));
        assert!(!is_safe_file_id(".."));
        assert!(!is_safe_file_id(""));
        assert!(!is_safe_file_id(&"x".repeat(129)));
    }

    /// Our own ids (UUIDs) must pass. Otherwise every file attachment would break.
    #[test]
    fn our_own_uuids_still_pass() {
        assert!(is_safe_file_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_safe_file_id("bl_abc123"));
    }

    /// The plaintext cache path is built as `{file_id}{ext}`, and `ext` comes from the remote peer's file name.
    #[test]
    fn extensions_cannot_carry_path_separators() {
        assert_eq!(safe_extension("photo.jpg"), ".jpg");
        assert_eq!(safe_extension("x./../../y"), "");
        assert_eq!(safe_extension("no-dot"), "");
        assert_eq!(safe_extension("weird."), "");
        assert_eq!(safe_extension("a.verylongextensionname"), "");
    }
}

#[cfg(test)]
mod delivery_ack_coverage_tests {
    /// Every content type that requires confirmation must trigger an Ack path on receipt. A receive arm without `send_ack` would make the sender retry for up to 7 days.
    /// The test scans the source (like `wipe_coverage_tests`, because `P2PCore` cannot be built here). Each arm calls `send_ack(` directly or is on the exemption list
    /// (another path provides the Ack).
    #[test]
    fn reaction_receive_arm_sends_an_ack() {
        let src = crate::CORE_SRC;

        // The `Reaction` arm of `receive_message` is destructured in a specific pattern. The send side writes its fields with `:`
        // (`let content = MessageContent::Reaction {\n  target_...:`), while the receive arm uses `, ` on one line. The pattern is built
        // from fragments so that this test block does not contain the pattern itself and confuse its own `find`.
        let arm_pat = ["MessageContent::Reaction { target_message_id,",
                       " emoji, group_id, reacted_at_ms } =>"].concat();
        let arm_start = src.find(&arm_pat)
            .expect("Reaction receive arm not found — did the destructure change?");
        let after = &src[arm_start + arm_pat.len()..];
        let arm_end = after.find("MessageContent::").unwrap_or(after.len());
        let arm_body = &after[..arm_end];

        assert!(
            arm_body.contains("self.send_ack("),
            "receive_message's `Reaction` arm does not call `send_ack`. `Reaction` \
             is on the `needs_delivery_confirmation` list, so the sender retries it \
             until confirmed (7 days) + writes it to `pending_durable_retries` — even if a \
             reaction is applied on the receiver, it hangs on the sender forever \
             (see the 2026-09-07 two-device test finding)."
        );
    }
}

#[cfg(test)]
mod keepalive_wire_tests {
    use super::*;

    fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    #[derive(Serialize, Deserialize)]
    struct OldResponse;

    /// Old peers send and expect the unit struct; the hint is optional.
    #[test]
    fn keepalive_response_stays_wire_compatible() {
        assert_eq!(cbor(&KeepAliveResponse { quiet_ms: None }), cbor(&OldResponse), "no hint = old bytes");
        let from_old: KeepAliveResponse = ciborium::from_reader(cbor(&OldResponse).as_slice()).unwrap();
        assert_eq!(from_old.quiet_ms, None);
        let hinted: KeepAliveResponse = ciborium::from_reader(cbor(&KeepAliveResponse { quiet_ms: Some(240_000) }).as_slice()).unwrap();
        assert_eq!(hinted.quiet_ms, Some(240_000));
    }
}

#[cfg(test)]
mod fanout_staleness_tests {
    use super::*;

    fn dev(fp: &str, last_seen: u64) -> DeviceRecord {
        DeviceRecord {
            device_fingerprint: fp.into(), identity_id: "id".into(),
            sign_pubkey_ed25519: vec![], sign_pubkey_mldsa: vec![], kem_pubkey_x25519: vec![], kem_pubkey_mlkem: vec![],
            device_name: String::new(), is_active: true, last_seen,
        }
    }

    /// `last_seen` must be refreshed, so the device filter for invites does not drop live devices.
    #[test]
    fn stale_devices_are_skipped_but_never_everyone() {
        let mut core = P2PCore::new();
        let old = current_time_ms() - STALE_PEER_RETRY_HORIZON_MS - 1;
        core.known_remote_devices.insert("dead".into(), dev("dead", old));
        core.known_remote_devices.insert("live".into(), dev("live", old));
        let mut all = core.fanout_targets("dead");
        all.sort();
        assert_eq!(all, vec!["dead".to_string(), "live".to_string()], "all stale: everyone, not just the primary");
        core.touch_device_seen("live");
        assert_eq!(core.fanout_targets("dead"), vec!["live".to_string()], "a packet from live makes dead skippable");
    }
}

#[cfg(test)]
mod unknown_inbound_tests {
    use super::{unknown_inbound_to_close, MAX_UNKNOWN_INBOUND, UNKNOWN_INBOUND_GRACE_MS};
    #[test]
    fn unknown_peers_hold_16_slots_for_2_minutes() {
        let now = 10 * UNKNOWN_INBOUND_GRACE_MS;
        // 20 fresh connections, ids in order of arrival: the 4 newest go.
        let fresh: Vec<(u64, u64)> = (0..20).map(|i| (i, now - 1000 + i)).collect();
        assert_eq!(unknown_inbound_to_close(fresh, now), vec![16, 17, 18, 19]);
        assert_eq!(MAX_UNKNOWN_INBOUND, 16);
        // One that outlived the grace time goes, the one inside it stays.
        let old = vec![(1u64, now - UNKNOWN_INBOUND_GRACE_MS - 1), (2, now - UNKNOWN_INBOUND_GRACE_MS)];
        assert_eq!(unknown_inbound_to_close(old, now), vec![1]);
    }
}

#[cfg(test)]
mod conn_path_rank_tests {
    use super::conn_path_rank;
    #[test]
    fn onion_beats_clearnet_and_relay() {
        let r = |s: &str| conn_path_rank(&s.parse().unwrap());
        let peer = "12D3KooWKyUGW1BQhQRTn6gGcidXMotu34zMsfodWjAZD6ebL1Uv";
        // Onion-only: the direct clearnet path is now the lowest (0), and never ranks above onion.
        assert_eq!(r(&format!("/ip4/192.168.1.103/tcp/42611/p2p/{peer}")), 0);
        assert_eq!(r(&format!("/dns/abc.onion/tcp/42611/p2p/{peer}")), 1);
        assert_eq!(r("/ip4/127.0.0.1/tcp/47420"), 1); // inbound over our onion service
        assert_eq!(r(&format!("/dns/abc.onion/tcp/42612/p2p/{peer}/p2p-circuit/p2p/{peer}")), 0);
        assert_eq!(r(&format!("/p2p/{peer}")), 0); // inbound relayed
    }

    #[test]
    fn onion3_is_an_onion_address() {
        use super::is_onion_multiaddr;
        let a: libp2p::Multiaddr = "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234".parse().unwrap();
        assert!(is_onion_multiaddr(&a));
        assert!(is_onion_multiaddr(&"/dns/abc.onion/tcp/1".parse().unwrap()));
        assert!(!is_onion_multiaddr(&"/ip4/10.0.0.1/tcp/1".parse().unwrap()));
    }

    #[test]
    fn extract_peer_id_takes_the_circuit_target() {
        let relay = "12D3KooWMYisTLof89ck4L5WmcZEQwDpZ1z85fzrBuxbf3k9pySd";
        let peer = "12D3KooWKyUGW1BQhQRTn6gGcidXMotu34zMsfodWjAZD6ebL1Uv";
        let a: libp2p::Multiaddr = format!("/dns/x.onion/tcp/42612/p2p/{relay}/p2p-circuit/p2p/{peer}").parse().unwrap();
        assert_eq!(super::extract_peer_id(&a).unwrap().to_string(), peer);
    }
}

#[cfg(test)]
mod at_rest_tests {
    use super::*;

    /// Queued outgoing content goes through `seal_local_blob`; rows written
    /// before that (plain CBOR) must still load.
    #[test]
    fn peer_prekey_needs_the_device_signature_and_does_not_go_back() {
        let (mut a, mut b) = (P2PCore::new(), P2PCore::new());
        let (b_fp, _) = b.generate_identity("B".into()).unwrap();
        let device = b.own_devices[&b_fp].clone();
        let make = |id: u64| {
            let keys = &b.own_device_keys[&b_fp];
            let (x, m) = (vec![9u8; 32], device.kem_pubkey_mlkem.clone());
            let input = packet::prekey_signing_input(&b_fp, id, &x, &m);
            let c: Ed25519Signature = keys.sign_sk_ed25519.sign(&input);
            let pq: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&input);
            SignedPrekey {
                id, kem_pubkey_x25519: x, kem_pubkey_mlkem: m,
                signature: c.to_bytes().to_vec(), signature_pq: pq.encode().to_vec(),
            }
        };
        a.store_peer_prekey(&b_fp, &make(20), &device, false);
        assert_eq!(a.peer_prekeys[&b_fp].id, 20);
        // An older one from a replayed packet does not replace it...
        a.store_peer_prekey(&b_fp, &make(10), &device, false);
        assert_eq!(a.peer_prekeys[&b_fp].id, 20);
        // one from an accepted HandshakeInit does.
        a.store_peer_prekey(&b_fp, &make(10), &device, true);
        assert_eq!(a.peer_prekeys[&b_fp].id, 10);
        // Keys the device did not sign are refused.
        let mut forged = make(30);
        forged.kem_pubkey_x25519 = vec![1u8; 32];
        a.store_peer_prekey(&b_fp, &forged, &device, true);
        assert_eq!(a.peer_prekeys[&b_fp].id, 10);
        // The ids are in what a HandshakeInit signs.
        assert_ne!(handshake_signing_input(b"x", b"k", b"c", 1, "r", 0, 0), handshake_signing_input(b"x", b"k", b"c", 1, "r", 7, 0));
        assert_ne!(handshake_signing_input(b"x", b"k", b"c", 1, "r", 0, 0), handshake_signing_input(b"x", b"k", b"c", 1, "r", 0, 7));
        // Without the storage key (and a database) no prekey is handed out:
        // its secret could not be kept.
        assert!(b.current_own_prekey().is_none());
    }

    #[test]
    fn duplicate_contact_rows_keep_the_one_with_the_most_devices() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE contacts (contact_id TEXT PRIMARY KEY, display_name TEXT, trusted_identity_id TEXT,
                known_devices_json TEXT, last_device_change INTEGER, avatar_jpeg BLOB);
             INSERT INTO contacts VALUES ('one', 'a', 'idA', '[1]', 9, NULL);
             INSERT INTO contacts VALUES ('two', 'a', 'idA', '[1,2]', 1, NULL);
             INSERT INTO contacts VALUES ('bad', 'a', 'idA', 'not json', 99, NULL);
             INSERT INTO contacts VALUES ('solo', 'b', 'idB', '[]', 0, NULL);",
        ).unwrap();
        conn.execute_batch(CONTACTS_ONE_ROW_PER_IDENTITY_SQL).unwrap();
        let left: Vec<String> = conn.prepare("SELECT contact_id FROM contacts ORDER BY contact_id").unwrap()
            .query_map([], |r| r.get(0)).unwrap().flatten().collect();
        assert_eq!(left, ["solo", "two"]);
        // And from now on the database refuses a second row.
        assert!(conn.execute("INSERT INTO contacts VALUES ('three', 'a', 'idA', '[]', 0, NULL)", []).is_err());
    }

    /// a revoked device of a group member who is not
    /// a contact signs rows dated after its revoke in vain.
    #[test]
    fn non_contact_revoke_dates_group_author_proofs() {
        let base = std::env::temp_dir().join(format!("typeon-orv-{}", std::process::id()));
        let mut cores: Vec<P2PCore> = (0..2).map(|i| {
            let d = base.join(i.to_string());
            std::fs::create_dir_all(&d).unwrap();
            let mut c = P2PCore::new();
            c.init_db(d.to_str().unwrap(), &[1u8; 32]).unwrap();
            c
        }).collect();
        let m = cores[1].generate_identity("m".into()).unwrap().0;
        let mut rec = cores[1].own_devices[&m].clone();
        let proof = cores[1].sign_group_author("g", "x", "t").unwrap();
        cores[0].generate_identity("me".into()).unwrap();
        rec.is_active = false;
        cores[0].known_remote_devices.insert(m.clone(), rec);
        // Inactive with no revoke time: refused.
        assert!(!cores[0].group_author_proof_valid("g", "x", &m, "t", 100, Some(&proof)));
        cores[0].meta_put(&format!("orv:{m}"), &format!("{m}|1000"));
        assert!(cores[0].owner_revoked(&m, &m));
        assert!(cores[0].group_author_proof_valid("g", "x", &m, "t", 999, Some(&proof)));
        assert!(!cores[0].group_author_proof_valid("g", "x", &m, "t", 1000, Some(&proof)));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn group_author_statement_separates_its_fields() {
        // "ab"+"c" and "a"+"bc" must not sign the same bytes.
        assert_ne!(group_author_statement("ab", "c", "i", "d", "t"), group_author_statement("a", "bc", "i", "d", "t"));
        assert_ne!(group_author_statement("g", "m", "i", "d", "hello"), group_author_statement("g", "m", "i", "d", "hellp"));
        // A deletion is not the signature of an empty text.
        assert_ne!(group_author_statement("g", "m", "i", "d", ""), group_author_statement("g", "m", "i", "d", GROUP_TOMBSTONE));
        // No keys and no known device: nothing verifies.
        let core = P2PCore::new();
        assert!(!core.group_author_proof_valid("g", "m", "i", "t", 1, None));
        assert!(!core.group_author_proof_valid("g", "m", "i", "t", 1, Some("fp:00")));
        assert!(!core.group_author_proof_valid("g", "m", "i", "t", 1, Some("fp:00:00")));
    }

    #[test]
    fn queued_content_is_sealed_and_legacy_rows_still_load() {
        let mut core = P2PCore::new();
        core.skipped_key_encryption_key = Some([5u8; 32]);
        let plain = ciborium_bytes(&MessageContent::Text {
            text: "secret-marker".into(), group_id: None, group_message_local_id: None, sent_at_ms: 1,
            reply_to_message_id: None, reply_to_preview: None, reply_to_sender_identity_id: None, author_proof: None, mentions: Vec::new(),
        }).unwrap();
        let sealed = core.seal_local_blob(&plain).unwrap();
        assert!(!sealed.windows(13).any(|w| w == b"secret-marker"));
        assert_eq!(core.open_local_blob(&sealed).unwrap(), plain);
        assert!(core.open_local_blob(&plain).is_none(), "plaintext row does not open");
        let src = crate::CORE_SRC;
        for f in ["fn persist_durable_retry(", "fn persist_pending_group_message("] {
            let body = &src[src.find(f).unwrap()..];
            assert!(body[..body.find("\n    }").unwrap()].contains("seal_local_blob"), "{f} must seal");
        }
    }
}

#[cfg(test)]
mod peer_mapping_tests {
    fn body<'a>(src: &'a str, start: &str) -> &'a str {
        let at = src.find(start).expect("fn not found");
        let body = &src[at..];
        &body[..body[1..].find("\n    }\n").map_or(body.len(), |i| i + 1)]
    }

    /// See `record_peer_id_if_known`'s callers: an unsigned IdentityExchange or
    /// a not-yet-decrypted packet must never map a device to the sender's PeerId.
    #[test]
    fn device_is_mapped_only_after_proof() {
        let src = crate::CORE_SRC;
        let call = ["self.record_peer_id_if_known", "(source"].concat();
        assert!(!body(src, &["fn process_identity_", "exchange(&mut self"].concat()).contains(&call));
        let recv = body(src, &["fn receive_", "message(&mut self, source"].concat());
        let decrypt = recv.find("state.decrypt(").expect("decrypt call");
        assert!(recv.find(&call).expect("mapping call") > decrypt, "map only after the packet decrypted");
    }
}

#[cfg(test)]
mod repair_identity_exchange_tests {
    /// A contact re-added within 12 hours sends an IdentityExchange byte-identical to the previous one, which the server's dedup would swallow.
    /// A pairing the user starts must clear that dedup (`send_identity_exchange_fresh`). So must the reply to a peer that (re)added us (`process_identity_exchange`, `!we_initiated`).
    #[test]
    fn pairing_paths_send_a_fresh_identity_exchange() {
        let src = crate::CORE_SRC;
        let fresh_call = ["self.send_identity_exchange", "_fresh("].concat();
        for start in [["fn pair_with_code", "(&mut self"], ["fn approve_device_link", "(&mut self"]] {
            let at = src.find(&start.concat()).expect("pairing fn not found");
            let body = &src[at..src.floor_char_boundary((at + 20000).min(src.len()))];
            let body = &body[..body[1..].find("\n    }\n").map_or(body.len(), |i| i + 1)];
            assert!(body.contains(&fresh_call), "{} must use send_identity_exchange_fresh", start[0]);
        }
    }
}

#[cfg(test)]
mod authz_coverage_tests {
    /// Each of the arms below leaked data or allowed identity takeover without an authority check.
    /// `P2PCore` cannot be built here, so the source is scanned (see `wipe_coverage_tests`).
    fn body_of<'a>(src: &'a str, start_parts: &[&str], len: usize) -> &'a str {
        let pat = start_parts.concat();
        let at = src.find(&pat).unwrap_or_else(|| panic!("not found: {pat}"));
        let end = (at + len).min(src.len());
        &src[at..src.floor_char_boundary(end)]
    }

    #[test]
    fn sensitive_arms_keep_their_guards() {
        let src = crate::CORE_SRC;
        let cases: &[(&[&str], usize, &str)] = &[
            (&["MessageContent::HistorySyncRequest { limit,", " before_timestamp, group_id, after_timestamp } =>"], 5000, "is_member(&sender_identity_id)"),
            (&["MessageContent::HistorySyncResponse { request_id,", " messages, group_id, more } =>"], 4000, "outstanding_history_requests.get("),
            (&["MessageContent::HistorySyncResponse { request_id,", " messages, group_id, more } =>"], 4000, "history_answered_by.get("),
            (&["fn adopt_device_link", "(&mut self"], 5000, "link_request_open_until"),
            // Without a signed DeviceAdd the identity claim must be bound to
            // the device, and nobody may claim my own identity.
            (&["fn process_identity_exchange", "(&mut self"], 20000, "!Self::identity_proved_by_root(exchange)"),
            (&["fn process_identity_exchange", "(&mut self"], 20000, "if my_id.as_deref() == Some(exchange.identity_id.as_str()) {"),
            (&["MessageContent::Seen { target_message_id,", " group_message_local_id } =>"], 5000, "may_mark_seen("),
            (&["fn process_handshake_init", "(&mut self"], 5000, "&recipient_fp,"),
            (&["fn remove_from_group", "(&mut self"], 1500, "is_member(member_identity_id)"),
            (&["fn verify_founder_transfer", "(&self"], 1500, "!signer.is_active"),
            (&["fn heal_founder_chain", "(&self"], 1500, "t.version > floor"),
            (&["MessageContent::Reaction { target_message_id,", " emoji, group_id, reacted_at_ms } =>"], 3000, "reaction_fits_chat("),
            (&["fn apply_edit_or_delete_content", "(&mut self"], 1500, "ex_member"),
        ];
        for (start, len, guard) in cases {
            assert!(
                body_of(src, start, *len).contains(guard),
                "{:?} arm has no `{}` authority check",
                start.concat(),
                guard
            );
        }
    }

    /// `touch_device_seen` may send (parked rows of a
    /// stale device). Before the decrypted state is on disk, a failed write
    /// rolled memory back behind those sends and the next message reused
    /// their message keys.
    #[test]
    fn receive_sends_nothing_before_the_ratchet_is_saved() {
        let src = crate::CORE_SRC;
        let body = body_of(src, &["fn receive_message", "(&mut self"], 40000);
        let saved = body.find("drop(snapshot);").expect("drop(snapshot) not found");
        let touch = body.find(&["self.touch_device_seen", "(&packet.header"].concat()).expect("touch_device_seen not found");
        assert!(touch > saved, "touch_device_seen runs before the ratchet state is saved");
    }
}

#[cfg(test)]
mod review5_tests {
    use super::*;

    fn core_on_disk(name: &str) -> (P2PCore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("typeon-r5-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = P2PCore::new();
        core.init_db(dir.to_str().unwrap(), &[1u8; 32]).unwrap();
        core.history_key = Some([2u8; 32]);
        core.skipped_key_encryption_key = Some([3u8; 32]);
        (core, dir)
    }

    /// An edit or delete of a row in a group not held yet (its GroupUpdate
    /// is still on the way) is applied, like the Text it targets; in a group
    /// we left it is not.
    #[test]
    fn group_edit_in_a_group_not_held_yet_is_applied() {
        let (mut core, dir) = core_on_disk("edit");
        let gid = "group-0123456789abcdef";
        let author = "ab".repeat(32);
        let m1 = format!("{}-1", hex::encode(group_msg_tag(gid, &author, "-1")));
        core.archive_group_message(gid, &author, "received", b"old", Some(&m1), None, None, None, 5, None).unwrap();
        // Another member may not edit it: the id carries the author's tag.
        let other = MessageContent::Edit { target_message_id: m1.clone(), new_text: "x".into(), group_id: Some(gid.into()), edited_at_ms: 9, author_proof: None };
        assert_eq!(core.apply_edit_or_delete_content("fp", &"cd".repeat(32), "p0", other)["type"], "noop");
        let edit = MessageContent::Edit { target_message_id: m1.clone(), new_text: "new".into(), group_id: Some(gid.into()), edited_at_ms: 10, author_proof: None };
        assert_eq!(core.apply_edit_or_delete_content("fp", &author, "p1", edit)["type"], "group_edit");
        core.remove_group_locally(gid);
        let delete = MessageContent::Delete { target_message_id: m1, group_id: Some(gid.into()), author_proof: None };
        assert_eq!(core.apply_edit_or_delete_content("fp", &author, "p2", delete)["type"], "noop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A group file id (the server blob id) carries its author's tag, so
    /// members can check who may offer it.
    #[test]
    fn group_file_id_carries_the_author_tag() {
        let rest = server_proto::blob_id_hash_hex(&[1u8; 16]);
        let mut secret = group_msg_tag("g", "a", &rest).to_vec();
        secret.extend_from_slice(&[1u8; 16]);
        let id = server_proto::blob_id_for_upload_secret(&secret).unwrap();
        // another file of the same author shows another tag.
        assert_ne!(group_msg_tag("g", "a", &rest), group_msg_tag("g", "a", &server_proto::blob_id_hash_hex(&[2u8; 16])));
        assert!(group_msg_id_bound("g", "a", &id));
        assert!(!group_msg_id_bound("g", "b", &id));
        assert!(!group_msg_id_bound("h", "a", &id));
        assert!(!group_msg_id_bound("g", "a", &hex::encode(group_msg_tag("g", "a", ""))), "tag alone is no id");
        assert!(!group_reply_bound("g", Some(&id), Some("b")));
        assert!(group_reply_bound("g", Some(&id), None));
    }

    /// A 1:1 row is owned by the identity whose chat it is in, not by any
    /// sender that names that chat key.
    #[test]
    fn one_to_one_ownership_needs_the_chat_identity() {
        let (mut core, dir) = core_on_disk("own");
        let (mut p, dp) = core_on_disk("own-p");
        let (mut q, dq) = core_on_disk("own-q");
        let pid = p.generate_identity("p".into()).unwrap().0;
        let qid = q.generate_identity("q".into()).unwrap().0;
        for rec in [p.own_devices[&pid].clone(), q.own_devices[&qid].clone()] {
            core.known_remote_devices.insert(rec.device_fingerprint.clone(), rec);
        }
        core.archive_message(&pid, "received", b"hi", Some("m1"), None, None, None, 5).unwrap();
        assert!(core.message_owned_by_sender(None, &pid, &pid, "m1"));
        assert!(!core.message_owned_by_sender(None, &pid, &qid, "m1"));
        for d in [dir, dp, dq] { let _ = std::fs::remove_dir_all(&d); }
    }

    /// The packet a rotation arrives with may be the answer to a pending
    /// one: that one is not resent on the new chain.
    #[test]
    fn a_history_answer_names_the_request_it_closes() {
        let answer = MessageContent::HistorySyncResponse { request_id: "r1".into(), messages: vec![], group_id: Some("g".into()), more: false };
        assert_eq!(answered_pending_id(&ciborium_bytes(&answer).unwrap()).as_deref(), Some("r1"));
        let ack = MessageContent::Ack { target_message_id: "t1".into() };
        assert_eq!(answered_pending_id(&ciborium_bytes(&ack).unwrap()).as_deref(), Some("t1"));
        let typing = MessageContent::TypingIndicator { is_typing: true, group_id: None };
        assert_eq!(answered_pending_id(&ciborium_bytes(&typing).unwrap()), None);
    }
}

#[cfg(test)]
mod fable_review_tests {
    use super::*;

    /// a second failing item of the same mailbox waits behind
    /// the first and does not restart its hold timer.
    #[test]
    fn two_failing_server_items_do_not_reset_each_other() {
        let mut core = P2PCore::new();
        core.server_rt.insert("s".into(), Default::default());
        let t0 = 1_000_000;
        assert!(core.hold_server_item("s", "mb", 5, t0));
        assert!(core.hold_server_item("s", "mb", 7, t0 + 10));
        let late = t0 + crate::server_client::SERVER_HOLD_GRACE_MS + 1;
        assert!(!core.hold_server_item("s", "mb", 5, late));
        assert!(core.server_rt["s"].passed.contains(&("mb".to_string(), 5)));
        // The next item starts its own timer now.
        assert!(core.hold_server_item("s", "mb", 7, late));
    }

    /// a code naming a known Active device lifts no block and
    /// stores no address.
    #[test]
    fn code_for_a_known_device_changes_nothing() {
        let mut core = P2PCore::new();
        let (id, fp) = ("a".repeat(64), "b".repeat(64));
        core.register_contact_from_pairing(id.clone(), fp.clone(), "Bob".into()).unwrap();
        core.block_identity(&id).unwrap();
        let addr = "/dns/x.onion/tcp/1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";
        core.pair_with_code(id.clone(), fp.clone(), "Eve", addr, &[], &[7u8; 16]).unwrap();
        assert!(core.is_blocked(&id));
        assert!(!core.device_last_addr.contains_key(&fp));
        let cid = core.identity_to_contact[&id].clone();
        assert_eq!(core.contacts[&cid].display_name, "Bob");
    }

    /// stored sessions that all fail to open (wrong key) keep
    /// the send gate shut; the right key opens it.
    #[test]
    fn wrong_storage_key_keeps_the_send_gate_shut() {
        let dir = std::env::temp_dir().join(format!("typeon-gate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = P2PCore::new();
        core.init_db(dir.to_str().unwrap(), &[1u8; 32]).unwrap();
        core.db.as_ref().unwrap().execute(
            "INSERT INTO ratchet_states (peer_device_fingerprint, encrypted_state, nonce, updated_at) VALUES ('p', x'00112233445566778899aabbccddeeff', x'000000000000000000000000', 1)",
            [],
        ).unwrap();
        core.install_skipped_key([9u8; 32]);
        assert!(!core.ratchets_loaded);
        core.db.as_ref().unwrap().execute("DELETE FROM ratchet_states", []).unwrap();
        core.install_skipped_key([9u8; 32]);
        assert!(core.ratchets_loaded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A ring answered on a sibling stops here but the group call stays
    /// joinable ("Attend"); joining it here hides the offer.
    #[test]
    fn sibling_busy_stops_the_ring_and_the_group_call_stays_joinable() {
        use crate::packet::CallAction;
        let (mut me, mut other) = (P2PCore::new(), P2PCore::new());
        me.generate_identity("me".into()).unwrap();
        let other_fp = other.generate_identity("o".into()).unwrap().0;
        let my_id = me.my_identity_id().unwrap();
        let other_id = other.my_identity_id().unwrap();
        me.known_remote_devices.insert(other_fp.clone(), other.own_devices[&other_fp].clone());
        let gid = "group-attend-0123456789".to_string();
        let mut g = Group::new(gid.clone(), "g".into(), other_id.clone(), 1);
        g.sync_members(&[other_id.clone(), my_id.clone()], 1);
        me.groups.insert(gid.clone(), g);
        let call_id = "call-attend-1".to_string();
        let signal = |core: &mut P2PCore, fp: &str, id: &str, action| {
            core.handle_call_signal(fp, id, call_id.clone(), action, Some(gid.clone()), true, vec![1; 32], vec![2; 8], current_time_ms(), Vec::new())
        };

        signal(&mut me, &other_fp, &other_id, CallAction::Invite);
        assert!(me.call.is_some(), "rings");
        assert_eq!(me.group_call_offer(&gid), 2);

        // Answered on my other device: the ring stops, nobody missed it.
        let ev = signal(&mut me, "sibling-device", &my_id, CallAction::Busy);
        assert!(me.call.is_none());
        assert_eq!(ev["ended"], true);
        assert_eq!(ev["missed"], false);
        // A repeat Invite of the same call does not ring again, but keeps the offer.
        signal(&mut me, &other_fp, &other_id, CallAction::Invite);
        assert!(me.call.is_none());
        assert_eq!(me.group_call_offer(&gid), 2);

        // Attend: joins the running call instead of starting a new one.
        assert_eq!(me.start_group_call(gid.clone(), false).unwrap(), call_id);
        let state: serde_json::Value = serde_json::from_str(&me.call_state_json()).unwrap();
        assert_eq!(state["state"], "active");
        assert_eq!(me.group_call_offer(&gid), 0);
        // A sibling's Busy never ends a call I am in.
        signal(&mut me, "sibling-device", &my_id, CallAction::Busy);
        assert!(me.call.is_some());
        me.end_call();
        assert_eq!(me.group_call_offer(&gid), 2, "after leaving, Attend shows again");
        // Another call ending here replaces `last_call_end`: the left call's
        // re-invite still must not ring.
        me.last_call_end = Some(("some-other-call".into(), "local".into()));
        signal(&mut me, &other_fp, &other_id, CallAction::Invite);
        assert!(me.call.is_none(), "a left group call never rings again");
        assert_eq!(me.group_call_offer(&gid), 2);

        // The caller never gets an Invite of its own call: leaving it while
        // others stay still leaves an offer, from a participant's keys.
        let own_gid = "group-attend-caller-01".to_string();
        let mut g = Group::new(own_gid.clone(), "g".into(), my_id.clone(), 1);
        g.sync_members(&[other_id.clone(), my_id.clone()], 1);
        me.groups.insert(own_gid.clone(), g);
        let own_call = me.start_group_call(own_gid.clone(), false).unwrap();
        me.handle_call_signal(&other_fp, &other_id, own_call, CallAction::Accept, Some(own_gid.clone()), false, vec![3; 32], vec![4; 8], current_time_ms(), Vec::new());
        assert_eq!(me.group_call_offer(&own_gid), 0, "in the call");
        me.end_call();
        assert_eq!(me.group_call_offer(&own_gid), 1, "left, the call goes on");

        // The last participant leaves: Ended drops the offer at once, and a
        // later Invite of that call (the Ended came from someone who only lost
        // sight of the others) brings Attend back but never rings.
        signal(&mut me, &other_fp, &other_id, CallAction::Ended);
        assert_eq!(me.group_call_offer(&gid), 0);
        signal(&mut me, &other_fp, &other_id, CallAction::Invite);
        assert_eq!(me.group_call_offer(&gid), 2);
        assert!(me.call.is_none());

        // My other device joins the call: no Attend here until it leaves.
        let ev = signal(&mut me, "sibling-device", &my_id, CallAction::Joined);
        assert_eq!(me.group_call_offer(&gid), 0, "a sibling is in it");
        assert!(ev["type"] != "call");
        signal(&mut me, "sibling-device", &my_id, CallAction::Hangup);
        assert_eq!(me.group_call_offer(&gid), 2, "the sibling left");
        // Joined from anyone but my own identity does nothing.
        signal(&mut me, &other_fp, &other_id, CallAction::Joined);
        assert_eq!(me.group_call_offer(&gid), 2);

        // Ended also stops a ring of that call.
        let ring = "call-attend-2".to_string();
        me.handle_call_signal(&other_fp, &other_id, ring.clone(), CallAction::Invite, Some(gid.clone()), true, vec![1; 32], vec![2; 8], current_time_ms(), Vec::new());
        assert!(me.call.is_some(), "rings");
        let ev = me.handle_call_signal(&other_fp, &other_id, ring, CallAction::Ended, Some(gid.clone()), true, Vec::new(), Vec::new(), current_time_ms(), Vec::new());
        assert!(me.call.is_none());
        assert_eq!(ev["ended"], true);
        assert_eq!(me.group_call_offer(&gid), 0);
    }
}

#[cfg(test)]
mod sibling_roster_tests {
    use super::*;

    fn on_disk(dir: &std::path::Path, name: &str) -> P2PCore {
        let d = dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        let mut c = P2PCore::new();
        c.init_db(d.to_str().unwrap(), &[1u8; 32]).unwrap();
        c.ratchets_loaded = true;
        c
    }

    /// A root `r`, its linked sibling `l` (same identity), and a stranger `n`.
    fn trio(dir: &std::path::Path) -> (P2PCore, P2PCore, P2PCore, String, String, String) {
        let (mut r, mut l, mut n) = (on_disk(dir, "r"), on_disk(dir, "l"), on_disk(dir, "n"));
        let root_id = r.generate_identity("r".into()).unwrap().0;
        let l_fp = l.generate_identity("l".into()).unwrap().0;
        let n_id = n.generate_identity("n".into()).unwrap().0;
        l.identity.as_mut().unwrap().identity_id = root_id.clone();
        l.own_devices.get_mut(&l_fp).unwrap().identity_id = root_id.clone();
        l.known_remote_devices.insert(root_id.clone(), r.own_devices[&root_id].clone());
        let mut l_rec = l.own_devices[&l_fp].clone();
        l_rec.identity_id = root_id.clone();
        r.known_remote_devices.insert(l_fp.clone(), l_rec);
        (r, l, n, root_id, l_fp, n_id)
    }

    /// A contact that pairs with the root after a sibling was linked: the
    /// root's roster goes to the sibling once the contact's keys are known
    /// (the sync at scan time carries no keys yet), and the sibling learns
    /// the contact from it.
    #[test]
    fn contact_paired_on_the_root_reaches_the_sibling() {
        let dir = std::env::temp_dir().join(format!("typeon-sibroster-{}", std::process::id()));
        let (mut r, mut l, mut n, root_id, l_fp, n_id) = trio(&dir);
        // n scans r's code: its IdentityExchange carries the code's proof.
        let nonce = r.issue_pairing_nonce().unwrap();
        n.put_pairing_secret("pn", &root_id, &nonce);
        let _ = n.send_identity_exchange_fresh(&root_id);
        let ix = n.pending_envelopes.iter().find_map(|q| match &q.envelope {
            NetworkEnvelope::IdentityExchange(ix) => Some(ix.clone()),
            _ => None,
        }).expect("queued IdentityExchange");
        r.process_identity_exchange(None, &ix).unwrap();
        assert!(r.identity_to_contact.contains_key(&n_id));
        assert!(r.pending_envelopes.iter().any(|q| q.target == l_fp) || r.awaiting_confirmation.values().any(|p| p.peer_device_fingerprint == l_fp),
            "the roster with the new contact's keys goes to the sibling");
        let mut learned = Vec::new();
        for p in r.build_sync_payloads() { learned.extend(l.import_sync_payload(&p)); }
        assert_eq!(learned, vec![n_id.clone()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A contact removed on the sibling and paired again on the root comes
    /// back on the sibling with the next roster; a removal after that pairing
    /// wins over a roster copy made before it.
    #[test]
    fn pairing_again_lifts_a_siblings_removed_marker_but_a_later_delete_wins() {
        let dir = std::env::temp_dir().join(format!("typeon-sibremoved-{}", std::process::id()));
        let (mut r, mut l, n, _root_id, _l_fp, n_id) = trio(&dir);
        let n_rec = n.own_devices[&n_id].clone();
        // The sibling had the contact and the user deleted it there.
        l.known_remote_devices.insert(n_id.clone(), n_rec.clone());
        l.register_contact_from_pairing(n_id.clone(), n_id.clone(), "n".into()).unwrap();
        let cid = l.identity_to_contact[&n_id].clone();
        l.delete_contact(&cid, false).unwrap();
        assert!(l.contact_removed_locally(&n_id));
        std::thread::sleep(std::time::Duration::from_millis(3));
        // The root pairs again by scanning n's code; then n's keys arrive.
        r.pair_with_code(n_id.clone(), n_id.clone(), "n", "", &[], &[5; 16]).unwrap();
        r.known_remote_devices.insert(n_id.clone(), n_rec);
        let roster = r.build_sync_payloads();
        let mut learned = Vec::new();
        for p in &roster { learned.extend(l.import_sync_payload(p)); }
        assert_eq!(learned, vec![n_id.clone()]);
        assert!(!l.contact_removed_locally(&n_id));
        // Scanning the code of a device the root already lists as active is a
        // new pairing too (the early return in `pair_with_code`).
        let first = r.contact_added_at(&n_id);
        std::thread::sleep(std::time::Duration::from_millis(3));
        r.pair_with_code(n_id.clone(), n_id.clone(), "n", "", &[], &[6; 16]).unwrap();
        assert!(r.contact_added_at(&n_id) > first);

        // Deleted again on the sibling, after that pairing: the same (older)
        // roster copy no longer brings it back.
        std::thread::sleep(std::time::Duration::from_millis(3));
        let cid = l.identity_to_contact[&n_id].clone();
        l.delete_contact(&cid, false).unwrap();
        for p in &roster { assert!(l.import_sync_payload(p).is_empty()); }
        assert!(!l.identity_to_contact.contains_key(&n_id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sibling's newer copy of a group updates the stale one here; an
    /// older copy does not roll it back.
    #[test]
    fn sibling_sync_updates_a_stale_group_but_never_rolls_it_back() {
        let dir = std::env::temp_dir().join(format!("typeon-sibgroup-{}", std::process::id()));
        let (mut r, mut l, _n, root_id, _l_fp, n_id) = trio(&dir);
        let taba = "a".repeat(64);
        let gid = "group-0123456789abcdef".to_string();
        let mut g = Group::new(gid.clone(), "g".into(), n_id.clone(), 1);
        g.sync_members(&[n_id.clone(), root_id.clone()], 1);
        g.version = 1;
        l.groups.insert(gid.clone(), g.clone());
        let mut newer = g.clone();
        newer.sync_members(&[n_id.clone(), root_id.clone(), taba.clone()], 2);
        newer.version = 2;
        r.groups.insert(gid.clone(), newer);
        for p in r.build_sync_payloads() { l.import_sync_payload(&p); }
        assert_eq!(l.groups[&gid].version, 2);
        assert!(l.groups[&gid].is_member(&taba));
        // r's copy is older now: l keeps its own.
        r.groups.insert(gid.clone(), g);
        for p in r.build_sync_payloads() { l.import_sync_payload(&p); }
        assert_eq!(l.groups[&gid].version, 2);
        assert!(l.groups[&gid].is_member(&taba));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
