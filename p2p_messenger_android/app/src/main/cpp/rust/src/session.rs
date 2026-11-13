//! Connections, prekeys, handshakes and ratchet rotation.

use super::*;

impl P2PCore {

    /// Starts the handshake proactively when the user opens a chat, before any message is typed. Before, the handshake only started lazily on the
    /// first `sendMessage` call. That left a window where the user opened a chat, typed, and sent with no connection indicator, so the message could
    /// be lost. No-op if a session already exists.
    pub(crate) fn ensure_handshake(&mut self, peer_device_fingerprint: &str) -> Result<(), String> {
        // Even with a session: if no live connection exists right now, try to reconnect at once, without waiting for the next `reconnect_sweep`
        // round (up to 15 s). This is the fastest recovery when a chat is opened or before a message.
        // Forced: the chat is on screen (or was just unblocked), so a wait left by a failed sweep must not hold it back. The send path stays gated:
        // automatic retries go through it too.
        self.try_reconnect_device(peer_device_fingerprint, true);
        if self.has_active_session(peer_device_fingerprint) {
            return Ok(());
        }
        self.initiate_handshake_with(peer_device_fingerprint)
    }

    /// If there is no LIVE libp2p connection to the given device AND we have a stored address hint, starts reconnecting at once (synchronously, without
    /// waiting for the sweep). No-op if it is connected or there is no address. Called from `ensure_handshake` and the send path, to reconnect a dropped
    /// contact immediately.
    ///
    /// See `try_reconnect_device`: there is deliberately NO `known_remote_devices`/Active filter here. This must work for a device that was JUST paired
    /// (its IdentityExchange has not completed yet), otherwise the first pairing could never make a real connection. The user is sent to ChatActivity,
    /// which waits for exactly the connection this function starts.
    pub(crate) fn ensure_connected(&mut self, device_fingerprint: &str) {
        self.try_reconnect_device(device_fingerprint, false);
    }

    /// The shared, backoff-aware dial logic for one device: used by `ensure_connected`, by the periodic `reconnect_sweep` (all known devices), and now by
    /// the immediate single-device reconnect triggered by `ping`/`ConnectionClosed` events (see `poll_events`). It is battery-friendly (see
    /// `RECONNECT_BACKOFF_*`) and prevents dial storms: calls from several triggers in a short time (message send, periodic scan, ping error) share the
    /// same backoff state, so they do not dial over each other.
    ///
    /// "Is this device known/active" filtering is deliberately NOT done here. Callers have different needs (see the `ensure_connected` docs). This
    /// function ONLY checks: is there an address hint, is it connected right now, and has the backoff window passed. Then it dials.
    ///
    /// `force=true` (a network change notification, see `reconnect_all_known_now`, and `ensure_handshake`) IGNORES `reconnect_backoff`. An interface
    /// change (Wi-Fi to cellular) makes the backoff history from the OLD network meaningless, so the first try on the new interface should always happen at once.
    ///
    /// Returns `true` if a dial was really attempted. `false` if it was already connected, there was no address, or the backoff skipped it.
    pub(crate) fn try_reconnect_device(&mut self, fp: &str, force: bool) -> bool {
        // See `blocked_identities`: a blocked contact is NEVER connected to.
        if self.is_blocked_device(fp) {
            return false;
        }
        // It said it is going offline (keepalive `bye`); it dials us when back.
        if self.meta_str(&format!("parked:{}", fp)).is_some() {
            return false;
        }
        let now = current_time_ms();
        // Network robustness fix (see the `device_onion_addr` field docs; the bug was: "a device paired over Tor on the same LAN can no longer talk to the
        // other phone once it switches to mobile data"). Before, this used ONLY `device_last_addr`, the last address that worked. That could be a LAN
        // address written over a LAN connection. Now the `.onion` address is also read from `device_onion_addr`, which is kept SEPARATE and is never
        // overwritten. If the two differ, BOTH are tried at the same time. Whichever is still valid after the network change succeeds.
        let primary_str = self.device_last_addr.get(fp).cloned();
        let onion_str = self.device_onion_addr.get(fp).cloned().filter(|o| Some(o) != primary_str.as_ref());
        // A group founder's hint (`vah:`), only while nothing better is known.
        let primary_str = match (primary_str, &onion_str) {
            (None, None) => self.meta_str(&format!("vah:{}", fp)),
            (p, _) => p,
        };
        if primary_str.is_none() && onion_str.is_none() {
            return false;
        }
        let primary_addr = primary_str.as_deref().and_then(|s| s.parse::<Multiaddr>().ok());
        let onion_addr = onion_str.as_deref().and_then(|s| s.parse::<Multiaddr>().ok());
        // The PeerId must be the SAME whichever address it is extracted from (both belong to the same device). It is taken from whichever is present or parseable.
        let peer_id = match primary_addr.as_ref().or(onion_addr.as_ref()).and_then(extract_peer_id) {
            Some(p) => p,
            None => return false,
        };
        let connected = self.swarm.as_ref().map(|s| s.is_connected(&peer_id)).unwrap_or(false);
        if connected {
            // See the `reconnect_backoff` docs. If the connection was somehow set up already, reset the backoff history, so the next drop starts again
            // from zero (quickly).
            self.reconnect_backoff.remove(fp);
            return false;
        }
        if !force {
            if let Some(&(next_allowed_at, _)) = self.reconnect_backoff.get(fp) {
                // A wait set in saver mode can be hours long; once the app is
                // on screen again it must not outlast the normal cap.
                let wait_cap = if self.radio_saver() { RECONNECT_BACKOFF_SAVER_MAX_MS } else { RECONNECT_BACKOFF_MAX_MS };
                if now < next_allowed_at && next_allowed_at - now <= wait_cap {
                    return false;
                }
            }
        }
        // Fix (reconnect after a network change was delayed by minutes): `force=true` skipped the gate above (around line 3688), but the `attempts` counter
        // still continued from the value accumulated on the OLD network. So a single forced try that failed (right after an interface change, or if the peer's
        // address also changed, which is quite likely) wrote a backoff entry one step HIGHER than before (up to `RECONNECT_BACKOFF_MAX_MS`, 10 min). That
        // blocked ALL later automatic reconnect paths (periodic `reconnect_sweep`, ping failure) for minutes: exactly the scenario `force` is meant to prevent.
        // With `force`, the counter ALWAYS starts at 1. The reasoning "backoff history from the old network is meaningless" (see the function docs above) must
        // cover the NEXT wait time, not only the gate.
        let attempts = if force {
            1
        } else {
            self.reconnect_backoff.get(fp).map(|&(_, n)| n).unwrap_or(0) + 1
        };
        // attempts=1 -> base * 2^0 (= RECONNECT_SWEEP_INTERVAL_MS, the same speed as a normal scan, no extra wait). attempts=2 -> 2x, attempts=3 -> 4x, ...
        // capped at `RECONNECT_BACKOFF_MAX_MS`.
        let delay = RECONNECT_BACKOFF_BASE_MS
            .saturating_mul(1u64 << attempts.saturating_sub(1).min(16))
            .min(if self.radio_saver() { RECONNECT_BACKOFF_SAVER_MAX_MS } else { RECONNECT_BACKOFF_MAX_MS });
        self.reconnect_backoff.insert(fp.to_string(), (now + delay, attempts));
        info!(
            "try_reconnect_device: kopmuş peer'a yeniden bağlanılıyor (deneme #{}, force={}, onion adayı={}): {}",
            attempts, force, onion_addr.is_some(), crate::log_id(&peer_id)
        );
        // `dial_with_relay_fallback` already tries the `primary_addr` AND all known relay candidates. If there is an `.onion` candidate, it is ALSO tried
        // here directly (without going through the relay fallback logic), since it is already a network-independent "direct" address.
        if let Some(onion) = onion_addr.clone() {
            if let Some(swarm) = &mut self.swarm {
                // with the peer condition, a dial still in flight from
                // the previous backoff step is not started a second time.
                let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
                    .addresses(vec![onion])
                    .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                    .build();
                if let Err(e) = swarm.dial(opts) {
                    error!("Onion adresine yeniden bağlanma denemesi başarısız: {}", e);
                }
            }
        }
        self.dial_with_relay_fallback(peer_id, primary_addr);
        // Also every address the behaviours know for this peer. No direct (IP)
        // addresses are added: the node is onion-only since the 2026-09-23
        // deanon fix (`DialReject` refuses clearnet dials anyway).
        if let Some(swarm) = &mut self.swarm {
            let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
                // Only if none of the dials above started. With `Always` this
                // was one more Tor circuit to the same onion on each attempt.
                .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                .build();
            let _ = swarm.dial(opts);
        }
        true
    }

    /// Tells every connected peer (not servers) that this device is shutting
    /// down: they park it and stop dialing it until it connects again.
    /// Returns how many peers were told.
    pub(crate) fn announce_offline(&mut self) -> usize {
        let peers: Vec<PeerId> = self.keepalive_state.keys().copied().filter(|p| !self.is_server_peer(p)).collect();
        let Some(swarm) = &mut self.swarm else { return 0 };
        for p in &peers {
            swarm.behaviour_mut().keepalive.send_request(p, KeepAliveRequest { bye: true });
        }
        peers.len()
    }

    /// Called from Kotlin when a network interface change is reported (Wi-Fi to cellular, or any "default network changed" event; see the
    /// `notifyNetworkChanged` JNI and the P2PService network change detection). It immediately tries to reconnect to ALL known ACTIVE devices,
    /// IGNORING `reconnect_backoff` (see the `force` note in `try_reconnect_device`). All connections made over the old network are now dead sockets
    /// (the IP changed). Instead of waiting for the periodic `reconnect_sweep` (up to 15 s) or for `ping` to notice, the network change itself is a clear
    /// signal, so it acts at once.
    pub(crate) fn reconnect_all_known_now(&mut self) {
        let now = mono_ms();
        if now.saturating_sub(self.last_network_change_at) < NETWORK_CHANGE_DEBOUNCE_MS {
            // Trailing edge: `poll_events` runs it once the window ends.
            self.network_change_pending = true;
            return;
        }
        self.last_network_change_at = now;
        self.network_change_pending = false;
        // Two-device test (2026-09-06): after a network change, Tor circuits and the onion descriptor took minutes to recover. Poke arti too: `bootstrap()`
        // is idempotent and cheap (see `notify_network_changed`).
        if let Some(tor) = &self.tor {
            tor.notify_network_changed();
        }
        // Old-interface connections may be dead. Probe them all at once. A dead one closes on timeout, and live ones are left alone (on a mobile-to-Wi-Fi
        // switch, mobile connections keep working). Servers are never probed. Without that, the flag stayed set, and the next bulk connection closed the
        // working one.
        let peers: Vec<PeerId> = self.keepalive_state.keys().copied().filter(|p| !self.is_server_peer(p)).collect();
        for p in peers {
            self.mark_connection_suspect(p, true);
        }
        self.fast_reconnect_until = mono_ms() + FAST_RECONNECT_WINDOW_MS;
        // Saver: the forced dial and the fast window are for the peers that
        // were connected before the change. The others keep their backoff: a
        // device that has been offline for long was dialed again on every
        // network callback.
        let saver = self.radio_saver();
        let connected_before: std::collections::HashSet<String> = self.device_to_peer_id.iter()
            .filter(|(_, p)| self.keepalive_state.contains_key(p))
            .map(|(fp, _)| fp.clone())
            .collect();
        self.fast_reconnect_fps = if saver { connected_before.clone() } else { std::collections::HashSet::new() };
        // Outside saver too, only the devices that were connected or were
        // heard from lately are dialed at once: forcing every known device
        // redialed peers offline for weeks on each network callback.
        let wall = current_time_ms();
        let fps: Vec<(String, bool)> = self.known_remote_devices.values()
            .filter(|d| d.is_active)
            .map(|d| (d.device_fingerprint.clone(), wall.saturating_sub(d.last_seen) < NETWORK_CHANGE_FORCE_SEEN_MS))
            .collect();
        for (fp, seen_lately) in fps {
            let force = connected_before.contains(&fp) || (!saver && seen_lately);
            self.try_reconnect_device(&fp, force);
        }
        // Network robustness fix (see the `announce_address_to_all_contacts` docs): when the interface changes, our own best address may also change (new
        // LAN IP, new UPnP mapping). We proactively tell EVERYONE we know, instead of only waiting for our contacts to reconnect to us.
        self.announce_address_to_all_contacts();
        // Multi-device (1.7): a network change is a strong signal. Ignore the debounce and try the sibling history backfill NOW (to catch messages from
        // people I missed while offline). At most one extra round per 5 minutes: every LTE/Wi-Fi flap asked every sibling for the newest rows of every
        // conversation again.
        self.last_sibling_backfill_at = self.last_sibling_backfill_at
            .min(current_time_ms().saturating_sub(SIBLING_BACKFILL_INTERVAL_MS - 5 * 60_000));
        self.last_sibling_roster_sync_at = 0;
        self.request_sibling_backfill();
    }

    /// This device's prekey to hand out, made or rotated when due. `None`
    /// while the local storage key or the database is missing: a prekey whose
    /// secret cannot be stored would be gone at the next start, and every
    /// handshake made with it lost.
    pub(crate) fn current_own_prekey(&mut self) -> Option<SignedPrekey> {
        use zeroize::Zeroize;
        self.skipped_key_encryption_key?;
        self.db.as_ref()?;
        let own_fp = self.get_active_own_device_fingerprint().ok()?;
        let now = current_time_ms();
        if !self.own_prekeys_loaded {
            self.own_prekeys_loaded = true;
            let rows: Vec<Vec<u8>> = self.db.as_ref().and_then(|conn| {
                let mut stmt = conn.prepare("SELECT sealed FROM own_prekeys ORDER BY id").ok()?;
                let rows: Vec<Vec<u8>> = stmt.query_map([], |r| r.get(0)).ok()?.flatten().collect();
                Some(rows)
            }).unwrap_or_default();
            for sealed in rows {
                let Some(mut plain) = self.open_local_blob(&sealed) else { continue };
                if let Ok(mut stored) = ciborium::from_reader::<StoredPrekey, _>(plain.as_slice()) {
                    let sk_x = <[u8; 32]>::try_from(stored.sk_x25519.as_slice()).ok().map(StaticSecret::from);
                    let sk_m = <ml_kem::Encoded<MlKem1024DecapsulationKey>>::try_from(stored.sk_mlkem.as_slice())
                        .ok().map(|e| MlKem1024DecapsulationKey::from_bytes(&e));
                    // an id the table cannot hold is not a row we wrote.
                    if let (Some(sk_x25519), Some(sk_mlkem), true) = (sk_x, sk_m, stored.signed.id <= i64::MAX as u64) {
                        self.own_prekeys.push(OwnPrekey { signed: stored.signed.clone(), sk_x25519, sk_mlkem });
                    }
                    stored.sk_x25519.zeroize();
                    stored.sk_mlkem.zeroize();
                }
                plain.zeroize();
            }
        }
        // The point of a prekey: its secret does not outlive its use.
        if self.own_prekeys.iter().any(|k| now.saturating_sub(k.signed.id) > PREKEY_KEEP_MS) {
            self.own_prekeys.retain(|k| now.saturating_sub(k.signed.id) <= PREKEY_KEEP_MS);
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM own_prekeys WHERE id < ?1", params![now.saturating_sub(PREKEY_KEEP_MS) as i64]);
            }
        }
        let due = self.own_prekeys.last().map_or(true, |k| now.saturating_sub(k.signed.id) >= PREKEY_ROTATE_MS);
        if due {
            let mut csprng = OsRng;
            let sk_x25519 = StaticSecret::random_from_rng(&mut csprng);
            let (sk_mlkem, _) = MlKem1024::generate(&mut csprng);
            let kem_pubkey_x25519 = X25519PublicKey::from(&sk_x25519).as_bytes().to_vec();
            let kem_pubkey_mlkem = sk_mlkem.encapsulation_key().as_bytes().to_vec();
            // Larger than every earlier id, also after a clock set back.
            let id = now.max(self.own_prekeys.last().map_or(0, |k| k.signed.id.saturating_add(1))).clamp(1, i64::MAX as u64);
            let keys = self.own_device_keys.get(&own_fp)?;
            let to_sign = packet::prekey_signing_input(&own_fp, id, &kem_pubkey_x25519, &kem_pubkey_mlkem);
            let sig_c: Ed25519Signature = keys.sign_sk_ed25519.sign(&to_sign);
            let sig_pq: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&to_sign);
            let signed = SignedPrekey {
                id, kem_pubkey_x25519, kem_pubkey_mlkem,
                signature: sig_c.to_bytes().to_vec(),
                signature_pq: sig_pq.encode().to_vec(),
            };
            let mut stored = StoredPrekey {
                signed: signed.clone(),
                sk_x25519: sk_x25519.to_bytes().to_vec(),
                sk_mlkem: sk_mlkem.as_bytes().to_vec(),
            };
            let mut plain = ciborium_bytes(&stored).ok();
            stored.sk_x25519.zeroize();
            stored.sk_mlkem.zeroize();
            let sealed = plain.as_deref().and_then(|p| self.seal_local_blob(p));
            if let Some(p) = plain.as_mut() {
                p.zeroize();
            }
            let written = match (&self.db, sealed) {
                (Some(conn), Some(sealed)) => conn.execute(
                    "INSERT OR REPLACE INTO own_prekeys (id, sealed) VALUES (?1, ?2)", params![id as i64, sealed],
                ).is_ok(),
                _ => false,
            };
            if written {
                info!("Yeni prekey üretildi (id={})", id);
                self.own_prekeys.push(OwnPrekey { signed, sk_x25519, sk_mlkem });
            } else {
                // Not handed out: see the function note.
                warn!("Prekey saklanamadı, bu turda kullanılmıyor");
            }
        }
        self.own_prekeys.last().map(|k| k.signed.clone())
    }

    /// Keeps a device's prekey for the next handshake to it, when it carries
    /// that device's hybrid signature. A lower id than the stored one is a
    /// replay of an older packet and is ignored, unless `authoritative`: the
    /// prekey came in a HandshakeInit that passed the replay checks and whose
    /// signature covers the prekey id (a device that lost its prekeys starts
    /// again with lower ids).
    pub(crate) fn store_peer_prekey(&mut self, fp: &str, prekey: &SignedPrekey, device: &DeviceRecord, authoritative: bool) {
        if prekey.id == 0
            || prekey.kem_pubkey_x25519.len() != 32
            || prekey.kem_pubkey_mlkem.len() != device.kem_pubkey_mlkem.len()
        {
            return;
        }
        match self.peer_prekeys.get(fp) {
            Some(old) if old.id == prekey.id => return,
            Some(old) if old.id > prekey.id && !authoritative => return,
            _ => {}
        }
        let signed = packet::prekey_signing_input(fp, prekey.id, &prekey.kem_pubkey_x25519, &prekey.kem_pubkey_mlkem);
        if let Err(e) = verify_hybrid_signature(&signed, &prekey.signature, &prekey.signature_pq, device) {
            warn!("Prekey reddedildi (peer={}): {}", &fp[..fp.len().min(8)], e);
            return;
        }
        if let (Some(conn), Ok(cbor)) = (&self.db, ciborium_bytes(prekey)) {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO peer_prekeys (device_fingerprint, prekey) VALUES (?1, ?2)", params![fp, cbor],
            );
        }
        self.peer_prekeys.insert(fp.to_string(), prekey.clone());
    }

    /// Puts a fresh session in place and stores it. A failed write puts the
    /// previous session back (memory and disk then agree) and is an error.
    pub(crate) fn install_ratchet(&mut self, fp: &str, state: DeviceRatchetState) -> Result<(), String> {
        let previous = self.ratchets.insert(fp.to_string(), state);
        if self.persist_ratchet_state(fp) {
            // Keys of the replaced session must not be loaded onto the new one.
            self.clear_persisted_skipped_keys(fp);
            return Ok(());
        }
        match previous {
            Some(p) => { self.ratchets.insert(fp.to_string(), p); }
            None => { self.ratchets.remove(fp); }
        }
        Err("Oturum durumu yazılamadı, el sıkışma yapılmadı".to_string())
    }

    pub(crate) fn initiate_handshake_with(&mut self, peer_device_fingerprint: &str) -> Result<(), String> {
        // Found on device (2026-09-18): at app start something sent a message
        // before `setSkippedKeyEncryptionKey` had loaded the sessions. No session
        // was in memory, so a NEW init was created and persisted over the real
        // session the peer still used. Every restart diverged the two devices
        // (siblings too) until a re-handshake.
        if !self.ratchets_loaded {
            return Err("Oturum durumu henüz yüklenmedi".to_string());
        }
        // No session is set up at all with a blocked person. Otherwise opening a chat from the UI or calling `ensure_handshake` would create a fresh ratchet
        // and send a handshake to the other side (see the `try_publish_raw` note for the same reasoning).
        if self.is_blocked_device(peer_device_fingerprint) {
            return Err("Bu kişi engellenmiş".to_string());
        }
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let peer = self.known_remote_devices.get(peer_device_fingerprint).cloned()
            .ok_or("Unknown peer device; complete key exchange first")?;
        if !peer.is_active {
            return Err("Peer device has been revoked".to_string());
        }

        // If `DeviceRatchetState::initiate` fails here with "Bad Kyber/X25519 public key length", this is a PERMANENT error (corrupted or incompatible key data,
        // e.g. this record was created BEFORE the Category 3 to 5 (ML-KEM-768 to 1024) migration, or while the other side was still paired with an old app
        // version). Unlike network problems, retrying never fixes it. Before, this was silently written to logcat on EVERY `send_message_content` call (messages,
        // typing indicators, profile updates and history sync all go through the same path), and the UI never showed it, so there was no hint for "cannot
        // connect". Now, the FIRST time it is seen for this peer (or when the error text changes), it is reported once as an event through
        // `attachment_events` (see `handshake_failure_notified`).
        // To the peer's prekey when one is known: its secret is deleted within weeks, the long-term KEM secret never. Without one (first contact before any
        // packet from the peer), the long-term keys are used, id 0.
        let peer_prekey = self.peer_prekeys.get(peer_device_fingerprint).cloned();
        let (peer_kem_x25519, peer_kem_mlkem, recipient_prekey_id) = match &peer_prekey {
            Some(p) => (p.kem_pubkey_x25519.as_slice(), p.kem_pubkey_mlkem.as_slice(), p.id),
            None => (peer.kem_pubkey_x25519.as_slice(), peer.kem_pubkey_mlkem.as_slice(), 0),
        };
        let sender_prekey = self.current_own_prekey();
        let (state, kyber_ct, own_kyber_pub) = match DeviceRatchetState::initiate(
            peer_kem_x25519,
            peer_kem_mlkem,
            current_time_ms(),
        ) {
            Ok(v) => v,
            Err(e) => {
                let e = e.to_string();
                if self.handshake_failure_notified.get(peer_device_fingerprint) != Some(&e) {
                    self.handshake_failure_notified.insert(peer_device_fingerprint.to_string(), e.clone());
                    self.attachment_events.push(serde_json::json!({
                        "type": "handshake_failed", "peer": peer_device_fingerprint, "error": e
                    }).to_string());
                }
                return Err(e);
            }
        };
        // The handshake was set up successfully in this turn. Any permanent error recorded earlier for this peer is no longer valid, so clear it (e.g. the
        // contact was deleted and re-paired, and this time the key length is right).
        self.handshake_failure_notified.remove(peer_device_fingerprint);

        // CRITICAL: `state.own_x25519_secret` is the FRESH EPHEMERAL secret generated inside `DeviceRatchetState::initiate()`, and the DH calculation was
        // already done with IT (ratchet.rs). The "initiator_x25519_pubkey" sent to the other side (in HandshakeInit) must be derived from the SAME ephemeral
        // secret. Before, `own_keys.kem_sk_x25519` was used by mistake (the device's LONG-TERM identity key, a completely different keypair). In that case the
        // responder does DH inside `respond()` against the (wrong, long-term) public key the initiator sent, while the initiator did DH with its ephemeral secret.
        // The two sides can never reach the same shared secret, so EVERY message ended in "Decryption failed".
        let initiator_x25519_pub = X25519PublicKey::from(&state.own_x25519_secret).as_bytes().to_vec();
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;

        let timestamp = current_time_ms();
        let to_sign = handshake_signing_input(
            &initiator_x25519_pub, &own_kyber_pub, &kyber_ct, timestamp, peer_device_fingerprint,
            recipient_prekey_id, sender_prekey.as_ref().map_or(0, |p| p.id),
        );
        let sig_classical: Ed25519Signature = own_keys.sign_sk_ed25519.sign(&to_sign);
        let sig_pq: MlDsaSignature<MlDsa87> = own_keys.sign_sk_mldsa.sign(&to_sign);

        let handshake = HandshakeInit {
            sender_identity_id: own_identity_id,
            sender_device_fingerprint: own_fp,
            initiator_x25519_pubkey: initiator_x25519_pub,
            initiator_kyber_pubkey: own_kyber_pub,
            kyber_ciphertext: kyber_ct,
            timestamp,
            recipient_prekey_id,
            sender_prekey,
            signature_classical: sig_classical.to_bytes().to_vec(),
            signature_pq: sig_pq.encode().to_vec(),
        };

        // Not published unless stored: after a restart the old state would
        // come back while the peer runs the new one.
        self.install_ratchet(peer_device_fingerprint, state)?;
        if recipient_prekey_id == 0 {
            self.id0_inits.insert(peer_device_fingerprint.to_string());
        } else {
            self.id0_inits.remove(peer_device_fingerprint);
        }
        let r = self.publish_envelope(peer_device_fingerprint, &NetworkEnvelope::Handshake(handshake));
        // See `pairing_mailbox_subs`. Once the handshake is PUBLISHED (it goes to the other side's mailbox topic), drop the pairing subscription. From now on
        // the other side writes on the rotated topic, and we are already subscribed to it.
        self.drop_pairing_mailbox(peer_device_fingerprint);
        r
    }

    /// Fix (delivery guarantee: "the first message written while the other side was offline never arrives"): the only way out of a lost `HandshakeInit`.
    ///
    /// Failure pattern: when a message is first written to an offline device, `send_message_content_inner` calls `initiate_handshake_with` first. That sets
    /// up the ratchet at once and tries to publish the `HandshakeInit`. If the other side is offline, `gossipsub.publish` fails and the envelope falls into
    /// `pending_envelopes`. If the envelope gets stale there (or the app closes in the meantime) it is NEVER sent again. `initiate_handshake_with` is only
    /// called when there is NO ratchet, but on the sender's side the ratchet now EXISTS. The receiver buffers incoming packets in `early_packets` and waits for
    /// a handshake that never comes. No error is visible on either end, and messages are retried for 7 days for nothing.
    ///
    /// Fix: if the other side has confirmed NOTHING for `MAX_UNCONFIRMED_AGE_MS` (not even one Ack), we assume the session was never set up on its side, and
    /// send a FRESH handshake. Triggers: (1) the refresh round (see the `message_id_override` arm of `send_message_content_inner`); (2) reconnecting to that
    /// peer (see the `connections_established` block of `poll_events`).
    ///
    /// Because the session is reset, pending packets stay encrypted under the old chain. So all of them are regenerated on the fresh chain with
    /// `regen_pending_for_peer`, the same path used after a rotation, with the same meaning of invalidation. The criterion is whether the root key REALLY
    /// changed, not the return value of `initiate_handshake_with`. Even if publishing fails transiently (the envelope is queued), the ratchet has already
    /// changed, and the pending packets must be renewed.
    /// Returns the identity of the current chain generation of a session (see `PendingConfirmation.chain_stamp`). Empty string if there is no session.
    pub(crate) fn chain_stamp_for(&self, peer_device_fingerprint: &str) -> String {
        self.ratchets
            .get(peer_device_fingerprint)
            .map(|r| Self::topic_for_root_key(&r.root_handle_now()).to_string())
            .unwrap_or_default()
    }

    /// A signed packet from a known device that our session cannot decrypt (and
    /// that is not a duplicate: `reack_if_already_handled` ran first). A few in a
    /// row mean the two sides hold different sessions. Both still look online,
    /// and nothing gets through until the 25 min redo (device, 2026-09-18). After
    /// `UNDECRYPTABLE_BEFORE_REHANDSHAKE` failures with no good packet in between,
    /// start a fresh handshake. If both sides do it at once, the collision rule
    /// in `process_handshake_init` picks one.
    pub(crate) fn note_undecryptable(&mut self, fp: &str) {
        let now = current_time_ms();
        // A session installed moments ago (by us or from the peer's init): packets
        // still in flight from the old session are expected to fail. Re-initiating
        // here overwrote a freshly adopted session, and the peer then ignored our
        // init under the collision rule → diverged again (device, 2026-09-18).
        if self.ratchets.get(fp).map_or(false, |s| now.saturating_sub(s.last_rotation) < HANDSHAKE_COLLISION_WINDOW_MS) {
            self.undecryptable_from.remove(fp);
            return;
        }
        let entry = self.undecryptable_from.entry(fp.to_string()).or_insert((now, 0));
        if now.saturating_sub(entry.0) > UNDECRYPTABLE_WINDOW_MS {
            *entry = (now, 0);
        }
        entry.1 += 1;
        if entry.1 < UNDECRYPTABLE_BEFORE_REHANDSHAKE {
            return;
        }
        self.undecryptable_from.remove(fp);
        if self.last_handshake_redo.get(fp).map_or(false, |(t, _)| now.saturating_sub(*t) < UNDECRYPTABLE_REDO_MIN_INTERVAL_MS) {
            return;
        }
        warn!("Karşı taraftan {} paket çözülemedi, oturumlar ayrışmış — el sıkışma yenileniyor: {}", UNDECRYPTABLE_BEFORE_REHANDSHAKE, &fp[..fp.len().min(8)]);
        let stale = self.ratchets.get(fp).map(|s| s.root_handle_now());
        self.last_handshake_redo.insert(fp.to_string(), (now, stale));
        if let Err(e) = self.initiate_handshake_with(fp) {
            warn!("El sıkışma yenilenemedi: {}", e);
            return;
        }
        // Pending packets were encrypted for the dead session: re-encrypt them now.
        self.regen_pending_for_peer(fp);
    }

    pub(crate) fn maybe_redo_handshake(&mut self, peer_device_fingerprint: &str) {
        // If there is no session at all, the normal path already starts the handshake.
        // DEFINITIVE criterion: have we NOT been able to decrypt ANYTHING from the other side in this session (see `never_heard` in ratchet.rs: it resets on
        // a rotation receive, so the previous chain is counted too)? If so, the other side may never have processed our handshake. If the other side has
        // answered even once (recv > 0), this never fires again. A healthy session is never reset.
        let never_heard = match self.ratchets.get(peer_device_fingerprint) {
            Some(s) => s.never_heard(),
            None => return,
        };
        if !never_heard {
            return;
        }
        let now = current_time_ms();
        // Every redo makes a session that is again `never_heard`, so against an
        // offline peer this fired every 10 min for 7 days. The wait now grows
        // with the age of the oldest stuck message (half of it, at most 6 h).
        let oldest_stuck_age = self.awaiting_confirmation.values()
            .filter(|p| p.peer_device_fingerprint == peer_device_fingerprint)
            .map(|p| now.saturating_sub(p.original_sent_at))
            .max()
            .unwrap_or(0);
        let min_interval = (oldest_stuck_age / 2).clamp(HANDSHAKE_REDO_MIN_INTERVAL_MS, 6 * 60 * 60 * 1000);
        let stale_root = match self.last_handshake_redo.get(peer_device_fingerprint) {
            Some((last, stale)) => {
                if now.saturating_sub(*last) < min_interval {
                    return;
                }
                stale.clone()
            }
            None => None,
        };
        // Second criterion: something must really be waiting for delivery. `original_sent_at` (when the message first entered the queue) is used, not
        // `first_sent_at` (the last refresh time). Otherwise each refresh would reset the counter, and the reconnect trigger would never fire.
        let stuck = self.awaiting_confirmation.values().any(|p| {
            p.peer_device_fingerprint == peer_device_fingerprint
                && now.saturating_sub(p.original_sent_at) > MAX_UNCONFIRMED_AGE_MS
        });
        if !stuck {
            return;
        }
        warn!(
            "El sıkışma tazeleniyor (peer={}) — bu oturumda karşı taraftan hiç paket alınmadı ve bekleyen mesaj {} ms'i aştı; HandshakeInit'imiz hiç ulaşmamış olabilir",
            crate::log_id(&peer_device_fingerprint), MAX_UNCONFIRMED_AGE_MS
        );
        let before = self.ratchets.get(peer_device_fingerprint).map(|s| s.root_handle_now());
        let result = self.initiate_handshake_with(peer_device_fingerprint);
        let after = self.ratchets.get(peer_device_fingerprint).map(|s| s.root_handle_now());
        let replaced = before != after;
        // The abandoned root key is kept for a later refresh to drop. If the session did not change, the stale record already held is kept.
        self.last_handshake_redo.insert(
            peer_device_fingerprint.to_string(),
            (now, if replaced { before } else { stale_root }),
        );
        if replaced {
            self.regen_pending_for_peer(peer_device_fingerprint);
        }
        if let Err(e) = result {
            warn!("Tazelenen el sıkışma hemen yayınlanamadı (kuyruğa alındı, yeniden denenecek): {}", e);
        }
    }

    // NOTE: skipped keys are NOT loaded from disk here (while a new session is being set up), because this is a NEW handshake. There can be no skipped-key
    // record in the DB for this device pair yet (message numbers start from zero in a new session). Writing or deleting skipped keys on disk happens only
    // WITHIN a session (in `receive_message`).
    //
    // The WHOLE ratchet state (root_key, ck_send/ck_recv, own and peer keys, counters) is now persisted in the `ratchet_states` table (encrypted with
    // `skipped_key_encryption_key`). See `persist_ratchet_state` and `load_ratchet_states_from_db`. When the process restarts (app update, background kill,
    // etc.), these sessions are restored after `init_db` once `setSkippedKeyEncryptionKey` is called. No new handshake is needed, and delayed or skipped
    // message keys from the past (from the skipped_message_keys table) are still valid.

    pub(crate) fn process_handshake_init(&mut self, source: Option<PeerId>, handshake: &HandshakeInit) -> Result<(), String> {
        // See `initiate_handshake_with`: a session made before the load is
        // overwritten by the stored one, and the two sides diverge.
        if !self.ratchets_loaded {
            return Err("Oturum durumu henüz yüklenmedi".to_string());
        }
        let sender =self.known_remote_devices.get(&handshake.sender_device_fingerprint).cloned()
            .ok_or("Unknown sender device; cannot verify signatures")?;
        // Before, `is_active` was not checked anywhere. Since no code path ever set it to false, it had no effect in practice. Now `revoke_contact_device`
        // really can set it to `false`, and it is enforced here: a handshake from a revoked device is rejected.
        if !sender.is_active {
            self.answer_revoked_sibling(&sender.device_fingerprint);
            return Err("Sender device has been revoked".to_string());
        }

        // See the same identity-binding fix in receive_message: the signature only proves the device signed it, not that the identity_id in the header belongs to
        // that device. Enforce the match with the stored (TOFU) binding.
        if handshake.sender_identity_id != sender.identity_id {
            return Err("HandshakeInit sender_identity_id, kayıtlı cihaz kimliğiyle eşleşmiyor".to_string());
        }

        // The signature covers the RECIPIENT (our fingerprint): a handshake that A sent to B cannot be replayed to C to break C's session with A.
        let recipient_fp = self.get_active_own_device_fingerprint()?;
        let to_verify = handshake_signing_input(
            &handshake.initiator_x25519_pubkey, &handshake.initiator_kyber_pubkey,
            &handshake.kyber_ciphertext, handshake.timestamp, &recipient_fp,
            handshake.recipient_prekey_id, handshake.sender_prekey.as_ref().map_or(0, |p| p.id),
        );
        verify_hybrid_signature(&to_verify, &handshake.signature_classical, &handshake.signature_pq, &sender)?;

        // Security fix (see the `record_peer_id_if_known` docs and the same note in `process_identity_exchange`): the signature was verified successfully at
        // this point. So it is proven that the sender really holds the private key of this fingerprint (already stored in `known_remote_devices`). It is now
        // safe to link this fingerprint with the `PeerId` that really published the packet. Before, this was done unconditionally, BEFORE signature verification.
        // The call itself is further down, after the freshness and replay checks: a replayed old init has a valid signature too.

        // Security fix (handshake replay leading to a session-reset DoS): gossipsub `Signed` mode lets an observer on the network re-publish a valid
        // `HandshakeInit` it captured. This function overwrites an existing ratchet with a fresh `respond` state, so such a replay could break a live
        // conversation. Two layers of defence (see the `recent_handshake_sigs` field note):
        // (1) a freshness window: a timestamp that is too old or too far ahead is rejected (filters captured old handshakes, tolerates clock skew);
        // (2) content dedup: the same signed (byte-identical) handshake is not applied a second time within the window. A real re-pairing carries fresh
        //     ephemeral keys, so a different signature, and it is accepted whatever the clock skew (no risk of a monotonic timestamp breaking re-pairing).
        let now = current_time_ms();
        let skew = now.abs_diff(handshake.timestamp);
        // An init waits in the server mailbox while this device is off, so the
        // past side of the window is the retry horizon, not the clock skew.
        let stale = handshake.timestamp < now && skew > HANDSHAKE_MAX_SKEW_MS;
        let window = if stale { HANDSHAKE_MAX_AGE_MS } else { HANDSHAKE_MAX_SKEW_MS };
        if skew > window {
            return Err(format!(
                "HandshakeInit timestamp'i pencere dışında (sapma {} ms) — muhtemel tekrar oynatma, reddedildi",
                skew
            ));
        }
        {
            let seen = self.recent_handshake_sigs.entry(handshake.sender_device_fingerprint.clone()).or_default();
            // Prune old entries from the window (prevents unbounded growth).
            seen.retain(|(ts, _)| now.abs_diff(*ts) <= HANDSHAKE_MAX_AGE_MS);
            // A stored init older than one already accepted would put the session back on keys the sender has replaced. Any older one counts, not only one
            // past the skew window (both on the sender's clock).
            if seen.iter().any(|(ts, _)| *ts > handshake.timestamp) {
                info!("HandshakeInit yok sayıldı (peer={}) — daha yenisi zaten kabul edildi", crate::log_id(&handshake.sender_device_fingerprint));
                return Ok(());
            }
            if seen.iter().any(|(_, sig)| sig == &handshake.signature_classical) {
                info!(
                    "HandshakeInit yok sayıldı (peer={}) — aynı imza pencerede zaten görüldü (tekrar oynatma/çift paket)",
                    crate::log_id(&handshake.sender_device_fingerprint)
                );
                return Ok(());
            }
            // Recorded now, whatever is decided below. Only an accepted init
            // was: one we ignored (collision, unknown prekey) could be
            // replayed for 7 days and then replaced the live session.
            seen.push((handshake.timestamp, handshake.signature_classical.clone()));
            // the newest 256 (the peer signs each one, but a peer that
            // keeps sending inits grew the list, and its app_meta copy, for 7 days).
            if seen.len() > 256 {
                seen.sort_by_key(|(ts, _)| *ts);
                let excess = seen.len() - 256;
                seen.drain(..excess);
            }
        }
        self.persist_handshake_sigs(&handshake.sender_device_fingerprint);

        // Past the replay checks, and the signature above covers its id: this
        // is the sender's prekey now, whatever was stored before.
        if let Some(prekey) = &handshake.sender_prekey {
            self.store_peer_prekey(&handshake.sender_device_fingerprint, prekey, &sender, true);
        }

        let own_fp = self.get_active_own_device_fingerprint()?;

        // A first contact (no session, or only our own init that carried no
        // message yet) must come to a prekey: an init to the long-term KEM
        // keys (id 0) is refused while this device hands prekeys out. The
        // sender's prekey is stored above, so the session starts from our
        // side, which also gives the sender our prekey. Our own pending init
        // stays when it went to a prekey: the sender adopts it (below, its
        // side of this rule). A session that carried messages still takes
        // id 0 (a peer that lost our prekey).
        if handshake.recipient_prekey_id == 0 && self.link_request_open_until <= now {
            let sender_fp = handshake.sender_device_fingerprint.clone();
            let own_pending = self.ratchets.get(&sender_fp).map(|e| {
                e.has_responded_to_peer_key == e.prev_root_key.is_none() && e.send_message_number == 0 && e.recv_message_number == 0
            });
            if own_pending != Some(false) && self.current_own_prekey().is_some() {
                let redo = own_pending.is_none() || self.id0_inits.contains(&sender_fp);
                if redo && self.last_handshake_redo.get(&sender_fp).map_or(true, |(t, _)| now.saturating_sub(*t) >= UNDECRYPTABLE_REDO_MIN_INTERVAL_MS) {
                    self.last_handshake_redo.insert(sender_fp.clone(), (now, None));
                    if let Err(e) = self.initiate_handshake_with(&sender_fp) {
                        warn!("Prekey'siz ilk temas sonrası el sıkışma başlatılamadı: {}", e);
                    }
                }
                return Err("HandshakeInit ilk temasta prekey kullanmıyor (id 0), reddedildi".to_string());
            }
        }

        // CRITICAL: concurrent handshake collision. If both devices (e.g. both restart the app and open the same chat at the same time, so `ensure_handshake`
        // finds `has_active_session == false` on both) send a `HandshakeInit` to each other at EXACTLY the same time: each side first creates an "initiator"
        // ratchet state in its own `initiate_handshake_with` call and writes it to `self.ratchets`. Then, while processing the other side's HandshakeInit (here),
        // it overwrites that state with a "responder" state. The problem: responder mode does DH/decapsulation with its OWN long-term identity KEM keys
        // (`own_keys.kem_sk_*`) against the other side's EPHEMERAL public key. If both sides do this, the derived shared secrets do NOT match. The symmetry of
        // DH only holds when "A's ephemeral + B's identity" CROSSES with "B's identity + A's ephemeral", and both sides using their own identity breaks that
        // symmetry. The result: ALL later messages fail with "Decryption failed" / "not in the skipped-key cache". A QR rescan appears to "fix" it, because it
        // forces a one-sided handshake.
        //
        // Deterministic resolution: the side whose fingerprint (hex string, comparable) is SMALLER is the "canonical initiator". If we already have our OWN
        // initiator state (one that has not carried any message yet, see the `send_message_number`/`recv_message_number` zero checks) AND our fingerprint is
        // SMALLER than the other side's, the incoming HandshakeInit is IGNORED (we keep our initiator state). The other side (with the bigger fingerprint)
        // then accepts OUR HandshakeInit symmetrically, and produces the correct responder state.
        if let Some(existing) = self.ratchets.get(&handshake.sender_device_fingerprint) {
            // Simultaneous handshake: both sides initiated. The smaller fingerprint's
            // init wins, and the larger side adopts it (the `respond` below). This
            // used to hold only while our session was still UNUSED. On a slow path
            // the losing init arrives late: the peer's init came via the server 31 s
            // after ours (device, re-pair on mobile data, 2026-09-18). By then the
            // peer had adopted our session and messages were flowing, so we replaced
            // a live session with the one the peer had already dropped. Both sides
            // stayed "online" but could not decrypt each other until the 25 min
            // redo. The winner now keeps its own young initiator session (not yet
            // rotated, `!has_responded_to_peer_key`) against any init created
            // within the collision window. A later init is a real re-handshake
            // (the peer's `maybe_redo_handshake`) and is still accepted.
            // The session we initiated, in its first generation: untouched
            // (flag set, no rotation), or after the peer's first rotation,
            // which a responder makes before its first send (flag clear, one
            // rotation). `!has_responded_to_peer_key` alone was also true for
            // a session we had only responded to, and false for our own
            // untouched one.
            let we_initiated = existing.has_responded_to_peer_key == existing.prev_root_key.is_none();
            let same_round = handshake.timestamp.abs_diff(existing.last_rotation) <= HANDSHAKE_COLLISION_WINDOW_MS;
            let existing_unused = existing.send_message_number == 0 && existing.recv_message_number == 0;
            // A device waiting to be linked (showing its link QR) always adopts. Its own init carries its pre-link identity, which the primary rejects
            // ("sender_identity_id does not match"). Keeping it (when this device's fingerprint happened to be the smaller one) left the two on different
            // sessions, and the DeviceLinkGrant never decrypted (device test, 2026-09-19).
            let awaiting_link = self.link_request_open_until > now;
            // An init older than the session we hold (not only one that waited past the skew window): the sender has moved on from it. Inside the
            // collision window the rule below decides instead. Two clocks: the sender's against ours. Within the skew this check already accepts above, it is
            // no proof of "older". Replays are caught by the signature list.
            if !same_round && handshake.timestamp.saturating_add(HANDSHAKE_MAX_SKEW_MS) < existing.last_rotation {
                info!("HandshakeInit yok sayıldı (peer={}) — oturumdan eski", crate::log_id(&handshake.sender_device_fingerprint));
                return Ok(());
            }
            // `we_initiated` for both: a session we only responded to is the
            // peer's to replace.
            // Our init went to id 0 and the peer hands prekeys out: it refused
            // ours (the rule above, on its side), so its init is the session.
            let ours_refused = handshake.sender_prekey.is_some() && self.id0_inits.contains(&handshake.sender_device_fingerprint);
            if !awaiting_link && !ours_refused && we_initiated && (existing_unused || same_round) && own_fp < handshake.sender_device_fingerprint {
                info!(
                    "Eşzamanlı el sıkışma çakışması (peer={}) — kendi initiator state'imiz korunuyor (küçük fingerprint kuralı)",
                    crate::log_id(&handshake.sender_device_fingerprint)
                );
                return Ok(());
            }
        }

        // The secret the initiator encapsulated to: one of our prekeys, or the
        // long-term keys (id 0) when it knew no prekey of ours.
        let (own_kem_x25519, own_kem_mlkem) = if handshake.recipient_prekey_id == 0 {
            let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
            (own_keys.kem_sk_x25519.clone(), own_keys.kem_sk_mlkem.clone())
        } else {
            self.current_own_prekey(); // loads them on first use
            match self.own_prekeys.iter().find(|k| k.signed.id == handshake.recipient_prekey_id) {
                Some(k) => (k.sk_x25519.clone(), k.sk_mlkem.clone()),
                None => {
                    // Deleted by now (the peer held an old one) or never ours
                    // (this install lost its prekeys). The session cannot be
                    // set up from this packet: start it from our side, which
                    // also hands the peer our current prekey.
                    let fp = handshake.sender_device_fingerprint.clone();
                    warn!("HandshakeInit bilinmeyen prekey kullanıyor (peer={}, id={}) — el sıkışma bizden yenileniyor", &fp[..fp.len().min(8)], handshake.recipient_prekey_id);
                    if self.last_handshake_redo.get(&fp).map_or(true, |(t, _)| now.saturating_sub(*t) >= UNDECRYPTABLE_REDO_MIN_INTERVAL_MS) {
                        let stale = self.ratchets.get(&fp).map(|s| s.root_handle_now());
                        self.last_handshake_redo.insert(fp.clone(), (now, stale));
                        if self.initiate_handshake_with(&fp).is_ok() {
                            self.regen_pending_for_peer(&fp);
                        }
                    }
                    return Err("HandshakeInit bilinmeyen bir prekey'e şifrelenmiş".to_string());
                }
            }
        };

        let installed = DeviceRatchetState::respond(
            own_kem_x25519,
            own_kem_mlkem,
            &handshake.initiator_x25519_pubkey,
            &handshake.initiator_kyber_pubkey,
            &handshake.kyber_ciphertext,
            now,
        )
        .map_err(|e| e.to_string())
        .and_then(|state| self.install_ratchet(&handshake.sender_device_fingerprint, state));
        if let Err(e) = installed {
            // A local failure (write error) is no decision about this init:
            // forget it, so the sender's retry of the same bytes is taken
            if let Some(seen) = self.recent_handshake_sigs.get_mut(&handshake.sender_device_fingerprint) {
                seen.retain(|(_, sig)| sig != &handshake.signature_classical);
            }
            self.persist_handshake_sigs(&handshake.sender_device_fingerprint);
            return Err(e);
        }
        self.id0_inits.remove(&handshake.sender_device_fingerprint);
        self.record_peer_id_if_known(source, &handshake.sender_device_fingerprint);
        // See `pairing_mailbox_subs`: the ratchet is set up, so the pairing-period subscription is no longer needed.
        self.drop_pairing_mailbox(&handshake.sender_device_fingerprint);
        Ok(())
    }

    /// Called before entering an active chat and when sending a message. `should_rotate()` implements Signal's real model (see ratchet.rs): we trigger the
    /// rotation ourselves only if 30 minutes have passed AND we have not yet answered the other side's current public key (`has_responded_to_peer_key == false`).
    /// Otherwise (we already answered, so the next rotation right belongs to the other side) nothing is done. A deterministic "smaller fingerprint triggers"
    /// rule is not needed, because the `has_responded_to_peer_key` flag already decides naturally whose turn it is.
    pub(crate) fn maybe_rotate_ratchet(&mut self, peer_device_fingerprint: &str) -> Result<Option<Vec<u8>>, String> {
        let now = current_time_ms();
        let should_rotate = self.ratchets.get(peer_device_fingerprint).map(|s| s.should_rotate(now)).unwrap_or(false);
        if !should_rotate {
            return Ok(None);
        }
        if let Some(state) = self.ratchets.get_mut(peer_device_fingerprint) {
            // memory goes back to this if the rotated state
            // cannot be written.
            let snapshot = state.clone();
            let kyber_ct = state.perform_dh_ratchet(now)?;
            // State first, then the table (as in `receive_message`): stopped
            // in between, the disk held the old state without its skipped keys.
            if !self.persist_ratchet_state(peer_device_fingerprint) {
                self.ratchets.insert(peer_device_fingerprint.to_string(), snapshot);
                return Err("Oturum durumu yazılamadı, rotasyon duyurulmadı".to_string());
            }
            // We triggered the rotation. The skipped keys of the old chain were moved into the state (`old_recv`), and their copies in the table would now
            // clash with the new chain's numbers.
            self.clear_persisted_skipped_keys(peer_device_fingerprint);
            return Ok(Some(kyber_ct));
        }
        Ok(None)
    }
}
