//! Device fan-out, device auth signatures, device linking and device notices.

use super::*;

impl P2PCore {

    /// The user deleted this contact on THIS device (`delete_contact`). A
    /// sibling that still has it must not bring it back with its next sync
    /// (`import_sync_payload`), and its own IdentityExchange must not either
    /// (`evaluate_sender_device`); scanning or typing its code again clears
    /// the mark (`pair_with_code`).
    /// The delete itself reaches siblings as `SiblingEchoBody::ContactRemoved`.
    /// Same mark for a group the user left or deleted here.
    pub(crate) fn group_removed_locally(&self, group_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row("SELECT 1 FROM removed_groups WHERE group_id = ?1", params![group_id], |_| Ok(())).is_ok()
        })
    }

    pub(crate) fn contact_removed_locally(&self, identity_id: &str) -> bool {
        self.contact_removed_at(identity_id).is_some()
    }

    /// When the contact was removed on this device or a sibling (ms), if it was.
    pub(crate) fn contact_removed_at(&self, identity_id: &str) -> Option<u64> {
        self.db.as_ref().and_then(|conn| {
            conn.query_row("SELECT removed_at FROM removed_contacts WHERE identity_id = ?1", params![identity_id], |r| r.get::<_, i64>(0)).ok()
        }).map(|t| t.max(0) as u64)
    }

    /// Writes the removed marker; a later removal time wins.
    pub(crate) fn mark_contact_removed(conn: &rusqlite::Connection, identity_id: &str, removed_at: u64) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO removed_contacts (identity_id, removed_at) VALUES (?1, ?2) \
             ON CONFLICT(identity_id) DO UPDATE SET removed_at = MAX(removed_at, excluded.removed_at)",
            params![identity_id, removed_at as i64],
        )
    }

    /// When the user last paired with this contact on any of my devices (ms, 0 = never).
    pub(crate) fn contact_added_at(&self, identity_id: &str) -> u64 {
        self.meta_u64(&format!("cadd:{}", identity_id))
    }

    /// Keeps the later of the stored pairing time and `at`.
    pub(crate) fn note_contact_added(&self, identity_id: &str, at: u64) {
        if at > self.contact_added_at(identity_id) {
            self.meta_put(&format!("cadd:{}", identity_id), &at.to_string());
        }
    }

    // ===============================================================
    // Multi-device: adding a device, revoking one, and syncing.
    // Design: the second device generates its OWN key pair (its own device_fingerprint) and ADOPTS the identity (identity_id) of the primary
    // device. The primary's long-lived secret key never leaves device 1. The secondary is authorized by a `DeviceAdd` signed by the primary.
    // After pairing, the two devices are independent: contacts fan out messages to each device separately.
    // ===============================================================

    pub(crate) fn my_identity_id(&self) -> Option<String> {
        self.identity.as_ref().map(|i| i.identity_id.clone())
    }

    /// The STABLE ("canonical") chat key for a device_fingerprint, shared by all devices of the same identity. Even when a contact has several
    /// devices, the local chat and archive stay under ONE key. The key is the smallest `(first_seen, fingerprint)` among the contact's known
    /// active devices (independent of HashMap iteration order). If the contact is unknown (a sibling device or a group), the fingerprint is returned as is.
    pub(crate) fn canonical_peer_key(&self, sender_fp: &str) -> String {
        let identity_id = match self.known_remote_devices.get(sender_fp) {
            Some(d) => d.identity_id.clone(),
            None => return sender_fp.to_string(),
        };
        self.canonical_device_for_identity(&identity_id).unwrap_or_else(|| sender_fp.to_string())
    }

    /// The canonical (deterministic) device of an identity; see `canonical_peer_key`.
    /// ContactSummary.active_device_fingerprint and the incoming message archive must use the SAME value. Otherwise the history of a contact
    /// with several devices gets split.
    pub(crate) fn canonical_device_for_identity(&self, identity_id: &str) -> Option<String> {
        if let Some(cid) = self.identity_to_contact.get(identity_id) {
            if let Some(contact) = self.contacts.get(cid) {
                let mut actives: Vec<&contact::KnownDevice> = contact.known_devices.iter()
                    .filter(|d| matches!(d.status, contact::KnownDeviceStatus::Active))
                    .collect();
                actives.sort_by(|a, b| a.first_seen.cmp(&b.first_seen)
                    .then_with(|| a.device_fingerprint.cmp(&b.device_fingerprint)));
                if let Some(d) = actives.first() {
                    return Some(d.device_fingerprint.clone());
                }
            }
        }
        // No contact record: fall back to known_remote_devices.
        let mut actives: Vec<&DeviceRecord> = self.known_remote_devices.values()
            .filter(|d| d.identity_id == identity_id && d.is_active)
            .collect();
        actives.sort_by(|a, b| a.device_fingerprint.cmp(&b.device_fingerprint));
        actives.first().map(|d| d.device_fingerprint.clone())
    }

    /// ALL active devices of an identity that messages fan out to (pairwise). Only devices whose PUBLIC keys are known (known_remote_devices)
    /// are returned. A device announced by a DeviceAdd whose IdentityExchange has not arrived yet is NOT included, because there are no keys to
    /// encrypt to. It is added when the IdentityExchange arrives.
    pub(crate) fn active_devices_for_identity(&self, identity_id: &str) -> Vec<String> {
        let mut v: Vec<String> = self.known_remote_devices.values()
            .filter(|d| d.identity_id == identity_id && d.is_active)
            .map(|d| d.device_fingerprint.clone())
            .collect();
        v.sort();
        v
    }

    /// 1:1 send fan-out targets: ALL active devices of the identity of `primary_fp` (including `primary_fp`). If the identity is unknown, only
    /// `primary_fp` (single device, the existing behaviour).
    ///
    /// A device unseen for `STALE_PEER_RETRY_HORIZON_MS` is left out, the same as `sibling_active_devices` does. The reason: a contact's abandoned
    /// old phone made every message (and every call invite) also go to its server mailbox, which filled up to its 5000-item cap. If that leaves
    /// nobody, every active device is kept.
    pub(crate) fn fanout_targets(&self, primary_fp: &str) -> Vec<String> {
        match self.known_remote_devices.get(primary_fp).map(|d| d.identity_id.clone()) {
            Some(id) => {
                let all = self.active_devices_for_identity(&id);
                let mut v: Vec<String> = all.iter().filter(|fp| self.device_recently_seen(fp)).cloned().collect();
                // Nobody recently seen (e.g. `last_seen` not refreshed yet
                // after an upgrade): fall back to every active device.
                if v.is_empty() { v = all; }
                if v.is_empty() { v.push(primary_fp.to_string()); }
                v
            }
            None => vec![primary_fp.to_string()],
        }
    }

    /// The devices a notice to all contacts goes to (name, photo, address,
    /// new device, account deleted): per contact its Active devices seen
    /// within `STALE_PEER_RETRY_HORIZON_MS`, or all its Active devices if none
    /// was, the same rule as `fanout_targets`. A contact's abandoned phone
    /// used to get each of these too (an avatar is up to 256 KB), retried and
    /// deposited for days.
    pub(crate) fn contact_device_targets(&self) -> Vec<String> {
        let my_id = self.my_identity_id();
        self.contacts.values()
            .filter(|c| my_id.as_deref() != Some(c.trusted_identity_id.as_str()))
            // Deleted accounts: every send to them is refused at publish anyway.
            .filter(|c| !self.deleted_identities.contains(&c.trusted_identity_id))
            .flat_map(|c| {
                let active: Vec<String> = c.known_devices.iter()
                    .filter(|d| matches!(d.status, contact::KnownDeviceStatus::Active))
                    .map(|d| d.device_fingerprint.clone())
                    .collect();
                let recent: Vec<String> = active.iter().filter(|fp| self.device_recently_seen(fp)).cloned().collect();
                if recent.is_empty() { active } else { recent }
            })
            .collect()
    }

    /// Refreshes `last_seen` on every successfully decrypted packet. It was
    /// only ever written at pairing, so the staleness filters built on it
    /// (`sibling_active_devices`, `fanout_targets`, durable-retry skip) wrote
    /// off LIVE devices seven days after pairing. Persisted at most hourly.
    pub(crate) fn touch_device_seen(&mut self, fp: &str) {
        let now = current_time_ms();
        let Some(d) = self.known_remote_devices.get_mut(fp) else { return };
        if now.saturating_sub(d.last_seen) < 60 * 60 * 1000 {
            return;
        }
        // Same test as `load_pending_durable_retries_from_db`, which skipped this
        // peer's rows at start-up while it was stale.
        let was_stale = now.saturating_sub(d.last_seen) >= STALE_PEER_RETRY_HORIZON_MS;
        d.last_seen = now;
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "UPDATE remote_devices SET last_seen = ?1 WHERE device_fingerprint = ?2",
                params![now as i64, fp],
            );
        }
        if was_stale {
            self.load_pending_durable_retries_from_db();
        }
    }

    /// Seen within `STALE_PEER_RETRY_HORIZON_MS` (or never stamped: 0), or
    /// connected right now: a device that is connected is not stale, and
    /// two devices that both wrote each other off never sent the packet
    /// that would stamp them again.
    pub(crate) fn device_recently_seen(&self, fp: &str) -> bool {
        self.known_remote_devices.get(fp).map_or(true, |d| {
            d.last_seen == 0 || current_time_ms().saturating_sub(d.last_seen) < STALE_PEER_RETRY_HORIZON_MS
        }) || self.is_connected_to_device(fp)
    }

    /// The active sibling devices of MY identity, EXCLUDING this device. Sync messages (DeviceSync / DeviceRevokeNotice) are sent to them.
    pub(crate) fn sibling_active_devices(&self) -> Vec<String> {
        let my_id = match self.my_identity_id() { Some(id) => id, None => return Vec::new() };
        let own_fp = self.get_active_own_device_fingerprint().ok();
        // Leave out a sibling not seen for a long time (see `STALE_PEER_RETRY_HORIZON_MS`). It is removed only from NEW fan-out, so that it does not
        // keep accumulating a new durable retry record for every message.
        let now = current_time_ms();
        self.known_remote_devices.values()
            .filter(|d| d.identity_id == my_id && d.is_active)
            // Never stamped (0) counts as recent, as in `device_recently_seen`:
            // only a decrypted packet stamps it, and a sibling left out here
            // never gets the sync that would make it answer.
            .filter(|d| {
                d.last_seen == 0
                    || now.saturating_sub(d.last_seen) < STALE_PEER_RETRY_HORIZON_MS
                    || self.is_connected_to_device(&d.device_fingerprint)
            })
            .map(|d| d.device_fingerprint.clone())
            .filter(|fp| own_fp.as_deref() != Some(fp.as_str()))
            .collect()
    }

    /// The canonical byte string that gets signed (DeviceAdd / DeviceRevoke).
    ///
    /// A revoke carries its own tag. Without one, the DeviceAdd and the DeviceRevoke signed the same bytes. So the DeviceAdd that a secondary shows
    /// to everyone (in each plaintext IdentityExchange) was also a valid DeviceRevoke of that secondary: any contact could send it back and wipe the
    /// device.
    ///
    /// Domain tag + length-framed fields (NUL-joined fields were ambiguous). Every DeviceAdd / DeviceRevoke signed before this format does not
    /// verify any more: devices must be re-linked.
    pub(crate) fn device_auth_signing_bytes(identity_id: &str, subject_fp: &str, actor_fp: &str, revoke: bool) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 + identity_id.len() + subject_fp.len() + actor_fp.len());
        b.extend_from_slice(b"typeon-device-auth-v1");
        for field in [identity_id, subject_fp, actor_fp] {
            b.extend_from_slice(&(field.len() as u32).to_be_bytes());
            b.extend_from_slice(field.as_bytes());
        }
        b.push(revoke as u8);
        b
    }

    /// What the ADDED device signs (`DeviceAdd.consent`): the bytes the first
    /// device signs, with a tag.
    pub(crate) fn device_add_consent_bytes(identity_id: &str, new_fp: &str, added_by: &str) -> Vec<u8> {
        let mut b = Self::device_auth_signing_bytes(identity_id, new_fp, added_by, false);
        b.extend_from_slice(b"\0consent");
        b
    }

    /// This device agrees to become a device of the identity of first device
    /// `root_fp` (`DeviceAdd.consent`, `consent_pq`).
    pub(crate) fn sign_link_consent(&self, root_fp: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let msg = Self::device_add_consent_bytes(root_fp, &own_fp, root_fp);
        let sig_c: Ed25519Signature = keys.sign_sk_ed25519.sign(&msg);
        let sig_pq: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&msg);
        Ok((sig_c.to_bytes().to_vec(), sig_pq.encode().to_vec()))
    }

    /// The added device countersigned this DeviceAdd. The keys are that
    /// device's signing keys, already checked against its fingerprint. Every
    /// place that accepts a DeviceAdd calls this.
    pub(crate) fn add_has_consent(da: &DeviceAdd, device_ed25519: &[u8], device_mldsa: &[u8]) -> bool {
        let msg = Self::device_add_consent_bytes(&da.identity_id, &da.new_device_fingerprint, &da.added_by);
        verify_hybrid_signature_with(&msg, &da.consent, &da.consent_pq, device_ed25519, device_mldsa).is_ok()
    }

    pub(crate) fn sign_device_add(&self, new_fp: &str, consent: &[u8], consent_pq: &[u8]) -> Result<DeviceAdd, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let identity_id = self.my_identity_id().ok_or("No identity")?;
        // see `verify_device_auth`: nobody accepts another signer.
        if own_fp != identity_id {
            return Err("Only the primary device can do this".to_string());
        }
        let keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let msg = Self::device_auth_signing_bytes(&identity_id, new_fp, &own_fp, false);
        let sig_c: Ed25519Signature = keys.sign_sk_ed25519.sign(&msg);
        let sig_pq: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&msg);
        Ok(DeviceAdd {
            identity_id,
            new_device_fingerprint: new_fp.to_string(),
            added_by: own_fp,
            signature: sig_c.to_bytes().to_vec(),
            signature_pq: sig_pq.encode().to_vec(),
            consent: consent.to_vec(),
            consent_pq: consent_pq.to_vec(),
        })
    }

    pub(crate) fn sign_device_revoke(&self, revoked_fp: &str) -> Result<DeviceRevoke, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let identity_id = self.my_identity_id().ok_or("No identity")?;
        // see `verify_device_auth`: nobody accepts another signer.
        if own_fp != identity_id {
            return Err("Only the primary device can do this".to_string());
        }
        let keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let msg = Self::device_auth_signing_bytes(&identity_id, revoked_fp, &own_fp, true);
        let sig_c: Ed25519Signature = keys.sign_sk_ed25519.sign(&msg);
        let sig_pq: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&msg);
        Ok(DeviceRevoke {
            identity_id,
            revoked_device_fingerprint: revoked_fp.to_string(),
            revoked_by: own_fp,
            signature: sig_c.to_bytes().to_vec(),
            signature_pq: sig_pq.encode().to_vec(),
        })
    }

    /// Verifies a DeviceAdd / DeviceRevoke signature with the key of a KNOWN ACTIVE device (the actor) of that identity. The actor can be in
    /// own_devices or known_remote_devices. Its identity must match and it must be active.
    pub(crate) fn verify_device_auth(&self, identity_id: &str, subject_fp: &str, actor_fp: &str, sig: &[u8], sig_pq: &[u8], revoke: bool) -> Result<(), String> {
        let actor = self.own_devices.get(actor_fp)
            .or_else(|| self.known_remote_devices.get(actor_fp))
            .cloned()
            .ok_or("Signing (actor) device unknown")?;
        if actor.identity_id != identity_id {
            return Err("Signing device does not belong to this identity".to_string());
        }
        if !actor.is_active {
            return Err("Signing device has been revoked".to_string());
        }
        // Only the identity's first device (fingerprint == identity id) adds
        // and revokes. Any active device could: a stolen secondary revoked the
        // primary and the siblings (they wiped themselves) and added devices
        // that outlived its own revocation. The first device is never revoked.
        if actor_fp != identity_id {
            return Err("Device add/revoke can only be signed by the identity's primary device".to_string());
        }
        if revoke && subject_fp == identity_id {
            return Err("The primary device cannot be revoked".to_string());
        }
        // A root revokes only its own devices: the signature proves who
        // signed, not that the subject is theirs.
        let subject_owner = self.own_devices.get(subject_fp)
            .or_else(|| self.known_remote_devices.get(subject_fp))
            .map(|d| d.identity_id.as_str())
            .or_else(|| self.verified_device_adds.get(subject_fp).map(|s| s.as_str()));
        if revoke && subject_owner.map_or(false, |owner| owner != identity_id) {
            return Err("Device to revoke does not belong to this identity".to_string());
        }
        let msg = Self::device_auth_signing_bytes(identity_id, subject_fp, actor_fp, revoke);
        verify_hybrid_signature(&msg, sig, sig_pq, &actor)
    }

    /// The "add a device" QR code shown by the second (new) device.
    /// That device has already been through normal onboarding (it created a provisional identity with createIdentity) and has started the network.
    pub(crate) fn build_device_link_request(&mut self) -> Result<Vec<u8>, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let rec = self.own_devices.get(&own_fp).ok_or("Missing own device record")?.clone();
        let rendezvous = self.get_node_address().ok_or("Network address not ready yet")?;
        let known_relays = self.freshest_relays();
        // One nonce per open window: a QR drawn again (the screen retries
        // until the address is ready) must not void the code already scanned.
        if self.link_request_nonce.len() != 16 || current_time_ms() > self.link_request_open_until {
            use rand::RngCore;
            let mut nonce = [0u8; 16];
            OsRng.fill_bytes(&mut nonce);
            self.link_request_nonce = nonce.to_vec();
            self.link_consent_peer = None;
            self.meta_put("link_request_nonce", &hex::encode(nonce));
            // see `first_contact_secrets`: the first device answers to the
            // mailbox made from this nonce.
            self.server_sweep_at = 0;
        }
        // See the packet.rs DeviceLinkRequest docs: fingerprint only. The public keys are no longer carried, because they exceeded the QR capacity.
        let req = DeviceLinkRequest {
            version: DeviceLinkRequest::CURRENT_VERSION,
            device_name: rec.device_name,
            device_fingerprint: own_fp,
            rendezvous_node: rendezvous,
            known_relays,
            nonce: self.link_request_nonce.clone(),
        };
        self.set_link_request_open_until(current_time_ms() + LINK_REQUEST_WINDOW_MS);
        req.to_cbor()
    }

    /// Called on the primary (approved) device when it scans the QR of the secondary device (fingerprint only; see the packet.rs DeviceLinkRequest docs).
    /// It ONLY connects here: it marks `pending_link_target` and sends our own `IdentityExchange`. The new device's REAL public keys (and so the
    /// fingerprint check, the signed DeviceAdd, DeviceLinkGrant / full sync, and the announcement to contacts) are completed when the counterpart's
    /// IdentityExchange arrives, in the `is_pending_link` arm of `process_identity_exchange`. For the same reason as the "pairing WIP" note in
    /// `process_qr_packet`, this function returns WITHOUT waiting for that handshake.
    pub(crate) fn approve_device_link(&mut self, request_cbor: &[u8]) -> Result<(String, String), String> {
        let req = DeviceLinkRequest::from_cbor(request_cbor)?;
        if req.nonce.len() != 16 {
            return Err("Invalid device link code (nonce)".to_string());
        }
        if !is_fingerprint_hex(&req.device_fingerprint) {
            return Err("Invalid device code".to_string());
        }
        let my_id = self.my_identity_id().ok_or("Create an identity first")?;
        let own_fp = self.get_active_own_device_fingerprint()?;
        // Before any side effect: on a secondary the link can
        // never complete (`sign_device_add` refuses), and both devices waited
        // an hour with no error shown.
        if own_fp != my_id {
            return Err("Only the primary device can do this".to_string());
        }
        if req.device_fingerprint == own_fp {
            return Err("This is already this device".to_string());
        }
        // Active device limit. Note: unlike `sibling_active_devices`, this does NOT leave out siblings that have not been seen for a week. They are still active.
        let active_count = 1 + self.known_remote_devices.values()
            .filter(|d| d.identity_id == my_id && d.is_active && d.device_fingerprint != own_fp)
            .count();
        if active_count >= identity::MAX_ACTIVE_DEVICES {
            return Err(format!("At most {} active devices allowed", identity::MAX_ACTIVE_DEVICES));
        }
        let new_fp = req.device_fingerprint.clone();

        // The device may first have been paired as a contact, under the identity it had before the link (its own fingerprint). That contact would
        // stay behind as a ghost whose only device is now a sibling. A device belonging to any OTHER contact is not ours to link.
        // Every contact listing it is checked (only the first match used to be looked at).
        // The ghost is deleted only once the device consents (see the `is_pending_link` arm of `process_identity_exchange`), so scanning the wrong
        // QR cannot cost a contact.
        let foreign = self.contacts.values()
            .filter(|c| c.find_device(&new_fp).is_some())
            .any(|c| c.trusted_identity_id != new_fp || self.contact_fingerprints_all(c).iter().any(|f| *f != new_fp));
        if foreign {
            return Err("This device belongs to one of your contacts".to_string());
        }

        self.dial_pairing_addr(&new_fp, &req.rendezvous_node, &req.known_relays);

        // pending_link_target: the next IdentityExchange from this fingerprint must be processed as a SIBLING device, not as a contact, and the
        // linking flow (DeviceAdd / DeviceLinkGrant / announcement) completes there. See `PENDING_LINK_RETRY_HORIZON_MS`: the window runs from this
        // moment (re-scanning the QR refreshes it).
        self.set_pending_link(Some(new_fp.clone()));
        // Goes back in the grant: it proves that grant answers this QR.
        self.pending_link_nonce = req.nonce.clone();
        self.meta_put("pending_link_nonce", &hex::encode(&req.nonce));
        // Kept after the link: see `first_contact_secrets`.
        if req.nonce.len() == 16 {
            self.put_pairing_secret("pn", &new_fp, &req.nonce);
            self.server_sweep_at = 0;
        }
        // Fresh: after a failed link or an unlink, the identical packet of the
        // earlier attempt still counted as deposited and was not sent.
        if let Err(e) = self.send_identity_exchange_fresh(&new_fp) {
            error!("IdentityExchange send temporarily failed (will retry): {}", e);
        }

        Ok((new_fp, sanitize_display_name(&req.device_name).unwrap_or_default()))
    }

    /// Builds a `SyncedDevice` from a `DeviceRecord` (for sync and announcements).
    pub(crate) fn synced_device_from_record(&self, rec: &DeviceRecord) -> SyncedDevice {
        SyncedDevice {
            device_fingerprint: rec.device_fingerprint.clone(),
            device_name: rec.device_name.clone(),
            sign_pubkey_ed25519: rec.sign_pubkey_ed25519.clone(),
            sign_pubkey_mldsa: rec.sign_pubkey_mldsa.clone(),
            kem_pubkey_x25519: rec.kem_pubkey_x25519.clone(),
            kem_pubkey_mlkem: rec.kem_pubkey_mlkem.clone(),
            is_active: rec.is_active,
            // onion only — never republish a clearnet/UPnP address.
            last_addr: self.device_onion_addr.get(&rec.device_fingerprint).cloned(),
            // Only `synced_for_sibling` fills it: this record also travels
            // unsealed (`IdentityExchange.device_add_signer`) and to contacts.
            mailbox_secrets: Vec::new(),
        }
    }

    /// `synced_device_from_record` for a `SyncPayload`: with the secrets of
    /// the device's first-contact mailbox (see `SyncedDevice.mailbox_secrets`).
    pub(crate) fn synced_for_sibling(&self, rec: &DeviceRecord) -> SyncedDevice {
        let mut sd = self.synced_device_from_record(rec);
        sd.mailbox_secrets = self.stored_pairing_secrets(&rec.device_fingerprint).iter().map(hex::encode).collect();
        sd
    }

    /// The receiving half of `synced_for_sibling`: kept where this device
    /// has none of its own for `sd` (first as `pn:`, second as `pk:`).
    pub(crate) fn import_mailbox_secrets(&self, sd: &SyncedDevice) {
        if !self.stored_pairing_secrets(&sd.device_fingerprint).is_empty() {
            return;
        }
        let valid = sd.mailbox_secrets.iter().filter(|s| s.len() == 32 && hex::decode(s).is_ok());
        for (kind, secret) in ["pn", "pk"].iter().zip(valid) {
            self.meta_put(&format!("{}:{}", kind, sd.device_fingerprint), secret);
        }
    }

    /// THIS device's own `SyncedDevice`. It is sent to contacts in a `DeviceAddNotice`, so they can reliably learn our keys.
    pub(crate) fn own_synced_device(&self) -> Option<SyncedDevice> {
        let own_fp = self.get_active_own_device_fingerprint().ok()?;
        self.own_devices.get(&own_fp).map(|r| self.synced_device_from_record(r))
    }

    pub(crate) fn synced_device_for(&self, fp: &str) -> Option<SyncedDevice> {
        self.own_devices.get(fp)
            .or_else(|| self.known_remote_devices.get(fp))
            .map(|r| self.synced_device_from_record(r))
    }
}

impl P2PCore {

    /// Adoption by a secondary device. Returns `true` if it was adopted for the first time (the UI should be told), or `false` if it was already
    /// adopted (only an Ack; do not announce again).
    pub(crate) fn adopt_device_link(&mut self, primary_fp: &str, identity_id: &str, device_add: &DeviceAdd, sync: &SyncPayload, nonce: &[u8]) -> Result<bool, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        if device_add.identity_id != identity_id
            || device_add.new_device_fingerprint != own_fp
            || device_add.added_by != primary_fp {
            return Err("DeviceLinkGrant fields inconsistent".to_string());
        }
        // Verify the signature with the primary device's key (learned from the IdentityExchange during pairing).
        self.verify_device_auth(identity_id, &own_fp, primary_fp, &device_add.signature, &device_add.signature_pq, false)?;
        // Our own half, given to the device that read our code: without it
        // nobody else accepts this add.
        let own_rec = self.own_devices.get(&own_fp).ok_or("Missing own device record")?;
        if !Self::add_has_consent(device_add, &own_rec.sign_pubkey_ed25519, &own_rec.sign_pubkey_mldsa) {
            return Err("DeviceLinkGrant rejected: this device has no consent signature".to_string());
        }

        // Already adopted: idempotent. Only merge the sync.
        let already = self.my_identity_id().as_deref() == Some(identity_id) && self.own_device_add.is_some();
        if already {
            self.import_sync_payload(sync);
            return Ok(false);
        }
        // Any device with a session to us can send a grant signed by itself;
        // the nonce below ties it to the QR the user showed. Adopting it hands that identity our contacts, groups,
        // archive key and (on request) all history. So a device that already
        // has contacts of its own is never moved to another identity.
        if self.contacts.values().any(|c| c.trusted_identity_id != identity_id) {
            return Err("DeviceLinkGrant rejected: this device has its own contacts, cannot link to another identity".to_string());
        }
        if current_time_ms() > self.link_request_open_until {
            return Err("Unsolicited DeviceLinkGrant: this device is not showing a link QR".to_string());
        }
        // The nonce is in the QR only: a grant without it comes from a device
        // that did not scan the code this device is showing.
        if self.link_request_nonce.len() != 16 || nonce != self.link_request_nonce.as_slice() {
            return Err("DeviceLinkGrant rejected: nonce does not match the QR".to_string());
        }
        let old_id = self.my_identity_id().unwrap_or_default();
        // During pairing, the primary may have been temporarily saved as a CONTACT. Remove it, since it is now a sibling device.
        let primary_cid = self.identity_to_contact.get(identity_id).cloned();
        // Disk FIRST, in one transaction: identities (yeni id) + own_devices
        // (yeni identity_id) + the primary's contact row. On failure nothing
        // changed, in memory or on disk, and the link window stays open: the
        // primary must not believe in a link this device forgets on restart.
        if let Some(conn) = self.db.as_ref() {
            let tx = conn.unchecked_transaction().map_err(|e| format!("Identity exchange could not be written to disk: {}", e))?;
            tx.execute("DELETE FROM identities WHERE id = ?1", params![old_id])
                .and_then(|_| tx.execute(
                    "INSERT OR REPLACE INTO identities (id, primary_device) VALUES (?1, ?2)",
                    params![identity_id, device_add.added_by],
                ))
                .and_then(|_| tx.execute(
                    "UPDATE own_devices SET identity_id = ?1 WHERE device_fingerprint = ?2",
                    params![identity_id, own_fp],
                ))
                .and_then(|_| match &primary_cid {
                    Some(cid) => tx.execute("DELETE FROM contacts WHERE contact_id = ?1", params![cid]),
                    None => Ok(0),
                })
                .and_then(|_| tx.commit())
                .map_err(|e| format!("Identity exchange could not be written to disk: {}", e))?;
        }
        self.set_link_request_open_until(0);
        // Update memory.
        if let Some(id) = self.identity.as_mut() {
            id.identity_id = identity_id.to_string();
            id.primary_device = Some(device_add.added_by.clone());
        }
        if let Some(rec) = self.own_devices.get_mut(&own_fp) {
            rec.identity_id = identity_id.to_string();
        }
        self.identity_to_contact.remove(&old_id);
        if let Some(cid) = primary_cid {
            self.identity_to_contact.remove(identity_id);
            self.contacts.remove(&cid);
        }
        // Link the primary device's record (a sibling) to my identity.
        if let Some(rec) = self.known_remote_devices.get_mut(primary_fp) {
            rec.identity_id = identity_id.to_string();
            rec.is_active = true;
            let rec2 = rec.clone();
            self.persist_remote_device(&rec2);
        }
        self.own_device_add = Some(device_add.clone());
        self.persist_own_device_add(device_add);

        // Import contacts, groups and siblings, then introduce myself to everyone.
        self.import_sync_payload(sync);
        self.announce_self_to_all_contacts();
        // The sibling devices I learned about should also know me and each other (3+ devices).
        self.sync_to_siblings();
        info!("This device linked to identity {} as a secondary device", crate::log_id(&identity_id));
        Ok(true)
    }

    pub(crate) fn apply_device_add_notice(&mut self, device_add: &DeviceAdd, device: &SyncedDevice, sender_identity_id: &str) -> Result<(), String> {
        self.verify_device_auth(
            &device_add.identity_id, &device_add.new_device_fingerprint, &device_add.added_by,
            &device_add.signature, &device_add.signature_pq, false,
        )?;
        if self.owner_revoked(&device_add.identity_id, &device_add.new_device_fingerprint) {
            return Err("DeviceAddNotice: device was revoked by its owner".to_string());
        }
        // Do the transferred keys match the claimed fingerprint?
        if device.device_fingerprint != device_add.new_device_fingerprint {
            return Err("DeviceAddNotice: device fingerprint does not match DeviceAdd".to_string());
        }
        if !device.keys_match_fingerprint() {
            return Err("DeviceAddNotice: keys inconsistent with fingerprint".to_string());
        }
        if !Self::add_has_consent(device_add, &device.sign_pubkey_ed25519, &device.sign_pubkey_mldsa) {
            return Err("DeviceAddNotice: added device has no consent signature".to_string());
        }
        // Security / DoS: one contact (identity) must NOT be able to claim an UNLIMITED number of devices, which would make us fan out every message
        // N times to it. If we already know this device (an idempotent repeat), let it through. If it is a NEW device and the identity is already at
        // its active-device maximum, reject it.
        // A device we already hold under another identity, or as revoked, is not moved or revived by a notice. (The DeviceAdd is signed by the
        // CLAIMED identity, so anyone could claim a third party's device this way.) A real move comes with the device's own IdentityExchange.
        if let Some(rec) = self.known_remote_devices.get(&device.device_fingerprint) {
            if rec.identity_id != device_add.identity_id || !rec.is_active {
                return Err("DeviceAddNotice: device is registered under another identity or as revoked".to_string());
            }
        }
        let already_known = self.known_remote_devices.contains_key(&device.device_fingerprint);
        if !already_known {
            let active_for_identity = self.known_remote_devices.values()
                .filter(|d| d.identity_id == device_add.identity_id && d.is_active)
                .count();
            if active_for_identity >= identity::MAX_ACTIVE_DEVICES {
                return Err(format!(
                    "DeviceAddNotice rejected: active device limit for {} reached ({})",
                    device_add.identity_id, identity::MAX_ACTIVE_DEVICES
                ));
            }
            // Revoked records are kept for good (they stop a revival): a
            // contact cycling add+revoke must not grow them without end.
            let all_for_identity = self.known_remote_devices.values()
                .filter(|d| d.identity_id == device_add.identity_id)
                .count();
            if all_for_identity >= 4 * identity::MAX_ACTIVE_DEVICES {
                return Err(format!("DeviceAddNotice rejected: device registration limit hit for {}", device_add.identity_id));
            }
        }
        let now = current_time_ms();
        self.verified_device_adds.insert(device_add.new_device_fingerprint.clone(), device_add.identity_id.clone());
        self.remember_device_add(device_add);
        // Write the keys to known_remote_devices IMMEDIATELY, so fan-out to this device works without waiting for a separate IdentityExchange.
        if !self.known_remote_devices.contains_key(&device.device_fingerprint) {
            let rec = DeviceRecord {
                device_fingerprint: device.device_fingerprint.clone(),
                identity_id: device_add.identity_id.clone(),
                sign_pubkey_ed25519: device.sign_pubkey_ed25519.clone(),
                sign_pubkey_mldsa: device.sign_pubkey_mldsa.clone(),
                kem_pubkey_x25519: device.kem_pubkey_x25519.clone(),
                kem_pubkey_mlkem: device.kem_pubkey_mlkem.clone(),
                device_name: device.device_name.clone(),
                is_active: device.is_active,
                last_seen: now,
            };
            self.persist_remote_device(&rec);
            self.known_remote_devices.insert(device.device_fingerprint.clone(), rec);
        }
        // The address is not signed. Taken for a device new to us, from a
        // device of that identity or of ours: any holder of a contact's
        // DeviceAdd could point that contact's known device at its own onion.
        let sender_ok = sender_identity_id == device_add.identity_id || self.my_identity_id().as_deref() == Some(sender_identity_id);
        if let (Some(addr), true) = (&device.last_addr, !already_known && sender_ok) {
            self.remember_device_addr(&device.device_fingerprint, addr);
        }
        // Add it to the contact's known device list.
        if let Some(cid) = self.identity_to_contact.get(&device_add.identity_id).cloned() {
            if let Some(contact) = self.contacts.get_mut(&cid) {
                if contact.find_device(&device_add.new_device_fingerprint).is_none() {
                    contact.add_device_via_signed_chain(device_add.new_device_fingerprint.clone(), now);
                }
            }
            if let Some(contact) = self.contacts.get(&cid) { self.persist_contact(contact); }
        }
        Ok(())
    }

    /// Returns `true` if this was a revocation of THIS device (all local state was erased; the caller must emit the `self_revoked` event), or
    /// `false` for an ordinary revocation of another identity's or device's entry.
    pub(crate) fn apply_device_revoke_notice(&mut self, revoke: &DeviceRevoke, sender_fp: &str) -> Result<bool, String> {
        self.verify_device_auth(
            &revoke.identity_id, &revoke.revoked_device_fingerprint, &revoke.revoked_by,
            &revoke.signature, &revoke.signature_pq, true,
        )?;
        // Does this revoke target THIS device? Then all local state is wiped.
        // The signature is the authority; the wipe also needs the notice to
        // come from one of my own devices, as a second lock on an action that
        // cannot be undone.
        let my_id = self.my_identity_id();
        let own_fp = self.get_active_own_device_fingerprint().ok();
        let is_self = my_id.as_deref() == Some(revoke.identity_id.as_str())
            && own_fp.as_deref() == Some(revoke.revoked_device_fingerprint.as_str());
        if is_self {
            let from_sibling = self.known_remote_devices.get(sender_fp)
                .map_or(false, |d| d.is_active && Some(&d.identity_id) == my_id.as_ref());
            if !from_sibling {
                return Err("Our own revocation came from a non-sibling device".to_string());
            }
            warn!(
                "THIS DEVICE was revoked by its own identity ({}) (revoked_by={}) — wiping all local state",
                crate::log_id(&revoke.identity_id), crate::log_id(&revoke.revoked_by)
            );
            self.wipe_all_local_state();
            // Every path that brings our own revoke (a notice, or one carried
            // back in an IdentityExchange) must tell the UI: that one returned
            // nothing, so the frontend kept its vault key and showed the
            // wiped chats until restart.
            self.attachment_events.push(serde_json::json!({"type": "self_revoked"}).to_string());
            return Ok(true);
        }
        if my_id.as_deref() == Some(revoke.identity_id.as_str()) {
            self.remember_own_revoke(revoke);
        }
        let now = current_time_ms();
        if let Some(cid) = self.identity_to_contact.get(&revoke.identity_id).cloned() {
            if let Some(contact) = self.contacts.get_mut(&cid) {
                contact.revoke_device_by_owner(&revoke.revoked_device_fingerprint, now);
            }
            if let Some(contact) = self.contacts.get(&cid) { self.persist_contact(contact); }
        } else if my_id.as_deref() != Some(revoke.identity_id.as_str()) {
            // no contact to hold the tombstone (a group member): its old
            // DeviceAdd must not bring the device back either.
            // ponytail: one app_meta row per such revoke, never pruned; each
            // is signed by the identity, so only group members can add them.
            // With the time: `group_author_proof_valid` takes the device's
            // proofs only for rows dated before it.
            self.meta_put(&format!("orv:{}", revoke.revoked_device_fingerprint), &format!("{}|{}", revoke.identity_id, now));
        }
        if let Some(rec) = self.known_remote_devices.get_mut(&revoke.revoked_device_fingerprint) {
            rec.is_active = false;
            let rec2 = rec.clone();
            self.persist_remote_device(&rec2);
        }
        self.verified_device_adds.remove(&revoke.revoked_device_fingerprint);
        // Nothing queued may still reach the revoked device.
        self.drop_device_sessions(&revoke.revoked_device_fingerprint);
        self.rekey_archive_to_canonical(&revoke.identity_id);
        Ok(false)
    }
}
