//! Contacts, blocking, device alerts, profile, account/contact deletion and wipe.

use super::*;

impl P2PCore {

    /// See the file-top note: the `contacts` table was never written before, so the contact list was lost on every restart (including app updates).
    /// Called from every mutation point (register_contact_from_pairing, evaluate_sender_device, accept_pending_device_alert).
    pub(crate) fn persist_contact(&self, contact: &Contact) {
        if let Err(e) = self.try_persist_contact(contact) {
            error!("Kişi kaydedilemedi: {}", e);
        }
    }

    pub(crate) fn try_persist_contact(&self, contact: &Contact) -> Result<(), String> {
        let conn = match &self.db {
            Some(c) => c,
            None => return Ok(()),
        };
        let known_devices_json = serde_json::to_string(&contact.known_devices).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO contacts (contact_id, display_name, trusted_identity_id, known_devices_json, last_device_change, avatar_jpeg, added_via_group)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                contact.contact_id, contact.display_name, contact.trusted_identity_id,
                known_devices_json, contact.last_device_change.map(|v| v as i64), contact.avatar_jpeg,
                contact.added_via_group as i32,
            ],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// On startup, restores all contacts stored in the DB into `self.contacts` / `self.identity_to_contact`.
    pub(crate) fn load_contacts_from_db(&mut self) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let mut stmt = match conn.prepare(
            "SELECT contact_id, display_name, trusted_identity_id, known_devices_json, last_device_change, avatar_jpeg, added_via_group FROM contacts ORDER BY rowid"
        ) {
            Ok(s) => s,
            Err(e) => { log::error!("contacts could not be loaded: {e}"); return }
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                // Old rows have NULL here. They count as directly added (false).
                row.get::<_, Option<i64>>(6)?.unwrap_or(0) != 0,
            ))
        });
        let mut loaded = Vec::new();
        if let Ok(rows) = rows {
            for row in rows {
                // A row that does not load is left alone on disk and logged.
                // Loaded with an empty device list it was written back that
                // way by the next `persist_contact`.
                let (contact_id, display_name, trusted_identity_id, known_devices_json, last_device_change, avatar_jpeg, added_via_group) = match row {
                    Ok(r) => r,
                    Err(e) => { error!("Kişi satırı okunamadı, atlandı: {}", e); continue; }
                };
                let known_devices: Vec<contact::KnownDevice> = match serde_json::from_str(&known_devices_json) {
                    Ok(d) => d,
                    Err(e) => { error!("Kişi {} cihaz listesi okunamadı, atlandı: {}", contact_id, e); continue; }
                };
                // Rows written before the write path checked these.
                if !is_fingerprint_hex(&trusted_identity_id) {
                    error!("Kişi {} geçersiz kimlikle kayıtlı, atlandı", contact_id);
                    continue;
                }
                let display_name = sanitize_display_name(&display_name).unwrap_or_default();
                loaded.push(Contact {
                    contact_id,
                    display_name,
                    trusted_identity_id,
                    known_devices,
                    last_device_change: last_device_change.map(|v| v as u64),
                    avatar_jpeg,
                    added_via_group,
                });
            }
        }
        for contact in loaded {
            // Two rows for one identity: the older row stays the contact.
            if self.identity_to_contact.contains_key(&contact.trusted_identity_id) {
                warn!("Kişi {} aynı kimliğin ikinci satırı, yüklenmedi", contact.contact_id);
                continue;
            }
            self.identity_to_contact.insert(contact.trusted_identity_id.clone(), contact.contact_id.clone());
            self.contacts.insert(contact.contact_id.clone(), contact);
        }
    }

    /// See the `persist_contact` note at the top of the file. `known_remote_devices` (the PUBLIC keys of known remote devices; not secret, so no encryption
    /// needed) was not persistent either. Signature verification and re-handshakes depend on these records, so when they were lost on restart, even messaging an
    /// existing contact was impossible until a new IdentityExchange arrived.
    pub(crate) fn persist_remote_device(&self, device: &DeviceRecord) {
        if let Err(e) = self.try_persist_remote_device(device) {
            error!("Cihaz kaydı yazılamadı: {}", e);
        }
    }

    pub(crate) fn try_persist_remote_device(&self, device: &DeviceRecord) -> Result<(), String> {
        let conn = match &self.db {
            Some(c) => c,
            None => return Ok(()),
        };
        conn.execute(
            "INSERT OR REPLACE INTO remote_devices
             (device_fingerprint, identity_id, sign_pk_ed25519, sign_pk_mldsa, kem_pk_x25519, kem_pk_mlkem,
              device_name, is_active, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                device.device_fingerprint, device.identity_id,
                device.sign_pubkey_ed25519, device.sign_pubkey_mldsa,
                device.kem_pubkey_x25519, device.kem_pubkey_mlkem,
                device.device_name, device.is_active as i32, device.last_seen as i64,
            ],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub(crate) fn load_remote_devices_from_db(&mut self) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let mut stmt = match conn.prepare(
            "SELECT device_fingerprint, identity_id, sign_pk_ed25519, sign_pk_mldsa, kem_pk_x25519, kem_pk_mlkem,
                    device_name, is_active, last_seen FROM remote_devices"
        ) {
            Ok(s) => s,
            Err(e) => { log::error!("remote_devices could not be loaded: {e}"); return }
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                row.get::<_, String>(6)?, row.get::<_, i32>(7)?, row.get::<_, i64>(8)?,
            ))
        });
        let mut loaded = Vec::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (fp, identity_id, sign_pk_ed, sign_pk_mldsa, kem_pk_x, kem_pk_mlkem, device_name, is_active, last_seen) = row;
                loaded.push(DeviceRecord {
                    device_fingerprint: fp,
                    identity_id,
                    sign_pubkey_ed25519: sign_pk_ed,
                    sign_pubkey_mldsa: sign_pk_mldsa,
                    kem_pubkey_x25519: kem_pk_x,
                    kem_pubkey_mlkem: kem_pk_mlkem,
                    device_name,
                    is_active: is_active != 0,
                    last_seen: last_seen as u64,
                });
            }
        }
        for device in loaded {
            self.known_remote_devices.insert(device.device_fingerprint.clone(), device);
        }
    }

    // ---------------------------------------------------------------
    // Section 2: TOFU and device-change detection
    // ---------------------------------------------------------------

    /// Applies the  decision tree to the sending device of an incoming packet.
    /// `sender_device_known_pubkeys`: must be downloaded from the other side or already known before this function is called (needed for signature verification).
    pub(crate) fn evaluate_sender_device(&mut self, identity_id: &str, device_fingerprint: &str, has_valid_signed_device_add: bool, device_name_hint: &str, pairing_proved: bool) -> DeviceCheckOutcome {
        let contact_id = self.identity_to_contact.get(identity_id).cloned();
        let contact = contact_id.as_ref().and_then(|id| self.contacts.get(id));
        let outcome = check_incoming_device(contact, device_fingerprint, has_valid_signed_device_add);

        let now = current_time_ms();
        match outcome {
            DeviceCheckOutcome::NewContactTofu => {
                // Deleted on this device: only a code the user scans or types
                // brings the contact back (`pair_with_code`). The peer still
                // has us and sends its IdentityExchange on every reconnect,
                // which used to recreate the contact within seconds.
                if self.contact_removed_locally(identity_id) {
                    info!("TOFU reddedildi: {} bu cihazda silinmiş bir kişi", crate::log_id(&identity_id));
                    return DeviceCheckOutcome::UnverifiedNewDeviceAlert;
                }
                // see `pairing_proof_valid`: only a device that read a code
                // this device shows becomes a contact.
                if !pairing_proved {
                    info!("TOFU reddedildi: gönderen bu cihazın kodunu okumamış ({})", crate::log_id(&identity_id));
                    return DeviceCheckOutcome::UnverifiedNewDeviceAlert;
                }
                // See `MAX_CONTACTS`: protection against Sybil/flood, especially for TOFU records created by one-sided `IdentityExchange` packets that need no user action.
                if self.contacts.len() >= MAX_CONTACTS {
                    warn!(
                        "TOFU reddedildi: contacts tablosu üst sınırda ({} >= {}), identity {} eklenmedi",
                        self.contacts.len(), MAX_CONTACTS, crate::log_id(&identity_id)
                    );
                    // the sender read our code, the user here waits
                    // for a contact that never comes: say why.
                    self.attachment_events.push(serde_json::json!({
                        "type": "pairing_failed", "reason": "contact_limit"
                    }).to_string());
                    // "Blocked", without an alert. Returning `NewContactTofu`
                    // let the caller store the device record anyway, so
                    // `remote_devices` grew without limit under a flood.
                    return DeviceCheckOutcome::UnverifiedNewDeviceAlert;
                } else if let Err(e) = self.register_contact_from_pairing(identity_id.to_string(), device_fingerprint.to_string(), device_name_hint.to_string()) {
                    warn!("TOFU reddedildi: {}", e);
                    return DeviceCheckOutcome::UnverifiedNewDeviceAlert;
                }
            }
            DeviceCheckOutcome::NewDeviceViaSignedAdd => {
                if let Some(cid) = &contact_id {
                    if let Some(c) = self.contacts.get_mut(cid) {
                        c.add_device_via_signed_chain(device_fingerprint.to_string(), now);
                    }
                    if let Some(c) = self.contacts.get(cid) {
                        self.persist_contact(c);
                    }
                }
                // Spec 2.2: "only an information notice is shown", not an alarm.
                info!("Identity {} yeni bir cihaz ekledi: {}", crate::log_id(&identity_id), crate::log_id(&device_fingerprint));
            }
            DeviceCheckOutcome::UnverifiedNewDeviceAlert => {
                // Listed but not Active: the user rejected or revoked this
                // device (or its owner did). It stays blocked and does not
                // prompt again; each repeated prompt made an "accept" by
                // mistake more likely.
                if contact.map_or(false, |c| c.find_device(device_fingerprint).is_some()) {
                    return outcome;
                }
                let display_name = contact_id
                    .as_ref()
                    .and_then(|cid| self.contacts.get(cid))
                    .map(|c| c.display_name.clone())
                    .unwrap_or_else(|| identity_id.to_string());
                let known_codes: Vec<String> = contact_id
                    .as_ref()
                    .and_then(|cid| self.contacts.get(cid))
                    .map(|c| c.known_devices.iter()
                        .filter_map(|d| hex::decode(&d.device_fingerprint).ok())
                        .map(|raw| identity::format_short_code(&raw))
                        .collect())
                    .unwrap_or_default();
                let new_code = hex::decode(device_fingerprint)
                    .map(|raw| identity::format_short_code(&raw))
                    .unwrap_or_else(|_| device_fingerprint.to_string());

                // See `MAX_PENDING_DEVICE_ALERTS`. Updating an existing alert for the same fingerprint is always allowed (it does not add to the alert count). Only a
                // brand-new fingerprint is silently dropped when the cap is full. The packet stays BLOCKED as the  requires (only no alert is shown in the UI).
                // Per identity too: unsigned claims with made-up keys cost the sender nothing, and 200 of them against one contact used up the whole cap, so a real
                // alert for another contact was lost.
                let for_this_identity = self.pending_device_alerts.values().filter(|a| a.identity_id == identity_id).count();
                if self.pending_device_alerts.contains_key(device_fingerprint)
                    || (self.pending_device_alerts.len() < MAX_PENDING_DEVICE_ALERTS && for_this_identity < 3)
                {
                    // User decision (2026-08-27): the alert is no longer silent. Before, it was only written to the `pending_device_alerts` map, and the UI had to
                    // open the settings screen and query the list to notice it, so in practice nobody saw it. It now also goes to the event stream. Both UIs show it
                    // as a popup or notification and ask accept or reject.
                    let is_new = !self.pending_device_alerts.contains_key(device_fingerprint);
                    self.pending_device_alerts.insert(device_fingerprint.to_string(), DeviceAlertInfo {
                        contact_display_name: display_name.clone(),
                        identity_id: identity_id.to_string(),
                        new_device_fingerprint: device_fingerprint.to_string(),
                        known_device_short_codes: known_codes,
                        new_device_short_code: new_code.clone(),
                    });
                    if is_new {
                        self.attachment_events.push(serde_json::json!({
                            "type": "device_alert",
                            "identity_id": identity_id,
                            "contact_display_name": display_name,
                            "device_fingerprint": device_fingerprint,
                            "device_short_code": new_code,
                        }).to_string());
                        self.persist_device_alerts();
                    }
                } else {
                    warn!(
                        "pending_device_alerts üst sınırda ({} >= {}), identity {} için yeni uyarı düşürüldü (paket yine de bloklu kalır)",
                        self.pending_device_alerts.len(), MAX_PENDING_DEVICE_ALERTS, crate::log_id(&identity_id)
                    );
                }
                // Spec: "BLOCK (new messages stop being sent or received)". The packet is not processed from or to this device. It waits in `pending_device_alerts`,
                // and the user must accept or reject it in the UI.
            }
            DeviceCheckOutcome::KnownActive => {}
        }
        outcome
    }

    pub(crate) fn load_blocked_from_db(&mut self) {
        let Some(conn) = &self.db else { return };
        if let Ok(mut stmt) = conn.prepare("SELECT identity_id FROM deleted_identities") {
            if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                self.deleted_identities = rows.flatten().collect();
            }
        }
        let Ok(mut stmt) = conn.prepare("SELECT identity_id FROM blocked_identities") else { return };
        let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) else { return };
        self.blocked_identities = rows.flatten().collect();
        if !self.blocked_identities.is_empty() {
            info!("{} engellenen kimlik yüklendi", self.blocked_identities.len());
        }
    }

    /// See `blocked_identities`. Blocking targets the contact, not the device.
    pub(crate) fn is_blocked(&self, identity_id: &str) -> bool {
        self.blocked_identities.contains(identity_id)
    }

    /// Looks up the identity for a device fingerprint and checks whether it is blocked. Used on the incoming packet path.
    pub(crate) fn is_blocked_device(&self, device_fingerprint: &str) -> bool {
        match self.known_remote_devices.get(device_fingerprint) {
            Some(d) => self.is_blocked(&d.identity_id),
            None => false,
        }
    }

    /// Blocks a contact: sessions and queues to all of its devices are deleted, pending "new device" alerts are cleared, and it is never connected to again.
    /// The difference from `delete_contact` is that the block SURVIVES deleting the contact.
    pub(crate) fn block_identity(&mut self, identity_id: &str) -> Result<(), String> {
        if self.my_identity_id().as_deref() == Some(identity_id) {
            return Err("Kendi kimliğinizi engelleyemezsiniz".to_string());
        }
        // Disk first: a block that is gone after a restart must not look done.
        if let Some(conn) = &self.db {
            conn.execute(
                "INSERT OR REPLACE INTO blocked_identities (identity_id, blocked_at) VALUES (?1, ?2)",
                params![identity_id, current_time_ms() as i64],
            ).map_err(|e| format!("Engel kaydedilemedi: {}", e))?;
        }
        self.blocked_identities.insert(identity_id.to_string());
        let fps: Vec<String> = self.known_remote_devices.values()
            .filter(|d| d.identity_id == identity_id)
            .map(|d| d.device_fingerprint.clone())
            .collect();
        for fp in &fps {
            // Session, topic subscription, queues, addresses, downloads and
            // the live connection.
            self.drop_device_sessions(fp);
        }
        self.pending_device_alerts.retain(|_, a| a.identity_id != identity_id);
        self.persist_device_alerts();
        // Group queues are keyed by IDENTITY, not by device, so the device loop above does not catch them.
        self.pending_group_messages.retain(|(_, member), _| member != identity_id);
        self.pending_group_syncs.retain(|(_, member), _| member != identity_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM pending_group_messages WHERE member_identity_id = ?1",
                params![identity_id],
            );
        }
        warn!("Kimlik ENGELLENDİ: {} ({} cihaz)", crate::log_id(&identity_id), fps.len());
        Ok(())
    }

    /// Lifts a block. Deliberately called only from a face-to-face re-pairing (`register_contact_from_pairing`, i.e. QR or manual code) and on the user's explicit
    /// request. No packet from the network can reach this function.
    pub(crate) fn unblock_identity(&mut self, identity_id: &str) {
        if self.blocked_identities.contains(identity_id) {
            // Disk first: lifted only in memory, the block came back on restart.
            if let Some(conn) = &self.db {
                if let Err(e) = conn.execute("DELETE FROM blocked_identities WHERE identity_id = ?1", params![identity_id]) {
                    error!("Kimlik engeli kaldırılamadı: {}", e);
                    return;
                }
            }
            self.blocked_identities.remove(identity_id);
            info!("Kimlik engeli kaldırıldı: {}", crate::log_id(&identity_id));
            // The block dropped the sessions. Without a new handshake here
            // the peer's packets were only buffered until the user opened
            // the chat.
            let fps: Vec<String> = self.identity_to_contact.get(identity_id)
                .and_then(|cid| self.contacts.get(cid))
                .map(|c| c.known_devices.iter()
                    .filter(|d| d.status == contact::KnownDeviceStatus::Active)
                    .map(|d| d.device_fingerprint.clone()).collect())
                .unwrap_or_default();
            for fp in fps {
                let _ = self.ensure_handshake(&fp);
            }
        }
    }

    pub(crate) fn list_blocked_identities(&self) -> Vec<String> {
        self.blocked_identities.iter().cloned().collect()
    }

    /// Called when the user taps "Re-verify and accept" on the alert screen.
    pub(crate) fn accept_pending_device_alert(&mut self, device_fingerprint: &str) -> Result<(), String> {
        let identity_id = self.pending_device_alerts.get(device_fingerprint)
            .ok_or("No pending alert for this device")?.identity_id.clone();
        // The alert is removed only once the contact is found: an error
        // must leave it for the user to answer again.
        let contact_id = self.identity_to_contact.get(&identity_id).cloned()
            .ok_or("Unknown contact")?;
        self.pending_device_alerts.remove(device_fingerprint);
        self.persist_device_alerts();
        if let Some(c) = self.contacts.get_mut(&contact_id) {
            c.add_device_unverified(device_fingerprint.to_string(), current_time_ms());
        }
        if let Some(c) = self.contacts.get(&contact_id) {
            self.persist_contact(c);
        }
        self.rekey_archive_to_canonical(&identity_id);
        // The IdentityExchange that raised the alert was dropped before its
        // keys were stored, so there is no `known_remote_devices` record and
        // the accepted device could neither send nor receive. Ask again, as a
        // pairing does: the peer answers our IdentityExchange with its own,
        // which now passes as `KnownActive`.
        self.subscribe_pairing_mailbox(device_fingerprint);
        if let Err(e) = self.send_identity_exchange_fresh(device_fingerprint) {
            error!("IdentityExchange gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
        }
        Ok(())
    }

    /// Called when the user taps "Reject" (the default behaviour, ).
    pub(crate) fn reject_pending_device_alert(&mut self, device_fingerprint: &str) {
        let Some(alert) = self.pending_device_alerts.remove(device_fingerprint) else { return };
        self.persist_device_alerts();
        // Remembered as a revoked entry of the contact, so the next
        // IdentityExchange of the device does not raise the alert again
        // (`evaluate_sender_device`). Scanning its code still brings it back.
        let Some(cid) = self.identity_to_contact.get(&alert.identity_id).cloned() else { return };
        if let Some(c) = self.contacts.get_mut(&cid) {
            if c.find_device(device_fingerprint).is_none() {
                let now = current_time_ms();
                c.add_device_unverified(device_fingerprint.to_string(), now);
                c.revoke_device(device_fingerprint, now);
                let c = c.clone();
                self.persist_contact(&c);
            }
        }
    }

    pub(crate) fn list_pending_device_alerts(&self) -> Vec<DeviceAlertInfo> {
        self.pending_device_alerts.values().cloned().collect()
    }

    /// Returns the known contacts for the UI's "who should I start a chat with" picker list. Each contact includes that identity's known (in phase A, the only)
    /// Active device fingerprint. The chat screen passes this fingerprint to `sendMessage` as the target.
    /// User decision (2026-08-27): a contact met through a group gets FULL trust.
    /// Contacts with `added_via_group` are marked in the UI as "added via group, not verified face to face", because we learned them through the founder's vouching,
    /// not by scanning a code. If the user verified that person by another route (comparing the security number in person, or confirming by phone), they must be able
    /// to remove this mark. It only affects display, not encryption.
    /// The SAFETY CODE of a contact is what gets compared. The code is derived from the fingerprint of the contact's canonical device, and that fingerprint is the
    /// SHA3-256 of four public keys (see `compute_fingerprint`). So a matching code means both sides really saw the same keys. That is the only concrete proof the
    /// "mark as verified" action rests on.
    /// Why it is needed: for contacts met through a group we take the keys from the founder. If the founder is malicious, it can hand over its own key as "Ayse's".
    /// There is NO cryptographic way to tell that apart, only comparing the code over another channel. Without showing this code, offering "verified" would be meaningless.
    pub(crate) fn contact_safety_code(&self, identity_id: &str) -> Option<String> {
        let fp = self.canonical_device_for_identity(identity_id)?;
        let raw = hex::decode(&fp).ok()?;
        Some(identity::format_short_code(&raw))
    }

    pub(crate) fn trust_contact(&mut self, contact_id: &str) -> Result<(), String> {
        let contact = self.contacts.get_mut(contact_id).ok_or("Kişi bulunamadı")?;
        if !contact.added_via_group {
            return Ok(());
        }
        contact.added_via_group = false;
        let snapshot = contact.clone();
        self.persist_contact(&snapshot);
        info!("Kişiye tam güven verildi: {}", crate::log_id(&snapshot.trusted_identity_id));
        Ok(())
    }

    pub(crate) fn list_contacts(&self) -> Vec<ContactSummary> {
        self.contacts.values().map(|c| ContactSummary {
            contact_id: c.contact_id.clone(),
            display_name: c.display_name.clone(),
            identity_id: c.trusted_identity_id.clone(),
            // Multi-device: a STABLE canonical device, so that a contact's chat and archive merge under ONE key even when the contact has several devices (see
            // `canonical_device_for_identity`). `resolve_*` (order depends on HashMap, so unstable) should not be used here, so that an incoming message stays
            // consistent with the archive key.
            active_device_fingerprint: self.canonical_device_for_identity(&c.trusted_identity_id),
            avatar_hex: c.avatar_jpeg.as_ref().map(|a| hex::encode(a)),
            added_via_group: c.added_via_group,
            account_deleted: self.deleted_identities.contains(&c.trusted_identity_id),
        }).collect()
    }

    /// Returns our own profile picture (if any), so the settings screen can show the current picture.
    pub(crate) fn get_own_avatar(&self) -> Option<Vec<u8>> {
        let conn = self.db.as_ref()?;
        let identity_id = self.identity.as_ref()?.identity_id.clone();
        conn.query_row(
            "SELECT avatar_jpeg FROM identities WHERE id = ?1",
            params![identity_id],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        ).ok().flatten()
    }

    /// This device's account name, as contacts see us.
    /// The name lives in `own_devices.device_name` in the data model (the identity record has NO separate "account name" field, see `identity::Identity`).
    /// Instead of inventing a new field, the existing one is used: the other side already names the contact from the first `IdentityExchange.device_name`, so the
    /// "account name" in this code base was ALREADY this field.
    pub(crate) fn own_display_name(&self) -> Option<String> {
        let fp = self.get_active_own_device_fingerprint().ok()?;
        self.own_devices.get(&fp).and_then(|d| sanitize_display_name(&d.device_name))
    }

    /// Writes the account name LOCALLY to all of my own device records. It does NOT publish. `set_display_name` (when the user changes it) and `import_sync_payload`
    /// (when a sibling device changes it) share this. The second must not publish, or two devices would trigger each other forever.
    pub(crate) fn adopt_own_device_name(&mut self, name: &str) {
        let my_id = match self.my_identity_id() { Some(id) => id, None => return };
        for rec in self.own_devices.values_mut() {
            if rec.identity_id == my_id {
                rec.device_name = name.to_string();
            }
        }
        if let Some(identity) = self.identity.as_mut() {
            for dev in identity.devices.iter_mut() {
                dev.device_name = name.to_string();
            }
        }
        // The `known_remote_devices` copies on sibling devices must carry the same name too, since the contact list and pending-message screens read it from here.
        let sibling_fps: Vec<String> = self.known_remote_devices.values()
            .filter(|d| d.identity_id == my_id && d.device_name != name)
            .map(|d| d.device_fingerprint.clone())
            .collect();
        for fp in sibling_fps {
            if let Some(rec) = self.known_remote_devices.get_mut(&fp) {
                rec.device_name = name.to_string();
                let rec = rec.clone();
                self.persist_remote_device(&rec);
            }
        }
        if let Some(conn) = &self.db {
            if let Err(e) = conn.execute(
                "UPDATE own_devices SET device_name = ?1 WHERE identity_id = ?2",
                params![name, my_id],
            ) {
                error!("Hesap adı yazılamadı: {}", e);
            }
        }
    }

    /// User request (2026-09-04): changes the account name and automatically notifies EVERY known contact of the change.
    /// Before, the name was asked once in the "device name" dialog at first launch, and could NEVER be changed afterwards, neither locally nor on the other side.
    /// Since there is no central directory, the notice goes out with the same fan-out pattern as the avatar (`set_own_profile_picture`): to each contact's each
    /// active device, over the ratchet, as a message awaiting delivery confirmation. So if the contact is offline, it receives the change when it returns, and it is not lost.
    /// `sync_to_siblings` is also called: my own secondary devices learn this device's new name (`SyncedDevice.device_name`).
    /// Called before the account is deleted: sends `AccountDeleted` to all contacts (including those met through a group) and to sibling devices, and hands the founder
    /// role to a remaining member in groups I founded. Returns the number of devices the notice was sent to. Deleting the local data is the UI's job (see `account_deletion_pending`).
    pub(crate) fn delete_account(&mut self) -> Result<usize, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_id = self.my_identity_id().ok_or("No identity")?;
        // The others take `AccountDeleted` from the first device only.
        if own_fp != own_id {
            return Err("Only the primary device can delete the account".to_string());
        }

        let founded: Vec<(String, Option<String>)> = self.groups.values()
            .filter(|g| g.founder_identity_id == own_id)
            .map(|g| {
                let heir = g.other_members(&own_id).into_iter()
                    .find(|m| !self.deleted_identities.contains(m));
                (g.group_id.clone(), heir)
            })
            .collect();
        for (gid, heir) in founded {
            if let Some(heir) = heir {
                if let Err(e) = self.transfer_group_founder(&gid, &heir) {
                    error!("Hesap silme: grup yetkisi devredilemedi ({}): {}", gid, e);
                }
            }
        }

        // Sealed history would otherwise stay on the servers until its TTL.
        // Best effort: an unreachable server keeps it, deletion goes on.
        let server_ids: Vec<String> = self.servers.iter().map(|s| s.server_id.clone()).collect();
        for sid in server_ids {
            self.purge_server_archive(&sid);
        }

        let content = MessageContent::AccountDeleted { deleted_at_ms: current_time_ms() };
        let mut targets: Vec<String> = self.contact_device_targets().into_iter()
            .filter(|fp| self.known_remote_devices.get(fp).map_or(true, |d| !self.deleted_identities.contains(&d.identity_id)))
            .collect();
        targets.extend(self.sibling_active_devices());
        targets.sort();
        targets.dedup();
        let mut sent = 0;
        for fp in targets {
            match self.send_message_content(fp.clone(), &content, None) {
                Ok(_) => sent += 1,
                Err(e) => error!("Hesap silme bildirimi gönderilemedi ({}): {}", crate::log_id(&fp), e),
            }
        }
        Ok(sent)
    }

    /// The number of `AccountDeleted` sends not yet confirmed. The UI waits for this to reach zero (or for an upper time limit) before deleting local data.
    pub(crate) fn account_deletion_pending(&self) -> usize {
        self.awaiting_confirmation.values()
            .filter(|p| matches!(p.regen_content, Some(MessageContent::AccountDeleted { .. })))
            .count()
    }

    /// Applies a contact's `AccountDeleted` notice: marks the identity as permanently deleted, clears the pending queues to it, and removes it from groups I founded.
    /// Returns the affected group ids.
    pub(crate) fn apply_account_deleted(&mut self, identity_id: &str) -> Vec<String> {
        self.deleted_identities.insert(identity_id.to_string());
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO deleted_identities (identity_id, deleted_at) VALUES (?1, ?2)",
                params![identity_id, current_time_ms() as i64],
            );
            let _ = conn.execute(
                "DELETE FROM pending_group_messages WHERE member_identity_id = ?1",
                params![identity_id],
            );
        }
        let fps = self.active_devices_for_identity(identity_id);
        for fp in &fps {
            self.awaiting_confirmation.retain(|_, p| &p.peer_device_fingerprint != fp);
            self.remove_durable_retries_for_peer(fp);
            self.pending_envelopes.retain(|q| &q.target != fp);
        }
        self.pending_group_messages.retain(|(_, member), _| member != identity_id);
        self.pending_group_syncs.retain(|(_, member), _| member != identity_id);

        let own_id = self.my_identity_id().unwrap_or_default();
        let groups: Vec<(String, bool)> = self.groups.values()
            .filter(|g| g.is_member(identity_id))
            .map(|g| (g.group_id.clone(), g.founder_identity_id == own_id))
            .collect();
        for (gid, i_am_founder) in &groups {
            if *i_am_founder {
                if let Err(e) = self.remove_from_group(gid, identity_id, false) {
                    error!("Hesabı silinen üye gruptan çıkarılamadı ({}): {}", gid, e);
                }
            }
        }
        groups.into_iter().map(|(gid, _)| gid).collect()
    }

    pub(crate) fn set_display_name(&mut self, name: &str) -> Result<(), String> {
        let name = sanitize_display_name(name)
            .ok_or_else(|| "Hesap adı boş olamaz".to_string())?;
        // If there is no identity (first launch not finished), there is no record to write the name to: `adopt_own_device_name` would silently do nothing, and the
        // user would see "changed" without knowing it did not.
        self.get_active_own_device_fingerprint()?;
        // The name belongs to the IDENTITY, not to one device: the other side names the contact by `identity_id` (see the `ProfileUpdate` handler). If my two devices
        // kept different names, the name my contacts see would keep flipping depending on which device spoke last. Renaming on the phone and changing a photo on the
        // laptop would silently switch the name back to "Laptop". So a rename updates the records of ALL my devices. It is carried to sibling devices with
        // `sync_to_siblings` (see the sibling loop in `import_sync_payload`, where the name is adopted).
        self.adopt_own_device_name(&name);
        // see `import_sync_payload`: a sibling takes the name only from a
        // sync that is newer than its own last rename.
        self.meta_put("name_changed_at", &current_time_ms().to_string());

        // See packet.rs `ProfileUpdate`: a FULL snapshot, the avatar goes too. Otherwise a name change would delete our photo on the other side.
        let content = MessageContent::ProfileUpdate {
            avatar_jpeg: self.get_own_avatar(),
            display_name: Some(name),
        };
        // The same filter as `set_own_profile_picture`: there is no point sending to revoked devices, since the other side rejects them anyway.
        let peer_fps = self.contact_device_targets();
        for fp in peer_fps {
            if let Err(e) = self.send_message_content(fp.clone(), &content, None) {
                error!("Ad değişikliği bildirilemedi ({}): {}", crate::log_id(&fp), e);
            }
        }
        self.sync_to_siblings();
        Ok(())
    }

    /// Sets or removes our own profile picture (`avatar_jpeg: None`) and sends a new `MessageContent::ProfileUpdate` to EVERY known contact (one by one, since there
    /// is no central directory in P2P). See the packet.rs note. This is triggered only when the user changes the picture, not automatically on every connection (spam prevention).
    pub(crate) fn set_own_profile_picture(&mut self, avatar_jpeg: Option<Vec<u8>>) -> Result<(), String> {
        // See `MAX_AVATAR_BYTES`. An avatar over the limit cannot be published (`MessageTooLarge`, PERMANENT), and the user would never learn why.
        if let Some(a) = &avatar_jpeg {
            if a.len() > MAX_AVATAR_BYTES {
                return Err(format!(
                    "Profil fotoğrafı çok büyük ({} KB) — en fazla {} KB olabilir",
                    a.len() / 1024, MAX_AVATAR_BYTES / 1024
                ));
            }
        }
        let identity_id = self.identity.as_ref().ok_or("Kimlik yok")?.identity_id.clone();
        if let Some(conn) = &self.db {
            conn.execute(
                "UPDATE identities SET avatar_jpeg = ?1 WHERE id = ?2",
                params![avatar_jpeg, identity_id],
            ).map_err(|e| e.to_string())?;
        }
        // `ProfileUpdate` is a FULL snapshot (see the packet.rs note): it has to carry the name too. Otherwise a photo change would leave the name "never announced" on the other side.
        let content = MessageContent::ProfileUpdate { avatar_jpeg, display_name: self.own_display_name() };
        // My other devices store it too (see the `ProfileUpdate` arm): a
        // rename on a sibling sends the photo that sibling holds, and with a
        // stale copy every contact got the old photo back.
        let siblings = self.sibling_active_devices();
        // There was NO `status == Active` filter, so revoked devices also got profile updates. The other side already rejects a revoked sender in `receive_message`, but we
        // should not waste the encryption and 7 days of retries either.
        let peer_fps = self.contact_device_targets();
        for fp in peer_fps {
            if let Err(e) = self.send_message_content(fp.clone(), &content, None) {
                error!("ProfileUpdate gönderilemedi ({}): {}", crate::log_id(&fp), e);
            }
        }
        for fp in siblings {
            let _ = self.send_message_content(fp, &content, None);
        }
        Ok(())
    }

    /// See the `packet.rs` `MessageContent::AddressAnnounce` docs (the bug: "after one of two Tor-enabled devices on the same LAN switches to mobile data and Tor, it cannot
    /// reach anyone"). Same fan-out pattern as `set_own_profile_picture`: sends our CURRENT `get_node_address()` to EVERY known contact. If there is no address yet (no
    /// listen address reported), it is a silent no-op. Callers: once after `start_network` (with the current address), when Tor reaches Ready (see the `tor_was_ready`
    /// comparison in `poll_events`), and on a network change notice (see `reconnect_all_known_now`). All three call this one function.
    pub(crate) fn announce_address_to_all_contacts(&mut self) {
        let addr = match self.get_node_address() {
            Some(a) => a,
            None => return,
        };
        // The address is the stable onion and PeerId: it does not change with
        // the network, yet every network change sent a signed packet (and a
        // server deposit) to every contact device. Again only when it changed,
        // or once a day for a device that missed it.
        let now = current_time_ms();
        let last = self.meta_str("last_announced_addr");
        let unchanged = last.as_deref().and_then(|v| v.rsplit_once('|')).map_or(false, |(a, t)| {
            a == addr && t.parse::<u64>().map_or(false, |t| now.saturating_sub(t) < ADDRESS_REANNOUNCE_MS)
        });
        if unchanged {
            return;
        }
        self.meta_put("last_announced_addr", &format!("{}|{}", addr, now));
        let content = MessageContent::AddressAnnounce { multiaddr: addr };
        // Active devices only, as in `set_own_profile_picture`: a revoked
        // device has no session, so this send started a new handshake with it
        // and gave it our current addresses.
        let peer_fps = self.contact_device_targets();
        for fp in peer_fps {
            if let Err(e) = self.send_message_content(fp.clone(), &content, None) {
                error!("AddressAnnounce gönderilemedi ({}): {}", crate::log_id(&fp), e);
            }
        }
    }

    /// Clear chat (the soft option, requested by the user): deletes only the local message and attachment history (including the `.enc` blobs on disk). The pairing and
    /// ratchet session are KEPT, the contact stays in the list, and the chat starts empty. See `delete_contact` (the hard option).
    pub(crate) fn clear_chat_history(&mut self, contact_id: &str) -> Result<(), String> {
        if self.groups.contains_key(contact_id) {
            return self.clear_group_history(contact_id);
        }
        let contact = self.contacts.get(contact_id).ok_or("Kişi bulunamadı")?.clone();
        // No history answer or sibling backfill may bring the rows back.
        self.raise_history_floor(&contact.trusted_identity_id, current_time_ms());
        // same device set as `delete_contact` (inactive records too).
        let fingerprints = self.contact_fingerprints_all(&contact);
        self.delete_chat_attachments(&fingerprints);
        // One transaction: a crash half-way left reactions/seen rows of
        // messages that were gone.
        if let Some(conn) = &self.db {
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
            for fp in &fingerprints {
                for sql in [
                    // Their reaction and seen rows hold the peer's identity id.
                    "DELETE FROM message_reactions WHERE message_id IN (SELECT message_id FROM messages WHERE peer_device_fingerprint = ?1)",
                    "DELETE FROM message_seen WHERE message_id IN (SELECT message_id FROM messages WHERE peer_device_fingerprint = ?1)",
                    "DELETE FROM messages WHERE peer_device_fingerprint = ?1",
                    "DELETE FROM files WHERE peer_device_fingerprint = ?1 AND group_id IS NULL",
                ] {
                    tx.execute(sql, params![fp]).map_err(|e| e.to_string())?;
                }
            }
            tx.commit().map_err(|e| e.to_string())?;
        }
        self.wb_delete_board(None, Some(&contact.trusted_identity_id));
        Ok(())
    }

    /// `clear_chat_history` for a group: this device's copy only, the group
    /// and its members stay.
    pub(crate) fn clear_group_history(&mut self, group_id: &str) -> Result<(), String> {
        // No history answer or sibling backfill may bring the rows back
        // (see `history_floor`; a group id never collides with an identity id).
        self.raise_history_floor(group_id, current_time_ms());
        let file_ids: Vec<String> = self.db.as_ref().and_then(|conn| {
            let mut stmt = conn.prepare("SELECT file_id FROM files WHERE group_id = ?1").ok()?;
            let rows = stmt.query_map(params![group_id], |r| r.get(0)).ok()?.flatten().collect();
            Some(rows)
        }).unwrap_or_default();
        if let Some(conn) = &self.db {
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
            for sql in [
                "DELETE FROM message_reactions WHERE message_id IN (SELECT message_id FROM messages WHERE group_id = ?1)",
                "DELETE FROM message_seen WHERE message_id IN (SELECT message_id FROM messages WHERE group_id = ?1)",
                // Reactions and seen marks on attachments, before their rows go.
                "DELETE FROM message_reactions WHERE message_id IN (SELECT file_id FROM files WHERE group_id = ?1)",
                "DELETE FROM message_seen WHERE message_id IN (SELECT file_id FROM files WHERE group_id = ?1)",
                "DELETE FROM messages WHERE group_id = ?1",
            ] {
                tx.execute(sql, params![group_id]).map_err(|e| e.to_string())?;
            }
            tx.commit().map_err(|e| e.to_string())?;
        }
        for file_id in &file_ids {
            self.delete_attachment_file(file_id);
        }
        self.wb_delete_board(Some(group_id), None);
        Ok(())
    }

    /// Every device fingerprint a contact's chat can be stored under: its
    /// listed devices and the inactive records `import_sync_payload` keeps.
    pub(crate) fn contact_fingerprints_all(&self, contact: &Contact) -> Vec<String> {
        let mut fps: Vec<String> = contact.known_devices.iter().map(|d| d.device_fingerprint.clone()).collect();
        fps.extend(self.known_remote_devices.values()
            .filter(|d| d.identity_id == contact.trusted_identity_id)
            .map(|d| d.device_fingerprint.clone()));
        fps.sort();
        fps.dedup();
        fps
    }

    /// the 1:1 attachments of these devices go completely — `.enc` blob,
    /// the decrypted `plain_cache` copy, a running transfer, the row
    /// (`delete_attachment_file`). `group_id IS NULL`: a group file offer is
    /// stored under the sending member's fingerprint and must stay.
    pub(crate) fn delete_chat_attachments(&mut self, fingerprints: &[String]) {
        let mut file_ids: Vec<String> = Vec::new();
        if let Some(conn) = &self.db {
            for fp in fingerprints {
                if let Ok(mut stmt) = conn.prepare("SELECT file_id FROM files WHERE peer_device_fingerprint = ?1 AND group_id IS NULL") {
                    if let Ok(rows) = stmt.query_map(params![fp], |r| r.get::<_, String>(0)) {
                        file_ids.extend(rows.flatten());
                    }
                }
            }
        }
        for file_id in &file_ids {
            // Reactions and seen marks of an attachment are keyed by its file
            // id, not a `messages` row.
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM message_reactions WHERE message_id = ?1", params![file_id]);
                let _ = conn.execute("DELETE FROM message_seen WHERE message_id = ?1", params![file_id]);
            }
            self.delete_attachment_file(file_id);
        }
    }

    /// Delete contact (the hard option requested by the user, with a double confirmation in the UI): deletes EVERYTHING, including the pairing and ratchet session.
    /// Chatting again requires a fresh QR or manual pairing. See `clear_chat_history` (the soft option, which only deletes history).
    pub(crate) fn delete_contact(&mut self, contact_id: &str) -> Result<(), String> {
        let contact = self.contacts.get(contact_id).ok_or("Kişi bulunamadı")?.clone();
        // see the `hfloor:` filter in the HistorySyncResponse arm.
        self.raise_history_floor(&contact.trusted_identity_id, current_time_ms());
        // Still a member of one of our groups: the device records, keys and
        // sessions stay. Without them group messages to and from this member
        // were dropped ("Unknown sender device") and a founder handover it
        // signed could not be verified. The 1:1 chat goes and the entry falls
        // back to what any group member is: vouched by the group, unverified.
        if self.groups.values().any(|g| g.is_member(&contact.trusted_identity_id)) {
            self.clear_chat_history(contact_id)?;
            self.purge_conv_archive(&contact.trusted_identity_id);
            if let Some(c) = self.contacts.get_mut(contact_id) {
                c.added_via_group = true;
            }
            if let Some(c) = self.contacts.get(contact_id) {
                self.persist_contact(c);
            }
            return Ok(());
        }
        let fingerprints = self.contact_fingerprints_all(&contact);
        // before the transaction (the cache path needs the file row).
        self.delete_chat_attachments(&fingerprints);

        // Disk first, in one transaction, and memory only after the commit.
        // Without it a kill half-way left the contact row (deleted last) with
        // no device records and no session: listed, and unusable until the
        // user paired again.
        if let Some(conn) = &self.db {
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
            // see `contact_removed_locally`.
            tx.execute("INSERT OR REPLACE INTO removed_contacts (identity_id) VALUES (?1)", params![contact.trusted_identity_id])
                .map_err(|e| e.to_string())?;
            for fp in &fingerprints {
                for sql in [
                    "DELETE FROM message_reactions WHERE message_id IN (SELECT message_id FROM messages WHERE peer_device_fingerprint = ?1)",
                    "DELETE FROM message_seen WHERE message_id IN (SELECT message_id FROM messages WHERE peer_device_fingerprint = ?1)",
                    "DELETE FROM messages WHERE peer_device_fingerprint = ?1",
                    "DELETE FROM files WHERE peer_device_fingerprint = ?1 AND group_id IS NULL",
                    "DELETE FROM ratchet_states WHERE peer_device_fingerprint = ?1",
                    "DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1",
                    "DELETE FROM device_addrs WHERE device_fingerprint = ?1",
                    "DELETE FROM device_onion_addrs WHERE device_fingerprint = ?1",
                    "DELETE FROM remote_devices WHERE device_fingerprint = ?1",
                    // Its first-contact mailbox secrets: the mailbox made
                    // only from them is no longer registered.
                    // Also its kept DeviceAdd and handshake replay marks.
                    "DELETE FROM app_meta WHERE k = 'pn:' || ?1 OR k = 'pk:' || ?1 OR k = 'pt:' || ?1 OR k LIKE 'gf:' || ?1 || ':%' OR k LIKE 'gfs:' || ?1 || ':%' OR k = 'da:' || ?1 OR k = 'hs:' || ?1 OR k = 'vah:' || ?1",
                ] {
                    tx.execute(sql, params![fp]).map_err(|e| e.to_string())?;
                }
            }
            tx.execute("DELETE FROM contacts WHERE contact_id = ?1", params![contact_id]).map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
        }
        // the sealed 1:1 archive would otherwise stay on the history
        // server for its TTL.
        self.purge_conv_archive(&contact.trusted_identity_id);

        self.contacts.remove(contact_id);
        self.identity_to_contact.remove(&contact.trusted_identity_id);
        self.wb_delete_board(None, Some(&contact.trusted_identity_id));
        for fp in &fingerprints {
            // Also closes the live connection and drops what is queued for the
            // device: a queued IdentityExchange, answered by the peer, used to
            // bring the deleted contact back by TOFU within seconds.
            self.drop_device_sessions(fp);
            // The trusted keys go too: pairing again must start from a code.
            self.known_remote_devices.remove(fp);
            // Otherwise the reply to a re-pairing within a minute is suppressed.
            self.last_identity_exchange_reply.remove(fp);
        }
        // An alert of the deleted contact could still be shown and accepted.
        self.pending_device_alerts.retain(|_, a| a.identity_id != contact.trusted_identity_id);
        self.persist_device_alerts();
        Ok(())
    }

    /// Before: `Contact::revoke_device` and `DeviceRecord.is_active` both EXISTED, but no caller ever set them to `false`/`Revoked`. A device could never be revoked
    /// (see SECURITY.md). This does the SAME cleanup steps as `delete_contact` (which deletes the contact COMPLETELY), but it does NOT delete the contact or its history.
    /// It only stops everything to and from this ONE device fingerprint (through the new `is_active` checks in `receive_message` and `process_handshake_init`).
    /// If the same contact has ANOTHER known device, that one is not affected (the multi-device case of ).
    pub(crate) fn revoke_contact_device(&mut self, contact_id: &str, device_fingerprint: &str) -> Result<(), String> {
        let mut contact = self.contacts.get(contact_id).cloned().ok_or("Kişi bulunamadı")?;
        // Everything below acts on the fingerprint alone: for a device of
        // someone else (even one of our own siblings) it would deactivate the
        // record and delete the session.
        if contact.find_device(device_fingerprint).is_none() {
            return Err("Bu cihaz bu kişiye ait değil".to_string());
        }
        contact.revoke_device(device_fingerprint, current_time_ms());
        let record = self.known_remote_devices.get(device_fingerprint).cloned().map(|mut r| {
            r.is_active = false;
            r
        });
        // disk first, both rows in one transaction; memory only after.
        if let Some(conn) = &self.db {
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
            self.try_persist_contact(&contact)?;
            if let Some(r) = &record {
                self.try_persist_remote_device(r)?;
            }
            tx.commit().map_err(|e| e.to_string())?;
        }
        self.contacts.insert(contact_id.to_string(), contact);
        if let Some(r) = record {
            self.known_remote_devices.insert(device_fingerprint.to_string(), r);
        }

        self.drop_device_sessions(device_fingerprint);
        let identity_id = self.contacts.get(contact_id).map(|c| c.trusted_identity_id.clone()).unwrap_or_default();
        self.rekey_archive_to_canonical(&identity_id);
        Ok(())
    }

    /// Everything that still talks to one device: its session, the queued and
    /// retried packets, its addresses, its downloads, the live connection.
    /// The device record stays; the caller marks it inactive or deletes it.
    pub(crate) fn drop_device_sessions(&mut self, fp: &str) {
        self.drop_device_sessions_keep_link(fp, true);
    }

    /// `disconnect` false: the connection stays up for `REVOKE_DISCONNECT_DELAY_MS`
    /// (see `revoke_own_linked_device`).
    pub(crate) fn drop_device_sessions_keep_link(&mut self, fp: &str, disconnect: bool) {
        if self.peer_prekeys.remove(fp).is_some() {
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM peer_prekeys WHERE device_fingerprint = ?1", params![fp]);
            }
        }
        self.ratchets.remove(fp);
        if let Some(peer_id) = self.device_to_peer_id.remove(fp) {
            if disconnect {
                if let Some(swarm) = &mut self.swarm {
                    let _ = swarm.disconnect_peer_id(peer_id);
                }
            } else {
                self.revoked_disconnects.push((peer_id, mono_ms() + REVOKE_DISCONNECT_DELAY_MS));
            }
        }
        self.device_last_addr.remove(fp);
        self.device_onion_addr.remove(fp);
        // `recent_handshake_sigs` stays: with the session gone nothing else
        // stops a captured init (valid for 7 days) from being accepted again,
        // e.g. after a block and unblock. Entries age out on the next init.
        self.clear_persisted_skipped_keys(fp);
        self.awaiting_confirmation.retain(|_, pc| pc.peer_device_fingerprint != fp);
        self.remove_durable_retries_for_peer(fp);
        self.active_downloads.retain(|_, d| d.peer_device_fingerprint != fp);
        // Queued envelopes for it are dropped too.
        self.pending_envelopes.retain(|q| q.target != fp);
        self.early_packets.remove(fp);
        self.early_handshakes.remove(fp);
        // Its buffered edits/deletes too: they would apply once their target arrives.
        self.pending_edits_deletes.retain(|_, b| { b.retain(|e| e.1 != fp); !b.is_empty() });
        self.unknown_group_held.retain(|_, b| { b.retain(|e| e.2 != fp); !b.is_empty() });
        self.undecryptable_from.remove(fp);
        self.last_handshake_redo.remove(fp);
        self.reconnect_backoff.remove(fp);
        // "Retry" on a group bubble must not send to it again.
        for (_, devices) in self.group_failed_copies.values_mut() {
            devices.retain(|d| d != fp);
        }
        if let Some(conn) = &self.db {
            for table_key in [
                "ratchet_states WHERE peer_device_fingerprint", "skipped_message_keys WHERE peer_device_fingerprint",
                "device_addrs WHERE device_fingerprint", "device_onion_addrs WHERE device_fingerprint",
            ] {
                let _ = conn.execute(&format!("DELETE FROM {} = ?1", table_key), params![fp]);
            }
        }
    }

    /// A chat is archived under the contact's canonical device (`canonical_device_for_identity`). When that device changes (it was revoked, or an older one came back),
    /// the rows move with it. Before, the chat opened empty, because its history was left under the old fingerprint.
    /// ponytail: message rows only. Attachment rows (`files`) stay under the device that offered them. Move them too if the attachment list of such a chat matters.
    pub(crate) fn rekey_archive_to_canonical(&self, identity_id: &str) {
        let Some(canon) = self.canonical_device_for_identity(identity_id) else { return };
        let Some(contact) = self.identity_to_contact.get(identity_id).and_then(|cid| self.contacts.get(cid)) else { return };
        let Some(conn) = &self.db else { return };
        // Also the identity's devices outside the contact list: before the
        // contact existed, `canonical_device_for_identity` picked among those
        // (by fingerprint only), and that half of the chat stayed behind.
        let mut fps: Vec<&str> = contact.known_devices.iter().map(|d| d.device_fingerprint.as_str()).collect();
        fps.extend(self.known_remote_devices.values().filter(|d| d.identity_id == identity_id).map(|d| d.device_fingerprint.as_str()));
        fps.sort_unstable();
        fps.dedup();
        for fp in fps.into_iter().filter(|fp| *fp != canon) {
            let _ = conn.execute(
                "UPDATE messages SET peer_device_fingerprint = ?1
                 WHERE peer_device_fingerprint = ?2 AND (group_id IS NULL OR group_id = '')",
                params![canon, fp],
            );
        }
    }

    /// User-requested extra (see the SECURITY.md "Cross-network connectivity" note): a relay address the user adds by hand in Settings, one they trust or run themselves
    /// (for example a VPS with a fixed IP, or a device with node mode on). This is the ONLY way to GUARANTEE that two STRANGERS with no shared relay history can pair
    /// across different networks for the first time. Organic discovery (identify, QR sharing, `known_relay_peers`) only works when a relay is already known on the network.
    pub(crate) fn add_known_relay_address(&mut self, multiaddr: &str) -> Result<(), String> {
        let addr: Multiaddr = multiaddr.trim().parse().map_err(|_| "Geçersiz multiaddr".to_string())?;
        let peer_id = extract_peer_id(&addr).ok_or("Adres bir /p2p/<peer_id> son eki içermeli")?;
        if let Some(swarm) = &mut self.swarm {
            swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
        }
        self.record_known_relay(peer_id, addr);
        Ok(())
    }

    /// For the Groups tab list. See the `GroupSummary` note.
    pub(crate) fn list_groups(&self) -> Vec<GroupSummary> {
        let own_identity_id = self.identity.as_ref().map(|i| i.identity_id.clone()).unwrap_or_default();
        self.groups.values().map(|g| GroupSummary {
            group_id: g.group_id.clone(),
            name: g.name.clone(),
            founder_identity_id: g.founder_identity_id.clone(),
            is_founder: g.founder_identity_id == own_identity_id,
            member_identity_ids: g.member_identity_ids(),
            avatar_hex: g.avatar_jpeg.as_ref().map(|a| hex::encode(a)),
        }).collect()
    }

    // ---------------------------------------------------------------
    // Section 3: hybrid KEM and Double Ratchet
    // ---------------------------------------------------------------

    /// Lets ChatActivity know when to hide its "connecting..." indicator: whether a ratchet session exists.
    pub(crate) fn has_active_session(&self, peer_device_fingerprint: &str) -> bool {
        self.ratchets.contains_key(peer_device_fingerprint)
    }

    /// The REAL live connection status. Unlike `has_active_session` (which only answers "has a ratchet session been set up?", stays true FOREVER once it is set up,
    /// is a cryptographic state, independent of the network connection), this function checks the `Swarm`'s OWN live connection table (`is_connected`).
    /// Before, ChatActivity's status line used `has_active_session`, so even when the other side was actually unreachable (after the ratchet was set up once),
    /// it always showed "Connected". Returns `false` if there is no record for the device in `device_to_peer_id` (no packet from that device has been received during this process).
    pub(crate) fn is_peer_connected(&self, peer_device_fingerprint: &str) -> bool {
        let peer_id = match self.device_to_peer_id.get(peer_device_fingerprint) {
            Some(pid) => pid,
            None => return false,
        };
        self.swarm.as_ref().map(|s| s.is_connected(peer_id)).unwrap_or(false)
    }
}

impl P2PCore {

    /// Called when this device is revoked by its OWN identity (`apply_device_revoke_notice`). Deletes ALL local state: DB tables, extra files on disk, and in-memory
    /// state (INCLUDING the PRIVATE KEYS; `DeviceKeys` zeroizes on Drop). After the delete, the core returns to an "identity-less" (fresh install) state. With no
    /// identity or keys, the send and receive paths are naturally inert, so no separate "locked" flag is needed (that would create a stuck-state risk, and the user
    /// must be able to create a new identity in the same process). IMPORTANT: the PERSISTENT copy of the private keys is NOT in the core, it is in the UI's
    /// Keystore/vault (see `load_secret_bundle`). The UI deletes it on its side when it gets the `self_revoked` event, and returns to onboarding.
    /// One identity per database. When the DB holds another identity than the one about to be installed, its whole local state goes first: history, contacts, groups,
    /// sessions, server records, attachment files. The storage keys the client loaded at start stay, since they belong to the device and not to the identity, so no restart is needed.
    pub(crate) fn wipe_other_identity(&mut self, identity_id: &str) {
        let other = self.db.as_ref().map_or(false, |c| {
            c.query_row("SELECT 1 FROM identities WHERE id != ?1", params![identity_id], |_| Ok(())).is_ok()
        });
        if !other {
            return;
        }
        let (history_key, skipped_key) = (self.history_key, self.skipped_key_encryption_key);
        self.wipe_all_local_state();
        self.history_key = history_key;
        self.skipped_key_encryption_key = skipped_key;
    }

    pub(crate) fn wipe_all_local_state(&mut self) {
        self.revoked_disconnects.clear();
        self.sticker_parts.clear();
        // Drops the call (and its media keys) without signalling anyone.
        self.call = None;
        self.first_contact_cache.take();
        self.last_call_end = None;
        call::drop_media();
        if let Some(conn) = &self.db {
            for table in [
                "identities", "own_devices", "contacts", "groups", "messages",
                "skipped_message_keys", "remote_devices", "ratchet_states", "files",
                "device_addrs", "device_onion_addrs", "pending_durable_retries",
                "pending_group_messages", "app_meta", "pending_sibling_ops", "acked_packets",
                // The server tables were NOT in the list. The `servers` row carries `enroll_sk`/`enroll_sk_pq`, the PRIVATE signing keys for our registration on the server.
                // `server_archive_queue` carries message bodies. On a remotely revoked device both were left on disk.
                "servers", "server_cursors", "server_archive_queue", "server_blob_uploads",
                "server_archived_convs", "server_archive_revs",
                // The block list is also local state of this device. The blocks of a deleted identity must not be left behind.
                "blocked_identities", "deleted_identities", "removed_contacts", "removed_groups",
                "wb_strokes", "wb_tombstones", "wb_page_sigs", "own_prekeys", "peer_prekeys",
                // They hold other people's identity ids (who reacted, who saw).
                "message_reactions", "message_seen", "stickers",
            ] {
                let _ = conn.execute(&format!("DELETE FROM {}", table), []);
            }
        }
        if let Ok(dir) = self.attachments_dir() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        if let Ok(dir) = self.stickers_dir() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        // Memory: including the private keys and session secrets. `own_device_keys` (DeviceKeys) and the ratchet states zeroize on Drop.
        self.identity = None;
        self.own_devices.clear();
        self.own_device_keys.clear();
        self.own_device_add = None;
        self.known_remote_devices.clear();
        self.contacts.clear();
        self.identity_to_contact.clear();
        self.ratchets.clear();
        self.groups.clear();
        self.awaiting_confirmation.clear();
        self.pending_group_messages.clear();
        self.wb_outbox.clear();
        self.wb_reply_at.clear();
        self.pending_group_syncs.clear();
        self.pending_edits_deletes.clear();
        self.unknown_group_held.clear();
        self.pending_envelopes.clear();
        self.early_packets.clear();
        self.early_handshakes.clear();
        self.group_failed_copies.clear();
        self.history_answered_at.clear();
        self.history_sent_bytes.clear();
        self.history_answered_by.clear();
        self.chunk_rate_limiter.clear();
        self.recent_inbound_digests.clear();
        self.sibling_backfill_since.clear();
        self.recently_acked.clear();
        self.outbound_acks.clear();
        self.ack_batches_inflight.clear();
        self.envelopes_inflight.clear();
        self.pairing_mailbox_subs.clear();
        self.pairing_reply_peer.clear();
        self.verified_device_adds.clear();
        for d in self.active_downloads.values_mut() {
            zeroize::Zeroize::zeroize(&mut d.file_key);
        }
        self.active_downloads.clear();
        self.auto_resumed_downloads.clear();
        self.message_status.clear();
        self.last_handshake_redo.clear();
        self.undecryptable_from.clear();
        self.link_request_open_until = 0;
        self.link_request_nonce.clear();
        self.link_consent_peer = None;
        self.pending_link_nonce.clear();
        self.own_prekeys.clear();
        self.own_prekeys_loaded = false;
        self.peer_prekeys.clear();
        self.id0_inits.clear();
        self.outstanding_history_requests.clear();
        self.sibling_fetch_open.clear();
        self.history_fetch_pages.clear();
        self.handshake_failure_notified.clear();
        // The server state and the root archive key must be cleared too. Otherwise a revoked device keeps acting as a registered server client for as long as the process lives.
        self.servers.clear();
        self.server_rt.clear();
        self.server_inflight.clear();
        self.server_cursors.clear();
        self.server_unknown_mailboxes.clear();
        self.server_unknown_streak.clear();
        self.server_archive_queue.clear();
        self.server_blob_uploads.clear();
        self.server_deposited.clear();
        self.server_deposit_locations.clear();
        self.deferred_incoming.clear();
        self.download_request_ids.clear();

        // Fix: the memory side of the device-revoke cleanup had been left half done. The following remained, and two of them are direct KEY MATERIAL:
        // * `pending_secret_bundle`: the block with the device's RAW private keys (it may be waiting to be handed to Kotlin). Leaving it in memory on a remotely
        //   revoked device was exactly what the delete must prevent.
        // * `skipped_key_encryption_key`: the key that decrypts ratchet states, skipped message keys, file keys and the server archive queue. `history_key` was cleared
        //   but this was not, which was inconsistent.
        // The rest leaked identity and contact pairing data: which fingerprint we saw at which network address, from whom and when we received a handshake, and which
        // contacts we were waiting on alerts for.
        {
            // Wiped, not only dropped: these are the raw device secrets and
            // the keys that open everything stored.
            use zeroize::Zeroize;
            self.pending_secret_bundle.zeroize();
            self.skipped_key_encryption_key.zeroize();
            self.history_key.zeroize();
            self.archive_root_key.zeroize();
        }
        self.history_key = None;
        self.archive_root_key = None;
        zeroize::Zeroize::zeroize(&mut self.pending_secret_bundle);
        self.pending_secret_bundle = None;
        self.skipped_key_encryption_key = None;
        // The gate shuts with the key: sessions made before a new
        // key is installed would not be stored.
        self.ratchets_loaded = false;
        self.peer_onion_addr.clear();
        self.pending_device_alerts.clear();
        self.last_identity_exchange_reply.clear();
        self.recent_handshake_sigs.clear();
        self.device_to_peer_id.clear();
        self.peer_id_to_addr.clear();
        self.device_last_addr.clear();
        self.device_onion_addr.clear();
        self.reconnect_backoff.clear();
        self.fast_reconnect_fps.clear();
        self.keepalive_state.clear();
        self.message_rate_limiter.clear();
        self.server_mail_rate = (0, 0);
        self.unknown_peer_rate = (0, 0);
        self.bulk_health.clear();
        self.extra_conns.clear();
        self.bulk_dials.clear();
        self.deferred_swarm_events.clear();
        self.attachment_events.clear();
        self.blocked_identities.clear();
        self.deleted_identities.clear();
        self.own_mailbox_topic_fp = None;
        self.pending_link_target = None;
        self.pending_link_started_at = 0;
    }
}
