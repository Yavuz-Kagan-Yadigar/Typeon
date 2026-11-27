//! Sync with this identity's other devices: roster, read state, history backfill.

use super::*;

impl P2PCore {

    /// Full sync payload: contacts (with their public keys), groups, and sibling devices.
    pub(crate) fn build_sync_payload(&self) -> SyncPayload {
        let my_id = self.my_identity_id();
        let mut contacts = Vec::new();
        for contact in self.contacts.values() {
            // Do not sync our own identity (the sibling devices) as a contact.
            if my_id.as_deref() == Some(contact.trusted_identity_id.as_str()) { continue; }
            let mut devices: Vec<SyncedDevice> = self.known_remote_devices.values()
                .filter(|d| d.identity_id == contact.trusted_identity_id)
                .map(|d| self.synced_for_sibling(d))
                .collect();
            // Stable order (here and below): `sync_roster_to` skips parts it sent unchanged.
            devices.sort_by(|a, b| a.device_fingerprint.cmp(&b.device_fingerprint));
            let device_proofs = devices.iter()
                .filter(|d| d.device_fingerprint != contact.trusted_identity_id)
                .filter_map(|d| self.device_add_proof(&d.device_fingerprint))
                .collect();
            contacts.push(SyncedContact {
                identity_id: contact.trusted_identity_id.clone(),
                display_name: contact.display_name.clone(),
                added_via_group: contact.added_via_group,
                // Avatars are deliberately NOT part of the sync: an envelope is capped at `MAX_ENVELOPE_BYTES` (1 MiB),
                // and a large contact list plus avatars could exceed it. Avatars travel separately, in each contact's `ProfileUpdate`
                // (contacts re-send them when the sibling introduces itself). Messaging does not need them.
                avatar_jpeg: None,
                devices,
                device_proofs,
                added_at_ms: self.contact_added_at(&contact.trusted_identity_id),
            });
        }
        contacts.sort_by(|a, b| a.identity_id.cmp(&b.identity_id));
        // Contact avatars are left out on purpose (the 1 MiB envelope limit). Groups, however, were embedded as-is through
        // `serde_json::to_value(g)`, and `Group.avatar_jpeg` lives inside that struct. Avatars are 720p / 85% JPEG (about 100-250 KB), so a few
        // groups with avatars exceed the `DeviceSync` / `DeviceLinkGrant` limit. `try_publish_raw` treats that as `PublishFailure::Permanent`: no retry,
        // and the message is dropped from `awaiting_confirmation`, so the device sync was silently never sent. The group avatar travels separately,
        // in the founder's `GroupUpdate` (`GroupChange::AvatarUpdate`).
        let mut sorted_groups: Vec<&Group> = self.groups.values().collect();
        sorted_groups.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        let groups: Vec<serde_json::Value> = sorted_groups.into_iter()
            .map(|g| {
                let mut stripped = g.clone();
                stripped.avatar_jpeg = None;
                stripped
            })
            .filter_map(|g| serde_json::to_value(&g).ok())
            .collect();
        // Sibling devices: this device plus the other known devices of our identity (so that 3+ devices learn about each other).
        let mut siblings: Vec<SyncedDevice> = Vec::new();
        if let Some(dev) = self.own_synced_device() {
            siblings.push(dev);
        }
        if let Some(id) = &my_id {
            let mut others: Vec<SyncedDevice> = self.known_remote_devices.values()
                .filter(|d| &d.identity_id == id)
                .map(|rec| self.synced_for_sibling(rec))
                .collect();
            others.sort_by(|a, b| a.device_fingerprint.cmp(&b.device_fingerprint));
            siblings.extend(others);
        }
        let sibling_proofs = siblings.iter()
            .filter(|d| Some(&d.device_fingerprint) != my_id.as_ref())
            .filter_map(|d| self.device_add_proof(&d.device_fingerprint))
            .collect();
        SyncPayload {
            contacts, groups, siblings, sibling_proofs,
            archive_root_key: self.archive_root_key_bytes(),
            name_changed_at_ms: self.meta_u64("name_changed_at"),
            own_revokes: self.own_revokes_to_send(None),
            blocked: {
                let mut b: Vec<String> = self.blocked_identities.iter().cloned().collect();
                b.sort();
                b
            },
            removed_groups: self.removed_group_ids(),
        }
    }

    /// Ids in `removed_groups`, newest 4096 (the receive bound), sorted.
    pub(crate) fn removed_group_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.db.as_ref().and_then(|c| {
            let mut stmt = c.prepare("SELECT group_id FROM removed_groups ORDER BY rowid DESC LIMIT 4096").ok()?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).ok()?;
            Some(rows.flatten().collect())
        }).unwrap_or_default();
        ids.sort();
        ids
    }

    /// `build_sync_payload` cut into parts of at most `SYNC_CHUNK_DEVICES`
    /// contact devices. One device is about 4.2 KB of public keys, so a full
    /// roster of a few hundred devices passed the 1 MiB transmit limit: the
    /// publish failed for good and both sibling sync and device linking
    /// stopped. Groups, siblings and the name go in the first part; the
    /// import is idempotent, so parts may arrive in any order.
    pub(crate) fn build_sync_payloads(&self) -> Vec<SyncPayload> {
        const SYNC_CHUNK_DEVICES: usize = 100;
        let mut first = self.build_sync_payload();
        let mut rest = std::mem::take(&mut first.contacts);
        let groups = std::mem::take(&mut first.groups);
        let mut parts: Vec<SyncPayload> = Vec::new();
        loop {
            let mut n = 0;
            let mut devices = 0;
            // A proof (signature + signer keys) weighs about two devices.
            let weight = |c: &SyncedContact| c.devices.len() + 2 * c.device_proofs.len();
            // the first part (siblings, their proofs, archive key) gets
            // half the budget and no "at least one" escape: one heavy
            // contact next to it passed the transmit limit, and that part
            // failing stopped the whole sibling sync. Such a contact goes
            // alone in a later part.
            let (budget, first_part) = if parts.is_empty() { (SYNC_CHUNK_DEVICES / 2, true) } else { (SYNC_CHUNK_DEVICES, false) };
            while n < rest.len() && ((n == 0 && !first_part) || devices + weight(&rest[n]) <= budget) {
                devices += weight(&rest[n]);
                n += 1;
            }
            let tail = rest.split_off(n);
            parts.push(if first_part {
                SyncPayload { contacts: rest, ..first.clone() }
            } else {
                SyncPayload {
                    contacts: rest, groups: Vec::new(), siblings: Vec::new(), sibling_proofs: Vec::new(),
                    archive_root_key: first.archive_root_key.clone(),
                    name_changed_at_ms: first.name_changed_at_ms,
                    own_revokes: Vec::new(),
                    blocked: Vec::new(),
                    removed_groups: Vec::new(),
                }
            });
            rest = tail;
            if rest.is_empty() {
                break;
            }
        }
        // groups in parts of their own, at most 256 KB of JSON each:
        // all in the first part, many groups pushed it over the transmit
        // limit and no part of the sync went.
        const SYNC_CHUNK_GROUP_BYTES: usize = 256 * 1024;
        let groups_part = |groups: Vec<serde_json::Value>| SyncPayload {
            contacts: Vec::new(), groups, siblings: Vec::new(), sibling_proofs: Vec::new(),
            archive_root_key: first.archive_root_key.clone(),
            name_changed_at_ms: first.name_changed_at_ms,
            own_revokes: Vec::new(),
            blocked: Vec::new(),
            removed_groups: Vec::new(),
        };
        let (mut chunk, mut bytes) = (Vec::new(), 0usize);
        for g in groups {
            let len = serde_json::to_vec(&g).map_or(0, |v| v.len());
            if !chunk.is_empty() && bytes + len > SYNC_CHUNK_GROUP_BYTES {
                parts.push(groups_part(std::mem::take(&mut chunk)));
                bytes = 0;
            }
            bytes += len;
            chunk.push(g);
        }
        if !chunk.is_empty() {
            parts.push(groups_part(chunk));
        }
        // Contact avatars, one per part (up to ~250 KB each): left out of the
        // contact parts above, a linked device only got one when the contact
        // itself sent a `ProfileUpdate`. No devices: an unknown contact is
        // not created from such a part.
        let my_id = self.my_identity_id();
        for c in self.contacts.values() {
            let Some(avatar) = c.avatar_jpeg.clone() else { continue };
            if my_id.as_deref() == Some(c.trusted_identity_id.as_str()) { continue; }
            parts.push(SyncPayload {
                contacts: vec![SyncedContact {
                    identity_id: c.trusted_identity_id.clone(),
                    display_name: c.display_name.clone(),
                    added_via_group: c.added_via_group,
                    avatar_jpeg: Some(avatar),
                    devices: Vec::new(),
                    device_proofs: Vec::new(),
                    added_at_ms: 0,
                }],
                ..groups_part(Vec::new())
            });
        }
        parts
    }

    pub(crate) fn meta_u64(&self, k: &str) -> u64 {
        self.db.as_ref()
            .and_then(|conn| conn.query_row("SELECT v FROM app_meta WHERE k = ?1", params![k], |r| r.get::<_, String>(0)).ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    /// Merges a sync payload idempotently. It NEVER overwrites the keys of a known device; it only adds missing contacts, devices and groups,
    /// and replaces a group copy older than the sibling's.
    /// Returns the newly learned contact identity ids, so the caller can introduce itself to them.
    pub(crate) fn import_sync_payload(&mut self, sync: &SyncPayload) -> Vec<String> {
        self.import_sync_payload_from(sync, true)
    }

    /// `trusted`: the payload comes from the root device, or this device is
    /// not the root. Otherwise (a secondary's payload on the root) a group
    /// is taken or replaced only when this identity founded it: any linked
    /// device (a stolen one too) could plant groups or rewrite them, with
    /// nothing signed by their founder.
    pub(crate) fn import_sync_payload_from(&mut self, sync: &SyncPayload, trusted: bool) -> Vec<String> {
        let now = current_time_ms();
        let my_id = self.my_identity_id();
        let mut learned = Vec::new();
        for sc in &sync.contacts {
            if my_id.as_deref() == Some(sc.identity_id.as_str()) { continue; }
            if !is_fingerprint_hex(&sc.identity_id) { continue; }
            // Deleted here or on a sibling: the sibling's copy brings it back only
            // if the user paired with it again after that removal (generations,
            // `contact_next_gen`; equal = made without knowing of each other,
            // the pairing wins). A stale copy (paired before the removal) does not.
            let added_at = sc.added_at_ms;
            if !self.identity_to_contact.contains_key(&sc.identity_id) {
                if let Some(removed_at) = self.contact_removed_at(&sc.identity_id) {
                    if added_at < removed_at { continue; }
                    if let Some(conn) = &self.db {
                        let _ = conn.execute("DELETE FROM removed_contacts WHERE identity_id = ?1", params![sc.identity_id]);
                    }
                }
            }
            // Kept so a delete echo older than this pairing is ignored, and passed on to further siblings.
            self.note_contact_added(&sc.identity_id, added_at);
            // Add the device public keys, without overwriting known ones.
            for sd in &sc.devices {
                // The fingerprint is the hash of the keys. Verify it, per the trust model.
                if !sd.keys_match_fingerprint() { continue; }
                // A device learned here must be bound to the identity (first
                // device, or proof): the sibling's word alone does not put a
                // device under a contact.
                let known = self.known_remote_devices.contains_key(&sd.device_fingerprint);
                if !known
                    && !Self::claim_is_bound(&sc.identity_id, &sd.device_fingerprint, &sc.device_proofs, &sd.sign_pubkey_ed25519, &sd.sign_pubkey_mldsa)
                {
                    continue;
                }
                if !known {
                    if let Some(p) = sc.device_proofs.iter().find(|p| p.device_add.new_device_fingerprint == sd.device_fingerprint) {
                        self.remember_device_add(&p.device_add);
                    }
                    let rec = DeviceRecord {
                        device_fingerprint: sd.device_fingerprint.clone(),
                        identity_id: sc.identity_id.clone(),
                        sign_pubkey_ed25519: sd.sign_pubkey_ed25519.clone(),
                        sign_pubkey_mldsa: sd.sign_pubkey_mldsa.clone(),
                        kem_pubkey_x25519: sd.kem_pubkey_x25519.clone(),
                        kem_pubkey_mlkem: sd.kem_pubkey_mlkem.clone(),
                        device_name: sanitize_display_name(&sd.device_name).unwrap_or_default(),
                        is_active: sd.is_active,
                        last_seen: now,
                    };
                    self.persist_remote_device(&rec);
                    self.known_remote_devices.insert(sd.device_fingerprint.clone(), rec);
                }
                if self.known_remote_devices.get(&sd.device_fingerprint).map_or(false, |d| d.identity_id == sc.identity_id) {
                    self.import_mailbox_secrets(sd);
                }
                // Only where this device has no address of its own: the
                // sibling's copy is older than ours, and each sync replaced
                // the address that works here (and gave one back to a device
                // revoked on this side).
                if let Some(addr) = sd.last_addr.as_ref().filter(|_| !self.device_last_addr.contains_key(&sd.device_fingerprint)) {
                    self.remember_device_addr(&sd.device_fingerprint, addr);
                }
            }
            // A device counts only if its record is stored for this identity
            // (key hash checked above, or known before) and it is active.
            let usable: Vec<String> = sc.devices.iter()
                .filter(|sd| sd.is_active)
                .filter(|sd| self.known_remote_devices.get(&sd.device_fingerprint)
                    .map_or(false, |d| d.identity_id == sc.identity_id && d.is_active))
                .map(|sd| sd.device_fingerprint.clone())
                .collect();
            // Add the contact record, without overwriting a known contact.
            if let Some(cid) = self.identity_to_contact.get(&sc.identity_id).cloned() {
                // Known contact: its devices the sibling learned first. Without
                // an entry in `known_devices` such a device raised a false
                // "unknown device" alert and its packets were blocked. A device
                // this side revoked has an entry and is left alone.
                let mut changed = false;
                if let Some(contact) = self.contacts.get_mut(&cid) {
                    // Avatars come in parts of their own (`build_sync_payloads`).
                    // Only where this device has none: the contact's own
                    // `ProfileUpdate` is newer than a sibling's copy.
                    if contact.avatar_jpeg.is_none() && sc.avatar_jpeg.is_some() {
                        contact.avatar_jpeg = sc.avatar_jpeg.clone();
                        changed = true;
                    }
                    for fp in &usable {
                        if contact.find_device(fp).is_none() {
                            contact.add_device_via_signed_chain(fp.clone(), now);
                            changed = true;
                        }
                    }
                }
                if changed {
                    if let Some(contact) = self.contacts.get(&cid) { self.persist_contact(contact); }
                    self.rekey_archive_to_canonical(&sc.identity_id);
                }
            } else {
                // No usable device: nothing to talk to, and a device-less
                // contact must not exist (see register_contact_from_pairing).
                // Same 500 cap as every other way a contact is created.
                if usable.is_empty() || self.contacts.len() >= MAX_CONTACTS { continue; }
                let contact_id = self.new_contact_id(&sc.identity_id);
                let mut contact = Contact::new(contact_id.clone(), sanitize_display_name(&sc.display_name).unwrap_or_default(), sc.identity_id.clone());
                contact.added_via_group = sc.added_via_group;
                contact.avatar_jpeg = sc.avatar_jpeg.clone();
                for fp in &usable {
                    contact.add_device_via_signed_chain(fp.clone(), now);
                }
                self.identity_to_contact.insert(sc.identity_id.clone(), contact_id.clone());
                self.persist_contact(&contact);
                self.contacts.insert(contact_id, contact);
                self.rekey_archive_to_canonical(&sc.identity_id);
                learned.push(sc.identity_id.clone());
            }
        }
        for gv in &sync.groups {
            if let Ok(mut g) = serde_json::from_value::<Group>(gv.clone()) {
                // Left or deleted on this device (`remove_group_locally`): the
                // sibling's copy must not bring it back.
                if self.group_removed_locally(&g.group_id) { continue; }
                if !trusted && my_id.as_deref() != Some(g.founder_identity_id.as_str()) { continue; }
                match self.groups.get(&g.group_id) {
                    None => {}
                    // A newer version from the sibling replaces a stale copy:
                    // a founder that does not know this device never sends it
                    // the GroupUpdate. An older or equal one never rolls it back.
                    Some(local) if g.version > local.version => {
                        // The sync carries no avatar; the founder's tie hash of
                        // the old version no longer applies.
                        g.avatar_jpeg = local.avatar_jpeg.clone();
                        self.set_group_tie(&g.group_id, &[]);
                    }
                    Some(_) => continue,
                }
                self.persist_group(&g);
                self.groups.insert(g.group_id.clone(), g);
            }
        }
        // Groups left or deleted on the sibling and not held here: marked, so an old founder-signed update cannot
        // re-create them (only an explicit new Add of us can, see `process_group_update`).
        for gid in &sync.removed_groups {
            if is_group_id(gid) && !self.groups.contains_key(gid) {
                if let Some(conn) = &self.db {
                    let _ = conn.execute("INSERT OR IGNORE INTO removed_groups (group_id, version, founder) VALUES (?1, 0, '')", params![gid]);
                }
            }
        }
        // Sibling devices: learn the other devices of our identity (3+ devices). Skip our own fingerprint and do not overwrite known ones.
        let own_fp = self.get_active_own_device_fingerprint().ok();
        if let Some(my) = &my_id {
            // A rename made on a sibling device arrives here. ONLY the name is adopted. Keys and active state are still NEVER overwritten
            // (the `continue` rules below are unchanged). The name is not security data and already belongs to the identity (see `adopt_own_device_name`).
            // Not adopting it would leave the old name on this device, and it would be spread back to contacts at the first opportunity.
            let sibling_names: Vec<String> = sync.siblings.iter()
                .filter_map(|sd| sanitize_display_name(&sd.device_name))
                .collect();
            // A sync has no order: one queued before a rename here arrived
            // after it and put the old name back. The name is taken only from
            // a sync whose rename is newer than ours (0 = a version without
            // the stamp, taken only while we have none either).
            // Clamped: a sibling stamp in the future pinned its name for good.
            let theirs = sync.name_changed_at_ms.min(now);
            let ours = self.meta_u64("name_changed_at");
            let newer = theirs > ours || (theirs == 0 && ours == 0);
            if let Some(n) = sibling_names.first().filter(|_| newer) {
                // Stamp 1 after a 0/0 adoption: two never-renamed devices
                // swapped names on every sync; now the other side adopts the
                // (same) name back once and both stop.
                self.meta_put("name_changed_at", &theirs.max(1).to_string());
                if self.own_display_name().as_deref() != Some(n.as_str()) {
                    self.adopt_own_device_name(n);
                }
            }
            let revoked: Vec<String> = self.own_revokes().into_iter().map(|r| r.revoked_device_fingerprint).collect();
            for sd in &sync.siblings {
                if own_fp.as_deref() == Some(sd.device_fingerprint.as_str()) { continue; }
                if self.known_remote_devices.get(&sd.device_fingerprint).map_or(false, |d| &d.identity_id == my) {
                    self.import_mailbox_secrets(sd);
                }
                if self.known_remote_devices.contains_key(&sd.device_fingerprint) { continue; }
                if !sd.keys_match_fingerprint() { continue; }
                // Only the first device adds a device: a sibling's word alone
                // made any device it listed a device of this identity.
                if revoked.contains(&sd.device_fingerprint)
                    || !Self::claim_is_bound(my, &sd.device_fingerprint, &sync.sibling_proofs, &sd.sign_pubkey_ed25519, &sd.sign_pubkey_mldsa)
                {
                    continue;
                }
                if let Some(p) = sync.sibling_proofs.iter().find(|p| p.device_add.new_device_fingerprint == sd.device_fingerprint) {
                    self.remember_device_add(&p.device_add);
                }
                let rec = DeviceRecord {
                    device_fingerprint: sd.device_fingerprint.clone(),
                    identity_id: my.clone(),
                    sign_pubkey_ed25519: sd.sign_pubkey_ed25519.clone(),
                    sign_pubkey_mldsa: sd.sign_pubkey_mldsa.clone(),
                    kem_pubkey_x25519: sd.kem_pubkey_x25519.clone(),
                    kem_pubkey_mlkem: sd.kem_pubkey_mlkem.clone(),
                    device_name: sanitize_display_name(&sd.device_name).unwrap_or_default(),
                    is_active: sd.is_active,
                    last_seen: now,
                };
                self.persist_remote_device(&rec);
                self.known_remote_devices.insert(sd.device_fingerprint.clone(), rec);
                self.import_mailbox_secrets(sd);
                if let Some(addr) = &sd.last_addr { self.remember_device_addr(&sd.device_fingerprint, addr); }
            }
        }
        // Blocks made on a sibling (an unblock travels as `SiblingEchoBody::Blocked`).
        for id in &sync.blocked {
            if is_fingerprint_hex(id) && my_id.as_deref() != Some(id.as_str()) && !self.blocked_identities.contains(id) {
                if let Err(e) = self.block_identity_local(id) {
                    warn!("Block received via sync not applied: {}", e);
                }
            }
        }
        // The revokes of my own devices, for a sibling linked after them.
        // Each is checked against the root's signature; our own revoke is
        // left to the paths that may wipe this device.
        if let Some(my) = &my_id {
            let own_fp = self.get_active_own_device_fingerprint().ok();
            let held: Vec<String> = self.own_revokes().into_iter().map(|r| r.revoked_device_fingerprint).collect();
            for r in &sync.own_revokes {
                if &r.identity_id != my
                    || own_fp.as_deref() == Some(r.revoked_device_fingerprint.as_str())
                    || held.contains(&r.revoked_device_fingerprint)
                {
                    continue;
                }
                if let Err(e) = self.apply_device_revoke_notice(r, "") {
                    warn!("Own revocation received via sync not applied: {}", e);
                }
            }
        }
        learned
    }

    /// Sends a `DeviceAddNotice` to every contact. Each goes to the contact's known active devices, one by one (reliable delivery).
    pub(crate) fn broadcast_device_add_to_contacts(&mut self, device_add: &DeviceAdd) {
        let targets = self.contact_device_targets();
        // Embed the new device's full keys (we know them from the QR or the sibling record) in the announcement, so contacts can fan out
        // to it right away without waiting for a separate IdentityExchange.
        let device = match self.synced_device_for(&device_add.new_device_fingerprint) {
            Some(d) => d,
            None => { error!("DeviceAddNotice: new device keys unknown"); return; }
        };
        let content = MessageContent::DeviceAddNotice { device_add: device_add.clone(), device };
        for fp in targets {
            if let Err(e) = self.send_message_content(fp, &content, None) {
                error!("DeviceAddNotice send failed: {}", e);
            }
        }
    }

    /// After a secondary device is adopted: introduces it to every contact with an IdentityExchange (keys) and a DeviceAddNotice (authority proof).
    /// Contacts then treat this device as a message recipient and fan out to it.
    pub(crate) fn announce_self_to_all_contacts(&mut self) {
        let device_add = match &self.own_device_add { Some(d) => d.clone(), None => return };
        let my_id = self.my_identity_id();
        let ids: Vec<String> = self.contacts.values()
            .filter(|c| my_id.as_deref() != Some(c.trusted_identity_id.as_str()))
            .map(|c| c.trusted_identity_id.clone())
            .collect();
        let targets: Vec<String> = ids.iter().flat_map(|id| self.active_devices_for_identity(id)).collect();
        let device = match self.own_synced_device() {
            Some(d) => d,
            None => return,
        };
        let notice = MessageContent::DeviceAddNotice { device_add, device };
        for fp in targets {
            let _ = self.send_identity_exchange(&fp);
            if let Err(e) = self.send_message_content(fp, &notice, None) {
                error!("DeviceAddNotice failed while secondary device introduced itself: {}", e);
            }
        }
    }

    /// Sends the current contact and group state to the sibling devices (a delta). Called when a contact is added or a group changes.
    /// The sibling merges it idempotently.
    pub(crate) fn sync_to_siblings(&mut self) {
        let siblings = self.sibling_active_devices();
        self.sync_roster_to(siblings);
    }

    pub(crate) fn sync_roster_to(&mut self, siblings: Vec<String>) {
        if siblings.is_empty() { return; }
        let parts: Vec<MessageContent> = self.build_sync_payloads().into_iter().map(MessageContent::DeviceSync).collect();
        // An avatar-only part goes to a sibling once per picture:
        // every roster sync sent every contact avatar to every sibling, which
        // keeps the one it has anyway. `avs:<sibling>:<identity>` = its hash.
        let avatar_key = |fp: &str, content: &MessageContent| match content {
            MessageContent::DeviceSync(p) if p.contacts.len() == 1 && p.groups.is_empty() && p.contacts[0].devices.is_empty() => {
                p.contacts[0].avatar_jpeg.as_ref().map(|a| (
                    format!("avs:{}:{}", fp, p.contacts[0].identity_id),
                    hex::encode(&<sha2::Sha256 as sha2::Digest>::digest(a)[..8]),
                ))
            }
            _ => None,
        };
        // Each part goes to a sibling only when it changed since it was last
        // sent there (`rsh:<sibling>` = "sent at|hash,hash,..."): every trigger
        // (pairing steps, rename, reconnect after each network change) sent
        // the whole roster, about 4.2 KB per contact device, to every sibling.
        // Everything is sent again once a day, in case a copy was lost.
        let part_hash = |content: &MessageContent| ciborium_bytes(content).ok()
            .map(|b| hex::encode(&<sha2::Sha256 as sha2::Digest>::digest(&b)[..8]));
        let hashes: Vec<Option<String>> = parts.iter().map(|c| part_hash(c)).collect();
        let now = current_time_ms();
        for fp in siblings {
            let key = format!("rsh:{}", fp);
            let stored = self.meta_str(&key).unwrap_or_default();
            let (at, sent_list) = stored.split_once('|')
                .map(|(a, h)| (a.parse::<u64>().unwrap_or(0), h.to_string()))
                .unwrap_or((0, String::new()));
            let fresh = now.saturating_sub(at) < ROSTER_RESEND_ALL_MS;
            let sent: std::collections::HashSet<&str> = if fresh { sent_list.split(',').filter(|h| !h.is_empty()).collect() } else { Default::default() };
            let mut now_sent: Vec<String> = Vec::new();
            for (content, hash) in parts.iter().zip(&hashes) {
                if let Some(h) = hash.as_deref().filter(|h| sent.contains(h)) {
                    now_sent.push(h.to_string());
                    continue;
                }
                let avatar = avatar_key(&fp, content);
                if let Some((k, h)) = &avatar {
                    if self.meta_str(k).as_deref() == Some(h.as_str()) {
                        continue;
                    }
                }
                match self.send_message_content(fp.clone(), content, None) {
                    Ok(_) => {
                        if let Some((k, h)) = &avatar {
                            self.meta_put(k, h);
                        }
                        if let Some(h) = hash {
                            now_sent.push(h.clone());
                        }
                    }
                    Err(e) => error!("DeviceSync send failed: {}", e),
                }
            }
            self.meta_put(&key, &format!("{}|{}", if fresh { at } else { now }, now_sent.join(",")));
        }
    }

    /// Emits a "read boundary" packet (`read_at_ms`) when a chat is read on THIS device. It goes to two targets:
    ///   1. Sibling devices, so they also count the chat as read.
    ///   2. **The counterpart / group members.** This is now the reliable path for 1:1 read receipts. One packet says "I have read up to here".
    ///      It is idempotent (the timestamp only moves forward). `needs_delivery_confirmation` and `regen_content` persist it to disk, re-encrypt
    ///      it after a ratchet rotation, leave it on the server if the counterpart is offline, and retry until acknowledged (for up to 7 days).
    ///      The single `Seen` packet is fragile (9 in-memory attempts, not persisted, lost on restart or rotation, never sent for messages loaded
    ///      from history). It now serves only as a fast, fine-grained signal. Durability is handled here.
    ///
    /// `peer_fp`: the counterpart device of a 1:1 chat (empty for a group).
    /// `group_id`: the group chat (empty for 1:1).
    pub(crate) fn sync_read_state(&mut self, peer_fp: &str, group_id: &str, read_at_ms: u64) {
        let is_group = !group_id.is_empty();
        self.start_expiry_on_screen(peer_fp, group_id);
        // the reader compares the boundary with the SENDER's clock
        // (`sent_at_ms` of its own messages). With our clock behind theirs
        // their newest messages never counted as seen; the newest
        // `sent_at_ms` we received here is on their clock and was read now.
        let received_floor: Option<i64> = self.db.as_ref().and_then(|conn| if is_group {
            conn.query_row(
                "SELECT MAX(sent_at_ms) FROM messages WHERE group_id = ?1 AND direction = 'received'",
                params![group_id], |r| r.get::<_, Option<i64>>(0),
            ).ok().flatten()
        } else {
            conn.query_row(
                "SELECT MAX(sent_at_ms) FROM messages WHERE peer_device_fingerprint IN (?1, ?2)
                   AND (group_id IS NULL OR group_id = '') AND direction = 'received'",
                params![peer_fp, self.canonical_peer_key(peer_fp)], |r| r.get::<_, Option<i64>>(0),
            ).ok().flatten()
        });
        let read_at_ms = read_at_ms.max(received_floor.unwrap_or(0).max(0) as u64);
        let gid_owned = if is_group { Some(group_id.to_string()) } else { None };
        let conv_id_owned = if is_group {
            None
        } else {
            match self.known_remote_devices.get(peer_fp) {
                Some(d) => Some(d.identity_id.clone()),
                None => return,
            }
        };
        // Nothing received since the last send: every chat open (the frontends pass "now") sent one signed packet to each
        // sibling and to every device of every group member, a server deposit for each offline one, with nothing new
        // for any of them to mark.
        let floor = received_floor.unwrap_or(0).max(0) as u64;
        let sent_key = format!("rsw:{}", gid_owned.as_deref().or(conv_id_owned.as_deref()).unwrap_or(""));
        if floor == 0 || floor <= self.meta_u64(&sent_key) {
            return;
        }
        self.meta_put(&sent_key, &floor.to_string());
        let content = MessageContent::ReadStateSync {
            conversation_identity_id: conv_id_owned.clone(),
            group_id: gid_owned.clone(),
            read_at_ms,
        };

        // Prevent pile-up (same pattern as `request_history_sync`): drop the older pending read-boundary retries for this conversation.
        // The new, larger `read_at_ms` covers all of them. Otherwise every chat open or `onResume` would add one more durable retry row
        // for an offline peer.
        let stale: Vec<String> = self.awaiting_confirmation.iter()
            .filter(|(_, p)| matches!(
                &p.regen_content,
                Some(MessageContent::ReadStateSync { group_id: g, conversation_identity_id: c, .. })
                    if *g == gid_owned && *c == conv_id_owned
            ))
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            self.awaiting_confirmation.remove(&id);
            self.remove_durable_retry(&id);
        }

        // Collect the targets first (borrow checker: before sending).
        let mut targets: Vec<String> = self.sibling_active_devices();
        self.journal_sibling_op(&content, &targets);
        if is_group {
            if let Ok(group) = self.groups.get(group_id).cloned_group() {
                let own_id = self.my_identity_id().unwrap_or_default();
                // Every live device of each member, like the 1:1 case below (with the same stale-device rule as `fanout_targets`).
                for member_identity_id in group.other_members(&own_id) {
                    let all = self.active_devices_for_identity(&member_identity_id);
                    let recent: Vec<String> = all.iter().filter(|fp| self.device_recently_seen(fp)).cloned().collect();
                    targets.extend(if recent.is_empty() { all } else { recent });
                }
            }
        } else if self.known_remote_devices.contains_key(peer_fp) {
            // Every live device of the contact, as a message goes. The
            // canonical device alone is the OLDEST one: after the contact
            // changed phones the watermark went only to the dead one.
            targets.extend(self.fanout_targets(peer_fp));
        }
        targets.sort();
        targets.dedup();

        for fp in targets {
            let _ = self.send_message_content(fp, &content, None);
        }
    }

    /// Handles a `ReadStateSync` (read boundary) from the counterpart (NOT a sibling) by applying a BULK seen receipt. The sender identity is the
    /// reader (`viewer`). It marks every message I sent in this conversation up to the boundary `read_at_ms` as seen, via `apply_seen_receipt`
    /// (idempotent: an older boundary never overwrites a newer record). Returns the affected `message_id`s, oldest first. Kotlin uses them for the `seen_bulk` event.
    pub(crate) fn apply_incoming_read_watermark(
        &self,
        peer_fp: &str,
        group_id: Option<&str>,
        viewer_identity_id: &str,
        read_at_ms: u64,
    ) -> Vec<String> {
        let Some(conn) = &self.db else { return Vec::new() };
        // The boundary is in the sender's clock. Clamp it to now, so a future timestamp (clock skew, or a malicious peer) cannot overwrite
        // later genuine `Seen` receipts in the monotonic check.
        let read_at_ms = read_at_ms.min(current_time_ms());
        let read_at = read_at_ms as i64;
        let mut ids: Vec<String> = Vec::new();

        if let Some(gid) = group_id {
            // See `sender_may_post_to_group`: a non-member must not be able to mark my group messages as seen.
            if !self.sender_may_post_to_group(gid, viewer_identity_id) {
                return Vec::new();
            }
            if let Ok(mut stmt) = conn.prepare(
                "SELECT message_id FROM messages
                 WHERE group_id = ?1 AND direction = 'sent'
                   AND message_id IS NOT NULL AND message_id != ''
                   AND COALESCE(NULLIF(sent_at_ms, 0), timestamp) <= ?2
                   AND NOT EXISTS (SELECT 1 FROM message_seen s WHERE s.message_id = messages.message_id AND s.viewer_identity_id = ?3)
                 ORDER BY COALESCE(NULLIF(sent_at_ms, 0), timestamp) ASC"
            ) {
                if let Ok(rows) = stmt.query_map(params![gid, read_at, viewer_identity_id], |r| r.get::<_, String>(0)) {
                    for id in rows.flatten() { ids.push(id); }
                }
            }
        } else {
            // For 1:1, the messages may be archived under the peer's canonical device fp. Try both the incoming fp and the canonical one.
            let mut keys: Vec<String> = vec![peer_fp.to_string()];
            if let Some(d) = self.known_remote_devices.get(peer_fp) {
                if let Some(canon) = self.canonical_device_for_identity(&d.identity_id) {
                    if canon != peer_fp { keys.push(canon); }
                }
            }
            let mut have: std::collections::HashSet<String> = ids.iter().cloned().collect();
            for k in keys {
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT message_id FROM messages
                     WHERE peer_device_fingerprint = ?1 AND direction = 'sent'
                       AND (group_id IS NULL OR group_id = '')
                       AND message_id IS NOT NULL AND message_id != ''
                       AND COALESCE(NULLIF(sent_at_ms, 0), timestamp) <= ?2
                       AND NOT EXISTS (SELECT 1 FROM message_seen s WHERE s.message_id = messages.message_id AND s.viewer_identity_id = ?3)
                     ORDER BY COALESCE(NULLIF(sent_at_ms, 0), timestamp) ASC"
                ) {
                    if let Ok(rows) = stmt.query_map(params![k, read_at, viewer_identity_id], |r| r.get::<_, String>(0)) {
                        for id in rows.flatten() {
                            if have.insert(id.clone()) { ids.push(id); }
                        }
                    }
                }
            }
        }

        // A read boundary only covers what actually reached the reader: a message
        // still waiting for its Ack was never displayed there, however old it is.
        // The boundary comes from ONE device (`peer_fp`): only copies still waiting for THAT
        // device count. A copy for another, offline device of the same reader does not.
        // A copy waits under its packet id; the row id is that id (1:1 main copy) or its
        // `group_message_local_id` (group copies, 1:1 fan-out copies).
        let mut waiting: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (key, p) in self.awaiting_confirmation.iter().filter(|(_, p)| p.peer_device_fingerprint == peer_fp) {
            if group_id.is_none() { waiting.insert(key.clone()); }
            if let Some(MessageContent::Text { group_id: g, group_message_local_id: Some(l), .. }) = &p.regen_content {
                if g.as_deref() == group_id { waiting.insert(l.clone()); }
            }
        }
        if let Some(gid) = group_id {
            // Copies still queued for the reader (no device known yet) never reached it either.
            if let Some(q) = self.pending_group_messages.get(&(gid.to_string(), viewer_identity_id.to_string())) {
                waiting.extend(q.iter().filter_map(|c| match c {
                    MessageContent::Text { group_message_local_id: Some(l), .. } => Some(l.clone()),
                    _ => None,
                }));
            }
        }
        ids.retain(|id| !waiting.contains(id));
        for id in &ids {
            self.apply_seen_receipt(id, viewer_identity_id, read_at_ms);
        }
        ids
    }

    /// Multi-device: echoes a 1:1 message, edit, or delete that I sent to my sibling devices, so it also appears as "sent" there.
    /// `peer_fp`: the device of the contact I sent to (its identity is resolved from it).
    pub(crate) fn echo_1to1_to_siblings(&mut self, peer_fp: &str, body: SiblingEchoBody) {
        let identity_id = match self.known_remote_devices.get(peer_fp) {
            Some(d) => d.identity_id.clone(),
            None => return,
        };
        let content = MessageContent::SiblingEcho {
            conversation_identity_id: Some(identity_id),
            group_id: None,
            body,
        };
        let siblings = self.sibling_active_devices();
        // Also for a sibling not in the list (stale) or one whose copy is lost: see `journal_sibling_op`.
        self.journal_sibling_op(&content, &siblings);
        if siblings.is_empty() {
            // If no sibling device is linked, this silently sends NOTHING. The log distinguishes "the edit/delete never reached the other device"
            // here from a send failure (the `error!` below). An empty list means either no sibling device is linked, or the roster sync
            // (`sync_to_siblings`) has not completed yet.
            warn!("echo_1to1_to_siblings: no known active sibling device, nothing sent (peer={})", crate::log_id(&peer_fp));
            return;
        }
        for fp in siblings {
            if let Err(e) = self.send_message_content(fp.clone(), &content, None) {
                error!("SiblingEcho (1:1) send failed (sibling={}): {}", crate::log_id(&fp), e);
            }
        }
    }

    /// See `echo_1to1_to_siblings`. The group counterpart.
    pub(crate) fn echo_group_to_siblings(&mut self, group_id: &str, body: SiblingEchoBody) {
        let content = MessageContent::SiblingEcho {
            conversation_identity_id: None,
            group_id: Some(group_id.to_string()),
            body,
        };
        let siblings = self.sibling_active_devices();
        self.journal_sibling_op(&content, &siblings);
        if siblings.is_empty() {
            // Same debugging rationale as `echo_1to1_to_siblings`.
            warn!("echo_group_to_siblings: no known active sibling device, nothing sent (group={})", group_id);
            return;
        }
        for fp in siblings {
            if let Err(e) = self.send_message_content(fp.clone(), &content, None) {
                error!("SiblingEcho (group) send failed (sibling={}): {}", crate::log_id(&fp), e);
            }
        }
    }

    /// Multi-device: asks sibling devices for a history backfill. While this device was offline it may have missed messages sent by CONTACTS
    /// (fan-out copies that timed out). Debounced.
    pub(crate) fn request_sibling_backfill(&mut self) {
        let now = current_time_ms();
        if now.saturating_sub(self.last_sibling_backfill_at) < SIBLING_BACKFILL_INTERVAL_MS {
            return;
        }
        // Only connected siblings are asked. An offline one cannot answer, and an unanswered request is retried and re-deposited on the server until it expires.
        // That repeated deposit kept the radio busy all night.
        let siblings: Vec<String> = self.sibling_active_devices().into_iter()
            .filter(|fp| self.is_connected_to_device(fp)).collect();
        if siblings.is_empty() { return; }
        self.last_sibling_backfill_at = now;
        for fp in siblings {
            self.send_sibling_backfill_request(&fp);
        }
    }

    /// A row from a contact or group member was archived at `archived_at` (this device's clock).
    /// `flush_sibling_push` sends it to the connected siblings at the end of the poll turn.
    pub(crate) fn note_sibling_push(&mut self, archived_at: i64) {
        self.sibling_push_from = Some(self.sibling_push_from.map_or(archived_at, |f| f.min(archived_at)));
    }

    /// Pushes the rows noted by `note_sibling_push` to every connected sibling as an unsolicited
    /// `SiblingHistoryResponse` (no window, no `ops_seq`, so it is no backfill answer). A sibling
    /// that a sender cannot reach (parked, no address for it, no common server) otherwise got
    /// the row only from the 30-minute backfill. One push per poll turn, so a server batch goes
    /// as one packet. A sibling not connected now gets the rows from its next backfill.
    pub(crate) fn flush_sibling_push(&mut self) {
        let Some(from) = self.sibling_push_from.take() else { return };
        let siblings: Vec<String> = self.sibling_active_devices().into_iter()
            .filter(|fp| self.is_connected_to_device(fp)).collect();
        if siblings.is_empty() { return; }
        let (entries, _, _) = self.build_sibling_backfill(from);
        if entries.is_empty() { return; }
        info!("Sibling push: {} rows to {} sibling(s)", entries.len(), siblings.len());
        let resp = MessageContent::SiblingHistoryResponse { entries, window: None, more: false, covered_to: None, ops_seq: None };
        for fp in siblings {
            if let Err(e) = self.send_message_content(fp.clone(), &resp, None) {
                warn!("Sibling push could not be sent (sibling={}): {}", crate::log_id(&fp), e);
            }
        }
    }

    /// Chat open: asks every connected sibling for the newest `SIBLING_BACKFILL_PER_CONVERSATION` rows of one chat
    /// (`chat_key`: the group id, or the contact's device fingerprint). No window, so the history floor still keeps out
    /// what the user cleared. Covers rows neither the sender nor `flush_sibling_push` brought here.
    pub(crate) fn refresh_chat_from_siblings(&mut self, chat_key: &str, is_group: bool) {
        let conversation_identity_id = if is_group {
            if !self.groups.contains_key(chat_key) { return; }
            None
        } else {
            match self.identity_id_for_device(chat_key) {
                Some(id) => Some(id),
                None => return,
            }
        };
        let chat = conversation_identity_id.clone().unwrap_or_else(|| chat_key.to_string());
        let now = current_time_ms();
        if self.sibling_refresh_at.get(&chat).map_or(false, |at| now.saturating_sub(*at) < SIBLING_REFRESH_MIN_MS) {
            return;
        }
        let siblings: Vec<String> = self.sibling_active_devices().into_iter()
            .filter(|fp| self.is_connected_to_device(fp)).collect();
        if siblings.is_empty() { return; }
        self.sibling_refresh_at.insert(chat, now);
        let content = MessageContent::SiblingHistoryRequest {
            per_conversation_limit: SIBLING_BACKFILL_PER_CONVERSATION,
            conversation_identity_id,
            group_id: is_group.then(|| chat_key.to_string()),
            before_timestamp: None,
            since_timestamp: None,
            after_timestamp: None,
            ops_since: None,
        };
        for fp in siblings {
            if let Err(e) = self.send_message_content(fp.clone(), &content, None) {
                warn!("Chat refresh request could not be sent (sibling={}): {}", crate::log_id(&fp), e);
            }
        }
    }

    /// One unscoped backfill request to `fp`: only what it archived since its last answer (`sibling_backfill_since`,
    /// on disk as `sbw:<fp>`, so a restart does not start over with the newest rows), and its journal operations
    /// after the last position it reported (`sjw:<fp>`).
    pub(crate) fn send_sibling_backfill_request(&mut self, fp: &str) {
        let now = current_time_ms();
        let saved = self.meta_u64(&format!("sbw:{}", fp));
        let ops_since = self.meta_str(&format!("sjw:{}", fp)).and_then(|v| v.parse::<u64>().ok());
        let state = self.sibling_backfill_since.entry(fp.to_string()).or_insert((0, saved));
        let since = (state.1 > 0).then(|| state.1.min(i64::MAX as u64) as i64);
        state.0 = now;
        let content = MessageContent::SiblingHistoryRequest {
            per_conversation_limit: SIBLING_BACKFILL_PER_CONVERSATION,
            conversation_identity_id: None,
            group_id: None,
            before_timestamp: None,
            since_timestamp: since,
            after_timestamp: None,
            ops_since,
        };
        let _ = self.send_message_content(fp.to_string(), &content, None);
    }

    /// A backfill answer from `fp`: moves its watermark and journal position, and asks for the rest at once when the
    /// answer was cut. `covered_to`: the sibling's clock, taken as is; `None` (the first answer, newest rows per chat)
    /// keeps the request time minus a clock-skew margin.
    pub(crate) fn note_sibling_backfill_answer(&mut self, fp: &str, covered_to: Option<i64>, ops_seq: Option<u64>, more: bool) {
        let mut advanced = false;
        if let Some(state) = self.sibling_backfill_since.get_mut(fp) {
            if state.0 > 0 {
                let next = match covered_to {
                    Some(c) => c.max(0) as u64,
                    None => state.0.saturating_sub(SIBLING_BACKFILL_SINCE_MARGIN_MS),
                };
                advanced = next != state.1;
                *state = (0, next);
                let next = next.to_string();
                self.meta_put(&format!("sbw:{}", fp), &next);
            }
        }
        if let Some(seq) = ops_seq {
            let key = format!("sjw:{}", fp);
            if self.meta_str(&key).and_then(|v| v.parse::<u64>().ok()) != Some(seq) {
                advanced = true;
                self.meta_put(&key, &seq.to_string());
            }
        }
        // Each follow-up starts where this answer ended, so the chain ends.
        if more && advanced {
            self.send_sibling_backfill_request(fp);
        }
    }

    /// The automatic backfill after a watermark (`since`, this device's archive clock): every row and attachment
    /// archived in `[since, covered_to)`, oldest first, within the entry and byte caps. Returns
    /// `(entries, covered_to, cut)`. A cut answer ends at a time over all chats: the per-chat limit of
    /// `build_sibling_history_response` kept only the newest rows of a busy chat, and the watermark then passed the
    /// rest for good.
    pub(crate) fn build_sibling_backfill(&self, since: i64) -> (Vec<SiblingHistoryEntry>, i64, bool) {
        let now = current_time_ms().min(i64::MAX as u64) as i64;
        let Some(conn) = &self.db else { return (Vec::new(), since, false) };
        let cap = SIBLING_BACKFILL_MAX_ENTRIES;
        let since = since.max(0);
        // The first time past the cap over all chats: everything before it fits one answer by count.
        let cut: Option<i64> = conn.query_row(
            "SELECT t FROM (SELECT timestamp AS t FROM messages WHERE timestamp >= ?1
                            UNION ALL SELECT created_at AS t FROM files WHERE status = 'complete' AND created_at >= ?1)
             ORDER BY t LIMIT 1 OFFSET ?2",
            params![since, cap as i64], |r| r.get(0),
        ).ok();
        // ponytail: more than a whole answer archived in one millisecond (a history-sync batch) goes whole into the
        // merge below, which ends inside it and skips the rest of that millisecond. A (time, id) cursor if that matters.
        let hi = cut.map_or(i64::MAX, |c| c.max(since + 1));
        let peers: Vec<String> = conn.prepare(
            "SELECT peer_device_fingerprint FROM messages WHERE group_id IS NULL AND peer_device_fingerprint IS NOT NULL AND timestamp >= ?1 AND timestamp < ?2
             UNION SELECT peer_device_fingerprint FROM files WHERE group_id IS NULL AND peer_device_fingerprint IS NOT NULL AND status = 'complete' AND created_at >= ?1 AND created_at < ?2",
        ).and_then(|mut st| st.query_map(params![since, hi], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<String>>>())
            .unwrap_or_default();
        let own_id = self.my_identity_id();
        let rows_max = cap as u32 + 1;
        let mut unlimited = usize::MAX;
        let mut all: Vec<(i64, SiblingHistoryEntry)> = Vec::new();
        let mut files_done: std::collections::HashSet<String> = std::collections::HashSet::new();
        for peer_fp in peers {
            let Some(identity_id) = self.known_remote_devices.get(&peer_fp).map(|d| d.identity_id.clone()) else { continue };
            if own_id.as_ref() == Some(&identity_id) { continue; }
            for m in self.load_message_history_q(&peer_fp, rows_max, Some(hi), Some(since - 1), false, false) {
                if m.is_deleted { continue; }
                let Some(mid) = m.message_id.clone().filter(|id| !id.is_empty()) else { continue };
                let reactions = self.reaction_rows(&mid);
                all.push((m.timestamp.min(i64::MAX as u64) as i64, SiblingHistoryEntry {
                    conversation_identity_id: Some(identity_id.clone()),
                    group_id: None,
                    direction: m.direction,
                    text: m.text,
                    message_id: mid,
                    sender_identity_id: None,
                    reply_to_message_id: m.reply_to_message_id,
                    reply_to_preview: m.reply_to_preview,
                    reply_to_sender_identity_id: None,
                    sent_at_ms: m.sent_at_ms,
                    relayed_by: None,
                    file: None,
                    reactions,
                }));
            }
            // Attachments once per contact (they live under any of its devices).
            if files_done.insert(identity_id.clone()) {
                let fps: Vec<String> = self.known_remote_devices.values()
                    .filter(|d| d.identity_id == identity_id)
                    .map(|d| d.device_fingerprint.clone())
                    .collect();
                for e in self.sibling_file_entries(&fps, None, Some(&identity_id), since, hi, rows_max, &mut unlimited) {
                    all.push((e.sent_at_ms.min(i64::MAX as u64) as i64, e));
                }
            }
        }
        for gid in self.groups.keys() {
            for m in self.load_group_message_history_q(gid, rows_max, Some(hi), Some(since - 1), false, false) {
                if m.is_deleted { continue; }
                let Some(mid) = m.message_id.clone().filter(|id| !id.is_empty()) else { continue };
                let reactions = self.reaction_rows(&mid);
                all.push((m.timestamp.min(i64::MAX as u64) as i64, SiblingHistoryEntry {
                    conversation_identity_id: None,
                    group_id: Some(gid.clone()),
                    direction: m.direction,
                    text: m.text,
                    message_id: mid,
                    sender_identity_id: m.sender_identity_id,
                    reply_to_message_id: m.reply_to_message_id,
                    reply_to_preview: m.reply_to_preview,
                    reply_to_sender_identity_id: m.reply_to_sender_identity_id,
                    sent_at_ms: m.sent_at_ms,
                    relayed_by: m.relayed_by,
                    file: None,
                    reactions,
                }));
            }
            for e in self.sibling_file_entries(&[], Some(gid), None, since, hi, rows_max, &mut unlimited) {
                all.push((e.sent_at_ms.min(i64::MAX as u64) as i64, e));
            }
        }
        all.sort_by_key(|(t, _)| *t);
        let cost = |e: &SiblingHistoryEntry| match e.file.as_deref() {
            Some(MessageContent::FileOffer { caption, chunk_hashes, preview_jpeg, .. }) =>
                512 + caption.len() + chunk_hashes.len() + preview_jpeg.as_ref().map_or(0, |p| p.len()),
            _ => e.text.len(),
        };
        let mut covered = cut.map_or(now.max(since), |c| c.max(since + 1));
        let mut stopped = false;
        let mut budget = HISTORY_SYNC_MAX_TEXT_BYTES;
        let mut entries = Vec::new();
        for (t, mut e) in all {
            if entries.len() >= cap {
                covered = covered.min(t.max(since + 1));
                stopped = true;
                break;
            }
            if cost(&e) > budget {
                // An attachment goes without its preview first, as in `sibling_file_entries`.
                if let Some(MessageContent::FileOffer { preview_jpeg, .. }) = e.file.as_deref_mut() {
                    *preview_jpeg = None;
                }
            }
            let c = cost(&e);
            // Never fits an answer: skipped for good, as before.
            if c > HISTORY_SYNC_MAX_TEXT_BYTES { continue; }
            if c > budget {
                covered = covered.min(t.max(since + 1));
                stopped = true;
                break;
            }
            budget -= c;
            entries.push(e);
        }
        (entries, covered, cut.is_some() || stopped)
    }

    /// Requests an older page of ONE chat from our own sibling devices, even when the counterpart (contact or group member) is unreachable.
    /// Unlike the automatic, bounded `request_sibling_backfill` (which covers ALL chats), this is triggered when the user scrolls up in a chat
    /// and asks for older messages. `peer_device_fingerprint` is the counterpart device of the 1:1 chat (the canonical device fp on this device;
    /// `conversation_identity_id` is resolved from it). `group_id` is the group chat. Both cannot be set at once: the caller (JNI) passes whichever is set.
    ///
    /// The window `[after, before)` of a "Fetch older history" press, sent
    /// to every connected sibling (or only `to`, a follow-up page). Each
    /// request is recorded in `sibling_fetch_open`: only the answer that
    /// echoes it is a user fetch.
    pub(crate) fn request_older_sibling_history(&mut self, conversation_identity_id: Option<&str>, group_id: Option<&str>, before: i64, after: i64, to: Option<&str>) -> Result<(), String> {
        // Connected siblings only, as in `request_sibling_backfill`: each
        // scroll-up queued one more request for an offline one.
        let siblings: Vec<String> = self.sibling_active_devices().into_iter()
            .filter(|fp| self.is_connected_to_device(fp) && to.map_or(true, |t| t == fp.as_str())).collect();
        if siblings.is_empty() {
            return Err("No sibling device".to_string());
        }
        let chat = conversation_identity_id.or(group_id).ok_or("No chat")?.to_string();
        let content = MessageContent::SiblingHistoryRequest {
            per_conversation_limit: HISTORY_SYNC_MAX_MESSAGES,
            conversation_identity_id: conversation_identity_id.map(|s| s.to_string()),
            group_id: group_id.map(|s| s.to_string()),
            before_timestamp: Some(before),
            since_timestamp: None,
            after_timestamp: Some(after),
            ops_since: None,
        };
        let now = current_time_ms();
        self.sibling_fetch_open.retain(|_, (_, at)| now.saturating_sub(*at) < TEXT_RETRY_GIVE_UP_MS);
        let mut sent_to_any = false;
        for fp in siblings {
            if self.send_message_content(fp.clone(), &content, None).is_ok() {
                self.sibling_fetch_open.insert((fp, before, after), (chat.clone(), now));
                sent_to_any = true;
            }
        }
        if sent_to_any { Ok(()) } else { Err("Could not send to sibling device".to_string()) }
    }

    /// Collects the last `limit` messages from my own archive. This is the answer to a sibling's backfill request. The total number of
    /// entries is capped by `SIBLING_BACKFILL_MAX_ENTRIES`.
    ///
    /// If both `scope_identity_id` and `scope_group_id` are `None`, the old behaviour applies: ALL chats, and `before_timestamp` is ignored
    /// (the automatic `request_sibling_backfill` uses this). If one is set, the request narrows to that single chat, and `before_timestamp`
    /// (if set) is used for its paging (see `request_older_sibling_history`).
    /// `window`: the `(before, after)` of a scoped "Fetch older history" request. Only rows sent inside it are returned. The second value is `more`:
    /// rows of the scoped request were cut (row or byte limit).
    pub(crate) fn build_sibling_history_response(&self, limit: u32, scope_identity_id: Option<&str>, scope_group_id: Option<&str>, before_timestamp: Option<i64>, since_timestamp: Option<i64>, window: Option<(i64, i64)>) -> (Vec<SiblingHistoryEntry>, bool) {
        // rows come newest first (local `timestamp`), so stop at the first older one.
        let too_old = |m: &ArchivedMessage| since_timestamp.is_some_and(|s| (m.timestamp as i64) < s);
        let mut entries = Vec::new();
        // The row-count cap alone did not guarantee the 1 MiB envelope limit (long message texts). See `HISTORY_SYNC_MAX_TEXT_BYTES`.
        let mut text_budget: usize = HISTORY_SYNC_MAX_TEXT_BYTES;
        let own_id = self.my_identity_id();
        // Unscoped (the automatic backfill): the entry cap is shared. With `limit` rows from each chat, the first ten 1:1 chats filled it,
        // so the other chats and all groups were never sent in any backfill.
        // ponytail: with more conversations than the cap, the last ones still get nothing. Rotate the start if that ever matters.
        let unscoped = scope_identity_id.is_none() && scope_group_id.is_none();
        // Attachment rows have only their local `created_at`.
        let file_bounds = match window {
            Some((before, after)) if !unscoped => (after, before),
            _ => (since_timestamp.unwrap_or(0), before_timestamp.unwrap_or(i64::MAX)),
        };
        let mut limit = limit;
        let mut more = false;
        // A press pages back from the oldest local row, so attachments and
        // reactions among the rows already here were never in any window.
        // They go after the window's rows, with what budget is left.
        let newer_lo = match window { Some((before, _)) if !unscoped => Some(before), _ => None };
        let mut newer: Vec<(Vec<String>, Option<String>, Option<String>)> = Vec::new();
        if scope_group_id.is_none() {
            // 1:1 chats. If narrowed to ONE contact, use all known devices of that contact (wherever the archive stores them).
            // Otherwise use every peer's rows in the archive.
            let peers: Vec<String> = if let Some(scope_id) = scope_identity_id {
                self.known_remote_devices.values()
                    .filter(|d| d.identity_id == scope_id)
                    .map(|d| d.device_fingerprint.clone())
                    .collect()
            } else if let Some(conn) = &self.db {
                let mut stmt = match conn.prepare("SELECT DISTINCT peer_device_fingerprint FROM messages WHERE group_id IS NULL") {
                    Ok(s) => s,
                    Err(_) => return (entries, false),
                };
                let rows = stmt.query_map([], |r| r.get::<_, String>(0));
                rows.map(|it| it.flatten().collect()).unwrap_or_default()
            } else {
                Vec::new()
            };
            if unscoped {
                limit = limit.min((SIBLING_BACKFILL_MAX_ENTRIES / (peers.len() + self.groups.len()).max(1)).max(1) as u32);
            }
            let (lo, hi) = file_bounds;
            let mut files_done: std::collections::HashSet<String> = std::collections::HashSet::new();
            for peer_fp in peers {
                let identity_id = match self.known_remote_devices.get(&peer_fp) {
                    Some(d) => d.identity_id.clone(),
                    None => continue,
                };
                if own_id.as_ref() == Some(&identity_id) { continue; }
                // Attachments, once per contact; for the backfill after the rows.
                if !unscoped && files_done.insert(identity_id.clone()) {
                    let fps: Vec<String> = self.known_remote_devices.values()
                        .filter(|d| d.identity_id == identity_id)
                        .map(|d| d.device_fingerprint.clone())
                        .collect();
                    for e in self.sibling_file_entries(&fps, None, Some(&identity_id), lo, hi, limit, &mut text_budget) {
                        entries.push(e);
                        if entries.len() >= SIBLING_BACKFILL_MAX_ENTRIES { return (entries, true); }
                    }
                    if newer_lo.is_some() { newer.push((fps, None, Some(identity_id.clone()))); }
                }
                // Newest first. A scoped request pages backwards from its
                // oldest row: a row skipped for the budget while older ones
                // were sent was a hole for good, so that reply ends there.
                let rows = match window {
                    Some((before, after)) if !unscoped => self.load_history_fetch_page(&peer_fp, None, limit, before, after),
                    _ => self.load_message_history_opt(&peer_fp, limit, before_timestamp, false),
                };
                if !unscoped && rows.len() as u32 >= limit { more = true; }
                for m in rows.into_iter().rev() {
                    if too_old(&m) { break; }
                    if m.is_deleted { continue; }
                    let mid = match &m.message_id { Some(id) if !id.is_empty() => id.clone(), _ => continue };
                    // Unscoped: skip, do not stop: one long early message used
                    // to cut off every later conversation, on every backfill.
                    if m.text.len() > text_budget {
                        if !unscoped && !entries.is_empty() { return (entries, true); }
                        continue;
                    }
                    text_budget -= m.text.len();
                    entries.push(SiblingHistoryEntry {
                        conversation_identity_id: Some(identity_id.clone()),
                        group_id: None,
                        direction: m.direction,
                        text: m.text,
                        message_id: mid.clone(),
                        sender_identity_id: None,
                        reply_to_message_id: m.reply_to_message_id,
                        reply_to_preview: m.reply_to_preview,
                        reply_to_sender_identity_id: None,
                        sent_at_ms: m.sent_at_ms,
                        relayed_by: None,
                        file: None,
                        reactions: self.reaction_rows(&mid),
                    });
                    if entries.len() >= SIBLING_BACKFILL_MAX_ENTRIES { return (entries, true); }
                }
                // Attachments come after the text rows. Their previews would otherwise use up the budget before any text row of the chat.
                // Once per contact (they live under any of its devices).
                // A scoped press keeps them first: it ends at its first budget skip, and pages back from the oldest row it got.
                if unscoped && files_done.insert(identity_id.clone()) {
                    let fps: Vec<String> = self.known_remote_devices.values()
                        .filter(|d| d.identity_id == identity_id)
                        .map(|d| d.device_fingerprint.clone())
                        .collect();
                    for e in self.sibling_file_entries(&fps, None, Some(&identity_id), lo, hi, limit, &mut text_budget) {
                        entries.push(e);
                        if entries.len() >= SIBLING_BACKFILL_MAX_ENTRIES { return (entries, true); }
                    }
                    if newer_lo.is_some() { newer.push((fps, None, Some(identity_id.clone()))); }
                }
            }
        }
        if scope_identity_id.is_none() {
            // Groups: if narrowed to ONE group, only that group. Otherwise all of them.
            let gids: Vec<String> = match scope_group_id {
                Some(gid) => vec![gid.to_string()],
                None => self.groups.keys().cloned().collect(),
            };
            for gid in gids {
                if !unscoped {
                    let (lo, hi) = file_bounds;
                    for e in self.sibling_file_entries(&[], Some(&gid), None, lo, hi, limit, &mut text_budget) {
                        entries.push(e);
                        if entries.len() >= SIBLING_BACKFILL_MAX_ENTRIES { return (entries, true); }
                    }
                    if newer_lo.is_some() { newer.push((Vec::new(), Some(gid.clone()), None)); }
                }
                let rows = match window {
                    Some((before, after)) if !unscoped => self.load_history_fetch_page("", Some(&gid), limit, before, after),
                    _ => self.load_group_message_history_opt(&gid, limit, before_timestamp, false),
                };
                if !unscoped && rows.len() as u32 >= limit { more = true; }
                for m in rows.into_iter().rev() {
                    if too_old(&m) { break; }
                    if m.is_deleted { continue; }
                    let mid = match &m.message_id { Some(id) if !id.is_empty() => id.clone(), _ => continue };
                    let cost = m.text.len();
                    // see the 1:1 loop above.
                    if cost > text_budget {
                        if !unscoped && !entries.is_empty() { return (entries, true); }
                        continue;
                    }
                    text_budget -= cost;
                    entries.push(SiblingHistoryEntry {
                        conversation_identity_id: None,
                        group_id: Some(gid.clone()),
                        direction: m.direction,
                        text: m.text,
                        message_id: mid.clone(),
                        sender_identity_id: m.sender_identity_id,
                        reply_to_message_id: m.reply_to_message_id,
                        reply_to_preview: m.reply_to_preview,
                        reply_to_sender_identity_id: m.reply_to_sender_identity_id,
                        sent_at_ms: m.sent_at_ms,
                        relayed_by: m.relayed_by,
                        file: None,
                        reactions: self.reaction_rows(&mid),
                    });
                    if entries.len() >= SIBLING_BACKFILL_MAX_ENTRIES { return (entries, true); }
                }
                // Attachments after the text rows, as for 1:1 chats.
                if unscoped {
                    let (lo, hi) = file_bounds;
                    for e in self.sibling_file_entries(&[], Some(&gid), None, lo, hi, limit, &mut text_budget) {
                        entries.push(e);
                        if entries.len() >= SIBLING_BACKFILL_MAX_ENTRIES { return (entries, true); }
                    }
                    if newer_lo.is_some() { newer.push((Vec::new(), Some(gid.clone()), None)); }
                }
            }
        }
        if let Some(lo) = newer_lo {
            for (fps, gid, identity_id) in newer {
                let mut extra = self.sibling_file_entries(&fps, gid.as_deref(), identity_id.as_deref(), lo, i64::MAX, limit, &mut text_budget);
                extra.extend(self.sibling_reaction_entries(&fps, gid.as_deref(), identity_id.as_deref(), lo, limit, &mut text_budget));
                for e in extra {
                    if entries.len() >= SIBLING_BACKFILL_MAX_ENTRIES { return (entries, more); }
                    entries.push(e);
                }
            }
        }
        (entries, more)
    }

    /// Text rows sent at or after `lo` that have reactions, without their
    /// text: the receiver only applies the reactions to a row it holds.
    pub(crate) fn sibling_reaction_entries(&self, fps: &[String], group_id: Option<&str>, identity_id: Option<&str>, lo: i64, limit: u32, budget: &mut usize) -> Vec<SiblingHistoryEntry> {
        let Some(conn) = &self.db else { return Vec::new() };
        if group_id.is_none() && fps.is_empty() { return Vec::new(); }
        let chat = match group_id {
            Some(_) => "group_id = ?1".to_string(),
            None => format!("group_id IS NULL AND peer_device_fingerprint IN ({})",
                (1..=fps.len()).map(|i| format!("?{}", i)).collect::<Vec<_>>().join(",")),
        };
        let at = "COALESCE(NULLIF(sent_at_ms,0), timestamp)";
        let sql = format!(
            "SELECT message_id, direction, sender_identity_id, {at} FROM messages
             WHERE {chat} AND {at} >= {lo} AND is_deleted = 0
               AND message_id IN (SELECT message_id FROM message_reactions)
             ORDER BY {at} DESC LIMIT {limit}");
        let args: Vec<String> = match group_id { Some(g) => vec![g.to_string()], None => fps.to_vec() };
        let rows: Vec<(String, String, Option<String>, i64)> = match conn.prepare(&sql) {
            Ok(mut stmt) => stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .map(|it| it.flatten().collect()).unwrap_or_default(),
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for (mid, direction, sender, at) in rows {
            let reactions = self.reaction_rows(&mid);
            let cost = 128 + mid.len() + reactions.iter().map(|(r, e, _)| 16 + r.len() + e.len()).sum::<usize>();
            if cost > *budget { continue; }
            *budget -= cost;
            out.push(SiblingHistoryEntry {
                conversation_identity_id: identity_id.map(str::to_string),
                group_id: group_id.map(str::to_string),
                direction,
                text: String::new(),
                message_id: mid,
                sender_identity_id: sender,
                reply_to_message_id: None,
                reply_to_preview: None,
                reply_to_sender_identity_id: None,
                sent_at_ms: at.max(0) as u64,
                relayed_by: None,
                file: None,
                reactions,
            });
        }
        out
    }

    /// The reactions of one message, as a sibling history entry carries them.
    pub(crate) fn reaction_rows(&self, message_id: &str) -> Vec<(String, String, u64)> {
        let Some(conn) = &self.db else { return Vec::new() };
        let Ok(mut stmt) = conn.prepare("SELECT reactor_identity_id, emoji, reacted_at_ms FROM message_reactions WHERE message_id = ?1") else { return Vec::new() };
        stmt.query_map(params![message_id], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)?.max(0) as u64)))
            .map(|it| it.flatten().collect())
            .unwrap_or_default()
    }

    /// The finished attachments of one chat for a sibling's history request:
    /// a 1:1 chat (`fps`, the contact's devices; `identity_id`, the contact)
    /// or `group_id`. The `limit` newest created in `[lo, hi)`, each with the
    /// offer the sibling downloads it from us with. Charged to `budget` like
    /// text rows; a row that does not fit is skipped.
    pub(crate) fn sibling_file_entries(&self, fps: &[String], group_id: Option<&str>, identity_id: Option<&str>, lo: i64, hi: i64, limit: u32, budget: &mut usize) -> Vec<SiblingHistoryEntry> {
        let Some(conn) = &self.db else { return Vec::new() };
        if group_id.is_none() && fps.is_empty() { return Vec::new(); }
        let chat = match group_id {
            Some(_) => "group_id = ?1".to_string(),
            None => format!("group_id IS NULL AND peer_device_fingerprint IN ({})",
                (1..=fps.len()).map(|i| format!("?{}", i)).collect::<Vec<_>>().join(",")),
        };
        let sql = format!(
            "SELECT file_id, direction, file_name, mime_type, total_size, sha256_hex, encrypted_file_key, key_nonce,
                    preview_jpeg, duration_ms, chunk_size, caption, reply_to_message_id, reply_to_preview,
                    reply_to_sender_identity_id, sticker, sticker_origin, chunk_hashes, created_at, sender_identity_id
             FROM files WHERE status = 'complete' AND expire_secs IS NULL AND {} AND created_at >= {} AND created_at < {}
             ORDER BY created_at DESC LIMIT {}",
            chat, lo, hi, limit
        );
        let args: Vec<String> = match group_id { Some(g) => vec![g.to_string()], None => fps.to_vec() };
        type Row = (String, String, String, String, i64, String, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<u32>, Option<i64>,
                    Option<String>, Option<String>, Option<String>, Option<String>, Option<bool>, Option<String>, Option<Vec<u8>>, i64, Option<String>);
        let rows: Vec<Row> = match conn.prepare(&sql) {
            Ok(mut stmt) => stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| Ok((
                r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?,
                r.get(10)?, r.get(11)?, r.get(12)?, r.get(13)?, r.get(14)?, r.get(15)?, r.get(16)?, r.get(17)?, r.get(18)?, r.get(19)?,
            ))).map(|it| it.flatten().collect()).unwrap_or_default(),
            Err(e) => { warn!("sibling_file_entries: {}", e); return Vec::new(); }
        };
        let mut out = Vec::new();
        for (file_id, direction, file_name, mime_type, total_size, sha256_hex, enc_key, key_nonce, preview_jpeg, duration_ms, chunk_size,
             caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, chunk_hashes, created_at, sender) in rows
        {
            let Ok(file_key) = self.unwrap_file_key(&enc_key, &key_nonce) else { continue };
            let caption = caption.unwrap_or_default();
            let chunk_hashes = chunk_hashes.unwrap_or_default();
            // A row stored before chunk hash lists existed: every receiver refuses its offer ("chunk hash list missing").
            if chunk_hashes.is_empty() { continue; }
            // Over the budget, the preview is dropped first. The file still arrives, shown with a generic icon until it is downloaded.
            let bare = 512 + caption.len() + chunk_hashes.len();
            let preview_len = preview_jpeg.as_ref().map_or(0, |p| p.len());
            let preview_jpeg = if bare + preview_len <= *budget { preview_jpeg } else { None };
            let cost = bare + preview_jpeg.as_ref().map_or(0, |p| p.len());
            if cost > *budget { continue; }
            *budget -= cost;
            let reactions = self.reaction_rows(&file_id);
            out.push(SiblingHistoryEntry {
                conversation_identity_id: identity_id.map(str::to_string),
                group_id: group_id.map(str::to_string),
                direction,
                text: String::new(),
                message_id: file_id.clone(),
                sender_identity_id: sender,
                reply_to_message_id: reply_to_message_id.clone(),
                reply_to_preview: reply_to_preview.clone(),
                reply_to_sender_identity_id: reply_to_sender_identity_id.clone(),
                sent_at_ms: created_at.max(0) as u64,
                relayed_by: None,
                file: Some(Box::new(MessageContent::FileOffer {
                    group_id: group_id.map(str::to_string),
                    file_id,
                    file_name,
                    mime_type,
                    total_size: total_size.max(0) as u64,
                    file_key,
                    sha256_hex,
                    preview_jpeg,
                    duration_ms,
                    chunk_size: chunk_size.map(|c| c as u32),
                    chunk_hashes,
                    caption,
                    reply_to_message_id,
                    reply_to_preview,
                    reply_to_sender_identity_id,
                    sticker: sticker.unwrap_or(false),
                    sticker_origin,
                    expire_secs: None,
                })),
                reactions,
            });
        }
        out
    }

    /// An attachment from a sibling's history answer: stored as if its offer
    /// came now, then given the sibling's direction, chat and date. The file
    /// comes from that sibling (`download_file` takes siblings as sources).
    pub(crate) fn apply_sibling_file(&mut self, peer_fp: &str, sender: &str, group_id: Option<&str>, chat_key: Option<&str>, direction: &str, created_at: u64, offer: MessageContent) -> bool {
        let MessageContent::FileOffer {
            file_id, file_name, mime_type, total_size, file_key, sha256_hex, preview_jpeg, duration_ms, chunk_size,
            chunk_hashes, caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, ..
        } = offer else { return false };
        let ev = self.receive_file_offer(
            peer_fp, sender, group_id.map(str::to_string), &file_id, &file_name, &mime_type,
            total_size, &file_key, &sha256_hex, &preview_jpeg, duration_ms, chunk_size, &chunk_hashes,
            &caption, reply_to_message_id.as_deref(), reply_to_preview.as_deref(),
            reply_to_sender_identity_id.as_deref(), sticker, sticker_origin.as_deref(), created_at,
        );
        if ev["type"] != "file_offer" { return false; }
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "UPDATE files SET direction = ?1, peer_device_fingerprint = ?2, created_at = ?3 WHERE file_id = ?4",
                params![direction, chat_key.unwrap_or(peer_fp), created_at.min(i64::MAX as u64) as i64, file_id],
            );
        }
        true
    }

    /// Imports history rows from a sibling into the local archive. Duplicates are skipped by `message_id` (1:1 `conv_id` / group `local_id`).
    /// This is a sibling's history answer. `window` is its echo of our request. When it matches an open press to this sibling
    /// (`sibling_fetch_open`, consumed here), only that chat's rows sent inside the window are kept. They may bring back rows below the history floor,
    /// and the floor moves down to the oldest row written. Any other answer is automatic, and the floor holds. `more`: the sibling cut its page,
    /// so the older rest of the window is requested. Returns the rows as event JSON and, for a press, its chat.
    pub(crate) fn apply_sibling_reply(&mut self, peer_fp: &str, window: Option<(i64, i64)>, more: bool, mut entries: Vec<SiblingHistoryEntry>) -> (Vec<serde_json::Value>, Option<String>) {
        let press = window.and_then(|(before, after)| {
            self.sibling_fetch_open.remove(&(peer_fp.to_string(), before, after)).map(|(chat, _)| (chat, before, after))
        });
        // The echo of a press this device no longer knows (a restart clears
        // `sibling_fetch_open`): the floor keeps its rows out, so the next
        // press asks for that window again.
        let lost_press = match (window, &press) {
            (Some((before, _)), None) => entries.first()
                .and_then(|e| e.group_id.clone().or_else(|| e.conversation_identity_id.clone()))
                .map(|chat| (chat, before.max(0) as u64)),
            _ => None,
        };
        // Past the window end only attachments and reaction carriers (see
        // `build_sibling_history_response`); text rows stay in the window.
        let in_window = |e: &SiblingHistoryEntry| press.as_ref().map_or(true, |(_, before, after)| (*after..*before).contains(&(e.sent_at_ms as i64)));
        if let Some((chat, before, _)) = &press {
            entries.retain(|e| e.group_id.as_deref().or(e.conversation_identity_id.as_deref()) == Some(chat.as_str())
                && (in_window(e) || (e.sent_at_ms as i64 >= *before && (e.file.is_some() || e.text.is_empty()))));
        }
        let oldest = entries.iter().filter(|e| in_window(e)).map(|e| e.sent_at_ms as i64).min();
        // Attachment rows are not text bubbles: the chat reloads them.
        let merged: Vec<serde_json::Value> = entries.iter().filter(|e| e.file.is_none() && !e.text.is_empty()).map(|e| serde_json::json!({
            "direction": e.direction, "text": e.text, "timestamp": e.sent_at_ms,
            "sent_at_ms": e.sent_at_ms, "message_id": e.message_id,
        })).collect();
        let written = self.apply_sibling_history(peer_fp, entries, press.is_some());
        let Some((chat, _, after)) = press else {
            if let Some((chat, before)) = lost_press { self.reopen_fetch_cursor(&chat, before) }
            return (merged, None);
        };
        if let Some(o) = written {
            self.lower_history_floor(&chat, o);
        }
        // `o + 1`: the window end is exclusive, and rows sent in the same ms
        // as `o` may be the ones cut. Rows asked for twice dedup by id.
        if let (true, Some(o)) = (more, oldest) {
            if o > after {
                let sent = self.take_fetch_page(&chat) && {
                    let group = self.groups.contains_key(&chat);
                    let (cid, gid) = if group { (None, Some(chat.as_str())) } else { (Some(chat.as_str()), None) };
                    self.request_older_sibling_history(cid, gid, o + 1, after, Some(peer_fp)).is_ok()
                };
                if !sent { self.reopen_fetch_cursor(&chat, o as u64 + 1) }
            }
        }
        (merged, Some(chat))
    }

    /// One follow-up page of a press for `chat` (`HISTORY_FETCH_MAX_PAGES`).
    pub(crate) fn take_fetch_page(&mut self, chat: &str) -> bool {
        match self.history_fetch_pages.get_mut(chat) {
            Some(n) if *n > 0 => { *n -= 1; true }
            _ => false,
        }
    }

    /// `user_fetch`: the answer to the user's "Fetch older history" press,
    /// which may bring back rows below the history floor. Returns the send
    /// time of the oldest row written.
    pub(crate) fn apply_sibling_history(&mut self, peer_fp: &str, entries: Vec<SiblingHistoryEntry>, user_fetch: bool) -> Option<u64> {
        let mut oldest_written: Option<u64> = None;
        let own_id = self.my_identity_id().unwrap_or_default();
        for mut e in entries {
            if e.message_id.is_empty() { continue; }
            if !matches!(e.direction.as_str(), "sent" | "received") { continue; }
            let file = e.file.take().filter(|f| matches!(&**f, MessageContent::FileOffer { file_id, .. } if *file_id == e.message_id));
            let file_present = |core: &Self| file.is_some() && core.db.as_ref().map_or(false, |c| {
                c.query_row("SELECT 1 FROM files WHERE file_id = ?1", params![e.message_id], |_| Ok(())).is_ok()
            });
            // Dedup per chat (below): ids are the sender's choice, and a
            // global lookup let a row of another chat suppress this one.
            // `present`: the row is here now (written or already), so its
            // reactions apply.
            let (present, written) = if let Some(gid) = e.group_id.clone() {
                // A group this device left (or never had): a sibling's
                // backfill must not write its messages back.
                if !self.groups.contains_key(&gid) { continue; }
                // Cleared by the user (`clear_group_history`).
                if !user_fetch && e.sent_at_ms < self.history_floor(&gid) { continue; }
                let sender = e.sender_identity_id.clone().unwrap_or_else(|| own_id.clone());
                if file_present(self) || (file.is_none() && self.message_exists_in_chat(&e.message_id, Some(gid.as_str()), "")) {
                    // Our sibling holds the author's own copy: a relayed row here is verified too.
                    // An empty text tells nothing (no text known), so the marker stays. The entry carries no edited
                    // flag: the sibling's text is the author's, shown without the "(edited)" label.
                    if file.is_none() && e.relayed_by.is_none() && !e.text.is_empty() {
                        self.verify_group_row(&gid, &e.message_id, Some((e.text.as_str(), false)));
                    }
                    (true, false)
                } else if let Some(f) = file {
                    let w = self.apply_sibling_file(peer_fp, &sender, Some(&gid), None, &e.direction, e.sent_at_ms, *f);
                    (w, w)
                } else if e.text.is_empty() {
                    (false, false) // reactions of a row this device lacks
                } else {
                    let w = self.archive_group_message(&gid, &sender, &e.direction, e.text.as_bytes(), Some(&e.message_id),
                        e.reply_to_message_id.as_deref(), e.reply_to_preview.as_deref(), e.reply_to_sender_identity_id.as_deref(), e.sent_at_ms, e.relayed_by.as_deref()).is_ok();
                    (w, w)
                }
            } else if let Some(id) = e.conversation_identity_id.clone() {
                // Same floor as the peer's history answer: a sibling still holds
                // the chat the user cleared (a contact kept as a group member).
                if !user_fetch && e.sent_at_ms < self.history_floor(&id) { continue; }
                let Some(ck) = self.canonical_device_for_identity(&id) else { continue };
                if file_present(self) || (file.is_none() && self.message_exists_in_chat(&e.message_id, None, &ck)) {
                    (true, false)
                } else if let Some(f) = file {
                    let sender = if e.direction == "sent" { own_id.clone() } else { id.clone() };
                    let w = self.apply_sibling_file(peer_fp, &sender, None, Some(&ck), &e.direction, e.sent_at_ms, *f);
                    (w, w)
                } else if e.text.is_empty() {
                    (false, false) // reactions of a row this device lacks
                } else {
                    let status = if e.direction == "sent" { Some(MessageSendStatus::Sent.as_str()) } else { None };
                    let w = self.archive_message(&ck, &e.direction, e.text.as_bytes(), Some(&e.message_id), status,
                        e.reply_to_message_id.as_deref(), e.reply_to_preview.as_deref(), e.sent_at_ms).is_ok();
                    (w, w)
                }
            } else {
                (false, false)
            };
            if present {
                for (reactor, emoji, at) in e.reactions.iter().take(256) {
                    if emoji.len() <= 64 && reactor.len() <= 128 {
                        self.apply_reaction(&e.message_id, reactor, emoji, *at);
                    }
                }
            }
            if written {
                oldest_written = Some(oldest_written.map_or(e.sent_at_ms, |o| o.min(e.sent_at_ms)));
            }
        }
        oldest_written
    }

    /// Devices of my identity for the settings screen: THIS device plus the sibling devices.
    /// JSON: `[{"device_fingerprint","device_name","is_active","is_this_device"}]`.
    pub(crate) fn list_linked_devices(&self) -> Vec<serde_json::Value> {
        let my_id = match self.my_identity_id() { Some(id) => id, None => return Vec::new() };
        let own_fp = self.get_active_own_device_fingerprint().ok();
        let mut out = Vec::new();
        // This device.
        if let Some(fp) = &own_fp {
            if let Some(rec) = self.own_devices.get(fp) {
                out.push(serde_json::json!({
                    "device_fingerprint": fp,
                    "device_name": sanitize_display_name(&rec.device_name).unwrap_or_default(),
                    "is_active": true,
                    "is_this_device": true,
                }));
            }
        }
        // Sibling devices (same identity as my_id, but not this device).
        let mut siblings: Vec<&DeviceRecord> = self.known_remote_devices.values()
            .filter(|d| d.identity_id == my_id && own_fp.as_deref() != Some(d.device_fingerprint.as_str()))
            .filter(|d| d.is_active || self.meta_str(&format!("hidden_dev:{}", d.device_fingerprint)).is_none())
            .collect();
        siblings.sort_by(|a, b| a.device_fingerprint.cmp(&b.device_fingerprint));
        for rec in siblings {
            out.push(serde_json::json!({
                "device_fingerprint": rec.device_fingerprint,
                "device_name": sanitize_display_name(&rec.device_name).unwrap_or_default(),
                "is_active": rec.is_active,
                "is_this_device": false,
            }));
        }
        out
    }

    /// Hides a revoked sibling from `list_linked_devices`. The record stays:
    /// `answer_revoked_sibling` needs it to send the revoke back if that
    /// device ever writes again, and the revoke itself is kept in `own_revokes`.
    pub(crate) fn forget_revoked_linked_device(&mut self, fp: &str) -> Result<(), String> {
        let my_id = self.my_identity_id().ok_or("No identity")?;
        let rec = self.known_remote_devices.get(fp).ok_or("Device not found")?;
        if rec.identity_id != my_id || rec.is_active {
            return Err("Only a revoked sibling device can be removed from the list".to_string());
        }
        self.meta_put(&format!("hidden_dev:{fp}"), "1");
        Ok(())
    }

    /// Some active device of my identity other than this one is known.
    pub(crate) fn has_linked_sibling(&self) -> bool {
        let Some(my_id) = self.my_identity_id() else { return false };
        self.known_remote_devices.values().any(|d| d.identity_id == my_id && d.is_active && !self.own_devices.contains_key(&d.device_fingerprint))
    }

    /// Keeps a non-additive operation sent to my siblings (edit, delete, reaction, contact or sticker removal, group
    /// left, block, contact device revoke, read state). A sibling whose copy was never queued (left out of
    /// `sibling_active_devices` as stale) or given up after the 7-day retry limit gets it again with its next backfill
    /// (`replay_sibling_journal`). The backfill only adds rows, so these stayed diverged for good. Texts, files and
    /// stickers are not kept: the backfill and `StickersRequest` bring them. Only the newest op per target is kept.
    /// `targets`: the siblings the live copy was queued for.
    pub(crate) fn journal_sibling_op(&self, content: &MessageContent, targets: &[String]) {
        let dkey = match content {
            MessageContent::SiblingEcho { body, group_id, .. } => match body {
                SiblingEchoBody::Edit { target_message_id, .. } => format!("ed:{}", target_message_id),
                SiblingEchoBody::Delete { target_message_id } => format!("del:{}", target_message_id),
                SiblingEchoBody::Reaction { target_message_id, emoji, .. } => format!("re:{}:{}", target_message_id, emoji),
                SiblingEchoBody::GroupLeft => format!("gl:{}", group_id.as_deref().unwrap_or("")),
                // One journal row per sticker, so a later re-add (`Sticker` below) clears exactly its own row.
                SiblingEchoBody::StickerRemoved { ids } if ids.len() != 1 => {
                    for id in ids {
                        let one = MessageContent::SiblingEcho {
                            conversation_identity_id: None,
                            group_id: None,
                            body: SiblingEchoBody::StickerRemoved { ids: vec![id.clone()] },
                        };
                        self.journal_sibling_op(&one, targets);
                    }
                    return;
                }
                SiblingEchoBody::StickerRemoved { ids } => format!("sr:{}", ids[0]),
                SiblingEchoBody::ContactRemoved { identity_id, .. } => format!("cr:{}", identity_id),
                SiblingEchoBody::Blocked { identity_id, .. } => format!("bl:{}", identity_id),
                SiblingEchoBody::ContactDeviceRevoked { device_fingerprint, .. } => format!("dr:{}", device_fingerprint),
                // Added again: an older removal must not be replayed over it.
                SiblingEchoBody::Sticker { id, .. } => {
                    if let Some(conn) = &self.db {
                        let _ = conn.execute("DELETE FROM sibling_journal WHERE dkey = ?1", params![format!("sr:{}", id)]);
                    }
                    return;
                }
                _ => return,
            },
            MessageContent::ReadStateSync { conversation_identity_id, group_id, .. } =>
                format!("rs:{}", group_id.as_deref().or(conversation_identity_id.as_deref()).unwrap_or("")),
            _ => return,
        };
        if !self.has_linked_sibling() { return; }
        let Some(conn) = &self.db else { return };
        let Ok(bytes) = ciborium_bytes(content) else { return };
        let now = current_time_ms().min(i64::MAX as u64) as i64;
        let _ = conn.execute("DELETE FROM sibling_journal WHERE dkey = ?1", params![dkey]);
        if let Err(e) = conn.execute(
            "INSERT INTO sibling_journal (at, dkey, targets, content) VALUES (?1, ?2, ?3, ?4)",
            params![now, dkey, targets.join(","), bytes],
        ) {
            warn!("Sibling journal write failed: {}", e);
        }
        let _ = conn.execute(
            "DELETE FROM sibling_journal WHERE seq <= (SELECT MAX(seq) FROM sibling_journal) - ?1 OR at < ?2",
            params![SIBLING_JOURNAL_MAX_ROWS as i64, now.saturating_sub(SIBLING_JOURNAL_MAX_AGE_MS as i64)],
        );
    }

    /// Sends `fp` again the journal operations after position `since` that it never got: its live copy was not
    /// queued for it, or was queued before the retry limit. Returns the position to answer with, and whether
    /// operations are left after it. `None`: a first request; nothing is sent, only the position.
    // ponytail: an old `GroupLeft` or `ContactDeviceRevoked` replayed after the user joined the group again or
    // accepted the device again on that sibling undoes it there. Stamp them with a generation if that shows.
    pub(crate) fn replay_sibling_journal(&mut self, fp: &str, since: Option<u64>) -> (u64, bool) {
        let (top, rows) = {
            let Some(conn) = &self.db else { return (since.unwrap_or(0), false) };
            let top = conn.query_row("SELECT COALESCE(MAX(seq), 0) FROM sibling_journal", [], |r| r.get::<_, i64>(0))
                .map_or(0, |v| v.max(0) as u64);
            let Some(since) = since else { return (top, false) };
            let rows: Vec<(i64, i64, String, Vec<u8>)> = conn.prepare(
                "SELECT seq, at, targets, content FROM sibling_journal WHERE seq > ?1 ORDER BY seq LIMIT ?2",
            ).and_then(|mut st| st.query_map(params![since.min(i64::MAX as u64) as i64, SIBLING_JOURNAL_REPLAY_MAX as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?.collect::<rusqlite::Result<Vec<_>>>()).unwrap_or_default();
            (top, rows)
        };
        let since = since.unwrap_or(0);
        let cut = rows.len() >= SIBLING_JOURNAL_REPLAY_MAX;
        let given_up_before = current_time_ms().saturating_sub(TEXT_RETRY_GIVE_UP_MS).min(i64::MAX as u64) as i64;
        let mut last = since;
        for (seq, at, targets, bytes) in rows {
            let got_live = at > given_up_before && targets.split(',').any(|t| t == fp);
            if !got_live {
                match MessageContent::from_cbor(&bytes) {
                    Ok(content) => {
                        if let Err(e) = self.send_message_content(fp.to_string(), &content, None) {
                            warn!("Sibling journal replay stopped: {}", e);
                            return (last, true);
                        }
                    }
                    Err(e) => warn!("Sibling journal row {} unreadable: {}", seq, e),
                }
            }
            last = seq.max(0) as u64;
        }
        (if cut { last } else { top.max(last) }, cut)
    }

    /// The new device acked its `DeviceLinkGrant`: it adopted this identity. Only now do contacts and the other
    /// siblings learn of it, and does it get the rest of the roster. Announced when the grant was sent, a device that
    /// refused the grant (its QR screen closed first) got every contact's messages as a ghost sibling.
    pub(crate) fn finish_device_link(&mut self, fp: &str, device_add: &DeviceAdd) {
        if self.known_remote_devices.get(fp).map_or(true, |d| !d.is_active || Some(&d.identity_id) != self.my_identity_id().as_ref()) {
            return;
        }
        info!("Linked device adopted the identity: {}", crate::log_id(fp));
        self.meta_del(&format!("rsh:{}", fp));
        // Announce the new device to all contacts.
        self.broadcast_device_add_to_contacts(device_add);
        // The other roster parts, and the existing siblings learn about the new device too (3+ devices).
        self.sync_to_siblings();
    }

    /// Logout on a linked device: asks the root to revoke this device
    /// (`SiblingEchoBody::DeviceLeaving`). Ack-tracked, so an offline root gets
    /// it from the server. Returns the packet id to wait on; `None` on the root.
    pub(crate) fn announce_leaving(&mut self) -> Option<String> {
        if self.own_device_add.is_none() {
            return None;
        }
        let root = self.my_identity_id()?;
        let content = MessageContent::SiblingEcho { conversation_identity_id: None, group_id: None, body: SiblingEchoBody::DeviceLeaving };
        match self.send_message_content(root, &content, None) {
            Ok((id, _)) => Some(id),
            Err(e) => {
                error!("DeviceLeaving send failed: {}", e);
                None
            }
        }
    }

    /// Revokes a SIBLING device of my identity: builds a signed `DeviceRevoke` and broadcasts it to all contacts and the other sibling devices,
    /// and deactivates it locally.
    pub(crate) fn revoke_own_linked_device(&mut self, fp: &str) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        if fp == own_fp {
            return Err("You cannot revoke this device from here".to_string());
        }
        let my_id = self.my_identity_id().ok_or("No identity")?;
        let is_sibling = self.known_remote_devices.get(fp)
            .map(|d| d.identity_id == my_id).unwrap_or(false);
        if !is_sibling {
            return Err("This device is not a sibling device of your identity".to_string());
        }
        let revoke = self.sign_device_revoke(fp)?;
        self.remember_own_revoke(&revoke);
        let content = MessageContent::DeviceRevokeNotice(revoke);
        // The revoked device first, on the session it still has: it wipes
        // itself (`apply_device_revoke_notice`). It is not in the broadcast
        // targets below; it gets this notice here, and is marked inactive below.
        // One attempt (direct, or the server mailbox when it is offline). The
        // retry entry is dropped with the session below, and a revoked
        // device's Ack is not accepted anyway. If it is lost, the device's
        // next packet brings the revoke back (`answer_revoked_sibling`).
        let _ = self.send_message_content(fp.to_string(), &content, None);
        // Deactivate it locally.
        if let Some(rec) = self.known_remote_devices.get_mut(fp) {
            rec.is_active = false;
            let rec2 = rec.clone();
            self.persist_remote_device(&rec2);
        }
        // The send path does not look at `is_active`: a DeviceSync (contacts,
        // archive key) queued for the device while it was offline was still
        // delivered after the revoke.
        self.verified_device_adds.remove(fp);
        // Not at once: the notice queued above was still in flight, and closing
        // the connection now cancelled it ("Connection was closed before a
        // response"), so an online revoked device only learned at its next send.
        self.drop_device_sessions_keep_link(fp, false);
        // Broadcast to all contacts and the other siblings.
        let ids: Vec<String> = self.contacts.values()
            .filter(|c| c.trusted_identity_id != my_id)
            .map(|c| c.trusted_identity_id.clone())
            .collect();
        let mut targets: Vec<String> = ids.iter().flat_map(|id| self.active_devices_for_identity(id)).collect();
        targets.extend(self.sibling_active_devices());
        for t in targets {
            if let Err(e) = self.send_message_content(t, &content, None) {
                error!("DeviceRevokeNotice send failed: {}", e);
            }
        }
        // The revoked device holds the archive key. It is inactive and has
        // no session by now: the new key goes to the remaining devices only.
        self.rotate_archive_root_key();
        Ok(())
    }
}
