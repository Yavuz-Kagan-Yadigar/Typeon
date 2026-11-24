//! Group create/update/membership, founder chain and group message fan-out.

use super::*;

impl P2PCore {

    // ---------------------------------------------------------------
    // Section 5: group messaging (pairwise)
    // ---------------------------------------------------------------

    /// `group-<16 hex nonce><32 hex tag>`, the tag a hash of founder and nonce.
    /// The id names its first founder: a group we do not hold is taken only
    /// from that identity (`process_group_update`).
    pub(crate) fn group_id_for_founder(founder_identity_id: &str, nonce: &str) -> String {
        let tag = compute_fingerprint(b"typeon-group-id", founder_identity_id.as_bytes(), nonce.as_bytes(), b"");
        format!("group-{}{}", nonce, hex::encode(&tag[..16]))
    }

    pub(crate) fn create_group(&mut self, name: String) -> Result<String, String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group_id = Self::group_id_for_founder(&own_identity_id, &uuid::Uuid::new_v4().simple().to_string()[..16]);
        let group = Group::new(group_id.clone(), name, own_identity_id, current_time_ms());
        self.persist_group(&group);
        self.groups.insert(group_id.clone(), group);
        Ok(group_id)
    }

    /// Writes the group row. Called after every change to the group.
    pub(crate) fn persist_group(&self, group: &Group) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let members_json = match serde_json::to_string(&group.members) {
            Ok(j) => j,
            Err(e) => { error!("Could not serialize group members: {}", e); return; }
        };
        let founder_chain_json = serde_json::to_string(&group.founder_chain).unwrap_or_else(|_| "[]".to_string());
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO groups (group_id, founder, name, version, members_json, created_at, avatar_jpeg, founder_chain_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![group.group_id, group.founder_identity_id, group.name, group.version, members_json, group.created_at as i64, group.avatar_jpeg, founder_chain_json],
)
        {
            error!("Could not write group ({}): {}", group.group_id, e);
        }
    }

    pub(crate) fn load_groups_from_db(&mut self) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let mut stmt = match conn.prepare(
            "SELECT group_id, founder, name, version, members_json, created_at, avatar_jpeg, founder_chain_json FROM groups"
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?, row.get::<_, Option<String>>(7)?,
            ))
        });
        let mut loaded = Vec::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (group_id, founder, name, version, members_json, created_at, avatar_jpeg, founder_chain_json) = row;
                let members: Vec<group::GroupMember> = serde_json::from_str(&members_json).unwrap_or_default();
                let founder_chain: Vec<packet::FounderTransfer> = founder_chain_json
                    .and_then(|j| serde_json::from_str(&j).ok())
                    .unwrap_or_default();
                loaded.push(Group {
                    group_id,
                    name,
                    founder_identity_id: founder,
                    members,
                    created_at: created_at as u64,
                    version,
                    avatar_jpeg,
                    founder_chain,
                });
            }
        }
        for group in loaded {
            self.groups.insert(group.group_id.clone(), group);
        }
    }

    /// The signed `GroupUpdate` for `change` on top of `group`: version + 1, and the member list and vouched devices as they are AFTER the change
    /// (a new member must get the full list, a removed one must not be in it). Shared by every founder action; the caller applies and fans out.
    ///
    /// Unless `full` is set, only the vouched devices that changed since this device's last update are included (`gvd:` in app_meta). `full`
    /// includes all of them, for example for a member just added. See `GroupSyncRequest`.
    pub(crate) fn sign_group_change(&self, group: &Group, change: &GroupChange) -> Result<GroupUpdate, String> {
        self.sign_group_change_with(group, change, false)
    }

    pub(crate) fn sign_group_change_with(&self, group: &Group, change: &GroupChange, full: bool) -> Result<GroupUpdate, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let new_version = group.version.checked_add(1).ok_or("Group version exhausted")?;
        let mut projected = group.clone();
        apply_change(&mut projected, change, new_version, current_time_ms());
        let members_after = projected.member_identity_ids();
        let mut vouched = self.collect_vouched_member_devices(&group.group_id, &members_after);
        let sent_key = format!("gvd:{}", group.group_id);
        let mut sent_map: HashMap<String, String> = HashMap::new();
        if !full {
            sent_map = self.meta_str(&sent_key).and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
            let now_map: HashMap<String, String> = vouched.iter()
                .filter_map(|d| ciborium_bytes(d).ok().map(|b| (d.device_fingerprint.clone(), hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&b)))))
                .collect();
            vouched.retain(|d| now_map.get(&d.device_fingerprint) != sent_map.get(&d.device_fingerprint));
            sent_map = now_map;
        }
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let update = sign_group_update(
            &group.group_id, new_version, change, &group.name, &members_after, &vouched,
            &self.vouch_proofs(&vouched), &own_identity_id, &own_fp, own_keys, &group.founder_chain,
        )?;
        // every member device carries ~4 KB of keys (+ a proof). Past the
        // 1 MiB envelope cap the update failed `MessageTooLarge` per member,
        // after the founder had applied it: refuse it here instead. 64 KiB
        // for the packet around it (header, hybrid signatures, encryption).
        // Any change that carries the lists (a Rename or an avatar too); a
        // Remove/Delete must always go out.
        if !matches!(change, GroupChange::Remove(_) | GroupChange::Delete) {
            check_group_update_size(&update)?;
        }
        if !full {
            self.meta_put(&sent_key, &serde_json::to_string(&sent_map).unwrap_or_default());
        }
        // what this device applies now, for the same-version tie-break.
        self.set_group_tie(&group.group_id, &group_tie_hash(&update)?);
        Ok(update)
    }

    /// The current state of a group we found, signed again at its current
    /// version with every vouched device: a reply to `GroupSyncRequest`,
    /// `requeue_unresolved_group_syncs`, `resend_group_to_all`. The change
    /// re-states the avatar (or the name): a member behind gets the whole
    /// state, one at this version takes it as the same state (see
    /// `process_group_update`, tie-break).
    pub(crate) fn sign_group_resync(&self, group: &Group) -> Result<GroupUpdate, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        if group.version == 0 {
            return Err("Group not published yet".to_string());
        }
        // "No avatar" is state too: a Rename left a member that
        // missed `AvatarUpdate(None)` with the old picture.
        let change = GroupChange::AvatarUpdate(group.avatar_jpeg.clone());
        let members = group.member_identity_ids();
        let vouched = self.collect_vouched_member_devices(&group.group_id, &members);
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let update = sign_group_update(
            &group.group_id, group.version, &change, &group.name, &members, &vouched,
            &self.vouch_proofs(&vouched), &own_identity_id, &own_fp, own_keys, &group.founder_chain,
        )?;
        // Refused here, never queued: an oversize resync in
        // `pending_group_syncs` failed every `group_sync_sweep` for good.
        check_group_update_size(&update)?;
        Ok(update)
    }

    /// The founder signs the current group state again and sends it to every member device (and to its own other devices).
    pub(crate) fn resend_group_to_all(&mut self, group_id: &str) -> Result<(), String> {
        let own_identity_id = self.my_identity_id().ok_or("No identity")?;
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Only the founder can resend the group".to_string());
        }
        let update = self.sign_group_resync(&group)?;
        for member in group.other_members(&own_identity_id) {
            self.send_group_update_to_member(group_id, &member, &update);
        }
        self.send_group_update_to_siblings(&update);
        Ok(())
    }

    /// a founder's other devices get each update it signs, so they
    /// never sign the same version themselves (they apply it like a member).
    pub(crate) fn send_group_update_to_siblings(&mut self, update: &GroupUpdate) {
        let content = MessageContent::GroupUpdate(update.clone());
        for fp in self.sibling_active_devices() {
            if let Err(e) = self.send_message_content(fp, &content, None) {
                warn!("GroupUpdate could not be sent to sibling device: {}", e);
            }
        }
    }

    /// hash of the update this device applied at the group's current
    /// version (`gvh:` in app_meta).
    pub(crate) fn group_tie(&self, group_id: &str) -> Vec<u8> {
        self.meta_str(&format!("gvh:{}", group_id)).and_then(|v| hex::decode(v).ok()).unwrap_or_default()
    }

    pub(crate) fn set_group_tie(&self, group_id: &str, hash: &[u8]) {
        self.meta_put(&format!("gvh:{}", group_id), &hex::encode(hash));
    }

    /// Asks the founder for the whole group state, at most once an hour per group.
    pub(crate) fn request_group_sync(&mut self, group_id: &str) {
        const EVERY_MS: u64 = 60 * 60 * 1000;
        let key = format!("gsr:{}", group_id);
        let now = current_time_ms();
        if now.saturating_sub(self.meta_u64(&key)) < EVERY_MS {
            return;
        }
        let Some(founder) = self.groups.get(group_id).map(|g| g.founder_identity_id.clone()) else { return };
        let me = self.my_identity_id();
        let targets = if me.as_deref() == Some(founder.as_str()) { self.sibling_active_devices() } else { self.active_devices_for_identity(&founder) };
        let content = MessageContent::GroupSyncRequest { group_id: group_id.to_string() };
        let mut sent = false;
        for fp in targets {
            sent |= self.send_message_content(fp, &content, None).is_ok();
        }
        if sent {
            self.meta_put(&key, &now.to_string());
        }
    }

    /// The founder creates a group invite. The invited person receives `GroupUpdate(Add)` over an existing or in-progress 1:1 connection.
    /// Here the founder adds the member to its own `members` and sends a `GroupUpdate` pairwise to all current and new members.
    pub(crate) fn invite_to_group(&mut self, group_id: &str, new_member_identity_id: &str) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();

        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Only the founder can add members".to_string());
        }
        // Each call signs a new version and sends it to every member.
        if group.is_member(new_member_identity_id) {
            return Err("This contact is already a group member".to_string());
        }
        // Every receiver refuses an update past this (`process_group_update`).
        if group.members.len() >= MAX_GROUP_MEMBERS {
            return Err(format!("Group is too large: at most {} members", MAX_GROUP_MEMBERS));
        }
        if self.is_blocked(new_member_identity_id) {
            return Err("A blocked contact cannot be added to the group".to_string());
        }
        let new_version = group.version.checked_add(1).ok_or("Group version exhausted")?;
        let change = GroupChange::Add(new_member_identity_id.to_string());
        // The new member gets every vouched device, the others only the new ones.
        let full = self.sign_group_change_with(&group, &change, true)?;
        let update = self.sign_group_change(&group, &change)?;

        // Update local state.
        if let Some(g) = self.groups.get_mut(group_id) {
            apply_change(g, &change, new_version, current_time_ms());
        }
        if let Some(g) = self.groups.get(group_id) {
            self.persist_group(g);
        }

        // Send pairwise to all members (including the new one) over the hybrid ratchet channel (see `MessageContent::GroupUpdate` and the
        // `needs_delivery_confirmation` list). If a target device cannot be resolved yet, `send_group_update_to_member` queues the update and
        // retries it periodically.
        let targets = self.groups.get(group_id).map(|g| g.member_identity_ids()).unwrap_or_default();
        for member_identity_id in targets {
            if member_identity_id == own_identity_id {
                continue;
            }
            let u = if member_identity_id == new_member_identity_id { &full } else { &update };
            self.send_group_update_to_member(group_id, &member_identity_id, u);
        }
        // The picture rides only an AvatarUpdate, never the Add: a full state
        // after it gives the new member the picture. Only when the Add went
        // out, or the queued Add would be replaced by it.
        let add_queued = self.pending_group_syncs.contains_key(&(group_id.to_string(), new_member_identity_id.to_string()));
        if let Some(g) = self.groups.get(group_id).filter(|g| g.avatar_jpeg.is_some() && !add_queued).cloned() {
            match self.sign_group_resync(&g) {
                Ok(resync) => self.send_group_update_to_member(group_id, new_member_identity_id, &resync),
                Err(e) => warn!("Group picture for the new member not sent: {}", e),
            }
        }
        self.send_group_update_to_siblings(&update);
        Ok(())
    }

    pub(crate) fn remove_from_group(&mut self, group_id: &str, member_identity_id: &str, notify_removed: bool) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Only the founder can remove members".to_string());
        }
        // A LeaveGroupRequest from a non-member made a new version, a new
        // signature and a GroupUpdate to every member, each time.
        if !group.is_member(member_identity_id) {
            return Err("Not found: this contact is not a group member".to_string());
        }
        // The founder is us: receivers ignore a founder Remove, so this only
        // burnt a version.
        if member_identity_id == own_identity_id {
            return Err("The founder cannot remove themselves from the group".to_string());
        }
        let new_version = group.version.checked_add(1).ok_or("Group version exhausted")?;
        let change = GroupChange::Remove(member_identity_id.to_string());
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let update = self.sign_group_change(&group, &change)?;
        // The removed member gets their own signed copy so the group closes on
        // their side instead of lingering forever. It carries no member list
        // and no vouched keys: it only proves the founder removed them.
        // Only for a founder-initiated removal: a member who left or deleted
        // their account has already dropped the group, so a notice would
        // never be acknowledged and would just be retried.
        let removal_notice = if notify_removed {
            Some(sign_group_update(group_id, new_version, &change, &group.name, &[], &[], &[], &own_identity_id, &own_fp, own_keys, &group.founder_chain)?)
        } else {
            None
        };

        // Take the old member list before the removed member is reached. A removed member no longer receives GroupUpdate or group messages.
        let remaining_targets: Vec<String> = group.other_members(&own_identity_id)
            .into_iter()
            .filter(|id| id != member_identity_id)
            .collect();

        if let Some(g) = self.groups.get_mut(group_id) {
            apply_change(g, &change, new_version, current_time_ms());
        }
        if let Some(g) = self.groups.get(group_id) {
            self.persist_group(g);
        }
        // What was queued for the removed member while it was still a member
        // (group updates with name, avatar and member list; messages) must not
        // reach it later through `group_sync_sweep`. Every removal path comes
        // through here: leave, founder removal, deleted account. The removal
        // notice below is queued after this, so it stays.
        let removed_key = (group_id.to_string(), member_identity_id.to_string());
        self.pending_group_syncs.remove(&removed_key);
        if self.pending_group_messages.remove(&removed_key).is_some() {
            self.remove_persisted_pending_group_messages(group_id, member_identity_id);
        }
        // See `send_group_update_to_member`: if the target device cannot be resolved yet, it is not silently lost. `group_sync_sweep` retries it.
        for member_identity_id in remaining_targets {
            self.send_group_update_to_member(group_id, &member_identity_id, &update);
        }
        if let Some(notice) = removal_notice {
            self.send_group_update_to_member(group_id, member_identity_id, &notice);
        }
        self.send_group_update_to_siblings(&update);
        Ok(())
    }

    /// Sets or removes the group profile picture. Uses the same signed `GroupUpdate` mechanism as `invite_to_group`/`remove_from_group`
    /// (`GroupChange::AvatarUpdate`). The "only the founder may change it" rule is already enforced by `validate_group_update`'s `NotFounder`
    /// check (here on the sending side, and in `process_group_update` on the receiving side), so no separate authority check was added.
    pub(crate) fn set_group_avatar(&mut self, group_id: &str, avatar_jpeg: Option<Vec<u8>>) -> Result<(), String> {
        // See `set_own_profile_picture` for the same check and `MAX_AVATAR_BYTES`. More critical in a group: `GroupUpdate` also carries a
        // ~4 KB vouch list per member.
        if let Some(a) = &avatar_jpeg {
            if a.len() > MAX_AVATAR_BYTES {
                return Err(format!(
                    "Group photo too large ({} KB) — at most {} KB allowed",
                    a.len() / 1024, MAX_AVATAR_BYTES / 1024
                ));
            }
        }
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Only the founder can change the profile photo".to_string());
        }
        let new_version = group.version.checked_add(1).ok_or("Group version exhausted")?;
        let change = GroupChange::AvatarUpdate(avatar_jpeg);
        let update = self.sign_group_change(&group, &change)?;

        if let Some(g) = self.groups.get_mut(group_id) {
            apply_change(g, &change, new_version, current_time_ms());
        }
        if let Some(g) = self.groups.get(group_id) {
            self.persist_group(g);
        }
        // See `send_group_update_to_member`: if the target device cannot be resolved yet, it is not silently lost. `group_sync_sweep` retries it.
        let targets = group.other_members(&own_identity_id);
        for member_identity_id in targets {
            self.send_group_update_to_member(group_id, &member_identity_id, &update);
        }
        self.send_group_update_to_siblings(&update);
        Ok(())
    }

    /// Hands the founder role to another MEMBER (see `GroupChange::TransferFounder`). After the handover this device can no longer manage the group:
    /// adding/removing members and changing the name and photo move to the new founder.
    pub(crate) fn transfer_group_founder(&mut self, group_id: &str, new_founder_identity_id: &str) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Only the founder can transfer ownership".to_string());
        }
        if new_founder_identity_id == own_identity_id {
            return Err("You already have ownership".to_string());
        }
        if !group.is_member(new_founder_identity_id) {
            return Err("Invalid: new founder must be a group member".to_string());
        }
        let new_version = group.version.checked_add(1).ok_or("Group version exhausted")?;
        let change = GroupChange::TransferFounder(new_founder_identity_id.to_string());
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        // See `packet::FounderTransfer`: the transfer's own verifiable, compact proof. It is appended to the chain, so a member who missed this update
        // can learn it from the new founder's NEXT updates and repair itself. The signature is by the OLD founder (us, at this point), so it cannot
        // be forged afterwards.
        let transfer_input = packet::founder_transfer_signing_input(
            group_id, new_version, &own_identity_id, new_founder_identity_id,
        );
        let transfer_sig: Ed25519Signature = own_keys.sign_sk_ed25519.sign(&transfer_input);
        let transfer_sig_pq: MlDsaSignature<MlDsa87> = own_keys.sign_sk_mldsa.sign(&transfer_input);
        let transfer = packet::FounderTransfer {
            group_id: group_id.to_string(),
            version: new_version,
            from_identity: own_identity_id.clone(),
            to_identity: new_founder_identity_id.to_string(),
            signed_by_device: own_fp.clone(),
            signature: transfer_sig.to_bytes().to_vec(),
            signature_pq: transfer_sig_pq.encode().to_vec(),
        };
        let mut group = group;
        group.push_founder_transfer(transfer);
        let update = self.sign_group_change(&group, &change)?;

        if let Some(g) = self.groups.get_mut(group_id) {
            apply_change(g, &change, new_version, current_time_ms());
            g.founder_chain = group.founder_chain.clone();
        }
        if let Some(g) = self.groups.get(group_id) {
            self.persist_group(g);
        }
        for member_identity_id in group.other_members(&own_identity_id) {
            self.send_group_update_to_member(group_id, &member_identity_id, &update);
        }
        self.send_group_update_to_siblings(&update);
        info!("Group founder rights transferred: {} -> {}", group_id, crate::log_id(&new_founder_identity_id));
        Ok(())
    }

    /// Deletes the group for ALL members. Only the founder can call this (the same `validate_group_update` authority rule is enforced on the other
    /// side too). A signed `GroupChange::Delete` update goes to all members, then the group is removed locally.
    pub(crate) fn delete_group(&mut self, group_id: &str) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Only the founder can delete the group".to_string());
        }
        let update = self.sign_group_change(&group, &GroupChange::Delete)?;

        // Each member gets the notice through `send_group_update_to_member`, the same helper as the other group updates. If a member's device
        // cannot be resolved yet, the notice is queued in `pending_group_syncs` and retried by `group_sync_sweep`.
        for member_identity_id in group.other_members(&own_identity_id) {
            self.send_group_update_to_member(group_id, &member_identity_id, &update);
        }
        self.send_group_update_to_siblings(&update);

        // `remove_group_locally` intentionally clears ALL pending syncs for this group ("never retry forever for a group that no longer exists").
        // That is right for `remove_from_group`/`leave_group`, but WRONG here: the delete notice just queued (for a member who is offline) must not be
        // lost. So only the local group record is removed here, `pending_group_syncs` is left alone, and `group_sync_sweep` delivers the delete notice
        // once the member is reachable again.
        let (version, founder) = self.groups.remove(group_id).map_or((0, String::new()), |g| (g.version, g.founder_identity_id));
        // The rest of `remove_group_locally`. `pending_group_syncs` stays: the
        // Delete notice must still reach members whose device is not known yet.
        self.pending_group_messages.retain(|(gid, _), _| gid != group_id);
        self.remove_persisted_pending_group_messages_for_group(group_id);
        self.wb_delete_board(Some(group_id), None);
        self.delete_group_meta(group_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM groups WHERE group_id = ?1", params![group_id]);
            // see `group_removed_locally`. Cleared when the founder adds us again.
            let _ = conn.execute(
                "INSERT INTO removed_groups (group_id, version, founder) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(group_id) DO UPDATE SET version = MAX(version, excluded.version), founder = excluded.founder",
                params![group_id, version, founder],
            );
        }
        // Owner decision: a group deleted for everyone or one we
        // were removed from leaves no messages or files here. A voluntary
        // leave keeps them.
        let _ = self.clear_group_history(group_id);
        Ok(())
    }

    /// A member (not the founder: for the founder, "leaving" is undefined, it can only `delete_group` for everyone) leaves the group by its own request.
    /// The authority model (only the founder changes membership, see `validate_group_update`) is NOT broken: no new signed `GroupChange` is produced here.
    /// Instead a `LeaveGroupRequest` goes directly to the founder, who on receiving it calls its own authorised `remove_from_group` and distributes the
    /// real signed `GroupChange::Remove` to all members (see the `LeaveGroupRequest` arm of `receive_message`). This device optimistically removes its
    /// LOCAL group record as soon as the request is sent. `remove_from_group` never sends the removed member a final GroupUpdate (see its note), so this
    /// device never gets an acknowledgement from the founder. Waiting would be pointless.
    pub(crate) fn leave_group(&mut self, group_id: &str) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id == own_identity_id {
            return Err("The founder cannot leave the group; they can delete it for everyone".to_string());
        }
        // Every founder device, like the other group sends: one dead device
        // must not swallow the request.
        let founder_devices = self.active_devices_for_identity(&group.founder_identity_id);
        if founder_devices.is_empty() {
            return Err("Founder's device unknown, leave request could not be sent".to_string());
        }
        let content = MessageContent::LeaveGroupRequest { group_id: group_id.to_string() };
        // See the `needs_delivery_confirmation` note: even if the founder is not reachable right now (sleep, offline), this request is retried
        // automatically until acknowledged, and is not lost.
        // The group stays unless the request could be queued for at least one founder device. Otherwise the founder never drops us and the members
        // keep sending to a group we deleted.
        let mut last_err = None;
        let mut sent = false;
        for founder_fp in founder_devices {
            match self.send_message_content(founder_fp, &content, None) {
                Ok(_) => sent = true,
                Err(e) => {
                    error!("LeaveGroupRequest could not be sent: {}", e);
                    last_err = Some(e);
                }
            }
        }
        if !sent {
            return Err(last_err.unwrap_or_else(|| "Leave request could not be sent".to_string()));
        }
        // The siblings keep the group until the founder's update reaches
        // them otherwise. Before the removal: the echo needs the group.
        self.echo_group_to_siblings(group_id, SiblingEchoBody::GroupLeft);
        self.remove_group_locally(group_id);
        Ok(())
    }

    /// A `LeaveGroupRequest` on a founder device that is not the root: kept as `glr:<group>:<member>` and acted on by `run_deferred_leaves`
    /// unless the root's Remove arrives first. `false`: nothing to defer (not our group or not a member), the caller goes on as before.
    pub(crate) fn defer_leave_request(&mut self, group_id: &str, member_identity_id: &str) -> bool {
        let me = self.my_identity_id().unwrap_or_default();
        let ours = self.groups.get(group_id).map_or(false, |g| g.founder_identity_id == me && g.is_member(member_identity_id));
        if !ours {
            return false;
        }
        let key = format!("glr:{}:{}", group_id, member_identity_id);
        if self.meta_str(&key).is_none() {
            self.meta_put(&key, &current_time_ms().to_string());
        }
        true
    }

    /// See `defer_leave_request`. Called from `group_sync_sweep`.
    pub(crate) fn run_deferred_leaves(&mut self) {
        let rows: Vec<(String, String)> = self.db.as_ref().and_then(|c| {
            let mut stmt = c.prepare("SELECT k, v FROM app_meta WHERE k >= 'glr:' AND k < 'glr;'").ok()?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).ok()?;
            Some(rows.flatten().collect())
        }).unwrap_or_default();
        let now = current_time_ms();
        for (k, v) in rows {
            if now.saturating_sub(v.parse::<u64>().unwrap_or(0)) < LEAVE_REQUEST_DEFER_MS {
                continue;
            }
            self.meta_del(&k);
            // "glr:<group>:<member>": a group id holds no ':'.
            let Some((group_id, member)) = k["glr:".len()..].split_once(':') else { continue };
            if self.groups.get(group_id).map_or(false, |g| g.is_member(member)) {
                if let Err(e) = self.remove_from_group(group_id, member, false) {
                    warn!("Deferred leave not applied (group={}): {}", group_id, e);
                }
            }
        }
    }

    /// Removes the group record from memory and from disk (see `delete_group` and the Delete arm of `process_group_update`).
    pub(crate) fn remove_group_locally(&mut self, group_id: &str) {
        let (version, founder) = self.groups.get(group_id).map_or((0, String::new()), |g| (g.version, g.founder_identity_id.clone()));
        // One transaction: a kill between the two left the group
        // gone but not marked removed, and an old founder-signed update that
        // names us re-created it. On failure the group stays, in memory too.
        if let Some(conn) = &self.db {
            let done = conn.unchecked_transaction().and_then(|tx| {
                tx.execute("DELETE FROM groups WHERE group_id = ?1", params![group_id])?;
                // see `group_removed_locally`. Cleared when the founder adds us again.
                tx.execute(
                    "INSERT INTO removed_groups (group_id, version, founder) VALUES (?1, ?2, ?3) \
                     ON CONFLICT(group_id) DO UPDATE SET version = MAX(version, excluded.version), founder = excluded.founder",
                    params![group_id, version, founder],
                )?;
                tx.commit()
            });
            if let Err(e) = done {
                error!("Could not remove group ({}): {}", group_id, e);
                return;
            }
        }
        self.groups.remove(group_id);
        // See `pending_group_syncs`: a group that no longer exists must not be retried forever.
        self.pending_group_syncs.retain(|(gid, _), _| gid != group_id);
        // Same note as `pending_group_messages`.
        self.pending_group_messages.retain(|(gid, _), _| gid != group_id);
        self.remove_persisted_pending_group_messages_for_group(group_id);
        self.wb_delete_board(Some(group_id), None);
        self.delete_group_meta(group_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM app_meta WHERE k LIKE 'pgs:' || ?1 || ':%'", params![group_id]);
        }
    }

    /// The per-group `app_meta` rows, once the group is gone here. `hfloor:`
    /// stays: the rows the user cleared must not come back if we are added
    /// to the group again.
    pub(crate) fn delete_group_meta(&mut self, group_id: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM app_meta WHERE k IN ('gvd:' || ?1, 'gvh:' || ?1, 'gav:' || ?1, 'gsr:' || ?1, 'hfetch:' || ?1) \
                 OR k LIKE 'gsq:' || ?1 || ':%' OR k LIKE 'gf:%:' || ?1 OR k LIKE 'gfs:%:' || ?1",
                params![group_id],
            );
        }
        // Open history requests of the group (`hsr:<request id>`): no answer
        // is taken any more, and their retries went to the members for days.
        let open: Vec<String> = self.outstanding_history_requests.iter()
            .filter(|(_, (_, g, _, _))| g.as_deref() == Some(group_id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in open {
            self.forget_history_request(&id);
            self.awaiting_confirmation.remove(&id);
            self.remove_durable_retry(&id);
        }
    }

    /// See `pending_group_messages`. Tries to send a group message (Text/Edit/Delete) to one member. If the target's active device is not yet known
    /// (see `resolve_active_device_for_identity`), the content is queued in the pending list instead of being silently dropped. `group_sync_sweep`
    /// retries once a device can be resolved. This gathers the block that was repeated in the fan-out loops of `send_group_message`,
    /// `edit_group_message` and `delete_group_message` (compare `send_group_update_to_member`, the same pattern for GroupUpdate).
    /// Returns `true` if the message was really sent (or at least a send attempt was made), `false` if it was only queued.
    pub(crate) fn send_group_message_to_member(&mut self, group_id: &str, member_identity_id: &str, content: &MessageContent) -> bool {
        self.send_group_message_to_member_published(group_id, member_identity_id, content).0
    }

    /// `send_group_message_to_member`, plus whether a copy was handed to the network at once (send status "sent", not only queued).
    pub(crate) fn send_group_message_to_member_published(&mut self, group_id: &str, member_identity_id: &str, content: &MessageContent) -> (bool, bool) {
        // A member that deleted its account is neither sent to nor queued for.
        if self.deleted_identities.contains(member_identity_id) {
            return (false, false);
        }
        // Multi-device (1.7.1): send to ALL of the member's active devices separately. Otherwise a member's secondary device would never see group
        // messages. On the receiving side the group archive is keyed by `group_message_local_id`, so there is no duplication or conflict between devices.
        let devices = self.active_devices_for_identity(member_identity_id);
        if !devices.is_empty() {
            // An `Ok` from `send_message_content` does not mean the publish succeeded: temporary network errors are retried through
            // `awaiting_confirmation` (see `publish_with_ack_tracking`). A device that refuses (for example no ratchet session) is parked as a
            // durable retry below, and only when every device refuses does the result become `false`.
            let mut sent_to_any_device = false;
            let mut published = false;
            let mut refused: Vec<String> = Vec::new();
            for peer_fp in devices {
                match self.send_message_content(peer_fp.clone(), content, None) {
                    Ok((_, status)) => {
                        sent_to_any_device = true;
                        published |= status == MessageSendStatus::Sent.as_str();
                    }
                    Err(e) => {
                        error!("Group message could not be sent to a member's device ({}): {}", crate::log_id(&peer_fp), e);
                        refused.push(peer_fp);
                    }
                }
            }
            if sent_to_any_device {
                self.park_device_copies(&refused, content);
                return (true, published);
            }
            // Every device refused (no session, keys, persist failure): queue
            // like an unresolved member instead of dropping it.
            warn!(
                "Group message: {} could not be sent to any device (group={}) — queued (see group_sync_sweep)",
                crate::log_id(&member_identity_id), group_id
            );
        } else {
            // None of the member's active devices is known yet. Instead of losing it silently, queue it. `group_sync_sweep` retries once one resolves.
            warn!(
                "Group message: no active device known yet for {} (group={}) — will retry periodically (see group_sync_sweep)",
                crate::log_id(&member_identity_id), group_id
            );
        }
        let key = (group_id.to_string(), member_identity_id.to_string());
        // NOTE: `remove_oldest_persisted_pending_group_message` (a `self` method) cannot be called while `queue` (see the `entry().or_default()` below)
        // is still mutably borrowed. So the full/overflow check is done FIRST, with a separate read-only view.
        let needs_eviction = self.pending_group_messages.get(&key)
            .map(|q| q.len() >= MAX_PENDING_GROUP_MESSAGES_PER_MEMBER)
            .unwrap_or(false);
        if needs_eviction {
            // We will drop the in-memory oldest, and also its persisted copy (the oldest row for the same group and member). Otherwise more rows pile up
            // on disk than in memory, and on the next restart the message that was really dropped would be sent again.
            self.remove_oldest_persisted_pending_group_message(group_id, member_identity_id);
            let dropped = self.pending_group_messages.get_mut(&key).map(|q| q.remove(0));
            // Only this member's copy is lost; the bubble id is shared by every
            // member's copy, so it is not marked failed.
            if dropped.is_some() {
                warn!("Group queue full (group={}, member={}): oldest copy dropped", group_id, crate::log_id(&member_identity_id));
            }
        }
        let queue = self.pending_group_messages.entry(key).or_default();
        queue.push(content.clone());
        self.persist_pending_group_message(group_id, member_identity_id, content);
        // Queued in memory and on disk (`pending_group_messages`); `group_sync_sweep` sends it once the member's device resolves. Queueing is a
        // deferred delivery, not a failure, so the callers do not show an error.
        (true, false)
    }

    /// Parks the copies of a group packet that some of a member's devices refused (no session yet, ...) while other devices took it. The
    /// member-level queue never sees them. Each gets a durable row of its own (fresh packet id), which
    /// `load_pending_durable_retries_from_db` sends again (at start, or when the device is seen again).
    pub(crate) fn park_device_copies(&mut self, refused: &[String], content: &MessageContent) {
        let now = current_time_ms();
        for fp in refused {
            self.persist_durable_retry(&uuid::Uuid::new_v4().to_string(), fp, content, now, None);
        }
        // The table is otherwise read only at start or when a stale device
        // comes back: a copy for a device seen every day waited for a restart.
        if !refused.is_empty() && self.durable_reload_at == 0 {
            self.durable_reload_at = now + DURABLE_PARK_RELOAD_MS;
        }
    }

    /// Tries to send a `GroupUpdate` to one member. If the target's active device is not yet known (see `pending_group_syncs`), the update is added
    /// to the pending list for this (group_id, identity_id) pair instead of being dropped. `group_sync_sweep` retries periodically until the device
    /// can be resolved. This gathers the block that was repeated in the fan-out loops of `invite_to_group`, `remove_from_group`, `set_group_avatar` and `delete_group`.
    pub(crate) fn send_group_update_to_member(&mut self, group_id: &str, member_identity_id: &str, update: &GroupUpdate) {
        // Multi-device: send to ALL of the member's active devices. Otherwise a member's secondary device would keep a stale group membership, name and avatar.
        let devices = self.active_devices_for_identity(member_identity_id);
        let mut sent = false;
        let mut refused: Vec<String> = Vec::new();
        let content = MessageContent::GroupUpdate(update.clone());
        for peer_fp in devices {
            match self.send_message_content(peer_fp.clone(), &content, None) {
                Ok(_) => sent = true,
                Err(e) => {
                    error!("GroupUpdate could not be sent to a member's device: {}", e);
                    refused.push(peer_fp);
                }
            }
        }
        // A Delete or a removal notice cannot be signed again after a
        // restart (`requeue_unresolved_group_syncs` rebuilds only current
        // members of groups we hold): kept on disk until delivered.
        let lasting = matches!(&update.change, GroupChange::Delete)
            || matches!(&update.change, GroupChange::Remove(id) if id == member_identity_id);
        let meta_key = format!("pgs:{}:{}", group_id, member_identity_id);
        if sent {
            self.park_device_copies(&refused, &content);
            self.pending_group_syncs.remove(&(group_id.to_string(), member_identity_id.to_string()));
            if lasting {
                self.meta_del(&meta_key);
            }
        } else {
            let key = (group_id.to_string(), member_identity_id.to_string());
            if lasting {
                // Written once ("<first queued ms>:<sealed hex>"), not on every
                // sweep; given up like any packet after TEXT_RETRY_GIVE_UP_MS.
                let fresh = self.pending_group_syncs.get(&key).map_or(true, |p| p.new_version != update.new_version);
                let since: Option<u64> = self.meta_str(&meta_key)
                    .and_then(|v| v.split_once(':').and_then(|(t, _)| t.parse().ok()));
                match since {
                    Some(t) if !fresh => {
                        if current_time_ms().saturating_sub(t) > TEXT_RETRY_GIVE_UP_MS {
                            warn!("GroupUpdate notice for {} given up (group={})", crate::log_id(&member_identity_id), group_id);
                            self.meta_del(&meta_key);
                            self.pending_group_syncs.remove(&key);
                            return;
                        }
                    }
                    _ => {
                        if let Some(sealed) = ciborium_bytes(update).ok().and_then(|b| self.seal_local_blob(&b)) {
                            self.meta_put(&meta_key, &format!("{}:{}", current_time_ms(), hex::encode(sealed)));
                        }
                    }
                }
            }
            if self.pending_group_syncs.insert(key, update.clone()).is_none() {
                error!(
                    "GroupUpdate: no active device known yet for {} (group={}) — will retry periodically (see group_sync_sweep)",
                    crate::log_id(&member_identity_id), group_id
                );
            }
        }
    }

    /// See `pending_group_syncs` and `send_group_update_to_member`: the same periodic pattern as `reconnect_sweep`. For each pending (group_id, identity_id),
    /// if the target device can now be resolved, the stored `GroupUpdate` is sent.
    pub(crate) fn group_sync_sweep(&mut self) {
        let now = current_time_ms();
        if now.saturating_sub(self.last_group_sync_sweep_at) < GROUP_SYNC_SWEEP_INTERVAL_MS {
            return;
        }
        self.last_group_sync_sweep_at = now;
        self.run_deferred_leaves();
        // ponytail: one reload per park. A copy whose resend fails again waits for the next park, a stale device's return, or a restart.
        if self.durable_reload_at != 0 && now >= self.durable_reload_at {
            self.durable_reload_at = 0;
            self.load_pending_durable_retries_from_db();
        }
        if !self.pending_group_syncs.is_empty() {
            // An identity that deleted its account never takes it: every
            // publish to it is refused, so the entry stayed for good.
            let deleted = &self.deleted_identities;
            self.pending_group_syncs.retain(|(_, id), _| !deleted.contains(id));
            let pending: Vec<(String, String, GroupUpdate)> = self.pending_group_syncs.iter()
                .map(|((gid, id), update)| (gid.clone(), id.clone(), update.clone()))
                .collect();
            for (group_id, member_identity_id, update) in pending {
                // Multi-device: the helper fans out to ALL of the member's active devices, and removes the entry from `pending_group_syncs` once they
                // resolve. If it is still unresolved (no active device), the entry is kept.
                self.send_group_update_to_member(&group_id, &member_identity_id, &update);
            }
        }
        // See `pending_group_messages`: the same sweep, but a separate queue. ALL messages accumulated for one member must be sent IN ORDER, unlike
        // GroupUpdate, where only the latest state matters.
        if !self.pending_group_messages.is_empty() {
            let keys: Vec<(String, String)> = self.pending_group_messages.keys().cloned().collect();
            for (group_id, member_identity_id) in keys {
                // Before draining the queue, verify the member is STILL in the group. A member may have been removed or may have left while messages waited
                // for its (then unresolved) device. Sending the stale messages once that device resolves would leak group activity to someone who is no
                // longer a member. If it is no longer a member, the queue (in memory and the persisted copy) is dropped silently.
                let still_member = self.groups.get(&group_id)
                    .map(|g| g.is_member(&member_identity_id))
                    .unwrap_or(false);
                if !still_member {
                    let dropped = self.pending_group_messages.remove(&(group_id.clone(), member_identity_id.clone()))
                        .map(|q| q.len()).unwrap_or(0);
                    self.remove_persisted_pending_group_messages(&group_id, &member_identity_id);
                    info!("group_sync_sweep: {} is no longer a group member (group={}) — dropped {} pending messages",
                        crate::log_id(&member_identity_id), group_id, dropped);
                    continue;
                }
                // Multi-device: if all of the member's active devices can be resolved, send to all of them.
                let devices = self.active_devices_for_identity(&member_identity_id);
                if devices.is_empty() { continue; }
                let queued = match self.pending_group_messages.remove(&(group_id.clone(), member_identity_id.clone())) {
                    Some(q) => q,
                    None => continue,
                };
                info!(
                    "group_sync_sweep: {} is resolvable now, sending {} pending group messages (group={})",
                    crate::log_id(&member_identity_id), queued.len(), group_id
                );
                // Send first, drop the disk rows after: a crash in between
                // re-sends (the receiver dedups), it never loses. An entry no
                // device took, and everything after it (order), stays queued.
                // A sent entry has its own durable retry (`publish_with_ack_tracking`).
                let mut unsent: Vec<MessageContent> = Vec::new();
                let total = queued.len();
                for content in queued {
                    if unsent.is_empty() {
                        let mut ok = false;
                        let mut refused: Vec<String> = Vec::new();
                        for peer_fp in &devices {
                            match self.send_message_content(peer_fp.clone(), &content, None) {
                                Ok(_) => ok = true,
                                Err(e) => {
                                    error!("group_sync_sweep: group message still could not be sent: {}", e);
                                    refused.push(peer_fp.clone());
                                }
                            }
                        }
                        if ok {
                            // Same as `send_group_message_to_member`: the
                            // devices that refused get a durable copy.
                            self.park_device_copies(&refused, &content);
                            continue;
                        }
                    }
                    unsent.push(content);
                }
                // Nothing went out: the stored rows are still right. Rewriting
                // them every sweep wrote ~2 MB per stuck member each 20 s
                if unsent.len() == total {
                    self.pending_group_messages.insert((group_id.clone(), member_identity_id.clone()), unsent);
                    continue;
                }
                self.remove_persisted_pending_group_messages(&group_id, &member_identity_id);
                if !unsent.is_empty() {
                    for content in &unsent {
                        self.persist_pending_group_message(&group_id, &member_identity_id, content);
                    }
                    self.pending_group_messages.insert((group_id.clone(), member_identity_id.clone()), unsent);
                }
            }
        }
    }

    /// Verifies a single founder handover attestation. See `packet::FounderTransfer`.
    ///
    /// The signing device must be ACTIVE now (a stolen or revoked device must not be able to hand the group over). Known cost: a member that missed a
    /// transfer whose signing device was revoked afterwards cannot verify it any more and must be re-invited.
    pub(crate) fn verify_founder_transfer(&self, group_id: &str, current_founder: &str, t: &packet::FounderTransfer) -> bool {
        if t.group_id != group_id || t.from_identity != current_founder {
            return false;
        }
        if t.to_identity == t.from_identity || t.to_identity.is_empty() {
            return false;
        }
        let Some(signer) = self.known_remote_devices.get(&t.signed_by_device)
            .or_else(|| self.own_devices.get(&t.signed_by_device))
        else {
            return false;
        };
        // `is_active`: a revoked (e.g. stolen) device of the founder must not be
        // able to hand the group over.
        if signer.identity_id != t.from_identity || !signer.is_active {
            return false;
        }
        let input = packet::founder_transfer_signing_input(
            group_id, t.version, &t.from_identity, &t.to_identity,
        );
        verify_hybrid_signature(&input, &t.signature, &t.signature_pq, signer).is_ok()
    }

    /// Advances the local founder using the transfer chain carried by an incoming update. See `packet::FounderTransfer` (deadlock scenario).
    ///
    /// Walks the chain in version order. At each step it looks for an entry that hands over from the CURRENT local founder and whose signature verifies.
    /// When it finds none, it stops. It cannot loop: each step must CHANGE the founder, and the number of rounds is bounded by the chain length.
    ///
    /// Returns the new founder's identity id if a repair was made.
    ///
    /// `local_chain`: the transfers this device already holds. A transfer is taken only if it is NEWER than the one that made the current founder
    /// founder. Without that floor an old transfer could be replayed: F hands over to A (v5), A hands back (v9), and anyone holding the v5 blob would
    /// make A founder again.
    pub(crate) fn heal_founder_chain(&self, group_id: &str, current_founder: &str, local_chain: &[packet::FounderTransfer], chain: &[packet::FounderTransfer], new_version: u32, min_floor: u32) -> Vec<packet::FounderTransfer> {
        let mut walked = Vec::new();
        let mut sorted: Vec<&packet::FounderTransfer> = chain.iter().collect();
        sorted.sort_by_key(|t| t.version);
        let mut founder = current_founder.to_string();
        let mut floor = founder_transfer_floor(local_chain, current_founder).max(min_floor);
        // `< new_version`: the transfer of this very update is applied by
        // `apply_change`. Walked here, it moved the founder before
        // `validate_group_update` ran and the founder's own handover was
        // rejected as NotFounder by every receiver.
        for _ in 0..sorted.len() {
            let Some(next) = sorted.iter().find(|t| t.version > floor && t.version < new_version && self.verify_founder_transfer(group_id, &founder, t)) else {
                break;
            };
            floor = next.version;
            info!(
                "Missed founder transfer repaired (group={}, v{}): {} -> {}",
                group_id, next.version, crate::log_id(&next.from_identity), crate::log_id(&next.to_identity)
            );
            founder = next.to_identity.clone();
            walked.push((*next).clone());
        }
        walked
    }

    /// Whether a received group text @mentions me: my own identity id in its list after dropping non-members (the text itself is not trusted).
    pub(crate) fn group_mentions_me(&self, group_id: &str, mentions: Vec<String>) -> bool {
        let (Some(me), Some(group)) = (self.identity.as_ref(), self.groups.get(group_id)) else { return false };
        filter_mentions(group, None, mentions).iter().any(|id| *id == me.identity_id)
    }

    /// Whether this sender is allowed to write to this group.
    ///
    /// Group messages (`Text`, `FileOffer`, `Reaction`) carry the `group_id` as the sender states it. So for a known group the sender must be a
    /// member, otherwise two things happen: a member removed from the group could keep writing, and any contact that knew a `group_id` (a removed
    /// member, or a leaked one) could inject messages or files into it.
    ///
    /// The rule applies ONLY when we know the group, on purpose. A group we have never seen may be an invite or `GroupUpdate` that has not reached
    /// us yet, and a late-joining member is exactly this case (see `sync_members`). Rejecting there would drop legitimate first messages.
    ///
    /// The rejected packet is NOT acked. A legitimate sender who learned of its membership before we did will retry, and be accepted once our
    /// `GroupUpdate` arrives. The race heals itself.
    pub(crate) fn sender_may_post_to_group(&self, group_id: &str, sender_identity_id: &str) -> bool {
        match self.groups.get(group_id) {
            Some(group) => group.is_member(sender_identity_id),
            // Unknown: the GroupUpdate may still be on its way. Not so for a group we left, were removed from, or deleted.
            // Only an id that `create_group` can make is accepted.
            None => is_group_id(group_id) && !self.group_removed_locally(group_id) && self.unknown_group_has_room(group_id),
        }
    }

    /// Rows of a group we do not hold are never shown or cleaned, and any contact can mint ids. An id that already has rows is taken. A new one is
    /// only accepted while fewer than 16 such groups exist.
    /// ponytail: one COUNT over messages per message of an unknown group. Keep a set in memory if that path gets hot.
    pub(crate) fn unknown_group_has_room(&self, group_id: &str) -> bool {
        let Some(conn) = &self.db else { return false };
        // Rows of a group that never arrived go after a day.
        let _ = conn.execute(
            "DELETE FROM messages WHERE group_id IS NOT NULL AND group_id != '' AND timestamp < ?1
               AND group_id NOT IN (SELECT group_id FROM groups)",
            params![current_time_ms().saturating_sub(UNKNOWN_GROUP_ROWS_MAX_AGE_MS) as i64],
        );
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE group_id = ?1)
                 OR (SELECT COUNT(DISTINCT group_id) FROM messages
                     WHERE group_id IS NOT NULL AND group_id != '' AND group_id NOT IN (SELECT group_id FROM groups)) < 16",
            params![group_id], |r| r.get::<_, bool>(0),
        ).unwrap_or(false)
    }

    /// Rows taken for a group before it was held here (`sender_may_post_to_group` lets any contact post to an unknown id): only its members' stay.
    pub(crate) fn drop_non_member_group_rows(&mut self, group_id: &str) {
        let Some(members) = self.groups.get(group_id).map(|g| g.member_identity_ids()) else { return };
        let Some(conn) = &self.db else { return };
        let rows: Vec<(i64, Option<String>)> = conn
            .prepare("SELECT id, sender_identity_id FROM messages WHERE group_id = ?1 AND direction = 'received'")
            .and_then(|mut st| st.query_map(params![group_id], |r| Ok((r.get(0)?, r.get(1)?))).map(|it| it.flatten().collect()))
            .unwrap_or_default();
        for (id, sender) in rows {
            if !sender.as_ref().map_or(false, |s| members.contains(s)) {
                let _ = conn.execute("DELETE FROM messages WHERE id = ?1", params![id]);
            }
        }
    }

    pub(crate) fn process_group_update(&mut self, update: &GroupUpdate) -> Result<(), String> {
        // `create_group` makes `group-<16 hex>`. A founder-chosen id could
        // otherwise be a contact's identity id, and the two share key spaces
        // (archive conversation key, whiteboard board).
        if !is_group_id(&update.group_id) {
            return Err("GroupUpdate: invalid group id".to_string());
        }
        let signer = self.known_remote_devices.get(&update.signed_by_device).cloned()
            .ok_or("Unknown signer device")?;
        let to_verify = group_update_signing_input(
            &update.group_id, update.new_version, &update.change, &update.group_name,
            &update.members, &update.member_devices, &update.signed_by, &update.signed_by_device,
        )?;
        // Now the same hybrid (Ed25519 + ML-DSA) model as MessagePacket/HandshakeInit. See `sign_group_update` and the packet.rs
        // `GroupUpdate.signature_pq` note (security fix).
        verify_hybrid_signature(&to_verify, &update.signature, &update.signature_pq, &signer)
            .map_err(|_| "GroupUpdate signature verification failed".to_string())?;
        // Stored, and returned by every `list_groups`.
        if update.group_name.len() > 256 || matches!(&update.change, GroupChange::Rename(n) if n.len() > 256) {
            return Err("GroupUpdate: group name too long".to_string());
        }

        // Check that `signed_by_device` is an Active device of the founder.
        let signer_is_active = signer.identity_id == update.signed_by && signer.is_active;

        // Members are stored, synced and fanned out to; ids are compared
        // pairwise. Nothing bounded either: one update from any contact could
        // name 250 000 members of a new group.
        if update.members.len() > MAX_GROUP_MEMBERS
            || update.member_devices.len() > MAX_GROUP_MEMBERS * identity::MAX_ACTIVE_DEVICES
            || update.members.iter().any(|m| !is_fingerprint_hex(m))
            || matches!(&update.change, GroupChange::Add(id) | GroupChange::Remove(id) | GroupChange::TransferFounder(id) if !is_fingerprint_hex(id))
        {
            return Err("GroupUpdate: member list invalid or too large".to_string());
        }

        let group_exists = self.groups.contains_key(&update.group_id);
        let group_snapshot = self.groups.get(&update.group_id).cloned();
        // A group we left or were removed from: (version, founder) at that time.
        let removed: Option<(u32, String)> = if group_exists { None } else {
            self.db.as_ref().and_then(|conn| {
                conn.query_row("SELECT version, founder FROM removed_groups WHERE group_id = ?1", params![update.group_id], |r| Ok((r.get(0)?, r.get(1)?))).ok()
            })
        };

        // A group seen for the first time is created with the name the `GroupUpdate` carries (see packet.rs).
        // A group we left comes back only under the founder it had, or one the carried chain leads to from there. Any contact that knew the id could
        // otherwise re-create it with itself as founder.
        // A group new to us: the founder its id names (`group_id_for_founder`). That is the signer, or the first founder of the carried chain, from which
        // the walk below must then reach the signer.
        let default_founder = match removed.as_ref().map(|(_, f)| f.clone()).filter(|f| !f.is_empty()) {
            Some(f) => f,
            None if group_exists => update.signed_by.clone(),
            None => {
                let nonce = update.group_id.get(6..22).unwrap_or_default();
                std::iter::once(&update.signed_by)
                    .chain(update.founder_chain.iter().map(|t| &t.from_identity))
                    .find(|f| Self::group_id_for_founder(f.as_str(), nonce) == update.group_id)
                    .cloned()
                    .ok_or("GroupUpdate: group id is not bound to its founder")?
            }
        };
        let default_group = || Group::new(update.group_id.clone(), update.group_name.clone(), default_founder.clone(), current_time_ms());
        let mut group_ref = group_snapshot.unwrap_or_else(default_group);

        // Founder handover repair: see `heal_founder_chain` and `packet::FounderTransfer`. It runs BEFORE validation, because the repair exists precisely
        // to prevent a `NotFounder` rejection. Each entry in the chain carries its own signature, so this does not loosen authority: a forged chain would
        // fail validation.
        // For a group we left, the stored founder already holds every transfer up to the version we left at. An older carried transfer is a replay.
        let min_floor = removed.as_ref().map_or(0, |(v, _)| *v);
        let walked = self.heal_founder_chain(
            &update.group_id, &group_ref.founder_identity_id, &group_ref.founder_chain, &update.founder_chain, update.new_version, min_floor,
        );
        if let Some(last) = walked.last() {
            // Only on the working copy. The stored group takes the new
            // founder further down, once the update itself has passed
            // `validate_group_update`: it used to be persisted here, so a
            // rejected update still changed the founder.
            group_ref.founder_identity_id = last.to_identity.clone();
        }

        // two founder devices can sign the same version. At the version
        // we hold, an update is taken again if it is a Delete, re-states the
        // same members and name (a resend, a full copy), or its tie hash is
        // larger than that of the update we applied: every member ends on the
        // same one. The losing founder device takes it too (it gets its
        // siblings' updates), so its next change is max(seen) + 1.
        let tie = group_tie_hash(update)?;
        let old_tie = self.group_tie(&update.group_id);
        let same_version = group_exists && update.new_version == group_ref.version && update.new_version > 0;
        let same_state = update.group_name == group_ref.name && {
            let mut a = update.members.clone();
            let mut b = group_ref.member_identity_ids();
            a.sort();
            b.sort();
            a == b
        };
        // A founder transfer always wins its version: decided by the tie hash,
        // the members that applied the transfer first refused the other change
        // (NotFounder) and the rest kept the old founder.
        let transfer_held = group_ref.founder_chain.iter().any(|t| t.version == update.new_version);
        let transfer_wins = same_version && !transfer_held && matches!(update.change, GroupChange::TransferFounder(_));
        let retake = same_version
            && (matches!(update.change, GroupChange::Delete)
                || transfer_wins
                || (!transfer_held && same_state && !matches!(update.change, GroupChange::AvatarUpdate(_) | GroupChange::TransferFounder(_)))
                || (!transfer_held && tie > old_tie));
        let mut check = group_ref.clone();
        if retake {
            check.version -= 1;
        }
        // The version jump limit only applies against a version we hold. For a group we do not hold, the check starts from the incoming version.
        // A group we left keeps its own guard below (`removed`).
        if !group_exists {
            check.version = update.new_version.saturating_sub(1);
        }
        let gap = group_exists && update.new_version > group_ref.version.saturating_add(1);
        if let Err(e) = validate_group_update(&check, &update.signed_by, signer_is_active, update.new_version) {
            // `StaleOrOutOfOrderVersion` is not an attack or corruption. The recipient has ALREADY applied this version, or a newer one. For example, while
            // this GroupUpdate was refreshed and retried because it could not be delivered for a long time, ANOTHER group change may already have arrived by
            // the normal path and moved the version forward. If we carried this up as an Err, the caller would send NO Ack (see the caller), and the sender
            // would keep refreshing and resending this stale packet forever, because it is never acknowledged. Nothing is left for the recipient to do, so
            // it counts as Ok(()). The caller acks every other error too, except "unknown signer device": the same update can never pass later. A missed
            // founder handover is healed by the carried `founder_chain`.
            if matches!(e, GroupUpdateError::StaleOrOutOfOrderVersion) {
                // An older update (late, or a full copy) still vouches for devices: founder-signed, and only of current members.
                if group_exists {
                    self.adopt_group_update_devices(update, &group_ref.member_identity_ids());
                }
                // An AvatarUpdate that arrives after a newer update: members
                // and name ride every update, the avatar does not, so it was
                // lost. Taken if it is newer than the last avatar change.
                // (Founder and signer were checked before the version.)
                if let GroupChange::AvatarUpdate(avatar) = &update.change {
                    if group_exists
                        && update.new_version > self.group_avatar_version(&update.group_id)
                        && avatar.as_ref().map_or(true, |a| a.len() <= MAX_AVATAR_BYTES)
                    {
                        if let Some(g) = self.groups.get_mut(&update.group_id) {
                            g.avatar_jpeg = avatar.clone();
                        }
                        if let Some(g) = self.groups.get(&update.group_id) {
                            self.persist_group(g);
                        }
                        self.set_group_avatar_version(&update.group_id, update.new_version);
                    }
                }
                // A late Add of a current member: it was removed and added
                // again while we missed the removal; its join time restarts
                // or it was handed the history of its absence.
                if let GroupChange::Add(id) = &update.change {
                    let now = current_time_ms();
                    let mut changed = false;
                    if let Some(g) = self.groups.get_mut(&update.group_id) {
                        if let Some(m) = g.members.iter_mut().find(|m| &m.identity_id == id) {
                            m.added_at = m.added_at.max(now);
                            changed = true;
                        }
                    }
                    if changed {
                        if let Some(g) = self.groups.get(&update.group_id) {
                            self.persist_group(g);
                        }
                    }
                }
                info!("GroupUpdate already applied/stale (group={}, incoming version={}, local version={}) — harmless, acknowledging", update.group_id, update.new_version, group_ref.version);
                return Ok(());
            }
            return Err(format!("{:?}", e));
        }

        // Gap detection: if one or more intermediate updates were missed (e.g. Add/Remove), the local member list may lag behind the latest. We no longer
        // deadlock (see the `StaleOrOutOfOrderVersion` note in group.rs), but we make this visible.
        if gap {
            error!(
                "GroupUpdate gap (group={}): local version {} -> incoming {} ({} updates missed; member list may be incomplete)",
                update.group_id, group_ref.version, update.new_version,
                update.new_version - group_ref.version - 1
            );
        }

        // The founder deleted the group for ALL members: remove the local record and leave (the field update path below is not applied). Authority was
        // already checked above with `validate_group_update` (founder only).
        // A Delete for a group not held here: there is no row for an id never held (any contact could add rows for ids bound to itself). For a group we
        // left, only its version moves, and its founder stays.
        if matches!(update.change, GroupChange::Delete) && !group_exists {
            if removed.is_some() {
                if let Some(conn) = &self.db {
                    let _ = conn.execute(
                        "UPDATE removed_groups SET version = MAX(version, ?2) WHERE group_id = ?1",
                        params![update.group_id, update.new_version],
                    );
                }
            }
            return Ok(());
        }
        if matches!(update.change, GroupChange::Delete) {
            info!("Group deleted by founder: {}", update.group_id);
            // The version of the Delete, not the local one: an update between
            // the two that we missed would bring the group back.
            if let Some(g) = self.groups.get_mut(&update.group_id) {
                g.version = update.new_version;
            }
            self.remove_group_locally(&update.group_id);
            let _ = self.clear_group_history(&update.group_id);  // Deleting a group: see `delete_group`.
            return Ok(());
        }

        if !group_exists {
            // An unknown group is created here only when this update makes US a member. Otherwise any contact could create a group on our device
            // with an arbitrary name and post into it. For a `members` list that is empty, the only basis is `Add(us)`.
            //
            // The caller acks this Err. A group we are really in but lost locally is not refused here: every update carries `members`, which names us.
            let me = self.identity.as_ref().map(|i| i.identity_id.clone()).unwrap_or_default();
            let adds_us = matches!(&update.change, GroupChange::Add(id) if *id == me);
            let makes_us_a_member = update.members.iter().any(|m| *m == me) || adds_us;
            // A removal notice for a group we no longer have (already left or
            // deleted it): nothing to do, acknowledge so it is not retried.
            if matches!(&update.change, GroupChange::Remove(id) if *id == me) && !me.is_empty() {
                return Ok(());
            }
            if !me.is_empty() && !makes_us_a_member {
                warn!(
                    "GroupUpdate REJECTED: unknown group and does not add us as a member (group={}, signer={})",
                    update.group_id, crate::log_id(&update.signed_by)
                );
                return Err("Unknown group that does not name us as a member".to_string());
            }
            // Version monotonicity outlives the local group: every member
            // holds old founder-signed updates that name us, and any of them
            // would otherwise re-create a group we left, with its old members.
            // And only an explicit Add of us: an update the founder signed
            // before it handled our leave still lists us and has a higher
            // version.
            if removed.as_ref().map_or(false, |(v, _)| update.new_version <= *v || !adds_us) {
                warn!("GroupUpdate ignored: does not restore a group we left (group={}, version={})", update.group_id, update.new_version);
                return Ok(());
            }
            // The `removed_groups` row goes once the group is persisted (below).
            self.groups.insert(update.group_id.clone(), Group::new(update.group_id.clone(), update.group_name.clone(), group_ref.founder_identity_id.clone(), current_time_ms()));
        }
        // See `MAX_AVATAR_BYTES`. The incoming direction had no limit. Founder authority is not a size authority: an oversized avatar is DROPPED, but
        // the rest of the update (membership, name, version) is processed normally. Otherwise one large photo would lock the group.
        let change = match &update.change {
            GroupChange::AvatarUpdate(Some(a)) if a.len() > MAX_AVATAR_BYTES => {
                warn!(
                    "Group avatar too large ({} bytes), ignored (group={})",
                    a.len(), update.group_id
                );
                GroupChange::AvatarUpdate(None)
            }
            other => other.clone(),
        };
        if let Some(g) = self.groups.get_mut(&update.group_id) {
            // A healed founder (see above); the same value when nothing healed.
            g.founder_identity_id = group_ref.founder_identity_id.clone();
            // Members first: `TransferFounder` only takes a member, and with a
            // stale local list the new founder arrives in this same update.
            if !update.members.is_empty() {
                g.sync_members(&update.members, current_time_ms());
            }
            apply_change(g, &change, update.new_version, current_time_ms());
            // Keep the name in sync on every update (self-healing), not only on an explicit Rename change.
            g.name = update.group_name.clone();
            // Sync to the FULL member list from the founder (see `GroupUpdate.members`). Without this, a member added later never learned about members
            // added BEFORE it (it thought the group was [founder, me]). For compatibility with an older sender that sends no members list, the list is not
            // touched when it is empty, and the old behaviour stays in that case. (Applied above, before `apply_change`.)
        }
        if matches!(change, GroupChange::AvatarUpdate(_)) {
            self.set_group_avatar_version(&update.group_id, update.new_version);
        }
        // Adopt the chain on every update (not only during a repair). If authority is handed to us, our NEXT updates must be signed with this chain, or
        // the members who missed the handover would reject everything from us. Unverifiable entries are not taken.
        // The chain is outside the update signature. Only what the walk above verified from our founder onward is kept, plus this update's own
        // transfer. Unverified entries would let a member fill the chain with transfers of its own near u32::MAX, and no real transfer could
        // heal us again.
        let own_transfer = update.founder_chain.iter().find(|t| {
            matches!(&update.change, GroupChange::TransferFounder(to) if *to == t.to_identity)
                && t.version == update.new_version
                && self.verify_founder_transfer(&update.group_id, &update.signed_by, t)
        }).cloned();
        if let Some(g) = self.groups.get_mut(&update.group_id) {
            for t in walked.into_iter().chain(own_transfer) {
                g.push_founder_transfer(t);
            }
        }
        // Adopt the device keys the founder vouched for on member identities. This lets us set up ratchets and message members we have never paired
        // with (see `adopt_vouched_member_devices`; the security rules are there).
        self.adopt_group_update_devices(update, &update.members);
        if !same_version || tie > old_tie || transfer_wins {
            self.set_group_tie(&update.group_id, &tie);
        }
        // The founder removed us (see `remove_from_group`'s removal notice):
        // close the group here, exactly like a founder delete.
        let me = self.my_identity_id().unwrap_or_default();
        if matches!(&update.change, GroupChange::Remove(id) if *id == me) && !me.is_empty() {
            info!("Founder removed us from group: {}", update.group_id);
            self.remove_group_locally(&update.group_id);
            let _ = self.clear_group_history(&update.group_id);  // Deleting a group: see `delete_group`.
            return Ok(());
        }
        if let Some(g) = self.groups.get(&update.group_id) {
            self.persist_group(g);
        }
        if !group_exists {
            self.drop_non_member_group_rows(&update.group_id);
        }
        // The founder added us (again): a sibling's sync may carry the group
        // from now on. Only with the group row on disk: if persisting failed,
        // the next start would have neither and a stale add brought it back.
        if removed.is_some() {
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "DELETE FROM removed_groups WHERE group_id = ?1 AND EXISTS (SELECT 1 FROM groups WHERE group_id = ?1)",
                    params![update.group_id],
                );
            }
        }
        // Updates carry only new devices. If one was missed (a gap), or we hold no device of a member, ask the founder for the whole state.
        let missing = self.groups.get(&update.group_id).map_or(false, |g| {
            g.other_members(&me).iter().any(|m| self.active_devices_for_identity(m).is_empty() && !self.deleted_identities.contains(m))
        });
        if gap || missing {
            self.request_group_sync(&update.group_id);
        }
        Ok(())
    }

    /// The vouched member devices of a founder-checked update: only devices
    /// of identities in `members` (the founder of a two-person group could
    /// otherwise fill our contact list with hundreds of identities it chose).
    pub(crate) fn adopt_group_update_devices(&mut self, update: &GroupUpdate, members: &[String]) {
        if update.member_devices.is_empty() {
            return;
        }
        let devices: Vec<GroupMemberDevice> = update.member_devices.iter()
            .filter(|d| members.contains(&d.identity_id))
            .cloned()
            .collect();
        self.adopt_vouched_member_devices(&devices, &update.member_device_proofs);
        // Only for a device we hold with these keys (adopted above or
        // known before), and the first one given wins: a founder of
        // another group cannot redirect our first contact with it.
        for d in devices.iter().filter(|d| d.first_contact_secret.len() == 16) {
            let known = self.known_remote_devices.get(&d.device_fingerprint)
                .map_or(false, |k| k.sign_pubkey_ed25519 == d.sign_pubkey_ed25519 && k.sign_pubkey_mldsa == d.sign_pubkey_mldsa);
            let key = format!("gf:{}:{}", d.device_fingerprint, update.group_id);
            if known && self.meta_str(&key).is_none() {
                self.meta_put(&key, &hex::encode(&d.first_contact_secret));
            }
        }
    }

    /// On the FOUNDER side, collects the device records to vouch for the given member identities (see `GroupUpdate.member_devices`). Our own devices
    /// come from `own_devices`, the others from `known_remote_devices`. Unknown members are skipped (if the founder does not know them either, it cannot vouch).
    pub(crate) fn collect_vouched_member_devices(&self, group_id: &str, member_ids: &[String]) -> Vec<GroupMemberDevice> {
        let own_identity_id = self.identity.as_ref().map(|i| i.identity_id.clone()).unwrap_or_default();
        let mut out = Vec::new();
        for id in member_ids {
            // The identity's first device if we have it (it needs no proof,
            // see `vouch_proofs`), else the smallest fingerprint; `find`
            // took whichever the map gave first.
            let pick = |m: &HashMap<String, DeviceRecord>| m.values()
                .filter(|d| d.identity_id == *id && d.is_active)
                .min_by_key(|d| (d.device_fingerprint != *id, d.device_fingerprint.clone()))
                .cloned();
            let rec = if *id == own_identity_id { pick(&self.own_devices) } else { pick(&self.known_remote_devices) };
            if let Some(d) = rec {
                out.push(GroupMemberDevice {
                    identity_id: d.identity_id.clone(),
                    device_fingerprint: d.device_fingerprint.clone(),
                    device_name: d.device_name.clone(),
                    sign_pubkey_ed25519: d.sign_pubkey_ed25519.clone(),
                    sign_pubkey_mldsa: d.sign_pubkey_mldsa.clone(),
                    kem_pubkey_x25519: d.kem_pubkey_x25519.clone(),
                    kem_pubkey_mlkem: d.kem_pubkey_mlkem.clone(),
                    // Onion only: a clearnet or UPnP address must never travel inside a group update (the node dials onion only). For another
                    // member's device this is `device_onion_addr`, which a LAN or relay address never overwrites. Our own device uses its node address.
                    last_addr: if *id == own_identity_id {
                        self.get_node_address()
                    } else {
                        self.device_onion_addr.get(&d.device_fingerprint).cloned()
                    },
                    first_contact_secret: if Some(&d.device_fingerprint) == self.own_mailbox_topic_fp.as_ref() {
                        self.own_group_contact_secret(group_id)
                    } else {
                        self.member_group_secret(&d.device_fingerprint, group_id).unwrap_or_default()
                    },
                });
            }
        }
        out
    }

    /// see `GroupUpdate.member_device_proofs`.
    pub(crate) fn vouch_proofs(&self, vouched: &[GroupMemberDevice]) -> Vec<packet::DeviceAddProof> {
        vouched.iter()
            .filter(|d| d.device_fingerprint != d.identity_id)
            .filter_map(|d| self.device_add_proof(&d.device_fingerprint))
            .collect()
    }

    /// Automatic introduction of members. On the RECEIVING side, this adopts the member devices the founder vouched for, so we can set up ratchets and
    /// message members we have never paired with (see `GroupUpdate.member_devices`).
    ///
    /// Security rules:
    /// - The keys of a device we ALREADY know are NEVER overwritten. A malicious founder cannot change the key of a person we trust.
    /// - `device_fingerprint` must be the SHA3-256 of the keys (records that are inconsistent with themselves are rejected).
    /// - Our own identity is skipped.
    /// - Added contacts are marked `added_via_group` (not verified face to face with a QR). The UI shows this.
    pub(crate) fn adopt_vouched_member_devices(&mut self, devices: &[GroupMemberDevice], proofs: &[packet::DeviceAddProof]) {
        let own_identity_id = self.identity.as_ref().map(|i| i.identity_id.clone()).unwrap_or_default();
        for d in devices {
            if d.identity_id == own_identity_id {
                continue;
            }
            // A founder cannot bring a blocked person back by vouching for them (see `block_identity`). The block targets that person, and it is lifted only
            // by a face-to-face pairing.
            if self.is_blocked(&d.identity_id) {
                warn!("Blocked identity tried to be added via group vouching, rejected: {}", crate::log_id(&d.identity_id));
                continue;
            }
            if self.known_remote_devices.contains_key(&d.device_fingerprint) {
                continue; // already known: never overwrite
            }
            // Is the fingerprint consistent with the keys? (Same check as in IdentityExchange.)
            if !d.keys_match_fingerprint() {
                error!("Group member device record inconsistent ({}) — rejected", crate::log_id(&d.device_fingerprint));
                continue;
            }
            // If we already know ANOTHER device for this identity, we do not add a second device on the founder's word. That could be an impersonation
            // attempt on a known person. The "unrecognised new device" flow is for QR and IdentityExchange.
            if self.known_remote_devices.values().any(|k| k.identity_id == d.identity_id) {
                info!(
                    "Group member {} already has a known device — vouched new device not added",
                    crate::log_id(&d.identity_id)
                );
                continue;
            }

            // `register_contact_from_pairing` would refuse it below, after the
            // device record was already stored.
            if !is_fingerprint_hex(&d.identity_id) {
                continue;
            }
            // The founder vouches for the KEYS of a member, not for whose they
            // are: a device is taken under an identity only if it is that
            // identity's first device, or comes with the proof. A founder
            // could otherwise hand out its own key as any member we had not
            // met, and read and write as that member.
            if !Self::claim_is_bound(&d.identity_id, &d.device_fingerprint, proofs, &d.sign_pubkey_ed25519, &d.sign_pubkey_mldsa) {
                warn!("Vouched device {} could not be linked to identity, not added", crate::log_id(&d.identity_id));
                continue;
            }
            if let Some(p) = proofs.iter().find(|p| p.device_add.new_device_fingerprint == d.device_fingerprint) {
                self.remember_device_add(&p.device_add);
            }
            // Same for a contact that already lists other devices (paired by
            // code, its keys not here yet): the founder's word does not add
            // one, as a scanned code does not.
            if let Some(c) = self.identity_to_contact.get(&d.identity_id).and_then(|cid| self.contacts.get(cid)) {
                if !c.known_devices.is_empty() && !c.is_known_active(&d.device_fingerprint) {
                    continue;
                }
            }
            // see `MAX_CONTACTS` — the same no-user-action contact creation as
            // the TOFU path (`evaluate_sender_device`), with the same cap: a
            // founder could flood the contact list with one large
            // `member_devices` list. Checked before the device record is
            // stored, so `remote_devices` stays bounded too.
            let is_new_contact = !self.identity_to_contact.contains_key(&d.identity_id);
            if is_new_contact && self.contacts.len() >= MAX_CONTACTS {
                warn!(
                    "Group vouching rejected: contacts table at limit ({} >= {}), identity {} not added",
                    self.contacts.len(), MAX_CONTACTS, crate::log_id(&d.identity_id)
                );
                continue;
            }

            let record = DeviceRecord {
                device_fingerprint: d.device_fingerprint.clone(),
                identity_id: d.identity_id.clone(),
                sign_pubkey_ed25519: d.sign_pubkey_ed25519.clone(),
                sign_pubkey_mldsa: d.sign_pubkey_mldsa.clone(),
                kem_pubkey_x25519: d.kem_pubkey_x25519.clone(),
                kem_pubkey_mlkem: d.kem_pubkey_mlkem.clone(),
                device_name: sanitize_display_name(&d.device_name).unwrap_or_default(),
                is_active: true,
                last_seen: current_time_ms(),
            };
            self.persist_remote_device(&record);
            self.known_remote_devices.insert(d.device_fingerprint.clone(), record);
            // Add to the contact list and mark it as "added via group" (see `Contact.added_via_group` and the security note).
            if let Err(e) = self.register_contact_from_pairing(
                d.identity_id.clone(),
                d.device_fingerprint.clone(),
                d.device_name.clone(),
            ) {
                warn!("Group member device {} known, contact not registered: {}", crate::log_id(&d.device_fingerprint), e);
            }
            if is_new_contact {
                if let Some(cid) = self.identity_to_contact.get(&d.identity_id).cloned() {
                    if let Some(c) = self.contacts.get_mut(&cid) {
                        c.added_via_group = true;
                    }
                    if let Some(c) = self.contacts.get(&cid) {
                        self.persist_contact(c);
                    }
                }
            }
            // Dial hint (if any), so a member on another network can be reached.
            // Only the founder signed it, not the device. It is kept apart from `device_last_addr`/`device_onion_addr`, whose PeerIds bind a connection to
            // the device (ConnectionEstablished, `record_peer_id_if_known`). As one of those, a founder could make any PeerId "the member" and take our
            // sends to it.
            if let Some(addr) = d.last_addr.as_deref().filter(|a| a.parse::<Multiaddr>().ok().is_some_and(|m| extract_peer_id(&m).is_some())) {
                self.meta_put(&format!("vah:{}", d.device_fingerprint), addr);
            }
            info!(
                "New contact added via group (founder vouching, NOT VERIFIED): {} / {}",
                crate::log_id(&d.identity_id), crate::log_id(&d.device_fingerprint)
            );
        }
    }

    /// The smallest active device fingerprint of an identity, if one is known.
    pub(crate) fn resolve_active_device_for_identity(&self, identity_id: &str) -> Option<String> {
        // Deterministic: the active device with the smallest fingerprint. HashMap order is random, so with several active devices a different
        // one would be returned on each call, and group messages would jump between a member's devices.
        self.known_remote_devices.values()
            .filter(|d| d.identity_id == identity_id && d.is_active)
            .map(|d| d.device_fingerprint.clone())
            .min()
    }

    /// Returns `group_message_local_id`: the id that merges the N fan-out copies of this group message into ONE local id (see packet.rs
    /// `Text.group_message_local_id`). Kotlin must use THIS as the `messageId` of its optimistic bubble, not a random UUID. Otherwise the returned
    /// "seen" notices cannot match any local bubble.
    /// `reply_to_message_id`/`reply_to_preview`/`reply_to_sender_identity_id`: same as in `send_message`. The group counterpart also carries the replied-to
    /// message's sender `identity_id` (see the packet.rs `reply_to_sender_identity_id` note), so the receiving side can show "reply to Ahmet".
    /// See `group_failed_copies`.
    pub(crate) fn note_group_copy_failed(&mut self, content: &MessageContent, device_fingerprint: &str) {
        let MessageContent::Text { group_id: Some(_), group_message_local_id: Some(local_id), .. } = content else { return };
        if self.group_failed_copies.len() >= 1_000 {
            self.group_failed_copies.clear();
        }
        let entry = self.group_failed_copies.entry(local_id.clone()).or_insert_with(|| (content.clone(), Vec::new()));
        if !entry.1.iter().any(|fp| fp == device_fingerprint) {
            entry.1.push(device_fingerprint.to_string());
        }
    }

    /// "Retry" on a group bubble: the same message, under the same group-wide
    /// id, only to the devices whose copy failed. `Ok(false)`: nothing is
    /// recorded for this id, the caller sends the message as a new one.
    pub(crate) fn retry_group_message_copies(&mut self, group_id: &str, local_id: &str) -> Result<bool, String> {
        let group = self.groups.get(group_id).cloned_group()?;
        let Some((content, devices)) = self.group_failed_copies.remove(local_id) else { return Ok(false) };
        // Every device that missed it was revoked since: nobody waits for it.
        if devices.is_empty() { return Ok(true) }
        let mut sent = false;
        for device in devices {
            // Removed from the group since: no copy.
            let still_member = self.identity_id_for_device(&device).map(|id| group.is_member(&id)).unwrap_or(false);
            if !still_member {
                continue;
            }
            match self.send_message_content(device.clone(), &content, None) {
                Ok(_) => sent = true,
                Err(e) => {
                    error!("Group message could not be sent again ({}): {}", crate::log_id(&device), e);
                    self.note_group_copy_failed(&content, &device);
                }
            }
        }
        if sent { Ok(true) } else { Err("No copy could be sent".to_string()) }
    }

    pub(crate) fn send_group_message(&mut self, group_id: &str, plaintext: &str, reply_to_message_id: Option<String>, reply_to_preview: Option<String>, reply_to_sender_identity_id: Option<String>, mentions: Vec<String>, expire_secs: Option<u32>) -> Result<String, String> {
        self.send_group_message_with_status(group_id, plaintext, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, mentions, expire_secs).map(|(id, _)| id)
    }

    /// `send_group_message` with the send status of the bubble, as `send_message` returns it: "sent" when a copy reached the network for at
    /// least one member (or there is nobody else), "pending" when every copy is only queued. A pending row is set "sent" by the first later
    /// publish (`retry_unconfirmed_messages`) or "delivered" by the first Ack.
    pub(crate) fn send_group_message_with_status(&mut self, group_id: &str, plaintext: &str, reply_to_message_id: Option<String>, reply_to_preview: Option<String>, reply_to_sender_identity_id: Option<String>, mentions: Vec<String>, expire_secs: Option<u32>) -> Result<(String, String), String> {
        // See `send_message`: None = the group's mode, Some(0) = ordinary.
        let expire_secs = match expire_secs {
            Some(secs) => packet::disappear_secs(Some(secs)),
            None => self.disappear_mode("", group_id),
        };
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if !group.is_member(&own_identity_id) {
            return Err("You are not a group member".to_string());
        }
        // Each member is encrypted separately with the existing 1:1 ratchet. `group_id: Some(...)`: real group integration, so the receiver can tell this
        // apart from an ordinary 1:1 message and route it to GroupChatActivity (see the receive_message note). Starts with our author tag: receivers
        // refuse an id without it.
        let id_rest = format!("-{}", uuid::Uuid::new_v4());
        let local_id = format!("{}{}", hex::encode(group_msg_tag(group_id, &own_identity_id, &id_rest)), id_rest);
        let sent_at_ms = current_time_ms();
        // Copy for the sibling-device echo (carried into the content below).
        let echo_reply_id = reply_to_message_id.clone();
        let echo_reply_prev = reply_to_preview.clone();
        let echo_reply_sender = reply_to_sender_identity_id.clone();
        // See packet.rs `MessageContent::Text.sent_at_ms`.
        let author_proof = self.sign_group_author(group_id, &local_id, plaintext)?;
        let content = MessageContent::Text {
            group_id: Some(group_id.to_string()),
            text: plaintext.to_string(),
            group_message_local_id: Some(local_id.clone()),
            sent_at_ms,
            reply_to_message_id, reply_to_preview, reply_to_sender_identity_id,
            author_proof: Some(author_proof.clone()),
            mentions: filter_mentions(&group, Some(&own_identity_id), mentions),
            expire_secs,
        };
        // Archive ONCE, as a single row, BEFORE the fan-out loop, not inside it. `send_message_content` is called separately for each member, and
        // passing `archive_plaintext: Some(...)` there would create one row per member. Our own archive must not depend on whether a single member
        // is reached: if the first member's send failed, we would lose our own "sent" record.
        let (reply_to_id, reply_to_prev, reply_to_sender) = match &content {
            MessageContent::Text { reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, .. } => {
                (reply_to_message_id.as_deref(), reply_to_preview.as_deref(), reply_to_sender_identity_id.as_deref())
            }
            _ => (None, None, None),
        };
        // Not sent when our own copy cannot be kept (see the 1:1 twin).
        self.archive_group_message_exp(group_id, &own_identity_id, "sent", plaintext.as_bytes(), Some(&local_id), reply_to_id, reply_to_prev, reply_to_sender, sent_at_ms, Some(&author_proof), expire_secs)
            .map_err(|e| format!("Could not save message: {}", e))?;
        let others = group.other_members(&own_identity_id);
        let mut published = others.is_empty();
        for member_identity_id in others {
            published |= self.send_group_message_to_member_published(group_id, &member_identity_id, &content).1;
        }
        let status = if published { MessageSendStatus::Sent } else { MessageSendStatus::Pending };
        if !published {
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE messages SET status = 'pending' WHERE message_id = ?1 AND group_id = ?2 AND direction = 'sent' AND status = 'sent'",
                    params![local_id, group_id],
                );
            }
        }
        // Multi-device (1.7): echo to my sibling devices, so my group message shows there too. My own message is not part of the fan-out, so the echo
        // does not create a duplicate record.
        self.echo_group_to_siblings(group_id, SiblingEchoBody::Text {
            message_id: local_id.clone(), text: plaintext.to_string(), sent_at_ms,
            reply_to_message_id: echo_reply_id, reply_to_preview: echo_reply_prev,
            reply_to_sender_identity_id: echo_reply_sender, expire_secs,
        });
        Ok((local_id, status.as_str().to_string()))
    }
}
