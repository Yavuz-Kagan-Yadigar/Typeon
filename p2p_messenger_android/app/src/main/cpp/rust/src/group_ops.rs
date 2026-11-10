//! Group create/update/membership, founder chain and group message fan-out.

use super::*;

impl P2PCore {

    // ---------------------------------------------------------------
    // Bölüm 5: Grup Mesajlaşma (pairwise)
    // ---------------------------------------------------------------

    /// `group-<16 hex nonce><32 hex tag>`, the tag a hash of founder and nonce.
    /// The id names its first founder: a group we do not hold is taken only
    /// from that identity (`process_group_update`). The id used to be free,
    /// and any contact that knew it could create the group here first, with
    /// itself as founder; the real founder's updates were then refused.
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

    /// bkz. `persist_contact` dosya başı notu — `groups` tablosu da aynı
    /// şekilde hiç yazılmıyordu.
    pub(crate) fn persist_group(&self, group: &Group) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let members_json = match serde_json::to_string(&group.members) {
            Ok(j) => j,
            Err(e) => { error!("Group members serileştirilemedi: {}", e); return; }
        };
        let founder_chain_json = serde_json::to_string(&group.founder_chain).unwrap_or_else(|_| "[]".to_string());
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO groups (group_id, founder, name, version, members_json, created_at, avatar_jpeg, founder_chain_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![group.group_id, group.founder_identity_id, group.name, group.version, members_json, group.created_at as i64, group.avatar_jpeg, founder_chain_json],
)
        {
            error!("Grup yazılamadı ({}): {}", group.group_id, e);
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

    /// The signed `GroupUpdate` for `change` on top of `group`: version + 1,
    /// and the member list and vouched devices as they are AFTER the change
    /// (a new member must get the full list, a removed one must not be in it).
    /// Shared by every founder action; the caller applies and fans out.
    ///
    /// M90/H6: `member_devices` holds only the devices new or changed since
    /// the previous update of this device (`gvd:` in app_meta); `full` puts
    /// every one in (for a member just added). See `GroupSyncRequest`.
    pub(crate) fn sign_group_change(&self, group: &Group, change: &GroupChange) -> Result<GroupUpdate, String> {
        self.sign_group_change_with(group, change, false)
    }

    pub(crate) fn sign_group_change_with(&self, group: &Group, change: &GroupChange, full: bool) -> Result<GroupUpdate, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let new_version = group.version.checked_add(1).ok_or("Grup sürümü tükendi")?;
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
        // H6: every member device carries ~4 KB of keys (+ a proof). Past the
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
        // H78: what this device applies now, for the same-version tie-break.
        self.set_group_tie(&group.group_id, &group_tie_hash(&update)?);
        Ok(update)
    }

    /// The current state of a group we found, signed again at its current
    /// version with every vouched device: a reply to `GroupSyncRequest`,
    /// `requeue_unresolved_group_syncs`, `resend_group_to_all`. The change
    /// re-states the avatar (or the name): a member behind gets the whole
    /// state, one at this version takes it as the same state (bkz.
    /// `process_group_update`, tie-break).
    pub(crate) fn sign_group_resync(&self, group: &Group) -> Result<GroupUpdate, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        if group.version == 0 {
            return Err("Grup henüz yayınlanmadı".to_string());
        }
        let change = match &group.avatar_jpeg {
            Some(a) => GroupChange::AvatarUpdate(Some(a.clone())),
            None => GroupChange::Rename(group.name.clone()),
        };
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

    /// #81 (H103): the founder signs the current group state again and sends
    /// it to every member device (and to its own other devices).
    pub(crate) fn resend_group_to_all(&mut self, group_id: &str) -> Result<(), String> {
        let own_identity_id = self.my_identity_id().ok_or("No identity")?;
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Sadece kurucu grubu yeniden gönderebilir".to_string());
        }
        let update = self.sign_group_resync(&group)?;
        for member in group.other_members(&own_identity_id) {
            self.send_group_update_to_member(group_id, &member, &update);
        }
        self.send_group_update_to_siblings(&update);
        Ok(())
    }

    /// H78: a founder's other devices get each update it signs, so they
    /// never sign the same version themselves (they apply it like a member).
    pub(crate) fn send_group_update_to_siblings(&mut self, update: &GroupUpdate) {
        let content = MessageContent::GroupUpdate(update.clone());
        for fp in self.sibling_active_devices() {
            if let Err(e) = self.send_message_content(fp, &content, None) {
                warn!("GroupUpdate kardeş cihaza gönderilemedi: {}", e);
            }
        }
    }

    /// H78: hash of the update this device applied at the group's current
    /// version (`gvh:` in app_meta).
    pub(crate) fn group_tie(&self, group_id: &str) -> Vec<u8> {
        self.meta_str(&format!("gvh:{}", group_id)).and_then(|v| hex::decode(v).ok()).unwrap_or_default()
    }

    pub(crate) fn set_group_tie(&self, group_id: &str, hash: &[u8]) {
        self.meta_put(&format!("gvh:{}", group_id), &hex::encode(hash));
    }

    /// #77: ask the founder for the whole group state, at most hourly per group.
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

    /// Spec 5.4: kurucu, grup daveti üretir; davet edilen kişi zaten var
    /// olan/kurulmakta olan 1:1 bağlantı üzerinden `GroupUpdate(Add)` alır.
    /// Burada: kurucu tarafında hem `members`'a ekler hem de tüm mevcut +
    /// yeni üyelere `GroupUpdate` pairwise gönderir (spec 5.2).
    pub(crate) fn invite_to_group(&mut self, group_id: &str, new_member_identity_id: &str) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();

        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Sadece kurucu üye ekleyebilir".to_string());
        }
        // Each call signs a new version and sends it to every member.
        if group.is_member(new_member_identity_id) {
            return Err("Bu kişi zaten grubun üyesi".to_string());
        }
        // Every receiver refuses an update past this (`process_group_update`).
        if group.members.len() >= MAX_GROUP_MEMBERS {
            return Err(format!("Grup en fazla {} üye alabilir", MAX_GROUP_MEMBERS));
        }
        if self.is_blocked(new_member_identity_id) {
            return Err("Engellenmiş bir kişi gruba eklenemez".to_string());
        }
        let new_version = group.version.checked_add(1).ok_or("Grup sürümü tükendi")?;
        let change = GroupChange::Add(new_member_identity_id.to_string());
        // The new member gets every vouched device, the others only the new ones.
        let full = self.sign_group_change_with(&group, &change, true)?;
        let update = self.sign_group_change(&group, &change)?;

        // Yerel state'i güncelle.
        if let Some(g) = self.groups.get_mut(group_id) {
            apply_change(g, &change, new_version, current_time_ms());
        }
        if let Some(g) = self.groups.get(group_id) {
            self.persist_group(g);
        }

        // Tüm üyelere (yeni eklenen dahil) pairwise gönder (spec 5.2).
        // Spec dışı, güvenlik denetimi düzeltmesi: önceden bare/şifrelenmemiş
        // bir NetworkEnvelope::GroupUpdate olarak gönderiliyordu (sadece
        // Ed25519 imzalı, gossipsub'a AÇIK METİN yayılıyordu) — artık diğer
        // her şeyle AYNI hibrit ratchet-şifreli kanaldan gidiyor (bkz.
        // MessageContent::GroupUpdate, needs_delivery_confirmation listesi).
        // Spec dışı, hata düzeltmesi ("Tor üzerinden bağlı bir cihaz gruba
        // davet edilmesine rağmen grubu hiç görmüyor"): hedef cihaz henüz
        // çözülemiyorsa (bkz. `send_group_update_to_member`) artık SESSİZCE
        // kaybolmuyor, periyodik olarak yeniden denenmek üzere bekleyen
        // listeye ekleniyor.
        let targets = self.groups.get(group_id).map(|g| g.member_identity_ids()).unwrap_or_default();
        for member_identity_id in targets {
            if member_identity_id == own_identity_id {
                continue;
            }
            let u = if member_identity_id == new_member_identity_id { &full } else { &update };
            self.send_group_update_to_member(group_id, &member_identity_id, u);
        }
        self.send_group_update_to_siblings(&update);
        Ok(())
    }

    pub(crate) fn remove_from_group(&mut self, group_id: &str, member_identity_id: &str, notify_removed: bool) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Sadece kurucu üye çıkarabilir".to_string());
        }
        // A LeaveGroupRequest from a non-member made a new version, a new
        // signature and a GroupUpdate to every member, each time.
        if !group.is_member(member_identity_id) {
            return Err("Bu kişi grubun üyesi değil".to_string());
        }
        // The founder is us: receivers ignore a founder Remove, so this only
        // burnt a version.
        if member_identity_id == own_identity_id {
            return Err("Kurucu kendini gruptan çıkaramaz".to_string());
        }
        let new_version = group.version.checked_add(1).ok_or("Grup sürümü tükendi")?;
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

        // Çıkarılan üyeye ULAŞMADAN önce eski üye listesini al (spec 5.3:
        // çıkarılan üyeye artık GroupUpdate/grup mesajı gönderilmez).
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
        // bkz. `send_group_update_to_member` — hedef cihaz henüz çözülemiyorsa
        // artık sessizce kaybolmaz, `group_sync_sweep` yeniden dener.
        for member_identity_id in remaining_targets {
            self.send_group_update_to_member(group_id, &member_identity_id, &update);
        }
        if let Some(notice) = removal_notice {
            self.send_group_update_to_member(group_id, member_identity_id, &notice);
        }
        self.send_group_update_to_siblings(&update);
        Ok(())
    }

    /// Spec dışı: grup profil fotoğrafını ayarlar/kaldırır. `invite_to_group`/
    /// `remove_from_group` ile AYNI imzalı `GroupUpdate` mekanizmasını
    /// kullanır (`GroupChange::AvatarUpdate`) — "sadece kurucu değiştirebilir"
    /// kısıtı zaten `validate_group_update`'in `NotFounder` kontrolünden
    /// (hem burada gönderen tarafta hem de `process_group_update`'te alıcı
    /// tarafında) geçer, ayrı bir yetki kontrolü icat edilmedi.
    pub(crate) fn set_group_avatar(&mut self, group_id: &str, avatar_jpeg: Option<Vec<u8>>) -> Result<(), String> {
        // bkz. `set_own_profile_picture` AYNI kontrolü / `MAX_AVATAR_BYTES`.
        // Grupta daha da kritik: `GroupUpdate` ayrıca üye başına ~4 KB'lık
        // kefalet listesi taşıyor.
        if let Some(a) = &avatar_jpeg {
            if a.len() > MAX_AVATAR_BYTES {
                return Err(format!(
                    "Grup fotoğrafı çok büyük ({} KB) — en fazla {} KB olabilir",
                    a.len() / 1024, MAX_AVATAR_BYTES / 1024
                ));
            }
        }
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Sadece kurucu profil fotoğrafını değiştirebilir".to_string());
        }
        let new_version = group.version.checked_add(1).ok_or("Grup sürümü tükendi")?;
        let change = GroupChange::AvatarUpdate(avatar_jpeg);
        let update = self.sign_group_change(&group, &change)?;

        if let Some(g) = self.groups.get_mut(group_id) {
            apply_change(g, &change, new_version, current_time_ms());
        }
        if let Some(g) = self.groups.get(group_id) {
            self.persist_group(g);
        }
        // bkz. `send_group_update_to_member` — hedef cihaz henüz çözülemiyorsa
        // artık sessizce kaybolmaz, `group_sync_sweep` yeniden dener.
        let targets = group.other_members(&own_identity_id);
        for member_identity_id in targets {
            self.send_group_update_to_member(group_id, &member_identity_id, &update);
        }
        self.send_group_update_to_siblings(&update);
        Ok(())
    }

    /// Spec dışı, kullanıcı isteği: grubu TÜM üyeler için siler. Yalnızca
    /// kurucu çağırabilir (aynı `validate_group_update` yetki kuralı karşı
    /// tarafta da uygulanır). İmzalı `GroupChange::Delete` güncellemesi tüm
    /// üyelere gönderilir, sonra grup yerelde kaldırılır.
    /// Kurucu yetkisini başka bir ÜYEYE devreder (bkz.
    /// `GroupChange::TransferFounder`). Devirden sonra bu cihaz artık
    /// grubu yönetemez — üye ekleme/çıkarma, ad ve fotoğraf değiştirme
    /// hakkı yeni kurucuya geçer.
    pub(crate) fn transfer_group_founder(&mut self, group_id: &str, new_founder_identity_id: &str) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Sadece kurucu yetkiyi devredebilir".to_string());
        }
        if new_founder_identity_id == own_identity_id {
            return Err("Yetki zaten sizde".to_string());
        }
        if !group.is_member(new_founder_identity_id) {
            return Err("Yeni kurucu grubun üyesi olmalı".to_string());
        }
        let new_version = group.version.checked_add(1).ok_or("Grup sürümü tükendi")?;
        let change = GroupChange::TransferFounder(new_founder_identity_id.to_string());
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        // bkz. `packet::FounderTransfer` — devrin KENDİ BAŞINA
        // doğrulanabilir, kompakt tanıklığı. Bu güncellemeyi kaçıran bir
        // üye onu yeni kurucunun SONRAKİ güncellemelerinden öğrenip
        // kendini onarabilsin diye zincire ekleniyor; imza ESKİ kurucunun
        // (yani bizim, şu anki) cihazına ait olduğundan sonradan
        // uydurulamaz.
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
        info!("Grup kurucu yetkisi devredildi: {} -> {}", group_id, crate::log_id(&new_founder_identity_id));
        Ok(())
    }

    pub(crate) fn delete_group(&mut self, group_id: &str) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Sadece kurucu grubu silebilir".to_string());
        }
        let update = self.sign_group_change(&group, &GroupChange::Delete)?;

        // Spec dışı, hata düzeltmesi (kullanıcı raporu: "silinen grup tüm
        // üyeler için silinmiyor"): önceden burada kendi basit döngüsü
        // vardı — bir üyenin aktif cihazı o anda çözülemiyorsa (ör.
        // çevrimdışıydı) bildirimi SESSİZCE kaybediyordu, `invite_to_group`/
        // `remove_from_group`/`set_group_avatar`'ın hepsinin kullandığı
        // `send_group_update_to_member` YENİDEN DENEME mekanizmasının
        // (bkz. `pending_group_syncs`/`group_sync_sweep`) AKSİNE. Artık o
        // AYNI helper kullanılıyor.
        for member_identity_id in group.other_members(&own_identity_id) {
            self.send_group_update_to_member(group_id, &member_identity_id, &update);
        }
        self.send_group_update_to_siblings(&update);

        // `remove_group_locally` KASITLI olarak bu grup için bekleyen TÜM
        // senkronları temizler ("artık var olmayan bir grup için sonsuza
        // dek yeniden denenmesin") — `remove_from_group`/`leave_group` için
        // doğru, ama TAM OLARAK yukarıdaki döngünün az önce kuyruğa almış
        // olabileceği silme bildirimini (bir üye çevrimdışıysa) kaybetmemesi
        // gereken bu fonksiyon için YANLIŞ olurdu. Bu yüzden burada onun
        // YERİNE sadece yerel grup kaydı kaldırılır — `pending_group_syncs`
        // dokunulmadan kalır, `group_sync_sweep` üye tekrar erişilebilir
        // olduğunda silme bildirimini teslim eder.
        let (version, founder) = self.groups.remove(group_id).map_or((0, String::new()), |g| (g.version, g.founder_identity_id));
        // The rest of `remove_group_locally`. `pending_group_syncs` stays: the
        // Delete notice must still reach members whose device is not known yet.
        self.pending_group_messages.retain(|(gid, _), _| gid != group_id);
        self.remove_persisted_pending_group_messages_for_group(group_id);
        self.wb_delete_board(Some(group_id), None);
        self.delete_group_meta(group_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM groups WHERE group_id = ?1", params![group_id]);
            // bkz. `group_removed_locally`. Cleared when the founder adds us again.
            let _ = conn.execute(
                "INSERT INTO removed_groups (group_id, version, founder) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(group_id) DO UPDATE SET version = MAX(version, excluded.version), founder = excluded.founder",
                params![group_id, version, founder],
            );
        }
        Ok(())
    }

    /// Spec dışı, kullanıcı isteği: bir üyenin (kurucu HARİÇ — kurucu için
    /// "ayrılma" tanımsız, o SADECE `delete_group` ile TÜM üyeler için
    /// silebilir) gruptan kendi isteğiyle ayrılması. Sadece kurucunun
    /// üyelik değiştirebildiği yetki modeli (bkz. `validate_group_update`)
    /// BOZULMAZ: burada YENİ bir imzalı `GroupChange` ÜRETİLMEZ — bunun
    /// yerine kurucuya doğrudan bir `LeaveGroupRequest` gönderilir, kurucu
    /// bunu alınca kendi (zaten var olan, yetkili) `remove_from_group`'unu
    /// çağırıp gerçek/imzalı `GroupChange::Remove`'u TÜM üyelere dağıtır
    /// (bkz. `receive_message` `LeaveGroupRequest` kolu). Bu cihaz ise
    /// isteği gönderir göndermez YEREL grup kaydını iyimser (optimistic)
    /// olarak hemen kaldırır — `remove_from_group` zaten çıkarılan üyeye
    /// SON GroupUpdate'i göndermediğinden (bkz. o fonksiyonun notu), bu
    /// cihaz kurucudan bir onay ASLA almayacaktır; beklemek anlamsız olurdu.
    pub(crate) fn leave_group(&mut self, group_id: &str) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id == own_identity_id {
            return Err("Kurucu gruptan ayrılamaz — grubu herkes için silebilir".to_string());
        }
        // Every founder device, like the other group sends: one dead device
        // must not swallow the request.
        let founder_devices = self.active_devices_for_identity(&group.founder_identity_id);
        if founder_devices.is_empty() {
            return Err("Kurucunun cihazı bilinmiyor, ayrılma isteği gönderilemedi".to_string());
        }
        let content = MessageContent::LeaveGroupRequest { group_id: group_id.to_string() };
        // bkz. `needs_delivery_confirmation` notu — kurucu o an erişilebilir
        // olmasa bile (uyku modu, çevrimdışı) bu istek onaylanana kadar
        // otomatik yeniden denenir, kaybolmaz.
        // The group stays unless the request could be queued for at least one
        // founder device: otherwise the founder never drops us and the members
        // keep sending to a group we deleted.
        let mut last_err = None;
        let mut sent = false;
        for founder_fp in founder_devices {
            match self.send_message_content(founder_fp, &content, None) {
                Ok(_) => sent = true,
                Err(e) => {
                    error!("LeaveGroupRequest gönderilemedi: {}", e);
                    last_err = Some(e);
                }
            }
        }
        if !sent {
            return Err(last_err.unwrap_or_else(|| "Ayrılma isteği gönderilemedi".to_string()));
        }
        // The siblings keep the group until the founder's update reaches
        // them otherwise. Before the removal: the echo needs the group.
        self.echo_group_to_siblings(group_id, SiblingEchoBody::GroupLeft);
        self.remove_group_locally(group_id);
        Ok(())
    }

    /// Grup kaydını bellekten ve diskten kaldırır (bkz. `delete_group` /
    /// `process_group_update` Delete kolu).
    pub(crate) fn remove_group_locally(&mut self, group_id: &str) {
        let (version, founder) = self.groups.remove(group_id).map_or((0, String::new()), |g| (g.version, g.founder_identity_id));
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM groups WHERE group_id = ?1", params![group_id]);
            // bkz. `group_removed_locally`. Cleared when the founder adds us again.
            let _ = conn.execute(
                "INSERT INTO removed_groups (group_id, version, founder) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(group_id) DO UPDATE SET version = MAX(version, excluded.version), founder = excluded.founder",
                params![group_id, version, founder],
            );
        }
        // bkz. `pending_group_syncs` dokümantasyonu — artık var olmayan bir
        // grup için sonsuza dek yeniden denenmesin.
        self.pending_group_syncs.retain(|(gid, _), _| gid != group_id);
        // bkz. `pending_group_messages` AYNI notu.
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

    /// bkz. `pending_group_messages` alanı dokümantasyonu — bir üyeye bir
    /// grup mesajı (Text/Edit/Delete) göndermeyi dener; hedefin aktif
    /// cihazı henüz bilinmiyorsa (bkz. `resolve_active_device_for_identity`)
    /// içeriği SESSİZCE KAYBETMEK yerine bekleyen kuyruğa ekler —
    /// `group_sync_sweep` cihaz çözülebilir hale gelince yeniden dener.
    /// `send_group_message`/`edit_group_message`/`delete_group_message`'ın
    /// fan-out döngülerindeki TEKRARLANAN bloğu tek bir yerde toplar (bkz.
    /// `send_group_update_to_member` AYNI desen, GroupUpdate için).
    /// Dönüş: mesaj GERÇEKTEN gönderildiyse (veya en azından bir gönderim
    /// denemesi yapıldıysa) `true`, sadece kuyruklandıysa `false`.
    pub(crate) fn send_group_message_to_member(&mut self, group_id: &str, member_identity_id: &str, content: &MessageContent) -> bool {
        // Hesabını silmiş üyeye gönderilmez ve kuyruğa da alınmaz.
        if self.deleted_identities.contains(member_identity_id) {
            return false;
        }
        // Çoklu-cihaz (spec 1.7.1): üyenin TÜM aktif cihazlarına ayrı ayrı
        // gönder — aksi halde bir üyenin ikincil cihazı grup mesajlarını hiç
        // görmezdi. Alıcı tarafta grup arşivi `group_message_local_id` ile
        // anahtarlandığından cihazlar arası tekrar/çakışma olmaz.
        let devices = self.active_devices_for_identity(member_identity_id);
        if !devices.is_empty() {
            // Spec dışı, hata düzeltmesi ("grup düzenle/sil sessizce
            // kimseye ulaşmayabiliyordu"): önceden burada üyenin cihaz
            // listesi BOŞ DEĞİLSE kayıtsız şartsız `true` dönülüyordu —
            // `send_message_content`'in HER cihaz için `Err` dönmesi
            // (ör. o cihazla ratchet oturumu kurulamadı) çağıranlara
            // (`edit_group_message`/`delete_group_message`) hiç
            // yansımıyordu, onlar da yine de `Ok(())` (başarı) rapor
            // ediyordu. `send_message_content`'in `Ok` dönmesi ağ
            // yayınının o an gerçekten başarılı olduğu anlamına gelmez
            // (geçici ağ hataları zaten ayrıca `awaiting_confirmation`
            // yeniden deneme kuyruğuna alınır, bkz. `publish_with_ack_tracking`)
            // — ama KALICI bir hata (ör. şifreleme/ratchet hatası) varsa bu
            // artık doğru şekilde `false`'a yansır.
            let mut sent_to_any_device = false;
            let mut refused: Vec<String> = Vec::new();
            for peer_fp in devices {
                match self.send_message_content(peer_fp.clone(), content, None) {
                    Ok(_) => sent_to_any_device = true,
                    Err(e) => {
                        error!("Grup mesajı bir üyenin cihazına gönderilemedi ({}): {}", crate::log_id(&peer_fp), e);
                        refused.push(peer_fp);
                    }
                }
            }
            if sent_to_any_device {
                self.park_device_copies(&refused, content);
                return true;
            }
            // Every device refused (no session, keys, persist failure): queue
            // like an unresolved member instead of dropping it.
            warn!(
                "Grup mesajı: {} hiçbir cihazına gönderilemedi (group={}) — kuyruğa alındı (bkz. group_sync_sweep)",
                crate::log_id(&member_identity_id), group_id
            );
        } else {
            // Üyenin hiçbir aktif cihazı henüz bilinmiyor — sessizce kaybetmek
            // yerine kuyruğa al; `group_sync_sweep` çözülünce yeniden dener.
            warn!(
                "Grup mesajı: {} için aktif cihaz henüz bilinmiyor (group={}) — periyodik olarak yeniden denenecek (bkz. group_sync_sweep)",
                crate::log_id(&member_identity_id), group_id
            );
        }
        let key = (group_id.to_string(), member_identity_id.to_string());
        // NOT: `remove_oldest_persisted_pending_group_message` (bir `self`
        // metodu) `queue` (bkz. aşağıdaki `entry().or_default()`) hâlâ
        // ödünç alınmışken çağrılamaz — bu yüzden dolu/aşım kontrolü ÖNCE,
        // AYRI bir salt-okunur bakışla yapılır.
        let needs_eviction = self.pending_group_messages.get(&key)
            .map(|q| q.len() >= MAX_PENDING_GROUP_MESSAGES_PER_MEMBER)
            .unwrap_or(false);
        if needs_eviction {
            // Bellek-içi en eskiyi atacağız, kalıcı kopyasını da (aynı
            // grup/üye için en eski satır) at — aksi halde diskte
            // bellek-içi listeden FAZLA satır birikir ve bir sonraki
            // restart'ta gerçekte atılmış olan bu eski mesaj da yeniden
            // gönderilirdi.
            self.remove_oldest_persisted_pending_group_message(group_id, member_identity_id);
            let dropped = self.pending_group_messages.get_mut(&key).map(|q| q.remove(0));
            // Not silently: the dropped text's bubble turns to "error".
            if let Some(MessageContent::Text { group_message_local_id: Some(local_id), .. }) = dropped {
                warn!("Grup kuyruğu dolu (group={}): en eski mesaj atıldı", group_id);
                self.attachment_events.push(serde_json::json!({
                    "type": "status", "peer": member_identity_id, "group_id": group_id,
                    "message_id": local_id, "status": "error"
                }).to_string());
            }
        }
        let queue = self.pending_group_messages.entry(key).or_default();
        queue.push(content.clone());
        self.persist_pending_group_message(group_id, member_identity_id, content);
        // Defter #26: burası eskiden `false` dönüyordu ve çağıranlar
        // (`send_group_message`/`edit_group_message`/`delete_group_message`)
        // bunu "ulaşılabilir grup üyesi yok" HATASI sayıp arayüze hata
        // gösteriyordu — oysa içerik hem bellekte hem DİSKTE kuyruğa alındı
        // (`pending_group_messages`) ve üyenin cihazı çözülür çözülmez
        // `group_sync_sweep` tarafından gönderilecek. Kuyruğa alma bir
        // BAŞARISIZLIK değil, ertelenmiş bir teslimdir.
        true
    }

    /// H8: a device of a member refused a group packet (no session yet, ...)
    /// while another device took it, so the member-level queue never sees it.
    /// A durable row of its own (fresh packet id) is sent again by
    /// `load_pending_durable_retries_from_db` (start, or the device seen again).
    pub(crate) fn park_device_copies(&mut self, refused: &[String], content: &MessageContent) {
        let now = current_time_ms();
        for fp in refused {
            self.persist_durable_retry(&uuid::Uuid::new_v4().to_string(), fp, content, now);
        }
        // The table is otherwise read only at start or when a stale device
        // comes back: a copy for a device seen every day waited for a restart.
        if !refused.is_empty() && self.durable_reload_at == 0 {
            self.durable_reload_at = now + DURABLE_PARK_RELOAD_MS;
        }
    }

    /// Spec dışı, hata düzeltmesi ("Tor üzerinden bağlı bir cihaz gruba
    /// davet edilmesine rağmen grubu hiç görmüyor"): bir üyeye bir
    /// `GroupUpdate` göndermeyi dener — hedefin aktif cihazı henüz
    /// bilinmiyorsa (bkz. `pending_group_syncs` notu), bu (group_id,
    /// identity_id) çifti için güncellemeyi SESSİZCE KAYBETMEK yerine
    /// bekleyen listeye ekler; `group_sync_sweep` cihaz çözülebilir hale
    /// gelene kadar periyodik olarak yeniden dener. `invite_to_group`/
    /// `remove_from_group`/`set_group_avatar`/`delete_group`'un fan-out
    /// döngülerindeki TEKRARLANAN bloğu tek bir yerde toplar.
    pub(crate) fn send_group_update_to_member(&mut self, group_id: &str, member_identity_id: &str, update: &GroupUpdate) {
        // Çoklu-cihaz: üyenin TÜM aktif cihazlarına gönder — aksi halde bir
        // üyenin ikincil cihazının grup üyeliği/adı/avatarı bayat kalırdı.
        let devices = self.active_devices_for_identity(member_identity_id);
        let mut sent = false;
        let mut refused: Vec<String> = Vec::new();
        let content = MessageContent::GroupUpdate(update.clone());
        for peer_fp in devices {
            match self.send_message_content(peer_fp.clone(), &content, None) {
                Ok(_) => sent = true,
                Err(e) => {
                    error!("GroupUpdate bir üyenin cihazına gönderilemedi: {}", e);
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
            if lasting {
                if let Some(sealed) = ciborium_bytes(update).ok().and_then(|b| self.seal_local_blob(&b)) {
                    self.meta_put(&meta_key, &hex::encode(sealed));
                }
            }
            error!(
                "GroupUpdate: {} için aktif cihaz henüz bilinmiyor (group={}) — periyodik olarak yeniden denenecek (bkz. group_sync_sweep)",
                crate::log_id(&member_identity_id), group_id
            );
            self.pending_group_syncs.insert((group_id.to_string(), member_identity_id.to_string()), update.clone());
        }
    }

    /// bkz. `pending_group_syncs`/`send_group_update_to_member` — `reconnect_sweep`
    /// ile AYNI periyodik desen. Bekleyen her (group_id, identity_id) için
    /// hedef cihaz artık çözülebiliyorsa saklanan `GroupUpdate`'i gönderir.
    pub(crate) fn group_sync_sweep(&mut self) {
        let now = current_time_ms();
        if now.saturating_sub(self.last_group_sync_sweep_at) < GROUP_SYNC_SWEEP_INTERVAL_MS {
            return;
        }
        self.last_group_sync_sweep_at = now;
        // ponytail: one reload per park; a copy whose resend fails again
        // waits for the next park, a stale device's return or a restart.
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
                // Çoklu-cihaz: helper üyenin TÜM aktif cihazlarına fan-out
                // eder ve çözülürse pending_group_syncs'ten düşer; hâlâ
                // çözülemiyorsa (aktif cihaz yok) girdiyi korur.
                self.send_group_update_to_member(&group_id, &member_identity_id, &update);
            }
        }
        // bkz. `pending_group_messages` alanı dokümantasyonu — AYNI sweep,
        // ayrı kuyruk (bir üye için birikmiş TÜM mesajlar, GroupUpdate'in
        // aksine tek bir "en güncel durum" değil, SIRAYLA gönderilmeli).
        if !self.pending_group_messages.is_empty() {
            let keys: Vec<(String, String)> = self.pending_group_messages.keys().cloned().collect();
            for (group_id, member_identity_id) in keys {
                // Spec dışı (dış AI incelemesi düzeltmesi — AI1-4): kuyruğu
                // boşaltmadan ÖNCE üyenin HÂLÂ grupta olduğunu doğrula. Bir
                // üye, mesajlar onun (o an çözülemeyen) cihazı için beklerken
                // gruptan çıkarılmış/ayrılmış olabilir; cihazı sonradan
                // çözülünce bu bayat mesajları göndermek, artık üye OLMAYAN
                // birine grup etkinliğini sızdırır. Artık üye değilse kuyruğu
                // (bellek + kalıcı kopya) sessizce at.
                let still_member = self.groups.get(&group_id)
                    .map(|g| g.is_member(&member_identity_id))
                    .unwrap_or(false);
                if !still_member {
                    let dropped = self.pending_group_messages.remove(&(group_id.clone(), member_identity_id.clone()))
                        .map(|q| q.len()).unwrap_or(0);
                    self.remove_persisted_pending_group_messages(&group_id, &member_identity_id);
                    info!("group_sync_sweep: {} artık grup üyesi değil (group={}) — bekleyen {} mesaj atıldı",
                        crate::log_id(&member_identity_id), group_id, dropped);
                    continue;
                }
                // Çoklu-cihaz: üyenin TÜM aktif cihazları çözülebiliyorsa hepsine.
                let devices = self.active_devices_for_identity(&member_identity_id);
                if devices.is_empty() { continue; }
                let queued = match self.pending_group_messages.remove(&(group_id.clone(), member_identity_id.clone())) {
                    Some(q) => q,
                    None => continue,
                };
                info!(
                    "group_sync_sweep: {} artık çözülebiliyor, {} bekleyen grup mesajı gönderiliyor (group={})",
                    crate::log_id(&member_identity_id), queued.len(), group_id
                );
                // Send first, drop the disk rows after: a crash in between
                // re-sends (the receiver dedups), it never loses. An entry no
                // device took, and everything after it (order), stays queued.
                // A sent entry has its own durable retry (`publish_with_ack_tracking`).
                let mut unsent: Vec<MessageContent> = Vec::new();
                for content in queued {
                    if unsent.is_empty() {
                        let mut ok = false;
                        let mut refused: Vec<String> = Vec::new();
                        for peer_fp in &devices {
                            match self.send_message_content(peer_fp.clone(), &content, None) {
                                Ok(_) => ok = true,
                                Err(e) => {
                                    error!("group_sync_sweep: grup mesajı yine gönderilemedi: {}", e);
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

    /// Tek bir kurucu devir tanıklığını doğrular — bkz.
    /// `packet::FounderTransfer`.
    ///
    /// The signing device must be ACTIVE now (a stolen, revoked device must
    /// not hand the group over). Known cost: a member that missed a transfer
    /// whose signing device was revoked afterwards cannot verify it any more
    /// and must be re-invited.
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

    /// Yerel kurucuyu, gelen güncellemenin taşıdığı devir zinciriyle
    /// ilerletir — bkz. `packet::FounderTransfer` (kilitlenme senaryosu).
    ///
    /// Zinciri sürüm sırasına göre yürür: her adımda "şu anki yerel
    /// kurucudan devralan, imzası doğrulanan" bir girdi arar. Bulamayınca
    /// durur. Döngüye giremez — her adım kurucuyu DEĞİŞTİRMEK zorunda ve
    /// tur sayısı zincir uzunluğuyla sınırlı.
    ///
    /// Dönüş: onarım yapıldıysa yeni kurucu kimliği.
    ///
    /// `local_chain`: the transfers this device already holds. A transfer is
    /// taken only if it is NEWER than the one that made the current founder
    /// founder. Without that floor an old transfer could be replayed: F hands
    /// over to A (v5), A hands back (v9), and anyone holding the v5 blob made
    /// A founder again.
    pub(crate) fn heal_founder_chain(&self, group_id: &str, current_founder: &str, local_chain: &[packet::FounderTransfer], chain: &[packet::FounderTransfer], new_version: u32) -> Vec<packet::FounderTransfer> {
        let mut walked = Vec::new();
        let mut sorted: Vec<&packet::FounderTransfer> = chain.iter().collect();
        sorted.sort_by_key(|t| t.version);
        let mut founder = current_founder.to_string();
        let mut floor = founder_transfer_floor(local_chain, current_founder);
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
                "Kaçırılmış kurucu devri onarıldı (group={}, v{}): {} -> {}",
                group_id, next.version, crate::log_id(&next.from_identity), crate::log_id(&next.to_identity)
            );
            founder = next.to_identity.clone();
            walked.push((*next).clone());
        }
        walked
    }

    /// Bu gönderen, bu gruba yazma yetkisine sahip mi?
    ///
    /// Bu denetimde bulundu: grup mesajları (`Text`/`FileOffer`/`Reaction`,
    /// hepsi `MessageContent.group_id` taşır) alıcı tarafta HİÇBİR üyelik
    /// kontrolünden geçmiyordu. `receive_message` yalnızca "paketi imzalayan
    /// cihaz tanıdık ve `sender_identity_id` o cihazın kayıtlı kimliği"
    /// olduğunu doğruluyor — `group_id` alanı ise tamamen gönderenin
    /// İDDİASI. Sonuçları:
    ///
    /// - Gruptan ÇIKARILAN bir üye yazmaya devam edebiliyordu: çıkarma
    ///   yalnızca kalan üyelerin GÖNDERME fan-out'undan düşürüyor, o kişiyle
    ///   kurulmuş ikili ratchet duruyor. Mesajı `archive_group_message` ile
    ///   arşive girip UI'da meşru bir grup mesajı olarak görünüyordu.
    /// - Grupla hiç ilgisi olmayan HERHANGİ bir kişi listesi üyesi, bir
    ///   `group_id` bildiği anda (çıkarılmış bir üye bilir, bir ekran
    ///   görüntüsü sızdırabilir) o gruba mesaj/dosya enjekte edebiliyordu.
    ///
    /// Kural KASITLI olarak yalnızca "grubu tanıyorsak" uygulanıyor: yerelde
    /// hiç bilmediğimiz bir grup, henüz ulaşmamış bir davet/`GroupUpdate`
    /// olabilir (gossipsub sıra garantisi vermez ve geç katılan üye
    /// senaryosu tam olarak budur, bkz. `sync_members`) — orada reddetmek
    /// meşru ilk mesajları düşürürdü. Bilinen bir grupta üye olmayan bir
    /// gönderen ise belirsiz değil, açık bir yetkisizlik.
    ///
    /// Reddedilen pakete Ack GÖNDERİLMEZ: bir üyeliği bizden ÖNCE öğrenmiş
    /// meşru bir gönderen (üyelik güncellemesi bize henüz gelmemiş) yeniden
    /// dener ve `GroupUpdate` ulaştığı anda kabul edilir — yani yarış
    /// kendiliğinden onarılır.
    /// Whether a received group text @mentions me: my own identity id in its
    /// list after dropping non-members (the text itself is not trusted).
    pub(crate) fn group_mentions_me(&self, group_id: &str, mentions: Vec<String>) -> bool {
        let (Some(me), Some(group)) = (self.identity.as_ref(), self.groups.get(group_id)) else { return false };
        filter_mentions(group, None, mentions).iter().any(|id| *id == me.identity_id)
    }

    pub(crate) fn sender_may_post_to_group(&self, group_id: &str, sender_identity_id: &str) -> bool {
        match self.groups.get(group_id) {
            Some(group) => group.is_member(sender_identity_id),
            // Unknown: the GroupUpdate may still be on its way. Not so for a
            // group we left, were removed from or deleted. H13: and only an
            // id `create_group` can make (any string, up to ~1 MB, was archived).
            None => is_group_id(group_id) && !self.group_removed_locally(group_id) && self.unknown_group_has_room(group_id),
        }
    }

    /// H2: rows of a group we do not hold are never shown nor cleaned, and
    /// any contact can mint ids. An id that already has rows is taken; a new
    /// one only while fewer than 16 such groups exist.
    /// ponytail: one COUNT over messages per message of an unknown group;
    /// keep a set in memory if that path gets hot.
    pub(crate) fn unknown_group_has_room(&self, group_id: &str) -> bool {
        let Some(conn) = &self.db else { return false };
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE group_id = ?1)
                 OR (SELECT COUNT(DISTINCT group_id) FROM messages
                     WHERE group_id IS NOT NULL AND group_id != '' AND group_id NOT IN (SELECT group_id FROM groups)) < 16",
            params![group_id], |r| r.get::<_, bool>(0),
        ).unwrap_or(false)
    }

    pub(crate) fn process_group_update(&mut self, update: &GroupUpdate) -> Result<(), String> {
        // `create_group` makes `group-<16 hex>`. A founder-chosen id could
        // otherwise be a contact's identity id, and the two share key spaces
        // (archive conversation key, whiteboard board).
        if !is_group_id(&update.group_id) {
            return Err("GroupUpdate: geçersiz grup kimliği".to_string());
        }
        let signer = self.known_remote_devices.get(&update.signed_by_device).cloned()
            .ok_or("Unknown signer device")?;
        let to_verify = group_update_signing_input(
            &update.group_id, update.new_version, &update.change, &update.group_name,
            &update.members, &update.member_devices, &update.signed_by, &update.signed_by_device,
        )?;
        // Artık MessagePacket/HandshakeInit ile AYNI hibrit (Ed25519+ML-DSA)
        // model — bkz. sign_group_update/packet.rs GroupUpdate.signature_pq
        // notu (güvenlik denetimi düzeltmesi).
        verify_hybrid_signature(&to_verify, &update.signature, &update.signature_pq, &signer)
            .map_err(|_| "GroupUpdate signature verification failed".to_string())?;
        // Stored, and returned by every `list_groups`.
        if update.group_name.len() > 256 || matches!(&update.change, GroupChange::Rename(n) if n.len() > 256) {
            return Err("GroupUpdate: grup adı çok uzun".to_string());
        }

        // signed_by_device'ın kurucunun bilinen/Active bir cihazı olup
        // olmadığını kontrol et (spec 5.2).
        let signer_is_active = signer.identity_id == update.signed_by && signer.is_active;

        // Members are stored, synced and fanned out to; ids are compared
        // pairwise. Nothing bounded either: one update from any contact could
        // name 250 000 members of a new group.
        if update.members.len() > MAX_GROUP_MEMBERS
            || update.member_devices.len() > MAX_GROUP_MEMBERS * identity::MAX_ACTIVE_DEVICES
            || update.members.iter().any(|m| !is_fingerprint_hex(m))
            || matches!(&update.change, GroupChange::Add(id) | GroupChange::Remove(id) | GroupChange::TransferFounder(id) if !is_fingerprint_hex(id))
        {
            return Err("GroupUpdate: üye listesi geçersiz ya da çok büyük".to_string());
        }

        let group_exists = self.groups.contains_key(&update.group_id);
        let group_snapshot = self.groups.get(&update.group_id).cloned();
        // A group we left or were removed from: (version, founder) at that time.
        let removed: Option<(u32, String)> = if group_exists { None } else {
            self.db.as_ref().and_then(|conn| {
                conn.query_row("SELECT version, founder FROM removed_groups WHERE group_id = ?1", params![update.group_id], |r| Ok((r.get(0)?, r.get(1)?))).ok()
            })
        };

        // Spec dışı düzeltme: önceden burada boş isimle ("") bir grup
        // oluşturuluyordu — `GroupUpdate` artık her zaman güncel
        // `group_name`'i taşıdığı için (bkz. packet.rs notu), ilk kez
        // görülen bir grup da doğru adla oluşturulabiliyor.
        // A group we left comes back only under the founder it had, or one the
        // carried chain leads to from there: any contact that knew the id
        // could re-create it with itself as founder.
        // A group new to us: the founder its id names (`group_id_for_founder`).
        // That is the signer, or the first founder of the carried chain, from
        // which the walk below must then reach the signer.
        let default_founder = match removed.as_ref().map(|(_, f)| f.clone()).filter(|f| !f.is_empty()) {
            Some(f) => f,
            None if group_exists => update.signed_by.clone(),
            None => {
                let nonce = update.group_id.get(6..22).unwrap_or_default();
                std::iter::once(&update.signed_by)
                    .chain(update.founder_chain.iter().map(|t| &t.from_identity))
                    .find(|f| Self::group_id_for_founder(f.as_str(), nonce) == update.group_id)
                    .cloned()
                    .ok_or("GroupUpdate: grup kimliği kurucusuna bağlı değil")?
            }
        };
        let default_group = || Group::new(update.group_id.clone(), update.group_name.clone(), default_founder.clone(), current_time_ms());
        let mut group_ref = group_snapshot.unwrap_or_else(default_group);

        // Kurucu devri onarımı — bkz. `heal_founder_chain` /
        // `packet::FounderTransfer`. Doğrulamadan ÖNCE, çünkü onarım tam
        // olarak `NotFounder` reddini önlemek için var. Zincirdeki her
        // girdi kendi imzasını taşıdığından bu, yetkiyi gevşetmiyor: uydurma
        // bir zincir doğrulamadan geçemez.
        let walked = self.heal_founder_chain(
            &update.group_id, &group_ref.founder_identity_id, &group_ref.founder_chain, &update.founder_chain, update.new_version,
        );
        if let Some(last) = walked.last() {
            // Only on the working copy. The stored group takes the new
            // founder further down, once the update itself has passed
            // `validate_group_update`: it used to be persisted here, so a
            // rejected update still changed the founder.
            group_ref.founder_identity_id = last.to_identity.clone();
        }

        // H78: two founder devices can sign the same version. At the version
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
        let retake = same_version
            && (matches!(update.change, GroupChange::Delete)
                || (same_state && !matches!(update.change, GroupChange::AvatarUpdate(_) | GroupChange::TransferFounder(_)))
                || tie > old_tie);
        let mut check = group_ref.clone();
        if retake {
            check.version -= 1;
        }
        let gap = group_exists && update.new_version > group_ref.version.saturating_add(1);
        if let Err(e) = validate_group_update(&check, &update.signed_by, signer_is_active, update.new_version) {
            // Spec dışı, hata düzeltmesi (bkz. `PendingConfirmation.regen_content`
            // / "6 saat çevrimdışı" senaryosu): `StaleOrOutOfOrderVersion`,
            // saldırı/bozulma DEĞİL — alıcı bu (veya daha yeni bir)
            // versiyonu ZATEN uygulamış demektir (ör. bu GroupUpdate uzun
            // süre teslim edilemediği için tazelenip tekrar denenirken, o
            // sırada BAŞKA bir grup değişikliği zaten normal yoldan ulaşıp
            // versiyonu ileri taşımış olabilir). Bunu Err olarak yukarı
            // taşırsak çağıran Ack GÖNDERMEZ (bkz. çağıran nokta) — gönderen
            // taraf artık gereksiz/bayat bu paketi SÜRESİZ tazeleyip
            // göndermeye devam eder, çünkü hiçbir zaman onaylanmaz. Alıcı
            // için yapacak bir şey kalmadığından bunu Ok(()) say. (H7: the
            // caller acks every other error too, except "Unknown signer
            // device": the same update can never pass later. A missed
            // founder handover is healed by the carried `founder_chain`.)
            if matches!(e, GroupUpdateError::StaleOrOutOfOrderVersion) {
                // #77: an older update (late, or a full copy) still vouches
                // for devices: founder-signed, and only of current members.
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
                info!("GroupUpdate zaten uygulanmış/bayat (group={}, gelen version={}, yerel version={}) — zararsız, onaylanıyor", update.group_id, update.new_version, group_ref.version);
                return Ok(());
            }
            return Err(format!("{:?}", e));
        }

        // Gap tespiti: bir veya daha fazla ara güncelleme kaçırıldıysa
        // (ör. Add/Remove) yerel üyelik listesi güncelin gerisinde olabilir —
        // artık kilitlenmiyoruz (bkz. group.rs StaleOrOutOfOrderVersion notu)
        // ama bunu görünür kılıyoruz.
        if gap {
            error!(
                "GroupUpdate gap (group={}): yerel version {} -> gelen {} (aradaki {} güncelleme kaçırıldı; üyelik listesi eksik olabilir)",
                update.group_id, group_ref.version, update.new_version,
                update.new_version - group_ref.version - 1
            );
        }

        // Spec dışı, kullanıcı isteği: kurucu grubu TÜM üyeler için sildi —
        // yerel kaydı kaldır ve çık (aşağıdaki alan güncelleme yolu
        // uygulanmaz). Yetki zaten yukarıda `validate_group_update` ile
        // doğrulandı (yalnızca kurucu).
        if matches!(update.change, GroupChange::Delete) {
            info!("Grup kurucusu tarafından silindi: {}", update.group_id);
            // The version of the Delete, not the local one: an update between
            // the two that we missed would bring the group back.
            if let Some(g) = self.groups.get_mut(&update.group_id) {
                g.version = update.new_version;
            }
            self.remove_group_locally(&update.group_id);
            return Ok(());
        }

        if !group_exists {
            // Bu denetimde bulundu: yerelde HİÇ bilmediğimiz bir grup için
            // `validate_group_update`, `group_ref`'i `default_group()` ile
            // (kurucu = imzalayan) kuruyor — yani kontrol tanımı gereği
            // geçiyor. Sonuç: kişi listesindeki HERHANGİ biri, bizi hiç üye
            // yapmayan bir `GroupUpdate` göndererek cihazımızda istediği
            // adla bir grup YARATABİLİYORDU ("Şirket BT Destek" gibi) ve
            // ardından kendisi o grubun tek üyesi/kurucusu olduğundan
            // `sender_may_post_to_group`'tan da geçip içine mesaj
            // atabiliyordu. Sosyal mühendislik için hazır bir yüzey.
            //
            // Kural: bilinmeyen bir grup ancak bu güncelleme BİZİ üye
            // yapıyorsa oluşturulur. `members` boş olan (eski sürüm)
            // göndericilerde tek dayanak `Add(biz)` olur.
            //
            // H7: the caller acks this Err. A group we are really in but lost
            // locally is not refused here: every update carries `members`,
            // which names us.
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
                    "GroupUpdate REDDEDİLDİ: bilinmeyen bir grup ve bizi üye yapmıyor (group={}, imzalayan={})",
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
                warn!("GroupUpdate yok sayıldı: ayrıldığımız grubu geri getirmiyor (group={}, version={})", update.group_id, update.new_version);
                return Ok(());
            }
            // The `removed_groups` row goes once the group is persisted (below).
            self.groups.insert(update.group_id.clone(), Group::new(update.group_id.clone(), update.group_name.clone(), group_ref.founder_identity_id.clone(), current_time_ms()));
        }
        // bkz. `MAX_AVATAR_BYTES` — gelen yönde sınır yoktu. Kurucu
        // yetkisi bir boyut yetkisi değil: aşan avatar DÜŞÜRÜLÜR ama
        // güncellemenin geri kalanı (üyelik, ad, sürüm) normal işlenir,
        // aksi hâlde tek bir büyük fotoğraf grubu kilitlerdi.
        let change = match &update.change {
            GroupChange::AvatarUpdate(Some(a)) if a.len() > MAX_AVATAR_BYTES => {
                warn!(
                    "Grup avatarı çok büyük ({} bayt), yok sayıldı (group={})",
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
            // Her güncellemede ismi senkron tut (self-healing) — sadece
            // açık bir Rename değişikliğinde değil.
            g.name = update.group_name.clone();
            // Spec dışı, hata düzeltmesi (üçüncü üye hatası): kurucudan gelen
            // TAM üyelik listesine eşitle — bkz. `GroupUpdate.members`. Bu
            // olmadan, sonradan eklenen bir üye kendisinden ÖNCE eklenmiş
            // üyeleri hiç öğrenemiyordu (grubu [kurucu, ben] sanıyordu).
            // Eski (members'sız) bir gönderenle uyum için liste boşsa
            // dokunmuyoruz — o durumda eski davranış korunur. (Applied above,
            // before `apply_change`.)
        }
        if matches!(change, GroupChange::AvatarUpdate(_)) {
            self.set_group_avatar_version(&update.group_id, update.new_version);
        }
        // Zinciri her güncellemede benimse (yalnızca onarım anında değil):
        // yetki bize devredilirse SONRAKİ güncellemelerimizi bu zincirle
        // imzalamamız gerekiyor, yoksa devri kaçıran üyeler bizden gelen
        // hiçbir şeyi kabul edemez. Doğrulanamayan girdiler alınmaz.
        // The chain is outside the update signature. Kept: what the walk
        // above verified from our founder on, and this update's own transfer.
        // Every self-signed entry used to be kept: a member forwarding a
        // genuine update filled the chain with transfers of its own at
        // versions near u32::MAX, and no real transfer could heal us again.
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
        // Spec dışı, kullanıcı kararı: kurucunun kefil olduğu üye
        // anahtarlarını benimse — böylece hiç eşleşmediğimiz üyelerle de
        // ratchet kurup mesajlaşabiliriz (bkz. adopt_vouched_member_devices;
        // güvenlik kuralları orada).
        self.adopt_group_update_devices(update, &update.members);
        if !same_version || tie > old_tie {
            self.set_group_tie(&update.group_id, &tie);
        }
        // The founder removed us (see `remove_from_group`'s removal notice):
        // close the group here, exactly like a founder delete.
        let me = self.my_identity_id().unwrap_or_default();
        if matches!(&update.change, GroupChange::Remove(id) if *id == me) && !me.is_empty() {
            info!("Kurucu bizi gruptan çıkardı: {}", update.group_id);
            self.remove_group_locally(&update.group_id);
            return Ok(());
        }
        if let Some(g) = self.groups.get(&update.group_id) {
            self.persist_group(g);
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
        // #77: updates carry only new devices. Missed one (a gap), or a
        // member we hold no device of: ask the founder for the whole state.
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

    /// Bir Identity için bilinen (ve Aşama A'da tek olan) Active cihaz
    /// fingerprint'ini bulur.
    /// Spec dışı, kullanıcı kararı (üyelerin otomatik tanıştırılması):
    /// KURUCU tarafında, verilen üye kimlikleri için kefil olunacak cihaz
    /// kayıtlarını toplar (bkz. `GroupUpdate.member_devices`). Kendi
    /// cihazımız `own_devices`'tan, diğerleri `known_remote_devices`'tan
    /// gelir; bilinmeyen üyeler atlanır (kurucu onları da tanımıyorsa
    /// kefil olamaz).
    pub(crate) fn collect_vouched_member_devices(&self, group_id: &str, member_ids: &[String]) -> Vec<GroupMemberDevice> {
        let own_identity_id = self.identity.as_ref().map(|i| i.identity_id.clone()).unwrap_or_default();
        let mut out = Vec::new();
        for id in member_ids {
            // The identity's first device if we have it (it needs no proof,
            // bkz. `vouch_proofs`), else the smallest fingerprint; `find`
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
                    // Spec dışı, ağ sağlamlığı düzeltmesi ("üç Tor eşli, biri
                    // kurucu/köprü olurken diğer ikisi hem DM hem grup
                    // içinde birbirine hiç ulaşamıyor" hatası): burada ÖNCEDEN
                    // sadece `device_last_addr` (en son işe yarayan HERHANGİ
                    // bir adres — bir LAN/röle bağlantısı görüldüyse bunun
                    // ÜZERİNE yazılmış, Tor-ONLY bir üçüncü tarafa asla
                    // ulaşamayacak bir adres olabilir) kullanılıyordu. Bu,
                    // `try_reconnect_device`'in AYNI kökten (bkz. o fonksiyon
                    // ve `device_onion_addr` alanı dokümantasyonu) zaten
                    // düzeltilmiş sorunuydu — kefalet (vouch) anlık görüntüsü
                    // bu düzeltmeyi hiç görmemişti. Artık asla bir LAN/röle
                    // adresi tarafından üzerine yazılmayan `device_onion_addr`
                    // kullanılır (M-28: `device_last_addr`'a düşülmez).
                    // M-28: onion only — a clearnet/UPnP address must never
                    // travel inside a group update (the node dials onion only).
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

    /// bkz. `GroupUpdate.member_device_proofs`.
    pub(crate) fn vouch_proofs(&self, vouched: &[GroupMemberDevice]) -> Vec<packet::DeviceAddProof> {
        vouched.iter()
            .filter(|d| d.device_fingerprint != d.identity_id)
            .filter_map(|d| self.device_add_proof(&d.device_fingerprint))
            .collect()
    }

    /// Spec dışı, kullanıcı kararı (üyelerin otomatik tanıştırılması):
    /// ALICI tarafında, kurucunun kefil olduğu üye cihazlarını benimser —
    /// böylece daha önce hiç eşleşmediğimiz üyelerle de ratchet kurup
    /// mesajlaşabiliriz (bkz. `GroupUpdate.member_devices`).
    ///
    /// GÜVENLİK KURALLARI (bkz. o alanın notu):
    /// - ZATEN BİLDİĞİMİZ bir cihazın anahtarları ASLA ezilmez (kötü niyetli
    ///   bir kurucu, güvendiğimiz bir kişinin anahtarını değiştiremez).
    /// - `device_fingerprint`, anahtarların SHA3-256'sı olmalı (kendi içinde
    ///   tutarsız kayıtlar reddedilir).
    /// - Kendi kimliğimiz atlanır.
    /// - Eklenen kişiler `verified=false` (grup üzerinden eklendi, yüz yüze
    ///   QR ile doğrulanmadı) — UI bunu gösterir.
    pub(crate) fn adopt_vouched_member_devices(&mut self, devices: &[GroupMemberDevice], proofs: &[packet::DeviceAddProof]) {
        let own_identity_id = self.identity.as_ref().map(|i| i.identity_id.clone()).unwrap_or_default();
        for d in devices {
            if d.identity_id == own_identity_id {
                continue;
            }
            // Engelli birini bir grup kurucusu kefil ederek geri
            // getiremez (bkz. `block_identity`) — engel kişiyi hedefliyor
            // ve yalnızca yüz yüze eşleşmeyle kalkıyor.
            if self.is_blocked(&d.identity_id) {
                warn!("Engelli kimlik grup kefaletiyle eklenmeye çalışıldı, reddedildi: {}", crate::log_id(&d.identity_id));
                continue;
            }
            if self.known_remote_devices.contains_key(&d.device_fingerprint) {
                continue; // zaten biliyoruz — ASLA ezme
            }
            // Fingerprint, anahtarlarla tutarlı mı? (IdentityExchange ile
            // aynı kontrol.)
            if !d.keys_match_fingerprint() {
                error!("Grup üyesi cihaz kaydı tutarsız ({}) — reddedildi", crate::log_id(&d.device_fingerprint));
                continue;
            }
            // Bu kimlik için BAŞKA bir cihazı zaten biliyorsak, kurucunun
            // sözüyle ikinci bir cihaz eklemiyoruz — bu, bilinen bir kişinin
            // yerine geçme (impersonation) denemesi olabilir; spec 2.2
            // "tanınmayan yeni cihaz" akışı QR/IdentityExchange içindir.
            if self.known_remote_devices.values().any(|k| k.identity_id == d.identity_id) {
                info!(
                    "Grup üyesi {} için zaten bilinen bir cihaz var — kefil edilen yeni cihaz eklenmedi",
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
                warn!("Kefil edilen cihaz {} kimliğine bağlanamadı, eklenmedi", crate::log_id(&d.identity_id));
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
            // bkz. `MAX_CONTACTS` — the same no-user-action contact creation as
            // the TOFU path (`evaluate_sender_device`), with the same cap: a
            // founder could flood the contact list with one large
            // `member_devices` list. Checked before the device record is
            // stored, so `remote_devices` stays bounded too.
            let is_new_contact = !self.identity_to_contact.contains_key(&d.identity_id);
            if is_new_contact && self.contacts.len() >= MAX_CONTACTS {
                warn!(
                    "Grup kefaleti reddedildi: contacts tablosu üst sınırda ({} >= {}), identity {} eklenmedi",
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
            // Kişi listesine ekle ve "grup üzerinden eklendi" olarak
            // işaretle (bkz. Contact.added_via_group / güvenlik notu).
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
            // Dial ipucu (varsa) — farklı ağdaki bir üyeye ulaşabilmek için.
            // Only the founder signed it, not the device: kept apart from
            // `device_last_addr`/`device_onion_addr`, whose PeerIds bind a
            // connection to the device (ConnectionEstablished,
            // `record_peer_id_if_known`). As one of those, a founder could
            // make any PeerId "the member" and take our sends to it.
            if let Some(addr) = d.last_addr.as_deref().filter(|a| a.parse::<Multiaddr>().ok().is_some_and(|m| extract_peer_id(&m).is_some())) {
                self.meta_put(&format!("vah:{}", d.device_fingerprint), addr);
            }
            info!(
                "Grup üzerinden yeni kişi eklendi (kurucu kefaletiyle, DOĞRULANMADI): {} / {}",
                crate::log_id(&d.identity_id), crate::log_id(&d.device_fingerprint)
            );
        }
    }

    pub(crate) fn resolve_active_device_for_identity(&self, identity_id: &str) -> Option<String> {
        // Çoklu-cihaz düzeltmesi: KARARLI (deterministik) seçim — `.find()`
        // HashMap iterasyon sırasına bağlıydı, yani bir kimliğin BİRDEN FAZLA
        // aktif cihazı olduğunda her çağrıda FARKLI bir cihaz dönebilirdi.
        // Bu, grup mesajlarının/güncellemelerinin bir üyenin cihazları
        // arasında rastgele "sıçramasına" (bir mesaj bir cihaza, sonraki
        // ötekine → her cihazda EKSİK/tutarsız grup geçmişi) yol açıyordu.
        // Artık en küçük fingerprint'li aktif cihaz (kanonik) seçilir.
        self.known_remote_devices.values()
            .filter(|d| d.identity_id == identity_id && d.is_active)
            .map(|d| d.device_fingerprint.clone())
            .min()
    }

    /// Dönüş: `group_message_local_id` — bu grup mesajının N üyeye giden
    /// fan-out kopyalarını TEK bir yerel kimlikte birleştiren id (bkz.
    /// packet.rs `Text.group_message_local_id` notu). Kotlin, kendi
    /// optimistic balonunu rastgele bir UUID yerine BUNU `messageId`
    /// olarak kullanmalı — aksi halde dönen "seen" bildirimleri hiçbir
    /// yerel balonla eşleşemez.
    /// `reply_to_message_id`/`reply_to_preview`/`reply_to_sender_identity_id`:
    /// bkz. `send_message` AYNI notu — grup karşılığı, ARTI yanıtlanan
    /// mesajın göndericisinin `identity_id`'si (bkz. packet.rs
    /// `reply_to_sender_identity_id` notu — alıcı tarafın "Ahmet'e yanıt"
    /// gösterebilmesi için).
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
                    error!("Grup mesajı yeniden gönderilemedi ({}): {}", crate::log_id(&device), e);
                    self.note_group_copy_failed(&content, &device);
                }
            }
        }
        if sent { Ok(true) } else { Err("No copy could be sent".to_string()) }
    }

    pub(crate) fn send_group_message(&mut self, group_id: &str, plaintext: &str, reply_to_message_id: Option<String>, reply_to_preview: Option<String>, reply_to_sender_identity_id: Option<String>, mentions: Vec<String>) -> Result<String, String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if !group.is_member(&own_identity_id) {
            return Err("Grup üyesi değilsiniz".to_string());
        }
        // Spec 5.1: her üye için ayrı ayrı, mevcut 1:1 ratchet ile şifrele.
        // `group_id: Some(...)` — gerçek grup entegrasyonu: alıcı tarafın
        // bunu sıradan bir 1:1 mesajdan ayırt edip GroupChatActivity'ye
        // yönlendirebilmesi için (bkz. receive_message notu).
        // Starts with our author tag: receivers refuse an id without it.
        let id_rest = format!("-{}", uuid::Uuid::new_v4());
        let local_id = format!("{}{}", hex::encode(group_msg_tag(group_id, &own_identity_id, &id_rest)), id_rest);
        let sent_at_ms = current_time_ms();
        // Kardeş cihaz yankısı için kopyala (aşağıda content'e taşınıyor).
        let echo_reply_id = reply_to_message_id.clone();
        let echo_reply_prev = reply_to_preview.clone();
        let echo_reply_sender = reply_to_sender_identity_id.clone();
        // bkz. packet.rs `MessageContent::Text.sent_at_ms` dokümantasyonu.
        let author_proof = self.sign_group_author(group_id, &local_id, plaintext)?;
        let content = MessageContent::Text {
            group_id: Some(group_id.to_string()),
            text: plaintext.to_string(),
            group_message_local_id: Some(local_id.clone()),
            sent_at_ms,
            reply_to_message_id, reply_to_preview, reply_to_sender_identity_id,
            author_proof: Some(author_proof.clone()),
            mentions: filter_mentions(&group, Some(&own_identity_id), mentions),
        };
        // Spec dışı, hata düzeltmesi (grup geçmişi kalıcılığı): ÖNCE, TEK
        // bir satır olarak arşivle — fan-out döngüsünün İÇİNDE değil,
        // çünkü aşağıdaki `send_message_content` her üye için AYRI
        // çağrılıyor; oraya `archive_plaintext: Some(...)` geçirmek N üye
        // için N ayrı (ve YANLIŞ anahtarlı, bkz. o fonksiyonun eski notu)
        // satır oluştururdu. Kendi mesajımızın arşivi, tek bir üyeye
        // ulaşıp ulaşmadığımızdan bağımsız olmalı — aksi halde fan-out'un
        // İLK üyesi başarısız olursa kendi "gönderdim" kaydımızı hiç
        // tutmazdık.
        let (reply_to_id, reply_to_prev, reply_to_sender) = match &content {
            MessageContent::Text { reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, .. } => {
                (reply_to_message_id.as_deref(), reply_to_preview.as_deref(), reply_to_sender_identity_id.as_deref())
            }
            _ => (None, None, None),
        };
        // Not sent when our own copy cannot be kept (see the 1:1 twin).
        self.archive_group_message(group_id, &own_identity_id, "sent", plaintext.as_bytes(), Some(&local_id), reply_to_id, reply_to_prev, reply_to_sender, sent_at_ms, Some(&author_proof))
            .map_err(|e| format!("Mesaj kaydedilemedi: {}", e))?;
        for member_identity_id in group.other_members(&own_identity_id) {
            self.send_group_message_to_member(group_id, &member_identity_id, &content);
        }
        // Çoklu-cihaz (spec 1.7): kardeş cihazlarıma yankıla — grup mesajım
        // onlarda da görünsün (kendi mesajım fan-out'a dahil değildir, bu
        // yüzden yankı çift kayda yol açmaz).
        self.echo_group_to_siblings(group_id, SiblingEchoBody::Text {
            message_id: local_id.clone(), text: plaintext.to_string(), sent_at_ms,
            reply_to_message_id: echo_reply_id, reply_to_preview: echo_reply_prev,
            reply_to_sender_identity_id: echo_reply_sender,
        });
        Ok(local_id)
    }
}
