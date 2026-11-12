//! Device fan-out, device auth signatures, device linking and device notices.

use super::*;

impl P2PCore {

    /// The user deleted this contact on THIS device (`delete_contact`). A
    /// sibling that still has it must not bring it back with its next sync
    /// (`import_sync_payload`), and its own IdentityExchange must not either
    /// (`evaluate_sender_device`); scanning or typing its code again clears
    /// the mark (`pair_with_code`).
    /// ponytail: local mark only, the delete is not sent to siblings. Add a
    /// sync message if contacts must disappear on every device.
    /// Same mark for a group the user left or deleted here.
    pub(crate) fn group_removed_locally(&self, group_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row("SELECT 1 FROM removed_groups WHERE group_id = ?1", params![group_id], |_| Ok(())).is_ok()
        })
    }

    pub(crate) fn contact_removed_locally(&self, identity_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row("SELECT 1 FROM removed_contacts WHERE identity_id = ?1", params![identity_id], |_| Ok(())).is_ok()
        })
    }

    // ===============================================================
    // Çoklu-cihaz (Description.md §1.5 cihaz ekleme, §1.6 iptal, §1.7
    // senkron). Tasarım: ikinci cihaz KENDİ anahtar çiftini üretir (kendi
    // device_fingerprint'i) ve birincil cihazın kimliğini (identity_id)
    // BENİMSER — birincilin uzun-vadeli secret anahtarı asla cihaz 1'den
    // çıkmaz; ikincil cihaz, birincilin İMZALADIĞI bir `DeviceAdd` ile
    // yetkilendirilir. Eşleşmeden sonra iki cihaz birbirinden bağımsızdır:
    // kişiler her iki cihaza da ayrı ayrı fan-out ile mesaj gönderir.
    // ===============================================================

    pub(crate) fn my_identity_id(&self) -> Option<String> {
        self.identity.as_ref().map(|i| i.identity_id.clone())
    }

    /// Bir device_fingerprint için, aynı kimliğe ait KARARLI (deterministik)
    /// "kanonik" sohbet anahtarı — bir kişinin birden fazla cihazı olsa bile
    /// yerel sohbet/arşiv TEK bir anahtar altında birleşsin diye. Kişinin
    /// bilinen aktif cihazları arasından `(first_seen, fingerprint)`'e göre
    /// en küçüğü seçilir (HashMap iterasyon sırasından bağımsız). Kişi
    /// bilinmiyorsa (kardeş cihaz/grup) fingerprint aynen döner.
    pub(crate) fn canonical_peer_key(&self, sender_fp: &str) -> String {
        let identity_id = match self.known_remote_devices.get(sender_fp) {
            Some(d) => d.identity_id.clone(),
            None => return sender_fp.to_string(),
        };
        self.canonical_device_for_identity(&identity_id).unwrap_or_else(|| sender_fp.to_string())
    }

    /// Bir kimliğin kanonik (deterministik) cihazı — bkz. `canonical_peer_key`.
    /// ContactSummary.active_device_fingerprint ve gelen mesaj arşivi AYNI
    /// değeri kullanmalı, aksi halde çoklu-cihazlı bir kişinin geçmişi
    /// bölünür.
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
        // Kişi kaydı yoksa known_remote_devices'a düş.
        let mut actives: Vec<&DeviceRecord> = self.known_remote_devices.values()
            .filter(|d| d.identity_id == identity_id && d.is_active)
            .collect();
        actives.sort_by(|a, b| a.device_fingerprint.cmp(&b.device_fingerprint));
        actives.first().map(|d| d.device_fingerprint.clone())
    }

    /// Bir kimliğin, mesaj fan-out edilecek TÜM aktif cihazları (spec 1.7.1
    /// pairwise). Sadece PUBLIC anahtarları bilinen (known_remote_devices)
    /// cihazlar döner — bir DeviceAdd ile duyurulmuş ama henüz
    /// IdentityExchange'i gelmemiş cihaz, anahtarı olmadığından burada YER
    /// ALMAZ (o cihaza şifreleme yapılamaz; IdentityExchange gelince eklenir).
    pub(crate) fn active_devices_for_identity(&self, identity_id: &str) -> Vec<String> {
        let mut v: Vec<String> = self.known_remote_devices.values()
            .filter(|d| d.identity_id == identity_id && d.is_active)
            .map(|d| d.device_fingerprint.clone())
            .collect();
        v.sort();
        v
    }

    /// 1:1 gönderim fan-out hedefleri: `primary_fp`'nin kimliğinin TÜM aktif
    /// cihazları (`primary_fp` dahil). Kimlik bilinmiyorsa yalnızca
    /// `primary_fp` (mevcut davranış — tek cihaz).
    ///
    /// A device unseen for `STALE_PEER_RETRY_HORIZON_MS` is left out, like
    /// `sibling_active_devices` does: a contact's abandoned old phone made
    /// every message (and call invite) also go to its server mailbox, which
    /// filled to the 5000-item cap (seen 2026-09-26). If that leaves nobody,
    /// every active device is kept.
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
    /// that would stamp them again (fable D-01).
    pub(crate) fn device_recently_seen(&self, fp: &str) -> bool {
        self.known_remote_devices.get(fp).map_or(true, |d| {
            d.last_seen == 0 || current_time_ms().saturating_sub(d.last_seen) < STALE_PEER_RETRY_HORIZON_MS
        }) || self.is_connected_to_device(fp)
    }

    /// Kendi kimliğimin, BU cihaz DIŞINDAKİ aktif kardeş cihazları — senkron
    /// (DeviceSync/DeviceRevokeNotice) buralara gönderilir.
    pub(crate) fn sibling_active_devices(&self) -> Vec<String> {
        let my_id = match self.my_identity_id() { Some(id) => id, None => return Vec::new() };
        let own_fp = self.get_active_own_device_fingerprint().ok();
        // bkz. `STALE_PEER_RETRY_HORIZON_MS` dokümantasyonu — uzun süredir
        // görülmemiş bir kardeş, artık her mesajda yeni bir kalıcı yeniden
        // deneme kaydı biriktirmesin diye buradan (yalnızca YENİ fan-out'tan)
        // çıkarılır.
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

    /// İmzalanacak kanonik bayt dizisi (DeviceAdd/DeviceRevoke).
    ///
    /// A revoke carries a tag. Without one the two signed the same bytes, so
    /// the DeviceAdd a secondary shows to everybody (in each plaintext
    /// IdentityExchange) was also a valid DeviceRevoke of that secondary:
    /// any contact could send it back and wipe the device.
    ///
    /// L-36 (2026-10-21): domain tag + length-framed fields (NUL joins were
    /// ambiguous). Every DeviceAdd/DeviceRevoke signed before this no longer
    /// verifies: devices must be re-linked.
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
        // bkz. `verify_device_auth`: nobody accepts another signer.
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
        // bkz. `verify_device_auth`: nobody accepts another signer.
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

    /// DeviceAdd/DeviceRevoke imzasını, o kimliğe ait BİLİNEN AKTİF bir
    /// cihazın (actor) anahtarıyla doğrular. actor, own_devices veya
    /// known_remote_devices'ta olabilir; kimliği eşleşmeli ve aktif olmalı.
    pub(crate) fn verify_device_auth(&self, identity_id: &str, subject_fp: &str, actor_fp: &str, sig: &[u8], sig_pq: &[u8], revoke: bool) -> Result<(), String> {
        let actor = self.own_devices.get(actor_fp)
            .or_else(|| self.known_remote_devices.get(actor_fp))
            .cloned()
            .ok_or("İmzalayan (actor) cihaz bilinmiyor")?;
        if actor.identity_id != identity_id {
            return Err("İmzalayan cihaz bu kimliğe ait değil".to_string());
        }
        if !actor.is_active {
            return Err("İmzalayan cihaz iptal edilmiş".to_string());
        }
        // Only the identity's first device (fingerprint == identity id) adds
        // and revokes. Any active device could: a stolen secondary revoked the
        // primary and the siblings (they wiped themselves) and added devices
        // that outlived its own revocation. The first device is never revoked.
        if actor_fp != identity_id {
            return Err("Cihaz ekleme/iptal yalnız kimliğin ana cihazı tarafından imzalanabilir".to_string());
        }
        if revoke && subject_fp == identity_id {
            return Err("Ana cihaz iptal edilemez".to_string());
        }
        // A root revokes only its own devices: the signature proves who
        // signed, not that the subject is theirs.
        let subject_owner = self.own_devices.get(subject_fp)
            .or_else(|| self.known_remote_devices.get(subject_fp))
            .map(|d| d.identity_id.as_str())
            .or_else(|| self.verified_device_adds.get(subject_fp).map(|s| s.as_str()));
        if revoke && subject_owner.map_or(false, |owner| owner != identity_id) {
            return Err("İptal edilen cihaz bu kimliğe ait değil".to_string());
        }
        let msg = Self::device_auth_signing_bytes(identity_id, subject_fp, actor_fp, revoke);
        verify_hybrid_signature(&msg, sig, sig_pq, &actor)
    }

    /// İkinci (yeni) cihazın gösterdiği "cihaz ekleme QR'ı" (spec 1.5 adım 2).
    /// Bu cihaz zaten normal onboarding'den geçmiş (createIdentity ile
    /// provizyonel bir kimlik üretmiş) ve ağı başlatmış olmalıdır.
    pub(crate) fn build_device_link_request(&mut self) -> Result<Vec<u8>, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let rec = self.own_devices.get(&own_fp).ok_or("Missing own device record")?.clone();
        let rendezvous = self.get_node_address().ok_or("Ağ adresi henüz hazır değil")?;
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
            // bkz. `first_contact_secrets`: the first device answers to the
            // mailbox made from this nonce.
            self.server_sweep_at = 0;
        }
        // bkz. packet.rs DeviceLinkRequest dokümantasyonu — fingerprint-only
        // (public key'ler artık taşınmaz, QR kapasitesini aşıyordu).
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

    /// Birincil (onaylı) cihaz, ikincil cihazın (fingerprint-only, bkz.
    /// packet.rs DeviceLinkRequest dokümantasyonu) QR'ını okuyunca çağrılır
    /// (spec 1.5 adım 3-5). Burada SADECE bağlanılır ve `pending_link_target`
    /// işaretlenip kendi `IdentityExchange`'imiz gönderilir — yeni cihazın
    /// GERÇEK public key'leri (dolayısıyla fingerprint doğrulaması, imzalı
    /// DeviceAdd, DeviceLinkGrant/tam senkron ve kişilere duyuru) karşı
    /// taraftan gelen KARŞILIKLI `IdentityExchange` işlenince
    /// `process_identity_exchange`'in `is_pending_link` kolunda tamamlanır
    /// (bkz. orada). `process_qr_packet`'teki "eşleşme WIP" notuyla AYNI
    /// gerekçeyle bu fonksiyon o el sıkışmayı BEKLEMEDEN döner.
    pub(crate) fn approve_device_link(&mut self, request_cbor: &[u8]) -> Result<(String, String), String> {
        let req = DeviceLinkRequest::from_cbor(request_cbor)?;
        if req.nonce.len() != 16 {
            return Err("Geçersiz cihaz bağlama kodu (nonce)".to_string());
        }
        if !is_fingerprint_hex(&req.device_fingerprint) {
            return Err("Geçersiz cihaz kodu".to_string());
        }
        let my_id = self.my_identity_id().ok_or("Önce bir kimlik oluşturun")?;
        let own_fp = self.get_active_own_device_fingerprint()?;
        // Before any side effect (fable D-09): on a secondary the link can
        // never complete (`sign_device_add` refuses), and both devices waited
        // an hour with no error shown.
        if own_fp != my_id {
            return Err("Only the primary device can do this".to_string());
        }
        if req.device_fingerprint == own_fp {
            return Err("Bu zaten bu cihaz".to_string());
        }
        // Aktif cihaz sınırı (spec 1.1 — max 5). Not `sibling_active_devices`:
        // that leaves out siblings not seen for a week, which are still active.
        let active_count = 1 + self.known_remote_devices.values()
            .filter(|d| d.identity_id == my_id && d.is_active && d.device_fingerprint != own_fp)
            .count();
        if active_count >= identity::MAX_ACTIVE_DEVICES {
            return Err(format!("En fazla {} aktif cihaz olabilir", identity::MAX_ACTIVE_DEVICES));
        }
        let new_fp = req.device_fingerprint.clone();

        // The device may have been paired as a contact first, under the
        // identity it had before the link (its own fingerprint). That contact
        // would stay as a ghost whose only device is now a sibling. A device
        // of any other contact is not ours to link.
        // Every contact listing it (H76: only the first one was looked at).
        // The ghost is deleted only once the device consents (see the
        // `is_pending_link` arm of `process_identity_exchange`): scanning the
        // wrong QR must not cost a contact.
        let foreign = self.contacts.values()
            .filter(|c| c.find_device(&new_fp).is_some())
            .any(|c| c.trusted_identity_id != new_fp || self.contact_fingerprints_all(c).iter().any(|f| *f != new_fp));
        if foreign {
            return Err("Bu cihaz kişilerinizden birine ait".to_string());
        }

        self.dial_pairing_addr(&new_fp, &req.rendezvous_node, &req.known_relays);

        // pending_link_target: process_identity_exchange, bu fingerprint'ten
        // gelecek bir sonraki IdentityExchange'i kişi olarak DEĞİL kardeş
        // cihaz olarak işlesin ve bağlanma akışını (DeviceAdd/DeviceLinkGrant/
        // duyuru) orada tamamlasın. bkz. `PENDING_LINK_RETRY_HORIZON_MS` —
        // ufuk bu andan itibaren işler (QR yeniden okutulursa tazelenir).
        self.set_pending_link(Some(new_fp.clone()));
        // Goes back in the grant: it proves that grant answers this QR.
        self.pending_link_nonce = req.nonce.clone();
        self.meta_put("pending_link_nonce", &hex::encode(&req.nonce));
        // Kept after the link: bkz. `first_contact_secrets`.
        if req.nonce.len() == 16 {
            self.put_pairing_secret("pn", &new_fp, &req.nonce);
            self.server_sweep_at = 0;
        }
        // Fresh: after a failed link or an unlink, the identical packet of the
        // earlier attempt still counted as deposited and was not sent.
        if let Err(e) = self.send_identity_exchange_fresh(&new_fp) {
            error!("IdentityExchange gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
        }

        Ok((new_fp, sanitize_display_name(&req.device_name).unwrap_or_default()))
    }

    /// Bir `DeviceRecord`'dan `SyncedDevice` üretir (senkron/duyuru için).
    pub(crate) fn synced_device_from_record(&self, rec: &DeviceRecord) -> SyncedDevice {
        SyncedDevice {
            device_fingerprint: rec.device_fingerprint.clone(),
            device_name: rec.device_name.clone(),
            sign_pubkey_ed25519: rec.sign_pubkey_ed25519.clone(),
            sign_pubkey_mldsa: rec.sign_pubkey_mldsa.clone(),
            kem_pubkey_x25519: rec.kem_pubkey_x25519.clone(),
            kem_pubkey_mlkem: rec.kem_pubkey_mlkem.clone(),
            is_active: rec.is_active,
            // M-28: onion only — never republish a clearnet/UPnP address.
            last_addr: self.device_onion_addr.get(&rec.device_fingerprint).cloned(),
            // Only `synced_for_sibling` fills it: this record also travels
            // unsealed (`IdentityExchange.device_add_signer`) and to contacts.
            mailbox_secrets: Vec::new(),
        }
    }

    /// `synced_device_from_record` for a `SyncPayload`: with the secrets of
    /// the device's first-contact mailbox (bkz. `SyncedDevice.mailbox_secrets`).
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

    /// BU cihazın kendi `SyncedDevice`'ı — kişilere `DeviceAddNotice` ile
    /// gönderilir (anahtarlarımızı güvenilir biçimde öğrensinler).
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

    /// İkincil cihaz benimsemesi (spec 1.5 adım 6). Dönüş: `true` = ilk kez
    /// benimsendi (UI bilgilendirilmeli), `false` = zaten benimsenmiş (yalnız
    /// Ack, tekrar duyuru yapma).
    pub(crate) fn adopt_device_link(&mut self, primary_fp: &str, identity_id: &str, device_add: &DeviceAdd, sync: &SyncPayload, nonce: &[u8]) -> Result<bool, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        if device_add.identity_id != identity_id
            || device_add.new_device_fingerprint != own_fp
            || device_add.added_by != primary_fp {
            return Err("DeviceLinkGrant alanları tutarsız".to_string());
        }
        // İmzayı birincil cihazın anahtarıyla doğrula (anahtarları eşleşme
        // sırasında gelen IdentityExchange'ten biliyoruz).
        self.verify_device_auth(identity_id, &own_fp, primary_fp, &device_add.signature, &device_add.signature_pq, false)?;
        // Our own half, given to the device that read our code: without it
        // nobody else accepts this add.
        let own_rec = self.own_devices.get(&own_fp).ok_or("Missing own device record")?;
        if !Self::add_has_consent(device_add, &own_rec.sign_pubkey_ed25519, &own_rec.sign_pubkey_mldsa) {
            return Err("DeviceLinkGrant reddedildi: bu cihazın onay imzası yok".to_string());
        }

        // Zaten benimsenmişse: idempotent — sadece senkronu birleştir.
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
            return Err("DeviceLinkGrant reddedildi: bu cihazın kendi kişileri var, başka bir kimliğe bağlanamaz".to_string());
        }
        if current_time_ms() > self.link_request_open_until {
            return Err("İstenmemiş DeviceLinkGrant: bu cihaz bağlama QR'ı göstermiyor".to_string());
        }
        // The nonce is in the QR only: a grant without it comes from a device
        // that did not scan the code this device is showing.
        if self.link_request_nonce.len() != 16 || nonce != self.link_request_nonce.as_slice() {
            return Err("DeviceLinkGrant reddedildi: QR'daki nonce ile eşleşmiyor".to_string());
        }
        let old_id = self.my_identity_id().unwrap_or_default();
        // Eşleşme sırasında birincil, geçici olarak bir KİŞİ olarak
        // kaydedilmiş olabilir — kaldır (o artık bir kardeş cihaz).
        let primary_cid = self.identity_to_contact.get(identity_id).cloned();
        // Disk FIRST, in one transaction: identities (yeni id) + own_devices
        // (yeni identity_id) + the primary's contact row. On failure nothing
        // changed, in memory or on disk, and the link window stays open: the
        // primary must not believe in a link this device forgets on restart.
        if let Some(conn) = self.db.as_ref() {
            let tx = conn.unchecked_transaction().map_err(|e| format!("Kimlik değişimi diske yazılamadı: {}", e))?;
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
                .map_err(|e| format!("Kimlik değişimi diske yazılamadı: {}", e))?;
        }
        self.set_link_request_open_until(0);
        // Belleği güncelle.
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
        // Birincil cihazın kaydını (kardeş) kimliğime bağla.
        if let Some(rec) = self.known_remote_devices.get_mut(primary_fp) {
            rec.identity_id = identity_id.to_string();
            rec.is_active = true;
            let rec2 = rec.clone();
            self.persist_remote_device(&rec2);
        }
        self.own_device_add = Some(device_add.clone());
        self.persist_own_device_add(device_add);

        // Kişileri/grupları/kardeşleri içe aktar, sonra herkese kendini tanıt.
        self.import_sync_payload(sync);
        self.announce_self_to_all_contacts();
        // Öğrendiğim kardeş cihazlar da beni ve birbirlerini bilsin (3+ cihaz).
        self.sync_to_siblings();
        info!("Bu cihaz {} kimliğine ikincil cihaz olarak bağlandı", crate::log_id(&identity_id));
        Ok(true)
    }

    pub(crate) fn apply_device_add_notice(&mut self, device_add: &DeviceAdd, device: &SyncedDevice, sender_identity_id: &str) -> Result<(), String> {
        self.verify_device_auth(
            &device_add.identity_id, &device_add.new_device_fingerprint, &device_add.added_by,
            &device_add.signature, &device_add.signature_pq, false,
        )?;
        if self.owner_revoked(&device_add.identity_id, &device_add.new_device_fingerprint) {
            return Err("DeviceAddNotice: cihaz sahibi tarafından iptal edilmiş".to_string());
        }
        // Taşınan anahtarlar, iddia edilen fingerprint ile tutarlı mı?
        if device.device_fingerprint != device_add.new_device_fingerprint {
            return Err("DeviceAddNotice: cihaz fingerprint'i DeviceAdd ile uyuşmuyor".to_string());
        }
        if !device.keys_match_fingerprint() {
            return Err("DeviceAddNotice: anahtarlar fingerprint ile tutarsız".to_string());
        }
        if !Self::add_has_consent(device_add, &device.sign_pubkey_ed25519, &device.sign_pubkey_mldsa) {
            return Err("DeviceAddNotice: eklenen cihazın onay imzası yok".to_string());
        }
        // Güvenlik/DoS: bir kişi (kimlik) SINIRSIZ cihaz iddia edip bizim ona
        // her mesajı N kez fan-out etmemize yol açamamalı. Zaten bu cihazı
        // biliyorsak (idempotent tekrar) geç; YENİ bir cihazsa ve o kimlik
        // için aktif cihaz sayısı üst sınırdaysa reddet (spec 1.1 — max 5).
        // A device we already hold under another identity, or as revoked, is not
        // moved or revived by a notice. (The DeviceAdd is signed by the CLAIMED
        // identity, so anyone could claim a third party's device this way.)
        // A real move comes with the device's own IdentityExchange.
        if let Some(rec) = self.known_remote_devices.get(&device.device_fingerprint) {
            if rec.identity_id != device_add.identity_id || !rec.is_active {
                return Err("DeviceAddNotice: cihaz başka bir kimlik altında ya da iptal edilmiş olarak kayıtlı".to_string());
            }
        }
        let already_known = self.known_remote_devices.contains_key(&device.device_fingerprint);
        if !already_known {
            let active_for_identity = self.known_remote_devices.values()
                .filter(|d| d.identity_id == device_add.identity_id && d.is_active)
                .count();
            if active_for_identity >= identity::MAX_ACTIVE_DEVICES {
                return Err(format!(
                    "DeviceAddNotice reddedildi: {} için aktif cihaz üst sınırı ({})",
                    device_add.identity_id, identity::MAX_ACTIVE_DEVICES
                ));
            }
            // Revoked records are kept for good (they stop a revival): a
            // contact cycling add+revoke must not grow them without end.
            let all_for_identity = self.known_remote_devices.values()
                .filter(|d| d.identity_id == device_add.identity_id)
                .count();
            if all_for_identity >= 4 * identity::MAX_ACTIVE_DEVICES {
                return Err(format!("DeviceAddNotice reddedildi: {} için cihaz kaydı üst sınırı", device_add.identity_id));
            }
        }
        let now = current_time_ms();
        self.verified_device_adds.insert(device_add.new_device_fingerprint.clone(), device_add.identity_id.clone());
        self.remember_device_add(device_add);
        // Anahtarları HEMEN known_remote_devices'a yaz — böylece bu cihaza
        // ayrı bir IdentityExchange beklemeden fan-out yapılabilir.
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
        // Kişinin bilinen cihaz listesine ekle (spec 2.2 NewDeviceViaSignedAdd).
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

    /// Dönüş: `true` ise bu, BU cihazın KENDİ iptaliydi (yerel durum tamamen
    /// silindi — çağıran `self_revoked` olayı üretmeli); `false` ise sıradan
    /// (başka bir kimliğe/cihaza ait) bir iptal.
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
                return Err("Kendi iptalimiz kardeş olmayan bir cihazdan geldi".to_string());
            }
            warn!(
                "BU CİHAZ kendi kimliği ({}) tarafından iptal edildi (revoked_by={}) — tüm yerel durum siliniyor",
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
            // L-22: no contact to hold the tombstone (a group member): its old
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
