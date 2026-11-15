//! Recovery file export/import.

use super::*;

impl P2PCore {

    // ---------------------------------------------------------------
    // Recovery file. The basic version is in place. Full SyncPayload and multi-device integration are the next step.
    // ---------------------------------------------------------------

    #[cfg(test)]
    pub(crate) fn export_recovery(&self, passphrase: String) -> Result<Vec<u8>, String> {
        let (plaintext, passphrase) = self.recovery_plaintext(passphrase, None)?;
        seal_recovery_file(&plaintext, &passphrase)
    }

    /// the part of `export_recovery` that needs the core. The Argon2
    /// step (`seal_recovery_file`) does not, a caller can run it unlocked.
    /// `chats`: from `recovery_chats_unlocked` (the lock taken per chat), or
    /// `None` to read them here.
    pub(crate) fn recovery_plaintext(&self, passphrase: String, chats: Option<Vec<RecoveryChat>>) -> Result<(zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<String>), String> {
        // JNI turns a null or unreadable string into "": the file with every
        // long-term key would be written under the empty passphrase.
        let passphrase = zeroize::Zeroizing::new(passphrase);
        if passphrase.is_empty() {
            return Err("Parola boş olamaz".to_string());
        }
        // Every long-term key is in the file: a short passphrase is guessed
        // offline. Import takes any passphrase, older files have shorter ones.
        // UTF-16 units, as the Android check counts them.
        if passphrase.encode_utf16().count() < RECOVERY_PASSPHRASE_MIN_CHARS {
            return Err("Parola en az 12 karakter olmalı".to_string());
        }
        let identity = self.identity.as_ref().ok_or("No identity to export")?;

        #[derive(Serialize)]
        struct ExportedDevice {
            device_fingerprint: String,
            sign_sk_ed25519: Vec<u8>,
            sign_sk_mldsa: Vec<u8>,
            kem_sk_x25519: Vec<u8>,
            kem_sk_mlkem: Vec<u8>,
        }
        // The long-term secret keys are wiped when the export is done
        //like `SecretKeyBundle`.
        impl Drop for ExportedDevice {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                self.sign_sk_ed25519.zeroize();
                self.sign_sk_mldsa.zeroize();
                self.kem_sk_x25519.zeroize();
                self.kem_sk_mlkem.zeroize();
            }
        }
        #[derive(Serialize)]
        struct ExportedIdentity {
            identity_id: String,
            devices: Vec<ExportedDevice>,
            /// Root archive key (ARK). Without it, a device restored from the recovery file cannot DECRYPT its history on the server.
            /// The identity and contacts come back, but the archive would remain an unreadable blob. `Option`: if the server was never used, there is no ARK.
            archive_root_key: Option<Vec<u8>>,
            /// Contacts, groups and every chat (`RecoveryData`), CBOR.
            #[serde(with = "serde_bytes")]
            data: Vec<u8>,
            /// A secondary's signed add: without it the restored device's
            /// IdentityExchange (fingerprint != identity id) is refused by every peer.
            own_device_add: Option<DeviceAdd>,
            /// Revokes this identity issued, or a contact that never saw one
            /// takes the revoked device back from an old DeviceAdd.
            own_revokes: Vec<DeviceRevoke>,
        }

        let mut devices: Vec<ExportedDevice> = self.own_devices.values()
            .filter(|d| d.identity_id == identity.identity_id)
            .filter_map(|d| self.own_device_keys.get(&d.device_fingerprint).map(|k| ExportedDevice {
                device_fingerprint: d.device_fingerprint.clone(),
                sign_sk_ed25519: k.sign_sk_ed25519.to_bytes().to_vec(),
                sign_sk_mldsa: k.sign_sk_mldsa.to_bytes().to_vec(),
                kem_sk_x25519: k.kem_sk_x25519.to_bytes().to_vec(),
                kem_sk_mlkem: mlkem_dk_to_bytes(&k.kem_sk_mlkem),
            }))
            .collect();
        // Primary first: import takes the first device (see `import_recovery`).
        devices.sort_by_key(|d| Some(&d.device_fingerprint) != identity.primary_device.as_ref());

        // Over the import cap the file would be written and never open again:
        // then only the newest messages go in. 1 MiB is left for the keys.
        let mut data = match chats {
            Some(chats) => RecoveryData { sync: self.build_sync_payload(), chats },
            None => self.recovery_data(),
        };
        let mut data_bytes = ciborium_bytes(&data)?;
        if data_bytes.len() > MAX_RECOVERY_FILE_BYTES - 1024 * 1024 {
            data.keep_newest(RECOVERY_TRIMMED_MESSAGES);
            data_bytes = ciborium_bytes(&data)?;
            warn!("Kurtarma dosyası sınırı aşıyor, yalnızca en yeni {} mesaj eklendi", RECOVERY_TRIMMED_MESSAGES);
        }
        drop(data);
        // CBOR: as JSON every byte was a number, and a few thousand messages
        // made a file of several MB.
        let plaintext = zeroize::Zeroizing::new(ciborium_bytes(&ExportedIdentity {
            identity_id: identity.identity_id.clone(),
            devices,
            archive_root_key: self.archive_root_key_bytes(),
            data: data_bytes,
            own_device_add: self.own_device_add.clone(),
            own_revokes: self.own_revokes(),
        })?);
        Ok((plaintext, passphrase))
    }
}

/// Encrypts a recovery plaintext under the passphrase (Argon2id + ChaCha20-
/// Poly1305). No core state: run it without the core lock.
pub(crate) fn seal_recovery_file(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    let rng = ring::rand::SystemRandom::new();
    use ring::rand::SecureRandom;
    let mut salt = [0u8; 16];
    rng.fill(&mut salt).map_err(|_| "RNG failed")?;
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| "RNG failed")?;

    // Passphrase-based key derivation is now Argon2id (memory-hard). It used to be HKDF-SHA256, a single HMAC. This file holds every long-term
    // secret key, so with HKDF a weak passphrase could be brute-forced offline in seconds. The parameters are stored in the file, so a future
    // import can re-derive the same key (the format describes itself and does not depend on fixed parameters).
    // 64 MiB (OWASP baseline is 19 MiB): the file holds every long-term secret key and only an empty
    // passphrase is refused, so the cost per guess is the whole defence.
    let (m_cost, t_cost, p_cost) = (65_536u32, 2u32, 1u32);
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| format!("Argon2 params: {e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon.hash_password_into(passphrase.as_bytes(), &salt, &mut key[..])
        .map_err(|e| format!("Argon2 hash: {e}"))?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| "Invalid key")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| "Encryption failed")?;

    let file = ciborium_bytes(&RecoveryFile {
        kdf: "argon2id".to_string(),
        argon2_m_cost: m_cost,
        argon2_t_cost: t_cost,
        argon2_p_cost: p_cost,
        ciphertext,
        nonce: nonce_bytes.to_vec(),
        salt: salt.to_vec(),
    })?;
    // Still over (the newest messages alone are that large): no file that
    // looks saved and cannot be imported.
    if file.len() > MAX_RECOVERY_FILE_BYTES {
        return Err("Kurtarma dosyası 64 MB sınırını aşıyor".to_string());
    }
    Ok(file)
}

/// Argon2id + decrypt of a recovery file. No core state: run it
/// without the core lock (between `import_recovery_precheck` and
/// `import_recovery_plaintext`).
pub(crate) fn open_recovery_file(file_bytes: &[u8], passphrase: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    // `export_recovery` writes no such file.
    if passphrase.is_empty() {
        return Err("Parola boş olamaz".to_string());
    }

    // The export cap is the import cap: a bigger file is no file of ours.
    if file_bytes.len() > MAX_RECOVERY_FILE_BYTES {
        return Err("Kurtarma dosyası çok büyük".to_string());
    }
    let file: RecoveryFile = ciborium::from_reader(file_bytes).map_err(|_| "Bozuk kurtarma dosyası".to_string())?;
    if file.kdf != "argon2id" {
        return Err(format!("Desteklenmeyen anahtar türetme algoritması: {}", file.kdf));
    }

    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    // The parameters come from the file. Unchecked, a damaged or crafted
    // file asked for gigabytes of memory (the app is killed) or hours of
    // work, before the passphrase is even tested. `seal_recovery_file`
    // writes m=64 MiB, t=2, p=1.
    // also a total-work bound (4x what `export_recovery` writes), or
    // 256 MiB x 10 passes froze the import screen for minutes.
    if file.argon2_m_cost > MAX_RECOVERY_ARGON2_M_COST_KIB || file.argon2_t_cost > 10 || file.argon2_p_cost > 4
        || file.argon2_m_cost as u64 * file.argon2_t_cost as u64 > 4 * 65_536 * 2
    {
        return Err("Bozuk kurtarma dosyası (Argon2 parametreleri sınır dışı)".to_string());
    }
    if file.salt.len() != 16 {
        return Err("Bozuk kurtarma dosyası (salt)".to_string());
    }
    let params = argon2::Params::new(file.argon2_m_cost, file.argon2_t_cost, file.argon2_p_cost, Some(32))
        .map_err(|e| format!("Argon2 params: {e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon.hash_password_into(passphrase.as_bytes(), &file.salt, &mut key[..])
        .map_err(|e| format!("Argon2 hash: {e}"))?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| "Invalid key")?;
    if file.nonce.len() != 12 {
        return Err("Bozuk kurtarma dosyası (nonce)".to_string());
    }
    let nonce = Nonce::from_slice(&file.nonce);
    let plaintext = zeroize::Zeroizing::new(cipher.decrypt(nonce, file.ciphertext.as_slice())
        .map_err(|_| "Yanlış parola veya bozuk dosya".to_string())?);
    Ok(plaintext)
}

impl P2PCore {

    /// The counterpart of `export_recovery`. Before it existed there was no such function. The file format describes itself for this purpose:
    /// KDF, Argon2 parameters, salt and nonce are stored in the file, not assumed as constants. It is called on a new or reset device (with NO
    /// identity yet). Instead of generating random keys, `create_identity` restores the SAME keys deterministically from this file.
    /// The Kotlin side then continues exactly as with `createIdentity`: it fetches `secret_bundle_bytes` from the return value via
    /// `getPendingSecretBundle`, encrypts it with the Keystore, and writes it to disk (see `IdentityManager.persistNewIdentity`, the same call and flow).
    ///
    /// `device_name` is NOT in the file (`export_recovery`'s `ExportedDevice` carries only the secret keys). So the import asks the user for a new
    /// name at that moment (the same pattern as Kotlin `ImportRecoveryActivity` / `showDeviceNameDialog`). All public keys EXCEPT ML-KEM can be
    /// derived deterministically from the secret (Ed25519 / ML-DSA / X25519, the same derivation as `generate_identity`). ML-KEM's
    /// `encapsulation_key()` also derives the public key (encapsulation key) directly from the secret (decapsulation key). So the file never
    /// needs to carry a public key: the `export_recovery` output already contained only secrets.
    #[cfg(test)]
    pub(crate) fn import_recovery(&mut self, file_bytes: &[u8], passphrase: &str, device_name: String) -> Result<(String, Vec<u8>), String> {
        self.import_recovery_precheck()?;
        let plaintext = open_recovery_file(file_bytes, passphrase)?;
        self.import_recovery_plaintext(&plaintext, device_name)
    }

    /// the cheap check, under the core lock.
    pub(crate) fn import_recovery_precheck(&self) -> Result<(), String> {
        // Refuses to overwrite a WORKING identity (one whose secret keys are in memory). This is NOT `self.identity.is_some()`: in the
        // "identity_secret.enc lost or corrupt" case (see the comment in MainActivity), `initDatabase` already loads the PUBLIC keys from the DB and
        // fills `self.identity`, but the secret keys (`own_device_keys`) stay empty. That is exactly the state this function must recover from.
        if self.get_active_own_device_fingerprint().is_ok() {
            return Err("Bu cihazda zaten çalışan bir kimlik var — önce Ayarlar'dan çıkış yapın".to_string());
        }
        Ok(())
    }

    pub(crate) fn import_recovery_plaintext(&mut self, plaintext: &[u8], device_name: String) -> Result<(String, Vec<u8>), String> {
        // Again: the lock may have been released since the precheck.
        self.import_recovery_precheck()?;

        #[derive(Deserialize)]
        struct ExportedIdentity {
            identity_id: String,
            devices: Vec<SecretKeyBundle>,
            /// See `export_recovery`. `#[serde(default)]`: recovery files made BEFORE this field existed must still be importable.
            #[serde(default)]
            archive_root_key: Option<Vec<u8>>,
            #[serde(default, with = "serde_bytes")]
            data: Vec<u8>,
            // Required: a file from before these fields restored a secondary
            // that no peer accepts (owner: old backups are not supported).
            own_device_add: Option<DeviceAdd>,
            own_revokes: Vec<DeviceRevoke>,
        }
        let exported: ExportedIdentity = ciborium::from_reader(plaintext)
            .map_err(|_| "Bozuk kurtarma dosyası (içerik)".to_string())?;
        if exported.devices.is_empty() {
            return Err("Kurtarma dosyasında cihaz anahtarı yok".to_string());
        }
        // Before anything is stored: an identity without it cannot read its
        // server history, and the user would not be told.
        if exported.archive_root_key.as_ref().map_or(false, |k| k.len() != 32) {
            return Err("Kurtarma dosyası bozuk (arşiv anahtarı)".to_string());
        }

        // parsed before the wipe, so a bad payload changes nothing.
        let recovery_data: Option<RecoveryData> = if exported.data.is_empty() {
            None
        } else {
            Some(ciborium::from_reader(exported.data.as_slice())
                .map_err(|_| "Kurtarma dosyası bozuk (kişiler ve sohbetler)".to_string())?)
        };

        let mut device_infos = Vec::new();
        let mut own_bundle_bytes: Option<Vec<u8>> = None;
        let mut primary_fp: Option<String> = None;

        // The first device only. The caller stores the secret keys of that one
        // alone, so any other device was a row without keys after a restart.
        for dev in exported.devices.iter().take(1) {
            let sign_sk_ed_bytes: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(dev.sign_sk_ed25519.as_slice().try_into().map_err(|_| "Bozuk Ed25519 secret key")?);
            let sign_sk_ed25519 = SigningKey::from_bytes(&sign_sk_ed_bytes);
            let sign_pk_ed25519 = sign_sk_ed25519.verifying_key();

            // See the generate_identity note. The ML-DSA secret key is stored as a 32-byte seed and deterministically regenerated with `from_seed`.
            let sign_sk_mldsa_seed: ml_dsa::Seed = dev.sign_sk_mldsa.as_slice().try_into().map_err(|_| "Bozuk ML-DSA secret key")?;
            let sign_sk_mldsa = MlDsaSigningKey::<MlDsa87>::from_seed(&sign_sk_mldsa_seed);
            let sign_pk_mldsa = sign_sk_mldsa.verifying_key().clone();

            let kem_sk_x_bytes: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(dev.kem_sk_x25519.as_slice().try_into().map_err(|_| "Bozuk X25519 secret key")?);
            let kem_sk_x25519 = StaticSecret::from(*kem_sk_x_bytes);
            let kem_pk_x25519 = X25519PublicKey::from(&kem_sk_x25519);

            let kem_sk_mlkem = mlkem_dk_from_bytes(&dev.kem_sk_mlkem).map_err(|_| "Bad Kyber secret key")?;
            let kem_pk_mlkem = kem_sk_mlkem.encapsulation_key().clone();

            let computed_fp = hex::encode(compute_fingerprint(
                sign_pk_ed25519.as_bytes(),
                &sign_pk_mldsa.encode(),
                kem_pk_x25519.as_bytes(),
                &mlkem_ek_to_bytes(&kem_pk_mlkem),
            ));
            if computed_fp != dev.device_fingerprint {
                return Err("Kurtarma dosyası bozuk (fingerprint uyuşmazlığı)".to_string());
            }
            // the keys decoded and match: only now does the other
            // identity go (`take(1)`: once).
            self.wipe_other_identity(&exported.identity_id);

            let name = device_name.clone();
            let record = DeviceRecord {
                device_fingerprint: computed_fp.clone(),
                identity_id: exported.identity_id.clone(),
                sign_pubkey_ed25519: sign_pk_ed25519.as_bytes().to_vec(),
                sign_pubkey_mldsa: sign_pk_mldsa.encode().to_vec(),
                kem_pubkey_x25519: kem_pk_x25519.as_bytes().to_vec(),
                kem_pubkey_mlkem: mlkem_ek_to_bytes(&kem_pk_mlkem),
                device_name: name.clone(),
                is_active: true,
                last_seen: current_time_ms(),
            };

            if let Some(conn) = &self.db {
                // One transaction: a failed insert left the other identity
                // deleted and none in its place.
                let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
                // see `generate_identity` — one identity per database.
                tx.execute("DELETE FROM identities WHERE id != ?1", params![exported.identity_id]).map_err(|e| e.to_string())?;
                tx.execute(
                    "INSERT OR REPLACE INTO identities (id, primary_device) VALUES (?1, ?2)",
                    params![exported.identity_id, computed_fp],
                ).map_err(|e| e.to_string())?;
                tx.execute(
                    "INSERT OR REPLACE INTO own_devices
                     (device_fingerprint, identity_id, sign_pk_ed25519, sign_pk_mldsa, kem_pk_x25519, kem_pk_mlkem,
                      device_name, is_active, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        record.device_fingerprint, record.identity_id,
                        record.sign_pubkey_ed25519, record.sign_pubkey_mldsa,
                        record.kem_pubkey_x25519, record.kem_pubkey_mlkem,
                        record.device_name, record.is_active as i32, record.last_seen as i64,
                    ],
                ).map_err(|e| e.to_string())?;
                tx.commit().map_err(|e| e.to_string())?;
            }

            let bundle_bytes = ciborium_bytes(&SecretKeyBundle {
                device_fingerprint: computed_fp.clone(),
                sign_sk_ed25519: dev.sign_sk_ed25519.clone(),
                sign_sk_mldsa: dev.sign_sk_mldsa.clone(),
                kem_sk_x25519: dev.kem_sk_x25519.clone(),
                kem_sk_mlkem: dev.kem_sk_mlkem.clone(),
            })?;
            if own_bundle_bytes.is_none() {
                own_bundle_bytes = Some(bundle_bytes);
                primary_fp = Some(computed_fp.clone());
            }

            device_infos.push(identity::DeviceInfo {
                device_fingerprint: computed_fp.clone(),
                device_name: name,
                added_at: current_time_ms(),
                status: DeviceStatus::Active,
            });

            self.own_devices.insert(computed_fp.clone(), record);
            self.own_device_keys.insert(computed_fp, DeviceKeys {
                sign_sk_ed25519,
                sign_pk_ed25519,
                sign_pk_mldsa,
                sign_sk_mldsa,
                kem_sk_x25519,
                kem_pk_x25519,
                kem_pk_mlkem,
                kem_sk_mlkem,
            });
        }

        self.identity = Some(identity::Identity {
            identity_id: exported.identity_id.clone(),
            devices: device_infos,
            primary_device: primary_fp,
        });

        // Only the add of the device restored here, for this identity.
        let restored_fp = self.identity.as_ref().and_then(|i| i.primary_device.clone());
        if let Some(da) = exported.own_device_add.as_ref()
            .filter(|da| da.identity_id == exported.identity_id && restored_fp.as_deref() == Some(da.new_device_fingerprint.as_str()))
        {
            self.persist_own_device_add(da);
            self.own_device_add = Some(da.clone());
        }
        for r in exported.own_revokes.iter().filter(|r| r.identity_id == exported.identity_id) {
            self.remember_own_revoke(r);
        }
        // After the devices: a file that fails their checks changes nothing.
        if let Some(ark) = &exported.archive_root_key {
            // A precondition for the history on the server to be decryptable on this device.
            if !self.set_archive_root_key(ark) {
                error!("Kurtarma: arşiv kök anahtarı yüklenemedi, sunucudaki geçmiş okunamayacak");
            }
        }
        if let Some(data) = recovery_data {
            self.apply_recovery_data(data);
        }
        Ok((exported.identity_id, own_bundle_bytes.unwrap_or_default()))
    }

    /// What a recovery file carries besides the keys: the sibling sync
    /// payload (contacts with their keys, groups, other own devices) and
    /// every chat, 1:1 and group. Attachments stay out (their files are
    /// sealed with this device's keys).
    pub(crate) fn recovery_data(&self) -> RecoveryData {
        let chats = self.recovery_chat_ids().into_iter().map(|(gid, key)| self.recovery_chat(gid, key)).collect();
        RecoveryData { sync: self.build_sync_payload(), chats }
    }

    /// The chats `recovery_data` writes: (group id, 1:1 chat key).
    pub(crate) fn recovery_chat_ids(&self) -> Vec<(Option<String>, String)> {
        let distinct = |sql: &str| -> Vec<String> {
            self.db.as_ref()
                .and_then(|c| c.prepare(sql).ok())
                .map(|mut st| st.query_map([], |r| r.get::<_, String>(0)).map(|rows| rows.flatten().collect()).unwrap_or_default())
                .unwrap_or_default()
        };
        let mut out: Vec<(Option<String>, String)> = distinct("SELECT DISTINCT peer_device_fingerprint FROM messages WHERE group_id IS NULL AND peer_device_fingerprint IS NOT NULL")
            .into_iter().map(|key| (None, key)).collect();
        out.extend(distinct("SELECT DISTINCT group_id FROM messages WHERE group_id IS NOT NULL").into_iter().map(|gid| (Some(gid), String::new())));
        out
    }

    /// One chat of `recovery_data`: every row, decrypted.
    pub(crate) fn recovery_chat(&self, gid: Option<String>, key: String) -> RecoveryChat {
        match gid {
            None => {
                let rows = self.load_message_history_opt(&key, u32::MAX, None, false);
                (None, key, rows)
            }
            Some(gid) => {
                let mut rows = self.load_group_message_history_opt(&gid, u32::MAX, None, false);
                for m in rows.iter_mut() {
                    m.author_proof = m.message_id.as_deref().and_then(|id| self.group_author_proof(&gid, id));
                }
                (Some(gid), key, rows)
            }
        }
    }

    pub(crate) fn apply_recovery_data(&mut self, data: RecoveryData) {
        self.import_sync_payload(&data.sync);
        let own_id = self.my_identity_id().unwrap_or_default();
        for (gid, key, rows) in data.chats {
            for m in rows {
                let mid = m.message_id.as_deref();
                if mid.map_or(false, |id| self.message_exists_in_chat(id, gid.as_deref(), &key)) {
                    continue;
                }
                let stored = match &gid {
                    Some(g) => {
                        let author = m.sender_identity_id.clone().unwrap_or_else(|| own_id.clone());
                        self.archive_group_message(g, &author, &m.direction, m.text.as_bytes(), mid,
                            m.reply_to_message_id.as_deref(), m.reply_to_preview.as_deref(), m.reply_to_sender_identity_id.as_deref(),
                            m.sent_at_ms, m.author_proof.as_deref())
                    }
                    None => self.archive_message(&key, &m.direction, m.text.as_bytes(), mid, m.status.as_deref(),
                        m.reply_to_message_id.as_deref(), m.reply_to_preview.as_deref(), m.sent_at_ms),
                };
                if let Err(e) = stored {
                    warn!("Kurtarma: mesaj yazılamadı: {}", e);
                    continue;
                }
                self.backdate_archived(gid.as_deref(), &key, mid, m.timestamp);
                let synced = SyncedMessage {
                    direction: m.direction.clone(), text: m.text.clone(), timestamp: m.timestamp,
                    sender_identity_id: m.sender_identity_id.clone(), message_id: m.message_id.clone(),
                    sent_at_ms: m.sent_at_ms, is_deleted: m.is_deleted, is_edited: m.is_edited,
                    author_proof: m.author_proof.clone(), reactions: Vec::new(),
                };
                self.apply_synced_message_flags(gid.as_deref(), &key, &synced);
            }
        }
    }
}

/// The recovery file: Argon2id parameters and salt, then ChaCha20-Poly1305
/// over the CBOR of the keys and `RecoveryData`. CBOR, not JSON with hex: a
/// group row's author proof is about 9.4 KB, and hex doubled it again.
#[derive(Serialize, Deserialize)]
pub(crate) struct RecoveryFile {
    /// The key derivation algorithm. It lets an import tell apart older HKDF-based files from newer Argon2id-based ones.
    pub(crate) kdf: String,
    pub(crate) argon2_m_cost: u32,
    pub(crate) argon2_t_cost: u32,
    pub(crate) argon2_p_cost: u32,
    #[serde(with = "serde_bytes")]
    pub(crate) ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) salt: Vec<u8>,
}

/// see `P2PCore::recovery_data`: (group id, 1:1 chat key, rows) per chat.
#[derive(Serialize, Deserialize)]
pub(crate) struct RecoveryData {
    pub(crate) sync: SyncPayload,
    pub(crate) chats: Vec<RecoveryChat>,
}

pub(crate) type RecoveryChat = (Option<String>, String, Vec<ArchivedMessage>);

/// The chats of `recovery_data`, the core lock taken once per chat: the whole
/// history (every row decrypted) under one lock stalled the poll loop for
/// seconds on a big database.
// ponytail: one huge chat still holds the lock for its own rows; page it
// if that shows.
pub(crate) fn recovery_chats_unlocked() -> Vec<RecoveryChat> {
    let ids = core_lock_read().recovery_chat_ids();
    ids.into_iter().map(|(gid, key)| core_lock_read().recovery_chat(gid, key)).collect()
}

impl RecoveryData {
    /// Keeps the `n` newest messages over all chats, by `timestamp`.
    pub(crate) fn keep_newest(&mut self, n: usize) {
        let mut times: Vec<u64> = self.chats.iter().flat_map(|(_, _, rows)| rows.iter().map(|m| m.timestamp)).collect();
        if n == 0 || times.len() <= n {
            return;
        }
        times.sort_unstable_by(|a, b| b.cmp(a));
        let cutoff = times[n - 1];
        // Rows at the cutoff time: only as many as fit.
        let mut room = times[..n].iter().filter(|t| **t == cutoff).count();
        for (_, _, rows) in &mut self.chats {
            rows.retain(|m| {
                if m.timestamp != cutoff {
                    return m.timestamp > cutoff;
                }
                let keep = room > 0;
                room = room.saturating_sub(1);
                keep
            });
        }
        self.chats.retain(|(_, _, rows)| !rows.is_empty());
    }
}
