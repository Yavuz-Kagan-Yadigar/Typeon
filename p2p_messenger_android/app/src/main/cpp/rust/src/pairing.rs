//! Own identity, QR/code pairing, first-contact secrets and IdentityExchange.

use super::*;

impl P2PCore {

    /// Uygulama yeniden başlatıldığında DB'de kayıtlı identity/device'ın
    /// PUBLIC key kayıtlarını belleğe yükler. Bulunamazsa (ilk açılış)
    /// sessizce hiçbir şey yapmaz — `generate_identity` çağrılmasını
    /// bekler. Secret key'ler burada YÜKLENMEZ — Kotlin, Keystore ile
    /// şifresini çözdüğü `SecretKeyBundle`'ı ayrıca `load_secret_bundle`
    /// ile göndermelidir (uygulama akışı: initDatabase → identity varsa
    /// Kotlin şifreli blob'u okur/çözer → loadSecretBundle çağrılır).
    pub(crate) fn load_identity_from_db(&mut self) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        // H75: a NULL `primary_device` (the column allows it) hid the whole
        // identity and the app offered to create a new one.
        let identity_row: Option<(String, Option<String>)> = conn
            .query_row("SELECT id, primary_device FROM identities ORDER BY rowid DESC LIMIT 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .ok();
        let (identity_id, primary_device) = match identity_row {
            Some(v) => v,
            None => return,
        };

        let mut stmt = match conn.prepare(
            "SELECT device_fingerprint, sign_pk_ed25519, sign_pk_mldsa, kem_pk_x25519, kem_pk_mlkem,
                    device_name, is_active, last_seen
             FROM own_devices WHERE identity_id = ?1"
        ) {
            Ok(s) => s,
            Err(e) => { error!("load_identity_from_db prepare failed: {}", e); return; }
        };

        let rows = stmt.query_map(params![identity_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?, row.get::<_, i32>(6)?, row.get::<_, i64>(7)?,
            ))
        });

        let mut device_infos = Vec::new();

        if let Ok(rows) = rows {
            for row in rows {
                // Logged: if it was the only row the identity looks gone and
                // the app offers to create a new one.
                let row = match row {
                    Ok(r) => r,
                    Err(e) => { error!("own_devices satırı okunamadı: {}", e); continue; }
                };
                let (fp, sign_pk_ed, sign_pk_mldsa, kem_pk_x, kem_pk_mlkem,
                     device_name, is_active, last_seen) = row;

                self.own_devices.insert(fp.clone(), DeviceRecord {
                    device_fingerprint: fp.clone(),
                    identity_id: identity_id.clone(),
                    sign_pubkey_ed25519: sign_pk_ed,
                    sign_pubkey_mldsa: sign_pk_mldsa,
                    kem_pubkey_x25519: kem_pk_x,
                    kem_pubkey_mlkem: kem_pk_mlkem,
                    device_name: device_name.clone(),
                    is_active: is_active != 0,
                    last_seen: last_seen as u64,
                });
                device_infos.push(identity::DeviceInfo {
                    device_fingerprint: fp,
                    device_name,
                    // No `added_at` column in `own_devices`: `last_seen` is the
                    // closest stored time (D-34).
                    added_at: last_seen as u64,
                    status: if is_active != 0 { DeviceStatus::Active } else { DeviceStatus::Revoked },
                });
            }
        }

        if !device_infos.is_empty() {
            self.identity = Some(identity::Identity {
                identity_id,
                devices: device_infos,
                primary_device,
            });
            info!("Identity DB'den yüklendi (public key'ler) — secret key'ler henüz yüklenmedi, load_secret_bundle bekleniyor");
        }
    }

    // ---------------------------------------------------------------
    // Bölüm 1: Identity/Device
    // ---------------------------------------------------------------

    /// Kimlik + ilk cihazı üretir. DB'ye SADECE public key'ler yazılır.
    /// Secret key'ler dönüş değerinde bir `SecretKeyBundle` (CBOR) olarak
    /// verilir — Rust bunları hiçbir zaman diske yazmaz; çağıran (Kotlin,
    /// JNI export'u üzerinden) bu bloğu Android Keystore ile şifreleyip
    /// kendi sorumluluğunda saklamalıdır (bkz. `KeystoreCrypto.kt`).
    /// `generate_identity` for the frontends. Refuses when it would destroy an
    /// identity: with one loaded, the new row replaces it in the DB and the
    /// frontend overwrites the stored secret bundle; without a DB the new
    /// identity lives in memory only and its bundle still overwrites the file.
    pub(crate) fn create_identity(&mut self, device_name: String) -> Result<String, String> {
        if self.identity.is_some() {
            return Err("Identity already exists".to_string());
        }
        let row_on_disk = match &self.db {
            None => return Err("DB not open".to_string()),
            Some(c) => c.query_row("SELECT 1 FROM identities LIMIT 1", [], |_| Ok(())).is_ok(),
        };
        // An identity row whose devices did not load: a new identity would
        // wipe it all (`wipe_other_identity`).
        if row_on_disk {
            return Err("Identity already exists".to_string());
        }
        let (id, bundle_bytes) = self.generate_identity(device_name)?;
        // Held until `load_secret_bundle` or a wipe: the frontend reads it
        // (`getPendingSecretBundle`) and may have to read it again if its own
        // write fails.
        zeroize::Zeroize::zeroize(&mut self.pending_secret_bundle);
        self.pending_secret_bundle = Some(bundle_bytes);
        Ok(id)
    }

    pub(crate) fn generate_identity(&mut self, device_name: String) -> Result<(String, Vec<u8>), String> {
        let mut csprng = OsRng;
        let sign_sk_ed25519 = SigningKey::generate(&mut csprng);
        let sign_pk_ed25519 = sign_sk_ed25519.verifying_key();
        // ML-DSA-87 — spec 1.1 tablosu ML-DSA-65 (NIST Kategori 3) belirtiyordu;
        // güvenlik marjını artırmak için ML-KEM-1024/ML-DSA-87'ye (Kategori 5)
        // yükseltildi (bkz. SECURITY.md "Anahtar boyutları" notu). getrandom
        // feature ile parametresiz üretim, rand_core sürüm çakışmasını
        // bypass eder (bkz. Cargo.toml notu).
        let sign_sk_mldsa: MlDsaSigningKey<MlDsa87> = MlDsaGenerate::generate();
        let sign_pk_mldsa = sign_sk_mldsa.verifying_key().clone();
        let kem_sk_x25519 = StaticSecret::random_from_rng(&mut csprng);
        let kem_pk_x25519 = X25519PublicKey::from(&kem_sk_x25519);
        // X25519 (rand_core 0.6 üzerinden rand 0.8) ve ML-KEM (rand_core
        // 0.6.4) aynı rand_core majör sürümü — aynı OsRng paylaşılabilir.
        let (kem_sk_mlkem, _kem_pk_mlkem_dup) = MlKem1024::generate(&mut csprng);
        let kem_pk_mlkem = kem_sk_mlkem.encapsulation_key().clone();

        let fingerprint_raw = compute_fingerprint(
            sign_pk_ed25519.as_bytes(),
            &sign_pk_mldsa.encode(),
            kem_pk_x25519.as_bytes(),
            &kem_pk_mlkem.as_bytes(),
        );
        let fingerprint_hex = hex::encode(&fingerprint_raw);

        // Aşama A: identity_id == ilk (ve tek) cihazın fingerprint'i.
        let identity_id = fingerprint_hex.clone();
        let device_fingerprint = fingerprint_hex;

        let identity = identity::Identity {
            identity_id: identity_id.clone(),
            devices: vec![identity::DeviceInfo {
                device_fingerprint: device_fingerprint.clone(),
                device_name: device_name.clone(),
                added_at: current_time_ms(),
                status: DeviceStatus::Active,
            }],
            primary_device: Some(device_fingerprint.clone()),
        };

        let record = DeviceRecord {
            device_fingerprint: device_fingerprint.clone(),
            identity_id: identity_id.clone(),
            sign_pubkey_ed25519: sign_pk_ed25519.as_bytes().to_vec(),
            sign_pubkey_mldsa: sign_pk_mldsa.encode().to_vec(),
            kem_pubkey_x25519: kem_pk_x25519.as_bytes().to_vec(),
            kem_pubkey_mlkem: kem_pk_mlkem.as_bytes().to_vec(),
            device_name,
            is_active: true,
            last_seen: current_time_ms(),
        };

        let secret_bundle = SecretKeyBundle {
            device_fingerprint: device_fingerprint.clone(),
            sign_sk_ed25519: sign_sk_ed25519.to_bytes().to_vec(),
            // ML-DSA'nın "secret key" serileştirmesi 32 baytlık bir seed'dir
            // (`KeyExport::to_bytes`) — bu seed'ten `SigningKey::from_seed`
            // ile deterministik olarak aynı anahtar geri üretilir.
            sign_sk_mldsa: sign_sk_mldsa.to_bytes().to_vec(),
            kem_sk_x25519: kem_sk_x25519.to_bytes().to_vec(),
            // ML-KEM'in seed'ten geri üretimi yok (bkz. ratchet.rs notu) —
            // tam serileştirilmiş secret key (`EncodedSizeUser::as_bytes`)
            // saklanır.
            kem_sk_mlkem: kem_sk_mlkem.as_bytes().to_vec(),
        };
        let secret_bundle_bytes = ciborium_bytes(&secret_bundle)?;

        let keys = DeviceKeys {
            sign_sk_ed25519,
            sign_pk_ed25519,
            sign_pk_mldsa,
            sign_sk_mldsa,
            kem_sk_x25519,
            kem_pk_x25519,
            kem_pk_mlkem,
            kem_sk_mlkem,
        };

        self.wipe_other_identity(&identity_id);
        if let Some(conn) = &self.db {
            // One identity per database: a leftover row of an older identity
            // could be the one `load_identity_from_db` picks at the next start.
            let _ = conn.execute("DELETE FROM identities WHERE id != ?1", params![identity_id]);
            conn.execute(
                "INSERT OR REPLACE INTO identities (id, primary_device) VALUES (?1, ?2)",
                params![identity_id, device_fingerprint],
            ).map_err(|e| e.to_string())?;
            // Sadece PUBLIC key'ler burada yazılıyor — secret key'ler bu
            // bağlantıya hiç yazılmaz (bkz. fonksiyon dokümantasyonu).
            conn.execute(
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
        }

        self.identity = Some(identity);
        self.own_devices.insert(device_fingerprint.clone(), record);
        self.own_device_keys.insert(device_fingerprint, keys);

        Ok((identity_id, secret_bundle_bytes))
    }

    /// Kotlin'in Keystore ile şifresini çözdüğü bir `SecretKeyBundle`'ı
    /// (CBOR) belleğe yükler — uygulama yeniden başlatıldığında,
    /// `load_identity_from_db`'nin doldurduğu PUBLIC key kayıtlarını
    /// tamamlamak için çağrılır. `load_identity_from_db` zaten
    /// `own_devices`/`identity`'yi doldurmuş olmalı; bu fonksiyon sadece
    /// eksik olan `own_device_keys` (secret key'ler) map'ini doldurur.
    pub(crate) fn load_secret_bundle(&mut self, bundle_bytes: &[u8]) -> Result<(), String> {
        let bundle: SecretKeyBundle = ciborium::from_reader(bundle_bytes).map_err(|e| e.to_string())?;

        let record = self.own_devices.get(&bundle.device_fingerprint).cloned()
            .ok_or("Bilinmeyen cihaz — önce load_identity_from_db (public key) çalışmalı")?;

        let mut sign_sk_ed_bytes: [u8; 32] = bundle.sign_sk_ed25519.as_slice().try_into().map_err(|_| "Bozuk Ed25519 secret key")?;
        let sign_sk_ed25519 = SigningKey::from_bytes(&sign_sk_ed_bytes);
        zeroize::Zeroize::zeroize(&mut sign_sk_ed_bytes);
        let sign_pk_ed25519 = sign_sk_ed25519.verifying_key();

        // ML-DSA secret key'i 32 baytlık seed olarak saklanıyor (bkz.
        // generate_identity notu) — `from_seed` ile deterministik üretiliyor.
        let sign_sk_mldsa_seed: ml_dsa::Seed = bundle.sign_sk_mldsa.as_slice().try_into().map_err(|_| "Bozuk ML-DSA secret key")?;
        let sign_sk_mldsa = MlDsaSigningKey::<MlDsa87>::from_seed(&sign_sk_mldsa_seed);
        let sign_pk_mldsa_encoded: EncodedVerifyingKey<MlDsa87> = record.sign_pubkey_mldsa.as_slice().try_into().map_err(|_| "Bozuk ML-DSA public key")?;
        let sign_pk_mldsa = MlDsaVerifyingKey::<MlDsa87>::decode(&sign_pk_mldsa_encoded);

        let mut kem_sk_x_bytes: [u8; 32] = bundle.kem_sk_x25519.as_slice().try_into().map_err(|_| "Bozuk X25519 secret key")?;
        let kem_sk_x25519 = StaticSecret::from(kem_sk_x_bytes);
        zeroize::Zeroize::zeroize(&mut kem_sk_x_bytes);
        let kem_pk_x25519 = X25519PublicKey::from(&kem_sk_x25519);

        // ML-KEM secret key'i tam serileştirilmiş biçimde saklanıyor (bkz.
        // generate_identity notu — ml-kem'de "seed"ten geri üretim yok).
        let kem_sk_encoded: ml_kem::Encoded<MlKem1024DecapsulationKey> = bundle.kem_sk_mlkem.as_slice().try_into().map_err(|_| "Bozuk Kyber secret key")?;
        let kem_sk_mlkem = MlKem1024DecapsulationKey::from_bytes(&kem_sk_encoded);
        let kem_pk_encoded: ml_kem::Encoded<MlKem1024EncapsulationKey> = record.kem_pubkey_mlkem.as_slice().try_into().map_err(|_| "Bozuk Kyber public key")?;
        let kem_pk_mlkem = MlKem1024EncapsulationKey::from_bytes(&kem_pk_encoded);

        // The secrets must be the ones behind the stored public keys (the
        // fingerprint peers trust). A bundle of another device would sign and
        // decrypt with keys nobody can verify.
        if sign_pk_ed25519.as_bytes().to_vec() != record.sign_pubkey_ed25519
            || sign_sk_mldsa.verifying_key().encode().to_vec() != record.sign_pubkey_mldsa
            || kem_pk_x25519.as_bytes().to_vec() != record.kem_pubkey_x25519
            || kem_sk_mlkem.encapsulation_key().as_bytes().to_vec() != record.kem_pubkey_mlkem
        {
            return Err("Secret key paketi bu cihazın kayıtlı public key'leriyle eşleşmiyor".to_string());
        }

        self.own_device_keys.insert(bundle.device_fingerprint.clone(), DeviceKeys {
            sign_sk_ed25519,
            sign_pk_ed25519,
            sign_pk_mldsa,
            sign_sk_mldsa,
            kem_sk_x25519,
            kem_pk_x25519,
            kem_pk_mlkem,
            kem_sk_mlkem,
        });
        Ok(())
    }

    pub(crate) fn get_active_own_device_fingerprint(&self) -> Result<String, String> {
        let identity_id = self.identity.as_ref().ok_or("No identity yet")?.identity_id.clone();
        // Çoklu-cihaz düzeltmesi: BU fiziksel cihazın kontrol ettiği (secret
        // anahtarına SAHİP olduğumuz) cihaz döndürülmeli. Birincil cihazda
        // `own_devices` kardeş cihazın (ikincil) PUBLIC kaydını da
        // içerebilir — onun secret'i yok, onunla imzalayamayız; bu yüzden
        // `own_device_keys` üyeliği ŞART.
        self.own_devices
            .iter()
            .find(|(fp, d)| d.identity_id == identity_id && d.is_active && self.own_device_keys.contains_key(*fp))
            .map(|(fp, _)| fp.clone())
            .ok_or_else(|| "No active own device".to_string())
    }

    /// Base32 kişi kodu (spec 1.2) — UI'de gösterilecek.
    pub(crate) fn identity_code(&self) -> Result<String, String> {
        let id = self.identity.as_ref().ok_or("No identity yet")?;
        identity::format_identity_code(&id.identity_id)
    }

    pub(crate) fn identity_short_code(&self) -> Result<String, String> {
        let id = self.identity.as_ref().ok_or("No identity yet")?;
        let raw = hex::decode(&id.identity_id).map_err(|_| "Bad identity_id")?;
        Ok(identity::format_short_code(&raw))
    }

    /// Spec dışı, kullanıcı isteği (WhatsApp tarzı "yanıtla" — grup
    /// yanıtlarında, yanıtlanan mesaj bu cihazda yerelde henüz
    /// yüklenmemişse "Sen" mi yoksa bir üyenin adı mı gösterileceğine karar
    /// vermek için Kotlin tarafının HAM `identity_id`'ye ihtiyacı var):
    /// `identity_code`/`identity_short_code`'un aksine BİÇİMLENDİRİLMEMİŞ
    /// (Base32/kısa kod değil) ham hex `identity_id`'yi döner — bu,
    /// `GroupUpdate`/`GroupMemberDevice`/mesaj olaylarındaki
    /// `sender_identity_id`/`reply_to_sender_identity_id` alanlarıyla
    /// AYNI biçimdir, doğrudan karşılaştırılabilir.
    pub(crate) fn own_identity_id(&self) -> Result<String, String> {
        Ok(self.identity.as_ref().ok_or("No identity yet")?.identity_id.clone())
    }

    // ---------------------------------------------------------------
    // Bölüm 1.3/1.4: QR + manuel eşleşme
    // ---------------------------------------------------------------

    /// Kendi QR paketimizi üretir (spec 1.3 — fingerprint-only karar).
    /// `rendezvous_node`: bilinen bootstrap node adresi (spec bölüm 6.5 —
    /// "tek bilinen node" v0.1 için yeterli).
    pub(crate) fn generate_qr_packet(&mut self, rendezvous_node: String) -> Result<Vec<u8>, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let device_name = self.own_devices.get(&own_fp).map(|d| d.device_name.clone()).unwrap_or_default();

        // bkz. SECURITY.md "Cross-network connectivity" notu / spec §4.1
        // ("~10 node adresi paylaşımı", önceden hiç implemente edilmemişti):
        // taşıdığımız bilinen röle adaylarından birkaçını da QR'a ekliyoruz
        // — bu sayede karşı taraf, biz doğrudan dial edilemesek bile (farklı
        // ağ/NAT) bizi bir röle üzerinden bulabilir. `known_relay_peers`
        // değerleri zaten TAM adres (`.../p2p/<röle_peer_id>` dahil, bkz.
        // `record_known_relay` çağrı noktaları) — burada tekrar eklemeye
        // gerek yok.
        let known_relays = self.freshest_relays();

        let nonce = self.issue_pairing_nonce()?;
        // The mailbox made from this nonce is registered now, not at the
        // next sweep: the scanner's first packet goes to it.
        self.server_sweep_at = 0;
        let packet = QrPacket {
            version: QrPacket::CURRENT_VERSION,
            device_name,
            identity_id,
            device_fingerprint: own_fp,
            rendezvous_node,
            known_relays,
            pairing_nonce: nonce,
        };
        packet.to_cbor()
    }

    /// Spec dışı, kullanıcı isteği: `process_manual_entry`'nin beklediği
    /// `identity_id|device_fingerprint|pairing_nonce|device_name|rendezvous_node`
    /// formatını (bkz. o fonksiyonun dokümantasyonu) burada, TEK bir yerde
    /// üretir — Kotlin tarafında elle string birleştirmek yerine (format
    /// driftine karşı; ayrıştırıcı ve üretici aynı formatı Rust'ta paylaşır).
    /// UI'de "Kodumu kopyala" düğmesi bunu panoya kopyalar, karşı taraf
    /// "Manuel Ekle" dialoguna yapıştırır — QR taranamayan durumlar için
    /// (ör. ekranlar fiziksel olarak yan yana değil).
    pub(crate) fn generate_manual_add_code(&mut self, rendezvous_node: &str) -> Result<String, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let device_name = self.own_devices.get(&own_fp).map(|d| d.device_name.clone()).unwrap_or_default();
        let nonce = hex::encode(self.issue_pairing_nonce()?);
        self.server_sweep_at = 0;
        Ok(format!("{}|{}|{}|{}|{}", identity_id, own_fp, nonce, device_name, rendezvous_node))
    }

    pub(crate) fn meta_str(&self, k: &str) -> Option<String> {
        self.db.as_ref()?.query_row("SELECT v FROM app_meta WHERE k = ?1", params![k], |r| r.get::<_, String>(0)).ok()
    }

    /// The nonces of the pairing codes this device produced that are still
    /// valid, with their expiry, oldest first. On disk, so a process restart
    /// keeps them.
    pub(crate) fn pairing_nonces(&self) -> Vec<(Vec<u8>, u64)> {
        let now = current_time_ms();
        self.meta_str("pairing_nonces").unwrap_or_default()
            .split(',')
            .filter_map(|entry| {
                let (nonce, until) = entry.split_once(':')?;
                Some((hex::decode(nonce).ok()?, until.parse::<u64>().ok()?))
            })
            .filter(|(_, until)| *until > now)
            .collect()
    }

    /// The nonce for a pairing code shown now. Each one is valid for
    /// `PAIRING_WINDOW_MS` and for any number of scans; at most
    /// `PAIRING_WINDOW_MS / PAIRING_NONCE_REUSE_MS` are valid at a time.
    /// L-35: Err when the nonce is not on disk: a code whose proof can never
    /// verify must not be shown.
    pub(crate) fn issue_pairing_nonce(&self) -> Result<Vec<u8>, String> {
        let now = current_time_ms();
        let mut all = self.pairing_nonces();
        if let Some((nonce, until)) = all.last() {
            if until.saturating_add(PAIRING_NONCE_REUSE_MS) > now.saturating_add(PAIRING_WINDOW_MS) {
                return Ok(nonce.clone());
            }
        }
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        all.push((nonce.to_vec(), now + PAIRING_WINDOW_MS));
        let v: Vec<String> = all.iter().map(|(n, until)| format!("{}:{}", hex::encode(n), until)).collect();
        let conn = self.db.as_ref().ok_or("Veritabanı açık değil, eşleşme kodu üretilemedi")?;
        conn.execute("INSERT OR REPLACE INTO app_meta (k, v) VALUES (?1, ?2)", params!["pairing_nonces", v.join(",")])
            .map_err(|e| format!("Eşleşme kodu kaydedilemedi: {}", e))?;
        bump_first_contact_gen("pairing_nonces");
        Ok(nonce.to_vec())
    }

    /// The sender read a code this device shows: `pairing_proof` is made from
    /// a nonce this device issued and that is still valid.
    pub(crate) fn pairing_proof_valid(&self, exchange: &IdentityExchange) -> bool {
        let made_from = |nonce: &[u8]| packet::pairing_nonce_proof(nonce, &exchange.device_fingerprint) == exchange.pairing_proof;
        // The link code makes a contact only of the first device to read it,
        // on a device with no contacts yet (the only kind a grant can move,
        // `adopt_device_link`). Anyone else who saw that code does not
        // become a contact of an identity in use.
        (self.contacts.is_empty() && self.link_proof_valid(exchange)) || self.pairing_nonces().iter().any(|(nonce, _)| made_from(nonce))
    }

    /// As `pairing_proof_valid`, for the link code this device shows now.
    pub(crate) fn link_proof_valid(&self, exchange: &IdentityExchange) -> bool {
        self.link_request_nonce.len() == 16
            && self.link_request_open_until > current_time_ms()
            && packet::pairing_nonce_proof(&self.link_request_nonce, &exchange.device_fingerprint) == exchange.pairing_proof
    }

    /// The 5 relays seen last, for a pairing or link code.
    pub(crate) fn freshest_relays(&self) -> Vec<String> {
        let mut relays: Vec<&(Multiaddr, u64)> = self.known_relay_peers.values().collect();
        relays.sort_by(|a, b| b.1.cmp(&a.1));
        relays.into_iter().take(5).map(|(a, _)| a.to_string()).collect()
    }

    /// The nonces kept for the first-contact mailbox of `fp`: of the code we
    /// read from it (`pn:`), then of the code of ours it read (`pk:`).
    pub(crate) fn stored_pairing_secrets(&self, fp: &str) -> Vec<Vec<u8>> {
        ["pn", "pk"].iter()
            .filter_map(|kind| self.meta_str(&format!("{}:{}", kind, fp)))
            .filter_map(|v| hex::decode(v).ok())
            .filter(|s| s.len() == 16)
            .collect()
    }

    /// Every secret a first-contact mailbox of this device is made from
    /// (`server_seal::first_contact_mailbox_id`): the codes it shows now
    /// (pairing, link), and the code behind each device it paired with, in
    /// either direction. A stranger holds none of them.
    /// ponytail: two range scans of `app_meta` per server sweep and fetch;
    /// keep the list in memory if that shows.
    ///
    /// Only for devices still waiting for a first handshake: one of the
    /// identity's devices has no session, or the code is less than 7 days
    /// old. The server refuses a whole `Register`/`Fetch` above 512 ids.
    pub(crate) fn first_contact_secrets(&self) -> Vec<Vec<u8>> {
        // It runs on every server sweep and fetch, and costs two meta range
        // scans plus a device scan per row and per group member. Computed
        // again when what it reads changes: sessions, devices, groups, the
        // link, the stored secrets (`meta_put`/`meta_del` of `pn:`/`pk:`/`pt:`
        // bump `first_contact_gen`), and every hour for the 7-day windows.
        // ponytail: counts, not contents, for devices; a device swapped for
        // another within the hour is seen at the next hour.
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        let mut sessions: u64 = 0;
        for fp in self.ratchets.keys() {
            let mut fh = std::collections::hash_map::DefaultHasher::new();
            fp.hash(&mut fh);
            sessions ^= fh.finish();
        }
        sessions.hash(&mut h);
        self.known_remote_devices.values().filter(|d| d.is_active).count().hash(&mut h);
        self.own_devices.values().filter(|d| d.is_active).count().hash(&mut h);
        let mut groups: u64 = 0;
        for g in self.groups.values() {
            let mut gh = std::collections::hash_map::DefaultHasher::new();
            (&g.group_id, g.version, g.members.len()).hash(&mut gh);
            groups ^= gh.finish();
        }
        groups.hash(&mut h);
        (&self.link_request_nonce, &self.pending_link_nonce, self.pending_link_started_at).hash(&mut h);
        (FIRST_CONTACT_GEN.load(std::sync::atomic::Ordering::Relaxed), current_time_ms() / (60 * 60 * 1000)).hash(&mut h);
        let key = h.finish();
        if let Some((k, v)) = self.first_contact_cache.borrow().as_ref() {
            if *k == key {
                return v.clone();
            }
        }
        let out = self.first_contact_secrets_uncached();
        *self.first_contact_cache.borrow_mut() = Some((key, out.clone()));
        out
    }

    pub(crate) fn first_contact_secrets_uncached(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self.pairing_nonces().into_iter().map(|(n, _)| n).collect();
        // #73: one secret per group I am in, while a member device of it has
        // no session with me; leaving drops its mailbox.
        let me = self.my_identity_id().unwrap_or_default();
        let mut gids: Vec<&Group> = self.groups.values()
            .filter(|g| g.other_members(&me).iter().any(|m| {
                let devices = self.active_devices_for_identity(m);
                devices.is_empty() || devices.iter().any(|fp| !self.ratchets.contains_key(fp))
            }))
            .collect();
        gids.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        out.extend(gids.into_iter().map(|g| self.own_group_contact_secret(&g.group_id)));
        out.push(self.link_request_nonce.clone());
        // Past the link horizon the link is dead; its `pn:` row below keeps
        // the mailbox as long as a paired code would.
        if current_time_ms().saturating_sub(self.pending_link_started_at) <= PENDING_LINK_RETRY_HORIZON_MS {
            out.push(self.pending_link_nonce.clone());
        }
        if let Some(conn) = &self.db {
            if let Ok(mut st) = conn.prepare("SELECT k, v FROM app_meta WHERE (k >= 'pn:' AND k < 'pn;') OR (k >= 'pk:' AND k < 'pk;')") {
                if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
                    out.extend(rows.flatten().filter(|(k, _)| self.awaits_first_contact(&k[3..])).filter_map(|(_, v)| hex::decode(v).ok()));
                }
            }
        }
        out.retain(|s| s.len() == 16);
        out.sort();
        out.dedup();
        out
    }

    /// Stores a first-contact secret of `fp` (`pn`/`pk`, bkz.
    /// `first_contact_secrets`) with the time it was made.
    pub(crate) fn put_pairing_secret(&self, kind: &str, fp: &str, nonce: &[u8]) {
        self.meta_put(&format!("{}:{}", kind, fp), &hex::encode(nonce));
        self.meta_put(&format!("pt:{}", fp), &current_time_ms().to_string());
    }

    /// `first_contact_secrets` keeps the mailbox of `fp`: paired in the last
    /// 7 days, or a device of its identity has no session yet.
    pub(crate) fn awaits_first_contact(&self, fp: &str) -> bool {
        const RECENT_MS: u64 = 7 * 24 * 60 * 60 * 1000;
        let paired_at = self.meta_str(&format!("pt:{}", fp)).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        if current_time_ms().saturating_sub(paired_at) < RECENT_MS {
            return true;
        }
        let own_fp = self.own_mailbox_topic_fp.as_deref();
        // A code whose pairing never completed: only its first 7 days.
        let Some(identity) = self.known_remote_devices.get(fp).or_else(|| self.own_devices.get(fp)).map(|d| &d.identity_id) else {
            return false;
        };
        self.known_remote_devices.values().chain(self.own_devices.values())
            .filter(|d| d.is_active && &d.identity_id == identity && Some(d.device_fingerprint.as_str()) != own_fp)
            .any(|d| !self.ratchets.contains_key(&d.device_fingerprint))
    }

    /// The secret of `target_fp`'s first-contact mailbox that this device
    /// holds: from the code between the two devices, else from the code
    /// between us and another device of the target's identity (a sibling
    /// sync gives every device of an identity those, bkz.
    /// `SyncedDevice.mailbox_secrets`). `None`: no server path to the device
    /// until a session exists.
    pub(crate) fn first_contact_secret_for(&self, target_fp: &str) -> Option<Vec<u8>> {
        if self.pending_link_target.as_deref() == Some(target_fp) && self.pending_link_nonce.len() == 16 {
            return Some(self.pending_link_nonce.clone());
        }
        if let Some(s) = self.stored_pairing_secrets(target_fp).into_iter().next() {
            return Some(s);
        }
        let identity = &self.known_remote_devices.get(target_fp)?.identity_id;
        let mut others: Vec<&String> = self.known_remote_devices.values()
            .filter(|d| &d.identity_id == identity && d.device_fingerprint != target_fp)
            .map(|d| &d.device_fingerprint)
            .collect();
        others.sort();
        others.into_iter().find_map(|fp| self.stored_pairing_secrets(fp).into_iter().next())
            .or_else(|| {
                // #73: the target's secret for a group we are both in.
                let mut gids: Vec<&Group> = self.groups.values().filter(|g| g.is_member(identity)).collect();
                gids.sort_by(|a, b| a.group_id.cmp(&b.group_id));
                gids.into_iter().find_map(|g| self.member_group_secret(target_fp, &g.group_id))
            })
    }

    /// The group first-contact secret `fp` gave for `group_id` (via the
    /// founder, bkz. `GroupMemberDevice.first_contact_secret`).
    pub(crate) fn member_group_secret(&self, fp: &str, group_id: &str) -> Option<Vec<u8>> {
        self.meta_str(&format!("gf:{}:{}", fp, group_id)).and_then(|v| hex::decode(v).ok()).filter(|s| s.len() == 16)
    }

    /// Gives the founder device that sent a group update our group
    /// first-contact secret, once (bkz. `GroupMemberDevice.first_contact_secret`).
    /// Again whenever the founder's update lists this device without it (the
    /// founder lost it); once per founder device when it lists another
    /// device of ours.
    pub(crate) fn give_founder_contact_secret(&mut self, update: &GroupUpdate, sender_identity_id: &str, peer_fp: &str) {
        let Some(g) = self.groups.get(&update.group_id) else { return };
        if g.founder_identity_id != sender_identity_id || self.my_identity_id().as_deref() == Some(sender_identity_id) {
            return;
        }
        let secret = self.own_group_contact_secret(&update.group_id);
        let sent = format!("gfs:{}:{}", peer_fp, update.group_id);
        let listed = update.member_devices.iter()
            .find(|d| Some(&d.device_fingerprint) == self.own_mailbox_topic_fp.as_ref())
            .map(|d| d.first_contact_secret == secret);
        if listed == Some(true) || (listed.is_none() && self.meta_str(&sent).is_some()) {
            return;
        }
        if secret.len() == 16 && self.send_message_content(peer_fp.to_string(), &MessageContent::FirstContactSecret { secret, group_id: update.group_id.clone() }, None).is_ok() {
            self.meta_put(&sent, "1");
        }
    }

    /// This device's first-contact secret for one group (bkz.
    /// `GroupMemberDevice.first_contact_secret`), derived from a device
    /// master made on first use. #73: per group, so a member of one group
    /// cannot reach the mailbox of another, and its mailbox is registered
    /// only while the group is here.
    pub(crate) fn own_group_contact_secret(&self, group_id: &str) -> Vec<u8> {
        let master = match self.meta_str("own_gfc").and_then(|v| hex::decode(v).ok()).filter(|s| s.len() == 16) {
            Some(m) => m,
            None if self.db.is_none() => return Vec::new(),
            None => {
                let mut m = vec![0u8; 16];
                rand::RngCore::fill_bytes(&mut OsRng, &mut m);
                // OR IGNORE + read back: a failed read must not replace the
                // stored master, and an unsaved one must not be handed out
                // (each call would make another).
                let saved = self.db.as_ref().map_or(false, |c| {
                    c.execute("INSERT OR IGNORE INTO app_meta (k, v) VALUES ('own_gfc', ?1)", params![hex::encode(&m)]).is_ok()
                });
                bump_first_contact_gen("own_gfc");
                match saved.then(|| self.meta_str("own_gfc")).flatten().and_then(|v| hex::decode(v).ok()).filter(|s| s.len() == 16) {
                    Some(m) => m,
                    None => return Vec::new(),
                }
            }
        };
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(b"typeon-group-first-contact-v1");
        h.update(&master);
        h.update(group_id.as_bytes());
        h.finalize()[..16].to_vec()
    }

    /// The signed revokes of my own identity, oldest first (bkz.
    /// `IdentityExchange.revokes`).
    /// ponytail: a device linked later does not get the earlier ones from its
    /// siblings. Put the list into `SyncPayload` if that matters.
    pub(crate) fn own_revokes(&self) -> Vec<DeviceRevoke> {
        self.db.as_ref()
            .and_then(|conn| conn.query_row("SELECT v FROM app_meta WHERE k = 'own_revokes'", [], |r| r.get::<_, String>(0)).ok())
            .and_then(|v| hex::decode(v).ok())
            .and_then(|b| ciborium::from_reader(b.as_slice()).ok())
            .unwrap_or_default()
    }

    pub(crate) fn remember_own_revoke(&self, revoke: &DeviceRevoke) {
        let mut all = self.own_revokes();
        if all.iter().any(|r| r.revoked_device_fingerprint == revoke.revoked_device_fingerprint) {
            return;
        }
        // Every revoke is kept: a DeviceAdd has no expiry, so a contact that
        // never saw the revoke takes the device back.
        // ponytail: each one adds about 4.7 KB to every IdentityExchange;
        // near 200 the packet passes `MAX_ENVELOPE_BYTES`. A device-set epoch
        // in DeviceAdd if an identity ever revokes that many.
        all.push(revoke.clone());
        if let Ok(bytes) = ciborium_bytes(&all) {
            self.meta_put("own_revokes", &hex::encode(bytes));
        }
    }

    /// The contact revoked this device with a signed notice (bkz.
    /// `KnownDevice.owner_revoked`).
    /// A device of mine that I revoked and that still sends: the one notice
    /// of `revoke_own_linked_device` did not reach it (the revoking device
    /// died right after, or the device was away). Its session is gone, so
    /// the revoke goes back in our IdentityExchange, which needs none; the
    /// device wipes itself on it. At most once per 10 min per device.
    pub(crate) fn answer_revoked_sibling(&mut self, fp: &str) {
        let now = current_time_ms();
        // Its own key: the plain one is set by any IdentityExchange reply,
        // the one of the link a few minutes earlier too.
        let key = format!("revoked:{fp}");
        if self.last_identity_exchange_reply.get(&key).map_or(false, |&t| now < t + 10 * 60_000) {
            return;
        }
        if !self.own_revokes().iter().any(|r| r.revoked_device_fingerprint == fp) {
            return;
        }
        info!("İptal edilmiş kardeş cihaz hâlâ gönderiyor, iptal yeniden iletiliyor: {}", crate::log_id(fp));
        match self.send_identity_exchange_fresh(fp) {
            Ok(()) => { self.last_identity_exchange_reply.insert(key, now); }
            Err(e) => warn!("İptal yeniden iletilemedi: {}", e),
        }
    }

    pub(crate) fn owner_revoked(&self, identity_id: &str, device_fingerprint: &str) -> bool {
        self.identity_to_contact.get(identity_id)
            .and_then(|cid| self.contacts.get(cid))
            .and_then(|c| c.find_device(device_fingerprint))
            .map_or(false, |d| d.owner_revoked)
            // L-22: a non-contact identity's (group member's) revoke.
            || self.non_contact_revoke(device_fingerprint).map_or(false, |(id, _)| id == identity_id)
            // A device of my own identity that I revoked: siblings that never
            // held its record have only `own_revokes` to go by. A device
            // linked again since is an active record and is not refused.
            || (self.my_identity_id().as_deref() == Some(identity_id)
                && !self.known_remote_devices.get(device_fingerprint).map_or(false, |d| d.is_active)
                && self.own_revokes().iter().any(|r| r.revoked_device_fingerprint == device_fingerprint))
    }

    /// A non-contact identity's revoke of `device_fingerprint` (`orv:` row,
    /// "identity|revoked_at"): the identity, and when we applied the revoke.
    pub(crate) fn non_contact_revoke(&self, device_fingerprint: &str) -> Option<(String, Option<u64>)> {
        let v = self.meta_str(&format!("orv:{}", device_fingerprint))?;
        let mut parts = v.splitn(2, '|');
        let id = parts.next()?.to_string();
        Some((id, parts.next().and_then(|t| t.parse().ok())))
    }

    /// Taranan bir QR'ı (veya manuel girilen aynı formattaki metni, spec
    /// 1.4) işler: TOFU olarak Contact kaydeder, rendezvous node'u swarm'a
    /// bilinen adres olarak ekler, ve karşı tarafın gerçek public key'lerini
    /// indirmek için kendi `IdentityExchange` paketimizi gönderir (spec 1.3:
    /// "fingerprint-only [...] bağlantı kurulunca karşı taraftan indirilir
    /// ve bu fingerprint ile karşılaştırılır").
    /// Dönüş (başarılıysa): `(identity_id, device_fingerprint, device_name)`
    /// — spec dışı, kullanıcı isteği: eşleşme genellikle UZUN sürer (gerçek
    /// dial/Noise/IdentityExchange el sıkışması bu fonksiyon DÖNDÜKTEN
    /// SONRA arka planda tamamlanır, bkz. aşağıdaki notlar) — çağıran taraf
    /// (Kotlin) bu üçlüyü kullanarak kullanıcıyı DOĞRUDAN yeni kişinin
    /// sohbet ekranına yönlendirebilir; o ekran zaten `hasActiveSession`/
    /// `isPeerConnected`'a bakan bir "Bağlanılıyor..." göstergesi taşıyor
    /// (bkz. ChatActivity `sessionPollRunnable`/`layoutConnecting`) — bu,
    /// eşleşmenin hâlâ devam ettiğini (WIP) göstermenin en doğal yolu,
    /// AYRI bir "eşleşme ilerliyor" ekranı icat etmeye gerek yok.
    /// `device_fingerprint` burada QR/manuel VERİDEN doğrudan alınır —
    /// `resolve_active_device_for_identity`/`known_remote_devices`'ı
    /// BEKLEMEZ (o, ancak gerçek IdentityExchange tamamlanınca dolar —
    /// tam da "eşleşme WIP" süresi boyunca boş kalırdı).
    pub(crate) fn process_qr_packet(&mut self, cbor_data: &[u8]) -> Result<(String, String, String), String> {
        let packet = QrPacket::from_cbor(cbor_data)?;
        self.pair_with_code(packet.identity_id, packet.device_fingerprint, &packet.device_name, &packet.rendezvous_node, &packet.known_relays, &packet.pairing_nonce)
    }

    /// M129: what a scanned contact code names, for the confirm step before
    /// `process_qr_packet`. The same checks as `pair_with_code` and
    /// `register_contact_from_pairing`; changes nothing, no network.
    /// `short_code` is the one the peer's own main screen shows, `safety_code`
    /// the one `contact_safety_code` shows after pairing.
    pub(crate) fn peek_qr_packet(&self, cbor_data: &[u8]) -> Result<serde_json::Value, String> {
        let packet = QrPacket::from_cbor(cbor_data)?;
        if packet.pairing_nonce.len() != 16 {
            return Err("Geçersiz kişi kodu (nonce)".to_string());
        }
        if !is_fingerprint_hex(&packet.identity_id) || !is_fingerprint_hex(&packet.device_fingerprint) {
            return Err("Geçersiz kişi kodu".to_string());
        }
        if self.my_identity_id().as_deref() == Some(packet.identity_id.as_str()) || self.own_devices.contains_key(&packet.device_fingerprint) {
            return Err("Kendi kodunuzu kişi olarak ekleyemezsiniz".to_string());
        }
        let short = |id: &str| hex::decode(id).map(|raw| identity::format_short_code(&raw)).unwrap_or_default();
        // fable D-02: the name in a code is the code author's choice; for an
        // existing contact show the stored name and say so.
        let known = self.identity_to_contact.get(&packet.identity_id).and_then(|c| self.contacts.get(c));
        Ok(serde_json::json!({
            "name": known.map(|c| c.display_name.clone())
                .unwrap_or_else(|| sanitize_display_name(&packet.device_name).unwrap_or_default()),
            "known_contact": known.is_some(),
            "short_code": short(&packet.identity_id),
            "safety_code": short(&packet.device_fingerprint),
            "identity_id": packet.identity_id,
            "device_fingerprint": packet.device_fingerprint,
        }))
    }

    /// Shared tail of `process_qr_packet` and `process_manual_entry`: the
    /// user scanned or typed a peer's code.
    ///
    /// The contact is registered first and the function returns without
    /// waiting for the network: dial, Noise and the IdentityExchange round
    /// finish in the background, and the chat screen shows "connecting".
    pub(crate) fn pair_with_code(&mut self, identity_id: String, device_fingerprint: String, device_name: &str, rendezvous_node: &str, known_relays: &[String], nonce: &[u8]) -> Result<(String, String, String), String> {
        if nonce.len() != 16 {
            return Err("Geçersiz kişi kodu (nonce)".to_string());
        }
        // Peer-chosen text: it is returned to the UI as the chat title.
        let device_name = sanitize_display_name(device_name).unwrap_or_default();
        // A device this contact already lists as Active: the code proves
        // nothing (identity id and fingerprint are public), so it changes no
        // state of that device: no new pairing secret, no block lifted, and
        // no address (fable D-02); its own AddressAnnounce and the stored
        // addresses reach it. The block has its own
        // control (`unblock_identity`).
        let known_active = self.identity_to_contact.get(&identity_id)
            .and_then(|c| self.contacts.get(c))
            .and_then(|c| c.find_device(&device_fingerprint))
            .map_or(false, |d| d.status == contact::KnownDeviceStatus::Active);
        self.register_contact_from_pairing(identity_id.clone(), device_fingerprint.clone(), device_name.clone())?;
        if known_active {
            if let Err(e) = self.send_identity_exchange_fresh(&device_fingerprint) {
                error!("IdentityExchange gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
            }
            return Ok((identity_id, device_fingerprint, device_name));
        }
        // Goes into each IdentityExchange to this device (`pairing_proof`).
        // ponytail: the row stays after the nonce expired (the proof is then
        // ignored), and is replaced by the next code of the same device.
        self.put_pairing_secret("pn", &device_fingerprint, nonce);
        // Also the secret of our first-contact mailbox for this device
        // (bkz. `first_contact_secrets`): registered before its reply comes.
        self.server_sweep_at = 0;
        // Only a code the user scanned or typed lifts a block or brings back
        // a deleted contact (`contact_removed_locally`), and only once the
        // code was accepted: no packet from the network reaches these lines.
        self.unblock_identity(&identity_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM removed_contacts WHERE identity_id = ?1", params![identity_id]);
        }
        self.dial_pairing_addr(&device_fingerprint, rendezvous_node, known_relays);
        // bkz. `pairing_mailbox_subs` — eşleşme süresince karşı tarafın posta
        // kutusu topic'ine de abone ol (gerçek mesh → hızlı IX/Handshake).
        self.subscribe_pairing_mailbox(&device_fingerprint);
        // Not fatal: the contact is registered, and `publish_envelope` queues
        // the packet and retries it from `poll_events`.
        if let Err(e) = self.send_identity_exchange_fresh(&device_fingerprint) {
            error!("IdentityExchange gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
        }
        // Çoklu-cihaz (spec 1.7 delta): yeni kişi kardeş cihazlarıma da
        // yayılsın (tek cihazsa no-op).
        self.sync_to_siblings();
        Ok((identity_id, device_fingerprint, device_name))
    }

    /// Dials the address a pairing or link code carries, and records its
    /// relay candidates first so the dial can fall back to them. The one
    /// place for any rule on addresses that come from a code.
    pub(crate) fn dial_pairing_addr(&mut self, device_fingerprint: &str, rendezvous_node: &str, known_relays: &[String]) {
        for relay in known_relays.iter().take(MAX_KNOWN_RELAYS) {
            if let Ok(addr) = relay.parse::<Multiaddr>() {
                if let Some(relay_peer_id) = extract_peer_id(&addr) {
                    // As for identify: only a server of ours becomes a relay
                    // candidate. A code filled the list with relays of its
                    // maker, which we then reserved at and gave out in our code.
                    if !self.is_server_peer(&relay_peer_id) {
                        continue;
                    }
                    if let Some(swarm) = &mut self.swarm {
                        swarm.behaviour_mut().kad.add_address(&relay_peer_id, addr.clone());
                    }
                    self.record_known_relay(relay_peer_id, addr);
                }
            }
        }
        if let Ok(addr) = rendezvous_node.parse::<Multiaddr>() {
            if let Some(peer_id) = extract_peer_id(&addr) {
                if let Some(swarm) = &mut self.swarm {
                    swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                }
                // bkz. `device_last_addr` — the first dial may fail (peer
                // offline, Tor not ready); `reconnect_sweep` keeps trying.
                self.remember_device_addr(device_fingerprint, rendezvous_node);
                // `kad.add_address` is only a routing hint and opens nothing.
                self.dial_with_relay_fallback(peer_id, Some(addr));
            }
        }
    }

    /// Kendi `IdentityExchange` paketimizi karşı tarafa gönderir — spec
    /// 1.3'teki "fingerprint-only QR + bağlantıda public key indirme"
    /// adımını taşır. Her iki taraf da eşleşme sonrası bunu birbirine
    /// gönderdiğinde, ikisi de karşı tarafın gerçek public key'lerini
    /// öğrenmiş ve kendi taraflarında fingerprint'i yeniden hesaplayıp
    /// doğrulamış olur (bkz. `process_identity_exchange`).
    pub(crate) fn send_identity_exchange(&mut self, target_device_fingerprint: &str) -> Result<(), String> {
        self.send_identity_exchange_opts(target_device_fingerprint, false)
    }

    /// A (re)pairing the user started, or our reply to one: the peer needs
    /// our IdentityExchange NOW.
    ///
    /// Found on device (2026-09-18): an IdentityExchange is byte-identical
    /// on every send, so its server dedup key (`deposit_dedup_key`) matches
    /// the copy deposited at the previous pairing. `already_deposited`
    /// assumes that copy is still on the server and reports success, but the
    /// peer fetched and acked it long ago. After deleting a contact and
    /// re-adding it within 12 h, a peer that was not directly connected
    /// never got our IdentityExchange. Our side then stayed on "Securing the
    /// connection" and every `ensure_handshake` failed with "Unknown peer
    /// device". The periodic resend paths keep the dedup, which is the
    /// deposit-storm guard.
    pub(crate) fn send_identity_exchange_fresh(&mut self, target_device_fingerprint: &str) -> Result<(), String> {
        self.send_identity_exchange_opts(target_device_fingerprint, true)
    }

    pub(crate) fn send_identity_exchange_opts(&mut self, target_device_fingerprint: &str, fresh: bool) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let own_record = self.own_devices.get(&own_fp).ok_or("Missing own device record")?.clone();

        let prekey = self.current_own_prekey();
        // The nonce of the code we read from this device: its link code
        // while we link it, else its pairing code.
        let peer_nonce = if self.pending_link_target.as_deref() == Some(target_device_fingerprint) {
            self.pending_link_nonce.clone()
        } else {
            self.meta_str(&format!("pn:{}", target_device_fingerprint)).and_then(|v| hex::decode(v).ok()).unwrap_or_default()
        };
        let pairing_proof = if peer_nonce.is_empty() { Vec::new() } else { packet::pairing_nonce_proof(&peer_nonce, &own_fp) };
        // bkz. `link_consent_peer`.
        let (link_consent, link_consent_pq) = if self.link_consent_peer.as_deref() == Some(target_device_fingerprint)
            && self.link_request_open_until > current_time_ms()
        {
            self.sign_link_consent(target_device_fingerprint)?
        } else {
            (Vec::new(), Vec::new())
        };
        // Rounded down so resends stay byte-identical (the deposit dedup keys
        // on the bytes): at most one new copy per interval and target.
        let now = current_time_ms();
        let timestamp = now - now % HANDSHAKE_REDO_MIN_INTERVAL_MS;
        let revokes = self.own_revokes();
        let to_sign = packet::identity_exchange_signing_input(
            &own_identity_id, &own_fp, &own_record.device_name, &pairing_proof, target_device_fingerprint, timestamp, &revokes,
        );
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let sig_classical: Ed25519Signature = own_keys.sign_sk_ed25519.sign(&to_sign);
        let sig_pq: MlDsaSignature<MlDsa87> = own_keys.sign_sk_mldsa.sign(&to_sign);
        let exchange = IdentityExchange {
            identity_id: own_identity_id,
            device_fingerprint: own_fp,
            device_name: own_record.device_name,
            sign_pubkey_ed25519: own_record.sign_pubkey_ed25519,
            sign_pubkey_mldsa: own_record.sign_pubkey_mldsa,
            kem_pubkey_x25519: own_record.kem_pubkey_x25519,
            kem_pubkey_mlkem: own_record.kem_pubkey_mlkem,
            // Spec dışı, hata düzeltmesi (kullanıcı: "özellikle ikincil
            // cihazlardan gönderilen mesajlar çok sıkıntılı"): bu cihaz bir
            // ikincilse, birincilin bize verdiği imzalı `DeviceAdd`'i BURADA
            // da taşı — karşı taraf ayrı bir `DeviceAddNotice`'ın ona ulaşmış
            // olmasına bağımlı kalmadan (bkz. `process_identity_exchange`)
            // bizi tek paketle doğrulayabilsin.
            device_add: self.own_device_add.clone(),
            revokes,
            device_add_signer: self.own_device_add.as_ref().and_then(|da| self.synced_device_for(&da.added_by)),
            pairing_proof,
            link_consent,
            link_consent_pq,
            prekey,
            timestamp,
            signature: sig_classical.to_bytes().to_vec(),
            signature_pq: sig_pq.encode().to_vec(),
        };
        let envelope = NetworkEnvelope::IdentityExchange(exchange);
        if fresh {
            if let Ok(bytes) = ciborium_bytes(&envelope) {
                let key = server_client::deposit_dedup_key(&envelope, &bytes);
                self.server_deposited.retain(|(_, k), _| *k != key);
            }
        }
        self.publish_envelope(target_device_fingerprint, &envelope)
    }

    /// Gelen bir `IdentityExchange` paketini işler: taşınan public key'lerden
    /// fingerprint'i YENİDEN HESAPLAR ve paketin `device_fingerprint`
    /// alanıyla eşleştiğini doğrular (spec 1.3 — "bu fingerprint ile
    /// karşılaştırılır"). Eşleşmezse paket reddedilir (sahte/bozuk public
    /// key ima eder). Eşleşirse `known_remote_devices`'a kaydedilir.
    pub(crate) fn process_identity_exchange(&mut self, source: Option<PeerId>, exchange: &IdentityExchange) -> Result<(), String> {
        // Bu paket GELMEDEN ÖNCE bu cihazı zaten tanıyor muyduk? Aşağıdaki
        // karşılıklı-yanıt bloğunun tek durma koşulu bu (bkz.
        // `last_identity_exchange_reply`).
        let knew_device_before = self.known_remote_devices.contains_key(&exchange.device_fingerprint);
        // Our own packet, reflected back: with its signed DeviceAdd it used to
        // be stored as a sibling of ourselves.
        if self.own_device_keys.contains_key(&exchange.device_fingerprint) {
            return Err("IdentityExchange kendi cihazımızdan geldi, yok sayıldı".to_string());
        }
        // Key lengths and fingerprint, bkz. `identity::keys_match_fingerprint`.
        if !exchange.keys_match_fingerprint() {
            return Err(format!("IdentityExchange anahtarları fingerprint ile tutarsız: {}", exchange.device_fingerprint));
        }
        // L-40: same window as a HandshakeInit (it also waits in the mailbox).
        let now = current_time_ms();
        let window = if exchange.timestamp < now { HANDSHAKE_MAX_AGE_MS } else { HANDSHAKE_MAX_SKEW_MS };
        if now.abs_diff(exchange.timestamp) > window {
            return Err("IdentityExchange timestamp'i pencere dışında, reddedildi".to_string());
        }
        // Signed by the device itself: the packet travels unsealed, and the
        // fingerprint covers neither `device_name` nor `identity_id`. A
        // version before this one sends no signature and cannot pair with us.
        // The signature also names this device as the recipient (L-40).
        let own_fp = self.get_active_own_device_fingerprint()?;
        verify_hybrid_signature_with(
            &packet::identity_exchange_signing_input(
                &exchange.identity_id, &exchange.device_fingerprint, &exchange.device_name, &exchange.pairing_proof,
                &own_fp, exchange.timestamp, &exchange.revokes,
            ),
            &exchange.signature, &exchange.signature_pq,
            &exchange.sign_pubkey_ed25519, &exchange.sign_pubkey_mldsa,
        ).map_err(|e| format!("IdentityExchange imzası geçersiz: {}", e))?;
        // No `record_peer_id_if_known` here (security review 2026-09-27): the
        // signature proves who WROTE the packet, not who delivered it, and a
        // matching fingerprint only proves the public keys are consistent. The keys are public, so any
        // contact who knows this device could build this packet and get its own
        // PeerId mapped to it, then take our direct sends to the device and fake
        // AckBatch receipts for them. The signed Handshake that follows maps the
        // connection, and a pairing address maps it on connect.
        // Our reply goes back over the connection this came in on (see
        // `pairing_reply_peer`): it carries only our public IX and a
        // HandshakeInit sealed to this device's keys.
        if let Some(pid) = source.filter(|p| !self.is_server_peer(p)) {
            self.pairing_reply_peer.insert(exchange.device_fingerprint.clone(), pid);
        }
        // A first device that read the link code this device shows: our reply
        // carries our half of its DeviceAdd (bkz. `link_consent_peer`).
        let link_proved = exchange.identity_id == exchange.device_fingerprint && self.link_proof_valid(exchange);
        if link_proved {
            self.link_consent_peer = Some(exchange.device_fingerprint.clone());
        }

        // Spec dışı, güvenlik denetimi düzeltmesi: önceden bu fonksiyon
        // `evaluate_sender_device`/spec 2.2 TOFU+uyarı karar ağacına HİÇ
        // girmiyordu — zaten bilinen bir Contact için gelen BEKLENMEYEN
        // yeni bir cihaz, hiçbir "tanınmayan cihaz" uyarısı tetiklenmeden
        // sessizce `known_remote_devices`'a yazılıyordu (bkz. SECURITY.md).
        // Artık `process_qr_packet`/`process_manual_entry` ile AYNI karar
        // ağacından geçiyor: yeni kişi ise TOFU ile eklenir (aşağıdaki
        // `register_contact_from_pairing` çağrısına gerek KALMAZ, bu kolu
        // `evaluate_sender_device` zaten kendi içinde yapar), bilinen bir
        // kişinin BEKLENMEYEN yeni cihazıysa spec 2.2 "BLOKLA" kuralı
        // uygulanır — bu fonksiyon `known_remote_devices`'a HİÇ yazmadan,
        // sessizce döner; kullanıcı `pending_device_alerts`'ten kabul/red
        // etmeden bu cihazdan gelen/bu cihaza giden hiçbir paket işlenmez.
        // Çoklu-cihaz (spec 1.5): bu gelen cihaz benim KENDİ kimliğimin bir
        // KARDEŞ cihazı mı? (ör. az önce onayladığım ikincil cihaz, veya bir
        // kardeşin duyurduğu üçüncü cihaz.) Öyleyse KİŞİ karar ağacına (TOFU/
        // uyarı) HİÇ girmez — doğrudan kardeş olarak (identity_id = kendi
        // kimliğim) kaydedilir.
        let fp = exchange.device_fingerprint.clone();
        let my_id = self.my_identity_id();
        // The link the user approved is honoured for as long as it is retried,
        // not for the rest of the process lifetime.
        let is_pending_link = self.pending_link_target.as_deref() == Some(fp.as_str())
            && current_time_ms().saturating_sub(self.pending_link_started_at) <= PENDING_LINK_RETRY_HORIZON_MS;

        // A revoked device stays revoked. Its record is kept with
        // `is_active = false`; the device still holds its keys, so its
        // IdentityExchange is byte-valid, and storing the record below with
        // `is_active = true` gave a revoked sibling contacts, groups and the
        // archive key again on the next `sync_to_siblings`. Only the user
        // brings a device back: linking it again (`is_pending_link`), or
        // pairing with the contact again (the contact entry is Active again).
        if let Some(prev) = self.known_remote_devices.get(&fp) {
            if !prev.is_active && !is_pending_link {
                let paired_again = self.identity_to_contact.get(&prev.identity_id)
                    .and_then(|cid| self.contacts.get(cid))
                    .map_or(false, |c| c.is_known_active(&fp));
                if !paired_again {
                    return Err("IdentityExchange iptal edilmiş bir cihazdan geldi, yok sayıldı".to_string());
                }
            }
        }
        // Revoked by its owner, perhaps before we ever saw it (the revoke came
        // with another device's IdentityExchange): its DeviceAdd still
        // verifies, and would make it a device of the contact again.
        // (The link the user is making now may bring back a device revoked earlier.)
        if !is_pending_link && self.owner_revoked(&exchange.identity_id, &fp) {
            return Err("IdentityExchange sahibinin iptal ettiği bir cihazdan geldi, yok sayıldı".to_string());
        }
        // Checked before `as_sibling` is computed: a sibling that introduces
        // itself with its signed DeviceAdd is a sibling from this first packet.
        if !self.verified_device_adds.contains_key(&fp) {
            if let Some(da) = &exchange.device_add {
                let consistent = da.new_device_fingerprint == fp && da.identity_id == exchange.identity_id;
                // For my own identity this device counts too (it is not in
                // `known_remote_devices`), as in `approve_device_link`.
                // Revoked records count too, against a wider cap: they are
                // kept for good (they stop a revival), and add+revoke cycles
                // grew them without end.
                let under_cap = self.known_remote_devices.contains_key(&fp) || {
                    self.known_remote_devices.values()
                        .filter(|d| d.identity_id == da.identity_id && d.is_active)
                        .count() + usize::from(my_id.as_deref() == Some(da.identity_id.as_str()))
                        < identity::MAX_ACTIVE_DEVICES
                    && self.known_remote_devices.values().filter(|d| d.identity_id == da.identity_id).count()
                        < 4 * identity::MAX_ACTIVE_DEVICES
                };
                if consistent
                    && under_cap
                    && self.verify_device_auth(
                        &da.identity_id, &da.new_device_fingerprint, &da.added_by,
                        &da.signature, &da.signature_pq, false,
                    ).is_ok()
                    && Self::add_has_consent(da, &exchange.sign_pubkey_ed25519, &exchange.sign_pubkey_mldsa)
                {
                    self.verified_device_adds.insert(fp.clone(), da.identity_id.clone());
                    self.remember_device_add(da);
                }
            }
        }
        let is_sibling_by_add = my_id.is_some()
            && self.verified_device_adds.get(&fp).map(|s| Some(s) == my_id.as_ref()).unwrap_or(false);
        let is_existing_sibling = self.known_remote_devices.get(&fp)
            .map(|d| Some(&d.identity_id) == my_id.as_ref()).unwrap_or(false);
        let as_sibling = is_pending_link || is_sibling_by_add || is_existing_sibling;

        if !as_sibling {
            // Spec 2.2: bir `DeviceAddNotice` ile önceden imzalı olarak
            // duyurulmuş bir cihaz mı (NewDeviceViaSignedAdd — sessizce kabul,
            // uyarı YOK)? Aksi halde bilinen bir kişinin beklenmeyen yeni
            // cihazı BLOKLANIR.
            //
            // Spec dışı, hata düzeltmesi (kullanıcı: "özellikle ikincil
            // cihazlardan gönderilen mesajlar çok sıkıntılı"): `verified_
            // device_adds` önceden SADECE ayrı bir `DeviceAddNotice` paketiyle
            // dolduruluyordu — o paket, kişi o an offline'sa/store-and-forward
            // ölüyse (bkz. Defter — mail kotası kilitlenmesi) hiç ulaşmayabilir
            // ve ikincil cihazın attığı HER mesaj süresiz BLOKLANIR. Artık
            // ikincil cihazın gönderdiği her `IdentityExchange` de kendi
            // imzalı `DeviceAdd`'ini taşıyor (bkz. `send_identity_exchange`),
            // o yüzden ayrı bir bildirime bağımlı kalmadan burada DOĞRUDAN
            // doğrulayıp `verified_device_adds`'a yazabiliriz — güvenlik
            // modeli `apply_device_add_notice` ile birebir aynı (imza +
            // fingerprint tutarlılığı + aktif cihaz üst sınırı), sadece
            // taşıyıcı paket farklı.
            // (The signed `DeviceAdd` this packet carries was checked above,
            // before `as_sibling`.)
            let signed = self.verified_device_adds.get(&fp).map(|s| s.as_str()) == Some(exchange.identity_id.as_str());
            // `identity_id` IdentityExchange'te imzasız bir İDDİA. İmzalı bir
            // DeviceAdd olmadan (1) bilinen bir cihazın kimliği değiştirilemez,
            // (2) kimse BENİM kimliğimi sahiplenemez — aksi halde kayıt
            // `identity_id = benim` olarak yazılır, cihaz sonraki pakette
            // "kardeş" sayılır ve `SiblingHistoryRequest`/`sync_to_siblings`
            // ile tüm geçmişimi, kişilerimi ve arşiv anahtarımı alırdı.
            if !signed {
                // The claim must be bound to the device: it is the device's
                // own fingerprint (a first device), or the identity's first
                // device signed this device's DeviceAdd and the packet proves
                // it by itself. A bare claim let anyone take an identity we
                // did not know yet, by IdentityExchange or by a shown code.
                // ponytail: a device linked by another secondary cannot prove
                // it this way, and a version without `device_add_signer`
                // cannot either. Both are still accepted where the signer is
                // already known (`signed`), and rejected as a first device.
                if exchange.identity_id != fp {
                    if !Self::identity_proved_by_root(exchange) {
                        return Err("IdentityExchange kimlik iddiası cihaza bağlı değil".to_string());
                    }
                }
                if my_id.as_deref() == Some(exchange.identity_id.as_str()) {
                    return Err("IdentityExchange kendi kimliğimizi imzalı DeviceAdd olmadan iddia ediyor".to_string());
                }
                if let Some(prev) = self.known_remote_devices.get(&fp) {
                    if prev.identity_id != exchange.identity_id {
                        return Err("IdentityExchange bilinen bir cihazın kimliğini imzasız değiştirmeye çalışıyor".to_string());
                    }
                }
            }
            // İmzalı kendi-kimlik = yeni kardeş cihaz; kişi karar ağacına
            // (TOFU kendimizi kişi olarak eklerdi) girmez.
            if my_id.as_deref() != Some(exchange.identity_id.as_str()) {
                let pairing_proved = self.pairing_proof_valid(exchange);
                let outcome = self.evaluate_sender_device(&exchange.identity_id, &fp, signed, &exchange.device_name, pairing_proved);
                if outcome == DeviceCheckOutcome::UnverifiedNewDeviceAlert {
                    return Ok(());
                }
                // Stored only for a device that was accepted: written before
                // that check, any stranger with a self-made root filled
                // `app_meta` with `da:` rows (10 KB each, never deleted).
                if !signed && exchange.identity_id != fp {
                    if let Some(da) = &exchange.device_add {
                        self.remember_device_add(da);
                    }
                }
            }
        }

        // A link completes only with the device's own consent, and nothing of
        // the device is stored before it: written first, a failed link (a
        // wrong QR, a device that refuses to adopt us) left it a permanent
        // sibling that got our contacts, groups and history.
        let mut link_add = None;
        if is_pending_link {
            let active_sibling = is_sibling_by_add
                || self.known_remote_devices.get(&fp).map_or(false, |d| d.is_active && Some(&d.identity_id) == my_id.as_ref());
            // Signed only with the device's own half: nobody accepts an add
            // without it. A packet without it (sent before the device saw our
            // proof) leaves the link pending for the next one.
            let signed_add = self.sign_device_add(&fp, &exchange.link_consent, &exchange.link_consent_pq)
                .and_then(|da| match Self::add_has_consent(&da, &exchange.sign_pubkey_ed25519, &exchange.sign_pubkey_mldsa) {
                    true => Ok(da),
                    false => Err("yeni cihazın onay imzası yok ya da geçersiz".to_string()),
                });
            match signed_add {
                Ok(da) => link_add = Some(da),
                Err(e) if !active_sibling => {
                    warn!("Cihaz bağlama henüz tamamlanamadı, cihaz kaydedilmedi: {}", e);
                    return Ok(());
                }
                Err(e) => error!("sign_device_add başarısız (cihaz bağlama tamamlanamadı): {}", e),
            }
            // The device consented, so the contact it was before the link
            // (its own identity, this device only) is a ghost now. Removed
            // only here: `approve_device_link` ran before anything was proved.
            if link_add.is_some() {
                let ghosts: Vec<String> = self.contacts.values()
                    .filter(|c| c.trusted_identity_id == fp && self.contact_fingerprints_all(c).iter().all(|f| *f == fp))
                    .map(|c| c.contact_id.clone())
                    .collect();
                for cid in ghosts {
                    if let Err(e) = self.delete_contact(&cid) {
                        warn!("Bağlanan cihazın eski kişi kaydı silinemedi: {}", e);
                    }
                }
            }
        }

        let now = current_time_ms();
        let stored_identity_id = if as_sibling {
            my_id.clone().unwrap_or_else(|| exchange.identity_id.clone())
        } else {
            exchange.identity_id.clone()
        };
        // This packet is not authenticated (the keys are public): for a known
        // device it changes only what was decided above, the identity (link)
        // and the activity (link, pairing again). Name and `last_seen` stay.
        // The keys are the ones the fingerprint commits to (lengths checked).
        let prev = self.known_remote_devices.get(&fp);
        let record = DeviceRecord {
            device_fingerprint: fp.clone(),
            identity_id: stored_identity_id,
            sign_pubkey_ed25519: exchange.sign_pubkey_ed25519.clone(),
            sign_pubkey_mldsa: exchange.sign_pubkey_mldsa.clone(),
            kem_pubkey_x25519: exchange.kem_pubkey_x25519.clone(),
            kem_pubkey_mlkem: exchange.kem_pubkey_mlkem.clone(),
            device_name: match prev {
                Some(p) => p.device_name.clone(),
                None => sanitize_display_name(&exchange.device_name).unwrap_or_default(),
            },
            is_active: true,
            last_seen: prev.filter(|p| p.is_active).map_or(now, |p| p.last_seen),
        };
        if prev != Some(&record) {
            self.persist_remote_device(&record);
            self.known_remote_devices.insert(fp.clone(), record);
        }
        // The code of ours this device read: kept past the code's 24 h as
        // the secret of the first-contact mailboxes between the two devices
        // (bkz. `first_contact_secrets`).
        let proved_nonce = if link_proved {
            Some(self.link_request_nonce.clone())
        } else {
            self.pairing_nonces().into_iter().map(|(n, _)| n)
                .find(|n| {
                    // Constant time (fable H-10).
                    let proof = packet::pairing_nonce_proof(n, &fp);
                    proof.len() == exchange.pairing_proof.len()
                        && proof.iter().zip(&exchange.pairing_proof).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
                })
        };
        if let Some(nonce) = proved_nonce {
            self.put_pairing_secret("pk", &fp, &nonce);
        }
        // The revokes this contact's identity signed (bkz.
        // `IdentityExchange.revokes`). The packet is not authenticated, each
        // revoke is: it is checked against a known active device of the
        // identity, the sender included now that its keys are stored.
        if !as_sibling {
            // At most as many as the owner-revoke tombstones hold (fable
            // D-06): a list of hundreds re-ran every check on each exchange.
            for revoke in exchange.revokes.iter().take(32) {
                if revoke.identity_id == exchange.identity_id
                    && !self.own_device_keys.contains_key(&revoke.revoked_device_fingerprint)
                    && !self.owner_revoked(&revoke.identity_id, &revoke.revoked_device_fingerprint)
                {
                    if let Err(e) = self.apply_device_revoke_notice(revoke, &fp) {
                        warn!("IdentityExchange ile gelen iptal uygulanmadı: {}", e);
                    }
                }
            }
        }
        // Our own revoke, carried back by a sibling (bkz. `answer_revoked_sibling`):
        // the one notice sent at the revoke is lost if the revoking device
        // dies at that moment, and this device would never wipe itself.
        if as_sibling {
            let own_fp = self.get_active_own_device_fingerprint().ok();
            if let Some(revoke) = exchange.revokes.iter().find(|r| Some(&r.revoked_device_fingerprint) == own_fp.as_ref()).cloned() {
                match self.apply_device_revoke_notice(&revoke, &fp) {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(e) => warn!("IdentityExchange ile gelen kendi iptalimiz uygulanmadı: {}", e),
                }
            }
        }
        if is_pending_link {
            // bkz. `approve_device_link` dokümantasyonu — QR fingerprint-only
            // olduğundan yeni cihazın GERÇEK anahtarları ancak burada (bu
            // IdentityExchange'de) öğrenilir; bağlanma akışının geri kalanı
            // (imzalı DeviceAdd, yeni cihaza tam senkron, kişilere duyuru)
            // ancak şimdi tamamlanabilir.
            if let Some(my_identity_id) = my_id.clone() {
                match link_add.ok_or_else(|| "yeni cihazın onayı yok".to_string()) {
                    Ok(device_add) => {
                        // bkz. `device_add_proof`: the first device cannot
                        // make this add again by itself.
                        self.remember_device_add(&device_add);
                        // Cleared only now: on an error the next
                        // IdentityExchange of the device tries again.
                        self.set_pending_link(None);
                        let mut parts = self.build_sync_payloads().into_iter();
                        self.meta_del("pending_link_nonce");
                        let grant = MessageContent::DeviceLinkGrant {
                            nonce: std::mem::take(&mut self.pending_link_nonce),
                            identity_id: my_identity_id,
                            device_add: device_add.clone(),
                            sync: parts.next().unwrap_or_else(|| self.build_sync_payload()),
                        };
                        if let Err(e) = self.send_message_content(fp.clone(), &grant, None) {
                            error!("DeviceLinkGrant gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
                        }
                        // The other parts: `sync_to_siblings` below sends every
                        // part to every sibling, this device included.
                        // Tüm kişilere yeni cihazı duyur (spec 1.5 adım 5).
                        self.broadcast_device_add_to_contacts(&device_add);
                        // Var olan kardeş cihazlar da yeni cihazı öğrensin (3+ cihaz).
                        self.sync_to_siblings();
                    }
                    Err(e) => error!("sign_device_add başarısız (cihaz bağlama tamamlanamadı): {}", e),
                }
            }
        }

        // Tek taraflı taranan bir QR senaryosunda (biz taradık, karşı taraf
        // henüz bizim IdentityExchange'imizi görmedi) karşılıklı exchange'i
        // tamamlamak için biz de kendi paketimizi göndeririz.
        //
        // AMA yalnızca bu cihazı BU PAKETLE yeni öğrendiysek. Koşulsuz yanıt
        // vermek sonsuz bir ping-pong demekti: karşı taraf da aynı kodu
        // çalıştırdığı için her yanıt bir yanıt daha doğuruyordu (bkz.
        // `last_identity_exchange_reply` alan notu). Yeni öğrendiğimizde
        // yanıtlamak akışı bitirir: karşı taraf bizi ZATEN tanıdığı için
        // (eşleşmeyi o başlattı) yanıtımıza yanıt vermez.
        //
        // Zaman kapısı ikinci emniyet: ilerideki bir yol "yeni cihaz" sanıp
        // döngüyü yeniden açarsa bile trafik cihaz başına dakikada bire iner.
        let now = current_time_ms();
        let since_last_reply = self
            .last_identity_exchange_reply
            .get(&exchange.device_fingerprint)
            .map(|t| now.saturating_sub(*t));
        let reply_due = since_last_reply.map_or(true, |d| d > IDENTITY_EXCHANGE_REPLY_MIN_INTERVAL_MS);
        // `knew_device_before` burada AYRICA profil fotoğrafı gönderimini de
        // kapılıyor (bkz. aşağıdaki blok / defter #18).
        let first_contact = !knew_device_before;
        // Peer re-added us (its IX arrives) while we still hold its OLD record — e.g. it deleted
        // us and scanned/typed our code again. It lost our keys and can only get them from our
        // IX; without a reply it stays at "Unknown peer device" forever. Reply when we are not
        // the initiator.
        let peer_readded_us = !first_contact
            && !as_sibling
            && !self.pairing_mailbox_subs.contains_key(&exchange.device_fingerprint);
        info!("IdentityExchange işlendi: peer={} knew_before={} as_sibling={} reply_due={} peer_readded_us={} we_have_pairing_sub={}",
            &exchange.device_fingerprint[..8.min(exchange.device_fingerprint.len())], knew_device_before, as_sibling, reply_due,
            peer_readded_us, self.pairing_mailbox_subs.contains_key(&exchange.device_fingerprint));
        if (first_contact || peer_readded_us || link_proved) && reply_due {
            self.last_identity_exchange_reply.insert(exchange.device_fingerprint.clone(), now);
            // We started this pairing ourselves (QR/manual subscribed the peer's
            // mailbox): our fresh IX is already on its way, so the reply may be
            // deduplicated. Otherwise the peer (re)added us and needs our IX even if
            // identical bytes were deposited before.
            let we_initiated = self.pairing_mailbox_subs.contains_key(&exchange.device_fingerprint);
            // An IdentityExchange is plaintext and byte-identical on every
            // send, so a captured one can be replayed. Each replay of a known
            // contact's packet used to clear the deposit dedup: one server
            // deposit a minute per contact, past the deposit-storm guard. The
            // dedup is now cleared at most once per handshake-redo interval;
            // in between the reply still goes out, deduplicated.
            let fresh = !we_initiated
                && (first_contact || since_last_reply.map_or(true, |d| d > HANDSHAKE_REDO_MIN_INTERVAL_MS));
            // bkz. `pairing_mailbox_subs` — cevabımız (IX + ardından Handshake)
            // karşı tarafa gerçek bir mesh üzerinden gitsin diye onun posta
            // kutusu topic'ine de abone ol.
            self.subscribe_pairing_mailbox(&exchange.device_fingerprint);
            let _ = self.send_identity_exchange_opts(&exchange.device_fingerprint, fresh);
        }

        // Spec dışı: eşleşme tamamlanır tamamlanmaz kendi profil
        // fotoğrafımızı (VARSA) bu yeni kişiye bir kez göndeririz — daha
        // sonra fotoğraf değişirse `set_own_profile_picture` zaten TÜM
        // kişilere tekrar gönderir, burası SADECE ilk eşleşme anını
        // kapsıyor (her yeniden bağlanışta değil, spam önleme).
        //
        // Defter #18: yorum "SADECE ilk eşleşme anı" diyordu ama kodda o
        // kapı YOKTU — blok, gelen HER `IdentityExchange`'te çalışıyordu.
        // Yukarıdaki `reply_due` kısıtı yalnızca karşı exchange'i koruyor,
        // bunu değil. `reconnect_sweep` bekleyen bir bağlanma hedefine 15
        // saniyede bir `IdentityExchange` yollayabildiği için karşı taraf
        // her seferinde ~250 KB'lık bir avatarla yanıtlanıyordu — üstelik
        // `ProfileUpdate` hem `needs_delivery_confirmation` hem
        // `regen_content` listelerinde olduğundan her kopya
        // `awaiting_confirmation`'a girip diske yazılıyor ve iki güne kadar
        // yeniden deneniyordu. `first_contact` ile yorum artık gerçek.
        if !as_sibling && first_contact {
            // Ad, `IdentityExchange.device_name` ile ZATEN ulaştı; burada
            // tekrar göndermenin sebebi `ProfileUpdate`'in bir DELTA değil
            // TAM GÖRÜNTÜ olması (bkz. packet.rs notu) — adı boş bırakmak
            // "adım yok" demek olurdu.
            if let Some(avatar) = self.get_own_avatar() {
                let content = MessageContent::ProfileUpdate {
                    avatar_jpeg: Some(avatar),
                    display_name: self.own_display_name(),
                };
                if let Err(e) = self.send_message_content(exchange.device_fingerprint.clone(), &content, None) {
                    error!("Eşleşme sonrası ProfileUpdate gönderilemedi: {}", e);
                }
            }
        }

        // İKİ CİHAZLI GERÇEK TESTTE BULUNDU (2026-09-06): IdentityExchange
        // artık (bkz. `pairing_mailbox_subs`) saniyeler içinde tamamlanıyor,
        // ama el sıkışmayı BAŞLATAN tek şey ChatActivity'nin sohbet açılışında
        // ya da mesaj gönderiminde yaptığı `ensure_handshake` çağrısıydı —
        // ve mesaj gönderimi artık ratchet hazır olana kadar KİLİTLİ. Sonuç:
        // IX bitiyor, `known_remote_devices` doluyor, ama hiçbir şey el
        // sıkışmayı tetiklemiyor; kullanıcı sonsuza kadar "Güvenli bağlantı
        // kuruluyor" ekranında kalıyordu. Artık IX'i işler işlemez, eğer bu
        // cihazla AKTİF olarak eşleşme sürecindeysek (`pairing_mailbox_subs`)
        // ve henüz ratchet yoksa el sıkışmayı BURADAN başlatıyoruz. İki taraf
        // da yapar; `process_handshake_init` içindeki "küçük fingerprint =
        // kanonik initiator" kuralı eşzamanlı başlatmayı deterministik çözer.
        // bkz. `early_handshakes` — karşı taraf bize kendi HandshakeInit'ini
        // biz onun kimliğini öğrenmeden göndermiş olabilir; artık
        // `known_remote_devices`'ta, o yüzden şimdi işlenebilir. Bu bir
        // RESPONDER ratchet üretir → aşağıdaki `initiate_handshake_with`
        // (both-initiate) atlanır, uyumsuz iki initiator sorunu oluşmaz.
        // Before any handshake below: it should already go to the prekey.
        if let Some(prekey) = &exchange.prekey {
            if let Some(device) = self.known_remote_devices.get(&exchange.device_fingerprint).cloned() {
                self.store_peer_prekey(&exchange.device_fingerprint, prekey, &device, false);
            }
        }
        self.replay_early_handshake(&exchange.device_fingerprint);

        if !as_sibling
            && self.pairing_mailbox_subs.contains_key(&exchange.device_fingerprint)
            && !self.ratchets.contains_key(&exchange.device_fingerprint)
        {
            if let Err(e) = self.initiate_handshake_with(&exchange.device_fingerprint) {
                warn!("Eşleşme sonrası el sıkışma başlatılamadı (kuyruğa alındı, yeniden denenecek): {}", e);
            }
        }

        Ok(())
    }

    /// bkz. `IdentityExchange.device_add_signer`: the DeviceAdd is for this
    /// device and this identity, it is signed by the device whose fingerprint
    /// IS the identity id, and the carried keys are that device's keys.
    pub(crate) fn identity_proved_by_root(exchange: &IdentityExchange) -> bool {
        match (&exchange.device_add, &exchange.device_add_signer) {
            (Some(da), Some(signer)) => Self::add_proves_identity(
                &exchange.identity_id, &exchange.device_fingerprint, da, signer,
                &exchange.sign_pubkey_ed25519, &exchange.sign_pubkey_mldsa,
            ),
            _ => false,
        }
    }

    /// bkz. `packet::DeviceAddProof`: the DeviceAdd is for this device and
    /// this identity, it is signed by the device whose fingerprint IS the
    /// identity id, and `signer` holds that device's keys.
    /// `device_ed25519`/`device_mldsa` are the added device's signing keys;
    /// the caller has checked them against `device_fingerprint`.
    pub(crate) fn add_proves_identity(identity_id: &str, device_fingerprint: &str, da: &DeviceAdd, signer: &SyncedDevice, device_ed25519: &[u8], device_mldsa: &[u8]) -> bool {
        if !Self::add_has_consent(da, device_ed25519, device_mldsa) {
            return false;
        }
        if da.identity_id != identity_id
            || da.new_device_fingerprint != device_fingerprint
            || da.added_by != identity_id
            || signer.device_fingerprint != da.added_by
            || !signer.keys_match_fingerprint()
        {
            return false;
        }
        let root = DeviceRecord {
            device_fingerprint: da.added_by.clone(),
            identity_id: da.identity_id.clone(),
            sign_pubkey_ed25519: signer.sign_pubkey_ed25519.clone(),
            sign_pubkey_mldsa: signer.sign_pubkey_mldsa.clone(),
            kem_pubkey_x25519: signer.kem_pubkey_x25519.clone(),
            kem_pubkey_mlkem: signer.kem_pubkey_mlkem.clone(),
            device_name: String::new(),
            is_active: true,
            last_seen: 0,
        };
        let msg = Self::device_auth_signing_bytes(&da.identity_id, &da.new_device_fingerprint, &da.added_by, false);
        verify_hybrid_signature(&msg, &da.signature, &da.signature_pq, &root).is_ok()
    }

    /// A third party's claim "device `fp` is identity `identity_id`'s": true
    /// for a first device, otherwise only with a proof among `proofs`.
    pub(crate) fn claim_is_bound(identity_id: &str, fp: &str, proofs: &[packet::DeviceAddProof], device_ed25519: &[u8], device_mldsa: &[u8]) -> bool {
        identity_id == fp || proofs.iter().any(|p| Self::add_proves_identity(identity_id, fp, &p.device_add, &p.signer, device_ed25519, device_mldsa))
    }

    /// The verified `DeviceAdd` of a device, kept so this side can prove the
    /// device's identity to others (`device_add_proof`).
    pub(crate) fn remember_device_add(&self, da: &DeviceAdd) {
        if let Ok(bytes) = ciborium_bytes(da) {
            self.meta_put(&format!("da:{}", da.new_device_fingerprint), &hex::encode(bytes));
        }
    }

    /// bkz. `packet::DeviceAddProof`. None for a first device (it needs
    /// none), and where the add or its signer's keys are not held.
    pub(crate) fn device_add_proof(&self, fp: &str) -> Option<packet::DeviceAddProof> {
        let device_add = match &self.own_device_add {
            Some(da) if da.new_device_fingerprint == fp => da.clone(),
            _ => {
                let v = self.db.as_ref()?
                    .query_row("SELECT v FROM app_meta WHERE k = ?1", params![format!("da:{}", fp)], |r| r.get::<_, String>(0)).ok()?;
                ciborium::from_reader(hex::decode(v).ok()?.as_slice()).ok()?
            }
        };
        let signer = self.synced_device_for(&device_add.added_by)?;
        Some(packet::DeviceAddProof { device_add, signer })
    }

    /// Spec 1.4: manuel giriş, QR ile aynı bilgiyi taşıyan bir metin/kod
    /// formatı. Burada Base32 kişi kodu + fingerprint + rendezvous adresini
    /// `|` ile ayrılmış tek satır olarak kabul ediyoruz (spec bu formatı
    /// tam belirtmemiş; en basit, insan tarafından elle girilebilir biçim).
    /// bkz. `process_qr_packet` dokümantasyonu — AYNI gerekçeyle,
    /// `(identity_id, device_fingerprint, device_name)` döner.
    pub(crate) fn process_manual_entry(&mut self, text: &str) -> Result<(String, String, String), String> {
        const FORMAT_ERR: &str = "Beklenen format: identity_id|device_fingerprint|nonce|device_name|rendezvous_node";
        // The device name is free text and may itself contain `|`: the first
        // two fields are taken from the left, the address from the right.
        let (head, rendezvous_node) = text.trim().rsplit_once('|').ok_or(FORMAT_ERR)?;
        let mut head = head.splitn(4, '|');
        let (identity_id, device_fingerprint, nonce, device_name) = match (head.next(), head.next(), head.next(), head.next()) {
            (Some(a), Some(b), Some(n), Some(c)) => (a.to_string(), b.to_string(), hex::decode(n).map_err(|_| FORMAT_ERR)?, c.to_string()),
            _ => return Err(FORMAT_ERR.to_string()),
        };
        self.pair_with_code(identity_id, device_fingerprint, &device_name, rendezvous_node, &[], &nonce)
    }

    pub(crate) fn register_contact_from_pairing(&mut self, identity_id: String, device_fingerprint: String, device_name: String) -> Result<(), String> {
        // DİKKAT: engel kaldırma BURADA DEĞİL. Bu fonksiyon yüz yüze
        // eşleşmenin yanı sıra grup kefaletinden
        // (`adopt_vouched_member_devices`) ve TOFU yolundan
        // (`evaluate_sender_device`) da çağrılıyor — engeli burada
        // kaldırmak, kurucusu engelli birini kefil ettiğinde engelin
        // SESSİZCE kalkması demek olurdu. Engel yalnızca `process_qr_packet`
        // ve `process_manual_entry` içinde, yani kullanıcının fiziksel
        // olarak bir kod okuttuğu noktada kalkıyor.
        //
        // Both values come from outside (QR, typed code, IdentityExchange,
        // group vouching) and no caller validated them: scanning our own code
        // made a contact of ourselves.
        if !is_fingerprint_hex(&identity_id) || !is_fingerprint_hex(&device_fingerprint) {
            return Err("Geçersiz kişi kodu".to_string());
        }
        if self.my_identity_id().as_deref() == Some(identity_id.as_str()) || self.own_devices.contains_key(&device_fingerprint) {
            return Err("Kendi kodunuzu kişi olarak ekleyemezsiniz".to_string());
        }
        let now = current_time_ms();
        if let Some(contact_id) = self.identity_to_contact.get(&identity_id).cloned() {
            // A known identity. Only a device this contact already lists can
            // come back here (one the user revoked, or whose alert they
            // rejected: scanning its code again is the consent). An unknown
            // fingerprint used to be added as an Active device with no
            // DeviceAdd: a code with a known contact's (public) identity id
            // and the attacker's own fingerprint made the attacker that
            // contact. A real new device arrives with a signed DeviceAdd in
            // its IdentityExchange.
            let contact = self.contacts.get_mut(&contact_id).ok_or("Kişi bulunamadı")?;
            match contact.find_device(&device_fingerprint).map(|d| (d.status, d.owner_revoked)) {
                Some((contact::KnownDeviceStatus::Active, _)) => return Ok(()),
                Some((_, true)) => return Err("Bu cihaz sahibi tarafından iptal edilmiş".to_string()),
                Some(_) => {}
                // An empty device list is no TOFU slot either: a public fp of
                // an unrelated device became this contact's Active device.
                None => return Err("Bu kod, kişilerinizdeki bir kimliği başka bir cihazla taşıyor. Gerçekten yeni bir cihazsa kişiyi silip yeniden ekleyin".to_string()),
            }
            contact.add_device_unverified(device_fingerprint, now);
            let contact = contact.clone();
            self.persist_contact(&contact);
            self.rekey_archive_to_canonical(&identity_id);
            return Ok(());
        }
        // Every caller's new contact: the scanning side got no error while
        // the other side refused it at the cap, and the pairing hung.
        if self.contacts.len() >= MAX_CONTACTS {
            return Err(format!("Kişi sınırına ulaşıldı ({})", MAX_CONTACTS));
        }

        let contact_id = self.new_contact_id(&identity_id);
        // `device_name` is the peer's own claim; it becomes the display name.
        let mut contact = Contact::new(contact_id.clone(), sanitize_display_name(&device_name).unwrap_or_default(), identity_id.clone());
        contact.add_device_unverified(device_fingerprint, now);
        // On disk first: a contact only in memory was lost on restart.
        self.try_persist_contact(&contact)?;
        self.identity_to_contact.insert(identity_id.clone(), contact_id.clone());
        self.contacts.insert(contact_id, contact);
        self.rekey_archive_to_canonical(&identity_id);
        Ok(())
    }

    /// The id for a NEW contact: `contact-` + the first 16 characters of its
    /// identity id. `identity_id` is an unsigned claim, and `persist_contact`
    /// is `INSERT OR REPLACE`: an identity that shares those 16 characters
    /// with a known contact used to replace that contact (devices, name,
    /// trusted identity). If the short id is taken, the full identity id is used.
    pub(crate) fn new_contact_id(&self, identity_id: &str) -> String {
        // Truncate by char count: byte-slicing can panic mid-UTF8-char.
        let short_id: String = identity_id.chars().take(16).collect();
        let contact_id = format!("contact-{}", short_id);
        if self.contacts.contains_key(&contact_id) {
            format!("contact-{}", identity_id)
        } else {
            contact_id
        }
    }
}
