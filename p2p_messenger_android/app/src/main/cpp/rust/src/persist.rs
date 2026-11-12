//! Sealed local blobs, ratchet and skipped-key persistence, durable retries.

use super::*;

impl P2PCore {

    /// `self.ratchets[peer_device_fingerprint]`'i (varsa) diske şifreli
    /// olarak kalıcılaştırır — aynı `skipped_key_encryption_key` ile
    /// (`persist_skipped_key`'deki AEAD desenini birebir tekrarlar).
    /// `skipped_key_encryption_key` henüz yüklenmemişse (Kotlin
    /// `setSkippedKeyEncryptionKey` çağırmadıysa) sessizce atlar —
    /// arşivleme gibi bu da best-effort'tur, mesajlaşmanın kendisini
    /// engellemez (state bellekte zaten güncel).
    /// `skipped_key_encryption_key` ile mühürler (12 baytlık nonce öneki +
    /// ChaCha20-Poly1305) — `persist_ratchet_state`/`persist_skipped_key` ile
    /// AYNI anahtar ve AYNI çerçeveleme.
    ///
    /// Bu anahtar seçildi çünkü `setSkippedKeyEncryptionKey` JNI çağrısı
    /// alanı doldurduktan HEMEN SONRA `load_servers_from_db`'yi çağırıyor —
    /// yani kuyruk diskten okunurken anahtar KESİN olarak elimizde.
    /// `history_key` öyle değil (Kotlin tarafında SkippedKeyManager'dan
    /// SONRA yükleniyor), o yüzden burada kullanılamaz.
    pub(crate) fn seal_local_blob(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        let (ciphertext, nonce_bytes) = seal_with(&self.skipped_key_encryption_key?, plaintext)?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Some(out)
    }

    /// `seal_local_blob`'un tersi. `None` (no key, damaged, never sealed):
    /// the caller drops the bytes — never uses them as plaintext.
    pub(crate) fn open_local_blob(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        if sealed.len() <= 12 {
            return None;
        }
        let key = self.skipped_key_encryption_key?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
        cipher.decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..]).ok()
    }

    /// `false`: the write failed (disk full, SQLITE_BUSY). A sender must not
    /// publish then: after a restart the same message key and nonce would be
    /// used again. No DB or no key is `true`, there is nothing to fall behind.
    pub(crate) fn persist_ratchet_state(&self, peer_device_fingerprint: &str) -> bool {
        let state = match self.ratchets.get(peer_device_fingerprint) {
            Some(s) => s,
            None => return true,
        };
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return true,
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return true,
        };

        let persistable = state.to_persistable();
        // Root, chain and ratchet secret keys: wiped when dropped.
        let plaintext = match ciborium_bytes(&persistable) {
            Ok(b) => zeroize::Zeroizing::new(b),
            Err(e) => { error!("Ratchet state serileştirilemedi: {}", e); return false; }
        };

        let Some((encrypted, nonce_bytes)) = seal_with(&enc_key, plaintext.as_slice()) else {
            error!("Ratchet state şifrelenemedi");
            return false;
        };

        // with WAL and synchronous=NORMAL a commit that returned
        // can still be lost on power loss; the send chain then rolled back
        // and the next message reused a key and nonce. This commit is synced
        // (FULL: the WAL is synced at commit), the rest of the database
        // keeps NORMAL. Inside an open transaction the pragma is left alone.
        let durable = conn.is_autocommit();
        if durable {
            let _ = conn.pragma_update(None, "synchronous", "FULL");
        }
        let written = conn.execute(
            "INSERT OR REPLACE INTO ratchet_states (peer_device_fingerprint, encrypted_state, nonce, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![peer_device_fingerprint, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64],
        );
        if durable {
            let _ = conn.pragma_update(None, "synchronous", "NORMAL");
        }
        if let Err(e) = &written {
            error!("Ratchet state yazılamadı ({}): {}", crate::log_id(&peer_device_fingerprint), e);
        }
        written.is_ok()
    }

    /// Uygulama açılışında (skipped_key_encryption_key yüklendikten sonra
    /// — bkz. JNI `setSkippedKeyEncryptionKey`) DB'de kayıtlı TÜM ratchet
    /// oturumlarını çözüp `self.ratchets`'e geri yükler. Bu, süreç yeniden
    /// başladığında (app güncellemesi, arka plan öldürme) devam eden
    /// sohbetlerin YENİDEN el sıkışma gerektirmeden çalışmaya devam
    /// etmesini sağlar — önceden bu state tamamen bellek-only olduğu için
    /// her süreç yeniden başlatmasında kayboluyordu (bkz. dosya sonu not).
    /// Loads the persisted sessions and opens the send gate (`ratchets_loaded`).
    /// The skipped-key/ratchet storage key arrived: load everything sealed
    /// with it. One implementation for JNI and `api.rs` (they had drifted).
    /// A second call with the same key does nothing: the reload rolled live
    /// sessions back to their stored state.
    pub(crate) fn install_skipped_key(&mut self, key: [u8; 32]) {
        if self.skipped_key_encryption_key == Some(key) && self.ratchets_loaded {
            return;
        }
        self.skipped_key_encryption_key = Some(key);
        self.load_ratchet_states_from_db();
        self.load_pending_durable_retries_from_db();
        self.load_pending_group_messages_from_db();
        self.requeue_unresolved_group_syncs();
        self.load_servers_from_db();
    }

    pub(crate) fn load_ratchet_states_from_db(&mut self) {
        let (rows, unopened) = self.load_ratchet_states_from_db_inner();
        // when stored sessions exist and none opens, the key is
        // wrong: the gate stays shut, or the next send replaced them one by
        // one. One bad row among good ones is dropped as before.
        if rows > 0 && unopened == rows {
            error!("Hiçbir oturum durumu çözülemedi ({} satır): anahtar yanlış, gönderim kapısı kapalı", rows);
            self.attachment_events.push(serde_json::json!({"type": "session_load_failed", "rows": rows}).to_string());
            return;
        }
        if self.skipped_key_encryption_key.is_some() && self.db.is_some() {
            self.ratchets_loaded = true;
        }
    }

    /// (rows read, rows that did not open).
    pub(crate) fn load_ratchet_states_from_db_inner(&mut self) -> (usize, usize) {
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return (0, 0),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return (0, 0),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&enc_key) {
            Ok(c) => c,
            Err(_) => return (0, 0),
        };

        let mut stmt = match conn.prepare(
            "SELECT peer_device_fingerprint, encrypted_state, nonce FROM ratchet_states"
        ) {
            Ok(s) => s,
            Err(_) => return (0, 0),
        };

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
        });

        let mut loaded: Vec<(String, DeviceRatchetState)> = Vec::new();
        let (mut read, mut unopened) = (0usize, 0usize);
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (peer_fp, encrypted, nonce_bytes) = row;
                read += 1;
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                let plaintext = match cipher.decrypt(nonce, encrypted.as_slice()) {
                    Ok(p) => zeroize::Zeroizing::new(p),
                    Err(_) => { unopened += 1; error!("Ratchet state çözülemedi ({}), atlanıyor", crate::log_id(&peer_fp)); continue; }
                };
                let persistable: ratchet::SerializableRatchetState = match ciborium::from_reader(plaintext.as_slice()) {
                    Ok(p) => p,
                    Err(e) => { error!("Ratchet state ayrıştırılamadı ({}): {}", crate::log_id(&peer_fp), e); continue; }
                };
                let skipped_keys = self.load_skipped_keys_from_db(&peer_fp);
                match DeviceRatchetState::from_persistable(persistable, skipped_keys) {
                    Ok(state) => loaded.push((peer_fp, state)),
                    Err(e) => error!("Ratchet state yeniden oluşturulamadı ({}): {}", crate::log_id(&peer_fp), e),
                }
            }
        }
        for (peer_fp, state) in loaded {
            self.ratchets.insert(peer_fp, state);
        }
        (read, unopened)
    }

    /// Spec dışı, kullanıcı isteği ("gönderilemeyen mesajlar/emirler ...
    /// geçici bir dosyada tutulsun"): `awaiting_confirmation` tamamen
    /// bellek-içi olduğundan, süreç TAMAMEN öldürülüp yeniden başlarsa
    /// (uygulama kapatılıp OS tarafından servis öldürülürse — sadece arka
    /// planda beklerken DEĞİL) bekleyen Edit/Delete/GroupUpdate kayboluyordu.
    /// Bunları "geçici dosya" yerine zaten var olan şifreli SQLite DB'ye
    /// yazıyoruz (ayrı bir dosya formatı/temizleme mantığı icat etmemek
    /// için — ratchet state de aynı DB'de). SADECE `regen_content` dolu
    /// girdiler (bkz. o alanın dokümantasyonu) buraya yazılır.
    ///
    /// NOT (eskimiş yorum düzeltildi): burada bir zamanlar "Text/
    /// HistorySyncRequest zaten kapsam dışında" yazıyordu — `Text` o zamandan
    /// beri `regen_content`'e alındı, yani süreç ölümüne karşı O DA korunuyor.
    /// Aynı şekilde çoklu-cihaz kontrol mesajları da (SiblingEcho/DeviceSync/
    /// DeviceAddNotice/…) artık buraya yazılıyor — önceden bir yeniden
    /// başlatma kuyruktaki TÜM kardeş senkronunu sessizce siliyordu.
    /// `original_sent_at`: mesajın İLK kuyruğa girdiği an — `current_time_ms()`
    /// DEĞİL. burası eskiden her
    /// yazışta `current_time_ms()` damgalıyordu, ama bu kolon
    /// `load_pending_durable_retries_from_db` tarafından `original_sent_at`
    /// olarak geri okunuyor — yani `TEXT_RETRY_GIVE_UP_MS` (7 gün) penceresi
    /// HER uygulama açılışında ve HER `regen` tazelemesinde (25 dakikada bir)
    /// sıfırlanıyordu. Sonuç: artık var olmayan bir eşe giden bir mesaj
    /// sonsuza kadar yeniden deneniyor ve kullanıcıya asla "gönderilemedi"
    /// denmiyordu. Gerçek başlangıç anı taşınınca 7 günlük tavan gerçekten
    /// işliyor.
    pub(crate) fn persist_durable_retry(&self, message_id: &str, peer_device_fingerprint: &str, content: &MessageContent, original_sent_at: u64) {
        let conn = match &self.db { Some(c) => c, None => return };
        // Sealed like `server_archive_queue` (it used to be plain CBOR: every
        // sent message sat readable on disk until acked).
        let content_cbor = match ciborium_bytes(content).map(|b| self.seal_local_blob(&b)) {
            Ok(Some(b)) => b,
            Ok(None) => { error!("Kalıcı yeniden deneme kaydı serileştirilemedi: şifreleme anahtarı yok"); return; }
            Err(e) => { error!("Kalıcı yeniden deneme kaydı serileştirilemedi: {}", e); return; }
        };
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO pending_durable_retries (message_id, peer_device_fingerprint, content_cbor, created_at, local_message_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![message_id, peer_device_fingerprint, content_cbor, original_sent_at as i64, group_row_id(content)],
        ) {
            // Memory copy still retries; only a process death loses it now.
            error!("Kalıcı yeniden deneme kaydı yazılamadı ({}): {}", message_id, e);
        }
    }

    /// bkz. `persist_durable_retry` — bir girdi onaylandığında (Ack) veya
    /// tazelenip YENİ bir message_id altında yeniden kaydedildiğinde ESKİ
    /// satır silinmezse bir sonraki süreç başlangıcında hem eski hem yeni
    /// kayıt yeniden gönderilir (ÇİFT GÖNDERİM) — bu yüzden
    /// `awaiting_confirmation`'dan her çıkarma/değiştirme noktasında bu da
    /// çağrılmalı.
    pub(crate) fn remove_durable_retry(&self, message_id: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM pending_durable_retries WHERE message_id = ?1", params![message_id]);
        }
    }

    /// bkz. `remove_durable_retry` — bir cihaz/kişi tamamen kaldırıldığında
    /// (bkz. `awaiting_confirmation.retain` çağrı yerleri) o cihaza ait
    /// TÜM kalıcı kayıtları da temizler.
    pub(crate) fn remove_durable_retries_for_peer(&mut self, peer_device_fingerprint: &str) {
        let mut ids: Vec<String> = Vec::new();
        if let Some(conn) = &self.db {
            if let Ok(mut stmt) = conn.prepare("SELECT message_id FROM pending_durable_retries WHERE peer_device_fingerprint = ?1") {
                if let Ok(rows) = stmt.query_map(params![peer_device_fingerprint], |r| r.get::<_, String>(0)) {
                    ids.extend(rows.flatten());
                }
            }
            let _ = conn.execute("DELETE FROM pending_durable_retries WHERE peer_device_fingerprint = ?1", params![peer_device_fingerprint]);
        }
        // nothing retries them any more.
        self.fail_orphaned_sends(&ids);
    }

    /// C6/H92/H93: our 1:1 messages whose retry was dropped with no Ack. A
    /// row left `pending` showed the clock icon for good, with no event; it
    /// goes to `error` and the screen is told. `sent`/`error` rows stay.
    pub(crate) fn fail_orphaned_sends(&mut self, message_ids: &[String]) {
        for id in message_ids {
            let Some(conn) = &self.db else { return };
            let peer: Option<String> = conn.query_row(
                "SELECT peer_device_fingerprint FROM messages WHERE message_id = ?1 AND direction = 'sent' AND status = 'pending'
                   AND (group_id IS NULL OR group_id = '')",
                params![id], |r| r.get(0),
            ).ok();
            let Some(peer) = peer else { continue };
            self.set_message_status(id, MessageSendStatus::Failed);
            self.attachment_events.push(serde_json::json!({
                "type": "status", "peer": self.canonical_peer_key(&peer), "message_id": id, "status": "error"
            }).to_string());
        }
    }

    /// bkz. `pending_group_messages` alanı dokümantasyonu — bir üyeye
    /// kuyruklanan HER mesajı ayrı bir satır olarak (üye başına birden
    /// fazla satır normal, `id` sütunuyla SIRAYLA korunur) kalıcı DB'ye
    /// de yazar.
    pub(crate) fn persist_pending_group_message(&self, group_id: &str, member_identity_id: &str, content: &MessageContent) {
        let conn = match &self.db { Some(c) => c, None => return };
        // Sealed like `server_archive_queue` (it used to be plain CBOR: every
        // sent message sat readable on disk until acked).
        let content_cbor = match ciborium_bytes(content).map(|b| self.seal_local_blob(&b)) {
            Ok(Some(b)) => b,
            Ok(None) => { error!("Kalıcı grup mesaj kuyruğu kaydı serileştirilemedi: şifreleme anahtarı yok"); return; }
            Err(e) => { error!("Kalıcı grup mesaj kuyruğu kaydı serileştirilemedi: {}", e); return; }
        };
        if let Err(e) = conn.execute(
            "INSERT INTO pending_group_messages (group_id, member_identity_id, content_cbor, created_at, local_message_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![group_id, member_identity_id, content_cbor, current_time_ms() as i64, group_row_id(content)],
        ) {
            error!("Kalıcı grup mesaj kuyruğu kaydı yazılamadı (group={}): {}", group_id, e);
        }
    }

    /// bkz. `persist_pending_group_message` — bellek-içi kuyruk
    /// `MAX_PENDING_GROUP_MESSAGES_PER_MEMBER` sınırını aşıp en eskiyi
    /// attığında, o üye/grup için diskteki EN ESKİ satırı da (aynı sırayla,
    /// `id ASC`) atarak iki tarafı senkron tutar.
    pub(crate) fn remove_oldest_persisted_pending_group_message(&self, group_id: &str, member_identity_id: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM pending_group_messages WHERE id = (
                    SELECT id FROM pending_group_messages
                    WHERE group_id = ?1 AND member_identity_id = ?2
                    ORDER BY id ASC LIMIT 1
                 )",
                params![group_id, member_identity_id],
            );
        }
    }

    /// bkz. `persist_pending_group_message` — üye çözülüp kuyruk
    /// tamamen boşaltıldığında (bkz. `group_sync_sweep`) o üye/grup için
    /// kalan TÜM kalıcı satırları temizler.
    pub(crate) fn remove_persisted_pending_group_messages(&self, group_id: &str, member_identity_id: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM pending_group_messages WHERE group_id = ?1 AND member_identity_id = ?2",
                params![group_id, member_identity_id],
            );
        }
    }

    /// bkz. `remove_persisted_pending_group_messages` — bir grup tamamen
    /// silindiğinde (bkz. `remove_group_locally`) o gruba ait TÜM kalıcı
    /// kayıtları da temizler.
    pub(crate) fn remove_persisted_pending_group_messages_for_group(&self, group_id: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM pending_group_messages WHERE group_id = ?1", params![group_id]);
        }
    }

    /// Uygulama açılışında, `load_pending_durable_retries_from_db` ile AYNI
    /// noktada çağrılır — diskte kalan tüm kuyruklanmış grup mesajlarını
    /// bellek-içi `pending_group_messages`'a geri yükler (SIRAYLA, `id ASC`)
    /// — süreç ölümünde bu kuyruk artık kaybolmaz.
    pub(crate) fn load_pending_group_messages_from_db(&mut self) {
        // Rows are sealed with this key. Without it they parsed as bad CBOR
        // and were deleted: the whole queue, silently.
        if self.skipped_key_encryption_key.is_none() {
            return;
        }
        let mut loaded: Vec<(String, String, Vec<u8>, i64)> = Vec::new();
        {
            let conn = match &self.db { Some(c) => c, None => return };
            let mut stmt = match conn.prepare(
                "SELECT group_id, member_identity_id, content_cbor, id FROM pending_group_messages ORDER BY id ASC"
            ) {
                Ok(s) => s,
                Err(_) => return,
            };
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, i64>(3)?))
            });
            if let Ok(rows) = rows {
                for row in rows.flatten() {
                    loaded.push(row);
                }
            }
        }
        if loaded.is_empty() {
            return;
        }
        let mut count = 0usize;
        for (group_id, member_identity_id, content_cbor, row_id) in loaded {
            // A row that does not open (wrong or stale key) is kept, as in
            // the durable-retry twin; only opened bytes that do not parse go
            let Some(plain) = self.open_local_blob(&content_cbor) else { continue };
            let content: MessageContent = match ciborium::from_reader(plain.as_slice()) {
                Ok(c) => c,
                Err(e) => {
                    // Dropped like the durable-retry twin: left in place it is
                    // read again on every start, and the "oldest row" eviction
                    // then removes it instead of the entry evicted from memory.
                    error!("Kalıcı grup mesaj kuyruğu kaydı ayrıştırılamadı, satır atılıyor: {}", e);
                    if let Some(conn) = &self.db {
                        let _ = conn.execute("DELETE FROM pending_group_messages WHERE id = ?1", params![row_id]);
                    }
                    continue;
                }
            };
            self.pending_group_messages.entry((group_id, member_identity_id)).or_default().push(content);
            count += 1;
        }
        info!("Kalıcı grup mesaj kuyruğundan {} girdi geri yüklendi", count);
    }

    /// Uygulama açılışında, ratchet state'lerle TAM OLARAK AYNI anda (bkz.
    /// JNI `setSkippedKeyEncryptionKey` — ratchet'ler olmadan zaten
    /// şifreleyip gönderemeyiz) çağrılır: diskte kalan tüm kalıcı yeniden
    /// deneme kayıtlarını okur ve HER BİRİNİ TAZE bir paket olarak
    /// (`send_message_content` — yeni message_id, yeni ratchet adımı)
    /// yeniden gönderir. Eski satır ÖNCE silinir (bkz. `remove_durable_retry`
    /// dokümantasyonu — çift gönderimi önlemek için) — `send_message_content`
    /// zaten kendi YENİ satırını `publish_with_ack_tracking` üzerinden
    /// baştan yazacaktır.
    /// `pending_group_syncs` is memory only. After a restart, sign the current
    /// state again (`sign_group_resync`) for each member of a group we founded
    /// whose device is still unknown; `group_sync_sweep` delivers it when the
    /// device resolves.
    pub(crate) fn requeue_unresolved_group_syncs(&mut self) {
        // The Delete / removal notices `send_group_update_to_member` kept.
        let kept: Vec<(String, String)> = self.db.as_ref().and_then(|c| {
            let mut stmt = c.prepare("SELECT k, v FROM app_meta WHERE k >= 'pgs:' AND k < 'pgs;'").ok()?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).ok()?;
            Some(rows.flatten().collect())
        }).unwrap_or_default();
        for (k, v) in kept {
            let update = hex::decode(&v).ok()
                .and_then(|b| self.open_local_blob(&b))
                .and_then(|p| ciborium::from_reader::<GroupUpdate, _>(p.as_slice()).ok());
            let member = k.rsplit(':').next().unwrap_or("").to_string();
            // A row that does not open (wrong key passed once) is kept.
            if self.deleted_identities.contains(&member) {
                self.meta_del(&k);
            } else if let Some(u) = update {
                self.pending_group_syncs.insert((u.group_id.clone(), member), u);
            }
        }
        let (Ok(own_fp), Some(own_identity_id)) = (self.get_active_own_device_fingerprint(), self.my_identity_id()) else { return };
        // checked once, and said, instead of a silent return inside the loop.
        if !self.own_device_keys.contains_key(&own_fp) {
            error!("Grup senkronları yeniden kuyruklanamadı: kendi cihaz anahtarları yok");
            return;
        }
        let founded: Vec<Group> = self.groups.values()
            .filter(|g| g.founder_identity_id == own_identity_id && g.version > 0)
            .cloned()
            .collect();
        for group in founded {
            for member in group.other_members(&own_identity_id) {
                if !self.active_devices_for_identity(&member).is_empty() || self.deleted_identities.contains(&member) {
                    continue;
                }
                if let Ok(update) = self.sign_group_resync(&group) {
                    self.pending_group_syncs.insert((group.group_id.clone(), member), update);
                }
            }
        }
    }

    pub(crate) fn load_pending_durable_retries_from_db(&mut self) {
        // KRİTİK: DB okuma kısmı (conn/stmt/rows) KENDİ bloğunda —
        // `self.send_message_content`/`self.remove_durable_retry` gibi
        // TÜM `self`'i ödünç alan (borrow) çağrılar aşağıda olduğundan,
        // `conn`'un (`&self.db`'den türeyen) ödünç alması buradaki blok
        // KAPANMADAN bitmiş olmalı — aksi halde "cannot borrow `*self`
        // as mutable because it is also borrowed as immutable" derleme
        // hatası (rusqlite `Rows`/`MappedRows` Drop implementasyonu
        // yüzünden NLL bunu son kullanım yerine göre otomatik kısaltamıyor).
        // bkz. `load_pending_group_messages_from_db`: also called from
        // `touch_device_seen`, at any time.
        if self.skipped_key_encryption_key.is_none() {
            return;
        }
        let mut loaded: Vec<(String, String, Vec<u8>, u64)> = Vec::new();
        let mut expired: Vec<String> = Vec::new();
        {
            let conn = match &self.db { Some(c) => c, None => return };
            // Expired rows first: past the 7-day give-up nothing retries them,
            // and they were read again on every start.
            let cutoff = current_time_ms().saturating_sub(TEXT_RETRY_GIVE_UP_MS) as i64;
            // their messages are marked failed below.
            if let Ok(mut stmt) = conn.prepare("SELECT message_id FROM pending_durable_retries WHERE created_at < ?1") {
                if let Ok(rows) = stmt.query_map(params![cutoff], |r| r.get::<_, String>(0)) {
                    expired.extend(rows.flatten());
                }
            }
            if let Err(e) = conn.execute("DELETE FROM pending_durable_retries WHERE created_at < ?1", params![cutoff]) {
                error!("Süresi dolmuş kalıcı yeniden deneme kayıtları silinemedi: {}", e);
            }
            // the keys of every row first (small), then the oldest 1000
            // that would really be sent now. A plain `LIMIT 1000` read rows
            // of stale devices or already in memory, and the rest never came.
            // ponytail: 1000 per load; the rest come on the next load.
            let mut heads: Vec<(String, String, u64)> = Vec::new();
            {
                let mut stmt = match conn.prepare(
                    "SELECT message_id, peer_device_fingerprint, created_at FROM pending_durable_retries ORDER BY created_at"
                ) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)? as u64))
                });
                if let Ok(rows) = rows {
                    heads.extend(rows.flatten());
                }
            }
            for (message_id, peer_fp, created_at) in heads.into_iter()
                .filter(|(id, fp, _)| !self.awaiting_confirmation.contains_key(id) && self.device_recently_seen(fp))
                .take(1000)
            {
                let blob: Option<Vec<u8>> = conn.query_row(
                    "SELECT content_cbor FROM pending_durable_retries WHERE message_id = ?1",
                    params![message_id], |r| r.get(0),
                ).ok();
                if let Some(blob) = blob {
                    loaded.push((message_id, peer_fp, blob, created_at));
                }
            }
        }
        // An expired entry still in memory is failed by the retry loop's age arm.
        expired.retain(|id| !self.awaiting_confirmation.contains_key(id));
        self.fail_orphaned_sends(&expired);
        if loaded.is_empty() {
            return;
        }
        info!("Kalıcı yeniden deneme kuyruğundan {} girdi geri yükleniyor", loaded.len());
        for (message_id, peer_fp, content_cbor, created_at) in loaded {
            // KRİTİK (teslim garantisi düzeltmesi): satır burada SİLİNMEZ.
            // Önceden `remove_durable_retry` yeniden gönderimden ÖNCE
            // çağrılıyordu ("nasılsa taze bir gönderimle değiştirilecek"
            // gerekçesiyle) — ama aşağıdaki `send_message_content_inner`
            // `Err` dönerse ("No ratchet session", "Missing own keys", "No
            // identity"; üçü de açılıştan hemen sonra gayet olası) o
            // değiştirme HİÇ olmuyor: ne disk satırı ne de bellekteki
            // `awaiting_confirmation` girdisi kalıyor ve mesaj KALICI olarak
            // kayboluyordu. Alttaki hata log'u "normal yeniden deneme
            // döngüsü devralacak" diyordu ama devralacak bir şey
            // bırakılmıyordu — oysa bu tablonun var oluş sebebi tam olarak
            // bu senaryoyu önlemekti.
            //
            // Silmeye gerek de yok: `persist_durable_retry` `INSERT OR
            // REPLACE`, yani BAŞARILI yolda satır zaten aynı birincil
            // anahtarla tazeleniyor; hata yolunda ise yerinde kalıp bir
            // sonraki açılışta yeniden deneniyor.
            if self.awaiting_confirmation.contains_key(&message_id) {
                continue;
            }
            // bkz. `STALE_PEER_RETRY_HORIZON_MS` dokümantasyonu — gerçek
            // cihazda (tablet + Redmi) her açılışta yüzlerce satırın
            // hayalet kardeş cihazlara boşuna yeniden gönderilmeye
            // çalışılması hem gözle görülür bir açılış gecikmesi yaratıyor
            // hem de kuyruğu asla küçültmüyordu. Satır yine SİLİNMEZ (üstteki
            // not) — sadece bu turda atlanır.
            // Same test as the reload trigger (`last_seen == 0` is not stale).
            if !self.device_recently_seen(&peer_fp) {
                continue;
            }
            // A decrypt failure (a wrong key passed once, keychain hiccup) is
            // not a corrupt row: keep it for the next load.
            let Some(plain) = self.open_local_blob(&content_cbor) else {
                warn!("Durable retry row {} could not be decrypted, kept", message_id);
                continue;
            };
            let content: MessageContent = match ciborium::from_reader(plain.as_slice()) {
                Ok(c) => c,
                Err(e) => {
                    // Bozuk satır YENİDEN DENENEMEZ (her açılışta aynı
                    // hatayı verir) — tek silinmesi gereken durum bu.
                    error!("Kalıcı yeniden deneme kaydı ayrıştırılamadı, satır atılıyor ({}): {}", message_id, e);
                    self.remove_durable_retry(&message_id);
                    continue;
                }
            };
            // A parked group copy is resent only while the device's
            // identity is still a member: a removed member got it forever.
            let group_id = match &content {
                MessageContent::Text { group_id: Some(g), .. }
                | MessageContent::Edit { group_id: Some(g), .. }
                | MessageContent::Delete { group_id: Some(g), .. }
                | MessageContent::Reaction { group_id: Some(g), .. } => Some(g.clone()),
                _ => None,
            };
            if let Some(gid) = group_id {
                let member = self.known_remote_devices.get(&peer_fp)
                    .map_or(true, |d| self.groups.get(&gid).map_or(false, |g| g.is_member(&d.identity_id)));
                if !member {
                    info!("Durable retry row {} dropped: device left group {}", message_id, gid);
                    self.remove_durable_retry(&message_id);
                    continue;
                }
            }
            // Güvenilirlik düzeltmesi ("restart sonrası balon sonsuza dek
            // 'error' kalıyor"): önceden buradan `send_message_content` (yeni
            // rastgele message_id) çağrılıyordu — arşivdeki balon ESKİ id'yi
            // taşıdığından, yeni id'nin Ack/status olayları o balonu asla
            // güncellemiyordu (init_db açılışta 'pending'→'error' çevirir,
            // mesaj gerçekte teslim edilse bile öyle kalırdı); alıcı tarafta
            // da id-dedup'u atlatıp çift arşive yol açabiliyordu. Artık AYNI
            // `message_id` (tablonun birincil anahtarı) ve mesajın İLK
            // kuyruğa girdiği an (`created_at` → `original_sent_at`) korunur
            // — Ack gelince `set_message_status` aynı arşiv satırını
            // 'sent'e çevirir, alıcı dedup'u da çalışır.
            let known = self.known_remote_devices.contains_key(&peer_fp);
            // The backoff reaches its cap (15+30+60 s) long before most
            // restores: do not restart it at 15 s after every process kill.
            let interval = (current_time_ms().saturating_sub(created_at) > ACK_RETRY_MAX_MS).then_some(ACK_RETRY_MAX_MS);
            if let Err(e) = self.send_message_content_inner(
                peer_fp, &content, None,
                Some(message_id.clone()), Some(created_at), interval,
            ) {
                error!("Kalıcı kuyruktan yeniden gönderim denemesi geçici olarak başarısız (normal yeniden deneme döngüsü devralacak): {}", e);
                // A device that is gone never gets it: the row would stay for good.
                if !known {
                    self.remove_durable_retry(&message_id);
                    self.fail_orphaned_sends(std::slice::from_ref(&message_id));
                }
            }
        }
    }
}
