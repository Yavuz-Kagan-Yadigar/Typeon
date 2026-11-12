//! Attachment offers, chunked downloads and serving chunks.

use super::*;

impl P2PCore {

    /// `attachment_key` diye AYRI bir anahtar İCAT ETMİYORUZ — bunun yerine
    /// zaten node modundan BAĞIMSIZ her zaman yüklenen
    /// `skipped_key_encryption_key`'i (bkz. o alanın dokümantasyonu) yeniden
    /// kullanıyoruz. Bu, "gönderen kendi node modundan bağımsız dosya
    /// kopyasını tutar" kuralının (dosyanın `file_key`'i her zaman diskte
    /// şifreli saklanabilmeli, node modu kapalı olsa bile) Kotlin tarafında
    /// yeni bir Keystore anahtarı/yaşam-döngüsü sınıfı gerektirmeden
    /// çalışmasını sağlar — aynı KEK, farklı küçük sırları (atlanmış mesaj
    /// anahtarları, ratchet state, şimdi de dosya anahtarları) taze
    /// nonce'larla sarmaya devam ediyor, standart bir uygulama.
    pub(crate) fn wrap_file_key(&self, file_key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let enc_key = self.skipped_key_encryption_key.ok_or("Şifreleme anahtarı henüz yüklenmedi")?;
        let (encrypted, nonce_bytes) = seal_with(&enc_key, file_key.as_slice()).ok_or("File key encryption failed")?;
        Ok((encrypted, nonce_bytes.to_vec()))
    }

    pub(crate) fn unwrap_file_key(&self, encrypted: &[u8], nonce_bytes: &[u8]) -> Result<[u8; 32], String> {
        let enc_key = self.skipped_key_encryption_key.ok_or("Şifreleme anahtarı henüz yüklenmedi")?;
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key).map_err(|_| "Invalid key")?;
        if nonce_bytes.len() != 12 {
            return Err("Bad nonce length".to_string());
        }
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, encrypted).map_err(|_| "File key decryption failed")?;
        plaintext.as_slice().try_into().map_err(|_| "Bad file key length".to_string())
    }

    /// Kullanıcının seçtiği bir dosyayı (Kotlin tarafından zaten yerel bir
    /// yola kopyalanmış olmalı — content:// URI burada işlenmez, bkz.
    /// P2PLib.kt dokümantasyonu) şifreleyip diske yazar, kendi kaydını
    /// `files` tablosuna ekler (sender-always-keeps-copy kuralı, kendi
    /// node modumuzdan BAĞIMSIZ) ve karşı tarafa bir `FileOffer` meta veri
    /// mesajı gönderir. BİLİNEN SINIR: `encrypt_file_to_disk` bounded-
    /// memory'dir ama SENKRONdur — bu çağrı boyunca `CORE` kilidi tutulur,
    /// yani çok büyük (GB mertebesinde) bir dosya için bu süre boyunca
    /// `pollNetwork`/diğer JNI çağrıları gecikebilir (mesajlaşmanın
    /// KENDİSİ bozulmaz, sadece o birkaç saniye/on saniye ertelenir) —
    /// tam asenkron bir mimari (ayrı worker thread + kanal) bu kapsamın
    /// dışında bırakıldı, bkz. proje notları.
    /// Performans/güvenilirlik düzeltmesi (kilit altında dosya şifreleme):
    /// eski tek parça `prepare_and_send_file`/`prepare_and_send_group_file`,
    /// 4GB'a varan ChaCha20 şifrelemesini GLOBAL core kilidi TUTARKEN
    /// yapıyordu — bu süre boyunca `poll_events` hiç çalışamıyor (swarm
    /// sürülmüyor, gelen keepalive istekleri yanıtlanamıyor), karşı
    /// taraflar ~20-30 sn içinde bağlantıyı "yarı açık" sayıp KAPATIYORDU:
    /// büyük bir video göndermek düğümü fiilen çevrimdışına alıyordu.
    /// Artık üç faz var: `begin_outgoing_file` (kısa, kilitli — doğrulama +
    /// kimlik/anahtar üretimi), şifrelemenin KENDİSİ (kilitsiz, bkz.
    /// dosya sonundaki `prepare_and_send_file_unlocked` serbest fonksiyonu)
    /// ve `finish_outgoing_file`/`finish_outgoing_group_file` (kısa,
    /// kilitli — DB kaydı + FileOffer gönderimi).
    ///
    /// `skipped_key_encryption_key` kontrolünün erken (şifrelemeden ÖNCE)
    /// yapılması kasıtlı: aksi halde GB'larca veri işlendikten sonra anahtar
    /// sarmalama başarısız olur, diskte DB kaydı olmayan "öksüz" bir `.enc`
    /// kalırdı. Boyut kontrolü de aynı gerekçeyle burada.
    pub(crate) fn begin_outgoing_file(&self, source_path: &str, group_id: Option<&str>) -> Result<(String, [u8; 32], std::path::PathBuf), String> {
        if self.skipped_key_encryption_key.is_none() {
            return Err("Şifreleme anahtarı henüz yüklenmedi, birazdan tekrar deneyin".to_string());
        }
        if let Some(gid) = group_id {
            // Grup yerelde yoksa şifrelemeye hiç başlama.
            if !self.groups.contains_key(gid) {
                return Err("Unknown group".to_string());
            }
        }
        let source_size = std::fs::metadata(source_path).map(|m| m.len()).map_err(|e| e.to_string())?;
        if source_size > MAX_ATTACHMENT_SIZE {
            return Err(format!(
                "Dosya çok büyük ({} bayt) — azami boyut {} bayt (4GB)",
                source_size, MAX_ATTACHMENT_SIZE
            ));
        }
        // `enforce_history_storage_limit` would evict this very file right
        // after it is stored, and the offer would go out for a file nobody
        // can download.
        if self.node_mode_enabled && source_size > self.history_storage_limit_bytes {
            return Err("Dosya, depolama sınırından büyük".to_string());
        }

        let mut file_key = [0u8; 32];
        {
            use rand::RngCore;
            OsRng.fill_bytes(&mut file_key);
        }
        // The id is the hash of the server upload secret (see
        // `blob_upload_secret`), so no recipient can claim the server blob.
        // In a group it starts with our author tag, which members check
        // (`group_msg_tag`); a 1:1 file gets a random one.
        // The group tag is made from the id's hash part, so it differs per
        // file.
        let secret_rest = self.blob_upload_secret(&file_key, &[0u8; 8]).ok_or_else(|| "History key not loaded".to_string())?;
        let hash_hex = server_proto::blob_id_hash_hex(&secret_rest[server_proto::BLOB_TAG_LEN..]);
        let tag: [u8; 8] = match group_id {
            Some(gid) => group_msg_tag(gid, &self.my_identity_id().ok_or("No identity")?, &hash_hex),
            None => { use rand::RngCore; let mut t = [0u8; 8]; OsRng.fill_bytes(&mut t); t }
        };
        let file_id = self
            .blob_upload_secret(&file_key, &tag)
            .and_then(|secret| server_proto::blob_id_for_upload_secret(&secret))
            .ok_or_else(|| "History key not loaded".to_string())?;

        let _ = std::fs::create_dir_all(self.attachments_dir()?);
        let dest_path = self.enc_path_for(&file_id)?;
        Ok((file_id, file_key, dest_path))
    }

    /// bkz. `begin_outgoing_file` — kilitli son faz (1:1). Şifreleme
    /// kilitsiz fazda zaten bitti; burada anahtar sarmalanır, DB kaydı
    /// yazılır ve `FileOffer` gönderilir.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_outgoing_file(&mut self, peer_device_fingerprint: String, file_id: String, file_key: [u8; 32], total_size: u64, sha256_hex: String, chunk_hashes: Vec<u8>, file_name: String, mime_type: String, preview_jpeg: Option<Vec<u8>>, duration_ms: Option<u32>, caption: String, reply_to_message_id: Option<String>, reply_to_preview: Option<String>, sticker_origin: Option<String>) -> Result<(String, String), String> {
        let sticker = sticker_origin.is_some();
        let (encrypted_key, key_nonce) = self.wrap_file_key(&file_key)?;
        if let Some(conn) = &self.db {
            // İKİ CİHAZLI GERÇEK TESTTE BULUNDU (2026-09-06): kolon listesi
            // 15, VALUES listesi 18 ifade taşıyordu (`caption`,
            // `reply_to_message_id`, `reply_to_preview` kolonları — bkz.
            // ALTER TABLE eklemeleri — VALUES/params'a eklenmiş ama kolon
            // listesine EKLENMEMİŞ). SQLite bunu "18 values for 15 columns"
            // ile reddediyor, `let _ =` hatayı yutuyordu — yani GÖNDEREN
            // KENDİ gönderdiği 1:1 ekini `files` tablosuna HİÇ yazmıyordu:
            // `serve_chunk_request` "kayıt yok" dönüyor (alıcı sadece
            // sunucudan indirebiliyor), `list_attachments` ek balonunu
            // geçmişte hiç göstermiyordu (sohbet yeniden açılınca ek
            // kayboluyordu). Kolon listesi artık 18 — VALUES ile birebir.
            let res = conn.execute(
                "INSERT OR REPLACE INTO files
                 (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size,
                  sha256_hex, encrypted_file_key, key_nonce, status, bytes_transferred, created_at, preview_jpeg, duration_ms, chunk_size,
                  caption, reply_to_message_id, reply_to_preview, sticker, sticker_origin, chunk_hashes)
                 VALUES (?1, ?2, 'sent', ?3, ?4, ?5, ?6, ?7, ?8, 'complete', ?5, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    file_id, peer_device_fingerprint, file_name, mime_type, total_size as i64,
                    sha256_hex, encrypted_key, key_nonce, current_time_ms() as i64, preview_jpeg, duration_ms,
                    attachments::FILE_CHUNK_SIZE_V2 as i64,
                    caption, reply_to_message_id, reply_to_preview, sticker, sticker_origin.clone(), chunk_hashes,
                ],
            );
            // bkz. yukarıdaki not — bu INSERT sessizce başarısız oluyordu.
            // Bir daha fark edilmeden geçmesin diye artık hata loglanıyor.
            // Without the row we cannot serve the file: sending the offer
            // anyway gave the recipient an attachment it could never download.
            if let Err(e) = res {
                error!("finish_outgoing_file: `files` satırı yazılamadı (file_id={}): {}", file_id, e);
                return Err(format!("Dosya kaydı yazılamadı: {}", e));
            }
        }
        // Kendi gönderdiğimiz dosya da toplam depolamaya katkı sağlar —
        // bkz. `enforce_history_storage_limit` notu.
        self.enforce_history_storage_limit();

        let content = MessageContent::FileOffer {
            group_id: None,
            file_id: file_id.clone(),
            file_name,
            mime_type,
            total_size,
            file_key,
            sha256_hex,
            preview_jpeg,
            duration_ms,
            chunk_size: Some(attachments::FILE_CHUNK_SIZE_V2 as u32),
            chunk_hashes,
            caption: caption.clone(),
            reply_to_message_id: reply_to_message_id.clone(),
            reply_to_preview: reply_to_preview.clone(),
            // 1:1'de yanıtlananın kimliği ayrıca taşınmıyor — karşı taraf
            // zaten tek bir kişi (bkz. `Text.reply_to_sender_identity_id`,
            // AYNI kural).
            reply_to_sender_identity_id: None,
            sticker,
            sticker_origin,
        };
        // Sunucu (bkz. `server_client`) varsa şifreli dosyayı oraya da
        // yükle — sunucu, istemcilerin ZATEN konuştuğu filexfer protokolünü
        // servis ettiği için alıcı tarafında hiçbir şey değişmiyor: sunucu
        // sadece "her zaman açık bir kaynak eş" oluyor.
        self.queue_blob_upload(&file_id, &file_key, attachments::total_chunks_with(total_size, attachments::FILE_CHUNK_SIZE_V2));
        let (_, status) = self.send_message_content(peer_device_fingerprint.clone(), &content, None)?;
        // `send_message` ile aynı: kişinin diğer cihazları + kendi kardeşlerim.
        self.fanout_extra_copies(&peer_device_fingerprint, &content);
        self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::File { offer: Box::new(content) });
        Ok((file_id, status))
    }

    /// Undoes what `finish_outgoing_file` / `finish_outgoing_group_file` wrote
    /// before they failed: the caller (`encrypt_then_finish`) deletes the
    /// `.enc`, so a 'complete' row and a queued server upload would point at a
    /// file that no longer exists.
    pub(crate) fn discard_outgoing_file(&mut self, file_id: &str) {
        self.finish_blob_upload(file_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM files WHERE file_id = ?1 AND direction = 'sent'", params![file_id]);
        }
    }

    /// `prepare_and_send_file`'ın
    /// grup karşılığı — dosya TEK SEFERDE şifrelenip diske yazılır (`file_id`/
    /// `file_key` TÜM üyeler arasında PAYLAŞILIR, bkz. `serve_chunk_request`
    /// notu: indirme isteği SADECE `file_id`'ye bakar, isteyen kimliğini
    /// KONTROL ETMEZ — bu yüzden aynı `.enc` blob'u N farklı üyeye ayrı ayrı
    /// serve etmek doğal olarak çalışır, ekstra bir mekanizma gerekmez).
    /// `archive_group_message`/`send_group_message`'daki AYNI desen: ÖNCE
    /// kendi arşiv satırımızı YAZ (fan-out döngüsünün dışında, tek satır),
    /// SONRA her üyeye ayrı ayrı `FileOffer` gönder.
    /// bkz. `begin_outgoing_file` — kilitli son faz (grup). Doğrulama
    /// (grubun varlığı) kilitli İLK fazda da yapıldı; burada gruba yeniden
    /// bakılır (kilitsiz şifreleme sırasında silinmiş olabilir — bu durumda
    /// temiz bir hata döner, `.enc` çağıran serbest fonksiyonda temizlenir).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_outgoing_group_file(&mut self, group_id: String, file_id: String, file_key: [u8; 32], total_size: u64, sha256_hex: String, chunk_hashes: Vec<u8>, file_name: String, mime_type: String, preview_jpeg: Option<Vec<u8>>, duration_ms: Option<u32>, caption: String, reply_to_message_id: Option<String>, reply_to_preview: Option<String>, reply_to_sender_identity_id: Option<String>, sticker_origin: Option<String>) -> Result<String, String> {
        let sticker = sticker_origin.is_some();
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        let (encrypted_key, key_nonce) = self.wrap_file_key(&file_key)?;
        if let Some(conn) = &self.db {
            // bkz. `finish_outgoing_file` (1:1) AYNI hata — kolon listesi
            // (17) VALUES listesinden (21 ifade) kısa kalıyordu; grup ekleri
            // için gönderen `files` satırını hiç yazamıyordu. Kolon listesi
            // artık 21: `caption`, `reply_to_message_id`, `reply_to_preview`,
            // `reply_to_sender_identity_id` de eklendi.
            let res = conn.execute(
                "INSERT OR REPLACE INTO files
                 (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size,
                  sha256_hex, encrypted_file_key, key_nonce, status, bytes_transferred, created_at, preview_jpeg, duration_ms, group_id, sender_identity_id, chunk_size,
                  caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, chunk_hashes)
                 VALUES (?1, '', 'sent', ?2, ?3, ?4, ?5, ?6, ?7, 'complete', ?4, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
                params![
                    file_id, file_name, mime_type, total_size as i64,
                    sha256_hex, encrypted_key, key_nonce, current_time_ms() as i64, preview_jpeg, duration_ms,
                    group_id, own_identity_id, attachments::FILE_CHUNK_SIZE_V2 as i64,
                    caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin.clone(), chunk_hashes,
                ],
            );
            if let Err(e) = res {
                error!("finish_outgoing_group_file: `files` satırı yazılamadı (file_id={}): {}", file_id, e);
                return Err(format!("Dosya kaydı yazılamadı: {}", e));
            }
        }
        self.enforce_history_storage_limit();

        let content = MessageContent::FileOffer {
            group_id: Some(group_id.clone()),
            file_id: file_id.clone(),
            file_name,
            mime_type,
            total_size,
            file_key,
            sha256_hex,
            preview_jpeg,
            duration_ms,
            chunk_size: Some(attachments::FILE_CHUNK_SIZE_V2 as u32),
            chunk_hashes,
            caption: caption.clone(),
            reply_to_message_id: reply_to_message_id.clone(),
            reply_to_preview: reply_to_preview.clone(),
            reply_to_sender_identity_id: reply_to_sender_identity_id.clone(),
            sticker,
            sticker_origin,
        };
        for member_identity_id in group.other_members(&own_identity_id) {
            // Like every other group send: all active devices, queued when no
            // device is known yet, skipped for deleted accounts.
            self.send_group_message_to_member(&group_id, &member_identity_id, &content);
        }
        self.echo_group_to_siblings(&group_id, SiblingEchoBody::File { offer: Box::new(content) });
        // bkz. `finish_outgoing_file` içindeki aynı kanca.
        self.queue_blob_upload(&file_id, &file_key, attachments::total_chunks_with(total_size, attachments::FILE_CHUNK_SIZE_V2));
        Ok(file_id)
    }

    /// Gelen bir `FileOffer`'ı işler: `files` tablosuna bir alıcı kaydı
    /// ekler (node modu açıksa hemen indirmeyi başlatır — kapalıysa sadece
    /// meta veri görünür kalır, kullanıcı "İndir" demeli).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn receive_file_offer(&mut self, peer_fp: &str, sender_identity_id: &str, group_id: Option<String>, file_id: &str, file_name: &str, mime_type: &str, total_size: u64, file_key: &[u8; 32], sha256_hex: &str, preview_jpeg: &Option<Vec<u8>>, duration_ms: Option<u32>, chunk_size: Option<u32>, chunk_hashes: &[u8], caption: &str, reply_to_message_id: Option<&str>, reply_to_preview: Option<&str>, reply_to_sender_identity_id: Option<&str>, sticker: bool, sticker_origin: Option<&str>) -> serde_json::Value {
        // `MAX_ATTACHMENT_SIZE`
        // önceden SADECE gönderim tarafında (`prepare_and_send_file`/
        // `prepare_and_send_group_file`, bkz. o fonksiyonların kontrolü)
        // uygulanıyordu — ALICI taraf, karşı taraftan gelen `total_size`
        // alanına hiç güvenmiyordu ki bunu kontrol etsin: kötü niyetli/bozuk
        // bir eş, `u64::MAX`'e yakın bir `total_size` göndererek aşağıdaki
        // `total_size as i64` dönüşümünü (ki taşarsa negatif bir sütun
        // değeri yazar) ve `attachments::total_chunks_with`'teki
        // `total_size + FILE_CHUNK_SIZE - 1` toplamını (release'de sessizce
        // sarabilir) tetikleyebilirdi — ikisi de `files` tablosuna bozuk bir
        // satır yazılmasına yol açardı. Artık alıcı tarafta da aynı üst
        // sınır uygulanıyor; aşan bir teklif hiçbir DB satırı yazmadan
        // reddedilir.
        // The peer's chunk size becomes buffer sizes and file offsets here.
        if chunk_size.map_or(false, |c| !attachments::chunk_size_ok(c as usize)) {
            warn!("FileOffer REDDEDİLDİ: geçersiz parça boyutu {:?} (gönderen: {})", chunk_size, crate::log_id(&peer_fp));
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Geçersiz parça boyutu"
            });
        }
        // `file_id` karşı taraftan geliyor ve birazdan dosya
        // yoluna dönüşecek — ÖNCE doğrula (bkz. `is_safe_file_id`).
        if !is_safe_file_id(file_id) {
            warn!(
                "FileOffer REDDEDİLDİ: file_id yol olarak güvenli değil (gönderen: {}, id: {:?})",
                crate::log_id(&peer_fp), file_id
            );
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Geçersiz dosya kimliği"
            });
        }
        // aşağıdaki yazma `INSERT OR REPLACE` — karşı taraf,
        // KENDİSİNE gönderdiğimiz bir dosyanın `file_id`'sini (ki teklifi
        // ona biz yolladık, yani biliyor) geri gönderirse bizdeki
        // `direction='sent'` satırı 'received' olarak EZİLİYORDU. Sonuç:
        // kendi giden ekimizin kaydı kayboluyor, `serve_chunk_request`
        // artık `NotFound` dönüyor (durum 'complete' değil) — yani o
        // dosyayı bekleyen DİĞER bütün alıcılar da indiremiyor — ve indirme
        // başlatılırsa `download_file`'ın `remove_file`'ı kendi şifreli
        // `.enc` dosyamızı siliyordu.
        // Stored and handed to the UI as they come.
        if sha256_hex.len() != 64 || !sha256_hex.bytes().all(|b| b.is_ascii_hexdigit())
            || mime_type.len() > 255 || caption.len() > 64 * 1024
            || preview_jpeg.as_ref().map_or(false, |p| p.len() > 512 * 1024)
        {
            warn!("FileOffer REDDEDİLDİ: alanlar geçersiz ya da çok büyük (gönderen: {})", crate::log_id(&peer_fp));
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Geçersiz dosya teklifi"
            });
        }
        let existing: Option<(String, Option<String>, Option<String>)> = self.db.as_ref().and_then(|conn| {
            conn.query_row(
                "SELECT direction, sender_identity_id, group_id FROM files WHERE file_id = ?1",
                params![file_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).ok()
        });
        let existing_direction = existing.as_ref().map(|e| e.0.clone());
        // Any existing row is final. A repeated offer (lost Ack) reset a
        // finished download to 'offered'; an offer from another chat with a
        // known file_id replaced the row's key and made the file unreadable.
        if let Some((_, row_sender, row_group)) = existing.as_ref().filter(|e| e.0 == "received") {
            // The same offer again. From somebody else, or in another chat,
            // it is another file under a taken id: a member that saw a group
            // offer first could send its own under that id, and the real one
            // was then dropped without a trace. Shown as failed instead.
            if row_sender.as_deref().map_or(true, |s| s == sender_identity_id) && *row_group == group_id {
                return serde_json::json!({"type": "noop"});
            }
            warn!("FileOffer REDDEDİLDİ: file_id başka bir gönderenin dosyasıyla çakışıyor (gönderen: {}, id: {})", crate::log_id(&peer_fp), file_id);
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Dosya kimliği çakışması"
            });
        }
        let collides_with_own_outgoing = existing_direction.is_some();
        if collides_with_own_outgoing {
            warn!(
                "FileOffer REDDEDİLDİ: file_id kendi GİDEN dosyamızla çakışıyor (gönderen: {}, id: {})",
                crate::log_id(&peer_fp), file_id
            );
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Dosya kimliği çakışması"
            });
        }
        if total_size > MAX_ATTACHMENT_SIZE {
            warn!(
                "FileOffer reddedildi: total_size ({}) MAX_ATTACHMENT_SIZE'ı ({}) aşıyor (gönderen: {})",
                total_size, MAX_ATTACHMENT_SIZE, crate::log_id(&peer_fp)
            );
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Dosya boyutu izin verilen üst sınırı aşıyor"
            });
        }
        // One hash per chunk group, signed with the offer: every chunk is
        // checked against it (`handle_chunk_response`). No list, no download.
        let offer_chunks = attachments::total_chunks_with(total_size, chunk_size.map_or(attachments::FILE_CHUNK_SIZE, |c| c as usize));
        if chunk_hashes.len() != attachments::chunk_hashes_len(offer_chunks) {
            warn!("FileOffer REDDEDİLDİ: parça hash listesi yok ya da boyu yanlış (gönderen: {})", crate::log_id(&peer_fp));
            return serde_json::json!({
                "type": "file_failed", "peer": peer_fp, "sender_identity_id": sender_identity_id,
                "group_id": group_id, "file_id": file_id,
                "error": "Geçersiz dosya teklifi"
            });
        }
        // Güvenlik düzeltmesi (bu denetim): `file_name` uzaktan kontrollü ve
        // hem bir dosya adı olarak kullanılıyor hem ekranda gösteriliyor —
        // TEK giriş kapısı burası, bkz. `safe_file_name`. Temizlenmiş hâli
        // DB'ye yazılır, böylece her iki istemci ve "İndirilenler'e kaydet"
        // akışı otomatik olarak korunur.
        let file_name = safe_file_name(file_name);
        let file_name = file_name.as_str();
        // 8 running downloads, at most 4 from one sender (H99: one contact
        // took the whole budget). The rest stay "offered".
        // Stickers are small and shown at once: fetched in any node mode.
        // A peer's `sticker` flag forces a download: only for a real sticker file.
        let sticker = sticker && total_size <= attachments::MAX_STICKER_BYTES
            && mime_type == "image/jxl" && file_name.to_ascii_lowercase().ends_with(".jxl");
        // Only the content id (`jxl:<offer sha>`) is kept: a reuse below is
        // checked against that hash; a peer-claimed `wa:` id is not checkable.
        let sticker_origin = sticker_origin.filter(|o| sticker && valid_sticker_origin(o) && o.strip_prefix("jxl:") == Some(sha256_hex));
        // Running downloads are charged at their declared size: each offer
        // alone fitting the limit let 8 of them overshoot it together.
        let in_flight: u64 = self.active_downloads.values().map(|d| d.total_size).sum();
        let auto_download_requested = (sticker
                || self.node_mode_enabled && in_flight.saturating_add(total_size) <= self.history_storage_limit_bytes)
            && self.active_downloads.len() < 8
            && self.active_downloads.values().filter(|d| d.peer_device_fingerprint == peer_fp).count() < 4;
        // Satır YAZILAMADIYSA (ör. şifreleme anahtarı henüz yüklenmedi),
        // "offered" olarak devam ediyoruz — DB kaydı olmadan "downloading"
        // raporlamak, `download_file`'ın hiçbir zaman bulamayacağı bir
        // dosya için Kotlin tarafında sonsuza kadar takılı bir UI'ye yol
        // açardı (bkz. dosya sonu not).
        let row_written = match self.wrap_file_key(file_key) {
            Ok((encrypted_key, key_nonce)) => {
                let status = if auto_download_requested { "downloading" } else { "offered" };
                let ok = if let Some(conn) = &self.db {
                    conn.execute(
                        "INSERT OR REPLACE INTO files
                         (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size,
                          sha256_hex, encrypted_file_key, key_nonce, status, bytes_transferred, created_at, preview_jpeg, duration_ms, group_id, sender_identity_id, chunk_size,
                          caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, chunk_hashes)
                         VALUES (?1, ?2, 'received', ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
                        params![
                            file_id, peer_fp, file_name, mime_type, total_size as i64,
                            sha256_hex, encrypted_key, key_nonce, status, current_time_ms() as i64, preview_jpeg, duration_ms,
                            group_id, sender_identity_id,
                            // `None` = guncellenmemis bir esten gelen teklif:
                            // miras 256 KiB (bkz. `FileOffer.chunk_size`).
                            chunk_size.map(|v| v as i64).unwrap_or(attachments::FILE_CHUNK_SIZE as i64),
                            caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, chunk_hashes,
                        ],
                    ).is_ok()
                } else {
                    false
                };
                ok
            }
            Err(e) => {
                error!("FileOffer için dosya anahtarı sarmalanamadı: {}", e);
                false
            }
        };

        // önceden burada `download_file`'ın başarısız
        // olması (ör. `device_to_peer_id`'de bu peer henüz yoksa) sadece
        // loglanıyordu — çağıran taraf (Kotlin) her zaman
        // "auto_downloading": true görüyordu ve UI "İndiriliyor" durumunda
        // sonsuza kadar takılı kalıyordu (indirme hiçbir zaman
        // `active_downloads`'a eklenmediği, dolayısıyla hiçbir zaman
        // hata/tamamlanma olayı üretmediği için). Artık gerçek sonucu
        // (`auto_downloading` alanı) doğru raporluyoruz.
        // No row: no bubble either (it failed on tap and was gone on reload).
        // The caller sends no Ack for this, so the offer comes again.
        if !row_written {
            return serde_json::json!({"type": "noop"});
        }
        // A sticker already in my store (same content hash): made here, no transfer.
        let reused = match sticker_origin {
            Some(_) => {
                let chunk = chunk_size.map_or(attachments::FILE_CHUNK_SIZE, |c| c as usize);
                let r = self.reuse_local_sticker(file_id, file_key, chunk, sha256_hex);
                if r.is_ok() {
                    self.attachment_events.push(serde_json::json!({"type": "file_complete", "peer": self.canonical_peer_key(peer_fp), "file_id": file_id}).to_string());
                }
                r.is_ok()
            }
            None => false,
        };
        let auto_downloading = !reused && auto_download_requested && {
            match self.download_file(file_id.to_string(), peer_fp.to_string()) {
                Ok(()) => true,
                Err(e) => {
                    error!("Otomatik dosya indirme başlatılamadı (node modu açık): {}", e);
                    if let Some(conn) = &self.db {
                        let _ = conn.execute("UPDATE files SET status = 'failed' WHERE file_id = ?1", params![file_id]);
                    }
                    self.attachment_events.push(serde_json::json!({"type": "file_failed", "peer": self.canonical_peer_key(peer_fp), "file_id": file_id, "error": e}).to_string());
                    false
                }
            }
        };

        // Çoklu-cihaz: 1:1 canlı olayı KANONİK sohbet cihazı altında yayınla
        // (kişinin ikincil cihazından gelse bile doğru sohbette görünsün).
        // Grup olayı `group_id` ile yönlendirildiğinden `peer` grupta önemsiz.
        let chat_peer = if group_id.is_none() { self.canonical_peer_key(peer_fp) } else { peer_fp.to_string() };
        serde_json::json!({
            // `sender_identity_id`: grup eklerinde bildirimi "kim gönderdi"
            // ile gösterebilmek için (bkz. P2PService.maybeNotify
            // "file_offer" kolu) — 1:1'de zaten `peer` yeterli.
            "type": "file_offer", "peer": chat_peer, "sender_identity_id": sender_identity_id,
            "group_id": group_id, "file_id": file_id,
            "file_name": file_name, "mime_type": mime_type, "total_size": total_size,
            "auto_downloading": auto_downloading, "complete": reused, "sticker": sticker,
            // Hex-encoded — JSON ham ikili veri taşıyamaz. Küçük bir
            // önizleme (tipik birkaç on KB) için hex'in base64'e göre ~%37
            // daha büyük olması önemsiz; yeni bir bağımlılık eklemekten
            // kaçınmak için mevcut `hex` crate'i kullanılıyor.
            "preview_hex": preview_jpeg.as_ref().map(|p| hex::encode(p)),
            "duration_ms": duration_ms,
            // ekle birlikte gelen açıklama ve
            // (varsa) yanıtlanan mesaj bağlamı — ek balonu bunları metin
            // mesajlarıyla AYNI biçimde gösteriyor.
            "caption": caption,
            "reply_to_message_id": reply_to_message_id,
            "reply_to_preview": reply_to_preview,
            "reply_to_sender_identity_id": reply_to_sender_identity_id,
        })
    }

    /// Spec dışı (dış AI incelemesi düzeltmesi — "FileOffer ack'lendi ama
    /// dosya sessizce kayboldu"): `reconnected` kümesindeki cihazlardan biri,
    /// DAHA ÖNCE indirilmeye başlanmış ama YARIM/BAŞARISIZ kalmış bir
    /// dosyanın kaynağıysa, o indirmeyi OTOMATİK yeniden başlat. Önceden
    /// FileOffer ack'lense (yalnızca metadata teslim edilse) bile, kaynak
    /// indirme ortasında çevrimdışı olursa alıcı `DOWNLOAD_GIVE_UP_TIMEOUT_MS`
    /// (10 dk) sonunda KALICI olarak pes ediyor ve kaynak geri döndüğünde
    /// dosyayı bir daha ASLA otomatik istemiyordu — kullanıcının elle "tekrar
    /// dene"mesi gerekiyordu (yanıltıcı teslim garantisi). Artık kaynak
    /// yeniden bağlandığı an sürdürülür. SADECE `direction='received'` ve
    /// durumu 'downloading' (ama artık `active_downloads`'da canlı DEĞİL —
    /// yani süreç ölmüş/pes edilmiş) ya da 'failed' olan dosyalar; kullanıcının
    /// indirmeyi hiç başlatmadığı 'offered' dosyalara DOKUNULMAZ (istenmeyen
    /// otomatik indirme olmaz).
    /// `server_back`: a server just enrolled — any partial download may have
    /// its blob there, so every row is a candidate.
    /// A row without chunk hashes (an offer from before them, I-41) is never
    /// a candidate: `download_file` refuses it every time.
    pub(crate) fn resume_incomplete_downloads_for(&mut self, reconnected: &std::collections::HashSet<String>, server_back: bool) {
        if reconnected.is_empty() && !server_back { return; }
        let candidates: Vec<(String, String, u64)> = {
            let conn = match &self.db { Some(c) => c, None => return };
            let mut stmt = match conn.prepare(
                "SELECT file_id, peer_device_fingerprint, total_size FROM files \
                 WHERE status IN ('downloading','failed') AND direction = 'received' \
                 AND length(chunk_hashes) > 0"
            ) { Ok(s) => s, Err(_) => return };
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? as u64)))
                .map(|it| it.flatten().collect())
                .unwrap_or_default()
        };
        for (file_id, owner_fp, total_size) in candidates {
            // Kaynak (satırda kayıtlı gönderen cihaz) az önce bağlanmadıysa
            // dokunma — hâlâ ulaşılamaz, boşuna bir dial denemesi olur.
            if !server_back && !reconnected.contains(&owner_fp) { continue; }
            if self.active_downloads.contains_key(&file_id) { continue; }
            // The caps of `receive_file_offer`: 8 running, 4 per sender, and
            // the storage limit. The rest waits for a later reconnect or a tap.
            if self.active_downloads.len() >= 8 { break; }
            if self.active_downloads.values().filter(|d| d.peer_device_fingerprint == owner_fp).count() >= 4 { continue; }
            let in_flight: u64 = self.active_downloads.values().map(|d| d.total_size).sum();
            if in_flight.saturating_add(total_size) > self.history_storage_limit_bytes { continue; }
            // Once per process run unless it made progress since (#76,
            // `handle_chunk_response`): a file that fails each time restarted
            // on every reconnect of its owner. After that it waits for a tap.
            if !self.auto_resumed_downloads.insert(file_id.clone()) { continue; }
            info!("Yarım kalan indirme, kaynak yeniden bağlandığı için sürdürülüyor: file_id={} kaynak={}", file_id, crate::log_id(&owner_fp));
            if let Err(e) = self.download_file(file_id.clone(), owner_fp.clone()) {
                warn!("İndirme yeniden bağlanmada sürdürülemedi: file_id={} {}", file_id, e);
            }
        }
    }

    /// Bir dosyanın indirmesini (kullanıcının "İndir" dokunuşu VEYA node
    /// modu açıkken otomatik) başlatır/devam ettirir. Zaten indiriliyorsa
    /// veya tamamlanmışsa no-op.
    pub(crate) fn download_file(&mut self, file_id: String, peer_device_fingerprint: String) -> Result<(), String> {
        info!("download_file çağrıldı: file_id={} peer={}", file_id, crate::log_id(&peer_device_fingerprint));
        if self.active_downloads.contains_key(&file_id) {
            info!("download_file: {} zaten indiriliyor, no-op", file_id);
            return Ok(());
        }
        // without a swarm no chunk is ever requested; the UI showed
        // "downloading" for 10 min instead of an error.
        if self.swarm.is_none() {
            return Err("Ağ henüz başlatılmadı".to_string());
        }
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let row: Option<(u64, Vec<u8>, Vec<u8>, String, String, Option<String>, Option<Vec<u8>>)> = conn.query_row(
            "SELECT total_size, encrypted_file_key, key_nonce, status, peer_device_fingerprint, group_id, chunk_hashes FROM files WHERE file_id = ?1",
            params![file_id],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, String>(4)?, r.get(5)?, r.get(6)?)),
        ).ok();
        let (total_size, encrypted_key, key_nonce, status, owner_fp, group_id, chunk_hashes) = row.ok_or("Unknown file_id")?;
        let chunk_hashes = chunk_hashes.unwrap_or_default();
        // Çoklu-cihaz (spec 1.7.1): dosyayı GERÇEK sahibinden (satırda kayıtlı
        // gönderen cihaz) indir. Çağıran, sohbetin KANONİK cihazını geçmiş
        // olabilir (dosya, o kişinin BAŞKA bir cihazından gelmişse kanonik
        // cihaz onu taşımıyordur) — o zaman kanonik cihazın PeerId'sine
        // istek atmak boşa giderdi. Satırdaki sahip boşsa çağırana düş.
        let peer_device_fingerprint = if owner_fp.is_empty() { peer_device_fingerprint } else { owner_fp };
        if status == "complete" {
            info!("download_file: {} zaten tamamlanmış, no-op", file_id);
            return Ok(());
        }
        let file_key = self.unwrap_file_key(&encrypted_key, &key_nonce)?;

        // Sunucu (bkz. `server_client`) yapılandırılmışsa, dosya orada da
        // duruyor olabilir. Bu, dış incelemedeki #19 maddesini kapatıyor:
        // önceden asıl gönderen çevrimdışıysa indirme 10 dakika boyunca
        // sessizce zaman aşımına uğrayıp başarısız oluyordu.
        let server_peers = self.ready_server_peers();
        let peer_id = match self.device_to_peer_id.get(&peer_device_fingerprint) {
            Some(pid) => *pid,
            None => *server_peers.first().ok_or(
                "Bu kişiden henüz doğrudan bir paket alınmadı, karşı taraf şu an erişilebilir değil",
            )?,
        };
        let cached_addr = self.peer_id_to_addr.get(&peer_id).cloned();
        let already_connected = self.swarm.as_ref().map(|s| s.is_connected(&peer_id)).unwrap_or(false);
        info!(
            "download_file: peer_id={} biliniyor, önbellekteki adres={:?}, swarm zaten bağlı mı={}",
            crate::log_id(&peer_id), cached_addr, already_connected
        );
        if let Some(addr) = cached_addr.clone() {
            if let Some(swarm) = &mut self.swarm {
                swarm.add_peer_address(peer_id, addr);
            }
        }
        // Spec dışı, ağ sağlamlığı düzeltmesi ("geçmişteki bir dosya, node
        // modundan bağımsız olarak istenebilmeli" — kullanıcı raporu): burada
        // önceden SADECE `add_peer_address` çağrılıyordu, bu da adresi
        // swarm'ın adres defterine ekler ama ne aktif bir dial BAŞLATIR ne de
        // (mesajlaşma/handshake yeniden bağlanma yollarının HEPSİNİN
        // kullandığı `dial_with_relay_fallback`'in aksine) bilinen röleler
        // üzerinden bir devre (circuit) dener. Karşı taraf doğrudan dial
        // edilemiyorsa (yaygın bir NAT durumu) `file_chunks.send_request`'in
        // kendi iç dial'ı hiçbir röle denemeden doğrudan başarısız oluyordu —
        // bu da `OutboundFailure` → `DOWNLOAD_GIVE_UP_TIMEOUT_MS`'ye (10 dk)
        // kadar sessiz yeniden deneme → sonunda "Ağ hatası" olarak
        // gözlemleniyordu. Mesajlaşmanın aynı sırada çalışmaya devam etmesi
        // yanıltıcıydı: gossipsub bir röleye/doğrudan bağlantıya ihtiyaç
        // duymadan mesh üzerinden yayılabilir, ama bu request-response
        // protokolü gerçek bir bağlantı gerektirir.
        if !already_connected {
            self.dial_with_relay_fallback(peer_id, cached_addr);
        }

        // Parca boyutu tekliften geldi ve `files` satirinda duruyor —
        // gonderenle AYNI adimi kullanmak zorundayiz (bkz. `file_chunk_size`).
        let chunk_size = self.file_chunk_size(&file_id);
        let total_chunks = attachments::total_chunks_with(total_size, chunk_size);
        // A row without the offer's chunk hashes (an offer from before they
        // existed) cannot be checked chunk by chunk: not downloaded.
        if chunk_hashes.len() != attachments::chunk_hashes_len(total_chunks) {
            return Err("Bu dosyanın parça hash listesi yok, gönderenden yeniden istenmeli".to_string());
        }
        let per_hash = attachments::chunks_per_hash(total_chunks);
        let enc_path = self.enc_path_for(&file_id)?;
        let _ = std::fs::create_dir_all(self.attachments_dir()?);
        // #76 resume: every chunk group a previous attempt left on disk that
        // matches its hash in the offer is kept, wherever it is in the file;
        // the rest is fetched again.
        // ponytail: hashes the whole partial file on this thread; move it off
        // the lock if multi-GB resumes show up as a stall.
        let mut received_chunks: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut resumed_bytes: u64 = 0;
        if enc_path.exists() {
            for (entry, want) in chunk_hashes.chunks_exact(32).enumerate() {
                let first = entry as u32 * per_hash;
                let count = per_hash.min(total_chunks - first);
                if attachments::enc_range_hash(&enc_path, first, count, chunk_size).is_ok_and(|h| h[..] == *want) {
                    for i in first..first + count {
                        received_chunks.insert(i);
                        resumed_bytes += attachments::chunk_plain_len(total_size, chunk_size, i);
                    }
                }
            }
        }
        let resumed = (0..total_chunks).find(|i| !received_chunks.contains(i)).unwrap_or(total_chunks);
        if !received_chunks.is_empty() {
            info!("download_file: {} kaldığı yerden sürüyor, {}/{} parça diskte", file_id, received_chunks.len(), total_chunks);
        }

        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET status = 'downloading', bytes_transferred = ?2 WHERE file_id = ?1", params![file_id, resumed_bytes as i64]);
        }

        // bu bir
        // grup dosyasıysa, DİĞER üyelerin bilinen/aktif cihazlarını (asıl
        // kaynak HARİÇ) alternatif aday olarak topla — bkz. `DownloadState.
        // alt_source_peer_ids` dokümantasyonu. Kimin GERÇEKTEN tamamladığını
        // bilmiyoruz, bu yüzden hepsi aday; gerçekte sahip olmayanlar
        // sadece ANINDA bir `NotFound` üretir (zararsız).
        let alt_source_peer_ids: std::collections::VecDeque<PeerId> = match &group_id {
            Some(gid) => self.groups.get(gid)
                .map(|g| g.member_identity_ids())
                .unwrap_or_default()
                .into_iter()
                .flat_map(|member_id| self.active_devices_for_identity(&member_id))
                .filter(|fp| fp != &peer_device_fingerprint)
                .filter_map(|fp| self.device_to_peer_id.get(&fp).copied())
                .collect(),
            // 1:1: kendi kardeşlerim — kardeşimin gönderdiği bir ekin
            // yankısında satırdaki sahip karşı taraftır, dosya ise kardeşte.
            None => self.sibling_active_devices()
                .into_iter()
                .filter(|fp| fp != &peer_device_fingerprint)
                .filter_map(|fp| self.device_to_peer_id.get(&fp).copied())
                .collect(),
        };
        // Sunucular ÖNE eklenir: bir sunucu tanım gereği her zaman açık,
        // bir eş cihaz değil. `serve_chunk_request` karşılığı sunucuda da
        // dosya yoksa ANINDA `NotFound` döner, yani yanlış tahminin
        // maliyeti bir gidiş-dönüş.
        let mut alt_source_peer_ids = alt_source_peer_ids;
        for sp in server_peers.into_iter().rev() {
            if sp != peer_id {
                alt_source_peer_ids.push_front(sp);
            }
        }

        self.active_downloads.insert(file_id.clone(), DownloadState {
            chunk_hashes,
            per_hash,
            pending_chunks: std::collections::HashMap::new(),
            bad_sources: std::collections::HashSet::new(),
            peer_id,
            peer_device_fingerprint: peer_device_fingerprint.clone(),
            total_size,
            total_chunks,
            next_chunk_index: resumed,
            bytes_done: resumed_bytes,
            file_key,
            enc_path,
            last_progress_at: current_time_ms(),
            last_retry_at: current_time_ms(),
            alt_source_peer_ids,
            retries_on_current_source: 0,
            inflight_chunks: std::collections::HashSet::new(),
            received_chunks,
            window: DOWNLOAD_WINDOW_START,
            chunk_sent_at: std::collections::HashMap::new(),
            rtt_min: u64::MAX,
            started_at: current_time_ms(),
            chunk_size,
            retry_at: 0,
        });
        self.request_next_chunk(&file_id);
        Ok(())
    }

    /// Bir sonraki parçayı ister — sıra bittiyse (`next_chunk_index >=
    /// total_chunks`) indirmeyi tamamlanmış sayar. Spec dışı, ağ sağlamlığı
    /// düzeltmesi: bu bir YENİDEN DENEMEYSE (bkz. `retry_or_give_up_download`
    /// — aynı `next_chunk_index` için önceki bir istek zaten yapılmış
    /// olabilir), ESKİ istek kimliğini `download_request_ids`'ten ÖNCE
    /// temizler — aksi hâlde GEÇ gelen eski bir yanıt/hata, `next_chunk_index`
    /// artık ilerlemiş olsa bile YANLIŞ parçaya (veri bozulmasına) uygulanabilirdi.
    pub(crate) fn request_next_chunk(&mut self, file_id: &str) {
        // Bitiş koşulu artık GELEN parça sayısına bakar; `next_chunk_index`
        // yalnızca bitişik su seviyesi (bkz. `received_chunks`).
        let done = match self.active_downloads.get(file_id) {
            Some(s) => s.received_chunks.len() as u32 >= s.total_chunks,
            None => return,
        };
        if done {
            self.finalize_download(file_id);
            return;
        }
        // Boru hattını doldur: eksik olan İLK `window` parçayı aynı anda
        // iste. Tek parça havadayken hız gidiş-dönüş süresine kilitleniyordu;
        // sabit ve fazla derin bir pencere ise hattı boğuyordu (bkz.
        // `DOWNLOAD_WINDOW_START`).
        let (want, peer): (Vec<u32>, PeerId) = match self.active_downloads.get(file_id) {
            Some(s) => {
                let mut v = Vec::new();
                // Everything below the contiguous mark is already here.
                for idx in s.next_chunk_index..s.total_chunks {
                    if v.len() + s.inflight_chunks.len() >= s.window {
                        break;
                    }
                    if s.received_chunks.contains(&idx) || s.inflight_chunks.contains(&idx) || s.pending_chunks.contains_key(&idx) {
                        continue;
                    }
                    v.push(idx);
                }
                (v, s.peer_id)
            }
            None => return,
        };
        if want.is_empty() {
            return;
        }
        let mut issued: Vec<(request_response::OutboundRequestId, u32)> = Vec::new();
        if let Some(swarm) = &mut self.swarm {
            for idx in want {
                let request_id = swarm.behaviour_mut().file_chunks.send_request(
                    &peer, FileChunkRequest { file_id: file_id.to_string(), chunk_index: idx },
                );
                issued.push((request_id, idx));
            }
        }
        let now = current_time_ms();
        for (request_id, idx) in issued {
            if let Some(s) = self.active_downloads.get_mut(file_id) {
                s.inflight_chunks.insert(idx);
                s.chunk_sent_at.insert(idx, now);
            }
            self.download_request_ids.insert(request_id, (file_id.to_string(), idx));
        }
    }

    /// Moves the download to its next alternative source (bkz.
    /// `DownloadState.alt_source_peer_ids`) and dials it. `None`: no candidate
    /// left, nothing changed. The caller asks for the chunks again
    /// (`request_next_chunk`).
    pub(crate) fn switch_to_alt_source(&mut self, file_id: &str) -> Option<PeerId> {
        // The list is built when the download starts: a server that was not
        // connected yet (the app had just started) was never tried, and a
        // file whose sender is offline retried that sender for 10 minutes.
        let ready = self.ready_server_peers();
        let s = self.active_downloads.get_mut(file_id)?;
        if s.alt_source_peer_ids.is_empty() {
            s.alt_source_peer_ids.extend(ready.into_iter().filter(|p| *p != s.peer_id && !s.bad_sources.contains(p)));
        }
        // A source that served a chunk not matching the offer's hashes is
        // never picked again in this attempt.
        let next_peer = loop {
            let p = s.alt_source_peer_ids.pop_front()?;
            if !s.bad_sources.contains(&p) {
                break p;
            }
        };
        s.peer_id = next_peer;
        s.retries_on_current_source = 0;
        // Eski kaynağa gönderilmiş istekler artık gelmeyecek; temizlenmezse o
        // indeksler sonsuza dek "havada" sayılır ve pencere bir daha dolmaz.
        s.inflight_chunks.clear();
        s.chunk_sent_at.clear();
        // Yeni kaynağın kapasitesi bilinmiyor — pencere ve taban gecikme
        // ölçümü baştan.
        s.window = DOWNLOAD_WINDOW_START;
        s.rtt_min = u64::MAX;
        // Up to `window` requests are still open at the old source. Their late
        // answers (it usually says NotFound to each) must not count against
        // the new source: every one of them switched the source again, and a
        // download that ran fine used up its candidates and failed.
        self.download_request_ids.retain(|_, (fid, _)| fid != file_id);
        let already_connected = self.swarm.as_ref().map(|s| s.is_connected(&next_peer)).unwrap_or(false);
        if !already_connected {
            // With its address: relays alone never reached a member we share
            // no connected relay with.
            let direct = self.peer_id_to_addr.get(&next_peer).cloned();
            self.dial_with_relay_fallback(next_peer, direct);
        }
        Some(next_peer)
    }

    /// "her şey
    /// onaylanana/çok çok uzun -10 dk- bir zaman aşımına kadar denenmeli"):
    /// bir parça isteği stall oldu (`check_stalled_downloads`) VEYA
    /// libp2p'den açık bir `OutboundFailure` geldiğinde çağrılır. SON
    /// GERÇEK ilerlemeden (`last_progress_at`) beri `DOWNLOAD_GIVE_UP_TIMEOUT_MS`
    /// geçmediyse AYNI parçayı yeniden ister (`request_next_chunk`);
    /// geçtiyse artık gerçekten pes edip indirmeyi başarısız sayar.
    pub(crate) fn retry_or_give_up_download(&mut self, file_id: &str, reason: &str) {
        let now = current_time_ms();
        let elapsed_since_progress = match self.active_downloads.get(file_id) {
            Some(s) => now.saturating_sub(s.last_progress_at),
            None => return, // indirme zaten kaldırılmış/iptal edilmiş
        };
        if elapsed_since_progress > DOWNLOAD_GIVE_UP_TIMEOUT_MS {
            error!(
                "İndirme {} dakikadır hiç ilerlemedi, pes ediliyor: file_id={} ({})",
                DOWNLOAD_GIVE_UP_TIMEOUT_MS / 60_000, file_id, reason
            );
            self.fail_download(file_id, reason);
            return;
        }
        // mevcut
        // kaynak ardışık birkaç kez ilerleme sağlamadıysa VE alternatif bir
        // aday varsa (bkz. `DownloadState.alt_source_peer_ids`), aynı
        // kaynağı süresiz yoklamak yerine bir sonraki adaya geçilir.
        const RETRIES_BEFORE_SOURCE_SWITCH: u32 = 2;
        let over_limit = {
            let s = match self.active_downloads.get_mut(file_id) { Some(s) => s, None => return };
            s.last_retry_at = now;
            s.retries_on_current_source += 1;
            s.retries_on_current_source > RETRIES_BEFORE_SOURCE_SWITCH
        };
        let old_peer = self.active_downloads.get(file_id).map(|s| s.peer_id);
        let switched_to = if over_limit { self.switch_to_alt_source(file_id) } else { None };
        // A silent source may only be offline for a minute: it goes back to
        // the end of the list, so the candidates rotate and are not used up.
        if let (Some(_), Some(old), Some(s)) = (switched_to, old_peer, self.active_downloads.get_mut(file_id)) {
            s.alt_source_peer_ids.push_back(old);
        }
        if let Some(next_peer) = switched_to {
            warn!(
                "İndirme mevcut kaynaktan {} kez yanıt alamadı, ALTERNATİF bir kaynağa geçiliyor: file_id={} yeni_peer={}",
                RETRIES_BEFORE_SOURCE_SWITCH, file_id, crate::log_id(&next_peer)
            );
        }
        info!("İndirme geçici olarak yanıt vermedi ({}), parçalar yeniden isteniyor: file_id={}", reason, file_id);
        // Havadaki istekler takıldı (yanıt gelmedi ya da kaynak değişti):
        // temizlenmezlerse o indeksler `inflight_chunks`te sonsuza dek kalır
        // ve boru hattı penceresi bir daha DOLMAZ — indirme sessizce durur.
        // Tekrar istemek güvenli: aynı parça iki kez gelirse
        // `handle_chunk_response` `received_chunks` kontrolüyle ikinciyi
        // yok sayar.
        if let Some(st) = self.active_downloads.get_mut(file_id) {
            st.inflight_chunks.clear();
            st.chunk_sent_at.clear();
            // Takılma = hat boğulmuş olabilir; pencereyi yarıya indir
            // (bkz. `DOWNLOAD_WINDOW_MIN`). Kaynak DEĞİŞTİYSE yukarıda
            // zaten başlangıç değerine döndürüldü — yeni kaynağı eskisinin
            // tıkanıklığı yüzünden cezalandırmayalım.
            if switched_to.is_none() {
                st.window = (st.window / 2).max(DOWNLOAD_WINDOW_MIN);
            }
        }
        self.download_request_ids.retain(|_, (fid, _)| fid != file_id);
        self.request_next_chunk(file_id);
    }

    /// `file_progress`/`file_complete`/`file_failed` olaylarının `"peer"`
    /// alanını doldurmak için — önce (henüz kaldırılmamışsa)
    /// `active_downloads`'a, yoksa (ör. indirme zaten sonlandırılmışsa)
    /// `files` tablosuna bakar. Bulunamazsa boş string döner (olay yine
    /// de üretilir, sadece Kotlin tarafı eşleştiremez — DB kaydı hiç
    /// yoksa zaten daha büyük bir sorun var demektir).
    /// the chat key (canonical device) the screen listens on, not the
    /// device the file came from.
    pub(crate) fn peer_for_file(&self, file_id: &str) -> String {
        if let Some(state) = self.active_downloads.get(file_id) {
            return self.canonical_peer_key(&state.peer_device_fingerprint);
        }
        self.db.as_ref().and_then(|conn| {
            conn.query_row(
                "SELECT peer_device_fingerprint FROM files WHERE file_id = ?1",
                params![file_id],
                |r| r.get::<_, String>(0),
            ).ok()
        }).map(|fp| self.canonical_peer_key(&fp)).unwrap_or_default()
    }

    pub(crate) fn finalize_download(&mut self, file_id: &str) {
        let peer_fp = self.peer_for_file(file_id);
        info!("finalize_download: file_id={} peer={} status='complete' olarak işaretlendi, file_complete olayı üretiliyor", file_id, crate::log_id(&peer_fp));
        if let Some(s) = self.active_downloads.get(file_id) {
            let secs = current_time_ms().saturating_sub(s.started_at) as f64 / 1000.0;
            if secs > 0.0 {
                info!(
                    "İndirme tamamlandı: {} parça, {} bayt, {:.1} sn, {:.0} KB/s, son pencere {}",
                    s.total_chunks, s.bytes_done, secs,
                    (s.bytes_done as f64 / 1024.0) / secs, s.window
                );
            }
        }
        // Every chunk already matched the signed offer's `chunk_hashes`, so the
        // file is the sender's; its plaintext SHA-256 is checked again on
        // every open (`decrypt_file_from_disk_with`).
        let Some(mut state) = self.active_downloads.remove(file_id) else { return };
        // A zero-byte file has no chunk, so no chunk write made its `.enc`:
        // every open failed with "No such file".
        if state.total_chunks == 0 {
            if let Ok(p) = self.enc_path_for(file_id) {
                let _ = std::fs::File::create(p);
            }
        }
        // the peer's `sticker` flag forced this download and
        // makes the chat decode it on sight. Only a real sticker keeps it:
        // its headers must say at most `STICKER_MAX_SIDE` a side.
        let flagged = self.db.as_ref().map_or(false, |c| {
            c.query_row("SELECT sticker FROM files WHERE file_id = ?1", params![file_id], |r| r.get::<_, i64>(0)).unwrap_or(0) != 0
        });
        if flagged {
            let side_ok = self.enc_path_for(file_id).ok()
                .and_then(|p| attachments::read_plain_chunk_with(&p, 0, &state.file_key, state.chunk_size).ok())
                .and_then(|head| attachments::jxl_head(&head))
                .map_or(false, |(w, h, _)| w <= attachments::STICKER_MAX_SIDE && h <= attachments::STICKER_MAX_SIDE);
            if !side_ok {
                warn!("Çıkartma işaretli dosya çıkartma değil, işaret kaldırıldı: {}", file_id);
                if let Some(conn) = &self.db {
                    let _ = conn.execute("UPDATE files SET sticker = 0, sticker_origin = NULL WHERE file_id = ?1", params![file_id]);
                }
            }
        }
        zeroize::Zeroize::zeroize(&mut state.file_key);
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET status = 'complete' WHERE file_id = ?1", params![file_id]);
        }
        self.attachment_events.push(serde_json::json!({"type": "file_complete", "peer": peer_fp, "file_id": file_id}).to_string());
        // Node modu bu dosyayı OTOMATİK indirmiş olabilir (bkz.
        // receive_file_offer) — bkz. `enforce_history_storage_limit` notu.
        self.enforce_history_storage_limit();
    }

    pub(crate) fn fail_download(&mut self, file_id: &str, reason: &str) {
        let peer_fp = self.peer_for_file(file_id);
        // #76: the partial `.enc` stays for the next attempt to resume from
        // (`download_file`); its size on disk goes into `bytes_transferred`,
        // which the quota counts for 'failed' rows too.
        if let Some(mut state) = self.active_downloads.remove(file_id) {
            zeroize::Zeroize::zeroize(&mut state.file_key);
        }
        self.download_request_ids.retain(|_, (fid, _)| fid != file_id);
        let on_disk = self.enc_path_for(file_id).ok()
            .and_then(|p| std::fs::metadata(p).ok())
            .map_or(0, |m| m.len());
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET status = 'failed', bytes_transferred = ?2 WHERE file_id = ?1", params![file_id, on_disk as i64]);
        }
        error!("Dosya indirme başarısız ({}): {}", file_id, reason);
        self.attachment_events.push(serde_json::json!({"type": "file_failed", "peer": peer_fp, "file_id": file_id, "error": reason}).to_string());
    }

    /// `poll_events`'ten her turda çağrılır — bkz. `DOWNLOAD_STALL_TIMEOUT_MS`
    /// dokümantasyonu. Bir indirme, hiçbir ilerleme/başarısızlık olayı
    /// üretmeden bu süreyi aşarsa (tipik olarak: TCP dial hiç sonuçlanmadı,
    /// iki cihaz da NAT arkasında ve doğrudan erişilemez) AYNI parça
    /// otomatik olarak yeniden istenir (bkz. `retry_or_give_up_download`) —
    /// SADECE `DOWNLOAD_GIVE_UP_TIMEOUT_MS` (10 dk) aşılırsa gerçekten
    /// başarısız sayılır, en azından UI SÜRESİZ "İndiriliyor" göstermez.
    pub(crate) fn check_stalled_downloads(&mut self) {
        let now = current_time_ms();
        // bkz. `DownloadState.retry_at`: only the missing chunks, the requests
        // still in flight are kept.
        let due: Vec<String> = self.active_downloads.iter_mut()
            .filter(|(_, s)| s.retry_at != 0 && now >= s.retry_at)
            .map(|(id, s)| { s.retry_at = 0; id.clone() })
            .collect();
        for file_id in due {
            self.request_next_chunk(&file_id);
        }
        // bkz. `DownloadState.last_retry_at` notu — `last_progress_at`
        // DEĞİL, bu alan denemeleri makul aralıklarla seyreltir (aksi
        // hâlde her `poll_events` turunda aynı parça tekrar tekrar istenirdi).
        let stalled: Vec<String> = self.active_downloads.iter()
            .filter(|(_, s)| now.saturating_sub(s.last_retry_at) > DOWNLOAD_STALL_TIMEOUT_MS)
            .map(|(id, _)| id.clone())
            .collect();
        for file_id in stalled {
            self.retry_or_give_up_download(&file_id, "Bağlantı zaman aşımına uğradı — karşı taraf yanıt vermedi");
        }
    }

    /// A chunk `peer` served did not match the offer's `chunk_hashes` (or its
    /// AEAD): `peer` is not asked again in this attempt. When it is the
    /// current source the download moves to the next one, or fails when none
    /// is left; the chunks that matched stay on disk for the next attempt.
    pub(crate) fn drop_bad_source(&mut self, file_id: &str, peer: PeerId, reason: &str) {
        let Some(s) = self.active_downloads.get_mut(file_id) else { return };
        s.bad_sources.insert(peer);
        if s.peer_id != peer {
            self.request_next_chunk(file_id);
            return;
        }
        match self.switch_to_alt_source(file_id) {
            Some(next) => {
                warn!("Parça doğrulanamadı ({}), kaynak bırakıldı, ALTERNATİF bir kaynağa geçiliyor: file_id={} yeni_peer={}", reason, file_id, crate::log_id(&next));
                self.request_next_chunk(file_id);
            }
            None => self.fail_download(file_id, reason),
        }
    }

    /// `poll_events`'in `FileChunks` olay kolundan çağrılır — gelen bir
    /// parça yanıtını işler.
    pub(crate) fn handle_chunk_response(&mut self, file_id: &str, chunk_index: u32, response: FileChunkResponse) {
        let data = match response {
            FileChunkResponse::Chunk { data } => data,
            FileChunkResponse::NotFound => {
                // bu, `retry_or_give_up_download`'ın
                // TERSİNE, AYNI kaynağa KASITLI olarak yeniden DENENMEZ —
                // geçici bir ağ sorunu değil, karşı tarafın KESİN/olumsuz
                // bir yanıtı ("bu dosyam yok"); aynı isteği tekrarlamak
                // sonsuza kadar aynı yanıtı üretir.
                //
                // Spec dışı, dış inceleme düzeltmesi ("çoklu kaynak yok"):
                // önceden bu HER ZAMAN indirmeyi tamamen başarısız
                // sayıyordu. Artık (bir grup dosyasıysa) varsa bir sonraki
                // alternatif kaynak (bkz. `DownloadState.alt_source_peer_ids`)
                // hemen denenir — sadece TÜM adaylar tükenince gerçekten
                // pes edilir.
                // KRİTİK AYRIM (bkz. `server_client`): bir EŞİN "yok"u
                // kesindir — o cihazda o dosya gerçekten yok. Ama bir
                // SUNUCUNUN "yok"u "HENÜZ yok" olabilir: gönderen blob'u hâlâ
                // parça parça yüklüyor olabilir (bkz.
                // `server_blob_uploads`). Sunucu yolu eklendiğinde bu ayrım
                // yapılmadığı için, yüklemesi süren 10 MB'lık bir video
                // ANINDA "Download failed" veriyordu — üstelik gerçek
                // gönderen o sırada çevrimiçiyken.
                let from_server = self
                    .active_downloads
                    .get(file_id)
                    .map(|s| s.peer_id)
                    .map(|p| self.is_server_peer(&p))
                    .unwrap_or(false);
                let old_peer = self.active_downloads.get(file_id).map(|s| s.peer_id);
                let next_peer = self.switch_to_alt_source(file_id);
                // A server's "not yet" goes back to the end of the list (once:
                // not while another server is still in it): members that say
                // "no" in a row must not use up the candidates while the
                // upload is still running. Back at the server with the list
                // empty, the throttled arm below takes over.
                if let (true, Some(_), Some(old)) = (from_server, next_peer, old_peer) {
                    let server_left = self.active_downloads.get(file_id)
                        .map_or(true, |s| s.alt_source_peer_ids.iter().any(|p| self.is_server_peer(p)));
                    if !server_left {
                        if let Some(s) = self.active_downloads.get_mut(file_id) {
                            s.alt_source_peer_ids.push_back(old);
                        }
                    }
                }
                match next_peer {
                    Some(peer) => {
                        warn!("Kaynakta dosya/parça bulunamadı, ALTERNATİF bir kaynağa geçiliyor: file_id={} yeni_peer={}", file_id, crate::log_id(&peer));
                        self.request_next_chunk(file_id);
                    }
                    None if from_server => {
                        // Zaman sınırlı yeniden deneme (bkz.
                        // `DOWNLOAD_GIVE_UP_TIMEOUT_MS` — 10 dk): yükleme
                        // biterse kendiliğinden toparlar, bitmezse yine de
                        // pes edilir. Kalıcı bir hata gibi davranmıyoruz.
                        // Not at once: the server answers in about a second, and
                        // that was a request loop at round-trip rate for the whole
                        // 10 min. One probe request every `DOWNLOAD_RETRY_DELAY_MS`
                        // (`check_stalled_downloads`); the window grows again with
                        // the first chunk.
                        if let Some(s) = self.active_downloads.get_mut(file_id) {
                            s.inflight_chunks.remove(&chunk_index);
                            s.chunk_sent_at.remove(&chunk_index);
                            s.window = DOWNLOAD_WINDOW_MIN;
                            s.retry_at = current_time_ms() + DOWNLOAD_RETRY_DELAY_MS;
                        }
                        info!("Sunucuda dosya henüz hazır değil (yükleme sürüyor olabilir): file_id={}", file_id);
                    }
                    None => {
                        self.fail_download(file_id, "Karşı tarafta bu dosya/parça bulunamadı");
                    }
                }
                return;
            }
            // the server's rate limit. Same source, later.
            FileChunkResponse::Busy => {
                if let Some(s) = self.active_downloads.get_mut(file_id) {
                    s.inflight_chunks.remove(&chunk_index);
                    s.chunk_sent_at.remove(&chunk_index);
                    s.window = DOWNLOAD_WINDOW_MIN;
                    s.retry_at = current_time_ms() + DOWNLOAD_RETRY_DELAY_MS;
                }
                return;
            }
        };
        let (enc_path, file_key, total_chunks, chunk_size, total_size, per_hash, peer, expected) = match self.active_downloads.get(file_id) {
            Some(s) => {
                let entry = (chunk_index / s.per_hash) as usize * 32;
                let expected: [u8; 32] = match s.chunk_hashes.get(entry..entry + 32) {
                    Some(h) => h.try_into().unwrap_or([0; 32]),
                    None => return, // index past the file: not one we asked for
                };
                (s.enc_path.clone(), s.file_key, s.total_chunks, s.chunk_size, s.total_size, s.per_hash, s.peer_id, expected)
            }
            None => return, // İptal edilmiş/başka nedenle düşmüş bir indirme — sessizce yok say.
        };
        // A chunk that is already here (or waits for the rest of its group) is
        // not written again: a second copy could differ.
        if self.active_downloads.get(file_id).map_or(false, |s| s.received_chunks.contains(&chunk_index) || s.pending_chunks.contains_key(&chunk_index)) {
            if let Some(s) = self.active_downloads.get_mut(file_id) {
                s.inflight_chunks.remove(&chunk_index);
                s.chunk_sent_at.remove(&chunk_index);
            }
            self.request_next_chunk(file_id);
            return;
        }
        // Parçayı KENDİ konumuna yaz (sona ekleme DEĞİL) — boru hattında
        // parçalar sırasız geliyor. AEAD doğrulaması yazmadan önce yapılır,
        // yani `Auth` hatasında diske hiçbir şey yazılmaz.
        // every chunk has its exact length (only the last one is
        // short). A longer last chunk would also leave bytes past the end
        // that a correct copy written later does not overwrite.
        let exact_len = attachments::chunk_plain_len(total_size, chunk_size, chunk_index) as usize + 16;
        // With one chunk per hash entry the chunk is checked against the
        // signed offer before anything is written. Every group member holds
        // the file key, so the AEAD alone does not say the sender made it.
        let written = if data.len() != exact_len {
            Err(attachments::ChunkAppendError::Auth(format!("Chunk {} does not have its length", chunk_index)))
        } else if per_hash == 1 && <sha2::Sha256 as sha2::Digest>::digest(&data)[..] != expected[..] {
            Err(attachments::ChunkAppendError::Auth(format!("Chunk {} does not match the offer's hash", chunk_index)))
        } else {
            attachments::write_verified_chunk_at_with(&enc_path, chunk_index, &data, &file_key, chunk_size)
        };
        let plaintext_len = match written {
            Ok(n) => n,
            // A forged or broken chunk: nothing was written. Its source is not
            // asked again in this attempt; the chunk comes from the next one.
            Err(attachments::ChunkAppendError::Auth(e)) => {
                self.drop_bad_source(file_id, peer, &e);
                return;
            }
            // Disk yazma hatası — `.enc` kısmen yazılmış olabilir, tutarlılık
            // garanti değil. Retry resumes only from chunk groups that match
            // their hash (`download_file`).
            Err(attachments::ChunkAppendError::Io(e)) => { self.fail_download(file_id, &e); return; }
        };
        // The chunks this answer makes good, with their plaintext length.
        let mut verified: Vec<(u32, u64)> = vec![(chunk_index, plaintext_len as u64)];
        if per_hash > 1 {
            // A file with more chunks than hash entries: the chunk waits on
            // disk until its whole group is here, then the group is checked.
            let first = chunk_index - chunk_index % per_hash;
            let count = per_hash.min(total_chunks - first);
            let group_in = {
                let Some(s) = self.active_downloads.get_mut(file_id) else { return };
                s.pending_chunks.insert(chunk_index, (peer, plaintext_len));
                (first..first + count).all(|i| s.pending_chunks.contains_key(&i))
            };
            verified.clear();
            if group_in {
                let ok = attachments::enc_range_hash(&enc_path, first, count, chunk_size).is_ok_and(|h| h == expected);
                let Some(s) = self.active_downloads.get_mut(file_id) else { return };
                let group: Vec<(u32, PeerId, usize)> = (first..first + count)
                    .filter_map(|i| s.pending_chunks.remove(&i).map(|(p, n)| (i, p, n)))
                    .collect();
                if ok {
                    verified = group.iter().map(|&(i, _, n)| (i, n as u64)).collect();
                } else {
                    // The group is fetched again. Its source is known only when
                    // one source served all of it; a mixed group is just
                    // fetched again (from the current source alone, so a
                    // forger that is the current source is caught next time).
                    s.inflight_chunks.remove(&chunk_index);
                    s.chunk_sent_at.remove(&chunk_index);
                    let reason = format!("Chunks {}..{} do not match the offer's hash", first, first + count);
                    if group.iter().all(|&(_, p, _)| p == group[0].1) {
                        self.drop_bad_source(file_id, group[0].1, &reason);
                    } else {
                        warn!("{} (several sources), fetched again: file_id={}", reason, file_id);
                        self.request_next_chunk(file_id);
                    }
                    return;
                }
            }
        }

        let mut emit_progress = false;
        let mut all_done = false;
        if let Some(state) = self.active_downloads.get_mut(file_id) {
            state.inflight_chunks.remove(&chunk_index);
            // Uyarlanır pencere: gidiş-dönüş hedefin altındaysa büyüt.
            // Hedefin üstündeyse hat doymuştur — büyütmek yalnızca tampon
            // şişirir (bkz. `DOWNLOAD_RTT_TARGET_MS`).
            if let Some(sent_at) = state.chunk_sent_at.remove(&chunk_index) {
                let rtt = current_time_ms().saturating_sub(sent_at);
                state.rtt_min = state.rtt_min.min(rtt.max(DOWNLOAD_RTT_FLOOR_MS));
                let queue_ok = rtt <= state.rtt_min.saturating_mul(DOWNLOAD_RTT_GROW_FACTOR);
                if queue_ok && rtt < DOWNLOAD_RTT_CEILING_MS && state.window < DOWNLOAD_WINDOW_MAX {
                    state.window += 1;
                }
            }
            // Aynı parça iki kez geldi (yeniden deneme yarışı) — baytları
            // iki kez saymayalım.
            //
            // Bu denetimde bulundu: burada `return` vardı ve fonksiyonun
            // SONUNDAKİ `request_next_chunk`'ı da atlıyordu. Parça ise az
            // önce `inflight_chunks`'tan DÜŞÜRÜLMÜŞTÜ — yani her yinelenen
            // parça boru hattı penceresini bir daraltıyor, hiçbir yeni
            // istek açılmıyordu. Yeterince yineleme üst üste gelirse
            // pencere boşalıyor ve indirme, 105 sn'lik takılma zamanlayıcısı
            // (`DOWNLOAD_STALL_TIMEOUT_MS`) devreye girene kadar duruyordu.
            // Artık muhasebe atlanıyor ama akış devam ediyor.
            // A chunk in a group still waiting for the rest is progress too,
            // but only checked chunks are counted as received.
            let mut duplicate = true;
            for &(i, n) in &verified {
                if state.received_chunks.insert(i) {
                    duplicate = false;
                    state.bytes_done += n;
                }
            }
            if !duplicate || (per_hash > 1 && verified.is_empty()) {
                // `next_chunk_index` artık BİTİŞİK su seviyesi: sırasız gelen
                // parçalarda "en yüksek + 1" bir boşluğu sessizce atlardı.
                while state.received_chunks.contains(&state.next_chunk_index) {
                    state.next_chunk_index += 1;
                }
                state.last_progress_at = current_time_ms();
                // Progress is not a stall (`check_stalled_downloads`).
                state.last_retry_at = state.last_progress_at;
                // #76: it moved, so the next reconnect may resume it again.
                self.auto_resumed_downloads.remove(file_id);
            }
            all_done = state.received_chunks.len() as u32 >= total_chunks;
            // Mevcut kaynak GERÇEKTEN çalışıyor — bkz. `retries_on_current_source`
            // dokümantasyonu, kaynak değiştirme sayacı sıfırlanır.
            state.retries_on_current_source = 0;
            // Her ~8 parçada bir (yaklaşık 2MB) veya son parçada ilerleme
            // bildir — her parçada bir olay üretmek (4GB/256KB = 16384 olay)
            // pollNetwork'ün döndürdüğü diziyi gereksiz yere şişirirdi.
            emit_progress = !duplicate && (state.received_chunks.len() % 8 == 0 || all_done);
            if emit_progress {
                if let Some(conn) = &self.db {
                    let _ = conn.execute("UPDATE files SET bytes_transferred = ?1 WHERE file_id = ?2", params![state.bytes_done as i64, file_id]);
                }
            }
        }
        if emit_progress {
            if let Some(state) = self.active_downloads.get(file_id) {
                let ev = serde_json::json!({
                    "type": "file_progress", "peer": self.canonical_peer_key(&state.peer_device_fingerprint), "file_id": file_id,
                    "bytes_done": state.bytes_done, "bytes_total": state.total_size
                }).to_string();
                self.attachment_events.push(ev);
            }
        }
        if all_done {
            self.finalize_download(file_id);
        } else {
            self.request_next_chunk(file_id);
        }
    }

    /// `serve_chunk_request`'in yetki kuralı — bkz. oradaki uzun not.
    ///
    /// `row_peer_fp` = `files.peer_device_fingerprint` (1:1'de sohbetin
    /// KARŞI tarafındaki cihaz; grupta teklifi yapan üyenin cihazı),
    /// `row_group_id` doluysa dosya bir grup ekidir.
    ///
    /// İzin verilenler:
    /// - Yapılandırılmış sunucularımız: blob'ları oraya BİZ yüklüyoruz ve
    ///   onlar bunu diğer üyelere yeniden servis ediyor (bkz.
    ///   `server_flush_blobs`) — burada engellemek kendi store-and-forward
    ///   yolumuzu kapatırdı.
    /// - Kendi kimliğimizin kardeş cihazları (çoklu-cihaz, spec 1.7).
    /// - Grup eki: istekçinin kimliği o grubun ÜYESİ olmalı (çıkarılan üye
    ///   anında erişimi kaybeder).
    /// - 1:1 eki: istekçinin kimliği, satırdaki karşı tarafın kimliğiyle
    ///   AYNI olmalı (o kişinin başka bir cihazı da olabilir).
    ///
    /// KABUL EDİLEN SINIR: `device_to_peer_id` ancak o cihazdan İMZASI
    /// DOĞRULANMIŞ bir paket aldığımızda dolar. Bir grup üyesi bize hiç
    /// bir şey göndermediyse PeerId'sini bilmiyoruz ve çoklu-kaynak
    /// indirmede bizi aday olarak deneyen o üye `NotFound` alır. Zararsız:
    /// asıl gönderen ve (varsa) sunucu hâlâ kaynak, ve o üye gruba ilk
    /// mesajını attığı an eşleme kurulur. Bunu gevşetmek, yetkiyi
    /// kanıtlanamayan bir PeerId'ye dayandırmak demek olurdu.
    pub(crate) fn may_serve_file_to(&self, peer: PeerId, row_peer_fp: &str, row_group_id: Option<&str>) -> bool {
        if self.is_server_peer(&peer) {
            return true;
        }
        // Kanıtlanmış PeerId -> bilinen cihaz. Bir cihazın PeerId'si ancak
        // ondan imzası doğrulanmış bir paket aldığımızda kaydedilir (bkz.
        // `record_peer_id_if_known`), yani bu eşleme sahte olamaz.
        let requester_fp = self.device_to_peer_id.iter()
            .find(|(_, pid)| **pid == peer)
            .map(|(fp, _)| fp.clone());
        let Some(requester_fp) = requester_fp else { return false };
        if self.is_blocked_device(&requester_fp) {
            return false;
        }
        let Some(requester_identity) = self.known_remote_devices.get(&requester_fp)
            .filter(|d| d.is_active)
            .map(|d| d.identity_id.clone())
        else {
            return false;
        };
        if self.my_identity_id().as_deref() == Some(requester_identity.as_str()) {
            return true;
        }
        match row_group_id {
            Some(gid) => self.groups.get(gid)
                .map(|g| g.is_member(&requester_identity))
                .unwrap_or(false),
            None => self.known_remote_devices.get(row_peer_fp)
                .map(|d| d.identity_id == requester_identity)
                .unwrap_or(false),
        }
    }

    /// `request_response` isteğinin RESPONDER tarafı — bu cihazın
    /// gönderdiği VEYA tamamen indirip yeniden servis ettiği bir dosyadan
    /// tek bir parça ister.
    pub(crate) fn serve_chunk_request(&self, peer: PeerId, request: &FileChunkRequest) -> FileChunkResponse {
        debug!("serve_chunk_request: file_id={} chunk={} isteği alındı", request.file_id, request.chunk_index);
        let row = self.db.as_ref().and_then(|conn| {
            conn.query_row(
                "SELECT status, peer_device_fingerprint, group_id FROM files WHERE file_id = ?1",
                params![request.file_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)),
            ).ok()
        });
        let Some((status, row_peer_fp, row_group_id)) = row else {
            error!("serve_chunk_request: file_id={} için kayıt yok — NotFound dönülüyor", request.file_id);
            return FileChunkResponse::NotFound;
        };
        if status != "complete" {
            error!("serve_chunk_request: file_id={} status='complete' değil — NotFound dönülüyor", request.file_id);
            return FileChunkResponse::NotFound;
        }
        // Güvenlik düzeltmesi (bu denetim): burada HİÇBİR yetki kontrolü
        // yoktu. Bu protokolü konuşan HERHANGİ bir eş — kişi listemizde
        // olmayan, hiç eşleşmediğimiz, node modunda bize bağlanan bir
        // yabancı dahil — bir `file_id` bildiği/tahmin ettiği anda
        // tamamlanmış HERHANGİ bir ekimizin şifreli parçalarını
        // çekebiliyordu; üstelik `NotFound`/`Chunk` ayrımı "bu dosya sende
        // var mı" sorusuna bir kâhin (oracle) olarak cevap veriyordu.
        // Baytlar `file_key` ile şifreli olduğundan içerik doğrudan
        // sızmıyordu, AMA: bir grup dosyasının `file_key`'i TÜM üyelerde
        // ortaktır (bkz. `finish_outgoing_group_file`), yani gruptan
        // ÇIKARILMIŞ eski bir üye kendi eski anahtarıyla dosyayı hâlâ
        // herhangi bir üyeden indirebilirdi. Artık istekçi, Noise ile
        // KANITLANMIŞ `PeerId`'sinden bilinen bir cihaza çözülmek ve o
        // dosyanın meşru karşı tarafı olmak zorunda.
        if !self.may_serve_file_to(peer, &row_peer_fp, row_group_id.as_deref()) {
            warn!(
                "serve_chunk_request REDDEDİLDİ: {} bu dosyanın yetkili karşı tarafı değil (file_id={})",
                crate::log_id(&peer), request.file_id
            );
            return FileChunkResponse::NotFound;
        }
        let enc_path = match self.enc_path_for(&request.file_id) {
            Ok(p) => p,
            Err(_) => return FileChunkResponse::NotFound,
        };
        let chunk_size = self.file_chunk_size(&request.file_id);
        match attachments::read_chunk_from_disk_with(&enc_path, request.chunk_index, chunk_size) {
            Ok(Some(data)) => {
                debug!("serve_chunk_request: file_id={} chunk={} {} bayt ile yanıtlanıyor", request.file_id, request.chunk_index, data.len());
                FileChunkResponse::Chunk { data }
            }
            other => {
                error!("serve_chunk_request: file_id={} chunk={} diskten okunamadı: {:?}", request.file_id, request.chunk_index, other.err());
                FileChunkResponse::NotFound
            }
        }
    }

    /// Bir sohbetteki bilinen ekleri listeler (bkz. `listAttachments` JNI
    /// export) — sadece bu süreç boyunca bilinen/DB'ye yazılmış kayıtlar
    /// (node modu kapalıyken teklif edilip hiç indirilmemiş bir dosya,
    /// spec dışı kural gereği zaten DB'ye yazılıyor — bkz.
    /// `receive_file_offer` — bu yüzden restart sonrası da metadata en
    /// azından görünür kalır, sadece yeniden indirme gerekir).
    // The newest `MAX_LISTED_ATTACHMENTS` (each row carries its preview JPEG
    // as hex, all under the core lock); older ones: `list_attachments_page`.
    pub(crate) fn list_attachments(&self, peer_device_fingerprint: &str) -> Vec<AttachmentSummary> {
        self.list_attachments_opt(peer_device_fingerprint, true, None, MAX_LISTED_ATTACHMENTS)
    }

    /// #80: the `limit` newest attachments created before `before_ms`, oldest first.
    pub(crate) fn list_attachments_page(&self, peer_device_fingerprint: &str, before_ms: u64, limit: usize) -> Vec<AttachmentSummary> {
        self.list_attachments_opt(peer_device_fingerprint, true, Some(before_ms), limit.min(MAX_LISTED_ATTACHMENTS))
    }

    /// `with_preview: false` leaves the preview JPEG in the database: the
    /// chat list asks every few seconds and only wants the newest row's label.
    pub(crate) fn list_attachments_opt(&self, peer_device_fingerprint: &str, with_preview: bool, before_ms: Option<u64>, limit: usize) -> Vec<AttachmentSummary> {
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };
        // Çoklu-cihaz (spec 1.7.1): bir kişinin ekleri, o kişinin HERHANGİ
        // bir cihazından gelmiş olabilir — hepsini TEK sohbet altında birleştir.
        // `peer_device_fingerprint` sütununa tam olarak eşitlik yerine, bu
        // cihazın kimliğinin TÜM bilinen cihaz fingerprint'lerini kabul
        // ediyoruz (tek cihazlı kişide bu, o tek fingerprint'e indirger —
        // davranış değişmez). İndirme yine dosyanın GERÇEK sahibine yönlenir
        // (bkz. download_file — satırdaki sahip cihazdan indirir).
        // `group_id IS NULL`: bir grup dosya teklifi de gönderen üyenin
        // `peer_device_fingerprint`'iyle saklanır — bu filtre olmadan bir grup
        // eki o üyenin 1:1 ek geçmişine sızardı.
        let mut device_fps: Vec<String> = self.known_remote_devices.get(peer_device_fingerprint)
            .map(|d| d.identity_id.clone())
            .map(|id| self.known_remote_devices.values()
                .filter(|d| d.identity_id == id)
                .map(|d| d.device_fingerprint.clone())
                .collect::<Vec<_>>())
            .unwrap_or_default();
        if device_fps.is_empty() { device_fps.push(peer_device_fingerprint.to_string()); }
        let placeholders = (1..=device_fps.len()).map(|i| format!("?{}", i)).collect::<Vec<_>>().join(",");
        // The page never splits a millisecond: every row sharing the oldest
        // row's `created_at` comes with it, or the next `< before_ms` page
        // skipped the rest of them.
        let filter = format!(
            "peer_device_fingerprint IN ({}) AND group_id IS NULL AND created_at < {}",
            placeholders, before_ms.map_or(i64::MAX, |b| b.min(i64::MAX as u64) as i64)
        );
        let sql = format!(
            "SELECT file_id, file_name, mime_type, total_size, direction, status, bytes_transferred, created_at, preview_jpeg, duration_ms, caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker
             FROM files WHERE {f} AND created_at >= COALESCE(
                 (SELECT created_at FROM files WHERE {f} ORDER BY created_at DESC LIMIT 1 OFFSET {o}), {min})
             ORDER BY created_at DESC",
            f = filter, o = limit.max(1) - 1, min = -1
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                warn!("Ek listesi sorgusu hazırlanamadı: {}", e);
                return Vec::new();
            }
        };
        let params_dyn: Vec<&dyn rusqlite::ToSql> = device_fps.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        // previews up to 512 KiB each, 500 rows, as hex: the older rows
        // past the budget come without one.
        let mut preview_budget = PAGE_MAX_BYTES;
        let rows = stmt.query_map(params_dyn.as_slice(), |r| {
            let preview: Option<Vec<u8>> = if with_preview { r.get(8)? } else { None };
            let preview = preview.filter(|p| p.len() <= preview_budget).inspect(|p| preview_budget -= p.len());
            let duration: Option<i64> = r.get(9)?;
            let file_id: String = r.get(0)?;
            let mut status: String = r.get(5)?;
            // `active_downloads` süreç içi bellekte tutulur — süreç
            // öldürülüp yeniden başladığında (ör. tam uygulama kapatma)
            // DB'de "downloading" olarak kalmış ama artık HİÇBİR canlı
            // indirme ilerlemesi almayacak (ve tıklandığında no-op olan,
            // bkz. ChatActivity.onAttachmentClicked) kayıtlar bu şekilde
            // sonsuza dek "İndiriliyor" görünürdü. Gerçekten devam eden bir
            // indirmenin `active_downloads`'da karşılığı OLMALI — yoksa
            // durum aslında "failed" (tekrar denenebilir) kabul edilir.
            if status == "downloading" && !self.active_downloads.contains_key(&file_id) {
                status = "failed".to_string();
            }
            Ok(AttachmentSummary {
                file_id,
                file_name: r.get(1)?,
                mime_type: r.get(2)?,
                total_size: r.get::<_, i64>(3)? as u64,
                direction: r.get(4)?,
                status,
                bytes_transferred: r.get::<_, i64>(6)? as u64,
                created_at: r.get::<_, i64>(7)? as u64,
                preview_hex: preview.map(|p| hex::encode(p)),
                duration_ms: duration.map(|d| d as u32),
                peer_device_fingerprint: String::new(),
                sender_identity_id: None,
                caption: r.get::<_, Option<String>>(10)?.unwrap_or_default(),
                reply_to_message_id: r.get(11)?,
                reply_to_preview: r.get(12)?,
                reply_to_sender_identity_id: r.get(13)?,
                sticker: r.get(14)?,
            })
        });
        newest_first_rows(rows)
    }

    /// `list_attachments`'ın grup
    /// karşılığı — `group_id`'ye göre filtreler (bkz. `load_group_message_history`
    /// AYNI desen). Grup içinde farklı ekler FARKLI göndericilerden
    /// gelebileceğinden, `peer_device_fingerprint`/`sender_identity_id`
    /// alanları BURADA (1:1'in aksine) doldurulur — `download_file`'ın
    /// "kimden indirileceğini" bilmesi ve gönderen adının gösterilebilmesi
    /// için.
    pub(crate) fn list_group_attachments(&self, group_id: &str) -> Vec<AttachmentSummary> {
        self.list_group_attachments_opt(group_id, true, None, MAX_LISTED_ATTACHMENTS)
    }

    /// #80: see `list_attachments_page`.
    pub(crate) fn list_group_attachments_page(&self, group_id: &str, before_ms: u64, limit: usize) -> Vec<AttachmentSummary> {
        self.list_group_attachments_opt(group_id, true, Some(before_ms), limit.min(MAX_LISTED_ATTACHMENTS))
    }

    /// See `list_attachments_opt`.
    pub(crate) fn list_group_attachments_opt(&self, group_id: &str, with_preview: bool, before_ms: Option<u64>, limit: usize) -> Vec<AttachmentSummary> {
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };
        let mut stmt = match conn.prepare(
            "SELECT file_id, file_name, mime_type, total_size, direction, status, bytes_transferred, created_at, preview_jpeg, duration_ms, peer_device_fingerprint, sender_identity_id, caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker
             FROM files WHERE group_id = ?1 AND created_at < ?2 AND created_at >= COALESCE(
                 (SELECT created_at FROM files WHERE group_id = ?1 AND created_at < ?2 ORDER BY created_at DESC LIMIT 1 OFFSET ?3), ?4)
             ORDER BY created_at DESC"
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("Ek listesi sorgusu hazırlanamadı: {}", e);
                return Vec::new();
            }
        };
        let before = before_ms.map_or(i64::MAX, |b| b.min(i64::MAX as u64) as i64);
        // See `list_attachments_opt`: the oldest millisecond is never split.
        let mut preview_budget = PAGE_MAX_BYTES;
        let rows = stmt.query_map(params![group_id, before, limit.max(1) as i64 - 1, -1i64], |r| {
            let preview: Option<Vec<u8>> = if with_preview { r.get(8)? } else { None };
            let preview = preview.filter(|p| p.len() <= preview_budget).inspect(|p| preview_budget -= p.len());
            let duration: Option<i64> = r.get(9)?;
            let file_id: String = r.get(0)?;
            let mut status: String = r.get(5)?;
            if status == "downloading" && !self.active_downloads.contains_key(&file_id) {
                status = "failed".to_string();
            }
            Ok(AttachmentSummary {
                file_id,
                file_name: r.get(1)?,
                mime_type: r.get(2)?,
                total_size: r.get::<_, i64>(3)? as u64,
                direction: r.get(4)?,
                status,
                bytes_transferred: r.get::<_, i64>(6)? as u64,
                created_at: r.get::<_, i64>(7)? as u64,
                preview_hex: preview.map(|p| hex::encode(p)),
                duration_ms: duration.map(|d| d as u32),
                peer_device_fingerprint: r.get(10)?,
                sender_identity_id: r.get(11)?,
                caption: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
                reply_to_message_id: r.get(13)?,
                reply_to_preview: r.get(14)?,
                reply_to_sender_identity_id: r.get(15)?,
                sticker: r.get(16)?,
            })
        });
        newest_first_rows(rows)
    }

    /// Tamamlanmış bir ekin düz metin (çözülmüş) kopyasının yolunu döner —
    /// yoksa (ilk açılış) önce diskten çözer. BİLİNEN SINIR:
    /// `decrypt_file_from_disk` senkron/bounded-memory'dir ama büyük bir
    /// dosya için yine de zaman alabilir — Kotlin tarafı bunu ana thread
    /// DIŞINDA çağırmalıdır (bkz. P2PLib.kt dokümantasyonu).
    /// bkz. `begin_outgoing_file` AYNI kilit-bölme gerekçesi — büyük bir
    /// ekin tamamını çözmek de dakikalar sürebilir ve önceden global kilit
    /// altında yapılıyordu. Bu, KISA kilitli faz: DB'den meta veriyi okur,
    /// anahtarı çözer ve yol çiftini döner; asıl `decrypt_file_from_disk`
    /// kilitsiz olarak `attachment_plaintext_path_unlocked` içinde çalışır.
    pub(crate) fn begin_attachment_decrypt(&self, file_id: &str) -> Result<([u8; 32], String, std::path::PathBuf, std::path::PathBuf), String> {
        info!("get_attachment_plaintext_path çağrıldı: file_id={}", file_id);
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let (encrypted_key, key_nonce, sha256_hex, status, file_name): (Vec<u8>, Vec<u8>, String, String, String) = conn.query_row(
            "SELECT encrypted_file_key, key_nonce, sha256_hex, status, file_name FROM files WHERE file_id = ?1",
            params![file_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).map_err(|e| format!("Unknown file_id ({}): {}", file_id, e))?;
        info!("get_attachment_plaintext_path: file_id={} DB durumu='{}'", file_id, status);
        if status != "complete" {
            return Err(format!("Dosya henüz tamamlanmadı (durum: {})", status));
        }
        let file_key = self.unwrap_file_key(&encrypted_key, &key_nonce)?;

        // bkz. `safe_extension` (#01): uzantı karşı tarafın gönderdiği dosya
        // adından türetiliyor, yol ayırıcı taşıyamaz.
        let ext = safe_extension(&file_name);
        let plain_path = self.attachments_dir()?.join("plain_cache").join(format!("{}{}", file_id, ext));
        let enc_path = self.enc_path_for(file_id)?;
        Ok((file_key, sha256_hex, enc_path, plain_path))
    }
}
