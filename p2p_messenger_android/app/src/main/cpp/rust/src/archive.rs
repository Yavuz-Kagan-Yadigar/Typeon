//! History requests, the message archive, edits/deletes on it and history loads.

use super::*;

impl P2PCore {

    /// Drops the unanswered chat-open `HistorySyncRequest`s (no window) to
    /// one device for one chat (`group_id`: None = the 1:1 chat): the newest
    /// request does the same work, and each one is retried and deposited
    /// until it is answered. A press window is never dropped here.
    pub(crate) fn cancel_pending_history_requests(&mut self, peer_device_fingerprint: &str, group_id: Option<&str>) {
        let stale: Vec<String> = self.awaiting_confirmation.iter()
            .filter(|(_, p)| p.peer_device_fingerprint == peer_device_fingerprint)
            .filter(|(_, p)| matches!(
                &p.regen_content,
                Some(MessageContent::HistorySyncRequest { group_id: g, before_timestamp: None, .. }) if g.as_deref() == group_id
            ))
            .map(|(id, _)| id.clone())
            .collect();
        // H10: only the retry stops. The request stays solicited, so an
        // answer already on its way is still taken (it was discarded and
        // acked, a lost page); it ages out after 7 days (bkz. the
        // `HistorySyncRequest` arm of `send_message_content_inner`).
        for id in stale {
            self.awaiting_confirmation.remove(&id);
            self.remove_durable_retry(&id);
        }
    }

    /// Spec dışı: node modu kapalı bir cihazda sohbet ekranı hiç yerel
    /// geçmiş bulamadığında çağrılır (bkz. ChatActivity
    /// `loadHistoryIfAvailable`) — karşı tarafa (chat peer) şifreli bir
    /// `HistorySyncRequest` gönderir. Yanıt asenkron gelir (bir sonraki
    /// `pollNetwork` turunda `{"type":"history_sync",...}` olayı olarak).
    pub(crate) fn request_history_sync(&mut self, peer_device_fingerprint: String, limit: u32) -> Result<(), String> {
        // İKİ CİHAZLI TESTTE (2026-09-06) görüldü: sohbet HER açılışında bir
        // `HistorySyncRequest` gidiyor ve bu, `regen_content` listesinde
        // olduğu için `pending_durable_retries` + `awaiting_confirmation`'a
        // yazılıyor; yalnızca `HistorySyncResponse` gelince temizleniyor.
        // Karşı taraf yavaş/çevrimdışıysa bu satırlar birikiyor (her açılış
        // +1) ve hepsi 7 güne kadar boşuna yeniden gönderiliyor. Yeni bir
        // istek göndermeden ÖNCE, bu peer'a giden bekleyen "tam senkron"
        // (`before_timestamp: None`) isteğini iptal et — en yenisi zaten
        // aynı işi yapar.
        self.cancel_pending_history_requests(&peer_device_fingerprint, None);
        let content = MessageContent::HistorySyncRequest { limit, before_timestamp: None, group_id: None, after_timestamp: None };
        self.send_message_content(peer_device_fingerprint, &content, None).map(|_| ())
    }

    /// Spec dışı, kullanıcı isteği (sonsuz kaydırma): sohbet geçmişinin en
    /// üstüne kaydırıldığında, YEREL arşiv tükendiğinde çağrılır (bkz.
    /// `getMessageHistoryBefore`) — karşı taraftan (chat peer) doğrudan
    /// `before_timestamp`'ten eski mesajları ister. Yanıt asenkron gelir
    /// (bkz. `HistorySyncResponse` kolu — `before_timestamp` dolu ise
    /// "older_history" olayı üretir).
    ///
    /// The window `[after, before)` of a "Fetch older history" press. Older
    /// presses are not cancelled: each asks for its own window.
    pub(crate) fn request_older_history(&mut self, peer_device_fingerprint: &str, before: i64, after: i64) -> Result<(), String> {
        let content = MessageContent::HistorySyncRequest {
            limit: HISTORY_SYNC_MAX_MESSAGES, before_timestamp: Some(before), group_id: None, after_timestamp: Some(after),
        };
        self.send_message_content(peer_device_fingerprint.to_string(), &content, None).map(|_| ())
    }

    /// bkz. `request_older_history` aynı notu — grup için. Grup mesajları
    /// pairwise fan-out olduğundan tek bir "otorite" yok; istek
    /// ulaşılabilir TÜM diğer üyelere gönderilir (bkz. `send_group_message`
    /// aynı fan-out deseni) — ilk yanıt veren boşluğu doldurur, sonraki
    /// yanıtlar `message_id` var-olma kontrolüyle (bkz.
    /// `message_exists_with_id`) sessizce yok sayılır.
    pub(crate) fn request_older_group_history(&mut self, group_id: &str, before: i64, after: i64) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        let content = MessageContent::HistorySyncRequest {
            limit: HISTORY_SYNC_MAX_MESSAGES, before_timestamp: Some(before), group_id: Some(group_id.to_string()), after_timestamp: Some(after),
        };
        let mut sent_to_any = false;
        for member_identity_id in group.other_members(&own_identity_id) {
            if let Some(peer_fp) = self.resolve_active_device_for_identity(&member_identity_id) {
                if self.send_message_content(peer_fp, &content, None).is_ok() {
                    sent_to_any = true;
                }
            }
        }
        if sent_to_any {
            Ok(())
        } else {
            Err("Ulaşılabilir grup üyesi yok".to_string())
        }
    }

    /// bkz. `HistorySyncResponse` "older" kolu — bir mesajın (kararlı
    /// `message_id`'sine göre) zaten yerel arşivde olup olmadığını
    /// kontrol eder. ESKİ SAYFA birleştirmesinde, mevcut "en yeniden daha
    /// yeni" zaman damgası eşiğinin YANLIŞ yönde çalışacağı yerde
    /// kullanılır (sayfalama kasıtlı olarak DAHA ESKİ mesajlar getirir).
    /// `message_exists_with_id` within one chat. The id is chosen by the peer,
    /// so a global match let a 1:1 message suppress a group message with the
    /// same id (and the reverse).
    pub(crate) fn message_exists_in_chat(&self, message_id: &str, group_id: Option<&str>, chat_key: &str) -> bool {
        let Some(conn) = &self.db else { return false };
        match group_id {
            Some(gid) => conn.query_row(
                "SELECT 1 FROM messages WHERE message_id = ?1 AND group_id = ?2 LIMIT 1",
                params![message_id, gid], |_| Ok(()),
            ),
            None => conn.query_row(
                "SELECT 1 FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL LIMIT 1",
                params![message_id, chat_key], |_| Ok(()),
            ),
        }.is_ok()
    }

    pub(crate) fn file_row_exists(&self, file_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row("SELECT 1 FROM files WHERE file_id = ?1 LIMIT 1", params![file_id], |_| Ok(())).is_ok()
        })
    }

    /// A row from a history backfill was inserted with `timestamp = now`.
    /// Paging and ordering use that column, so give it the row's real time.
    /// Only in the chat it was inserted into: the id is the peer's choice, and
    /// unscoped it moved a row of any other chat back to a time of its liking.
    pub(crate) fn backdate_archived(&self, group_id: Option<&str>, chat_key: &str, message_id: Option<&str>, timestamp: u64) {
        let (Some(conn), Some(mid)) = (&self.db, message_id) else { return };
        // Above i64::MAX the cast wraps negative and the row sorts first.
        if timestamp == 0 || timestamp > i64::MAX as u64 { return; }
        let _ = conn.execute(
            "UPDATE messages SET timestamp = ?1 WHERE message_id = ?2 AND timestamp > ?1
             AND group_id IS ?3 AND (?3 IS NOT NULL OR peer_device_fingerprint = ?4)",
            params![timestamp as i64, mid, group_id, chat_key],
        );
    }

    /// Is `target_message_id` a message or attachment WE sent in this chat?
    /// The only rows a sibling's echoed Edit/Delete may touch (the 1:1 rule of
    /// `message_owned_by_sender`, mirrored): a linked device could otherwise
    /// rewrite or delete what contacts wrote, on every sibling.
    pub(crate) fn own_sent_target(&self, group_id: Option<&str>, chat_key: &str, target_message_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row(
                "SELECT 1 FROM messages WHERE message_id = ?1 AND direction = 'sent'
                   AND group_id IS ?2 AND (?2 IS NOT NULL OR peer_device_fingerprint = ?3)
                 UNION ALL
                 SELECT 1 FROM files WHERE file_id = ?1 AND direction = 'sent' AND group_id IS ?2
                 LIMIT 1",
                params![target_message_id, group_id, chat_key], |_| Ok(()),
            ).is_ok()
        })
    }

    /// A sibling echoed an Edit (`new_text` Some) or Delete (None) of a message
    /// this device does not have yet. It is stored (text sealed) and acked, and
    /// applied when the message is archived (`apply_pending_sibling_ops`).
    /// Returns false if it could not be stored; the caller then sends no Ack.
    /// ponytail: no index on target_message_id, the table holds a few rows;
    /// add one if it ever grows.
    pub(crate) fn remember_sibling_op(&self, target_message_id: &str, new_text: Option<&str>, edited_at_ms: u64) -> bool {
        const KEEP_MS: i64 = 30 * 24 * 60 * 60 * 1000;
        let Some(conn) = &self.db else { return false };
        let sealed = match new_text {
            Some(t) => match self.seal_local_blob(t.as_bytes()) {
                Some(b) => Some(b),
                None => return false,
            },
            None => None,
        };
        let now = current_time_ms() as i64;
        let _ = conn.execute("DELETE FROM pending_sibling_ops WHERE created_at < ?1", params![now - KEEP_MS]);
        conn.execute(
            "INSERT INTO pending_sibling_ops (target_message_id, new_text, edited_at_ms, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![target_message_id, sealed, edited_at_ms as i64, now],
        ).is_ok()
    }

    /// bkz. `remember_sibling_op`. Called when one of OUR messages is archived.
    /// Edits first, by stamp; a delete last.
    pub(crate) fn apply_pending_sibling_ops(&mut self, group_id: Option<&str>, chat_key: &str, target_message_id: &str) {
        let ops: Vec<(i64, Option<Vec<u8>>, i64)> = {
            let Some(conn) = &self.db else { return };
            let Ok(mut stmt) = conn.prepare(
                "SELECT id, new_text, edited_at_ms FROM pending_sibling_ops
                 WHERE target_message_id = ?1 ORDER BY new_text IS NULL, edited_at_ms"
            ) else { return };
            let rows: Vec<(i64, Option<Vec<u8>>, i64)> = stmt
                .query_map(params![target_message_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map(|it| it.flatten().collect())
                .unwrap_or_default();
            rows
        };
        for (row_id, sealed, edited_at_ms) in ops {
            // Each row goes once it applies: one that cannot be opened now
            // (key not loaded) stays until its `KEEP_MS` expiry.
            let event = match sealed {
                Some(blob) => {
                    let Some(text) = self.open_local_blob(&blob).and_then(|p| String::from_utf8(p).ok()) else { continue };
                    self.delete_pending_sibling_op(row_id);
                    self.apply_edit_to_archive(group_id, chat_key, target_message_id, &text, edited_at_ms.max(0) as u64);
                    match group_id {
                        Some(gid) => serde_json::json!({"type": "group_edit", "group_id": gid, "message_id": target_message_id, "text": text}),
                        None => serde_json::json!({"type": "edit", "peer": chat_key, "message_id": target_message_id, "text": text}),
                    }
                }
                None => {
                    self.delete_pending_sibling_op(row_id);
                    self.apply_delete_to_archive(group_id, chat_key, target_message_id);
                    if let Some(gid) = group_id {
                        self.sign_own_group_tombstone(gid, target_message_id);
                    }
                    match group_id {
                        Some(gid) => serde_json::json!({"type": "group_delete", "group_id": gid, "message_id": target_message_id}),
                        None => serde_json::json!({"type": "delete", "peer": chat_key, "message_id": target_message_id}),
                    }
                }
            };
            self.attachment_events.push(event.to_string());
        }
    }

    pub(crate) fn delete_pending_sibling_op(&self, row_id: i64) {
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM pending_sibling_ops WHERE id = ?1", params![row_id]);
        }
    }

    /// bkz. `remember_sibling_op` — a file whose delete came before its offer.
    pub(crate) fn take_pending_sibling_delete(&self, target_message_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.execute(
                "DELETE FROM pending_sibling_ops WHERE target_message_id = ?1 AND new_text IS NULL",
                params![target_message_id],
            ).map_or(false, |n| n > 0)
        })
    }

    /// bkz. `process_group_update` (late AvatarUpdate): the version of the last
    /// avatar change applied to a group.
    pub(crate) fn group_avatar_version(&self, group_id: &str) -> u32 {
        self.db.as_ref()
            .and_then(|conn| conn.query_row(
                "SELECT v FROM app_meta WHERE k = ?1", params![format!("gav:{}", group_id)],
                |r| r.get::<_, i64>(0),
            ).ok())
            .map_or(0, |v| v.max(0) as u32)
    }

    pub(crate) fn set_group_avatar_version(&self, group_id: &str, version: u32) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO app_meta (k, v) VALUES (?1, ?2)",
                params![format!("gav:{}", group_id), version as i64],
            );
        }
    }

    /// A row just archived from a peer's history answer: carry over its
    /// deleted and edited marks (the text is already the current one).
    pub(crate) fn apply_synced_message_flags(&mut self, group_id: Option<&str>, chat_key: &str, m: &SyncedMessage) {
        let Some(mid) = m.message_id.as_deref() else { return };
        if m.is_deleted {
            self.apply_delete_to_archive(group_id, chat_key, mid);
        }
        if m.is_edited {
            self.mark_synced_message_edited(group_id, chat_key, mid);
        }
    }

    /// bkz. `outstanding_history_requests` — bir isteği kayıttan düşürür.
    pub(crate) fn forget_history_request(&mut self, request_id: &str) {
        self.outstanding_history_requests.remove(request_id);
        self.history_answered_by.remove(request_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM app_meta WHERE k = ?1", params![format!("hsr:{}", request_id)]);
        }
    }

    /// H9: `message_exists_with_id` among the 1:1 rows received from the
    /// identity of `sender_fp` only. The id is the peer's choice: a global
    /// match let another chat's row re-ack a packet that was never stored.
    pub(crate) fn received_from_sender(&self, message_id: &str, sender_fp: &str) -> bool {
        if self.own_devices.contains_key(sender_fp) {
            return self.message_exists_with_id(message_id);
        }
        let Some(conn) = &self.db else { return false };
        let Some(identity) = self.known_remote_devices.get(sender_fp).map(|d| d.identity_id.clone()) else { return false };
        self.known_remote_devices.values().filter(|d| d.identity_id == identity).any(|d| conn.query_row(
            "SELECT 1 FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND direction = 'received' LIMIT 1",
            params![message_id, d.device_fingerprint], |_| Ok(()),
        ).is_ok())
    }

    pub(crate) fn message_exists_with_id(&self, message_id: &str) -> bool {
        let conn = match &self.db {
            Some(c) => c,
            None => return false,
        };
        conn.query_row("SELECT 1 FROM messages WHERE message_id = ?1 LIMIT 1", params![message_id], |_| Ok(())).is_ok()
    }

    /// Bir mesajı yerel arşive ekler. Çağıran senaryolar: (1) canlı 1:1
    /// mesaj trafiği; (2) `HistorySyncResponse` — senkron yoluyla öğrenilen
    /// geçmişi yerelde kalıcı kılmak için (bkz. receive_message notu).
    /// `history_key` yüklenmemişse (Kotlin henüz Keystore'dan çözüp
    /// vermemişse) sessizce atlar — arşivleme best-effort, mesajlaşmanın
    /// kendisini asla engellemez.
    ///
    /// `message_id`/`status`: spec dışı, hata düzeltmesi ("bekleyen
    /// mesajlar yeniden açılınca gönderildi gösteriliyor") — önceden bu
    /// ikisi hiç kaydedilmiyordu, `message_status` SADECE bellek-içi bir
    /// `HashMap` idi; uygulama/sohbet ekranı yeniden açıldığında taze bir
    /// DB okuması HER satırı durumsuz döndürüyordu ve Kotlin tarafı
    /// eksik durumu "gönderildi" (checkmark) varsayıyordu — gerçekten
    /// hâlâ bekleyen ya da başarısız olmuş bir mesaj dahil. Artık
    /// `message_id` sabit tutulup durum güncellemeleri `set_message_status`
    /// ile AYNI satıra yazılıyor, bu yüzden bir reload gerçek durumu görür.
    /// `reply_to_message_id`/`reply_to_preview`: spec dışı, kullanıcı
    /// isteği (WhatsApp tarzı yanıt) — bkz. packet.rs
    /// `MessageContent::Text.reply_to_message_id` dokümantasyonu. Bu
    /// satırlara AYRICA kalıcılaştırılır, aksi hâlde bir sohbet geçmişi
    /// yeniden yüklendiğinde (uygulama/ekran yeniden açılışı) yanıt
    /// önizlemesi kaybolurdu.
    pub(crate) fn archive_message(&mut self, peer_device_fingerprint: &str, direction: &str, plaintext: &[u8], message_id: Option<&str>, status: Option<&str>, reply_to_message_id: Option<&str>, reply_to_preview: Option<&str>, sent_at_ms: u64) -> Result<(), String> {
        // The sender's clock: not later than ours, or its messages sort into
        // the future (and land in an archive bucket nobody probes).
        let sent_at_ms = sent_at_ms.min(current_time_ms());
        let key = match &self.history_key {
            Some(k) => *k,
            None => {
                // SESSİZCE düşürmek gerçek bir hataya yol açtı: Linux
                // istemcisinde gelen mesajlar çözülüyor, hata üretmiyor ama
                // arşive yazılmadığı için arayüzde HİÇ görünmüyordu
                // ("No messages yet"), sohbet bile açılmıyordu. Sebebi
                // bulmak, bu satır olmadığı için saatler aldı.
                warn!(
                    "Geçmiş anahtarı yüklenmemiş — mesaj arşive YAZILMIYOR (peer={}, yön={})",
                    crate::log_id(&peer_device_fingerprint), direction
                );
                return Err("history key not loaded".to_string());
            }
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Err("DB not open".to_string()),
        };

        let (encrypted, nonce_bytes) = seal_with(&key, plaintext).ok_or("History encryption failed")?;

        let sent_col: Option<i64> = if sent_at_ms > 0 { Some(sent_at_ms as i64) } else { None };
        // L-32: a row with this id is already there (UNIQUE index): nothing new.
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO messages (peer_device_fingerprint, direction, encrypted_blob, nonce, timestamp, message_id, status, reply_to_message_id, reply_to_preview, sent_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![peer_device_fingerprint, direction, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64, message_id, status, reply_to_message_id, reply_to_preview, sent_col],
        ).map_err(|e| e.to_string())?;
        if inserted == 0 {
            return Ok(());
        }

        // Sunucu arşivi (bkz. `server_client::queue_archive_record`) — YEREL
        // arşive yazılan satırın aynısı, ama `archive_key` ile YENİDEN
        // şifrelenip sunucuya yüklenmek üzere. Sunucuda geçmiş saklama
        // kapalıysa fonksiyon hemen döner.
        //
        // Sunucu arşivi KİMLİK bazlı (cihaz fingerprint'i değil): karşı taraf
        // cihazını değiştirdiğinde (spec §2.2) geçmişin okunabilirliği
        // kaybolmasın diye.
        if let Some(mid) = message_id {
            let conv_key = self.identity_id_for_device(peer_device_fingerprint);
            if let Some(conv_key) = conv_key {
                let archived = ArchivedMessage {
                    direction: direction.to_string(),
                    text: String::from_utf8_lossy(plaintext).to_string(),
                    timestamp: current_time_ms(),
                    sent_at_ms,
                    status: status.map(|s| s.to_string()),
                    sender_identity_id: None,
                    message_id: Some(mid.to_string()),
                    reply_to_message_id: reply_to_message_id.map(|s| s.to_string()),
                    reply_to_preview: reply_to_preview.map(|s| s.to_string()),
                    reply_to_sender_identity_id: None,
                    is_deleted: false,
                    is_edited: false,
                    // Yeni gelen/gonderilen bir mesajin henuz tepkisi/görüldü
                    // bilgisi olamaz. bkz. `ArchivedMessage.reactions`/`seen_by`.
                    reactions: String::new(),
                    seen_by: String::new(),
                    author_proof: None,
                    mentions_me: false,
                };
                if let Ok(cbor) = ciborium_bytes(&archived) {
                    // `rev` from our clock, as every later revision: with the
                    // sender's clock ahead, edits and deletes were lower
                    // revisions and the server kept the original.
                    let now = current_time_ms();
                    self.queue_archive_record(&conv_key, mid, now, if sent_at_ms > 0 { sent_at_ms } else { now }, cbor);
                }
            }
        }
        if direction == "sent" {
            if let Some(mid) = message_id {
                self.apply_pending_sibling_ops(None, peer_device_fingerprint, mid);
            }
        }
        Ok(())
    }

    /// Bir cihaz fingerprint'inden sahibinin `identity_id`'si.
    ///
    /// Sunucu arşivinin sohbet anahtarı için gerekli — bkz. `archive_message`
    /// içindeki not.
    pub(crate) fn identity_id_for_device(&self, device_fingerprint: &str) -> Option<String> {
        self.known_remote_devices
            .get(device_fingerprint)
            .map(|d| d.identity_id.clone())
    }

    /// Spec dışı, hata düzeltmesi (grup geçmişi kalıcılığı): bir grup
    /// mesajını yerel arşive ekler — `archive_message`'ın grup karşılığı.
    /// `peer_device_fingerprint` sütununa kasıtlı olarak boş string
    /// yazılır (NOT NULL kısıtını bozmadan "bu bir DM değil" işareti);
    /// gerçek anahtar `group_id`. Önceden grup mesajları ya HİÇ
    /// arşivlenmiyordu (alınanlar — bkz. receive_message Text/group_id
    /// notu) ya da YANLIŞ anahtarla (gönderilenler — her alıcının 1:1
    /// `peer_device_fingerprint`'i, N-yönlü fan-out'un her kopyası için
    /// AYRI bir satır) arşivleniyordu; ikincisi hem gerçek grup geçmişi
    /// olarak hiç okunamıyordu hem de o alıcı aynı zamanda bir 1:1
    /// kişiyse onun DM geçmişine sızıyordu (`load_message_history`
    /// SADECE `peer_device_fingerprint`'e göre filtreliyor). Artık HER
    /// grup mesajı (gönderilen/alınan) TEK bir satırla, `group_id`'ye göre
    /// arşivleniyor.
    /// `reply_to_message_id`/`reply_to_preview`/`reply_to_sender_identity_id`:
    /// bkz. `archive_message` AYNI notu — grup karşılığı, ARTI yanıtlanan
    /// mesajın göndericisinin `identity_id`'si (bkz. packet.rs
    /// `reply_to_sender_identity_id` notu).
    /// Signs a group message as its author, with this device's hybrid key
    /// (Ed25519 and ML-DSA-87, like every other signature here). The result
    /// travels with the message and is stored by every member:
    /// `"<device fingerprint>:<Ed25519 hex>:<ML-DSA hex>"`.
    // ponytail: hex text, about 9.4 KB a message (the ML-DSA signature is
    // 4.6 KB raw). Make the field bytes if the size of group packets and
    // history pages matters.
    pub(crate) fn sign_group_author(&self, group_id: &str, message_id: &str, text: &str) -> Result<String, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.my_identity_id().ok_or("No identity")?;
        let keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let statement = group_author_statement(group_id, message_id, &own_identity_id, &own_fp, text);
        let sig_c: Ed25519Signature = keys.sign_sk_ed25519.sign(&statement);
        let sig_pq: MlDsaSignature<MlDsa87> = keys.sign_sk_mldsa.sign(&statement);
        Ok(format!("{}:{}:{}", own_fp, hex::encode(sig_c.to_bytes()), hex::encode(sig_pq.encode().to_vec())))
    }

    /// Whether `proof` is a hybrid signature by a device of
    /// `author_identity_id` over exactly this group message. Both halves must
    /// verify. A revoked device counts only for rows dated before its
    /// `revoked_at`: its old messages stay valid.
    pub(crate) fn group_author_proof_valid(&self, group_id: &str, message_id: &str, author_identity_id: &str, text: &str, sent_at_ms: u64, proof: Option<&str>) -> bool {
        let mut parts = proof.unwrap_or("").splitn(3, ':');
        let (Some(device_fp), Some(sig_c), Some(sig_pq)) = (parts.next(), parts.next(), parts.next()) else { return false };
        // M-81: a revoked device's proof only for a row dated before its revoke.
        // A group member that is not a contact keeps its revokes in `orv:`.
        let revoked_at = self.contacts.values()
            .filter(|c| c.trusted_identity_id == author_identity_id)
            .find_map(|c| c.revoked_at(device_fp))
            .or_else(|| self.non_contact_revoke(device_fp).filter(|(id, _)| id == author_identity_id).and_then(|(_, t)| t));
        if revoked_at.map_or(false, |r| sent_at_ms == 0 || sent_at_ms >= r) {
            return false;
        }
        let (Ok(sig_c), Ok(sig_pq)) = (hex::decode(sig_c), hex::decode(sig_pq)) else { return false };
        // Own devices (this one and the siblings) or a known device of the author.
        let device = self.own_devices.get(device_fp).or_else(|| self.known_remote_devices.get(device_fp));
        let Some(device) = device.filter(|d| d.identity_id == author_identity_id) else { return false };
        // Another identity's revoked device with no time known to date its
        // proofs against: none counts.
        if !device.is_active && revoked_at.is_none() && !self.own_devices.contains_key(device_fp) {
            return false;
        }
        verify_hybrid_signature(
            &group_author_statement(group_id, message_id, author_identity_id, device_fp, text),
            &sig_c, &sig_pq, device,
        ).is_ok()
    }

    /// The stored proof of a group row, to hand on with history.
    /// Scoped to the group: ids are the sender's choice and may repeat in another one.
    pub(crate) fn group_author_proof(&self, group_id: &str, message_id: &str) -> Option<String> {
        self.db.as_ref()?.query_row(
            "SELECT author_proof FROM messages WHERE message_id = ?1 AND group_id = ?2",
            params![message_id, group_id], |r| r.get::<_, Option<String>>(0),
        ).ok().flatten()
    }

    /// After an edit: stores `proof` when it signs the row as it is stored
    /// NOW (the edit may have been stale and not applied). `apply_edit_to_archive`
    /// cleared the old proof, so a row without a matching one is not handed on.
    pub(crate) fn adopt_group_author_proof(&mut self, group_id: &str, message_id: &str, proof: Option<&str>) {
        let Some(proof) = proof else { return };
        let Some(key) = self.history_key else { return };
        let row: Option<(Option<String>, Vec<u8>, Vec<u8>, bool, i64)> = self.db.as_ref().and_then(|c| c.query_row(
            "SELECT sender_identity_id, encrypted_blob, nonce, COALESCE(is_deleted, 0), COALESCE(NULLIF(sent_at_ms, 0), timestamp) FROM messages WHERE message_id = ?1 AND group_id = ?2",
            params![message_id, group_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).ok());
        let Some((Some(author), blob, nonce, deleted, sent_at)) = row else { return };
        if nonce.len() != 12 { return }
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(&key) else { return };
        let Ok(plain) = cipher.decrypt(Nonce::from_slice(&nonce), blob.as_slice()) else { return };
        let Ok(text) = String::from_utf8(plain) else { return };
        // A deleted row is signed as a deletion, not as an empty text.
        let text = if deleted { GROUP_TOMBSTONE.to_string() } else { text };
        if !self.group_author_proof_valid(group_id, message_id, &author, &text, sent_at.max(0) as u64, Some(proof)) {
            return;
        }
        let Some(conn) = &self.db else { return };
        if let Err(e) = conn.execute(
            "UPDATE messages SET author_proof = ?1 WHERE message_id = ?2 AND group_id = ?3",
            params![proof, message_id, group_id],
        ) {
            warn!("author_proof could not be stored ({}): {}", message_id, e);
            return;
        }
        self.requeue_archive_row(Some(group_id), "", message_id);
    }

    /// A sibling deleted our group message: this device signs the deletion
    /// too, so the row it hands on with history is taken.
    pub(crate) fn sign_own_group_tombstone(&mut self, group_id: &str, message_id: &str) {
        match self.sign_group_author(group_id, message_id, GROUP_TOMBSTONE) {
            Ok(proof) => self.adopt_group_author_proof(group_id, message_id, Some(&proof)),
            Err(e) => warn!("Group tombstone could not be signed ({}): {}", message_id, e),
        }
    }

    pub(crate) fn archive_group_message(&mut self, group_id: &str, sender_identity_id: &str, direction: &str, plaintext: &[u8], message_id: Option<&str>, reply_to_message_id: Option<&str>, reply_to_preview: Option<&str>, reply_to_sender_identity_id: Option<&str>, sent_at_ms: u64, author_proof: Option<&str>) -> Result<(), String> {
        // The sender's clock: not later than ours, or its messages sort into
        // the future (and land in an archive bucket nobody probes).
        let sent_at_ms = sent_at_ms.min(current_time_ms());
        let key = match &self.history_key {
            Some(k) => *k,
            None => return Err("history key not loaded".to_string()),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Err("DB not open".to_string()),
        };

        let (encrypted, nonce_bytes) = seal_with(&key, plaintext).ok_or("History encryption failed")?;

        let sent_col: Option<i64> = if sent_at_ms > 0 { Some(sent_at_ms as i64) } else { None };
        // L-32: see `archive_message`.
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO messages (peer_device_fingerprint, direction, encrypted_blob, nonce, timestamp, group_id, sender_identity_id, message_id, status, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sent_at_ms, author_proof)
             VALUES ('', ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'sent', ?8, ?9, ?10, ?11, ?12)",
            params![direction, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64, group_id, sender_identity_id, message_id, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sent_col, author_proof],
        ).map_err(|e| e.to_string())?;
        if inserted == 0 {
            return Ok(());
        }

        // bkz. `archive_message` içindeki aynı kanca — grupta sohbet
        // anahtarı doğrudan `group_id`.
        if let Some(mid) = message_id {
            let archived = ArchivedMessage {
                direction: direction.to_string(),
                text: String::from_utf8_lossy(plaintext).to_string(),
                timestamp: current_time_ms(),
                sent_at_ms,
                status: None,
                sender_identity_id: Some(sender_identity_id.to_string()),
                message_id: Some(mid.to_string()),
                reply_to_message_id: reply_to_message_id.map(|s| s.to_string()),
                reply_to_preview: reply_to_preview.map(|s| s.to_string()),
                reply_to_sender_identity_id: reply_to_sender_identity_id.map(|s| s.to_string()),
                is_deleted: false,
                is_edited: false,
                // Yeni gelen/gonderilen bir mesajin henuz tepkisi/görüldü
                // bilgisi olamaz. bkz. `ArchivedMessage.reactions`/`seen_by`.
                reactions: String::new(),
                seen_by: String::new(),
                author_proof: author_proof.map(|p| p.to_string()),
                mentions_me: false,
            };
            if let Ok(cbor) = ciborium_bytes(&archived) {
                // bkz. `archive_message`.
                let now = current_time_ms();
                self.queue_archive_record(group_id, mid, now, if sent_at_ms > 0 { sent_at_ms } else { now }, cbor);
            }
        }
        if direction == "sent" {
            if let Some(mid) = message_id {
                self.apply_pending_sibling_ops(Some(group_id), "", mid);
            }
        }
        Ok(())
    }

    /// Whether `target_message_id` in our archive was originally authored by
    /// `sender_identity_id`, for a Delete/Edit that just arrived FROM that
    /// sender. 1:1: the archived row's `direction` must be `"received"`
    /// (i.e. the peer sent it to us — a peer can never own our own "sent"
    /// row). Group: the row's `sender_identity_id` column must match. If the
    /// row isn't found at all, ownership is denied (fail closed). Without
    /// this check, any paired contact/group member could edit or delete an
    /// arbitrary message just by knowing/guessing its id, including one they
    /// never sent.
    pub(crate) fn message_owned_by_sender(&self, group_id: Option<&str>, peer_device_fingerprint: &str, sender_identity_id: &str, target_message_id: &str) -> bool {
        let conn = match &self.db {
            Some(c) => c,
            None => return false,
        };
        match group_id {
            Some(gid) => {
                let row_sender: Option<String> = conn.query_row(
                    "SELECT sender_identity_id FROM messages WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid], |r| r.get(0),
                ).ok();
                row_sender.as_deref() == Some(sender_identity_id)
            }
            None => {
                // The chat key must be that sender's chat: any device of the
                // identity may edit, a device of another identity never.
                if self.canonical_device_for_identity(sender_identity_id).as_deref() != Some(peer_device_fingerprint) {
                    return false;
                }
                let direction: Option<String> = conn.query_row(
                    "SELECT direction FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint], |r| r.get(0),
                ).ok();
                direction.as_deref() == Some("received")
            }
        }
    }

    /// bkz. `pending_edits_deletes` dokümantasyonu — bir Edit/Delete'in
    /// hedefinin arşivde (mesaj OLARAK ya da dosya OLARAK) HİÇ olup
    /// olmadığını, sahiplik/yetki kontrolü YAPMADAN kontrol eder. Bu,
    /// `message_owned_by_sender`/`owns_file`'ın "satır yok" (Text henüz
    /// gelmedi — tamponla) durumunu "satır var ama başkasına ait" (gerçek,
    /// kalıcı red) durumundan ayırt edebilmek için gerekli.
    pub(crate) fn edit_or_delete_target_exists(&self, target_message_id: &str) -> bool {
        if self.message_exists_with_id(target_message_id) {
            return true;
        }
        self.db.as_ref().map(|conn| {
            conn.query_row("SELECT 1 FROM files WHERE file_id = ?1 LIMIT 1", params![target_message_id], |_| Ok(())).is_ok()
        }).unwrap_or(false)
    }

    /// H9: `edit_or_delete_target_exists` in the chat the Edit/Delete is for
    /// (the group, or the sender's 1:1 chat). A row with that id in another
    /// chat made the edit "rejected" and acked instead of buffered.
    pub(crate) fn edit_target_in_chat(&self, target_message_id: &str, group_id: Option<&str>, peer_fp: &str) -> bool {
        let chat_key = self.canonical_peer_key(peer_fp);
        if self.message_exists_in_chat(target_message_id, group_id, &chat_key) {
            return true;
        }
        let Some(conn) = &self.db else { return false };
        match group_id {
            Some(gid) => conn.query_row(
                "SELECT 1 FROM files WHERE file_id = ?1 AND group_id = ?2 LIMIT 1",
                params![target_message_id, gid], |_| Ok(()),
            ).is_ok(),
            // A 1:1 file row keeps the device it came from or went to.
            None => conn.query_row(
                "SELECT peer_device_fingerprint FROM files WHERE file_id = ?1 AND group_id IS NULL",
                params![target_message_id], |r| r.get::<_, String>(0),
            ).map_or(false, |fp| self.canonical_peer_key(&fp) == chat_key),
        }
    }

    /// Hedefi HENÜZ arşivde olmayan bir Edit/Delete'i tamponlar — bkz.
    /// `pending_edits_deletes` alanı ve `EARLY_EDIT_DELETE_TTL_MS`
    /// dokümantasyonu. KASITLI OLARAK Ack GÖNDERMEZ: gönderenin
    /// `awaiting_confirmation` yeniden deneme mekanizması bu paketi canlı
    /// tutar, hedef `Text` arşivlenip `replay_buffered_edits_deletes`
    /// çağrılana (ya da TTL dolana) kadar. Hedef başına
    /// `MAX_EARLY_EDITS_DELETES_PER_TARGET` ile sınırlı (en eskisi atılır) —
    /// kötü niyetli bir eş sınırsız bellek tüketemesin.
    pub(crate) fn buffer_edit_or_delete(&mut self, target_message_id: &str, peer_fp: &str, sender_identity_id: &str, packet_message_id: &str, content: MessageContent) {
        let now = current_time_ms();
        // The per-target cap alone left the number of targets open: a peer
        // could park one edit per invented message id.
        // H85: not acked, so the sender's retry tries again later.
        if self.pending_edits_deletes.len() >= 512 && !self.pending_edits_deletes.contains_key(target_message_id) {
            warn!("Erken Edit tamponu dolu (hedef sayısı) — atlandı (target={})", target_message_id);
            return;
        }
        // And per sender: one contact filled all 512 with invented targets
        // and everybody else's early edits were dropped.
        if self.pending_edits_deletes.values().flatten().filter(|e| e.1 == peer_fp).count() >= 64 {
            warn!("Erken Edit tamponu dolu (gönderen) — atlandı (target={})", target_message_id);
            return;
        }
        // And in bytes: the counts alone let edits of ~1 MiB text each park
        // hundreds of MB. ponytail: scan per buffered packet; fine at these caps.
        let edit_bytes = |c: &MessageContent| match c { MessageContent::Edit { new_text, .. } => new_text.len(), _ => 0 };
        let held: usize = self.pending_edits_deletes.values().flatten().map(|e| edit_bytes(&e.4)).sum();
        if held + edit_bytes(&content) > 16 * 1024 * 1024 {
            warn!("Erken Edit tamponu dolu (bayt) — atlandı (target={})", target_message_id);
            return;
        }
        let buf = self.pending_edits_deletes.entry(target_message_id.to_string()).or_default();
        // A re-encrypted retry of a packet already buffered: it would push a
        // real entry out at the cap.
        if buf.iter().any(|(_, _, _, id, _)| id == packet_message_id) {
            return;
        }
        if buf.len() >= MAX_EARLY_EDITS_DELETES_PER_TARGET {
            // The sender's own oldest goes, never another member's. With none
            // of its own buffered it is not taken: unacked, it comes again.
            let Some(i) = buf.iter().position(|e| e.1 == peer_fp) else {
                warn!("Early Edit buffer full for target {}, not buffered", target_message_id);
                return;
            };
            buf.remove(i);
        }
        buf.push((now, peer_fp.to_string(), sender_identity_id.to_string(), packet_message_id.to_string(), content));
        info!(
            "Hedef mesaj henüz arşivde değil (target={}) — Edit/Delete tamponlandı, Text arşivlenince yeniden denenecek ({} bekliyor)",
            target_message_id, buf.len()
        );
    }

    /// Bir `Text`/grup `Text` başarıyla arşivlendikten HEMEN sonra çağrılır
    /// (bkz. receive_message Text kolları) — o hedef için tamponlanmış
    /// Edit/Delete varsa (bkz. `pending_edits_deletes`) GELİŞ SIRASINDA
    /// yeniden uygular. Üretilen olaylar `attachment_events`'e eklenir
    /// (bkz. `replay_early_packets` aynı desen — `poll_events` bunu
    /// drenaj edip Kotlin/Linux tarafına iletir).
    pub(crate) fn replay_buffered_edits_deletes(&mut self, target_message_id: &str) {
        let buffered = match self.pending_edits_deletes.remove(target_message_id) {
            Some(b) if !b.is_empty() => b,
            _ => return,
        };
        info!("Hedef mesaj artık arşivde (target={}) — {} tamponlanmış Edit/Delete yeniden deneniyor", target_message_id, buffered.len());
        for (_, peer_fp, sender_identity_id, packet_message_id, content) in buffered {
            let event = self.apply_edit_or_delete_content(&peer_fp, &sender_identity_id, &packet_message_id, content);
            self.attachment_events.push(event.to_string());
        }
    }

    /// `poll_events`'ten çağrılır — hedefi hiç gelmeyen tamponlanmış
    /// Edit/Delete paketlerini süresi dolunca temizler (bkz.
    /// `EARLY_EDIT_DELETE_TTL_MS`).
    pub(crate) fn prune_pending_edits_deletes(&mut self) {
        let now = current_time_ms();
        // Dropped entries are acked: the target never came (e.g. the chat was
        // deleted here), and unacked the sender resent them for 7 days.
        let mut expired: Vec<(String, String)> = Vec::new();
        self.pending_edits_deletes.retain(|_, buf| {
            buf.retain(|(t, peer_fp, _, packet_id, _)| {
                let keep = now.saturating_sub(*t) <= EARLY_EDIT_DELETE_TTL_MS;
                if !keep {
                    expired.push((peer_fp.clone(), packet_id.clone()));
                }
                keep
            });
            !buf.is_empty()
        });
        for (peer_fp, packet_id) in expired {
            self.send_ack(&peer_fp, &packet_id);
        }
    }

    /// `Edit`/`Delete` içeriğini GERÇEKTEN uygular — sahiplik/yetki kontrolü,
    /// arşiv güncellemesi, Ack ve olay üretimi (bkz. `message_owned_by_sender`
    /// dokümantasyonu). Hem hedefi zaten var olan canlı paketler için hem de
    /// `replay_buffered_edits_deletes`'ten (tamponlanmış paketler için)
    /// çağrılır — tek bir yerde tutularak iki çağrı yolunun DAVRANIŞÇA
    /// AYNI kalması garanti edilir.
    pub(crate) fn apply_edit_or_delete_content(&mut self, peer_fp: &str, sender_identity_id: &str, packet_message_id: &str, content: MessageContent) -> serde_json::Value {
        // Çoklu-cihaz düzeltmesi (bkz. `canonical_peer_key`): 1:1 arşiv
        // satırları KANONİK cihaz anahtarı altında yazılır (receive_message
        // Text kolu) — sahiplik kontrolü/arşiv güncellemesi/UI olayı da AYNI
        // anahtarı kullanmalı, aksi hâlde kanonik olmayan bir cihazdan gelen
        // Edit/Delete hedef satırı asla bulamazdı. Ack ise GERÇEK gönderen
        // cihaza (`peer_fp`) gider — o cihazla kurulu ratchet üzerinden.
        let chat_key = self.canonical_peer_key(peer_fp);
        // Authorship of the row is not enough in a group: a removed member
        // could still rewrite or delete its old messages for everyone. A group
        // not held yet follows the Text rule: its row was taken under it, so
        // the edit of that row is taken too (its GroupUpdate may be on its way).
        // A group target must also carry the sender's author tag
        // (`group_msg_tag`): only the author can edit or delete it.
        let ex_member = match &content {
            MessageContent::Edit { group_id: Some(gid), target_message_id, .. } | MessageContent::Delete { group_id: Some(gid), target_message_id, .. } =>
                !self.sender_may_post_to_group(gid, sender_identity_id) || !group_msg_id_bound(gid, sender_identity_id, target_message_id),
            _ => false,
        };
        if ex_member {
            self.send_ack(peer_fp, packet_message_id);
            warn!("Grup Edit/Delete reddedildi (gönderen üye değil ya da hedef onun değil): {}", packet_message_id);
            return serde_json::json!({"type": "noop"});
        }
        match content {
            MessageContent::Edit { target_message_id, new_text, group_id, edited_at_ms, author_proof } => {
                // Without this check, any paired contact/group member could
                // edit an arbitrary message (including one they never sent)
                // just by knowing/guessing its id — see
                // `message_owned_by_sender` docs.
                let owns_message = self.message_owned_by_sender(group_id.as_deref(), &chat_key, sender_identity_id, &target_message_id);
                // Acked once stored (as a Text is): acked first, an edit that
                // came before the history key was lost for good. The event
                // only for an edit that was applied: a stale one, arriving
                // late, showed the older text until reload.
                let mut applied = false;
                if owns_message {
                    match self.apply_edit_to_archive(group_id.as_deref(), &chat_key, &target_message_id, &new_text, edited_at_ms) {
                        None => return serde_json::json!({"type": "noop"}),
                        Some(a) => applied = a,
                    }
                    if let (Some(gid), true) = (group_id.as_deref(), applied) {
                        self.adopt_group_author_proof(gid, &target_message_id, author_proof.as_deref());
                    }
                }
                self.send_ack(peer_fp, packet_message_id);
                if owns_message && !applied {
                    return serde_json::json!({"type": "noop"});
                }
                match (&group_id, owns_message) {
                    (Some(gid), true) => serde_json::json!({"type": "group_edit", "group_id": gid, "message_id": target_message_id, "text": new_text}),
                    (None, true) => serde_json::json!({"type": "edit", "peer": chat_key, "message_id": target_message_id, "text": new_text}),
                    // bkz. #16 — hiçbir istemcinin işlemediği bir tür
                    // yayınlamak yerine tanılama log'u + `noop`.
                    (_, false) => {
                        warn!("Edit reddedildi (sahiplik doğrulanamadı): {}", packet_message_id);
                        serde_json::json!({"type": "noop"})
                    }
                }
            }
            MessageContent::Delete { target_message_id, group_id, author_proof } => {
                self.send_ack(peer_fp, packet_message_id);
                // Same ownership rule as Edit (see `message_owned_by_sender`)
                // — otherwise any paired contact could delete an unrelated
                // message/attachment just by guessing/knowing its id.
                let owns_message = self.message_owned_by_sender(group_id.as_deref(), &chat_key, sender_identity_id, &target_message_id);
                // `direction = 'received'`/`sender_identity_id` match: this
                // sender must be the one who originally SENT us the file —
                // otherwise they could delete a file WE sent THEM (which
                // lives in our own "sent" row for that same DM/group).
                let owns_file = match &group_id {
                    // Membership: `ex_member` above.
                    Some(gid) => self.db.as_ref().map(|conn| {
                        conn.query_row(
                            "SELECT 1 FROM files WHERE file_id = ?1 AND group_id = ?2 AND sender_identity_id = ?3",
                            params![target_message_id, gid, sender_identity_id], |_| Ok(()),
                        ).is_ok()
                    }).unwrap_or(false),
                    None => self.db.as_ref().map(|conn| {
                        conn.query_row(
                            // By identity: the peer may delete from another of its
                            // devices than the one that sent the file. The device
                            // column is kept for rows older than `sender_identity_id`.
                            "SELECT 1 FROM files WHERE file_id = ?1 AND (sender_identity_id = ?3 OR peer_device_fingerprint = ?2) AND group_id IS NULL AND direction = 'received'",
                            params![target_message_id, peer_fp, sender_identity_id], |_| Ok(()),
                        ).is_ok()
                    }).unwrap_or(false),
                };
                if owns_file {
                    self.purge_attachment_if_exists(&target_message_id);
                }
                if owns_message {
                    self.apply_delete_to_archive(group_id.as_deref(), &chat_key, &target_message_id);
                    if let Some(gid) = group_id.as_deref() {
                        self.adopt_group_author_proof(gid, &target_message_id, author_proof.as_deref());
                    }
                }
                match (&group_id, owns_message || owns_file) {
                    (Some(gid), true) => serde_json::json!({"type": "group_delete", "group_id": gid, "message_id": target_message_id}),
                    (None, true) => serde_json::json!({"type": "delete", "peer": chat_key, "message_id": target_message_id}),
                    // bkz. #16 — aynı gerekçe.
                    (_, false) => {
                        warn!("Delete reddedildi (sahiplik doğrulanamadı): {}", packet_message_id);
                        serde_json::json!({"type": "noop"})
                    }
                }
            }
            _ => serde_json::json!({"type": "noop"}),
        }
    }

    /// Re-encrypts `new_text` and overwrites the archived copy of
    /// `target_message_id` in place, so an edit survives chat reopen/app
    /// restart instead of only updating the live in-memory adapter. Scoped
    /// by peer/group so it can only ever touch a row that already belongs to
    /// that 1:1/group conversation (see `message_owned_by_sender` for the
    /// caller-side authorization check on the receive path).
    pub(crate) fn apply_edit_to_archive(&mut self, group_id: Option<&str>, peer_device_fingerprint: &str, target_message_id: &str, new_text: &str, edited_at_ms: u64) -> Option<bool> {
        // None: nothing could be stored (key, DB). Some(false): a stale edit.
        let key = self.history_key?;
        let conn = self.db.as_ref()?;
        // Spec dışı (dış AI incelemesi düzeltmesi — sıra-dışı Edit koruması):
        // hedef satırın arşivde SAKLANAN son düzenleme damgasını oku; gelen
        // düzenleme DAHA ESKİ ise (ikisi de sıfırdan farklıysa) bu, gossipsub
        // sırasızlığı yüzünden DAHA YENİ bir düzenlemeden SONRA ulaşan bayat
        // bir düzenlemedir — sessizce yok say, aksi halde en güncel metni
        // eskisiyle "geri alırdı". `edited_at_ms == 0` (sıralama bilgisi
        // taşımayan eski paket) veya `stored == 0` (bu ilk düzenleme)
        // durumunda koşulsuz uygulanır — davranış regresyonu yok.
        let stored_edit_ts: u64 = {
            let row = match group_id {
                Some(gid) => conn.query_row(
                    "SELECT edit_ts FROM messages WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid], |r| r.get::<_, i64>(0),
                ),
                None => conn.query_row(
                    "SELECT edit_ts FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint], |r| r.get::<_, i64>(0),
                ),
            };
            row.map(|v| v as u64).unwrap_or(0)
        };
        if edited_at_ms != 0 && stored_edit_ts != 0 && edited_at_ms <= stored_edit_ts {
            info!(
                "Bayat Edit yok sayıldı (target={} gelen_ts={} <= saklanan_ts={})",
                target_message_id, edited_at_ms, stored_edit_ts
            );
            return Some(false);
        }
        let (encrypted, nonce_bytes) = seal_with(&key, new_text.as_bytes())?;
        // `edit_ts`: en güncel uygulanan düzenlemenin damgasını sakla — bir
        // sonraki (muhtemelen sırasız) düzenlemenin bayat olup olmadığını
        // yukarıdaki kontrol bununla belirler. `GREATEST`-benzeri davranış:
        // yalnızca gelen damga daha büyükse ilerlet (0 gelirse mevcut değeri
        // korur, çünkü buraya sadece "uygulanmalı" kararı verildiğinde geldik).
        let new_edit_ts = std::cmp::max(edited_at_ms, stored_edit_ts) as i64;
        let updated = match group_id {
            Some(gid) => conn.execute(
                "UPDATE messages SET encrypted_blob = ?1, nonce = ?2, is_edited = 1, edit_ts = ?3, author_proof = NULL WHERE message_id = ?4 AND group_id = ?5",
                params![encrypted, nonce_bytes.to_vec(), new_edit_ts, target_message_id, gid],
            ),
            None => conn.execute(
                "UPDATE messages SET encrypted_blob = ?1, nonce = ?2, is_edited = 1, edit_ts = ?3 WHERE message_id = ?4 AND peer_device_fingerprint = ?5 AND group_id IS NULL",
                params![encrypted, nonce_bytes.to_vec(), new_edit_ts, target_message_id, peer_device_fingerprint],
            ),
        };
        updated.ok()?;
        // Sunucudaki geçmişe de yansıt — bkz. `requeue_archive_row`. Bu
        // olmadan sunucu arşivi mesajın DÜZENLENMEMİŞ hâlini saklamaya devam
        // ederdi ve yeni bir cihaz eski metni görürdü.
        self.requeue_archive_row(group_id, peer_device_fingerprint, target_message_id);
        Some(true)
    }


    /// Yerelde DEĞİŞTİRİLMİŞ (düzenlenmiş/silinmiş) bir arşiv satırını
    /// sunucu arşivine yeniden yükler.
    ///
    /// Bu olmadan sunucudaki geçmiş, yeni bir cihaza mesajların DÜZENLENMEMİŞ
    /// hâlini gösterirdi — silinmiş bir mesaj bile geri gelirdi. Protokol bunu
    /// `ArchiveRecord.rev` ile çözüyor: sunucu aynı `record_id` için sadece
    /// DAHA YÜKSEK revizyonu kabul eder.
    ///
    /// `rev` olarak duvar saati kullanılıyor. İlk yükleme `sent_at_ms`
    /// (geçmişte bir an) ile yapıldığından, bir düzenleme/silme her zaman
    /// daha büyük bir değer üretir. Aynı kimliğin iki cihazı aynı satırı
    /// yüklerse yüksek revizyonlu kazanır — yerel arşivin kendi
    /// son-yazan-kazanır kuralıyla (bkz. `edit_ts`) aynı davranış.
    pub(crate) fn requeue_archive_row(&mut self, group_id: Option<&str>, peer_device_fingerprint: &str, target_message_id: &str) {
        let Some(key) = self.history_key else { return };
        if self.archive_root_key.is_none() {
            return;
        }
        let Some(conn) = &self.db else { return };

        let row: Option<(Vec<u8>, Vec<u8>, String, Option<i64>, Option<String>, i64, i64, Option<String>, Option<String>, Option<String>)> =
            match group_id {
                Some(gid) => conn.query_row(
                    "SELECT encrypted_blob, nonce, direction, sent_at_ms, sender_identity_id, is_edited, is_deleted, \
                            reply_to_message_id, reply_to_preview, reply_to_sender_identity_id \
                     FROM messages WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
                ),
                None => conn.query_row(
                    "SELECT encrypted_blob, nonce, direction, sent_at_ms, sender_identity_id, is_edited, is_deleted, \
                            reply_to_message_id, reply_to_preview, reply_to_sender_identity_id \
                     FROM messages WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
                ),
            }
            .ok();
        let Some((blob, nonce_bytes, direction, sent_col, sender_identity_id, is_edited, is_deleted, r_id, r_prev, r_sender)) = row
        else {
            return;
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(&key) else { return };
        if nonce_bytes.len() != 12 { return; } // `from_slice` panics
        let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&nonce_bytes), blob.as_slice()) else { return };

        let sent_at_ms = sent_col.unwrap_or(0).max(0) as u64;
        let archived = ArchivedMessage {
            direction,
            text: String::from_utf8_lossy(&plaintext).to_string(),
            timestamp: current_time_ms(),
            sent_at_ms,
            status: None,
            sender_identity_id,
            message_id: Some(target_message_id.to_string()),
            reply_to_message_id: r_id,
            reply_to_preview: r_prev,
            reply_to_sender_identity_id: r_sender,
            is_deleted: is_deleted != 0,
            is_edited: is_edited != 0,
            // bkz. `ArchivedMessage.reactions`/`seen_by` — bir düzenleme bu
            // satırı YENİDEN arşivler, o ana kadar birikmiş tepki/görüldü
            // bilgisi kaybolmasın diye ikisi de taze okunur.
            reactions: self.reactions_summary(target_message_id),
            seen_by: self.seen_by_json(target_message_id),
            author_proof: group_id.and_then(|gid| self.group_author_proof(gid, target_message_id)),
            mentions_me: false,
        };
        let Ok(cbor) = ciborium_bytes(&archived) else { return };

        let conv_key = match group_id {
            Some(gid) => Some(gid.to_string()),
            None => self.identity_id_for_device(peer_device_fingerprint),
        };
        if let Some(conv_key) = conv_key {
            self.queue_archive_record(&conv_key, target_message_id, current_time_ms(), sent_at_ms, cbor);
        }
    }

    /// Soft-deletes the archived copy of `target_message_id` (see
    /// `apply_edit_to_archive` — same scoping rationale).
    pub(crate) fn apply_delete_to_archive(&mut self, group_id: Option<&str>, peer_device_fingerprint: &str, target_message_id: &str) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        // The text goes too. Only the flag was set: the ciphertext stayed in
        // the row and was uploaded again, in full, to the server archive.
        if let Some((blob, nonce)) = self.history_key.and_then(|k| seal_with(&k, b"")) {
            let _ = match group_id {
                Some(gid) => conn.execute(
                    "UPDATE messages SET encrypted_blob = ?1, nonce = ?2, reply_to_preview = NULL, author_proof = NULL WHERE message_id = ?3 AND group_id = ?4",
                    params![blob, nonce.to_vec(), target_message_id, gid],
                ),
                None => conn.execute(
                    "UPDATE messages SET encrypted_blob = ?1, nonce = ?2, reply_to_preview = NULL WHERE message_id = ?3 AND peer_device_fingerprint = ?4 AND group_id IS NULL",
                    params![blob, nonce.to_vec(), target_message_id, peer_device_fingerprint],
                ),
            };
        }
        match group_id {
            Some(gid) => {
                let _ = conn.execute(
                    "UPDATE messages SET is_deleted = 1 WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid],
                );
            }
            None => {
                let _ = conn.execute(
                    "UPDATE messages SET is_deleted = 1 WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint],
                );
            }
        }
        // Replies that quote it kept its text in `reply_to_preview`, here and
        // in their archived copies.
        // In this chat only: the id is the peer's choice, and in 1:1 this ran
        // over every chat (previews of replies to a same-id message elsewhere).
        let quoting: Vec<(String, String)> = conn
            .prepare("SELECT message_id, peer_device_fingerprint FROM messages WHERE reply_to_message_id = ?1 AND group_id IS ?2 AND (?2 IS NOT NULL OR peer_device_fingerprint = ?3) AND reply_to_preview IS NOT NULL AND message_id IS NOT NULL")
            .and_then(|mut st| st.query_map(params![target_message_id, group_id, peer_device_fingerprint], |r| Ok((r.get(0)?, r.get(1)?))).map(|rows| rows.flatten().collect()))
            .unwrap_or_default();
        let _ = conn.execute("UPDATE messages SET reply_to_preview = NULL WHERE reply_to_message_id = ?1 AND group_id IS ?2 AND (?2 IS NOT NULL OR peer_device_fingerprint = ?3)", params![target_message_id, group_id, peer_device_fingerprint]);
        // A file row is under the device that sent it, not the chat key: any
        // device of the same identity.
        let _ = conn.execute(
            "UPDATE files SET reply_to_preview = NULL WHERE reply_to_message_id = ?1 AND group_id IS ?2
             AND (?2 IS NOT NULL OR peer_device_fingerprint = ?3 OR peer_device_fingerprint IN (
                 SELECT device_fingerprint FROM remote_devices WHERE identity_id =
                     (SELECT identity_id FROM remote_devices WHERE device_fingerprint = ?3)))",
            params![target_message_id, group_id, peer_device_fingerprint],
        );
        // bkz. `apply_edit_to_archive` içindeki aynı kanca — silinmiş bir
        // mesajın sunucudaki kopyası da tombstone'lanmalı, yoksa yeni bir
        // cihazda geri gelirdi.
        self.requeue_archive_row(group_id, peer_device_fingerprint, target_message_id);
        for (message_id, fp) in quoting {
            self.requeue_archive_row(group_id, &fp, &message_id);
        }
    }

    /// Bir geçmiş-senkron satırı TAZE arşivlendiğinde (bu cihaz o satıra
    /// hiç sahip değildi — bkz. `apply_delete_to_archive` çağrı yerlerindeki
    /// AYNI desen) yanıtlayan tarafta `is_edited` işaretliyse burada da
    /// işaretlemek için. `apply_edit_to_archive`'ın AKSİNE metni yeniden
    /// ŞİFRELEMEZ — taze arşivleme zaten `SyncedMessage.text`'i (yanıtlayanın
    /// GÜNCEL/düzenlenmiş içeriği) yazdı, burada sadece bayrak eksik kalmasın
    /// diye üzerine yazılıyor.
    pub(crate) fn mark_synced_message_edited(&mut self, group_id: Option<&str>, peer_device_fingerprint: &str, target_message_id: &str) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        match group_id {
            Some(gid) => {
                let _ = conn.execute(
                    "UPDATE messages SET is_edited = 1 WHERE message_id = ?1 AND group_id = ?2",
                    params![target_message_id, gid],
                );
            }
            None => {
                let _ = conn.execute(
                    "UPDATE messages SET is_edited = 1 WHERE message_id = ?1 AND peer_device_fingerprint = ?2 AND group_id IS NULL",
                    params![target_message_id, peer_device_fingerprint],
                );
            }
        }
    }

    /// Bir kişiyle olan mesaj geçmişini çözüp döner (en yeni `limit` mesaj,
    /// eskiden yeniye sıralı). `history_key` yoksa boş liste döner.
    pub(crate) fn load_message_history(&self, peer_device_fingerprint: &str, limit: u32, before_timestamp: Option<i64>) -> Vec<ArchivedMessage> {
        self.load_message_history_opt(peer_device_fingerprint, limit, before_timestamp, true)
    }

    /// `with_marks: false` skips the reactions and seen-by lookups (two
    /// queries per row): the history-sync answer does not send them.
    pub(crate) fn load_message_history_opt(&self, peer_device_fingerprint: &str, limit: u32, before_timestamp: Option<i64>, with_marks: bool) -> Vec<ArchivedMessage> {
        self.load_message_history_q(peer_device_fingerprint, limit, before_timestamp, None, with_marks, false)
    }

    /// H122: only rows archived after `after_timestamp` (the newest one the
    /// UI holds), newest `limit` of them.
    pub(crate) fn load_message_history_since(&self, peer_device_fingerprint: &str, after_timestamp: i64, limit: u32) -> Vec<ArchivedMessage> {
        self.load_message_history_q(peer_device_fingerprint, limit, None, Some(after_timestamp), true, false)
    }

    /// `sent_clock`: the cursors compare send time (falling back to arrival)
    /// instead of arrival; see `load_history_fetch_page`.
    pub(crate) fn load_message_history_q(&self, peer_device_fingerprint: &str, limit: u32, before_timestamp: Option<i64>, after_timestamp: Option<i64>, with_marks: bool, sent_clock: bool) -> Vec<ArchivedMessage> {
        let key = match &self.history_key {
            Some(k) => *k,
            None => return Vec::new(),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        // `before_timestamp`: bkz. `request_older_history` — dolu ise
        // sonsuz kaydırma sayfalaması (bu zaman damgasından eski mesajlar),
        // `None` ise mevcut davranış (en yeni `limit` mesaj).
        //
        // The cursor is a timestamp only, and a history sync archives a whole
        // batch within one millisecond. A plain `LIMIT` that cut through such
        // a batch lost the rest of it: the next page asks for
        // `timestamp < boundary`. So the page runs to the end of the
        // millisecond of its `limit`-th row (the subquery) and can be a few
        // rows longer than `limit`.
        // ponytail: page size is not exact. A (timestamp, id) cursor through
        // JNI and both UIs is the upgrade if that ever matters.
        if limit == 0 {
            return Vec::new();
        }
        let t = if sent_clock { "COALESCE(NULLIF(sent_at_ms,0), timestamp)" } else { "timestamp" };
        let mut stmt = match conn.prepare(&format!(
            "SELECT direction, encrypted_blob, nonce, timestamp, message_id, status, reply_to_message_id, reply_to_preview, is_deleted, is_edited, COALESCE(NULLIF(sent_at_ms,0), timestamp) FROM messages
             WHERE peer_device_fingerprint = ?1 AND (?3 IS NULL OR {t} < ?3) AND (?4 IS NULL OR {t} > ?4)
               AND {t} >= COALESCE((SELECT {t} FROM messages
                    WHERE peer_device_fingerprint = ?1 AND (?3 IS NULL OR {t} < ?3) AND (?4 IS NULL OR {t} > ?4)
                    ORDER BY {t} DESC, id DESC LIMIT 1 OFFSET ?2 - 1), 0)
             ORDER BY {t} DESC, id DESC"
        )) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map(params![peer_device_fingerprint, limit, before_timestamp, after_timestamp], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
            ))
        });

        let mut results = Vec::new();
        let (mut page_budget, mut page_cut) = (PAGE_MAX_BYTES, None);
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (direction, encrypted_blob, nonce_bytes, timestamp, message_id, status, reply_to_message_id, reply_to_preview, is_deleted, is_edited, eff_sent) = row;
                // H3: bounded in bytes, not rows only (500 texts near 1 MiB
                // each went into one JNI string); never mid-millisecond.
                if page_bytes_full(&mut page_budget, &mut page_cut, if sent_clock { eff_sent } else { timestamp }, encrypted_blob.len()) {
                    break;
                }
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_blob.as_slice()) {
                    if let Ok(text) = String::from_utf8(plaintext) {
                        // `message_id` push icinde MOVE edildiginden ozetleri ONCE hesapla.
                        let reactions_for_row = if with_marks { self.reactions_summary(message_id.as_deref().unwrap_or("")) } else { String::new() };
                        // bkz. `ArchivedMessage.seen_by` — `reactions` ile AYNI
                        // desen, canlı olaydan değil BURADAN (kalıcı
                        // `message_seen` tablosu) taze okunur.
                        let seen_by_for_row = if with_marks { self.seen_by_json(message_id.as_deref().unwrap_or("")) } else { String::new() };
                        results.push(ArchivedMessage {
                            direction,
                            text,
                            timestamp: timestamp as u64,
                            sent_at_ms: eff_sent as u64,
                            status,
                            sender_identity_id: None,
                            message_id,
                            reply_to_message_id,
                            reply_to_preview,
                            reply_to_sender_identity_id: None,
                            is_deleted: is_deleted != 0,
                            is_edited: is_edited != 0,
                            reactions: reactions_for_row,
                            seen_by: seen_by_for_row,
                            author_proof: None,
                            mentions_me: false,
                        });
                    }
                }
            }
        }
        results.reverse(); // eskiden yeniye
        results
    }

    /// Bu peer için yerelde ARŞİVLENMİŞ en yeni mesajın zaman damgası
    /// (arşiv boşsa/DB yoksa `None`). `HistorySyncResponse` işlenirken,
    /// zaten sahip olduğumuz mesajları TEKRAR arşivlememek için kullanılır
    /// (bkz. receive_message notu) — aksi halde her sohbet açılışında
    /// (artık her zaman senkron denendiği için) aynı satırlar yinelenirdi.
    /// `history_key` gerektirmez (sadece zaman damgası okunuyor, şifreli
    /// içerik çözülmüyor).
    pub(crate) fn latest_archived_timestamp(&self, peer_device_fingerprint: &str) -> Option<i64> {
        let conn = self.db.as_ref()?;
        conn.query_row(
            "SELECT MAX(timestamp) FROM messages WHERE peer_device_fingerprint = ?1",
            params![peer_device_fingerprint],
            |row| row.get::<_, Option<i64>>(0),
        ).ok().flatten()
    }

    /// Spec dışı, hata düzeltmesi (grup geçmişi kalıcılığı): bir grubun
    /// mesaj geçmişini çözüp döner — `load_message_history`'nin grup
    /// karşılığı, `group_id`'ye göre filtreler (bkz. `archive_group_message`
    /// notu — artık `peer_device_fingerprint`'e göre YANLIŞ filtrelenmiyor).
    pub(crate) fn load_group_message_history(&self, group_id: &str, limit: u32, before_timestamp: Option<i64>) -> Vec<ArchivedMessage> {
        self.load_group_message_history_opt(group_id, limit, before_timestamp, true)
    }

    /// `with_marks: false` skips the reactions and seen-by lookups (two
    /// queries per row): the history-sync answer does not send them.
    pub(crate) fn load_group_message_history_opt(&self, group_id: &str, limit: u32, before_timestamp: Option<i64>, with_marks: bool) -> Vec<ArchivedMessage> {
        self.load_group_message_history_q(group_id, limit, before_timestamp, None, with_marks, false)
    }

    /// H122: group twin of `load_message_history_since`.
    pub(crate) fn load_group_message_history_since(&self, group_id: &str, after_timestamp: i64, limit: u32) -> Vec<ArchivedMessage> {
        self.load_group_message_history_q(group_id, limit, None, Some(after_timestamp), true, false)
    }

    /// The rows of a `HistorySyncResponse` we keep, before any is written.
    /// In 1:1 only the peer's own ("sent") rows. A reply to the user's
    /// "Fetch older history" press, known by OUR request's window (never the
    /// response's word), keeps only rows sent inside that window and is the
    /// only one that may bring back rows below the history floor: any other
    /// reply (the chat-open sync) drops what the user cleared, pruned or
    /// deleted with the contact. For a press returns its window
    /// `(before, after)` and the oldest row inside it before the 1:1
    /// direction cut (where a follow-up page continues).
    pub(crate) fn filter_history_reply(&self, request_id: &str, group_id: Option<&str>, sender_identity_id: &str, messages: &mut Vec<SyncedMessage>) -> Option<((i64, i64), Option<i64>)> {
        let window = self.outstanding_history_requests.get(request_id).and_then(|e| e.3);
        // Same clock as `prune_chat_before`.
        let sent_at = |m: &SyncedMessage| (if m.sent_at_ms != 0 { m.sent_at_ms } else { m.timestamp }) as i64;
        let mut oldest = None;
        let floor = match window {
            Some((before, after)) => {
                messages.retain(|m| (after..before).contains(&sent_at(m)));
                oldest = messages.iter().map(sent_at).min();
                0
            }
            None => self.history_floor(group_id.unwrap_or(sender_identity_id)) as i64,
        };
        messages.retain(|m| (group_id.is_some() || m.direction == "sent") && sent_at(m) >= floor);
        window.map(|w| (w, oldest))
    }

    /// One "Fetch older history" page of a chat (`group_id`, else the 1:1
    /// chat under `peer_device_fingerprint`): the newest `limit` rows sent in
    /// `[after, before)`, oldest first, without marks.
    pub(crate) fn load_history_fetch_page(&self, peer_device_fingerprint: &str, group_id: Option<&str>, limit: u32, before: i64, after: i64) -> Vec<ArchivedMessage> {
        // `after_timestamp` of the queries is exclusive.
        let after = Some(after.saturating_sub(1));
        match group_id {
            Some(g) => self.load_group_message_history_q(g, limit, Some(before), after, false, true),
            None => self.load_message_history_q(peer_device_fingerprint, limit, Some(before), after, false, true),
        }
    }

    /// H137: the chat list's previews under one lock: per contact (key:
    /// identity id) and per group, the newest message and newest attachment.
    pub(crate) fn chat_list_previews(&self) -> serde_json::Value {
        // F1: the chat orders by sent time, so the preview must too. SQL picks
        // the row (no decryption); only its arrival millisecond is loaded.
        // ponytail: rows sharing that millisecond (a history-sync batch) are all
        // decrypted; a (timestamp, id) cursor is the upgrade if that matters.
        fn newest_sent(rows: Vec<ArchivedMessage>) -> Option<ArchivedMessage> {
            rows.into_iter().max_by_key(|m| if m.sent_at_ms > 0 { m.sent_at_ms } else { m.timestamp })
        }
        let preview_arrival = |column: &str, id: &str| -> Option<i64> {
            self.db.as_ref()?.query_row(
                &format!("SELECT timestamp FROM messages WHERE {column} = ?1
                          ORDER BY COALESCE(NULLIF(sent_at_ms,0), timestamp) DESC, timestamp DESC, id DESC LIMIT 1"),
                params![id], |r| r.get(0),
            ).ok()
        };
        let my_id = self.my_identity_id();
        let mut contacts = serde_json::Map::new();
        for c in self.contacts.values() {
            if my_id.as_deref() == Some(c.trusted_identity_id.as_str()) { continue; }
            let Some(fp) = self.canonical_device_for_identity(&c.trusted_identity_id) else { continue };
            contacts.insert(c.trusted_identity_id.clone(), serde_json::json!({
                "peer": fp,
                "message": preview_arrival("peer_device_fingerprint", &fp)
                    .and_then(|t| newest_sent(self.load_message_history_opt(&fp, 1, Some(t + 1), false))),
                // Limit 1: the rows come oldest first, so `next()` of 500 was the oldest.
                "attachment": self.list_attachments_opt(&fp, false, None, 1).into_iter().next(),
            }));
        }
        let mut groups = serde_json::Map::new();
        for gid in self.groups.keys() {
            groups.insert(gid.clone(), serde_json::json!({
                "message": preview_arrival("group_id", gid)
                    .and_then(|t| newest_sent(self.load_group_message_history_opt(gid, 1, Some(t + 1), false))),
                "attachment": self.list_group_attachments_opt(gid, false, None, 1).into_iter().next(),
            }));
        }
        serde_json::json!({ "contacts": contacts, "groups": groups })
    }

    pub(crate) fn load_group_message_history_q(&self, group_id: &str, limit: u32, before_timestamp: Option<i64>, after_timestamp: Option<i64>, with_marks: bool, sent_clock: bool) -> Vec<ArchivedMessage> {
        let key = match &self.history_key {
            Some(k) => *k,
            None => return Vec::new(),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        // bkz. `load_message_history` aynı `before_timestamp` notu.
        if limit == 0 {
            return Vec::new();
        }
        let t = if sent_clock { "COALESCE(NULLIF(sent_at_ms,0), timestamp)" } else { "timestamp" };
        let mut stmt = match conn.prepare(&format!(
            "SELECT direction, encrypted_blob, nonce, timestamp, message_id, sender_identity_id, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, is_deleted, is_edited, COALESCE(NULLIF(sent_at_ms,0), timestamp), mentions_me, status FROM messages
             WHERE group_id = ?1 AND (?3 IS NULL OR {t} < ?3) AND (?4 IS NULL OR {t} > ?4)
               AND {t} >= COALESCE((SELECT {t} FROM messages
                    WHERE group_id = ?1 AND (?3 IS NULL OR {t} < ?3) AND (?4 IS NULL OR {t} > ?4)
                    ORDER BY {t} DESC, id DESC LIMIT 1 OFFSET ?2 - 1), 0)
             ORDER BY {t} DESC, id DESC"
        )) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map(params![group_id, limit, before_timestamp, after_timestamp], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
                row.get::<_, Option<String>>(13)?,
            ))
        });

        let mut results = Vec::new();
        let (mut page_budget, mut page_cut) = (PAGE_MAX_BYTES, None);
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (direction, encrypted_blob, nonce_bytes, timestamp, message_id, sender_identity_id, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, is_deleted, is_edited, eff_sent, mentions_me, row_status) = row;
                // H3: bounded in bytes, not rows only (500 texts near 1 MiB
                // each went into one JNI string); never mid-millisecond.
                if page_bytes_full(&mut page_budget, &mut page_cut, if sent_clock { eff_sent } else { timestamp }, encrypted_blob.len()) {
                    break;
                }
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_blob.as_slice()) {
                    if let Ok(text) = String::from_utf8(plaintext) {
                        // `message_id` push icinde MOVE edildiginden ozetleri ONCE hesapla.
                        let reactions_for_row = if with_marks { self.reactions_summary(message_id.as_deref().unwrap_or("")) } else { String::new() };
                        // bkz. `ArchivedMessage.seen_by` — grup için ÖZELLİKLE
                        // önemli (kullanıcı: "özellikle gruplarda güvenilir
                        // değil"): çoklu-üye "kim gördü" listesi artık burada,
                        // kalıcı `message_seen` tablosundan taze okunuyor.
                        let seen_by_for_row = if with_marks { self.seen_by_json(message_id.as_deref().unwrap_or("")) } else { String::new() };
                        results.push(ArchivedMessage {
                            direction,
                            text,
                            timestamp: timestamp as u64,
                            sent_at_ms: eff_sent as u64,
                            // The row's own status (delivered, error), not always "sent".
                            status: Some(row_status.unwrap_or_else(|| "sent".to_string())),
                            sender_identity_id,
                            message_id,
                            reply_to_message_id,
                            reply_to_preview,
                            reply_to_sender_identity_id,
                            is_deleted: is_deleted != 0,
                            is_edited: is_edited != 0,
                            reactions: reactions_for_row,
                            seen_by: seen_by_for_row,
                            author_proof: None,
                            mentions_me: mentions_me != 0,
                        });
                    }
                }
            }
        }
        results.reverse(); // eskiden yeniye
        results
    }

    /// Spec dışı, hata düzeltmesi ("bekleyen mesajlar yeniden açılınca
    /// gönderildi gösteriliyor"): `message_status`'un HER değişimini
    /// (bellek-içi HashMap) AYNI ANDA arşivlenmiş satıra da yazar — bu
    /// sayede bir sonraki `load_message_history` (uygulama yeniden
    /// başlasa/sohbet ekranı yeniden açılsa BİLE) gerçek durumu döner.
    /// Satır henüz arşivlenmemişse (ör. `history_key` o an yüklenmemişti)
    /// `UPDATE` sessizce 0 satır etkiler — zararsız, sonraki bir arşivleme
    /// zaten güncel durumu doğrudan yazacaktır.
    pub(crate) fn set_message_status(&mut self, message_id: &str, status: MessageSendStatus) {
        // The map is read once, right after the send (`send_message_content_inner`);
        // the row in `messages` is the record.
        // ponytail: crude bound. Drop the map and return the status from the publish call instead.
        if self.message_status.len() >= 10_000 {
            self.message_status.clear();
        }
        self.message_status.insert(message_id.to_string(), status);
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                // Only our own rows carry a send status; ids are the sender's
                // choice and a received row may share one.
                // #85: 'delivered' is final; a late copy's publish or failure
                // must not turn it back into sent/error.
                "UPDATE messages SET status = ?1 WHERE message_id = ?2 AND direction = 'sent' AND status != 'delivered'",
                params![status.as_str(), message_id],
            );
        }
    }

    // ---------------------------------------------------------------
    // Skipped-message-key kalıcılığı (Double Ratchet sıra dışı mesaj
    // desteği) — bkz. ratchet.rs `skipped_keys` alanı dokümantasyonu.
    // ---------------------------------------------------------------

    /// Bir skipped-key'i (bir cihaz-çifti oturumunda atlanmış bir mesaj
    /// numarasına ait anahtar) Keystore'dan yüklenen anahtarla şifreleyip
    /// DB'ye yazar. `ratchet.rs decrypt`'in "Greater" dalında yeni bir
    /// skipped-key üretildiğinde çağrılır. Anahtar yüklenmemişse (Kotlin
    /// henüz `setSkippedKeyEncryptionKey` çağırmadıysa) sessizce atlanır —
    /// bu durumda skipped-key sadece bellekte kalır (eski davranış).
    pub(crate) fn persist_skipped_key(&self, peer_device_fingerprint: &str, message_number: u32, key: &[u8; 32]) -> Result<(), String> {
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return Ok(()),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Ok(()),
        };

        let (encrypted, nonce_bytes) = seal_with(&enc_key, key.as_slice()).ok_or("Skipped-key encryption failed")?;

        conn.execute(
            "INSERT OR REPLACE INTO skipped_message_keys (peer_device_fingerprint, message_number, encrypted_key, nonce, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![peer_device_fingerprint, message_number, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Bir skipped-key kullanıldığında (mesaj çözüldüğünde) DB'den silinir
    /// — artık tekrar gerekmeyecek (Double Ratchet'in tek-kullanımlık
    /// mesaj anahtarı prensibi diskteki kopya için de geçerli).
    pub(crate) fn delete_persisted_skipped_key(&self, peer_device_fingerprint: &str, message_number: u32) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1 AND message_number = ?2",
                params![peer_device_fingerprint, message_number],
            );
        }
    }

    /// Bir cihaz-çifti oturumu için DB'de kayıtlı (henüz kullanılmamış)
    /// skipped-key'leri çözüp döner. `load_ratchet_states_from_db` tarafından
    /// çağrılır — dönen map, geri yüklenen `DeviceRatchetState.skipped_keys`
    /// alanına atanır.
    pub(crate) fn load_skipped_keys_from_db(&self, peer_device_fingerprint: &str) -> HashMap<u32, [u8; 32]> {
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return HashMap::new(),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return HashMap::new(),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&enc_key) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };

        // M-93: a key older than the old-chain limit is dropped, not loaded.
        let cutoff = current_time_ms().saturating_sub(ratchet::OLD_RECV_MAX_AGE_MS) as i64;
        let _ = conn.execute(
            "DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1 AND created_at < ?2",
            params![peer_device_fingerprint, cutoff],
        );
        let mut stmt = match conn.prepare(
            "SELECT message_number, encrypted_key, nonce FROM skipped_message_keys WHERE peer_device_fingerprint = ?1"
        ) {
            Ok(s) => s,
            Err(_) => return HashMap::new(),
        };

        let rows = stmt.query_map(params![peer_device_fingerprint], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
        });

        let mut results = HashMap::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (message_number, encrypted_key, nonce_bytes) = row;
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_key.as_slice()) {
                    if let Ok(key_bytes) = <[u8; 32]>::try_from(plaintext.as_slice()) {
                        results.insert(message_number, key_bytes);
                    }
                }
            }
        }
        results
    }

    /// Bir cihaz-çifti için diskte kayıtlı TÜM skipped-key'leri siler —
    /// rotasyon olduğunda (`perform_dh_ratchet`/`respond_to_rotation`,
    /// bkz. ratchet.rs) eski zincire ait skipped-key'ler anlamsız kaldığı
    /// için bellekteki `skipped_keys.clear()` ile birlikte diskten de
    /// temizlenmesi gerekir.
    pub(crate) fn clear_persisted_skipped_keys(&self, peer_device_fingerprint: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1",
                params![peer_device_fingerprint],
            );
        }
    }
}
