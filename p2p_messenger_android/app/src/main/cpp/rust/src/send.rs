//! Sending messages, reactions, seen receipts, edits/deletes, acks and typing.

use super::*;

impl P2PCore {

    /// `send_message`/`edit_message`/`delete_message`'ın ortak gövdesi —
    /// üçü de aynı ratchet-şifreli `MessagePacket` yolundan geçer, sadece
    /// çözüldükten sonraki `MessageContent` türü farklıdır (bkz. packet.rs
    /// dokümantasyonu — edit/delete de tam uçtan uca şifreli/imzalı olsun
    /// diye ayrı bir zarf yerine bu ortak yol kullanılıyor).
    /// `archive_plaintext`: SADECE düz metin mesajlar için Some — edit/delete
    /// şu an yerel (node modu) arşive yansıtılmıyor (bkz. dosya sonu not).
    /// Başarılıysa bu mesajın `message_id`'sini döner — çağıran taraf
    /// (Kotlin) bunu ileride edit/delete hedefi olarak saklayabilir.
    /// Dönüş: `(message_id, durum_string)` — durum "sent" (hemen
    /// gönderildi) veya "pending" (geçici olarak kuyrukta, arka planda
    /// yeniden denenecek) olabilir. Bkz. `MessageSendStatus`.
    pub(crate) fn send_message_content(&mut self, peer_device_fingerprint: String, content: &MessageContent, archive_plaintext: Option<&[u8]>) -> Result<(String, String), String> {
        self.send_message_content_inner(peer_device_fingerprint, content, archive_plaintext, None, None, None)
    }

    /// bkz. `send_message_content` dokümantasyonu — asıl gövde. Spec dışı,
    /// kullanıcı isteği (pil dostu, kalıcı yeniden deneme): son üç parametre
    /// SADECE `retry_unconfirmed_messages`'ın `regen_content` tazeleme
    /// yolundan (bkz. o fonksiyon) `Some(...)` geçirilir — bir mesaj
    /// `TEXT_RETRY_GIVE_UP_MS`'ye kadar taze ciphertext'lerle yeniden
    /// denenirken AYNI `message_id`'yi (dolayısıyla AYNI UI balonunu/
    /// `awaiting_confirmation` girdisini), mesajın İLK kuyruğa girdiği
    /// zaman damgasını VE o ana kadar ulaşılmış üstel geri çekilme
    /// aralığını (bkz. `publish_with_ack_tracking` pil dokümantasyonu —
    /// her tazelemede 15s'ye sıfırlanmasın diye) KORUR — normal (yeni) bir
    /// gönderim için üçü de `None`, davranış tamamen değişmeden kalır.
    pub(crate) fn send_message_content_inner(
        &mut self,
        peer_device_fingerprint: String,
        content: &MessageContent,
        archive_plaintext: Option<&[u8]>,
        message_id_override: Option<String>,
        original_sent_at_override: Option<u64>,
        retry_interval_ms_override: Option<u64>,
    ) -> Result<(String, String), String> {
        if !self.ratchets_loaded {
            return Err("Oturum durumu henüz yüklenmedi".to_string()); // see `initiate_handshake_with`
        }
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();

        // `message_id_override` dolu = bu bir TAZELEME (regen / kalıcı kuyruk
        // geri yüklemesi): aynı kimlikle YEPYENİ bir ciphertext üretilecek.
        // bkz. `forget_server_deposit` — sunucu hafızası ciphertext'i değil
        // sadece message_id'yi tanıdığı için, bu silinmezse taze kopya
        // sunucuya (yani karşı taraf çevrimdışıyken tek ulaşılabilir yere)
        // hiç yatırılmıyordu.
        // Only a refresh carries `original_sent_at_override`; a fresh 1:1 text
        // also pins its id (`send_message`) but is no refresh.
        if let (Some(mid), Some(_)) = (&message_id_override, original_sent_at_override) {
            self.forget_server_deposit(mid);
            // Tazeleme, karşı tarafın 25 dakikadır HİÇBİR şeyi
            // onaylamadığı anlamına gelir — el sıkışmamızın hiç ulaşmamış
            // olma ihtimali de buna dahil (bkz. `maybe_redo_handshake`).
            let prev = self.regen_skip_id.replace(mid.clone());
            self.maybe_redo_handshake(&peer_device_fingerprint);
            self.regen_skip_id = prev;
        }

        // Spec dışı, ağ sağlamlığı: gönderim yolunda, karşı tarafa canlı bir
        // bağlantı yoksa hemen yeniden bağlanmayı tetikle — böylece gossipsub
        // publish, bağlantı kurulur kurulmaz (pending_envelopes retry'siyle)
        // başarılı olur, reconnect_sweep'in bir sonraki turunu beklemeden.
        self.ensure_connected(&peer_device_fingerprint);

        if !self.ratchets.contains_key(&peer_device_fingerprint) {
            // `initiate_handshake_with` ratchet state'i publish denemesinden
            // ÖNCE oluşturur (bkz. o fonksiyon) — bu yüzden HandshakeInit'in
            // KENDİ gönderimi (aşağıdaki `publish_envelope` gibi) geçici
            // olarak başarısız olsa bile burada durmuyoruz: state zaten var,
            // asıl mesajı şifreleyip göndermeye devam edebiliriz.
            // HandshakeInit'in kendisi başarısız olduysa `publish_envelope`
            // onu kendi içinde yeniden deneme kuyruğuna zaten ekledi.
            if let Err(e) = self.initiate_handshake_with(&peer_device_fingerprint) {
                error!("Handshake gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
            }
            // KNOWN GAP (aynı önceki tasarımdan miras): handshake ve mesaj
            // ardışık gönderiliyor, gossipsub sıra garantisi vermiyor.
        }

        // NOT: bu iki bayrak ÖNCEDEN paket inşasından SONRA hesaplanıyordu —
        // artık rotasyon kararının ÖNCESİNE taşındı (aşağıdaki rotasyon
        // gating'i için gerekli), anlamları/dokümantasyonları değişmedi
        // (bkz. aşağıda, publish seçim noktasındaki uzun notlar).
        let needs_delivery_confirmation = matches!(
            content,
            MessageContent::Text { .. }
                | MessageContent::Edit { .. }
                | MessageContent::Delete { .. }
                | MessageContent::Reaction { .. }
                | MessageContent::HistorySyncRequest { .. }
                | MessageContent::HistorySyncResponse { .. }
                | MessageContent::FileOffer { .. }
                | MessageContent::GroupUpdate(_)
                | MessageContent::LeaveGroupRequest { .. }
                | MessageContent::GroupSyncRequest { .. }
                | MessageContent::ProfileUpdate { .. }
                | MessageContent::DeviceLinkGrant { .. }
                | MessageContent::DeviceAddNotice { .. }
                | MessageContent::DeviceRevokeNotice(_)
                | MessageContent::FirstContactSecret { .. }
                | MessageContent::DeviceSync(_)
                | MessageContent::SiblingEcho { .. }
                | MessageContent::ReadStateSync { .. }
                | MessageContent::SiblingHistoryRequest { .. }
                | MessageContent::AccountDeleted { .. }
                | MessageContent::WbDigest { .. }
        );

        // Güvenilirlik düzeltmesi (rotasyon duyurusu kaybı): rotasyon SADECE
        // onay-takipli (karşı taraf Ack'leyene kadar yeniden denenen) bir
        // içerik gönderilirken tetiklenir. Önceden HER içerik tetikleyebilirdi
        // — duyuru bir `TypingIndicator`'a (hiç yeniden denenmeyen) ya da
        // bir `Ack`'e (sınırlı deneme) binerse ve o paket kaybolursa, karşı
        // taraf yeni kök anahtarı/topic'i ASLA öğrenemiyor ve oturum kalıcı
        // olarak kopuyordu. Ek güvence: taze bir rotasyon yoksa bile,
        // henüz doğrulanMAMIŞ bir önceki rotasyonun duyurusu
        // (`pending_rotation_ct`, bkz. ratchet.rs) HER giden pakete yeniden
        // eklenir — alıcı tarafta idempotent (bkz. `respond_to_rotation`
        // çift-uygulama koruması), `try_publish_raw` bu paketleri karşı
        // tarafın hâlâ dinlediği ESKİ topic'ten yollar.
        // A responder leaves the handshake chain before it sends anything at
        // all, an Ack included (bkz. ratchet.rs `respond`): that chain is a
        // function of the HandshakeInit alone. The announcement is repeated
        // on every packet until confirmed, so it may ride an unreliable one.
        let fresh_responder = self.ratchets.get(&peer_device_fingerprint).map_or(false, |s| s.is_fresh_responder());
        // M-94: a peer that only reads sends `Seen` (and `ReadStateSync`,
        // in the list above); it takes its rotation turn on them too, or it
        // never heals. The announcement repeats on every packet until confirmed.
        let rotation_turn = needs_delivery_confirmation || matches!(content, MessageContent::Seen { .. });
        let fresh_rotation_ct = if rotation_turn || fresh_responder {
            self.maybe_rotate_ratchet(&peer_device_fingerprint)?
        } else {
            None
        };
        if fresh_rotation_ct.is_some() {
            // bkz. `regen_pending_for_peer` — az önce rotasyon yaptık; bu
            // peer için bekleyen (eski zincirle şifrelenmiş, artık asla
            // çözülemeyecek) paketler hemen taze zincirle yeniden üretilir.
            // This message is encrypted on the fresh chain below anyway.
            let prev = std::mem::replace(&mut self.regen_skip_id, message_id_override.clone());
            self.regen_pending_for_peer(&peer_device_fingerprint);
            self.regen_skip_id = prev;
        }
        let rotation_kyber_ciphertext = match fresh_rotation_ct {
            Some(ct) => Some(ct),
            None => self
                .ratchets
                .get(&peer_device_fingerprint)
                .and_then(|s| s.pending_rotation_ct.clone()),
        };

        // Before `encrypt_next`: an Err after it leaves a used message number
        // and an orphan `hsr:` row.
        if !self.own_device_keys.contains_key(&own_fp) {
            return Err("Missing own keys".to_string());
        }
        let state = self.ratchets.get_mut(&peer_device_fingerprint).ok_or("No ratchet session")?;
        // NOT: `own_ratchet_pubkeys()` rotasyon SONRASI çağrılıyor
        // (maybe_rotate_ratchet zaten çalıştı), bu yüzden rotasyon olduysa
        // burada YENİ public key'ler alınır. Sent only with a rotation
        // announcement: the receiver reads it in no other packet, and it was
        // 1.6 KB of every message, ack and typing indicator.
        let ratchet_pubkey = match rotation_kyber_ciphertext {
            Some(_) => state.own_ratchet_pubkeys().to_bytes()?,
            None => Vec::new(),
        };
        let content_bytes = ciborium_bytes(content)?;
        let message_id = message_id_override.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        // M-89: the header is built first; its raw bytes are the AEAD's
        // associated data and what the signature covers.
        let (message_number, prev_chain_length) = state.next_send_numbers();
        let header = packet::SignedHeader::new(MessagePacketHeader {
            sender_identity_id: own_identity_id,
            sender_device_fingerprint: own_fp.clone(),
            message_id: message_id.clone(),
            ratchet_pubkey,
            message_number,
            prev_chain_length,
            rotation_kyber_ciphertext,
            sent_at_ms: current_time_ms(),
        })?;
        // Rollback copy: a state that cannot be saved must not burn the
        // message number (nothing is published with it).
        let snapshot = state.clone();
        let (ciphertext, used_number, used_prev) = state.encrypt_next(&content_bytes, header.raw())?;
        if (used_number, used_prev) != (message_number, prev_chain_length) {
            self.ratchets.insert(peer_device_fingerprint.clone(), snapshot);
            return Err("Ratchet numbers moved under the header".to_string());
        }
        // `encrypt_next` her çağrıda ck_send/send_message_number'ı ilerletir
        // — diskteki kopya bayatlamasın diye her mesajda kalıcılaştırıyoruz
        // (rotasyon olduysa `maybe_rotate_ratchet` zaten yukarıda ayrıca
        // yazdı, bu ikinci yazma zararsız/idempotent bir üst kaplama).
        if !self.persist_ratchet_state(&peer_device_fingerprint) {
            self.ratchets.insert(peer_device_fingerprint.clone(), snapshot);
            return Err("Oturum durumu yazılamadı, paket gönderilmedi".to_string());
        }
        drop(snapshot);

        if let MessageContent::HistorySyncRequest { group_id, before_timestamp, after_timestamp, .. } = content {
            let now = current_time_ms();
            // Yanıt, isteğin yeniden deneme ömrü içinde gelir; daha eskisi atılır.
            let stale: Vec<String> = self.outstanding_history_requests.iter()
                .filter(|(_, (_, _, at, _))| now.saturating_sub(*at) >= TEXT_RETRY_GIVE_UP_MS)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &stale {
                self.forget_history_request(id);
            }
            let target_identity = if group_id.is_none() {
                self.identity_id_for_device(&peer_device_fingerprint)
            } else {
                None
            };
            let entry = (target_identity, group_id.clone(), now, before_timestamp.zip(*after_timestamp));
            // Diske de yazılır: yanıt sunucu posta kutusunda beklerken süreç
            // ölürse, açılışta istenmemiş sayılıp reddedilmesin.
            if let Some(conn) = &self.db {
                if let Ok(json) = serde_json::to_string(&entry) {
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO app_meta (k, v) VALUES (?1, ?2)",
                        params![format!("hsr:{}", message_id), json],
                    );
                }
            }
            self.outstanding_history_requests.insert(message_id.clone(), entry);
        }
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let to_sign = packet_signing_input(header.raw(), &ciphertext, &peer_device_fingerprint);
        let sig_classical: Ed25519Signature = own_keys.sign_sk_ed25519.sign(&to_sign);
        let sig_pq: MlDsaSignature<MlDsa87> = own_keys.sign_sk_mldsa.sign(&to_sign);

        let packet = MessagePacket {
            header,
            ciphertext,
            signature_classical: sig_classical.to_bytes().to_vec(),
            signature_pq: sig_pq.encode().to_vec(),
        };

        // Spec dışı düzeltme: önceden SADECE node modu açık cihazlarda
        // arşivleniyordu (o zamanki kullanıcı tercihi) — kullanıcı artık
        // açıkça TÜM cihazlarda (node olsun olmasın) kendi sohbet
        // geçmişinin yerelde şifreli kalıcı kılınmasını istedi; node modu
        // artık SADECE "karşı taraflara geçmiş senkronizasyon isteklerinde
        // yardımcı olma" (bkz. HistorySyncRequest) ve röle hizmetini
        // etkiliyor, kendi geçmişini SAKLAMA kararını değil.
        // Ağ paketinin kendisi zaten uçtan uca şifreli; bu AYRI bir
        // "dinlenme hâlinde şifreleme" katmanıdır (bkz. archive_message —
        // `history_key` artık node modundan bağımsız her zaman yüklü,
        // bkz. P2PService/MessageHistoryManager).
        // Spec dışı, hata düzeltmesi ("bekleyen mesajlar yeniden açılınca
        // gönderildi gösteriliyor"): `message_id` ve ilk durum artık
        // satırla BİRLİKTE yazılıyor — `Pending` olarak başlar, aşağıdaki
        // gerçek yayın denemesi (`publish_with_ack_tracking`/
        // `publish_envelope`) sonucu `set_message_status` ile AYNI satırı
        // Sent/Failed'e günceller. Böylece bir reload (uygulama/sohbet
        // ekranı yeniden açılışı) gerçek durumu görür, sabit "gönderildi"
        // varsaymaz. NOT: grup mesajları (`send_group_message`) BURAYA
        // `archive_plaintext: None` geçer (bkz. o fonksiyonun notu) — kendi
        // arşivlemesini `archive_group_message` ile TEK satır olarak,
        // fan-out döngüsünden ÖNCE zaten yapıyor; aksi halde N üyeye giden
        // fan-out'un HER kopyası burada ayrı bir satır oluştururdu.
        if let Some(plaintext) = archive_plaintext {
            // bkz. packet.rs `MessageContent::Text.reply_to_message_id`
            // dokümantasyonu — kendi gönderdiğimiz mesajın arşiv satırı da
            // (varsa) yanıt bilgisini taşımalı, aksi hâlde KENDİ balonumuzda
            // bile bir reload sonrası "kime yanıt verdim" bilgisi kaybolurdu.
            let (reply_to_id, reply_to_prev, sent_at) = match content {
                MessageContent::Text { reply_to_message_id, reply_to_preview, sent_at_ms, .. } => {
                    (reply_to_message_id.as_deref(), reply_to_preview.as_deref(), *sent_at_ms)
                }
                _ => (None, None, 0),
            };
            // Not sent when our own copy cannot be kept: the peer would hold
            // a message our history never has. The skipped number is harmless.
            if let Err(e) = self.archive_message(&peer_device_fingerprint, "sent", plaintext, Some(&message_id), Some(MessageSendStatus::Pending.as_str()), reply_to_id, reply_to_prev, sent_at) {
                error!("Gönderilen mesaj arşive yazılamadı, gönderilmedi: {}", e);
                return Err(format!("Mesaj kaydedilemedi: {}", e));
            }
        }

        // Spec dışı, kullanıcı tarafından istenen güvenilir teslim:
        // Text (grup DIŞI)/Edit/Delete/HistorySyncRequest, karşı taraftan
        // bir onay (Ack veya HistorySyncResponse) gelene kadar SÜRESİZ
        // yeniden gönderilir (bkz. `awaiting_confirmation` dokümantasyonu)
        // — `gossipsub.publish()`'in yerel başarısı karşı tarafın GERÇEKTEN
        // aldığının garantisi değildir, bu yüzden tek seferlik/zaman
        // sınırlı `publish_envelope`/`pending_envelopes` yetersizdi (bazı
        // mesajlar/düzenlemeler/silmeler hiç karşı tarafa ulaşmadan
        // sessizce "gönderildi" sayılıyordu). Diğer içerik türleri (Ack,
        // HistorySyncResponse, FileOffer, grup mesajları) eski davranışı
        // (tek seferlik, kısa süreli yeniden deneme) korur — Ack zaten
        // kendisi onaylanmıyor (sonsuz döngü riski), grup mesajlarının
        // N-yönlü fan-out'u bu mekanizmayı karmaşıklaştırırdı (bilinen
        // sınır, ileride genişletilebilir).
        // `FileOffer` de dahil: bu paket kaybolursa (aynı ağ
        // güvenilmezliği, bkz. dosya başı not), alıcı bir dosya
        // teklif edildiğini HİÇBİR ZAMAN öğrenemez ve ek balonu hiç
        // görünmez — dosya parça transferinin (request_response,
        // attachments.rs) KENDİ güvenilirliği (chunk-seviyeli yeniden
        // deneme) bu METADATA mesajını kapsamıyordu, ayrı bir sorun.
        //
        // Spec dışı, hata düzeltmesi ("bir grup üyesi bazı mesajları
        // kaçırıyor"): `Text { group_id: Some(_), .. }` artık BURADA DA —
        // önceden grup metni bilinçli olarak dışarıda bırakılmıştı ("N-yönlü
        // fan-out'u karmaşıklaştırır" gerekçesiyle), ama fan-out zaten HER
        // üyeye AYRI bir `send_message_content` çağrısı (kendi message_id/
        // kendi hedef peer_fp) olduğundan, bu mekanizma tek bir 1:1 gönderim
        // gibi sorunsuz uygulanıyor — karmaşıklaştıran bir şey yok, sadece
        // gözden kaçmış bir hariç tutma. Alıcı tarafı da artık Ack gönderiyor
        // (bkz. receive_message Text/group_id kolu).
        //
        // Spec dışı, ağ sağlamlığı düzeltmesi (kullanıcı isteği: "her şey
        // onaylanana kadar denenmeli"): `ProfileUpdate` (alıcı zaten Ack
        // gönderiyordu, sadece bu listeye hiç eklenmemişti) ve
        // `HistorySyncResponse` (bkz. receive_message HistorySyncResponse
        // kolu — artık geri bir Ack gönderiyor) da artık BURADA. Kasıtlı
        // olarak BURAYA EKLENMEYENLER: `Ack`/`Seen` (kendileri
        // onaylanmıyor — sonsuz ack-of-ack döngüsü riski; bir kez gönderilir,
        // bkz. `reack_if_already_handled`) ve `TypingIndicator` (bkz. packet.rs
        // notu — birkaç saniyede bayatlayan bir sinyali dakikalarca yeniden
        // denemenin hiçbir değeri yok, YANLIŞ/eski bir "yazıyor" göstergesi
        // göstermekten başka bir işe yaramaz).
        // (`needs_delivery_confirmation` bu noktadan YUKARI taşındı — rotasyon
        // gating'i onu paket inşasından önce gerektiriyor; kapsam listesi ve
        // gerekçeleri değişmedi: DeviceLinkGrant kritik [kaybolursa ikincil
        // cihaz asla benimsenmez], SiblingEcho/ReadStateSync kardeş senkronu
        // güvenilir olmalı, SiblingHistoryRequest önceden hiç Ack'lenmiyordu.)
        // Ack/Seen bir kez gönderilir (yayın geçici başarısızsa
        // `pending_envelopes` yeniden dener). Önceden koşulsuz 9 kez (~10.6 dk)
        // tekrar ediliyordu: tek bir mesaj başına onlarca gereksiz paket, ve
        // sunucu açıkken her biri ayrı bir Deposit. Kayıp bir Ack'i artık
        // göndericinin kendi yeniden denemesi + `reack_if_already_handled`
        // telafi ediyor; "görüldü"nün güvenilir yolu `ReadStateSync`.
        // Spec dışı, kullanıcı geri bildirimi ("6 saat interneti açmayan
        // biri" senaryosu, sonra kullanıcı isteğiyle sıradan Text'e de
        // genişletildi): `MAX_UNCONFIRMED_AGE_MS` dolduğunda bu türler pes
        // etmek yerine taze şifrelenip `TEXT_RETRY_GIVE_UP_MS`'ye kadar
        // yeniden denenir — bkz. `PendingConfirmation.regen_content`
        // dokümantasyonu.
        //
        // Spec dışı, kullanıcı geri bildirimi ("aynı hesaba bağlı cihazlar
        // arası senkron berbat, çok geç geliyor, çoğu düşüyor"): çoklu-cihaz
        // kontrol mesajları da ARTIK bu listede. Önceden değillerdi ve bu,
        // sessiz KALICI kayıplarının doğrudan sebebiydi: bu türler
        // `needs_delivery_confirmation`'da olduğu için onaylanana kadar
        // yeniden deneniyorlardı, ama HER ZAMAN AYNI ciphertext'le. Kardeş
        // cihaz `MAX_UNCONFIRMED_AGE_MS`'ten (~25 dk) uzun süre çevrimdışı
        // kalırsa — telefonun cebinde kaldığı herhangi bir öğleden sonra —
        // aradaki ratchet rotasyonu alıcının o zincire ait skipped-key
        // önbelleğini siler ve o paket ARTIK ASLA çözülemez; yeniden deneme
        // kriptografik olarak imkânsız bir şeyi denemeye devam eder, sonra
        // "Failed" olarak bırakılır. Kullanıcı tarafında bu tam olarak
        // "mesajların çoğu diğer cihaza hiç düşmedi" demek.
        //
        // `regen_content` ile bunun yerine TAZE bir ratchet adımıyla, AYNI
        // `message_id` ile yeniden şifrelenirler (bkz. `message_id_override`)
        // — alıcı zaten `message_id` üzerinden dedup ettiği için çift arşiv
        // oluşmaz, ve `TEXT_RETRY_GIVE_UP_MS`'ye (7 gün) kadar hayatta
        // kalırlar. `Ack`/`Seen`/`TypingIndicator` KASITLI olarak dışarıda
        // (bkz. yukarıdaki notlar); `HistorySyncResponse` de dışarıda —
        // toplu bir yanıt, kaybolursa istek zaten yeniden sorulur ve
        // günlerce yeniden şifrelemeye değmez.
        // Spec dışı, dayanıklılık düzeltmesi: `HistorySyncRequest` ve
        // `LeaveGroupRequest` önceden bu listede DEĞİLDİ — `regen_content`
        // `None` olduğunda `publish_with_ack_tracking` bu girdiyi
        // `persist_durable_retry` ile diske YAZMIYOR (bkz. o fonksiyonun
        // çağrı yeri), yani süreç (uygulama) bu paketler onaylanmadan
        // ÖLDÜRÜLÜRSE/yeniden başlarsa `awaiting_confirmation`'daki bellek
        // içi kaydı kalıcı olarak kaybolur ve bir daha ASLA yeniden
        // denenmez — sessiz kalıcı kayıp. `HistorySyncResponse` kasıtlı
        // olarak dışarıda bırakılıyor (yukarıdaki not) çünkü kaybı zaten
        // zararsız: istek (`HistorySyncRequest`) artık kalıcı olduğundan
        // kendi yeniden denemesi taze bir yanıt tetikleyecektir.
        let regen_content = matches!(
            content,
            MessageContent::Text { .. }
                | MessageContent::Edit { .. }
                | MessageContent::Delete { .. }
                | MessageContent::Reaction { .. }
                | MessageContent::GroupUpdate(_)
                | MessageContent::SiblingEcho { .. }
                | MessageContent::DeviceSync(_)
                | MessageContent::DeviceLinkGrant { .. }
                | MessageContent::DeviceAddNotice { .. }
                | MessageContent::DeviceRevokeNotice(_)
                | MessageContent::FirstContactSecret { .. }
                | MessageContent::ReadStateSync { .. }
                | MessageContent::ProfileUpdate { .. }
                | MessageContent::FileOffer { .. }
                | MessageContent::HistorySyncRequest { .. }
                | MessageContent::LeaveGroupRequest { .. }
                | MessageContent::GroupSyncRequest { .. }
                | MessageContent::AccountDeleted { .. }
                | MessageContent::WbDigest { .. }
        ).then(|| content.clone());
        if needs_delivery_confirmation {
            self.publish_with_ack_tracking(
                &peer_device_fingerprint, &message_id, NetworkEnvelope::Message(packet), regen_content,
                original_sent_at_override, retry_interval_ms_override,
            );
        } else if let Err(e) = self.publish_envelope(&peer_device_fingerprint, &NetworkEnvelope::Message(packet)) {
            error!("Mesaj gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
        }
        let status = self.message_status.remove(&message_id).unwrap_or(MessageSendStatus::Pending);
        Ok((message_id, status.as_str().to_string()))
    }

    /// `reply_to_message_id`/`reply_to_preview`: spec dışı, kullanıcı
    /// isteği (WhatsApp tarzı "sağa kaydırıp yanıtla") — bkz. packet.rs
    /// `MessageContent::Text.reply_to_message_id` dokümantasyonu. Kotlin
    /// tarafı zaten yerelde gösterdiği mesajın metnini bildiğinden özeti
    /// (kırpılmış) BURADA sağlar — Rust tarafı ayrıca bir arşiv sorgusu
    /// yapmaz.
    pub(crate) fn send_message(&mut self, peer_device_fingerprint: String, plaintext: String, reply_to_message_id: Option<String>, reply_to_preview: Option<String>) -> Result<(String, String), String> {
        if self.known_remote_devices.get(&peer_device_fingerprint)
            .map_or(false, |d| self.deleted_identities.contains(&d.identity_id))
        {
            return Err("Bu kişi hesabını sildi".to_string());
        }
        // bkz. packet.rs `MessageContent::Text.sent_at_ms` dokümantasyonu —
        // BURADA, İLK yazılma anında, bir kez damgalanır; `regen_content`
        // tazelemeleri (bkz. network.rs retry_unconfirmed_messages) bu değeri
        // İÇEREN `content`'i AYNEN klonlayıp yeniden şifreler, DEĞİŞTİRMEZ.
        let sent_at_ms = current_time_ms();
        // Çoklu-cihaz (spec 1.7.1): 1:1 mesajlara da grup mesajları gibi
        // KARARLI bir konuşma-içi kimlik (`conv_id`) veriyoruz — TÜM fan-out
        // kopyaları AYNI `group_message_local_id`'yi taşır. Böylece bir
        // düzenleme/silme/"görüldü" (alıcı ister tek ister çok cihazlı olsun)
        // her cihazda AYNI balona uygulanır. Ana kopyanın paket başlığı
        // (`message_id`) da `conv_id`'ye sabitlenir (`message_id_override`),
        // böylece teslim onayı (Ack) + gönderim durumu + UI balonu hepsi AYNI
        // kimliği paylaşır. Fan-out kopyaları kendi (farklı) paket kimliğini
        // alır (kendi Ack'leri için) ama içerikteki `conv_id` ortaktır.
        let conv_id = uuid::Uuid::new_v4().to_string();
        let content = MessageContent::Text {
            group_id: None, text: plaintext.clone(), group_message_local_id: Some(conv_id.clone()), sent_at_ms,
            reply_to_message_id: reply_to_message_id.clone(), reply_to_preview: reply_to_preview.clone(),
            reply_to_sender_identity_id: None, author_proof: None, mentions: Vec::new(),
        };
        info!("Metin gönderiliyor: id={} peer={}", &conv_id[..8], &peer_device_fingerprint[..8.min(peer_device_fingerprint.len())]);
        let result = self.send_message_content_inner(
            peer_device_fingerprint.clone(), &content, Some(plaintext.as_bytes()), Some(conv_id.clone()), None, None,
        );
        // Kardeş cihazlarıma da yankıla (AYNI conv_id ile).
        if result.is_ok() {
            // Only after the primary copy: on Err there is no row and no
            // retry entry here, and the other devices would get a text the
            // sender does not have.
            self.fanout_extra_copies(&peer_device_fingerprint, &content);
            self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::Text {
                message_id: conv_id.clone(), text: plaintext, sent_at_ms,
                reply_to_message_id, reply_to_preview, reply_to_sender_identity_id: None,
            });
        }
        result
    }

    /// Çoklu-cihaz (spec 1.7.1): bir 1:1 mesajı, hedef kişinin ANA cihazına
    /// gönderildikten sonra AYNI kişinin DİĞER aktif cihazlarına da ayrı ayrı
    /// (kendi ratchet'leriyle) gönderilir. Tek cihazlı kişilerde no-op
    /// (davranış değişmez). Arşiv YAPILMAZ (ana gönderim zaten tek satır
    /// arşivledi).
    pub(crate) fn fanout_extra_copies(&mut self, primary_fp: &str, content: &MessageContent) {
        for fp in self.fanout_targets(primary_fp) {
            if fp == primary_fp { continue; }
            if let Err(e) = self.send_message_content(fp.clone(), content, None) {
                error!("Çoklu-cihaz fan-out kopyası ({}) başarısız: {}", crate::log_id(&fp), e);
            }
        }
    }

    /// The reactions of `reactors` (at most one row each) on `message_id`.
    pub(crate) fn reactions_of(&self, message_id: &str, reactors: [&str; 2]) -> Vec<(String, String, u64)> {
        let Some(conn) = &self.db else { return Vec::new() };
        conn.prepare("SELECT reactor_identity_id, emoji, reacted_at_ms FROM message_reactions WHERE message_id = ?1 AND reactor_identity_id IN (?2, ?3)")
            .and_then(|mut stmt| stmt.query_map(params![message_id, reactors[0], reactors[1]], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)?.max(0) as u64)))?.collect())
            .unwrap_or_default()
    }

    /// F3: a history page's reactions, for the rows `event["messages"]` kept
    /// (after the floor, direction and author checks). The responder's own
    /// are taken. Mine only to restore one I have no row for (a new device),
    /// on a row I have, stamped in the past: the responder could otherwise
    /// forge, freeze (huge stamp) or erase (empty emoji) my reactions.
    pub(crate) fn apply_synced_reactions(&self, event: &mut serde_json::Value, reactions: &HashMap<String, Vec<(String, String, u64)>>, group_id: Option<&str>, sender_identity_id: &str) {
        let own_id = self.my_identity_id();
        let now = current_time_ms();
        let Some(rows) = event["messages"].as_array_mut() else { return };
        for row in rows {
            let Some(mid) = row["message_id"].as_str().map(str::to_string) else { continue };
            let Some(list) = reactions.get(&mid) else { continue };
            let mut changed = false;
            for (reactor, emoji, at) in list {
                if emoji.len() > 64 || !self.reaction_fits_chat(&mid, group_id, sender_identity_id) {
                    continue;
                }
                let take = reactor == sender_identity_id
                    || (Some(reactor) == own_id.as_ref() && !emoji.is_empty() && *at > 0 && *at <= now + 60_000
                        && self.db.as_ref().is_some_and(|c| c.query_row(
                            "SELECT (EXISTS(SELECT 1 FROM messages WHERE message_id = ?1) OR EXISTS(SELECT 1 FROM files WHERE file_id = ?1))
                               AND NOT EXISTS(SELECT 1 FROM message_reactions WHERE message_id = ?1 AND reactor_identity_id = ?2)",
                            params![mid, reactor], |r| r.get::<_, bool>(0),
                        ).unwrap_or(false)));
                if take {
                    changed |= self.apply_reaction(&mid, reactor, emoji, *at);
                }
            }
            if changed {
                row["reactions"] = self.reactions_summary(&mid).into();
            }
        }
    }

    /// Spec dışı, kullanıcı isteği (WhatsApp tarzı tepkiler): bir kişinin
    /// bir mesaja bıraktığı emojiyi yerel arşive yazar.
    ///
    /// KİŞİ BAŞINA TEK tepki: `INSERT OR REPLACE` yeni emojiyi eskinin
    /// yerine koyar, boş `emoji` satırı siler. `reacted_at_ms` koruması
    /// `apply_edit_to_archive` ile AYNI gerekçeye dayanır: gossipsub sıra
    /// garantisi vermez, aynı kişinin hızlıca değiştirdiği iki tepki ters
    /// sırada ulaşabilir — DAHA ESKİ olan, daha yeninin üzerine YAZMAMALI.
    /// Damgası olmayan (eski sürüm) paketler koşulsuz uygulanır.
    /// `false`: the row could not be written (a received reaction is then not acked).
    pub(crate) fn apply_reaction(&self, target_message_id: &str, reactor_identity_id: &str, emoji: &str, reacted_at_ms: u64) -> bool {
        // M101: no DB is not "applied".
        let Some(conn) = &self.db else { return false };
        if reacted_at_ms > 0 {
            let previous: Option<i64> = conn
                .query_row(
                    "SELECT reacted_at_ms FROM message_reactions WHERE message_id = ?1 AND reactor_identity_id = ?2",
                    params![target_message_id, reactor_identity_id],
                    |row| row.get(0),
                )
                .ok();
            if let Some(prev) = previous {
                if prev as u64 > reacted_at_ms { return true; }
            }
        }
        // A removal stays as a row with an empty emoji: its stamp is what stops
        // an older add, delivered later, from bringing the reaction back.
        match conn.execute(
            "INSERT OR REPLACE INTO message_reactions (message_id, reactor_identity_id, emoji, reacted_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![target_message_id, reactor_identity_id, emoji, reacted_at_ms.min(i64::MAX as u64) as i64],
        ) {
            Ok(_) => true,
            Err(e) => { error!("Tepki yazılamadı: {}", e); false }
        }
    }

    /// False only if `target_message_id` is a row of ANOTHER chat than the one
    /// the reaction claims. An unknown target passes: the message may still be
    /// on its way.
    pub(crate) fn reaction_fits_chat(&self, target_message_id: &str, group_id: Option<&str>, sender_identity_id: &str) -> bool {
        let Some(conn) = &self.db else { return true };
        let row: Option<(Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT group_id, peer_device_fingerprint FROM messages WHERE message_id = ?1
                 UNION ALL
                 SELECT group_id, peer_device_fingerprint FROM files WHERE file_id = ?1
                 LIMIT 1",
                params![target_message_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        // Not here yet (the reaction overtook its message): allowed, but not
        // under an id of any length.
        // And not without end: each invented id left a row for good.
        // ponytail: scans the reactor's rows; index reactor_identity_id if the table grows.
        let Some((row_group, row_peer)) = row else {
            let pending: i64 = conn.query_row(
                "SELECT COUNT(*) FROM message_reactions r WHERE r.reactor_identity_id = ?1
                   AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.message_id = r.message_id)
                   AND NOT EXISTS (SELECT 1 FROM files f WHERE f.file_id = r.message_id)",
                params![sender_identity_id], |r| r.get(0),
            ).unwrap_or(0);
            return target_message_id.len() <= 128 && pending < 64;
        };
        match (row_group.filter(|g| !g.is_empty()), group_id) {
            (Some(g), Some(claimed)) => g == claimed,
            (None, None) => row_peer
                .and_then(|fp| self.identity_id_for_device(&fp))
                .as_deref() == Some(sender_identity_id),
            _ => false,
        }
    }

    /// Bir mesajın tepkilerinin gösterime hazır özeti — ör. `"👍2 ❤️"`.
    /// Tek kişilik bir tepkide sayı YAZILMAZ (WhatsApp deseni). Sıralama
    /// önce adede, sonra emojiye göre — böylece aynı veri her cihazda AYNI
    /// dizeyi üretir.
    pub(crate) fn reactions_summary(&self, target_message_id: &str) -> String {
        let Some(conn) = &self.db else { return String::new() };
        let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        if let Ok(mut stmt) = conn.prepare("SELECT emoji FROM message_reactions WHERE message_id = ?1 AND emoji != ''") {
            if let Ok(rows) = stmt.query_map(params![target_message_id], |row| row.get::<_, String>(0)) {
                for emoji in rows.flatten() {
                    *counts.entry(emoji).or_insert(0) += 1;
                }
            }
        }
        if counts.is_empty() { return String::new() }
        let mut pairs: Vec<(String, u32)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        pairs
            .iter()
            .map(|(emoji, n)| if *n > 1 { format!("{}{}", emoji, n) } else { emoji.clone() })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Spec dışı, kullanıcı isteği ("tepki pill'ine tıklayınca kim ne atmış
    /// gösteren bir liste açılsın"): bir mesajın tepkilerini KİŞİ BAZINDA
    /// döner — `[{"identity_id": "...", "emoji": "👍"}, ...]`.
    ///
    /// `reactions_summary` bilerek yalnızca toplamları veriyor (balonun
    /// yanındaki pill için); burada kimin ne attığı gerektiğinden ayrı bir
    /// okuma var. En yeni tepki en üstte — WhatsApp da böyle sıralıyor.
    pub(crate) fn list_reactions(&self, target_message_id: &str) -> String {
        let Some(conn) = &self.db else { return "[]".to_string() };
        let mut out = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT reactor_identity_id, emoji FROM message_reactions
             WHERE message_id = ?1 AND emoji != '' ORDER BY reacted_at_ms DESC"
        ) {
            if let Ok(rows) = stmt.query_map(params![target_message_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                // `is_me`: "Sen" etiketini Kotlin tarafında hesaplamak için
                // orada kendi `identity_id`'mizi bilmek gerekirdi ve onu
                // veren bir JNI yok. Karşılaştırmayı zaten kimliğe sahip
                // olan burada yapmak hem doğru yer hem de yeni bir API
                // yüzeyi açmıyor.
                let own = self.identity.as_ref().map(|i| i.identity_id.as_str()).unwrap_or("");
                for (identity_id, emoji) in rows.flatten() {
                    let is_me = identity_id == own;
                    out.push(serde_json::json!({
                        "identity_id": identity_id, "emoji": emoji, "is_me": is_me
                    }));
                }
            }
        }
        serde_json::to_string(&out).unwrap_or_else(|_| "[]".to_string())
    }

    /// bkz. `message_seen` tablosu dokümantasyonu — bir "görüldü" bildirimi
    /// alındığında (1:1 VEYA grup, `message_id` her iki durumda da AYNI
    /// kolon/anlam, bkz. `load_message_history`/`load_group_message_history`)
    /// kalıcı olarak yazar. `apply_reaction` ile AYNI sırasız-teslim koruması:
    /// daha eski bir damga, aynı görüntüleyenin daha yeni kaydının üzerine
    /// YAZMAZ.
    /// `viewer`, BENİM gönderdiğim `message_id`'yi görmüş olabilir mi? 1:1'de
    /// mesajın karşı tarafı, grupta o grubun üyesi olmalı — aksi halde
    /// herhangi bir kişi başka sohbetlerdeki mesajlarımı "gördü" diye
    /// işaretleyebilirdi.
    pub(crate) fn may_mark_seen(&self, message_id: &str, viewer_identity_id: &str) -> bool {
        let Some(conn) = &self.db else { return false };
        let row: Option<(Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT group_id, peer_device_fingerprint FROM messages
                 WHERE message_id = ?1 AND direction = 'sent'
                 UNION ALL
                 SELECT group_id, peer_device_fingerprint FROM files
                 WHERE file_id = ?1 AND direction = 'sent'
                 LIMIT 1",
                params![message_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        match row {
            Some((Some(gid), _)) if !gid.is_empty() => {
                self.groups.get(&gid).map_or(false, |g| g.is_member(viewer_identity_id))
            }
            Some((_, Some(fp))) => self.identity_id_for_device(&fp).as_deref() == Some(viewer_identity_id),
            _ => false,
        }
    }

    pub(crate) fn apply_seen_receipt(&self, message_id: &str, viewer_identity_id: &str, seen_at_ms: u64) {
        let Some(conn) = &self.db else { return };
        if seen_at_ms > 0 {
            let previous: Option<i64> = conn
                .query_row(
                    "SELECT seen_at_ms FROM message_seen WHERE message_id = ?1 AND viewer_identity_id = ?2",
                    params![message_id, viewer_identity_id],
                    |row| row.get(0),
                )
                .ok();
            if let Some(prev) = previous {
                if prev as u64 > seen_at_ms { return; }
            }
        }
        let _ = conn.execute(
            "INSERT OR REPLACE INTO message_seen (message_id, viewer_identity_id, seen_at_ms) VALUES (?1, ?2, ?3)",
            params![message_id, viewer_identity_id, seen_at_ms as i64],
        );
    }

    /// bkz. `ArchivedMessage.seen_by` — bir mesajı kimlerin gördüğü, her
    /// geçmiş satırına GÖMÜLECEK şekilde `list_reactions` ile AYNI JSON
    /// şekli (`[{"identity_id":..,"seen_at_ms":..}]`). En ÖNCE gören en
    /// üstte (WhatsApp'ın grup okundu listesiyle aynı sıralama hissi).
    pub(crate) fn seen_by_json(&self, message_id: &str) -> String {
        if message_id.is_empty() { return "[]".to_string() }
        let Some(conn) = &self.db else { return "[]".to_string() };
        let mut out = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT viewer_identity_id, seen_at_ms FROM message_seen
             WHERE message_id = ?1 ORDER BY seen_at_ms ASC"
        ) {
            if let Ok(rows) = stmt.query_map(params![message_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for (identity_id, seen_at_ms) in rows.flatten() {
                    out.push(serde_json::json!({
                        "identity_id": identity_id, "seen_at_ms": seen_at_ms
                    }));
                }
            }
        }
        serde_json::to_string(&out).unwrap_or_else(|_| "[]".to_string())
    }

    /// Spec dışı, kullanıcı isteği: 1:1 sohbette bir mesaja tepki bırakır
    /// (boş `emoji` = kendi tepkimi kaldır). `edit_message` ile AYNI dört
    /// adımlı desen: karşı tarafa gönder, kişinin diğer cihazlarına fan-out,
    /// yerel arşive uygula, kendi kardeş cihazlarıma yankıla.
    pub(crate) fn react_to_message(&mut self, peer_device_fingerprint: String, target_message_id: String, emoji: String) -> Result<String, String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        // Tek damga, tüm kopyalarda AYNI — bkz. `edit_message` aynı gerekçe.
        let reacted_at_ms = current_time_ms();
        let content = MessageContent::Reaction {
            target_message_id: target_message_id.clone(),
            emoji: emoji.clone(),
            group_id: None,
            reacted_at_ms,
        };
        // Not applied locally if nothing could even be queued for the peer.
        self.send_message_content(peer_device_fingerprint.clone(), &content, None)?;
        self.fanout_extra_copies(&peer_device_fingerprint, &content);
        self.apply_reaction(&target_message_id, &own_identity_id, &emoji, reacted_at_ms);
        self.requeue_archive_row(None, &peer_device_fingerprint, &target_message_id);
        self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::Reaction {
            target_message_id: target_message_id.clone(), emoji, reacted_at_ms,
        });
        Ok(self.reactions_summary(&target_message_id))
    }

    /// bkz. `react_to_message` — grup karşılığı (`edit_group_message` ile
    /// AYNI fan-out deseni).
    pub(crate) fn react_to_group_message(&mut self, group_id: String, target_message_id: String, emoji: String) -> Result<String, String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        let reacted_at_ms = current_time_ms();
        let content = MessageContent::Reaction {
            target_message_id: target_message_id.clone(),
            emoji: emoji.clone(),
            group_id: Some(group_id.clone()),
            reacted_at_ms,
        };
        for member_identity_id in group.other_members(&own_identity_id) {
            self.send_group_message_to_member(&group_id, &member_identity_id, &content);
        }
        self.apply_reaction(&target_message_id, &own_identity_id, &emoji, reacted_at_ms);
        self.requeue_archive_row(Some(&group_id), "", &target_message_id);
        self.echo_group_to_siblings(&group_id, SiblingEchoBody::Reaction {
            target_message_id: target_message_id.clone(), emoji, reacted_at_ms,
        });
        Ok(self.reactions_summary(&target_message_id))
    }

    /// Spec dışı: bir mesajı düzenler. `target_message_id`, düzenlenecek
    /// mesajın `MessagePacketHeader.message_id`'sidir (gönderirken dönen
    /// değer). Karşı taraf, bu `message_id`'ye sahip bir mesajı daha önce
    /// gördüyse UI'da güncellemelidir (bkz. ChatActivity).
    pub(crate) fn edit_message(&mut self, peer_device_fingerprint: String, target_message_id: String, new_text: String) -> Result<(String, String), String> {
        // Sıra-dışı Edit koruması (bkz. `apply_edit_to_archive`): tüm
        // kopyalar (karşı tarafa giden paket, çoklu-cihaz fan-out, kardeş
        // yankısı ve yerel arşiv) AYNI damgayı taşımalı ki her cihaz aynı
        // sıralama kararını versin — bu yüzden BİR KEZ üretilip paylaşılır.
        let edited_at_ms = current_time_ms();
        let content = MessageContent::Edit { target_message_id: target_message_id.clone(), new_text: new_text.clone(), group_id: None, edited_at_ms, author_proof: None };
        // `?` first: an edit that could not even be queued must not show as
        // done here and on the siblings while the peer keeps the old text.
        let result = Ok(self.send_message_content(peer_device_fingerprint.clone(), &content, None)?);
        self.fanout_extra_copies(&peer_device_fingerprint, &content);
        self.apply_edit_to_archive(None, &peer_device_fingerprint, &target_message_id, &new_text, edited_at_ms);
        self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::Edit {
            target_message_id: target_message_id.clone(), new_text: new_text.clone(), edited_at_ms,
        });
        result
    }

    /// Spec dışı: bir mesajı siler (karşı tarafa "sil" bildirimi gönderir).
    /// Also purges the local attachment file, if any (see `purge_attachment_if_exists`).
    /// Deleting a message that is still queued withdraws every copy that has
    /// not been confirmed (peer devices, siblings, server deposits). Without
    /// this the text was still delivered, notification and all, and only
    /// then deleted. The Delete itself still goes out for copies that did
    /// arrive.
    pub(crate) fn withdraw_unsent(&mut self, target_message_id: &str) {
        let ids: Vec<String> = self.awaiting_confirmation.iter()
            .filter(|(id, p)| id.as_str() == target_message_id || match &p.regen_content {
                Some(MessageContent::Text { group_message_local_id: Some(g), .. }) => g == target_message_id,
                Some(MessageContent::SiblingEcho { body: SiblingEchoBody::Text { message_id, .. }, .. }) => message_id == target_message_id,
                _ => false,
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.awaiting_confirmation.remove(&id);
            self.remove_durable_retry(&id);
            self.cancel_server_deposit(&id);
        }
        // Copies still waiting for an unresolved member device. Only the
        // Text row itself (`group_row_id`); queued Edit/Delete entries stay.
        for queue in self.pending_group_messages.values_mut() {
            queue.retain(|c| group_row_id(c) != Some(target_message_id));
        }
        self.pending_group_messages.retain(|_, q| !q.is_empty());
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM pending_group_messages WHERE local_message_id = ?1",
                params![target_message_id],
            );
        }
    }

    pub(crate) fn delete_message(&mut self, peer_device_fingerprint: String, target_message_id: String) -> Result<(String, String), String> {
        let content = MessageContent::Delete { target_message_id: target_message_id.clone(), group_id: None, author_proof: None };
        // `?` first, like `edit_message`: nothing is deleted here unless the
        // delete could at least be queued for the peer.
        let result = Ok(self.send_message_content(peer_device_fingerprint.clone(), &content, None)?);
        self.withdraw_unsent(&target_message_id);
        self.fanout_extra_copies(&peer_device_fingerprint, &content);
        self.purge_attachment_if_exists(&target_message_id);
        self.apply_delete_to_archive(None, &peer_device_fingerprint, &target_message_id);
        self.echo_1to1_to_siblings(&peer_device_fingerprint, SiblingEchoBody::Delete {
            target_message_id: target_message_id.clone(),
        });
        result
    }

    /// Spec dışı, kullanıcı isteği: `edit_message`'ın grup karşılığı — bkz.
    /// `send_group_message`/`request_older_group_history` AYNI fan-out
    /// deseni. `target_group_message_local_id`, düzenlenecek grup mesajının
    /// `Text.group_message_local_id`'sidir (Kotlin zaten kendi balonunun
    /// `messageId`'si olarak BUNU kullanıyor, bkz. GroupChatActivity notu).
    pub(crate) fn edit_group_message(&mut self, group_id: String, target_group_message_local_id: String, new_text: String) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        // bkz. `edit_message` — tüm kopyalar aynı sıralama damgasını taşır.
        let edited_at_ms = current_time_ms();
        let content = MessageContent::Edit {
            target_message_id: target_group_message_local_id.clone(),
            new_text: new_text.clone(),
            group_id: Some(group_id.clone()),
            edited_at_ms,
            author_proof: Some(self.sign_group_author(&group_id, &target_group_message_local_id, &new_text)?),
        };
        let others = group.other_members(&own_identity_id);
        let mut sent_to_any = others.is_empty(); // alone in the group: nobody to tell
        for member_identity_id in others {
            if self.send_group_message_to_member(&group_id, &member_identity_id, &content) {
                sent_to_any = true;
            }
        }
        if !sent_to_any {
            return Err("Ulaşılabilir grup üyesi yok".to_string());
        }
        self.apply_edit_to_archive(Some(&group_id), "", &target_group_message_local_id, &new_text, edited_at_ms);
        self.echo_group_to_siblings(&group_id, SiblingEchoBody::Edit {
            target_message_id: target_group_message_local_id.clone(), new_text: new_text.clone(), edited_at_ms,
        });
        Ok(())
    }

    /// bkz. `edit_group_message` aynı notu — `delete_message`'ın grup
    /// karşılığı. Also purges the local attachment file, if any.
    pub(crate) fn delete_group_message(&mut self, group_id: String, target_group_message_local_id: String) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        let tombstone = self.sign_group_author(&group_id, &target_group_message_local_id, GROUP_TOMBSTONE)?;
        let content = MessageContent::Delete {
            target_message_id: target_group_message_local_id.clone(),
            group_id: Some(group_id.clone()),
            author_proof: Some(tombstone.clone()),
        };
        let others = group.other_members(&own_identity_id);
        let mut sent_to_any = others.is_empty(); // alone in the group: nobody to tell
        for member_identity_id in others {
            if self.send_group_message_to_member(&group_id, &member_identity_id, &content) {
                sent_to_any = true;
            }
        }
        if !sent_to_any {
            return Err("Ulaşılabilir grup üyesi yok".to_string());
        }
        self.withdraw_unsent(&target_group_message_local_id);
        self.purge_attachment_if_exists(&target_group_message_local_id);
        self.apply_delete_to_archive(Some(&group_id), "", &target_group_message_local_id);
        self.adopt_group_author_proof(&group_id, &target_group_message_local_id, Some(&tombstone));
        self.echo_group_to_siblings(&group_id, SiblingEchoBody::Delete {
            target_message_id: target_group_message_local_id.clone(),
        });
        Ok(())
    }
}

impl P2PCore {

    /// bkz. `MessageContent::Ack` dokümantasyonu (packet.rs) — Text (grup
    /// dışı)/Edit/Delete/HistorySyncRequest başarıyla işlendiğinde
    /// gönderene geri gönderilir. Fire-and-forget: bu çağrının kendisi
    /// `send_message_content`'in normal (kısa süreli, `pending_envelopes`
    /// tabanlı) yolundan geçer — Ack'in KENDİSİ `awaiting_confirmation`'a
    /// eklenmez (sonsuz döngü riski, bkz. packet.rs notu). Kaybolursa
    /// göndericinin yeniden denemesi `reack_if_already_handled`'a düşer.
    pub(crate) fn send_ack(&mut self, peer_device_fingerprint: &str, target_message_id: &str) {
        let now = current_time_ms();
        if self.recently_acked.len() >= RECENTLY_ACKED_MAX_ENTRIES {
            self.recently_acked.retain(|_, (_, at)| now.saturating_sub(*at) < MAX_UNCONFIRMED_AGE_MS);
            if self.recently_acked.len() >= RECENTLY_ACKED_MAX_ENTRIES {
                // Drop the busiest peer's entries, not everyone's: one
                // flooding contact no longer wipes the re-ack memory of all.
                let mut per_peer: HashMap<&str, usize> = HashMap::new();
                for (peer, _) in self.recently_acked.values() {
                    *per_peer.entry(peer.as_str()).or_default() += 1;
                }
                let busiest = per_peer.into_iter().max_by_key(|(_, n)| *n).map(|(p, _)| p.to_string());
                if let Some(busiest) = busiest {
                    self.recently_acked.retain(|_, (peer, _)| *peer != busiest);
                }
            }
        }
        self.recently_acked.insert(target_message_id.to_string(), (peer_device_fingerprint.to_string(), now));
        let queue = self.outbound_acks.entry(peer_device_fingerprint.to_string()).or_default();
        if !queue.iter().any(|id| id == target_message_id) {
            queue.push(target_message_id.to_string());
        }
    }

    /// Bir Ack'i uygular (şifreli `MessageContent::Ack` ya da `AckBatchRequest`).
    /// Bekleyen paket GERÇEKTEN bu eşe kuyruklanmış olmalı — aksi halde herhangi
    /// bir eş, bilinen bir `message_id` ile başka bir eşe giden bekleyen paketi
    /// sahte Ack'le iptal edebilirdi. `None` = uygulanmadı.
    pub(crate) fn apply_incoming_ack(&mut self, peer_fp: &str, target_message_id: &str) -> Option<serde_json::Value> {
        let owned_by_this_peer = self.awaiting_confirmation.get(target_message_id)
            .map(|p| p.peer_device_fingerprint == peer_fp)
            .unwrap_or(false);
        if !owned_by_this_peer {
            return None;
        }
        let regen_content = self.awaiting_confirmation.get(target_message_id)
            .and_then(|p| p.regen_content.clone());
        self.awaiting_confirmation.remove(target_message_id);
        self.remove_durable_retry(target_message_id);
        // Acked over one path while a copy is still out on another: forget
        // the copy. Its late failure took it for an untracked envelope,
        // queued it, and the queue then reported "sent" or "error" for a
        // message the peer already has.
        let acked = |e: &NetworkEnvelope| matches!(e, NetworkEnvelope::Message(m) if m.header.message_id == target_message_id);
        self.envelopes_inflight.retain(|_, (_, e, _, _)| !acked(e));
        self.pending_envelopes.retain(|q| !acked(&q.envelope));
        // #85: a text acked by a device of the peer (not one of our siblings)
        // is delivered. The bubble id is the conversation-wide id the copies
        // to every device share.
        if let Some(MessageContent::Text { group_id, group_message_local_id, .. }) = &regen_content {
            let from_peer = self.known_remote_devices.get(peer_fp)
                .map_or(true, |d| self.my_identity_id().as_deref() != Some(d.identity_id.as_str()));
            let bubble_id = group_message_local_id.clone().unwrap_or_else(|| target_message_id.to_string());
            let changed = from_peer && self.db.as_ref().map_or(false, |c| c.execute(
                "UPDATE messages SET status = 'delivered' WHERE message_id = ?1 AND direction = 'sent' AND status != 'delivered'",
                params![bubble_id],
            ).map_or(false, |n| n > 0));
            if changed {
                // 1:1: the chat's canonical device, as the bubble's screen knows it.
                let peer = if group_id.is_some() { peer_fp.to_string() } else { self.canonical_peer_key(peer_fp) };
                let mut ev = serde_json::json!({
                    "type": "status", "peer": peer, "message_id": bubble_id,
                    "status": MessageSendStatus::Delivered.as_str(),
                });
                if let Some(gid) = group_id {
                    ev["group_id"] = serde_json::Value::String(gid.clone());
                }
                self.attachment_events.push(ev.to_string());
            }
        }
        let (event_message_id, event_group_id) = match &regen_content {
            Some(MessageContent::Edit { target_message_id: real_target, group_id, .. }) =>
                (real_target.clone(), group_id.clone()),
            Some(MessageContent::Delete { target_message_id: real_target, group_id, .. }) =>
                (real_target.clone(), group_id.clone()),
            // The UI knows a file bubble by `file_id`, not by the packet id.
            Some(MessageContent::FileOffer { file_id, group_id, .. }) =>
                (file_id.clone(), group_id.clone()),
            _ => (target_message_id.to_string(), None),
        };
        Some(match event_group_id {
            Some(gid) => serde_json::json!({"type": "ack", "peer": peer_fp, "group_id": gid, "message_id": event_message_id}),
            // 1:1: keyed like the chat screen, see the `status` event above.
            None => serde_json::json!({"type": "ack", "peer": self.canonical_peer_key(peer_fp), "message_id": event_message_id}),
        })
    }

    /// Ack'in şifreli paket yolu — bağlantı yokken ya da toplu istek
    /// başarısız olunca (bkz. `ACK_PROTOCOL`). Sunucu açıksa oraya bırakılır.
    pub(crate) fn send_ack_message(&mut self, peer_device_fingerprint: &str, target_message_id: &str) {
        let content = MessageContent::Ack { target_message_id: target_message_id.to_string() };
        if let Err(e) = self.send_message_content(peer_device_fingerprint.to_string(), &content, None) {
            error!("Ack gönderilemedi: {}", e);
        }
    }

    /// `send_ack` kuyruğunu boşaltır: canlı bağlantısı olan eşe tek bir
    /// `AckBatchRequest`, olmayana şifreli Ack paketleri. `poll_events`
    /// sonunda çağrılır, yani o turda üretilen Ack'ler aynı turda çıkar.
    pub(crate) fn flush_outbound_acks(&mut self) {
        if self.outbound_acks.is_empty() {
            return;
        }
        let queued = std::mem::take(&mut self.outbound_acks);
        for (fp, ids) in queued {
            let connected_peer = self.device_to_peer_id.get(&fp).copied()
                .filter(|p| self.swarm.as_ref().map_or(false, |s| s.is_connected(p)));
            match (connected_peer, self.swarm.as_mut()) {
                (Some(peer), Some(swarm)) => {
                    info!("Ack: {} adet toplu istekle (peer={})", ids.len(), crate::log_id(&fp));
                    for chunk in ids.chunks(ACK_BATCH_MAX) {
                        let request_id = swarm.behaviour_mut().acks.send_request(&peer, AckBatchRequest { ids: chunk.to_vec() });
                        self.ack_batches_inflight.insert(request_id, (fp.clone(), chunk.to_vec()));
                    }
                }
                _ => {
                    info!("Ack: {} adet şifreli paketle, canlı bağlantı yok (peer={})", ids.len(), crate::log_id(&fp));
                    for id in &ids {
                        self.send_ack_message(&fp, id);
                    }
                }
            }
        }
    }

    /// Tekrar gelen (çözülemeyen ya da bayt-aynısı) bir `Message` için: bu
    /// paketi daha önce işleyip Ack'lediysek Ack'i yeniden yolla. Gönderen
    /// ancak Ack'imiz ona ulaşmadıysa yeniden dener, yani bu kayıp Ack'i
    /// telafi eder. Arşiv kontrolü süreç yeniden başlasa da kalıcı mesajları
    /// kapsar; `recently_acked` arşive yazılmayan türleri (ReadStateSync,
    /// SiblingEcho, GroupUpdate...) kapsar. İmza çağıranda zaten doğrulandı;
    /// gönderen de eşleşmeli.
    /// Ack for a Text, and a durable note of the packet id when the row is
    /// archived under ANOTHER id (group texts and fan-out copies use the
    /// conversation-wide id). `reack_if_already_handled` finds a replayed
    /// packet by its packet id; after a restart `recently_acked` is empty and
    /// the row lookup missed these, so the sender resent for ~25 min.
    pub(crate) fn ack_text_packet(&mut self, peer_fp: &str, packet_id: &str, archived_as: Option<&str>) {
        self.send_ack(peer_fp, packet_id);
        if archived_as == Some(packet_id) {
            return;
        }
        if let Some(conn) = &self.db {
            let now = current_time_ms() as i64;
            // Pruned in `periodic_storage_sweep`, not per ack (fable A-14).
            let _ = conn.execute("INSERT OR REPLACE INTO acked_packets (packet_id, acked_at) VALUES (?1, ?2)", params![packet_id, now]);
        }
    }

    pub(crate) fn packet_was_acked(&self, packet_id: &str) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row("SELECT 1 FROM acked_packets WHERE packet_id = ?1", params![packet_id], |_| Ok(())).is_ok()
        })
    }

    pub(crate) fn reack_if_already_handled(&mut self, header: &MessagePacketHeader) -> bool {
        let peer = header.sender_device_fingerprint.clone();
        let mid = header.message_id.clone();
        let recent = self.recently_acked.get(&mid)
            .map_or(false, |(p, at)| *p == peer && current_time_ms().saturating_sub(*at) < MAX_UNCONFIRMED_AGE_MS);
        if !recent && !self.received_from_sender(&mid, &peer) && !self.packet_was_acked(&mid) {
            return false;
        }
        // L-21: one re-ack per id per 5 s. The sender's retries are 15 s
        // apart or more; faster copies are replays (or the same packet over
        // another path), and each re-ack costs an encrypt + sign + send.
        let just_acked = self.recently_acked.get(&mid)
            .map_or(false, |(p, at)| *p == peer && current_time_ms().saturating_sub(*at) < 5_000);
        if just_acked {
            return true;
        }
        self.send_ack(&peer, &mid);
        true
    }

    /// Spec dışı, kullanıcı tarafından istenen "görüldü" bildirimi —
    /// `send_ack` ile AYNI desen (bkz. packet.rs `Seen` notu). `Ack`'in
    /// aksine OTOMATİK değil: Kotlin tarafı, mesajı kullanıcıya EKRANDA
    /// gösterdiği anda çağırmalı (bkz. ChatActivity/GroupChatActivity).
    pub(crate) fn send_seen(&mut self, peer_device_fingerprint: &str, target_message_id: &str, group_message_local_id: Option<String>) -> bool {
        let content = MessageContent::Seen {
            target_message_id: target_message_id.to_string(),
            group_message_local_id,
        };
        match self.send_message_content(peer_device_fingerprint.to_string(), &content, None) {
            Ok(_) => true,
            Err(e) => {
                error!("Görüldü bildirimi gönderilemedi: {}", e);
                false
            }
        }
    }

    /// Spec dışı: "yazıyor..." göstergesi. bkz. `MessageContent::TypingIndicator`
    /// dokümantasyonu (packet.rs) — arşivlenmez, güvenilir teslim
    /// kuyruğuna girmez, fire-and-forget.
    pub(crate) fn send_typing_indicator(&mut self, peer_device_fingerprint: String, is_typing: bool) -> Result<(), String> {
        // Canlı bağlantı yoksa hiç gönderme: aksi halde sunucuya bırakılıyor
        // ve alıcı dakikalar sonra bayat bir "yazıyor" çekiyordu (cihazda
        // ölçüldü: çevrimdışı alıcıya her metinle birlikte 2 × ~8 KB).
        // No session: sending would start a handshake just for "typing".
        if !self.is_connected_to_device(&peer_device_fingerprint) || !self.has_active_session(&peer_device_fingerprint) {
            return Ok(());
        }
        let content = MessageContent::TypingIndicator { is_typing, group_id: None };
        self.send_message_content(peer_device_fingerprint, &content, None).map(|_| ())
    }

    /// Bu cihazla şu an canlı bir libp2p bağlantısı var mı (LAN, Tor, röle).
    pub(crate) fn is_connected_to_device(&self, device_fingerprint: &str) -> bool {
        self.device_to_peer_id.get(device_fingerprint)
            .map_or(false, |p| self.swarm.as_ref().map_or(false, |s| s.is_connected(p)))
    }

    /// Group version of `send_typing_indicator`, fanned out like
    /// `edit_group_message`/`delete_group_message`. Uses
    /// `resolve_active_device_for_identity` directly instead of the queuing
    /// `send_group_message_to_member` — a stale typing state delivered
    /// minutes later once a device resolves has no value.
    pub(crate) fn send_group_typing_indicator(&mut self, group_id: String, is_typing: bool) -> Result<(), String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(&group_id).cloned_group()?;
        let content = MessageContent::TypingIndicator { is_typing, group_id: Some(group_id.clone()) };
        for member_identity_id in group.other_members(&own_identity_id) {
            if let Some(peer_fp) = self.resolve_active_device_for_identity(&member_identity_id)
                .filter(|fp| self.is_connected_to_device(fp) && self.has_active_session(fp))
            {
                if let Err(e) = self.send_message_content(peer_fp, &content, None) {
                    error!("Grup yazıyor göstergesi bir üyeye gönderilemedi: {}", e);
                }
            }
        }
        Ok(())
    }
}
