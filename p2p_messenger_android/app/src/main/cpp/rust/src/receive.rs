//! `receive_message` and the dispatch of decrypted content.

use super::*;

impl P2PCore {

    pub(crate) fn receive_message(&mut self, source: Option<PeerId>, packet: &MessagePacket) -> Result<String, String> {
        let sender = self.known_remote_devices.get(&packet.header.sender_device_fingerprint).cloned()
            .ok_or("Unknown sender device; cannot verify signatures")?;
        // bkz. process_handshake_init aynı notu — güvenlik denetimi
        // düzeltmesi, artık gerçekten uygulanıyor.
        if !sender.is_active {
            self.answer_revoked_sibling(&sender.device_fingerprint);
            return Err("Sender device has been revoked".to_string());
        }

        // imza SADECE bu paketi `sender` CİHAZININ imzaladığını kanıtlar —
        // header'daki `sender_identity_id` alanının o cihaza AİT güvenilen
        // Identity olduğunu KANITLAMAZ. Cihaz→Identity bağı eşleşme (TOFU)
        // anında kaydedilir (`DeviceRecord.identity_id`); header'daki
        // değerin bununla eşleştiğini burada zorlamazsak, eşleşmiş bir cihaz
        // header'a BAŞKA bir kişinin identity_id'sini yazıp grup mesajlarında
        // o kişiyi taklit edebilir (bkz. group_message kolu) VEYA bir
        // `ProfileUpdate`'i başka bir kişiye yönlendirip onun avatarını
        // ezebilir (bkz. ProfileUpdate kolu — `identity_to_contact` lookup'ı
        // bu alana güveniyordu). Artık uyuşmazlık paketi tamamen reddediyor.
        if packet.header.sender_identity_id != sender.identity_id {
            return Err("sender_identity_id, imzalayan cihazın kayıtlı kimliğiyle eşleşmiyor".to_string());
        }

        let to_verify = packet_signing_input(packet.header.raw(), &packet.ciphertext, &self.get_active_own_device_fingerprint()?);
        verify_hybrid_signature(&to_verify, &packet.signature_classical, &packet.signature_pq, &sender)?;


        // Rotasyon senkronizasyonu (spec 3.2, artık gerçek): gönderen bu
        // mesajla birlikte bir DH/KEM rotasyonu tetiklediyse
        // (rotation_kyber_ciphertext dolu), biz de kendi tarafımızda aynı
        // yeni anahtarları türetmek için respond_to_rotation çağırırız.
        // Boşsa (normal mesaj, rotasyon yok) hiçbir şey yapmayız —
        // ratchet_pubkey zaten her mesajda taşınır ama rotasyon olmadıkça
        // değişmez, bu yüzden onu görmezden gelmek güvenlidir.
        // The ratchet applies the rotation only if the packet then decrypts
        // on the new chain (bkz. ratchet.rs `decrypt`). Başlık alıcıya bağlı
        // değil: A'nın B'ye gönderdiği rotasyonlu paket C'ye tekrar
        // oynatılırsa, önce uygulanan rotasyon C'nin A oturumunu bozardı.
        // The packet's rotation was applied: the state is written at once.
        let rotated;
        // Rollback copy: if the advanced state cannot be saved, memory goes
        // back to it and the packet fails (no archive, no Ack), so the
        // sender's retry decrypts again instead of being lost.
        let mut snapshot: Option<DeviceRatchetState>;
        let decrypted = {
            let state = self.ratchets.get_mut(&packet.header.sender_device_fingerprint)
                .ok_or("No ratchet session for sender")?;
            snapshot = Some(state.clone());
            let new_peer_keys = packet.header.rotation_kyber_ciphertext.as_ref()
                .and_then(|_| RatchetPublicKeys::from_bytes(&packet.header.ratchet_pubkey).ok());
            let rotation = new_peer_keys.as_ref().zip(packet.header.rotation_kyber_ciphertext.as_deref());
            let result = state.decrypt(&packet.ciphertext, packet.header.message_number, rotation, current_time_ms(), packet.header.raw());
            rotated = result.as_ref().map_or(false, |(_, changes)| changes.rotated);
            result
        };
        if rotated {
            // Eski topic hemen bırakılmaz (gönderen hâlâ oradan yayınlayabilir),
            // bir sonraki rotasyonda bırakılır.
            // Eski zincirin skipped-key'leri state'in içine taşındı
            // (`old_recv`); bu çözmenin eklediği yeni anahtarlar aşağıda
            // tabloya yazılır. State first: the table rows go only once
            // the state holding them is on disk.
            if !self.persist_ratchet_state(&packet.header.sender_device_fingerprint) {
                if let Some(s) = snapshot.take() {
                    self.ratchets.insert(packet.header.sender_device_fingerprint.clone(), s);
                }
                return Err("Ratchet state could not be saved".to_string());
            }
            // The rotated state is on disk now: a later failure must not roll
            // memory back behind it.
            snapshot = None;
            self.clear_persisted_skipped_keys(&packet.header.sender_device_fingerprint);
            // Eski zincirle şifrelenmiş bekleyen paketler hemen taze zincirle yeniden gönderilir.
            // Not the one this very packet answers: it is closed below, and
            // resent the peer answered it a second time.
            let answered = decrypted.as_ref().ok().and_then(|(p, _)| answered_pending_id(p.as_slice()));
            let prev = self.regen_skip_id.clone();
            if answered.is_some() {
                self.regen_skip_id = answered;
            }
            self.regen_pending_for_peer(&packet.header.sender_device_fingerprint);
            self.regen_skip_id = prev;
        }
        let (payload_bytes, skipped_changes) = match decrypted {
            Ok(v) => v,
            Err(e) => {
                // İKİ CİHAZLI GERÇEK TESTTE BULUNDU — "Ack kilitlenmesi".
                // Gözlenen: iki telefon arasında saniyeler arayla, dakikalarca
                // tekrar eden `Message N not found in skipped-key cache
                // (already decrypted, or evicted)` hataları — HER İKİ yönde.
                // Döngü şöyle kuruluyor: AYNI zarf iki kez ulaşıyor (bu kurulumda
                // NORMAL — hem gossipsub hem sunucu aynı anda taşıyor, bkz.
                // `should_shadow_on_gossipsub`). İlk kopya çözülüp arşivleniyor
                // ve Ack gönderiliyor. İkinci kopya geldiğinde ise zincir çoktan
                // ilerlemiş ve o mesaj numarasının skipped-key'i TÜKETİLMİŞ
                // durumda, yani ARTIK ÇÖZÜLEMİYOR. Çözülemeyince `message_id`
                // okunamıyor; okunamayınca dedup edilemiyor; dedup edilemeyince
                // Ack GÖNDERİLEMİYOR. Gönderen onay alamadığı için aynı zarfı
                // yeniden denemeye devam ediyor — ve o zarf da asla
                // çözülemeyeceği için durum kilitleniyor. Ancak
                // `MAX_UNCONFIRMED_AGE_MS` (~25 dk) dolup `regen_content` taze
                // bir ciphertext ürettiğinde kırılıyor: yani 25 dakika boyunca
                // her iki telefon da boşuna imza doğrulama + radyo trafiği
                // yapıyor.
                // Kilidi kırmak için şifre çözmeye gerek YOK: `MessagePacketHeader`
                // imzalı ama ŞİFRELİ DEĞİL (bkz. `send_message_content_inner` —
                // imza `header ‖ ciphertext` üzerine atılır, header düz gider) ve
                // `message_id`'yi açıkça taşır. İmza bu noktada ZATEN doğrulandı,
                // yani bu alan güvenilir. O kimliğe sahip bir mesaj arşivimizde
                // VARSA, bu paketi kanıtlanabilir biçimde daha önce işledik —
                // Ack'i yeniden gönderip göndereni durdurabiliriz.
                // KASITLI OLARAK DAR: yalnızca arşivde GERÇEKTEN bulduğumuzda
                // Ack atıyoruz. Anahtarı gerçekten kaybettiğimiz (önbellek
                // taşması/rotasyon) durumda mesaj arşivde olmaz, Ack atılmaz ve
                // mevcut davranış (25 dk sonra taze şifrelemeyle yeniden deneme)
                // aynen korunur — teslim edilmemiş bir mesajı yanlışlıkla
                // onaylamayız.
                if self.reack_if_already_handled(&packet.header) {
                    info!(
                        "Çözülemeyen paket zaten işlendi (id={}) — yinelenen teslim, Ack yeniden gönderildi (gönderen aksi hâlde ~25 dk boşuna dener)",
                        packet.header.message_id
                    );
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // A number already consumed on the current chain is an old or
                // duplicate packet (e.g. resent after an app restart, when
                // `recently_acked` is empty again), not a sign of diverged sessions.
                // Nor is a packet made before this session was set up or last
                // rotated (`sent_at_ms` is signed): a captured old packet,
                // replayed three times, made us drop the live session, again
                // every two minutes.
                let session_since = self.ratchets.get(&packet.header.sender_device_fingerprint).map_or(0, |s| s.last_rotation);
                if !matches!(e, ratchet::RatchetError::KeyNotFound(_)) && packet.header.sent_at_ms >= session_since {
                    self.note_undecryptable(&packet.header.sender_device_fingerprint);
                }
                return Err(e.to_string());
            }
        };
        // Map the connection only now (security review 2026-09-27): a valid
        // signature proves who WROTE the packet, not who delivered it. Any
        // contact holding an old packet of this device could replay it to get
        // its own PeerId mapped here, then take our direct sends to the device
        // and fake AckBatch receipts for them. A replayed or cross-addressed
        // packet never decrypts.
        self.record_peer_id_if_known(source, &packet.header.sender_device_fingerprint);
        self.undecryptable_from.remove(&packet.header.sender_device_fingerprint);
        let state = self.ratchets.get_mut(&packet.header.sender_device_fingerprint)
            .ok_or("No ratchet session for sender")?;
        // bkz. `pending_rotation_ct` (ratchet.rs): rotasyonu BİZ tetiklediysek,
        // karşı taraftan YENİ zincirde gelen bir paketin çözülmesi onun
        // rotasyonu uyguladığının kanıtıdır — duyuruyu her pakete eklemeyi
        // bırakabiliriz. A packet of the chain before the rotation
        // (`old_chain`) proves nothing: the peer sent it before it knew.
        if !skipped_changes.old_chain && state.pending_rotation_ct.take().is_some() {
            info!(
                "Rotasyon karşı tarafça uygulandı (peer={}) — duyuru tekrarı durduruluyor",
                crate::log_id(&packet.header.sender_device_fingerprint)
            );
        }
        // Skipped-key değişikliklerini diske (Keystore ile şifreli) yansıt.
        // Before the ratchet state: a crash in between must not leave the
        // advanced counter on disk without the keys it skipped.
        let mut saved = true;
        for (msg_num, key) in &skipped_changes.added {
            if let Err(e) = self.persist_skipped_key(&packet.header.sender_device_fingerprint, *msg_num, key) {
                error!("Skipped-key diske yazılamadı: {}", e);
                saved = false;
                break;
            }
        }
        // `decrypt` her çağrıda ck_recv/recv_message_number'ı ilerletir —
        // diskteki kopyayı güncel tut. A failed write rolls memory back and
        // fails the packet: the retry must still find the key it needs.
        if saved {
            saved = self.persist_ratchet_state(&packet.header.sender_device_fingerprint);
        }
        if !saved {
            if let Some(s) = snapshot.take() {
                self.ratchets.insert(packet.header.sender_device_fingerprint.clone(), s);
            }
            return Err("Ratchet state could not be saved".to_string());
        }
        drop(snapshot);
        // Used keys go only after the state that no longer needs them is on disk.
        for msg_num in &skipped_changes.used {
            self.delete_persisted_skipped_key(&packet.header.sender_device_fingerprint, *msg_num);
        }
        // Only now: for a stale device this resends its parked rows, and any
        // send before the state above was on disk could be rolled back to
        // `snapshot`, reusing the message keys it spent.
        self.touch_device_seen(&packet.header.sender_device_fingerprint);

        let peer_fp = packet.header.sender_device_fingerprint.clone();
        let sender_identity_id = packet.header.sender_identity_id.clone();
        let message_id = packet.header.message_id.clone();
        // Parsed only after the ratchet is on disk. A variant this version
        // does not know is acked: a retry can never parse either.
        let content: MessageContent = match MessageContent::from_cbor(payload_bytes.as_slice()) {
            Ok(c) => c,
            Err(e) => {
                warn!("Paket içeriği ayrıştırılamadı (id={}): {}", message_id, e);
                self.send_ack(&peer_fp, &message_id);
                return Ok(serde_json::json!({"type": "noop"}).to_string());
            }
        };
        let mut content = content;
        // The send time as the author sent it, for the revoke check of a group
        // author proof: clamped to now, a future stamp from a device revoked
        // later than now read as "sent before the revoke".
        let signed_sent_at_ms = match &content { MessageContent::Text { sent_at_ms, .. } => *sent_at_ms, _ => 0 };
        clamp_received_times(&mut content, current_time_ms());
        self.dispatch_received_content(source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms)
    }

    /// The decrypted content of a received packet, acted on. Content for a
    /// group we do not hold yet (its GroupUpdate may still be on the way) is
    /// held in memory (`unknown_group_held`) instead of being archived, and
    /// goes through here again, membership checked, once the group is known.
    pub(crate) fn dispatch_received_content(&mut self, source: Option<PeerId>, peer_fp: String, sender_identity_id: String, message_id: String, content: MessageContent, signed_sent_at_ms: u64) -> Result<String, String> {
        let held_gid = match &content {
            MessageContent::Text { group_id: Some(g), .. }
            | MessageContent::FileOffer { group_id: Some(g), .. }
            | MessageContent::Reaction { group_id: Some(g), .. } => Some(g.clone()),
            _ => None,
        };
        if let Some(gid) = held_gid.filter(|g| !self.groups.contains_key(g)) {
            if is_group_id(&gid) && !self.group_removed_locally(&gid) {
                // No Ack: dropped here (cap, age, restart), the sender's retry
                // brings it again.
                let now = current_time_ms();
                self.unknown_group_held.retain(|_, b| {
                    b.retain(|e| now.saturating_sub(e.0) <= UNKNOWN_GROUP_HOLD_TTL_MS);
                    !b.is_empty()
                });
                let room = self.unknown_group_held.contains_key(&gid) || self.unknown_group_held.len() < UNKNOWN_GROUP_HOLD_GROUPS;
                let buf = self.unknown_group_held.get(&gid);
                let dup = buf.map_or(false, |b| b.iter().any(|e| e.4 == message_id));
                let full = buf.map_or(false, |b| b.len() >= UNKNOWN_GROUP_HOLD_PER_GROUP);
                // Per sender and in bytes too, as `buffer_edit_or_delete`: one
                // contact with invented group ids held all slots and up to
                // ~1 GiB of text.
                let held_bytes = |c: &MessageContent| match c {
                    MessageContent::Text { text, .. } => text.len(),
                    MessageContent::FileOffer { preview_jpeg, caption, .. } => preview_jpeg.as_ref().map_or(0, |p| p.len()) + caption.len(),
                    _ => 0,
                };
                let all = self.unknown_group_held.values().flatten();
                let sender_full = all.clone().filter(|e| e.2 == peer_fp).count() >= UNKNOWN_GROUP_HOLD_PER_GROUP;
                let bytes_full = all.map(|e| held_bytes(&e.5)).sum::<usize>() + held_bytes(&content) > 16 * 1024 * 1024;
                if room && !dup && !full && !sender_full && !bytes_full {
                    self.unknown_group_held.entry(gid).or_default()
                        .push((now, source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms));
                }
            } else if is_group_id(&gid) {
                // A group removed here: final until a GroupUpdate adds us
                // again. Acked, as for a contact removed here, or the sender
                // retried it for 7 days.
                self.send_ack(&peer_fp, &message_id);
            }
            return Ok(serde_json::json!({"type": "noop"}).to_string());
        }
        let result = self.dispatch_received_content_inner(source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms);
        self.replay_unknown_group_held();
        result
    }

    /// Replays the held content of every group that is known now (bkz.
    /// `dispatch_received_content`). Each entry is checked like a live one:
    /// a sender that is not a member is refused.
    pub(crate) fn replay_unknown_group_held(&mut self) {
        let ready: Vec<String> = self.unknown_group_held.keys().filter(|g| self.groups.contains_key(*g)).cloned().collect();
        for gid in ready {
            let Some(buf) = self.unknown_group_held.remove(&gid) else { continue };
            for (_, source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms) in buf {
                match self.dispatch_received_content(source, peer_fp, sender_identity_id, message_id, content, signed_sent_at_ms) {
                    Ok(event) => self.attachment_events.push(event),
                    Err(e) => warn!("Tutulan grup paketi işlenemedi (group={}): {}", gid, e),
                }
            }
        }
    }

    pub(crate) fn dispatch_received_content_inner(&mut self, source: Option<PeerId>, peer_fp: String, sender_identity_id: String, message_id: String, content: MessageContent, signed_sent_at_ms: u64) -> Result<String, String> {
        // Çoklu-cihaz: gönderen kişi birden fazla cihaza sahip olabilir —
        // yerel sohbet/arşiv, o kişinin KARARLI kanonik cihazı altında
        // birleşsin (bkz. `canonical_peer_key`). ACK/Seen gibi geri
        // gönderimler yine GERÇEK gönderen `peer_fp`'ye gider (o cihazla
        // kurulu ratchet üzerinden); yalnızca yerel arşiv anahtarı + UI'ye
        // giden "peer" alanı kanonikleşir. Tek cihazlı kişilerde
        // `chat_key == peer_fp` (davranış değişmez).
        let chat_key = self.canonical_peer_key(&peer_fp);

        // Spec dışı: `pollNetwork`'ün Kotlin tarafına döndürdüğü her satır
        // artık düz metin DEĞİL, `{"type":...}` etiketli bir JSON olayı —
        // bkz. P2PService/ChatActivity. Bu, edit/delete'i aynı String
        // kanalından (JNI imzasını değiştirmeden) taşıyabilmek ve mesajın
        // HANGİ karşı tarafa (peer) ait olduğunu iletebilmek için gerekli —
        // önceden bu bilgi hiç taşınmıyordu (bkz. eski "cross-chat sızıntısı"
        // notu: birden çok sohbet varken gelen her mesaj, o an açık olan
        // HANGİ ChatActivity ise ona ekleniyordu, doğru olanına değil).
        let event = match content {
            MessageContent::Text { group_id: None, text, group_message_local_id, sent_at_ms, reply_to_message_id, reply_to_preview, .. } => {
                // Çoklu-cihaz (spec 1.7.1): KARARLI konuşma kimliği — varsa
                // `group_message_local_id` (gönderenin tüm fan-out kopyalarında
                // AYNI), yoksa (eski sürüm göndericisi) paket başlığındaki id.
                // Arşiv/UI/düzenleme/silme/görüldü hepsi bunu kullanır; ACK ise
                // paketin KENDİ `message_id`'sini kullanır (per-cihaz teslim).
                let display_id = group_message_local_id.clone().unwrap_or_else(|| message_id.clone());
                // Güvenilirlik düzeltmesi (çift arşiv): AYNI mantıksal mesaj
                // ikinci kez gelebilir — `regen_content` tazelemesi kayıp bir
                // Ack'ten sonra AYNI kimlikle TAZE (çözülebilir) bir
                // ciphertext yollar; restart sonrası kalıcı kuyruk da aynı
                // şekilde yeniden gönderir. Önceden bu kol hiç dedup
                // yapmadığından her tekrar ayrı bir arşiv satırı oluşturuyordu
                // (UI ekranda maskeliyordu ama arşiv/geçmiş senkronu çiftleri
                // taşımaya devam ediyordu). Ack YİNE gönderilir — gönderenin
                // yeniden denemesi ancak böyle durur.
                info!("Metin alındı: id={} kaynak={}", display_id.chars().take(8).collect::<String>(), if source.is_some() { "p2p" } else { "sunucu" });
                if self.message_exists_in_chat(&display_id, None, &chat_key) {
                    self.ack_text_packet(&peer_fp, &message_id, Some(&display_id));
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // bkz. send_message_content'teki aynı düzeltme notu —
                // artık node modundan bağımsız her cihaz kendi geçmişini
                // yerelde şifreli tutuyor.
                // Ack sadece arşive KALICI olarak yazılabildiyse gönderilir
                // — aksi halde (disk dolu/DB hatası gibi geçici bir arıza)
                // gönderen tarafa "aldım, artık tekrar deneme" denmiş
                // olurdu ama mesaj hiçbir yerde kalıcı değil; Ack
                // gönderilmezse gönderenin `awaiting_confirmation` mekanizması
                // (bkz. o alanın dokümantasyonu) otomatik olarak tekrar dener.
                match self.archive_message(&chat_key, "received", text.as_bytes(), Some(&display_id), None, reply_to_message_id.as_deref(), reply_to_preview.as_deref(), sent_at_ms) {
                    Ok(()) => {
                        self.ack_text_packet(&peer_fp, &message_id, Some(&display_id));
                        // bkz. `pending_edits_deletes` dokümantasyonu — bu
                        // Text'ten ÖNCE gelmiş (gossipsub sırasızlığı) bir
                        // Edit/Delete varsa şimdi uygula.
                        self.replay_buffered_edits_deletes(&display_id);
                    }
                    Err(e) => {
                        // No event either: the UI would show a message that is
                        // gone on reload, and show it again when the retry lands.
                        error!("Mesaj arşivlenemedi, Ack ertelendi (gönderen tekrar deneyecek): {}", e);
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                }
                // Spec dışı, kullanıcı isteği: `sent_at_ms` — göndericinin
                // KENDİ cihazındaki gönderim anı — alıcı tarafın "10:42
                // (sent at: 10:41)" gibi hem yerel ALINMA anını hem
                // göndericinin GERÇEK gönderim anını göstermesi için (bkz.
                // ChatActivity/SimpleChatAdapter). 0 = eski/bilinmeyen
                // sürüm, Kotlin tarafı bu durumda parantez içi gösterimi
                // atlar (bkz. packet.rs `sent_at_ms` notu).
                // Spec dışı, kullanıcı isteği (WhatsApp tarzı yanıt): bkz.
                // packet.rs `MessageContent::Text.reply_to_message_id`
                // dokümantasyonu — canlı olay da bu bilgiyi taşır (arşive
                // yazılmasını/bir reload'u beklemeden, ekran o an açıksa
                // hemen doğru şekilde çizilsin diye).
                serde_json::json!({
                    "type": "message", "peer": chat_key, "message_id": display_id, "text": text, "sent_at_ms": sent_at_ms,
                    "reply_to_message_id": reply_to_message_id, "reply_to_preview": reply_to_preview
                })
            }
            MessageContent::Text { group_id: Some(gid), text, group_message_local_id, sent_at_ms, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, author_proof, mentions } => {
                // Gerçek grup entegrasyonu: bu, bir grup mesajının pairwise
                // fan-out kopyası — GroupChatActivity'nin doğru sohbete
                // yönlendirebilmesi için `group_id` VE göndericinin
                // `identity_id`'si (bir grupta birden fazla kişi olduğundan
                // "kim gönderdi" bilgisi 1:1'in aksine zorunlu) taşınıyor.
                // `group_message_local_id`: Kotlin bu mesajı "gördü" olarak
                // işaretlerken (bkz. Seen) geri göndermesi gereken kimlik —
                // `message_id` göndericiye anlamsız (bkz. packet.rs notu),
                // sadece bu paylaşılan kimlik her N kopya arasında ortak.
                // önceden bu kol HİÇBİR ŞEYİ arşivlemiyordu — alınan bir
                // grup mesajı sadece bu tek `pollNetwork` turunda Kotlin'e
                // geçici bir JSON olayı olarak veriliyordu; ekran o an açık
                // değilse ya da süreç yeniden başlarsa mesaj kalıcı olarak
                // kayboluyordu ("grup geçmişi bazen kalıcı olmuyor" hatası).
                // `group_message_local_id`, her N kopya arasında ortak
                // olduğundan `message_id` yerine arşiv kimliği olarak
                // kullanılıyor — reload sonrası "görüldü" eşleşmesi hâlâ
                // çalışsın diye.
                // Güvenilirlik düzeltmesi (çift arşiv) — 1:1 Text kolundaki
                // AYNI dedup: `group_message_local_id` tüm fan-out kopyaları/
                // tekrarlar arasında kararlı olduğundan dedup anahtarıdır
                // (yoksa — eski sürüm göndericisi — dedup yapılamaz, eski
                // davranış korunur). Ack yine gönderilir.
                // bkz. `sender_may_post_to_group` — çıkarılmış bir üyenin
                // (ya da grupla hiç ilgisi olmayan bir kişinin) mesajı
                // buraya kadar gelebiliyordu ve arşive girip meşru bir grup
                // mesajı gibi görünüyordu. Ack GÖNDERİLMEZ: bizden önce
                // eklenmiş meşru bir üye, `GroupUpdate` bize ulaştığında
                // yeniden denemesiyle kabul edilir.
                if !self.sender_may_post_to_group(&gid, &sender_identity_id) {
                    warn!(
                        "Grup mesajı REDDEDİLDİ: gönderen bu grubun üyesi değil (group={}, gönderen={})",
                        gid, crate::log_id(&sender_identity_id)
                    );
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // The id must carry the sender's author tag (`group_msg_tag`):
                // then no other member can hold it, and a row already under
                // it is this sender's own copy (a duplicate).
                if !group_message_local_id.as_deref().map_or(false, |id| group_msg_id_bound(&gid, &sender_identity_id, id)) {
                    warn!(
                        "Group message refused: id not bound to its author (group={}, sender={})",
                        gid, crate::log_id(&sender_identity_id)
                    );
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                let (reply_to_message_id, reply_to_preview, reply_to_sender_identity_id) =
                    if group_reply_bound(&gid, reply_to_message_id.as_deref(), reply_to_sender_identity_id.as_deref()) {
                        (reply_to_message_id, reply_to_preview, reply_to_sender_identity_id)
                    } else {
                        (None, None, None)
                    };
                let already_archived = group_message_local_id.as_deref()
                    .map(|id| self.message_exists_in_chat(id, Some(gid.as_str()), ""))
                    .unwrap_or(false);
                if already_archived {
                    self.ack_text_packet(&peer_fp, &message_id, group_message_local_id.as_deref());
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // Kept only when it checks out: other members hand it on with
                // the group history as the proof of who wrote this.
                let author_proof = author_proof.filter(|p| {
                    group_message_local_id.as_deref().map_or(false, |mid| self.group_author_proof_valid(&gid, mid, &sender_identity_id, &text, signed_sent_at_ms, Some(p.as_str())))
                });
                let archived_ok = self.archive_group_message(&gid, &sender_identity_id, "received", text.as_bytes(), group_message_local_id.as_deref(), reply_to_message_id.as_deref(), reply_to_preview.as_deref(), reply_to_sender_identity_id.as_deref(), sent_at_ms, author_proof.as_deref()).is_ok();
                let mentions_me = self.group_mentions_me(&gid, mentions);
                if archived_ok && mentions_me {
                    if let (Some(conn), Some(mid)) = (&self.db, group_message_local_id.as_deref()) {
                        let _ = conn.execute("UPDATE messages SET mentions_me = 1 WHERE group_id = ?1 AND message_id = ?2", params![gid, mid]);
                    }
                }
                // Spec dışı, hata düzeltmesi ("bir grup üyesi bazı mesajları
                // kaçırıyor"): önceden grup metin mesajları için HİÇ Ack
                // gönderilmiyordu (bkz. `needs_delivery_confirmation`
                // dokümantasyonu — grup mesajları bilinçli olarak bu
                // mekanizmanın DIŞINDA bırakılmıştı). Bu, gönderenin
                // `awaiting_confirmation` yeniden deneme döngüsünün hiçbir
                // zaman tetiklenemeyeceği anlamına geliyordu — tek seferlik
                // `publish_envelope` (20 sn sonra sessizce vazgeçen) TEK
                // güvenceydi. Alıcı o anda kısa süreliğine ulaşılamazsa
                // (uyku modu, arka plana atılma, geçici NAT/ağ sıçraması —
                // özellikle 3 üyeli bir grupta fan-out'un HER bir kopyası
                // ayrı bir dial gerektirdiğinden, tam o anda meşgul/uykuda
                // olan üye sistematik olarak mesaj kaybediyordu) mesaj
                // SESSİZCE kaybolurdu. Artık diğer her şeyle AYNI Ack
                // mekanizması kullanılıyor (bkz. `needs_delivery_confirmation`
                // notu — artık grup metnini de kapsıyor).
                // Ack yalnızca arşive kalıcı olarak yazılabildiyse gönderilir
                // (bkz. 1:1 Text kolundaki aynı düzeltme notu) — aksi halde
                // gönderen tarafın yeniden deneme mekanizması devam eder.
                if archived_ok {
                    self.ack_text_packet(&peer_fp, &message_id, group_message_local_id.as_deref());
                    // bkz. `pending_edits_deletes` dokümantasyonu — bu grup
                    // Text'inden ÖNCE gelmiş bir Edit/Delete varsa şimdi
                    // uygula. `target_message_id` grup bağlamında
                    // `group_message_local_id`'dir (bkz. edit_group_message/
                    // delete_group_message notu) — yoksa (eski sürüm
                    // göndericisi) zaten tamponlanamamıştır, atlanır.
                    if let Some(local_id) = &group_message_local_id {
                        self.replay_buffered_edits_deletes(local_id);
                    }
                } else {
                    error!("Grup mesajı arşivlenemedi, Ack ertelendi (gönderen tekrar deneyecek)");
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                serde_json::json!({
                    "type": "group_message", "group_id": gid, "peer": peer_fp,
                    "sender_identity_id": sender_identity_id,
                    "message_id": message_id, "text": text,
                    "group_message_local_id": group_message_local_id,
                    "sent_at_ms": sent_at_ms,
                    "reply_to_message_id": reply_to_message_id, "reply_to_preview": reply_to_preview,
                    "reply_to_sender_identity_id": reply_to_sender_identity_id,
                    "mentions_me": mentions_me
                })
            }
            MessageContent::Edit { target_message_id, new_text, group_id, edited_at_ms, author_proof } => {
                // Spec dışı, hata düzeltmesi ("hızlı gönder+düzenle, düzenleme
                // kayboluyor"): gossipsub sıra garantisi vermediğinden bu Edit,
                // hedefi olan Text'ten ÖNCE gelmiş olabilir. Böyle bir durumda
                // hedef satır arşivde HİÇ yok (başkasına ait olduğu için değil)
                // — bu ayrımı burada yapıp tamponluyoruz (bkz.
                // `pending_edits_deletes`), aksi halde `message_owned_by_sender`
                // hedefi bulamadığı için `false` döner ve paket KALICI olarak
                // "rejected" sayılırdı, Text sonradan gelse bile bir daha asla
                // uygulanmazdı.
                if self.edit_target_in_chat(&target_message_id, group_id.as_deref(), &peer_fp) {
                    self.apply_edit_or_delete_content(&peer_fp, &sender_identity_id, &message_id,
                        MessageContent::Edit { target_message_id, new_text, group_id, edited_at_ms, author_proof })
                } else {
                    self.buffer_edit_or_delete(&target_message_id, &peer_fp, &sender_identity_id, &message_id,
                        MessageContent::Edit { target_message_id: target_message_id.clone(), new_text, group_id, edited_at_ms, author_proof });
                    serde_json::json!({"type": "noop"})
                }
            }
            MessageContent::Delete { target_message_id, group_id, author_proof } => {
                // bkz. yukarıdaki Edit kolu aynı notu.
                if self.edit_target_in_chat(&target_message_id, group_id.as_deref(), &peer_fp) {
                    self.apply_edit_or_delete_content(&peer_fp, &sender_identity_id, &message_id,
                        MessageContent::Delete { target_message_id, group_id, author_proof })
                } else {
                    self.buffer_edit_or_delete(&target_message_id, &peer_fp, &sender_identity_id, &message_id,
                        MessageContent::Delete { target_message_id: target_message_id.clone(), group_id, author_proof });
                    serde_json::json!({"type": "noop"})
                }
            }
            MessageContent::Reaction { target_message_id, emoji, group_id, reacted_at_ms } => {
                // `Reaction` is in `needs_delivery_confirmation`: the sender
                // retries it for 7 days until acked. Acked once written or
                // rejected for good; NOT acked when the write failed (the retry
                // brings it back) nor from a non-member of a known group (like
                // group Text: a member we do not know of yet is taken once its
                // GroupUpdate arrives).
                // bkz. `sender_may_post_to_group` — grup Text/FileOffer ile
                // AYNI boşluk; tepki de arşive (reactions tablosu) yazıyor.
                if let Some(gid) = &group_id {
                    if !self.sender_may_post_to_group(gid, &sender_identity_id) {
                        warn!(
                            "Grup tepkisi REDDEDİLDİ: gönderen bu grubun üyesi değil (group={}, gönderen={})",
                            gid, crate::log_id(&sender_identity_id)
                        );
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                }
                // The target must be a message of the chat the reaction names:
                // `group_id: None` skipped the membership check above, and any
                // contact could react on a group message whose id it knew.
                if emoji.len() > 64 || !self.reaction_fits_chat(&target_message_id, group_id.as_deref(), &sender_identity_id) {
                    warn!("Tepki REDDEDİLDİ: hedef bu sohbete ait değil ya da emoji çok uzun (gönderen={})", crate::log_id(&sender_identity_id));
                    self.send_ack(&peer_fp, &message_id);
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                if !self.apply_reaction(&target_message_id, &sender_identity_id, &emoji, reacted_at_ms) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                self.send_ack(&peer_fp, &message_id);
                self.requeue_archive_row(group_id.as_deref(), &chat_key, &target_message_id);
                let summary = self.reactions_summary(&target_message_id);
                match &group_id {
                    Some(gid) => serde_json::json!({
                        "type": "reaction", "group_id": gid,
                        "message_id": target_message_id, "reactions": summary
                    }),
                    None => serde_json::json!({
                        "type": "reaction", "peer": chat_key,
                        "message_id": target_message_id, "reactions": summary
                    }),
                }
            }
            MessageContent::HistorySyncRequest { limit, before_timestamp, group_id, after_timestamp } => {
                // `load_message_history`/`load_group_message_history` zaten
                // `history_key` yüklenmemişse (node modu hiç açılmadıysa)
                // veya arşiv yoksa boş liste döner — burada ayrıca
                // `node_mode_enabled` kontrolüne gerek yok. Bu bir orijinal
                // kullanıcı mesajı değil, kontrol paketi — kendi arşivimize
                // TEKRAR yazılmaz (archive_plaintext: None, bkz.
                // send_message_content).
                // Güvenilirlik düzeltmesi (MessageTooLarge): istekteki `limit`
                // karşı taraf kontrolünde ve sınırsızdı — devasa bir yanıt,
                // gossipsub'un 1MB `max_transmit_size` sınırını aşıp KALICI
                // olarak yayınlanamaz hale gelirdi (bkz. `PublishFailure`).
                // Hem satır sayısı hem toplam metin baytı sınırlanır; kırpılan
                // kısım karşı tarafın sayfalama isteğiyle (before_timestamp)
                // zaten sonradan çekilebilir.
                // Grup geçmişi yalnızca ŞU AN üye olana verilir: aksi halde
                // `group_id`'yi bilen herhangi bir kişi (ör. çıkarılmış eski
                // üye) çıkarıldıktan sonraki mesajlar dahil tüm geçmişi
                // sayfalayarak çekebilirdi.
                if let Some(gid) = &group_id {
                    if !self.groups.get(gid).map_or(false, |g| g.is_member(&sender_identity_id)) {
                        warn!("Grup geçmişi isteği REDDEDİLDİ: gönderen üye değil (group={}, gönderen={})", gid, crate::log_id(&sender_identity_id));
                        // Ack: istek `needs_delivery_confirmation`'da; yanıt
                        // gelmeyeceği için aksi halde gönderen günlerce yeniden dener.
                        self.send_ack(&peer_fp, &message_id);
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                }
                // One answer per device per 2 s (a page is asked for by a
                // scroll). Each answer is up to 512 KiB, tracked and retried
                // until acknowledged: a few hundred requests from a peer that
                // never acks held hundreds of MB.
                // A shed request is NOT acked and does not restart the window:
                // the requester's retry gets the answer a little later.
                let now = current_time_ms();
                if self.history_answered_at.len() > 1000 {
                    self.history_answered_at.retain(|_, t| now.saturating_sub(*t) < 2_000);
                }
                if self.history_answered_at.get(&peer_fp).map_or(false, |t| now.saturating_sub(*t) < 2_000) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // and at most HISTORY_SYNC_BYTES_PER_WINDOW of rows per
                // device per minute, shed the same way.
                const HISTORY_SYNC_WINDOW_MS: u64 = 60_000;
                const HISTORY_SYNC_BYTES_PER_WINDOW: usize = 2 * 1024 * 1024;
                if self.history_sent_bytes.len() > 1000 {
                    self.history_sent_bytes.retain(|_, (start, _)| now.saturating_sub(*start) < HISTORY_SYNC_WINDOW_MS);
                }
                if self.history_sent_bytes.get(&peer_fp).map_or(false, |(start, sent)| now.saturating_sub(*start) < HISTORY_SYNC_WINDOW_MS && *sent >= HISTORY_SYNC_BYTES_PER_WINDOW) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                self.history_answered_at.insert(peer_fp.clone(), now);
                let limit = limit.min(HISTORY_SYNC_MAX_MESSAGES);
                // Çoklu-cihaz düzeltmesi: 1:1 arşivimiz KANONİK cihaz
                // anahtarı altında (bkz. `canonical_peer_key`/Text kolu) —
                // isteyen kişinin kanonik-olmayan bir cihazından gelen istek
                // de aynı sohbet geçmişini bulabilmeli.
                // A "Fetch older history" press gets only rows sent in its
                // window `[after, before)`, at most one window long; the
                // chat-open sync (no `before_timestamp`) is unchanged.
                // a group member gets history from at most one day
                // before it was added (its latest add, `GroupMember.added_at`,
                // our local time of that update), never older. Our own other
                // devices get everything. A missing or zero `added_at` counts
                // as now.
                const GROUP_HISTORY_BEFORE_JOIN_MS: u64 = 24 * 60 * 60 * 1000;
                let history_floor: Option<u64> = group_id.as_ref().and_then(|gid| {
                    if self.my_identity_id().as_deref() == Some(sender_identity_id.as_str()) {
                        return None;
                    }
                    let added = self.groups.get(gid)
                        .and_then(|g| g.members.iter().find(|m| m.identity_id == sender_identity_id))
                        .map(|m| m.added_at)
                        .filter(|t| *t > 0)
                        .unwrap_or(now);
                    Some(added.saturating_sub(GROUP_HISTORY_BEFORE_JOIN_MS))
                });
                let window = before_timestamp.map(|b| {
                    let min_after = b.saturating_sub(HISTORY_FETCH_WINDOW_MS as i64);
                    let after = after_timestamp.map_or(min_after, |a| a.max(min_after));
                    (b, history_floor.map_or(after, |f| after.max(f as i64)))
                });
                let mut history = match (&group_id, window) {
                    (_, Some((before, after))) if before <= after => Vec::new(),
                    (gid, Some((before, after))) => self.load_history_fetch_page(&chat_key, gid.as_deref(), limit, before, after),
                    (Some(gid), None) => self.load_group_message_history_opt(gid, limit, None, false),
                    (None, None) => self.load_message_history_opt(&chat_key, limit, None, false),
                };
                // Rows count as pre-join if we got them before the floor OR
                // their author sent them before it (a row we fetched late).
                let raw_loaded = history.len();
                if let Some(f) = history_floor {
                    history.retain(|m| m.timestamp >= f && (m.sent_at_ms == 0 || m.sent_at_ms >= f));
                }
                let loaded = history.len();
                // `history` is oldest first and the requester pages backwards
                // from the oldest row it gets, so the budget must cut the OLD
                // end: walk from the newest. The newest row is always sent, or
                // one oversized row would end the paging for good.
                let mut text_budget: usize = HISTORY_SYNC_MAX_TEXT_BYTES;
                let mut first = true;
                // Group rows go out with their author's signature. It is far
                // larger than most texts, so it counts toward the budget.
                if let Some(gid) = &group_id {
                    for m in history.iter_mut() {
                        m.author_proof = m.message_id.as_deref().and_then(|id| self.group_author_proof(gid, id));
                    }
                }
                // Reactions: only the requester's and mine (the only ones it
                // takes), and they count toward the budget too.
                let own_id = self.my_identity_id().unwrap_or_default();
                let mut kept: Vec<(ArchivedMessage, Vec<(String, String, u64)>)> = history.into_iter().rev()
                    .map(|m| {
                        let r = m.message_id.as_deref().map(|id| self.reactions_of(id, [sender_identity_id.as_str(), own_id.as_str()])).unwrap_or_default();
                        (m, r)
                    })
                    .take_while(|(m, r)| {
                        let cost = m.text.len() + m.author_proof.as_ref().map_or(0, |p| p.len())
                            + r.iter().map(|(who, emoji, _)| who.len() + emoji.len() + 16).sum::<usize>();
                        let is_first = std::mem::take(&mut first);
                        if cost > text_budget && !is_first {
                            return false;
                        }
                        text_budget = text_budget.saturating_sub(cost);
                        true
                    })
                    .collect();
                kept.reverse();
                // Rows of the window were cut: the requester asks for the rest.
                // `raw_loaded`: a full page before the C-06 filter may still
                // have more; a page the filter emptied has no row to page from.
                let more = window.is_some() && !kept.is_empty() && (raw_loaded as u32 >= limit || kept.len() < loaded);
                let messages: Vec<SyncedMessage> = kept.into_iter()
                    .map(|(m, reactions)| SyncedMessage {
                        reactions,
                        direction: m.direction, text: m.text, timestamp: m.timestamp,
                        sender_identity_id: m.sender_identity_id, message_id: m.message_id,
                        sent_at_ms: m.sent_at_ms, is_deleted: m.is_deleted, is_edited: m.is_edited,
                        author_proof: m.author_proof,
                    })
                    .collect();
                // `request_id`, isteyen tarafın bu yanıtı doğru
                // `awaiting_confirmation` girdisine eşleyip yeniden
                // deneme kuyruğundan çıkarabilmesi için isteğin KENDİ
                // `message_id`'sini taşır (bkz. packet.rs notu).
                let response = MessageContent::HistorySyncResponse {
                    request_id: message_id.clone(), messages, group_id: group_id.clone(), more,
                };
                if let Err(e) = self.send_message_content(peer_fp.clone(), &response, None) {
                    error!("HistorySyncResponse gönderilemedi: {}", e);
                    // nothing went out, the window is not used up.
                    self.history_answered_at.remove(&peer_fp);
                } else {
                    let used = HISTORY_SYNC_MAX_TEXT_BYTES - text_budget;
                    let entry = self.history_sent_bytes.entry(peer_fp.clone()).or_insert((now, 0));
                    if now.saturating_sub(entry.0) >= HISTORY_SYNC_WINDOW_MS {
                        *entry = (now, 0);
                    }
                    entry.1 += used;
                }
                // bu olay hiçbir istemcide işlenmiyordu ve
                // işlenmesi de gerekmiyor (karşı tarafın bizden geçmiş
                // istemesi kullanıcıyı ilgilendiren bir olay değil).
                // Tanılama için log'a, akışa `noop` olarak.
                info!("Geçmiş senkronu istendi (peer={}, group={:?})", crate::log_id(&peer_fp), group_id);
                serde_json::json!({"type": "noop"})
            }
            MessageContent::HistorySyncResponse { request_id, messages, group_id, more } => {
                // A group request is open to every member, but each answers once.
                let answered_before = self.history_answered_by.get(&request_id).is_some_and(|s| s.contains(&sender_identity_id));
                let solicited = !answered_before && match self.outstanding_history_requests.get(&request_id) {
                    Some((target_identity, req_group, _, _)) if *req_group == group_id => match &group_id {
                        Some(gid) => self.groups.get(gid).map_or(false, |g| g.is_member(&sender_identity_id)),
                        None => target_identity.as_deref() == Some(sender_identity_id.as_str()),
                    },
                    _ => false,
                };
                if !solicited {
                    // Ack yine gider: yanıtlayan aksi halde boşuna yeniden dener.
                    self.send_ack(&peer_fp, &message_id);
                    // A member answering its own request again (it got a
                    // resent copy) is handled already, not unsolicited.
                    if answered_before {
                        debug!("HistorySyncResponse already taken from this member (peer={}, request_id={})", crate::log_id(&peer_fp), request_id);
                    } else {
                        warn!("İstenmemiş HistorySyncResponse REDDEDİLDİ (peer={}, request_id={})", crate::log_id(&peer_fp), request_id);
                    }
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // The request is closed and the response acked only AFTER the
                // rows are on disk (see the end of this arm): a failed write
                // leaves both open, the responder's retry is still solicited.
                // An archive write failure sets this.
                let mut write_failed = false;
                // No more rows than could be asked for. In 1:1 only the
                // peer's own messages: nothing proves who wrote a row, and
                // every row the peer marked "received" became a message WE
                // sent, backdated, on all our devices. Our own messages come
                // back from a sibling or from our server archive.
                let mut messages = messages;
                messages.truncate(HISTORY_SYNC_MAX_MESSAGES as usize);
                // reactions ride along; applied at the end, only on the rows
                // that passed the filters below (see `apply_synced_reactions`).
                let mut reactions: HashMap<String, Vec<(String, String, u64)>> = HashMap::new();
                for m in messages.iter_mut() {
                    if let Some(mid) = m.message_id.clone() {
                        let mut r = std::mem::take(&mut m.reactions);
                        r.truncate(64);
                        reactions.insert(mid, r);
                    }
                }
                let floor_key = group_id.clone().unwrap_or_else(|| sender_identity_id.clone());
                let press = self.filter_history_reply(&request_id, group_id.as_deref(), &sender_identity_id, &mut messages);
                // Send time of the oldest row written (a press lowers the floor to it).
                let mut oldest_written: Option<u64> = None;
                // `group_id` is the one we asked with (`solicited`); the page
                // kind comes from our request (`press`), never the
                // responder's word. A group answer went down the 1:1 arm
                // below: unfiltered, unsigned rows, archived into our 1:1
                // chat as sent by us.
                let mut event = if group_id.is_some() || press.is_some() {
                    // Spec dışı, kullanıcı isteği (sonsuz kaydırma): ESKİ
                    // SAYFA yanıtı — mevcut "en yeniden daha yeni" zaman
                    // damgası eşiği burada YANLIŞ yönde çalışırdı (bu
                    // sayfalama KASITLI olarak daha eski mesajlar getiriyor),
                    // bu yüzden `message_id` bazlı var-olma kontrolü kullanılır.
                    match &group_id {
                        Some(gid) => {
                            let own_identity_id = self.identity.as_ref().map(|i| i.identity_id.clone());
                            let merged: Vec<serde_json::Value> = messages.into_iter().filter_map(|mut m| {
                                // "sent" ise gönderen YANITLAYANIN kendisi
                                // (paket başlığından zaten bilinen
                                // `sender_identity_id`); "received" ise
                                // yanıtlayanın kendi arşivindeki gerçek
                                // gönderen taşınır (bkz. packet.rs
                                // SyncedMessage notu).
                                let actual_sender = if m.direction == "sent" {
                                    Some(sender_identity_id.clone())
                                } else {
                                    m.sender_identity_id.clone()
                                };
                                let our_direction = if actual_sender == own_identity_id { "sent" } else { "received" };
                                // A row the responder did not write itself is
                                // taken only with its author's signature: the
                                // responder could otherwise put any text under
                                // any name, ours included.
                                let author = actual_sender.clone().unwrap_or_default();
                                // A deleted row has no text: its author signed
                                // the deletion instead.
                                if m.is_deleted {
                                    m.text.clear();
                                }
                                let signed_text = if m.is_deleted { GROUP_TOMBSTONE } else { m.text.as_str() };
                                let signed = m.message_id.as_deref().map_or(false, |mid| {
                                    self.group_author_proof_valid(gid, mid, &author, signed_text, if m.sent_at_ms != 0 { m.sent_at_ms } else { m.timestamp }, m.author_proof.as_deref())
                                });
                                if !signed {
                                    m.author_proof = None;
                                    if m.direction != "sent" {
                                        warn!("Grup geçmişi satırı atlandı: yazar imzası yok ya da geçersiz (group={}, yazar={})", gid, crate::log_id(&author));
                                        return None;
                                    }
                                }
                                // A row without an id cannot be deduped: it was
                                // never archived, but shown again on every page.
                                let Some(mid) = m.message_id.clone() else { return None };
                                // The id must carry its author's tag
                                // (`group_msg_tag`): no other member can then
                                // have taken it, so a row already under it is
                                // this author's and a duplicate.
                                if !group_msg_id_bound(gid, &author, &mid) {
                                    warn!("Grup geçmişi satırı atlandı: kimlik yazarına bağlı değil (group={}, yazar={})", gid, crate::log_id(&author));
                                    return None;
                                }
                                if !self.message_exists_in_chat(&mid, Some(gid.as_str()), "") {
                                    // NOT: `SyncedMessage` (bkz. packet.rs) henüz yanıt
                                    // bilgisi taşımıyor — geçmiş senkronuyla gelen eski
                                    // mesajlar şimdilik yanıt önizlemesi olmadan arşivlenir
                                    // (bilinen, kabul edilmiş bir kapsam sınırı).
                                    // Not shown when it is not on disk: it would vanish on reload.
                                    if let Err(e) = self.archive_group_message(gid, &author, our_direction, m.text.as_bytes(), Some(&mid), None, None, None, m.sent_at_ms, m.author_proof.as_deref()) {
                                        error!("Grup geçmişi satırı arşivlenemedi: {}", e);
                                        write_failed = true;
                                        return None;
                                    }
                                    self.backdate_archived(Some(gid.as_str()), "", m.message_id.as_deref(), m.timestamp);
                                    let at = if m.sent_at_ms != 0 { m.sent_at_ms } else { m.timestamp };
                                    oldest_written = Some(oldest_written.map_or(at, |o| o.min(at)));
                                    // bu satırı hiç sahip olmadığımız için taze arşivliyoruz —
                                    // yanıtlayan tarafta silinmiş olarak
                                    // işaretliyse bizde de ÖYLE işaretlenmeli,
                                    // aksi halde silinen bir mesaj bu cihazda
                                    // (ör. yeni eklenen ikincil cihaz, ya da
                                    // hiç sahip olunmayan eski bir sayfa)
                                    // sanki hiç silinmemiş gibi geri gelir.
                                    self.apply_synced_message_flags(Some(gid), "", &m);
                                    // The delete above cleared the proof.
                                    if let (true, Some(mid)) = (m.is_deleted, m.message_id.as_deref()) {
                                        self.adopt_group_author_proof(gid, mid, m.author_proof.as_deref());
                                    }
                                }
                                Some(serde_json::json!({
                                    "direction": our_direction, "text": m.text, "timestamp": m.timestamp, "sent_at_ms": m.sent_at_ms,
                                    "sender_identity_id": actual_sender, "reactions": m.message_id.as_deref().map(|id| self.reactions_summary(id)).unwrap_or_default(), "message_id": m.message_id, "is_deleted": m.is_deleted, "is_edited": m.is_edited
                                }))
                            }).collect();
                            serde_json::json!({"type": "older_group_history", "group_id": gid, "messages": merged})
                        }
                        None => {
                            let merged: Vec<serde_json::Value> = messages.into_iter().filter_map(|m| {
                                let our_direction = if m.direction == "sent" { "received" } else { "sent" };
                                // See the group arm: id-less rows are skipped.
                                let mid = m.message_id.as_deref()?;
                                if !self.message_exists_in_chat(mid, None, &chat_key) {
                                    // bkz. yukarıdaki archive_group_message aynı notu
                                    // (SyncedMessage henüz yanıt bilgisi taşımıyor).
                                    // Çoklu-cihaz düzeltmesi: KANONİK sohbet
                                    // anahtarı altına arşivle (canlı Text
                                    // koluyla AYNI) — `peer_fp` kanonik değilse
                                    // satırlar UI'nin hiç okumadığı ayrı bir
                                    // sohbete düşüyordu.
                                    if let Err(e) = self.archive_message(&chat_key, our_direction, m.text.as_bytes(), Some(mid), None, None, None, m.sent_at_ms) {
                                        error!("Geçmiş satırı arşivlenemedi: {}", e);
                                        write_failed = true;
                                        return None;
                                    }
                                    self.backdate_archived(None, &chat_key, Some(mid), m.timestamp);
                                    self.mark_synced(&chat_key, Some(mid));
                                    let at = if m.sent_at_ms != 0 { m.sent_at_ms } else { m.timestamp };
                                    oldest_written = Some(oldest_written.map_or(at, |o| o.min(at)));
                                    // bkz. yukarıdaki grup koluyla aynı düzeltme —
                                    // yanıtlayanın silinmiş işaretini bu ilk
                                    // arşivlemede de yansıt.
                                    self.apply_synced_message_flags(None, &chat_key, &m);
                                }
                                Some(serde_json::json!({"direction": our_direction, "text": m.text, "timestamp": m.timestamp, "sent_at_ms": m.sent_at_ms, "reactions": m.message_id.as_deref().map(|id| self.reactions_summary(id)).unwrap_or_default(), "message_id": m.message_id, "is_deleted": m.is_deleted, "is_edited": m.is_edited, "via_sync": self.is_synced(&chat_key, m.message_id.as_deref())}))
                            }).collect();
                            serde_json::json!({"type": "older_history", "peer": chat_key, "messages": merged})
                        }
                    }
                } else {
                    // Mevcut davranış (DEĞİŞMEDİ): sohbet açılışı senkronu.
                    // `messages`'in direction'ı YANITLAYANIN (arşivi tutan
                    // node'un) bakış açısıyla geldi — bizim ekranımız için
                    // ters çevrilmeli: onların "sent"i bizim "received"imiz,
                    // onların "received"i bizim "sent"imiz.
                    // Spec dışı düzeltme: senkronla gelen mesajlar önceden
                    // SADECE bu ekranın o anki bellek-içi listesine
                    // ekleniyordu — kalıcı hiçbir kayıt bırakmıyordu,
                    // geçmiş her sohbet açılışında ağdan yeniden çekilmek
                    // zorundaydı. Artık HER cihaz (node olsun olmasın, bkz.
                    // send_message_content/yukarıdaki Text kolu notu)
                    // kendi canlı trafiğini zaten yerelde arşivliyor —
                    // burada `latest_archived_timestamp` ile SADECE zaten
                    // sahip OLMADIĞIMIZ (daha yeni) mesajlar yazılıyor,
                    // aksi halde her sohbet açılışında (artık her zaman
                    // senkron denendiği için) aynı satırlar tekrar tekrar
                    // eklenip yinelenen kayıtlar oluşurdu.
                    // Çoklu-cihaz düzeltmesi: eşik/arşiv/olay hepsi KANONİK
                    // sohbet anahtarını kullanır (bkz. pagination kolundaki
                    // aynı not).
                    let already_have_since = self.latest_archived_timestamp(&chat_key);
                    let flipped: Vec<serde_json::Value> = messages.into_iter().filter_map(|m| {
                        let our_direction = if m.direction == "sent" { "received" } else { "sent" };
                        // önceden dedup SADECE
                        // zaman damgası eşiğiyle yapılıyordu ve arşivleme
                        // `message_id: None` geçiyordu — yani bu yoldan
                        // gelen satırlar hiçbir zaman `message_id` ile
                        // aranamıyordu (gelecekteki bir senkronda tekrar
                        // dedup edilemez, bkz. `message_exists_with_id`).
                        // Artık (varsa) `message_id` de hem dedup için hem
                        // kalıcı kayıt için kullanılıyor — pagination
                        // yolundaki (`before_timestamp.is_some()`) aynı
                        // deseni burada da uyguluyoruz.
                        let already_exists = m.message_id.as_deref()
                            .map(|mid| self.message_exists_in_chat(mid, None, &chat_key))
                            .unwrap_or(false);
                        // The clock test is only for rows without an id. With an
                        // id, `already_exists` decides: the test dropped exactly
                        // the gap messages (older than our newest row).
                        let is_new = !already_exists
                            && (m.message_id.is_some() || already_have_since.map(|t| m.timestamp > t as u64).unwrap_or(true));
                        if is_new {
                            if let Err(e) = self.archive_message(&chat_key, our_direction, m.text.as_bytes(), m.message_id.as_deref(), None, None, None, m.sent_at_ms) {
                                error!("Geçmiş satırı arşivlenemedi: {}", e);
                                write_failed = true;
                                return None;
                            }
                            self.backdate_archived(None, &chat_key, m.message_id.as_deref(), m.timestamp);
                            self.mark_synced(&chat_key, m.message_id.as_deref());
                            // Spec dışı, hata düzeltmesi ("silinen mesaj
                            // geçmiş senkronuyla geri geliyor"): bu satırı
                            // hiç sahip olmadığımız için taze arşivliyoruz —
                            // yanıtlayan tarafta silinmiş işaretliyse bizde
                            // de öyle işaretlenmeli.
                            self.apply_synced_message_flags(None, &chat_key, &m);
                        }
                        Some(serde_json::json!({"direction": our_direction, "text": m.text, "timestamp": m.timestamp, "sent_at_ms": m.sent_at_ms, "reactions": m.message_id.as_deref().map(|id| self.reactions_summary(id)).unwrap_or_default(), "message_id": m.message_id, "is_deleted": m.is_deleted, "is_edited": m.is_edited, "via_sync": self.is_synced(&chat_key, m.message_id.as_deref())}))
                    }).collect();
                    serde_json::json!({"type": "history_sync", "peer": chat_key, "messages": flipped})
                };
                self.apply_synced_reactions(&mut event, &reactions, group_id.as_deref(), &sender_identity_id);
                if let Some(((_, after), oldest)) = press {
                    // The user fetched rows back: from the oldest one written
                    // on they are not "cleared" any more.
                    if let Some(o) = oldest_written {
                        self.lower_history_floor(&floor_key, o);
                    }
                    // The responder cut its page: ask it for the older rest of
                    // the window (`HISTORY_FETCH_MAX_PAGES`).
                    // `o + 1`: rows sent in the same ms as `o` may be the
                    // ones cut; rows asked for twice dedup by id. Not sent
                    // (budget out, or the budget was lost in a restart): the
                    // next press asks for the rest.
                    if let (true, Some(o), false) = (more, oldest, write_failed) {
                        if o > after {
                            let sent = self.take_fetch_page(&floor_key) && {
                                let content = MessageContent::HistorySyncRequest {
                                    limit: HISTORY_SYNC_MAX_MESSAGES, before_timestamp: Some(o + 1), group_id: group_id.clone(), after_timestamp: Some(after),
                                };
                                self.send_message_content(peer_fp.clone(), &content, None).is_ok()
                            };
                            if !sent { self.reopen_fetch_cursor(&floor_key, o as u64 + 1) }
                        }
                    }
                }
                if write_failed {
                    // No Ack: the responder retries; rows already written dedup by id.
                    return Ok(event.to_string());
                }
                self.awaiting_confirmation.remove(&request_id);
                self.remove_durable_retry(&request_id);
                // 1:1: one answer per request. The entry used to stay for 7
                // days and the same peer could answer it again and again.
                // Group: the same request goes to every member, so it stays
                // open for the others (rows dedup by id; the stale sweep in
                // `send_message_content` drops it after TEXT_RETRY_GIVE_UP_MS).
                if group_id.is_none() {
                    self.forget_history_request(&request_id);
                } else {
                    self.history_answered_by.entry(request_id.clone()).or_default().insert(sender_identity_id.clone());
                }
                // The responder's `HistorySyncResponse` is in
                // `needs_delivery_confirmation`: it retries until this Ack.
                self.send_ack(&peer_fp, &message_id);
                event
            }
            MessageContent::FileOffer {
                group_id, file_id, file_name, mime_type, total_size, file_key, sha256_hex,
                preview_jpeg, duration_ms, chunk_size, chunk_hashes,
                caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin,
            } => {
                // bkz. `sender_may_post_to_group` — grup Text koluyla AYNI
                // boşluk, ve burada daha ağır: kabul edilen bir teklif node
                // modunda OTOMATİK indirme başlatıyor, yani yetkisiz bir
                // gönderen alıcının diskine ve bant genişliğine doğrudan
                // erişiyordu.
                if let Some(gid) = &group_id {
                    if !self.sender_may_post_to_group(gid, &sender_identity_id) {
                        warn!(
                            "Grup dosya teklifi REDDEDİLDİ: gönderen bu grubun üyesi değil (group={}, gönderen={})",
                            gid, crate::log_id(&sender_identity_id)
                        );
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                    // The file id is the group message id: it must carry the
                    // sender's author tag, as a Text id does (`group_msg_tag`).
                    if !group_msg_id_bound(gid, &sender_identity_id, &file_id) {
                        warn!(
                            "Group file offer refused: id not bound to its author (group={}, sender={})",
                            gid, crate::log_id(&sender_identity_id)
                        );
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                }
                let reply_ok = group_id.as_deref().map_or(true, |g| group_reply_bound(g, reply_to_message_id.as_deref(), reply_to_sender_identity_id.as_deref()));
                let (reply_to_message_id, reply_to_preview, reply_to_sender_identity_id) =
                    if reply_ok { (reply_to_message_id, reply_to_preview, reply_to_sender_identity_id) } else { (None, None, None) };
                let ev = self.receive_file_offer(
                    &peer_fp, &sender_identity_id, group_id, &file_id, &file_name, &mime_type,
                    total_size, &file_key, &sha256_hex, &preview_jpeg, duration_ms, chunk_size, &chunk_hashes,
                    &caption, reply_to_message_id.as_deref(), reply_to_preview.as_deref(),
                    reply_to_sender_identity_id.as_deref(), sticker, sticker_origin.as_deref(),
                );
                // "noop" with no row = the row could not be written (key or DB
                // not ready): no Ack, the sender offers again. Every other
                // outcome is final (stored, duplicate, rejected).
                if ev["type"] != "noop" || self.file_row_exists(&file_id) {
                    self.send_ack(&peer_fp, &message_id);
                }
                ev
            }
            MessageContent::Ack { target_message_id } => {
                // Karşı taraf bizim gönderdiğimiz bir Text/Edit/Delete/
                // HistorySyncRequest'i başarıyla aldı — o paketi artık
                // yeniden denemeyi bırakabiliriz (bkz.
                // `awaiting_confirmation` dokümantasyonu).
                // `target_message_id` here is the acked packet's own id. For
                // a `Text` that equals the UI bubble id, but for Edit/Delete
                // it's a separate, random packet id — not the message being
                // edited/deleted. Look up `regen_content` (the original
                // content) before removing, so the emitted event can carry
                // the real target id instead.
                // Onaylanan paketin GERÇEKTEN bu Ack'i gönderen eş için
                // kuyruklanmış olduğunu doğrula — aksi halde herhangi bir
                // eş, rastgele/bilinen bir `message_id` ile başka bir eşe
                // giden bekleyen bir paketi sahte Ack'le iptal edebilirdi
                // (session binding eksikliği).
                match self.apply_incoming_ack(&peer_fp, &target_message_id) {
                    Some(ev) => ev,
                    None => return Ok(serde_json::json!({"type": "noop"}).to_string()),
                }
            }
            MessageContent::Seen { target_message_id, group_message_local_id } => {
                // bkz. packet.rs `Seen` notu — teslim (Ack) değil, GÖRME
                // bildirimi. Kendisi ayrıca onaylanmaz (Ack'le aynı sonsuz
                // döngü gerekçesi).
                // "seen mekanizması ve
                // seen pp bubbles güvenilir değil, özellikle gruplarda"):
                // önceden BURADA kalıcı hiçbir şey yazılmıyordu — aşağıdaki
                // JSON sadece o an sohbet ekranı AÇIKSA görülen, kalıcı
                // olmayan bir olaydı. Uygulama arka plandayken/ekran
                // kapalıyken gelen HER "görüldü" bildirimi sonsuza dek
                // kayboluyordu (bkz. `message_seen` tablosu dokümantasyonu).
                // `message_id` kolonuyla AYNI anlam: grup mesajında
                // `group_message_local_id`, 1:1'de `target_message_id` (bkz.
                // `load_message_history`/`load_group_message_history`).
                let seen_key = group_message_local_id.clone().unwrap_or_else(|| target_message_id.clone());
                if !self.may_mark_seen(&seen_key, &sender_identity_id) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                self.apply_seen_receipt(&seen_key, &sender_identity_id, current_time_ms());
                // So the seen state reaches the server archive as well. The
                // packet names no group: the row does.
                let seen_group: Option<String> = self.db.as_ref().and_then(|c| {
                    c.query_row("SELECT group_id FROM messages WHERE message_id = ?1", params![seen_key], |r| r.get::<_, Option<String>>(0)).ok().flatten()
                });
                self.requeue_archive_row(seen_group.as_deref(), &chat_key, &seen_key);
                serde_json::json!({
                    "type": "seen", "peer": chat_key,
                    "sender_identity_id": sender_identity_id,
                    "message_id": target_message_id,
                    "group_message_local_id": group_message_local_id
                })
            }
            MessageContent::Call { call_id, action, group_id, video, media_key, stream_id, sent_at_ms, participants } => {
                self.handle_call_signal(&peer_fp, &sender_identity_id, call_id, action, group_id, video, media_key, stream_id, sent_at_ms, participants)
            }
            // Whiteboard — see `whiteboard`. Only the digest is acked (it is
            // the one reliable packet); the handlers check who may touch
            // which board.
            MessageContent::WbOps { group_id, conversation_identity_id, strokes, erased, sigs } => {
                self.wb_on_ops(&peer_fp, group_id, conversation_identity_id, strokes, erased, sigs)
            }
            MessageContent::WbDigest { group_id, conversation_identity_id, pages } => {
                self.send_ack(&peer_fp, &message_id);
                self.wb_on_digest(&peer_fp, group_id, conversation_identity_id, pages)
            }
            MessageContent::WbPageRequest { group_id, conversation_identity_id, pages } => {
                self.wb_on_page_request(&peer_fp, group_id, conversation_identity_id, pages)
            }
            MessageContent::WbPage { group_id, conversation_identity_id, page, authors, strokes, tombstones, sigs } => {
                self.wb_on_page(&peer_fp, group_id, conversation_identity_id, page, authors, strokes, tombstones, sigs)
            }
            MessageContent::TypingIndicator { is_typing, group_id } => {
                if group_id.as_ref().map_or(false, |gid| !self.sender_may_post_to_group(gid, &sender_identity_id)) {
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                // Kasitli olarak: arsivlenmez, Ack GONDERILMEZ (bkz.
                // packet.rs notu) -- birkac saniyede bayatlayan bir bilgi
                // icin tekrar deneme/onay trafiginin hicbir degeri yok.
                // `sender_identity_id` identifies which member is typing (needed for groups).
                match &group_id {
                    Some(gid) => serde_json::json!({
                        "type": "typing", "group_id": gid, "peer": peer_fp,
                        "sender_identity_id": sender_identity_id, "is_typing": is_typing
                    }),
                    None => serde_json::json!({
                        "type": "typing", "peer": chat_key,
                        "sender_identity_id": sender_identity_id, "is_typing": is_typing
                    }),
                }
            }
            MessageContent::ProfileUpdate { avatar_jpeg, display_name } => {
                self.send_ack(&peer_fp, &message_id);
                // bkz. `MAX_AVATAR_BYTES` — gelen yönde hiç sınır yoktu;
                // karşı taraf her kişi satırına istediği kadar bayt
                // yazdırabiliyordu. Ack YİNE gönderilir (yeniden denemesin),
                // sadece avatar yok sayılır — the stored one stays, and the
                // name in the same packet is still taken.
                let avatar_too_big = avatar_jpeg.as_ref().map_or(false, |a| a.len() > MAX_AVATAR_BYTES);
                if avatar_too_big {
                    warn!(
                        "ProfileUpdate avatarı çok büyük ({} bayt), yok sayıldı (gönderen: {})",
                        avatar_jpeg.as_ref().map_or(0, |a| a.len()), crate::log_id(&peer_fp)
                    );
                }
                // Kullanıcı isteği (2026-09-04): karşı taraf adını
                // değiştirdiyse kişi listesindeki ad da değişir. `None` =
                // paket ad TAŞIMIYOR (eski sürüm) — o durumda mevcut ad
                // KORUNUR; boş/kontrol karakterli bir ad da yok sayılır
                // (bkz. `sanitize_display_name`).
                // From one of my own devices: it is MY photo that changed
                // (`set_own_profile_picture`). The name travels by DeviceSync.
                if self.my_identity_id().as_deref() == Some(sender_identity_id.as_str()) {
                    if let (Some(conn), false) = (&self.db, avatar_too_big) {
                        if let Err(e) = conn.execute(
                            "UPDATE identities SET avatar_jpeg = ?1 WHERE id = ?2",
                            params![avatar_jpeg, sender_identity_id],
                        ) {
                            error!("Profil fotoğrafı kaydedilemedi: {}", e);
                        }
                    }
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                let new_name = display_name.as_deref().and_then(sanitize_display_name);
                let mut renamed_from: Option<String> = None;
                let mut shown_avatar = if avatar_too_big { None } else { avatar_jpeg.clone() };
                if let Some(cid) = self.identity_to_contact.get(&sender_identity_id).cloned() {
                    if let Some(c) = self.contacts.get_mut(&cid) {
                        if avatar_too_big {
                            shown_avatar = c.avatar_jpeg.clone();
                        } else {
                            c.avatar_jpeg = avatar_jpeg.clone();
                        }
                        if let Some(n) = &new_name {
                            if &c.display_name != n {
                                renamed_from = Some(c.display_name.clone());
                                c.display_name = n.clone();
                            }
                        }
                    }
                    if let Some(c) = self.contacts.get(&cid) {
                        self.persist_contact(c);
                    }
                }
                serde_json::json!({
                    "type": "profile_update", "peer": chat_key,
                    "avatar_hex": shown_avatar.as_ref().map(|a| hex::encode(a)),
                    // Arayüz, ad GERÇEKTEN değiştiyse kullanıcıya
                    // gösterebilsin diye eski/yeni ad birlikte veriliyor
                    // (aynı adın yeniden bildirilmesi olağan: her fotoğraf
                    // değişikliği de bu paketi taşıyor).
                    "display_name": new_name,
                    "previous_display_name": renamed_from
                })
            }
            MessageContent::GroupUpdate(update) => {
                // artık ratchet- şifreli kanaldan geliyor (bkz. packet.rs notu) — bu, DIŞ
                // paketin (`MessagePacket`) zaten hibrit doğrulanmış
                // göndericisi (`sender_identity_id`/`peer_fp`) İLE
                // `update.signed_by`'nin AYNI kişi olması gerekmediği
                // anlamına gelir (ör. kurucu olmayan bir üye de bu paketi
                // pairwise iletebilir, sadece bu kod tabanında henüz
                // relay yok) — asıl yetki kontrolü `process_group_update`
                // içindeki KENDİ (ayrıca hibrit) `update.signature`/
                // `signature_pq` doğrulaması ve `signed_by == founder`
                // kısıtıdır, dış paket imzası sadece taşıma bütünlüğünü
                // garanti eder.
                let group_id = update.group_id.clone();
                match self.process_group_update(&update) {
                    Ok(()) => {
                        self.send_ack(&peer_fp, &message_id);
                        self.give_founder_contact_secret(&update, &sender_identity_id, &peer_fp);
                        serde_json::json!({"type": "group_updated", "peer": peer_fp, "group_id": group_id})
                    }
                    Err(e) => {
                        error!("GroupUpdate işlenemedi: {}", e);
                        // Only an unknown signer can be cured by a later packet.
                        // Every other error is final: without the Ack the
                        // sender resent the same update for 7 days.
                        if e != "Unknown signer device" {
                            self.send_ack(&peer_fp, &message_id);
                        }
                        serde_json::json!({"type": "group_update_failed", "peer": peer_fp, "group_id": group_id, "error": e})
                    }
                }
            }
            MessageContent::GroupSyncRequest { group_id } => {
                // #77: a member (or my own other device) lacks devices of the
                // group: the founder re-sends the whole state to it, at most
                // every 10 minutes per member.
                self.send_ack(&peer_fp, &message_id);
                let me = self.my_identity_id().unwrap_or_default();
                let group = self.groups.get(&group_id)
                    .filter(|g| g.founder_identity_id == me && g.is_member(&sender_identity_id))
                    .cloned();
                let key = format!("gsq:{}:{}", group_id, sender_identity_id);
                let now = current_time_ms();
                if let Some(g) = group {
                    if now.saturating_sub(self.meta_u64(&key)) >= 10 * 60 * 1000 {
                        match self.sign_group_resync(&g) {
                            Ok(update) => {
                                self.meta_put(&key, &now.to_string());
                                self.send_group_update_to_member(&group_id, &sender_identity_id, &update);
                            }
                            Err(e) => warn!("GroupSyncRequest yanıtlanamadı: {}", e),
                        }
                    }
                }
                serde_json::json!({"type": "noop"})
            }
            MessageContent::LeaveGroupRequest { group_id } => {
                // bkz. `leave_group` dokümantasyonu — bu isteği yalnızca
                // gerçekten bu grubun kurucusu isek işleriz (`remove_from_group`
                // zaten bunu kendi içinde kontrol eder, ör. bir hata/kafa
                // karışıklığı sonucu kurucu olmayan bir cihaza ulaşırsa
                // sessizce reddedilir, grup durumu bozulmaz). Ack HER
                // durumda gönderilir — ayrılan üyenin isteği en azından
                // BİZE ulaştı, `awaiting_confirmation` yeniden denemeyi
                // durdurabilir (işleyemesek bile, örn. bu grubun kurucusu
                // biz değilsek, tekrar denemenin bir faydası olmaz).
                self.send_ack(&peer_fp, &message_id);
                if let Err(e) = self.remove_from_group(&group_id, &sender_identity_id, false) {
                    error!("LeaveGroupRequest işlenemedi (group={}, ayrılan={}): {}", group_id, crate::log_id(&sender_identity_id), e);
                    return Ok(serde_json::json!({"type": "noop"}).to_string());
                }
                serde_json::json!({"type": "member_left", "group_id": group_id, "identity_id": sender_identity_id})
            }
            MessageContent::AddressAnnounce { multiaddr } => {
                // bkz. packet.rs `AddressAnnounce` dokümantasyonu — bu, tam
                // olarak `remember_device_addr`'ın (bkz. o fonksiyon —
                // `.onion` ise ayrıca `device_onion_addr`'a da yazar)
                // beklediği biçimde tam bir multiaddr (`.../p2p/<peer_id>`
                // dahil). Kasıtlı olarak Ack GÖNDERİLMİYOR/arşivlenmiyor —
                // `TypingIndicator` ile AYNI gerekçe (bkz. o notun ayrıntısı):
                // bu bir "o anki en iyi adresim" anlık görüntüsü, göndericinin
                // kendisi zaten Tor hazır olduğunda/ağ değiştiğinde periyodik
                // olarak yeniden yollar (bkz. `announce_address_to_all_contacts`
                // çağıranları) — süresiz onay bekleme mekanizmasının burada
                // hiçbir değeri yok.
                // Only the sender's own onion address: a contact must not
                // point us at a stranger to dial again and again. A PeerId
                // other than the one we know for the device (or any, when none
                // is known) counts only when the device delivered this itself
                // over that PeerId's connection (a restored device has a new one).
                let announced = multiaddr.parse::<Multiaddr>().ok()
                    .filter(is_onion_multiaddr)
                    .and_then(|m| extract_peer_id(&m));
                let own_pid = announced.filter(|pid| {
                    self.device_to_peer_id.get(&peer_fp).map_or(false, |known| known == pid) || source == Some(*pid)
                });
                if own_pid.is_some() {
                    self.remember_device_addr(&peer_fp, &multiaddr);
                } else {
                    warn!("AddressAnnounce yok sayıldı (onion değil ya da başka bir PeerId): {}", crate::log_id(&peer_fp));
                }
                serde_json::json!({"type": "address_announce", "peer": peer_fp})
            }
            // Çoklu-cihaz (spec 1.5 adım 5-6): birincil cihaz, bu (ikincil)
            // cihazı kimliğine kabul etti. `peer_fp` = gönderen = birincil.
            MessageContent::DeviceLinkGrant { identity_id, device_add, sync, nonce } => {
                // Acked once adopted: acked first, a failure here lost the
                // grant and the link never completed.
                match self.adopt_device_link(&peer_fp, &identity_id, &device_add, &sync, &nonce) {
                    Ok(linked) => {
                        self.send_ack(&peer_fp, &message_id);
                        if linked { serde_json::json!({"type": "device_linked", "identity_id": identity_id}) } else { serde_json::json!({"type": "noop"}) }
                    }
                    Err(e) => {
                        error!("DeviceLinkGrant benimsenemedi: {}", e);
                        // Past the link window no retry can be adopted (a new
                        // QR has a new nonce): acked, or it came for 7 days.
                        if current_time_ms() > self.link_request_open_until {
                            self.send_ack(&peer_fp, &message_id);
                        }
                        serde_json::json!({"type": "noop"})
                    }
                }
            }
            // Çoklu-cihaz (spec 1.5 adım 5, kişi tarafı): bir kimliğe yeni cihaz
            // eklendi. İmzayı o kimliğin bilinen aktif cihazıyla doğrula.
            MessageContent::DeviceAddNotice { device_add, device } => {
                self.send_ack(&peer_fp, &message_id);
                match self.apply_device_add_notice(&device_add, &device, &sender_identity_id) {
                    Ok(()) => serde_json::json!({"type": "device_change", "identity_id": device_add.identity_id}),
                    Err(e) => { error!("DeviceAddNotice reddedildi: {}", e); serde_json::json!({"type": "noop"}) }
                }
            }
            // Çoklu-cihaz (spec 1.6): imzalı cihaz iptali.
            MessageContent::DeviceRevokeNotice(revoke) => {
                // Ack ÖNCE gönderilir — self-revoke'ta wipe ratchet'i sildikten
                // sonra artık Ack üretemeyiz, ama iptali başlatan cihazın "bu
                // cihaz bildirimi aldı" bilmesi değerli.
                self.send_ack(&peer_fp, &message_id);
                match self.apply_device_revoke_notice(&revoke, &peer_fp) {
                    // Bu cihazın KENDİ iptali — yerel durum tamamen silindi.
                    // UI bunu alınca Keystore/vault sırrını da silip
                    // onboarding'e dönmeli (bkz. `wipe_all_local_state`).
                    // `self_revoked` is already queued by `apply_device_revoke_notice`.
                    Ok(true) => serde_json::json!({"type": "noop"}),
                    Ok(false) => serde_json::json!({"type": "device_change", "identity_id": revoke.identity_id}),
                    Err(e) => { error!("DeviceRevokeNotice reddedildi: {}", e); serde_json::json!({"type": "noop"}) }
                }
            }
            // Çoklu-cihaz (spec 1.7): kardeş cihazdan gelen delta senkron —
            // SADECE gönderen kendi kimliğimin bir cihazıysa kabul et.
            MessageContent::DeviceSync(sync) => {
                self.send_ack(&peer_fp, &message_id);
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if from_sibling {
                    // Kardeş cihaz bize kök arşiv anahtarını (ARK) verdiyse
                    // benimse — bu olmadan sunucudaki geçmiş bu cihazda
                    // ÇÖZÜLEMEZ. Zaten bir ARK'ımız varsa DOKUNMA: iki
                    // cihaz aynı anda kurulup farklı anahtar üretmiş
                    // olabilir, o durumda sessizce üzerine yazmak eski
                    // arşivi okunamaz hâle getirirdi.
                    // The primary's key replaces ours (it rotates the key
                    // when it revokes a device); bkz. `adopt_archive_key`.
                    if let Some(ark) = &sync.archive_root_key {
                        let had_key = self.archive_root_key.is_some();
                        if self.adopt_archive_key(ark, my_id_now.as_deref() == Some(peer_fp.as_str())) {
                            info!("Kardeş cihazdan kök arşiv anahtarı alındı");
                            // Rows written before the first key came were never
                            // queued. Not after a rotation: the primary uploads
                            // the history again, this device does not.
                            if !had_key && self.servers.iter().any(|s| s.store_history) {
                                self.backfill_server_archive();
                            }
                        }
                    }
                    let learned = self.import_sync_payload(&sync);
                    // Yeni öğrenilen kişilere kendimizi tanıt (bu cihazı da
                    // tanısınlar) — anahtarlarımızı güvenilir biçimde ver.
                    let own_dev = self.own_synced_device();
                    let own_da = self.own_device_add.clone();
                    for id in &learned {
                        for fp in self.active_devices_for_identity(id) {
                            let _ = self.send_identity_exchange(&fp);
                            if let (Some(da), Some(dev)) = (own_da.clone(), own_dev.clone()) {
                                let _ = self.send_message_content(fp, &MessageContent::DeviceAddNotice { device_add: da, device: dev }, None);
                            }
                        }
                    }
                    serde_json::json!({"type": "sync"})
                } else {
                    serde_json::json!({"type": "noop"})
                }
            }
            // Çoklu-cihaz (spec 1.7.1): kardeşten "okundu" senkronu.
            MessageContent::ReadStateSync { conversation_identity_id, group_id, read_at_ms } => {
                // Ack KOŞULSUZ (bkz. DeviceSync kolu aynı desen): bu artık
                // güvenilir teslimli, ve reddedilen bir senkronu sonsuza dek
                // yeniden denetmenin hiçbir değeri yok — küçük bir ipucu
                // mesajı, kaybolması "sohbet diğer cihazda okunmadı görünür"
                // demek, sonsuz trafikten iyidir.
                self.send_ack(&peer_fp, &message_id);
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if from_sibling {
                    // Yerel sohbet anahtarına çevir: grup → "group:<id>",
                    // 1:1 → kişinin kanonik cihazı (bu cihazdaki sohbet
                    // anahtarı). Kotlin bunu ReadStatePrefs'e uygular.
                    let conversation = if let Some(gid) = group_id {
                        format!("group:{}", gid)
                    } else if let Some(id) = conversation_identity_id {
                        self.canonical_device_for_identity(&id).unwrap_or_default()
                    } else {
                        String::new()
                    };
                    if conversation.is_empty() {
                        serde_json::json!({"type": "noop"})
                    } else {
                        serde_json::json!({"type": "read_state_sync", "conversation": conversation, "read_at": read_at_ms})
                    }
                } else {
                    // KARŞI TARAFTAN (2026-09-07): "okuma sınırı" = TOPLU
                    // görüldü makbuzu. Gönderen = okuyan. bkz.
                    // `apply_incoming_read_watermark`.
                    let viewer = self.known_remote_devices.get(&peer_fp).map(|d| d.identity_id.clone());
                    match viewer {
                        Some(viewer_id) => {
                            let affected = self.apply_incoming_read_watermark(
                                &peer_fp, group_id.as_deref(), &viewer_id, read_at_ms,
                            );
                            if affected.is_empty() {
                                serde_json::json!({"type": "noop"})
                            } else {
                                // Seen state reaches the server archive once per
                                // batch, on its newest message (oldest first).
                                if let Some(newest) = affected.last() {
                                    self.requeue_archive_row(group_id.as_deref(), &chat_key, newest);
                                }
                                serde_json::json!({
                                    "type": "seen_bulk",
                                    "peer": peer_fp,
                                    // 1:1 için `null` (boş string DEĞİL): ChatActivity
                                    // dinleyicisi `!isNull("group_id")` olan olayı
                                    // grup olayı sayıp atıyor.
                                    "group_id": group_id.clone(),
                                    "viewer_identity_id": viewer_id,
                                    "up_to_ms": read_at_ms,
                                    "message_ids": affected,
                                })
                            }
                        }
                        None => serde_json::json!({"type": "noop"}),
                    }
                }
            }
            // Çoklu-cihaz (spec 1.7): kendi başka cihazımın gönderdiği mesaj/
            // düzenleme/silme — burada da "gönderilen" olarak göster.
            MessageContent::SiblingEcho { conversation_identity_id, group_id, body } => {
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if !from_sibling {
                    serde_json::json!({"type": "noop"})
                } else {
                    let own_id = my_id_now.clone().unwrap_or_default();
                    // 1:1 için yerel sohbet anahtarı (bu cihazdaki kanonik cihaz).
                    let chat_key = conversation_identity_id.as_ref()
                        .and_then(|id| self.canonical_device_for_identity(id));
                    // A contact deleted on this device only: there is nowhere
                    // to store the echo, ever. Unacked, the sibling sent each
                    // one again for 7 days.
                    if group_id.is_none() && chat_key.is_none()
                        && conversation_identity_id.as_deref().map_or(false, |id| self.contact_removed_locally(id))
                    {
                        self.send_ack(&peer_fp, &message_id);
                        return Ok(serde_json::json!({"type": "noop"}).to_string());
                    }
                    // Acked after the body is handled, and not at all when it
                    // could not be stored (contact not synced, archive error):
                    // the sibling then sends again.
                    let mut ack = true;
                    let ev = match body {
                        SiblingEchoBody::Text { message_id: mid, text, sent_at_ms, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id } => {
                            // Güvenilirlik düzeltmesi (çift arşiv) — 1:1/grup
                            // Text kollarındaki AYNI dedup: kardeşin
                            // `regen_content` tazelemesi/restart yeniden
                            // gönderimi aynı yankıyı ikinci kez getirebilir.
                            // Ack aşağıda (`ack`) gönderilir.
                            // In this chat: with the global check, a member who
                            // saw the id could send any text under it first and
                            // the echo was dropped as a duplicate.
                            let dup = match (&group_id, &chat_key) {
                                (Some(gid), _) => self.message_exists_in_chat(&mid, Some(gid.as_str()), ""),
                                (None, Some(ck)) => self.message_exists_in_chat(&mid, None, ck),
                                _ => false,
                            };
                            // A group left on this device gets no new rows.
                            if dup || group_id.as_ref().map_or(false, |gid| !self.groups.contains_key(gid)) {
                                serde_json::json!({"type": "noop"})
                            } else if let Some(gid) = &group_id {
                                ack = self.archive_group_message(gid, &own_id, "sent", text.as_bytes(), Some(&mid),
                                    reply_to_message_id.as_deref(), reply_to_preview.as_deref(), reply_to_sender_identity_id.as_deref(), sent_at_ms, None).is_ok();
                                serde_json::json!({
                                    "type": "sibling_group_message", "group_id": gid, "message_id": mid,
                                    "text": text, "sent_at_ms": sent_at_ms, "sender_identity_id": own_id,
                                    "reply_to_message_id": reply_to_message_id, "reply_to_preview": reply_to_preview,
                                    "reply_to_sender_identity_id": reply_to_sender_identity_id
                                })
                            } else if let Some(ck) = &chat_key {
                                ack = self.archive_message(ck, "sent", text.as_bytes(), Some(&mid),
                                    Some(MessageSendStatus::Sent.as_str()), reply_to_message_id.as_deref(), reply_to_preview.as_deref(), sent_at_ms).is_ok();
                                serde_json::json!({
                                    "type": "sibling_message", "peer": ck, "message_id": mid, "text": text,
                                    "sent_at_ms": sent_at_ms, "reply_to_message_id": reply_to_message_id,
                                    "reply_to_preview": reply_to_preview
                                })
                            } else {
                                ack = false;
                                serde_json::json!({"type": "noop"})
                            }
                        }
                        SiblingEchoBody::Edit { target_message_id, new_text, edited_at_ms } => {
                            if !self.edit_or_delete_target_exists(&target_message_id) {
                                // Stored and acked; applied when the message comes.
                                ack = self.remember_sibling_op(&target_message_id, Some(&new_text), edited_at_ms);
                                serde_json::json!({"type": "noop"})
                            } else if !self.own_sent_target(group_id.as_deref(), chat_key.as_deref().unwrap_or(""), &target_message_id) {
                                warn!("Kardeş Edit yok sayıldı: hedef bizim gönderdiğimiz bir mesaj değil ({})", target_message_id);
                                serde_json::json!({"type": "noop"})
                            } else if let Some(gid) = &group_id {
                                self.apply_edit_to_archive(Some(gid), "", &target_message_id, &new_text, edited_at_ms);
                                serde_json::json!({"type": "group_edit", "group_id": gid, "message_id": target_message_id, "text": new_text})
                            } else if let Some(ck) = &chat_key {
                                self.apply_edit_to_archive(None, ck, &target_message_id, &new_text, edited_at_ms);
                                serde_json::json!({"type": "edit", "peer": ck, "message_id": target_message_id, "text": new_text})
                            } else {
                                serde_json::json!({"type": "noop"})
                            }
                        }
                        SiblingEchoBody::Reaction { target_message_id, emoji, reacted_at_ms } => {
                            // Yankı KENDİ tepkim — bu yüzden tepki veren
                            // kendi kimliğim (`own_id`), kardeş cihazın
                            // kimliği değil (ikisi zaten aynı identity).
                            // The contact arm's checks; a 1:1 row's chat is the
                            // conversation identity, not mine.
                            let chat_identity = if group_id.is_some() { own_id.as_str() } else { conversation_identity_id.as_deref().unwrap_or("") };
                            if emoji.len() > 64 || !self.reaction_fits_chat(&target_message_id, group_id.as_deref(), chat_identity) {
                                warn!("Kardeş tepkisi yok sayıldı: hedef bu sohbete ait değil ya da emoji çok uzun");
                                serde_json::json!({"type": "noop"})
                            } else if !self.apply_reaction(&target_message_id, &own_id, &emoji, reacted_at_ms) {
                                ack = false; // write failed: the sibling sends it again
                                serde_json::json!({"type": "noop"})
                            } else if let Some(gid) = &group_id {
                                let summary = self.reactions_summary(&target_message_id);
                                serde_json::json!({"type": "reaction", "group_id": gid, "message_id": target_message_id, "reactions": summary})
                            } else if let Some(ck) = &chat_key {
                                let summary = self.reactions_summary(&target_message_id);
                                serde_json::json!({"type": "reaction", "peer": ck, "message_id": target_message_id, "reactions": summary})
                            } else {
                                serde_json::json!({"type": "noop"})
                            }
                        }
                        SiblingEchoBody::File { offer } => match *offer {
                            MessageContent::FileOffer {
                                file_id, file_name, mime_type, total_size, file_key, sha256_hex,
                                preview_jpeg, duration_ms, chunk_size, chunk_hashes,
                                caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id, sticker, sticker_origin, ..
                            } => {
                                // Aynı yankı ikinci kez (regen/restart): satır varsa
                                // dokunma — `receive_file_offer`'ın INSERT OR REPLACE'i
                                // tamamlanmış bir indirmeyi sıfırlardı.
                                let exists = self.db.as_ref().map_or(false, |c| {
                                    c.query_row("SELECT 1 FROM files WHERE file_id = ?1", params![file_id], |_| Ok(())).is_ok()
                                });
                                if exists || self.take_pending_sibling_delete(&file_id) {
                                    serde_json::json!({"type": "noop"})
                                } else if group_id.is_none() && chat_key.is_none() {
                                    ack = false;
                                    serde_json::json!({"type": "noop"})
                                } else {
                                    let mut ev = self.receive_file_offer(
                                        &peer_fp, &own_id, group_id.clone(), &file_id, &file_name, &mime_type,
                                        total_size, &file_key, &sha256_hex, &preview_jpeg, duration_ms, chunk_size, &chunk_hashes,
                                        &caption, reply_to_message_id.as_deref(), reply_to_preview.as_deref(),
                                        reply_to_sender_identity_id.as_deref(), sticker, sticker_origin.as_deref(),
                                    );
                                    if ev["type"] == "file_offer" {
                                        // Satır benim giden ekim. Grupta kaynak kardeş
                                        // kalır; 1:1'de sütun sohbet anahtarıdır (ek
                                        // doğru sohbette listelensin) ve yeniden
                                        // indirmede `download_file` kardeşleri aday ekler.
                                        let peer_col = if group_id.is_some() { peer_fp.clone() } else { chat_key.clone().unwrap_or_default() };
                                        if let Some(conn) = &self.db {
                                            let _ = conn.execute(
                                                "UPDATE files SET direction = 'sent', peer_device_fingerprint = ?1 WHERE file_id = ?2",
                                                params![peer_col, file_id],
                                            );
                                        }
                                        ev["type"] = "sibling_file".into();
                                        ev["peer"] = peer_col.into();
                                    } else if ev["type"] == "noop" {
                                        ack = false; // row not written, see `receive_file_offer`
                                    }
                                    ev
                                }
                            }
                            _ => serde_json::json!({"type": "noop"}),
                        },
                        SiblingEchoBody::Sticker { jxl, origin, id, part, parts } => 'sticker: {
                            // A part of a big sticker: kept until all are here.
                            let jxl = if parts > 1 {
                                match self.add_sticker_part(&id, part, parts, jxl) {
                                    Ok(Some(whole)) => whole,
                                    Ok(None) => break 'sticker serde_json::json!({"type": "noop"}),
                                    Err(e) => {
                                        warn!("Kardeş sticker parçası atıldı: {}", e);
                                        break 'sticker serde_json::json!({"type": "noop"});
                                    }
                                }
                            } else {
                                jxl
                            };
                            // Not a sticker at all: final (acked). Anything else
                            // (keys not loaded, disk, DB): sent again.
                            let mut not_a_sticker = false;
                            let stored = self.attachments_dir().and_then(|dir| {
                                let tmp = dir.join("plain_cache").join(format!(".sticker-{}.jxl", uuid::Uuid::new_v4()));
                                let r = std::fs::write(&tmp, &jxl).map_err(|e| e.to_string()).and_then(|()| {
                                    let r = self.store_sticker(&tmp, false, origin.as_deref());
                                    not_a_sticker = r.is_err() && attachments::sticker_check(&tmp).is_err();
                                    r
                                });
                                let _ = std::fs::remove_file(&tmp);
                                r
                            });
                            match stored {
                                Ok(id) => serde_json::json!({"type": "stickers_changed", "added": id}),
                                Err(e) => {
                                    warn!("Kardeş sticker saklanamadı: {}", e);
                                    ack = not_a_sticker;
                                    serde_json::json!({"type": "noop"})
                                }
                            }
                        }
                        SiblingEchoBody::StickersRequest { have } => {
                            // Only the root device answers (a desktop's request
                            // reaches every sibling). Off the core lock: one
                            // decrypt + send per sticker, the lock taken each time.
                            if self.own_device_add.is_none() {
                                let have: std::collections::HashSet<String> = have.into_iter().collect();
                                let ids: Vec<String> = self.sticker_ids().into_iter().filter(|id| !have.contains(id)).collect();
                                info!("Sticker request from sibling {}: sending {}", crate::log_id(&peer_fp), ids.len());
                                let to = peer_fp.clone();
                                std::thread::spawn(move || {
                                    let _guard = crate::RUNTIME.enter();
                                    for id in ids {
                                        crate::core_lock().send_sticker_to_sibling(&to, &id);
                                    }
                                });
                            }
                            serde_json::json!({"type": "noop"})
                        }
                        SiblingEchoBody::StickerRemoved { id } => match self.delete_sticker(&id, false) {
                            Ok(()) => serde_json::json!({"type": "stickers_changed", "removed": id}),
                            Err(e) => {
                                warn!("Kardeş sticker silinemedi: {}", e);
                                // A bad id is final; a DB error is sent again.
                                ack = self.sticker_enc_path(&id).is_err();
                                serde_json::json!({"type": "noop"})
                            }
                        },
                        SiblingEchoBody::GroupLeft => match &group_id {
                            Some(gid) if self.groups.contains_key(gid) => {
                                self.remove_group_locally(gid);
                                serde_json::json!({"type": "group_updated", "group_id": gid})
                            }
                            _ => serde_json::json!({"type": "noop"}),
                        },
                        SiblingEchoBody::Delete { target_message_id } => {
                            // birincil cihazdaki
                            // silme, ekli dosyayı da diskten kaldırıyor
                            // (bkz. `delete_message`/`delete_group_message`
                            // aynı çağrı) ama bu kardeş-yankı kolu önceden
                            // SADECE arşiv satırını güncelliyordu — ikincil
                            // cihazda dosya kalıcı olarak diskte kalırdı
                            // (sızıntı, hiçbir zaman temizlenmezdi).
                            if !self.edit_or_delete_target_exists(&target_message_id) {
                                ack = self.remember_sibling_op(&target_message_id, None, 0);
                                serde_json::json!({"type": "noop"})
                            } else if !self.own_sent_target(group_id.as_deref(), chat_key.as_deref().unwrap_or(""), &target_message_id) {
                                warn!("Kardeş Delete yok sayıldı: hedef bizim gönderdiğimiz bir mesaj değil ({})", target_message_id);
                                serde_json::json!({"type": "noop"})
                            } else {
                                self.purge_attachment_if_exists(&target_message_id);
                                if let Some(gid) = &group_id {
                                    self.apply_delete_to_archive(Some(gid), "", &target_message_id);
                                    self.sign_own_group_tombstone(gid, &target_message_id);
                                    serde_json::json!({"type": "group_delete", "group_id": gid, "message_id": target_message_id})
                                } else if let Some(ck) = &chat_key {
                                    self.apply_delete_to_archive(None, ck, &target_message_id);
                                    serde_json::json!({"type": "delete", "peer": ck, "message_id": target_message_id})
                                } else {
                                    serde_json::json!({"type": "noop"})
                                }
                            }
                        }
                    };
                    if ack {
                        self.send_ack(&peer_fp, &message_id);
                    }
                    ev
                }
            }
            // Çoklu-cihaz (spec 1.7): kardeşten geçmiş geri-doldurma isteği.
            MessageContent::FirstContactSecret { secret, group_id } => {
                self.send_ack(&peer_fp, &message_id);
                // Kept only by the founder of that group: only it forwards the secret.
                let me = self.my_identity_id().unwrap_or_default();
                let founder_of = self.groups.get(&group_id)
                    .map_or(false, |g| g.founder_identity_id == me && g.is_member(&sender_identity_id));
                if secret.len() == 16 && founder_of {
                    self.meta_put(&format!("gf:{}:{}", peer_fp, group_id), &hex::encode(&secret));
                }
                serde_json::json!({"type": "noop"})
            }
            MessageContent::AccountDeleted { .. } => {
                self.send_ack(&peer_fp, &message_id);
                let my_id_now = self.my_identity_id();
                let from_sibling = my_id_now.as_deref() == Some(sender_identity_id.as_str());
                // Only the identity's first device deletes the account (bkz.
                // `verify_device_auth`): a stolen secondary wiped the others,
                // and made every contact drop the identity.
                if peer_fp != sender_identity_id {
                    warn!("AccountDeleted ana cihazdan gelmedi, yok sayıldı (peer={})", crate::log_id(&peer_fp));
                    serde_json::json!({"type": "noop"})
                } else if from_sibling {
                    // Hesap başka bir cihazımdan silindi: bu cihaz da silinir
                    // (UI `self_revoked` ile dosyaları temizleyip yeniden başlar).
                    warn!("Hesap kardeş cihazdan silindi (peer={}) — yerel durum siliniyor", crate::log_id(&peer_fp));
                    self.wipe_all_local_state();
                    serde_json::json!({"type": "self_revoked"})
                } else {
                    let display_name = self.identity_to_contact.get(&sender_identity_id)
                        .and_then(|cid| self.contacts.get(cid))
                        .map(|c| c.display_name.clone())
                        .unwrap_or_default();
                    let group_ids = self.apply_account_deleted(&sender_identity_id);
                    info!("Kişi hesabını sildi: {} ({} grup)", crate::log_id(&sender_identity_id), group_ids.len());
                    serde_json::json!({
                        "type": "account_deleted", "peer": chat_key,
                        "identity_id": sender_identity_id,
                        "display_name": display_name,
                        "group_ids": group_ids,
                    })
                }
            }
            MessageContent::SiblingHistoryRequest { per_conversation_limit, conversation_identity_id, group_id, before_timestamp, since_timestamp, after_timestamp } => {
                // Spec dışı, ağ sağlamlığı düzeltmesi ("ack kullanımını
                // genişlet"): önceden bu paket hiç Ack'lenmiyordu — tek
                // güvence 5 dakikalık debounce'lu periyodik yeniden
                // tetiklemeydi (bkz. `request_sibling_backfill`), yani kayıp
                // bir istek en kötü senaryoda 5 dakika fark edilmeden
                // kalabiliyordu. `LeaveGroupRequest` ile AYNI gerekçe: Ack
                // HER durumda gönderilir — istek en azından BİZE ulaştı,
                // gönderenin `awaiting_confirmation` yeniden denemesi
                // durabilir (yanıt üretilemese/gönderilemese bile, ör.
                // gönderen artık gerçek bir kardeş değilse).
                self.send_ack(&peer_fp, &message_id);
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if from_sibling {
                    // A "Fetch older history" window: one window, at most 30 days.
                    let window = before_timestamp.zip(after_timestamp)
                        .map(|(b, a)| (b, a.max(b.saturating_sub(HISTORY_FETCH_WINDOW_MS as i64))));
                    let limit = per_conversation_limit.min(if window.is_some() { HISTORY_SYNC_MAX_MESSAGES } else { SIBLING_BACKFILL_PER_CONVERSATION });
                    let (entries, more) = self.build_sibling_history_response(limit, conversation_identity_id.as_deref(), group_id.as_deref(), before_timestamp, since_timestamp, window);
                    // The echo is the request's own window, not the clamped one.
                    let resp = MessageContent::SiblingHistoryResponse { entries, window: before_timestamp.zip(after_timestamp), more };
                    if let Err(e) = self.send_message_content(peer_fp.clone(), &resp, None) {
                        error!("SiblingHistoryResponse gönderilemedi: {}", e);
                    }
                }
                serde_json::json!({"type": "noop"})
            }
            // Çoklu-cihaz (spec 1.7): kardeşin gönderdiği geçmiş — arşive işle.
            MessageContent::SiblingHistoryResponse { entries, window, more } => {
                let my_id_now = self.my_identity_id();
                let from_sibling = self.known_remote_devices.get(&peer_fp)
                    .map(|d| my_id_now.as_deref() == Some(d.identity_id.as_str()))
                    .unwrap_or(false);
                if !from_sibling {
                    serde_json::json!({"type": "noop"})
                } else {
                    // Spec dışı, dış inceleme düzeltmesi ("sibling backfill
                    // sayfalama desteklemiyor"): `request_older_sibling_history`
                    // TEK bir sohbete daralmış bir istek gönderir, bu yüzden
                    // yanıt da (varsa) o TEK sohbetin girdilerinden oluşur —
                    // bunu tespit edip, ekranda açık bir sohbet varsa ANINDA
                    // birleşsin diye `older_history`/`older_group_history` ile
                    // AYNI şekle sokuyoruz (Kotlin/Linux tarafı zaten bu iki
                    // olay türünü biliyor, yeni bir tüketici yazmaya gerek
                    // yok). Otomatik/geniş kapsamlı `request_sibling_backfill`
                    // yanıtı (birden fazla/karışık sohbet) için eski genel
                    // "history_backfilled" bildirimi korunur.
                    let single_group: Option<String> = {
                        let gids: std::collections::HashSet<&str> = entries.iter().filter_map(|e| e.group_id.as_deref()).collect();
                        if gids.len() == 1 && entries.iter().all(|e| e.group_id.is_some()) {
                            gids.into_iter().next().map(|s| s.to_string())
                        } else {
                            None
                        }
                    };
                    let single_conversation: Option<String> = if single_group.is_none() {
                        let ids: std::collections::HashSet<&str> = entries.iter().filter_map(|e| e.conversation_identity_id.as_deref()).collect();
                        if ids.len() == 1 && entries.iter().all(|e| e.conversation_identity_id.is_some()) {
                            ids.into_iter().next().map(|s| s.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    // NOT: `SiblingHistoryEntry` ayrı bir "yerel alınma anı"
                    // taşımıyor (`ArchivedMessage.timestamp`'in aksine) —
                    // `sent_at_ms` zaten `load_message_history`'nin
                    // `COALESCE(NULLIF(sent_at_ms,0), timestamp)` ile ürettiği
                    // "etkin" değer, bu yüzden `timestamp` alanı için de
                    // güvenle kullanılabilir.
                    let (merged, press_chat) = self.apply_sibling_reply(&peer_fp, window, more, entries);
                    // Decided by the request, not by the shape of the answer
                    //no window and no press it answers, while
                    // a backfill request is open, is the unscoped backfill,
                    // also when all its rows belong to one chat.
                    let backfill = window.is_none() && press_chat.is_none()
                        && self.sibling_backfill_since.get(&peer_fp).map_or(false, |s| s.0 > 0);
                    // A press answer is about its chat, empty or not.
                    let (single_group, single_conversation) = match press_chat {
                        Some(c) if self.groups.contains_key(&c) => (Some(c), None),
                        Some(c) => (None, Some(c)),
                        None if backfill => (None, None),
                        None => (single_group, single_conversation),
                    };
                    // an answer to the unscoped backfill (an empty one
                    // too) moves this sibling's watermark.
                    if backfill {
                        if let Some(state) = self.sibling_backfill_since.get_mut(&peer_fp) {
                            if state.0 > 0 {
                                *state = (0, state.0);
                            }
                        }
                    }
                    if let Some(gid) = single_group {
                        serde_json::json!({"type": "older_group_history", "group_id": gid, "messages": merged})
                    } else if let Some(id) = single_conversation {
                        match self.canonical_device_for_identity(&id) {
                            Some(ck) => serde_json::json!({"type": "older_history", "peer": ck, "messages": merged}),
                            None => serde_json::json!({"type": "history_backfilled"}),
                        }
                    } else {
                        serde_json::json!({"type": "history_backfilled"})
                    }
                }
            }
        };
        Ok(event.to_string())
    }
}
