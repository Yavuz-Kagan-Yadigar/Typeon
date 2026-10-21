# Typeon — Teknik Devir Dökümanı (Mimari, Güvenlik, Çalışma Anı Algoritmaları)

Bu doküman `HANDOFF.md`'nin (çalışma kuralları, dosya haritası) teknik tamamlayıcısıdır. Aşağıdaki her iddia kaynak kodda doğrulandı; dosya/fonksiyon adı verilmiştir. Çelişki halinde **kod** doğrudur (`SECURITY.md` ve `Description.md` kısmen eskidir).

İçindekiler: 1 Katmanlar · 2 Kripto ilkelleri · 3 Kimlik ve güven · 4 Oturum kurulumu (handshake) · 5 Ratchet · 6 Mesaj paketi · 7 Gönderim yolu · 8 Alım yolu · 9 Teslim/yeniden deneme · 10 Çoklu cihaz · 11 Grup · 12 Ağ katmanı · 13 Sunucu · 14 Yerel depolama · 15 Dosya/medya · 16 Arama · 17 Tehdit modeli · 18 Sabitler tablosu

---

## 1. Katmanlar

```
┌────────────────────────────────────────────────────────────────┐
│ UI:  Android Kotlin (ChatActivity, P2PService…)  | Linux GTK4   │
├────────────────────────────────────────────────────────────────┤
│ Köprü: JNI (lib.rs sonu, P2PLib.kt)  | api.rs (Linux, JNI'siz)  │
├────────────────────────────────────────────────────────────────┤
│ Çekirdek (crate p2p_messenger): P2PCore  — lib.rs              │
│   iş mantığı, DB, libp2p swarm, Tor, sunucu istemcisi, arama   │
├────────────────────────────────────────────────────────────────┤
│ typeon-crypto: identity, ratchet, packet, server_proto, seal   │
├────────────────────────────────────────────────────────────────┤
│ libp2p (noise, yamux, gossipsub, kad, relay, dcutr, req-resp)  │
│ arti (Tor istemci + onion servis) · SQLCipher · ml-kem/ml-dsa   │
└────────────────────────────────────────────────────────────────┘
          (isteğe bağlı) typeon-server: store-and-forward
```

- **Tek `P2PCore` örneği**, global `core_lock()` mutex'i arkasında. Her JNI/api çağrısı `catch_panic` + `RUNTIME.enter()` + `core_lock()` sırasıyla girer. Yani çekirdek **tek kilitli, olay-sürümlü**: paralel iş yok, uzun işlem kilidi tutar (`lock_watch` modülü kilit süresini izler).
- Ağ olayları **çekerek (poll)** işlenir: Kotlin `P2PService` döngüsü `poll_events()` çağırır; çekirdek swarm olaylarını `swarm.next().now_or_never()` ile bloklamadan boşaltır, JSON olay listesi döndürür.
- Linux istemci aynı çekirdeği `api.rs` üzerinden çağırır; protokolün ikinci kopyası yoktur.

---

## 2. Kripto ilkelleri (hepsi doğrulandı)

| Amaç | Algoritma | Yer |
|---|---|---|
| İmza | **Ed25519 + ML-DSA-87**, ikisi de üretilir ve ikisi de doğrulanır | `verify_hybrid_signature*` lib.rs ~21591 |
| Anahtar anlaşma | **X25519 + ML-KEM-1024** (ikisinin çıktısı birleştirilir) | `ratchet.rs` |
| KDF | HKDF-SHA256, etiketli (`p2pmsg-v0.x-…`) + transcript hash | `derive_keys`, `kem_key` |
| AEAD | ChaCha20-Poly1305 (mesaj: nonce = mesaj numarası; yerel satırlar: rastgele 12 bayt nonce) | `encrypt_next`, `seal_with` |
| Fingerprint | SHA3-256(ed25519‖mldsa‖x25519‖mlkem), uzunluklar sabit (32, 2592, 32, 1568) | `identity.rs compute_fingerprint` |
| Kurtarma dosyası | Argon2id + ChaCha20-Poly1305 | `export_recovery` |
| AppLock | PBKDF2-HMAC-SHA256, 300.000 iterasyon (eski 120.000 okunur) | `util/AppLock.kt` |
| Yerel DB | SQLCipher; anahtar = HKDF(storage_key, `typeon-db-sqlcipher-v1`) | `db_key_pragma` |

Önemli ayrıntılar:
- X25519 ortak sırrı "contributory" değilse (küçük mertebe nokta) reddedilir (`x25519()` ratchet.rs).
- ML-KEM şifre çözme asla hata vermez (yanlış anahtar → rastgele bayt); bu yüzden rotasyon bir **kopya üzerinde** denenir, yalnız paket yeni zincirde çözülürse kalıcılaştırılır (bkz. §5).
- Tüm gizli simetrik alanlar (`root_key`, `ck_send`, `ck_recv`, atlanmış anahtarlar, mesaj anahtarı) `zeroize` ile silinir; kütüphane anahtarları `zeroize` feature'ıyla build edilir.
- İmza girdileri **alan-ayrımlı ve uzunluk-önekli**: `p2pmsg-v0.4-handshake`, `p2pmsg-v0.6-packet` (paket), `p2pmsg-v0.5-identity-exchange`, `p2pmsg-v0.4-prekey`, `p2pmsg-v0.1-founder-transfer`.

---

## 3. Kimlik ve güven modeli

### 3.1 Yapı
- **Device**: kendi 4 anahtar çiftini üretir. `device_fingerprint` = anahtarların hash'i.
- **Identity**: `identity_id` = ilk cihazın fingerprint'i (değişmez). Bir identity'de en çok `MAX_ACTIVE_DEVICES = 5` aktif cihaz (`identity.rs`).
- Kişi (`Contact`) ve grup üyeliği `identity_id` ile tutulur. 1:1 sohbet anahtarı cihaz bazlı; kişinin birden çok cihazı varsa `canonical_peer_key` ile tek sohbete indirgenir (kimliğin `min` cihazı).
- **Birincil cihaz** = fingerprint'i `identity_id`'ye eşit olan cihaz. Cihaz ekleme (`sign_device_add`), iptal, hesap silme **yalnız onda** çalışır ("Only the primary device can do this").

### 3.2 İlk temas (pairing)
1. A kendi QR'ını gösterir: `QrPacket` (CBOR, `version=3`): `device_name, identity_id, device_fingerprint, rendezvous_node (onion multiaddr), known_relays, pairing_nonce(16 bayt)`.
2. B tarar. B, A'nın kimliğini **QR'dan alır** (TOFU), ama anahtarları henüz bilmez.
3. İki taraf `IdentityExchange` yollar (`send_identity_exchange_opts`): tam 4 public key + `pairing_proof = SHA3-256("typeon-pairing-nonce"‖uzunluk(nonce, u32 BE)‖nonce‖gönderen_fp)` + hibrit imza (`identity_exchange_signing_input`: imza **alıcı cihazın fingerprint'ini** ve **zaman damgasını** da kapsar; etiket `p2pmsg-v0.5-identity-exchange`). Gönderen zaman damgasını **10 dk'lık kovalara** yuvarlar (`now - now % HANDSHAKE_REDO_MIN_INTERVAL_MS`): yeniden gönderimler bayt-aynı kalır, sunucudaki tekrar elenir.
4. Alan taraf (`process_identity_exchange`) sırayla: kendi cihazından mı → reddet; `keys_match_fingerprint` → değilse reddet; **zaman damgası penceresi** (`HandshakeInit` ile aynı: geçmişe aitse `HANDSHAKE_MAX_AGE_MS` = 7 gün, ileriye aitse `HANDSHAKE_MAX_SKEW_MS` = 10 dk; dışı **imzadan önce** reddedilir); hibrit imza doğrula (imza alıcı fp'yi bağlar → başka bir cihaza oynanmış paket reddedilir); iptal edilmiş cihaz mı → reddet; kimlik iddiası cihaza bağlı mı (`identity_id == fp` ya da imzalı `DeviceAdd`) ; `evaluate_sender_device` ile cihaz güveni kararı; sonra `DeviceRecord` yazılır.
5. İlk-temas mesajları ortak sırla mühürlenmiş posta kutusundan gider (`first_contact_mailbox_id`, sır = pairing nonce); sunucu mailbox adından fingerprint çıkaramaz.

### 3.3 Güven karar akışı (özet)
Her gelen paket/handshake önce `known_remote_devices` içinde gönderen cihazı arar; yoksa "Unknown sender device" → paket `early_handshakes`/`early_packets` tamponuna (bekleyen IdentityExchange için; en çok 64 el sıkışma, kimlik başına 4) ya da düşer. Bilinmeyen/yeni cihaz bir kişiye aitse `device_alert` olayı üretilir ve kullanıcı kararı beklenir (`check_incoming_device`, `contact.rs`). `is_blocked(identity)` / `is_blocked_device(fp)` her yolun başında kontrol edilir.

---

## 4. Oturum kurulumu (HandshakeInit)

Yalnızca **tek-tur, asenkron** (karşı tarafın çevrimiçi olması gerekmez).

**Initiator** (`initiate_handshake_with` → `DeviceRatchetState::initiate`):
1. Karşı cihazın KEM anahtarını seç: varsa alıcının **imzalı prekey**'i (`peer_prekeys`), yoksa uzun-dönem KEM anahtarı (`recipient_prekey_id = 0`).
2. Taze X25519 + ML-KEM-1024 çifti üret. `dh = X25519(own_eph, peer_x25519)`, `(ct, ss) = ML-KEM.Encaps(peer_kyber)`.
3. `ikm = dh ‖ ss`. `transcript = SHA256(init_x ‖ init_kyber ‖ ct ‖ resp_x ‖ resp_kyber)`.
4. `HKDF(ikm)` → etiketler `p2pmsg-v0.2-root`, `…a-to-b`, `…b-to-a` (+ transcript) → `root_key, ck_send, ck_recv`.
5. `HandshakeInit{ sender ids, x25519, kyber_pub, ct, timestamp, recipient_prekey_id, sender_prekey, imza }` yayınlanır. İmza **alıcı fp'ye ve prekey id'lerine bağlıdır** (`handshake_signing_input`).
6. Durum hemen kalıcılaştırılır, `has_responded_to_peer_key = true`.

**Responder** (`process_handshake_init` → `respond`):
1. Gönderen bilinmiyorsa tamponla; iptalse reddet; `sender_identity_id` kayıtla uyuşmalı.
2. İmza doğrula (alıcı fp = kendi aktif fp'miz).
3. **Tekrar oynatma koruması (H37):** zaman damgası ±`HANDSHAKE_MAX_SKEW_MS` (10 dk) içinde olmalı (eski ise `HANDSHAKE_MAX_AGE_MS` = 7 gün pencere), aynı klasik imza pencerede görüldüyse yok sayılır (`recent_handshake_sigs`, kalıcı). Ayrıca **daha önce kabul edilmiş bir el sıkışmadan eski** her init yok sayılır (yalnız sapma penceresini aşan değil) ve **mevcut oturumdan eski** init (`handshake.timestamp < existing.last_rotation`, çakışma penceresi dışında) yok sayılır — gönderen o anahtarları değiştirmiştir.
4. İlk temas `recipient_prekey_id == 0` ise ve prekey varsa **reddedilir** + yeniden el sıkışma başlatılır (id 0 yalnız link penceresinde kabul).
5. **Eşzamanlı el sıkışma çakışması** (90 sn): kendi initiator durumu varsa ve `own_fp < sender_fp` ise kendininkini koru; yoksa karşıyı kabul et (küçük fingerprint kazanır).
6. Kendi prekey/KEM gizli anahtarıyla `respond` → aynı anahtarlar türetilir, `has_responded_to_peer_key = false`, `ratchet_states`'e yazılır, gossipsub topic'ine abone olunur.

Responder determinist olduğundan **ilk göndermeden önce mutlaka rotasyon yapar** (`is_fresh_responder`), böylece replay edilen bir init anahtar+nonce tekrarı yaptıramaz.

**Kendi kendini iyileştirme:** `note_undecryptable` — 2 dk içinde 3 çözülemeyen paket gelirse (oturum yeni değilse) el sıkışma yenilenir; `maybe_redo_handshake` ve `UNDECRYPTABLE_REDO_MIN_INTERVAL_MS` = 2 dk ile hız sınırlanır.

---

## 5. Çift ratchet (`typeon-crypto/src/ratchet.rs`)

**Durum** `DeviceRatchetState`: `root_key, prev_root_key, ck_send, ck_recv, own_x25519_secret, own_kyber_secret, peer_x25519_pubkey, peer_kyber_pubkey, send_message_number, recv_message_number, prev_chain_length, last_rotation, has_responded_to_peer_key, pending_rotation_ct, skipped_keys, old_recv`.

**Simetrik adım** (`chain_step`): `message_key = HKDF(ck, "p2pmsg-v0.1-msgkey")`, `next_ck = HKDF(ck, "p2pmsg-v0.1-chainkey")`. Nonce = 12 bayt, son 4 bayt `message_number` (zincir anahtarı tek kullanımlık olduğu için güvenli). Sayaç taşarsa "Send chain exhausted".

**DH/KEM rotasyonu** (`perform_dh_ratchet`, 30 dk = `RATCHET_ROTATION_MS`):
- Tetikleyen taraf yalnızca "karşının güncel anahtarına henüz cevap vermemiş" taraftır (`!has_responded_to_peer_key`); 30 dk dolunca ya da taze responder ise `should_rotate()` true olur. Deterministik "kim başlatır" kuralı yoktur (Signal modeli).
- Taze X25519+ML-KEM çifti üretir; karşının **mevcut** public key'lerine karşı anlaşır; `ikm = root_key ‖ dh ‖ ss`; yeni root/chain'ler türetilir; sayaçlar sıfırlanır; eski root `prev_root_key` olarak **bir nesil** saklanır; eski alıcı zinciri `old_recv` olarak (atlanmış anahtarlarıyla) saklanır.
- Rotasyon duyurusu (`rotation_kyber_ciphertext` + yeni `ratchet_pubkey`) **her giden pakete eklenir** (`pending_rotation_ct`) karşı taraf yeni zincirde bir paketi çözdüğünü kanıtlayana kadar.

**Alıcı** (`decrypt`):
1. Duyuru varsa ve yeni X25519 anahtarı kayıtlıdan farklıysa: durumu **kopyala**, `respond_to_rotation` uygula, paket yeni zincirde çözülürse kopyayı kabul et (`rotated = true`). Çözülmezse atılır (yanlış/eski duyuru oturumu bozamaz).
2. Değilse mevcut zincirde çöz (`chain_decrypt`): `message_number < next` ise `skipped_keys`'ten, değilse ileri sar. Üst sınırlar: `MAX_SKIP_AHEAD = 10.000` adım (kimlik doğrulanmadan HKDF maliyeti sınırı), önbellekte en çok `MAX_SKIPPED_KEYS = 1000` (en eskiler atılır).
3. Başarısızsa `old_recv` (eski zincir) denenir → rotasyondan önce gönderilmiş paketler kaybolmaz.
4. AEAD doğrulaması başarılı olmadan zincir ilerletilmez (hata halinde imleç silinir).

Kalıcılık: her başarılı adımdan sonra `persist_ratchet_state` (yazılamazsa paket **gönderilmez**: "Oturum durumu yazılamadı"). Atlanmış anahtarlar şifreli olarak ayrı tabloda (`skipped_message_keys`).

---

## 6. Mesaj paketi ve zarf

```
NetworkEnvelope (CBOR) =
   IdentityExchange | Handshake(HandshakeInit) | Message(MessagePacket)

MessagePacket {
  header = SignedHeader (CBOR baytları **olduğu gibi** taşınır)
    { sender_identity_id, sender_device_fingerprint, message_id(UUIDv4),
      ratchet_pubkey (yalnız rotasyonda dolu), message_number, prev_chain_length,
      rotation_kyber_ciphertext (rotasyonda), sent_at_ms }
  ciphertext   = ChaCha20-Poly1305( CBOR(MessageContent), AAD = ham header baytları )
  signature_classical (Ed25519), signature_pq (ML-DSA-87)
}
imza girdisi = ham header baytları ‖ ciphertext ‖ alıcı_fp (uzunluk-önekli, etiket "p2pmsg-v0.6-packet")
```
- **Başlık önce kurulur** (`SignedHeader::new`): imza bu ham baytları, ratchet AEAD de aynı baytları **associated data** olarak kapsar → alıcı yalnız gönderenin şifrelediği başlığa göre işlem yapar; başlığı değiştirilmiş paket etiketi geçmez.
- İmza **alıcıya bağlı**: A→M paketi B'de de geçerli olup oturumu bozamaz (bilinçli protokol kırılması).
- `MessageContent` (CBOR enum): `Text, Reaction, Edit, Delete, HistorySyncRequest/Response, Ack, FileOffer, TypingIndicator, Seen, ProfileUpdate, GroupUpdate, GroupSyncRequest, LeaveGroupRequest, AddressAnnounce, DeviceLinkGrant, DeviceAddNotice, ReadStateSync, DeviceRevokeNotice, FirstContactSecret{secret, group_id}, DeviceSync, SiblingEcho, SiblingHistoryRequest/Response, AccountDeleted, Call{call_id, action, group_id, video, media_key, stream_id, sent_at_ms, participants}, WbOps/WbDigest/WbPageRequest/WbPage`.
- Zarf üst sınırı `MAX_ENVELOPE_BYTES = 1 MiB`.

---

## 7. Gönderim yolu (algoritma)

`send_message` → `send_message_content_inner(peer_fp, content, …)` (lib.rs ~9382):

```
1. ratchets_loaded değilse hata.
2. ensure_connected(peer)           # bağlantı yoksa hemen dial
3. ratchet yoksa initiate_handshake_with(peer)
4. needs_delivery_confirmation = içerik türü Ack'lenenlerden mi
5. if (needs_confirm || Seen) || fresh_responder: maybe_rotate_ratchet(peer)
        -> rotasyon yapıldıysa regen_pending_for_peer (bekleyenleri yeni zincirle yeniden üret)
        (`Seen` de rotasyon sırası alır: yalnız okuyan taraf rotasyonu hiç yapmazsa iyileşmez)
6. rotation_ct = taze rotasyon ?? state.pending_rotation_ct
7. header'ı kur (n, prev_len = state.next_send_numbers()); (ciphertext, n, prev_len) = state.encrypt_next(CBOR(content), AAD = header.raw())
8. persist_ratchet_state()  — başarısızsa DUR
9. header'ın ham baytlarını imzala (Ed25519 + ML-DSA, alıcıya bağlı)
10. arşive "sent / pending" yaz (metin için)
11. if needs_confirm: publish_with_ack_tracking(...)
    else:             publish_envelope(...)
```

**Yol seçimi** (`try_publish_raw_via`):
- Konu (topic): `Handshake/IdentityExchange` → `p2p_msg_<alıcı_fp>`; rotasyon duyuran paket → **eski** root'tan `p2p_rt_<hex>` (karşı yeni root'u bilmez); diğer → mevcut root'tan `p2p_rt_<hex>` (`topic_for_root_key`, HKDF `p2pmsg-v0.1-gossip-topic`, 16 bayt).
- `direct = bağlı mı`. `critical = handshake | identityexchange | rotasyon | arama sinyali`.
- **Sunucuya bırak** şu koşullardan biri doğruysa: `!direct || critical || (onay 1,5 sn'de gelmedi)` ve sunucu bağlı+kayıtlı.
- **Doğrudan gönder:** bağlıysa `/p2pmessenger/envelope/1.0.0` request-response ile.
- **gossipsub'a yayınla:** direct değilse veya sunucuya bırakılamadıysa; sunucuya bırakılmış olsa bile `should_shadow_on_gossipsub` (handshake, rotasyon, ya da 30 sn'den eski ilk gönderim) true ise ek olarak gossipsub'a da gider.
- Hata sınıfları: `Permanent` (engelli, silinmiş hesap, zarf >1 MiB) → durum `Failed`; `Transient` → `pending_envelopes` kuyruğu + durum `Pending`.

---

## 8. Alım yolu (algoritma)

Kaynaklar: gossipsub mesajı, doğrudan envelope isteği, sunucu `Push`/`Batch`.

`process_incoming_envelope`:
1. **Kopya engeli:** ham baytın hash'i son 10 dk (`INBOUND_DEDUP_WINDOW_MS`, 8192 giriş) içinde görüldüyse atla; mesajsa Ack'i yeniden yolla.
2. CBOR çöz. Engelli kimlik/cihaz → sessizce düşür.
3. `IdentityExchange` → `process_identity_exchange`. `Handshake` → `process_handshake_init` (bilinmeyen gönderen → `early_handshakes`).
4. `Message`: ratchet yoksa ama cihaz bilinen+aktifse imzayı doğrulayıp `early_packets`'e at; aksi halde `receive_message`.

`receive_message` (lib.rs ~10157):
```
1. gönderen cihaz bilinmeli ve aktif; sender_identity_id kayıtla eşleşmeli
2. hibrit imza doğrula (alıcı = kendi aktif fp)
3. ratchet.decrypt(...)  [bkz. §5]; rotasyon olduysa topic yeniden abone, atlanmış anahtarlar temizlenir, bekleyenler yeniden üretilir
4. çözülemezse: reack_if_already_handled() ?  -> yinelenen teslim, Ack tekrar
                 aksi halde note_undecryptable(sender)  (3 başarısızlıkta rehandshake)
5. başarılıysa: son görülme, ratchet+skipped anahtarlar kalıcı
6. CBOR -> MessageContent; zamanlar clamp_received_times ile kıstırılır
7. tür bazlı işlem:
   Text(1:1): arşivde var mı -> sadece Ack; yoksa archive_message(); BAŞARILIYSA Ack, başarısızsa Ack ERTELE
   Text(grup): sender_may_post_to_group? değilse REDDET; author_proof (cihaz imzası) doğrulanır
   Edit/Delete: hedef varsa uygula, yoksa buffer_edit_or_delete (hedef gelince replay)
   Reaction/Seen/…: ilgili tablo
8. UI için JSON olay döndür ({"type":"message",...})
```
`Ack` alım tarafı: `awaiting_confirmation`'dan siler, durum `Delivered`.

---

## 9. Teslim güvenilirliği

- **Ack alan türler** (`needs_delivery_confirmation`): `Text, Edit, Delete, Reaction, HistorySyncRequest/Response, FileOffer, GroupUpdate, LeaveGroupRequest, ProfileUpdate, DeviceLinkGrant, DeviceAddNotice, DeviceRevokeNotice, FirstContactSecret, DeviceSync, SiblingEcho, ReadStateSync, SiblingHistoryRequest, AccountDeleted, WbDigest`. Ack **almayanlar:** `Ack, Seen, TypingIndicator, AddressAnnounce, SiblingHistoryResponse`, arama/WbOps.
- `awaiting_confirmation[message_id]` = `PendingConfirmation{envelope, next_retry_at, retry_interval_ms, first_sent_at, original_sent_at, regen_content, chain_stamp…}`; ayrıca `pending_durable_retries` tablosuna yazılır (süreç ölse de yeniden başlar).
- `retry_unconfirmed_messages` (periyodik):
  - ilk 1,5 sn'de Ack yoksa bağlantı "şüpheli" işaretlenir ve sunucuya erken bırakma denenir;
  - aralık `15 sn` (`ACK_RETRY_INITIAL_MS`) → ×2 → en çok `120 sn`;
  - zarfın yaşı `MAX_UNCONFIRMED_AGE_MS` (= rotasyon süresi − 5 dk = **25 dk**) aşılırsa ya da zincir değişmişse (`chain_stamp`) içerik `regen_content` ile **taze şifrelenip aynı `message_id`** ile gönderilir (alıcı `message_id` ile tekilleştirir);
  - `TEXT_RETRY_GIVE_UP_MS` = **7 gün** sonra vazgeçilir, durum `Failed`;
  - `SiblingEcho, ReadStateSync, DeviceSync, WbDigest` tazelenmeden bırakılır (bayatlayan veri).
- Radyo tasarruf modunda (`radio_saver`) 60 sn'den eski yeniden denemeler pencere kapalıyken tutulur.
- Hız sınırı (alım): 10 sn pencerede 60 paket (`RATE_LIMIT_MAX_PER_WINDOW`), kurulu bağlantı için 600; ayrıca `MAX_DEFERRED_INCOMING = 2000`, `MAX_UNKNOWN_INBOUND = 16`.

---

## 10. Çoklu cihaz

**Bağlama (secondary → primary)** (spec §1.5):
1. İkincil cihaz kendi anahtarlarını üretir; `DeviceLinkRequest` QR'ı gösterir (tam public key'ler + nonce).
2. Birincil QR'ı tarar → `pending_link_target`/`pending_link_nonce` set eder, ikincile `IdentityExchange` yollar.
3. İkincil `link_consent` (+PQ) ile **kendi onay imzasını** verir; `process_identity_exchange` içinde birincil `sign_device_add(fp, consent)` ile imzalı `DeviceAdd` üretir; `add_has_consent` yeni cihazın onayını doğrular.
4. Birincil `DeviceLinkGrant{nonce, identity_id, device_add, sync}` + devam parçaları `DeviceSync` yollar (ratchet-şifreli). `broadcast_device_add_to_contacts` tüm kişilere `DeviceAddNotice` (tam anahtarlarla) yollar; `sync_to_siblings`.
5. İkincil `identity_id`'yi benimser, kendi anahtarları aynı kalır.

**Çalışma anı:**
- Kişiler her mesajı alıcı kimliğin **tüm aktif cihazlarına** ayrı paketle yollar (`fanout_targets`).
- Kendi gönderdiklerim `SiblingEcho{Text|Edit|Delete|Reaction|File|GroupLeft}` ile kardeşlere iletilir; aynı `message_id` kullanıldığından düzenleme/silme aynı balonu hedefler.
- Kardeş geçmişi: `SiblingHistoryRequest` (sohbet başına `before_timestamp` sayfalama). Okundu: `ReadStateSync` (kalıcı watermark).
- `pending_sibling_ops` tablosu: hedef henüz yokken gelen kardeş işlemleri tamponlanır.
- İptal: `DeviceRevoke` (imzalı); iptal edilen cihazdan gelen paket reddedilir ve `answer_revoked_sibling`.
- Yetki: sadece kimliğin kök (birincil) cihazı ekler/çıkarır/siler.

---

## 11. Grup

**Yapı** (`group.rs`): `Group{group_id, name, founder_identity_id, members[GroupMember{identity_id, added_at, added_by}], version, avatar_jpeg, founder_chain}`. `group_id` biçimi `group-<16..48 hex>`; hex kısmı kurucu kimliği + nonce'tan türer (`group_id_for_founder`), yani bilinmeyen bir grup kimliği kurucusuna bağlanamıyorsa reddedilir. Üye sınırı `MAX_GROUP_MEMBERS`, `member_devices` ≤ üye × 5.

**İlk temas sırrı artık grup başına:** `FirstContactSecret{secret, group_id}` — cihazın sırrı `SHA-256("typeon-group-first-contact-v1" ‖ master ‖ group_id)`'in ilk 16 baytıdır (`own_group_contact_secret(group_id)`), kurucu onu `gf:<fp>:<group_id>` altında saklar ve **yalnız o grubun** üyelerine dağıtır. Eski **kişisel** sır kaldırıldı: üyeler artık tek bir kişisel ilk-temas kutusuna değil, **kendi grubunun** kutusuna erişir; bu kutu yalnız cihaz grupta olduğu sürece kayıtlı tutulur (`first_contact_secrets`).

**Değişiklik türleri** (`GroupChange`): `Add(id)`, `Remove(id)`, `Rename(ad)`, `AvatarUpdate(Option<bytes>)`, `Delete`, `TransferFounder(id)`. Hepsini **yalnız mevcut kurucu** imzalayabilir (ayrı yetki mekanizması yok; üyeler kendi başlarına değişiklik yapamaz). Üye ayrılmak isterse `leave_group`: kurucunun tüm aktif cihazlarına `LeaveGroupRequest` yollar (Ack'li), kendi yerelinde `remove_group_locally` yapar (`removed_groups`'a sürüm+kurucu yazılır, bekleyen kuyruklar ve beyaz tahta silinir) ve kardeşlere `SiblingEchoBody::GroupLeft` yansıtır. Kurucu bu isteği alınca `remove_from_group` ile `Remove` yayınlar (bu fonksiyon yalnız kurucuda çalışır: "Sadece kurucu üye çıkarabilir"). **Kurucu ayrılamaz**; grubu herkes için silebilir (`Delete`) ya da yetkiyi `TransferFounder` ile devreder.

**Doğrulama** (`validate_group_update`): imzalayan kimlik = `founder_identity_id` (aksi `NotFounder`); imzalayan cihaz aktif olmalı; `new_version > group.version` (aksi `StaleOrOutOfOrderVersion`, zararsız sayılıp onaylanır); `new_version <= version + 4096` (`MAX_VERSION_JUMP`). `apply_change`: `Remove` kurucuyu çıkaramaz; `TransferFounder` hedefi üye değilse yok sayılır (sürüm yine ilerler).

**Eşit sürüm çakışması (H78):** iki kurucu cihazı aynı sürümü imzalayabilir. Alıcı, elinde tuttuğu sürümdeki bir güncelleme için `group_tie_hash` (SHA-256: grup id + sürüm + değişiklik + ad + üye listesi + imzalayan) **daha büyükse** güncellemeyi yeniden alır; `Delete` ve aynı üye/adı tekrarlayan bir "yeniden gönderim" de alınır. Böylece her üye aynı sürümde **aynı** durumda biter; kaybeden kurucu cihaz kardeşinin güncellemesini alır ve sonraki değişikliği `max(görülen sürüm)+1` olarak yapar.

**Alım adımları** (`process_group_update`, lib.rs ~14806):
1. `group_id` biçimi → imzalayan cihaz bilinen mi → `group_update_signing_input` (grup id, sürüm, değişiklik, ad, üyeler, üye cihazlar, imzalayan kimlik+cihaz) üzerinde hibrit imza.
2. Ad ≤ 256 bayt; üye listesi ≤ sınır ve elemanlar fingerprint-hex olmalı.
3. Grup yerelde yoksa: daha önce **ayrıldığımız** (`removed_groups`) bir grup yeni sürümle ve bizi `Add` ile eklemeden geri gelemez; bizi üye yapmayan bilinmeyen grup **reddedilir**.
4. Kurucu zinciri: `heal_founder_chain` ile `FounderTransfer` zinciri yürünür (her halka eski kurucunun hibrit imzası, `founder_transfer_signing_input`); `founder_transfer_floor` geri sarmayı engeller; zincir `MAX_FOUNDER_CHAIN` ile kısıtlı.
5. `Delete` → `remove_group_locally`. Aksi halde `sync_members` + `apply_change`; bizi `Remove` ediyorsa grup yerelden silinir.
6. `member_devices` + `member_device_proofs`: üyenin cihaz anahtarları kurucu tarafından "vouch" edilir (`adopt_vouched_member_devices`); güncelleme **delta**dır: yalnız son güncellemeden sonra **yeni veya değişmiş** cihazlar taşınır (yeni eklenen üyeye tam liste gider). Eksik kalan üye ya da sürüm boşluğu `GroupSyncRequest` ile kurucudan **tam durum** ister (kurucu üye başına en çok 10 dk'da bir yanıtlar, `sign_group_resync`); `first_contact_secret` (16 bayt) `gf:<fp>:<group_id>` anahtarıyla saklanır → hiç eşleşmemiş üye o grubun ilk temas kutusuna açılabilir.

**Kurucu cihazları ve yeniden gönderme:** Kurucunun imzaladığı her güncelleme **kurucunun kendi kardeş cihazlarına** da gider (`send_group_update_to_siblings`); böylece iki kurucu cihazı aynı sürümü imzalamaz. Kurucu ayrıca grubu herkese yeniden gönderebilir (`resend_group_to_all`; Android `P2PLib.resendGroupToAll`): güncel imzalı durum **her üye cihazına** tekrar gönderilir.

**Mesaj gönderme** (`send_group_message`): üye olduğunu kontrol et → `local_id` (UUID) üret → `sign_group_author`: cihaz imzası ile `author_proof = "cihaz_fp:imza_klasik_hex:imza_pq_hex"` (`group_author_statement(group_id, message_id, identity, device, text)`) → arşive yaz → **her diğer üye için** `send_group_message_to_member`: üyenin tüm aktif cihazlarına ayrı 1:1 paket (`send_message_content`). Üyenin aktif cihazı henüz bilinmiyorsa içerik `pending_group_messages` kuyruğuna (üye başına `MAX_PENDING_GROUP_MESSAGES_PER_MEMBER`, taşarsa en eski atılır, DB'de kalıcı) yazılır ve `group_sync_sweep` periyodik yeniden dener. Son olarak kardeş cihazlara `SiblingEcho` yansıtılır.

**Alım** (`receive_message` Text kolu): `sender_may_post_to_group` (üye değilse reddet) → aynı `group_message_local_id` arşivde varsa yalnız Ack → `group_author_proof_valid` (cihaz o kimliğe ait mi + imza) geçerliyse `author_proof` saklanır → arşivle → Ack. Edit/Delete aynı `author_proof` ile yazara bağlanır.

**Eksik geçmiş:** `HistorySyncRequest{group_id, …}` / `HistorySyncResponse` ile diğer üyelerden; sunucu arşivi opsiyonel kaynak (§13).

---

## 12. Ağ katmanı

**Swarm kurulumu** (`start_network`, lib.rs ~17084):
- Kimlik: libp2p Ed25519 anahtarı `files/libp2p_identity.key` dosyasında (protobuf; bozuksa yenisi üretilir, okunamazsa o çalıştırma için geçici). Bu **Typeon cihaz kimliğinden ayrıdır**; PeerId bu anahtardan gelir ve sunucu kaydında görünür.
- Taşıma: `tcp(nodelay)` → **`DialReject`** ile sarılı (dışarı dial her zaman `MultiaddrNotSupported`) → noise → yamux; ve `ArtiDialTransport` (Tor üzerinden `.onion` dial) → noise → yamux. Dinleme yalnızca `127.0.0.1:<listen_port>`'ta; Tor onion servisinin gelen akışları `bridge_incoming_stream` ile bu yerel porta köprülenir (`MAX_INBOUND_ONION_STREAMS = 64`). Yani clearnet'ten gelen/giden doğrudan bağlantı yoktur.
- gossipsub: `MessageAuthenticity::Signed(libp2p keypair)`, `ValidationMode::Strict`, heartbeat 10 sn, `max_transmit_size` 1 MiB. Başlangıçta kendi `p2p_msg_<aktif_fp>` topic'ine ve her ratchet için `p2p_rt_<hex>` (mevcut + `prev_root_key`) topic'ine abone olunur.
- kad: `Mode::Client` (başkalarının yönlendirmesini yapmaz); node modu açıksa relay server davranışı eklenir (`relay::Behaviour` yalnız `node_mode`'da).
- `mdns = None`, `upnp = None` (Toggle kapalı); `dcutr` ve relay client açık; `identify` açık.
- Request-response davranışları: `envelopes` (`/p2pmessenger/envelope/1.0.0`), `acks` (`/p2pmessenger/ack/1.0.0`, AckBatch ≤256), `keepalive` (`1.0.0`/`1.1.0`), `file_chunks` (`/p2pmessenger/filexfer/1.0.0`), `server_rpc` (`/typeon/server/1.0.0`), `stream` (libp2p-stream: `/typeon/media/1.0.0`, `/typeon/relay/1.0.0`).

**Tor** (`tor.rs`): `TorClient::create_unbootstrapped` + `launch_onion_service` (nickname `p2pmsg`). `bootstrap()` başarısız olursa 2 sn'den başlayıp 60 sn'ye katlanan beklemeyle sonsuz yeniden dener. Durum: `Disabled` → `Bootstrapping` → `Ready` (onion adresi alınır) / `Failed`. `corrupted data in persistent state` hatasında `state/` ve `hss/` silinip bir kez daha başlatılır; `keystore/` (onion kimliği) korunur. `set_dormant` ile radyo tasarrufu.

**Poll modeli** (Kotlin `P2PService`): ayrı `HandlerThread`; aralık `nextPollDelayMs`: sohbet açıkken 1 sn; boşta artan 2–3 sn; ekran kapalı ve çekirdek meşgulse 5 sn; tam boşta (12 boş poll) 30 sn (`DEEP_IDLE`, wake lock bırakılır). Her poll `poll_events()`: radyo penceresi/Tor dormant kararı → `call_sweep` → swarm olaylarını boşalt → dedup → `process_incoming_envelope` → keepalive/reconnect/retry süpürmeleri → JSON olaylar.

**Keşif/yeniden bağlanma:** QR'daki `rendezvous_node`, `device_addrs`/`device_onion_addrs` tabloları, `AddressAnnounce`, röleler (`known_relays`, ≤10), `dial_with_relay_fallback` (doğrudan → röle). `reconnect_sweep` 15 sn (hızlı pencere 3 sn/60 sn); başarısız hedef için üstel geri çekilme 15 sn → 10 dk (tasarruf modunda ≤3 saat); **Fan-out filtresi:** 7 gündür (`STALE_PEER_RETRY_HORIZON_MS`) görülmemiş cihaz `fanout_targets`/`sibling_active_devices`/`contact_device_targets` dışında bırakılır (terk edilmiş eski telefon sunucu kutusunu 5000 öğeye doldurmasın diye); hiç yakın zamanda görülen yoksa tüm aktif cihazlar kullanılır.

**Keepalive:** aralık 2 sn (hızlı) / 20 sn (boşta) / 60 sn (güç tasarrufu); 3 ardışık hata = kopuk; sunucu RPC'sinde 3 zaman aşımı = kopuk.

**Radyo penceresi:** `RADIO_WINDOW_MS` 8 dk (Wi-Fi 4 dk), `RADIO_AWAKE_MS` 30 sn, `TOR_FULL_WAKE_MS` 45 dk. **Toplu dial koruması:** `BULK_PARALLEL_CONNECTIONS` 3, min aralık 6 sn, 60 sn'de 3 vuruş = bırak, 3 bırakma sonrası 5 dk soğuma.

---

## 13. Sunucu (store-and-forward)

### 13.1 Protokol
`/typeon/server/1.0.0`, libp2p request-response CBOR. Kablo sınırı: istek ≤ 1 MiB (codec sert sınırı; aşan sessizce kırpılır), yanıt ≤ 10 MiB → bu yüzden `MAX_DEPOSIT_BYTES = 900 KiB`, aşan zarf sunucuya hiç denenmez (doğrudan gossipsub).

`ServerRequest`: `Hello{version}` (sürüm 3), `Enroll{…}`, `Rebind{…}`, `Register{add, drop, proofs}`, `Deposit{mailbox, sealed}`, `Fetch{cursors, max_items, max_bytes}`, `Ack{acks:[(mailbox, seq)]}`, `Cancel{mailbox, seqs}`, `ArchivePut/Probe/Fetch/Purge`, `BlobPut/Finish/Delete`; sunucu→istemci: `Notify`, `Push{item}`.
`ServerResponse`: `Welcome{version, challenge, enrolled, enrollment_id, limits, server_name}`, `Enrolled{enrollment_id, limits}`, `Deposited{seq}`, `Batch{items, more}`, `ArchiveProbed`, `ArchiveBatch`, `Registered{proof_needed, refused}` (`Register` yanıtı; eski `ProofNeeded` yok), `Ok`, `Err(code)`.

### 13.2 Kayıt (sunucu tarafı `handle_*`)
- `Hello`: sürüm ≠ `SERVER_PROTOCOL_VERSION` (3) → `Unsupported`. Aksi halde 32 bayt rastgele `challenge` üretilip bağlantı durumuna yazılır; yanıt `Welcome` (+ `enrolled` = bu PeerId'nin kaydı `Active` mi, `enrollment_id` = o kaydın kimliği; `Enrolled` yanıtı kaybolan istemci geri alır).
- `Enroll`: sırayla — sürüm; `|now − ts_ms| ≤ 5 dk` (`Stale`); davet jetonu hash'i geçerli ve kullanım hakkı var (`BadInvite`); bağlantının tek kullanımlık `challenge`'ı `take()` ile alınır ve istemcinin gönderdiğiyle eşit olmalı (`BadSignature`); hibrit imza `enroll_signing_input(version, server_peer_id, client_peer_id, token, enroll_pk, enroll_pk_pq, challenge, ts)` doğrulanır (istemci PeerId'si ve iki enroll anahtarı imzaya bağlı); `Enroll`/`Rebind` ortak bir **küresel doğrulama bütçesine** (`verify_budget`, dakikada 120) tabidir → aşılırsa `RateLimited`; anahtar `blocked_keys`'te ise `Revoked`; herkese açık davet (`uses_left == -1`) saatte 60 kayıt tavanı (`QuotaExceeded`); aktif kayıt sayısı `max_enrollments` (varsayılan 64, son 30 gündür boşta olmayanlar sayılır) → `QuotaExceeded`; sonra `enroll_with_invite` tek işlemde jeton tüketir + kaydı yazar. Aynı PeerId yeniden kayıt olursa önceki `enrollment_id` ve kota sayaçları korunur.
- `Rebind`: `ts` penceresi, `challenge`, mevcut kaydın `enroll_pk` hibrit imzası `rebind_signing_input(enrollment_id, server_peer_id, yeni_peer_id, challenge, ts)`; `Revoked`/engelli anahtar reddedilir; kayıt yeni PeerId'ye taşınır, jeton tüketilmez.
- **İptal (revoke) = engelleme.** Sunucu tarafında iptal, kaydın `enroll_pk`'sini `blocked_keys`'e koyar (`store.rs`); "kaydı kapatıp taze davetle dönüşe izin ver" DEĞİLDİR. Aynı anahtar geri gelemez; ama uygulamayı yeniden kurup yeni PeerId + yeni enroll anahtarı üreten biri, kullanılabilir bir davet jetonuyla yeniden kaydolabilir. Gerçek yasak için **katılım kodunu (davet jetonunu) döndür**. Sunucu uygulamasını kaldırmak onion kimliğini ve kayıtlı her cihazın jetonunu siler.
- Diğer tüm istekler `authenticate(peer)` ister; kayıt yoksa `NotEnrolled`, iptalse `Revoked`. Her istek önce `check_rate` (dakikada `requests_per_minute`=1800; dosya parçası için ayrı `CHUNKS_PER_MINUTE`=600) → `RateLimited`.

### 13.3 Posta kutusu semantiği (`store.rs`)
- **`Register{add, drop, proofs}`:** `add` kimlikleri `is_safe_id` olmalı. Her kutu, o kutunun **kutu anahtarı** (`mailbox_proof_seeds`'ten türeyen hibrit anahtar) ile imzalı kanıt ister (`register_signing_input(mailbox, enrollment_id, server_peer_id)`). Kutu ilk kaydeden anahtara bağlanır (`mailbox_keys`, `mailbox_key_hash`); okuyucusu varken başka anahtar kabul edilmez. Kanıtsız kutular `ProofNeeded(ids)` ile istenir; istemci ≤64 kanıtlı yeniden `Register` yollar. Kota/okuyucu sınırı aşan → `QuotaExceeded`. Kabul edilen kutular sunucuda `live_interest[peer]`'e yazılır (Push/Notify hedefi).
- **`Deposit`:** `sealed ≤ min(max_item_bytes, 900 KiB)` (`TooLarge`); kutu kayıtlı değil → `UnknownMailbox`; yatıran kaydın `bytes_mail ≤ max_mail_bytes`, toplam disk bütçesi (`total_storage_budget_bytes`), kutuda ≤ `max_items_per_mailbox` (5000) → aksi `QuotaExceeded`. Aynı `(mailbox, depositor, sha256(sealed))` zaten varsa **yeni satır açılmaz**, TTL uzatılır ve eski `seq` döner (idempotent). Aksi halde `mail` satırı: `seq` (rowid), `expires_at = now + mailbox_ttl` (14 gün).
- **`Fetch{cursors}`:** istemcinin bildirdiği her `(mailbox, after_seq)` için `seq > after_seq`, **`depositor != requester`** (kendi bıraktığını geri almaz) ve istekçi o kutunun `mailbox_readers`'ında olan satırlar `seq` sırasıyla, ≤64 öğe ve ≤512 KiB; sığmayan kalırsa `more = true`.
- **`Ack{(mailbox, seq)}`:** yalnız o kutunun okuyucusu sayılır; `mail_acks(mailbox, owner)` için `through_seq = MIN(seq, MAX(seq mevcut))` ve yalnız **ilerliyorsa** yazılır. Sonra `delete_fully_acked`: bir satır, kendisi dışındaki **tüm aktif okuyucular** `through_seq ≥ seq` olunca silinir (okuyucu başına ack; çok cihazlı kimliğin her cihazı ayrı okur).
- **`Cancel`:** yatıran kendi `seq`'lerini siler (gönderen mesajı geri çekerse).
- **Süpürme** (`maybe_sweep`, 60 sn): iptal edilmiş/uyuyan kayıtların okuyucu satırları kaldırılır → yetim kutuların tam-ack'li satırları silinir → `expires_at ≤ now` olanlar silinir → `blobs_to_gc` (blob_ttl 30 gün) → `incremental_vacuum`. **Saat sıçraması** (>24 saat) algılanırsa TTL süpürmesi bir saat bekletilir (yanlış saat tüm postayı silmesin). Boşta 30 gün kalan kayıt "uyutulur" (`sleep_idle_enrollments`). Kayıtsız bağlantılar 60 sn sonra düşürülür (node modu hariç).
- **Bildirim** (`notify_owner_of`): yeni zarf için, kutuyu `live_interest`'inde tutan ve yatıran olmayan her bağlı okuyucuya: okuyucunun o kutuda **tek** ack'siz öğesi varsa ve zarf ≤64 KiB ise `Push{item}` (satır içi teslim, ek Fetch gerekmez); değilse `Notify`. `Notify` Fetch gelene kadar 20 sn'de bir tekrarlanır (`NOTIFY_RESEND_MS`).

### 13.4 İstemci tarafı akış (`server_client.rs`)
**Bağlantı yaşam döngüsü:** sunucu bağlanınca `Hello` → `Welcome`; `enrolled` ise `server_sweep_at = 0` (hemen `Register`+`Fetch`), değilse `begin_enrollment`: kayıtlıysa `Rebind` (kalıcı `enrollment_id` + enroll anahtarı), değilse jeton varsa `Enroll` (sunucuya özel Ed25519 sk 32 bayt + ML-DSA-87 **seed**; yoksa "Kayıt anahtarı eski biçimde" hatası). Bağlantı koparsa `enrolled=false`, `registered` temizlenir.
**Süpürme** `SERVER_SWEEP_INTERVAL_MS` = 15 sn: kayıtlıysa kutu kayıtlarını (`Register`, ratchet root'larından türeyen kutular + ilk temas kutuları) yeniler; `Fetch` en geç `SERVER_FETCH_SWEEP_INTERVAL_MS` = 5 dk'da bir, ayrıca `Notify`/`Push` ile hemen.
**Fetch işleme** (`Batch{items, more}`):
1. Öğenin kutusu bizim kutularımızdan biri değilse atla; `seq ≤ kayıtlı imleç` ise atla.
2. Aç: oturum kutusu → `open_envelope(root_key, mailbox, peer_fp)`; ilk temas kutusu → `open_first_contact(secret, mailbox, kem_sk…)`.
3. Açılırsa ham zarf `incoming.push((None, raw))` ile **normal `process_incoming_envelope` yoluna** girer (`source = None`). **Açılamayan öğe Ack'lenmez ve kutunun imleci onun önünde kalır; 5 dk (`SERVER_HOLD_GRACE_MS`) tutulur, 45 sn'de (`SERVER_HOLD_REFETCH_MS`) bir yeniden çekilir; süre dolunca atlanır. İmleç hiçbir zaman o öğenin `seq`'ine taşınmaz.** Çekilen öğenin işlenmesi başarısız olursa (`server_item_failed`) imleç aynı şekilde geri alınır.
4. Her kutu için en yüksek (başarılı) `seq` imleç olarak kalıcı yazılır (`persist_cursor`) ve `Ack{acks}` yollanır; `more && ilerleme` ise hemen yeniden Fetch.
**`Push`:** tek öğe sahte `Batch` olarak aynı yolla işlenir; sunucudan 5 sn'de >30 Push gelirse `Notify` gibi davranılıp toplu çekime düşülür.
**Deposit tarafı** (`try_server_deposit`): bkz. §7. `Deposited{seq}` gelince `server_deposit_locations[(server, message_id)] = (mailbox, seq)` saklanır (iptal için `Cancel`). Zarf bırakılırken iptal edildiyse gelen `seq` hemen `Cancel` edilir.
**Hata işleme** (`handle_server_error`):
| Kod | Davranış |
|---|---|
| `UnknownMailbox` | O (sunucu, kutu) 60 sn "bilinmeyen" işaretlenir; zarf hemen gossipsub'a verilir |
| `NotEnrolled` | `enrolled=false`, yeniden `Hello`; `Rebind` sırasındaysa `enrollment_id` silinir ("yeni davet kodu ekleyin") |
| `Revoked` | `enrollment_id` silinir, "operatör iptal etti" |
| `QuotaExceeded` (Deposit) | O kutuya 5 dk bırakma durdurulur, gossipsub'a verilir |
| `RateLimited`, `Internal` | Geçici sayılır; bırakmada 5 dk geri çekilme (`SERVER_DEPOSIT_BACKOFF_MS`) |
| `BadInvite` (Enroll) | Jeton silinir |
| `BadHash` (BlobFinish) | Kalıcı: depolanan baytlar `enc_sha256` ile uyuşmuyor, aynı Finish tekrar işe yaramaz |
| diğerleri (`TooLarge`, `BadSignature`…) | Kalıcı; blob/arşivde iş bırakılır |
Zaman aşımı/bağlantı hatası (`handle_server_failure`): bırakma geri çekilmesi + gossipsub'a düşme. **Her başarısız bırakma gossipsub'a düşer**; sunucu hiçbir zaman tek teslim yolu değildir.

### 13.5 Sunucu tarafı gizlilik ve mühür
- Oturum kutusu `mb_<hex16>` (`server_seal::session_mailbox`) cihaz çifti başına **sabit**tir: iki cihazın uzun ömürlü KEM X25519 anahtarlarıyla statik DH + sıralı fingerprint'lerden HKDF (`p2pmsg-v0.6-session-mailbox`); rotasyonda değişmez, root_key/topic'ten türemez (yalnız X25519, statik ML-KEM yok). Mühür anahtarı yine ratchet root'tan gelir (alıcı mevcut + önceki root'u dener); ilk temas kutusu = HKDF(sır, `p2pmsg-v0.5-first-contact-mailbox:`‖fp) — sır eşleşme nonce'u, link nonce'u ya da **grup başına** ilk temas sırrı olabilir (bkz. §11); arama röle kutusu = HKDF(pair_key, `p2pmsg-v0.5-call-relay-mailbox`).
- `seal_envelope`: ChaCha20-Poly1305(HKDF(root_key, `p2pmsg-v0.1-server-seal`), AAD = mailbox‖0‖sender_fp, CBOR(zarf)). Sunucu AAD'yi bilir ama anahtarı bilmez.
- `seal_first_contact`: ortak sır (`p2pmsg-v0.5-first-contact-seal`) + varsa alıcının KEM anahtarı; açma `open_first_contact(secret, mailbox, kem_sk_x25519, kem_sk_mlkem, sealed)`.
- Sunucu veritabanında kimlik/fingerprint/içerik yoktur; `enrollments` yalnızca `enroll_pk`, `enroll_pk_pq`, `peer_id`, durum, sayaçlar tutar.

### 13.6 Arşiv ve blob (kodda doğrulandı)
**Arşiv — sunucu:** `archive_put` kayıtları `(bucket, record_id)` anahtarıyla yazar; çakışmada **yalnız `rev` daha büyükse** üzerine yazar (`WHERE excluded.rev > archive.rev`), yani eski revizyon yeniyi ezemez. `record_id` ≤128 bayt, bucket `is_safe_id`, kayıt ≤900 KiB, `max_archive_bytes` (1 GiB) ve toplam disk bütçesi kontrol edilir; kayıt başına `owner` bayt sayacı yeniden hesaplanır.
**Arşiv — istemci:** kayıtlar **yalnız `store_history` açık bir sunucu varsa ve kök arşiv anahtarı mevcutsa** `queue_archive_record` ile kuyruğa girer (düz metin yerelde `seal_local_blob` ile mühürlü bekler); `ArchivePut` partisi 50 kayıtta (`SERVER_ARCHIVE_BATCH`) ya da mühürlü bayt `MAX_DEPOSIT_BYTES/2`'yi aşınca kapanır. Geri yükleme: `ArchiveProbe(buckets)` → dolu kovalar (`before_ms` verilmişse en yeni önce) → `ArchiveFetch{bucket, before_ms}` sayfalama (`more` ise `before_ms` = sayfadaki en eski `sent_at_ms`) → `merge_server_archive`: kaydı `open_archive_record(ark, conv_key, record_id, rev, bucket, sent_at_ms, sealed)` ile aç (AAD bu alanları bağlar); `note_archive_rev` ile **görülenden eski `rev` reddedilir** (`server_archive_revs` tablosu); yerelde aynı `record_id`'li mesaj zaten varsa **atlanır** (yani sunucu arşivi mevcut mesajı değiştirmez, yalnız eksik olanı doldurur); grup değilse `resolve_active_device_for_identity(conv_key)` ile sohbete yazılır. Sonuç `history_backfilled{count, source:"server"}` olayı. Çözülemeyen/ayrıştırılamayan kayıt atlanır.
**Blob — istemci** (`queue_blob_upload` / `server_flush_blobs`): yalnız `route_messages` açık bir sunucu varsa kuyruğa alınır; kuyrukta **aynı anda tek blob** (baştaki) yüklenir; durum `server_blob_uploads` tablosunda kalıcıdır. Parçalar diskte şifreli dosyadan `chunk_size` ile okunur, `window` kadarı havada tutulur (başlangıç 4, min 2, max 40; RTT tabanın 2 katını aşmadıkça ve 90 sn zaman aşımının %80'i altındaysa büyür, zaman aşımında yarıya iner). Tüm parçalar bitince şifreli dosyanın SHA-256'sı ile `BlobFinish`. Sunucu değişirse yükleme baştan başlar.
**Blob — sunucu:** `BlobPut` parçayı dosyada `offset = chunk_index × (chunk_size + 16)` konumuna yazar (rastgele erişim; parça ≤768 KiB; sahip kontrolü; hem tek blob ofseti hem kayıt başına `bytes_blob` `max_blob_bytes` 4 GiB'ı aşamaz; aynı parça tekrar gelirse `Ok`, hash sürerken `RateLimited`); `BlobFinish`: sahip eşleşmeli, alınan parça sayısı `total_chunks`'tan az olmamalı, aynı anda en çok `MAX_HASH_JOBS` = 4 hash işi (aksi `RateLimited`); hash arka planda akışlı hesaplanır, yanıt hash bitince gider. **Uyuşmazsa dosya silinir ve `Internal` döner.** Tamamlanan blob `filexfer` protokolüyle servis edilir (`serve_chunk`, parça hız sınırı 600/dk, relay/cold bütçeleri ayrı); `blob_ttl` (30 gün) sonra GC.

### 13.7 Veri dizini kilidi, DB şifreleme, arşiv ömrü
- **Süreç kilidi:** veri dizininde `server.lock` dosyası `flock` ile kilitlenir (`ServerCore` ömrü boyunca tutulur, `_dir_lock`); ikinci bir sunucu aynı dizini açamaz ("bu veri dizini başka bir sunucu işlemi tarafından kullanılıyor").
- **DB şifreleme:** Android sunucu uygulaması DB'yi **SQLCipher** ile açar — anahtar 32 rastgele bayt, Android Keystore'daki (dışa aktarılamayan) AES-GCM anahtarıyla sarılır (`DbKey.get`), `ServerLib.setDbKey` ile çekirdeğe 64 hex olarak verilir. Eski (düz) DB ilk açılışta **bir kez** şifreli DB'ye geçirilir (`sqlcipher_export`); anahtar gelmezse sunucu **düşer** (fail-closed, düz DB'ye düşmez). Linux `typeon-server` **düz** kalır; `TYPEON_SERVER_DB_KEY` (64 hex) verilirse aynı şekilde şifreli açılır (düz DB yine bir kez geçirilir).
- **Arşiv ömrü:** arşiv satırları son yazıldıktan **13 ay** sonra silinir (`ARCHIVE_TTL_MS` = 13×30 gün; `sweep_expired_archive`, posta süpürmesiyle birlikte çalışır, kota sayaçları yeniden hesaplanır).
- **PIN kilidi (sunucu uygulaması):** tüm ekran (katılım kodu, cihaz listesi, ayarlar) PIN arkasında; PBKDF2-HMAC-SHA256, 300.000 iterasyon, en az 6 karakter; 5 hatalı denemeden sonra artan bekleme (30 sn, sonra katlanarak); ekran kapanınca anında, uygulamadan çıkınca 30 sn sonra kilitlenir.

---

## 14. Yerel depolama ve anahtar yönetimi

- **DB:** `p2p_messenger.db`, SQLCipher (`rusqlite` bundled-sqlcipher-vendored-openssl). `PRAGMA key = x'…'` (HKDF'den), `WAL`, `synchronous=NORMAL`, `secure_delete=ON`. Eski düz DB ilk açılışta şifrelenir (tek seferlik göç).
- **Anahtar zinciri (Android):** `KeystoreCrypto` — Android Keystore'da (StrongBox → TEE) AES-256 anahtarı; Rust'ta üretilen gizli anahtar paketi (`SecretKeyBundle`) ve `storage_key` bu anahtarla sarılıp dosyaya yazılır (`IdentityManager`, `ArchiveKeyManager`). **AppLock parolası DB/anahtar türetmede KULLANILMAZ**; yalnızca UI kapısıdır (PBKDF2 hash saklanır, süreç ölünce kilit tekrar sorulur). Yani cihaz root/bellek erişimi ya da Keystore saldırısı AppLock'u aşar; bu bilinen sınırdır.
- **Linux:** gizli anahtarlar KDE Wallet (+ isteğe bağlı parola) ile mühürlenir (`keyring.rs`, `secrets.rs`).
- **Satır şifreleme:** geçmiş/atlanmış anahtar/ratchet durumu/dosya anahtarı ayrıca `seal_with` (rastgele nonce ChaCha20-Poly1305) ile mühürlenir (`ratchet_states.sealed` vb.).
- **Tablolar:** bkz. HANDOFF §3.8. Yeni sütun `ALTER TABLE` ile eklenir.
- **Kurtarma dosyası:** `RecoveryFile{kdf:"argon2id", m/t/p, salt, nonce, ciphertext}`; parola ≥12 karakter; içerik: kimlik, tüm cihaz gizli anahtarları, kök arşiv anahtarı, veri (sınır 64 MiB; aşarsa en yeni 6500 mesaj). İçe aktarımda Argon2 bellek maliyeti ≤256 MiB sınırı.
- **Yedekleme** kapalı (`allowBackup=false`); `FLAG_SECURE` **istemcide yok** (sunucu uygulamasında release derlemede var).

---

## 15. Dosya ve medya

- `FileOffer` (metadata, Ack'li) → alıcı `/p2pmessenger/filexfer/1.0.0` ile parça ister (`FileChunkRequest/Response`). Dosya başına rastgele anahtar; parçalar şifreli. Çok kaynaktan (gönderen, kardeş, sunucu `alt_source_peer_ids`) indirme, otomatik devam, kimlik doğrulama kurtarma. `FileChunkResponse::Busy` = sunucunun hız sınırı; istemci aynı kaynaktan `DOWNLOAD_RETRY_DELAY_MS` sonra yeniden dener. Sınır 4 GiB (`MAX_ATTACHMENT_SIZE`).
- Sunucu blob'u: parçalar sunucuda dosya anahtarıyla şifreli kalır; `BlobPut/Finish`, `blob_ttl 30 gün`.
- Gönderimde gizlilik: Metadata temizliği (`attachments.rs`) yalnız **JPEG ve PNG**'yi kapsar; diğer biçimlerde (HEIC/WebP/GIF/video vb.) EXIF/GPS **temizlenmez** (Android `OutgoingMedia.kt` ayrıca yeniden kodlar/remux eder; Linux'ta soyma katmanı yoktur). JPEG/PNG'de metadata ayrıştırılamıyorsa dosya **reddedilir** (fail-closed), kirli gönderilmez. Yönlendirme (orientation) korunur.

---

## 16. Arama ve beyaz tahta

### 16.1 Arama durum makinesi (`call.rs`, tek `CallSession`)
`CallPhase`: `Outgoing`, `Incoming`, `Active`. Aynı anda tek arama (`"Zaten bir arama sürüyor"`).

**Başlatma:** `start_call(peer)`: `fanout_targets(peer)` içinde ratchet'i olan **tüm cihazlara** davet. Grup: `group_call_devices` = diğer üyelerin aktif ve **yakın zamanda görülmüş** cihazları. Her katılımcı arama başına **taze rastgele** `my_key` (32 bayt) ve `my_sid` (8 bayt) üretir (`CallSession::new`) ve `media_start` ile medya motorunu açar.

**Sinyal** = `MessageContent::Call{call_id, action, group_id, video, media_key, stream_id, sent_at_ms, participants}`, normal ratchet/E2E yolundan; `call_signal_sending=true` iken `critical` sayılır (sunucuya + doğrudan birlikte). `Invite` ve `Accept` içinde **alıcıya özel** anahtar gider: `media_key = pair_key(my_key, alıcı_fp) = HKDF(my_key, "typeon-call-pair-v1"‖alıcı_fp)`, `stream_id = my_sid`. Her alıcı ayrı anahtar aldığı için bir üye başka üyeymiş gibi paket mühürleyemez.

**Grup daveti katılımcıları taşır (C10):** grup `Invite`'ında `participants` = arayanın **çalldığı tüm cihazların** fingerprint'idir (≤ `MAX_INVITE_PARTICIPANTS` = 1024). Alıcı, "bayat" saydığı üyelerle de anahtar değiştirir: listedeki cihazlar grubun aktif üye cihazlarıysa davete eklenir (kendi cihazı hariç).

**Alıcı kuralları** (`handle_call_signal`):
- `Invite`: anahtar uzunlukları 32/8; `sent_at_ms` ±60 sn (`INVITE_MAX_AGE_MS`, geç teslim edilen davet çalmaz); bu `call_id` zaten bitmişse yok say; grup araması ise gönderen üye olmalı. **Glare:** iki taraf aynı anda 1:1 ararsa `call_id` küçük olan kazanır (`ours < call_id` → gelen yok sayılır, aksi halde kendi arama bitirilip gelen kabul). Başka aramadaysak `Busy` yanıtı.
- `Accept`: `call_id` eşleşmeli; gönderen davetliyse ya da (grup ve üye ise) listeye eklenir; `Outgoing` → `Active`, 1:1'de diğer cihazlara `Hangup` (çalmayı durdur); `media_add_remote(peer, key, sid)`. Grupta aktif aramaya sonradan katılan yeni üye için `Accept` karşılığı anahtarla yanıtlanır.
- `Reject/Busy/Hangup`: katılımcı çıkarılır; arama bitişi 1:1/grup/faz kombinasyonuna göre (`over`). Cevapsız gelen 1:1 için arşive "📞 Missed call" yazılır.
- Zaman aşımları: çalma 45 sn (`RING_TIMEOUT_MS`, iki yön); aktifken 30 sn kimseden medya gelmezse arama `lost` (`MEDIA_LOST_MS`, her katılımcı saniyede bir durum paketi yollar).

### 16.2 Medya yolu
Kotlin kodlar (Opus ses; video H.264/HEVC — bayrak biti), çekirdek `media_send(kind, payload)` ile **çekirdek kilidi ve poll döngüsünden bağımsız** şifreler ve per-link kanallara iter; tokio görevleri uzun ömürlü libp2p-stream akışlarına yazar.
- **Paket:** `[ver=1][stream_id 8][seq u64 BE]` + ChaCha20-Poly1305(`[kind][sent_ms u32][payload]`), AAD = başlık (17 bayt), nonce = `stream_id[..4]‖seq`. `kind`: 1 ses, 2 video, 3 rapor, 4 durum.
- **Yol (hedef cihaz başına):** canlı doğrudan bağlantı varsa `/typeon/media/1.0.0` akışı; yoksa sunucu röle akışı `/typeon/relay/1.0.0`, adres = `relay_mailbox_id(pair_key)`; sunucu bunu **saklamaz**, yalnız hedef o an bağlıysa iletir (çerçeve: `[u16 mailbox len][mailbox][u32 len][data]`). `call_force_relay` dosyası varsa test için röle zorlanır.
- **Alım** (`media_on_packet`): başlıktan `sid`+`seq` → ilgili `Remote`'un anahtarıyla aç; son 64 `seq` için tekrar/sıra penceresi (`is_new`); `STATE`/`REPORT` çekirdekte tüketilir, ses/video Kotlin'e `[kind][slot][payload]` olarak `inbox`'a (≤64; dolunca en eski **video** atılır ve o slota keyframe istenir).
- **Tıkanıklık:** gönderen tarafta kuyruk sınırı ses 16 / video 6 (`LINK_QUEUE` 48); doluysa paket düşer (canlı medya, geç = işe yaramaz). Alıcı 500 ms'de bir `REPORT{kuyruk_ms, keyframe_iste}` yollar; kuyruk >400 ms ise gönderen sesi tutar (<150 ms'de bırakır); `media_backlog` Kotlin'e video fps/bitrate düşürme sinyali verir.
- Çerçeve ≤256 KiB (`MAX_FRAME`).

### 16.3 Beyaz tahta (`whiteboard.rs`)
`WbOps` (imzalı vuruşlar `WbStroke`) 1:1 veya grup; sayfa bütünlüğü `WbPageSig`/`WbPageDigest`. Senkron: `WbDigest` (Ack'li, `regen_content`'li) ile durum özeti, farkta `WbPageRequest` → `WbPage`. Grup tahtası grup silinince/ayrılınca `wb_delete_board` ile temizlenir.

**Özet vuruş başına içerik hash'idir:** sayfa hash'i artık vuruş id'lerinin XOR'u değil, her vuruşun `SHA-256("typeon-wb-digest-v1" ‖ vuruş hash'i ‖ yazar ‖ imza)`'sinin ilk 8 baytının XOR'udur (`wb_digest_item`; vuruş hash'i id + sayfa + ton + kalınlık + noktaları kapsar) → aynı id ama farklı içerikli iki kopya **eşit sayılmaz**.

---

## 17. Tehdit modeli (özet)

**Korunan:** içerik gizliliği ve bütünlüğü (E2E + PQ hibrit), ileri gizlilik (30 dk rotasyon + zincir anahtarı silme), sonrası-iyileşme (rotasyon), gönderen kimliği (hibrit imza, alıcıya bağlı), tekrar oynatma (message_id dedup, tüketilmiş anahtar, handshake imza/zaman penceresi), IP gizliliği (yalnız onion; clearnet dial yok), sunucudan içerik gizliliği (çift mühür, kör kutu adı).

**Kabul edilen/bilinen sınırlar:**
- Sunucu operatörü hacim/zaman/PeerId↔kutu eşleşmesini görür (eş grafiği); mesajı geciktirebilir/atabilir ama sahteleyemez (bu yüzden gossipsub'a kopya).
- Sunucu arşivi ileri-gizli değil; sunucu eski bir düzenleme revizyonunu sıfırdan geri yükleyen cihaza sunabilir.
- `Handshake`/`IdentityExchange` sunucuda okunur durur (gönderen adı görünür); yalnız public key + imza taşır.
- Noise taşıma klasik X25519'dur (içerik zaten hibrit).
- İlk temas TOFU'dur; QR/kod doğrulaması kullanıcıya bağlıdır.
- AppLock yalnız arayüz kilididir (anahtar türetmeye bağlı değil).
- Birincil cihaz ele geçirilirse kimlik ele geçirilir (yetki kökü).
- Handshake'te prekey kullanılmazsa (id 0) ilk gönderimler yalnız uzun-dönem KEM'e dayanır; responder ilk gönderimden önce rotasyon yapar.

---

## 18. Sabitler (kod değerleri)

| Sabit | Değer | Yer |
|---|---|---|
| `RATCHET_ROTATION_MS` | 30 dk | ratchet.rs |
| `MAX_SKIPPED_KEYS` / `MAX_SKIP_AHEAD` | 1000 / 10.000 | ratchet.rs |
| `MAX_ACTIVE_DEVICES` | 5 | identity.rs |
| `ACK_RETRY_INITIAL_MS` / `ACK_RETRY_MAX_MS` | 15 sn / 120 sn | lib.rs 2953 |
| `ACK_SUSPECT_MS` | 1,5 sn | lib.rs 2480 |
| `MAX_UNCONFIRMED_AGE_MS` | 25 dk | lib.rs 2980 |
| `TEXT_RETRY_GIVE_UP_MS` | 7 gün | lib.rs 3003 |
| `HANDSHAKE_MAX_SKEW_MS` / `HANDSHAKE_COLLISION_WINDOW_MS` | 10 dk / 90 sn | lib.rs 2905, 2913 |
| `HANDSHAKE_REDO_MIN_INTERVAL_MS` (IdentityExchange zaman kovası) | 10 dk | lib.rs 2530 |
| `UNDECRYPTABLE_BEFORE_REHANDSHAKE` / pencere / min aralık | 3 / 2 dk / 2 dk | lib.rs 2915-2917 |
| `PREKEY_ROTATE_MS` | 7 gün | lib.rs 1897 |
| `INBOUND_DEDUP_WINDOW_MS` / `_MAX_ENTRIES` | 10 dk / 8192 | lib.rs 2388 |
| `RATE_LIMIT_WINDOW_MS` / `_MAX_PER_WINDOW` / `_MAX_ESTABLISHED` | 10 sn / 60 / 600 | lib.rs 2674-2693 |
| `RECONNECT_SWEEP_INTERVAL_MS` | 15 sn | lib.rs 2730 |
| `KEEPALIVE_*` | 2 / 20 / 60 sn | lib.rs 2426-2436 |
| `MAX_ENVELOPE_BYTES` | 1 MiB | lib.rs 2515 |
| `MAX_DEPOSIT_BYTES` | 900 KiB | server_proto.rs 71 |
| `SERVER_ONLY_GRACE_MS` | 30 sn | server_client.rs 78 |
| `mailbox_ttl_ms` | 14 gün | server_proto.rs ServerLimits |
| `MAX_ATTACHMENT_SIZE` | 4 GiB | lib.rs 150 |
| `MAX_CONTACTS` | 500 | lib.rs 2656 |
| `PENDING_LINK_RETRY_HORIZON_MS` / `LINK_REQUEST_WINDOW_MS` | 1 saat / 24 saat | lib.rs 2795, 3012 |
| `PAIRING_WINDOW_MS` / `PAIRING_NONCE_REUSE_MS` | 30 dk / 5 dk | lib.rs 3061, 3064 |
| `RATE_LIMIT_MAX_UNKNOWN_TOTAL` (tanınmayan eşler, toplam) | 300 / 10 sn | lib.rs 2710 |
| `MAX_ARCHIVE_PUT_RECORDS` | 256 | server_proto.rs 82 |
| `ARCHIVE_TTL_MS` (sunucu arşiv satırı) | 13 ay (13×30 gün) | typeon-server/src/store.rs |
| `MAX_INVITE_PARTICIPANTS` | 1024 | call.rs |
| AppLock PBKDF2 | 300.000 it. | AppLock.kt |

Not: Bu sabitler zamanla değişir. Bir sayıya güvenmeden önce `grep -n "SABIT_ADI"` ile doğrula.

---

## 19. 2026-10-20/21 düzeltme turu (protokol ve davranış değişiklikleri)

Kaynak: `reviews/MERGED_REVIEWS.md`, raporlar `reviews/fixpass-2026-10-20/report_*.md`. Derlenmedi/cihazda denenmedi. Eski sürümlerle uyum aranmaz.

**PROTOKOL KIRILMALARI**
- **Sunucu protokolü v3** (`SERVER_PROTOCOL_VERSION`): `Register` → `Registered{proof_needed, refused}` (kalıcı reddedilenler `refused`'da); `Welcome` `enrollment_id` taşır; `enroll_signing_input` istemci PeerId'sini + `enroll_pk` + `enroll_pk_pq`'yu da bağlar.
- **Arşiv kablo kayıt kimliği** = `HKDF(arşiv anahtarı, konuşma, mesaj kimliği)` (anahtarlı; eskiden açık türetim). DB: `server_blob_uploads.server_id` sütunu. `sent_at_ms` hâlâ açık (karar bekliyor).
- **Paket imza girdisi** etiketli ve çerçeveli (`"p2pmsg-v0.5-packet"`; 3. turda `"p2pmsg-v0.6-packet"` ve **ham başlık baytları**); **DeviceAdd/DeviceRevoke/onay** imza baytları `"typeon-device-auth-v1"` ile. Sonuç: **TÜM cihazlar yeniden bağlanmalı (re-link), tüm kişiler yeniden eşleşmeli (re-pair)**; sürüm yükseltilmeli.
- **2. tur (2026-10-21):** oturum posta kutusu kimliği (artık çift başına sabit, bkz. §13.5); `ServerErrorCode::BadHash`; `FileChunkResponse::Busy`; eşleşme nonce kanıtı uzunluk-önekli; `DeviceAdd`/`DeviceRevoke` `signature_pq` zorunlu (`serde(default)` yok). Sürüm yükseltilmeli, tüm cihazlar güncellenmeli.
- **3. tur (2026-10-21, bu tur):** `MessagePacket.header` artık **ham CBOR baytları** olarak taşınır (`SignedHeader`) — imza o baytları kapsar (`p2pmsg-v0.6-packet`) ve aynı baytlar ratchet AEAD'in **associated data**'sıdır; `IdentityExchange` imzası **alıcı cihazın fingerprint'ini + zaman damgasını** kapsar (`p2pmsg-v0.5-identity-exchange`); `FirstContactSecret.group_id` eklendi (grup başına ilk temas sırrı, kişisel sır kaldırıldı); `GroupSyncRequest` yeni mesaj türü; `member_devices` artık **delta**; `Call.participants` eklendi; beyaz tahta özeti vuruş başına **içerik hash**'i. Sonuç: **TÜM cihazlar yeniden bağlanmalı (re-link), tüm kişiler yeniden eşleşmeli (re-pair)**; sürüm yükseltilmeli.
- `Contact.avatar_jpeg` `serde_bytes` (kardeş senkronu).
- `SiblingHistoryRequest.since_timestamp` alanı eklendi.

**DAVRANIŞ**
- Sunucu `Ack`/imleç, mesaj **işlendikten sonra** ilerler (`commit_server_fetches`); işlenmemiş/ertelenmiş gelenler varken `Fetch`/`Ack` yok.
- `ArchivePut` ≤ 256 kayıt. `Enroll`/`Rebind` küresel doğrulama bütçesi (120/dk). `RateLimited` geçici hata sayılır.
- **Tor zorunlu:** Tor kapalıyken `start_network` hata verir (ağ yok). `get_node_address` yalnız onion; onion hizmeti ayağa kalkana dek boş. QR/manuel kod da o zamana dek üretilmez (`Err`).
- **Eşleşme penceresi 30 dk** (`PAIRING_WINDOW_MS`; eskiden 24 sa), en çok 6 eşzamanlı nonce.
- JPEG/PNG'de metadata ayrıştırılamıyorsa gönderim reddedilir (fail-closed).
- Sunucu geçmişi **kapatılırsa sunucu arşivi silinir** (purge).
- Yeni hız sınırları: sunucudan gelen posta 600/10 sn (`source=None` bütçesi), tanınmayan eşler toplam 300/10 sn; sunucu `CHUNKS_PER_MINUTE` 600.
- Düğüm modu yalnız röle hizmetidir; DHT katkısı yok (D-03/H-16; uygulama dizesi düzeltildi).
- Linux: 60 sn etkinlik yoksa güç tasarrufu (`set_power_save`), ölçülü ağ (`gio::NetworkMonitor`) bildirimi.
- Bağlantı/kişi limiti dolunca `pairing_failed` (`contact_limit`) olayı; istemciler kullanıcıya bildirir.
- Sunucu panic'i `core_panic` olayı olarak bildirilir (yeniden başlatma yok).
- **Bildirimlerde mesaj metni varsayılan KAPALI** (`NotificationPrefs.showMessageText` = false): kapalıyken bildirim yalnız "Yeni mesaj" der — ne gönderen ne metin görünür; kullanıcı Ayarlar'dan açabilir.
- **`SYSTEM_ALERT_WINDOW` izni kaldırıldı** (istemci `AndroidManifest.xml`): arama ekranı bu izinle açılmıyor.
- **Release APK Gradle tarafından imzalanmaz** (`signingConfig` yok): imzayı yalnız `sign-release.sh` yapar (özel anahtar, v3 soy zinciri; en yeni build-tools; iki uygulama için de aynı betik).

**Sahip kuralı (D-21):** istemcide `FLAG_SECURE` yoktur ve eklenmez; sunucu uygulaması (`ServerActivity`) release (debug olmayan) derlemelerde kullanır.
