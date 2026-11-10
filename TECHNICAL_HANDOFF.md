# Typeon — Teknik Devir Dökümanı (Mimari, Güvenlik, Çalışma Anı Algoritmaları)

Bu doküman `HANDOFF.md`'nin (çalışma kuralları, dosya haritası) teknik tamamlayıcısıdır. Aşağıdaki her iddia kaynak kodda doğrulandı; dosya/fonksiyon adı verilmiştir. Çelişki halinde **kod** doğrudur (`SECURITY.md` ve `Description.md` kısmen eskidir).

**Son güncelleme: 2026-11-11 (HEAD `e916a13`).** Çekirdek (`p2p_messenger_core`) artık tek bir `lib.rs` değildir: 24 konu modülüne bölündü (§1.1). Bu belgede kod konumu `dosya.rs fonksiyon_adı` biçiminde verilir (çekirdek dosyaları: `p2p_messenger_android/app/src/main/cpp/rust/src/`); satır numarası verilmez, kayar. Bulmak için: `grep -n "fn ad" p2p_messenger_android/app/src/main/cpp/rust/src/*.rs`. Sürümler: istemci 6.0.7 (kod 51), sunucu uygulaması 6.0.1 (kod 44), Linux/Windows masaüstü 6.1.4, sunucu protokolü 7.

İçindekiler: 1 Katmanlar (1.1 modül haritası, 1.2 masaüstü istemci) · 2 Kripto ilkelleri · 3 Kimlik ve güven · 4 Oturum kurulumu (handshake) · 5 Ratchet · 6 Mesaj paketi · 7 Gönderim yolu · 8 Alım yolu · 9 Teslim/yeniden deneme · 10 Çoklu cihaz · 11 Grup · 12 Ağ katmanı · 13 Sunucu · 14 Yerel depolama · 15 Dosya/medya · 16 Arama · 17 Tehdit modeli · 18 Sabitler tablosu · 19 2026-10-20/21 düzeltme turu · 20 2026-11-05..11 değişiklikleri

---

## 1. Katmanlar

```
┌────────────────────────────────────────────────────────────────┐
│ UI:  Android Kotlin (ChatActivity, P2PService…)                 │
│      | GTK4 + libadwaita (Linux ve Windows, aynı crate)         │
├────────────────────────────────────────────────────────────────┤
│ Köprü: JNI (jni_exports.rs, P2PLib.kt) | api.rs (masaüstü,      │
│        JNI'siz)                                                 │
├────────────────────────────────────────────────────────────────┤
│ Çekirdek (crate p2p_messenger_core): P2PCore — struct lib.rs'te,│
│   `impl P2PCore` 24 konu modülüne bölünmüş (§1.1)              │
│   iş mantığı, DB, libp2p swarm, Tor, sunucu istemcisi, arama   │
├────────────────────────────────────────────────────────────────┤
│ typeon-crypto: identity, ratchet, packet, server_proto, seal   │
├────────────────────────────────────────────────────────────────┤
│ libp2p (noise, yamux, gossipsub, kad, relay, dcutr, req-resp)  │
│ arti (Tor istemci + onion servis) · SQLCipher · ml-kem/ml-dsa   │
└────────────────────────────────────────────────────────────────┘
          (isteğe bağlı) typeon-server: store-and-forward
```

- **Tek `P2PCore` örneği**, global `core_lock()` mutex'i arkasında (`core_lock.rs core_lock`; salt-okunur durum sorguları için `core_lock_read`). Her JNI/api çağrısı `catch_panic` (`jni_exports.rs catch_panic`, içinde `RUNTIME.enter()`) + `core_lock()` sırasıyla girer; `api.rs` aynı sırayı uygular. Yani çekirdek **tek kilitli, olay-sürümlü**: paralel iş yok, uzun işlem kilidi tutar (`core_lock.rs` içindeki `lock_watch` modülü kilit süresini izler; 10 sn'den uzun tutma loglanır). Kilit bırakılarak çalışan dosya/çıkartma işleri `media_unlocked.rs`'tedir.
- Ağ olayları **çekerek (poll)** işlenir: Kotlin `P2PService` döngüsü `poll_events()` (`poll.rs poll_events`) çağırır; çekirdek swarm olaylarını `swarm.next().now_or_never()` ile bloklamadan boşaltır, JSON olay listesi döndürür.
- Masaüstü istemci (Linux/Windows) aynı çekirdeği `api.rs` üzerinden rlib olarak çağırır; protokolün ikinci kopyası yoktur.

### 1.1 Çekirdek modül haritası (`p2p_messenger_android/app/src/main/cpp/rust/src/`)

`lib.rs` yalnız şunları tutar: `P2PCore` yapısı, global `RUNTIME`/`CORE`/`NET_WAKE`, `MAX_ATTACHMENT_SIZE`, modül listesi ve `CORE_SRC`. Her alt modül `use super::*;` ile crate kökünü görür; eskiden özel olan öğeler `pub(crate)` oldu; kök modülleri yeniden dışa aktarır, yani `crate::ad` yolları değişmedi. Kaynak metni tarayan testler `crate::CORE_SRC` okur (`lib.rs`'teki `concat!(include_str!(...))`; **yeni bir çekirdek dosyası açılırsa oraya da eklenmeli**).

| Dosya | İçerik (başlıca) |
|---|---|
| `lib.rs` | `P2PCore` struct, `RUNTIME`/`CORE`/`NET_WAKE`, modül bildirimleri, `CORE_SRC` |
| `core_lock.rs` | `core_lock`, `core_lock_read`, `core_lock_poll`, `lock_watch` (kilit izleme), `wait_for_network_activity` |
| `media_unlocked.rs` | kilitsiz dosya/etiket (sticker) işleri: `prepare_and_send_file_unlocked`, `send_sticker_unlocked`, `import_sticker_frames_unlocked` |
| `wire.rs` | libp2p kablo tipleri (keepalive, ack, envelope) ve birleşik `P2PBehaviour` |
| `util.rs` | küçük serbest yardımcılar: `group_msg_tag`/`group_msg_id_bound`, `handshake_signing_input`, `group_update_signing_input`, `group_tie_hash`, `verify_hybrid_signature(_with)`, `seal_with`, `founder_transfer_floor`, `clamp_received_times`, `mono_ms` |
| `types.rs` | anahtar paketleri, cihaz kayıtları, özetler, aktarım durumu, `PREKEY_ROTATE_MS` |
| `tuning.rs` | zaman aşımı/limit/protokol sabitleri (§18'in çoğu) |
| `db.rs` | `P2PCore::new`, `init_db` (şema + `migrate`), `meta_*`, SQLCipher anahtarı (`db_key_pragma`) ve göç |
| `pairing.rs` | kendi kimliği, QR/kod ile eşleşme, ilk-temas sırları, `IdentityExchange` (`process_identity_exchange`) |
| `devices.rs` | cihaz fan-out (`fanout_targets`), cihaz yetki imzaları, cihaz bağlama/bildirimleri |
| `sibling_sync.rs` | kardeş cihaz eşitleme: roster/`DeviceSync` (`build_sync_payloads`), okundu (`sync_read_state`), geçmiş (`build_sibling_history_response`, `apply_sibling_reply`) |
| `contacts.rs` | kişiler, engelleme, cihaz uyarıları (`evaluate_sender_device`), profil, hesap/kişi silme, `wipe_all_local_state` |
| `session.rs` | bağlantılar, prekey'ler, handshake'ler, ratchet rotasyonu (`initiate_handshake_with`, `process_handshake_init`, `maybe_rotate_ratchet`, `note_undecryptable`) |
| `send.rs` | gönderim (`send_message_content_inner`), tepki, görüldü, düzenle/sil, Ack, yazıyor |
| `receive.rs` | `receive_message` ve çözülmüş içeriğin dağıtımı (`dispatch_received_content*`) |
| `archive.rs` | geçmiş istekleri, mesaj arşivi (`archive_message`), arşivde düzenle/sil, `pending_sibling_ops`, grup yazar kanıtı |
| `persist.rs` | mühürlü yerel blob (`seal_local_blob`), ratchet/atlanmış anahtar kalıcılığı, kalıcı yeniden denemeler |
| `group_ops.rs` | grup oluştur/güncelle/üyelik, kurucu zinciri (`heal_founder_chain`), grup mesajı fan-out, `process_group_update` |
| `storage.rs` | etiketler (sticker), depolama sınırları ve budama |
| `network.rs` | swarm başlatma (`start_network`), radyo/güç modları, röleler, yeniden bağlanma, yeniden denemeli yayın (`try_publish_raw_via`, `retry_unconfirmed_messages`) |
| `file_transfer.rs` | dosya teklifleri, parçalı indirme, parça servisi |
| `poll.rs` | `poll_events`, erken paket tamponu, hız sınırı, `process_incoming_envelope` |
| `recovery.rs` | kurtarma dosyası dışa/içe aktarma |
| `jni_exports.rs` | Android JNI bağları (`Java_com_p2p_messenger_P2PLib_*`) ve yardımcıları (`catch_panic`) |
| `core_tests.rs` | crate düzeyi testler (`#[cfg(test)]`) |

Çekirdek crate'in modül-dışı dosyaları (bölünmeden önce de ayrıydı): `api.rs` (JNI'siz arayüz), `server_client.rs` (istemcinin sunucu tarafı + `ServerCore` ile konuşma, ~4300 satır), `call.rs`, `whiteboard.rs`, `attachments.rs`, `tor.rs` (arti + `DialReject`), `group.rs`, `contact.rs`.

### 1.2 Masaüstü istemci (`Linux/`, crate `typeon-linux`) — Linux ve Windows

Aynı GTK4 + libadwaita crate'i iki platformda derlenir; platform kodu `#[cfg(windows)]` / `#[cfg(unix)]` ile ayrılır (`main.rs`, `app.rs`, `font.rs`, `secrets.rs`, `util.rs`, `call_media.rs`, `ui/window.rs`, `ui/settings.rs`). Windows için `main.rs` `audio` ve `keyring` modüllerini `#[cfg_attr(windows, path = "audio_win.rs" / "keyring_win.rs")]` ile başka dosyaya yönlendirir.

- **Yalnız ikincil cihaz, bağlama-only.** Karşılama sayfası (`ui/onboarding.rs welcome_page`) yalnız "Link to my phone" sunar; hesap oluşturma ve kurtarma-dosyası geri yükleme masaüstünden kaldırıldı (`core::create_identity` yalnız bağlama için kendi cihaz anahtar çiftini üretir). Birincil/yetki rolü yok: ulaşılamayan masaüstü diğer cihazları bozmasın diye (sahip kuralı, `AGENTS.md`). `1a180c3`: bekleyen bağlama (`awaiting_link`) sayfasından onaylı "sil ve çık" ile kurulum ekranına dönülebilir.
- **Kasa anahtarı:** Linux'ta Secret Service (GNOME Keyring / KDE Wallet, `keyring.rs`+`secrets.rs`); Windows'ta DPAPI (`keyring_win.rs`: `CryptProtectData`/`CryptUnprotectData`, mühürlü anahtar veri dizininde `vault-key.dpapi`; veri dizini `main.rs data_directory` = `glib::user_data_dir()/typeon`, Windows'ta `%LOCALAPPDATA%\typeon` — dizin yolunu `AGENTS.md` verir, GLib'in Windows davranışına dayanır, kodda ayrıca doğrulanmadı).
- **Windows'a özel:** `win.rs` — kendi `Shell_NotifyIconW` tepsi simgesi (`install_tray`: sol tık açar, sağ tık Open/Quit), balon bildirimleri (`win::notify`; `app::post_notification` Windows'ta bunu çağırır, gio `send_notification` çağrılmaz çünkü GLib'in ikinci, menüsüz simgesini yaratır), otomatik başlatma (`set_autostart`: HKCU `...\Run`, `--background` argümanı), özel yazı tipi (`register_font` → `pango_font_map_add_font_file`). Pencere kapatılınca tepsiye gizlenir (`set_hide_on_close`), ana menü "Quit" çıkar (`ui/window.rs`). Sesli mesaj: GStreamer `wasapi2src` (`audio_win.rs`); arama: `call_media.rs` içinde `wasapi2src`, `mfvideosrc`, kodlayıcı `mfh265enc`/`mfh264enc`/`openh264enc`, çözücü `d3d11h26{4,5}dec`/`openh264dec`.
- **Çekirdek tarafında Windows farkı:** `util.rs mono_ms` Windows'ta `GetTickCount64` kullanır (CLOCK_BOOTTIME yok); `rust/build.rs` libjxl için sysroot'un statik lcms2'sini bağlar.
- **Derleme (sahip "derle" derse):** Linux'ta `Linux/packaging/README.md` (Flatpak, GNOME SDK içinde); Windows'ta `Linux/packaging/windows/build.sh`/`package.sh` (llvm-mingw + MSYS2 CLANG64 sysroot ile Linux'ta çapraz derleme) veya `package-msys2.sh`; ayrıntı `AGENTS.md`.

---

## 2. Kripto ilkelleri (hepsi doğrulandı)

| Amaç | Algoritma | Yer |
|---|---|---|
| İmza | **Ed25519 + ML-DSA-87**, ikisi de üretilir ve ikisi de doğrulanır | `util.rs verify_hybrid_signature` / `verify_hybrid_signature_with` |
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
2. Değilse mevcut zincirde çöz (`chain_decrypt`): `message_number < next` ise `skipped_keys`'ten, değilse ileri sar. Üst sınırlar: `MAX_SKIP_AHEAD = 2.000` adım (kimlik doğrulanmadan HKDF maliyeti sınırı), önbellekte en çok `MAX_SKIPPED_KEYS = 1000` (en eskiler atılır).
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
- **Katı CBOR:** eş kaynaklı üç ayrıştırıcı sondaki baytları reddeder (6a603c7): `MessageContent::from_cbor` (`content: trailing bytes`; en çok `MAX_NESTING` = 32 iç içelik), `SignedHeader` deserialize (`header: trailing bytes`; özyineleme sınırı 4), `RatchetPublicKeys::from_bytes` (`Ratchet public key: trailing bytes`; ≤ 2048 bayt, anahtar uzunlukları tam 32 ve 1568). Aynı içeriğin iki farklı bayt dizisi olmaz.

---

## 7. Gönderim yolu (algoritma)

`send_message` → `send_message_content_inner(peer_fp, content, …)` (`send.rs`):

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

`receive_message` (`receive.rs`):
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

- **Ack alan türler** (`needs_delivery_confirmation`): `Text, Edit, Delete, Reaction, HistorySyncRequest/Response, FileOffer, GroupUpdate, LeaveGroupRequest, GroupSyncRequest, ProfileUpdate, DeviceLinkGrant, DeviceAddNotice, DeviceRevokeNotice, FirstContactSecret, DeviceSync, SiblingEcho, ReadStateSync, SiblingHistoryRequest, AccountDeleted, WbDigest`. Ack **almayanlar:** `Ack, Seen, TypingIndicator, AddressAnnounce, SiblingHistoryResponse`, arama/WbOps.
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
- Kardeş geçmişi (`sibling_sync.rs`): aşağıdaki **Kardeş geçmişi** bloğu. Okundu: `ReadStateSync` (kalıcı watermark, `sync_read_state` / `apply_incoming_read_watermark`).
- `pending_sibling_ops` tablosu: hedef henüz yokken gelen kardeş işlemleri tamponlanır.
- İptal: `DeviceRevoke` (imzalı); iptal edilen cihazdan gelen paket reddedilir ve `answer_revoked_sibling`.
- Yetki: sadece kimliğin kök (birincil) cihazı ekler/çıkarır/siler.

**Kardeş geçmişi (history backfill)** — iki tetikleyici, tek yanıt üreticisi `sibling_sync.rs build_sibling_history_response`:
- *Otomatik* (`request_sibling_backfill`): `SIBLING_BACKFILL_INTERVAL_MS` (30 dk) debounce'lu; yalnız **bağlı** kardeşlere (çevrimdışına gönderilen istek sunucuda yeniden yatırılıp geceleri radyoyu açık tutuyordu); `since_timestamp` = o kardeşten son yanıtlanan istekten beri (`sibling_backfill_since`, `SIBLING_BACKFILL_SINCE_MARGIN_MS` = 10 dk saat farkı payı), sohbet başına `SIBLING_BACKFILL_PER_CONVERSATION` (30). Kapsamsız (tüm sohbetler) yanıtta satır sınırı `SIBLING_BACKFILL_MAX_ENTRIES` (300) sohbet/grup sayısına bölünür.
- *Kullanıcı basışı* "Fetch older history" (`request_older_sibling_history`): tek sohbet, `[after_timestamp, before_timestamp)` penceresi, sayfa başına `HISTORY_SYNC_MAX_MESSAGES` (200); her bağlı kardeşe gider ve `sibling_fetch_open[(kardeş, before, after)]`'e yazılır; yanıt (`SiblingHistoryResponse{entries, window, more}`) pencereyi **yankılar**, yalnız yankısı açık bir basışla eşleşen yanıt kullanıcı fetch'i sayılır (eşleşme tüketilir; yeniden başlatma `sibling_fetch_open`'ı siler, o durumda kayıp basış yeniden açılır: `reopen_fetch_cursor`). `more` ise yanıtlayan sayfayı kesmiştir ve pencerenin eski kalanı aynı kardeşten tekrar istenir.
- **Bütçe:** metin satırları `HISTORY_SYNC_MAX_TEXT_BYTES` (512 KiB) bütçesinden düşer (gossipsub 1 MiB sınırı için). Kapsamsız yanıtta sığmayan satır **atlanır** (bir uzun mesaj sonraki sohbetleri kesmesin); kapsamlı basışta, atlanan satırın altındaki eski satırlar kalıcı delik olacağı için yanıt orada biter (`more = true`).
- **Ekler ve tepkiler** (dcd2cb6): `SiblingHistoryEntry` iki alan kazandı: `file: Option<Box<MessageContent>>` (her zaman bir `FileOffer`; `file_id` = `message_id`, alıcı dosyayı o kardeşten indirir) ve `reactions: Vec<(tepki_veren_identity, emoji, reacted_at_ms)>` (boş emoji = geri alma, damgası için saklanır). `sibling_file_entries` yalnız `status = 'complete'` dosyaları, `created_at` penceresinde, en yeni `limit` tanesini yollar; dosya anahtarı (`unwrap_file_key`), `chunk_hashes`, başlık/alıntı alanları ve etiket bilgisi teklifle gider. Alıcı `apply_sibling_file` ile satırı `receive_file_offer` gibi yazar, sonra yönünü/sohbetini/tarihini kardeşinkine çevirir. Ek satırları metin balonu değildir: `apply_sibling_reply` olay JSON'una yalnız `file.is_none()` ve boş olmayan metinler girer, sohbet yeniden yüklenir.
- **Bütçe kuralı, ek** (670ab45): ek `512 + başlık + chunk_hashes` bayt + önizleme olarak ücretlendirilir; bütçe yetmezse **önizleme (preview_jpeg) önce atılır** — dosya yine gelir, indirilene dek genel simgeyle görünür; yalnız önizlemesiz hali de sığmazsa satır atlanır. Tepki taşıyıcı satır `128 + id + tepkiler` bayt.
- **Basış önceki basışla kayan imleç sorunu** (926d724): önceki bir basış fetch imlecini metnini getirdiği satırların altına indirmişti; o satırların ekleri/tepkileri sonraki hiçbir pencerede olmuyordu. Şimdi yanıtlayan, pencere satırlarından **sonra** (bütçenin kalanıyla), pencere sonundan (`before`) beri gönderilmiş satırların biten eklerini (`sibling_file_entries`) ve tepkilerini (`sibling_reaction_entries`, metinsiz taşıyıcı satır) ekler. Alıcı (`apply_sibling_reply`) pencere dışı kayıtlardan yalnız ek ve tepki taşıyıcılarını (`file.is_some() || metin boş`) tutar, metin satırları pencerede kalır; tepki taşıyıcı için satır **yazılmaz** (yalnız elindeki satıra tepki uygulanır).
- **Alıcı tarafı** (`apply_sibling_history`): `file` yalnız `FileOffer` ve `file_id == message_id` ise kabul edilir; dedup **sohbet başına** (başka sohbetin satırı bunu bastırmasın); tepkiler yalnız satır orada olduğunda (`present`) uygulanır (en çok 256 tepki, emoji ≤ 64, tepki veren ≤ 128 bayt, `apply_reaction`); kullanıcı basışı değilse, kullanıcının temizlediği sohbetin tabanının (`history_floor`) altındaki satırlar yazılmaz; ayrılınmış/bilinmeyen gruba geri yazılmaz. Pencere isteği yanıtlayanda en çok `HISTORY_FETCH_WINDOW_MS` = 30 gün'e kısılır (`receive.rs`, `SiblingHistoryRequest` kolu); istek yalnız kendi kimliğimizin cihazından geldiyse yanıtlanır, `SiblingHistoryRequest` her halükârda Ack'lenir.
- **Kişi avatarları** (dcd2cb6): `build_sync_payloads` her avatarlı kişi için ayrı bir `SyncPayload` parçası ekler (≈250 KB'a kadar, `devices` boş: bilinmeyen kişi böyle bir parçadan yaratılmaz); önceden bağlı cihaz avatarı ancak kişi `ProfileUpdate` yollarsa alıyordu. Linux (`Linux/src/app.rs`, `ui/chats.rs`) sync olayında kişileri yeniler.

---

## 11. Grup

**Yapı** (`group.rs`): `Group{group_id, name, founder_identity_id, members[GroupMember{identity_id, added_at, added_by}], version, avatar_jpeg, founder_chain}`. `group_id` biçimi `group-<16..48 hex>`; hex kısmı kurucu kimliği + nonce'tan türer (`group_id_for_founder`), yani bilinmeyen bir grup kimliği kurucusuna bağlanamıyorsa reddedilir. Üye sınırı `MAX_GROUP_MEMBERS`, `member_devices` ≤ üye × 5.

**İlk temas sırrı artık grup başına:** `FirstContactSecret{secret, group_id}` — cihazın sırrı `SHA-256("typeon-group-first-contact-v1" ‖ master ‖ group_id)`'in ilk 16 baytıdır (`own_group_contact_secret(group_id)`), kurucu onu `gf:<fp>:<group_id>` altında saklar ve **yalnız o grubun** üyelerine dağıtır. Eski **kişisel** sır kaldırıldı: üyeler artık tek bir kişisel ilk-temas kutusuna değil, **kendi grubunun** kutusuna erişir; bu kutu yalnız cihaz grupta olduğu sürece kayıtlı tutulur (`first_contact_secrets`).

**Değişiklik türleri** (`GroupChange`): `Add(id)`, `Remove(id)`, `Rename(ad)`, `AvatarUpdate(Option<bytes>)`, `Delete`, `TransferFounder(id)`. Hepsini **yalnız mevcut kurucu** imzalayabilir (ayrı yetki mekanizması yok; üyeler kendi başlarına değişiklik yapamaz). Üye ayrılmak isterse `leave_group`: kurucunun tüm aktif cihazlarına `LeaveGroupRequest` yollar (Ack'li), kendi yerelinde `remove_group_locally` yapar (`removed_groups`'a sürüm+kurucu yazılır, bekleyen kuyruklar ve beyaz tahta silinir) ve kardeşlere `SiblingEchoBody::GroupLeft` yansıtır. Kurucu bu isteği alınca `remove_from_group` ile `Remove` yayınlar (bu fonksiyon yalnız kurucuda çalışır: "Sadece kurucu üye çıkarabilir"). **Kurucu ayrılamaz**; grubu herkes için silebilir (`Delete`) ya da yetkiyi `TransferFounder` ile devreder.

**Doğrulama** (`validate_group_update`): imzalayan kimlik = `founder_identity_id` (aksi `NotFounder`); imzalayan cihaz aktif olmalı; `new_version > group.version` (aksi `StaleOrOutOfOrderVersion`, zararsız sayılıp onaylanır); `new_version <= version + 4096` (`MAX_VERSION_JUMP`). `apply_change`: `Remove` kurucuyu çıkaramaz; `TransferFounder` hedefi üye değilse yok sayılır (sürüm yine ilerler).

**Eşit sürüm çakışması (H78):** iki kurucu cihazı aynı sürümü imzalayabilir. Alıcı, elinde tuttuğu sürümdeki bir güncelleme için `group_tie_hash` (SHA-256: grup id + sürüm + değişiklik + ad + üye listesi + imzalayan) **daha büyükse** güncellemeyi yeniden alır; `Delete` ve aynı üye/adı tekrarlayan bir "yeniden gönderim" de alınır. Böylece her üye aynı sürümde **aynı** durumda biter; kaybeden kurucu cihaz kardeşinin güncellemesini alır ve sonraki değişikliği `max(görülen sürüm)+1` olarak yapar.

**Alım adımları** (`group_ops.rs process_group_update`):
1. `group_id` biçimi → imzalayan cihaz bilinen mi → `group_update_signing_input` (grup id, sürüm, değişiklik, ad, üyeler, üye cihazlar, imzalayan kimlik+cihaz) üzerinde hibrit imza.
2. Ad ≤ 256 bayt; üye listesi ≤ sınır ve elemanlar fingerprint-hex olmalı.
3. Grup yerelde yoksa: daha önce **ayrıldığımız** (`removed_groups`) bir grup yeni sürümle ve bizi `Add` ile eklemeden geri gelemez; bizi üye yapmayan bilinmeyen grup **reddedilir**.
4. Kurucu zinciri: `heal_founder_chain` ile `FounderTransfer` zinciri yürünür (her halka eski kurucunun hibrit imzası, `founder_transfer_signing_input`); `founder_transfer_floor` geri sarmayı engeller; zincir `MAX_FOUNDER_CHAIN` ile kısıtlı.
5. `Delete` → `remove_group_locally`. Aksi halde `sync_members` + `apply_change`; bizi `Remove` ediyorsa grup yerelden silinir.
6. `member_devices` + `member_device_proofs`: üyenin cihaz anahtarları kurucu tarafından "vouch" edilir (`adopt_vouched_member_devices`); güncelleme **delta**dır: yalnız son güncellemeden sonra **yeni veya değişmiş** cihazlar taşınır (yeni eklenen üyeye tam liste gider). Eksik kalan üye ya da sürüm boşluğu `GroupSyncRequest` ile kurucudan **tam durum** ister (kurucu üye başına en çok 10 dk'da bir yanıtlar, `sign_group_resync`); `first_contact_secret` (16 bayt) `gf:<fp>:<group_id>` anahtarıyla saklanır → hiç eşleşmemiş üye o grubun ilk temas kutusuna açılabilir.

**Kurucu cihazları ve yeniden gönderme:** Kurucunun imzaladığı her güncelleme **kurucunun kendi kardeş cihazlarına** da gider (`send_group_update_to_siblings`); böylece iki kurucu cihazı aynı sürümü imzalamaz. Kurucu ayrıca grubu herkese yeniden gönderebilir (`resend_group_to_all`; Android `P2PLib.resendGroupToAll`): güncel imzalı durum **her üye cihazına** tekrar gönderilir.

**Mesaj gönderme** (`group_ops.rs send_group_message`): üye olduğunu kontrol et → `local_id` üret (`<8 bayt etiket hex><-uuid>`; etiket = `util.rs group_msg_tag(grup, yazar kimliği, "-<uuid>")`, alıcı `group_msg_id_bound` ile kimliğin yazara ait olduğunu doğrular: başka üye aynı kimlikle çakışan mesaj üretemez, düzenle/sil yalnız yazara bağlanır) → `sign_group_author`: cihaz imzası ile `author_proof = "cihaz_fp:imza_klasik_hex:imza_pq_hex"` (`group_author_statement(group_id, message_id, identity, device, text)`) → arşive yaz → **her diğer üye için** `send_group_message_to_member`: üyenin tüm aktif cihazlarına ayrı 1:1 paket (`send_message_content`). Üyenin aktif cihazı henüz bilinmiyorsa içerik `pending_group_messages` kuyruğuna (üye başına `MAX_PENDING_GROUP_MESSAGES_PER_MEMBER`, taşarsa en eski atılır, DB'de kalıcı) yazılır ve `group_sync_sweep` periyodik yeniden dener. Son olarak kardeş cihazlara `SiblingEcho` yansıtılır.

**Alım** (`receive_message` Text kolu): `sender_may_post_to_group` (üye değilse reddet) → aynı `group_message_local_id` arşivde varsa yalnız Ack → `group_author_proof_valid` (cihaz o kimliğe ait mi + imza) geçerliyse `author_proof` saklanır → arşivle → Ack. Edit/Delete aynı `author_proof` ile yazara bağlanır.

**Eksik geçmiş:** `HistorySyncRequest{group_id, …}` / `HistorySyncResponse` ile diğer üyelerden; sunucu arşivi opsiyonel kaynak (§13).

---

## 12. Ağ katmanı

**Swarm kurulumu** (`network.rs start_network`):
- Kimlik: libp2p Ed25519 anahtarı `files/libp2p_identity.key` dosyasında (protobuf; bozuksa yenisi üretilir, okunamazsa o çalıştırma için geçici). Bu **Typeon cihaz kimliğinden ayrıdır**; PeerId bu anahtardan gelir ve sunucu kaydında görünür.
- Taşıma: `tcp(nodelay)` → **`DialReject`** (`tor.rs`) ile sarılı (dışarı dial her zaman `MultiaddrNotSupported`) → noise → yamux; ve `ArtiDialTransport` (Tor üzerinden `.onion` dial) → noise → yamux. Dinleme yalnızca `127.0.0.1:<listen_port>`'ta; Tor onion servisinin gelen akışları `tor.rs bridge_incoming_stream` ile bu yerel porta köprülenir (`tor.rs MAX_INBOUND_ONION_STREAMS = 64`). Yani clearnet'ten gelen/giden doğrudan bağlantı yoktur.
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

`ServerRequest`: `Hello{version}` (sürüm **7**, `SERVER_PROTOCOL_VERSION`; sürüm geçmişi `server_proto.rs`: 2 `Registered`, 4 blob `upload_secret`, 5 oturum/röle kutu kimliği kanıt anahtarından (`key_bound_mailbox_id`), 6 24 baytlık yükleme sırrı + yazar etiketi, 7 blob kimliği yalnız etiketten sonraki baytları hash'ler), `Enroll{…}`, `Rebind{…}`, `Register{add, drop, proofs}`, `Deposit{mailbox, sealed}`, `Fetch{cursors, max_items, max_bytes}`, `Ack{acks:[(mailbox, seq)]}`, `Cancel{mailbox, seqs}`, `ArchivePut/Probe/Fetch/Purge`, `BlobPut/Finish/Delete`; sunucu→istemci: `Notify`, `Push{item}`.
`ServerResponse`: `Welcome{version, challenge, enrolled, enrollment_id, limits, server_name}`, `Enrolled{enrollment_id, limits}`, `Deposited{seq}`, `Batch{items, more}`, `ArchiveProbed`, `ArchiveBatch`, `Registered{proof_needed, refused}` (`Register` yanıtı; her kutu kabulse düz `Ok`; eski `ProofNeeded` yok), `Ok`, `Err(code)`. Hata kodları (`ServerErrorCode`): `NotEnrolled, BadInvite, BadSignature, Stale, UnknownMailbox, TooLarge, QuotaExceeded, RateLimited, Revoked, BadDirection, Unsupported, Internal, BadHash, BlobIncomplete`. `MailItem.seq` **kutu başına** artar (aşağıda §13.3).

### 13.2 Kayıt (sunucu tarafı `handle_*`)
- `Hello`: sürüm ≠ `SERVER_PROTOCOL_VERSION` (7) → `Unsupported`. Blob istekleri 24 baytlık bir `upload_secret` taşır; blob kimliği = 8 baytlık yazar etiketi (açık) + `blob_id_hash_hex` (etiketten sonraki baytların SHA-256'sı, `typeon-blob-id-v3`, ilk 16 bayt) = 48 hex karakter (`blob_id_for_upload_secret`). Aksi halde 32 bayt rastgele `challenge` üretilip bağlantı durumuna yazılır; yanıt `Welcome` (+ `enrolled` = bu PeerId'nin kaydı `Active` mi, `enrollment_id` = o kaydın kimliği; `Enrolled` yanıtı kaybolan istemci geri alır).
- `Enroll`: sırayla — sürüm; `|now − ts_ms| ≤ 5 dk` (`Stale`); davet jetonu hash'i geçerli ve kullanım hakkı var (`BadInvite`); bağlantının tek kullanımlık `challenge`'ı `take()` ile alınır ve istemcinin gönderdiğiyle eşit olmalı (`BadSignature`); hibrit imza `enroll_signing_input(version, server_peer_id, client_peer_id, token, enroll_pk, enroll_pk_pq, challenge, ts)` doğrulanır (istemci PeerId'si ve iki enroll anahtarı imzaya bağlı); `Enroll`/`Rebind` ortak bir **küresel doğrulama bütçesine** (`verify_budget`, dakikada 120, eş başına en çok 4) tabidir → aşılırsa `RateLimited`; `Register` kanıtlarının ayrı havuzu var (dakikada 256, eş başına 64 = bir tam `Register`), yani bir eş ne başkalarını ne de kayıtları aç bırakabilir; reddedilen istek bütçeden düşmez; anahtar `blocked_keys`'te ise `Revoked`; herkese açık davet (`uses_left == -1`) saatte 60 kayıt tavanı (`QuotaExceeded`); aktif kayıt sayısı `max_enrollments` (varsayılan 64, son 30 gündür boşta olmayanlar sayılır) → `QuotaExceeded`; sonra `enroll_with_invite` tek işlemde jeton tüketir + kaydı yazar. Aynı PeerId yeniden kayıt olursa önceki `enrollment_id` ve kota sayaçları korunur.
- `Rebind`: kayıt bilinmiyorsa `NotEnrolled`; `Rebind` doğrulama havuzu (`VerifyPool::Rebind`); `ts` penceresi, `challenge`, mevcut kaydın `enroll_pk` hibrit imzası `rebind_signing_input(enrollment_id, server_peer_id, yeni_peer_id, challenge, ts)`. **`Revoked` (iptal edilmiş kayıt ya da `blocked_keys`'teki anahtar) yalnız imza doğrulandıktan sonra** döner (6a603c7): kayıt kimliğini bilen ama anahtarı olmayan biri iptal durumunu öğrenemez. Sonra kayıt yeni PeerId'ye taşınır, jeton tüketilmez.
- **İptal (revoke) = engelleme.** Sunucu tarafında iptal, kaydın `enroll_pk`'sini `blocked_keys`'e koyar (`store.rs`); "kaydı kapatıp taze davetle dönüşe izin ver" DEĞİLDİR. Aynı anahtar geri gelemez; ama uygulamayı yeniden kurup yeni PeerId + yeni enroll anahtarı üreten biri, kullanılabilir bir davet jetonuyla yeniden kaydolabilir. Gerçek yasak için **katılım kodunu (davet jetonunu) döndür**. Sunucu uygulamasını kaldırmak onion kimliğini ve kayıtlı her cihazın jetonunu siler.
- Diğer tüm istekler `authenticate(peer)` ister; kayıt yoksa `NotEnrolled`, iptalse `Revoked`. Her istek önce `check_rate` (dakikada `requests_per_minute`=1800; dosya parçası için ayrı `CHUNKS_PER_MINUTE`=600) → `RateLimited`.

### 13.3 Posta kutusu semantiği (`store.rs`)
- **`Register{add, drop, proofs}`:** `add`/`drop` ≤ `max_mailboxes`, `proofs` ≤ `MAX_REGISTER_PROOFS` (64); kimlikler `is_safe_id` olmalı (aksi `BadDirection`). Yeni okuyucu, kutunun **kutu anahtarı** (`mailbox_proof_seeds`'ten türeyen hibrit anahtar) ile imzalı kanıt ister (`register_signing_input(mailbox, enrollment_id, server_peer_id)`); kanıtlar kendi doğrulama havuzundan düşer. Sunucu kutuyu bir anahtara değil **okuyucu başına** anahtar karmasına (`mailbox_readers.key_hash`, `mailbox_key_hash`) bağlar; eski `mailbox_keys` tablosu kaldırıldı. `mk_` önekli (anahtara-bağlı) kutu kimliği, yalnız kendi kanıt anahtarından türeyen kimlik olabilir (`key_bound_mailbox_id`); başka anahtar `refused`. Kanıtı hiç gelmeyen kutular `Registered{proof_needed}`'de, doğrulanmayan/reddedilenler `refused`'ta döner (istemci ≤64 kanıtlı yeniden `Register` yollar; hepsi kabulse `Ok`). Okuyucu sınırı **anahtar başına** `MAX_READERS_PER_KEY` = 2 (I-48): iki farklı anahtar aynı ilk-temas kutusunda ayrı ayrı 2'şer okuyucu alabilir, biri ötekinin yerini dolduramaz. Aynı anahtarla dolu kutuya gelen yeni okuyucu (geri yüklenmiş cihaz) en uzun süredir görülmeyen aynı-anahtar okuyucunun yerini **yalnız** o okuyucu 7 gündür (`READER_EVICT_IDLE_MS`; kendi istekleri ya da son `Register`'ı) görülmediyse alır, aksi halde `refused`. Kayıt sayısı `max_mailboxes` aşılırsa da `refused`. Kabul edilen kutular sunucuda `live_interest[peer]`'e yazılır (Push/Notify hedefi).
- **`Deposit`:** `sealed ≤ min(max_item_bytes, 900 KiB)` (`TooLarge`); yatıran dışında, aktif kayıtlı bir okuyucusu olmayan kutu (`mailbox_has_other_reader`) → `UnknownMailbox`; yatıran kaydın `bytes_mail ≤ max_mail_bytes`, toplam disk bütçesi (`total_budget_exceeded`) ve **yatıranın o kutudaki** öğe sayısı (`depositor_item_count`) < `max_items_per_mailbox` (5000) → aksi `QuotaExceeded`. Aynı `(mailbox, depositor, sha256(sealed))` zaten varsa **yeni satır açılmaz**, TTL uzatılır ve eski `seq` döner (idempotent). Aksi halde `mail` satırı: **`seq` kutu başına sayaçtır** (`mail_seq` tablosu: `INSERT ... ON CONFLICT DO UPDATE SET last = last + 1 RETURNING last`; satır kimliği ayrı `id`, `UNIQUE(mailbox_id, seq)`), böylece bir okuyucu `seq` boşluklarından sunucunun toplam alım hızını kestiremez. `mail_seq` satırı hiç silinmez (kutu boşalsa da sayaç sıfırlanmaz, yoksa yeni posta okuyucu imlecinin altına düşerdi). Eski küresel-AUTOINCREMENT şemadan göç (`init_schema`, `SCHEMA_VERSION` 4): eski satırlar `seq`'ini korur, yeni kutular eski en yüksek değerin (`meta.mail_seq_base`) üstünden başlar → hiçbir istemci imleci yeni postanın üstünde kalmaz. `expires_at = now + mailbox_ttl` (14 gün).
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
**Deposit tarafı** (`server_client.rs try_server_deposit`): bkz. §7. `Deposited{seq}` gelince `server_deposit_locations[(server, message_id)] = (mailbox, seq)` saklanır (iptal için `Cancel`). Zarf bırakılırken iptal edildiyse gelen `seq` hemen `Cancel` edilir.
**Hata işleme** (`handle_server_error`):
| Kod | Davranış |
|---|---|
| `UnknownMailbox` | O (sunucu, kutu) "bilinmeyen" işaretlenir ve **duraklama ardışık her yanıtta ikiye katlanır**: 60 sn (`SERVER_UNKNOWN_MAILBOX_TTL_MS`) << `min(seri, 6)`, en çok 60 dk (`SERVER_UNKNOWN_MAILBOX_MAX_TTL_MS`); seri `server_unknown_streak[(sunucu, kutu)]`'da tutulur, **aynı anda uçuşan** yatırmalar duraklama bitmeden tek basamak sayar, o kutuya başarılı `Deposited` gelince seri silinir (fb5fecd; öncesinde sunucuya hiç kaydolmamış bir cihaz için her 2 dk'lık yeniden denemede onaysız paketler Tor üzerinden tekrar yatırılıp LTE radyosunu geceleri %60-75 açık tutuyordu). Zarf her seferinde hemen gossipsub'a verilir. Hesap silme/wipe (`contacts.rs wipe_all_local_state`) seriyi de temizler |
| `NotEnrolled` | `enrolled=false`, yeniden `Hello`; `Rebind` sırasındaysa `enrollment_id` silinir ("yeni davet kodu ekleyin") |
| `Revoked` | `enrollment_id` silinir, "operatör iptal etti" |
| `QuotaExceeded` (Deposit) | O kutuya 5 dk (`SERVER_DEPOSIT_BACKOFF_MS`) bırakma durdurulur (aynı `server_unknown_mailboxes` haritası, katlama yok), gossipsub'a verilir |
| `RateLimited`, `Internal` | Geçici sayılır; bırakmada 5 dk geri çekilme (`SERVER_DEPOSIT_BACKOFF_MS`) |
| `BadInvite` (Enroll) | Jeton silinir |
| `BadHash` (BlobFinish) | Kalıcı: depolanan baytlar `enc_sha256` ile uyuşmuyor, aynı Finish tekrar işe yaramaz |
| diğerleri (`TooLarge`, `BadSignature`…) | Kalıcı; blob/arşivde iş bırakılır |
Zaman aşımı/bağlantı hatası (`handle_server_failure`): bırakma geri çekilmesi + gossipsub'a düşme. **Her başarısız bırakma gossipsub'a düşer**; sunucu hiçbir zaman tek teslim yolu değildir.

### 13.5 Sunucu tarafı gizlilik ve mühür
- Oturum kutusu cihaz çifti başına **sabit**tir (`server_client.rs session_mailbox`): iki cihazın uzun ömürlü KEM X25519 anahtarlarıyla statik DH + sıralı fingerprint'lerden HKDF (`server_seal::session_mailbox_secret`, `p2pmsg-v0.6-session-mailbox:`); rotasyonda değişmez, root_key/topic'ten türemez (yalnız X25519, statik ML-KEM yok). Kutu kimliği bu sırdan türeyen **kanıt anahtarının karmasıdır**: `mk_<hex16>` (`server_client.rs key_bound_mailbox_id` → `server_proto::key_bound_mailbox_id(mailbox_key_hash(...))`); arama röle kutusu da aynı biçimde `pair_key`'den. Sunucu `mk_` kutusu için başka anahtarı kabul etmez (§13.3): kimliği bilmek okuyucu olmaya yetmez. Mühür anahtarı yine ratchet root'tan gelir (alıcı mevcut + önceki root'u dener); ilk temas kutusu = HKDF(sır, `p2pmsg-v0.5-first-contact-mailbox:`‖fp) — sır eşleşme nonce'u, link nonce'u ya da **grup başına** ilk temas sırrı olabilir (bkz. §11); ilk temas kutusu `mb_<hex16>` biçimindedir (anahtara bağlı değil); onun okuyucu kanıt anahtarı okuyan cihazın kendi Ed25519 imza anahtarından türer (`server_client.rs own_server_mailboxes`, `mailbox_proof_seeds`).
- `seal_envelope`: ChaCha20-Poly1305(HKDF(root_key, `p2pmsg-v0.1-server-seal`), AAD = mailbox‖0‖sender_fp, CBOR(zarf)). Sunucu AAD'yi bilir ama anahtarı bilmez.
- `seal_first_contact`: ortak sır (`p2pmsg-v0.5-first-contact-seal`) + varsa alıcının KEM anahtarı; açma `open_first_contact(secret, mailbox, kem_sk_x25519, kem_sk_mlkem, sealed)`.
- Sunucu veritabanında kimlik/fingerprint/içerik yoktur; `enrollments` yalnızca `enroll_pk`, `enroll_pk_pq`, `peer_id`, durum, sayaçlar tutar.

### 13.6 Arşiv ve blob (kodda doğrulandı)
**Arşiv — sunucu:** `archive_put` kayıtları `(bucket, record_id)` anahtarıyla yazar; çakışmada **yalnız `rev` daha büyükse** üzerine yazar (`WHERE excluded.rev > archive.rev`), yani eski revizyon yeniyi ezemez. `record_id` ≤128 bayt, bucket `is_safe_id`, kayıt ≤900 KiB, `max_archive_bytes` (1 GiB) ve toplam disk bütçesi kontrol edilir; kayıt başına `owner` bayt sayacı yeniden hesaplanır.
**Arşiv — istemci:** kayıtlar **yalnız `store_history` açık bir sunucu varsa ve kök arşiv anahtarı mevcutsa** `queue_archive_record` ile kuyruğa girer (düz metin yerelde `seal_local_blob` ile mühürlü bekler); `ArchivePut` partisi 50 kayıtta (`SERVER_ARCHIVE_BATCH`) ya da mühürlü bayt `MAX_DEPOSIT_BYTES/2`'yi aşınca kapanır. Geri yükleme: `ArchiveProbe(buckets)` → dolu kovalar (`before_ms` verilmişse en yeni önce) → `ArchiveFetch{bucket, before_ms}` sayfalama (`more` ise `before_ms` = sayfadaki en eski `sent_at_ms`) → `merge_server_archive`: kaydı `open_archive_record(ark, conv_key, record_id, rev, bucket, sent_at_ms, sealed)` ile aç (AAD bu alanları bağlar); `note_archive_rev` ile **görülenden eski `rev` reddedilir** (`server_archive_revs` tablosu); yerelde aynı `record_id`'li mesaj zaten varsa **atlanır** (yani sunucu arşivi mevcut mesajı değiştirmez, yalnız eksik olanı doldurur); grup değilse `resolve_active_device_for_identity(conv_key)` ile sohbete yazılır. Sonuç `history_backfilled{count, source:"server"}` olayı. Çözülemeyen/ayrıştırılamayan kayıt atlanır.
**Blob — istemci** (`queue_blob_upload` / `server_flush_blobs`): yalnız `route_messages` açık bir sunucu varsa kuyruğa alınır; kuyrukta **aynı anda tek blob** (baştaki) yüklenir; durum `server_blob_uploads` tablosunda kalıcıdır. Parçalar diskte şifreli dosyadan `chunk_size` ile okunur, `window` kadarı havada tutulur (başlangıç 4, min 2, max 40; RTT tabanın 2 katını aşmadıkça ve 90 sn zaman aşımının %80'i altındaysa büyür, zaman aşımında yarıya iner). Tüm parçalar bitince şifreli dosyanın SHA-256'sı ile `BlobFinish`. Sunucu değişirse yükleme baştan başlar.
**Blob kimliği ve grup etiketi:** yükleme sırrı 24 bayttır = 8 bayt yazar etiketi + 16 bayt; `FileOffer`'a yalnız türetilmiş blob kimliği girer. Grup dosyasında etiket artık **dosya başına** farklıdır: `util.rs group_msg_tag(group_id, yazar_identity, rest)` = SHA-256(`typeon-group-msg-id-v2` ‖ grup ‖ 0 ‖ yazar ‖ 0 ‖ rest)'in ilk 8 baytı; dosyada `rest` = kimliğin hash kısmı (`blob_id_hash_hex`), metinde `-<uuid>`. Böylece sunucu bir yazarın iki dosyasını etiketten ilişkilendiremez (I-42). Alıcı `util.rs group_msg_id_bound` ile kimliğin o yazara ait olduğunu yeniden hesaplar. Sonuç: sunucu protokolü 6 → 7 (**protokol kırılması**).
**Blob — sunucu:** `BlobPut` parçayı dosyada `offset = chunk_index × (chunk_size + 16)` konumuna yazar (rastgele erişim; parça ≤768 KiB; sahip kontrolü; hem tek blob ofseti hem kayıt başına `bytes_blob` `max_blob_bytes` 4 GiB'ı aşamaz; aynı parça tekrar gelirse `Ok`, hash sürerken `RateLimited`); `BlobFinish`: sahip eşleşmeli, alınan parça sayısı `total_chunks`'tan az olmamalı (aksi `BlobIncomplete`: kalıcı değil, istemci 0. parçadan yeniden yükler), aynı anda en çok `MAX_HASH_JOBS` = 4 hash işi (aksi `RateLimited`); hash arka planda akışlı hesaplanır, yanıt hash bitince gider. **Uyuşmazsa dosya silinir ve `Internal` döner.** Tamamlanan blob `filexfer` protokolüyle servis edilir (`serve_chunk`, parça hız sınırı 600/dk, relay/cold bütçeleri ayrı); `blob_ttl` (30 gün) sonra GC.

### 13.7 Veri dizini kilidi, DB şifreleme, arşiv ömrü
- **Süreç kilidi:** veri dizininde `server.lock` dosyası `flock` ile kilitlenir (`ServerCore` ömrü boyunca tutulur, `_dir_lock`); ikinci bir sunucu aynı dizini açamaz ("bu veri dizini başka bir sunucu işlemi tarafından kullanılıyor").
- **DB şifreleme:** Android sunucu uygulaması DB'yi **SQLCipher** ile açar — anahtar 32 rastgele bayt, Android Keystore'daki (dışa aktarılamayan) AES-GCM anahtarıyla sarılır (`DbKey.get`), `ServerLib.setDbKey` ile çekirdeğe 64 hex olarak verilir. Eski (düz) DB ilk açılışta **bir kez** şifreli DB'ye geçirilir (`sqlcipher_export`); anahtar gelmezse sunucu **düşer** (fail-closed, düz DB'ye düşmez). Linux `typeon-server` **düz** kalır; `TYPEON_SERVER_DB_KEY` (64 hex) verilirse aynı şekilde şifreli açılır (düz DB yine bir kez geçirilir).
- **Arşiv ömrü:** arşiv satırları son yazıldıktan **13 ay** sonra silinir (`ARCHIVE_TTL_MS` = 13×30 gün; `sweep_expired_archive`, posta süpürmesiyle birlikte çalışır, kota sayaçları yeniden hesaplanır).
- **PIN kilidi (sunucu uygulaması):** tüm ekran (katılım kodu, cihaz listesi, ayarlar) PIN arkasında; PBKDF2-HMAC-SHA256, 300.000 iterasyon, en az 6 karakter; 5 hatalı denemeden sonra artan bekleme (30 sn, sonra katlanarak); ekran kapanınca anında, uygulamadan çıkınca 30 sn sonra kilitlenir.

---

## 14. Yerel depolama ve anahtar yönetimi

- **DB:** `p2p_messenger.db`, SQLCipher (`rusqlite` bundled-sqlcipher-vendored-openssl). `PRAGMA key = x'…'` (HKDF'den), `WAL`, `synchronous=NORMAL`, `secure_delete=ON`. Eski düz DB ilk açılışta şifrelenir (tek seferlik göç).
- **Anahtar zinciri (Android):** `KeystoreCrypto` — Android Keystore'da (StrongBox → TEE) AES-256 anahtarı; Rust'ta üretilen gizli anahtar paketi (`SecretKeyBundle`) ve `storage_key` bu anahtarla sarılıp dosyaya yazılır (`IdentityManager`, `ArchiveKeyManager`). **AppLock parolası DB/anahtar türetmede KULLANILMAZ**; yalnızca UI kapısıdır (PBKDF2 hash saklanır, süreç ölünce kilit tekrar sorulur). Yani cihaz root/bellek erişimi ya da Keystore saldırısı AppLock'u aşar; bu bilinen sınırdır.
- **Linux:** kasa anahtarı Secret Service'te (GNOME Keyring / KDE Wallet, `keyring.rs`; kasa `secrets.rs`, isteğe bağlı parola). **Windows:** kasa anahtarı DPAPI ile mühürlü dosyada (`keyring_win.rs`, `vault-key.dpapi`). İkisi de yalnız ikincil cihaz kasasıdır (§1.2).
- **Satır şifreleme:** geçmiş/atlanmış anahtar/ratchet durumu/dosya anahtarı ayrıca `seal_with` (rastgele nonce ChaCha20-Poly1305) ile mühürlenir (`ratchet_states.sealed` vb.).
- **Tablolar:** bkz. HANDOFF §3.8. Yeni sütun `ALTER TABLE` ile eklenir (`db.rs init_db` içindeki `migrate`): `duplicate column name` dışındaki **her `ALTER TABLE` hatası `init_db`'yi başarısız kılar** (eksik sütun sonradan INSERT'leri sessizce bozmasın; 6a603c7); veri yüzünden başarısız olabilen `CREATE INDEX`/dolgu adımları en-iyi-çaba kalır. Sunucu DB'si aynı sözleşmeyi uygular (`typeon-server/src/store.rs init_schema`, `add_column`; `user_version` yalnız başarıdan sonra damgalanır, bir sonraki açılış yeniden dener).
- **Kurtarma dosyası:** `RecoveryFile{kdf:"argon2id", m/t/p, salt, nonce, ciphertext}`; parola ≥12 karakter; içerik: kimlik, tüm cihaz gizli anahtarları, kök arşiv anahtarı, veri (sınır 64 MiB; aşarsa en yeni 6500 mesaj). İçe aktarımda Argon2 bellek maliyeti ≤256 MiB sınırı.
- **Yedekleme** kapalı (`allowBackup=false`); `FLAG_SECURE` **istemcide yok** (sunucu uygulamasında release derlemede var).

---

## 15. Dosya ve medya

- `FileOffer` (metadata, Ack'li) → alıcı `/p2pmessenger/filexfer/1.0.0` ile parça ister (`FileChunkRequest/Response`). Dosya başına rastgele anahtar; parçalar şifreli. Çok kaynaktan (gönderen, kardeş, sunucu `alt_source_peer_ids`) indirme, otomatik devam, kimlik doğrulama kurtarma. `FileChunkResponse::Busy` = sunucunun hız sınırı; istemci aynı kaynaktan `DOWNLOAD_RETRY_DELAY_MS` sonra yeniden dener. Sınır 4 GiB (`MAX_ATTACHMENT_SIZE`).
- Sunucu blob'u: parçalar sunucuda dosya anahtarıyla şifreli kalır; `BlobPut/Finish`, `blob_ttl 30 gün`.
- Gönderimde gizlilik: Metadata temizliği (`attachments.rs`) yalnız **JPEG ve PNG**'yi kapsar; diğer biçimlerde (HEIC/WebP/GIF/video vb.) EXIF/GPS **temizlenmez** (Android `OutgoingMedia.kt` ayrıca yeniden kodlar/remux eder; Linux `prepare_outgoing` de öyle). Yeniden kodlanamayan JPEG/PNG dışı görsel (çözülemeyen HEIC, animasyonlu WebP, sınır üstü GIF, API 26–27'de alfa) ve remux edilemeyen video, iki istemcide de ancak kullanıcı "metadata ile gönder?" onayını verirse olduğu gibi gider. JPEG/PNG'de metadata ayrıştırılamıyorsa dosya **reddedilir** (fail-closed), kirli gönderilmez. Yönlendirme (orientation) korunur.

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
| `MAX_SKIPPED_KEYS` / `MAX_SKIP_AHEAD` | 1000 / 2.000 | ratchet.rs |
| `MAX_ACTIVE_DEVICES` | 5 | identity.rs |
| `ACK_RETRY_INITIAL_MS` / `ACK_RETRY_MAX_MS` | 15 sn / 120 sn | tuning.rs |
| `ACK_SUSPECT_MS` | 1,5 sn | tuning.rs |
| `MAX_UNCONFIRMED_AGE_MS` | 25 dk (= `RATCHET_ROTATION_MS` − 5 dk) | tuning.rs |
| `TEXT_RETRY_GIVE_UP_MS` | 7 gün | tuning.rs |
| `HANDSHAKE_MAX_SKEW_MS` / `HANDSHAKE_MAX_AGE_MS` / `HANDSHAKE_COLLISION_WINDOW_MS` | 10 dk / 7 gün (= `TEXT_RETRY_GIVE_UP_MS`) / 90 sn | tuning.rs |
| `HANDSHAKE_REDO_MIN_INTERVAL_MS` (IdentityExchange zaman kovası) | 10 dk | tuning.rs |
| `UNDECRYPTABLE_BEFORE_REHANDSHAKE` / `_WINDOW_MS` / `_REDO_MIN_INTERVAL_MS` | 3 / 2 dk / 2 dk | tuning.rs |
| `PREKEY_ROTATE_MS` | 7 gün | types.rs |
| `INBOUND_DEDUP_WINDOW_MS` / `_MAX_ENTRIES` | 10 dk / 8192 | tuning.rs |
| `RATE_LIMIT_WINDOW_MS` / `_MAX_PER_WINDOW` / `_MAX_ESTABLISHED` | 10 sn / 60 / 600 | tuning.rs |
| `RECONNECT_SWEEP_INTERVAL_MS` | 15 sn | tuning.rs |
| `KEEPALIVE_FAST_INTERVAL_MS` / `_IDLE_` / `_POWER_SAVE_INTERVAL_MS` | 2 / 20 / 60 sn | tuning.rs |
| `MAX_ENVELOPE_BYTES` | 1 MiB | tuning.rs |
| `SERVER_PROTOCOL_VERSION` | 7 | typeon-crypto/src/server_proto.rs |
| `MAX_DEPOSIT_BYTES` | 900 KiB | server_proto.rs |
| `SERVER_ONLY_GRACE_MS` | 30 sn | server_client.rs |
| `SERVER_DEPOSIT_BACKOFF_MS` | 5 dk | server_client.rs |
| `SERVER_UNKNOWN_MAILBOX_TTL_MS` / `_MAX_TTL_MS` | 60 sn (her ardışık `UnknownMailbox`'ta ikiye katlanır, 6 basamak) / 60 dk | server_client.rs |
| `SERVER_SWEEP_INTERVAL_MS` / `SERVER_FETCH_SWEEP_INTERVAL_MS` | 15 sn / 5 dk | server_client.rs |
| `SERVER_HOLD_GRACE_MS` / `SERVER_HOLD_REFETCH_MS` | 5 dk / 45 sn | server_client.rs |
| `SERVER_ARCHIVE_BATCH` | 50 kayıt | server_client.rs |
| `SIBLING_BACKFILL_INTERVAL_MS` / `_SINCE_MARGIN_MS` | 30 dk / 10 dk | tuning.rs |
| `SIBLING_BACKFILL_PER_CONVERSATION` / `_MAX_ENTRIES` | 30 / 300 | tuning.rs |
| `HISTORY_SYNC_MAX_TEXT_BYTES` / `HISTORY_SYNC_MAX_MESSAGES` | 512 KiB / 200 | tuning.rs |
| `HISTORY_FETCH_MAX_PAGES` | 20 | tuning.rs |
| `mailbox_ttl_ms` | 14 gün | server_proto.rs ServerLimits |
| `MAX_ATTACHMENT_SIZE` | 4 GiB | lib.rs |
| `MAX_CONTACTS` | 500 | tuning.rs |
| `PENDING_LINK_RETRY_HORIZON_MS` / `LINK_REQUEST_WINDOW_MS` | 1 saat / 1 saat (ikincisi birincisine eşitlenmiş) | tuning.rs |
| `PAIRING_WINDOW_MS` / `PAIRING_NONCE_REUSE_MS` | 30 dk / 5 dk | tuning.rs |
| `RATE_LIMIT_MAX_UNKNOWN_TOTAL` (tanınmayan eşler, toplam) | 300 / 10 sn | tuning.rs |
| `MAX_ARCHIVE_PUT_RECORDS` | 256 | server_proto.rs |
| `MAX_FETCH_BATCH_ITEMS` / `MAX_FETCH_BATCH_BYTES` | 64 / 512 KiB | server_proto.rs |
| `MAX_BLOB_CHUNK_BYTES` / `BLOB_UPLOAD_SECRET_LEN` / `BLOB_TAG_LEN` | 768 KiB / 24 / 8 | server_proto.rs |
| `MAX_READERS_PER_KEY` / `READER_EVICT_IDLE_MS` | 2 / 7 gün | typeon-server/src/store.rs |
| `SCHEMA_VERSION` (sunucu DB) | 4 | typeon-server/src/store.rs |
| `NOTIFY_RESEND_MS` / `CHUNKS_PER_MINUTE` / `MAX_HASH_JOBS` | 20 sn / 600 / 4 | typeon-server/src/lib.rs |
| `ARCHIVE_TTL_MS` (sunucu arşiv satırı) | 13 ay (13×30 gün) | typeon-server/src/store.rs |
| `MAX_INVITE_PARTICIPANTS` / `RING_TIMEOUT_MS` / `MEDIA_LOST_MS` / `INVITE_MAX_AGE_MS` | 1024 / 45 sn / 30 sn / 60 sn | call.rs |
| AppLock PBKDF2 | 300.000 it. | AppLock.kt |

Not: Bu sabitler zamanla değişir. Bir sayıya güvenmeden önce `grep -n "SABIT_ADI"` ile doğrula.

---

## 19. 2026-10-20/21 düzeltme turu (protokol ve davranış değişiklikleri)

_Tarihsel bölüm: buradaki `SERVER_PROTOCOL_VERSION` v4 ve kod konumları o günün durumudur; güncel sürüm 7 (§13, §20) ve konumlar §1.1'deki modüllerdedir._

Kaynak: `reviews/archive/MERGED_REVIEWS.md`, raporlar `reviews/fixpass-2026-10-20/report_*.md`. Derlenmedi/cihazda denenmedi. Eski sürümlerle uyum aranmaz.

**PROTOKOL KIRILMALARI**
- **Sunucu protokolü v4** (`SERVER_PROTOCOL_VERSION`): `Register` → `Registered{proof_needed, refused}` (kalıcı reddedilenler `refused`'da); `Welcome` `enrollment_id` taşır; `enroll_signing_input` istemci PeerId'sini + `enroll_pk` + `enroll_pk_pq`'yu da bağlar; v4 blob istekleri bir `upload_secret` taşır ve blob kimliği bu sırrın hash'idir.
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

---

## 20. 2026-11-05..11 değişiklikleri (ef2f806 sonrası, HEAD e916a13)

Kaynak: `git log ef2f806..HEAD`; inceleme kararları `reviews/glm5-2026-11-05/`, `reviews/qwen-2026-11-06/`. Sürümler: istemci 6.0.7 (kod 51), sunucu uygulaması 6.0.1 (kod 44), Linux/Windows 6.1.4. Eski sürümlerle uyum aranmaz.

**PROTOKOL / KABLO KIRILMALARI**
- **Sunucu protokolü 6 → 7** (6c9d437): blob kimliği artık yalnız etiketten sonraki yükleme-sırrı baytlarını hash'ler (`blob_id_hash_hex`, `typeon-blob-id-v3`); grup dosyasında yazar etiketi **dosya başına** farklıdır (`group_msg_tag(grup, yazar, rest)`, `typeon-group-msg-id-v2`; I-42). Grup mesaj kimliği `<etiket><-uuid>`; alıcı `group_msg_id_bound` ile yeniden hesaplar. Eski sürümle blob/grup kimliği uyuşmaz (§13.6).
- **Kutu başına `seq`** (6a603c7): sunucu `mail.seq` artık küresel AUTOINCREMENT değil, `mail_seq` tablosunda kutu başına sayaç; sunucu DB `SCHEMA_VERSION` 3 → 4, eski satırlar için göç (`mail_seq_base`). Sunucu eski sürümde açılmış bir DB'yi göç ettirir; istemci imleçleri geçerli kalır (§13.3). `MailItem.seq` alan semantiği değişti.
- **Katı CBOR** (6a603c7): `MessageContent`, `SignedHeader`, `RatchetPublicKeys` sondaki baytları reddeder (§6).
- `SiblingHistoryEntry` iki yeni alan: `file`, `reactions` (§10). İkisi de `serde(default)` (boş ise `skip_serializing_if` ile yazılmaz): eski göndericiden gelen girdide boş okunur.
- Sürüm yükselmesi gerekir; sahip kuralı: uyumluluk kodu yazılmaz.

**ÇOKLU CİHAZ (kardeş geçmişi, §10)**
- dcd2cb6 / 670ab45 / 926d724: bağlı cihazın geçmişi artık ekleri (ses, etiket, dosya), tüm tepkileri ve kişi avatarlarını taşır; bütçe yetmezse önizleme önce atılır; "geçmişi getir" basışı, önceki basışın imleci altına bıraktığı satırların ek/tepkilerini de getirir.
- 1a180c3 (Linux): bekleyen bağlama sayfasında onaylı "sil ve çık" ile kurulum ekranına dönülebilir.

**SUNUCU / AĞ**
- fb5fecd: `UnknownMailbox` duraklaması ikiye katlanır (60 sn → en çok 60 dk), başarılı yatırma seriyi sıfırlar; sunucuya hiç kayıtlı olmayan bir bağlı cihaz yüzünden onaysız paketlerin 2 dk'da bir Tor'dan yeniden yatırılması engellendi (§13.4).
- 6a603c7 (sunucu): `Rebind` `Revoked`'u yalnız imza doğrulandıktan sonra bildirir (§13.2). 6c9d437: `init_schema` `duplicate column name` dışındaki `ALTER` hatalarında başarısız olur ve `user_version` damgalamaz; okuyucu sınırı **anahtar başına** 2 (§13.3).
- 6a603c7 (çekirdek): aynı ilke `db.rs init_db`'de (§14); `unknown_group_has_room` DB yoksa/sorgu hata verirse **kapalı** (yer yok) döner (`group_ops.rs`); sticker kare boyutu u64 + `saturating_mul`; 6c9d437: indirme-devam adayları `length(chunk_hashes) > 0` olan satırlarla sınırlı (parça özetsiz eski teklifler `download_file` tarafından her seferinde reddediliyordu; I-41).

**ÇEKİRDEK YAPISI**
- 447e83e: `lib.rs` (~29.000 satır) 24 konu modülüne bölündü (§1.1); `P2PCore` struct ve modül listesi `lib.rs`'te; alt modüller `use super::*`; özel öğeler `pub(crate)`; `lib.rs` artık ~930 satır. Kaynak tarayan testler `crate::CORE_SRC` okur. Yeni çekirdek dosyası `CORE_SRC`'ye eklenmeli. Windows için `mono_ms` `GetTickCount64` kullanır, `rust/build.rs` Windows hedefinde statik `lcms2` bağlar.

**MASAÜSTÜ (Linux + Windows, §1.2)**
- e916a13: aynı `Linux/` crate'inden Windows istemcisi (`x86_64-pc-windows-gnullvm`; DPAPI kasa anahtarı, `win.rs` tepsi/bildirim/otomatik başlatma/yazı tipi, WASAPI/Media Foundation/D3D11 arama öğeleri). **Masaüstleri yalnız bağlama (link-only) ikincil cihazdır**: hesap oluşturma ve kurtarma-dosyası geri yükleme kaldırıldı; karşılama sayfası yalnız "Link to my phone" sunar. `AGENTS.md` kurallar ve derleme tariflerini taşır.

**ANDROID ARAYÜZ (çekirdek dışı)**
- 8527802: özel yazı tipi (`util/FontOverride.kt`): sistem yazı tipi takma adları ve `p2p-imported-font` adı içe aktarılan yazı tipine eşlenir, `sDefaultTypeface` değiştirilir, her `Activity` penceresinde her yerleşim geçişinde TextView'lara yeniden uygulanır.
- fb5fecd: etiket (`sendSticker`/`sendGroupSticker`), dosya, fotoğraf ve sesli mesaj, girişteki ilk alıntıyı `reply` alanıyla yanıtlar (JNI `sendSticker`/`sendGroupSticker` yeni `reply_to_*` parametreleri; `jni_exports.rs sticker_reply_to`, `media_unlocked.rs send_sticker_unlocked`; Kotlin `util/Quote.kt`); alıntı, alıntılanan mesajın kendi sözlerini gösterir (içindeki alıntıyı değil). Sohbet listesi alt boşluğu yalnız yazıyor göstergesine yer bırakır.
- 6a603c7: ayarlar/kişiler JNI çağrıları ana iş parçacığı dışında; avatar ve duvar kâğıdı içe aktarımı boyut sınırlı; medya sihirli baytla (magic) tanınır: yanlış etiketli MP4/MOV/HEIC/TIFF/MKV/AVI remux edilir ya da "metadata ile gönder?" onayı ister; 6c9d437: m4a ses dosyasından metadata atılır, ayarlarda uygulama sürümü, sunucu kodu yapıştırma kapısı ekleme uyarısını gösterir.

**DOĞRULANMADI:** bu turdaki değişikliklerin hepsi kaynak okumayla doğrulandı; derleme/cihaz sonuçları commit mesajlarından alındı (6c9d437: host testleri crypto 37, server 51, core 124; Linux check; iki debug APK derlendi — bu belgeyi yazarken yeniden çalıştırılmadı). Windows'ta gerçek cihazda bağlama sorunu teşhis edilmemiştir (`Linux/packaging/windows/TEST-NOTES.md`).
