# Typeon — Devir Rehberi (basit sürüm)

Bu dosyayı okuyan yapay zeka projeyi hiç bilmiyor. Küçük/yerel model olabilir. Bu yüzden: kısa cümle, net kural, adım adım.
Proje sahibi: Yavuz. Türkçe konuşur. Cevapları kısa ve doğrudan ver.
Bu dosyadaki sayıların hepsi kodda kontrol edildi. Kontrol edilmeyen şey "DOĞRULANMADI" diye işaretli.

---

## 0. EN ÖNEMLİ 10 KURAL (ihlal etme)

1. **Derleme YAPMA.** `gradlew`, `cargo build`, `cargo check`, `cargo test`, `flatpak-builder` çalıştırma. Sahip açıkça "derle" derse yap, yalnız o iş için.
2. **Geri alma için git komutu KULLANMA.** `git checkout`, `git restore`, `git stash`, `git reset --hard` yasak. Çalışma ağacında commit edilmemiş iş var; bu komutlar onu siler. Geri almak için düzenlemeyi elle tersine çevir. Büyük düzenlemeden önce dosyayı başka klasöre kopyala.
3. **Commit/push yapma**, sahip istemedikçe. Uzak depo yok. Dal: `master`.
4. **Eski sürümle uyumluluk ÖNEMSİZ.** Protokolü kırabilirsin. Uyumluluk kodu yazma. Yalnız "protokol kırıldı, sürüm artmalı" diye not düş.
5. **Yorumlara güvenme.** Kod yorumu yanlış olabilir. Kodun gerçekte ne yaptığına bak. (Yeni yorum yazarsan çevredeki yorum stilini kullan.)
6. **Küçük değişiklik yap.** Önce `grep` ile fonksiyonu çağıran her yeri bul. Kök nedeni tek yerde düzelt. Yeni kütüphane ekleme.
7. **Yeni Android metni** hem `res/values/strings.xml` hem `res/values-tr/strings.xml` dosyasına girer.
8. **Dürüst rapor ver:** "derledim / sadece okudum / cihazda denedim / başarısız oldu" ayrı ayrı yaz.
9. **Dokunma:** `service/BatteryLog.kt`; klavye düzeltmesi (`util/KeyboardInsets.kt`, `adjustResize`, input bar); istemciye `FLAG_SECURE` ekleme (sunucu uygulamasında release'te var, kalsın); sunucu kaydına LAN adresi ekleme. **İmza:** `app/build.gradle`'a release imzası **ekleme** — Gradle release'ı imzasız üretir, imzayı `./sign-release.sh` yapar (özel anahtar, v3 soy zinciri).
10. **Redmi Note 9S sahibin günlük telefonu.** Silme, sıfırlama, ağ ayarı bırakma. Ayarı değiştirdiysen eski haline getir.

Yayın (release) kuralı: önce sürüm artır (3 yer: `p2p_messenger_android/app/build.gradle`, `p2p_messenger_android_server/app/build.gradle`, `Linux/Cargo.toml`). Sonra dosyaları `dist/` içine `typeon-client-<sürüm>.apk` gibi koy. **İmzayı `sign-release.sh` yapar** (Gradle imzalamaz). `dist/SHA256SUMS` dosyasını komutla yeniden üret, elle yazma.

---

## 1. Proje ne yapıyor

Sunucusuz çalışabilen, uçtan uca şifreli mesajlaşma uygulaması. Klasik + post-kuantum şifreleme birlikte kullanılır.

Dört ürün var:
- **Android istemci** (Kotlin arayüz).
- **Linux istemci** (Rust + GTK4 arayüz). **Windows istemci** de aynı `Linux/` crate'inden derlenir (`#[cfg(windows)]`). İkisi de yalnız **ikincil cihazdır**: telefona QR ile bağlanır, hesap oluşturmaz.
- **Sunucu** (isteğe bağlı): çevrimdışı kişi için mesajı saklar. Linux programı veya Android uygulaması olarak çalışır.

**Tüm asıl mantık tek bir Rust çekirdeğinde.** Android bu çekirdeği JNI ile çağırır. Linux ve Windows aynı çekirdeği doğrudan (rlib) çağırır. Kotlin/GTK sadece arayüzdür.

Özellikler: 1:1 mesaj, grup, düzenleme, silme, tepki, okundu, dosya/medya, sesli/görüntülü arama, beyaz tahta, çoklu cihaz, uygulama kilidi (AppLock), kurtarma dosyası.

---

## 2. Dosya haritası (neresi ne işe yarar)

| Yol | Ne var |
|---|---|
| `typeon-crypto/src/identity.rs` | Cihaz kimliği, anahtar türetme, `MAX_ACTIVE_DEVICES = 5` |
| `typeon-crypto/src/ratchet.rs` | Çift ratchet. `RATCHET_ROTATION_MS = 30 dk` |
| `typeon-crypto/src/packet.rs` | `MessagePacket`, `MessageContent` (mesaj türleri), imza girdisi |
| `typeon-crypto/src/server_proto.rs` | Sunucu mesaj türleri + varsayılan limitler (`mailbox_ttl_ms` = 14 gün) |
| `typeon-crypto/src/server_seal.rs` | Sunucuya giden zarfı ikinci kez mühürleme |
| `p2p_messenger_android/app/src/main/cpp/rust/src/lib.rs` | Çekirdeğin kökü (~930 satır): `P2PCore` yapısı, global `RUNTIME`/`CORE`, modül listesi, `CORE_SRC`. Eskiden 29.000 satırlık tek dosyaydı; artık konu modüllerine bölünmüş (aşağıdaki satır) |
| aynı klasör, çekirdek konu modülleri (hepsi `impl P2PCore` / `use super::*`) | `core_lock.rs` (çekirdek kilidi), `media_unlocked.rs` (kilitsiz dosya/etiket işi), `wire.rs` (libp2p kablo tipleri), `util.rs` (yardımcılar, imza girdileri, `mono_ms`), `types.rs` (tipler), `tuning.rs` (sabitler), `db.rs` (`init_db`, şema, SQLCipher), `pairing.rs` (QR/eşleşme, `IdentityExchange`), `devices.rs` (cihaz fan-out/yetki), `sibling_sync.rs` (kardeş cihaz: eşitleme, okundu, geçmiş), `contacts.rs` (kişiler, engel, silme/wipe), `session.rs` (handshake, ratchet rotasyonu), `send.rs` (gönderim, tepki, düzenle/sil, Ack), `receive.rs` (`receive_message`), `archive.rs` (mesaj arşivi, geçmiş istekleri), `persist.rs` (mühürlü blob, ratchet kalıcılığı), `group_ops.rs` (grup işlemleri), `storage.rs` (etiketler, depolama), `network.rs` (`start_network`, yeniden bağlanma, yeniden deneme), `file_transfer.rs` (dosya aktarımı), `poll.rs` (`poll_events`, `process_incoming_envelope`), `recovery.rs` (kurtarma dosyası), `jni_exports.rs` (JNI fonksiyonları `Java_com_p2p_messenger_P2PLib_*`), `core_tests.rs` (testler). Ayrıntı: TECHNICAL_HANDOFF §1.1 |
| aynı klasör `api.rs` | JNI'siz saf Rust arayüzü. Linux/Windows bunu çağırır |
| aynı klasör `server_client.rs` | İstemcinin sunucu tarafı: kayıt, bırakma, çekme, arşiv |
| aynı klasör `call.rs` | Arama medya taşıma (şifreli paketler, libp2p stream) |
| aynı klasör `whiteboard.rs` | Beyaz tahta |
| aynı klasör `attachments.rs` | Dosya parçaları, EXIF/GPS soyma |
| aynı klasör `tor.rs` | Tor (arti) istemcisi + onion servisi |
| aynı klasör `group.rs`, `contact.rs` | Grup yapısı/doğrulama; kişi ve cihaz güven kontrolü |
| `p2p_messenger_android/app/src/main/java/com/p2p/messenger/` | Android Kotlin kodu |
| ↳ `P2PLib.kt` | JNI `external` fonksiyon tanımları (Rust'taki adlarla birebir) |
| ↳ `service/P2PService.kt` | Arka plan servisi. Çekirdekten JSON olay alır (`poll_events`), bildirim gösterir |
| ↳ `ui/` | Ekranlar (20 dosya; başlıcaları): `ChatActivity`, `GroupChatActivity`, `CallActivity`, `AppLockActivity`, `MediaViewerActivity`, `LinkDeviceActivity`, `QrScanActivity` |
| ↳ `util/` | Yardımcılar (42 dosya; başlıcaları): `AppLock`, `OutgoingMedia` (medya temizleme), `KeystoreCrypto`, `IdentityManager`, `NotificationHelper`, `FontOverride` (özel yazı tipi), `Quote` (alıntı) |
| `trafficvis/` | Trafik görselleştirme simülatörü (`traffic_visualization.html`, `selftest.js`) |
| `p2p_messenger_android_server/` | Sunucunun Android uygulaması. Ekran: `ServerActivity` |
| `typeon-server/src/` | Sunucu mantığı: `lib.rs` (protokol), `store.rs` (SQLite; posta `seq`'i kutu başına, `mail_seq` tablosu), `jni.rs`, `bin/typeon-server.rs` (CLI) |
| `Linux/src/` | Masaüstü istemci (Linux + Windows, aynı crate `typeon-linux`). `core.rs` çekirdek köprüsü, `ui/*.rs` ekranlar, `prefs.rs`/`theme.rs`/`font.rs`/`audio.rs`/`qr.rs`/`util.rs` yardımcılar, `call_media.rs` arama (GStreamer), `keyring.rs`+`secrets.rs` anahtar saklama (Secret Service: GNOME Keyring / KDE Wallet). **Windows dosyaları:** `win.rs` (tepsi simgesi, bildirim, otomatik başlatma, yazı tipi), `keyring_win.rs` (DPAPI kasa anahtarı), `audio_win.rs` (WASAPI ses kaydı); `main.rs` Windows'ta `audio`/`keyring` modüllerini bunlara yönlendirir |
| `Linux/packaging/` | Flatpak paketleme (`README.md`). `Linux/packaging/windows/`: Windows çapraz derleme/paket betikleri (`build.sh`, `package.sh`, `package-msys2.sh`, `fetch-sysroot.py`) ve `TEST-NOTES.md` |
| `AGENTS.md` | Ajanlar için ortak kurallar + derleme tarifleri (Linux, Windows çapraz derleme) |
| `reviews/` | Eski kod inceleme notları. `ALL_OPEN_FINDINGS.md` = bilerek açık bırakılan maddeler, tekrar tartışma |
| `Description.md` | Protokol şartnamesi (Türkçe). Bölümler: 1 kimlik, 2 güven, 3 şifreleme, 4 keşif+sunucu, 5 grup, 6 açık kararlar |
| `SECURITY.md` | Güvenlik özeti (İngilizce). **Kısmen eski**, çelişirse koda inan |
| `Mesaj-Akisi-Senaryosu.md` | Mesaj gönderme/ack/edit/dosya akışının örnekli anlatımı. Ack davranışı için iyi kaynak |
| `.claude/skills/typeon-adb-debug/SKILL.md` | Telefonda adb ile test rehberi (parola orada eski, doğrusu bu dosyada) |
| `sign-release.sh` | APK yeniden imzalama |
| `dist/` | Yayın dosyaları |

Bir davranışı bulmak için: `grep -n "fn fonksiyon_adı" p2p_messenger_android/app/src/main/cpp/rust/src/*.rs` (çekirdek tek dosya değil, modüllere bölünmüş). Büyük dosyayı komple okuma, parça parça oku.
JNI fonksiyonunu değiştirirsen hem `jni_exports.rs` hem `P2PLib.kt` (gerekirse `api.rs`) aynı anda değişmeli. Yeni bir çekirdek `.rs` dosyası açarsan hem `lib.rs`'teki `mod` listesine hem `CORE_SRC`'ye (kaynak tarayan testler) ekle.

---

## 3. Mantık — adım adım

### 3.1 Kimlik
- Kişi = **Identity**. Kişinin 1–5 **Device**'ı (cihazı) olur.
- `identity_id` = ilk cihazın fingerprint'i. Hiç değişmez.
- Kişiler ve gruplar `identity_id` ile tutulur. 1:1 sohbet arşivi cihaz fingerprint'i ile tutulur.
- İmza: Ed25519 **ve** ML-DSA-87 (ikisi de doğrulanır). Anahtar değişimi: X25519 **ve** ML-KEM-1024. Şifreleme: ChaCha20-Poly1305.
- Yeni kişi ilk kez QR veya elle girilen kodla eklenir (TOFU: ilk görüşte güven). Sonra her pakette cihazın bilinen cihaz olup olmadığı kontrol edilir (`check_incoming_device` in `contact.rs`). Yeni/şüpheli cihaz `device_alert` olayı üretir.

### 3.2 Mesaj gönderme (sırayla)
1. `send_message` → `send_message_content_inner` (`send.rs`).
2. Bağlantı yoksa `ensure_connected` bağlanmayı dener.
3. Ratchet yoksa el sıkışma yapılır (`initiate_handshake_with`).
4. 30 dk geçtiyse ratchet yenilenir (`maybe_rotate_ratchet`).
5. Mesaj şifrelenir, hibrit imzalanır, gossipsub topic'ine yayınlanır. Sunucu ayarlıysa ayrıca sunucuya bırakılır.
6. Ack bekleyen türler `awaiting_confirmation` listesine ve DB'ye (`pending_durable_retries`, `pending_group_messages`) yazılır.
7. Yeniden deneme: ilk 15 sn (`ACK_RETRY_INITIAL_MS`), sonra katlanarak en çok 120 sn (`ACK_RETRY_MAX_MS`). Yaklaşık 25 dk sonra aynı `message_id` ile taze şifreli kopya. **7 gün** (`TEXT_RETRY_GIVE_UP_MS`) sonra vazgeçer.

### 3.3 Mesaj alma
1. `receive_message` ratchet ile çözer.
2. **Önce arşive yazar** (`archive_message`). Başarılıysa Ack yollar. Başarısızsa Ack'i geciktirir.
3. Aynı `message_id` ikinci kez gelirse atılır.
4. Hız sınırı: 10 sn'de en çok 60 paket (`RATE_LIMIT_MAX_PER_WINDOW`); kurulu bağlantıda 600.
5. Ack **almayan** türler (bilerek): `Ack`, `Seen`, `TypingIndicator`, `AddressAnnounce`, `SiblingHistoryResponse`. (`HistorySyncResponse` Ack'lenir.)
6. Düzenle/Sil mesajı hedef mesajdan önce gelirse tamponda bekler.

### 3.4 Çoklu cihaz
- Her cihaz **kendi anahtarını** üretir. İkinci cihaz QR ile bağlanır. Birincil cihaz `DeviceAdd` imzalar.
- Birincil cihaz = `identity_id` ile aynı fingerprint'e sahip cihaz. Cihaz ekleme (`sign_device_add`), çıkarma ve hesap silme **yalnız birincil cihazda** çalışır; diğerinde "Only the primary device can do this" hatası verir.
- Birincil cihazın gizli anahtarı hiç çıkmaz. Bağlantıdan sonra iki cihaz birbirinden bağımsız çalışır.
- Karşı taraf her mesajı kişinin tüm aktif cihazlarına ayrı ayrı gönderir.
- Kendi yazdıklarım diğer cihazıma `SiblingEcho` ile gider (metin/düzenleme/silme).
- Geçmiş: `SiblingHistoryRequest` ile sayfa sayfa çekilir.
- Okundu durumu: `ReadStateSync` ile cihazlar arası.
- Birincil olmayan cihaz kişi/grup bilgisini `DeviceSync`/`SyncPayload` ile alır.

### 3.5 Grup
- Grup mesajı = her üyenin her aktif cihazına ayrı şifreli kopya (ortak grup anahtarı yok).
- Üyeler `identity_id` ile tutulur. Kurucu (`founder_identity_id`) üye ekler/çıkarır. `GroupUpdate` sürüm numaralı ve imzalıdır (`validate_group_update`, `apply_change` in `group.rs`).
- Eksik güncellemeler `group_sync_sweep` ile periyodik gönderilir.

### 3.6 Ağ
- libp2p. Taşıma: Noise + yamux. Mesaj: gossipsub. Keşif: Kademlia (varsayılan istemci modu). Röle: Circuit Relay v2 + DCUtR.
- Özel protokoller: `/p2pmessenger/envelope/1.0.0`, `/p2pmessenger/ack/1.0.0`, `/p2pmessenger/keepalive/1.0.0` (ve `1.1.0`), `/p2pmessenger/filexfer/1.0.0`, `/typeon/server/1.0.0`.
- **İnternet yalnız Tor onion üzerinden.** mDNS ve UPnP kodda `None` (kapalı). Düz TCP çıkışı `DialReject` ile reddedilir. Bu bilerek: IP adresi sızmasın. Bunu "düzeltme".
- Tor durumları (`TorStatus`): `Disabled`, `Bootstrapping`, `Ready`, `Failed`.
- `start_network` ağı başlatır. `poll_events` olayları JSON olarak döndürür.
- Bağlantı yenileme: `reconnect_sweep` her 15 sn. `dial_with_relay_fallback` önce doğrudan, olmazsa röle.
- Keepalive aralığı: ekran açık 2 sn, boşta 20 sn, güç tasarrufunda 60 sn.
- Dosya: parça parça, dosyaya özel anahtar, birden çok kaynaktan indirme, en çok 4 GB.
- Gönderilen resim/videodan EXIF, GPS, cihaz bilgisi silinir (`attachments.rs` ve `OutgoingMedia.kt`). Yönlendirme (orientation) korunur.

### 3.7 Sunucu (isteğe bağlı)
- Ne yapar: alıcı çevrimdışıyken şifreli zarfı **diske yazar**, alıcı gelince verir.
- Üç işlem: `Deposit` (bırak), `Fetch` (çek), `Ack` (silinebilir de).
- Varsayılan saklama: **14 gün** (`mailbox_ttl_ms`, `server_proto.rs`). Kayıtlı cihaz 30 gün boşta kalırsa düşer (`ENROLLMENT_IDLE_MS`). Varsayılan en çok 64 kayıt. Saatte en çok 60 herkese açık kayıt.
- Sunucu içeriği göremez: zarf zaten uçtan uca şifreli, üstüne ikinci mühür var. Oturum kutusu adı, iki cihazın uzun ömürlü KEM X25519 anahtarlarının statik DH'sinden türer (çift başına sabit, rotasyonda değişmez; `server_seal::session_mailbox`); mühür anahtarı ratchet root'tan gelir.
- Sunucu şunları görebilir: boyut, zaman, hangi PeerId hangi kutuyu okuyor. Bu bilinen ve kabul edilen sınır.
- Sunucu mesajı geciktirebilir/atabilir ama sahteleyemez. Bu yüzden: sıradan mesaj ilk 30 sn yalnız sunucuya gider (`SERVER_ONLY_GRACE_MS`), sonra her yeniden deneme gossipsub'a da gider. El sıkışma (`Handshake`, `IdentityExchange`) ve ratchet yenileme duyurusu hep ikisine birden gider.
- Açılamayan/işlenemeyen sunucu öğesi Ack'lenmez; kutu imleci onun önünde 5 dk kalır, 45 sn'de bir yeniden çekilir, sonra atlanır (`SERVER_HOLD_GRACE_MS`; ayrıntı TECHNICAL_HANDOFF §13.4).
- Sunucudan çekilen zarflar `source = None` ile gelen mesaj yoluna girer (sunucunun adresi kişi adres defterine yazılmasın diye).
- Sunucunun **onion adresi onun kimliğidir.** Güncellemede korunmalı. Uygulamayı kaldırıp kurma onion adresini siler.
- "Geçmişi sunucuda sakla" ayrı ve varsayılan kapalı seçenek. Arşiv kök anahtarla şifrelenir (ileri-gizli değil, kabul edilmiş bedel).
- SQLite tabloları (`store.rs`, şema sürümü 4): `enrollments, invites, mailboxes, mailbox_readers, mail, mail_seq, mail_acks, archive, blobs, blob_chunks, blocked_keys, meta`.

### 3.8 Yerel veri
- Veritabanı: SQLCipher, dosya `p2p_messenger.db`. Şema `init_db` içinde (`db.rs`).
- Ana tablolar: `identities, own_devices, contacts, groups, messages, message_reactions, message_seen, ratchet_states, skipped_message_keys, remote_devices, files, device_addrs, device_onion_addrs, pending_durable_retries, pending_group_messages, blocked_identities, deleted_identities, removed_contacts, removed_groups, app_meta, acked_packets, own_prekeys, peer_prekeys, pending_sibling_ops`.
- Sonradan eklenen sütunlar `ALTER TABLE` ile eklenir; `CREATE TABLE IF NOT EXISTS` eski tabloyu değiştirmez.
- AppLock: parola PBKDF2-HMAC-SHA256 ile türetilir (`util/AppLock.kt`).
- Kurtarma dosyası: tüm gizli anahtarlar, Argon2id ile şifreli (`RecoveryFile`).
- Android yedekleme (backup) kapalı.

### 3.9 Arama
- Sinyalleşme ratchet mesajıyla gider. Medya ayrı libp2p stream üzerinden, her paket ayrı AEAD ile şifreli (`call.rs`). Doğrudan veya röle/sunucu üzerinden.
- Video bayrağında HEVC biti var. Linux tarafı GStreamer kullanır.
- Grup araması: `start_group_call`.
- Android olayı: `type = "call"`, `action = "invite"` ise zil çalar.

### 3.10 Android olay türleri (`P2PService.maybeNotify`)
`sync`, `device_linked`, `history_restore_incomplete`, `account_deleted`, `self_revoked`, `read_state_sync`, `call` (`action="invite"` zil), `message`, `group_message`, `delete`, `device_alert`, `group_delete`, `edit`, `group_edit`, `file_offer`, `pairing_failed`, `core_panic`.

---

## 4. Sık yapılan hatalar

- İmza girdisini / paket biçimini değiştirirsen tüm cihazlar yeniden eşleşmeli. Sürüm artır.
- Wake lock: tek nesne, her acquire'a karşılık release. Eskiden sızıntı yüzünden pil bitiyordu.
- Sunucuya aynı el sıkışmayı sürekli tekrar bırakma. Sunucu kotası dolar, store-and-forward kilitlenir.
- Linux GTK: `AdwActionRow` zaten bir `GtkListBoxRow`. Başka `ListBoxRow` içine koyma, `activated` olayı gelmez.
- Linux bildirimi için kurulu `.desktop` dosyası ve bildirim servisi gerekir.
- Android `Kotlin` artımlı derleme önbelleği bazen eski APK verir. "Değişiklik yok" derse `dumpsys package` `lastUpdateTime` bak.
- Arti (Tor) durumu bozulursa `tor.rs` `state/` ve `hss/` klasörünü silip bir kez yeniden başlatır. `keystore/` (onion kimliği) **silinmez**.
- Debug APK, cihazdaki release imzasıyla uyuşmaz (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`). `./sign-release.sh giris.apk cikis.apk` ile yeniden imzala. Gradle'in `assembleRelease` çıktısı **imzasızdır**; dağıtımdan önce hep bu betikle imzala.
- **Bildirimlerde mesaj metni varsayılan kapalı** (Ayarlar'daki "bildirimlerde mesajları göster" anahtarı). Kapalıyken bildirim yalnız "Yeni mesaj" der: ne gönderen ne metin görünür.
- `SYSTEM_ALERT_WINDOW` izni **kaldırıldı**; arama ekranı bu izinle açılmıyor, geri ekleme.
- **Uygulamayı kaldırıp yeniden kurma:** kimlik, kişiler, ratchet (sunucuda onion adresi) silinir. Yapma.
- `FLAG_SECURE`: istemcide **yok** (sahip kuralı, eklenmez); sunucu uygulamasında debug olmayan derlemede var (`ServerActivity`). `SECURITY.md` bu duruma göre güncellendi.

---

## 5. Derleme (yalnız sahip "derle" derse)

```bash
export JAVA_HOME=~/tools/jdk-21 ANDROID_HOME=~/Android/Sdk \
       ANDROID_NDK_HOME=~/Android/Sdk/ndk/30.0.16138531
export PATH=$JAVA_HOME/bin:~/.cargo/bin:$PATH
cd p2p_messenger_android && ./gradlew assembleDebug     # veya assembleRelease
```
- JDK 21 gerekir (sistemdeki JDK 25 olmaz).
- `assembleRelease` komutuna `--offline` ekleme (lint önbellekte yok). Lint'i kapatma.
- `assembleRelease` **imzasız** APK üretir (Gradle release'ı imzalamaz). Yayınlamadan önce `./sign-release.sh <apk> <çıktı.apk>` ile imzala; betik en yeni build-tools'ı kullanır ve iki uygulama (istemci + sunucu) için de aynıdır.
- `-x cargoNdkBuild` Rust'ı yeniden derlemez.
- Linux: `cd Linux && cargo check`.
- Flatpak: `Linux/packaging/README.md`. Komut: `flatpak run org.flatpak.Builder --user --force-clean --disable-rofiles-fuse --repo=repo build-dir com.p2p.messenger.Typeon.yml` sonra `flatpak build-bundle repo typeon.flatpak com.p2p.messenger.Typeon`. `build-bundle` derleme patlasa da başarılı döner: derleme çıkış kodunu kontrol et.

## 6. Cihazda test (adb)

| Seri | Cihaz | Not |
|---|---|---|
| `<serial>` | Redmi Note 9S | Günlük telefon. MIUI `logcat` ve `run-as` engelli, ekran görüntüsüyle bak |
| `<serial>` | Samsung Tab A8 | Debug'da `run-as` çalışır. Otomatik döner, kilitle |
| `<serial>` | Redmi Note 8 Pro | İstemci + sunucu uygulaması |

- Her cihazda AppLock parolası: **(removed)**.
- Döngü: ekran görüntüsü al → oku → `adb shell input tap x y`.
- Klavye açılınca buton yeri değişir; yeniden ekran görüntüsü al.
- Parola alanında metin varken `uiautomator dump` boş döner; Unlock'a basmak yerine `KEYCODE_ENTER` gönder.
- Veritabanını okumak için `sqlcipher3-binary` (Python venv). Anahtar: `files/debug_db_key.hex`.
- Log aramak için dizeler: `Metin gönderiliyor`, `Metin alındı`, `Sunucuya bırakılıyor`, `Sunucudan N zarf çekildi`.

## 7. Nasıl çalışılır

1. Soruyu oku. İlgili fonksiyonu `grep` ile bul.
2. Çağıran her yeri bul. Kök nedeni düzelt.
3. Küçük değişiklik yap. Derleme yok (sahip "derle" demedikçe).
4. Ne yaptığını kısa yaz: hangi dosya, hangi satır, neden, ne doğrulandı, ne doğrulanmadı.
5. Emin olmadığın şeyi uydurma. "Bilmiyorum, şu dosyaya bakmak lazım" de.
6. Belirsiz karar sahibe aittir: seçenekleri kısa yaz, öneriyi söyle, sor.

## 8. DOĞRULANMADI / dikkat

- `reviews/` altındaki bulgular tarihî. Satır numaraları kaymış olabilir. Düzeltmeden önce satırı oku.
- `SECURITY.md` ve `Description.md` bazı yerlerde kodun gerisinde. Çelişki varsa kod doğrudur.
- Bu dosyadaki fonksiyon adlarının hepsi kodda var, ama davranış ayrıntısı için fonksiyonu okumadan değiştirme.
