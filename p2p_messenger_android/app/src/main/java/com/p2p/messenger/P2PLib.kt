package com.p2p.messenger

object P2PLib {
    init {
        System.loadLibrary("p2p_messenger")
    }

    // --- Bölüm 1: Identity/Device ---
    /** Android'in uygulamaya özel dosya dizini (Context.filesDir.absolutePath)
     *  ile SQLite veritabanını açar. Diğer her şeyden ÖNCE çağrılmalıdır.
     *  Varsa, kayıtlı identity'nin PUBLIC key'lerini de belleğe yükler. */
    fun initDatabase(filesDir: String): Boolean {
        if (databaseOpen) return true
        return com.p2p.messenger.util.SkippedKeyManager.openDatabase(java.io.File(filesDir)).also { databaseOpen = it }
    }
    @Volatile private var databaseOpen = false
    /** The database is encrypted under [storageKey] (the SkippedKeyManager
     *  key). Only through [initDatabase]. */
    external fun initDatabaseKeyed(filesDir: String, storageKey: ByteArray): Boolean
    /** initDatabase sonrası: DB'de daha önce oluşturulmuş bir identity var mı
     *  (public key kayıtları belleğe yüklendi mi). */
    external fun hasStoredIdentity(): Boolean
    /** Yeni identity + ilk cihazı üretir. DÖNÜŞ: identity_id (veya "Error: ...").
     *  Bu çağrıdan HEMEN SONRA getPendingSecretBundle() çağrılıp sonucu
     *  KeystoreCrypto ile şifrelenip saklanmalıdır — aksi halde secret
     *  key'ler sadece bellekte kalır ve süreç öldüğünde kaybolur. */
    external fun createIdentity(deviceName: String): String
    /** createIdentity sonrası bir kereliğine: az önce üretilen secret key
     *  bundle'ını (CBOR, plaintext) döner. Rust tarafında bu çağrıdan sonra
     *  bellekten silinir — tekrar çağrılırsa boş dizi döner. */
    external fun getPendingSecretBundle(): ByteArray
    /** Keystore ile şifresi çözülmüş bir secret bundle'ı belleğe yükler —
     *  uygulama açılışında, initDatabase + hasStoredIdentity=true sonrası
     *  çağrılmalıdır. */
    external fun loadSecretBundle(bundleBytes: ByteArray): Boolean
    external fun getIdentityCode(): String
    external fun getIdentityShortCode(): String
    /** Spec dışı, kullanıcı isteği (WhatsApp tarzı grup yanıtı — yanıtlanan
     *  mesaj yerelde henüz yüklenmemişse "Sen" mi yoksa bir üyenin adı mı
     *  gösterileceğine karar vermek için): `getIdentityCode`/
     *  `getIdentityShortCode`'un aksine BİÇİMLENDİRİLMEMİŞ ham hex
     *  `identity_id` döner — `sender_identity_id`/`reply_to_sender_identity_id`
     *  alanlarıyla AYNI biçim, doğrudan karşılaştırılabilir. */
    external fun getOwnIdentityId(): String

    // --- Bölüm 4: Ağ ---
    /** `torEnabled`: açıksa arti ile bir Tor onion service başlatılır; cihaz
     *  CGNAT arkasında bile ulaşılabilir olur (bkz. tor.rs / SECURITY.md).
     *  Tor durumu `torStatus()` ile izlenir. Bu ayarın değişmesi ağ katmanının
     *  yeniden başlatılmasını gerektirir (canlı swarm'a transport eklenemez). */
    external fun startNetwork(nodeMode: Boolean, torEnabled: Boolean): String
    external fun setNodeMode(enabled: Boolean)
    /** Spec dışı, kullanıcı isteği: Ayarlar'daki geçmiş/ek depolama sınırı
     *  slider'ı (100MB-32GB). Sadece node modu açıkken uygulanır (bkz. Rust
     *  `enforce_history_storage_limit`) — sınırı düşürmek en eski dosyaları
     *  hemen siler. */
    external fun setHistoryStorageLimitBytes(bytes: Long)
    /** Spec dışı, kullanıcı isteği (Tor): UI için Tor durumu. Dönüş:
     *  "disabled" | "bootstrapping" | "ready" | "ready|<host>.onion" | "failed". */
    external fun torStatus(): String
    /** Spec dışı, kullanıcı isteği: BU cihazın (karşı tarafınki DEĞİL, bkz.
     *  `hasActiveSession`/`isPeerConnected`) genel ağ bağlantı durumu —
     *  JSON: `{"connected_peers": Int, "listening": Bool, "tor_enabled":
     *  Bool, "tor_status": String, "node_mode": Bool}`. Sohbet ekranının üst
     *  çubuğunda gösterilmek üzere. */
    external fun ownConnectionStatus(): String
    /** Polls the network; returns any messages decrypted during this poll. */
    external fun pollNetwork(): Array<String>
    /** Swarm'ın gerçekten dinlemeye başladığı, karşı tarafın dial edebileceği
     *  adres (`/p2p/<peer_id>` son ekiyle) — QR/manuel eşleşme akışının
     *  `rendezvous_node`'u bu olmalı. `startNetwork` sonrası ilk birkaç
     *  `pollNetwork` turuna kadar boş string dönebilir (henüz hiçbir
     *  dinleme adresi bildirilmedi). */
    external fun getNodeAddress(): String

    // --- Bölüm 1.3/1.4: QR + manuel eşleşme ---
    external fun generateQrPacket(rendezvousNode: String): ByteArray
    /** Spec dışı, kullanıcı isteği: `processManualEntry`'nin beklediği
     *  `identity_id|device_fingerprint|nonce|device_name|rendezvous_node`
     *  formatını üretir — panoya kopyalayıp karşı tarafa (ör. farklı bir
     *  ağdaysa, ekran paylaşımı/mesajla) iletmek için. Hata durumunda "". */
    external fun getManualAddCode(rendezvousNode: String): String
    /** Dönüş: başarılıysa `{"identity_id":...,"device_fingerprint":...,
     *  "device_name":...}` (JSON), başarısızsa "Error: ...". Kullanıcı
     *  isteği: `device_fingerprint`, çağıran tarafın (bkz. QrScanActivity)
     *  kullanıcıyı DOĞRUDAN yeni kişinin sohbet ekranına yönlendirip
     *  eşleşmenin hâlâ devam ettiğini ("Bağlanılıyor...") göstermesi için —
     *  `listContacts()`'ın `active_device_fingerprint`'ini BEKLEMEZ, o ancak
     *  gerçek IdentityExchange tamamlanınca dolar. */
    external fun processQrPacket(data: ByteArray): String
    /** bkz. `processQrPacket` aynı dönüş biçimi notu. */
    external fun processManualEntry(text: String): String
    /** JSON-encoded List<ContactSummary>. */
    external fun listContacts(): String

    // --- Çoklu-cihaz (spec 1.5/1.6/1.7): ikincil cihaz bağlama ---
    /** İkincil (yeni) cihazda: bu cihazı bir kimliğe bağlamak için gösterilecek
     *  "cihaz ekleme QR'ı"nın ham CBOR baytları. Bu cihaz önce normal
     *  `createIdentity` + `startNetwork`'ten geçmiş (provizyonel bir kimlik
     *  üretmiş) olmalı; `getNodeAddress()` hazır olana kadar boş dönebilir. */
    external fun buildDeviceLinkRequest(): ByteArray

    /** Closes the window in which a link grant is accepted (QR screen left). */
    external fun closeDeviceLinkWindow()
    /** Birincil (var olan hesabın) cihazında: taranan ikincil cihaz QR'ını
     *  (CBOR) işler — onaylar, bağlanır, tam senkron gönderir, tüm kişilere
     *  yeni cihazı duyurur. Dönüş: başarılıysa
     *  `{"device_fingerprint":...,"device_name":...}`, aksi halde "Error: ...". */
    external fun approveDeviceLink(data: ByteArray): String
    /** Reads a scanned link QR without acting on it. Same return shape. */
    external fun peekDeviceLink(data: ByteArray): String
    /** Six-digit compare code of a link QR ("123 456"): the new device and the
     *  approving device both show it. Empty if [data] is not a link request. */
    external fun deviceLinkCode(data: ByteArray): String
    /** Kimliğime ait cihazların listesi (bu cihaz + bağlı kardeş cihazlar).
     *  JSON dizi: `[{"device_fingerprint","device_name","is_active","is_this_device"}]`. */
    external fun listLinkedDevices(): String
    /** Bu cihaz bir kimliğe İKİNCİL olarak mı bağlandı (başka bir cihazca
     *  onaylandı mı)? İkincil cihazın bağlanma QR ekranı, bağlanmanın
     *  tamamlandığını bununla anlar. */
    external fun isSecondaryDevice(): Boolean
    /** Bir kardeş cihazı iptal eder (spec 1.6) — tüm kişilere/kardeşlere imzalı
     *  iptal yayılır. Dönüş: "OK" veya "Error: ...". */
    external fun revokeLinkedDevice(deviceFingerprint: String): String
    /** Çoklu-cihaz (spec 1.7.1): bir sohbet BU cihazda okununca kardeş
     *  cihazlara "okundu" bildir (onlar da okunmuş saysın). 1:1 için
     *  `peerDeviceFingerprint` dolu + `groupId` boş; grup için tersi.
     *  Kardeş cihaz yoksa no-op. Bir "read_state_sync" pollNetwork olayı
     *  olarak diğer cihazlara ulaşır. */
    external fun syncReadState(peerDeviceFingerprint: String, groupId: String, readAtMs: Long)

    // --- Bölüm 2.2: Cihaz değişikliği uyarıları ---
    /** JSON-encoded List<DeviceAlertInfo>. */
    external fun listPendingDeviceAlerts(): String
    external fun acceptDeviceAlert(fingerprint: String): Boolean
    external fun rejectDeviceAlert(fingerprint: String)

    /**
     * Kişiyi ENGELLER (kullanıcı kararı, 2026-08-27).
     *
     * `revokeContactDevice`'tan farkı kasıtlı: iptal TEK BİR CİHAZI kapatır
     * ve o kişi yeni bir cihazla geri gelebilir. Engel ise KİMLİĞİ hedefler
     * — o kişinin hiçbir cihazından paket kabul edilmez, hiçbirine
     * bağlanılmaz, "yeni cihaz" uyarısı bile üretilmez. Engelden çıkmanın
     * tek yolu YÜZ YÜZE yeniden eşleşme (karekod/manuel kod).
     */
    external fun blockIdentity(identityId: String): String

    /** Engeli kaldırır — yalnızca kullanıcının açık isteğiyle çağrılmalı. */
    external fun unblockIdentity(identityId: String)

    /** Engellenen kimlikler, JSON dizisi. */
    external fun listBlockedIdentities(): String

    /**
     * Güç tasarrufu modu (pil düzeltmesi, 2026-08-28).
     *
     * Ekran kapalı VE uygulama arka plandayken açılır. Ağ davranışını
     * bozmaz — yalnızca zaten sağlıklı, sessiz bekleyen bağlantıların
     * canlılık yoklama sıklığını 20 saniyeden 60 saniyeye indirir. Hücresel
     * radyo her yoklamadan sonra 5-15 saniye yüksek güçlü durumda kaldığı
     * için asıl kazanç burada.
     */
    external fun setPowerSave(enabled: Boolean)

    /**
     * Grup üzerinden tanışılmış bir kişiye TAM güven verir — arayüzdeki
     * "grup üzerinden eklendi, doğrulanmadı" işaretini kaldırır. Şifreleme
     * zaten aynıydı; bu yalnızca güven göstergesini değiştirir.
     */
    /**
     * Bir kişinin GÜVENLİK KODU — "doğrulandı olarak işaretle" derken
     * karşılaştırılacak şey bu.
     *
     * Kod, kişinin cihaz parmak izinden türetiliyor; o parmak izi de dört
     * açık anahtarın özeti. Kodun iki tarafta eşleşmesi, gerçekten aynı
     * anahtarları gördüğünüz anlamına gelir. Grup üzerinden tanışılan
     * kişilerde anahtarlar kurucudan geldiği için, kurucunun araya girmediğini
     * anlamanın kriptografik bir yolu YOK — yalnızca bu kodu başka bir
     * kanaldan (telefon, yüz yüze) karşılaştırmak var.
     */
    external fun contactSafetyCode(identityId: String): String

    external fun trustContact(contactId: String): String

    /**
     * Grup kurucu yetkisini başka bir ÜYEYE devreder. Kurucu bütün
     * cihazlarını kaybederse grup aksi halde kalıcı olarak kilitlenirdi.
     */
    external fun transferGroupFounder(groupId: String, newFounderIdentityId: String): String

    // --- Spec dışı, kullanıcı isteği: bekleyen (henüz ack alınmamış)
    //     mesajlar — bkz. lib.rs `awaiting_confirmation`/`regen_content`
    //     genişletmesi, SettingsFragment "Pending Messages" ekranı. ---
    /** Uygulama ön plana geldiğinde çağrılır — bkz. P2PApplication foreground
     *  algılama, lib.rs `retry_all_pending_now` dokümantasyonu (üstel geri
     *  çekilme aralığını beklemeden HEMEN yeniden dener). */
    external fun retryAllPendingNow()
    /** JSON-encoded List<PendingMessageSummary>. */
    external fun listPendingMessages(): String
    /** Bir bekleyen mesajı kalıcı olarak (Failed) bırakır — bkz. lib.rs
     *  `cancel_pending_message`. */
    external fun cancelPendingMessage(messageId: String): Boolean
    /** Spec dışı, kullanıcı isteği: bekleyen mesajlar listesindeki manuel
     *  "Şimdi Dene" düğmesi — bkz. lib.rs `retry_pending_message_now`
     *  (SADECE bu mesajın bir sonraki deneme zamanını HEMEN'e çeker, ağ
     *  I/O'su burada YAPILMAZ). */
    external fun retryPendingMessageNow(messageId: String): Boolean

    // --- Spec dışı, kullanıcı isteği ("connection testing and
    //     re-connecting automatically should be better") ---
    /** Bir ağ arayüzü değişikliği (Wi-Fi<->hücresel, ya da ağ tamamen
     *  kaybolup tekrar kazanılması) bildirir — bkz. P2PService
     *  `observeNetworkChangesForReconnect`, lib.rs `reconnect_all_known_now`.
     *  Bilinen TÜM Aktif cihazlar için, geri çekilme geçmişini yok
     *  sayarak ANINDA yeniden bağlanmayı dener. */
    /** Poll thread'i: ağda olay olana, başka bir çağrı çekirdeği isteyene ya da
     *  `timeoutMs` dolana kadar bloklar (bkz. Rust `wait_for_network_activity`).
     *  Sabit `postDelayed` beklemesinin yerine — mesajlar poll turunu beklemez. */
    external fun waitForNetworkActivity(timeoutMs: Long)

    /** Ends a running [waitForNetworkActivity] at once. Takes no core lock. */
    external fun wakePoll()
    /** PBKDF2-HMAC-SHA256 (Rust/ring) — bkz. `AppLock.derive`. Çekirdek kilidini almaz. */
    external fun pbkdf2Sha256(password: String, salt: ByteArray, iterations: Int, outLen: Int): ByteArray
    external fun notifyNetworkChanged()

    // --- Bölüm 3: Mesajlaşma ---
    /** Dönüş: başarılıysa `{"message_id":"...","status":"sent"|"pending"}`
     *  (JSON), başarısızsa "Error: ...". `status`, mesaj balonundaki
     *  gönderim ikonunu hemen doğru göstermek için — "pending" ise arka
     *  planda otomatik yeniden denenip bir "status" olayıyla (pollNetwork)
     *  güncellenecek. */
    /** `replyToMessageId`/`replyToPreview`: spec dışı, kullanıcı isteği
     *  (WhatsApp tarzı "sağa kaydırıp yanıtla") — yanıt verilmiyorsa ikisi
     *  de `null` geçilmeli (`external fun`'da varsayılan parametre değeri
     *  DESTEKLENMİYOR — bkz. Kotlin/Native sınırı, bu yüzden her çağıran
     *  taraf açıkça `null` geçirmeli). `replyToPreview`, yanıtlanan
     *  mesajın (çağıran tarafın kırptığı) kısa özeti — alıcı tarafın kendi
     *  arşivine bakmasına gerek kalmadan yanıtı gösterebilmesi için. */
    external fun sendMessage(targetDeviceFingerprint: String, message: String, replyToMessageId: String?, replyToPreview: String?): String
    /** Dönüş: sendMessage ile aynı JSON biçimi. */
    external fun editMessage(targetDeviceFingerprint: String, targetMessageId: String, newText: String): String
    external fun deleteMessage(targetDeviceFingerprint: String, targetMessageId: String): String
    /** Spec dışı, kullanıcı isteği (WhatsApp tarzı tepkiler): bir mesaja
     *  emoji bırakır. `emoji` BOŞ dize ise kendi tepkim kaldırılır (ayrı
     *  bir "kaldır" çağrısı yok — kişi başına tek tepki, bkz. Rust
     *  `MessageContent::Reaction`). Dönüş: o mesajın GÜNCEL tepki özeti
     *  (ör. "👍2 ❤️"), doğrudan tepki pill'ine yazılabilir. */
    external fun reactToMessage(targetDeviceFingerprint: String, targetMessageId: String, emoji: String): String
    /** bkz. `reactToMessage` — grup karşılığı. */
    external fun reactToGroupMessage(groupId: String, targetMessageId: String, emoji: String): String
    /** Spec dışı, kullanıcı isteği: tepki pill'ine dokunulduğunda "kim ne
     *  attı" listesi. JSON: `[{"identity_id":"...","emoji":"👍"}, ...]`,
     *  en yeni tepki başta. Pill'deki özet (bkz. `reactToMessage` dönüşü)
     *  yalnızca TOPLAMLARI taşır, kişi bilgisini taşımaz — bu yüzden ayrı
     *  bir çağrı. */
    external fun listReactions(targetMessageId: String): String
    /** Spec dışı, kullanıcı isteği (grup düzenle/sil): `editMessage`/
     *  `deleteMessage`'ın grup karşılığı — ulaşılabilir TÜM diğer üyelere
     *  gönderilir (bkz. `sendGroupMessage` AYNI fan-out deseni).
     *  `targetGroupMessageLocalId`, düzenlenecek/silinecek grup mesajının
     *  `messageId`'sidir (gönderirken dönen `group_message_local_id`).
     *  Dönüş: "OK" veya "Error: ...". */
    external fun editGroupMessage(groupId: String, targetGroupMessageLocalId: String, newText: String): String
    external fun deleteGroupMessage(groupId: String, targetGroupMessageLocalId: String): String
    /** Bir karşı tarafla aktif bir ratchet oturumu (el sıkışma tamamlanmış)
     *  var mı — ChatActivity'nin "bağlanılıyor..." göstergesi için. */
    external fun hasActiveSession(peerDeviceFingerprint: String): Boolean
    /** Spec dışı: GERÇEK canlı bağlantı durumu — `hasActiveSession`'ın
     *  aksine (o, bir ratchet oturumu kuruldu mu diye bakar ve bir kez
     *  kurulunca SÜRESİZ true kalır), bu, karşı taraf ŞU AN gerçekten
     *  bağlı mı diye Swarm'ın kendi bağlantı defterine bakar. Sohbet
     *  ekranındaki "Bağlı"/"Bağlanılıyor" durum yazısı için kullanılmalı —
     *  "Bağlanılıyor..." banner'ı (ilk el sıkışma) hâlâ hasActiveSession
     *  kullanır, bunlar farklı sorular. */
    external fun isPeerConnected(peerDeviceFingerprint: String): Boolean
    /** Bir sohbet açıldığında el sıkışmayı proaktif olarak başlatır (zaten
     *  bir oturum varsa no-op). */
    external fun ensureHandshake(peerDeviceFingerprint: String)
    /** Spec dışı, kullanıcı tarafından istenen "görüldü" bildirimi — `Ack`
     *  ile AYNI desen ama OTOMATİK değil: UI, mesajı kullanıcıya EKRANDA
     *  gösterdiği anda çağırmalı. `groupMessageLocalId`: 1:1 sohbette
     *  `null`, grup sohbetinde gelen "group_message" olayındaki AYNI
     *  değer geri gönderilmeli (bkz. Rust packet.rs `Seen` notu). */
    external fun sendSeenReceipt(targetDeviceFingerprint: String, targetMessageId: String, groupMessageLocalId: String?): Boolean

    // --- Mesaj geçmişi (spec dışı, kullanıcı tercihi: sadece node modu
    // açıkken yerelde şifreli arşivlenir) ---
    /** Keystore'dan çözülmüş 32 baytlık geçmiş şifreleme anahtarını yükler. */
    external fun setHistoryKey(keyBytes: ByteArray): Boolean
    /** Skipped-message-key önbelleğinin diske şifreli kalıcılığı için
     *  kullanılan anahtarı yükler. Node modundan BAĞIMSIZ her zaman
     *  çağrılmalıdır — bkz. Rust setSkippedKeyEncryptionKey dokümantasyonu. */
    external fun setSkippedKeyEncryptionKey(keyBytes: ByteArray): Boolean
    /** JSON-encoded List<ArchivedMessage>, eskiden yeniye sıralı. Her
     *  öğede artık `message_id`/`status` alanları da var (bkz. Rust
     *  ArchivedMessage notu — durum kalıcılığı düzeltmesi). */
    external fun getMessageHistory(peerDeviceFingerprint: String, limit: Int): String
    /** Spec dışı, hata düzeltmesi (grup geçmişi kalıcılığı):
     *  `getMessageHistory`'nin grup karşılığı — GroupChatActivity açılışında
     *  çağrılmalı (önceden hiç çağrılmıyordu, ekran her zaman boştan
     *  başlıyordu). Her öğede ayrıca `sender_identity_id` var (grupta
     *  birden çok gönderen olabildiğinden). */
    external fun getGroupMessageHistory(groupId: String, limit: Int): String
    /** Spec dışı: node modu kapalı cihazlarda yerel geçmiş boşsa, karşı
     *  tarafa (node modu açıksa) şifreli bir geçmiş isteği gönderir. Yanıt
     *  asenkron gelir — bkz. pollNetwork "history_sync" olayı. */
    external fun requestHistorySync(peerDeviceFingerprint: String, limit: Int)
    /** Spec dışı, kullanıcı isteği (sonsuz kaydırma): sohbet geçmişinin en
     *  üstüne kaydırıldığında ÖNCE bu çağrılmalı — YEREL arşivde
     *  `beforeTimestamp`'ten eski mesaj varsa (ağ gerekmeden) onları döner,
     *  `getMessageHistory` ile aynı JSON biçimi. */
    external fun getMessageHistoryBefore(peerDeviceFingerprint: String, beforeTimestamp: Long, limit: Int): String
    /** bkz. `getMessageHistoryBefore` aynı notu — grup arşivi için. */
    external fun getGroupMessageHistoryBefore(groupId: String, beforeTimestamp: Long, limit: Int): String
    /** Spec dışı, kullanıcı isteği (sonsuz kaydırma): `getMessageHistoryBefore`
     *  boş/yetersiz döndüğünde çağrılmalı — karşı taraftan bu zaman
     *  damgasından eski mesajları ağdan ister. Yanıt asenkron gelir — bkz.
     *  pollNetwork "older_history" olayı. */
    external fun requestOlderMessageHistory(peerDeviceFingerprint: String, beforeTimestamp: Long, limit: Int)
    /** bkz. `requestOlderMessageHistory` aynı notu — grup için, ulaşılabilir
     *  TÜM diğer üyelere gönderilir. Yanıt: pollNetwork "older_group_history". */
    external fun requestOlderGroupMessageHistory(groupId: String, beforeTimestamp: Long, limit: Int)
    /** Spec dışı, dış inceleme düzeltmesi ("sibling backfill sayfalama
     *  desteklemiyordu — karşı taraf ulaşılamazken bu cihazın KENDİ diğer
     *  cihazından eski geçmiş istemesinin yolu yoktu"): `requestOlderMessageHistory`
     *  ile AYNI ANDA, EK bir kaynak olarak çağrılmalı — ikisi de `message_id`
     *  bazlı dedup ettiğinden çift kayıt oluşturmaz. Yanıt da AYNI
     *  "older_history" olayı olarak gelir. */
    external fun requestOlderSiblingHistory(peerDeviceFingerprint: String, beforeTimestamp: Long, limit: Int)
    /** bkz. `requestOlderSiblingHistory` aynı notu — grup için,
     *  `requestOlderGroupMessageHistory` ile birlikte EK kaynak. */
    external fun requestOlderSiblingGroupHistory(groupId: String, beforeTimestamp: Long, limit: Int)

    // --- Spec dışı: dosya/foto/video/ses ekleri (azami 4GB) ---
    /** `sourcePath` zaten yerel bir dosya yolu olmalı (content:// URI
     *  DEĞİL — çağıran taraf önce ContentResolver ile yerel bir önbellek
     *  dosyasına kopyalamalı). `previewJpeg`: foto/video ekleri için
     *  önceden oluşturulmuş küçük bir 480p/%85 JPEG önizleme kapağı (bkz.
     *  ChatActivity generateImagePreview/generateVideoPreview) — diğer
     *  türler için `null` geçilmeli. BÜYÜK dosyalar için bu çağrı bir süre
     *  alabilir — ANA THREAD'DE ÇAĞIRMAYIN (coroutine/Dispatchers.IO
     *  kullanın). Dönüş: sendMessage ile aynı JSON biçimi, message_id
     *  alanı burada file_id'dir. */
    /** `durationMs`: sesli mesajlar için çalma süresi, diğer türler için -1
     *  geçilmeli (jint null taşıyamadığından, -1 = "yok" sentineli). */
    external fun prepareAndSendFile(targetDeviceFingerprint: String, sourcePath: String, fileName: String, mimeType: String, previewJpeg: ByteArray?, durationMs: Int, caption: String, replyToMessageId: String, replyToPreview: String): String
    /** Başarılıysa "OK" döner ve ilerleme/tamamlanma pollNetwork() üzerinden
     *  "file_progress"/"file_complete"/"file_failed" olaylarıyla gelir.
     *  Başarısızsa "Error: ..." döner VE bu durumda hiçbir pollNetwork
     *  olayı gelmeyecektir (indirme hiç başlamadı) — çağıran taraf bu
     *  dönüş değerini MUTLAKA kontrol etmeli, aksi halde UI "İndiriliyor"
     *  durumunda sonsuza kadar takılı kalır. */
    external fun downloadFile(fileId: String, peerDeviceFingerprint: String): String
    /** JSON-encoded List<AttachmentSummary>, oluşturulma sırasına göre. */
    external fun listAttachments(peerDeviceFingerprint: String): String

    /** [listAttachments] / [listGroupAttachments] without the preview images. */
    external fun listAttachmentsBrief(peerDeviceFingerprint: String): String
    external fun listGroupAttachmentsBrief(groupId: String): String
    /** Spec dışı, kullanıcı isteği (grup ekleri): `prepareAndSendFile`'ın
     *  grup karşılığı — dosya TEK SEFERDE şifrelenir, ulaşılabilir TÜM diğer
     *  üyelere aynı `file_id`/anahtarla sunulur. Dönüş: başarılıysa
     *  `file_id`, aksi halde "Error: ...". İndirme için AYRI bir fonksiyon
     *  YOK — mevcut `downloadFile` kullanılır (bkz. `listGroupAttachments`
     *  dönen `peer_device_fingerprint` alanı, indirilecek göndericiyi taşır). */
    external fun prepareAndSendGroupFile(groupId: String, sourcePath: String, fileName: String, mimeType: String, previewJpeg: ByteArray?, durationMs: Int, caption: String, replyToMessageId: String, replyToPreview: String, replyToSenderIdentityId: String): String
    /** bkz. `listAttachments` aynı notu — grup ekleri için. Her öğede
     *  AYRICA `peer_device_fingerprint` (bu ekin `downloadFile` ile hangi
     *  göndericiden isteneceği) ve `sender_identity_id` (kimin gönderdiği,
     *  isim/avatar göstermek için) alanları vardır. */
    external fun listGroupAttachments(groupId: String): String
    /** Tamamlanmış bir ekin çözülmüş (plaintext) kopyasının mutlak yolu,
     *  ya da hata varsa "Error: ...". BÜYÜK dosyalar için ANA THREAD'DE
     *  ÇAĞIRMAYIN. */
    external fun getAttachmentPlaintextPath(fileId: String): String

    // --- Bölüm 5: Grup mesajlaşma ---
    /** JSON-encoded List<GroupSummary>. */
    external fun listGroups(): String
    external fun createGroup(name: String): String
    external fun inviteToGroup(groupId: String, identityId: String): Boolean
    /** "Retry" on a group bubble: 1 = sent again to the devices that missed
     *  it, 0 = nothing recorded for this id, -1 = nothing could be sent. */
    external fun retryGroupMessageCopies(groupId: String, localId: String): Int
    external fun removeFromGroup(groupId: String, identityId: String): Boolean
    /** Spec dışı, kullanıcı isteği: grubu TÜM üyeler için siler (imzalı
     *  `GroupChange::Delete` herkese gönderilir). SADECE kurucu için
     *  başarılıdır; aksi halde "Error: ..." döner. */
    external fun deleteGroup(groupId: String): String
    /** Spec dışı, kullanıcı isteği: kurucu OLMAYAN bir üye gruptan kendi
     *  isteğiyle ayrılır — kurucuya bir ayrılma isteği gönderilir (kurucu
     *  o an erişilemez olsa bile güvenilir teslim ile beklemeye alınır) ve
     *  bu cihazdaki grup kaydı hemen kaldırılır. Kurucu için "Error: ..."
     *  döner (kurucu SADECE `deleteGroup` ile herkes için silebilir). */
    external fun leaveGroup(groupId: String): String
    /** Dönüş: `group_message_local_id` (bkz. Rust send_group_message notu —
     *  N üyeye giden fan-out kopyalarını TEK bir yerel kimlikte
     *  birleştirir, "görüldü" bildirimlerini doğru balona eşlemek için
     *  gerekli) veya "Error: ...". `replyTo*`: bkz. `sendMessage` AYNI
     *  notu — grup için ARTI `replyToSenderIdentityId` (yanıtlanan mesajı
     *  gönderenin kimliği, "Ahmet'e yanıt" gösterebilmek için). */
    external fun sendGroupMessage(groupId: String, message: String, replyToMessageId: String?, replyToPreview: String?, replyToSenderIdentityId: String?): String
    /** Spec dışı: grup profil fotoğrafı — SADECE kurucu için başarılı olur
     *  (bkz. Rust set_group_avatar). `avatarJpeg` null ise kaldırılır. Her
     *  iki durumda da TÜM üyelere bir GroupUpdate yayılır. */
    external fun setGroupProfilePicture(groupId: String, avatarJpeg: ByteArray?): String

    // --- Bölüm 1.8: Kurtarma dosyası ---
    external fun exportRecovery(passphrase: String): ByteArray

    /** `exportRecovery`'nin karşılığı — `createIdentity` ile AYNI kalıp:
     *  başarılıysa identity_id döner ve secret bundle'ı bekletmeye alır,
     *  hemen ardından [getPendingSecretBundle] ile çekilip Keystore'la
     *  şifrelenip diske yazılmalıdır (bkz. IdentityManager.persistNewIdentity).
     *  Başarısızsa "Error: ..." döner (yanlış parola/bozuk dosya). */
    external fun importRecovery(fileBytes: ByteArray, passphrase: String, deviceName: String): String

    // --- Spec dışı: yazıyor... göstergesi ---
    /** Fire-and-forget — arşivlenmez, güvenilir teslim kuyruğuna girmez.
     *  Kotlin tarafı sadece false->true/true->false GEÇİŞLERİNDE
     *  çağırmalı, her tuş vuruşunda DEĞİL. */
    external fun sendTypingIndicator(targetDeviceFingerprint: String, isTyping: Boolean): Boolean
    /** bkz. `sendTypingIndicator` aynı notu — grup sohbeti için, ulaşılabilir
     *  TÜM diğer üyelere gönderilir. */
    external fun sendGroupTypingIndicator(groupId: String, isTyping: Boolean): Boolean

    // --- Spec dışı: profil fotoğrafı (720p/%85 JPEG) ---
    /** Şu an ayarlı olan kendi profil fotoğrafımız, yoksa boş dizi. */
    external fun getOwnProfilePicture(): ByteArray
    /** `avatarJpeg` null ise fotoğraf kaldırılır. Her iki durumda da
     *  bilinen TÜM kişilere bir `ProfileUpdate` gönderilir — büyük bir
     *  dosya olabileceğinden (yüzlerce KB) ANA THREAD'DE ÇAĞIRMAYIN. */
    external fun setOwnProfilePicture(avatarJpeg: ByteArray?): String

    // --- Spec dışı, kullanıcı isteği (2026-09-04): hesap adı ---
    /** Şu anki hesap adımız (kişilerin bizi gördüğü ad), yoksa boş dize. */
    external fun getDisplayName(): String
    /** Hesap adını değiştirir ve değişikliği bilinen TÜM kişilere otomatik
     *  bildirir (`ProfileUpdate`, ratchet üzerinden — çevrimdışı kişiler
     *  geri döndüklerinde alır). Fan-out kişi başına şifreleme yaptığından
     *  ANA THREAD'DE ÇAĞIRMAYIN. Başarılıysa "OK". */
    external fun setDisplayName(name: String): String

    /** Tüm kişilere ve kardeş cihazlara `AccountDeleted` gönderir (grup
     *  kurucusuysa yetkiyi devreder). Bildirim giden cihaz sayısı; hata `-1`. */
    external fun deleteAccount(): Int

    /** Henüz onaylanmamış hesap silme bildirimi sayısı. */
    external fun accountDeletionPending(): Int

    // --- Spec dışı: sohbet/kişi silme (uzun basma menüsü) ---
    /** Yumuşak seçenek: sadece yerel mesaj/ek geçmişini siler, eşleşme
     *  KORUNUR. */
    external fun clearChatHistory(contactId: String): String
    /** Sert seçenek: eşleşme/ratchet oturumu DAHİL kişiyi tamamen siler —
     *  yeniden mesajlaşmak için taze bir QR/manuel eşleşme gerekir. */
    external fun deleteContact(contactId: String): String
    /** Spec dışı, güvenlik denetimi düzeltmesi: bu kişinin TEK bir cihazını
     *  iptal eder — kişiyi/geçmişi SİLMEZ, sadece o cihaz fingerprint'inden
     *  gelecek/giden her şeyi durdurur (bkz. Rust revoke_contact_device —
     *  is_active artık receive_message/handshake'te gerçekten kontrol
     *  ediliyor). Ör. "eski telefonum çalındı, bu cihazı artık güvenme". */
    external fun revokeContactDevice(contactId: String, deviceFingerprint: String): String
    /** Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
     *  connectivity" notu): kullanıcının güvendiği/kendi işlettiği bir röle
     *  (Circuit Relay v2) adresini elle ekler — ör. "/ip4/1.2.3.4/tcp/4001/p2p/12D3Koo...".
     *  Farklı ağlardaki iki kişinin (aralarında hiç ortak röle geçmişi
     *  olmadan) ilk kez eşleşebilmesini garanti eden tek yol budur. */
    external fun addKnownRelayAddress(multiaddr: String): String

    // --- Sunucu (store-and-forward) seçeneği ---
    //
    // Rölelerden FARKLI: bir röle hiçbir şey saklamaz, sadece iki taraf da
    // O ANDA bağlıyken canlı bir devre kurar. Sunucu ise alıcı çevrimdışıyken
    // zarfı diske yazar ve alıcı döndüğünde teslim eder. Sunucu içeriği
    // okuyamaz: zarflar zaten uçtan uca şifreli ve ikinci kez mühürlü.

    /** Davet kodundan (`typeon-server:<multiaddr>#<jeton>`) sunucu ekler. */
    external fun addServer(inviteCode: String): String

    external fun removeServer(serverId: String): String

    /** `[{server_id, address, name, route_messages, store_history, connected, enrolled, last_error}]` */
    external fun listServers(): String


    external fun setServerRouting(serverId: String, enabled: Boolean): String

    /**
     * Geçmişi sunucuda saklama — mesaj yönlendirmeden AYRI ve varsayılan
     * KAPALI. Arşiv gerçek bir yedektir ve ratchet'in aksine ileri-gizli
     * DEĞİLDİR: kök arşiv anahtarı bir gün sızarsa o ana kadar yüklenmiş TÜM
     * geçmiş okunur. "Yeni cihazımda geçmişimi göreyim" ile ileri-gizlilik
     * matematiksel olarak uzlaşmaz, bu yüzden takas kullanıcının açık
     * tercihi olmalı.
     */
    external fun setServerHistory(serverId: String, enabled: Boolean): String

    /**
     * Kök arşiv anahtarı (ARK). `setHistoryKey` ile aynı desen ama bu anahtar
     * CİHAZA değil KİMLİĞE aittir — aynı kimliğin bütün cihazları sunucudaki
     * arşivi okuyabilmeli, bu yüzden kardeş cihazlara `DeviceSync` ile ve
     * kurtarma dosyasına da girer.
     */
    external fun setArchiveRootKey(keyBytes: ByteArray): Boolean

    /** Çekirdekteki ARK (yoksa boş) — kardeşten gelenin diske yazılması için. */
    external fun archiveRootKey(): ByteArray

    /**
     * Sunucudaki BÜTÜN geçmişi indirir — kurtarma dosyasından ya da cihaz
     * bağlamayla yeni kurulmuş bir cihaz için. `"OK:<sohbet sayısı>"` döner.
     *
     * Sohbette yukarı kaydırma akışından farkı: o, sohbetin zaten görünür
     * olmasını varsayar. Sıfırdan kurulan bir cihazda kişiler geri gelir ama
     * hiç mesaj yoktur ve kullanıcının kaydıracağı bir şey de yoktur.
     */
    external fun restoreServerHistory(): String

    /**
     * One chat's older history from the server archive, for a "fetch history
     * from server" button; scrolling up never asks the server. [chatKey]: the
     * peer device fingerprint, or the group id. [beforeTimestamp]: the oldest
     * message on screen (ms), 0 = from the newest. Returns "OK" or
     * "Error: ..."; the rows arrive later with a `history_backfilled` event.
     */
    external fun fetchServerHistory(chatKey: String, isGroup: Boolean, beforeTimestamp: Long): String

    // --- Voice/video calls (Rust `call.rs`) ---
    /** Rings a 1:1 contact device. Returns the call id or "Error: ...". */
    external fun startCall(peerFingerprint: String, video: Boolean): String
    /** Rings every other member of the group. Returns the call id or "Error: ...". */
    external fun startGroupCall(groupId: String, video: Boolean): String
    /** Answers the ringing incoming call. */
    external fun acceptCall(): Boolean
    /** Rejects a ringing call, hangs up otherwise. */
    external fun endCall(): Boolean
    /** JSON: `{"state":"idle|outgoing|incoming|active", participants:[{fp,name,joined,slot}], media:{...}}`. */
    external fun callState(): String
    /** Queues one encoded frame (1 = Opus bundle, 2 = H.264) for every participant.
     *  Takes no core lock: safe to call 20-40 times a second from media threads. */
    external fun callSend(kind: Int, data: ByteArray): Boolean
    /** Next received frame `[kind][slot][payload]`, or null after [timeoutMs]. No core lock. */
    external fun callRecv(timeoutMs: Int): ByteArray?
    /** Deepest outgoing link queue, in frames (0..48) — the congestion signal. */
    external fun callBacklog(): Int
    /** Metered (cellular) network: Tor channel padding off; otherwise reduced. */
    external fun setMeteredNetwork(metered: Boolean)
    /** Our decoder for [slot] needs a keyframe; asks that sender in the next report. */
    external fun callRequestKeyframe(slot: Int)
    /** True once after a participant asked us for a keyframe. */
    external fun callTakeKeyframeRequest(): Boolean

    // --- Shared whiteboard (see whiteboard.rs). Every call names a chat: a
    // group by [groupId], or the 1:1 chat with [peer] when [groupId] is "". ---

    /** A finished stroke on the 1600x1000 board; [points] are little-endian u16
     *  x,y pairs, [shade] 0 light / 1 base / 2 dark, [width] the pen width in
     *  board units (0 = default). Returns the new stroke
     *  ids as hex (16 digits each), or "Error: ...". */
    external fun whiteboardAddStroke(peer: String, groupId: String, page: Int, shade: Int, width: Int, points: ByteArray): String
    /** [ids]: 8 bytes per erased stroke. */
    external fun whiteboardErase(peer: String, groupId: String, ids: ByteArray): String
    /** The board was opened: syncs with the devices that are connected now. */
    external fun whiteboardOpen(peer: String, groupId: String)
    external fun whiteboardMarkRead(peer: String, groupId: String, page: Int)
    /** JSON: `{"pages", "unread" (bit per page), "me", "participants":[{"id","name"}]}`;
     *  the participant order is the colour order. */
    external fun whiteboardInfo(peer: String, groupId: String): String
    /** Per stroke: id(8) shade(1) author index(1, 255 = left) width(1) point count(u16) points. */
    external fun whiteboardPage(peer: String, groupId: String, page: Int): ByteArray
    /** Sends batched strokes / the settling summary if they are due. */
    external fun whiteboardTick()
}
