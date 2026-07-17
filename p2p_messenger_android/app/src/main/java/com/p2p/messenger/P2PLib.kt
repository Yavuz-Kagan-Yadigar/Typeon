package com.p2p.messenger

object P2PLib {
    init {
        System.loadLibrary("p2p_messenger")
    }

    // --- Bölüm 1: Identity/Device ---
    /** Android'in uygulamaya özel dosya dizini (Context.filesDir.absolutePath)
     *  ile SQLite veritabanını açar. Diğer her şeyden ÖNCE çağrılmalıdır.
     *  Varsa, kayıtlı identity'nin PUBLIC key'lerini de belleğe yükler. */
    external fun initDatabase(filesDir: String): Boolean
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

    // --- Bölüm 4: Ağ ---
    external fun startNetwork(nodeMode: Boolean): String
    external fun setNodeMode(enabled: Boolean)
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
    external fun processQrPacket(data: ByteArray): String
    external fun processManualEntry(text: String): String
    /** JSON-encoded List<ContactSummary>. */
    external fun listContacts(): String

    // --- Bölüm 2.2: Cihaz değişikliği uyarıları ---
    /** JSON-encoded List<DeviceAlertInfo>. */
    external fun listPendingDeviceAlerts(): String
    external fun acceptDeviceAlert(fingerprint: String): Boolean
    external fun rejectDeviceAlert(fingerprint: String)

    // --- Bölüm 3: Mesajlaşma ---
    /** Dönüş: başarılıysa `{"message_id":"...","status":"sent"|"pending"}`
     *  (JSON), başarısızsa "Error: ...". `status`, mesaj balonundaki
     *  gönderim ikonunu hemen doğru göstermek için — "pending" ise arka
     *  planda otomatik yeniden denenip bir "status" olayıyla (pollNetwork)
     *  güncellenecek. */
    external fun sendMessage(targetDeviceFingerprint: String, message: String): String
    /** Dönüş: sendMessage ile aynı JSON biçimi. */
    external fun editMessage(targetDeviceFingerprint: String, targetMessageId: String, newText: String): String
    external fun deleteMessage(targetDeviceFingerprint: String, targetMessageId: String): String
    /** Bir karşı tarafla aktif bir ratchet oturumu (el sıkışma tamamlanmış)
     *  var mı — ChatActivity'nin "bağlanılıyor..." göstergesi için. */
    external fun hasActiveSession(peerDeviceFingerprint: String): Boolean
    /** Bir sohbet açıldığında el sıkışmayı proaktif olarak başlatır (zaten
     *  bir oturum varsa no-op). */
    external fun ensureHandshake(peerDeviceFingerprint: String)

    // --- Mesaj geçmişi (spec dışı, kullanıcı tercihi: sadece node modu
    // açıkken yerelde şifreli arşivlenir) ---
    /** Keystore'dan çözülmüş 32 baytlık geçmiş şifreleme anahtarını yükler. */
    external fun setHistoryKey(keyBytes: ByteArray): Boolean
    /** Skipped-message-key önbelleğinin diske şifreli kalıcılığı için
     *  kullanılan anahtarı yükler. Node modundan BAĞIMSIZ her zaman
     *  çağrılmalıdır — bkz. Rust setSkippedKeyEncryptionKey dokümantasyonu. */
    external fun setSkippedKeyEncryptionKey(keyBytes: ByteArray): Boolean
    /** JSON-encoded List<ArchivedMessage>, eskiden yeniye sıralı. */
    external fun getMessageHistory(peerDeviceFingerprint: String, limit: Int): String
    /** Spec dışı: node modu kapalı cihazlarda yerel geçmiş boşsa, karşı
     *  tarafa (node modu açıksa) şifreli bir geçmiş isteği gönderir. Yanıt
     *  asenkron gelir — bkz. pollNetwork "history_sync" olayı. */
    external fun requestHistorySync(peerDeviceFingerprint: String, limit: Int)

    // --- Spec dışı: dosya/foto/video/ses ekleri (azami 4GB) ---
    /** `sourcePath` zaten yerel bir dosya yolu olmalı (content:// URI
     *  DEĞİL — çağıran taraf önce ContentResolver ile yerel bir önbellek
     *  dosyasına kopyalamalı). BÜYÜK dosyalar için bu çağrı bir süre
     *  alabilir — ANA THREAD'DE ÇAĞIRMAYIN (coroutine/Dispatchers.IO
     *  kullanın). Dönüş: sendMessage ile aynı JSON biçimi, message_id
     *  alanı burada file_id'dir. */
    external fun prepareAndSendFile(targetDeviceFingerprint: String, sourcePath: String, fileName: String, mimeType: String): String
    /** Hemen döner — ilerleme/tamamlanma pollNetwork() üzerinden
     *  "file_progress"/"file_complete"/"file_failed" olaylarıyla gelir. */
    external fun downloadFile(fileId: String, peerDeviceFingerprint: String): Boolean
    /** JSON-encoded List<AttachmentSummary>, oluşturulma sırasına göre. */
    external fun listAttachments(peerDeviceFingerprint: String): String
    /** Tamamlanmış bir ekin çözülmüş (plaintext) kopyasının mutlak yolu,
     *  ya da hata varsa "Error: ...". BÜYÜK dosyalar için ANA THREAD'DE
     *  ÇAĞIRMAYIN. */
    external fun getAttachmentPlaintextPath(fileId: String): String

    // --- Bölüm 5: Grup mesajlaşma ---
    /** JSON-encoded List<GroupSummary>. */
    external fun listGroups(): String
    external fun createGroup(name: String): String
    external fun inviteToGroup(groupId: String, identityId: String): Boolean
    external fun removeFromGroup(groupId: String, identityId: String): Boolean
    external fun sendGroupMessage(groupId: String, message: String): Boolean

    // --- Bölüm 1.8: Kurtarma dosyası ---
    external fun exportRecovery(passphrase: String): ByteArray
}
