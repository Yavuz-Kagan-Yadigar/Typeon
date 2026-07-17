package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.P2PLib
import java.io.File
import java.security.SecureRandom

/**
 * Mesaj geçmişi arşivinin şifreleme anahtarını yönetir. Artık node
 * modundan BAĞIMSIZ olarak her zaman yüklenir (bkz. P2PService
 * onStartCommand notu) — ama bunu YAZMA POLİTİKASI hâlâ iki farklı
 * kaynağa göre değişir (bkz. lib.rs `archive_message` çağıranları):
 * - Canlı mesaj trafiği: SADECE node modu açık cihazlarda arşivlenir
 *   (kullanıcı tercihi — "server olmayı tercih eden" cihaz).
 * - `HistorySyncResponse` (karşı taraftan çekilen geçmiş): node modu
 *   KAPALI cihazlarda da yerelde kalıcı kılınır — aksi halde uygulama her
 *   kapatılıp açıldığında geçmiş sanki kayboluyormuş gibi görünürdü.
 *
 * Anahtar hayat döngüsü, IdentityManager ile aynı desende:
 * - İlk açılışta rastgele 256-bit bir "history data key" üretilir,
 *   Keystore'daki AYRI bir sarma (wrap) anahtarıyla şifrelenip diske
 *   yazılır.
 * - Her açılışta şifre çözülüp Rust'a `setHistoryKey` ile yüklenir.
 * - Diskte hiçbir zaman plaintext data key bulunmaz.
 */
object MessageHistoryManager {
    private const val HISTORY_KEY_FILENAME = "history_key.enc"

    private fun keyFile(context: Context): File =
        File(context.filesDir, HISTORY_KEY_FILENAME)

    /**
     * Node modu açıkken uygulama her başladığında (veya node modu ilk kez
     * açıldığında) çağrılır: anahtar dosyası yoksa yeni bir data key
     * üretip şifreleyerek diske yazar; varsa çözüp Rust'a yükler.
     */
    fun ensureHistoryKeyLoaded(context: Context) {
        val file = keyFile(context)

        val dataKey: ByteArray = if (file.exists()) {
            val encrypted = try {
                file.readBytes()
            } catch (e: Exception) {
                return
            }
            try {
                KeystoreCrypto.decrypt(encrypted, KeystoreCrypto.ALIAS_HISTORY)
            } catch (e: Exception) {
                // Keystore anahtarı kayıp/bozuk — mesaj geçmişi arşivi
                // kurtarılamaz (bu, identity'den farklı olarak recovery
                // dosyasının kapsamında değil; sadece yerel arşiv). Yeni
                // bir anahtarla baştan başlanır, eski arşiv satırları
                // artık çözülemez halde DB'de kalır (temizlenmez).
                generateAndPersist(context)
                return
            }
        } else {
            generateAndPersist(context)
            return
        }

        try {
            P2PLib.setHistoryKey(dataKey)
        } finally {
            dataKey.fill(0)
        }
    }

    private fun generateAndPersist(context: Context) {
        val dataKey = ByteArray(32)
        SecureRandom().nextBytes(dataKey)
        try {
            val encrypted = KeystoreCrypto.encrypt(dataKey, KeystoreCrypto.ALIAS_HISTORY)
            keyFile(context).writeBytes(encrypted)
            P2PLib.setHistoryKey(dataKey)
        } finally {
            dataKey.fill(0)
        }
    }
}
