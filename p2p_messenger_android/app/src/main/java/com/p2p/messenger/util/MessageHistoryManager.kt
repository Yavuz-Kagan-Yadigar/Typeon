package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.P2PLib
import java.io.File
import java.security.SecureRandom

/**
 * Mesaj geçmişi arşivinin şifreleme anahtarını yönetir. Node modundan
 * BAĞIMSIZ olarak her zaman yüklenir (bkz. P2PService onStartCommand
 * notu). Spec dışı düzeltme: önceden hem bu anahtarın yüklenmesi HEM DE
 * canlı mesaj trafiğinin arşivlenmesi SADECE node modu açıkken
 * yapılıyordu ("server olmayı tercih eden cihaz" kullanıcı tercihi) —
 * kullanıcı artık açıkça TÜM cihazlarda (node olsun olmasın) kendi
 * sohbet geçmişinin yerelde şifreli kalıcı kılınmasını istedi. Node modu
 * artık SADECE karşı taraflara `HistorySyncRequest` yanıtlarken yardımcı
 * olma (bkz. receive.rs receive_message) ve DHT routing katılımını
 * etkiliyor — kendi geçmişini saklama kararını değil (bkz. archive.rs
 * `archive_message` çağıranları, `node_mode_enabled` kontrolü artık YOK).
 *
 * Anahtar hayat döngüsü, IdentityManager ile aynı desende:
 * - İlk açılışta rastgele 256-bit bir "history data key" üretilir,
 *   Keystore'daki AYRI bir sarma (wrap) anahtarıyla şifrelenip diske
 *   yazılır.
 * - Her açılışta şifre çözülüp Rust'a `setHistoryKey` ile yüklenir.
 * - Diskte hiçbir zaman plaintext data key bulunmaz.
 */
object MessageHistoryManager {
    private const val TAG = "MessageHistoryManager"
    // Defter #04: cozme HATASINDA anahtar YENIDEN URETILMEZ.
    //
    // Burasi eskiden "dosya var ama decrypt istisna atti" durumunda
    // `generateAndPersist` cagiriyor, yani anahtar dosyasini taze rastgele
    // bir anahtarla EZIYORDU — "anahtar yok" ile "anahtar bu sefer
    // cozulemedi"yi ayni sey sayarak. Tek bir gecici Keystore hatasi (cihaz
    // yedekten donus, ekran kilidi kimlik bilgisinin sifirlanmasi, StrongBox
    // arizasi) bu anahtarla sifrelenmis HER SEYI geri donusuz yok ediyordu
    // ve kullanici hicbir uyari gormuyordu. Kardesleri (`ArchiveKeyManager`,
    // `IdentityManager`) zaten dogru davraniyordu: cozme basarisizsa sadece
    // geri don. Yeniden uretim artik SADECE dosya hic yokken.

    private const val HISTORY_KEY_FILENAME = "history_key.enc"

    private fun keyFile(context: Context): File =
        File(context.filesDir, HISTORY_KEY_FILENAME)

    /**
     * Node modu açıkken uygulama her başladığında (veya node modu ilk kez
     * açıldığında) çağrılır: anahtar dosyası yoksa yeni bir data key
     * üretip şifreleyerek diske yazar; varsa çözüp Rust'a yükler.
     */
    @Synchronized
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
                // bkz. TAG notu (#04) — ASLA yeniden uretme.
                android.util.Log.e(TAG, "Anahtar cozulemedi, YENIDEN URETILMIYOR", e)
                KeystoreCrypto.reportKeyFailure(context)
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
            keyFile(context).writeBytesAtomic(encrypted)
            P2PLib.setHistoryKey(dataKey)
        } catch (e: Exception) {
            // Keystore or disk failure: this runs on unguarded start-up
            // paths and took the process down before the network started.
            android.util.Log.e(TAG, "Anahtar uretilemedi", e)
        } finally {
            dataKey.fill(0)
        }
    }
}
