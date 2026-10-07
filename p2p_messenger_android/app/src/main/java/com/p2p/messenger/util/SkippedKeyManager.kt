package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.P2PLib
import java.io.File
import java.security.SecureRandom

/**
 * Skipped-message-key önbelleğinin (Double Ratchet sıra dışı/gecikmeli
 * mesaj desteği) diske şifreli kalıcılığı için kullanılan anahtarı
 * yönetir. `MessageHistoryManager`'ın aksine bu, node modundan
 * BAĞIMSIZ her zaman yüklenir — mesajlaşmanın güvenilirliği için
 * gerekli bir mekanizma, opsiyonel bir arşivleme değil.
 *
 * Anahtar hayat döngüsü aynı desende (IdentityManager/MessageHistoryManager
 * ile tutarlı): rastgele 256-bit veri anahtarı üretilir, Keystore'daki
 * AYRI bir sarma anahtarıyla (ALIAS_SKIPPED_KEYS) şifrelenip diske
 * yazılır; her açılışta çözülüp Rust'a yüklenir. Diskte hiçbir zaman
 * plaintext anahtar bulunmaz.
 */
object SkippedKeyManager {
    private const val TAG = "SkippedKeyManager"
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

    private const val KEY_FILENAME = "skipped_key_enc.enc"

    private fun keyFile(context: Context): File =
        File(context.filesDir, KEY_FILENAME)

    /** Uygulama her başladığında (initDatabase sonrası, node modundan
     *  bağımsız) çağrılmalıdır. */
    @Synchronized
    fun ensureLoaded(context: Context) {
        val file = keyFile(context)

        val dataKey: ByteArray = if (file.exists()) {
            val encrypted = try {
                file.readBytes()
            } catch (e: Exception) {
                return
            }
            try {
                KeystoreCrypto.decrypt(encrypted, KeystoreCrypto.ALIAS_SKIPPED_KEYS)
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
            P2PLib.setSkippedKeyEncryptionKey(dataKey)
        } finally {
            dataKey.fill(0)
        }
    }

    private fun generateAndPersist(context: Context) {
        val dataKey = ByteArray(32)
        SecureRandom().nextBytes(dataKey)
        try {
            val encrypted = KeystoreCrypto.encrypt(dataKey, KeystoreCrypto.ALIAS_SKIPPED_KEYS)
            keyFile(context).writeBytesAtomic(encrypted)
            P2PLib.setSkippedKeyEncryptionKey(dataKey)
        } catch (e: Exception) {
            // Keystore or disk failure: this runs on unguarded start-up
            // paths and took the process down before the network started.
            android.util.Log.e(TAG, "Anahtar uretilemedi", e)
        } finally {
            dataKey.fill(0)
        }
    }
}
