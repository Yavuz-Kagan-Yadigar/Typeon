package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.P2PLib
import java.io.File

/**
 * Identity yaşam döngüsünü yönetir: ilk oluşturma sırasında secret key
 * bundle'ını Keystore ile şifreleyip diske yazar; sonraki açılışlarda
 * şifreyi çözüp Rust çekirdeğine geri yükler.
 *
 * Diskte SADECE KeystoreCrypto.encrypt çıktısı (AES-256-GCM ciphertext,
 * Android Keystore/StrongBox'ta tutulan bir anahtarla) bulunur — hiçbir
 * zaman plaintext secret key diske yazılmaz. Bu dosyayı başka bir uygulama
 * (root olmadan) okuyamaz; root ile okunsa bile Keystore anahtarı olmadan
 * (ki o anahtar donanım güvenlik modülünde tutulur ve dışarı çıkarılamaz)
 * içerik anlamsız ciphertext'tir.
 */
object IdentityManager {
    private const val SECRET_BUNDLE_FILENAME = "identity_secret.enc"

    private fun secretBundleFile(context: Context): File =
        File(context.filesDir, SECRET_BUNDLE_FILENAME)

    /**
     * Uygulama açılışında çağrılır (initDatabase sonrası). DB'de bir
     * identity varsa ama Rust'ın belleğinde secret key henüz yoksa
     * (`hasStoredIdentity() == true` ama ratchet/imza işlemleri henüz
     * mümkün değil), şifreli bundle'ı diskten okuyup çözer ve Rust'a
     * yükler. Dosya yoksa veya bozuksa false döner (identity_secret.enc
     * kaybolmuş/bozulmuş demektir — kurtarma dosyasından geri yükleme
     * gerekir, spec 1.8).
     */
    fun loadIfPresent(context: Context): Boolean {
        val file = secretBundleFile(context)
        if (!file.exists()) return false

        val encrypted = try {
            file.readBytes()
        } catch (e: Exception) {
            return false
        }

        val plaintext = try {
            KeystoreCrypto.decrypt(encrypted)
        } catch (e: Exception) {
            // Keystore anahtarı kayıp/bozuk olabilir (ör. factory reset
            // sonrası Keystore temizlendi ama dosya kaldıysa) — bu durumda
            // kurtarma dosyasından geri yükleme gerekir.
            return false
        }

        return try {
            P2PLib.loadSecretBundle(plaintext)
        } finally {
            plaintext.fill(0) // bellekte iz bırakmamak için sıfırla
        }
    }

    /**
     * createIdentity() çağrısından HEMEN SONRA çağrılmalıdır: Rust'ın
     * ürettiği plaintext secret bundle'ı alır, Keystore ile şifreler,
     * diske yazar.
     */
    fun persistNewIdentity(context: Context) {
        val plaintext = P2PLib.getPendingSecretBundle()
        if (plaintext.isEmpty()) return
        try {
            val encrypted = KeystoreCrypto.encrypt(plaintext)
            secretBundleFile(context).writeBytes(encrypted)
        } finally {
            plaintext.fill(0)
        }
    }
}
