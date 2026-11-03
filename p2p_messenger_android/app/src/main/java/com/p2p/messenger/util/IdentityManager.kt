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

    /**
     * Bundle YÜKLEME bir kez yapılır: `P2PApplication` (Activity oluşturulurken)
     * ve `MainActivity` her soğuk başlangıçta aynı şeyi istiyor — her istek
     * dosyayı yeniden okuyup Keystore'da yeniden çözüyor ve Rust'a yeniden
     * yüklüyordu (süreç başlangıcının ANR'ye en duyarlı penceresinde).
     * Yalnızca BAŞARILI yükleme hatırlanır: başarısız olan yeniden
     * denenebilir kalmalı (kurtarma dosyası akışı).
     */
    @Volatile
    private var loaded = false

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
     *
     * Sonuç SÜREÇ BOYUNCA hatırlanır: aynı bundle'ı ikinci kez yüklemek
     * (Keystore çözme + dosya okuma + `loadSecretBundle`) gereksiz.
     */
    @Synchronized
    fun loadIfPresent(context: Context): Boolean {
        if (loaded) return true
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

        val ok = try {
            P2PLib.loadSecretBundle(plaintext)
        } finally {
            plaintext.fill(0) // bellekte iz bırakmamak için sıfırla
        }
        if (ok) loaded = true
        return ok
    }

    /**
     * createIdentity() çağrısından HEMEN SONRA çağrılmalıdır: Rust'ın
     * ürettiği plaintext secret bundle'ı alır, Keystore ile şifreler,
     * diske yazar.
     *
     * DÖNÜŞ: `true` = bundle diske yazıldı, `false` = YAZILAMADI (çekirdekte
     * bekleyen bundle yoktu). Çağıran, `false` aldığında "kimlik oluşturuldu"
     * diye devam etmemeli: secret key'ler diskte olmadığı için bir sonraki
     * açılışta o kimlik yüklenemez.
     */
    fun persistNewIdentity(context: Context): Boolean {
        val plaintext = P2PLib.getPendingSecretBundle()
        if (plaintext.isEmpty()) return false
        try {
            val encrypted = KeystoreCrypto.encrypt(plaintext)
            secretBundleFile(context).writeBytesAtomic(encrypted)
        } catch (e: Exception) {
            // Keystore or disk failure: "not written", as documented.
            return false
        } finally {
            plaintext.fill(0)
        }
        return true
    }
}
