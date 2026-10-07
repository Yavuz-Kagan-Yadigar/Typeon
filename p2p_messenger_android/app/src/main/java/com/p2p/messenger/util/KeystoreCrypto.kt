package com.p2p.messenger.util

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Yerel identity/device secret key'lerini diskte şifreli tutmak için
 * kullanılan zarf şifreleme (envelope encryption) katmanı.
 *
 * Android Keystore'da (mümkünse StrongBox donanımında) bir AES-256 anahtarı
 * üretilir ve tutulur — bu anahtar HİÇBİR ZAMAN dışarı çıkmaz, sadece
 * Cipher nesnesi Keystore içinde çalıştırılır. Rust/JNI tarafına asla
 * Keystore anahtarının kendisi geçirilmez; sadece bu anahtarla
 * şifrelenmiş/çözülmüş VERİ (identity secret key'leri) geçirilir.
 *
 * NOT: Post-quantum (Kyber, Dilithium) ve X25519/Ed25519 anahtarları
 * Android Keystore'un desteklediği algoritmalar DEĞİL (Keystore sadece
 * EC/RSA/AES destekler), bu yüzden bu anahtarların kendisini doğrudan
 * Keystore'da üretip işlemleri orada yaptırmak mümkün değil. Bunun yerine
 * "envelope encryption" kullanılır: gerçek secret key'ler Rust tarafında
 * normal şekilde üretilir, ama diske yazılmadan önce bu AES anahtarıyla
 * şifrelenir. Diskte hiçbir zaman çıplak secret key bulunmaz; sadece bu
 * AES anahtarının şifrelediği ciphertext bulunur.
 */
/**
 * Yerel identity/device secret key'lerini VE mesaj geçmişi arşivini
 * diskte şifreli tutmak için kullanılan zarf şifreleme (envelope
 * encryption) katmanı.
 *
 * Android Keystore'da (mümkünse StrongBox donanımında) bir AES-256 anahtarı
 * üretilir ve tutulur — bu anahtar HİÇBİR ZAMAN dışarı çıkmaz, sadece
 * Cipher nesnesi Keystore içinde çalıştırılır. Rust/JNI tarafına asla
 * Keystore anahtarının kendisi geçirilmez; sadece bu anahtarla
 * şifrelenmiş/çözülmüş VERİ (identity secret key'leri, mesaj geçmişi
 * anahtarı) geçirilir.
 *
 * NOT: Post-quantum (Kyber, Dilithium) ve X25519/Ed25519 anahtarları
 * Android Keystore'un desteklediği algoritmalar DEĞİL (Keystore sadece
 * EC/RSA/AES destekler), bu yüzden bu anahtarların kendisini doğrudan
 * Keystore'da üretip işlemleri orada yaptırmak mümkün değil. Bunun yerine
 * "envelope encryption" kullanılır: gerçek secret key'ler Rust tarafında
 * normal şekilde üretilir, ama diske yazılmadan önce bu AES anahtarıyla
 * şifrelenir. Diskte hiçbir zaman çıplak secret key bulunmaz; sadece bu
 * AES anahtarının şifrelediği ciphertext bulunur.
 */
object KeystoreCrypto {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    /** Identity secret key bundle'ını sarmalayan anahtarın alias'ı. */
    const val ALIAS_IDENTITY = "p2p_messenger_master_key"
    /** Mesaj geçmişi arşiv anahtarını sarmalayan anahtarın alias'ı — ayrı
     *  tutulmasının nedeni: ileride birini iptal edip diğerini
     *  etkilememek (ör. "tüm geçmişi sil" ayrı bir anahtar rotasyonuyla
     *  yapılabilir, identity'yi etkilemeden). */
    const val ALIAS_HISTORY = "p2p_messenger_history_wrap_key"
    /** Skipped-message-key önbelleğini (Double Ratchet'in sıra dışı/
     *  gecikmeli mesaj desteği) sarmalayan anahtarın alias'ı. Bu, node
     *  modundan BAĞIMSIZ her zaman kullanılır — mesaj geçmişi arşivinin
     *  aksine, bu cache mesajlaşmanın güvenilirliği için gerekli (node
     *  modu kapalıyken de sıra dışı mesajlar çözülebilmeli). */
    const val ALIAS_SKIPPED_KEYS = "p2p_messenger_skipped_keys_wrap_key"
    /** Kök arşiv anahtarını (ARK) sarmalayan anahtarın alias'ı — sunucuda
     *  saklanan geçmişi çözer (bkz. ArchiveKeyManager).
     *
     *  ALIAS_HISTORY'den AYRI olmasının nedeni ikisinin KAPSAMLARININ
     *  farklı olması: history key CİHAZA ait, rastgele, kurtarma dosyasında
     *  YOK — sadece yerel arşivi diskte şifreler. ARK ise KİMLİĞE ait,
     *  kardeş cihazlara `DeviceSync` ile gider ve kurtarma dosyasına da
     *  girer. Aynı alias altında tutulsalardı "yerel geçmişi sıfırla"
     *  eylemi sunucudaki arşivi de okunamaz hale getirirdi. */
    const val ALIAS_ARCHIVE_ROOT = "p2p_messenger_archive_root_wrap_key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH_BITS = 128

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    }

    /** Verilen alias için Keystore anahtarını döner, yoksa üretir
     *  (StrongBox varsa onda, yoksa TEE'de). */
    @Synchronized
    private fun getOrCreateKey(alias: String): SecretKey {
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val baseSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)

        // Önce StrongBox'ta (ayrı güvenlik çipi) denenir — daha güçlü
        // izolasyon. `setIsStrongBoxBacked` API 28'de eklendi; bu
        // uygulamanın minSdk'ı 26 olduğu için önce API seviyesini kontrol
        // ediyoruz (aksi halde API 26/27'de NoSuchMethodError riski var).
        // Cihaz/Android sürümü desteklemiyorsa TEE'ye (Trusted Execution
        // Environment) düşülür; ikisi de "diğer uygulamaların okuyamayacağı"
        // garantisini sağlar, StrongBox ekstra donanım izolasyonu ekler.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            try {
                keyGenerator.init(baseSpec.setIsStrongBoxBacked(true).build())
                return keyGenerator.generateKey()
            } catch (e: StrongBoxUnavailableException) {
                // Aşağıdaki TEE fallback'ine düş.
            } catch (e: Exception) {
                // Bazı OEM'lerde StrongBox flag'i farklı istisnalarla
                // başarısız olabiliyor; güvenli tarafta kalıp TEE'ye
                // düşüyoruz.
            }
        }
        // API 28+ only, like the call above: on 8.0/8.1 this method does not
        // exist and the first launch died with NoSuchMethodError.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            baseSpec.setIsStrongBoxBacked(false)
        }
        keyGenerator.init(baseSpec.build())
        return keyGenerator.generateKey()
    }

    /**
     * Veriyi belirtilen Keystore anahtarıyla şifreler. Dönen bayt dizisi
     * `[12 byte IV][ciphertext+tag]` biçimindedir — dosyaya/BLOB olarak
     * olduğu gibi yazılabilir.
     */
    fun encrypt(plaintext: ByteArray, alias: String = ALIAS_IDENTITY): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(alias))
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        return iv + ciphertext
    }

    /** `encrypt`'in ürettiği `[iv][ciphertext+tag]` formatını çözer. */
    fun decrypt(ivAndCiphertext: ByteArray, alias: String = ALIAS_IDENTITY): ByteArray {
        require(ivAndCiphertext.size > 12) { "Encrypted blob too short" }
        val iv = ivAndCiphertext.copyOfRange(0, 12)
        val ciphertext = ivAndCiphertext.copyOfRange(12, ivAndCiphertext.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // Never create here: a missing alias must fail, not be replaced by a
        // fresh key that cannot open anything written before.
        val key = keyStore.getKey(alias, null) as? SecretKey
            ?: throw java.security.KeyStoreException("Keystore key missing: $alias")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    /** Bu cihazda anahtarın gerçekten donanım içinde tutulup tutulmadığını
     *  bildirir — teşhis/ayarlar ekranında gösterilebilir. */
    fun isHardwareBacked(alias: String = ALIAS_IDENTITY): Boolean {
        return try {
            val key = keyStore.getKey(alias, null) as? SecretKey ?: return false
            val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER)
            val keyInfo = factory.getKeySpec(key, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
            keyInfo.isInsideSecureHardware
        } catch (e: Exception) {
            false
        }
    }
}

/** Geçici dosyaya yaz + `rename`: şifreli anahtar dosyaları yazılırken
 *  çökme/güç kesintisi yarım (açılamaz) bir dosya bırakmasın. */
fun java.io.File.writeBytesAtomic(bytes: ByteArray) {
    val tmp = java.io.File(parentFile, "$name.tmp")
    java.io.FileOutputStream(tmp).use { out ->
        out.write(bytes)
        out.fd.sync()
    }
    if (!tmp.renameTo(this)) throw java.io.IOException("rename failed: $tmp")
}
