package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.P2PLib
import java.io.File
import java.security.SecureRandom

/**
 * Kök arşiv anahtarını (ARK) yönetir — sunucuda saklanan mesaj geçmişini
 * çözen anahtar (bkz. Rust `server_seal::seal_archive_record`).
 *
 * `MessageHistoryManager` ile AYNI Keystore desenini kullanır ama KAPSAMI
 * farklıdır ve bu fark önemli:
 *
 * - `history_key`: **cihaza** ait, rastgele, kurtarma dosyasında YOK.
 *   Sadece yerel SQLite arşivini diskte şifreler. Kaybolursa sadece bu
 *   cihazın yerel geçmişi okunamaz hale gelir.
 * - **ARK** (bu sınıf): **kimliğe** ait. Aynı kimliğin bütün cihazları
 *   sunucudaki arşivi okuyabilmeli, bu yüzden kardeş cihazlara `DeviceSync`
 *   ile taşınır (ratchet-şifreli) ve kurtarma dosyasına da girer. İlk
 *   üreten cihaz "kaynak"tır; sonradan bağlanan cihazlar kendi rastgele
 *   anahtarlarını üretmez, kardeşten geleni benimser (Rust tarafı zaten
 *   var olan bir ARK'ın üzerine yazmaz).
 *
 * Dürüst takas: ARK ileri-gizli DEĞİLDİR. Bir gün sızarsa o ana kadar
 * sunucuya yüklenmiş TÜM geçmiş okunur — ratchet ciphertext'inin aksine,
 * ki o kullanıldıktan sonra çözülemez hale gelir. "Yeni cihazımda geçmişimi
 * göreyim" ile ileri-gizlilik matematiksel olarak uzlaşmaz; bu yüzden
 * sunucuda geçmiş saklama Ayarlar'da AYRI ve VARSAYILAN KAPALI bir
 * seçenektir.
 */
object ArchiveKeyManager {
    private const val ARCHIVE_KEY_FILENAME = "archive_root_key.enc"

    private fun keyFile(context: Context): File =
        File(context.filesDir, ARCHIVE_KEY_FILENAME)

    /**
     * Uygulama açılışında çağrılır. Anahtar varsa çözüp Rust'a yükler.
     *
     * `MessageHistoryManager`den FARKLI olarak burada anahtar yoksa
     * KENDİLİĞİNDEN ÜRETİLMEZ — bkz. `ensureCreated`. Sebep: sonradan
     * bağlanan bir cihaz, kardeşinden ARK'ı almadan önce kendi rastgele
     * anahtarını üretirse, o cihazın yüklediği arşiv diğer cihazlarda
     * okunamaz olurdu. Üretim sadece kullanıcı sunucuda geçmiş saklamayı
     * AÇTIĞINDA yapılır.
     */
    /** Kardeş cihazdan gelen ARK yalnızca çekirdeğin belleğindeydi —
     *  yeniden başlatınca kayboluyordu. Dosya henüz yoksa diske yazar. */
    fun persistIfNew(context: Context) {
        val file = keyFile(context)
        if (file.exists()) return
        val key = try { P2PLib.archiveRootKey() } catch (e: Exception) { return }
        if (key.size != 32) return
        try {
            file.writeBytesAtomic(KeystoreCrypto.encrypt(key, KeystoreCrypto.ALIAS_ARCHIVE_ROOT))
        } catch (e: Exception) {
        } finally {
            key.fill(0)
        }
    }

    fun loadIfPresent(context: Context) {
        val file = keyFile(context)
        if (!file.exists()) return
        val dataKey = try {
            KeystoreCrypto.decrypt(file.readBytes(), KeystoreCrypto.ALIAS_ARCHIVE_ROOT)
        } catch (e: Exception) {
            // Keystore anahtarı kayıp/bozuk. Yenisini ÜRETMİYORUZ: sunucudaki
            // mevcut arşiv o anahtarla şifreli ve yeni bir anahtar onu
            // kurtarmaz, sadece bundan sonrasını böler. Kullanıcı kurtarma
            // dosyasından geri yükleyebilir ya da kardeş bir cihazdan
            // `DeviceSync` ile anahtar tekrar gelir.
            return
        }
        try {
            P2PLib.setArchiveRootKey(dataKey)
        } finally {
            dataKey.fill(0)
        }
    }

    /**
     * Sunucuda geçmiş saklama açılırken çağrılır: anahtar yoksa üretir.
     *
     * Rust tarafı bir kardeş cihazdan ARK aldığında onu bize geri
     * bildirmediği için, burada üretilen anahtar yalnızca "bu kimliğin ilk
     * cihazı" durumunda doğrudur. Kardeşten anahtar gelmiş bir cihazda bu
     * fonksiyon çağrılırsa Rust tarafı zaten var olanın üzerine yazmaz —
     * ama diskteki kopya ayrışır. Bu yüzden çağıran, kullanıcı geçmiş
     * saklamayı açtığında ve SADECE o zaman çağırmalı.
     */
    fun ensureCreated(context: Context) {
        val file = keyFile(context)
        if (file.exists()) {
            loadIfPresent(context)
            return
        }
        // Kardeşten (`DeviceSync`) gelmiş bir ARK bellekte olabilir: onu
        // yaz, yenisini üretip üstüne yazma (arşiv cihazlar arasında bölünürdü).
        val fromCore = try { P2PLib.archiveRootKey() } catch (e: Exception) { ByteArray(0) }
        val dataKey = if (fromCore.size == 32) fromCore else ByteArray(32).also { SecureRandom().nextBytes(it) }
        try {
            file.writeBytesAtomic(KeystoreCrypto.encrypt(dataKey, KeystoreCrypto.ALIAS_ARCHIVE_ROOT))
            P2PLib.setArchiveRootKey(dataKey)
        } catch (e: Exception) {
            // Keystore erişilemiyorsa sessizce vazgeç — sunucu yönlendirmesi
            // (mesaj teslimi) bundan ETKİLENMEZ, sadece geçmiş yüklenmez.
        } finally {
            dataKey.fill(0)
        }
    }
}
