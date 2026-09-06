package com.p2p.messenger.util

import android.content.Context
import java.io.File

/**
 * Bu cihazdaki TÜM kimlik/mesaj verisini siler — "çıkış yap" (Ayarlar) ve
 * uzaktan iptal (`self_revoked`, bkz. `P2PService.maybeNotify`) için TEK
 * ortak yol.
 *
 * **Neden tek bir yerde:** bu denetimde bulundu — iki çağıran da (Ayarlar'ın
 * `performLogout`'u ve `self_revoked` kolu) AYNI beş satırı kopyalamıştı ve
 * ikisi de aynı üç dosyayı ATLIYORDU:
 *
 * - `history_key.enc` — yerel SQLite mesaj arşivini çözer
 *   ([MessageHistoryManager]).
 * - `skipped_key_enc.enc` — kalıcı ratchet skipped-key tablosunu, sarmalı
 *   dosya anahtarlarını ve sunucu arşiv kuyruğunu çözer
 *   ([SkippedKeyManager]).
 * - `archive_root_key.enc` — kök arşiv anahtarı (ARK), yani SUNUCUDA duran
 *   geçmişin tamamını çözen anahtar ([ArchiveKeyManager]).
 *
 * Bunların arkada kalması iki ayrı sorun üretiyordu:
 *
 * 1. **Güvenlik.** `self_revoked` yolunun VAR OLMA SEBEBİ "telefonum
 *    çalındı, birincil cihazdan iptal ediyorum". O yol çalıştıktan sonra
 *    cihazda hâlâ ARK duruyordu — ve sunucudaki arşiv silinmiyor, 30 gün
 *    daha orada bekliyor. Dosyalar Keystore ile sarılı, yani anahtarın
 *    kendisi çıkarılamaz; ama silmemenin bir gerekçesi de yok, ve
 *    Linux istemcisi bunu ZATEN doğru yapıyor (`confirm_logout`
 *    `remove_dir_all(data_dir)` + `keyring::delete_key`).
 * 2. **Doğruluk.** Çıkıştan sonra kurulan YENİ kimlik, açılışta
 *    `ArchiveKeyManager.loadIfPresent`/`MessageHistoryManager` üzerinden
 *    ESKİ kimliğin anahtarlarını devralıyordu. ARK kimliğe ait ve kardeş
 *    cihazlara senkronlanıyor — yani yeni kimlik, kardeşlerinin hiç
 *    bilmediği bir ARK'la sunucuya arşiv yükleyebilir, ya da kurtarma
 *    dosyasından gelen doğru ARK'la çakışabilirdi.
 *
 * Görünüm/tema tercihleri (`ThemePrefs`, duvarkağıdı) KASITLI olarak
 * bırakılıyor: kimliğe değil cihaza ait, silinmeleri kullanıcı için bir
 * kazanç değil bir kayıp olurdu. Buna karşılık sohbet başına METADATA
 * (`chat_read_state`, `pinned_chats` — anahtarları karşı tarafın cihaz
 * fingerprint'i / grup kimliği) siliniyor: bunlar doğrudan "kiminle
 * yazıştın" bilgisi ve silinen bir kimlikten arta kalmamalı.
 *
 * Çağıran bundan sonra [AppRestarter.restart] çağırmalı — Rust çekirdeği
 * canlı süreçte kimliği güvenle "unutamaz", temiz bir süreçte açılış
 * `hasStoredIdentity() == false` görüp onboarding'e düşer.
 */
object LocalWipe {

    /** Kimliğe ait, Keystore ile sarılmış anahtar dosyaları. */
    private val SECRET_FILES = listOf(
        "identity_secret.enc",
        "history_key.enc",
        "skipped_key_enc.enc",
        "archive_root_key.enc",
    )

    private val DB_FILES = listOf(
        "p2p_messenger.db",
        "p2p_messenger.db-wal",
        "p2p_messenger.db-shm",
    )

    /** Sohbet başına metadata tutan, kimlikle birlikte gitmesi gereken
     *  SharedPreferences dosyaları. `p2p_settings` KASITLI olarak yok —
     *  tema/bildirim/uygulama kilidi gibi cihaza ait tercihleri tutuyor. */
    private val CONVERSATION_PREFS = listOf("chat_read_state", "pinned_chats")

    fun wipe(context: Context) {
        val filesDir = context.applicationContext.filesDir
        for (name in DB_FILES) File(filesDir, name).delete()
        for (name in SECRET_FILES) File(filesDir, name).delete()
        File(filesDir, "attachments").deleteRecursively()
        for (name in CONVERSATION_PREFS) {
            context.applicationContext
                .getSharedPreferences(name, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .apply()
        }
    }
}
