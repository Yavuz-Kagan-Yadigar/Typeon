package com.p2p.messenger.util

import android.content.Context

/**
 * Spec dışı, kullanıcı isteği: "bildirimlerde mesajları göster" anahtarı
 * (Ayarlar). Varsayılan AÇIK — mevcut davranış korunur; kapatıldığında
 * bildirim yalnızca KİMDEN (ve grup mesajıysa hangi grupta) geldiğini
 * gösterir, mesaj METNİ hiç görünmez (bkz. NotificationHelper).
 *
 * Bu, `NotificationHelper`'daki kilit ekranı `publicVersion`
 * redaksiyonundan FARKLI ve ondan bağımsız bir katman: o yalnızca cihaz
 * kilitliyken ve sistemin "hassas içeriği gizle" ayarı açıkken devreye
 * girer; bu anahtar ise kilit açıkken de her zaman geçerlidir.
 */
object NotificationPrefs {
    private const val PREFS_NAME = "p2p_settings"
    private const val KEY_SHOW_MESSAGE_TEXT = "notif_show_message_text"

    fun showMessageText(context: Context): Boolean =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_SHOW_MESSAGE_TEXT, true)

    fun setShowMessageText(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_SHOW_MESSAGE_TEXT, enabled)
            .apply()
    }
}
