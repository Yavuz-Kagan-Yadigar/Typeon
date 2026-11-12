package com.p2p.messenger.util

import android.content.Context

/**
 * "bildirimlerde mesajları göster" anahtarı
 * (Ayarlar). Varsayılan KAPALI (#43); kapalıyken
 * bildirim yalnızca "Yeni mesaj" der — ne gönderen ne metin görünür (bkz. NotificationHelper).
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
            .getBoolean(KEY_SHOW_MESSAGE_TEXT, false) // #43: hidden by default

    fun setShowMessageText(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_SHOW_MESSAGE_TEXT, enabled)
            .apply()
    }
}
