package com.p2p.messenger.util

import android.content.Context

/**
 * The "show messages in notifications" switch (Settings). OFF by default. When it is off, a notification says only "New message". It shows neither the sender
 * nor the text. See NotificationHelper.
 *
 * This is a DIFFERENT layer from the lock-screen `publicVersion` redaction in NotificationHelper, and it is independent of it. That one applies only while the
 * device is locked and the system "hide sensitive content" setting is on. This switch always applies, even when the device is unlocked.
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
