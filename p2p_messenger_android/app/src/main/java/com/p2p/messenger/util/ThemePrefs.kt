package com.p2p.messenger.util

import android.content.Context
import android.content.res.Configuration

/**
 * Görünüm tercihleri — spec dışı, salt kullanıcı deneyimi tercihi.
 * "OLED siyah": kullanıcı Ayarlar'dan açtığında ve sistem koyu temadayken,
 * yüzey/arkaplan renklerini tam siyaha (#000000) zorlayan bir ThemeOverlay
 * uygulanır (bkz. P2PApplication, ThemeOverlay.P2PMessenger.OledBlack).
 */
object ThemePrefs {
    private const val PREFS_NAME = "p2p_settings"
    private const val KEY_OLED_BLACK = "oled_black_enabled"

    fun isOledBlackEnabled(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getBoolean(KEY_OLED_BLACK, false)
    }

    fun setOledBlackEnabled(context: Context, enabled: Boolean) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putBoolean(KEY_OLED_BLACK, enabled).apply()
    }

    fun isNightModeActive(context: Context): Boolean {
        val mode = context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK
        return mode == Configuration.UI_MODE_NIGHT_YES
    }
}
