package com.p2p.messenger

import android.app.Activity
import android.app.Application
import android.os.Bundle
import com.google.android.material.color.DynamicColors
import com.p2p.messenger.util.ThemePrefs

class P2PApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // Material You: cihazın duvar kağıdından türetilen dinamik renkler
        // (Android 12+). Desteklenmeyen cihazlarda no-op'tur — otomatik
        // olarak themes.xml'deki statik M3 paletine düşülür.
        DynamicColors.applyToActivitiesIfAvailable(this)

        // OLED "tam siyah" tercihi: kullanıcı Ayarlar'dan açtıysa VE sistem
        // koyu temadaysa, her Activity oluşturulmadan hemen önce yüzey/
        // arkaplan renklerini zorlayan bir ThemeOverlay uygula. Bu callback
        // DynamicColors'ınkinden SONRA kayıt olur (callback'ler kayıt
        // sırasına göre çalışır) — böylece OLED overlay, dinamik renklerin
        // üzerine binip her zaman kazanır.
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityPreCreated(activity: Activity, savedInstanceState: Bundle?) {
                if (ThemePrefs.isOledBlackEnabled(activity) && ThemePrefs.isNightModeActive(activity)) {
                    activity.theme.applyStyle(R.style.ThemeOverlay_P2PMessenger_OledBlack, true)
                }
            }

            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityStarted(activity: Activity) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }
}
