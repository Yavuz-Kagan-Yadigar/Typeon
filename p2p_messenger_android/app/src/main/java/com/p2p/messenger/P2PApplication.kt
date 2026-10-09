package com.p2p.messenger

import android.app.Activity
import android.content.Intent
import android.app.Application
import android.content.res.Configuration
import android.os.Bundle
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.google.android.material.color.DynamicColors
import com.p2p.messenger.service.P2PRetryWorker
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.ThemePrefs
import java.util.concurrent.TimeUnit

class P2PApplication : Application() {
    /**
     * Spec dışı, kullanıcı isteği: uygulama ön plana geldiğinde (arka
     * planda bekletildikten SONRA yeniden açıldığında — herhangi bir
     * Activity'nin sıradan `onResume`'u DEĞİL, ör. ChatActivity açıp
     * kapatmak/döndürmek bunu TETİKLEMEMELİ) bekleyen tüm mesajları HEMEN
     * yeniden dener (bkz. `P2PLib.retryAllPendingNow`). Android'in bunun
     * için standart aracı `androidx.lifecycle:lifecycle-process`
     * (`ProcessLifecycleOwner`) — ama bu proje o bağımlılığı henüz
     * içermiyor ve yeni bir bağımlılık eklemek gradle senkronu
     * gerektirir (build doğrulanamıyor). Bunun yerine `ProcessLifecycleOwner`'ın
     * kendi iç mantığıyla AYNI, bağımlılıksız desen: "başlamış" (started,
     * `onStart`..`onStop` arası) Activity sayacı — sıfırdan bire çıkış
     * "uygulama ön plana geldi" anıdır (birden çok Activity arasında
     * geçiş sırasında sayaç asla 0'a inmez, bu yüzden ekran değiştirmek
     * yanlışlıkla tetiklemez).
     */
    private var startedActivityCount = 0

    override fun onCreate() {
        super.onCreate()
        registerReceiver(object : android.content.BroadcastReceiver() {
            override fun onReceive(c: android.content.Context?, i: Intent?) = AppLock.lockNow()
        }, android.content.IntentFilter(Intent.ACTION_SCREEN_OFF))

        // Spec dışı, kullanıcı isteği ("break material, doesn't matter,
        // force font on all UI"): Android'in kendi varsayılan Typeface
        // statik alanlarını değiştirir — bkz. `FontOverride` dokümantasyonu.
        // BURADA, ilk Activity oluşturulmadan ÖNCE (Application.onCreate,
        // her zaman en erken çalışan hook) uygulanmalı ki İLK ekran bile
        // eski fontla bir an için çizilip sonra değişmesin. Kullanıcı
        // Ayarlar'dan font değiştirdiğinde `SettingsFragment` bunu AYRICA
        // (hemen, `recreate()`'ten önce) çağırır — bkz. o çağrı noktası.
        val initialFontChoice = com.p2p.messenger.util.ThemePrefs.getFontChoice(this)
        if (initialFontChoice == com.p2p.messenger.util.ThemePrefs.FontChoice.CUSTOM) {
            // bkz. `ThemePrefs.activeCustomFontFile` — birden fazla içe
            // aktarılmış font arasından o an SEÇİLİ olanın dosyası; kayıt
            // bozulmuşsa (null) sessizce hiçbir şey uygulanmaz.
            com.p2p.messenger.util.ThemePrefs.activeCustomFontFile(this)?.let {
                com.p2p.messenger.util.FontOverride.applyFile(it)
            }
        } else {
            com.p2p.messenger.util.FontOverride.apply(initialFontChoice.familyName)
        }

        // Spec dışı, kullanıcı isteği: gönderilemeyen mesajlar/emirler
        // (Edit/Delete/GroupUpdate — bkz. lib.rs `pending_durable_retries`)
        // arka planda da saatte bir denensin. `KEEP`: uygulama her
        // başlatıldığında yeniden enqueue edilse bile MEVCUT programı
        // (ve bir sonraki çalışma zamanını) bozmaz — sadece hiç
        // programlanmamışsa yenisini oluşturur. `NetworkType.CONNECTED`
        // kısıtı: hiç bağlantı yokken servisi boşuna uyandırmaz (bkz.
        // P2PRetryWorker dokümantasyonu — asıl iş zaten P2PService'in
        // sürekli çalışan döngüsünde, bu sadece "ölmüşse yeniden başlat"
        // yedek mekanizması).
        val retryWork = PeriodicWorkRequestBuilder<P2PRetryWorker>(1, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    // Spec dışı, pil sağlamlığı düzeltmesi: bu, "ölmüşse
                    // yeniden başlat" yedek mekanizması — asıl teslimat
                    // P2PService'in kendi sürekli döngüsünde. Pil kritik
                    // seviyedeyken bu saatlik yedek taramayı ertelemenin
                    // güvenilirlik bedeli yok (WorkManager pil normale
                    // dönünce zaten çalıştırır), ama sistemin en çok
                    // tasarruf etmeye çalıştığı anda bir uyanma daha az.
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "p2p_pending_retry_sweep",
            ExistingPeriodicWorkPolicy.KEEP,
            retryWork
        )

        // Material You: cihazın duvar kağıdından türetilen dinamik renkler
        // (Android 12+). Desteklenmeyen cihazlarda no-op'tur — otomatik
        // olarak themes.xml'deki statik M3 paletine düşülür.
        // ThemePrefs.applyAccentColor uygular (Material You anahtarına bağlı).

        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityPreCreated(activity: Activity, savedInstanceState: Bundle?) {
                // Spec dışı, kullanıcı isteği: Ayarlar'daki vurgu (accent)
                // rengi — bkz. ThemePrefs.applyAccentColor dokümantasyonu.
                ThemePrefs.applyAccentColor(activity)
                // Spec dışı, kullanıcı isteği: Ayarlar'daki metin/arayüz
                // boyutu kaydırıcıları — bkz. ThemePrefs dokümantasyonu.
                applyScalePreferences(activity)
                // Spec dışı, kullanıcı isteği: Ayarlar'daki sistem fontu
                // seçici combobox'ı — bkz. ThemePrefs.FontChoice/themes.xml
                // `appFontFamily` notu. Yukarıdakilerle SIRA ÖNEMLİ DEĞİL
                // (hepsi ayrık özniteliklere dokunuyor).
                val fontChoice = ThemePrefs.getFontChoice(activity)
                if (fontChoice.overlayStyleRes != 0) {
                    activity.theme.applyStyle(fontChoice.overlayStyleRes, true)
                }
                // Spec dışı, hata düzeltmesi ("uygulamadan gir çık yapınca
                // ya da ekran değiştirince metin tipi varsayılana dönüyor"):
                // `FontOverride` süreç genelindeki `Typeface` statiklerini
                // değiştirir ve BU, `Application.onCreate`'te TEK SEFER
                // yapılıyordu. Belgelenmemiş bir teknik olduğundan bu
                // statikler bazı ROM'larda/konfigürasyon değişimlerinde
                // yeniden kurulabiliyor ve o andan sonra açılan ekranlar
                // varsayılan fontla çiziliyordu. Burada HER Activity
                // oluşturulmadan hemen önce (yani ekran değiştirmede de,
                // süreç yeniden başlatmada da) yeniden uygulanıyor —
                // idempotent ve çok ucuz (yalnızca birkaç reflection
                // `Field.set`). Asıl kalıcı çözüm tema tarafında
                // (`android:textViewStyle`, bkz. themes.xml); bu, o
                // özniteliği hiç okumayan görünümler için yedek katman.
                //
                // SIRA ÖNEMLİ: `applyScalePreferences` yukarıda
                // `Resources.updateConfiguration` çağırdıktan SONRA
                // gelmeli.
                if (fontChoice == com.p2p.messenger.util.ThemePrefs.FontChoice.CUSTOM) {
                    com.p2p.messenger.util.ThemePrefs.activeCustomFontFile(activity)?.let {
                        com.p2p.messenger.util.FontOverride.applyFile(it)
                    }
                } else {
                    com.p2p.messenger.util.FontOverride.apply(fontChoice.familyName)
                }
            }

            /**
             * Spec dışı, kullanıcı isteği: Ayarlar'daki "Metin boyutu"/
             * "Arayüz boyutu" kaydırıcıları — sistemin ERİŞİLEBİLİRLİK
             * ayarlarının (Configuration.fontScale/densityDpi) ÜZERİNE,
             * uygulamaya özel bir ek çarpan olarak bindirilir (sistem
             * tercihini SIFIRLAMAZ, ondan başlayıp ölçekler).
             *
             * `Activity.applyOverrideConfiguration` burada KULLANILAMAZ —
             * `Activity.attach()` (dolayısıyla `mWindow`) bu callback'ten
             * ÖNCE zaten kurulduğundan `IllegalStateException` fırlatır (o
             * API sadece `attachBaseContext()` içinden çağrılabilir, ki bu
             * uygulama HER Activity'ye ayrı bir taban sınıf eklemeden bunu
             * yapamaz). Bunun yerine, daha eski ama bu tam senaryoda hâlâ
             * işlevsel olan `Resources.updateConfiguration` kullanılıyor —
             * Activity'nin KENDİ `Resources`'ını, henüz `onCreate`/
             * `setContentView` (dolayısıyla ilk düzen şişirmesi) ÇALIŞMADAN
             * ÖNCE (bu callback tam bunun için doğru an) günceller.
             */
            private fun applyScalePreferences(activity: Activity) {
                val res = activity.resources
                val textScale = ThemePrefs.getTextScale(activity)
                val uiScale = ThemePrefs.getUiScale(activity)
                val system = android.content.res.Resources.getSystem()
                val atDefault = textScale == ThemePrefs.TEXT_SCALE_DEFAULT && uiScale == ThemePrefs.UI_SCALE_DEFAULT
                if (atDefault && res.configuration.fontScale == system.configuration.fontScale &&
                    res.configuration.densityDpi == system.displayMetrics.densityDpi) {
                    return
                }
                val config = Configuration(res.configuration)
                // At default after a non-default value: the shared Resources
                // were changed for good and stayed scaled until a restart.
                config.fontScale = if (atDefault) system.configuration.fontScale else textScale
                val metrics = res.displayMetrics
                // Spec dışı, hata düzeltmesi ("hangi kaydırıcıyı hareket
                // ettirirsem ettireyim aynı şeyi yapıyor, birbirini
                // etkiliyor"): `activity.resources` çoğu durumda süreç
                // genelinde PAYLAŞILAN tek bir Resources örneğidir —
                // `res.updateConfiguration(...)` çağrısı onu KALICI olarak
                // mutasyona uğratır. Taban değer buradan (`metrics.densityDpi`)
                // okunursa, HER Activity yeniden oluşturmasında (font
                // değişimi/accent-arka plan rengi/ui_scale farketmeksizin
                // TÜMÜ `recreate()` çağırır) o an zaten ÖNCEKİ çağrıdan ölçeklenmiş
                // yoğunluk tekrar `uiScale` ile çarpılır — katlanarak büyür/
                // küçülür, bu yüzden HANGİ kaydırıcı hareket ettirilirse
                // ettirilsin aynı (kümülatif) görsel etki ortaya çıkar.
                // `Resources.getSystem()` ise cihazın hiç dokunulmamış
                // SİSTEM varsayılanını verir — sabit bir taban.
                val baseDensityDpi = android.content.res.Resources.getSystem().displayMetrics.densityDpi
                val newDensityDpi = (baseDensityDpi * uiScale).toInt()
                config.densityDpi = newDensityDpi
                @Suppress("DEPRECATION")
                res.updateConfiguration(config, metrics)
            }

            /**
             * Runs inside `super.onCreate()`, before the activity's own
             * `onCreate` body. After process death Android recreates the top
             * activity directly: a chat screen came up on a core that had
             * never opened its database (empty history, sends fail, no
             * service start) until the user went back to MainActivity.
             */
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                if (P2PLib.hasStoredIdentity()) return
                try {
                    P2PLib.initDatabase(filesDir.absolutePath)
                    if (P2PLib.hasStoredIdentity()) {
                        com.p2p.messenger.util.IdentityManager.loadIfPresent(this@P2PApplication)
                        com.p2p.messenger.util.MessageHistoryManager.ensureHistoryKeyLoaded(this@P2PApplication)
                    }
                } catch (e: Exception) {
                    android.util.Log.w("P2PApplication", "Core init failed: ${e.message}")
                }
            }

            override fun onActivityStarted(activity: Activity) {
                // Spec dışı, kullanıcı isteği: uygulamayı açmak için şifre.
                // Kilit ekranı HER Activity başlangıcında kontrol edilir
                // (sadece MainActivity'de değil) — bir bildirimden doğrudan
                // ChatActivity'ye girmek de kilidi atlamamalı. bkz.
                // `AppLock` / `AppLockActivity`.
                AppLock.guard(activity)
                // bkz. `startedActivityCount` dokümantasyonu.
                if (startedActivityCount == 0) {
                    if (P2PLib.hasStoredIdentity()) {
                        // Ana thread'i JNI çağrısıyla meşgul etmemek için
                        // (bkz. genel JNI-ana-thread hijyeni bu projede) —
                        // `retry_all_pending_now` kendisi hafif olsa da
                        // (sadece bir HashMap üzerinde zaman damgası
                        // günceller, ağ I/O'su YAPMAZ) tutarlılık için.
                        Thread { P2PLib.retryAllPendingNow() }.start()
                        // Servis yalnızca MainActivity.onResume'dan başlıyordu: sistem
                        // servisi durdurduktan sonra kullanıcı doğrudan ChatActivity'ye
                        // dönerse (görev geri yükleme/bildirim) mesaj alımı hiç
                        // yeniden başlamıyordu. Startın idempotent (bkz. onStartCommand).
                        try {
                            androidx.core.content.ContextCompat.startForegroundService(
                                this@P2PApplication,
                                Intent(this@P2PApplication, com.p2p.messenger.service.P2PService::class.java)
                            )
                        } catch (e: Exception) {
                            android.util.Log.w("P2PApplication", "Servis başlatılamadı: ${e.message}")
                        }
                    }
                }
                startedActivityCount++
                com.p2p.messenger.service.P2PService.setAppVisible(true)
            }

            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}

            override fun onActivityStopped(activity: Activity) {
                startedActivityCount = (startedActivityCount - 1).coerceAtLeast(0)
                // Uygulama TAMAMEN arka plana düştü (ekranlar arası geçişte
                // sayaç 0'a inmez, bkz. `startedActivityCount`) — bir
                // sonraki dönüşte şifre yeniden sorulsun.
                // `isChangingConfigurations`: `recreate()` (ölçek, yazı tipi,
                // dil, renk/tema ayarları) ve döndürme Activity'yi durdurup
                // yeniden başlatıyor — sayaç o anda 0'a iniyor ama uygulama
                // arka plana DÜŞMEDİ; önceden her görünüm değişikliği şifre
                // soruyordu.
                if (startedActivityCount == 0 && !activity.isChangingConfigurations) {
                    AppLock.lock()
                    com.p2p.messenger.service.P2PService.setAppVisible(false)
                }
            }
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }
}
