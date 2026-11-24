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
     * Runs when the app comes back to the foreground after being stopped. Ordinary `onResume` of an
     * activity does NOT trigger it (opening and closing a chat screen, or rotating, must not). It retries
     * all pending messages at once (see `P2PLib.retryAllPendingNow`). The standard tool is
     * `ProcessLifecycleOwner` from androidx.lifecycle:lifecycle-process, but this project does not depend
     * on it. Adding a dependency needs a Gradle sync. So the same logic is done without it: a count of
     * started activities (between `onStart` and `onStop`). Going from 0 to 1 is the "came to the foreground"
     * moment. Moving between activities never drops the count to 0, so switching screens does not trigger it.
     */
    private var startedActivityCount = 0
    /** The last screen stopped only for a recreate (rotation, theme): its restart is no return from the background. */
    private var recreating = false
    /** Set once the core reported a stored identity. Later checks skip the core mutex on the main thread. */
    @Volatile private var identityKnown = false

    companion object {
        /** FLAG_SECURE on release builds only. Debuggable builds stay capturable, for adb screenshots. */
        fun setSecure(activity: Activity, on: Boolean) {
            if ((activity.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) return
            if (on) activity.window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            else activity.window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    override fun onCreate() {
        super.onCreate()
        // A logout / account delete / revoke left the marker: wipe again before anything opens a file.
        com.p2p.messenger.util.LocalWipe.finishPending(this)
        // Plaintext left behind by a killed process: a recording or an outgoing copy that was never sent.
        // It runs on this thread before any activity starts. A background delete could otherwise remove a file
        // that a cold-start share or a recording has just written there.
        java.io.File(cacheDir, "voice").deleteRecursively()
        java.io.File(cacheDir, "outgoing").deleteRecursively()
        java.io.File(cacheDir, "attachment_edit").deleteRecursively()
        java.io.File(cacheDir, "attachment_preview").deleteRecursively()
        java.io.File(cacheDir, "avatar_view").deleteRecursively()
        java.io.File(cacheDir, "sticker_import").deleteRecursively()
        java.io.File(filesDir, "attachments/plain_cache").listFiles()?.forEach { it.deleteRecursively() }
        androidx.core.content.ContextCompat.registerReceiver(this, object : android.content.BroadcastReceiver() {
            override fun onReceive(c: android.content.Context?, i: Intent?) = AppLock.lockNow(c)
        }, android.content.IntentFilter(Intent.ACTION_SCREEN_OFF), androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED)

        // Forces the app font on all UI. It replaces Android's own default Typeface static fields (see the
        // `FontOverride` docs). It runs HERE, before the first activity is created (Application.onCreate is the
        // earliest hook), so even the first screen does not draw in the old font and then change. When the user
        // changes the font in Settings, SettingsFragment calls this again right away, before `recreate()`.
        val initialFontChoice = com.p2p.messenger.util.ThemePrefs.getFontChoice(this)
        if (initialFontChoice == com.p2p.messenger.util.ThemePrefs.FontChoice.CUSTOM) {
            // The file of the custom font that is SELECTED among the imported ones (see `ThemePrefs.activeCustomFontFile`).
            // If the record is broken (null), nothing is applied, silently.
            com.p2p.messenger.util.ThemePrefs.activeCustomFontFile(this)?.let {
                com.p2p.messenger.util.FontOverride.applyFile(it)
            }
        } else {
            com.p2p.messenger.util.FontOverride.apply(initialFontChoice.familyName)
        }

        // Messages that could not be sent (Edit, Delete, GroupUpdate; see persist.rs `pending_durable_retries`) are also
        // retried in the background, once an hour. `KEEP` means that re-enqueueing on every app start keeps the EXISTING
        // work and its next run time. It creates one only when none is scheduled. The `NetworkType.CONNECTED` constraint
        // means no wake-up without a connection (see P2PRetryWorker). The main delivery is the always-running loop of
        // P2PService. This is only a fallback that restarts the service if it died.
        val retryWork = PeriodicWorkRequestBuilder<P2PRetryWorker>(1, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    // This is the fallback that restarts the service if it died. Main delivery is P2PService's
                    // own always-running loop. Deferring this hourly fallback costs no reliability when the battery is
                    // critical (WorkManager runs it again once the battery is normal). It saves one wake-up when the
                    // system is trying hardest to save power.
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "p2p_pending_retry_sweep",
            ExistingPeriodicWorkPolicy.KEEP,
            retryWork
        )
        com.p2p.messenger.service.SelfUpdate.schedule(this)

        // Wallpaper-derived (dynamic) colours on Android 12 and later are applied per activity by
        // ThemePrefs.applyAccentColor, see onActivityPreCreated. Older devices keep the static palette in themes.xml.

        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityPreCreated(activity: Activity, savedInstanceState: Bundle?) {
                // The Recents card showed the last chat without the app password.
                if (android.os.Build.VERSION.SDK_INT >= 33) activity.setRecentsScreenshotEnabled(false)
                // No recents opt-out before API 33: every screen gets FLAG_SECURE there.
                // Link QR, QR scan, camera and lock screens always do.
                if (activity is com.p2p.messenger.ui.LinkDeviceActivity ||
                    activity is com.p2p.messenger.ui.QrScanActivity ||
                    activity is com.p2p.messenger.ui.CameraCaptureActivity ||
                    activity is com.p2p.messenger.ui.AppLockActivity ||
                    android.os.Build.VERSION.SDK_INT < 33
                ) setSecure(activity, true)
                // The accent colour chosen in Settings. See the ThemePrefs.applyAccentColor docs.
                ThemePrefs.applyAccentColor(activity)
                // The text and interface size sliders in Settings. See the ThemePrefs docs.
                applyScalePreferences(activity)
                // The system font combo box in Settings. See ThemePrefs.FontChoice and the `appFontFamily` note in themes.xml.
                // Order against the lines above does not matter: they all touch separate attributes.
                val fontChoice = ThemePrefs.getFontChoice(activity)
                if (fontChoice.overlayStyleRes != 0) {
                    activity.theme.applyStyle(fontChoice.overlayStyleRes, true)
                }
                // Activities re-apply the font overrides before they are created, because `FontOverride` changes
                // process-wide Typeface statics. Those were set once in Application.onCreate. The override is undocumented,
                // so on some ROMs or configuration changes the statics can be rebuilt. Screens opened after that drew in the
                // default font. Re-applying it here, before every Activity is created (both on a screen change and on a
                // process restart), is idempotent and cheap (a few reflection Field.set calls). The lasting fix is on the
                // theme side (`android:textViewStyle`, see themes.xml). This is the fallback for views that never read that attribute.
                //
                // ORDER MATTERS: this must come AFTER `applyScalePreferences`, which calls `Resources.updateConfiguration`
                // above.
                if (fontChoice == com.p2p.messenger.util.ThemePrefs.FontChoice.CUSTOM) {
                    com.p2p.messenger.util.ThemePrefs.activeCustomFontFile(activity)?.let {
                        com.p2p.messenger.util.FontOverride.applyFile(it)
                    }
                } else {
                    com.p2p.messenger.util.FontOverride.apply(fontChoice.familyName)
                }
            }

            /**
             * The "text size" and "interface size" sliders in Settings. They are applied as an app-only multiplier ON TOP
             * of the system accessibility settings (Configuration.fontScale / densityDpi). The system preference is not reset.
             *
             * `Activity.applyOverrideConfiguration` cannot be used here. `Activity.attach()` (so `mWindow` too) is already
             * set up before this callback, which throws IllegalStateException. That API works only inside
             * `attachBaseContext()`, and this app cannot add that to every Activity without a base class. So
             * `Resources.updateConfiguration` is used instead. It updates the Activity's own Resources before `onCreate`
             * and `setContentView` run (so before the first layout inflation), which is the right moment for this callback.
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
                // Back to the default after a non-default value: the shared Resources were changed for good and stayed scaled
                // until a restart.
                config.fontScale = if (atDefault) system.configuration.fontScale else textScale
                val metrics = res.displayMetrics
                // `activity.resources` is in most cases ONE Resources object shared by the whole process. The
                // `res.updateConfiguration(...)` call changes it permanently. If the base value were read from it
                // (`metrics.densityDpi`), every Activity recreation (font change, accent or background change, ui_scale:
                // all of them call `recreate()`) would multiply the density already scaled by the previous call by
                // `uiScale` again. It would grow or shrink each time, so every slider had the same cumulative effect.
                // `Resources.getSystem()` gives the device's untouched SYSTEM default, which is a fixed base.
                val baseDensityDpi = android.content.res.Resources.getSystem().displayMetrics.densityDpi
                val newDensityDpi = (baseDensityDpi * uiScale).toInt()
                config.densityDpi = newDensityDpi
                @Suppress("DEPRECATION")
                res.updateConfiguration(config, metrics)
            }

            // After the activity's `onCreate`: its views exist. Below Android 12 the text colour is painted onto
            // the views here (`applyTextColorLegacy`); on 12+ the theme carries it (`applyAccentColor`).
            override fun onActivityPostCreated(activity: Activity, savedInstanceState: Bundle?) {
                ThemePrefs.applyTextColorLegacy(activity)
            }

            /**
             * Runs inside `super.onCreate()`, before the activity's own `onCreate` body. After a process death Android
             * recreates the top activity directly. A chat screen could come up on a core that had never opened its
             * database (empty history, sends fail, no service start) until the user went back to MainActivity.
             */
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                // MainActivity opens the core itself, off the main thread.
                if (activity is MainActivity || identityKnown) return
                if (P2PLib.hasStoredIdentity()) {
                    identityKnown = true
                    return
                }
                try {
                    P2PLib.initDatabase(filesDir.absolutePath)
                    if (P2PLib.hasStoredIdentity()) {
                        identityKnown = true
                        com.p2p.messenger.util.IdentityManager.loadIfPresent(this@P2PApplication)
                        com.p2p.messenger.util.MessageHistoryManager.ensureHistoryKeyLoaded(this@P2PApplication)
                    }
                } catch (e: Exception) {
                    com.p2p.messenger.util.Log.w("P2PApplication", "Core init failed: ${e.message}")
                }
            }

            override fun onActivityStarted(activity: Activity) {
                com.p2p.messenger.util.FontOverride.forceOnWindow(activity)
                // The app password. The lock screen is checked at EVERY Activity start, not only in MainActivity. Opening
                // ChatActivity straight from a notification must not skip the lock. See `AppLock` and `AppLockActivity`.
                AppLock.guard(activity)
                // See the `startedActivityCount` docs.
                if (startedActivityCount == 0 && !recreating) {
                    // The check takes the core mutex, which a long poll turn can hold: off the UI thread.
                    Thread {
                        if (identityKnown || P2PLib.hasStoredIdentity()) {
                            identityKnown = true
                            P2PLib.retryAllPendingNow()
                            // The service used to start only from MainActivity.onResume. If the system stopped the service and the
                            // user came straight back into ChatActivity (task restore or a notification), message receipt never
                            // restarted. The start is idempotent (see onStartCommand).
                            try {
                                androidx.core.content.ContextCompat.startForegroundService(
                                    this@P2PApplication,
                                    Intent(this@P2PApplication, com.p2p.messenger.service.P2PService::class.java)
                                )
                            } catch (e: Exception) {
                                com.p2p.messenger.util.Log.w("P2PApplication", "Service could not be started: ${e.message}")
                            }
                        }
                    }.start()
                }
                recreating = false
                startedActivityCount++
                com.p2p.messenger.service.P2PService.setAppVisible(true)
            }

            override fun onActivityResumed(activity: Activity) {
                AppLock.excursionResumed()
                // `AppLock.guard` may hide the content under the prompt. It is shown again here, on resume, once unlocked.
                // A screen that was never stopped under the prompt gets only this call.
                if (AppLock.isUnlocked()) {
                    activity.findViewById<android.view.View>(android.R.id.content)?.visibility = android.view.View.VISIBLE
                }
            }
            override fun onActivityPaused(activity: Activity) = AppLock.excursionPaused()

            override fun onActivityStopped(activity: Activity) {
                startedActivityCount = (startedActivityCount - 1).coerceAtLeast(0)
                recreating = startedActivityCount == 0 && activity.isChangingConfigurations
                // The app went fully to the background (the count does not drop to 0 between screens, see
                // `startedActivityCount`). The password is asked again on the next return. `isChangingConfigurations` covers
                // `recreate()` (scale, font, language, colour and theme settings) and rotation: they stop and restart the
                // activity, so the count drops to 0 briefly, but the app did NOT go to the background. Without this check,
                // every appearance change asked for the password.
                if (startedActivityCount == 0 && !activity.isChangingConfigurations) {
                    AppLock.lock()
                    com.p2p.messenger.service.P2PService.setAppVisible(false)
                } else if (startedActivityCount == 1 && com.p2p.messenger.ui.CallActivity.inPip
                    && activity !is com.p2p.messenger.ui.CallActivity && !activity.isChangingConfigurations) {
                    // Only the call in picture-in-picture is left: the app is in the background for the lock.
                    AppLock.lock()
                }
            }
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }
}
