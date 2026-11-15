package com.p2p.messenger.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.p2p.messenger.util.Log
import androidx.core.content.ContextCompat
import com.p2p.messenger.P2PLib

/**
 * Brings the network back after a reboot.
 *
 * Before this fix, after the phone rebooted the app stayed completely dead. No message was received until the user opened the app by hand. The only
 * fallback was `P2PRetryWorker`, which runs hourly. It calls `startForegroundService` from the BACKGROUND, and Android 12+ (API 31) refuses that with
 * `ForegroundServiceStartNotAllowedException` when the app is not exempt from battery optimisation. So the worst case was: the phone rebooted overnight,
 * and no messages had arrived by morning.
 *
 * `ACTION_BOOT_COMPLETED` is one of the few broadcasts that Android explicitly exempts from the foreground service start restrictions. So starting from
 * here does not depend on the battery exemption, and it always works.
 *
 * `ACTION_MY_PACKAGE_REPLACED` is handled for the same reason: when the app is updated, the process is killed and the service does not come back by itself.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {}
            else -> return
        }
        // Opening the database on the main thread held up every other boot
        // receiver of the process (and can run into the broadcast ANR limit).
        val pending = goAsync()
        val app = context.applicationContext
        Thread {
            try {
                // See the same note in P2PRetryWorker: the process may have just been born, and `hasStoredIdentity` returns a wrong (false) result before the
                // DB is opened. `initDatabase` is idempotent.
                // A database that did not open (Keystore not ready) is not "no account": the service retries the open itself.
                if (!P2PLib.initDatabase(app.filesDir.absolutePath) || P2PLib.hasStoredIdentity()) {
                    ContextCompat.startForegroundService(app, Intent(app, P2PService::class.java))
                }
            } catch (e: Throwable) {
                // If the device is still in direct boot, or an OEM restriction applies, skip quietly. `P2PRetryWorker` and the user opening the app are still
                // the fallback paths.
                Log.w("BootReceiver", "Açılışta servis başlatılamadı: ${e.message}")
            } finally {
                pending.finish()
            }
        }.start()
    }
}
