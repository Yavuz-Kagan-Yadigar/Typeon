package com.p2p.messenger.service

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.p2p.messenger.P2PLib

/**
 * Runs an hourly fallback in the background, so that messages and commands that could not be sent get another try. Not requested by the user.
 *
 * P2PService is START_STICKY, so the OS is expected to restart it. But aggressive battery optimisation on some OEMs can delay that restart for
 * hours. WorkManager (JobScheduler based: the OS runs this job together with other apps' jobs) gives a more battery-friendly fallback than a custom
 * AlarmManager or wakelock loop.
 *
 * `doWork` only TRIES to (re)start the service. If the service is already running, this is a harmless no-op (see the `isRunning` guard in
 * `P2PService.onStartCommand`, which only refreshes the notification). If it had died, the restart also triggers the durable retry queue to be
 * reloaded from disk (see persist.rs `load_pending_durable_retries_from_db`) through `setSkippedKeyEncryptionKey`. No separate "retry now" JNI call
 * is needed.
 */
class P2PRetryWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        // CRITICAL: WorkManager may restart the process to run this Worker even when the process was completely dead. In that case the Rust `identity`
        // field has not been loaded from the DB yet (`initDatabase` may never have been called). Without that call, `hasStoredIdentity()` gives a WRONG
        // (false negative) result. `initDatabase` is idempotent (see the P2PService.onStartCommand note), so when the service is already running this
        // is a harmless repeat call.
        // If the service is polling, there is nothing to restart. Calling `initDatabase` and a service start every hour only wakes the core.
        if (P2PService.alive) return Result.success()
        // Database not open is not "no account": try again later.
        if (!P2PLib.initDatabase(applicationContext.filesDir.absolutePath)) return Result.retry()
        if (P2PLib.hasStoredIdentity()) {
            val serviceIntent = Intent(applicationContext, P2PService::class.java)
            // This call was not protected before. On Android 12+ (API 31), starting a foreground service FROM THE BACKGROUND is refused
            // (`ForegroundServiceStartNotAllowedException`), and this Worker runs exactly in the background. The exception is allowed only for apps exempt from
            // battery optimisation. Otherwise it is thrown. WorkManager caught it and marked the job "failed", so the fallback silently never ran. Now the
            // exception is swallowed, but the job is NOT reported as successful. It is reported to WorkManager with `Result.retry()`, so it is retried under
            // WorkManager's own backoff rule, and the periodic schedule is not broken. The main start path is now `BootReceiver`, which is exempt from the restriction.
            try {
                ContextCompat.startForegroundService(applicationContext, serviceIntent)
            } catch (e: Exception) {
                android.util.Log.w("P2PRetryWorker", "Servis arka plandan başlatılamadı: ${e.message}")
                // Reporting "success" would hide that this fallback never actually ran. Tell WorkManager the status, so the job is retried with its own
                // backoff rule.
                return Result.retry()
            }
        }
        return Result.success()
    }
}
