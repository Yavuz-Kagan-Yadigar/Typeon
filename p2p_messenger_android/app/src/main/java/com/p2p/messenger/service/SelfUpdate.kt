package com.p2p.messenger.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Self-update from GitHub releases (see update.rs in the core). The core does the daily check and the verified
 * download over Tor; this side schedules it and hands the APK to PackageInstaller. The first update asks the user
 * once; after that this app is the installer of record and Android 12+ installs later ones silently.
 */
object SelfUpdate {
    private const val TAG = "SelfUpdate"
    private const val CHANNEL = "updates"

    fun dir(context: Context) = File(context.noBackupFilesDir, "update")

    fun beta(context: Context) = File(dir(context), "beta").exists()

    /** Same files the core reads (`update::set_beta`). A changed channel is checked right away. */
    fun setBeta(context: Context, on: Boolean) {
        val d = dir(context).apply { mkdirs() }
        File(d, "last-check").delete()
        if (on) File(d, "beta").createNewFile() else File(d, "beta").delete()
        WorkManager.getInstance(context).enqueueUniqueWork(
            "self_update_now", ExistingWorkPolicy.REPLACE,
            OneTimeWorkRequestBuilder<UpdateWorker>().setConstraints(constraints()).build()
        )
    }

    private fun constraints() = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

    /** Twice a day; the core skips a check younger than 20 h, so this is one check a day. */
    fun schedule(context: Context) {
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            "self_update", ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<UpdateWorker>(12, TimeUnit.HOURS).setConstraints(constraints()).build()
        )
    }

    fun currentVersion(context: Context): String =
        context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "0"

    fun install(context: Context, apk: File) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            if (Build.VERSION.SDK_INT >= 34) setRequestUpdateOwnership(true)
        }
        val id = installer.createSession(params)
        installer.openSession(id).use { session ->
            session.openWrite("base.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
            val intent = Intent(context, UpdateReceiver::class.java).putExtra("version", apk.name.substringBefore("-typeon"))
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
            session.commit(PendingIntent.getBroadcast(context, id, intent, flags).intentSender)
        }
        Log.i(TAG, "install session $id committed for ${apk.name}")
    }

    /** Android wants the user to confirm (first update, or no silent-install right). Ask through a notification. */
    fun askUser(context: Context, confirm: Intent, version: String) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.update_ready_title), NotificationManager.IMPORTANCE_DEFAULT))
        confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val tap = PendingIntent.getActivity(context, 7301, confirm, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.update_ready_title))
            .setContentText(context.getString(R.string.update_ready_text, version))
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()
        try {
            manager.notify(7301, notification)
        } catch (e: SecurityException) {
            Log.w(TAG, "no notification permission: ${e.message}")
        }
    }
}

class UpdateWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        // The check rides the core's Tor client, which only runs inside P2PService.
        if (!P2PService.alive) return Result.retry()
        val ctx = applicationContext
        val out = P2PLib.checkUpdate(SelfUpdate.dir(ctx).absolutePath, SelfUpdate.currentVersion(ctx), false)
        if (out.startsWith("Error:")) {
            Log.w("SelfUpdate", out)
            return Result.retry()
        }
        if (out.isNotEmpty()) SelfUpdate.install(ctx, File(out))
        return Result.success()
    }
}

class UpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val version = intent.getStringExtra("version") ?: ""
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            @Suppress("DEPRECATION")
            val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
            SelfUpdate.askUser(context, confirm, version)
        } else {
            Log.i("SelfUpdate", "install status $status: ${intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)}")
            // Not installed (user backed out, storage...): the next tick tries again. The verified APK stays,
            // so that costs no download.
            if (status != PackageInstaller.STATUS_SUCCESS) File(SelfUpdate.dir(context), "last-check").delete()
        }
    }
}
