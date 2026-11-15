package com.p2p.messenger.server

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

/**
 * Brings the server back after a reboot.
 *
 * The same reason as `service.BootReceiver` in the client, but the result is heavier. While the server is off, store-and-forward stops COMPLETELY. Every message
 * sent to an offline recipient waits in the sender's retry queue, and it cannot be delivered until the recipient is reachable peer to peer. So the server's reason
 * to exist disappears. If the phone rebooted overnight, that lasts until someone opens the app by hand.
 *
 * `ACTION_BOOT_COMPLETED` is one of the few broadcasts that Android explicitly exempts from the foreground service start restrictions. So starting from here
 * does not depend on the battery optimisation exemption.
 *
 * `ACTION_MY_PACKAGE_REPLACED` is also handled. When the app is updated, the process is killed and the service does not come back by itself. This happened on a phone
 * when release APKs were installed: the server stayed off after the install.
 *
 * NOT direct-boot aware, on purpose (the data is in credential-protected storage). After a reboot, the server comes back only once the phone has been unlocked.
 * Keep it that way. Making it direct-boot aware would make the DB key and the enrolment keys readable on a cold-booted device.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {}
            else -> return
        }
        // The user's on/off switch (see ServerActivity). If it is off, do not start it at boot either. The "off" decision is respected.
        if (!ServerService.isEnabled(context)) {
            Log.i("ServerBootReceiver", "Server turned off by user — not started at boot")
            return
        }
        try {
            ContextCompat.startForegroundService(
                context.applicationContext,
                Intent(context.applicationContext, ServerService::class.java)
            )
        } catch (e: Exception) {
            // Direct boot stage, or an OEM restriction: skip quietly. The server starts when the user next opens the app.
            Log.w("ServerBootReceiver", "Server could not be started at boot: ${e.message}")
        }
    }
}
