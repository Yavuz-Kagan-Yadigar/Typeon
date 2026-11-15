package com.p2p.messenger.util

import android.content.Context
import android.content.Intent
import androidx.appcompat.app.AlertDialog
import com.p2p.messenger.R

/**
 * Used by the quick "disconnect / reconnect Tor" button on the chat and settings top bar.
 *
 * Today the network layer does NOT support being rebuilt inside a LIVE process. This includes the Tor dial transport added to the libp2p swarm (see
 * `ArtiDialTransport` in tor.rs). Even the Tor on/off switch in Settings only saves the preference, and asks the user to restart the app by hand (see
 * SettingsFragment `tor_switch`, `R.string.tor_restart_needed`, and the note "toggle takes effect on the next network-layer start" in SECURITY.md). On the
 * Rust side there is no verified way to call `start_network` a second time in a live process SAFELY. The old swarm's sockets and background tasks (see the
 * Tor bootstrap retry loop in tor.rs) must be shut down cleanly first, and that is not verified. So no new, unverified "hot restart" logic is written here.
 *
 * Instead, the one safe path that already exists is used: the app PROCESS is killed completely and restarted. That is exactly what happens when the user
 * closes the app from Recents and opens it again. It follows the same code path that already runs on every normal start:
 * `MainActivity.onCreate` -> `initDatabase` / `loadIfPresent` / `startNetworkService` -> `P2PLib.startNetwork` in a CLEAN process.
 */
object AppRestarter {
    fun restart(context: Context) {
        val packageManager = context.packageManager
        val intent = packageManager.getLaunchIntentForPackage(context.packageName) ?: return
        val component = intent.component ?: return
        val restartIntent = Intent.makeRestartActivityTask(component)
        // A background start (service path) can be blocked on API 29+; it must
        // not crash the restart, and the exit waits so the task can start.
        try { context.startActivity(restartIntent) } catch (e: Exception) { com.p2p.messenger.util.Log.w("AppRestarter", "startActivity: ${e.message}") }
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ Runtime.getRuntime().exit(0) }, 400)
    }

    /**
     * This is destructive (it kills the whole process), so it is never triggered directly. The user is asked to confirm first. Both the toolbar button (see
     * `wireTorReconnectButton`) and the top-bar menu item in SettingsFragment share this.
     */
    fun confirmAndRestart(context: Context) {
        AlertDialog.Builder(context)
            .setTitle(R.string.title_tor_reconnect)
            .setMessage(R.string.msg_tor_reconnect)
            .setPositiveButton(R.string.action_reconnect) { _, _ -> restart(context) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
