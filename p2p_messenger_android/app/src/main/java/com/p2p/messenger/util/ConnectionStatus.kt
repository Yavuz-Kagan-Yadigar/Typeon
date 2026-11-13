package com.p2p.messenger.util

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import org.json.JSONObject

/**
 * Shows this device's general network connection status (NOT the other side's) in the top bar of the chat screen (see ChatActivity
 * `txtToolbarSubtitle` and `hasActiveSession`). It combines two sources: Android's `ConnectivityManager` (is there real internet access?
 * Rust and libp2p have no access to the OS network interfaces), and the Rust `ownConnectionStatus()` (Tor, node and swarm connection counts).
 */
object ConnectionStatus {

    /** Not only text: a coloured dot that is easy to tell apart at a glance (see `util.PulsingStatusDot`). It is derived from the SAME decision
     *  tree as the text (see `current()`). There is no second, separate logic, so the text and the dot colour can never disagree. */
    enum class Level { CONNECTED, CONNECTING, PROBLEM }

    data class Status(val level: Level, val text: String)

    /** Whether there is verified internet access over any active network: WiFi, mobile data or Ethernet, not only WiFi. This is the general form of
     *  the `isValidatedWifi` pattern in P2PService. */
    fun hasInternet(context: Context): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
            val network = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(network) ?: return false
            // Not VALIDATED: where Android's own connectivity probe is blocked
            // (censored or filtered network, broken private DNS) the network
            // never validates while Tor is connected and messages flow.
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        } catch (e: Exception) {
            false
        }
    }

    /** This device's overall connection state. It returns both a short human-readable summary (the small status line in the chat top bar) and a
     *  `Level` (for the coloured dot). */
    fun current(context: Context): Status {
        if (!hasInternet(context)) {
            return Status(Level.PROBLEM, context.getString(R.string.status_no_internet))
        }
        val json = try {
            JSONObject(P2PLib.ownConnectionStatus())
        } catch (e: Exception) {
            return Status(Level.PROBLEM, context.getString(R.string.status_unknown))
        }
        val torEnabled = json.optBoolean("tor_enabled", false)
        val torStatus = json.optString("tor_status", "disabled")
        val connectedPeers = json.optInt("connected_peers", 0)
        val nodeMode = json.optBoolean("node_mode", false)

        if (torEnabled) {
            return when (torStatus) {
                "ready" -> Status(
                    Level.CONNECTED,
                    context.getString(if (nodeMode) R.string.status_connected_tor_node else R.string.status_connected_tor)
                )
                "failed" -> Status(Level.PROBLEM, context.getString(R.string.status_tor_failed))
                else -> Status(Level.CONNECTING, context.getString(R.string.status_tor_bootstrapping))
            }
        }
        return if (connectedPeers > 0) {
            Status(
                Level.CONNECTED,
                context.getString(if (nodeMode) R.string.status_connected_node else R.string.status_connected)
            )
        } else {
            Status(Level.CONNECTING, context.getString(R.string.status_reconnecting))
        }
    }
}
