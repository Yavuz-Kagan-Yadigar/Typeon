package com.p2p.messenger.util

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import org.json.JSONObject

/**
 * Spec dışı, kullanıcı isteği: sohbet ekranının üst çubuğunda BU cihazın
 * (karşı tarafınki DEĞİL — bkz. ChatActivity `txtToolbarSubtitle`/
 * `hasActiveSession`) genel ağ bağlantı durumunu göstermek için. İki
 * kaynağı birleştirir: Android'in `ConnectivityManager`'ı (gerçekten
 * internet var mı — Rust/libp2p'nin işletim sistemi ağ arayüzlerine erişimi
 * yok) ve Rust `ownConnectionStatus()` (Tor/node/swarm bağlantı sayısı).
 */
object ConnectionStatus {

    /** Spec dışı, kullanıcı isteği: sadece metin değil, ilk bakışta ayırt
     *  edilebilir bir renkli nokta da göstermek için (bkz.
     *  `util.PulsingStatusDot`) — `describe()`'un metin kararıyla AYNI
     *  karar ağacından türetilir (bkz. `current()`), iki AYRI mantık
     *  YAZILMAZ ki metin ile nokta rengi asla birbirinden SAPMASIN. */
    enum class Level { CONNECTED, CONNECTING, PROBLEM }

    data class Status(val level: Level, val text: String)

    /** Herhangi bir aktif ağ üzerinden (WiFi/mobil veri/ethernet — SADECE
     *  WiFi değil, bkz. P2PService `isValidatedWifi` aynı desenin daha
     *  genel hali) doğrulanmış internet erişimi var mı. */
    fun hasInternet(context: Context): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
            val network = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(network) ?: return false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        } catch (e: Exception) {
            false
        }
    }

    /** Bu cihazın genel bağlantı durumu — hem insana okunur kısa özet
     *  (sohbet üst çubuğundaki küçük durum satırı) hem de bir `Level`
     *  (renkli nokta için) birlikte döner. */
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
