package com.p2p.messenger.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.net.TrafficStats
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Battery diary of this app, written to
 * `Android/data/com.p2p.messenger/files/battery_log.txt`.
 *
 * batterystats resets on charge and cannot split one app's traffic by network,
 * so the app keeps its own: one line per plug/unplug, network switch and hour,
 * and on every plug a summary of the battery session that just ended — time on
 * battery, % and mAh drop, and what Typeon itself used in it: CPU, mobile and
 * Wi-Fi bytes, wake lock time, plus screen-on time.
 *
 * Cheap by design: it never wakes the phone (no alarms; the hourly line is
 * an uptime Handler, so it only runs while the CPU is awake anyway), counters
 * are kept in memory and written to SharedPreferences only at an event line,
 * so a process restart (update) inside a session is not lost. Traffic is the UID's TrafficStats total,
 * attributed to the network that was active since the previous sample.
 */
object BatteryLog {
    private const val PREFS = "battery_log"
    private const val HOUR_MS = 60 * 60 * 1000L
    private const val MAX_BYTES = 2L * 1024 * 1024

    private lateinit var app: Context
    private val handler = Handler(Looper.getMainLooper())
    private var receiver: BroadcastReceiver? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private var net = "none"
    private var screenOn = true
    private var screenSince = 0L
    private var wakeSince = 0L
    private var wakeUntil = 0L
    /** Session counters (ms / bytes), flushed to prefs by `write`. */
    private val acc = HashMap<String, Long>()
    private val KEYS = listOf("a_cpu", "a_wake", "a_wake_off", "a_screen", "a_mob_rx", "a_mob_tx", "a_wifi_rx", "a_wifi_tx", "a_other_rx", "a_other_tx")

    private val hourly = object : Runnable {
        override fun run() {
            write("HOURLY", summary = true)
            handler.postDelayed(this, HOUR_MS)
        }
    }

    @Synchronized
    fun start(ctx: Context) {
        if (receiver != null) return
        app = ctx.applicationContext
        val pm = app.getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        screenOn = pm.isInteractive
        screenSince = SystemClock.elapsedRealtime()
        net = currentNet()
        KEYS.forEach { acc[it] = prefs().getLong(it, 0L) }
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                when (i?.action) {
                    Intent.ACTION_POWER_CONNECTED -> write("PLUG", summary = true, endSession = true)
                    Intent.ACTION_POWER_DISCONNECTED -> write("UNPLUG", startSession = true)
                    Intent.ACTION_SCREEN_ON -> setScreen(true)
                    Intent.ACTION_SCREEN_OFF -> setScreen(false)
                }
            }
        }
        receiver = r
        val f = IntentFilter().apply {
            addAction(Intent.ACTION_POWER_CONNECTED)
            addAction(Intent.ACTION_POWER_DISCONNECTED)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        androidx.core.content.ContextCompat.registerReceiver(app, r, f, androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(n: Network) = onNet()
            override fun onLost(n: Network) = onNet()
        }
        netCallback = cb
        try { cm().registerDefaultNetworkCallback(cb) } catch (e: Exception) {}
        // First run, or the service started while unplugged: open a session.
        if (prefs().getLong("s_time", 0L) == 0L && !plugged()) write("START", startSession = true)
        else write("START")
        handler.postDelayed(hourly, HOUR_MS)
    }

    @Synchronized
    fun stop() {
        handler.removeCallbacks(hourly)
        receiver?.let { try { app.unregisterReceiver(it) } catch (e: Exception) {} }
        netCallback?.let { try { cm().unregisterNetworkCallback(it) } catch (e: Exception) {} }
        receiver = null
        netCallback = null
        if (::app.isInitialized) write("STOP")
    }

    /** From `P2PService` when it takes the wake lock; `timeoutMs` 0 = until released. */
    @Synchronized
    fun wakeAcquired(timeoutMs: Long) {
        val now = SystemClock.elapsedRealtime()
        closeWake(now)
        wakeSince = now
        wakeUntil = if (timeoutMs > 0) now + timeoutMs else Long.MAX_VALUE
    }

    @Synchronized
    fun wakeReleased() = closeWake(SystemClock.elapsedRealtime())

    private fun closeWake(now: Long) {
        if (wakeSince == 0L || !::app.isInitialized) return
        val held = minOf(now, wakeUntil) - wakeSince
        add("a_wake", held)
        // Screen off is the part that costs: with the screen on the CPU is awake anyway.
        // `setScreen` closes the interval at every screen change, so one state covers it.
        if (!screenOn) add("a_wake_off", held)
        wakeSince = 0L
    }

    @Synchronized
    private fun setScreen(on: Boolean) {
        val now = SystemClock.elapsedRealtime()
        if (screenOn) add("a_screen", now - screenSince)
        if (wakeSince != 0L) { closeWake(now); if (now < wakeUntil) wakeSince = now }
        screenOn = on
        screenSince = now
    }

    @Synchronized
    private fun onNet() {
        val n = currentNet()
        if (n == net) return
        write("NET $net->$n")
    }

    /** Folds everything since the last sample into the session counters. */
    private fun sample() {
        val p = prefs()
        val e = p.edit()
        val now = SystemClock.elapsedRealtime()
        // CPU: per process; a new pid means a restart, count from zero.
        val pid = android.os.Process.myPid()
        val cpu = android.os.Process.getElapsedCpuTime()
        val lastCpu = if (p.getInt("l_pid", 0) == pid) p.getLong("l_cpu", 0L) else 0L
        add("a_cpu", cpu - lastCpu)
        e.putInt("l_pid", pid).putLong("l_cpu", cpu)
        // Traffic: UID totals (reset at reboot -> a drop means count from zero).
        val uid = android.os.Process.myUid()
        val rx = TrafficStats.getUidRxBytes(uid).coerceAtLeast(0)
        val tx = TrafficStats.getUidTxBytes(uid).coerceAtLeast(0)
        val lastRx = p.getLong("l_rx", -1L)
        val lastTx = p.getLong("l_tx", -1L)
        if (lastRx >= 0) {
            val dRx = if (rx >= lastRx) rx - lastRx else rx
            val dTx = if (tx >= lastTx) tx - lastTx else tx
            val key = if (net == "mobile") "a_mob" else if (net == "wifi") "a_wifi" else "a_other"
            add("${key}_rx", dRx)
            add("${key}_tx", dTx)
        }
        e.putLong("l_rx", rx).putLong("l_tx", tx)
        if (wakeSince != 0L) { closeWake(now); if (now < wakeUntil) wakeSince = now }
        if (screenOn) { add("a_screen", now - screenSince); screenSince = now }
        net = currentNet()
        KEYS.forEach { e.putLong(it, acc[it] ?: 0L) }
        e.apply()
    }

    @Synchronized
    private fun write(event: String, summary: Boolean = false, startSession: Boolean = false, endSession: Boolean = false) {
        try {
            sample()
            val p = prefs()
            val bm = app.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
            val pct = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
            val mAh = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER) / 1000
            val sb = StringBuilder()
            sb.append(SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date()))
                .append("  ").append(event)
                .append("  bat=").append(pct).append("% ").append(mAh).append("mAh")
                .append(" net=").append(net).append(" screen=").append(if (screenOn) "on" else "off")
            val sTime = p.getLong("s_time", 0L)
            if (summary && sTime != 0L) {
                val dur = System.currentTimeMillis() - sTime
                sb.append("\n    session ").append(fmtDur(dur))
                    .append(": ").append(p.getInt("s_pct", pct)).append("% -> ").append(pct).append("%")
                    .append(" (").append(p.getInt("s_mah", mAh) - mAh).append(" mAh")
                if (dur > 0) sb.append(", ").append("%.1f".format(Locale.US, (p.getInt("s_pct", pct) - pct) * HOUR_MS.toDouble() / dur)).append("%/h")
                sb.append(")  screen on ").append(fmtDur((acc["a_screen"] ?: 0L)))
                sb.append("\n    Typeon: cpu ").append(fmtDur((acc["a_cpu"] ?: 0L)))
                    .append("  wakelock ").append(fmtDur((acc["a_wake"] ?: 0L)))
                    .append(" (screen off ").append(fmtDur((acc["a_wake_off"] ?: 0L))).append(")")
                    .append("  mobile ").append(mb((acc["a_mob_rx"] ?: 0L))).append(" in/").append(mb((acc["a_mob_tx"] ?: 0L))).append(" out")
                    .append("  wifi ").append(mb((acc["a_wifi_rx"] ?: 0L))).append(" in/").append(mb((acc["a_wifi_tx"] ?: 0L))).append(" out")
            }
            append(sb.toString())
            if (startSession || endSession) {
                val e = p.edit()
                KEYS.forEach { e.remove(it); acc[it] = 0L }
                if (startSession) e.putLong("s_time", System.currentTimeMillis()).putInt("s_pct", pct).putInt("s_mah", mAh)
                else e.remove("s_time")
                e.apply()
            }
        } catch (e: Exception) {
            com.p2p.messenger.util.Log.w("BatteryLog", "write failed: ${e.message}")
        }
    }

    private fun append(line: String) {
        val dir = app.getExternalFilesDir(null) ?: app.filesDir
        val f = File(dir, "battery_log.txt")
        if (f.length() > MAX_BYTES) f.renameTo(File(dir, "battery_log.old.txt"))
        f.appendText(line + "\n")
    }

    private fun add(key: String, v: Long) {
        if (v > 0) acc[key] = (acc[key] ?: 0L) + v
    }

    private fun prefs() = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private fun cm() = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private fun currentNet(): String {
        val caps = try { cm().getNetworkCapabilities(cm().activeNetwork) } catch (e: Exception) { null } ?: return "none"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "mobile"
            else -> "other"
        }
    }

    private fun plugged(): Boolean {
        val i = app.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) ?: return false
        return i.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) != 0
    }

    private fun fmtDur(ms: Long): String {
        val s = ms / 1000
        return if (s >= 3600) "%dh%02dm".format(s / 3600, s % 3600 / 60) else "%dm%02ds".format(s / 60, s % 60)
    }

    private fun mb(b: Long) = "%.1fMB".format(Locale.US, b / 1048576.0)
}
