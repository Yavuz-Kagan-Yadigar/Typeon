package com.p2p.messenger.server

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Sunucuyu ayakta tutan foreground service.
 *
 * İstemcinin `P2PService`'iyle aynı desen (aynı `dataSync` tipi, aynı
 * `START_STICKY`), ama çok daha basit: burada olay döngüsü yok. Rust
 * tarafındaki `ServerCore` kendi tokio görevinde dönüyor; bu servisin tek
 * işi süreci canlı tutmak ve kullanıcıya kalıcı bir bildirim göstermek.
 *
 * DÜRÜST SINIR: Android bellek baskısı altında bir foreground service'i
 * yine de öldürebilir. Bu uygulama "evde duran, fişte bir yedek telefon"
 * senaryosu için; kesintisiz çalışması gereken bir sunucu için küçük bir
 * VPS'te `typeon-server` daemon'ı önerilir.
 */
class ServerService : Service() {

    companion object {
        private const val TAG = "TypeonServerSvc"
        private const val CHANNEL_ID = "TypeonServerChannel"
        private const val NOTIFICATION_ID = 1
        private const val ERROR_NOTIFICATION_ID = 2

        const val PREFS_NAME = "typeon_server_settings"
        private const val KEY_NODE = "node_mode"
        private const val KEY_ENABLED = "server_enabled"
        // Holds the BLOB dir. The stored key keeps its old name; identity,
        // database and Tor state never move (see `dataDir`).
        private const val KEY_BLOB_DIR = "data_dir"

        /**
         * Every native start and stop runs here, one at a time and in order,
         * so a stop always queues behind a start that is still initialising.
         * On separate threads the stop was a no-op and the server then came
         * up with no service, no wake lock and the switch off.
         */
        val core: ExecutorService = Executors.newSingleThreadExecutor()

        /** Why the last start failed; the activity shows it. */
        @Volatile
        var lastError: String? = null

        /** A storage move is copying or deleting blob files. */
        val moving = AtomicBoolean(false)

        private const val WATCHDOG_MS = 60_000L
        private const val WATCHDOG_MAX_MS = 30 * 60_000L

        /** Network pokes run here, coalesced: a flapping network used to spawn a thread per callback. */
        private val poker: ExecutorService = Executors.newSingleThreadExecutor()
        private val pokePending = AtomicBoolean(false)

        @Volatile
        private var instance: ServerService? = null

        /**
         * Starts the native core again inside the running service (after a
         * storage move stopped it). The service stays in the foreground the
         * whole time, so this works with the app in the background, where
         * Android 12+ refuses to start a service.
         */
        fun restartCore() {
            instance?.startCore()
        }

        fun isNodeMode(context: Context): Boolean =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getBoolean(KEY_NODE, false)

        fun setNodeMode(context: Context, enabled: Boolean) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_NODE, enabled).apply()
        }

        fun isEnabled(context: Context): Boolean =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getBoolean(KEY_ENABLED, false)

        fun setEnabled(context: Context, enabled: Boolean) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_ENABLED, enabled).commit() // apply() could lose an "off" across process death
        }

        /**
         * Kimlik, veritabanı ve Tor durumu — HER ZAMAN dahili depolama.
         *
         * Taşınabilir DEĞİL: arti (Tor) kalıcı durumu için POSIX izin modeli
         * istiyor, SD kart bağlaması vermiyor ve
         * `could not read/write persistent state` ile açılmıyor. Gerçek
         * testte olan buydu — sunucu Tor'suz, rastgele portta kalktı ve
         * kayıtlı bütün istemciler koptu.
         */
        fun dataDir(context: Context): java.io.File = context.filesDir

        /**
         * Blobların (dosya ekleri) dizini — yer kaplayan TEK şey bu (gerçek
         * testte 504 MB), ve izin modeline duyarlı bir şey içermediği için
         * güvenle SD karta alınabilir.
         */
        fun blobDir(context: Context): java.io.File {
            val saved = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_BLOB_DIR, null)
            // A chosen dir is never replaced silently. With the SD card not
            // mounted the server used to start on an empty internal dir:
            // every stored attachment failed and new uploads were orphaned.
            // The service checks `blobDirUsable` and refuses to start instead.
            if (!saved.isNullOrEmpty()) return java.io.File(saved)
            // Created here: `StatFs` throws on a path that does not exist.
            return java.io.File(context.filesDir, "blobs").apply { mkdirs() }
        }

        fun blobDirUsable(dir: java.io.File): Boolean = (dir.isDirectory || dir.mkdirs()) && dir.canWrite()

        fun setBlobDir(context: Context, dir: java.io.File) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putString(KEY_BLOB_DIR, dir.absolutePath).apply()
        }

        /**
         * Yazılabilir depolama birimleri: dahili + varsa SD kart.
         *
         * `getExternalFilesDirs` KASITLI tercih — SAF (klasör seçici) burada
         * kullanılamaz: SQLite ve blob dosyaları GERÇEK bir dosya yolu
         * istiyor, SAF ise `content://` URI veriyor. `getExternalFilesDirs`
         * her birimde uygulamaya ait, izin gerektirmeyen ve gerçek yolu olan
         * bir dizin döndürüyor.
         */
        fun storageVolumes(context: Context): List<java.io.File> {
            val out = mutableListOf(context.filesDir)
            // Before Android 11 any app with the storage permission can read
            // another app's external files dir (blob names, sizes, times).
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return out
            context.getExternalFilesDirs(null)
                .filterNotNull()
                .filter { it.absolutePath != context.filesDir.absolutePath }
                .forEach { out.add(it) }
            return out
        }
    }

    @Volatile
    private var isRunning = false
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null

    /**
     * Wake lock + Wi-Fi lock. A server that is up needs both (screen-off Wi-Fi
     * power save dropped the Tor circuits in the 2026-09-06 test;
     * `WIFI_MODE_FULL_LOW_LATENCY` only works in the foreground), so they are
     * held while it runs. Released while the core is failing to start.
     */
    @Synchronized
    private fun setLocks(on: Boolean) {
        retryLock?.let { if (it.isHeld) it.release() }
        retryLock = null
        if (!on) {
            wakeLock?.let { if (it.isHeld) it.release() }
            wakeLock = null
            wifiLock?.let { if (it.isHeld) it.release() }
            wifiLock = null
            return
        }
        if (wakeLock == null) {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Typeon:server").apply {
                setReferenceCounted(false)
                acquire()
            }
        }
        if (wifiLock == null) {
            @Suppress("DEPRECATION")
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            @Suppress("DEPRECATION")
            wifiLock = wm?.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "Typeon:server-wifi")?.apply {
                setReferenceCounted(false)
                acquire()
            }
        }
    }

    private var retryLock: PowerManager.WakeLock? = null

    /** The watchdog runs on the uptime clock: without a lock the CPU suspends
     *  and a failed start stays down until something else wakes the phone.
     *  Timed, so a core that never starts does not hold the CPU for good. */
    @Synchronized
    private fun holdForRetry() {
        // One object: a second failed start must not leave the first lock held.
        retryLock?.let { if (it.isHeld) it.release() }
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        retryLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Typeon:server-retry").apply {
            setReferenceCounted(false)
            acquire(watchdogDelay + 15_000L)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (isRunning) return START_STICKY
        isRunning = true
        instance = this
        lastError = null

        createChannel()
        // API 34+: remoteMessaging, which has no daily cap (dataSync is
        // capped at 6 h a day on Android 15+ and then demoted).
        val notification = buildNotification(getString(R.string.notif_starting))
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            // Android 12+: a sticky restart in the background, without the
            // battery exemption, may not go foreground. Uncaught, this
            // crashed the process on every restart attempt.
            Log.w(TAG, "Ön plana geçilemedi: ${e.message}")
            isRunning = false
            stopSelf()
            return START_NOT_STICKY
        }

        // Ekran kapalıyken de teslim yapabilmek için. Sunucu tanım gereği
        // "her zaman açık" olmalı; kullanıcı pil optimizasyonu muafiyetini
        // reddederse bu wakelock tek başına yeterli olmayabilir.
        setLocks(true)

        // Ağ değişikliği (Wi-Fi kopup gelme, hücresele geçiş) güçlü bir
        // sinyal — arti'nin devreleri yeniden kurup onion descriptor'ı
        // yeniden yayınlaması için çekirdeği dürt (bkz.
        // ServerLib.notifyNetworkChanged / `ServerCore::notify_network_changed`).
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) { pokeCore("network available") }
                override fun onCapabilitiesChanged(n: Network, c: NetworkCapabilities) {}
                override fun onLost(network: Network) { Log.i(TAG, "Ağ kaybedildi") }
            }
            cm.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build(),
                cb
            )
            netCallback = cb
        } catch (e: Exception) {
            Log.w(TAG, "Ağ geri çağrısı kaydedilemedi: ${e.message}")
        }

        startCore()
        watchdog.postDelayed(watchdogTick, WATCHDOG_MS)
        return START_STICKY
    }

    private val watchdog = android.os.Handler(android.os.Looper.getMainLooper())

    /**
     * The native loop can end on its own (a panic inside it). Nobody else
     * notices with the screen off: the service kept the wake lock and the
     * Wi-Fi lock for a server that was gone. Start it again.
     */
    // Doubles while the core stays down (failed start included), capped.
    private var watchdogDelay = WATCHDOG_MS

    private val watchdogTick = object : Runnable {
        override fun run() {
            core.execute {
                try {
                    val dead = !org.json.JSONObject(ServerLib.serverStatus()).optBoolean("running")
                    if (isRunning && dead && !moving.get()) {
                        Log.w(TAG, "Sunucu döngüsü ölmüş, yeniden başlatılıyor")
                        startCore()
                        watchdogDelay = (watchdogDelay * 2).coerceAtMost(WATCHDOG_MAX_MS)
                    } else {
                        watchdogDelay = WATCHDOG_MS
                    }
                } catch (e: Throwable) {
                    Log.w(TAG, "Durum okunamadı: ${e.message}")
                }
                if (isRunning) watchdog.postDelayed(this, watchdogDelay)
            }
        }
    }

    private fun startCore() {
        core.execute {
            // A stop is queued behind this one, or a move owns the blob files.
            if (!isRunning || moving.get()) return@execute
            val result = try {
                val blobs = awaitBlobDir()
                    ?: throw java.io.IOException(getString(R.string.err_storage_unavailable))
                // Tor parametresi yok — onion service her zaman açık
                // (bkz. ServerLib.startServer notu).
                // DB encryption at rest: fail closed, never fall back to a plain DB.
                val dbKey = DbKey.get(this)
                val keyRes = try { ServerLib.setDbKey(dbKey) } finally { dbKey.fill(0) }
                if (keyRes.startsWith("Error:")) throw java.io.IOException(keyRes)
                ServerLib.startServer(
                    dataDir(this).absolutePath,
                    isNodeMode(this),
                    "Typeon",
                    storageBudgetBytes(blobs),
                    blobs.absolutePath
                )
            } catch (e: Throwable) {
                Log.e(TAG, "Sunucu başlatılamadı", e)
                "Error: ${e.message}"
            }
            val failed = result.startsWith("Error:")
            // The success value is the server's peer id: not for logcat.
            Log.i(TAG, if (failed) "startServer: $result" else "startServer: ok")
            // Stopped meanwhile: `onDestroy` queued the stop behind this.
            if (!isRunning) return@execute
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (failed) {
                // Storage or Tor can come back (SD card, "old loop still
                // closing"): stay in the foreground and let the watchdog retry
                // with backoff, but do not hold the locks meanwhile.
                lastError = result
                setLocks(false)
                holdForRetry()
                nm.notify(NOTIFICATION_ID, buildNotification(serverErrorText(this, result)))
            } else {
                lastError = null
                setLocks(true)
                nm.cancel(ERROR_NOTIFICATION_ID)
                nm.notify(NOTIFICATION_ID, buildNotification(getString(R.string.notif_running)))
            }
        }
    }

    override fun onDestroy() {
        // Rust çekirdeğini de GERÇEKTEN durdur. Önceden burada
        // yalnızca wake lock bırakılıyordu; sunucu süreçte çalışmaya devam
        // ediyor, arayüzdeki anahtar "kapalı" gösterse bile posta kabul
        // etmeyi sürdürüyordu.
        core.execute {
            try {
                val r = ServerLib.stopServer()
                if (r.startsWith("Error:")) Log.w(TAG, "stopServer: $r")
            } catch (e: Throwable) {
                Log.w(TAG, "Sunucu durdurulamadı: ${e.message}")
            }
        }
        setLocks(false)
        netCallback?.let {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                    .unregisterNetworkCallback(it)
            } catch (_: Exception) {}
        }
        netCallback = null
        watchdog.removeCallbacks(watchdogTick)
        if (instance === this) instance = null
        isRunning = false
        super.onDestroy()
    }

    /** Ağ değişikliğinde çekirdeği dürt — arti devrelerini/onion yayınını
     *  tazelesin. `ServerLib.notifyNetworkChanged` yoksa (eski .so) sessizce geç. */
    private fun pokeCore(reason: String) {
        if (!pokePending.compareAndSet(false, true)) return
        poker.execute {
            pokePending.set(false)
            try {
                ServerLib.notifyNetworkChanged()
                Log.i(TAG, "notifyNetworkChanged ($reason)")
            } catch (e: Throwable) {
                Log.w(TAG, "notifyNetworkChanged başarısız: ${e.message}")
            }
        }
    }

    private fun createChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notif_channel),
            NotificationManager.IMPORTANCE_LOW
        )
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .createNotificationChannel(channel)
    }

    private fun buildNotification(text: String, ongoing: Boolean = true): Notification {
        val intent = PendingIntent.getActivity(
            this, 0, Intent(this, ServerActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentIntent(intent)
            .setOngoing(ongoing)
            .build()
    }


    /**
     * The chosen blob dir, waiting up to a minute for it: after a reboot
     * BOOT_COMPLETED can arrive before the SD card is mounted.
     */
    private fun awaitBlobDir(): java.io.File? {
        val dir = blobDir(this)
        repeat(30) {
            if (blobDirUsable(dir)) return dir
            if (!isRunning) return null
            try { Thread.sleep(2000) } catch (e: InterruptedException) { return null }
        }
        return null
    }

    /**
     * Sunucunun disk bütçesi: ZATEN sakladığı bloblar + o anki BOŞ alanın
     * yarısı, 8 GB'ı geçmemek üzere.
     *
     * "Yarısı", cihazın kendi işine (güncelleme, fotoğraf, kurulum) yer
     * bırakmak için. What the server already stores is added back: half of
     * the free space alone shrank on every start as the server filled, fell
     * below current usage, and then every deposit was refused with space left.
     * Free space is the smaller of the blob dir's and the internal data
     * dir's volume: mail and archive live in the database on internal storage.
     */
    private fun storageBudgetBytes(blobs: java.io.File): Long {
        return try {
            val free = minOf(
                android.os.StatFs(blobs.absolutePath).availableBytes,
                android.os.StatFs(dataDir(this).absolutePath).availableBytes
            )
            val used = blobs.listFiles()?.sumOf { it.length() } ?: 0L
            // At least 1: 0 means "no budget" to the native side.
            (used + free / 2).coerceAtMost(8L * 1024 * 1024 * 1024).coerceAtLeast(1L)
        } catch (e: Throwable) {
            Log.w(TAG, "Boş alan okunamadı, varsayılan bütçe: ${e.message}")
            512L * 1024 * 1024
        }
    }
}
