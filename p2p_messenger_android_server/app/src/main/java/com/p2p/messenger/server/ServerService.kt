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

        const val PREFS_NAME = "typeon_server_settings"
        private const val KEY_NODE = "node_mode"
        private const val KEY_NAME = "server_name"
        private const val KEY_ENABLED = "server_enabled"
        private const val KEY_DATA_DIR = "data_dir"

        fun isNodeMode(context: Context): Boolean =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getBoolean(KEY_NODE, false)

        fun setNodeMode(context: Context, enabled: Boolean) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_NODE, enabled).apply()
        }

        fun serverName(context: Context): String =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_NAME, "Typeon") ?: "Typeon"

        fun isEnabled(context: Context): Boolean =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getBoolean(KEY_ENABLED, false)

        fun setEnabled(context: Context, enabled: Boolean) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_ENABLED, enabled).apply()
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
                .getString(KEY_DATA_DIR, null)
            if (!saved.isNullOrEmpty()) {
                val f = java.io.File(saved)
                if ((f.isDirectory || f.mkdirs()) && f.canWrite()) return f
                Log.w(TAG, "Seçili blob dizini kullanılamıyor, dahiliye dönülüyor: $saved")
            }
            return java.io.File(context.filesDir, "blobs")
        }

        fun setBlobDir(context: Context, dir: java.io.File) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putString(KEY_DATA_DIR, dir.absolutePath).apply()
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

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (isRunning) return START_STICKY
        isRunning = true

        createChannel()
        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.notif_starting)))

        // Ekran kapalıyken de teslim yapabilmek için. Sunucu tanım gereği
        // "her zaman açık" olmalı; kullanıcı pil optimizasyonu muafiyetini
        // reddederse bu wakelock tek başına yeterli olmayabilir.
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Typeon:server").apply {
            setReferenceCounted(false)
            acquire()
        }

        // İKİ CİHAZLI TESTTE (2026-09-06) görüldü: telefonda çalışan onion
        // sunucusuna istemciler aralıklarla ulaşamıyor ("Failed to obtain
        // hidden service circuit", enrollment/deposit zaman aşımı). Sebep:
        // `PARTIAL_WAKE_LOCK` CPU'yu açık tutuyor ama Wi-Fi radyosunu DEĞİL —
        // ekran kapanınca Wi-Fi güç tasarrufuna geçip (ya da tamamen düşüp)
        // Tor devrelerini/onion descriptor yayınını koparıyor. `WifiLock`
        // (yüksek performans / düşük gecikme modu) radyoyu tam güçte tutar.
        // `WIFI_MODE_FULL_HIGH_PERF` API 29'da deprecated ama kaldırılmadı;
        // `WIFI_MODE_FULL_LOW_LATENCY` yalnızca uygulama ön planda + ekran
        // açıkken devreye girer — bir arka plan sunucusu için işe yaramaz.
        @Suppress("DEPRECATION")
        val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        @Suppress("DEPRECATION")
        wifiLock = wm?.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "Typeon:server-wifi")?.apply {
            setReferenceCounted(false)
            acquire()
        }

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

        Thread {
            val result = try {
                // Tor parametresi yok — onion service her zaman açık
                // (bkz. ServerLib.startServer notu).
                ServerLib.startServer(
                    dataDir(this).absolutePath,
                    isNodeMode(this),
                    serverName(this),
                    storageBudgetBytes(),
                    blobDir(this).absolutePath
                )
            } catch (e: Throwable) {
                Log.e(TAG, "Sunucu başlatılamadı", e)
                "Error: ${e.message}"
            }
            Log.i(TAG, "startServer -> $result")
            updateNotification(
                if (result.startsWith("Error:")) result
                else getString(R.string.notif_running)
            )
        }.start()

        return START_STICKY
    }

    override fun onDestroy() {
        // Defter #11: Rust çekirdeğini de GERÇEKTEN durdur. Önceden burada
        // yalnızca wake lock bırakılıyordu; sunucu süreçte çalışmaya devam
        // ediyor, arayüzdeki anahtar "kapalı" gösterse bile posta kabul
        // etmeyi sürdürüyordu.
        Thread {
            try {
                ServerLib.stopServer()
            } catch (e: Throwable) {
                Log.w(TAG, "Sunucu durdurulamadı: ${e.message}")
            }
        }.start()
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        wifiLock?.let { if (it.isHeld) it.release() }
        wifiLock = null
        netCallback?.let {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                    .unregisterNetworkCallback(it)
            } catch (_: Exception) {}
        }
        netCallback = null
        isRunning = false
        super.onDestroy()
    }

    /** Ağ değişikliğinde çekirdeği dürt — arti devrelerini/onion yayınını
     *  tazelesin. `ServerLib.notifyNetworkChanged` yoksa (eski .so) sessizce geç. */
    private fun pokeCore(reason: String) {
        Thread {
            try {
                ServerLib.notifyNetworkChanged()
                Log.i(TAG, "notifyNetworkChanged ($reason)")
            } catch (e: Throwable) {
                Log.w(TAG, "notifyNetworkChanged başarısız: ${e.message}")
            }
        }.start()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel),
                NotificationManager.IMPORTANCE_LOW
            )
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val intent = PendingIntent.getActivity(
            this, 0, Intent(this, ServerActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentIntent(intent)
            .setOngoing(true)
            .build()
    }


    /**
     * Sunucunun kullanabileceği disk bütçesi: o anki BOŞ alanın yarısı,
     * 8 GB'ı geçmemek üzere.
     *
     * "Yarısı", cihazın kendi işine (güncelleme, fotoğraf, kurulum) yer
     * bırakmak için — test sırasında sunucu diski doldurunca yeni bir APK
     * bile kurulamadı. Tavan ise makul bir üst sınır: boş alanı 500 GB olan
     * bir cihazda 250 GB'lık kota vaat etmenin anlamı yok.
     */
    private fun storageBudgetBytes(): Long {
        return try {
            val fs = android.os.StatFs(blobDir(this).absolutePath)
            val free = fs.availableBytes
            (free / 2).coerceAtMost(8L * 1024 * 1024 * 1024).coerceAtLeast(64L * 1024 * 1024)
        } catch (e: Throwable) {
            Log.w(TAG, "Boş alan okunamadı, varsayılan bütçe: ${e.message}")
            512L * 1024 * 1024
        }
    }

    private fun updateNotification(text: String) {
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }
}
