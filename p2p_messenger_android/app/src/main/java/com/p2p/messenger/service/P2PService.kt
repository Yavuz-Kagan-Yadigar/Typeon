package com.p2p.messenger.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.*
import androidx.core.app.NotificationCompat
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.util.NotificationHelper
import org.json.JSONObject

/** bkz. `P2PService.bindToWifiIfAvailable` dokümantasyonu — transport tipi
 *  TEK BAŞINA yeterli değil, gerçekten doğrulanmış internet erişimi de
 *  gerekli (aksi halde internetsiz bir WiFi'ye yanlışlıkla bağlanıp mobil
 *  veri üzerinden çalışan bir cihazı bağlantısız bırakabiliriz). */
private fun NetworkCapabilities?.isValidatedWifi(): Boolean {
    if (this == null) return false
    return hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
        hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
        hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
}

class P2PService : Service() {

    companion object {
        const val CHANNEL_ID = "P2PServiceChannel"
        const val NOTIFICATION_ID = 1
        const val PREFS_NAME = "p2p_settings"
        const val KEY_NODE_MODE = "node_mode_enabled"

        /** Registered by UI components (e.g. ChatActivity) that want to be
         *  notified as decrypted messages arrive. Kept simple/static rather
         *  than a full pub-sub bus since this is a single-process app. */
        private val listeners = mutableListOf<(String) -> Unit>()

        fun addMessageListener(listener: (String) -> Unit) {
            listeners.add(listener)
        }

        fun removeMessageListener(listener: (String) -> Unit) {
            listeners.remove(listener)
        }

        /**
         * Spec dışı: şu an EKRANDA açık olan sohbetin kimliği — 1:1 için
         * `peer_device_fingerprint`, grup için `"group:$group_id"`
         * (ChatActivity/GroupChatActivity onResume/onPause'da set/clear
         * eder). Bir mesaj bu konuşmaya aitse bildirim GÖSTERİLMEZ (zaten
         * ekranda canlı görünüyor) — başka HERHANGİ bir konuşmaya aitse
         * (veya hiçbir sohbet açık değilse) bildirim gösterilir.
         */
        var activeConversationId: String? = null

        /** Spec 4.3: Node modu — kullanıcı ayarlardan açıp kapatabilir. */
        fun isNodeModeEnabled(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getBoolean(KEY_NODE_MODE, false)
        }

        fun setNodeModeEnabled(context: Context, enabled: Boolean) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putBoolean(KEY_NODE_MODE, enabled).apply()
            // Zaten çalışan bir ağ varsa canlı olarak da güncelle.
            P2PLib.setNodeMode(enabled)
        }
    }

    private var isRunning = false
    private var wifiNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private var handler: Handler = Handler(Looper.getMainLooper())
    private val pollRunnable = object : Runnable {
        override fun run() {
            if (isRunning) {
                val messages = P2PLib.pollNetwork()
                for (msg in messages) {
                    if (msg.isNotEmpty()) {
                        listeners.forEach { it(msg) }
                        maybeNotify(msg)
                    }
                }
                handler.postDelayed(this, 1000)
            }
        }
    }

    /**
     * Google Play Services/FCM'ye bağımlı OLMAYAN, tamamen lokal bildirim
     * sistemi (bkz. NotificationHelper dosya başı notu) — bu servis zaten
     * her saniye ağı taradığından ayrı bir push altyapısına gerek yok.
     * SADECE gerçek yeni mesajlar ("message"/"group_message") bildirim
     * üretir; edit/delete/status olayları sessizdir. İlgili sohbet ekranda
     * açıksa (activeConversationId eşleşiyorsa) bildirim BASTIRILIR — zaten
     * canlı görünüyor.
     */
    private fun maybeNotify(json: String) {
        val obj = try {
            JSONObject(json)
        } catch (e: Exception) {
            return
        }
        when (obj.optString("type")) {
            "message" -> {
                val peer = obj.optString("peer")
                if (peer.isNotEmpty() && activeConversationId != peer) {
                    NotificationHelper.showMessageNotification(applicationContext, peer, obj.optString("text"))
                }
            }
            "group_message" -> {
                val groupId = obj.optString("group_id")
                if (groupId.isNotEmpty() && activeConversationId != "group:$groupId") {
                    NotificationHelper.showGroupMessageNotification(
                        applicationContext, groupId, obj.optString("sender_identity_id"), obj.optString("text")
                    )
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        NotificationHelper.createChannel(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Typoon")
            .setContentText("Secure P2P Connection Active")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .build()

        startForeground(NOTIFICATION_ID, notification)

        if (!isRunning) {
            isRunning = true
            // bkz. `bindToWifiIfAvailable` dokümantasyonu — libp2p soketleri
            // (özellikle UPnP arama) `startNetwork`'ten ÖNCE doğru arayüze
            // (WiFi) bağlanabilsin diye burada, ağ başlamadan hemen önce.
            bindToWifiIfAvailable()
            // Güvenlik ağı: sistem bu servisi MainActivity'den bağımsız
            // olarak yeniden başlatırsa (START_STICKY sonrası süreç
            // öldürülüp geri getirilirse), initDatabase VE secret key
            // yükleme hiç çağrılmamış olabilir. Bu çağrılar idempotent —
            // initDatabase zaten açık bir bağlantıyı tekrar açmak
            // zararsızdır (SQLite yeniden CREATE TABLE IF NOT EXISTS
            // çalıştırır), loadIfPresent de zaten yüklenmiş key'lerin
            // üzerine aynı değerleri yazar.
            P2PLib.initDatabase(applicationContext.filesDir.absolutePath)
            if (P2PLib.hasStoredIdentity()) {
                com.p2p.messenger.util.IdentityManager.loadIfPresent(applicationContext)
            }
            // Node modundan BAĞIMSIZ her zaman yüklenir — mesajlaşmanın
            // güvenilirliği için gerekli (sıra dışı/gecikmeli mesajlar).
            com.p2p.messenger.util.SkippedKeyManager.ensureLoaded(applicationContext)
            // Spec dışı düzeltme: önceden SADECE node modu açıkken
            // yükleniyordu ("canlı mesaj trafiğini arşivleme" kuralı hâlâ
            // node moduna bağlı, bkz. Rust archive_message çağıranları) —
            // ama artık node modu KAPALI cihazlar da `HistorySyncResponse`
            // ile öğrendikleri geçmişi yerelde kalıcı kılmak için bu
            // anahtara ihtiyaç duyuyor (aksi halde uygulama her
            // kapatılıp açıldığında geçmiş "kayboluyormuş" gibi
            // görünüyordu — aslında her seferinde ağdan yeniden
            // çekilmesi gerekiyordu, karşı taraf o an erişilemezse bu
            // başarısız oluyordu).
            com.p2p.messenger.util.MessageHistoryManager.ensureHistoryKeyLoaded(applicationContext)
            val nodeMode = isNodeModeEnabled(applicationContext)
            P2PLib.startNetwork(nodeMode)
            handler.post(pollRunnable)
        }

        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        handler.removeCallbacks(pollRunnable)
        wifiNetworkCallback?.let {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(it)
            } catch (e: Exception) {
                // Zaten kayıtlı değilse (ör. WiFi hiç bağlanmadıysa) sessizce yok say.
            }
        }
        wifiNetworkCallback = null
    }

    /**
     * Spec dışı, hata ayıklama düzeltmesi: gerçek bir cihazda, router'da
     * UPnP açık olmasına rağmen UPnP taraması hep "gateway bulunamadı"
     * döndürdüğü rapor edildi. Kök sebep muhtemelen şu: Android telefonlar
     * genelde WiFi'ye bağlıyken bile mobil veriyi arka planda AÇIK tutar —
     * Rust tarafındaki UPnP arama soketi (igd_next crate'i) `0.0.0.0`'a
     * bind olur, yani HANGİ arayüzden çıkacağını işletim sisteminin
     * varsayılan yönlendirme tablosuna bırakır. Bu, WiFi yerine YANLIŞLIKLA
     * mobil veri üzerinden gönderilebilir — router hiç görmez, "bulunamadı"
     * sonucu WiFi UPnP'siyle hiç ilgisi olmadan ortaya çıkar (aynı sınıf
     * karışıklık teorik olarak libp2p'nin diğer soketlerini de
     * etkileyebilir).
     *
     * `ConnectivityManager.bindProcessToNetwork` bu süreçte AÇILAN TÜM yeni
     * soketleri (Rust tarafındakiler dahil, aynı process'te çalıştıkları
     * için) belirtilen ağa zorlar — WiFi varsa ona bağlanır, WiFi
     * kaybolursa serbest bırakılır (mobil veriye doğal olarak döner, ör.
     * hiç WiFi'si olmayan bir kullanıcı için).
     */
    private fun bindToWifiIfAvailable() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        // Spec dışı, hata ayıklama düzeltmesi: SADECE WiFi transport'u
        // kontrol etmek YETERSİZ — bir cihazın WiFi radyosu açık ve
        // bilinen/kayıtlı bir ağa bağlı olabilir ama o ağın GERÇEK internet
        // erişimi olmayabilir (ör. boşta duran bir ev ağı, portal arkasında
        // kalmış bir misafir ağı). Sadece transport'a bakıp bağlarsak, o an
        // mobil veri üzerinden ÇALIŞAN bir cihazı internetsiz bir WiFi'ye
        // zorlayıp TAMAMEN bağlantısız bırakabiliriz — NET_CAPABILITY_INTERNET
        // + NET_CAPABILITY_VALIDATED (sistem gerçekten "bu ağdan internete
        // çıkabiliyorum" diye doğruladı) ikisi de gerekli.
        val active = cm.activeNetwork
        val activeCaps = active?.let { cm.getNetworkCapabilities(it) }
        if (activeCaps.isValidatedWifi()) {
            cm.bindProcessToNetwork(active)
        }
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                cm.bindProcessToNetwork(network)
            }
            override fun onLost(network: Network) {
                cm.bindProcessToNetwork(null)
            }
        }
        wifiNetworkCallback = callback
        try {
            cm.registerNetworkCallback(request, callback)
        } catch (e: Exception) {
            // Kayıt başarısız olursa (ör. çok eski/tuhaf bir cihaz) sessizce
            // devam — süreç varsayılan sistem yönlendirmesini kullanır,
            // bugünkünden daha kötü olmaz.
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "P2P Background Service",
            NotificationManager.IMPORTANCE_LOW
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }
}
