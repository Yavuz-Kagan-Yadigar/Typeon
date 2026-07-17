package com.p2p.messenger.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.*
import androidx.core.app.NotificationCompat
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.util.NotificationHelper
import org.json.JSONObject

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
