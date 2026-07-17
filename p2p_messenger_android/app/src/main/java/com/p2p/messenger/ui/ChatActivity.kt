package com.p2p.messenger.ui

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Spec 3 (Mesajlaşma) — tek bir kişiyle 1:1 sohbet ekranı.
 *
 * Mesaj geçmişi kalıcılığı, kullanıcı tercihine bağlıdır (spec dışı):
 * SADECE node modu açık olan cihazda ("server olmayı tercih eden" cihaz)
 * mesajlar yerelde şifreli olarak arşivlenir (bkz. MessageHistoryManager,
 * lib.rs archive_message/load_message_history). Node modu kapalıysa
 * geçmiş bu Activity kapandığında kaybolur — sadece anlık gösterim olur.
 */
class ChatActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PEER_DEVICE_FINGERPRINT = "peer_device_fingerprint"
        const val EXTRA_PEER_DISPLAY_NAME = "peer_display_name"
        private const val HISTORY_LOAD_LIMIT = 200
        private const val HISTORY_SYNC_LIMIT = 30
        private const val SESSION_POLL_INTERVAL_MS = 800L
    }

    private lateinit var peerDeviceFingerprint: String
    private val localMessages = mutableListOf<SimpleChatAdapter.Item>()
    private lateinit var adapter: SimpleChatAdapter
    private lateinit var recycler: RecyclerView
    private lateinit var connectingBanner: View
    /** bkz. `loadHistoryIfAvailable`/`handleIncomingEvent` "history_sync" —
     *  yereldeki arşiv boşsa karşı tarafa (node modu açıksa) bir geçmiş
     *  isteği gönderilir; yanıt gelene kadar bu true kalır ki yanıt geldiğinde
     *  onu listenin başına eklemeyi bilelim (peer değişince sıfırlanır). */
    private var historySyncPending = false

    private val sessionPollHandler = Handler(Looper.getMainLooper())
    private val sessionPollRunnable = object : Runnable {
        override fun run() {
            val connected = try {
                P2PLib.hasActiveSession(peerDeviceFingerprint)
            } catch (e: Exception) {
                false
            }
            connectingBanner.visibility = if (connected) View.GONE else View.VISIBLE
            if (!connected) {
                sessionPollHandler.postDelayed(this, SESSION_POLL_INTERVAL_MS)
            }
        }
    }

    /**
     * Gelen olaylar artık düz metin DEĞİL, `{"type":...}` etiketli bir JSON
     * (bkz. Rust `receive_message` dokümantasyonu — edit/delete/status'u aynı
     * String kanalından taşıyabilmek için). `peer` alanı, bu olayın HANGİ
     * karşı tarafa ait olduğunu taşır — önceden bu bilgi hiç taşınmıyordu
     * ve birden fazla sohbet açıkken gelen her mesaj, o an ekranda hangi
     * ChatActivity varsa ona ekleniyordu (yanlış sohbete sızma riski).
     */
    private val messageListener: (String) -> Unit = { json ->
        try {
            val obj = JSONObject(json)
            if (obj.optString("peer") == peerDeviceFingerprint) {
                runOnUiThread { handleIncomingEvent(obj) }
            }
        } catch (e: Exception) {
            // Ayrıştırılamayan olay — sessizce yok say.
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)

        connectingBanner = findViewById(R.id.layoutConnecting)
        recycler = findViewById(R.id.recyclerMessages)
        adapter = SimpleChatAdapter(localMessages)
        adapter.onItemLongPress = { item -> showEditDeleteDialog(item) }
        recycler.layoutManager = LinearLayoutManager(this)
        recycler.adapter = adapter

        val input = findViewById<EditText>(R.id.edtMessage)
        findViewById<Button>(R.id.btnSend).setOnClickListener {
            val text = input.text.toString()
            if (text.isBlank()) return@setOnClickListener
            input.text.clear()
            sendNewMessage(text)
        }

        if (!bindToIntent(intent)) {
            finish()
            return
        }
    }

    /**
     * Spec dışı sağlamlaştırma: hem `onCreate` hem `onNewIntent` tarafından
     * çağrılır. `PendingIntent`'ler `FLAG_ACTIVITY_CLEAR_TOP` taşıdığından
     * (bkz. NotificationHelper), geri yığında zaten bir `ChatActivity`
     * varsa Android yeni bir örnek OLUŞTURMAZ — var olanı `onNewIntent` ile
     * çağırır. Önceden bu override edilmediği için bildirime tıklamak,
     * (varsa) yığındaki ESKİ sohbeti öne getiriyordu, bildirimin ait olduğu
     * sohbeti DEĞİL. Aynı kişi için gelen bir bildirimse (peer değişmedi)
     * mesaj listesini gereksiz yere sıfırlamıyoruz.
     *
     * Dönüş: `false` ise (peer fingerprint hiç yok) çağıran `finish()`
     * çağırmalı.
     */
    private fun bindToIntent(intent: Intent): Boolean {
        val newPeer = intent.getStringExtra(EXTRA_PEER_DEVICE_FINGERPRINT) ?: return false
        val displayName = intent.getStringExtra(EXTRA_PEER_DISPLAY_NAME) ?: newPeer.take(8)
        supportActionBar?.title = displayName

        if (::peerDeviceFingerprint.isInitialized && peerDeviceFingerprint == newPeer) {
            // Aynı sohbet için tekrar bir intent geldi (ör. aynı kişiden
            // ardışık bildirimler) — durumu sıfırlamaya gerek yok.
            return true
        }

        peerDeviceFingerprint = newPeer
        P2PService.activeConversationId = peerDeviceFingerprint

        localMessages.clear()
        adapter.notifyDataSetChanged()
        historySyncPending = false
        connectingBanner.visibility = View.VISIBLE
        sessionPollHandler.removeCallbacks(sessionPollRunnable)
        sessionPollHandler.post(sessionPollRunnable)

        loadHistoryIfAvailable()

        // Spec dışı sağlamlaştırma: sohbeti AÇAR açmaz (ilk mesaj yazılmadan
        // önce) el sıkışmayı proaktif başlatıyoruz — bkz. Rust
        // `ensure_handshake` notu. `sessionPollRunnable`, bu tamamlanana
        // kadar üstte bir "Bağlanılıyor..." göstergesi tutar.
        try {
            P2PLib.ensureHandshake(peerDeviceFingerprint)
        } catch (e: Exception) {
            // yoksay — sessionPollRunnable zaten periyodik kontrol edecek
        }
        return true
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!bindToIntent(intent)) {
            finish()
        }
    }

    /**
     * Spec dışı sağlamlaştırma: mesajı HER ZAMAN iyimser (optimistic) olarak
     * gösteriyoruz — Rust artık gönderim anında başarısız olsa bile mesajı
     * arka planda otomatik olarak yeniden dener (bkz. lib.rs
     * `pending_envelopes`) ve her durumda geçerli bir `message_id` ile
     * ilk durumu (`sent`/`pending`) döner. "pending" ise ikon saat simgesini
     * gösterir, arka planda kesinleşince bir "status" olayıyla güncellenir.
     */
    private fun sendNewMessage(text: String) {
        val result = P2PLib.sendMessage(peerDeviceFingerprint, text)
        val (messageId, status) = if (result.startsWith("Error:")) {
            Toast.makeText(this, result, Toast.LENGTH_SHORT).show()
            UUID.randomUUID().toString() to SimpleChatAdapter.Status.ERROR
        } else {
            try {
                val obj = JSONObject(result)
                obj.optString("message_id") to parseStatus(obj.optString("status"))
            } catch (e: Exception) {
                UUID.randomUUID().toString() to SimpleChatAdapter.Status.ERROR
            }
        }
        adapter.addMessage(SimpleChatAdapter.Item(messageId = messageId, text = text, isMine = true, status = status))
        recycler.scrollToPosition(localMessages.size - 1)
    }

    private fun parseStatus(status: String): SimpleChatAdapter.Status = when (status) {
        "sent" -> SimpleChatAdapter.Status.SENT
        "error" -> SimpleChatAdapter.Status.ERROR
        else -> SimpleChatAdapter.Status.PENDING
    }

    private fun handleIncomingEvent(obj: JSONObject) {
        when (obj.optString("type")) {
            "message" -> {
                adapter.addMessage(
                    SimpleChatAdapter.Item(
                        messageId = obj.optString("message_id"),
                        text = obj.optString("text"),
                        isMine = false
                    )
                )
                recycler.scrollToPosition(localMessages.size - 1)
            }
            "edit" -> adapter.applyEdit(obj.optString("message_id"), obj.optString("text"))
            "delete" -> adapter.applyDelete(obj.optString("message_id"))
            "status" -> adapter.applyStatus(obj.optString("message_id"), parseStatus(obj.optString("status")))
            "history_sync" -> applyHistorySync(obj)
        }
    }

    /**
     * Spec dışı: node modu kapalı cihazlarda yerel arşiv boş olduğunda
     * `loadHistoryIfAvailable`'ın gönderdiği `requestHistorySync` isteğine
     * karşı taraftan (node modu açıksa) gelen yanıt. `historySyncPending`
     * false ise (yerelde zaten geçmiş vardı, ya da peer bu sırada
     * değişti) sessizce yok sayılır — tekrar eklenmesin diye.
     */
    private fun applyHistorySync(obj: JSONObject) {
        if (!historySyncPending) return
        historySyncPending = false
        val array = obj.optJSONArray("messages") ?: return
        if (array.length() == 0) return
        val synced = (0 until array.length()).map { i ->
            val m = array.getJSONObject(i)
            SimpleChatAdapter.Item(
                messageId = UUID.randomUUID().toString(),
                text = m.optString("text"),
                isMine = m.optString("direction") == "sent",
                timestamp = m.optLong("timestamp", System.currentTimeMillis())
            )
        }
        localMessages.addAll(0, synced)
        adapter.notifyItemRangeInserted(0, synced.size)
    }

    /** Kendi mesajımıza uzun basınca: Düzenle/Sil seçenekleri. */
    private fun showEditDeleteDialog(item: SimpleChatAdapter.Item) {
        val options = arrayOf(getString(R.string.action_edit_message), getString(R.string.action_delete_message))
        AlertDialog.Builder(this)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> showEditMessageDialog(item)
                    1 -> confirmDeleteMessage(item)
                }
            }
            .show()
    }

    private fun showEditMessageDialog(item: SimpleChatAdapter.Item) {
        val input = EditText(this)
        input.setText(item.text)
        input.hint = getString(R.string.lbl_edit_message_hint)
        AlertDialog.Builder(this)
            .setTitle(R.string.action_edit_message)
            .setView(input)
            .setPositiveButton(R.string.action_edit_message) { _, _ ->
                val newText = input.text.toString()
                if (newText.isBlank()) return@setPositiveButton
                val result = P2PLib.editMessage(peerDeviceFingerprint, item.messageId, newText)
                if (result.startsWith("Error:")) {
                    Toast.makeText(this, result, Toast.LENGTH_SHORT).show()
                } else {
                    adapter.applyEdit(item.messageId, newText)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDeleteMessage(item: SimpleChatAdapter.Item) {
        AlertDialog.Builder(this)
            .setMessage(R.string.confirm_delete_message)
            .setPositiveButton(R.string.action_delete_message) { _, _ ->
                val result = P2PLib.deleteMessage(peerDeviceFingerprint, item.messageId)
                if (result.startsWith("Error:")) {
                    Toast.makeText(this, result, Toast.LENGTH_SHORT).show()
                } else {
                    adapter.applyDelete(item.messageId)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Node modu açıksa (dolayısıyla history key yüklüyse) bu kişiyle olan
     * şifreli arşivi çözüp gösterir. Node modu kapalıysa veya arşiv boşsa,
     * yerelde hiç geçmiş yoksa karşı tarafa (chat peer) şifreli bir
     * `HistorySyncRequest` gönderilir — o cihaz node modu açıksa zaten bu
     * konuşmanın her iki yönünü de arşivlemiştir (bkz.
     * `P2PLib.requestHistorySync`). Yanıt asenkron gelir; bkz.
     * `applyHistorySync`.
     *
     * BİLİNEN SINIR: arşiv (`ArchivedMessage`) bir `message_id` taşımıyor
     * (DB şeması bunu hiç saklamadı) — bu yüzden geçmişten yüklenen
     * mesajlar için rastgele bir yerel id üretiliyor. Bu satırlar teknik
     * olarak "uzun basılabilir" ama gerçek edit/delete hedefi olamazlar
     * (karşı taraf farklı bir id ile gönderdi) — spec dışı bir sınırlama.
     */
    private fun loadHistoryIfAvailable() {
        val json = try {
            P2PLib.getMessageHistory(peerDeviceFingerprint, HISTORY_LOAD_LIMIT)
        } catch (e: Exception) {
            return
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            return
        }
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            val direction = obj.optString("direction")
            val text = obj.optString("text")
            val timestamp = obj.optLong("timestamp", System.currentTimeMillis())
            localMessages.add(
                SimpleChatAdapter.Item(
                    messageId = UUID.randomUUID().toString(),
                    text = text,
                    isMine = direction == "sent",
                    timestamp = timestamp
                )
            )
        }
        if (localMessages.isNotEmpty()) {
            adapter.notifyItemRangeInserted(0, localMessages.size)
            recycler.scrollToPosition(localMessages.size - 1)
        } else {
            historySyncPending = true
            try {
                P2PLib.requestHistorySync(peerDeviceFingerprint, HISTORY_SYNC_LIMIT)
            } catch (e: Exception) {
                historySyncPending = false
            }
        }
    }

    override fun onResume() {
        super.onResume()
        P2PService.addMessageListener(messageListener)
        P2PService.activeConversationId = peerDeviceFingerprint
        sessionPollHandler.post(sessionPollRunnable)
    }

    override fun onPause() {
        super.onPause()
        P2PService.removeMessageListener(messageListener)
        if (P2PService.activeConversationId == peerDeviceFingerprint) {
            P2PService.activeConversationId = null
        }
        sessionPollHandler.removeCallbacks(sessionPollRunnable)
    }
}
