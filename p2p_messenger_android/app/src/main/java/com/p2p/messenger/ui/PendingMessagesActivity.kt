package com.p2p.messenger.ui

import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray

/**
 * Spec dışı, kullanıcı isteği: Ayarlar'dan açılan, henüz karşı taraftan
 * "ack" alınmamış (bkz. lib.rs `awaiting_confirmation`/`regen_content` —
 * `TEXT_RETRY_GIVE_UP_MS`'ye, 2 güne, kadar otomatik olarak taze bir
 * ratchet adımıyla yeniden denenir) mesajların listesi. Her satırda hedef
 * (kişi/grup), metin önizlemesi, en son deneme zamanı ve bir "İptal"
 * düğmesi (bkz. lib.rs `cancel_pending_message`) gösterilir.
 */
class PendingMessagesActivity : AppCompatActivity() {

    private lateinit var recycler: RecyclerView
    private lateinit var txtEmpty: TextView
    private lateinit var adapter: PendingMessagesAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pending_messages)
        supportActionBar?.title = getString(R.string.title_pending_messages)

        recycler = findViewById(R.id.recyclerPendingMessages)
        txtEmpty = findViewById(R.id.txtNoPendingMessages)
        adapter = PendingMessagesAdapter(
            mutableListOf(),
            onCancel = { item -> cancelPending(item) },
            onRetry = { item -> retryPending(item) }
        )
        recycler.layoutManager = LinearLayoutManager(this)
        recycler.adapter = adapter

        loadPendingMessages()
    }

    /** A message acknowledged or given up while this screen is open. */
    private val listener: (String) -> Unit = { json ->
        if (json.contains("\"type\":\"ack\"") || json.contains("\"type\":\"status\"")) {
            runOnUiThread { loadPendingMessages() }
        }
    }

    override fun onPause() {
        super.onPause()
        com.p2p.messenger.service.P2PService.removeMessageListener(listener)
    }

    override fun onResume() {
        super.onResume()
        com.p2p.messenger.service.P2PService.addMessageListener(listener)
        // Bu ekran ASLINDA canlı bir olay akışına abonedir: `listener` bir
        // ack/status olayında listeyi yeniden yükler (bir mesaj bu ekran
        // açıkken onaylanırsa satır bayatlamasın — bkz. `retry_unconfirmed_
        // messages`, arka planda P2PService poll döngüsü çalışmaya devam
        // eder). Her ön plana gelişte tekrar tazelemek de basit ve yeterli.
        loadPendingMessages()
    }

    private fun loadPendingMessages() {
        lifecycleScope.launch {
            val items = withContext(Dispatchers.IO) { fetchPendingMessages() }
            adapter.submitList(items)
            txtEmpty.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    /**
     * `peer_device_fingerprint`/`group_id`'yi (bkz. lib.rs
     * `PendingMessageSummary`) insan-okur bir isme çevirir — `listContacts`/
     * `listGroups` zaten var olan JNI çağrılarını yeniden kullanır, isim
     * çözümleme mantığını burada TEKRAR İCAT ETMEZ (bkz. NotificationHelper
     * aynı desen).
     */
    private fun fetchPendingMessages(): List<PendingMessagesAdapter.Item> {
        val pendingJson = try {
            JSONArray(P2PLib.listPendingMessages())
        } catch (e: Exception) {
            return emptyList()
        }
        val contactsByFp = mutableMapOf<String, String>()
        try {
            val contacts = JSONArray(P2PLib.listContacts())
            for (i in 0 until contacts.length()) {
                val c = contacts.getJSONObject(i)
                val fp = c.optString("active_device_fingerprint")
                if (fp.isNotEmpty()) contactsByFp[fp] = c.optString("display_name")
            }
        } catch (e: Exception) {
            // İsim çözülemedi — fingerprint kısaltması gösterilir.
        }
        val groupsById = mutableMapOf<String, String>()
        try {
            val groups = JSONArray(P2PLib.listGroups())
            for (i in 0 until groups.length()) {
                val g = groups.getJSONObject(i)
                groupsById[g.optString("group_id")] = g.optString("name")
            }
        } catch (e: Exception) {
            // İsim çözülemedi — group_id kısaltması gösterilir.
        }

        val result = mutableListOf<PendingMessagesAdapter.Item>()
        for (i in 0 until pendingJson.length()) {
            val obj = pendingJson.optJSONObject(i) ?: continue
            val groupId = if (obj.isNull("group_id")) null else obj.optString("group_id").ifEmpty { null }
            val fp = obj.optString("peer_device_fingerprint")
            val targetName = if (groupId != null) {
                groupsById[groupId] ?: groupId.take(8)
            } else {
                contactsByFp[fp] ?: fp.take(8)
            }
            result.add(
                PendingMessagesAdapter.Item(
                    messageId = obj.optString("message_id"),
                    targetName = targetName,
                    deviceName = obj.optString("device_name"),
                    text = com.p2p.messenger.util.Quote.plain(obj.optString("text")),
                    lastAttemptAtMs = obj.optLong("last_attempt_at")
                )
            )
        }
        // En son denenen en üstte — kullanıcının "hangisi hâlâ takılı"
        // sorusuna en alakalı sırayla cevap verir.
        result.sortByDescending { it.lastAttemptAtMs }
        return result
    }

    private fun cancelPending(item: PendingMessagesAdapter.Item) {
        lifecycleScope.launch {
            val ok = withContext(Dispatchers.IO) {
                try {
                    P2PLib.cancelPendingMessage(item.messageId)
                } catch (e: Exception) {
                    false
                }
            }
            if (ok) {
                adapter.removeById(item.messageId)
                Toast.makeText(this@PendingMessagesActivity, R.string.msg_pending_message_cancelled, Toast.LENGTH_SHORT).show()
                if (adapter.itemCount == 0) txtEmpty.visibility = View.VISIBLE
            }
        }
    }

    /**
     * Spec dışı, kullanıcı isteği: bekleyen mesajlar listesindeki manuel
     * "Şimdi Dene" düğmesi — bkz. lib.rs `retry_pending_message_now`
     * (SADECE bu mesajın bir sonraki deneme zamanını HEMEN'e çeker; gerçek
     * gönderim denemesi bir sonraki `poll_events` turunda, saniyede bir
     * zaten çalışan arka plan döngüsünde olur — burada AYRI bir ağ I/O'su
     * YAPILMAZ, pil dostu). Listeyi hemen kaldırmıyoruz (İptal'in aksine) —
     * mesaj hâlâ bekliyor, sadece denemesi öne çekildi; bir sonraki
     * `onResume`/tazelemede ya onaylanmış (listeden düşmüş) ya da hâlâ
     * bekliyor (aynı satırda, güncel "son deneme" zamanıyla) görünecek.
     */
    private fun retryPending(item: PendingMessagesAdapter.Item) {
        lifecycleScope.launch {
            val ok = withContext(Dispatchers.IO) {
                try {
                    P2PLib.retryPendingMessageNow(item.messageId)
                } catch (e: Exception) {
                    false
                }
            }
            if (ok) {
                Toast.makeText(this@PendingMessagesActivity, R.string.msg_pending_message_retrying, Toast.LENGTH_SHORT).show()
            }
        }
    }
}
