package com.p2p.messenger.ui

import android.content.Intent
import android.os.Bundle
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
 * Spec 5 (Grup mesajlaşma) — gerçek grup sohbet ekranı. Önceden
 * `sendGroupMessage` her üyeye ayrı ayrı normal bir 1:1 mesaj olarak
 * gönderiliyordu AMA alıcı tarafta bunun bir grup mesajı olduğunu belirten
 * hiçbir bilgi yoktu — gelen mesaj göndericinin 1:1 sohbetine karışıyordu,
 * grup diye ayrı bir yer yoktu. Artık `MessageContent::Text.group_id`
 * (bkz. packet.rs) sayesinde `receive_message` bunu "group_message" olayı
 * olarak ayırt edip buraya yönlendirebiliyor.
 *
 * BİLİNEN SINIR: grup mesajları yerel arşive (node modu) yazılmıyor ve bu
 * ekran geçmiş yüklemez — sadece ekran açıkken canlı gelen/giden mesajları
 * gösterir (1:1 ChatActivity'nin aksine).
 */
class GroupChatActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_GROUP_ID = "group_id"
        const val EXTRA_GROUP_NAME = "group_name"
    }

    private lateinit var groupId: String
    private val localMessages = mutableListOf<SimpleChatAdapter.Item>()
    private lateinit var adapter: SimpleChatAdapter
    private lateinit var recycler: RecyclerView

    /** `peer` alanı burada anlamlı değil (grup mesajı birden çok 1:1
     *  bağlantı üzerinden pairwise geliyor) — bunun yerine `group_id`'ye
     *  bakıyoruz. Sadece "group_message" tipi olaylarla ilgileniyoruz. */
    private val messageListener: (String) -> Unit = { json ->
        try {
            val obj = JSONObject(json)
            if (obj.optString("type") == "group_message" && obj.optString("group_id") == groupId) {
                runOnUiThread { handleIncomingGroupMessage(obj) }
            }
        } catch (e: Exception) {
            // Ayrıştırılamayan olay — sessizce yok say.
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)

        // Grup sohbetinde tek bir "el sıkışma" durumu yok (her üyeyle ayrı
        // bir 1:1 bağlantı) — bu banner burada anlamlı değil, gizli kalır.
        findViewById<View>(R.id.layoutConnecting).visibility = View.GONE

        recycler = findViewById(R.id.recyclerMessages)
        adapter = SimpleChatAdapter(localMessages)
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
     * bkz. ChatActivity.bindToIntent aynı notu — `FLAG_ACTIVITY_CLEAR_TOP`
     * yığındaki var olan bir `GroupChatActivity`'yi `onNewIntent` ile
     * çağırdığında, önceden bu override edilmediği için bildirim yanlış
     * (eski) grubu öne getiriyordu.
     */
    private fun bindToIntent(intent: Intent): Boolean {
        val newGroupId = intent.getStringExtra(EXTRA_GROUP_ID) ?: return false
        val groupName = intent.getStringExtra(EXTRA_GROUP_NAME) ?: newGroupId.take(8)
        supportActionBar?.title = groupName

        if (::groupId.isInitialized && groupId == newGroupId) {
            return true
        }

        groupId = newGroupId
        P2PService.activeConversationId = "group:$groupId"
        localMessages.clear()
        adapter.notifyDataSetChanged()
        return true
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!bindToIntent(intent)) {
            finish()
        }
    }

    private fun sendNewMessage(text: String) {
        val ok = try {
            P2PLib.sendGroupMessage(groupId, text)
        } catch (e: Exception) {
            false
        }
        if (!ok) {
            Toast.makeText(this, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
        }
        // Grup fan-out'unun her üyeye giden kopyası ayrı bir message_id
        // taşıyor (bkz. lib.rs send_group_message) — buradaki tek "kendi
        // balonumuz" o kopyaların hiçbirine karşılık gelmiyor, sadece
        // yerel/optimistic bir gösterim. Bu yüzden edit/delete şu an grup
        // mesajları için desteklenmiyor (uzun basma yok).
        adapter.addMessage(
            SimpleChatAdapter.Item(
                messageId = UUID.randomUUID().toString(),
                text = text,
                isMine = true,
                status = if (ok) SimpleChatAdapter.Status.SENT else SimpleChatAdapter.Status.ERROR
            )
        )
        recycler.scrollToPosition(localMessages.size - 1)
    }

    private fun handleIncomingGroupMessage(obj: JSONObject) {
        val senderIdentityId = obj.optString("sender_identity_id")
        val senderName = resolveContactNameByIdentity(senderIdentityId) ?: senderIdentityId.take(8)
        adapter.addMessage(
            SimpleChatAdapter.Item(
                messageId = obj.optString("message_id"),
                text = obj.optString("text"),
                isMine = false,
                senderName = senderName
            )
        )
        recycler.scrollToPosition(localMessages.size - 1)
    }

    private fun resolveContactNameByIdentity(identityId: String): String? {
        return try {
            val array = JSONArray(P2PLib.listContacts())
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                if (obj.optString("identity_id") == identityId) {
                    return obj.optString("display_name")
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    override fun onResume() {
        super.onResume()
        P2PService.addMessageListener(messageListener)
        P2PService.activeConversationId = "group:$groupId"
    }

    override fun onPause() {
        super.onPause()
        P2PService.removeMessageListener(messageListener)
        if (P2PService.activeConversationId == "group:$groupId") {
            P2PService.activeConversationId = null
        }
    }
}
