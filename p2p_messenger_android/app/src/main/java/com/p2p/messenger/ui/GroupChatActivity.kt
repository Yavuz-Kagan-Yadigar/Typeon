package com.p2p.messenger.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.hexToBytes
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
    private lateinit var txtToolbarTitle: TextView
    private lateinit var imgToolbarAvatar: ImageView

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

        // bkz. ChatActivity aynı notu — grup için gerçek bir "grup
        // fotoğrafı" kavramı yok, bu yüzden AvatarUtil'in isimden ürettiği
        // rozet gösterilir (fotoğrafsız kişilerle aynı görsel dil).
        val toolbarTitleView = layoutInflater.inflate(R.layout.actionbar_chat_title, null)
        txtToolbarTitle = toolbarTitleView.findViewById(R.id.txtToolbarTitle)
        imgToolbarAvatar = toolbarTitleView.findViewById(R.id.imgToolbarAvatar)
        toolbarTitleView.findViewById<View>(R.id.txtToolbarSubtitle).visibility = View.GONE
        supportActionBar?.apply {
            setDisplayShowCustomEnabled(true)
            setDisplayShowTitleEnabled(false)
            customView = toolbarTitleView
        }

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
        txtToolbarTitle.text = groupName
        AvatarUtil.renderInto(imgToolbarAvatar, null, groupName)

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
        val sender = resolveContactByIdentity(senderIdentityId)
        val senderName = sender?.displayName ?: senderIdentityId.take(8)
        adapter.addMessage(
            SimpleChatAdapter.Item(
                messageId = obj.optString("message_id"),
                text = obj.optString("text"),
                isMine = false,
                senderName = senderName,
                senderAvatarJpeg = sender?.avatarHex?.let { hexToBytes(it) }
            )
        )
        recycler.scrollToPosition(localMessages.size - 1)
    }

    private data class ContactLookup(val displayName: String, val avatarHex: String?)

    private fun resolveContactByIdentity(identityId: String): ContactLookup? {
        return try {
            val array = JSONArray(P2PLib.listContacts())
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                if (obj.optString("identity_id") == identityId) {
                    return ContactLookup(
                        displayName = obj.optString("display_name"),
                        avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
                    )
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
