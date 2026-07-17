package com.p2p.messenger

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.p2p.messenger.ui.ChatActivity
import com.p2p.messenger.ui.ChatAdapter
import com.p2p.messenger.ui.GroupChatActivity
import com.p2p.messenger.util.hexToBytes
import org.json.JSONArray

/**
 * Spec 3 minimum kapsamı: bilinen kişilerin + grupların TEK bir listesi,
 * tıklanınca ilgili sohbet ekranını açar. `ListAdapter`/`DiffUtil` tabanlı
 * gerçek bir adapter kullanır (bkz. ChatAdapter) ve periyodik olarak
 * yenilenir. Node modu kapalıyken kişiler için "son mesaj" alanı boş kalır
 * (mesaj geçmişi o durumda hiç saklanmıyor); gruplar için zaten hiç mesaj
 * arşivi yok (bkz. GroupChatActivity dosya başı notu), bu yüzden hep boş.
 *
 * Spec dışı: önceden ayrı bir "Gruplar" sekmesi vardı — kullanıcı isteği
 * üzerine kaldırıldı, grup listesi/oluşturma buraya taşındı (bkz.
 * `btnCreateGroup`, eski GroupsFragment'in mantığı).
 */
class ChatsFragment : Fragment() {

    private lateinit var adapter: ChatAdapter
    private lateinit var noContactsText: View
    private val refreshHandler = Handler(Looper.getMainLooper())
    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshList()
            refreshHandler.postDelayed(this, 5000)
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_chats, container, false)

        val recycler = view.findViewById<RecyclerView>(R.id.recyclerChats)
        noContactsText = view.findViewById(R.id.txtNoContacts)
        recycler.layoutManager = LinearLayoutManager(requireContext())

        adapter = ChatAdapter { message ->
            when {
                message.isGroup -> openGroupChat(message)
                message.contactId.isNotEmpty() -> {
                    val intent = Intent(requireContext(), ChatActivity::class.java)
                    intent.putExtra(ChatActivity.EXTRA_PEER_DEVICE_FINGERPRINT, message.contactId)
                    intent.putExtra(ChatActivity.EXTRA_PEER_DISPLAY_NAME, message.displayName)
                    startActivity(intent)
                }
            }
        }
        adapter.onContactLongClick = { message -> showChatLongPressMenu(message) }
        recycler.adapter = adapter

        view.findViewById<FloatingActionButton>(R.id.btnCreateGroup).setOnClickListener {
            showCreateGroupDialog()
        }

        refreshList()
        return view
    }

    private fun openGroupChat(message: ChatAdapter.ChatMessage) {
        val intent = Intent(requireContext(), GroupChatActivity::class.java)
        intent.putExtra(GroupChatActivity.EXTRA_GROUP_ID, message.contactId)
        intent.putExtra(GroupChatActivity.EXTRA_GROUP_NAME, message.displayName)
        startActivity(intent)
    }

    /**
     * Spec dışı, uzun basma menüsü: kullanıcıyla birlikte netleştirilen iki
     * ayrı seçenek — "sohbet geçmişini temizle" (yumuşak, tek onay, kişi
     * paired kalır) ve "kişiyi sil" (sert, ÇİFT onay, eşleşme dahil her şey
     * silinir). SADECE kişiler için — gruplar `realContactId` taşımadığından
     * (bkz. ChatAdapter) bu menü zaten tetiklenmez.
     */
    private fun showChatLongPressMenu(message: ChatAdapter.ChatMessage) {
        val options = arrayOf(
            getString(R.string.action_clear_chat_history),
            getString(R.string.action_delete_contact)
        )
        AlertDialog.Builder(requireContext())
            .setTitle(message.displayName)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> confirmClearChatHistory(message)
                    1 -> confirmDeleteContactStep1(message)
                }
            }
            .show()
    }

    private fun confirmClearChatHistory(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_clear_chat_history)
            .setPositiveButton(R.string.action_clear_chat_history) { _, _ ->
                val result = try {
                    P2PLib.clearChatHistory(message.realContactId)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(requireContext(), result, Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(requireContext(), R.string.msg_chat_history_cleared, Toast.LENGTH_SHORT).show()
                    refreshList()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** İlk onay — bkz. dosya başı notu, bu işlem SERT olduğundan (eşleşme
     *  dahil her şey silinir) çift onay isteniyor. */
    private fun confirmDeleteContactStep1(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_delete_contact_step1)
            .setPositiveButton(R.string.action_delete_contact) { _, _ -> confirmDeleteContactStep2(message) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDeleteContactStep2(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_delete_contact_step2)
            .setPositiveButton(R.string.action_delete_contact) { _, _ ->
                val result = try {
                    P2PLib.deleteContact(message.realContactId)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(requireContext(), result, Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(requireContext(), R.string.msg_contact_deleted, Toast.LENGTH_SHORT).show()
                    refreshList()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** bkz. eski GroupsFragment.showCreateGroupDialog — buraya taşındı. */
    private fun showCreateGroupDialog() {
        val input = EditText(requireContext())
        input.hint = getString(R.string.lbl_new_group_name_hint)
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.action_create_group)
            .setView(input)
            .setPositiveButton(R.string.action_create_group) { _, _ ->
                val name = input.text.toString().trim()
                if (name.isBlank()) return@setPositiveButton
                val groupId = P2PLib.createGroup(name)
                if (groupId.startsWith("Error:")) {
                    Toast.makeText(requireContext(), groupId, Toast.LENGTH_LONG).show()
                } else {
                    refreshList()
                    showAddMembersDialog(groupId)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Kişi listesinden çoklu seçimle grup üyesi ekler (bkz. spec 5.4 —
     *  kurucu davet üretir, her davet edilen mevcut/kurulmakta olan 1:1
     *  bağlantı üzerinden GroupUpdate alır). */
    private fun showAddMembersDialog(groupId: String) {
        val contactsJson = try {
            P2PLib.listContacts()
        } catch (e: Exception) {
            "[]"
        }
        val array = try {
            JSONArray(contactsJson)
        } catch (e: Exception) {
            JSONArray()
        }
        if (array.length() == 0) {
            Toast.makeText(requireContext(), R.string.msg_no_contacts_to_add, Toast.LENGTH_LONG).show()
            return
        }
        val names = (0 until array.length()).map { array.getJSONObject(it).optString("display_name", "Bilinmeyen") }.toTypedArray()
        val identityIds = (0 until array.length()).map { array.getJSONObject(it).optString("identity_id") }
        val checked = BooleanArray(names.size)

        AlertDialog.Builder(requireContext())
            .setTitle(R.string.lbl_add_member_to_group)
            .setMultiChoiceItems(names, checked) { _, which, isChecked -> checked[which] = isChecked }
            .setPositiveButton(R.string.lbl_add_member_to_group) { _, _ ->
                for (i in identityIds.indices) {
                    if (checked[i]) {
                        val ok = P2PLib.inviteToGroup(groupId, identityIds[i])
                        if (!ok) {
                            Toast.makeText(requireContext(), "${names[i]}: ${getString(R.string.error_network)}", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
                refreshList()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    override fun onResume() {
        super.onResume()
        refreshHandler.post(refreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        refreshHandler.removeCallbacks(refreshRunnable)
    }

    private fun refreshList() {
        // NOT: Her yenilemede kişi başına bir getMessageHistory JNI çağrısı
        // yapılıyor (O(n)). Aşama A kapsamındaki küçük kişi sayıları için
        // sorun değil; çok sayıda kişiye ölçeklenecekse Rust tarafında
        // "tüm kişiler için son mesajı tek seferde döndüren" toplu bir
        // sorgu eklenmesi düşünülebilir.
        val contacts = loadContacts()
        val groups = loadGroups()
        noContactsText.visibility = if (contacts.isEmpty() && groups.isEmpty()) View.VISIBLE else View.GONE

        val contactItems = contacts.map { contact ->
            val fingerprint = contact.activeDeviceFingerprint ?: ""
            val lastMessage = if (fingerprint.isNotEmpty()) loadLastMessagePreview(fingerprint) else null
            ChatAdapter.ChatMessage(
                contactId = fingerprint,
                displayName = contact.displayName,
                lastMessage = lastMessage?.text ?: "",
                timestamp = lastMessage?.timestamp ?: 0L,
                unreadCount = 0, // Aşama A'da okunmamış sayacı takip edilmiyor.
                realContactId = contact.contactId,
                avatarJpeg = contact.avatarHex?.let { hexToBytes(it) }
            )
        }
        val groupItems = groups.map { group ->
            ChatAdapter.ChatMessage(
                contactId = group.groupId,
                displayName = group.name,
                lastMessage = resources.getQuantityString(R.plurals.lbl_member_count, group.memberCount, group.memberCount),
                timestamp = 0L,
                avatarJpeg = group.avatarHex?.let { hexToBytes(it) },
                isGroup = true
            )
        }
        adapter.submitList(contactItems + groupItems)
    }

    private data class ContactRow(
        val contactId: String,
        val displayName: String,
        val activeDeviceFingerprint: String?,
        val avatarHex: String?
    )
    private data class GroupRow(val groupId: String, val name: String, val memberCount: Int, val avatarHex: String?)
    private data class LastMessagePreview(val text: String, val timestamp: Long)

    private fun loadContacts(): List<ContactRow> {
        val json = try {
            P2PLib.listContacts()
        } catch (e: Exception) {
            return emptyList()
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            return emptyList()
        }
        return (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            val fingerprint = if (obj.isNull("active_device_fingerprint")) null
                else obj.optString("active_device_fingerprint")
            ContactRow(
                contactId = obj.optString("contact_id"),
                displayName = obj.optString("display_name", "Bilinmeyen"),
                activeDeviceFingerprint = fingerprint,
                avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
            )
        }
    }

    private fun loadGroups(): List<GroupRow> {
        val json = try {
            P2PLib.listGroups()
        } catch (e: Exception) {
            return emptyList()
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            return emptyList()
        }
        return (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            val members = obj.optJSONArray("member_identity_ids")
            GroupRow(
                groupId = obj.optString("group_id"),
                name = obj.optString("name"),
                memberCount = members?.length() ?: 0,
                avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
            )
        }
    }

    /** Node modu kapalıyken (history key yüklenmemişken) bu her zaman
     *  null döner — P2PLib.getMessageHistory boş dizi döndürür. */
    private fun loadLastMessagePreview(peerDeviceFingerprint: String): LastMessagePreview? {
        val json = try {
            P2PLib.getMessageHistory(peerDeviceFingerprint, 1)
        } catch (e: Exception) {
            return null
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            return null
        }
        if (array.length() == 0) return null
        val obj = array.getJSONObject(0)
        return LastMessagePreview(
            text = obj.optString("text", ""),
            timestamp = obj.optLong("timestamp", 0L)
        )
    }
}
