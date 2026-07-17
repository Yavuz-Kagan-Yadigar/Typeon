package com.p2p.messenger

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.ui.ChatActivity
import com.p2p.messenger.ui.ChatAdapter
import org.json.JSONArray

/**
 * Spec 3 minimum kapsamı: bilinen kişilerin listesi, tıklanınca sohbet
 * ekranını açar. `ListAdapter`/`DiffUtil` tabanlı gerçek bir adapter
 * kullanır (bkz. ChatAdapter) ve periyodik olarak yenilenir — yeni bir
 * kişi eklendiğinde veya (node modu açıksa) son mesaj değiştiğinde liste
 * güncellenir. Node modu kapalıyken "son mesaj" alanı boş kalır, çünkü
 * mesaj geçmişi o durumda hiç saklanmıyor (bkz. ChatActivity dosya başı
 * notu / kullanıcı tercihi).
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

        adapter = ChatAdapter { peerDeviceFingerprint ->
            if (peerDeviceFingerprint.isNotEmpty()) {
                val intent = Intent(requireContext(), ChatActivity::class.java)
                intent.putExtra(ChatActivity.EXTRA_PEER_DEVICE_FINGERPRINT, peerDeviceFingerprint)
                startActivity(intent)
            }
        }
        recycler.adapter = adapter

        refreshList()
        return view
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
        noContactsText.visibility = if (contacts.isEmpty()) View.VISIBLE else View.GONE

        val chatItems = contacts.map { contact ->
            val fingerprint = contact.activeDeviceFingerprint ?: ""
            val lastMessage = if (fingerprint.isNotEmpty()) loadLastMessagePreview(fingerprint) else null
            ChatAdapter.ChatMessage(
                contactId = fingerprint,
                displayName = contact.displayName,
                lastMessage = lastMessage?.text ?: "",
                timestamp = lastMessage?.timestamp ?: 0L,
                unreadCount = 0 // Aşama A'da okunmamış sayacı takip edilmiyor.
            )
        }
        adapter.submitList(chatItems)
    }

    private data class ContactRow(val displayName: String, val activeDeviceFingerprint: String?)
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
                displayName = obj.optString("display_name", "Bilinmeyen"),
                activeDeviceFingerprint = fingerprint
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
