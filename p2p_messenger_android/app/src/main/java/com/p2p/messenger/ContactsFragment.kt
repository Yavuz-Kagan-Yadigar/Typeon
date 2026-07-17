package com.p2p.messenger

import android.app.AlertDialog
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.p2p.messenger.ui.ChatActivity
import com.p2p.messenger.ui.ChatAdapter
import com.p2p.messenger.ui.QrScanActivity
import com.p2p.messenger.util.QrBinaryCodec
import com.p2p.messenger.util.hexToBytes
import org.json.JSONArray

class ContactsFragment : Fragment() {

    private lateinit var adapter: ChatAdapter
    private lateinit var placeholder: View
    private lateinit var recycler: RecyclerView
    private lateinit var imgOwnQr: ImageView
    private lateinit var txtOwnIdentityCode: TextView
    /** bkz. `loadNodeAddressAndGenerateQr` — `getNodeAddress()` swarm
     *  gerçekten dinlemeye başlayana kadar boş dönebilir, bu yüzden ayrı
     *  bir handler ile birkaç kez yeniden denenir (bkz. eski
     *  QrDisplayActivity — bu mantık buraya taşındı). */
    private val qrRetryHandler = Handler(Looper.getMainLooper())
    private val refreshHandler = Handler(Looper.getMainLooper())
    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshList()
            refreshHandler.postDelayed(this, 5000)
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_contacts, container, false)

        view.findViewById<Button>(R.id.btn_scan_qr).setOnClickListener {
            val intent = Intent(requireContext(), QrScanActivity::class.java)
            startActivity(intent)
        }

        view.findViewById<Button>(R.id.btn_manual_add).setOnClickListener {
            showManualAddDialog()
        }

        // Spec dışı, kullanıcı isteği: kendi QR kodumuz artık "My QR"
        // adında ayrı bir düğme/ekrana gitmeden doğrudan bu sekmede
        // görünür — bkz. eski QrDisplayActivity (silindi), üretim mantığı
        // birebir buraya taşındı.
        imgOwnQr = view.findViewById(R.id.imgOwnQr)
        txtOwnIdentityCode = view.findViewById(R.id.txtOwnIdentityCode)
        txtOwnIdentityCode.text = try {
            P2PLib.getIdentityCode()
        } catch (e: Exception) {
            ""
        }
        loadNodeAddressAndGenerateQr(attemptsLeft = 10)

        placeholder = view.findViewById(R.id.contactsPlaceholder)
        recycler = view.findViewById(R.id.recyclerContacts)
        recycler.layoutManager = LinearLayoutManager(requireContext())
        adapter = ChatAdapter { message ->
            if (message.contactId.isNotEmpty()) {
                val intent = Intent(requireContext(), ChatActivity::class.java)
                intent.putExtra(ChatActivity.EXTRA_PEER_DEVICE_FINGERPRINT, message.contactId)
                intent.putExtra(ChatActivity.EXTRA_PEER_DISPLAY_NAME, message.displayName)
                startActivity(intent)
            } else {
                // Kayıt (TOFU) tamamlandı ama karşı tarafla henüz gerçek bir
                // bağlantı/IdentityExchange tamamlanmadı (bkz. Rust
                // pending_identity_exchanges notu) — sohbet açılamaz.
                Toast.makeText(requireContext(), "Bağlantı henüz tamamlanmadı, birazdan tekrar deneyin", Toast.LENGTH_SHORT).show()
            }
        }
        adapter.onContactLongClick = { message -> showChatLongPressMenu(message) }
        recycler.adapter = adapter

        refreshList()
        return view
    }

    /** bkz. dosya başı notu — `getNodeAddress()` boşsa kısa aralıklarla
     *  yeniden dener (sabit bir 0.0.0.0/tcp/0 asla dial edilemez). */
    private fun loadNodeAddressAndGenerateQr(attemptsLeft: Int) {
        if (!isAdded) return
        val nodeAddress = try {
            P2PLib.getNodeAddress()
        } catch (e: Exception) {
            ""
        }
        if (nodeAddress.isEmpty() && attemptsLeft > 0) {
            qrRetryHandler.postDelayed({ loadNodeAddressAndGenerateQr(attemptsLeft - 1) }, 500)
            return
        }
        val qrBytes = try {
            P2PLib.generateQrPacket(nodeAddress)
        } catch (e: Exception) {
            null
        }
        if (qrBytes != null && qrBytes.isNotEmpty()) {
            imgOwnQr.setImageBitmap(encodeBinaryAsQrBitmap(qrBytes, 400, 400))
        }
    }

    /** bkz. eski QrDisplayActivity.encodeBinaryAsQrBitmap — birebir aynı. */
    private fun encodeBinaryAsQrBitmap(data: ByteArray, width: Int, height: Int): Bitmap {
        val text = QrBinaryCodec.bytesToLatin1String(data)
        val hints = mapOf(EncodeHintType.CHARACTER_SET to "ISO-8859-1")
        val bitMatrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height, hints)
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        return bitmap
    }

    /** bkz. ChatsFragment.showChatLongPressMenu aynı notu — iki sekme de
     *  aynı kişi listesini/adapter'ı paylaştığından davranış birebir aynı. */
    private fun showChatLongPressMenu(message: ChatAdapter.ChatMessage) {
        val options = arrayOf(
            getString(R.string.action_clear_chat_history),
            getString(R.string.action_revoke_device),
            getString(R.string.action_delete_contact)
        )
        AlertDialog.Builder(requireContext())
            .setTitle(message.displayName)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> confirmClearChatHistory(message)
                    1 -> confirmRevokeDevice(message)
                    2 -> confirmDeleteContactStep1(message)
                }
            }
            .show()
    }

    /** bkz. ChatsFragment.confirmRevokeDevice aynı notu. */
    private fun confirmRevokeDevice(message: ChatAdapter.ChatMessage) {
        if (message.contactId.isEmpty()) return
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_revoke_device)
            .setPositiveButton(R.string.action_revoke_device) { _, _ ->
                val result = try {
                    P2PLib.revokeContactDevice(message.realContactId, message.contactId)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(requireContext(), result, Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(requireContext(), R.string.msg_device_revoked, Toast.LENGTH_SHORT).show()
                    refreshList()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
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

    override fun onResume() {
        super.onResume()
        refreshHandler.post(refreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        refreshHandler.removeCallbacks(refreshRunnable)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        qrRetryHandler.removeCallbacksAndMessages(null)
    }

    private fun refreshList() {
        val json = try {
            P2PLib.listContacts()
        } catch (e: Exception) {
            "[]"
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            JSONArray()
        }

        val items = (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            val fingerprint = if (obj.isNull("active_device_fingerprint")) ""
                else obj.optString("active_device_fingerprint")
            val avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
            ChatAdapter.ChatMessage(
                contactId = fingerprint,
                displayName = obj.optString("display_name", "Bilinmeyen"),
                lastMessage = "",
                timestamp = 0L,
                realContactId = obj.optString("contact_id"),
                avatarJpeg = avatarHex?.let { hexToBytes(it) }
            )
        }

        placeholder.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
        recycler.visibility = if (items.isEmpty()) View.GONE else View.VISIBLE
        adapter.submitList(items)
    }

    /**
     * Spec 1.4: manuel giriş, QR'ın taşıdığı bilgiyi elle girmek için.
     * Format: identity_id|device_fingerprint|device_name|rendezvous_node
     * (bkz. Rust P2PLib.processManualEntry dokümantasyonu).
     */
    private fun showManualAddDialog() {
        val input = EditText(requireContext())
        input.hint = "identity_id|device_fingerprint|device_name|rendezvous_node"

        AlertDialog.Builder(requireContext())
            .setTitle("Manuel Ekle")
            .setView(input)
            .setPositiveButton("Ekle") { _, _ ->
                val text = input.text.toString()
                val result = P2PLib.processManualEntry(text)
                if (result.startsWith("Error:")) {
                    Toast.makeText(requireContext(), result, Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(requireContext(), "Eklendi: ${result.take(16)}...", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("İptal", null)
            .show()
    }
}
