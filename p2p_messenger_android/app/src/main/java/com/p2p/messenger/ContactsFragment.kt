package com.p2p.messenger

import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
import androidx.core.view.doOnPreDraw
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
import org.json.JSONObject

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
    /** bkz. `loadNodeAddressAndGenerateQr` — QR ile aynı kaynaktan, "Kodumu/
     *  Adresimi kopyala" düğmeleri için ayrıca saklanır. QR üretilene kadar
     *  boş kalabilir (bkz. o fonksiyonun yeniden deneme notu). */
    private var ownNodeAddress: String = ""
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
        // Not hardcoded, and not just a fraction of the RAW screen size:
        // `resources.displayMetrics` is the full display, which still
        // includes the status bar, the system nav bar, AND this app's own
        // top status-text bar + BottomNavigationView (see activity_main.xml
        // — nav_host_fragment is constrained between them). Sizing off that
        // raw figure overshoots the space actually available for this
        // fragment's content. Instead, wait for this view to be laid out
        // and size off ITS OWN measured viewport (`view` here is the
        // NestedScrollView root, match_parent WITHIN nav_host_fragment, so
        // its height already excludes all of the above) — the smaller of
        // its width/height, minus a fixed thin margin, so the QR (a
        // square) always fits with at least that margin regardless of
        // device or orientation.
        view.doOnPreDraw {
            val minDimensionPx = minOf(view.width, view.height)
            val thinMarginPx = (16 * resources.displayMetrics.density).toInt()
            val qrSide = (minDimensionPx - thinMarginPx * 2)
                .coerceAtLeast((160 * resources.displayMetrics.density).toInt())
            imgOwnQr.layoutParams = imgOwnQr.layoutParams.apply {
                width = qrSide
                height = qrSide
            }
        }
        txtOwnIdentityCode = view.findViewById(R.id.txtOwnIdentityCode)
        txtOwnIdentityCode.text = try {
            P2PLib.getIdentityCode()
        } catch (e: Exception) {
            ""
        }
        loadNodeAddressAndGenerateQr(attemptsLeft = 10)

        view.findViewById<Button>(R.id.btn_copy_manual_code).setOnClickListener { copyManualAddCode() }
        view.findViewById<Button>(R.id.btn_copy_own_address).setOnClickListener { copyOwnAddress() }

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
                Toast.makeText(requireContext(), R.string.msg_connection_not_complete, Toast.LENGTH_SHORT).show()
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
        ownNodeAddress = nodeAddress
        val qrBytes = try {
            P2PLib.generateQrPacket(nodeAddress)
        } catch (e: Exception) {
            null
        }
        if (qrBytes != null && qrBytes.isNotEmpty()) {
            imgOwnQr.setImageBitmap(encodeBinaryAsQrBitmap(qrBytes, 1200, 1200))
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
        // Kullanicı kararı (2026-08-27): menuye ENGELLE eklendi ve grup
        // uzerinden tanisilan kisiler icin "dogrulandi olarak isaretle"
        // secenegi cikiyor. Engelle, iptalin (revoke) yanina konuldu ama
        // anlami cok farkli: iptal tek bir cihazi kapatir ve kisi yeni bir
        // cihazla geri gelebilir; engel ise kimligi hedefler ve yalnizca
        // yuz yuze yeniden eslesmeyle kalkar.
        val isBlocked = message.identityId.isNotEmpty() && try {
            org.json.JSONArray(P2PLib.listBlockedIdentities()).let { arr ->
                (0 until arr.length()).any { arr.optString(it) == message.identityId }
            }
        } catch (e: Exception) {
            false
        }
        val options = mutableListOf(
            getString(R.string.action_clear_chat_history),
            getString(R.string.action_revoke_device),
            getString(if (isBlocked) R.string.action_unblock else R.string.action_block),
            getString(R.string.action_delete_contact)
        )
        if (message.addedViaGroup) {
            options.add(getString(R.string.action_trust_contact))
        }
        AlertDialog.Builder(requireContext())
            .setTitle(message.displayName)
            .setItems(options.toTypedArray()) { _, which ->
                when (which) {
                    0 -> confirmClearChatHistory(message)
                    1 -> confirmRevokeDevice(message)
                    2 -> if (isBlocked) unblockIdentity(message) else confirmBlockIdentity(message)
                    3 -> confirmDeleteContactStep1(message)
                    4 -> confirmTrustContact(message)
                }
            }
            .show()
    }

    /**
     * Kullanici karari: kalici engelleme. `revoke`'tan farki metinde acikca
     * anlatiliyor — geri donusu yalnizca yuz yuze yeniden eslesme.
     */
    private fun confirmBlockIdentity(message: ChatAdapter.ChatMessage) {
        val identityId = message.identityId
        if (identityId.isEmpty()) return
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.confirm_block_title)
            .setMessage(getString(R.string.confirm_block_body, message.displayName))
            .setPositiveButton(R.string.action_block) { _, _ ->
                val result = try {
                    P2PLib.blockIdentity(identityId)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(requireContext(), result, Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(requireContext(), R.string.msg_identity_blocked, Toast.LENGTH_LONG).show()
                    refreshList()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun unblockIdentity(message: ChatAdapter.ChatMessage) {
        try {
            P2PLib.unblockIdentity(message.identityId)
            Toast.makeText(requireContext(), R.string.msg_identity_unblocked, Toast.LENGTH_SHORT).show()
            refreshList()
        } catch (e: Exception) {
            Toast.makeText(requireContext(), "Error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    /**
     * Kullanici karari: grup uzerinden tanisilan bir kisiye TAM guven verir
     * — "grup uzerinden eklendi, dogrulanmadi" isaretini kaldirir.
     * Sifreleme zaten aynıydi; degisen yalnizca guven gostergesi.
     */
    private fun confirmTrustContact(message: ChatAdapter.ChatMessage) {
        if (message.realContactId.isEmpty()) return
        // Kullanıcı sorusu (2026-08-28): "güven" derken arkada anahtar
        // alışverişi olmuyor — anahtarlar ZATEN uçtan uca kullanılıyor.
        // Eksik olan tek şey, o anahtarların gerçekten bu kişiye ait
        // olduğunun DOĞRULANMASI. Bunu ancak kullanıcı, kodu başka bir
        // kanaldan karşılaştırarak yapabilir; o yüzden kod artık burada,
        // onay penceresinin içinde gösteriliyor.
        val safetyCode = try {
            P2PLib.contactSafetyCode(message.identityId)
        } catch (e: Exception) {
            ""
        }
        val body = if (safetyCode.isNotEmpty()) {
            getString(R.string.confirm_trust_body, message.displayName) +
                "\n\n" + getString(R.string.lbl_safety_code, safetyCode)
        } else {
            getString(R.string.confirm_trust_body, message.displayName)
        }
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.confirm_trust_title)
            .setMessage(body)
            .setPositiveButton(R.string.action_trust_contact) { _, _ ->
                val result = try {
                    P2PLib.trustContact(message.realContactId)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(requireContext(), result, Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(requireContext(), R.string.msg_contact_trusted, Toast.LENGTH_SHORT).show()
                    refreshList()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
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
            // Spec dışı, kullanıcı kararı: grup üzerinden (kurucu
            // kefaletiyle) eklenen kişiler yüz yüze doğrulanmadı — kişi
            // satırında hem uyarı işareti (bkz. ChatAdapter.bind) hem de
            // açıklama gösterilir.
            val addedViaGroup = obj.optBoolean("added_via_group", false)
            ChatAdapter.ChatMessage(
                contactId = fingerprint,
                displayName = obj.optString("display_name", "Unknown"),
                lastMessage = if (addedViaGroup) getString(R.string.contact_added_via_group) else "",
                timestamp = 0L,
                realContactId = obj.optString("contact_id"),
                avatarJpeg = avatarHex?.let { hexToBytes(it) },
                addedViaGroup = addedViaGroup,
                identityId = obj.optString("identity_id")
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
        input.hint = getString(R.string.hint_manual_add_format)

        AlertDialog.Builder(requireContext())
            .setTitle(R.string.title_add_manually)
            .setView(input)
            .setPositiveButton(R.string.action_add) { _, _ ->
                val text = input.text.toString()
                val result = P2PLib.processManualEntry(text)
                if (result.startsWith("Error:")) {
                    Toast.makeText(requireContext(), result, Toast.LENGTH_LONG).show()
                } else {
                    // Spec dışı, kullanıcı isteği: bkz. QrScanActivity AYNI
                    // desen — ilk eşleşme uzun sürebilir, kullanıcıyı
                    // DOĞRUDAN yeni kişinin sohbet ekranına yönlendirmek
                    // (o ekranın "Bağlanılıyor..." göstergesiyle) sadece
                    // bir toast göstermekten çok daha açık.
                    openChatForPairingResult(result)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** bkz. `showManualAddDialog`/QrScanActivity.openChatOrFallback AYNI
     *  desen — `processManualEntry`'nin JSON dönüşünü ayrıştırıp yeni
     *  kişinin sohbet ekranını açar. */
    private fun openChatForPairingResult(resultJson: String) {
        val deviceFingerprint: String?
        val deviceName: String
        try {
            val obj = JSONObject(resultJson)
            deviceFingerprint = obj.optString("device_fingerprint").ifEmpty { null }
            deviceName = obj.optString("device_name")
        } catch (e: Exception) {
            Toast.makeText(requireContext(), R.string.msg_added, Toast.LENGTH_SHORT).show()
            return
        }
        if (deviceFingerprint == null) {
            Toast.makeText(requireContext(), R.string.msg_added, Toast.LENGTH_SHORT).show()
            return
        }
        val intent = Intent(requireContext(), ChatActivity::class.java)
        intent.putExtra(ChatActivity.EXTRA_PEER_DEVICE_FINGERPRINT, deviceFingerprint)
        intent.putExtra(ChatActivity.EXTRA_PEER_DISPLAY_NAME, deviceName.ifEmpty { deviceFingerprint.take(8) })
        startActivity(intent)
    }

    /** bkz. `btn_copy_manual_code` — karşı taraf QR tarayamıyorsa (ör.
     *  ekranlar yan yana değil, farklı ağ) bu metni "Manuel Ekle"sine
     *  yapıştırabilir. `getManualAddCode` Rust tarafında tek bir yerden
     *  üretilir (bkz. o fonksiyonun dokümantasyonu) — format
     *  `processManualEntry`'nin beklediğiyle birebir aynı kalır. */
    private fun copyManualAddCode() {
        if (ownNodeAddress.isEmpty()) {
            Toast.makeText(requireContext(), R.string.error_address_not_ready, Toast.LENGTH_SHORT).show()
            return
        }
        val code = try {
            P2PLib.getManualAddCode(ownNodeAddress)
        } catch (e: Exception) {
            ""
        }
        if (code.isEmpty()) {
            Toast.makeText(requireContext(), R.string.error_address_not_ready, Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Typeon pairing code", code))
        Toast.makeText(requireContext(), R.string.msg_manual_code_copied, Toast.LENGTH_LONG).show()
    }

    /** bkz. `btn_copy_own_address` — spec dışı, kullanıcı isteği: bu da
     *  `copyManualAddCode` ile AYNI `getManualAddCode` formatını kopyalar
     *  (bkz. o fonksiyonun dokümantasyonu), böylece bir telefonda "Copy my
     *  address"e basıp öbür telefonda direkt "Add Manually"ye yapıştırmak
     *  bire bir çalışır — önceden burada bare multiaddr kopyalanıyordu ki
     *  `processManualEntry`'nin beklediği pipe'lı formatla uyuşmuyordu. */
    private fun copyOwnAddress() {
        if (ownNodeAddress.isEmpty()) {
            Toast.makeText(requireContext(), R.string.error_address_not_ready, Toast.LENGTH_SHORT).show()
            return
        }
        val code = try {
            P2PLib.getManualAddCode(ownNodeAddress)
        } catch (e: Exception) {
            ""
        }
        if (code.isEmpty()) {
            Toast.makeText(requireContext(), R.string.error_address_not_ready, Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Typeon pairing code", code))
        Toast.makeText(requireContext(), R.string.msg_own_address_copied, Toast.LENGTH_LONG).show()
    }
}
