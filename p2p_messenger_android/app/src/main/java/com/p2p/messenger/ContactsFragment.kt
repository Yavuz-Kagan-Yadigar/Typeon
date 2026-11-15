package com.p2p.messenger

import android.app.AlertDialog
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

    companion object {
        /** Delay before the list refreshes after an event. A burst of events causes a single refresh. */
        private const val EVENT_REFRESH_DEBOUNCE_MS = 1000L
        /** How often the pairing QR on screen is regenerated. The core's pairing window is 30 minutes (`qrRefreshRunnable`). */
        private const val QR_REFRESH_INTERVAL_MS = 5 * 60 * 1000L
    }

    private lateinit var adapter: ChatAdapter
    private lateinit var placeholder: View
    private lateinit var recycler: RecyclerView
    private lateinit var imgOwnQr: ImageView
    private lateinit var txtOwnIdentityCode: TextView
    /** `getNodeAddress()` can return empty until the swarm is actually listening, so the QR chain
     *  retries a few times on a separate handler (the logic moved here from the former QrDisplayActivity). */
    private val qrRetryHandler = Handler(Looper.getMainLooper())
    /** The same source as the QR, kept for the "Copy my code / my address" buttons. Can stay empty until
     *  the QR is produced (see the retry note of that function). */
    private var ownNodeAddress: String = ""
    private val refreshHandler = Handler(Looper.getMainLooper())
    /** Not a full rebuild every 5 seconds. The list refreshes on return to the screen and when an event
     *  arrives from the service (`listContacts` carries every contact's avatar as hex, so polling is expensive). */
    /** A refresh is queued (`Handler.hasCallbacks` is API 29, minSdk is 26). */
    @Volatile private var eventRefreshQueued = false
    private val eventRefreshRunnable = Runnable { eventRefreshQueued = false; refreshList() }
    private val eventListener: (String) -> Unit = { _ ->
        if (!eventRefreshQueued) {
            eventRefreshQueued = true
            refreshHandler.postDelayed(eventRefreshRunnable, EVENT_REFRESH_DEBOUNCE_MS)
        }
    }
    /** Whether the QR generation chain is running (only one chain). */
    @Volatile private var qrChainRunning = false
    /** The core's pairing code window is 30 minutes (`PAIRING_WINDOW_MS`). So that a QR left on screen does not
     *  go stale silently, `refreshOwnQrCode()` repeats every 5 minutes while the fragment is in front
     *  (see `onResume` / `onPause`). */
    private val qrRefreshHandler = Handler(Looper.getMainLooper())
    private val qrRefreshRunnable = object : Runnable {
        override fun run() {
            if (!isAdded || view == null || !isResumed) return
            refreshOwnQrCode()
            qrRefreshHandler.postDelayed(this, QR_REFRESH_INTERVAL_MS)
        }
    }

    /** JNI calls that take the core lock run off the main thread. [done] runs on the main thread while the
     *  fragment is still attached. */
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor()

    /** Runs [work] on the worker thread. The executor is shut down in `onDestroy`, so a late callback
     *  cannot crash the app. */
    private fun runOnWorker(work: () -> Unit) {
        try {
            worker.execute(work)
        } catch (e: java.util.concurrent.RejectedExecutionException) {
        // The fragment is gone, so there is no screen left to show the result on.
        }
    }

    private fun <T> offMain(work: () -> T, done: (T) -> Unit) {
        runOnWorker {
            val result = try { work() } catch (e: Exception) {
                com.p2p.messenger.util.Log.w("ContactsFragment", "background call failed", e)
                return@runOnWorker
            }
            refreshHandler.post { if (isAdded && view != null) done(result) }
        }
    }

    /** The core returns an error as an "Error: ..." string. The text shown to the user comes from resources,
     *  not a fixed English string. */
    private fun errorText(result: String): String =
        com.p2p.messenger.util.coreErrorText(requireContext(), result)

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_contacts, container, false)

        view.findViewById<Button>(R.id.btn_scan_qr).setOnClickListener {
            val intent = Intent(requireContext(), QrScanActivity::class.java)
            startActivity(intent)
        }

        view.findViewById<Button>(R.id.btn_manual_add).setOnClickListener {
            showManualAddDialog()
        }

        // The own QR code is shown directly on this tab, with no separate "My QR" button or screen.
        // The generation logic was moved here unchanged from the former QrDisplayActivity (now deleted).
        imgOwnQr = view.findViewById(R.id.imgOwnQr)
        // Not a hardcoded size, and not a fraction of the raw screen size. `resources.displayMetrics` covers
        // the whole display, including the status bar, the system navigation bar and this app's own top
        // status text and BottomNavigationView (nav_host_fragment is constrained between them, see
        // activity_main.xml). Sizing from that figure overshoots the space this fragment really has.
        // So the size waits for the view to be laid out and uses ITS OWN measured viewport. `view` is the
        // NestedScrollView root, match_parent inside nav_host_fragment, so its height already excludes the
        // bars above. The smaller of its width and height, minus a fixed margin, is used, so the square QR
        // always fits with that margin, on any device and orientation.
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
        // `getIdentityCode` is a JNI call, so it does not run on the main thread.
        runOnWorker {
            val code = try {
                P2PLib.getIdentityCode()
            } catch (e: Exception) {
                ""
            }
            refreshHandler.post {
                if (!isAdded || view == null) return@post
                txtOwnIdentityCode.text = code
            }
        }
        // The QR chain starts in `onResume`, only while this screen is in front.

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
                startActivity(com.p2p.messenger.util.ShareIntake.attachTo(intent))
            } else {
                // Registration (TOFU) is complete, but the real connection and IdentityExchange with the other
                // side are not finished yet (see the Rust pending_identity_exchanges note). The chat cannot be opened yet.
                Toast.makeText(requireContext(), R.string.msg_connection_not_complete, Toast.LENGTH_SHORT).show()
            }
        }
        adapter.onContactLongClick = { message -> showChatLongPressMenu(message) }
        recycler.adapter = adapter

        refreshList()
        return view
    }

    /** See the file header: if `getNodeAddress()` is empty, it is retried at short intervals (a fixed
     *  0.0.0.0/tcp/0 can never be dialled). The chain is a SINGLE chain: `qrChainRunning` stops a second
     *  chain from starting (each retry used to open a new thread). */
    private fun startQrChain(attemptsLeft: Int) {
        if (!isAdded || qrChainRunning) return
        qrChainRunning = true
        qrChainStep(attemptsLeft)
    }

    /** One step of the chain. The next step is scheduled from the main thread. */
    private fun qrChainStep(attemptsLeft: Int) {
        // Two JNI calls and a 1200x1200 QR bitmap run off the main thread, on the ONE worker thread.
        // A new thread per attempt used to be spawned every 500 ms while the node address was unknown.
        runOnWorker {
            val nodeAddress = try {
                P2PLib.getNodeAddress()
            } catch (e: Exception) {
                ""
            }
            val retryFast = nodeAddress.isEmpty() && attemptsLeft > 0
            val packet = if (retryFast) ByteArray(0) else try {
                P2PLib.generateQrPacket(nodeAddress)
            } catch (e: Exception) {
                ByteArray(0)
            }
            val bitmap = if (packet.isEmpty()) null else try {
                encodeBinaryAsQrBitmap(packet, 1200, 1200)
            } catch (e: Exception) {
                null
            }
            qrRetryHandler.post {
                // Paused in the meantime: the chain stops here, and `onResume` restarts it.
                if (!isAdded || view == null || !isResumed) {
                    qrChainRunning = false
                    return@post
                }
                if (retryFast) {
                    qrRetryHandler.postDelayed({ qrChainStep(attemptsLeft - 1) }, 500)
                    return@post
                }
                // Tor is not ready after the fast retries: show what is available, but keep trying.
                // A code without the rendezvous address was never refreshed, and pairing from it hung.
                if (nodeAddress.isEmpty()) {
                    qrRetryHandler.postDelayed({ qrChainStep(0) }, 3000)
                    return@post
                }
                qrChainRunning = false
                ownNodeAddress = nodeAddress
                bitmap?.let { imgOwnQr.setImageBitmap(it) }
            }
        }
    }

    /**
     * Shows a fresh pairing packet and its QR bitmap. The core accepts a pairing code only for one day, and the
     * code on screen did not match the packet stored in the core: the previous `onResume` produced a new packet
     * and threw the result away. The packet is now used and shown. JNI calls do not run on the main thread.
     */
    private fun refreshOwnQrCode() {
        val address = ownNodeAddress
        if (address.isEmpty()) return
        runOnWorker {
            val packet = try {
                P2PLib.generateQrPacket(address)
            } catch (e: Exception) {
                ByteArray(0)
            }
            val bitmap = if (packet.isEmpty()) null else try {
                encodeBinaryAsQrBitmap(packet, 1200, 1200)
            } catch (e: Exception) {
                null
            }
            qrRetryHandler.post {
                if (!isAdded || view == null) return@post
                bitmap?.let { imgOwnQr.setImageBitmap(it) }
            }
        }
    }

    /** Same as `encodeBinaryAsQrBitmap` in the former QrDisplayActivity. */
    private fun encodeBinaryAsQrBitmap(data: ByteArray, width: Int, height: Int): Bitmap {
        val text = QrBinaryCodec.bytesToLatin1String(data)
        val hints = mapOf(EncodeHintType.CHARACTER_SET to "ISO-8859-1")
        val bitMatrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height, hints)
        // One bulk write instead of 1.44 million `setPixel` calls.
        val pixels = IntArray(width * height) { if (bitMatrix[it % width, it / width]) Color.BLACK else Color.WHITE }
        return Bitmap.createBitmap(pixels, width, height, Bitmap.Config.RGB_565)
    }

    /** Same note as `ChatsFragment.showChatLongPressMenu`. Both tabs share the same contact list and adapter,
     *  so the behaviour is identical. */
    private fun showChatLongPressMenu(message: ChatAdapter.ChatMessage) {
        // The menu has a "Block" entry, and for people met through a group a "Mark as verified" entry.
        // Block sits next to Revoke but means something different. Revoke shuts down one device, and the person
        // can come back with a new device. Block targets the identity, and only an in-person re-pairing lifts it.
        // A JNI call that takes the core lock: off the main thread.
        offMain({
            message.identityId.isNotEmpty() && try {
                org.json.JSONArray(P2PLib.listBlockedIdentities()).let { arr ->
                    (0 until arr.length()).any { arr.optString(it) == message.identityId }
                }
            } catch (e: Exception) {
                false
            }
        }) { isBlocked -> showChatLongPressDialog(message, isBlocked) }
    }

    private fun showChatLongPressDialog(message: ChatAdapter.ChatMessage, isBlocked: Boolean) {
        val options = mutableListOf(
            getString(R.string.action_clear_chat_history),
            getString(R.string.action_revoke_device),
            getString(if (isBlocked) R.string.action_unblock else R.string.action_block),
            getString(R.string.action_delete_contact),
            getString(R.string.lbl_safety_number)
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
                    4 -> showSafetyCode(message)
                    5 -> confirmTrustContact(message)
                }
            }
            .show()
    }

    /** The code of any contact, not only of one that came through a group. */
    private fun showSafetyCode(message: ChatAdapter.ChatMessage) {
        // A JNI call that takes the core lock: off the main thread.
        offMain({
            try { P2PLib.contactSafetyCode(message.identityId) } catch (e: Exception) { "" }
        }) { code ->
            if (code.isNotEmpty()) {
                AlertDialog.Builder(requireContext())
                    .setTitle(message.displayName)
                    .setMessage(getString(R.string.lbl_safety_code, code))
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
        }
    }

    /**
     * Permanent block of a contact. The text says plainly how it differs from revoke: the only way back is an
     * in-person re-pairing.
     */
    private fun confirmBlockIdentity(message: ChatAdapter.ChatMessage) {
        val identityId = message.identityId
        if (identityId.isEmpty()) return
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.confirm_block_title)
            .setMessage(getString(R.string.confirm_block_body, message.displayName))
            .setPositiveButton(R.string.action_block) { _, _ ->
                offMain({
                    try { P2PLib.blockIdentity(identityId) } catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_identity_blocked, Toast.LENGTH_LONG).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun unblockIdentity(message: ChatAdapter.ChatMessage) {
        offMain({
            try {
                P2PLib.unblockIdentity(message.identityId)
                null
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
        }) { error ->
            if (error != null) {
                Toast.makeText(requireContext(), errorText(error), Toast.LENGTH_LONG).show()
            } else {
                Toast.makeText(requireContext(), R.string.msg_identity_unblocked, Toast.LENGTH_SHORT).show()
                refreshList()
            }
        }
    }

    /**
     * Gives FULL trust to a contact met through a group. It removes the "added via group, not verified" mark.
     * The encryption was the same before; only the trust indicator changes.
     */
    private fun confirmTrustContact(message: ChatAdapter.ChatMessage) {
        if (message.realContactId.isEmpty()) return
        // Trust here does not mean a key exchange: the keys are ALREADY used end to end. What is missing is
        // checking that those keys really belong to this person. Only the user can do that, by comparing the
        // code over another channel. So the code is shown here, inside the confirmation dialog.
        // The screen does not block: the code is produced with a JNI call, so it runs off the main thread (`offMain`).
        runOnWorker {
            val safetyCode = try {
                P2PLib.contactSafetyCode(message.identityId)
            } catch (e: Exception) {
                ""
            }
            refreshHandler.post {
                if (!isAdded || view == null) return@post
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
                        offMain({
                            try { P2PLib.trustContact(message.realContactId) } catch (e: Exception) { "Error: ${e.message}" }
                        }) { result ->
                            if (result.startsWith("Error:")) {
                                Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_LONG).show()
                            } else {
                                Toast.makeText(requireContext(), R.string.msg_contact_trusted, Toast.LENGTH_SHORT).show()
                                refreshList()
                            }
                        }
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
    }

    /** See the same note on `ChatsFragment.confirmRevokeDevice`. */
    private fun confirmRevokeDevice(message: ChatAdapter.ChatMessage) {
        if (message.contactId.isEmpty()) return
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_revoke_device)
            .setPositiveButton(R.string.action_revoke_device) { _, _ ->
                offMain({
                    try { P2PLib.revokeContactDevice(message.realContactId, message.contactId) }
                    catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_device_revoked, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmClearChatHistory(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_clear_chat_history)
            .setPositiveButton(R.string.action_clear_chat_history) { _, _ ->
                offMain({
                    try { P2PLib.clearChatHistory(message.realContactId) }
                    catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_chat_history_cleared, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
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
                offMain({
                    try { P2PLib.deleteContact(message.realContactId) }
                    catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_contact_deleted, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    override fun onResume() {
        super.onResume()
        // The own pairing QR is on screen.
        P2PApplication.setSecure(requireActivity(), true)
        // The core accepts a stranger's pairing only for 30 minutes after the code was produced (PAIRING_WINDOW_MS).
        // This view can stay alive longer than that, so the code (and the QR showing it) is refreshed when the
        // screen comes back, and again while it stays on screen.
        refreshOwnQrCode()
        qrRefreshHandler.postDelayed(qrRefreshRunnable, QR_REFRESH_INTERVAL_MS)
        // The QR is produced once the node address is known. The chain runs only while this screen is in front
        // (see `onPause`).
        if (ownNodeAddress.isEmpty()) startQrChain(attemptsLeft = 10)
        refreshList()
        com.p2p.messenger.service.P2PService.addMessageListener(eventListener)
    }

    override fun onPause() {
        super.onPause()
        // Before API 33 the whole app stays FLAG_SECURE (no opt-out from recents).
        if (android.os.Build.VERSION.SDK_INT >= 33) P2PApplication.setSecure(requireActivity(), false)
        com.p2p.messenger.service.P2PService.removeMessageListener(eventListener)
        refreshHandler.removeCallbacks(eventRefreshRunnable)
        eventRefreshQueued = false
        // The QR retry chain must not keep the core busy while the app is in the background.
        qrRetryHandler.removeCallbacksAndMessages(null)
        qrChainRunning = false
        qrRefreshHandler.removeCallbacks(qrRefreshRunnable)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        // The next view starts with an empty adapter.
        lastContactsJson = null
        qrRetryHandler.removeCallbacksAndMessages(null)
        // The adapter holds EVERY contact's avatar bytes, and the QR bitmap is about 2.9 MB. Both must not stay
        // alive while another tab is shown.
        if (::adapter.isInitialized) adapter.submitList(emptyList())
        if (::imgOwnQr.isInitialized) imgOwnQr.setImageDrawable(null)
    }

    override fun onDestroy() {
        super.onDestroy()
        // The worker is a live non-daemon thread, so it is shut down with the fragment.
        worker.shutdownNow()
    }

    private var lastContactsJson: String? = null
    @Volatile private var refreshing = false
    /** A refresh requested while one is running (after a delete, a pin, and so on) runs once more, because the
     *  running one may have read the old state. */
    private var refreshAgain = false

    /** Called on return to the screen and when an event arrives from the service, not every 5 seconds. It runs
     *  off the main thread (the JNI call takes the core lock). An unchanged list is not parsed again, and avatars
     *  are not resolved again. */
    private fun refreshList() {
        if (refreshing) { refreshAgain = true; return }
        val ctx = context ?: return
        val viaGroupLabel = ctx.getString(R.string.contact_added_via_group)
        // The fallback for a contact without a name. The same text is used in both tabs, and it comes from resources.
        val unknownLabel = ctx.getString(R.string.lbl_unknown)
        refreshing = true
        runOnWorker {
            val json = try {
                P2PLib.listContacts()
            } catch (e: Exception) {
                "[]"
            }
            val items = if (json == lastContactsJson) null else try {
                parseContacts(json, viaGroupLabel, unknownLabel)
            } catch (e: Exception) {
                null
            }
            refreshHandler.post {
                refreshing = false
                if (refreshAgain) { refreshAgain = false; refreshList() }
                if (items == null || !isAdded || view == null) return@post
                lastContactsJson = json
                placeholder.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
                recycler.visibility = if (items.isEmpty()) View.GONE else View.VISIBLE
                adapter.submitList(items)
            }
        }
    }

    private fun parseContacts(json: String, viaGroupLabel: String, unknownLabel: String): List<ChatAdapter.ChatMessage> {
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            JSONArray()
        }
        // The fallback is the same in both tabs (it used to be "Unknown" here and another text in the chats tab).
        val duplicateNames = com.p2p.messenger.util.ContactNames.duplicates(
            (0 until array.length()).map { array.getJSONObject(it).optString("display_name", unknownLabel) }
        )
        val items = (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            val fingerprint = if (obj.isNull("active_device_fingerprint")) ""
                else obj.optString("active_device_fingerprint")
            val avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
            // Contacts added through a group (vouched by the founder) have not been verified in person. Their row
            // shows a warning mark (see ChatAdapter.bind) and a description.
            val addedViaGroup = obj.optBoolean("added_via_group", false)
            ChatAdapter.ChatMessage(
                contactId = fingerprint,
                displayName = com.p2p.messenger.util.ContactNames.label(
                    obj.optString("display_name", unknownLabel), obj.optString("identity_id"), duplicateNames
                ),
                lastMessage = if (addedViaGroup) viaGroupLabel else "",
                timestamp = 0L,
                realContactId = obj.optString("contact_id"),
                avatarJpeg = avatarHex?.let { hexToBytes(it) },
                addedViaGroup = addedViaGroup,
                identityId = obj.optString("identity_id")
            )
        }

        return items
    }

    /**
     * Manual entry (section 1.4): enter the information the QR carries by hand.
     * Format: identity_id|device_fingerprint|nonce|device_name|rendezvous_node
     * (see the Rust P2PLib.processManualEntry docs).
     */
    private fun showManualAddDialog() {
        val input = EditText(requireContext())
        input.hint = getString(R.string.hint_manual_add_format)

        AlertDialog.Builder(requireContext())
            .setTitle(R.string.title_add_manually)
            .setView(input)
            .setPositiveButton(R.string.action_add) { _, _ ->
                val text = input.text.toString()
                // The Rust handshake can take a while, so the main thread is not blocked.
                offMain({
                    try { P2PLib.processManualEntry(text) } catch (e: Throwable) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_LONG).show()
                    } else {
                        openChatForPairingResult(result)
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Same pattern as `showManualAddDialog` and QrScanActivity.openChatOrFallback: parses the JSON returned by
     *  `processManualEntry` and opens the new contact's chat screen. */
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
        // The pending share is also attached to this chat, as in every other open path. Otherwise shared content
        // was lost after the browser or manual add path and later stuck to an unrelated chat.
        startActivity(com.p2p.messenger.util.ShareIntake.attachTo(intent))
    }

    /** See `btn_copy_manual_code`. If the other side cannot scan the QR (for example the screens are not side by side,
     *  or the networks differ), this text can be pasted into their "Add Manually" field. `getManualAddCode` builds it in
     *  one place in Rust (see that function's docs). The format stays identical to what `processManualEntry` expects. */
    private fun copyManualAddCode() {
        if (ownNodeAddress.isEmpty()) {
            Toast.makeText(requireContext(), R.string.error_address_not_ready, Toast.LENGTH_SHORT).show()
            return
        }
        // `getManualAddCode` takes the core lock, so it runs off the main thread (`offMain`).
        offMain({
            try {
                P2PLib.getManualAddCode(ownNodeAddress)
            } catch (e: Exception) {
                ""
            }
        }) { code ->
            if (code.isEmpty()) {
                Toast.makeText(requireContext(), R.string.error_address_not_ready, Toast.LENGTH_SHORT).show()
            } else {
                com.p2p.messenger.util.copySensitive(requireContext(), getString(R.string.lbl_clipboard_pairing_code), code)
                Toast.makeText(requireContext(), R.string.msg_manual_code_copied, Toast.LENGTH_LONG).show()
            }
        }
    }

    /** See `btn_copy_own_address`. It copies the SAME `getManualAddCode` format as `copyManualAddCode`, so the text
     *  copied with "Copy my address" pastes directly into "Add Manually" on the other phone. Earlier it copied a bare
     *  multiaddr, which did not match the pipe-separated format `processManualEntry` expects. */
    private fun copyOwnAddress() {
        if (ownNodeAddress.isEmpty()) {
            Toast.makeText(requireContext(), R.string.error_address_not_ready, Toast.LENGTH_SHORT).show()
            return
        }
        // `getManualAddCode` takes the core lock, so it runs off the main thread (`offMain`).
        offMain({
            try {
                P2PLib.getManualAddCode(ownNodeAddress)
            } catch (e: Exception) {
                ""
            }
        }) { code ->
            if (code.isEmpty()) {
                Toast.makeText(requireContext(), R.string.error_address_not_ready, Toast.LENGTH_SHORT).show()
            } else {
                com.p2p.messenger.util.copySensitive(requireContext(), getString(R.string.lbl_clipboard_pairing_code), code)
                Toast.makeText(requireContext(), R.string.msg_own_address_copied, Toast.LENGTH_LONG).show()
            }
        }
    }
}
