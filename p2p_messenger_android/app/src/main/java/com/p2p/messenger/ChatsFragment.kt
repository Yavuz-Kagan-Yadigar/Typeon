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
import androidx.appcompat.widget.SearchView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.p2p.messenger.ui.ChatActivity
import com.p2p.messenger.ui.ChatAdapter
import com.p2p.messenger.ui.GroupChatActivity
import com.p2p.messenger.util.PinnedChatsPrefs
import com.p2p.messenger.util.ReadStatePrefs
import com.p2p.messenger.util.hexToBytes
import org.json.JSONArray
import org.json.JSONObject

/**
 * One list of known contacts and groups. A tap opens the matching chat screen. It uses a real
 * `ListAdapter` with `DiffUtil` (see ChatAdapter) and refreshes on events. The chat with the newest
 * message or attachment is at the top, for contacts and groups together on one timeline (see `refreshList`).
 * With node mode off, the "last message" field stays empty for contacts, because no message history is
 * stored then. The same limit applies to groups (see `archive_group_message`).
 *
 * Groups used to have their own tab. That tab was removed, and group listing and creation moved here
 * (see `btnCreateGroup`, the logic of the former GroupsFragment).
 */
class ChatsFragment : Fragment() {

    companion object {
        /** Delay before the list refreshes after an event. A burst of events causes one refresh. */
        private const val EVENT_REFRESH_DEBOUNCE_MS = 1000L

        /** Events that never change a chat or contact list row (progress, typing, ticks, calls). */
        private val QUIET_EVENTS = setOf(
            "typing", "file_progress", "noop", "ack", "status", "whiteboard", "call", "group_call_offer",
            "address_announce", "stickers_changed",
        )

        /** True for an event the lists can ignore; also used by ContactsFragment. */
        internal fun isQuietEvent(json: String): Boolean =
            try { org.json.JSONObject(json).optString("type") in QUIET_EVENTS } catch (e: Exception) { false }
    }

    /** Set by `ChatListDrawer`: true while the drawer that hosts this list is closed. The list is then rebuilt
     *  only when the drawer opens, not on every event of the open chat. */
    var inClosedDrawer: () -> Boolean = { false }
    private var staleWhileClosed = false

    fun onDrawerOpened() {
        if (staleWhileClosed && isResumed) {
            staleWhileClosed = false
            refreshList()
        }
    }

    /**
     * This fragment can live in two places: the MainActivity tab (full screen, this callback stays `null`),
     * and the left drawer of ChatActivity / GroupChatActivity (see the DrawerLayout in activity_chat.xml).
     * Inside the drawer, tapping a chat starts a NEW ChatActivity / GroupChatActivity (see `openGroupChat` and the
     * DM branch below). The host (see ChatActivity.setupChatListDrawer) sets this callback to `{ finish() }`, so
     * the open chat is not stacked under another one. The MainActivity tab does not set it, so its behaviour is unchanged.
     */
    var onChatOpenedFromDrawer: (() -> Unit)? = null

    private lateinit var adapter: ChatAdapter
    private lateinit var noContactsText: View
    /** The most recently loaded FULL list (contacts and groups). The search query filters it here. A refresh
     *  of the list does NOT reset the search query. */
    private var allChatItems: List<ChatAdapter.ChatMessage> = emptyList()
    private var searchQuery: String = ""

    /** The core returns an error as an "Error: ..." string. The text shown to the user comes from resources,
     *  not a fixed English string. */
    private fun errorText(result: String): String =
        com.p2p.messenger.util.coreErrorText(requireContext(), result)
    private val refreshHandler = Handler(Looper.getMainLooper())
    /**
     * The list is NOT fully rebuilt every 5 seconds. Each round used to re-read every contact and group, the last
     * message previews and the attachments. That was O(chats x attachments) work under the core lock, every 5 seconds
     * (see the `refreshList` note).
     *
     * The list is now refreshed by EVENTS: on return to the screen and when the service reports an event
     * (message, read state, pairing, group update, ...).
     */
    /** A refresh is queued (`Handler.hasCallbacks` is API 29, minSdk is 26). */
    @Volatile private var eventRefreshQueued = false
    private val eventRefreshRunnable = Runnable {
        eventRefreshQueued = false
        if (inClosedDrawer()) staleWhileClosed = true else refreshList()
    }
    private val eventListener: (String) -> Unit = listener@{ msg ->
        if (isQuietEvent(msg)) return@listener
        // Events arrive one by one. A burst of 50 messages would otherwise cause 50 rebuilds, so if a refresh
        // is already pending, a new one is not added.
        if (!eventRefreshQueued) {
            eventRefreshQueued = true
            refreshHandler.postDelayed(eventRefreshRunnable, EVENT_REFRESH_DEBOUNCE_MS)
        }
    }
    /** Spinner while the service leaves power save and re-verifies its links ("syncing" in `ownConnectionStatus`).
     *  It refreshes the list when done. It polls off the main thread (the JNI call takes the core lock) and stops
     *  by itself once the core reports it is in sync. */
    private val syncRunnable = object : Runnable {
        override fun run() {
            runOnWorker {
                val syncing = try {
                    org.json.JSONObject(P2PLib.ownConnectionStatus()).optBoolean("syncing", false)
                } catch (e: Exception) { false }
                refreshHandler.post {
                    val spinner = view?.findViewById<View>(R.id.progressSync) ?: return@post
                    if (!syncing && spinner.visibility == View.VISIBLE) refreshList()
                    spinner.visibility = if (syncing) View.VISIBLE else View.GONE
                    if (syncing && isResumed) refreshHandler.postDelayed(this, 400)
                }
            }
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
                    startActivity(com.p2p.messenger.util.ShareIntake.attachTo(intent))
                    onChatOpenedFromDrawer?.invoke()
                }
            }
        }
        adapter.onContactLongClick = { message -> showChatLongPressMenu(message) }
        recycler.adapter = adapter

        // Search by contact or group name.
        view.findViewById<SearchView>(R.id.searchChats).setOnQueryTextListener(object : SearchView.OnQueryTextListener {
            override fun onQueryTextSubmit(query: String?): Boolean = false
            override fun onQueryTextChange(newText: String?): Boolean {
                searchQuery = newText ?: ""
                applyFilter()
                return true
            }
        })

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
        startActivity(com.p2p.messenger.util.ShareIntake.attachTo(intent))
        onChatOpenedFromDrawer?.invoke()
    }

    /** See PinnedChatsPrefs. It is the same key that `refreshList` uses to compute `message.isPinned` for this row. */
    private fun pinKeyFor(message: ChatAdapter.ChatMessage): String =
        if (message.isGroup) "group:${message.contactId}" else message.realContactId

    private fun togglePin(message: ChatAdapter.ChatMessage) {
        val key = pinKeyFor(message)
        PinnedChatsPrefs.setPinned(requireContext(), key, !message.isPinned)
        refreshList()
    }

    /**
     * Two separate options, agreed with the user: "clear chat history" (soft, one confirmation, the contact stays
     * paired) and "delete contact" (hard, TWO confirmations, everything including the pairing is deleted). ONLY for
     * contacts. Groups have no `realContactId` (see ChatAdapter), so this menu is never shown for them. Both contact
     * and group rows also get pin / unpin for the chat (see `togglePin`).
     */
    private fun showChatLongPressMenu(message: ChatAdapter.ChatMessage) {
        val pinLabel = getString(if (message.isPinned) R.string.action_unpin_chat else R.string.action_pin_chat)
        // Group rows do not get the DM options (clear history, revoke device, delete contact), which make no sense
        // for a group. The founder sees "Delete group for everyone". Other members see "Leave group"
        // (see Rust `leave_group`: the founder cannot leave, only delete for everyone).
        if (message.isGroup) {
            val destructiveLabel = getString(
                if (message.isGroupFounder) R.string.action_delete_group else R.string.action_leave_group
            )
            AlertDialog.Builder(requireContext())
                .setTitle(message.displayName)
                .setItems(arrayOf(pinLabel, getString(R.string.action_clear_chat_history), destructiveLabel)) { _, which ->
                    when (which) {
                        0 -> togglePin(message)
                        1 -> confirmClearChatHistory(message, message.contactId)
                        2 -> if (message.isGroupFounder) confirmDeleteGroup(message) else confirmLeaveGroup(message)
                    }
                }
                .show()
            return
        }
        val options = arrayOf(
            pinLabel,
            getString(R.string.action_clear_chat_history),
            getString(R.string.action_revoke_device),
            getString(R.string.action_delete_contact)
        )
        AlertDialog.Builder(requireContext())
            .setTitle(message.displayName)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> togglePin(message)
                    1 -> confirmClearChatHistory(message)
                    2 -> confirmRevokeDevice(message)
                    3 -> confirmDeleteContactStep1(message)
                }
            }
            .show()
    }

    /** The founder deletes the group for ALL members (a signed `GroupChange::Delete` goes to everyone). This cannot
     *  be undone, so it asks for confirmation (see Rust `delete_group`). */
    private fun confirmDeleteGroup(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_delete_group)
            .setPositiveButton(R.string.action_delete_group) { _, _ ->
                offMain({
                    try { P2PLib.deleteGroup(message.contactId) } catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_group_deleted, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** A member who is NOT the founder leaves the group by their own choice (see Rust `leave_group`). This cannot be
     *  undone (rejoining needs a new invitation), so it asks for confirmation. */
    private fun confirmLeaveGroup(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_leave_group)
            .setPositiveButton(R.string.action_leave_group) { _, _ ->
                offMain({
                    try { P2PLib.leaveGroup(message.contactId) } catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_left_group, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** See the file header. It does NOT delete the contact or the history. It revokes only this ONE device
     *  (see Rust revoke_contact_device). One confirmation is enough: it is less destructive than clearing history
     *  (history is kept), and less destructive than deleting the contact (no re-pairing needed, only that device is blocked). */
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

    private fun confirmClearChatHistory(message: ChatAdapter.ChatMessage, chatId: String = message.realContactId) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_clear_chat_history)
            .setPositiveButton(R.string.action_clear_chat_history) { _, _ ->
                offMain({
                    try { P2PLib.clearChatHistory(chatId) }
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

    /** First confirmation. See the file header: because this action is HARD (the pairing and everything else is
     *  deleted), a second confirmation is asked. */
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

    /** Same as the former GroupsFragment.showCreateGroupDialog, moved here. */
    private fun showCreateGroupDialog() {
        val input = EditText(requireContext())
        input.hint = getString(R.string.lbl_new_group_name_hint)
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.action_create_group)
            .setView(input)
            .setPositiveButton(R.string.action_create_group) { _, _ ->
                val name = input.text.toString().trim()
                if (name.isBlank()) return@setPositiveButton
                offMain({ P2PLib.createGroup(name) }) { groupId ->
                    if (groupId.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(groupId), Toast.LENGTH_LONG).show()
                    } else {
                        refreshList()
                        showAddMembersDialog(groupId)
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Adds group members from the contact list in a multi-select (see section 5.4). The founder creates the
     *  invitation, and each invited member receives a GroupUpdate over their existing or new 1:1 connection. */
    private fun showAddMembersDialog(groupId: String) {
        // `listContacts` carries every contact's avatar as hex, so it is not called on the main thread.
        offMain({
            try { P2PLib.listContacts() } catch (e: Exception) { "[]" }
        }) { contactsJson ->
            val array = try {
                JSONArray(contactsJson)
            } catch (e: Exception) {
                JSONArray()
            }
            if (array.length() == 0) {
                Toast.makeText(requireContext(), R.string.msg_no_contacts_to_add, Toast.LENGTH_LONG).show()
            } else {
                val names = (0 until array.length()).map {
                    array.getJSONObject(it).optString("display_name", getString(R.string.lbl_unknown))
                }.toTypedArray()
                val identityIds = (0 until array.length()).map { array.getJSONObject(it).optString("identity_id") }
                val checked = BooleanArray(names.size)

                AlertDialog.Builder(requireContext())
                    .setTitle(R.string.lbl_add_member_to_group)
                    .setMultiChoiceItems(names, checked) { _, which, isChecked -> checked[which] = isChecked }
                    .setPositiveButton(R.string.lbl_add_member_to_group) { _, _ ->
                        offMain({
                            identityIds.indices.filter { checked[it] }
                                .map { it to P2PLib.inviteToGroup(groupId, identityIds[it]) }.filter { it.second != "OK" }
                        }) { failed ->
                            for ((i, r) in failed) {
                                Toast.makeText(requireContext(), "${names[i]}: ${errorText(r)}", Toast.LENGTH_SHORT).show()
                            }
                            refreshList()
                        }
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // The list refreshes on return to the screen and when an event arrives from the service
        // (no full rebuild every 5 seconds, see `eventListener`).
        if (inClosedDrawer()) staleWhileClosed = true else refreshList()
        com.p2p.messenger.service.P2PService.addMessageListener(eventListener)
        // 300 ms: the service leaves power save on the same resume.
        refreshHandler.postDelayed(syncRunnable, 300)
    }

    override fun onPause() {
        super.onPause()
        com.p2p.messenger.service.P2PService.removeMessageListener(eventListener)
        refreshHandler.removeCallbacks(eventRefreshRunnable)
        eventRefreshQueued = false
        refreshHandler.removeCallbacks(syncRunnable)
    }

    /** When the view is destroyed, the avatar bytes are released too. `allChatItems` held the FULL avatar of every
     *  contact and group (100-250 KB each), and it stayed in memory while the list was open in another tab. */
    override fun onDestroyView() {
        super.onDestroyView()
        refreshHandler.removeCallbacksAndMessages(null)
        allChatItems = emptyList()
        if (::adapter.isInitialized) adapter.submitList(emptyList())
    }

    override fun onDestroy() {
        super.onDestroy()
        // The worker is a live non-daemon thread, so it is shut down with the fragment.
        worker.shutdownNow()
    }

    /** JNI calls that take the core lock run off the main thread. [done] runs on the main thread while the
     *  fragment is still attached. */
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor()

    /** Runs [work] on the worker thread. The executor is shut down in `onDestroy`, so a late callback cannot crash the app. */
    private fun runOnWorker(work: () -> Unit) {
        try {
            worker.execute(work)
        } catch (e: java.util.concurrent.RejectedExecutionException) {
        // The fragment is gone, so there is no screen left to show the result on.
        }
    }

    private fun <T> offMain(work: () -> T, done: (T) -> Unit) {
        runOnWorker {
            // A detached fragment throws from getString, so the result is dropped.
            val result = try { work() } catch (e: Exception) {
                com.p2p.messenger.util.Log.w("ChatsFragment", "background call failed", e)
                return@runOnWorker
            }
            refreshHandler.post { if (isAdded && view != null) done(result) }
        }
    }

    @Volatile private var refreshing = false
    /** A refresh requested while one is running (after a delete, a pin, and so on) runs once more, because the running
     *  one may have read the old state. */
    @Volatile private var refreshAgain = false

    /** Rebuilds the whole list. It runs one history query and reads the whole attachment list per chat, under the core
     *  lock. On the main thread that caused stutter and an ANR behind a long poll turn. It runs when the screen comes
     *  back and when the service reports an event, NOT every 5 seconds (the cost this list had in every open chat and in
     *  every chat screen's drawer). */
    private fun refreshList() {
        if (refreshing) { refreshAgain = true; return }
        val ctx = context?.applicationContext ?: return
        refreshing = true
        runOnWorker {
            val result = try { buildChatItems(ctx) } catch (e: Exception) { null }
            refreshHandler.post {
                refreshing = false
                if (refreshAgain) { refreshAgain = false; refreshList() }
                if (result == null || !isAdded || view == null) return@post
                noContactsText.visibility = if (result.isEmpty()) View.VISIBLE else View.GONE
                allChatItems = result
                applyFilter()
            }
        }
    }

    private fun buildChatItems(ctx: android.content.Context): List<ChatAdapter.ChatMessage> {
        val contacts = loadContacts(ctx)
        val groups = loadGroups()
        val previews = try { JSONObject(P2PLib.chatListPreviews()) } catch (e: Exception) { null }

        val duplicateNames = com.p2p.messenger.util.ContactNames.duplicates(contacts.map { it.displayName })
        val contactItems = contacts.map { contact ->
            val fingerprint = contact.activeDeviceFingerprint ?: ""
            // The last row is a TEXT message or an ATTACHMENT. Whichever is newer is shown. Attachments are stored in the
            // `files` table, not in `messages`, so they are queried separately.
            val lastMessage = if (fingerprint.isNotEmpty()) previewOf(previews?.optJSONObject("contacts")?.optJSONObject(contact.identityId)) else null
            ChatAdapter.ChatMessage(
                contactId = fingerprint,
                displayName = com.p2p.messenger.util.ContactNames.label(contact.displayName, contact.identityId, duplicateNames),
                lastMessage = lastMessage?.text ?: "",
                timestamp = lastMessage?.timestamp ?: 0L,
                hasUnread = lastMessage != null &&
                    lastMessage.timestamp > ReadStatePrefs.lastReadAtForContact(ctx, contact.contactId, fingerprint),
                // Keyed on the STABLE contact id (not the device fingerprint, which changes if the contact re-pairs a
                // device), so a pin survives that.
                isPinned = PinnedChatsPrefs.isPinned(ctx, contact.contactId),
                realContactId = contact.contactId,
                avatarJpeg = contact.avatarHex?.let { hexToBytes(it) }
            )
        }
        val groupItems = groups.map { group ->
            // Groups get the same real last message and attachment preview as 1:1 contacts. The list needs a real
            // timestamp to sort by newest message. A fixed "N members" text never changes and carries no information.
            val lastMessage = previewOf(previews?.optJSONObject("groups")?.optJSONObject(group.groupId))
            ChatAdapter.ChatMessage(
                contactId = group.groupId,
                displayName = group.name,
                lastMessage = lastMessage?.text
                    ?: resources.getQuantityString(R.plurals.lbl_member_count, group.memberCount, group.memberCount),
                timestamp = lastMessage?.timestamp ?: 0L,
                hasUnread = lastMessage != null &&
                    lastMessage.timestamp > ReadStatePrefs.lastReadAt(ctx, "group:${group.groupId}"),
                isPinned = PinnedChatsPrefs.isPinned(ctx, "group:${group.groupId}"),
                avatarJpeg = group.avatarHex?.let { hexToBytes(it) },
                isGroup = true,
                isGroupFounder = group.isFounder
            )
        }
        // The chat list is ordered by the newest message sent or received, for contacts and groups together on one
        // timeline. A chat with no messages (timestamp = 0) sinks to the BOTTOM, as the descending sort does
        // naturally. Pinned chats (there can be several) stay ABOVE this order, and among themselves are ordered by
        // newest message too.
        return (contactItems + groupItems)
            .sortedWith(compareByDescending<ChatAdapter.ChatMessage> { it.isPinned }.thenByDescending { it.timestamp })
    }

    /** See the `allChatItems` / `searchQuery` notes at the top of the file. Case-insensitive search on the contact or
     *  group name (the raw `displayName`, not decorations such as the warning mark or the initial badge). */
    private fun applyFilter() {
        val query = searchQuery.trim()
        val filtered = if (query.isEmpty()) {
            allChatItems
        } else {
            allChatItems.filter { it.displayName.contains(query, ignoreCase = true) }
        }
        adapter.submitList(filtered) { adapter.refreshTimeLabels() }
    }

    private data class ContactRow(
        val contactId: String,
        val displayName: String,
        val identityId: String,
        val activeDeviceFingerprint: String?,
        val avatarHex: String?
    )
    private data class GroupRow(val groupId: String, val name: String, val memberCount: Int, val avatarHex: String?, val isFounder: Boolean)
    private data class LastMessagePreview(val text: String, val timestamp: Long)

    /** The newer of the last text row and the last attachment. One `chatListPreviews` call covers the whole list,
     *  instead of two per chat. */
    private fun previewOf(entry: JSONObject?): LastMessagePreview? {
        if (entry == null) return null
        val m = entry.optJSONObject("message")
        val a = entry.optJSONObject("attachment")
        val msg = m?.let {
            // A deleted row shows the placeholder, as the bubble does.
            LastMessagePreview(
                if (it.optBoolean("is_deleted", false)) getString(R.string.msg_deleted) else com.p2p.messenger.util.Quote.plain(it.optString("text", "")),
                it.optLong("timestamp", 0L)
            )
        }
        val att = a?.let {
            LastMessagePreview(attachmentPreviewLabel(it.optString("mime_type", ""), it.optString("file_name", ""), it.optBoolean("sticker")), it.optLong("created_at", 0L))
        }
        return when {
            msg == null -> att
            att == null -> msg
            att.timestamp > msg.timestamp -> att
            else -> msg
        }
    }

    /** Short label by attachment type. For unknown types, the file name. */
    private fun attachmentPreviewLabel(mimeType: String, fileName: String, sticker: Boolean): String = when {
        sticker -> getString(R.string.lbl_last_sticker)
        mimeType.startsWith("image/") -> getString(R.string.lbl_last_photo)
        mimeType.startsWith("video/") -> getString(R.string.lbl_last_video)
        mimeType.startsWith("audio/") -> getString(R.string.lbl_last_voice)
        fileName.isNotEmpty() -> "📎 $fileName"
        else -> getString(R.string.lbl_last_file)
    }

    private fun loadContacts(ctx: android.content.Context): List<ContactRow> {
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
                // The fallback is the same in both tabs (it used to be a different text here, and "Unknown" in the
                // contacts tab).
                displayName = obj.optString("display_name", ctx.getString(R.string.lbl_unknown)),
                identityId = obj.optString("identity_id"),
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
                avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null },
                // "Delete group for everyone" is shown only to the founder.
                isFounder = obj.optBoolean("is_founder", false)
            )
        }
    }
}
