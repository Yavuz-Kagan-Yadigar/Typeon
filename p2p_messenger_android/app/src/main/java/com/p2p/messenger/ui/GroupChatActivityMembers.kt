package com.p2p.messenger.ui

import com.p2p.messenger.util.safeSaveFileName
import android.Manifest
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Canvas
import android.media.MediaMetadataRetriever
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.media.PlaybackParams
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListPopupWindow
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.ActionBar
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SearchView
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.coreErrorText
import com.p2p.messenger.util.AppRestarter
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.CapturedImage
import com.p2p.messenger.util.promptAttachmentCaption
import com.p2p.messenger.util.ReactionPicker
import com.p2p.messenger.util.ConnectionStatus
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.MAX_FOREIGN_URI_BYTES
import com.p2p.messenger.util.copyToCapped
import com.p2p.messenger.util.KeyboardInsets
import com.p2p.messenger.util.OutgoingMedia
import com.p2p.messenger.util.PlaybackSpeed
import com.p2p.messenger.util.PulsingStatusDot
import com.p2p.messenger.util.hexToBytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import com.p2p.messenger.ui.GroupChatActivity.Companion.AVATAR_JPEG_QUALITY
import com.p2p.messenger.ui.GroupChatActivity.Companion.AVATAR_MAX_DIMENSION
import com.p2p.messenger.ui.GroupChatActivity.Companion.CONTACT_CACHE_TTL_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.MAX_ATTACHMENT_SIZE
import com.p2p.messenger.ui.GroupChatActivity.Companion.PREVIEW_JPEG_QUALITY
import com.p2p.messenger.ui.GroupChatActivity.Companion.PREVIEW_MAX_DIMENSION
import com.p2p.messenger.ui.GroupChatActivity.Companion.RECORDING_CANCEL_SWIPE_DP
import com.p2p.messenger.ui.GroupChatActivity.Companion.RECORDING_MIN_DURATION_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.REPLY_HIGHLIGHT_DURATION_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.REPLY_PREVIEW_MAX_CHARS
import com.p2p.messenger.ui.GroupChatActivity.Companion.REPLY_SWIPE_MAX_DP
import com.p2p.messenger.ui.GroupChatActivity.Companion.TYPHOON_QUIET_WINDOW_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.TYPING_INDICATOR_TIMEOUT_MS
import com.p2p.messenger.ui.GroupChatActivity.ContactLookup

// GroupChatActivity: group info, members, founder transfer, group picture, mentions, contact lookup.

/**
 * Fetches this group's current state from `listGroups()` (founder or not, members, profile photo) and updates the top bar avatar too.
 *
 * `P2PLib.listGroups()` (a JNI call plus a DB query over ALL groups, avatar hex blobs included) runs on a background thread, not synchronously on the
 * main thread from `bindToIntent` (and so from `onCreate`). None of the callers depends on the updated `isFounder` / `memberIdentityIds` right after the call
 * (they run at the end of an event or are triggered by another screen's refresh), so fire-and-forget on a background task is safe.
 */
internal fun GroupChatActivity.refreshGroupInfo() {
    val targetGroupId = groupId
    lifecycleScope.launch {
        val array = withContext(Dispatchers.IO) {
            try {
                JSONArray(P2PLib.listGroups())
            } catch (e: Exception) {
                null
            }
        } ?: return@launch
        if (groupId != targetGroupId) return@launch
        for (i in 0 until array.length()) {
            val obj = array.getJSONObject(i)
            if (obj.optString("group_id") != targetGroupId) continue
            isFounder = obj.optBoolean("is_founder")
            founderIdentityId = obj.optString("founder_identity_id")
            val avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
            currentGroupAvatar = avatarHex?.let { hexToBytes(it) }
            val members = obj.optJSONArray("member_identity_ids")
            memberIdentityIds = (0 until (members?.length() ?: 0)).map { members!!.getString(it) }
            adapter.mentionNames = mentionCandidates().map { it.second }
            adapter.notifyDataSetChanged()
            AvatarUtil.renderInto(imgToolbarAvatar, currentGroupAvatar, txtToolbarTitle.text.toString())
            return@launch
        }
        // The group is gone here: the founder deleted it or removed us.
        Toast.makeText(this@refreshGroupInfo, R.string.msg_group_gone, Toast.LENGTH_LONG).show()
        finish()
    }
}

/**
 * Tapping the top bar opens the member list and, for the founder only, the profile photo change and remove options, plus adding members.
 * The member and photo actions live here, not in the Groups tab.
 */
internal fun GroupChatActivity.showGroupInfoDialog() {
    val view = layoutInflater.inflate(R.layout.dialog_group_info, null)
    val imgAvatar = view.findViewById<ImageView>(R.id.imgGroupAvatarLarge)
    val rowAvatarActions = view.findViewById<View>(R.id.rowAvatarActions)
    val btnChange = view.findViewById<Button>(R.id.btnChangeGroupPicture)
    val btnRemove = view.findViewById<Button>(R.id.btnRemoveGroupPicture)
    val txtMemberCount = view.findViewById<TextView>(R.id.txtGroupMemberCount)
    val btnAddMember = view.findViewById<Button>(R.id.btnAddMemberToGroup)
    val layoutMembersList = view.findViewById<LinearLayout>(R.id.layoutMembersList)

    AvatarUtil.renderInto(imgAvatar, currentGroupAvatar, txtToolbarTitle.text.toString())
    imgAvatar.setOnClickListener { AvatarUtil.openFullscreen(this, currentGroupAvatar) }
    rowAvatarActions.visibility = if (isFounder) View.VISIBLE else View.GONE
    // For the founder, 'Manage members' also covers removing members, not just showing the count.
    txtMemberCount.text = if (isFounder) {
        getString(R.string.lbl_manage_members)
    } else {
        resources.getQuantityString(R.plurals.lbl_member_count, memberIdentityIds.size, memberIdentityIds.size)
    }
    // 'Add member' sits above the list.
    btnAddMember.visibility = if (isFounder) View.VISIBLE else View.GONE

    val dialog = AlertDialog.Builder(this)
        .setTitle(txtToolbarTitle.text)
        .setView(view)
        .setNegativeButton(android.R.string.ok, null)
        .create()

    // Each member's name, plus (founder only, not on their own row) a confirmed remove button. A local function redraws the list
    // after a removal, without closing and reopening the dialog.
    fun populateMembers() {
        layoutMembersList.removeAllViews()
        for (identityId in memberIdentityIds) {
            val row = layoutInflater.inflate(R.layout.item_group_member, layoutMembersList, false)
            val rowAvatar = row.findViewById<ImageView>(R.id.imgMemberAvatar)
            val rowName = row.findViewById<TextView>(R.id.txtMemberName)
            val rowRemoveButton = row.findViewById<Button>(R.id.btnRemoveMember)
            val contact = resolveContactByIdentity(identityId)
            val displayName = when {
                identityId == ownIdentityId -> getString(R.string.lbl_you)
                else -> contact?.displayName ?: (identityId.take(16) + "…")
            }
            rowName.text = if (identityId == founderIdentityId) getString(R.string.lbl_founder_badge, displayName) else displayName
            AvatarUtil.renderInto(rowAvatar, contact?.avatarHex?.let { hexToBytes(it) }, displayName)
            if (isFounder && identityId != founderIdentityId) {
                rowRemoveButton.visibility = View.VISIBLE
                rowRemoveButton.setOnClickListener {
                    confirmRemoveMember(identityId, displayName) { populateMembers() }
                }
                // If the founder loses all devices, the group is locked for good: nobody can add or remove members, or change its name or photo.
                // A long press on a member hands over the founder role, which avoids that.
                row.setOnLongClickListener {
                    confirmTransferFounder(identityId, displayName) {
                        dialog.dismiss()
                    }
                    true
                }
            } else {
                rowRemoveButton.visibility = View.GONE
            }
            layoutMembersList.addView(row)
        }
    }
    populateMembers()

    btnChange.setOnClickListener {
        AppLock.beginTrustedExcursion()
        pickGroupAvatarLauncher.launch(arrayOf("image/*"))
    }
    btnRemove.setOnClickListener {
        setGroupAvatar(null)
        dialog.dismiss()
    }
    btnAddMember.setOnClickListener {
        dialog.dismiss()
        showAddMembersDialog()
    }
    view.findViewById<Button>(R.id.btnGroupFilesMedia).setOnClickListener {
        dialog.dismiss()
        startActivity(Intent(this, StorageActivity::class.java)
            .putExtra(StorageActivity.EXTRA_CHAT_KIND, "group")
            .putExtra(StorageActivity.EXTRA_CHAT_ID, groupId)
            .putExtra(StorageActivity.EXTRA_CHAT_NAME, txtToolbarTitle.text.toString()))
    }
    if (isFounder) {
        // Founder-only: re-send the signed group state to every member device.
        val parent = btnAddMember.parent as ViewGroup
        parent.addView(Button(this).apply {
            setText(R.string.action_resend_group)
            setOnClickListener {
                val gid = groupId
                lifecycleScope.launch {
                    val result = withContext(Dispatchers.IO) {
                        try { P2PLib.resendGroupToAll(gid) } catch (e: Throwable) { "Error: ${e.message}" }
                    }
                    Toast.makeText(this@showGroupInfoDialog,
                        if (result.startsWith("Error:")) R.string.error_network else R.string.msg_group_resent,
                        Toast.LENGTH_SHORT).show()
                }
            }
        }, parent.indexOfChild(btnAddMember) + 1)
    }
    dialog.show()
}

/**
 * Asks for confirmation before removing a member (not the founder; see the caller). The removal cannot be undone:
 * Rust `remove_from_group` sends a signed `GroupChange::Remove` to all members.
 * `onRemoved` is the callback the caller passes (while the dialog is open), so the member list can be redrawn after a successful removal.
 */
/**
 * Hands the group's admin role to another member. After the handover, THIS device can no longer manage the group.
 */
internal fun GroupChatActivity.confirmTransferFounder(identityId: String, displayName: String, onDone: () -> Unit) {
    AlertDialog.Builder(this)
        .setTitle(R.string.action_transfer_founder)
        .setMessage(getString(R.string.confirm_transfer_founder, displayName))
        .setPositiveButton(R.string.action_transfer_founder) { _, _ ->
            val gid = groupId
            lifecycleScope.launch {
                // signs and fans out to every member; not on the main thread.
                val result = withContext(Dispatchers.IO) {
                    try { P2PLib.transferGroupFounder(gid, identityId) } catch (e: Throwable) { "Error: ${e.message}" }
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@confirmTransferFounder, com.p2p.messenger.util.coreErrorText(this@confirmTransferFounder, result), Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(this@confirmTransferFounder, R.string.msg_founder_transferred, Toast.LENGTH_LONG).show()
                    refreshGroupInfo()
                    onDone()
                }
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

internal fun GroupChatActivity.confirmRemoveMember(identityId: String, displayName: String, onRemoved: () -> Unit) {
    AlertDialog.Builder(this)
        .setMessage(getString(R.string.confirm_remove_member, displayName))
        .setPositiveButton(R.string.action_remove_member) { _, _ ->
            val gid = groupId
            lifecycleScope.launch {
                // signed fan-out to every member; not on the main thread.
                val ok = withContext(Dispatchers.IO) {
                    try { P2PLib.removeFromGroup(gid, identityId) } catch (e: Throwable) { "Error: ${e.message}" }
                }
                if (ok == "OK") {
                    Toast.makeText(this@confirmRemoveMember, R.string.msg_member_removed, Toast.LENGTH_SHORT).show()
                    // `refreshGroupInfo` is asynchronous; the dialog redraws now.
                    if (gid == groupId) memberIdentityIds = memberIdentityIds - identityId
                    refreshGroupInfo()
                    onRemoved()
                } else {
                    Toast.makeText(this@confirmRemoveMember, coreErrorText(this@confirmRemoveMember, ok), Toast.LENGTH_SHORT).show()
                }
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

internal fun GroupChatActivity.onGroupAvatarPicked(uri: Uri) {
    lifecycleScope.launch(Dispatchers.IO) {
        val tempFile = File(File(cacheDir, "group_avatar").apply { mkdirs() }, UUID.randomUUID().toString())
        try {
            // Foreign `content://` bytes: capped, else the avatar fails (same toast).
            val copied = contentResolver.openInputStream(uri)?.use { it.copyToCapped(tempFile, MAX_FOREIGN_URI_BYTES) } ?: false
            if (!copied) throw java.io.IOException("File could not be opened")
            val compressed = ImagePreview.compressFile(tempFile, AVATAR_MAX_DIMENSION, AVATAR_JPEG_QUALITY)
            withContext(Dispatchers.Main) { setGroupAvatar(compressed) }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                Toast.makeText(this@onGroupAvatarPicked, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
            }
        } finally {
            tempFile.delete()
        }
    }
}

/** Succeeds ONLY for the founder (see Rust `set_group_avatar`, which reuses the existing founder check of `validate_group_update`).
 *  A call from a non-founder returns "Error: ..." from Rust, and that error is shown here. */
internal fun GroupChatActivity.setGroupAvatar(avatarJpeg: ByteArray?) {
    currentGroupAvatar = avatarJpeg
    AvatarUtil.renderInto(imgToolbarAvatar, avatarJpeg, txtToolbarTitle.text.toString())
    lifecycleScope.launch(Dispatchers.IO) {
        val result = try {
            P2PLib.setGroupProfilePicture(groupId, avatarJpeg)
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
        if (result.startsWith("Error:")) {
            withContext(Dispatchers.Main) {
                Toast.makeText(this@setGroupAvatar, com.p2p.messenger.util.coreErrorText(this@setGroupAvatar, result), Toast.LENGTH_SHORT).show()
                refreshGroupInfo()
            }
        }
    }
}

/** See the old GroupsFragment.showAddMembersDialog, which moved here. */
internal fun GroupChatActivity.showAddMembersDialog() {
    // listContacts takes the core lock: off the main thread.
    lifecycleScope.launch {
        val contactsJson = withContext(Dispatchers.IO) {
            try { P2PLib.listContacts() } catch (e: Exception) { "[]" }
        }
        showAddMembersDialog(contactsJson)
    }
}

internal fun GroupChatActivity.showAddMembersDialog(contactsJson: String) {
    val array = try {
        JSONArray(contactsJson)
    } catch (e: Exception) {
        JSONArray()
    }
    if (array.length() == 0) {
        Toast.makeText(this, R.string.msg_no_contacts_to_add, Toast.LENGTH_LONG).show()
        return
    }
    // Not the people who are in the group already.
    val candidates = (0 until array.length()).map { array.getJSONObject(it) }
        .filter { it.optString("identity_id") !in memberIdentityIds }
    if (candidates.isEmpty()) {
        Toast.makeText(this, R.string.msg_no_contacts_to_add, Toast.LENGTH_LONG).show()
        return
    }
    val names = candidates.map { it.optString("display_name", getString(R.string.lbl_unknown)) }.toTypedArray()
    val identityIds = candidates.map { it.optString("identity_id") }
    val checked = BooleanArray(names.size)

    AlertDialog.Builder(this)
        .setTitle(R.string.lbl_add_member_to_group)
        .setMultiChoiceItems(names, checked) { _, which, isChecked -> checked[which] = isChecked }
        .setPositiveButton(R.string.lbl_add_member_to_group) { _, _ ->
            // Each invite signs, stores and sends under the core lock: off
            // the main thread (several at once froze the screen).
            val gid = groupId
            val picked = identityIds.indices.filter { checked[it] }
            lifecycleScope.launch {
                for (i in picked) {
                    val ok = withContext(Dispatchers.IO) {
                        try { P2PLib.inviteToGroup(gid, identityIds[i]) } catch (e: Throwable) { "Error: ${e.message}" }
                    }
                    if (ok != "OK") {
                        Toast.makeText(this@showAddMembersDialog, "${names[i]}: ${coreErrorText(this@showAddMembersDialog, ok)}", Toast.LENGTH_SHORT).show()
                    }
                }
                refreshGroupInfo()
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

/**
 * Sends a group message in the background. `P2PLib.sendGroupMessage` (JNI) runs a separate ratchet encryption, a hybrid signature and a gossipsub
 * publish attempt for EVERY member (see Rust `send_group_message`, the pairwise fan-out). On the main thread that froze touch input for the whole
 * time, which grows with group size. `btnSend` is now disabled while it runs and `progressSending` is shown instead (same pattern as ChatActivity).
 */
/** Other members as (identity id, display name), for @mentions. */
internal fun GroupChatActivity.mentionCandidates(): List<Pair<String, String>> =
    memberIdentityIds.filter { it != ownIdentityId }
        .map { it to (resolveContactByIdentity(it)?.displayName ?: it.take(8)) }

/** Ids of the members whose "@Name" is in [text], as a JSON array (null: none).
 *  The name must end at a non-letter/digit or the end of the text ("@Alice"
 *  does not mention "Al"); at each '@' only the longest matching name counts. */
internal fun GroupChatActivity.mentionIdsJson(fullText: String): String? {
    // A quoted message's @names are not mentions of this one.
    val text = com.p2p.messenger.util.Quote.withoutQuotes(fullText)
    val candidates = mentionCandidates()
    val ids = LinkedHashSet<String>()
    var at = text.indexOf('@')
    while (at >= 0) {
        val hits = candidates.filter { (_, name) ->
            val end = at + 1 + name.length
            name.isNotEmpty() && text.startsWith(name, at + 1) && (end == text.length || !text[end].isLetterOrDigit())
        }
        val longest = hits.maxOfOrNull { it.second.length }
        hits.filter { it.second.length == longest }.mapTo(ids) { it.first }
        at = text.indexOf('@', at + 1)
    }
    return if (ids.isEmpty()) null else JSONArray(ids.toList()).toString()
}

/** "@" + what follows it up to the cursor opens a member picker; a pick
 *  writes "@Name " in its place. */
internal fun GroupChatActivity.updateMentionPopup(input: EditText) {
    val text = input.text ?: return
    val cursor = input.selectionStart
    val at = if (cursor > 0) text.lastIndexOf('@', cursor - 1) else -1
    val query = if (at >= 0 && (at == 0 || text[at - 1].isWhitespace())) text.substring(at + 1, cursor) else null
    val matches = if (query == null || query.length > 32 || '\n' in query) emptyList()
        else mentionCandidates().filter { it.second.contains(query, ignoreCase = true) && it.second != query.trimEnd() }
    if (matches.isEmpty()) { mentionPopup?.dismiss(); return }
    val popup = mentionPopup ?: ListPopupWindow(this).also {
        it.anchorView = input
        it.inputMethodMode = ListPopupWindow.INPUT_METHOD_NEEDED
        mentionPopup = it
    }
    popup.setAdapter(android.widget.ArrayAdapter(this, android.R.layout.simple_list_item_1, matches.map { it.second }))
    popup.setOnItemClickListener { _, _, pos, _ ->
        popup.dismiss()
        text.replace(at, cursor, "@${matches[pos].second} ")
    }
    popup.show()
}

/** Short-lived cache for `resolveContactByIdentity`, so history loading does not repeat the same JNI/DB result over and over. */
@Volatile private var contactListCache: JSONArray? = null
@Volatile private var contactListCacheAt: Long = 0

/** One decoded avatar per distinct hex string: every bubble and seen-viewer of a member shares the same bytes. */
internal fun GroupChatActivity.sharedAvatarBytes(hex: String): ByteArray = avatarBytesCache.getOrPut(hex) { hexToBytes(hex) }

/**
 * Cached for a short time. Group history loading calls `resolveContactByIdentity` once per row (through `itemFromGroupHistoryJson` and `itemFromGroupAttachmentJson`).
 * Without a cache, each call re-runs `P2PLib.listContacts()`: a JNI call and a DB query that reads the whole contact list, avatar hex blobs included, and parses the JSON.
 * So a history of N rows would parse the whole list N times (N x M, M = number of contacts). The cache holds the result for `CONTACT_CACHE_TTL_MS`,
 * so one history-load burst shares one parse. The TTL is short and the live event handlers use the same function, so a changed contact shows up within a few seconds.
 */
internal fun GroupChatActivity.resolveContactByIdentity(identityId: String): ContactLookup? {
    return try {
        val now = System.currentTimeMillis()
        val cached = contactListCache
        val array = if (cached != null && now - contactListCacheAt < CONTACT_CACHE_TTL_MS) {
            cached
        } else if (cached != null && Looper.myLooper() == Looper.getMainLooper()) {
            // Every incoming message and every keystroke (mention popup)
            // resolves names on the main thread: a stale list is shown
            // once more and refreshed off it, not read under the core lock.
            refreshContactCacheAsync()
            cached
        } else if (Looper.myLooper() == Looper.getMainLooper()) {
            // First lookup on the main thread: do not read under the core lock; fill the cache off-thread.
            refreshContactCacheAsync()
            return null
        } else {
            JSONArray(P2PLib.listContacts()).also {
                contactListCache = it
                contactListCacheAt = now
            }
        }
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

@Volatile private var contactCacheRefreshing = false

internal fun GroupChatActivity.refreshContactCacheAsync() {
    if (contactCacheRefreshing) return
    contactCacheRefreshing = true
    lifecycleScope.launch(Dispatchers.IO) {
        try {
            contactListCache = JSONArray(P2PLib.listContacts())
            contactListCacheAt = System.currentTimeMillis()
        } catch (e: Exception) {
        } finally {
            contactCacheRefreshing = false
        }
    }
}
