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

// GroupChatActivity: history loading, paging and read-state sync.

/** IO thread: the newest page (texts + attachments, see `newestPage`), in send order, and the 'seen' viewers of its messages
 *  (see `seenViewersFromHistoryJson`). `knownIds`: rows already on screen keep their decoded preview. */
internal fun GroupChatActivity.readNewestGroupPage(gid: String, knownIds: Set<String> = emptySet()): Pair<List<SimpleChatAdapter.Item>, List<Pair<String, List<Pair<String, SimpleChatAdapter.SeenByViewer>>>>> {
    val array = try { JSONArray(P2PLib.getGroupMessageHistory(gid, CHAT_PAGE_SIZE)) } catch (e: Exception) { null }
    val texts = if (array != null) (0 until array.length()).map { itemFromGroupHistoryJson(array.getJSONObject(it)) } else emptyList()
    // Rows oldest to newest, replayed to `applySeen` in the same order, so the adapter settles on the last message seen.
    val seenEntries = if (array != null) (0 until array.length()).mapNotNull { i ->
        val obj = array.getJSONObject(i)
        val localId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
        val viewers = if (localId != null) seenViewersFromHistoryJson(obj) else emptyList()
        if (localId != null && viewers.isNotEmpty()) localId to viewers else null
    } else emptyList()
    val attachments = try {
        val att = JSONArray(P2PLib.listGroupAttachmentsBefore(gid, Long.MAX_VALUE, CHAT_PAGE_SIZE))
        (0 until att.length()).map { itemFromGroupAttachmentJson(att.getJSONObject(it), knownIds) }
    } catch (e: Exception) {
        emptyList()
    }
    return newestPage(texts, attachments).sortedBy { it.orderKey } to seenEntries
}

/**
 * Loads group history in the background, through `getGroupMessageHistory` (same pattern as ChatActivity.loadHistoryIfAvailable).
 * Without it, the screen would show only live messages, so reopening the screen or restarting the app would hide all visible history
 * (the Rust side keeps it in `archive_group_message`).
 *
 * The JNI calls (`getGroupMessageHistory` and `listGroupAttachments`) and the per-row parsing (`itemFromGroupHistoryJson` / `itemFromGroupAttachmentJson`,
 * which can make another JNI call through `resolveContactByIdentity`) run on `Dispatchers.IO`. Only the list and adapter update runs on the main thread.
 * `targetGroupId` stops a result from being applied to the wrong chat if the user switches to another group before the load finishes.
 */
internal fun GroupChatActivity.loadGroupHistoryIfAvailable() {
    val targetGroupId = groupId
    lifecycleScope.launch {
        val (merged, seenEntries) = withContext(Dispatchers.IO) { readNewestGroupPage(targetGroupId) }
        if (groupId != targetGroupId) return@launch
        // syncMissedGroupMessages (onResume) can race this: both fetch on
        // IO and either can finish first. Filter by what's already in
        // localMessages, checked here on the main thread right before
        // merging, and notify only the actually-new range.
        val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
        val newItems = merged.filter { it.messageId !in existingIds }
        if (newItems.isNotEmpty()) {
            localMessages.addAll(newItems)
            // If history loading finishes after a live message, appending would push the live message above the old history, off screen.
            // Re-sort by send order.
            localMessages.sortWith(compareBy { it.orderKey })
            resolveReplyLabels()
            adapter.notifyDataSetChanged()
            adapter.dedupeByMessageId()
            recycler.scrollToPosition(localMessages.size - 1)
        }
        // See `seenViewersFromHistoryJson`. The replay runs AFTER all messages are added to the adapter. `applySeen` returns -1 from `indexOfMessageId` for a row
        // not added yet, and only ONE pending entry (`pendingSeenMessageId`) can be held, so earlier calls would be overwritten.
        // The "who saw" info is refreshed even when `newItems` is empty (for example when these rows are already in localMessages).
        for ((localId, viewers) in seenEntries) {
            val map = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
            for ((identityId, viewer) in viewers) map[identityId] = viewer
            adapter.applySeen(localId, map.values.toList())
        }
    }
}

/**
 * Same pattern as ChatActivity's attachment-row loader: builds an `Item` from one JSON row of `listGroupAttachments`.
 * The sender (if this is not my own message) is resolved via `sender_identity_id`, the same logic as for text messages.
 */
internal fun GroupChatActivity.itemFromGroupAttachmentJson(obj: JSONObject, knownIds: Set<String> = emptySet()): SimpleChatAdapter.Item {
    val isMine = obj.optString("direction") == "sent"
    val senderIdentityId = if (obj.isNull("sender_identity_id")) null else obj.optString("sender_identity_id").ifEmpty { null }
    val sender = if (!isMine && senderIdentityId != null) resolveContactByIdentity(senderIdentityId) else null
    val previewHex = obj.optString("preview_hex", "")
    val previewJpeg = if (obj.optString("file_id") !in knownIds && previewHex.isNotEmpty() && previewHex != "null") hexToBytes(previewHex) else null
    return SimpleChatAdapter.Item(
        messageId = obj.optString("file_id"),
        text = "",
        isMine = isMine,
        timestamp = obj.optLong("created_at", System.currentTimeMillis()),
        expireSecs = Disappear.fromEvent(obj).first,
        expireAtMs = Disappear.fromEvent(obj).second,
        senderName = sender?.displayName ?: senderIdentityId?.take(8),
        senderAvatarJpeg = sender?.avatarHex?.let { sharedAvatarBytes(it) },
        senderIdentityId = senderIdentityId,
        attachment = SimpleChatAdapter.AttachmentInfo(
            fileId = obj.optString("file_id"),
            fileName = obj.optString("file_name"),
            mimeType = obj.optString("mime_type"),
            totalSize = obj.optLong("total_size"),
            status = parseAttachmentStatus(obj.optString("status")),
            bytesDone = obj.optLong("bytes_transferred"),
            previewJpeg = previewJpeg,
            durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it },
            peerDeviceFingerprint = obj.optString("peer_device_fingerprint"),
            isSticker = obj.optBoolean("sticker", false)
        ),
        // Same as ChatActivity: an attachment from the archive also keeps its caption and reply context.
        caption = obj.optString("caption", ""),
        replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null },
        replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
    )
}

internal fun GroupChatActivity.parseAttachmentStatus(status: String): SimpleChatAdapter.AttachmentStatus = when (status) {
    "downloading" -> SimpleChatAdapter.AttachmentStatus.DOWNLOADING
    "complete" -> SimpleChatAdapter.AttachmentStatus.COMPLETE
    "failed" -> SimpleChatAdapter.AttachmentStatus.FAILED
    else -> SimpleChatAdapter.AttachmentStatus.OFFERED
}

/**
 * Same note as ChatActivity.itemFromHistoryJson: a JSON row from any of the three sources (local first load, local older page, older page from the network)
 * is parsed the same way.
 */
internal fun GroupChatActivity.itemFromGroupHistoryJson(obj: JSONObject): SimpleChatAdapter.Item {
    val direction = obj.optString("direction")
    val isMine = direction == "sent"
    val senderIdentityId = if (obj.isNull("sender_identity_id")) null else obj.optString("sender_identity_id").ifEmpty { null }
    val sender = if (!isMine && senderIdentityId != null) resolveContactByIdentity(senderIdentityId) else null
    val messageId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
    // Same as ChatActivity.itemFromHistoryJson (WhatsApp-style reply). `replyToSenderLabel` cannot be resolved here; see `resolveReplyLabels`.
    val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
    val replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
    val replyToSenderIdentityId = if (obj.isNull("reply_to_sender_identity_id")) null else obj.optString("reply_to_sender_identity_id").ifEmpty { null }
    val relayedBy = if (obj.isNull("relayed_by")) null else obj.optString("relayed_by").ifEmpty { null }
    return SimpleChatAdapter.Item(
        messageId = messageId ?: UUID.randomUUID().toString(),
        relayedByName = relayedBy?.let { resolveContactByIdentity(it)?.displayName ?: it.take(8) },
        text = obj.optString("text"),
        isMine = isMine,
        status = if (!isMine) SimpleChatAdapter.Status.SENT else when (if (obj.isNull("status")) "sent" else obj.optString("status", "sent")) {
            "pending" -> SimpleChatAdapter.Status.PENDING
            "error" -> SimpleChatAdapter.Status.ERROR
            else -> SimpleChatAdapter.Status.SENT
        },
        timestamp = obj.optLong("timestamp", System.currentTimeMillis()),
        // Send order: the sender's send time (same note as ChatActivity).
        sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 },
        senderName = sender?.displayName ?: senderIdentityId?.take(8),
        senderAvatarJpeg = sender?.avatarHex?.let { sharedAvatarBytes(it) },
        // See the Item.senderIdentityId docs. It is always stored, regardless of `isMine`. Archive 'sent' rows also carry `sender_identity_id`
        // (see the Rust `archive_group_message` call site), so the next reply can carry the correct identity (see `startReply`).
        senderIdentityId = senderIdentityId,
        replyToMessageId = replyToMessageId,
        replyToPreview = replyToPreview,
        replyToSenderIdentityId = replyToSenderIdentityId,
        isDeleted = obj.optBoolean("is_deleted", false),
        // The '(edited)' label comes from the archived `is_edited` flag (see Rust `ArchivedMessage.is_edited`), so it survives a reopen,
        // not only the live edit event.
        isEdited = obj.optBoolean("is_edited", false),
        mentionsMe = obj.optBoolean("mentions_me", false),
        reactions = obj.optString("reactions", ""),
        expireSecs = Disappear.fromEvent(obj).first,
        expireAtMs = Disappear.fromEvent(obj).second
    )
}

/**
 * Seen state for old messages. Live `handleIncomingSeen` events fill `seenByPerMessage` only while the screen is open.
 * The history row's `seen_by` (see Rust `ArchivedMessage.seen_by`) is resolved the same way as `handleIncomingSeen`, so messages seen while the chat
 * was closed still show in the 'seen by' list after a reopen. It returns `(identityId, viewer)` pairs, so the caller can write them into
 * `seenByPerMessage` with the same key.
 */
internal fun GroupChatActivity.seenViewersFromHistoryJson(obj: JSONObject): List<Pair<String, SimpleChatAdapter.SeenByViewer>> {
    val raw = obj.optString("seen_by", "[]").ifEmpty { "[]" }
    val arr = try { JSONArray(raw) } catch (e: Exception) { return emptyList() }
    val out = mutableListOf<Pair<String, SimpleChatAdapter.SeenByViewer>>()
    for (i in 0 until arr.length()) {
        val entry = arr.optJSONObject(i) ?: continue
        val identityId = entry.optString("identity_id")
        if (identityId.isEmpty()) continue
        val sender = resolveContactByIdentity(identityId)
        out.add(identityId to SimpleChatAdapter.SeenByViewer(
            avatarJpeg = sender?.avatarHex?.let { sharedAvatarBytes(it) },
            displayName = sender?.displayName ?: identityId.take(8)
        ))
    }
    return out
}

/** The label over a quote: "You" or the sender name of the quoted
 *  message, only when that message is in the local history. */
internal fun GroupChatActivity.resolveReplyLabel(replyToMessageId: String?, replyToSenderIdentityId: String? = null): String? {
    if (replyToMessageId == null) return null
    val target = localMessages.find { it.messageId == replyToMessageId }
    if (target != null) {
        return if (target.isMine) getString(R.string.lbl_you) else target.senderName
    }
    // The quoted message is not here: the sender-claimed author id is
    // not trusted, so no name is shown (a member could forge a quote
    // attributed to someone else).
    return null
}

/** Same pattern as ChatActivity.resolveReplyLabels. */
internal fun GroupChatActivity.resolveReplyLabels() {
    val byId = localMessages.associateBy { it.messageId }
    for (item in localMessages) {
        val id = item.replyToMessageId ?: continue
        val target = byId[id]
        item.replyToSenderLabel = if (target == null) null
            else if (target.isMine) getString(R.string.lbl_you) else target.senderName
    }
}

/**
 * Same pattern as ChatActivity.loadOlderHistory. When the top of the group history is scrolled to, it first tries the free local archive.
 * If that is not enough, it asks all reachable members over the network (see the Rust `request_older_group_history` fan-out).
 */
internal fun GroupChatActivity.loadOlderGroupHistory() {
    if (isLoadingOlderHistory || noMoreOlderHistory || localMessages.isEmpty()) return
    isLoadingOlderHistory = true
    progressOlderHistory.visibility = View.VISIBLE
    // Texts and attachments page on cursors of their own (separate tables).
    val beforeTimestamp = localMessages.filter { it.attachment == null }.minOfOrNull { it.timestamp }
        ?: localMessages.minOf { it.timestamp }
    val beforeAttachment = localMessages.filter { it.attachment != null }.minOfOrNull { it.timestamp } ?: Long.MAX_VALUE
    val gid = groupId
    // off the main thread (core lock); an empty page means the end of the archive.
    lifecycleScope.launch {
        val localOlder = withContext(Dispatchers.IO) {
            try {
                val json = P2PLib.getGroupMessageHistoryBefore(gid, beforeTimestamp, CHAT_PAGE_SIZE)
                val array = JSONArray(json)
                (0 until array.length()).map { itemFromGroupHistoryJson(array.getJSONObject(it)) }
            } catch (e: Exception) {
                null
            }
        }
        // Attachments older than the oldest loaded one (own cursor).
        val olderAttachments = withContext(Dispatchers.IO) {
            try {
                val array = JSONArray(P2PLib.listGroupAttachmentsBefore(gid, beforeAttachment, CHAT_PAGE_SIZE))
                (0 until array.length()).map { itemFromGroupAttachmentJson(array.getJSONObject(it)) }
            } catch (e: Exception) {
                emptyList()
            }
        }
        if (gid == groupId) {
            val page = newestPage(localOlder ?: emptyList(), olderAttachments)
            if (page.isNotEmpty()) prependOlderMessages(page)
            else if (localOlder != null) noMoreOlderHistory = true
        }
        isLoadingOlderHistory = false
        progressOlderHistory.visibility = View.GONE
    }
}

/** See `loadOlderGroupHistory`: an 'older_group_history' network reply from a member. An empty array means this group is not asked again. */
internal fun GroupChatActivity.applyOlderGroupHistory(obj: JSONObject) {
    val array = obj.optJSONArray("messages") ?: return
    // Every member answers; a later answer may carry reactions the first lacked.
    for (i in 0 until array.length()) {
        val m = array.getJSONObject(i)
        val reactions = m.optString("reactions")
        if (reactions.isNotEmpty()) adapter.applyReactions(m.optString("message_id"), reactions)
    }
    // Only what the "Fetch older history" button asked for.
    if (!fetchHistoryButton.acceptsReply()) return
    // Empty: another source (peer, own device, server) may still answer.
    if (array.length() == 0) return
    fetchHistoryButton.onBackfilled()
    val items = (0 until array.length()).map { itemFromGroupHistoryJson(array.getJSONObject(it)) }
    prependOlderMessages(items)
}

/** Same note as ChatActivity.prependOlderMessages. */
internal fun GroupChatActivity.prependOlderMessages(items: List<SimpleChatAdapter.Item>) {
    if (items.isEmpty()) return
    val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
    val fresh = items.filter { it.messageId !in existingIds }.sortedBy { it.orderKey }
    if (fresh.isEmpty()) return
    if (fresh.last().orderKey > localMessages.firstOrNull()?.orderKey ?: Long.MAX_VALUE) {
        // The page belongs BELOW rows already shown (old attachments):
        // merge by send order and keep the row the user is looking at.
        val lm = recycler.layoutManager as? LinearLayoutManager
        val anchorPos = lm?.findFirstVisibleItemPosition() ?: -1
        val anchor = localMessages.getOrNull(anchorPos)
        val anchorTop = lm?.findViewByPosition(anchorPos)?.top ?: 0
        localMessages.addAll(fresh)
        localMessages.sortWith(compareBy { it.orderKey })
        resolveReplyLabels()
        adapter.notifyDataSetChanged()
        if (anchor != null) lm?.scrollToPositionWithOffset(localMessages.indexOf(anchor), anchorTop)
        return
    }
    localMessages.addAll(0, fresh)
    resolveReplyLabels()
    adapter.notifyItemRangeInserted(0, fresh.size)
}

// the core lock is not taken on the main thread.
internal fun GroupChatActivity.syncGroupReadStateAsync() {
    val gid = groupId
    val now = System.currentTimeMillis()
    Thread { try { P2PLib.syncReadState("", gid, now) } catch (e: Exception) {} }.start()
}

internal fun GroupChatActivity.scheduleGroupReadWatermark() {
    if (!AppLock.isUnlocked()) return
    groupReadWatermarkHandler.removeCallbacks(groupReadWatermarkRunnable)
    groupReadWatermarkHandler.postDelayed(groupReadWatermarkRunnable, 700L)
}

/** See the onResume call site — group version of
 *  ChatActivity.syncMissedMessages, same "only newer" idea keyed on
 *  message/file id so it's safe to call redundantly. */
internal fun GroupChatActivity.syncMissedGroupMessages() {
    val targetGroupId = groupId
    // See ChatActivity.syncMissedMessages: rows on screen keep their preview.
    val knownIds = localMessages.mapTo(HashSet()) { it.messageId }
    lifecycleScope.launch {
        val (merged, seenEntries) = withContext(Dispatchers.IO) { readNewestGroupPage(targetGroupId, knownIds) }
        if (groupId != targetGroupId) return@launch
        // Recompute existingIds here, right before merging, not before the
        // IO fetch above — loadGroupHistoryIfAvailable can insert
        // concurrently while this fetch is in flight, and a set captured
        // earlier would be stale, causing duplicate inserts.
        // Hole after a long background: see ChatActivity.syncMissedMessages.
        if (merged.size >= CHAT_PAGE_SIZE && localMessages.isNotEmpty() &&
            merged.minOf { it.timestamp } > localMessages.maxOf { it.timestamp }
        ) {
            localMessages.clear()
            noMoreOlderHistory = false
        }
        val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
        val missed = merged.filter { it.messageId !in existingIds }
        if (adapter.refreshFrom(merged)) resolveReplyLabels()
        if (missed.isNotEmpty()) {
            localMessages.addAll(missed)
            // If history loading finishes after a live message, appending would push the live message above the old history, off screen (observed on a device).
            // So re-sort by send order.
            localMessages.sortWith(compareBy { it.orderKey })
            resolveReplyLabels()
            adapter.notifyDataSetChanged()
            adapter.dedupeByMessageId()
            onNewIncomingItemAdded()
        }
        // Same seen-replay note as under `loadGroupHistoryIfAvailable`.
        for ((localId, viewers) in seenEntries) {
            val map = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
            for ((identityId, viewer) in viewers) map[identityId] = viewer
            adapter.applySeen(localId, map.values.toList())
        }
    }
}
