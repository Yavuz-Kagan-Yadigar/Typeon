package com.p2p.messenger.ui

import com.p2p.messenger.util.safeSaveFileName
import android.app.AlertDialog
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.media.MediaMetadataRetriever
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.media.MediaScannerConnection
import android.media.PlaybackParams
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.OpenableColumns
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.ImageView
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
import com.google.android.material.color.MaterialColors
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.AppRestarter
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.CapturedImage
import com.p2p.messenger.util.promptAttachmentCaption
import com.p2p.messenger.util.ReactionPicker
import com.p2p.messenger.util.ConnectionStatus
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.KeyboardInsets
import com.p2p.messenger.util.NotificationHelper
import com.p2p.messenger.util.OutgoingMedia
import com.p2p.messenger.util.PlaybackSpeed
import com.p2p.messenger.util.PulsingStatusDot
import com.p2p.messenger.util.ReadStatePrefs
import com.p2p.messenger.util.ThemePrefs
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
import com.p2p.messenger.ui.ChatActivity.Companion.MAX_ATTACHMENT_SIZE
import com.p2p.messenger.ui.ChatActivity.Companion.PREVIEW_JPEG_QUALITY
import com.p2p.messenger.ui.ChatActivity.Companion.PREVIEW_MAX_DIMENSION
import com.p2p.messenger.ui.ChatActivity.Companion.RECORDING_CANCEL_SWIPE_DP
import com.p2p.messenger.ui.ChatActivity.Companion.RECORDING_MIN_DURATION_MS
import com.p2p.messenger.ui.ChatActivity.Companion.REPLY_HIGHLIGHT_DURATION_MS
import com.p2p.messenger.ui.ChatActivity.Companion.REPLY_PREVIEW_MAX_CHARS
import com.p2p.messenger.ui.ChatActivity.Companion.REPLY_SWIPE_MAX_DP
import com.p2p.messenger.ui.ChatActivity.Companion.TYPHOON_QUIET_WINDOW_MS
import com.p2p.messenger.ui.ChatActivity.Companion.TYPING_INDICATOR_TIMEOUT_MS

// ChatActivity: history loading, paging, history sync and read-state sync.

// ---------------------------------------------------------------
// History
// ---------------------------------------------------------------

internal fun ChatActivity.loadHistoryIfAvailable(targetPeer: String) {
    lifecycleScope.launch {
        val merged = withContext(Dispatchers.IO) { readNewestPage(targetPeer) }
        if (peerDeviceFingerprint != targetPeer) return@launch
        val (mergedItems, seenMessageIds) = merged
        // `syncMissedMessages` (onResume) can race this: both fetch on
        // IO and either can finish first. Filter by what's already in
        // `localMessages` (checked here, on the main thread, right
        // before merging) and notify only the actually-new range —
        // otherwise a duplicate insert or a wrong notifyItemRangeInserted
        // count corrupts RecyclerView's internal state.
        val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
        val newItems = mergedItems.filter { it.messageId !in existingIds }
        if (newItems.isNotEmpty()) {
            localMessages.addAll(newItems)
            // If history loading finishes after a live message, appending would push the live message above the old history, off screen. Re-sort by send order.
            localMessages.sortWith(compareBy { it.orderKey })
            resolveReplyLabels()
            adapter.notifyDataSetChanged()
            // `dedupeByMessageId`: the loadHistory and syncMissed paths can race and add the same message_id twice.
            adapter.dedupeByMessageId()
            recycler.scrollToPosition(localMessages.size - 1)
        }
        // The 'seen' state is read from the archive too, not only from live events, so a message seen while the chat was closed still shows as seen after a reopen
        // (the Rust `message_seen` table holds it). A replay for a row not added yet is held by `applySeen` and applied when the row arrives.
        if (seenMessageIds.isNotEmpty()) {
            val viewer = SimpleChatAdapter.SeenByViewer(
                peerAvatar(), txtToolbarTitle.text.toString()
            )
            for (id in seenMessageIds) adapter.applySeen(id, listOf(viewer))
        }
        // No history request to the peer on open: only the "fetch older
        // history" action goes to the network (P2PLib.fetchServerHistory).
    }
}

/**
 * Parses a JSON row from any of the three sources (local first load, local older page, older page from the network) the same way.
 * The 'status' field is not carried on the network path, so it can be missing. In that case it falls back to 'sent', the same assumption as for older rows.
 */
internal fun ChatActivity.itemFromHistoryJson(obj: JSONObject): SimpleChatAdapter.Item {
    val direction = obj.optString("direction")
    val text = obj.optString("text")
    val timestamp = obj.optLong("timestamp", System.currentTimeMillis())
    val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
    val messageId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
    val status = if (obj.isNull("status")) null else obj.optString("status").ifEmpty { null }
    val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
    val replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
    val isDeleted = obj.optBoolean("is_deleted", false)
    val isEdited = obj.optBoolean("is_edited", false)
    return SimpleChatAdapter.Item(
        messageId = messageId ?: UUID.randomUUID().toString(),
        text = text,
        isMine = direction == "sent",
        timestamp = timestamp,
        sentAtMs = sentAtMs,
        status = if (direction == "sent") parseStatus(status ?: "sent") else SimpleChatAdapter.Status.SENT,
        isEdited = isEdited,
        viaSync = obj.optBoolean("via_sync", false),
        isDeleted = isDeleted,
        replyToMessageId = replyToMessageId,
        replyToPreview = replyToPreview,
        // The 1:1 history load now reads the reaction summary too (the group path, `itemFromGroupHistoryJson`, already did). Reactions are kept in the DB
        // (`message_reactions`) and show in the live event, but a reopen or app restart would hide them. `load_message_history` puts the `reactions` field
        // in the JSON (see Rust `reactions_summary`).
        reactions = obj.optString("reactions", ""),
        expireSecs = Disappear.fromEvent(obj).first,
        expireAtMs = Disappear.fromEvent(obj).second
    )
}

/** The 'replying to' label in the quote box. In 1:1 there are only two possibilities: me or the other side. */
internal fun ChatActivity.resolveReplyLabel(replyToMessageId: String?): String? {
    if (replyToMessageId == null) return null
    val target = localMessages.firstOrNull { it.messageId == replyToMessageId } ?: return null
    return if (target.isMine) getString(R.string.lbl_you) else txtToolbarTitle.text?.toString()
}

/** After new rows are added: the target of a reply may only be loaded NOW (for example an older page arrived), so the labels are refreshed. */
internal fun ChatActivity.resolveReplyLabels() {
    val byId = localMessages.associateBy { it.messageId }
    for (item in localMessages) {
        val id = item.replyToMessageId ?: continue
        val target = byId[id]
        item.replyToSenderLabel = if (target == null) null
            else if (target.isMine) getString(R.string.lbl_you) else txtToolbarTitle.text?.toString()
    }
}

/**
 * Infinite scroll: one page from the LOCAL archive. Nothing is sent over the network.
 */
internal fun ChatActivity.loadOlderHistory() {
    if (isLoadingOlderHistory || noMoreOlderHistory || localMessages.isEmpty()) return
    isLoadingOlderHistory = true
    progressOlderHistory.visibility = View.VISIBLE
    // Texts and attachments page on cursors of their own (separate tables).
    val beforeTimestamp = localMessages.filter { it.attachment == null }.minOfOrNull { it.timestamp }
        ?: localMessages.minOf { it.timestamp }
    val beforeAttachment = localMessages.filter { it.attachment != null }.minOfOrNull { it.timestamp } ?: Long.MAX_VALUE
    val peer = peerDeviceFingerprint
    // the archive query takes the core lock; scrolling must not wait for it.
    lifecycleScope.launch {
        val localOlder = withContext(Dispatchers.IO) {
            try {
                val json = P2PLib.getMessageHistoryBefore(peer, beforeTimestamp, CHAT_PAGE_SIZE)
                val array = JSONArray(json)
                (0 until array.length()).map { itemFromHistoryJson(array.getJSONObject(it)) }
            } catch (e: Exception) {
                null
            }
        }
        // Attachments older than the oldest loaded one (own cursor).
        val olderAttachments = withContext(Dispatchers.IO) {
            try {
                val array = JSONArray(P2PLib.listAttachmentsBefore(peer, beforeAttachment, CHAT_PAGE_SIZE))
                (0 until array.length()).map { attachmentItemFromJson(array.getJSONObject(it)) }
            } catch (e: Exception) {
                emptyList()
            }
        }
        if (peer == peerDeviceFingerprint) {
            val page = newestPage(localOlder ?: emptyList(), olderAttachments)
            if (page.isNotEmpty()) prependOlderMessages(page)
            // an empty page from the local archive is the end of it.
            else if (localOlder != null) noMoreOlderHistory = true
        }
        // Local archive only: scrolling sends nothing to the network.
        isLoadingOlderHistory = false
        progressOlderHistory.visibility = View.GONE
    }
}

/** IO thread: the newest page (texts + attachments, see `newestPage`), in send order, and the ids of
 *  its messages that carry a 'seen' mark. `knownIds`: rows already on screen keep their decoded preview. */
internal fun ChatActivity.readNewestPage(peer: String, knownIds: Set<String> = emptySet()): Pair<List<SimpleChatAdapter.Item>, List<String>> {
    val seen = mutableListOf<String>()
    val texts = try {
        val array = JSONArray(P2PLib.getMessageHistory(peer, CHAT_PAGE_SIZE))
        (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            val id = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
            if (id != null && obj.optString("seen_by", "[]").ifEmpty { "[]" } != "[]") seen.add(id)
            itemFromHistoryJson(obj)
        }
    } catch (e: Exception) {
        emptyList()
    }
    val attachments = try {
        val array = JSONArray(P2PLib.listAttachmentsBefore(peer, Long.MAX_VALUE, CHAT_PAGE_SIZE))
        (0 until array.length()).map { attachmentItemFromJson(array.getJSONObject(it), knownIds) }
    } catch (e: Exception) {
        emptyList()
    }
    return newestPage(texts, attachments).sortedBy { it.orderKey } to seen
}

/** Item from one `listAttachments`-shaped JSON row. No preview decode for ids in `skipPreview`. */
internal fun ChatActivity.attachmentItemFromJson(obj: JSONObject, skipPreview: Set<String> = emptySet()): SimpleChatAdapter.Item {
    val previewHex = if (obj.optString("file_id") in skipPreview) "" else obj.optString("preview_hex", "")
    return SimpleChatAdapter.Item(
        messageId = obj.optString("file_id"),
        text = "",
        isMine = obj.optString("direction") == "sent",
        expireSecs = Disappear.fromEvent(obj).first,
        expireAtMs = Disappear.fromEvent(obj).second,
        // My file's offer status (`send_status`), so an ERROR mark survives a reload.
        status = if (obj.isNull("send_status")) SimpleChatAdapter.Status.SENT else parseStatus(obj.optString("send_status")),
        timestamp = obj.optLong("created_at", System.currentTimeMillis()),
        attachment = SimpleChatAdapter.AttachmentInfo(
            fileId = obj.optString("file_id"),
            fileName = obj.optString("file_name"),
            mimeType = obj.optString("mime_type"),
            totalSize = obj.optLong("total_size"),
            status = parseAttachmentStatus(obj.optString("status")),
            bytesDone = obj.optLong("bytes_transferred"),
            previewJpeg = if (previewHex.isNotEmpty() && previewHex != "null") hexToBytes(previewHex) else null,
            durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it },
            isSticker = obj.optBoolean("sticker", false)
        ),
        caption = obj.optString("caption", ""),
        replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null },
        replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
    )
}

/** See `loadOlderHistory`: an 'older_history' network reply from the other side. Only the reply to the "Fetch older history" button is accepted,
 *  and an empty reply is ignored. */
internal fun ChatActivity.applyOlderHistory(obj: JSONObject) {
    // Only what the "Fetch older history" button asked for.
    if (!fetchHistoryButton.acceptsReply()) return
    val array = obj.optJSONArray("messages") ?: return
    // Empty: another source (peer, own device, server) may still answer.
    if (array.length() == 0) return
    fetchHistoryButton.onBackfilled()
    val items = (0 until array.length()).map { itemFromHistoryJson(array.getJSONObject(it)) }
    prependOlderMessages(items)
}

/** Adds older page results to the START of the list, shared by the local and network paths. A message already on screen (same `message_id`)
 *  is not added again, for example when the local page and the network reply contain the same rows. */
internal fun ChatActivity.prependOlderMessages(items: List<SimpleChatAdapter.Item>) {
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
    // See `resolveReplyLabels`: an older page may bring a reply chain not seen before (for example when the replied-to message is on this page too).
    resolveReplyLabels()
    adapter.notifyItemRangeInserted(0, fresh.size)
}

// the core lock is not taken on the main thread.
internal fun ChatActivity.syncReadStateAsync() {
    val peer = peerDeviceFingerprint
    val now = System.currentTimeMillis()
    Thread { try { P2PLib.syncReadState(peer, "", now) } catch (e: Exception) { } }.start()
}

/** Sends the 'read up to here' boundary to the other side. Debounced: many calls are collected into one packet (the Rust side cancels a pending
 *  older boundary, see `sync_read_state`). Called on chat open, `onResume`, and after a live message arrives. */
internal fun ChatActivity.scheduleReadWatermark() {
    if (!AppLock.isUnlocked()) return
    readWatermarkHandler.removeCallbacks(readWatermarkRunnable)
    readWatermarkHandler.postDelayed(readWatermarkRunnable, 700L)
}

/** Messages that arrive while the screen is in the background are not heard by `messageListener`, so they do not reach the screen. They are read from
 *  the archive and the missing ones are filled in. For the race condition see the same note under `loadHistoryIfAvailable` (both run on IO, and which finishes first is not known). */
internal fun ChatActivity.syncMissedMessages() {
    val targetPeer = peerDeviceFingerprint
    // Runs on every resume: rows already on screen keep their decoded
    // preview (see `refreshFrom`) instead of decoding it from hex again.
    val knownIds = localMessages.mapTo(HashSet()) { it.messageId }
    lifecycleScope.launch {
        val missed = withContext(Dispatchers.IO) { readNewestPage(targetPeer, knownIds) }
        if (peerDeviceFingerprint != targetPeer) return@launch
        val (missedItems, seenMessageIds) = missed
        // A full newest page that starts after everything on screen leaves a hole that scroll-up paging never reads: drop the old rows, paging refills them.
        if (missedItems.size >= CHAT_PAGE_SIZE && localMessages.isNotEmpty() &&
            missedItems.minOf { it.timestamp } > localMessages.maxOf { it.timestamp }
        ) {
            localMessages.clear()
            noMoreOlderHistory = false
        }
        val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
        val fresh = missedItems.filter { it.messageId !in existingIds }
        if (adapter.refreshFrom(missedItems)) resolveReplyLabels()
        if (fresh.isNotEmpty()) {
            localMessages.addAll(fresh)
            // If history loading finishes after a live message, appending would push the live message above the old history, off screen. Re-sort by send order.
            localMessages.sortWith(compareBy { it.orderKey })
            resolveReplyLabels()
            adapter.notifyDataSetChanged()
            adapter.dedupeByMessageId()
            onNewIncomingItemAdded()
        }
        // See the same 'seen' replay note under `loadHistoryIfAvailable`.
        if (seenMessageIds.isNotEmpty()) {
            val viewer = SimpleChatAdapter.SeenByViewer(
                peerAvatar(), txtToolbarTitle.text.toString()
            )
            for (id in seenMessageIds) adapter.applySeen(id, listOf(viewer))
        }
    }
}
