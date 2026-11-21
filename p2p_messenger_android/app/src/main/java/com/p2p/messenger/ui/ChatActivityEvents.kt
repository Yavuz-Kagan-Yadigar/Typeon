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

// ChatActivity: incoming core events, sending text, seen and typing.

/** `expireSecs`: a disappearing message (see ui/Disappear.kt), 0 = an ordinary one. */
internal fun ChatActivity.sendNewMessage(text: String, expireSecs: Int = disappearSecs): kotlinx.coroutines.Job {
    btnSend.isEnabled = false
    btnSend.visibility = View.INVISIBLE
    progressSending.visibility = View.VISIBLE
    val targetPeer = peerDeviceFingerprint

    return lifecycleScope.launch {
        val result = withContext(Dispatchers.IO) {
            try {
                P2PLib.sendMessage(targetPeer, text, null, null, expireSecs.toLong())
            } catch (e: Throwable) {
                "Error: ${e.message}" // a JNI throw must not kill the process
            }
        }
        if (peerDeviceFingerprint != targetPeer) {
            progressSending.visibility = View.GONE
            btnSend.visibility = View.VISIBLE
            btnSend.isEnabled = true
            return@launch
        }
        if (result.startsWith("Error:") && findViewById<android.widget.EditText>(R.id.edtMessage).text.isNullOrBlank()) {
            // Nothing was queued: give the text back instead of a bubble that vanishes when the chat closes.
            Toast.makeText(this@sendNewMessage, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
            findViewById<android.widget.EditText>(R.id.edtMessage).apply { setText(text); setSelection(text.length) }
            progressSending.visibility = View.GONE
            btnSend.visibility = View.VISIBLE
            btnSend.isEnabled = true
            return@launch
        }
        val (messageId, status) = if (result.startsWith("Error:")) {
            Toast.makeText(this@sendNewMessage, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
            UUID.randomUUID().toString() to SimpleChatAdapter.Status.ERROR
        } else {
            try {
                val obj = JSONObject(result)
                obj.optString("message_id") to parseStatus(obj.optString("status"))
            } catch (e: Exception) {
                UUID.randomUUID().toString() to SimpleChatAdapter.Status.ERROR
            }
        }
        adapter.addMessage(
            SimpleChatAdapter.Item(
                messageId = messageId, text = text, isMine = true, status = status,
                expireSecs = expireSecs,
                expireAtMs = if (expireSecs > 0) System.currentTimeMillis() + expireSecs * 1000L else 0L
            )
        )
        scrollToBottomNow()
        maybePlayTyphoonEffect()
        progressSending.visibility = View.GONE
        btnSend.visibility = View.VISIBLE
        btnSend.isEnabled = true
    }
}

internal fun ChatActivity.parseStatus(status: String): SimpleChatAdapter.Status = when (status) {
    "sent", "delivered" -> SimpleChatAdapter.Status.SENT
    "error" -> SimpleChatAdapter.Status.ERROR
    else -> SimpleChatAdapter.Status.PENDING
}

internal fun ChatActivity.parseAttachmentStatus(status: String): SimpleChatAdapter.AttachmentStatus = when (status) {
    "downloading" -> SimpleChatAdapter.AttachmentStatus.DOWNLOADING
    "complete" -> SimpleChatAdapter.AttachmentStatus.COMPLETE
    "failed" -> SimpleChatAdapter.AttachmentStatus.FAILED
    else -> SimpleChatAdapter.AttachmentStatus.OFFERED
}

internal fun ChatActivity.handleIncomingEvent(obj: JSONObject) {
    // The listener filtered by peer on its thread; the chat may have been rebound since.
    if (!obj.isNull("peer") && obj.optString("peer").let { it.isNotEmpty() && it != peerDeviceFingerprint }) return
    when (obj.optString("type")) {
        "stickers_changed" -> stickerPicker.reload()
        "message" -> {
            val messageId = obj.optString("message_id")
            // The sender's embedded send time, the real moment it was sent (see SimpleChatAdapter.Item.sentAtMs). If it is '0' or missing
            // (an older sender version), it falls back to null, and the bubble shows a single timestamp.
            val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
            // See `resolveReplyLabel`: for this live event, `localMessages` already holds the complete set (the replied-to message, if any, must have been added
            // earlier), so it can be resolved directly here.
            // The isNull() check matters: org.json's optString(key, "") only falls back on a MISSING key, not an explicit JSON null. Rust always sends this key,
            // so without the check every received message would get the literal string 'null' here.
            val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
            adapter.addMessage(
                SimpleChatAdapter.Item(
                    messageId = messageId,
                    text = obj.optString("text"),
                    isMine = false,
                    sentAtMs = sentAtMs,
                    replyToMessageId = replyToMessageId,
                    replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null },
                    replyToSenderLabel = resolveReplyLabel(replyToMessageId),
                    expireSecs = Disappear.fromEvent(obj).first,
                    expireAtMs = Disappear.fromEvent(obj).second
                )
            )
            maybePlayTyphoonEffect()
            onNewIncomingItemAdded()
            // 'Seen' in 1:1 is only the read boundary (ReadStateSync). The other side applies it to this message as well, via `seen_bulk`; it is written to disk
            // and retried. Sending a separate `Seen` per message would have been a second packet carrying the same information.
            scheduleReadWatermark()
        }
        // Multi-device echo: a message I sent from another of my devices. It is shown here as a 'sent' bubble too (markSeen NOT called, since it is my own
        // message). After a reopen it already comes from the archive as 'sent'.
        "sibling_message" -> {
            val messageId = obj.optString("message_id")
            val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
            val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
            adapter.addMessage(
                SimpleChatAdapter.Item(
                    messageId = messageId,
                    text = obj.optString("text"),
                    isMine = true,
                    status = SimpleChatAdapter.Status.SENT,
                    sentAtMs = sentAtMs,
                    replyToMessageId = replyToMessageId,
                    replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null },
                    replyToSenderLabel = resolveReplyLabel(replyToMessageId),
                    expireSecs = Disappear.fromEvent(obj).first,
                    expireAtMs = Disappear.fromEvent(obj).second
                )
            )
            scrollToBottomNow()
        }
        "edit" -> adapter.applyEdit(obj.optString("message_id"), obj.optString("text"))
        "delete" -> adapter.applyDelete(obj.optString("message_id"))
        // Emoji reactions: Rust sends a ready SUMMARY string (see `reactions_summary`); nothing is counted or summed here.
        "reaction" -> adapter.applyReactions(obj.optString("message_id"), obj.optString("reactions"))
        "status" -> adapter.applyStatus(obj.optString("message_id"), parseStatus(obj.optString("status")))
        "older_history" -> applyOlderHistory(obj)
        // Server or sibling restore covering several chats: reload from the archive.
        "history_backfilled" -> {
            syncMissedMessages()
            // Rows older than the loaded page: read them from the local archive now.
            if (fetchHistoryButton.onBackfilled()) {
                noMoreOlderHistory = false
                loadOlderHistory()
            }
        }
        // 'sibling_file': an attachment I sent from another of my devices. Same bubble, on my side.
        "file_offer", "sibling_file" -> {
            val autoDownloading = obj.optBoolean("auto_downloading", false)
            // isNull() check: optString("preview_hex", "") returns the
            // literal string "null" (not the fallback) for an explicit
            // JSON null, which then crashes hexToBytes below.
            val previewHex = if (obj.isNull("preview_hex")) null else obj.optString("preview_hex").ifEmpty { null }
            val previewJpeg = previewHex?.let { hexToBytes(it) }
            val durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it }
            // Attachment bubble with its caption and reply context (see the Rust `file_offer` event).
            val attachmentCaption = obj.optString("caption", "")
            val attachmentReplyId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
            val attachmentReplyPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
            adapter.addMessage(
                SimpleChatAdapter.Item(
                    messageId = obj.optString("file_id"),
                    text = "",
                    isMine = obj.optString("type") == "sibling_file",
                    expireSecs = Disappear.fromEvent(obj).first, expireAtMs = Disappear.fromEvent(obj).second,
                    attachment = SimpleChatAdapter.AttachmentInfo(
                        fileId = obj.optString("file_id"),
                        fileName = obj.optString("file_name"),
                        mimeType = obj.optString("mime_type"),
                        totalSize = obj.optLong("total_size"),
                        status = if (obj.optBoolean("complete", false)) SimpleChatAdapter.AttachmentStatus.COMPLETE
                                  else if (autoDownloading) SimpleChatAdapter.AttachmentStatus.DOWNLOADING
                                  else SimpleChatAdapter.AttachmentStatus.OFFERED,
                        previewJpeg = previewJpeg,
                        durationMs = durationMs,
                        isSticker = obj.optBoolean("sticker", false)
                    ),
                    // Attachment + caption + reply.
                    caption = attachmentCaption,
                    replyToMessageId = attachmentReplyId,
                    replyToPreview = attachmentReplyPreview,
                    replyToSenderLabel = resolveReplyLabel(attachmentReplyId)
                )
            )
            onNewIncomingItemAdded()
            // The read boundary covers only the `messages` table. Attachments keep individual `Seen` packets. It is not sent for the echo of my own attachment.
            if (obj.optString("type") == "file_offer") {
                markSeen(obj.optString("file_id"))
                // Sibling devices keep the notification until the watermark moves.
                scheduleReadWatermark()
            }
        }
        "file_progress" -> adapter.applyAttachmentUpdate(
            obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.DOWNLOADING, obj.optLong("bytes_done")
        )
        "file_complete" -> adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.COMPLETE)
        "file_failed" -> adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.FAILED)
        // Rust emits this event both when the storage limit evicts a file and when an attached message is deleted, but no client listened to it.
        // The bubble kept showing 'completed', and tapping it found no file. Now it goes back to 'offered', so it looks downloadable again.
        "file_evicted" -> adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.OFFERED)
        // 'Seen' notice: the other side saw the message on its screen. It is shown as a small avatar badge under the bubble (see SimpleChatAdapter.applySeen).
        "seen" -> {
            val messageId = obj.optString("message_id")
            val peerName = txtToolbarTitle.text.toString()
            adapter.applySeen(
                messageId,
                listOf(SimpleChatAdapter.SeenByViewer(peerAvatar(), peerName))
            )
        }
        // Bulk seen: the other side sent a 'read up to here' boundary (see Rust `apply_incoming_read_watermark`). `message_ids` are sorted oldest to newest.
        // The 1:1 adapter shows a single 'last seen' mark, so applying the NEWEST one is enough.
        "seen_bulk" -> {
            // Group events were already filtered out in `messageListener` (when `group_id` is not null).
            val arr = obj.optJSONArray("message_ids")
            if (arr != null && arr.length() > 0) {
                val newestId = arr.optString(arr.length() - 1)
                val peerName = txtToolbarTitle.text.toString()
                adapter.applySeen(
                    newestId,
                    listOf(SimpleChatAdapter.SeenByViewer(peerAvatar(), peerName))
                )
            }
        }
        "account_deleted" -> {
            peerAccountDeleted = true
            connectingBanner.visibility = View.VISIBLE
            updateComposerLock()
        }
        "typing" -> {
            val isTyping = obj.optBoolean("is_typing", false)
            typingHandler.removeCallbacks(clearPeerTypingRunnable)
            layoutTypingIndicator.visibility = if (isTyping) View.VISIBLE else View.GONE
            if (isTyping) {
                // See `TYPING_INDICATOR_TIMEOUT_MS`: if the turn-off notice is lost, the indicator must not hang forever.
                typingHandler.postDelayed(clearPeerTypingRunnable, TYPING_INDICATOR_TIMEOUT_MS)
                if (isRecyclerNearBottom()) {
                    recycler.scrollToPosition(localMessages.size - 1)
                }
            }
        }
        // The other side changed its profile (see Rust `ProfileUpdate`): the avatar and name in the top bar update live.
        "profile_update" -> {
            val avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
            toolbarAvatarBytes = avatarHex?.let { hexToBytes(it) }
            toolbarAvatarLoaded = true
            // `previous_display_name` is set only if the NAME really changed (every photo change carries this packet too, see the note on the Rust side).
            // The user notice is based on it; otherwise the same name would look 'changed' every time.
            val newName = if (obj.isNull("display_name")) null else obj.optString("display_name").ifEmpty { null }
            val oldName = if (obj.isNull("previous_display_name")) null else obj.optString("previous_display_name").ifEmpty { null }
            if (newName != null && oldName != null) {
                txtToolbarTitle.text = newName
                Toast.makeText(this, getString(R.string.msg_contact_renamed, oldName, newName), Toast.LENGTH_LONG).show()
            }
            AvatarUtil.renderInto(imgToolbarAvatar, toolbarAvatarBytes, txtToolbarTitle.text.toString())
        }
        // Permanent handshake failure (version or key mismatch): tell the user, instead of showing 'Connecting' forever.
        "handshake_failed" -> {
            Toast.makeText(this, R.string.error_handshake_incompatible, Toast.LENGTH_LONG).show()
        }
    }
}

internal fun ChatActivity.markSeen(messageId: String) {
    if (!AppLock.isUnlocked()) return
    // The `sendSeenReceipt` JNI call queues on the core lock, so it is not called from the main thread (UI stalls / ANR). Order is kept by the single-thread queue.
    // The peer of THIS message: the screen may switch chats before the queued task runs, and the receipt must not go to the next peer.
    val peer = peerDeviceFingerprint
    netPack.execute {
        try {
            P2PLib.sendSeenReceipt(peer, messageId, null)
        } catch (e: Exception) {
        }
    }
}

/** A single packet is sent when the status CHANGES, not on every keystroke (see `isTypingSent`). */
internal fun ChatActivity.sendTypingState(isTyping: Boolean) {
    if (isTypingSent == isTyping) return
    isTypingSent = isTyping
    // See `markSeen`.
    val peer = peerDeviceFingerprint
    netPack.execute {
        try {
            P2PLib.sendTypingIndicator(peer, isTyping)
        } catch (e: Exception) {
        }
    }
}
