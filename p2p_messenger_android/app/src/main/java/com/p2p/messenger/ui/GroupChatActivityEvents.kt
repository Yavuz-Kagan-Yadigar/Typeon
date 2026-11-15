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

// GroupChatActivity: incoming core events, sending text, seen and typing.

internal fun GroupChatActivity.sendNewMessage(text: String): kotlinx.coroutines.Job {
    btnSend.isEnabled = false
    btnSend.visibility = View.INVISIBLE
    progressSending.visibility = View.VISIBLE
    val targetGroupId = groupId
    return lifecycleScope.launch {
        val result = withContext(Dispatchers.IO) {
            try {
                P2PLib.sendGroupMessage(targetGroupId, text, null, null, null, mentionIdsJson(text))
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
        }
        progressSending.visibility = View.GONE
        btnSend.visibility = View.VISIBLE
        btnSend.isEnabled = true
        // onNewIntent can reuse this Activity for a different group
        // (singleTop) while this send is in flight — restore the send
        // button above regardless, but don't drop the result bubble into
        // the wrong group's message list.
        if (groupId != targetGroupId) return@launch
        val ok = !result.startsWith("Error:")
        if (!ok) {
            Toast.makeText(this@sendNewMessage, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
        }
        // Use the `group_message_local_id` returned by Rust as the `messageId` of our own bubble (not a random UUID),
        // so the returned 'seen' notices match the right bubble.
        val localId = if (ok) result else UUID.randomUUID().toString()
        adapter.addMessage(
            SimpleChatAdapter.Item(
                messageId = localId,
                text = text,
                isMine = true,
                status = if (ok) SimpleChatAdapter.Status.SENT else SimpleChatAdapter.Status.ERROR,
                senderIdentityId = ownIdentityId
            )
        )
        maybePlayTyphoonEffect()
        scrollToBottomNow()
    }
}

/**
 * Multi-device echo: a group message I sent from another of my devices is added as an isMine bubble (not marked as seen, since it is my own message).
 * After a reopen it already comes from the archive as 'sent'.
 */
internal fun GroupChatActivity.handleSiblingGroupMessage(obj: JSONObject) {
    val localId = obj.optString("message_id")
    val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
    val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
    val replyToSenderIdentityId = if (obj.isNull("reply_to_sender_identity_id")) null else obj.optString("reply_to_sender_identity_id").ifEmpty { null }
    adapter.addMessage(
        SimpleChatAdapter.Item(
            messageId = localId,
            text = obj.optString("text"),
            isMine = true,
            status = SimpleChatAdapter.Status.SENT,
            sentAtMs = sentAtMs,
            senderIdentityId = ownIdentityId,
            replyToMessageId = replyToMessageId,
            replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null },
            replyToSenderIdentityId = replyToSenderIdentityId,
            replyToSenderLabel = resolveReplyLabel(replyToMessageId, replyToSenderIdentityId)
        )
    )
    scrollToBottomNow()
}

internal fun GroupChatActivity.handleIncomingGroupMessage(obj: JSONObject) {
    val senderIdentityId = obj.optString("sender_identity_id")
    val sender = resolveContactByIdentity(senderIdentityId)
    val senderName = sender?.displayName ?: senderIdentityId.take(8)
    val messageId = obj.optString("message_id")
    // This bubble's `Item.messageId` is the `group_message_local_id`, NOT the per-packet `message_id`.
    // That keeps it consistent with messages I sent to the group (see the `sendNewMessage` note on my own bubble's messageId) and with rows loaded
    // from history (the DB's `message_id` column stores `group_message_local_id`; see the Rust `archive_group_message` call site).
    // The per-packet id was used here before. Edit and delete only fire on my own messages (see the `isMine` guard in `showGroupEditDeleteDialog`),
    // so the mismatch went unnoticed. Reply (`startReply`) also works on OTHERS' messages, though, and the wrong id would match no message on the other side.
    val localId = if (obj.isNull("group_message_local_id")) null else obj.optString("group_message_local_id").ifEmpty { null }
    val bubbleId = localId ?: messageId
    // Sender-embedded real send time, same pattern as ChatActivity.
    val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
    // isNull() check matters: org.json's optString(key, "") only falls
    // back on a MISSING key, not an explicit JSON null — Rust always
    // sends these keys, so without the check every received group
    // message got the literal string "null" here.
    val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
    val replyToSenderIdentityId = if (obj.isNull("reply_to_sender_identity_id")) null else obj.optString("reply_to_sender_identity_id").ifEmpty { null }
    adapter.addMessage(
        SimpleChatAdapter.Item(
            messageId = bubbleId,
            text = obj.optString("text"),
            isMine = false,
            sentAtMs = sentAtMs,
            senderName = senderName,
            senderAvatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
            senderIdentityId = senderIdentityId,
            replyToMessageId = replyToMessageId,
            replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null },
            replyToSenderIdentityId = replyToSenderIdentityId,
            replyToSenderLabel = resolveReplyLabel(replyToMessageId, replyToSenderIdentityId),
            mentionsMe = obj.optBoolean("mentions_me")
        )
    )
    maybePlayTyphoonEffect()
    onNewIncomingItemAdded()
    // Seen: sent automatically for a live group message that arrives while the screen is open (same reasoning as the 1:1 ChatActivity).
    // `peer` is the fingerprint of the 1:1 channel (the sender) this copy arrived on.
    if (AppLock.isUnlocked()) netPack.execute {
        try { P2PLib.sendSeenReceipt(obj.optString("peer"), messageId, localId) } catch (e: Exception) { /* yoksay */ }
    }
    // Reliable path: the read boundary is written to disk even if an individual Seen is lost.
    scheduleGroupReadWatermark()
}

/** Same as the `seenByPerMessage` note at the top of the file: accumulates the members who saw each message, keyed by identity_id,
 *  and passes the complete current list to the adapter every time. */
internal fun GroupChatActivity.handleIncomingSeen(obj: JSONObject) {
    // group_message_local_id is an Option<String> on the Rust side, so an
    // explicit JSON null must be guarded (optString alone would return
    // the literal string "null" and silently mismatch every bubble).
    val localId = if (obj.isNull("group_message_local_id")) null else obj.optString("group_message_local_id").ifEmpty { null }
    if (localId == null) return
    // Asked of the list itself: a separate set of "ids I sent" held only
    // this session's text sends, so a "seen" for a message loaded from
    // history or for an attachment was dropped.
    if (localMessages.none { it.isMine && it.messageId == localId }) return
    val senderIdentityId = obj.optString("sender_identity_id")
    val sender = resolveContactByIdentity(senderIdentityId)
    val viewer = SimpleChatAdapter.SeenByViewer(
        avatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
        displayName = sender?.displayName ?: senderIdentityId.take(8)
    )
    val viewers = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
    viewers[senderIdentityId] = viewer
    adapter.applySeen(localId, viewers.values.toList())
}

/**
 * Bulk seen: a member sent a "read up to here" boundary. Rust returns the `message_id`s of MY messages up to that boundary.
 * For each one, add that member to `seenByPerMessage` and pass the full list to the adapter, as `handleIncomingSeen` does.
 */
internal fun GroupChatActivity.handleIncomingSeenBulk(obj: JSONObject) {
    val arr = obj.optJSONArray("message_ids") ?: return
    val senderIdentityId = obj.optString("viewer_identity_id")
    if (senderIdentityId.isEmpty()) return
    val sender = resolveContactByIdentity(senderIdentityId)
    val viewer = SimpleChatAdapter.SeenByViewer(
        avatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
        displayName = sender?.displayName ?: senderIdentityId.take(8)
    )
    for (i in 0 until arr.length()) {
        val localId = arr.optString(i)
        if (localId.isEmpty()) continue
        val viewers = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
        viewers[senderIdentityId] = viewer
        adapter.applySeen(localId, viewers.values.toList())
    }
}

/** Called on state transitions only, by the EditText watcher and `stopTypingRunnable`. */
internal fun GroupChatActivity.sendTypingState(isTyping: Boolean) {
    if (isTypingSent == isTyping) return
    isTypingSent = isTyping
    // Same as `netPack` (see the top of the file).
    val gid = groupId
    netPack.execute {
        try {
            P2PLib.sendGroupTypingIndicator(gid, isTyping)
        } catch (e: Exception) {
            // Fire-and-forget.
        }
    }
}

/** Handles a `{"type":"typing","group_id":...,"sender_identity_id":...,"is_typing":...}` event. */
internal fun GroupChatActivity.handleIncomingGroupTyping(obj: JSONObject) {
    val senderIdentityId = obj.optString("sender_identity_id")
    if (senderIdentityId.isEmpty() || senderIdentityId == ownIdentityId) return
    val isTyping = obj.optBoolean("is_typing", false)
    typingMembers.remove(senderIdentityId)?.let { typingHandler.removeCallbacks(it) }
    if (isTyping) {
        val clearRunnable = Runnable {
            typingMembers.remove(senderIdentityId)
            updateTypingIndicatorUi()
        }
        typingMembers[senderIdentityId] = clearRunnable
        typingHandler.postDelayed(clearRunnable, TYPING_INDICATOR_TIMEOUT_MS)
    }
    updateTypingIndicatorUi()
    if (isTyping && isRecyclerNearBottom()) recycler.scrollToPosition(localMessages.size - 1)
}

/** Shows the most recent typer's avatar; falls back to generic text if several are typing. */
internal fun GroupChatActivity.updateTypingIndicatorUi() {
    if (typingMembers.isEmpty()) {
        layoutTypingIndicator.visibility = View.GONE
        return
    }
    val lastIdentityId = typingMembers.keys.last()
    val contact = resolveContactByIdentity(lastIdentityId)
    val displayName = contact?.displayName?.takeIf { it.isNotBlank() } ?: lastIdentityId.take(8)
    val avatarBytes = contact?.avatarHex?.let { hexToBytes(it) }
    AvatarUtil.renderInto(imgTypingAvatar, avatarBytes, displayName)
    imgTypingAvatar.visibility = View.VISIBLE
    txtTypingIndicator.text = if (typingMembers.size == 1) {
        getString(R.string.lbl_typing_named, displayName)
    } else {
        getString(R.string.lbl_typing_several)
    }
    layoutTypingIndicator.visibility = View.VISIBLE
}
