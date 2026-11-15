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

// GroupChatActivity: per-message actions (edit, delete, reactions, reply, copy, retry).

/** "Resend" on a group message: its member copies are queued under per-member ids, so every pending retry is pulled to now
 *  (same as opening the app). Copies already acknowledged are not sent again. */
internal fun GroupChatActivity.resendGroupNow() {
    lifecycleScope.launch(Dispatchers.IO) { try { P2PLib.retryAllPendingNow() } catch (e: Throwable) {} }
    Toast.makeText(this, R.string.msg_retrying_message, Toast.LENGTH_SHORT).show()
}

/**
 * Resends a failed (ERROR) group message. It keeps the SAME bubble (see `SimpleChatAdapter.retryMessage`) and adds no second copy.
 * It fans out again with a new `group_message_local_id` (same mechanism as `sendNewMessage`).
 */
internal fun GroupChatActivity.retryFailedGroupMessage(item: SimpleChatAdapter.Item) {
    // Some members got it: send only the copies that failed, under the
    // same id (see Rust `retry_group_message_copies`). 0 = the message
    // never left this device, so it is sent as a new one below.
    val gid = groupId
    lifecycleScope.launch {
        val partial = withContext(Dispatchers.IO) { try { P2PLib.retryGroupMessageCopies(gid, item.messageId) } catch (e: Exception) { 0 } }
        when (partial) {
            1 -> { adapter.applyStatus(item.messageId, SimpleChatAdapter.Status.SENT); return@launch }
            -1 -> { Toast.makeText(this@retryFailedGroupMessage, R.string.error_send_failed, Toast.LENGTH_SHORT).show(); return@launch }
        }
        // Same as ChatActivity.retryFailedMessage: if it is a reply, the same reply context is kept.
        val result = withContext(Dispatchers.IO) {
            try {
                P2PLib.sendGroupMessage(gid, item.text, item.replyToMessageId, item.replyToPreview, item.replyToSenderIdentityId, mentionIdsJson(item.text))
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
        }
        if (result.startsWith("Error:")) {
            Toast.makeText(this@retryFailedGroupMessage, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
            adapter.applyStatus(item.messageId, SimpleChatAdapter.Status.ERROR)
            return@launch
        }
        adapter.retryMessage(item.messageId, result, SimpleChatAdapter.Status.SENT)
    }
}

/**
 * Same pattern as ChatActivity.showEditDeleteDialog. Edit and delete also apply to group messages.
 * Attachment bubbles are not supported (see the SimpleChatAdapter long-press guard, `item.attachment == null`), so this fires only for plain text messages.
 * Messages from others also react to a long press, but for them only Copy is shown. Edit, Delete and Resend make sense only for our own messages.
 */
internal fun GroupChatActivity.showGroupEditDeleteDialog(item: SimpleChatAdapter.Item) {
    if (!item.isMine) {
        // Same pattern as ChatActivity: we cannot edit someone else's message, but we can leave a reaction.
        val theirOptions = listOfNotNull(
            getString(R.string.action_react),
            getString(R.string.lbl_copy),
            getString(R.string.action_forward).takeIf { com.p2p.messenger.util.Forward.canForward(item) },
            getString(R.string.action_select),
        )
        AlertDialog.Builder(this)
            .setItems(theirOptions.toTypedArray()) { _, which ->
                when (theirOptions[which]) {
                    getString(R.string.action_react) -> showReactionPicker(item)
                    getString(R.string.lbl_copy) -> copyMessageText(item)
                    getString(R.string.action_forward) -> com.p2p.messenger.util.Forward.start(this, item)
                    getString(R.string.action_select) -> selection.start(item)
                }
            }
            .show()
        return
    }
    val showRetry = item.status == SimpleChatAdapter.Status.ERROR
    val options = mutableListOf<String>().apply {
        if (showRetry) add(getString(R.string.action_retry_message))
        else if (!item.isDeleted) add(getString(R.string.action_resend_message))
        add(getString(R.string.action_react))
        add(getString(R.string.action_edit_message))
        add(getString(R.string.action_delete_message))
        add(getString(R.string.lbl_copy))
        if (com.p2p.messenger.util.Forward.canForward(item)) add(getString(R.string.action_forward))
        add(getString(R.string.action_select))
    }
    AlertDialog.Builder(this)
        .setItems(options.toTypedArray()) { _, which ->
            when (options[which]) {
                getString(R.string.action_resend_message) -> resendGroupNow()
                getString(R.string.action_forward) -> com.p2p.messenger.util.Forward.start(this, item)
                getString(R.string.action_select) -> selection.start(item)
                getString(R.string.action_retry_message) -> retryFailedGroupMessage(item)
                getString(R.string.action_react) -> showReactionPicker(item)
                getString(R.string.action_edit_message) -> showEditGroupMessageDialog(item)
                getString(R.string.action_delete_message) -> confirmDeleteGroupMessage(item)
                getString(R.string.lbl_copy) -> copyMessageText(item)
            }
        }
        .show()
}

/**
 * Tapping the reaction pill opens a list of who reacted with what (WhatsApp style).
 *
 * The identities come from the network as `identity_id`. Names are resolved here, from this device's OWN contact list: the protocol carries no names,
 * since a sender could claim any name. An unknown identity is shown with its shortened id, and our own id shows as "You".
 */
internal fun GroupChatActivity.showReactionsDialog(item: SimpleChatAdapter.Item) {
    lifecycleScope.launch(Dispatchers.IO) {
        val raw = try { P2PLib.listReactions(item.messageId) } catch (e: Exception) { "[]" }
        val names = HashMap<String, String>()
        try {
            val contacts = JSONArray(P2PLib.listContacts())
            for (i in 0 until contacts.length()) {
                val c = contacts.getJSONObject(i)
                names[c.optString("identity_id")] = c.optString("display_name")
            }
        } catch (e: Exception) {
            // If the contact list cannot be read, names fall back to the shortened id.
        }
        val rows = mutableListOf<String>()
        var myRow = -1
        try {
            val array = JSONArray(raw)
            for (i in 0 until array.length()) {
                val entry = array.getJSONObject(i)
                val identityId = entry.optString("identity_id")
                val who = when {
                    // See Rust `list_reactions`: the 'is it me' decision is made in the core, which owns the identity.
                    entry.optBoolean("is_me", false) -> getString(R.string.lbl_you)
                    names[identityId]?.isNotBlank() == true -> names[identityId]!!
                    else -> identityId.take(8)
                }
                if (entry.optBoolean("is_me", false)) myRow = rows.size
                rows.add("${entry.optString("emoji")}   $who")
            }
        } catch (e: Exception) {
            // Malformed JSON: show an empty list instead of crashing.
        }
        withContext(Dispatchers.Main) {
            if (rows.isEmpty()) return@withContext
            AlertDialog.Builder(this@showReactionsDialog)
                .setTitle(R.string.title_reactions)
                .setItems(rows.toTypedArray()) { _, which ->
                    // Removing my own reaction clears it (empty emoji).
                    if (which != myRow) return@setItems
                    lifecycleScope.launch(Dispatchers.IO) {
                        val summary = try { P2PLib.reactToGroupMessage(groupId, item.messageId, "") } catch (e: Exception) { "Error: ${e.message}" }
                        withContext(Dispatchers.Main) {
                            if (summary.startsWith("Error:")) {
                                Toast.makeText(this@showReactionsDialog, summary, Toast.LENGTH_SHORT).show()
                            } else {
                                adapter.applyReactions(item.messageId, summary)
                            }
                        }
                    }
                }
                .setNegativeButton(android.R.string.ok, null)
                .show()
        }
    }
}

/** Same pattern as ChatActivity.showReactionPicker, for groups. */
internal fun GroupChatActivity.showReactionPicker(item: SimpleChatAdapter.Item) {
    ReactionPicker.show(this, item.reactions.isNotBlank()) { emoji ->
        lifecycleScope.launch(Dispatchers.IO) {
            val summary = try {
                P2PLib.reactToGroupMessage(groupId, item.messageId, emoji)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (summary.startsWith("Error:")) {
                    Toast.makeText(this@showReactionPicker, summary, Toast.LENGTH_SHORT).show()
                } else {
                    adapter.applyReactions(item.messageId, summary)
                }
            }
        }
    }
}

/** Same pattern as ChatActivity.copyMessageText. */
internal fun GroupChatActivity.copyMessageText(item: SimpleChatAdapter.Item) {
    com.p2p.messenger.util.copySensitive(this, "message", com.p2p.messenger.util.Quote.plain(com.p2p.messenger.util.Forward.strip(item.text)))
    Toast.makeText(this, R.string.lbl_copied, Toast.LENGTH_SHORT).show()
}

internal fun GroupChatActivity.setupSwipeToReply() {
    val replyIcon = ContextCompat.getDrawable(this, R.drawable.ic_reply)
    val maxSwipePx = REPLY_SWIPE_MAX_DP * resources.displayMetrics.density
    val callback = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.RIGHT) {
        override fun onMove(rv: RecyclerView, viewHolder: RecyclerView.ViewHolder, target: RecyclerView.ViewHolder) = false

        override fun getSwipeThreshold(viewHolder: RecyclerView.ViewHolder): Float = 0.4f

        override fun onChildDraw(
            c: Canvas, recyclerView: RecyclerView, viewHolder: RecyclerView.ViewHolder,
            dX: Float, dY: Float, actionState: Int, isCurrentlyActive: Boolean
        ) {
            val clampedDx = dX.coerceIn(0f, maxSwipePx)
            if (actionState == ItemTouchHelper.ACTION_STATE_SWIPE) {
                val itemView = viewHolder.itemView
                val progress = (clampedDx / maxSwipePx).coerceIn(0f, 1f)
                if (replyIcon != null && progress > 0f) {
                    val iconSize = (24 * resources.displayMetrics.density).toInt()
                    val top = itemView.top + (itemView.height - iconSize) / 2
                    val left = itemView.left + (12 * resources.displayMetrics.density).toInt()
                    replyIcon.setBounds(left, top, left + iconSize, top + iconSize)
                    replyIcon.alpha = (progress * 255).toInt()
                    replyIcon.draw(c)
                }
            }
            super.onChildDraw(c, recyclerView, viewHolder, clampedDx, dY, actionState, isCurrentlyActive)
        }

        /** Same fix as ChatActivity.setupSwipeToReply: the target is the message the gesture STARTED on, not the one it ended on. */
        override fun onSelectedChanged(viewHolder: RecyclerView.ViewHolder?, actionState: Int) {
            super.onSelectedChanged(viewHolder, actionState)
            if (actionState == ItemTouchHelper.ACTION_STATE_SWIPE && viewHolder != null) {
                @Suppress("DEPRECATION")
                val start = viewHolder.adapterPosition
                swipeStartMessageId = localMessages.getOrNull(start)?.messageId
            }
        }

        override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
            @Suppress("DEPRECATION")
            val position = viewHolder.adapterPosition
            // With change animations off (see `supportsChangeAnimations`), `notifyItemChanged` rebinds the SAME view.
            // ItemTouchHelper keeps that view as swiped and keeps drawing it offset on every frame.
            // Detaching and re-attaching the helper clears that state and resets the offset.
            recycler.post {
                swipeHelper.attachToRecyclerView(null)
                swipeHelper.attachToRecyclerView(recycler)
            }
            if (position != RecyclerView.NO_POSITION) adapter.notifyItemChanged(position)
            val startedOn = swipeStartMessageId
            swipeStartMessageId = null
            val item = startedOn?.let { id -> localMessages.firstOrNull { it.messageId == id } } ?: return
            // Same pattern as ChatActivity: replies are supported for attachments too.
            if (item.isDeleted) return
            startReply(item)
        }
    }
    swipeHelper = ItemTouchHelper(callback)
    swipeHelper.attachToRecyclerView(recycler)
}

/** Same pattern as ChatActivity.startReply: in a group, when `item.isMine` is false, the label is the already-resolved `senderName` of that message. */
internal fun GroupChatActivity.startReply(item: SimpleChatAdapter.Item) {
    com.p2p.messenger.util.Quote.insert(findViewById(R.id.edtMessage), item.messageId, replyPreviewFor(item))
}

/** Same pattern as `ChatActivity.replyPreviewFor`. */
internal fun GroupChatActivity.replyPreviewFor(item: SimpleChatAdapter.Item): String {
    val attachment = item.attachment
    return if (attachment != null) {
        getString(R.string.lbl_attachment_reply_preview, attachment.fileName)
    } else {
        com.p2p.messenger.util.Quote.ownText(com.p2p.messenger.util.Forward.strip(item.text)).takeWholeChars(REPLY_PREVIEW_MAX_CHARS)
    }
}

/** Same pattern as ChatActivity.scrollToMessage. */
internal fun GroupChatActivity.scrollToMessage(targetMessageId: String) {
    val position = localMessages.indexOfFirst { it.messageId == targetMessageId }
    if (position < 0) {
        Toast.makeText(this, R.string.msg_reply_target_not_loaded, Toast.LENGTH_SHORT).show()
        return
    }
    recycler.scrollToPosition(position)
    adapter.setHighlighted(targetMessageId)
    replyHighlightHandler.removeCallbacksAndMessages(null)
    replyHighlightHandler.postDelayed({ adapter.setHighlighted(null) }, REPLY_HIGHLIGHT_DURATION_MS)
}

/**
 * Same pattern as ChatActivity.showEditMessageDialog. `editGroupMessage` returns "OK" or "Error: ..." (not JSON; see the P2PLib.kt note).
 */
internal fun GroupChatActivity.showEditGroupMessageDialog(item: SimpleChatAdapter.Item) {
    val input = EditText(this)
    com.p2p.messenger.util.Quote.attach(input)
    input.setText(com.p2p.messenger.util.Forward.strip(item.text))
    input.hint = getString(R.string.lbl_edit_message_hint)
    AlertDialog.Builder(this)
        .setTitle(R.string.action_edit_message)
        .setView(input)
        .setPositiveButton(R.string.action_edit_message) { _, _ ->
            if (input.text.isBlank()) return@setPositiveButton
            // Same pattern as ChatActivity.showEditMessageDialog. The label stays.
            val newText = input.text.toString().let { if (com.p2p.messenger.util.Forward.isForwarded(item.text)) com.p2p.messenger.util.Forward.mark(it) else it }
            val gid = groupId
            lifecycleScope.launch {
                val result = withContext(Dispatchers.IO) {
                    try { P2PLib.editGroupMessage(gid, item.messageId, newText) } catch (e: Throwable) { "Error: ${e.message}" }
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@showEditGroupMessageDialog, R.string.error_edit_failed, Toast.LENGTH_SHORT).show()
                } else {
                    adapter.applyEdit(item.messageId, newText)
                }
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

internal fun GroupChatActivity.confirmDeleteGroupMessage(item: SimpleChatAdapter.Item) {
    AlertDialog.Builder(this)
        .setMessage(R.string.confirm_delete_message)
        .setPositiveButton(R.string.action_delete_message) { _, _ ->
            val gid = groupId
            lifecycleScope.launch {
                val result = withContext(Dispatchers.IO) {
                    try { P2PLib.deleteGroupMessage(gid, item.messageId) } catch (e: Throwable) { "Error: ${e.message}" }
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@confirmDeleteGroupMessage, R.string.error_delete_failed, Toast.LENGTH_SHORT).show()
                } else {
                    adapter.applyDelete(item.messageId)
                }
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}
