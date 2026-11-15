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

// ChatActivity: per-message actions (edit, delete, reactions, reply, copy, retry) and the contact info dialog.

/** Contact info plus this chat's local attachments (`StorageActivity`). */
internal fun ChatActivity.showContactInfoDialog() {
    val view = layoutInflater.inflate(R.layout.dialog_contact_info, null)
    val name = txtToolbarTitle.text.toString()
    view.findViewById<TextView>(R.id.txtContactName).text = name
    AvatarUtil.renderInto(view.findViewById(R.id.imgContactAvatarLarge), peerAvatar(), name)
    val dialog = AlertDialog.Builder(this)
        .setTitle(name)
        .setView(view)
        .setNegativeButton(android.R.string.ok, null)
        .create()
    view.findViewById<View>(R.id.btnContactFilesMedia).setOnClickListener {
        dialog.dismiss()
        startActivity(Intent(this, StorageActivity::class.java)
            .putExtra(StorageActivity.EXTRA_CHAT_KIND, "contact")
            .putExtra(StorageActivity.EXTRA_CHAT_ID, peerDeviceFingerprint)
            .putExtra(StorageActivity.EXTRA_CHAT_NAME, name))
    }
    dialog.show()
}

// ---------------------------------------------------------------
// Edit / delete / copy / reply
// ---------------------------------------------------------------

internal fun ChatActivity.showEditDeleteDialog(item: SimpleChatAdapter.Item) {
    if (!item.isMine) {
        // We cannot edit or delete the other side's message (the other side would reject it anyway; see Rust `message_owned_by_sender`), but we can leave a reaction.
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
        add(getString(R.string.action_react))
        add(getString(R.string.action_edit_message))
        add(getString(R.string.action_delete_message))
        add(getString(R.string.lbl_copy))
        add(getString(R.string.action_forward))
        add(getString(R.string.action_select))
    }
    AlertDialog.Builder(this)
        .setItems(options.toTypedArray()) { _, which ->
            when (options[which]) {
                getString(R.string.action_forward) -> com.p2p.messenger.util.Forward.start(this, item)
                getString(R.string.action_select) -> selection.start(item)
                getString(R.string.action_retry_message) -> retryFailedMessage(item)
                getString(R.string.action_react) -> showReactionPicker(item)
                getString(R.string.action_edit_message) -> showEditMessageDialog(item)
                getString(R.string.action_delete_message) -> confirmDeleteMessage(item)
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
internal fun ChatActivity.showReactionsDialog(item: SimpleChatAdapter.Item) {
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
                    // Tapping my own row removes my reaction (empty emoji).
                    if (which != myRow) return@setItems
                    lifecycleScope.launch(Dispatchers.IO) {
                        val summary = try { P2PLib.reactToMessage(peerDeviceFingerprint, item.messageId, "") } catch (e: Exception) { "Error: ${e.message}" }
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

/**
 * Sends a reaction. The JNI call can reach the network, so it runs OFF the main thread. The returned value is the message's CURRENT reaction summary
 * (see Rust `react_to_message`), written straight into the pill. Delivery to the other side is guaranteed by `needs_delivery_confirmation`,
 * so there is no need to wait here.
 */
internal fun ChatActivity.showReactionPicker(item: SimpleChatAdapter.Item) {
    ReactionPicker.show(this, item.reactions.isNotBlank()) { emoji ->
        lifecycleScope.launch(Dispatchers.IO) {
            val summary = try {
                P2PLib.reactToMessage(peerDeviceFingerprint, item.messageId, emoji)
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

internal fun ChatActivity.copyMessageText(item: SimpleChatAdapter.Item) {
    com.p2p.messenger.util.copySensitive(this, "message", com.p2p.messenger.util.Quote.plain(com.p2p.messenger.util.Forward.strip(item.text)))
    Toast.makeText(this, R.string.lbl_copied, Toast.LENGTH_SHORT).show()
}

internal fun ChatActivity.setupSwipeToReply() {
    val replyIcon: Drawable? = ContextCompat.getDrawable(this, R.drawable.ic_reply)
    val maxSwipePx = REPLY_SWIPE_MAX_DP * resources.displayMetrics.density
    val callback = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.RIGHT) {
        /**
         * The target is chosen by where the swipe STARTED, not where it ended. `onSwiped` gets `adapterPosition` at the moment the gesture ENDS.
         * If a new message arrives during the gesture (common in a live chat), every position shifts: that index now points to a DIFFERENT message,
         * and if the list was rebound meanwhile, `NO_POSITION` is returned and nothing is replied to. So the target is captured at the START as a stable
         * `messageId`, and the right message is replied to even if the index shifts.
         */
        override fun onSelectedChanged(viewHolder: RecyclerView.ViewHolder?, actionState: Int) {
            super.onSelectedChanged(viewHolder, actionState)
            if (actionState == ItemTouchHelper.ACTION_STATE_SWIPE && viewHolder != null) {
                @Suppress("DEPRECATION")
                val start = viewHolder.adapterPosition
                swipeStartMessageId = localMessages.getOrNull(start)?.messageId
            }
        }

        override fun onMove(
            rv: RecyclerView,
            viewHolder: RecyclerView.ViewHolder,
            target: RecyclerView.ViewHolder
        ): Boolean = false

        override fun getSwipeThreshold(viewHolder: RecyclerView.ViewHolder): Float = 0.4f

        override fun onChildDraw(
            c: Canvas,
            recyclerView: RecyclerView,
            viewHolder: RecyclerView.ViewHolder,
            dX: Float,
            dY: Float,
            actionState: Int,
            isCurrentlyActive: Boolean
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

        override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
            val position = viewHolder.adapterPosition
            // Settle the bubble back into place. This is not a swipe-to-delete.
            // With change animations off (see `supportsChangeAnimations`), `notifyItemChanged` rebinds the SAME view. ItemTouchHelper keeps that view as swiped
            // and keeps drawing it offset on every frame. Detaching and re-attaching the helper clears that state and resets the offset.
            recycler.post {
                swipeHelper.attachToRecyclerView(null)
                swipeHelper.attachToRecyclerView(recycler)
            }
            if (position != RecyclerView.NO_POSITION) adapter.notifyItemChanged(position)
            // See `onSelectedChanged`: the target is the message the gesture STARTED on.
            val startedOn = swipeStartMessageId
            swipeStartMessageId = null
            val item = startedOn?.let { id -> localMessages.firstOrNull { it.messageId == id } }
            if (item != null && !item.isDeleted) startReply(item)
        }
    }
    swipeHelper = ItemTouchHelper(callback)
    swipeHelper.attachToRecyclerView(recycler)
}

internal fun ChatActivity.startReply(item: SimpleChatAdapter.Item) {
    com.p2p.messenger.util.Quote.insert(findViewById(R.id.edtMessage), item.messageId, replyPreviewFor(item))
}

/** Attachment bubbles have no text, so the file name is shown. */
internal fun ChatActivity.replyPreviewFor(item: SimpleChatAdapter.Item): String {
    val attachment = item.attachment
    return if (attachment != null) {
        getString(R.string.lbl_attachment_reply_preview, attachment.fileName)
    } else {
        com.p2p.messenger.util.Quote.ownText(com.p2p.messenger.util.Forward.strip(item.text)).takeWholeChars(REPLY_PREVIEW_MAX_CHARS)
    }
}

/** Tapping the quote box scrolls to the replied message and highlights it briefly. If the target is not loaded yet (older history), it warns. */
internal fun ChatActivity.scrollToMessage(targetMessageId: String) {
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

/** Resends a FAILED message in the SAME bubble. It does not create a second bubble (see SimpleChatAdapter.retryMessage). */
internal fun ChatActivity.retryFailedMessage(item: SimpleChatAdapter.Item) {
    val peer = peerDeviceFingerprint
    lifecycleScope.launch {
        val result = withContext(Dispatchers.IO) {
            try {
                P2PLib.sendMessage(peer, item.text, item.replyToMessageId, item.replyToPreview)
            } catch (e: Throwable) {
                "Error: ${e.message}"
            }
        }
        if (result.startsWith("Error:")) {
            Toast.makeText(this@retryFailedMessage, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
            adapter.applyStatus(item.messageId, SimpleChatAdapter.Status.ERROR)
            return@launch
        }
        val (newMessageId, status) = try {
            val obj = JSONObject(result)
            obj.optString("message_id") to parseStatus(obj.optString("status"))
        } catch (e: Exception) {
            item.messageId to SimpleChatAdapter.Status.ERROR
        }
        adapter.retryMessage(item.messageId, newMessageId, status)
    }
}

internal fun ChatActivity.showEditMessageDialog(item: SimpleChatAdapter.Item) {
    val input = EditText(this)
    com.p2p.messenger.util.Quote.attach(input)
    input.setText(com.p2p.messenger.util.Forward.strip(item.text))
    input.hint = getString(R.string.lbl_edit_message_hint)
    AlertDialog.Builder(this)
        .setTitle(R.string.action_edit_message)
        .setView(input)
        .setPositiveButton(R.string.action_edit_message) { _, _ ->
            if (input.text.isBlank()) return@setPositiveButton
            // An edit keeps the "Forwarded" label.
            val newText = input.text.toString().let { if (com.p2p.messenger.util.Forward.isForwarded(item.text)) com.p2p.messenger.util.Forward.mark(it) else it }
            val peer = peerDeviceFingerprint
            lifecycleScope.launch {
                val result = withContext(Dispatchers.IO) {
                    try { P2PLib.editMessage(peer, item.messageId, newText) } catch (e: Throwable) { "Error: ${e.message}" }
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@showEditMessageDialog, R.string.error_edit_failed, Toast.LENGTH_SHORT).show()
                } else {
                    adapter.applyEdit(item.messageId, newText)
                }
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

internal fun ChatActivity.confirmDeleteMessage(item: SimpleChatAdapter.Item) {
    AlertDialog.Builder(this)
        .setMessage(R.string.confirm_delete_message)
        .setPositiveButton(R.string.action_delete_message) { _, _ ->
            val peer = peerDeviceFingerprint
            lifecycleScope.launch {
                val result = withContext(Dispatchers.IO) {
                    try { P2PLib.deleteMessage(peer, item.messageId) } catch (e: Throwable) { "Error: ${e.message}" }
                }
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@confirmDeleteMessage, R.string.error_delete_failed, Toast.LENGTH_SHORT).show()
                } else {
                    adapter.applyDelete(item.messageId)
                }
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}
