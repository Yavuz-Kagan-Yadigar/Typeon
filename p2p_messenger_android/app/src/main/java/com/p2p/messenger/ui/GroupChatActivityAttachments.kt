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

// GroupChatActivity: picking, sending, opening and saving attachments; shared content; incoming file offers.

/** Content selected from the share screen (see util.ShareIntake). */
internal fun GroupChatActivity.consumeShare(intent: Intent) {
    com.p2p.messenger.util.ShareIntake.takeForward(intent)?.let { f ->
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.confirm_forward, txtToolbarTitle.text))
            .setPositiveButton(R.string.btn_send) { _, _ ->
                lifecycleScope.launch {
                    var done = 0
                    try {
                        for (p in f) {
                            if (p.file != null) onGroupFilePicked(Uri.fromFile(p.file), p.caption, hiRes = true, name = p.fileName, mime = p.mimeType).join()
                            else p.text?.let { sendNewMessage(it).join() }
                            done++
                        }
                    } finally {
                        // Leaving the chat cancels the rest: say so.
                        val left = f.size - done
                        if (left > 0) Toast.makeText(applicationContext, applicationContext.resources.getQuantityString(R.plurals.forward_not_sent, left, left), Toast.LENGTH_LONG).show()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
        return
    }
    val share = com.p2p.messenger.util.ShareIntake.take(intent) ?: return
    com.p2p.messenger.util.ShareIntake.text(share)?.let {
        findViewById<EditText>(R.id.edtMessage).apply { setText(it); setSelection(text.length) }
    }
    val uris = com.p2p.messenger.util.ShareIntake.uris(share)
    if (uris.isEmpty()) return
    // The chat was picked with one tap in a list that reorders itself.
    AlertDialog.Builder(this)
        .setMessage(getString(R.string.confirm_send_shared, uris.size, txtToolbarTitle.text))
        .setPositiveButton(R.string.btn_send) { _, _ -> sendPickedFiles(uris.map { it to false }) }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

/**
 * Same pattern as ChatActivity.onPhotoCaptured, for groups. The captured frame is written to a temporary cache file, sent, and deleted at once.
 * Nothing is written to the gallery or shared storage.
 */
internal fun GroupChatActivity.onGroupPhotoCaptured(jpeg: ByteArray, caption: String = "", hiRes: Boolean = false, quote: com.p2p.messenger.util.Quote.Ref? = null) {
    val fileName = "IMG_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date()) + ".jpg"
    // The group is captured BEFORE the coroutine: `groupId` was read
    // INSIDE the IO block, and the user can switch to another group
    // (singleTop) while the picture is being prepared — the file would
    // then be sent to the WRONG group (or to none).
    val targetGroupId = groupId
    lifecycleScope.launch(Dispatchers.IO) {
        val tempFile = File(File(cacheDir, "outgoing").apply { mkdirs() }, UUID.randomUUID().toString())
        var sent = tempFile
        try {
            tempFile.writeBytes(jpeg)
            val previewJpeg = try {
                generateImagePreview(tempFile)
            } catch (e: Exception) {
                null
            }
            val prepared = OutgoingMedia.prepare(tempFile, fileName, "image/jpeg", hiRes) { OutgoingMedia.askSendUnscrubbed(this@onGroupPhotoCaptured) }
            sent = prepared.file
            val result = P2PLib.prepareAndSendGroupFile(
                targetGroupId, prepared.file.absolutePath, prepared.fileName, prepared.mimeType, previewJpeg, -1,
                caption, quote?.id ?: "", quote?.preview ?: "", quote?.sender ?: ""
            )
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@onGroupPhotoCaptured, com.p2p.messenger.util.coreErrorText(this@onGroupPhotoCaptured, result), Toast.LENGTH_SHORT).show()
                } else {
                    adapter.addMessage(
                        SimpleChatAdapter.Item(
                            messageId = result,
                            text = "",
                            isMine = true,
                            expireSecs = disappearSecs, expireAtMs = Disappear.atFor(disappearSecs),
                            attachment = SimpleChatAdapter.AttachmentInfo(
                                fileId = result,
                                fileName = prepared.fileName,
                                mimeType = prepared.mimeType,
                                totalSize = prepared.file.length(),
                                status = SimpleChatAdapter.AttachmentStatus.COMPLETE,
                                bytesDone = prepared.file.length(),
                                previewJpeg = previewJpeg
                            
                            ),
                            // The caption typed during sending shows at once.
                            caption = caption,
                            replyToMessageId = quote?.id,
                            replyToPreview = quote?.preview,
                            replyToSenderLabel = resolveReplyLabel(quote?.id),
                            replyToSenderIdentityId = quote?.sender
                        )
                    )
                    scrollToBottomNow()
                }
            }
        } catch (e: Exception) {
            if (e is java.util.concurrent.CancellationException) return@launch
            withContext(Dispatchers.Main) {
                Toast.makeText(this@onGroupPhotoCaptured, getString(R.string.error_send_failed), Toast.LENGTH_SHORT).show()
            }
        } finally {
            tempFile.delete()
            sent.delete()
        }
    }
}

/** One send at a time so the files arrive in the order they were
 *  picked; the caption goes with the last one, under the batch. */
internal fun GroupChatActivity.sendPickedFiles(files: List<Pair<Uri, Boolean>>, caption: String = "", quote: com.p2p.messenger.util.Quote.Ref? = null) =
    lifecycleScope.launch { files.forEachIndexed { i, (u, hiRes) -> val last = i == files.lastIndex; onGroupFilePicked(u, if (last) caption else "", hiRes, quote = if (last) quote else null).join() } }

/**
 * Same pattern as ChatActivity.onFilePicked: the file picked with SAF is first copied to the cache,
 * then offered to ALL members with `prepareAndSendGroupFile`.
 */
internal fun GroupChatActivity.onGroupFilePicked(uri: Uri, caption: String = "", hiRes: Boolean = false, name: String? = null, mime: String? = null, quote: com.p2p.messenger.util.Quote.Ref? = null): kotlinx.coroutines.Job {
    // The group is captured BEFORE the coroutine starts (same note as `onGroupPhotoCaptured`).
    val targetGroupId = groupId
    return lifecycleScope.launch(Dispatchers.IO) {
        // Provider queries are IPC to another app: not on the main thread.
        val fileName = name ?: queryDisplayName(uri) ?: "file"
        val mimeType = mime ?: contentResolver.getType(uri) ?: "application/octet-stream"
        val size = querySize(uri)
        val tooLarge = size != null && size > MAX_ATTACHMENT_SIZE
        withContext(Dispatchers.Main) {
            if (tooLarge) {
                Toast.makeText(this@onGroupFilePicked, getString(R.string.error_file_too_large_named, fileName), Toast.LENGTH_LONG).show()
            } else {
                Toast.makeText(this@onGroupFilePicked, fileName, Toast.LENGTH_SHORT).show()
            }
        }
        if (tooLarge) return@launch
        val tempFile = File(File(cacheDir, "outgoing").apply { mkdirs() }, UUID.randomUUID().toString())
        var sent = tempFile
        try {
            contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    // SIZE column can lie: hard cap on bytes actually copied.
                    val buf = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_ATTACHMENT_SIZE) throw IllegalStateException("too_large")
                        output.write(buf, 0, n)
                    }
                }
            } ?: throw java.io.IOException(getString(R.string.error_attachment_open_failed))

            val previewJpeg = try {
                when {
                    mimeType.startsWith("image/") -> generateImagePreview(tempFile)
                    mimeType.startsWith("video/") -> generateVideoPreview(tempFile)
                    else -> null
                }
            } catch (e: Exception) {
                null
            }

            val prepared = OutgoingMedia.prepare(tempFile, fileName, mimeType, hiRes) { OutgoingMedia.askSendUnscrubbed(this@onGroupFilePicked) }
            sent = prepared.file
            val result = P2PLib.prepareAndSendGroupFile(
                targetGroupId, prepared.file.absolutePath, prepared.fileName, prepared.mimeType, previewJpeg, -1,
                caption, quote?.id ?: "", quote?.preview ?: "", quote?.sender ?: ""
            )
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@onGroupFilePicked, com.p2p.messenger.util.coreErrorText(this@onGroupFilePicked, result), Toast.LENGTH_SHORT).show()
                } else {
                    adapter.addMessage(
                        SimpleChatAdapter.Item(
                            messageId = result,
                            text = "",
                            isMine = true,
                            expireSecs = disappearSecs, expireAtMs = Disappear.atFor(disappearSecs),
                            attachment = SimpleChatAdapter.AttachmentInfo(
                                fileId = result,
                                fileName = prepared.fileName,
                                mimeType = prepared.mimeType,
                                totalSize = prepared.file.length(),
                                status = SimpleChatAdapter.AttachmentStatus.COMPLETE,
                                bytesDone = prepared.file.length(),
                                previewJpeg = previewJpeg
                            
                            ),
                            // The caption typed during sending shows at once.
                            caption = caption,
                            replyToMessageId = quote?.id,
                            replyToPreview = quote?.preview,
                            replyToSenderLabel = resolveReplyLabel(quote?.id),
                            replyToSenderIdentityId = quote?.sender
                        )
                    )
                    scrollToBottomNow()
                }
            }
        } catch (e: Exception) {
            if (e is java.util.concurrent.CancellationException) return@launch
            withContext(Dispatchers.Main) {
                if (e.message == "too_large") Toast.makeText(this@onGroupFilePicked, getString(R.string.error_file_too_large_named, fileName), Toast.LENGTH_LONG).show() else Toast.makeText(this@onGroupFilePicked, getString(R.string.error_send_failed), Toast.LENGTH_SHORT).show()
            }
        } finally {
            tempFile.delete()
            sent.delete()
        }
    }
}

/**
 * Same pattern as ChatActivity.onAttachmentClicked. One difference: the download target (`peerDeviceFingerprint`) is not a fixed field
 * but is carried on `AttachmentInfo`, because different attachments in a group can come from different senders.
 */
internal fun GroupChatActivity.onGroupAttachmentClicked(item: SimpleChatAdapter.Item) {
    val attachment = item.attachment ?: return
    when (attachment.status) {
        SimpleChatAdapter.AttachmentStatus.OFFERED, SimpleChatAdapter.AttachmentStatus.FAILED -> {
            adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.DOWNLOADING, 0)
            lifecycleScope.launch(Dispatchers.IO) {
                val result = try {
                    P2PLib.downloadFile(attachment.fileId, attachment.peerDeviceFingerprint)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                if (result.startsWith("Error:")) {
                    withContext(Dispatchers.Main) {
                        adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.FAILED)
                        Toast.makeText(this@onGroupAttachmentClicked, com.p2p.messenger.util.coreErrorText(this@onGroupAttachmentClicked, result), Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
        SimpleChatAdapter.AttachmentStatus.COMPLETE -> {
            lifecycleScope.launch(Dispatchers.IO) {
                val path = try {
                    P2PLib.getAttachmentPlaintextPath(attachment.fileId)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                withContext(Dispatchers.Main) {
                    if (path.startsWith("Error:")) {
                        Toast.makeText(this@onGroupAttachmentClicked, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                    } else {
                        openGroupAttachmentFile(path, Disappear.locked(item))
                    }
                }
            }
        }
        SimpleChatAdapter.AttachmentStatus.DOWNLOADING -> { /* no-op, zaten devam ediyor */ }
    }
}

/** Same as ChatActivity.openAttachmentFile; it does not depend on the peer. */
/** `protected`: a disappearing file. Shown only in the in-app viewer, with screenshots blocked; never handed to another app. */
internal fun GroupChatActivity.openGroupAttachmentFile(path: String, protected: Boolean = false) {
    // The file's own extension picks the viewer and the handler, not the
    // type the sender declared.
    val mimeType = android.webkit.MimeTypeMap.getSingleton()
        .getMimeTypeFromExtension(File(path).extension.lowercase()) ?: "*/*"
    try {
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", File(path))
        if (mimeType.startsWith("image/") || mimeType.startsWith("video/")) {
            val intent = Intent(this, MediaViewerActivity::class.java).apply {
                putExtra(MediaViewerActivity.EXTRA_URI, uri)
                putExtra(MediaViewerActivity.EXTRA_MIME_TYPE, mimeType)
                putExtra(MediaViewerActivity.EXTRA_PROTECTED, protected)
            }
            grantUriPermission(packageName, uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(intent)
            return
        }
        if (protected) {
            Toast.makeText(this, R.string.disappear_cannot_open, Toast.LENGTH_LONG).show()
            return
        }
        val intent = Intent(Intent.ACTION_VIEW).apply {
            // The file's own extension picks the handler, not the type
            // the sender declared.
            setDataAndType(uri, mimeType)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        com.p2p.messenger.util.confirmExternalOpen(this, intent.type) {
            AppLock.beginTrustedExcursion()
            try { startActivity(intent) } catch (e: Exception) {
                Toast.makeText(this, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
            }
        }
    } catch (e: Exception) {
        Toast.makeText(this, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
    }
}

/** Same pattern as ChatActivity.onAttachmentLongClicked. This screen never wired it before, so a long press on a group attachment did nothing. */
internal fun GroupChatActivity.onGroupAttachmentLongClicked(item: SimpleChatAdapter.Item) {
    val attachment = item.attachment ?: return
    // Same pattern as ChatActivity.onAttachmentLongClicked: only attachments we sent ourselves can be deleted.
    val options = mutableListOf<String>().apply {
        // A disappearing file: nothing that copies it out (open in another app, save, copy, add sticker, select).
        val locked = Disappear.locked(item)
        if (!locked) {
            add(getString(R.string.action_open_with))
            add(getString(R.string.action_save_to_downloads))
            // Save to Downloads hands out a JPEG XL as PNG/GIF; this keeps the original.
            if (attachment.fileName.endsWith(".jxl", true) || attachment.mimeType == "image/jxl") add(getString(R.string.action_save_as_jxl))
            if (attachment.mimeType.startsWith("image/")) add(getString(R.string.action_copy_image))
            if (attachment.isSticker && !item.isMine) add(getString(R.string.action_add_to_my_stickers))
        }
        if (com.p2p.messenger.util.Forward.canForward(item)) add(getString(R.string.action_forward))
        if (item.isMine && item.status != SimpleChatAdapter.Status.SENT) add(getString(R.string.action_resend_message))
        if (item.isMine) add(getString(R.string.action_delete_message))
        if (!locked) add(getString(R.string.action_select))
    }
    AlertDialog.Builder(this)
        .setItems(options.toTypedArray()) { _, which ->
            when (options[which]) {
                getString(R.string.action_forward) -> com.p2p.messenger.util.Forward.start(this, item)
                getString(R.string.action_select) -> selection.start(item)
                getString(R.string.action_resend_message) -> resendGroupNow()
                getString(R.string.action_open_with) -> openGroupAttachmentWithChooser(attachment)
                getString(R.string.action_save_to_downloads) -> saveGroupAttachmentToDownloads(attachment)
                getString(R.string.action_save_as_jxl) -> saveGroupAttachmentToDownloads(attachment, original = true)
                getString(R.string.action_copy_image) -> OutgoingMedia.copyImage(this, attachment.fileId)
                getString(R.string.action_add_to_my_stickers) -> stickerPicker.saveReceived(attachment.fileId)
                getString(R.string.action_delete_message) -> confirmDeleteGroupMessage(item)
            }
        }
        .show()
}

/** Same pattern as ChatActivity.openAttachmentWithChooser. */
internal fun GroupChatActivity.openGroupAttachmentWithChooser(attachment: SimpleChatAdapter.AttachmentInfo) {
    lifecycleScope.launch(Dispatchers.IO) {
        val path = try {
            P2PLib.getAttachmentPlaintextPath(attachment.fileId)
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
        withContext(Dispatchers.Main) {
            if (path.startsWith("Error:")) {
                Toast.makeText(this@openGroupAttachmentWithChooser, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                return@withContext
            }
            try {
                val uri = FileProvider.getUriForFile(this@openGroupAttachmentWithChooser, "$packageName.fileprovider", File(path))
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    // The file's own extension, never the type the sender declared.
                    setDataAndType(
                        uri,
                        android.webkit.MimeTypeMap.getSingleton()
                            .getMimeTypeFromExtension(File(path).extension.lowercase()) ?: "*/*"
                    )
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                com.p2p.messenger.util.confirmExternalOpen(this@openGroupAttachmentWithChooser, intent.type) {
                    AppLock.beginTrustedExcursion()
                    try { startActivity(Intent.createChooser(intent, getString(R.string.lbl_open_with_chooser))) } catch (e: Exception) {
                        Toast.makeText(this@openGroupAttachmentWithChooser, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(this@openGroupAttachmentWithChooser, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
            }
        }
    }
}

/** Same pattern as ChatActivity.saveAttachmentToDownloads. */
/** `original`: a JPEG XL as it came (`image/jxl`), not converted. */
internal fun GroupChatActivity.saveGroupAttachmentToDownloads(attachment: SimpleChatAdapter.AttachmentInfo, original: Boolean = false) {
    lifecycleScope.launch(Dispatchers.IO) {
        val plainPath = try {
            if (original) P2PLib.getAttachmentOriginalPath(attachment.fileId)
            else P2PLib.getAttachmentPlaintextPath(attachment.fileId)
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
        if (plainPath.startsWith("Error:")) {
            withContext(Dispatchers.Main) {
                Toast.makeText(this@saveGroupAttachmentToDownloads, com.p2p.messenger.util.coreErrorText(this@saveGroupAttachmentToDownloads, plainPath), Toast.LENGTH_SHORT).show()
            }
            return@launch
        }
        val (name, mime) = if (original) attachment.fileName.let { if (it.endsWith(".jxl", true)) it else "$it.jxl" } to "image/jxl"
            else OutgoingMedia.savedAs(File(plainPath), attachment.fileName, attachment.mimeType)
        val saved = saveToPublicDownloads(File(plainPath), name, mime)
        withContext(Dispatchers.Main) {
            Toast.makeText(
                this@saveGroupAttachmentToDownloads,
                if (saved) getString(R.string.msg_saved_to_downloads) else getString(R.string.error_attachment_open_failed),
                Toast.LENGTH_SHORT
            ).show()
        }
    }
}

/** Same pattern as ChatActivity.saveToPublicDownloads. */
/**
 * Makes the file name sent by the other side harmless before it is used as a FILE NAME.
 *
 * The core does the same cleaning (Rust `safe_file_name`, `receive_file_offer`), but only for offers received AFTER that change.
 * Rows already in the `files` table keep the raw name, and the API 26-28 branch below does `File(p2pDir, displayName)`.
 * A name such as "../../DCIM/Camera/IMG_0001.jpg" would then write to an arbitrary path in shared storage.
 */
internal fun GroupChatActivity.saveToPublicDownloads(source: File, displayName: String, mimeType: String): Boolean {
    return try {
        val safeName = safeSaveFileName(displayName)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = android.content.ContentValues().apply {
                put(android.provider.MediaStore.Downloads.DISPLAY_NAME, safeName)
                put(android.provider.MediaStore.Downloads.MIME_TYPE, mimeType.ifBlank { "application/octet-stream" })
                put(android.provider.MediaStore.Downloads.RELATIVE_PATH, "Download/P2P")
            }
            // Pending until the copy is complete, and removed when it
            // fails: a half file used to stay in Download/P2P.
            values.put(android.provider.MediaStore.Downloads.IS_PENDING, 1)
            val uri = contentResolver.insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return false
            try {
                contentResolver.openOutputStream(uri)!!.use { output ->
                    source.inputStream().use { input -> input.copyTo(output) }
                }
                values.clear()
                values.put(android.provider.MediaStore.Downloads.IS_PENDING, 0)
                contentResolver.update(uri, values, null, null)
            } catch (e: Exception) {
                contentResolver.delete(uri, null, null)
                return false
            }
            true
        } else {
            @Suppress("DEPRECATION")
            val downloadsDir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
            val p2pDir = File(downloadsDir, "P2P").apply { mkdirs() }
            // Never over an earlier file of the same name.
            val dest = File(p2pDir, safeName).let {
                if (it.exists()) File(p2pDir, "${System.currentTimeMillis()}_$safeName") else it
            }
            source.inputStream().use { input -> dest.outputStream().use { output -> input.copyTo(output) } }
            android.media.MediaScannerConnection.scanFile(this, arrayOf(dest.absolutePath), arrayOf(mimeType), null)
            true
        }
    } catch (e: Exception) {
        false
    }
}

/**
 * A live group FileOffer, received as an event. Same logic as the ChatActivity handleIncomingEvent "file_offer" arm, plus the sender name and
 * avatar (resolved as for text messages, `resolveContactByIdentity`) and `peerDeviceFingerprint` (the download target).
 */
internal fun GroupChatActivity.handleIncomingGroupFileOffer(obj: JSONObject) {
    val senderIdentityId = obj.optString("sender_identity_id")
    val sender = resolveContactByIdentity(senderIdentityId)
    val autoDownloading = obj.optBoolean("auto_downloading", false)
    val previewHex = obj.optString("preview_hex", "")
    val previewJpeg = if (previewHex.isNotEmpty() && previewHex != "null") hexToBytes(previewHex) else null
    val durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it }
    // Attachment bubble with incoming caption and reply context.
    val attachmentCaption = obj.optString("caption", "")
    val attachmentReplyId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
    val attachmentReplyPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
    adapter.addMessage(
        SimpleChatAdapter.Item(
            messageId = obj.optString("file_id"),
            text = "",
            isMine = obj.optString("type") == "sibling_file",
            expireSecs = Disappear.fromEvent(obj).first, expireAtMs = Disappear.fromEvent(obj).second,
            senderName = sender?.displayName ?: senderIdentityId.take(8),
            senderAvatarJpeg = sender?.avatarHex?.let { sharedAvatarBytes(it) },
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
                peerDeviceFingerprint = obj.optString("peer"),
                isSticker = obj.optBoolean("sticker", false)
            ),
            // Attachment + caption + reply.
            caption = attachmentCaption,
            replyToMessageId = attachmentReplyId,
            replyToPreview = attachmentReplyPreview,
            senderIdentityId = senderIdentityId,
            replyToSenderLabel = resolveReplyLabel(attachmentReplyId)
        )
    )
    onNewIncomingItemAdded()
    // Sibling devices keep the notification until the watermark moves.
    if (obj.optString("type") == "file_offer") {
        // The watermark covers text rows only: the sender gets "seen" for
        // an attachment from this receipt, as on the 1:1 screen.
        val fileId = obj.optString("file_id")
        if (AppLock.isUnlocked()) netPack.execute {
            try { P2PLib.sendSeenReceipt(obj.optString("peer"), fileId, fileId) } catch (e: Exception) { }
        }
        scheduleGroupReadWatermark()
    }
}

internal fun GroupChatActivity.queryDisplayName(uri: Uri): String? {
    return try {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) cursor.getString(idx) else null
            } else null
        }
    } catch (e: Exception) {
        null
    }
}

internal fun GroupChatActivity.querySize(uri: Uri): Long? {
    return try {
        contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val idx = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (idx >= 0 && !cursor.isNull(idx)) cursor.getLong(idx) else null
            } else null
        }
    } catch (e: Exception) {
        null
    }
}

/** Same as ChatActivity.generateImagePreview. */
internal fun GroupChatActivity.generateImagePreview(file: File): ByteArray? =
    ImagePreview.compressFile(file, PREVIEW_MAX_DIMENSION, PREVIEW_JPEG_QUALITY)

/** Same as ChatActivity.generateVideoPreview. */
internal fun GroupChatActivity.generateVideoPreview(file: File): ByteArray? {
    val retriever = MediaMetadataRetriever()
    return try {
        retriever.setDataSource(file.absolutePath)
        val frame = retriever.getFrameAtTime(1_000_000L, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
            ?: retriever.getFrameAtTime(0L, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
            ?: return null
        ImagePreview.compressBitmap(frame, PREVIEW_MAX_DIMENSION, PREVIEW_JPEG_QUALITY)
    } catch (e: Exception) {
        null
    } finally {
        retriever.release()
    }
}
