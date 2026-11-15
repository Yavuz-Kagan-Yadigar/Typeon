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

// ChatActivity: picking, sending, opening and saving attachments; shared content.

/** Content selected on the share screen (see util.ShareIntake). */
internal fun ChatActivity.consumeShare(intent: Intent) {
    com.p2p.messenger.util.ShareIntake.takeForward(intent)?.let {
        pendingForward = it
        flushPendingShare()
        return
    }
    val share = com.p2p.messenger.util.ShareIntake.take(intent) ?: return
    com.p2p.messenger.util.ShareIntake.text(share)?.let {
        findViewById<EditText>(R.id.edtMessage).apply { setText(it); setSelection(text.length) }
    }
    pendingShare = com.p2p.messenger.util.ShareIntake.uris(share)
    flushPendingShare()
}

internal fun ChatActivity.flushPendingShare() {
    if (!handshakeReady || peerAccountDeleted) return
    pendingForward?.let { f ->
        pendingForward = null
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.confirm_forward, txtToolbarTitle.text))
            .setPositiveButton(R.string.btn_send) { _, _ ->
                lifecycleScope.launch {
                    var done = 0
                    try {
                        for (p in f) {
                            if (p.file != null) onFilePicked(Uri.fromFile(p.file), p.caption, hiRes = true, name = p.fileName, mime = p.mimeType).join()
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
    }
    if (pendingShare.isEmpty()) return
    val uris = pendingShare
    pendingShare = emptyList()
    // The chat was picked with one tap in a list that reorders itself.
    AlertDialog.Builder(this)
        .setMessage(getString(R.string.confirm_send_shared, uris.size, txtToolbarTitle.text))
        .setPositiveButton(R.string.btn_send) { _, _ -> sendPickedFiles(uris.map { it to false }) }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

// ---------------------------------------------------------------
// Ekler
// ---------------------------------------------------------------

/** Copies a resolved attachment into the 'Downloads/P2P' folder. API 29+ uses MediaStore (no permission needed). Below that, direct file writes
 *  (WRITE_EXTERNAL_STORAGE; see the permission request in onCreate). */
/**
 * Makes the file name sent by the other side harmless before it is used as a FILE NAME.
 *
 * The core does the same cleaning (Rust `safe_file_name`, `receive_file_offer`), but only for offers received AFTER that change.
 * Rows already in the `files` table keep the raw name, and the API 26-28 branch below does `File(p2pDir, displayName)`.
 * A name such as "../../DCIM/Camera/IMG_0001.jpg" would write to an arbitrary path in shared storage.
 */
internal fun ChatActivity.saveToPublicDownloads(source: File, displayName: String, mimeType: String): Boolean {
    return try {
        val safeName = safeSaveFileName(displayName)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
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
            // So the gallery and file manager see the new file at once.
            MediaScannerConnection.scanFile(this, arrayOf(dest.absolutePath), arrayOf(mimeType), null)
            true
        }
    } catch (e: Exception) {
        false
    }
}

/**
 * Long press on an attachment bubble (only when it is completed; see SimpleChatAdapter) shows 'Save to Downloads/P2P'.
 * It saves directly, without asking the sender. The file is already downloaded and encrypted on the device, and a sender approval round trip
 * added nothing (it could never arrive while the sender was offline). This applies to incoming and own attachments alike (`item.isMine` is not checked).
 */
internal fun ChatActivity.onAttachmentLongClicked(item: SimpleChatAdapter.Item) {
    val attachment = item.attachment ?: return
    // 'Open with another app' is available. A tap (photo and video in the in-app MediaViewerActivity, others in the system default) is unchanged.
    // This option always shows the app chooser (`Intent.createChooser`).
    val options = mutableListOf<String>().apply {
        add(getString(R.string.action_open_with))
        add(getString(R.string.action_save_to_downloads))
        // Save to Downloads hands out a JPEG XL as PNG/GIF; this keeps the original.
        if (attachment.fileName.endsWith(".jxl", true) || attachment.mimeType == "image/jxl") add(getString(R.string.action_save_as_jxl))
        if (attachment.mimeType.startsWith("image/")) add(getString(R.string.action_copy_image))
        if (attachment.isSticker && !item.isMine) add(getString(R.string.action_add_to_my_stickers))
        if (com.p2p.messenger.util.Forward.canForward(item)) add(getString(R.string.action_forward))
        if (item.isMine) add(getString(R.string.action_delete_message))
        add(getString(R.string.action_select))
    }
    AlertDialog.Builder(this)
        .setItems(options.toTypedArray()) { _, which ->
            when (options[which]) {
                getString(R.string.action_forward) -> com.p2p.messenger.util.Forward.start(this, item)
                getString(R.string.action_select) -> selection.start(item)
                getString(R.string.action_open_with) -> openAttachmentWithChooser(attachment)
                getString(R.string.action_save_to_downloads) -> saveAttachmentToDownloads(attachment)
                getString(R.string.action_save_as_jxl) -> saveAttachmentToDownloads(attachment, original = true)
                getString(R.string.action_copy_image) -> OutgoingMedia.copyImage(this, attachment.fileId)
                getString(R.string.action_add_to_my_stickers) -> stickerPicker.saveReceived(attachment.fileId)
                getString(R.string.action_delete_message) -> confirmDeleteMessage(item)
            }
        }
        .show()
}

internal fun ChatActivity.openAttachmentWithChooser(attachment: SimpleChatAdapter.AttachmentInfo) {
    lifecycleScope.launch(Dispatchers.IO) {
        val path = try {
            P2PLib.getAttachmentPlaintextPath(attachment.fileId)
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
        withContext(Dispatchers.Main) {
            if (path.startsWith("Error:")) {
                Toast.makeText(this@openAttachmentWithChooser, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                return@withContext
            }
            try {
                val uri = FileProvider.getUriForFile(this@openAttachmentWithChooser, "$packageName.fileprovider", File(path))
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    // The file's own extension, never the type the sender declared.
                    setDataAndType(
                        uri,
                        android.webkit.MimeTypeMap.getSingleton()
                            .getMimeTypeFromExtension(File(path).extension.lowercase()) ?: "*/*"
                    )
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                com.p2p.messenger.util.confirmExternalOpen(this@openAttachmentWithChooser, intent.type) {
                    AppLock.beginTrustedExcursion()
                    try { startActivity(Intent.createChooser(intent, getString(R.string.lbl_open_with_chooser))) } catch (e: Exception) {
                        Toast.makeText(this@openAttachmentWithChooser, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(this@openAttachmentWithChooser, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
            }
        }
    }
}

/** `original`: a JPEG XL as it came (`image/jxl`), not converted. */
internal fun ChatActivity.saveAttachmentToDownloads(attachment: SimpleChatAdapter.AttachmentInfo, original: Boolean = false) {
    lifecycleScope.launch(Dispatchers.IO) {
        val plainPath = try {
            if (original) P2PLib.getAttachmentOriginalPath(attachment.fileId)
            else P2PLib.getAttachmentPlaintextPath(attachment.fileId)
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
        if (plainPath.startsWith("Error:")) {
            withContext(Dispatchers.Main) {
                Toast.makeText(this@saveAttachmentToDownloads, com.p2p.messenger.util.coreErrorText(this@saveAttachmentToDownloads, plainPath), Toast.LENGTH_SHORT).show()
            }
            return@launch
        }
        val (name, mime) = if (original) attachment.fileName.let { if (it.endsWith(".jxl", true)) it else "$it.jxl" } to "image/jxl"
            else OutgoingMedia.savedAs(File(plainPath), attachment.fileName, attachment.mimeType)
        val saved = saveToPublicDownloads(File(plainPath), name, mime)
        withContext(Dispatchers.Main) {
            Toast.makeText(
                this@saveAttachmentToDownloads,
                if (saved) getString(R.string.msg_saved_to_downloads)
                else getString(R.string.error_attachment_open_failed),
                Toast.LENGTH_SHORT
            ).show()
        }
    }
}

/** Single tap: download if not yet downloaded, open if completed. A tap during a download does nothing. */
internal fun ChatActivity.onAttachmentClicked(item: SimpleChatAdapter.Item) {
    val attachment = item.attachment ?: return
    when (attachment.status) {
        SimpleChatAdapter.AttachmentStatus.OFFERED, SimpleChatAdapter.AttachmentStatus.FAILED -> {
            adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.DOWNLOADING, 0)
            lifecycleScope.launch(Dispatchers.IO) {
                val result = try {
                    P2PLib.downloadFile(attachment.fileId, peerDeviceFingerprint)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                if (result.startsWith("Error:")) {
                    withContext(Dispatchers.Main) {
                        adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.FAILED)
                        Toast.makeText(this@onAttachmentClicked, com.p2p.messenger.util.coreErrorText(this@onAttachmentClicked, result), Toast.LENGTH_SHORT).show()
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
                        Toast.makeText(this@onAttachmentClicked, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                    } else {
                        openAttachmentFile(path)
                    }
                }
            }
        }
        SimpleChatAdapter.AttachmentStatus.DOWNLOADING -> {
            // Already downloading: a tap does nothing.
        }
    }
}

/** Photos and videos open in the in-app viewer (MediaViewerActivity); other types go to the system default. */
internal fun ChatActivity.openAttachmentFile(path: String) {
    // The file's own extension picks the viewer and the handler, not the
    // type the sender declared.
    val mimeType = android.webkit.MimeTypeMap.getSingleton()
        .getMimeTypeFromExtension(File(path).extension.lowercase()) ?: "*/*"
    try {
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", File(path))
        if (mimeType.startsWith("image/") || mimeType.startsWith("video/")) {
            val intent = Intent(this, MediaViewerActivity::class.java).apply {
                putExtra("uri", uri)
                putExtra("mime_type", mimeType)
            }
            grantUriPermission(packageName, uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(intent)
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

/**
 * Sends a photo captured by the camera. Same send path as `onFilePicked`; the one difference is that the source is JPEG bytes already in memory,
 * not a `content://` URI. So there is no separate name or size lookup (SAF `OpenableColumns`), and the name is generated at capture time.
 *
 * The temporary file in the cache (`cacheDir/outgoing`) is needed because the Rust core wants a real file PATH when sending an attachment.
 * It is deleted in `finally`. The photo is never written to the system gallery or shared storage.
 */
internal fun ChatActivity.onPhotoCaptured(jpeg: ByteArray, caption: String = "", hiRes: Boolean = false, quote: com.p2p.messenger.util.Quote.Ref? = null) {
    val fileName = "IMG_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date()) + ".jpg"
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
            val prepared = OutgoingMedia.prepare(tempFile, fileName, "image/jpeg", hiRes) { OutgoingMedia.askSendUnscrubbed(this@onPhotoCaptured) }
            sent = prepared.file
            val result = P2PLib.prepareAndSendFile(
                peerDeviceFingerprint, prepared.file.absolutePath, prepared.fileName, prepared.mimeType, previewJpeg, -1,
                caption, quote?.id ?: "", quote?.preview ?: ""
            )
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@onPhotoCaptured, com.p2p.messenger.util.coreErrorText(this@onPhotoCaptured, result), Toast.LENGTH_SHORT).show()
                } else {
                    val obj = JSONObject(result)
                    adapter.addMessage(
                        SimpleChatAdapter.Item(
                            messageId = obj.optString("message_id"),
                            text = "",
                            isMine = true,
                            attachment = SimpleChatAdapter.AttachmentInfo(
                                fileId = obj.optString("message_id"),
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
                            replyToSenderLabel = resolveReplyLabel(quote?.id)
                        )
                    )
                    scrollToBottomNow()
                }
            }
        } catch (e: Exception) {
            if (e is java.util.concurrent.CancellationException) return@launch
            withContext(Dispatchers.Main) {
                Toast.makeText(this@onPhotoCaptured, getString(R.string.error_send_failed), Toast.LENGTH_SHORT).show()
            }
        } finally {
            tempFile.delete()
            sent.delete()
        }
    }
}

/** One send at a time so the files arrive in the order they were
 *  picked; the caption goes with the last one, under the batch. */
internal fun ChatActivity.sendPickedFiles(files: List<Pair<Uri, Boolean>>, caption: String = "", quote: com.p2p.messenger.util.Quote.Ref? = null) =
    lifecycleScope.launch { files.forEachIndexed { i, (u, hiRes) -> val last = i == files.lastIndex; onFilePicked(u, if (last) caption else "", hiRes, quote = if (last) quote else null).join() } }

/**
 * A file picked with SAF (`OpenDocument`) is first copied to the app's own cache, because a `content://` URI is not a path and the Rust side needs a real file path.
 * Then it is encrypted and offered with `prepareAndSendFile`.
 */
internal fun ChatActivity.onFilePicked(uri: Uri, caption: String = "", hiRes: Boolean = false, name: String? = null, mime: String? = null, quote: com.p2p.messenger.util.Quote.Ref? = null): kotlinx.coroutines.Job {
    return lifecycleScope.launch(Dispatchers.IO) {
        // Provider queries are IPC to another app: not on the main thread.
        val fileName = name ?: queryDisplayName(uri) ?: "file"
        val mimeType = mime ?: contentResolver.getType(uri) ?: "application/octet-stream"
        val size = querySize(uri)
        val tooLarge = size != null && size > MAX_ATTACHMENT_SIZE
        withContext(Dispatchers.Main) {
            if (tooLarge) {
                Toast.makeText(this@onFilePicked, getString(R.string.error_file_too_large_named, fileName), Toast.LENGTH_LONG).show()
            } else {
                Toast.makeText(this@onFilePicked, fileName, Toast.LENGTH_SHORT).show()
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
            } ?: throw java.io.IOException("File could not be opened")

            val previewJpeg = try {
                when {
                    mimeType.startsWith("image/") -> generateImagePreview(tempFile)
                    mimeType.startsWith("video/") -> generateVideoPreview(tempFile)
                    else -> null
                }
            } catch (e: Exception) {
                null
            }

            val prepared = OutgoingMedia.prepare(tempFile, fileName, mimeType, hiRes) { OutgoingMedia.askSendUnscrubbed(this@onFilePicked) }
            sent = prepared.file
            val result = P2PLib.prepareAndSendFile(
                peerDeviceFingerprint, prepared.file.absolutePath, prepared.fileName, prepared.mimeType, previewJpeg, -1,
                caption, quote?.id ?: "", quote?.preview ?: ""
            )
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@onFilePicked, com.p2p.messenger.util.coreErrorText(this@onFilePicked, result), Toast.LENGTH_SHORT).show()
                } else {
                    val obj = JSONObject(result)
                    adapter.addMessage(
                        SimpleChatAdapter.Item(
                            messageId = obj.optString("message_id"),
                            text = "",
                            isMine = true,
                            attachment = SimpleChatAdapter.AttachmentInfo(
                                fileId = obj.optString("message_id"),
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
                            replyToSenderLabel = resolveReplyLabel(quote?.id)
                        )
                    )
                    scrollToBottomNow()
                }
            }
        } catch (e: Exception) {
            if (e is java.util.concurrent.CancellationException) return@launch
            withContext(Dispatchers.Main) {
                if (e.message == "too_large") Toast.makeText(this@onFilePicked, getString(R.string.error_file_too_large_named, fileName), Toast.LENGTH_LONG).show() else Toast.makeText(this@onFilePicked, getString(R.string.error_send_failed), Toast.LENGTH_SHORT).show()
            }
        } finally {
            tempFile.delete()
            sent.delete()
        }
    }
}

internal fun ChatActivity.queryDisplayName(uri: Uri): String? {
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

internal fun ChatActivity.querySize(uri: Uri): Long? {
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

/** A small 480p / 85% JPEG cover, sent with the `FileOffer`, so the recipient can see a preview before downloading the full file. */
internal fun ChatActivity.generateImagePreview(file: File): ByteArray? =
    ImagePreview.compressFile(file, PREVIEW_MAX_DIMENSION, PREVIEW_JPEG_QUALITY)

internal fun ChatActivity.generateVideoPreview(file: File): ByteArray? {
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
