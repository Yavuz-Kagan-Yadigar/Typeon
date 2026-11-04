package com.p2p.messenger.util

import android.app.AlertDialog
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.net.Uri
import android.provider.OpenableColumns
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.ui.MediaViewerActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

/** One attachment the user kept in the caption dialog: its position in the
 *  `uris` list (0 for the camera's `jpeg`), its own lossless choice and what
 *  to send — the picked [uri] or camera [jpeg], or the editor's PNG in their
 *  place (as our own FileProvider URI, or its bytes for the camera). */
class PickedAttachment(val index: Int, val hiRes: Boolean, val uri: Uri?, val jpeg: ByteArray?)

/**
 * Caption dialog shown before an attachment goes out (shared by the 1:1 and
 * group chats). Any reply the screen holds travels with the attachment, so
 * the dialog only asks for the caption, which may stay empty.
 *
 * Every file in `uris` (or the camera's `jpeg`) gets a tile above the
 * caption box: a thumbnail that opens the image editor (the viewer for a
 * JPEG XL; the file name when it is not an image), a remove button and, for
 * images, its own lossless switch.
 * Removing the last tile cancels the dialog.
 */
fun AppCompatActivity.promptAttachmentCaption(
    onCancel: () -> Unit = {},
    uris: List<Uri> = emptyList(),
    jpeg: ByteArray? = null,
    onRetake: (() -> Unit)? = null,
    onConfirm: (caption: String, picked: List<PickedAttachment>) -> Unit,
) {
    val density = resources.displayMetrics.density
    val count = if (jpeg != null) 1 else uris.size
    val tileSize = ((if (count == 1) 200 else 120) * density).toInt()
    val strip = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
    val input = EditText(this).apply {
        hint = getString(R.string.hint_attachment_caption)
        setSingleLine(false)
        maxLines = 4
    }
    val container = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        val pad = (20 * density).toInt()
        setPadding(pad, pad / 2, pad, 0)
        if (count > 0) addView(HorizontalScrollView(this@promptAttachmentCaption).apply { addView(strip) })
        addView(input)
    }
    val title = getString(R.string.title_attachment_caption)
    fun titleFor(n: Int) = if (n > 1) "$title ($n)" else title
    val hiRes = BooleanArray(count)
    val kept = (0 until count).toMutableList()
    val previewDir = File(cacheDir, "attachment_preview")
    // Edited images: still read by the send after the dialog closes, so not
    // in `previewDir`. Kept when sent, deleted otherwise.
    val editDir = File(cacheDir, "attachment_edit")
    val edited = arrayOfNulls<File>(count)
    val names = arrayOfNulls<String>(count)
    val thumbs = arrayOfNulls<Bitmap>(count)
    var sent = false
    fun picked(i: Int): PickedAttachment {
        val e = edited[i]
        return if (jpeg != null) PickedAttachment(i, hiRes[i], null, e?.readBytes() ?: jpeg)
        else PickedAttachment(i, hiRes[i], e?.let { FileProvider.getUriForFile(this, "$packageName.fileprovider", it) } ?: uris[i], null)
    }
    val dialog = AlertDialog.Builder(this)
        .setTitle(titleFor(count))
        .setView(container)
        .setPositiveButton(R.string.btn_send) { _, _ -> sent = true; onConfirm(input.text.toString(), kept.map { picked(it) }) }
        .setNegativeButton(android.R.string.cancel) { _, _ -> onCancel() }
        .setOnCancelListener { onCancel() }
        .create()
    dialog.setOnDismissListener {
        previewDir.deleteRecursively()
        if (!sent) edited.forEach { it?.parentFile?.deleteRecursively() }
    }

    val gap = (4 * density).toInt()
    val tiles = (0 until count).map { i ->
        val image = ImageView(this).apply { scaleType = ImageView.ScaleType.CENTER_CROP }
        val name = TextView(this).apply {
            gravity = Gravity.CENTER
            setPadding(gap * 2, gap * 2, gap * 2, gap * 2)
            ellipsize = TextUtils.TruncateAt.MIDDLE
            maxLines = 4
        }
        val lossless = CheckBox(this).apply {
            setText(R.string.attachment_hi_res)
            textSize = 12f
            setTextColor(Color.WHITE)
            setBackgroundColor(0x99000000.toInt())
            visibility = View.GONE
            setOnCheckedChangeListener { _, checked -> hiRes[i] = checked }
        }
        val tile = FrameLayout(this).apply {
            setBackgroundColor(0x33808080)
            addView(name, FrameLayout.LayoutParams(MATCH, MATCH))
            addView(image, FrameLayout.LayoutParams(MATCH, MATCH))
            addView(lossless, FrameLayout.LayoutParams(MATCH, WRAP, Gravity.BOTTOM))
        }
        val remove = ImageButton(this).apply {
            setImageResource(R.drawable.ic_close)
            setColorFilter(Color.WHITE)
            setBackgroundColor(0x99000000.toInt())
            contentDescription = getString(R.string.action_delete_message)
            setOnClickListener {
                kept.remove(i)
                strip.removeView(tile)
                if (kept.isEmpty()) dialog.cancel() else dialog.setTitle(titleFor(kept.size))
            }
        }
        tile.addView(remove, FrameLayout.LayoutParams((32 * density).toInt(), (32 * density).toInt(), Gravity.TOP or Gravity.END))
        strip.addView(tile, LinearLayout.LayoutParams(tileSize, tileSize).apply { marginEnd = gap })
        Triple(image, name, lossless)
    }
    dialog.show()

    if (count == 0) return
    lifecycleScope.launch(Dispatchers.IO) {
        // ponytail: sent edits are swept an hour later, long after the send copied them.
        val stale = System.currentTimeMillis() - 3_600_000
        editDir.listFiles()?.forEach { if (it.lastModified() < stale) it.deleteRecursively() }
        for (i in 0 until count) {
            // Provider reads are IPC to another app: off the main thread.
            val uri = uris.getOrNull(i)
            val jxl = uri != null && isJxl(uri)
            val thumb = when {
                jpeg != null -> ImagePreview.decodeBytes(jpeg, tileSize)
                jxl -> decodeJxlThumb(uri!!, tileSize)
                else -> decodeBitmapThumb(uri!!, tileSize)
            }
            val label = if (uri != null) queryName(uri) else null
            withContext(Dispatchers.Main) {
                val (image, name, lossless) = tiles[i]
                if (thumb == null) {
                    name.text = label ?: "?"
                    return@withContext
                }
                names[i] = label
                thumbs[i] = thumb
                image.setImageBitmap(thumb)
                // A JPEG XL goes as it is: the switch would change nothing.
                if (!jxl) lossless.visibility = View.VISIBLE
                image.setOnClickListener {
                    // JPEG XL: no Android decoder to edit with, the viewer only.
                    if (jxl) openPreview(uri, jpeg, jxl, previewDir) else editTile(i, uri, jpeg, names, edited, editDir, onRetake?.let { retake -> { dialog.dismiss(); retake() } }) { file ->
                        if (file == null) image.setImageBitmap(thumbs[i])
                        else lifecycleScope.launch(Dispatchers.IO) {
                            val t = decodeBitmapThumb(Uri.fromFile(file), tileSize)
                            withContext(Dispatchers.Main) { if (edited[i] == file) image.setImageBitmap(t) }
                        }
                    }
                }
                // The in-app camera's shot opens straight in the editor; OK lands on this dialog.
                if (jpeg != null && dialog.isShowing) image.performClick()
            }
        }
    }
}

/** Opens tile [i] in the editor: from its last edit if any, Revert goes
 *  back to the picked file. [edited] gets the new PNG (null: the original). */
private fun AppCompatActivity.editTile(
    i: Int, uri: Uri?, jpeg: ByteArray?, names: Array<String?>, edited: Array<File?>, editDir: File,
    onRetake: (() -> Unit)?,
    onChanged: (File?) -> Unit,
) {
    val original = { if (jpeg != null) ImagePreview.decodeBytes(jpeg, EDIT_MAX) else decodeBitmapThumbOrThrow(uri!!, EDIT_MAX) }
    val current = edited[i]
    // A provider's display name may hold anything: no path separators in ours.
    val base = names[i]?.substringBeforeLast('.')?.replace('/', '_')?.replace('\u0000', '_')?.take(80)?.takeIf { it.isNotBlank() } ?: "IMG"
    openImageEditor(
        load = { current?.let { decodeBitmapThumbOrThrow(Uri.fromFile(it), EDIT_MAX) } ?: original() },
        original = original,
        startEdited = current != null,
        out = File(editDir, "${UUID.randomUUID()}/$base.png"),
        onRetake = onRetake,
    ) { file ->
        edited[i]?.parentFile?.deleteRecursively()
        edited[i] = file
        onChanged(file)
    }
}

private const val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
private const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

/** Full-screen look at a tile. The viewer reads a picked `content://` URI
 *  directly; the camera's bytes and a JPEG XL (no Android decoder: its
 *  first frames as GIF) go through a temp file the dialog deletes. */
private fun AppCompatActivity.openPreview(uri: Uri?, jpeg: ByteArray?, jxl: Boolean, dir: File) {
    lifecycleScope.launch(Dispatchers.IO) {
        val (viewUri, mime) = try {
            when {
                jpeg != null -> shareable(dir, "jpg") { it.writeBytes(jpeg) } to "image/jpeg"
                jxl -> shareable(dir, "gif") { out ->
                    val src = File(dir.apply { mkdirs() }, "src-${UUID.randomUUID()}")
                    try {
                        contentResolver.openInputStream(uri!!)?.use { input -> src.outputStream().use { input.copyTo(it) } }
                        if (P2PLib.jxlToGif(src.absolutePath, out.absolutePath) != "OK") throw java.io.IOException("jxl")
                    } finally {
                        src.delete()
                    }
                } to "image/gif"
                else -> uri!! to (contentResolver.getType(uri) ?: "image/*")
            }
        } catch (e: Exception) {
            return@launch
        }
        withContext(Dispatchers.Main) {
            startActivity(Intent(this@openPreview, MediaViewerActivity::class.java).apply {
                putExtra(MediaViewerActivity.EXTRA_URI, viewUri)
                putExtra(MediaViewerActivity.EXTRA_MIME_TYPE, mime)
            })
        }
    }
}

private fun AppCompatActivity.shareable(dir: File, ext: String, write: (File) -> Unit): Uri {
    val file = File(dir.apply { mkdirs() }, "${UUID.randomUUID()}.$ext")
    write(file)
    return FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
}

private fun AppCompatActivity.isJxl(uri: Uri): Boolean = try {
    val head = ByteArray(12)
    val n = contentResolver.openInputStream(uri)?.use { it.read(head) } ?: 0
    ImagePreview.isJxl(head.copyOf(maxOf(n, 0)))
} catch (e: Exception) {
    false
}

private fun AppCompatActivity.queryName(uri: Uri): String? = try {
    contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    }
} catch (e: Exception) {
    null
}

/** BitmapFactory cannot read JPEG XL: copy to a temp file and go through
 *  the same first-frame path the attachment preview uses. */
private fun AppCompatActivity.decodeJxlThumb(uri: Uri, maxDimension: Int): Bitmap? {
    val tmp = File(File(cacheDir, "outgoing").apply { mkdirs() }, "thumb-${UUID.randomUUID()}")
    return try {
        contentResolver.openInputStream(uri)?.use { input -> tmp.outputStream().use { input.copyTo(it) } } ?: return null
        ImagePreview.compressFile(tmp, maxDimension, 85)?.let { ImagePreview.decodeBytes(it, maxDimension) }
    } catch (e: Throwable) {
        null
    } finally {
        tmp.delete()
    }
}

/** Sampled decode straight from the provider; what does not decode (a
 *  video, a document) gets its file name instead. */
private fun AppCompatActivity.decodeBitmapThumb(uri: Uri, maxDimension: Int): Bitmap? = try {
    decodeBitmapThumbOrThrow(uri, maxDimension)
} catch (e: Throwable) {
    null
}

private fun AppCompatActivity.decodeBitmapThumbOrThrow(uri: Uri, maxDimension: Int): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    val options = BitmapFactory.Options().apply {
        inSampleSize = ImagePreview.sampleSizeFor(bounds.outWidth, bounds.outHeight, maxDimension)
    }
    val bmp = contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, options) } ?: return null
    val exif = try {
        contentResolver.openInputStream(uri)?.use { android.media.ExifInterface(it) }
    } catch (e: Exception) {
        null
    }
    return if (exif != null) ImagePreview.rotateForExif(bmp, exif) else bmp
}
