package com.p2p.messenger.util

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import android.graphics.Rect
import android.graphics.Typeface
import android.widget.ImageView
import androidx.core.content.FileProvider
import com.p2p.messenger.ui.MediaViewerActivity
import java.io.File
import java.util.UUID

/**
 * Profile photo display (chat list and group bubbles). There is no image library such as Glide or Coil in the project. So both the drawing of a
 * real photo (always cropped to a square from the centre and masked to a circle, to match the "previews are square" choice) and the coloured
 * initial badge for people without a photo are done by hand.
 */
object AvatarUtil {
    private const val SIZE_PX = 96

    private val PALETTE = intArrayOf(
        0xFFEF5350.toInt(), 0xFFAB47BC.toInt(), 0xFF5C6BC0.toInt(), 0xFF29B6F6.toInt(),
        0xFF26A69A.toInt(), 0xFF9CCC65.toInt(), 0xFFFFCA28.toInt(), 0xFFFF7043.toInt()
    )

    /**
     * `renderInto`, and therefore `decodeCircularSquare` (BitmapFactory decode, square crop, scale, circle mask), used to run from scratch in every
     * `RecyclerView.onBindViewHolder` (chat list, contact list, EVERY message bubble). The same person's avatar was decoded again and again while a
     * list scrolled, which could cause visible jank. This is a simple in-memory cache. The key is a 64-bit fingerprint of the bytes (contentHashCode
     * plus an independent FNV-1a pass). A plain 32-bit hash could collide: one person's JPEG could match another's input and show the WRONG face.
     * It prevents decoding the same photo again and again. `LruCache` is synchronised internally, so it is safe to call from several RecyclerViews and
     * threads. 100 entries at about 36 KB each (96x96 ARGB_8888) is an upper bound of about 3.6 MB, a reasonable memory and speed balance.
     */
    private val placeholderCache = android.util.LruCache<String, Bitmap>(64)

    private val avatarBitmapCache = android.util.LruCache<Long, Bitmap>(100)

    /** 64-bit content fingerprint for the cache key. A single 32-bit
     *  `contentHashCode` let a peer-supplied JPEG collide with another
     *  contact's entry and render the WRONG face (however briefly): the
     *  combination with an independent FNV-1a pass keeps the per-bind cost
     *  O(n) as before but makes an accidental collision implausible. */
    private fun cacheKey(bytes: ByteArray): Long {
        var fnv = 2166136261L.toInt()
        for (b in bytes) {
            fnv = fnv xor (b.toInt() and 0xff)
            fnv *= 16777619
        }
        return (bytes.contentHashCode().toLong() shl 32) or (fnv.toLong() and 0xffffffffL)
    }

    /** If `avatarBytes` is set, the real photo is shown (cropped to a square and masked to a circle). Otherwise a deterministic coloured badge is
     *  made from the initial letter of `displayName`. */
    fun renderInto(imageView: ImageView, avatarBytes: ByteArray?, displayName: String) {
        val bitmap = avatarBytes?.let { bytes ->
            val key = cacheKey(bytes)
            // A failed decode is cached too (as the placeholder), so a bad image is not re-decoded on every bind.
            avatarBitmapCache.get(key) ?: (decodeCircularSquare(bytes) ?: placeholderCircle(displayName)).also { avatarBitmapCache.put(key, it) }
        } ?: placeholderCache.get(displayName) ?: placeholderCircle(displayName).also { placeholderCache.put(displayName, it) }
        imageView.setImageBitmap(bitmap)
    }

    /**
     * Tapping the profile photo opens it full screen with pinch-to-zoom (single-tap close is implemented in
     * MediaViewerActivity.setupZoomableImage). Unlike `renderInto`, the original bytes are shown here at full resolution, without the crop or
     * downscale of the 96x96 preview. If there is no photo (only the initial badge is shown), nothing happens.
     */
    fun openFullscreen(context: Context, avatarBytes: ByteArray?) {
        if (avatarBytes == null || avatarBytes.isEmpty()) return
        try {
            val dir = File(context.cacheDir, "avatar_view").apply { mkdirs() }
            // The photo is written as a plaintext file in the app cache. Files older than 10 minutes are deleted on each call, so the cache does
            // not grow. A file is not deleted at once: MediaViewerActivity may still be showing it.
            val retentionMs = 10 * 60 * 1000L
            val now = System.currentTimeMillis()
            dir.listFiles()?.forEach { old ->
                if (now - old.lastModified() > retentionMs) {
                    old.delete()
                }
            }
            val file = File(dir, "${UUID.randomUUID()}.jpg")
            file.writeBytes(avatarBytes)
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
            val intent = Intent(context, MediaViewerActivity::class.java).apply {
                putExtra(MediaViewerActivity.EXTRA_URI, uri)
                putExtra(MediaViewerActivity.EXTRA_MIME_TYPE, "image/jpeg")
            }
            context.startActivity(intent)
        } catch (e: Exception) {
        // Silently ignored. The profile photo preview is already visible, and full screen is only a convenience.
        }
    }

    private fun decodeCircularSquare(bytes: ByteArray): Bitmap? {
        val raw = ImagePreview.decodeBytes(bytes, SIZE_PX) ?: return null
        val edge = minOf(raw.width, raw.height)
        val x = (raw.width - edge) / 2
        val y = (raw.height - edge) / 2
        val square = Bitmap.createBitmap(raw, x, y, edge, edge)
        val scaled = Bitmap.createScaledBitmap(square, SIZE_PX, SIZE_PX, true)
        return toCircular(scaled)
    }

    private fun toCircular(bitmap: Bitmap): Bitmap {
        val output = Bitmap.createBitmap(bitmap.width, bitmap.height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(output)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        val rect = Rect(0, 0, bitmap.width, bitmap.height)
        canvas.drawCircle(bitmap.width / 2f, bitmap.height / 2f, bitmap.width / 2f, paint)
        paint.xfermode = PorterDuffXfermode(PorterDuff.Mode.SRC_IN)
        canvas.drawBitmap(bitmap, rect, rect, paint)
        return output
    }

    private fun placeholderCircle(displayName: String): Bitmap {
        val bitmap = Bitmap.createBitmap(SIZE_PX, SIZE_PX, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        val initial = displayName.trim().let { n ->
            // A whole code point: an emoji is two UTF-16 units.
            if (n.isEmpty()) "?" else n.substring(0, n.offsetByCodePoints(0, 1)).uppercase()
        }
        val bgColor = PALETTE[Math.floorMod(displayName.hashCode(), PALETTE.size)]
        val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = bgColor }
        canvas.drawCircle(SIZE_PX / 2f, SIZE_PX / 2f, SIZE_PX / 2f, bgPaint)
        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.WHITE
            textSize = SIZE_PX * 0.5f
            textAlign = Paint.Align.CENTER
            typeface = Typeface.DEFAULT_BOLD
        }
        val textY = SIZE_PX / 2f - (textPaint.descent() + textPaint.ascent()) / 2f
        canvas.drawText(initial, SIZE_PX / 2f, textY, textPaint)
        return bitmap
    }
}
