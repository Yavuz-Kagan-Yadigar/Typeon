package com.p2p.messenger.util

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.ImageDecoder
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import android.os.Build
import com.p2p.messenger.P2PLib
import java.io.File
import kotlin.math.roundToInt

/**
 * A picture file as a sticker. GIF ([GifFrames]) and animated WebP
 * ([animatedWebp]) keep their frames; anything else is one still frame.
 */
object StickerImport {
    /** The core's own cap (attachments::jxl_codec::STICKER_MAX_SIDE). */
    const val MAX_SIDE = 600
    /** attachments::jxl_codec::MAX_ANIMATION_FRAMES. */
    const val MAX_FRAMES = 300
    /** attachments::jxl_codec::MAX_IMAGE_PIXELS: the core refuses more (all frames). */
    private const val MAX_PIXELS = 24_000_000L

    /** [file] is a GIF, PNG, JPEG or WebP. Returns the sticker id or "Error: ...". */
    fun importFile(file: File, origin: String? = null): String {
        if (!file.exists() || file.length() == 0L) return "Error: file could not be read"
        val head = ByteArray(4)
        val read = try { file.inputStream().use { it.read(head) } } catch (e: Exception) { return "Error: ${e.message}" }
        val magic = String(head, 0, read.coerceAtLeast(0), Charsets.ISO_8859_1)
        // A still GIF/WebP (or one over the caps) is imported as its first frame.
        val animation = when (magic) {
            "GIF8" -> GifFrames.decode(file, MAX_FRAMES, MAX_PIXELS)
            "RIFF" -> try { animatedWebp(file.readBytes()) } catch (e: Exception) { null }
            else -> null
        }
        return if (animation != null) importAnimated(animation, origin) else importStill(file, origin)
    }

    /** A still picture: one frame, no delay. */
    private fun importStill(file: File, origin: String?): String {
        val bitmap = fit(decodeStill(file)) ?: return "Error: image could not be decoded"
        try {
            return P2PLib.importStickerFrames(
                arrayOf(toRgba(bitmap)), bitmap.width, bitmap.height, intArrayOf(0), origin
            )
        } finally {
            bitmap.recycle()
        }
    }

    /** An animation, scaled to the sticker's cap. */
    private fun importAnimated(gif: GifFrames, origin: String?): String {
        var w = gif.width
        var h = gif.height
        var frames = gif.frames
        if (maxOf(w, h) > MAX_SIDE) {
            val scale = MAX_SIDE.toFloat() / maxOf(w, h)
            val nw = (w * scale).roundToInt().coerceAtLeast(1)
            val nh = (h * scale).roundToInt().coerceAtLeast(1)
            frames = Array(frames.size) { scaleFrame(frames[it], w, h, nw, nh) }
            w = nw
            h = nh
        }
        // The core's budget for all frames together: a longer animation is
        // cut short (the first frames are kept).
        val budget = (MAX_PIXELS / (w.toLong() * h)).toInt().coerceAtLeast(1)
        val count = minOf(frames.size, budget)
        return P2PLib.importStickerFrames(
            frames.copyOfRange(0, count), w, h, gif.delaysMs.copyOfRange(0, count), origin
        )
    }

    /**
     * The composited frames of an animated WebP (RIFF/VP8X/ANMF), or null when
     * it is not animated. Each ANMF frame is re-wrapped as a still WebP for
     * BitmapFactory, then drawn onto the canvas with its blend/dispose flags.
     * Frames past [MAX_FRAMES] or [MAX_PIXELS] are cut.
     */
    private fun animatedWebp(d: ByteArray): GifFrames? {
        fun u24(i: Int) = (d[i].toInt() and 0xFF) or ((d[i + 1].toInt() and 0xFF) shl 8) or ((d[i + 2].toInt() and 0xFF) shl 16)
        fun u32(i: Int) = u24(i) or ((d[i + 3].toInt() and 0xFF) shl 24)
        fun fourcc(i: Int) = String(d, i, 4, Charsets.ISO_8859_1)
        if (d.size < 30 || fourcc(8) != "WEBP" || fourcc(12) != "VP8X" || d[20].toInt() and 0x02 == 0) return null
        val w = u24(24) + 1
        val h = u24(27) + 1
        if (w.toLong() * h > MAX_PIXELS) return null
        val canvasBitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(canvasBitmap)
        val replace = Paint().apply { xfermode = PorterDuffXfermode(PorterDuff.Mode.SRC) }
        val clear = Paint().apply { xfermode = PorterDuffXfermode(PorterDuff.Mode.CLEAR) }
        val frames = ArrayList<ByteArray>()
        val delays = ArrayList<Int>()
        try {
            var pos = 12
            while (pos + 8 <= d.size && frames.size < MAX_FRAMES && (frames.size + 1L) * w * h <= MAX_PIXELS) {
                val size = u32(pos + 4)
                val body = pos + 8
                if (size < 0 || body + size > d.size) break
                if (fourcc(pos) == "ANMF" && size > 16) {
                    val x = u24(body) * 2f
                    val y = u24(body + 3) * 2f
                    val fw = u24(body + 6) + 1
                    val fh = u24(body + 9) + 1
                    val flags = d[body + 15].toInt()
                    val data = d.copyOfRange(body + 16, body + size)
                    // A still WebP: RIFF + VP8X (alpha flag, frame size) + the frame's own chunks.
                    // The flag is always set: without it the decoder drops a VP8L frame's alpha.
                    val vp8x = ByteArray(18).also {
                        "VP8X".toByteArray(Charsets.ISO_8859_1).copyInto(it)
                        it[4] = 10
                        it[8] = 0x10
                        for (k in 0 until 3) {
                            it[12 + k] = ((fw - 1) shr (8 * k)).toByte()
                            it[15 + k] = ((fh - 1) shr (8 * k)).toByte()
                        }
                    }
                    val riffSize = 4 + vp8x.size + data.size
                    val still = "RIFF".toByteArray(Charsets.ISO_8859_1) +
                        byteArrayOf(riffSize.toByte(), (riffSize shr 8).toByte(), (riffSize shr 16).toByte(), (riffSize shr 24).toByte()) +
                        "WEBP".toByteArray(Charsets.ISO_8859_1) + vp8x + data
                    val frame = BitmapFactory.decodeByteArray(still, 0, still.size) ?: return null
                    canvas.drawBitmap(frame, x, y, if (flags and 0x02 != 0) replace else null)
                    frame.recycle()
                    frames.add(toRgba(canvasBitmap))
                    delays.add(u24(body + 12).let { if (it <= 10) 100 else it })
                    if (flags and 0x01 != 0) canvas.drawRect(x, y, x + fw, y + fh, clear)
                }
                pos = body + size + (size and 1)
            }
        } finally {
            canvasBitmap.recycle()
        }
        if (frames.size < 2) return null
        return GifFrames(w, h, frames.toTypedArray(), delays.toIntArray(), true)
    }

    /** The picture, at most [MAX_SIDE] a side (the aspect ratio is kept). */
    private fun decodeStill(file: File): Bitmap? {
        val decoded: Bitmap? = if (Build.VERSION.SDK_INT >= 28) {
            try {
                ImageDecoder.decodeBitmap(ImageDecoder.createSource(file)) { decoder, info, _ ->
                    decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                    // No isUnpremultipliedRequired: it throws with setTargetSize,
                    // and getPixels (toRgba) un-premultiplies anyway.
                    val w = info.size.width
                    val h = info.size.height
                    val longest = maxOf(w, h)
                    if (longest > MAX_SIDE) {
                        val scale = MAX_SIDE.toFloat() / longest
                        decoder.setTargetSize(
                            (w * scale).roundToInt().coerceAtLeast(1),
                            (h * scale).roundToInt().coerceAtLeast(1)
                        )
                    }
                }
            } catch (e: Throwable) {
                null
            }
        } else {
            // API 26/27: no ImageDecoder — a sampled decode instead.
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            try {
                BitmapFactory.decodeFile(file.absolutePath, bounds)
            } catch (e: Throwable) {
                return null
            }
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
            val options = BitmapFactory.Options().apply {
                inSampleSize = ImagePreview.sampleSizeFor(bounds.outWidth, bounds.outHeight, MAX_SIDE)
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }
            try {
                BitmapFactory.decodeFile(file.absolutePath, options)
            } catch (e: Throwable) {
                null
            }
        }
        if (decoded == null) return null
        // A 16-bit source can decode as F16 — the pixel copy wants 8-bit.
        if (decoded.config == Bitmap.Config.ARGB_8888) return decoded
        val copy = try {
            decoded.copy(Bitmap.Config.ARGB_8888, false)
        } catch (e: Throwable) {
            null
        }
        decoded.recycle()
        return copy
    }

    /** [bitmap] at most [MAX_SIDE] a side; the aspect ratio is kept. */
    private fun fit(bitmap: Bitmap?): Bitmap? {
        if (bitmap == null) return null
        val longest = maxOf(bitmap.width, bitmap.height)
        if (longest <= MAX_SIDE) return bitmap
        val scale = MAX_SIDE.toFloat() / longest
        val scaled = Bitmap.createScaledBitmap(
            bitmap,
            (bitmap.width * scale).roundToInt().coerceAtLeast(1),
            (bitmap.height * scale).roundToInt().coerceAtLeast(1),
            true
        )
        if (scaled !== bitmap) bitmap.recycle()
        return scaled
    }

    /** The pixels as straight (not premultiplied) RGBA bytes. */
    private fun toRgba(bitmap: Bitmap): ByteArray {
        val w = bitmap.width
        val h = bitmap.height
        val pixels = IntArray(w * h)
        bitmap.getPixels(pixels, 0, w, 0, 0, w, h)
        val out = ByteArray(w * h * 4)
        for (i in pixels.indices) {
            val p = pixels[i]
            out[i * 4] = (p shr 16).toByte()
            out[i * 4 + 1] = (p shr 8).toByte()
            out[i * 4 + 2] = p.toByte()
            out[i * 4 + 3] = (p ushr 24).toByte()
        }
        return out
    }

    /** One GIF frame, scaled to [nw] x [nh]. */
    private fun scaleFrame(rgba: ByteArray, w: Int, h: Int, nw: Int, nh: Int): ByteArray {
        val src = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val pixels = IntArray(w * h)
        for (i in pixels.indices) {
            val r = rgba[i * 4].toInt() and 0xFF
            val g = rgba[i * 4 + 1].toInt() and 0xFF
            val b = rgba[i * 4 + 2].toInt() and 0xFF
            val a = rgba[i * 4 + 3].toInt() and 0xFF
            pixels[i] = (a shl 24) or (r shl 16) or (g shl 8) or b
        }
        src.setPixels(pixels, 0, w, 0, 0, w, h)
        val scaled = Bitmap.createScaledBitmap(src, nw, nh, true)
        val out = toRgba(scaled)
        src.recycle()
        scaled.recycle()
        return out
    }
}
