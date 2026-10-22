package com.p2p.messenger.util

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.os.Build
import com.p2p.messenger.P2PLib
import java.io.File
import kotlin.math.max
import kotlin.math.roundToInt

/**
 * Bir görsel dosyasını çıkartmaya (sticker) çevirir.
 *
 * GIF'ler kendi kodlayıcımızla (bkz. `GifFrames`) kare kare çözülür; diğer
 * formatlar (PNG/JPEG/WebP) TEK kare olarak alınır.
 * ponytail: animasyonlu bir WebP'nin kareleri çıkarılmaz — `ImageDecoder`
 * kare vermez, yalnızca bir `Drawable` (ilk kare yeterli).
 *
 * Sonuç: çıkartma id'si, ya da "Error: ...".
 */
object StickerImport {
    /** The core's own cap (attachments::STICKER_MAX_SIDE). */
    const val MAX_SIDE = 600
    /** attachments::MAX_ANIMATION_FRAMES. */
    const val MAX_FRAMES = 300
    /** attachments::MAX_IMAGE_PIXELS — the core refuses more (all frames). */
    private const val MAX_PIXELS = 24_000_000L

    /** [file] is a GIF, PNG, JPEG or WebP. Returns the sticker id or "Error: ...". */
    fun importFile(file: File): String {
        if (!file.exists() || file.length() == 0L) return "Error: dosya okunamadı"
        val head = ByteArray(4)
        var read = 0
        try {
            file.inputStream().use { s ->
                while (read < 4) {
                    val n = s.read(head, read, 4 - read)
                    if (n <= 0) break
                    read += n
                }
            }
        } catch (e: Exception) {
            return "Error: ${e.message}"
        }
        return if (String(head, 0, read, Charsets.ISO_8859_1) == "GIF8") importGif(file) else importStill(file)
    }

    /** A still picture: one frame, no delay. */
    private fun importStill(file: File): String {
        val bitmap = fit(decodeStill(file)) ?: return "Error: görsel çözülemedi"
        try {
            return P2PLib.importStickerFrames(
                arrayOf(toRgba(bitmap)), bitmap.width, bitmap.height, intArrayOf(0)
            )
        } finally {
            bitmap.recycle()
        }
    }

    /** An animated picture: the GIF frames, scaled to the sticker's cap. */
    private fun importGif(file: File): String {
        // A still GIF (or one over the caps) goes the normal way: its first
        // frame as a still sticker.
        val gif = GifFrames.decode(file, MAX_FRAMES, MAX_PIXELS) ?: return importStill(file)
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
            frames.copyOfRange(0, count), w, h, gif.delaysMs.copyOfRange(0, count)
        )
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
