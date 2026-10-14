package com.p2p.messenger.util

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMuxer
import android.os.Build
import android.util.Log
import com.p2p.messenger.P2PLib
import java.io.File
import java.nio.ByteBuffer
import java.util.UUID

/**
 * What an outgoing photo or video becomes before it is encrypted:
 *
 * - Image, default: JPEG quality 90 at full resolution, upright, without
 *   metadata. Left as it is: GIF and animated WebP (the animation would be
 *   lost) and images with transparent pixels.
 * - Image, "hi-res": a JPEG goes as it is (the core strips its EXIF); any
 *   other format becomes lossless JPEG XL.
 * - Video: MP4, 3GP and WebM are copied into a new container without
 *   metadata (location, device, dates); nothing is re-encoded.
 *
 * Anything that cannot be decoded or remuxed goes out unchanged.
 */
object OutgoingMedia {
    private const val TAG = "OutgoingMedia"
    private const val JPEG_QUALITY = 90
    /** Same cap as the core's `attachments::MAX_IMAGE_PIXELS`. */
    private const val MAX_PIXELS = 64_000_000L

    class Prepared(val file: File, val fileName: String, val mimeType: String)

    /** The returned file is either [src] or a new file next to it; the caller deletes both. */
    fun prepare(src: File, fileName: String, mimeType: String, hiRes: Boolean): Prepared {
        val unchanged = Prepared(src, fileName, mimeType)
        return try {
            when {
                mimeType.startsWith("image/") -> prepareImage(src, fileName, hiRes) ?: unchanged
                mimeType.startsWith("video/") -> remuxVideo(src, fileName, mimeType) ?: unchanged
                else -> unchanged
            }
        } catch (e: Throwable) {
            // OutOfMemoryError included: a huge image goes out as it is.
            Log.w(TAG, "left unchanged: ${e.message}")
            unchanged
        }
    }

    /** A saved hi-res image: the core opens a JPEG XL as PNG, so it is stored under that name and type. */
    fun savedAs(plain: File, fileName: String, mimeType: String): Pair<String, String> =
        if (plain.extension.equals("png", true) && fileName.endsWith(".jxl", true)) {
            fileName.dropLast(4) + ".png" to "image/png"
        } else {
            fileName to mimeType
        }

    private fun prepareImage(src: File, fileName: String, hiRes: Boolean): Prepared? {
        val head = ByteArray(32).also { b -> src.inputStream().use { it.read(b) } }
        if (isGif(head) || isAnimatedWebp(head)) return null
        if (hiRes && isJpeg(head)) return null
        val bitmap = decode(src, srgb = hiRes) ?: return null
        try {
            if (bitmap.width.toLong() * bitmap.height > MAX_PIXELS) return null
            val opaque = isOpaque(bitmap)
            val base = fileName.substringBeforeLast('.', fileName)
            return if (!hiRes) {
                if (!opaque) return null
                val out = sibling(src)
                out.outputStream().use { bitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, it) }
                Prepared(out, "$base.jpg", "image/jpeg")
            } else {
                val argb = if (bitmap.config == Bitmap.Config.ARGB_8888) bitmap else bitmap.copy(Bitmap.Config.ARGB_8888, false)
                // Native memory: a 48 MP photo is ~190 MB of pixels.
                val pixels = ByteBuffer.allocateDirect(argb.width * argb.height * 4)
                argb.copyPixelsToBuffer(pixels)
                val (w, h) = argb.width to argb.height
                if (argb !== bitmap) argb.recycle()
                val out = sibling(src)
                val result = P2PLib.encodeJxlLossless(pixels, w, h, !opaque, out.absolutePath)
                if (result != "OK") {
                    out.delete()
                    Log.w(TAG, "JPEG XL: $result")
                    return null
                }
                Prepared(out, "$base.jxl", "image/jxl")
            }
        } finally {
            bitmap.recycle()
        }
    }

    /** Upright, not premultiplied (lossless alpha). [srgb]: JPEG XL here carries no ICC profile. */
    private fun decode(src: File, srgb: Boolean): Bitmap? =
        if (Build.VERSION.SDK_INT >= 28) {
            // Also HEIC; EXIF orientation is applied by the decoder.
            ImageDecoder.decodeBitmap(ImageDecoder.createSource(src)) { decoder, _, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                decoder.isUnpremultipliedRequired = true
                if (srgb) decoder.setTargetColorSpace(android.graphics.ColorSpace.get(android.graphics.ColorSpace.Named.SRGB))
            }
        } else {
            BitmapFactory.decodeFile(src.absolutePath, BitmapFactory.Options().apply { inPremultiplied = false })
                ?.let { ImagePreview.rotateForExif(it, android.media.ExifInterface(src.absolutePath)) }
        }

    private fun isOpaque(bitmap: Bitmap): Boolean {
        if (!bitmap.hasAlpha()) return true
        val row = IntArray(bitmap.width)
        for (y in 0 until bitmap.height) {
            bitmap.getPixels(row, 0, bitmap.width, 0, y, bitmap.width, 1)
            for (p in row) if (p ushr 24 != 0xFF) return false
        }
        return true
    }

    private fun isJpeg(h: ByteArray) = h[0] == 0xFF.toByte() && h[1] == 0xD8.toByte() && h[2] == 0xFF.toByte()

    private fun isGif(h: ByteArray) = String(h, 0, 4, Charsets.ISO_8859_1) == "GIF8"

    /** RIFF....WEBPVP8X with the animation flag. */
    private fun isAnimatedWebp(h: ByteArray) =
        String(h, 0, 4, Charsets.ISO_8859_1) == "RIFF" && String(h, 8, 8, Charsets.ISO_8859_1) == "WEBPVP8X" &&
            (h[20].toInt() and 0x02) != 0

    private fun sibling(src: File) = File(src.parentFile, UUID.randomUUID().toString())

    /**
     * MediaMuxer writes its own metadata: the device maker and model, the
     * Android version (`moov/meta`) and the mux time. In place, so no chunk
     * offset moves: a `udta`/`meta` box becomes a zeroed `free` box of the same
     * size, and the creation/modification times of `mvhd`/`tkhd`/`mdhd` become 0.
     */
    private fun scrubMp4(file: File) {
        java.io.RandomAccessFile(file, "rw").use { f ->
            fun walk(start: Long, end: Long) {
                var pos = start
                while (pos + 8 <= end) {
                    f.seek(pos)
                    var size = f.readInt().toLong() and 0xFFFFFFFFL
                    val type = ByteArray(4).also { f.readFully(it) }.toString(Charsets.ISO_8859_1)
                    var header = 8L
                    if (size == 1L) { size = f.readLong(); header = 16 }
                    if (size == 0L) size = end - pos
                    if (size < header || pos + size > end) return
                    when (type) {
                        "moov", "trak", "mdia" -> walk(pos + header, pos + size)
                        "udta", "meta" -> {
                            f.seek(pos + header - 4)
                            f.write("free".toByteArray(Charsets.ISO_8859_1))
                            f.write(ByteArray((size - header).toInt()))
                        }
                        "mvhd", "tkhd", "mdhd" -> {
                            f.seek(pos + header)
                            val version = f.read()
                            f.seek(pos + header + 4)
                            f.write(ByteArray(if (version == 1) 16 else 8))
                        }
                    }
                    pos += size
                }
            }
            walk(0, f.length())
        }
    }

    /** A copy of the audio and video tracks in a new container: no metadata, same bytes of media. */
    private fun remuxVideo(src: File, fileName: String, mimeType: String): Prepared? {
        val container = when (mimeType) {
            "video/mp4" -> MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4
            "video/3gpp" -> MediaMuxer.OutputFormat.MUXER_OUTPUT_3GPP
            "video/webm" -> MediaMuxer.OutputFormat.MUXER_OUTPUT_WEBM
            else -> return null
        }
        val out = sibling(src)
        val extractor = MediaExtractor()
        var muxer: MediaMuxer? = null
        try {
            extractor.setDataSource(src.absolutePath)
            val m = MediaMuxer(out.absolutePath, container).also { muxer = it }
            val tracks = IntArray(extractor.trackCount) { -1 }
            var maxSample = 1 shl 20
            for (i in 0 until extractor.trackCount) {
                val format = extractor.getTrackFormat(i)
                val mime = format.getString(MediaFormat.KEY_MIME) ?: continue
                // Only media: a vendor data track (gyro, motion photo) stays behind.
                if (!mime.startsWith("video/") && !mime.startsWith("audio/")) continue
                if (format.containsKey(MediaFormat.KEY_MAX_INPUT_SIZE)) {
                    maxSample = maxOf(maxSample, format.getInteger(MediaFormat.KEY_MAX_INPUT_SIZE))
                }
                if (mime.startsWith("video/") && format.containsKey(MediaFormat.KEY_ROTATION)) {
                    m.setOrientationHint(format.getInteger(MediaFormat.KEY_ROTATION))
                }
                tracks[i] = m.addTrack(format)
                extractor.selectTrack(i)
            }
            if (tracks.all { it < 0 }) return null.also { out.delete() }
            m.start()
            val buffer = ByteBuffer.allocateDirect(maxSample)
            val info = MediaCodec.BufferInfo()
            while (true) {
                val size = extractor.readSampleData(buffer, 0)
                if (size < 0) break
                val track = tracks[extractor.sampleTrackIndex]
                if (track >= 0) {
                    val key = (extractor.sampleFlags and MediaExtractor.SAMPLE_FLAG_SYNC) != 0
                    info.set(0, size, extractor.sampleTime, if (key) MediaCodec.BUFFER_FLAG_KEY_FRAME else 0)
                    m.writeSampleData(track, buffer, info)
                }
                extractor.advance()
            }
            m.stop()
            m.release()
            muxer = null
            if (container != MediaMuxer.OutputFormat.MUXER_OUTPUT_WEBM) scrubMp4(out)
            return Prepared(out, fileName, mimeType)
        } catch (e: Exception) {
            Log.w(TAG, "video left unchanged: ${e.message}")
            out.delete()
            return null
        } finally {
            extractor.release()
            try { muxer?.release() } catch (_: Exception) {}
        }
    }
}
