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
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

/**
 * What an outgoing photo or video becomes before it is encrypted:
 *
 * - Image, default: JPEG quality 90, upright, without metadata; an image with
 *   transparent pixels becomes lossless JPEG XL; one over the pixel cap is
 *   scaled down first. GIF becomes animated JPEG XL; animated WebP/APNG are left as
 *   they are (no frame decoder).
 * - Image, "hi-res": a JPEG goes as it is (the core strips its EXIF); any
 *   other format becomes lossless JPEG XL.
 * - A JPEG XL file goes as it is (the core strips its Exif/xml/jumb boxes).
 * - Video: MP4, 3GP and WebM are copied into a new container without
 *   metadata (location, device, dates); nothing is re-encoded.
 *
 * A JPEG/PNG/JPEG XL that cannot be decoded fails the send (the core strips one that
 * goes as it is). Any other image left as it is (HEIC that cannot be decoded,
 * animated WebP, a GIF over the caps, alpha below Android 9) and a video that
 * cannot be remuxed go out unchanged only after the user confirms.
 */
object OutgoingMedia {
    private const val TAG = "OutgoingMedia"
    private const val JPEG_QUALITY = 90
    /** Larger images are scaled down (sampled decode) to at most MAX_JXL_PIXELS. */
    private const val MAX_PIXELS = 64_000_000L
    /** Same cap as the core's `attachments::MAX_IMAGE_PIXELS`: a larger
     *  hi-res image becomes JPEG, the receiver could not open the JPEG XL. */
    private const val MAX_JXL_PIXELS = 24_000_000L
    private const val MAX_ANIM_FRAMES = 300

    class Prepared(val file: File, val fileName: String, val mimeType: String)

    /** A cleaned photo or video goes out as `image.<ext>` / `video.<ext>`:
     *  gallery and camera names carry the capture date and time the scrub
     *  just removed, and screenshots the app on screen. */
    private fun neutralName(p: Prepared, base: String): Prepared {
        val ext = p.fileName.substringAfterLast('.', "").takeIf { it.isNotEmpty() && it.length <= 8 }
        return Prepared(p.file, if (ext == null) base else "$base.$ext", p.mimeType)
    }

    /** The returned file is either [src] or a new file next to it; the caller deletes both. */
    suspend fun prepare(
        src: File, fileName: String, mimeType: String, hiRes: Boolean,
        confirmUnscrubbed: suspend () -> Boolean,
    ): Prepared {
        val unchanged = Prepared(src, fileName, mimeType)
        return try {
            when {
                // The core strips only JPEG/PNG/JPEG XL metadata: anything else left as it is asks first.
                mimeType.startsWith("image/") -> prepareImage(src, fileName, hiRes)?.let { neutralName(it, "image") }
                    ?: if (coreScrubs(src) || confirmUnscrubbed()) unchanged else throw java.util.concurrent.CancellationException("send cancelled")
                mimeType.startsWith("video/") -> remuxVideo(src, fileName, mimeType)?.let { neutralName(it, "video") }
                    ?: if (confirmUnscrubbed()) unchanged else throw java.util.concurrent.CancellationException("send cancelled")
                // m4a/ISO-BMFF audio can carry location atoms: remux without them, else ask. Other audio is untouched.
                mimeType.startsWith("audio/") ->
                    if (mediaMagic(src) == "video/mp4") {
                        remuxVideo(src, fileName, "video/mp4")?.let { Prepared(it.file, fileName, mimeType) }
                            ?: if (confirmUnscrubbed()) unchanged else throw java.util.concurrent.CancellationException("send cancelled")
                    } else unchanged
                // A mislabeled container (ISO-BMFF, Matroska, TIFF, AVI): the core
                // does not strip it, so remux it as a video or ask first.
                else -> when (val kind = mediaMagic(src)) {
                    null -> unchanged
                    else -> (if (kind.startsWith("video/")) remuxVideo(src, fileName, kind) else null)
                        ?: if (confirmUnscrubbed()) unchanged else throw java.util.concurrent.CancellationException("send cancelled")
                }
            }
        } catch (e: java.util.concurrent.CancellationException) {
            throw e
        } catch (e: Throwable) {
            Log.w(TAG, "left unchanged: ${e.message}")
            // a JPEG/PNG/JPEG XL that failed to decode goes out NOT as it is (GPS
            // in its EXIF): the caller shows the send-failed error.
            // Any other image or video goes as it is only after the user confirms.
            if (mimeType.startsWith("image/") && coreScrubs(src)) throw java.io.IOException("image scrub failed", e)
            if ((mimeType.startsWith("image/") || mimeType.startsWith("video/")) && !confirmUnscrubbed()) {
                throw java.util.concurrent.CancellationException("send cancelled")
            }
            unchanged
        }
    }

    /** #46c: "Location/device data could not be removed. Send anyway?" Cancel = nothing sent. */
    suspend fun askSendUnscrubbed(activity: android.app.Activity): Boolean =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
            kotlinx.coroutines.suspendCancellableCoroutine { cont ->
                val d = androidx.appcompat.app.AlertDialog.Builder(activity)
                    .setMessage(com.p2p.messenger.R.string.msg_media_scrub_failed)
                    .setPositiveButton(com.p2p.messenger.R.string.action_send_anyway) { _, _ -> if (cont.isActive) cont.resume(true) {} }
                    .setNegativeButton(android.R.string.cancel) { _, _ -> if (cont.isActive) cont.resume(false) {} }
                    .setOnCancelListener { if (cont.isActive) cont.resume(false) {} }
                    .show()
                cont.invokeOnCancellation { d.dismiss() }
            }
        }

    /** A saved hi-res image: the core opens a JPEG XL as PNG, so it is stored under that name and type. */
    fun savedAs(plain: File, fileName: String, mimeType: String): Pair<String, String> =
        if (fileName.endsWith(".jxl", true) && (plain.extension.equals("png", true) || plain.extension.equals("gif", true))) {
            val gif = plain.extension.equals("gif", true)
            fileName.dropLast(4) + (if (gif) ".gif" else ".png") to (if (gif) "image/gif" else "image/png")
        } else {
            fileName to mimeType
        }

    /** A received image on the clipboard: its decrypted copy. A JPEG XL is already a PNG there (see `savedAs`). The AppLock purge of `plain_cache` makes a later
     *  paste fail. */
    fun copyImage(activity: androidx.appcompat.app.AppCompatActivity, fileId: String) {
        activity.lifecycleScope.launch(kotlinx.coroutines.Dispatchers.IO) {
            val path = try {
                P2PLib.getAttachmentPlaintextPath(fileId)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            val copied = !path.startsWith("Error:") && runCatching {
                val uri = androidx.core.content.FileProvider.getUriForFile(activity, "${activity.packageName}.fileprovider", File(path))
                val clip = android.content.ClipData.newUri(activity.contentResolver, "image", uri)
                // Keyboards and the system overlay do not preview it.
                if (Build.VERSION.SDK_INT >= 33) {
                    clip.description.extras = android.os.PersistableBundle().apply {
                        putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true)
                    }
                }
                activity.getSystemService(android.content.ClipboardManager::class.java).setPrimaryClip(clip)
            }.isSuccess
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                // Android 13+ shows its own confirmation.
                if (!copied || Build.VERSION.SDK_INT < 33) {
                    android.widget.Toast.makeText(
                        activity,
                        if (copied) com.p2p.messenger.R.string.lbl_copied else com.p2p.messenger.R.string.error_attachment_open_failed,
                        android.widget.Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    private fun prepareImage(src: File, fileName: String, hiRes: Boolean): Prepared? {
        val head = ByteArray(256).also { b -> src.inputStream().use { it.read(b) } }
        // #46d: GIF -> animated JPEG XL (own decoder). Animated WebP/APNG have no frame
        // decoder on API 26+ here: they, and GIFs over the caps, go unchanged.
        // JPEG XL has no Android decoder: it goes as it is (the core strips its metadata boxes).
        if (ImagePreview.isJxl(head)) return null
        if (isGif(head)) return animatedGif(src, fileName)
        if (isAnimatedWebp(head) || isImageSequence(head) || isAnimatedPng(head, src)) return null
        if (hiRes && isJpeg(head)) return null
        // Size from the header, before a decode that could run out of memory.
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(src.absolutePath, bounds)
        val pixels = bounds.outWidth.toLong() * bounds.outHeight
        // Over the cap: sampled decode (power of 2), aspect kept.
        var sample = 1
        if (pixels > MAX_PIXELS) while (pixels / (sample.toLong() * sample) > MAX_JXL_PIXELS) sample *= 2
        @Suppress("NAME_SHADOWING")
        val hiRes = hiRes && pixels <= MAX_JXL_PIXELS
        val bitmap = decode(src, sample) ?: throw java.io.IOException("decode failed")
        try {
            val opaque = isOpaque(bitmap)
            // Below Android 9 the alpha is premultiplied: not lossless. The
            // file goes as it is (a PNG: the core drops its metadata chunks;
            // anything else: `prepare` asks first).
            if (!opaque && bitmap.isPremultiplied) return null
            val base = fileName.substringBeforeLast('.', fileName)
            return if (!hiRes && opaque) {
                val out = sibling(src)
                out.outputStream().use { bitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, it) }
                Prepared(out, "$base.jpg", "image/jpeg")
            } else {
                val argb = if (bitmap.config == Bitmap.Config.ARGB_8888) bitmap else bitmap.copy(Bitmap.Config.ARGB_8888, false)
                val out = sibling(src)
                // The core reads the pixels straight from the bitmap.
                val result = P2PLib.encodeJxlLossless(argb, !opaque, out.absolutePath)
                if (argb !== bitmap) argb.recycle()
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

    private fun animatedGif(src: File, fileName: String): Prepared? {
        val gif = GifFrames.decode(src, MAX_ANIM_FRAMES, MAX_JXL_PIXELS) ?: return null
        val out = sibling(src)
        val result = P2PLib.encodeJxlAnimated(gif.frames, gif.width, gif.height, gif.delaysMs, gif.hasAlpha, out.absolutePath)
        if (result != "OK") {
            out.delete()
            Log.w(TAG, "animated JPEG XL: $result")
            return null
        }
        return Prepared(out, fileName.substringBeforeLast('.', fileName) + ".jxl", "image/jxl")
    }

    /** Upright, not premultiplied (lossless alpha), sRGB (JPEG XL here carries no ICC profile). [sample]: 1/sample size. */
    private fun decode(src: File, sample: Int): Bitmap? =
        if (Build.VERSION.SDK_INT >= 28) {
            // Also HEIC; EXIF orientation is applied by the decoder.
            ImageDecoder.decodeBitmap(ImageDecoder.createSource(src)) { decoder, _, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                decoder.isUnpremultipliedRequired = true
                decoder.setTargetColorSpace(android.graphics.ColorSpace.get(android.graphics.ColorSpace.Named.SRGB))
                if (sample > 1) decoder.setTargetSampleSize(sample)
            }
        } else {
            // Premultiplied: the EXIF rotation draws it on a canvas.
            BitmapFactory.decodeFile(src.absolutePath, BitmapFactory.Options().apply { inSampleSize = sample })
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

    /** JPEG, PNG or JPEG XL: the core strips their metadata. */
    private fun coreScrubs(src: File): Boolean = try {
        val h = ByteArray(12)
        val n = src.inputStream().use { it.read(h) }
        n >= 4 && (isJpeg(h) || ImagePreview.isJxl(h) || (h[0] == 0x89.toByte() && h[1] == 'P'.code.toByte() && h[2] == 'N'.code.toByte() && h[3] == 'G'.code.toByte()))
    } catch (e: Exception) { false }

    /**
     * Media by content, whatever the label: "video/mp4" (ISO-BMFF video),
     * "video/webm" (EBML), "media" (HEIF/AVIF, TIFF, AVI: not remuxed here)
     * or null.
     */
    private fun mediaMagic(src: File): String? {
        val h = ByteArray(16)
        if (src.inputStream().use { it.read(h) } < 12) return null
        val s = String(h, Charsets.ISO_8859_1)
        return when {
            s.substring(4, 8) == "ftyp" ->
                if (s.substring(8, 12) in IMAGE_BRANDS) "media" else "video/mp4"
            h[0] == 0x1A.toByte() && h[1] == 0x45.toByte() && h[2] == 0xDF.toByte() && h[3] == 0xA3.toByte() -> "video/webm"
            s.startsWith("II*\u0000") || s.startsWith("MM\u0000*") -> "media"
            s.startsWith("RIFF") && s.substring(8, 12) == "AVI " -> "media"
            else -> null
        }
    }

    private val IMAGE_BRANDS = setOf("heic", "heix", "heim", "heis", "hevc", "hevx", "mif1", "msf1", "avif", "avis")

    private fun isJpeg(h: ByteArray) = h[0] == 0xFF.toByte() && h[1] == 0xD8.toByte() && h[2] == 0xFF.toByte()

    private fun isGif(h: ByteArray) = String(h, 0, 4, Charsets.ISO_8859_1) == "GIF8"

    /** RIFF....WEBPVP8X with the animation flag. */
    private fun isAnimatedWebp(h: ByteArray) =
        String(h, 0, 4, Charsets.ISO_8859_1) == "RIFF" && String(h, 8, 8, Charsets.ISO_8859_1) == "WEBPVP8X" &&
            (h[20].toInt() and 0x02) != 0

    /** HEIF/AVIF image sequence: an `ftyp` brand msf1, hevs or avis. */
    private fun isImageSequence(h: ByteArray): Boolean {
        if (String(h, 4, 4, Charsets.ISO_8859_1) != "ftyp") return false
        val size = ByteBuffer.wrap(h, 0, 4).int.coerceIn(8, h.size)
        return (8..size - 4 step 4).any { String(h, it, 4, Charsets.ISO_8859_1) in SEQUENCE_BRANDS }
    }

    private val SEQUENCE_BRANDS = setOf("msf1", "hevs", "avis")

    /** APNG: an `acTL` chunk before the first `IDAT`. */
    private fun isAnimatedPng(h: ByteArray, src: File): Boolean {
        if (String(h, 1, 3, Charsets.ISO_8859_1) != "PNG") return false
        java.io.RandomAccessFile(src, "r").use { f ->
            var pos = 8L
            while (pos + 8 <= f.length()) {
                f.seek(pos)
                val length = f.readInt().toLong() and 0xFFFFFFFFL
                when (ByteArray(4).also { f.readFully(it) }.toString(Charsets.ISO_8859_1)) {
                    "acTL" -> return true
                    "IDAT", "IEND" -> return false
                }
                pos += 12 + length
            }
        }
        return false
    }

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
                            f.seek(pos + 4)
                            f.write("free".toByteArray(Charsets.ISO_8859_1))
                            f.seek(pos + header)
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
            // An iPhone .mov (its GPS in a ©xyz atom): same codecs, MP4 box.
            "video/quicktime" -> MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4
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
            // An MP4 box under another name (a .mov the provider called
            // video/mp4, or video/quicktime) is named for what it now is.
            val ext = fileName.substringAfterLast('.', "").lowercase()
            if (container == MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4 && ext != "mp4" && ext != "m4v") {
                return Prepared(out, fileName.substringBeforeLast('.', fileName) + ".mp4", "video/mp4")
            }
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
