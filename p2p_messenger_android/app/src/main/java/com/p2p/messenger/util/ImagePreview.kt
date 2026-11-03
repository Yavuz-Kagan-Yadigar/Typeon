package com.p2p.messenger.util

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.p2p.messenger.P2PLib
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * Spec dışı: görsel küçültme/sıkıştırma — hem sohbet eki önizlemeleri
 * (480p/%85, bkz. ChatActivity) hem de profil fotoğrafları (720p/%85, bkz.
 * SettingsFragment) AYNI mantığı kullanır, sadece hedef boyut farklı.
 * Önceden bu mantık ChatActivity içinde private/tek kullanım yerine özeldi
 * — profil fotoğrafı eklenirken buraya taşındı.
 */
object ImagePreview {
    /** Büyük görselleri TAM çözünürlükte belleğe yüklememek için önce
     *  sınırları (`inJustDecodeBounds`) okuyup uygun bir `inSampleSize`
     *  hesaplar, sonra `compressBitmap` ile tam hassas boyuta iner. */
    fun compressFile(file: File, maxDimension: Int, quality: Int): ByteArray? {
        if (isJxl(file)) {
            // BitmapFactory cannot read JPEG XL: its first frame as a temp GIF.
            val tmp = File(file.parentFile, "${file.name}.${System.nanoTime()}.tmp")
            return try {
                if (P2PLib.jxlToGif(file.absolutePath, tmp.absolutePath) == "OK") compressDecoded(tmp, maxDimension, quality) else null
            } catch (e: Throwable) {
                null
            } finally {
                tmp.delete()
            }
        }
        return compressDecoded(file, maxDimension, quality)
    }

    /** JPEG XL: bare codestream (FF 0A) or ISO container signature. */
    fun isJxl(h: ByteArray): Boolean =
        (h.size >= 2 && h[0] == 0xFF.toByte() && h[1] == 0x0A.toByte()) ||
            (h.size >= 12 && h.copyOf(12).contentEquals(JXL_CONTAINER))

    fun isJxl(file: File): Boolean = try {
        val h = ByteArray(12)
        val n = file.inputStream().use { it.read(h) }
        isJxl(h.copyOf(maxOf(n, 0)))
    } catch (e: Exception) { false }

    private val JXL_CONTAINER = byteArrayOf(0, 0, 0, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87.toByte(), 0x0A)

    private fun compressDecoded(file: File, maxDimension: Int, quality: Int): ByteArray? {
        val boundsOptions = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, boundsOptions)
        if (boundsOptions.outWidth <= 0 || boundsOptions.outHeight <= 0) return null

        val decodeOptions = BitmapFactory.Options().apply {
            inSampleSize = sampleSizeFor(boundsOptions.outWidth, boundsOptions.outHeight, maxDimension)
        }
        val sampled = try {
            BitmapFactory.decodeFile(file.absolutePath, decodeOptions)
        } catch (e: OutOfMemoryError) {
            null
        } ?: return null
        return compressBitmap(applyExifOrientation(sampled, file), maxDimension, quality)
    }

    /** Largest power of two that keeps the LONG edge at or above
     *  `maxDimension`. With `&&` a panorama or a long screenshot was never
     *  sampled down and decoded at full size. */
    fun sampleSizeFor(width: Int, height: Int, maxDimension: Int): Int {
        var sampleSize = 1
        while (maxOf(width, height) / (sampleSize * 2) >= maxDimension) sampleSize *= 2
        return sampleSize
    }

    /** Decodes untrusted image bytes (a contact's avatar, an attachment
     *  preview) without ever allocating the full-resolution bitmap: a 25 KB
     *  palette PNG can declare 16000x12000 pixels. */
    fun decodeBytes(bytes: ByteArray, maxDimension: Int): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        val options = BitmapFactory.Options().apply {
            inSampleSize = sampleSizeFor(bounds.outWidth, bounds.outHeight, maxDimension)
        }
        return try {
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
        } catch (e: Throwable) {
            null
        }
    }

    /** Cameras store the rotation in EXIF instead of rotating the pixels. */
    private fun applyExifOrientation(bitmap: Bitmap, file: File): Bitmap =
        try {
            rotateForExif(bitmap, android.media.ExifInterface(file.absolutePath))
        } catch (e: Exception) {
            bitmap
        }

    fun rotateForExif(bitmap: Bitmap, exif: android.media.ExifInterface): Bitmap {
        val matrix = android.graphics.Matrix()
        when (exif.getAttributeInt(android.media.ExifInterface.TAG_ORIENTATION, 0)) {
            android.media.ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> matrix.setScale(-1f, 1f)
            android.media.ExifInterface.ORIENTATION_ROTATE_180 -> matrix.setRotate(180f)
            android.media.ExifInterface.ORIENTATION_FLIP_VERTICAL -> matrix.setScale(1f, -1f)
            android.media.ExifInterface.ORIENTATION_TRANSPOSE -> matrix.apply { setRotate(90f); postScale(-1f, 1f) }
            android.media.ExifInterface.ORIENTATION_ROTATE_90 -> matrix.setRotate(90f)
            android.media.ExifInterface.ORIENTATION_TRANSVERSE -> matrix.apply { setRotate(-90f); postScale(-1f, 1f) }
            android.media.ExifInterface.ORIENTATION_ROTATE_270 -> matrix.setRotate(270f)
            else -> return bitmap
        }
        val rotated = Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
        if (rotated !== bitmap) bitmap.recycle()
        return rotated
    }

    /** En uzun kenarı `maxDimension`'a sığdırır (en-boy oranı KORUNUR —
     *  kullanıcı isteği: küçük resimler kare olsun ama gerçek görselin
     *  oranı bozulmasın, kare kırpma sadece bindAttachment'taki
     *  ImageView'ın `centerCrop` scaleType'ıyla GÖRSEL olarak yapılır, bu
     *  fonksiyon kaynağı hiç kırpmaz), sonra JPEG'e sıkıştırır. */
    fun compressBitmap(bitmap: Bitmap, maxDimension: Int, quality: Int): ByteArray {
        val longEdge = maxOf(bitmap.width, bitmap.height)
        val scaled = if (longEdge > maxDimension) {
            val scale = maxDimension.toFloat() / longEdge
            val scaledBitmap = Bitmap.createScaledBitmap(
                bitmap, (bitmap.width * scale).toInt().coerceAtLeast(1),
                (bitmap.height * scale).toInt().coerceAtLeast(1), true
            )
            if (scaledBitmap !== bitmap) bitmap.recycle()
            scaledBitmap
        } else {
            bitmap
        }
        val out = ByteArrayOutputStream()
        scaled.compress(Bitmap.CompressFormat.JPEG, quality, out)
        scaled.recycle()
        return out.toByteArray()
    }
}
