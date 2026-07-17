package com.p2p.messenger.util

import android.graphics.Bitmap
import android.graphics.BitmapFactory
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
        val boundsOptions = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, boundsOptions)
        if (boundsOptions.outWidth <= 0 || boundsOptions.outHeight <= 0) return null

        var sampleSize = 1
        while (boundsOptions.outWidth / (sampleSize * 2) >= maxDimension &&
            boundsOptions.outHeight / (sampleSize * 2) >= maxDimension) {
            sampleSize *= 2
        }
        val decodeOptions = BitmapFactory.Options().apply { inSampleSize = sampleSize }
        val sampled = BitmapFactory.decodeFile(file.absolutePath, decodeOptions) ?: return null
        return compressBitmap(sampled, maxDimension, quality)
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
