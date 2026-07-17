package com.p2p.messenger.util

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

/**
 * Spec dışı: profil fotoğrafı gösterimi (sohbet listesi + grup balonları).
 * Proje içinde Glide/Coil gibi bir görsel kütüphane yok — bu yüzden hem
 * gerçek fotoğrafın (her zaman ORTADAN kare kırpılıp daireye maskelenir,
 * kullanıcının "önizlemeler kare olsun" isteğiyle tutarlı) hem de fotoğrafı
 * olmayan kişiler için renkli baş harf rozetinin çizimi elle yapılıyor.
 */
object AvatarUtil {
    private const val SIZE_PX = 96

    private val PALETTE = intArrayOf(
        0xFFEF5350.toInt(), 0xFFAB47BC.toInt(), 0xFF5C6BC0.toInt(), 0xFF29B6F6.toInt(),
        0xFF26A69A.toInt(), 0xFF9CCC65.toInt(), 0xFFFFCA28.toInt(), 0xFFFF7043.toInt()
    )

    /** `avatarBytes` doluysa gerçek fotoğraf (kare kırpılıp daireye
     *  maskelenir) gösterilir, yoksa `displayName`'in baş harfinden
     *  deterministik renkli bir rozet üretilir. */
    fun renderInto(imageView: ImageView, avatarBytes: ByteArray?, displayName: String) {
        val bitmap = avatarBytes?.let { decodeCircularSquare(it) } ?: placeholderCircle(displayName)
        imageView.setImageBitmap(bitmap)
    }

    private fun decodeCircularSquare(bytes: ByteArray): Bitmap? {
        val raw = try {
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        } catch (e: Exception) {
            null
        } ?: return null
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
        val initial = displayName.trim().firstOrNull()?.uppercaseChar()?.toString() ?: "?"
        val bgColor = PALETTE[Math.abs(displayName.hashCode()) % PALETTE.size]
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
