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

    /**
     * Spec dışı, performans denetimi düzeltmesi: `renderInto` — dolayısıyla
     * `decodeCircularSquare` (BitmapFactory decode + kare kırpma + ölçekleme
     * + daire maskeleme) — her `RecyclerView.onBindViewHolder`'da (sohbet
     * listesi, kişi listesi, HER mesaj balonu) sıfırdan çalışıyordu; aynı
     * kişinin/grubun avatarı bir liste kaydırılırken defalarca yeniden
     * çözülüyordu, gözle görülür kasılmaya (jank) yol açabiliyordu. Basit
     * bir bellek-içi önbellek — anahtar olarak baytların 64 bitlik parmak
     * izi (contentHashCode + bağımsız FNV-1a geçişi; salt 32 bitlik hash'te
     * kişi taraflı bir JPEG başka bir kişinin girdisiyle çakışıp YANLIŞ
     * yüzü gösterebiliyordu) — aynı fotoğrafı tekrar tekrar decode
     * etmeyi önler. `LruCache`
     * dahili olarak senkronize, birden fazla RecyclerView/thread'den
     * güvenle çağrılabilir. 100 giriş × ~36 KB (96x96 ARGB_8888) ≈ 3.6 MB
     * üst sınır — makul bir bellek/performans dengesi.
     */
    // H138: the letter placeholder was drawn anew on every bind.
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

    /** `avatarBytes` doluysa gerçek fotoğraf (kare kırpılıp daireye
     *  maskelenir) gösterilir, yoksa `displayName`'in baş harfinden
     *  deterministik renkli bir rozet üretilir. */
    fun renderInto(imageView: ImageView, avatarBytes: ByteArray?, displayName: String) {
        val bitmap = avatarBytes?.let { bytes ->
            val key = cacheKey(bytes)
            // A failed decode is cached too (as the placeholder), so a bad image is not re-decoded on every bind.
            avatarBitmapCache.get(key) ?: (decodeCircularSquare(bytes) ?: placeholderCircle(displayName)).also { avatarBitmapCache.put(key, it) }
        } ?: placeholderCache.get(displayName) ?: placeholderCircle(displayName).also { placeholderCache.put(displayName, it) }
        imageView.setImageBitmap(bitmap)
    }

    /**
     * Spec dışı, kullanıcı isteği: profil fotoğrafına dokununca tam ekran +
     * pinch-to-zoom açar (bkz. MediaViewerActivity.setupZoomableImage — tek
     * dokunuşla kapatma da orada uygulanıyor). `renderInto`'nun aksine burada
     * `avatarBytes` KIRPILMADAN/küçültülmeden (96x96 önizlemenin tersine)
     * ham/orijinal çözünürlükte gösterilir. Fotoğraf yoksa (ör. sadece baş
     * harf rozeti gösteriliyorsa) hiçbir şey yapmaz.
     */
    fun openFullscreen(context: Context, avatarBytes: ByteArray?) {
        if (avatarBytes == null || avatarBytes.isEmpty()) return
        try {
            val dir = File(context.cacheDir, "avatar_view").apply { mkdirs() }
            // Spec dışı, güvenlik/depolama denetimi düzeltmesi: her tıklama
            // burada yeni bir plaintext JPEG dosyası yazıyordu ama HİÇBİRİ
            // silinmiyordu (uygulamadaki diğer TÜM geçici dosya yollarının
            // aksine — bkz. ChatActivity/SettingsFragment/GroupChatActivity
            // `tempFile.delete()` deseni). Profil fotoğrafları tekrar tekrar
            // görüntülendikçe uygulama önbelleğinde sınırsız sayıda
            // şifrelenmemiş yüz fotoğrafı birikiyordu — `allowBackup=false`
            // bulut sızıntısını engelliyor ama yerel dosya erişimi olan
            // herhangi bir şeye (root, USB hata ayıklamalı ADB, adli analiz)
            // gereğinden çok daha uzun süre açık kalıyordu. `MediaViewerActivity`
            // dosyayı hâlâ görüntülüyor olabileceğinden YENİ dosyayı yazmadan
            // önce TÜMÜNÜ silmek riskli (o an açık bir görüntüleyiciyi
            // bozabilir) — bunun yerine makul bir saklama süresini (10 dk)
            // aşan ESKİ dosyaları buduyoruz, bu da sınırsız birikmeyi önler.
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
            // Sessizce yok say — profil fotoğrafı önizlemesi zaten görünür,
            // tam ekran sadece bir kolaylık.
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
