package com.p2p.messenger.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import kotlin.math.abs
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * Spec dışı, kullanıcı isteği ("anlık çekim ve crop ile gönderilsin"):
 * çekilen fotoğrafı gösterip üzerinde sürüklenebilir/yeniden
 * boyutlandırılabilir bir kırpma dörtgeni çizen küçük görünüm.
 *
 * Neden hazır bir kırpma kütüphanesi (uCrop, Android-Image-Cropper) değil:
 * bu proje, kilitli/çevrimdışı derlenebilirliği bilerek koruyor ve yeni bir
 * üçüncü taraf bağımlılığı eklemek gradle senkronu gerektirir (bkz.
 * P2PApplication'daki `lifecycle-process` notu, AYNI gerekçe). İhtiyaç
 * duyulan davranış — dört köşeden tut/yeniden boyutlandır, içeriden tut/
 * kaydır, 90° döndür — tek bir `View` içinde zaten karşılanabiliyor.
 *
 * Bitmap HİÇ diske yazılmaz; kırpma da `Bitmap.createBitmap` ile bellekte
 * yapılır (bkz. CameraCaptureActivity).
 */
class CropOverlayView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    private var bitmap: Bitmap? = null

    /** Bitmap'in ekranda çizildiği (en-boy oranı korunarak sığdırılmış) alan. */
    private val imageRect = RectF()

    /** Kırpma dörtgeni — HER ZAMAN `imageRect` içinde kalır. */
    private val cropRect = RectF()

    private val density = resources.displayMetrics.density
    private val touchSlop = 28f * density
    private val minCropSize = 56f * density

    private val bitmapPaint = Paint(Paint.FILTER_BITMAP_FLAG or Paint.ANTI_ALIAS_FLAG)
    private val dimPaint = Paint().apply { color = 0xB4000000.toInt() }
    private val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = Color.WHITE
        strokeWidth = 1.5f * density
    }
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = 0x66FFFFFF
        strokeWidth = 1f * density
    }
    private val handlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        color = Color.WHITE
        strokeWidth = 3.5f * density
    }

    private var activeHandle = HANDLE_NONE
    private var lastTouchX = 0f
    private var lastTouchY = 0f

    fun setBitmap(newBitmap: Bitmap?) {
        bitmap = newBitmap
        recomputeRects(resetCrop = true)
        invalidate()
    }

    /** Kullanıcı isteğiyle 90° saat yönünde döndürür — kırpma dörtgeni
     *  sıfırlanır (döndürülmüş görüntüde eski dörtgenin bir karşılığı yok). */
    fun rotate90() {
        val source = bitmap ?: return
        val matrix = Matrix().apply { postRotate(90f) }
        val rotated = try {
            Bitmap.createBitmap(source, 0, 0, source.width, source.height, matrix, true)
        } catch (e: OutOfMemoryError) {
            return
        }
        if (rotated !== source) source.recycle()
        setBitmap(rotated)
    }

    /** Kırpılmış kopyayı üretir. Kırpma dörtgeni hiç oynatılmamışsa TÜM
     *  görüntüyü döndürür (yani "kırpmadan gönder" ayrı bir kod yolu
     *  gerektirmez). */
    fun buildCroppedBitmap(): Bitmap? {
        val source = bitmap ?: return null
        if (imageRect.width() <= 0f || imageRect.height() <= 0f) return source
        val scaleX = source.width / imageRect.width()
        val scaleY = source.height / imageRect.height()
        val left = ((cropRect.left - imageRect.left) * scaleX).roundToInt().coerceIn(0, source.width - 1)
        val top = ((cropRect.top - imageRect.top) * scaleY).roundToInt().coerceIn(0, source.height - 1)
        val right = ((cropRect.right - imageRect.left) * scaleX).roundToInt().coerceIn(left + 1, source.width)
        val bottom = ((cropRect.bottom - imageRect.top) * scaleY).roundToInt().coerceIn(top + 1, source.height)
        return try {
            Bitmap.createBitmap(source, left, top, right - left, bottom - top)
        } catch (e: Exception) {
            source
        }
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        recomputeRects(resetCrop = true)
    }

    private fun recomputeRects(resetCrop: Boolean) {
        val source = bitmap ?: return
        if (width == 0 || height == 0 || source.width == 0 || source.height == 0) return
        val scale = min(width.toFloat() / source.width, height.toFloat() / source.height)
        val drawWidth = source.width * scale
        val drawHeight = source.height * scale
        val left = (width - drawWidth) / 2f
        val top = (height - drawHeight) / 2f
        imageRect.set(left, top, left + drawWidth, top + drawHeight)
        if (resetCrop) cropRect.set(imageRect)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val source = bitmap ?: return
        canvas.drawBitmap(source, null, imageRect, bitmapPaint)

        // Kırpma dışında kalan her şey karartılır (dört dikdörtgen — tek bir
        // `Path` + EVEN_ODD'dan daha ucuz ve donanım hızlandırmada güvenli).
        canvas.drawRect(0f, 0f, width.toFloat(), cropRect.top, dimPaint)
        canvas.drawRect(0f, cropRect.bottom, width.toFloat(), height.toFloat(), dimPaint)
        canvas.drawRect(0f, cropRect.top, cropRect.left, cropRect.bottom, dimPaint)
        canvas.drawRect(cropRect.right, cropRect.top, width.toFloat(), cropRect.bottom, dimPaint)

        canvas.drawRect(cropRect, borderPaint)
        val thirdW = cropRect.width() / 3f
        val thirdH = cropRect.height() / 3f
        for (i in 1..2) {
            canvas.drawLine(cropRect.left + thirdW * i, cropRect.top, cropRect.left + thirdW * i, cropRect.bottom, gridPaint)
            canvas.drawLine(cropRect.left, cropRect.top + thirdH * i, cropRect.right, cropRect.top + thirdH * i, gridPaint)
        }

        val armLength = min(24f * density, min(cropRect.width(), cropRect.height()) / 3f)
        drawCorner(canvas, cropRect.left, cropRect.top, armLength, armLength)
        drawCorner(canvas, cropRect.right, cropRect.top, -armLength, armLength)
        drawCorner(canvas, cropRect.left, cropRect.bottom, armLength, -armLength)
        drawCorner(canvas, cropRect.right, cropRect.bottom, -armLength, -armLength)
    }

    private fun drawCorner(canvas: Canvas, x: Float, y: Float, dx: Float, dy: Float) {
        canvas.drawLine(x, y, x + dx, y, handlePaint)
        canvas.drawLine(x, y, x, y + dy, handlePaint)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (bitmap == null) return false
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                activeHandle = pickHandle(event.x, event.y)
                lastTouchX = event.x
                lastTouchY = event.y
                // Kırpma alanının DIŞINA basıldığında olayı tüketmiyoruz ki
                // altındaki düzen (ör. kaydırma) normal davranabilsin.
                return activeHandle != HANDLE_NONE
            }
            MotionEvent.ACTION_MOVE -> {
                if (activeHandle == HANDLE_NONE) return false
                applyDrag(event.x - lastTouchX, event.y - lastTouchY)
                lastTouchX = event.x
                lastTouchY = event.y
                invalidate()
                return true
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                activeHandle = HANDLE_NONE
                return true
            }
        }
        return false
    }

    private fun pickHandle(x: Float, y: Float): Int {
        val nearLeft = abs(x - cropRect.left) <= touchSlop
        val nearRight = abs(x - cropRect.right) <= touchSlop
        val nearTop = abs(y - cropRect.top) <= touchSlop
        val nearBottom = abs(y - cropRect.bottom) <= touchSlop
        val withinY = y >= cropRect.top - touchSlop && y <= cropRect.bottom + touchSlop
        val withinX = x >= cropRect.left - touchSlop && x <= cropRect.right + touchSlop
        return when {
            nearLeft && nearTop -> HANDLE_TOP_LEFT
            nearRight && nearTop -> HANDLE_TOP_RIGHT
            nearLeft && nearBottom -> HANDLE_BOTTOM_LEFT
            nearRight && nearBottom -> HANDLE_BOTTOM_RIGHT
            nearLeft && withinY -> HANDLE_LEFT
            nearRight && withinY -> HANDLE_RIGHT
            nearTop && withinX -> HANDLE_TOP
            nearBottom && withinX -> HANDLE_BOTTOM
            cropRect.contains(x, y) -> HANDLE_MOVE
            else -> HANDLE_NONE
        }
    }

    private fun applyDrag(dx: Float, dy: Float) {
        if (activeHandle == HANDLE_MOVE) {
            val clampedDx = dx.coerceIn(imageRect.left - cropRect.left, imageRect.right - cropRect.right)
            val clampedDy = dy.coerceIn(imageRect.top - cropRect.top, imageRect.bottom - cropRect.bottom)
            cropRect.offset(clampedDx, clampedDy)
            return
        }
        if (activeHandle and EDGE_LEFT != 0) {
            cropRect.left = (cropRect.left + dx).coerceIn(imageRect.left, cropRect.right - minCropSize)
        }
        if (activeHandle and EDGE_RIGHT != 0) {
            cropRect.right = (cropRect.right + dx).coerceIn(cropRect.left + minCropSize, imageRect.right)
        }
        if (activeHandle and EDGE_TOP != 0) {
            cropRect.top = (cropRect.top + dy).coerceIn(imageRect.top, cropRect.bottom - minCropSize)
        }
        if (activeHandle and EDGE_BOTTOM != 0) {
            cropRect.bottom = (cropRect.bottom + dy).coerceIn(cropRect.top + minCropSize, imageRect.bottom)
        }
    }

    private companion object {
        // Kenarlar bit maskesi: bir köşe, iki kenarın BİRLEŞİMİ — böylece
        // `applyDrag` tek bir kod yoluyla hem kenarları hem köşeleri işler.
        const val HANDLE_NONE = 0
        const val EDGE_LEFT = 1
        const val EDGE_RIGHT = 2
        const val EDGE_TOP = 4
        const val EDGE_BOTTOM = 8
        const val HANDLE_LEFT = EDGE_LEFT
        const val HANDLE_RIGHT = EDGE_RIGHT
        const val HANDLE_TOP = EDGE_TOP
        const val HANDLE_BOTTOM = EDGE_BOTTOM
        const val HANDLE_TOP_LEFT = EDGE_TOP or EDGE_LEFT
        const val HANDLE_TOP_RIGHT = EDGE_TOP or EDGE_RIGHT
        const val HANDLE_BOTTOM_LEFT = EDGE_BOTTOM or EDGE_LEFT
        const val HANDLE_BOTTOM_RIGHT = EDGE_BOTTOM or EDGE_RIGHT
        const val HANDLE_MOVE = 16
    }
}
