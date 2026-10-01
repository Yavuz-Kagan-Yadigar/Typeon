package com.p2p.messenger.ui

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.view.MotionEvent
import android.view.View
import androidx.core.graphics.ColorUtils
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.hypot

/**
 * The drawing surface of the shared whiteboard: a black 16:10 board that is
 * always shown whole. Strokes live in the core's 1600x1000 virtual canvas
 * (see `whiteboard.rs`); this view only scales them to its own size, so every
 * device shows the same picture.
 */
@SuppressLint("ViewConstructor")
class WhiteboardView(context: Context) : View(context) {

    class Stroke(val id: ByteArray, val shade: Int, val author: Int, val width: Int, val points: FloatArray) {
        val path: Path by lazy {
            Path().apply {
                moveTo(points[0], points[1])
                for (i in 2 until points.size step 2) lineTo(points[i], points[i + 1])
                // A dot: a zero-length line still draws with a round cap.
                if (points.size == 2) lineTo(points[0], points[1])
            }
        }
    }

    companion object {
        const val WIDTH = 1600f
        const val HEIGHT = 1000f
        /** Share of the screen height the board may take, so the chat stays usable below it. */
        private const val MAX_SCREEN_SHARE = 0.55f
        const val DEFAULT_PEN_WIDTH = 5
        const val MAX_PEN_WIDTH = 40
        /** Minimum distance between two stored points, in board units. */
        private const val MIN_STEP = 3f
        private const val ERASER_RADIUS = 18f

        /** Everyone gets one hue, at equal angles around the colour wheel; the
         *  three shades of a person share it. [author] 255 = no longer a participant. */
        fun colorOf(author: Int, participants: Int, shade: Int): Int {
            val lightness = when (shade) { 0 -> 0.75f; 2 -> 0.35f; else -> 0.55f }
            if (author !in 0 until participants) return ColorUtils.HSLToColor(floatArrayOf(0f, 0f, lightness))
            return ColorUtils.HSLToColor(floatArrayOf(360f * author / participants, 0.9f, lightness))
        }

        /** Parses `P2PLib.whiteboardPage`: id(8) shade(1) author(1) width(1) count(u16 LE) points(u16 LE x,y). */
        fun parsePage(blob: ByteArray): ArrayList<Stroke> {
            val out = ArrayList<Stroke>()
            val buf = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
            while (buf.remaining() >= 13) {
                val id = ByteArray(8).also { buf.get(it) }
                val shade = buf.get().toInt() and 0xFF
                val author = buf.get().toInt() and 0xFF
                val width = buf.get().toInt() and 0xFF
                val count = buf.short.toInt() and 0xFFFF
                if (count == 0 || buf.remaining() < count * 4) break
                val points = FloatArray(count * 2) { (buf.short.toInt() and 0xFFFF).toFloat() }
                out.add(Stroke(id, shade, author, width, points))
            }
            return out
        }

        /** Draws a page in board units; the caller scales the canvas. Shared by the view and the PDF export. */
        fun drawPage(canvas: Canvas, strokes: List<Stroke>, participants: Int, paint: Paint) {
            canvas.drawColor(Color.BLACK)
            for (s in strokes) drawStroke(canvas, s, participants, paint)
        }

        private fun drawStroke(canvas: Canvas, s: Stroke, participants: Int, paint: Paint) {
            paint.color = colorOf(s.author, participants, s.shade)
            // 0 = drawn by a build without pen sizes.
            paint.strokeWidth = (if (s.width == 0) DEFAULT_PEN_WIDTH else s.width).toFloat()
            canvas.drawPath(s.path, paint)
        }

        fun strokePaint() = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
        }
    }

    var strokes: ArrayList<Stroke> = ArrayList()
        set(value) { field = value; invalidate() }
    /** Strokes drawn here that the core has not echoed back in [strokes] yet. */
    val pending = ArrayList<Stroke>()
    var participants = 2
    var me = 0
    var shade = 1
    var penWidth = DEFAULT_PEN_WIDTH
    var erasing = false
    /** Pen lifted: the new stroke, already added to [pending]. */
    var onStroke: ((Stroke) -> Unit)? = null
    var onErase: ((List<Stroke>) -> Unit)? = null

    private val paint = strokePaint()
    private val current = ArrayList<Float>()

    override fun onMeasure(widthSpec: Int, heightSpec: Int) {
        var w = MeasureSpec.getSize(widthSpec)
        var h = (w * HEIGHT / WIDTH).toInt()
        val maxH = (resources.displayMetrics.heightPixels * MAX_SCREEN_SHARE).toInt()
        if (h > maxH) {
            h = maxH
            w = (h * WIDTH / HEIGHT).toInt()
        }
        setMeasuredDimension(w, h)
    }

    override fun onDraw(canvas: Canvas) {
        canvas.save()
        canvas.scale(width / WIDTH, height / HEIGHT)
        drawPage(canvas, strokes, participants, paint)
        for (s in pending) drawStroke(canvas, s, participants, paint)
        if (current.size >= 2) {
            paint.color = colorOf(me, participants, shade)
            paint.strokeWidth = penWidth.toFloat()
            val path = Path().apply {
                moveTo(current[0], current[1])
                for (i in 2 until current.size step 2) lineTo(current[i], current[i + 1])
                if (current.size == 2) lineTo(current[0], current[1])
            }
            canvas.drawPath(path, paint)
        }
        canvas.restore()
    }

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                // The chat-list drawer and the message list must not steal the gesture.
                parent?.requestDisallowInterceptTouchEvent(true)
                current.clear()
                touch(event.x, event.y)
            }
            MotionEvent.ACTION_MOVE -> {
                for (i in 0 until event.historySize) touch(event.getHistoricalX(i), event.getHistoricalY(i))
                touch(event.x, event.y)
            }
            MotionEvent.ACTION_UP -> finishStroke()
            MotionEvent.ACTION_CANCEL -> current.clear()
            else -> return false
        }
        invalidate()
        return true
    }

    private fun touch(viewX: Float, viewY: Float) {
        val x = (viewX * WIDTH / width).coerceIn(0f, WIDTH)
        val y = (viewY * HEIGHT / height).coerceIn(0f, HEIGHT)
        if (erasing) { eraseAt(x, y); return }
        val n = current.size
        if (n >= 2 && hypot(x - current[n - 2], y - current[n - 1]) < MIN_STEP) return
        current.add(x)
        current.add(y)
    }

    private fun finishStroke() {
        if (erasing || current.isEmpty()) return
        val stroke = Stroke(ByteArray(0), shade, me, penWidth, current.toFloatArray())
        current.clear()
        pending.add(stroke)
        onStroke?.invoke(stroke)
    }

    /** Stroke eraser: every stroke the finger touches goes away whole. */
    private fun eraseAt(x: Float, y: Float) {
        val hit = strokes.filter { near(it, x, y) }
        if (hit.isEmpty()) return
        strokes.removeAll(hit.toSet())
        onErase?.invoke(hit)
    }

    private fun near(s: Stroke, x: Float, y: Float): Boolean {
        val p = s.points
        for (i in 0 until p.size step 2) {
            val j = if (i + 2 < p.size) i + 2 else i
            if (segmentDistance(x, y, p[i], p[i + 1], p[j], p[j + 1]) < ERASER_RADIUS) return true
        }
        return false
    }

    private fun segmentDistance(px: Float, py: Float, ax: Float, ay: Float, bx: Float, by: Float): Float {
        val dx = bx - ax
        val dy = by - ay
        val len2 = dx * dx + dy * dy
        val t = if (len2 == 0f) 0f else (((px - ax) * dx + (py - ay) * dy) / len2).coerceIn(0f, 1f)
        return hypot(px - (ax + t * dx), py - (ay + t * dy))
    }
}
