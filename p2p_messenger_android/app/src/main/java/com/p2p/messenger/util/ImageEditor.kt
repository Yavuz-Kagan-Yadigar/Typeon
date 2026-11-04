package com.p2p.messenger.util

import android.app.Dialog
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.BitmapShader
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PointF
import android.graphics.Rect
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.ImageButton
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.core.graphics.ColorUtils
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.color.MaterialColors
import com.google.android.material.slider.Slider
import com.p2p.messenger.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.math.hypot

/** Long edge the editor decodes to: a sampled decode lands in [EDIT_MAX, 2 * EDIT_MAX). */
const val EDIT_MAX = 2048

/**
 * Full-screen editor the caption dialog opens on an image tile: rotate 90°
 * either way, crop, a pen (colour + size) and a blur pen (size), with undo.
 * Two fingers zoom and pan in every tool; one finger pans when no tool is on.
 *
 * [load] (run off the main thread) gives the image to start from, [original]
 * the untouched one Revert goes back to. OK (or Back) closes the editor:
 * [onDone] gets [out] holding the edit as PNG, or null when the image ended
 * up as the original. Nothing touched since opening: [onDone] is not called.
 * [onRetake] (the in-app camera's shot) adds Retake: it closes the editor
 * without [onDone] and calls it.
 */
fun AppCompatActivity.openImageEditor(
    load: () -> Bitmap?,
    original: () -> Bitmap?,
    startEdited: Boolean,
    out: File,
    onRetake: (() -> Unit)? = null,
    onDone: (File?) -> Unit,
) {
    val dp = resources.displayMetrics.density
    // Same palette as the rest of the app (see WhiteboardPanel): bars on the
    // action bar's colour, the image on the window's.
    val chrome = MaterialColors.getColor(this, com.google.android.material.R.attr.colorSurfaceContainer, Color.DKGRAY)
    val onChrome = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurface, Color.BLACK)
    val accent = MaterialColors.getColor(this, com.google.android.material.R.attr.colorPrimary, onChrome)
    val selectedBg = MaterialColors.getColor(this, com.google.android.material.R.attr.colorSecondaryContainer, Color.GRAY)
    val onSelected = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSecondaryContainer, onChrome)

    val dialog = Dialog(this, R.style.Theme_P2PMessenger).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
    val board = EditCanvas(this)
    var baseEdited = startEdited // the image undo goes back to is itself an edit
    var dirty = false // anything done since the editor opened
    var busy = true
    board.onEdit = { dirty = true }

    fun setImage(source: () -> Bitmap?, edited: Boolean) {
        busy = true
        lifecycleScope.launch(Dispatchers.IO) {
            val bmp = try {
                source()
            } catch (e: Throwable) {
                null
            }
            withContext(Dispatchers.Main) {
                busy = false
                if (bmp == null) return@withContext
                board.load(bmp)
                baseEdited = edited
            }
        }
    }

    fun finish() {
        if (busy) return
        board.applyCrop()
        val bmp = board.bitmap
        when {
            bmp == null || !dirty -> dialog.dismiss()
            !baseEdited && !board.hasEdits -> { dialog.dismiss(); onDone(null) }
            else -> {
                busy = true
                lifecycleScope.launch(Dispatchers.IO) {
                    val ok = try {
                        out.parentFile?.mkdirs()
                        out.outputStream().use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
                    } catch (e: Exception) {
                        false
                    }
                    withContext(Dispatchers.Main) {
                        dialog.dismiss()
                        if (ok) onDone(out) else out.parentFile?.deleteRecursively()
                    }
                }
            }
        }
    }

    fun pill(selected: Boolean) = GradientDrawable().apply {
        cornerRadius = 100 * dp
        setColor(if (selected) selectedBg else Color.TRANSPARENT)
    }
    fun icon(parent: LinearLayout, drawable: Int, description: Int, weight: Float = 0f, onClick: () -> Unit) = ImageButton(this).apply {
        setImageResource(drawable)
        imageTintList = ColorStateList.valueOf(onChrome)
        background = pill(false)
        contentDescription = getString(description)
        tooltipText = contentDescription
        setOnClickListener { if (!busy) onClick() }
        parent.addView(this, LinearLayout.LayoutParams(if (weight > 0) 0 else (48 * dp).toInt(), (48 * dp).toInt(), weight).apply {
            if (weight > 0) setMargins((6 * dp).toInt(), (6 * dp).toInt(), (6 * dp).toInt(), (6 * dp).toInt())
        })
    }
    fun row() = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setBackgroundColor(chrome)
        val pad = (8 * dp).toInt()
        setPadding(pad, 0, pad, 0)
    }

    // Options of the active tool: pen colours + size, blur size, crop's apply.
    val options = row()
    val swatches = PEN_COLORS.map {
        View(this).apply {
            contentDescription = getString(R.string.image_edit_color)
            options.addView(this, LinearLayout.LayoutParams((28 * dp).toInt(), (28 * dp).toInt()).apply { marginEnd = (8 * dp).toInt() })
        }
    }
    fun styleSwatches() = swatches.forEachIndexed { i, v ->
        val on = PEN_COLORS[i] == board.color
        v.background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(PEN_COLORS[i])
            setStroke(((if (on) 3 else 1) * dp).toInt(), if (on) accent else ColorUtils.setAlphaComponent(onChrome, 90))
        }
    }
    swatches.forEachIndexed { i, v -> v.setOnClickListener { board.color = PEN_COLORS[i]; styleSwatches() } }
    val size = Slider(this).apply {
        valueFrom = 0f
        valueTo = 100f
        isTickVisible = false
        trackActiveTintList = ColorStateList.valueOf(accent)
        thumbTintList = ColorStateList.valueOf(accent)
        trackInactiveTintList = ColorStateList.valueOf(ColorUtils.setAlphaComponent(onChrome, 70))
        contentDescription = getString(R.string.image_edit_size)
        addOnChangeListener { _, p, fromUser ->
            if (!fromUser) return@addOnChangeListener
            if (board.mode == EditCanvas.Mode.BLUR) board.blurDp = 10f + p * 0.9f else board.penDp = 2f + p * 0.38f
        }
    }
    options.addView(size, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
    var closeTool: () -> Unit = {}
    val applyCrop = icon(options, R.drawable.ic_check, R.string.image_edit_apply_crop) { closeTool() }

    val tools = row()
    lateinit var toolViews: Map<EditCanvas.Mode, ImageButton>
    fun select(mode: EditCanvas.Mode) {
        board.applyCrop() // leaving crop mode keeps the frame
        board.mode = if (board.mode == mode) EditCanvas.Mode.NONE else mode
        val m = board.mode
        toolViews.forEach { (k, v) ->
            v.background = pill(k == m)
            v.imageTintList = ColorStateList.valueOf(if (k == m) onSelected else onChrome)
        }
        options.visibility = if (m == EditCanvas.Mode.NONE) View.INVISIBLE else View.VISIBLE
        swatches.forEach { it.visibility = if (m == EditCanvas.Mode.PEN) View.VISIBLE else View.GONE }
        size.visibility = if (m == EditCanvas.Mode.PEN || m == EditCanvas.Mode.BLUR) View.VISIBLE else View.GONE
        applyCrop.visibility = if (m == EditCanvas.Mode.CROP) View.VISIBLE else View.GONE
        size.value = (if (m == EditCanvas.Mode.BLUR) (board.blurDp - 10f) / 0.9f else (board.penDp - 2f) / 0.38f).coerceIn(0f, 100f)
    }
    icon(tools, R.drawable.ic_rotate_left, R.string.image_edit_rotate_left, 1f) { board.rotate(-90f) }
    icon(tools, R.drawable.ic_rotate_right, R.string.image_edit_rotate_right, 1f) { board.rotate(90f) }
    toolViews = mapOf(
        EditCanvas.Mode.CROP to icon(tools, R.drawable.ic_crop, R.string.image_edit_crop, 1f) { select(EditCanvas.Mode.CROP) },
        EditCanvas.Mode.PEN to icon(tools, R.drawable.ic_pen, R.string.image_edit_pen, 1f) { select(EditCanvas.Mode.PEN) },
        EditCanvas.Mode.BLUR to icon(tools, R.drawable.ic_blur, R.string.image_edit_blur, 1f) { select(EditCanvas.Mode.BLUR) },
    )
    closeTool = { select(board.mode) } // selecting the active tool again turns it off
    styleSwatches()
    select(EditCanvas.Mode.NONE)

    val top = row()
    top.addView(MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
        setText(R.string.image_edit_revert)
        setOnClickListener {
            if (busy) return@setOnClickListener
            if (board.mode != EditCanvas.Mode.NONE) select(board.mode)
            dirty = true
            setImage(original, false)
        }
    })
    if (onRetake != null) top.addView(MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
        setText(R.string.action_retake_photo)
        setOnClickListener {
            if (busy) return@setOnClickListener
            dialog.dismiss()
            onRetake()
        }
    }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = (8 * dp).toInt() })
    top.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f))
    top.addView(MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
        setText(R.string.image_edit_undo)
        setIconResource(R.drawable.ic_undo)
        setOnClickListener {
            if (busy) return@setOnClickListener
            if (board.mode == EditCanvas.Mode.CROP) select(EditCanvas.Mode.CROP) // drop the unapplied frame first
            board.undo()
        }
    })
    top.addView(MaterialButton(this).apply {
        setText(android.R.string.ok)
        setOnClickListener { finish() }
    }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = (8 * dp).toInt() })

    val bar = (56 * dp).toInt()
    val root = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(top, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, bar))
        addView(board, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        addView(options, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, bar))
        addView(tools, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (64 * dp).toInt()))
    }
    dialog.setContentView(root)
    dialog.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
    // Back keeps the edit, like OK.
    dialog.setOnCancelListener { finish() }
    dialog.show()
    setImage(load, startEdited)
}

private val PEN_COLORS = intArrayOf(Color.WHITE, Color.BLACK, 0xFFE53935.toInt(), 0xFFFDD835.toInt(), 0xFF43A047.toInt(), 0xFF1E88E5.toInt())

/** The image, fitted to the view and zoomed/panned on top of that. A stroke
 *  shows as an overlay while drawn and goes into the bitmap when the finger
 *  lifts; a second finger turns it into a pinch instead. */
private class EditCanvas(context: Context) : View(context) {
    enum class Mode { NONE, PEN, BLUR, CROP }

    var bitmap: Bitmap? = null
        private set
    var mode = Mode.NONE
        set(value) {
            field = value
            bitmap?.let { crop.set(0f, 0f, it.width.toFloat(), it.height.toFloat()) }
            invalidate()
        }
    var color = PEN_COLORS[2]
    var penDp = 6f
    var blurDp = 30f
    var onEdit: () -> Unit = {}

    private val dp = resources.displayMetrics.density
    private val fitMatrix = Matrix()
    private val user = Matrix() // pinch zoom + pan on top of the fit
    private val toView = Matrix()
    private val toBitmap = Matrix()
    private var bitmapCanvas: Canvas? = null
    private val crop = RectF()
    private val image = Paint(Paint.FILTER_BITMAP_FLAG)
    private val stroke = Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val frame = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE; style = Paint.Style.STROKE; strokeWidth = 2 * dp }
    private val handle = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE }
    private val dim = Paint().apply { color = 0x99000000.toInt() }
    private var last: PointF? = null
    private var grab = -1 // crop: corner 0..3 (clockwise from top-left), 4 = move, -1 = nothing
    private var base: Bitmap? = null
    private val ops = mutableListOf<Op>()
    private var points = ArrayList<Float>() // the stroke being drawn, bitmap coordinates
    private var preview: Path? = null
    private var gesture = false // a pinch/pan runs until every finger lifts
    private var lastFocus: PointF? = null
    private var lastSpan = 0f

    /** Starts over from [b]: no edits to undo. [b] itself is never drawn on. */
    fun load(b: Bitmap) {
        base = b
        ops.clear()
        rebuild()
    }

    val hasEdits get() = ops.isNotEmpty()

    fun undo() {
        if (ops.isEmpty()) return
        ops.removeAt(ops.lastIndex)
        rebuild()
        onEdit()
    }

    fun rotate(degrees: Float) = commit(Op.Rotate(degrees))

    fun applyCrop() {
        val b = bitmap ?: return
        if (mode != Mode.CROP) return
        val r = Rect().also { crop.round(it) }
        if (!r.intersect(0, 0, b.width, b.height) || (r.width() == b.width && r.height() == b.height)) return
        commit(Op.Crop(r))
    }

    /** One edit; undo replays the rest from [base]. */
    private sealed class Op {
        class Rotate(val degrees: Float) : Op()
        class Crop(val rect: Rect) : Op()
        class Stroke(val blur: Boolean, val color: Int, val width: Float, val points: FloatArray) : Op()
    }

    private fun commit(op: Op) {
        if (!run(op)) return
        ops.add(op)
        onEdit()
    }

    // ponytail: undo replays every edit from the start on the main thread; snapshots if it gets slow.
    private fun rebuild() {
        val b = base ?: return
        show(b.copy(Bitmap.Config.ARGB_8888, true) ?: return)
        for (op in ops) run(op)
    }

    /** Out of memory: the edit is skipped, the image stays as it was. */
    private fun run(op: Op): Boolean {
        val b = bitmap ?: return false
        return try {
            when (op) {
                is Op.Rotate -> show(mutable(Bitmap.createBitmap(b, 0, 0, b.width, b.height, Matrix().apply { setRotate(op.degrees) }, true)))
                is Op.Crop -> show(mutable(Bitmap.createBitmap(b, op.rect.left, op.rect.top, op.rect.width(), op.rect.height())))
                is Op.Stroke -> {
                    startStroke(op.blur, op.color, op.width, b)
                    bitmapCanvas?.drawPath(pathOf(op.points), stroke)
                    stroke.shader = null
                    invalidate()
                }
            }
            true
        } catch (e: Throwable) {
            stroke.shader = null
            false
        }
    }

    private fun pathOf(p: FloatArray) = Path().apply {
        moveTo(p[0], p[1])
        lineTo(p[0], p[1]) // a tap: the round cap draws a dot
        for (i in 2 until p.size step 2) lineTo(p[i], p[i + 1])
    }

    /** A new size (rotate, crop) refits the view; the same size keeps the zoom. */
    private fun show(b: Bitmap) {
        val old = bitmap
        bitmap = b
        bitmapCanvas = Canvas(b)
        crop.set(0f, 0f, b.width.toFloat(), b.height.toFloat())
        if (old == null || old.width != b.width || old.height != b.height) user.reset()
        fit()
        invalidate()
    }

    private fun startStroke(blur: Boolean, color: Int, width: Float, b: Bitmap) {
        stroke.strokeWidth = width
        if (blur) {
            stroke.color = Color.BLACK // opaque: the shader gives the colour
            stroke.shader = blurShader(b)
        } else {
            stroke.shader = null
            stroke.color = color
        }
    }

    private fun mutable(b: Bitmap): Bitmap =
        if (b.isMutable && b.config == Bitmap.Config.ARGB_8888) b else b.copy(Bitmap.Config.ARGB_8888, true)

    private fun fit() {
        val b = bitmap ?: return
        if (width == 0) return
        val pad = 16 * dp
        fitMatrix.setRectToRect(
            RectF(0f, 0f, b.width.toFloat(), b.height.toFloat()),
            RectF(pad, pad, width - pad, height - pad), Matrix.ScaleToFit.CENTER,
        )
        updateView()
    }

    /** Applies [user] on top of the fit, kept at 1x..8x and with the image
     *  centred while it is smaller than the view, edge to edge otherwise. */
    private fun updateView() {
        val b = bitmap ?: return
        toView.set(fitMatrix)
        toView.postConcat(user)
        val r = RectF(0f, 0f, b.width.toFloat(), b.height.toFloat()).also { toView.mapRect(it) }
        fun shift(start: Float, end: Float, size: Float) = when {
            end - start <= size -> size / 2 - (start + end) / 2
            start > 0 -> -start
            end < size -> size - end
            else -> 0f
        }
        user.postTranslate(shift(r.left, r.right, width.toFloat()), shift(r.top, r.bottom, height.toFloat()))
        toView.set(fitMatrix)
        toView.postConcat(user)
        toView.invert(toBitmap)
        invalidate()
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) = fit()

    /** View pixels per bitmap pixel. */
    private val scale get() = toView.mapRadius(1f)

    override fun onDraw(canvas: Canvas) {
        val b = bitmap ?: return
        canvas.drawBitmap(b, toView, image)
        preview?.let {
            canvas.save()
            canvas.concat(toView)
            canvas.clipRect(0f, 0f, b.width.toFloat(), b.height.toFloat())
            canvas.drawPath(it, stroke)
            canvas.restore()
        }
        if (mode != Mode.CROP) return
        val img = RectF(0f, 0f, b.width.toFloat(), b.height.toFloat()).also { toView.mapRect(it) }
        val r = RectF(crop).also { toView.mapRect(it) }
        canvas.drawRect(img.left, img.top, img.right, r.top, dim)
        canvas.drawRect(img.left, r.bottom, img.right, img.bottom, dim)
        canvas.drawRect(img.left, r.top, r.left, r.bottom, dim)
        canvas.drawRect(r.right, r.top, img.right, r.bottom, dim)
        canvas.drawRect(r, frame)
        for ((x, y) in listOf(r.left to r.top, r.right to r.top, r.right to r.bottom, r.left to r.bottom)) canvas.drawCircle(x, y, 8 * dp, handle)
    }

    override fun onTouchEvent(e: MotionEvent): Boolean {
        val b = bitmap ?: return false
        val action = e.actionMasked
        if (e.pointerCount > 1 && !gesture) {
            // Second finger: whatever the first one started is dropped.
            gesture = true
            preview = null
            stroke.shader = null
            grab = -1
            last = null
            lastFocus = null
        }
        if (gesture || mode == Mode.NONE) {
            pinch(e)
            if (action == MotionEvent.ACTION_UP || action == MotionEvent.ACTION_CANCEL) gesture = false
            return true
        }
        val p = floatArrayOf(e.x, e.y).also { toBitmap.mapPoints(it) }
        if (mode == Mode.CROP) dragCrop(action, p[0], p[1], b) else paint(action, p[0], p[1], b)
        invalidate()
        return true
    }

    /** Pan with the fingers' centre, zoom with their spread. A finger
     *  going down or up re-anchors, so nothing jumps. */
    private fun pinch(e: MotionEvent) {
        if (e.actionMasked != MotionEvent.ACTION_MOVE) {
            lastFocus = null
            return
        }
        val n = e.pointerCount
        var fx = 0f
        var fy = 0f
        for (i in 0 until n) { fx += e.getX(i); fy += e.getY(i) }
        fx /= n
        fy /= n
        val span = if (n > 1) hypot(e.getX(0) - e.getX(1), e.getY(0) - e.getY(1)) else 0f
        val lf = lastFocus
        if (lf != null) {
            user.postTranslate(fx - lf.x, fy - lf.y)
            if (span > 0 && lastSpan > 0) {
                val zoom = user.mapRadius(1f)
                val f = (span / lastSpan).coerceIn(1f / zoom, MAX_ZOOM / zoom)
                user.postScale(f, f, fx, fy)
            }
            updateView()
        }
        lastFocus = PointF(fx, fy)
        lastSpan = span
    }

    private fun paint(action: Int, x: Float, y: Float, b: Bitmap) {
        when (action) {
            MotionEvent.ACTION_DOWN -> {
                val width = (if (mode == Mode.PEN) penDp else blurDp) * dp / scale
                try { startStroke(mode == Mode.BLUR, color, width, b) } catch (e: Throwable) { return }
                points = arrayListOf(x, y)
                preview = pathOf(points.toFloatArray())
            }
            MotionEvent.ACTION_MOVE -> {
                val path = preview ?: return
                path.lineTo(x, y)
                points.add(x)
                points.add(y)
            }
            MotionEvent.ACTION_UP -> {
                if (preview == null) return
                preview = null
                commit(Op.Stroke(mode == Mode.BLUR, color, stroke.strokeWidth, points.toFloatArray()))
            }
            else -> {
                preview = null
                stroke.shader = null
            }
        }
    }

    /** Blur source: the image halved down to ~64 px on its long edge (each
     *  halving averages), drawn back up with bilinear filtering. */
    private fun blurShader(b: Bitmap): Shader {
        var s = b
        do {
            val next = Bitmap.createScaledBitmap(s, maxOf(1, s.width / 2), maxOf(1, s.height / 2), true)
            if (s !== b) s.recycle()
            s = next
        } while (maxOf(s.width, s.height) > 64)
        return BitmapShader(s, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP).apply {
            setLocalMatrix(Matrix().apply { setScale(b.width.toFloat() / s.width, b.height.toFloat() / s.height) })
        }
    }

    private fun dragCrop(action: Int, x: Float, y: Float, b: Bitmap) {
        val w = b.width.toFloat()
        val h = b.height.toFloat()
        when (action) {
            MotionEvent.ACTION_DOWN -> {
                val corners = listOf(crop.left to crop.top, crop.right to crop.top, crop.right to crop.bottom, crop.left to crop.bottom)
                val near = corners.indices.minByOrNull { val (cx, cy) = corners[it]; (cx - x) * (cx - x) + (cy - y) * (cy - y) }!!
                val (cx, cy) = corners[near]
                val reach = 32 * dp / scale
                grab = when {
                    (cx - x) * (cx - x) + (cy - y) * (cy - y) <= reach * reach -> near
                    crop.contains(x, y) -> 4
                    else -> -1
                }
                last = PointF(x, y)
            }
            MotionEvent.ACTION_MOVE -> {
                val l = last ?: return
                val min = minOf(48 * dp / scale, w / 4, h / 4)
                when (grab) {
                    0 -> { crop.left = x.coerceIn(0f, crop.right - min); crop.top = y.coerceIn(0f, crop.bottom - min) }
                    1 -> { crop.right = x.coerceIn(crop.left + min, w); crop.top = y.coerceIn(0f, crop.bottom - min) }
                    2 -> { crop.right = x.coerceIn(crop.left + min, w); crop.bottom = y.coerceIn(crop.top + min, h) }
                    3 -> { crop.left = x.coerceIn(0f, crop.right - min); crop.bottom = y.coerceIn(crop.top + min, h) }
                    4 -> crop.offset((x - l.x).coerceIn(-crop.left, w - crop.right), (y - l.y).coerceIn(-crop.top, h - crop.bottom))
                }
                l.set(x, y)
            }
            else -> { last = null; grab = -1 }
        }
    }

    private companion object {
        const val MAX_ZOOM = 8f
    }
}
