package com.p2p.messenger.util

import android.app.Dialog
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.BitmapFactory
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
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.Toast
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
import java.io.InputStream
import kotlin.math.hypot

/** An image decoded for the editor; [reduced]: smaller than its source. */
class EditImage(val bitmap: Bitmap, val reduced: Boolean)

/** Full-size bitmaps the editor may hold at once (base, working image, an
 *  undo replay, a rotate's temporaries): the decode budget is a quarter of the heap / this. */
private const val EDIT_COPIES = 6

/**
 * Decodes [open]'s image (EXIF rotation applied) as large as the heap allows
 * for editing: sampled down by powers of two only when it would not fit.
 * [open] is called up to three times, each stream is closed here.
 */
fun decodeForEdit(open: () -> InputStream?): EditImage? = try {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    open()?.use { BitmapFactory.decodeStream(it, null, bounds) }
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
        null
    } else {
        val budget = Runtime.getRuntime().maxMemory() / 4 / EDIT_COPIES
        var sample = 1
        while ((bounds.outWidth / sample).toLong() * (bounds.outHeight / sample) > budget) sample *= 2
        val bmp = open()?.use { BitmapFactory.decodeStream(it, null, BitmapFactory.Options().apply { inSampleSize = sample }) }
        val exif = try {
            open()?.use { android.media.ExifInterface(it) }
        } catch (e: Exception) {
            null
        }
        bmp?.let { EditImage(if (exif != null) ImagePreview.rotateForExif(it, exif) else it, sample > 1) }
    }
} catch (e: Throwable) {
    null
}

/**
 * Full-screen editor the caption dialog opens on an image tile: rotate 90°
 * either way, crop, a pen (colour + size) and a blur pen (size), with undo.
 * Two fingers zoom and pan in every tool; one finger pans when no tool is on.
 *
 * [load] (run off the main thread) gives the image to start from, [original]
 * the untouched one the Original button goes back to. OK (or Back) runs
 * [save] off the main thread on the result and hands what it returns to
 * [onDone] — null when the image ended up as the original — and only then
 * closes; a failed save keeps the editor open. Nothing touched since opening:
 * [onDone] is not called. [onRetake] (the in-app camera's shot) adds Retake:
 * it closes the editor without [onDone] and calls it.
 */
fun <T : Any> AppCompatActivity.openImageEditor(
    load: () -> EditImage?,
    original: () -> EditImage?,
    startEdited: Boolean,
    save: (Bitmap) -> T,
    onRetake: (() -> Unit)? = null,
    onDone: (T?) -> Unit,
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
    var busy = false
    fun setBusy(value: Boolean) {
        busy = value
        board.isEnabled = !value // no stroke lands while a load, an undo or the save runs
    }
    fun toast(text: Int) = Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    board.onEdit = { dirty = true }
    board.onNoMemory = { toast(R.string.image_edit_no_memory) }

    fun setImage(source: () -> EditImage?, edited: Boolean) {
        setBusy(true)
        lifecycleScope.launch(Dispatchers.IO) {
            val image = source()
            val working = try { image?.bitmap?.copy(Bitmap.Config.ARGB_8888, true) } catch (e: Throwable) { null }
            withContext(Dispatchers.Main) {
                setBusy(false)
                if (image == null || working == null) {
                    toast(R.string.image_edit_no_memory)
                    return@withContext
                }
                board.load(image.bitmap, working)
                baseEdited = edited
                if (image.reduced) {
                    Toast.makeText(this@openImageEditor, getString(R.string.image_edit_reduced, working.width, working.height), Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    fun finish() {
        if (busy) return
        // A crop that ran out of memory must not send the uncropped image.
        if (!board.applyCrop()) return
        val bmp = board.bitmap
        when {
            bmp == null || !dirty -> dialog.dismiss()
            !baseEdited && !board.hasEdits -> { dialog.dismiss(); onDone(null) }
            else -> {
                setBusy(true)
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try { save(bmp) } catch (e: Throwable) { null }
                    withContext(Dispatchers.Main) {
                        if (result == null) {
                            setBusy(false)
                            toast(R.string.image_edit_save_failed)
                        } else {
                            dialog.dismiss()
                            onDone(result)
                        }
                    }
                }
            }
        }
    }

    fun undo() {
        val (base, keep) = board.undoPlan() ?: return
        setBusy(true)
        // Replays the kept edits from the start: off the main thread.
        lifecycleScope.launch(Dispatchers.Default) {
            val result = EditCanvas.replay(base, keep)
            withContext(Dispatchers.Main) {
                setBusy(false)
                if (result == null) toast(R.string.image_edit_no_memory) else board.undone(base, result)
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
    fun textButton(parent: LinearLayout, text: Int, filled: Boolean = false, onClick: () -> Unit) = MaterialButton(
        this, null,
        if (filled) com.google.android.material.R.attr.materialButtonStyle else com.google.android.material.R.attr.materialButtonOutlinedStyle,
    ).apply {
        setText(text)
        setOnClickListener { if (!busy) onClick() }
        parent.addView(this, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            if (parent.childCount > 0) marginStart = (8 * dp).toInt()
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
    textButton(top, R.string.image_edit_revert) {
        if (board.mode != EditCanvas.Mode.NONE) select(board.mode)
        dirty = true
        setImage(original, false)
    }
    if (onRetake != null) textButton(top, R.string.action_retake_photo) {
        dialog.dismiss()
        onRetake()
    }
    top.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f))
    textButton(top, R.string.image_edit_undo) {
        if (board.mode == EditCanvas.Mode.CROP) board.mode = EditCanvas.Mode.CROP // drops the unapplied frame
        undo()
    }.setIconResource(R.drawable.ic_undo)
    textButton(top, android.R.string.ok, filled = true) { finish() }

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
    // Back = OK. Not a cancel: that would close the editor before the save
    // finished, and the caption dialog could send the unedited image meanwhile.
    dialog.setCancelable(false)
    dialog.setOnKeyListener { _, code, event ->
        if (code != KeyEvent.KEYCODE_BACK) return@setOnKeyListener false
        if (event.action == KeyEvent.ACTION_UP) finish()
        true
    }
    // Its own window, so the activity's FLAG_SECURE does not cover it. It sets
    // FLAG_SECURE itself below API 33.
    if (android.os.Build.VERSION.SDK_INT < 33) {
        dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
    }
    // The activity going away takes the editor with it (no leaked window).
    val closeOnDestroy = androidx.lifecycle.LifecycleEventObserver { _, e ->
        if (e == androidx.lifecycle.Lifecycle.Event.ON_DESTROY && dialog.isShowing) dialog.dismiss()
    }
    lifecycle.addObserver(closeOnDestroy)
    dialog.setOnDismissListener { lifecycle.removeObserver(closeOnDestroy) }
    dialog.show()
    setImage(load, startEdited)
}

private val PEN_COLORS = intArrayOf(Color.WHITE, Color.BLACK, 0xFFE53935.toInt(), 0xFFFDD835.toInt(), 0xFF43A047.toInt(), 0xFF1E88E5.toInt())

/** The image, fitted to the view and zoomed/panned on top of that. A stroke
 *  shows as an overlay while drawn and goes into the bitmap when the finger
 *  lifts; a second finger turns it into a pinch instead. */
private class EditCanvas(context: Context) : View(context) {
    enum class Mode { NONE, PEN, BLUR, CROP }

    /** One edit; undo replays the rest from the base image. */
    sealed class Op {
        class Rotate(val degrees: Float) : Op()
        class Crop(val rect: Rect) : Op()
        class Stroke(val blur: Boolean, val color: Int, val width: Float, val points: FloatArray) : Op()
    }

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
    var onNoMemory: () -> Unit = {}

    private val dp = resources.displayMetrics.density
    private val fitMatrix = Matrix()
    private val user = Matrix() // pinch zoom + pan on top of the fit
    private val toView = Matrix()
    private val toBitmap = Matrix()
    private val crop = RectF()
    private val image = Paint(Paint.FILTER_BITMAP_FLAG)
    private var stroke = Paint() // the stroke being drawn; strokePaint() makes it
    private val frame = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE; style = Paint.Style.STROKE; strokeWidth = 2 * dp }
    private val handle = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE }
    private val dim = Paint().apply { color = 0x99000000.toInt() }
    private var last: PointF? = null
    private var grab = -1 // crop: corner 0..3 (clockwise from top-left), 4 = move, -1 = nothing
    private var base: Bitmap? = null // never drawn on
    private val ops = mutableListOf<Op>()
    private var points = ArrayList<Float>() // the stroke being drawn, bitmap coordinates
    private var preview: Path? = null
    private var gesture = false // a pinch/pan runs until every finger lifts
    private var lastFocus: PointF? = null
    private var lastSpan = 0f

    /** Starts over: [working] is a drawable copy of [base]. */
    fun load(base: Bitmap, working: Bitmap) {
        this.base = base
        ops.clear()
        show(working)
    }

    val hasEdits get() = ops.isNotEmpty()

    /** What undo replays: the base and every edit but the last; null: nothing to undo. */
    fun undoPlan(): Pair<Bitmap, List<Op>>? {
        val b = base ?: return null
        if (ops.isEmpty()) return null
        return b to ops.dropLast(1)
    }

    /** [replay]'s result for [undoPlan]; ignored if the image was replaced meanwhile. */
    fun undone(forBase: Bitmap, result: Bitmap) {
        if (forBase !== base || ops.isEmpty()) return
        ops.removeAt(ops.lastIndex)
        show(result)
        onEdit()
    }

    fun rotate(degrees: Float) = commit(Op.Rotate(degrees))

    /** False only when a pending crop could not be applied (out of memory). */
    fun applyCrop(): Boolean {
        val b = bitmap ?: return true
        if (mode != Mode.CROP) return true
        val r = Rect().also { crop.round(it) }
        if (!r.intersect(0, 0, b.width, b.height) || (r.width() == b.width && r.height() == b.height)) return true
        return commit(Op.Crop(r))
    }

    private fun commit(op: Op): Boolean {
        val b = bitmap ?: return false
        val next = apply(op, b)
        if (next == null) {
            onNoMemory()
            return false
        }
        ops.add(op)
        if (next !== b) show(next) else invalidate()
        onEdit()
        return true
    }

    /** A new size (rotate, crop) refits the view; the same size keeps the zoom. */
    private fun show(b: Bitmap) {
        val old = bitmap
        bitmap = b
        crop.set(0f, 0f, b.width.toFloat(), b.height.toFloat())
        if (old == null || old.width != b.width || old.height != b.height) user.reset()
        fit()
        invalidate()
    }

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

    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        // Disabled mid-pinch the last finger-up never arrives here: end the
        // gesture too, or the next stroke would pan.
        if (!enabled) { cancelTouch(); gesture = false }
    }

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

    /** Drops what a finger started: the unlifted stroke, a crop drag. */
    private fun cancelTouch() {
        preview = null
        grab = -1
        last = null
        lastFocus = null
        invalidate()
    }

    override fun onTouchEvent(e: MotionEvent): Boolean {
        if (!isEnabled) return false
        val b = bitmap ?: return false
        val action = e.actionMasked
        if (e.pointerCount > 1 && !gesture) {
            // Second finger: whatever the first one started is dropped.
            gesture = true
            cancelTouch()
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
                stroke = try {
                    strokePaint(mode == Mode.BLUR, color, width, b)
                } catch (e: Throwable) {
                    onNoMemory()
                    return
                }
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
            else -> preview = null
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
                // The smallest frame depends on the zoom: never more than the
                // frame already is (a frame made at 8x, then zoomed out), else
                // the ranges below would be empty.
                val min = minOf(48 * dp / scale, w / 4, h / 4, crop.width(), crop.height())
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

    companion object {
        const val MAX_ZOOM = 8f

        /** [ops] on a fresh copy of [base]; null when memory runs out (nothing half-done is kept). */
        fun replay(base: Bitmap, ops: List<Op>): Bitmap? {
            var b = try { base.copy(Bitmap.Config.ARGB_8888, true) } catch (e: Throwable) { null } ?: return null
            for (op in ops) b = apply(op, b) ?: return null
            return b
        }

        /** [op] on [b]: a stroke draws into it, rotate/crop return a new bitmap.
         *  Null when memory runs out; [b] is then unchanged. */
        fun apply(op: Op, b: Bitmap): Bitmap? = try {
            when (op) {
                is Op.Rotate -> mutable(Bitmap.createBitmap(b, 0, 0, b.width, b.height, Matrix().apply { setRotate(op.degrees) }, true))
                is Op.Crop -> mutable(Bitmap.createBitmap(b, op.rect.left, op.rect.top, op.rect.width(), op.rect.height()))
                is Op.Stroke -> {
                    val paint = strokePaint(op.blur, op.color, op.width, b)
                    Canvas(b).drawPath(pathOf(op.points), paint)
                    b
                }
            }
        } catch (e: Throwable) {
            null
        }

        private fun mutable(b: Bitmap): Bitmap =
            if (b.isMutable && b.config == Bitmap.Config.ARGB_8888) b
            else b.copy(Bitmap.Config.ARGB_8888, true) ?: throw OutOfMemoryError()

        fun pathOf(p: FloatArray) = Path().apply {
            moveTo(p[0], p[1])
            lineTo(p[0], p[1]) // a tap: the round cap draws a dot
            for (i in 2 until p.size step 2) lineTo(p[i], p[i + 1])
        }

        fun strokePaint(blur: Boolean, color: Int, width: Float, b: Bitmap) = Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG).apply {
            style = Paint.Style.STROKE
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
            strokeWidth = width
            if (blur) {
                this.color = Color.BLACK // opaque: the shader gives the colour
                shader = blurShader(b)
            } else {
                this.color = color
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
    }
}
