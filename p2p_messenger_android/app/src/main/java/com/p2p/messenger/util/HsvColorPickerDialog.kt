package com.p2p.messenger.util

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ComposeShader
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.Shader
import android.text.Editable
import android.text.InputFilter
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import androidx.appcompat.app.AlertDialog
import androidx.annotation.StringRes
import com.p2p.messenger.R

/**
 * Classic HSV picker, with a Saturation/Value (SV) square and a Hue bar, plus manual hex entry. It replaces a fixed colour swatch grid. No external
 * library is added (the Gradle build cannot be verified in this environment; see the other notes in this file about avoiding new dependencies). It is
 * drawn entirely by hand with `Canvas` and `Shader`.
 */
private class SvPickerView(context: Context) : View(context) {
    var hue: Float = 0f
        set(value) {
            field = value
            updateShader()
            invalidate()
        }
    var sat: Float = 1f
        private set
    var valueComponent: Float = 1f
        private set
    var onChanged: (() -> Unit)? = null

    private val fillPaint = Paint()
    private val markerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 5f
        color = Color.WHITE
    }
    private val markerOutlinePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2f
        color = Color.BLACK
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        updateShader()
    }

    private fun updateShader() {
        if (width <= 0 || height <= 0) return
        val satShader = LinearGradient(
            0f, 0f, width.toFloat(), 0f,
            Color.WHITE, Color.HSVToColor(floatArrayOf(hue, 1f, 1f)),
            Shader.TileMode.CLAMP
        )
        val valShader = LinearGradient(
            0f, 0f, 0f, height.toFloat(),
            Color.WHITE, Color.BLACK,
            Shader.TileMode.CLAMP
        )
        // Two shaders of the same kind are not composed by the hardware
        // canvas before API 28: the square came out wrong on Android 8.x.
        if (android.os.Build.VERSION.SDK_INT < 28 && layerType != LAYER_TYPE_SOFTWARE) setLayerType(LAYER_TYPE_SOFTWARE, null)
        fillPaint.shader = ComposeShader(valShader, satShader, PorterDuff.Mode.MULTIPLY)
    }

    override fun onDraw(canvas: Canvas) {
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), fillPaint)
        val cx = (sat * width).coerceIn(0f, width.toFloat())
        val cy = ((1f - valueComponent) * height).coerceIn(0f, height.toFloat())
        canvas.drawCircle(cx, cy, 12f, markerPaint)
        canvas.drawCircle(cx, cy, 12f, markerOutlinePaint)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (width <= 0 || height <= 0) return true
        when (event.action) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE -> {
                parent?.requestDisallowInterceptTouchEvent(true)
                sat = (event.x / width).coerceIn(0f, 1f)
                valueComponent = (1f - event.y / height).coerceIn(0f, 1f)
                invalidate()
                onChanged?.invoke()
            }
        }
        return true
    }

    fun setSatVal(s: Float, v: Float) {
        sat = s.coerceIn(0f, 1f)
        valueComponent = v.coerceIn(0f, 1f)
        invalidate()
    }
}

private class HuePickerView(context: Context) : View(context) {
    var hue: Float = 0f
        private set
    var onChanged: ((Float) -> Unit)? = null

    private val fillPaint = Paint()
    private val markerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 5f
        color = Color.WHITE
    }
    private val markerOutlinePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2f
        color = Color.BLACK
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (w <= 0) return
        val colors = IntArray(7) { i -> Color.HSVToColor(floatArrayOf(i * 60f, 1f, 1f)) }
        fillPaint.shader = LinearGradient(0f, 0f, w.toFloat(), 0f, colors, null, Shader.TileMode.CLAMP)
    }

    override fun onDraw(canvas: Canvas) {
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), fillPaint)
        val cx = ((hue / 360f) * width).coerceIn(0f, width.toFloat())
        canvas.drawLine(cx, 0f, cx, height.toFloat(), markerPaint)
        canvas.drawLine(cx, 0f, cx, height.toFloat(), markerOutlinePaint)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (width <= 0) return true
        when (event.action) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE -> {
                parent?.requestDisallowInterceptTouchEvent(true)
                hue = ((event.x / width) * 360f).coerceIn(0f, 359.999f)
                invalidate()
                onChanged?.invoke(hue)
            }
        }
        return true
    }

    fun setHue(h: Float) {
        hue = h.coerceIn(0f, 359.999f)
        invalidate()
    }
}

object HsvColorPickerDialog {
    /** `onPicked(null)` means "Reset" (back to the theme default). The dialog triggers it with its `Reset` button. */
    fun show(context: Context, @StringRes titleRes: Int, initialColor: Int?, onPicked: (Int?) -> Unit) {
        val density = context.resources.displayMetrics.density
        fun dp(v: Int) = (v * density).toInt()

        val root = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(4))
        }

        val previewRow = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val preview = View(context).apply {
            layoutParams = LinearLayout.LayoutParams(dp(40), dp(40)).apply { marginEnd = dp(12) }
        }
        val hexInput = EditText(context).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            hint = "#RRGGBB"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            filters = arrayOf(InputFilter.LengthFilter(7))
        }
        previewRow.addView(preview)
        previewRow.addView(hexInput)

        val svPicker = SvPickerView(context).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(200)).apply {
                topMargin = dp(20)
            }
        }
        val huePicker = HuePickerView(context).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(28)).apply {
                topMargin = dp(16)
            }
        }

        val startHsv = FloatArray(3)
        Color.colorToHSV(initialColor ?: Color.WHITE, startHsv)
        huePicker.setHue(startHsv[0])
        svPicker.hue = startHsv[0]
        svPicker.setSatVal(startHsv[1], startHsv[2])

        fun currentColor(): Int = Color.HSVToColor(floatArrayOf(huePicker.hue, svPicker.sat, svPicker.valueComponent))

        var suppressHexWatcher = false
        fun refreshPreview() {
            val c = currentColor()
            preview.setBackgroundColor(c)
            suppressHexWatcher = true
            hexInput.setText(String.format(java.util.Locale.US, "#%06X", 0xFFFFFF and c))
            suppressHexWatcher = false
        }
        refreshPreview()

        svPicker.onChanged = { refreshPreview() }
        huePicker.onChanged = { h -> svPicker.hue = h; refreshPreview() }
        hexInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                if (suppressHexWatcher) return
                val text = s?.toString().orEmpty()
                if (text.length == 7 && text.startsWith("#")) {
                    val parsed = try { Color.parseColor(text) } catch (e: Exception) { null }
                    if (parsed != null) {
                        val hsv = FloatArray(3)
                        Color.colorToHSV(parsed, hsv)
                        huePicker.setHue(hsv[0])
                        svPicker.hue = hsv[0]
                        svPicker.setSatVal(hsv[1], hsv[2])
                        preview.setBackgroundColor(parsed)
                    }
                }
            }
        })

        root.addView(previewRow)
        root.addView(svPicker)
        root.addView(huePicker)

        AlertDialog.Builder(context)
            .setTitle(titleRes)
            .setView(root)
            .setPositiveButton(android.R.string.ok) { _, _ -> onPicked(currentColor()) }
            .setNegativeButton(android.R.string.cancel, null)
            .setNeutralButton(R.string.action_reset) { _, _ -> onPicked(null) }
            .show()
    }
}
