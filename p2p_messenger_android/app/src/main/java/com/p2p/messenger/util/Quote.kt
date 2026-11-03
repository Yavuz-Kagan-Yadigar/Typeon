package com.p2p.messenger.util

import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.text.Editable
import android.text.Spannable
import android.text.TextPaint
import android.text.TextUtils
import android.text.TextWatcher
import android.text.style.ClickableSpan
import android.text.style.ReplacementSpan
import android.view.View
import android.widget.EditText

/**
 * Inline quotes: a message can quote several messages, each at its own place
 * in the text. Like [Forward], no protocol field: each quote travels inside
 * the text as an invisible-delimited marker `START id SEP preview END`, and
 * is drawn as a box ([Box]) both in the input field and in the bubble.
 */
object Quote {
    private const val START = "⁢⁤"
    private const val SEP = "⁣"
    private const val END = "⁤⁢"
    private val MARKER = Regex("⁢⁤([^⁢-⁤\\s]{1,128})⁣([^⁢-⁤]*)⁤⁢")

    private fun clean(s: String) = s.replace(Regex("[⁢-⁤]"), "")

    fun marker(messageId: String, preview: String) = START + clean(messageId) + SEP + clean(preview) + END

    /** The text with every quote removed: the sender's own words only. */
    fun withoutQuotes(text: String) = MARKER.replace(text, "")

    /** Text for places that cannot draw boxes: notifications, chat list, copy. */
    fun plain(text: String) = MARKER.replace(text) { "> " + it.groupValues[2].replace('\n', ' ') }

    /** Inserts a quote at the cursor, on its own line. */
    fun insert(edit: EditText, messageId: String, preview: String) {
        val text = edit.text
        val at = edit.selectionStart.coerceIn(0, text.length)
        val before = if (at > 0 && text[at - 1] != '\n') "\n" else ""
        val after = if (at < text.length && text[at] == '\n') "" else "\n"
        val chunk = before + marker(messageId, preview) + after
        text.insert(at, chunk)
        edit.setSelection(at + chunk.length)
        edit.requestFocus()
    }

    /** Input field: draws markers as boxes and deletes a box whole. */
    fun attach(edit: EditText) {
        edit.addTextChangedListener(object : TextWatcher {
            private var cut = emptyList<Box>()
            /** Typing with the cursor inside a box: moved to after the box. */
            private var into: Box? = null
            private var typedAt = 0
            private var typedLen = 0
            private var busy = false
            override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {
                if (busy || s !is Spannable) return
                if (count == 0) {
                    into = if (after == 0) null else s.getSpans(start, start, Box::class.java)
                        .firstOrNull { s.getSpanStart(it) < start && s.getSpanEnd(it) > start }
                    typedAt = start
                    typedLen = after
                    return
                }
                cut = s.getSpans(start, start + count, Box::class.java).filter {
                    s.getSpanStart(it) < start + count && s.getSpanEnd(it) > start
                }
            }
            override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable) {
                if (busy) return
                busy = true
                into?.let { box ->
                    val typed = s.subSequence(typedAt, typedAt + typedLen).toString()
                    s.delete(typedAt, typedAt + typedLen)
                    val end = s.getSpanEnd(box)
                    if (end >= 0) {
                        s.insert(end, typed)
                        edit.setSelection(end + typed.length)
                    }
                }
                into = null
                for (box in cut) {
                    val a = s.getSpanStart(box)
                    val b = s.getSpanEnd(box)
                    if (a in 0 until b) s.delete(a, b)
                }
                cut = emptyList()
                s.getSpans(0, s.length, Box::class.java).forEach { s.removeSpan(it) }
                val width = edit.width - edit.totalPaddingLeft - edit.totalPaddingRight
                val max = if (width > 0) width else edit.resources.displayMetrics.widthPixels / 2
                for (m in MARKER.findAll(s)) {
                    s.setSpan(Box(null, m.groupValues[2], max), m.range.first, m.range.last + 1, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
                }
                busy = false
            }
        })
    }

    /**
     * Bubble: draws each marker as a box. [resolve] maps (id, sender preview)
     * to (label, shown text); a tap calls [onTap] with the id.
     * Returns true when the text had a quote.
     */
    fun decorate(
        text: Spannable, maxWidth: Int,
        resolve: (String, String) -> Pair<String?, String>,
        onTap: (String) -> Unit
    ): Boolean {
        var any = false
        for (m in MARKER.findAll(text)) {
            val id = m.groupValues[1]
            val (label, shown) = resolve(id, m.groupValues[2])
            val a = m.range.first
            val b = m.range.last + 1
            text.setSpan(Box(label, shown, maxWidth), a, b, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
            text.setSpan(object : ClickableSpan() {
                override fun onClick(widget: View) = onTap(id)
                override fun updateDrawState(ds: TextPaint) {}
            }, a, b, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
            any = true
        }
        return any
    }

    /** The quote box: optional bold label over one ellipsized line. */
    class Box(private val label: String?, text: String, private val maxWidth: Int) : ReplacementSpan() {
        private val text = text.replace('\n', ' ')

        private fun dp(paint: Paint, v: Float) = v * paint.textSize / 15f
        /** The owner name: bold, smaller and faded. */
        private fun bold(paint: Paint) = TextPaint(paint).apply {
            typeface = Typeface.create(typeface, Typeface.BOLD)
            textSize = paint.textSize * 0.8f
            color = (paint.color and 0xFFFFFF) or 0x99000000.toInt()
        }

        private fun labelHeight(paint: Paint) = if (label == null) 0 else bold(paint).fontMetricsInt.let { it.descent - it.ascent }

        private fun width(paint: Paint): Int {
            val pad = dp(paint, 10f)
            val content = maxOf(label?.let { bold(paint).measureText(it) } ?: 0f, paint.measureText(text))
            return minOf(maxWidth, kotlin.math.ceil(content + pad * 2).toInt() + 1)
        }

        private fun boxHeight(paint: Paint): Int {
            val fmi = paint.fontMetricsInt
            return fmi.descent - fmi.ascent + labelHeight(paint) + dp(paint, 12f).toInt()
        }

        override fun getSize(paint: Paint, text: CharSequence?, start: Int, end: Int, fm: Paint.FontMetricsInt?): Int {
            if (fm != null) {
                val fmi = paint.fontMetricsInt
                val gap = dp(paint, 3f).toInt()
                fm.ascent = fmi.descent - boxHeight(paint) - gap
                fm.top = fm.ascent
                fm.descent = fmi.descent + gap
                fm.bottom = fm.descent
            }
            return width(paint)
        }

        override fun draw(canvas: Canvas, text: CharSequence?, start: Int, end: Int, x: Float, top: Int, y: Int, bottom: Int, paint: Paint) {
            val fmi = paint.fontMetricsInt
            val w = width(paint).toFloat()
            val bottomY = (y + fmi.descent).toFloat()
            val topY = bottomY - boxHeight(paint)
            val pad = dp(paint, 10f)
            val color = paint.color
            val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { this.color = (color and 0xFFFFFF) or 0x26000000 }
            val radius = dp(paint, 8f)
            canvas.drawRoundRect(RectF(x, topY, x + w, bottomY), radius, radius, fill)
            val avail = w - pad * 2
            val textX = x + pad
            if (label != null) {
                val bp = bold(paint)
                canvas.drawText(TextUtils.ellipsize(label, bp, avail, TextUtils.TruncateAt.END).toString(), textX, topY + dp(paint, 6f) - bp.fontMetricsInt.ascent, bp)
            }
            val baseline = topY + dp(paint, 6f) + labelHeight(paint) - fmi.ascent
            val tp = TextPaint(paint)
            canvas.drawText(TextUtils.ellipsize(this.text, tp, avail, TextUtils.TruncateAt.END).toString(), textX, baseline, tp)
        }
    }
}
