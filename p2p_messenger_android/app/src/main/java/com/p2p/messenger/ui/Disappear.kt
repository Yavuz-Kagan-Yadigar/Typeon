package com.p2p.messenger.ui

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.view.HapticFeedbackConstants
import android.view.MotionEvent
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.slider.Slider
import com.p2p.messenger.R

/**
 * Disappearing messages: hold Send for 3 s to turn the chat's disappearing mode on, change or off. While it is on, everything
 * sent in the chat (text, files, voice, stickers) carries the timer; the core stamps it (`disappear_mode`). Each message keeps
 * its own timer (Rust `MessageContent::Text.expire_secs`). A received one counts down from when it is on screen on this device, never from when
 * it was sent, so a late delivery does not shorten it. The bubble side (pulsing edge, time left, slide-out) is in
 * SimpleChatAdapter; the core clears the archive on its own clock (`expire_due`).
 */
object Disappear {
    /** Timer choices in seconds; the labels are `R.array.disappear_stop_labels`. The desktop has the same stops. */
    private val STOPS = intArrayOf(30, 5 * 60, 3600, 8 * 3600, 24 * 3600, 7 * 24 * 3600, 28 * 24 * 3600)
    private const val HOLD_MS = 3000L

    /** The stop picked last, offered first next time (this process only). */
    private var lastStop = 2

    /** Time left, never more than the timer: a received message not on screen yet holds a later cap. */
    private fun leftMs(item: SimpleChatAdapter.Item, now: Long): Long =
        (item.expireAtMs - now).coerceIn(0L, item.expireSecs * 1000L)

    /** "42 s", "12 min", "5 h", "3 days", rounded up. */
    fun formatLeft(ctx: Context, item: SimpleChatAdapter.Item, now: Long): String {
        val s = (leftMs(item, now) + 999) / 1000
        return when {
            s < 60 -> ctx.getString(R.string.disappear_left_s, s.toInt())
            s < 3600 -> ctx.getString(R.string.disappear_left_min, ((s + 59) / 60).toInt())
            s < 86_400 -> ctx.getString(R.string.disappear_left_h, ((s + 3599) / 3600).toInt())
            else -> ctx.getString(R.string.disappear_left_d, ((s + 86_399) / 86_400).toInt())
        }
    }

    /** A received message from a live event: (timer, expiry) from the event JSON; (0, 0) for an ordinary message. */
    fun fromEvent(obj: org.json.JSONObject): Pair<Int, Long> {
        val secs = obj.optLong("expire_secs", 0L).toInt()
        if (secs <= 0) return 0 to 0L
        return secs to (obj.optLong("expire_at_ms", 0L).takeIf { it > 0 } ?: (System.currentTimeMillis() + secs * 1000L))
    }

    /**
     * A press on [button] held for 3 s opens the disappearing-mode picker instead of sending. A normal tap still sends at once
     * (the button's own click listener). [current]: the chat's mode now (0 = off); [onPick] gets the new mode (0 = off).
     */
    @SuppressLint("ClickableViewAccessibility")
    fun attachHold(button: View, current: () -> Int, onPick: (Int) -> Unit) {
        val ui = Handler(Looper.getMainLooper())
        var held = false
        val open = Runnable {
            held = true
            button.isPressed = false
            button.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
            pick(button.context, current(), onPick)
        }
        button.setOnTouchListener { _, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    held = false
                    ui.postDelayed(open, HOLD_MS)
                    false
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    ui.removeCallbacks(open)
                    // The picker is open: this release must not send as well.
                    if (held) {
                        held = false
                        button.isPressed = false
                        true
                    } else {
                        false
                    }
                }
                else -> false
            }
        }
    }

    /** The Send button shows whether the chat's messages disappear. */
    fun showMode(button: android.widget.ImageView, secs: Int) {
        button.setImageResource(if (secs > 0) R.drawable.ic_send_timer else R.drawable.ic_send_cloud)
    }

    private fun pick(ctx: Context, current: Int, onPick: (Int) -> Unit) {
        val labels = ctx.resources.getStringArray(R.array.disappear_stop_labels)
        val on = STOPS.indexOf(current)
        val start = if (on >= 0) on else lastStop
        val pad = (16 * ctx.resources.displayMetrics.density).toInt()
        val value = TextView(ctx).apply {
            text = labels[start]
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(com.google.android.material.color.MaterialColors.getColor(ctx, androidx.appcompat.R.attr.colorPrimary, 0))
        }
        val slider = Slider(ctx).apply {
            valueFrom = 0f
            valueTo = (STOPS.size - 1).toFloat()
            stepSize = 1f
            this.value = start.toFloat()
            setLabelFormatter { labels[it.toInt().coerceIn(0, STOPS.size - 1)] }
            addOnChangeListener { _, v, _ -> value.text = labels[v.toInt().coerceIn(0, STOPS.size - 1)] }
        }
        val hint = TextView(ctx).apply {
            setText(R.string.disappear_hint)
            alpha = 0.7f
            textSize = 13f
        }
        val content = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad + pad / 2, pad / 2, pad + pad / 2, 0)
            addView(value)
            addView(slider)
            addView(hint)
        }
        val dialog = AlertDialog.Builder(ctx)
            .setTitle(R.string.disappear_title)
            .setView(content)
            .setPositiveButton(if (on >= 0) R.string.disappear_change else R.string.disappear_turn_on) { _, _ ->
                lastStop = slider.value.toInt().coerceIn(0, STOPS.size - 1)
                onPick(STOPS[lastStop])
            }
            .setNegativeButton(android.R.string.cancel, null)
        if (on >= 0) dialog.setNeutralButton(R.string.disappear_turn_off) { _, _ -> onPick(0) }
        dialog.show()
    }

    /** A disappearing message on screen: copy, forward, reply quote, save and share are not offered for it. */
    fun locked(item: SimpleChatAdapter.Item) = item.expireSecs > 0

    /** `expireAtMs` of my own message sent now with [secs] (0 = an ordinary one). */
    fun atFor(secs: Int): Long = if (secs > 0) System.currentTimeMillis() + secs * 1000L else 0L

    /** Stamps my own new bubble with the chat's mode, the same timer the core gave the message. */
    fun stamp(item: SimpleChatAdapter.Item, secs: Int): SimpleChatAdapter.Item {
        if (secs > 0) {
            item.expireSecs = secs
            item.expireAtMs = System.currentTimeMillis() + secs * 1000L
        }
        return item
    }
}
