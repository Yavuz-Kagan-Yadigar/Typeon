package com.p2p.messenger.util

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import kotlin.math.cos

/**
 * A slow fade in and out for "something is waiting" marks. Not an animator:
 * an animator redraws at the display rate (60-120 Hz); this steps about 12
 * times a second, which still reads as a smooth fade at this speed.
 * [onFrame] gets 0..1 (0 = at rest, also given once on stop). Stop it while
 * the screen is not visible.
 */
class SlowPulse(private val onFrame: (Float) -> Unit) {
    private val ui = Handler(Looper.getMainLooper())
    private val step = object : Runnable {
        override fun run() {
            val t = (SystemClock.uptimeMillis() % PERIOD_MS) / PERIOD_MS.toFloat()
            onFrame(0.5f - 0.5f * cos(2 * Math.PI * t).toFloat())
            ui.postDelayed(this, STEP_MS)
        }
    }

    var running = false
        set(value) {
            if (field == value) return
            field = value
            ui.removeCallbacks(step)
            if (value) ui.post(step) else onFrame(0f)
        }

    private companion object {
        const val PERIOD_MS = 1600L
        const val STEP_MS = 80L
    }
}
