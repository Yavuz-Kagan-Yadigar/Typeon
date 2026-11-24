package com.p2p.messenger.util

import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.res.ColorStateList
import android.view.View
import androidx.core.content.ContextCompat

/**
 * Shows the connection state (of the other side, OR of this device itself) as a small coloured dot. While "connecting", the dot pulses.
 * ChatActivity uses it for the PEER state (`dotPeerStatus`) and for this device's own state (`dotOwnStatus`). GroupChatActivity uses it only for
 * this device's own state. All three share the same animator lifecycle (start, stop, cancel in `onPause`), so the logic lives in one place.
 */
class PulsingStatusDot(private val dot: View) {
    private var pulseAnimator: ObjectAnimator? = null

    private var lastColorRes = 0
    private var lastPulsing = false

    fun update(colorRes: Int, pulsing: Boolean) {
        // Polled every 2 s: an unchanged state must not restart the pulse
        // or re-tint the view (that kept the screen from ever going idle).
        val running = pulseAnimator?.isRunning == true
        if (colorRes == lastColorRes && pulsing == lastPulsing && (!pulsing || running)) return
        lastColorRes = colorRes
        lastPulsing = pulsing
        pulseAnimator?.cancel()
        pulseAnimator = null
        dot.alpha = 1f
        dot.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(dot.context, colorRes))
        if (pulsing) {
            pulseAnimator = ObjectAnimator.ofFloat(dot, View.ALPHA, 1f, 0.25f).apply {
                duration = 700
                repeatCount = ValueAnimator.INFINITE
                repeatMode = ValueAnimator.REVERSE
                start()
            }
        }
    }

    /** See `Activity.onPause`. A pulse animation must not stay registered with vsync in the background while the Activity is not visible. */
    fun cancelPulse() {
        pulseAnimator?.cancel()
    }
}
