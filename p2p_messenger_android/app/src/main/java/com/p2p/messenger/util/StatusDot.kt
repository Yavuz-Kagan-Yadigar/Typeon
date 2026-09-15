package com.p2p.messenger.util

import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.res.ColorStateList
import android.view.View
import androidx.core.content.ContextCompat

/**
 * Spec dışı, kullanıcı isteği: bağlantı durumunu (karşı taraf VEYA bu
 * cihazın kendisi) küçük renkli bir nokta + "bağlanılıyor" durumunda nabız
 * gibi atan (pulse) bir animasyonla gösterir. ChatActivity'de KARŞI
 * TARAFIN durumu (`dotPeerStatus`) VE bu cihazın kendi durumu
 * (`dotOwnStatus`) için, GroupChatActivity'de sadece bu cihazın kendi
 * durumu için kullanılır — üçünün de animator yaşam döngüsü (başlat/
 * durdur/`onPause`'da iptal) birebir aynı olduğundan tek bir yerde.
 */
class PulsingStatusDot(private val dot: View) {
    private var pulseAnimator: ObjectAnimator? = null

    private var lastColorRes = 0
    private var lastPulsing = false

    fun update(colorRes: Int, pulsing: Boolean) {
        // Polled every 0.8-2 s: an unchanged state must not restart the pulse
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

    /** bkz. `Activity.onPause` — Activity görünür değilken bir pulse
     *  animasyonunun arka planda vsync'e kayıtlı kalmaması için. */
    fun cancelPulse() {
        pulseAnimator?.cancel()
    }
}
