package com.p2p.messenger.util

import android.app.Activity
import android.view.View
import android.view.ViewGroup
import com.p2p.messenger.R

/**
 * Kullanıcı isteği: alıntı açıkken alıntı ile alt çubuk tek bir "ada" içinde
 * (bkz. activity_chat.xml `viewReplyIsland`). Adayı gösterir ve çubuğu adanın
 * içine çeker: çubuk kenarlardan ve alttan [INSET_DP] içeri girer, böylece
 * etrafında adanın rengi bir çerçeve gibi görünür. Kapatınca eski yerine döner.
 */
object ReplyIsland {
    private const val INSET_DP = 6

    fun set(activity: Activity, visible: Boolean) {
        activity.findViewById<View>(R.id.viewReplyIsland).visibility = if (visible) View.VISIBLE else View.GONE
        val input = activity.findViewById<View>(R.id.layoutMessageInput)
        val inset = if (visible) (INSET_DP * activity.resources.displayMetrics.density).toInt() else 0
        val lp = input.layoutParams as ViewGroup.MarginLayoutParams
        if (lp.leftMargin == inset && lp.bottomMargin == inset) return
        lp.setMargins(inset, lp.topMargin, inset, inset)
        lp.marginStart = inset
        lp.marginEnd = inset
        input.layoutParams = lp
    }
}
