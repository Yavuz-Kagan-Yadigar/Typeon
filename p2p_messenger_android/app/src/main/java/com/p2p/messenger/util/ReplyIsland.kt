package com.p2p.messenger.util

import android.app.Activity
import android.view.View
import android.view.ViewGroup
import com.p2p.messenger.R

/**
 * Kullanıcı isteği: alıntı açıkken alıntı ile alt çubuk tek bir "ada" içinde
 * (bkz. activity_chat.xml `viewReplyIsland`). Ada çubuğun ETRAFINA [INSET_DP]
 * taşar; çubuğun boyutu ve konumu hiç değişmez (kullanıcı: "adacık alt pili
 * yeniden boyutlandırmamalı"). Kenarlar çubuğun gerçek konumundan
 * hesaplanıyor ve çubuk yer değiştirdikçe (klavye, çok satırlı yazı)
 * yeniden hesaplanıyor.
 */
object ReplyIsland {
    private const val INSET_DP = 6

    fun set(activity: Activity, visible: Boolean) {
        val island = activity.findViewById<View>(R.id.viewReplyIsland)
        val input = activity.findViewById<View>(R.id.layoutMessageInput)
        island.visibility = if (visible) View.VISIBLE else View.GONE
        if (!visible) return
        if (island.getTag(R.id.viewReplyIsland) == null) {
            island.setTag(R.id.viewReplyIsland, true)
            input.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ ->
                if (island.visibility == View.VISIBLE) place(island, input)
            }
        }
        place(island, input)
    }

    private fun place(island: View, input: View) {
        val parent = island.parent as? ViewGroup ?: return
        if (parent.width == 0) {
            island.post { place(island, input) }
            return
        }
        val inset = (INSET_DP * island.resources.displayMetrics.density).toInt()
        val start = (input.left - inset - parent.paddingLeft).coerceAtLeast(0)
        val end = (parent.width - parent.paddingRight - input.right - inset).coerceAtLeast(0)
        val bottom = (parent.height - parent.paddingBottom - input.bottom - inset).coerceAtLeast(0)
        val lp = island.layoutParams as ViewGroup.MarginLayoutParams
        if (lp.leftMargin == start && lp.rightMargin == end && lp.bottomMargin == bottom) return
        lp.setMargins(start, lp.topMargin, end, bottom)
        lp.marginStart = start
        lp.marginEnd = end
        island.layoutParams = lp
    }
}
