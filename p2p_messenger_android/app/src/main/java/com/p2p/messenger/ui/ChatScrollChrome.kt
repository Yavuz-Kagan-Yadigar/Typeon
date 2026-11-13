package com.p2p.messenger.ui

import android.content.Context
import android.text.format.DateUtils
import android.view.View
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.R

/** Messages (texts + attachments together) per history page, first load included. */
const val CHAT_PAGE_SIZE = 100

/**
 * Merges one page of texts and one page of attachments and keeps the newest
 * [CHAT_PAGE_SIZE] by `timestamp` (the clock both archive cursors use). What is
 * cut off is older than everything kept, so the next older page reads it again.
 * The cut never splits a millisecond: the cursors are strict `<`, so a row
 * sharing the oldest kept timestamp would be skipped for good.
 */
fun newestPage(
    texts: List<SimpleChatAdapter.Item>,
    attachments: List<SimpleChatAdapter.Item>
): List<SimpleChatAdapter.Item> {
    val all = (texts + attachments).sortedByDescending { it.timestamp }
    if (all.size <= CHAT_PAGE_SIZE) return all
    val floor = all[CHAT_PAGE_SIZE - 1].timestamp
    return all.takeWhile { it.timestamp >= floor }
}

/** "Today", "Yesterday", or the date (the year only when it is not this year). */
fun chatDayLabel(context: Context, timestampMs: Long): String = when {
    DateUtils.isToday(timestampMs) -> context.getString(R.string.lbl_today)
    DateUtils.isToday(timestampMs + DateUtils.DAY_IN_MILLIS) -> context.getString(R.string.lbl_yesterday)
    else -> DateUtils.formatDateTime(context, timestampMs, DateUtils.FORMAT_SHOW_DATE)
}

/** Shows the date of the top visible message in [pill] while [recycler] scrolls. */
fun attachScrollDatePill(recycler: RecyclerView, pill: TextView, timestampAt: (Int) -> Long?) {
    val hide = Runnable { pill.animate().alpha(0f).withEndAction { pill.visibility = View.GONE } }
    recycler.addOnScrollListener(object : RecyclerView.OnScrollListener() {
        override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
            if (dy == 0) return
            val pos = (rv.layoutManager as? LinearLayoutManager)?.findFirstVisibleItemPosition() ?: return
            val ts = timestampAt(pos) ?: return
            pill.text = chatDayLabel(rv.context, ts)
            pill.animate().cancel()
            pill.alpha = 1f
            pill.visibility = View.VISIBLE
            pill.removeCallbacks(hide)
        }

        override fun onScrollStateChanged(rv: RecyclerView, newState: Int) {
            pill.removeCallbacks(hide)
            if (newState == RecyclerView.SCROLL_STATE_IDLE) pill.postDelayed(hide, 1500)
        }
    })
}
