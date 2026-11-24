package com.p2p.messenger.util

import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

/**
 * When the keyboard opens, the chat compensates for its height, so the bottom message stays visible. When the keyboard closes, it
 * takes that back.
 *
 * WHY `android:windowSoftInputMode="adjustResize"` ALONE IS NOT ENOUGH: on the project's test phone (Redmi Note 8 Pro, Android 16), it was
 * measured with `adb shell dumpsys window`. Even with `adjustResize` declared, the window was not really resized. The manifest entry is still
 * REQUIRED: otherwise the default `adjustPan` takes effect, which pans the whole window, and it overlaps the padding this code adds.
 *
 * ONE MEASUREMENT SOURCE: `WindowInsetsCompat.Type.ime()`. As a fallback, `getWindowVisibleDisplayFrame` (the area of the window not covered
 * by the keyboard) was tried on a real device and then removed. On this screen that metric returned meaningless large values for the window
 * height and broke the layout completely: the input bar jumped to the top of the screen. Heuristics of this kind had failed in this project
 * before. Insets are the only correct source. The reason it did not work on the phone was not the measurement. It was the missing
 * `adjustResize`, which made the window PAN.
 *
 * SCROLLING: not "scroll to the bottom". The first version did that, and on the device it was wrong. Opening the keyboard while the user had
 * scrolled up threw the list to the very bottom. The right behaviour is COMPENSATION. The content scrolls by exactly as much as the list shrank.
 * The message at the bottom of the screen stays at the bottom. When the keyboard closes (negative delta), it is taken back automatically.
 * See the `addOnLayoutChangeListener` comment for the details, and for why the insets delta is NOT used.
 */
object KeyboardInsets {

    fun attach(root: View, recycler: RecyclerView) {
        val basePaddingBottom = root.paddingBottom
        // See the `addOnLayoutChangeListener` note below. A snapshot taken when the insets are dispatched (before the layout runs): was the user
        // at the bottom of the list at that moment?
        var wasNearBottomBeforeResize = true

        // The insets listener is not reliable on every phone: the chat root sits inside a DrawerLayout that can consume the insets. So the flag
        // is also tracked from real scrolls. Calls with dy == 0 (sent after every layout, including the resize itself) do not touch it, so it
        // still holds the state from before the resize when the layout listener runs.
        recycler.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                if (dy != 0) wasNearBottomBeforeResize = isRecyclerNearBottom(rv)
            }
        })
        // New items at the end while the user was at the bottom keep them there.
        recycler.adapter?.registerAdapterDataObserver(object : RecyclerView.AdapterDataObserver() {
            override fun onItemRangeInserted(positionStart: Int, itemCount: Int) {
                if (!recycler.canScrollVertically(1)) wasNearBottomBeforeResize = true
            }
        })

        ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
            val navigation = insets.getInsets(WindowInsetsCompat.Type.navigationBars()).bottom
            // The navigation bar is already part of the root padding. Only the part BEYOND it belongs to the keyboard.
            val extra = (ime - navigation).coerceAtLeast(0)
            wasNearBottomBeforeResize = isRecyclerNearBottom(recycler)
            root.setPadding(
                root.paddingLeft,
                root.paddingTop,
                root.paddingRight,
                basePaddingBottom + extra
            )
            insets
        }

        /*
         * The compensation is derived from the REAL size change of the list, not from the insets delta.
         *
         * An earlier version said "scroll by as much as the keyboard opened" and did not work on the device. The user showed it with a
         * screenshot: the input bar moved up, but the list did not scroll, and the bottom messages were cut off. The cause was timing. The
         * scroll amount was accumulated when the padding was assigned. But a layout pass triggered while the list size had NOT changed yet
         * came in between. The scroll was consumed there, and when the real shrink happened, the layout manager restored its anchor and
         * cancelled the effect.
         *
         * This version has no "pending amount" ledger. Whenever the list shrinks by N pixels, the content scrolls by exactly N pixels at that
         * moment (it scrolls the other way if it grows). By definition, this keeps "the message at the bottom of the screen stays at the
         * bottom", and it needs no separate branch for opening or closing the keyboard.
         */
        recycler.addOnLayoutChangeListener { _, _, top, _, bottom, _, oldTop, _, oldBottom ->
            val previousHeight = oldBottom - oldTop
            // No previous height on the first layout. Scrolling from 0 would make the list jump when it opens.
            if (previousHeight == 0) return@addOnLayoutChangeListener
            val delta = previousHeight - (bottom - top)
            if (delta == 0) return@addOnLayoutChangeListener
            if (wasNearBottomBeforeResize) {
                // When the list GROWS (the keyboard closes), LinearLayoutManager already compensates by itself, so the bottom gap is not left.
                // It re-anchors the content end to the viewport end, without any `scrollBy` call from us. When the list SHRINKS (the keyboard
                // opens), that self-compensation does NOT happen. The LayoutManager keeps the top anchor fixed and silently clips the content
                // below. So a pixel delta is really needed there (the `else` branch below).
                // But if we also apply the same pixel delta on GROW while at the bottom, it stacks on top of the LayoutManager's own compensation.
                // That dragged the list up beyond the real bottom, which was the reported bug. So while at the bottom on grow, the list is pinned
                // straight to the bottom, instead of doing pixel work. It uses the same two-pass pattern (scrollToPosition, then the remaining
                // difference) as `ChatActivity.onNewIncomingItemAdded`.
                recycler.post {
                    val adapter = recycler.adapter
                    val last = (adapter?.itemCount ?: 0) - 1
                    if (last < 0) return@post
                    recycler.scrollToPosition(last)
                    recycler.post {
                        val lm = recycler.layoutManager as? LinearLayoutManager ?: return@post
                        val view = lm.findViewByPosition(last) ?: return@post
                        val overshoot = view.bottom - (recycler.height - recycler.paddingBottom)
                        if (overshoot != 0) recycler.scrollBy(0, overshoot)
                    }
                }
            } else {
                // `post`: a `scrollBy` cannot run while a layout is in progress (RecyclerView rejects it).
                recycler.post { recycler.scrollBy(0, delta) }
            }
        }

        // The listener does not see insets sent BEFORE it was installed. If the screen was recreated while the keyboard was open, the first
        // padding would never have been applied.
        ViewCompat.requestApplyInsets(root)
    }

    /** Same definition of "near the bottom" as `ChatActivity.isRecyclerNearBottom`, rewritten here so this general-purpose util object does
     *  not depend on an Activity. */
    private fun isRecyclerNearBottom(recycler: RecyclerView): Boolean {
        val adapter = recycler.adapter ?: return true
        if (adapter.itemCount == 0) return true
        val lm = recycler.layoutManager as? LinearLayoutManager ?: return true
        val lastVisible = lm.findLastVisibleItemPosition()
        return lastVisible == RecyclerView.NO_POSITION || lastVisible >= adapter.itemCount - 2
    }
}
