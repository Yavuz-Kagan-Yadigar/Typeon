package com.p2p.messenger.ui

import android.os.SystemClock
import android.view.View
import android.widget.Button
import android.widget.Toast
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R

/**
 * "Fetch older history" at the top of the locally loaded messages. The only
 * place a chat screen asks the network for history: scrolling stays local.
 * Shown while the list cannot scroll further up. Rows arrive later: from
 * the server with `history_backfilled`, from peers and own devices with
 * `older_history` / `older_group_history` (see [onBackfilled]).
 */
class FetchHistoryButton(
    private val button: Button,
    private val recycler: RecyclerView,
    private val isGroup: Boolean,
    private val chatKey: () -> String,
    /** Timestamp (ms) of the oldest message on screen, 0 for an empty chat. */
    private val oldestTimestamp: () -> Long,
) {
    private var request = 0
    private var pending = false
    private var repliesUntil = 0L

    /** Several sources answer one request (peer, own devices, server), so
     *  replies count for the whole wait, not only up to the first one. */
    fun acceptsReply(): Boolean = SystemClock.elapsedRealtime() < repliesUntil

    init {
        button.setOnClickListener { fetch() }
        recycler.post { update() }
    }

    /** Call from the list's scroll listener. */
    fun update() {
        button.visibility = if (pending || !recycler.canScrollVertically(-1)) View.VISIBLE else View.GONE
    }

    /** Call on `history_backfilled`. True if this button had asked for it. */
    fun onBackfilled(): Boolean {
        val wasPending = pending
        finish()
        return wasPending
    }

    private fun fetch() {
        if (pending) return
        pending = true
        repliesUntil = SystemClock.elapsedRealtime() + REPLY_WAIT_MS
        val current = ++request
        button.isEnabled = false
        button.setText(R.string.msg_fetch_history_requested)
        val key = chatKey()
        val before = oldestTimestamp()
        // L-189: a stuck JNI call must not leave the button disabled for good
        // (finish() also drops the late result, `current` no longer matches).
        button.postDelayed({ if (current == request) finish() }, JNI_WAIT_MS)
        Thread {
            val result = try {
                P2PLib.fetchServerHistory(key, isGroup, before)
            } catch (e: Throwable) {
                "Error: ${e.message}"
            }
            button.post {
                if (current != request || !button.isAttachedToWindow) return@post
                if (result != "OK") {
                    finish()
                    Toast.makeText(button.context, com.p2p.messenger.util.coreErrorText(button.context, result), Toast.LENGTH_LONG).show()
                } else {
                    // No reply (server offline, nothing older): the button comes back.
                    button.postDelayed({ if (current == request) finish() }, REPLY_WAIT_MS)
                }
            }
        }.start()
    }

    private fun finish() {
        request++
        pending = false
        button.isEnabled = true
        button.setText(R.string.action_fetch_older_history)
        update()
    }

    private companion object {
        const val REPLY_WAIT_MS = 20_000L
        const val JNI_WAIT_MS = 30_000L
    }
}
