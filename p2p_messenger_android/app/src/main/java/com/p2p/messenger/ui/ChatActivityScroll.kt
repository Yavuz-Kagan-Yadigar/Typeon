package com.p2p.messenger.ui

import com.p2p.messenger.util.safeSaveFileName
import android.app.AlertDialog
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.media.MediaMetadataRetriever
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.media.MediaScannerConnection
import android.media.PlaybackParams
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.OpenableColumns
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.ActionBar
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SearchView
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.AppRestarter
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.CapturedImage
import com.p2p.messenger.util.promptAttachmentCaption
import com.p2p.messenger.util.ReactionPicker
import com.p2p.messenger.util.ConnectionStatus
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.KeyboardInsets
import com.p2p.messenger.util.NotificationHelper
import com.p2p.messenger.util.OutgoingMedia
import com.p2p.messenger.util.PlaybackSpeed
import com.p2p.messenger.util.PulsingStatusDot
import com.p2p.messenger.util.ReadStatePrefs
import com.p2p.messenger.util.ThemePrefs
import com.p2p.messenger.util.hexToBytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import com.p2p.messenger.ui.ChatActivity.Companion.MAX_ATTACHMENT_SIZE
import com.p2p.messenger.ui.ChatActivity.Companion.PREVIEW_JPEG_QUALITY
import com.p2p.messenger.ui.ChatActivity.Companion.PREVIEW_MAX_DIMENSION
import com.p2p.messenger.ui.ChatActivity.Companion.RECORDING_CANCEL_SWIPE_DP
import com.p2p.messenger.ui.ChatActivity.Companion.RECORDING_MIN_DURATION_MS
import com.p2p.messenger.ui.ChatActivity.Companion.REPLY_HIGHLIGHT_DURATION_MS
import com.p2p.messenger.ui.ChatActivity.Companion.REPLY_PREVIEW_MAX_CHARS
import com.p2p.messenger.ui.ChatActivity.Companion.REPLY_SWIPE_MAX_DP
import com.p2p.messenger.ui.ChatActivity.Companion.TYPHOON_QUIET_WINDOW_MS
import com.p2p.messenger.ui.ChatActivity.Companion.TYPING_INDICATOR_TIMEOUT_MS

// ChatActivity: scrolling, the scroll-to-bottom button and in-chat search.

// ---------------------------------------------------------------
// Scrolling and the 'scroll to bottom' button
// ---------------------------------------------------------------

internal fun ChatActivity.isRecyclerNearBottom(): Boolean {
    if (localMessages.isEmpty()) return true
    val lm = recycler.layoutManager as? LinearLayoutManager ?: return true
    val lastVisible = lm.findLastVisibleItemPosition()
    return lastVisible == RecyclerView.NO_POSITION || lastVisible >= localMessages.size - 2
}

/** A new message arrived: follow it if the user is already at the bottom. If they are scrolled up in the history, keep their position and only blink the FAB. */
internal fun ChatActivity.onNewIncomingItemAdded() {
    if (isRecyclerNearBottom()) {
        scrollToLastSettled()
    } else {
        blinkScrollToBottomFab()
    }
}

/**
 * Plays a light particle 'typhoon' effect when a message is sent or arrives in a chat that has had no messages for the last 15 minutes.
 *
 * The check runs AFTER insertion: it compares the gap between the newest message and the one before it. So callers need no separate 'was it quiet' flag
 * before inserting; one call site is enough.
 *
 * It does not play on the chat's FIRST message (there is no earlier one to compare with): opening an empty chat and writing the first message is not a wake-up moment.
 */
internal fun ChatActivity.maybePlayTyphoonEffect() {
    val newest = localMessages.lastOrNull() ?: return
    val previous = localMessages.getOrNull(localMessages.size - 2) ?: return
    if (newest.orderKey - previous.orderKey < TYPHOON_QUIET_WINDOW_MS) return
    // The effect is drawn over the whole view (see TyphoonParticleView `burst`), so the bubble position is not needed.
    typhoonEffect.burst(
        com.google.android.material.color.MaterialColors.getColor(
            // Not `colorPrimary`: in this theme that is the dark, matte counterpart of the bubble orange, and particles looked dim on the dark background.
            // The colour the user sees as the accent is the bubble background, which is `colorPrimaryContainer`.
            typhoonEffect, com.google.android.material.R.attr.colorPrimaryContainer
        )
    )
}

/**
 * The bottom bar and the quote pill are transparent outside, so the chat shows at the sides and underneath (see activity_chat.xml).
 * The list extends to the bottom of the screen and the bar floats above it. So messages do not disappear under the bar, the list gets bottom padding
 * equal to the bar's real height. With `clipToPadding=false`, content scrolls behind the bar but rests above it.
 *
 * A fixed dp value is not enough: the bar grows while a multi-line message is typed, and the quote pill opens and closes. So the padding is
 * recalculated whenever either layout changes.
 */
internal fun ChatActivity.syncRecyclerBottomInset() {
    // The list runs under the bar: its padding reaches the top of the
    // bar plus room for the typing indicator (its height, the 4 dp
    // spacer under it, 2 dp over it), so it never covers the last message.
    val typing = layoutTypingIndicator
    if (typing.height == 0) typing.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED)
    val gap = maxOf(typing.height, typing.measuredHeight) + (6 * resources.displayMetrics.density).toInt()
    val inset = recycler.bottom - layoutMessageInput.top + gap
    if (recycler.paddingBottom == inset) return
    recycler.setPadding(recycler.paddingLeft, recycler.paddingTop, recycler.paddingRight, inset)
}

internal fun ChatActivity.scrollToLastSettled() {
    // Scroll to the new message when the user is already at the bottom (auto-scroll for new messages).
    // `scrollToPosition` called DIRECTLY is unreliable: the newly added row is not measured yet, so the scroll sometimes does not happen or stops short.
    // `post` runs after layout. The second `post` closes the remaining gap if the bottom edge of a long bubble is still below the screen
    // (the same two-pass correction is used by the keyboard offset, see util.KeyboardInsets).
    val last = localMessages.size - 1
    recycler.post {
        recycler.scrollToPosition(last)
        recycler.post {
            val lm = recycler.layoutManager as? LinearLayoutManager ?: return@post
            val view = lm.findViewByPosition(last) ?: return@post
            val overshoot = view.bottom - (recycler.height - recycler.paddingBottom)
            if (overshoot > 0) recycler.scrollBy(0, overshoot)
        }
    }
}

internal fun ChatActivity.scrollToBottomNow() {
    scrollToLastSettled()
    hideScrollToBottomFab()
}

internal fun ChatActivity.updateScrollToBottomFabVisibility() {
    if (isRecyclerNearBottom()) {
        hideScrollToBottomFab()
    } else if (fabScrollToBottom.visibility != View.VISIBLE) {
        com.p2p.messenger.util.ScrollDownFab.style(fabScrollToBottom, newMessage = false)
        fabScrollToBottom.visibility = View.VISIBLE
    }
}

internal fun ChatActivity.blinkScrollToBottomFab() {
    com.p2p.messenger.util.ScrollDownFab.style(fabScrollToBottom, newMessage = true)
    fabScrollToBottom.visibility = View.VISIBLE
}

internal fun ChatActivity.hideScrollToBottomFab() {
    fabScrollToBottom.visibility = View.GONE
}

// ---------------------------------------------------------------
// In-chat search
// ---------------------------------------------------------------

/**
 * In-chat message search. The search icon in the toolbar (see `onOptionsItemSelected`) opens and closes this row.
 * Search works ONLY on the messages loaded right now (`localMessages`). No network request is made for older history that is not loaded yet;
 * more history loads as the user scrolls up (see `loadOlderHistory`).
 */
internal fun ChatActivity.setupMessageSearch() {
    layoutSearchMessages = findViewById(R.id.layoutSearchMessages)
    searchMessagesView = findViewById(R.id.searchMessages)
    txtSearchMatchCount = findViewById(R.id.txtSearchMatchCount)
    searchMessagesView.setOnQueryTextListener(object : SearchView.OnQueryTextListener {
        override fun onQueryTextSubmit(query: String?): Boolean = false
        override fun onQueryTextChange(newText: String?): Boolean {
            runMessageSearch(newText ?: "")
            return true
        }
    })
    findViewById<ImageButton>(R.id.btnSearchPrev).setOnClickListener { moveSearchMatch(-1) }
    findViewById<ImageButton>(R.id.btnSearchNext).setOnClickListener { moveSearchMatch(1) }
}

internal fun ChatActivity.toggleMessageSearch() {
    if (layoutSearchMessages.visibility == View.VISIBLE) {
        layoutSearchMessages.visibility = View.GONE
        searchMessagesView.setQuery("", false)
        runMessageSearch("")
    } else {
        layoutSearchMessages.visibility = View.VISIBLE
        searchMessagesView.isIconified = false
        searchMessagesView.requestFocus()
        searchMessagesView.post {
            val imm = getSystemService(android.content.Context.INPUT_METHOD_SERVICE) as InputMethodManager
            imm.showSoftInput(searchMessagesView.findFocus(), InputMethodManager.SHOW_IMPLICIT)
        }
    }
}

/** Deleted rows and attachments are not searched. Results start from the NEWEST (users usually look for the latest conversation). */
internal fun ChatActivity.runMessageSearch(query: String) {
    if (query.isBlank()) {
        searchMatches = emptyList()
        currentSearchMatchIndex = -1
        txtSearchMatchCount.text = ""
        adapter.setHighlighted(null)
        return
    }
    searchMatches = localMessages
        .filter { item -> !item.isDeleted && item.attachment == null && item.text.contains(query, ignoreCase = true) }
        .map { it.messageId }
    currentSearchMatchIndex = if (searchMatches.isEmpty()) -1 else searchMatches.size - 1
    goToSearchMatch()
}

internal fun ChatActivity.moveSearchMatch(delta: Int) {
    if (searchMatches.isEmpty()) return
    currentSearchMatchIndex = (currentSearchMatchIndex + delta + searchMatches.size) % searchMatches.size
    goToSearchMatch()
}

internal fun ChatActivity.goToSearchMatch() {
    if (currentSearchMatchIndex < 0 || currentSearchMatchIndex >= searchMatches.size) {
        txtSearchMatchCount.text = getString(R.string.lbl_search_no_matches)
        adapter.setHighlighted(null)
        return
    }
    txtSearchMatchCount.text = "${currentSearchMatchIndex + 1}/${searchMatches.size}"
    val matchId = searchMatches[currentSearchMatchIndex]
    val position = localMessages.indexOfFirst { it.messageId == matchId }
    if (position < 0) return
    recycler.scrollToPosition(position)
    adapter.setHighlighted(matchId)
}
