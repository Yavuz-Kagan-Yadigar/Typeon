package com.p2p.messenger.ui

import com.p2p.messenger.util.safeSaveFileName
import android.Manifest
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Canvas
import android.media.MediaMetadataRetriever
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.media.PlaybackParams
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListPopupWindow
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
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.coreErrorText
import com.p2p.messenger.util.AppRestarter
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.CapturedImage
import com.p2p.messenger.util.promptAttachmentCaption
import com.p2p.messenger.util.ReactionPicker
import com.p2p.messenger.util.ConnectionStatus
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.MAX_FOREIGN_URI_BYTES
import com.p2p.messenger.util.copyToCapped
import com.p2p.messenger.util.KeyboardInsets
import com.p2p.messenger.util.OutgoingMedia
import com.p2p.messenger.util.PlaybackSpeed
import com.p2p.messenger.util.PulsingStatusDot
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
import com.p2p.messenger.ui.GroupChatActivity.Companion.AVATAR_JPEG_QUALITY
import com.p2p.messenger.ui.GroupChatActivity.Companion.AVATAR_MAX_DIMENSION
import com.p2p.messenger.ui.GroupChatActivity.Companion.CONTACT_CACHE_TTL_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.MAX_ATTACHMENT_SIZE
import com.p2p.messenger.ui.GroupChatActivity.Companion.PREVIEW_JPEG_QUALITY
import com.p2p.messenger.ui.GroupChatActivity.Companion.PREVIEW_MAX_DIMENSION
import com.p2p.messenger.ui.GroupChatActivity.Companion.RECORDING_CANCEL_SWIPE_DP
import com.p2p.messenger.ui.GroupChatActivity.Companion.RECORDING_MIN_DURATION_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.REPLY_HIGHLIGHT_DURATION_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.REPLY_PREVIEW_MAX_CHARS
import com.p2p.messenger.ui.GroupChatActivity.Companion.REPLY_SWIPE_MAX_DP
import com.p2p.messenger.ui.GroupChatActivity.Companion.TYPHOON_QUIET_WINDOW_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.TYPING_INDICATOR_TIMEOUT_MS
import com.p2p.messenger.ui.GroupChatActivity.ContactLookup

// GroupChatActivity: scrolling, the scroll-to-bottom button and in-chat search.

/** Same pattern and reasoning as ChatActivity.maybePlayTyphoonEffect. */
internal fun GroupChatActivity.maybePlayTyphoonEffect() {
    val newest = localMessages.lastOrNull() ?: return
    val previous = localMessages.getOrNull(localMessages.size - 2) ?: return
    if (newest.orderKey - previous.orderKey < TYPHOON_QUIET_WINDOW_MS) return
    // The funnel now covers the whole view (see TyphoonParticleView `burst`), so the bubble position does not need to be computed.
    typhoonEffect.burst(
        com.google.android.material.color.MaterialColors.getColor(
            // Not `colorPrimary`: in this theme that is the dark, matte counterpart of the bubble orange, and particles looked dim on the dark background.
            // The colour the user sees as the accent is the bubble background, which is `colorPrimaryContainer`.
            typhoonEffect, com.google.android.material.R.attr.colorPrimaryContainer
        )
    )
}

/** Near the bottom = last item visible (or list empty). */
internal fun GroupChatActivity.isRecyclerNearBottom(): Boolean {
    if (localMessages.isEmpty()) return true
    val lastVisible = (recycler.layoutManager as? LinearLayoutManager)?.findLastVisibleItemPosition()
        ?: return true
    return lastVisible == RecyclerView.NO_POSITION || lastVisible >= localMessages.size - 2
}

/** Auto-scroll only if already near the bottom; otherwise blink the FAB. */
internal fun GroupChatActivity.onNewIncomingItemAdded() {
    if (isRecyclerNearBottom()) {
        scrollToLastSettled()
    } else {
        blinkScrollToBottomFab()
    }
}

/**
 * The bottom bar and the quote pill are transparent outside, so the chat shows at the sides and underneath.
 * The list now extends to the bottom of the screen and the bar floats above it (see activity_chat.xml).
 * So messages do not disappear under the bar, the list gets bottom padding equal to the bar's real height. With `clipToPadding=false`, content scrolls
 * behind the bar but rests above it.
 *
 * A fixed dp value is not enough: the bar grows while a multi-line message is typed, and the quote pill opens and closes. So the padding is recalculated
 * whenever either layout changes.
 */
internal fun GroupChatActivity.syncRecyclerBottomInset() {
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

/** Unconditional scroll, for our own sent messages and attachments. */
internal fun GroupChatActivity.scrollToLastSettled() {
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

internal fun GroupChatActivity.scrollToBottomNow() {
    scrollToLastSettled()
    hideScrollToBottomFab()
}

/** Shown any time the user is scrolled away from the bottom (independent of new messages). */
internal fun GroupChatActivity.updateScrollToBottomFabVisibility() {
    if (isRecyclerNearBottom()) {
        hideScrollToBottomFab()
    } else if (fabScrollToBottom.visibility != View.VISIBLE) {
        com.p2p.messenger.util.ScrollDownFab.style(fabScrollToBottom, newMessage = false)
        fabScrollToBottom.visibility = View.VISIBLE
    }
}

/** New message arrived while scrolled away: steady accent. */
internal fun GroupChatActivity.blinkScrollToBottomFab() {
    com.p2p.messenger.util.ScrollDownFab.style(fabScrollToBottom, newMessage = true)
    fabScrollToBottom.visibility = View.VISIBLE
}

internal fun GroupChatActivity.hideScrollToBottomFab() {
    fabScrollToBottom.visibility = View.GONE
}

/**
 * Same pattern as ChatActivity.setupMessageSearch / toggleMessageSearch / runMessageSearch / moveSearchMatch / goToSearchMatch:
 * in-chat message search, over the `localMessages` currently loaded.
 */
internal fun GroupChatActivity.setupMessageSearch() {
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

internal fun GroupChatActivity.toggleMessageSearch() {
    if (layoutSearchMessages.visibility == View.VISIBLE) {
        layoutSearchMessages.visibility = View.GONE
        searchMessagesView.setQuery("", false)
        runMessageSearch("")
    } else {
        layoutSearchMessages.visibility = View.VISIBLE
        searchMessagesView.isIconified = false
        searchMessagesView.requestFocus()
        // requestFocus() alone doesn't reliably pop the keyboard for a
        // programmatically-focused view — show it explicitly.
        searchMessagesView.post {
            val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
            imm.showSoftInput(searchMessagesView.findFocus(), android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
        }
    }
}

internal fun GroupChatActivity.runMessageSearch(query: String) {
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

internal fun GroupChatActivity.moveSearchMatch(delta: Int) {
    if (searchMatches.isEmpty()) return
    currentSearchMatchIndex = (currentSearchMatchIndex + delta + searchMatches.size) % searchMatches.size
    goToSearchMatch()
}

internal fun GroupChatActivity.goToSearchMatch() {
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
