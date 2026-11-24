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

/**
 * One-to-one chat screen with a single contact.
 *
 * Messages arrive from `P2PService`'s `pollNetwork` loop through `messageListener`. Each event is JSON tagged with `{"type":...}` (see Rust `receive_message`).
 * This screen handles ONLY the events of its own peer (`peer`) that do NOT belong to a group. See `messageListener`.
 *
 * Message history is kept encrypted on each device, independent of node mode (see Rust `archive_message` / MessageHistoryManager).
 * On open, this screen loads the local history first (`loadHistoryIfAvailable`), then asks the other side for what is missing (`requestHistorySync`).
 */
class ChatActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PEER_DEVICE_FINGERPRINT = "peer_device_fingerprint"
        const val EXTRA_PEER_DISPLAY_NAME = "peer_display_name"

        /** When the list is scrolled this close to the top, the next page is requested. */
        private const val LOAD_OLDER_HISTORY_THRESHOLD = 3

        private const val SESSION_POLL_INTERVAL_MS = 800L
        /** After the handshake completes, polling becomes sparser. See `sessionPollRunnable`. */
        private const val STEADY_STATE_POLL_INTERVAL_MS = 5_000L
        private const val OWN_STATUS_POLL_INTERVAL_MS = 2_000L

        /** See Rust `MAX_ATTACHMENT_SIZE`: the same upper limit. */
        internal const val MAX_ATTACHMENT_SIZE = 4L * 1024 * 1024 * 1024

        /** See `maybePlayTyphoonEffect`: a message arriving in a chat that has been quiet this long counts as a 'wake-up'. */
        internal const val TYPHOON_QUIET_WINDOW_MS = 15 * 60 * 1000L

        internal const val PREVIEW_MAX_DIMENSION = 480
        internal const val PREVIEW_JPEG_QUALITY = 85

        /** How long after the user stops typing the 'typing' state is turned off. */
        private const val TYPING_IDLE_TIMEOUT_MS = 3_000L
        /** How long the peer's 'typing' indicator stays on by itself, so that if its turn-off notice is lost it does not hang on screen
         *  (see Rust `TypingIndicator`: this packet is intentionally not retried). */
        internal const val TYPING_INDICATOR_TIMEOUT_MS = 8_000L

        internal const val RECORDING_MIN_DURATION_MS = 500L
        internal const val RECORDING_CANCEL_SWIPE_DP = 120f
        private const val VOICE_PLAYBACK_TICK_MS = 200L

        internal const val REPLY_PREVIEW_MAX_CHARS = 120
        internal const val REPLY_SWIPE_MAX_DP = 72f
        internal const val REPLY_HIGHLIGHT_DURATION_MS = 1_500L
    }

    internal lateinit var peerDeviceFingerprint: String
    private lateinit var whiteboard: WhiteboardPanel
    internal val localMessages = mutableListOf<SimpleChatAdapter.Item>()
    internal lateinit var adapter: SimpleChatAdapter
    internal lateinit var selection: MessageSelection
    internal lateinit var recycler: RecyclerView
    internal lateinit var connectingBanner: View

    internal lateinit var fetchHistoryButton: FetchHistoryButton
    /** Only one older-page request at a time during infinite scroll. */
    internal var isLoadingOlderHistory = false
    /** If the other side also returned an empty page, stop asking. */
    internal var noMoreOlderHistory = false
    /** Set in onResume: the chat is really in front of the user, not just
     *  resumed for a moment underneath the app lock screen. */
    private var resumedUnlocked = false
    internal var toolbarAvatarLoaded = false
    /** Invalidates a voice message still being loaded (see `loadAndPlayVoiceMessage`). */
    internal var voiceLoadRequest = 0

    /** In-chat search: ids of the matching rows (see `runMessageSearch` / `goToSearchMatch`).
     *  Message ids, not list positions: prepending an older page or re-sorting moves every position. */
    internal var searchMatches: List<String> = emptyList()
    internal var currentSearchMatchIndex = -1
    internal lateinit var layoutSearchMessages: View
    internal lateinit var searchMessagesView: SearchView
    internal lateinit var txtSearchMatchCount: TextView

    internal lateinit var txtToolbarTitle: TextView
    private lateinit var txtToolbarSubtitle: TextView
    private lateinit var txtOwnConnectionStatus: TextView
    internal lateinit var imgToolbarAvatar: ImageView
    private lateinit var dotPeerStatus: View
    private lateinit var dotOwnStatus: View
    private lateinit var peerStatusDot: PulsingStatusDot
    private lateinit var ownStatusDot: PulsingStatusDot

    /** The send key is no longer a `Button` with a text glyph. It is a circular `ImageButton` that uses the app's cloud logo as a mask
     *  (see activity_chat.xml btnSend and drawable/ic_send_cloud). */
    internal lateinit var btnSend: ImageButton
    /** This chat's disappearing mode in seconds, 0 = off (top bar clock, see ui/Disappear.kt). */
    internal var disappearSecs = 0
    /** Until a ratchet session exists, the send, attach, camera and voice buttons and `btnSend` are disabled (see `sessionPollRunnable` and `updateComposerLock`).
     *  The text box stays editable, and the banner states the reason. */
    private lateinit var btnAttach: ImageButton
    private lateinit var btnCamera: ImageButton
    internal lateinit var btnVoice: ImageButton
    private lateinit var btnSticker: ImageButton
    private lateinit var txtConnectingBanner: TextView
    /** Updated by `sessionPollRunnable`: `hasActiveSession`, whether a ratchet session has been set up. Nothing can be sent while this is false. */
    internal var handshakeReady = false
    /** The other side deleted its account (`account_deleted`): sending is closed. */
    internal var peerAccountDeleted = false
    /** Limits how often `sessionPollRunnable` nudges the handshake. */
    private var lastEnsureHandshakeAt = 0L
    /** Consecutive failed nudges. For a contact whose handshake never completes, the retry is spaced out to every 30 s after the first 5 tries,
     *  instead of an error and a wake-up every 3 s. */
    private var ensureHandshakeStreak = 0
    /** See `maybePlayTyphoonEffect` and ui.TyphoonParticleView. */
    internal lateinit var typhoonEffect: TyphoonParticleView
    internal lateinit var progressSending: ProgressBar
    internal lateinit var progressOlderHistory: ProgressBar
    /** The contact's avatar in the top bar. It is kept so the full-screen view can open (see `AvatarUtil.openFullscreen`). */
    internal var toolbarAvatarBytes: ByteArray? = null

    internal lateinit var layoutTypingIndicator: View
    internal val typingHandler = Handler(Looper.getMainLooper())
    /** See `TYPING_INDICATOR_TIMEOUT_MS`. */
    internal val clearPeerTypingRunnable = Runnable { layoutTypingIndicator.visibility = View.GONE }
    internal var isTypingSent = false
    /** See `TYPING_IDLE_TIMEOUT_MS`. */
    private val stopTypingRunnable = Runnable { sendTypingState(false) }

    internal lateinit var fabScrollToBottom: FloatingActionButton

    internal lateinit var swipeHelper: ItemTouchHelper
    internal val replyHighlightHandler = Handler(Looper.getMainLooper())

    internal var mediaRecorder: MediaRecorder? = null
    private var backgrounded = false
    internal var recordingDialog: AlertDialog? = null

    internal var recordingFile: File? = null
    internal var recordingStartTime: Long = 0
    internal var recordingTouchStartX = 0f
    internal var recordingCancelled = false
    internal lateinit var layoutMessageInput: View
    internal lateinit var layoutRecording: View
    internal lateinit var txtRecordingTimer: TextView
    internal lateinit var txtCancelPill: TextView
    internal val recordingHandler = Handler(Looper.getMainLooper())
    /**
     * The `sendSeenReceipt` and `sendTypingIndicator` JNI calls can queue on the shared core lock, so they do NOT run on the main thread.
     * They run on a single-thread queue (same `DiscardPolicy` pattern as CallActivity: sends after close are dropped silently).
     */
    internal val netPack = java.util.concurrent.ThreadPoolExecutor(
        1, 1, 10L, java.util.concurrent.TimeUnit.SECONDS,
        java.util.concurrent.LinkedBlockingQueue(), java.util.concurrent.ThreadPoolExecutor.DiscardPolicy()
    )
    internal val recordingTimerRunnable = object : Runnable {
        override fun run() {
            val elapsed = android.os.SystemClock.elapsedRealtime() - recordingStartTime
            txtRecordingTimer.text = formatDurationMs(elapsed)
            recordingHandler.postDelayed(this, VOICE_PLAYBACK_TICK_MS)
        }
    }
    internal val requestRecordAudioPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* reddedilse bile devam — basılı tutma o zaman kayıt başlatmaz */ }

    /** Voice message playback: ONE shared `MediaPlayer` for ALL bubbles (see SimpleChatAdapter `updateVoicePlayback`). */
    internal var voicePlayer: MediaPlayer? = null
    internal var voicePlayingFileId: String? = null
    internal var voicePlaybackSpeed = 1f
    internal val voicePlaybackHandler = Handler(Looper.getMainLooper())
    internal val voicePlaybackTickRunnable = object : Runnable {
        override fun run() {
            val player = voicePlayer ?: return
            val fileId = voicePlayingFileId ?: return
            try {
                adapter.tickVoicePlayback(fileId, player.currentPosition, player.duration)
            } catch (e: Exception) {
            }
            voicePlaybackHandler.postDelayed(this, VOICE_PLAYBACK_TICK_MS)
        }
    }

    private val pickFileLauncher = registerForActivityResult(
        com.p2p.messenger.util.OpenMultipleDocumentsAtHome()
    ) { uris -> if (uris.isNotEmpty()) promptAttachmentCaption(uris = uris) { caption, picked ->
        sendPickedFiles(picked.map { it.uri!! to it.hiRes }, caption, takeQuote()).invokeOnCompletion { picked.forEach { it.release() } }
    } }

    internal val stickerPicker = StickerPicker(this, { id, quote -> P2PLib.sendSticker(peerDeviceFingerprint, id, quote?.id ?: "", quote?.preview ?: "") }, ::takeQuote) { item ->
        item.replyToSenderLabel = resolveReplyLabel(item.replyToMessageId)
        adapter.addMessage(Disappear.stamp(item, disappearSecs))
        scrollToBottomNow()
    }

    /**
     * The camera button on the input bar: instant capture and crop (see ui.CameraCaptureActivity). The result comes back through `CapturedImage`,
     * not an `Intent` extra (see the reason there). Only an 'ok or not' flag is carried here.
     */
    private val takePhotoLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            CapturedImage.take()?.let { jpeg -> promptAttachmentCaption(jpeg = jpeg, onRetake = { findViewById<View>(R.id.btnCamera).performClick() }) { caption, picked -> picked.firstOrNull()?.let { onPhotoCaptured(it.jpeg!!, caption, it.hiRes, takeQuote()) } } }
        }
    }

    /** ONLY for API 26-28 (before scoped storage). Never used on API 29+. See the saveToPublicDownloads note. */
    private val requestStoragePermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* reddedilse bile devam — kaydetme o zaman başarısız olur, mesajlaşma etkilenmez */ }

    private val sessionPollHandler = Handler(Looper.getMainLooper())
    /**
     * Connection status indicator. Two different questions are checked separately, because they are different things:
     * - `hasActiveSession` (for the 'Connecting' banner at the top): whether a ratchet session has been set up. It is a cryptographic state.
     *   Once set up it stays true, even if the connection drops: messages are retried until acknowledged (see `awaiting_confirmation`),
     *   so saying 'not connected' would be wrong.
     * - `isPeerConnected` (for the 'Connected' / 'Connecting' status line under the action bar): whether the peer is connected RIGHT NOW. It reads the live
     *   connection book of the swarm, and switches back to 'Connecting' at once when the connection drops.
     *
     * Using `hasActiveSession` for both would keep 'Connected' on even when the other device is offline or unreachable.
     */
    private val sessionPollRunnable: Runnable = object : Runnable {
        override fun run() {
            val self = this
            // JNI calls wait on the core lock: never on the main thread.
            lifecycleScope.launch {
                val (handshakeDone, liveConnected) = withContext(Dispatchers.IO) {
                    val hs = try { P2PLib.hasActiveSession(peerDeviceFingerprint) } catch (e: Exception) { false }
                    val live = try { P2PLib.isPeerConnected(peerDeviceFingerprint) } catch (e: Exception) { false }
                    hs to live
                }
                applySessionState(handshakeDone, liveConnected)
                sessionPollHandler.removeCallbacks(self)
                if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) {
                    sessionPollHandler.postDelayed(
                        self,
                        if (handshakeDone) STEADY_STATE_POLL_INTERVAL_MS else SESSION_POLL_INTERVAL_MS
                    )
                }
            }
        }
    }

    private fun applySessionState(handshakeDone: Boolean, liveConnected: Boolean) {
        connectingBanner.visibility = if (handshakeDone && !peerAccountDeleted) View.GONE else View.VISIBLE
        if (handshakeDone != handshakeReady) {
            handshakeReady = handshakeDone
            updateComposerLock()
            flushPendingShare()
        }
        // No session yet: re-poke the handshake (a no-op once a session exists).
        if (handshakeDone) ensureHandshakeStreak = 0
        val pokeGapMs = if (ensureHandshakeStreak < 5) 3_000L else 30_000L
        if (!handshakeDone && SystemClock.elapsedRealtime() - lastEnsureHandshakeAt > pokeGapMs) {
            lastEnsureHandshakeAt = SystemClock.elapsedRealtime()
            ensureHandshakeStreak++
            lifecycleScope.launch(Dispatchers.IO) {
                try { P2PLib.ensureHandshake(peerDeviceFingerprint) } catch (_: Exception) {}
            }
        }
        val subtitle = getString(if (liveConnected) R.string.lbl_status_online else R.string.lbl_status_offline)
        if (txtToolbarSubtitle.text?.toString() != subtitle) txtToolbarSubtitle.text = subtitle
        updatePeerStatusDot(connecting = !handshakeDone, online = liveConnected)
    }

    /**
     * Until a ratchet session is set up, NOTHING can be sent. The text box stays editable, so a draft can be typed, but the send, attach, camera and voice
     * buttons are disabled and dimmed. The banner states the reason clearly.
     */
    internal fun updateComposerLock() {
        val enabled = handshakeReady && !peerAccountDeleted
        val alpha = if (enabled) 1f else 0.4f
        for (b in listOf(btnSend, btnAttach, btnCamera, btnVoice, btnSticker)) {
            b.isEnabled = enabled
            b.alpha = alpha
        }
        txtConnectingBanner.setText(
            when {
                peerAccountDeleted -> R.string.msg_account_deleted_no_send
                enabled -> R.string.msg_connecting
                else -> R.string.msg_securing_no_send
            }
        )
    }

    /** Every send entry point (send, attach, camera, voice) calls this: if not ready, it shows a short warning and returns `false`. */
    internal fun ensureHandshakeReadyOrWarn(): Boolean {
        if (peerAccountDeleted) {
            Toast.makeText(this, R.string.msg_account_deleted_no_send, Toast.LENGTH_SHORT).show()
            return false
        }
        if (handshakeReady) return true
        Toast.makeText(this, R.string.msg_wait_secure_connection, Toast.LENGTH_SHORT).show()
        return false
    }

    /**
     * A small coloured dot plus a pulsing animation while 'connecting', so the peer's connection state is easier to see at a glance than the plain
     * text of `txtToolbarSubtitle`. Three states:
     * - `connecting` (no ratchet session yet, see `hasActiveSession`): orange, a continuous fade-in and fade-out pulse.
     * - `online` (session set up AND connected right now): green, steady.
     * - otherwise `offline` (session exists but the peer cannot be reached right now): grey, steady.
     */
    private fun updatePeerStatusDot(connecting: Boolean, online: Boolean) {
        val colorRes = when {
            connecting -> R.color.warning
            online -> R.color.online
            else -> R.color.offline
        }
        peerStatusDot.update(colorRes, connecting)
    }

    private val ownStatusPollHandler = Handler(Looper.getMainLooper())
    /** This device's own network state (see ConnectionStatus), as a separate dot and text next to the peer's state. */
    private val ownStatusPollRunnable: Runnable = object : Runnable {
        override fun run() {
            val self = this
            lifecycleScope.launch {
                val status = withContext(Dispatchers.IO) { ConnectionStatus.current(this@ChatActivity) }
                applyOwnStatus(status)
                ownStatusPollHandler.removeCallbacks(self)
                if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) {
                    ownStatusPollHandler.postDelayed(self, OWN_STATUS_POLL_INTERVAL_MS)
                }
            }
        }
    }

    private fun applyOwnStatus(status: ConnectionStatus.Status) {
        if (txtOwnConnectionStatus.text?.toString() != status.text) txtOwnConnectionStatus.text = status.text
        val colorRes = when (status.level) {
            ConnectionStatus.Level.CONNECTED -> R.color.online
            ConnectionStatus.Level.CONNECTING -> R.color.warning
            ConnectionStatus.Level.PROBLEM -> R.color.danger
        }
        ownStatusDot.update(colorRes, status.level == ConnectionStatus.Level.CONNECTING)
    }

    /**
     * Attachments and messages sent to groups must not appear as 1:1 traffic as well.
     * If `group_id` / `group_message_local_id` is set (the event belongs to a GROUP), the 1:1 screen never handles it.
     * GroupChatActivity routes it to the right screen by its own `group_id` match.
     */
    internal val messageListener: (String) -> Unit = { json ->
        try {
            val obj = JSONObject(json)
            val isForThisPeer = obj.optString("peer") == peerDeviceFingerprint
            val isGroupScoped = !obj.isNull("group_id") || !obj.isNull("group_message_local_id")
            // "history_backfilled" covers several chats and carries no peer.
            // Nor does "stickers_changed" (my sticker store, any chat).
            if ((isForThisPeer && !isGroupScoped) || obj.optString("type") == "history_backfilled"
                || obj.optString("type") == "stickers_changed" || obj.optString("type") == "file_evicted"
            ) {
                runOnUiThread { handleIncomingEvent(obj) }
            }
        } catch (e: Exception) {
            // Unparseable event: ignore silently.
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)
        whiteboard = WhiteboardPanel(this, findViewById(R.id.whiteboardHost), findViewById(R.id.whiteboardHandle))
        ThemePrefs.applyChatBackground(this)
        // See the util.ChatListDrawer docs.
        com.p2p.messenger.util.ChatListDrawer.setup(this) {
            // Back with the search bar open closes the bar, not the chat.
            (layoutSearchMessages.visibility == View.VISIBLE).also { if (it) toggleMessageSearch() }
        }

        connectingBanner = findViewById(R.id.layoutConnecting)
        layoutTypingIndicator = findViewById(R.id.layoutTypingIndicator)
        fabScrollToBottom = findViewById(R.id.fabScrollToBottom)
        fabScrollToBottom.setOnClickListener { scrollToBottomNow() }
        recycler = findViewById(R.id.recyclerMessages)
        // This must run BEFORE `addOnLayoutChangeListener` below, which uses it. Otherwise the lateinit property is accessed before init
        // (UninitializedPropertyAccessException). That crashed every ChatActivity open.
        layoutMessageInput = findViewById(R.id.layoutMessageInput)
        setupMessageSearch()

        adapter = SimpleChatAdapter(localMessages)
        adapter.onItemLongPress = { item -> showEditDeleteDialog(item) }
        adapter.onDisappearStarted = {
            val peer = peerDeviceFingerprint
            Thread { try { P2PLib.startDisappearCountdown(peer, "") } catch (e: Throwable) { } }.start()
        }
        // A disappearing message on screen: screenshots, screen recording and the recents thumbnail come out black.
        // Below API 33 the whole screen stays secure (P2PApplication), so it is never cleared there.
        adapter.onDisappearPresent = { on ->
            if (on || android.os.Build.VERSION.SDK_INT >= 33) com.p2p.messenger.P2PApplication.setSecure(this, on)
        }
        selection = MessageSelection(this, adapter, { saveAttachmentToDownloads(it) }) { P2PLib.deleteMessage(peerDeviceFingerprint, it) }
        adapter.onAttachmentClick = { item -> onAttachmentClicked(item) }
        adapter.onAttachmentLongClick = { item -> onAttachmentLongClicked(item) }
        adapter.onReactionsClick = { item -> showReactionsDialog(item) }
        adapter.onItemDoubleTap = { item, bubble -> showReactionPicker(item, bubble) }
        adapter.onSeenByClick = { item -> showSeenByDialog(item.messageId) }
        adapter.onReplyPreviewClick = { targetMessageId -> scrollToMessage(targetMessageId) }
        adapter.peerName = { txtToolbarTitle.text?.toString() }
        stickerPicker.provideBubbleImages(adapter)

        val chatLayoutManager = LinearLayoutManager(this)
        recycler.layoutManager = chatLayoutManager
        recycler.adapter = adapter
        adapter.warmPool(recycler)
        // Message bubbles flickered: tick, seen and reaction updates arrive through `notifyItemChanged`, and the default animator cross-fades each bubble
        // between its old and new state, so change animations are off. A new message at the bottom gets a small pop.
        recycler.itemAnimator = MessageItemAnimator()
        // The single outer outline of merged bubbles. See MergedBubbleDecoration for why each bubble's own background is not enough.
        recycler.addItemDecoration(MergedBubbleDecoration(adapter))
        setupSwipeToReply()

        // Infinite scroll: when the top of the list is reached, the next 'older' page is requested (see `loadOlderHistory`).
        recycler.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                if (chatLayoutManager.findFirstVisibleItemPosition() <= LOAD_OLDER_HISTORY_THRESHOLD) {
                    loadOlderHistory()
                }
                updateScrollToBottomFabVisibility()
                fetchHistoryButton.update()
            }
        })
        progressOlderHistory = findViewById(R.id.progressOlderHistory)
        attachScrollDatePill(recycler, findViewById(R.id.txtScrollDate)) { localMessages.getOrNull(it)?.timestamp }
        fetchHistoryButton = FetchHistoryButton(findViewById(R.id.btnFetchHistory), recycler, false,
            { peerDeviceFingerprint }, { localMessages.minOfOrNull { it.orderKey } ?: 0L })

        val toolbarTitleView = layoutInflater.inflate(R.layout.actionbar_chat_title, null)
        txtToolbarTitle = toolbarTitleView.findViewById(R.id.txtToolbarTitle)
        txtToolbarSubtitle = toolbarTitleView.findViewById(R.id.txtToolbarSubtitle)
        txtOwnConnectionStatus = toolbarTitleView.findViewById(R.id.txtOwnConnectionStatus)
        imgToolbarAvatar = toolbarTitleView.findViewById(R.id.imgToolbarAvatar)
        dotPeerStatus = toolbarTitleView.findViewById(R.id.dotPeerStatus)
        dotOwnStatus = toolbarTitleView.findViewById(R.id.dotOwnStatus)
        peerStatusDot = PulsingStatusDot(dotPeerStatus)
        ownStatusDot = PulsingStatusDot(dotOwnStatus)
        imgToolbarAvatar.setOnClickListener { AvatarUtil.openFullscreen(this, toolbarAvatarBytes) }
        // Tapping the top bar opens contact info and 'Files and media' (the 1:1 counterpart of the group chat menu, see showGroupInfoDialog).
        toolbarTitleView.setOnClickListener { showContactInfoDialog() }
        supportActionBar?.apply {
            setDisplayShowCustomEnabled(true)
            setDisplayShowTitleEnabled(false)
            setCustomView(
                toolbarTitleView,
                ActionBar.LayoutParams(ActionBar.LayoutParams.MATCH_PARENT, ActionBar.LayoutParams.MATCH_PARENT)
            )
        }

        val input = findViewById<EditText>(R.id.edtMessage)
        com.p2p.messenger.util.Quote.attach(input)
        typhoonEffect = findViewById(R.id.typhoonEffect)
        // When the keyboard opens, the chat compensates for its height so the last message stays visible.
        // See util.KeyboardInsets (why `adjustResize` alone is not enough is documented there, with measurements).
        KeyboardInsets.attach(findViewById(R.id.rootChatLayout), recycler)
        // See `syncRecyclerBottomInset`: the list's bottom padding must follow changes in the height of the bar and the quote pill.
        layoutMessageInput.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ -> syncRecyclerBottomInset() }
        btnSend = findViewById(R.id.btnSend)
        btnAttach = findViewById(R.id.btnAttach)
        btnCamera = findViewById(R.id.btnCamera)
        btnVoice = findViewById(R.id.btnVoice)
        btnSticker = findViewById(R.id.btnSticker)
        txtConnectingBanner = findViewById(R.id.txtConnectingBanner)
        progressSending = findViewById(R.id.progressSending)
        btnSend.setOnClickListener {
            if (!ensureHandshakeReadyOrWarn()) return@setOnClickListener
            val text = input.text.toString()
            if (text.isNotBlank()) {
                input.text.clear()
                sendNewMessage(text)
            }
        }
        input.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                typingHandler.removeCallbacks(stopTypingRunnable)
                if (s.isNullOrBlank()) {
                    sendTypingState(false)
                } else {
                    sendTypingState(true)
                    typingHandler.postDelayed(stopTypingRunnable, TYPING_IDLE_TIMEOUT_MS)
                }
            }
        })

        btnAttach.setOnClickListener {
            if (!ensureHandshakeReadyOrWarn()) return@setOnClickListener
            // The system file picker opens in ANOTHER process. See AppLock.beginTrustedExcursion (the password must not be asked on return).
            AppLock.beginTrustedExcursion()
            pickFileLauncher.launch(arrayOf("*/*"))
        }

        // Camera directly, next to the attach button.
        btnCamera.setOnClickListener {
            if (!ensureHandshakeReadyOrWarn()) return@setOnClickListener
            takePhotoLauncher.launch(Intent(this, CameraCaptureActivity::class.java))
        }

        btnSticker.setOnClickListener {
            if (!ensureHandshakeReadyOrWarn()) return@setOnClickListener
            stickerPicker.show()
        }

        // See `saveToPublicDownloads`: only needed on versions before scoped storage. API 29+ asks for no permission.
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.Q &&
            ContextCompat.checkSelfPermission(
                this, android.Manifest.permission.WRITE_EXTERNAL_STORAGE
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            AppLock.beginTrustedExcursion()
            requestStoragePermission.launch(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
        }

        layoutRecording = findViewById(R.id.layoutRecording)
        txtRecordingTimer = findViewById(R.id.txtRecordingTimer)
        txtCancelPill = findViewById(R.id.txtCancelPill)
        setupVoiceRecordButton()

        adapter.onVoicePlayClick = { item -> onVoicePlayClicked(item) }
        adapter.onVoiceSpeedClick = { item -> onVoiceSpeedClicked(item) }
        adapter.onVoiceSeek = { item, positionMs -> onVoiceSeeked(item, positionMs) }

        // Not on a restore: the same intent would send the files again.
        if (!bindToIntent(intent)) finish() else if (savedInstanceState == null) consumeShare(intent)
    }

    /** Shared files go out under the same lock as every send button: the
     *  chat has just opened and the handshake is not proven yet. */
    internal var pendingShare: List<Uri> = emptyList()
    internal var pendingForward: List<com.p2p.messenger.util.Forward.Pending>? = null

    // ---------------------------------------------------------------
    // Binding the chat and sending
    // ---------------------------------------------------------------

    /**
     * Binds this screen to the contact in the Intent. If it returns `false`, the Intent cannot be used (no fingerprint) and the screen closes.
     * Binding to the SAME contact again (for example a second Intent from a notification) does NOT reset the state. The screen is cleared only
     * when switching to a different contact.
     */
    private fun bindToIntent(intent: Intent): Boolean {
        val newPeer = intent.getStringExtra(EXTRA_PEER_DEVICE_FINGERPRINT) ?: return false
        val displayName = intent.getStringExtra(EXTRA_PEER_DISPLAY_NAME) ?: newPeer.take(8)
        txtToolbarTitle.text = displayName
        // The photo is not loaded yet: start with the initial-letter badge, and replace it when the background job below fetches the real avatar.
        AvatarUtil.renderInto(imgToolbarAvatar, null, displayName)

        if (::peerDeviceFingerprint.isInitialized && peerDeviceFingerprint == newPeer) return true

        peerDeviceFingerprint = newPeer
        whiteboard.bind(peerDeviceFingerprint, "")
        // This chat's disappearing mode. Here, not in onCreate: the peer is only known from this point (and changes with a new contact).
        disappearSecs = 0
        Disappear.showMode(btnSend, 0)
        lifecycleScope.launch {
            val secs = withContext(Dispatchers.IO) { try { P2PLib.getDisappearMode(newPeer, "").toInt() } catch (e: Throwable) { 0 } }
            if (peerDeviceFingerprint == newPeer) {
                disappearSecs = secs
                Disappear.showMode(btnSend, secs)
            }
        }
        P2PService.activeConversationId = peerDeviceFingerprint
        localMessages.clear()
        adapter.notifyDataSetChanged()
        adapter.updateDisappearPulse()
        isLoadingOlderHistory = false
        noMoreOlderHistory = false
        searchMatches = emptyList()
        currentSearchMatchIndex = -1
        if (::layoutSearchMessages.isInitialized) layoutSearchMessages.visibility = View.GONE
        typingHandler.removeCallbacksAndMessages(null)
        layoutTypingIndicator.visibility = View.GONE
        isTypingSent = false
        stopVoicePlayback()
        connectingBanner.visibility = View.VISIBLE
        // New chat: sending stays LOCKED until proven (the first round of the poll).
        handshakeReady = false
        pendingShare = emptyList()
        peerAccountDeleted = false
        toolbarAvatarLoaded = false
        updateComposerLock()
        sessionPollHandler.removeCallbacks(sessionPollRunnable)
        sessionPollHandler.post(sessionPollRunnable)

        // `listContacts` is a JNI call, so it is not run on the main thread.
        lifecycleScope.launch(Dispatchers.IO) {
            val avatarBytes = resolveContactAvatar(newPeer)
            val deleted = isAccountDeleted(newPeer)
            withContext(Dispatchers.Main) {
                // The user may have switched to another chat in the meantime.
                if (peerDeviceFingerprint == newPeer) {
                    if (deleted) {
                        peerAccountDeleted = true
                        updateComposerLock()
                    }
                    toolbarAvatarLoaded = true
                    toolbarAvatarBytes = avatarBytes
                    AvatarUtil.renderInto(imgToolbarAvatar, avatarBytes, displayName)
                }
            }
        }

        loadHistoryIfAvailable(newPeer)

        // Start the handshake if none exists, without waiting for the first message to be typed (see Rust `ensure_handshake`).
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                P2PLib.ensureHandshake(newPeer)
            } catch (e: Exception) {
            }
        }
        return true
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!bindToIntent(intent)) finish() else consumeShare(intent)
    }

    private fun isAccountDeleted(deviceFingerprint: String): Boolean = try {
        val array = JSONArray(P2PLib.listContacts())
        (0 until array.length()).any {
            val obj = array.getJSONObject(it)
            obj.optString("active_device_fingerprint") == deviceFingerprint && obj.optBoolean("account_deleted")
        }
    } catch (e: Exception) {
        false
    }

    /** The avatar loaded when the chat opened. Every "seen" event used to
     *  parse the whole contact list on the UI thread to find it again. */
    internal fun peerAvatar(): ByteArray? =
        if (toolbarAvatarLoaded) toolbarAvatarBytes else null // loaded off-main in the chat-open path; no JNI here

    /** Top bar avatar: finds the contact with this device fingerprint in `listContacts()` and returns its profile photo (or `null`,
     *  in which case `AvatarUtil` shows the initial-letter badge). */
    private fun resolveContactAvatar(deviceFingerprint: String): ByteArray? {
        return try {
            val array = JSONArray(P2PLib.listContacts())
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                if (obj.optString("active_device_fingerprint") == deviceFingerprint) {
                    val avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
                    return avatarHex?.let { hexToBytes(it) }
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    /** The first quote in the input: the attachment or sticker being sent answers it. */
    internal fun takeQuote() = com.p2p.messenger.util.Quote.takeFirst(findViewById(R.id.edtMessage))

    /** See `setupSwipeToReply` / `onSelectedChanged`: the stable id of the target message, captured when the swipe STARTS. */
    internal var swipeStartMessageId: String? = null

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_chat_search, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_search_messages -> {
                toggleMessageSearch()
                true
            }
            R.id.action_voice_call, R.id.action_video_call -> {
                CallActivity.startOutgoing(this, peerDeviceFingerprint, null, item.itemId == R.id.action_video_call)
                true
            }
            R.id.action_disappear -> {
                Disappear.tapClock(this, disappearSecs) { secs -> onDisappearPicked(secs) }
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    /** A mode picked in the disappearing picker (top bar clock). Turned on with text typed, the text goes out at once. */
    private fun onDisappearPicked(secs: Int) {
        val input = findViewById<EditText>(R.id.edtMessage)
        disappearSecs = secs
        Disappear.showMode(btnSend, secs)
        val peer = peerDeviceFingerprint
        lifecycleScope.launch(Dispatchers.IO) { try { P2PLib.setDisappearMode(peer, "", secs.toLong()) } catch (e: Throwable) { } }
        val text = input.text.toString()
        if (secs > 0 && text.isNotBlank() && ensureHandshakeReadyOrWarn()) {
            input.text.clear()
            sendNewMessage(text)
        }
    }

    // ---------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------

    override fun onResume() {
        super.onResume()
        val wasBackgrounded = backgrounded
        backgrounded = false
        if (wasBackgrounded) promptRecordingDecision()
        // A locked app resumes this screen for a moment under the password
        // prompt: nothing was read, so no notification is cleared and no
        // "read up to now" goes out (see onPause too).
        resumedUnlocked = AppLock.isUnlocked()
        if (resumedUnlocked) NotificationHelper.clearForPeer(this, peerDeviceFingerprint)
        ThemePrefs.applyChatBackground(this)
        // The conversation id FIRST: a message that lands between the
        // listener registration and this line would post a notification for
        // the conversation that is already open on the screen.
        P2PService.activeConversationId = peerDeviceFingerprint
        P2PService.addMessageListener(messageListener)
        sessionPollHandler.post(sessionPollRunnable)
        ownStatusPollHandler.post(ownStatusPollRunnable)
        syncMissedMessages()
        // Tell the other side the 'read up to here' boundary as soon as the chat opens. Doing it only in onPause, and only to sibling devices,
        // meant messages delivered by store-and-forward and loaded as history never got a receipt.
        if (resumedUnlocked) scheduleReadWatermark()
        adapter.setOnScreen(resumedUnlocked)
    }

    internal val readWatermarkHandler = Handler(Looper.getMainLooper())
    internal val readWatermarkRunnable = Runnable {
        syncReadStateAsync()
    }
    override fun onPause() {
        super.onPause()
        // finish() in onCreate (no peer in the intent) still delivers onPause.
        if (!::peerDeviceFingerprint.isInitialized) return
        P2PService.removeMessageListener(messageListener)
        if (P2PService.activeConversationId == peerDeviceFingerprint) {
            P2PService.activeConversationId = null
        }
        // Tell the sibling devices AND the other side that this chat was read (see `sync_read_state`, which now has two targets).
        // If a debounced send is pending, cancel it and send one definitive packet now.
        readWatermarkHandler.removeCallbacks(readWatermarkRunnable)
        if (resumedUnlocked) {
            ReadStatePrefs.markRead(this, peerDeviceFingerprint)
            syncReadStateAsync()
        }
        resumedUnlocked = false
        adapter.setOnScreen(false)
        sessionPollHandler.removeCallbacks(sessionPollRunnable)
        ownStatusPollHandler.removeCallbacks(ownStatusPollRunnable)
        peerStatusDot.cancelPulse()
        ownStatusDot.cancelPulse()
        typingHandler.removeCallbacksAndMessages(null)
        // The 8 s cleaner was just cancelled and the peer's "stopped typing"
        // event is missed while paused.
        layoutTypingIndicator.visibility = View.GONE
        sendTypingState(false)
        backgrounded = true // the recording keeps running (service has the microphone type)
        stopVoicePlayback()
    }

    /**
     * The pending callbacks of the handlers hold the adapter (and with it
     * this activity) alive: the reply highlight (1.5 s), the typing cleaner
     * (8 s), the voice tick, the recording timer, the two poll loops and the
     * read watermark. `onPause` only removes SOME of them — a pending
     * callback survived the pause and kept the whole screen alive.
     */
    override fun onDestroy() {
        if (mediaRecorder != null) finishVoiceRecording(send = false)
        typingHandler.removeCallbacksAndMessages(null)
        replyHighlightHandler.removeCallbacksAndMessages(null)
        recordingHandler.removeCallbacksAndMessages(null)
        voicePlaybackHandler.removeCallbacksAndMessages(null)
        sessionPollHandler.removeCallbacksAndMessages(null)
        ownStatusPollHandler.removeCallbacksAndMessages(null)
        readWatermarkHandler.removeCallbacksAndMessages(null)
        netPack.shutdownNow()
        super.onDestroy()
    }
}
