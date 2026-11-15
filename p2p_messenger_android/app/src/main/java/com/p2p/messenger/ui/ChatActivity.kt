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

        private const val HISTORY_SYNC_LIMIT = 30
        private const val OLDER_HISTORY_REPLY_WAIT_MS = 15_000L
        /** When the list is scrolled this close to the top, the next page is requested. */
        private const val LOAD_OLDER_HISTORY_THRESHOLD = 3

        private const val SESSION_POLL_INTERVAL_MS = 800L
        /** After the handshake completes, polling becomes sparser. See `sessionPollRunnable`. */
        private const val STEADY_STATE_POLL_INTERVAL_MS = 5_000L
        private const val OWN_STATUS_POLL_INTERVAL_MS = 2_000L

        /** See Rust `MAX_ATTACHMENT_SIZE`: the same upper limit. */
        private const val MAX_ATTACHMENT_SIZE = 4L * 1024 * 1024 * 1024

        /** See `maybePlayTyphoonEffect`: a message arriving in a chat that has been quiet this long counts as a 'wake-up'. */
        private const val TYPHOON_QUIET_WINDOW_MS = 15 * 60 * 1000L

        private const val PREVIEW_MAX_DIMENSION = 480
        private const val PREVIEW_JPEG_QUALITY = 85

        /** How long after the user stops typing the 'typing' state is turned off. */
        private const val TYPING_IDLE_TIMEOUT_MS = 3_000L
        /** How long the peer's 'typing' indicator stays on by itself, so that if its turn-off notice is lost it does not hang on screen
         *  (see Rust `TypingIndicator`: this packet is intentionally not retried). */
        private const val TYPING_INDICATOR_TIMEOUT_MS = 8_000L

        private const val RECORDING_MIN_DURATION_MS = 500L
        private const val RECORDING_CANCEL_SWIPE_DP = 120f
        private const val VOICE_PLAYBACK_TICK_MS = 200L

        private const val REPLY_PREVIEW_MAX_CHARS = 120
        private const val REPLY_SWIPE_MAX_DP = 72f
        private const val REPLY_HIGHLIGHT_DURATION_MS = 1_500L
    }

    private lateinit var peerDeviceFingerprint: String
    private lateinit var whiteboard: WhiteboardPanel
    private val localMessages = mutableListOf<SimpleChatAdapter.Item>()
    private lateinit var adapter: SimpleChatAdapter
    private lateinit var selection: MessageSelection
    private lateinit var recycler: RecyclerView
    private lateinit var connectingBanner: View

    /** `requestHistorySync` was sent and the reply is awaited (see `applyHistorySync`; if no reply comes, nothing happens). */
    private var historySyncPending = false
    private lateinit var fetchHistoryButton: FetchHistoryButton
    /** Only one older-page request at a time during infinite scroll. */
    private var isLoadingOlderHistory = false
    /** If the other side also returned an empty page, stop asking. */
    private var noMoreOlderHistory = false
    private var olderHistoryRequest = 0
    private var olderHistoryEmptyReply = false
    /** Set in onResume: the chat is really in front of the user, not just
     *  resumed for a moment underneath the app lock screen. */
    private var resumedUnlocked = false
    private var toolbarAvatarLoaded = false
    /** Invalidates a voice message still being loaded (see `loadAndPlayVoiceMessage`). */
    private var voiceLoadRequest = 0

    /** In-chat search: indices into `localMessages` of the matching rows (see `runMessageSearch` / `goToSearchMatch`). */
    /** Message ids, not list positions: prepending an older page or re-sorting moves every position. */
    private var searchMatches: List<String> = emptyList()
    private var currentSearchMatchIndex = -1
    private lateinit var layoutSearchMessages: View
    private lateinit var searchMessagesView: SearchView
    private lateinit var txtSearchMatchCount: TextView

    private lateinit var txtToolbarTitle: TextView
    private lateinit var txtToolbarSubtitle: TextView
    private lateinit var txtOwnConnectionStatus: TextView
    private lateinit var imgToolbarAvatar: ImageView
    private lateinit var dotPeerStatus: View
    private lateinit var dotOwnStatus: View
    private lateinit var peerStatusDot: PulsingStatusDot
    private lateinit var ownStatusDot: PulsingStatusDot

    /** The send key is no longer a `Button` with a text glyph. It is a circular `ImageButton` that uses the app's cloud logo as a mask
     *  (see activity_chat.xml btnSend and drawable/ic_send_cloud). */
    private lateinit var btnSend: ImageButton
    /** Until a ratchet session exists, the send, attach, camera and voice buttons and `btnSend` are disabled (see `sessionPollRunnable` and `updateComposerLock`).
     *  The text box stays editable, and the banner states the reason. */
    private lateinit var btnAttach: ImageButton
    private lateinit var btnCamera: ImageButton
    private lateinit var btnVoice: ImageButton
    private lateinit var btnSticker: ImageButton
    private lateinit var txtConnectingBanner: TextView
    /** Updated by `sessionPollRunnable`: `hasActiveSession`, whether a ratchet session has been set up. Nothing can be sent while this is false. */
    private var handshakeReady = false
    /** The other side deleted its account (`account_deleted`): sending is closed. */
    private var peerAccountDeleted = false
    /** Limits how often `sessionPollRunnable` nudges the handshake. */
    private var lastEnsureHandshakeAt = 0L
    /** Consecutive failed nudges. For a contact whose handshake never completes, the retry is spaced out to every 30 s after the first 5 tries,
     *  instead of an error and a wake-up every 3 s. */
    private var ensureHandshakeStreak = 0
    /** See `maybePlayTyphoonEffect` and ui.TyphoonParticleView. */
    private lateinit var typhoonEffect: TyphoonParticleView
    private lateinit var progressSending: ProgressBar
    private lateinit var progressOlderHistory: ProgressBar
    /** The contact's avatar in the top bar. It is kept so the full-screen view can open (see `AvatarUtil.openFullscreen`). */
    private var toolbarAvatarBytes: ByteArray? = null

    private lateinit var layoutTypingIndicator: View
    private val typingHandler = Handler(Looper.getMainLooper())
    /** See `TYPING_INDICATOR_TIMEOUT_MS`. */
    private val clearPeerTypingRunnable = Runnable { layoutTypingIndicator.visibility = View.GONE }
    private var isTypingSent = false
    /** See `TYPING_IDLE_TIMEOUT_MS`. */
    private val stopTypingRunnable = Runnable { sendTypingState(false) }

    private lateinit var fabScrollToBottom: FloatingActionButton

    private lateinit var swipeHelper: ItemTouchHelper
    private val replyHighlightHandler = Handler(Looper.getMainLooper())

    private var mediaRecorder: MediaRecorder? = null
    private var backgrounded = false
    private var recordingDialog: AlertDialog? = null

    /** #86: the finger is gone (touch cancelled / app was in the background): keep recording, ask send or discard. */
    private fun promptRecordingDecision() {
        if (mediaRecorder == null || recordingDialog?.isShowing == true) return
        recordingDialog = AlertDialog.Builder(this)
            .setMessage(R.string.msg_recording_in_background)
            .setCancelable(false)
            .setPositiveButton(R.string.btn_send) { _, _ -> finishVoiceRecording(send = true) }
            .setNegativeButton(R.string.action_discard) { _, _ -> finishVoiceRecording(send = false) }
            .show()
    }
    private var recordingFile: File? = null
    private var recordingStartTime: Long = 0
    private var recordingTouchStartX = 0f
    private var recordingCancelled = false
    private lateinit var layoutMessageInput: View
    private lateinit var layoutRecording: View
    private lateinit var txtRecordingTimer: TextView
    private lateinit var txtCancelPill: TextView
    private val recordingHandler = Handler(Looper.getMainLooper())
    /**
     * The `sendSeenReceipt` and `sendTypingIndicator` JNI calls can queue on the shared core lock, so they do NOT run on the main thread.
     * They run on a single-thread queue (same `DiscardPolicy` pattern as CallActivity: sends after close are dropped silently).
     */
    private val netPack = java.util.concurrent.ThreadPoolExecutor(
        1, 1, 10L, java.util.concurrent.TimeUnit.SECONDS,
        java.util.concurrent.LinkedBlockingQueue(), java.util.concurrent.ThreadPoolExecutor.DiscardPolicy()
    )
    private val recordingTimerRunnable = object : Runnable {
        override fun run() {
            val elapsed = android.os.SystemClock.elapsedRealtime() - recordingStartTime
            txtRecordingTimer.text = formatDurationMs(elapsed)
            recordingHandler.postDelayed(this, VOICE_PLAYBACK_TICK_MS)
        }
    }
    private val requestRecordAudioPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* reddedilse bile devam — basılı tutma o zaman kayıt başlatmaz */ }

    /** Voice message playback: ONE shared `MediaPlayer` for ALL bubbles (see SimpleChatAdapter `updateVoicePlayback`). */
    private var voicePlayer: MediaPlayer? = null
    private var voicePlayingFileId: String? = null
    private var voicePlaybackSpeed = 1f
    private val voicePlaybackHandler = Handler(Looper.getMainLooper())
    private val voicePlaybackTickRunnable = object : Runnable {
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

    private val stickerPicker = StickerPicker(this, { id, quote -> P2PLib.sendSticker(peerDeviceFingerprint, id, quote?.id ?: "", quote?.preview ?: "") }, ::takeQuote) { item ->
        item.replyToSenderLabel = resolveReplyLabel(item.replyToMessageId)
        adapter.addMessage(item)
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
    private fun updateComposerLock() {
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
    private fun ensureHandshakeReadyOrWarn(): Boolean {
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
    private val messageListener: (String) -> Unit = { json ->
        try {
            val obj = JSONObject(json)
            val isForThisPeer = obj.optString("peer") == peerDeviceFingerprint
            val isGroupScoped = !obj.isNull("group_id") || !obj.isNull("group_message_local_id")
            // "history_backfilled" covers several chats and carries no peer.
            // Nor does "stickers_changed" (my sticker store, any chat).
            if ((isForThisPeer && !isGroupScoped) || obj.optString("type") == "history_backfilled"
                || obj.optString("type") == "stickers_changed"
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
        selection = MessageSelection(this, adapter, { saveAttachmentToDownloads(it) }) { P2PLib.deleteMessage(peerDeviceFingerprint, it) }
        adapter.onAttachmentClick = { item -> onAttachmentClicked(item) }
        adapter.onAttachmentLongClick = { item -> onAttachmentLongClicked(item) }
        adapter.onReactionsClick = { item -> showReactionsDialog(item) }
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

    /** Content selected on the share screen (see util.ShareIntake). */
    private fun consumeShare(intent: Intent) {
        com.p2p.messenger.util.ShareIntake.takeForward(intent)?.let {
            pendingForward = it
            flushPendingShare()
            return
        }
        val share = com.p2p.messenger.util.ShareIntake.take(intent) ?: return
        com.p2p.messenger.util.ShareIntake.text(share)?.let {
            findViewById<EditText>(R.id.edtMessage).apply { setText(it); setSelection(text.length) }
        }
        pendingShare = com.p2p.messenger.util.ShareIntake.uris(share)
        flushPendingShare()
    }

    /** Shared files go out under the same lock as every send button: the
     *  chat has just opened and the handshake is not proven yet. */
    private var pendingShare: List<Uri> = emptyList()
    private var pendingForward: List<com.p2p.messenger.util.Forward.Pending>? = null

    private fun flushPendingShare() {
        if (!handshakeReady || peerAccountDeleted) return
        pendingForward?.let { f ->
            pendingForward = null
            AlertDialog.Builder(this)
                .setMessage(getString(R.string.confirm_forward, txtToolbarTitle.text))
                .setPositiveButton(R.string.btn_send) { _, _ ->
                    lifecycleScope.launch {
                        var done = 0
                        try {
                            for (p in f) {
                                if (p.file != null) onFilePicked(Uri.fromFile(p.file), p.caption, hiRes = true, name = p.fileName, mime = p.mimeType).join()
                                else p.text?.let { sendNewMessage(it).join() }
                                done++
                            }
                        } finally {
                            // Leaving the chat cancels the rest: say so.
                            val left = f.size - done
                            if (left > 0) Toast.makeText(applicationContext, applicationContext.resources.getQuantityString(R.plurals.forward_not_sent, left, left), Toast.LENGTH_LONG).show()
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
        if (pendingShare.isEmpty()) return
        val uris = pendingShare
        pendingShare = emptyList()
        // The chat was picked with one tap in a list that reorders itself.
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.confirm_send_shared, uris.size, txtToolbarTitle.text))
            .setPositiveButton(R.string.btn_send) { _, _ -> sendPickedFiles(uris.map { it to false }) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ---------------------------------------------------------------
    // Voice message: recording
    // ---------------------------------------------------------------

    /** Hold to record, slide left to cancel (WhatsApp style). */
    private fun setupVoiceRecordButton() {
        btnVoice.setOnTouchListener { _, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    if (!ensureHandshakeReadyOrWarn()) return@setOnTouchListener true
                    if (ContextCompat.checkSelfPermission(
                            this, android.Manifest.permission.RECORD_AUDIO
                        ) != PackageManager.PERMISSION_GRANTED
                    ) {
                        AppLock.beginTrustedExcursion()
                        requestRecordAudioPermission.launch(android.Manifest.permission.RECORD_AUDIO)
                        return@setOnTouchListener true
                    }
                    recordingTouchStartX = event.rawX
                    startVoiceRecording()
                    true
                }
                MotionEvent.ACTION_UP -> {
                    if (mediaRecorder != null) finishVoiceRecording(send = !recordingCancelled)
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    if (mediaRecorder != null) {
                        val dx = event.rawX - recordingTouchStartX
                        val thresholdPx = RECORDING_CANCEL_SWIPE_DP * resources.displayMetrics.density
                        recordingCancelled = dx > thresholdPx
                        updateCancelPill(dx, thresholdPx)
                    }
                    true
                }
                MotionEvent.ACTION_CANCEL -> {
                    // backgrounding cancels the touch; the recording goes on, the user decides
                    promptRecordingDecision()
                    true
                }
                else -> false
            }
        }
    }

    /** The 'slide to cancel' pill: it moves with the finger, and turns red once the threshold is passed. */
    private fun updateCancelPill(dx: Float, thresholdPx: Float) {
        txtCancelPill.translationX = dx.coerceIn(0f, thresholdPx)
        val pastThreshold = dx > thresholdPx
        txtCancelPill.setTextColor(
            if (pastThreshold) android.graphics.Color.WHITE
            else MaterialColors.getColor(txtCancelPill, com.google.android.material.R.attr.colorOnSurfaceVariant)
        )
        txtCancelPill.backgroundTintList =
            if (pastThreshold) {
                ColorStateList.valueOf(
                    MaterialColors.getColor(txtCancelPill, com.google.android.material.R.attr.colorError)
                )
            } else {
                null
            }
    }

    private fun startVoiceRecording() {
        val file = File(File(cacheDir, "voice").apply { mkdirs() }, "${UUID.randomUUID()}.m4a")
        val recorder = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            MediaRecorder(this)
        } else {
            @Suppress("DEPRECATION")
            MediaRecorder()
        }
        try {
            recorder.setAudioSource(MediaRecorder.AudioSource.MIC)
            recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            recorder.setAudioEncodingBitRate(64_000)
            recorder.setAudioSamplingRate(44_100)
            recorder.setOutputFile(file.absolutePath)
            // Ceiling: 10 minutes. The recorder stops itself at the ceiling and
            // the app then takes the SAME send/discard decision it already takes
            // when a recording ends (ACTION_UP).
            recorder.setMaxDuration(10 * 60 * 1000)
            recorder.setOnInfoListener { _, what, _ ->
                if (what == MediaRecorder.MEDIA_RECORDER_INFO_MAX_DURATION_REACHED) {
                    // The info callback is not guaranteed to arrive on the main
                    // thread: the decision (and its UI work) runs there.
                    recordingHandler.post {
                        if (mediaRecorder === recorder) finishVoiceRecording(send = !recordingCancelled)
                    }
                }
            }
            recorder.prepare()
            recorder.start()
        } catch (e: Exception) {
            Toast.makeText(this, R.string.error_recording_failed, Toast.LENGTH_SHORT).show()
            recorder.release()
            return
        }
        mediaRecorder = recorder
        P2PService.setRecordingActive(applicationContext, true)
        recordingFile = file
        recordingStartTime = android.os.SystemClock.elapsedRealtime()
        recordingCancelled = false
        layoutMessageInput.visibility = View.GONE
        layoutRecording.visibility = View.VISIBLE
        txtRecordingTimer.text = "0:00"
        txtCancelPill.translationX = 0f
        txtCancelPill.backgroundTintList = null
        recordingHandler.post(recordingTimerRunnable)
    }

    /** When `send = false` (cancelled or error), the recording file is deleted. */
    private fun finishVoiceRecording(send: Boolean) {
        val recorder = mediaRecorder ?: return
        val file = recordingFile
        val durationMs = android.os.SystemClock.elapsedRealtime() - recordingStartTime
        mediaRecorder = null
        recordingFile = null
        P2PService.setRecordingActive(applicationContext, false)
        recordingHandler.removeCallbacks(recordingTimerRunnable)
        layoutRecording.visibility = View.GONE
        layoutMessageInput.visibility = View.VISIBLE
        try {
            recorder.stop()
        } catch (e: Exception) {
            // Very short recordings can make `stop()` throw. The file is unusable then.
            file?.delete()
            recorder.release()
            return
        }
        recorder.release()
        if (send && durationMs >= RECORDING_MIN_DURATION_MS && file != null) {
            // A caption can also be typed under the voice message. The recording is not sent on release: the caption is asked for first.
            // If it is left empty, the message is sent as before.
            promptAttachmentCaption(onCancel = { file.delete() }) { caption, _ -> sendVoiceMessage(file, durationMs, caption, takeQuote()) }
        } else {
            file?.delete()
            if (send) {
                Toast.makeText(this, R.string.msg_recording_cancelled, Toast.LENGTH_SHORT).show()
            }
        }
    }

    /** A voice message is sent as a normal file attachment (MIME 'audio/mp4'). The only difference is that `durationMs` is carried (see Rust `FileOffer.duration_ms`). */
    private fun sendVoiceMessage(file: File, durationMs: Long, caption: String = "", quote: com.p2p.messenger.util.Quote.Ref? = null) {
        lifecycleScope.launch(Dispatchers.IO) {
            // The copy is deleted even if the screen closes while sending.
            // The recorder's MP4 carries the Android version (on many phones
            // maker and model) and creation times: scrubbed like a picked
            // m4a; a failed scrub cancels the send.
            val prepared = try {
                com.p2p.messenger.util.OutgoingMedia.prepare(file, file.name, "audio/mp4", false) { false }
            } catch (e: Exception) {
                null
            }
            try {
                val result = if (prepared == null) "Error: INTERNAL: voice scrub" else try {
                    P2PLib.prepareAndSendFile(
                        peerDeviceFingerprint, prepared.file.absolutePath, file.name, "audio/mp4", null, durationMs.toInt(),
                        caption, quote?.id ?: "", quote?.preview ?: ""
                    )
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                withContext(Dispatchers.Main) {
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@ChatActivity, com.p2p.messenger.util.coreErrorText(this@ChatActivity, result), Toast.LENGTH_SHORT).show()
                    } else {
                        val obj = JSONObject(result)
                        adapter.addMessage(
                            SimpleChatAdapter.Item(
                                messageId = obj.optString("message_id"),
                                text = "",
                                isMine = true,
                                caption = caption,
                                replyToMessageId = quote?.id,
                                replyToPreview = quote?.preview,
                                replyToSenderLabel = resolveReplyLabel(quote?.id),
                                attachment = SimpleChatAdapter.AttachmentInfo(
                                    fileId = obj.optString("message_id"),
                                    fileName = file.name,
                                    mimeType = "audio/mp4",
                                    totalSize = file.length(),
                                    status = SimpleChatAdapter.AttachmentStatus.COMPLETE,
                                    bytesDone = file.length(),
                                    durationMs = durationMs.toInt()
                                )
                            )
                        )
                        resolveReplyLabels()
                        scrollToBottomNow()
                    }
                }
            } finally {
                prepared?.file?.delete()
                file.delete()
            }
        }
    }

    private fun formatDurationMs(ms: Long): String {
        val totalSeconds = ms / 1000
        return String.format(java.util.Locale.getDefault(), "%d:%02d", totalSeconds / 60, totalSeconds % 60)
    }

    // ---------------------------------------------------------------
    // Voice message: playback
    // ---------------------------------------------------------------

    private fun onVoicePlayClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        if (attachment.status != SimpleChatAdapter.AttachmentStatus.COMPLETE) return
        if (voicePlayingFileId == attachment.fileId) {
            val player = voicePlayer ?: return
            if (player.isPlaying) {
                player.pause()
                voicePlaybackHandler.removeCallbacks(voicePlaybackTickRunnable)
                adapter.updateVoicePlayback(attachment.fileId, false, player.currentPosition, voicePlaybackSpeed)
            } else {
                player.start()
                voicePlaybackHandler.post(voicePlaybackTickRunnable)
                adapter.updateVoicePlayback(attachment.fileId, true, player.currentPosition, voicePlaybackSpeed)
            }
        } else {
            loadAndPlayVoiceMessage(item, attachment, 0)
        }
    }

    /** The user drags the slider and releases it: if the playing message is this one, seek directly; otherwise load it from that position. */
    private fun onVoiceSeeked(item: SimpleChatAdapter.Item, positionMs: Int) {
        val attachment = item.attachment ?: return
        if (attachment.status != SimpleChatAdapter.AttachmentStatus.COMPLETE) return
        if (voicePlayingFileId == attachment.fileId) {
            val player = voicePlayer ?: return
            player.seekTo(positionMs)
            adapter.tickVoicePlayback(attachment.fileId, positionMs, player.duration)
        } else {
            loadAndPlayVoiceMessage(item, attachment, positionMs)
        }
    }

    /** The decrypted copy's path is obtained OFF the main thread: decrypting a large file can take minutes (see Rust `begin_attachment_decrypt`). */
    private fun loadAndPlayVoiceMessage(
        item: SimpleChatAdapter.Item,
        attachment: SimpleChatAdapter.AttachmentInfo,
        startPositionMs: Int
    ) {
        stopVoicePlayback()
        val request = voiceLoadRequest
        lifecycleScope.launch(Dispatchers.IO) {
            val path = try {
                P2PLib.getAttachmentPlaintextPath(attachment.fileId)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                // Another tap or a pause came first: starting now would leave
                // a second player that nobody ever releases.
                if (request != voiceLoadRequest) return@withContext
                if (path.startsWith("Error:")) {
                    Toast.makeText(this@ChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                    return@withContext
                }
                var created: MediaPlayer? = null
                try {
                    val player = MediaPlayer()
                    created = player
                    player.setDataSource(path)
                    player.setOnCompletionListener {
                        voicePlaybackHandler.removeCallbacks(voicePlaybackTickRunnable)
                        adapter.updateVoicePlayback(attachment.fileId, false, 0, voicePlaybackSpeed)
                    }
                    player.prepare()
                    if (startPositionMs > 0) player.seekTo(startPositionMs)
                    voicePlaybackSpeed = attachment.playbackSpeed
                    if (voicePlaybackSpeed != 1f &&
                        android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M
                    ) {
                        player.playbackParams = PlaybackParams().setSpeed(voicePlaybackSpeed)
                    }
                    player.start()
                    voicePlayer = player
                    voicePlayingFileId = attachment.fileId
                    voicePlaybackHandler.post(voicePlaybackTickRunnable)
                    adapter.updateVoicePlayback(attachment.fileId, true, startPositionMs, voicePlaybackSpeed)
                } catch (e: Exception) {
                    // A corrupt file: free the native decoder, it was never stored.
                    created?.release()
                    Toast.makeText(this@ChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /** Speed badge (1x → 1.5x → 2x → 0.5x, see PlaybackSpeed). On a bubble that is not playing it is only stored as a preference. */
    private fun onVoiceSpeedClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        val newSpeed = PlaybackSpeed.next(attachment.playbackSpeed)
        if (voicePlayingFileId == attachment.fileId) {
            voicePlaybackSpeed = newSpeed
            val player = voicePlayer
            if (player != null && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                try {
                    // Setting the speed starts a paused player (documented): put it back.
                    val wasPlaying = player.isPlaying
                    player.playbackParams = PlaybackParams().setSpeed(newSpeed)
                    if (!wasPlaying) player.pause()
                } catch (e: Exception) {
                }
            }
            adapter.updateVoicePlayback(
                attachment.fileId, player?.isPlaying ?: false, player?.currentPosition ?: 0, newSpeed
            )
        } else {
            attachment.playbackSpeed = newSpeed
            adapter.updateVoicePlayback(attachment.fileId, false, attachment.playbackPositionMs, newSpeed)
        }
    }

    private fun stopVoicePlayback() {
        voiceLoadRequest++
        val fileId = voicePlayingFileId
        voicePlaybackHandler.removeCallbacks(voicePlaybackTickRunnable)
        try {
            voicePlayer?.stop()
            voicePlayer?.release()
        } catch (e: Exception) {
        }
        voicePlayer = null
        voicePlayingFileId = null
        if (fileId != null) {
            adapter.updateVoicePlayback(fileId, false, 0, voicePlaybackSpeed)
        }
    }

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
        P2PService.activeConversationId = peerDeviceFingerprint
        localMessages.clear()
        adapter.notifyDataSetChanged()
        historySyncPending = false
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

    /** Contact info plus this chat's local attachments (`StorageActivity`). */
    private fun showContactInfoDialog() {
        val view = layoutInflater.inflate(R.layout.dialog_contact_info, null)
        val name = txtToolbarTitle.text.toString()
        view.findViewById<TextView>(R.id.txtContactName).text = name
        AvatarUtil.renderInto(view.findViewById(R.id.imgContactAvatarLarge), peerAvatar(), name)
        val dialog = AlertDialog.Builder(this)
            .setTitle(name)
            .setView(view)
            .setNegativeButton(android.R.string.ok, null)
            .create()
        view.findViewById<View>(R.id.btnContactFilesMedia).setOnClickListener {
            dialog.dismiss()
            startActivity(Intent(this, StorageActivity::class.java)
                .putExtra(StorageActivity.EXTRA_CHAT_KIND, "contact")
                .putExtra(StorageActivity.EXTRA_CHAT_ID, peerDeviceFingerprint)
                .putExtra(StorageActivity.EXTRA_CHAT_NAME, name))
        }
        dialog.show()
    }

    private fun sendNewMessage(text: String): kotlinx.coroutines.Job {
        btnSend.isEnabled = false
        btnSend.visibility = View.INVISIBLE
        progressSending.visibility = View.VISIBLE

        return lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    P2PLib.sendMessage(peerDeviceFingerprint, text, null, null)
                } catch (e: Throwable) {
                    "Error: ${e.message}" // a JNI throw must not kill the process
                }
            }
            val (messageId, status) = if (result.startsWith("Error:")) {
                Toast.makeText(this@ChatActivity, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
                UUID.randomUUID().toString() to SimpleChatAdapter.Status.ERROR
            } else {
                try {
                    val obj = JSONObject(result)
                    obj.optString("message_id") to parseStatus(obj.optString("status"))
                } catch (e: Exception) {
                    UUID.randomUUID().toString() to SimpleChatAdapter.Status.ERROR
                }
            }
            adapter.addMessage(
                SimpleChatAdapter.Item(
                    messageId = messageId, text = text, isMine = true, status = status
                )
            )
            scrollToBottomNow()
            maybePlayTyphoonEffect()
            progressSending.visibility = View.GONE
            btnSend.visibility = View.VISIBLE
            btnSend.isEnabled = true
        }
    }

    private fun parseStatus(status: String): SimpleChatAdapter.Status = when (status) {
        "sent", "delivered" -> SimpleChatAdapter.Status.SENT
        "error" -> SimpleChatAdapter.Status.ERROR
        else -> SimpleChatAdapter.Status.PENDING
    }

    private fun parseAttachmentStatus(status: String): SimpleChatAdapter.AttachmentStatus = when (status) {
        "downloading" -> SimpleChatAdapter.AttachmentStatus.DOWNLOADING
        "complete" -> SimpleChatAdapter.AttachmentStatus.COMPLETE
        "failed" -> SimpleChatAdapter.AttachmentStatus.FAILED
        else -> SimpleChatAdapter.AttachmentStatus.OFFERED
    }

    /** Top bar avatar: finds the contact with this device fingerprint in `listContacts()` and returns its profile photo (or `null`,
     *  in which case `AvatarUtil` shows the initial-letter badge). */
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
    private fun peerAvatar(): ByteArray? =
        if (toolbarAvatarLoaded) toolbarAvatarBytes else null // loaded off-main in the chat-open path; no JNI here

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

    private fun handleIncomingEvent(obj: JSONObject) {
        when (obj.optString("type")) {
            "stickers_changed" -> stickerPicker.reload()
            "message" -> {
                val messageId = obj.optString("message_id")
                // The sender's embedded send time, the real moment it was sent (see SimpleChatAdapter.Item.sentAtMs). If it is '0' or missing
                // (an older sender version), it falls back to null, and the bubble shows a single timestamp.
                val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
                // See `resolveReplyLabel`: for this live event, `localMessages` already holds the complete set (the replied-to message, if any, must have been added
                // earlier), so it can be resolved directly here.
                // The isNull() check matters: org.json's optString(key, "") only falls back on a MISSING key, not an explicit JSON null. Rust always sends this key,
                // so without the check every received message would get the literal string 'null' here.
                val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
                adapter.addMessage(
                    SimpleChatAdapter.Item(
                        messageId = messageId,
                        text = obj.optString("text"),
                        isMine = false,
                        sentAtMs = sentAtMs,
                        replyToMessageId = replyToMessageId,
                        replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null },
                        replyToSenderLabel = resolveReplyLabel(replyToMessageId)
                    )
                )
                maybePlayTyphoonEffect()
                onNewIncomingItemAdded()
                // 'Seen' in 1:1 is only the read boundary (ReadStateSync). The other side applies it to this message as well, via `seen_bulk`; it is written to disk
                // and retried. Sending a separate `Seen` per message would have been a second packet carrying the same information.
                scheduleReadWatermark()
            }
            // Multi-device echo: a message I sent from another of my devices. It is shown here as a 'sent' bubble too (markSeen NOT called, since it is my own
            // message). After a reopen it already comes from the archive as 'sent'.
            "sibling_message" -> {
                val messageId = obj.optString("message_id")
                val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
                val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
                adapter.addMessage(
                    SimpleChatAdapter.Item(
                        messageId = messageId,
                        text = obj.optString("text"),
                        isMine = true,
                        status = SimpleChatAdapter.Status.SENT,
                        sentAtMs = sentAtMs,
                        replyToMessageId = replyToMessageId,
                        replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null },
                        replyToSenderLabel = resolveReplyLabel(replyToMessageId)
                    )
                )
                scrollToBottomNow()
            }
            "edit" -> adapter.applyEdit(obj.optString("message_id"), obj.optString("text"))
            "delete" -> adapter.applyDelete(obj.optString("message_id"))
            // Emoji reactions: Rust sends a ready SUMMARY string (see `reactions_summary`); nothing is counted or summed here.
            "reaction" -> adapter.applyReactions(obj.optString("message_id"), obj.optString("reactions"))
            "status" -> adapter.applyStatus(obj.optString("message_id"), parseStatus(obj.optString("status")))
            "history_sync" -> applyHistorySync(obj)
            "older_history" -> applyOlderHistory(obj)
            // Server or sibling restore covering several chats: reload from the archive.
            "history_backfilled" -> {
                syncMissedMessages()
                // Rows older than the loaded page: read them from the local archive now.
                if (fetchHistoryButton.onBackfilled()) {
                    noMoreOlderHistory = false
                    loadOlderHistory()
                }
            }
            // 'sibling_file': an attachment I sent from another of my devices. Same bubble, on my side.
            "file_offer", "sibling_file" -> {
                val autoDownloading = obj.optBoolean("auto_downloading", false)
                // isNull() check: optString("preview_hex", "") returns the
                // literal string "null" (not the fallback) for an explicit
                // JSON null, which then crashes hexToBytes below.
                val previewHex = if (obj.isNull("preview_hex")) null else obj.optString("preview_hex").ifEmpty { null }
                val previewJpeg = previewHex?.let { hexToBytes(it) }
                val durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it }
                // Attachment bubble with its caption and reply context (see the Rust `file_offer` event).
                val attachmentCaption = obj.optString("caption", "")
                val attachmentReplyId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
                val attachmentReplyPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
                adapter.addMessage(
                    SimpleChatAdapter.Item(
                        messageId = obj.optString("file_id"),
                        text = "",
                        isMine = obj.optString("type") == "sibling_file",
                        attachment = SimpleChatAdapter.AttachmentInfo(
                            fileId = obj.optString("file_id"),
                            fileName = obj.optString("file_name"),
                            mimeType = obj.optString("mime_type"),
                            totalSize = obj.optLong("total_size"),
                            status = if (obj.optBoolean("complete", false)) SimpleChatAdapter.AttachmentStatus.COMPLETE
                                      else if (autoDownloading) SimpleChatAdapter.AttachmentStatus.DOWNLOADING
                                      else SimpleChatAdapter.AttachmentStatus.OFFERED,
                            previewJpeg = previewJpeg,
                            durationMs = durationMs,
                            isSticker = obj.optBoolean("sticker", false)
                        ),
                        // Attachment + caption + reply.
                        caption = attachmentCaption,
                        replyToMessageId = attachmentReplyId,
                        replyToPreview = attachmentReplyPreview,
                        replyToSenderLabel = resolveReplyLabel(attachmentReplyId)
                    )
                )
                onNewIncomingItemAdded()
                // The read boundary covers only the `messages` table. Attachments keep individual `Seen` packets. It is not sent for the echo of my own attachment.
                if (obj.optString("type") == "file_offer") {
                    markSeen(obj.optString("file_id"))
                    // Sibling devices keep the notification until the watermark moves.
                    scheduleReadWatermark()
                }
            }
            "file_progress" -> adapter.applyAttachmentUpdate(
                obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.DOWNLOADING, obj.optLong("bytes_done")
            )
            "file_complete" -> adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.COMPLETE)
            "file_failed" -> adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.FAILED)
            // Rust emits this event both when the storage limit evicts a file and when an attached message is deleted, but no client listened to it.
            // The bubble kept showing 'completed', and tapping it found no file. Now it goes back to 'offered', so it looks downloadable again.
            "file_evicted" -> adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.OFFERED)
            // 'Seen' notice: the other side saw the message on its screen. It is shown as a small avatar badge under the bubble (see SimpleChatAdapter.applySeen).
            "seen" -> {
                val messageId = obj.optString("message_id")
                val peerName = txtToolbarTitle.text.toString()
                adapter.applySeen(
                    messageId,
                    listOf(SimpleChatAdapter.SeenByViewer(peerAvatar(), peerName))
                )
            }
            // Bulk seen: the other side sent a 'read up to here' boundary (see Rust `apply_incoming_read_watermark`). `message_ids` are sorted oldest to newest.
            // The 1:1 adapter shows a single 'last seen' mark, so applying the NEWEST one is enough.
            "seen_bulk" -> {
                // Group events were already filtered out in `messageListener` (when `group_id` is not null).
                val arr = obj.optJSONArray("message_ids")
                if (arr != null && arr.length() > 0) {
                    val newestId = arr.optString(arr.length() - 1)
                    val peerName = txtToolbarTitle.text.toString()
                    adapter.applySeen(
                        newestId,
                        listOf(SimpleChatAdapter.SeenByViewer(peerAvatar(), peerName))
                    )
                }
            }
            "account_deleted" -> {
                peerAccountDeleted = true
                connectingBanner.visibility = View.VISIBLE
                updateComposerLock()
            }
            "typing" -> {
                val isTyping = obj.optBoolean("is_typing", false)
                typingHandler.removeCallbacks(clearPeerTypingRunnable)
                layoutTypingIndicator.visibility = if (isTyping) View.VISIBLE else View.GONE
                if (isTyping) {
                    // See `TYPING_INDICATOR_TIMEOUT_MS`: if the turn-off notice is lost, the indicator must not hang forever.
                    typingHandler.postDelayed(clearPeerTypingRunnable, TYPING_INDICATOR_TIMEOUT_MS)
                    if (isRecyclerNearBottom()) {
                        recycler.scrollToPosition(localMessages.size - 1)
                    }
                }
            }
            // The other side changed its profile (see Rust `ProfileUpdate`): the avatar and name in the top bar update live.
            "profile_update" -> {
                val avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
                toolbarAvatarBytes = avatarHex?.let { hexToBytes(it) }
                toolbarAvatarLoaded = true
                // `previous_display_name` is set only if the NAME really changed (every photo change carries this packet too, see the note on the Rust side).
                // The user notice is based on it; otherwise the same name would look 'changed' every time.
                val newName = if (obj.isNull("display_name")) null else obj.optString("display_name").ifEmpty { null }
                val oldName = if (obj.isNull("previous_display_name")) null else obj.optString("previous_display_name").ifEmpty { null }
                if (newName != null && oldName != null) {
                    txtToolbarTitle.text = newName
                    Toast.makeText(this, getString(R.string.msg_contact_renamed, oldName, newName), Toast.LENGTH_LONG).show()
                }
                AvatarUtil.renderInto(imgToolbarAvatar, toolbarAvatarBytes, txtToolbarTitle.text.toString())
            }
            // Permanent handshake failure (version or key mismatch): tell the user, instead of showing 'Connecting' forever.
            "handshake_failed" -> {
                Toast.makeText(this, R.string.error_handshake_incompatible, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun markSeen(messageId: String) {
        if (!AppLock.isUnlocked()) return
        // The `sendSeenReceipt` JNI call queues on the core lock, so it is not called from the main thread (UI stalls / ANR). Order is kept by the single-thread queue.
        // The peer of THIS message: the screen may switch chats before the queued task runs, and the receipt must not go to the next peer.
        val peer = peerDeviceFingerprint
        netPack.execute {
            try {
                P2PLib.sendSeenReceipt(peer, messageId, null)
            } catch (e: Exception) {
            }
        }
    }

    /** A single packet is sent when the status CHANGES, not on every keystroke (see `isTypingSent`). */
    private fun sendTypingState(isTyping: Boolean) {
        if (isTypingSent == isTyping) return
        isTypingSent = isTyping
        // See `markSeen`.
        val peer = peerDeviceFingerprint
        netPack.execute {
            try {
                P2PLib.sendTypingIndicator(peer, isTyping)
            } catch (e: Exception) {
            }
        }
    }

    // ---------------------------------------------------------------
    // Scrolling and the 'scroll to bottom' button
    // ---------------------------------------------------------------

    private fun isRecyclerNearBottom(): Boolean {
        if (localMessages.isEmpty()) return true
        val lm = recycler.layoutManager as? LinearLayoutManager ?: return true
        val lastVisible = lm.findLastVisibleItemPosition()
        return lastVisible == RecyclerView.NO_POSITION || lastVisible >= localMessages.size - 2
    }

    /** A new message arrived: follow it if the user is already at the bottom. If they are scrolled up in the history, keep their position and only blink the FAB. */
    private fun onNewIncomingItemAdded() {
        if (isRecyclerNearBottom()) {
            scrollToLastSettled()
        } else {
            blinkScrollToBottomFab()
        }
    }

    /**
     * Plays a light particle 'typhoon' effect when a message is sent to a chat that has had no messages for the last 15 minutes.
     *
     * The check runs AFTER insertion: it compares the gap between the newest message and the one before it. So callers need no separate 'was it quiet' flag
     * before inserting; one call site is enough.
     *
     * It does not play on the chat's FIRST message (there is no earlier one to compare with): opening an empty chat and writing the first message is not a wake-up moment.
     */
    private fun maybePlayTyphoonEffect() {
        val newest = localMessages.lastOrNull() ?: return
        val previous = localMessages.getOrNull(localMessages.size - 2) ?: return
        if (newest.orderKey - previous.orderKey < TYPHOON_QUIET_WINDOW_MS) return
        // `post`: the bubble has not been measured in this frame yet, so its position is known only after layout.
        // The funnel now covers the whole view (see TyphoonParticleView `burst`), so the bubble position does not need to be computed.
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
    private fun syncRecyclerBottomInset() {
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

    private fun scrollToLastSettled() {
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

    private fun scrollToBottomNow() {
        scrollToLastSettled()
        hideScrollToBottomFab()
    }

    private fun updateScrollToBottomFabVisibility() {
        if (isRecyclerNearBottom()) {
            hideScrollToBottomFab()
        } else if (fabScrollToBottom.visibility != View.VISIBLE) {
            com.p2p.messenger.util.ScrollDownFab.style(fabScrollToBottom, newMessage = false)
            fabScrollToBottom.visibility = View.VISIBLE
        }
    }

    private fun blinkScrollToBottomFab() {
        com.p2p.messenger.util.ScrollDownFab.style(fabScrollToBottom, newMessage = true)
        fabScrollToBottom.visibility = View.VISIBLE
    }

    private fun hideScrollToBottomFab() {
        fabScrollToBottom.visibility = View.GONE
    }

    // ---------------------------------------------------------------
    // Ekler
    // ---------------------------------------------------------------

    /** Copies a resolved attachment into the 'Downloads/P2P' folder. API 29+ uses MediaStore (no permission needed). Below that, direct file writes
     *  (WRITE_EXTERNAL_STORAGE; see the permission request in onCreate). */
    /**
     * Makes the file name sent by the other side harmless before it is used as a FILE NAME.
     *
     * The core does the same cleaning (Rust `safe_file_name`, `receive_file_offer`), but only for offers received AFTER that change.
     * Rows already in the `files` table keep the raw name, and the API 26-28 branch below does `File(p2pDir, displayName)`.
     * A name such as "../../DCIM/Camera/IMG_0001.jpg" would write to an arbitrary path in shared storage.
     */
    private fun saveToPublicDownloads(source: File, displayName: String, mimeType: String): Boolean {
        return try {
            val safeName = safeSaveFileName(displayName)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                val values = ContentValues().apply {
                    put(android.provider.MediaStore.Downloads.DISPLAY_NAME, safeName)
                    put(android.provider.MediaStore.Downloads.MIME_TYPE, mimeType.ifBlank { "application/octet-stream" })
                    put(android.provider.MediaStore.Downloads.RELATIVE_PATH, "Download/P2P")
                }
                // Pending until the copy is complete, and removed when it
                // fails: a half file used to stay in Download/P2P.
                values.put(android.provider.MediaStore.Downloads.IS_PENDING, 1)
                val uri = contentResolver.insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: return false
                try {
                    contentResolver.openOutputStream(uri)!!.use { output ->
                        source.inputStream().use { input -> input.copyTo(output) }
                    }
                    values.clear()
                    values.put(android.provider.MediaStore.Downloads.IS_PENDING, 0)
                    contentResolver.update(uri, values, null, null)
                } catch (e: Exception) {
                    contentResolver.delete(uri, null, null)
                    return false
                }
                true
            } else {
                @Suppress("DEPRECATION")
                val downloadsDir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
                val p2pDir = File(downloadsDir, "P2P").apply { mkdirs() }
                // Never over an earlier file of the same name.
                val dest = File(p2pDir, safeName).let {
                    if (it.exists()) File(p2pDir, "${System.currentTimeMillis()}_$safeName") else it
                }
                source.inputStream().use { input -> dest.outputStream().use { output -> input.copyTo(output) } }
                // So the gallery and file manager see the new file at once.
                MediaScannerConnection.scanFile(this, arrayOf(dest.absolutePath), arrayOf(mimeType), null)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Long press on an attachment bubble (only when it is completed; see SimpleChatAdapter) shows 'Save to Downloads/P2P'.
     * It saves directly, without asking the sender. The file is already downloaded and encrypted on the device, and a sender approval round trip
     * added nothing (it could never arrive while the sender was offline). This applies to incoming and own attachments alike (`item.isMine` is not checked).
     */
    private fun onAttachmentLongClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        // 'Open with another app' is available. A tap (photo and video in the in-app MediaViewerActivity, others in the system default) is unchanged.
        // This option always shows the app chooser (`Intent.createChooser`).
        val options = mutableListOf<String>().apply {
            add(getString(R.string.action_open_with))
            add(getString(R.string.action_save_to_downloads))
            // Save to Downloads hands out a JPEG XL as PNG/GIF; this keeps the original.
            if (attachment.fileName.endsWith(".jxl", true) || attachment.mimeType == "image/jxl") add(getString(R.string.action_save_as_jxl))
            if (attachment.mimeType.startsWith("image/")) add(getString(R.string.action_copy_image))
            if (attachment.isSticker && !item.isMine) add(getString(R.string.action_add_to_my_stickers))
            if (com.p2p.messenger.util.Forward.canForward(item)) add(getString(R.string.action_forward))
            if (item.isMine) add(getString(R.string.action_delete_message))
            add(getString(R.string.action_select))
        }
        AlertDialog.Builder(this)
            .setItems(options.toTypedArray()) { _, which ->
                when (options[which]) {
                    getString(R.string.action_forward) -> com.p2p.messenger.util.Forward.start(this, item)
                    getString(R.string.action_select) -> selection.start(item)
                    getString(R.string.action_open_with) -> openAttachmentWithChooser(attachment)
                    getString(R.string.action_save_to_downloads) -> saveAttachmentToDownloads(attachment)
                    getString(R.string.action_save_as_jxl) -> saveAttachmentToDownloads(attachment, original = true)
                    getString(R.string.action_copy_image) -> OutgoingMedia.copyImage(this, attachment.fileId)
                    getString(R.string.action_add_to_my_stickers) -> stickerPicker.saveReceived(attachment.fileId)
                    getString(R.string.action_delete_message) -> confirmDeleteMessage(item)
                }
            }
            .show()
    }

    private fun openAttachmentWithChooser(attachment: SimpleChatAdapter.AttachmentInfo) {
        lifecycleScope.launch(Dispatchers.IO) {
            val path = try {
                P2PLib.getAttachmentPlaintextPath(attachment.fileId)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (path.startsWith("Error:")) {
                    Toast.makeText(this@ChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                    return@withContext
                }
                try {
                    val uri = FileProvider.getUriForFile(this@ChatActivity, "$packageName.fileprovider", File(path))
                    val intent = Intent(Intent.ACTION_VIEW).apply {
                        // The file's own extension, never the type the sender declared.
                        setDataAndType(
                            uri,
                            android.webkit.MimeTypeMap.getSingleton()
                                .getMimeTypeFromExtension(File(path).extension.lowercase()) ?: "*/*"
                        )
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    com.p2p.messenger.util.confirmExternalOpen(this@ChatActivity, intent.type) {
                        AppLock.beginTrustedExcursion()
                        try { startActivity(Intent.createChooser(intent, getString(R.string.lbl_open_with_chooser))) } catch (e: Exception) {
                            Toast.makeText(this@ChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                        }
                    }
                } catch (e: Exception) {
                    Toast.makeText(this@ChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /** `original`: a JPEG XL as it came (`image/jxl`), not converted. */
    private fun saveAttachmentToDownloads(attachment: SimpleChatAdapter.AttachmentInfo, original: Boolean = false) {
        lifecycleScope.launch(Dispatchers.IO) {
            val plainPath = try {
                if (original) P2PLib.getAttachmentOriginalPath(attachment.fileId)
                else P2PLib.getAttachmentPlaintextPath(attachment.fileId)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (plainPath.startsWith("Error:")) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@ChatActivity, com.p2p.messenger.util.coreErrorText(this@ChatActivity, plainPath), Toast.LENGTH_SHORT).show()
                }
                return@launch
            }
            val (name, mime) = if (original) attachment.fileName.let { if (it.endsWith(".jxl", true)) it else "$it.jxl" } to "image/jxl"
                else OutgoingMedia.savedAs(File(plainPath), attachment.fileName, attachment.mimeType)
            val saved = saveToPublicDownloads(File(plainPath), name, mime)
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    this@ChatActivity,
                    if (saved) getString(R.string.msg_saved_to_downloads)
                    else getString(R.string.error_attachment_open_failed),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    /** Single tap: download if not yet downloaded, open if completed. A tap during a download does nothing. */
    private fun onAttachmentClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        when (attachment.status) {
            SimpleChatAdapter.AttachmentStatus.OFFERED, SimpleChatAdapter.AttachmentStatus.FAILED -> {
                adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.DOWNLOADING, 0)
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try {
                        P2PLib.downloadFile(attachment.fileId, peerDeviceFingerprint)
                    } catch (e: Exception) {
                        "Error: ${e.message}"
                    }
                    if (result.startsWith("Error:")) {
                        withContext(Dispatchers.Main) {
                            adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.FAILED)
                            Toast.makeText(this@ChatActivity, com.p2p.messenger.util.coreErrorText(this@ChatActivity, result), Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }
            SimpleChatAdapter.AttachmentStatus.COMPLETE -> {
                lifecycleScope.launch(Dispatchers.IO) {
                    val path = try {
                        P2PLib.getAttachmentPlaintextPath(attachment.fileId)
                    } catch (e: Exception) {
                        "Error: ${e.message}"
                    }
                    withContext(Dispatchers.Main) {
                        if (path.startsWith("Error:")) {
                            Toast.makeText(this@ChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                        } else {
                            openAttachmentFile(path)
                        }
                    }
                }
            }
            SimpleChatAdapter.AttachmentStatus.DOWNLOADING -> {
                // Already downloading: a tap does nothing.
            }
        }
    }

    /** Photos and videos open in the in-app viewer (MediaViewerActivity); other types go to the system default. */
    private fun openAttachmentFile(path: String) {
        // The file's own extension picks the viewer and the handler, not the
        // type the sender declared.
        val mimeType = android.webkit.MimeTypeMap.getSingleton()
            .getMimeTypeFromExtension(File(path).extension.lowercase()) ?: "*/*"
        try {
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", File(path))
            if (mimeType.startsWith("image/") || mimeType.startsWith("video/")) {
                val intent = Intent(this, MediaViewerActivity::class.java).apply {
                    putExtra("uri", uri)
                    putExtra("mime_type", mimeType)
                }
                grantUriPermission(packageName, uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
                startActivity(intent)
                return
            }
            val intent = Intent(Intent.ACTION_VIEW).apply {
                // The file's own extension picks the handler, not the type
                // the sender declared.
                setDataAndType(uri, mimeType)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            com.p2p.messenger.util.confirmExternalOpen(this, intent.type) {
                AppLock.beginTrustedExcursion()
                try { startActivity(intent) } catch (e: Exception) {
                    Toast.makeText(this, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                }
            }
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Sends a photo captured by the camera. Same send path as `onFilePicked`; the one difference is that the source is JPEG bytes already in memory,
     * not a `content://` URI. So there is no separate name or size lookup (SAF `OpenableColumns`), and the name is generated at capture time.
     *
     * The temporary file in the cache (`cacheDir/outgoing`) is needed because the Rust core wants a real file PATH when sending an attachment.
     * It is deleted in `finally`. The photo is never written to the system gallery or shared storage.
     */
    private fun onPhotoCaptured(jpeg: ByteArray, caption: String = "", hiRes: Boolean = false, quote: com.p2p.messenger.util.Quote.Ref? = null) {
        val fileName = "IMG_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date()) + ".jpg"
        lifecycleScope.launch(Dispatchers.IO) {
            val tempFile = File(File(cacheDir, "outgoing").apply { mkdirs() }, UUID.randomUUID().toString())
            var sent = tempFile
            try {
                tempFile.writeBytes(jpeg)
                val previewJpeg = try {
                    generateImagePreview(tempFile)
                } catch (e: Exception) {
                    null
                }
                val prepared = OutgoingMedia.prepare(tempFile, fileName, "image/jpeg", hiRes) { OutgoingMedia.askSendUnscrubbed(this@ChatActivity) }
                sent = prepared.file
                val result = P2PLib.prepareAndSendFile(
                    peerDeviceFingerprint, prepared.file.absolutePath, prepared.fileName, prepared.mimeType, previewJpeg, -1,
                    caption, quote?.id ?: "", quote?.preview ?: ""
                )
                withContext(Dispatchers.Main) {
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@ChatActivity, com.p2p.messenger.util.coreErrorText(this@ChatActivity, result), Toast.LENGTH_SHORT).show()
                    } else {
                        val obj = JSONObject(result)
                        adapter.addMessage(
                            SimpleChatAdapter.Item(
                                messageId = obj.optString("message_id"),
                                text = "",
                                isMine = true,
                                attachment = SimpleChatAdapter.AttachmentInfo(
                                    fileId = obj.optString("message_id"),
                                    fileName = prepared.fileName,
                                    mimeType = prepared.mimeType,
                                    totalSize = prepared.file.length(),
                                    status = SimpleChatAdapter.AttachmentStatus.COMPLETE,
                                    bytesDone = prepared.file.length(),
                                    previewJpeg = previewJpeg
                                
                                ),
                                // The caption typed during sending shows at once.
                                caption = caption,
                                replyToMessageId = quote?.id,
                                replyToPreview = quote?.preview,
                                replyToSenderLabel = resolveReplyLabel(quote?.id)
                            )
                        )
                        scrollToBottomNow()
                    }
                }
            } catch (e: Exception) {
                if (e is java.util.concurrent.CancellationException) return@launch
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@ChatActivity, getString(R.string.error_send_failed), Toast.LENGTH_SHORT).show()
                }
            } finally {
                tempFile.delete()
                sent.delete()
            }
        }
    }

    /** One send at a time so the files arrive in the order they were
     *  picked; the caption goes with the last one, under the batch. */
    private fun sendPickedFiles(files: List<Pair<Uri, Boolean>>, caption: String = "", quote: com.p2p.messenger.util.Quote.Ref? = null) =
        lifecycleScope.launch { files.forEachIndexed { i, (u, hiRes) -> val last = i == files.lastIndex; onFilePicked(u, if (last) caption else "", hiRes, quote = if (last) quote else null).join() } }

    /** The first quote in the input: the attachment or sticker being sent answers it. */
    private fun takeQuote() = com.p2p.messenger.util.Quote.takeFirst(findViewById(R.id.edtMessage))

    /**
     * A file picked with SAF (`OpenDocument`) is first copied to the app's own cache, because a `content://` URI is not a path and the Rust side needs a real file path.
     * Then it is encrypted and offered with `prepareAndSendFile`.
     */
    private fun onFilePicked(uri: Uri, caption: String = "", hiRes: Boolean = false, name: String? = null, mime: String? = null, quote: com.p2p.messenger.util.Quote.Ref? = null): kotlinx.coroutines.Job {
        return lifecycleScope.launch(Dispatchers.IO) {
            // Provider queries are IPC to another app: not on the main thread.
            val fileName = name ?: queryDisplayName(uri) ?: "file"
            val mimeType = mime ?: contentResolver.getType(uri) ?: "application/octet-stream"
            val size = querySize(uri)
            val tooLarge = size != null && size > MAX_ATTACHMENT_SIZE
            withContext(Dispatchers.Main) {
                if (tooLarge) {
                    Toast.makeText(this@ChatActivity, getString(R.string.error_file_too_large_named, fileName), Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(this@ChatActivity, fileName, Toast.LENGTH_SHORT).show()
                }
            }
            if (tooLarge) return@launch
            val tempFile = File(File(cacheDir, "outgoing").apply { mkdirs() }, UUID.randomUUID().toString())
            var sent = tempFile
            try {
                contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output ->
                        // SIZE column can lie: hard cap on bytes actually copied.
                        val buf = ByteArray(64 * 1024)
                        var total = 0L
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            total += n
                            if (total > MAX_ATTACHMENT_SIZE) throw IllegalStateException("too_large")
                            output.write(buf, 0, n)
                        }
                    }
                } ?: throw java.io.IOException("File could not be opened")

                val previewJpeg = try {
                    when {
                        mimeType.startsWith("image/") -> generateImagePreview(tempFile)
                        mimeType.startsWith("video/") -> generateVideoPreview(tempFile)
                        else -> null
                    }
                } catch (e: Exception) {
                    null
                }

                val prepared = OutgoingMedia.prepare(tempFile, fileName, mimeType, hiRes) { OutgoingMedia.askSendUnscrubbed(this@ChatActivity) }
                sent = prepared.file
                val result = P2PLib.prepareAndSendFile(
                    peerDeviceFingerprint, prepared.file.absolutePath, prepared.fileName, prepared.mimeType, previewJpeg, -1,
                    caption, quote?.id ?: "", quote?.preview ?: ""
                )
                withContext(Dispatchers.Main) {
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@ChatActivity, com.p2p.messenger.util.coreErrorText(this@ChatActivity, result), Toast.LENGTH_SHORT).show()
                    } else {
                        val obj = JSONObject(result)
                        adapter.addMessage(
                            SimpleChatAdapter.Item(
                                messageId = obj.optString("message_id"),
                                text = "",
                                isMine = true,
                                attachment = SimpleChatAdapter.AttachmentInfo(
                                    fileId = obj.optString("message_id"),
                                    fileName = prepared.fileName,
                                    mimeType = prepared.mimeType,
                                    totalSize = prepared.file.length(),
                                    status = SimpleChatAdapter.AttachmentStatus.COMPLETE,
                                    bytesDone = prepared.file.length(),
                                    previewJpeg = previewJpeg
                                
                                ),
                                // The caption typed during sending shows at once.
                                caption = caption,
                                replyToMessageId = quote?.id,
                                replyToPreview = quote?.preview,
                                replyToSenderLabel = resolveReplyLabel(quote?.id)
                            )
                        )
                        scrollToBottomNow()
                    }
                }
            } catch (e: Exception) {
                if (e is java.util.concurrent.CancellationException) return@launch
                withContext(Dispatchers.Main) {
                    if (e.message == "too_large") Toast.makeText(this@ChatActivity, getString(R.string.error_file_too_large_named, fileName), Toast.LENGTH_LONG).show() else Toast.makeText(this@ChatActivity, getString(R.string.error_send_failed), Toast.LENGTH_SHORT).show()
                }
            } finally {
                tempFile.delete()
                sent.delete()
            }
        }
    }

    private fun queryDisplayName(uri: Uri): String? {
        return try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) cursor.getString(idx) else null
                } else null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun querySize(uri: Uri): Long? {
        return try {
            contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (idx >= 0 && !cursor.isNull(idx)) cursor.getLong(idx) else null
                } else null
            }
        } catch (e: Exception) {
            null
        }
    }

    /** A small 480p / 85% JPEG cover, sent with the `FileOffer`, so the recipient can see a preview before downloading the full file. */
    private fun generateImagePreview(file: File): ByteArray? =
        ImagePreview.compressFile(file, PREVIEW_MAX_DIMENSION, PREVIEW_JPEG_QUALITY)

    private fun generateVideoPreview(file: File): ByteArray? {
        val retriever = MediaMetadataRetriever()
        return try {
            retriever.setDataSource(file.absolutePath)
            val frame = retriever.getFrameAtTime(1_000_000L, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
                ?: retriever.getFrameAtTime(0L, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
                ?: return null
            ImagePreview.compressBitmap(frame, PREVIEW_MAX_DIMENSION, PREVIEW_JPEG_QUALITY)
        } catch (e: Exception) {
            null
        } finally {
            retriever.release()
        }
    }

    // ---------------------------------------------------------------
    // History
    // ---------------------------------------------------------------

    /** Opening sync from the other side (see `requestHistorySync`): only rows NEWER than the local ones are added. */
    private fun applyHistorySync(obj: JSONObject) {
        if (!historySyncPending) return
        historySyncPending = false
        val array = obj.optJSONArray("messages") ?: return
        if (array.length() == 0) return
        val withoutId = HashSet<String>()
        val synced = (0 until array.length()).map { i ->
            val m = array.getJSONObject(i)
            val messageId = if (m.isNull("message_id")) null else m.optString("message_id").ifEmpty { null }
            SimpleChatAdapter.Item(
                messageId = messageId ?: UUID.randomUUID().toString().also { withoutId.add(it) },
                text = m.optString("text"),
                isMine = m.optString("direction") == "sent",
                timestamp = m.optLong("timestamp", System.currentTimeMillis()),
                sentAtMs = m.optLong("sent_at_ms", 0L).takeIf { it > 0 },
                isEdited = m.optBoolean("is_edited", false),
                viaSync = m.optBoolean("via_sync", false),
                reactions = m.optString("reactions", ""),
                isDeleted = m.optBoolean("is_deleted", false)
            )
        }
        // Rows are filtered by `message_id` as well as by time. `timestamp` is the local archive time, so a sync copy from the other side can carry a LATER
        // timestamp than our own copy of the same message. Without the id filter, our own sent messages were added a second time (a duplicate bubble on the sender).
        val existingIds = localMessages.mapTo(HashSet()) { it.messageId }
        val toAdd = if (localMessages.isEmpty()) {
            synced
        } else {
            val latestLocal = localMessages.maxOf { it.timestamp }
            // The peer's archive clock is not ours: a missed message older
            // than our newest row (or any, with the peer's clock behind) was
            // never merged. Only rows without an id still need the clock.
            synced.filter { it.messageId !in existingIds && (it.messageId !in withoutId || it.timestamp > latestLocal) }
        }
        if (toAdd.isEmpty()) return
        localMessages.addAll(toAdd)
        localMessages.sortWith(compareBy { it.orderKey })
        adapter.notifyDataSetChanged()
        adapter.dedupeByMessageId()
        recycler.scrollToPosition(localMessages.size - 1)
    }

    // ---------------------------------------------------------------
    // Edit / delete / copy / reply
    // ---------------------------------------------------------------

    private fun showEditDeleteDialog(item: SimpleChatAdapter.Item) {
        if (!item.isMine) {
            // We cannot edit or delete the other side's message (the other side would reject it anyway; see Rust `message_owned_by_sender`), but we can leave a reaction.
            val theirOptions = listOfNotNull(
                getString(R.string.action_react),
                getString(R.string.lbl_copy),
                getString(R.string.action_forward).takeIf { com.p2p.messenger.util.Forward.canForward(item) },
                getString(R.string.action_select),
            )
            AlertDialog.Builder(this)
                .setItems(theirOptions.toTypedArray()) { _, which ->
                    when (theirOptions[which]) {
                        getString(R.string.action_react) -> showReactionPicker(item)
                        getString(R.string.lbl_copy) -> copyMessageText(item)
                        getString(R.string.action_forward) -> com.p2p.messenger.util.Forward.start(this, item)
                        getString(R.string.action_select) -> selection.start(item)
                    }
                }
                .show()
            return
        }
        val showRetry = item.status == SimpleChatAdapter.Status.ERROR
        val options = mutableListOf<String>().apply {
            if (showRetry) add(getString(R.string.action_retry_message))
            add(getString(R.string.action_react))
            add(getString(R.string.action_edit_message))
            add(getString(R.string.action_delete_message))
            add(getString(R.string.lbl_copy))
            add(getString(R.string.action_forward))
            add(getString(R.string.action_select))
        }
        AlertDialog.Builder(this)
            .setItems(options.toTypedArray()) { _, which ->
                when (options[which]) {
                    getString(R.string.action_forward) -> com.p2p.messenger.util.Forward.start(this, item)
                    getString(R.string.action_select) -> selection.start(item)
                    getString(R.string.action_retry_message) -> retryFailedMessage(item)
                    getString(R.string.action_react) -> showReactionPicker(item)
                    getString(R.string.action_edit_message) -> showEditMessageDialog(item)
                    getString(R.string.action_delete_message) -> confirmDeleteMessage(item)
                    getString(R.string.lbl_copy) -> copyMessageText(item)
                }
            }
            .show()
    }

    /**
     * Tapping the reaction pill opens a list of who reacted with what (WhatsApp style).
     *
     * The identities come from the network as `identity_id`. Names are resolved here, from this device's OWN contact list: the protocol carries no names,
     * since a sender could claim any name. An unknown identity is shown with its shortened id, and our own id shows as "You".
     */
    private fun showReactionsDialog(item: SimpleChatAdapter.Item) {
        lifecycleScope.launch(Dispatchers.IO) {
            val raw = try { P2PLib.listReactions(item.messageId) } catch (e: Exception) { "[]" }
            val names = HashMap<String, String>()
            try {
                val contacts = JSONArray(P2PLib.listContacts())
                for (i in 0 until contacts.length()) {
                    val c = contacts.getJSONObject(i)
                    names[c.optString("identity_id")] = c.optString("display_name")
                }
            } catch (e: Exception) {
                // If the contact list cannot be read, names fall back to the shortened id.
            }
            val rows = mutableListOf<String>()
            var myRow = -1
            try {
                val array = JSONArray(raw)
                for (i in 0 until array.length()) {
                    val entry = array.getJSONObject(i)
                    val identityId = entry.optString("identity_id")
                    val who = when {
                        // See Rust `list_reactions`: the 'is it me' decision is made in the core, which owns the identity.
                        entry.optBoolean("is_me", false) -> getString(R.string.lbl_you)
                        names[identityId]?.isNotBlank() == true -> names[identityId]!!
                        else -> identityId.take(8)
                    }
                    if (entry.optBoolean("is_me", false)) myRow = rows.size
                    rows.add("${entry.optString("emoji")}   $who")
                }
            } catch (e: Exception) {
                // Malformed JSON: show an empty list instead of crashing.
            }
            withContext(Dispatchers.Main) {
                if (rows.isEmpty()) return@withContext
                AlertDialog.Builder(this@ChatActivity)
                    .setTitle(R.string.title_reactions)
                    .setItems(rows.toTypedArray()) { _, which ->
                        // Tapping my own row removes my reaction (empty emoji).
                        if (which != myRow) return@setItems
                        lifecycleScope.launch(Dispatchers.IO) {
                            val summary = try { P2PLib.reactToMessage(peerDeviceFingerprint, item.messageId, "") } catch (e: Exception) { "Error: ${e.message}" }
                            withContext(Dispatchers.Main) {
                                if (summary.startsWith("Error:")) {
                                    Toast.makeText(this@ChatActivity, summary, Toast.LENGTH_SHORT).show()
                                } else {
                                    adapter.applyReactions(item.messageId, summary)
                                }
                            }
                        }
                    }
                    .setNegativeButton(android.R.string.ok, null)
                    .show()
            }
        }
    }

    /**
     * Sends a reaction. The JNI call can reach the network, so it runs OFF the main thread. The returned value is the message's CURRENT reaction summary
     * (see Rust `react_to_message`), written straight into the pill. Delivery to the other side is guaranteed by `needs_delivery_confirmation`,
     * so there is no need to wait here.
     */
    private fun showReactionPicker(item: SimpleChatAdapter.Item) {
        ReactionPicker.show(this, item.reactions.isNotBlank()) { emoji ->
            lifecycleScope.launch(Dispatchers.IO) {
                val summary = try {
                    P2PLib.reactToMessage(peerDeviceFingerprint, item.messageId, emoji)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                withContext(Dispatchers.Main) {
                    if (summary.startsWith("Error:")) {
                        Toast.makeText(this@ChatActivity, summary, Toast.LENGTH_SHORT).show()
                    } else {
                        adapter.applyReactions(item.messageId, summary)
                    }
                }
            }
        }
    }

    private fun copyMessageText(item: SimpleChatAdapter.Item) {
        com.p2p.messenger.util.copySensitive(this, "message", com.p2p.messenger.util.Quote.plain(com.p2p.messenger.util.Forward.strip(item.text)))
        Toast.makeText(this, R.string.lbl_copied, Toast.LENGTH_SHORT).show()
    }

    /** Swiping a bubble RIGHT starts a reply to that message. The swipe is limited to `REPLY_SWIPE_MAX_DP`, and the bubble settles back into place
     *  (it is not a real swipe-to-dismiss). */
    /** See `setupSwipeToReply` / `onSelectedChanged`: the stable id of the target message, captured when the swipe STARTS. */
    private var swipeStartMessageId: String? = null

    private fun setupSwipeToReply() {
        val replyIcon: Drawable? = ContextCompat.getDrawable(this, R.drawable.ic_reply)
        val maxSwipePx = REPLY_SWIPE_MAX_DP * resources.displayMetrics.density
        val callback = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.RIGHT) {
            /**
             * The target is chosen by where the swipe STARTED, not where it ended. `onSwiped` gets `adapterPosition` at the moment the gesture ENDS.
             * If a new message arrives during the gesture (common in a live chat), every position shifts: that index now points to a DIFFERENT message,
             * and if the list was rebound meanwhile, `NO_POSITION` is returned and nothing is replied to. So the target is captured at the START as a stable
             * `messageId`, and the right message is replied to even if the index shifts.
             */
            override fun onSelectedChanged(viewHolder: RecyclerView.ViewHolder?, actionState: Int) {
                super.onSelectedChanged(viewHolder, actionState)
                if (actionState == ItemTouchHelper.ACTION_STATE_SWIPE && viewHolder != null) {
                    @Suppress("DEPRECATION")
                    val start = viewHolder.adapterPosition
                    swipeStartMessageId = localMessages.getOrNull(start)?.messageId
                }
            }

            override fun onMove(
                rv: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                target: RecyclerView.ViewHolder
            ): Boolean = false

            override fun getSwipeThreshold(viewHolder: RecyclerView.ViewHolder): Float = 0.4f

            override fun onChildDraw(
                c: Canvas,
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                dX: Float,
                dY: Float,
                actionState: Int,
                isCurrentlyActive: Boolean
            ) {
                val clampedDx = dX.coerceIn(0f, maxSwipePx)
                if (actionState == ItemTouchHelper.ACTION_STATE_SWIPE) {
                    val itemView = viewHolder.itemView
                    val progress = (clampedDx / maxSwipePx).coerceIn(0f, 1f)
                    if (replyIcon != null && progress > 0f) {
                        val iconSize = (24 * resources.displayMetrics.density).toInt()
                        val top = itemView.top + (itemView.height - iconSize) / 2
                        val left = itemView.left + (12 * resources.displayMetrics.density).toInt()
                        replyIcon.setBounds(left, top, left + iconSize, top + iconSize)
                        replyIcon.alpha = (progress * 255).toInt()
                        replyIcon.draw(c)
                    }
                }
                super.onChildDraw(c, recyclerView, viewHolder, clampedDx, dY, actionState, isCurrentlyActive)
            }

            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                val position = viewHolder.adapterPosition
                // Settle the bubble back into place. This is not a swipe-to-delete.
                // With change animations off (see `supportsChangeAnimations`), `notifyItemChanged` rebinds the SAME view. ItemTouchHelper keeps that view as swiped
                // and keeps drawing it offset on every frame. Detaching and re-attaching the helper clears that state and resets the offset.
                recycler.post {
                    swipeHelper.attachToRecyclerView(null)
                    swipeHelper.attachToRecyclerView(recycler)
                }
                if (position != RecyclerView.NO_POSITION) adapter.notifyItemChanged(position)
                // See `onSelectedChanged`: the target is the message the gesture STARTED on.
                val startedOn = swipeStartMessageId
                swipeStartMessageId = null
                val item = startedOn?.let { id -> localMessages.firstOrNull { it.messageId == id } }
                if (item != null && !item.isDeleted) startReply(item)
            }
        }
        swipeHelper = ItemTouchHelper(callback)
        swipeHelper.attachToRecyclerView(recycler)
    }

    private fun startReply(item: SimpleChatAdapter.Item) {
        com.p2p.messenger.util.Quote.insert(findViewById(R.id.edtMessage), item.messageId, replyPreviewFor(item))
    }

    /** Attachment bubbles have no text, so the file name is shown. */
    private fun replyPreviewFor(item: SimpleChatAdapter.Item): String {
        val attachment = item.attachment
        return if (attachment != null) {
            getString(R.string.lbl_attachment_reply_preview, attachment.fileName)
        } else {
            com.p2p.messenger.util.Quote.ownText(com.p2p.messenger.util.Forward.strip(item.text)).takeWholeChars(REPLY_PREVIEW_MAX_CHARS)
        }
    }

    /** Tapping the quote box scrolls to the replied message and highlights it briefly. If the target is not loaded yet (older history), it warns. */
    private fun scrollToMessage(targetMessageId: String) {
        val position = localMessages.indexOfFirst { it.messageId == targetMessageId }
        if (position < 0) {
            Toast.makeText(this, R.string.msg_reply_target_not_loaded, Toast.LENGTH_SHORT).show()
            return
        }
        recycler.scrollToPosition(position)
        adapter.setHighlighted(targetMessageId)
        replyHighlightHandler.removeCallbacksAndMessages(null)
        replyHighlightHandler.postDelayed({ adapter.setHighlighted(null) }, REPLY_HIGHLIGHT_DURATION_MS)
    }

    /** Resends a FAILED message in the SAME bubble. It does not create a second bubble (see SimpleChatAdapter.retryMessage). */
    private fun retryFailedMessage(item: SimpleChatAdapter.Item) {
        val peer = peerDeviceFingerprint
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    P2PLib.sendMessage(peer, item.text, item.replyToMessageId, item.replyToPreview)
                } catch (e: Throwable) {
                    "Error: ${e.message}"
                }
            }
            if (result.startsWith("Error:")) {
                Toast.makeText(this@ChatActivity, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
                adapter.applyStatus(item.messageId, SimpleChatAdapter.Status.ERROR)
                return@launch
            }
            val (newMessageId, status) = try {
                val obj = JSONObject(result)
                obj.optString("message_id") to parseStatus(obj.optString("status"))
            } catch (e: Exception) {
                item.messageId to SimpleChatAdapter.Status.ERROR
            }
            adapter.retryMessage(item.messageId, newMessageId, status)
        }
    }

    private fun showEditMessageDialog(item: SimpleChatAdapter.Item) {
        val input = EditText(this)
        com.p2p.messenger.util.Quote.attach(input)
        input.setText(com.p2p.messenger.util.Forward.strip(item.text))
        input.hint = getString(R.string.lbl_edit_message_hint)
        AlertDialog.Builder(this)
            .setTitle(R.string.action_edit_message)
            .setView(input)
            .setPositiveButton(R.string.action_edit_message) { _, _ ->
                if (input.text.isBlank()) return@setPositiveButton
                // An edit keeps the "Forwarded" label.
                val newText = input.text.toString().let { if (com.p2p.messenger.util.Forward.isForwarded(item.text)) com.p2p.messenger.util.Forward.mark(it) else it }
                val peer = peerDeviceFingerprint
                lifecycleScope.launch {
                    val result = withContext(Dispatchers.IO) {
                        try { P2PLib.editMessage(peer, item.messageId, newText) } catch (e: Throwable) { "Error: ${e.message}" }
                    }
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@ChatActivity, R.string.error_edit_failed, Toast.LENGTH_SHORT).show()
                    } else {
                        adapter.applyEdit(item.messageId, newText)
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDeleteMessage(item: SimpleChatAdapter.Item) {
        AlertDialog.Builder(this)
            .setMessage(R.string.confirm_delete_message)
            .setPositiveButton(R.string.action_delete_message) { _, _ ->
                val peer = peerDeviceFingerprint
                lifecycleScope.launch {
                    val result = withContext(Dispatchers.IO) {
                        try { P2PLib.deleteMessage(peer, item.messageId) } catch (e: Throwable) { "Error: ${e.message}" }
                    }
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@ChatActivity, R.string.error_delete_failed, Toast.LENGTH_SHORT).show()
                    } else {
                        adapter.applyDelete(item.messageId)
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun loadHistoryIfAvailable(targetPeer: String) {
        lifecycleScope.launch {
            val merged = withContext(Dispatchers.IO) { readNewestPage(targetPeer) }
            if (peerDeviceFingerprint != targetPeer) return@launch
            val (mergedItems, seenMessageIds) = merged
            // `syncMissedMessages` (onResume) can race this: both fetch on
            // IO and either can finish first. Filter by what's already in
            // `localMessages` (checked here, on the main thread, right
            // before merging) and notify only the actually-new range —
            // otherwise a duplicate insert or a wrong notifyItemRangeInserted
            // count corrupts RecyclerView's internal state.
            val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
            val newItems = mergedItems.filter { it.messageId !in existingIds }
            if (newItems.isNotEmpty()) {
                localMessages.addAll(newItems)
                // If history loading finishes after a live message, appending would push the live message above the old history, off screen. Re-sort by send order.
                localMessages.sortWith(compareBy { it.orderKey })
                resolveReplyLabels()
                adapter.notifyDataSetChanged()
                // `dedupeByMessageId`: the loadHistory and syncMissed paths can race and add the same message_id twice.
                adapter.dedupeByMessageId()
                recycler.scrollToPosition(localMessages.size - 1)
            }
            // The 'seen' state is read from the archive too, not only from live events, so a message seen while the chat was closed still shows as seen after a reopen
            // (the Rust `message_seen` table holds it). Replays run AFTER the messages are added: `applySeen` returns -1 from `indexOfMessageId` for a row not added yet.
            if (seenMessageIds.isNotEmpty()) {
                val viewer = SimpleChatAdapter.SeenByViewer(
                    peerAvatar(), txtToolbarTitle.text.toString()
                )
                for (id in seenMessageIds) adapter.applySeen(id, listOf(viewer))
            }
            // No history request to the peer on open: only the "fetch older
            // history" action goes to the network (P2PLib.fetchServerHistory).
        }
    }

    /**
     * Parses a JSON row from any of the three sources (local first load, local older page, older page from the network) the same way.
     * The 'status' field is not carried on the network path, so it can be missing. In that case it falls back to 'sent', the same assumption as for older rows.
     */
    private fun itemFromHistoryJson(obj: JSONObject): SimpleChatAdapter.Item {
        val direction = obj.optString("direction")
        val text = obj.optString("text")
        val timestamp = obj.optLong("timestamp", System.currentTimeMillis())
        val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
        val messageId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
        val status = if (obj.isNull("status")) null else obj.optString("status").ifEmpty { null }
        val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
        val replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
        val isDeleted = obj.optBoolean("is_deleted", false)
        val isEdited = obj.optBoolean("is_edited", false)
        return SimpleChatAdapter.Item(
            messageId = messageId ?: UUID.randomUUID().toString(),
            text = text,
            isMine = direction == "sent",
            timestamp = timestamp,
            sentAtMs = sentAtMs,
            status = if (direction == "sent") parseStatus(status ?: "sent") else SimpleChatAdapter.Status.SENT,
            isEdited = isEdited,
            viaSync = obj.optBoolean("via_sync", false),
            isDeleted = isDeleted,
            replyToMessageId = replyToMessageId,
            replyToPreview = replyToPreview,
            // The 1:1 history load now reads the reaction summary too (the group path, `itemFromGroupHistoryJson`, already did). Reactions are kept in the DB
            // (`message_reactions`) and show in the live event, but a reopen or app restart would hide them. `load_message_history` puts the `reactions` field
            // in the JSON (see Rust `reactions_summary`).
            reactions = obj.optString("reactions", "")
        )
    }

    /** The 'replying to' label in the quote box. In 1:1 there are only two possibilities: me or the other side. */
    private fun resolveReplyLabel(replyToMessageId: String?): String? {
        if (replyToMessageId == null) return null
        val target = localMessages.firstOrNull { it.messageId == replyToMessageId } ?: return null
        return if (target.isMine) getString(R.string.lbl_you) else txtToolbarTitle.text?.toString()
    }

    /** After new rows are added: the target of a reply may only be loaded NOW (for example an older page arrived), so the labels are refreshed. */
    private fun resolveReplyLabels() {
        for (item in localMessages) {
            if (item.replyToMessageId != null) {
                item.replyToSenderLabel = resolveReplyLabel(item.replyToMessageId)
            }
        }
    }

    /**
     * Infinite scroll: one page from the LOCAL archive. Nothing is sent over the network.
     */
    private fun loadOlderHistory() {
        if (isLoadingOlderHistory || noMoreOlderHistory || localMessages.isEmpty()) return
        isLoadingOlderHistory = true
        progressOlderHistory.visibility = View.VISIBLE
        // Texts and attachments page on cursors of their own (separate tables).
        val beforeTimestamp = localMessages.filter { it.attachment == null }.minOfOrNull { it.timestamp }
            ?: localMessages.minOf { it.timestamp }
        val beforeAttachment = localMessages.filter { it.attachment != null }.minOfOrNull { it.timestamp } ?: Long.MAX_VALUE
        val peer = peerDeviceFingerprint
        // the archive query takes the core lock; scrolling must not wait for it.
        lifecycleScope.launch {
            val localOlder = withContext(Dispatchers.IO) {
                try {
                    val json = P2PLib.getMessageHistoryBefore(peer, beforeTimestamp, CHAT_PAGE_SIZE)
                    val array = JSONArray(json)
                    (0 until array.length()).map { itemFromHistoryJson(array.getJSONObject(it)) }
                } catch (e: Exception) {
                    null
                }
            }
            // Attachments older than the oldest loaded one (own cursor).
            val olderAttachments = withContext(Dispatchers.IO) {
                try {
                    val array = JSONArray(P2PLib.listAttachmentsBefore(peer, beforeAttachment, CHAT_PAGE_SIZE))
                    (0 until array.length()).map { attachmentItemFromJson(array.getJSONObject(it)) }
                } catch (e: Exception) {
                    emptyList()
                }
            }
            if (peer == peerDeviceFingerprint) {
                val page = newestPage(localOlder ?: emptyList(), olderAttachments)
                if (page.isNotEmpty()) prependOlderMessages(page)
                // an empty page from the local archive is the end of it.
                else if (localOlder != null) noMoreOlderHistory = true
            }
            // Local archive only: scrolling sends nothing to the network.
            isLoadingOlderHistory = false
            progressOlderHistory.visibility = View.GONE
        }
    }

    /** IO thread: the newest page (texts + attachments, see `newestPage`), in send order, and the ids of
     *  its messages that carry a 'seen' mark. `knownIds`: rows already on screen keep their decoded preview. */
    private fun readNewestPage(peer: String, knownIds: Set<String> = emptySet()): Pair<List<SimpleChatAdapter.Item>, List<String>> {
        val seen = mutableListOf<String>()
        val texts = try {
            val array = JSONArray(P2PLib.getMessageHistory(peer, CHAT_PAGE_SIZE))
            (0 until array.length()).map { i ->
                val obj = array.getJSONObject(i)
                val id = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
                if (id != null && obj.optString("seen_by", "[]").ifEmpty { "[]" } != "[]") seen.add(id)
                itemFromHistoryJson(obj)
            }
        } catch (e: Exception) {
            emptyList()
        }
        val attachments = try {
            val array = JSONArray(P2PLib.listAttachmentsBefore(peer, Long.MAX_VALUE, CHAT_PAGE_SIZE))
            (0 until array.length()).map { attachmentItemFromJson(array.getJSONObject(it), knownIds) }
        } catch (e: Exception) {
            emptyList()
        }
        return newestPage(texts, attachments).sortedBy { it.orderKey } to seen
    }

    /** Item from one `listAttachments`-shaped JSON row. No preview decode for ids in `skipPreview`. */
    private fun attachmentItemFromJson(obj: JSONObject, skipPreview: Set<String> = emptySet()): SimpleChatAdapter.Item {
        val previewHex = if (obj.optString("file_id") in skipPreview) "" else obj.optString("preview_hex", "")
        return SimpleChatAdapter.Item(
            messageId = obj.optString("file_id"),
            text = "",
            isMine = obj.optString("direction") == "sent",
            timestamp = obj.optLong("created_at", System.currentTimeMillis()),
            attachment = SimpleChatAdapter.AttachmentInfo(
                fileId = obj.optString("file_id"),
                fileName = obj.optString("file_name"),
                mimeType = obj.optString("mime_type"),
                totalSize = obj.optLong("total_size"),
                status = parseAttachmentStatus(obj.optString("status")),
                bytesDone = obj.optLong("bytes_transferred"),
                previewJpeg = if (previewHex.isNotEmpty() && previewHex != "null") hexToBytes(previewHex) else null,
                durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it },
                isSticker = obj.optBoolean("sticker", false)
            ),
            caption = obj.optString("caption", ""),
            replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null },
            replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
        )
    }

    /** See `loadOlderHistory`: an 'older_history' network reply from the other side. If an empty array comes back (no older message left, locally or on the other side),
     *  `noMoreOlderHistory` is set and this chat is not asked again. */
    private fun applyOlderHistory(obj: JSONObject) {
        // Only what the "Fetch older history" button asked for.
        if (!fetchHistoryButton.acceptsReply()) return
        val array = obj.optJSONArray("messages") ?: return
        // Empty: another source (peer, own device, server) may still answer.
        if (array.length() == 0) return
        fetchHistoryButton.onBackfilled()
        val items = (0 until array.length()).map { itemFromHistoryJson(array.getJSONObject(it)) }
        prependOlderMessages(items)
    }

    /** Adds older page results to the START of the list, shared by the local and network paths. A message already on screen (same `message_id`)
     *  is not added again, for example when the local page and the network reply contain the same rows. */
    private fun prependOlderMessages(items: List<SimpleChatAdapter.Item>) {
        if (items.isEmpty()) return
        val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
        val fresh = items.filter { it.messageId !in existingIds }.sortedBy { it.orderKey }
        if (fresh.isEmpty()) return
        if (fresh.last().orderKey > localMessages.firstOrNull()?.orderKey ?: Long.MAX_VALUE) {
            // The page belongs BELOW rows already shown (old attachments):
            // merge by send order and keep the row the user is looking at.
            val lm = recycler.layoutManager as? LinearLayoutManager
            val anchorPos = lm?.findFirstVisibleItemPosition() ?: -1
            val anchor = localMessages.getOrNull(anchorPos)
            val anchorTop = lm?.findViewByPosition(anchorPos)?.top ?: 0
            localMessages.addAll(fresh)
            localMessages.sortWith(compareBy { it.orderKey })
            resolveReplyLabels()
            adapter.notifyDataSetChanged()
            if (anchor != null) lm?.scrollToPositionWithOffset(localMessages.indexOf(anchor), anchorTop)
            return
        }
        localMessages.addAll(0, fresh)
        // See `resolveReplyLabels`: an older page may bring a reply chain not seen before (for example when the replied-to message is on this page too).
        resolveReplyLabels()
        adapter.notifyItemRangeInserted(0, fresh.size)
    }

    // ---------------------------------------------------------------
    // In-chat search
    // ---------------------------------------------------------------

    /**
     * In-chat message search. The search icon in the toolbar (see `onOptionsItemSelected`) opens and closes this row.
     * Search works ONLY on the messages loaded right now (`localMessages`). No network request is made for older history that is not loaded yet;
     * more history loads as the user scrolls up (see `loadOlderHistory`).
     */
    private fun setupMessageSearch() {
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

    private fun toggleMessageSearch() {
        if (layoutSearchMessages.visibility == View.VISIBLE) {
            layoutSearchMessages.visibility = View.GONE
            searchMessagesView.setQuery("", false)
            runMessageSearch("")
        } else {
            layoutSearchMessages.visibility = View.VISIBLE
            searchMessagesView.isIconified = false
            searchMessagesView.requestFocus()
            searchMessagesView.post {
                val imm = getSystemService(INPUT_METHOD_SERVICE) as InputMethodManager
                imm.showSoftInput(searchMessagesView.findFocus(), InputMethodManager.SHOW_IMPLICIT)
            }
        }
    }

    /** Deleted rows and attachments are not searched. Results start from the NEWEST (users usually look for the latest conversation). */
    private fun runMessageSearch(query: String) {
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

    private fun moveSearchMatch(delta: Int) {
        if (searchMatches.isEmpty()) return
        currentSearchMatchIndex = (currentSearchMatchIndex + delta + searchMatches.size) % searchMatches.size
        goToSearchMatch()
    }

    private fun goToSearchMatch() {
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
            // See AppRestarter: the Tor circuit and the network stack can only be set up cleanly when the process restarts.
            R.id.action_tor_reconnect -> {
                AppRestarter.confirmAndRestart(this)
                true
            }
            else -> super.onOptionsItemSelected(item)
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
    }

    private val readWatermarkHandler = Handler(Looper.getMainLooper())
    private val readWatermarkRunnable = Runnable {
        syncReadStateAsync()
    }
    // the core lock is not taken on the main thread.
    private fun syncReadStateAsync() {
        val peer = peerDeviceFingerprint
        val now = System.currentTimeMillis()
        Thread { try { P2PLib.syncReadState(peer, "", now) } catch (e: Exception) { } }.start()
    }

    /** Sends the 'read up to here' boundary to the other side. Debounced: many calls are collected into one packet (the Rust side cancels a pending
     *  older boundary, see `sync_read_state`). Called on chat open, `onResume`, and after a live message arrives. */
    private fun scheduleReadWatermark() {
        if (!AppLock.isUnlocked()) return
        readWatermarkHandler.removeCallbacks(readWatermarkRunnable)
        readWatermarkHandler.postDelayed(readWatermarkRunnable, 700L)
    }

    /** Messages that arrive while the screen is in the background are not heard by `messageListener`, so they do not reach the screen. They are read from
     *  the archive and the missing ones are filled in. For the race condition see the same note under `loadHistoryIfAvailable` (both run on IO, and which finishes first is not known). */
    private fun syncMissedMessages() {
        val targetPeer = peerDeviceFingerprint
        // Runs on every resume: rows already on screen keep their decoded
        // preview (see `refreshFrom`) instead of decoding it from hex again.
        val knownIds = localMessages.mapTo(HashSet()) { it.messageId }
        lifecycleScope.launch {
            val missed = withContext(Dispatchers.IO) { readNewestPage(targetPeer, knownIds) }
            if (peerDeviceFingerprint != targetPeer) return@launch
            val (missedItems, seenMessageIds) = missed
            val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
            val fresh = missedItems.filter { it.messageId !in existingIds }
            if (adapter.refreshFrom(missedItems)) resolveReplyLabels()
            if (fresh.isNotEmpty()) {
                localMessages.addAll(fresh)
                // If history loading finishes after a live message, appending would push the live message above the old history, off screen. Re-sort by send order.
                localMessages.sortWith(compareBy { it.orderKey })
                resolveReplyLabels()
                adapter.notifyDataSetChanged()
                adapter.dedupeByMessageId()
                onNewIncomingItemAdded()
            }
            // See the same 'seen' replay note under `loadHistoryIfAvailable`.
            if (seenMessageIds.isNotEmpty()) {
                val viewer = SimpleChatAdapter.SeenByViewer(
                    peerAvatar(), txtToolbarTitle.text.toString()
                )
                for (id in seenMessageIds) adapter.applySeen(id, listOf(viewer))
            }
        }
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
        sessionPollHandler.removeCallbacks(sessionPollRunnable)
        ownStatusPollHandler.removeCallbacks(ownStatusPollRunnable)
        peerStatusDot.cancelPulse()
        ownStatusDot.cancelPulse()
        typingHandler.removeCallbacksAndMessages(null)
        // The 6 s cleaner was just cancelled and the peer's "stopped typing"
        // event is missed while paused.
        layoutTypingIndicator.visibility = View.GONE
        sendTypingState(false)
        backgrounded = true // the recording keeps running (service has the microphone type)
        stopVoicePlayback()
    }

    /**
     * The pending callbacks of the handlers hold the adapter (and with it
     * this activity) alive: the reply highlight (2 s), the typing cleaner
     * (6 s), the voice tick, the recording timer, the two poll loops and the
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
