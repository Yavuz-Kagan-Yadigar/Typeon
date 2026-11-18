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

/**
 * Group chat screen. A group message is sent to each member as a separate 1:1 message, with `MessageContent::Text.group_id` (see packet.rs).
 * `receive_message` uses that field to raise a "group_message" event, which this screen handles.
 *
 * Group messages are archived and encrypted locally by `archive_group_message` (one row per group). `loadGroupHistoryIfAvailable`, called from `bindToIntent`,
 * loads that history, the same pattern as ChatActivity.
 * Known limit: this is the device's own archive. A message a member sent while this device was offline, and that never reached it, is not synced.
 * There is no network history request for groups yet, unlike `HistorySyncRequest` for direct chats.
 */
class GroupChatActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_GROUP_ID = "group_id"
        const val EXTRA_GROUP_NAME = "group_name"
        /** Same standard as SettingsFragment AVATAR_MAX_DIMENSION. */
        internal const val AVATAR_MAX_DIMENSION = 720
        internal const val AVATAR_JPEG_QUALITY = 85
        /** See the `resolveContactByIdentity` docs. */
        internal const val CONTACT_CACHE_TTL_MS = 5000L
        /** Same constants as ChatActivity (infinite scroll). */
        private const val LOAD_OLDER_HISTORY_THRESHOLD = 3
        /** Same constants as ChatActivity (group attachments). */
        internal const val MAX_ATTACHMENT_SIZE = 4L * 1024 * 1024 * 1024
        /** Same constant as ChatActivity. */
        internal const val TYPHOON_QUIET_WINDOW_MS = 15 * 60 * 1000L

        internal const val PREVIEW_MAX_DIMENSION = 480
        internal const val PREVIEW_JPEG_QUALITY = 85
        /** Same constant as ChatActivity `ownStatusPollRunnable`. */
        private const val OWN_STATUS_POLL_INTERVAL_MS = 2000L
        /** Same constants as ChatActivity (hold to record a voice message). Supported in group chats too. */
        internal const val RECORDING_MIN_DURATION_MS = 500L
        internal const val RECORDING_CANCEL_SWIPE_DP = 120f
        private const val VOICE_PLAYBACK_TICK_MS = 200L
        /** Same constants as ChatActivity (WhatsApp-style swipe to reply). Supported in group chats too. */
        internal const val REPLY_PREVIEW_MAX_CHARS = 120
        internal const val REPLY_SWIPE_MAX_DP = 72f
        internal const val REPLY_HIGHLIGHT_DURATION_MS = 1500L
        /** Same constants as ChatActivity (typing indicator). Supported in group chats too. */
        private const val TYPING_IDLE_TIMEOUT_MS = 3000L
        internal const val TYPING_INDICATOR_TIMEOUT_MS = 8000L
    }

    internal lateinit var groupId: String
    private lateinit var whiteboard: WhiteboardPanel
    internal val localMessages = mutableListOf<SimpleChatAdapter.Item>()
    internal lateinit var adapter: SimpleChatAdapter
    internal lateinit var selection: MessageSelection
    internal lateinit var recycler: RecyclerView
    internal lateinit var txtToolbarTitle: TextView
    internal lateinit var imgToolbarAvatar: ImageView
    /** See util.ConnectionStatus: this device's overall connection state. */
    private lateinit var txtOwnConnectionStatus: TextView
    /**
     * Coloured dot for this device's own connection state. Same pattern as ChatActivity (`util.PulsingStatusDot`).
     * A group chat has no single 'other side', so only this device's own state is shown. ChatActivity's `dotPeerStatus` has no equivalent here
     * (see the `layoutToolbarSubtitleRow` hiding note).
     */
    private lateinit var dotOwnStatus: View
    private lateinit var ownStatusDot: PulsingStatusDot
    /**
     * While a message is sending, the send button is replaced by a loading indicator and disabled, which blocks double taps (same pattern as ChatActivity, `sendNewMessage`).
     */
    /** Same note as ChatActivity `btnSend`: the cloud logo is a masked circular `ImageButton`. */
    internal lateinit var btnSend: ImageButton
    /** See `maybePlayTyphoonEffect` and ui.TyphoonParticleView. */
    internal lateinit var typhoonEffect: TyphoonParticleView
    internal lateinit var progressSending: ProgressBar
    internal lateinit var progressOlderHistory: ProgressBar

    /**
     * This device's raw `identity_id`: not formatted like `getIdentityCode`, but in the same form as the `sender_identity_id` fields, so they compare directly.
     * Used to decide whether a reply label shows "You" or a member's name (see `resolveReplyLabel` / `startReply`). `lazy`: resolved on first use only (a JNI call).
     */
    internal val ownIdentityId: String? by lazy {
        try {
            P2PLib.getOwnIdentityId().takeUnless { it.startsWith("Error:") }
        } catch (e: Exception) {
            null
        }
    }

    /** Last fetched state, used to fill the group info dialog opened by tapping the top bar (see `refreshGroupInfo`). */
    internal var isFounder = false
    internal var currentGroupAvatar: ByteArray? = null
    internal var memberIdentityIds: List<String> = emptyList()
    /** Used so the founder's own row in `showGroupInfoDialog` has no 'remove' button (see the `founder_identity_id` field of `list_groups`). */
    internal var founderIdentityId: String = ""
    /** Same fields as ChatActivity (infinite scroll). */
    internal var isLoadingOlderHistory = false
    internal var noMoreOlderHistory = false
    internal lateinit var fetchHistoryButton: FetchHistoryButton
    /** Set in onResume: the chat is really in front of the user, not just
     *  resumed for a moment underneath the app lock screen. */
    private var resumedUnlocked = false
    /** Invalidates a voice message still being loaded (see `loadAndPlayVoiceMessage`). */
    internal var voiceLoadRequest = 0
    /** Same fields as ChatActivity (in-chat message search). */
    /** Message ids, not list positions: prepending an older page or re-sorting moves every position. */
    internal var searchMatches: List<String> = emptyList()
    internal var currentSearchMatchIndex: Int = -1
    internal lateinit var layoutSearchMessages: View
    internal lateinit var searchMessagesView: SearchView
    internal lateinit var txtSearchMatchCount: TextView

    // --- Swipe right to reply (WhatsApp style). Same fields and pattern as ChatActivity. ---
    internal lateinit var swipeHelper: ItemTouchHelper
    internal val replyHighlightHandler = Handler(Looper.getMainLooper())

    // Typing indicator (group). Unlike 1:1, several members can type at
    // once, so each is tracked with its own clear-timeout. LinkedHashMap
    // keeps insertion order so the most recent typer's avatar shows.
    internal lateinit var layoutTypingIndicator: View
    internal lateinit var imgTypingAvatar: ImageView
    internal lateinit var txtTypingIndicator: TextView
    internal val typingHandler = Handler(Looper.getMainLooper())
    /**
     * The `sendGroupTypingIndicator` and `sendSeenReceipt` JNI calls can queue on the core lock, so they do NOT run on the main thread.
     * They run on a single-thread executor (same `DiscardPolicy` pattern as CallActivity: sends after close are dropped silently).
     */
    internal val netPack = java.util.concurrent.ThreadPoolExecutor(
        1, 1, 10L, java.util.concurrent.TimeUnit.SECONDS,
        java.util.concurrent.LinkedBlockingQueue(), java.util.concurrent.ThreadPoolExecutor.DiscardPolicy()
    )
    internal val typingMembers = LinkedHashMap<String, Runnable>()
    /** Our own last-reported typing state to other members. */
    internal var isTypingSent = false
    internal val stopTypingRunnable = Runnable { sendTypingState(false) }

    // Scroll-to-bottom FAB (see ChatActivity for the same fields/pattern).
    internal lateinit var fabScrollToBottom: FloatingActionButton

    // --- Hold to record a voice message (group). Same fields and pattern as ChatActivity.
    // The one difference: sending goes to ALL members through `prepareAndSendGroupFile`. ---
    internal var mediaRecorder: MediaRecorder? = null
    private var backgrounded = false
    internal var recordingDialog: AlertDialog? = null

    internal var recordingFile: File? = null
    internal var recordingStartTime: Long = 0L
    internal var recordingTouchStartX: Float = 0f
    internal var recordingCancelled = false
    internal lateinit var layoutMessageInput: View
    internal lateinit var layoutRecording: View
    internal lateinit var txtRecordingTimer: TextView
    internal lateinit var txtCancelPill: TextView
    internal val recordingHandler = Handler(Looper.getMainLooper())
    internal val recordingTimerRunnable = object : Runnable {
        override fun run() {
            val elapsed = android.os.SystemClock.elapsedRealtime() - recordingStartTime
            txtRecordingTimer.text = formatDurationMs(elapsed)
            recordingHandler.postDelayed(this, 200)
        }
    }
    internal val requestRecordAudioPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* reddedilse bile devam — kullanıcı düğmeye tekrar basmalı */ }

    // --- Voice message playback (group). Same fields and pattern as ChatActivity (one shared MediaPlayer). ---
    internal var voicePlayer: MediaPlayer? = null
    internal var voicePlayingFileId: String? = null
    internal var voicePlaybackSpeed: Float = 1f
    internal val voicePlaybackHandler = Handler(Looper.getMainLooper())
    internal val voicePlaybackTickRunnable = object : Runnable {
        override fun run() {
            val player = voicePlayer
            val fileId = voicePlayingFileId
            if (player != null && fileId != null) {
                try {
                    adapter.tickVoicePlayback(fileId, player.currentPosition, player.duration)
                } catch (e: Exception) { /* MediaPlayer o an geçerli bir durumda olmayabilir */ }
                voicePlaybackHandler.postDelayed(this, VOICE_PLAYBACK_TICK_MS)
            }
        }
    }

    /**
     * group_message_local_id -> (identity_id -> viewer info). Accumulates the different members who saw the same message.
     * See the note in SimpleChatAdapter applySeen: it expects the FULL list.
     */
    internal val seenByPerMessage = mutableMapOf<String, MutableMap<String, SimpleChatAdapter.SeenByViewer>>()

    /** See util.ConnectionStatus and ChatActivity `ownStatusPollRunnable`: this device's overall connection state (same pattern). */
    private val ownStatusPollHandler = Handler(Looper.getMainLooper())
    private val ownStatusPollRunnable: Runnable = object : Runnable {
        override fun run() {
            val self = this
            // ConnectionStatus.current makes a JNI call: keep it off the main thread.
            lifecycleScope.launch {
                val status = withContext(Dispatchers.IO) { ConnectionStatus.current(this@GroupChatActivity) }
                if (txtOwnConnectionStatus.text?.toString() != status.text) txtOwnConnectionStatus.text = status.text
                val colorRes = when (status.level) {
                    ConnectionStatus.Level.CONNECTED -> R.color.online
                    ConnectionStatus.Level.CONNECTING -> R.color.warning
                    ConnectionStatus.Level.PROBLEM -> R.color.danger
                }
                ownStatusDot.update(colorRes, pulsing = status.level == ConnectionStatus.Level.CONNECTING)
                ownStatusPollHandler.removeCallbacks(self)
                if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) {
                    ownStatusPollHandler.postDelayed(self, OWN_STATUS_POLL_INTERVAL_MS)
                }
            }
        }
    }

    /** `registerForActivityResult` must be called BEFORE the Activity is STARTED. See the same note in ChatActivity and SettingsFragment. */
    internal val pickGroupAvatarLauncher = registerForActivityResult(com.p2p.messenger.util.OpenDocumentAtHome()) { uri ->
        uri?.let { onGroupAvatarPicked(it) }
    }

    /** Same note as ChatActivity `pickFileLauncher` (group attachments). */
    private val pickGroupFileLauncher = registerForActivityResult(com.p2p.messenger.util.OpenMultipleDocumentsAtHome()) { uris ->
        if (uris.isNotEmpty()) promptAttachmentCaption(uris = uris) { caption, picked ->
        sendPickedFiles(picked.map { it.uri!! to it.hiRes }, caption, takeQuote()).invokeOnCompletion { picked.forEach { it.release() } }
    }
    }

    /** Same note as ChatActivity `takePhotoLauncher`: an instant capture and crop, with the result arriving as a `CapturedImage`. */
    private val takePhotoLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            CapturedImage.take()?.let { jpeg -> promptAttachmentCaption(jpeg = jpeg, onRetake = { findViewById<View>(R.id.btnCamera).performClick() }) { caption, picked -> picked.firstOrNull()?.let { onGroupPhotoCaptured(it.jpeg!!, caption, it.hiRes, takeQuote()) } } }
        }
    }

    internal val stickerPicker = StickerPicker(this, { id, quote -> P2PLib.sendGroupSticker(groupId, id, quote?.id ?: "", quote?.preview ?: "", quote?.sender ?: "") }, ::takeQuote) { item ->
        item.replyToSenderLabel = resolveReplyLabel(item.replyToMessageId)
        adapter.addMessage(item)
        scrollToBottomNow()
    }

    /**
     * The `peer` field has no meaning here: a group message arrives pairwise over several 1:1 connections. So this screen looks at `group_id` instead,
     * and only handles "group_message" events.
     */
    private val messageListener: (String) -> Unit = { json ->
        try {
            val obj = JSONObject(json)
            val type = obj.optString("type")
            when {
                type == "stickers_changed" -> runOnUiThread { stickerPicker.reload() }
                (type == "group_call_offer" && obj.optString("group_id") == groupId) || type == "call_state" ->
                    runOnUiThread { refreshCallOffer() }
                type == "group_message" && obj.optString("group_id") == groupId ->
                    runOnUiThread { handleIncomingGroupMessage(obj) }
                // Multi-device echo: a group message I sent from another of my devices is shown here as sent as well.
                type == "sibling_group_message" && obj.optString("group_id") == groupId ->
                    runOnUiThread { handleSiblingGroupMessage(obj) }
                // "seen" carries no `group_id`: `handleIncomingSeen` keeps it
                // only when it names one of OUR messages in this list.
                type == "seen" && !obj.isNull("group_message_local_id") ->
                    runOnUiThread { handleIncomingSeen(obj) }
                // Bulk seen: a member sent a 'read up to here' boundary (see Rust `apply_incoming_read_watermark`).
                type == "seen_bulk" && obj.optString("group_id") == groupId ->
                    runOnUiThread { handleIncomingSeenBulk(obj) }
                // Rust emits this event when a GroupUpdate is processed (name, membership, avatar; see group_ops.rs process_group_update).
                // The top bar avatar refreshes on it, so an open screen picks up a changed group photo.
                type == "group_updated" && obj.optString("group_id") == groupId ->
                    runOnUiThread { refreshGroupInfo() }
                // The old-page reply from the other member (see `loadOlderGroupHistory`).
                type == "older_group_history" && obj.optString("group_id") == groupId ->
                    runOnUiThread { applyOlderGroupHistory(obj) }
                // Group message edit and delete. Rust's receive_message Edit/Delete arm carries `group_id`, so no outer 'peer' filter is needed (unlike 1:1).
                type == "group_edit" && obj.optString("group_id") == groupId ->
                    runOnUiThread { adapter.applyEdit(obj.optString("message_id"), obj.optString("text")) }
                type == "group_delete" && obj.optString("group_id") == groupId ->
                    runOnUiThread { adapter.applyDelete(obj.optString("message_id")) }
                // Emoji reactions: Rust sends a ready SUMMARY string (see `reactions_summary`).
                type == "reaction" && obj.optString("group_id") == groupId ->
                    runOnUiThread { adapter.applyReactions(obj.optString("message_id"), obj.optString("reactions")) }
                // `isNull("group_id")` filters out 1:1 typing events too (they never carry it).
                type == "typing" && !obj.isNull("group_id") && obj.optString("group_id") == groupId ->
                    runOnUiThread { handleIncomingGroupTyping(obj) }
                // "file_offer" is handled only when it belongs to this group (carried in `group_id`).
                // file_progress, file_complete and file_failed are keyed by a globally unique `file_id`, so they are handled unconditionally.
                // If the file is not in `localMessages` they are no-ops (see SimpleChatAdapter.applyAttachmentUpdate).
                (type == "file_offer" || type == "sibling_file") && !obj.isNull("group_id") && obj.optString("group_id") == groupId ->
                    runOnUiThread { handleIncomingGroupFileOffer(obj) }
                type == "file_progress" -> runOnUiThread {
                    adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.DOWNLOADING, obj.optLong("bytes_done"))
                }
                type == "history_backfilled" -> runOnUiThread {
                    syncMissedGroupMessages()
                    // Rows older than the loaded page: read them from the local archive now.
                    if (fetchHistoryButton.onBackfilled()) {
                        noMoreOlderHistory = false
                        loadOlderGroupHistory()
                    }
                }
                type == "file_complete" -> runOnUiThread {
                    adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.COMPLETE)
                }
                // A copy of one of our group messages was given up or cancelled.
                type == "status" && obj.optString("group_id") == groupId && obj.optString("status") == "error" -> runOnUiThread {
                    adapter.applyStatus(obj.optString("message_id"), SimpleChatAdapter.Status.ERROR)
                }
                // End-to-end Ack from a member: a copy got through, a failure
                // mark set by another member's copy goes away.
                type == "status" && obj.optString("group_id") == groupId && obj.optString("status") == "delivered" -> runOnUiThread {
                    adapter.applyStatus(obj.optString("message_id"), SimpleChatAdapter.Status.SENT)
                }
                type == "file_failed" -> runOnUiThread {
                    adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.FAILED)
                }
                // The file was deleted locally: the bubble must not keep showing 'completed', and it should become downloadable again.
                type == "file_evicted" -> runOnUiThread {
                    adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.OFFERED)
                }
                // A member leaving the group: refresh the member list and subtitle here too (`group_updated` above already covers it).
                type == "member_left" && obj.optString("group_id") == groupId ->
                    runOnUiThread { refreshGroupInfo() }
                // A member deleted their account: show a visible notice to everyone in the group.
                type == "account_deleted" &&
                    (obj.optJSONArray("group_ids")?.let { a -> (0 until a.length()).any { a.optString(it) == groupId } } == true) ->
                    runOnUiThread {
                        val name = obj.optString("display_name").ifBlank { obj.optString("identity_id").take(8) }
                        Toast.makeText(this, getString(R.string.msg_contact_deleted_account, name), Toast.LENGTH_LONG).show()
                        refreshGroupInfo()
                    }
                // Rust emits this event when a GroupUpdate fails the signature, version or founder check. Show it, so the user knows the group was not updated.
                type == "group_update_failed" && obj.optString("group_id") == groupId -> runOnUiThread {
                    Toast.makeText(
                        this, getString(R.string.error_group_update_rejected), Toast.LENGTH_LONG
                    ).show()
                }
            }
        } catch (e: Exception) {
            // Unparseable event: ignore silently.
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)
        // Fill the lazy own id and the contact cache off the main thread, so the first main-thread use does not take the core lock.
        lifecycleScope.launch(Dispatchers.IO) { ownIdentityId }
        refreshContactCacheAsync()
        whiteboard = WhiteboardPanel(this, findViewById(R.id.whiteboardHost), findViewById(R.id.whiteboardHandle))
        // Sender names in the hue of each member's whiteboard pen (HSV): dark theme
        // 30 % saturation, value 100 % in the dark theme and 50 % in the light one.
        whiteboard.onParticipants = { ids ->
            val dark = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
                android.content.res.Configuration.UI_MODE_NIGHT_YES
            val value = if (dark) 1f else 0.5f
            val colors = ids.withIndex().associate { (i, id) ->
                id to android.graphics.Color.HSVToColor(floatArrayOf(360f * i / ids.size, 0.3f, value))
            }
            if (colors != adapter.senderColors) {
                adapter.senderColors = colors
                @Suppress("NotifyDataSetChanged") adapter.notifyDataSetChanged()
            }
        }
        com.p2p.messenger.util.ThemePrefs.applyChatBackground(this)
        // See the util.ChatListDrawer docs.
        com.p2p.messenger.util.ChatListDrawer.setup(this) {
            // Back with the search bar open closes the bar, not the chat.
            (layoutSearchMessages.visibility == View.VISIBLE).also { if (it) toggleMessageSearch() }
        }

        // A group chat has no single handshake state (each member has its own 1:1 link), so this banner does not apply and stays hidden.
        findViewById<View>(R.id.layoutConnecting).visibility = View.GONE
        setupMessageSearch()

        layoutTypingIndicator = findViewById(R.id.layoutTypingIndicator)
        imgTypingAvatar = findViewById(R.id.imgTypingAvatar)
        txtTypingIndicator = findViewById(R.id.txtTypingIndicator)
        fabScrollToBottom = findViewById(R.id.fabScrollToBottom)
        fabScrollToBottom.setOnClickListener { scrollToBottomNow() }

        recycler = findViewById(R.id.recyclerMessages)
        adapter = SimpleChatAdapter(localMessages)
        val groupLayoutManager = LinearLayoutManager(this)
        recycler.layoutManager = groupLayoutManager
        recycler.adapter = adapter
        adapter.warmPool(recycler)
        // Message bubbles flickered: tick, seen and reaction updates arrive through `notifyItemChanged`, and the default animator cross-fades each bubble
        // between its old and new state, so change animations are off. A new message at the bottom gets a small pop.
        recycler.itemAnimator = MessageItemAnimator()
        // The single outer outline of merged bubbles. See MergedBubbleDecoration for why each bubble's own background is not enough.
        recycler.addItemDecoration(MergedBubbleDecoration(adapter))
        // Loads older history when the list is scrolled near the top.
        recycler.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                if (groupLayoutManager.findFirstVisibleItemPosition() <= LOAD_OLDER_HISTORY_THRESHOLD) {
                    loadOlderGroupHistory()
                }
                updateScrollToBottomFabVisibility()
                fetchHistoryButton.update()
            }
        })
        progressOlderHistory = findViewById(R.id.progressOlderHistory)
        attachScrollDatePill(recycler, findViewById(R.id.txtScrollDate)) { localMessages.getOrNull(it)?.timestamp }
        fetchHistoryButton = FetchHistoryButton(findViewById(R.id.btnFetchHistory), recycler, true,
            { groupId }, { localMessages.minOfOrNull { it.orderKey } ?: 0L })
        // Group messages also get Edit and Delete (plus Resend if sending failed). See ChatActivity.showEditDeleteDialog, same pattern.
        adapter.onItemLongPress = { item -> showGroupEditDeleteDialog(item) }
        selection = MessageSelection(this, adapter, { saveGroupAttachmentToDownloads(it) }) { P2PLib.deleteGroupMessage(groupId, it) }
        adapter.onAttachmentClick = { item -> onGroupAttachmentClicked(item) }
        // Long press on an attachment bubble opens 'Save to Downloads' and 'Open with another app'. This was not wired on this screen before
        // (see ChatActivity.onAttachmentLongClicked, same pattern).
        adapter.onAttachmentLongClick = { item -> onGroupAttachmentLongClicked(item) }
        adapter.onReactionsClick = { item -> showReactionsDialog(item) }
        adapter.onReplyPreviewClick = { targetMessageId -> scrollToMessage(targetMessageId) }
        stickerPicker.provideBubbleImages(adapter)
        setupSwipeToReply()
        // Voice recording and playback in group chats use the same MediaRecorder and MediaPlayer setup as ChatActivity. The one difference:
        // sending goes to ALL members through `prepareAndSendGroupFile` (see `sendVoiceMessage`).
        layoutMessageInput = findViewById(R.id.layoutMessageInput)
        layoutRecording = findViewById(R.id.layoutRecording)
        txtRecordingTimer = findViewById(R.id.txtRecordingTimer)
        txtCancelPill = findViewById(R.id.txtCancelPill)
        setupVoiceRecordButton()
        adapter.onVoicePlayClick = { item -> onVoicePlayClicked(item) }
        adapter.onVoiceSpeedClick = { item -> onVoiceSpeedClicked(item) }
        adapter.onVoiceSeek = { item, positionMs -> onVoiceSeeked(item, positionMs) }

        // File, photo and video attachment sending. See ChatActivity.onFilePicked, same pattern.
        findViewById<ImageButton>(R.id.btnAttach).setOnClickListener {
            // Same note as ChatActivity: the system picker is an external process.
            AppLock.beginTrustedExcursion()
            pickGroupFileLauncher.launch(arrayOf("*/*"))
        }

        // Same note as ChatActivity: direct camera.
        findViewById<ImageButton>(R.id.btnCamera).setOnClickListener {
            takePhotoLauncher.launch(Intent(this, CameraCaptureActivity::class.java))
        }

        findViewById<ImageButton>(R.id.btnSticker).setOnClickListener {
            stickerPicker.show()
        }

        // Same note as ChatActivity. A group has no real group-photo concept here, so the badge AvatarUtil generates from the name is shown
        // (the same visual language as contacts without a photo).
        val toolbarTitleView = layoutInflater.inflate(R.layout.actionbar_chat_title, null)
        txtToolbarTitle = toolbarTitleView.findViewById(R.id.txtToolbarTitle)
        imgToolbarAvatar = toolbarTitleView.findViewById(R.id.imgToolbarAvatar)
        txtOwnConnectionStatus = toolbarTitleView.findViewById(R.id.txtOwnConnectionStatus)
        dotOwnStatus = toolbarTitleView.findViewById(R.id.dotOwnStatus)
        ownStatusDot = PulsingStatusDot(dotOwnStatus)
        // See actionbar_chat_title.xml: there is no single other side or handshake state, so the whole text and status dot ROW is hidden.
        // Hiding only the text would leave an orphan, unlabelled dot.
        toolbarTitleView.findViewById<View>(R.id.layoutToolbarSubtitleRow).visibility = View.GONE
        // Tapping the top bar opens the group info (member list, plus profile photo change for the founder only).
        toolbarTitleView.setOnClickListener { showGroupInfoDialog() }
        // Tapping the avatar itself opens fullscreen with pinch-to-zoom, overriding the general click on the row. See AvatarUtil.openFullscreen.
        imgToolbarAvatar.setOnClickListener { AvatarUtil.openFullscreen(this, currentGroupAvatar) }
        supportActionBar?.apply {
            setDisplayShowCustomEnabled(true)
            setDisplayShowTitleEnabled(false)
            // Same note as ChatActivity: the connection status view must span the full toolbar width to appear at the far right.
            setCustomView(toolbarTitleView, ActionBar.LayoutParams(ActionBar.LayoutParams.MATCH_PARENT, ActionBar.LayoutParams.MATCH_PARENT))
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
        progressSending = findViewById(R.id.progressSending)
        btnSend.setOnClickListener {
            val text = input.text.toString()
            if (text.isBlank()) return@setOnClickListener
            input.text.clear()
            sendNewMessage(text)
        }
        // Only sends on false->true/true->false transitions (see ChatActivity).
        input.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                updateMentionPopup(input)
                typingHandler.removeCallbacks(stopTypingRunnable)
                if (s.isNullOrBlank()) {
                    sendTypingState(false)
                } else {
                    sendTypingState(true)
                    typingHandler.postDelayed(stopTypingRunnable, TYPING_IDLE_TIMEOUT_MS)
                }
            }
        })

        // See ChatActivity: saving to Downloads below API 29 needs it, and a
        // user who only ever saved from a group was never asked.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q &&
            checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            AppLock.beginTrustedExcursion()
            androidx.core.app.ActivityCompat.requestPermissions(
                this, arrayOf(android.Manifest.permission.WRITE_EXTERNAL_STORAGE), 0
            )
        }

        if (!bindToIntent(intent)) {
            finish()
            return
        }
        // Not on a restore: the same intent would send the files again.
        if (savedInstanceState == null) consumeShare(intent)
    }

    /**
     * See ChatActivity.bindToIntent, same note: when `FLAG_ACTIVITY_CLEAR_TOP` calls `onNewIntent` on an existing `GroupChatActivity` in the stack,
     * this override is required. Without it, the notification brought the wrong (old) group forward.
     */
    internal fun bindToIntent(intent: Intent): Boolean {
        val newGroupId = intent.getStringExtra(EXTRA_GROUP_ID) ?: return false
        val groupName = intent.getStringExtra(EXTRA_GROUP_NAME) ?: newGroupId.take(8)
        txtToolbarTitle.text = groupName
        AvatarUtil.renderInto(imgToolbarAvatar, currentGroupAvatar, groupName)

        if (::groupId.isInitialized && groupId == newGroupId) {
            refreshGroupInfo()
            return true
        }

        groupId = newGroupId
        whiteboard.bind("", groupId)
        refreshCallOffer()
        P2PService.activeConversationId = "group:$groupId"
        localMessages.clear()
        adapter.notifyDataSetChanged()
        seenByPerMessage.clear()
        isLoadingOlderHistory = false
        noMoreOlderHistory = false
        searchMatches = emptyList()
        currentSearchMatchIndex = -1
        if (::layoutSearchMessages.isInitialized) layoutSearchMessages.visibility = View.GONE
        // The typing line and the voice message playback belonged to the PREVIOUS group. The 1:1 `bindToIntent` resets them, but the group twin did not:
        // if group A was in front and B was opened, A's indicator stayed on top of B. `isTypingSent` must be reset too, or B's first typing packet is suppressed.
        typingHandler.removeCallbacksAndMessages(null)
        typingMembers.clear()
        updateTypingIndicatorUi()
        isTypingSent = false
        stopVoicePlayback()
        refreshGroupInfo()
        loadGroupHistoryIfAvailable()
        return true
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!bindToIntent(intent)) {
            finish()
            return
        }
        consumeShare(intent)
    }

    internal var mentionPopup: ListPopupWindow? = null

    // ---------------------------------------------------------------
    // Swipe right to reply (WhatsApp style), also in group chats. Same pattern as ChatActivity.
    // ---------------------------------------------------------------

    /** The target captured when the swipe STARTS (see `setupSwipeToReply`). */
    internal var swipeStartMessageId: String? = null

    /** The first quote in the input with its sender: the attachment or
     *  sticker being sent answers it. */
    internal fun takeQuote() = com.p2p.messenger.util.Quote.takeFirst(findViewById(R.id.edtMessage))?.let { q ->
        val target = localMessages.firstOrNull { it.messageId == q.id }
        q.copy(sender = target?.senderIdentityId ?: if (target?.isMine == true) ownIdentityId else null)
    }

    internal val avatarBytesCache = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()
    internal data class ContactLookup(val displayName: String, val avatarHex: String?)

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_chat_search, menu)
        attendView = menu.findItem(R.id.action_attend_call).actionView?.findViewById<TextView>(R.id.txtAttendCall)?.apply {
            setOnClickListener { CallActivity.startOutgoing(this@GroupChatActivity, null, groupId, callOffer == 2) }
            val tv = android.util.TypedValue()
            theme.resolveAttribute(androidx.appcompat.R.attr.colorPrimary, tv, true)
            val pill = com.p2p.messenger.util.fullSaturation(tv.data)
            background = background?.mutate()?.also { it.setTint(pill) }
            // onPrimary was picked for the paler accent: pick again for the saturated one (the icon follows the text colour).
            setTextColor(if (androidx.core.graphics.ColorUtils.calculateContrast(android.graphics.Color.WHITE, pill or 0xFF000000.toInt()) >= 3.0) android.graphics.Color.WHITE else android.graphics.Color.BLACK)
        }
        return true
    }

    /** A call running in this group (`P2PLib.groupCallOffer`): 0 none, 1 voice, 2 video. */
    private var callOffer = 0
    private var attendView: TextView? = null
    private val offerRecheck = android.os.Handler(android.os.Looper.getMainLooper())
    private val attendPulse = com.p2p.messenger.util.SlowPulse { attendView?.alpha = 1f - 0.6f * it }

    override fun onPrepareOptionsMenu(menu: Menu): Boolean {
        menu.findItem(R.id.action_attend_call).isVisible = callOffer != 0
        menu.findItem(R.id.action_voice_call).isVisible = callOffer == 0
        menu.findItem(R.id.action_video_call).isVisible = callOffer == 0
        attendView?.let { v ->
            val icon = ContextCompat.getDrawable(this, if (callOffer == 2) R.drawable.videocall else R.drawable.voicecall)?.mutate()
            val size = (18 * resources.displayMetrics.density).toInt()
            icon?.setBounds(0, 0, size, size)
            icon?.setTint(v.currentTextColor)
            v.setCompoundDrawablesRelative(icon, null, null, null)
        }
        return super.onPrepareOptionsMenu(menu)
    }

    /** Off the main thread (core lock); the pill only fades while the screen is in front. */
    internal fun refreshCallOffer() {
        if (!::groupId.isInitialized) return
        val gid = groupId
        lifecycleScope.launch {
            val offer = withContext(Dispatchers.IO) { try { P2PLib.groupCallOffer(gid) } catch (e: Throwable) { 0 } }
            if (gid != groupId) return@launch
            if (offer != callOffer) {
                callOffer = offer
                invalidateOptionsMenu()
            }
            attendPulse.running = callOffer != 0 && lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)
            // The core's expiry event can be missed: look again until the pill is gone.
            offerRecheck.removeCallbacksAndMessages(null)
            // Only in front: a refresh that finishes after onPause must not start polling in the background.
            if (attendPulse.running) offerRecheck.postDelayed({ refreshCallOffer() }, 20_000)
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == R.id.action_search_messages) {
            toggleMessageSearch()
            return true
        }
        if (item.itemId == R.id.action_voice_call || item.itemId == R.id.action_video_call) {
            CallActivity.startOutgoing(this, null, groupId, item.itemId == R.id.action_video_call)
            return true
        }
        if (item.itemId == R.id.action_tor_reconnect) {
            AppRestarter.confirmAndRestart(this)
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    override fun onResume() {
        super.onResume()
        val wasBackgrounded = backgrounded
        backgrounded = false
        if (wasBackgrounded) promptRecordingDecision()
        // When this group chat opens, clear any pending notification for it.
        // A locked app resumes this screen for a moment under the password prompt. Nothing was read then, so no notification is cleared and
        // no "read up to now" is sent (see onPause too).
        resumedUnlocked = com.p2p.messenger.util.AppLock.isUnlocked()
        if (resumedUnlocked) com.p2p.messenger.util.NotificationHelper.clearForGroup(this, groupId)
        // So a wallpaper or colour change made in Settings shows here at once when returning to this screen.
        com.p2p.messenger.util.ThemePrefs.applyChatBackground(this)
        // The conversation id FIRST: a message that lands between the
        // listener registration and this line would post a notification for
        // the group that is already open on the screen.
        P2PService.activeConversationId = "group:$groupId"
        P2PService.addMessageListener(messageListener)
        refreshCallOffer()
        ownStatusPollHandler.post(ownStatusPollRunnable)
        // While paused (e.g. the file picker or MediaViewerActivity was on
        // top of this screen), the live listener above was detached — any
        // message that arrived meanwhile was archived but never appended
        // to the UI. Catch up now.
        syncMissedGroupMessages()
        // Members are told the read boundary as soon as the group opens (not only in onPause, and to members as well as sibling devices).
        if (resumedUnlocked) scheduleGroupReadWatermark()
    }

    internal val groupReadWatermarkHandler = Handler(Looper.getMainLooper())
    internal val groupReadWatermarkRunnable = Runnable {
        syncGroupReadStateAsync()
    }
    override fun onPause() {
        super.onPause()
        if (!::groupId.isInitialized) return  // group id is not initialised yet, nothing to load
        P2PService.removeMessageListener(messageListener)
        if (P2PService.activeConversationId == "group:$groupId") {
            P2PService.activeConversationId = null
        }
        // Sibling devices AND members both count this group as read (see `sync_read_state`, which now has two targets).
        groupReadWatermarkHandler.removeCallbacks(groupReadWatermarkRunnable)
        if (resumedUnlocked) {
            com.p2p.messenger.util.ReadStatePrefs.markRead(this, "group:$groupId")
            syncGroupReadStateAsync()
        }
        resumedUnlocked = false
        ownStatusPollHandler.removeCallbacks(ownStatusPollRunnable)
        // Same note as ChatActivity onPause: a pulse animation must not stay registered with vsync in the background while the Activity is not visible.
        ownStatusDot.cancelPulse()
        attendPulse.running = false
        offerRecheck.removeCallbacksAndMessages(null)
        // Tell members we stopped typing and clear pending timeouts.
        typingHandler.removeCallbacksAndMessages(null)
        typingMembers.clear()
        updateTypingIndicatorUi()
        sendTypingState(false)
        // Same note as ChatActivity onPause: an ongoing recording or playback is stopped cleanly when the user leaves the screen.
        backgrounded = true // the recording keeps running (service has the microphone type)
        stopVoicePlayback()
    }

    /**
     * The pending callbacks of the handlers hold the adapter (and with it
     * this activity) alive: the reply highlight (2 s), the typing cleaners,
     * the voice tick, the recording timer, the status poll and the read
     * watermark. `onPause` only removes SOME of them — a pending callback
     * survived the pause and kept the whole screen alive.
     */
    override fun onDestroy() {
        if (mediaRecorder != null) finishVoiceRecording(send = false)
        typingHandler.removeCallbacksAndMessages(null)
        replyHighlightHandler.removeCallbacksAndMessages(null)
        recordingHandler.removeCallbacksAndMessages(null)
        voicePlaybackHandler.removeCallbacksAndMessages(null)
        ownStatusPollHandler.removeCallbacksAndMessages(null)
        groupReadWatermarkHandler.removeCallbacksAndMessages(null)
        mentionPopup?.dismiss()
        netPack.shutdownNow()
        super.onDestroy()
    }
}
