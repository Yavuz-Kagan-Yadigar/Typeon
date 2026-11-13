package com.p2p.messenger.ui

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
        private const val AVATAR_MAX_DIMENSION = 720
        private const val AVATAR_JPEG_QUALITY = 85
        /** Same constant as ChatActivity. */
        private const val HISTORY_LOAD_LIMIT = 200
        /** See the `resolveContactByIdentity` docs. */
        private const val CONTACT_CACHE_TTL_MS = 5000L
        /** Same constants as ChatActivity (infinite scroll). */
        private const val OLDER_HISTORY_PAGE_SIZE = 50
        private const val OLDER_HISTORY_REPLY_WAIT_MS = 15_000L
        private const val LOAD_OLDER_HISTORY_THRESHOLD = 3
        /** Same constants as ChatActivity (group attachments). */
        private const val MAX_ATTACHMENT_SIZE = 4L * 1024 * 1024 * 1024
        /** Same constant as ChatActivity. */
        private const val TYPHOON_QUIET_WINDOW_MS = 15 * 60 * 1000L

        private const val PREVIEW_MAX_DIMENSION = 480
        private const val PREVIEW_JPEG_QUALITY = 85
        /** Same constant as ChatActivity `ownStatusPollRunnable`. */
        private const val OWN_STATUS_POLL_INTERVAL_MS = 2000L
        /** Same constants as ChatActivity (hold to record a voice message). Supported in group chats too. */
        private const val RECORDING_MIN_DURATION_MS = 500L
        private const val RECORDING_CANCEL_SWIPE_DP = 120f
        private const val VOICE_PLAYBACK_TICK_MS = 200L
        /** Same constants as ChatActivity (WhatsApp-style swipe to reply). Supported in group chats too. */
        private const val REPLY_PREVIEW_MAX_CHARS = 120
        private const val REPLY_SWIPE_MAX_DP = 72f
        private const val REPLY_HIGHLIGHT_DURATION_MS = 1500L
        /** Same constants as ChatActivity (typing indicator). Supported in group chats too. */
        private const val TYPING_IDLE_TIMEOUT_MS = 3000L
        private const val TYPING_INDICATOR_TIMEOUT_MS = 8000L
    }

    private lateinit var groupId: String
    private lateinit var whiteboard: WhiteboardPanel
    private val localMessages = mutableListOf<SimpleChatAdapter.Item>()
    private lateinit var adapter: SimpleChatAdapter
    private lateinit var selection: MessageSelection
    private lateinit var recycler: RecyclerView
    private lateinit var txtToolbarTitle: TextView
    private lateinit var imgToolbarAvatar: ImageView
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
    private lateinit var btnSend: ImageButton
    /** See `maybePlayTyphoonEffect` and ui.TyphoonParticleView. */
    private lateinit var typhoonEffect: TyphoonParticleView
    private lateinit var progressSending: ProgressBar

    /**
     * This device's raw `identity_id`: not formatted like `getIdentityCode`, but in the same form as the `sender_identity_id` fields, so they compare directly.
     * Used to decide whether a reply label shows "You" or a member's name (see `resolveReplyLabel` / `startReply`). `lazy`: resolved on first use only (a JNI call).
     */
    private val ownIdentityId: String? by lazy {
        try {
            P2PLib.getOwnIdentityId().takeUnless { it.startsWith("Error:") }
        } catch (e: Exception) {
            null
        }
    }

    /** Last fetched state, used to fill the group info dialog opened by tapping the top bar (see `refreshGroupInfo`). */
    private var isFounder = false
    private var currentGroupAvatar: ByteArray? = null
    private var memberIdentityIds: List<String> = emptyList()
    /** Used so the founder's own row in `showGroupInfoDialog` has no 'remove' button (see the `founder_identity_id` field of `list_groups`). */
    private var founderIdentityId: String = ""
    /** Same fields as ChatActivity (infinite scroll). */
    private var isLoadingOlderHistory = false
    private var noMoreOlderHistory = false
    private lateinit var fetchHistoryButton: FetchHistoryButton
    private var olderHistoryRequest = 0
    private var olderHistoryEmptyReply = false
    /** Set in onResume: the chat is really in front of the user, not just
     *  resumed for a moment underneath the app lock screen. */
    private var resumedUnlocked = false
    /** Invalidates a voice message still being loaded (see `loadAndPlayVoiceMessage`). */
    private var voiceLoadRequest = 0
    /** Same fields as ChatActivity (in-chat message search). */
    /** Message ids, not list positions: prepending an older page or re-sorting moves every position. */
    private var searchMatches: List<String> = emptyList()
    private var currentSearchMatchIndex: Int = -1
    private lateinit var layoutSearchMessages: View
    private lateinit var searchMessagesView: SearchView
    private lateinit var txtSearchMatchCount: TextView

    // --- Swipe right to reply (WhatsApp style). Same fields and pattern as ChatActivity. ---
    private lateinit var swipeHelper: ItemTouchHelper
    private val replyHighlightHandler = Handler(Looper.getMainLooper())

    // Typing indicator (group). Unlike 1:1, several members can type at
    // once, so each is tracked with its own clear-timeout. LinkedHashMap
    // keeps insertion order so the most recent typer's avatar shows.
    private lateinit var layoutTypingIndicator: View
    private lateinit var imgTypingAvatar: ImageView
    private lateinit var txtTypingIndicator: TextView
    private val typingHandler = Handler(Looper.getMainLooper())
    /**
     * The `sendGroupTypingIndicator` and `sendSeenReceipt` JNI calls can queue on the core lock, so they do NOT run on the main thread.
     * They run on a single-thread executor (same `DiscardPolicy` pattern as CallActivity: sends after close are dropped silently).
     */
    private val netPack = java.util.concurrent.ThreadPoolExecutor(
        1, 1, 10L, java.util.concurrent.TimeUnit.SECONDS,
        java.util.concurrent.LinkedBlockingQueue(), java.util.concurrent.ThreadPoolExecutor.DiscardPolicy()
    )
    private val typingMembers = LinkedHashMap<String, Runnable>()
    /** Our own last-reported typing state to other members. */
    private var isTypingSent = false
    private val stopTypingRunnable = Runnable { sendTypingState(false) }

    // Scroll-to-bottom FAB (see ChatActivity for the same fields/pattern).
    private lateinit var fabScrollToBottom: FloatingActionButton

    // --- Hold to record a voice message (group). Same fields and pattern as ChatActivity.
    // The one difference: sending goes to ALL members through `prepareAndSendGroupFile`. ---
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
    private var recordingStartTime: Long = 0L
    private var recordingTouchStartX: Float = 0f
    private var recordingCancelled = false
    private lateinit var layoutMessageInput: View
    private lateinit var layoutRecording: View
    private lateinit var txtRecordingTimer: TextView
    private lateinit var txtCancelPill: TextView
    private val recordingHandler = Handler(Looper.getMainLooper())
    private val recordingTimerRunnable = object : Runnable {
        override fun run() {
            val elapsed = android.os.SystemClock.elapsedRealtime() - recordingStartTime
            txtRecordingTimer.text = formatDurationMs(elapsed)
            recordingHandler.postDelayed(this, 200)
        }
    }
    private val requestRecordAudioPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* reddedilse bile devam — kullanıcı düğmeye tekrar basmalı */ }

    // --- Voice message playback (group). Same fields and pattern as ChatActivity (one shared MediaPlayer). ---
    private var voicePlayer: MediaPlayer? = null
    private var voicePlayingFileId: String? = null
    private var voicePlaybackSpeed: Float = 1f
    private val voicePlaybackHandler = Handler(Looper.getMainLooper())
    private val voicePlaybackTickRunnable = object : Runnable {
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
    private val seenByPerMessage = mutableMapOf<String, MutableMap<String, SimpleChatAdapter.SeenByViewer>>()

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
    private val pickGroupAvatarLauncher = registerForActivityResult(com.p2p.messenger.util.OpenDocumentAtHome()) { uri ->
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

    private val stickerPicker = StickerPicker(this, { id, quote -> P2PLib.sendGroupSticker(groupId, id, quote?.id ?: "", quote?.preview ?: "", quote?.sender ?: "") }, ::takeQuote) { item ->
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
        recycler.itemAnimator = MessageItemAnimator(adapter::isMineAt)
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

    /** Content selected from the share screen (see util.ShareIntake). */
    private fun consumeShare(intent: Intent) {
        com.p2p.messenger.util.ShareIntake.takeForward(intent)?.let { f ->
            AlertDialog.Builder(this)
                .setMessage(getString(R.string.confirm_forward, txtToolbarTitle.text))
                .setPositiveButton(R.string.btn_send) { _, _ ->
                    lifecycleScope.launch {
                        var done = 0
                        try {
                            for (p in f) {
                                if (p.file != null) onGroupFilePicked(Uri.fromFile(p.file), p.caption, hiRes = true, name = p.fileName, mime = p.mimeType).join()
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
            return
        }
        val share = com.p2p.messenger.util.ShareIntake.take(intent) ?: return
        com.p2p.messenger.util.ShareIntake.text(share)?.let {
            findViewById<EditText>(R.id.edtMessage).apply { setText(it); setSelection(text.length) }
        }
        val uris = com.p2p.messenger.util.ShareIntake.uris(share)
        if (uris.isEmpty()) return
        // The chat was picked with one tap in a list that reorders itself.
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.confirm_send_shared, uris.size, txtToolbarTitle.text))
            .setPositiveButton(R.string.btn_send) { _, _ -> sendPickedFiles(uris.map { it to false }) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * See ChatActivity.bindToIntent, same note: when `FLAG_ACTIVITY_CLEAR_TOP` calls `onNewIntent` on an existing `GroupChatActivity` in the stack,
     * this override is required. Without it, the notification brought the wrong (old) group forward.
     */
    private fun bindToIntent(intent: Intent): Boolean {
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

    /**
     * Loads group history in the background, through `getGroupMessageHistory` (same pattern as ChatActivity.loadHistoryIfAvailable).
     * Without it, the screen would show only live messages, so reopening the screen or restarting the app would hide all visible history
     * (the Rust side keeps it in `archive_group_message`).
     *
     * The JNI calls (`getGroupMessageHistory` and `listGroupAttachments`) and the per-row parsing (`itemFromGroupHistoryJson` / `itemFromGroupAttachmentJson`,
     * which can make another JNI call through `resolveContactByIdentity`) run on `Dispatchers.IO`. Only the list and adapter update runs on the main thread.
     * `targetGroupId` stops a result from being applied to the wrong chat if the user switches to another group before the load finishes.
     */
    private fun loadGroupHistoryIfAvailable() {
        val targetGroupId = groupId
        lifecycleScope.launch {
            val (merged, seenEntries) = withContext(Dispatchers.IO) {
                val json = try {
                    P2PLib.getGroupMessageHistory(targetGroupId, HISTORY_LOAD_LIMIT)
                } catch (e: Exception) {
                    null
                }
                val array = try {
                    if (json != null) JSONArray(json) else null
                } catch (e: Exception) {
                    null
                }
                val textItems = if (array != null) (0 until array.length()).map { itemFromGroupHistoryJson(array.getJSONObject(it)) } else emptyList()
                // See `seenViewersFromHistoryJson`. Rows are collected oldest to newest and replayed to `applySeen` in the same order,
                // so the adapter settles on the last message seen.
                val seenEntries = if (array != null) (0 until array.length()).mapNotNull { i ->
                    val obj = array.getJSONObject(i)
                    val localId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
                    val viewers = if (localId != null) seenViewersFromHistoryJson(obj) else emptyList()
                    if (localId != null && viewers.isNotEmpty()) localId to viewers else null
                } else emptyList()

                // Same pattern as ChatActivity.loadHistoryIfAvailable: attachments sent or received in the past are merged into the text messages by timestamp.
                val attachmentsJson = try {
                    P2PLib.listGroupAttachments(targetGroupId)
                } catch (e: Exception) {
                    null
                }
                val attachmentsArray = try {
                    if (attachmentsJson != null) JSONArray(attachmentsJson) else null
                } catch (e: Exception) {
                    null
                }
                val attachmentItems = if (attachmentsArray != null) {
                    (0 until attachmentsArray.length()).map { itemFromGroupAttachmentJson(attachmentsArray.getJSONObject(it)) }
                } else emptyList()

                (textItems + attachmentItems).sortedBy { it.orderKey } to seenEntries
            }
            if (groupId != targetGroupId) return@launch
            // syncMissedGroupMessages (onResume) can race this: both fetch on
            // IO and either can finish first. Filter by what's already in
            // localMessages, checked here on the main thread right before
            // merging, and notify only the actually-new range.
            val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
            val newItems = merged.filter { it.messageId !in existingIds }
            if (newItems.isNotEmpty()) {
                localMessages.addAll(newItems)
                // If history loading finishes after a live message, appending would push the live message above the old history, off screen.
                // Re-sort by send order.
                localMessages.sortWith(compareBy { it.orderKey })
                resolveReplyLabels()
                adapter.notifyDataSetChanged()
                adapter.dedupeByMessageId()
                recycler.scrollToPosition(localMessages.size - 1)
            }
            // See `seenViewersFromHistoryJson`. The replay runs AFTER all messages are added to the adapter. `applySeen` returns -1 from `indexOfMessageId` for a row
            // not added yet, and only ONE pending entry (`pendingSeenMessageId`) can be held, so earlier calls would be overwritten.
            // The "who saw" info is refreshed even when `newItems` is empty (for example when these rows are already in localMessages).
            for ((localId, viewers) in seenEntries) {
                val map = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
                for ((identityId, viewer) in viewers) map[identityId] = viewer
                adapter.applySeen(localId, map.values.toList())
            }
        }
    }

    /**
     * Same pattern as ChatActivity's attachment-row loader: builds an `Item` from one JSON row of `listGroupAttachments`.
     * The sender (if this is not my own message) is resolved via `sender_identity_id`, the same logic as for text messages.
     */
    private fun itemFromGroupAttachmentJson(obj: JSONObject, knownIds: Set<String> = emptySet()): SimpleChatAdapter.Item {
        val isMine = obj.optString("direction") == "sent"
        val senderIdentityId = if (obj.isNull("sender_identity_id")) null else obj.optString("sender_identity_id").ifEmpty { null }
        val sender = if (!isMine && senderIdentityId != null) resolveContactByIdentity(senderIdentityId) else null
        val previewHex = obj.optString("preview_hex", "")
        val previewJpeg = if (obj.optString("file_id") !in knownIds && previewHex.isNotEmpty() && previewHex != "null") hexToBytes(previewHex) else null
        return SimpleChatAdapter.Item(
            messageId = obj.optString("file_id"),
            text = "",
            isMine = isMine,
            timestamp = obj.optLong("created_at", System.currentTimeMillis()),
            senderName = sender?.displayName ?: senderIdentityId?.take(8),
            senderAvatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
            senderIdentityId = senderIdentityId,
            attachment = SimpleChatAdapter.AttachmentInfo(
                fileId = obj.optString("file_id"),
                fileName = obj.optString("file_name"),
                mimeType = obj.optString("mime_type"),
                totalSize = obj.optLong("total_size"),
                status = parseAttachmentStatus(obj.optString("status")),
                bytesDone = obj.optLong("bytes_transferred"),
                previewJpeg = previewJpeg,
                durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it },
                peerDeviceFingerprint = obj.optString("peer_device_fingerprint"),
                isSticker = obj.optBoolean("sticker", false)
            ),
            // Same as ChatActivity: an attachment from the archive also keeps its caption and reply context.
            caption = obj.optString("caption", ""),
            replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null },
            replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
        )
    }

    private fun parseAttachmentStatus(status: String): SimpleChatAdapter.AttachmentStatus = when (status) {
        "downloading" -> SimpleChatAdapter.AttachmentStatus.DOWNLOADING
        "complete" -> SimpleChatAdapter.AttachmentStatus.COMPLETE
        "failed" -> SimpleChatAdapter.AttachmentStatus.FAILED
        else -> SimpleChatAdapter.AttachmentStatus.OFFERED
    }

    /**
     * Same note as ChatActivity.itemFromHistoryJson: a JSON row from any of the three sources (local first load, local older page, older page from the network)
     * is parsed the same way.
     */
    private fun itemFromGroupHistoryJson(obj: JSONObject): SimpleChatAdapter.Item {
        val direction = obj.optString("direction")
        val isMine = direction == "sent"
        val senderIdentityId = if (obj.isNull("sender_identity_id")) null else obj.optString("sender_identity_id").ifEmpty { null }
        val sender = if (!isMine && senderIdentityId != null) resolveContactByIdentity(senderIdentityId) else null
        val messageId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
        // Same as ChatActivity.itemFromHistoryJson (WhatsApp-style reply). `replyToSenderLabel` cannot be resolved here; see `resolveReplyLabels`.
        val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
        val replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
        val replyToSenderIdentityId = if (obj.isNull("reply_to_sender_identity_id")) null else obj.optString("reply_to_sender_identity_id").ifEmpty { null }
        return SimpleChatAdapter.Item(
            messageId = messageId ?: UUID.randomUUID().toString(),
            text = obj.optString("text"),
            isMine = isMine,
            status = SimpleChatAdapter.Status.SENT,
            timestamp = obj.optLong("timestamp", System.currentTimeMillis()),
            // Send order: the sender's send time (same note as ChatActivity).
            sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 },
            senderName = sender?.displayName ?: senderIdentityId?.take(8),
            senderAvatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
            // See the Item.senderIdentityId docs. It is always stored, regardless of `isMine`. Archive 'sent' rows also carry `sender_identity_id`
            // (see the Rust `archive_group_message` call site), so the next reply can carry the correct identity (see `startReply`).
            senderIdentityId = senderIdentityId,
            replyToMessageId = replyToMessageId,
            replyToPreview = replyToPreview,
            replyToSenderIdentityId = replyToSenderIdentityId,
            isDeleted = obj.optBoolean("is_deleted", false),
            // The '(edited)' label comes from the archived `is_edited` flag (see Rust `ArchivedMessage.is_edited`), so it survives a reopen,
            // not only the live edit event.
            isEdited = obj.optBoolean("is_edited", false),
            mentionsMe = obj.optBoolean("mentions_me", false),
            reactions = obj.optString("reactions", "")
        )
    }

    /**
     * Seen state for old messages. Live `handleIncomingSeen` events fill `seenByPerMessage` only while the screen is open.
     * The history row's `seen_by` (see Rust `ArchivedMessage.seen_by`) is resolved the same way as `handleIncomingSeen`, so messages seen while the chat
     * was closed still show in the 'seen by' list after a reopen. It returns `(identityId, viewer)` pairs, so the caller can write them into
     * `seenByPerMessage` with the same key.
     */
    private fun seenViewersFromHistoryJson(obj: JSONObject): List<Pair<String, SimpleChatAdapter.SeenByViewer>> {
        val raw = obj.optString("seen_by", "[]").ifEmpty { "[]" }
        val arr = try { JSONArray(raw) } catch (e: Exception) { return emptyList() }
        val out = mutableListOf<Pair<String, SimpleChatAdapter.SeenByViewer>>()
        for (i in 0 until arr.length()) {
            val entry = arr.optJSONObject(i) ?: continue
            val identityId = entry.optString("identity_id")
            if (identityId.isEmpty()) continue
            val sender = resolveContactByIdentity(identityId)
            out.add(identityId to SimpleChatAdapter.SeenByViewer(
                avatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
                displayName = sender?.displayName ?: identityId.take(8)
            ))
        }
        return out
    }

    /** The label over a quote: "You" or the sender name of the quoted
     *  message, only when that message is in the local history. */
    private fun resolveReplyLabel(replyToMessageId: String?, replyToSenderIdentityId: String? = null): String? {
        if (replyToMessageId == null) return null
        val target = localMessages.find { it.messageId == replyToMessageId }
        if (target != null) {
            return if (target.isMine) getString(R.string.lbl_you) else target.senderName
        }
        // The quoted message is not here: the sender-claimed author id is
        // not trusted, so no name is shown (a member could forge a quote
        // attributed to someone else).
        return null
    }

    /** Same pattern as ChatActivity.resolveReplyLabels. */
    private fun resolveReplyLabels() {
        for (item in localMessages) {
            if (item.replyToMessageId != null) {
                item.replyToSenderLabel = resolveReplyLabel(item.replyToMessageId, item.replyToSenderIdentityId)
            }
        }
    }

    /**
     * Same pattern as ChatActivity.loadOlderHistory. When the top of the group history is scrolled to, it first tries the free local archive.
     * If that is not enough, it asks all reachable members over the network (see the Rust `request_older_group_history` fan-out).
     */
    private fun loadOlderGroupHistory() {
        if (isLoadingOlderHistory || noMoreOlderHistory || localMessages.isEmpty()) return
        isLoadingOlderHistory = true
        // Text rows only: the first load mixes the newest texts with EVERY
        // attachment ever sent, so one old photo used to move the cursor
        // past all the texts between it and the oldest loaded one.
        val beforeTimestamp = localMessages.filter { it.attachment == null }.minOfOrNull { it.timestamp }
            ?: localMessages.minOf { it.timestamp }
        val beforeAttachment = localMessages.filter { it.attachment != null }.minOfOrNull { it.timestamp } ?: Long.MAX_VALUE
        val gid = groupId
        // off the main thread (core lock); an empty page means the end of the archive.
        lifecycleScope.launch {
            val localOlder = withContext(Dispatchers.IO) {
                try {
                    val json = P2PLib.getGroupMessageHistoryBefore(gid, beforeTimestamp, OLDER_HISTORY_PAGE_SIZE)
                    val array = JSONArray(json)
                    (0 until array.length()).map { itemFromGroupHistoryJson(array.getJSONObject(it)) }
                } catch (e: Exception) {
                    null
                }
            }
            // Attachments older than the oldest loaded one (own cursor).
            val olderAttachments = withContext(Dispatchers.IO) {
                try {
                    val array = JSONArray(P2PLib.listGroupAttachmentsBefore(gid, beforeAttachment, OLDER_HISTORY_PAGE_SIZE))
                    (0 until array.length()).map { itemFromGroupAttachmentJson(array.getJSONObject(it)) }
                } catch (e: Exception) {
                    emptyList()
                }
            }
            if (gid == groupId) {
                val page = (localOlder ?: emptyList()) + olderAttachments
                if (page.isNotEmpty()) prependOlderMessages(page)
                else if (localOlder != null) noMoreOlderHistory = true
            }
            isLoadingOlderHistory = false
        }
    }

    /** See `loadOlderGroupHistory`: an 'older_group_history' network reply from a member. An empty array means this group is not asked again. */
    private fun applyOlderGroupHistory(obj: JSONObject) {
        val array = obj.optJSONArray("messages") ?: return
        // Every member answers; a later answer may carry reactions the first lacked.
        for (i in 0 until array.length()) {
            val m = array.getJSONObject(i)
            val reactions = m.optString("reactions")
            if (reactions.isNotEmpty()) adapter.applyReactions(m.optString("message_id"), reactions)
        }
        // Only what the "Fetch older history" button asked for.
        if (!fetchHistoryButton.acceptsReply()) return
        // Empty: another source (peer, own device, server) may still answer.
        if (array.length() == 0) return
        fetchHistoryButton.onBackfilled()
        val items = (0 until array.length()).map { itemFromGroupHistoryJson(array.getJSONObject(it)) }
        prependOlderMessages(items)
    }

    /** Same note as ChatActivity.prependOlderMessages. */
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
        resolveReplyLabels()
        adapter.notifyItemRangeInserted(0, fresh.size)
    }

    /**
     * Fetches this group's current state from `listGroups()` (founder or not, members, profile photo) and updates the top bar avatar too.
     *
     * `P2PLib.listGroups()` (a JNI call plus a DB query over ALL groups, avatar hex blobs included) runs on a background thread, not synchronously on the
     * main thread from `bindToIntent` (and so from `onCreate`). None of the callers depends on the updated `isFounder` / `memberIdentityIds` right after the call
     * (they run at the end of an event or are triggered by another screen's refresh), so fire-and-forget on a background task is safe.
     */
    private fun refreshGroupInfo() {
        val targetGroupId = groupId
        lifecycleScope.launch {
            val array = withContext(Dispatchers.IO) {
                try {
                    JSONArray(P2PLib.listGroups())
                } catch (e: Exception) {
                    null
                }
            } ?: return@launch
            if (groupId != targetGroupId) return@launch
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                if (obj.optString("group_id") != targetGroupId) continue
                isFounder = obj.optBoolean("is_founder")
                founderIdentityId = obj.optString("founder_identity_id")
                val avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
                currentGroupAvatar = avatarHex?.let { hexToBytes(it) }
                val members = obj.optJSONArray("member_identity_ids")
                memberIdentityIds = (0 until (members?.length() ?: 0)).map { members!!.getString(it) }
                adapter.mentionNames = mentionCandidates().map { it.second }
                adapter.notifyDataSetChanged()
                AvatarUtil.renderInto(imgToolbarAvatar, currentGroupAvatar, txtToolbarTitle.text.toString())
                return@launch
            }
            // The group is gone here: the founder deleted it or removed us.
            Toast.makeText(this@GroupChatActivity, R.string.msg_group_gone, Toast.LENGTH_LONG).show()
            finish()
        }
    }

    /**
     * Tapping the top bar opens the member list and, for the founder only, the profile photo change and remove options, plus adding members.
     * The member and photo actions live here, not in the Groups tab.
     */
    private fun showGroupInfoDialog() {
        val view = layoutInflater.inflate(R.layout.dialog_group_info, null)
        val imgAvatar = view.findViewById<ImageView>(R.id.imgGroupAvatarLarge)
        val rowAvatarActions = view.findViewById<View>(R.id.rowAvatarActions)
        val btnChange = view.findViewById<Button>(R.id.btnChangeGroupPicture)
        val btnRemove = view.findViewById<Button>(R.id.btnRemoveGroupPicture)
        val txtMemberCount = view.findViewById<TextView>(R.id.txtGroupMemberCount)
        val btnAddMember = view.findViewById<Button>(R.id.btnAddMemberToGroup)
        val layoutMembersList = view.findViewById<LinearLayout>(R.id.layoutMembersList)

        AvatarUtil.renderInto(imgAvatar, currentGroupAvatar, txtToolbarTitle.text.toString())
        imgAvatar.setOnClickListener { AvatarUtil.openFullscreen(this, currentGroupAvatar) }
        rowAvatarActions.visibility = if (isFounder) View.VISIBLE else View.GONE
        // For the founder, 'Manage members' also covers removing members, not just showing the count.
        txtMemberCount.text = if (isFounder) {
            getString(R.string.lbl_manage_members)
        } else {
            resources.getQuantityString(R.plurals.lbl_member_count, memberIdentityIds.size, memberIdentityIds.size)
        }
        // 'Add member' sits above the list.
        btnAddMember.visibility = if (isFounder) View.VISIBLE else View.GONE

        val dialog = AlertDialog.Builder(this)
            .setTitle(txtToolbarTitle.text)
            .setView(view)
            .setNegativeButton(android.R.string.ok, null)
            .create()

        // Each member's name, plus (founder only, not on their own row) a confirmed remove button. A local function redraws the list
        // after a removal, without closing and reopening the dialog.
        fun populateMembers() {
            layoutMembersList.removeAllViews()
            for (identityId in memberIdentityIds) {
                val row = layoutInflater.inflate(R.layout.item_group_member, layoutMembersList, false)
                val rowAvatar = row.findViewById<ImageView>(R.id.imgMemberAvatar)
                val rowName = row.findViewById<TextView>(R.id.txtMemberName)
                val rowRemoveButton = row.findViewById<Button>(R.id.btnRemoveMember)
                val contact = resolveContactByIdentity(identityId)
                val displayName = when {
                    identityId == ownIdentityId -> getString(R.string.lbl_you)
                    else -> contact?.displayName ?: (identityId.take(16) + "…")
                }
                rowName.text = if (identityId == founderIdentityId) getString(R.string.lbl_founder_badge, displayName) else displayName
                AvatarUtil.renderInto(rowAvatar, contact?.avatarHex?.let { hexToBytes(it) }, displayName)
                if (isFounder && identityId != founderIdentityId) {
                    rowRemoveButton.visibility = View.VISIBLE
                    rowRemoveButton.setOnClickListener {
                        confirmRemoveMember(identityId, displayName) { populateMembers() }
                    }
                    // If the founder loses all devices, the group is locked for good: nobody can add or remove members, or change its name or photo.
                    // A long press on a member hands over the founder role, which avoids that.
                    row.setOnLongClickListener {
                        confirmTransferFounder(identityId, displayName) {
                            dialog.dismiss()
                        }
                        true
                    }
                } else {
                    rowRemoveButton.visibility = View.GONE
                }
                layoutMembersList.addView(row)
            }
        }
        populateMembers()

        btnChange.setOnClickListener {
            AppLock.beginTrustedExcursion()
            pickGroupAvatarLauncher.launch(arrayOf("image/*"))
        }
        btnRemove.setOnClickListener {
            setGroupAvatar(null)
            dialog.dismiss()
        }
        btnAddMember.setOnClickListener {
            dialog.dismiss()
            showAddMembersDialog()
        }
        view.findViewById<Button>(R.id.btnGroupFilesMedia).setOnClickListener {
            dialog.dismiss()
            startActivity(Intent(this, StorageActivity::class.java)
                .putExtra(StorageActivity.EXTRA_CHAT_KIND, "group")
                .putExtra(StorageActivity.EXTRA_CHAT_ID, groupId)
                .putExtra(StorageActivity.EXTRA_CHAT_NAME, txtToolbarTitle.text.toString()))
        }
        if (isFounder) {
            // Founder-only: re-send the signed group state to every member device.
            val parent = btnAddMember.parent as ViewGroup
            parent.addView(Button(this).apply {
                setText(R.string.action_resend_group)
                setOnClickListener {
                    val gid = groupId
                    lifecycleScope.launch {
                        val result = withContext(Dispatchers.IO) {
                            try { P2PLib.resendGroupToAll(gid) } catch (e: Throwable) { "Error: ${e.message}" }
                        }
                        Toast.makeText(this@GroupChatActivity,
                            if (result.startsWith("Error:")) R.string.error_network else R.string.msg_group_resent,
                            Toast.LENGTH_SHORT).show()
                    }
                }
            }, parent.indexOfChild(btnAddMember) + 1)
        }
        dialog.show()
    }

    /**
     * Asks for confirmation before removing a member (not the founder; see the caller). The removal cannot be undone:
     * Rust `remove_from_group` sends a signed `GroupChange::Remove` to all members.
     * `onRemoved` is the callback the caller passes (while the dialog is open), so the member list can be redrawn after a successful removal.
     */
    /**
     * Hands the group's admin role to another member. After the handover, THIS device can no longer manage the group.
     */
    private fun confirmTransferFounder(identityId: String, displayName: String, onDone: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle(R.string.action_transfer_founder)
            .setMessage(getString(R.string.confirm_transfer_founder, displayName))
            .setPositiveButton(R.string.action_transfer_founder) { _, _ ->
                val gid = groupId
                lifecycleScope.launch {
                    // signs and fans out to every member; not on the main thread.
                    val result = withContext(Dispatchers.IO) {
                        try { P2PLib.transferGroupFounder(gid, identityId) } catch (e: Throwable) { "Error: ${e.message}" }
                    }
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@GroupChatActivity, com.p2p.messenger.util.coreErrorText(this@GroupChatActivity, result), Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(this@GroupChatActivity, R.string.msg_founder_transferred, Toast.LENGTH_LONG).show()
                        refreshGroupInfo()
                        onDone()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmRemoveMember(identityId: String, displayName: String, onRemoved: () -> Unit) {
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.confirm_remove_member, displayName))
            .setPositiveButton(R.string.action_remove_member) { _, _ ->
                val gid = groupId
                lifecycleScope.launch {
                    // signed fan-out to every member; not on the main thread.
                    val ok = withContext(Dispatchers.IO) {
                        try { P2PLib.removeFromGroup(gid, identityId) } catch (e: Throwable) { "Error: ${e.message}" }
                    }
                    if (ok == "OK") {
                        Toast.makeText(this@GroupChatActivity, R.string.msg_member_removed, Toast.LENGTH_SHORT).show()
                        // `refreshGroupInfo` is asynchronous; the dialog redraws now.
                        if (gid == groupId) memberIdentityIds = memberIdentityIds - identityId
                        refreshGroupInfo()
                        onRemoved()
                    } else {
                        Toast.makeText(this@GroupChatActivity, coreErrorText(this@GroupChatActivity, ok), Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun onGroupAvatarPicked(uri: Uri) {
        lifecycleScope.launch(Dispatchers.IO) {
            val tempFile = File(File(cacheDir, "group_avatar").apply { mkdirs() }, UUID.randomUUID().toString())
            try {
                // Foreign `content://` bytes: capped, else the avatar fails (same toast).
                val copied = contentResolver.openInputStream(uri)?.use { it.copyToCapped(tempFile, MAX_FOREIGN_URI_BYTES) } ?: false
                if (!copied) throw java.io.IOException("Dosya açılamadı")
                val compressed = ImagePreview.compressFile(tempFile, AVATAR_MAX_DIMENSION, AVATAR_JPEG_QUALITY)
                withContext(Dispatchers.Main) { setGroupAvatar(compressed) }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@GroupChatActivity, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                }
            } finally {
                tempFile.delete()
            }
        }
    }

    /** Succeeds ONLY for the founder (see Rust `set_group_avatar`, which reuses the existing founder check of `validate_group_update`).
     *  A call from a non-founder returns "Error: ..." from Rust, and that error is shown here. */
    private fun setGroupAvatar(avatarJpeg: ByteArray?) {
        currentGroupAvatar = avatarJpeg
        AvatarUtil.renderInto(imgToolbarAvatar, avatarJpeg, txtToolbarTitle.text.toString())
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try {
                P2PLib.setGroupProfilePicture(groupId, avatarJpeg)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (result.startsWith("Error:")) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@GroupChatActivity, com.p2p.messenger.util.coreErrorText(this@GroupChatActivity, result), Toast.LENGTH_SHORT).show()
                    refreshGroupInfo()
                }
            }
        }
    }

    /** See the old GroupsFragment.showAddMembersDialog, which moved here. */
    private fun showAddMembersDialog() {
        // listContacts takes the core lock: off the main thread.
        lifecycleScope.launch {
            val contactsJson = withContext(Dispatchers.IO) {
                try { P2PLib.listContacts() } catch (e: Exception) { "[]" }
            }
            showAddMembersDialog(contactsJson)
        }
    }

    private fun showAddMembersDialog(contactsJson: String) {
        val array = try {
            JSONArray(contactsJson)
        } catch (e: Exception) {
            JSONArray()
        }
        if (array.length() == 0) {
            Toast.makeText(this, R.string.msg_no_contacts_to_add, Toast.LENGTH_LONG).show()
            return
        }
        // Not the people who are in the group already.
        val candidates = (0 until array.length()).map { array.getJSONObject(it) }
            .filter { it.optString("identity_id") !in memberIdentityIds }
        if (candidates.isEmpty()) {
            Toast.makeText(this, R.string.msg_no_contacts_to_add, Toast.LENGTH_LONG).show()
            return
        }
        val names = candidates.map { it.optString("display_name", "Bilinmeyen") }.toTypedArray()
        val identityIds = candidates.map { it.optString("identity_id") }
        val checked = BooleanArray(names.size)

        AlertDialog.Builder(this)
            .setTitle(R.string.lbl_add_member_to_group)
            .setMultiChoiceItems(names, checked) { _, which, isChecked -> checked[which] = isChecked }
            .setPositiveButton(R.string.lbl_add_member_to_group) { _, _ ->
                // Each invite signs, stores and sends under the core lock: off
                // the main thread (several at once froze the screen).
                val gid = groupId
                val picked = identityIds.indices.filter { checked[it] }
                lifecycleScope.launch {
                    for (i in picked) {
                        val ok = withContext(Dispatchers.IO) {
                            try { P2PLib.inviteToGroup(gid, identityIds[i]) } catch (e: Throwable) { "Error: ${e.message}" }
                        }
                        if (ok != "OK") {
                            Toast.makeText(this@GroupChatActivity, "${names[i]}: ${coreErrorText(this@GroupChatActivity, ok)}", Toast.LENGTH_SHORT).show()
                        }
                    }
                    refreshGroupInfo()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
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

    /**
     * Sends a group message in the background. `P2PLib.sendGroupMessage` (JNI) runs a separate ratchet encryption, a hybrid signature and a gossipsub
     * publish attempt for EVERY member (see Rust `send_group_message`, the pairwise fan-out). On the main thread that froze touch input for the whole
     * time, which grows with group size. `btnSend` is now disabled while it runs and `progressSending` is shown instead (same pattern as ChatActivity).
     */
    /** Other members as (identity id, display name), for @mentions. */
    private fun mentionCandidates(): List<Pair<String, String>> =
        memberIdentityIds.filter { it != ownIdentityId }
            .map { it to (resolveContactByIdentity(it)?.displayName ?: it.take(8)) }

    /** Ids of the members whose "@Name" is in [text], as a JSON array (null: none).
     *  The name must end at a non-letter/digit or the end of the text ("@Alice"
     *  does not mention "Al"); at each '@' only the longest matching name counts. */
    private fun mentionIdsJson(fullText: String): String? {
        // A quoted message's @names are not mentions of this one.
        val text = com.p2p.messenger.util.Quote.withoutQuotes(fullText)
        val candidates = mentionCandidates()
        val ids = LinkedHashSet<String>()
        var at = text.indexOf('@')
        while (at >= 0) {
            val hits = candidates.filter { (_, name) ->
                val end = at + 1 + name.length
                name.isNotEmpty() && text.startsWith(name, at + 1) && (end == text.length || !text[end].isLetterOrDigit())
            }
            val longest = hits.maxOfOrNull { it.second.length }
            hits.filter { it.second.length == longest }.mapTo(ids) { it.first }
            at = text.indexOf('@', at + 1)
        }
        return if (ids.isEmpty()) null else JSONArray(ids.toList()).toString()
    }

    private var mentionPopup: ListPopupWindow? = null

    /** "@" + what follows it up to the cursor opens a member picker; a pick
     *  writes "@Name " in its place. */
    private fun updateMentionPopup(input: EditText) {
        val text = input.text ?: return
        val cursor = input.selectionStart
        val at = if (cursor > 0) text.lastIndexOf('@', cursor - 1) else -1
        val query = if (at >= 0 && (at == 0 || text[at - 1].isWhitespace())) text.substring(at + 1, cursor) else null
        val matches = if (query == null || query.length > 32 || '\n' in query) emptyList()
            else mentionCandidates().filter { it.second.contains(query, ignoreCase = true) && it.second != query.trimEnd() }
        if (matches.isEmpty()) { mentionPopup?.dismiss(); return }
        val popup = mentionPopup ?: ListPopupWindow(this).also {
            it.anchorView = input
            it.inputMethodMode = ListPopupWindow.INPUT_METHOD_NEEDED
            mentionPopup = it
        }
        popup.setAdapter(android.widget.ArrayAdapter(this, android.R.layout.simple_list_item_1, matches.map { it.second }))
        popup.setOnItemClickListener { _, _, pos, _ ->
            popup.dismiss()
            text.replace(at, cursor, "@${matches[pos].second} ")
        }
        popup.show()
    }

    private fun sendNewMessage(text: String): kotlinx.coroutines.Job {
        btnSend.isEnabled = false
        btnSend.visibility = View.INVISIBLE
        progressSending.visibility = View.VISIBLE
        val targetGroupId = groupId
        return lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    P2PLib.sendGroupMessage(targetGroupId, text, null, null, null, mentionIdsJson(text))
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
            }
            progressSending.visibility = View.GONE
            btnSend.visibility = View.VISIBLE
            btnSend.isEnabled = true
            // onNewIntent can reuse this Activity for a different group
            // (singleTop) while this send is in flight — restore the send
            // button above regardless, but don't drop the result bubble into
            // the wrong group's message list.
            if (groupId != targetGroupId) return@launch
            val ok = !result.startsWith("Error:")
            if (!ok) {
                Toast.makeText(this@GroupChatActivity, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
            }
            // Use the `group_message_local_id` returned by Rust as the `messageId` of our own bubble (not a random UUID),
            // so the returned 'seen' notices match the right bubble.
            val localId = if (ok) result else UUID.randomUUID().toString()
            adapter.addMessage(
                SimpleChatAdapter.Item(
                    messageId = localId,
                    text = text,
                    isMine = true,
                    status = if (ok) SimpleChatAdapter.Status.SENT else SimpleChatAdapter.Status.ERROR,
                    senderIdentityId = ownIdentityId
                )
            )
            maybePlayTyphoonEffect()
            scrollToBottomNow()
        }
    }

    /**
     * Resends a failed (ERROR) group message. It keeps the SAME bubble (see `SimpleChatAdapter.retryMessage`) and adds no second copy.
     * It fans out again with a new `group_message_local_id` (same mechanism as `sendNewMessage`).
     */
    private fun retryFailedGroupMessage(item: SimpleChatAdapter.Item) {
        // Some members got it: send only the copies that failed, under the
        // same id (see Rust `retry_group_message_copies`). 0 = the message
        // never left this device, so it is sent as a new one below.
        val gid = groupId
        lifecycleScope.launch {
            val partial = withContext(Dispatchers.IO) { try { P2PLib.retryGroupMessageCopies(gid, item.messageId) } catch (e: Exception) { 0 } }
            when (partial) {
                1 -> { adapter.applyStatus(item.messageId, SimpleChatAdapter.Status.SENT); return@launch }
                -1 -> { Toast.makeText(this@GroupChatActivity, R.string.error_send_failed, Toast.LENGTH_SHORT).show(); return@launch }
            }
            // Same as ChatActivity.retryFailedMessage: if it is a reply, the same reply context is kept.
            val result = withContext(Dispatchers.IO) {
                try {
                    P2PLib.sendGroupMessage(gid, item.text, item.replyToMessageId, item.replyToPreview, item.replyToSenderIdentityId, mentionIdsJson(item.text))
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
            }
            if (result.startsWith("Error:")) {
                Toast.makeText(this@GroupChatActivity, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
                adapter.applyStatus(item.messageId, SimpleChatAdapter.Status.ERROR)
                return@launch
            }
            adapter.retryMessage(item.messageId, result, SimpleChatAdapter.Status.SENT)
        }
    }

    /**
     * Same pattern as ChatActivity.showEditDeleteDialog. Edit and delete also apply to group messages.
     * Attachment bubbles are not supported (see the SimpleChatAdapter long-press guard, `item.attachment == null`), so this fires only for plain text messages.
     * Messages from others also react to a long press, but for them only Copy is shown. Edit, Delete and Resend make sense only for our own messages.
     */
    private fun showGroupEditDeleteDialog(item: SimpleChatAdapter.Item) {
        if (!item.isMine) {
            // Same pattern as ChatActivity: we cannot edit someone else's message, but we can leave a reaction.
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
            if (com.p2p.messenger.util.Forward.canForward(item)) add(getString(R.string.action_forward))
            add(getString(R.string.action_select))
        }
        AlertDialog.Builder(this)
            .setItems(options.toTypedArray()) { _, which ->
                when (options[which]) {
                    getString(R.string.action_forward) -> com.p2p.messenger.util.Forward.start(this, item)
                    getString(R.string.action_select) -> selection.start(item)
                    getString(R.string.action_retry_message) -> retryFailedGroupMessage(item)
                    getString(R.string.action_react) -> showReactionPicker(item)
                    getString(R.string.action_edit_message) -> showEditGroupMessageDialog(item)
                    getString(R.string.action_delete_message) -> confirmDeleteGroupMessage(item)
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
                AlertDialog.Builder(this@GroupChatActivity)
                    .setTitle(R.string.title_reactions)
                    .setItems(rows.toTypedArray()) { _, which ->
                        // Removing my own reaction clears it (empty emoji).
                        if (which != myRow) return@setItems
                        lifecycleScope.launch(Dispatchers.IO) {
                            val summary = try { P2PLib.reactToGroupMessage(groupId, item.messageId, "") } catch (e: Exception) { "Error: ${e.message}" }
                            withContext(Dispatchers.Main) {
                                if (summary.startsWith("Error:")) {
                                    Toast.makeText(this@GroupChatActivity, summary, Toast.LENGTH_SHORT).show()
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

    /** Same pattern as ChatActivity.showReactionPicker, for groups. */
    private fun showReactionPicker(item: SimpleChatAdapter.Item) {
        ReactionPicker.show(this, item.reactions.isNotBlank()) { emoji ->
            lifecycleScope.launch(Dispatchers.IO) {
                val summary = try {
                    P2PLib.reactToGroupMessage(groupId, item.messageId, emoji)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                withContext(Dispatchers.Main) {
                    if (summary.startsWith("Error:")) {
                        Toast.makeText(this@GroupChatActivity, summary, Toast.LENGTH_SHORT).show()
                    } else {
                        adapter.applyReactions(item.messageId, summary)
                    }
                }
            }
        }
    }

    /** Same pattern and reasoning as ChatActivity.maybePlayTyphoonEffect. */
    private fun maybePlayTyphoonEffect() {
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

    /** Same pattern as ChatActivity.copyMessageText. */
    private fun copyMessageText(item: SimpleChatAdapter.Item) {
        com.p2p.messenger.util.copySensitive(this, "message", com.p2p.messenger.util.Quote.plain(com.p2p.messenger.util.Forward.strip(item.text)))
        Toast.makeText(this, R.string.lbl_copied, Toast.LENGTH_SHORT).show()
    }

    // ---------------------------------------------------------------
    // Swipe right to reply (WhatsApp style), also in group chats. Same pattern as ChatActivity.
    // ---------------------------------------------------------------

    /** The target captured when the swipe STARTS (see `setupSwipeToReply`). */
    private var swipeStartMessageId: String? = null

    private fun setupSwipeToReply() {
        val replyIcon = ContextCompat.getDrawable(this, R.drawable.ic_reply)
        val maxSwipePx = REPLY_SWIPE_MAX_DP * resources.displayMetrics.density
        val callback = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.RIGHT) {
            override fun onMove(rv: RecyclerView, viewHolder: RecyclerView.ViewHolder, target: RecyclerView.ViewHolder) = false

            override fun getSwipeThreshold(viewHolder: RecyclerView.ViewHolder): Float = 0.4f

            override fun onChildDraw(
                c: Canvas, recyclerView: RecyclerView, viewHolder: RecyclerView.ViewHolder,
                dX: Float, dY: Float, actionState: Int, isCurrentlyActive: Boolean
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

            /** Same fix as ChatActivity.setupSwipeToReply: the target is the message the gesture STARTED on, not the one it ended on. */
            override fun onSelectedChanged(viewHolder: RecyclerView.ViewHolder?, actionState: Int) {
                super.onSelectedChanged(viewHolder, actionState)
                if (actionState == ItemTouchHelper.ACTION_STATE_SWIPE && viewHolder != null) {
                    @Suppress("DEPRECATION")
                    val start = viewHolder.adapterPosition
                    swipeStartMessageId = localMessages.getOrNull(start)?.messageId
                }
            }

            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                @Suppress("DEPRECATION")
                val position = viewHolder.adapterPosition
                // With change animations off (see `supportsChangeAnimations`), `notifyItemChanged` rebinds the SAME view.
                // ItemTouchHelper keeps that view as swiped and keeps drawing it offset on every frame.
                // Detaching and re-attaching the helper clears that state and resets the offset.
                recycler.post {
                    swipeHelper.attachToRecyclerView(null)
                    swipeHelper.attachToRecyclerView(recycler)
                }
                if (position != RecyclerView.NO_POSITION) adapter.notifyItemChanged(position)
                val startedOn = swipeStartMessageId
                swipeStartMessageId = null
                val item = startedOn?.let { id -> localMessages.firstOrNull { it.messageId == id } } ?: return
                // Same pattern as ChatActivity: replies are supported for attachments too.
                if (item.isDeleted) return
                startReply(item)
            }
        }
        swipeHelper = ItemTouchHelper(callback)
        swipeHelper.attachToRecyclerView(recycler)
    }

    /** Same pattern as ChatActivity.startReply: in a group, when `item.isMine` is false, the label is the already-resolved `senderName` of that message. */
    private fun startReply(item: SimpleChatAdapter.Item) {
        com.p2p.messenger.util.Quote.insert(findViewById(R.id.edtMessage), item.messageId, replyPreviewFor(item))
    }

    /** Same pattern as `ChatActivity.replyPreviewFor`. */
    private fun replyPreviewFor(item: SimpleChatAdapter.Item): String {
        val attachment = item.attachment
        return if (attachment != null) {
            getString(R.string.lbl_attachment_reply_preview, attachment.fileName)
        } else {
            com.p2p.messenger.util.Quote.ownText(com.p2p.messenger.util.Forward.strip(item.text)).takeWholeChars(REPLY_PREVIEW_MAX_CHARS)
        }
    }

    /** Same pattern as ChatActivity.scrollToMessage. */
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

    // ---------------------------------------------------------------
    // Voice recording in group chats. Same pattern as ChatActivity (hold to record, slide right to cancel).
    // The one difference: sending goes through `prepareAndSendGroupFile`.
    // ---------------------------------------------------------------

    private fun setupVoiceRecordButton() {
        findViewById<ImageButton>(R.id.btnVoice).setOnTouchListener { _, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                        AppLock.beginTrustedExcursion()
                        requestRecordAudioPermission.launch(Manifest.permission.RECORD_AUDIO)
                        return@setOnTouchListener true
                    }
                    recordingTouchStartX = event.rawX
                    startVoiceRecording()
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
                MotionEvent.ACTION_UP -> {
                    if (mediaRecorder != null) finishVoiceRecording(send = !recordingCancelled)
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

    private fun updateCancelPill(dx: Float, thresholdPx: Float) {
        txtCancelPill.translationX = dx.coerceIn(0f, thresholdPx)
        val pastThreshold = dx > thresholdPx
        txtCancelPill.setTextColor(
            if (pastThreshold) android.graphics.Color.WHITE
            else com.google.android.material.color.MaterialColors.getColor(txtCancelPill, com.google.android.material.R.attr.colorOnSurfaceVariant)
        )
        txtCancelPill.backgroundTintList = if (pastThreshold) {
            android.content.res.ColorStateList.valueOf(
                com.google.android.material.color.MaterialColors.getColor(txtCancelPill, com.google.android.material.R.attr.colorError)
            )
        } else {
            null
        }
    }

    private fun startVoiceRecording() {
        val file = File(File(cacheDir, "voice").apply { mkdirs() }, "${UUID.randomUUID()}.m4a")
        val recorder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) MediaRecorder(this) else @Suppress("DEPRECATION") MediaRecorder()
        try {
            recorder.setAudioSource(MediaRecorder.AudioSource.MIC)
            recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            recorder.setAudioEncodingBitRate(64000)
            recorder.setAudioSamplingRate(44100)
            recorder.setOutputFile(file.absolutePath)
            // Upper limit: 10 minutes. The recording ends by itself, and the app then makes the same send-or-attach decision it makes on ACTION_UP.
            recorder.setMaxDuration(10 * 60 * 1000)
            recorder.setOnInfoListener { _, what, _ ->
                if (what == MediaRecorder.MEDIA_RECORDER_INFO_MAX_DURATION_REACHED) {
                    // The event may not arrive on the main thread, so the decision (and the screen work) runs on the main thread.
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
            file?.delete()
            recorder.release()
            return
        }
        recorder.release()
        if (!send || durationMs < RECORDING_MIN_DURATION_MS || file == null) {
            file?.delete()
            if (send) Toast.makeText(this, R.string.msg_recording_cancelled, Toast.LENGTH_SHORT).show()
            return
        }
        // Same note as ChatActivity: text goes under the voice message too.
        promptAttachmentCaption(onCancel = { file.delete() }) { caption, _ -> sendVoiceMessage(file, durationMs, caption, takeQuote()) }
    }

    /**
     * Same pattern as ChatActivity.sendVoiceMessage. The differences: `prepareAndSendGroupFile` (offered to ALL members), and the return value
     * is a plain file-id string, not the JSON `{message_id, status}` of the 1:1 path (see the `onGroupFilePicked` note on the return format).
     */
    private fun sendVoiceMessage(file: File, durationMs: Long, caption: String = "", quote: com.p2p.messenger.util.Quote.Ref? = null) {
        val targetGroupId = groupId
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
                    P2PLib.prepareAndSendGroupFile(
                        targetGroupId, prepared.file.absolutePath, file.name, "audio/mp4", null, durationMs.toInt(),
                        caption, quote?.id ?: "", quote?.preview ?: "", quote?.sender ?: ""
                    )
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                withContext(Dispatchers.Main) {
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@GroupChatActivity, com.p2p.messenger.util.coreErrorText(this@GroupChatActivity, result), Toast.LENGTH_SHORT).show()
                    } else {
                        adapter.addMessage(
                            SimpleChatAdapter.Item(
                                messageId = result,
                                text = "",
                                isMine = true,
                                caption = caption,
                                replyToMessageId = quote?.id,
                                replyToPreview = quote?.preview,
                                replyToSenderLabel = resolveReplyLabel(quote?.id),
                                attachment = SimpleChatAdapter.AttachmentInfo(
                                    fileId = result,
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
        val minutes = totalSeconds / 60
        val seconds = totalSeconds % 60
        return String.format(java.util.Locale.getDefault(), "%d:%02d", minutes, seconds)
    }

    // ---------------------------------------------------------------
    // Voice message playback in group chats. Same pattern as ChatActivity (one shared MediaPlayer).
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
            return
        }
        loadAndPlayVoiceMessage(item, attachment, 0)
    }

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

    private fun loadAndPlayVoiceMessage(item: SimpleChatAdapter.Item, attachment: SimpleChatAdapter.AttachmentInfo, startPositionMs: Int) {
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
                    Toast.makeText(this@GroupChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
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
                    if (voicePlaybackSpeed != 1f && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
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
                    Toast.makeText(this@GroupChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun onVoiceSpeedClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        val newSpeed = PlaybackSpeed.next(attachment.playbackSpeed)
        if (voicePlayingFileId == attachment.fileId) {
            voicePlaybackSpeed = newSpeed
            val player = voicePlayer
            if (player != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    // Setting the speed starts a paused player (documented): put it back.
                    val wasPlaying = player.isPlaying
                    player.playbackParams = PlaybackParams().setSpeed(newSpeed)
                    if (!wasPlaying) player.pause()
                } catch (e: Exception) { /* bazı cihazlarda desteklenmeyen hız oranı olabilir */ }
            }
            adapter.updateVoicePlayback(attachment.fileId, player?.isPlaying ?: false, player?.currentPosition ?: 0, newSpeed)
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
        } catch (e: Exception) { /* zaten serbest bırakılmış olabilir */ }
        voicePlayer = null
        voicePlayingFileId = null
        if (fileId != null) adapter.updateVoicePlayback(fileId, false, 0, voicePlaybackSpeed)
    }

    /**
     * Same pattern as ChatActivity.showEditMessageDialog. `editGroupMessage` returns "OK" or "Error: ..." (not JSON; see the P2PLib.kt note).
     */
    private fun showEditGroupMessageDialog(item: SimpleChatAdapter.Item) {
        val input = EditText(this)
        com.p2p.messenger.util.Quote.attach(input)
        input.setText(com.p2p.messenger.util.Forward.strip(item.text))
        input.hint = getString(R.string.lbl_edit_message_hint)
        AlertDialog.Builder(this)
            .setTitle(R.string.action_edit_message)
            .setView(input)
            .setPositiveButton(R.string.action_edit_message) { _, _ ->
                if (input.text.isBlank()) return@setPositiveButton
                // Same pattern as ChatActivity.showEditMessageDialog. The label stays.
                val newText = input.text.toString().let { if (com.p2p.messenger.util.Forward.isForwarded(item.text)) com.p2p.messenger.util.Forward.mark(it) else it }
                val gid = groupId
                lifecycleScope.launch {
                    val result = withContext(Dispatchers.IO) {
                        try { P2PLib.editGroupMessage(gid, item.messageId, newText) } catch (e: Throwable) { "Error: ${e.message}" }
                    }
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@GroupChatActivity, R.string.error_edit_failed, Toast.LENGTH_SHORT).show()
                    } else {
                        adapter.applyEdit(item.messageId, newText)
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDeleteGroupMessage(item: SimpleChatAdapter.Item) {
        AlertDialog.Builder(this)
            .setMessage(R.string.confirm_delete_message)
            .setPositiveButton(R.string.action_delete_message) { _, _ ->
                val gid = groupId
                lifecycleScope.launch {
                    val result = withContext(Dispatchers.IO) {
                        try { P2PLib.deleteGroupMessage(gid, item.messageId) } catch (e: Throwable) { "Error: ${e.message}" }
                    }
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@GroupChatActivity, R.string.error_delete_failed, Toast.LENGTH_SHORT).show()
                    } else {
                        adapter.applyDelete(item.messageId)
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Same pattern as ChatActivity.onPhotoCaptured, for groups. The captured frame is written to a temporary cache file, sent, and deleted at once.
     * Nothing is written to the gallery or shared storage.
     */
    private fun onGroupPhotoCaptured(jpeg: ByteArray, caption: String = "", hiRes: Boolean = false, quote: com.p2p.messenger.util.Quote.Ref? = null) {
        val fileName = "IMG_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date()) + ".jpg"
        // The group is captured BEFORE the coroutine: `groupId` was read
        // INSIDE the IO block, and the user can switch to another group
        // (singleTop) while the picture is being prepared — the file would
        // then be sent to the WRONG group (or to none).
        val targetGroupId = groupId
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
                val prepared = OutgoingMedia.prepare(tempFile, fileName, "image/jpeg", hiRes) { OutgoingMedia.askSendUnscrubbed(this@GroupChatActivity) }
                sent = prepared.file
                val result = P2PLib.prepareAndSendGroupFile(
                    targetGroupId, prepared.file.absolutePath, prepared.fileName, prepared.mimeType, previewJpeg, -1,
                    caption, quote?.id ?: "", quote?.preview ?: "", quote?.sender ?: ""
                )
                withContext(Dispatchers.Main) {
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@GroupChatActivity, com.p2p.messenger.util.coreErrorText(this@GroupChatActivity, result), Toast.LENGTH_SHORT).show()
                    } else {
                        adapter.addMessage(
                            SimpleChatAdapter.Item(
                                messageId = result,
                                text = "",
                                isMine = true,
                                attachment = SimpleChatAdapter.AttachmentInfo(
                                    fileId = result,
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
                                replyToSenderLabel = resolveReplyLabel(quote?.id),
                                replyToSenderIdentityId = quote?.sender
                            )
                        )
                        scrollToBottomNow()
                    }
                }
            } catch (e: Exception) {
                if (e is java.util.concurrent.CancellationException) return@launch
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@GroupChatActivity, getString(R.string.error_send_failed), Toast.LENGTH_SHORT).show()
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
        lifecycleScope.launch { files.forEachIndexed { i, (u, hiRes) -> val last = i == files.lastIndex; onGroupFilePicked(u, if (last) caption else "", hiRes, quote = if (last) quote else null).join() } }

    /** The first quote in the input with its sender: the attachment or
     *  sticker being sent answers it. */
    private fun takeQuote() = com.p2p.messenger.util.Quote.takeFirst(findViewById(R.id.edtMessage))?.let { q ->
        val target = localMessages.firstOrNull { it.messageId == q.id }
        q.copy(sender = target?.senderIdentityId ?: if (target?.isMine == true) ownIdentityId else null)
    }

    /**
     * Same pattern as ChatActivity.onFilePicked: the file picked with SAF is first copied to the cache,
     * then offered to ALL members with `prepareAndSendGroupFile`.
     */
    private fun onGroupFilePicked(uri: Uri, caption: String = "", hiRes: Boolean = false, name: String? = null, mime: String? = null, quote: com.p2p.messenger.util.Quote.Ref? = null): kotlinx.coroutines.Job {
        // The group is captured BEFORE the coroutine starts (same note as `onGroupPhotoCaptured`).
        val targetGroupId = groupId
        return lifecycleScope.launch(Dispatchers.IO) {
            // Provider queries are IPC to another app: not on the main thread.
            val fileName = name ?: queryDisplayName(uri) ?: "file"
            val mimeType = mime ?: contentResolver.getType(uri) ?: "application/octet-stream"
            val size = querySize(uri)
            val tooLarge = size != null && size > MAX_ATTACHMENT_SIZE
            withContext(Dispatchers.Main) {
                if (tooLarge) {
                    Toast.makeText(this@GroupChatActivity, getString(R.string.error_file_too_large_named, fileName), Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(this@GroupChatActivity, fileName, Toast.LENGTH_SHORT).show()
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
                } ?: throw java.io.IOException(getString(R.string.error_attachment_open_failed))

                val previewJpeg = try {
                    when {
                        mimeType.startsWith("image/") -> generateImagePreview(tempFile)
                        mimeType.startsWith("video/") -> generateVideoPreview(tempFile)
                        else -> null
                    }
                } catch (e: Exception) {
                    null
                }

                val prepared = OutgoingMedia.prepare(tempFile, fileName, mimeType, hiRes) { OutgoingMedia.askSendUnscrubbed(this@GroupChatActivity) }
                sent = prepared.file
                val result = P2PLib.prepareAndSendGroupFile(
                    targetGroupId, prepared.file.absolutePath, prepared.fileName, prepared.mimeType, previewJpeg, -1,
                    caption, quote?.id ?: "", quote?.preview ?: "", quote?.sender ?: ""
                )
                withContext(Dispatchers.Main) {
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@GroupChatActivity, com.p2p.messenger.util.coreErrorText(this@GroupChatActivity, result), Toast.LENGTH_SHORT).show()
                    } else {
                        adapter.addMessage(
                            SimpleChatAdapter.Item(
                                messageId = result,
                                text = "",
                                isMine = true,
                                attachment = SimpleChatAdapter.AttachmentInfo(
                                    fileId = result,
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
                                replyToSenderLabel = resolveReplyLabel(quote?.id),
                                replyToSenderIdentityId = quote?.sender
                            )
                        )
                        scrollToBottomNow()
                    }
                }
            } catch (e: Exception) {
                if (e is java.util.concurrent.CancellationException) return@launch
                withContext(Dispatchers.Main) {
                    if (e.message == "too_large") Toast.makeText(this@GroupChatActivity, getString(R.string.error_file_too_large_named, fileName), Toast.LENGTH_LONG).show() else Toast.makeText(this@GroupChatActivity, getString(R.string.error_send_failed), Toast.LENGTH_SHORT).show()
                }
            } finally {
                tempFile.delete()
                sent.delete()
            }
        }
    }

    /**
     * Same pattern as ChatActivity.onAttachmentClicked. One difference: the download target (`peerDeviceFingerprint`) is not a fixed field
     * but is carried on `AttachmentInfo`, because different attachments in a group can come from different senders.
     */
    private fun onGroupAttachmentClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        when (attachment.status) {
            SimpleChatAdapter.AttachmentStatus.OFFERED, SimpleChatAdapter.AttachmentStatus.FAILED -> {
                adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.DOWNLOADING, 0)
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try {
                        P2PLib.downloadFile(attachment.fileId, attachment.peerDeviceFingerprint)
                    } catch (e: Exception) {
                        "Error: ${e.message}"
                    }
                    if (result.startsWith("Error:")) {
                        withContext(Dispatchers.Main) {
                            adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.FAILED)
                            Toast.makeText(this@GroupChatActivity, com.p2p.messenger.util.coreErrorText(this@GroupChatActivity, result), Toast.LENGTH_SHORT).show()
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
                            Toast.makeText(this@GroupChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                        } else {
                            openGroupAttachmentFile(path)
                        }
                    }
                }
            }
            SimpleChatAdapter.AttachmentStatus.DOWNLOADING -> { /* no-op, zaten devam ediyor */ }
        }
    }

    /** Same as ChatActivity.openAttachmentFile; it does not depend on the peer. */
    private fun openGroupAttachmentFile(path: String) {
        // The file's own extension picks the viewer and the handler, not the
        // type the sender declared.
        val mimeType = android.webkit.MimeTypeMap.getSingleton()
            .getMimeTypeFromExtension(File(path).extension.lowercase()) ?: "*/*"
        try {
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", File(path))
            if (mimeType.startsWith("image/") || mimeType.startsWith("video/")) {
                val intent = Intent(this, MediaViewerActivity::class.java).apply {
                    putExtra(MediaViewerActivity.EXTRA_URI, uri)
                    putExtra(MediaViewerActivity.EXTRA_MIME_TYPE, mimeType)
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

    /** Same pattern as ChatActivity.onAttachmentLongClicked. This screen never wired it before, so a long press on a group attachment did nothing. */
    private fun onGroupAttachmentLongClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        // Same pattern as ChatActivity.onAttachmentLongClicked: only attachments we sent ourselves can be deleted.
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
                    getString(R.string.action_open_with) -> openGroupAttachmentWithChooser(attachment)
                    getString(R.string.action_save_to_downloads) -> saveGroupAttachmentToDownloads(attachment)
                    getString(R.string.action_save_as_jxl) -> saveGroupAttachmentToDownloads(attachment, original = true)
                    getString(R.string.action_copy_image) -> OutgoingMedia.copyImage(this, attachment.fileId)
                    getString(R.string.action_add_to_my_stickers) -> stickerPicker.saveReceived(attachment.fileId)
                    getString(R.string.action_delete_message) -> confirmDeleteGroupMessage(item)
                }
            }
            .show()
    }

    /** Same pattern as ChatActivity.openAttachmentWithChooser. */
    private fun openGroupAttachmentWithChooser(attachment: SimpleChatAdapter.AttachmentInfo) {
        lifecycleScope.launch(Dispatchers.IO) {
            val path = try {
                P2PLib.getAttachmentPlaintextPath(attachment.fileId)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (path.startsWith("Error:")) {
                    Toast.makeText(this@GroupChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                    return@withContext
                }
                try {
                    val uri = FileProvider.getUriForFile(this@GroupChatActivity, "$packageName.fileprovider", File(path))
                    val intent = Intent(Intent.ACTION_VIEW).apply {
                        // The file's own extension, never the type the sender declared.
                        setDataAndType(
                            uri,
                            android.webkit.MimeTypeMap.getSingleton()
                                .getMimeTypeFromExtension(File(path).extension.lowercase()) ?: "*/*"
                        )
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    com.p2p.messenger.util.confirmExternalOpen(this@GroupChatActivity, intent.type) {
                        AppLock.beginTrustedExcursion()
                        try { startActivity(Intent.createChooser(intent, getString(R.string.lbl_open_with_chooser))) } catch (e: Exception) {
                            Toast.makeText(this@GroupChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                        }
                    }
                } catch (e: Exception) {
                    Toast.makeText(this@GroupChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /** Same pattern as ChatActivity.saveAttachmentToDownloads. */
    /** `original`: a JPEG XL as it came (`image/jxl`), not converted. */
    private fun saveGroupAttachmentToDownloads(attachment: SimpleChatAdapter.AttachmentInfo, original: Boolean = false) {
        lifecycleScope.launch(Dispatchers.IO) {
            val plainPath = try {
                if (original) P2PLib.getAttachmentOriginalPath(attachment.fileId)
                else P2PLib.getAttachmentPlaintextPath(attachment.fileId)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (plainPath.startsWith("Error:")) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@GroupChatActivity, com.p2p.messenger.util.coreErrorText(this@GroupChatActivity, plainPath), Toast.LENGTH_SHORT).show()
                }
                return@launch
            }
            val (name, mime) = if (original) attachment.fileName.let { if (it.endsWith(".jxl", true)) it else "$it.jxl" } to "image/jxl"
                else OutgoingMedia.savedAs(File(plainPath), attachment.fileName, attachment.mimeType)
            val saved = saveToPublicDownloads(File(plainPath), name, mime)
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    this@GroupChatActivity,
                    if (saved) getString(R.string.msg_saved_to_downloads) else getString(R.string.error_attachment_open_failed),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    /** Same pattern as ChatActivity.saveToPublicDownloads. */
    /**
     * Makes the file name sent by the other side harmless before it is used as a FILE NAME.
     *
     * The core does the same cleaning (Rust `safe_file_name`, `receive_file_offer`), but only for offers received AFTER that change.
     * Rows already in the `files` table keep the raw name, and the API 26-28 branch below does `File(p2pDir, displayName)`.
     * A name such as "../../DCIM/Camera/IMG_0001.jpg" would then write to an arbitrary path in shared storage.
     */
    private fun safeSaveFileName(name: String): String {
        val cleaned = name
            .filter {
                it != '/' && it != '\\' && it != ':' && !it.isISOControl() &&
                    // Bidi overrides and zero-width characters disguise the extension.
                    Character.getType(it) != Character.FORMAT.toInt()
            }
            .trim()
            .trimStart('.')
            .trim()
        return cleaned.ifEmpty { "file" }.take(120)
    }

    private fun saveToPublicDownloads(source: File, displayName: String, mimeType: String): Boolean {
        return try {
            val safeName = safeSaveFileName(displayName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val values = android.content.ContentValues().apply {
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
                android.media.MediaScannerConnection.scanFile(this, arrayOf(dest.absolutePath), arrayOf(mimeType), null)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * A live group FileOffer, received as an event. Same logic as the ChatActivity handleIncomingEvent "file_offer" arm, plus the sender name and
     * avatar (resolved as for text messages, `resolveContactByIdentity`) and `peerDeviceFingerprint` (the download target).
     */
    private fun handleIncomingGroupFileOffer(obj: JSONObject) {
        val senderIdentityId = obj.optString("sender_identity_id")
        val sender = resolveContactByIdentity(senderIdentityId)
        val autoDownloading = obj.optBoolean("auto_downloading", false)
        val previewHex = obj.optString("preview_hex", "")
        val previewJpeg = if (previewHex.isNotEmpty() && previewHex != "null") hexToBytes(previewHex) else null
        val durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it }
        // Attachment bubble with incoming caption and reply context.
        val attachmentCaption = obj.optString("caption", "")
        val attachmentReplyId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
        val attachmentReplyPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
        adapter.addMessage(
            SimpleChatAdapter.Item(
                messageId = obj.optString("file_id"),
                text = "",
                isMine = obj.optString("type") == "sibling_file",
                senderName = sender?.displayName ?: senderIdentityId.take(8),
                senderAvatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
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
                    peerDeviceFingerprint = obj.optString("peer"),
                    isSticker = obj.optBoolean("sticker", false)
                ),
                // Attachment + caption + reply.
                caption = attachmentCaption,
                replyToMessageId = attachmentReplyId,
                replyToPreview = attachmentReplyPreview,
                senderIdentityId = senderIdentityId,
                replyToSenderLabel = resolveReplyLabel(attachmentReplyId)
            )
        )
        onNewIncomingItemAdded()
        // Sibling devices keep the notification until the watermark moves.
        if (obj.optString("type") == "file_offer") {
            // The watermark covers text rows only: the sender gets "seen" for
            // an attachment from this receipt, as on the 1:1 screen.
            val fileId = obj.optString("file_id")
            if (AppLock.isUnlocked()) netPack.execute {
                try { P2PLib.sendSeenReceipt(obj.optString("peer"), fileId, fileId) } catch (e: Exception) { }
            }
            scheduleGroupReadWatermark()
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

    /** Same as ChatActivity.generateImagePreview. */
    private fun generateImagePreview(file: File): ByteArray? =
        ImagePreview.compressFile(file, PREVIEW_MAX_DIMENSION, PREVIEW_JPEG_QUALITY)

    /** Same as ChatActivity.generateVideoPreview. */
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

    /**
     * Multi-device echo: a group message I sent from another of my devices is added as an isMine bubble (not marked as seen, since it is my own message).
     * After a reopen it already comes from the archive as 'sent'.
     */
    private fun handleSiblingGroupMessage(obj: JSONObject) {
        val localId = obj.optString("message_id")
        val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
        val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
        val replyToSenderIdentityId = if (obj.isNull("reply_to_sender_identity_id")) null else obj.optString("reply_to_sender_identity_id").ifEmpty { null }
        adapter.addMessage(
            SimpleChatAdapter.Item(
                messageId = localId,
                text = obj.optString("text"),
                isMine = true,
                status = SimpleChatAdapter.Status.SENT,
                sentAtMs = sentAtMs,
                senderIdentityId = ownIdentityId,
                replyToMessageId = replyToMessageId,
                replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null },
                replyToSenderIdentityId = replyToSenderIdentityId,
                replyToSenderLabel = resolveReplyLabel(replyToMessageId, replyToSenderIdentityId)
            )
        )
        scrollToBottomNow()
    }

    private fun handleIncomingGroupMessage(obj: JSONObject) {
        val senderIdentityId = obj.optString("sender_identity_id")
        val sender = resolveContactByIdentity(senderIdentityId)
        val senderName = sender?.displayName ?: senderIdentityId.take(8)
        val messageId = obj.optString("message_id")
        // This bubble's `Item.messageId` is the `group_message_local_id`, NOT the per-packet `message_id`.
        // That keeps it consistent with messages I sent to the group (see the `sendNewMessage` note on my own bubble's messageId) and with rows loaded
        // from history (the DB's `message_id` column stores `group_message_local_id`; see the Rust `archive_group_message` call site).
        // The per-packet id was used here before. Edit and delete only fire on my own messages (see the `isMine` guard in `showGroupEditDeleteDialog`),
        // so the mismatch went unnoticed. Reply (`startReply`) also works on OTHERS' messages, though, and the wrong id would match no message on the other side.
        val localId = if (obj.isNull("group_message_local_id")) null else obj.optString("group_message_local_id").ifEmpty { null }
        val bubbleId = localId ?: messageId
        // Sender-embedded real send time, same pattern as ChatActivity.
        val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
        // isNull() check matters: org.json's optString(key, "") only falls
        // back on a MISSING key, not an explicit JSON null — Rust always
        // sends these keys, so without the check every received group
        // message got the literal string "null" here.
        val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
        val replyToSenderIdentityId = if (obj.isNull("reply_to_sender_identity_id")) null else obj.optString("reply_to_sender_identity_id").ifEmpty { null }
        adapter.addMessage(
            SimpleChatAdapter.Item(
                messageId = bubbleId,
                text = obj.optString("text"),
                isMine = false,
                sentAtMs = sentAtMs,
                senderName = senderName,
                senderAvatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
                senderIdentityId = senderIdentityId,
                replyToMessageId = replyToMessageId,
                replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null },
                replyToSenderIdentityId = replyToSenderIdentityId,
                replyToSenderLabel = resolveReplyLabel(replyToMessageId, replyToSenderIdentityId),
                mentionsMe = obj.optBoolean("mentions_me")
            )
        )
        maybePlayTyphoonEffect()
        onNewIncomingItemAdded()
        // Seen: sent automatically for a live group message that arrives while the screen is open (same reasoning as the 1:1 ChatActivity).
        // `peer` is the fingerprint of the 1:1 channel (the sender) this copy arrived on.
        if (AppLock.isUnlocked()) netPack.execute {
            try { P2PLib.sendSeenReceipt(obj.optString("peer"), messageId, localId) } catch (e: Exception) { /* yoksay */ }
        }
        // Reliable path: the read boundary is written to disk even if an individual Seen is lost.
        scheduleGroupReadWatermark()
    }

    /** Same as the `seenByPerMessage` note at the top of the file: accumulates the members who saw each message, keyed by identity_id,
     *  and passes the complete current list to the adapter every time. */
    private fun handleIncomingSeen(obj: JSONObject) {
        // group_message_local_id is an Option<String> on the Rust side, so an
        // explicit JSON null must be guarded (optString alone would return
        // the literal string "null" and silently mismatch every bubble).
        val localId = if (obj.isNull("group_message_local_id")) null else obj.optString("group_message_local_id").ifEmpty { null }
        if (localId == null) return
        // Asked of the list itself: a separate set of "ids I sent" held only
        // this session's text sends, so a "seen" for a message loaded from
        // history or for an attachment was dropped.
        if (localMessages.none { it.isMine && it.messageId == localId }) return
        val senderIdentityId = obj.optString("sender_identity_id")
        val sender = resolveContactByIdentity(senderIdentityId)
        val viewer = SimpleChatAdapter.SeenByViewer(
            avatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
            displayName = sender?.displayName ?: senderIdentityId.take(8)
        )
        val viewers = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
        viewers[senderIdentityId] = viewer
        adapter.applySeen(localId, viewers.values.toList())
    }

    /**
     * Bulk seen: a member sent a "read up to here" boundary. Rust returns the `message_id`s of MY messages up to that boundary.
     * For each one, add that member to `seenByPerMessage` and pass the full list to the adapter, as `handleIncomingSeen` does.
     */
    private fun handleIncomingSeenBulk(obj: JSONObject) {
        val arr = obj.optJSONArray("message_ids") ?: return
        val senderIdentityId = obj.optString("viewer_identity_id")
        if (senderIdentityId.isEmpty()) return
        val sender = resolveContactByIdentity(senderIdentityId)
        val viewer = SimpleChatAdapter.SeenByViewer(
            avatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
            displayName = sender?.displayName ?: senderIdentityId.take(8)
        )
        for (i in 0 until arr.length()) {
            val localId = arr.optString(i)
            if (localId.isEmpty()) continue
            val viewers = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
            viewers[senderIdentityId] = viewer
            adapter.applySeen(localId, viewers.values.toList())
        }
    }

    private data class ContactLookup(val displayName: String, val avatarHex: String?)

    /** Short-lived cache for `resolveContactByIdentity`, so history loading does not repeat the same JNI/DB result over and over. */
    @Volatile private var contactListCache: JSONArray? = null
    @Volatile private var contactListCacheAt: Long = 0

    /**
     * Cached for a short time. Group history loading calls `resolveContactByIdentity` once per row (through `itemFromGroupHistoryJson` and `itemFromGroupAttachmentJson`).
     * Without a cache, each call re-runs `P2PLib.listContacts()`: a JNI call and a DB query that reads the whole contact list, avatar hex blobs included, and parses the JSON.
     * So a history of N rows would parse the whole list N times (N x M, M = number of contacts). The cache holds the result for `CONTACT_CACHE_TTL_MS`,
     * so one history-load burst shares one parse. The TTL is short and the live event handlers use the same function, so a changed contact shows up within a few seconds.
     */
    private fun resolveContactByIdentity(identityId: String): ContactLookup? {
        return try {
            val now = System.currentTimeMillis()
            val cached = contactListCache
            val array = if (cached != null && now - contactListCacheAt < CONTACT_CACHE_TTL_MS) {
                cached
            } else if (cached != null && Looper.myLooper() == Looper.getMainLooper()) {
                // Every incoming message and every keystroke (mention popup)
                // resolves names on the main thread: a stale list is shown
                // once more and refreshed off it, not read under the core lock.
                refreshContactCacheAsync()
                cached
            } else if (Looper.myLooper() == Looper.getMainLooper()) {
                // First lookup on the main thread: do not read under the core lock; fill the cache off-thread.
                refreshContactCacheAsync()
                return null
            } else {
                JSONArray(P2PLib.listContacts()).also {
                    contactListCache = it
                    contactListCacheAt = now
                }
            }
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                if (obj.optString("identity_id") == identityId) {
                    return ContactLookup(
                        displayName = obj.optString("display_name"),
                        avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
                    )
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    @Volatile private var contactCacheRefreshing = false

    private fun refreshContactCacheAsync() {
        if (contactCacheRefreshing) return
        contactCacheRefreshing = true
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                contactListCache = JSONArray(P2PLib.listContacts())
                contactListCacheAt = System.currentTimeMillis()
            } catch (e: Exception) {
            } finally {
                contactCacheRefreshing = false
            }
        }
    }

    /** Called on state transitions only, by the EditText watcher and `stopTypingRunnable`. */
    private fun sendTypingState(isTyping: Boolean) {
        if (isTypingSent == isTyping) return
        isTypingSent = isTyping
        // Same as `netPack` (see the top of the file).
        val gid = groupId
        netPack.execute {
            try {
                P2PLib.sendGroupTypingIndicator(gid, isTyping)
            } catch (e: Exception) {
                // Fire-and-forget.
            }
        }
    }

    /** Near the bottom = last item visible (or list empty). */
    private fun isRecyclerNearBottom(): Boolean {
        if (localMessages.isEmpty()) return true
        val lastVisible = (recycler.layoutManager as? LinearLayoutManager)?.findLastVisibleItemPosition()
            ?: return true
        return lastVisible == RecyclerView.NO_POSITION || lastVisible >= localMessages.size - 2
    }


    /** Auto-scroll only if already near the bottom; otherwise blink the FAB. */
    private fun onNewIncomingItemAdded() {
        if (isRecyclerNearBottom()) {
            scrollToLastSettled()
        } else {
            blinkScrollToBottomFab()
        }
    }

    /** Unconditional scroll, for our own sent messages and attachments. */
    /**
     * The bottom bar and the quote pill are transparent outside, so the chat shows at the sides and underneath.
     * The list now extends to the bottom of the screen and the bar floats above it (see activity_chat.xml).
     * So messages do not disappear under the bar, the list gets bottom padding equal to the bar's real height. With `clipToPadding=false`, content scrolls
     * behind the bar but rests above it.
     *
     * A fixed dp value is not enough: the bar grows while a multi-line message is typed, and the quote pill opens and closes. So the padding is recalculated
     * whenever either layout changes.
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

    /** Shown any time the user is scrolled away from the bottom (independent of new messages). */
    private fun updateScrollToBottomFabVisibility() {
        if (isRecyclerNearBottom()) {
            hideScrollToBottomFab()
        } else if (fabScrollToBottom.visibility != View.VISIBLE) {
            com.p2p.messenger.util.ScrollDownFab.style(fabScrollToBottom, newMessage = false)
            fabScrollToBottom.visibility = View.VISIBLE
        }
    }

    /** New message arrived while scrolled away: steady accent. */
    private fun blinkScrollToBottomFab() {
        com.p2p.messenger.util.ScrollDownFab.style(fabScrollToBottom, newMessage = true)
        fabScrollToBottom.visibility = View.VISIBLE
    }

    private fun hideScrollToBottomFab() {
        fabScrollToBottom.visibility = View.GONE
    }

    /** Handles a `{"type":"typing","group_id":...,"sender_identity_id":...,"is_typing":...}` event. */
    private fun handleIncomingGroupTyping(obj: JSONObject) {
        val senderIdentityId = obj.optString("sender_identity_id")
        if (senderIdentityId.isEmpty() || senderIdentityId == ownIdentityId) return
        val isTyping = obj.optBoolean("is_typing", false)
        typingMembers.remove(senderIdentityId)?.let { typingHandler.removeCallbacks(it) }
        if (isTyping) {
            val clearRunnable = Runnable {
                typingMembers.remove(senderIdentityId)
                updateTypingIndicatorUi()
            }
            typingMembers[senderIdentityId] = clearRunnable
            typingHandler.postDelayed(clearRunnable, TYPING_INDICATOR_TIMEOUT_MS)
        }
        updateTypingIndicatorUi()
        if (isTyping && isRecyclerNearBottom()) recycler.scrollToPosition(localMessages.size - 1)
    }

    /** Shows the most recent typer's avatar; falls back to generic text if several are typing. */
    private fun updateTypingIndicatorUi() {
        if (typingMembers.isEmpty()) {
            layoutTypingIndicator.visibility = View.GONE
            return
        }
        val lastIdentityId = typingMembers.keys.last()
        val contact = resolveContactByIdentity(lastIdentityId)
        val displayName = contact?.displayName?.takeIf { it.isNotBlank() } ?: lastIdentityId.take(8)
        val avatarBytes = contact?.avatarHex?.let { hexToBytes(it) }
        AvatarUtil.renderInto(imgTypingAvatar, avatarBytes, displayName)
        imgTypingAvatar.visibility = View.VISIBLE
        txtTypingIndicator.text = if (typingMembers.size == 1) {
            getString(R.string.lbl_typing_named, displayName)
        } else {
            getString(R.string.lbl_typing_several)
        }
        layoutTypingIndicator.visibility = View.VISIBLE
    }

    /**
     * Same pattern as ChatActivity.setupMessageSearch / toggleMessageSearch / runMessageSearch / moveSearchMatch / goToSearchMatch:
     * in-chat message search, over the `localMessages` currently loaded.
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
            // requestFocus() alone doesn't reliably pop the keyboard for a
            // programmatically-focused view — show it explicitly.
            searchMessagesView.post {
                val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
                imm.showSoftInput(searchMessagesView.findFocus(), android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
            }
        }
    }

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
        ownStatusPollHandler.post(ownStatusPollRunnable)
        // While paused (e.g. the file picker or MediaViewerActivity was on
        // top of this screen), the live listener above was detached — any
        // message that arrived meanwhile was archived but never appended
        // to the UI. Catch up now.
        syncMissedGroupMessages()
        // Members are told the read boundary as soon as the group opens (not only in onPause, and to members as well as sibling devices).
        if (resumedUnlocked) scheduleGroupReadWatermark()
    }

    private val groupReadWatermarkHandler = Handler(Looper.getMainLooper())
    private val groupReadWatermarkRunnable = Runnable {
        syncGroupReadStateAsync()
    }
    // the core lock is not taken on the main thread.
    private fun syncGroupReadStateAsync() {
        val gid = groupId
        val now = System.currentTimeMillis()
        Thread { try { P2PLib.syncReadState("", gid, now) } catch (e: Exception) {} }.start()
    }
    private fun scheduleGroupReadWatermark() {
        if (!AppLock.isUnlocked()) return
        groupReadWatermarkHandler.removeCallbacks(groupReadWatermarkRunnable)
        groupReadWatermarkHandler.postDelayed(groupReadWatermarkRunnable, 700L)
    }

    /** See the onResume call site — group version of
     *  ChatActivity.syncMissedMessages, same "only newer" idea keyed on
     *  message/file id so it's safe to call redundantly. */
    private fun syncMissedGroupMessages() {
        val targetGroupId = groupId
        // See ChatActivity.syncMissedMessages: rows on screen keep their preview.
        val knownIds = localMessages.mapTo(HashSet()) { it.messageId }
        lifecycleScope.launch {
            val (merged, seenEntries) = withContext(Dispatchers.IO) {
                val json = try { P2PLib.getGroupMessageHistory(targetGroupId, HISTORY_LOAD_LIMIT) } catch (e: Exception) { null }
                val array = try { if (json != null) JSONArray(json) else null } catch (e: Exception) { null }
                val textItems = if (array != null) {
                    (0 until array.length()).map { itemFromGroupHistoryJson(array.getJSONObject(it)) }
                } else emptyList()
                // Same pattern as `loadGroupHistoryIfAvailable` / `seenViewersFromHistoryJson`. This function runs in `onResume` (returning from the background),
                // so it is the most frequently hit path in practice.
                val seenEntries = if (array != null) (0 until array.length()).mapNotNull { i ->
                    val obj = array.getJSONObject(i)
                    val localId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
                    val viewers = if (localId != null) seenViewersFromHistoryJson(obj) else emptyList()
                    if (localId != null && viewers.isNotEmpty()) localId to viewers else null
                } else emptyList()

                val attachmentsJson = try { P2PLib.listGroupAttachments(targetGroupId) } catch (e: Exception) { null }
                val attachmentsArray = try { if (attachmentsJson != null) JSONArray(attachmentsJson) else null } catch (e: Exception) { null }
                val attachmentItems = if (attachmentsArray != null) {
                    (0 until attachmentsArray.length()).map { itemFromGroupAttachmentJson(attachmentsArray.getJSONObject(it), knownIds) }
                } else emptyList()

                (textItems + attachmentItems).sortedBy { it.orderKey } to seenEntries
            }
            if (groupId != targetGroupId) return@launch
            // Recompute existingIds here, right before merging, not before the
            // IO fetch above — loadGroupHistoryIfAvailable can insert
            // concurrently while this fetch is in flight, and a set captured
            // earlier would be stale, causing duplicate inserts.
            val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
            val missed = merged.filter { it.messageId !in existingIds }
            if (adapter.refreshFrom(merged)) resolveReplyLabels()
            if (missed.isNotEmpty()) {
                localMessages.addAll(missed)
                // If history loading finishes after a live message, appending would push the live message above the old history, off screen (observed on a device).
                // So re-sort by send order.
                localMessages.sortWith(compareBy { it.orderKey })
                resolveReplyLabels()
                adapter.notifyDataSetChanged()
                adapter.dedupeByMessageId()
                onNewIncomingItemAdded()
            }
            // Same seen-replay note as under `loadGroupHistoryIfAvailable`.
            for ((localId, viewers) in seenEntries) {
                val map = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
                for ((identityId, viewer) in viewers) map[identityId] = viewer
                adapter.applySeen(localId, map.values.toList())
            }
        }
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
