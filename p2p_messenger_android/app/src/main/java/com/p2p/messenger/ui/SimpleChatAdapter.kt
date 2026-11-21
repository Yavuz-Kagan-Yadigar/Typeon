package com.p2p.messenger.ui

import android.graphics.Typeface
import android.text.format.Formatter
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.slider.Slider
import com.p2p.messenger.R
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.formatAbsoluteTime
import java.util.Locale
import kotlin.math.roundToInt

/**
 * Minimal adapter that draws the message bubbles of one chat screen.
 * Storage is not here (see ChatActivity). GroupChatActivity uses the same adapter;
 * `senderName` is filled only there.
 *
 * Every `Item` carries a stable `messageId` (the Rust `MessagePacketHeader.message_id`),
 * so an incoming edit or delete finds its row (`applyEdit` / `applyDelete`).
 * Deleted messages stay in the list as a "This message was deleted" placeholder,
 * so positions do not shift.
 */
class SimpleChatAdapter(private val items: MutableList<Item>) : RecyclerView.Adapter<SimpleChatAdapter.BubbleViewHolder>() {

    companion object {
        private const val GROUP_WINDOW_MS = 2 * 60 * 1000L
        private const val ORDER_MAX_AGE_MS = 31L * 24 * 60 * 60 * 1000
        /** Attachment preview decodes run on one shared background thread, not per adapter. */
        private val previewDecoder = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
            Thread(r, "preview-decode").apply { isDaemon = true }
        }
    }

    enum class Status { PENDING, SENT, ERROR }

    /** Group chats: member names that are shown bold ("@Name") in bubbles. */
    var mentionNames: List<String> = emptyList()

    /** Bolds "@Name" for known members. A message that mentions me also bolds every "@word". */
    private fun markMentions(text: android.text.Spannable, mentionsMe: Boolean): Boolean {
        var any = false
        fun mark(start: Int, end: Int, highlight: Boolean) {
            text.setSpan(android.text.style.StyleSpan(Typeface.BOLD), start, end, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            if (highlight) text.setSpan(android.text.style.BackgroundColorSpan(0x55FFC107), start, end, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            any = true
        }
        for (name in mentionNames) {
            var i = text.indexOf("@$name")
            while (i >= 0) {
                mark(i, i + name.length + 1, false)
                i = text.indexOf("@$name", i + 1)
            }
        }
        if (mentionsMe) Regex("@\\S+").findAll(text).forEach { mark(it.range.first, it.range.last + 1, true) }
        return any
    }

    /** 1:1 chats: label used for the peer's quoted messages. */
    var peerName: () -> String? = { null }
    /** Group chats: sender identity id -> name colour (see GroupChatActivity). */
    var senderColors: Map<String, Int> = emptyMap()

    /** Inline quote (see util.Quote). Shows the quoted message's own text when it is
     *  available locally; otherwise the sender's preview with no label. */
    private fun quoteOf(ctx: android.content.Context, id: String, preview: String): Pair<String?, String> {
        val t = items.firstOrNull { it.messageId == id } ?: return null to preview
        val label = if (t.isMine) ctx.getString(R.string.lbl_you) else t.senderName?.takeIf { it.isNotEmpty() } ?: peerName() ?: ""
        val text = when {
            t.isDeleted -> ctx.getString(R.string.msg_deleted)
            t.attachment != null -> ctx.getString(R.string.lbl_attachment_reply_preview, t.attachment!!.fileName)
            else -> com.p2p.messenger.util.Quote.ownText(com.p2p.messenger.util.Forward.strip(t.text)).takeWholeChars(120)
        }
        return label to text
    }

    /** Decoded attachment previews by file id. A rebind does not decode again. */
    private val previewCache = object : android.util.LruCache<String, android.graphics.Bitmap>(24 * 1024 * 1024) {
        override fun sizeOf(key: String, value: android.graphics.Bitmap): Int = value.byteCount
    }

    /** `applySeen` / `lastSeenAvatars`. `displayName` is used only to draw an initial badge
     *  when the person has no photo (see AvatarUtil). */
    data class SeenByViewer(val avatarJpeg: ByteArray?, val displayName: String)

    /** Attachment state (see P2PLib.prepareAndSendFile / downloadFile and the "file_*" poll events). */
    enum class AttachmentStatus { OFFERED, DOWNLOADING, COMPLETE, FAILED }

    data class AttachmentInfo(
        val fileId: String,
        val fileName: String,
        val mimeType: String,
        val totalSize: Long,
        var status: AttachmentStatus,
        var bytesDone: Long = 0,
        /** Download start time in ms. Set on the first "file_progress" event.
         *  Remaining time is computed from the average speed (bytesDone / elapsed). */
        var downloadStartedAt: Long = 0L,
        /** Small 480p / 85% JPEG cover made by the sender (photo and video only). When present,
         *  it is shown in `bindAttachment` before the full file is downloaded. */
        var previewJpeg: ByteArray? = null,
        /** Voice messages only (mimeType starts with "audio/"). See Rust `FileOffer.duration_ms`. */
        var durationMs: Int? = null,
        /** The three fields below mirror voice playback only. ChatActivity's single shared
         *  MediaPlayer owns them (see `updateVoicePlayback`). */
        var isPlaying: Boolean = false,
        var playbackPositionMs: Int = 0,
        var playbackSpeed: Float = 1f,
        /** Group chats only: the sender this attachment is downloaded from with `downloadFile`.
         *  1:1 chats do not need it (ChatActivity uses its `peerDeviceFingerprint`). */
        var peerDeviceFingerprint: String = "",
        /** Rust `FileOffer.sticker`: drawn without a frame (see `bindSticker`). */
        var isSticker: Boolean = false
    )

    data class Item(
        /** Retry of a failed message. `var`: the retry replaces the message id of THIS bubble
         *  with the new send's id (see `retryMessage`). No second bubble is created. */
        var messageId: String,
        var text: String,
        val isMine: Boolean,
        val timestamp: Long = System.currentTimeMillis(),
        /** Received messages (`!isMine`) only: the sender's own send time (Rust
         *  `MessageContent::Text.sent_at_ms`). Shown next to `timestamp` (local receive time),
         *  for example "10:42 (sent at: 10:41)". `null` or `0` means unknown (older sender,
         *  or loaded from local history). Then only `timestamp` is shown. */
        val sentAtMs: Long? = null,
        var status: Status = Status.SENT,
        var isEdited: Boolean = false,
        /** The row came from the contact's history answer, not from a live event. */
        val viaSync: Boolean = false,
        var isDeleted: Boolean = false,
        /** Group chats only. Shown when the message is not mine. */
        val senderName: String? = null,
        /** Group chats only: the raw `identity_id` of the sender (this device's own identity when
         *  `isMine`). `senderName` is the resolved display name. When a reply starts, this value
         *  is sent as `reply_to_sender_identity_id`. The receiver uses it as a fallback to
         *  resolve the name when the replied-to message is not stored locally (see `resolveReplyLabel`). */
        val senderIdentityId: String? = null,
        /** Group chats only, shown with `senderName`. See AvatarUtil (initial badge when no photo). */
        val senderAvatarJpeg: ByteArray? = null,
        /** When set, this row is a file attachment bubble, not text. `messageId` is then the `file_id`. */
        var attachment: AttachmentInfo? = null,
        /** Id of the message this one replies to: the stable id (`message_id` in 1:1,
         *  `group_message_local_id` in groups). When set, a small quote box is drawn in the bubble.
         *  Tapping it scrolls the chat to that message (see `onBindViewHolder` / `onReplyPreviewClick`). */
        /** Summary of the reactions on this message, for example "👍2 ❤️". Empty means none.
         *  Rust computes it (`reactions_summary`) and sends the same string in history JSON and in
         *  the live `reaction` event. The adapter does not count anything itself. */
        var reactions: String = "",
        /** Group text that @mentions me (see Rust `mentions_me`). */
        val mentionsMe: Boolean = false,
        /** Caption drawn under an attachment bubble. Empty means none. Text messages do not use
         *  it (their text is `text`). */
        var caption: String = "",
        var replyToMessageId: String? = null,
        /** Short text summary of the replied-to message, embedded by the sender. The receiver
         *  does NOT need to have that message archived locally. */
        var replyToPreview: String? = null,
        /** Label shown in the quote box for the replied-to person: fixed "You" (R.string.lbl_you)
         *  in 1:1, or the replied-to sender's name in groups. The caller (ChatActivity /
         *  GroupChatActivity) already knows the name, so no id lookup happens here. */
        var replyToSenderLabel: String? = null,
        /** Group messages only: the raw `identity_id` of the replied-to message's sender
         *  (Rust `MessageContent::Text.reply_to_sender_identity_id`). The caller that builds
         *  `replyToSenderLabel` (GroupChatActivity.resolveReplyLabel) falls back to this value
         *  when the replied-to message is not stored on this device. It maps the id to a name
         *  through the contact list (`resolveContactByIdentity`). */
        var replyToSenderIdentityId: String? = null,
        /** Disappearing message: the timer in seconds (Rust `MessageContent::Text.expire_secs`), 0 = an ordinary message. */
        var expireSecs: Int = 0,
        /** When it goes, this device's clock (ms). A received one holds a later cap until it is on screen (see `disappearTick`). */
        var expireAtMs: Long = 0L
    ) {
        /** Sort key of the row: the sender's send time (`sentAtMs`), or this device's receive or
         *  create time (`timestamp`) when unknown. A late-delivered message goes to its SEND
         *  position, not the bottom (see `addMessage`).
         *
         *  Known limit: this is the sender's raw local clock, not a synchronised logical clock.
         *  Two devices of one identity that send in the same second, with clock skew, can
         *  interleave out of order. A fix needs a per-identity logical counter (new wire field,
         *  DB column, sync over `SiblingEcho`). Not done: the gain is small and a wrong
         *  implementation could break ordering in general. */
        val orderKey: Long get() = sentAtMs?.takeIf { it > 0 }
            // The sender's clock is only trusted within bounds: a message cannot have been
            // sent after we received it, and the server keeps mail for 30 days. A clock far
            // ahead is clamped to the receive time, so it cannot pin the message to the bottom.
            ?.coerceIn(timestamp - ORDER_MAX_AGE_MS, timestamp) ?: timestamp
    }

    /** Called on long press of one of my own messages. The Edit / Delete menu is shown by
     *  ChatActivity / GroupChatActivity; the adapter only passes the item. */
    var onItemLongPress: ((Item) -> Unit)? = null
    /** Called on double tap of a text message (not while selecting). The view is the bubble, to anchor the quick-reaction bar. */
    var onItemDoubleTap: ((Item, View) -> Unit)? = null
    /** Called when the "Download" button of an attachment bubble, or a completed attachment, is tapped. */
    var onAttachmentClick: ((Item) -> Unit)? = null
    /** Called on long press of a completed attachment bubble (for example to open the
     *  "save to Downloads/P2P" menu). Enabled only when `AttachmentStatus.COMPLETE`. */
    var onAttachmentLongClick: ((Item) -> Unit)? = null
    /** Called when the play / pause button of a voice bubble is tapped. ChatActivity runs the
     *  real playback with one shared MediaPlayer; the adapter only passes the item. */
    var onVoicePlayClick: ((Item) -> Unit)? = null
    /** Called when the speed badge (1x / 1.5x / 2x / 0.5x) is tapped. */
    var onVoiceSpeedClick: ((Item) -> Unit)? = null
    /** Called when the user drags and releases a voice slider. The target position is in ms. */
    var onVoiceSeek: ((Item, Int) -> Unit)? = null
    /** Called when the small quote box inside a bubble is tapped. The target `replyToMessageId`
     *  is passed; the caller (ChatActivity / GroupChatActivity) scrolls to that message. */
    var onReplyPreviewClick: ((String) -> Unit)? = null

    /** Multi-select (see [MessageSelection]): selected message ids. One [Kind] at a time,
     *  set by the first pick, because the actions differ per kind. While anything is selected,
     *  tap and long press toggle the row instead of acting. */
    enum class Kind { TEXT, IMAGE, VIDEO, VOICE, STICKER, FILE }
    val selectedIds = LinkedHashSet<String>()
    private var selectedKind: Kind? = null
    var onSelectionChanged: (() -> Unit)? = null
    val selecting get() = selectedIds.isNotEmpty()
    private var recyclerView: RecyclerView? = null

    fun kindOf(item: Item): Kind {
        val a = item.attachment ?: return Kind.TEXT
        return when {
            a.isSticker -> Kind.STICKER
            a.mimeType.startsWith("audio/") && (a.durationMs ?: 0) > 0 -> Kind.VOICE
            a.mimeType.startsWith("image/") -> Kind.IMAGE
            a.mimeType.startsWith("video/") -> Kind.VIDEO
            else -> Kind.FILE
        }
    }

    /** Selected items, in chat order. */
    fun selectedItems(): List<Item> = items.filter { it.messageId in selectedIds && !it.isDeleted }

    fun toggleSelection(item: Item) {
        // A disappearing message is never picked: selection copies and forwards.
        if (item.isDeleted || Disappear.locked(item)) return
        if (!selectedIds.remove(item.messageId)) {
            val kind = kindOf(item)
            if (selectedKind != null && selectedKind != kind) {
                recyclerView?.let { android.widget.Toast.makeText(it.context, R.string.msg_select_same_kind, android.widget.Toast.LENGTH_SHORT).show() }
                return
            }
            selectedKind = kind
            selectedIds.add(item.messageId)
        }
        if (selectedIds.isEmpty()) selectedKind = null
        val i = indexOfMessageId(item.messageId)
        if (i >= 0) notifyItemChanged(i)
        onSelectionChanged?.invoke()
    }

    fun clearSelection() {
        if (selectedIds.isEmpty()) return
        val was = selectedIds.toList()
        selectedIds.clear()
        selectedKind = null
        was.forEach { id -> indexOfMessageId(id).takeIf { it >= 0 }?.let { notifyItemChanged(it) } }
        onSelectionChanged?.invoke()
    }

    private fun longPress(item: Item, menu: ((Item) -> Unit)?) {
        if (selecting) toggleSelection(item) else menu?.invoke(item)
    }

    /** While selecting, a tap anywhere on a row toggles it. Handled on ACTION_UP, so scrolling
     *  still works and the row's own click receives a CANCEL. */
    override fun onAttachedToRecyclerView(rv: RecyclerView) {
        recyclerView = rv
        val taps = android.view.GestureDetector(rv.context, object : android.view.GestureDetector.SimpleOnGestureListener() {
            override fun onSingleTapUp(e: android.view.MotionEvent) = true
        })
        // Separate detector: a double-tap listener on `taps` would swallow the second tap's
        // `onSingleTapUp`, so quick taps while selecting would toggle only once.
        val doubleTaps = android.view.GestureDetector(rv.context, object : android.view.GestureDetector.SimpleOnGestureListener() {
            override fun onDoubleTap(e: android.view.MotionEvent): Boolean {
                if (selecting) return false
                val child = rv.findChildViewUnder(e.x, e.y) ?: return false
                val holder = rv.getChildViewHolder(child) as? BubbleViewHolder ?: return false
                val item = items.getOrNull(holder.bindingAdapterPosition) ?: return false
                if (item.isDeleted || item.attachment != null) return false
                onItemDoubleTap?.invoke(item, holder.bubble)
                return true
            }
        })
        rv.addOnItemTouchListener(object : RecyclerView.SimpleOnItemTouchListener() {
            override fun onInterceptTouchEvent(rv: RecyclerView, e: android.view.MotionEvent): Boolean {
                doubleTaps.onTouchEvent(e)
                val tap = taps.onTouchEvent(e) && e.actionMasked == android.view.MotionEvent.ACTION_UP
                if (!tap || !selecting) return false
                val child = rv.findChildViewUnder(e.x, e.y) ?: return true
                items.getOrNull(rv.getChildAdapterPosition(child))?.let { toggleSelection(it) }
                return true
            }
        })
    }

    /** Playback progress is pushed straight into the ViewHolder that is on screen, instead of
     *  calling a full `notifyItemChanged` every frame (see `tickVoicePlayback`). While the user
     *  drags the slider (`userSeekingFileIds`) programmatic updates are skipped, so the thumb
     *  does not jump back. */
    private val boundVoiceHolders = mutableMapOf<String, BubbleViewHolder>()
    private val userSeekingFileIds = mutableSetOf<String>()

    /** A sticker bubble's picture, resolved off the main thread (see StickerPicker.provideBubbleImages). */
    var stickerImageProvider: ((fileId: String, done: (android.graphics.drawable.Drawable?) -> Unit) -> Unit)? = null

    private val stickerImages = object : android.util.LruCache<String, android.graphics.drawable.Drawable>(STICKER_CACHE_BYTES) {
        override fun sizeOf(key: String, value: android.graphics.drawable.Drawable): Int = stickerDrawableBytes(value)
    }
    /** Decode in progress: no second request for the same file. */
    private val stickerPending = mutableSetOf<String>()

    /** Consecutive messages from the same sender within this time window are drawn as one group
     *  (tighter spacing, one trailing timestamp, sender name and avatar shown once), like
     *  WhatsApp and Telegram. */
    private fun isSameSender(a: Item, b: Item): Boolean {
        if (a.isMine != b.isMine) return false
        return a.isMine || a.senderIdentityId == b.senderIdentityId
    }

    private fun isGroupedWithPrevious(position: Int): Boolean {
        if (position <= 0) return false
        val prev = items[position - 1]
        val cur = items[position]
        if (prev.isDeleted || cur.isDeleted) return false
        // A frameless sticker never joins a group with its neighbours.
        if (isSticker(cur) || isSticker(prev)) return false
        // A message with a quote box does not join the group with the one before it. The quote box
        // sits ABOVE the bubble as a separate block, so it adds a gap between the bubbles, and the
        // merged outline (see MergedBubbleDecoration) would paint over the quote. A quoted message
        // is a new visual start anyway.
        if (cur.replyToMessageId != null) return false
        if (!isSameSender(prev, cur)) return false
        // Groups follow send order, like the sort: messages sent hours apart and delivered
        // together do not form one group.
        return cur.orderKey - prev.orderKey in 0 until GROUP_WINDOW_MS
    }

    /** See MergedBubbleDecoration: it draws the merged shape and needs the group bounds and
     *  which side the group is aligned to. */
    fun isGroupedWithNextPublic(position: Int): Boolean = isGroupedWithNext(position)

    fun isMineAt(position: Int): Boolean = items.getOrNull(position)?.isMine ?: false

    fun isStickerAt(position: Int): Boolean = isSticker(items.getOrNull(position))

    /** Drawn as a sticker: no frame. Until it is downloaded it is a normal attachment bubble. */
    private fun isSticker(item: Item?): Boolean =
        item?.attachment?.let { it.isSticker && it.status == AttachmentStatus.COMPLETE && !item.isDeleted } == true

    private fun isGroupedWithNext(position: Int): Boolean {
        if (position >= items.size - 1) return false
        val cur = items[position]
        val next = items[position + 1]
        if (cur.isDeleted || next.isDeleted) return false
        if (isSticker(cur) || isSticker(next)) return false
        // Same rule as `isGroupedWithPrevious`: a bubble followed by a reply ends its group.
        // Otherwise it would never show its timestamp.
        if (next.replyToMessageId != null) return false
        if (!isSameSender(cur, next)) return false
        return next.orderKey - cur.orderKey in 0 until GROUP_WINDOW_MS
    }

    /** The "seen" mark is shown only under the latest seen message that I sent. All earlier
     *  messages count as seen implicitly (WhatsApp / Telegram pattern). `applySeen` updates
     *  both values; `onBindViewHolder` shows the avatar row only on the row whose
     *  `messageId == lastSeenMessageId`. */
    private var lastSeenMessageId: String? = null
    private var lastSeenAvatars: List<SeenByViewer> = emptyList()

    /**
     * A seen notice whose target row is not in the list yet is held back. Before, it was
     * dropped. That happens often: the other side opens the chat right away, while our
     * bubble is still loading from the archive or arrives later in event order. Then the
     * avatars did not show, or showed only after the next notice.
     *
     * The held notice is applied as soon as its target row is added (see `addMessage`).
     */
    private var pendingSeenMessageId: String? = null
    private var pendingSeenAvatars: List<SeenByViewer> = emptyList()

    /** In-chat message search. Temporarily highlights the current match (see `setHighlighted`;
     *  ChatActivity / GroupChatActivity search navigation buttons). */
    private var highlightedMessageId: String? = null

    class BubbleViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val container: LinearLayout = itemView as LinearLayout
        val senderRow: View = itemView.findViewById(R.id.rowSender)
        val senderAvatar: ImageView = itemView.findViewById(R.id.imgSenderAvatar)
        val senderName: TextView = itemView.findViewById(R.id.txtSenderName)
        val bubble: LinearLayout = itemView.findViewById(R.id.layoutBubble)
        val bubbleLine: LinearLayout = itemView.findViewById(R.id.rowBubbleLine)
        val sideColumn: LinearLayout = itemView.findViewById(R.id.colBubbleSide)
        val pillReactions: TextView = itemView.findViewById(R.id.pillReactions)
        val txtAttachmentCaption: TextView = itemView.findViewById(R.id.txtAttachmentCaption)
        val textView: TextView = itemView.findViewById(R.id.txtBubbleText)
        val txtForwarded: TextView = itemView.findViewById(R.id.txtForwarded)
        val layoutReplyQuote: View = itemView.findViewById(R.id.layoutReplyQuote)
        val viewReplyQuoteBar: View = itemView.findViewById(R.id.viewReplyQuoteBar)
        val txtReplyQuoteSender: TextView = itemView.findViewById(R.id.txtReplyQuoteSender)
        val txtReplyQuoteText: TextView = itemView.findViewById(R.id.txtReplyQuoteText)
        val editedLabel: TextView = itemView.findViewById(R.id.txtEditedLabel)
        val timestamp: TextView = itemView.findViewById(R.id.txtTimestamp)
        val status: ImageView = itemView.findViewById(R.id.imgStatus)
        val layoutAttachment: LinearLayout = itemView.findViewById(R.id.layoutAttachment)
        val imgAttachmentThumbnail: ImageView = itemView.findViewById(R.id.imgAttachmentThumbnail)
        val imgSticker: ImageView = itemView.findViewById(R.id.imgSticker)
        val rowGenericAttachment: View = itemView.findViewById(R.id.rowGenericAttachment)
        val txtAttachmentName: TextView = itemView.findViewById(R.id.txtAttachmentName)
        val txtAttachmentSize: TextView = itemView.findViewById(R.id.txtAttachmentSize)
        val progressAttachment: LinearProgressIndicator = itemView.findViewById(R.id.progressAttachment)
        val txtAttachmentEta: TextView = itemView.findViewById(R.id.txtAttachmentEta)
        val btnAttachmentDownload: Button = itemView.findViewById(R.id.btnAttachmentDownload)
        val layoutVoiceMessage: View = itemView.findViewById(R.id.layoutVoiceMessage)
        val btnVoicePlayPause: ImageView = itemView.findViewById(R.id.btnVoicePlayPause)
        val progressVoicePlayback: Slider = itemView.findViewById(R.id.progressVoicePlayback)
        val txtVoiceDuration: TextView = itemView.findViewById(R.id.txtVoiceDuration)
        val btnVoiceSpeed: TextView = itemView.findViewById(R.id.btnVoiceSpeed)
        val rowSeenBy: View = itemView.findViewById(R.id.rowSeenBy)
        val imgSeenBy1: ImageView = itemView.findViewById(R.id.imgSeenBy1)
        val imgSeenBy2: ImageView = itemView.findViewById(R.id.imgSeenBy2)
        val imgSeenBy3: ImageView = itemView.findViewById(R.id.imgSeenBy3)
        val imgSeenBy4: ImageView = itemView.findViewById(R.id.imgSeenBy4)
        val imgSeenBy5: ImageView = itemView.findViewById(R.id.imgSeenBy5)
        val txtSeenByMore: TextView = itemView.findViewById(R.id.txtSeenByMore)
        val txtExpire: TextView = itemView.findViewById(R.id.txtExpire)
    }

    // --- Disappearing messages ---

    /** Bound holders of disappearing bubbles: the pulse and the time-left line touch only these. */
    private val disappearHolders = HashSet<BubbleViewHolder>()
    /** The chat screen is resumed. The pulse runs only then, and only then does a received message start counting down. */
    private var onScreen = false
    private var lastSecond = 0L
    /** A received disappearing message started counting down on screen: the caller tells the core (`P2PLib.startDisappearCountdown`). */
    var onDisappearStarted: (() -> Unit)? = null
    /** The same slow fade as the whiteboard tab and the call Attend pill. */
    private val disappearPulse = com.p2p.messenger.util.SlowPulse { disappearTick(it) }

    /** From the Activity's onResume (true) and onPause (false). */
    fun setOnScreen(visible: Boolean) {
        onScreen = visible
        updateDisappearPulse()
    }

    /** Called when a disappearing bubble comes on screen (true) or the last one goes (false): the Activity blocks screenshots. */
    var onDisappearPresent: ((Boolean) -> Unit)? = null
    private var disappearPresent = false

    private fun updateDisappearPulse() {
        val present = items.any { it.expireSecs > 0 && !it.isDeleted }
        disappearPulse.running = onScreen && present
        if (present != disappearPresent) {
            disappearPresent = present
            onDisappearPresent?.invoke(present)
        }
    }

    /** One pulse frame: the accent edge fades with [p]. Once a second the time-left lines change, received messages on screen
     *  start counting down, and the ones whose time is up slide out. */
    private fun disappearTick(p: Float) {
        // 8 steps, as the desktop: a drawable redraws only when its alpha changes, so this halves the bubble redraws.
        val alpha = 64 + 191 * (p * 7).roundToInt() / 7
        for (h in disappearHolders) h.bubble.foreground?.alpha = alpha
        val now = System.currentTimeMillis()
        if (!onScreen || now / 1000 == lastSecond) return
        lastSecond = now / 1000
        var started = false
        val gone = ArrayList<String>()
        for (item in items) {
            if (item.expireSecs <= 0 || item.isDeleted) continue
            val full = now + item.expireSecs * 1000L
            if (!item.isMine && item.expireAtMs > full) {
                item.expireAtMs = full
                started = true
            }
            if (item.expireAtMs <= now) gone.add(item.messageId)
        }
        for (h in disappearHolders) {
            val pos = h.bindingAdapterPosition
            if (pos in items.indices) h.txtExpire.text = Disappear.formatLeft(h.itemView.context, items[pos], now)
        }
        if (started) onDisappearStarted?.invoke()
        gone.forEach { slideOut(it) }
    }

    /** Slides the bubble off to its own side, then drops the row. The core removes it from the archive on its own clock. */
    private fun slideOut(messageId: String) {
        val idx = indexOfMessageId(messageId)
        if (idx < 0) return
        val item = items[idx]
        item.expireSecs = 0
        val drop = {
            val i = indexOfMessageId(messageId)
            if (i >= 0) {
                items.removeAt(i)
                notifyItemRemoved(i)
                // The neighbours' grouping (merged outline, time on the last one) changes.
                if (i > 0) notifyItemChanged(i - 1)
                if (i < items.size) notifyItemChanged(i)
            }
            updateDisappearPulse()
        }
        val holder = recyclerView?.findViewHolderForAdapterPosition(idx) as? BubbleViewHolder
        if (holder == null) {
            drop()
            return
        }
        val v = holder.itemView
        v.animate().translationX((if (item.isMine) 1f else -1f) * v.width).alpha(0f).setDuration(300L).withEndAction { drop() }.start()
    }

    private fun bindDisappear(holder: BubbleViewHolder, item: Item) {
        if (item.expireSecs <= 0 || item.isDeleted) {
            holder.txtExpire.visibility = View.GONE
            holder.bubble.foreground = null
            disappearHolders.remove(holder)
            return
        }
        holder.txtExpire.visibility = View.VISIBLE
        holder.txtExpire.gravity = if (item.isMine) Gravity.END else Gravity.START
        holder.txtExpire.text = Disappear.formatLeft(holder.itemView.context, item, System.currentTimeMillis())
        val density = holder.itemView.resources.displayMetrics.density
        holder.bubble.foreground = android.graphics.drawable.GradientDrawable().apply {
            cornerRadius = 18f * density // MergedBubbleDecoration.OUTER_RADIUS_DP
            setColor(android.graphics.Color.TRANSPARENT)
            setStroke((2 * density).toInt().coerceAtLeast(1), MaterialColors.getColor(holder.bubble, androidx.appcompat.R.attr.colorPrimary))
        }
        disappearHolders.add(holder)
        updateDisappearPulse()
    }

    override fun onViewRecycled(holder: BubbleViewHolder) {
        super.onViewRecycled(holder)
        disappearHolders.remove(holder)
        // A slid-out row comes back for another message.
        holder.itemView.animate().cancel()
        holder.itemView.translationX = 0f
        holder.itemView.alpha = 1f
        val fileId = holder.itemView.getTag(R.id.layoutVoiceMessage) as? String
        if (fileId != null && boundVoiceHolders[fileId] === holder) {
            boundVoiceHolders.remove(fileId)
            userSeekingFileIds.remove(fileId)
        }
    }

    fun indexOfMessageId(messageId: String): Int = items.indexOfFirst { it.messageId == messageId }

    private fun selectionTint(v: View) = android.graphics.drawable.ColorDrawable(
        androidx.core.graphics.ColorUtils.setAlphaComponent(MaterialColors.getColor(v, androidx.appcompat.R.attr.colorPrimary), 0x40)
    )

    /**
     * Applies freshly loaded history to rows that are ALREADY on screen. The live listener is
     * detached while the chat is paused, so a download that finished, an edit, a delete or a
     * pending-to-sent change during that time did not reach the bubble. Returns true if any row changed.
     */
    fun refreshFrom(loaded: List<Item>): Boolean {
        val byId = loaded.associateBy { it.messageId }
        var changed = false
        for (i in items.indices) {
            val old = items[i]
            val now = byId[old.messageId] ?: continue
            val sameAttachment = old.attachment?.status == now.attachment?.status
            if (old.text == now.text && old.isEdited == now.isEdited && old.isDeleted == now.isDeleted &&
                old.reactions == now.reactions && sameAttachment && (!old.isMine || now.attachment != null || old.status == now.status)) continue
            old.text = now.text
            old.isEdited = now.isEdited
            old.isDeleted = now.isDeleted
            old.reactions = now.reactions
            // Attachment reload rows carry no message status: keep the live one (an ERROR mark).
            if (old.isMine && now.attachment == null) old.status = now.status
            if (!sameAttachment) {
                // The reload may skip the preview of a row that is on screen.
                now.attachment?.let { if (it.previewJpeg == null) it.previewJpeg = old.attachment?.previewJpeg }
                old.attachment = now.attachment
            }
            notifyItemChanged(i)
            changed = true
        }
        return changed
    }

    /**
     * Two paths can both add history rows: `loadHistoryIfAvailable` and `syncMissedMessages`
     * in `onResume`. Both read the archive on IO and add to `localMessages`, so one
     * `message_id` can occasionally appear twice. This removes the extra rows for the same
     * non-blank `message_id` and keeps the first one. Called after every merge.
     * Returns the number of rows removed.
     */
    fun dedupeByMessageId(): Int {
        val seen = HashSet<String>()
        var removed = 0
        var i = 0
        while (i < items.size) {
            val id = items[i].messageId
            if (id.isNotEmpty() && !seen.add(id)) {
                items.removeAt(i)
                notifyItemRemoved(i)
                removed++
            } else {
                i++
            }
        }
        return removed
    }

    /** See the `highlightedMessageId` note at the top of the file. Passing `null` clears the
     *  highlight (for example after a timer, see the search navigation in ChatActivity / GroupChatActivity). */
    fun setHighlighted(messageId: String?) {
        val previous = highlightedMessageId
        highlightedMessageId = messageId
        if (previous != null && previous != messageId) {
            val idx = indexOfMessageId(previous)
            if (idx >= 0) notifyItemChanged(idx)
        }
        if (messageId != null) {
            val idx = indexOfMessageId(messageId)
            if (idx >= 0) notifyItemChanged(idx)
        }
    }

    fun addMessage(item: Item) {
        // One message can arrive several times over different paths (LAN, onion, server, gossip).
        // Each copy used to call `addMessage` again, so one message got several bubbles.
        // Now the add is idempotent by `messageId`: if a row with that id exists, no new bubble
        // is added. Rows with random UUIDs (failed or optimistic rows) are already unique.
        if (item.messageId.isNotEmpty() && items.any { it.messageId == item.messageId }) {
            return
        }
        // Insert in SEND order. Messages mostly arrive in order (a backwards scan is close to O(1)).
        // A late-delivered message, for example one from a sender that was offline for a while,
        // goes to its send-time position, not to the bottom. Equal keys append after the last one.
        var idx = items.size
        while (idx > 0 && items[idx - 1].orderKey > item.orderKey) idx--
        items.add(idx, item)
        notifyItemInserted(idx)
        // If a held "seen" notice targets exactly this message, apply it now. Otherwise the mark
        // would stay on the old message (see `pendingSeenMessageId`).
        val awaitingSeenId = pendingSeenMessageId
        if (awaitingSeenId != null && awaitingSeenId == item.messageId) {
            val avatars = pendingSeenAvatars
            pendingSeenMessageId = null
            applySeen(awaitingSeenId, avatars)
        }
        // The "grouped with the previous" state of the neighbours may have changed when a new
        // neighbour is added. Rebind them so the timestamp is hidden or shown correctly.
        if (idx > 0) notifyItemChanged(idx - 1)
        if (idx < items.size - 1) notifyItemChanged(idx + 1)
    }

    /** Updates the reaction summary of a message (see the Rust `reaction` event and
     *  `reactions_summary`). If the target is not in this list, it is ignored silently. */
    /** Tapping the reaction pill opens the "who reacted with what" list (see ChatActivity /
     *  GroupChatActivity `showReactionsDialog`). */
    var onReactionsClick: ((Item) -> Unit)? = null

    /** Tapping the seen-by avatars lists who saw the message and when (`showSeenByDialog`). */
    var onSeenByClick: ((Item) -> Unit)? = null

    fun applyReactions(messageId: String, summary: String) {
        val idx = indexOfMessageId(messageId)
        if (idx < 0) return
        items[idx].reactions = summary
        notifyItemChanged(idx)
    }

    /** Updates the state and progress of an attachment (see the pollNetwork "file_progress",
     *  "file_complete" and "file_failed" events). An unknown target is ignored silently. */
    fun applyAttachmentUpdate(fileId: String, status: AttachmentStatus, bytesDone: Long? = null) {
        val idx = indexOfMessageId(fileId)
        if (idx < 0) return
        val attachment = items[idx].attachment ?: return
        // Record the download start at the first DOWNLOADING transition. Reset it on complete or
        // failure, so a later retry measures from scratch.
        if (status == AttachmentStatus.DOWNLOADING) {
            if (attachment.downloadStartedAt == 0L) {
                attachment.downloadStartedAt = System.currentTimeMillis()
            }
        } else {
            attachment.downloadStartedAt = 0L
        }
        attachment.status = status
        if (bytesDone != null) attachment.bytesDone = bytesDone
        notifyItemChanged(idx)
    }

    /** Updates voice playback state. ChatActivity calls it on play, pause and speed changes
     *  (infrequent events) and it triggers a full `notifyItemChanged`. For the frequent
     *  progress ticks (every 200 ms) use `tickVoicePlayback` instead, otherwise the full rebind
     *  would move the slider under the user's finger. */
    fun updateVoicePlayback(fileId: String, isPlaying: Boolean, positionMs: Int, speed: Float) {
        val idx = indexOfMessageId(fileId)
        if (idx < 0) return
        val attachment = items[idx].attachment ?: return
        attachment.isPlaying = isPlaying
        attachment.playbackPositionMs = positionMs
        attachment.playbackSpeed = speed
        notifyItemChanged(idx)
    }

    /** Frequent position update during playback (every 200 ms). It writes straight into the
     *  ViewHolder that is on screen, without a full rebind (see `boundVoiceHolders`). If the row
     *  is off screen, the update is ignored, but `attachment.playbackPositionMs` is still
     *  updated in the item data, so the correct position shows when the row comes back. */
    fun tickVoicePlayback(fileId: String, positionMs: Int, durationMs: Int) {
        val idx = indexOfMessageId(fileId)
        if (idx >= 0) items[idx].attachment?.playbackPositionMs = positionMs
        if (fileId in userSeekingFileIds) return
        val holder = boundVoiceHolders[fileId] ?: return
        val slider = holder.progressVoicePlayback
        val safeDuration = durationMs.coerceAtLeast(1)
        if (slider.valueTo != safeDuration.toFloat()) slider.valueTo = safeDuration.toFloat()
        slider.value = positionMs.toFloat().coerceIn(0f, slider.valueTo)
        val remaining = (durationMs - positionMs).coerceAtLeast(0)
        holder.txtVoiceDuration.text = formatDuration(remaining)
    }

    /** Applies an incoming or outgoing edit event. An unknown target (for example a message
     *  that is not loaded) is ignored silently. */
    fun applyEdit(targetMessageId: String, newText: String) {
        val idx = indexOfMessageId(targetMessageId)
        if (idx < 0) return
        items[idx].text = newText
        items[idx].isEdited = true
        notifyItemChanged(idx)
    }

    fun applyDelete(targetMessageId: String) {
        val idx = indexOfMessageId(targetMessageId)
        if (idx < 0) return
        items[idx].isDeleted = true
        notifyItemChanged(idx)
        // A selected row that is deleted leaves the selection.
        if (selectedIds.remove(targetMessageId)) {
            if (selectedIds.isEmpty()) selectedKind = null
            onSelectionChanged?.invoke()
        }
        // A deleted message no longer groups with its neighbours. Rebind them too, so they
        // un-merge (spacing, timestamp and sender row are restored).
        if (idx > 0) notifyItemChanged(idx - 1)
        if (idx < items.size - 1) notifyItemChanged(idx + 1)
        // Replies on screen that quote this message lose the quoted text too. The core has cleared
        // it, but these rows were loaded before.
        items.forEachIndexed { i, it ->
            if (it.replyToMessageId == targetMessageId && it.replyToPreview != null) {
                it.replyToPreview = null
                notifyItemChanged(i)
            }
        }
    }

    /** Applies a send status update (see the Rust "status" event). A message that stayed "pending"
     *  on the first try becomes "sent" or "error" later. */
    fun applyStatus(targetMessageId: String, status: Status) {
        val idx = indexOfMessageId(targetMessageId)
        if (idx < 0) return
        items[idx].status = status
        notifyItemChanged(idx)
    }

    /**
     * Retries a failed (ERROR) message. The SAME bubble is kept, no second copy is added.
     * The retry is a new network packet with a new `message_id` / `local_id`, because the old
     * ratchet position may no longer be valid (see the Rust `MAX_UNCONFIRMED_AGE_MS` note).
     * So this bubble's id is updated to the new one, and later "status" and "seen" events match it.
     * An unknown target is ignored silently.
     */
    fun retryMessage(oldMessageId: String, newMessageId: String, status: Status) {
        val idx = indexOfMessageId(oldMessageId)
        if (idx < 0) return
        items[idx].messageId = newMessageId
        items[idx].status = status
        notifyItemChanged(idx)
    }

    /**
     * Applies a seen notice (see the `lastSeenMessageId` note at the top of the file).
     * `viewerAvatars` is the FULL current list of people who have seen this message, not a
     * delta: the caller passes the full list every time (in a group it builds up over time).
     * The row is updated if it is the current latest-seen message or newer. A notice for an
     * OLDER message (rare, for example out of order) is ignored, so the mark never moves back.
     */
    fun applySeen(targetMessageId: String, viewerAvatars: List<SeenByViewer>) {
        val idx = indexOfMessageId(targetMessageId)
        if (idx < 0) {
            // Held back, not dropped, when its target is not loaded yet (see `pendingSeenMessageId`).
            pendingSeenMessageId = targetMessageId
            pendingSeenAvatars = viewerAvatars
            return
        }
        // Only its own held notice is cleared. An older "seen" that arrives first must not drop
        // the one held for a message that is not in the list yet.
        if (pendingSeenMessageId == targetMessageId) pendingSeenMessageId = null
        val previousId = lastSeenMessageId
        val previousIdx = previousId?.let { indexOfMessageId(it) } ?: -1
        if (idx < previousIdx) return
        lastSeenMessageId = targetMessageId
        lastSeenAvatars = viewerAvatars
        if (previousId != null && previousId != targetMessageId && previousIdx >= 0) {
            notifyItemChanged(previousIdx)
        }
        notifyItemChanged(idx)
    }

    /** The RecyclerView pool keeps 5 rows by default. A screen of short text rows needs about 20,
     *  and each inflate is slow (font lookup per TextView). The pool is pre-filled when idle, so the
     *  first scroll from tall media rows into text rows does not stutter. */
    fun warmPool(rv: RecyclerView, count: Int = 24) {
        val pool = rv.recycledViewPool
        pool.setMaxRecycledViews(0, count + 8)
        rv.setItemViewCacheSize(8)
        var left = count
        android.os.Looper.myQueue().addIdleHandler {
            if (!rv.isAttachedToWindow) return@addIdleHandler false
            pool.putRecycledView(createViewHolder(rv, 0))
            --left > 0
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): BubbleViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message_bubble, parent, false)
        val holder = BubbleViewHolder(view)
        // The fixed 340 dp max width plus the side column (reactions, seen marks) pushed the row off
        // narrow screens. The limit is now derived from the screen width.
        val d = parent.resources.displayMetrics
        val screenDp = d.widthPixels / d.density
        val textMax = (minOf(340f, screenDp - 8f - 72f - 24f) * d.density).toInt()
        holder.textView.maxWidth = textMax
        holder.txtAttachmentCaption.maxWidth = textMax
        holder.txtReplyQuoteText.maxWidth = (minOf(300f, screenDp - 80f) * d.density).toInt()
        // Sticker: no frame, slightly rounded corners.
        val radius = 8 * d.density
        holder.imgSticker.outlineProvider = object : android.view.ViewOutlineProvider() {
            override fun getOutline(view: View, outline: android.graphics.Outline) {
                outline.setRoundRect(0, 0, view.width, view.height, radius)
            }
        }
        holder.imgSticker.clipToOutline = true
        return holder
    }

    override fun onBindViewHolder(holder: BubbleViewHolder, position: Int) {
        val item = items[position]
        holder.itemView.foreground = if (item.messageId in selectedIds) selectionTint(holder.itemView) else null
        val groupedWithPrevious = isGroupedWithPrevious(position)
        val groupedWithNext = isGroupedWithNext(position)
        holder.container.gravity = if (item.isMine) Gravity.END else Gravity.START
        placeSideColumn(holder, item.isMine)
        // The bubble background is applied to the container that wraps the text or attachment
        // layout AND the meta row together (see item_message_bubble.xml `layoutBubble`), so the
        // time sits inside the bubble.
        // Grouped bubbles: the corner radius on the joined edge is reduced, so a run of messages
        // reads as one stack. The first bubble of a group keeps its normal corners, the others use
        // the "grouped" variant (see bubble_*_grouped.xml).
        // Grouped bubbles do NOT draw their own background. The merged outline (convex corners and
        // concave steps) is drawn as one path under the list by MergedBubbleDecoration. A drawable
        // per bubble only knows its own bounds, so a gradient across the whole list is not possible.
        // All backgrounds are drawn in one place with one shared shader (see MergedBubbleDecoration).
        holder.bubble.background = null

        // The reaction pill sits beside the bubble, on the first line (see item_message_bubble.xml
        // `colBubbleSide`). The caption exists only on attachment bubbles (a text message's text is
        // `txtBubbleText`). A sticker has no caption.
        val attachmentInfo = item.attachment
        if (attachmentInfo != null && item.caption.isNotBlank() && !item.isDeleted
            && !attachmentInfo.isSticker
        ) {
            holder.txtAttachmentCaption.visibility = View.VISIBLE
            holder.txtAttachmentCaption.text = com.p2p.messenger.util.Forward.strip(item.caption)
        } else {
            holder.txtAttachmentCaption.visibility = View.GONE
        }

        if (item.reactions.isBlank() || item.isDeleted) {
            holder.pillReactions.visibility = View.GONE
        } else {
            holder.pillReactions.visibility = View.VISIBLE
            holder.pillReactions.text = item.reactions
            holder.pillReactions.setOnClickListener { onReactionsClick?.invoke(item) }
        }

        // Corner radii are chosen per position in the group. The bubbles themselves must also touch:
        // the bottom padding of the row above is set to ZERO on the grouped edge, and the top padding
        // of the next row is zero too. The two bubbles then join into one shape
        // (see bubble_*_grouped.xml).
        val defaultPaddingPx = (4 * holder.itemView.resources.displayMetrics.density).toInt()
        holder.container.setPadding(
            defaultPaddingPx,
            if (groupedWithPrevious) 0 else defaultPaddingPx,
            defaultPaddingPx,
            if (groupedWithNext) 0 else defaultPaddingPx
        )

        // The row that matches the search is highlighted temporarily. A translucent colour is set on
        // the whole row background, instead of changing the bubble drawable (that would need a light
        // and a dark variant).
        holder.container.setBackgroundColor(
            if (item.messageId == highlightedMessageId) {
                MaterialColors.getColor(holder.container, com.google.android.material.R.attr.colorTertiaryContainer)
            } else {
                android.graphics.Color.TRANSPARENT
            }
        )

        // The text colour is always set from the theme (for my own bubbles, from the accent colour in
        // Settings, see ThemePrefs.applyAccentColor). There is no separate text colour setting.
        // Material's dynamic colour engine computes the `colorOn*` roles correctly from the background.
        val onColorAttr = if (item.isMine) {
            com.google.android.material.R.attr.colorOnPrimaryContainer
        } else {
            com.google.android.material.R.attr.colorOnSurfaceVariant
        }
        val onColor = MaterialColors.getColor(holder.textView, onColorAttr)
        holder.textView.setTextColor(onColor)
        holder.txtAttachmentName.setTextColor(onColor)
        holder.txtAttachmentCaption.setTextColor(onColor)
        holder.txtForwarded.setTextColor(onColor)
        val forwarded = !item.isDeleted && com.p2p.messenger.util.Forward.isForwarded(if (item.attachment != null) item.caption else item.text)
        holder.txtForwarded.visibility = if (forwarded) View.VISIBLE else View.GONE
        // The time, "edited" label and status tick are inside the bubble. A fixed
        // `?attr/colorOnSurfaceVariant` is hard to read on an outgoing bubble with an accent
        // background. A slightly faded version of the bubble's own text colour gives the right
        // contrast on both bubble colours, in light and dark themes.
        val metaColor = androidx.core.graphics.ColorUtils.setAlphaComponent(onColor, 0xB3)
        holder.timestamp.setTextColor(metaColor)
        holder.editedLabel.setTextColor(metaColor)
        // Secondary lines of an attachment bubble use the same colour family. A fixed
        // `?attr/colorOnSurfaceVariant` is too grey, and on an outgoing accent bubble it is almost
        // unreadable after the colour was darkened.
        holder.txtAttachmentSize.setTextColor(metaColor)
        holder.txtAttachmentEta.setTextColor(metaColor)
        holder.txtVoiceDuration.setTextColor(metaColor)
        // The status tick and the "seen by" indicator are NOT inside the bubble. They sit BESIDE it,
        // directly on the chat background. They used to inherit the bubble's text colour (`onColor`),
        // which only works inside the bubble. On a dark chat background it was almost invisible.
        // The correct role for this position is the surface colour.
        val sideColor = MaterialColors.getColor(
            holder.container, com.google.android.material.R.attr.colorOnSurfaceVariant
        )
        holder.status.imageTintList = android.content.res.ColorStateList.valueOf(sideColor)
        // No bubble behind a sticker: its time sits on the chat background too.
        if (isSticker(item)) holder.timestamp.setTextColor(sideColor)
        holder.txtSeenByMore.setTextColor(sideColor)

        if (!item.isMine && item.senderName != null && !groupedWithPrevious) {
            holder.senderName.text = item.senderName
            holder.senderName.setTextColor(
                senderColors[item.senderIdentityId]
                    ?: MaterialColors.getColor(holder.senderName, com.google.android.material.R.attr.colorPrimary)
            )
            AvatarUtil.renderInto(holder.senderAvatar, item.senderAvatarJpeg, item.senderName)
            holder.senderRow.visibility = View.VISIBLE
        } else {
            holder.senderRow.visibility = View.GONE
        }

        // A message that replies to another one gets a small quote box inside the bubble. Tapping it
        // scrolls the chat to the replied-to message (see `onReplyPreviewClick`).
        // The "null" guard: a JSON parsing bug upstream once let the literal string "null" through
        // instead of a real null (org.json's optString(key, "") does not fall back on an explicit JSON
        // null, only on a missing key). The guard stays as a safety net for that class of bug.
        val replyToId = item.replyToMessageId?.takeIf { it != "null" }
        if (replyToId != null) {
            holder.layoutReplyQuote.visibility = View.VISIBLE
            holder.txtReplyQuoteSender.text = item.replyToSenderLabel?.takeIf { it != "null" }
            // No preview left: the quoted message was deleted.
            // The preview comes from the sender. When the quoted message is available locally, its own
            // text is shown instead, so the text is never put under the wrong name.
            val replyTarget = items.firstOrNull { it.messageId == replyToId }
            val quoteText = when {
                replyTarget == null -> item.replyToPreview?.takeIf { it != "null" && it.isNotEmpty() }
                replyTarget.isDeleted -> null
                else -> replyTarget.attachment
                    ?.let { holder.itemView.context.getString(R.string.lbl_attachment_reply_preview, it.fileName) }
                    ?: com.p2p.messenger.util.Quote.ownText(com.p2p.messenger.util.Forward.strip(replyTarget.text)).takeWholeChars(120)
            }
            holder.txtReplyQuoteText.text = quoteText ?: holder.itemView.context.getString(R.string.msg_deleted)
            // Quote background: the design is a translucent `colorOnSurface` over the surface colour.
            // XML cannot set the alpha on `<solid>`, so the alpha is applied in code, and the colours
            // stay in the theme roles.
            //
            // The quote box is NOT inside the bubble. It is a sibling of `txtBubbleText` in
            // item_message_bubble.xml, on top of the chat background. So the base colour is the surface
            // colour, not the bubble's text colour. The timestamp below uses the same colour family.
            val quoteBase = MaterialColors.getColor(
                holder.layoutReplyQuote, com.google.android.material.R.attr.colorOnSurface
            )
            val quoteAccent = MaterialColors.getColor(
                holder.layoutReplyQuote, com.google.android.material.R.attr.colorPrimary
            )
            holder.layoutReplyQuote.backgroundTintList = android.content.res.ColorStateList.valueOf(
                androidx.core.graphics.ColorUtils.setAlphaComponent(quoteBase, 0x1F)
            )
            holder.viewReplyQuoteBar.setBackgroundColor(quoteAccent)
            holder.txtReplyQuoteSender.setTextColor(quoteAccent)
            holder.txtReplyQuoteText.setTextColor(quoteBase)
            holder.layoutReplyQuote.setOnClickListener {
                onReplyPreviewClick?.invoke(replyToId)
            }
        } else {
            holder.layoutReplyQuote.visibility = View.GONE
            holder.layoutReplyQuote.setOnClickListener(null)
        }

        val attachment = item.attachment
        if (attachment != null && item.isDeleted) {
            // An attachment that is deleted shows the same "This message was deleted" placeholder as a
            // deleted text message. Before, this branch did not check `isDeleted` at all, so a deleted
            // attachment kept its look.
            holder.layoutAttachment.visibility = View.GONE
            holder.textView.visibility = View.VISIBLE
            holder.editedLabel.visibility = View.GONE
            holder.textView.text = holder.itemView.context.getString(R.string.msg_deleted)
            holder.textView.setTypeface(holder.textView.typeface, Typeface.ITALIC)
            holder.textView.alpha = 0.6f
        } else if (attachment != null) {
            holder.textView.visibility = View.GONE
            holder.editedLabel.visibility = View.GONE
            bindAttachment(holder, item, attachment)
        } else {
            holder.layoutAttachment.visibility = View.GONE
            holder.textView.visibility = View.VISIBLE
            if (item.isDeleted) {
                holder.textView.text = holder.itemView.context.getString(R.string.msg_deleted)
                holder.textView.setTypeface(holder.textView.typeface, Typeface.ITALIC)
                holder.textView.alpha = 0.6f
                holder.editedLabel.visibility = View.GONE
            } else {
                val shownText = com.p2p.messenger.util.Forward.strip(item.text)
                holder.textView.text = shownText
                holder.textView.setTypeface(Typeface.DEFAULT, Typeface.NORMAL)
                holder.textView.alpha = 1f
                holder.editedLabel.visibility = if (item.isEdited || item.viaSync) View.VISIBLE else View.GONE
                holder.editedLabel.text = listOfNotNull(
                    holder.itemView.context.getString(R.string.lbl_edited).takeIf { item.isEdited },
                    holder.itemView.context.getString(R.string.lbl_synced).takeIf { item.viaSync }
                ).joinToString(" ")
                // Links in the message text (http, https, www) are clickable. `Linkify.addLinks` sets its
                // own `LinkMovementMethod` on the TextView, which consumes ACTION_DOWN, so the long-press
                // listener of `holder.itemView` never fires (a child view that consumes touch hides it from
                // the parent). The same long-press listener is therefore also set on `holder.textView`
                // (below), so the menu opens whichever view gets the touch.
                val linked = android.text.SpannableString(shownText)
                if (markMentions(linked, item.mentionsMe)) holder.textView.text = linked
                val quoted = com.p2p.messenger.util.Quote.decorate(
                    linked, holder.textView.maxWidth - holder.textView.totalPaddingLeft - holder.textView.totalPaddingRight,
                    { id, preview -> quoteOf(holder.itemView.context, id, preview) },
                    { id -> onReplyPreviewClick?.invoke(id) }
                )
                if (quoted) holder.textView.text = linked
                if (android.text.util.Linkify.addLinks(linked, android.text.util.Linkify.WEB_URLS) || quoted) {
                    // A tap on a link leaves the app for the system browser: ask first.
                    for (span in linked.getSpans(0, linked.length, android.text.style.URLSpan::class.java)) {
                        val start = linked.getSpanStart(span)
                        val end = linked.getSpanEnd(span)
                        val flags = linked.getSpanFlags(span)
                        linked.removeSpan(span)
                        // A URL inside a quote box: the box's tap scrolls to the quoted message.
                        if (linked.getSpans(start, end, com.p2p.messenger.util.Quote.Box::class.java)
                                .any { linked.getSpanStart(it) < end && linked.getSpanEnd(it) > start }) continue
                        linked.setSpan(ConfirmUrlSpan(span.url), start, end, flags)
                    }
                    holder.textView.text = linked
                    holder.textView.movementMethod = android.text.method.LinkMovementMethod.getInstance()
                } else {
                    // A recycled row that showed a link must stop consuming taps.
                    holder.textView.movementMethod = null
                }
            }
        }

        // The timestamp is an absolute time, for example "(sent at: HH:MM day)", which also shows the
        // day. The format is util.formatAbsoluteTime, shared with the pending-message list in Settings.
        // For received messages with a known sender send time (`Item.sentAtMs`), both times are shown,
        // for example "10:42 (sent at: 10:41)". Network delay and queuing can make them differ.
        // Otherwise (a sending bubble, an older sender, or a message loaded from history) only the
        // single receive time is shown.
        val sentAt = item.sentAtMs
        holder.timestamp.text = if (!item.isMine && sentAt != null && sentAt > 0) {
            holder.itemView.context.getString(
                R.string.lbl_received_sent_at, formatAbsoluteTime(item.timestamp), formatAbsoluteTime(sentAt)
            )
        } else {
            holder.itemView.context.getString(R.string.lbl_sent_at, formatAbsoluteTime(item.timestamp))
        }
        // Only the last bubble of a grouped run shows a timestamp.
        holder.timestamp.visibility = if (groupedWithNext) View.GONE else View.VISIBLE

        // Only a message that is not yet out, or that failed, carries a status mark. A sent message
        // shows nothing; its read state is the seen-by avatars below.
        val statusIcon = if (!item.isMine || item.isDeleted) 0 else when (item.status) {
            Status.PENDING -> R.drawable.ic_status_pending
            Status.ERROR -> R.drawable.ic_status_error
            Status.SENT -> 0
        }
        if (statusIcon != 0) {
            holder.status.visibility = View.VISIBLE
            holder.status.setImageResource(statusIcon)
        } else {
            holder.status.visibility = View.GONE
        }

        if (item.isMine && !item.isDeleted && item.messageId == lastSeenMessageId && lastSeenAvatars.isNotEmpty()) {
            bindSeenBy(holder)
            holder.rowSeenBy.setOnClickListener { onSeenByClick?.invoke(item) }
        } else {
            holder.rowSeenBy.visibility = View.GONE
        }

        val longPressListener = View.OnLongClickListener {
            // Attachment bubbles support no edit, delete or copy (see the top of the file). Only plain
            // text messages react to long press. Both my own and received messages react now. The
            // caller (ChatActivity / GroupChatActivity) shows only "Copy" for received messages and the
            // full menu for my own.
            if (!item.isDeleted && item.attachment == null) {
                longPress(item, onItemLongPress)
                true
            } else {
                false
            }
        }
        holder.itemView.setOnLongClickListener(longPressListener)
        // See the `Linkify.addLinks` note above. A text with links can consume the touch on
        // `holder.textView` through its own `LinkMovementMethod`, so the same listener is set there too.
        holder.textView.setOnLongClickListener(longPressListener)
        bindDisappear(holder, item)
    }

    /**
     * The side column (reactions, pending or error mark, seen-by avatars) is on the OUTER side of
     * the bubble: right of a received bubble, LEFT of my own. On my own side it used to push the
     * bubble inward by its width, so my bubbles did not share their right edge. MergedBubbleDecoration
     * draws a run from that shared edge, so the bubbles were painted under the neighbours' avatars and
     * pills, and the avatars sat in the screen-edge column of the scroll-to-bottom button.
     */
    private fun placeSideColumn(holder: BubbleViewHolder, isMine: Boolean) {
        val line = holder.bubbleLine
        val first = if (isMine) holder.sideColumn else holder.bubble
        if (line.getChildAt(0) !== first) {
            line.removeView(first)
            line.addView(first, 0)
        }
        val gap = (4 * holder.itemView.resources.displayMetrics.density).toInt()
        val params = holder.sideColumn.layoutParams as ViewGroup.MarginLayoutParams
        val start = if (isMine) 0 else gap
        val end = if (isMine) gap else 0
        if (params.marginStart != start || params.marginEnd != end) {
            params.marginStart = start
            params.marginEnd = end
            holder.sideColumn.layoutParams = params
        }
        holder.sideColumn.gravity = Gravity.TOP or (if (isMine) Gravity.END else Gravity.START)
    }

    /** Fills an attachment bubble. OFFERED / FAILED: "Download" button. DOWNLOADING: progress indicator.
     *  COMPLETE: tap opens the file (download button and progress hidden, whole row tappable).
     *  Preview images are not part of this version: every file type shows the same generic file icon,
     *  name and size. Tapping a completed image opens the system viewer (see ChatActivity openAttachment).
     */
    private fun bindAttachment(holder: BubbleViewHolder, item: Item, attachment: AttachmentInfo) {
        holder.layoutAttachment.visibility = View.VISIBLE
        if (isSticker(item)) {
            bindSticker(holder, item, attachment)
            return
        }
        holder.imgSticker.visibility = View.GONE

        // Only a REAL voice message is drawn as a player. A plain audio FILE that the user added from the
        // file manager has no duration. Drawn as a player, the bubble lost its file name, size and any
        // useful label, so the receiver could not see what it was. The sender puts `duration_ms` into
        // FileOffer for real voice notes, so a voice note that is NOT downloaded yet is still drawn as a player.
        if (attachment.mimeType.startsWith("audio/") && (attachment.durationMs ?: 0) > 0) {
            holder.imgAttachmentThumbnail.visibility = View.GONE
            holder.rowGenericAttachment.visibility = View.GONE
            holder.layoutVoiceMessage.visibility = View.VISIBLE
            // A recycled holder keeps the state of the previous FILE row: stale progress, and a tap that
            // would open the other message's file. Both are reset here.
            holder.progressAttachment.visibility = View.GONE
            holder.txtAttachmentEta.visibility = View.GONE
            val voiceClick = View.OnClickListener {
                if (attachment.status != AttachmentStatus.DOWNLOADING && attachment.status != AttachmentStatus.COMPLETE) {
                    onAttachmentClick?.invoke(item)
                }
            }
            holder.btnAttachmentDownload.setOnClickListener(voiceClick)
            holder.layoutAttachment.setOnClickListener(voiceClick)
            holder.layoutAttachment.setOnLongClickListener(null)
            bindVoiceMessage(holder, item, attachment)
            return
        }
        holder.layoutVoiceMessage.visibility = View.GONE
        holder.rowGenericAttachment.visibility = View.VISIBLE
        holder.txtAttachmentName.text = attachment.fileName
        val context = holder.itemView.context

        // If the preview is present, it is shown without downloading the full file.
        val preview = attachment.previewJpeg
        val thumb = holder.imgAttachmentThumbnail
        if (preview != null) {
            // The sender controls the bytes: decode with a bounded size (see ImagePreview.decodeBytes).
            // The cache key includes the bytes too, so a re-sent file with the same id gets its new preview.
            val cacheKey = attachment.fileId + ":" + preview.contentHashCode()
            val cached = previewCache.get(cacheKey)
            thumb.tag = cacheKey
            if (cached != null) {
                thumb.visibility = View.VISIBLE
                thumb.setImageBitmap(cached)
            } else {
                // A cache miss decodes on a worker thread. The recycled holder is checked by its tag.
                thumb.visibility = View.GONE
                previewDecoder.execute {
                    val bmp = com.p2p.messenger.util.ImagePreview.decodeBytes(preview, 1024) ?: return@execute
                    previewCache.put(cacheKey, bmp)
                    thumb.post {
                        if (thumb.tag == cacheKey) {
                            thumb.visibility = View.VISIBLE
                            thumb.setImageBitmap(bmp)
                        }
                    }
                }
            }
        } else {
            thumb.tag = null
            thumb.visibility = View.GONE
        }

        holder.txtAttachmentSize.text = when (attachment.status) {
            AttachmentStatus.DOWNLOADING -> context.getString(R.string.msg_attachment_downloading) +
                " " + Formatter.formatShortFileSize(context, attachment.bytesDone) + " / " +
                Formatter.formatShortFileSize(context, attachment.totalSize)
            AttachmentStatus.FAILED -> context.getString(R.string.msg_attachment_failed)
            else -> Formatter.formatShortFileSize(context, attachment.totalSize)
        }

        if (attachment.status == AttachmentStatus.DOWNLOADING) {
            holder.progressAttachment.visibility = View.VISIBLE
            val max = attachment.totalSize.coerceAtLeast(1L)
            // `setProgressCompat(.., true)` animates the progress instead of jumping to the new percentage
            // (see the "real progress" note at the top of the file).
            holder.progressAttachment.max = 1000
            val fraction = ((attachment.bytesDone.toDouble() / max.toDouble()) * 1000).toInt().coerceIn(0, 1000)
            holder.progressAttachment.setProgressCompat(fraction, true)
            // Remaining time (ETA) is computed from the average speed (bytes received / elapsed time).
            // It stays hidden until there is enough data to measure, rather than showing a misleading estimate.
            val etaText = formatEta(context, attachment)
            if (etaText != null) {
                holder.txtAttachmentEta.visibility = View.VISIBLE
                holder.txtAttachmentEta.text = etaText
            } else {
                holder.txtAttachmentEta.visibility = View.GONE
            }
        } else {
            holder.progressAttachment.visibility = View.GONE
            holder.txtAttachmentEta.visibility = View.GONE
        }
        holder.btnAttachmentDownload.setText(
            if (attachment.status == AttachmentStatus.FAILED && attachment.bytesDone > 0) R.string.action_resume_download else R.string.lbl_download
        )
        holder.btnAttachmentDownload.visibility = if (attachment.status == AttachmentStatus.OFFERED || attachment.status == AttachmentStatus.FAILED) View.VISIBLE else View.GONE

        val clickListener = View.OnClickListener {
            if (attachment.status != AttachmentStatus.DOWNLOADING) {
                onAttachmentClick?.invoke(item)
            }
        }
        holder.btnAttachmentDownload.setOnClickListener(clickListener)
        holder.layoutAttachment.setOnClickListener(clickListener)
        holder.layoutAttachment.setOnLongClickListener {
            if (attachment.status == AttachmentStatus.COMPLETE) {
                longPress(item, onAttachmentLongClick)
                true
            } else {
                false
            }
        }
    }

    /** A sticker: the picture fitted into 160 dp, no frame (MergedBubbleDecoration skips it), no name row. */
    private fun bindSticker(holder: BubbleViewHolder, item: Item, attachment: AttachmentInfo) {
        holder.rowGenericAttachment.visibility = View.GONE
        holder.layoutVoiceMessage.visibility = View.GONE
        holder.imgAttachmentThumbnail.visibility = View.GONE
        holder.progressAttachment.visibility = View.GONE
        holder.txtAttachmentEta.visibility = View.GONE
        holder.btnAttachmentDownload.visibility = View.GONE
        holder.txtAttachmentName.text = ""
        holder.txtAttachmentSize.text = ""
        holder.imgSticker.visibility = View.VISIBLE

        val cached = stickerImages.get(attachment.fileId)
        if (cached != null) {
            holder.imgSticker.setImageDrawable(cached)
            // Play a few loops, then stop on the last frame. A looping sticker on screen kept the whole
            // chat redrawing at about 35 fps, which cost half a core on a Samsung 9S.
            (cached as? android.graphics.drawable.AnimatedImageDrawable)?.apply { repeatCount = 2; start() }
        } else {
            holder.imgSticker.setImageDrawable(null)
            val provider = stickerImageProvider
            if (provider != null && stickerPending.add(attachment.fileId)) {
                provider(attachment.fileId) { drawable ->
                    stickerPending.remove(attachment.fileId)
                    if (drawable != null) {
                        stickerImages.put(attachment.fileId, drawable)
                        val idx = indexOfMessageId(attachment.fileId)
                        if (idx >= 0) notifyItemChanged(idx)
                    }
                }
            }
        }

        holder.layoutAttachment.setOnClickListener { onAttachmentClick?.invoke(item) }
        holder.layoutAttachment.setOnLongClickListener {
            longPress(item, onAttachmentLongClick)
            true
        }
    }

    /**
     * Voice message bubble. In OFFERED, DOWNLOADING and FAILED states the bar shows the download
     * progress, and the play button starts the download (`onAttachmentClick`, the same trigger as the
     * generic attachment). In COMPLETE the bar returns to the playback position, and the play / pause
     * and speed badge are enabled.
     */
    private fun bindVoiceMessage(holder: BubbleViewHolder, item: Item, attachment: AttachmentInfo) {
        val isComplete = attachment.status == AttachmentStatus.COMPLETE
        val durationMs = attachment.durationMs ?: 0
        val slider = holder.progressVoicePlayback

        holder.itemView.setTag(R.id.layoutVoiceMessage, attachment.fileId)
        boundVoiceHolders[attachment.fileId] = holder

        if (isComplete) {
            slider.isEnabled = true
            val safeDuration = durationMs.coerceAtLeast(1)
            // Order matters: set `valueTo` before `value`, so `value` never leaves the valid range
            // (a Slider throws IllegalStateException when value > valueTo).
            slider.value = 0f
            slider.valueTo = safeDuration.toFloat()
            slider.value = attachment.playbackPositionMs.toFloat().coerceIn(0f, safeDuration.toFloat())
            val remaining = (durationMs - attachment.playbackPositionMs).coerceAtLeast(0)
            holder.txtVoiceDuration.text = formatDuration(if (attachment.isPlaying || attachment.playbackPositionMs > 0) remaining else durationMs)
            holder.btnVoicePlayPause.setImageResource(if (attachment.isPlaying) R.drawable.ic_pause else R.drawable.ic_play)
            holder.btnVoiceSpeed.visibility = View.VISIBLE
            holder.btnVoiceSpeed.text = formatSpeed(attachment.playbackSpeed)
            holder.btnVoicePlayPause.setOnClickListener { onVoicePlayClick?.invoke(item) }
            holder.btnVoiceSpeed.setOnClickListener { onVoiceSpeedClick?.invoke(item) }
            holder.layoutVoiceMessage.setOnLongClickListener {
                longPress(item, onAttachmentLongClick)
                true
            }
            slider.clearOnSliderTouchListeners()
            slider.addOnSliderTouchListener(object : Slider.OnSliderTouchListener {
                override fun onStartTrackingTouch(s: Slider) { userSeekingFileIds.add(attachment.fileId) }
                override fun onStopTrackingTouch(s: Slider) {
                    userSeekingFileIds.remove(attachment.fileId)
                    onVoiceSeek?.invoke(item, s.value.toInt())
                }
            })
        } else {
            slider.isEnabled = false
            val safeTotal = attachment.totalSize.coerceAtLeast(1L).toFloat()
            slider.value = 0f
            slider.valueTo = safeTotal
            val downloaded = if (attachment.status == AttachmentStatus.DOWNLOADING) attachment.bytesDone.toFloat() else 0f
            slider.value = downloaded.coerceIn(0f, safeTotal)
            holder.txtVoiceDuration.text = when (attachment.status) {
                AttachmentStatus.FAILED -> holder.itemView.context.getString(R.string.msg_attachment_failed)
                AttachmentStatus.DOWNLOADING -> holder.itemView.context.getString(R.string.msg_attachment_downloading)
                else -> if (durationMs > 0) formatDuration(durationMs) else ""
            }
            holder.btnVoicePlayPause.setImageResource(R.drawable.ic_play)
            holder.btnVoiceSpeed.visibility = View.GONE
            val downloadListener = View.OnClickListener {
                if (attachment.status != AttachmentStatus.DOWNLOADING) onAttachmentClick?.invoke(item)
            }
            holder.btnVoicePlayPause.setOnClickListener(downloadListener)
            holder.btnVoiceSpeed.setOnClickListener(null)
            holder.layoutVoiceMessage.setOnLongClickListener(null)
            slider.clearOnSliderTouchListeners()
        }
    }

    /** Shows the 5 latest viewers as small avatars (the list is in seen order). The rest is summarised
     *  as "+N". In 1:1 chats `lastSeenAvatars` always has one entry. */
    private fun bindSeenBy(holder: BubbleViewHolder) {
        holder.rowSeenBy.visibility = View.VISIBLE
        val slots = listOf(holder.imgSeenBy1, holder.imgSeenBy2, holder.imgSeenBy3, holder.imgSeenBy4, holder.imgSeenBy5)
        val avatars = lastSeenAvatars.takeLast(slots.size)
        for (i in slots.indices) {
            if (i < avatars.size) {
                slots[i].visibility = View.VISIBLE
                AvatarUtil.renderInto(slots[i], avatars[i].avatarJpeg, avatars[i].displayName)
            } else {
                slots[i].visibility = View.GONE
            }
        }
        val overflow = lastSeenAvatars.size - avatars.size
        if (overflow > 0) {
            holder.txtSeenByMore.visibility = View.VISIBLE
            holder.txtSeenByMore.text = "+$overflow"
        } else {
            holder.txtSeenByMore.visibility = View.GONE
        }
    }

    /** Remaining time (ETA) text. Computed from the average speed (bytes received / elapsed time).
     *  The average is steadier than the instantaneous speed on a fluctuating network. Returns `null`
     *  when there is not enough data yet (not started, less than 1 s elapsed, or no bytes received),
     *  and the counter is hidden. */
    private fun formatEta(context: android.content.Context, attachment: AttachmentInfo): String? {
        val startedAt = attachment.downloadStartedAt
        if (startedAt <= 0L) return null
        val elapsedMs = System.currentTimeMillis() - startedAt
        if (elapsedMs < 1000L) return null
        val done = attachment.bytesDone
        if (done <= 0L) return null
        val remaining = attachment.totalSize - done
        if (remaining <= 0L) return null
        val bytesPerMs = done.toDouble() / elapsedMs.toDouble()
        if (bytesPerMs <= 0.0) return null
        val etaSeconds = (remaining.toDouble() / bytesPerMs / 1000.0).toLong()
        return if (etaSeconds >= 60) {
            context.getString(R.string.lbl_eta_minutes, etaSeconds / 60, etaSeconds % 60)
        } else {
            context.getString(R.string.lbl_eta_seconds, etaSeconds.coerceAtLeast(1))
        }
    }

    private fun formatDuration(ms: Int): String {
        val totalSeconds = ms / 1000
        val minutes = totalSeconds / 60
        val seconds = totalSeconds % 60
        return String.format(Locale.getDefault(), "%d:%02d", minutes, seconds)
    }

    private fun formatSpeed(speed: Float): String {
        val trimmed = if (speed == speed.toInt().toFloat()) speed.toInt().toString() else speed.toString()
        return "${trimmed}x"
    }

    override fun getItemCount(): Int = items.size
}

/** A link in a message: shows the real host and asks before it opens. */
private class ConfirmUrlSpan(url: String) : android.text.style.URLSpan(url) {
    override fun onClick(widget: View) {
        val host = try {
            java.net.IDN.toASCII(android.net.Uri.parse(url).host ?: "")
        } catch (e: Exception) {
            ""
        }
        android.app.AlertDialog.Builder(widget.context)
            .setTitle(host.ifEmpty { url })
            .setMessage(widget.context.getString(R.string.msg_open_link_warning, url))
            .setPositiveButton(R.string.action_open) { _, _ -> open(widget) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun open(widget: View) {
        try {
            super.onClick(widget)
        } catch (e: Exception) {
        }
    }
}

/** `take(n)` on UTF-16 can split a surrogate pair (emoji) in half; back off one unit then. */
fun String.takeWholeChars(n: Int): String =
    if (length <= n) this else substring(0, if (n > 0 && Character.isHighSurrogate(this[n - 1])) n - 1 else n)
