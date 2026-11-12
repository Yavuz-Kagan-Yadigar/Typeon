package com.p2p.messenger.ui

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
 * Tek bir kişiyle (1:1) yapılan sohbet ekranı.
 *
 * Mesajlar `P2PService`'in `pollNetwork` döngüsünden `messageListener`
 * üzerinden gelir; her olay `{"type":...}` etiketli bir JSON'dur (bkz. Rust
 * `receive_message`). Bu ekran SADECE kendi karşı tarafına (`peer`) ait ve
 * gruba ait OLMAYAN olayları işler — bkz. `messageListener`.
 *
 * Mesaj geçmişi artık node modundan BAĞIMSIZ olarak her cihazda yerelde
 * şifreli tutuluyor (bkz. Rust `archive_message` / MessageHistoryManager);
 * bu ekran açılışta önce yereli yükler (`loadHistoryIfAvailable`), sonra
 * karşı taraftan eksik olanları ister (`requestHistorySync`).
 */
class ChatActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PEER_DEVICE_FINGERPRINT = "peer_device_fingerprint"
        const val EXTRA_PEER_DISPLAY_NAME = "peer_display_name"

        private const val HISTORY_LOAD_LIMIT = 200
        private const val HISTORY_SYNC_LIMIT = 30
        /** Sonsuz kaydırmada bir seferde çekilen "daha eski" sayfa boyutu. */
        private const val OLDER_HISTORY_PAGE_SIZE = 50
        private const val OLDER_HISTORY_REPLY_WAIT_MS = 15_000L
        /** Listenin başına bu kadar yaklaşıldığında bir sonraki sayfa istenir. */
        private const val LOAD_OLDER_HISTORY_THRESHOLD = 3

        private const val SESSION_POLL_INTERVAL_MS = 800L
        /** El sıkışma tamamlandıktan sonra yoklama seyrekleşir — bkz.
         *  `sessionPollRunnable`. */
        private const val STEADY_STATE_POLL_INTERVAL_MS = 5_000L
        private const val OWN_STATUS_POLL_INTERVAL_MS = 2_000L

        /** bkz. Rust `MAX_ATTACHMENT_SIZE` — aynı üst sınır. */
        private const val MAX_ATTACHMENT_SIZE = 4L * 1024 * 1024 * 1024

        /** bkz. `maybePlayTyphoonEffect` — bu kadar süredir sessiz olan bir
         *  sohbete gelen mesaj "uyandırma" sayılır. */
        private const val TYPHOON_QUIET_WINDOW_MS = 15 * 60 * 1000L

        private const val PREVIEW_MAX_DIMENSION = 480
        private const val PREVIEW_JPEG_QUALITY = 85

        /** Yazmayı bıraktıktan sonra "yazıyor" durumunun kapatılma süresi. */
        private const val TYPING_IDLE_TIMEOUT_MS = 3_000L
        /** Karşı taraftan gelen "yazıyor" göstergesinin kendi kendine
         *  sönme süresi — kapatma bildirimi kaybolursa ekranda asılı
         *  kalmasın (bkz. Rust `TypingIndicator` notu: bu paket kasıtlı
         *  olarak yeniden denenmiyor). */
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

    /** `requestHistorySync` gönderildi, yanıtı bekleniyor — bkz.
     *  `applyHistorySync` (yanıt gelmezse hiçbir şey olmaz). */
    private var historySyncPending = false
    private lateinit var fetchHistoryButton: FetchHistoryButton
    /** Sonsuz kaydırmada aynı anda tek bir sayfa isteği olsun diye. */
    private var isLoadingOlderHistory = false
    /** Karşı taraf da boş sayfa döndürdüyse artık hiç sorma. */
    private var noMoreOlderHistory = false
    private var olderHistoryRequest = 0
    private var olderHistoryEmptyReply = false
    /** Set in onResume: the chat is really in front of the user, not just
     *  resumed for a moment underneath the app lock screen. */
    private var resumedUnlocked = false
    private var toolbarAvatarLoaded = false
    /** Invalidates a voice message still being loaded (see `loadAndPlayVoiceMessage`). */
    private var voiceLoadRequest = 0

    /** Sohbet içi arama: eşleşen satırların `localMessages` içindeki
     *  indeksleri (bkz. `runMessageSearch`/`goToSearchMatch`). */
    /** Message ids, not list positions: an older page prepended or a
     *  re-sort moves every position. */
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

    /** gönder tuşu artık metin ("➤") taşıyan
     *  bir `Button` değil, uygulamanın bulut logosunu maske olarak
     *  kullanan dairesel bir `ImageButton` — bkz. activity_chat.xml
     *  btnSend / drawable/ic_send_cloud. */
    private lateinit var btnSend: ImageButton
    /** Kullanıcı isteği (2026-09-06): "birşey göndermeyi engellemek gerek
     *  [ratchet oturumu] tam gelene kadar". Bu üç düğme + `btnSend`, bir
     *  ratchet oturumu kurulana kadar (bkz. `sessionPollRunnable` /
     *  `updateComposerLock`) devre dışı bırakılıyor. */
    private lateinit var btnAttach: ImageButton
    private lateinit var btnCamera: ImageButton
    private lateinit var btnVoice: ImageButton
    private lateinit var btnSticker: ImageButton
    private lateinit var txtConnectingBanner: TextView
    /** `sessionPollRunnable` günceller — `hasActiveSession` (bir ratchet
     *  oturumu kuruldu mu). Bu `true` olana kadar hiçbir şey gönderilemez. */
    private var handshakeReady = false
    /** Karşı taraf hesabını sildi (`account_deleted`) — gönderim kapalı. */
    private var peerAccountDeleted = false
    /** `sessionPollRunnable`'ın el sıkışmayı yeniden dürtme hızını sınırlar. */
    private var lastEnsureHandshakeAt = 0L
    /** Ardışık başarısız dürtme sayısı: eşleşmesi hiç tamamlanmayan kişide her 3 sn'de bir
     *  hata + uyanma yerine ilk 5 denemeden sonra 30 sn'ye seyrelir. */
    private var ensureHandshakeStreak = 0
    /** bkz. `maybePlayTyphoonEffect` / ui.TyphoonParticleView. */
    private lateinit var typhoonEffect: TyphoonParticleView
    private lateinit var progressSending: ProgressBar
    /** Üst çubuktaki kişi avatarı — tam ekran açılabilmesi için saklanır
     *  (bkz. `AvatarUtil.openFullscreen`). */
    private var toolbarAvatarBytes: ByteArray? = null

    private lateinit var layoutTypingIndicator: View
    private val typingHandler = Handler(Looper.getMainLooper())
    /** bkz. `TYPING_INDICATOR_TIMEOUT_MS`. */
    private val clearPeerTypingRunnable = Runnable { layoutTypingIndicator.visibility = View.GONE }
    private var isTypingSent = false
    /** bkz. `TYPING_IDLE_TIMEOUT_MS`. */
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
    /** `sendSeenReceipt` / `sendTypingIndicator` JNI çağrıları
     *  paylaşılan çekirdek kilidinde sıraya durabildiğinden ana iş parçacığında
     *  ÇALIŞMAZ — tek iş parçacıklı sıra (CallActivity'deki `DiscardPolicy`
     *  deseni; kapanış sonrası gönderimler sessizce atılır). */
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

    /** Sesli mesaj çalma: TÜM balonlar için TEK bir paylaşımlı
     *  `MediaPlayer` (bkz. SimpleChatAdapter `updateVoicePlayback`). */
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
     * giriş çubuğundaki kamera düğmesi —
     * anlık çekim + kırpma (bkz. ui.CameraCaptureActivity). Sonuç
     * `Intent` extra'sıyla DEĞİL, `CapturedImage` üzerinden geliyor
     * (gerekçe orada); burada sadece "tamam mı" bilgisi taşınıyor.
     */
    private val takePhotoLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            CapturedImage.take()?.let { jpeg -> promptAttachmentCaption(jpeg = jpeg, onRetake = { findViewById<View>(R.id.btnCamera).performClick() }) { caption, picked -> picked.firstOrNull()?.let { onPhotoCaptured(it.jpeg!!, caption, it.hiRes, takeQuote()) } } }
        }
    }

    /** SADECE API 26-28 (scoped storage öncesi) için — bkz.
     *  saveToPublicDownloads notu. API 29+'ta hiç kullanılmaz. */
    private val requestStoragePermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* reddedilse bile devam — kaydetme o zaman başarısız olur, mesajlaşma etkilenmez */ }

    private val sessionPollHandler = Handler(Looper.getMainLooper())
    /**
     * bağlantı durumu göstergesi — iki AYRI sorunun cevabını
     * ayrı ayrı kontrol eder, çünkü bunlar farklı şeyler:
     * - `hasActiveSession` (üstteki "Bağlanılıyor" banner'ı için): "bir
     *   ratchet oturumu kuruldu mu" — kriptografik bir durum, bir kez
     *   kurulunca SÜRESİZ true kalır (bağlantı kopsa bile geçerliliğini
     *   korur — mesajlar artık onaylanana kadar yeniden denendiği için,
     *   bkz. `awaiting_confirmation`, "bağlı değilsin" demek yanlış olurdu).
     * - `isPeerConnected` (action bar altyazısındaki "Bağlı"/"Bağlanılıyor"
     *   durum metni için): karşı taraf ŞU AN gerçekten bağlı mı — Swarm'ın
     *   canlı bağlantı defterine bakar, bağlantı koparsa hemen "Bağlanılıyor"a
     *   döner.
     *
     * ÖNCEDEN İKİSİ İÇİN DE `hasActiveSession` kullanılıyordu — bu yüzden
     * durum metni bir kez "Bağlı" olduktan sonra karşı cihaz gerçekten
     * kapansa/erişilemez olsa bile hep "Bağlı" göstermeye devam ediyordu.
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
     * Kullanıcı isteği (2026-09-06): ratchet oturumu kurulana kadar HİÇBİR
     * şey gönderilemesin — 1:1 sohbette taze eşleşmeden sonra ilk dakikalarda
     * gönderilen mesajların "kaybolmuş gibi" görünmesi buradan geliyordu.
     * Metin kutusu düzenlenebilir kalır (taslak yazılabilir), ama gönder/ek/
     * kamera/ses düğmeleri devre dışı ve soluk; banner NEDEN'i açıkça yazar.
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

    /** Gönderme yolundaki her giriş noktası (gönder/ek/kamera/ses) bunu
     *  çağırır — hazır değilse kısa bir uyarı gösterip `false` döner. */
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
     * karşı tarafın bağlantı durumunu
     * `txtToolbarSubtitle`'ın düz metninden DAHA belirgin/ilk bakışta
     * ayırt edilebilir kılmak için küçük renkli bir nokta + "bağlanılıyor"
     * durumunda nabız gibi atan (pulse) bir animasyon. Üç durum:
     * - `connecting` (henüz bir ratchet oturumu kurulmadı, bkz.
     *   `hasActiveSession`): turuncu, sürekli soluklaşıp-koyulaşan pulse.
     * - `online` (oturum kuruldu VE şu an gerçekten bağlı): yeşil, sabit.
     * - aksi hâlde (`offline` — oturum var ama şu an ulaşılamıyor): gri, sabit.
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
    /** BU cihazın kendi ağ durumu (bkz. ConnectionStatus) —
     *  karşı tarafın durumunun yanında, ayrı bir nokta + metin olarak. */
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
     * "attachments and
     * messages sended to groups seems like sended from 1:1 as well").
     * Artık `group_id`/`group_message_local_id` doluysa (yani bu olay bir
     * GRUBA aitse) 1:1 ekranı bu olayı asla işlemez —
     * GroupChatActivity zaten kendi `group_id` eşleşmesiyle bunu doğru
     * ekrana yönlendiriyor.
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
            // Ayrıştırılamayan olay — sessizce yok say.
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)
        whiteboard = WhiteboardPanel(this, findViewById(R.id.whiteboardHost), findViewById(R.id.whiteboardHandle))
        ThemePrefs.applyChatBackground(this)
        // bkz. util.ChatListDrawer dokümantasyonu.
        com.p2p.messenger.util.ChatListDrawer.setup(this) {
            // Back with the search bar open closes the bar, not the chat.
            (layoutSearchMessages.visibility == View.VISIBLE).also { if (it) toggleMessageSearch() }
        }

        connectingBanner = findViewById(R.id.layoutConnecting)
        layoutTypingIndicator = findViewById(R.id.layoutTypingIndicator)
        fabScrollToBottom = findViewById(R.id.fabScrollToBottom)
        fabScrollToBottom.setOnClickListener { scrollToBottomNow() }
        recycler = findViewById(R.id.recyclerMessages)
        // bkz. aşağıdaki `addOnLayoutChangeListener` — bu, findViewById'i
        // ondan ÖNCE yapmalı, yoksa lateinit init edilmeden kullanılır
        // (UninitializedPropertyAccessException, her ChatActivity açılışında
        // çöktürüyordu).
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
        // Kullanıcı: "mesaj balonları bazen titriyor". Tik/görüldü/tepki
        // güncellemeleri `notifyItemChanged` ile geliyor ve varsayılan
        // animatör her birinde balonun eski ve yeni hâli arasında çapraz
        // geçiş (crossfade) oynatıyordu. Ekleme/silme animasyonları kalıyor.
        (recycler.itemAnimator as? androidx.recyclerview.widget.SimpleItemAnimator)?.supportsChangeAnimations = false
        // Birleşen balonların TEK dış hattı — bkz. MergedBubbleDecoration
        // (neden her balonun kendi arka planı yetmiyor, orada yazılı).
        recycler.addItemDecoration(MergedBubbleDecoration(adapter))
        setupSwipeToReply()

        // Sonsuz kaydırma: listenin başına yaklaşıldığında bir sonraki
        // "daha eski" sayfa istenir (bkz. `loadOlderHistory`).
        recycler.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                if (chatLayoutManager.findFirstVisibleItemPosition() <= LOAD_OLDER_HISTORY_THRESHOLD) {
                    loadOlderHistory()
                }
                updateScrollToBottomFabVisibility()
                fetchHistoryButton.update()
            }
        })
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
        // Üst çubuğa dokununca kişi bilgisi + "Dosyalar ve medya" (grup
        // sohbetindeki menünün 1:1 karşılığı, bkz. showGroupInfoDialog).
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
        // klavye
        // açılınca sohbet onun yüksekliğini telafi etsin ve son mesaj
        // görünür kalsın — bkz. util.KeyboardInsets (neden `adjustResize`
        // yetmiyor, orada ölçümle birlikte yazılı).
        KeyboardInsets.attach(findViewById(R.id.rootChatLayout), recycler)
        // bkz. `syncRecyclerBottomInset` — çubuğun/alıntı pilinin yüksekliği
        // değiştikçe listenin alt dolgusu takip etmeli.
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
            // Sistem dosya seçicisi BAŞKA bir süreçte açılır — bkz.
            // AppLock.beginTrustedExcursion (dönüşte şifre sorulmamalı).
            AppLock.beginTrustedExcursion()
            pickFileLauncher.launch(arrayOf("*/*"))
        }

        // ek düğmesinin yanında doğrudan kamera.
        btnCamera.setOnClickListener {
            if (!ensureHandshakeReadyOrWarn()) return@setOnClickListener
            takePhotoLauncher.launch(Intent(this, CameraCaptureActivity::class.java))
        }

        btnSticker.setOnClickListener {
            if (!ensureHandshakeReadyOrWarn()) return@setOnClickListener
            stickerPicker.show()
        }

        // bkz. `saveToPublicDownloads` — SADECE scoped storage öncesi
        // sürümlerde gerekiyor, API 29+ hiçbir izin istemiyor.
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

    /** Paylaşım ekranından seçilen içerik (bkz. util.ShareIntake). */
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
    // Sesli mesaj — kayıt
    // ---------------------------------------------------------------

    /** Basılı tut = kaydet, sola kaydır = iptal (WhatsApp deseni). */
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
                    // #86: backgrounding cancels the touch; the recording goes on, the user decides
                    promptRecordingDecision()
                    true
                }
                else -> false
            }
        }
    }

    /** "İptal etmek için kaydır" hapı: parmakla birlikte kayar, eşiği
     *  geçince kırmızıya döner. */
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

    /** `send = false` (iptal ya da hata) durumunda kayıt dosyası silinir. */
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
            // Çok kısa kayıtlarda `stop()` fırlatabilir — dosya kullanılamaz.
            file?.delete()
            recorder.release()
            return
        }
        recorder.release()
        if (send && durationMs >= RECORDING_MIN_DURATION_MS && file != null) {
            // sesli mesajın da altına yazı
            // yazılabilsin. Kayıt bırakılır bırakılmaz gönderilmiyor, önce
            // açıklama soruluyor — kullanıcı boş bırakırsa davranış eskisiyle
            // aynı.
            promptAttachmentCaption(onCancel = { file.delete() }) { caption, _ -> sendVoiceMessage(file, durationMs, caption, takeQuote()) }
        } else {
            file?.delete()
            if (send) {
                Toast.makeText(this, R.string.msg_recording_cancelled, Toast.LENGTH_SHORT).show()
            }
        }
    }

    /** Sesli mesaj, normal bir dosya eki olarak gönderilir (mime
     *  "audio/mp4") — tek fark `durationMs`'in taşınması, bkz. Rust
     *  `FileOffer.duration_ms`. */
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
    // Sesli mesaj — çalma
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

    /** Kullanıcı kaydırıcıyı sürükleyip bıraktı — o an çalan mesaj buysa
     *  doğrudan `seekTo`, değilse o konumdan başlatarak yükle. */
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

    /** Ekin çözülmüş kopyasının yolu ana thread DIŞINDA alınır — büyük bir
     *  dosyanın çözülmesi dakikalar sürebilir (bkz. Rust
     *  `begin_attachment_decrypt` notu). */
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

    /** Hız rozeti (1x → 1.5x → 2x → 0.5x, bkz. PlaybackSpeed). Çalmayan bir
     *  balonda sadece tercih olarak saklanır. */
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
    // Sohbet bağlama / gönderim
    // ---------------------------------------------------------------

    /**
     * Intent'teki kişiye bağlanır. `false` dönerse Intent kullanılamaz
     * (fingerprint yok) ve ekran kapanır. AYNI kişiye tekrar bağlanmak
     * (ör. bildirimden gelen ikinci bir Intent) durumu SIFIRLAMAZ —
     * yalnızca farklı bir kişiye geçildiğinde ekran temizlenir.
     */
    private fun bindToIntent(intent: Intent): Boolean {
        val newPeer = intent.getStringExtra(EXTRA_PEER_DEVICE_FINGERPRINT) ?: return false
        val displayName = intent.getStringExtra(EXTRA_PEER_DISPLAY_NAME) ?: newPeer.take(8)
        txtToolbarTitle.text = displayName
        // Fotoğraf henüz yüklenmedi — baş harf rozetiyle başla, aşağıdaki
        // arka plan işi gerçek avatarı getirince değiştir.
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
        // Yeni sohbet: kanıtlanana kadar (poll'ün ilk turu) gönderim KİLİTLİ.
        handshakeReady = false
        pendingShare = emptyList()
        peerAccountDeleted = false
        toolbarAvatarLoaded = false
        updateComposerLock()
        sessionPollHandler.removeCallbacks(sessionPollRunnable)
        sessionPollHandler.post(sessionPollRunnable)

        // `listContacts` bir JNI çağrısı — ana thread'de yapılmaz.
        lifecycleScope.launch(Dispatchers.IO) {
            val avatarBytes = resolveContactAvatar(newPeer)
            val deleted = isAccountDeleted(newPeer)
            withContext(Dispatchers.Main) {
                // Bu arada başka bir sohbete geçilmiş olabilir.
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

        // El sıkışma yoksa başlat — ilk mesajın yazılmasını beklemeden
        // (bkz. Rust `ensure_handshake`).
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

    /** Kişi bilgisi + bu sohbetin yerel ekleri (`StorageActivity`). */
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

    /** bkz. üst çubuk avatarı — `listContacts()`'ta bu cihaz parmak izine
     *  sahip kişiyi bulup profil fotoğrafını döner (yoksa `null`, o zaman
     *  `AvatarUtil` baş harf rozeti gösterir). */
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
                // göndericinin embed ettiği
                // gerçek gönderim anı (bkz. SimpleChatAdapter.Item.sentAtMs
                // dokümantasyonu) — "0"/eksikse (eski sürüm göndericisi)
                // null'a düşer, bubble tek zaman damgasına döner.
                val sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 }
                // bkz. `resolveReplyLabel` — bu canlı olay için `localMessages`
                // zaten TAM (yanıtlanan mesaj, varsa, önceden eklenmiş
                // olmalı), bu yüzden burada DOĞRUDAN çözülebilir.
                // isNull() check matters: org.json's optString(key, "") only
                // falls back on a MISSING key, not an explicit JSON null —
                // Rust always sends this key, so without the check every
                // received message got the literal string "null" here.
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
                // "Görüldü": 1:1'de yalnızca okuma sınırı (ReadStateSync) —
                // karşı taraf onu `seen_bulk` ile bu mesaja da uygular, diske
                // yazılır ve yeniden denenir. Mesaj başına ayrıca `Seen`
                // göndermek aynı bilginin ikinci bir paketiydi.
                scheduleReadWatermark()
            }
            // Çoklu-cihaz (spec 1.7): başka bir cihazımdan gönderdiğim mesaj —
            // burada da "gönderilen" balon olarak göster (markSeen YOK, kendi
            // mesajım). Yeniden açılışta arşivden zaten "sent" olarak gelir.
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
            // emoji tepkileri — Rust tarafı
            // hazır ÖZET dizesini gönderiyor (bkz. `reactions_summary`),
            // burada sayma/toplama yapılmaz.
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
            // "sibling_file": başka cihazımdan gönderdiğim ek — aynı balon, benim tarafımda.
            "file_offer", "sibling_file" -> {
                val autoDownloading = obj.optBoolean("auto_downloading", false)
                // isNull() check: optString("preview_hex", "") returns the
                // literal string "null" (not the fallback) for an explicit
                // JSON null, which then crashes hexToBytes below.
                val previewHex = if (obj.isNull("preview_hex")) null else obj.optString("preview_hex").ifEmpty { null }
                val previewJpeg = previewHex?.let { hexToBytes(it) }
                val durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it }
                // ekle birlikte gelen açıklama
                // ve yanıt bağlamı (bkz. Rust `file_offer` olayı).
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
                        // ek + açıklama + yanıt.
                        caption = attachmentCaption,
                        replyToMessageId = attachmentReplyId,
                        replyToPreview = attachmentReplyPreview,
                        replyToSenderLabel = resolveReplyLabel(attachmentReplyId)
                    )
                )
                onNewIncomingItemAdded()
                // Okuma sınırı yalnızca `messages` tablosunu kapsıyor; ekler
                // için tekil `Seen` kalıyor. Kendi ekimin yankısına gönderilmez.
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
            // Rust bu olayı hem depolama sınırı tahliyesinde hem
            // de ekli bir mesaj silindiğinde üretiyordu ama HİÇBİR istemci
            // dinlemiyordu — balon "tamamlandı" görünmeye devam ediyor,
            // kullanıcı dokununca dosya yok. Artık "teklif edildi"ye döner,
            // yani tekrar indirilebilir görünür.
            "file_evicted" -> adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.OFFERED)
            // "görüldü" bildirimi — karşı taraf
            // mesajı ekranında gördü. Balonun altında küçük bir avatar
            // rozetiyle gösterilir (bkz. SimpleChatAdapter.applySeen).
            "seen" -> {
                val messageId = obj.optString("message_id")
                val peerName = txtToolbarTitle.text.toString()
                adapter.applySeen(
                    messageId,
                    listOf(SimpleChatAdapter.SeenByViewer(peerAvatar(), peerName))
                )
            }
            // Toplu görüldü (2026-09-07): karşı taraf "buraya kadar okudum"
            // sınırı yolladı (bkz. Rust `apply_incoming_read_watermark`).
            // `message_ids` en eskiden yeniye sıralı — 1:1 adaptörü tek bir
            // "son görülen" işareti gösterdiğinden EN YENİsini uygulamak yeter.
            "seen_bulk" -> {
                // Grup olayları `messageListener`'da zaten elendi (`group_id` null değilse).
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
                    // bkz. `TYPING_INDICATOR_TIMEOUT_MS` — kapatma bildirimi
                    // kaybolursa gösterge sonsuza dek asılı kalmasın.
                    typingHandler.postDelayed(clearPeerTypingRunnable, TYPING_INDICATOR_TIMEOUT_MS)
                    if (isRecyclerNearBottom()) {
                        recycler.scrollToPosition(localMessages.size - 1)
                    }
                }
            }
            // Karşı taraf profilini değiştirdi (bkz. Rust `ProfileUpdate`)
            // — üst çubuktaki avatar VE ad canlı güncellenir.
            "profile_update" -> {
                val avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
                toolbarAvatarBytes = avatarHex?.let { hexToBytes(it) }
                toolbarAvatarLoaded = true
                // `previous_display_name` yalnızca ad GERÇEKTEN değiştiyse
                // dolu (her fotoğraf değişikliği de bu paketi taşıyor, bkz.
                // Rust tarafındaki not) — kullanıcıya bildirimi ona bakarak
                // gösteriyoruz, yoksa aynı ad her seferinde "değişti"
                // diye görünürdü.
                val newName = if (obj.isNull("display_name")) null else obj.optString("display_name").ifEmpty { null }
                val oldName = if (obj.isNull("previous_display_name")) null else obj.optString("previous_display_name").ifEmpty { null }
                if (newName != null && oldName != null) {
                    txtToolbarTitle.text = newName
                    Toast.makeText(this, getString(R.string.msg_contact_renamed, oldName, newName), Toast.LENGTH_LONG).show()
                }
                AvatarUtil.renderInto(imgToolbarAvatar, toolbarAvatarBytes, txtToolbarTitle.text.toString())
            }
            // el sıkışma kalıcı olarak başarısız (sürüm/anahtar
            // uyuşmazlığı) — kullanıcıya söylenmeden sessizce sonsuza kadar
            // "Bağlanılıyor" gösteriliyordu.
            "handshake_failed" -> {
                Toast.makeText(this, R.string.error_handshake_incompatible, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun markSeen(messageId: String) {
        if (!AppLock.isUnlocked()) return
        // `sendSeenReceipt` JNI çağrısı çekirdek kilidinde
        // sıraya durur — ana iş parçacığından çağrılmaz (arayüz takılması
        // / ANR). Sıra korunur: tek iş parçacıklı kuyruk.
        // The peer of THIS message: the screen may switch chats before the
        // queued task runs, and the receipt must not go to the next peer.
        val peer = peerDeviceFingerprint
        netPack.execute {
            try {
                P2PLib.sendSeenReceipt(peer, messageId, null)
            } catch (e: Exception) {
            }
        }
    }

    /** Durum DEĞİŞTİĞİNDE tek bir paket gönderilir — her tuş vuruşunda
     *  değil (bkz. `isTypingSent`). */
    private fun sendTypingState(isTyping: Boolean) {
        if (isTypingSent == isTyping) return
        isTypingSent = isTyping
        // bkz. `markSeen`.
        val peer = peerDeviceFingerprint
        netPack.execute {
            try {
                P2PLib.sendTypingIndicator(peer, isTyping)
            } catch (e: Exception) {
            }
        }
    }

    // ---------------------------------------------------------------
    // Kaydırma / "en alta in" düğmesi
    // ---------------------------------------------------------------

    private fun isRecyclerNearBottom(): Boolean {
        if (localMessages.isEmpty()) return true
        val lm = recycler.layoutManager as? LinearLayoutManager ?: return true
        val lastVisible = lm.findLastVisibleItemPosition()
        return lastVisible == RecyclerView.NO_POSITION || lastVisible >= localMessages.size - 2
    }

    /** Yeni bir mesaj geldi: kullanıcı zaten en alttaysa takip et, yukarıda
     *  geçmişe bakıyorsa yerini BOZMA — sadece FAB'ı yanıp söndür. */
    private fun onNewIncomingItemAdded() {
        if (isRecyclerNearBottom()) {
            scrollToLastSettled()
        } else {
            blinkScrollToBottomFab()
        }
    }

    /**
     * "son 15 dakikada mesaj olmayan bir
     * sohbete mesaj atıldığında hafif bir parçacık typhoon efekti".
     *
     * Kontrol EKLEMEDEN SONRA yapılıyor: en yeni mesajla ondan bir öncekinin
     * arasındaki boşluğa bakıyoruz. Böylece her çağıran tarafın ekleme
     * ÖNCESİNDE ayrıca bir "sessiz miydi" bayrağı taşıması gerekmiyor —
     * tek bir çağrı noktası yetiyor.
     *
     * Sohbetin İLK mesajında oynamaz (kıyaslanacak bir önceki yok): boş bir
     * sohbeti açıp ilk mesajı yazmak "uyandırma" anı değil.
     */
    private fun maybePlayTyphoonEffect() {
        val newest = localMessages.lastOrNull() ?: return
        val previous = localMessages.getOrNull(localMessages.size - 2) ?: return
        if (newest.orderKey - previous.orderKey < TYPHOON_QUIET_WINDOW_MS) return
        // `post`: balon bu karede henüz ölçülmedi, konumu ancak yerleşimden
        // sonra biliniyor.
        // Huni artık görünümün TAMAMINI kaplıyor (bkz. TyphoonParticleView
        // `burst`) — balonun konumunu hesaplamaya gerek yok.
        typhoonEffect.burst(
            com.google.android.material.color.MaterialColors.getColor(
                // `colorPrimary` DEĞİL: bu temada o, balonlarda görünen
                // turuncunun koyu/mat karşılığı ve parçacıklar koyu zeminde
                // sönük çıkıyordu. Kullanıcının "accent" diye GÖRDÜĞÜ renk
                // balonların zemini, yani `colorPrimaryContainer`.
                typhoonEffect, com.google.android.material.R.attr.colorPrimaryContainer
            )
        )
    }

    /**
     * Spec dışı, kullanıcı isteği ("alt bar ve alıntı pilinin dışı şeffaf
     * olsun, chat yanlardan ve alttan görünsün"): liste artık ekranın
     * altına kadar uzanıyor ve çubuk onun üstünde yüzüyor (bkz.
     * activity_chat.xml). Mesajların çubuğun ALTINDA kaybolmaması için
     * listeye, çubuğun GERÇEK yüksekliği kadar alt dolgu veriliyor —
     * `clipToPadding=false` sayesinde içerik kaydırırken çubuğun arkasından
     * geçer ama dinlenme konumunda üstünde durur.
     *
     * Sabit bir dp YETMEZ: çubuk çok satırlı yazarken büyüyor, alıntı pili
     * açılıp kapanıyor. Bu yüzden ikisinin de yerleşimi her değiştiğinde
     * yeniden hesaplanıyor.
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
        // "en alttaysak yeni
        // mesajla otomatik aşağı kaysın"): `scrollToPosition` DOĞRUDAN
        // çağrılınca güvenilmez — yeni eklenen satır o anda henüz
        // ölçülmemiş oluyor ve kaydırma ya hiç olmuyor ya da eksik
        // kalıyordu. `post`: yerleşim bittikten sonra; ikinci `post`:
        // uzun bir balonun alt kenarı hâlâ ekranın altında kalıyorsa
        // kalan farkı kapatır (aynı iki geçişli düzeltme klavye
        // telafisinde de kullanılıyor, bkz. util.KeyboardInsets).
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

    /** çözülmüş bir eki "İndirilenler/P2P" klasörüne kopyalar.
     *  API 29+ MediaStore (izin gerekmez), altında doğrudan dosya yazımı
     *  (WRITE_EXTERNAL_STORAGE, bkz. onCreate'teki izin isteği). */
    /**
     * Karsi tarafin gonderdigi dosya adini, bir DOSYA ADI olarak
     * kullanmadan once zararsiz hale getirir.
     *
     * Cekirdek tarafinda da ayni temizlik yapiliyor (bkz. Rust
     * `safe_file_name`, `receive_file_offer`) — ama o, bu duzeltmeden SONRA
     * gelen teklifler icin gecerli. `files` tablosunda ONCEDEN duran
     * satirlar hala ham adi tasiyor, ve asagidaki API 26-28 kolu
     * `File(p2pDir, displayName)` yapiyor: `"../../DCIM/Camera/IMG_0001.jpg"`
     * gibi bir ad paylasilan depolamada KEYFI bir yola yazardi.
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
        val base = cleaned.ifEmpty { "file" }
        // Cap by UTF-8 bytes (200) at a char boundary; keep the extension.
        if (base.toByteArray().size <= 200) return base
        val dot = base.lastIndexOf('.')
        val ext = if (dot > 0 && base.length - dot <= 16) base.substring(dot) else ""
        var stem = if (ext.isEmpty()) base else base.substring(0, dot)
        while (stem.isNotEmpty() && (stem + ext).toByteArray().size > 200) {
            stem = stem.dropLast(if (stem.length > 1 && Character.isLowSurrogate(stem.last())) 2 else 1)
        }
        return stem.ifEmpty { "file" } + ext
    }

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
                // Galeri/dosya yöneticisinin yeni dosyayı hemen görmesi için.
                MediaScannerConnection.scanFile(this, arrayOf(dest.absolutePath), arrayOf(mimeType), null)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * bir ek balonuna basılı tutulunca (SADECE tamamlanmışsa,
     * bkz. SimpleChatAdapter) "İndirilenler/P2P"ye kaydet seçeneğini
     * gösterir.
     *
     * Kullanıcı isteğiyle KALDIRILDI: önceden karşı taraftan gelen (bizim
     * göndermediğimiz) bir ek için, kaydetmeden önce göndericiye bir
     * `SaveRequest` gönderip Evet/Hayır onayını BEKLİYORDU (bkz. eski
     * `showSaveRequestDialog`/`handleSaveResponse`, Rust
     * `MessageContent::SaveRequest`/`SaveApproval`) — dosya zaten uçtan uca
     * şifreli olarak indirilip yerel cihazda duruyorken, onu KENDİ
     * "İndirilenler" klasörüne kopyalamak için ayrıca göndericiden izin
     * istemenin (asenkron, karşı taraf çevrimdışıysa hiç gelmeyen bir ek
     * round-trip) kullanıcı deneyimi açısından değeri yoktu. Artık
     * `item.isMine`'dan BAĞIMSIZ, doğrudan yerelde kaydedilir.
     */
    private fun onAttachmentLongClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        // "Başka bir uygulamayla aç" eklendi —
        // `onAttachmentClicked`'ın tek dokunuşu (foto/video için uygulama
        // içi MediaViewerActivity'ye, diğerleri için doğrudan sistem
        // varsayılanına) gider; bu SEÇENEK yerine `Intent.createChooser`
        // ile HER ZAMAN uygulama seçici gösterir.
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

    /** Tek dokunuş: indirilmemişse indir, tamamlanmışsa aç. İndirme
     *  sürerken dokunmak no-op'tur. */
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
                // Zaten indiriliyor — dokunmak bir şey yapmaz.
            }
        }
    }

    /** Foto/video uygulama İÇİNDEKİ görüntüleyiciye (MediaViewerActivity),
     *  diğer türler sistem varsayılanına gider. */
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
     * kameradan gelen kare. `onFilePicked`
     * ile AYNI gönderme yolu, tek farkı kaynağın bir `content://` URI
     * yerine ZATEN bellekte duran JPEG baytları olması — bu yüzden ayrı
     * bir isim/boyut sorgusu (SAF `OpenableColumns`) yok, ad da
     * çekim anından üretiliyor.
     *
     * Önbellekteki geçici dosya (`cacheDir/outgoing`) Rust çekirdeği ek
     * gönderirken gerçek bir dosya YOLU istediği için gerekli ve
     * `finally`'de siliniyor — fotoğraf sistem galerisine/paylaşılan
     * depolamaya HİÇ yazılmıyor (kullanıcı isteği: "diske kaydedilmeden").
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
                                // gönderirken yazılan açıklama hemen görünsün.
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
     * SAF (`OpenDocument`) ile seçilen dosya önce uygulamanın kendi
     * önbelleğine kopyalanır (`content://` bir yol değildir, Rust tarafı
     * gerçek bir dosya yolu ister), sonra `prepareAndSendFile` ile
     * şifrelenip teklif edilir.
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
                } ?: throw java.io.IOException("Dosya açılamadı")

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
                                // gönderirken yazılan açıklama hemen görünsün.
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

    /** Küçük bir 480p/%85 JPEG kapak — `FileOffer` ile birlikte gider, alıcı
     *  TAM dosyayı indirmeden önizleme görebilsin diye. */
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
    // Geçmiş
    // ---------------------------------------------------------------

    /** Karşı taraftan gelen açılış senkronu (bkz. `requestHistorySync`) —
     *  SADECE yerelde olandan DAHA YENİ satırlar eklenir. */
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
        // İKİ CİHAZLI TESTTE (2026-09-06) bulundu: eski filtre SADECE
        // `timestamp > latestLocal` idi. Ama `timestamp` yerel arşivleme
        // anıdır — karşı taraf mesajı BİZDEN sonra arşivlediği için, karşı
        // tarafın senkron kopyasının timestamp'i bizim yerel kopyamızınkinden
        // DAHA BÜYÜK; sonuç: gönderdiğimiz mesajlar, zaten listede olsa bile
        // (aynı `message_id`) senkron yanıtından bir kez daha ekleniyordu
        // (gönderende çift balon). Artık `message_id` bazında da eleniyor.
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
    // Düzenle / sil / kopyala / yanıtla
    // ---------------------------------------------------------------

    private fun showEditDeleteDialog(item: SimpleChatAdapter.Item) {
        if (!item.isMine) {
            // Karşı tarafın mesajını düzenleyemeyiz/silemeyiz (karşı taraf
            // zaten reddederdi, bkz. Rust `message_owned_by_sender`) — ama
            // tepki bırakabiliriz.
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
     * tepki pill'ine dokununca "kim ne attı"
     * listesi (WhatsApp deseni).
     *
     * Kimlikler ağdan `identity_id` olarak geliyor; isimler burada, cihazın
     * KENDİ kişi listesinden çözülüyor — protokole isim koymuyoruz (bir
     * gönderici istediği ismi iddia edebilirdi). Tanınmayan bir kimlik
     * kısaltılmış kimliğiyle gösterilir; kendi kimliğim "Sen" olur.
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
                // Kişi listesi okunamazsa isimler kısaltılmış kimliğe düşer.
            }
            val rows = mutableListOf<String>()
            var myRow = -1
            try {
                val array = JSONArray(raw)
                for (i in 0 until array.length()) {
                    val entry = array.getJSONObject(i)
                    val identityId = entry.optString("identity_id")
                    val who = when {
                        // bkz. Rust `list_reactions` — "benim mi" kararı
                        // kimliğe sahip olan çekirdekte veriliyor.
                        entry.optBoolean("is_me", false) -> getString(R.string.lbl_you)
                        names[identityId]?.isNotBlank() == true -> names[identityId]!!
                        else -> identityId.take(8)
                    }
                    if (entry.optBoolean("is_me", false)) myRow = rows.size
                    rows.add("${entry.optString("emoji")}   $who")
                }
            } catch (e: Exception) {
                // Bozuk JSON: boş liste gösterilir, çökmez.
            }
            withContext(Dispatchers.Main) {
                if (rows.isEmpty()) return@withContext
                AlertDialog.Builder(this@ChatActivity)
                    .setTitle(R.string.title_reactions)
                    .setItems(rows.toTypedArray()) { _, which ->
                        // Kendi satırıma dokunmak tepkimi kaldırır (boş emoji).
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
     * Spec dışı, kullanıcı isteği (WhatsApp tarzı tepkiler). JNI çağrısı
     * ağa çıkabildiğinden ana thread DIŞINDA; dönen değer o mesajın GÜNCEL
     * tepki özeti (bkz. Rust `react_to_message`), doğrudan pill'e yazılır.
     * Karşı tarafa ulaşması `needs_delivery_confirmation` ile garanti —
     * burada beklemeye gerek yok.
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

    /** balonu SAĞA kaydırmak
     *  o mesaja yanıt başlatır. Kaydırma `REPLY_SWIPE_MAX_DP` ile sınırlı,
     *  balon geri yerine oturur (gerçek bir "swipe to dismiss" değil). */
    /** bkz. `setupSwipeToReply`/`onSelectedChanged` — kaydırma BAŞLADIĞINDA
     *  yakalanan hedef mesajın kararlı kimliği. */
    private var swipeStartMessageId: String? = null

    private fun setupSwipeToReply() {
        val replyIcon: Drawable? = ContextCompat.getDrawable(this, R.drawable.ic_reply)
        val maxSwipePx = REPLY_SWIPE_MAX_DP * resources.displayMetrics.density
        val callback = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.RIGHT) {
            /**
             * Kullanıcı raporu: "alıntılama hareketi başka mesajın yanında
             * bitince yanıtlamıyor; swipe'ın BAŞLADIĞI noktaya göre
             * seçilsin". `onSwiped` içindeki `adapterPosition`, hareketin
             * BİTTİĞİ andaki konumdur — hareket sürerken yeni bir mesaj
             * gelirse (canlı sohbette sık) tüm konumlar kayar ve o indeks
             * artık BAŞKA bir mesajı gösterir; liste o arada yeniden
             * bağlandıysa `NO_POSITION` dönüp hiç yanıtlamaz. Bu yüzden
             * hedefi hareketin BAŞINDA, kararlı `messageId` olarak
             * yakalıyoruz — indeks kaysa da doğru mesaj yanıtlanır.
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
                // Balonu geri yerine oturt — bu bir "kaydırıp sil" değil.
                // Değişiklik animasyonu kapalıyken (bkz. `supportsChangeAnimations`)
                // `notifyItemChanged` AYNI görünümü yeniden bağlar ve ItemTouchHelper
                // o görünümü "kaydırılmış" olarak tutup her karede kaydırılmış
                // konumda çizmeye devam eder (eskiden eski görünüm ayrıldığı için
                // temizleniyordu). Helper'ı ayırıp yeniden bağlamak bu durumu
                // temizler ve ötelemeyi sıfırlar.
                recycler.post {
                    swipeHelper.attachToRecyclerView(null)
                    swipeHelper.attachToRecyclerView(recycler)
                }
                if (position != RecyclerView.NO_POSITION) adapter.notifyItemChanged(position)
                // bkz. `onSelectedChanged` — hedef, hareketin BAŞLADIĞI mesaj.
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

    /** Ek balonlarında metin yok — dosya adı gösterilir. */
    private fun replyPreviewFor(item: SimpleChatAdapter.Item): String {
        val attachment = item.attachment
        return if (attachment != null) {
            getString(R.string.lbl_attachment_reply_preview, attachment.fileName)
        } else {
            com.p2p.messenger.util.Quote.ownText(com.p2p.messenger.util.Forward.strip(item.text)).takeWholeChars(REPLY_PREVIEW_MAX_CHARS)
        }
    }

    /** Alıntı kutusuna dokunulunca yanıtlanan mesaja kaydırır ve kısa süre
     *  vurgular. Hedef henüz yüklenmemişse (eski geçmiş) uyarır. */
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

    /** "Failed" bir mesajı AYNI balonda
     *  yeniden gönder — ikinci bir balon oluşturmaz (bkz.
     *  SimpleChatAdapter.retryMessage). */
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
            val merged = withContext(Dispatchers.IO) {
                val textItems = mutableListOf<SimpleChatAdapter.Item>()
                val json = try {
                    P2PLib.getMessageHistory(targetPeer, HISTORY_LOAD_LIMIT)
                } catch (e: Exception) {
                    null
                }
                val array = try {
                    if (json != null) JSONArray(json) else null
                } catch (e: Exception) {
                    null
                }
                // bkz. `loadHistoryIfAvailable` altındaki "seen" replay notu —
                // hangi mesajların (arşivlenmiş) görüldü bilgisi taşıdığı
                // burada (IO thread) toplanır, SeenByViewer'ın kendisi (View
                // okuması gerektirir) ana thread'de kuruluyor.
                val seenMessageIds = mutableListOf<String>()
                if (array != null) {
                    for (i in 0 until array.length()) {
                        val obj = array.getJSONObject(i)
                        textItems.add(itemFromHistoryJson(obj))
                        val messageId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
                        val seenByRaw = obj.optString("seen_by", "[]").ifEmpty { "[]" }
                        if (messageId != null && seenByRaw != "[]") {
                            seenMessageIds.add(messageId)
                        }
                    }
                }
                // geçmişte gönderilmiş/alınmış dosya ekleri önceden
                // hiç yeniden yüklenmiyordu (sadece metin mesajları) — artık
                // `listAttachments` ile aynı anda çekilip zaman damgasına göre
                // metin mesajlarıyla ARAYA SERPİŞTİRİLİYOR, tıpkı canlı
                // sohbette olduğu gibi kronolojik sırada görünsünler diye.
                val attachmentItems = mutableListOf<SimpleChatAdapter.Item>()
                val attachmentsJson = try {
                    P2PLib.listAttachments(targetPeer)
                } catch (e: Exception) {
                    null
                }
                val attachmentsArray = try {
                    if (attachmentsJson != null) JSONArray(attachmentsJson) else null
                } catch (e: Exception) {
                    null
                }
                if (attachmentsArray != null) {
                    for (i in 0 until attachmentsArray.length()) {
                        val obj = attachmentsArray.getJSONObject(i)
                        val previewHex = obj.optString("preview_hex", "")
                        val previewJpeg = if (previewHex.isNotEmpty() && previewHex != "null") hexToBytes(previewHex) else null
                        attachmentItems.add(
                            SimpleChatAdapter.Item(
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
                                    previewJpeg = previewJpeg,
                                    durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it },
                                    isSticker = obj.optBoolean("sticker", false)
                                ),
                                // arşivden geri
                                // yüklenen ekler de açıklamalarını ve yanıt
                                // bağlamını korur (bkz. Rust `files` tablosu).
                                caption = obj.optString("caption", ""),
                                replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null },
                                replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
                            )
                        )
                    }
                }
                (textItems + attachmentItems).sortedBy { it.orderKey } to seenMessageIds
            }
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
                // Geçmiş yüklemesi bir canlı mesajdan SONRA biterse sona eklemek
                // canlı mesajı eski geçmişin üstüne, ekran dışına itiyordu (cihazda
                // görüldü) — gönderim sırasına göre yeniden diz.
                localMessages.sortWith(compareBy { it.orderKey })
                resolveReplyLabels()
                adapter.notifyDataSetChanged()
                // bkz. `dedupeByMessageId` — loadHistory/syncMissed yarışı
                // aynı message_id'yi iki kez ekleyebiliyor.
                adapter.dedupeByMessageId()
                recycler.scrollToPosition(localMessages.size - 1)
            }
            // "seen mekanizması ... hem
            // dm hem gruplarda güvenilir değil"): önceden "görüldü" tiki
            // SADECE sohbet ekranı açıkken canlı gelen olayla işaretleniyordu
            // — ekran kapalıyken görülen bir mesaj, sohbet yeniden açıldığında
            // hiç görülmemiş gösteriliyordu (Rust `message_seen` tablosunda
            // gerçekte duruyordu, sadece burada okunmuyordu). Mesajlar
            // adaptöre eklendikten SONRA replay edilir — `applySeen` içindeki
            // `indexOfMessageId` henüz eklenmemiş bir satır için -1 döner.
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

    /** bkz. `loadHistoryIfAvailable`/`loadOlderHistory`/`applyOlderHistory`
     *  — üç kaynaktan gelen (yerel ilk yükleme, yerel eski sayfa, ağdan
     *  gelen eski sayfa) JSON satırı AYNI şekilde ayrıştırılır; "status"
     *  alanı ağ yolunda hiç taşınmadığından eksik olabilir, bu durumda
     *  (eski satırlar için de geçerli olan) "sent" varsayımına düşer. */
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
            // İki cihazlı test (2026-09-07): 1:1 geçmiş yüklemesi tepki özetini
            // OKUMUYORDU (grup yolu `itemFromGroupHistoryJson` okuyor) — tepki
            // DB'de kalıcı (`message_reactions`) ve canlı olayda görünüyordu ama
            // sohbet yeniden açılınca / uygulama yeniden başlayınca balondan
            // kayboluyordu. `load_message_history` zaten `reactions` alanını
            // JSON'a koyuyor (bkz. Rust `reactions_summary`).
            reactions = obj.optString("reactions", "")
        )
    }

    /** Alıntı kutusundaki "kime yanıt" etiketi — 1:1'de sadece iki
     *  olasılık var: ben ya da karşı taraf. */
    private fun resolveReplyLabel(replyToMessageId: String?): String? {
        if (replyToMessageId == null) return null
        val target = localMessages.firstOrNull { it.messageId == replyToMessageId } ?: return null
        return if (target.isMine) getString(R.string.lbl_you) else txtToolbarTitle.text?.toString()
    }

    /** Yeni satırlar eklendikten sonra: bir yanıtın hedefi ancak ŞİMDİ
     *  yüklenmiş olabilir (ör. eski sayfa geldi) — etiketleri tazele. */
    private fun resolveReplyLabels() {
        for (item in localMessages) {
            if (item.replyToMessageId != null) {
                item.replyToSenderLabel = resolveReplyLabel(item.replyToMessageId)
            }
        }
    }

    /**
     * Sonsuz kaydırma: YEREL arşivden bir sayfa. Ağa hiçbir şey gitmez.
     */
    private fun loadOlderHistory() {
        if (isLoadingOlderHistory || noMoreOlderHistory || localMessages.isEmpty()) return
        isLoadingOlderHistory = true
        // Text rows only: the first load mixes the newest texts with EVERY
        // attachment ever sent, so one old photo used to move the cursor
        // past all the texts between it and the oldest loaded one.
        val beforeTimestamp = localMessages.filter { it.attachment == null }.minOfOrNull { it.timestamp }
            ?: localMessages.minOf { it.timestamp }
        val beforeAttachment = localMessages.filter { it.attachment != null }.minOfOrNull { it.timestamp } ?: Long.MAX_VALUE
        val peer = peerDeviceFingerprint
        // the archive query takes the core lock; scrolling must not wait for it.
        lifecycleScope.launch {
            val localOlder = withContext(Dispatchers.IO) {
                try {
                    val json = P2PLib.getMessageHistoryBefore(peer, beforeTimestamp, OLDER_HISTORY_PAGE_SIZE)
                    val array = JSONArray(json)
                    (0 until array.length()).map { itemFromHistoryJson(array.getJSONObject(it)) }
                } catch (e: Exception) {
                    null
                }
            }
            // Attachments older than the oldest loaded one (own cursor).
            val olderAttachments = withContext(Dispatchers.IO) {
                try {
                    val array = JSONArray(P2PLib.listAttachmentsBefore(peer, beforeAttachment, OLDER_HISTORY_PAGE_SIZE))
                    (0 until array.length()).map { attachmentItemFromJson(array.getJSONObject(it)) }
                } catch (e: Exception) {
                    emptyList()
                }
            }
            if (peer == peerDeviceFingerprint) {
                val page = (localOlder ?: emptyList()) + olderAttachments
                if (page.isNotEmpty()) prependOlderMessages(page)
                // an empty page from the local archive is the end of it.
                else if (localOlder != null) noMoreOlderHistory = true
            }
            // Local archive only: scrolling sends nothing to the network.
            isLoadingOlderHistory = false
        }
    }

    /** Item from one `listAttachments`-shaped JSON row (older-page path). */
    private fun attachmentItemFromJson(obj: JSONObject): SimpleChatAdapter.Item {
        val previewHex = obj.optString("preview_hex", "")
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

    /** bkz. `loadOlderHistory` — karşı taraftan gelen "older_history" ağ
     *  yanıtı. Boş dizi dönerse (ne yerelde ne karşı tarafta daha eski
     *  mesaj kalmadı) `noMoreOlderHistory` işaretlenir, bu sohbet için
     *  artık tekrar denenmez. */
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

    /** Eski sayfa sonuçlarını listenin BAŞINA ekler — hem yerel hem ağ
     *  yolunda ortak. `message_id` eşleşmesiyle zaten ekranda olan bir
     *  mesajın TEKRAR eklenmesini önler (ör. yerel sayfa ile ağ yanıtı
     *  aynı satırları içeriyorsa). */
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
        // bkz. `resolveReplyLabels` — eski sayfa, daha önce görülmemiş bir
        // yanıt zinciri getirmiş olabilir (ör. yanıtlanan mesaj da bu
        // sayfadaydı).
        resolveReplyLabels()
        adapter.notifyItemRangeInserted(0, fresh.size)
    }

    // ---------------------------------------------------------------
    // Sohbet içi arama
    // ---------------------------------------------------------------

    /**
     * sohbet içi mesaj arama. Toolbar'daki
     * arama simgesi (bkz. `onOptionsItemSelected`) bu satırı aç/kapatır;
     * arama SADECE o an yüklü (`localMessages`) mesajlarda çalışır — henüz
     * yüklenmemiş eski geçmiş için ayrıca bir ağ isteği tetiklenmez (bkz.
     * `loadOlderHistory` — kullanıcı yukarı kaydırdıkça zaten daha fazla
     * geçmiş yüklenir).
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

    /** Silinmiş satırlar ve ekler aramaya girmez. Sonuçlar EN YENİDEN
     *  başlar (kullanıcı genelde son konuşmayı arar). */
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
            // bkz. AppRestarter — Tor devresi/ağ yığını sadece süreç
            // yeniden başlayınca temiz kurulabiliyor.
            R.id.action_tor_reconnect -> {
                AppRestarter.confirmAndRestart(this)
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    // ---------------------------------------------------------------
    // Yaşam döngüsü
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
        // "görüldü" güvenilirlik + hız (2026-09-07): sohbeti AÇAR AÇMAZ karşı
        // tarafa "şu ana kadar okudum" sınırını bildir. Eskiden sadece
        // `onPause`'da ve yalnızca kardeş cihazlara gidiyordu → store-forward
        // ile gelip geçmiş olarak yüklenen mesajlar için makbuz HİÇ gitmezdi.
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

    /** Karşı tarafa "buraya kadar okudum" sınırını yollar — debounce'lu
     *  (tek pakette toplanır; Rust tarafı bekleyen eski sınırı iptal eder,
     *  bkz. `sync_read_state`). Sohbet açılışı / `onResume` / canlı gelen
     *  mesaj sonrası çağrılır. */
    private fun scheduleReadWatermark() {
        if (!AppLock.isUnlocked()) return
        readWatermarkHandler.removeCallbacks(readWatermarkRunnable)
        readWatermarkHandler.postDelayed(readWatermarkRunnable, 700L)
    }

    /** Ekran arka plandayken gelen mesajlar `messageListener` dinlemediği
     *  için ekrana düşmedi; arşivden okunup eksikler tamamlanır. Yarış
     *  koşulu için bkz. `loadHistoryIfAvailable` aynı not (ikisi de IO'da
     *  çalışır ve hangisinin önce biteceği belli değildir). */
    private fun syncMissedMessages() {
        val targetPeer = peerDeviceFingerprint
        // Runs on every resume: rows already on screen keep their decoded
        // preview (see `refreshFrom`) instead of decoding it from hex again.
        val knownIds = localMessages.mapTo(HashSet()) { it.messageId }
        lifecycleScope.launch {
            val missed = withContext(Dispatchers.IO) {
                val textItems = mutableListOf<SimpleChatAdapter.Item>()
                val json = try {
                    P2PLib.getMessageHistory(targetPeer, HISTORY_LOAD_LIMIT)
                } catch (e: Exception) {
                    null
                }
                val array = try {
                    if (json != null) JSONArray(json) else null
                } catch (e: Exception) {
                    null
                }
                // bkz. `loadHistoryIfAvailable` altındaki "seen" replay notu —
                // AYNI desen, bu fonksiyon `onResume`'da (arka plandan
                // dönüşte) çalıştığından pratikte EN ÇOK vurulan yol.
                val seenMessageIds = mutableListOf<String>()
                if (array != null) {
                    for (i in 0 until array.length()) {
                        val obj = array.getJSONObject(i)
                        textItems.add(itemFromHistoryJson(obj))
                        val messageId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
                        val seenByRaw = obj.optString("seen_by", "[]").ifEmpty { "[]" }
                        if (messageId != null && seenByRaw != "[]") {
                            seenMessageIds.add(messageId)
                        }
                    }
                }
                val attachmentItems = mutableListOf<SimpleChatAdapter.Item>()
                val attachmentsJson = try {
                    P2PLib.listAttachments(targetPeer)
                } catch (e: Exception) {
                    null
                }
                val attachmentsArray = try {
                    if (attachmentsJson != null) JSONArray(attachmentsJson) else null
                } catch (e: Exception) {
                    null
                }
                if (attachmentsArray != null) {
                    for (i in 0 until attachmentsArray.length()) {
                        val obj = attachmentsArray.getJSONObject(i)
                        val fileId = obj.optString("file_id")
                        val previewHex = obj.optString("preview_hex", "")
                        val previewJpeg = if (fileId !in knownIds && previewHex.isNotEmpty() && previewHex != "null") hexToBytes(previewHex) else null
                        attachmentItems.add(
                            SimpleChatAdapter.Item(
                                messageId = fileId,
                                text = "",
                                isMine = obj.optString("direction") == "sent",
                                timestamp = obj.optLong("created_at", System.currentTimeMillis()),
                                attachment = SimpleChatAdapter.AttachmentInfo(
                                    fileId = fileId,
                                    fileName = obj.optString("file_name"),
                                    mimeType = obj.optString("mime_type"),
                                    totalSize = obj.optLong("total_size"),
                                    status = parseAttachmentStatus(obj.optString("status")),
                                    bytesDone = obj.optLong("bytes_transferred"),
                                    previewJpeg = previewJpeg,
                                    durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it },
                                    isSticker = obj.optBoolean("sticker", false)
                                ),
                                // arşivden geri
                                // yüklenen ekler de açıklamalarını ve yanıt
                                // bağlamını korur (bkz. Rust `files` tablosu).
                                caption = obj.optString("caption", ""),
                                replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null },
                                replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
                            )
                        )
                    }
                }
                (textItems + attachmentItems).sortedBy { it.orderKey } to seenMessageIds
            }
            if (peerDeviceFingerprint != targetPeer) return@launch
            val (missedItems, seenMessageIds) = missed
            val existingIds = localMessages.mapTo(mutableSetOf()) { it.messageId }
            val fresh = missedItems.filter { it.messageId !in existingIds }
            if (adapter.refreshFrom(missedItems)) resolveReplyLabels()
            if (fresh.isNotEmpty()) {
                localMessages.addAll(fresh)
                // Geçmiş yüklemesi bir canlı mesajdan SONRA biterse sona eklemek
                // canlı mesajı eski geçmişin üstüne, ekran dışına itiyordu (cihazda
                // görüldü) — gönderim sırasına göre yeniden diz.
                localMessages.sortWith(compareBy { it.orderKey })
                resolveReplyLabels()
                adapter.notifyDataSetChanged()
                adapter.dedupeByMessageId()
                onNewIncomingItemAdded()
            }
            // bkz. `loadHistoryIfAvailable` altındaki AYNI "seen" replay notu.
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
        // Bu sohbeti okuduğumuzu kardeş cihazlara VE karşı tarafa bildir
        // (bkz. `sync_read_state` — artık iki hedef). Debounce'lu bekleyen
        // varsa iptal edip HEMEN kesin bir tane yolla.
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
        backgrounded = true // #86: the recording keeps running (service has the microphone type)
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
