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
import com.p2p.messenger.util.ReactionPicker
import com.p2p.messenger.util.ConnectionStatus
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.KeyboardInsets
import com.p2p.messenger.util.OutgoingMedia
import com.p2p.messenger.util.ReplyIsland
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
 * Spec 5 (Grup mesajlaşma) — gerçek grup sohbet ekranı. Önceden
 * `sendGroupMessage` her üyeye ayrı ayrı normal bir 1:1 mesaj olarak
 * gönderiliyordu AMA alıcı tarafta bunun bir grup mesajı olduğunu belirten
 * hiçbir bilgi yoktu — gelen mesaj göndericinin 1:1 sohbetine karışıyordu,
 * grup diye ayrı bir yer yoktu. Artık `MessageContent::Text.group_id`
 * (bkz. packet.rs) sayesinde `receive_message` bunu "group_message" olayı
 * olarak ayırt edip buraya yönlendirebiliyor.
 *
 * Hata düzeltmesi ("grup geçmişi bazen kalıcı olmuyor"): grup mesajları
 * artık `archive_group_message` ile (group_id'ye göre, TEK satır) yerelde
 * şifreli kalıcı kılınıyor ve bu ekran `bindToIntent` içinde
 * `loadGroupHistoryIfAvailable` ile bu geçmişi yükler (1:1 ChatActivity ile
 * aynı desen). Bilinen kalan sınır: bu, cihazınızın kendi arşivi — bir üye
 * siz çevrimdışıyken gönderilen bir mesajı (bu cihaza hiç ULAŞMAMIŞSA)
 * geriye dönük olarak senkronlamaz; DM'lerdeki `HistorySyncRequest` gibi bir
 * ağ-üzerinden-geçmiş-isteme mekanizması gruplar için henüz yok.
 */
class GroupChatActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_GROUP_ID = "group_id"
        const val EXTRA_GROUP_NAME = "group_name"
        /** bkz. SettingsFragment AVATAR_MAX_DIMENSION aynı standart. */
        private const val AVATAR_MAX_DIMENSION = 720
        private const val AVATAR_JPEG_QUALITY = 85
        /** bkz. ChatActivity aynı sabit. */
        private const val HISTORY_LOAD_LIMIT = 200
        /** bkz. `resolveContactByIdentity` dokümantasyonu. */
        private const val CONTACT_CACHE_TTL_MS = 5000L
        /** bkz. ChatActivity aynı sabitler (sonsuz kaydırma). */
        private const val OLDER_HISTORY_PAGE_SIZE = 50
        private const val OLDER_HISTORY_REPLY_WAIT_MS = 15_000L
        private const val LOAD_OLDER_HISTORY_THRESHOLD = 3
        /** bkz. ChatActivity aynı sabitler (grup ekleri). */
        private const val MAX_ATTACHMENT_SIZE = 4L * 1024 * 1024 * 1024
        /** bkz. ChatActivity AYNI sabit. */
        private const val TYPHOON_QUIET_WINDOW_MS = 15 * 60 * 1000L

        private const val PREVIEW_MAX_DIMENSION = 480
        private const val PREVIEW_JPEG_QUALITY = 85
        /** bkz. ChatActivity `ownStatusPollRunnable` aynı sabit. */
        private const val OWN_STATUS_POLL_INTERVAL_MS = 2000L
        /** bkz. ChatActivity aynı sabitler (basılı tut/kaydet sesli mesaj —
         *  kullanıcı isteği: grup sohbetinde de destekleniyor). */
        private const val RECORDING_MIN_DURATION_MS = 500L
        private const val RECORDING_CANCEL_SWIPE_DP = 120f
        private const val VOICE_PLAYBACK_TICK_MS = 200L
        /** bkz. ChatActivity aynı sabitler (WhatsApp tarzı "sağa kaydırıp
         *  yanıtla" — kullanıcı isteği: grup sohbetinde de destekleniyor). */
        private const val REPLY_PREVIEW_MAX_CHARS = 120
        private const val REPLY_SWIPE_MAX_DP = 72f
        private const val REPLY_HIGHLIGHT_DURATION_MS = 1500L
        /** bkz. ChatActivity aynı sabitler ("yazıyor..." göstergesi —
         *  kullanıcı isteği: grup sohbetinde de destekleniyor). */
        private const val TYPING_IDLE_TIMEOUT_MS = 3000L
        private const val TYPING_INDICATOR_TIMEOUT_MS = 8000L
    }

    private lateinit var groupId: String
    private lateinit var whiteboard: WhiteboardPanel
    private val localMessages = mutableListOf<SimpleChatAdapter.Item>()
    private lateinit var adapter: SimpleChatAdapter
    private lateinit var recycler: RecyclerView
    private lateinit var txtToolbarTitle: TextView
    private lateinit var imgToolbarAvatar: ImageView
    /** bkz. util.ConnectionStatus — BU cihazın genel bağlantı durumu. */
    private lateinit var txtOwnConnectionStatus: TextView
    /** Spec dışı, kullanıcı isteği: bu cihazın kendi bağlantı durumu için
     *  renkli nokta — bkz. ChatActivity aynı desen, `util.PulsingStatusDot`.
     *  Grup sohbetinde tek bir "karşı taraf" kavramı olmadığından SADECE
     *  bu (kendi durumumuz), ChatActivity'deki `dotPeerStatus`'un karşılığı
     *  YOK (bkz. `layoutToolbarSubtitleRow` gizleme notu). */
    private lateinit var dotOwnStatus: View
    private lateinit var ownStatusDot: PulsingStatusDot
    /** Spec dışı, kullanıcı isteği: gönderim sırasında düğmenin YERİNE
     *  yükleniyor göstergesi + çift dokunuşu engellemek için devre dışı
     *  bırakma — bkz. ChatActivity aynı desen, `sendNewMessage`. */
    /** bkz. ChatActivity `btnSend` aynı notu — bulut logosu maskeli
     *  dairesel `ImageButton`. */
    private lateinit var btnSend: ImageButton
    /** bkz. `maybePlayTyphoonEffect` / ui.TyphoonParticleView. */
    private lateinit var typhoonEffect: TyphoonParticleView
    private lateinit var progressSending: ProgressBar

    /** Spec dışı, kullanıcı isteği (WhatsApp tarzı grup yanıtı — "Sen" mi
     *  yoksa bir üyenin adı mı gösterileceğine karar vermek için, bkz.
     *  `resolveReplyLabel`/`startReply`): bu cihazın HAM `identity_id`'si —
     *  `getIdentityCode`'un aksine biçimlendirilmemiş, `sender_identity_id`
     *  alanlarıyla AYNI biçimde, doğrudan karşılaştırılabilir. `lazy`:
     *  sadece ilk gerçekten ihtiyaç duyulduğunda (JNI çağrısı) çözülür.
     */
    private val ownIdentityId: String? by lazy {
        try {
            P2PLib.getOwnIdentityId().takeUnless { it.startsWith("Error:") }
        } catch (e: Exception) {
            null
        }
    }

    /** bkz. `refreshGroupInfo` — üst çubuğa dokununca açılan grup bilgi
     *  dialogunu doldurmak için son çekilen durum. */
    private var isFounder = false
    private var currentGroupAvatar: ByteArray? = null
    private var memberIdentityIds: List<String> = emptyList()
    /** bkz. `showGroupInfoDialog` — kurucunun kendi satırında "kaldır"
     *  düğmesi gösterilmemesi için (bkz. `list_groups` `founder_identity_id`
     *  alanı). */
    private var founderIdentityId: String = ""
    /** bkz. ChatActivity aynı alanlar (sonsuz kaydırma). */
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
    /** bkz. ChatActivity aynı alanlar (sohbet içi mesaj arama). */
    /** Message ids, not list positions: an older page prepended or a
     *  re-sort moves every position. */
    private var searchMatches: List<String> = emptyList()
    private var currentSearchMatchIndex: Int = -1
    private lateinit var layoutSearchMessages: View
    private lateinit var searchMessagesView: SearchView
    private lateinit var txtSearchMatchCount: TextView

    // --- Spec dışı, kullanıcı isteği (WhatsApp tarzı "sağa kaydırıp
    // yanıtla") — bkz. ChatActivity AYNI alanlar/desen. ---
    private lateinit var layoutReplyPreview: View
    private lateinit var swipeHelper: ItemTouchHelper
    private lateinit var txtReplyPreviewSender: TextView
    private lateinit var txtReplyPreviewText: TextView
    private var activeReplyToMessageId: String? = null
    private var activeReplyToPreview: String? = null
    /** bkz. `startReply`/`Item.senderIdentityId` — yanıtlanan mesajı
     *  gönderenin ham kimliği, gönderim anında `sendGroupMessage`'a
     *  `replyToSenderIdentityId` olarak geçirilir (bkz. `resolveReplyLabel`
     *  yedek çözümleme mekanizması, alıcı taraf yanıtlanan mesajı yerelde
     *  bulamazsa BUNU kullanır). */
    private var activeReplyToSenderIdentityId: String? = null
    private val replyHighlightHandler = Handler(Looper.getMainLooper())

    // Typing indicator (group). Unlike 1:1, several members can type at
    // once, so each is tracked with its own clear-timeout. LinkedHashMap
    // keeps insertion order so the most recent typer's avatar shows.
    private lateinit var layoutTypingIndicator: View
    private lateinit var imgTypingAvatar: ImageView
    private lateinit var txtTypingIndicator: TextView
    private val typingHandler = Handler(Looper.getMainLooper())
    /** fixpass (glm A2): `sendGroupTypingIndicator` / `sendSeenReceipt` JNI
     *  çağrıları çekirdek kilidinde sıraya durabildiğinden ana iş parçacığında
     *  ÇALIŞMAZ — tek iş parçacıklı sıra (CallActivity'deki `DiscardPolicy`
     *  deseni; kapanış sonrası gönderimler sessizce atılır). */
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

    // --- Spec dışı, kullanıcı isteği: basılı tut/kaydet sesli mesaj (grup) —
    // bkz. ChatActivity AYNI alanlar/desen, tek fark gönderim
    // `prepareAndSendGroupFile` ile TÜM üyelere yapılır.
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

    // --- Spec dışı, kullanıcı isteği: sesli mesaj çalma (grup) — bkz.
    // ChatActivity AYNI alanlar/desen (tek paylaşımlı MediaPlayer).
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

    /** group_message_local_id -> (identity_id -> görüntüleyen bilgisi) —
     *  aynı mesajı gören farklı üyeleri biriktirir (bkz. SimpleChatAdapter
     *  applySeen'in TAM liste beklediği notu). */
    private val seenByPerMessage = mutableMapOf<String, MutableMap<String, SimpleChatAdapter.SeenByViewer>>()

    /** bkz. util.ConnectionStatus / ChatActivity `ownStatusPollRunnable`
     *  AYNI desen — BU cihazın genel bağlantı durumu. */
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

    /** `registerForActivityResult` Activity STARTED olmadan ÖNCE
     *  çağrılmalı — bkz. ChatActivity/SettingsFragment aynı notu. */
    private val pickGroupAvatarLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { onGroupAvatarPicked(it) }
    }

    /** bkz. ChatActivity `pickFileLauncher` aynı notu (grup ekleri). */
    private val pickGroupFileLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { picked -> promptAttachmentCaption(offerHiRes = contentResolver.getType(picked)?.startsWith("image/") == true) { caption, hiRes -> onGroupFilePicked(picked, caption, hiRes) } }
    }

    /** bkz. ChatActivity `takePhotoLauncher` aynı notu — anlık çekim +
     *  kırpma, sonuç `CapturedImage` üzerinden. */
    private val takePhotoLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            CapturedImage.take()?.let { jpeg -> promptAttachmentCaption(offerHiRes = true) { caption, hiRes -> onGroupPhotoCaptured(jpeg, caption, hiRes) } }
        }
    }

    private val stickerPicker = StickerPicker(this, { P2PLib.sendGroupSticker(groupId, it) }) { item ->
        adapter.addMessage(item)
        scrollToBottomNow()
    }

    /** `peer` alanı burada anlamlı değil (grup mesajı birden çok 1:1
     *  bağlantı üzerinden pairwise geliyor) — bunun yerine `group_id`'ye
     *  bakıyoruz. Sadece "group_message" tipi olaylarla ilgileniyoruz. */
    private val messageListener: (String) -> Unit = { json ->
        try {
            val obj = JSONObject(json)
            val type = obj.optString("type")
            when {
                type == "stickers_changed" -> runOnUiThread { stickerPicker.reload() }
                type == "group_message" && obj.optString("group_id") == groupId ->
                    runOnUiThread { handleIncomingGroupMessage(obj) }
                // Çoklu-cihaz (spec 1.7): başka bir cihazımdan gönderdiğim grup
                // mesajı — burada da "gönderilen" olarak göster.
                type == "sibling_group_message" && obj.optString("group_id") == groupId ->
                    runOnUiThread { handleSiblingGroupMessage(obj) }
                // "seen" carries no `group_id`: `handleIncomingSeen` keeps it
                // only when it names one of OUR messages in this list.
                type == "seen" && !obj.isNull("group_message_local_id") ->
                    runOnUiThread { handleIncomingSeen(obj) }
                // Toplu görüldü (2026-09-07): bir üye "buraya kadar okudum"
                // sınırı yolladı (bkz. Rust `apply_incoming_read_watermark`).
                type == "seen_bulk" && obj.optString("group_id") == groupId ->
                    runOnUiThread { handleIncomingSeenBulk(obj) }
                // Spec dışı, hata düzeltmesi ("grup fotoğrafı cihazlar
                // arasında senkron olmuyor"): Rust, bir GroupUpdate
                // işlendiğinde (isim/üyelik/AVATAR — bkz. lib.rs
                // process_group_update) bu olayı zaten yayınlıyordu, ama
                // hiçbir Kotlin kodu onu dinlemiyordu. Bu ekran zaten
                // açıkken (ör. kurucu fotoğrafı değiştirirken karşı üye bu
                // sohbete bakıyorsa) üst çubuk avatarı hiç güncellenmiyordu
                // — geri gidip yeniden girmek (yeni bir Intent/bindToIntent)
                // dışında hiçbir yenileme yolu yoktu.
                type == "group_updated" && obj.optString("group_id") == groupId ->
                    runOnUiThread { refreshGroupInfo() }
                // Spec dışı, kullanıcı isteği (sonsuz kaydırma): karşı
                // üyeden gelen eski-sayfa yanıtı — bkz. `loadOlderGroupHistory`.
                type == "older_group_history" && obj.optString("group_id") == groupId ->
                    runOnUiThread { applyOlderGroupHistory(obj) }
                // Spec dışı, kullanıcı isteği: grup mesajı düzenle/sil —
                // bkz. Rust receive_message Edit/Delete kolu, `group_id`
                // ile taşınır (1:1'in aksine, "peer" outer filtreye gerek
                // yok).
                type == "group_edit" && obj.optString("group_id") == groupId ->
                    runOnUiThread { adapter.applyEdit(obj.optString("message_id"), obj.optString("text")) }
                type == "group_delete" && obj.optString("group_id") == groupId ->
                    runOnUiThread { adapter.applyDelete(obj.optString("message_id")) }
                // Spec dışı, kullanıcı isteği: emoji tepkileri — Rust hazır
                // ÖZET dizesi gönderir (bkz. `reactions_summary`).
                type == "reaction" && obj.optString("group_id") == groupId ->
                    runOnUiThread { adapter.applyReactions(obj.optString("message_id"), obj.optString("reactions")) }
                // `isNull("group_id")` filters out 1:1 typing events too (they never carry it).
                type == "typing" && !obj.isNull("group_id") && obj.optString("group_id") == groupId ->
                    runOnUiThread { handleIncomingGroupTyping(obj) }
                // Spec dışı, kullanıcı isteği (grup ekleri): "file_offer"
                // SADECE bu gruba aitse işlenir (`group_id` ile taşınır);
                // "file_progress"/"file_complete"/"file_failed" `file_id`
                // GLOBAL olarak benzersiz olduğundan koşulsuz işlenir —
                // bu ekranın `localMessages`'ında yoksa zaten no-op'tur
                // (bkz. SimpleChatAdapter.applyAttachmentUpdate).
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
                // End-to-end Ack from a member: bubble gets the double tick.
                type == "status" && obj.optString("group_id") == groupId && obj.optString("status") == "delivered" -> runOnUiThread {
                    adapter.applyStatus(obj.optString("message_id"), SimpleChatAdapter.Status.DELIVERED)
                }
                type == "file_failed" -> runOnUiThread {
                    adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.FAILED)
                }
                // Defter #16: dosya yerelden silindi — balon "tamamlandı"
                // görünmeye devam etmesin, tekrar indirilebilir olsun.
                type == "file_evicted" -> runOnUiThread {
                    adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.OFFERED)
                }
                // Defter #17: bir üye gruptan ayrıldığında Linux önbelleği
                // tazeliyordu, Android hiçbir şey yapmıyordu — üye listesi
                // ve alt başlık sekme değiştirilene kadar bayat kalıyordu.
                // (`group_updated` yukarıda zaten karşılanıyor.)
                type == "member_left" && obj.optString("group_id") == groupId ->
                    runOnUiThread { refreshGroupInfo() }
                // Bir üye hesabını sildi: gruptaki herkese görünür bildirim.
                type == "account_deleted" &&
                    (obj.optJSONArray("group_ids")?.let { a -> (0 until a.length()).any { a.optString(it) == groupId } } == true) ->
                    runOnUiThread {
                        val name = obj.optString("display_name").ifBlank { obj.optString("identity_id").take(8) }
                        Toast.makeText(this, getString(R.string.msg_contact_deleted_account, name), Toast.LENGTH_LONG).show()
                        refreshGroupInfo()
                    }
                // Defter #16: bir `GroupUpdate` imza/versiyon/kurucu
                // doğrulamasından geçemediğinde Rust bu olayı üretiyordu ama
                // kimse dinlemiyordu — kullanıcı grubun sessizce
                // güncellenmediğini hiç öğrenmiyordu.
                type == "group_update_failed" && obj.optString("group_id") == groupId -> runOnUiThread {
                    Toast.makeText(
                        this, getString(R.string.error_group_update_rejected), Toast.LENGTH_LONG
                    ).show()
                }
            }
        } catch (e: Exception) {
            // Ayrıştırılamayan olay — sessizce yok say.
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)
        whiteboard = WhiteboardPanel(this, findViewById(R.id.whiteboardHost), findViewById(R.id.whiteboardHandle))
        com.p2p.messenger.util.ThemePrefs.applyChatBackground(this)
        // bkz. util.ChatListDrawer dokümantasyonu.
        com.p2p.messenger.util.ChatListDrawer.setup(this) {
            // Back with the search bar open closes the bar, not the chat.
            (layoutSearchMessages.visibility == View.VISIBLE).also { if (it) toggleMessageSearch() }
        }

        // Grup sohbetinde tek bir "el sıkışma" durumu yok (her üyeyle ayrı
        // bir 1:1 bağlantı) — bu banner burada anlamlı değil, gizli kalır.
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
        // Kullanıcı: "mesaj balonları bazen titriyor". Tik/görüldü/tepki
        // güncellemeleri `notifyItemChanged` ile geliyor ve varsayılan
        // animatör her birinde balonun eski ve yeni hâli arasında çapraz
        // geçiş (crossfade) oynatıyordu. Ekleme/silme animasyonları kalıyor.
        (recycler.itemAnimator as? androidx.recyclerview.widget.SimpleItemAnimator)?.supportsChangeAnimations = false
        // Birleşen balonların TEK dış hattı — bkz. MergedBubbleDecoration
        // (neden her balonun kendi arka planı yetmiyor, orada yazılı).
        recycler.addItemDecoration(MergedBubbleDecoration(adapter))
        // Listenin üstüne yaklaşınca eski geçmişi yükler.
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
        // Spec dışı, kullanıcı isteği: grup mesajları için de Düzenle/Sil
        // (+ başarısızsa Yeniden Gönder) — bkz. ChatActivity.showEditDeleteDialog
        // AYNI desen.
        adapter.onItemLongPress = { item -> showGroupEditDeleteDialog(item) }
        adapter.onAttachmentClick = { item -> onGroupAttachmentClicked(item) }
        // Spec dışı, hata düzeltmesi + kullanıcı isteği: bu ekranda ek
        // balonuna uzun basmak ÖNCEDEN hiç kablolanmamıştı (bkz.
        // ChatActivity.onAttachmentLongClicked AYNI desen — orada var,
        // burada eksikti) — artık "İndirilenler"e kaydet VE "Başka bir
        // uygulamayla aç" ikisi de var.
        adapter.onAttachmentLongClick = { item -> onGroupAttachmentLongClicked(item) }
        adapter.onReactionsClick = { item -> showReactionsDialog(item) }
        adapter.onReplyPreviewClick = { targetMessageId -> scrollToMessage(targetMessageId) }
        stickerPicker.provideBubbleImages(adapter)
        setupSwipeToReply()
        layoutReplyPreview = findViewById(R.id.layoutReplyPreview)
        txtReplyPreviewSender = findViewById(R.id.txtReplyPreviewSender)
        txtReplyPreviewText = findViewById(R.id.txtReplyPreviewText)
        findViewById<ImageButton>(R.id.btnCancelReply).setOnClickListener { cancelReply() }
        // Spec dışı, kullanıcı isteği: grup sohbetinde de sesli mesaj kaydı/
        // oynatımı — bkz. ChatActivity AYNI MediaRecorder/MediaPlayer
        // altyapısı, tek fark gönderimin `prepareAndSendGroupFile` ile TÜM
        // üyelere yapılması (bkz. `sendVoiceMessage`).
        layoutMessageInput = findViewById(R.id.layoutMessageInput)
        layoutRecording = findViewById(R.id.layoutRecording)
        txtRecordingTimer = findViewById(R.id.txtRecordingTimer)
        txtCancelPill = findViewById(R.id.txtCancelPill)
        setupVoiceRecordButton()
        adapter.onVoicePlayClick = { item -> onVoicePlayClicked(item) }
        adapter.onVoiceSpeedClick = { item -> onVoiceSpeedClicked(item) }
        adapter.onVoiceSeek = { item, positionMs -> onVoiceSeeked(item, positionMs) }

        // Spec dışı, kullanıcı isteği (grup ekleri): dosya/foto/video eki
        // gönderme — bkz. ChatActivity.onFilePicked AYNI desen.
        findViewById<ImageButton>(R.id.btnAttach).setOnClickListener {
            // bkz. ChatActivity aynı notu — sistem seçicisi dış süreç.
            AppLock.beginTrustedExcursion()
            pickGroupFileLauncher.launch(arrayOf("*/*"))
        }

        // bkz. ChatActivity aynı notu — doğrudan kamera.
        findViewById<ImageButton>(R.id.btnCamera).setOnClickListener {
            takePhotoLauncher.launch(Intent(this, CameraCaptureActivity::class.java))
        }

        findViewById<ImageButton>(R.id.btnSticker).setOnClickListener {
            stickerPicker.show()
        }

        // bkz. ChatActivity aynı notu — grup için gerçek bir "grup
        // fotoğrafı" kavramı yok, bu yüzden AvatarUtil'in isimden ürettiği
        // rozet gösterilir (fotoğrafsız kişilerle aynı görsel dil).
        val toolbarTitleView = layoutInflater.inflate(R.layout.actionbar_chat_title, null)
        txtToolbarTitle = toolbarTitleView.findViewById(R.id.txtToolbarTitle)
        imgToolbarAvatar = toolbarTitleView.findViewById(R.id.imgToolbarAvatar)
        txtOwnConnectionStatus = toolbarTitleView.findViewById(R.id.txtOwnConnectionStatus)
        dotOwnStatus = toolbarTitleView.findViewById(R.id.dotOwnStatus)
        ownStatusDot = PulsingStatusDot(dotOwnStatus)
        // bkz. actionbar_chat_title.xml notu — TEK bir karşı taraf/el
        // sıkışma kavramı yok, bu yüzden metin+durum noktası SATIRININ
        // TAMAMI gizlenir (sadece metni gizlemek yetim/etiketsiz bir nokta
        // bırakırdı).
        toolbarTitleView.findViewById<View>(R.id.layoutToolbarSubtitleRow).visibility = View.GONE
        // Spec dışı: üst çubuğa dokununca grup bilgisi (üye listesi + —
        // SADECE kurucu için — profil fotoğrafı değiştirme) açılır.
        toolbarTitleView.setOnClickListener { showGroupInfoDialog() }
        // Spec dışı, kullanıcı isteği: avatarın kendisine dokununca (üstteki
        // genel tıklamayı geçersiz kılarak) tam ekran + pinch-to-zoom açar —
        // bkz. AvatarUtil.openFullscreen.
        imgToolbarAvatar.setOnClickListener { AvatarUtil.openFullscreen(this, currentGroupAvatar) }
        supportActionBar?.apply {
            setDisplayShowCustomEnabled(true)
            setDisplayShowTitleEnabled(false)
            // bkz. ChatActivity aynı notu — bağlantı durumunun üst çubuğun
            // EN SAĞINDA görünebilmesi için özel görünüm AÇIKÇA toolbar
            // genişliğini kaplamalı.
            setCustomView(toolbarTitleView, ActionBar.LayoutParams(ActionBar.LayoutParams.MATCH_PARENT, ActionBar.LayoutParams.MATCH_PARENT))
        }

        val input = findViewById<EditText>(R.id.edtMessage)
        typhoonEffect = findViewById(R.id.typhoonEffect)
        // Spec dışı, kullanıcı isteği (açıkça yeniden istendi): klavye
        // açılınca sohbet onun yüksekliğini telafi etsin ve son mesaj
        // görünür kalsın — bkz. util.KeyboardInsets (neden `adjustResize`
        // yetmiyor, orada ölçümle birlikte yazılı).
        KeyboardInsets.attach(findViewById(R.id.rootChatLayout), recycler)
        // bkz. `syncRecyclerBottomInset` — çubuğun/alıntı pilinin yüksekliği
        // değiştikçe listenin alt dolgusu takip etmeli.
        layoutMessageInput.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ -> syncRecyclerBottomInset() }
        layoutReplyPreview.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ -> syncRecyclerBottomInset() }
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

    /** Paylaşım ekranından seçilen içerik (bkz. util.ShareIntake). */
    private fun consumeShare(intent: Intent) {
        val share = com.p2p.messenger.util.ShareIntake.take(intent) ?: return
        com.p2p.messenger.util.ShareIntake.text(share)?.let {
            findViewById<EditText>(R.id.edtMessage).apply { setText(it); setSelection(text.length) }
        }
        val uris = com.p2p.messenger.util.ShareIntake.uris(share)
        if (uris.isEmpty()) return
        // The chat was picked with one tap in a list that reorders itself.
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.confirm_send_shared, uris.size, txtToolbarTitle.text))
            .setPositiveButton(R.string.btn_send) { _, _ -> uris.forEach { onGroupFilePicked(it) } }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * bkz. ChatActivity.bindToIntent aynı notu — `FLAG_ACTIVITY_CLEAR_TOP`
     * yığındaki var olan bir `GroupChatActivity`'yi `onNewIntent` ile
     * çağırdığında, önceden bu override edilmediği için bildirim yanlış
     * (eski) grubu öne getiriyordu.
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
        // Önceki sohbette açık kalan yanıt, yeni sohbetteki mesaja yapışmasın.
        cancelReply()
        adapter.notifyDataSetChanged()
        seenByPerMessage.clear()
        isLoadingOlderHistory = false
        noMoreOlderHistory = false
        searchMatches = emptyList()
        currentSearchMatchIndex = -1
        if (::layoutSearchMessages.isInitialized) layoutSearchMessages.visibility = View.GONE
        // "…yazıyor" satırları ve sesli mesajın sesi ÖNCEKİ grubun aitti:
        // 1:1'in `bindToIntent`'i bunu sıfırlıyor, grup ikizi sıfırlamıyordu
        // (A grubu ön plandayken B açılırsa A'nın göstergesi B'nin üstünde
        // kalıyordu). `isTypingSent` de sıfırlanmalı: aksi halde B'nin ilk
        // "yazıyor" paketi bastırılıyordu.
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
     * Spec dışı, hata düzeltmesi ("grup geçmişi bazen kalıcı olmuyor"):
     * önceden bu ekran HİÇ geçmiş yüklemiyordu (bkz. dosya başı eski
     * "BİLİNEN SINIR" notu) — sadece ekran açıkken canlı gelen/giden
     * mesajları gösteriyordu, bu yüzden ekranı kapatıp yeniden açmak ya da
     * uygulamayı yeniden başlatmak tüm görünür geçmişi siliyordu (gerçekte
     * artık Rust tarafında `archive_group_message` ile kalıcı olsa bile,
     * Kotlin tarafı hiç okumuyordu). Artık `getGroupMessageHistory` ile
     * yükleniyor — bkz. ChatActivity.loadHistoryIfAvailable AYNI desen.
     *
     * Spec dışı, performans düzeltmesi ("sohbetin açılması uzun sürüyor"):
     * bu fonksiyon (`getGroupMessageHistory`/`listGroupAttachments` JNI
     * çağrıları + HER satır için `itemFromGroupHistoryJson`/
     * `itemFromGroupAttachmentJson`, bunlar da `resolveContactByIdentity`
     * ÜZERİNDEN başka bir JNI çağrısı yapabilir) önceden `bindToIntent`
     * (dolayısıyla `onCreate`) içinde ANA THREAD'DE SENKRON çalışıyordu.
     * Artık ağır kısmın TAMAMI (`Dispatchers.IO`) arka planda, SADECE
     * liste/adapter güncellemesi ana thread'de. `targetGroupId` —
     * kullanıcı bu yükleme bitmeden BAŞKA bir gruba geçerse sonucun YANLIŞ
     * sohbete uygulanmasını önler.
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
                // bkz. `seenViewersFromHistoryJson` dokümantasyonu — geçmiş
                // sırasıyla (eskiden yeniye) toplanır, aşağıda AYNI sırayla
                // `applySeen`'e replay edilir ki adaptör kendiliğinden en
                // SONUNCU görülen mesajda karar kılsın.
                val seenEntries = if (array != null) (0 until array.length()).mapNotNull { i ->
                    val obj = array.getJSONObject(i)
                    val localId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
                    val viewers = if (localId != null) seenViewersFromHistoryJson(obj) else emptyList()
                    if (localId != null && viewers.isNotEmpty()) localId to viewers else null
                } else emptyList()

                // Spec dışı, kullanıcı isteği (grup ekleri): bkz.
                // ChatActivity.loadHistoryIfAvailable AYNI desen — geçmişte
                // gönderilmiş/alınmış ekler metin mesajlarıyla zaman damgasına
                // göre ARAYA SERPİŞTİRİLİR.
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
                // Geçmiş yüklemesi bir canlı mesajdan SONRA biterse sona eklemek
                // canlı mesajı eski geçmişin üstüne, ekran dışına itiyordu (cihazda
                // görüldü) — gönderim sırasına göre yeniden diz.
                localMessages.sortWith(compareBy { it.orderKey })
                resolveReplyLabels()
                adapter.notifyDataSetChanged()
                adapter.dedupeByMessageId()
                recycler.scrollToPosition(localMessages.size - 1)
            }
            // bkz. `seenViewersFromHistoryJson` dokümantasyonu — mesajların
            // TAMAMI adaptöre eklendikten SONRA replay edilir
            // (`applySeen` içindeki `indexOfMessageId` henüz eklenmemiş bir
            // satır için -1 döner ve yalnızca TEK bir bekleyen girdi
            // tutulabilir — bkz. `pendingSeenMessageId` — sıradaki
            // `applySeen` çağrıları onu sessizce ezerdi). `newItems` boş
            // olsa BİLE (ör. bu satırlar zaten localMessages'taysa) "kim
            // gördü" bilgisi yine de tazelenmeli.
            for ((localId, viewers) in seenEntries) {
                val map = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
                for ((identityId, viewer) in viewers) map[identityId] = viewer
                adapter.applySeen(localId, map.values.toList())
            }
        }
    }

    /** bkz. ChatActivity `loadHistoryIfAvailable` ek-satırı AYNI desen —
     *  `listGroupAttachments`'ın JSON satırından bir `Item` üretir.
     *  Gönderen (kendi mesajımız değilse) `sender_identity_id` üzerinden
     *  çözülür — metin mesajlarıyla AYNI mantık. */
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
            // bkz. ChatActivity aynı notu — arşivden gelen ek de açıklamasını
            // ve yanıt bağlamını korur.
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

    /** bkz. ChatActivity.itemFromHistoryJson aynı notu — üç kaynaktan
     *  (yerel ilk yükleme, yerel eski sayfa, ağdan gelen eski sayfa) gelen
     *  JSON satırı AYNI şekilde ayrıştırılır. */
    private fun itemFromGroupHistoryJson(obj: JSONObject): SimpleChatAdapter.Item {
        val direction = obj.optString("direction")
        val isMine = direction == "sent"
        val senderIdentityId = if (obj.isNull("sender_identity_id")) null else obj.optString("sender_identity_id").ifEmpty { null }
        val sender = if (!isMine && senderIdentityId != null) resolveContactByIdentity(senderIdentityId) else null
        val messageId = if (obj.isNull("message_id")) null else obj.optString("message_id").ifEmpty { null }
        // bkz. ChatActivity.itemFromHistoryJson AYNI notu (WhatsApp tarzı
        // yanıt) — `replyToSenderLabel` burada çözülemez, bkz.
        // `resolveReplyLabels`.
        val replyToMessageId = if (obj.isNull("reply_to_message_id")) null else obj.optString("reply_to_message_id").ifEmpty { null }
        val replyToPreview = if (obj.isNull("reply_to_preview")) null else obj.optString("reply_to_preview").ifEmpty { null }
        val replyToSenderIdentityId = if (obj.isNull("reply_to_sender_identity_id")) null else obj.optString("reply_to_sender_identity_id").ifEmpty { null }
        return SimpleChatAdapter.Item(
            messageId = messageId ?: UUID.randomUUID().toString(),
            text = obj.optString("text"),
            isMine = isMine,
            status = if (isMine && obj.optString("status") == "delivered") SimpleChatAdapter.Status.DELIVERED else SimpleChatAdapter.Status.SENT,
            timestamp = obj.optLong("timestamp", System.currentTimeMillis()),
            // Gönderim-sırası: göndericinin gönderim anı (bkz. ChatActivity aynı not).
            sentAtMs = obj.optLong("sent_at_ms", 0L).takeIf { it > 0 },
            senderName = sender?.displayName ?: senderIdentityId?.take(8),
            senderAvatarJpeg = sender?.avatarHex?.let { hexToBytes(it) },
            // bkz. Item.senderIdentityId dokümantasyonu — `isMine`'dan
            // BAĞIMSIZ her zaman kaydedilir (arşiv "sent" satırları için de
            // `sender_identity_id` doldurulur, bkz. Rust `archive_group_message`
            // çağrı noktası), bir SONRAKİ yanıtın doğru kimliği taşıyabilmesi
            // için (bkz. `startReply`).
            senderIdentityId = senderIdentityId,
            replyToMessageId = replyToMessageId,
            replyToPreview = replyToPreview,
            replyToSenderIdentityId = replyToSenderIdentityId,
            isDeleted = obj.optBoolean("is_deleted", false),
            // bkz. Rust `ArchivedMessage.is_edited` — önceden "(düzenlendi)"
            // etiketi SADECE canlı edit olayından geliyordu, sohbet yeniden
            // açılınca kayboluyordu.
            isEdited = obj.optBoolean("is_edited", false),
            mentionsMe = obj.optBoolean("mentions_me", false),
            reactions = obj.optString("reactions", "")
        )
    }

    /**
     * Spec dışı, hata düzeltmesi (kullanıcı: "seen mekanizması ve seen pp
     * bubbles güvenilir değil, özellikle gruplarda"): önceden `seenByPerMessage`
     * SADECE ekran açıkken canlı gelen `handleIncomingSeen` olaylarıyla
     * dolduruluyordu — sohbet kapalıyken/uygulama arka plandayken görülen HER
     * mesaj, sohbet yeniden açıldığında "kim gördü" listesinden KALICI olarak
     * kaybolmuş görünüyordu (Rust tarafında `message_seen` tablosunda gerçekte
     * duruyordu, sadece Kotlin okumuyordu). Artık geçmiş satırındaki
     * `seen_by` (bkz. Rust `ArchivedMessage.seen_by`) da `handleIncomingSeen`
     * ile AYNI şekilde çözülüyor — `(identityId, viewer)` çiftleri döner ki
     * çağıran taraf `seenByPerMessage`'a AYNI anahtarla yazabilsin.
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
        // The quoted message is not here: the name the sender claims for it
        // is not shown ("You" or a member over words they never wrote).
        // bkz. `Item.replyToSenderIdentityId` dokümantasyonu — gönderenin
        // kimliği yedek olarak taşınır ve kişi listesinden ADA çevrilebilir
        // (yerel arşive bakmaya gerek kalmadan). Önceden bu yedek
        // KULLANILMIYORDU: alıntı kutusu boş gönderici etiketi gösteriyordu.
        val identityId = replyToSenderIdentityId
        if (identityId.isNullOrEmpty()) return null
        val name = resolveContactByIdentity(identityId)?.displayName
        return name?.takeIf { it.isNotBlank() }
    }

    /** bkz. ChatActivity.resolveReplyLabels AYNI desen. */
    private fun resolveReplyLabels() {
        for (item in localMessages) {
            if (item.replyToMessageId != null) {
                item.replyToSenderLabel = resolveReplyLabel(item.replyToMessageId, item.replyToSenderIdentityId)
            }
        }
    }

    /**
     * Spec dışı, kullanıcı isteği (sonsuz kaydırma): bkz.
     * ChatActivity.loadOlderHistory AYNI desen — grup geçmişinin en
     * üstüne kaydırıldığında ÖNCE yereldeki (ücretsiz) arşivi dener,
     * yetersiz kalırsa ulaşılabilir TÜM diğer üyelere ağ üzerinden istek
     * gönderir (bkz. Rust `request_older_group_history` fan-out).
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
        // H121: off the main thread (core lock); M115: empty page = end of archive.
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

    /** bkz. `loadOlderGroupHistory` — bir üyeden gelen "older_group_history"
     *  ağ yanıtı. Boş dizi dönerse artık bu grup için tekrar denenmez. */
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

    /** bkz. ChatActivity.prependOlderMessages aynı notu. */
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
     * `listGroups()`'tan bu grubun güncel durumunu (kurucu mu, üyeler,
     * profil fotoğrafı) çeker — üst çubuk avatarını da günceller.
     *
     * Spec dışı, performans düzeltmesi ("sohbetin açılması uzun sürüyor"):
     * `P2PLib.listGroups()` (JNI + TÜM grupların bilgisini/avatar hex
     * blob'unu okuyan bir DB sorgusu) önceden `bindToIntent`'ten
     * (dolayısıyla `onCreate`'ten) ANA THREAD'DE SENKRON çağrılıyordu.
     * Çağıran taraflardan HİÇBİRİ dönüşte GÜNCELLENMİŞ `isFounder`/
     * `memberIdentityIds`'a hemen bağımlı olmadığından (hepsi ya bir
     * olayın SONUNDA ya da başka bir ekranda tetiklenen bir yenileme),
     * fire-and-forget bir arka plan görevine çevrilmesi güvenli.
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
     * Spec dışı: üst çubuğa dokununca — üye listesi + (SADECE kurucu için)
     * profil fotoğrafı değiştirme/kaldırma + üye ekleme. Önceden bu bilgi
     * (Gruplar sekmesindeki uzun basma menüsü) ayrı bir yerdeydi — kullanıcı
     * isteği üzerine buraya, üst çubuğa taşındı.
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
        // Spec dışı, kullanıcı isteği: kurucu için "Üyeleri Yönet" — sadece
        // üye sayısı değil, bu bölümün artık kaldırma da yaptığını belirtir.
        txtMemberCount.text = if (isFounder) {
            getString(R.string.lbl_manage_members)
        } else {
            resources.getQuantityString(R.plurals.lbl_member_count, memberIdentityIds.size, memberIdentityIds.size)
        }
        // Spec dışı, kullanıcı isteği: "Üye Ekle" listenin ÜZERİNDE.
        btnAddMember.visibility = if (isFounder) View.VISIBLE else View.GONE

        val dialog = AlertDialog.Builder(this)
            .setTitle(txtToolbarTitle.text)
            .setView(view)
            .setNegativeButton(android.R.string.ok, null)
            .create()

        // Spec dışı, kullanıcı isteği: her üyenin adı + (SADECE kurucu,
        // kendi satırı HARİÇ) doğrulamalı bir kaldırma düğmesi. Bir üye
        // kaldırıldıktan sonra listeyi YENİDEN ÇİZMEK için yerel fonksiyon
        // (dialog'u kapatıp yeniden açmadan).
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
                    // Dis inceleme onerisi (2026-08-27): kurucu butun
                    // cihazlarini kaybederse grup KALICI olarak kilitleniyor
                    // — kimse uye ekleyip cikaramiyor, adini ve fotografini
                    // degistiremiyordu. Uyeye uzun basip yoneticiligi
                    // devredebiliyoruz.
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

    /** Spec dışı, kullanıcı isteği: bir üyeyi (kurucu HARİÇ, bkz. çağıran
     *  taraf) gruptan çıkarmadan önce onay ister — geri alınamaz (bkz. Rust
     *  `remove_from_group`, imzalı `GroupChange::Remove` tüm üyelere gider).
     *  `onRemoved`, başarılı çıkarma sonrası üye listesini yeniden
     *  çizebilmesi için çağıranın (dialog açıkken) verdiği geri çağırım. */
    /**
     * Grup yoneticiligini baska bir uyeye devreder (dis inceleme onerisi).
     * Devirden sonra BU cihaz artik grubu yonetemez.
     */
    private fun confirmTransferFounder(identityId: String, displayName: String, onDone: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle(R.string.action_transfer_founder)
            .setMessage(getString(R.string.confirm_transfer_founder, displayName))
            .setPositiveButton(R.string.action_transfer_founder) { _, _ ->
                val gid = groupId
                lifecycleScope.launch {
                    // H121: signs and fans out to every member; not on the main thread.
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
                    // H121: signed fan-out to every member; not on the main thread.
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
                contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output -> input.copyTo(output, bufferSize = 64 * 1024) }
                } ?: throw java.io.IOException("Dosya açılamadı")
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

    /** SADECE kurucu için başarılı olur (bkz. Rust `set_group_avatar` —
     *  `validate_group_update`'in mevcut founder kontrolünü yeniden
     *  kullanır) — bu çağrı bir non-founder'dan gelirse Rust "Error: ..."
     *  döner ve burada gösterilir. */
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

    /** bkz. eski GroupsFragment.showAddMembersDialog — buraya taşındı. */
    private fun showAddMembersDialog() {
        val contactsJson = try {
            P2PLib.listContacts()
        } catch (e: Exception) {
            "[]"
        }
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
                for (i in identityIds.indices) {
                    if (checked[i]) {
                        val ok = P2PLib.inviteToGroup(groupId, identityIds[i])
                        if (ok != "OK") {
                            Toast.makeText(this, "${names[i]}: ${coreErrorText(this, ok)}", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
                refreshGroupInfo()
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
     * Performans/kullanıcı isteği düzeltmesi: `P2PLib.sendGroupMessage`
     * (JNI — grubun HER üyesi için AYRI bir ratchet şifreleme + hibrit
     * imza + gossipsub publish denemesi, bkz. Rust `send_group_message`
     * pairwise fan-out) önceden doğrudan ANA THREAD'DE, senkron
     * çağrılıyordu — birden çok üyeli bir grupta bu, 1:1'e göre orantılı
     * olarak DAHA UZUN sürer, dokunma girdisini o süre boyunca hiçbir geri
     * bildirim vermeden dondurabilirdi. Artık arka planda çalışıyor;
     * `btnSend` bu sırada devre dışı + yerine `progressSending` gösteriliyor
     * (bkz. ChatActivity aynı desen).
     */
    /** Other members as (identity id, display name), for @mentions. */
    private fun mentionCandidates(): List<Pair<String, String>> =
        memberIdentityIds.filter { it != ownIdentityId }
            .map { it to (resolveContactByIdentity(it)?.displayName ?: it.take(8)) }

    /** Ids of the members whose "@Name" is in [text], as a JSON array (null: none).
     *  The name must end at a non-letter/digit or the end of the text ("@Alice"
     *  does not mention "Al"); at each '@' only the longest matching name counts. */
    private fun mentionIdsJson(text: String): String? {
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

    private fun sendNewMessage(text: String) {
        btnSend.isEnabled = false
        btnSend.visibility = View.INVISIBLE
        progressSending.visibility = View.VISIBLE
        // bkz. ChatActivity.sendNewMessage AYNI notu (WhatsApp tarzı
        // yanıt) — ANLIK olarak yakalanır. `replyToSenderIdentityId`:
        // alıcı taraf, yanıtlanan mesajı yerelde bulamazsa bunu bir yedek
        // olarak kullanır (bkz. `resolveReplyLabel` genişletilmiş notu).
        val replyToMessageId = activeReplyToMessageId
        val replyToPreview = activeReplyToPreview
        val replyToSenderLabel = if (replyToMessageId != null) txtReplyPreviewSender.text?.toString() else null
        val replyToSenderIdentityId = activeReplyToSenderIdentityId
        val targetGroupId = groupId
        cancelReply()
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    P2PLib.sendGroupMessage(targetGroupId, text, replyToMessageId, replyToPreview, replyToSenderIdentityId, mentionIdsJson(text))
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
            // Rust'ın döndürdüğü
            // `group_message_local_id`'yi KENDİ balonumuzun `messageId`'si
            // olarak kullanıyoruz (rastgele bir UUID yerine, önceden olduğu
            // gibi) ki dönen "seen" bildirimleri doğru balonla eşleşebilsin.
            val localId = if (ok) result else UUID.randomUUID().toString()
            adapter.addMessage(
                SimpleChatAdapter.Item(
                    messageId = localId,
                    text = text,
                    isMine = true,
                    status = if (ok) SimpleChatAdapter.Status.SENT else SimpleChatAdapter.Status.ERROR,
                    senderIdentityId = ownIdentityId,
                    replyToMessageId = replyToMessageId, replyToPreview = replyToPreview,
                    replyToSenderIdentityId = replyToSenderIdentityId,
                    replyToSenderLabel = replyToSenderLabel
                )
            )
            maybePlayTyphoonEffect()
            scrollToBottomNow()
        }
    }

    /**
     * Spec dışı, kullanıcı isteği: başarısız (ERROR) bir grup mesajını
     * yeniden gönderir — AYNI balonu tutar (bkz.
     * `SimpleChatAdapter.retryMessage`), ikinci bir kopya eklemez. Yeni bir
     * `group_message_local_id` ile yeniden fan-out edilir (bkz.
     * `sendNewMessage` aynı mekanizma).
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
            // bkz. ChatActivity.retryFailedMessage AYNI notu — bir yanıtsa AYNI
            // yanıt korunmalı.
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

    /** bkz. ChatActivity.showEditDeleteDialog AYNI desen — kullanıcı
     *  isteği üzerine grup mesajlarına da Düzenle/Sil eklendi. Ek
     *  balonları için desteklenmiyor (bkz. SimpleChatAdapter uzun basma
     *  guard'ı — `item.attachment == null`), bu yüzden burası SADECE düz
     *  metin mesajları için tetiklenir. Spec dışı, kullanıcı isteği: alınan
     *  (kendimize ait olmayan) mesajlar da artık uzun basmaya tepki verir
     *  — onlar için SADECE Kopyala gösterilir, Düzenle/Sil/Yeniden Gönder
     *  sadece kendi mesajlarımızda anlamlı. */
    private fun showGroupEditDeleteDialog(item: SimpleChatAdapter.Item) {
        if (!item.isMine) {
            // bkz. ChatActivity AYNI desen — başkasının mesajını
            // düzenleyemeyiz ama tepki bırakabiliriz.
            val theirOptions = arrayOf(getString(R.string.action_react), getString(R.string.lbl_copy))
            AlertDialog.Builder(this)
                .setItems(theirOptions) { _, which ->
                    when (which) {
                        0 -> showReactionPicker(item)
                        else -> copyMessageText(item)
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
        }
        AlertDialog.Builder(this)
            .setItems(options.toTypedArray()) { _, which ->
                when (options[which]) {
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
     * Spec dışı, kullanıcı isteği: tepki pill'ine dokununca "kim ne attı"
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
                AlertDialog.Builder(this@GroupChatActivity)
                    .setTitle(R.string.title_reactions)
                    .setItems(rows.toTypedArray()) { _, which ->
                        // Kendi satırıma dokunmak tepkimi kaldırır (boş emoji).
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

    /** bkz. ChatActivity.showReactionPicker AYNI desen — grup için. */
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

    /** bkz. ChatActivity.maybePlayTyphoonEffect AYNI desen ve gerekçe. */
    private fun maybePlayTyphoonEffect() {
        val newest = localMessages.lastOrNull() ?: return
        val previous = localMessages.getOrNull(localMessages.size - 2) ?: return
        if (newest.orderKey - previous.orderKey < TYPHOON_QUIET_WINDOW_MS) return
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

    /** bkz. ChatActivity.copyMessageText AYNI desen. */
    private fun copyMessageText(item: SimpleChatAdapter.Item) {
        com.p2p.messenger.util.copySensitive(this, "message", item.text)
        Toast.makeText(this, R.string.lbl_copied, Toast.LENGTH_SHORT).show()
    }

    // ---------------------------------------------------------------
    // Spec dışı, kullanıcı isteği (WhatsApp tarzı "sağa kaydırıp yanıtla",
    // grup sohbetinde de) — bkz. ChatActivity AYNI desen.
    // ---------------------------------------------------------------

    /** bkz. `setupSwipeToReply` — kaydırma BAŞLADIĞINDA yakalanan hedef. */
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

            /** bkz. ChatActivity.setupSwipeToReply AYNI hata ve gerekçe —
             *  hedef, hareketin BİTTİĞİ değil BAŞLADIĞI mesaj. */
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
                val startedOn = swipeStartMessageId
                swipeStartMessageId = null
                val item = startedOn?.let { id -> localMessages.firstOrNull { it.messageId == id } } ?: return
                // bkz. ChatActivity AYNI desen — ekler için de yanıt destekleniyor.
                if (item.isDeleted) return
                startReply(item)
            }
        }
        swipeHelper = ItemTouchHelper(callback)
        swipeHelper.attachToRecyclerView(recycler)
    }

    /** bkz. ChatActivity.startReply AYNI desen — grupta `item.isMine`
     *  değilse etiket, o mesajın zaten çözülmüş `senderName`'i. */
    private fun startReply(item: SimpleChatAdapter.Item) {
        activeReplyToMessageId = item.messageId
        val preview = replyPreviewFor(item)
        activeReplyToPreview = preview
        // bkz. `activeReplyToSenderIdentityId` dokümantasyonu — `item.isMine`
        // ise BİZİM kimliğimiz (kendi mesajımıza yanıt), değilse `item`
        // üzerinde zaten saklı olan göndericinin kimliği (bkz.
        // `itemFromGroupHistoryJson`/`handleIncomingGroupMessage`
        // `senderIdentityId` doldurma noktaları).
        activeReplyToSenderIdentityId = if (item.isMine) ownIdentityId else item.senderIdentityId
        txtReplyPreviewSender.text = if (item.isMine) getString(R.string.lbl_you) else item.senderName
        txtReplyPreviewText.text = preview
        layoutReplyPreview.visibility = View.VISIBLE
        ReplyIsland.set(this, true)
    }

    /** bkz. `ChatActivity.replyPreviewFor` AYNI desen. */
    private fun replyPreviewFor(item: SimpleChatAdapter.Item): String {
        val attachment = item.attachment
        return if (attachment != null) {
            getString(R.string.lbl_attachment_reply_preview, attachment.fileName)
        } else {
            item.text.takeWholeChars(REPLY_PREVIEW_MAX_CHARS)
        }
    }

    private fun cancelReply() {
        activeReplyToMessageId = null
        activeReplyToSenderIdentityId = null
        activeReplyToPreview = null
        layoutReplyPreview.visibility = View.GONE
        ReplyIsland.set(this, false)
    }

    /** bkz. ChatActivity.scrollToMessage AYNI desen. */
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
    // Spec dışı, kullanıcı isteği: grup sohbetinde sesli mesaj kaydı —
    // bkz. ChatActivity AYNI desen (basılı tut/kaydet, sağa kaydır iptal
    // et), tek fark gönderimin `prepareAndSendGroupFile` ile olması.
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
                    // #86: backgrounding cancels the touch; the recording goes on, the user decides
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
        // bkz. ChatActivity aynı notu — sesli mesajın altına da yazı.
        promptAttachmentCaption(onCancel = { file.delete() }) { caption, _ -> sendVoiceMessage(file, durationMs, caption) }
    }

    /** bkz. ChatActivity.sendVoiceMessage AYNI desen — tek fark
     *  `prepareAndSendGroupFile` (TÜM üyelere sunulur) ve dönüşün sadece
     *  bir dosya kimliği string'i olması (bkz. `onGroupFilePicked` AYNI
     *  dönüş biçimi notu, 1:1'in JSON `{message_id, status}`'ından farklı). */
    private fun sendVoiceMessage(file: File, durationMs: Long, caption: String = "") {
        // Taken and cleared here: the next message was sent as a reply too.
        val replyId = activeReplyToMessageId
        val replyPreview = activeReplyToPreview
        val replySender = activeReplyToSenderIdentityId
        cancelReply()
        val targetGroupId = groupId
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try {
                P2PLib.prepareAndSendGroupFile(
                    targetGroupId, file.absolutePath, file.name, "audio/mp4", null, durationMs.toInt(),
                    caption, replyId ?: "", replyPreview ?: "",
                    replySender ?: ""
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
                            replyToMessageId = replyId,
                            replyToPreview = replyPreview,
                            replyToSenderIdentityId = replySender,
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
            file.delete()
        }
    }

    private fun formatDurationMs(ms: Long): String {
        val totalSeconds = ms / 1000
        val minutes = totalSeconds / 60
        val seconds = totalSeconds % 60
        return String.format(java.util.Locale.getDefault(), "%d:%02d", minutes, seconds)
    }

    // ---------------------------------------------------------------
    // Spec dışı, kullanıcı isteği: grup sohbetinde sesli mesaj oynatma —
    // bkz. ChatActivity AYNI desen (tek paylaşımlı MediaPlayer).
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
                try {
                    val player = MediaPlayer()
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

    /** bkz. ChatActivity.showEditMessageDialog AYNI desen —
     *  `editGroupMessage` "OK"/"Error: ..." döner (1:1'in aksine JSON
     *  değil, bkz. P2PLib.kt notu). */
    private fun showEditGroupMessageDialog(item: SimpleChatAdapter.Item) {
        val input = EditText(this)
        input.setText(item.text)
        input.hint = getString(R.string.lbl_edit_message_hint)
        AlertDialog.Builder(this)
            .setTitle(R.string.action_edit_message)
            .setView(input)
            .setPositiveButton(R.string.action_edit_message) { _, _ ->
                val newText = input.text.toString()
                if (newText.isBlank()) return@setPositiveButton
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

    /** bkz. ChatActivity.onPhotoCaptured AYNI desen (grup için) — kameradan
     *  gelen kare bellekten geçici bir önbellek dosyasına yazılıp
     *  gönderilir ve dosya hemen silinir; galeriye/paylaşılan depolamaya
     *  hiçbir şey yazılmaz. */
    private fun onGroupPhotoCaptured(jpeg: ByteArray, caption: String = "", hiRes: Boolean = false) {
        // Ekle birlikte gidecek yanıt bağlamı, coroutine BAŞLAMADAN
        // yakalanıyor: `cancelReply()` aşağıda hemen çağrılıyor (kullanıcı
        // arayüzde yanıtın tüketildiğini anında görmeli) ve arka planda
        // okunsaydı çoktan temizlenmiş olurdu.
        val replyId = activeReplyToMessageId ?: ""
        val replyPreview = activeReplyToPreview ?: ""
        val replySender = activeReplyToSenderIdentityId ?: ""
        cancelReply()
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
                    caption, replyId, replyPreview, replySender
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
                                // Spec dışı: gönderirken yazılan açıklama hemen görünsün.
                                caption = caption
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

    /**
     * Spec dışı, kullanıcı isteği (grup ekleri): bkz. ChatActivity.onFilePicked
     * AYNI desen — SAF ile seçilen dosya önce önbelleğe kopyalanır, sonra
     * `prepareAndSendGroupFile` ile TÜM üyelere sunulur.
     */
    private fun onGroupFilePicked(uri: Uri, caption: String = "", hiRes: Boolean = false) {
        // Ekle birlikte gidecek yanıt bağlamı, coroutine BAŞLAMADAN
        // yakalanıyor: `cancelReply()` aşağıda hemen çağrılıyor (kullanıcı
        // arayüzde yanıtın tüketildiğini anında görmeli) ve arka planda
        // okunsaydı çoktan temizlenmiş olurdu.
        val replyId = activeReplyToMessageId ?: ""
        val replyPreview = activeReplyToPreview ?: ""
        val replySender = activeReplyToSenderIdentityId ?: ""
        cancelReply()
        // The group is captured BEFORE the coroutine (bkz.
        // `onGroupPhotoCaptured` aynı not).
        val targetGroupId = groupId
        lifecycleScope.launch(Dispatchers.IO) {
            // Provider queries are IPC to another app: not on the main thread.
            val fileName = queryDisplayName(uri) ?: "file"
            val mimeType = contentResolver.getType(uri) ?: "application/octet-stream"
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
                    caption, replyId, replyPreview, replySender
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
                                // Spec dışı: gönderirken yazılan açıklama hemen görünsün.
                                caption = caption
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

    /** bkz. ChatActivity.onAttachmentClicked AYNI desen — tek fark: indirme
     *  hedefi (`peerDeviceFingerprint`) sabit bir alan değil, `AttachmentInfo`
     *  üzerinde taşınır (bkz. dosya başı notu — grup içinde farklı ekler
     *  farklı göndericilerden gelebilir). */
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

    /** bkz. ChatActivity.openAttachmentFile — AYNI, peer'e bağımlı değil. */
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
            AppLock.beginTrustedExcursion()
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
        }
    }

    /** bkz. ChatActivity.onAttachmentLongClicked AYNI desen — önceden bu
     *  ekranda hiç kablolanmamıştı (grup ek balonuna uzun basmak no-op'tu). */
    private fun onGroupAttachmentLongClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        // bkz. ChatActivity.onAttachmentLongClicked AYNI desen — sadece
        // KENDİ gönderdiğimiz ekler silinebilir.
        val options = mutableListOf<String>().apply {
            add(getString(R.string.action_open_with))
            add(getString(R.string.action_save_to_downloads))
            // Save to Downloads hands out a JPEG XL as PNG/GIF; this keeps the original.
            if (attachment.fileName.endsWith(".jxl", true) || attachment.mimeType == "image/jxl") add(getString(R.string.action_save_as_jxl))
            if (attachment.mimeType.startsWith("image/")) add(getString(R.string.action_copy_image))
            if (attachment.isSticker && !item.isMine) add(getString(R.string.action_add_to_my_stickers))
            if (item.isMine) add(getString(R.string.action_delete_message))
        }
        AlertDialog.Builder(this)
            .setItems(options.toTypedArray()) { _, which ->
                when (options[which]) {
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

    /** bkz. ChatActivity.openAttachmentWithChooser AYNI desen. */
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
                    AppLock.beginTrustedExcursion()
                    startActivity(Intent.createChooser(intent, getString(R.string.lbl_open_with_chooser)))
                } catch (e: Exception) {
                    Toast.makeText(this@GroupChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /** bkz. ChatActivity.saveAttachmentToDownloads AYNI desen. */
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

    /** bkz. ChatActivity.saveToPublicDownloads AYNI desen. */
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
     * Spec dışı, kullanıcı isteği (grup ekleri): canlı gelen bir grup
     * `FileOffer`'ı — bkz. ChatActivity handleIncomingEvent "file_offer"
     * kolu AYNI mantık, ARTI gönderen adı/avatarı (metin mesajlarıyla AYNI
     * `resolveContactByIdentity` çözümü) ve `peerDeviceFingerprint`
     * (indirme hedefi).
     */
    private fun handleIncomingGroupFileOffer(obj: JSONObject) {
        val senderIdentityId = obj.optString("sender_identity_id")
        val sender = resolveContactByIdentity(senderIdentityId)
        val autoDownloading = obj.optBoolean("auto_downloading", false)
        val previewHex = obj.optString("preview_hex", "")
        val previewJpeg = if (previewHex.isNotEmpty() && previewHex != "null") hexToBytes(previewHex) else null
        val durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it }
        // Spec dışı, kullanıcı isteği: ekle gelen açıklama + yanıt bağlamı.
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
                // Spec dışı, kullanıcı isteği: ek + açıklama + yanıt.
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

    /** bkz. ChatActivity.generateImagePreview — AYNI. */
    private fun generateImagePreview(file: File): ByteArray? =
        ImagePreview.compressFile(file, PREVIEW_MAX_DIMENSION, PREVIEW_JPEG_QUALITY)

    /** bkz. ChatActivity.generateVideoPreview — AYNI. */
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
     * Çoklu-cihaz (spec 1.7): başka bir cihazımdan gönderdiğim grup mesajının
     * yankısı — `isMine=true` balon olarak eklenir (görüldü gönderilmez, kendi
     * mesajım). Yeniden açılışta arşivden "sent" olarak zaten gelir.
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
        // Spec dışı, hata düzeltmesi: bu balonun `Item.messageId`'si ARTIK
        // per-paket `message_id` DEĞİL, `group_message_local_id` — kendi
        // gönderdiğimiz grup mesajlarıyla (bkz. `sendNewMessage` "KENDİ
        // balonumuzun messageId'si" notu) VE geçmişten yüklenen satırlarla
        // (bkz. `itemFromGroupHistoryJson` — DB'nin `message_id` kolonuna
        // zaten `group_message_local_id` yazılıyor, bkz. Rust
        // `archive_group_message` çağrı noktası) TUTARLI olması için.
        // Önceden bu satır per-paket id kullanıyordu — edit/delete zaten
        // SADECE kendi mesajlarımızda tetiklendiğinden (bkz.
        // `showGroupEditDeleteDialog` `isMine` guard'ı) bu tutarsızlık
        // fark edilmemişti, ama WhatsApp tarzı "yanıtla" (bkz.
        // `startReply`) BAŞKASININ mesajına da yanıt vermeyi gerektiriyor —
        // yanlış id, yanıtın karşı tarafta hiçbir mesajla eşleşmemesine
        // yol açardı.
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
        // Spec dışı, kullanıcı isteği: "görüldü" — ekran açıkken gelen
        // canlı grup mesajı için otomatik gönderilir (bkz. ChatActivity
        // 1:1 karşılığı AYNI gerekçe). `peer`, bu kopyanın geldiği 1:1
        // kanalın (göndericinin) fingerprint'i.
        if (AppLock.isUnlocked()) netPack.execute {
            try { P2PLib.sendSeenReceipt(obj.optString("peer"), messageId, localId) } catch (e: Exception) { /* yoksay */ }
        }
        // Güvenilir yol: tekil `Seen` kaybolsa bile okuma sınırı diske yazılır.
        scheduleGroupReadWatermark()
    }

    /** bkz. dosya başı `seenByPerMessage` notu — aynı mesajı gören farklı
     *  üyeleri identity_id bazında biriktirir, adaptöre her seferinde
     *  TAM güncel listeyi geçirir. */
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

    /** Toplu görüldü: bir üye "buraya kadar okudum" sınırı yolladı; Rust
     *  BENİM gönderdiğim, sınıra kadar olan mesajların `message_id`'lerini
     *  verir. Her biri için o üyeyi `seenByPerMessage`'a ekleyip adaptöre
     *  tam listeyi geçir — tıpkı `handleIncomingSeen` gibi. */
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

    /** bkz. `resolveContactByIdentity` dokümantasyonu — geçmiş yüklenirken
     *  aynı JNI/DB sonucunun tekrar tekrar çekilmesini önleyen kısa ömürlü
     *  önbellek. */
    @Volatile private var contactListCache: JSONArray? = null
    @Volatile private var contactListCacheAt: Long = 0

    /**
     * Spec dışı, performans düzeltmesi ("sohbetin açılması uzun sürüyor"):
     * önceden HER çağrıda `P2PLib.listContacts()` (JNI + TÜM kişi listesini,
     * avatar hex blobları DAHİL, yeniden okuyup JSON ayrıştıran bir DB
     * sorgusu) baştan çalıştırılıyordu — grup geçmişi yüklenirken bu fonksiyon
     * HER mesaj/ek satırı için (bkz. `itemFromGroupHistoryJson`/
     * `itemFromGroupAttachmentJson`, geçmişteki YÜZLERCE satır üzerinde
     * döngüde çağrılıyor) ayrı ayrı çağrılıyordu — yani N mesajlı bir
     * geçmiş, TÜM kişi listesini N KEZ baştan çekip ayrıştırıyordu (N×M
     * büyümesi, M=kişi sayısı). Artık sonuç kısa bir süre (bkz.
     * `CONTACT_CACHE_TTL_MS`) önbellekleniyor — bir geçmiş yükleme
     * "patlaması" içindeki TÜM çağrılar TEK bir JNI/JSON ayrıştırmasını
     * paylaşır. TTL kısa tutulduğundan (canlı olay işleyicileri de AYNI
     * fonksiyonu kullanıyor) bir kişi bilgisi değiştiğinde birkaç saniyeden
     * daha eski gösterilmez.
     */
    private fun resolveContactByIdentity(identityId: String): ContactLookup? {
        return try {
            val now = System.currentTimeMillis()
            val cached = contactListCache
            val array = if (cached != null && now - contactListCacheAt < CONTACT_CACHE_TTL_MS) {
                cached
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

    /** Called on state transitions only, by the EditText watcher and `stopTypingRunnable`. */
    private fun sendTypingState(isTyping: Boolean) {
        if (isTypingSent == isTyping) return
        isTypingSent = isTyping
        // fixpass (glm A2): bkz. `netPack` (dosya başı).
        netPack.execute {
            try {
                P2PLib.sendGroupTypingIndicator(groupId, isTyping)
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
            // Spec dışı, hata düzeltmesi (kullanıcı: "en alttaysak yeni
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
        } else {
            blinkScrollToBottomFab()
        }
    }

    /** Unconditional scroll — for our own sent messages/attachments. */
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
        // Spec dışı, kullanıcı isteği: son mesajlar alt çubuğun altında
        // kalıyordu — çubuğun gerçek yüksekliğine ek olarak ekran
        // yüksekliğinin ~%10'u kadar boş alt boşluk bırakılıyor.
        val gap = (8 * resources.displayMetrics.density).toInt() +
            (resources.displayMetrics.heightPixels * 0.10f).toInt()
        val replyHeight = if (layoutReplyPreview.visibility == View.VISIBLE) layoutReplyPreview.height else 0
        val inset = layoutMessageInput.height + replyHeight + gap
        if (recycler.paddingBottom == inset) return
        recycler.setPadding(recycler.paddingLeft, recycler.paddingTop, recycler.paddingRight, inset)
    }

    /**
     * Spec dışı, kullanıcı isteği: "fotoğraf/eklenti/ses atarken de bir
     * mesaj yanıtlanabilmeli ve altına bir yazı yazılabilmeli."
     *
     * Yanıt için ayrı bir adım YOK — ekran zaten aktif bir yanıt tutuyorsa
     * (sağa kaydırıp yanıtla, bkz. `activeReplyToMessageId`) ek onunla
     * birlikte gidiyor. Bu pencere yalnızca açıklamayı soruyor; boş
     * bırakılabilir.
     */
    private fun promptAttachmentCaption(onCancel: () -> Unit = {}, offerHiRes: Boolean = false, onConfirm: (caption: String, hiRes: Boolean) -> Unit) {
        val input = EditText(this).apply {
            hint = getString(R.string.hint_attachment_caption)
            setSingleLine(false)
            maxLines = 4
        }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad / 2, pad, 0)
            addView(input)
        }
        // Images: lossless (a JPEG as it is, other formats as JPEG XL)
        // instead of JPEG quality 90. See util.OutgoingMedia.
        val hiRes = android.widget.CheckBox(this).apply {
            setText(R.string.attachment_hi_res)
            visibility = if (offerHiRes) View.VISIBLE else View.GONE
        }
        container.addView(hiRes)
        AlertDialog.Builder(this)
            .setTitle(R.string.title_attachment_caption)
            .setView(container)
            .setPositiveButton(R.string.btn_send) { _, _ -> onConfirm(input.text.toString(), hiRes.isChecked) }
            .setNegativeButton(android.R.string.cancel) { _, _ -> onCancel() }
            .setOnCancelListener { onCancel() }
            .show()
    }

    private fun scrollToBottomNow() {
        recycler.scrollToPosition(localMessages.size - 1)
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

    /** bkz. ChatActivity.setupMessageSearch/toggleMessageSearch/
     *  runMessageSearch/moveSearchMatch/goToSearchMatch AYNI desen —
     *  sohbet içi mesaj arama, sadece o an yüklü `localMessages` üzerinde. */
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
        // Spec dışı, kullanıcı isteği: bu grup sohbeti açıldığında ona ait
        // bekleyen bildirim varsa temizlensin.
        // A locked app resumes this screen for a moment under the password
        // prompt: nothing was read, so no notification is cleared and no
        // "read up to now" goes out (see onPause too).
        resumedUnlocked = com.p2p.messenger.util.AppLock.isUnlocked()
        if (resumedUnlocked) com.p2p.messenger.util.NotificationHelper.clearForGroup(this, groupId)
        // Spec dışı, kullanıcı isteği: Ayarlar'dan duvarkağıdı/renk
        // değiştirilip bu ekrana geri dönüldüğünde HEMEN yansısın.
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
        // "görüldü" güvenilirlik + hız (2026-09-07): grup açılır açılmaz
        // "buraya kadar okudum" sınırını üyelere bildir — eskiden sadece
        // onPause'da ve yalnızca kardeş cihazlara gidiyordu.
        if (resumedUnlocked) scheduleGroupReadWatermark()
    }

    private val groupReadWatermarkHandler = Handler(Looper.getMainLooper())
    private val groupReadWatermarkRunnable = Runnable {
        syncGroupReadStateAsync()
    }
    // H121: the core lock is not taken on the main thread.
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
                // bkz. `loadGroupHistoryIfAvailable`/`seenViewersFromHistoryJson`
                // AYNI desen — bu fonksiyon `onResume`'da (arka plandan
                // dönüşte) çalıştığından pratikte EN ÇOK vurulan yol.
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
                // Geçmiş yüklemesi bir canlı mesajdan SONRA biterse sona eklemek
                // canlı mesajı eski geçmişin üstüne, ekran dışına itiyordu (cihazda
                // görüldü) — gönderim sırasına göre yeniden diz.
                localMessages.sortWith(compareBy { it.orderKey })
                resolveReplyLabels()
                adapter.notifyDataSetChanged()
                adapter.dedupeByMessageId()
                onNewIncomingItemAdded()
            }
            // bkz. `loadGroupHistoryIfAvailable` altındaki AYNI "seen" replay notu.
            for ((localId, viewers) in seenEntries) {
                val map = seenByPerMessage.getOrPut(localId) { mutableMapOf() }
                for ((identityId, viewer) in viewers) map[identityId] = viewer
                adapter.applySeen(localId, map.values.toList())
            }
        }
    }

    override fun onPause() {
        super.onPause()
        if (!::groupId.isInitialized) return // H63
        P2PService.removeMessageListener(messageListener)
        if (P2PService.activeConversationId == "group:$groupId") {
            P2PService.activeConversationId = null
        }
        // Kardeş cihazlar VE üyeler bu grubu okunmuş saysın (bkz.
        // `sync_read_state` — artık iki hedef).
        groupReadWatermarkHandler.removeCallbacks(groupReadWatermarkRunnable)
        if (resumedUnlocked) {
            com.p2p.messenger.util.ReadStatePrefs.markRead(this, "group:$groupId")
            syncGroupReadStateAsync()
        }
        resumedUnlocked = false
        ownStatusPollHandler.removeCallbacks(ownStatusPollRunnable)
        // bkz. ChatActivity onPause aynı notu — Activity görünür değilken
        // bir pulse animasyonunun arka planda vsync'e kayıtlı kalmaması için.
        ownStatusDot.cancelPulse()
        // Tell members we stopped typing and clear pending timeouts.
        typingHandler.removeCallbacksAndMessages(null)
        typingMembers.clear()
        updateTypingIndicatorUi()
        sendTypingState(false)
        // bkz. ChatActivity onPause AYNI notu — kullanıcı ekranı kapatırken
        // devam eden bir kayıt/oynatma varsa temiz bir şekilde durdurulur.
        backgrounded = true // #86: the recording keeps running (service has the microphone type)
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
