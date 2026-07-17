package com.p2p.messenger.ui

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
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
import android.view.MotionEvent
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.PlaybackSpeed
import com.p2p.messenger.util.hexToBytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * Spec 3 (Mesajlaşma) — tek bir kişiyle 1:1 sohbet ekranı.
 *
 * Mesaj geçmişi artık HER cihazda (node modu açık olsun olmasın) yerelde
 * şifreli olarak kalıcı tutulur (bkz. MessageHistoryManager, lib.rs
 * archive_message/load_message_history) — kullanıcı tercihi (bu
 * görüşmede netleştirildi). Node modu artık sadece karşı taraflara
 * geçmiş senkronizasyonunda yardımcı olma (bkz. `requestHistorySync`) ve
 * DHT routing katılımını etkiliyor.
 */
class ChatActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PEER_DEVICE_FINGERPRINT = "peer_device_fingerprint"
        const val EXTRA_PEER_DISPLAY_NAME = "peer_display_name"
        private const val HISTORY_LOAD_LIMIT = 200
        private const val HISTORY_SYNC_LIMIT = 30
        private const val SESSION_POLL_INTERVAL_MS = 800L
        private const val STEADY_STATE_POLL_INTERVAL_MS = 5000L
        /** bkz. Rust MAX_ATTACHMENT_SIZE (lib.rs) — burada AYRICA kontrol
         *  edilir ki aşırı büyük bir dosya reddedilmeden önce boşuna
         *  uygulamanın önbelleğine kopyalanmasın. */
        private const val MAX_ATTACHMENT_SIZE = 4L * 1024 * 1024 * 1024
        /** Spec dışı: kullanıcı tarafından istenen önizleme boyutu/kalitesi
         *  — bkz. generateImagePreview/generateVideoPreview. "480p", en
         *  uzun kenarın 480px'e sınırlanması olarak yorumlanıyor. */
        private const val PREVIEW_MAX_DIMENSION = 480
        private const val PREVIEW_JPEG_QUALITY = 85
        /** Kullanıcı yazmayı bıraktıktan bu kadar süre sonra otomatik
         *  "yazmıyor" gönderilir (karşı tarafa açıkça bildirmeyi unutursa,
         *  ör. ekranı kapatıp uygulamadan çıkarsa diye). */
        private const val TYPING_IDLE_TIMEOUT_MS = 3000L
        /** Karşı taraftan gelen bir "yazıyor" olayının, bir "yazmıyor"
         *  takibi hiç gelmezse ne kadar süre sonra kendiliğinden
         *  temizleneceği — kayıp bir paket yüzünden göstergenin sonsuza
         *  kadar takılı kalmasını önler. */
        private const val TYPING_INDICATOR_TIMEOUT_MS = 8000L
        /** Bu kadar kısa bir basılı tutma, kazara dokunma sayılır ve kayıt
         *  gönderilmeden atılır (bkz. finishVoiceRecording). */
        private const val RECORDING_MIN_DURATION_MS = 500L
        /** Bu kadar sola kaydırınca kayıt iptal edilir (bkz. dosya başı
         *  "basılı tut, bırakınca gönder, sola kaydır iptal et" isteği). */
        private const val RECORDING_CANCEL_SWIPE_DP = 120f
        private const val VOICE_PLAYBACK_TICK_MS = 200L
    }

    private lateinit var peerDeviceFingerprint: String
    private val localMessages = mutableListOf<SimpleChatAdapter.Item>()
    private lateinit var adapter: SimpleChatAdapter
    private lateinit var recycler: RecyclerView
    private lateinit var connectingBanner: View
    /** bkz. `loadHistoryIfAvailable`/`handleIncomingEvent` "history_sync" —
     *  yereldeki arşiv boşsa karşı tarafa (node modu açıksa) bir geçmiş
     *  isteği gönderilir; yanıt gelene kadar bu true kalır ki yanıt geldiğinde
     *  onu listenin başına eklemeyi bilelim (peer değişince sıfırlanır). */
    private var historySyncPending = false

    // --- Spec dışı: "yazıyor..." göstergesi ---
    /** Karşı taraftan en son alınan "typing" olayının durumu — sohbet
     *  başlığının altındaki durum yazısını (Bağlı/Bağlanılıyor yerine)
     *  geçici olarak değiştirir, bkz. `sessionPollRunnable`. */
    private var peerIsTyping = false
    private val typingHandler = Handler(Looper.getMainLooper())
    private val clearPeerTypingRunnable = Runnable { peerIsTyping = false }
    /** Biz KENDİMİZ karşı tarafa en son "yazıyor" mu "yazmıyor" mu
     *  bildirdik — sadece false->true/true->false GEÇİŞLERİNDE paket
     *  göndermek için (her tuş vuruşunda değil). */
    private var isTypingSent = false
    private val stopTypingRunnable = Runnable { sendTypingState(false) }

    // --- Spec dışı: basılı tut/kaydet sesli mesaj ---
    private var mediaRecorder: MediaRecorder? = null
    private var recordingFile: File? = null
    private var recordingStartTime: Long = 0L
    private var recordingTouchStartX: Float = 0f
    private var recordingCancelled = false
    private lateinit var layoutMessageInput: View
    private lateinit var layoutRecording: View
    private lateinit var txtRecordingTimer: android.widget.TextView
    private val recordingHandler = Handler(Looper.getMainLooper())
    private val recordingTimerRunnable = object : Runnable {
        override fun run() {
            val elapsed = System.currentTimeMillis() - recordingStartTime
            txtRecordingTimer.text = formatDurationMs(elapsed)
            recordingHandler.postDelayed(this, 200)
        }
    }
    private val requestRecordAudioPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* reddedilse bile devam — kullanıcı düğmeye tekrar basmalı */ }

    // --- Spec dışı: sesli mesaj çalma (tek paylaşımlı MediaPlayer — aynı
    // anda sadece bir sesli mesaj çalar, biri başlarken diğeri durur) ---
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
                    adapter.updateVoicePlayback(fileId, true, player.currentPosition, voicePlaybackSpeed)
                } catch (e: Exception) { /* MediaPlayer o an geçerli bir durumda olmayabilir */ }
                voicePlaybackHandler.postDelayed(this, VOICE_PLAYBACK_TICK_MS)
            }
        }
    }

    /** Spec dışı: dosya/foto/video/ses eki seçimi — SAF `OpenDocument`
     *  kullanılıyor (bkz. dosya sonu `onFilePicked` notu): tüm ek
     *  türlerini tek bir seçiciyle kapsar VE hiçbir çalışma zamanı
     *  depolama izni gerektirmez (Android 13+ READ_MEDIA_*'ye bile gerek
     *  yok). `registerForActivityResult` Activity STARTED olmadan ÖNCE
     *  çağrılmalı — bu yüzden alan bildirimi (field initializer) olarak,
     *  onCreate'ten önce çalışır. */
    private val pickFileLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { onFilePicked(it) }
    }
    /** SADECE API 26-28 (scoped storage öncesi) için — bkz.
     *  saveToPublicDownloads notu. API 29+'ta hiç kullanılmaz. */
    private val requestStoragePermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* reddedilse bile devam — kaydetme o zaman başarısız olur, mesajlaşma etkilenmez */ }

    private val sessionPollHandler = Handler(Looper.getMainLooper())
    /**
     * Spec dışı: bağlantı durumu göstergesi — iki AYRI sorunun cevabını
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
    private val sessionPollRunnable = object : Runnable {
        override fun run() {
            val handshakeDone = try {
                P2PLib.hasActiveSession(peerDeviceFingerprint)
            } catch (e: Exception) {
                false
            }
            val liveConnected = try {
                P2PLib.isPeerConnected(peerDeviceFingerprint)
            } catch (e: Exception) {
                false
            }
            connectingBanner.visibility = if (handshakeDone) View.GONE else View.VISIBLE
            supportActionBar?.subtitle = when {
                peerIsTyping -> getString(R.string.lbl_typing)
                liveConnected -> getString(R.string.lbl_status_online)
                else -> getString(R.string.lbl_status_offline)
            }
            sessionPollHandler.postDelayed(
                this, if (handshakeDone) STEADY_STATE_POLL_INTERVAL_MS else SESSION_POLL_INTERVAL_MS
            )
        }
    }

    /**
     * Gelen olaylar artık düz metin DEĞİL, `{"type":...}` etiketli bir JSON
     * (bkz. Rust `receive_message` dokümantasyonu — edit/delete/status'u aynı
     * String kanalından taşıyabilmek için). `peer` alanı, bu olayın HANGİ
     * karşı tarafa ait olduğunu taşır — önceden bu bilgi hiç taşınmıyordu
     * ve birden fazla sohbet açıkken gelen her mesaj, o an ekranda hangi
     * ChatActivity varsa ona ekleniyordu (yanlış sohbete sızma riski).
     */
    private val messageListener: (String) -> Unit = { json ->
        try {
            val obj = JSONObject(json)
            if (obj.optString("peer") == peerDeviceFingerprint) {
                runOnUiThread { handleIncomingEvent(obj) }
            }
        } catch (e: Exception) {
            // Ayrıştırılamayan olay — sessizce yok say.
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)

        connectingBanner = findViewById(R.id.layoutConnecting)
        recycler = findViewById(R.id.recyclerMessages)
        adapter = SimpleChatAdapter(localMessages)
        adapter.onItemLongPress = { item -> showEditDeleteDialog(item) }
        adapter.onAttachmentClick = { item -> onAttachmentClicked(item) }
        adapter.onAttachmentLongClick = { item -> onAttachmentLongClicked(item) }
        recycler.layoutManager = LinearLayoutManager(this)
        recycler.adapter = adapter

        val input = findViewById<EditText>(R.id.edtMessage)
        findViewById<Button>(R.id.btnSend).setOnClickListener {
            val text = input.text.toString()
            if (text.isBlank()) return@setOnClickListener
            input.text.clear()
            sendNewMessage(text)
        }
        // Spec dışı: "yazıyor..." göstergesi — SADECE false->true/
        // true->false geçişlerinde paket gönderir (her tuş vuruşunda
        // değil), bkz. `sendTypingState`. Boşta kalma zaman aşımı
        // (kullanıcı yazmayı bırakıp mesajı hiç göndermezse) için her
        // metin değişikliğinde `stopTypingRunnable` yeniden zamanlanır.
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
        findViewById<ImageButton>(R.id.btnAttach).setOnClickListener {
            pickFileLauncher.launch(arrayOf("*/*"))
        }
        // bkz. requestStoragePermission notu — SADECE API 26-28, erkenden
        // (kullanıcı gerçekten bir şey kaydetmeye çalışmadan önce) istenir
        // ki o an geldiğinde izin muhtemelen zaten verilmiş olsun.
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.Q &&
            androidx.core.content.ContextCompat.checkSelfPermission(this, android.Manifest.permission.WRITE_EXTERNAL_STORAGE) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestStoragePermission.launch(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
        }

        layoutMessageInput = findViewById(R.id.layoutMessageInput)
        layoutRecording = findViewById(R.id.layoutRecording)
        txtRecordingTimer = findViewById(R.id.txtRecordingTimer)
        setupVoiceRecordButton()
        adapter.onVoicePlayClick = { item -> onVoicePlayClicked(item) }
        adapter.onVoiceSpeedClick = { item -> onVoiceSpeedClicked(item) }

        if (!bindToIntent(intent)) {
            finish()
            return
        }
    }

    /**
     * Spec dışı: basılı tut/kaydet sesli mesaj — ACTION_DOWN kaydı başlatır,
     * ACTION_UP gönderir, sola (bkz. RECORDING_CANCEL_SWIPE_DP) kaydırıp
     * bırakmak iptal eder (WhatsApp'taki gibi). İzin yoksa ilk basışta
     * istenir, o basış kayıt BAŞLATMAZ (kullanıcı izni verdikten sonra
     * tekrar basmalı — standart Android deseni).
     */
    private fun setupVoiceRecordButton() {
        findViewById<ImageButton>(R.id.btnVoice).setOnTouchListener { _, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
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
                        recordingCancelled = dx < -thresholdPx
                    }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    if (mediaRecorder != null) finishVoiceRecording(send = !recordingCancelled)
                    true
                }
                MotionEvent.ACTION_CANCEL -> {
                    if (mediaRecorder != null) finishVoiceRecording(send = false)
                    true
                }
                else -> false
            }
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
        recordingFile = file
        recordingStartTime = System.currentTimeMillis()
        recordingCancelled = false
        layoutMessageInput.visibility = View.GONE
        layoutRecording.visibility = View.VISIBLE
        txtRecordingTimer.text = "0:00"
        recordingHandler.post(recordingTimerRunnable)
    }

    private fun finishVoiceRecording(send: Boolean) {
        val recorder = mediaRecorder ?: return
        val file = recordingFile
        val durationMs = System.currentTimeMillis() - recordingStartTime
        mediaRecorder = null
        recordingFile = null
        recordingHandler.removeCallbacks(recordingTimerRunnable)
        layoutRecording.visibility = View.GONE
        layoutMessageInput.visibility = View.VISIBLE
        try {
            recorder.stop()
        } catch (e: Exception) {
            // Çok kısa bir dokunuştan hemen sonra stop() çağrılırsa
            // IllegalStateException fırlatabilir — kayıt zaten geçersiz.
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
        sendVoiceMessage(file, durationMs)
    }

    private fun sendVoiceMessage(file: File, durationMs: Long) {
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try {
                P2PLib.prepareAndSendFile(peerDeviceFingerprint, file.absolutePath, file.name, "audio/mp4", null, durationMs.toInt())
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@ChatActivity, result, Toast.LENGTH_SHORT).show()
                } else {
                    val obj = JSONObject(result)
                    adapter.addMessage(
                        SimpleChatAdapter.Item(
                            messageId = obj.optString("message_id"),
                            text = "",
                            isMine = true,
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
                    recycler.scrollToPosition(localMessages.size - 1)
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

    /**
     * Spec dışı: sesli mesaj oynat/duraklat — tek paylaşımlı bir
     * MediaPlayer kullanılır (aynı anda sadece bir sesli mesaj çalar).
     * Başka bir mesaj çalınıyorsa önce o durdurulur.
     */
    private fun onVoicePlayClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        if (attachment.status != SimpleChatAdapter.AttachmentStatus.COMPLETE) return

        if (voicePlayingFileId == attachment.fileId) {
            // Aynı mesaj — oynat/duraklat arasında geçiş.
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

        // Farklı bir mesaj — önce eskisini durdur, yenisini hazırla.
        stopVoicePlayback()
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
                    val player = MediaPlayer()
                    player.setDataSource(path)
                    player.setOnCompletionListener {
                        voicePlaybackHandler.removeCallbacks(voicePlaybackTickRunnable)
                        adapter.updateVoicePlayback(attachment.fileId, false, 0, voicePlaybackSpeed)
                    }
                    player.prepare()
                    voicePlaybackSpeed = attachment.playbackSpeed
                    if (voicePlaybackSpeed != 1f && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        player.playbackParams = PlaybackParams().setSpeed(voicePlaybackSpeed)
                    }
                    player.start()
                    voicePlayer = player
                    voicePlayingFileId = attachment.fileId
                    voicePlaybackHandler.post(voicePlaybackTickRunnable)
                    adapter.updateVoicePlayback(attachment.fileId, true, 0, voicePlaybackSpeed)
                } catch (e: Exception) {
                    Toast.makeText(this@ChatActivity, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /** bkz. `PlaybackSpeed` — sesli mesaj VE video oynatıcı AYNI hız
     *  listesini paylaşır. Çalan mesaj değişse bile hız tercihini item'da
     *  saklıyoruz ki bir daha oynatılınca hatırlansın. */
    private fun onVoiceSpeedClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        val newSpeed = PlaybackSpeed.next(attachment.playbackSpeed)
        if (voicePlayingFileId == attachment.fileId) {
            voicePlaybackSpeed = newSpeed
            val player = voicePlayer
            if (player != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    player.playbackParams = PlaybackParams().setSpeed(newSpeed)
                } catch (e: Exception) { /* bazı cihazlarda desteklenmeyen hız oranı olabilir */ }
            }
            adapter.updateVoicePlayback(attachment.fileId, player?.isPlaying ?: false, player?.currentPosition ?: 0, newSpeed)
        } else {
            attachment.playbackSpeed = newSpeed
            adapter.updateVoicePlayback(attachment.fileId, false, attachment.playbackPositionMs, newSpeed)
        }
    }

    private fun stopVoicePlayback() {
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
     * Spec dışı sağlamlaştırma: hem `onCreate` hem `onNewIntent` tarafından
     * çağrılır. `PendingIntent`'ler `FLAG_ACTIVITY_CLEAR_TOP` taşıdığından
     * (bkz. NotificationHelper), geri yığında zaten bir `ChatActivity`
     * varsa Android yeni bir örnek OLUŞTURMAZ — var olanı `onNewIntent` ile
     * çağırır. Önceden bu override edilmediği için bildirime tıklamak,
     * (varsa) yığındaki ESKİ sohbeti öne getiriyordu, bildirimin ait olduğu
     * sohbeti DEĞİL. Aynı kişi için gelen bir bildirimse (peer değişmedi)
     * mesaj listesini gereksiz yere sıfırlamıyoruz.
     *
     * Dönüş: `false` ise (peer fingerprint hiç yok) çağıran `finish()`
     * çağırmalı.
     */
    private fun bindToIntent(intent: Intent): Boolean {
        val newPeer = intent.getStringExtra(EXTRA_PEER_DEVICE_FINGERPRINT) ?: return false
        val displayName = intent.getStringExtra(EXTRA_PEER_DISPLAY_NAME) ?: newPeer.take(8)
        supportActionBar?.title = displayName

        if (::peerDeviceFingerprint.isInitialized && peerDeviceFingerprint == newPeer) {
            // Aynı sohbet için tekrar bir intent geldi (ör. aynı kişiden
            // ardışık bildirimler) — durumu sıfırlamaya gerek yok.
            return true
        }

        peerDeviceFingerprint = newPeer
        P2PService.activeConversationId = peerDeviceFingerprint

        localMessages.clear()
        adapter.notifyDataSetChanged()
        historySyncPending = false
        typingHandler.removeCallbacksAndMessages(null)
        peerIsTyping = false
        isTypingSent = false
        stopVoicePlayback()
        connectingBanner.visibility = View.VISIBLE
        sessionPollHandler.removeCallbacks(sessionPollRunnable)
        sessionPollHandler.post(sessionPollRunnable)

        loadHistoryIfAvailable()

        // Spec dışı sağlamlaştırma: sohbeti AÇAR açmaz (ilk mesaj yazılmadan
        // önce) el sıkışmayı proaktif başlatıyoruz — bkz. Rust
        // `ensure_handshake` notu. `sessionPollRunnable`, bu tamamlanana
        // kadar üstte bir "Bağlanılıyor..." göstergesi tutar.
        try {
            P2PLib.ensureHandshake(peerDeviceFingerprint)
        } catch (e: Exception) {
            // yoksay — sessionPollRunnable zaten periyodik kontrol edecek
        }
        return true
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!bindToIntent(intent)) {
            finish()
        }
    }

    /**
     * Spec dışı sağlamlaştırma: mesajı HER ZAMAN iyimser (optimistic) olarak
     * gösteriyoruz — Rust artık gönderim anında başarısız olsa bile mesajı
     * arka planda otomatik olarak yeniden dener (bkz. lib.rs
     * `pending_envelopes`) ve her durumda geçerli bir `message_id` ile
     * ilk durumu (`sent`/`pending`) döner. "pending" ise ikon saat simgesini
     * gösterir, arka planda kesinleşince bir "status" olayıyla güncellenir.
     */
    private fun sendNewMessage(text: String) {
        val result = P2PLib.sendMessage(peerDeviceFingerprint, text)
        val (messageId, status) = if (result.startsWith("Error:")) {
            Toast.makeText(this, result, Toast.LENGTH_SHORT).show()
            UUID.randomUUID().toString() to SimpleChatAdapter.Status.ERROR
        } else {
            try {
                val obj = JSONObject(result)
                obj.optString("message_id") to parseStatus(obj.optString("status"))
            } catch (e: Exception) {
                UUID.randomUUID().toString() to SimpleChatAdapter.Status.ERROR
            }
        }
        adapter.addMessage(SimpleChatAdapter.Item(messageId = messageId, text = text, isMine = true, status = status))
        recycler.scrollToPosition(localMessages.size - 1)
    }

    private fun parseStatus(status: String): SimpleChatAdapter.Status = when (status) {
        "sent" -> SimpleChatAdapter.Status.SENT
        "error" -> SimpleChatAdapter.Status.ERROR
        else -> SimpleChatAdapter.Status.PENDING
    }

    private fun parseAttachmentStatus(status: String): SimpleChatAdapter.AttachmentStatus = when (status) {
        "downloading" -> SimpleChatAdapter.AttachmentStatus.DOWNLOADING
        "complete" -> SimpleChatAdapter.AttachmentStatus.COMPLETE
        "failed" -> SimpleChatAdapter.AttachmentStatus.FAILED
        else -> SimpleChatAdapter.AttachmentStatus.OFFERED
    }

    private fun handleIncomingEvent(obj: JSONObject) {
        when (obj.optString("type")) {
            "message" -> {
                adapter.addMessage(
                    SimpleChatAdapter.Item(
                        messageId = obj.optString("message_id"),
                        text = obj.optString("text"),
                        isMine = false
                    )
                )
                recycler.scrollToPosition(localMessages.size - 1)
            }
            "edit" -> adapter.applyEdit(obj.optString("message_id"), obj.optString("text"))
            "delete" -> adapter.applyDelete(obj.optString("message_id"))
            "status" -> adapter.applyStatus(obj.optString("message_id"), parseStatus(obj.optString("status")))
            "history_sync" -> applyHistorySync(obj)
            "file_offer" -> {
                val autoDownloading = obj.optBoolean("auto_downloading", false)
                val previewHex = obj.optString("preview_hex", "")
                val previewJpeg = if (previewHex.isNotEmpty()) hexToBytes(previewHex) else null
                val durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it }
                adapter.addMessage(
                    SimpleChatAdapter.Item(
                        messageId = obj.optString("file_id"),
                        text = "",
                        isMine = false,
                        attachment = SimpleChatAdapter.AttachmentInfo(
                            fileId = obj.optString("file_id"),
                            fileName = obj.optString("file_name"),
                            mimeType = obj.optString("mime_type"),
                            totalSize = obj.optLong("total_size"),
                            status = if (autoDownloading) SimpleChatAdapter.AttachmentStatus.DOWNLOADING
                                      else SimpleChatAdapter.AttachmentStatus.OFFERED,
                            previewJpeg = previewJpeg,
                            durationMs = durationMs
                        )
                    )
                )
                recycler.scrollToPosition(localMessages.size - 1)
            }
            "file_progress" -> adapter.applyAttachmentUpdate(
                obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.DOWNLOADING, obj.optLong("bytes_done")
            )
            "file_complete" -> adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.COMPLETE)
            "file_failed" -> adapter.applyAttachmentUpdate(obj.optString("file_id"), SimpleChatAdapter.AttachmentStatus.FAILED)
            "save_request" -> showSaveRequestDialog(obj.optString("file_id"), obj.optString("file_name"))
            "save_response" -> handleSaveResponse(obj.optString("file_id"), obj.optBoolean("approved"))
            "typing" -> {
                peerIsTyping = obj.optBoolean("is_typing", false)
                typingHandler.removeCallbacks(clearPeerTypingRunnable)
                if (peerIsTyping) {
                    typingHandler.postDelayed(clearPeerTypingRunnable, TYPING_INDICATOR_TIMEOUT_MS)
                }
            }
        }
    }

    /** bkz. dosya başı "yazıyor..." notu — SADECE geçiş anında (false->true/
     *  true->false) çağrılır, `edtMessage`'ın TextWatcher'ı ve
     *  `stopTypingRunnable` (boşta kalma zaman aşımı) tarafından. */
    private fun sendTypingState(isTyping: Boolean) {
        if (isTypingSent == isTyping) return
        isTypingSent = isTyping
        try {
            P2PLib.sendTypingIndicator(peerDeviceFingerprint, isTyping)
        } catch (e: Exception) {
            // fire-and-forget — en kötü ihtimalle gösterge bir sonraki
            // paket kadar gecikir.
        }
    }

    /**
     * Spec dışı: BİZ bu dosyanın GÖNDERİCİSİYİZ — karşı taraf onu
     * "İndirilenler/P2P"ye kaydetmek istiyor, onayımızı bekliyor.
     */
    private fun showSaveRequestDialog(fileId: String, fileName: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.title_save_request)
            .setMessage(getString(R.string.msg_save_request, fileName))
            .setPositiveButton(R.string.action_approve) { _, _ ->
                lifecycleScope.launch(Dispatchers.IO) {
                    try {
                        P2PLib.respondToSaveRequest(fileId, peerDeviceFingerprint, true)
                    } catch (e: Exception) { /* en iyi çaba — karşı taraf zaten yeniden dener */ }
                }
            }
            .setNegativeButton(R.string.action_decline) { _, _ ->
                lifecycleScope.launch(Dispatchers.IO) {
                    try {
                        P2PLib.respondToSaveRequest(fileId, peerDeviceFingerprint, false)
                    } catch (e: Exception) { }
                }
            }
            .setCancelable(false)
            .show()
    }

    /**
     * Spec dışı: BİZ İSTEYENİZ — gönderdiğimiz SaveRequest'e cevap geldi.
     * Onaylandıysa, zaten çözülmüş (veya şimdi çözülecek) yerel kopyayı
     * MediaStore üzerinden "İndirilenler/P2P"ye kopyalar.
     */
    private fun handleSaveResponse(fileId: String, approved: Boolean) {
        if (!approved) {
            Toast.makeText(this, R.string.msg_save_declined, Toast.LENGTH_SHORT).show()
            return
        }
        val item = localMessages.find { it.attachment?.fileId == fileId }
        val attachment = item?.attachment ?: return
        lifecycleScope.launch(Dispatchers.IO) {
            val plainPath = try {
                P2PLib.getAttachmentPlaintextPath(fileId)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (plainPath.startsWith("Error:")) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@ChatActivity, plainPath, Toast.LENGTH_SHORT).show()
                }
                return@launch
            }
            val saved = saveToPublicDownloads(File(plainPath), attachment.fileName, attachment.mimeType)
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    this@ChatActivity,
                    if (saved) getString(R.string.msg_saved_to_downloads) else getString(R.string.error_attachment_open_failed),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    /**
     * "İndirilenler/P2P" içine kopyalar — API 29+'ta MediaStore.Downloads
     * ile hiçbir izin gerekmez (scoped storage); API 26-28'de
     * WRITE_EXTERNAL_STORAGE + doğrudan dosya yazımı gerekir (manifest'te
     * maxSdkVersion=28 ile tanımlı, bkz. AndroidManifest.xml notu).
     */
    private fun saveToPublicDownloads(source: File, displayName: String, mimeType: String): Boolean {
        return try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                val values = android.content.ContentValues().apply {
                    put(android.provider.MediaStore.Downloads.DISPLAY_NAME, displayName)
                    put(android.provider.MediaStore.Downloads.MIME_TYPE, mimeType.ifBlank { "application/octet-stream" })
                    put(android.provider.MediaStore.Downloads.RELATIVE_PATH, "Download/P2P")
                }
                val uri = contentResolver.insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: return false
                contentResolver.openOutputStream(uri)?.use { output ->
                    source.inputStream().use { input -> input.copyTo(output) }
                } ?: return false
                true
            } else {
                @Suppress("DEPRECATION")
                val downloadsDir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
                val p2pDir = File(downloadsDir, "P2P").apply { mkdirs() }
                val dest = File(p2pDir, displayName)
                source.inputStream().use { input -> dest.outputStream().use { output -> input.copyTo(output) } }
                // Galeri/dosya yöneticisinin yeni dosyayı hemen görmesi için.
                android.media.MediaScannerConnection.scanFile(this, arrayOf(dest.absolutePath), arrayOf(mimeType), null)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Spec dışı: bir ek balonuna basılı tutulunca (SADECE tamamlanmışsa,
     * bkz. SimpleChatAdapter) "İndirilenler/P2P"ye kaydet seçeneğini
     * gösterir. `item.isMine` ayrımı önemli: bu BİZİM gönderdiğimiz bir
     * dosyaysa (kendi kopyamız), onay istemeye gerek yok — doğrudan
     * kaydedilir. Karşı taraftan gelen bir dosyaysa, gerçek kaydetme
     * göndericinin onayından SONRA `handleSaveResponse`'ta gerçekleşir.
     */
    private fun onAttachmentLongClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        AlertDialog.Builder(this)
            .setItems(arrayOf(getString(R.string.action_save_to_downloads))) { _, _ ->
                if (item.isMine) {
                    saveOwnAttachment(attachment)
                } else {
                    lifecycleScope.launch(Dispatchers.IO) {
                        try {
                            P2PLib.requestSaveApproval(attachment.fileId, peerDeviceFingerprint, attachment.fileName)
                        } catch (e: Exception) { }
                    }
                    Toast.makeText(this, R.string.msg_save_request_sent, Toast.LENGTH_SHORT).show()
                }
            }
            .show()
    }

    /** Kendi gönderdiğimiz bir dosya — karşı taraftan onay istemeye gerek
     *  yok, doğrudan kaydedilir. */
    private fun saveOwnAttachment(attachment: SimpleChatAdapter.AttachmentInfo) {
        lifecycleScope.launch(Dispatchers.IO) {
            val plainPath = try {
                P2PLib.getAttachmentPlaintextPath(attachment.fileId)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (plainPath.startsWith("Error:")) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@ChatActivity, plainPath, Toast.LENGTH_SHORT).show()
                }
                return@launch
            }
            val saved = saveToPublicDownloads(File(plainPath), attachment.fileName, attachment.mimeType)
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    this@ChatActivity,
                    if (saved) getString(R.string.msg_saved_to_downloads) else getString(R.string.error_attachment_open_failed),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    /**
     * Spec dışı: bir ek balonuna dokunulduğunda (İndir düğmesi VEYA
     * tamamlanmış bir eke tıklama). OFFERED/FAILED -> indirmeyi başlatır
     * (hemen "DOWNLOADING" gösterip arka planda `downloadFile` çağırır —
     * asıl ilerleme/tamamlanma `pollNetwork` "file_progress"/"file_complete"
     * olaylarıyla gelecek). COMPLETE -> çözülmüş kopyanın yolunu alıp
     * sistem görüntüleyicisiyle açar.
     */
    private fun onAttachmentClicked(item: SimpleChatAdapter.Item) {
        val attachment = item.attachment ?: return
        when (attachment.status) {
            SimpleChatAdapter.AttachmentStatus.OFFERED, SimpleChatAdapter.AttachmentStatus.FAILED -> {
                adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.DOWNLOADING, 0)
                lifecycleScope.launch(Dispatchers.IO) {
                    // KRİTİK: dönüş değeri MUTLAKA kontrol edilmeli — Rust
                    // tarafı bir hata durumunda (ör. karşı taraf şu an
                    // erişilebilir değil) SENKRON olarak "Error: ..." döner
                    // ve bu durumda pollNetwork() üzerinden HİÇBİR olay
                    // gelmeyecektir (indirme hiç başlamadı). Önceden bu
                    // dönüş değeri (o zaman Boolean) hiç kontrol edilmiyordu
                    // — bu da başarısız bir indirmenin UI'de sonsuza kadar
                    // "İndiriliyor" gösterip 0MB'da takılı kalmasına yol
                    // açıyordu.
                    val result = try {
                        P2PLib.downloadFile(attachment.fileId, peerDeviceFingerprint)
                    } catch (e: Exception) {
                        "Error: ${e.message}"
                    }
                    if (result.startsWith("Error:")) {
                        withContext(Dispatchers.Main) {
                            adapter.applyAttachmentUpdate(attachment.fileId, SimpleChatAdapter.AttachmentStatus.FAILED)
                            Toast.makeText(this@ChatActivity, result, Toast.LENGTH_SHORT).show()
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
                            openAttachmentFile(path, attachment.mimeType)
                        }
                    }
                }
            }
            SimpleChatAdapter.AttachmentStatus.DOWNLOADING -> { /* no-op, zaten devam ediyor */ }
        }
    }

    /**
     * Spec dışı: foto/video için, kullanıcının istediği basit uygulama içi
     * görüntüleyiciyi (bkz. MediaViewerActivity) açar — diğer türler
     * (ses, belge...) hâlâ sistem varsayılan uygulamasına devredilir.
     */
    private fun openAttachmentFile(path: String, mimeType: String) {
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
                setDataAndType(uri, mimeType.ifBlank { "*/*" })
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Spec dışı: kullanıcının SAF (`OpenDocument`) ile seçtiği bir dosya/
     * foto/video/ses klibi. `content://` URI'sini doğrudan Rust'a
     * geçiremeyiz (JNI tarafı düz bir dosya sistemi yolu bekliyor, bkz.
     * P2PLib.kt notu) — önce uygulamanın önbellek dizinine (bounded buffer
     * ile, akış hâlinde) kopyalanır, sonra `prepareAndSendFile` çağrılır.
     * TAMAMI ana thread DIŞINDA (Dispatchers.IO) — 4GB'a kadar bir dosya
     * için bu kopyalama/şifreleme adımı saniyeler/on saniyeler sürebilir.
     */
    private fun onFilePicked(uri: Uri) {
        val fileName = queryDisplayName(uri) ?: "file"
        val mimeType = contentResolver.getType(uri) ?: "application/octet-stream"
        val size = querySize(uri)
        if (size != null && size > MAX_ATTACHMENT_SIZE) {
            Toast.makeText(this, "$fileName: 4GB sınırını aşıyor", Toast.LENGTH_LONG).show()
            return
        }
        Toast.makeText(this, fileName, Toast.LENGTH_SHORT).show()
        lifecycleScope.launch(Dispatchers.IO) {
            val tempFile = File(File(cacheDir, "outgoing").apply { mkdirs() }, UUID.randomUUID().toString())
            try {
                contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output ->
                        input.copyTo(output, bufferSize = 64 * 1024)
                    }
                } ?: throw java.io.IOException("Dosya açılamadı")

                // Spec dışı: foto/video ekleri için gönderen tarafta
                // (görünmez şekilde) küçük bir 480p/%85 JPEG önizleme
                // kapağı oluşturulur — alıcı tarafta TAM dosya hiç
                // indirilmeden gösterilebilsin diye (bkz.
                // P2PLib.prepareAndSendFile notu). Oluşturulamazsa (bozuk
                // dosya, desteklenmeyen codec vb.) sessizce `null` kalır —
                // önizleme opsiyoneldir, gönderimi ASLA engellemez.
                val previewJpeg = try {
                    when {
                        mimeType.startsWith("image/") -> generateImagePreview(tempFile)
                        mimeType.startsWith("video/") -> generateVideoPreview(tempFile)
                        else -> null
                    }
                } catch (e: Exception) {
                    null
                }

                val result = P2PLib.prepareAndSendFile(peerDeviceFingerprint, tempFile.absolutePath, fileName, mimeType, previewJpeg, -1)
                withContext(Dispatchers.Main) {
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this@ChatActivity, result, Toast.LENGTH_SHORT).show()
                    } else {
                        val obj = JSONObject(result)
                        adapter.addMessage(
                            SimpleChatAdapter.Item(
                                messageId = obj.optString("message_id"),
                                text = "",
                                isMine = true,
                                attachment = SimpleChatAdapter.AttachmentInfo(
                                    fileId = obj.optString("message_id"),
                                    fileName = fileName,
                                    mimeType = mimeType,
                                    totalSize = tempFile.length(),
                                    status = SimpleChatAdapter.AttachmentStatus.COMPLETE,
                                    bytesDone = tempFile.length(),
                                    previewJpeg = previewJpeg
                                )
                            )
                        )
                        recycler.scrollToPosition(localMessages.size - 1)
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@ChatActivity, getString(R.string.error_send_failed), Toast.LENGTH_SHORT).show()
                }
            } finally {
                tempFile.delete()
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

    /** `null` dönerse (bazı content provider'lar boyutu bildirmez) 4GB
     *  kontrolü atlanır — o durumda Rust tarafındaki asıl kontrol (bkz.
     *  MAX_ATTACHMENT_SIZE, lib.rs) son çare olarak devreye girer. */
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

    /** Spec dışı: bir görsel dosyasından 480p/%85 JPEG önizleme kapağı
     *  üretir — bkz. `ImagePreview.compressFile` (profil fotoğrafıyla
     *  paylaşılan ortak mantık, sadece hedef boyut farklı). */
    private fun generateImagePreview(file: File): ByteArray? =
        ImagePreview.compressFile(file, PREVIEW_MAX_DIMENSION, PREVIEW_JPEG_QUALITY)

    /**
     * Spec dışı: bir video dosyasından 480p/%85 JPEG önizleme kapağı
     * üretir — `MediaMetadataRetriever` ile ~1. saniyedeki kareyi (çoğu
     * video için siyah bir açılış karesinden kaçınmak için) alır, o da
     * yoksa (çok kısa video) ilk kareye düşer.
     */
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
     * Spec dışı: node modu kapalı cihazlarda yerel arşiv boş olduğunda
     * `loadHistoryIfAvailable`'ın gönderdiği `requestHistorySync` isteğine
     * karşı taraftan (node modu açıksa) gelen yanıt. `historySyncPending`
     * false ise (yerelde zaten geçmiş vardı, ya da peer bu sırada
     * değişti) sessizce yok sayılır — tekrar eklenmesin diye.
     */
    private fun applyHistorySync(obj: JSONObject) {
        if (!historySyncPending) return
        historySyncPending = false
        val array = obj.optJSONArray("messages") ?: return
        if (array.length() == 0) return
        val synced = (0 until array.length()).map { i ->
            val m = array.getJSONObject(i)
            SimpleChatAdapter.Item(
                messageId = UUID.randomUUID().toString(),
                text = m.optString("text"),
                isMine = m.optString("direction") == "sent",
                timestamp = m.optLong("timestamp", System.currentTimeMillis())
            )
        }
        if (localMessages.isEmpty()) {
            // Yerelde hiç geçmiş yoktu — tamamı senkrondan geliyor.
            localMessages.addAll(0, synced)
            adapter.notifyItemRangeInserted(0, synced.size)
        } else {
            // Spec dışı: "hangi cihazda daha güncel mesajlar varsa onunla
            // yenilensin" — yerelde zaten bir geçmiş varsa, karşı taraftan
            // gelenlerin SADECE elimizdeki en yeni mesajdan daha yeni
            // olanlarını sona ekliyoruz (ör. bu cihaz bir süre çevrimdışı
            // kalıp karşı tarafın gönderdiği mesajları kaçırmışsa). Zaten
            // sahip olduğumuz mesajları tekrar eklemiyoruz — `ArchivedMessage`
            // kararlı bir id taşımadığından (bilinen sınır, bkz. dosya
            // sonu not) eşleştirme zaman damgasına dayanıyor.
            val latestLocal = localMessages.maxOf { it.timestamp }
            val newer = synced.filter { it.timestamp > latestLocal }
            if (newer.isNotEmpty()) {
                localMessages.addAll(newer)
                adapter.notifyItemRangeInserted(localMessages.size - newer.size, newer.size)
                recycler.scrollToPosition(localMessages.size - 1)
            }
        }
    }

    /** Kendi mesajımıza uzun basınca: Düzenle/Sil seçenekleri. */
    private fun showEditDeleteDialog(item: SimpleChatAdapter.Item) {
        val options = arrayOf(getString(R.string.action_edit_message), getString(R.string.action_delete_message))
        AlertDialog.Builder(this)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> showEditMessageDialog(item)
                    1 -> confirmDeleteMessage(item)
                }
            }
            .show()
    }

    private fun showEditMessageDialog(item: SimpleChatAdapter.Item) {
        val input = EditText(this)
        input.setText(item.text)
        input.hint = getString(R.string.lbl_edit_message_hint)
        AlertDialog.Builder(this)
            .setTitle(R.string.action_edit_message)
            .setView(input)
            .setPositiveButton(R.string.action_edit_message) { _, _ ->
                val newText = input.text.toString()
                if (newText.isBlank()) return@setPositiveButton
                val result = P2PLib.editMessage(peerDeviceFingerprint, item.messageId, newText)
                if (result.startsWith("Error:")) {
                    Toast.makeText(this, result, Toast.LENGTH_SHORT).show()
                } else {
                    adapter.applyEdit(item.messageId, newText)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDeleteMessage(item: SimpleChatAdapter.Item) {
        AlertDialog.Builder(this)
            .setMessage(R.string.confirm_delete_message)
            .setPositiveButton(R.string.action_delete_message) { _, _ ->
                val result = P2PLib.deleteMessage(peerDeviceFingerprint, item.messageId)
                if (result.startsWith("Error:")) {
                    Toast.makeText(this, result, Toast.LENGTH_SHORT).show()
                } else {
                    adapter.applyDelete(item.messageId)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Node modu açıksa (dolayısıyla history key yüklüyse) bu kişiyle olan
     * şifreli arşivi çözüp gösterir. Node modu kapalıysa veya arşiv boşsa,
     * yerelde hiç geçmiş yoksa karşı tarafa (chat peer) şifreli bir
     * `HistorySyncRequest` gönderilir — o cihaz node modu açıksa zaten bu
     * konuşmanın her iki yönünü de arşivlemiştir (bkz.
     * `P2PLib.requestHistorySync`). Yanıt asenkron gelir; bkz.
     * `applyHistorySync`.
     *
     * BİLİNEN SINIR: arşiv (`ArchivedMessage`) bir `message_id` taşımıyor
     * (DB şeması bunu hiç saklamadı) — bu yüzden geçmişten yüklenen
     * mesajlar için rastgele bir yerel id üretiliyor. Bu satırlar teknik
     * olarak "uzun basılabilir" ama gerçek edit/delete hedefi olamazlar
     * (karşı taraf farklı bir id ile gönderdi) — spec dışı bir sınırlama.
     */
    private fun loadHistoryIfAvailable() {
        val textItems = mutableListOf<SimpleChatAdapter.Item>()
        val json = try {
            P2PLib.getMessageHistory(peerDeviceFingerprint, HISTORY_LOAD_LIMIT)
        } catch (e: Exception) {
            null
        }
        val array = try {
            if (json != null) JSONArray(json) else null
        } catch (e: Exception) {
            null
        }
        if (array != null) {
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                val direction = obj.optString("direction")
                val text = obj.optString("text")
                val timestamp = obj.optLong("timestamp", System.currentTimeMillis())
                textItems.add(
                    SimpleChatAdapter.Item(
                        messageId = UUID.randomUUID().toString(),
                        text = text,
                        isMine = direction == "sent",
                        timestamp = timestamp
                    )
                )
            }
        }
        // Spec dışı: geçmişte gönderilmiş/alınmış dosya ekleri önceden hiç
        // yeniden yüklenmiyordu (sadece metin mesajları) — artık
        // `listAttachments` ile aynı anda çekilip zaman damgasına göre
        // metin mesajlarıyla ARAYA SERPİŞTİRİLİYOR, tıpkı canlı sohbette
        // olduğu gibi kronolojik sırada görünsünler diye.
        val attachmentItems = mutableListOf<SimpleChatAdapter.Item>()
        val attachmentsJson = try {
            P2PLib.listAttachments(peerDeviceFingerprint)
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
                            durationMs = obj.optInt("duration_ms", -1).let { if (it < 0) null else it }
                        )
                    )
                )
            }
        }
        val merged = (textItems + attachmentItems).sortedBy { it.timestamp }
        localMessages.addAll(merged)
        if (localMessages.isNotEmpty()) {
            adapter.notifyItemRangeInserted(0, localMessages.size)
            recycler.scrollToPosition(localMessages.size - 1)
        }
        // Spec dışı: önceden SADECE yerel geçmiş boşsa senkron isteniyordu
        // — artık her sohbet açılışında deneniyor (yerel geçmiş olsun ya
        // da olmasın), çünkü karşı taraf bu cihazın kaçırdığı DAHA YENİ
        // mesajlara sahip olabilir (bkz. applyHistorySync'teki
        // "sadece daha yeni olanları ekle" birleştirme mantığı). Karşı
        // taraf erişilemezse veya node modu kapalıysa istek sessizce
        // yanıtsız kalır — mevcut yerel görünüm etkilenmez.
        historySyncPending = true
        try {
            P2PLib.requestHistorySync(peerDeviceFingerprint, HISTORY_SYNC_LIMIT)
        } catch (e: Exception) {
            historySyncPending = false
        }
    }

    override fun onResume() {
        super.onResume()
        P2PService.addMessageListener(messageListener)
        P2PService.activeConversationId = peerDeviceFingerprint
        sessionPollHandler.post(sessionPollRunnable)
    }

    override fun onPause() {
        super.onPause()
        P2PService.removeMessageListener(messageListener)
        if (P2PService.activeConversationId == peerDeviceFingerprint) {
            P2PService.activeConversationId = null
        }
        sessionPollHandler.removeCallbacks(sessionPollRunnable)
        typingHandler.removeCallbacksAndMessages(null)
        sendTypingState(false)
        if (mediaRecorder != null) finishVoiceRecording(send = false)
        stopVoicePlayback()
    }
}
