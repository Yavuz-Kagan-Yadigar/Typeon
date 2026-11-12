package com.p2p.messenger.ui

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.PictureInPictureParams
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.SurfaceTexture
import android.media.AudioManager
import android.media.RingtoneManager
import android.media.ToneGenerator
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.util.Rational
import android.util.Size
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.CallMedia
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * The one call screen: outgoing ring, incoming ring, in call — 1:1 and group,
 * voice and video. All call state lives in Rust (`call.rs`); this screen polls
 * `P2PLib.callState()` (twice a second in a call, plus `call_state` events) and renders it, so there is no second
 * state machine here to drift out of sync.
 */
class CallActivity : AppCompatActivity() {

    companion object {
        /** The call screen is in picture-in-picture: `P2PApplication` does
         *  not count it as a visible screen for the background lock (fable J-02). */
        @Volatile var inPip = false

        private const val TAG = "CallActivity"
        const val EXTRA_PEER = "call_peer"
        const val EXTRA_GROUP = "call_group"
        const val EXTRA_VIDEO = "call_video"
        private const val CHANNEL_ID = "calls"
        const val NOTIFICATION_ID = 0x0CA11
        private const val REQ_PERMS = 41
        private const val ACTION_PIP_MUTE = "com.p2p.messenger.CALL_PIP_MUTE"

        /** From a chat screen: ring [peer] (1:1) or every member of [groupId]. */
        fun startOutgoing(context: Context, peer: String?, groupId: String?, video: Boolean) {
            // The platform Opus encoder arrived with Android 10: below it the
            // call connected with no outgoing audio and no error.
            if (android.os.Build.VERSION.SDK_INT < 29) {
                Toast.makeText(context, R.string.call_needs_android10, Toast.LENGTH_LONG).show()
                return
            }
            context.startActivity(Intent(context, CallActivity::class.java).apply {
                putExtra(EXTRA_PEER, peer)
                putExtra(EXTRA_GROUP, groupId)
                putExtra(EXTRA_VIDEO, video)
            })
        }

        /** From P2PService on an incoming Invite: a full-screen call notification
         *  (the only way to surface an activity from the background), plus a
         *  direct start that works when the app is in the foreground. */
        fun ring(context: Context, name: String, video: Boolean) {
            // Same limit as `startOutgoing`: an accepted call sent no audio.
            if (android.os.Build.VERSION.SDK_INT < 29) {
                Thread { try { P2PLib.endCall() } catch (e: Throwable) { } }.start()
                return
            }
            val intent = Intent(context, CallActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val pending = PendingIntent.getActivity(
                context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, context.getString(R.string.call_channel_name), NotificationManager.IMPORTANCE_HIGH)
            )
            val text = context.getString(if (video) R.string.call_incoming_video else R.string.call_incoming_voice)
            // Lock screen: no caller name (same as message notifications).
            val publicVersion = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(context.getString(R.string.app_name))
                .setContentText(text)
                .build()
            val n = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setPublicVersion(publicVersion)
                .setContentTitle(name)
                .setContentText(text)
                .setCategory(NotificationCompat.CATEGORY_CALL)
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setOngoing(true)
                .setTimeoutAfter(45_000)
                .setContentIntent(pending)
                .setFullScreenIntent(pending, true)
                .build()
            try { nm.notify(NOTIFICATION_ID, n) } catch (e: SecurityException) { Log.w(TAG, "No notification permission") }
            try { context.startActivity(intent) } catch (e: Exception) { Log.w(TAG, "Background start blocked, notification only") }
        }

        fun cancelRing(context: Context) {
            context.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        }
    }

    private val ui = Handler(Looper.getMainLooper())
    /** Discards after shutdown: `poll()` can re-arm itself from a task that
     *  was still in flight when `onDestroy` shut the executor down — a plain
     *  `AbortPolicy` threw RejectedExecutionException on the UI thread
     *  (same deliberate pattern as WhiteboardPanel's `DiscardPolicy`). */
    private val io = java.util.concurrent.ThreadPoolExecutor(
        1, 1, 0L, java.util.concurrent.TimeUnit.MILLISECONDS,
        java.util.concurrent.LinkedBlockingQueue(), java.util.concurrent.ThreadPoolExecutor.DiscardPolicy()
    )
    private lateinit var txtName: TextView
    private lateinit var txtStatus: TextView
    private lateinit var grid: LinearLayout
    private lateinit var header: View
    private lateinit var bar: View
    private lateinit var selfView: PreviewView
    private lateinit var btnAccept: Button
    private lateinit var btnHangup: Button
    private lateinit var btnMute: Button
    private lateinit var btnSpeaker: Button
    private lateinit var btnCamera: Button
    private lateinit var btnPip: Button

    /** Saw a non-idle state at least once — only then does "idle" mean "ended". */
    private var callSeen = false
    private val createdAt = android.os.SystemClock.elapsedRealtime()
    private var starting = false
    private var finishingAt = 0L
    private var mediaRunning = false
    private var video = false
    private var state = "idle"
    private var ringtone: android.media.Ringtone? = null
    private var ringback: ToneGenerator? = null
    private var cameraProvider: ProcessCameraProvider? = null
    private var imageAnalysis: ImageAnalysis? = null
    private val analysisExecutor = Executors.newSingleThreadExecutor()
    /** slot -> tile */
    private val tiles = HashMap<Int, Tile>()
    /** H140: phase/participant changes arrive as `call_state` events (same
     *  JSON as `callState()`); the poll below only keeps the timer and media
     *  stats moving. */
    private val keepPollFast: (String) -> Unit = { msg ->
        if (msg.contains("call_state")) {
            val json = try { JSONObject(msg) } catch (e: Exception) { null }
            if (json != null && json.optString("type") == "call_state") ui.post { if (!isDestroyed && !isFinishing) render(json) }
        }
    }

    private class Tile(val root: FrameLayout, val label: TextView, var texture: TextureView?) {
        var mutedShown = false
        var avatar: ImageView? = null
        var peer = ""
        var framed = false
        var videoW = 0
        var videoH = 0
    }

    /** The ring opened this screen while the app was in the background: when
     *  the call ends, go back to what the user was doing, not to the app's
     *  password prompt (the task's own screens are still locked). */
    private var cameFromBackground = false

    override fun finish() {
        if (cameFromBackground) moveTaskToBack(true)
        super.finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        cameFromBackground = !com.p2p.messenger.service.P2PService.appVisible
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        supportActionBar?.hide()
        setContentView(buildLayout())
        video = intent.getBooleanExtra(EXTRA_VIDEO, false)
        val peer = intent.getStringExtra(EXTRA_PEER)
        val group = intent.getStringExtra(EXTRA_GROUP)
        if (savedInstanceState == null && (peer != null || group != null)) {
            starting = true
            txtStatus.setText(R.string.call_calling)
            if (hasPermissions(video)) placeCall(peer, group) else requestPermissions(video)
        }
        // Keeps the service poll loop at its fast rate for signalling/link
        // upkeep. For the whole life of the screen, not onStart..onStop: a
        // call with the screen off or behind another app dropped into power
        // save.
        androidx.core.content.ContextCompat.registerReceiver(
            this, pipMuteReceiver, android.content.IntentFilter(ACTION_PIP_MUTE), androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
        )
        P2PService.addMessageListener(keepPollFast)
        poll()
    }

    override fun onDestroy() {
        Companion.inPip = false
        P2PService.removeMessageListener(keepPollFast)
        unregisterReceiver(pipMuteReceiver)
        ui.removeCallbacksAndMessages(null)
        stopTones()
        stopMedia()
        // Leaving the screen any other way than Hang up must not leave a
        // zombie call ringing or holding the mic on the other side.
        if (isFinishing && state != "idle") io.execute { P2PLib.endCall() }
        io.shutdown()
        analysisExecutor.shutdown()
        super.onDestroy()
    }

    @Deprecated("Back would leave a call running with no screen; use Hang up.")
    override fun onBackPressed() {
        if (!enterPip()) moveTaskToBack(true)
    }

    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        enterPip()
    }

    /** Shrinks the call into the system's draggable picture-in-picture window.
     *  Not while ringing in: Accept has to stay reachable. */
    private fun enterPip(): Boolean {
        if (state != "active" && state != "outgoing") return false
        if (!packageManager.hasSystemFeature(PackageManager.FEATURE_PICTURE_IN_PICTURE)) return false
        val ratio = if (video) Rational(3, 4) else Rational(16, 9)
        return try {
            enterPictureInPictureMode(pipParams(ratio))
        } catch (e: IllegalStateException) {
            false
        }
    }

    private fun pipParams(ratio: Rational = if (video) Rational(3, 4) else Rational(16, 9)): PictureInPictureParams {
        val muted = CallMedia.muted
        val pi = PendingIntent.getBroadcast(
            this, 0, Intent(ACTION_PIP_MUTE).setPackage(packageName), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val title = getString(if (muted) R.string.call_unmute else R.string.call_mute)
        val action = android.app.RemoteAction(
            android.graphics.drawable.Icon.createWithResource(this, if (muted) R.drawable.ic_mic_off else R.drawable.ic_mic), title, title, pi
        )
        return PictureInPictureParams.Builder().setAspectRatio(ratio).setActions(listOf(action)).build()
    }

    private fun toggleMute() {
        CallMedia.muted = !CallMedia.muted
        btnMute.setText(if (CallMedia.muted) R.string.call_unmute else R.string.call_mute)
        if (isInPictureInPictureMode) setPictureInPictureParams(pipParams())
    }

    private val pipMuteReceiver = object : android.content.BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) { toggleMute() }
    }

    override fun onPictureInPictureModeChanged(inPip: Boolean, newConfig: Configuration) {
        super.onPictureInPictureModeChanged(inPip, newConfig)
        // The call screen stays started in PiP, so the app never counts as
        // backgrounded and never locked. A screen of this app that starts
        // right after (PiP by Back) clears the mark again in `guard`.
        if (inPip) com.p2p.messenger.util.AppLock.lock()
        Companion.inPip = inPip
        val dp = resources.displayMetrics.density
        header.visibility = if (inPip) View.GONE else View.VISIBLE
        bar.visibility = if (inPip) View.GONE else View.VISIBLE
        selfView.visibility = if (!inPip && cameraProvider != null && CallMedia.videoEncoder?.enabled == true) View.VISIBLE else View.GONE
        (grid.layoutParams as FrameLayout.LayoutParams).apply {
            topMargin = if (inPip) 0 else (96 * dp).toInt()
            bottomMargin = if (inPip) 0 else (88 * dp).toInt()
        }
        grid.requestLayout()
    }

    /** The manifest keeps this screen alive across a rotation, so the use
     *  case kept the rotation it was bound with and the other side saw the
     *  picture sideways after the sender turned the phone. */
    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        @Suppress("DEPRECATION")
        imageAnalysis?.targetRotation = windowManager.defaultDisplay.rotation
    }

    // ---------------------------------------------------------------- actions

    private fun placeCall(peer: String?, group: String?) {
        io.execute {
            val r = if (group != null) P2PLib.startGroupCall(group, video) else P2PLib.startCall(peer ?: "", video)
            ui.post {
                starting = false
                if (r.startsWith("Error")) {
                    Toast.makeText(this, com.p2p.messenger.util.coreErrorText(this, r), Toast.LENGTH_LONG).show()
                    finish()
                }
            }
        }
    }

    private fun accept() {
        if (!hasPermissions(video)) { requestPermissions(video); return }
        btnAccept.isEnabled = false
        // A refused accept must leave the button usable: the call still rings.
        io.execute { if (!P2PLib.acceptCall()) ui.post { btnAccept.isEnabled = true } }
    }

    private fun hangup() {
        io.execute { P2PLib.endCall() }
        state = "idle"
        stopMedia()
        finish()
    }

    private fun hasPermissions(video: Boolean): Boolean =
        perms(video).all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }

    private fun perms(video: Boolean) =
        if (video) arrayOf(Manifest.permission.RECORD_AUDIO, Manifest.permission.CAMERA) else arrayOf(Manifest.permission.RECORD_AUDIO)

    private fun requestPermissions(video: Boolean) =
        ActivityCompat.requestPermissions(this, perms(video), REQ_PERMS)

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_PERMS) return
        if (grantResults.isEmpty() || grantResults[0] != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this, R.string.call_permission_needed, Toast.LENGTH_LONG).show()
            if (starting) finish()
            return
        }
        // Camera may be denied on a video call: continue audio-only.
        if (grantResults.size > 1 && grantResults[1] != PackageManager.PERMISSION_GRANTED) video = false
        if (starting) placeCall(intent.getStringExtra(EXTRA_PEER), intent.getStringExtra(EXTRA_GROUP))
        else if (state == "incoming") accept()
        // Granted while the call was already active: media never started.
        else if (state == "active") startMedia()
    }

    // ---------------------------------------------------------------- state

    private fun poll() {
        io.execute {
            val json = try { JSONObject(P2PLib.callState()) } catch (e: Exception) { null }
            ui.post {
                if (isDestroyed) return@post
                if (json != null && !isFinishing) render(json)
                // After the answer, not on a fixed clock: with the core lock
                // busy the queries piled up behind each other.
                // Timer/media stats need 2 Hz in a call; otherwise the
                // `call_state` event drives the screen, this is a fallback.
                ui.postDelayed(::poll, if (state == "active") 500 else 5000)
            }
        }
    }

    private fun render(s: JSONObject) {
        val newState = s.optString("state", "idle")
        if (newState != "idle") {
            callSeen = true
            if (!mediaRunning && !starting) video = s.optBoolean("video", video)
        }
        if (newState != state) onStateChanged(state, newState, s)
        state = newState
        if (newState == "idle") {
            // Opened from a ring that already ended (timeout, caller hung up).
            if (!callSeen && !starting && android.os.SystemClock.elapsedRealtime() - createdAt > 2000) finish()
            return
        }

        // Over the lock screen the caller stays hidden, same as the ring notification.
        val locked = (getSystemService(android.content.Context.KEYGUARD_SERVICE) as? android.app.KeyguardManager)?.isKeyguardLocked == true
        txtName.text = if (locked) getString(R.string.app_name) else s.optString("name")
        val participants = s.optJSONArray("participants")
        when (newState) {
            "outgoing" -> txtStatus.setText(R.string.call_calling)
            "incoming" -> txtStatus.setText(if (video) R.string.call_incoming_video else R.string.call_incoming_voice)
            "active" -> {
                val secs = (s.optLong("now") - s.optLong("connected_at")).coerceAtLeast(0) / 1000
                val media = s.optJSONObject("media")
                val path = when {
                    media == null -> ""
                    media.optInt("direct_links") > 0 && media.optLong("via_direct") > 0 -> getString(R.string.call_via_p2p)
                    media.optInt("relay_links") > 0 -> getString(R.string.call_via_server)
                    else -> getString(R.string.call_connecting)
                }
                txtStatus.text = String.format("%02d:%02d · %s", secs / 60, secs % 60, path)
            }
        }
        btnAccept.visibility = if (newState == "incoming") View.VISIBLE else View.GONE
        btnHangup.setText(if (newState == "incoming") R.string.call_decline else R.string.call_hangup)
        val inCall = newState == "active"
        btnMute.visibility = if (inCall) View.VISIBLE else View.GONE
        btnSpeaker.visibility = if (inCall) View.VISIBLE else View.GONE
        btnCamera.visibility = if (inCall && video) View.VISIBLE else View.GONE
        btnPip.visibility = if (inCall || newState == "outgoing") View.VISIBLE else View.GONE
        if (inCall && participants != null) { syncTiles(participants); frameTiles() }
    }

    private fun onStateChanged(old: String, new: String, s: JSONObject) {
        stopTones()
        if (new != "idle") finishingAt = 0L
        when (new) {
            "incoming" -> {
                try {
                    ringtone = RingtoneManager.getRingtone(this, RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE))?.also { it.play() }
                } catch (e: Exception) { }
            }
            "outgoing" -> {
                try { ringback = ToneGenerator(AudioManager.STREAM_VOICE_CALL, 70).also { it.startTone(ToneGenerator.TONE_SUP_RINGTONE) } } catch (e: Exception) { }
            }
            "active" -> {
                cancelRing(this)
                startMedia()
            }
            "idle" -> {
                cancelRing(this)
                stopMedia()
                if (!callSeen && starting) return // our own call not created yet
                if (finishingAt == 0L) {
                    finishingAt = System.currentTimeMillis()
                    txtStatus.setText(
                        when (s.optString("reason")) {
                            "rejected" -> R.string.call_rejected
                            "busy" -> R.string.call_busy
                            "no_answer" -> R.string.call_no_answer
                            "missed" -> R.string.call_missed
                            else -> R.string.call_ended
                        }
                    )
                    btnAccept.visibility = View.GONE
                    // Not if another call arrived on this screen meanwhile.
                    ui.postDelayed({ if (state == "idle") finish() }, 1500)
                }
            }
        }
        if (old == "incoming" && new != "incoming") cancelRing(this)
    }

    private fun stopTones() {
        try { ringtone?.stop() } catch (e: Exception) { }
        ringtone = null
        try { ringback?.stopTone(); ringback?.release() } catch (e: Exception) { }
        ringback = null
    }

    // ---------------------------------------------------------------- media

    private fun startMedia() {
        if (mediaRunning) return
        if (!hasPermissions(false)) { requestPermissions(video); return }
        mediaRunning = true
        P2PService.setCallActive(this, true)
        val am = getSystemService(AudioManager::class.java)
        am.mode = AudioManager.MODE_IN_COMMUNICATION
        @Suppress("DEPRECATION")
        am.isSpeakerphoneOn = video
        updateSpeakerLabel()
        CallMedia.start(video && hasPermissions(true))
        if (video && hasPermissions(true)) startCamera()
    }

    private fun stopMedia() {
        if (!mediaRunning) return
        mediaRunning = false
        P2PService.setCallActive(this, false)
        cameraProvider?.unbindAll()
        cameraProvider = null
        selfView.visibility = View.GONE
        CallMedia.stop()
        tiles.clear()
        grid.removeAllViews()
        val am = getSystemService(AudioManager::class.java)
        @Suppress("DEPRECATION")
        am.isSpeakerphoneOn = false
        am.mode = AudioManager.MODE_NORMAL
    }

    private fun startCamera() {
        selfView.visibility = if (isInPictureInPictureMode) View.GONE else View.VISIBLE
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            if (!mediaRunning) return@addListener
            val provider = try { future.get() } catch (e: Exception) { return@addListener }
            val selector = ResolutionSelector.Builder()
                .setAspectRatioStrategy(AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY)
                .setResolutionStrategy(ResolutionStrategy(Size(640, 480), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER))
                .build()
            val preview = Preview.Builder().setResolutionSelector(selector).build().also {
                it.setSurfaceProvider(selfView.surfaceProvider)
            }
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(selector)
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                .build()
            imageAnalysis = analysis
            analysis.setAnalyzer(analysisExecutor) { image ->
                try { CallMedia.videoEncoder?.encode(image) } catch (e: Exception) {
                    Log.w(TAG, "Video encode failed", e)
                } finally { image.close() }
            }
            try {
                provider.unbindAll()
                provider.bindToLifecycle(this, CameraSelector.DEFAULT_FRONT_CAMERA, preview, analysis)
                cameraProvider = provider
            } catch (e: Exception) {
                Log.w(TAG, "Camera bind failed", e)
                selfView.visibility = View.GONE
            }
        }, ContextCompat.getMainExecutor(this))
    }

    /** One tile per joined participant; a TextureView in it on video calls. */
    private fun syncTiles(participants: org.json.JSONArray) {
        val live = HashMap<Int, JSONObject>()
        for (i in 0 until participants.length()) {
            val p = participants.getJSONObject(i)
            if (!p.optBoolean("joined") || p.isNull("slot")) continue
            live[p.getInt("slot")] = p
        }
        for (slot in tiles.keys.toList()) {
            if (slot !in live) {
                grid.removeView(tiles.remove(slot)!!.root)
                CallMedia.dropSlot(slot)
            }
        }
        for ((slot, p) in live) {
            val tile = tiles[slot] ?: newTile(slot).also { tiles[slot] = it; grid.addView(it.root) }
            tile.label.text = p.optString("name")
            // Camera off on their side: hide the last frame instead of freezing on it.
            val camOff = p.optBoolean("video_off")
            tile.texture?.visibility = if (camOff) View.INVISIBLE else View.VISIBLE
            // Camera off (or voice call): their profile picture instead of a black tile.
            tile.avatar?.visibility = if (camOff || tile.texture == null) View.VISIBLE else View.GONE
            val peerKey = p.optString("peer")
            if (tile.peer != peerKey) {
                tile.peer = peerKey
                loadAvatar(tile, peerKey, p.optString("name"))
            }
            // Muted participants get a mic-off icon before their name.
            val muted = p.optBoolean("muted")
            if (muted != tile.mutedShown) {
                tile.mutedShown = muted
                tile.label.setCompoundDrawablesRelativeWithIntrinsicBounds(if (muted) R.drawable.ic_mic_off else 0, 0, 0, 0)
                tile.label.compoundDrawablePadding = (6 * resources.displayMetrics.density).toInt()
            }
        }
    }

    private fun newTile(slot: Int): Tile {
        val root = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
            setBackgroundColor(Color.rgb(24, 24, 28))
        }
        val label = TextView(this).apply {
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER_VERTICAL
            textSize = if (video) 14f else 22f
            setPadding(24, 12, 24, 12)
        }
        var texture: TextureView? = null
        if (video) {
            texture = TextureView(this).apply {
                layoutParams = FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT, Gravity.CENTER)
                surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                    override fun onSurfaceTextureAvailable(st: SurfaceTexture, w: Int, h: Int) {
                        val tv = this@apply
                        CallMedia.attachVideo(slot, Surface(st)) { vw, vh ->
                            ui.post { tiles[slot]?.let { it.videoW = vw; it.videoH = vh }; fitVideo(tv, root, vw, vh) }
                        }
                    }
                    override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) {}
                    override fun onSurfaceTextureDestroyed(st: SurfaceTexture): Boolean { CallMedia.dropSlot(slot); return true }
                    override fun onSurfaceTextureUpdated(st: SurfaceTexture) {}
                }
            }
            root.addView(texture)
        }
        val size = (112 * resources.displayMetrics.density).toInt()
        root.addView(label, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            if (video) Gravity.BOTTOM or Gravity.START else Gravity.CENTER
        ).apply {
            // Centred with the avatar: a top margin of one avatar plus a gap
            // moves the name just below the circle instead of across it.
            if (!video) topMargin = size + (16 * resources.displayMetrics.density).toInt()
        })
        val avatar = ImageView(this).apply { visibility = View.GONE }
        root.addView(avatar, 0, FrameLayout.LayoutParams(size, size, Gravity.CENTER))
        val tile = Tile(root, label, texture).also { it.avatar = avatar }
        // The tile is resized when the call enters or leaves picture-in-picture.
        root.addOnLayoutChangeListener { _, l, t, r, b, oldL, oldT, oldR, oldB ->
            if (r - l != oldR - oldL || b - t != oldB - oldT) texture?.let { tv -> root.post { fitVideo(tv, root, tile.videoW, tile.videoH) } }
        }
        return tile
    }

    /** Fingerprint -> avatar jpeg; an EMPTY array means "no avatar" (the full
     *  `listContacts()` dump was scanned by a fresh Thread per tile, per
     *  participant, while a call screen re-renders twice a second). */
    private val peerAvatars = HashMap<String, ByteArray>()

    /** Placeholder now; the real picture once the contact list is read (off the UI thread). */
    private fun loadAvatar(tile: Tile, peer: String, name: String) {
        com.p2p.messenger.util.AvatarUtil.renderInto(tile.avatar!!, null, name)
        val cached = synchronized(peerAvatars) { peerAvatars[peer] }
        if (cached != null) {
            // One scan per distinct peer, not one Thread + listContacts() per
            // tile: re-renders, PiP round-trips and rejoining participants
            // all hit this path.
            if (cached.isNotEmpty()) com.p2p.messenger.util.AvatarUtil.renderInto(tile.avatar!!, cached, name)
            return
        }
        io.execute {
            val jpeg = try {
                val a = org.json.JSONArray(P2PLib.listContacts())
                (0 until a.length()).map { a.getJSONObject(it) }
                    .firstOrNull { it.optString("active_device_fingerprint") == peer }
                    ?.optString("avatar_hex")?.ifEmpty { null }?.let { com.p2p.messenger.util.hexToBytes(it) }
            } catch (e: Exception) { null }
            synchronized(peerAvatars) { peerAvatars[peer] = jpeg ?: ByteArray(0) }
            if (jpeg != null) ui.post {
                if (!isDestroyed && tile.peer == peer) com.p2p.messenger.util.AvatarUtil.renderInto(tile.avatar!!, jpeg, name)
            }
        }
    }

    /** Accent frame around a tile while its participant speaks. */
    private fun frameTiles() {
        for ((slot, t) in tiles) {
            val on = CallMedia.isSpeaking(slot)
            if (on == t.framed) continue
            t.framed = on
            t.root.foreground = if (!on) null else android.graphics.drawable.GradientDrawable().apply {
                setStroke((3 * resources.displayMetrics.density).toInt(),
                    com.p2p.messenger.util.ThemePrefs.getAccentColor(this@CallActivity)
                        ?: com.google.android.material.color.MaterialColors.getColor(t.root, androidx.appcompat.R.attr.colorPrimary))
            }
        }
    }

    /** Letterbox the remote video into its tile, keeping the aspect ratio. */
    private fun fitVideo(tv: TextureView, box: View, vw: Int, vh: Int) {
        if (vw <= 0 || vh <= 0 || box.width == 0 || box.height == 0) return
        val scale = minOf(box.width.toFloat() / vw, box.height.toFloat() / vh)
        tv.layoutParams = FrameLayout.LayoutParams((vw * scale).toInt(), (vh * scale).toInt(), Gravity.CENTER)
    }

    private fun updateSpeakerLabel() {
        @Suppress("DEPRECATION")
        val on = getSystemService(AudioManager::class.java).isSpeakerphoneOn
        btnSpeaker.setText(if (on) R.string.call_earpiece else R.string.call_speaker)
    }

    // ---------------------------------------------------------------- layout

    private fun buildLayout(): View {
        val dp = resources.displayMetrics.density
        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        grid = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(grid, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT).apply {
            topMargin = (96 * dp).toInt(); bottomMargin = (88 * dp).toInt()
        })
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding((20 * dp).toInt(), (28 * dp).toInt(), (20 * dp).toInt(), 0)
        }
        txtName = TextView(this).apply { setTextColor(Color.WHITE); textSize = 24f }
        txtStatus = TextView(this).apply { setTextColor(Color.LTGRAY); textSize = 15f }
        header.addView(txtName)
        header.addView(txtStatus)
        root.addView(header)
        this.header = header
        selfView = PreviewView(this).apply {
            visibility = View.GONE
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
        root.addView(selfView, FrameLayout.LayoutParams((110 * dp).toInt(), (147 * dp).toInt(), Gravity.TOP or Gravity.END).apply {
            topMargin = (100 * dp).toInt(); rightMargin = (12 * dp).toInt()
        })
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, (20 * dp).toInt())
        }
        fun button(text: Int, color: Int, onClick: () -> Unit) = Button(this).apply {
            setText(text)
            setTextColor(Color.WHITE)
            isAllCaps = false
            maxLines = 1
            textSize = 13f
            setPadding((8 * dp).toInt(), 0, (8 * dp).toInt(), 0)
            minHeight = (48 * dp).toInt()
            background = android.graphics.drawable.GradientDrawable().apply {
                shape = android.graphics.drawable.GradientDrawable.RECTANGLE
                cornerRadius = 100 * dp
                setColor(color)
            }
            setOnClickListener { onClick() }
            bar.addView(this, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = (4 * dp).toInt(); marginEnd = (4 * dp).toInt()
            })
        }
        val grey = Color.rgb(60, 60, 66)
        btnMute = button(R.string.call_mute, grey) { toggleMute() }
        btnSpeaker = button(R.string.call_speaker, grey) {
            val am = getSystemService(AudioManager::class.java)
            @Suppress("DEPRECATION")
            am.isSpeakerphoneOn = !am.isSpeakerphoneOn
            updateSpeakerLabel()
        }
        // Off unbinds the camera; on binds it again — which is also how the
        // user recovers after unblocking the system camera privacy switch
        // (CameraX gives up on a disabled camera and never retries).
        btnCamera = button(R.string.call_camera_off, grey) {
            val enc = CallMedia.videoEncoder ?: return@button
            enc.enabled = !enc.enabled
            if (enc.enabled) startCamera() else {
                cameraProvider?.unbindAll()
                selfView.visibility = View.GONE
            }
            btnCamera.setText(if (enc.enabled) R.string.call_camera_off else R.string.call_camera_on)
        }
        btnPip = button(R.string.call_pip, grey) { enterPip() }
        btnAccept = button(R.string.call_accept, Color.rgb(46, 160, 67)) { accept() }
        btnHangup = button(R.string.call_hangup, Color.rgb(211, 47, 47)) { hangup() }
        btnMute.visibility = View.GONE
        btnSpeaker.visibility = View.GONE
        btnCamera.visibility = View.GONE
        btnPip.visibility = View.GONE
        btnAccept.visibility = View.GONE
        root.addView(bar, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM))
        this.bar = bar
        return root
    }
}
