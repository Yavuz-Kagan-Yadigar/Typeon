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
 * `P2PLib.callState()` twice a second and renders it, so there is no second
 * state machine here to drift out of sync.
 */
class CallActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "CallActivity"
        const val EXTRA_PEER = "call_peer"
        const val EXTRA_GROUP = "call_group"
        const val EXTRA_VIDEO = "call_video"
        private const val CHANNEL_ID = "calls"
        private const val NOTIFICATION_ID = 0x0CA11
        private const val REQ_PERMS = 41

        /** From a chat screen: ring [peer] (1:1) or every member of [groupId]. */
        fun startOutgoing(context: Context, peer: String?, groupId: String?, video: Boolean) {
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
            val intent = Intent(context, CallActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val pending = PendingIntent.getActivity(
                context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, context.getString(R.string.call_channel_name), NotificationManager.IMPORTANCE_HIGH)
            )
            val text = context.getString(if (video) R.string.call_incoming_video else R.string.call_incoming_voice)
            val n = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification)
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
    private val io = Executors.newSingleThreadExecutor()
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

    /** Saw a non-idle state at least once — only then does "idle" mean "ended". */
    private var callSeen = false
    private val createdAt = System.currentTimeMillis()
    private var starting = false
    private var finishingAt = 0L
    private var mediaRunning = false
    private var video = false
    private var state = "idle"
    private var ringtone: android.media.Ringtone? = null
    private var ringback: ToneGenerator? = null
    private var cameraProvider: ProcessCameraProvider? = null
    private val analysisExecutor = Executors.newSingleThreadExecutor()
    /** slot -> tile */
    private val tiles = HashMap<Int, Tile>()
    private val keepPollFast: (String) -> Unit = {}

    private class Tile(val root: FrameLayout, val label: TextView, var texture: TextureView?) {
        var mutedShown = false
        var videoW = 0
        var videoH = 0
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
        poll()
    }

    // onStart/onStop, not onResume/onPause: a picture-in-picture call is
    // paused but still on screen and still needs the fast poll.
    override fun onStart() {
        super.onStart()
        // Keeps the service poll loop at its fast rate for signalling/link upkeep.
        P2PService.addMessageListener(keepPollFast)
    }

    override fun onStop() {
        super.onStop()
        P2PService.removeMessageListener(keepPollFast)
    }

    override fun onDestroy() {
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
            enterPictureInPictureMode(PictureInPictureParams.Builder().setAspectRatio(ratio).build())
        } catch (e: IllegalStateException) {
            false
        }
    }

    override fun onPictureInPictureModeChanged(inPip: Boolean, newConfig: Configuration) {
        super.onPictureInPictureModeChanged(inPip, newConfig)
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

    // ---------------------------------------------------------------- actions

    private fun placeCall(peer: String?, group: String?) {
        io.execute {
            val r = if (group != null) P2PLib.startGroupCall(group, video) else P2PLib.startCall(peer ?: "", video)
            ui.post {
                starting = false
                if (r.startsWith("Error")) {
                    Toast.makeText(this, r.removePrefix("Error: "), Toast.LENGTH_LONG).show()
                    finish()
                }
            }
        }
    }

    private fun accept() {
        if (!hasPermissions(video)) { requestPermissions(video); return }
        btnAccept.isEnabled = false
        io.execute { P2PLib.acceptCall() }
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
    }

    // ---------------------------------------------------------------- state

    private fun poll() {
        io.execute {
            val json = try { JSONObject(P2PLib.callState()) } catch (e: Exception) { null }
            ui.post { if (json != null && !isFinishing) render(json) }
        }
        ui.postDelayed(::poll, 500)
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
            if (!callSeen && !starting && System.currentTimeMillis() - createdAt > 2000) finish()
            return
        }

        txtName.text = s.optString("name")
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
        if (inCall && participants != null) syncTiles(participants)
    }

    private fun onStateChanged(old: String, new: String, s: JSONObject) {
        stopTones()
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
                    ui.postDelayed({ finish() }, 1500)
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
            tile.texture?.visibility = if (p.optBoolean("video_off")) View.INVISIBLE else View.VISIBLE
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
        root.addView(label, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            if (video) Gravity.BOTTOM or Gravity.START else Gravity.CENTER
        ))
        val tile = Tile(root, label, texture)
        // The tile is resized when the call enters or leaves picture-in-picture.
        root.addOnLayoutChangeListener { _, l, t, r, b, oldL, oldT, oldR, oldB ->
            if (r - l != oldR - oldL || b - t != oldB - oldT) texture?.let { tv -> root.post { fitVideo(tv, root, tile.videoW, tile.videoH) } }
        }
        return tile
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
            backgroundTintList = android.content.res.ColorStateList.valueOf(color)
            setOnClickListener { onClick() }
            bar.addView(this, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = (4 * dp).toInt(); marginEnd = (4 * dp).toInt()
            })
        }
        val grey = Color.rgb(60, 60, 66)
        btnMute = button(R.string.call_mute, grey) {
            CallMedia.muted = !CallMedia.muted
            btnMute.setText(if (CallMedia.muted) R.string.call_unmute else R.string.call_mute)
        }
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
        btnAccept = button(R.string.call_accept, Color.rgb(46, 160, 67)) { accept() }
        btnHangup = button(R.string.call_hangup, Color.rgb(211, 47, 47)) { hangup() }
        btnMute.visibility = View.GONE
        btnSpeaker.visibility = View.GONE
        btnCamera.visibility = View.GONE
        btnAccept.visibility = View.GONE
        root.addView(bar, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM))
        this.bar = bar
        return root
    }
}
