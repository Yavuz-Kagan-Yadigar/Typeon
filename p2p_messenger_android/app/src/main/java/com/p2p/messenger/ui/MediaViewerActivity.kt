package com.p2p.messenger.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.MediaPlayer
import android.media.PlaybackParams
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.view.View
import android.view.ViewConfiguration
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import android.widget.VideoView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.slider.Slider
import com.p2p.messenger.R
import com.p2p.messenger.util.PlaybackSpeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

/**
 * kullanıcı tarafından istenen basit uygulama içi görüntüleyici
 * — önceden tamamlanmış bir foto/video eki, HER ZAMAN sistem varsayılan
 * uygulamasına (ACTION_VIEW) devrediliyordu; artık foto/video özelinde
 * (diğer türler hâlâ sistem uygulamasına gider, bkz. ChatActivity
 * onAttachmentClicked) tam boyut/kalitede, uygulamanın kendi içinde
 * gösterilir. Video oynatma için Android'in kendi `VideoView`'ı
 * kullanılıyor — yeni bir kütüphaneye (ExoPlayer vb.) gerek yok; hız
 * kontrolü + çift dokunuşla atlama için `VideoView.setOnPreparedListener`in
 * verdiği GERÇEK `MediaPlayer` referansı kullanılıyor (reflection gerekmez
 * — `onPrepared(MediaPlayer mp)` zaten canlı nesneyi taşıyor).
 */
class MediaViewerActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_URI = "uri"
        const val EXTRA_MIME_TYPE = "mime_type"
        private const val MIN_SCALE = 1f
        /** Longest bitmap edge decoded; a canvas refuses to draw much more. */
        private const val MAX_BITMAP_EDGE = 4096
        private const val MAX_SCALE = 6f
        private const val SKIP_MS = 5000
        private const val SKIP_INDICATOR_DURATION_MS = 500L
        private const val VIDEO_PROGRESS_TICK_MS = 300L
    }

    private var videoMediaPlayer: MediaPlayer? = null
    private var videoSpeed = 1f
    private var resumePositionMs = 0
    private val videoHandler = Handler(Looper.getMainLooper())
    private var videoSlider: Slider? = null
    private var btnPlayPauseVideo: ImageButton? = null
    /** Kullanıcı kaydırıcıyı sürüklerken periyodik konum güncellemesi
     *  ATLANIR — aksi halde kaydırıcı sürüklemenin altından kayardı (bkz.
     *  SimpleChatAdapter sesli mesaj kaydırıcısındaki AYNI gerekçe). */
    private var isSeekingVideo = false
    private val videoProgressRunnable = object : Runnable {
        override fun run() {
            val mp = videoMediaPlayer ?: return
            val slider = videoSlider ?: return
            if (!isSeekingVideo) {
                try {
                    if (mp.duration > 0) {
                        if (slider.valueTo != mp.duration.toFloat()) slider.valueTo = mp.duration.toFloat()
                        slider.value = mp.currentPosition.toFloat().coerceIn(0f, slider.valueTo)
                    }
                } catch (e: Exception) { /* geçersiz durumda olabilir (ör. tam kapanıyor) */ }
            }
            videoHandler.postDelayed(this, VIDEO_PROGRESS_TICK_MS)
        }
    }

    // Bkz. `setupZoomableImage` — `ImageView.ScaleType.MATRIX` ile elle
    // yönetilen pinch-zoom/pan durumu. `baseMatrix` ekrana tam oturmuş
    // (fitCenter benzeri) hâli, `currentMatrix` kullanıcının o anki
    // zoom/pan durumunu taşır.
    private val baseMatrix = Matrix()
    private val currentMatrix = Matrix()
    private var currentScale = MIN_SCALE
    private lateinit var scaleDetector: ScaleGestureDetector
    private var lastTouchX = 0f
    private var lastTouchY = 0f
    private var activePointerId = -1
    private var isDragging = false

    // Bkz. `setupZoomableImage` tek dokunuşla kapatma: ACTION_DOWN
    // noktasından `touchSlop`u aşan bir sürükleme YA da bir pinch
    // (multi-touch) olmadıysa, ACTION_UP bir "tek dokunuş" sayılır.
    private var downX = 0f
    private var downY = 0f
    private var hasMovedPastSlop = false
    private var hadMultiTouch = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_media_viewer)

        val uri = intent.getParcelableExtra<Uri>(EXTRA_URI) ?: run { finish(); return }
        val mimeType = intent.getStringExtra(EXTRA_MIME_TYPE) ?: ""

        findViewById<View>(R.id.btnViewerClose).setOnClickListener { finish() }
        val progress = findViewById<ProgressBar>(R.id.progressViewer)

        if (mimeType.startsWith("video/")) {
            progress.visibility = View.GONE
            val videoView = findViewById<VideoView>(R.id.videoViewer)
            videoView.visibility = View.VISIBLE
            videoView.setVideoURI(uri)
            videoView.setOnErrorListener { _, _, _ ->
                Toast.makeText(this, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                finish()
                true
            }
            videoView.setOnPreparedListener { mp ->
                videoMediaPlayer = mp
                mp.isLooping = false
                // The surface comes back after screen off and prepares again:
                // continue where it stopped, at the chosen speed.
                if (resumePositionMs > 0) mp.seekTo(resumePositionMs)
                if (videoSpeed != 1f && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    try { mp.playbackParams = PlaybackParams().setSpeed(videoSpeed) } catch (e: Exception) { }
                }
                mp.start()
                findViewById<View>(R.id.layoutVideoControls).visibility = View.VISIBLE
                findViewById<View>(R.id.btnPlaybackSpeed).visibility = View.VISIBLE
                btnPlayPauseVideo?.setImageResource(R.drawable.ic_pause)
                // One chain: every prepare used to start another 300 ms tick.
                videoHandler.removeCallbacks(videoProgressRunnable)
                videoHandler.post(videoProgressRunnable)
            }
            setupVideoControls(videoView)
        } else if (mimeType == "image/gif" && Build.VERSION.SDK_INT >= 28) {
            // Animated (a received animated JPEG XL arrives as .gif). No pinch-zoom: fit-center.
            lifecycleScope.launch(Dispatchers.IO) {
                val drawable = try {
                    android.graphics.ImageDecoder.decodeDrawable(android.graphics.ImageDecoder.createSource(contentResolver, uri)) { decoder, info, _ ->
                        // A huge canvas would crash the renderer: sample it down.
                        val edge = maxOf(info.size.width, info.size.height)
                        if (edge > MAX_BITMAP_EDGE) decoder.setTargetSampleSize((edge + MAX_BITMAP_EDGE - 1) / MAX_BITMAP_EDGE)
                    }
                } catch (e: Throwable) { null }
                withContext(Dispatchers.Main) {
                    progress.visibility = View.GONE
                    if (drawable == null) {
                        Toast.makeText(this@MediaViewerActivity, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                        finish()
                    } else {
                        val imageView = findViewById<ImageView>(R.id.imgViewerImage)
                        imageView.scaleType = ImageView.ScaleType.FIT_CENTER
                        imageView.visibility = View.VISIBLE
                        imageView.setImageDrawable(drawable)
                        (drawable as? android.graphics.drawable.AnimatedImageDrawable)?.apply {
                            repeatCount = android.graphics.drawable.AnimatedImageDrawable.REPEAT_INFINITE
                            start()
                        }
                        imageView.setOnClickListener { finish() }
                    }
                }
            }
        } else {
            // Görsel — büyük dosyaları TAM çözünürlükte belleğe yüklememek
            // için ekran boyutuna göre bir `inSampleSize` hesaplanır (bkz.
            // ChatActivity.generateImagePreview'daki aynı desen, burada
            // hedef 480px değil EKRANIN gerçek boyutu — "tam kalite"
            // isteniyor, sadece gereksiz yere aşırı büyük bir bitmap
            // (OOM riski) önleniyor).
            lifecycleScope.launch(Dispatchers.IO) {
                val bitmap = try {
                    contentResolver.openInputStream(uri)?.use { input ->
                        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                        BitmapFactory.decodeStream(input, null, bounds)
                        val metrics = resources.displayMetrics
                        var sampleSize = 1
                        while (bounds.outWidth / (sampleSize * 2) >= metrics.widthPixels &&
                            bounds.outHeight / (sampleSize * 2) >= metrics.heightPixels) {
                            sampleSize *= 2
                        }
                        // The rule above never samples a panorama or a long
                        // screenshot (one edge stays under the screen's): cap
                        // the long edge at what a canvas can draw.
                        while (maxOf(bounds.outWidth, bounds.outHeight) / sampleSize > MAX_BITMAP_EDGE) sampleSize *= 2
                        contentResolver.openInputStream(uri)?.use { input2 ->
                            BitmapFactory.decodeStream(input2, null, BitmapFactory.Options().apply { inSampleSize = sampleSize })
                        }?.let { decoded ->
                            // Same as the thumbnails: the camera's rotation is in EXIF.
                            try {
                                contentResolver.openInputStream(uri)?.use { input3 ->
                                    com.p2p.messenger.util.ImagePreview.rotateForExif(decoded, android.media.ExifInterface(input3))
                                } ?: decoded
                            } catch (e: Exception) {
                                decoded
                            }
                        }
                    }
                } catch (e: Throwable) {
                    // Throwable: OutOfMemoryError is not an Exception.
                    null
                }
                withContext(Dispatchers.Main) {
                    progress.visibility = View.GONE
                    if (bitmap == null) {
                        Toast.makeText(this@MediaViewerActivity, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                        finish()
                    } else {
                        val imageView = findViewById<ImageView>(R.id.imgViewerImage)
                        imageView.visibility = View.VISIBLE
                        setupZoomableImage(imageView, bitmap)
                    }
                }
            }
        }
    }

    /**
     * Pinch-to-zoom + sürükleyerek gezinme (pan) — proje içinde Glide/Coil/
     * PhotoView gibi bir görsel kütüphane yok, bu yüzden elle
     * `ScaleGestureDetector` + `Matrix` ile uygulanıyor.
     * `ImageView.scaleType` XML'de zaten `matrix` — `imageMatrix` her
     * güncellemede manuel set edilir.
     */
    private fun setupZoomableImage(imageView: ImageView, bitmap: Bitmap) {
        imageView.setImageBitmap(bitmap)
        imageView.post {
            val viewWidth = imageView.width.toFloat()
            val viewHeight = imageView.height.toFloat()
            if (viewWidth <= 0f || viewHeight <= 0f) return@post
            val bmpWidth = bitmap.width.toFloat()
            val bmpHeight = bitmap.height.toFloat()
            val scale = minOf(viewWidth / bmpWidth, viewHeight / bmpHeight)
            val dx = (viewWidth - bmpWidth * scale) / 2f
            val dy = (viewHeight - bmpHeight * scale) / 2f
            baseMatrix.reset()
            baseMatrix.postScale(scale, scale)
            baseMatrix.postTranslate(dx, dy)
            currentMatrix.set(baseMatrix)
            currentScale = MIN_SCALE
            imageView.imageMatrix = currentMatrix
        }

        scaleDetector = ScaleGestureDetector(this, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
            override fun onScale(detector: ScaleGestureDetector): Boolean {
                val newScale = (currentScale * detector.scaleFactor).coerceIn(MIN_SCALE, MAX_SCALE)
                val factor = if (currentScale == 0f) 1f else newScale / currentScale
                currentScale = newScale
                currentMatrix.postScale(factor, factor, detector.focusX, detector.focusY)
                imageView.imageMatrix = currentMatrix
                return true
            }
        })

        val touchSlop = ViewConfiguration.get(this).scaledTouchSlop
        imageView.setOnTouchListener { _, event ->
            scaleDetector.onTouchEvent(event)
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    lastTouchX = event.x
                    lastTouchY = event.y
                    downX = event.x
                    downY = event.y
                    hasMovedPastSlop = false
                    hadMultiTouch = false
                    activePointerId = event.getPointerId(0)
                    isDragging = true
                }
                MotionEvent.ACTION_POINTER_DOWN -> {
                    hadMultiTouch = true
                }
                MotionEvent.ACTION_MOVE -> {
                    val pointerIndex = event.findPointerIndex(activePointerId)
                    if (isDragging && pointerIndex != -1) {
                        val x = event.getX(pointerIndex)
                        val y = event.getY(pointerIndex)
                        if (!scaleDetector.isInProgress && currentScale > MIN_SCALE) {
                            currentMatrix.postTranslate(x - lastTouchX, y - lastTouchY)
                            imageView.imageMatrix = currentMatrix
                        }
                        // Also during a pinch: with a stale point the image
                        // jumped when panning started again.
                        lastTouchX = x
                        lastTouchY = y
                    }
                    if (kotlin.math.abs(event.x - downX) > touchSlop || kotlin.math.abs(event.y - downY) > touchSlop) {
                        hasMovedPastSlop = true
                    }
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    isDragging = false
                    activePointerId = -1
                    if (currentScale <= MIN_SCALE) {
                        currentMatrix.set(baseMatrix)
                        currentScale = MIN_SCALE
                        imageView.imageMatrix = currentMatrix
                    }
                    // Spec dışı, kullanıcı isteği (profil fotoğrafı tam ekran
                    // görüntüleyici): pinch/sürükleme OLMADAN tek dokunuş —
                    // görüntüleyiciyi kapatır.
                    if (event.actionMasked == MotionEvent.ACTION_UP && !hasMovedPastSlop && !hadMultiTouch) {
                        finish()
                    }
                }
                MotionEvent.ACTION_POINTER_UP -> {
                    val pointerIndex = event.actionIndex
                    val pointerId = event.getPointerId(pointerIndex)
                    if (pointerId == activePointerId) {
                        val newPointerIndex = if (pointerIndex == 0) 1 else 0
                        lastTouchX = event.getX(newPointerIndex)
                        lastTouchY = event.getY(newPointerIndex)
                        activePointerId = event.getPointerId(newPointerIndex)
                    }
                }
            }
            true
        }
    }

    /**
     * `VideoView`'ın kendi `MediaController`'ı yerine — YouTube
     * tarzı tek dokunuş (oynat/duraklat), çift dokunuş (ekranın sol/sağ
     * yarısına göre ±5sn atlama + kısa animasyonlu gösterge), ve hız
     * rozeti (bkz. `PlaybackSpeed`, sesli mesajlarla AYNI döngü).
     */
    private fun setupVideoControls(videoView: VideoView) {
        val overlay = findViewById<View>(R.id.viewVideoGestureOverlay)
        val skipLeft = findViewById<TextView>(R.id.txtSkipIndicatorLeft)
        val skipRight = findViewById<TextView>(R.id.txtSkipIndicatorRight)
        val speedButton = findViewById<TextView>(R.id.btnPlaybackSpeed)
        overlay.visibility = View.VISIBLE

        // çift dokunuşla ±5sn atlama HÂLÂ çalışır (bkz. gesture
        // detector aşağıda) ama artık kullanıcıya görünür, dokunulabilir
        // düğmeler DE var — önceden sadece görünmez bir dokunuş bölgesi
        // olduğundan kontroller keşfedilemezdi.
        videoSlider = findViewById(R.id.progressVideoPlayback)
        btnPlayPauseVideo = findViewById(R.id.btnPlayPauseVideo)
        val btnSkipBack = findViewById<ImageButton>(R.id.btnSkipBack)
        val btnSkipForward = findViewById<ImageButton>(R.id.btnSkipForward)

        btnPlayPauseVideo?.setOnClickListener { togglePlayPause() }
        btnSkipBack.setOnClickListener { skip(-SKIP_MS, skipLeft) }
        btnSkipForward.setOnClickListener { skip(SKIP_MS, skipRight) }

        videoSlider?.addOnSliderTouchListener(object : Slider.OnSliderTouchListener {
            override fun onStartTrackingTouch(slider: Slider) { isSeekingVideo = true }
            override fun onStopTrackingTouch(slider: Slider) {
                isSeekingVideo = false
                videoMediaPlayer?.seekTo(slider.value.toInt())
            }
        })

        val gestureDetector = GestureDetector(this, object : GestureDetector.SimpleOnGestureListener() {
            override fun onSingleTapConfirmed(e: MotionEvent): Boolean {
                togglePlayPause()
                return true
            }

            override fun onDoubleTap(e: MotionEvent): Boolean {
                val isLeftHalf = e.x < overlay.width / 2f
                skip(if (isLeftHalf) -SKIP_MS else SKIP_MS, if (isLeftHalf) skipLeft else skipRight)
                return true
            }
        })
        overlay.setOnTouchListener { _, event -> gestureDetector.onTouchEvent(event) }

        speedButton.setOnClickListener {
            videoSpeed = PlaybackSpeed.next(videoSpeed)
            speedButton.text = formatSpeedLabel(videoSpeed)
            val mp = videoMediaPlayer
            if (mp != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    // Setting the speed starts a paused player (documented):
                    // put it back, the icon still says "play".
                    val wasPlaying = mp.isPlaying
                    mp.playbackParams = PlaybackParams().setSpeed(videoSpeed)
                    if (!wasPlaying) mp.pause()
                } catch (e: Exception) { /* bazı cihazlarda desteklenmeyen hız oranı olabilir */ }
            }
        }
    }

    private fun togglePlayPause() {
        val mp = videoMediaPlayer ?: return
        if (mp.isPlaying) {
            mp.pause()
            btnPlayPauseVideo?.setImageResource(R.drawable.ic_play)
        } else {
            mp.start()
            btnPlayPauseVideo?.setImageResource(R.drawable.ic_pause)
        }
    }

    private fun skip(deltaMs: Int, indicator: TextView) {
        val mp = videoMediaPlayer ?: return
        val target = (mp.currentPosition + deltaMs).coerceIn(0, mp.duration.coerceAtLeast(0))
        mp.seekTo(target)
        videoSlider?.value = target.toFloat().coerceIn(0f, (videoSlider?.valueTo ?: 1f))
        showSkipIndicator(indicator)
    }

    private fun showSkipIndicator(view: TextView) {
        (view.tag as? Runnable)?.let { videoHandler.removeCallbacks(it) }
        view.visibility = View.VISIBLE
        view.alpha = 1f
        val hide = Runnable { view.animate().alpha(0f).setDuration(150).withEndAction { view.visibility = View.INVISIBLE } }
        view.tag = hide
        videoHandler.postDelayed(hide, SKIP_INDICATOR_DURATION_MS)
    }

    private fun formatSpeedLabel(speed: Float): String {
        val trimmed = if (speed == speed.toInt().toFloat()) speed.toInt().toString() else speed.toString()
        return "${trimmed}x"
    }

    override fun onPause() {
        super.onPause()
        // The tick used to keep hitting duration/currentPosition and the slider
        // 3.3×/s after Home or screen-off; it is re-armed in `onResume`.
        videoHandler.removeCallbacks(videoProgressRunnable)
        // VideoView releases the player when its surface goes away (screen
        // off): `isPlaying` then throws IllegalStateException.
        try {
            videoMediaPlayer?.let {
                resumePositionMs = it.currentPosition
                if (it.isPlaying) it.pause()
            }
        } catch (e: IllegalStateException) { }
    }

    override fun onResume() {
        super.onResume()
        if (videoMediaPlayer == null) return
        videoHandler.removeCallbacks(videoProgressRunnable)
        videoHandler.post(videoProgressRunnable)
    }

    override fun onDestroy() {
        super.onDestroy()
        videoHandler.removeCallbacksAndMessages(null)
        videoMediaPlayer = null
        // release the codec now, not when the view is collected.
        try { findViewById<VideoView>(R.id.videoViewer)?.stopPlayback() } catch (e: Exception) { }
        // The full-size avatar copy of `AvatarUtil.openFullscreen` is plaintext
        // on disk and has no other use.
        if (isFinishing) {
            intent.getParcelableExtra<Uri>(EXTRA_URI)
                ?.takeIf { it.authority == "$packageName.fileprovider" && it.pathSegments.firstOrNull() == "avatar_view" }
                ?.lastPathSegment
                ?.let { java.io.File(java.io.File(cacheDir, "avatar_view"), it).delete() }
        }
    }
}
