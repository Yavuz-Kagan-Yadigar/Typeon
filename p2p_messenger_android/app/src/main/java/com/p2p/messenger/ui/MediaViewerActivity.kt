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
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import android.widget.VideoView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.p2p.messenger.R
import com.p2p.messenger.util.PlaybackSpeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

/**
 * Spec dışı: kullanıcı tarafından istenen basit uygulama içi görüntüleyici
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
        private const val MAX_SCALE = 6f
        private const val SKIP_MS = 5000
        private const val SKIP_INDICATOR_DURATION_MS = 500L
        private const val VIDEO_PROGRESS_TICK_MS = 300L
    }

    private var videoMediaPlayer: MediaPlayer? = null
    private var videoSpeed = 1f
    private val videoHandler = Handler(Looper.getMainLooper())
    private var videoProgressBar: LinearProgressIndicator? = null
    private val videoProgressRunnable = object : Runnable {
        override fun run() {
            val mp = videoMediaPlayer ?: return
            val bar = videoProgressBar ?: return
            try {
                if (mp.duration > 0) {
                    bar.max = mp.duration
                    bar.setProgressCompat(mp.currentPosition, true)
                }
            } catch (e: Exception) { /* geçersiz durumda olabilir (ör. tam kapanıyor) */ }
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
                mp.start()
                videoProgressBar?.visibility = View.VISIBLE
                findViewById<View>(R.id.btnPlaybackSpeed).visibility = View.VISIBLE
                videoHandler.post(videoProgressRunnable)
            }
            setupVideoControls(videoView)
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
                        contentResolver.openInputStream(uri)?.use { input2 ->
                            BitmapFactory.decodeStream(input2, null, BitmapFactory.Options().apply { inSampleSize = sampleSize })
                        }
                    }
                } catch (e: Exception) {
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

        imageView.setOnTouchListener { _, event ->
            scaleDetector.onTouchEvent(event)
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    lastTouchX = event.x
                    lastTouchY = event.y
                    activePointerId = event.getPointerId(0)
                    isDragging = true
                }
                MotionEvent.ACTION_MOVE -> {
                    if (isDragging && !scaleDetector.isInProgress && currentScale > MIN_SCALE) {
                        val pointerIndex = event.findPointerIndex(activePointerId)
                        if (pointerIndex != -1) {
                            val x = event.getX(pointerIndex)
                            val y = event.getY(pointerIndex)
                            currentMatrix.postTranslate(x - lastTouchX, y - lastTouchY)
                            imageView.imageMatrix = currentMatrix
                            lastTouchX = x
                            lastTouchY = y
                        }
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
     * Spec dışı: `VideoView`'ın kendi `MediaController`'ı yerine — YouTube
     * tarzı tek dokunuş (oynat/duraklat), çift dokunuş (ekranın sol/sağ
     * yarısına göre ±5sn atlama + kısa animasyonlu gösterge), ve hız
     * rozeti (bkz. `PlaybackSpeed`, sesli mesajlarla AYNI döngü).
     */
    private fun setupVideoControls(videoView: VideoView) {
        videoProgressBar = findViewById(R.id.progressVideoPlayback)
        val overlay = findViewById<View>(R.id.viewVideoGestureOverlay)
        val skipLeft = findViewById<TextView>(R.id.txtSkipIndicatorLeft)
        val skipRight = findViewById<TextView>(R.id.txtSkipIndicatorRight)
        val speedButton = findViewById<TextView>(R.id.btnPlaybackSpeed)
        overlay.visibility = View.VISIBLE

        val gestureDetector = GestureDetector(this, object : GestureDetector.SimpleOnGestureListener() {
            override fun onSingleTapConfirmed(e: MotionEvent): Boolean {
                val mp = videoMediaPlayer ?: return true
                if (mp.isPlaying) mp.pause() else mp.start()
                return true
            }

            override fun onDoubleTap(e: MotionEvent): Boolean {
                val mp = videoMediaPlayer ?: return true
                val isLeftHalf = e.x < overlay.width / 2f
                val target = if (isLeftHalf) (mp.currentPosition - SKIP_MS).coerceAtLeast(0)
                             else (mp.currentPosition + SKIP_MS).coerceAtMost(mp.duration)
                mp.seekTo(target)
                showSkipIndicator(if (isLeftHalf) skipLeft else skipRight)
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
                    mp.playbackParams = PlaybackParams().setSpeed(videoSpeed)
                } catch (e: Exception) { /* bazı cihazlarda desteklenmeyen hız oranı olabilir */ }
            }
        }
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
        videoMediaPlayer?.let { if (it.isPlaying) it.pause() }
    }

    override fun onDestroy() {
        super.onDestroy()
        videoHandler.removeCallbacksAndMessages(null)
        videoMediaPlayer = null
    }
}
