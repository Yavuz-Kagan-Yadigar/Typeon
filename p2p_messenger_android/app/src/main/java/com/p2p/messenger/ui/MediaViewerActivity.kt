package com.p2p.messenger.ui

import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.MediaController
import android.widget.ProgressBar
import android.widget.Toast
import android.widget.VideoView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.p2p.messenger.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Spec dışı: kullanıcı tarafından istenen basit uygulama içi görüntüleyici
 * — önceden tamamlanmış bir foto/video eki, HER ZAMAN sistem varsayılan
 * uygulamasına (ACTION_VIEW) devrediliyordu; artık foto/video özelinde
 * (diğer türler hâlâ sistem uygulamasına gider, bkz. ChatActivity
 * onAttachmentClicked) tam boyut/kalitede, uygulamanın kendi içinde
 * gösterilir. Video oynatma için Android'in kendi `VideoView`'ı
 * kullanılıyor — yeni bir kütüphaneye (ExoPlayer vb.) gerek yok.
 */
class MediaViewerActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_URI = "uri"
        const val EXTRA_MIME_TYPE = "mime_type"
    }

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
            videoView.setMediaController(MediaController(this).apply { setAnchorView(videoView) })
            videoView.setOnErrorListener { _, _, _ ->
                Toast.makeText(this, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                finish()
                true
            }
            videoView.setOnPreparedListener { it.start() }
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
                        findViewById<ImageView>(R.id.imgViewerImage).apply {
                            visibility = View.VISIBLE
                            setImageBitmap(bitmap)
                        }
                    }
                }
            }
        }
    }
}
