package com.p2p.messenger.ui

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.os.Bundle
import android.widget.ImageButton
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.p2p.messenger.R
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.CapturedImage
import com.p2p.messenger.util.ImagePreview
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Spec dışı, kullanıcı isteği: sohbet giriş çubuğundaki kamera düğmesinin
 * açtığı anlık çekim ekranı. The shot goes straight to the caption dialog,
 * which opens it in the image editor (crop, rotate, retake are there).
 *
 * Kullanıcı isteğinin can alıcı kısmı "diske kaydedilmeden": bu yüzden
 * `ImageCapture.OnImageCapturedCallback` (BELLEĞE çeken overload)
 * kullanılıyor — dosyaya yazan `takePicture(OutputFileOptions, ...)`
 * overload'ı DEĞİL — ve sonuç, sistem galerisine/`MediaStore`'a HİÇ
 * dokunmadan `CapturedImage` üzerinden çağırana geçiyor. (Rust çekirdeği
 * ek gönderirken gerçek bir dosya yolu istediğinden gönderme anında
 * uygulamanın KENDİ önbelleğinde kısa ömürlü bir geçici dosya oluşur ve
 * hemen silinir — bkz. ChatActivity.onFilePicked AYNI desen; galeriye ya
 * da paylaşılan depolamaya hiçbir şey yazılmaz.)
 *
 * Sonuç `Intent` extra'sı olarak DEĞİL, `CapturedImage` üzerinden
 * taşınıyor — gerekçe orada.
 */
class CameraCaptureActivity : AppCompatActivity() {

    companion object {
        /** Çekilen fotoğrafın uzun kenar sınırı. Mesajlaşma için 1600px
         *  fazlasıyla yeterli; tam sensör çözünürlüğünü taşımak hem
         *  belleği hem de karşı tarafın indirme süresini gereksiz
         *  büyütürdü (bkz. ChatActivity MAX_ATTACHMENT_SIZE). */
        private const val CAPTURE_MAX_DIMENSION = 1600
        private const val CAPTURE_JPEG_QUALITY = 88
    }

    private var imageCapture: ImageCapture? = null
    private var cameraProvider: ProcessCameraProvider? = null
    private var lensFacing = CameraSelector.LENS_FACING_BACK

    private lateinit var previewView: PreviewView

    private val requestCameraPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            startCamera()
        } else {
            Toast.makeText(this, R.string.error_camera_permission, Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_camera_capture)
        supportActionBar?.hide()

        previewView = findViewById(R.id.cameraPreview)

        findViewById<ImageButton>(R.id.btnCloseCamera).setOnClickListener { finish() }
        findViewById<ImageButton>(R.id.btnShutter).setOnClickListener { capture() }
        findViewById<ImageButton>(R.id.btnFlipCamera).setOnClickListener {
            lensFacing = if (lensFacing == CameraSelector.LENS_FACING_BACK) {
                CameraSelector.LENS_FACING_FRONT
            } else {
                CameraSelector.LENS_FACING_BACK
            }
            startCamera()
        }

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            // Çalışma zamanı izin diyaloğu da dış süreçte — bkz.
            // AppLock.beginTrustedExcursion.
            AppLock.beginTrustedExcursion()
            requestCameraPermission.launch(Manifest.permission.CAMERA)
        }
    }

    private fun startCamera() {
        val providerFuture = ProcessCameraProvider.getInstance(this)
        providerFuture.addListener({
            val provider = try {
                providerFuture.get()
            } catch (e: Exception) {
                Toast.makeText(this, getString(R.string.error_camera_start_failed, e.message ?: ""), Toast.LENGTH_LONG).show()
                finish()
                return@addListener
            }
            cameraProvider = provider

            val preview = androidx.camera.core.Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }
            // MINIMIZE_LATENCY: kullanıcı isteği "anlık çekim" — deklanşöre
            // basınca beklemeden çeksin (kalite modu birden fazla kare
            // biriktirip işler, gözle görülür bir gecikme yaratır).
            val capture = ImageCapture.Builder()
                .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
                .build()
            imageCapture = capture

            try {
                provider.unbindAll()
                provider.bindToLifecycle(
                    this,
                    CameraSelector.Builder().requireLensFacing(lensFacing).build(),
                    preview,
                    capture
                )
            } catch (e: Exception) {
                Toast.makeText(this, getString(R.string.error_camera_start_failed, e.message ?: ""), Toast.LENGTH_LONG).show()
                finish()
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun capture() {
        val capture = imageCapture ?: return
        // A second tap failed after `unbindAll` and showed an error for a
        // photo that was taken.
        val shutter = findViewById<ImageButton>(R.id.btnShutter)
        if (!shutter.isEnabled) return
        shutter.isEnabled = false
        capture.takePicture(
            ContextCompat.getMainExecutor(this),
            object : ImageCapture.OnImageCapturedCallback() {
                override fun onCaptureSuccess(image: ImageProxy) {
                    // The JPEG decode + rotate of a full-size frame: off the
                    // main thread; the shutter stays disabled meanwhile.
                    lifecycleScope.launch {
                        val bitmap = try {
                            withContext(Dispatchers.Default) {
                                try {
                                    decodeRotated(image)
                                } catch (e: Exception) {
                                    null
                                } catch (e: OutOfMemoryError) {
                                    null
                                }
                            }
                        } finally {
                            // Also when the activity went away first.
                            image.close()
                        }
                        if (bitmap == null) {
                            shutter.isEnabled = true
                            Toast.makeText(
                                this@CameraCaptureActivity,
                                getString(R.string.error_camera_start_failed, ""),
                                Toast.LENGTH_SHORT
                            ).show()
                            return@launch
                        }
                        finishWithPhoto(bitmap)
                    }
                }

                override fun onError(exception: ImageCaptureException) {
                    shutter.isEnabled = true
                    Toast.makeText(
                        this@CameraCaptureActivity,
                        getString(R.string.error_camera_start_failed, exception.message ?: ""),
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        )
    }

    /**
     * `ImageProxy` JPEG baytlarını taşır ama fiziksel sensör yönünde —
     * `imageInfo.rotationDegrees` uygulanmazsa fotoğraf yan çıkar. Aynı
     * anda, sensörün TAM çözünürlüğünü belleğe almamak için
     * `inSampleSize` ile örnekleyerek çözüyoruz (bkz. ImagePreview,
     * AYNI desen).
     */
    private fun decodeRotated(image: ImageProxy): Bitmap? {
        val buffer = image.planes[0].buffer
        val bytes = ByteArray(buffer.remaining()).also { buffer.get(it) }

        val boundsOptions = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, boundsOptions)
        var sampleSize = 1
        while (boundsOptions.outWidth / (sampleSize * 2) >= CAPTURE_MAX_DIMENSION &&
            boundsOptions.outHeight / (sampleSize * 2) >= CAPTURE_MAX_DIMENSION
        ) {
            sampleSize *= 2
        }
        val decoded = BitmapFactory.decodeByteArray(
            bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sampleSize }
        ) ?: return null

        val degrees = image.imageInfo.rotationDegrees
        // Ön kamera görüntüsü aynalanmış gelir — önizlemede kullanıcının
        // gördüğüyle çekilen kare aynı olsun diye yatayda çevriliyor.
        val mirrored = lensFacing == CameraSelector.LENS_FACING_FRONT
        if (degrees == 0 && !mirrored) return decoded
        // Upright first, then mirror: mirrored first, a 90/270 degree sensor
        // (every phone held upright) gave the selfie upside down.
        val matrix = Matrix().apply {
            if (degrees != 0) postRotate(degrees.toFloat())
            if (mirrored) postScale(-1f, 1f)
        }
        val rotated = Bitmap.createBitmap(decoded, 0, 0, decoded.width, decoded.height, matrix, true)
        if (rotated !== decoded) decoded.recycle()
        return rotated
    }

    /** The shutter stays disabled: the photo is on its way. */
    private fun finishWithPhoto(bitmap: Bitmap) {
        cameraProvider?.unbindAll()
        lifecycleScope.launch(Dispatchers.IO) {
            val jpeg = try {
                ImagePreview.compressBitmap(bitmap, CAPTURE_MAX_DIMENSION, CAPTURE_JPEG_QUALITY)
            } catch (e: Exception) {
                null
            } catch (e: OutOfMemoryError) {
                null
            }
            withContext(Dispatchers.Main) {
                if (jpeg == null) {
                    Toast.makeText(this@CameraCaptureActivity, R.string.error_send_failed, Toast.LENGTH_SHORT).show()
                    finish()
                    return@withContext
                }
                CapturedImage.put(jpeg)
                setResult(RESULT_OK)
                finish()
            }
        }
    }
}
