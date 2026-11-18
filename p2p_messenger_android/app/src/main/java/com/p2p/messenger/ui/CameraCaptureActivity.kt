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
 * Instant capture screen, opened by the camera button in the chat input bar. The shot goes straight to the caption dialog, which opens it in the image
 * editor (crop, rotate and retake are there).
 *
 * The key point is "without saving to disk". So `ImageCapture.OnImageCapturedCallback` is used (the overload that captures to MEMORY), not the
 * `takePicture(OutputFileOptions, ...)` overload that writes to a file. The result goes to the caller through `CapturedImage`, without touching the system
 * gallery or `MediaStore` at all. (The Rust core needs a real file path when an attachment is sent, so at send time a short-lived temporary file is created in
 * the app's OWN cache and deleted right away. See ChatActivity.onFilePicked, the same pattern. Nothing is written to the gallery or to shared storage.)
 *
 * The result is carried through `CapturedImage`, not as an Intent extra. The reason is in that class.
 */
class CameraCaptureActivity : AppCompatActivity() {

    companion object {
        /** Long-edge limit of the captured photo. 1600 px is more than enough for messaging. Carrying the full sensor resolution would inflate both memory and
         *  the other side's download time (see ChatActivity MAX_ATTACHMENT_SIZE). */
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
            // The runtime permission dialog is also in an external process. See AppLock.beginTrustedExcursion.
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
            // MINIMIZE_LATENCY: the shot should be taken as soon as the shutter is pressed, without waiting. The quality mode gathers several frames and
            // processes them, which adds a visible delay.
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
        // Flip would unbind the use case mid-capture and change the mirror flag.
        val flip = findViewById<ImageButton>(R.id.btnFlipCamera)
        flip.isEnabled = false
        val lens = lensFacing
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
                                    decodeRotated(image, lens)
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
                            flip.isEnabled = true
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
                    flip.isEnabled = true
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
     * The `ImageProxy` JPEG bytes are in the physical sensor orientation. If `imageInfo.rotationDegrees` is not applied, the photo comes out sideways.
     * At the same time, the full sensor resolution is not loaded into memory. It is decoded with `inSampleSize` sampling (the same pattern as ImagePreview).
     */
    private fun decodeRotated(image: ImageProxy, lens: Int): Bitmap? {
        val buffer = image.planes[0].buffer
        val bytes = ByteArray(buffer.remaining()).also { buffer.get(it) }

        val boundsOptions = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, boundsOptions)
        var sampleSize = 1
        // Halve while the LONG edge stays at the target: a full-sensor decode plus its rotated copy is ~96 MB.
        while (maxOf(boundsOptions.outWidth, boundsOptions.outHeight) / (sampleSize * 2) >= CAPTURE_MAX_DIMENSION) {
            sampleSize *= 2
        }
        val decoded = BitmapFactory.decodeByteArray(
            bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sampleSize }
        ) ?: return null

        val degrees = image.imageInfo.rotationDegrees
        // A front camera image comes mirrored. It is flipped horizontally here, so the frame the user sees in the preview matches the captured one.
        val mirrored = lens == CameraSelector.LENS_FACING_FRONT
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
