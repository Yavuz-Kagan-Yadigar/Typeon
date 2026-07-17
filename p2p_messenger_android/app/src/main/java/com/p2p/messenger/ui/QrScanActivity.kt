package com.p2p.messenger.ui

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.util.QrBinaryCodec
import java.nio.ByteBuffer
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Spec 1.3/1.4 QR tarama akışı: kamera görüntüsünden QR'ı okur, ISO-8859-1
 * ile ham CBOR baytlarına çevirir (bkz. QrBinaryCodec), ve
 * P2PLib.processQrPacket ile işler.
 */
class QrScanActivity : AppCompatActivity() {

    private lateinit var cameraExecutor: ExecutorService
    private val alreadyHandled = AtomicBoolean(false)

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
        setContentView(R.layout.activity_qr_scan)
        supportActionBar?.title = "Scan QR"
        cameraExecutor = Executors.newSingleThreadExecutor()

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            requestCameraPermission.launch(Manifest.permission.CAMERA)
        }
    }

    private fun startCamera() {
        val previewView = findViewById<PreviewView>(R.id.cameraPreview)
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()

            val preview = androidx.camera.core.Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }

            val imageAnalysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also {
                    it.setAnalyzer(cameraExecutor, ::analyzeFrame)
                }

            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageAnalysis)
            } catch (e: Exception) {
                Toast.makeText(this, "Kamera başlatılamadı: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private val reader = MultiFormatReader().apply {
        setHints(mapOf(
            DecodeHintType.POSSIBLE_FORMATS to arrayListOf(BarcodeFormat.QR_CODE),
            // Encoder tarafında da ISO-8859-1 kullanılmalı (bkz.
            // QrBinaryCodec) — aksi halde ZXing QR'ın gerçek karakter
            // setini kendi tahmin eder ve rawBytes ile eşleşmeyebilir.
            DecodeHintType.CHARACTER_SET to "ISO-8859-1"
        ))
    }

    private fun analyzeFrame(imageProxy: ImageProxy) {
        if (alreadyHandled.get()) {
            imageProxy.close()
            return
        }
        val supportedFormats = listOf(ImageFormat.YUV_420_888, ImageFormat.YUV_422_888, ImageFormat.YUV_444_888)
        if (imageProxy.format !in supportedFormats) {
            imageProxy.close()
            return
        }

        val bytes = imageProxy.planes[0].buffer.toByteArray()
        val source = PlanarYUVLuminanceSource(
            bytes, imageProxy.width, imageProxy.height,
            0, 0, imageProxy.width, imageProxy.height, false
        )
        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))

        try {
            val result = reader.decodeWithState(binaryBitmap)
            if (alreadyHandled.compareAndSet(false, true)) {
                handleScannedText(result.text)
            }
        } catch (e: NotFoundException) {
            // Bu karede QR bulunamadı — normal, bir sonraki kareyi bekle.
        } finally {
            reader.reset()
            imageProxy.close()
        }
    }

    private fun handleScannedText(text: String) {
        runOnUiThread {
            val cborBytes = QrBinaryCodec.latin1StringToBytes(text)
            val result = P2PLib.processQrPacket(cborBytes)
            if (result.startsWith("Error:")) {
                Toast.makeText(this, result, Toast.LENGTH_LONG).show()
                alreadyHandled.set(false)
            } else {
                Toast.makeText(this, "Bağlanıldı: ${result.take(16)}...", Toast.LENGTH_SHORT).show()
                finish()
            }
        }
    }

    private fun ByteBuffer.toByteArray(): ByteArray {
        rewind()
        val data = ByteArray(remaining())
        get(data)
        return data
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }
}
