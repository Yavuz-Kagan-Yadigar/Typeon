package com.p2p.messenger.ui

import android.Manifest
import android.content.Intent
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
import org.json.JSONObject
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

    companion object {
        /** Çoklu-cihaz (spec 1.5): bu extra `"link_approve"` ise taranan QR bir
         *  KİŞİ eşleşme QR'ı değil, bir İKİNCİL CİHAZ ekleme QR'ıdır —
         *  `approveDeviceLink` çağrılır (bkz. SettingsFragment "İkinci cihaz
         *  ekle"). Yoksa/boşsa normal kişi eşleşmesi (`processQrPacket`). */
        const val EXTRA_MODE = "mode"
        const val MODE_LINK_APPROVE = "link_approve"
        /** Sunucu (store-and-forward) davet QR'ı — bkz. SettingsFragment
         *  "Sunucular" bölümü. Diğer iki modun aksine bu QR CBOR DEĞİL, düz
         *  metin bir davet kodu taşır (`typeon-server:<multiaddr>#<jeton>`);
         *  sunucu uygulaması onu kopyalanabilir metin olarak da gösterdiği
         *  için tek kanonik biçim bu. */
        const val MODE_ADD_SERVER = "add_server"
    }

    private lateinit var cameraExecutor: ExecutorService
    private val alreadyHandled = AtomicBoolean(false)
    private val linkApproveMode: Boolean by lazy {
        intent.getStringExtra(EXTRA_MODE) == MODE_LINK_APPROVE
    }
    private val addServerMode: Boolean by lazy {
        intent.getStringExtra(EXTRA_MODE) == MODE_ADD_SERVER
    }

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
        supportActionBar?.title = getString(R.string.title_scan_qr)
        cameraExecutor = Executors.newSingleThreadExecutor()
        // Debug builds only (see the debug manifest): a decoded QR from adb
        // goes through the same confirm-and-run path as a camera frame.
        val injected = intent.getStringExtra("debug_qr_hex")
        if (injected != null && applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            val bytes = injected.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            alreadyHandled.set(true)
            Thread { handleScannedText(if (addServerMode) String(bytes) else String(bytes, Charsets.ISO_8859_1)) }.start()
            return
        }

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            com.p2p.messenger.util.AppLock.beginTrustedExcursion()
            requestCameraPermission.launch(Manifest.permission.CAMERA)
        }
    }

    private fun startCamera() {
        val previewView = findViewById<PreviewView>(R.id.cameraPreview)
        // SurfaceView (PERFORMANCE) bazı cihazlarda siyah kare veriyor; TextureView güvenli.
        previewView.implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener({
            if (isFinishing || isDestroyed) return@addListener
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
                val camera = cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageAnalysis)
                // Kamera açılamazsa (gizlilik anahtarı/ERROR_CAMERA_DISABLED, başka
                // uygulama kullanıyor, donanım hatası) önizleme SİYAH kalıyordu ve
                // kullanıcıya hiçbir şey söylenmiyordu: hatayı göster ve ekranı kapat.
                camera.cameraInfo.cameraState.observe(this) { st ->
                    val err = st.error ?: return@observe
                    if (err.type == androidx.camera.core.CameraState.ErrorType.CRITICAL ||
                        err.code == androidx.camera.core.CameraState.ERROR_CAMERA_DISABLED ||
                        err.code == androidx.camera.core.CameraState.ERROR_CAMERA_FATAL_ERROR
                    ) {
                        Toast.makeText(this, getString(R.string.error_camera_start_failed,
                            "camera unavailable (code ${err.code}) — check the system camera privacy switch"), Toast.LENGTH_LONG).show()
                        finish()
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(this, getString(R.string.error_camera_start_failed, e.message ?: ""), Toast.LENGTH_LONG).show()
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

        try {
            val bytes = imageProxy.planes[0].buffer.toByteArray()
            // The plane's row stride is the data width: with padded rows (stride
            // wider than the image) the picture was sheared and never decoded.
            val source = PlanarYUVLuminanceSource(
                bytes, imageProxy.planes[0].rowStride, imageProxy.height,
                0, 0, imageProxy.width, imageProxy.height, false
            )
            val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
            val result = reader.decodeWithState(binaryBitmap)
            if (alreadyHandled.compareAndSet(false, true)) {
                handleScannedText(result.text)
            }
        } catch (e: NotFoundException) {
            // Bu karede QR bulunamadı — normal, bir sonraki kareyi bekle.
        } catch (e: Exception) {
            // Kısa bozuk Y düzlemi, ZXing'in kendi ArrayIndexOutOfBounds/
            // IllegalArgumentException'ı... bu kare çöpe: bir hata buradan
            // analiz thread'ine kaçtığında süreç ölüyordu ve kapatılmayan
            // ImageProxy KEEP_ONLY_LATEST akışını kalıcı olarak tıkıyordu.
            android.util.Log.w("QrScan", "Frame analysis failed, skipping frame", e)
        } finally {
            reader.reset()
            imageProxy.close()
        }
    }

    /** Rust çağrıları (eşleşme/el sıkışma) uzun sürebilir: ana thread'de
     *  çalışınca kamera önizlemesi donup siyah ekran kalıyordu. Arka planda
     *  çalıştır, sonucu UI'ya döndür. */
    private fun handleScannedText(text: String) {
        val cborBytes = if (addServerMode) ByteArray(0) else QrBinaryCodec.latin1StringToBytes(text)
        if (!addServerMode && !linkApproveMode) {
            // #87: confirm before the handshake starts (name + safety code from
            // a side-effect-free peek); cancel = nothing sent.
            Thread {
                val peek = try { P2PLib.peekContactQr(cborBytes) } catch (e: Throwable) { "Error: ${e.message}" }
                val obj = if (peek.startsWith("Error:")) null else try { JSONObject(peek) } catch (e: Exception) { null }
                runOnUiThread {
                    if (isFinishing) return@runOnUiThread
                    if (obj == null) {
                        Toast.makeText(this, com.p2p.messenger.util.coreErrorText(this, peek), Toast.LENGTH_LONG).show()
                        rearmLater()
                        return@runOnUiThread
                    }
                    androidx.appcompat.app.AlertDialog.Builder(this)
                        .setTitle(R.string.title_confirm_contact)
                        .setMessage(getString(R.string.msg_confirm_contact_named, obj.optString("name"), obj.optString("safety_code")))
                        .setPositiveButton(android.R.string.ok) { _, _ -> runScanned(text, cborBytes) }
                        .setNegativeButton(android.R.string.cancel) { _, _ -> rearmLater() }
                        .setOnCancelListener { rearmLater() }
                        .show()
                }
            }.start()
            return
        }
        // Not at once: any code caught in the frame added a server, or linked
        // a device with the whole account. The user sees what it is first.
        val question = if (addServerMode) {
            val invite = text.trim()
            // Already off the main thread (camera analyzer): the same
            // history-server read MainActivity does before its confirm dialog.
            addServerQuestion(invite.take(300), P2PLib.nextServerStoresHistory(invite))
        } else {
            val peek = try { P2PLib.peekDeviceLink(cborBytes) } catch (e: Throwable) { "Error: ${e.message}" }
            val obj = if (peek.startsWith("Error:")) null else try { JSONObject(peek) } catch (e: Exception) { null }
            if (obj == null) {
                runOnUiThread { if (!isFinishing) onScanResult(if (peek.startsWith("Error:")) peek else "Error: $peek") }
                return
            }
            val code = try { P2PLib.deviceLinkCode(cborBytes) } catch (e: Throwable) { "" }
            getString(R.string.link_device_confirm, obj.optString("device_name"), obj.optString("device_fingerprint")) +
                "\n\n" + getString(R.string.link_device_code_check, code)
        }
        runOnUiThread {
            if (isFinishing) return@runOnUiThread
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setMessage(question)
                .setPositiveButton(android.R.string.ok) { _, _ -> runScanned(text, cborBytes) }
                .setNegativeButton(android.R.string.cancel) { _, _ -> rearmLater() }
                .setOnCancelListener { rearmLater() }
                .show()
        }
    }

    /** The add-server question; the history warning (and what joining it
     *  uploads) only when this server would become the history server. */
    private fun addServerQuestion(code: String, historyServer: Boolean): String =
        getString(R.string.msg_join_link_confirm, code) +
            if (historyServer) {
                "\n\n" + getString(R.string.lbl_server_history_warn) + " " + getString(R.string.msg_server_history_upload)
            } else ""

    private fun runScanned(text: String, cborBytes: ByteArray) {
        Thread {
            val result = try {
                when {
                    addServerMode -> P2PLib.addServer(text.trim())
                    linkApproveMode -> P2PLib.approveDeviceLink(cborBytes)
                    else -> P2PLib.processQrPacket(cborBytes)
                }
            } catch (e: Throwable) {
                "Error: ${e.message}"
            }
            runOnUiThread { if (!isFinishing) onScanResult(result) }
        }.start()
    }

    /** Not at once: a bad code that stays in view started a thread, a JNI
     *  call and a long toast on every camera frame. */
    private fun rearmLater() {
        window.decorView.postDelayed({ alreadyHandled.set(false) }, 2000)
    }

    private fun onScanResult(result: String) {
        run {
            if (addServerMode) {
                // Sunucu davet kodu DÜZ METİN — CBOR'a çevirmiyoruz (bkz.
                // MODE_ADD_SERVER notu). Rust tarafı adresi ve jetonu
                // kendisi ayrıştırır.
                if (result.startsWith("Error:")) {
                    Toast.makeText(this, com.p2p.messenger.util.coreErrorText(this, result), Toast.LENGTH_LONG).show()
                    rearmLater()
                } else {
                    Toast.makeText(this, getString(R.string.msg_server_added), Toast.LENGTH_LONG).show()
                    finish()
                }
                return@run
            }
            if (linkApproveMode) {
                // Çoklu-cihaz (spec 1.5): taranan QR bir ikincil cihaz ekleme
                // isteği — onayla, imzalı DeviceAdd + tam senkron gönder.
                if (result.startsWith("Error:")) {
                    Toast.makeText(this, com.p2p.messenger.util.coreErrorText(this, result), Toast.LENGTH_LONG).show()
                    rearmLater()
                } else {
                    Toast.makeText(this, getString(R.string.link_device_approved), Toast.LENGTH_LONG).show()
                    finish()
                }
                return@run
            }
            if (result.startsWith("Error:")) {
                Toast.makeText(this, com.p2p.messenger.util.coreErrorText(this, result), Toast.LENGTH_LONG).show()
                rearmLater()
            } else {
                // Spec dışı, kullanıcı isteği: ilk eşleşme (gerçek dial/
                // Noise/IdentityExchange el sıkışması) UZUN sürebilir — bir
                // toast gösterip bu ekranı kapatmak, kullanıcıyı hiçbir
                // ilerleme göstergesi olmadan bırakıyordu. Artık kullanıcı
                // DOĞRUDAN yeni kişinin sohbet ekranına yönlendiriliyor —
                // o ekran zaten `hasActiveSession`/`isPeerConnected`'a
                // bakan bir "Bağlanılıyor..." göstergesi (bkz. ChatActivity
                // sessionPollRunnable/layoutConnecting/dotPeerStatus)
                // taşıyor, eşleşmenin hâlâ devam ettiğini (WIP) doğal
                // olarak gösterir.
                openChatOrFallback(result)
            }
        }
    }

    /** bkz. `handleScannedText` — `P2PLib.processQrPacket`'in JSON dönüşünü
     *  (`{"identity_id":...,"device_fingerprint":...,"device_name":...}`)
     *  ayrıştırıp yeni kişinin sohbet ekranını açar. Ayrıştırma başarısız
     *  olursa (beklenmeyen bir durum) eski davranışa (toast + kapat) düşer. */
    private fun openChatOrFallback(resultJson: String) {
        val deviceFingerprint: String?
        val deviceName: String
        try {
            val obj = JSONObject(resultJson)
            deviceFingerprint = obj.optString("device_fingerprint").ifEmpty { null }
            deviceName = obj.optString("device_name")
        } catch (e: Exception) {
            Toast.makeText(this, R.string.msg_connected, Toast.LENGTH_SHORT).show()
            finish()
            return
        }
        if (deviceFingerprint == null) {
            Toast.makeText(this, R.string.msg_connected, Toast.LENGTH_SHORT).show()
            finish()
            return
        }
        val intent = Intent(this, ChatActivity::class.java).apply {
            putExtra(ChatActivity.EXTRA_PEER_DEVICE_FINGERPRINT, deviceFingerprint)
            putExtra(ChatActivity.EXTRA_PEER_DISPLAY_NAME, deviceName.ifEmpty { deviceFingerprint.take(8) })
        }
        startActivity(com.p2p.messenger.util.ShareIntake.attachTo(intent))
        finish()
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
