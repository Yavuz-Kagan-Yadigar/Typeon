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
 * QR scanning flow (section 1.3 and 1.4). Reads the QR from the camera image, converts it to raw CBOR bytes with
 * ISO-8859-1 (see QrBinaryCodec), and handles it with P2PLib.processQrPacket.
 */
class QrScanActivity : AppCompatActivity() {

    companion object {
        /** Multi-device (section 1.5): if this extra is `"link_approve"`, the scanned QR is NOT a contact pairing QR. It is a
         *  SECONDARY device add QR, and `approveDeviceLink` is called. If it is missing or empty, the normal contact pairing
         *  (`processQrPacket`) runs. */
        const val EXTRA_MODE = "mode"
        const val MODE_LINK_APPROVE = "link_approve"
        /** Server invitation QR (store-and-forward). Unlike the other two modes, this QR carries plain text, not CBOR. It holds
         *  an invitation code `typeon-server:<multiaddr>#<token>`. The server app also shows it as copyable text, so this is the
         *  single canonical format. */
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
        // Debug builds only (see the debug manifest). A decoded QR sent over adb goes through the same confirm-and-run path as a
        // camera frame. Malformed hex input from adb is ignored, and the camera opens as usual.
        val injected = intent.getStringExtra("debug_qr_hex")
            ?.takeIf { applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0 }
            ?.let { hex -> runCatching { hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray() }.getOrNull() }
        if (injected != null) {
            val bytes = injected
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
        // SurfaceView shows a black frame on some devices (performance); TextureView is safe.
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
                // If the camera cannot open (privacy switch or ERROR_CAMERA_DISABLED, another app is using it, or a hardware fault),
                // the preview stayed black and the user was told nothing. Show the error and close the screen.
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
            // The encoder side must also use ISO-8859-1 (see QrBinaryCodec). Otherwise ZXing guesses the QR's real character set
            // itself, and the result may not match rawBytes.
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
            // The plane's row stride is the data width. With padded rows (stride wider than the image), the picture was sheared
            // and never decoded.
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
        // No QR found in this frame. That is normal, so wait for the next frame.
        } catch (e: Exception) {
            // A short or corrupt Y plane makes ZXing throw ArrayIndexOutOfBoundsException or IllegalArgumentException. This frame is
            // discarded. If the exception left the analysis thread, the process died, and the ImageProxy that was not closed kept
            // the KEEP_ONLY_LATEST stream blocked for good.
            android.util.Log.w("QrScan", "Frame analysis failed, skipping frame", e)
        } finally {
            reader.reset()
            imageProxy.close()
        }
    }

    /** Core calls (pairing and handshake) can take a long time. On the main thread the camera preview froze into a black screen.
     *  So they run in the background, and the result returns to the UI. */
    private fun handleScannedText(text: String) {
        val cborBytes = if (addServerMode) ByteArray(0) else QrBinaryCodec.latin1StringToBytes(text)
        if (!addServerMode && !linkApproveMode) {
            // Confirm before the handshake starts: name and safety code are shown from a peek with no side effects. Cancel sends nothing.
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
        // Not at once. Any code caught in the frame could add a server, or link a device with the whole account. The user sees what
        // it is first.
        val question = if (addServerMode) {
            val invite = text.trim()
            // Already off the main thread (camera analyzer). Same history-server read as MainActivity, before its confirm dialog.
            addServerQuestion(invite, P2PLib.nextServerStoresHistory(invite))
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

    /** The add-server question. The history warning, and what joining it uploads, is shown only when this server would become the
     *  history server. */
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

    /** Not at once. A bad code that stays in view would otherwise start a thread, a JNI call and a long toast on every camera frame. */
    private fun rearmLater() {
        window.decorView.postDelayed({ alreadyHandled.set(false) }, 2000)
    }

    private fun onScanResult(result: String) {
        run {
            if (addServerMode) {
                // The server invitation code is plain TEXT. It is NOT converted to CBOR (see the MODE_ADD_SERVER note). The Rust side
                // parses the address and token itself.
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
                // Multi-device (section 1.5): the scanned QR is a secondary device add request. Approve it, and send a signed DeviceAdd
                // plus a full sync.
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
                // The first pairing (a real dial and Noise / IdentityExchange handshake) can take a long time. Showing a toast and
                // closing this screen used to leave the user with no progress indicator. Now the user goes straight to the new contact's
                // chat screen. That screen already shows a "Connecting..." indicator from `hasActiveSession` and `isPeerConnected`
                // (see ChatActivity sessionPollRunnable, layoutConnecting, dotPeerStatus), so the pairing still in progress is visible.
                openChatOrFallback(result)
            }
        }
    }

    /** See `handleScannedText`. This parses the JSON returned by `P2PLib.processQrPacket`
     *  (`{"identity_id":...,"device_fingerprint":...,"device_name":...}`) and opens the new contact's chat screen. If parsing fails
     *  (an unexpected case), it falls back to the old behaviour: toast and close. */
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
