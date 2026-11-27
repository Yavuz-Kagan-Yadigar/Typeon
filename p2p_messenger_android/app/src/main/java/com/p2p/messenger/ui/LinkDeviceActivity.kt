package com.p2p.messenger.ui

import com.p2p.messenger.util.ltr
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.doOnPreDraw
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.util.QrBinaryCodec

/**
 * Multi-device linking (section 1.5). The linking screen shown on the SECONDARY device. It shows this device's "add device QR"
 * (`buildDeviceLinkRequest`, fingerprint only; see the Rust packet.rs `DeviceLinkRequest` docs). The full public keys (ML-DSA-87 plus
 * ML-KEM-1024, about 4.2 KB in total) do not fit in one QR code. Scanning it used to fail every time with "Data too big". The screen
 * waits for the primary device to scan it. After the scan, the real keys are learned through a mutual `IdentityExchange`, and a signed
 * `DeviceAdd` plus a full sync arrive. Linking is complete when `isSecondaryDevice()` is `true`.
 *
 * Before this screen, the device has already gone through the normal `createIdentity` and `startNetwork` (with a provisional identity).
 * The QR can only be produced once the network listen address (`getNodeAddress`) is ready. So it is retried at short intervals (the
 * same pattern as ContactsFragment).
 */
class LinkDeviceActivity : AppCompatActivity() {

    private val handler = Handler(Looper.getMainLooper())
    private lateinit var qrImage: ImageView
    private lateinit var statusText: TextView
    private var done = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_link_device)
        supportActionBar?.title = getString(R.string.link_device_title)
        qrImage = findViewById(R.id.link_qr_image)
        statusText = findViewById(R.id.link_status)
        statusText.text = getString(R.string.link_device_waiting)

        // See the ContactsFragment imgOwnQr sizing note. The same sizing is used here. Instead of a fixed 280 dp, the QR grows to the smallest
        // measured size of this screen's own viewport, leaving room for the status and instruction text.
        val root = findViewById<View>(R.id.link_device_root)
        root.doOnPreDraw {
            val minDimensionPx = minOf(root.width, root.height)
            val thinMarginPx = (16 * resources.displayMetrics.density).toInt()
            val qrSide = (minDimensionPx - thinMarginPx * 2)
                .coerceAtLeast((160 * resources.displayMetrics.density).toInt())
            qrImage.layoutParams = qrImage.layoutParams.apply {
                width = qrSide
                height = qrSide
            }
        }

        tryBuildQr(attemptsLeft = 40)
    }

    override fun onResume() {
        super.onResume()
        if (!done) handler.post(pollAdopted)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(pollAdopted)
    }

    /** Retries QR generation until the network address is ready. */
    private fun tryBuildQr(attemptsLeft: Int) {
        // The JNI call (core lock) and the QR encode run off the main thread.
        Thread {
            val bytes = try { P2PLib.buildDeviceLinkRequest() } catch (e: Exception) { ByteArray(0) }
            var bmp: Bitmap? = null
            var code = ""
            if (bytes.isNotEmpty()) {
                // WriterException: the request does not fit a QR code.
                bmp = try { encodeBinaryAsQrBitmap(bytes, 1000, 1000) } catch (e: Exception) { null }
                code = try { P2PLib.deviceLinkCode(bytes) } catch (e: Throwable) { "" }
            }
            handler.post { if (!isDestroyed) showQr(bytes.isNotEmpty(), bmp, code, attemptsLeft) }
        }.start()
    }

    private fun showQr(haveBytes: Boolean, bmp: Bitmap?, code: String, attemptsLeft: Int) {
        if (!haveBytes) {
            // Fast retries first, then a slow one for as long as the screen is open (Tor can need minutes).
            if (attemptsLeft <= 0) statusText.text = getString(R.string.link_device_network_not_ready)
            handler.postDelayed({ tryBuildQr(maxOf(attemptsLeft - 1, 0)) }, if (attemptsLeft > 0) 500L else 5000L)
            return
        }
        if (bmp == null) {
            statusText.text = getString(R.string.link_device_network_not_ready)
            return
        }
        qrImage.setImageBitmap(bmp)
        // The approving device shows the same code in its confirm dialog.
        if (code.isNotEmpty()) {
            statusText.textAlignment = View.TEXT_ALIGNMENT_CENTER
            statusText.text = getString(R.string.link_device_waiting) + "\n\n" + getString(R.string.link_device_code_shown, ltr(code))
        }
    }

    override fun onDestroy() {
        // The QR retry lambda is not `pollAdopted`: onPause does not remove it.
        handler.removeCallbacksAndMessages(null)
        // Left without a link: a grant that comes later must not be accepted.
        if (isFinishing && !done) {
            // Takes the core lock: not on the UI thread.
            Thread { try { P2PLib.closeDeviceLinkWindow() } catch (e: Throwable) { } }.start()
        }
        super.onDestroy()
    }

    /** Polls every 2 seconds until the primary device accepts this device. */
    private val pollAdopted = object : Runnable {
        override fun run() {
            if (done) return
            // the JNI call runs off the main thread.
            Thread {
                val linked = try { P2PLib.isSecondaryDevice() } catch (e: Exception) { false }
                handler.post {
                    if (done || isDestroyed) return@post
                    if (linked) {
                        done = true
                        Toast.makeText(this@LinkDeviceActivity, R.string.link_device_success, Toast.LENGTH_LONG).show()
                        finish()
                    } else {
                        handler.postDelayed(this, 2000)
                    }
                }
            }.start()
        }
    }

    /** Same as ContactsFragment.encodeBinaryAsQrBitmap. */
    private fun encodeBinaryAsQrBitmap(data: ByteArray, width: Int, height: Int): Bitmap {
        val text = QrBinaryCodec.bytesToLatin1String(data)
        val hints = mapOf(EncodeHintType.CHARACTER_SET to "ISO-8859-1")
        val bitMatrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height, hints)
        // One bulk write instead of a million `setPixel` calls.
        val pixels = IntArray(width * height) { if (bitMatrix[it % width, it / width]) Color.BLACK else Color.WHITE }
        return Bitmap.createBitmap(pixels, width, height, Bitmap.Config.RGB_565)
    }
}
