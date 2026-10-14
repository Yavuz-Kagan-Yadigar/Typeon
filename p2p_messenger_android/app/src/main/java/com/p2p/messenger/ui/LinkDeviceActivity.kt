package com.p2p.messenger.ui

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
 * Çoklu-cihaz (Description.md §1.5): İKİNCİL cihazda gösterilen bağlanma
 * ekranı. Bu cihazın "cihaz ekleme QR'ı"nı (`buildDeviceLinkRequest` —
 * fingerprint-only, bkz. Rust packet.rs `DeviceLinkRequest` dokümantasyonu:
 * tam public key'ler [ML-DSA-87 + ML-KEM-1024 dahil ~4.2KB] bir QR koduna
 * SIĞMAZ, önceden buradaki taramanın HER ZAMAN "Data too big" ile
 * çökmesine yol açıyordu) gösterir ve birincil cihazın onu taramasını
 * bekler. Birincil taradıktan sonra karşılıklı `IdentityExchange` ile
 * gerçek anahtarlar öğrenilir, imzalı `DeviceAdd` + tam senkron gelir;
 * `isSecondaryDevice()` `true` olduğunda bağlanma tamamlanmıştır.
 *
 * Bu cihaz bu ekrana gelmeden önce zaten normal `createIdentity` +
 * `startNetwork`'ten geçmiştir (provizyonel bir kimlikle) — QR yalnızca ağ
 * dinleme adresi (`getNodeAddress`) hazır olunca üretilebildiğinden kısa
 * aralıklarla yeniden denenir (bkz. ContactsFragment aynı desen).
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

        // bkz. ContactsFragment imgOwnQr sizing notu — kullanıcı isteği:
        // AYNI ölçekleme burada da kullanılsın. Sabit 280dp yerine, bu
        // ekranın kendi ölçülmüş viewport'unun (durum/talimat metni İÇİN
        // yer bırakarak) en küçük boyutu kadar büyütülür.
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

    /** Ağ adresi hazır olana kadar QR üretimini yeniden dener. */
    private fun tryBuildQr(attemptsLeft: Int) {
        val bytes = try { P2PLib.buildDeviceLinkRequest() } catch (e: Exception) { ByteArray(0) }
        if (bytes.isEmpty()) {
            if (attemptsLeft > 0) {
                handler.postDelayed({ tryBuildQr(attemptsLeft - 1) }, 500)
            } else {
                statusText.text = getString(R.string.link_device_network_not_ready)
            }
            return
        }
        try {
            qrImage.setImageBitmap(encodeBinaryAsQrBitmap(bytes, 1000, 1000))
            // The approving device shows the same code in its confirm dialog.
            val code = try { P2PLib.deviceLinkCode(bytes) } catch (e: Throwable) { "" }
            if (code.isNotEmpty()) {
                statusText.textAlignment = View.TEXT_ALIGNMENT_CENTER
                statusText.text = getString(R.string.link_device_waiting) + "\n\n" + getString(R.string.link_device_code_shown, code)
            }
        } catch (e: Exception) {
            // WriterException: the request does not fit a QR code.
            statusText.text = getString(R.string.link_device_network_not_ready)
        }
    }

    override fun onDestroy() {
        // The QR retry lambda is not `pollAdopted`: onPause does not remove it.
        handler.removeCallbacksAndMessages(null)
        // Left without a link: a grant that comes later must not be accepted.
        if (isFinishing && !done) {
            try { P2PLib.closeDeviceLinkWindow() } catch (e: Throwable) { }
        }
        super.onDestroy()
    }

    /** Birincil cihaz benimseyene kadar 2 saniyede bir yoklar. */
    private val pollAdopted = object : Runnable {
        override fun run() {
            if (done) return
            val linked = try { P2PLib.isSecondaryDevice() } catch (e: Exception) { false }
            if (linked) {
                done = true
                Toast.makeText(this@LinkDeviceActivity, R.string.link_device_success, Toast.LENGTH_LONG).show()
                finish()
                return
            }
            handler.postDelayed(this, 2000)
        }
    }

    /** bkz. ContactsFragment.encodeBinaryAsQrBitmap — birebir aynı. */
    private fun encodeBinaryAsQrBitmap(data: ByteArray, width: Int, height: Int): Bitmap {
        val text = QrBinaryCodec.bytesToLatin1String(data)
        val hints = mapOf(EncodeHintType.CHARACTER_SET to "ISO-8859-1")
        val bitMatrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height, hints)
        // One bulk write instead of a million `setPixel` calls.
        val pixels = IntArray(width * height) { if (bitMatrix[it % width, it / width]) Color.BLACK else Color.WHITE }
        return Bitmap.createBitmap(pixels, width, height, Bitmap.Config.RGB_565)
    }
}
