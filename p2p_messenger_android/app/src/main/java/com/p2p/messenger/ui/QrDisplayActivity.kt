package com.p2p.messenger.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.util.QrBinaryCodec

/**
 * Spec 1.3: kendi QR kodumuzu gösterir (fingerprint-only paket, CBOR).
 * Karşı taraf bunu tarayınca P2PLib.processQrPacket ile eşleşme başlar.
 */
class QrDisplayActivity : AppCompatActivity() {

    private val retryHandler = Handler(Looper.getMainLooper())
    private var identityCode = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_display)
        supportActionBar?.title = "Kodum"

        identityCode = try {
            P2PLib.getIdentityCode()
        } catch (e: Exception) {
            ""
        }
        findViewById<TextView>(R.id.txtIdentityCode).text = identityCode

        findViewById<Button>(R.id.btnCopy).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("identity_code", identityCode))
            Toast.makeText(this, R.string.lbl_copied, Toast.LENGTH_SHORT).show()
        }

        loadNodeAddressAndGenerateQr(attemptsLeft = 10)
    }

    /**
     * `getNodeAddress()` sadece swarm gerçekten bir adres üzerinde dinlemeye
     * başladıktan sonra (bkz. Rust `poll_events`/`NewListenAddr`) dolu bir
     * değer döner — `startNetwork` çağrısından hemen sonraki ilk anlarda
     * boş olabilir. Sabit bir `/ip4/0.0.0.0/tcp/0` yerine koymak yerine
     * (karşı taraf bunu asla dial edemez — bkz. spec dışı önceki hata),
     * kısa aralıklarla birkaç kez deniyoruz.
     */
    private fun loadNodeAddressAndGenerateQr(attemptsLeft: Int) {
        val nodeAddress = try {
            P2PLib.getNodeAddress()
        } catch (e: Exception) {
            ""
        }

        if (nodeAddress.isEmpty() && attemptsLeft > 0) {
            findViewById<TextView>(R.id.txtNodeAddress).text = "Ağa bağlanılıyor..."
            retryHandler.postDelayed({ loadNodeAddressAndGenerateQr(attemptsLeft - 1) }, 500)
            return
        }

        if (nodeAddress.isEmpty()) {
            findViewById<TextView>(R.id.txtNodeAddress).text = "Ağa bağlanılamadı"
            Toast.makeText(this, "Ağa henüz bağlanılamadı — QR kod geçici olarak çalışmayabilir", Toast.LENGTH_LONG).show()
        } else {
            findViewById<TextView>(R.id.txtNodeAddress).text = nodeAddress
        }

        val qrBytes = try {
            P2PLib.generateQrPacket(nodeAddress)
        } catch (e: Exception) {
            null
        }

        if (qrBytes != null && qrBytes.isNotEmpty()) {
            val bitmap = encodeBinaryAsQrBitmap(qrBytes, 800, 800)
            findViewById<ImageView>(R.id.imgQRCode).setImageBitmap(bitmap)
        } else {
            Toast.makeText(this, "QR kod oluşturulamadı", Toast.LENGTH_LONG).show()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        retryHandler.removeCallbacksAndMessages(null)
    }

    /**
     * Ham CBOR baytlarını, QrBinaryCodec'in ISO-8859-1 kodlamasıyla bir QR
     * bitmap'ine gömer — QrScanActivity'nin aynı kodlamayla geri okuyacağı
     * varsayımına dayanır (bkz. QrBinaryCodec dokümantasyonu).
     */
    private fun encodeBinaryAsQrBitmap(data: ByteArray, width: Int, height: Int): Bitmap {
        val text = QrBinaryCodec.bytesToLatin1String(data)
        val hints = mapOf(EncodeHintType.CHARACTER_SET to "ISO-8859-1")
        val bitMatrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height, hints)
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        return bitmap
    }
}
