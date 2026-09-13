package com.p2p.messenger.server

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import org.json.JSONArray
import org.json.JSONObject

/**
 * Sunucunun tek ekranı: aç/kapat, adresler, katılım QR'ı, kayıtlı cihazlar.
 *
 * Bilinçli olarak minimal — bu bir mesajlaşma uygulaması değil, bir altyapı
 * aracı. Gösterdiği her şey operatörün gerçekten karar vermesi gereken
 * şeyler: sunucu ayakta mı, adresi ne, kimi davet ettim, kimi çıkarıyorum.
 */
class ServerActivity : AppCompatActivity() {

    private val handler = Handler(Looper.getMainLooper())
    private lateinit var statusText: TextView
    private lateinit var addressText: TextView
    private lateinit var statsText: TextView
    private lateinit var devicesContainer: LinearLayout
    private lateinit var qrImage: ImageView
    private lateinit var inviteCodeText: TextView
    private var lastInvite: String? = null

    /**
     * Son çizilen cihaz listesinin ham JSON'u ve son yazılan durum/istatistik
     * metinleri. Yenileme turu saniyede bir dönüyor; DEĞİŞMEDİĞİ hâlde
     * satırları söküp yeniden kurmak ScrollView'ın odağı kaybedip listenin
     * başına zıplamasına yol açıyordu (ekran kendiliğinden yukarı kayıyor).
     */
    private var lastDevicesJson: String? = null
    private var lastStatus: String? = null
    private var lastAddresses: String? = null
    private var lastStats: String? = null

    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshStatus()
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_server)

        statusText = findViewById(R.id.status_text)
        addressText = findViewById(R.id.address_text)
        statsText = findViewById(R.id.stats_text)
        devicesContainer = findViewById(R.id.devices_container)
        qrImage = findViewById(R.id.invite_qr)
        inviteCodeText = findViewById(R.id.invite_code)

        val enableSwitch = findViewById<SwitchMaterial>(R.id.switch_enabled)
        enableSwitch.isChecked = ServerService.isEnabled(this)
        enableSwitch.setOnCheckedChangeListener { _, checked ->
            ServerService.setEnabled(this, checked)
            if (checked) {
                startServerService()
            } else {
                // Defter #11: artık gerçekten duruyor — `ServerService.onDestroy`
                // `ServerLib.stopServer()` çağırıyor, o da Rust döngüsünü
                // sonlandırıyor. "Yeniden başlatma gerekiyor" uyarısı kalktı.
                stopService(Intent(this, ServerService::class.java))
            }
        }

        val nodeSwitch = findViewById<SwitchMaterial>(R.id.switch_node)
        nodeSwitch.isChecked = ServerService.isNodeMode(this)
        nodeSwitch.setOnCheckedChangeListener { _, checked ->
            ServerService.setNodeMode(this, checked)
            // Defter #11: node modu artık gerçekten uygulanabiliyor —
            // sunucuyu durdurup yeniden başlatmak yeterli (süreç öldürmeye
            // gerek yok).
            if (ServerService.isEnabled(this)) {
                restartServerService()
            }
        }

        findViewById<Button>(R.id.btn_new_invite).setOnClickListener { confirmRotateJoinCode() }
        findViewById<Button>(R.id.btn_copy_invite).setOnClickListener { copyInvite() }
        findViewById<Button>(R.id.btn_battery).setOnClickListener { requestIgnoreBatteryOptimizations() }
        findViewById<Button>(R.id.btn_storage).setOnClickListener { chooseStorage() }
        refreshStorageLabel()

        if (ServerService.isEnabled(this)) {
            startServerService()
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(refreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(refreshRunnable)
    }

    /**
     * Sunucuyu durdurup yeniden başlatır — yapılandırma değişiklikleri
     * (node modu, blob dizini, disk bütçesi) yalnızca `startServer`
     * anında okunuyor ve o da çalışan bir çekirdek varken no-op.
     */
    private fun restartServerService() {
        stopService(Intent(this, ServerService::class.java))
        handler.postDelayed({ startServerService() }, 600)
    }

    private fun startServerService() {
        val intent = Intent(this, ServerService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun refreshStatus() {
        val json = try {
            JSONObject(ServerLib.serverStatus())
        } catch (e: Exception) {
            JSONObject()
        }
        if (!json.optBoolean("running")) {
            lastStatus = setTextIfChanged(statusText, getString(R.string.state_stopped), lastStatus)
            lastAddresses = setTextIfChanged(addressText, "", lastAddresses)
            lastStats = setTextIfChanged(statsText, "", lastStats)
            return
        }

        val tor = json.optString("tor")
        lastStatus = setTextIfChanged(statusText, getString(R.string.state_running_fmt, tor), lastStatus)

        val addrs = json.optJSONArray("addresses") ?: JSONArray()
        val addressLabel = if (addrs.length() == 0) {
            // Tor açıkken onion adresi arti'nin bootstrap'ını bekler; ilk
            // açılışta 30-60 sn sürebilir ve o ana kadar davet kodu
            // üretilemez.
            getString(R.string.state_no_address)
        } else {
            (0 until addrs.length()).joinToString("\n") { addrs.optString(it) }
        }
        val addressesChanged = addressLabel != lastAddresses
        lastAddresses = setTextIfChanged(addressText, addressLabel, lastAddresses)

        // Kod, adres hazır olur olmaz kendiliğinden görünür — operatörün
        // bir düğmeye basması gerekmez. Yalnızca henüz gösterilmediyse
        // sorulur: kod KALICI, saniyede bir yeniden okumanın (JNI + iki
        // SQLite sorgusu) hiçbir karşılığı yok.
        // Kod adresleri içeriyor: adres değişince (Wi-Fi IP'si, onion hazır
        // olunca) eski QR yanlış adrese götürür — yeniden oku.
        if (addrs.length() > 0 && (lastInvite == null || addressesChanged)) showJoinCode()

        lastStats = setTextIfChanged(
            statsText,
            getString(
                R.string.stats_fmt,
                json.optInt("devices"),
                json.optLong("deposits"),
                json.optLong("fetches"),
                json.optLong("chunks_served"),
                formatBytes(diskUsage())
            ),
            lastStats
        )

        refreshDevices()
    }

    /**
     * Metni yalnızca gerçekten değiştiyse yazar.
     *
     * `TextView.setText` aynı metinle bile yeni bir ölçüm/yerleşim turu
     * tetikliyor; saniyede bir tüm ekranı yeniden yerleştirmek kaydırma
     * konumunu oynatıyordu. Karşılaştırmayı `TextView.getText` yerine ayrı
     * bir alanda tutuyoruz: seçilebilir metinlerde (`textIsSelectable`)
     * getText, span'lar yüzünden yazdığımız String'e eşit çıkmayabiliyor.
     */
    private fun setTextIfChanged(view: TextView, value: String, last: String?): String {
        if (value != last) view.text = value
        return value
    }

    private fun diskUsage(): Long = try {
        ServerLib.diskUsage().toLong()
    } catch (e: Exception) {
        0L
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1_073_741_824 -> String.format("%.1f GB", bytes / 1_073_741_824.0)
        bytes >= 1_048_576 -> String.format("%.1f MB", bytes / 1_048_576.0)
        bytes >= 1024 -> String.format("%.1f KB", bytes / 1024.0)
        else -> "$bytes B"
    }

    private fun refreshDevices() {
        val raw = try {
            ServerLib.listDevices()
        } catch (e: Exception) {
            "[]"
        }
        // Liste aynıysa hiçbir şeye dokunma: `removeAllViews` + yeniden ekleme,
        // o an odaklı olan satır düğmesini yok ediyor ve ScrollView odağı
        // yukarıdaki ilk odaklanabilir view'a taşıyarak ekranı kaydırıyordu.
        if (raw == lastDevicesJson) return
        lastDevicesJson = raw
        val arr = try {
            JSONArray(raw)
        } catch (e: Exception) {
            JSONArray()
        }
        devicesContainer.removeAllViews()
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val id = obj.optString("enrollment_id")
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, 8, 0, 8)
            }
            row.addView(TextView(this).apply {
                // Kayıt kimliği, cihazın GERÇEK kimliğiyle ilişkisiz taze bir
                // anahtardan üretiliyor (bkz. Rust `ServerRequest::Enroll`) —
                // operatör kimin kim olduğunu buradan öğrenemez, sadece
                // iptal edebilir.
                text = getString(
                    R.string.device_row_fmt,
                    id.take(12),
                    formatBytes(obj.optLong("bytes_mail") + obj.optLong("bytes_archive") + obj.optLong("bytes_blob"))
                )
                textSize = 13f
                if (obj.optBoolean("revoked")) alpha = 0.4f
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })
            val blocked = obj.optBoolean("blocked")
            if (!obj.optBoolean("revoked")) {
                row.addView(Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                    setText(R.string.action_revoke)
                    setOnClickListener { confirmRevoke(id) }
                })
            }
            // Kullanıcı kararı: iptalin YANINA engelleme. İptal, cihazın taze
            // bir davetle geri dönmesine izin verir; engel vermez.
            row.addView(Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                setText(if (blocked) R.string.action_unblock else R.string.action_block)
                setOnClickListener { if (blocked) unblock(id) else confirmBlock(id) }
            })
            devicesContainer.addView(row)
        }
    }

    private fun confirmRevoke(enrollmentId: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.dlg_revoke_title)
            .setMessage(R.string.dlg_revoke_body)
            .setPositiveButton(R.string.action_revoke) { _, _ ->
                val res = try {
                    ServerLib.revokeDevice(enrollmentId)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                if (res.startsWith("Error:")) {
                    Toast.makeText(this, res, Toast.LENGTH_LONG).show()
                }
                lastDevicesJson = null
                refreshDevices()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Engelleme, iptalden farklı: kayıt anahtarına konur, yani cihaz taze
     * bir davetle bile geri dönemez. Bu yüzden ayrı bir onay metni var.
     */
    private fun confirmBlock(enrollmentId: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.dlg_block_title)
            .setMessage(R.string.dlg_block_body)
            .setPositiveButton(R.string.action_block) { _, _ ->
                val res = try {
                    ServerLib.blockDevice(enrollmentId)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                if (res.startsWith("Error:")) {
                    Toast.makeText(this, res, Toast.LENGTH_LONG).show()
                }
                lastDevicesJson = null
                refreshDevices()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun unblock(enrollmentId: String) {
        val res = try {
            ServerLib.unblockDevice(enrollmentId)
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
        if (res.startsWith("Error:")) {
            Toast.makeText(this, res, Toast.LENGTH_LONG).show()
        }
        lastDevicesJson = null
        refreshDevices()
    }

    /**
     * Kalıcı katılım kodunu gösterir (bkz. `ServerLib.joinCode`).
     *
     * `refreshStatus` her turda çağırır ama iş YALNIZCA kod değiştiğinde
     * yapılır: QR kodlama 900x900'lük bir bitmap'i piksel piksel dolduruyor,
     * saniyede bir tekrarlamak ana thread'i boşuna meşgul ederdi. Sunucunun
     * adresi (Tor bootstrap) hazır olur olmaz kod kendiliğinden belirir —
     * operatörün bir düğmeye basması gerekmez.
     */
    private fun showJoinCode(rotate: Boolean = false) {
        val code = try {
            ServerLib.joinCode(rotate)
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
        if (code.startsWith("Error:")) {
            // Adres henüz yokken (Tor açılıyor) hata NORMAL: bir sonraki
            // yenileme turu tekrar dener. Kullanıcıyı her 2 saniyede bir
            // Toast'la rahatsız etmenin anlamı yok — yalnızca kodu
            // KENDİSİ yenilemek istediğinde söylüyoruz.
            if (rotate) Toast.makeText(this, code, Toast.LENGTH_LONG).show()
            return
        }
        if (code == lastInvite) return
        lastInvite = code
        qrImage.setImageBitmap(encodeQr(code, 900, 900))
        inviteCodeText.text = code
    }

    /**
     * Kodu döndürme YIKICI: yayımlanmış QR/link o an ölür ve henüz
     * katılmamış herkesin elindeki kod çalışmaz. Bu yüzden onay isteniyor —
     * eski "yeni davet üret" düğmesinin aksine burada geri dönüş yok.
     */
    private fun confirmRotateJoinCode() {
        AlertDialog.Builder(this)
            .setTitle(R.string.action_new_invite)
            .setMessage(R.string.confirm_rotate_join_code)
            .setPositiveButton(R.string.action_new_invite) { _, _ -> showJoinCode(rotate = true) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun copyInvite() {
        if (lastInvite == null) showJoinCode()
        val code = lastInvite
        if (code == null) {
            Toast.makeText(this, R.string.msg_no_invite_yet, Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("Typeon server invite", code))
        Toast.makeText(this, R.string.msg_invite_copied, Toast.LENGTH_SHORT).show()
    }

    /**
     * Davet kodunu QR'a çevirir.
     *
     * İstemcinin QR'larından FARKLI olarak burada `QrBinaryCodec` yok:
     * davet kodu düz ASCII metin (`typeon-server:…#…`), CBOR değil. Sunucu
     * uygulaması aynı kodu kopyalanabilir metin olarak da gösterdiği için
     * tek kanonik biçim bu.
     */
    private fun encodeQr(text: String, width: Int, height: Int): Bitmap {
        val hints = mapOf(EncodeHintType.CHARACTER_SET to "UTF-8")
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height, hints)
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        return bitmap
    }

    /**
     * Pil optimizasyonu muafiyeti. Bir sunucunun tanım gereği her zaman
     * açık olması gerekiyor; Android'in uyku kısıtlamaları bunu doğrudan
     * baltalar.
     */

    /** Seçili konumu ve boş alanını gösterir. */
    private fun refreshStorageLabel() {
        val dir = ServerService.blobDir(this)
        val free = try {
            android.os.StatFs(dir.absolutePath).availableBytes
        } catch (e: Throwable) {
            0L
        }
        findViewById<TextView>(R.id.txt_storage_current).text =
            getString(R.string.lbl_storage_desc) + "\n" + dir.absolutePath +
                " — " + (free / (1024 * 1024)) + " MB " + getString(R.string.lbl_free_suffix)
    }

    /**
     * Blob dizinini seçtirir ve gerekiyorsa BLOB'LARI taşır.
     *
     * Defter #12: bu yorum eskiden "dizinde SQLite, libp2p kimliği ve Tor
     * onion durumu da duruyor, o yüzden taşımak şart" diyordu — YANLIŞTI.
     * `chooseStorage` yalnızca `blobs` dizinini taşıyor; `data_dir` her
     * zaman `context.filesDir` (bkz. `ServerService.dataDir` ve
     * `jni.rs` — sadece `blob_dir` geçersiz kılınabiliyor). Yani peer id ve
     * .onion adresi bu işlemden HİÇ etkilenmiyor.
     */
    private fun chooseStorage() {
        val vols = ServerService.storageVolumes(this)
        val current = ServerService.blobDir(this)
        val labels = vols.map { v ->
            val free = try { android.os.StatFs(v.absolutePath).availableBytes } catch (e: Throwable) { 0L }
            // Etiketi YOLA göre tahmin etmek yanlış sonuç veriyordu:
            // `getExternalFilesDirs` dahili birimin `Android/data` dizinini de
            // döndürüyor ve o da "SD kart" görünüyordu (ikisi de aynı boş
            // alanı gösterince kullanıcı hangisini seçeceğini bilemez).
            // `isExternalStorageRemovable` gerçekten çıkarılabilir birimi
            // ayırt eden tek doğru API.
            val name = when {
                v.absolutePath == filesDir.absolutePath -> getString(R.string.lbl_internal)
                isRemovable(v) -> getString(R.string.lbl_sdcard)
                else -> getString(R.string.lbl_external)
            }
            val mark = if (java.io.File(v, "blobs").absolutePath == current.absolutePath) " ✓" else ""
            "$name$mark\n${free / (1024 * 1024)} MB " + getString(R.string.lbl_free_suffix)
        }.toTypedArray()

        AlertDialog.Builder(this)
            .setTitle(R.string.dlg_storage_title)
            .setItems(labels) { _, which ->
                val target = java.io.File(vols[which], "blobs")
                if (target.absolutePath == current.absolutePath) {
                    Toast.makeText(this, R.string.msg_storage_same, Toast.LENGTH_SHORT).show()
                    return@setItems
                }
                moveStorage(current, target)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }


    private fun isRemovable(dir: java.io.File): Boolean = try {
        android.os.Environment.isExternalStorageRemovable(dir)
    } catch (e: Throwable) {
        false
    }

    private fun moveStorage(from: java.io.File, to: java.io.File) {
        val wasRunning = ServerService.isEnabled(this)
        val progress = AlertDialog.Builder(this)
            .setMessage(R.string.dlg_storage_moving)
            .setCancelable(false)
            .show()
        // Defter #12: `stopService` TEK BAŞINA çekirdeği durdurmuyordu —
        // yani `copyTree` canlı bir sunucunun yazdığı blob'ları kopyalıyor,
        // `deleteTree` de orijinalleri onun altından siliyordu (devam eden
        // yükleme bozulur, tamamlanmış blob'lar diskten gider ama `blobs`
        // tablosu hâlâ "var" der). Artık `ServerService.onDestroy` →
        // `ServerLib.stopServer()` gerçekten durduruyor; kopyalamaya
        // başlamadan önce kısa bir pay bırakıyoruz.
        stopService(Intent(this, ServerService::class.java))
        Thread {
            try { Thread.sleep(800) } catch (e: InterruptedException) { }
            val error = try {
                copyTree(from, to)
                // Kopya bittikten SONRA sil — yarıda kalırsa veri kaybolmasın.
                deleteTree(from, keepRoot = true)
                null
            } catch (e: Throwable) {
                e.message ?: "bilinmeyen hata"
            }
            runOnUiThread {
                progress.dismiss()
                if (error == null) {
                    // Defter #12: yeni dizin YALNIZCA `startServer` anında
                    // okunuyor. Eskiden `startServer` no-op olduğu için
                    // taşıma sonrası çalışan çekirdek ESKİ (artık
                    // boşaltılmış) dizine yazmaya devam ediyordu; artık
                    // durdurma gerçek olduğu için yeniden başlatma yeni
                    // dizini alıyor.
                    ServerService.setBlobDir(this, to)
                    refreshStorageLabel()
                    Toast.makeText(this, R.string.msg_storage_moved, Toast.LENGTH_LONG).show()
                    if (wasRunning) startServerService()
                } else {
                    Toast.makeText(this, getString(R.string.msg_storage_failed, error), Toast.LENGTH_LONG).show()
                    if (wasRunning) startServerService()
                }
            }
        }.start()
    }

    private fun copyTree(from: java.io.File, to: java.io.File) {
        if (!to.exists() && !to.mkdirs()) throw java.io.IOException("hedef dizin oluşturulamadı")
        from.listFiles()?.forEach { child ->
            val dest = java.io.File(to, child.name)
            if (child.isDirectory) {
                copyTree(child, dest)
            } else {
                child.inputStream().use { input ->
                    dest.outputStream().use { output -> input.copyTo(output, 1 shl 16) }
                }
            }
        }
    }

    private fun deleteTree(dir: java.io.File, keepRoot: Boolean) {
        dir.listFiles()?.forEach { child ->
            if (child.isDirectory) deleteTree(child, keepRoot = false) else child.delete()
        }
        if (!keepRoot) dir.delete()
    }

    private fun requestIgnoreBatteryOptimizations() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        if (pm.isIgnoringBatteryOptimizations(packageName)) {
            Toast.makeText(this, R.string.msg_battery_already, Toast.LENGTH_SHORT).show()
            return
        }
        try {
            startActivity(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    .setData(Uri.parse("package:$packageName"))
            )
        } catch (e: Exception) {
            // Bazı ROM'larda bu intent yok — kullanıcı ayarlardan elle yapar.
            Toast.makeText(this, R.string.msg_battery_manual, Toast.LENGTH_LONG).show()
        }
    }
}
