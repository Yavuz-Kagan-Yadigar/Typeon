package com.p2p.messenger

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.setupWithNavController
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.IdentityManager
import org.json.JSONArray

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private val alertPollHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private val alertPollRunnable = object : Runnable {
        override fun run() {
            checkPendingDeviceAlerts()
            alertPollHandler.postDelayed(this, 5000)
        }
    }

    /** Android 13+ (API 33) bildirim göstermek için çalışma zamanı izni
     *  ister — bu YAPILMADAN hem P2PService'in kalıcı bildirimi hem de
     *  (bkz. NotificationHelper) gelen mesaj bildirimleri sistem tarafından
     *  SESSİZCE bastırılır. Google Play Services/FCM ile ilgisi yok, salt
     *  platform izni. */
    private val requestNotificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* reddedilse bile devam ediyoruz — bildirimler o zaman görünmez, mesajlaşma etkilenmez */ }

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        ensureNotificationPermission()

        statusText = findViewById(R.id.statusText)
        val navView: BottomNavigationView = findViewById(R.id.nav_view)
        // NOT: `Activity.findNavController(viewId)` yerine NavHostFragment'ı
        // FragmentManager'dan doğrudan alıp `.navController` okuyoruz —
        // ilki, NavHostFragment'ın kendi NavController tag'ini XML'deki
        // konteyner view'ına taşıması gereken bir iç kontrole (`onViewCreated`
        // içindeki `viewParent.id == id`) bağımlı ve bazı ortamlarda bu adım
        // atlanıp "does not have a NavController set" hatasına yol açabiliyor.
        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        val navController = navHostFragment.navController
        navView.setupWithNavController(navController)

        // Her şeyden önce: Android'in uygulamaya özel dosya dizinini Rust
        // tarafına geçirip SQLite'ı orada açıyoruz (Rust kendi başına bu
        // yolu bilemez). Bu, varsa mevcut identity'nin PUBLIC key'lerini
        // de belleğe yükler.
        P2PLib.initDatabase(applicationContext.filesDir.absolutePath)

        if (P2PLib.hasStoredIdentity()) {
            // Public key'ler yüklendi ama secret key'ler henüz Rust
            // belleğinde değil — Keystore ile şifrelenmiş dosyadan çözüp
            // yüklüyoruz.
            val loaded = IdentityManager.loadIfPresent(applicationContext)
            if (!loaded) {
                // identity_secret.enc kayıp/bozuk — Keystore anahtarı
                // muhtemelen kaybolmuş (ör. cihaz sıfırlandı). Kurtarma
                // dosyasından geri yükleme akışı burada tetiklenmeli
                // (spec 1.8) — Aşama A kapsamında henüz UI'ı yok, şimdilik
                // kullanıcıyı bilgilendiriyoruz.
                Toast.makeText(
                    this,
                    "Kimlik anahtarları okunamadı. Kurtarma dosyanız varsa onu kullanmanız gerekebilir.",
                    Toast.LENGTH_LONG
                ).show()
            }
            startNetworkService()
        } else {
            // İlk açılış: kullanıcıdan cihaz adı iste, identity'yi bir kez
            // oluştur (spec 1: her Device bir device_name taşır).
            showDeviceNameDialog()
        }
    }

    private fun showDeviceNameDialog() {
        val input = EditText(this)
        input.hint = "Cihaz adı (ör. Telefonum)"
        AlertDialog.Builder(this)
            .setTitle("Hoş geldiniz")
            .setMessage("Kimliğinizi oluşturmak için bir cihaz adı girin.")
            .setView(input)
            .setCancelable(false)
            .setPositiveButton("Oluştur") { _, _ ->
                val deviceName = input.text.toString().ifBlank { "Device" }
                val identityId = P2PLib.createIdentity(deviceName)
                if (identityId.startsWith("Error:")) {
                    Toast.makeText(this, identityId, Toast.LENGTH_LONG).show()
                } else {
                    // Secret key bundle'ını HEMEN Keystore ile şifreleyip
                    // diske yaz — aksi halde süreç öldüğünde kaybolur.
                    IdentityManager.persistNewIdentity(applicationContext)
                    statusText.text = "ID: ${identityId.take(8)}..."
                    startNetworkService()
                }
            }
            .show()
    }

    private fun startNetworkService() {
        val serviceIntent = Intent(this, P2PService::class.java)
        startForegroundService(serviceIntent)
        try {
            statusText.text = "ID: ${P2PLib.getIdentityShortCode()}"
        } catch (e: Exception) {
            // identity henüz okunamadı, önemli değil — status metni ikinci
            // planda.
        }
    }

    override fun onResume() {
        super.onResume()
        alertPollHandler.post(alertPollRunnable)
    }

    override fun onPause() {
        super.onPause()
        alertPollHandler.removeCallbacks(alertPollRunnable)
    }

    /**
     * Spec 2.2: bekleyen cihaz değişikliği uyarılarını kontrol eder, varsa
     * kullanıcıya bir uyarı dialog'u gösterir (kabul/red).
     */
    private fun checkPendingDeviceAlerts() {
        val json = try {
            P2PLib.listPendingDeviceAlerts()
        } catch (e: Exception) {
            return
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            return
        }
        if (array.length() == 0) return

        val alert = array.getJSONObject(0)
        val contactName = alert.optString("contact_display_name", "Bilinmeyen")
        val newCode = alert.optString("new_device_short_code", "")
        val fingerprint = alert.optString("new_device_fingerprint", "")

        AlertDialog.Builder(this)
            .setTitle("Güvenlik Uyarısı")
            .setMessage(
                "$contactName için yeni ve DOĞRULANMAMIŞ bir cihaz tespit edildi.\n\n" +
                "Yeni cihaz kodu: $newCode\n\n" +
                "Bu değişikliği $contactName ile başka bir kanaldan (telefon, yüz yüze) " +
                "doğrulamadan kabul etmeyin."
            )
            .setPositiveButton("Doğruladım, Kabul Et") { _, _ ->
                P2PLib.acceptDeviceAlert(fingerprint)
            }
            .setNegativeButton("Reddet") { _, _ ->
                P2PLib.rejectDeviceAlert(fingerprint)
            }
            .setCancelable(false)
            .show()
    }
}
