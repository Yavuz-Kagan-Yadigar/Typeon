package com.p2p.messenger

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.setupWithNavController
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.IdentityManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private val alertPollHandler = android.os.Handler(android.os.Looper.getMainLooper())
    /** Spec dışı, kararlılık denetimi düzeltmesi: `checkPendingDeviceAlerts`
     *  her 5 saniyede bir çalışır. Kullanıcı bir güvenlik uyarısını hemen
     *  kabul/red etmezse (ör. telefondan uzaklaşırsa), önceden HER turda
     *  `array.getJSONObject(0)` hâlâ aynı bekleyen uyarıyı döndürdüğü için
     *  YENİ bir `AlertDialog` (`setCancelable(false)`) üstüste açılıyordu —
     *  dakikalar içinde onlarca kapatılamaz modal dialog birikebilir, hatta
     *  kötü niyetli bir kişi tekrar tekrar yeni-cihaz olayı tetikleyerek bu
     *  ekranı kasıtlı spam'leyebilir (tam da bu güvenlik kontrolüne olan
     *  güveni zedeler). Şimdi hâlâ gösterilmekte olan uyarının parmak izini
     *  takip ediyoruz; aynı uyarı için ikinci bir dialog AÇILMAZ. */
    private var shownAlertFingerprint: String? = null
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
                AppLock.beginTrustedExcursion()
                requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    /** bkz. SettingsFragment `pickAvatarLauncher` aynı not: `registerForActivityResult`
     *  Activity STARTED olmadan ÖNCE (bir property initializer'ında) kaydedilmeli.
     *  bkz. `showImportPassphraseDialog`/`importRecoveryFrom` — SettingsFragment'ın
     *  "Kurtarma Dosyasını Dışa Aktar"ının EKSİK karşılığı: dışa aktarılan bir
     *  dosyanın bu (veya başka) bir cihazda geri yüklenebileceği hiçbir yer yoktu. */
    private val pickRecoveryFileLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { showImportPassphraseDialog(it) }
    }

    /** [showDeviceNameDialog]'daki isim alanından, dosya seçici açılmadan
     *  ÖNCE okunur (kullanıcı SAF'ta gezinirken dialog'un View'ı zaten
     *  dismiss edilmiş olur). */
    private var pendingImportDeviceName: String = "Device"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        ensureNotificationPermission()
        // Spec dışı, gerçek cihazda ölçülen hata düzeltmesi: bu fonksiyon
        // yazılmış ama HİÇ ÇAĞRILMAMIŞTI. Sonucu logcat'te görüldü — Android
        // ön plan servisini "app idle" diyerek durdurdu ("Stopping service
        // due to app idle") ve 14 MB'lık bir yükleme, kullanıcıya
        // "gönderildi" görünürken sessizce yarıda kaldı; `pollNetwork` bir
        // daha hiç çalışmadı. Muafiyet, o kısıtlamanın doğrudan çaresi.
        ensureBatteryOptimizationExemption()

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
                    R.string.msg_identity_read_failed,
                    Toast.LENGTH_LONG
                ).show()
            }
            startNetworkService()
        } else {
            // İlk açılış: kullanıcıdan cihaz adı iste, identity'yi bir kez
            // oluştur (spec 1: her Device bir device_name taşır).
            showDeviceNameDialog()
        }

        handleJoinLink(intent)
        handleShare(intent)
    }

    /** Paylaşım ekranından gelen içerik: bekletilir, kullanıcı sohbet seçince
     *  gönderilir (bkz. util.ShareIntake). */
    private fun handleShare(intent: Intent?) {
        if (!com.p2p.messenger.util.ShareIntake.isShare(intent)) return
        com.p2p.messenger.util.ShareIntake.pending = intent
        android.widget.Toast.makeText(this, R.string.msg_share_pick_chat, android.widget.Toast.LENGTH_LONG).show()
    }

    /** `singleTop` — uygulama zaten açıkken tıklanan katılım bağlantısı
     *  yeni bir örnek yerine BURAYA düşer (bkz. AndroidManifest). */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleJoinLink(intent)
        handleShare(intent)
    }

    /**
     * Kullanıcı isteği (2026-09-04): sunucuya tek bir QR/link/metin ile,
     * operatörle hiç konuşmadan katılabilmek. QR tarama ve elle yapıştırma
     * Ayarlar'da zaten vardı; burası ÜÇÜNCÜ yol — operatörün bir kez
     * yayımladığı `typeon-server:…#…` kodu, tıklanabilir bir bağlantı
     * olarak doğrudan uygulamayı açar.
     *
     * Onay diyaloğu ATLANMAZ: bir bağlantıya dokunmak, sunucu eklemeyi
     * kullanıcının GÖRDÜĞÜ bir karar olmaktan çıkarmamalı — kötü niyetli
     * bir sayfa aksi halde arka planda sunucu ekletebilirdi.
     */
    private fun handleJoinLink(intent: Intent?) {
        val data = intent?.data ?: return
        if (intent.action != Intent.ACTION_VIEW) return
        if (!data.scheme.equals("typeon-server", ignoreCase = true)) return
        // Aynı bağlantı `onCreate` + yapılandırma değişikliğiyle iki kez
        // gelmesin: tüketildiği anda intent'ten düşürülür.
        intent.data = null

        val code = data.toString()
        if (!P2PLib.hasStoredIdentity()) {
            // Hesap yokken sunucu eklenemez (çekirdeğin kimliği yok).
            // Kullanıcı hesabı oluşturduktan sonra kodu Ayarlar'a
            // yapıştırabilir — kodu panoya bırakmak sessizce kaybolmasını
            // engeller.
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("Typeon server", code))
            Toast.makeText(this, R.string.msg_join_link_needs_identity, Toast.LENGTH_LONG).show()
            return
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.dlg_add_server_title)
            .setMessage(getString(R.string.msg_join_link_confirm, code))
            .setPositiveButton(android.R.string.ok) { _, _ -> addServerFromLink(code) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun addServerFromLink(code: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            // `addServer` diske yazar ve dial başlatır — ana thread'de değil
            // (SettingsFragment'taki aynı çağrının senkron olması, orada
            // kullanıcının zaten bir diyalogda beklemesinden).
            val result = try {
                P2PLib.addServer(code)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@MainActivity, result, Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(this@MainActivity, R.string.msg_server_added, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun showDeviceNameDialog() {
        val input = EditText(this)
        input.hint = getString(R.string.hint_username)
        AlertDialog.Builder(this)
            .setTitle(R.string.title_welcome)
            .setMessage(R.string.msg_enter_username)
            .setView(input)
            .setCancelable(false)
            .setPositiveButton(R.string.action_create) { _, _ ->
                createIdentityAndStart(input.text.toString().ifBlank { "Device" }, linkAsSecondary = false)
            }
            // Çoklu-cihaz (spec 1.5): bu, var olan bir hesabın İKİNCİL cihazı.
            // Yine de kendi anahtar çiftini/geçici kimliğini üretir (birincilin
            // secret anahtarı asla kopyalanmaz) ve bir bağlanma QR'ı gösterir;
            // birincil cihaz bu QR'ı tarayınca bu cihaz hesaba katılır.
            .setNeutralButton(R.string.link_device_as_secondary) { _, _ ->
                createIdentityAndStart(input.text.toString().ifBlank { "Device" }, linkAsSecondary = true)
            }
            .setNegativeButton(R.string.action_restore_from_recovery) { _, _ ->
                pendingImportDeviceName = input.text.toString().ifBlank { "Device" }
                AppLock.beginTrustedExcursion()
                pickRecoveryFileLauncher.launch(arrayOf("*/*"))
            }
            .show()
    }

    /**
     * bkz. `pickRecoveryFileLauncher` dokümantasyonu. Dosya seçildikten
     * sonra parolayı ister (bkz. SettingsFragment `showExportRecoveryDialog`
     * AYNI desen) — dosyanın kendisi parola olmadan anlamsız (Argon2id ile
     * sertleştirilmiş, bkz. Rust `import_recovery`).
     */
    private fun showImportPassphraseDialog(uri: Uri) {
        val input = EditText(this).apply {
            hint = getString(R.string.lbl_recovery_password)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.action_restore_from_recovery)
            .setMessage(R.string.lbl_recovery_import_desc)
            .setView(input)
            .setCancelable(false)
            .setPositiveButton(R.string.action_restore_from_recovery) { _, _ ->
                val passphrase = input.text.toString()
                if (passphrase.isEmpty()) {
                    Toast.makeText(this, R.string.error_recovery_password_empty, Toast.LENGTH_SHORT).show()
                    showDeviceNameDialog()
                } else {
                    importRecoveryFrom(uri, passphrase)
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> showDeviceNameDialog() }
            .show()
    }

    /**
     * `P2PLib.importRecovery` KASITLI OLARAK yavaş bir Argon2id KDF
     * çalıştırır (bkz. SettingsFragment `exportRecoveryTo` AYNI gerekçe) —
     * ANA THREAD DIŞINDA çağrılır. Başarılıysa `createIdentityAndStart`'ın
     * kimlik-oluşturma-sonrası kuyruğuyla (persist + startNetworkService +
     * pil optimizasyonu istemi) AYNI kuyruğu izler.
     */
    private fun importRecoveryFrom(uri: Uri, passphrase: String) {
        Toast.makeText(this, R.string.msg_recovery_importing, Toast.LENGTH_SHORT).show()
        lifecycleScope.launch(Dispatchers.IO) {
            val bytes = try {
                contentResolver.openInputStream(uri)?.use { it.readBytes() }
            } catch (e: Exception) {
                null
            }
            if (bytes == null) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, R.string.error_attachment_open_failed, Toast.LENGTH_LONG).show()
                    showDeviceNameDialog()
                }
                return@launch
            }
            val identityId = try {
                P2PLib.importRecovery(bytes, passphrase, pendingImportDeviceName)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (identityId.startsWith("Error:")) {
                    Toast.makeText(this@MainActivity, identityId, Toast.LENGTH_LONG).show()
                    showDeviceNameDialog()
                } else {
                    IdentityManager.persistNewIdentity(applicationContext)
                    statusText.text = getString(R.string.lbl_id_short, identityId.take(8))
                    startNetworkService()
                    ensureBatteryOptimizationExemption()
                    Toast.makeText(this@MainActivity, R.string.msg_recovery_import_success, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun createIdentityAndStart(deviceName: String, linkAsSecondary: Boolean) {
        val identityId = P2PLib.createIdentity(deviceName)
        if (identityId.startsWith("Error:")) {
            Toast.makeText(this, identityId, Toast.LENGTH_LONG).show()
            return
        }
        // Secret key bundle'ını HEMEN Keystore ile şifreleyip diske yaz —
        // aksi halde süreç öldüğünde kaybolur. (İkincil cihaz da KENDİ
        // anahtarlarını böyle saklar; benimseme sadece identity_id'yi değiştirir.)
        IdentityManager.persistNewIdentity(applicationContext)
        statusText.text = getString(R.string.lbl_id_short, identityId.take(8))
        startNetworkService()
        ensureBatteryOptimizationExemption()
        if (linkAsSecondary) {
            startActivity(Intent(this, com.p2p.messenger.ui.LinkDeviceActivity::class.java))
        }
    }

    /**
     * Spec dışı, kullanıcı isteği: uygulamanın İLK açılışında (sadece
     * yeni bir identity oluşturulduğunda — mevcut kullanıcılar için tekrar
     * TEKRAR sorulmaz, `showDeviceNameDialog` zaten sadece bu akışta bir
     * kez çalışır) Android'in pil optimizasyonunu bu uygulama için devre
     * dışı bırakmasını ister. Bu uygulama sürekli çalışan bir foreground
     * service + arka plan mesaj teslim/yeniden deneme döngüsüne (bkz.
     * P2PService, lib.rs `awaiting_confirmation`) dayanıyor — OEM'lerin
     * agresif pil yönetimi (Doze, uygulama bazlı arka plan kısıtlamaları)
     * bu döngüyü geciktirip mesajların "takılı" görünmesine yol açabilir.
     * `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, kullanıcıya TEK
     * dokunuşluk bir sistem diyaloğu gösterir ("İzin ver"/"Reddet") —
     * genel Ayarlar listesine gömülü bir toggle aratmaktan çok daha az
     * sürtünmeli. Bazı OEM'lerde bu intent kısıtlı/desteklenmiyor olabilir
     * — o durumda genel pil optimizasyonu ayarlar ekranına düşülür,
     * o da yoksa sessizce vazgeçilir (bu bir gereklilik değil, bir öneri).
     */
    private fun ensureBatteryOptimizationExemption() {
        val powerManager = getSystemService(android.os.PowerManager::class.java) ?: return
        // "Background restricted" (MIUI battery saver "Restrict", Android's
        // "Restricted") is a different switch from the optimisation exemption
        // and worse: startForeground() is refused, so nothing arrives with
        // the screen off (seen on the Note 9S: "not allowed due to bg
        // restriction"). Only the app's settings page can lift it.
        val am = getSystemService(android.app.ActivityManager::class.java)
        val prefs0 = getSharedPreferences("p2p_settings", Context.MODE_PRIVATE)
        if (Build.VERSION.SDK_INT >= 28 && am?.isBackgroundRestricted == true &&
            System.currentTimeMillis() - prefs0.getLong("bg_restricted_prompt_ms", 0L) > 24L * 60 * 60 * 1000) {
            prefs0.edit().putLong("bg_restricted_prompt_ms", System.currentTimeMillis()).apply()
            AlertDialog.Builder(this)
                .setTitle(R.string.title_reliable_delivery)
                .setMessage(R.string.msg_background_restricted)
                .setPositiveButton(R.string.action_open_settings) { _, _ ->
                    try {
                        AppLock.beginTrustedExcursion()
                        startActivity(Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                            data = android.net.Uri.parse("package:$packageName")
                        })
                    } catch (e: Exception) { }
                }
                .setNegativeButton(R.string.action_not_now, null)
                .show()
            return
        }
        // Android 14+ grants full-screen intents only to dialer/alarm apps by
        // default; without it an incoming call on a locked phone is just a
        // notification (seen on the Note 8 Pro: "USE_FULL_SCREEN_INTENT ...
        // rejectTime"). Only the system settings page can grant it.
        val nm = getSystemService(android.app.NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 34 && nm?.canUseFullScreenIntent() == false &&
            System.currentTimeMillis() - prefs0.getLong("fsi_prompt_ms", 0L) > 24L * 60 * 60 * 1000) {
            prefs0.edit().putLong("fsi_prompt_ms", System.currentTimeMillis()).apply()
            AlertDialog.Builder(this)
                .setTitle(R.string.call_channel_name)
                .setMessage(R.string.msg_full_screen_intent)
                .setPositiveButton(R.string.action_open_settings) { _, _ ->
                    try {
                        AppLock.beginTrustedExcursion()
                        startActivity(Intent(android.provider.Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT).apply {
                            data = android.net.Uri.parse("package:$packageName")
                        })
                    } catch (e: Exception) { }
                }
                .setNegativeButton(R.string.action_not_now, null)
                .show()
            return
        }
        if (powerManager.isIgnoringBatteryOptimizations(packageName)) return
        // Her açılışta sormak dırdır olurdu: kullanıcı reddettiyse bir gün
        // boyunca bir daha sorma. (Muafiyet zaten varsa yukarıda çıkıldı.)
        val prefs = getSharedPreferences("p2p_settings", Context.MODE_PRIVATE)
        val lastAsked = prefs.getLong("battery_prompt_last_ms", 0L)
        val now = System.currentTimeMillis()
        if (now - lastAsked < 24L * 60 * 60 * 1000) return
        prefs.edit().putLong("battery_prompt_last_ms", now).apply()
        AlertDialog.Builder(this)
            .setTitle(R.string.title_reliable_delivery)
            .setMessage(R.string.msg_battery_optimization)
            .setPositiveButton(R.string.action_open_settings) { _, _ ->
                try {
                    AppLock.beginTrustedExcursion()
                    startActivity(
                        Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                            data = android.net.Uri.parse("package:$packageName")
                        }
                    )
                } catch (e: Exception) {
                    try {
                        startActivity(Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                    } catch (e2: Exception) {
                        // Cihaz/OEM bu ayarı desteklemiyor — sessizce vazgeç,
                        // mesajlaşmanın kendisi bundan bağımsız çalışır.
                    }
                }
            }
            .setNegativeButton(R.string.action_not_now, null)
            .show()
    }

    private fun startNetworkService() {
        val serviceIntent = Intent(this, P2PService::class.java)
        startForegroundService(serviceIntent)
        try {
            statusText.text = getString(R.string.lbl_id_code, P2PLib.getIdentityShortCode())
        } catch (e: Exception) {
            // identity henüz okunamadı, önemli değil — status metni ikinci
            // planda.
        }
    }

    override fun onResume() {
        super.onResume()
        // Spec dışı, kullanıcı isteği: uygulamaya girildiğinde bildirim
        // çubuğundaki TÜM mesaj bildirimleri temizlensin.
        com.p2p.messenger.util.NotificationHelper.clearAll(this)
        alertPollHandler.post(alertPollRunnable)
        // Spec dışı, kullanıcı isteği: uygulama ön plana her alındığında
        // gönderilemeyen mesajlar/emirler için bir yeniden deneme
        // tetiklensin. Servis zaten çalışıyorsa `startNetworkService`
        // zararsız bir no-op'tur (bkz. P2PService.onStartCommand
        // `isRunning` koruması); OS tarafından öldürülmüşse yeniden
        // başlatılması, kalıcı yeniden deneme kuyruğunun (bkz. lib.rs
        // `load_pending_durable_retries_from_db`) diskten geri
        // yüklenmesini de otomatik tetikler.
        if (P2PLib.hasStoredIdentity()) {
            startNetworkService()
        }
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
        if (array.length() == 0) {
            shownAlertFingerprint = null
            return
        }

        val alert = array.getJSONObject(0)
        val contactName = alert.optString("contact_display_name", getString(R.string.lbl_unknown))
        val newCode = alert.optString("new_device_short_code", "")
        val fingerprint = alert.optString("new_device_fingerprint", "")

        // bkz. `shownAlertFingerprint` dokümantasyonu — bu tam olarak AYNI
        // uyarı için zaten bir dialog açıksa, ikinci bir tane AÇMA.
        if (fingerprint.isNotEmpty() && fingerprint == shownAlertFingerprint) return
        shownAlertFingerprint = fingerprint

        AlertDialog.Builder(this)
            .setTitle(R.string.title_security_warning_dialog)
            .setMessage(getString(R.string.msg_new_device_warning, contactName, newCode))
            .setPositiveButton(R.string.action_verified_accept) { _, _ ->
                P2PLib.acceptDeviceAlert(fingerprint)
                shownAlertFingerprint = null
            }
            .setNegativeButton(R.string.action_reject) { _, _ ->
                P2PLib.rejectDeviceAlert(fingerprint)
                shownAlertFingerprint = null
            }
            // Kullanıcı kararı (2026-08-27): reddetmek yalnızca BU uyarıyı
            // kapatır — aynı cihaz tekrar paket yollarsa uyarı geri gelir.
            // Engelleme ise kalıcı: o kimliğin hiçbir cihazından bir daha
            // paket kabul edilmez ve yalnızca yüz yüze yeniden eşleşmeyle
            // geri açılır.
            .setNeutralButton(R.string.action_block) { _, _ ->
                P2PLib.rejectDeviceAlert(fingerprint)
                val identityId = alert.optString("identity_id", "")
                if (identityId.isNotEmpty()) {
                    val result = try { P2PLib.blockIdentity(identityId) } catch (e: Exception) { "Error: ${e.message}" }
                    if (result.startsWith("Error:")) {
                        Toast.makeText(this, result, Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(this, R.string.msg_identity_blocked, Toast.LENGTH_SHORT).show()
                    }
                }
                shownAlertFingerprint = null
            }
            .setCancelable(false)
            .show()
    }
}
