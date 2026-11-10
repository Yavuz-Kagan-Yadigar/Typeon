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
import androidx.lifecycle.withStarted
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

    private companion object {
        const val MAX_RECOVERY_FILE_BYTES = 64 * 1024 * 1024
    }

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
     *  güveni zedeler).
     *
     *  Bekleyen uyarılar bir KÜME ile takip edilir, TEK bir slotla değil:
     *  çekirdek listeyi bir HashMap'te tutuyor, sıra her yoklamada
     *  değişebiliyor — iki uyarı beklerken "ilk uyarı" A,B,A şeklinde
     *  değişiyor ve her turda yeni bir kapatılamaz dialog üstüste biniyordu.
     *  Artık: aynı uyarı için ikinci bir dialog AÇILMAZ ve aynı anda yalnızca
     *  TEK dialog açık olur; sıradaki uyarı ancak önceki kapanınca gösterilir. */
    private val shownAlertFingerprints = HashSet<String>()
    /** Aynı anda açık olan tek güvenlik dialog'u (üste binen ikinci bir
     *  dialog, altındakinin cevaplanmasını engelliyordu). */
    private var alertDialog: androidx.appcompat.app.AlertDialog? = null
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
    private val pickRecoveryFileLauncher = registerForActivityResult(com.p2p.messenger.util.OpenDocumentAtHome()) { uri ->
        uri?.let { showImportPassphraseDialog(it) }
    }

    /** [showDeviceNameDialog]'daki isim alanından, dosya seçici açılmadan
     *  ÖNCE okunur (kullanıcı SAF'ta gezinirken dialog'un View'ı zaten
     *  dismiss edilmiş olur). */
    private var pendingImportDeviceName: String = "Device"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // #48: the database / key work is slow: not on the main thread. A loading
        // screen meanwhile; the real layout (and its fragments) only after the core is up.
        setContentView(android.widget.FrameLayout(this).apply {
            addView(android.widget.ProgressBar(this@MainActivity), android.widget.FrameLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT, android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                android.view.Gravity.CENTER))
            contentDescription = getString(R.string.msg_loading)
        })
        lifecycleScope.launch {
            // 0 = no database, 1 = identity stored (+ secrets loaded?), 2 = first start
            val state = withContext(Dispatchers.IO) {
                if (!P2PLib.initDatabase(applicationContext.filesDir.absolutePath)) 0
                else if (P2PLib.hasStoredIdentity()) (if (IdentityManager.loadIfPresent(applicationContext)) 1 else 3)
                else 2
            }
            // The app lock may sit on top meanwhile: inflating the fragments
            // after onSaveInstanceState throws, so wait until we are started.
            lifecycle.withStarted { continueStartup(savedInstanceState, state) }
        }
    }

    /** Core is open. [state]: 0 no database, 1 identity loaded, 3 identity unreadable, 2 first start. */
    private fun continueStartup(savedInstanceState: Bundle?, state: Int) {
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

        if (state == 0) {
            // No database (its key could not be read): not a first start. A
            // new identity made here would overwrite the stored one.
            com.p2p.messenger.util.KeystoreCrypto.reportKeyFailure(this)
        } else if (state != 2) {
            if (state == 3) {
                // identity_secret.enc lost/corrupt — the Keystore key is
                // probably gone (e.g. device reset). The core's
                // import_recovery accepts exactly this state (public keys
                // loaded, no secret keys): offer the same recovery-file flow
                // the first-start dialog uses.
                AlertDialog.Builder(this)
                    .setMessage(R.string.msg_identity_read_failed)
                    .setPositiveButton(R.string.action_restore_from_recovery) { _, _ ->
                        AppLock.beginTrustedExcursion()
                        pickRecoveryFileLauncher.launch(arrayOf("*/*"))
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
            startNetworkService()
        } else {
            // İlk açılış: kullanıcıdan cihaz adı iste, identity'yi bir kez
            // oluştur (spec 1: her Device bir device_name taşır).
            showDeviceNameDialog()
        }

        handleJoinLink(intent)
        // Only on a real start: a rotation, a theme change or a restore after
        // process death replays the same intent and queued the share again.
        if (savedInstanceState == null) handleShare(intent)
        ready = true
        if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) resumeWork()
    }

    @Volatile private var ready = false

    override fun onDestroy() {
        if (isFinishing) com.p2p.messenger.util.ShareIntake.pending = null
        // The security dialog is a window of this activity: leaving it open
        // leaks it (and the answer buttons would act on a dead activity).
        alertDialog?.dismiss()
        alertDialog = null
        super.onDestroy()
    }

    override fun onStop() {
        // Left without picking a chat (Home, another screen): the share must
        // not ride along with the next chat opened. Not while the lock prompt
        // covers this screen, the share is still wanted after the password.
        if (!isChangingConfigurations && com.p2p.messenger.util.AppLock.isUnlocked()) {
            com.p2p.messenger.util.ShareIntake.pending = null
        }
        super.onStop()
    }

    /** Paylaşım ekranından gelen içerik: bekletilir, kullanıcı sohbet seçince
     *  gönderilir (bkz. util.ShareIntake). */
    private fun handleShare(intent: Intent?) {
        if (!com.p2p.messenger.util.ShareIntake.isShare(intent)) return
        // The share target is exported: a sender that grants no read access
        // to its URIs made `startActivity` (which passes the grant on to the
        // chat screen) throw SecurityException and kill the app.
        if (com.p2p.messenger.util.ShareIntake.uris(intent!!).any {
                checkCallingOrSelfUriPermission(it, Intent.FLAG_GRANT_READ_URI_PERMISSION) != android.content.pm.PackageManager.PERMISSION_GRANTED
            }) {
            android.widget.Toast.makeText(this, R.string.error_attachment_open_failed, android.widget.Toast.LENGTH_SHORT).show()
            return
        }
        com.p2p.messenger.util.ShareIntake.pending = intent
        android.widget.Toast.makeText(this, R.string.msg_share_pick_chat, android.widget.Toast.LENGTH_LONG).show()
    }

    /** `singleTop` — uygulama zaten açıkken tıklanan katılım bağlantısı
     *  yeni bir örnek yerine BURAYA düşer (bkz. AndroidManifest). */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!ready) return // continueStartup handles the current intent
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

        val code = data.toString().take(300)
        if (!P2PLib.hasStoredIdentity()) {
            // No account, no server. Not put on the clipboard: any web page
            // could overwrite what the user had copied.
            Toast.makeText(this, R.string.msg_join_link_needs_identity, Toast.LENGTH_LONG).show()
            return
        }

        // Whether THIS server would become the history server is a JNI/SQLite
        // read (off the main thread, see SettingsFragment `refreshServers`):
        // the history warning is appended only for the server that would be it.
        lifecycleScope.launch {
            val historyServer = withContext(Dispatchers.IO) { P2PLib.nextServerStoresHistory(code) }
            if (isFinishing || isDestroyed) return@launch
            AlertDialog.Builder(this@MainActivity)
                .setTitle(R.string.dlg_add_server_title)
                .setMessage(addServerQuestion(code, historyServer))
                .setPositiveButton(android.R.string.ok) { _, _ -> addServerFromLink(code) }
                .setNegativeButton(android.R.string.cancel, null)
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
                    Toast.makeText(this@MainActivity, com.p2p.messenger.util.coreErrorText(this@MainActivity, result), Toast.LENGTH_LONG).show()
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
                // The primary lists this device under that name: the model says more than "Device".
                createIdentityAndStart(input.text.toString().ifBlank { android.os.Build.MODEL ?: "Device" }, linkAsSecondary = true)
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
            // Bounded: the user may pick any file, and a huge one ended in
            // an OutOfMemoryError that no `catch (Exception)` stops.
            val bytes = try {
                contentResolver.openInputStream(uri)?.use { input ->
                    val out = java.io.ByteArrayOutputStream()
                    val buf = ByteArray(8192)
                    while (out.size() <= MAX_RECOVERY_FILE_BYTES) {
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                    }
                    if (out.size() > MAX_RECOVERY_FILE_BYTES) null else out.toByteArray()
                }
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
                // The chats in the file are stored under the history key; with
                // no identity yet the app had not loaded one.
                com.p2p.messenger.util.MessageHistoryManager.ensureHistoryKeyLoaded(applicationContext)
                P2PLib.importRecovery(bytes, passphrase, pendingImportDeviceName)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (identityId.startsWith("Error:")) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, com.p2p.messenger.util.coreErrorText(this@MainActivity, identityId), Toast.LENGTH_LONG).show()
                    showDeviceNameDialog()
                }
                return@launch
            }
            // Keystore + disk: this coroutine already runs on the IO
            // dispatcher. `false` = çekirdekte bekleyen bundle yoktu, yani
            // secret key'ler hiç yazılmadı.
            val persistError = try {
                if (IdentityManager.persistNewIdentity(applicationContext)) null else "no pending secret bundle"
            } catch (e: Exception) {
                e.message ?: e.toString()
            }
            if (persistError != null) {
                // Keystore or disk failure, as in `createIdentityAndStart`.
                android.util.Log.w("MainActivity", "Kimlik secret bundle'ı kaydedilemedi: $persistError")
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, R.string.error_identity_persist_failed, Toast.LENGTH_LONG).show()
                    com.p2p.messenger.util.LocalWipe.wipe(applicationContext)
                    com.p2p.messenger.util.AppRestarter.restart(applicationContext)
                }
                return@launch
            }
            withContext(Dispatchers.Main) {
                // The archive root key came back with the recovery file
                // but lived only in the core's memory: after a restart it
                // was gone and a new random one split the server archive.
                com.p2p.messenger.util.ArchiveKeyManager.persistIfNew(applicationContext)
                statusText.text = getString(R.string.lbl_id_short, identityId.take(8))
                startNetworkService()
                ensureBatteryOptimizationExemption()
                Toast.makeText(this@MainActivity, R.string.msg_recovery_import_success, Toast.LENGTH_LONG).show()
            }
        }
    }

    /**
     * Yeni kimlik oluşturur ve ağı başlatır. Anahtar üretimi ve
     * Keystore/diske yazma JNI + dosya I/O'su olduğu için ANA THREAD'de
     * yapılmaz (bkz. `importRecoveryFrom` AYNI desen).
     */
    private fun createIdentityAndStart(deviceName: String, linkAsSecondary: Boolean) {
        lifecycleScope.launch {
            // One block that a rotation cannot cancel: if the activity dies between
            // creating the identity and saving its secret keys, the keys are lost.
            var persistError: String? = null
            val identityId = withContext(kotlinx.coroutines.NonCancellable + Dispatchers.IO) {
                val id = try { P2PLib.createIdentity(deviceName) } catch (e: Exception) { "Error: ${e.message}" }
                if (!id.startsWith("Error:")) {
                    // Secret key bundle'ını HEMEN Keystore ile şifreleyip diske yaz —
                    // aksi halde süreç öldüğünde kaybolur. (İkincil cihaz da KENDİ
                    // anahtarlarını böyle saklar; benimseme sadece identity_id'yi değiştirir.)
                    persistError = try {
                        // `false` = çekirdekte bekleyen bundle yoktu: kimliğin
                        // secret key'leri hiç yazılmadı, bir sonraki açılışta
                        // yüklenemez.
                        if (IdentityManager.persistNewIdentity(applicationContext)) null else "no pending secret bundle"
                    } catch (e: Exception) {
                        e.message ?: e.toString()
                    }
                }
                id
            }
            if (identityId.startsWith("Error:")) {
                Toast.makeText(this@MainActivity, com.p2p.messenger.util.coreErrorText(this@MainActivity, identityId), Toast.LENGTH_LONG).show()
                showDeviceNameDialog()
                return@launch
            }
            if (persistError != null) {
                // Keystore or disk failure: without this the identity exists in
                // the database but its secret keys are lost at the next restart,
                // and the install is stuck at "identity read failed". The identity
                // is seconds old: remove it and start the setup again.
                android.util.Log.w("MainActivity", "Kimlik secret bundle'ı kaydedilemedi: $persistError")
                Toast.makeText(this@MainActivity, R.string.error_identity_persist_failed, Toast.LENGTH_LONG).show()
                com.p2p.messenger.util.LocalWipe.wipe(applicationContext)
                com.p2p.messenger.util.AppRestarter.restart(applicationContext)
                return@launch
            }
            statusText.text = getString(R.string.lbl_id_short, identityId.take(8))
            startNetworkService()
            ensureBatteryOptimizationExemption()
            if (linkAsSecondary) {
                startActivity(Intent(this@MainActivity, com.p2p.messenger.ui.LinkDeviceActivity::class.java))
            }
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
        try {
            startForegroundService(serviceIntent)
        } catch (e: Exception) {
            // API 31+: ForegroundServiceStartNotAllowedException when this runs
            // after the user left the app (e.g. during a recovery import).
            android.util.Log.w("MainActivity", "Service not started: ${e.message}")
        }
        // Off the main thread: the call waits for the core lock, which a
        // long poll turn holds (every onResume came through here).
        lifecycleScope.launch {
            val code = withContext(Dispatchers.IO) {
                try { P2PLib.getIdentityShortCode() } catch (e: Exception) { null }
            } ?: return@launch
            statusText.text = getString(R.string.lbl_id_code, code)
        }
    }

    override fun onResume() {
        super.onResume()
        if (ready) resumeWork()
    }

    private fun resumeWork() {
        // Spec dışı, kullanıcı isteği: uygulamaya girildiğinde bildirim
        // çubuğundaki TÜM mesaj bildirimleri temizlensin.
        // AMA kilit ekranı bu ekranın üstüne geldiğinde bildirim çubuğu
        // okunmamış mesajların TEK izi: kilitliyken temizlenirse kullanıcı
        // şifreyi girip geri çıktığında bildirim çubuğu bomboş kalıyordu.
        if (com.p2p.messenger.util.AppLock.isUnlocked()) {
            com.p2p.messenger.util.NotificationHelper.clearAll(this)
        }
        alertPollHandler.post(alertPollRunnable)
        // Spec dışı, kullanıcı isteği: uygulama ön plana her alındığında
        // gönderilemeyen mesajlar/emirler için bir yeniden deneme
        // tetiklensin. Servis zaten çalışıyorsa `startNetworkService`
        // zararsız bir no-op'tur (bkz. P2PService.onStartCommand
        // `isRunning` koruması); OS tarafından öldürülmüşse yeniden
        // başlatılması, kalıcı yeniden deneme kuyruğunun (bkz. persist.rs
        // `load_pending_durable_retries_from_db`) diskten geri
        // yüklenmesini de otomatik tetikler.
        lifecycleScope.launch {
            val hasIdentity = withContext(Dispatchers.IO) {
                try { P2PLib.hasStoredIdentity() } catch (e: Exception) { false }
            }
            if (hasIdentity) startNetworkService()
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
        // Every 5 s, and the JNI call takes the core lock: not on the main thread.
        lifecycleScope.launch {
            val json = withContext(Dispatchers.IO) {
                try { P2PLib.listPendingDeviceAlerts() } catch (e: Exception) { null }
            } ?: return@launch
            if (!isFinishing && !isDestroyed) showPendingDeviceAlert(json)
        }
    }

    private fun showPendingDeviceAlert(json: String) {
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            return
        }
        if (array.length() == 0) {
            shownAlertFingerprints.clear()
            return
        }
        // Aynı anda tek dialog: altındaki kapatılamaz dialog cevaplanmadan
        // üstüne ikinci biri açılırsa ekran kilitlenir.
        if (alertDialog?.isShowing == true) return
        // Sıra kararlı değil (çekirdek HashMap): henüz gösterilmemiş ilk
        // uyarıyı seç.
        for (i in 0 until array.length()) {
            val alert = array.optJSONObject(i) ?: continue
            val fingerprint = alert.optString("new_device_fingerprint", "")
            if (fingerprint.isEmpty() || shownAlertFingerprints.contains(fingerprint)) continue
            showDeviceAlertDialog(alert, fingerprint)
            return
        }
    }

    /** bkz. `shownAlertFingerprints` dokümantasyonu. */
    private fun showDeviceAlertDialog(alert: org.json.JSONObject, fingerprint: String) {
        val contactName = alert.optString("contact_display_name", getString(R.string.lbl_unknown))
        val newCode = alert.optString("new_device_short_code", "")
        shownAlertFingerprints.add(fingerprint)

        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.title_security_warning_dialog)
            .setMessage(getString(R.string.msg_new_device_warning, contactName, newCode))
            .setPositiveButton(R.string.action_verified_accept) { _, _ ->
                answerDeviceAlert(fingerprint, accept = true)
                shownAlertFingerprints.remove(fingerprint)
            }
            .setNegativeButton(R.string.action_reject) { _, _ ->
                answerDeviceAlert(fingerprint, accept = false)
                shownAlertFingerprints.remove(fingerprint)
            }
            // Kullanıcı kararı (2026-08-27): reddetmek yalnızca BU uyarıyı
            // kapatır — aynı cihaz tekrar paket yollarsa uyarı geri gelir.
            // Engelleme ise kalıcı: o kimliğin hiçbir cihazından bir daha
            // paket kabul edilmez ve yalnızca yüz yüze yeniden eşleşmeyle
            // geri açılır.
            .setNeutralButton(R.string.action_block) { _, _ ->
                answerDeviceAlert(fingerprint, accept = false)
                val identityId = alert.optString("identity_id", "")
                if (identityId.isNotEmpty()) blockIdentityInBackground(identityId)
                shownAlertFingerprints.remove(fingerprint)
            }
            .setCancelable(false)
            .create()
        dialog.setOnDismissListener { if (alertDialog === dialog) alertDialog = null }
        alertDialog = dialog
        dialog.show()
    }

    /** The core calls take the global lock: not on the main thread. */
    private fun answerDeviceAlert(fingerprint: String, accept: Boolean) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                if (accept) P2PLib.acceptDeviceAlert(fingerprint) else P2PLib.rejectDeviceAlert(fingerprint)
            } catch (e: Exception) {
                android.util.Log.w("MainActivity", "Cihaz uyarısı yanıtlanamadı: ${e.message}")
            }
        }
    }

    /** bkz. `answerDeviceAlert` — aynı nedenle arka planda. */
    private fun blockIdentityInBackground(identityId: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try { P2PLib.blockIdentity(identityId) } catch (e: Exception) { "Error: ${e.message}" }
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@MainActivity, com.p2p.messenger.util.coreErrorText(this@MainActivity, result), Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(this@MainActivity, R.string.msg_identity_blocked, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
}
