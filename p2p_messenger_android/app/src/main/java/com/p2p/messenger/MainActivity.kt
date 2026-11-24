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
    /** `checkPendingDeviceAlerts` runs every 5 seconds. A security alert that the user does not
     *  answer right away (for example, the user walks away from the phone) is shown once. The same
     *  pending alert is returned on every poll, so the dialog is not opened again each time: one
     *  non-cancelable dialog would otherwise pile up per poll. A hostile sender could also trigger
     *  new-device events in a loop to spam this screen, so the dedupe is part of the security check.
     *
     *  Pending alerts are tracked as a SET, not as a single slot. The core keeps the list in a HashMap,
     *  so the order can change between polls. The same alert never opens a second dialog, and only one
     *  dialog is open at a time. The next alert is shown after the current one is closed. */
    private val shownAlertFingerprints = HashSet<String>()
    /** The single security dialog that is open at a time. A second dialog on top would block the
     *  answer to the one below it. */
    private var alertDialog: androidx.appcompat.app.AlertDialog? = null
    private val alertPollRunnable = object : Runnable {
        override fun run() {
            checkPendingDeviceAlerts()
            alertPollHandler.postDelayed(this, 5000)
        }
    }

    /** Android 13+ (API 33) needs the runtime permission to post notifications. Without it, the
     *  foreground service notification of P2PService and the incoming-message notifications
     *  (see NotificationHelper) are suppressed by the system. This is a plain platform permission,
     *  not Google Play Services or FCM. */
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

    /** Like the note in SettingsFragment `pickAvatarLauncher`: `registerForActivityResult` must be
     *  registered before the activity is STARTED, so it is a property initializer.
     *  See `showImportPassphraseDialog` / `importRecoveryFrom`. This is the import side of the
     *  recovery-file export in SettingsFragment: without it, an exported file had nowhere to be restored. */
    private val pickRecoveryFileLauncher = registerForActivityResult(com.p2p.messenger.util.OpenDocumentAtHome()) { uri ->
        uri?.let { showImportPassphraseDialog(it) }
    }

    /** The name field of [showDeviceNameDialog] is read BEFORE the file picker opens, because the
     *  dialog's view is dismissed while the user browses in SAF. */
    private var pendingImportDeviceName: String = "Device"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The database and key work is slow, so it does not run on the main thread. A loading screen
        // is shown meanwhile. The real layout and its fragments are created only after the core is up.
        setContentView(android.widget.FrameLayout(this).apply {
            addView(android.widget.ProgressBar(this@MainActivity), android.widget.FrameLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT, android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                android.view.Gravity.CENTER))
            contentDescription = getString(R.string.msg_loading)
        })
        lifecycleScope.launch {
            // 0 = no database, 1 = identity stored (secrets loaded), 2 = first start, 3 = identity stored but its secrets could not be loaded
            val state = withContext(Dispatchers.IO) {
                if (!P2PLib.initDatabase(applicationContext.filesDir.absolutePath)) 0
                else if (P2PLib.hasStoredIdentity()) (if (IdentityManager.loadIfPresent(applicationContext)) 1 else 3)
                else 2
            }
            // The app lock may cover the screen meanwhile. Inflating fragments after
            // onSaveInstanceState throws, so wait until the activity is started.
            lifecycle.withStarted { continueStartup(savedInstanceState, state) }
        }
    }

    /** The core is open. [state]: 0 no database, 1 identity loaded, 3 identity unreadable, 2 first start. */
    private fun continueStartup(savedInstanceState: Bundle?, state: Int) {
        setContentView(R.layout.activity_main)

        ensureNotificationPermission()
        // Battery-optimisation exemption. Without it, Android stops the foreground service as "app idle"
        // (seen in logcat: "Stopping service due to app idle"). A large download then stops silently in
        // the middle, and `pollNetwork` no longer runs. The exemption is the direct fix for that restriction.
        ensureBatteryOptimizationExemption()

        statusText = findViewById(R.id.statusText)
        val navView: BottomNavigationView = findViewById(R.id.nav_view)
        // The NavController is read from the NavHostFragment in FragmentManager, not with
        // `Activity.findNavController(viewId)`. The latter depends on NavHostFragment moving its
        // NavController tag to the container view (checked in `onViewCreated`). On some devices that
        // step is skipped and the call fails with "does not have a NavController set".
        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        val navController = navHostFragment.navController
        navView.setupWithNavController(navController)

        if (state == 0) {
            // No database (its key could not be read): this is not a first start. A new identity
            // created here would overwrite the stored one.
            com.p2p.messenger.util.KeystoreCrypto.reportKeyFailure(this)
        } else if (state != 2) {
            if (state == 3) {
                // identity_secret.enc is lost or corrupt, probably because the Keystore key is gone
                // (for example after a device reset). The core's import_recovery accepts exactly this
                // state (public keys loaded, no secret keys), so the same recovery-file flow as the
                // first-start dialog is offered.
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
            // First start: ask for the device name and create the identity once. Each device carries
            // a device_name.
            showDeviceNameDialog()
        }

        handleJoinLink(intent)
        // Only on a real start. A rotation, a theme change or a restore after process death replays the
        // same intent and would queue the share again.
        if (savedInstanceState == null) handleShare(intent)
        ready = true
        if (lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) resumeWork()
    }

    @Volatile private var ready = false

    override fun onDestroy() {
        if (isFinishing) com.p2p.messenger.util.ShareIntake.pending = null
        // The security dialog is a window of this activity. Leaving it open leaks the window, and the
        // answer buttons would act on a dead activity.
        alertDialog?.dismiss()
        alertDialog = null
        super.onDestroy()
    }

    override fun onStop() {
        // If the user leaves without picking a chat (Home, another screen), the pending share is dropped.
        // It must not ride along with the next chat opened. It is kept while the lock prompt covers this
        // screen, because the share is still wanted after the password.
        if (!isChangingConfigurations && com.p2p.messenger.util.AppLock.isUnlocked()) {
            com.p2p.messenger.util.ShareIntake.pending = null
        }
        super.onStop()
    }

    /** Content from the share sheet. It is held until the user picks a chat, then sent
     *  (see util.ShareIntake). */
    private fun handleShare(intent: Intent?) {
        if (!com.p2p.messenger.util.ShareIntake.isShare(intent)) return
        // The share target is exported. A sender that grants no read access to its URIs makes
        // `startActivity` throw SecurityException (the grant is passed on to the chat screen), which
        // would kill the app. Such a share is refused.
        if (com.p2p.messenger.util.ShareIntake.uris(intent!!).any {
                checkCallingOrSelfUriPermission(it, Intent.FLAG_GRANT_READ_URI_PERMISSION) != android.content.pm.PackageManager.PERMISSION_GRANTED
            }) {
            android.widget.Toast.makeText(this, R.string.error_attachment_open_failed, android.widget.Toast.LENGTH_SHORT).show()
            return
        }
        com.p2p.messenger.util.ShareIntake.pending = intent
        android.widget.Toast.makeText(this, R.string.msg_share_pick_chat, android.widget.Toast.LENGTH_LONG).show()
    }

    /** `singleTop`: a join link tapped while the app is already open lands HERE, not in a new
     *  instance (see AndroidManifest). */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!ready) return // continueStartup handles the current intent
        handleJoinLink(intent)
        handleShare(intent)
    }

    /**
     * Joining a server with one QR, link or text. The operator publishes a `typeon-server:...#...`
     * code once. Tapping it as a link opens the app directly. QR scanning and manual paste already
     * exist in Settings. This is the third route, and it needs no conversation with the operator.
     *
     * The confirmation dialog is NOT skipped. Tapping a link must not turn adding a server into a
     * decision the user did not see. Otherwise a hostile page could add a server in the background.
     */
    private fun handleJoinLink(intent: Intent?) {
        val data = intent?.data ?: return
        if (intent.action != Intent.ACTION_VIEW) return
        if (!data.scheme.equals("typeon-server", ignoreCase = true)) return
        // The same link must not be handled twice (onCreate plus a configuration change). It is removed
        // from the intent as soon as it is consumed.
        intent.data = null

        val code = data.toString().take(300)

        // Whether THIS server would become the history server is a JNI and SQLite read. It runs off the
        // main thread (see SettingsFragment `refreshServers`). The history warning is added only for the
        // server that would become the history server.
        lifecycleScope.launch {
            // null = no account. Both calls take the core mutex: off the main thread.
            val historyServer = withContext(Dispatchers.IO) {
                if (P2PLib.hasStoredIdentity()) P2PLib.nextServerStoresHistory(code) else null
            }
            if (isFinishing || isDestroyed) return@launch
            if (historyServer == null) {
                // No account, no server. The link is not copied to the clipboard: any web page could
                // overwrite what the user copied.
                Toast.makeText(this@MainActivity, R.string.msg_join_link_needs_identity, Toast.LENGTH_LONG).show()
                return@launch
            }
            AlertDialog.Builder(this@MainActivity)
                .setTitle(R.string.dlg_add_server_title)
                .setMessage(addServerQuestion(code, historyServer))
                .setPositiveButton(android.R.string.ok) { _, _ -> addServerFromLink(code) }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    /** The add-server question. The history warning, and what joining it uploads, is shown only when
     *  this server would become the history server. */
    private fun addServerQuestion(code: String, historyServer: Boolean): String =
        getString(R.string.msg_join_link_confirm, code) +
            if (historyServer) {
                "\n\n" + getString(R.string.lbl_server_history_warn) + " " + getString(R.string.msg_server_history_upload)
            } else ""

    private fun addServerFromLink(code: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            // `addServer` writes to disk and starts the dial, so it does not run on the main thread.
            // (The same call in SettingsFragment is synchronous, because the user is already waiting
            // in a dialog there.)
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
            // Multi-device: this is a SECONDARY device of an existing account. It still generates its own
            // key pair and a provisional identity (the primary's secret key is never copied). It shows a
            // link QR. When the primary scans that QR, this device joins the account.
            .setNeutralButton(R.string.link_device_as_secondary) { _, _ ->
                // The primary lists this device under that name, so the label says more than "Device".
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
     * See the `pickRecoveryFileLauncher` docs. After the file is picked, the passphrase is asked for
     * (same pattern as SettingsFragment `showExportRecoveryDialog`). The file alone is useless without
     * the passphrase: it is hardened with Argon2id (see Rust `import_recovery`).
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
     * `P2PLib.importRecovery` runs a deliberately slow Argon2id KDF (same reason as SettingsFragment
     * `exportRecoveryTo`). It is called OFF the main thread. On success it follows the same queue as
     * `createIdentityAndStart` after identity creation: persist, start the network service, and ask for
     * the battery-optimisation exemption.
     */
    private fun importRecoveryFrom(uri: Uri, passphrase: String) {
        Toast.makeText(this, R.string.msg_recovery_importing, Toast.LENGTH_SHORT).show()
        lifecycleScope.launch(Dispatchers.IO) {
            // Bounded read: the user may pick any file, and a very large one ends in an
            // OutOfMemoryError that `catch (Exception)` does not stop.
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
                // The chats in the file are stored under the history key. With no identity yet, the app has
                // not loaded one, so the chats cannot be read yet.
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
            // Keystore and disk writes. This coroutine already runs on the IO dispatcher. `false` means the
            // core had no pending secret bundle, so no secret keys were written.
            val persistError = try {
                if (IdentityManager.persistNewIdentity(applicationContext)) null else "no pending secret bundle"
            } catch (e: Exception) {
                e.message ?: e.toString()
            }
            if (persistError != null) {
                // Keystore or disk failure, handled as in `createIdentityAndStart`.
                com.p2p.messenger.util.Log.w("MainActivity", "Identity secret bundle could not be saved: $persistError")
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, R.string.error_identity_persist_failed, Toast.LENGTH_LONG).show()
                    com.p2p.messenger.util.LocalWipe.wipe(applicationContext)
                    com.p2p.messenger.util.AppRestarter.restart(applicationContext)
                }
                return@launch
            }
            withContext(Dispatchers.Main) {
                // The archive root key comes back with the recovery file, but it lived only in the core's
                // memory. After a restart it was lost, and a new random key would split the server archive.
                com.p2p.messenger.util.ArchiveKeyManager.persistIfNew(applicationContext)
                statusText.text = getString(R.string.lbl_id_short, identityId.take(8))
                startNetworkService()
                ensureBatteryOptimizationExemption()
                Toast.makeText(this@MainActivity, R.string.msg_recovery_import_success, Toast.LENGTH_LONG).show()
            }
        }
    }

    /**
     * Creates a new identity and starts the network. Key generation and the Keystore/disk writes are
     * JNI and file I/O, so they do NOT run on the main thread (same pattern as `importRecoveryFrom`).
     */
    private fun createIdentityAndStart(deviceName: String, linkAsSecondary: Boolean) {
        lifecycleScope.launch {
            // One block that a rotation cannot cancel. If the activity dies between creating the identity
            // and saving its secret keys, the keys are lost.
            var persistError: String? = null
            val identityId = withContext(kotlinx.coroutines.NonCancellable + Dispatchers.IO) {
                val id = try { P2PLib.createIdentity(deviceName) } catch (e: Exception) { "Error: ${e.message}" }
                if (!id.startsWith("Error:")) {
                    // Encrypt the secret key bundle with the Keystore and write it to disk at once. Otherwise
                    // it is lost when the process dies. A secondary device keeps its keys the same way; adopting
                    // a identity only changes the identity_id.
                    persistError = try {
                        // `false` means the core had no pending bundle: the secret keys of the identity were
                        // never written, so the identity cannot be loaded at the next start.
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
                // Keystore or disk failure. Without this step the identity exists in the database, but its
                // secret keys are lost at the next restart, and the install gets stuck at "identity read
                // failed". The identity is only seconds old, so it is removed and the setup starts again.
                com.p2p.messenger.util.Log.w("MainActivity", "Identity secret bundle could not be saved: $persistError")
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
     * Asks the user to disable Android's battery optimisation for this app. It runs on every start and
     * right after a NEW identity is created, but after each prompt the question is not asked again for
     * one day (see the `battery_prompt_last_ms` check below).
     *
     * The app depends on a long-running foreground service and a background delivery and retry loop
     * (see P2PService and `awaiting_confirmation` in the Rust core). Aggressive OEM battery management (Doze,
     * per-app background restrictions) can delay that loop, and messages then look stuck.
     * `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` shows a single system dialog with one tap
     * ("Allow" / "Deny"). That is less friction than searching for a toggle in the settings list.
     * Some OEMs restrict or do not support this intent. Then the general battery-optimisation settings
     * screen is used, and if that is missing too, the request is dropped silently. It is a suggestion,
     * not a requirement.
     */
    private fun ensureBatteryOptimizationExemption() {
        val powerManager = getSystemService(android.os.PowerManager::class.java) ?: return
        // "Background restricted" (for example MIUI's battery saver "Restrict", or Android's "Restricted")
        // is a different switch from the optimisation exemption, and it is stricter. startForeground() is
        // refused, so nothing arrives with the screen off (logcat on Note 9S: "not allowed due to bg
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
        // On Android 14+ full-screen intents are granted by default only to dialer and alarm apps. Without
        // the grant, an incoming call on a locked phone is only a notification (logcat on Note 8 Pro:
        // "USE_FULL_SCREEN_INTENT ... rejectTime"). Only the system settings page can grant it.
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
        // Asking on every start would be annoying, so after a prompt the question is not asked again for
        // one day. (If the exemption is already granted, it was left above.)
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
                    // The device or OEM does not support this setting. Give up silently: messaging works
                    // without it.
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
            // API 31+: ForegroundServiceStartNotAllowedException when this runs after the user has left the
            // app (for example during a recovery import).
            com.p2p.messenger.util.Log.w("MainActivity", "Service not started: ${e.message}")
        }
        // Off the main thread: the call waits for the core lock, which a long poll turn holds. Every
        // onResume comes through here.
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
        // When the app comes to the foreground, all message notifications in the status bar are cleared.
        // BUT while the lock screen covers this screen, the status bar is the only trace of unread messages.
        // If it were cleared while locked, the status bar would be empty after the user entered the
        // password and came back.
        if (com.p2p.messenger.util.AppLock.isUnlocked()) {
            com.p2p.messenger.util.NotificationHelper.clearAll(this)
        }
        alertPollHandler.post(alertPollRunnable)
        // Each time the app comes to the foreground, a retry is triggered for messages and commands that
        // could not be sent. If the service is already running, `startNetworkService` is a harmless no-op
        // (see the `isRunning` guard in P2PService.onStartCommand). If the OS killed it, starting it again
        // also reloads the durable retry queue from disk (see persist.rs `load_pending_durable_retries_from_db`).
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
     * Checks for pending device-change alerts (section 2.2). If there are any, shows a dialog that asks the
     * user to accept or reject them.
     */
    private fun checkPendingDeviceAlerts() {
        // Every 5 seconds. The JNI call takes the core lock, so it does not run on the main thread.
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
        // Only one dialog at a time. If a second non-cancelable dialog opened on top before the one below
        // was answered, the screen would lock up.
        if (alertDialog?.isShowing == true) return
        // The order is not stable (the core uses a HashMap). Pick the first alert that is not shown yet.
        for (i in 0 until array.length()) {
            val alert = array.optJSONObject(i) ?: continue
            val fingerprint = alert.optString("new_device_fingerprint", "")
            if (fingerprint.isEmpty() || shownAlertFingerprints.contains(fingerprint)) continue
            showDeviceAlertDialog(alert, fingerprint)
            return
        }
    }

    /** See the `shownAlertFingerprints` docs. */
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
            // Rejecting closes only THIS alert. If the same device sends packets again, the
            // alert comes back. Blocking is persistent: no packet from any device of that identity is accepted
            // again, until the user unblocks it in Contacts or re-pairs in person.
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

    /** The core calls take the global lock, so they do not run on the main thread. */
    private fun answerDeviceAlert(fingerprint: String, accept: Boolean) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                if (accept) P2PLib.acceptDeviceAlert(fingerprint) else P2PLib.rejectDeviceAlert(fingerprint)
            } catch (e: Exception) {
                com.p2p.messenger.util.Log.w("MainActivity", "Device alert could not be answered: ${e.message}")
            }
        }
    }

    /** See `answerDeviceAlert`: same reason, off the main thread. */
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
