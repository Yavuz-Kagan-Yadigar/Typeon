package com.p2p.messenger

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.core.view.MenuProvider
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import com.google.android.material.color.MaterialColors
import com.google.android.material.switchmaterial.SwitchMaterial
import com.p2p.messenger.ui.QrScanActivity
import com.p2p.messenger.util.ArchiveKeyManager
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.ui.PendingMessagesActivity
import com.p2p.messenger.ui.StorageActivity
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.AppRestarter
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.MAX_FOREIGN_URI_BYTES
import com.p2p.messenger.util.NotificationPrefs
import com.p2p.messenger.util.ThemePrefs
import com.p2p.messenger.util.copyToCapped
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

class SettingsFragment : Fragment() {

    companion object {
        /** Which settings cards are open. Process-wide so an appearance change
         *  (which recreates the activity) does not fold the card the user was in. */
        private val expandedSections = mutableSetOf("profile")
        /** Same note as ChatActivity PREVIEW_MAX_DIMENSION. The profile photo standard is 720p at 85% JPEG: larger than chat attachment previews (480p),
         *  because a profile photo can be shown full screen or larger. */
        private const val AVATAR_MAX_DIMENSION = 720
        /** See `performDeleteAccount`. */
        private const val ACCOUNT_DELETE_WAIT_MS = 15_000L
        /** See `onFontPicked`: large CJK fonts are around 20 MB. */
        private const val MAX_FONT_BYTES = 32L * 1024 * 1024
        private const val AVATAR_JPEG_QUALITY = 85

        /** See `onChatWallpaperPicked`: larger than an avatar (it is shown full screen as the background), but still a reasonable upper limit. */
        private const val WALLPAPER_MAX_DIMENSION = 1080
        private const val WALLPAPER_JPEG_QUALITY = 80

        /** Slider for the history and attachment storage limit, from 100 MB to 32 GB, in discrete steps (Slider valueFrom=0..8). */
        private val HISTORY_STORAGE_LIMIT_STEPS_BYTES = longArrayOf(
            100L * 1024 * 1024,
            250L * 1024 * 1024,
            500L * 1024 * 1024,
            1L * 1024 * 1024 * 1024,
            2L * 1024 * 1024 * 1024,
            4L * 1024 * 1024 * 1024,
            8L * 1024 * 1024 * 1024,
            16L * 1024 * 1024 * 1024,
            32L * 1024 * 1024 * 1024
        )

        private fun formatStorageLimit(bytes: Long): String = when {
            bytes >= 1024L * 1024 * 1024 -> {
                val gb = bytes.toDouble() / (1024 * 1024 * 1024)
                if (gb == gb.toLong().toDouble()) "${gb.toLong()} GB" else "%.2f GB".format(gb)
            }
            else -> "${bytes / (1024 * 1024)} MB"
        }

        private fun closestStepIndex(bytes: Long): Int {
            var bestIndex = 0
            var bestDiff = Long.MAX_VALUE
            for (i in HISTORY_STORAGE_LIMIT_STEPS_BYTES.indices) {
                val diff = kotlin.math.abs(HISTORY_STORAGE_LIMIT_STEPS_BYTES[i] - bytes)
                if (diff < bestDiff) {
                    bestDiff = diff
                    bestIndex = i
                }
            }
            return bestIndex
        }

        /**
         * The text and interface size sliders used to use a bare decimal `stepSize` (0.05f). 0.05 cannot be represented exactly in binary floating point.
         * The Material Slider's own `validateValues()` check (run on every `onSizeChanged`) requires a value read back from SharedPreferences to be exactly
         * 'valueFrom plus a multiple of stepSize'. A tiny floating-point error there threw `IllegalStateException` and crashed the app.
         * Fix, using the same pattern as `history_storage_limit_slider`: the slider works ONLY on whole-number indices (`valueFrom=0, stepSize=1`, so no
         * floating-point precision is involved), and the real scale value is looked up from these constant arrays.
         */
        private val TEXT_SCALE_STEPS = floatArrayOf(
            0.70f, 0.75f, 0.80f, 0.85f, 0.90f, 0.95f, 1.00f, 1.05f, 1.10f, 1.15f,
            1.20f, 1.25f, 1.30f, 1.35f, 1.40f, 1.45f, 1.50f, 1.55f, 1.60f
        )
        private val UI_SCALE_STEPS = floatArrayOf(
            0.75f, 0.80f, 0.85f, 0.90f, 0.95f, 1.00f, 1.05f, 1.10f, 1.15f, 1.20f, 1.25f, 1.30f
        )

        private fun closestStepIndex(steps: FloatArray, value: Float): Int {
            var bestIndex = 0
            var bestDiff = Float.MAX_VALUE
            for (i in steps.indices) {
                val diff = kotlin.math.abs(steps[i] - value)
                if (diff < bestDiff) {
                    bestDiff = diff
                    bestIndex = i
                }
            }
            return bestIndex
        }
    }

    private lateinit var imgOwnAvatar: ImageView
    /** Raw profile photo bytes, passed to the full-screen viewer by the click listener of `imgOwnAvatar` (see AvatarUtil.openFullscreen). */
    private var ownAvatarBytes: ByteArray? = null
    private var displayNameValue: TextView? = null

    /** Status label and periodic poll. The poll starts in `onResume` and stops in `onPause`. A JNI poll every 2 s from view creation would keep running
     *  while the app is in the background, wasting battery and core-lock time. */
    private var torStatusView: TextView? = null
    private var updateStatusView: TextView? = null
    private val torStatusHandler = Handler(Looper.getMainLooper())
    private val torStatusRunnable = object : Runnable {
        override fun run() {
            updateTorStatusLabel()
            updateStatusView?.text = context?.let { com.p2p.messenger.service.SelfUpdate.statusText(it) }
            // The Tor status (bootstrap) can change within seconds, so refresh every 2 s.
            torStatusHandler.postDelayed(this, 2000)
        }
    }

    /** `registerForActivityResult` must be called BEFORE the Fragment is STARTED. See the same note in ChatActivity's pickFileLauncher. */
    private val pickAvatarLauncher = registerForActivityResult(com.p2p.messenger.util.OpenDocumentAtHome()) { uri ->
        uri?.let { onAvatarPicked(it) }
    }

    /** See `onChatWallpaperPicked`: the same pattern as `pickAvatarLauncher`. */
    private val pickWallpaperLauncher = registerForActivityResult(com.p2p.messenger.util.OpenDocumentAtHome()) { uri ->
        uri?.let { onChatWallpaperPicked(it) }
    }

    /** Font picker: chooses a `.ttf` or `.otf` font file. The same `OpenDocument` pattern as `pickWallpaperLauncher`. */
    private val pickFontLauncher = registerForActivityResult(com.p2p.messenger.util.OpenDocumentAtHome()) { uri ->
        uri?.let { onFontPicked(it) }
    }

    /**
     * The Rust side (`export_recovery`, hardened with Argon2id, see SECURITY.md §6) is triggered from this screen.
     * The passphrase is held here temporarily, just before it is written to the target the user picks with SAF (Storage Access Framework,
     * `CreateDocument`), in `showExportRecoveryDialog`. This file carries ALL long-term identity keys, so the target must be a location the user
     * chooses. SAF is the only way that works the same on every API level without WRITE_EXTERNAL_STORAGE.
     */
    private var pendingRecoveryPassphrase: String? = null

    private val createRecoveryFileLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val passphrase = pendingRecoveryPassphrase
        pendingRecoveryPassphrase = null
        if (uri == null) return@registerForActivityResult
        if (passphrase == null) {
            // The fragment was recreated while the picker was open (rotation,
            // process death) and the passphrase is gone. The picker already
            // created the file: remove it, or an empty file stays behind as
            // the user's "recovery file".
            try {
                android.provider.DocumentsContract.deleteDocument(requireContext().contentResolver, uri)
            } catch (e: Exception) {
            }
            Toast.makeText(requireContext(), R.string.error_recovery_export_failed, Toast.LENGTH_LONG).show()
            return@registerForActivityResult
        }
        exportRecoveryTo(uri, passphrase)
    }

    /** Set while a server switch is put back after a failed change. */
    private var revertingServerToggle = false

    /** Runs a core server setting; on failure shows it and puts the switch
     *  back, so it never shows ON while nothing is stored or routed. */
    private fun applyServerToggle(switch: android.widget.CompoundButton, checked: Boolean, change: () -> String) {
        if (revertingServerToggle) return
        // the core call (key creation, DB) must not run on the main thread.
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try { change() } catch (e: Exception) { "Error: ${e.message}" }
            if (!result.startsWith("Error")) return@launch
            withContext(Dispatchers.Main) {
                Toast.makeText(switch.context, com.p2p.messenger.util.coreErrorText(switch.context, result), Toast.LENGTH_LONG).show()
                revertingServerToggle = true
                switch.isChecked = !checked
                revertingServerToggle = false
            }
        }
    }

    /** Each card's header folds/unfolds its body; the chevron shows the state. */
    private fun setupSections(root: View) {
        val sections = mapOf(
            "profile" to (R.id.section_profile_header to R.id.section_profile_body),
            "appearance" to (R.id.section_appearance_header to R.id.section_appearance_body),
            "privacy" to (R.id.section_privacy_header to R.id.section_privacy_body),
            "network" to (R.id.section_network_header to R.id.section_network_body),
            "servers" to (R.id.section_servers_header to R.id.section_servers_body),
            "devices" to (R.id.section_devices_header to R.id.section_devices_body),
            "account" to (R.id.section_account_header to R.id.section_account_body),
        )
        for ((key, ids) in sections) {
            val header = root.findViewById<TextView>(ids.first)
            val body = root.findViewById<View>(ids.second)
            // Chevron points down when folded, up when open (level 0 / 10000).
            val chevron = android.graphics.drawable.RotateDrawable().apply {
                drawable = header.compoundDrawablesRelative[2]
                fromDegrees = 0f; toDegrees = 180f
            }
            header.setCompoundDrawablesRelativeWithIntrinsicBounds(null, null, chevron, null)
            fun render() {
                val open = key in expandedSections
                body.visibility = if (open) View.VISIBLE else View.GONE
                chevron.level = if (open) 10000 else 0
            }
            render()
            header.setOnClickListener {
                if (!expandedSections.remove(key)) expandedSections.add(key)
                render()
            }
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_settings, container, false)

        imgOwnAvatar = view.findViewById(R.id.img_own_avatar)
        refreshOwnAvatar()
        // Tapping the profile photo opens it full screen with pinch-to-zoom (see AvatarUtil.openFullscreen).
        imgOwnAvatar.setOnClickListener { AvatarUtil.openFullscreen(requireContext(), ownAvatarBytes) }
        view.findViewById<Button>(R.id.btn_change_picture).setOnClickListener {
            AppLock.beginTrustedExcursion()
            pickAvatarLauncher.launch(arrayOf("image/*"))
        }
        view.findViewById<Button>(R.id.btn_remove_picture).setOnClickListener {
            setOwnAvatar(null)
        }

        // Account name: see `showChangeDisplayNameDialog`.
        displayNameValue = view.findViewById(R.id.display_name_value)
        refreshDisplayName()
        view.findViewById<Button>(R.id.btn_change_display_name).setOnClickListener {
            showChangeDisplayNameDialog()
        }

        val identityCodeValue = view.findViewById<android.widget.TextView>(R.id.identity_code_value)
        // The JNI call (`getIdentityCode` → core lock) does NOT run on the main thread; the result is written on the main thread.
        identityCodeValue.text = ""
        lifecycleScope.launch(Dispatchers.IO) {
            val code = try { P2PLib.getIdentityCode() } catch (e: Exception) { "" }
            withContext(Dispatchers.Main) {
                if (identityCodeValue.isAttachedToWindow) identityCodeValue.text = code
            }
        }

        val nodeModeSwitch = view.findViewById<SwitchMaterial>(R.id.node_mode_switch)
        nodeModeSwitch.isChecked = P2PService.isNodeModeEnabled(requireContext())

        val historyStorageLimitLabel = view.findViewById<TextView>(R.id.history_storage_limit_label)
        val historyStorageLimitDesc = view.findViewById<TextView>(R.id.history_storage_limit_desc)
        val historyStorageLimitValue = view.findViewById<TextView>(R.id.history_storage_limit_value)
        val historyStorageLimitSlider = view.findViewById<android.widget.SeekBar>(R.id.history_storage_limit_slider)

        fun setHistoryStorageLimitVisible(visible: Boolean) {
            val v = if (visible) View.VISIBLE else View.GONE
            historyStorageLimitLabel.visibility = v
            historyStorageLimitDesc.visibility = v
            historyStorageLimitValue.visibility = v
            historyStorageLimitSlider.visibility = v
        }

        val currentLimitBytes = P2PService.getHistoryStorageLimitBytes(requireContext())
        historyStorageLimitSlider.max = HISTORY_STORAGE_LIMIT_STEPS_BYTES.size - 1
        historyStorageLimitSlider.progress = closestStepIndex(currentLimitBytes)
        historyStorageLimitValue.text = formatStorageLimit(HISTORY_STORAGE_LIMIT_STEPS_BYTES[closestStepIndex(currentLimitBytes)])
        setHistoryStorageLimitVisible(nodeModeSwitch.isChecked)
        historyStorageLimitSlider.setOnSeekBarChangeListener(object : android.widget.SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(bar: android.widget.SeekBar, progress: Int, fromUser: Boolean) {
                val bytes = HISTORY_STORAGE_LIMIT_STEPS_BYTES[progress]
                historyStorageLimitValue.text = formatStorageLimit(bytes)
                if (fromUser) {
                    P2PService.setHistoryStorageLimitBytes(requireContext(), bytes)
                }
            }
            override fun onStartTrackingTouch(bar: android.widget.SeekBar) {}
            override fun onStopTrackingTouch(bar: android.widget.SeekBar) {}
        })

        nodeModeSwitch.setOnCheckedChangeListener { _, isChecked ->
            P2PService.setNodeModeEnabled(requireContext(), isChecked)
            setHistoryStorageLimitVisible(isChecked)
        }

        // Tor onion service: reachable even behind CGNAT (see tor.rs and SECURITY.md). Unlike node mode there is NO live toggle: a change takes effect
        // only when the network layer restarts (the transport can only be added in startNetwork). So the user is shown a 'restart the app' notice.
        val torSwitch = view.findViewById<SwitchMaterial>(R.id.tor_switch)
        torStatusView = view.findViewById(R.id.tor_status)
        torSwitch.isChecked = P2PService.isTorEnabled(requireContext())
        torSwitch.setOnCheckedChangeListener { _, isChecked ->
            P2PService.setTorEnabled(requireContext(), isChecked)
            Toast.makeText(requireContext(), R.string.tor_restart_needed, Toast.LENGTH_LONG).show()
            if (!isChecked) Toast.makeText(requireContext(), R.string.tor_off_no_network, Toast.LENGTH_LONG).show()
        }
        val betaSwitch = view.findViewById<SwitchMaterial>(R.id.beta_updates_switch)
        updateStatusView = view.findViewById(R.id.update_status)
        view.findViewById<Button>(R.id.btn_check_updates).setOnClickListener {
            com.p2p.messenger.service.SelfUpdate.checkNow(requireContext())
        }
        betaSwitch.isChecked = com.p2p.messenger.service.SelfUpdate.beta(requireContext())
        betaSwitch.setOnCheckedChangeListener { _, isChecked ->
            com.p2p.messenger.service.SelfUpdate.setBeta(requireContext(), isChecked)
        }
        // The poll starts in `onResume` (below), not at view creation, so it does not keep running while the app is in the background.

        // See SECURITY.md, 'Cross-network connectivity'. If no relay is discovered organically (for example no node mode is on and no reachable contact has been met),
        // this manual address is the only guarantee for a first pairing between two people on different networks.
        val relayAddressInput = view.findViewById<EditText>(R.id.relay_address_input)
        view.findViewById<Button>(R.id.btn_add_relay_address).setOnClickListener {
            val addr = relayAddressInput.text.toString().trim()
            if (addr.isEmpty()) return@setOnClickListener
            // Takes the core lock, which a long poll turn can hold: never on the main thread.
            lifecycleScope.launch(Dispatchers.IO) {
                val result = try {
                    P2PLib.addKnownRelayAddress(addr)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
                withContext(Dispatchers.Main) {
                    if (!isAdded) return@withContext
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), com.p2p.messenger.util.coreErrorText(requireContext(), result), Toast.LENGTH_SHORT).show()
                    } else {
                        relayAddressInput.text.clear()
                        Toast.makeText(requireContext(), R.string.msg_relay_address_added, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

        setupServers(view)
        view.findViewById<TextView>(R.id.txt_app_version)?.text = getString(
            R.string.lbl_app_version,
            try { requireContext().packageManager.getPackageInfo(requireContext().packageName, 0).versionName } catch (e: Exception) { "?" }
        )

        setupAppearanceControls(view)
        setupLanguageControl(view)
        setupChatAppearanceControls(view)
        setupNotificationControls(view)
        setupAppLockControls(view)

        // Show whether the keys are kept in the hardware security module (StrongBox or TEE): a concrete security indicator for the user.
        val securityStatus = view.findViewById<android.widget.TextView>(R.id.key_security_status)
        securityStatus.text = if (com.p2p.messenger.util.KeystoreCrypto.isHardwareBacked()) {
            getString(R.string.lbl_keys_hardware_backed)
        } else {
            getString(R.string.lbl_keys_software_backed)
        }

        // Trigger for the recovery-file export flow (see `pendingRecoveryPassphrase` and `createRecoveryFileLauncher`).
        view.findViewById<Button>(R.id.btn_export_recovery).setOnClickListener {
            withAppPassword { showExportRecoveryDialog() }
        }

        // Pending messages list (not yet acknowledged): see ui.PendingMessagesActivity.
        view.findViewById<Button>(R.id.btn_pending_messages).setOnClickListener {
            startActivity(Intent(requireContext(), PendingMessagesActivity::class.java))
        }

        view.findViewById<Button>(R.id.btn_storage).setOnClickListener {
            startActivity(Intent(requireContext(), StorageActivity::class.java))
        }

        // Multi-device: manage linked devices and add a new one.
        view.findViewById<Button>(R.id.btn_linked_devices).setOnClickListener {
            showLinkedDevicesDialog()
        }

        // Log out of the account: see `confirmLogout`.
        view.findViewById<Button>(R.id.btn_logout).setOnClickListener {
            withAppPassword { confirmLogout() }
        }
        view.findViewById<Button>(R.id.btn_delete_account).setOnClickListener {
            withAppPassword { confirmDeleteAccount() }
        }

        setupSections(view)
        return view
    }

    /**
     * Logout, and the recovery path after a crash during 'Link as a secondary device' (`LinkDeviceActivity`).
     * The identity is written to disk before that screen starts (`createIdentityAndStart` → `IdentityManager.persistNewIdentity`). If the app crashes right after,
     * the next launch sees `hasStoredIdentity()==true` in `MainActivity.onCreate` and continues with that half-finished, unpaired identity as if it were a normal
     * account, with no way to start over. This is the general 'log out' gate for that case: it deletes the local identity, message and contact data
     * (see `performLogout`), and restarts in a clean process with `AppRestarter`. `MainActivity` then sees `hasStoredIdentity()==false` and shows
     * `showDeviceNameDialog()` again.
     */
    private fun confirmLogout() {
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.logout_confirm_title)
            .setMessage(R.string.logout_confirm_message)
            .setPositiveButton(R.string.action_logout_confirm) { _, _ -> performLogout() }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Deletes ALL persistent identity and message data on this device: the SQLite DB (plus its WAL and SHM helper files), the encrypted secret key bundle
     * (`identity_secret.enc`), the other identity keys wrapped by the Keystore (history, skipped-key and ARK; see [com.p2p.messenger.util.LocalWipe]),
     * and the attachment storage directory. The Rust core has no verified way to 'forget' these safely inside a running process (see the `AppRestarter` docs:
     * same reason, delete the files and restart in a clean process instead of resetting identity or network state in a live process).
     * View and theme preferences (`ThemePrefs`) are deliberately left alone: they belong to the device, not the identity.
     */
    /** Deletes the account. First a notice goes to all contacts, groups and sibling devices (see Rust `delete_account`). It waits for confirmations, or at most
     *  [ACCOUNT_DELETE_WAIT_MS] (offline contacts get it through the server), then the local data is deleted with `performLogout`. */
    /** This device is the root of the account (its fingerprint is the identity id). */
    private fun isRootDevice(): Boolean = try {
        val arr = org.json.JSONArray(P2PLib.listLinkedDevices())
        (0 until arr.length()).map { arr.getJSONObject(it) }
            .any { it.optBoolean("is_this_device") && it.optString("device_fingerprint") == P2PLib.getOwnIdentityId() }
    } catch (e: Exception) { true }

    private fun confirmDeleteAccount() {
        // `isRootDevice()` makes two JNI calls, so it does NOT run on the main thread. The dialog opens on the main thread with the result.
        lifecycleScope.launch(Dispatchers.IO) {
            val root = isRootDevice()
            withContext(Dispatchers.Main) {
                // The core refuses it on a linked device; the generic "couldn't
                // notify your contacts" was shown for that.
                if (!root) {
                    Toast.makeText(requireContext(), R.string.msg_primary_device_only_delete, Toast.LENGTH_LONG).show()
                    return@withContext
                }
                AlertDialog.Builder(requireContext())
                    .setTitle(R.string.delete_account_confirm_title)
                    .setMessage(R.string.delete_account_confirm_message)
                    .setPositiveButton(R.string.action_delete_account) { _, _ -> performDeleteAccount() }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
    }

    private fun performDeleteAccount() {
        val ctx = requireContext().applicationContext
        val progress = AlertDialog.Builder(requireContext())
            .setMessage(R.string.msg_deleting_account)
            .setCancelable(false)
            .show()
        Thread {
            // -1 or an exception: nothing was announced. Wiping now would
            // destroy the only keys that can ever announce it, and contacts,
            // groups and sibling devices would never learn of the deletion.
            val sent = try { P2PLib.deleteAccount() } catch (e: Exception) { -1 }
            waitAndWipeAccount(ctx, progress, sent)
        }.start()
    }

    /** Runs on a background thread. Waits for the deletion notices to be
     *  acknowledged; if some are still unacknowledged at the deadline, asks the
     *  user whether to keep waiting or delete anyway (the wipe drops the resend queue). */
    private fun waitAndWipeAccount(ctx: android.content.Context, progress: AlertDialog, sent: Int) {
        var pending = 0
        if (sent >= 0) {
            try {
                val deadline = android.os.SystemClock.elapsedRealtime() + ACCOUNT_DELETE_WAIT_MS
                while (android.os.SystemClock.elapsedRealtime() < deadline) {
                    pending = P2PLib.accountDeletionPending()
                    if (pending == 0) break
                    Thread.sleep(500)
                }
            } catch (e: Exception) {
            }
        }
        val main = android.os.Handler(android.os.Looper.getMainLooper())
        if (sent >= 0 && pending > 0) {
            main.post {
                val act = activity
                if (act == null || !isAdded) {
                    Thread { finishAccountWipe(ctx, progress, true) }.start()
                    return@post
                }
                AlertDialog.Builder(act)
                    .setMessage(getString(R.string.delete_account_pending_message, pending))
                    .setCancelable(false)
                    .setPositiveButton(R.string.delete_account_keep_waiting) { _, _ ->
                        Thread { waitAndWipeAccount(ctx, progress, sent) }.start()
                    }
                    .setNegativeButton(R.string.delete_account_anyway) { _, _ ->
                        Thread { finishAccountWipe(ctx, progress, true) }.start()
                    }
                    .show()
            }
            return
        }
        finishAccountWipe(ctx, progress, sent >= 0)
    }

    private fun finishAccountWipe(ctx: android.content.Context, progress: AlertDialog, announced: Boolean) {
        if (announced) com.p2p.messenger.util.LocalWipe.wipe(ctx)
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            try { progress.dismiss() } catch (e: Exception) {}
            if (!announced) {
                Toast.makeText(ctx, R.string.error_delete_account_failed, Toast.LENGTH_LONG).show()
                return@post
            }
            AppRestarter.restart(ctx)
        }
    }

    private fun performLogout() {
        // Disk I/O off the UI thread; the restart hops back to main.
        val app = requireContext().applicationContext
        Thread {
            com.p2p.messenger.util.LocalWipe.wipe(app)
            android.os.Handler(android.os.Looper.getMainLooper()).post { AppRestarter.restart(app) }
        }.start()
    }

    /**
     * Multi-device: lists the devices linked to the identity, and allows adding a new one (by scanning a QR) and revoking a sibling device.
     * Add flow: on the OTHER (new) device, 'Link as a secondary device' is chosen and a QR is shown. THIS (existing) device scans that QR.
     */
    private fun showLinkedDevicesDialog() {
        // The JNI call (`listLinkedDevices` → core lock) does NOT run on the main thread. The dialog is built on the main thread (the identityCode pattern).
        lifecycleScope.launch(Dispatchers.IO) {
            val json = try { P2PLib.listLinkedDevices() } catch (e: Exception) { "[]" }
            withContext(Dispatchers.Main) {
                if (!isAdded) return@withContext
                val arr = try { org.json.JSONArray(json) } catch (e: Exception) { org.json.JSONArray() }
                val labels = ArrayList<String>()
                val fingerprints = ArrayList<String?>()
                val revokedFps = ArrayList<String?>()
                val thisDevice = getString(R.string.linked_devices_this_device)
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    val name = o.optString("device_name").ifEmpty { o.optString("device_fingerprint").take(8) }
                    val isThis = o.optBoolean("is_this_device", false)
                    val isActive = o.optBoolean("is_active", true)
                    val suffix = when {
                        isThis -> " ($thisDevice)"
                        !isActive -> " (${getString(R.string.linked_devices_revoked)})"
                        else -> ""
                    }
                    labels.add(name + suffix)
                    fingerprints.add(if (isThis || !isActive) null else o.optString("device_fingerprint"))
                    revokedFps.add(if (!isThis && !isActive) o.optString("device_fingerprint") else null)
                }

                AlertDialog.Builder(requireContext())
                    .setTitle(R.string.linked_devices_section_title)
                    .setItems(labels.toTypedArray()) { _, which ->
                        val fp = fingerprints.getOrNull(which)
                        if (fp != null) withAppPassword { confirmRevokeLinkedDevice(fp) }
                        revokedFps.getOrNull(which)?.let { confirmForgetRevokedDevice(it) }
                    }
                    .setPositiveButton(R.string.linked_devices_add) { _, _ ->
                        // Only the root device may add one (the core refuses the grant):
                        // say so before the camera opens, not after a scan.
                        // `isRootDevice()` JNI — off the main thread.
                        lifecycleScope.launch(Dispatchers.IO) {
                            val root = isRootDevice()
                            withContext(Dispatchers.Main) {
                                if (!isAdded) return@withContext
                                if (!root) {
                                    Toast.makeText(requireContext(), R.string.msg_primary_device_only, Toast.LENGTH_LONG).show()
                                    return@withContext
                                }
                                withAppPassword {
                                    startActivity(
                                        Intent(requireContext(), com.p2p.messenger.ui.QrScanActivity::class.java).apply {
                                            putExtra(com.p2p.messenger.ui.QrScanActivity.EXTRA_MODE,
                                                com.p2p.messenger.ui.QrScanActivity.MODE_LINK_APPROVE)
                                        }
                                    )
                                }
                            }
                        }
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
    }

    /** Asks for the app password before [action]: whoever holds the unlocked
     *  phone is not always its owner. */
    private fun withAppPassword(action: () -> Unit) {
        val context = requireContext()
        if (!AppLock.hasPassword(context)) {
            action()
            return
        }
        val wait = AppLock.retryWaitSeconds(context)
        if (wait > 0) {
            Toast.makeText(context, getString(R.string.error_app_lock_wait, wait), Toast.LENGTH_LONG).show()
            return
        }
        val field = EditText(context).apply {
            hint = getString(R.string.hint_app_lock_current)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val container = LinearLayout(context).apply {
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad / 2, pad, 0)
            addView(field)
        }
        AlertDialog.Builder(context)
            .setTitle(R.string.title_app_lock_unlock)
            .setView(container)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val entered = field.text.toString()
                lifecycleScope.launch(Dispatchers.IO) {
                    val ok = AppLock.verify(context, entered)
                    if (ok) AppLock.clearFailedAttempts(context) else AppLock.noteFailedAttempt(context)
                    withContext(Dispatchers.Main) {
                        if (!ok) {
                            Toast.makeText(context, R.string.error_app_lock_wrong, Toast.LENGTH_LONG).show()
                        } else if (isAdded) {
                            action()
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** A revoked device only clutters the list; the core keeps its record
     *  and the revoke (it is told again if it ever writes), so no password. */
    private fun confirmForgetRevokedDevice(fingerprint: String) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.linked_devices_confirm_forget)
            .setPositiveButton(R.string.action_remove_from_list) { _, _ ->
                val ctx = requireContext().applicationContext
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try { P2PLib.forgetRevokedLinkedDevice(fingerprint) } catch (e: Exception) { "Error: ${e.message}" }
                    withContext(Dispatchers.Main) {
                        if (result.startsWith("Error:")) {
                            Toast.makeText(ctx, com.p2p.messenger.util.coreErrorText(ctx, result), Toast.LENGTH_SHORT).show()
                        } else if (isAdded) {
                            showLinkedDevicesDialog()
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmRevokeLinkedDevice(fingerprint: String) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.linked_devices_confirm_revoke)
            .setPositiveButton(R.string.action_revoke_device) { _, _ ->
                // Signs and fans the revocation out to every contact and
                // sibling under the core lock: not on the main thread.
                val ctx = requireContext().applicationContext
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try { P2PLib.revokeLinkedDevice(fingerprint) } catch (e: Exception) { "Error: ${e.message}" }
                    withContext(Dispatchers.Main) {
                        Toast.makeText(ctx,
                            if (result.startsWith("Error:")) com.p2p.messenger.util.coreErrorText(ctx, result) else ctx.getString(R.string.msg_device_revoked),
                            Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Text size and interface size sliders, plus the system font picker. See `ThemePrefs` / `P2PApplication.applyScalePreferences`. Both are applied in
     * `onActivityPreCreated`, before the Activity's `onCreate` runs. The reason is the same as for the OLED switch: a change takes effect only when the next
     * Activity is created. So ALL THREE call `requireActivity().recreate()` when the value is released (slider) or chosen (dropdown). Not during the drag
     * (that would mean dozens of needless recreates per second), only at the final value.
     */
    private fun setupAppearanceControls(view: View) {
        val textScaleValue = view.findViewById<TextView>(R.id.text_scale_value)
        val textScaleSlider = view.findViewById<android.widget.SeekBar>(R.id.text_scale_slider)
        // See `TEXT_SCALE_STEPS` / `closestStepIndex`: a whole-number index (not a floating-point `stepSize`). This avoids the Material Slider crash at its root.
        textScaleSlider.max = TEXT_SCALE_STEPS.size - 1
        val currentTextScale = ThemePrefs.getTextScale(requireContext())
        textScaleSlider.progress = closestStepIndex(TEXT_SCALE_STEPS, currentTextScale)
        textScaleValue.text = formatScalePercent(TEXT_SCALE_STEPS[closestStepIndex(TEXT_SCALE_STEPS, currentTextScale)])
        textScaleSlider.setOnSeekBarChangeListener(object : android.widget.SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(bar: android.widget.SeekBar, progress: Int, fromUser: Boolean) {
                textScaleValue.text = formatScalePercent(TEXT_SCALE_STEPS[progress])
            }
            override fun onStartTrackingTouch(bar: android.widget.SeekBar) {}
            override fun onStopTrackingTouch(bar: android.widget.SeekBar) {
                ThemePrefs.setTextScale(requireContext(), TEXT_SCALE_STEPS[bar.progress])
                requireActivity().recreate()
            }
        })

        val uiScaleValue = view.findViewById<TextView>(R.id.ui_scale_value)
        val uiScaleSlider = view.findViewById<android.widget.SeekBar>(R.id.ui_scale_slider)
        uiScaleSlider.max = UI_SCALE_STEPS.size - 1
        val currentUiScale = ThemePrefs.getUiScale(requireContext())
        uiScaleSlider.progress = closestStepIndex(UI_SCALE_STEPS, currentUiScale)
        uiScaleValue.text = formatScalePercent(UI_SCALE_STEPS[closestStepIndex(UI_SCALE_STEPS, currentUiScale)])
        uiScaleSlider.setOnSeekBarChangeListener(object : android.widget.SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(bar: android.widget.SeekBar, progress: Int, fromUser: Boolean) {
                uiScaleValue.text = formatScalePercent(UI_SCALE_STEPS[progress])
            }
            override fun onStartTrackingTouch(bar: android.widget.SeekBar) {}
            override fun onStopTrackingTouch(bar: android.widget.SeekBar) {
                ThemePrefs.setUiScale(requireContext(), UI_SCALE_STEPS[bar.progress])
                requireActivity().recreate()
            }
        })

        // See ThemePrefs.FontChoice: the order must match the displayed name list exactly (index-based mapping). `CUSTOM` is NOT in this list: it is not a directory.
        // `getActiveCustomFontId` tracks which of the N imported fonts from `ThemePrefs.getCustomFonts()` is selected (see the dialog setup below).
        // A custom font shows its real imported name, and several imports are supported.
        val fontChoices = ThemePrefs.FontChoice.entries.filter { it != ThemePrefs.FontChoice.CUSTOM }
        val fontLabels = arrayOf(
            getString(R.string.lbl_font_default),
            getString(R.string.lbl_font_sans_medium),
            getString(R.string.lbl_font_sans_condensed),
            getString(R.string.lbl_font_serif),
            getString(R.string.lbl_font_monospace),
            getString(R.string.lbl_font_sans_black)
        )
        // Replaces a `MaterialAutoCompleteTextView` with `setSimpleItems` by a plain `Button` and `AlertDialog.setSingleChoiceItems`. The exposed dropdown
        // showed only the default item on a real device, and its popup behaviour cannot be verified in this environment, so a simpler mechanism is used.
        // This list is not filtered: ALL options are always shown.
        //
        // Known limit: the list offers only the generic aliases that every Android device guarantees (`sans-serif`, `serif`, `monospace`, plus weight and width
        // variants). There is no general, official Android API to enumerate a manufacturer's branded or downloaded font names (for example 'One UI Sans' or a
        // downloaded Google Fonts family), so those never appear here. The 'Default' option still uses the device's CURRENT system default (even if the user
        // changed it in manufacturer settings), because no override is applied.
        val fontValueText = view.findViewById<TextView>(R.id.font_family_value)
        fun currentFontLabel(): String {
            val choice = ThemePrefs.getFontChoice(requireContext())
            return if (choice == ThemePrefs.FontChoice.CUSTOM) {
                // See `ThemePrefs.activeCustomFontName`: the real name of the selected font among several imported ones. If the record is broken (the id was deleted),
                // it falls back to the generic name.
                ThemePrefs.activeCustomFontName(requireContext()) ?: getString(R.string.lbl_font_custom)
            } else {
                fontLabels[fontChoices.indexOf(choice).coerceAtLeast(0)]
            }
        }
        fontValueText.text = currentFontLabel()
        view.findViewById<Button>(R.id.btn_pick_font).setOnClickListener {
            val currentChoice = ThemePrefs.getFontChoice(requireContext())
            val activeCustomId = ThemePrefs.getActiveCustomFontId(requireContext())
            val customFonts = ThemePrefs.getCustomFonts(requireContext())
            // Dialog rows: [0] 'Import', [1..fontChoices.size] the built-in fonts, then any imported fonts. Each imported font has its own name
            // (see `ThemePrefs.CustomFont.displayName`): the real font name, not 'custom', and several may exist.
            val dialogLabels = arrayOf(getString(R.string.lbl_font_import)) + fontLabels +
                customFonts.map { it.displayName }.toTypedArray()
            val currentIndex = if (currentChoice == ThemePrefs.FontChoice.CUSTOM) {
                val i = customFonts.indexOfFirst { it.id == activeCustomId }
                if (i >= 0) 1 + fontChoices.size + i else 0
            } else {
                fontChoices.indexOf(currentChoice).coerceAtLeast(0) + 1
            }
            AlertDialog.Builder(requireContext())
                .setTitle(R.string.lbl_font_family)
                .setSingleChoiceItems(dialogLabels, currentIndex) { dialog, position ->
                    when {
                        position == 0 -> {
                            // 'Import a .ttf file…' selects no font. It closes the dialog and opens the file picker.
                            dialog.dismiss()
                            AppLock.beginTrustedExcursion()
                            pickFontLauncher.launch(arrayOf("font/ttf", "font/otf", "application/x-font-ttf", "application/octet-stream", "*/*"))
                        }
                        position <= fontChoices.size -> {
                            // See `fontChoices`: position 1 and up maps to index = position - 1.
                            val chosen = fontChoices[position - 1]
                            if (chosen != currentChoice) {
                                ThemePrefs.setFontChoice(requireContext(), chosen)
                                fontValueText.text = fontLabels[position - 1]
                                // Forces the font on all UI: see the `FontOverride` docs. It replaces Android's default Typeface at once (`P2PApplication.onCreate` runs only at
                                // process start, so without this call the change would show only after the next full app restart). `recreate()` then redraws this Activity with the
                                // updated default Typeface.
                                com.p2p.messenger.util.FontOverride.apply(chosen.familyName)
                                requireActivity().recreate()
                            }
                            dialog.dismiss()
                        }
                        else -> {
                            // One of the fonts imported earlier was selected (see `dialogLabels`: these rows are offset in `customFonts` by fontChoices.size).
                            val cf = customFonts[position - 1 - fontChoices.size]
                            if (!(currentChoice == ThemePrefs.FontChoice.CUSTOM && cf.id == activeCustomId)) {
                                ThemePrefs.setFontChoice(requireContext(), ThemePrefs.FontChoice.CUSTOM)
                                ThemePrefs.setActiveCustomFontId(requireContext(), cf.id)
                                fontValueText.text = cf.displayName
                                com.p2p.messenger.util.FontOverride.applyFile(ThemePrefs.customFontFile(requireContext(), cf.id))
                                requireActivity().recreate()
                            }
                            dialog.dismiss()
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    /**
     * 'Show messages in notifications' switch. On by default. When off, a notification shows only the sender (for a group message, the sender and the group),
     * not the text. See util.NotificationPrefs and NotificationHelper.
     */
    private fun setupNotificationControls(view: View) {
        val notifSwitch = view.findViewById<SwitchMaterial>(R.id.notif_show_message_switch)
        notifSwitch.isChecked = NotificationPrefs.showMessageText(requireContext())
        notifSwitch.setOnCheckedChangeListener { _, checked ->
            NotificationPrefs.setShowMessageText(requireContext(), checked)
        }
    }

    /**
     * App-open password. From here it can only be CHANGED. There is no removal option (a password must never be empty), and an empty new password is refused too.
     *
     * The current password is checked with `AppLock.verify`. In a session that is not locked (the user is already inside), this stops someone who briefly
     * gets the phone from changing the password silently. `AppLock.verify` and `setPassword` deliberately run a slow KDF (see AppLock.ITERATIONS), so they
     * are called OFF the main thread.
     */
    private fun setupAppLockControls(view: View) {
        view.findViewById<Button>(R.id.btn_change_app_password).setOnClickListener {
            val context = requireContext()
            val container = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                val pad = (20 * resources.displayMetrics.density).toInt()
                setPadding(pad, pad / 2, pad, 0)
            }
            fun passwordField(hintRes: Int) = EditText(context).apply {
                hint = getString(hintRes)
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            // If no password has ever been set (for example an older install upgraded to this version that has not shown the lock screen yet), asking for the
            // 'current password' field makes no sense.
            val hasExisting = AppLock.hasPassword(context)
            val currentField = passwordField(R.string.hint_app_lock_current)
            val newField = passwordField(R.string.hint_app_lock_new)
            val confirmField = passwordField(R.string.hint_app_lock_password_confirm)
            if (hasExisting) container.addView(currentField)
            container.addView(newField)
            container.addView(confirmField)

            AlertDialog.Builder(context)
                .setTitle(R.string.action_change_app_password)
                .setView(container)
                .setPositiveButton(R.string.action_app_lock_save) { _, _ ->
                    val newPassword = newField.text.toString()
                    if (newPassword.isBlank()) {
                        Toast.makeText(context, R.string.error_app_lock_empty, Toast.LENGTH_LONG).show()
                        return@setPositiveButton
                    }
                    if (newPassword.length < AppLock.MIN_PASSWORD_LENGTH) {
                        Toast.makeText(context, getString(R.string.error_app_lock_short, AppLock.MIN_PASSWORD_LENGTH), Toast.LENGTH_LONG).show()
                        return@setPositiveButton
                    }
                    if (newPassword != confirmField.text.toString()) {
                        Toast.makeText(context, R.string.error_app_lock_mismatch, Toast.LENGTH_LONG).show()
                        return@setPositiveButton
                    }
                    val current = currentField.text.toString()
                    lifecycleScope.launch(Dispatchers.IO) {
                        val waitSec = if (hasExisting) AppLock.retryWaitSeconds(context) else 0
                        val currentOk = !hasExisting || AppLock.verifyThrottled(context, current)
                        if (currentOk) AppLock.setPassword(context, newPassword)
                        withContext(Dispatchers.Main) {
                            if (waitSec > 0) {
                                Toast.makeText(context, getString(R.string.error_app_lock_wait, waitSec), Toast.LENGTH_LONG).show()
                                return@withContext
                            }
                            val messageRes = if (currentOk) {
                                R.string.msg_app_lock_changed
                            } else {
                                R.string.error_app_lock_wrong
                            }
                            Toast.makeText(context, messageRes, Toast.LENGTH_LONG).show()
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    /** Language picker (English/Turkish). AppCompatDelegate.setApplicationLocales
     *  persists the choice itself (see AndroidManifest AppLocalesMetadataHolderService)
     *  and recreates all activities; the explicit recreate() below matches this
     *  screen's own font/color pickers for immediate visual feedback. */
    private fun setupLanguageControl(view: View) {
        val languageCodes = arrayOf("en", "tr")
        val languageLabels = arrayOf("English", "Türkçe")
        val languageValueText = view.findViewById<TextView>(R.id.language_value)
        fun currentLanguageIndex(): Int {
            val current = AppCompatDelegate.getApplicationLocales().toLanguageTags()
            return languageCodes.indexOfFirst { current.startsWith(it) }.coerceAtLeast(0)
        }
        languageValueText.text = languageLabels[currentLanguageIndex()]
        view.findViewById<Button>(R.id.btn_pick_language).setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle(R.string.lbl_language)
                .setSingleChoiceItems(languageLabels, currentLanguageIndex()) { dialog, position ->
                    AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(languageCodes[position]))
                    dialog.dismiss()
                    requireActivity().recreate()
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private fun formatScalePercent(scale: Float): String = getString(R.string.lbl_scale_percent, (scale * 100).toInt())

    /**
     * ONE accent colour, used everywhere (buttons, switches, sliders, and our own message bubbles), with variations (see `ThemePrefs.applyAccentColor`,
     * Material's content-based dynamic colour engine). The text colour is NOT chosen separately: it is always computed as black or white, whichever is
     * readable on that colour. The background colour is valid for both the general UI and the chat screen (see `ThemePrefs.applyChatBackground`).
     * The colour picker is a full HSV picker (see `HsvColorPickerDialog`) and needs NO external library: this build cannot be verified in this environment,
     * so no new Gradle dependency is added. Both colours (accent and background) change the whole app's theme, like OLED and the font,
     * so `recreate()` is needed after the choice.
     */
    private fun setupChatAppearanceControls(view: View) {
        val bgSwatch = view.findViewById<View>(R.id.chat_bg_color_swatch)
        val accentSwatch = view.findViewById<View>(R.id.accent_color_swatch)
        val textSwatch = view.findViewById<View>(R.id.text_color_swatch)
        val wallpaperThumb = view.findViewById<ImageView>(R.id.chat_wallpaper_thumb)
        val btnRemoveWallpaper = view.findViewById<Button>(R.id.btn_remove_chat_wallpaper)

        fun swatchDrawable(color: Int?): android.graphics.drawable.Drawable {
            return android.graphics.drawable.GradientDrawable().apply {
                shape = android.graphics.drawable.GradientDrawable.OVAL
                setColor(color ?: MaterialColors.getColor(bgSwatch, com.google.android.material.R.attr.colorSurfaceVariant))
                setStroke((1.5f * resources.displayMetrics.density).toInt(), MaterialColors.getColor(bgSwatch, com.google.android.material.R.attr.colorOutline))
            }
        }

        fun refreshSwatches() {
            bgSwatch.background = swatchDrawable(ThemePrefs.getChatBackgroundColor(requireContext()))
            accentSwatch.background = swatchDrawable(ThemePrefs.getAccentColor(requireContext()))
            textSwatch.background = swatchDrawable(ThemePrefs.getTextColor(requireContext()))
        }

        val blurRow = view.findViewById<View>(R.id.wallpaper_blur_row)
        val darknessRow = view.findViewById<View>(R.id.wallpaper_darkness_row)
        val blurSlider = view.findViewById<android.widget.SeekBar>(R.id.wallpaper_blur_slider)
        val darknessSlider = view.findViewById<android.widget.SeekBar>(R.id.wallpaper_darkness_slider)
        val blurValue = view.findViewById<TextView>(R.id.wallpaper_blur_value)
        val darknessValue = view.findViewById<TextView>(R.id.wallpaper_darkness_value)

        // Cheap downscaled preview while dragging (off the main thread, newest wins).
        var previewJob: kotlinx.coroutines.Job? = null
        fun previewEffects() {
            val app = requireContext().applicationContext
            val blur = blurSlider.progress
            val dark = darknessSlider.progress
            previewJob?.cancel()
            previewJob = viewLifecycleOwner.lifecycleScope.launch(Dispatchers.Default) {
                val bmp = ThemePrefs.wallpaperPreview(app, blur, dark, 160) ?: return@launch
                withContext(Dispatchers.Main) { wallpaperThumb.setImageBitmap(bmp) }
            }
        }

        fun refreshWallpaperPreview() {
            val file = ThemePrefs.chatWallpaperFile(requireContext())
            if (file.exists()) {
                blurSlider.progress = ThemePrefs.getWallpaperBlur(requireContext())
                darknessSlider.progress = ThemePrefs.getWallpaperDarkness(requireContext())
                blurValue.text = "%.1f".format(blurSlider.progress / 10f)
                darknessValue.text = "${darknessSlider.progress}%"
                wallpaperThumb.setImageBitmap(android.graphics.BitmapFactory.decodeFile(file.absolutePath))
                previewEffects()
                wallpaperThumb.visibility = View.VISIBLE
                btnRemoveWallpaper.visibility = View.VISIBLE
                blurRow.visibility = View.VISIBLE
                darknessRow.visibility = View.VISIBLE
            } else {
                wallpaperThumb.visibility = View.GONE
                btnRemoveWallpaper.visibility = View.GONE
                blurRow.visibility = View.GONE
                darknessRow.visibility = View.GONE
            }
        }

        // On release: store values, compute the processed file once, off the main thread.
        // On release: store values, compute the processed file once, off the main thread.
        fun seekListener(onProgress: (Int, Boolean) -> Unit) = object : android.widget.SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(bar: android.widget.SeekBar, progress: Int, fromUser: Boolean) = onProgress(progress, fromUser)
            override fun onStartTrackingTouch(bar: android.widget.SeekBar) {}
            override fun onStopTrackingTouch(bar: android.widget.SeekBar) {
                val app = requireContext().applicationContext
                ThemePrefs.setWallpaperEffects(app, blurSlider.progress, darknessSlider.progress)
                lifecycleScope.launch(Dispatchers.IO) {
                    try {
                        ThemePrefs.regenerateProcessedWallpaper(app)
                    } catch (e: Exception) {
                        com.p2p.messenger.util.Log.w("SettingsFragment", "wallpaper effects failed", e)
                    }
                }
            }
        }
        blurSlider.setOnSeekBarChangeListener(seekListener { value, fromUser ->
            blurValue.text = "%.1f".format(value / 10f)
            if (fromUser) previewEffects()
        })
        darknessSlider.setOnSeekBarChangeListener(seekListener { value, fromUser ->
            darknessValue.text = "${value}%"
            if (fromUser) previewEffects()
        })

        refreshSwatches()
        refreshWallpaperPreview()

        view.findViewById<Button>(R.id.btn_pick_chat_bg_color).setOnClickListener {
            com.p2p.messenger.util.HsvColorPickerDialog.show(
                requireContext(), R.string.title_pick_bg_color, ThemePrefs.getChatBackgroundColor(requireContext())
            ) { picked ->
                ThemePrefs.setChatBackgroundColor(requireContext(), picked)
                refreshSwatches()
                requireActivity().recreate()
            }
        }
        // `ThemePrefs.applyAccentColor` rides on dynamic colour (Android 12+).
        if (!com.google.android.material.color.DynamicColors.isDynamicColorAvailable()) {
            view.findViewById<Button>(R.id.btn_pick_accent_color).visibility = View.GONE
            accentSwatch.visibility = View.GONE
        }
        view.findViewById<Button>(R.id.btn_pick_text_color).setOnClickListener {
            com.p2p.messenger.util.HsvColorPickerDialog.show(
                requireContext(), R.string.title_pick_text_color, ThemePrefs.getTextColor(requireContext())
            ) { picked ->
                ThemePrefs.setTextColor(requireContext(), picked)
                refreshSwatches()
                requireActivity().recreate()
            }
        }
        val myBtn = view.findViewById<SwitchMaterial>(R.id.material_you_switch)
        val accentBtn = view.findViewById<Button>(R.id.btn_pick_accent_color)
        fun syncAccentEnabled() {
            val on = ThemePrefs.isMaterialYou(requireContext())
            for (b in listOf(accentBtn, view.findViewById<Button>(R.id.btn_pick_chat_bg_color), view.findViewById<Button>(R.id.btn_pick_text_color))) {
                b.isEnabled = !on
            }
            for (sw in listOf(accentSwatch, bgSwatch, textSwatch)) sw.alpha = if (on) 0.4f else 1f
        }
        if (!com.google.android.material.color.DynamicColors.isDynamicColorAvailable()) {
            myBtn.visibility = View.GONE
            (myBtn.parent as View).visibility = View.GONE
        }
        myBtn.isChecked = ThemePrefs.isMaterialYou(requireContext())
        syncAccentEnabled()
        myBtn.setOnCheckedChangeListener { _, on ->
            ThemePrefs.setMaterialYou(requireContext(), on)
            syncAccentEnabled()
            requireActivity().recreate()
        }
        view.findViewById<Button>(R.id.btn_pick_accent_color).setOnClickListener {
            com.p2p.messenger.util.HsvColorPickerDialog.show(
                requireContext(), R.string.title_pick_accent_color, ThemePrefs.getAccentColor(requireContext())
            ) { picked ->
                ThemePrefs.setAccentColor(requireContext(), picked)
                refreshSwatches()
                requireActivity().recreate()
            }
        }
        view.findViewById<Button>(R.id.btn_pick_chat_wallpaper).setOnClickListener {
            AppLock.beginTrustedExcursion()
            pickWallpaperLauncher.launch(arrayOf("image/*"))
        }
        btnRemoveWallpaper.setOnClickListener {
            ThemePrefs.clearChatWallpaper(requireContext())
            refreshWallpaperPreview()
        }
    }

    /**
     * Same `content://` to local file copy pattern as `onAvatarPicked`. The difference: this is ONLY a local UI preference, sent to nobody
     * (see ThemePrefs.chatWallpaperFile), so Rust is not involved.
     */
    private fun onChatWallpaperPicked(uri: Uri) {
        // Off the fragment: `requireContext()` on the worker threw once the
        // screen was gone.
        val app = requireContext().applicationContext
        lifecycleScope.launch(Dispatchers.IO) {
            val tempFile = File(File(app.cacheDir, "wallpaper").apply { mkdirs() }, UUID.randomUUID().toString())
            try {
                // Foreign `content://` URI: cap the bytes actually streamed into the cache (see ImagePreview.copyToCapped and GroupChatActivity).
                val copied = app.contentResolver.openInputStream(uri)?.use { input ->
                    input.copyToCapped(tempFile, MAX_FOREIGN_URI_BYTES)
                } ?: false
                if (!copied) throw java.io.IOException("Dosya açılamadı")
                // Not a readable image: the catch below shows the error toast.
                val compressed = ImagePreview.compressFile(tempFile, WALLPAPER_MAX_DIMENSION, WALLPAPER_JPEG_QUALITY)
                    ?: throw java.io.IOException("not an image")
                ThemePrefs.chatWallpaperFile(app).writeBytes(compressed)
                // New image: rebuild the processed copy with the current slider values.
                ThemePrefs.regenerateProcessedWallpaper(app)
                withContext(Dispatchers.Main) {
                    view?.let { v ->
                        val thumb = v.findViewById<ImageView>(R.id.chat_wallpaper_thumb)
                        val btnRemove = v.findViewById<Button>(R.id.btn_remove_chat_wallpaper)
                        val file = ThemePrefs.chatWallpaperFile(app)
                        if (file.exists()) {
                            thumb.setImageBitmap(android.graphics.BitmapFactory.decodeFile(file.absolutePath))
                            thumb.visibility = View.VISIBLE
                            btnRemove.visibility = View.VISIBLE
                            v.findViewById<View>(R.id.wallpaper_blur_row).visibility = View.VISIBLE
                            v.findViewById<View>(R.id.wallpaper_darkness_row).visibility = View.VISIBLE
                        }
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(app, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                }
            } finally {
                tempFile.delete()
            }
        }
    }

    /**
     * See `onChatWallpaperPicked`: a RAW byte copy from a `content://` URI into the local `filesDir`. No threads or coroutines: synchronous, a simple
     * `openInputStream` → `copyTo`. Font files are small (usually under 1 MB), so no block-size optimisation is needed.
     *
     * Each pick is copied to its OWN new id (`newCustomFontId`) and ADDED to the list, so earlier imported fonts stay. The shown name is the REAL file name
     * that SAF provides (`OpenableColumns.DISPLAY_NAME`). If the copy fails (or SAF gives no name and the fallback path also fails), no record is added or selected,
     * so no orphan list entry remains.
     */
    private fun onFontPicked(uri: Uri) {
        // Copies up to 32 MB: off the main thread.
        val ctx = requireContext().applicationContext
        lifecycleScope.launch {
            val displayName = withContext(Dispatchers.IO) { copyPickedFont(ctx, uri) }
            if (displayName == null) {
                Toast.makeText(ctx, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                return@launch
            }
            val id = displayName.first
            val file = ThemePrefs.customFontFile(ctx, id)
            val name = displayName.second
            ThemePrefs.registerCustomFont(ctx, id, name)
            ThemePrefs.setFontChoice(ctx, ThemePrefs.FontChoice.CUSTOM)
            ThemePrefs.setActiveCustomFontId(ctx, id)
            view?.findViewById<TextView>(R.id.font_family_value)?.text = name
            com.p2p.messenger.util.FontOverride.applyFile(file)
            activity?.recreate()
        }
    }

    /** Blocking part of [onFontPicked]: (font id, display name), or null on failure. */
    private fun copyPickedFont(context: android.content.Context, uri: Uri): Pair<String, String>? {
        val id = ThemePrefs.newCustomFontId()
        val file = ThemePrefs.customFontFile(context, id)
        try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                // The '*/*' picker accepts any file. Only files with a font signature (TrueType, OpenType or collection) and a reasonable size are copied, so an
                // accidentally picked video cannot fill filesDir and a broken file does not enter the list. `readNBytes` needs API 33+; minSdk is 26, so a short
                // file hits EOFException.
                val head = ByteArray(4).also { java.io.DataInputStream(input).readFully(it) }
                val magicOk = (
                    head.contentEquals(byteArrayOf(0, 1, 0, 0)) ||
                        String(head, Charsets.ISO_8859_1) in setOf("OTTO", "true", "ttcf"))
                if (!magicOk) throw java.io.IOException("not a font file")
                file.outputStream().use { out ->
                    out.write(head)
                    val buf = ByteArray(64 * 1024)
                    var total = head.size.toLong()
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_FONT_BYTES) throw java.io.IOException("font too large")
                        out.write(buf, 0, n)
                    }
                }
            } ?: return null
            return id to (queryDisplayName(context, uri) ?: file.name)
        } catch (e: Exception) {
            // See `onChatWallpaperPicked`: must not crash, passes silently. A half-copied file is also dropped. It is never added to the list, so it cannot be
            // selected, but it must not stay on disk as an orphan.
            file.delete()
            return null
        }
    }

    /** Reads the REAL file name from the `content://` URI that SAF gave (see `onFontPicked`: the font list shows this name instead of 'Custom').
     *  Some providers may leave this column empty; if it returns `null`, the caller falls back to its own file name. */
    private fun queryDisplayName(context: android.content.Context, uri: Uri): String? {
        return try {
            context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                val idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (idx >= 0 && cursor.moveToFirst()) cursor.getString(idx) else null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Quick Tor and network reconnect menu item in the top bar. See util/AppRestarter.kt (why a full app restart is needed) and menu_settings.xml.
     * MainActivity is ONE Activity with three bottom-navigation tabs (Chats, Contacts, Settings). The `MenuProvider` is registered with `viewLifecycleOwner`
     * and `RESUMED`, so this menu item appears ONLY while the Settings tab is visible, and disappears on the other tabs automatically (when the Fragment's
     * view is destroyed, the provider is removed too, no manual cleanup needed). It is registered in `onViewCreated`, not inside `onCreateView`:
     * `viewLifecycleOwner` is valid only once `onCreateView` has returned.
     */
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        requireActivity().addMenuProvider(object : MenuProvider {
            override fun onCreateMenu(menu: Menu, menuInflater: MenuInflater) {
                menuInflater.inflate(R.menu.menu_settings, menu)
            }

            override fun onMenuItemSelected(menuItem: MenuItem): Boolean {
                if (menuItem.itemId == R.id.action_tor_reconnect) {
                    AppRestarter.confirmAndRestart(requireContext())
                    return true
                }
                return false
            }
        }, viewLifecycleOwner, Lifecycle.State.RESUMED)
    }

    /**
     * Takes the passphrase (and its confirmation). If they do not match or it is empty, the user is warned. If they match, it continues with the SAF
     * target picker (see `createRecoveryFileLauncher`). The Rust side (`export_recovery`) hardens the passphrase with Argon2id, so no minimum length or
     * complexity rule is imposed here. A short passphrase is cheaper to brute-force, but that is the user's own risk and preference; no further policy is set here.
     */
    private fun showExportRecoveryDialog() {
        val context = requireContext()
        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (16 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
        }
        val passwordInput = EditText(context).apply {
            hint = getString(R.string.lbl_recovery_password)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val confirmInput = EditText(context).apply {
            hint = getString(R.string.lbl_recovery_password_confirm)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        layout.addView(passwordInput)
        layout.addView(confirmInput)

        AlertDialog.Builder(context)
            .setTitle(R.string.action_export_recovery)
            .setMessage(R.string.lbl_recovery_export_desc)
            .setView(layout)
            .setPositiveButton(R.string.action_export_recovery) { _, _ ->
                val password = passwordInput.text.toString()
                val confirm = confirmInput.text.toString()
                when {
                    password.isEmpty() -> Toast.makeText(context, R.string.error_recovery_password_empty, Toast.LENGTH_SHORT).show()
                    // Offline guessing is the only thing between this file and every key.
                    password.length < 12 -> Toast.makeText(context, getString(R.string.error_recovery_password_short, 12), Toast.LENGTH_LONG).show()
                    password != confirm -> Toast.makeText(context, R.string.error_recovery_password_mismatch, Toast.LENGTH_SHORT).show()
                    else -> {
                        pendingRecoveryPassphrase = password
                        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                        AppLock.beginTrustedExcursion()
                        createRecoveryFileLauncher.launch("typeon-recovery-$stamp.bin")
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Writes the Argon2id-encrypted recovery file to `uri` (the target the user picked with SAF). `P2PLib.exportRecovery` runs a deliberately slow,
     * memory-heavy KDF (see the Argon2id note in Cargo.toml), so it is called OFF the main thread, otherwise it would risk an ANR lasting seconds.
     * An empty byte array (see the Rust `Java_..._exportRecovery` docs) means failure.
     */
    private fun exportRecoveryTo(uri: Uri, passphrase: String) {
        Toast.makeText(requireContext(), R.string.msg_recovery_exporting, Toast.LENGTH_SHORT).show()
        // Taken now: the export runs for seconds and `requireContext()` on the
        // worker threw once the user had left the screen meanwhile.
        val resolver = requireContext().applicationContext.contentResolver
        lifecycleScope.launch(Dispatchers.IO) {
            val bytes = try {
                P2PLib.exportRecovery(passphrase)
            } catch (e: Exception) {
                null
            }
            val ok = try {
                if (bytes != null && bytes.isNotEmpty()) {
                    resolver.openOutputStream(uri)?.use { out -> out.write(bytes); true } ?: false
                } else {
                    false
                }
            } catch (e: Exception) {
                false
            }
            withContext(Dispatchers.Main) {
                if (isAdded) {
                    Toast.makeText(
                        requireContext(),
                        if (ok) R.string.msg_recovery_export_success else R.string.error_recovery_export_failed,
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun refreshDisplayName() {
        // The JNI call (`getDisplayName` → core lock) does NOT run on the main thread; the result is written on the main thread.
        lifecycleScope.launch(Dispatchers.IO) {
            val name = try {
                P2PLib.getDisplayName()
            } catch (e: Exception) {
                ""
            }
            withContext(Dispatchers.Main) {
                val v = displayNameValue
                if (v != null && v.isAttachedToWindow) v.text = name
            }
        }
    }

    /**
     * Changes the account name and sends the change to contacts AUTOMATICALLY.
     *
     * Same pattern and reason as `setOwnAvatar`: the fan-out encrypts separately for each contact (see Rust `set_display_name`), so it cannot run on the main thread.
     * The name on screen updates at once. The sending runs in the background and is retried for offline contacts over days, so the user does not need to wait for it.
     */
    private fun showChangeDisplayNameDialog() {
        // The JNI call (`getDisplayName` → core lock) does NOT run on the main thread; the dialog opens on the main thread.
        lifecycleScope.launch(Dispatchers.IO) {
            val current = try {
                P2PLib.getDisplayName()
            } catch (e: Exception) {
                ""
            }
            withContext(Dispatchers.Main) {
                if (!isAdded) return@withContext
                val input = EditText(requireContext()).apply {
                    setText(current)
                    setSingleLine(true)
                    // Rust also trims the name (`MAX_DISPLAY_NAME_CHARS`). This limit only stops the user typing a name that would be cut silently.
                    filters = arrayOf(android.text.InputFilter.LengthFilter(48))
                }
                AlertDialog.Builder(requireContext())
                    .setTitle(R.string.dlg_change_display_name_title)
                    .setMessage(R.string.lbl_display_name_desc)
                    .setView(input)
                    .setPositiveButton(android.R.string.ok) { _, _ ->
                        val name = input.text.toString().trim()
                        if (name.isEmpty()) return@setPositiveButton
                        displayNameValue?.text = name
                        lifecycleScope.launch(Dispatchers.IO) {
                            val result = try {
                                P2PLib.setDisplayName(name)
                            } catch (e: Exception) {
                                "Error: ${e.message}"
                            }
                            withContext(Dispatchers.Main) {
                                if (!isAdded) return@withContext
                                if (result.startsWith("Error:")) {
                                    Toast.makeText(requireContext(), com.p2p.messenger.util.coreErrorText(requireContext(), result), Toast.LENGTH_LONG).show()
                                    refreshDisplayName()
                                } else {
                                    Toast.makeText(requireContext(), R.string.msg_display_name_changed, Toast.LENGTH_SHORT).show()
                                }
                            }
                        }
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
    }

    private fun refreshOwnAvatar() {
        // The JNI calls (`getOwnProfilePicture`, `getDisplayName`, `getIdentityShortCode` → core lock) do NOT run on the main thread.
        // The drawing happens on the main thread (identityCode pattern).
        lifecycleScope.launch(Dispatchers.IO) {
            val bytes = try {
                P2PLib.getOwnProfilePicture().takeIf { it.isNotEmpty() }
            } catch (e: Exception) {
                null
            }
            // With no photo, the initial letter is shown (see AvatarUtil). The initial of the account name, or the first character of the identity code,
            // is meaningful: contacts already know us by that name.
            val name = try {
                P2PLib.getDisplayName().ifEmpty { P2PLib.getIdentityShortCode() }
            } catch (e: Exception) {
                "?"
            }
            withContext(Dispatchers.Main) {
                val v = imgOwnAvatar
                if (isAdded && v.isAttachedToWindow) {
                    ownAvatarBytes = bytes
                    AvatarUtil.renderInto(v, bytes, name)
                }
            }
        }
    }

    /**
     * An image the user picked with SAF (`OpenDocument`). Same `content://` to local file copy as `ChatActivity.onFilePicked`. It is compressed to 720p at
     * 85% JPEG, then both stored by `setOwnProfilePicture` AND sent to ALL known contacts (see Rust `set_own_profile_picture`). So it runs OFF the main thread.
     */
    private fun onAvatarPicked(uri: Uri) {
        val app = requireContext().applicationContext
        lifecycleScope.launch(Dispatchers.IO) {
            val tempFile = File(File(app.cacheDir, "avatar").apply { mkdirs() }, UUID.randomUUID().toString())
            try {
                // Foreign `content://` URI: cap the bytes actually streamed into the cache (see ImagePreview.copyToCapped and AttachmentPrompt).
                val copied = app.contentResolver.openInputStream(uri)?.use { input ->
                    input.copyToCapped(tempFile, MAX_FOREIGN_URI_BYTES)
                } ?: false
                if (!copied) throw java.io.IOException("Dosya açılamadı")
                // null = not an image. `setOwnAvatar(null)` means "remove" and
                // would publish the removal to every contact.
                val compressed = ImagePreview.compressFile(tempFile, AVATAR_MAX_DIMENSION, AVATAR_JPEG_QUALITY)
                    ?: throw java.io.IOException("Not an image")
                withContext(Dispatchers.Main) { setOwnAvatar(compressed) }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(app, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                }
            } finally {
                tempFile.delete()
            }
        }
    }

    private fun setOwnAvatar(avatarJpeg: ByteArray?) {
        // The JNI calls (`getDisplayName` and `getIdentityShortCode` → core lock) do NOT run on the main thread. Drawing happens on the main thread,
        // and sending continues in the background (see the identityCode pattern, `onCreateView`).
        lifecycleScope.launch(Dispatchers.IO) {
            val name = try {
                P2PLib.getDisplayName().ifEmpty { P2PLib.getIdentityShortCode() }
            } catch (e: Exception) {
                "?"
            }
            withContext(Dispatchers.Main) {
                val v = imgOwnAvatar
                if (isAdded && v.isAttachedToWindow) {
                    ownAvatarBytes = avatarJpeg
                    AvatarUtil.renderInto(v, avatarJpeg, name)
                }
            }
            val result = try {
                P2PLib.setOwnProfilePicture(avatarJpeg)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (result.startsWith("Error:")) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(requireContext(), com.p2p.messenger.util.coreErrorText(requireContext(), result), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /** Polls Rust `torStatus()` and updates the label. If the reply is 'ready|<host>.onion', it shows the host too. */
    private fun startTorStatusPolling() {
        torStatusHandler.removeCallbacks(torStatusRunnable)
        torStatusHandler.post(torStatusRunnable)
    }

    /** See `torStatusRunnable`: the poll runs only while the screen is in the foreground. */
    override fun onResume() {
        super.onResume()
        startTorStatusPolling()
    }

    override fun onPause() {
        super.onPause()
        torStatusHandler.removeCallbacks(torStatusRunnable)
    }

    private fun updateTorStatusLabel() {
        val label = torStatusView ?: return
        // `torStatus()` is a JNI call that takes the core lock, so it is not run on the main thread.
        lifecycleScope.launch {
            val raw = withContext(Dispatchers.IO) {
                try {
                    P2PLib.torStatus()
                } catch (e: Exception) {
                    "failed"
                }
            }
            if (torStatusView !== label) return@launch
            val state = raw.substringBefore('|')
            label.text = when (state) {
                "bootstrapping" -> getString(R.string.tor_status_bootstrapping)
                "ready" -> {
                    val host = raw.substringAfter('|', "")
                    if (host.isNotEmpty()) getString(R.string.tor_status_ready) + "\n" + host
                    else getString(R.string.tor_status_ready)
                }
                "failed" -> getString(R.string.tor_status_failed)
                else -> getString(R.string.tor_status_disabled)
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        torStatusHandler.removeCallbacks(torStatusRunnable)
        torStatusView = null
        updateStatusView = null
    }

    // -----------------------------------------------------------------
    // Servers (store-and-forward). See the Rust `server_client` module.
    // -----------------------------------------------------------------
    //
    // Servers are a separate section because they are not relays. A relay stores nothing: it builds a live circuit only while both sides are connected.
    // A server writes the envelope to disk when the recipient is offline. That difference is what the user sees, and combining both in one 'add address'
    // box would set a wrong expectation.

    private var serversContainer: LinearLayout? = null

    /** To scan a server QR: see QrScanActivity.MODE_ADD_SERVER. */
    private val scanServerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { refreshServers() }

    private fun setupServers(view: View) {
        serversContainer = view.findViewById(R.id.servers_container)

        view.findViewById<Button>(R.id.btn_add_server).setOnClickListener {
            val intent = Intent(requireContext(), QrScanActivity::class.java)
            intent.putExtra(QrScanActivity.EXTRA_MODE, QrScanActivity.MODE_ADD_SERVER)
            scanServerLauncher.launch(intent)
        }

        view.findViewById<Button>(R.id.btn_add_server_paste).setOnClickListener {
            showPasteServerCodeDialog()
        }

        refreshServers()
    }

    private fun showPasteServerCodeDialog() {
        val input = EditText(requireContext()).apply {
            hint = getString(R.string.dlg_add_server_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(false)
            maxLines = 4
        }
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.dlg_add_server_title)
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val code = input.text.toString().trim()
                if (code.isEmpty()) return@setPositiveButton
                // Same disclosure as the other add-server doors: the history
                // warning only when this server would become the history server.
                lifecycleScope.launch {
                    val historyServer = withContext(Dispatchers.IO) { P2PLib.nextServerStoresHistory(code) }
                    if (!isAdded) return@launch
                    AlertDialog.Builder(requireContext())
                        .setTitle(R.string.dlg_add_server_title)
                        .setMessage(
                            getString(R.string.msg_join_link_confirm, code) +
                                if (historyServer) "\n\n" + getString(R.string.lbl_server_history_warn) + " " + getString(R.string.msg_server_history_upload) else ""
                        )
                        .setPositiveButton(android.R.string.ok) { _, _ -> addServer(code) }
                        .setNegativeButton(android.R.string.cancel, null)
                        .show()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun addServer(code: String) {
        if (code.isEmpty()) return
        val ctx = requireContext().applicationContext
        // Writes to disk and starts a dial under the core lock.
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try {
                P2PLib.addServer(code)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(ctx, com.p2p.messenger.util.coreErrorText(ctx, result), Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(ctx, R.string.msg_server_added, Toast.LENGTH_SHORT).show()
                    if (view != null) refreshServers()
                }
            }
        }
    }

    /**
     * Redraws the server rows.
     *
     * The number of rows varies, so they are built in code rather than fixed in XML. The look matches the other sections of the settings:
     * bold 16sp title, 12sp description at 70% opacity, `?attr/materialButtonOutlinedStyle` buttons, and `SwitchMaterial`.
     */
    private fun refreshServers() {
        if (serversContainer == null) return

        // `listServers()` JNI — off the main thread; rows are
        // built back on the main thread.
        lifecycleScope.launch(Dispatchers.IO) {
            val json = try {
                P2PLib.listServers()
            } catch (e: Exception) {
                "[]"
            }
            val arr = try {
                org.json.JSONArray(json)
            } catch (e: Exception) {
                org.json.JSONArray()
            }
            val rows = (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }
            withContext(Dispatchers.Main) {
                val fresh = serversContainer ?: return@withContext
                // Cleared here, not before the read: two refreshes in flight
                // (screen opened + scan result) both appended their rows.
                fresh.removeAllViews()
                for (obj in rows) fresh.addView(buildServerRow(obj))
            }
        }
    }

    private fun buildServerRow(obj: org.json.JSONObject): View {
        val serverId = obj.optString("server_id")
        val ctx = requireContext()
        val density = resources.displayMetrics.density
        fun dp(v: Int) = (v * density).toInt()

        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(12), dp(12), dp(12))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
            setBackgroundColor(
                MaterialColors.getColor(this, com.google.android.material.R.attr.colorSurfaceContainerHigh)
            )
        }

        val name = obj.optString("name").ifEmpty { obj.optString("address") }
        row.addView(TextView(ctx).apply {
            text = name
            textSize = 14f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })

        // Status: connected and registered, connecting, or not registered. Registration uses the join code the operator publishes. If it fails, the reason
        // is shown here (`last_error`).
        val connected = obj.optBoolean("connected")
        val enrolled = obj.optBoolean("enrolled")
        val lastError = obj.optString("last_error").takeIf { it.isNotEmpty() && it != "null" }
        val stateText = when {
            lastError != null -> lastError
            connected && enrolled -> getString(R.string.state_server_connected)
            connected -> getString(R.string.state_server_not_enrolled)
            else -> getString(R.string.state_server_connecting)
        }
        row.addView(TextView(ctx).apply {
            text = stateText
            textSize = 12f
            alpha = 0.7f
        })

        row.addView(SwitchMaterial(ctx).apply {
            text = getString(R.string.lbl_server_route)
            isChecked = obj.optBoolean("route_messages")
            setOnCheckedChangeListener { button, checked ->
                applyServerToggle(button, checked) { P2PLib.setServerRouting(serverId, checked) }
            }
        })

        row.addView(SwitchMaterial(ctx).apply {
            text = getString(R.string.lbl_server_history)
            isChecked = obj.optBoolean("store_history")
            setOnCheckedChangeListener { button, checked ->
                applyServerToggle(button, checked) {
                    // The root archive key (ARK) is generated ONLY here (see ArchiveKeyManager). If it were generated at startup, a device that opened before getting the key
                    // from its sibling would use its own random key, and the archive it uploaded would be unreadable on the other devices.
                    if (checked && !revertingServerToggle && !ArchiveKeyManager.ensureCreated(ctx.applicationContext)) {
                        "Error: archive key unavailable"
                    } else {
                        P2PLib.setServerHistory(serverId, checked)
                    }
                }
            }
        })

        row.addView(TextView(ctx).apply {
            text = getString(R.string.lbl_server_history_warn)
            textSize = 12f
            alpha = 0.7f
        })

        // For a freshly set up device: the scroll-up flow assumes the chat is already visible, but here there are no messages and nothing to scroll.
        row.addView(Button(ctx, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.action_restore_history)
            setOnClickListener {
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try {
                        P2PLib.restoreServerHistory()
                    } catch (e: Exception) {
                        "Error: ${e.message}"
                    }
                    withContext(Dispatchers.Main) {
                        val msg = if (result.startsWith("Error:")) com.p2p.messenger.util.coreErrorText(ctx, result)
                        else ctx.getString(R.string.msg_restore_started)
                        Toast.makeText(ctx, msg, Toast.LENGTH_LONG).show()
                    }
                }
            }
        })

        row.addView(Button(ctx, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.action_remove_server)
            setTextColor(MaterialColors.getColor(this, com.google.android.material.R.attr.colorError))
            setOnClickListener {
                // `removeServer` JNI — off the main thread.
                lifecycleScope.launch(Dispatchers.IO) {
                    val res = try {
                        P2PLib.removeServer(serverId)
                    } catch (e: Exception) {
                        "Error: ${e.message}"
                    }
                    withContext(Dispatchers.Main) {
                        if (res.startsWith("Error:")) {
                            Toast.makeText(ctx, com.p2p.messenger.util.coreErrorText(ctx, res), Toast.LENGTH_LONG).show()
                        } else {
                            Toast.makeText(ctx, R.string.msg_server_removed, Toast.LENGTH_SHORT).show()
                        }
                        refreshServers()
                    }
                }
            }
        })

        return row
    }

}
