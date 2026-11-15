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
        internal const val AVATAR_MAX_DIMENSION = 720
        /** See `performDeleteAccount`. */
        internal const val ACCOUNT_DELETE_WAIT_MS = 15_000L
        /** See `onFontPicked`: large CJK fonts are around 20 MB. */
        internal const val MAX_FONT_BYTES = 32L * 1024 * 1024
        internal const val AVATAR_JPEG_QUALITY = 85

        /** See `onChatWallpaperPicked`: larger than an avatar (it is shown full screen as the background), but still a reasonable upper limit. */
        internal const val WALLPAPER_MAX_DIMENSION = 1080
        internal const val WALLPAPER_JPEG_QUALITY = 80

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

        internal fun closestStepIndex(bytes: Long): Int {
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
        internal val TEXT_SCALE_STEPS = floatArrayOf(
            0.70f, 0.75f, 0.80f, 0.85f, 0.90f, 0.95f, 1.00f, 1.05f, 1.10f, 1.15f,
            1.20f, 1.25f, 1.30f, 1.35f, 1.40f, 1.45f, 1.50f, 1.55f, 1.60f
        )
        internal val UI_SCALE_STEPS = floatArrayOf(
            0.75f, 0.80f, 0.85f, 0.90f, 0.95f, 1.00f, 1.05f, 1.10f, 1.15f, 1.20f, 1.25f, 1.30f
        )

        internal fun closestStepIndex(steps: FloatArray, value: Float): Int {
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

    internal lateinit var imgOwnAvatar: ImageView
    /** Raw profile photo bytes, passed to the full-screen viewer by the click listener of `imgOwnAvatar` (see AvatarUtil.openFullscreen). */
    internal var ownAvatarBytes: ByteArray? = null
    internal var displayNameValue: TextView? = null

    /** Status label and periodic poll. The poll starts in `onResume` and stops in `onPause`. A JNI poll every 2 s from view creation would keep running
     *  while the app is in the background, wasting battery and core-lock time. */
    internal var torStatusView: TextView? = null
    private var updateStatusView: TextView? = null
    internal val torStatusHandler = Handler(Looper.getMainLooper())
    internal val torStatusRunnable = object : Runnable {
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
    internal val pickWallpaperLauncher = registerForActivityResult(com.p2p.messenger.util.OpenDocumentAtHome()) { uri ->
        uri?.let { onChatWallpaperPicked(it) }
    }

    /** Font picker: chooses a `.ttf` or `.otf` font file. The same `OpenDocument` pattern as `pickWallpaperLauncher`. */
    internal val pickFontLauncher = registerForActivityResult(com.p2p.messenger.util.OpenDocumentAtHome()) { uri ->
        uri?.let { onFontPicked(it) }
    }

    /**
     * The Rust side (`export_recovery`, hardened with Argon2id, see SECURITY.md §6) is triggered from this screen.
     * The passphrase is held here temporarily, just before it is written to the target the user picks with SAF (Storage Access Framework,
     * `CreateDocument`), in `showExportRecoveryDialog`. This file carries ALL long-term identity keys, so the target must be a location the user
     * chooses. SAF is the only way that works the same on every API level without WRITE_EXTERNAL_STORAGE.
     */
    internal var pendingRecoveryPassphrase: String? = null

    internal val createRecoveryFileLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
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
    internal var revertingServerToggle = false

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

    /** See `torStatusRunnable`: the poll runs only while the screen is in the foreground. */
    override fun onResume() {
        super.onResume()
        startTorStatusPolling()
    }

    override fun onPause() {
        super.onPause()
        torStatusHandler.removeCallbacks(torStatusRunnable)
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

    internal var serversContainer: LinearLayout? = null

    /** To scan a server QR: see QrScanActivity.MODE_ADD_SERVER. */
    internal val scanServerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { refreshServers() }

}
