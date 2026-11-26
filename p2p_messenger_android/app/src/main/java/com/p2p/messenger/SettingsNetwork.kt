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
import com.p2p.messenger.SettingsFragment.Companion.ACCOUNT_DELETE_WAIT_MS
import com.p2p.messenger.SettingsFragment.Companion.AVATAR_JPEG_QUALITY
import com.p2p.messenger.SettingsFragment.Companion.AVATAR_MAX_DIMENSION
import com.p2p.messenger.SettingsFragment.Companion.MAX_FONT_BYTES
import com.p2p.messenger.SettingsFragment.Companion.TEXT_SCALE_STEPS
import com.p2p.messenger.SettingsFragment.Companion.UI_SCALE_STEPS
import com.p2p.messenger.SettingsFragment.Companion.WALLPAPER_JPEG_QUALITY
import com.p2p.messenger.SettingsFragment.Companion.WALLPAPER_MAX_DIMENSION
import com.p2p.messenger.SettingsFragment.Companion.closestStepIndex

// SettingsFragment, network card: servers and the Tor status line.

/** Runs a core server setting; on failure shows it and puts the switch
 *  back, so it never shows ON while nothing is stored or routed. */
internal fun SettingsFragment.applyServerToggle(switch: android.widget.CompoundButton, checked: Boolean, change: () -> String) {
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

/** Polls Rust `torStatus()` and updates the label. If the reply is 'ready|<host>.onion', it shows the host too. */
internal fun SettingsFragment.startTorStatusPolling() {
    torStatusHandler.removeCallbacks(torStatusRunnable)
    torStatusHandler.post(torStatusRunnable)
}

internal fun SettingsFragment.updateTorStatusLabel() {
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
        updateTorModeDesc()
    }
}

internal fun SettingsFragment.setupServers(view: View) {
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

internal fun SettingsFragment.showPasteServerCodeDialog() {
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

internal fun SettingsFragment.addServer(code: String) {
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
 * bold 14sp title, 12sp description at 70% opacity, `?attr/materialButtonOutlinedStyle` buttons, and `SwitchMaterial`.
 */
internal fun SettingsFragment.refreshServers() {
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

internal fun SettingsFragment.buildServerRow(obj: org.json.JSONObject): View {
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
            // Rejoining needs the operator's join code again: ask first.
            AlertDialog.Builder(ctx)
                .setMessage(getString(R.string.confirm_remove_server, name))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.action_remove_server) { _, _ ->
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
                .show()
        }
    })

    return row
}

/** Tor connection modes, in dialog order. See Rust `tor::set_transport`. */
private val TOR_MODES = arrayOf("direct", "snowflake", "obfs4")

internal fun SettingsFragment.torModeLabel(mode: String): String = getString(
    when (mode) {
        "snowflake" -> R.string.tor_mode_snowflake
        "obfs4" -> R.string.tor_mode_obfs4
        else -> R.string.tor_mode_direct
    }
)

/** Mode label, plus which path is in use now: a bridge mode is a fallback (Rust `tor::watch_bridge_fallback`).
 *  Refreshed by the Tor status poll, which runs only while this screen is in the foreground. */
internal fun SettingsFragment.updateTorModeDesc(root: View? = view) {
    val desc = root?.findViewById<TextView>(R.id.tor_mode_desc) ?: return
    val mode = P2PService.getTorMode(requireContext())
    desc.text = if (mode == "direct") torModeLabel(mode)
        else torModeLabel(mode) + "\n" + getString(if (P2PLib.torBridgeInUse()) R.string.tor_state_bridge else R.string.tor_state_direct)
}

internal fun SettingsFragment.setupTorMode(view: View) {
    updateTorModeDesc(view)
    view.findViewById<Button>(R.id.btn_tor_mode).setOnClickListener { showTorModeDialog() }
}

/** Direct / Snowflake / obfs4 bridges. A change is stored and the app restarts: arti reads it only at start
 *  (see util/AppRestarter.kt). A mode whose PT binary is not in this APK cannot be picked. */
internal fun SettingsFragment.showTorModeDialog() {
    val ctx = requireContext()
    val ptDir = ctx.applicationInfo.nativeLibraryDir
    val current = P2PService.getTorMode(ctx)
    val storedBridges = P2PService.getTorBridges(ctx)
    val pad = (16 * resources.displayMetrics.density).toInt()
    val root = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad / 2, pad, 0) }
    root.addView(TextView(ctx).apply { setText(R.string.msg_tor_mode_restart) })
    val group = android.widget.RadioGroup(ctx)
    TOR_MODES.forEachIndexed { i, mode ->
        val available = P2PLib.torTransportAvailable(mode, ptDir)
        group.addView(android.widget.RadioButton(ctx).apply {
            id = View.generateViewId()
            tag = mode
            text = if (available) torModeLabel(mode)
                else torModeLabel(mode) + "\n" + getString(R.string.tor_mode_unavailable)
            isEnabled = available || mode == current
            isChecked = mode == current || (i == 0 && current !in TOR_MODES)
        })
    }
    root.addView(group)
    val bridgesInput = EditText(ctx).apply {
        hint = getString(R.string.hint_tor_bridges)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        setSingleLine(false)
        minLines = 3
        maxLines = 8
        textSize = 12f
        typeface = android.graphics.Typeface.MONOSPACE
        setText(storedBridges)
    }
    val errorView = TextView(ctx).apply {
        setTextColor(MaterialColors.getColor(this, com.google.android.material.R.attr.colorError))
        visibility = View.GONE
    }
    root.addView(bridgesInput)
    root.addView(errorView)
    fun selected(): String = group.findViewById<View>(group.checkedRadioButtonId)?.tag as? String ?: "direct"
    fun syncVisibility() {
        bridgesInput.visibility = if (selected() == "obfs4") View.VISIBLE else View.GONE
        errorView.visibility = View.GONE
    }
    group.setOnCheckedChangeListener { _, _ -> syncVisibility() }
    syncVisibility()

    val dialog = AlertDialog.Builder(ctx)
        .setTitle(R.string.lbl_tor_connection)
        .setView(android.widget.ScrollView(ctx).apply { addView(root) })
        .setPositiveButton(android.R.string.ok, null)
        .setNegativeButton(android.R.string.cancel, null)
        .create()
    dialog.setOnShowListener {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val mode = selected()
            val bridges = bridgesInput.text.toString().trim()
            if (mode == "obfs4") {
                val check = P2PLib.validateBridgeLines(bridges)
                if (check.startsWith("Error")) {
                    errorView.text = getString(R.string.msg_tor_bridges_invalid, check.removePrefix("Error: "))
                    errorView.visibility = View.VISIBLE
                    return@setOnClickListener
                }
            }
            dialog.dismiss()
            if (mode == current && (mode != "obfs4" || bridges == storedBridges)) return@setOnClickListener
            P2PService.setTorTransport(ctx, mode, if (mode == "obfs4") bridges else storedBridges)
            AppRestarter.restart(ctx)
        }
    }
    dialog.show()
}
