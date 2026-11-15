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

// SettingsFragment, linked devices card.

/**
 * Multi-device: lists the devices linked to the identity, and allows adding a new one (by scanning a QR) and revoking a sibling device.
 * Add flow: on the OTHER (new) device, 'Link as a secondary device' is chosen and a QR is shown. THIS (existing) device scans that QR.
 */
internal fun SettingsFragment.showLinkedDevicesDialog() {
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
internal fun SettingsFragment.withAppPassword(action: () -> Unit) {
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
internal fun SettingsFragment.confirmForgetRevokedDevice(fingerprint: String) {
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

internal fun SettingsFragment.confirmRevokeLinkedDevice(fingerprint: String) {
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
