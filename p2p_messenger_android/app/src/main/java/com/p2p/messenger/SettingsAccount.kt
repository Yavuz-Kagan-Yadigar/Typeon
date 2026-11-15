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

// SettingsFragment, account card: profile name and picture, recovery export, logout and account deletion.

/**
 * Logout, and the recovery path after a crash during 'Link as a secondary device' (`LinkDeviceActivity`).
 * The identity is written to disk before that screen starts (`createIdentityAndStart` → `IdentityManager.persistNewIdentity`). If the app crashes right after,
 * the next launch sees `hasStoredIdentity()==true` in `MainActivity.onCreate` and continues with that half-finished, unpaired identity as if it were a normal
 * account, with no way to start over. This is the general 'log out' gate for that case: it deletes the local identity, message and contact data
 * (see `performLogout`), and restarts in a clean process with `AppRestarter`. `MainActivity` then sees `hasStoredIdentity()==false` and shows
 * `showDeviceNameDialog()` again.
 */
internal fun SettingsFragment.confirmLogout() {
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
internal fun SettingsFragment.isRootDevice(): Boolean = try {
    val arr = org.json.JSONArray(P2PLib.listLinkedDevices())
    (0 until arr.length()).map { arr.getJSONObject(it) }
        .any { it.optBoolean("is_this_device") && it.optString("device_fingerprint") == P2PLib.getOwnIdentityId() }
} catch (e: Exception) { true }

internal fun SettingsFragment.confirmDeleteAccount() {
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

internal fun SettingsFragment.performDeleteAccount() {
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
internal fun SettingsFragment.waitAndWipeAccount(ctx: android.content.Context, progress: AlertDialog, sent: Int) {
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

internal fun SettingsFragment.finishAccountWipe(ctx: android.content.Context, progress: AlertDialog, announced: Boolean) {
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

internal fun SettingsFragment.performLogout() {
    // Disk I/O off the UI thread; the restart hops back to main.
    val app = requireContext().applicationContext
    Thread {
        com.p2p.messenger.util.LocalWipe.wipe(app)
        android.os.Handler(android.os.Looper.getMainLooper()).post { AppRestarter.restart(app) }
    }.start()
}

/**
 * Takes the passphrase (and its confirmation). If they do not match or it is empty, the user is warned. If they match, it continues with the SAF
 * target picker (see `createRecoveryFileLauncher`). The Rust side (`export_recovery`) hardens the passphrase with Argon2id, so no minimum length or
 * complexity rule is imposed here. A short passphrase is cheaper to brute-force, but that is the user's own risk and preference; no further policy is set here.
 */
internal fun SettingsFragment.showExportRecoveryDialog() {
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
internal fun SettingsFragment.exportRecoveryTo(uri: Uri, passphrase: String) {
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

internal fun SettingsFragment.refreshDisplayName() {
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
internal fun SettingsFragment.showChangeDisplayNameDialog() {
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

internal fun SettingsFragment.refreshOwnAvatar() {
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
internal fun SettingsFragment.onAvatarPicked(uri: Uri) {
    val app = requireContext().applicationContext
    lifecycleScope.launch(Dispatchers.IO) {
        val tempFile = File(File(app.cacheDir, "avatar").apply { mkdirs() }, UUID.randomUUID().toString())
        try {
            // Foreign `content://` URI: cap the bytes actually streamed into the cache (see ImagePreview.copyToCapped and AttachmentPrompt).
            val copied = app.contentResolver.openInputStream(uri)?.use { input ->
                input.copyToCapped(tempFile, MAX_FOREIGN_URI_BYTES)
            } ?: false
            if (!copied) throw java.io.IOException("File could not be opened")
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

internal fun SettingsFragment.setOwnAvatar(avatarJpeg: ByteArray?) {
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
