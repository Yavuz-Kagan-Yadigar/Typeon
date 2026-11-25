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

// SettingsFragment, notification and app lock cards.

/**
 * 'Show messages in notifications' switch. Off by default. When off, a notification shows only the sender (for a group message, the sender and the group),
 * not the text. See util.NotificationPrefs and NotificationHelper.
 */
internal fun SettingsFragment.setupNotificationControls(view: View) {
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
 * gets the phone from changing the password silently. `AppLock.verify` and `setPassword` deliberately run a slow KDF (Argon2id, see Vault), so they
 * are called OFF the main thread.
 */
internal fun SettingsFragment.setupAppLockControls(view: View) {
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
