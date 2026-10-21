package com.p2p.messenger.server

import android.app.Activity
import android.content.Context
import android.os.SystemClock
import android.text.InputType
import android.util.Base64
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * PIN lock of the server app (same approach as the client's AppLock: PBKDF2
 * hash, escalating wait after 5 failures, relock after leaving / screen off).
 * The whole screen (join code, devices, settings) sits behind it.
 */
object ServerLock {
    private const val KEY_SALT = "lock_salt"
    private const val KEY_HASH = "lock_hash"
    private const val KEY_FAILED = "lock_failed"
    private const val KEY_WAIT_UNTIL = "lock_wait_until_wall"
    private const val ITERATIONS = 300_000
    private const val MIN_LEN = 6
    private const val FREE_ATTEMPTS = 5
    private const val GRACE_MS = 30_000L

    @Volatile private var unlocked = false
    @Volatile private var leftAt = 0L

    private fun prefs(c: Context) = c.getSharedPreferences(ServerService.PREFS_NAME, Context.MODE_PRIVATE)

    fun hasPin(c: Context) = prefs(c).contains(KEY_HASH)

    /** True when the content must stay hidden until the PIN is entered. */
    fun isLocked(c: Context): Boolean {
        if (!hasPin(c)) return false
        val l = leftAt
        leftAt = 0L
        if (l != 0L && SystemClock.elapsedRealtime() - l > GRACE_MS) unlocked = false
        return !unlocked
    }

    fun noteLeft() { leftAt = SystemClock.elapsedRealtime() }
    fun lockNow() { unlocked = false }

    private fun derive(pin: String, salt: ByteArray): ByteArray =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, 256)).encoded

    private fun verify(c: Context, pin: String): Boolean {
        val p = prefs(c)
        val salt = p.getString(KEY_SALT, null) ?: return false
        val hash = p.getString(KEY_HASH, null) ?: return false
        return MessageDigest.isEqual(Base64.decode(hash, Base64.NO_WRAP), derive(pin, Base64.decode(salt, Base64.NO_WRAP)))
    }

    private fun setPin(c: Context, pin: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        prefs(c).edit()
            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(KEY_HASH, Base64.encodeToString(derive(pin, salt), Base64.NO_WRAP))
            .commit()
    }

    private fun waitSeconds(c: Context): Int =
        ((prefs(c).getLong(KEY_WAIT_UNTIL, 0L) - System.currentTimeMillis() + 999) / 1000).coerceAtLeast(0).toInt()

    /** PBKDF2 at 300k iterations: callers run this off the UI thread or accept ~0.3 s. */
    private fun tryPin(c: Context, pin: String): Boolean {
        if (waitSeconds(c) > 0) return false
        val p = prefs(c)
        if (verify(c, pin)) {
            p.edit().remove(KEY_FAILED).remove(KEY_WAIT_UNTIL).commit()
            return true
        }
        val failed = p.getInt(KEY_FAILED, 0) + 1
        val e = p.edit().putInt(KEY_FAILED, failed)
        if (failed >= FREE_ATTEMPTS) {
            e.putLong(KEY_WAIT_UNTIL, System.currentTimeMillis() + (30_000L shl (failed - FREE_ATTEMPTS).coerceAtMost(5)))
        }
        e.commit()
        return false
    }

    private fun field(a: Activity, hint: Int) = EditText(a).apply {
        setHint(hint)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    }

    /** Modal, non-cancelable unlock prompt; [onOk] runs after a correct PIN. */
    fun showUnlock(a: Activity, onOk: () -> Unit): AlertDialog {
        val input = field(a, R.string.pin_hint)
        val dlg = AlertDialog.Builder(a)
            .setTitle(R.string.pin_unlock_title)
            .setView(input)
            .setCancelable(false)
            .setPositiveButton(R.string.pin_unlock, null)
            .setNegativeButton(R.string.pin_exit) { _, _ -> a.finish() }
            .create()
        dlg.setOnShowListener {
            dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val wait = waitSeconds(a)
                when {
                    wait > 0 -> Toast.makeText(a, a.getString(R.string.pin_wait_fmt, wait), Toast.LENGTH_SHORT).show()
                    tryPin(a, input.text.toString()) -> { unlocked = true; dlg.dismiss(); onOk() }
                    else -> { input.text.clear(); Toast.makeText(a, R.string.pin_wrong, Toast.LENGTH_SHORT).show() }
                }
            }
        }
        dlg.show()
        return dlg
    }

    /** Set, change or (empty new PIN) remove the PIN. Asks for the current one if set. */
    fun showSettings(a: Activity) {
        val has = hasPin(a)
        val cur = field(a, R.string.pin_current_hint)
        val new = field(a, R.string.pin_new_hint)
        val box = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 16, 48, 0)
            if (has) addView(cur)
            addView(new)
        }
        val dlg = AlertDialog.Builder(a)
            .setTitle(R.string.pin_settings_title)
            .setMessage(if (has) R.string.pin_change_msg else R.string.pin_set_msg)
            .setView(box)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dlg.setOnShowListener {
            dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val n = new.text.toString()
                if (has && !tryPin(a, cur.text.toString())) {
                    Toast.makeText(a, R.string.pin_wrong, Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                if (n.isEmpty() && has) {
                    prefs(a).edit().remove(KEY_HASH).remove(KEY_SALT).commit()
                    Toast.makeText(a, R.string.pin_removed, Toast.LENGTH_SHORT).show()
                } else if (n.length < MIN_LEN) {
                    Toast.makeText(a, a.getString(R.string.pin_too_short_fmt, MIN_LEN), Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                } else {
                    setPin(a, n)
                    unlocked = true
                    Toast.makeText(a, R.string.pin_saved, Toast.LENGTH_SHORT).show()
                }
                dlg.dismiss()
            }
        }
        dlg.show()
    }
}
