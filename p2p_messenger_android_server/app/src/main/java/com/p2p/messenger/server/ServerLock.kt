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
import java.util.concurrent.Executors

/**
 * PIN lock of the server app (same approach as the client's AppLock: PBKDF2
 * hash, escalating wait after 5 failures, relock after leaving / screen off).
 * The whole screen (join code, devices, settings) sits behind it. The PIN is
 * mandatory: the join code is a bearer token for enrolments, so an unlocked
 * spare phone must not show it to whoever picks it up.
 */
object ServerLock {
    private const val KEY_SALT = "lock_salt"
    private const val KEY_HASH = "lock_hash"
    private const val KEY_FAILED = "lock_failed"
    // Wait anchored to time since boot (the user can set the wall clock
    // forward); the wall clock only re-anchors it after a reboot.
    private const val KEY_WAIT_FROM = "lock_wait_from_elapsed"
    private const val KEY_WAIT_MS = "lock_wait_ms"
    private const val KEY_WAIT_WALL = "lock_wait_wall"
    private const val KEY_ITERATIONS = "lock_iterations"
    private const val ITERATIONS = 600_000
    /** PINs saved before `KEY_ITERATIONS` existed. */
    private const val OLD_ITERATIONS = 300_000
    private const val MIN_LEN = 6
    private const val FREE_ATTEMPTS = 5
    private const val GRACE_MS = 30_000L

    @Volatile private var unlocked = false
    @Volatile private var leftAt = 0L
    /** Single worker: PBKDF2 verify (+set) is ~0.3 s of CPU that blocks. */
    private val cpu = Executors.newSingleThreadExecutor()

    private fun prefs(c: Context) = c.getSharedPreferences(ServerService.PREFS_NAME, Context.MODE_PRIVATE)

    fun hasPin(c: Context) = prefs(c).contains(KEY_HASH)

    /** True when the content must stay hidden until the PIN is entered (or, with no PIN yet, set). */
    fun isLocked(c: Context): Boolean {
        if (!hasPin(c)) return true
        val l = leftAt
        leftAt = 0L
        if (l != 0L && SystemClock.elapsedRealtime() - l > GRACE_MS) unlocked = false
        return !unlocked
    }

    fun noteLeft() { leftAt = SystemClock.elapsedRealtime() }
    fun lockNow() { unlocked = false }

    private fun derive(pin: String, salt: ByteArray, iterations: Int): ByteArray {
        val chars = pin.toCharArray()
        val spec = PBEKeySpec(chars, salt, iterations, 256)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
            chars.fill('\u0000')
        }
    }

    private fun verify(c: Context, pin: String): Boolean {
        val p = prefs(c)
        val salt = p.getString(KEY_SALT, null) ?: return false
        val hash = p.getString(KEY_HASH, null) ?: return false
        val iterations = p.getInt(KEY_ITERATIONS, OLD_ITERATIONS)
        return MessageDigest.isEqual(Base64.decode(hash, Base64.NO_WRAP), derive(pin, Base64.decode(salt, Base64.NO_WRAP), iterations))
    }

    private fun setPin(c: Context, pin: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        prefs(c).edit()
            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(KEY_HASH, Base64.encodeToString(derive(pin, salt, ITERATIONS), Base64.NO_WRAP))
            .putInt(KEY_ITERATIONS, ITERATIONS)
            .commit()
    }

    private fun waitSeconds(c: Context): Int {
        val p = prefs(c)
        val waitMs = p.getLong(KEY_WAIT_MS, 0L)
        if (waitMs <= 0L) return 0
        val now = SystemClock.elapsedRealtime()
        var from = p.getLong(KEY_WAIT_FROM, 0L)
        if (now < from) {
            // Rebooted: credit the wall time since the failure, but never more
            // than the uptime since boot, so a clock set forward refunds nothing.
            val passed = (System.currentTimeMillis() - p.getLong(KEY_WAIT_WALL, 0L)).coerceIn(0L, minOf(waitMs, now))
            from = now - passed
            p.edit().putLong(KEY_WAIT_FROM, from).commit()
        }
        return ((from + waitMs - now).coerceAtLeast(0L) + 999).div(1000).toInt()
    }

    /** PBKDF2 at 600k iterations: always run on [cpu], never the UI thread. */
    private fun tryPin(c: Context, pin: String): Boolean {
        if (waitSeconds(c) > 0) return false
        val p = prefs(c)
        if (verify(c, pin)) {
            p.edit().remove(KEY_FAILED).remove(KEY_WAIT_FROM).remove(KEY_WAIT_MS).remove(KEY_WAIT_WALL).commit()
            return true
        }
        val failed = p.getInt(KEY_FAILED, 0) + 1
        val e = p.edit().putInt(KEY_FAILED, failed)
        if (failed >= FREE_ATTEMPTS) {
            e.putLong(KEY_WAIT_FROM, SystemClock.elapsedRealtime())
                .putLong(KEY_WAIT_WALL, System.currentTimeMillis())
                .putLong(KEY_WAIT_MS, 30_000L shl (failed - FREE_ATTEMPTS).coerceAtMost(5))
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
            dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { btn ->
                val wait = waitSeconds(a)
                if (wait > 0) {
                    Toast.makeText(a, a.getString(R.string.pin_wait_fmt, wait), Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                // PBKDF2 off the UI thread; the button waits for the result.
                btn.isEnabled = false
                val pin = input.text.toString()
                cpu.execute {
                    val ok = tryPin(a, pin)
                    a.runOnUiThread {
                        btn.isEnabled = true
                        if (ok) { unlocked = true; dlg.dismiss(); onOk() }
                        else {
                            input.text.clear()
                            Toast.makeText(a, R.string.pin_wrong, Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }
        }
        dlg.show()
        return dlg
    }

    /** Set or change the PIN. Asks for the current one if set. [mandatory]: first PIN, the screen stays hidden
     *  until one is saved (Exit closes the app); [onSaved] runs after that. */
    fun showSettings(a: Activity, mandatory: Boolean = false, onSaved: () -> Unit = {}): AlertDialog {
        val has = hasPin(a)
        val cur = field(a, R.string.pin_current_hint)
        val new = field(a, R.string.pin_new_hint)
        val box = LinearLayout(a).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 16, 48, 0)
            if (has) addView(cur)
            addView(new)
        }
        val builder = AlertDialog.Builder(a)
            .setTitle(R.string.pin_settings_title)
            .setMessage(if (has) R.string.pin_change_msg else R.string.pin_set_msg)
            .setView(box)
            .setPositiveButton(android.R.string.ok, null)
        if (mandatory) builder.setCancelable(false).setNegativeButton(R.string.pin_exit) { _, _ -> a.finish() }
        else builder.setNegativeButton(android.R.string.cancel, null)
        val dlg = builder.create()
        dlg.setOnShowListener {
            dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { btn ->
                val n = new.text.toString()
                // PBKDF2 off the UI thread (same worker as showUnlock).
                btn.isEnabled = false
                val curPin = cur.text.toString()
                cpu.execute {
                    val curOk = !has || tryPin(a, curPin)
                    if (curOk && n.length >= MIN_LEN) setPin(a, n)
                    a.runOnUiThread {
                        btn.isEnabled = true
                        if (!curOk) {
                            Toast.makeText(a, R.string.pin_wrong, Toast.LENGTH_SHORT).show()
                            return@runOnUiThread
                        }
                        if (n.length < MIN_LEN) {
                            Toast.makeText(a, a.getString(R.string.pin_too_short_fmt, MIN_LEN), Toast.LENGTH_SHORT).show()
                            return@runOnUiThread
                        } else {
                            unlocked = true
                            Toast.makeText(a, R.string.pin_saved, Toast.LENGTH_SHORT).show()
                        }
                        dlg.dismiss()
                        onSaved()
                    }
                }
            }
        }
        dlg.show()
        return dlg
    }
}
