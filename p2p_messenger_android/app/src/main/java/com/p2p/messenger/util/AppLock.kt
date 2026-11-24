package com.p2p.messenger.util

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.util.Base64
import com.p2p.messenger.ui.AppLockActivity
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * A password that opens the app.
 *
 * The password itself is stored nowhere. A PBKDF2-HMAC-SHA256 derivation with a random salt is stored instead.
 * That stops someone with access to device memory from reading the password directly, and a high iteration count
 * makes guessing expensive. This lock is a layer SEPARATE from the end-to-end encryption of the app: identity and
 * ratchet keys are already protected by the Android Keystore (see `KeystoreCrypto`). This screen is an interface-level
 * barrier against someone who picks up the phone.
 *
 * The password must never be empty. So neither the first setup (`AppLockActivity` CREATE mode) nor a change
 * (SettingsFragment) accepts an empty value, and there is no way to remove the password entirely.
 */
object AppLock {
    private const val PREFS_NAME = "p2p_settings"
    private const val KEY_SALT = "app_lock_salt"
    private const val KEY_HASH = "app_lock_hash"
    private const val KEY_ITERATIONS = "app_lock_iterations"

    /** The old fixed value was 120,000. That was the OWASP recommendation around 2018, and modern GPU and ASIC guessing
     *  makes it weak. 600,000 is the current OWASP guidance for PBKDF2-HMAC-SHA256. The native (ring) path in `derive`
     *  keeps the unlock delay acceptable even on slow tablets.
     *
     *  Raising the constant must NOT lock out existing installs. The iteration count a hash was derived with is stored
     *  separately in `KEY_ITERATIONS` (see `setPassword` / `verify`). If an old record has no such field, the old constant
     *  (120,000) is assumed. Every new `setPassword` call writes the current constant. So the password gets stronger
     *  silently the next time the user changes it, and the existing password does not break. */
    private const val ITERATIONS = 600_000
    /** See the `ITERATIONS` docs. This is the iteration count the records already written to disk were derived with,
     *  before that constant is raised. */
    private const val LEGACY_ITERATIONS = 120_000
    private const val KEY_LENGTH_BITS = 256
    /** The hash sits in SharedPreferences; on a rooted phone it can be guessed offline, so short passwords fall fast.
     *  Only new passwords are checked; an existing shorter one keeps working until it is changed. */
    const val MIN_PASSWORD_LENGTH = 8

    /** Lock state for the life of the process. NOT written to disk. When the process dies, or the app goes to the
     *  background and `lock()` is called, the password is asked again. */
    @Volatile private var unlocked = false

    /** See `beginTrustedExcursion`. The first background transition after this time (elapsedRealtime) passes without
     *  locking. The timestamp is used, not a plain flag. See `TRUSTED_EXCURSION_WINDOW_MS`. */
    @Volatile private var excursionValidUntil = 0L

    /**
     * How long a "trusted exit" marker stays valid.
     *
     * A user report said the app opened without a password when a notification was tapped. The cause was that the marker
     * had no time limit. `beginTrustedExcursion()` was called, but the expected external screen never opened. An example:
     * the POST_NOTIFICATIONS permission was denied twice on Android 13+. `launch()` then does not show the system dialog
     * any more, it denies at once, and the app never goes to the background. The marker stayed set, and the NEXT real
     * background transition (the user pressing Home) went through without a lock. After that the app stayed unlocked, and
     * opening from a notification did not ask for the password.
     *
     * The time window closes this structurally. An activity we really started sends us to the background within
     * milliseconds. A marker for a screen that never opened expires by itself.
     */
    private const val TRUSTED_EXCURSION_WINDOW_MS = 5_000L
    private const val MAX_EXCURSION_MS = 60_000L  // was 3 min; same as BACKGROUND_LOCK_MS
    @Volatile private var excursionLeftAt = 0L

    /** If the app stays in the background longer than this, the password is asked (the screen locks at once, see `lockNow`).
     *  Short transitions do not ask. */
    private const val BACKGROUND_LOCK_MS = 60_000L
    @Volatile private var backgroundedAt = 0L

    fun hasPassword(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.contains(KEY_HASH) && prefs.contains(KEY_SALT)
    }

    /** Returns `false` and writes NOTHING if the password is empty. See the class note. */
    fun setPassword(context: Context, password: String): Boolean {
        if (password.isBlank() || password.length < MIN_PASSWORD_LENGTH) return false
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val hash = derive(password, salt, ITERATIONS)
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(KEY_HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
            .putInt(KEY_ITERATIONS, ITERATIONS)
            .apply()
        return true
    }

    /**
     * `MessageDigest.isEqual` is a constant-time comparison. A plain `==` (or `contentEquals`) returns at the first
     * differing byte, and in theory that leaks timing information.
     */
    fun verify(context: Context, password: String): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saltB64 = prefs.getString(KEY_SALT, null) ?: return false
        val hashB64 = prefs.getString(KEY_HASH, null) ?: return false
        // See the `ITERATIONS` docs. This field is absent in a record written BEFORE the current constant was raised, so
        // that record must have been derived with the old constant (120,000). Otherwise every old install's password would
        // break with this update.
        val iterations = if (prefs.contains(KEY_ITERATIONS)) prefs.getInt(KEY_ITERATIONS, ITERATIONS) else LEGACY_ITERATIONS
        return try {
            val expected = Base64.decode(hashB64, Base64.NO_WRAP)
            val actual = derive(password, Base64.decode(saltB64, Base64.NO_WRAP), iterations)
            try { MessageDigest.isEqual(expected, actual) } finally { actual.fill(0) }
        } catch (e: Exception) {
            false
        }
    }

    private fun derive(password: String, salt: ByteArray, iterations: Int): ByteArray {
        // Native (ring) path: same output, much faster than Java. On a Samsung Tab A8 the Java unlock took 4-8 seconds.
        // Java is the fallback if the library cannot be loaded.
        try {
            val out = com.p2p.messenger.P2PLib.pbkdf2Sha256(password, salt, iterations, KEY_LENGTH_BITS / 8)
            if (out.size == KEY_LENGTH_BITS / 8) return out
        } catch (e: Throwable) {
        }
        val chars = password.toCharArray()
        val spec = PBEKeySpec(chars, salt, iterations, KEY_LENGTH_BITS)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
            chars.fill('\u0000')
        }
    }

    fun isUnlocked(): Boolean = unlocked

    fun markUnlocked() {
        unlocked = true
    }

    /** Failed attempts are stored, so a force stop does not reset them. The wait is measured with elapsed time since boot.
     *  The wall clock is used only to re-anchor the wait after a reboot (see `retryWaitSeconds`). */
    private const val FREE_ATTEMPTS = 5
    private const val KEY_FAILED_ATTEMPTS = "app_lock_failed_attempts"
    private const val KEY_WAIT_FROM = "app_lock_wait_from_elapsed"
    private const val KEY_WAIT_MS = "app_lock_wait_ms"
    private const val KEY_WAIT_WALL = "app_lock_wait_wall"

    /** Seconds until the next attempt is allowed. 0 = now. */
    fun retryWaitSeconds(context: Context): Int {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val waitMs = prefs.getLong(KEY_WAIT_MS, 0L)
        if (waitMs <= 0L) return 0
        val now = SystemClock.elapsedRealtime()
        var from = prefs.getLong(KEY_WAIT_FROM, 0L)
        if (now < from) {
            // After a reboot the time since boot restarts. Re-anchor from the wall clock saved at the failure, so the reboot
            // does not refund the wait. But credit no more than the uptime since boot: a clock set forward before opening the
            // app must not skip the wait.
            val wallPassed = (System.currentTimeMillis() - prefs.getLong(KEY_WAIT_WALL, 0L)).coerceIn(0L, minOf(waitMs, now))
            from = now - wallPassed
            prefs.edit().putLong(KEY_WAIT_FROM, from).apply()
        }
        return ((from + waitMs - now).coerceAtLeast(0L) + 999).div(1000).toInt()
    }

    /** After [FREE_ATTEMPTS] wrong passwords: 30 s, doubling up to 16 min. */
    fun noteFailedAttempt(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val failed = prefs.getInt(KEY_FAILED_ATTEMPTS, 0) + 1
        val over = failed - FREE_ATTEMPTS
        val edit = prefs.edit().putInt(KEY_FAILED_ATTEMPTS, failed)
        if (over >= 0) {
            edit.putLong(KEY_WAIT_FROM, SystemClock.elapsedRealtime())
                .putLong(KEY_WAIT_WALL, System.currentTimeMillis())
                .putLong(KEY_WAIT_MS, 30_000L shl over.coerceAtMost(5))
        }
        // Synchronous: a process killed right after a wrong guess must still count it.
        edit.commit()
    }

    /** Password check for flows outside the lock screen (password change). It applies the same wait and failure counting as the
     *  prompt. Returns false while waiting. */
    fun verifyThrottled(context: Context, password: String): Boolean {
        if (retryWaitSeconds(context) > 0) return false
        val ok = verify(context, password)
        if (ok) clearFailedAttempts(context) else noteFailedAttempt(context)
        return ok
    }

    fun clearFailedAttempts(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .remove(KEY_FAILED_ATTEMPTS).remove(KEY_WAIT_FROM).remove(KEY_WAIT_MS).remove(KEY_WAIT_WALL).apply()
    }

    /**
     * A user report: "after the internal file picker or the camera for a message, don't ask for the password."
     *
     * The problem is structural. The system file picker (SAF / DocumentsUI), the runtime permission dialog, external viewers
     * and system settings screens are activities in OTHER processes. When they open, all of OUR activities get `onStop`, the
     * started-activity count drops to 0, and `lock()` fires. The user never left the app, so asking for the password on
     * return is a plain bug.
     *
     * So every call site that hands control to an outside screen (see where this function is called) announces it first,
     * and the NEXT single background transition is not locked.
     *
     * KNOWN LIMIT: if the user presses Home while the picker or permission screen is open, the flag is already used up. Our
     * activities have stopped at that point, and no second `onStop` arrives. So the password is not asked on that return
     * either. The lock then applies only on the NEXT real background transition. Closing this would need to know which
     * activity is in front, and Android deliberately does not give apps that. This is a deliberate trade: a wrong lock is a
     * frequent and visible error, and this gap is rarer.
     */
    fun beginTrustedExcursion() {
        excursionValidUntil = SystemClock.elapsedRealtime() + TRUSTED_EXCURSION_WINDOW_MS
    }

    /** Our screen was covered within the window (a chooser or a dialog of another app). The excursion holds until our screen
     *  comes back, however long the user takes to pick an app there. */
    @Volatile private var excursionCovered = false

    fun excursionPaused() {
        val validUntil = excursionValidUntil
        if (validUntil != 0L && SystemClock.elapsedRealtime() < validUntil) excursionCovered = true
    }

    /** Our screen is back without the app having left: the excursion ended. */
    fun excursionResumed() {
        excursionCovered = false
    }

    /** See P2PApplication.onActivityStopped. Called when the app goes fully to the background. */
    fun lock() {
        val validUntil = excursionValidUntil
        val covered = excursionCovered
        excursionValidUntil = 0L
        excursionCovered = false
        // `elapsedRealtime`, not the wall clock. The window cannot move even if the user or the network changes the clock.
        val inWindow = validUntil != 0L && SystemClock.elapsedRealtime() < validUntil
        if (covered || inWindow) {
            excursionLeftAt = SystemClock.elapsedRealtime()
            // Left later from a chooser: the user may have gone Home from it, so the usual background timeout applies, not
            // the long excursion one.
            excursionLimitMs = if (inWindow) MAX_EXCURSION_MS else BACKGROUND_LOCK_MS
            return
        }
        backgroundedAt = SystemClock.elapsedRealtime()
    }

    /** Screen off: lock at once, with no delay. */
    fun lockNow(context: Context?) {
        if (!unlocked) return
        unlocked = false
        if (context == null) return
        val leftAt = excursionLeftAt
        if (leftAt == 0L) {
            purgePlainCache(context)
            return
        }
        // An external viewer may still have a decrypted file open. Purge when the user comes back (`guard`), at the latest
        // when the excursion would have timed out anyway.
        purgePending = true
        purgeContext = context.applicationContext
        val wait = (leftAt + excursionLimitMs - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
        mainHandler.removeCallbacks(purgeLater)
        mainHandler.postDelayed(purgeLater, wait)
    }

    /** `lockNow` during a trusted excursion: the purge waits for the excursion to end. */
    @Volatile private var purgePending = false
    @Volatile private var purgeContext: Context? = null
    @Volatile private var excursionLimitMs = MAX_EXCURSION_MS
    private val mainHandler by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }
    private val purgeLater = Runnable {
        val context = purgeContext
        if (purgePending && context != null) {
            purgePending = false
            purgePlainCache(context)
        }
    }

    /** Decrypted attachment copies do not outlive the unlocked session. This happens only where the lock really engages.
     *  A trusted excursion (picker, external viewer) keeps `unlocked`, so the file it has open stays. */
    private fun purgePlainCache(context: Context) {
        if (!hasPassword(context)) return
        // Off the main thread: deleting large decrypted videos takes time. File names are unique, so order does not matter.
        val files = context.filesDir
        val cache = context.cacheDir
        Thread {
            java.io.File(files, "attachments/plain_cache").listFiles()?.forEach { it.deleteRecursively() }
            // Decrypted full-screen avatar copies (AvatarUtil.openFullscreen).
            java.io.File(cache, "avatar_view").listFiles()?.forEach { it.deleteRecursively() }
        }.start()
    }

    /**
     * Called from `onActivityStarted` of EVERY activity (see P2PApplication). It is not only in MainActivity,
     * so that opening ChatActivity straight from a notification cannot skip the lock.
     *
     * If no password has been set yet, the same screen opens in CREATE mode. A state with no password cannot be permanent:
     * the user must set one.
     */
    fun guard(activity: Activity) {
        // The call screen works like a phone call: answer or decline without the app password. Since the app locks on
        // screen-off, the password prompt would otherwise cover every incoming call. Everything else stays guarded.
        if (activity is AppLockActivity) return
        // If a trusted navigation deferred the lock, and the user pressed Home from the picker and came back a long time later,
        // the app must open locked. Otherwise it would stay unlocked forever.
        val wasUnlocked = unlocked
        val leftAt = excursionLeftAt
        if (leftAt != 0L) {
            excursionLeftAt = 0L
            if (SystemClock.elapsedRealtime() - leftAt > excursionLimitMs) unlocked = false
        }
        val bgAt = backgroundedAt
        backgroundedAt = 0L
        if (bgAt != 0L && SystemClock.elapsedRealtime() - bgAt > BACKGROUND_LOCK_MS) unlocked = false
        if ((wasUnlocked && !unlocked) || purgePending) {
            purgePending = false
            mainHandler.removeCallbacks(purgeLater)
            purgePlainCache(activity)
        }
        // After the timeouts above. Skipping them here let the call screen's own stop renew `backgroundedAt`, so the app opened
        // without the password for a minute after any call.
        if (activity is com.p2p.messenger.ui.CallActivity) return
        // The screen under the prompt is drawn for a moment before the prompt covers it. Its content stays hidden until the
        // password is entered.
        activity.findViewById<android.view.View>(android.R.id.content)?.visibility =
            if (unlocked) android.view.View.VISIBLE else android.view.View.INVISIBLE
        if (unlocked) return
        // No "already showing" short-circuit: an activity started over the prompt (a notification with CLEAR_TOP) would finish
        // it and stay open unlocked. SINGLE_TOP keeps a prompt that is already on top from stacking.
        activity.startActivity(
            Intent(activity, AppLockActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NO_ANIMATION)
        )
    }
}
