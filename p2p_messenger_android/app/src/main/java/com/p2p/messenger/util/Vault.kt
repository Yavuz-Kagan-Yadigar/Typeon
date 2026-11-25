package com.p2p.messenger.util

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.p2p.messenger.MainActivity
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import java.io.File
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The vault key binds every stored secret to the app password, so a rooted attacker or a copy of the app data
 * cannot open them with the Keystore alone.
 *
 * Every blob [KeystoreCrypto] writes is sealed twice: first with this random 256-bit vault key (AES-GCM), then
 * with the Keystore key. The vault key itself is in `vault.enc`, sealed with a key derived from the app password
 * (Argon2id, [P2PLib.argon2idKey]) and then with its own Keystore key. A root user who can use the app's Keystore
 * keys still needs the password, and has to guess it at Argon2id cost per try.
 *
 * The vault key lives only in this process's memory. After a reboot or a process kill, nothing can be decrypted
 * until the password is entered again: the database stays closed and no messages are received. [showUnlockPrompt]
 * puts up a full-screen prompt so the user unlocks at once.
 *
 * Limit: an attacker with root while the app is unlocked can read the key from process memory. No app-level
 * measure stops that.
 *
 * File: `salt(16) || m_kib(4) || t(4) || keystore( iv(12) || AES-GCM_kek(vaultKey), aad = header )`.
 */
object Vault {
    private const val FILE = "vault.enc"
    private const val SALT_LEN = 16
    private const val HEADER_LEN = SALT_LEN + 8
    /** 64 MiB, 3 passes: about a second on a slow phone, and memory-hard against GPU guessing. */
    private const val M_KIB = 64 * 1024
    private const val T_COST = 3
    private const val TAG_BITS = 128
    private const val UNLOCK_CHANNEL_ID = "P2PUnlockChannel"
    private const val UNLOCK_NOTIFICATION_ID = 0x7a017

    @Volatile private var key: ByteArray? = null
    private val opened = MutableStateFlow(false)

    private fun file(context: Context) = File(context.applicationContext.filesDir, FILE)

    fun exists(context: Context): Boolean = file(context).exists()

    fun isOpen(): Boolean = key != null

    /** Suspends until the vault is open. */
    suspend fun awaitOpen() {
        opened.first { it }
    }

    /** Runs [block] once the vault is open (at once if it already is), on the opening thread. */
    fun whenOpen(block: () -> Unit) {
        synchronized(waiters) {
            if (key == null) { waiters.add(block); return }
        }
        block()
    }
    private val waiters = mutableListOf<() -> Unit>()

    /** The vault key, for [KeystoreCrypto]. Throws while locked. */
    internal fun keyOrThrow(): ByteArray = key ?: throw VaultLockedException()

    /**
     * First password. An install from before the vault (wrapped keys without the vault layer) cannot be read any
     * more, so it is wiped first: the user starts fresh (owner decision, no migration).
     */
    @Synchronized
    fun create(context: Context, password: String): Boolean {
        if (exists(context)) return false
        val app = context.applicationContext
        if (hasPreVaultState(app)) {
            LocalWipe.wipe(app)
            LocalWipe.finishPending(app)
        }
        val vaultKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        if (!write(app, password, vaultKey)) {
            vaultKey.fill(0)
            return false
        }
        install(app, vaultKey)
        return true
    }

    /** Checks [password]. On success the vault is open (if it was not already). */
    @Synchronized
    fun open(context: Context, password: String): Boolean {
        val app = context.applicationContext
        if (checkTamper(app)) return false
        val candidate = read(app, password) ?: return false
        val current = key
        if (current != null) {
            val same = java.security.MessageDigest.isEqual(current, candidate)
            candidate.fill(0)
            return same
        }
        install(app, candidate)
        return true
    }

    /** New password for the open vault. The vault key stays, so nothing else is re-encrypted. */
    @Synchronized
    fun changePassword(context: Context, newPassword: String): Boolean {
        val current = key ?: return false
        return write(context.applicationContext, newPassword, current)
    }

    private fun install(app: Context, vaultKey: ByteArray) {
        val run: List<() -> Unit>
        synchronized(waiters) {
            key = vaultKey
            run = waiters.toList()
            waiters.clear()
        }
        opened.value = true
        cancelUnlockPrompt(app)
        run.forEach { try { it() } catch (e: Exception) { Log.w("Vault", "open callback: ${e.message}") } }
    }

    private fun hasPreVaultState(app: Context): Boolean =
        listOf("identity_secret.enc", "skipped_key_enc.enc").any { File(app.filesDir, it).exists() }

    private fun header(salt: ByteArray, mKib: Int, t: Int): ByteArray =
        ByteBuffer.allocate(HEADER_LEN).put(salt).putInt(mKib).putInt(t).array()

    private fun write(app: Context, password: String, vaultKey: ByteArray): Boolean {
        val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        val kek = P2PLib.argon2idKey(password, salt, M_KIB, T_COST)
        if (kek.size != 32) return false
        return try {
            val header = header(salt, M_KIB, T_COST)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(kek, "AES"))
            cipher.updateAAD(header)
            val inner = cipher.iv + cipher.doFinal(vaultKey)
            file(app).writeBytesAtomic(header + KeystoreCrypto.keystoreEncrypt(inner, KeystoreCrypto.ALIAS_VAULT))
            true
        } catch (e: Exception) {
            Log.e("Vault", "vault could not be written", e)
            false
        } finally {
            kek.fill(0)
        }
    }

    private fun read(app: Context, password: String): ByteArray? {
        val bytes = try { file(app).readBytes() } catch (e: Exception) { return null }
        if (bytes.size <= HEADER_LEN) return null
        val buf = ByteBuffer.wrap(bytes)
        val salt = ByteArray(SALT_LEN).also { buf.get(it) }
        val mKib = buf.int
        val t = buf.int
        val kek = P2PLib.argon2idKey(password, salt, mKib, t)
        if (kek.size != 32) return null
        return try {
            val inner = KeystoreCrypto.keystoreDecrypt(bytes.copyOfRange(HEADER_LEN, bytes.size), KeystoreCrypto.ALIAS_VAULT)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(kek, "AES"), GCMParameterSpec(TAG_BITS, inner, 0, 12))
            cipher.updateAAD(bytes.copyOfRange(0, HEADER_LEN))
            cipher.doFinal(inner, 12, inner.size - 12).takeIf { it.size == 32 }
        } catch (e: Exception) {
            null  // wrong password (tag mismatch) or a Keystore failure
        } finally {
            kek.fill(0)
        }
    }

    /**
     * A root attacker on a running phone reads keys out of memory or hooks the crypto calls with a debugger or a hooking
     * framework injected into this process. When one is seen ([P2PLib.tamperSigns]), the vault key is zeroed and the
     * process exits, so the core's keys leave memory too. The next start needs the password, and [open] refuses while the
     * tool is still there. Rooted phones as such are not refused. Release builds only: debug builds run under a debugger.
     * Best effort: a tool that hides from the checks is not seen.
     *
     * Returns true when tampering was found (the process is then exiting).
     */
    fun checkTamper(context: Context): Boolean {
        if (com.p2p.messenger.BuildConfig.DEBUG) return false
        val signs = try { P2PLib.tamperSigns() } catch (e: Throwable) { "" }
        if (signs.isEmpty()) return false
        val app = context.applicationContext
        synchronized(waiters) {
            key?.fill(0)
            key = null
        }
        try {
            val nm = app.getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(NotificationChannel(
                UNLOCK_CHANNEL_ID, app.getString(R.string.channel_unlock), NotificationManager.IMPORTANCE_HIGH))
            nm?.notify(UNLOCK_NOTIFICATION_ID, NotificationCompat.Builder(app, UNLOCK_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(app.getString(R.string.app_name))
                .setContentText(app.getString(R.string.msg_tamper_closed))
                .setStyle(NotificationCompat.BigTextStyle().bigText(app.getString(R.string.msg_tamper_closed)))
                .build())
        } catch (e: Exception) {}
        android.os.Process.killProcess(android.os.Process.myPid())
        return true
    }

    /**
     * The vault is closed but an account exists (after a reboot or a process kill). Shows a full-screen prompt:
     * on a locked or idle screen it opens the app's password screen at once, otherwise it is a heads-up
     * notification. Background activity starts are blocked from Android 10, a full-screen intent is the
     * allowed way. Cancelled when the vault opens.
     */
    fun showUnlockPrompt(context: Context) {
        val app = context.applicationContext
        if (isOpen() || !exists(app)) return
        val nm = app.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(NotificationChannel(
            UNLOCK_CHANNEL_ID, app.getString(R.string.channel_unlock), NotificationManager.IMPORTANCE_HIGH))
        val intent = Intent(app, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pending = PendingIntent.getActivity(app, UNLOCK_NOTIFICATION_ID, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val n = NotificationCompat.Builder(app, UNLOCK_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(app.getString(R.string.app_name))
            .setContentText(app.getString(R.string.msg_unlock_to_receive))
            .setCategory(NotificationCompat.CATEGORY_STATUS)  // ALARM made MIUI ring it like an alarm clock
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setOngoing(true)
            .setContentIntent(pending)
            .setFullScreenIntent(pending, true)
            .build()
        try { nm.notify(UNLOCK_NOTIFICATION_ID, n) } catch (e: SecurityException) { Log.w("Vault", "No notification permission") }
        // The full-screen intent opens the screen only on a locked or idle phone. With "Display over other apps" the
        // password screen opens at once on an unlocked phone too (a PIN phone learns of the boot only after its unlock).
        if (android.provider.Settings.canDrawOverlays(app)) {
            try { app.startActivity(intent) } catch (e: Exception) { Log.w("Vault", "Password screen not opened: ${e.message}") }
        }
    }

    private fun cancelUnlockPrompt(app: Context) {
        app.getSystemService(NotificationManager::class.java)?.cancel(UNLOCK_NOTIFICATION_ID)
    }
}

class VaultLockedException : java.security.GeneralSecurityException("vault locked")
