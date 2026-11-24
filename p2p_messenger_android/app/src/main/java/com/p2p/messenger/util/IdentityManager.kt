package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.P2PLib
import java.io.File

/**
 * Manages the identity lifecycle. At first creation it encrypts the secret key bundle with the Keystore and writes it to disk. At later starts it
 * decrypts it and loads it back into the Rust core.
 *
 * Only KeystoreCrypto.encrypt output (AES-256-GCM ciphertext, under a key held in the Android Keystore / StrongBox) is on disk. A plaintext secret key
 * is never written to disk. Another app cannot read this file without root. Even with root, without the Keystore key (held in the hardware security module,
 * and not exportable) the content is meaningless ciphertext.
 */
object IdentityManager {
    private const val SECRET_BUNDLE_FILENAME = "identity_secret.enc"

    /**
     * The bundle is loaded ONCE. `P2PApplication` (when the Activity is created) and `MainActivity` both ask for it on every cold start. Each request read the file
     * again and decrypted it again in the Keystore, and reloaded it into Rust. That happened in the window most sensitive to ANRs during process start.
     * Only a SUCCESSFUL load is remembered. A failed load must stay retryable (the recovery file flow).
     */
    @Volatile
    private var loaded = false

    private fun secretBundleFile(context: Context): File =
        File(context.filesDir, SECRET_BUNDLE_FILENAME)

    /**
     * Called at app start (after initDatabase). If the DB has an identity but the Rust side does not have its secret keys in memory yet
     * (`hasStoredIdentity() == true`, but ratchet and signing operations are not possible yet), it reads the encrypted bundle from disk, decrypts it and loads it
     * into Rust. If the file is missing or damaged, it returns false. That means identity_secret.enc is lost or corrupt, and a restore from the recovery file is needed
     * (section 1.8).
     *
     * The result is remembered for the whole process. Loading the same bundle a second time (Keystore decrypt, file read, `loadSecretBundle`) is not needed.
     */
    @Synchronized
    fun loadIfPresent(context: Context): Boolean {
        if (loaded) return true
        val file = secretBundleFile(context)
        if (!file.exists()) return false

        val encrypted = try {
            file.readBytes()
        } catch (e: Exception) {
            return false
        }

        val plaintext = try {
            KeystoreCrypto.decrypt(encrypted)
        } catch (e: Exception) {
            // The Keystore key may be lost or corrupt (for example, after a factory reset the Keystore was cleared but the file stayed). In that case a
            // restore from the recovery file is needed.
            return false
        }

        val ok = try {
            P2PLib.loadSecretBundle(plaintext)
        } finally {
            plaintext.fill(0)  // wipe to avoid leaving traces in memory
        }
        if (ok) loaded = true
        return ok
    }

    /**
     * Must be called RIGHT AFTER createIdentity(). It takes the plaintext secret bundle that Rust generated, encrypts it with the Keystore, and writes it to disk.
     *
     * RETURN: `true` = the bundle was written to disk. `false` = it could NOT be written (the core had no pending bundle). When the caller gets `false`, it must not
     * continue as if the identity was created. The secret keys are not on disk, so that identity cannot be loaded at the next start.
     */
    fun persistNewIdentity(context: Context): Boolean {
        val plaintext = P2PLib.getPendingSecretBundle()
        if (plaintext.isEmpty()) return false
        try {
            val encrypted = KeystoreCrypto.encrypt(plaintext)
            secretBundleFile(context).writeBytesAtomic(encrypted)
        } catch (e: Exception) {
            // Keystore or disk failure: "not written", as documented.
            return false
        } finally {
            plaintext.fill(0)
        }
        return true
    }
}
