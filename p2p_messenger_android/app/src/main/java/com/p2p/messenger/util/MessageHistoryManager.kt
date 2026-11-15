package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.P2PLib
import java.io.File
import java.security.SecureRandom

/**
 * Manages the encryption key of the message history archive. It is ALWAYS loaded, regardless of node mode (see the P2PService onStartCommand note).
 *
 * Before, both loading this key AND archiving live message traffic happened ONLY while node mode was on (a user preference for the device that
 * prefers to act as a server). The user has since asked for the local chat history to be kept encrypted on EVERY device, node mode or not. Node
 * mode now affects ONLY helping peers with `HistorySyncRequest` replies (see receive.rs receive_message) and DHT routing participation. It no
 * longer decides whether this device keeps its own history (see the archive.rs `archive_message` callers, which no longer check `node_mode_enabled`).
 *
 * The key lifecycle follows the same pattern as IdentityManager:
 * - On first start, a random 256-bit history data key is generated. It is encrypted with a SEPARATE wrap key in the Keystore and written to disk.
 * - On every start, it is decrypted and loaded into Rust with `setHistoryKey`.
 * - A plaintext data key never exists on disk.
 */
object MessageHistoryManager {
    private const val TAG = "MessageHistoryManager"
    // On a DECRYPT ERROR the key is NOT regenerated.
    //
    // This used to call `generateAndPersist` when the file existed but decryption threw. That OVERWROTE the key file with a fresh random key. It
    // treated "no key" and "the key could not be decrypted this time" as the same thing. A single temporary Keystore failure (a device restored from
    // backup, a lock-screen change that reset the credential, a StrongBox fault) then destroyed everything encrypted with that key, irreversibly, and
    // the user saw no warning. The sibling classes (`ArchiveKeyManager`, `IdentityManager`) already behaved correctly: on a decrypt failure they only
    // return. Regeneration now happens ONLY when the file does not exist at all.

    private const val HISTORY_KEY_FILENAME = "history_key.enc"

    private fun keyFile(context: Context): File =
        File(context.filesDir, HISTORY_KEY_FILENAME)

    /**
     * Called whenever the app starts while node mode is on (or the first time node mode is turned on). If the key file does not exist, it generates
     * a new data key, encrypts it and writes it to disk. If it exists, it decrypts it and loads it into Rust.
     */
    @Synchronized
    fun ensureHistoryKeyLoaded(context: Context) {
        val file = keyFile(context)

        val dataKey: ByteArray = if (file.exists()) {
            val encrypted = try {
                file.readBytes()
            } catch (e: Exception) {
                return
            }
            try {
                KeystoreCrypto.decrypt(encrypted, KeystoreCrypto.ALIAS_HISTORY)
            } catch (e: Exception) {
                // See the TAG note (#04). NEVER regenerate here.
                com.p2p.messenger.util.Log.e(TAG, "Anahtar cozulemedi, YENIDEN URETILMIYOR", e)
                KeystoreCrypto.reportKeyFailure(context)
                return
            }
        } else {
            generateAndPersist(context)
            return
        }

        try {
            P2PLib.setHistoryKey(dataKey)
        } finally {
            dataKey.fill(0)
        }
    }

    private fun generateAndPersist(context: Context) {
        val dataKey = ByteArray(32)
        SecureRandom().nextBytes(dataKey)
        try {
            val encrypted = KeystoreCrypto.encrypt(dataKey, KeystoreCrypto.ALIAS_HISTORY)
            keyFile(context).writeBytesAtomic(encrypted)
            P2PLib.setHistoryKey(dataKey)
        } catch (e: Exception) {
            // Keystore or disk failure: this runs on unguarded start-up
            // paths and took the process down before the network started.
            com.p2p.messenger.util.Log.e(TAG, "Anahtar uretilemedi", e)
        } finally {
            dataKey.fill(0)
        }
    }
}
