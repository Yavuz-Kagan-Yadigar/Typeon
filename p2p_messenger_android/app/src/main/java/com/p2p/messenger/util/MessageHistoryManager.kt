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
    // A key file that exists but cannot be decrypted is never regenerated: a new key would make the old history unreadable.
    // A new key is generated only when the file does not exist.

    private const val HISTORY_KEY_FILENAME = "history_key.enc"

    private fun keyFile(context: Context): File =
        File(context.filesDir, HISTORY_KEY_FILENAME)

    /**
     * Called on every app start. If the key file does not exist, it generates a new data key, encrypts it and writes it to disk.
     * If it exists, it decrypts it and loads it into Rust.
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
                // Never regenerate here (see the note above the key file name).
                com.p2p.messenger.util.Log.e(TAG, "Key could not be decrypted, NOT REGENERATING", e)
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
