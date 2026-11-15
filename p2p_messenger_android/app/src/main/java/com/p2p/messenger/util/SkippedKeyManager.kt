package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.P2PLib
import java.io.File
import java.security.SecureRandom

/**
 * Manages the key that keeps the skipped-message-key cache (the Double Ratchet's support for out-of-order and late messages) persisted on disk, encrypted.
 * Unlike `MessageHistoryManager`, this key is ALWAYS loaded, regardless of node mode. It is a mechanism needed for messaging reliability, not an optional archive.
 *
 * The key lifecycle follows the same pattern (consistent with IdentityManager and MessageHistoryManager): a random 256-bit data key is generated, encrypted with
 * a SEPARATE wrap key in the Keystore (ALIAS_SKIPPED_KEYS), and written to disk. On every start it is decrypted and loaded into Rust. A plaintext key never
 * exists on disk.
 */
object SkippedKeyManager {
    private const val TAG = "SkippedKeyManager"
    // On a DECRYPT ERROR the key is NOT regenerated.
    //
    // This used to call `generateAndPersist` when the file existed but decryption threw. That OVERWROTE the key file with a fresh random key. It
    // treated "no key" and "the key could not be decrypted this time" as the same thing. A single temporary Keystore failure (a device restored from
    // backup, a lock-screen change that reset the credential, a StrongBox fault) then destroyed everything encrypted with that key, irreversibly, and
    // the user saw no warning. The sibling classes (`ArchiveKeyManager`, `IdentityManager`) already behaved correctly: on a decrypt failure they only
    // return. Regeneration now happens ONLY when the file does not exist at all.

    private const val KEY_FILENAME = "skipped_key_enc.enc"

    private fun keyFile(context: Context): File =
        File(context.filesDir, KEY_FILENAME)

    /** Must be called every time the app starts (after initDatabase), regardless of node mode. */
    @Synchronized
    fun ensureLoaded(context: Context) {
        val existed = keyFile(context).exists()
        val dataKey = loadOrCreate(context.filesDir)
        if (dataKey == null) {
            if (existed) KeystoreCrypto.reportKeyFailure(context)
            return
        }
        try {
            P2PLib.setSkippedKeyEncryptionKey(dataKey)
        } finally {
            dataKey.fill(0)
        }
    }

    /** The database is encrypted under this key, so it is needed before the
     *  database opens. Only through [P2PLib.initDatabase]. Same lock as
     *  [ensureLoaded]: two first starts must not make two keys. */
    @Synchronized
    fun openDatabase(filesDir: File): Boolean {
        val dataKey = loadOrCreate(filesDir) ?: return false
        try {
            return P2PLib.initDatabaseKeyed(filesDir.absolutePath, dataKey)
        } finally {
            dataKey.fill(0)
        }
    }

    /** `null`: the key file could not be read or decrypted (it is NOT made
     *  again then, see #04 above), or a first key could not be stored. */
    private fun loadOrCreate(filesDir: File): ByteArray? {
        val file = File(filesDir, KEY_FILENAME)
        if (file.exists()) {
            return try {
                KeystoreCrypto.decrypt(file.readBytes(), KeystoreCrypto.ALIAS_SKIPPED_KEYS)
            } catch (e: Exception) {
                com.p2p.messenger.util.Log.e(TAG, "Key could not be decrypted, NOT REGENERATING", e)
                null
            }
        }
        val dataKey = ByteArray(32)
        SecureRandom().nextBytes(dataKey)
        return try {
            file.writeBytesAtomic(KeystoreCrypto.encrypt(dataKey, KeystoreCrypto.ALIAS_SKIPPED_KEYS))
            dataKey
        } catch (e: Exception) {
            // Keystore or disk failure: this runs on unguarded start-up
            // paths and took the process down before the network started.
            com.p2p.messenger.util.Log.e(TAG, "Anahtar uretilemedi", e)
            dataKey.fill(0)
            null
        }
    }
}
