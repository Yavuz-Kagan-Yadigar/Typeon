package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.P2PLib
import java.io.File
import java.security.SecureRandom

/**
 * Manages the root archive key (ARK): the key that decrypts the message history stored on the server (see Rust `server_seal::seal_archive_record`).
 *
 * It uses the SAME Keystore pattern as `MessageHistoryManager`, but its SCOPE is different, and the difference matters:
 *
 * - `history_key`: belongs to the DEVICE. Random. NOT in the recovery file. It only encrypts the local SQLite archive on disk. If it is lost, only
 *   this device's local history becomes unreadable.
 * - ARK (this class): belongs to the IDENTITY. Every device of the same identity must be able to read the archive on the server. So it is passed to
 *   sibling devices with `DeviceSync` (ratchet-encrypted), and it is included in the recovery file. The device that created it first is the source.
 *   Devices linked later do not generate their own random key. They adopt the one from a sibling (the Rust side never overwrites an existing ARK).
 *
 * The honest trade-off: the ARK is NOT forward-secret. If it ever leaks, ALL history uploaded to the server up to that point can be read. Ratchet
 * ciphertext, by contrast, becomes unreadable once used. "I want to see my history on my new device" cannot be reconciled with forward secrecy
 * mathematically. So keeping history on the server is a SEPARATE option in Settings, and it is OFF by default.
 */
object ArchiveKeyManager {
    private const val ARCHIVE_KEY_FILENAME = "archive_root_key.enc"

    private fun keyFile(context: Context): File =
        File(context.filesDir, ARCHIVE_KEY_FILENAME)

    /**
     * Called at app start. If a key exists, it is decrypted and loaded into Rust.
     *
     * Unlike `MessageHistoryManager`, a key is NOT generated here if none exists (see `ensureCreated`). Reason: a device linked later that generated
     * its own random key before getting the ARK from its sibling would write an archive that the other devices could not read. Generation happens only
     * when the user turns on server-side history.
     */
    /** An ARK that came from a sibling device was held only in the core's memory, and was lost on restart. It is written to disk now, if the file does not exist yet. */
    @Synchronized
    fun persistIfNew(context: Context) {
        val file = keyFile(context)
        val key = try { P2PLib.archiveRootKey() } catch (e: Exception) { return }
        if (key.size != 32) return
        // Written again when the key changed: it is replaced when a device
        // is revoked.
        if (file.exists()) {
            val stored = try { KeystoreCrypto.decrypt(file.readBytes(), KeystoreCrypto.ALIAS_ARCHIVE_ROOT) } catch (e: Exception) { null }
            val same = stored != null && stored.contentEquals(key)
            stored?.fill(0)
            if (same) { key.fill(0); return }
        }
        try {
            file.writeBytesAtomic(KeystoreCrypto.encrypt(key, KeystoreCrypto.ALIAS_ARCHIVE_ROOT))
        } catch (e: Exception) {
        } finally {
            key.fill(0)
        }
    }

    @Synchronized
    fun loadIfPresent(context: Context) {
        val file = keyFile(context)
        if (!file.exists()) return
        val dataKey = try {
            KeystoreCrypto.decrypt(file.readBytes(), KeystoreCrypto.ALIAS_ARCHIVE_ROOT)
        } catch (e: Exception) {
            // The Keystore key is lost or corrupt. A new one is NOT generated. The archive on the server is encrypted with the old key, and a new key
            // would not recover it. It would only split the archive from this point on. The user can restore from the recovery file, or the key comes
            // back from a sibling device through `DeviceSync`.
            return
        }
        try {
            P2PLib.setArchiveRootKey(dataKey)
        } finally {
            dataKey.fill(0)
        }
    }

    /**
     * Called when server-side history is turned on. It generates the key if none exists.
     *
     * When the Rust side receives an ARK from a sibling device, it does not report it back to us. So the key generated here is correct only for "the first
     * device of this identity". If this is called on a device that already got a key from a sibling, the Rust side does not overwrite the existing one, but
     * the copy on disk can diverge. So the caller must call this only when the user turns history on, and only then.
     */
    @Synchronized
    fun ensureCreated(context: Context): Boolean {
        val file = keyFile(context)
        if (file.exists()) {
            loadIfPresent(context)
            return true
        }
        // A key that arrived from a sibling (`DeviceSync`) may be in memory. Write it, and do not generate a new one on top. Otherwise the archive would
        // be split across devices.
        val fromCore = try { P2PLib.archiveRootKey() } catch (e: Exception) { ByteArray(0) }
        // a failed read counts as secondary (fail closed, no random key).
        // A linked device waits for its sibling's key: one made here would
        // stay for good and split the archive between the devices.
        if (fromCore.size != 32 && try { P2PLib.isSecondaryDevice() } catch (e: Exception) { true }) return false
        val dataKey = if (fromCore.size == 32) fromCore else ByteArray(32).also { SecureRandom().nextBytes(it) }
        try {
            file.writeBytesAtomic(KeystoreCrypto.encrypt(dataKey, KeystoreCrypto.ALIAS_ARCHIVE_ROOT))
            P2PLib.setArchiveRootKey(dataKey)
            return true
        } catch (e: Exception) {
            // The Keystore is not reachable. Server routing (message delivery) is NOT affected by this. Only the history is not loaded. `false` is returned
            // so the caller does not show the key as available.
            return false
        } finally {
            dataKey.fill(0)
        }
    }
}
