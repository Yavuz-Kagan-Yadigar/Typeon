package com.p2p.messenger.util

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Envelope encryption layer. It keeps the local identity and device secret keys, and the message history archive, encrypted on disk.
 *
 * An AES-256 key is created and stored in the Android Keystore (in StrongBox hardware when available). That key NEVER leaves the Keystore.
 * The Cipher object runs inside the Keystore. The Keystore key itself is never passed to the Rust/JNI side. Only DATA encrypted or decrypted
 * with it crosses over (identity secret keys, the history key).
 *
 * Note: the post-quantum keys (Kyber, Dilithium) and X25519/Ed25519 keys are NOT algorithms the Android Keystore supports (it supports only
 * EC, RSA and AES). So those keys cannot be generated in the Keystore and operated there. Instead, envelope encryption is used. The real secret
 * keys are generated normally on the Rust side. Before being written to disk, they are encrypted with this AES key. A bare secret key never
 * reaches the disk; only the ciphertext does.
 */
object KeystoreCrypto {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    /** Alias of the key that wraps the identity secret key bundle. */
    const val ALIAS_IDENTITY = "p2p_messenger_master_key"
    /** Alias of the key that wraps the message history archive key. It is kept separate so one can be revoked without affecting the other.
     *  For example, "delete all history" can be done with a separate key rotation, without touching the identity. */
    const val ALIAS_HISTORY = "p2p_messenger_history_wrap_key"
    /** Alias of the key that wraps the skipped-message-key cache (the Double Ratchet's support for out-of-order and late messages). It is
     *  ALWAYS used, regardless of node mode. Unlike the history archive, this cache is needed for messaging reliability: out-of-order messages
     *  must still decrypt while node mode is off. */
    const val ALIAS_SKIPPED_KEYS = "p2p_messenger_skipped_keys_wrap_key"
    /** Alias of the key that wraps the root archive key (ARK). It decrypts the history stored on the server (see ArchiveKeyManager).
     *
     *  Why it is separate from ALIAS_HISTORY: the two have different scopes. The history key belongs to the DEVICE, is random, and is NOT
     *  in the recovery file. It only encrypts the local archive on disk. The ARK belongs to the IDENTITY. It goes to sibling devices through
     *  `DeviceSync`, and it is included in the recovery file. If they shared one alias, "reset local history" would also make the server
     *  archive unreadable. */
    const val ALIAS_ARCHIVE_ROOT = "p2p_messenger_archive_root_wrap_key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH_BITS = 128

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
    }

    /** Returns the Keystore key for the given alias. If it does not exist, it is created (in StrongBox if available, otherwise in the TEE). */
    @Synchronized
    private fun getOrCreateKey(alias: String): SecretKey {
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        // an existing alias that is unusable must not be silently replaced
        // (everything wrapped under it would become unreadable).
        if (keyStore.containsAlias(alias)) throw java.security.GeneralSecurityException("keystore key unusable: $alias")

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val baseSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)

        // StrongBox (a separate security chip) is tried first, for stronger isolation. `setIsStrongBoxBacked` was added in API 28, and this
        // app's minSdk is 26, so the API level is checked first (otherwise there is a NoSuchMethodError risk on API 26 and 27). If the device or
        // Android version does not support it, it falls back to the TEE (Trusted Execution Environment). Both give the guarantee that other
        // apps cannot read the key. StrongBox adds extra hardware isolation.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            try {
                keyGenerator.init(baseSpec.setIsStrongBoxBacked(true).build())
                return keyGenerator.generateKey()
            } catch (e: StrongBoxUnavailableException) {
            // Falls back to the TEE path below.
            } catch (e: Exception) {
            // On some OEMs the StrongBox flag fails with different exceptions. Staying on the safe side, it falls back to the TEE.
            }
        }
        // API 28+ only, like the call above: on 8.0/8.1 this method does not
        // exist and the first launch died with NoSuchMethodError.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            baseSpec.setIsStrongBoxBacked(false)
        }
        keyGenerator.init(baseSpec.build())
        return keyGenerator.generateKey()
    }

    /** Account wipe, see [LocalWipe]. */
    @Synchronized
    fun deleteAllKeys() {
        for (alias in listOf(ALIAS_IDENTITY, ALIAS_HISTORY, ALIAS_SKIPPED_KEYS, ALIAS_ARCHIVE_ROOT)) {
            try { keyStore.deleteEntry(alias) } catch (e: Exception) { }
        }
    }

    /**
     * Encrypts data with the given Keystore key. The returned byte array has the form `[12-byte IV][ciphertext+tag]`. It can be written
     * to a file or a BLOB as is.
     */
    fun encrypt(plaintext: ByteArray, alias: String = ALIAS_IDENTITY): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(alias))
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        return iv + ciphertext
    }

    /** Decodes the `[iv][ciphertext+tag]` format produced by `encrypt`. */
    fun decrypt(ivAndCiphertext: ByteArray, alias: String = ALIAS_IDENTITY): ByteArray {
        require(ivAndCiphertext.size > 12) { "Encrypted blob too short" }
        val iv = ivAndCiphertext.copyOfRange(0, 12)
        val ciphertext = ivAndCiphertext.copyOfRange(12, ivAndCiphertext.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // Never create here: a missing alias must fail, not be replaced by a
        // fresh key that cannot open anything written before.
        val key = keyStore.getKey(alias, null) as? SecretKey
            ?: throw java.security.KeyStoreException("Keystore key missing: $alias")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    /** Reports whether the key really is kept in hardware on this device. It can be shown on a diagnostics or settings screen. */
    private val keyFailureShown = java.util.concurrent.atomic.AtomicBoolean(false)

    /** A stored key could not be opened, so history or session state is not
     *  kept from here on. Said once per process: the log line alone left the
     *  user with an app that quietly forgot things. */
    fun reportKeyFailure(context: android.content.Context) {
        if (!keyFailureShown.compareAndSet(false, true)) return
        val app = context.applicationContext
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            android.widget.Toast.makeText(app, com.p2p.messenger.R.string.error_key_unreadable, android.widget.Toast.LENGTH_LONG).show()
        }
    }

    fun isHardwareBacked(alias: String = ALIAS_IDENTITY): Boolean {
        return try {
            val key = keyStore.getKey(alias, null) as? SecretKey ?: return false
            val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER)
            val keyInfo = factory.getKeySpec(key, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
            keyInfo.isInsideSecureHardware
        } catch (e: Exception) {
            false
        }
    }
}

/** Writes to a temporary file, then `rename`s it. This stops a crash or power loss during a write from leaving a half-written (unreadable)
 *  key file. */
fun java.io.File.writeBytesAtomic(bytes: ByteArray) {
    // unique tmp per call, two writers never share one.
    val tmp = java.io.File(parentFile, "$name.${System.nanoTime()}.tmp")
    try {
        java.io.FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        if (!tmp.renameTo(this)) throw java.io.IOException("rename failed: $tmp")
        // the rename is on disk only once the directory is synced.
        try {
            val dir = android.system.Os.open(parentFile!!.path, android.system.OsConstants.O_RDONLY, 0)
            try { android.system.Os.fsync(dir) } finally { android.system.Os.close(dir) }
        } catch (e: Exception) {}
    } catch (e: Exception) {
        tmp.delete()
        throw e
    }
}
