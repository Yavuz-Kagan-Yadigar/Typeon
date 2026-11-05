package com.p2p.messenger.server

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * SQLCipher key of the server DB: 32 random bytes, stored only wrapped by a
 * non-exportable Android Keystore AES-GCM key (same envelope scheme as the
 * client's KeystoreCrypto). Returned as raw bytes for `ServerLib.setDbKey`;
 * the caller zeroes the array after the call.
 */
object DbKey {
    private const val ALIAS = "typeon_server_db_wrap_key"
    private const val PREF = "db_key_wrapped"

    @Synchronized
    fun get(context: Context): ByteArray {
        val prefs = context.getSharedPreferences(ServerService.PREFS_NAME, Context.MODE_PRIVATE)
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val wrapped = prefs.getString(PREF, null)
        if (wrapped != null) {
            // Never create here: a missing alias must fail, a fresh key cannot open the DB.
            val key = ks.getKey(ALIAS, null) as? SecretKey
                ?: throw java.security.KeyStoreException("Keystore key missing: $ALIAS")
            val raw = Base64.decode(wrapped, Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, raw.copyOfRange(0, 12)))
            return cipher.doFinal(raw, 12, raw.size - 12)
        }
        // An alias without a saved blob: a crash before the commit below. No DB
        // was ever keyed with it, so it is replaced (refusing would block the server for good).
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        val wrapKey = gen.generateKey()
        val dbKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
        val blob = cipher.iv + cipher.doFinal(dbKey)
        // commit(): the DB is keyed with this at once; a lost blob would orphan it.
        if (!prefs.edit().putString(PREF, Base64.encodeToString(blob, Base64.NO_WRAP)).commit()) {
            throw java.io.IOException("db key not saved")
        }
        return dbKey
    }
}
