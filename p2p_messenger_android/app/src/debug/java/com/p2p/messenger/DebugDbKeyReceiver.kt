package com.p2p.messenger

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.util.Log
import com.p2p.messenger.util.KeystoreCrypto
import java.io.File

/** JNI: the SQLCipher raw key (64 hex characters) derived from the local
 *  storage key. The class exists only in the debug source set. */
object DebugDbKey {
    init {
        System.loadLibrary("p2p_messenger")
    }

    external fun dbKeyHex(storageKey: ByteArray): String
}

/**
 * Debug builds only. An adb-pulled database is SQLCipher-encrypted under a
 * key that never leaves the device; this writes that key to
 * `files/debug_db_key.hex`:
 *
 *     adb shell am broadcast -n com.p2p.messenger/.DebugDbKeyReceiver --include-stopped-packages
 *     adb shell run-as com.p2p.messenger cat files/debug_db_key.hex
 */
class DebugDbKeyReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) return
        val out = File(context.filesDir, "debug_db_key.hex")
        try {
            // Same file and wrapping key as util.SkippedKeyManager.
            val storageKey = KeystoreCrypto.decrypt(
                File(context.filesDir, "skipped_key_enc.enc").readBytes(),
                KeystoreCrypto.ALIAS_SKIPPED_KEYS
            )
            try {
                val hex = DebugDbKey.dbKeyHex(storageKey)
                check(hex.length == 64) { "no key derived" }
                out.writeText(hex)
            } finally {
                storageKey.fill(0)
            }
            Log.i("DebugDbKey", "key written to ${out.path}")
        } catch (e: Throwable) {
            out.delete()
            Log.e("DebugDbKey", "key export failed", e)
        }
    }
}
