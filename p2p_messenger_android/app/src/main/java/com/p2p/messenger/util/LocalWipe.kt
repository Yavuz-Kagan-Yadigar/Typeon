package com.p2p.messenger.util

import android.content.Context
import java.io.File

/**
 * Returns the app to its first-install state: identity, keys, database,
 * attachments, Tor state, every preference file (app lock, theme, node and
 * Tor switches, read state, pins), wallpaper and custom fonts. The one path
 * for "log out", "delete account" and remote revoke (`self_revoked`, see
 * `P2PService`).
 *
 * The caller must call [AppRestarter.restart] right after: the Rust core
 * cannot forget the identity in a live process, and cached preferences are
 * still in memory.
 */
object LocalWipe {

    fun wipe(context: Context) {
        val app = context.applicationContext
        // Everything the app stores lives under filesDir: database, wrapped
        // keys, libp2p key, attachments, arti state, wallpaper, fonts.
        app.filesDir.listFiles()?.forEach { it.deleteRecursively() }
        // The wrapping keys too: a deleted `.enc` file recovered from flash
        // stays closed. The next identity makes new ones.
        KeystoreCrypto.deleteAllKeys()
        // Plaintext leftovers: voice recordings, outgoing copies, avatars.
        app.cacheDir.deleteRecursively()
        app.getExternalFilesDir(null)?.deleteRecursively()
        // Every preference file, not a list of names: a new one is covered.
        File(app.applicationInfo.dataDir, "shared_prefs").listFiles()?.forEach { file ->
            if (file.extension == "xml") {
                // Clear the in-memory copy first (commit, not apply: the
                // caller exits the process right after), then the file.
                app.getSharedPreferences(file.nameWithoutExtension, Context.MODE_PRIVATE).edit().clear().commit()
                app.deleteSharedPreferences(file.nameWithoutExtension)
            } else {
                file.delete()
            }
        }
    }
}
