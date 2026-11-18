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
        // The poll thread, arti and the service still run in this process and
        // can write files (or re-create a Keystore key) after the delete below.
        // The marker makes the next process start wipe again before anything opens.
        try { marker(app).createNewFile() } catch (e: Exception) { com.p2p.messenger.util.Log.w("LocalWipe", "marker: ${e.message}") }
        deleteAll(app)
    }

    /** Called first thing in `P2PApplication.onCreate`: finishes a wipe whose process exited. */
    fun finishPending(context: Context) {
        val app = context.applicationContext
        val m = marker(app)
        if (!m.exists()) return
        deleteAll(app)
        m.delete()
    }

    /** Outside filesDir, the caches and shared_prefs, so [deleteAll] keeps it. */
    private fun marker(app: Context) = File(app.applicationInfo.dataDir, "wipe_pending")

    private fun deleteAll(app: Context) {
        // Everything the app stores lives under filesDir: database, wrapped
        // keys, libp2p key, attachments, arti state, wallpaper, fonts.
        app.filesDir.listFiles()?.forEach {
            if (!it.deleteRecursively()) com.p2p.messenger.util.Log.w("LocalWipe", "could not delete ${it.name}")
        }
        // The wrapping keys too: a deleted `.enc` file recovered from flash
        // stays closed. The next identity makes new ones.
        KeystoreCrypto.deleteAllKeys()
        // Plaintext leftovers: voice recordings, outgoing copies, avatars.
        for (dir in listOfNotNull(app.cacheDir, app.codeCacheDir, app.noBackupFilesDir,
                app.externalCacheDir, app.getExternalFilesDir(null))) {
            if (dir.exists() && !dir.deleteRecursively()) {
                com.p2p.messenger.util.Log.w("LocalWipe", "could not fully delete ${dir.name}")
            }
        }
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
