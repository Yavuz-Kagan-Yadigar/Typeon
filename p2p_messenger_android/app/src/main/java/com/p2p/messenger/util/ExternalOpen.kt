package com.p2p.messenger.util

import android.content.Context
import androidx.appcompat.app.AlertDialog
import com.p2p.messenger.R

/**
 * Images and videos open in the app's own viewer. Anything else goes to an
 * outside app that talks to the network outside Tor (a web page or SVG can
 * load remote content), so ask once before handing it over.
 */
fun confirmExternalOpen(context: Context, mime: String?, go: () -> Unit) {
    if (mime != null && (mime.startsWith("image/") || mime.startsWith("video/"))) {
        go()
        return
    }
    AlertDialog.Builder(context)
        .setTitle(R.string.external_open_title)
        .setMessage(R.string.external_open_message)
        .setPositiveButton(R.string.external_open_continue) { _, _ -> go() }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}
