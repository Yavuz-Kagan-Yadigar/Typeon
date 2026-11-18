package com.p2p.messenger.util

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/** Copies [text] marked sensitive: no clipboard preview, and keyboards that
 *  honour the flag keep it out of their history and cloud sync. */
fun copySensitive(context: Context, label: String, text: String) =
    copySensitiveClip(context, ClipData.newPlainText(label, text))

/** Same for any clip (an image URI): marked sensitive, cleared after 60 s while still ours. Main thread. */
fun copySensitiveClip(context: Context, clip: ClipData) {
    val label = clip.description.label?.toString() ?: ""
    clip.description.extras = PersistableBundle().apply {
        putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
    // The application's manager: the listener below must be removed from the
    // same instance it was added to, and must not hold an activity.
    val clipboard = context.applicationContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.watchForForeignCopy()
    clipboard.setPrimaryClip(clip)
    clipboard.scheduleSelfClear(label)
}

/** Sensitive copies survived AppLock, logout, anything (preview is hidden;
 *  the text itself was not): a pairing code or a message body stayed on the
 *  clipboard indefinitely. 60 s after the copy the clipboard is emptied —
 *  ONLY while it is still ours: anything the user copies in the meantime
 *  is left exactly where it is. Two checks: a change seen by the listener
 *  (it fires only while we have focus), and the label of the clip on the
 *  board. From the background (API 29+) the label cannot be read, and a
 *  copy made in another app then reached no listener either: the clear
 *  waits until the label is readable again (the app back in front). */
private const val SELF_CLEAR_DELAY_MS = 60_000L
private const val SELF_CLEAR_RETRY_MS = 30_000L
// ponytail: gives up after ~2 h in the background (or on an empty board,
// which reads the same as no access); the clip then stays as before.
private const val SELF_CLEAR_MAX_RETRIES = 240
private val clipClearHandler = Handler(Looper.getMainLooper())
private var ownEventPending = false
@Volatile private var foreignCopy = false
private val foreignCopyListener = ClipboardManager.OnPrimaryClipChangedListener {
    // The first event is the notification of our own `setPrimaryClip`.
    if (ownEventPending) ownEventPending = false else foreignCopy = true
}

private fun ClipboardManager.watchForForeignCopy() {
    removePrimaryClipChangedListener(foreignCopyListener)
    ownEventPending = true
    foreignCopy = false
    addPrimaryClipChangedListener(foreignCopyListener)
}

private fun ClipboardManager.scheduleSelfClear(label: String) {
    clipClearHandler.removeCallbacksAndMessages(null)
    clipClearHandler.postDelayed({ trySelfClear(label, 0) }, SELF_CLEAR_DELAY_MS)
}

private fun ClipboardManager.trySelfClear(label: String, retries: Int) {
    try {
        if (foreignCopy) {
            removePrimaryClipChangedListener(foreignCopyListener)
            return
        }
        val desc = primaryClipDescription
        if (desc == null) {
            if (retries < SELF_CLEAR_MAX_RETRIES) {
                clipClearHandler.postDelayed({ trySelfClear(label, retries + 1) }, SELF_CLEAR_RETRY_MS)
            } else {
                removePrimaryClipChangedListener(foreignCopyListener)
            }
            return
        }
        removePrimaryClipChangedListener(foreignCopyListener)
        if (desc.label?.toString() == label) {
            clearPrimaryClip()
        }
    } catch (e: Exception) { }
}
