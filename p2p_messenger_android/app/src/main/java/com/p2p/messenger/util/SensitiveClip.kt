package com.p2p.messenger.util

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/** Copies [text] marked sensitive: no clipboard preview, and keyboards that
 *  honour the flag keep it out of their history and cloud sync. */
fun copySensitive(context: Context, label: String, text: String) {
    val clip = ClipData.newPlainText(label, text)
    clip.description.extras = PersistableBundle().apply {
        putBoolean("android.content.extra.IS_SENSITIVE", true)
    }
    // The application's manager: the listener below must be removed from the
    // same instance it was added to, and must not hold an activity.
    val clipboard = context.applicationContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.watchForForeignCopy()
    clipboard.setPrimaryClip(clip)
    clipboard.scheduleSelfClear()
}

/** Sensitive copies survived AppLock, logout, anything (preview is hidden;
 *  the text itself was not): a pairing code or a message body stayed on the
 *  clipboard indefinitely. 60 s after the copy the clipboard is emptied —
 *  ONLY while it is still ours: anything the user copies in the meantime
 *  is left exactly where it is. The clip itself cannot be read back from the
 *  background or a locked screen (API 29+), so "still ours" is tracked by
 *  listening for the next change instead. */
private const val SELF_CLEAR_DELAY_MS = 60_000L
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

private fun ClipboardManager.scheduleSelfClear() {
    clipClearHandler.removeCallbacksAndMessages(null)
    clipClearHandler.postDelayed({
        try {
            removePrimaryClipChangedListener(foreignCopyListener)
            if (!foreignCopy) {
                // `clearPrimaryClip` is API 28; minSdk is 26.
                if (android.os.Build.VERSION.SDK_INT >= 28) clearPrimaryClip()
                else setPrimaryClip(ClipData.newPlainText("", ""))
            }
        } catch (e: Exception) { }
    }, SELF_CLEAR_DELAY_MS)
}
