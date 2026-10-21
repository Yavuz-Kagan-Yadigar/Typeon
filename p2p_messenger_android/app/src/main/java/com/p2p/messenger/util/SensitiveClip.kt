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
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(clip)
    clipboard.scheduleSelfClear(label)
}

/** Sensitive copies survived AppLock, logout, anything (preview is hidden;
 *  the text itself was not): a pairing code or a message body stayed on the
 *  clipboard indefinitely. 60 s after the copy the clipboard is emptied —
 *  ONLY while it is still ours: anything the user copies in the meantime
 *  (a different label sits on the board) is left exactly where it is. */
private const val SELF_CLEAR_DELAY_MS = 60_000L
private val clipClearHandler = Handler(Looper.getMainLooper())

private fun ClipboardManager.scheduleSelfClear(label: String) {
    clipClearHandler.removeCallbacksAndMessages(null)
    clipClearHandler.postDelayed({
        try {
            // Only the description is readable from the background (API 29 +
            // focus rule applies to the text alone) — the label tells ours.
            val desc = primaryClipDescription
            if (desc?.label?.toString() == label) {
                // `clearPrimaryClip` is API 28; minSdk is 26.
                if (android.os.Build.VERSION.SDK_INT >= 28) clearPrimaryClip()
                else setPrimaryClip(ClipData.newPlainText("", ""))
            }
        } catch (e: Exception) { }
    }, SELF_CLEAR_DELAY_MS)
}
