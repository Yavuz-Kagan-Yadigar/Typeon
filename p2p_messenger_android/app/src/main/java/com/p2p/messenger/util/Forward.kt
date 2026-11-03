package com.p2p.messenger.util

import android.content.Intent
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import com.p2p.messenger.MainActivity
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.ui.SimpleChatAdapter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Forwarding a message to another chat (WhatsApp pattern). The chat is
 * picked in the chat list like a share (see [ShareIntake.forward]).
 *
 * The "Forwarded" label travels as [MARK] at the start of the text (or of
 * the caption of a file): no protocol field, and clients that do not know
 * it show nothing, the characters are invisible.
 */
object Forward {
    private const val MARK = "⁤⁣"

    fun isForwarded(text: String) = text.startsWith(MARK)
    fun strip(text: String) = text.removePrefix(MARK)
    fun mark(text: String) = MARK + strip(text)

    /** Either [text] or [file] (with its name, type and caption). */
    class Pending(val text: String?, val file: File?, val fileName: String = "", val mimeType: String = "", val caption: String = "")

    /** Stickers are not offered: sent as a file they would lose the sticker look. */
    fun canForward(item: SimpleChatAdapter.Item) =
        !item.isDeleted && item.attachment?.isSticker != true

    fun start(activity: ComponentActivity, item: SimpleChatAdapter.Item) {
        val attachment = item.attachment
        if (attachment == null) {
            open(activity, Pending(mark(item.text), null))
            return
        }
        activity.lifecycleScope.launch {
            val path = withContext(Dispatchers.IO) {
                try { P2PLib.getAttachmentPlaintextPath(attachment.fileId) } catch (e: Exception) { "Error: ${e.message}" }
            }
            if (path.startsWith("Error:")) {
                Toast.makeText(activity, coreErrorText(activity, path), Toast.LENGTH_SHORT).show()
                return@launch
            }
            open(activity, Pending(null, File(path), attachment.fileName, attachment.mimeType, mark(item.caption)))
        }
    }

    private fun open(activity: ComponentActivity, pending: Pending) {
        ShareIntake.forward = pending
        activity.startActivity(
            Intent(activity, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        )
        Toast.makeText(activity, R.string.msg_forward_pick_chat, Toast.LENGTH_LONG).show()
    }
}
