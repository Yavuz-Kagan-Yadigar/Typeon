package com.p2p.messenger.ui

import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.view.ActionMode
import androidx.lifecycle.lifecycleScope
import com.p2p.messenger.R
import com.p2p.messenger.util.Forward
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Multi-message selection for ChatActivity and GroupChatActivity: the
 * adapter keeps the selected ids (one kind at a time, see
 * [SimpleChatAdapter.Kind]), this shows the action bar over the toolbar.
 * Back or the bar's close button ends the selection.
 */
class MessageSelection(
    private val activity: AppCompatActivity,
    private val adapter: SimpleChatAdapter,
    private val save: (SimpleChatAdapter.AttachmentInfo) -> Unit,
    /** Core delete call for one message; "Error: ..." on failure. */
    private val delete: (messageId: String) -> String,
) : ActionMode.Callback {
    private var mode: ActionMode? = null

    init {
        adapter.onSelectionChanged = {
            val count = adapter.selectedItems().size
            if (count == 0) {
                mode?.finish()
            } else {
                val m = mode ?: activity.startSupportActionMode(this).also { mode = it }
                m?.title = count.toString()
                m?.invalidate()
            }
        }
    }

    /** "Select" in a message's long-press menu. */
    fun start(item: SimpleChatAdapter.Item) = adapter.toggleSelection(item)

    override fun onCreateActionMode(mode: ActionMode, menu: Menu): Boolean {
        listOf(R.string.lbl_copy, R.string.action_forward, R.string.action_save_to_downloads, R.string.action_delete_message)
            .forEach { menu.add(Menu.NONE, it, Menu.NONE, it).setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM or MenuItem.SHOW_AS_ACTION_WITH_TEXT) }
        return true
    }

    override fun onPrepareActionMode(mode: ActionMode, menu: Menu): Boolean {
        val items = adapter.selectedItems()
        val text = items.all { it.attachment == null }
        menu.findItem(R.string.lbl_copy).isVisible = text
        menu.findItem(R.string.action_forward).isVisible = items.all(Forward::canForward)
        menu.findItem(R.string.action_save_to_downloads).isVisible =
            !text && items.all { it.attachment?.status == SimpleChatAdapter.AttachmentStatus.COMPLETE }
        menu.findItem(R.string.action_delete_message).isVisible = items.all { it.isMine }
        return true
    }

    override fun onActionItemClicked(mode: ActionMode, menuItem: MenuItem): Boolean {
        val items = adapter.selectedItems()
        if (items.isEmpty()) {
            mode.finish()
            return true
        }
        when (menuItem.itemId) {
            R.string.lbl_copy -> {
                com.p2p.messenger.util.copySensitive(activity, "message", items.joinToString("\n") { com.p2p.messenger.util.Quote.plain(Forward.strip(it.text)) })
                Toast.makeText(activity, R.string.lbl_copied, Toast.LENGTH_SHORT).show()
            }
            R.string.action_forward -> Forward.start(activity, items)
            R.string.action_save_to_downloads -> items.forEach { item -> item.attachment?.let(save) }
            R.string.action_delete_message -> {
                confirmDelete(items)
                return true // the selection stays until the dialog is answered
            }
            else -> return false
        }
        mode.finish()
        return true
    }

    override fun onDestroyActionMode(mode: ActionMode) {
        this.mode = null
        adapter.clearSelection()
    }

    private fun confirmDelete(items: List<SimpleChatAdapter.Item>) {
        AlertDialog.Builder(activity)
            .setMessage(activity.resources.getQuantityString(R.plurals.confirm_delete_messages, items.size, items.size))
            .setPositiveButton(R.string.action_delete_message) { _, _ ->
                mode?.finish()
                activity.lifecycleScope.launch {
                    var failed = false
                    for (item in items) {
                        val result = withContext(Dispatchers.IO) {
                            try { delete(item.messageId) } catch (e: Throwable) { "Error: ${e.message}" }
                        }
                        if (result.startsWith("Error:")) failed = true else adapter.applyDelete(item.messageId)
                    }
                    if (failed) Toast.makeText(activity, R.string.error_delete_failed, Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
