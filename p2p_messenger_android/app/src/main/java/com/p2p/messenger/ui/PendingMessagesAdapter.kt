package com.p2p.messenger.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.R
import com.p2p.messenger.util.formatAbsoluteTime

/**
 * The "pending messages" list in Settings: messages that have not been acknowledged by the other side yet (see lib.rs `awaiting_confirmation`
 * and types.rs `regen_content`). See `PendingMessagesActivity`. The expected size is small (a few items in typical use), so it uses the same simple
 * pattern as `SimpleChatAdapter`: a plain list with a targeted `notifyItemRemoved`, not `ListAdapter` / `DiffUtil`.
 */
class PendingMessagesAdapter(
    private val items: MutableList<Item>,
    private val onCancel: (Item) -> Unit,
    private val onRetry: (Item) -> Unit
) : RecyclerView.Adapter<PendingMessagesAdapter.ViewHolder>() {

    data class Item(
        val messageId: String,
        val targetName: String,
        /** The name of the target DEVICE. See the `PendingMessageSummary.device_name` docs in types.rs. A contact or group name alone does not say
         *  which device has still not confirmed. Empty means it is not shown on the row. */
        val deviceName: String,
        val text: String,
        val lastAttemptAtMs: Long
    )

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val target: TextView = itemView.findViewById(R.id.txtPendingTarget)
        val text: TextView = itemView.findViewById(R.id.txtPendingText)
        val lastAttempt: TextView = itemView.findViewById(R.id.txtPendingLastAttempt)
        val btnCancel: Button = itemView.findViewById(R.id.btnCancelPending)
        val btnRetry: Button = itemView.findViewById(R.id.btnRetryPending)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_pending_message, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        // The name of the target device too, if there is one. See the `Item.deviceName` docs.
        holder.target.text = if (item.deviceName.isNotEmpty()) {
            "${item.targetName} · ${item.deviceName}"
        } else {
            item.targetName
        }
        holder.text.text = item.text
        holder.lastAttempt.text = holder.itemView.context.getString(
            R.string.lbl_pending_last_attempt, formatAbsoluteTime(item.lastAttemptAtMs)
        )
        holder.btnCancel.setOnClickListener { onCancel(item) }
        holder.btnRetry.setOnClickListener { onRetry(item) }
    }

    /** See `PendingMessagesActivity.cancelPending`. When an item is cancelled (already removed on the Rust side), it is removed from the list too. */
    fun removeById(messageId: String) {
        val index = items.indexOfFirst { it.messageId == messageId }
        if (index >= 0) {
            items.removeAt(index)
            notifyItemRemoved(index)
        }
    }

    fun submitList(newItems: List<Item>) {
        items.clear()
        items.addAll(newItems)
        notifyDataSetChanged()
    }
}
