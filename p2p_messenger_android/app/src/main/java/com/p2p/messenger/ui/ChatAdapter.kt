package com.p2p.messenger.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.R

/**
 * Sohbet/kişi listesi adapter'ı. `ListAdapter` + `DiffUtil` kullanır ki
 * liste güncellendiğinde (yeni kişi eklendi, son mesaj değişti vb.)
 * `notifyDataSetChanged()` yerine sadece değişen satırlar animasyonlu
 * olarak güncellensin — büyüyen kişi listelerinde performans ve UX farkı
 * yaratır.
 */
class ChatAdapter(
    private val onContactClick: (String, String) -> Unit
) : ListAdapter<ChatAdapter.ChatMessage, ChatAdapter.ChatViewHolder>(DIFF_CALLBACK) {

    data class ChatMessage(
        val contactId: String,
        val displayName: String,
        val lastMessage: String,
        val timestamp: Long,
        val unreadCount: Int = 0
    )

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<ChatMessage>() {
            override fun areItemsTheSame(old: ChatMessage, new: ChatMessage) =
                old.contactId == new.contactId

            override fun areContentsTheSame(old: ChatMessage, new: ChatMessage) =
                old == new
        }
    }

    inner class ChatViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val txtName: TextView = itemView.findViewById(R.id.txtContactName)
        private val txtLastMessage: TextView = itemView.findViewById(R.id.txtLastMessage)
        private val txtTimestamp: TextView = itemView.findViewById(R.id.txtTimestamp)
        private val txtUnread: TextView = itemView.findViewById(R.id.txtUnreadCount)

        fun bind(message: ChatMessage) {
            txtName.text = message.displayName
            txtLastMessage.text = message.lastMessage
            txtTimestamp.text = if (message.timestamp > 0) formatTimestamp(message.timestamp) else ""
            txtUnread.visibility = if (message.unreadCount > 0) View.VISIBLE else View.GONE
            txtUnread.text = message.unreadCount.toString()

            itemView.setOnClickListener {
                onContactClick(message.contactId, message.displayName)
            }
        }

        private fun formatTimestamp(timestamp: Long): String {
            val now = System.currentTimeMillis()
            val diff = now - timestamp
            return when {
                diff < 60000 -> "Just now"
                diff < 3600000 -> "${diff / 60000}m ago"
                diff < 86400000 -> "${diff / 3600000}h ago"
                else -> "${diff / 86400000}d ago"
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ChatViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_chat, parent, false)
        return ChatViewHolder(view)
    }

    override fun onBindViewHolder(holder: ChatViewHolder, position: Int) {
        holder.bind(getItem(position))
    }
}
