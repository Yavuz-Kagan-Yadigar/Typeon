package com.p2p.messenger.ui

import android.graphics.BitmapFactory
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.R
import com.p2p.messenger.util.AvatarUtil

/**
 * Sohbet/kişi listesi adapter'ı. `ListAdapter` + `DiffUtil` kullanır ki
 * liste güncellendiğinde (yeni kişi eklendi, son mesaj değişti vb.)
 * `notifyDataSetChanged()` yerine sadece değişen satırlar animasyonlu
 * olarak güncellensin — büyüyen kişi listelerinde performans ve UX farkı
 * yaratır.
 */
class ChatAdapter(
    private val onItemClick: (ChatMessage) -> Unit
) : ListAdapter<ChatAdapter.ChatMessage, ChatAdapter.ChatViewHolder>(DIFF_CALLBACK) {

    data class ChatMessage(
        val contactId: String,
        val displayName: String,
        val lastMessage: String,
        val timestamp: Long,
        val unreadCount: Int = 0,
        /** Rust'ın gerçek `contact_id`'si (`contactId` alanı tarihsel
         *  olarak AYGIT parmak izini taşıyor, bkz. ChatsFragment notu) —
         *  sadece uzun basma menüsündeki sohbet geçmişi temizleme/kişi
         *  silme çağrıları için gerekli. Grup satırlarında boş kalır. */
        val realContactId: String = "",
        /** Bu kişinin/grubun profil fotoğrafı (720p/%85 JPEG), yoksa
         *  `null` (baş harf rozeti gösterilir). */
        val avatarJpeg: ByteArray? = null,
        /** Spec dışı: Gruplar sekmesi kaldırıldı, gruplar bu listeye
         *  karıştırıldı (bkz. kullanıcı isteği) — `true` ise `contactId`
         *  aslında bir `group_id`'dir, tıklama `GroupChatActivity` açmalı. */
        val isGroup: Boolean = false,
        /** Spec dışı, kullanıcı kararı: bu kişi yüz yüze QR ile DEĞİL, bir
         *  grup üzerinden kurucu kefaletiyle eklendiyse `true` — satırda
         *  uyarı işareti gösterilir (bkz. Rust `Contact.added_via_group`). */
        val addedViaGroup: Boolean = false,
        /** Spec dışı, kullanıcı isteği: `isGroup` satırlarında, bu grubun
         *  kurucusu BİZ miyiz — uzun basma menüsünde "grubu herkes için
         *  sil" seçeneği yalnızca kurucuya gösterilir. */
        val isGroupFounder: Boolean = false
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ChatMessage) return false
            return contactId == other.contactId && displayName == other.displayName &&
                lastMessage == other.lastMessage && timestamp == other.timestamp &&
                unreadCount == other.unreadCount && realContactId == other.realContactId &&
                isGroup == other.isGroup &&
                (avatarJpeg?.contentEquals(other.avatarJpeg) ?: (other.avatarJpeg == null))
        }

        override fun hashCode(): Int {
            var result = contactId.hashCode()
            result = 31 * result + displayName.hashCode()
            result = 31 * result + lastMessage.hashCode()
            result = 31 * result + timestamp.hashCode()
            result = 31 * result + unreadCount
            result = 31 * result + realContactId.hashCode()
            result = 31 * result + isGroup.hashCode()
            result = 31 * result + (avatarJpeg?.contentHashCode() ?: 0)
            return result
        }
    }

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<ChatMessage>() {
            override fun areItemsTheSame(old: ChatMessage, new: ChatMessage) =
                old.contactId == new.contactId

            override fun areContentsTheSame(old: ChatMessage, new: ChatMessage) =
                old == new
        }
    }

    /** Bir kişi satırına uzun basıldığında (sohbet geçmişini temizle/
     *  kişiyi sil menüsü ChatsFragment/ContactsFragment'ta gösterilir). */
    var onContactLongClick: ((ChatMessage) -> Unit)? = null

    inner class ChatViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val txtName: TextView = itemView.findViewById(R.id.txtContactName)
        private val txtLastMessage: TextView = itemView.findViewById(R.id.txtLastMessage)
        private val txtTimestamp: TextView = itemView.findViewById(R.id.txtTimestamp)
        private val txtUnread: TextView = itemView.findViewById(R.id.txtUnreadCount)
        private val imgAvatar: ImageView = itemView.findViewById(R.id.imgAvatar)

        fun bind(message: ChatMessage) {
            // Grup üzerinden (kurucu kefaletiyle) eklenmiş kişiler yüz yüze
            // QR ile doğrulanmadı — isimde görünür bir uyarı işareti.
            txtName.text = if (message.addedViaGroup) "⚠ ${message.displayName}" else message.displayName
            txtLastMessage.text = message.lastMessage
            txtTimestamp.text = if (message.timestamp > 0) formatTimestamp(message.timestamp) else ""
            txtUnread.visibility = if (message.unreadCount > 0) View.VISIBLE else View.GONE
            txtUnread.text = message.unreadCount.toString()
            AvatarUtil.renderInto(imgAvatar, message.avatarJpeg, message.displayName)

            itemView.setOnClickListener {
                onItemClick(message)
            }
            itemView.setOnLongClickListener {
                if (message.realContactId.isNotEmpty()) {
                    onContactLongClick?.invoke(message)
                    true
                } else {
                    false
                }
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
