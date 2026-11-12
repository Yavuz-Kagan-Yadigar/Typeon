package com.p2p.messenger.ui

import android.app.Dialog
import android.content.Context
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
import com.p2p.messenger.util.ImagePreview

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
        /** True if this conversation has activity since it was last opened
         *  (see ReadStatePrefs) — drives the row's accent-tinted background. */
        val hasUnread: Boolean = false,
        /** See PinnedChatsPrefs — pinned rows always sort above unpinned
         *  ones (ChatsFragment.refreshList) and get a 📌 prefix on the name. */
        val isPinned: Boolean = false,
        /** Rust'ın gerçek `contact_id`'si (`contactId` alanı tarihsel
         *  olarak AYGIT parmak izini taşıyor, bkz. ChatsFragment notu) —
         *  sadece uzun basma menüsündeki sohbet geçmişi temizleme/kişi
         *  silme çağrıları için gerekli. Grup satırlarında boş kalır. */
        val realContactId: String = "",
        /** Bu kişinin/grubun profil fotoğrafı (720p/%85 JPEG), yoksa
         *  `null` (baş harf rozeti gösterilir). */
        val avatarJpeg: ByteArray? = null,
        /** Gruplar sekmesi kaldırıldı, gruplar bu listeye
         *  karıştırıldı (bkz. kullanıcı isteği) — `true` ise `contactId`
         *  aslında bir `group_id`'dir, tıklama `GroupChatActivity` açmalı. */
        val isGroup: Boolean = false,
        /** bu kişi yüz yüze QR ile DEĞİL, bir
         *  grup üzerinden kurucu kefaletiyle eklendiyse `true` — satırda
         *  uyarı işareti gösterilir (bkz. Rust `Contact.added_via_group`). */
        val addedViaGroup: Boolean = false,
        /** `isGroup` satırlarında, bu grubun
         *  kurucusu BİZ miyiz — uzun basma menüsünde "grubu herkes için
         *  sil" seçeneği yalnızca kurucuya gösterilir. */
        val isGroupFounder: Boolean = false,
        /** Kullanıcı kararı (2026-08-27): ENGELLEME kişiyi (kimliği)
         *  hedefliyor, cihazı değil — bu yüzden uzun basma menüsünün
         *  `identity_id`'ye ihtiyacı var. `contactId` tarihsel olarak aygıt
         *  parmak izini taşıyor, o iş görmüyor. Grup satırlarında boş. */
        val identityId: String = ""
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ChatMessage) return false
            return contactId == other.contactId && displayName == other.displayName &&
                lastMessage == other.lastMessage && timestamp == other.timestamp &&
                hasUnread == other.hasUnread &&
                isPinned == other.isPinned &&
                realContactId == other.realContactId && identityId == other.identityId &&
                isGroup == other.isGroup &&
                // bu
                // ikisi önceden eksikti — `DiffUtil.ItemCallback.areContentsTheSame`
                // bu `equals`'ı kullandığından, GÜVENLİKLE İLGİLİ "⚠
                // doğrulanmadı" rozetini süren `addedViaGroup` (bkz. `bind`
                // fonksiyonundaki kullanımı) yalnızca BAŞKA bir alan (ör.
                // isim/son mesaj) da aynı anda değişirse güncellenirdi — bir
                // kişi sonradan doğrulanıp `addedViaGroup` tek başına
                // değiştiğinde satır YENİDEN BAĞLANMAZ, eski uyarı rozeti
                // ekranda kalırdı.
                addedViaGroup == other.addedViaGroup && isGroupFounder == other.isGroupFounder &&
                (avatarJpeg?.contentEquals(other.avatarJpeg) ?: (other.avatarJpeg == null))
        }

        override fun hashCode(): Int {
            var result = contactId.hashCode()
            result = 31 * result + displayName.hashCode()
            result = 31 * result + lastMessage.hashCode()
            result = 31 * result + timestamp.hashCode()
            result = 31 * result + hasUnread.hashCode()
            result = 31 * result + isPinned.hashCode()
            result = 31 * result + realContactId.hashCode()
            result = 31 * result + isGroup.hashCode()
            result = 31 * result + addedViaGroup.hashCode()
            result = 31 * result + isGroupFounder.hashCode()
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
        private val imgAvatar: ImageView = itemView.findViewById(R.id.imgAvatar)

        /** only the relative time label (no avatar decode, no rebind). */
        fun bindTime(message: ChatMessage) {
            txtTimestamp.text = if (message.timestamp > 0) formatTimestamp(message.timestamp) else ""
        }

        fun bind(message: ChatMessage) {
            // Grup üzerinden (kurucu kefaletiyle) eklenmiş kişiler yüz yüze
            // QR ile doğrulanmadı — isimde görünür bir uyarı işareti.
            val pinPrefix = if (message.isPinned) "📌 " else ""
            val warnPrefix = if (message.addedViaGroup) "⚠ " else ""
            txtName.text = "$pinPrefix$warnPrefix${message.displayName}"
            txtLastMessage.text = message.lastMessage
            txtTimestamp.text = if (message.timestamp > 0) formatTimestamp(message.timestamp) else ""
            AvatarUtil.renderInto(imgAvatar, message.avatarJpeg, message.displayName)

            // Avatar tap shows the photo full screen; with no photo (letter
            // badge) it still opens the chat. Long-press stays on the row.
            imgAvatar.setOnClickListener {
                val bytes = message.avatarJpeg
                if (bytes == null || bytes.isEmpty()) onItemClick(message)
                else showAvatarFullscreen(itemView.context, bytes)
            }
            imgAvatar.setOnLongClickListener { itemView.performLongClick() }

            // Unread rows get a 20%-alpha accent color overlay on top of the
            // normal background; cleared once ReadStatePrefs marks it read.
            itemView.setBackgroundColor(
                if (message.hasUnread) {
                    val accent = com.google.android.material.color.MaterialColors.getColor(
                        itemView, com.google.android.material.R.attr.colorPrimary
                    )
                    androidx.core.graphics.ColorUtils.setAlphaComponent(accent, (255 * 0.20f).toInt())
                } else {
                    android.graphics.Color.TRANSPARENT
                }
            )

            itemView.setOnClickListener {
                onItemClick(message)
            }
            itemView.setOnLongClickListener {
                // Group rows never carry a realContactId (they're not a
                // Contact) — the long-press menu still applies to them
                // (delete-group for the founder), so gate on isGroup too.
                // Previously this guard was realContactId-only, which
                // silently swallowed every long-press on a group row.
                if (message.isGroup || message.realContactId.isNotEmpty()) {
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
            val context = itemView.context
            return when {
                diff < 60000 -> context.getString(R.string.lbl_time_just_now)
                diff < 3600000 -> context.getString(R.string.lbl_time_minutes_ago, diff / 60000)
                diff < 86400000 -> context.getString(R.string.lbl_time_hours_ago, diff / 3600000)
                else -> context.getString(R.string.lbl_time_days_ago, diff / 86400000)
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

    override fun onBindViewHolder(holder: ChatViewHolder, position: Int, payloads: MutableList<Any>) {
        if (payloads.contains(TIME_PAYLOAD)) holder.bindTime(getItem(position)) else super.onBindViewHolder(holder, position, payloads)
    }

    private val TIME_PAYLOAD = Any()
    private var labelsMinute = 0L

    /** "Just now" is computed when a row is bound, and an unchanged row is
     *  never bound again: called on every list refresh, rebinds once a minute. */
    fun refreshTimeLabels() {
        val minute = System.currentTimeMillis() / 60_000
        if (minute == labelsMinute) return
        labelsMinute = minute
        notifyItemRangeChanged(0, itemCount, TIME_PAYLOAD)
    }
}

/** Full-screen raw avatar JPEG in a plain Dialog — no temp file on disk
 *  (unlike AvatarUtil.openFullscreen, which needs a URI for MediaViewer). */
private fun showAvatarFullscreen(context: Context, bytes: ByteArray) {
    val bitmap = ImagePreview.decodeBytes(bytes, 2048) ?: return
    val dialog = Dialog(context, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
    val image = ImageView(context).apply {
        setImageBitmap(bitmap)
        scaleType = ImageView.ScaleType.FIT_CENTER
        setOnClickListener { dialog.dismiss() }
    }
    dialog.setContentView(image, ViewGroup.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT
    ))
    // Bound to the screen: a recreate must not leak the window.
    (context as? androidx.lifecycle.LifecycleOwner)?.lifecycle?.addObserver(object : androidx.lifecycle.DefaultLifecycleObserver {
        override fun onDestroy(owner: androidx.lifecycle.LifecycleOwner) { dialog.dismiss() }
    })
    dialog.show()
}
