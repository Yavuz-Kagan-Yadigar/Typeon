package com.p2p.messenger.ui

import android.graphics.Typeface
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.p2p.messenger.R
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Bir sohbet ekranındaki mesaj balonlarını gösteren minimal adapter.
 * Kalıcı depolama yok — bkz. ChatActivity dosya başı notu. GroupChatActivity
 * da aynı adapter'ı kullanır (`senderName` alanı sadece orada dolu olur).
 *
 * Spec dışı: mesaj düzenleme/silme desteği — her `Item` kararlı bir
 * `messageId` taşır (bkz. Rust `MessagePacketHeader.message_id`), bu sayede
 * gelen bir edit/delete olayı doğru satırı bulup güncelleyebilir
 * (`applyEdit`/`applyDelete`). Silinen mesajlar listeden ÇIKARILMAZ —
 * pozisyon kararlılığı için yerine "Bu mesaj silindi" yer tutucusu konur
 * (WhatsApp/Telegram'daki gibi).
 */
class SimpleChatAdapter(private val items: MutableList<Item>) : RecyclerView.Adapter<SimpleChatAdapter.BubbleViewHolder>() {

    enum class Status { PENDING, SENT, ERROR }

    data class Item(
        val messageId: String,
        var text: String,
        val isMine: Boolean,
        val timestamp: Long = System.currentTimeMillis(),
        var status: Status = Status.SENT,
        var isEdited: Boolean = false,
        var isDeleted: Boolean = false,
        /** Sadece grup sohbetinde, kendi mesajımız değilse gösterilir. */
        val senderName: String? = null
    )

    /** Kendi mesajlarımıza uzun basıldığında tetiklenir (Düzenle/Sil menüsü
     *  ChatActivity/GroupChatActivity'de gösterilir — adapter sadece
     *  "hangi item" bilgisini taşır). */
    var onItemLongPress: ((Item) -> Unit)? = null

    private val timeFormat = SimpleDateFormat("HH:mm", Locale.getDefault())

    class BubbleViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val container: LinearLayout = itemView as LinearLayout
        val senderName: TextView = itemView.findViewById(R.id.txtSenderName)
        val textView: TextView = itemView.findViewById(R.id.txtBubbleText)
        val editedLabel: TextView = itemView.findViewById(R.id.txtEditedLabel)
        val timestamp: TextView = itemView.findViewById(R.id.txtTimestamp)
        val status: ImageView = itemView.findViewById(R.id.imgStatus)
    }

    fun indexOfMessageId(messageId: String): Int = items.indexOfFirst { it.messageId == messageId }

    fun addMessage(item: Item) {
        items.add(item)
        notifyItemInserted(items.size - 1)
    }

    /** Gelen/giden bir edit olayını uygular. Hedef bulunamazsa (ör. geçmişte
     *  yüklenmemiş bir mesajı düzenliyorsa) sessizce yok sayılır. */
    fun applyEdit(targetMessageId: String, newText: String) {
        val idx = indexOfMessageId(targetMessageId)
        if (idx < 0) return
        items[idx].text = newText
        items[idx].isEdited = true
        notifyItemChanged(idx)
    }

    fun applyDelete(targetMessageId: String) {
        val idx = indexOfMessageId(targetMessageId)
        if (idx < 0) return
        items[idx].isDeleted = true
        notifyItemChanged(idx)
    }

    /** Bir gönderim durumu güncellemesi uygular (bkz. Rust "status" olayı —
     *  ilk denemede "pending" kalan bir mesaj sonradan "sent"/"error" olur). */
    fun applyStatus(targetMessageId: String, status: Status) {
        val idx = indexOfMessageId(targetMessageId)
        if (idx < 0) return
        items[idx].status = status
        notifyItemChanged(idx)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): BubbleViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message_bubble, parent, false)
        return BubbleViewHolder(view)
    }

    override fun onBindViewHolder(holder: BubbleViewHolder, position: Int) {
        val item = items[position]
        holder.container.gravity = if (item.isMine) Gravity.END else Gravity.START
        holder.textView.setBackgroundResource(if (item.isMine) R.drawable.bubble_mine else R.drawable.bubble_theirs)

        val onColorAttr = if (item.isMine) {
            com.google.android.material.R.attr.colorOnPrimaryContainer
        } else {
            com.google.android.material.R.attr.colorOnSurfaceVariant
        }
        holder.textView.setTextColor(MaterialColors.getColor(holder.textView, onColorAttr))

        if (!item.isMine && item.senderName != null) {
            holder.senderName.text = item.senderName
            holder.senderName.visibility = View.VISIBLE
        } else {
            holder.senderName.visibility = View.GONE
        }

        if (item.isDeleted) {
            holder.textView.text = holder.itemView.context.getString(R.string.msg_deleted)
            holder.textView.setTypeface(holder.textView.typeface, Typeface.ITALIC)
            holder.textView.alpha = 0.6f
            holder.editedLabel.visibility = View.GONE
        } else {
            holder.textView.text = item.text
            holder.textView.setTypeface(Typeface.DEFAULT, Typeface.NORMAL)
            holder.textView.alpha = 1f
            holder.editedLabel.visibility = if (item.isEdited) View.VISIBLE else View.GONE
        }

        holder.timestamp.text = timeFormat.format(Date(item.timestamp))

        if (item.isMine && !item.isDeleted) {
            holder.status.visibility = View.VISIBLE
            holder.status.setImageResource(
                when (item.status) {
                    Status.PENDING -> R.drawable.ic_status_pending
                    Status.SENT -> R.drawable.ic_status_sent
                    Status.ERROR -> R.drawable.ic_status_error
                }
            )
        } else {
            holder.status.visibility = View.GONE
        }

        holder.itemView.setOnLongClickListener {
            if (item.isMine && !item.isDeleted) {
                onItemLongPress?.invoke(item)
                true
            } else {
                false
            }
        }
    }

    override fun getItemCount(): Int = items.size
}
