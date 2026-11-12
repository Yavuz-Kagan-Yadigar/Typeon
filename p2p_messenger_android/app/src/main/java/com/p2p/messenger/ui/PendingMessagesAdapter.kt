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
 * Ayarlar'daki "bekleyen mesajlar" (henüz
 * karşı taraftan "ack" alınmamış, bkz. lib.rs `awaiting_confirmation`/
 * types.rs `regen_content`) listesi — bkz. `PendingMessagesActivity`. Beklenen
 * boyut küçük (tipik kullanımda birkaç kalem) olduğundan `SimpleChatAdapter`
 * ile aynı basit desen: `ListAdapter`/`DiffUtil` yerine düz bir liste +
 * hedefli `notifyItemRemoved`.
 */
class PendingMessagesAdapter(
    private val items: MutableList<Item>,
    private val onCancel: (Item) -> Unit,
    private val onRetry: (Item) -> Unit
) : RecyclerView.Adapter<PendingMessagesAdapter.ViewHolder>() {

    data class Item(
        val messageId: String,
        val targetName: String,
        /** hedef CİHAZIN adı — bkz.
         *  types.rs `PendingMessageSummary.device_name` dokümantasyonu (kişi/
         *  grup adı tek başına hangi cihazın hâlâ onay vermediğini
         *  söylemez). Boşsa satırda gösterilmez. */
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
        // hedef cihazın adı da (varsa) —
        // bkz. `Item.deviceName` dokümantasyonu.
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

    /** bkz. `PendingMessagesActivity.cancelPending` — bir öğe iptal
     *  edildiğinde (Rust tarafında zaten kaldırıldıktan SONRA) listeden
     *  de kaldırır. */
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
