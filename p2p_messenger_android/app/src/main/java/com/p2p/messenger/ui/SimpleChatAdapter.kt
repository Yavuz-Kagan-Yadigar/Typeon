package com.p2p.messenger.ui

import android.graphics.Typeface
import android.text.format.Formatter
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.p2p.messenger.R
import com.p2p.messenger.util.AvatarUtil
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

    /** Spec dışı: dosya/foto/video/ses eki durumu (bkz. dosya başı notu —
     *  P2PLib.prepareAndSendFile/downloadFile/pollNetwork "file_*" olayları). */
    enum class AttachmentStatus { OFFERED, DOWNLOADING, COMPLETE, FAILED }

    data class AttachmentInfo(
        val fileId: String,
        val fileName: String,
        val mimeType: String,
        val totalSize: Long,
        var status: AttachmentStatus,
        var bytesDone: Long = 0,
        /** Spec dışı: gönderen tarafın önceden oluşturduğu küçük bir 480p/
         *  %85 JPEG önizleme kapağı (foto/video için) — doluysa, TAM dosya
         *  hiç indirilmeden `bindAttachment`'ta küçük resim olarak
         *  gösterilir. */
        var previewJpeg: ByteArray? = null,
        /** Sadece sesli mesajlar için (mimeType "audio/" ile başlar) —
         *  bkz. Rust `FileOffer.duration_ms`. */
        var durationMs: Int? = null,
        /** Aşağıdaki üç alan SADECE sesli mesaj çalma durumunu yansıtır —
         *  ChatActivity'nin tek paylaşımlı MediaPlayer'ı tarafından
         *  yönetilir (bkz. `updateVoicePlayback`). */
        var isPlaying: Boolean = false,
        var playbackPositionMs: Int = 0,
        var playbackSpeed: Float = 1f
    )

    data class Item(
        val messageId: String,
        var text: String,
        val isMine: Boolean,
        val timestamp: Long = System.currentTimeMillis(),
        var status: Status = Status.SENT,
        var isEdited: Boolean = false,
        var isDeleted: Boolean = false,
        /** Sadece grup sohbetinde, kendi mesajımız değilse gösterilir. */
        val senderName: String? = null,
        /** Sadece grup sohbetinde, `senderName` ile birlikte gösterilir —
         *  bkz. AvatarUtil (fotoğraf yoksa baş harf rozeti). */
        val senderAvatarJpeg: ByteArray? = null,
        /** Doluysa bu bir metin değil, dosya eki balonudur (bkz.
         *  onBindViewHolder) — `messageId` bu durumda `file_id`'dir. */
        var attachment: AttachmentInfo? = null
    )

    /** Kendi mesajlarımıza uzun basıldığında tetiklenir (Düzenle/Sil menüsü
     *  ChatActivity/GroupChatActivity'de gösterilir — adapter sadece
     *  "hangi item" bilgisini taşır). */
    var onItemLongPress: ((Item) -> Unit)? = null
    /** Bir ek balonundaki "İndir" düğmesine (veya tamamlanmış bir eke)
     *  dokunulduğunda tetiklenir. */
    var onAttachmentClick: ((Item) -> Unit)? = null
    /** Spec dışı: tamamlanmış bir ek balonuna basılı tutulunca (ör.
     *  "İndirilenler/P2P"ye kaydet menüsünü açmak için) tetiklenir —
     *  bkz. `bindAttachment`, SADECE `AttachmentStatus.COMPLETE` iken
     *  etkin. */
    var onAttachmentLongClick: ((Item) -> Unit)? = null
    /** Sesli mesaj balonundaki oynat/duraklat düğmesine dokunulduğunda —
     *  ChatActivity tek paylaşımlı bir MediaPlayer ile gerçek çalmayı
     *  yönetir, adapter sadece "hangi item" bilgisini taşır. */
    var onVoicePlayClick: ((Item) -> Unit)? = null
    /** Hız rozetine (1x/1.5x/2x/0.5x) dokunulduğunda. */
    var onVoiceSpeedClick: ((Item) -> Unit)? = null

    private val timeFormat = SimpleDateFormat("HH:mm", Locale.getDefault())

    class BubbleViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val container: LinearLayout = itemView as LinearLayout
        val senderRow: View = itemView.findViewById(R.id.rowSender)
        val senderAvatar: ImageView = itemView.findViewById(R.id.imgSenderAvatar)
        val senderName: TextView = itemView.findViewById(R.id.txtSenderName)
        val textView: TextView = itemView.findViewById(R.id.txtBubbleText)
        val editedLabel: TextView = itemView.findViewById(R.id.txtEditedLabel)
        val timestamp: TextView = itemView.findViewById(R.id.txtTimestamp)
        val status: ImageView = itemView.findViewById(R.id.imgStatus)
        val layoutAttachment: LinearLayout = itemView.findViewById(R.id.layoutAttachment)
        val imgAttachmentThumbnail: ImageView = itemView.findViewById(R.id.imgAttachmentThumbnail)
        val rowGenericAttachment: View = itemView.findViewById(R.id.rowGenericAttachment)
        val txtAttachmentName: TextView = itemView.findViewById(R.id.txtAttachmentName)
        val txtAttachmentSize: TextView = itemView.findViewById(R.id.txtAttachmentSize)
        val progressAttachment: CircularProgressIndicator = itemView.findViewById(R.id.progressAttachment)
        val btnAttachmentDownload: Button = itemView.findViewById(R.id.btnAttachmentDownload)
        val layoutVoiceMessage: View = itemView.findViewById(R.id.layoutVoiceMessage)
        val btnVoicePlayPause: ImageView = itemView.findViewById(R.id.btnVoicePlayPause)
        val progressVoicePlayback: LinearProgressIndicator = itemView.findViewById(R.id.progressVoicePlayback)
        val txtVoiceDuration: TextView = itemView.findViewById(R.id.txtVoiceDuration)
        val btnVoiceSpeed: TextView = itemView.findViewById(R.id.btnVoiceSpeed)
    }

    fun indexOfMessageId(messageId: String): Int = items.indexOfFirst { it.messageId == messageId }

    fun addMessage(item: Item) {
        items.add(item)
        notifyItemInserted(items.size - 1)
    }

    /** Bir ekin durumunu/ilerlemesini günceller (bkz. pollNetwork
     *  "file_progress"/"file_complete"/"file_failed" olayları). Hedef
     *  bulunamazsa sessizce yok sayılır. */
    fun applyAttachmentUpdate(fileId: String, status: AttachmentStatus, bytesDone: Long? = null) {
        val idx = indexOfMessageId(fileId)
        if (idx < 0) return
        val attachment = items[idx].attachment ?: return
        attachment.status = status
        if (bytesDone != null) attachment.bytesDone = bytesDone
        notifyItemChanged(idx)
    }

    /** Sesli mesaj çalma durumunu günceller — ChatActivity'nin paylaşımlı
     *  MediaPlayer'ı periyodik olarak (çalarken) veya oynat/duraklat/hız
     *  değişince çağırır. Hedef bulunamazsa sessizce yok sayılır. */
    fun updateVoicePlayback(fileId: String, isPlaying: Boolean, positionMs: Int, speed: Float) {
        val idx = indexOfMessageId(fileId)
        if (idx < 0) return
        val attachment = items[idx].attachment ?: return
        attachment.isPlaying = isPlaying
        attachment.playbackPositionMs = positionMs
        attachment.playbackSpeed = speed
        notifyItemChanged(idx)
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
        val bubbleBackground = if (item.isMine) R.drawable.bubble_mine else R.drawable.bubble_theirs
        holder.textView.setBackgroundResource(bubbleBackground)
        holder.layoutAttachment.setBackgroundResource(bubbleBackground)

        val onColorAttr = if (item.isMine) {
            com.google.android.material.R.attr.colorOnPrimaryContainer
        } else {
            com.google.android.material.R.attr.colorOnSurfaceVariant
        }
        val onColor = MaterialColors.getColor(holder.textView, onColorAttr)
        holder.textView.setTextColor(onColor)
        holder.txtAttachmentName.setTextColor(onColor)

        if (!item.isMine && item.senderName != null) {
            holder.senderName.text = item.senderName
            AvatarUtil.renderInto(holder.senderAvatar, item.senderAvatarJpeg, item.senderName)
            holder.senderRow.visibility = View.VISIBLE
        } else {
            holder.senderRow.visibility = View.GONE
        }

        val attachment = item.attachment
        if (attachment != null) {
            holder.textView.visibility = View.GONE
            holder.editedLabel.visibility = View.GONE
            bindAttachment(holder, item, attachment)
        } else {
            holder.layoutAttachment.visibility = View.GONE
            holder.textView.visibility = View.VISIBLE
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
            // Ek balonları için düzenle/sil desteklenmiyor (bkz. dosya başı
            // notu) — sadece düz metin mesajları uzun basmaya tepki verir.
            if (item.isMine && !item.isDeleted && item.attachment == null) {
                onItemLongPress?.invoke(item)
                true
            } else {
                false
            }
        }
    }

    /** Bir ek balonunu doldurur: OFFERED/FAILED -> "İndir" düğmesi,
     *  DOWNLOADING -> ilerleme göstergesi, COMPLETE -> dokununca açılabilir
     *  (indirme düğmesi/ilerleme gizli, tüm satır tıklanabilir). Küçük
     *  resim önizlemesi bilinçli olarak v1 kapsamı DIŞINDA bırakıldı — her
     *  ek türü aynı jenerik dosya simgesi + ad/boyut satırıyla gösterilir,
     *  tamamlanmış bir görsele dokunmak sistem görüntüleyicisini açar
     *  (bkz. ChatActivity openAttachment).
     */
    private fun bindAttachment(holder: BubbleViewHolder, item: Item, attachment: AttachmentInfo) {
        holder.layoutAttachment.visibility = View.VISIBLE

        if (attachment.mimeType.startsWith("audio/")) {
            holder.imgAttachmentThumbnail.visibility = View.GONE
            holder.rowGenericAttachment.visibility = View.GONE
            holder.layoutVoiceMessage.visibility = View.VISIBLE
            bindVoiceMessage(holder, item, attachment)
            return
        }
        holder.layoutVoiceMessage.visibility = View.GONE
        holder.rowGenericAttachment.visibility = View.VISIBLE
        holder.txtAttachmentName.text = attachment.fileName
        val context = holder.itemView.context

        // Spec dışı: küçük (birkaç on KB) bir JPEG olduğundan senkron
        // decode burada kabul edilebilir — ayrı bir yükleme thread'i/
        // görsel yükleme kütüphanesi gerektirmiyor. Doluysa TAM dosya hiç
        // indirilmeden bir önizleme gösterilir.
        val preview = attachment.previewJpeg
        if (preview != null) {
            val bitmap = try {
                android.graphics.BitmapFactory.decodeByteArray(preview, 0, preview.size)
            } catch (e: Exception) {
                null
            }
            if (bitmap != null) {
                holder.imgAttachmentThumbnail.visibility = View.VISIBLE
                holder.imgAttachmentThumbnail.setImageBitmap(bitmap)
            } else {
                holder.imgAttachmentThumbnail.visibility = View.GONE
            }
        } else {
            holder.imgAttachmentThumbnail.visibility = View.GONE
        }

        holder.txtAttachmentSize.text = when (attachment.status) {
            AttachmentStatus.DOWNLOADING -> context.getString(R.string.msg_attachment_downloading) +
                " " + Formatter.formatShortFileSize(context, attachment.bytesDone) + " / " +
                Formatter.formatShortFileSize(context, attachment.totalSize)
            AttachmentStatus.FAILED -> context.getString(R.string.msg_attachment_failed)
            else -> Formatter.formatShortFileSize(context, attachment.totalSize)
        }

        if (attachment.status == AttachmentStatus.DOWNLOADING) {
            holder.progressAttachment.visibility = View.VISIBLE
            val max = attachment.totalSize.coerceAtLeast(1L)
            // Spec dışı Material You: `setProgressCompat(.., true)` yüzde
            // sıçramak yerine akıcı animasyonla ilerler — bkz. dosya başı
            // "gerçek belirlenimli ilerleme" notu.
            holder.progressAttachment.max = 1000
            val fraction = ((attachment.bytesDone.toDouble() / max.toDouble()) * 1000).toInt().coerceIn(0, 1000)
            holder.progressAttachment.setProgressCompat(fraction, true)
        } else {
            holder.progressAttachment.visibility = View.GONE
        }
        holder.btnAttachmentDownload.visibility = if (attachment.status == AttachmentStatus.OFFERED || attachment.status == AttachmentStatus.FAILED) View.VISIBLE else View.GONE

        val clickListener = View.OnClickListener {
            if (attachment.status != AttachmentStatus.DOWNLOADING) {
                onAttachmentClick?.invoke(item)
            }
        }
        holder.btnAttachmentDownload.setOnClickListener(clickListener)
        holder.layoutAttachment.setOnClickListener(clickListener)
        holder.layoutAttachment.setOnLongClickListener {
            if (attachment.status == AttachmentStatus.COMPLETE) {
                onAttachmentLongClick?.invoke(item)
                true
            } else {
                false
            }
        }
    }

    /**
     * Spec dışı: sesli mesaj balonu. OFFERED/DOWNLOADING/FAILED durumunda
     * çubuk indirme ilerlemesini gösterir, oynat düğmesi indirmeyi tetikler
     * (bkz. `onAttachmentClick` — jenerik ekle AYNI tetikleyici). COMPLETE
     * olunca çubuk ÇALMA konumuna döner, oynat/duraklat + hız rozeti etkin
     * olur.
     */
    private fun bindVoiceMessage(holder: BubbleViewHolder, item: Item, attachment: AttachmentInfo) {
        val isComplete = attachment.status == AttachmentStatus.COMPLETE
        val durationMs = attachment.durationMs ?: 0

        holder.progressVoicePlayback.max = 1000
        if (isComplete) {
            val fraction = if (durationMs > 0) {
                ((attachment.playbackPositionMs.toDouble() / durationMs.toDouble()) * 1000).toInt().coerceIn(0, 1000)
            } else 0
            holder.progressVoicePlayback.setProgressCompat(fraction, attachment.isPlaying)
            val remaining = (durationMs - attachment.playbackPositionMs).coerceAtLeast(0)
            holder.txtVoiceDuration.text = formatDuration(if (attachment.isPlaying || attachment.playbackPositionMs > 0) remaining else durationMs)
            holder.btnVoicePlayPause.setImageResource(if (attachment.isPlaying) R.drawable.ic_pause else R.drawable.ic_play)
            holder.btnVoiceSpeed.visibility = View.VISIBLE
            holder.btnVoiceSpeed.text = formatSpeed(attachment.playbackSpeed)
            holder.btnVoicePlayPause.setOnClickListener { onVoicePlayClick?.invoke(item) }
            holder.btnVoiceSpeed.setOnClickListener { onVoiceSpeedClick?.invoke(item) }
            holder.layoutVoiceMessage.setOnLongClickListener {
                onAttachmentLongClick?.invoke(item)
                true
            }
        } else {
            val max = attachment.totalSize.coerceAtLeast(1L)
            val fraction = attachment.status.let {
                if (it == AttachmentStatus.DOWNLOADING) ((attachment.bytesDone.toDouble() / max.toDouble()) * 1000).toInt().coerceIn(0, 1000) else 0
            }
            holder.progressVoicePlayback.setProgressCompat(fraction, true)
            holder.txtVoiceDuration.text = when (attachment.status) {
                AttachmentStatus.FAILED -> holder.itemView.context.getString(R.string.msg_attachment_failed)
                AttachmentStatus.DOWNLOADING -> holder.itemView.context.getString(R.string.msg_attachment_downloading)
                else -> if (durationMs > 0) formatDuration(durationMs) else ""
            }
            holder.btnVoicePlayPause.setImageResource(R.drawable.ic_play)
            holder.btnVoiceSpeed.visibility = View.GONE
            val downloadListener = View.OnClickListener {
                if (attachment.status != AttachmentStatus.DOWNLOADING) onAttachmentClick?.invoke(item)
            }
            holder.btnVoicePlayPause.setOnClickListener(downloadListener)
            holder.btnVoiceSpeed.setOnClickListener(null)
            holder.layoutVoiceMessage.setOnLongClickListener(null)
        }
    }

    private fun formatDuration(ms: Int): String {
        val totalSeconds = ms / 1000
        val minutes = totalSeconds / 60
        val seconds = totalSeconds % 60
        return String.format(Locale.getDefault(), "%d:%02d", minutes, seconds)
    }

    private fun formatSpeed(speed: Float): String {
        val trimmed = if (speed == speed.toInt().toFloat()) speed.toInt().toString() else speed.toString()
        return "${trimmed}x"
    }

    override fun getItemCount(): Int = items.size
}
