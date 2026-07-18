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
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.slider.Slider
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

    /** bkz. `applySeen`/`lastSeenAvatars` — `displayName` yalnızca bu
     *  kişinin fotoğrafı yoksa baş harf rozeti üretmek için (bkz.
     *  AvatarUtil). */
    data class SeenByViewer(val avatarJpeg: ByteArray?, val displayName: String)

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
        /** Spec dışı, kullanıcı isteği (ETA sayacı): indirmenin başladığı
         *  an (ms). İlk `file_progress` olayında set edilir; kalan süre
         *  ortalama hızdan (bytesDone / geçen süre) hesaplanır. */
        var downloadStartedAt: Long = 0L,
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
    /** Kullanıcı bir sesli mesajın kaydırıcısını sürükleyip bırakınca —
     *  hedef konum milisaniye olarak taşınır. */
    var onVoiceSeek: ((Item, Int) -> Unit)? = null

    /** bkz. `tickVoicePlayback` — çalma sırasında HER karede tam
     *  `notifyItemChanged` (yeniden bind) yapmak yerine, o an ekranda
     *  bağlı olan ViewHolder'a doğrudan yazmak için. Sürükleniyorken
     *  (bkz. `userSeekingFileIds`) programatik güncelleme ATLANIR, aksi
     *  halde kullanıcının parmağı sürüklerken kaydırıcı sürekli geri
     *  sıçrardı. */
    private val boundVoiceHolders = mutableMapOf<String, BubbleViewHolder>()
    private val userSeekingFileIds = mutableSetOf<String>()

    /** Spec dışı, kullanıcı isteği: "görüldü" bilgisi SADECE en son
     *  görülen (kendi gönderdiğimiz) mesajın altında gösterilir — önceki
     *  tüm mesajlar örtük olarak görülmüş sayılır (WhatsApp/Telegram
     *  deseni). `applySeen` bu ikisini günceller; `onBindViewHolder`
     *  sadece `messageId == lastSeenMessageId` olan satırda avatar
     *  satırını gösterir. */
    private var lastSeenMessageId: String? = null
    private var lastSeenAvatars: List<SeenByViewer> = emptyList()

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
        val progressAttachment: LinearProgressIndicator = itemView.findViewById(R.id.progressAttachment)
        val txtAttachmentEta: TextView = itemView.findViewById(R.id.txtAttachmentEta)
        val btnAttachmentDownload: Button = itemView.findViewById(R.id.btnAttachmentDownload)
        val layoutVoiceMessage: View = itemView.findViewById(R.id.layoutVoiceMessage)
        val btnVoicePlayPause: ImageView = itemView.findViewById(R.id.btnVoicePlayPause)
        val progressVoicePlayback: Slider = itemView.findViewById(R.id.progressVoicePlayback)
        val txtVoiceDuration: TextView = itemView.findViewById(R.id.txtVoiceDuration)
        val btnVoiceSpeed: TextView = itemView.findViewById(R.id.btnVoiceSpeed)
        val rowSeenBy: View = itemView.findViewById(R.id.rowSeenBy)
        val imgSeenBy1: ImageView = itemView.findViewById(R.id.imgSeenBy1)
        val imgSeenBy2: ImageView = itemView.findViewById(R.id.imgSeenBy2)
        val imgSeenBy3: ImageView = itemView.findViewById(R.id.imgSeenBy3)
        val txtSeenByMore: TextView = itemView.findViewById(R.id.txtSeenByMore)
    }

    override fun onViewRecycled(holder: BubbleViewHolder) {
        super.onViewRecycled(holder)
        val fileId = holder.itemView.getTag(R.id.layoutVoiceMessage) as? String
        if (fileId != null && boundVoiceHolders[fileId] === holder) {
            boundVoiceHolders.remove(fileId)
            userSeekingFileIds.remove(fileId)
        }
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
        // Spec dışı, kullanıcı isteği (ETA): indirme başlangıcını ilk
        // DOWNLOADING geçişinde damgala; tamamlanınca/başarısız olunca
        // sıfırla ki olası bir yeniden denemede taze ölçüm yapılsın.
        if (status == AttachmentStatus.DOWNLOADING) {
            if (attachment.downloadStartedAt == 0L) {
                attachment.downloadStartedAt = System.currentTimeMillis()
            }
        } else {
            attachment.downloadStartedAt = 0L
        }
        attachment.status = status
        if (bytesDone != null) attachment.bytesDone = bytesDone
        notifyItemChanged(idx)
    }

    /** Sesli mesaj çalma durumunu günceller — ChatActivity oynat/duraklat/
     *  hız DEĞİŞİKLİKLERİNDE (sık olmayan olaylar) çağırır, tam bir
     *  `notifyItemChanged` (yeniden bind) tetikler. Sık aralıklı ilerleme
     *  karolarını (200ms'de bir) bunun YERİNE `tickVoicePlayback`
     *  kullanmalı — aksi halde sürekli yeniden bind, kullanıcı
     *  kaydırıcıyı sürüklerken elini altından "kayardı". */
    fun updateVoicePlayback(fileId: String, isPlaying: Boolean, positionMs: Int, speed: Float) {
        val idx = indexOfMessageId(fileId)
        if (idx < 0) return
        val attachment = items[idx].attachment ?: return
        attachment.isPlaying = isPlaying
        attachment.playbackPositionMs = positionMs
        attachment.playbackSpeed = speed
        notifyItemChanged(idx)
    }

    /** bkz. dosya başı `boundVoiceHolders` notu — çalma sırasında sık
     *  aralıklı (200ms) konum güncellemesi için, TAM yeniden bind
     *  YAPMADAN doğrudan o an ekranda bağlı ViewHolder'a yazar. Item
     *  ekranda değilse (kaydırılıp gitmişse) sessizce yok sayılır —
     *  `attachment.playbackPositionMs` yine de item verisinde güncel
     *  tutulur ki tekrar ekrana gelince doğru konumla göstersin. */
    fun tickVoicePlayback(fileId: String, positionMs: Int, durationMs: Int) {
        val idx = indexOfMessageId(fileId)
        if (idx >= 0) items[idx].attachment?.playbackPositionMs = positionMs
        if (fileId in userSeekingFileIds) return
        val holder = boundVoiceHolders[fileId] ?: return
        val slider = holder.progressVoicePlayback
        val safeDuration = durationMs.coerceAtLeast(1)
        if (slider.valueTo != safeDuration.toFloat()) slider.valueTo = safeDuration.toFloat()
        slider.value = positionMs.toFloat().coerceIn(0f, slider.valueTo)
        val remaining = (durationMs - positionMs).coerceAtLeast(0)
        holder.txtVoiceDuration.text = formatDuration(remaining)
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

    /**
     * Bir "görüldü" bildirimi uygular — bkz. `lastSeenMessageId` dosya
     * başı notu. `viewerAvatars`: bu mesajı gören(ler)in TAM güncel
     * listesi (artımlı değil — çağıran taraf, ör. bir grupta zamanla
     * birikensetten, HER seferinde tam listeyi geçirmeli). Hedef mesaj,
     * şu an "en son görülen" olarak işaretliden DAHA YENİ veya AYNIYSA
     * (ör. aynı gruptaki başka bir üye de aynı mesajı gördüyse)
     * güncellenir — daha ESKİ bir mesaj için gelen bir bildirim (nadir,
     * ör. sıra dışı geliş) yok sayılır ki gösterge geri gitmesin.
     */
    fun applySeen(targetMessageId: String, viewerAvatars: List<SeenByViewer>) {
        val idx = indexOfMessageId(targetMessageId)
        if (idx < 0) return
        val previousId = lastSeenMessageId
        val previousIdx = previousId?.let { indexOfMessageId(it) } ?: -1
        if (idx < previousIdx) return
        lastSeenMessageId = targetMessageId
        lastSeenAvatars = viewerAvatars
        if (previousId != null && previousId != targetMessageId && previousIdx >= 0) {
            notifyItemChanged(previousIdx)
        }
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

        if (item.isMine && !item.isDeleted && item.messageId == lastSeenMessageId && lastSeenAvatars.isNotEmpty()) {
            bindSeenBy(holder)
        } else {
            holder.rowSeenBy.visibility = View.GONE
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
            // Spec dışı, kullanıcı isteği: kalan süre (ETA) — ortalama hız
            // (indirilen bayt / geçen süre) üzerinden. Henüz ölçecek kadar
            // veri yoksa gizli kalır (yanıltıcı bir tahmin göstermektense).
            val etaText = formatEta(context, attachment)
            if (etaText != null) {
                holder.txtAttachmentEta.visibility = View.VISIBLE
                holder.txtAttachmentEta.text = etaText
            } else {
                holder.txtAttachmentEta.visibility = View.GONE
            }
        } else {
            holder.progressAttachment.visibility = View.GONE
            holder.txtAttachmentEta.visibility = View.GONE
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
        val slider = holder.progressVoicePlayback

        holder.itemView.setTag(R.id.layoutVoiceMessage, attachment.fileId)
        boundVoiceHolders[attachment.fileId] = holder

        if (isComplete) {
            slider.isEnabled = true
            val safeDuration = durationMs.coerceAtLeast(1)
            // `valueTo` degistirmeden once `value`'nun gecerli araliktan
            // disari cikmamasi icin sira onemli (Slider, value > valueTo
            // ise IllegalStateException firlatir).
            slider.value = 0f
            slider.valueTo = safeDuration.toFloat()
            slider.value = attachment.playbackPositionMs.toFloat().coerceIn(0f, safeDuration.toFloat())
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
            slider.clearOnSliderTouchListeners()
            slider.addOnSliderTouchListener(object : Slider.OnSliderTouchListener {
                override fun onStartTrackingTouch(s: Slider) { userSeekingFileIds.add(attachment.fileId) }
                override fun onStopTrackingTouch(s: Slider) {
                    userSeekingFileIds.remove(attachment.fileId)
                    onVoiceSeek?.invoke(item, s.value.toInt())
                }
            })
        } else {
            slider.isEnabled = false
            val safeTotal = attachment.totalSize.coerceAtLeast(1L).toFloat()
            slider.value = 0f
            slider.valueTo = safeTotal
            val downloaded = if (attachment.status == AttachmentStatus.DOWNLOADING) attachment.bytesDone.toFloat() else 0f
            slider.value = downloaded.coerceIn(0f, safeTotal)
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
            slider.clearOnSliderTouchListeners()
        }
    }

    /** En fazla 3 küçük avatar gösterir, fazlası "+N" ile özetlenir —
     *  1:1 sohbette `lastSeenAvatars` her zaman tek elemanlıdır, grup
     *  sohbetinde birden fazla üyenin avatarı olabilir. */
    private fun bindSeenBy(holder: BubbleViewHolder) {
        holder.rowSeenBy.visibility = View.VISIBLE
        val avatars = lastSeenAvatars
        val slots = listOf(holder.imgSeenBy1, holder.imgSeenBy2, holder.imgSeenBy3)
        for (i in slots.indices) {
            if (i < avatars.size && i < 3) {
                slots[i].visibility = View.VISIBLE
                AvatarUtil.renderInto(slots[i], avatars[i].avatarJpeg, avatars[i].displayName)
            } else {
                slots[i].visibility = View.GONE
            }
        }
        val overflow = avatars.size - 3
        if (overflow > 0) {
            holder.txtSeenByMore.visibility = View.VISIBLE
            holder.txtSeenByMore.text = "+$overflow"
        } else {
            holder.txtSeenByMore.visibility = View.GONE
        }
    }

    /** Spec dışı, kullanıcı isteği: kalan süre (ETA) metni. Ortalama hız
     *  (indirilen bayt / geçen süre) üzerinden hesaplanır — anlık hız
     *  yerine ortalama, ağdaki dalgalanmalarda çok daha kararlı bir tahmin
     *  verir. Ölçüm için yeterli veri yoksa (henüz başlamadı, 1 sn'den az
     *  geçti, veya hiç bayt inmedi) `null` döner ve sayaç gizlenir —
     *  yanıltıcı bir "0 sn kaldı" göstermemek için. */
    private fun formatEta(context: android.content.Context, attachment: AttachmentInfo): String? {
        val startedAt = attachment.downloadStartedAt
        if (startedAt <= 0L) return null
        val elapsedMs = System.currentTimeMillis() - startedAt
        if (elapsedMs < 1000L) return null
        val done = attachment.bytesDone
        if (done <= 0L) return null
        val remaining = attachment.totalSize - done
        if (remaining <= 0L) return null
        val bytesPerMs = done.toDouble() / elapsedMs.toDouble()
        if (bytesPerMs <= 0.0) return null
        val etaSeconds = (remaining.toDouble() / bytesPerMs / 1000.0).toLong()
        return if (etaSeconds >= 60) {
            context.getString(R.string.lbl_eta_minutes, etaSeconds / 60, etaSeconds % 60)
        } else {
            context.getString(R.string.lbl_eta_seconds, etaSeconds.coerceAtLeast(1))
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
