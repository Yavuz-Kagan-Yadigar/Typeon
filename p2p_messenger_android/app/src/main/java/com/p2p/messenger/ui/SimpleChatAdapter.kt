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
import com.p2p.messenger.util.formatAbsoluteTime
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

    companion object {
        private const val GROUP_WINDOW_MS = 2 * 60 * 1000L
        private const val ORDER_MAX_AGE_MS = 31L * 24 * 60 * 60 * 1000
    }

    enum class Status { PENDING, SENT, DELIVERED, ERROR }

    /** Decoded attachment previews by file id: a rebind does not decode again. */
    private val previewCache = object : android.util.LruCache<String, android.graphics.Bitmap>(24 * 1024 * 1024) {
        override fun sizeOf(key: String, value: android.graphics.Bitmap): Int = value.byteCount
    }

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
        var playbackSpeed: Float = 1f,
        /** Spec dışı, kullanıcı isteği (grup ekleri): SADECE grup sohbetinde
         *  dolu — bu ekin `downloadFile` ile HANGİ göndericiden isteneceği
         *  (1:1'de bu her zaman tek bir sabit peer olduğundan gerek yok,
         *  ChatActivity kendi `peerDeviceFingerprint` alanını kullanır). */
        var peerDeviceFingerprint: String = "",
        /** Spec dışı, kullanıcı isteği (WhatsApp tarzı çıkartmalar): bu ek
         *  bir çıkartma mı? Çıkartmalar çerçevesiz gösterilir (bkz.
         *  `bindSticker`) — Rust `FileOffer.sticker` bayrağı. */
        var isSticker: Boolean = false
    )

    data class Item(
        /** Spec dışı, kullanıcı isteği (başarısız mesajı yeniden gönder):
         *  `var` — bir retry, AYNI balonu tutup içindeki mesaj kimliğini
         *  yeni gönderimin kimliğiyle değiştirir (bkz. `retryMessage`),
         *  ikinci bir balon oluşturmaz. */
        var messageId: String,
        var text: String,
        val isMine: Boolean,
        val timestamp: Long = System.currentTimeMillis(),
        /** Spec dışı, kullanıcı isteği: SADECE alınan (`!isMine`) mesajlar
         *  için, göndericinin KENDİ cihazındaki gönderim anı (bkz. Rust
         *  `MessageContent::Text.sent_at_ms`) — `timestamp` (bu cihazın
         *  ALDIĞI an) ile birlikte "10:42 (sent at: 10:41)" gibi ikisini
         *  ayrı ayrı gösterebilmek için. `null`/`0` = bilinmiyor (eski
         *  sürüm göndericisi, ya da yerel geçmişten yüklenmiş — bkz.
         *  ChatActivity/GroupChatActivity notu, SADECE canlı gelen
         *  olaylarda dolduruluyor) — bu durumda `timestamp` tek başına
         *  gösterilir, önceki davranışla AYNI. */
        val sentAtMs: Long? = null,
        var status: Status = Status.SENT,
        var isEdited: Boolean = false,
        var isDeleted: Boolean = false,
        /** Sadece grup sohbetinde, kendi mesajımız değilse gösterilir. */
        val senderName: String? = null,
        /** SADECE grup sohbetinde dolu — bu mesajı gönderenin HAM
         *  `identity_id`'si (`isMine` ise bu cihazın kendi kimliği).
         *  `senderName` görüntü amaçlı çözülmüş isimken, BU alan bir
         *  yanıt başlatıldığında (bkz. GroupChatActivity.startReply)
         *  `reply_to_sender_identity_id` olarak gönderilmek üzere saklanır
         *  — alıcı taraf, yanıtlanan mesajı yerelde bulamazsa bunu bir
         *  YEDEK olarak kullanıp yine de doğru ada çözebilsin diye (bkz.
         *  `resolveReplyLabel`). */
        val senderIdentityId: String? = null,
        /** Sadece grup sohbetinde, `senderName` ile birlikte gösterilir —
         *  bkz. AvatarUtil (fotoğraf yoksa baş harf rozeti). */
        val senderAvatarJpeg: ByteArray? = null,
        /** Doluysa bu bir metin değil, dosya eki balonudur (bkz.
         *  onBindViewHolder) — `messageId` bu durumda `file_id`'dir. */
        var attachment: AttachmentInfo? = null,
        /** Spec dışı, kullanıcı isteği (WhatsApp tarzı "sağa kaydırıp
         *  yanıtla"): bu mesaj başka bir mesaja yanıtsa, o mesajın kararlı
         *  kimliği (1:1'de `message_id`, grupta `group_message_local_id`) —
         *  dolu olması balonun içinde küçük bir alıntı kutusu gösterilmesini
         *  tetikler (bkz. `onBindViewHolder`/`onReplyPreviewClick`, ona
         *  dokununca sohbet bu id'ye kaydırılır). */
        /** Spec dışı, kullanıcı isteği: bu mesaja bırakılmış tepkilerin
         *  hazır özeti (ör. "👍2 ❤️"); boş = tepki yok. Rust tarafında
         *  hesaplanıp hem geçmiş JSON'unda hem canlı `reaction` olayında
         *  aynen geliyor (bkz. `reactions_summary`) — burada ayrıca bir
         *  toplama/sayma YAPILMAZ, böylece her cihaz aynı dizeyi gösterir. */
        var reactions: String = "",
        /** Spec dışı, kullanıcı isteği: ek balonunun ALTINDA gösterilen
         *  açıklama metni (boş = yok). Metin mesajlarında kullanılmaz —
         *  onların metni zaten `text`. */
        var caption: String = "",
        var replyToMessageId: String? = null,
        /** Yanıtlanan mesajın (gönderen tarafından gömülen) kısa metin
         *  özeti — bu cihazın o mesajı yerelde arşivlemiş olması
         *  GEREKMEZ. */
        var replyToPreview: String? = null,
        /** Alıntı kutusunda gösterilecek "kime yanıt verildiği" etiketi —
         *  1:1'de sabit "Sen" (bkz. R.string.lbl_you) ya da kişi adı,
         *  grupta yanıtlanan mesajın göndericisinin adı. Çağıran taraf
         *  (ChatActivity/GroupChatActivity) zaten bu ismi bildiğinden
         *  BURADA ayrıca bir kimlik çözümlemesi yapılmaz. */
        var replyToSenderLabel: String? = null,
        /** SADECE grup mesajlarında dolu — yanıtlanan mesajı gönderenin HAM
         *  `identity_id`'si (bkz. Rust `MessageContent::Text.
         *  reply_to_sender_identity_id`). `replyToSenderLabel`'ı hesaplayan
         *  taraf (bkz. GroupChatActivity.resolveReplyLabel), yanıtlanan
         *  mesaj bu cihazda YERELDE bulunamazsa (ör. hiç senkronlanmadı)
         *  BUNU bir YEDEK olarak kullanır — `resolveContactByIdentity` ile
         *  kişi listesinden ada çevrilebilir, yerel arşive bakmaya gerek
         *  kalmadan. */
        var replyToSenderIdentityId: String? = null
    ) {
        /** Spec dışı, kullanıcı isteği (gönderim-sırası): balonların SIRALAMA
         *  anahtarı — göndericinin gönderim anı (`sentAtMs`), bilinmiyorsa
         *  bu cihazın aldığı/oluşturduğu an (`timestamp`). Gecikmeli teslim
         *  edilen bir mesaj, ALINMA değil GÖNDERİM sırasındaki yerine oturur
         *  (bkz. `addMessage` sıralı ekleme).
         *
         *  BİLİNEN SINIR (dış inceleme, kasıtlı olarak düzeltilmedi): bu,
         *  göndericinin HAM yerel saatidir — senkronize bir mantıksal
         *  (Lamport/vector clock) sayaç DEĞİLDİR. Aynı kişinin farklı
         *  cihazları (ör. Ahmet'in telefonu + laptop'u) neredeyse aynı anda
         *  mesaj gönderirse, iki cihazın sistem saatleri arasında kayma
         *  varsa sıra karışabilir. Bunu KESİN çözmek, her identity için
         *  cihazlar arası senkronize bir mantıksal sayaç (yeni bir kablo
         *  alanı + DB kolonu + `SiblingEcho` üzerinden senkron) gerektirir
         *  — gerçek fayda alanı dar (aynı kişinin İKİ cihazının aynı
         *  saniye içinde, senkron olmadan yazması) olduğundan ve yanlış
         *  uygulanırsa asıl mesaj sıralamasını BOZMA riski gerçek olduğundan
         *  şimdilik ertelendi. */
        val orderKey: Long get() = sentAtMs?.takeIf { it > 0 }
            // The sender's clock is not trusted without bounds: nothing was
            // sent after we received it, and the server holds mail 30 days.
            // A clock far ahead used to pin a message to the bottom forever.
            ?.coerceIn(timestamp - ORDER_MAX_AGE_MS, timestamp) ?: timestamp
    }

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
    /** Spec dışı, kullanıcı isteği (WhatsApp tarzı yanıt): bir balonun
     *  içindeki küçük alıntı kutusuna dokunulduğunda — hedef
     *  `replyToMessageId` taşınır, çağıran taraf (bkz. ChatActivity/
     *  GroupChatActivity) sohbeti o mesaja kaydırır. */
    var onReplyPreviewClick: ((String) -> Unit)? = null

    /** bkz. `tickVoicePlayback` — çalma sırasında HER karede tam
     *  `notifyItemChanged` (yeniden bind) yapmak yerine, o an ekranda
     *  bağlı olan ViewHolder'a doğrudan yazmak için. Sürükleniyorken
     *  (bkz. `userSeekingFileIds`) programatik güncelleme ATLANIR, aksi
     *  halde kullanıcının parmağı sürüklerken kaydırıcı sürekli geri
     *  sıçrardı. */
    private val boundVoiceHolders = mutableMapOf<String, BubbleViewHolder>()
    private val userSeekingFileIds = mutableSetOf<String>()

    /** Spec dışı, kullanıcı isteği (WhatsApp tarzı çıkartmalar): çıkartma
     *  balonunun görseli. Çözme (JNI) + decode ana thread'de yapılmaz —
     *  çağıran taraf (ChatActivity/GroupChatActivity) arka planda çözer,
     *  `done` ile hazır çizimi verir. */
    var stickerImageProvider: ((fileId: String, done: (android.graphics.drawable.Drawable?) -> Unit) -> Unit)? = null

    /** Çözülmüş çıkartma çizimleri (dosya id -> çizim). */
    private val stickerImages = android.util.LruCache<String, android.graphics.drawable.Drawable>(16)
    /** Çözülmekte olan çıkartmalar — aynı dosya için ikinci istek atılmasın. */
    private val stickerPending = mutableSetOf<String>()

    /** Consecutive same-sender messages within this window merge visually
     *  (tighter spacing, single trailing timestamp, sender name/avatar
     *  shown once) — WhatsApp/Telegram-style grouping. */
    private fun isSameSender(a: Item, b: Item): Boolean {
        if (a.isMine != b.isMine) return false
        return a.isMine || a.senderIdentityId == b.senderIdentityId
    }

    private fun isGroupedWithPrevious(position: Int): Boolean {
        if (position <= 0) return false
        val prev = items[position - 1]
        val cur = items[position]
        if (prev.isDeleted || cur.isDeleted) return false
        // Spec dışı, kullanıcı isteği (WhatsApp tarzı çıkartmalar): bir
        // çıkartma ÇERÇEVESİZ gösterilir — komşusuyla birleşmez.
        if (isSticker(cur) || isSticker(prev)) return false
        // Spec dışı, hata düzeltmesi (kullanıcı: "alıntılar bozuk"): bir
        // alıntı kutusu balonun İÇİNDE değil, ÜSTÜNDE ayrı bir blok olarak
        // duruyor (bkz. item_message_bubble.xml `layoutReplyQuote`). Yani
        // iki balon arasına dikey bir boşluk giriyor ve birleşik dış hat
        // (bkz. MergedBubbleDecoration) o boşluğu da doldurup alıntının
        // arkasını boyuyordu. Alıntılı bir mesaj zaten görsel olarak yeni
        // bir başlangıç — grubu burada kesmek hem doğrusu hem de en basiti.
        if (cur.replyToMessageId != null) return false
        if (!isSameSender(prev, cur)) return false
        // Send order, like the sort: messages sent hours apart and delivered
        // together are not one group.
        return cur.orderKey - prev.orderKey in 0 until GROUP_WINDOW_MS
    }

    /** bkz. MergedBubbleDecoration — birleşik şekli çizen dekorasyon,
     *  grubun sınırlarını ve hangi tarafa yaslı olduğunu bilmek zorunda. */
    fun isGroupedWithNextPublic(position: Int): Boolean = isGroupedWithNext(position)

    fun isMineAt(position: Int): Boolean = items.getOrNull(position)?.isMine ?: false

    /** Spec dışı, kullanıcı isteği (WhatsApp tarzı çıkartmalar): bu satır
     *  bir çıkartma mı (çerçevesiz gösterilir)? */
    fun isStickerAt(position: Int): Boolean = isSticker(items.getOrNull(position))

    private fun isSticker(item: Item?): Boolean = item?.attachment?.isSticker == true

    private fun isGroupedWithNext(position: Int): Boolean {
        if (position >= items.size - 1) return false
        val cur = items[position]
        val next = items[position + 1]
        if (cur.isDeleted || next.isDeleted) return false
        // bkz. `isGroupedWithPrevious` — bir çıkartma komşusuyla birleşmez.
        if (isSticker(cur) || isSticker(next)) return false
        // Same break as `isGroupedWithPrevious`: a bubble followed by a
        // reply ends its group, otherwise it never showed its time.
        if (next.replyToMessageId != null) return false
        if (!isSameSender(cur, next)) return false
        return next.orderKey - cur.orderKey in 0 until GROUP_WINDOW_MS
    }

    /** Spec dışı, kullanıcı isteği: "görüldü" bilgisi SADECE en son
     *  görülen (kendi gönderdiğimiz) mesajın altında gösterilir — önceki
     *  tüm mesajlar örtük olarak görülmüş sayılır (WhatsApp/Telegram
     *  deseni). `applySeen` bu ikisini günceller; `onBindViewHolder`
     *  sadece `messageId == lastSeenMessageId` olan satırda avatar
     *  satırını gösterir. */
    private var lastSeenMessageId: String? = null
    private var lastSeenAvatars: List<SeenByViewer> = emptyList()

    /**
     * Spec dışı, hata düzeltmesi (kullanıcı raporu: "görülmeyle chatte
     * hareket eden profil fotoğrafları geç ve yanlış oluyor bazen").
     *
     * `applySeen` hedef mesajı listede bulamazsa ESKİDEN olayı tamamen
     * DÜŞÜRÜYORDU. Bu, düşünüldüğünden çok daha sık oluyor: "görüldü"
     * bildirimi, karşı taraf sohbeti açar açmaz gelir ve bizim
     * gönderdiğimiz mesajın balonu o an listeye HENÜZ eklenmemiş olabilir
     * (arşivden sayfa yükleniyor, ya da olay sırası gereği). Sonuç:
     * avatarlar ya hiç görünmüyor ya da bir SONRAKİ bildirimle geç
     * görünüyordu — ve bu arada gösterge, gerçekte daha yeni bir mesaj
     * görülmüşken hâlâ ESKİ mesajın yanında durduğu için "yanlış" oluyordu.
     *
     * Artık uygulanamayan bildirim burada bekletiliyor ve hedef mesaj
     * listeye girdiği anda (bkz. `addMessage`) uygulanıyor.
     */
    private var pendingSeenMessageId: String? = null
    private var pendingSeenAvatars: List<SeenByViewer> = emptyList()

    /** Spec dışı, kullanıcı isteği: sohbet içi mesaj arama — o an
     *  "hedeflenen" eşleşmeyi geçici olarak vurgular (bkz. `setHighlighted`,
     *  ChatActivity/GroupChatActivity arama gezinme düğmeleri). */
    private var highlightedMessageId: String? = null

    class BubbleViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val container: LinearLayout = itemView as LinearLayout
        val senderRow: View = itemView.findViewById(R.id.rowSender)
        val senderAvatar: ImageView = itemView.findViewById(R.id.imgSenderAvatar)
        val senderName: TextView = itemView.findViewById(R.id.txtSenderName)
        val bubble: LinearLayout = itemView.findViewById(R.id.layoutBubble)
        val pillReactions: TextView = itemView.findViewById(R.id.pillReactions)
        val txtAttachmentCaption: TextView = itemView.findViewById(R.id.txtAttachmentCaption)
        val textView: TextView = itemView.findViewById(R.id.txtBubbleText)
        val layoutReplyQuote: View = itemView.findViewById(R.id.layoutReplyQuote)
        val viewReplyQuoteBar: View = itemView.findViewById(R.id.viewReplyQuoteBar)
        val txtReplyQuoteSender: TextView = itemView.findViewById(R.id.txtReplyQuoteSender)
        val txtReplyQuoteText: TextView = itemView.findViewById(R.id.txtReplyQuoteText)
        val editedLabel: TextView = itemView.findViewById(R.id.txtEditedLabel)
        val timestamp: TextView = itemView.findViewById(R.id.txtTimestamp)
        val status: ImageView = itemView.findViewById(R.id.imgStatus)
        val layoutAttachment: LinearLayout = itemView.findViewById(R.id.layoutAttachment)
        val imgAttachmentThumbnail: ImageView = itemView.findViewById(R.id.imgAttachmentThumbnail)
        /** Spec dışı, kullanıcı isteği (WhatsApp tarzı çıkartmalar): çıkartma
         *  balonunun görseli (çerçevesiz). */
        val imgSticker: ImageView = itemView.findViewById(R.id.imgSticker)
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

    /**
     * Applies freshly loaded history to rows that are ALREADY on screen.
     * The live listener is detached while a chat is paused, so a download
     * that finished, an edit, a delete or a pending->sent change in that
     * time never reached the bubble: it stayed "downloading" until the chat
     * was closed and reopened. Returns true if any row changed.
     */
    fun refreshFrom(loaded: List<Item>): Boolean {
        val byId = loaded.associateBy { it.messageId }
        var changed = false
        for (i in items.indices) {
            val old = items[i]
            val now = byId[old.messageId] ?: continue
            val sameAttachment = old.attachment?.status == now.attachment?.status
            if (old.text == now.text && old.isEdited == now.isEdited && old.isDeleted == now.isDeleted &&
                old.reactions == now.reactions && sameAttachment && (!old.isMine || old.status == now.status)) continue
            old.text = now.text
            old.isEdited = now.isEdited
            old.isDeleted = now.isDeleted
            old.reactions = now.reactions
            if (old.isMine) old.status = now.status
            if (!sameAttachment) {
                // The reload may skip the preview of a row it knows is on screen.
                now.attachment?.let { if (it.previewJpeg == null) it.previewJpeg = old.attachment?.previewJpeg }
                old.attachment = now.attachment
            }
            notifyItemChanged(i)
            changed = true
        }
        return changed
    }

    /**
     * İKİ CİHAZLI GERÇEK TESTTE (2026-09-06) görüldü: `loadHistoryIfAvailable`
     * ve `onResume`'daki `syncMissedMessages` ikisi de IO'da geçmişi çekip
     * `localMessages`'a EKLİYOR (bkz. o iki fonksiyondaki "yarış koşulu"
     * notları). Nadiren aynı `message_id` iki kez giriyor — bir mesaj balonu
     * çift görünüyor (veri değil, sadece liste; bir sonraki resume'da
     * kendiliğinden düzeliyordu). Her birleştirmeden SONRA çağrılır: aynı
     * NON-BLANK `message_id`'ye sahip fazladan satırları (ilki kalır) atar.
     * Dönüş: silinen satır sayısı.
     */
    fun dedupeByMessageId(): Int {
        val seen = HashSet<String>()
        var removed = 0
        var i = 0
        while (i < items.size) {
            val id = items[i].messageId
            if (id.isNotEmpty() && !seen.add(id)) {
                items.removeAt(i)
                notifyItemRemoved(i)
                removed++
            } else {
                i++
            }
        }
        return removed
    }

    /** bkz. dosya başı `highlightedMessageId` notu — `null` geçilerek
     *  vurgu kaldırılır (ör. bir zamanlayıcıyla kısa süre sonra, bkz.
     *  ChatActivity/GroupChatActivity arama gezinmesi). */
    fun setHighlighted(messageId: String?) {
        val previous = highlightedMessageId
        highlightedMessageId = messageId
        if (previous != null && previous != messageId) {
            val idx = indexOfMessageId(previous)
            if (idx >= 0) notifyItemChanged(idx)
        }
        if (messageId != null) {
            val idx = indexOfMessageId(messageId)
            if (idx >= 0) notifyItemChanged(idx)
        }
    }

    fun addMessage(item: Item) {
        // İKİ CİHAZLI GERÇEK TESTTE BULUNDU (2026-09-06): çok yollu teslim
        // (LAN + onion + sunucu + gossipsub) aynı zarfı 2-4 kez getirebiliyor;
        // her kopya için `handleIncomingEvent` bir kez daha `addMessage`
        // çağırıyordu → AYNI mesaj için birden fazla balon (gönderende de
        // görülüyordu — geçici, sohbet yeniden yüklenince tek'e düşüyordu).
        // Artık `messageId` bazında idempotent: aynı kimlikli bir satır zaten
        // varsa yeni balon EKLENMEZ (rastgele UUID taşıyan hata/iyimser
        // satırlar zaten benzersiz).
        if (item.messageId.isNotEmpty() && items.any { it.messageId == item.messageId }) {
            return
        }
        // Spec dışı, kullanıcı isteği: GÖNDERİM sırasına göre ekle — mesajlar
        // genelde sırayla gelir (sondan başa tarama O(1)'e yakın), ama
        // gecikmeli teslim edilen bir mesaj (ör. gönderen bir süre çevrimdışı
        // kaldıysa) ALINMA sırasına göre EN ALTA değil, GÖNDERİM anındaki
        // doğru konumuna oturur. Eşit anahtarda sona (en yeniden sonra) ekler.
        var idx = items.size
        while (idx > 0 && items[idx - 1].orderKey > item.orderKey) idx--
        items.add(idx, item)
        notifyItemInserted(idx)
        // bkz. `pendingSeenMessageId`: hedefi olmadığı için bekletilen bir
        // "görüldü" bildirimi varsa ve gelen mesaj TAM O hedefse, şimdi
        // uygula — yoksa gösterge eski mesajın yanında asılı kalırdı.
        val awaitingSeenId = pendingSeenMessageId
        if (awaitingSeenId != null && awaitingSeenId == item.messageId) {
            val avatars = pendingSeenAvatars
            pendingSeenMessageId = null
            applySeen(awaitingSeenId, avatars)
        }
        // Komşuların "bir sonrakiyle gruplandı" durumu değişmiş olabilir
        // (yeni bir komşu edindiler) — zaman damgası gizleme/gösterme için
        // yeniden bind et.
        if (idx > 0) notifyItemChanged(idx - 1)
        if (idx < items.size - 1) notifyItemChanged(idx + 1)
    }

    /** Spec dışı, kullanıcı isteği: bir mesajın tepki özetini günceller
     *  (bkz. Rust `reaction` olayı / `reactions_summary`). Hedef bu
     *  listede yoksa sessizce yok sayılır — tepki, kaybolduğunda sohbetin
     *  anlamını bozmayan bir süs; gönderen tarafta zaten yeniden deneme
     *  kuyruğunda. */
    /** Spec dışı, kullanıcı isteği: tepki pill'ine dokununca "kim ne attı"
     *  listesi açılır (bkz. ChatActivity/GroupChatActivity
     *  `showReactionsDialog`). */
    var onReactionsClick: ((Item) -> Unit)? = null

    fun applyReactions(messageId: String, summary: String) {
        val idx = indexOfMessageId(messageId)
        if (idx < 0) return
        items[idx].reactions = summary
        notifyItemChanged(idx)
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
        // A deleted message no longer groups with its neighbors — re-bind
        // them too, so they un-merge (restore spacing/timestamp/sender row).
        if (idx > 0) notifyItemChanged(idx - 1)
        if (idx < items.size - 1) notifyItemChanged(idx + 1)
        // Replies on screen that quote it lose the text too (the core has
        // cleared it; these rows were loaded before).
        items.forEachIndexed { i, it ->
            if (it.replyToMessageId == targetMessageId && it.replyToPreview != null) {
                it.replyToPreview = null
                notifyItemChanged(i)
            }
        }
    }

    /** Bir gönderim durumu güncellemesi uygular (bkz. Rust "status" olayı —
     *  ilk denemede "pending" kalan bir mesaj sonradan "sent"/"error" olur). */
    fun applyStatus(targetMessageId: String, status: Status) {
        val idx = indexOfMessageId(targetMessageId)
        if (idx < 0) return
        // delivered never goes back to sent/pending (events can arrive out of order)
        if (items[idx].status == Status.DELIVERED && (status == Status.SENT || status == Status.PENDING)) return
        items[idx].status = status
        notifyItemChanged(idx)
    }

    /**
     * Spec dışı, kullanıcı isteği: başarısız (ERROR) bir mesajı yeniden
     * gönderme — AYNI balonu tutar, ikinci bir kopya EKLEMEZ. Yeniden
     * gönderim yeni bir ağ paketi (yeni `message_id`/`local_id`, çünkü
     * eskisinin ratchet konumu artık geçersiz olabilir — bkz. Rust
     * `MAX_UNCONFIRMED_AGE_MS` notu) olduğundan, bu balonun kimliği de
     * ileride gelecek "status"/"seen" olaylarının doğru eşleşebilmesi için
     * yeni kimlikle güncellenir. Hedef bulunamazsa sessizce yok sayılır.
     */
    fun retryMessage(oldMessageId: String, newMessageId: String, status: Status) {
        val idx = indexOfMessageId(oldMessageId)
        if (idx < 0) return
        items[idx].messageId = newMessageId
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
        if (idx < 0) {
            // bkz. `pendingSeenMessageId` — düşürmek yerine beklet.
            pendingSeenMessageId = targetMessageId
            pendingSeenAvatars = viewerAvatars
            return
        }
        // Only its own: an older "seen" arriving first used to drop the one
        // held back for a message not in the list yet.
        if (pendingSeenMessageId == targetMessageId) pendingSeenMessageId = null
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
        val holder = BubbleViewHolder(view)
        // Sabit 340dp maxWidth + yan sütun (tepki/görüldü) dar ekranda satırı
        // ekrandan taşırıyordu; sınırı ekran genişliğinden türet.
        val d = parent.resources.displayMetrics
        val screenDp = d.widthPixels / d.density
        val textMax = (minOf(340f, screenDp - 8f - 72f - 24f) * d.density).toInt()
        holder.textView.maxWidth = textMax
        holder.txtAttachmentCaption.maxWidth = textMax
        holder.txtReplyQuoteText.maxWidth = (minOf(300f, screenDp - 80f) * d.density).toInt()
        // Spec dışı, kullanıcı isteği (WhatsApp tarzı çıkartmalar): çıkartma
        // balonunun köşeleri hafif yuvarlatılmış (çerçeve YOK).
        val radius = 8 * d.density
        holder.imgSticker.outlineProvider = object : android.view.ViewOutlineProvider() {
            override fun getOutline(view: View, outline: android.graphics.Outline) {
                outline.setRoundRect(0, 0, view.width, view.height, radius)
            }
        }
        holder.imgSticker.clipToOutline = true
        return holder
    }

    override fun onBindViewHolder(holder: BubbleViewHolder, position: Int) {
        val item = items[position]
        val groupedWithPrevious = isGroupedWithPrevious(position)
        val groupedWithNext = isGroupedWithNext(position)
        holder.container.gravity = if (item.isMine) Gravity.END else Gravity.START
        // Spec dışı, kullanıcı isteği (saat/tikler balonun İÇİNE taşındı):
        // balon arka planı artık metnin/ek düzeninin KENDİSİNE değil,
        // ikisini de meta satırıyla birlikte saran kapsayıcıya uygulanıyor
        // — bkz. item_message_bubble.xml `layoutBubble`. Aksi halde saat,
        // balonun içinde değil altında/yanında ayrı bir kutuda kalırdı.
        // Spec dışı, kullanıcı isteği (gönderilen görsel): art arda gelen
        // ve arası 2 dakikadan kısa olan mesajlar TEK bir yığın gibi
        // okunsun. Bunu, balonların BİRLEŞTİĞİ kenardaki köşe yarıçapını
        // küçülterek yapıyoruz — grubun ilki normal, sonrakiler "kaynamış"
        // varyantı kullanır (bkz. bubble_*_grouped.xml).
        // Gruplanan balonlar KENDİ arka planlarını ÇİZMEZ: birleşik dış hat
        // (dışbükey köşeler + basamaklardaki içbükey filetolar) tek bir yol
        // olarak `MergedBubbleDecoration` tarafından listenin altına
        // çiziliyor. Burada bir yuvarlak dikdörtgen çizmek, tam da
        // kullanıcının şikâyet ettiği "hâlâ kendi filetleriyle kalıyorlar"
        // durumunu geri getirirdi.
        // Hiçbir balon KENDİ arka planını çizmez — gruplu da, tek de.
        // Sebep kullanıcı isteği: "en üstteki balonlar daha açık, alttakiler
        // şu anki renginde, arada gradient". Bir drawable yalnızca kendi
        // sınırlarını bilir, listenin tamamına gerilmiş bir gradyandan kendi
        // payına düşen dilimi alamaz. Bütün zeminler tek yerden, ortak bir
        // shader ile çiziliyor: bkz. MergedBubbleDecoration.
        holder.bubble.background = null

        // Tepki pill'i — balonun yanında, ilk satır hizasında (bkz.
        // item_message_bubble.xml `colBubbleSide`).
        // Açıklama SADECE ek balonlarında (metin mesajının kendi metni
        // zaten `txtBubbleText`). Spec dışı, kullanıcı isteği (WhatsApp
        // tarzı çıkartmalar): bir çıkartmanın altında açıklama/ dosya adı
        // satırı YOK.
        val attachmentInfo = item.attachment
        if (attachmentInfo != null && item.caption.isNotBlank() && !item.isDeleted
            && !attachmentInfo.isSticker
        ) {
            holder.txtAttachmentCaption.visibility = View.VISIBLE
            holder.txtAttachmentCaption.text = item.caption
        } else {
            holder.txtAttachmentCaption.visibility = View.GONE
        }

        if (item.reactions.isBlank() || item.isDeleted) {
            holder.pillReactions.visibility = View.GONE
        } else {
            holder.pillReactions.visibility = View.VISIBLE
            holder.pillReactions.text = item.reactions
            holder.pillReactions.setOnClickListener { onReactionsClick?.invoke(item) }
        }

        // Spec dışı, hata düzeltmesi (kullanıcı: "birleşen balonlar
        // çalışmıyor"): köşe yarıçapları doğru seçiliyordu ama balonlar
        // birbirine HİÇ DEĞMİYORDU — önceki satırın ALT dolgusu 4dp olarak
        // kalıyor, yalnızca sonrakinin ÜST dolgusu 1dp'ye çekiliyordu, yani
        // arada hâlâ 5dp boşluk vardı ve "kaynamış blok" etkisi hiç
        // oluşmuyordu. Gruplanan kenarda dolgu artık TAM SIFIR: iki balon
        // birbirine değiyor ve küçültülmüş köşelerle tek parça okunuyor
        // (bkz. bubble_*_grouped.xml).
        val defaultPaddingPx = (4 * holder.itemView.resources.displayMetrics.density).toInt()
        holder.container.setPadding(
            defaultPaddingPx,
            if (groupedWithPrevious) 0 else defaultPaddingPx,
            defaultPaddingPx,
            if (groupedWithNext) 0 else defaultPaddingPx
        )

        // Spec dışı, kullanıcı isteği: arama sonucunda hedeflenen mesajı
        // geçici olarak vurgular — bubble drawable'ını DEĞİŞTİRMEK yerine
        // (açık/koyu tema varyantı gerektirirdi) tüm satırın arkaplanına
        // yarı saydam bir renk uygulanır.
        holder.container.setBackgroundColor(
            if (item.messageId == highlightedMessageId) {
                MaterialColors.getColor(holder.container, com.google.android.material.R.attr.colorTertiaryContainer)
            } else {
                android.graphics.Color.TRANSPARENT
            }
        )

        // Spec dışı, kullanıcı isteği: metin rengi HER ZAMAN tema rengiyle
        // (dolayısıyla — kendi balonlarımız için — Ayarlar'daki vurgu/accent
        // rengiyle, bkz. ThemePrefs.applyAccentColor) OTOMATİK belirlenir,
        // elle seçilebilir AYRI bir metin rengi tercihi YOK ("text alwasy
        // should be full black or white depending on accent color" — bunu
        // Material'ın content-based dynamic color motoru zaten `colorOn*`
        // rollerinde doğru hesaplıyor).
        val onColorAttr = if (item.isMine) {
            com.google.android.material.R.attr.colorOnPrimaryContainer
        } else {
            com.google.android.material.R.attr.colorOnSurfaceVariant
        }
        val onColor = MaterialColors.getColor(holder.textView, onColorAttr)
        holder.textView.setTextColor(onColor)
        holder.txtAttachmentName.setTextColor(onColor)
        holder.txtAttachmentCaption.setTextColor(onColor)
        // Saat/"düzenlendi"/durum tiki artık balonun İÇİNDE — sabit bir
        // `?attr/colorOnSurfaceVariant` (XML'deki eski değer) giden balonun
        // vurgu renkli zemininde okunmuyordu. Balonun kendi metin renginin
        // hafif soluk bir tonu her iki balonda da, açık ve koyu temada
        // doğru kontrastı verir.
        val metaColor = androidx.core.graphics.ColorUtils.setAlphaComponent(onColor, 0xB3)
        holder.timestamp.setTextColor(metaColor)
        holder.editedLabel.setTextColor(metaColor)
        // Ek balonundaki ikincil satırlar da AYNI aileden olmalı: sabit
        // `?attr/colorOnSurfaceVariant` (XML'deki değer) griler
        // koyulaştırıldıktan sonra vurgu renkli giden balonun üzerinde
        // neredeyse okunmuyordu (gerçek cihazda görüldü).
        holder.txtAttachmentSize.setTextColor(metaColor)
        holder.txtAttachmentEta.setTextColor(metaColor)
        holder.txtVoiceDuration.setTextColor(metaColor)
        // Spec dışı, hata düzeltmesi (kullanıcı: "Redmi'de okunma tikleri
        // görünmüyor"): durum tiki ve "gören" göstergesi artık balonun
        // İÇİNDE değil, YANINDA — yani sohbetin arka planının üzerinde
        // duruyorlar. Balonun metin rengini (`onColor`) miras almaya devam
        // ediyorlardı ve o renk yalnızca balonun İÇİNDE doğru: turuncu
        // balonun `colorOnPrimaryContainer`'ı koyu, koyu sohbet zemininde
        // ise neredeyse görünmez oluyordu. Dışarıda doğru rol yüzeyin
        // rengi.
        val sideColor = MaterialColors.getColor(
            holder.container, com.google.android.material.R.attr.colorOnSurfaceVariant
        )
        holder.status.imageTintList = android.content.res.ColorStateList.valueOf(sideColor)
        holder.txtSeenByMore.setTextColor(sideColor)

        if (!item.isMine && item.senderName != null && !groupedWithPrevious) {
            holder.senderName.text = item.senderName
            AvatarUtil.renderInto(holder.senderAvatar, item.senderAvatarJpeg, item.senderName)
            holder.senderRow.visibility = View.VISIBLE
        } else {
            holder.senderRow.visibility = View.GONE
        }

        // Spec dışı, kullanıcı isteği (WhatsApp tarzı "sağa kaydırıp
        // yanıtla"): bu mesaj başka bir mesaja yanıtsa, balonun içinde
        // küçük bir alıntı kutusu — dokununca sohbet yanıtlanan mesaja
        // kaydırılır (bkz. `onReplyPreviewClick`).
        // "null" guard: a JSON-parsing bug upstream once let the literal
        // string "null" through instead of real null here (org.json's
        // optString(key, "") doesn't fall back on an explicit JSON null,
        // only a missing key) — kept as a safety net against that class of bug.
        val replyToId = item.replyToMessageId?.takeIf { it != "null" }
        if (replyToId != null) {
            holder.layoutReplyQuote.visibility = View.VISIBLE
            holder.txtReplyQuoteSender.text = item.replyToSenderLabel?.takeIf { it != "null" }
            // No preview left: the quoted message was deleted.
            // The sender writes the preview: when the quoted message is here,
            // its own text is shown, so nobody can put words under "You".
            val replyTarget = items.firstOrNull { it.messageId == replyToId }
            val quoteText = when {
                replyTarget == null -> item.replyToPreview?.takeIf { it != "null" && it.isNotEmpty() }
                replyTarget.isDeleted -> null
                else -> replyTarget.attachment
                    ?.let { holder.itemView.context.getString(R.string.lbl_attachment_reply_preview, it.fileName) }
                    ?: replyTarget.text.takeWholeChars(120)
            }
            holder.txtReplyQuoteText.text = quoteText ?: holder.itemView.context.getString(R.string.msg_deleted)
            // Kullanıcı raporu ("alıntı mesajlar beyaz görünüyor").
            //
            // Tasarım niyeti doğruydu: yüzey renginin üzerine %12 opaklıkta
            // `colorOnSurface`. Uygulaması bozuktu — `reply_quote_background.xml`
            // içinde `<solid android:color="?attr/colorOnSurface"
            // android:alpha="0.12" />` yazıyordu ve `android:alpha`, `<solid>`
            // etiketinin GEÇERLİ bir özniteliği DEĞİL. Sessizce yok sayılıp
            // dolgu TAM OPAK `colorOnSurface` oluyordu; koyu temada bu renk
            // neredeyse beyaz olduğu için kutu, koyu sohbetin ortasında
            // bembeyaz bir blok olarak çiziliyordu.
            //
            // NOT (ilk denememde yanlış varsaydım): bu kutu balonun İÇİNDE
            // değil — `item_message_bubble.xml`'de `txtBubbleText`'in KARDEŞİ,
            // yani sohbet arka planının üzerinde duruyor. Bu yüzden renk
            // temeli balonun metin rengi değil, YÜZEY rengi olmalı; zaten
            // balonun altındaki zaman damgası da aynı aileyi kullanıyor ve
            // bu arka planda okunaklı olduğu görülüyor.
            //
            // Alfa artık kodda uygulanıyor (XML'de mümkün olmadığı için),
            // renkler orijinal niyetteki tema rollerinde kalıyor.
            val quoteBase = MaterialColors.getColor(
                holder.layoutReplyQuote, com.google.android.material.R.attr.colorOnSurface
            )
            val quoteAccent = MaterialColors.getColor(
                holder.layoutReplyQuote, com.google.android.material.R.attr.colorPrimary
            )
            holder.layoutReplyQuote.backgroundTintList = android.content.res.ColorStateList.valueOf(
                androidx.core.graphics.ColorUtils.setAlphaComponent(quoteBase, 0x1F)
            )
            holder.viewReplyQuoteBar.setBackgroundColor(quoteAccent)
            holder.txtReplyQuoteSender.setTextColor(quoteAccent)
            holder.txtReplyQuoteText.setTextColor(quoteBase)
            holder.layoutReplyQuote.setOnClickListener {
                onReplyPreviewClick?.invoke(replyToId)
            }
        } else {
            holder.layoutReplyQuote.visibility = View.GONE
            holder.layoutReplyQuote.setOnClickListener(null)
        }

        val attachment = item.attachment
        if (attachment != null && item.isDeleted) {
            // Spec dışı, hata düzeltmesi ("ekleri de uzun basıp silebilmeliyiz"):
            // önceden bu dal HİÇ `isDeleted`i kontrol etmiyordu — bir ek
            // silindiğinde (bkz. ChatActivity.confirmDeleteMessage) balon
            // görsel olarak DEĞİŞMİYORDU, sanki hiç silinmemiş gibi
            // göründüğü hâlde arka planda mesaj zaten silinmişti. Metin
            // mesajlarıyla AYNI "Bu mesaj silindi" yer tutucusu.
            holder.layoutAttachment.visibility = View.GONE
            holder.textView.visibility = View.VISIBLE
            holder.editedLabel.visibility = View.GONE
            holder.textView.text = holder.itemView.context.getString(R.string.msg_deleted)
            holder.textView.setTypeface(holder.textView.typeface, Typeface.ITALIC)
            holder.textView.alpha = 0.6f
        } else if (attachment != null) {
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
                // Spec dışı, kullanıcı isteği: mesaj metnindeki linkler
                // (http/https/www) tıklanabilir olsun. `Linkify.addLinks`
                // link bulursa TextView'a kendi `LinkMovementMethod`'unu
                // atar — bu, ACTION_DOWN'ı tüketip üstteki `holder.itemView`
                // long-click dinleyicisinin hiç tetiklenmemesine yol
                // açabilir (bilinen Android davranışı: bir alt view kendi
                // hareket yöntemiyle dokunuşu tüketirse üst view'a asla
                // ulaşmaz) — bu yüzden AYNI uzun-basma dinleyicisi (bkz.
                // aşağısı) `holder.textView`'a da AYRICA atanıyor, hangisi
                // dokunuşu yakalarsa yakalasın menü yine açılır.
                val linked = android.text.SpannableString(item.text)
                if (android.text.util.Linkify.addLinks(linked, android.text.util.Linkify.WEB_URLS)) {
                    // A tap leaves Tor for the system browser: ask first.
                    for (span in linked.getSpans(0, linked.length, android.text.style.URLSpan::class.java)) {
                        val start = linked.getSpanStart(span)
                        val end = linked.getSpanEnd(span)
                        val flags = linked.getSpanFlags(span)
                        linked.removeSpan(span)
                        linked.setSpan(ConfirmUrlSpan(span.url), start, end, flags)
                    }
                    holder.textView.text = linked
                    holder.textView.movementMethod = android.text.method.LinkMovementMethod.getInstance()
                }
            }
        }

        // Spec dışı, kullanıcı isteği: her mesajın altında salt "HH:mm"
        // yerine tam "(sent at: HH:MM day)" biçiminde, hangi GÜN
        // gönderildiğini de gösteren mutlak bir zaman damgası — bkz.
        // util.formatAbsoluteTime (Ayarlar'daki bekleyen mesajlar
        // listesiyle PAYLAŞILAN aynı biçim). Kullanıcı isteği (genişletme):
        // ALINAN mesajlarda, göndericinin embed ettiği GERÇEK gönderim anı
        // (bkz. `Item.sentAtMs`) biliniyorsa "10:42 (sent at: 10:41)" gibi
        // hem yerel ALINMA anı HEM gönderim anı gösterilir — ikisi network
        // gecikmesi/kuyruklama yüzünden FARKLI olabilir. Bilinmiyorsa
        // (gönderiliyor balonu, eski sürüm göndericisi, ya da yerel
        // geçmişten yüklenmiş bir mesaj) önceki tek-zaman-damgası davranışına
        // düşülür.
        val sentAt = item.sentAtMs
        holder.timestamp.text = if (!item.isMine && sentAt != null && sentAt > 0) {
            holder.itemView.context.getString(
                R.string.lbl_received_sent_at, formatAbsoluteTime(item.timestamp), formatAbsoluteTime(sentAt)
            )
        } else {
            holder.itemView.context.getString(R.string.lbl_sent_at, formatAbsoluteTime(item.timestamp))
        }
        // Only the last bubble in a grouped run shows a timestamp.
        holder.timestamp.visibility = if (groupedWithNext) View.GONE else View.VISIBLE

        if (item.isMine && !item.isDeleted) {
            holder.status.visibility = View.VISIBLE
            holder.status.contentDescription =
                if (item.status == Status.DELIVERED) holder.itemView.context.getString(R.string.cd_status_delivered) else null
            holder.status.setImageResource(
                when (item.status) {
                    Status.PENDING -> R.drawable.ic_status_pending
                    Status.SENT -> R.drawable.ic_status_sent
                    Status.DELIVERED -> R.drawable.ic_status_delivered
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

        val longPressListener = View.OnLongClickListener {
            // Ek balonları için düzenle/sil/kopyala desteklenmiyor (bkz.
            // dosya başı notu) — sadece düz metin mesajları uzun basmaya
            // tepki verir. Spec dışı, kullanıcı isteği: önceden SADECE
            // kendi mesajlarımız (`item.isMine`) tepki veriyordu (Düzenle/
            // Sil için) — artık alınan mesajlar da tepki verir, çağıran
            // taraf (bkz. ChatActivity/GroupChatActivity) `isMine`'a göre
            // ya sadece "Kopyala" ya da tam menüyü gösterir.
            if (!item.isDeleted && item.attachment == null) {
                onItemLongPress?.invoke(item)
                true
            } else {
                false
            }
        }
        holder.itemView.setOnLongClickListener(longPressListener)
        // bkz. `Linkify.addLinks` çağrısı yukarısı — link içeren bir metinde
        // `holder.textView` kendi `LinkMovementMethod`'u yüzünden dokunuşu
        // tüketebilir, bu yüzden AYNI dinleyici ona da atanıyor.
        holder.textView.setOnLongClickListener(longPressListener)
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
        // Spec dışı, kullanıcı isteği (WhatsApp tarzı çıkartmalar): bir
        // çıkartma çerçevesiz gösterilir — indirilene kadar normal ek
        // balonu (indirme düğmesi) görünür.
        if (attachment.isSticker && attachment.status == AttachmentStatus.COMPLETE) {
            bindSticker(holder, item, attachment)
            return
        }
        holder.imgSticker.visibility = View.GONE

        // Sadece GERÇEK bir sesli mesaj oynatıcı olarak çizilir. Kullanıcının
        // dosya yöneticisinden eklediği düz bir ses DOSYASININ süresi yoktur
        // ve oynatıcı olarak çizilince balonda ne dosya adı, ne boyut, ne de
        // anlamlı bir etiket kalıyordu — alıcı ne geldiğini göremiyordu.
        // Gönderen gerçek sesli notlarda `duration_ms`'i FileOffer'a koyduğu
        // için, henüz İNDİRİLMEMİŞ bir sesli not yine oynatıcı olarak çizilir.
        if (attachment.mimeType.startsWith("audio/") && (attachment.durationMs ?: 0) > 0) {
            holder.imgAttachmentThumbnail.visibility = View.GONE
            holder.rowGenericAttachment.visibility = View.GONE
            holder.layoutVoiceMessage.visibility = View.VISIBLE
            // A recycled holder keeps the previous FILE row's state: stale
            // progress, and a tap that opened the other message's file.
            holder.progressAttachment.visibility = View.GONE
            holder.txtAttachmentEta.visibility = View.GONE
            val voiceClick = View.OnClickListener {
                if (attachment.status != AttachmentStatus.DOWNLOADING && attachment.status != AttachmentStatus.COMPLETE) {
                    onAttachmentClick?.invoke(item)
                }
            }
            holder.btnAttachmentDownload.setOnClickListener(voiceClick)
            holder.layoutAttachment.setOnClickListener(voiceClick)
            holder.layoutAttachment.setOnLongClickListener(null)
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
            // Sender-controlled bytes: bounded decode (see ImagePreview.decodeBytes).
            // ponytail: the first bind still decodes on the main thread;
            // decode on a worker if one preview alone ever janks.
            // L-84: keyed by the bytes too, a re-sent file with the same id gets its new preview.
            val cacheKey = attachment.fileId + ":" + preview.contentHashCode()
            val bitmap = previewCache.get(cacheKey)
                ?: com.p2p.messenger.util.ImagePreview.decodeBytes(preview, 1024)
                    ?.also { previewCache.put(cacheKey, it) }
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
        holder.btnAttachmentDownload.setText(
            if (attachment.status == AttachmentStatus.FAILED && attachment.bytesDone > 0) R.string.action_resume_download else R.string.lbl_download
        )
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
     * Spec dışı, kullanıcı isteği (WhatsApp tarzı çıkartmalar): bir çıkartma
     * balonu — ÇERÇEVESİZ (balon arka planı çizilmez, bkz.
     * MergedBubbleDecoration), dosya adı/açıklama satırı yok; görsel 160
     * dp'lik bir kutuya sığdırılır (en-boy oranı korunur).
     *
     * Görsel ana thread'de çözülmez: JNI çağrısı + decode arka planda
     * yapılır (bkz. `stickerImageProvider`).
     */
    private fun bindSticker(holder: BubbleViewHolder, item: Item, attachment: AttachmentInfo) {
        holder.rowGenericAttachment.visibility = View.GONE
        holder.layoutVoiceMessage.visibility = View.GONE
        holder.imgAttachmentThumbnail.visibility = View.GONE
        holder.progressAttachment.visibility = View.GONE
        holder.txtAttachmentEta.visibility = View.GONE
        holder.btnAttachmentDownload.visibility = View.GONE
        holder.txtAttachmentName.text = ""
        holder.txtAttachmentSize.text = ""
        holder.imgSticker.visibility = View.VISIBLE

        val cached = stickerImages.get(attachment.fileId)
        if (cached != null) {
            holder.imgSticker.setImageDrawable(cached)
            (cached as? android.graphics.drawable.AnimatedImageDrawable)?.start()
        } else {
            holder.imgSticker.setImageDrawable(null)
            val provider = stickerImageProvider
            if (provider != null && attachment.fileId !in stickerPending) {
                stickerPending.add(attachment.fileId)
                provider(attachment.fileId) { drawable ->
                    stickerPending.remove(attachment.fileId)
                    if (drawable != null) {
                        stickerImages.put(attachment.fileId, drawable)
                        val idx = indexOfMessageId(attachment.fileId)
                        if (idx >= 0) notifyItemChanged(idx)
                    }
                }
            }
        }

        holder.layoutAttachment.setOnClickListener {
            if (attachment.status != AttachmentStatus.DOWNLOADING) onAttachmentClick?.invoke(item)
        }
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

/** A link in a message: shows the real host and asks before it opens. */
private class ConfirmUrlSpan(url: String) : android.text.style.URLSpan(url) {
    override fun onClick(widget: View) {
        val host = try {
            java.net.IDN.toASCII(android.net.Uri.parse(url).host ?: "")
        } catch (e: Exception) {
            ""
        }
        android.app.AlertDialog.Builder(widget.context)
            .setTitle(host.ifEmpty { url })
            .setMessage(widget.context.getString(R.string.msg_open_link_warning, url))
            .setPositiveButton(R.string.action_open) { _, _ -> open(widget) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun open(widget: View) {
        try {
            super.onClick(widget)
        } catch (e: Exception) {
        }
    }
}

/** `take(n)` on UTF-16 can cut a surrogate pair (emoji) in half; back off one unit then. */
fun String.takeWholeChars(n: Int): String =
    if (length <= n) this else substring(0, if (n > 0 && Character.isHighSurrogate(this[n - 1])) n - 1 else n)
