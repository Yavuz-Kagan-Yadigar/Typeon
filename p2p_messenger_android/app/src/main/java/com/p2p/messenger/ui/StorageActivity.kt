package com.p2p.messenger.ui

import android.graphics.Bitmap
import android.os.Bundle
import android.text.format.Formatter
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.SeekBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.coreErrorText
import com.p2p.messenger.util.hexToBytesOrNull
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Settings → Storage: usage totals, per-chat attachment size, and a chat's
 * local attachments (media grid + file list) to bulk-delete. Deleting drops
 * only this device's copy (`P2PLib.removeLocalAttachments`).
 */
class StorageActivity : AppCompatActivity() {

    companion object {
        /** Set these three to open one chat's attachments directly (from the chat screen). */
        const val EXTRA_CHAT_KIND = "chat_kind"
        const val EXTRA_CHAT_ID = "chat_id"
        const val EXTRA_CHAT_NAME = "chat_name"
    }

    private lateinit var layoutChats: View
    private lateinit var layoutAttachments: View
    private lateinit var txtTotal: TextView
    private lateinit var txtBreakdown: TextView
    private lateinit var txtNoChats: View
    private lateinit var txtNoAttachments: View
    private lateinit var txtAttachmentsTitle: TextView
    private lateinit var btnDeleteSelected: Button

    private val chatAdapter = StorageChatsAdapter(lifecycleScope, { loadUsage() }) { chat -> openChat(chat) }
    private val selected = mutableSetOf<String>()
    private val attachmentAdapter = StorageAttachmentsAdapter(selected) { refreshDeleteButton() }
    private var currentChat: StorageChat? = null
    private lateinit var backToChats: OnBackPressedCallback
    private lateinit var attachmentsPrune: PrunePanel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_storage)
        supportActionBar?.title = getString(R.string.title_storage)

        layoutChats = findViewById(R.id.layoutStorageChats)
        layoutAttachments = findViewById(R.id.layoutStorageAttachments)
        txtTotal = findViewById(R.id.txtStorageTotal)
        txtBreakdown = findViewById(R.id.txtStorageBreakdown)
        txtNoChats = findViewById(R.id.txtStorageNoChats)
        txtNoAttachments = findViewById(R.id.txtStorageNoAttachments)
        txtAttachmentsTitle = findViewById(R.id.txtStorageAttachmentsTitle)
        btnDeleteSelected = findViewById(R.id.btnDeleteSelected)

        findViewById<RecyclerView>(R.id.recyclerStorageChats).apply {
            layoutManager = LinearLayoutManager(this@StorageActivity)
            adapter = chatAdapter
        }
        findViewById<RecyclerView>(R.id.recyclerStorageAttachments).apply {
            // Media: three to a row; a file: a full-width row.
            layoutManager = GridLayoutManager(this@StorageActivity, 3).apply {
                spanSizeLookup = object : GridLayoutManager.SpanSizeLookup() {
                    override fun getSpanSize(position: Int) =
                        if (attachmentAdapter.items[position].preview != null) 1 else 3
                }
            }
            adapter = attachmentAdapter
        }

        attachmentsPrune = PrunePanel(findViewById(R.id.pruneAttachments), lifecycleScope) {
            currentChat?.let { loadAttachments(it) }
        }

        findViewById<Button>(R.id.btnClearCache).setOnClickListener { clearDecryptedCache() }
        findViewById<Button>(R.id.btnSelectAll).setOnClickListener { toggleSelectAll() }
        btnDeleteSelected.setOnClickListener { confirmDeleteSelected() }
        refreshDeleteButton()

        // Back from a chat's attachments returns to the chat list.
        backToChats = object : OnBackPressedCallback(false) {
            override fun handleOnBackPressed() { showChats() }
        }
        onBackPressedDispatcher.addCallback(this, backToChats)

        val directChatId = intent.getStringExtra(EXTRA_CHAT_ID)
        if (directChatId != null) {
            // Straight to the chat; the list stays hidden and back finishes.
            layoutChats.visibility = View.GONE
            openChat(
                StorageChat(
                    intent.getStringExtra(EXTRA_CHAT_KIND) ?: "contact",
                    directChatId,
                    intent.getStringExtra(EXTRA_CHAT_NAME) ?: directChatId.take(8),
                    0, 0
                )
            )
        } else {
            loadUsage()
        }
    }

    private fun loadUsage() {
        lifecycleScope.launch {
            val obj = withContext(Dispatchers.IO) {
                try { JSONObject(P2PLib.storageUsage()) } catch (e: Exception) { null }
            }
            if (obj == null) {
                Toast.makeText(this@StorageActivity, R.string.msg_storage_load_failed, Toast.LENGTH_SHORT).show()
                return@launch
            }
            val parts = listOf(
                R.string.storage_database to obj.optLong("db_bytes"),
                R.string.storage_attachments to obj.optLong("attachments_bytes"),
                R.string.storage_voice to obj.optLong("voice_bytes"),
                R.string.storage_stickers to obj.optLong("stickers_bytes"),
                R.string.storage_decrypted_cache to obj.optLong("cache_bytes"),
            )
            txtTotal.text = getString(R.string.storage_total) + ": " + formatSize(parts.sumOf { it.second })
            txtBreakdown.text = parts.joinToString("\n") { (label, bytes) -> getString(label) + ": " + formatSize(bytes) }

            val arr = obj.optJSONArray("chats") ?: JSONArray()
            val chats = (0 until arr.length()).mapNotNull { i ->
                arr.optJSONObject(i)?.let { c ->
                    StorageChat(c.optString("kind"), c.optString("id"), c.optString("name"), c.optLong("bytes"), c.optInt("count"))
                }
            }
            chatAdapter.submitList(chats)
            txtNoChats.visibility = if (chats.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    /** The chat's attachments that have a copy here, media first. */
    private var loadSeq = 0

    private fun loadAttachments(chat: StorageChat) {
        val seq = ++loadSeq
        lifecycleScope.launch {
            val items = withContext(Dispatchers.IO) {
                val arr = try {
                    JSONArray(if (chat.kind == "group") P2PLib.listGroupAttachments(chat.id) else P2PLib.listAttachments(chat.id))
                } catch (e: Exception) { JSONArray() }
                (0 until arr.length()).mapNotNull { i ->
                    val a = arr.optJSONObject(i) ?: return@mapNotNull null
                    // 'offered': nothing on this device.
                    if (a.optString("status") == "offered") return@mapNotNull null
                    // My own sent files: the only copy anyone can fetch from, not removable.
                    if (a.optString("direction") == "sent") return@mapNotNull null
                    StorageAttachment(
                        fileId = a.optString("file_id"),
                        name = a.optString("file_name"),
                        mimeType = a.optString("mime_type"),
                        size = a.optLong("total_size"),
                        createdAt = a.optLong("created_at"),
                        preview = if (a.isNull("preview_hex")) null else hexToBytesOrNull(a.optString("preview_hex"))
                    )
                }.sortedBy { it.preview == null }
            }
            // A newer load, or another chat, took over meanwhile.
            if (seq != loadSeq || currentChat?.id != chat.id) return@launch
            // Drop selections of files that are gone.
            selected.retainAll(items.map { it.fileId }.toSet())
            refreshDeleteButton()
            attachmentAdapter.submitList(items)
            txtNoAttachments.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    private fun openChat(chat: StorageChat) {
        currentChat = chat
        selected.clear()
        refreshDeleteButton()
        txtAttachmentsTitle.text = chat.name
        // Direct per-chat mode: the list was never shown, so back leaves the screen.
        backToChats.isEnabled = layoutChats.visibility == View.VISIBLE
        layoutChats.visibility = View.GONE
        layoutAttachments.visibility = View.VISIBLE
        attachmentsPrune.bind(chat.kind, chat.id)
        loadAttachments(chat)
    }

    private fun showChats() {
        currentChat = null
        selected.clear()
        refreshDeleteButton()
        layoutAttachments.visibility = View.GONE
        layoutChats.visibility = View.VISIBLE
        backToChats.isEnabled = false
        loadUsage()
    }

    /** Same clean-up the app does at start (P2PApplication.onCreate). */
    private fun clearDecryptedCache() {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                java.io.File(filesDir, "attachments/plain_cache").listFiles()?.forEach { it.deleteRecursively() }
            }
            Toast.makeText(this@StorageActivity, R.string.msg_decrypted_cache_cleared, Toast.LENGTH_SHORT).show()
            loadUsage()
        }
    }

    private fun toggleSelectAll() {
        val all = attachmentAdapter.items
        if (selected.size >= all.size) selected.clear() else all.forEach { selected.add(it.fileId) }
        attachmentAdapter.notifyDataSetChanged()
        refreshDeleteButton()
    }

    private fun refreshDeleteButton() {
        btnDeleteSelected.isEnabled = selected.isNotEmpty()
    }

    private fun confirmDeleteSelected() {
        AlertDialog.Builder(this)
            .setTitle(R.string.storage_delete_confirm_title)
            .setMessage(R.string.storage_delete_confirm_message)
            .setPositiveButton(R.string.action_delete_selected) { _, _ -> deleteSelected() }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun deleteSelected() {
        val ids = selected.toList()
        val payload = JSONArray(ids).toString()
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                try { P2PLib.removeLocalAttachments(payload) } catch (e: Exception) { "Error: ${e.message}" }
            }
            Toast.makeText(
                this@StorageActivity,
                if (result.startsWith("Error:")) coreErrorText(this@StorageActivity, result)
                else getString(R.string.msg_attachments_removed, ids.size),
                Toast.LENGTH_SHORT
            ).show()
            selected.clear()
            refreshDeleteButton()
            currentChat?.let {
                attachmentsPrune.bind(it.kind, it.id)
                loadAttachments(it)
            }
        }
    }

    private fun formatSize(bytes: Long): String = Formatter.formatShortFileSize(this, bytes)
}

/** A chat row of Rust `storage_usage`; `id` is the contact's canonical device or the group id. */
data class StorageChat(val kind: String, val id: String, val name: String, val bytes: Long, val count: Int)

/** An attachment with a local copy; `preview` set for media. */
class StorageAttachment(
    val fileId: String,
    val name: String,
    val mimeType: String,
    val size: Long,
    val createdAt: Long,
    val preview: ByteArray?
)

class StorageChatsAdapter(
    private val scope: CoroutineScope,
    private val onPruned: () -> Unit,
    private val onClick: (StorageChat) -> Unit
) : RecyclerView.Adapter<StorageChatsAdapter.ViewHolder>() {

    private val items = mutableListOf<StorageChat>()

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val name: TextView = itemView.findViewById(R.id.txtStorageChatName)
        val size: TextView = itemView.findViewById(R.id.txtStorageChatSize)
        lateinit var prune: PrunePanel
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder =
        ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_storage_chat, parent, false)).also {
            it.prune = PrunePanel(it.itemView.findViewById(R.id.pruneChat), scope, onPruned)
        }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.prune.bind(item.kind, item.id)
        holder.name.text = item.name
        holder.size.text = holder.itemView.context.getString(
            R.string.storage_files_count,
            item.count,
            Formatter.formatShortFileSize(holder.itemView.context, item.bytes)
        )
        holder.itemView.setOnClickListener { onClick(item) }
    }

    fun submitList(newItems: List<StorageChat>) {
        items.clear()
        items.addAll(newItems)
        notifyDataSetChanged()
    }
}

/** Media as grid cells (thumbnail + check box), files as rows. */
class StorageAttachmentsAdapter(
    private val selected: MutableSet<String>,
    private val onToggle: () -> Unit
) : RecyclerView.Adapter<StorageAttachmentsAdapter.ViewHolder>() {

    val items = mutableListOf<StorageAttachment>()

    // Decoded thumbnails, capped by bytes; the list keeps only the encoded previews.
    private val thumbs = object : android.util.LruCache<String, Bitmap>(8 * 1024 * 1024) {
        override fun sizeOf(key: String, value: Bitmap) = value.byteCount
    }

    // One worker that exits when idle (core 0; the queue is unbounded, so max 1 is the real size).
    private val decoder = java.util.concurrent.ThreadPoolExecutor(
        0, 1, 5, java.util.concurrent.TimeUnit.SECONDS, java.util.concurrent.LinkedBlockingQueue()
    )

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val check: CheckBox = itemView.findViewById(R.id.checkStorageAttachment)
        val image: ImageView? = itemView.findViewById(R.id.imgStorageAttachment)
        val name: TextView? = itemView.findViewById(R.id.txtStorageAttachmentName)
        val info: TextView? = itemView.findViewById(R.id.txtStorageAttachmentInfo)
    }

    override fun getItemViewType(position: Int): Int = if (items[position].preview != null) 1 else 0

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val layout = if (viewType == 1) R.layout.item_storage_media else R.layout.item_storage_attachment
        val view = LayoutInflater.from(parent.context).inflate(layout, parent, false)
        // Square cells: the grid has 3 columns.
        if (viewType == 1 && parent.width > 0) view.layoutParams.height = parent.width / 3
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        val context = holder.itemView.context
        val fileId = item.fileId
        holder.image?.tag = fileId
        val cached = thumbs.get(fileId)
        holder.image?.setImageBitmap(cached)
        val bytes = item.preview
        if (cached == null && bytes != null && holder.image != null) {
            // Decode off the main thread; a recycled cell (tag changed) drops the result.
            decoder.execute {
                val bmp = ImagePreview.decodeBytes(bytes, 256) ?: return@execute
                holder.image.post {
                    thumbs.put(fileId, bmp)
                    if (holder.image.tag == fileId) holder.image.setImageBitmap(bmp)
                }
            }
        }
        holder.name?.text = item.name
        holder.info?.text = context.getString(
            R.string.storage_attachment_type,
            item.mimeType.ifEmpty { "—" }.substringAfter('/').uppercase(),
            formatStorageDate(item.createdAt)
        ) + " · " + Formatter.formatShortFileSize(context, item.size)

        // A recycled row: the old listener must not fire.
        holder.check.setOnCheckedChangeListener(null)
        holder.check.isChecked = selected.contains(item.fileId)
        holder.check.setOnCheckedChangeListener { _, checked ->
            if (checked) selected.add(item.fileId) else selected.remove(item.fileId)
            onToggle()
        }
        holder.itemView.setOnClickListener { holder.check.isChecked = !holder.check.isChecked }
    }

    fun submitList(newItems: List<StorageAttachment>) {
        items.clear()
        items.addAll(newItems)
        thumbs.evictAll()
        notifyDataSetChanged()
    }
}

private fun formatStorageDate(timestampMs: Long): String {
    if (timestampMs <= 0) return ""
    return SimpleDateFormat("d MMM yyyy, HH:mm", Locale.getDefault()).format(Date(timestampMs))
}

/**
 * "Delete older than" for one chat: the slider runs from the chat's oldest
 * message (right of 0) to now; 0 = nothing. Shows the cut-off date and the
 * sizes before / after, and asks before deleting (`P2PLib.pruneChatBefore`).
 */
class PrunePanel(root: View, private val scope: CoroutineScope, private val onDone: () -> Unit) {
    private val seek: SeekBar = root.findViewById(R.id.seekPrune)
    private val date: TextView = root.findViewById(R.id.txtPruneDate)
    private val sizes: TextView = root.findViewById(R.id.txtPruneSizes)
    private val button: Button = root.findViewById(R.id.btnPrune)
    private val context = root.context
    private var kind = ""
    private var id = ""
    private var oldest = 0L
    /** Fixed at bind, so the shown sizes and the deleted range use the same cut-off. */
    private var nowMs = 0L
    private var delCount = 0L
    private var job: Job? = null

    init {
        seek.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(bar: SeekBar, progress: Int, fromUser: Boolean) {
                if (fromUser) refresh()
            }
            override fun onStartTrackingTouch(bar: SeekBar) {}
            override fun onStopTrackingTouch(bar: SeekBar) {}
        })
        button.setOnClickListener { confirm() }
    }

    fun bind(kind: String, id: String) {
        this.kind = kind
        this.id = id
        oldest = 0
        seek.progress = 0
        nowMs = System.currentTimeMillis()
        // No stale range / sizes of the chat that used this row before. The stats are asked
        // lazily, on the first slider touch: not one locked DB scan per bound row.
        job?.cancel()
        seek.isEnabled = true
        button.isEnabled = false
        sizes.text = ""
        date.text = "—"
    }

    private fun beforeMs(): Long {
        val p = seek.progress
        if (p == 0 || oldest == 0L) return 0
        return oldest + (nowMs - oldest) * p / 100
    }

    private fun refresh() {
        val before = beforeMs()
        val (k, i) = kind to id
        date.text = if (before == 0L) "—" else SimpleDateFormat("d MMM yyyy", Locale.getDefault()).format(Date(before))
        job?.cancel()
        job = scope.launch {
            // Debounce a dragged slider: only the last position asks the core.
            delay(150)
            val st = withContext(Dispatchers.IO) {
                try { JSONObject(P2PLib.chatPruneStats(k, i, before)) } catch (e: Exception) { JSONObject() }
            }
            if (k != kind || i != id) return@launch
            // The range comes from the first (before = 0) load of this chat.
            if (oldest == 0L) {
                oldest = st.optLong("oldest_ms")
                // The slider was moved before the range was known: ask again for its real position.
                if (oldest != 0L && seek.progress > 0) { refresh(); return@launch }
            }
            delCount = st.optLong("del_msg_count") + (if (st.optLong("del_att_bytes") > 0) 1 else 0)
            seek.isEnabled = oldest != 0L
            button.isEnabled = delCount > 0
            val msg = st.optLong("msg_bytes")
            val att = st.optLong("att_bytes")
            val dm = st.optLong("del_msg_bytes")
            val da = st.optLong("del_att_bytes")
            sizes.text = context.getString(
                R.string.storage_prune_sizes,
                st.optLong("msg_count"), fmt(msg), fmt(msg - dm), fmt(att), fmt(att - da)
            )
        }
    }

    private fun confirm() {
        val before = beforeMs()
        if (before == 0L) return
        val day = SimpleDateFormat("d MMM yyyy", Locale.getDefault()).format(Date(before))
        val dialog = AlertDialog.Builder(context)
            .setTitle(R.string.storage_prune_confirm_title)
            .setMessage(context.getString(R.string.storage_prune_confirm_message, day))
            .setPositiveButton(R.string.storage_prune_button) { _, _ ->
                val (k, i) = kind to id
                scope.launch {
                    val r = withContext(Dispatchers.IO) {
                        try { P2PLib.pruneChatBefore(k, i, before) } catch (e: Exception) { "Error: ${e.message}" }
                    }
                    Toast.makeText(
                        context,
                        if (r.startsWith("Error:")) coreErrorText(context, r) else context.getString(R.string.storage_prune_done),
                        Toast.LENGTH_SHORT
                    ).show()
                    if (k == kind && i == id) bind(k, i)
                    onDone()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        // Bound to the screen: a recreate must not leak the window.
        (context as? androidx.lifecycle.LifecycleOwner)?.lifecycle?.addObserver(object : androidx.lifecycle.DefaultLifecycleObserver {
            override fun onDestroy(owner: androidx.lifecycle.LifecycleOwner) { dialog.dismiss() }
        })
        dialog.show()
    }

    private fun fmt(bytes: Long) = Formatter.formatShortFileSize(context, bytes)
}
