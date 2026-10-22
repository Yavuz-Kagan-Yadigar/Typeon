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
import kotlinx.coroutines.Dispatchers
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

    private lateinit var layoutChats: View
    private lateinit var layoutAttachments: View
    private lateinit var txtTotal: TextView
    private lateinit var txtBreakdown: TextView
    private lateinit var txtNoChats: View
    private lateinit var txtNoAttachments: View
    private lateinit var txtAttachmentsTitle: TextView
    private lateinit var btnDeleteSelected: Button

    private val chatAdapter = StorageChatsAdapter { chat -> openChat(chat) }
    private val selected = mutableSetOf<String>()
    private val attachmentAdapter = StorageAttachmentsAdapter(selected) { refreshDeleteButton() }
    private var currentChat: StorageChat? = null
    private lateinit var backToChats: OnBackPressedCallback

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

        findViewById<Button>(R.id.btnClearCache).setOnClickListener { clearDecryptedCache() }
        findViewById<Button>(R.id.btnSelectAll).setOnClickListener { toggleSelectAll() }
        btnDeleteSelected.setOnClickListener { confirmDeleteSelected() }
        refreshDeleteButton()

        // Back from a chat's attachments returns to the chat list.
        backToChats = object : OnBackPressedCallback(false) {
            override fun handleOnBackPressed() { showChats() }
        }
        onBackPressedDispatcher.addCallback(this, backToChats)

        loadUsage()
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
    private fun loadAttachments(chat: StorageChat) {
        lifecycleScope.launch {
            val items = withContext(Dispatchers.IO) {
                val arr = try {
                    JSONArray(if (chat.kind == "group") P2PLib.listGroupAttachments(chat.id) else P2PLib.listAttachments(chat.id))
                } catch (e: Exception) { JSONArray() }
                (0 until arr.length()).mapNotNull { i ->
                    val a = arr.optJSONObject(i) ?: return@mapNotNull null
                    // 'offered': nothing on this device.
                    if (a.optString("status") == "offered") return@mapNotNull null
                    StorageAttachment(
                        fileId = a.optString("file_id"),
                        name = a.optString("file_name"),
                        mimeType = a.optString("mime_type"),
                        size = a.optLong("total_size"),
                        createdAt = a.optLong("created_at"),
                        preview = if (a.isNull("preview_hex")) null
                            else hexToBytesOrNull(a.optString("preview_hex"))?.let { ImagePreview.decodeBytes(it, 256) }
                    )
                }.sortedBy { it.preview == null }
            }
            attachmentAdapter.submitList(items)
            txtNoAttachments.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    private fun openChat(chat: StorageChat) {
        currentChat = chat
        selected.clear()
        refreshDeleteButton()
        txtAttachmentsTitle.text = chat.name
        layoutChats.visibility = View.GONE
        layoutAttachments.visibility = View.VISIBLE
        backToChats.isEnabled = true
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
            currentChat?.let { loadAttachments(it) }
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
    val preview: Bitmap?
)

class StorageChatsAdapter(
    private val onClick: (StorageChat) -> Unit
) : RecyclerView.Adapter<StorageChatsAdapter.ViewHolder>() {

    private val items = mutableListOf<StorageChat>()

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val name: TextView = itemView.findViewById(R.id.txtStorageChatName)
        val size: TextView = itemView.findViewById(R.id.txtStorageChatSize)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder =
        ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_storage_chat, parent, false))

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
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
        holder.image?.setImageBitmap(item.preview)
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
        notifyDataSetChanged()
    }
}

private fun formatStorageDate(timestampMs: Long): String {
    if (timestampMs <= 0) return ""
    return SimpleDateFormat("d MMM yyyy, HH:mm", Locale.getDefault()).format(Date(timestampMs))
}
