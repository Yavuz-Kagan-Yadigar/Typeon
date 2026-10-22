package com.p2p.messenger.ui

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
 * Spec dışı, kullanıcı isteği: depolama yönetimi ekranı (Ayarlar →
 * "Storage"). Üstte toplam kullanım özeti (veritabanı / ekler / çözülmüş
 * önbellek) ve "Çözülmüş önbelleği temizle" düğmesi; altta sohbet başına
 * ek boyutu (büyükten küçüğe). Bir sohbete dokunulunca o sohbetin ekleri
 * açılır: onay kutuları, "Tümünü seç" ve "Seçilenleri sil".
 *
 * Silme YALNIZCA bu cihazdaki kopyayı kaldırır (bkz.
 * `P2PLib.removeLocalAttachments`): karşı taraf BİLMEZ, `files` satırı
 * kalır ve ek sohbette yeniden indirilebilir görünür.
 */
class StorageActivity : AppCompatActivity() {

    private lateinit var layoutChats: View
    private lateinit var layoutAttachments: View
    private lateinit var txtTotal: TextView
    private lateinit var txtDatabase: TextView
    private lateinit var txtAttachments: TextView
    private lateinit var txtCache: TextView
    private lateinit var txtNoChats: View
    private lateinit var txtNoAttachments: View
    private lateinit var txtAttachmentsTitle: TextView
    private lateinit var btnDeleteSelected: Button

    private val chatAdapter = StorageChatsAdapter { chat -> openChat(chat) }
    private val selected = mutableSetOf<String>()
    private val attachmentAdapter = StorageAttachmentsAdapter(selected) { _, _ -> refreshDeleteButton() }
    private var currentChat: StorageChat? = null
    private lateinit var backToChats: OnBackPressedCallback

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_storage)
        supportActionBar?.title = getString(R.string.title_storage)

        layoutChats = findViewById(R.id.layoutStorageChats)
        layoutAttachments = findViewById(R.id.layoutStorageAttachments)
        txtTotal = findViewById(R.id.txtStorageTotal)
        txtDatabase = findViewById(R.id.txtStorageDatabase)
        txtAttachments = findViewById(R.id.txtStorageAttachments)
        txtCache = findViewById(R.id.txtStorageCache)
        txtNoChats = findViewById(R.id.txtStorageNoChats)
        txtNoAttachments = findViewById(R.id.txtStorageNoAttachments)
        txtAttachmentsTitle = findViewById(R.id.txtStorageAttachmentsTitle)
        btnDeleteSelected = findViewById(R.id.btnDeleteSelected)

        findViewById<RecyclerView>(R.id.recyclerStorageChats).apply {
            layoutManager = LinearLayoutManager(this@StorageActivity)
            adapter = chatAdapter
        }
        findViewById<RecyclerView>(R.id.recyclerStorageAttachments).apply {
            layoutManager = LinearLayoutManager(this@StorageActivity)
            adapter = attachmentAdapter
        }

        // Çözülmüş (düz metin) kopyalar: uygulama zaten birkaç yerde bunları
        // siliyor (bkz. P2PApplication.onCreate / util.AppLock) — aynı desen.
        findViewById<Button>(R.id.btnClearCache).setOnClickListener { clearDecryptedCache() }
        findViewById<Button>(R.id.btnSelectAll).setOnClickListener { toggleSelectAll() }
        btnDeleteSelected.setOnClickListener { confirmDeleteSelected() }
        refreshDeleteButton()

        // Sistem "geri" tuşu ekranı kapatmak yerine sohbet listesine dönsün.
        backToChats = object : OnBackPressedCallback(false) {
            override fun handleOnBackPressed() { showChats() }
        }
        onBackPressedDispatcher.addCallback(this, backToChats)

        loadUsage()
    }

    /** Depolama özeti + sohbet listesi. */
    private fun loadUsage() {
        lifecycleScope.launch {
            val json = withContext(Dispatchers.IO) {
                try { P2PLib.storageUsage() } catch (e: Exception) { "" }
            }
            val obj = try { JSONObject(json) } catch (e: Exception) { null }
            if (obj == null) {
                Toast.makeText(this@StorageActivity, R.string.msg_storage_load_failed, Toast.LENGTH_SHORT).show()
                return@launch
            }
            val dbBytes = obj.optLong("db_bytes")
            val attachmentBytes = obj.optLong("attachments_bytes")
            val cacheBytes = obj.optLong("cache_bytes")
            txtTotal.text = getString(R.string.storage_total) + ": " + formatSize(dbBytes + attachmentBytes + cacheBytes)
            txtDatabase.text = getString(R.string.storage_database) + ": " + formatSize(dbBytes)
            txtAttachments.text = getString(R.string.storage_attachments) + ": " + formatSize(attachmentBytes)
            txtCache.text = getString(R.string.storage_decrypted_cache) + ": " + formatSize(cacheBytes)

            val chats = mutableListOf<StorageChat>()
            val arr = obj.optJSONArray("chats") ?: JSONArray()
            for (i in 0 until arr.length()) {
                val c = arr.optJSONObject(i) ?: continue
                chats.add(StorageChat(
                    kind = c.optString("kind"),
                    id = c.optString("id"),
                    name = c.optString("name"),
                    bytes = c.optLong("bytes"),
                    count = c.optInt("count")
                ))
            }
            chatAdapter.submitList(chats)
            txtNoChats.visibility = if (chats.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    /** Seçili sohbetin ek listesi (1:1 → `listAttachments`, grup →
     *  `listGroupAttachments`). */
    private fun loadAttachments(chat: StorageChat) {
        lifecycleScope.launch {
            val json = withContext(Dispatchers.IO) {
                try {
                    if (chat.kind == "group") P2PLib.listGroupAttachments(chat.id)
                    else P2PLib.listAttachments(chat.id)
                } catch (e: Exception) { "[]" }
            }
            val items = mutableListOf<StorageAttachment>()
            val arr = try { JSONArray(json) } catch (e: Exception) { JSONArray() }
            for (i in 0 until arr.length()) {
                val a = arr.optJSONObject(i) ?: continue
                val previewHex = a.optString("preview_hex")
                items.add(StorageAttachment(
                    fileId = a.optString("file_id"),
                    name = a.optString("file_name"),
                    mimeType = a.optString("mime_type"),
                    size = a.optLong("total_size"),
                    createdAt = a.optLong("created_at"),
                    preview = if (previewHex.isEmpty()) null else hexToBytesOrNull(previewHex)
                ))
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

    /** Çözülmüş (düz metin) kopyaları siler — uygulamanın zaten yaptığı
     *  temizlik (bkz. P2PApplication.onCreate / util.AppLock). */
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
        if (all.isEmpty()) return
        if (selected.size >= all.size) {
            selected.clear()
        } else {
            all.forEach { selected.add(it.fileId) }
        }
        attachmentAdapter.notifyDataSetChanged()
        refreshDeleteButton()
    }

    private fun refreshDeleteButton() {
        btnDeleteSelected.isEnabled = selected.isNotEmpty()
    }

    private fun confirmDeleteSelected() {
        if (selected.isEmpty()) {
            Toast.makeText(this, R.string.msg_storage_nothing_selected, Toast.LENGTH_SHORT).show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.storage_delete_confirm_title)
            .setMessage(R.string.storage_delete_confirm_message)
            .setPositiveButton(R.string.action_delete_selected) { _, _ -> deleteSelected() }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun deleteSelected() {
        val ids = selected.toList()
        val payload = JSONArray().apply { ids.forEach { put(it) } }.toString()
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                try { P2PLib.removeLocalAttachments(payload) } catch (e: Exception) { "Error: ${e.message}" }
            }
            if (result.startsWith("Error:")) {
                Toast.makeText(
                    this@StorageActivity,
                    coreErrorText(this@StorageActivity, result),
                    Toast.LENGTH_SHORT
                ).show()
            } else {
                Toast.makeText(
                    this@StorageActivity,
                    getString(R.string.msg_attachments_removed, ids.size),
                    Toast.LENGTH_SHORT
                ).show()
            }
            selected.clear()
            refreshDeleteButton()
            currentChat?.let { loadAttachments(it) }
            loadUsage()
        }
    }

    private fun formatSize(bytes: Long): String = Formatter.formatShortFileSize(this, bytes)
}

/** Bir sohbetin depolama satırı (bkz. Rust `storage_usage`). */
data class StorageChat(
    /** "contact" | "group" */
    val kind: String,
    /** 1:1 → kişinin kanonik cihaz parmak izi, grup → `group_id`. */
    val id: String,
    val name: String,
    val bytes: Long,
    val count: Int
)

/** Bir ekin satırı (bkz. Rust `AttachmentSummary`). */
data class StorageAttachment(
    val fileId: String,
    val name: String,
    val mimeType: String,
    val size: Long,
    val createdAt: Long,
    /** Küçük JPEG önizleme (hex'ten çözülmüş) — dosya/klasör değil, görsel. */
    val preview: ByteArray?
)

/** Sohbet listesi: ad + ek boyutu/dosya sayısı. */
class StorageChatsAdapter(
    private val onClick: (StorageChat) -> Unit
) : RecyclerView.Adapter<StorageChatsAdapter.ViewHolder>() {

    val items = mutableListOf<StorageChat>()

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val name: TextView = itemView.findViewById(R.id.txtStorageChatName)
        val size: TextView = itemView.findViewById(R.id.txtStorageChatSize)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_storage_chat, parent, false)
        return ViewHolder(view)
    }

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

/** Bir sohbetin ekleri: onay kutusu, küçük önizleme, ad, tür/boyut/tarih. */
class StorageAttachmentsAdapter(
    private val selected: MutableSet<String>,
    private val onToggle: (StorageAttachment, Boolean) -> Unit
) : RecyclerView.Adapter<StorageAttachmentsAdapter.ViewHolder>() {

    val items = mutableListOf<StorageAttachment>()

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val check: CheckBox = itemView.findViewById(R.id.checkStorageAttachment)
        val image: ImageView = itemView.findViewById(R.id.imgStorageAttachment)
        val name: TextView = itemView.findViewById(R.id.txtStorageAttachmentName)
        val info: TextView = itemView.findViewById(R.id.txtStorageAttachmentInfo)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_storage_attachment, parent, false)
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        val context = holder.itemView.context
        holder.name.text = item.name
        holder.info.text = context.getString(
            R.string.storage_attachment_type,
            item.mimeType.ifEmpty { "—" }.substringAfter('/').uppercase(),
            formatStorageDate(item.createdAt)
        ) + " · " + Formatter.formatShortFileSize(context, item.size)

        // Görsel önizleme: dosya/klasör eklerinde yoktur.
        val preview = item.preview
        val bitmap = preview?.let { ImagePreview.decodeBytes(it, 256) }
        if (bitmap != null) {
            holder.image.visibility = View.VISIBLE
            holder.image.setImageBitmap(bitmap)
        } else {
            holder.image.visibility = View.GONE
        }

        // Geri dönüştürülmüş satır: eski dinleyici tetiklenmesin.
        holder.check.setOnCheckedChangeListener(null)
        holder.check.isChecked = selected.contains(item.fileId)
        holder.check.setOnCheckedChangeListener { _, checked ->
            if (checked) selected.add(item.fileId) else selected.remove(item.fileId)
            onToggle(item, checked)
        }
        holder.itemView.setOnClickListener { holder.check.isChecked = !holder.check.isChecked }
    }

    fun submitList(newItems: List<StorageAttachment>) {
        items.clear()
        items.addAll(newItems)
        notifyDataSetChanged()
    }
}

/** Ek tarihi (gün/ay/yıl + saat) — sohbet balonundaki kısa biçimden uzun. */
private fun formatStorageDate(timestampMs: Long): String {
    if (timestampMs <= 0) return ""
    return SimpleDateFormat("d MMM yyyy, HH:mm", Locale.getDefault()).format(Date(timestampMs))
}
