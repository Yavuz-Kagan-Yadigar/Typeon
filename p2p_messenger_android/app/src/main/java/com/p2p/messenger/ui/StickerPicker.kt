package com.p2p.messenger.ui

import android.content.Context
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.graphics.drawable.AnimatedImageDrawable
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.StickerImport
import com.p2p.messenger.util.coreErrorText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.io.File
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

/**
 * Stickers in a chat screen (1:1 and group): the picker sheet (my stickers,
 * import from gallery / WhatsApp folder), sending, sticker bubble images and
 * "Add to my stickers". Built as a field: it registers activity-result
 * launchers.
 */
class StickerPicker(
    private val activity: AppCompatActivity,
    /** Sends a sticker id (off the main thread): the attachment's file id or "Error: ...". */
    private val send: (String) -> String,
    /** The sent sticker's bubble, on the main thread. */
    private val onSent: (SimpleChatAdapter.Item) -> Unit,
) {
    private val scope = activity.lifecycleScope
    private var dialog: BottomSheetDialog? = null
    private var progressDialog: AlertDialog? = null
    private val ids = mutableListOf<String>()
    private val favorites = mutableSetOf<String>()
    /** Long-press starts a selection; while it is not empty a tap selects too. */
    private val selected = mutableSetOf<String>()
    private var selectAllButton: View? = null
    private var deleteSelectedButton: View? = null
    private var favoriteButton: View? = null
    private val gridAdapter = StickerGridAdapter()

    private val pickImages = activity.registerForActivityResult(
        com.p2p.messenger.util.OpenMultipleDocumentsAtHome()
    ) { uris -> if (uris.isNotEmpty()) importAll { uris } }

    private val pickTree = activity.registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri -> uri?.let { tree -> importAll(whatsapp = true) { webpFilesIn(tree) } } }

    init {
        activity.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onDestroy(owner: LifecycleOwner) {
                dialog?.dismiss()
                progressDialog?.dismiss()
            }
        })
    }

    fun show() {
        if (dialog?.isShowing == true) return
        val sheet = LayoutInflater.from(activity).inflate(R.layout.sheet_sticker_picker, null)
        val grid = sheet.findViewById<RecyclerView>(R.id.recyclerStickers)
        grid.layoutManager = GridLayoutManager(activity, 3)
        grid.adapter = gridAdapter
        sheet.findViewById<View>(R.id.btnStickerAdd).setOnClickListener {
            // The system picker runs in another process.
            AppLock.beginTrustedExcursion()
            pickImages.launch(arrayOf("image/*"))
        }
        sheet.findViewById<View>(R.id.btnStickerImportWhatsapp).setOnClickListener {
            AppLock.beginTrustedExcursion()
            pickTree.launch(whatsAppStickersUri())
        }
        selected.clear()
        selectAllButton = sheet.findViewById<View>(R.id.btnStickerSelectAll).apply {
            setOnClickListener {
                val added = ids.filter { it !in selected }
                selected.addAll(ids)
                selectionChanged(added)
            }
        }
        deleteSelectedButton = sheet.findViewById<View>(R.id.btnStickerDeleteSelected).apply {
            setOnClickListener { confirmDeleteSelected() }
        }
        favoriteButton = sheet.findViewById<View>(R.id.btnStickerFavorite).apply {
            setOnClickListener { favoriteSelected() }
        }
        // 75 % of the screen, opened fully: the grid takes what the buttons leave.
        val height = (activity.resources.displayMetrics.heightPixels * 0.75f).toInt()
        grid.layoutParams.height = height - (64 * activity.resources.displayMetrics.density).toInt()
        dialog = BottomSheetDialog(activity).apply {
            setContentView(sheet)
            behavior.peekHeight = height
            behavior.state = com.google.android.material.bottomsheet.BottomSheetBehavior.STATE_EXPANDED
            behavior.skipCollapsed = true
            // The shared adapter would keep every dismissed sheet's grid and bitmaps alive.
            setOnDismissListener {
                grid.adapter = null
                if (dialog === this) dialog = null
            }
            show()
        }
        refresh()
    }

    /** "stickers_changed" (another device of mine): reload an open sheet. */
    fun reload() {
        if (dialog?.isShowing == true) refresh()
    }

    /** Sticker bubbles get their picture from the decrypted attachment, decoded off the main thread. */
    fun provideBubbleImages(adapter: SimpleChatAdapter) {
        adapter.stickerImageProvider = { fileId, done ->
            scope.launch(Dispatchers.IO) {
                // First frame at once, the (maybe slow) animation after it.
                drawableAt { P2PLib.getAttachmentFirstFrame(fileId) }?.let { p -> withContext(Dispatchers.Main) { done(p) } }
                val drawable = drawableAt { P2PLib.getAttachmentPlaintextPath(fileId) }
                withContext(Dispatchers.Main) { done(drawable) }
            }
        }
    }

    /** "Add to my stickers" on a received sticker. */
    fun saveReceived(fileId: String) {
        scope.launch(Dispatchers.IO) {
            val result = call { P2PLib.saveReceivedSticker(fileId) }
            withContext(Dispatchers.Main) {
                toast(if (result.startsWith("Error:")) coreErrorText(activity, result) else activity.getString(R.string.msg_sticker_saved))
            }
        }
    }

    private fun refresh() {
        scope.launch(Dispatchers.IO) {
            val rows = try {
                val array = JSONArray(P2PLib.listStickers())
                (0 until array.length()).mapNotNull { array.optJSONObject(it)?.takeIf { o -> o.optString("id").isNotEmpty() } }
            } catch (e: Exception) {
                emptyList()
            }
            val list = rows.map { it.optString("id") }
            withContext(Dispatchers.Main) {
                ids.clear()
                ids.addAll(list)
                favorites.clear()
                rows.filter { it.optBoolean("favorite") }.mapTo(favorites) { it.optString("id") }
                selected.retainAll(list.toSet())
                selectionChanged()
            }
        }
    }

    private fun sendSticker(id: String) {
        dialog?.dismiss()
        scope.launch(Dispatchers.IO) {
            val fileId = call { send(id) }
            withContext(Dispatchers.Main) {
                if (fileId.startsWith("Error:")) toast(coreErrorText(activity, fileId)) else onSent(sentBubble(fileId))
            }
        }
    }

    /** A sent sticker's bubble, the same shape as a file send. */
    private fun sentBubble(fileId: String) = SimpleChatAdapter.Item(
        messageId = fileId,
        text = "",
        isMine = true,
        attachment = SimpleChatAdapter.AttachmentInfo(
            fileId = fileId,
            fileName = "sticker.jxl",
            mimeType = "image/jxl",
            totalSize = 0,
            status = SimpleChatAdapter.AttachmentStatus.COMPLETE,
            isSticker = true
        )
    )

    private fun toggle(id: String) {
        if (!selected.remove(id)) selected.add(id)
        selectionChanged(listOf(id))
    }

    /**
     * Buttons + grid. [changed] = ids whose selected state flipped: only those
     * cells are rebound (payload, so no re-decode and no change animation).
     * null = the list itself changed: full rebind.
     */
    private fun selectionChanged(changed: List<String>? = null) {
        val any = selected.isNotEmpty()
        selectAllButton?.visibility = if (any) View.VISIBLE else View.GONE
        deleteSelectedButton?.visibility = if (any) View.VISIBLE else View.GONE
        favoriteButton?.visibility = if (any) View.VISIBLE else View.GONE
        (favoriteButton as? android.widget.Button)?.setText(
            if (any && favorites.containsAll(selected)) R.string.action_sticker_unfavorite else R.string.action_sticker_favorite
        )
        (deleteSelectedButton as? android.widget.Button)?.text =
            "${activity.getString(R.string.action_delete_selected)} (${selected.size})"
        if (changed == null) {
            gridAdapter.notifyDataSetChanged()
        } else {
            for (id in changed) {
                val idx = ids.indexOf(id)
                if (idx >= 0) gridAdapter.notifyItemChanged(idx, SELECTION_PAYLOAD)
            }
        }
    }

    /** All selected are favorites: unfavorite them, else favorite them. Favorites list first. */
    private fun favoriteSelected() {
        val chosen = selected.toList()
        val favorite = !favorites.containsAll(chosen)
        scope.launch(Dispatchers.IO) {
            val failed = chosen.map { call { P2PLib.setStickerFavorite(it, favorite) } }.firstOrNull { it.startsWith("Error:") }
            withContext(Dispatchers.Main) {
                if (failed != null) toast(coreErrorText(activity, failed))
                selected.clear()
                refresh()
            }
        }
    }

    private fun confirmDeleteSelected() {
        val doomed = selected.toList()
        AlertDialog.Builder(activity)
            .setMessage(R.string.msg_confirm_delete_sticker)
            .setPositiveButton(R.string.action_delete_selected) { _, _ ->
                scope.launch(Dispatchers.IO) {
                    val failed = doomed.map { call { P2PLib.deleteSticker(it) } }.firstOrNull { it.startsWith("Error:") }
                    withContext(Dispatchers.Main) {
                        if (failed != null) toast(coreErrorText(activity, failed))
                        selected.clear()
                        refresh()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Imports the pictures [list] gives (it runs off the main thread). */
    private fun importAll(whatsapp: Boolean = false, list: () -> List<Uri>) {
        val bar = android.widget.ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal)
        val label = android.widget.TextView(activity).apply { text = activity.getString(R.string.msg_sticker_importing, 0, 0) }
        val pad = (24 * activity.resources.displayMetrics.density).toInt()
        val box = android.widget.LinearLayout(activity).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad / 2)
            addView(label)
            addView(bar)
        }
        val progress = AlertDialog.Builder(activity).setView(box).setCancelable(false).show()
        progressDialog = progress
        scope.launch(Dispatchers.IO) {
            val uris = try { list() } catch (e: Exception) { emptyList() }
            val imported = AtomicInteger()
            val done = AtomicInteger()
            // A few at a time: each encode is single-threaded, and an animation's
            // frames are large, so the worker count also caps the memory.
            val workers = Semaphore((Runtime.getRuntime().availableProcessors() / 2).coerceIn(1, 4))
            withContext(Dispatchers.Main) {
                bar.max = uris.size
                label.text = activity.getString(R.string.msg_sticker_importing, 0, uris.size)
            }
            coroutineScope {
                for (uri in uris) launch {
                    // An OOM must fail this one picture, never the app.
                    val ok = try { workers.withPermit { importUri(uri, whatsapp) } } catch (e: OutOfMemoryError) { false }
                    if (ok) imported.incrementAndGet()
                    done.incrementAndGet()
                    withContext(Dispatchers.Main) {
                        val n = done.get()
                        bar.progress = n
                        label.text = activity.getString(R.string.msg_sticker_importing, n, uris.size)
                    }
                }
            }
            val ok = imported.get()
            withContext(Dispatchers.Main) {
                progress.dismiss()
                progressDialog = null
                toast(
                    if (ok > 0) activity.getString(R.string.msg_sticker_imported, ok)
                    else activity.getString(R.string.msg_sticker_import_failed)
                )
                refresh()
            }
        }
    }

    private val animatedImports = Semaphore(1)

    /** One picture as a sticker, through a cache file (the import reads a file). */
    private suspend fun importUri(uri: Uri, whatsapp: Boolean): Boolean {
        val tmp = File(File(activity.cacheDir, "sticker_import").apply { mkdirs() }, UUID.randomUUID().toString())
        return try {
            activity.contentResolver.openInputStream(uri)?.use { input ->
                tmp.outputStream().use { output -> input.copyTo(output) }
            } ?: return false
            // WhatsApp ships identical bytes to everyone: their hash names the sticker across devices.
            val origin = if (whatsapp) "wa:" + java.security.MessageDigest.getInstance("SHA-256").let { md ->
                tmp.inputStream().use { input ->
                    val buf = ByteArray(64 * 1024)
                    while (true) { val n = input.read(buf); if (n < 0) break; md.update(buf, 0, n) }
                }
                md.digest().joinToString("") { "%02x".format(it) }
            } else null
            // Already in the store: skip the decode + encode.
            if (origin != null && P2PLib.hasStickerOrigin(origin)) return true
            // Animations hold all frames (~100 MB + temps): one at a time.
            val animated = tmp.inputStream().use { i -> ByteArray(4).also { i.read(it) } }.let {
                val m = String(it, Charsets.ISO_8859_1); m == "GIF8" || m == "RIFF"
            }
            val result = if (animated) animatedImports.withPermit { StickerImport.importFile(tmp, origin) }
                else StickerImport.importFile(tmp, origin)
            !result.startsWith("Error:")
        } catch (e: Exception) {
            false
        } catch (e: OutOfMemoryError) {
            // ponytail: workers are counted, not their bytes; several huge
            // animations at once can run out. One fails; weigh by size if it matters.
            false
        } finally {
            tmp.delete()
        }
    }

    /** Every `.webp` under [treeUri], subfolders included. */
    private fun webpFilesIn(treeUri: Uri): List<Uri> {
        val out = mutableListOf<Uri>()
        fun walk(parentId: String) {
            activity.contentResolver.query(
                DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId),
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE
                ),
                null, null, null
            )?.use { cursor ->
                while (cursor.moveToNext()) {
                    val id = cursor.getString(0) ?: continue
                    if (cursor.getString(2) == DocumentsContract.Document.MIME_TYPE_DIR) walk(id)
                    else if (cursor.getString(1)?.endsWith(".webp", true) == true) {
                        out.add(DocumentsContract.buildDocumentUriUsingTree(treeUri, id))
                    }
                }
            }
        }
        walk(DocumentsContract.getTreeDocumentId(treeUri))
        return out
    }

    private fun whatsAppStickersUri(): Uri = DocumentsContract.buildDocumentUri(
        "com.android.externalstorage.documents",
        "primary:Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Stickers"
    )

    private fun toast(text: String) = Toast.makeText(activity, text, Toast.LENGTH_SHORT).show()

    private fun call(f: () -> String): String = try { f() } catch (e: Exception) { "Error: ${e.message}" }

    /** The picture at the path [path] returns (a `.png`, or a `.gif` that plays). */
    private fun drawableAt(path: () -> String): Drawable? {
        val p = call(path)
        return if (p.startsWith("Error:")) null else loadStickerDrawable(activity, File(p))
    }

    private inner class StickerGridAdapter : RecyclerView.Adapter<StickerGridAdapter.Holder>() {
        private val cache = object : android.util.LruCache<String, Drawable>(STICKER_CACHE_BYTES) {
            override fun sizeOf(key: String, value: Drawable): Int = stickerDrawableBytes(value)
        }
        /** Being decoded: no second request for the same sticker. */
        private val pending = mutableSetOf<String>()

        inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val image: ImageView = view.findViewById(R.id.imgStickerCell)
            val star: View = view.findViewById(R.id.txtStickerFavorite)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_sticker, parent, false))

        override fun getItemCount(): Int = ids.size

        override fun onBindViewHolder(holder: Holder, position: Int, payloads: MutableList<Any>) {
            if (payloads.isEmpty()) onBindViewHolder(holder, position) else bindSelection(holder, ids[position])
        }

        private fun bindSelection(holder: Holder, id: String) {
            val on = id in selected
            // Dim + accent frame: dimming alone is easy to miss on busy stickers.
            holder.image.alpha = if (on) 0.5f else 1f
            holder.itemView.foreground = if (on) selectionFrame else null
        }

        private val selectionFrame: Drawable by lazy {
            val d = activity.resources.displayMetrics.density
            val accent = com.p2p.messenger.util.ThemePrefs.getAccentColor(activity)
                ?: com.google.android.material.color.MaterialColors.getColor(
                    activity, androidx.appcompat.R.attr.colorPrimary, android.graphics.Color.BLUE
                )
            android.graphics.drawable.GradientDrawable().apply {
                setStroke((3 * d).toInt(), accent)
                cornerRadius = 8 * d
            }
        }

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val id = ids[position]
            val cached = cache.get(id)
            holder.image.setImageDrawable(cached)
            bindSelection(holder, id)
            holder.star.visibility = if (id in favorites) View.VISIBLE else View.GONE
            holder.itemView.setOnClickListener { if (selected.isEmpty()) sendSticker(id) else toggle(id) }
            holder.itemView.setOnLongClickListener {
                toggle(id)
                true
            }
            if (cached != null || !pending.add(id)) return
            scope.launch(Dispatchers.IO) {
                drawableAt { P2PLib.stickerFirstFrame(id) }?.let { p ->
                    withContext(Dispatchers.Main) {
                        cache.put(id, p)
                        val idx = ids.indexOf(id)
                        if (idx >= 0) notifyItemChanged(idx)
                    }
                }
                val drawable = drawableAt { P2PLib.stickerPlainPath(id) }
                withContext(Dispatchers.Main) {
                    pending.remove(id)
                    if (drawable == null) return@withContext
                    cache.put(id, drawable)
                    val idx = ids.indexOf(id)
                    if (idx >= 0) notifyItemChanged(idx)
                }
            }
        }
    }
}

private const val SELECTION_PAYLOAD = "selection"

/** Byte budget of a sticker drawable cache. */
internal const val STICKER_CACHE_BYTES = 32 * 1024 * 1024

/** Approximate pixel bytes of a cached sticker (animated ones keep ~2 frame buffers). */
internal fun stickerDrawableBytes(d: Drawable): Int {
    val n = if (d is android.graphics.drawable.BitmapDrawable && d.bitmap != null) {
        d.bitmap.allocationByteCount.toLong()
    } else {
        maxOf(d.intrinsicWidth, 0).toLong() * maxOf(d.intrinsicHeight, 0) * 8
    }
    return n.coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
}

/** A sticker picture: a `.gif` plays (API 28+), anything else is a still. */
private fun loadStickerDrawable(context: Context, file: File): Drawable? {
    if (!file.exists()) return null
    return try {
        if (file.extension.equals("gif", true) && Build.VERSION.SDK_INT >= 28) {
            ImageDecoder.decodeDrawable(ImageDecoder.createSource(file)).also {
                (it as? AnimatedImageDrawable)?.apply {
                    repeatCount = AnimatedImageDrawable.REPEAT_INFINITE
                    start()
                }
            }
        } else {
            BitmapDrawable(context.resources, BitmapFactory.decodeFile(file.absolutePath) ?: return null)
        }
    } catch (e: Throwable) {
        null
    }
}
