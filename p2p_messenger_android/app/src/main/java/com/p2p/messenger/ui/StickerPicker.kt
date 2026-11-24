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
import com.p2p.messenger.util.MAX_FOREIGN_URI_BYTES
import com.p2p.messenger.util.StickerImport
import com.p2p.messenger.util.copyToCapped
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
    /** Sends a sticker id as an answer to the quote (off the main thread): the attachment's file id or "Error: ...". */
    private val send: (String, com.p2p.messenger.util.Quote.Ref?) -> String,
    /** The quote the sticker answers, taken from the input on the main thread. */
    private val takeQuote: () -> com.p2p.messenger.util.Quote.Ref?,
    /** The sent sticker's bubble, on the main thread. */
    private val onSent: (SimpleChatAdapter.Item) -> Unit,
) {
    private val scope = activity.lifecycleScope
    private var dialog: BottomSheetDialog? = null
    private var progressDialog: AlertDialog? = null
    /** Every sticker in the store, favorites first. */
    private val allIds = mutableListOf<String>()
    /** The stickers the grid shows: all, or the open folder's. */
    private val ids = mutableListOf<String>()
    private val favorites = mutableSetOf<String>()
    /** Animated stickers: only these get a first-frame placeholder. */
    private val animatedIds = mutableSetOf<String>()
    private class Folder(val id: Long, val name: String, val stickers: Set<String>)
    private val folders = mutableListOf<Folder>()
    /** The folder the grid shows, or null: folders first, then every sticker. */
    private var openFolder: Folder? = null
    /** Folder cells ahead of the stickers in the grid. */
    private val folderCount get() = if (openFolder == null) folders.size else 0
    private var bar: View? = null
    private var backCallback: androidx.activity.OnBackPressedCallback? = null
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
        bar = sheet
        openFolder = null
        sheet.findViewById<View>(R.id.btnStickerFolderBack).setOnClickListener { showFolder(null) }
        sheet.findViewById<View>(R.id.btnStickerFolderRename).setOnClickListener { renameOpenFolder() }
        sheet.findViewById<View>(R.id.btnStickerFolderDelete).setOnClickListener { confirmDeleteOpenFolder() }
        sheet.findViewById<View>(R.id.btnStickerNewFolder).setOnClickListener {
            askFolderName(R.string.action_sticker_folder_create, "") { name -> coreCall({ P2PLib.createStickerFolder(name) }) { refresh() } }
        }
        sheet.findViewById<View>(R.id.btnStickerAddToFolder).setOnClickListener { chooseFolderForSelected() }
        sheet.findViewById<View>(R.id.btnStickerRemoveFromFolder).setOnClickListener { removeSelectedFromFolder() }
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
            // Back closes an open folder first, then the sheet.
            backCallback = object : androidx.activity.OnBackPressedCallback(false) {
                override fun handleOnBackPressed() = showFolder(null)
            }.also { onBackPressedDispatcher.addCallback(it) }
            behavior.peekHeight = height
            behavior.state = com.google.android.material.bottomsheet.BottomSheetBehavior.STATE_EXPANDED
            behavior.skipCollapsed = true
            // The shared adapter would keep every dismissed sheet's grid and bitmaps alive.
            setOnDismissListener {
                grid.adapter = null
                if (bar === sheet) bar = null
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
            val folderList = try {
                val array = JSONArray(P2PLib.listStickerFolders())
                (0 until array.length()).mapNotNull { i ->
                    val o = array.optJSONObject(i) ?: return@mapNotNull null
                    val stickers = o.optJSONArray("stickers")
                    Folder(o.optLong("id"), o.optString("name"), (0 until (stickers?.length() ?: 0)).mapTo(mutableSetOf()) { stickers!!.optString(it) })
                }
            } catch (e: Exception) {
                emptyList()
            }
            withContext(Dispatchers.Main) {
                allIds.clear()
                allIds.addAll(list)
                favorites.clear()
                rows.filter { it.optBoolean("favorite") }.mapTo(favorites) { it.optString("id") }
                animatedIds.clear()
                rows.filter { it.optBoolean("animated") }.mapTo(animatedIds) { it.optString("id") }
                folders.clear()
                folders.addAll(folderList)
                // The open folder, refreshed (null when it is gone).
                openFolder = openFolder?.let { o -> folders.firstOrNull { it.id == o.id } }
                showGrid()
            }
        }
    }

    /** Shows [folder]'s stickers, or (null) the folders and every sticker. */
    private fun showFolder(folder: Folder?) {
        openFolder = folder
        selected.clear()
        showGrid()
        bar?.findViewById<RecyclerView>(R.id.recyclerStickers)?.scrollToPosition(0)
    }

    private fun showGrid() {
        ids.clear()
        val folder = openFolder
        if (folder == null) ids.addAll(allIds) else allIds.filterTo(ids) { it in folder.stickers }
        selected.retainAll(ids.toSet())
        selectionChanged()
    }

    /** Grid position of the sticker [id], or -1. */
    private fun positionOf(id: String): Int = ids.indexOf(id).let { if (it < 0) -1 else it + folderCount }

    private fun chooseFolderForSelected() {
        val chosen = selected.toList()
        val list = folders.toList()
        val names = list.map { it.name } + activity.getString(R.string.action_sticker_folder_create)
        AlertDialog.Builder(activity)
            .setTitle(R.string.action_sticker_add_to_folder)
            .setItems(names.toTypedArray()) { _, which ->
                val folder = list.getOrNull(which)
                if (folder != null) {
                    addToFolder(folder.id, folder.name, chosen)
                } else {
                    askFolderName(R.string.action_sticker_folder_create, "") { name ->
                        coreCall({ P2PLib.createStickerFolder(name) }) { id -> addToFolder(id.toLong(), name, chosen) }
                    }
                }
            }
            .show()
    }

    private fun addToFolder(id: Long, name: String, chosen: List<String>) {
        coreCall({ P2PLib.addStickersToFolder(id, JSONArray(chosen).toString()) }) {
            toast(activity.getString(R.string.msg_sticker_added_to_folder, name))
            selected.clear()
            refresh()
        }
    }

    private fun removeSelectedFromFolder() {
        val folder = openFolder ?: return
        val chosen = selected.toList()
        coreCall({ P2PLib.removeStickersFromFolder(folder.id, JSONArray(chosen).toString()) }) {
            selected.clear()
            refresh()
        }
    }

    private fun renameOpenFolder() {
        val folder = openFolder ?: return
        askFolderName(R.string.action_sticker_folder_rename, folder.name) { name ->
            coreCall({ P2PLib.renameStickerFolder(folder.id, name) }) { refresh() }
        }
    }

    /** Deletes the open folder only: its stickers stay. */
    private fun confirmDeleteOpenFolder() {
        val folder = openFolder ?: return
        AlertDialog.Builder(activity)
            .setMessage(activity.getString(R.string.msg_confirm_delete_sticker_folder, folder.name))
            .setPositiveButton(R.string.action_sticker_folder_delete) { _, _ ->
                coreCall({ P2PLib.deleteStickerFolder(folder.id) }) {
                    showFolder(null)
                    refresh()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun askFolderName(title: Int, initial: String, done: (String) -> Unit) {
        val input = android.widget.EditText(activity).apply {
            setText(initial)
            setSelection(initial.length)
            hint = activity.getString(R.string.hint_sticker_folder_name)
            isSingleLine = true
            filters = arrayOf(android.text.InputFilter.LengthFilter(64))
        }
        AlertDialog.Builder(activity)
            .setTitle(title)
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val name = input.text.toString().trim()
                if (name.isNotEmpty()) done(name)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Runs [f] off the main thread; an error is a toast, else [ok] gets the result on the main thread. */
    private fun coreCall(f: () -> String, ok: (String) -> Unit) {
        scope.launch(Dispatchers.IO) {
            val result = call(f)
            withContext(Dispatchers.Main) { if (result.startsWith("Error:")) toast(coreErrorText(activity, result)) else ok(result) }
        }
    }

    private fun sendSticker(id: String) {
        dialog?.dismiss()
        val quote = takeQuote()
        scope.launch(Dispatchers.IO) {
            val fileId = call { send(id, quote) }
            withContext(Dispatchers.Main) {
                if (fileId.startsWith("Error:")) toast(coreErrorText(activity, fileId)) else onSent(sentBubble(fileId, quote))
            }
        }
    }

    /** A sent sticker's bubble, the same shape as a file send. */
    private fun sentBubble(fileId: String, quote: com.p2p.messenger.util.Quote.Ref?) = SimpleChatAdapter.Item(
        messageId = fileId,
        text = "",
        isMine = true,
        replyToMessageId = quote?.id,
        replyToPreview = quote?.preview,
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
        val folder = openFolder
        bar?.let { b ->
            fun show(id: Int, on: Boolean) { b.findViewById<View>(id).visibility = if (on) View.VISIBLE else View.GONE }
            show(R.id.btnStickerFolderBack, folder != null)
            show(R.id.btnStickerFolderRename, folder != null && !any)
            show(R.id.btnStickerFolderDelete, folder != null && !any)
            show(R.id.btnStickerAdd, folder == null)
            show(R.id.btnStickerImportWhatsapp, folder == null)
            show(R.id.btnStickerNewFolder, folder == null && !any)
            show(R.id.btnStickerAddToFolder, any)
            show(R.id.btnStickerRemoveFromFolder, folder != null && any)
            b.findViewById<android.widget.Button>(R.id.btnStickerFolderBack).text = "‹ ${folder?.name.orEmpty()}"
        }
        backCallback?.isEnabled = folder != null
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
                val idx = positionOf(id)
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
                    val failed = call { P2PLib.deleteStickers(org.json.JSONArray(doomed).toString()) }.takeIf { it.startsWith("Error:") }
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
            // Foreign `content://` bytes: capped, else this one picture fails
            // (tmp deleted in `finally`), the import toast counts it as failed.
            val copied = activity.contentResolver.openInputStream(uri)?.use { it.copyToCapped(tmp, MAX_FOREIGN_URI_BYTES) } ?: false
            if (!copied) return false
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

    /** The picture at the path [path] returns (a `.png`, or a `.gif` that plays), at most [maxPx] a side (0 = as stored). */
    private fun drawableAt(maxPx: Int = 0, path: () -> String): Drawable? {
        val p = call(path)
        return if (p.startsWith("Error:")) null else loadStickerDrawable(activity, File(p), maxPx)
    }

    private inner class StickerGridAdapter : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
        // Cell-sized pictures: a 600 px sticker decoded whole filled the cache
        // with ~11 animations, so scrolling back showed blank cells again.
        // ponytail: one fixed size; tablets with wide cells may want more.
        // Lazy: the picker (and this adapter) is built in the Activity's field initializers, before it has resources.
        private val maxPx by lazy { (128 * activity.resources.displayMetrics.density).toInt() }
        private val cache = object : android.util.LruCache<String, Drawable>(2 * STICKER_CACHE_BYTES) {
            override fun sizeOf(key: String, value: Drawable): Int = stickerDrawableBytes(value)
        }
        /** Cached as the first frame only: the animation is still to load. */
        private val partial = mutableSetOf<String>()
        /** Being decoded: no second request for the same sticker. */
        private val pending = mutableSetOf<String>()
        /** The cell each shown sticker is bound to (main thread). */
        private val boundHolders = HashMap<String, Holder>()
        /** Few grid decodes at once: a fling must not decode 64 animations in parallel. */
        private val decodeGate = Semaphore(3)
        /** Animation conversions (slow) wait here, not in front of the stills and first frames. */
        private val animationGate = Semaphore(2)

        inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val image: ImageView = view.findViewById(R.id.imgStickerCell)
            val star: View = view.findViewById(R.id.txtStickerFavorite)
            var boundId: String? = null
        }

        override fun onViewRecycled(holder: RecyclerView.ViewHolder) {
            if (holder is Holder) holder.boundId?.let { if (boundHolders[it] === holder) boundHolders.remove(it) }
        }

        /** Main thread: [id] still has a cell; else it stops pending (a re-bind asks again). */
        private fun wanted(id: String): Boolean =
            (boundHolders[id]?.boundId == id).also { if (!it) pending.remove(id) }

        /** Main thread: caches [d] and puts it in [id]'s cell, no rebind (no change animation). */
        private fun show(id: String, d: Drawable, firstFrame: Boolean) {
            cache.put(id, d)
            if (firstFrame) partial.add(id) else partial.remove(id)
            boundHolders[id]?.takeIf { it.boundId == id }?.image?.setImageDrawable(d)
        }

        inner class FolderHolder(view: View) : RecyclerView.ViewHolder(view) {
            val label: android.widget.TextView = view.findViewById(R.id.txtStickerFolder)
            val previews: List<ImageView> = listOf(
                R.id.imgStickerFolderPreview0, R.id.imgStickerFolderPreview1,
                R.id.imgStickerFolderPreview2, R.id.imgStickerFolderPreview3,
            ).map { view.findViewById(it) }
        }

        /** Folder previews: quarter-cell stills (an animation's first frame), kept apart from the grid cache. */
        private val previewCache = object : android.util.LruCache<String, android.graphics.Bitmap>(4 * 1024 * 1024) {
            override fun sizeOf(key: String, value: android.graphics.Bitmap): Int = value.allocationByteCount
        }

        /** Shows the first four of [folder]'s stickers (grid order) in [holder]'s 2x2 previews; false when it has none. */
        private fun bindFolderPreviews(holder: FolderHolder, folder: Folder): Boolean {
            val shown = allIds.asSequence().filter { it in folder.stickers }.take(holder.previews.size).toList()
            holder.previews.forEachIndexed { i, view ->
                val id = shown.getOrNull(i)
                // The tag says which sticker the view waits for: a recycled view drops a late decode.
                view.tag = id
                val cached = id?.let { previewCache.get(it) }
                view.setImageBitmap(cached)
                if (id == null || cached != null) return@forEachIndexed
                val animated = id in animatedIds
                scope.launch(Dispatchers.IO) {
                    val bitmap = decodeGate.withPermit {
                        val path: () -> String = if (animated) ({ P2PLib.stickerFirstFrame(id) }) else ({ P2PLib.stickerPlainPath(id) })
                        (drawableAt(maxPx / 2, path) as? BitmapDrawable)?.bitmap
                    } ?: return@launch
                    withContext(Dispatchers.Main) {
                        previewCache.put(id, bitmap)
                        if (view.tag == id) view.setImageBitmap(bitmap)
                    }
                }
            }
            return shown.isNotEmpty()
        }

        override fun getItemViewType(position: Int): Int = if (position < folderCount) FOLDER_CELL else STICKER_CELL

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val inflater = LayoutInflater.from(parent.context)
            return if (viewType == FOLDER_CELL) FolderHolder(inflater.inflate(R.layout.item_sticker_folder, parent, false))
                else Holder(inflater.inflate(R.layout.item_sticker, parent, false))
        }

        override fun getItemCount(): Int = folderCount + ids.size

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int, payloads: MutableList<Any>) {
            if (payloads.isEmpty() || holder !is Holder) onBindViewHolder(holder, position)
            else bindSelection(holder, ids[position - folderCount])
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

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            if (holder is FolderHolder) {
                val folder = folders[position]
                val icon = if (bindFolderPreviews(holder, folder)) "" else "📁 "
                holder.label.text = "$icon${folder.name} (${folder.stickers.size})"
                holder.itemView.setOnClickListener { showFolder(folder) }
                return
            }
            holder as Holder
            val id = ids[position - folderCount]
            holder.boundId?.let { if (boundHolders[it] === holder) boundHolders.remove(it) }
            holder.boundId = id
            boundHolders[id] = holder
            val cached = cache.get(id)
            holder.image.setImageDrawable(cached)
            bindSelection(holder, id)
            holder.star.visibility = if (id in favorites) View.VISIBLE else View.GONE
            holder.itemView.setOnClickListener { if (selected.isEmpty()) sendSticker(id) else toggle(id) }
            holder.itemView.setOnLongClickListener {
                toggle(id)
                true
            }
            if ((cached != null && id !in partial) || !pending.add(id)) return
            val animated = id in animatedIds
            val needFirst = animated && cached == null
            scope.launch(Dispatchers.IO) {
                // A still's first frame is the still itself: one decode, not two.
                if (needFirst) decodeGate.withPermit {
                    if (!withContext(Dispatchers.Main) { wanted(id) }) return@launch
                    drawableAt(maxPx) { P2PLib.stickerFirstFrame(id) }?.let { p -> withContext(Dispatchers.Main) { show(id, p, true) } }
                }
                (if (animated) animationGate else decodeGate).withPermit {
                    // Scrolled away while waiting: skip; a re-bind asks again.
                    if (!withContext(Dispatchers.Main) { wanted(id) }) return@launch
                    val drawable = drawableAt(maxPx) { P2PLib.stickerPlainPath(id) }
                    withContext(Dispatchers.Main) {
                        pending.remove(id)
                        if (drawable != null) show(id, drawable, false)
                    }
                }
            }
        }
    }
}

private const val SELECTION_PAYLOAD = "selection"
private const val STICKER_CELL = 0
private const val FOLDER_CELL = 1

/** Byte budget unit of a sticker drawable cache (the grid cache holds twice this). */
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

/** A sticker picture: a `.gif` plays, anything else is a still. At most [maxPx] a side (0 = as stored). */
private fun loadStickerDrawable(context: Context, file: File, maxPx: Int = 0): Drawable? {
    if (!file.exists()) return null
    return try {
        if (maxPx > 0) {
            val scaled = ImageDecoder.OnHeaderDecodedListener { decoder, info, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                val (w, h) = info.size.width to info.size.height
                val big = maxOf(w, h)
                if (big > maxPx) decoder.setTargetSize(maxOf(1, w * maxPx / big), maxOf(1, h * maxPx / big))
            }
            val source = ImageDecoder.createSource(file)
            return if (file.extension.equals("gif", true)) {
                ImageDecoder.decodeDrawable(source, scaled).also {
                    (it as? AnimatedImageDrawable)?.apply {
                        repeatCount = AnimatedImageDrawable.REPEAT_INFINITE
                        start()
                    }
                }
            } else {
                BitmapDrawable(context.resources, ImageDecoder.decodeBitmap(source, scaled))
            }
        }
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
