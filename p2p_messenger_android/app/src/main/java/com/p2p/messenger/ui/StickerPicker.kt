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
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.io.File
import java.util.UUID

/**
 * Spec dışı, kullanıcı isteği (WhatsApp tarzı çıkartmalar): sohbet giriş
 * çubuğundaki çıkartma düğmesiyle açılan alt sayfa — kendi
 * çıkartmalarımızın ızgarası, "Ekle" (galeri) ve "WhatsApp'tan aktar"
 * (klasör) düğmeleri.
 *
 * Bir çıkartmaya dokunmak [onSend] ile gönderir; uzun basmak silmeyi
 * sorar. Başka bir cihazım çıkartma eklediyse/çıkardıysa ("stickers_changed"
 * olayı) [reload] listeyi tazeler.
 */
class StickerPicker(
    private val activity: AppCompatActivity,
    /** Sticker id -> gönder (1:1 veya grup — çağıran taraf bilir). */
    private val onSend: (String) -> Unit,
) {
    private val scope = activity.lifecycleScope
    private var dialog: BottomSheetDialog? = null
    private val items = mutableListOf<Sticker>()
    private val gridAdapter = StickerGridAdapter()

    /** Galeriden ekle (birden çok). */
    private val pickImages = activity.registerForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris -> if (uris.isNotEmpty()) importUris(uris) }

    /** WhatsApp'ın çıkartma klasörü. */
    private val pickTree = activity.registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri -> uri?.let { importTree(it) } }

    fun show() {
        if (dialog?.isShowing == true) return
        val sheet = LayoutInflater.from(activity).inflate(R.layout.sheet_sticker_picker, null)
        val bottom = BottomSheetDialog(activity)
        bottom.setContentView(sheet)
        val grid = sheet.findViewById<RecyclerView>(R.id.recyclerStickers)
        grid.layoutManager = GridLayoutManager(activity, GRID_COLUMNS)
        grid.adapter = gridAdapter
        sheet.findViewById<View>(R.id.btnStickerAdd).setOnClickListener {
            // Sistem dosya seçicisi BAŞKA bir süreçte açılır.
            AppLock.beginTrustedExcursion()
            pickImages.launch(arrayOf("image/*"))
        }
        sheet.findViewById<View>(R.id.btnStickerImportWhatsapp).setOnClickListener {
            AppLock.beginTrustedExcursion()
            pickTree.launch(whatsAppStickersUri())
        }
        dialog = bottom
        bottom.show()
        refresh()
    }

    /** The sticker store changed (another device): reload, but only if the
     *  sheet is open — otherwise there is nothing to show. */
    fun reload() {
        if (dialog?.isShowing == true) refresh()
    }

    private fun refresh() {
        scope.launch(Dispatchers.IO) {
            val list = loadStickers()
            withContext(Dispatchers.Main) {
                items.clear()
                items.addAll(list)
                gridAdapter.notifyDataSetChanged()
            }
        }
    }

    private fun loadStickers(): List<Sticker> {
        val json = try {
            P2PLib.listStickers()
        } catch (e: Exception) {
            return emptyList()
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            return emptyList()
        }
        val out = mutableListOf<Sticker>()
        for (i in 0 until array.length()) {
            val o = array.optJSONObject(i) ?: continue
            val id = o.optString("id")
            if (id.isEmpty()) continue
            out.add(Sticker(id))
        }
        return out
    }

    private fun send(sticker: Sticker) {
        dialog?.dismiss()
        onSend(sticker.id)
    }

    private fun confirmDelete(sticker: Sticker) {
        AlertDialog.Builder(activity)
            .setMessage(R.string.msg_confirm_delete_sticker)
            .setPositiveButton(R.string.action_delete_sticker) { _, _ -> deleteSticker(sticker) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun deleteSticker(sticker: Sticker) {
        scope.launch(Dispatchers.IO) {
            val result = try {
                P2PLib.deleteSticker(sticker.id)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(
                        activity, coreErrorText(activity, result), Toast.LENGTH_SHORT
                    ).show()
                } else {
                    refresh()
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // İçe aktarma
    // ---------------------------------------------------------------

    private fun importUris(uris: List<Uri>) {
        scope.launch(Dispatchers.IO) {
            var ok = 0
            for (uri in uris) if (importUri(uri)) ok++
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    activity,
                    if (ok > 0) activity.getString(R.string.msg_sticker_imported, ok)
                    else activity.getString(R.string.msg_sticker_import_failed),
                    Toast.LENGTH_SHORT
                ).show()
                refresh()
            }
        }
    }

    /** Every `.webp` in the chosen tree (recursively) is imported. */
    private fun importTree(treeUri: Uri) {
        scope.launch(Dispatchers.IO) {
            val files = mutableListOf<Uri>()
            try {
                collectWebp(treeUri, DocumentsContract.getTreeDocumentId(treeUri), files)
            } catch (e: Exception) {
                // A tree that cannot be listed: nothing to import.
            }
            var ok = 0
            for (uri in files) if (importUri(uri)) ok++
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    activity,
                    if (ok > 0) activity.getString(R.string.msg_sticker_imported, ok)
                    else activity.getString(R.string.msg_sticker_import_failed),
                    Toast.LENGTH_SHORT
                ).show()
                refresh()
            }
        }
    }

    /** One picture as a sticker. The bytes are copied to a cache file first:
     *  the core reads a sticker from a real file. */
    private fun importUri(uri: Uri): Boolean {
        val tmp = File(File(activity.cacheDir, "sticker_import").apply { mkdirs() }, UUID.randomUUID().toString())
        return try {
            activity.contentResolver.openInputStream(uri)?.use { input ->
                tmp.outputStream().use { output -> input.copyTo(output) }
            } ?: return false
            !StickerImport.importFile(tmp).startsWith("Error:")
        } catch (e: Exception) {
            false
        } finally {
            tmp.delete()
        }
    }

    /** The `.webp` files under [parentId] (and its subfolders). */
    private fun collectWebp(treeUri: Uri, parentId: String, out: MutableList<Uri>) {
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId)
        activity.contentResolver.query(
            children,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE
            ),
            null, null, null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getString(0) ?: continue
                val name = cursor.getString(1) ?: ""
                val mime = cursor.getString(2) ?: ""
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                    collectWebp(treeUri, id, out)
                } else if (name.endsWith(".webp", true)) {
                    out.add(DocumentsContract.buildDocumentUriUsingTree(treeUri, id))
                }
            }
        }
    }

    /** WhatsApp's sticker folder, as the tree picker wants it. */
    private fun whatsAppStickersUri(): Uri = DocumentsContract.buildDocumentUri(
        "com.android.externalstorage.documents",
        "primary:Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Stickers"
    )

    // ---------------------------------------------------------------
    // Izgara
    // ---------------------------------------------------------------

    /** One sticker in the grid. */
    private data class Sticker(val id: String)

    private inner class StickerGridAdapter : RecyclerView.Adapter<StickerGridAdapter.Holder>() {
        /** Çözülmüş çıkartma çizimleri (çıkartma id -> çizim). */
        private val cache = android.util.LruCache<String, Drawable>(16)
        /** Çözülmekte olanlar — aynı çıkartma için ikinci istek atılmasın. */
        private val pending = mutableSetOf<String>()

        inner class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val image: ImageView = view.findViewById(R.id.imgStickerCell)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_sticker, parent, false))

        override fun getItemCount(): Int = items.size

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val sticker = items[position]
            val cached = cache.get(sticker.id)
            holder.image.setImageDrawable(cached)
            holder.itemView.setOnClickListener { send(sticker) }
            holder.itemView.setOnLongClickListener {
                confirmDelete(sticker)
                true
            }
            if (cached != null || sticker.id in pending) return
            pending.add(sticker.id)
            // The core's viewable copy (`.png`/`.gif`) + the decode: both off
            // the main thread — the cell fills in when it is ready.
            scope.launch(Dispatchers.IO) {
                val drawable = stickerDrawable(sticker.id)
                withContext(Dispatchers.Main) {
                    pending.remove(sticker.id)
                    if (drawable == null) return@withContext
                    cache.put(sticker.id, drawable)
                    val idx = items.indexOfFirst { it.id == sticker.id }
                    if (idx >= 0) notifyItemChanged(idx)
                }
            }
        }
    }

    /** The sticker's picture: the core's viewable copy of it. */
    private fun stickerDrawable(id: String): Drawable? {
        val path = try {
            P2PLib.stickerPlainPath(id)
        } catch (e: Exception) {
            return null
        }
        if (path.startsWith("Error:")) return null
        return loadStickerDrawable(activity, File(path))
    }

    private companion object {
        const val GRID_COLUMNS = 3
    }
}

/**
 * A sticker's picture: a `.gif` plays (like the app's GIF viewer, bkz.
 * MediaViewerActivity), a `.png` is a still.
 */
fun loadStickerDrawable(context: Context, file: File): Drawable? {
    if (!file.exists()) return null
    return try {
        if (file.extension.equals("gif", true) && Build.VERSION.SDK_INT >= 28) {
            val drawable = ImageDecoder.decodeDrawable(ImageDecoder.createSource(file))
            (drawable as? AnimatedImageDrawable)?.apply {
                repeatCount = AnimatedImageDrawable.REPEAT_INFINITE
                start()
            }
            drawable
        } else {
            val bitmap = BitmapFactory.decodeFile(file.absolutePath) ?: return null
            BitmapDrawable(context.resources, bitmap)
        }
    } catch (e: Throwable) {
        null
    }
}
