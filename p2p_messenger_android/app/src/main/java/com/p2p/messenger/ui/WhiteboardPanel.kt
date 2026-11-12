package com.p2p.messenger.ui

import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorFilter
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PixelFormat
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.graphics.ColorUtils
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.google.android.material.color.MaterialColors
import com.google.android.material.slider.Slider
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.hexToBytesOrNull
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.Executors

/**
 * The shared whiteboard of one chat, pulled down above the message list by the
 * tab that hangs under the top bar (the
 * chat stays usable below it). Used by both chat screens; [bind] names the
 * chat: `peer` for a 1:1 chat, `groupId` for a group — one of them is empty.
 *
 * All board state lives in the core (`whiteboard.rs`); this panel draws what
 * the core has and hands it strokes and erases. Nothing here polls: other
 * people's changes arrive as `"whiteboard"` events.
 */
class WhiteboardPanel(private val activity: AppCompatActivity, private val host: FrameLayout, private val handle: View) {
    companion object {
        private const val MAX_PAGES = 20
        private const val MAX_UNDO = 50
        /** Just past the core's 800 ms burst debounce and its 5 s digest delay. */
        private const val TICK_OPS_MS = 900L
        /** Static: the screen (and this panel) is created again when the
         *  phone is turned while the file picker is open. */
        private var pdfPage = 0
        private const val TICK_DIGEST_MS = 6_000L
    }

    private val ui = Handler(Looper.getMainLooper())
    /** Discards after shutdown: a board event still in flight when the screen
     *  is destroyed must not throw RejectedExecutionException on the UI thread. */
    private val io = java.util.concurrent.ThreadPoolExecutor(
        1, 1, 0L, java.util.concurrent.TimeUnit.MILLISECONDS,
        java.util.concurrent.LinkedBlockingQueue(), java.util.concurrent.ThreadPoolExecutor.DiscardPolicy()
    )
    private val dp = activity.resources.displayMetrics.density
    private val board = WhiteboardView(activity)
    private val legend = LinearLayout(activity)
    private val pageLabel = TextView(activity)
    private val toolButtons = ArrayList<View>()
    private var peer = ""
    private var groupId = ""
    private var page = 0
    private var pageCount = 1
    private var unread = 0
    private var built = false
    private val undoStack = ArrayDeque<Step>()
    private val redoStack = ArrayDeque<Step>()
    private lateinit var undoButton: View
    private lateinit var redoButton: View

    /** Theme colours. Only the drawing surface itself stays black (see
     *  WhiteboardView); the bars and the tab look like the top bar they
     *  hang from: Material3's action bar is `colorSurfaceContainer`. */
    private val chromeColor = MaterialColors.getColor(activity, com.google.android.material.R.attr.colorSurfaceContainer, Color.DKGRAY)
    private val onChromeColor = MaterialColors.getColor(activity, com.google.android.material.R.attr.colorOnSurface, Color.BLACK)
    private val accentColor = MaterialColors.getColor(activity, com.google.android.material.R.attr.colorPrimary, onChromeColor)
    private val alertColor = MaterialColors.getColor(activity, com.google.android.material.R.attr.colorError, Color.RED)

    private val tab = TabDrawable(chromeColor, onChromeColor, alertColor)
    private val isOpen: Boolean get() = host.visibility == View.VISIBLE

    private val savePdf = activity.registerForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        if (uri != null) exportPdf(uri)
    }

    private val listener: (String) -> Unit = { json ->
        try {
            val obj = JSONObject(json)
            // An unbound panel ("" / "") matched every group event: those carry no "peer".
            if (obj.optString("type") == "whiteboard" && (peer.isNotEmpty() || groupId.isNotEmpty()) &&
                (if (groupId.isNotEmpty()) obj.optString("group_id") == groupId else obj.optString("peer") == peer)
            ) ui.post { onBoardChanged(obj) }
        } catch (e: Exception) { }
    }

    private val tick = Runnable { io.execute { P2PLib.whiteboardTick() } }
    private val lateTick = Runnable { io.execute { P2PLib.whiteboardTick() } }

    init {
        handle.background = tab
        handle.setOnClickListener { toggle() }
        // Listen only while the chat is on screen. Held until onDestroy, a chat
        // left in the back stack kept the service in "a screen is open" mode
        // with the phone locked: no power save, no deep idle (9S 2026-10-02).
        activity.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                P2PService.addMessageListener(listener)
                // Catch up on what changed while the chat was not visible.
                if (peer.isNotEmpty() || groupId.isNotEmpty()) {
                    refreshInfo()
                    if (isOpen) loadPage()
                }
            }
            override fun onStop(owner: LifecycleOwner) {
                P2PService.removeMessageListener(listener)
            }
            override fun onDestroy(owner: LifecycleOwner) {
                ui.removeCallbacksAndMessages(null)
                // Whatever is still queued goes out before the screen is gone.
                io.execute { P2PLib.whiteboardTick() }
                io.shutdown()
            }
        })
    }

    /** Points the panel at a chat. The screen is reused when the user switches
     *  chats, so this also closes the board of the previous one. */
    fun bind(peer: String, groupId: String) {
        this.peer = peer
        this.groupId = groupId
        host.visibility = View.GONE
        tab.open = false
        undoStack.clear()
        redoStack.clear()
        page = 0
        pageCount = 1
        board.pending.clear()
        board.strokes = ArrayList()
        setUnread(0)
        refreshInfo()
    }

    private fun toggle() {
        tab.open = !isOpen
        if (isOpen) {
            host.visibility = View.GONE
            return
        }
        if (!built) build()
        host.visibility = View.VISIBLE
        io.execute { P2PLib.whiteboardOpen(peer, groupId) }
        refreshInfo()
        loadPage()
    }

    // ------------------------------------------------------------------ data

    private fun refreshInfo() {
        val (peer, groupId) = Pair(peer, groupId)
        io.execute {
            val info = try { JSONObject(P2PLib.whiteboardInfo(peer, groupId)) } catch (e: Exception) { return@execute }
            ui.post {
                if (peer != this.peer || groupId != this.groupId) return@post
                pageCount = maxOf(pageCount, info.optInt("pages", 1), page + 1)
                val people = info.optJSONArray("participants")
                board.participants = people?.length() ?: 2
                board.me = info.optInt("me", 0)
                setUnread(info.optInt("unread"))
                if (built && people != null) {
                    showLegend(List(people.length()) { people.getJSONObject(it).optString("name") })
                    styleTools()
                }
            }
        }
    }

    private fun loadPage() {
        val shown = page
        val (peer, groupId) = Pair(peer, groupId)
        io.execute {
            val strokes = WhiteboardView.parsePage(P2PLib.whiteboardPage(peer, groupId, shown))
            P2PLib.whiteboardMarkRead(peer, groupId, shown)
            ui.post {
                if (shown != page || peer != this.peer || groupId != this.groupId) return@post
                board.strokes = strokes
                setUnread(unread and (1 shl shown).inv())
            }
        }
    }

    /** A burst of incoming `whiteboard` events (each triggers one in the core)
     *  used to run one full page fetch + main-thread rebuild per event; queued
     *  events collapse to one fetch per main-loop turn. */
    private fun loadPageCoalesced() {
        if (reloadQueued) return
        reloadQueued = true
        ui.post {
            reloadQueued = false
            loadPage()
        }
    }

    private var reloadQueued = false

    private fun onBoardChanged(event: JSONObject) {
        val pages = event.optJSONArray("pages")
        var changedHere = false
        for (i in 0 until (pages?.length() ?: 0)) {
            val p = pages!!.optInt(i)
            pageCount = maxOf(pageCount, p + 1)
            if (p == page) changedHere = true
        }
        setUnread(event.optInt("unread"))
        if (isOpen && changedHere) loadPageCoalesced() else updatePageLabel()
    }

    private fun setUnread(mask: Int) {
        unread = mask
        tab.unread = mask != 0
        if (built) updatePageLabel()
    }

    private fun scheduleTicks() {
        ui.removeCallbacks(tick)
        ui.removeCallbacks(lateTick)
        ui.postDelayed(tick, TICK_OPS_MS)
        ui.postDelayed(lateTick, TICK_DIGEST_MS)
    }

    /** One undoable step: strokes that are either on the board ([live], with
     *  their current [ids]) or erased. Undo and redo both just flip it. */
    private class Step(val page: Int, val strokes: List<WhiteboardView.Stroke>, var ids: ByteArray, var live: Boolean)

    private fun pointBytes(stroke: WhiteboardView.Stroke): ByteArray {
        val bytes = ByteBuffer.allocate(stroke.points.size * 2).order(ByteOrder.LITTLE_ENDIAN)
        for (v in stroke.points) bytes.putShort(v.toInt().toShort())
        return bytes.array()
    }

    private fun hexToBytes(hex: String): ByteArray? = hexToBytesOrNull(hex)

    private fun remember(step: Step) {
        undoStack.addLast(step)
        if (undoStack.size > MAX_UNDO) undoStack.removeFirst()
        redoStack.clear()
        styleTools()
    }

    private fun addStroke(stroke: WhiteboardView.Stroke) {
        val shown = page
        val (peer, groupId) = Pair(peer, groupId)
        val step = Step(shown, listOf(stroke), ByteArray(0), true)
        remember(step)
        io.execute {
            val result = P2PLib.whiteboardAddStroke(peer, groupId, shown, stroke.shade, stroke.width, pointBytes(stroke))
            // Invalid input from the core takes the error path as well, not a
            // NumberFormatException (bkz. hexToBytesOrNull above).
            val ids = if (result.startsWith("Error")) null else hexToBytes(result)
            val failed = ids == null
            // The stroke disappears from the board without a word otherwise.
            if (failed || result.length != 16) android.util.Log.w("Whiteboard", "addStroke: '$result' page=$shown points=${stroke.points.size}")
            if (ids != null) step.ids = ids
            ui.post {
                board.pending.remove(stroke)
                if (shown == page && peer == this.peer && groupId == this.groupId) {
                    if (!failed && step.ids.size == 8) {
                        // The call returned the new id: keep the stroke. The
                        // whole page was fetched and rebuilt after every
                        // stroke, and that older snapshot also brought back
                        // a stroke erased in the meantime.
                        board.strokes.add(WhiteboardView.Stroke(step.ids, stroke.shade, stroke.author, stroke.width, stroke.points))
                        board.strokesChanged()
                    } else {
                        loadPage()
                    }
                }
                if (failed) {
                    undoStack.remove(step)
                    styleTools()
                    Toast.makeText(activity, R.string.whiteboard_page_full, Toast.LENGTH_SHORT).show()
                }
            }
        }
        scheduleTicks()
    }

    private fun erase(strokes: List<WhiteboardView.Stroke>) {
        val ids = ByteArray(strokes.size * 8)
        strokes.forEachIndexed { i, s -> s.id.copyInto(ids, i * 8) }
        val (peer, groupId) = Pair(peer, groupId)
        remember(Step(page, strokes, ids, false))
        io.execute { P2PLib.whiteboardErase(peer, groupId, ids) }
        scheduleTicks()
    }

    /** Undo ([from] = undo stack) or redo: flips the newest step. An erased
     *  stroke cannot come back under its old id (the erase is remembered by
     *  every device), so it is drawn again as a new stroke — in my colour,
     *  also when the erased one was somebody else's. */
    private fun flip(from: ArrayDeque<Step>, to: ArrayDeque<Step>) {
        val step = from.removeLastOrNull() ?: return
        to.addLast(step)
        styleTools()
        val (peer, groupId) = Pair(peer, groupId)
        io.execute {
            if (step.live) {
                P2PLib.whiteboardErase(peer, groupId, step.ids)
                step.live = !step.live
            } else {
                // Redo draws every erased stroke again under a new id. Each
                // reply is validated and the step stays erased on any failure:
                // it used to join the replies verbatim, so one page-full error
                // collapsed to "" — an id array shorter than the stroke list,
                // and the next undo removed only the successful prefix.
                // A stroke over 512 points comes back as several segment ids
                // (8 bytes each): collect what the core returned, so the
                // rollback and the next undo use the real ids.
                val collected = java.io.ByteArrayOutputStream()
                var ok = true
                step.strokes.forEach { s ->
                    val r = P2PLib.whiteboardAddStroke(peer, groupId, step.page, s.shade, s.width, pointBytes(s))
                    val b = if (r.startsWith("Error")) null else hexToBytes(r)
                    if (b == null || b.isEmpty() || b.size % 8 != 0) ok = false else collected.write(b)
                }
                val ids = collected.toByteArray()
                if (ok) {
                    step.ids = ids
                    step.live = !step.live
                } else {
                    // Roll the partially re-added strokes back so the core is
                    // not left half-redone, and the redo can be tried again.
                    android.util.Log.w("Whiteboard", "redo: page ${step.page} full or malformed id")
                    P2PLib.whiteboardErase(peer, groupId, ids)
                    ui.post { Toast.makeText(activity, R.string.whiteboard_page_full, Toast.LENGTH_SHORT).show() }
                }
            }
            ui.post { if (step.page == page) loadPage() else goToPage(step.page) }
        }
        scheduleTicks()
    }

    private fun goToPage(target: Int) {
        if (target < 0 || target >= MAX_PAGES) return
        page = target
        pageCount = maxOf(pageCount, page + 1)
        board.pending.clear()
        board.strokes = ArrayList()
        updatePageLabel()
        loadPage()
    }

    /** Saves the page that was on screen when PDF was tapped. */
    private fun exportPdf(uri: Uri) {
        val shown = pdfPage
        val participants = board.participants
        val (peer, groupId) = Pair(peer, groupId)
        io.execute {
            val pdf = PdfDocument()
            val ok = try {
                val strokes = WhiteboardView.parsePage(P2PLib.whiteboardPage(peer, groupId, shown))
                val sheet = pdf.startPage(
                    PdfDocument.PageInfo.Builder(WhiteboardView.WIDTH.toInt(), WhiteboardView.HEIGHT.toInt(), 1).create()
                )
                WhiteboardView.drawPage(sheet.canvas, strokes, participants, WhiteboardView.strokePaint())
                pdf.finishPage(sheet)
                activity.contentResolver.openOutputStream(uri)?.use { pdf.writeTo(it); true } ?: false
            } catch (e: Exception) {
                false
            } finally {
                pdf.close()
            }
            // The picker already created the file: do not leave it empty.
            if (!ok) try { android.provider.DocumentsContract.deleteDocument(activity.contentResolver, uri) } catch (e: Exception) { }
            ui.post {
                Toast.makeText(activity, if (ok) R.string.whiteboard_pdf_saved else R.string.whiteboard_pdf_failed, Toast.LENGTH_SHORT).show()
            }
        }
    }

    // ---------------------------------------------------------------- layout

    private fun build() {
        built = true
        val root = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setBackgroundColor(chromeColor)
        }
        legend.orientation = LinearLayout.HORIZONTAL
        legend.setPadding((8 * dp).toInt(), (4 * dp).toInt(), (8 * dp).toInt(), (4 * dp).toInt())
        root.addView(
            HorizontalScrollView(activity).apply { isHorizontalScrollBarEnabled = false; addView(legend) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        )
        board.onStroke = ::addStroke
        board.onErase = ::erase
        root.addView(board, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

        // Two rows: pages and history above, drawing tools below.
        fun row() = LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding((6 * dp).toInt(), (3 * dp).toInt(), (6 * dp).toInt(), (3 * dp).toInt())
            root.addView(this, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        val height = (34 * dp).toInt()
        fun place(bar: LinearLayout, view: View, widthDp: Int) = bar.addView(view, LinearLayout.LayoutParams((widthDp * dp).toInt(), height).apply {
            marginStart = (3 * dp).toInt(); marginEnd = (3 * dp).toInt()
        })
        fun icon(bar: LinearLayout, drawable: Int, description: Int, onClick: () -> Unit) = ImageButton(activity).apply {
            setImageResource(drawable)
            setColorFilter(onChromeColor)
            background = pill(false)
            contentDescription = activity.getString(description)
            setOnClickListener { onClick() }
            place(bar, this, 52)
        }
        fun text(bar: LinearLayout, label: String, description: Int, onClick: () -> Unit) = TextView(activity).apply {
            text = label
            setTextColor(onChromeColor)
            textSize = 18f
            gravity = Gravity.CENTER
            background = pill(false)
            contentDescription = activity.getString(description)
            setOnClickListener { onClick() }
            place(bar, this, 52)
        }
        val pages = row()
        text(pages, "‹", R.string.whiteboard_prev_page) { goToPage(page - 1) }
        pageLabel.setTextColor(onChromeColor)
        pageLabel.textSize = 14f
        pageLabel.gravity = Gravity.CENTER
        pages.addView(pageLabel, LinearLayout.LayoutParams((48 * dp).toInt(), height))
        text(pages, "›", R.string.whiteboard_next_page) { goToPage(page + 1) }
        pages.addView(View(activity), LinearLayout.LayoutParams(0, 1, 1f))
        // Pen size: 1..MAX_PEN_WIDTH board units. Only finished strokes carry it.
        val accent = ColorStateList.valueOf(accentColor)
        val sizeBar = Slider(activity).apply {
            valueFrom = 1f
            valueTo = WhiteboardView.MAX_PEN_WIDTH.toFloat()
            stepSize = 1f
            value = board.penWidth.toFloat()
            isTickVisible = false
            trackActiveTintList = accent
            thumbTintList = accent
            trackInactiveTintList = ColorStateList.valueOf(ColorUtils.setAlphaComponent(onChromeColor, 70))
            contentDescription = activity.getString(R.string.whiteboard_pen_size)
            addOnChangeListener { _, value, _ -> board.penWidth = value.toInt() }
        }
        pages.addView(sizeBar, LinearLayout.LayoutParams((150 * dp).toInt(), ViewGroup.LayoutParams.WRAP_CONTENT))
        text(pages, "PDF", R.string.whiteboard_export_pdf) { pdfPage = page; savePdf.launch("whiteboard-${page + 1}.pdf") }.apply { textSize = 13f }

        val tools = row()
        toolButtons.add(icon(tools, R.drawable.ic_pen, R.string.whiteboard_pen) { board.erasing = false; styleTools() })
        toolButtons.add(icon(tools, R.drawable.ic_eraser, R.string.whiteboard_eraser) { board.erasing = true; styleTools() })
        for (shade in 0..2) {
            val swatch = View(activity).apply {
                contentDescription = activity.getString(R.string.whiteboard_color)
                setOnClickListener { board.shade = shade; board.erasing = false; styleTools() }
            }
            toolButtons.add(swatch)
            tools.addView(swatch, LinearLayout.LayoutParams((26 * dp).toInt(), (26 * dp).toInt()).apply {
                marginStart = (5 * dp).toInt(); marginEnd = (5 * dp).toInt()
            })
        }
        undoButton = text(tools, "↶", R.string.whiteboard_undo) { flip(undoStack, redoStack) }
        redoButton = text(tools, "↷", R.string.whiteboard_redo) { flip(redoStack, undoStack) }

        host.addView(root, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        updatePageLabel()
        styleTools()
    }

    /** Who draws in which colour: each name with its three shades. */
    private fun showLegend(names: List<String>) {
        legend.removeAllViews()
        names.forEachIndexed { index, name ->
            for (shade in 0..2) {
                legend.addView(View(activity).apply { background = dot(WhiteboardView.colorOf(index, names.size, shade), false) },
                    LinearLayout.LayoutParams((10 * dp).toInt(), (10 * dp).toInt()).apply {
                        gravity = Gravity.CENTER_VERTICAL; marginEnd = (2 * dp).toInt()
                    })
            }
            legend.addView(TextView(activity).apply {
                text = name
                setTextColor(onChromeColor)
                textSize = 12f
                setPadding((3 * dp).toInt(), 0, (14 * dp).toInt(), 0)
            })
        }
    }

    private fun updatePageLabel() {
        val elsewhere = unread and (1 shl page).inv() != 0
        pageLabel.text = "${page + 1}/$pageCount" + if (elsewhere) " •" else ""
    }

    /** Marks the active tool: pen, eraser, and the three colour swatches. */
    private fun styleTools() {
        if (!built) return
        undoButton.alpha = if (undoStack.isEmpty()) 0.3f else 1f
        redoButton.alpha = if (redoStack.isEmpty()) 0.3f else 1f
        toolButtons[0].background = pill(!board.erasing)
        toolButtons[1].background = pill(board.erasing)
        for (shade in 0..2) {
            toolButtons[2 + shade].background =
                dot(WhiteboardView.colorOf(board.me, board.participants, shade), !board.erasing && board.shade == shade)
        }
    }

    /** The rounded background every button of the bars sits on: a tint of
     *  the bar's text colour, so it reads on light and dark bars alike. */
    private fun pill(selected: Boolean) = GradientDrawable().apply {
        cornerRadius = 100 * dp
        setColor(ColorUtils.setAlphaComponent(onChromeColor, if (selected) 70 else 22))
    }

    private fun dot(color: Int, ring: Boolean) = GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(color)
        if (ring) setStroke((3 * dp).toInt(), onChromeColor)
    }

    /** The pull tab under the top bar: a chevron (down = open the board, up =
     *  close it) and a dot while someone else's drawing is unseen. */
    private class TabDrawable(
        private val fillColor: Int,
        private val chevronColor: Int,
        private val unreadColor: Int,
    ) : Drawable() {
        var open = false
            set(value) { field = value; invalidateSelf() }
        var unread = false
            set(value) { field = value; invalidateSelf() }
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val path = Path()

        override fun draw(canvas: Canvas) {
            val w = bounds.width().toFloat()
            val h = bounds.height().toFloat()
            val shoulder = h * 0.7f
            val corner = h * 0.35f
            path.rewind()
            path.moveTo(0f, 0f)
            path.quadTo(shoulder, 0f, shoulder, h * 0.5f)
            path.lineTo(shoulder, h - corner)
            path.quadTo(shoulder, h, shoulder + corner, h)
            path.lineTo(w - shoulder - corner, h)
            path.quadTo(w - shoulder, h, w - shoulder, h - corner)
            path.lineTo(w - shoulder, h * 0.5f)
            path.quadTo(w - shoulder, 0f, w, 0f)
            path.close()
            paint.style = Paint.Style.FILL
            paint.color = fillColor
            canvas.drawPath(path, paint)

            val cx = w / 2
            val cy = h * 0.48f
            val half = h * 0.26f
            val tip = if (open) -h * 0.13f else h * 0.13f
            path.rewind()
            path.moveTo(cx - half, cy - tip)
            path.lineTo(cx, cy + tip)
            path.lineTo(cx + half, cy - tip)
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = h * 0.14f
            paint.strokeCap = Paint.Cap.ROUND
            paint.strokeJoin = Paint.Join.ROUND
            paint.color = chevronColor
            canvas.drawPath(path, paint)

            if (unread) {
                paint.style = Paint.Style.FILL
                paint.color = unreadColor
                canvas.drawCircle(cx + half + h * 0.5f, cy, h * 0.14f, paint)
            }
        }

        override fun setAlpha(alpha: Int) {}
        override fun setColorFilter(colorFilter: ColorFilter?) {}
        @Deprecated("Deprecated in Java")
        override fun getOpacity() = PixelFormat.TRANSLUCENT
    }
}
