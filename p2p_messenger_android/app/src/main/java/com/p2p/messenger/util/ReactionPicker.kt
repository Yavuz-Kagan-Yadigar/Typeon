package com.p2p.messenger.util

import android.content.Context
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.PopupWindow
import android.widget.TextView
import androidx.emoji2.emojipicker.EmojiPickerView
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.findViewTreeLifecycleOwner
import androidx.lifecycle.lifecycleScope
import com.google.android.material.color.MaterialColors
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Long-pressing a message opens the full SYSTEM emoji picker, as in WhatsApp.
 *
 * The first version had a fixed row of six emojis. That was removed. In its place is `androidx.emoji2.emojipicker.EmojiPickerView`, a full grid with categories,
 * a search bar, "recently used", and skin-tone variants.
 *
 * SCOPE LIMIT: Android has no public API that lets an app open the keyboard's OWN emoji panel directly. No such intent or `InputMethodManager` call exists.
 * `EmojiPickerView` is the official picker that uses the platform's own emoji data (emoji2), and it is the closest equivalent.
 *
 * PRESENTATION: a centred `AlertDialog`. A `BottomSheetDialog` was tried first. The user reported that it opened strangely and far too low, and that was right:
 * on wide screens Material's bottom sheet is capped at a maximum width. On tablets it appeared as a narrow, floating panel at the bottom centre, with its
 * bottom cut off. A centred dialog is predictable on both form factors: a fixed box in the middle of the screen, scaled to the screen.
 */
object ReactionPicker {

    /**
     * Double tap on a message: a bar with my 5 most used emojis (see Rust `top_reactions`) and a "+" that opens the full picker ([show]).
     * Shown above [anchor] (the bubble), or below it when there is no room above.
     */
    fun showQuick(anchor: View, showRemove: Boolean, onPick: (String) -> Unit) {
        val owner = anchor.findViewTreeLifecycleOwner() ?: return
        owner.lifecycleScope.launch {
            // The core read lock can wait on network work: never on the main thread.
            val emojis = withContext(Dispatchers.IO) {
                try {
                    val array = org.json.JSONArray(P2PLib.topReactions())
                    List(array.length()) { array.getString(it) }
                } catch (e: Exception) {
                    emptyList()
                }
            }
            if (anchor.isAttachedToWindow) showQuickBar(anchor, emojis, showRemove, onPick)
        }
    }

    private fun showQuickBar(anchor: View, emojis: List<String>, showRemove: Boolean, onPick: (String) -> Unit) {
        val context = anchor.context
        val density = context.resources.displayMetrics.density
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            val pad = (6 * density).toInt()
            setPadding(pad, pad / 2, pad, pad / 2)
        }
        val popup = PopupWindow(row, ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, true).apply {
            setBackgroundDrawable(GradientDrawable().apply {
                cornerRadius = 28 * density
                setColor(MaterialColors.getColor(anchor, com.google.android.material.R.attr.colorSurfaceContainerHigh))
            })
            elevation = 8 * density
        }
        val ripple = TypedValue().also {
            context.theme.resolveAttribute(android.R.attr.selectableItemBackgroundBorderless, it, true)
        }.resourceId
        fun cell(label: String, action: () -> Unit) = TextView(context).apply {
            text = label
            textSize = 26f
            gravity = Gravity.CENTER
            val pad = (8 * density).toInt()
            setPadding(pad, pad, pad, pad)
            if (ripple != 0) setBackgroundResource(ripple)
            setOnClickListener {
                popup.dismiss()
                action()
            }
            row.addView(this)
        }
        emojis.forEach { emoji -> cell(emoji) { onPick(emoji) } }
        cell("+") { show(context, showRemove, onPick) }.apply {
            contentDescription = context.getString(R.string.title_pick_reaction)
            setTextColor(MaterialColors.getColor(anchor, com.google.android.material.R.attr.colorOnSurfaceVariant))
        }

        row.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED)
        val (w, h) = row.measuredWidth to row.measuredHeight
        val root = anchor.rootView
        val at = IntArray(2).also { anchor.getLocationInWindow(it) }
        val gap = (8 * density).toInt()
        // ponytail: fixed allowance for status bar + toolbar; read the real toolbar bottom if the bar ever hides behind it.
        val minTop = (96 * density).toInt()
        val x = (at[0] + anchor.width / 2 - w / 2).coerceIn(gap, maxOf(gap, root.width - w - gap))
        val above = at[1] - h - gap
        val y = (if (above >= minTop) above else at[1] + anchor.height + gap).coerceIn(minTop, maxOf(minTop, root.height - h - gap))
        popup.showAtLocation(anchor, Gravity.NO_GRAVITY, x, y)
    }

    /**
     * [onPick] receives an empty string when the reaction is to be removed.
     *
     * [showRemove]: when the message ALREADY has a reaction from me, a "remove" button is added above the grid. Why not "tap the same emoji again to remove it":
     * the summary string (see Rust `reactions_summary`) does not say which emoji is MINE. It carries only totals. To know that, the protocol would need a
     * per-person list. An explicit "remove" button does the same job without growing the protocol.
     */
    fun show(context: Context, showRemove: Boolean, onPick: (String) -> Unit) {
        val density = context.resources.displayMetrics.density
        val metrics = context.resources.displayMetrics

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        container.addView(TextView(context).apply {
            setText(R.string.title_pick_reaction)
            textSize = 16f
            val pad = (16 * density).toInt()
            setPadding(pad, pad, pad, pad / 2)
        })

        // `dialog` is built below. The listeners need access to it from here.
        var dialogRef: AlertDialog? = null

        if (showRemove) {
            container.addView(Button(context).apply {
                setText(R.string.action_remove_reaction)
                val margin = (16 * density).toInt()
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    marginStart = margin
                    gravity = Gravity.START
                }
                setOnClickListener {
                    onPick("")
                    dialogRef?.dismiss()
                }
            })
        }

        container.addView(EmojiPickerView(context).apply {
            // Fixed height: WRAP_CONTENT is meaningless for a grid. It either shrinks to nothing or fills the whole screen.
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (340 * density).toInt()
            )
            setOnEmojiPickedListener { picked ->
                onPick(picked.emoji)
                dialogRef?.dismiss()
            }
        })

        val dialog = AlertDialog.Builder(context)
            .setView(container)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialogRef = dialog
        dialog.show()
        // With WRAP_CONTENT, the grid either shrinks too far or fills the screen. So the width is given explicitly from the screen size. On a tablet it does
        // not stretch edge to edge, and on a phone it is not too narrow.
        dialog.window?.setLayout(
            minOf((metrics.widthPixels * 0.92f).toInt(), (420 * density).toInt()),
            ViewGroup.LayoutParams.WRAP_CONTENT
        )
    }
}
