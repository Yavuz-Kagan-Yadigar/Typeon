package com.p2p.messenger.util

import android.content.Context
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.emoji2.emojipicker.EmojiPickerView
import androidx.appcompat.app.AlertDialog
import com.p2p.messenger.R

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
