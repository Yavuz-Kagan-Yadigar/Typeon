package com.p2p.messenger.util

import android.content.res.ColorStateList
import android.graphics.Color
import com.google.android.material.color.MaterialColors
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.shape.MaterialShapeDrawable

/**
 * The "scroll to bottom" button of both chat screens. Nothing new below:
 * surface fill with an accent ring. A new message below: the theme's accent
 * fill, steady (it used to blink, and the blink redrew the whole screen).
 */
object ScrollDownFab {
    private class Accent(val fill: ColorStateList?, val icon: ColorStateList?)

    fun style(fab: FloatingActionButton, newMessage: Boolean) {
        // The theme's own colours, read once before the first restyle.
        val accent = fab.getTag(com.p2p.messenger.R.id.fabScrollToBottom) as? Accent
            ?: Accent(fab.backgroundTintList, fab.imageTintList).also { fab.setTag(com.p2p.messenger.R.id.fabScrollToBottom, it) }
        if (newMessage) {
            fab.backgroundTintList = accent.fill
            fab.imageTintList = accent.icon
            fab.foreground = null
            return
        }
        val ring = MaterialColors.getColor(fab, com.google.android.material.R.attr.colorPrimary)
        fab.backgroundTintList = ColorStateList.valueOf(MaterialColors.getColor(fab, com.google.android.material.R.attr.colorSurface))
        fab.imageTintList = ColorStateList.valueOf(ring)
        // Same outline as the button itself (a rounded square in Material 3).
        fab.foreground = MaterialShapeDrawable(fab.shapeAppearanceModel).apply {
            fillColor = ColorStateList.valueOf(Color.TRANSPARENT)
            setStroke(2 * fab.resources.displayMetrics.density, ring)
        }
    }
}
