package com.p2p.messenger.ui

import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.view.View
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.p2p.messenger.R

/**
 * Draws consecutive grouped messages as ONE outline.
 *
 * WHY A BUBBLE'S OWN BACKGROUND IS NOT ENOUGH: shrinking the corner radius on the joined edge and zeroing the gap between
 * bubbles still leaves each bubble visibly separate. The merged shape has two features that single rounded rectangles
 * cannot produce:
 *
 *  1. Rounded outer corners, only where the outline is actually exposed. Where two bubbles touch there is no corner.
 *  2. At a width change (a step), a CONCAVE fillet. Going from a narrow bubble to a wider one, the outline does not make a
 *     sharp 270-degree corner. It curves inward. A rectangle's corner radius only describes convex corners. A concave fillet
 *     exists only when the whole group is drawn as ONE Path.
 *
 * So the grouped bubbles have no background of their own (see SimpleChatAdapter: group members get no background), and the
 * merged shape is drawn once, below the list. `ItemDecoration.onDraw` is the right place: layout is finished, the real bounds
 * of all visible children are known, and the drawing lands BEHIND the children.
 *
 * During swipe-to-reply the row moves with `translationX`. Those translations are included in the bounds, so the background
 * moves with the bubble.
 */
class MergedBubbleDecoration(
    private val adapter: SimpleChatAdapter
) : RecyclerView.ItemDecoration() {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val path = Path()
    private val scratch = RectF()
    private val matrix = android.graphics.Matrix()

    // The colour gradient runs from the top of the list to the bottom. Upper bubbles are lighter, lower bubbles keep the current
    // colour. The colour comes from one vertical `LinearGradient` stretched over the whole list, not from each bubble's own
    // background. So a bubble's tone changes with its position on screen as it scrolls. The shaders are rebuilt only when
    // the list height or the colours change.
    private var mineShader: android.graphics.LinearGradient? = null
    private var theirsShader: android.graphics.LinearGradient? = null
    private var shaderHeight = 0
    private var shaderMine = 0
    private var shaderTheirs = 0

    // --- Zero allocation on the draw path ---
    //
    // `onDraw` runs on every frame during scrolling. An earlier version allocated a new `mutableListOf<RectF>()` per group, a new
    // `RectF` per member, and another list with `map { it.width() }`. At 60 fps that is hundreds of short-lived objects a second,
    // and the garbage collector causes stutter while scrolling. Intermediate data now lives in arrays that are reused. As long as
    // the arrays do not grow, nothing is allocated.
    private var tops = FloatArray(16)
    private var bottoms = FloatArray(16)
    private var widths = FloatArray(16)
    private var lefts = FloatArray(16)
    private var rights = FloatArray(16)
    private var memberCount = 0

    private companion object {
        /** Outer (convex) corner radius, the same as for single bubbles. */
        const val OUTER_RADIUS_DP = 18f
        /** Concave fillet at the steps. It must be smaller than the outer radius: when equal, the step looks melted and the outline
         *  is unreadable. */
        const val INNER_RADIUS_DP = 12f
    }

    override fun onDraw(canvas: Canvas, parent: RecyclerView, state: RecyclerView.State) {
        val childCount = parent.childCount
        if (childCount == 0) return
        val density = parent.resources.displayMetrics.density
        val outer = OUTER_RADIUS_DP * density
        val inner = INNER_RADIUS_DP * density
        // Theme colours stay fixed across the frame, so they are resolved once per frame, not once per group.
        val mineColor = MaterialColors.getColor(parent, com.google.android.material.R.attr.colorPrimaryContainer)
        val theirsColor = MaterialColors.getColor(parent, com.google.android.material.R.attr.colorSurfaceVariant)
        ensureShaders(parent.height, mineColor, theirsColor)

        var index = 0
        // Known failure case: some bubbles had no background drawn. The old skip condition was
        // `adapter.isGroupStart(position)`. The inner loop cuts a group when it sees a vertical gap between two consecutive bubbles
        // (the side column, such as the reaction or seen line, is taller than the bubble). The member that was cut off was NOT a
        // group start (the adapter counts it as grouped with the previous message), so the outer loop skipped it too. Its background
        // was never drawn. Now the code tracks whether a position was drawn yet, not whether it is a group start. Every visible
        // bubble that is not drawn yet gets a path.
        var drawnThroughPosition = RecyclerView.NO_POSITION
        while (index < childCount) {
            val child = parent.getChildAt(index)
            val position = parent.getChildAdapterPosition(child)
            // Skip only positions that a PREVIOUS group actually painted.
            if (position == RecyclerView.NO_POSITION ||
                (drawnThroughPosition != RecyclerView.NO_POSITION && position <= drawnThroughPosition)
            ) {
                index++
                continue
            }
            // A sticker has no bubble.
            if (adapter.isStickerAt(position)) {
                index++
                continue
            }
            memberCount = 0
            var cursor = index
            var cursorPosition = position
            while (cursor < childCount) {
                val member = parent.getChildAt(cursor)
                if (parent.getChildAdapterPosition(member) != cursorPosition) break
                if (!collectBubble(member)) break
                // A row that is swiped (translationX != 0) is drawn on its own. Otherwise the merged shape would move or distort the whole group.
                val moved = member.translationX != 0f
                if (moved && memberCount >= 2) {
                    memberCount--
                    break
                }
                // The group continues only while the bubbles really touch. Every vertical gap between them (a quote box, a sender line) would
                // make the merged shape fill that gap too, which broke the quotes. So the group is cut at that point.
                if (memberCount >= 2 && tops[memberCount - 1] - bottoms[memberCount - 2] > 1f) {
                    memberCount--
                    break
                }
                cursor++
                cursorPosition++
                if (moved) break
                if (!adapter.isGroupedWithNextPublic(cursorPosition - 1)) break
            }
            val isMine = adapter.isMineAt(position)
            paint.shader = if (isMine) mineShader else theirsShader
            if (memberCount >= 2) {
                buildUnionPath(isMine, outer, inner)
                canvas.drawPath(path, paint)
            } else if (memberCount == 1) {
                // SINGLE bubbles are drawn here too. They used to use their own drawable backgrounds, but a drawable only knows its own
                // bounds, so it cannot take its slice of a gradient stretched over the whole list. Drawing all of them in one place means
                // grouped and single bubbles share the SAME gradient.
                buildSinglePath(isMine, outer)
                canvas.drawPath(path, paint)
            }
            paint.shader = null
            if (memberCount >= 1) {
                // In this pass, `position .. position + memberCount - 1` have been painted.
                drawnThroughPosition = position + memberCount - 1
            }
            index = if (cursor > index) cursor else index + 1
        }
    }

    /** Writes the bubble's bounds into the buffers. Returns `false` if they cannot be found. */
    private fun collectBubble(itemView: View): Boolean {
        val bubble = bubbleOf(itemView) ?: return false
        var offsetX = 0f
        var offsetY = 0f
        var node: View = bubble
        while (node !== itemView) {
            offsetX += node.left
            offsetY += node.top
            node = node.parent as? View ?: return false
        }
        if (memberCount == tops.size) grow()
        val left = itemView.left + itemView.translationX + offsetX
        val top = itemView.top + itemView.translationY + offsetY
        tops[memberCount] = top
        bottoms[memberCount] = top + bubble.height
        lefts[memberCount] = left
        rights[memberCount] = left + bubble.width
        widths[memberCount] = bubble.width.toFloat()
        memberCount++
        return true
    }

    private fun grow() {
        val size = tops.size * 2
        tops = tops.copyOf(size)
        bottoms = bottoms.copyOf(size)
        widths = widths.copyOf(size)
        lefts = lefts.copyOf(size)
        rights = rights.copyOf(size)
    }

    /** `findViewById` used to be called for EVERY child on EVERY frame. The result now lives in the row's own `tag`. Even when the view
     *  is recycled, the row's `layoutBubble` stays the same instance. */
    private fun bubbleOf(itemView: View): View? {
        (itemView.getTag(R.id.layoutBubble) as? View)?.let { return it }
        val found = itemView.findViewById<View>(R.id.layoutBubble) ?: return null
        itemView.setTag(R.id.layoutBubble, found)
        return found
    }

    /**
     * Gradient shaders. They are rebuilt only when the list height or the theme colours change (creating a `LinearGradient` every frame
     * would be needless allocation).
     *
     * Top end: the base colour blended toward white, so the top bubbles are lighter.
     * Bottom end: the base colour itself, so the lower bubbles keep the current colour.
     */
    private fun ensureShaders(height: Int, mineColor: Int, theirsColor: Int) {
        if (height <= 0) return
        if (height == shaderHeight && mineColor == shaderMine && theirsColor == shaderTheirs) return
        shaderHeight = height
        shaderMine = mineColor
        shaderTheirs = theirsColor
        val lightMine = androidx.core.graphics.ColorUtils.blendARGB(mineColor, android.graphics.Color.WHITE, 0.30f)
        val lightTheirs = androidx.core.graphics.ColorUtils.blendARGB(theirsColor, android.graphics.Color.WHITE, 0.24f)
        mineShader = android.graphics.LinearGradient(
            0f, 0f, 0f, height.toFloat(), lightMine, mineColor, android.graphics.Shader.TileMode.CLAMP
        )
        theirsShader = android.graphics.LinearGradient(
            0f, 0f, 0f, height.toFloat(), lightTheirs, theirsColor, android.graphics.Shader.TileMode.CLAMP
        )
    }

    /**
     * Path for a SINGLE, ungrouped bubble. The geometry matches the `bubble_mine` and `bubble_theirs` drawables: three rounded corners
     * and a small "tail" corner. It is a `Path`, so it can be filled with the gradient.
     */
    private val singleRadii = FloatArray(8)

    private fun buildSinglePath(isMine: Boolean, outer: Float) {
        path.reset()
        val top = tops[0]
        val bottom = bottoms[0]
        val left = lefts[0]
        val right = rights[0]
        val r = minOf(outer, (bottom - top) / 2f, (right - left) / 2f)
        // Tail corner: bottom right for my own messages, bottom left for received ones.
        val tail = r * 0.22f
        scratch.set(left, top, right, bottom)
        // reused array, no allocation per frame.
        val radii = singleRadii
        radii[0] = r; radii[1] = r; radii[2] = r; radii[3] = r
        radii[4] = if (isMine) tail else r; radii[5] = radii[4]
        radii[6] = if (isMine) r else tail; radii[7] = radii[6]
        path.addRoundRect(scratch, radii, Path.Direction.CW)
    }

    /**
     * Builds the merged outline of a group.
     *
     * The path is built in "u space": `u` is the horizontal distance from the aligned edge, growing toward the variable edge. So my
     * messages (aligned right) and received messages (aligned left) share ONE geometry. Mirroring is done at the very end with a `Matrix`.
     * Doing it by hand in the coordinates needed the sign of every arc flipped separately, and a matrix removes that whole class of error.
     *
     * The aligned edge is straight from end to end. Only its top and bottom corners are rounded. On the variable edge, each width change
     * has TWO corners: a convex one (normal rounding) and a CONCAVE fillet at the step.
     */
    private fun buildUnionPath(isMine: Boolean, outer: Float, inner: Float) {
        path.reset()
        val top = tops[0]
        val bottom = bottoms[memberCount - 1]
        // Radii cannot be bigger than the bubble itself. On a short or narrow bubble (for example a single emoji), the arc would go beyond
        // the rectangle and fold over the shape.
        var minHeight = Float.MAX_VALUE
        var minWidth = Float.MAX_VALUE
        var flushLeft = Float.MAX_VALUE
        var flushRight = -Float.MAX_VALUE
        for (i in 0 until memberCount) {
            val h = bottoms[i] - tops[i]
            if (h < minHeight) minHeight = h
            if (widths[i] < minWidth) minWidth = widths[i]
            if (lefts[i] < flushLeft) flushLeft = lefts[i]
            if (rights[i] > flushRight) flushRight = rights[i]
        }
        // The path measures every member from ONE aligned edge. A bubble with
        // a reaction pill or seen avatars beside it starts further in, and its
        // background was drawn shifted: the first ~20 dp of text had none.
        for (i in 0 until memberCount) {
            widths[i] = if (isMine) flushRight - lefts[i] else rights[i] - flushLeft
        }
        val outerR = minOf(outer, minHeight / 2f, minWidth / 2f)
        path.moveTo(outerR, top)
        path.lineTo(widths[0] - outerR, top)
        corner(widths[0] - outerR, top + outerR, outerR, -90f, 90f)  // top outer corner

        for (i in 0 until memberCount) {
            val current = widths[i]
            if (i == memberCount - 1) {
                path.lineTo(current, bottom - outerR)
                corner(current - outerR, bottom - outerR, outerR, 0f, 90f)  // bottom outer corner
                break
            }
            val junction = bottoms[i]
            val next = widths[i + 1]
            // When a step is small, both radii are reduced to match. Otherwise, with a width difference of a few pixels, the arcs overlapped
            // each other and formed a knot.
            val step = kotlin.math.abs(next - current)
            val stepOuter = minOf(outerR, step / 2f)
            val stepInner = minOf(inner, step / 2f)
            when {
                next > current + 0.5f -> {
                    // Narrow to wide: open outward with a concave fillet.
                    path.lineTo(current, junction - stepInner)
                    corner(current + stepInner, junction - stepInner, stepInner, 180f, -90f)
                    path.lineTo(next - stepOuter, junction)
                    corner(next - stepOuter, junction + stepOuter, stepOuter, -90f, 90f)
                }
                next < current - 0.5f -> {
                    // Wide to narrow: convex corner first, then a concave fillet.
                    path.lineTo(current, junction - stepOuter)
                    corner(current - stepOuter, junction - stepOuter, stepOuter, 0f, 90f)
                    path.lineTo(next + stepInner, junction)
                    corner(next + stepInner, junction + stepInner, stepInner, -90f, -90f)
                }
            // Same width: a continuous straight edge, no corner.
            }
        }

        path.lineTo(outerR, bottom)
        corner(outerR, bottom - outerR, outerR, 90f, 90f)  // bottom aligned corner
        path.lineTo(0f, top + outerR)
        corner(outerR, top + outerR, outerR, 180f, 90f)  // top aligned corner
        path.close()

        // From u space to screen coordinates.
        matrix.reset()
        if (isMine) {
            // Right-aligned: u is measured from the right edge going LEFT.
            matrix.setScale(-1f, 1f)
            matrix.postTranslate(flushRight, 0f)
        } else {
            matrix.setTranslate(flushLeft, 0f)
        }
        path.transform(matrix)
    }

    /**
     * A quarter arc with its centre and angles given explicitly.
     *
     * Guessing the centre from the two endpoints was tried and did not work. There are TWO candidate centres at equal distance from both
     * endpoints, and which one is picked decides whether the corner is drawn convex or concave. So the guess left the most important
     * distinction of this shape to chance. Now each corner gives its own centre and turn direction (the sign of `sweep`): positive is
     * clockwise (convex), negative is counter-clockwise (concave fillet).
     */
    private fun corner(cx: Float, cy: Float, radius: Float, startAngle: Float, sweep: Float) {
        scratch.set(cx - radius, cy - radius, cx + radius, cy + radius)
        path.arcTo(scratch, startAngle, sweep)
    }
}
