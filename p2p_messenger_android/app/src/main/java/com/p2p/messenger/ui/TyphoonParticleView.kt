package com.p2p.messenger.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.os.SystemClock
import android.util.AttributeSet
import android.view.View
import kotlin.math.cos
import kotlin.math.sin
import kotlin.random.Random

/**
 * A particle "typhoon" effect, played when a message is sent to a chat that had no message in the last 15 minutes. It is drawn in 3D:
 * wide at the top, narrow at the bottom, and large. So the first version, a spiral thrown outward from one point, was dropped. A real
 * FUNNEL (tornado) geometry replaces it:
 *
 * - Each particle has a HEIGHT (`h`, 0 = funnel tip at the bottom, 1 = mouth at the top) and an ANGLE. The orbit radius grows with
 *   height (`FUNNEL_TIP_RADIUS` to `FUNNEL_MOUTH_RADIUS`), so the top is wide and the bottom narrow.
 * - The 3D feel comes from PERSPECTIVE, not from a fake shadow. The horizontal radius is full, and the vertical radius is squashed by
 *   `ELLIPSE_SQUASH`, so a circle seen from above appears as an ellipse. `sin(angle)` is used as DEPTH: particles behind (farther away)
 *   are smaller and fainter. So the rotation reads as real volume moving from front to back.
 * - Particles rise over time, and they spin faster toward the tip (as in a real tornado). That gives the funnel its twist.
 *
 * It is still light: one `Paint`, a fixed duration, and the view goes `GONE` when the animation ends. No endless animation runs.
 */
class TyphoonParticleView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    private companion object {
        /**
         * The particle count was lowered from 110 to 56.
         *
         * The real cost was not the count. Each particle's trail had a `BlurMaskFilter`. That filter is NOT supported by hardware
         * acceleration, so every draw that uses it falls back to software rasterisation for that layer. With 110 blurred lines per
         * frame, that meant 110 software passes every frame. The filter is removed entirely. The "blur" feel now comes from the
         * trail's own geometry (see `TRAIL_SEGMENTS`). Halving the count is an extra saving.
         */
        const val PARTICLE_COUNT = 56
        const val DURATION_MS = 1900L
        /**
         * The trail is not one thick line. It is a chain of short segments. The thick end is opaque, and the tail thins and fades out.
         * A single `drawLine` cannot do that: it has one width and one alpha. Splitting it into segments, and reducing the width and
         * alpha along the chain, gives a tapered and fading motion trail. It is much cheaper than `BlurMaskFilter`.
         */
        const val TRAIL_SEGMENTS = 10
        /** Funnel tip (bottom), as a fraction of the view width. */
        const val FUNNEL_TIP_RADIUS = 0.045f
        /** Funnel mouth (top): wide at the top, as wanted. */
        const val FUNNEL_MOUTH_RADIUS = 0.46f
        /** Vertical squash: 1 = circle (seen from above), smaller = flatter. */
        const val ELLIPSE_SQUASH = 0.30f
        /** Total rotation the particle makes over its life, in radians. */
        const val BASE_SPIN = 7.0f
        /** Time-based length of the longest trail. The real length is scaled with the particle's size (see `Particle.trailSpan`). */
        const val TRAIL_SPAN_MAX = 0.22f
    }

    private class Particle(
        val angle0: Float,
        val height0: Float,
        val rise: Float,
        val spin: Float,
        val size: Float,
        val delay: Float,
        /** The trail length follows the particle SIZE, with random variation: a large particle leaves a long trail. */
        val trailSpan: Float,
        val hueShift: Float,
        val satShift: Float,
        val valShift: Float,
        /** Final colour, derived from the accent. It is computed once in `burst`, not on every frame. */
        var color: Int = 0,
    )

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)

    private var particles: List<Particle> = emptyList()
    private var startedAt = 0L
    private var tint = 0

    init {
        isClickable = false
        isFocusable = false
    }

    /**
     * Starts the effect. The funnel covers the WHOLE view, so there is no centre point. The caller does not need to compute the
     * position of a bubble.
     */
    fun burst(color: Int) {
        tint = color
        val random = Random(SystemClock.uptimeMillis())
        particles = List(PARTICLE_COUNT) {
            // The size is chosen first, as a ratio. Both the pixel size and the trail length come from the same random value.
            val sizeFraction = random.nextFloat()
            val sizePx = (4.0f + sizeFraction * 7.5f) * resources.displayMetrics.density
            Particle(
                angle0 = random.nextFloat() * 6.2832f,
                // The starting heights are spread over the whole funnel, so the effect is full from the first frame and does not
                // fill up slowly from the bottom.
                height0 = random.nextFloat(),
                rise = 0.25f + random.nextFloat() * 0.55f,
                spin = 0.7f + random.nextFloat() * 0.8f,
                // Particles are larger than before.
                size = sizePx,
                trailSpan = TRAIL_SPAN_MAX * (0.35f + 0.65f * sizeFraction),
                delay = random.nextFloat() * 0.2f,
                // Colour: about the accent colour, with some variation. Hue, saturation and brightness are shifted slightly in HSV.
                // Shifting in RGB pulled the colour away from the accent family and produced grey or muddy tones.
                hueShift = (random.nextFloat() - 0.5f) * 34f,
                satShift = (random.nextFloat() - 0.5f) * 0.30f,
                valShift = (random.nextFloat() - 0.5f) * 0.34f,
            )
        }
        val hsv = FloatArray(3)
        Color.colorToHSV(color, hsv)
        for (p in particles) {
            p.color = Color.HSVToColor(
                floatArrayOf(
                    (hsv[0] + p.hueShift + 360f) % 360f,
                    (hsv[1] + p.satShift).coerceIn(0.25f, 1f),
                    (hsv[2] + p.valShift).coerceIn(0.5f, 1f),
                )
            )
        }
        startedAt = SystemClock.uptimeMillis()
        visibility = VISIBLE
        postInvalidateOnAnimation()
    }

    // Output of the position calculation, reused for every particle. This avoids allocating a `PointF` per particle every frame
    // (hundreds of objects).
    private var posX = 0f
    private var posY = 0f
    private var posHeight = 0f

    // Trail points, reused so that no array is allocated per particle per frame. Plus one for the head point.
    private val trailX = FloatArray(TRAIL_SEGMENTS + 1)
    private val trailY = FloatArray(TRAIL_SEGMENTS + 1)

    /** Writes the particle's screen position at time `t` into `posX` / `posY`. */
    private fun computePosition(p: Particle, t: Float, w: Float, h: Float, centerX: Float) {
        val heightFraction = (p.height0 + p.rise * t) % 1f
        // Faster spin toward the tip, which gives the twist of the tornado.
        val angle = p.angle0 + BASE_SPIN * p.spin * (1.6f - heightFraction) * t
        val radius = (FUNNEL_TIP_RADIUS + (FUNNEL_MOUTH_RADIUS - FUNNEL_TIP_RADIUS) * heightFraction) * w
        posHeight = heightFraction
        posX = centerX + cos(angle) * radius
        posY = h - heightFraction * h + sin(angle) * radius * ELLIPSE_SQUASH
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (particles.isEmpty()) return
        val progress = (SystemClock.uptimeMillis() - startedAt).toFloat() / DURATION_MS
        if (progress >= 1f) {
            particles = emptyList()
            visibility = GONE
            return
        }
        val w = width.toFloat()
        val h = height.toFloat()
        if (w <= 0f || h <= 0f) return
        val centerX = w / 2f
        // Overall visibility of the effect: it appears quickly and fades out slowly.
        val envelope = if (progress < 0.18f) progress / 0.18f else 1f - (progress - 0.18f) / 0.82f

        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND

        for (p in particles) {
            val t = ((progress - p.delay) / (1f - p.delay)).coerceIn(0f, 1f)
            if (t <= 0f) continue

            computePosition(p, t, w, h, centerX)
            var headX = posX
            var headY = posY
            var headHeight = posHeight
            val heightFraction = posHeight

            // The depth is not derived from the position. The angle is already known to `computePosition`. Here, only a rough front/back
            // split is needed, so the sign of the vertical offset along the orbit is used.
            val orbitCenterY = h - heightFraction * h
            val depth = ((headY - orbitCenterY) / (ELLIPSE_SQUASH * FUNNEL_MOUTH_RADIUS * w))
                .coerceIn(-1f, 1f)
            val depthScale = 0.55f + 0.45f * (depth + 1f) / 2f
            // Softly fade at the ends (bottom and top), so the funnel does not look cut off.
            val edgeFade = (1f - kotlin.math.abs(heightFraction - 0.5f) * 1.35f).coerceIn(0f, 1f)
            val headAlpha = 235f * envelope * depthScale * edgeFade
            if (headAlpha <= 1f) continue

            val headWidth = p.size * depthScale
            paint.color = p.color

            // Collect the trail points first (head to tail), then draw in REVERSE order.
            //
            // The reverse order is required. Each segment has round caps (`Cap.ROUND`) and the segments have different widths. Drawing
            // from head to tail put the round end of a thick segment on top of the next, thinner segment, and the trail showed bulges
            // like beads on a real device. Drawing from tail to head makes each thick segment cover the end of the previous one, so the
            // transition becomes a smooth taper.
            trailX[0] = headX
            trailY[0] = headY
            var points = 1
            var previousHeight = headHeight
            for (segment in 1..TRAIL_SEGMENTS) {
                val fraction = segment.toFloat() / TRAIL_SEGMENTS
                val tailT = (t - p.trailSpan * fraction).coerceAtLeast(0f)
                computePosition(p, tailT, w, h, centerX)
                // When the height wraps (`% 1f`), the earlier position lands on the other end of the funnel. Drawing that segment would
                // produce a wrong line across the whole screen.
                if (kotlin.math.abs(posHeight - previousHeight) > 0.5f) break
                trailX[points] = posX
                trailY[points] = posY
                previousHeight = posHeight
                points++
            }

            for (i in points - 1 downTo 1) {
                // `i` near the tail is thin and transparent, and near the head it is thick and opaque. That is the taper.
                val fraction = i.toFloat() / TRAIL_SEGMENTS
                paint.strokeWidth = headWidth * (1f - fraction) + 0.35f
                paint.alpha = (headAlpha * (1f - fraction)).toInt().coerceIn(0, 255)
                canvas.drawLine(trailX[i - 1], trailY[i - 1], trailX[i], trailY[i], paint)
            }
        }
        postInvalidateOnAnimation()
    }
}
