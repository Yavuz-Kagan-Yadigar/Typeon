package com.p2p.messenger.ui

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ObjectAnimator
import android.animation.PropertyValuesHolder
import android.view.View
import android.view.animation.DecelerateInterpolator
import androidx.recyclerview.widget.DefaultItemAnimator
import androidx.recyclerview.widget.RecyclerView

/**
 * Default animator, plus a small scale-and-slide "pop" for one new message at the bottom of the
 * list (sent or received). Only a lone insert at the last position pops: history pages (range
 * inserts at the top) and full reloads keep the plain behaviour. The default fade still runs; the
 * pop starts together with it in [onAddStarting], so it also waits for move animations.
 */
class MessageItemAnimator(private val isMineAt: (Int) -> Boolean) : DefaultItemAnimator() {
    private val adds = ArrayList<RecyclerView.ViewHolder>()
    private val armed = HashSet<RecyclerView.ViewHolder>()
    private val running = HashMap<RecyclerView.ViewHolder, Animator>()

    init {
        supportsChangeAnimations = false
        addDuration = 220
    }

    override fun animateAdd(holder: RecyclerView.ViewHolder): Boolean {
        adds += holder
        return super.animateAdd(holder)
    }

    override fun runPendingAnimations() {
        val h = adds.singleOrNull()
        adds.clear()
        val pos = h?.bindingAdapterPosition ?: RecyclerView.NO_POSITION
        val count = h?.bindingAdapter?.itemCount ?: 0
        if (h != null && pos != RecyclerView.NO_POSITION && pos == count - 1) {
            val v = h.itemView
            v.pivotX = if (isMineAt(pos)) v.width.toFloat() else 0f
            v.pivotY = v.height.toFloat()
            v.scaleX = 0.85f
            v.scaleY = 0.85f
            v.translationY = v.height * 0.4f
            armed += h
        }
        super.runPendingAnimations()
    }

    override fun onAddStarting(item: RecyclerView.ViewHolder) {
        if (!armed.remove(item)) return
        val a = ObjectAnimator.ofPropertyValuesHolder(
            item.itemView,
            PropertyValuesHolder.ofFloat(View.SCALE_X, 1f),
            PropertyValuesHolder.ofFloat(View.SCALE_Y, 1f),
            PropertyValuesHolder.ofFloat(View.TRANSLATION_Y, 0f),
        ).setDuration(addDuration)
        a.interpolator = DecelerateInterpolator(2f)
        a.addListener(object : AnimatorListenerAdapter() {
            override fun onAnimationEnd(animation: Animator) {
                running.remove(item)
                reset(item.itemView)
            }
        })
        running[item] = a
        a.start()
    }

    override fun endAnimation(item: RecyclerView.ViewHolder) {
        stop(item)
        super.endAnimation(item)
    }

    override fun endAnimations() {
        (armed + running.keys).toList().forEach(::stop)
        super.endAnimations()
    }

    private fun stop(item: RecyclerView.ViewHolder) {
        armed.remove(item)
        running.remove(item)?.cancel()
        reset(item.itemView)
    }

    private fun reset(v: View) {
        v.scaleX = 1f
        v.scaleY = 1f
        v.translationY = 0f
    }
}
