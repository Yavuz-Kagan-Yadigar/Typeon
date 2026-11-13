package com.p2p.messenger.ui

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ObjectAnimator
import android.view.View
import android.view.animation.OvershootInterpolator
import androidx.recyclerview.widget.DefaultItemAnimator
import androidx.recyclerview.widget.RecyclerView

/**
 * Default animator, plus a WhatsApp-like slide for one new message at the bottom of the list
 * (sent or received): it rises from below its own bottom edge, with a slight overshoot. Only a lone insert at the last position pops: history pages (range
 * inserts at the top) and full reloads keep the plain behaviour. The default fade still runs; the
 * pop starts together with it in [onAddStarting], so it also waits for move animations.
 */
class MessageItemAnimator : DefaultItemAnimator() {
    private val adds = ArrayList<RecyclerView.ViewHolder>()
    private val armed = HashSet<RecyclerView.ViewHolder>()
    private val running = HashMap<RecyclerView.ViewHolder, Animator>()

    init {
        supportsChangeAnimations = false
        addDuration = 320
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
            h.itemView.translationY = h.itemView.height.toFloat()
            armed += h
        }
        super.runPendingAnimations()
    }

    override fun onAddStarting(item: RecyclerView.ViewHolder) {
        if (!armed.remove(item)) return
        val a = ObjectAnimator.ofFloat(item.itemView, View.TRANSLATION_Y, 0f).setDuration(addDuration)
        a.interpolator = OvershootInterpolator(1.2f)
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
        v.translationY = 0f
    }
}
