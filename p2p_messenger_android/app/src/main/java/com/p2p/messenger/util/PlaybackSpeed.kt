package com.p2p.messenger.util

/** Speed levels shared by the voice message bubble AND the video player. Each tap cycles through them (1x -> 1.5x -> 2x -> 0.5x -> 1x). */
object PlaybackSpeed {
    val LEVELS = floatArrayOf(1f, 1.5f, 2f, 0.5f)

    fun next(current: Float): Float {
        val idx = LEVELS.indexOfFirst { it == current }
        return LEVELS[(idx + 1).mod(LEVELS.size)]
    }
}
