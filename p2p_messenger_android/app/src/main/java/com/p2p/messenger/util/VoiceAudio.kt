package com.p2p.messenger.util

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.media.AudioManager

/** Audio focus and "headphones unplugged" handling for voice-message playback (one player at a time). */
object VoiceAudio {
    private var receiver: BroadcastReceiver? = null

    /** Takes transient focus; [onNoisy] runs when the output route is about to change (headphones unplugged). */
    @Suppress("DEPRECATION")
    fun begin(context: Context, onNoisy: () -> Unit) {
        end(context)
        val app = context.applicationContext
        try {
            (app.getSystemService(Context.AUDIO_SERVICE) as AudioManager)
                .requestAudioFocus(null, AudioManager.STREAM_MUSIC, AudioManager.AUDIOFOCUS_GAIN_TRANSIENT)
            val r = object : BroadcastReceiver() {
                override fun onReceive(c: Context?, i: Intent?) = onNoisy()
            }
            app.registerReceiver(r, IntentFilter(AudioManager.ACTION_AUDIO_BECOMING_NOISY))
            receiver = r
        } catch (e: Exception) {
        }
    }

    @Suppress("DEPRECATION")
    fun end(context: Context) {
        val app = context.applicationContext
        receiver?.let { try { app.unregisterReceiver(it) } catch (e: Exception) { } }
        receiver = null
        try {
            (app.getSystemService(Context.AUDIO_SERVICE) as AudioManager).abandonAudioFocus(null)
        } catch (e: Exception) {
        }
    }
}
