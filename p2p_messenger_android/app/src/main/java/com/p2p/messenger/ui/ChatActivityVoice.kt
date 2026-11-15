package com.p2p.messenger.ui

import com.p2p.messenger.util.safeSaveFileName
import android.app.AlertDialog
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.media.MediaMetadataRetriever
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.media.MediaScannerConnection
import android.media.PlaybackParams
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.OpenableColumns
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.ActionBar
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SearchView
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.AppRestarter
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.CapturedImage
import com.p2p.messenger.util.promptAttachmentCaption
import com.p2p.messenger.util.ReactionPicker
import com.p2p.messenger.util.ConnectionStatus
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.KeyboardInsets
import com.p2p.messenger.util.NotificationHelper
import com.p2p.messenger.util.OutgoingMedia
import com.p2p.messenger.util.PlaybackSpeed
import com.p2p.messenger.util.PulsingStatusDot
import com.p2p.messenger.util.ReadStatePrefs
import com.p2p.messenger.util.ThemePrefs
import com.p2p.messenger.util.hexToBytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import com.p2p.messenger.ui.ChatActivity.Companion.MAX_ATTACHMENT_SIZE
import com.p2p.messenger.ui.ChatActivity.Companion.PREVIEW_JPEG_QUALITY
import com.p2p.messenger.ui.ChatActivity.Companion.PREVIEW_MAX_DIMENSION
import com.p2p.messenger.ui.ChatActivity.Companion.RECORDING_CANCEL_SWIPE_DP
import com.p2p.messenger.ui.ChatActivity.Companion.RECORDING_MIN_DURATION_MS
import com.p2p.messenger.ui.ChatActivity.Companion.REPLY_HIGHLIGHT_DURATION_MS
import com.p2p.messenger.ui.ChatActivity.Companion.REPLY_PREVIEW_MAX_CHARS
import com.p2p.messenger.ui.ChatActivity.Companion.REPLY_SWIPE_MAX_DP
import com.p2p.messenger.ui.ChatActivity.Companion.TYPHOON_QUIET_WINDOW_MS
import com.p2p.messenger.ui.ChatActivity.Companion.TYPING_INDICATOR_TIMEOUT_MS

// ChatActivity: voice message recording and playback.

/** #86: the finger is gone (touch cancelled / app was in the background): keep recording, ask send or discard. */
internal fun ChatActivity.promptRecordingDecision() {
    if (mediaRecorder == null || recordingDialog?.isShowing == true) return
    recordingDialog = AlertDialog.Builder(this)
        .setMessage(R.string.msg_recording_in_background)
        .setCancelable(false)
        .setPositiveButton(R.string.btn_send) { _, _ -> finishVoiceRecording(send = true) }
        .setNegativeButton(R.string.action_discard) { _, _ -> finishVoiceRecording(send = false) }
        .show()
}

// ---------------------------------------------------------------
// Voice message: recording
// ---------------------------------------------------------------

/** Hold to record, slide left to cancel (WhatsApp style). */
internal fun ChatActivity.setupVoiceRecordButton() {
    btnVoice.setOnTouchListener { _, event ->
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                if (!ensureHandshakeReadyOrWarn()) return@setOnTouchListener true
                if (ContextCompat.checkSelfPermission(
                        this, android.Manifest.permission.RECORD_AUDIO
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    AppLock.beginTrustedExcursion()
                    requestRecordAudioPermission.launch(android.Manifest.permission.RECORD_AUDIO)
                    return@setOnTouchListener true
                }
                recordingTouchStartX = event.rawX
                startVoiceRecording()
                true
            }
            MotionEvent.ACTION_UP -> {
                if (mediaRecorder != null) finishVoiceRecording(send = !recordingCancelled)
                true
            }
            MotionEvent.ACTION_MOVE -> {
                if (mediaRecorder != null) {
                    val dx = event.rawX - recordingTouchStartX
                    val thresholdPx = RECORDING_CANCEL_SWIPE_DP * resources.displayMetrics.density
                    recordingCancelled = dx > thresholdPx
                    updateCancelPill(dx, thresholdPx)
                }
                true
            }
            MotionEvent.ACTION_CANCEL -> {
                // backgrounding cancels the touch; the recording goes on, the user decides
                promptRecordingDecision()
                true
            }
            else -> false
        }
    }
}

/** The 'slide to cancel' pill: it moves with the finger, and turns red once the threshold is passed. */
internal fun ChatActivity.updateCancelPill(dx: Float, thresholdPx: Float) {
    txtCancelPill.translationX = dx.coerceIn(0f, thresholdPx)
    val pastThreshold = dx > thresholdPx
    txtCancelPill.setTextColor(
        if (pastThreshold) android.graphics.Color.WHITE
        else MaterialColors.getColor(txtCancelPill, com.google.android.material.R.attr.colorOnSurfaceVariant)
    )
    txtCancelPill.backgroundTintList =
        if (pastThreshold) {
            ColorStateList.valueOf(
                MaterialColors.getColor(txtCancelPill, com.google.android.material.R.attr.colorError)
            )
        } else {
            null
        }
}

internal fun ChatActivity.startVoiceRecording() {
    val file = File(File(cacheDir, "voice").apply { mkdirs() }, "${UUID.randomUUID()}.m4a")
    val recorder = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
        MediaRecorder(this)
    } else {
        @Suppress("DEPRECATION")
        MediaRecorder()
    }
    try {
        recorder.setAudioSource(MediaRecorder.AudioSource.MIC)
        recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
        recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
        recorder.setAudioEncodingBitRate(64_000)
        recorder.setAudioSamplingRate(44_100)
        recorder.setOutputFile(file.absolutePath)
        // Ceiling: 10 minutes. The recorder stops itself at the ceiling and
        // the app then takes the SAME send/discard decision it already takes
        // when a recording ends (ACTION_UP).
        recorder.setMaxDuration(10 * 60 * 1000)
        recorder.setOnInfoListener { _, what, _ ->
            if (what == MediaRecorder.MEDIA_RECORDER_INFO_MAX_DURATION_REACHED) {
                // The info callback is not guaranteed to arrive on the main
                // thread: the decision (and its UI work) runs there.
                recordingHandler.post {
                    if (mediaRecorder === recorder) finishVoiceRecording(send = !recordingCancelled)
                }
            }
        }
        recorder.prepare()
        recorder.start()
    } catch (e: Exception) {
        Toast.makeText(this, R.string.error_recording_failed, Toast.LENGTH_SHORT).show()
        recorder.release()
        return
    }
    mediaRecorder = recorder
    P2PService.setRecordingActive(applicationContext, true)
    recordingFile = file
    recordingStartTime = android.os.SystemClock.elapsedRealtime()
    recordingCancelled = false
    layoutMessageInput.visibility = View.GONE
    layoutRecording.visibility = View.VISIBLE
    txtRecordingTimer.text = "0:00"
    txtCancelPill.translationX = 0f
    txtCancelPill.backgroundTintList = null
    recordingHandler.post(recordingTimerRunnable)
}

/** When `send = false` (cancelled or error), the recording file is deleted. */
internal fun ChatActivity.finishVoiceRecording(send: Boolean) {
    val recorder = mediaRecorder ?: return
    val file = recordingFile
    val durationMs = android.os.SystemClock.elapsedRealtime() - recordingStartTime
    mediaRecorder = null
    recordingFile = null
    P2PService.setRecordingActive(applicationContext, false)
    recordingHandler.removeCallbacks(recordingTimerRunnable)
    layoutRecording.visibility = View.GONE
    layoutMessageInput.visibility = View.VISIBLE
    try {
        recorder.stop()
    } catch (e: Exception) {
        // Very short recordings can make `stop()` throw. The file is unusable then.
        file?.delete()
        recorder.release()
        return
    }
    recorder.release()
    if (send && durationMs >= RECORDING_MIN_DURATION_MS && file != null) {
        // A caption can also be typed under the voice message. The recording is not sent on release: the caption is asked for first.
        // If it is left empty, the message is sent as before.
        promptAttachmentCaption(onCancel = { file.delete() }) { caption, _ -> sendVoiceMessage(file, durationMs, caption, takeQuote()) }
    } else {
        file?.delete()
        if (send) {
            Toast.makeText(this, R.string.msg_recording_cancelled, Toast.LENGTH_SHORT).show()
        }
    }
}

/** A voice message is sent as a normal file attachment (MIME 'audio/mp4'). The only difference is that `durationMs` is carried (see Rust `FileOffer.duration_ms`). */
internal fun ChatActivity.sendVoiceMessage(file: File, durationMs: Long, caption: String = "", quote: com.p2p.messenger.util.Quote.Ref? = null) {
    lifecycleScope.launch(Dispatchers.IO) {
        // The copy is deleted even if the screen closes while sending.
        // The recorder's MP4 carries the Android version (on many phones
        // maker and model) and creation times: scrubbed like a picked
        // m4a; a failed scrub cancels the send.
        val prepared = try {
            com.p2p.messenger.util.OutgoingMedia.prepare(file, file.name, "audio/mp4", false) { false }
        } catch (e: Exception) {
            null
        }
        try {
            val result = if (prepared == null) "Error: INTERNAL: voice scrub" else try {
                P2PLib.prepareAndSendFile(
                    peerDeviceFingerprint, prepared.file.absolutePath, file.name, "audio/mp4", null, durationMs.toInt(),
                    caption, quote?.id ?: "", quote?.preview ?: ""
                )
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@sendVoiceMessage, com.p2p.messenger.util.coreErrorText(this@sendVoiceMessage, result), Toast.LENGTH_SHORT).show()
                } else {
                    val obj = JSONObject(result)
                    adapter.addMessage(
                        SimpleChatAdapter.Item(
                            messageId = obj.optString("message_id"),
                            text = "",
                            isMine = true,
                            caption = caption,
                            replyToMessageId = quote?.id,
                            replyToPreview = quote?.preview,
                            replyToSenderLabel = resolveReplyLabel(quote?.id),
                            attachment = SimpleChatAdapter.AttachmentInfo(
                                fileId = obj.optString("message_id"),
                                fileName = file.name,
                                mimeType = "audio/mp4",
                                totalSize = file.length(),
                                status = SimpleChatAdapter.AttachmentStatus.COMPLETE,
                                bytesDone = file.length(),
                                durationMs = durationMs.toInt()
                            )
                        )
                    )
                    resolveReplyLabels()
                    scrollToBottomNow()
                }
            }
        } finally {
            prepared?.file?.delete()
            file.delete()
        }
    }
}

internal fun ChatActivity.formatDurationMs(ms: Long): String {
    val totalSeconds = ms / 1000
    return String.format(java.util.Locale.getDefault(), "%d:%02d", totalSeconds / 60, totalSeconds % 60)
}

// ---------------------------------------------------------------
// Voice message: playback
// ---------------------------------------------------------------

internal fun ChatActivity.onVoicePlayClicked(item: SimpleChatAdapter.Item) {
    val attachment = item.attachment ?: return
    if (attachment.status != SimpleChatAdapter.AttachmentStatus.COMPLETE) return
    if (voicePlayingFileId == attachment.fileId) {
        val player = voicePlayer ?: return
        if (player.isPlaying) {
            player.pause()
            voicePlaybackHandler.removeCallbacks(voicePlaybackTickRunnable)
            adapter.updateVoicePlayback(attachment.fileId, false, player.currentPosition, voicePlaybackSpeed)
        } else {
            player.start()
            voicePlaybackHandler.post(voicePlaybackTickRunnable)
            adapter.updateVoicePlayback(attachment.fileId, true, player.currentPosition, voicePlaybackSpeed)
        }
    } else {
        loadAndPlayVoiceMessage(item, attachment, 0)
    }
}

/** The user drags the slider and releases it: if the playing message is this one, seek directly; otherwise load it from that position. */
internal fun ChatActivity.onVoiceSeeked(item: SimpleChatAdapter.Item, positionMs: Int) {
    val attachment = item.attachment ?: return
    if (attachment.status != SimpleChatAdapter.AttachmentStatus.COMPLETE) return
    if (voicePlayingFileId == attachment.fileId) {
        val player = voicePlayer ?: return
        player.seekTo(positionMs)
        adapter.tickVoicePlayback(attachment.fileId, positionMs, player.duration)
    } else {
        loadAndPlayVoiceMessage(item, attachment, positionMs)
    }
}

/** The decrypted copy's path is obtained OFF the main thread: decrypting a large file can take minutes (see Rust `begin_attachment_decrypt`). */
internal fun ChatActivity.loadAndPlayVoiceMessage(
    item: SimpleChatAdapter.Item,
    attachment: SimpleChatAdapter.AttachmentInfo,
    startPositionMs: Int
) {
    stopVoicePlayback()
    val request = voiceLoadRequest
    lifecycleScope.launch(Dispatchers.IO) {
        val path = try {
            P2PLib.getAttachmentPlaintextPath(attachment.fileId)
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
        withContext(Dispatchers.Main) {
            // Another tap or a pause came first: starting now would leave
            // a second player that nobody ever releases.
            if (request != voiceLoadRequest) return@withContext
            if (path.startsWith("Error:")) {
                Toast.makeText(this@loadAndPlayVoiceMessage, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
                return@withContext
            }
            var created: MediaPlayer? = null
            try {
                val player = MediaPlayer()
                created = player
                player.setDataSource(path)
                player.setOnCompletionListener {
                    voicePlaybackHandler.removeCallbacks(voicePlaybackTickRunnable)
                    adapter.updateVoicePlayback(attachment.fileId, false, 0, voicePlaybackSpeed)
                }
                player.prepare()
                if (startPositionMs > 0) player.seekTo(startPositionMs)
                voicePlaybackSpeed = attachment.playbackSpeed
                if (voicePlaybackSpeed != 1f &&
                    android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M
                ) {
                    player.playbackParams = PlaybackParams().setSpeed(voicePlaybackSpeed)
                }
                player.start()
                voicePlayer = player
                voicePlayingFileId = attachment.fileId
                voicePlaybackHandler.post(voicePlaybackTickRunnable)
                adapter.updateVoicePlayback(attachment.fileId, true, startPositionMs, voicePlaybackSpeed)
            } catch (e: Exception) {
                // A corrupt file: free the native decoder, it was never stored.
                created?.release()
                Toast.makeText(this@loadAndPlayVoiceMessage, getString(R.string.error_attachment_open_failed), Toast.LENGTH_SHORT).show()
            }
        }
    }
}

/** Speed badge (1x → 1.5x → 2x → 0.5x, see PlaybackSpeed). On a bubble that is not playing it is only stored as a preference. */
internal fun ChatActivity.onVoiceSpeedClicked(item: SimpleChatAdapter.Item) {
    val attachment = item.attachment ?: return
    val newSpeed = PlaybackSpeed.next(attachment.playbackSpeed)
    if (voicePlayingFileId == attachment.fileId) {
        voicePlaybackSpeed = newSpeed
        val player = voicePlayer
        if (player != null && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            try {
                // Setting the speed starts a paused player (documented): put it back.
                val wasPlaying = player.isPlaying
                player.playbackParams = PlaybackParams().setSpeed(newSpeed)
                if (!wasPlaying) player.pause()
            } catch (e: Exception) {
            }
        }
        adapter.updateVoicePlayback(
            attachment.fileId, player?.isPlaying ?: false, player?.currentPosition ?: 0, newSpeed
        )
    } else {
        attachment.playbackSpeed = newSpeed
        adapter.updateVoicePlayback(attachment.fileId, false, attachment.playbackPositionMs, newSpeed)
    }
}

internal fun ChatActivity.stopVoicePlayback() {
    voiceLoadRequest++
    val fileId = voicePlayingFileId
    voicePlaybackHandler.removeCallbacks(voicePlaybackTickRunnable)
    try {
        voicePlayer?.stop()
        voicePlayer?.release()
    } catch (e: Exception) {
    }
    voicePlayer = null
    voicePlayingFileId = null
    if (fileId != null) {
        adapter.updateVoicePlayback(fileId, false, 0, voicePlaybackSpeed)
    }
}
