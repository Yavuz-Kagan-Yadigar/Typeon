package com.p2p.messenger.ui

import com.p2p.messenger.util.safeSaveFileName
import android.Manifest
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Canvas
import android.media.MediaMetadataRetriever
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.media.PlaybackParams
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListPopupWindow
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
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.coreErrorText
import com.p2p.messenger.util.AppRestarter
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.CapturedImage
import com.p2p.messenger.util.promptAttachmentCaption
import com.p2p.messenger.util.ReactionPicker
import com.p2p.messenger.util.ConnectionStatus
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.MAX_FOREIGN_URI_BYTES
import com.p2p.messenger.util.copyToCapped
import com.p2p.messenger.util.KeyboardInsets
import com.p2p.messenger.util.OutgoingMedia
import com.p2p.messenger.util.PlaybackSpeed
import com.p2p.messenger.util.PulsingStatusDot
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
import com.p2p.messenger.ui.GroupChatActivity.Companion.AVATAR_JPEG_QUALITY
import com.p2p.messenger.ui.GroupChatActivity.Companion.AVATAR_MAX_DIMENSION
import com.p2p.messenger.ui.GroupChatActivity.Companion.CONTACT_CACHE_TTL_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.MAX_ATTACHMENT_SIZE
import com.p2p.messenger.ui.GroupChatActivity.Companion.PREVIEW_JPEG_QUALITY
import com.p2p.messenger.ui.GroupChatActivity.Companion.PREVIEW_MAX_DIMENSION
import com.p2p.messenger.ui.GroupChatActivity.Companion.RECORDING_CANCEL_SWIPE_DP
import com.p2p.messenger.ui.GroupChatActivity.Companion.RECORDING_MIN_DURATION_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.REPLY_HIGHLIGHT_DURATION_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.REPLY_PREVIEW_MAX_CHARS
import com.p2p.messenger.ui.GroupChatActivity.Companion.REPLY_SWIPE_MAX_DP
import com.p2p.messenger.ui.GroupChatActivity.Companion.TYPHOON_QUIET_WINDOW_MS
import com.p2p.messenger.ui.GroupChatActivity.Companion.TYPING_INDICATOR_TIMEOUT_MS
import com.p2p.messenger.ui.GroupChatActivity.ContactLookup

// GroupChatActivity: voice message recording and playback.

/** #86: the finger is gone (touch cancelled / app was in the background): keep recording, ask send or discard. */
internal fun GroupChatActivity.promptRecordingDecision() {
    if (mediaRecorder == null || recordingDialog?.isShowing == true) return
    recordingDialog = AlertDialog.Builder(this)
        .setMessage(R.string.msg_recording_in_background)
        .setCancelable(false)
        .setPositiveButton(R.string.btn_send) { _, _ -> finishVoiceRecording(send = true) }
        .setNegativeButton(R.string.action_discard) { _, _ -> finishVoiceRecording(send = false) }
        .show()
}

// ---------------------------------------------------------------
// Voice recording in group chats. Same pattern as ChatActivity (hold to record, slide right to cancel).
// The one difference: sending goes through `prepareAndSendGroupFile`.
// ---------------------------------------------------------------

internal fun GroupChatActivity.setupVoiceRecordButton() {
    findViewById<ImageButton>(R.id.btnVoice).setOnTouchListener { _, event ->
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                    AppLock.beginTrustedExcursion()
                    requestRecordAudioPermission.launch(Manifest.permission.RECORD_AUDIO)
                    return@setOnTouchListener true
                }
                recordingTouchStartX = event.rawX
                startVoiceRecording()
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
            MotionEvent.ACTION_UP -> {
                if (mediaRecorder != null) finishVoiceRecording(send = !recordingCancelled)
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

internal fun GroupChatActivity.updateCancelPill(dx: Float, thresholdPx: Float) {
    txtCancelPill.translationX = dx.coerceIn(0f, thresholdPx)
    val pastThreshold = dx > thresholdPx
    txtCancelPill.setTextColor(
        if (pastThreshold) android.graphics.Color.WHITE
        else com.google.android.material.color.MaterialColors.getColor(txtCancelPill, com.google.android.material.R.attr.colorOnSurfaceVariant)
    )
    txtCancelPill.backgroundTintList = if (pastThreshold) {
        android.content.res.ColorStateList.valueOf(
            com.google.android.material.color.MaterialColors.getColor(txtCancelPill, com.google.android.material.R.attr.colorError)
        )
    } else {
        null
    }
}

internal fun GroupChatActivity.startVoiceRecording() {
    val file = File(File(cacheDir, "voice").apply { mkdirs() }, "${UUID.randomUUID()}.m4a")
    val recorder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) MediaRecorder(this) else @Suppress("DEPRECATION") MediaRecorder()
    try {
        recorder.setAudioSource(MediaRecorder.AudioSource.MIC)
        recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
        recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
        recorder.setAudioEncodingBitRate(64000)
        recorder.setAudioSamplingRate(44100)
        recorder.setOutputFile(file.absolutePath)
        // Upper limit: 10 minutes. The recording ends by itself, and the app then makes the same send-or-attach decision it makes on ACTION_UP.
        recorder.setMaxDuration(10 * 60 * 1000)
        recorder.setOnInfoListener { _, what, _ ->
            if (what == MediaRecorder.MEDIA_RECORDER_INFO_MAX_DURATION_REACHED) {
                // The event may not arrive on the main thread, so the decision (and the screen work) runs on the main thread.
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

internal fun GroupChatActivity.finishVoiceRecording(send: Boolean) {
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
        file?.delete()
        recorder.release()
        return
    }
    recorder.release()
    if (!send || durationMs < RECORDING_MIN_DURATION_MS || file == null) {
        file?.delete()
        if (send) Toast.makeText(this, R.string.msg_recording_cancelled, Toast.LENGTH_SHORT).show()
        return
    }
    // Same note as ChatActivity: text goes under the voice message too.
    promptAttachmentCaption(onCancel = { file.delete() }) { caption, _ -> sendVoiceMessage(file, durationMs, caption, takeQuote()) }
}

/**
 * Same pattern as ChatActivity.sendVoiceMessage. The differences: `prepareAndSendGroupFile` (offered to ALL members), and the return value
 * is a plain file-id string, not the JSON `{message_id, status}` of the 1:1 path (see the `onGroupFilePicked` note on the return format).
 */
internal fun GroupChatActivity.sendVoiceMessage(file: File, durationMs: Long, caption: String = "", quote: com.p2p.messenger.util.Quote.Ref? = null) {
    val targetGroupId = groupId
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
                P2PLib.prepareAndSendGroupFile(
                    targetGroupId, prepared.file.absolutePath, file.name, "audio/mp4", null, durationMs.toInt(),
                    caption, quote?.id ?: "", quote?.preview ?: "", quote?.sender ?: ""
                )
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(this@sendVoiceMessage, com.p2p.messenger.util.coreErrorText(this@sendVoiceMessage, result), Toast.LENGTH_SHORT).show()
                } else {
                    adapter.addMessage(
                        SimpleChatAdapter.Item(
                            messageId = result,
                            text = "",
                            isMine = true,
                            caption = caption,
                            replyToMessageId = quote?.id,
                            replyToPreview = quote?.preview,
                            replyToSenderLabel = resolveReplyLabel(quote?.id),
                            attachment = SimpleChatAdapter.AttachmentInfo(
                                fileId = result,
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

internal fun GroupChatActivity.formatDurationMs(ms: Long): String {
    val totalSeconds = ms / 1000
    val minutes = totalSeconds / 60
    val seconds = totalSeconds % 60
    return String.format(java.util.Locale.getDefault(), "%d:%02d", minutes, seconds)
}

// ---------------------------------------------------------------
// Voice message playback in group chats. Same pattern as ChatActivity (one shared MediaPlayer).
// ---------------------------------------------------------------

internal fun GroupChatActivity.onVoicePlayClicked(item: SimpleChatAdapter.Item) {
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
        return
    }
    loadAndPlayVoiceMessage(item, attachment, 0)
}

internal fun GroupChatActivity.onVoiceSeeked(item: SimpleChatAdapter.Item, positionMs: Int) {
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

internal fun GroupChatActivity.loadAndPlayVoiceMessage(item: SimpleChatAdapter.Item, attachment: SimpleChatAdapter.AttachmentInfo, startPositionMs: Int) {
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
                if (voicePlaybackSpeed != 1f && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
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

internal fun GroupChatActivity.onVoiceSpeedClicked(item: SimpleChatAdapter.Item) {
    val attachment = item.attachment ?: return
    val newSpeed = PlaybackSpeed.next(attachment.playbackSpeed)
    if (voicePlayingFileId == attachment.fileId) {
        voicePlaybackSpeed = newSpeed
        val player = voicePlayer
        if (player != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                // Setting the speed starts a paused player (documented): put it back.
                val wasPlaying = player.isPlaying
                player.playbackParams = PlaybackParams().setSpeed(newSpeed)
                if (!wasPlaying) player.pause()
            } catch (e: Exception) { /* bazı cihazlarda desteklenmeyen hız oranı olabilir */ }
        }
        adapter.updateVoicePlayback(attachment.fileId, player?.isPlaying ?: false, player?.currentPosition ?: 0, newSpeed)
    } else {
        attachment.playbackSpeed = newSpeed
        adapter.updateVoicePlayback(attachment.fileId, false, attachment.playbackPositionMs, newSpeed)
    }
}

internal fun GroupChatActivity.stopVoicePlayback() {
    voiceLoadRequest++
    val fileId = voicePlayingFileId
    voicePlaybackHandler.removeCallbacks(voicePlaybackTickRunnable)
    try {
        voicePlayer?.stop()
        voicePlayer?.release()
    } catch (e: Exception) { /* zaten serbest bırakılmış olabilir */ }
    voicePlayer = null
    voicePlayingFileId = null
    if (fileId != null) adapter.updateVoicePlayback(fileId, false, 0, voicePlaybackSpeed)
}
