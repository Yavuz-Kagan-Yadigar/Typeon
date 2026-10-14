package com.p2p.messenger.util

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.Image
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaRecorder
import android.os.Bundle
import android.util.Log
import android.view.Surface
import androidx.camera.core.ImageProxy
import com.p2p.messenger.P2PLib
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap

/**
 * Call media engine: capture + encode, decode + play per remote participant.
 * Transport and encryption live in Rust (`call.rs`); this side only moves
 * opaque frames:
 *  - send:    `P2PLib.callSend(kind, payload)`
 *  - receive: `P2PLib.callRecv()` -> `[kind][slot][payload]`
 *
 * Audio: 16 kHz mono Opus at 12 kbps, three 20 ms packets per frame (60 ms).
 * A Tor cell carries ~500 bytes; one ~30-byte packet per cell would waste most
 * of every cell. Transport is TCP (Tor), so nothing is ever lost, only late:
 * the jitter buffer pads with silence after an underrun and drops when a burst
 * piles up, instead of concealing losses.
 *
 * Video: hardware HEVC (H.264 fallback) up to 640x480, every encoder knob set
 * explicitly in [VideoTuning]: VBR, no B-frames, latency 1, QP clamp, long GOP
 * with keyframes on request, intra refresh where supported, and our own VRR —
 * a frame whose luma barely changed is not encoded at all. Frame rate and
 * bitrate follow the congestion signal from Rust (`callBacklog`).
 */
object CallMedia {
    const val KIND_AUDIO = 1
    const val KIND_VIDEO = 2
    /** `[flags]` bit 0 muted, bit 1 camera off — Rust `KIND_STATE`. */
    private const val KIND_STATE = 4
    private const val STATE_EVERY_MS = 1000L
    private const val TAG = "CallMedia"
    private const val SAMPLE_RATE = 16000
    private const val FRAME_SAMPLES = 320 // 20 ms
    private const val PACKETS_PER_FRAME = 3
    /** While the path queues: 120 ms per write, half the Tor cells (a cell is a
     *  fixed ~500 bytes, so lowering the Opus bitrate alone saves none). */
    private const val PACKETS_PER_FRAME_LOW = 6
    private const val AUDIO_BITRATE = 12000
    /** Used while the send queue stands (slow link); back to [AUDIO_BITRATE] once it is empty. */
    private const val AUDIO_BITRATE_LOW = 6000
    /** `callBacklog` (frames, 100 ms each when reported by the peer) to drop / to restore. */
    private const val AUDIO_LOW_AT = 4
    private const val AUDIO_HIGH_AT = 1
    /** Stay low at least this long: while audio is held the queue empties at once
     *  and an immediate climb back flapped 6/12 kbps every ~4 s. */
    private const val AUDIO_LOW_HOLD_MS = 10_000L
    /** Frames a decode lane may hold (~1 s of audio bundles or video). */
    private const val LANE_QUEUE = 24

    @Volatile var muted = false
    @Volatile private var running = false
    private var audioThread: Thread? = null
    private var recvThread: Thread? = null
    private val audioSinks = ConcurrentHashMap<Int, AudioSink>()
    private val videoSinks = ConcurrentHashMap<Int, VideoSink>()
    /** Decoder types that refused `KEY_LOW_LATENCY` once. */
    private val noLowLatency = java.util.Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())
    /** Set while a video call runs; fed by the camera analyzer. */
    @Volatile var videoEncoder: VideoEncoder? = null

    /** Each call's threads carry their own number: `running` alone let a
     *  thread that outlived `stop()` come back to life with the next call. */
    @Volatile private var generation = 0

    fun start(video: Boolean) {
        if (running) return
        val gen = ++generation
        running = true
        muted = false
        if (video) videoEncoder = VideoEncoder()
        audioThread = Thread({ captureLoop(gen) }, "call-audio-tx").apply { start() }
        recvThread = Thread({ receiveLoop(gen) }, "call-rx").apply { start() }
    }

    /** Called on the UI thread: everything is detached here, the waiting
     *  (up to 1.5 s per thread, 1 s per lane) happens on a thread of its own. */
    fun stop() {
        if (!running) return
        running = false
        val threads = listOfNotNull(audioThread, recvThread)
        audioThread = null
        recvThread = null
        val oldLanes = lanes.values.toList()
        lanes.clear()
        oldLanes.forEach { it.alive = false }
        val oldAudio = audioSinks.values.toList()
        audioSinks.clear()
        // Video sinks now: their Surface goes away with the screen.
        videoSinks.values.forEach { it.release() }
        videoSinks.clear()
        val encoder = videoEncoder
        videoEncoder = null
        encoder?.enabled = false
        Thread({
            threads.forEach { it.join(1500) }
            oldLanes.forEach { it.stop() }
            oldAudio.forEach { it.release() }
            encoder?.release()
        }, "call-stop").start()
    }

    /** Renders [slot]'s video into [surface]; [onSize] gets the displayed (rotated) size. */
    fun attachVideo(slot: Int, surface: Surface, onSize: (Int, Int) -> Unit) {
        Log.i(TAG, "attachVideo slot $slot")
        videoSinks.remove(slot)?.release()
        videoSinks[slot] = VideoSink(slot, surface, onSize)
    }

    /** True while [slot]'s audio is clearly above its own noise floor. */
    fun isSpeaking(slot: Int): Boolean =
        (audioSinks[slot]?.speakingUntil ?: 0L) > android.os.SystemClock.elapsedRealtime()

    fun dropSlot(slot: Int) {
        Log.i(TAG, "dropSlot $slot")
        // UI thread, see `stop`.
        val oldLanes = listOf(KIND_AUDIO, KIND_VIDEO).mapNotNull { lanes.remove(slot * 4 + it) }
        oldLanes.forEach { it.alive = false }
        val oldAudio = audioSinks.remove(slot)
        videoSinks.remove(slot)?.release()
        Thread({
            oldLanes.forEach { it.stop() }
            oldAudio?.release()
        }, "call-drop").start()
    }

    private fun captureLoop(gen: Int) {
        android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_AUDIO)
        // A recorder that stops delivering (audio server restart) is built
        // again; any other failure ends the capture as before.
        while (running && generation == gen && captureSession(gen)) Thread.sleep(500)
    }

    private class CaptureStalled(message: String) : Exception(message)

    /** @return true when the recorder died and a new session should start. */
    private fun captureSession(gen: Int): Boolean {
        var rec: AudioRecord? = null
        var enc: MediaCodec? = null
        try {
            val minBuf = AudioRecord.getMinBufferSize(SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
            rec = AudioRecord(
                MediaRecorder.AudioSource.VOICE_COMMUNICATION, SAMPLE_RATE,
                AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT,
                maxOf(minBuf, FRAME_SAMPLES * 2 * 8)
            )
            enc = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)
            val fmt = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, SAMPLE_RATE, 1).apply {
                setInteger(MediaFormat.KEY_BIT_RATE, AUDIO_BITRATE)
                setInteger(MediaFormat.KEY_COMPLEXITY, 10)
            }
            enc.configure(fmt, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            enc.start()
            rec.startRecording()
            val pcm = ByteArray(FRAME_SAMPLES * 2)
            val info = MediaCodec.BufferInfo()
            val bundle = ArrayList<ByteArray>(PACKETS_PER_FRAME)
            var pts = 0L
            var lastFlags = -1
            var stateAt = 0L
            var peak = 0
            var sentBundles = 0
            var logAt = System.currentTimeMillis()
            var bitrate = AUDIO_BITRATE
            var perFrame = PACKETS_PER_FRAME
            var rateAt = 0L
            var lowAt = 0L
            while (running && generation == gen) {
                val nowMs = System.currentTimeMillis()
                if (nowMs - rateAt >= 1000) {
                    rateAt = nowMs
                    val backlog = P2PLib.callBacklog()
                    if (backlog >= AUDIO_LOW_AT) lowAt = nowMs
                    val want = if (backlog >= AUDIO_LOW_AT) AUDIO_BITRATE_LOW
                        else if (backlog <= AUDIO_HIGH_AT && nowMs - lowAt >= AUDIO_LOW_HOLD_MS) AUDIO_BITRATE
                        else bitrate
                    if (want != bitrate) {
                        bitrate = want
                        perFrame = if (want == AUDIO_BITRATE_LOW) PACKETS_PER_FRAME_LOW else PACKETS_PER_FRAME
                        Log.i(TAG, "audio bitrate $bitrate (backlog $backlog)")
                        enc.setParameters(Bundle().apply { putInt(MediaFormat.KEY_BIT_RATE, bitrate) })
                    }
                }
                val flags = (if (muted) 1 else 0) or (if (videoEncoder?.enabled == false) 2 else 0)
                if (flags != lastFlags || nowMs - stateAt >= STATE_EVERY_MS) {
                    P2PLib.callSend(KIND_STATE, byteArrayOf(flags.toByte()))
                    lastFlags = flags
                    stateAt = nowMs
                }
                if (nowMs - logAt >= 5000) {
                    Log.i(TAG, "audio tx: $sentBundles bundles/5s, peak ${dbfs(peak)} dBFS, muted=$muted")
                    peak = 0; sentBundles = 0; logAt = nowMs
                }
                var read = 0
                var dry = 0
                while (read < pcm.size && running) {
                    val n = rec.read(pcm, read, pcm.size - read)
                    if (n > 0) { read += n; dry = 0; continue }
                    // It used to spin here 100 times a second until the call
                    // ended, silent and without a log line.
                    if (++dry > 100) throw CaptureStalled("AudioRecord.read = $n")
                    Thread.sleep(10)
                }
                if (read < pcm.size) continue
                peak = maxOf(peak, peakOf(pcm))
                val inIdx = enc.dequeueInputBuffer(10_000)
                if (inIdx >= 0) {
                    enc.getInputBuffer(inIdx)!!.apply { clear(); put(pcm) }
                    enc.queueInputBuffer(inIdx, 0, pcm.size, pts, 0)
                    pts += 20_000
                }
                while (true) {
                    val outIdx = enc.dequeueOutputBuffer(info, 0)
                    if (outIdx == MediaCodec.INFO_TRY_AGAIN_LATER) break
                    if (outIdx < 0) continue
                    if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG == 0 && info.size > 0) {
                        val b = ByteArray(info.size)
                        enc.getOutputBuffer(outIdx)!!.apply { position(info.offset); get(b) }
                        bundle.add(b)
                    }
                    enc.releaseOutputBuffer(outIdx, false)
                    if (bundle.size >= perFrame) {
                        if (!muted && P2PLib.callSend(KIND_AUDIO, packBundle(bundle))) sentBundles++
                        bundle.clear()
                    }
                }
            }
        } catch (e: CaptureStalled) {
            Log.w(TAG, "Audio capture stalled, restarting", e)
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Audio capture failed", e)
        } finally {
            try { rec?.stop() } catch (_: Exception) {}
            rec?.release()
            try { enc?.stop() } catch (_: Exception) {}
            enc?.release()
        }
        return false
    }

    /**
     * Only demultiplexes: every (participant, kind) gets its own decode lane
     * and thread. One shared decode thread let a codec that is slow to answer
     * (Codec2 calls wait on the codec's looper: up to 0.5 s each on the Note
     * 9S in a 3-way video call) starve every other participant's audio.
     */
    private fun receiveLoop(gen: Int) {
        while (running && generation == gen) {
            val f = P2PLib.callRecv(200) ?: continue
            if (f.size < 3) continue
            val kind = f[0].toInt()
            val slot = f[1].toInt() and 0xff
            if (kind != KIND_AUDIO && kind != KIND_VIDEO) continue
            val lane = lanes.getOrPut(slot * 4 + kind) { Lane(slot, kind) }
            if (!lane.queue.offer(f)) {
                // Lane behind: shed the oldest; a video hole needs a keyframe.
                lane.queue.poll()
                lane.queue.offer(f)
                if (kind == KIND_VIDEO) P2PLib.callRequestKeyframe(slot)
            }
        }
    }

    private val lanes = ConcurrentHashMap<Int, Lane>()

    private class Lane(val slot: Int, val kind: Int) {
        val queue = java.util.concurrent.ArrayBlockingQueue<ByteArray>(LANE_QUEUE)
        @Volatile var alive = true
        private val thread = Thread({
            android.os.Process.setThreadPriority(
                if (kind == KIND_AUDIO) android.os.Process.THREAD_PRIORITY_URGENT_AUDIO
                else android.os.Process.THREAD_PRIORITY_DISPLAY
            )
            while (alive && running) {
                val f = queue.poll(200, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
                decode(f)
            }
        }, "call-rx-$kind-$slot").apply { start() }

        private var audioRetryAt = 0L

        private fun decode(f: ByteArray) {
            if (!alive) return
            when (kind) {
                KIND_AUDIO -> try {
                    // Not on every 60 ms packet after a failure.
                    if (android.os.SystemClock.elapsedRealtime() < audioRetryAt) return
                    audioSinks.getOrPut(slot) { AudioSink() }.feed(f, 2)
                } catch (e: Exception) {
                    Log.w(TAG, "Audio decode failed (slot $slot), resetting", e)
                    audioSinks.remove(slot)?.release()
                    audioRetryAt = android.os.SystemClock.elapsedRealtime() + 2_000
                }
                KIND_VIDEO -> try {
                    videoSinks[slot]?.feed(f, 2)
                } catch (e: Exception) {
                    Log.w(TAG, "Video decode failed (slot $slot), waiting for next keyframe", e)
                    videoSinks[slot]?.resync()
                }
            }
        }

        fun stop() {
            alive = false
            thread.join(1000)
        }
    }

    /** Largest |sample| of 16-bit little-endian PCM. */
    private fun peakOf(pcm: ByteArray, len: Int = pcm.size): Int {
        var p = 0
        var i = 0
        while (i + 1 < len) {
            val v = ((pcm[i + 1].toInt() shl 8) or (pcm[i].toInt() and 0xff)).toShort().toInt()
            if (v > p) p = v else if (-v > p) p = -v
            i += 2
        }
        return p
    }

    private fun dbfs(peak: Int): Int =
        if (peak <= 0) -99 else (20 * kotlin.math.log10(peak / 32768.0)).toInt()

    /** `[n][len u16]*n [packet]*n` */
    private fun packBundle(packets: List<ByteArray>): ByteArray {
        val out = ByteBuffer.allocate(1 + packets.size * 2 + packets.sumOf { it.size })
        out.put(packets.size.toByte())
        packets.forEach { out.putShort(it.size.toShort()) }
        packets.forEach { out.put(it) }
        return out.array()
    }

    private fun unpackBundle(b: ByteArray, off: Int): List<ByteArray> {
        val n = b[off].toInt() and 0xff
        var pos = off + 1 + n * 2
        val out = ArrayList<ByteArray>(n)
        for (i in 0 until n) {
            val lenAt = off + 1 + i * 2
            if (lenAt + 1 >= b.size) break
            val len = ((b[lenAt].toInt() and 0xff) shl 8) or (b[lenAt + 1].toInt() and 0xff)
            if (pos + len > b.size) break
            out.add(b.copyOfRange(pos, pos + len))
            pos += len
        }
        return out
    }

    private class AudioSink {
        private val dec = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)
        private val info = MediaCodec.BufferInfo()
        private var track: AudioTrack? = null
        private var outRate = 48000
        private var outChannels = 1
        private var written = 0L
        private var pts = 0L
        private var underruns = 0
        private var lastUnderrunAt = 0L
        /** Since when [buffered] stands above [CATCHUP_MS]; 0 = not. */
        private var overSince = 0L
        private var catchupTick = 0
        private var statPackets = 0
        private var statPeak = 0
        private var statOverflow = 0
        private var statAt = System.currentTimeMillis()
        /** Noise floor (peak units) and last time the level stood clear of it. */
        private var noise = 400f
        @Volatile var speakingUntil = 0L

        /** SNR proxy, ~50 ops per 20 ms frame: strided peak against a
         *  min-tracking noise floor. Speaking = >= ~10 dB over the floor and
         *  above an absolute minimum; held 400 ms so the frame does not flicker. */
        private fun trackLevel(pcm: ByteArray) {
            var p = 0
            var i = 0
            while (i + 1 < pcm.size) { // every 16th sample
                val v = ((pcm[i + 1].toInt() shl 8) or (pcm[i].toInt() and 0xff)).toShort().toInt()
                val a = if (v < 0) -v else v
                if (a > p) p = a
                i += 32
            }
            noise = if (p < noise) p.toFloat().coerceAtLeast(60f) else noise + (p - noise) * 0.002f
            if (p > 1500 && p > noise * 3.2f) speakingUntil = android.os.SystemClock.elapsedRealtime() + 400
        }

        init {
            val fmt = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, 48000, 1).apply {
                setByteBuffer("csd-0", ByteBuffer.wrap(opusHead()))
                setByteBuffer("csd-1", nativeLong(0))
                setByteBuffer("csd-2", nativeLong(80_000_000))
            }
            try {
                dec.configure(fmt, null, null, 0)
                dec.start()
            } catch (e: Exception) {
                dec.release()
                throw e
            }
        }

        fun feed(frame: ByteArray, off: Int) {
            for (pkt in unpackBundle(frame, off)) {
                drain()
                val i = dec.dequeueInputBuffer(2_000)
                if (i >= 0) {
                    dec.getInputBuffer(i)!!.apply { clear(); put(pkt) }
                    dec.queueInputBuffer(i, 0, pkt.size, pts, 0)
                    pts += 20_000
                }
                drain()
            }
        }

        private fun drain() {
            while (true) {
                val o = dec.dequeueOutputBuffer(info, 0)
                when {
                    o == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                        outRate = dec.outputFormat.getInteger(MediaFormat.KEY_SAMPLE_RATE)
                        outChannels = dec.outputFormat.getInteger(MediaFormat.KEY_CHANNEL_COUNT)
                        track?.release()
                        track = null
                        written = 0
                    }
                    o == MediaCodec.INFO_TRY_AGAIN_LATER -> return
                    o < 0 -> {}
                    else -> {
                        if (info.size > 0) {
                            val pcm = ByteArray(info.size)
                            dec.getOutputBuffer(o)!!.apply { position(info.offset); get(pcm) }
                            play(pcm)
                        }
                        dec.releaseOutputBuffer(o, false)
                    }
                }
            }
        }

        /** Jitter buffer on top of AudioTrack's own buffer: after an underrun
         *  pad with silence (more after each one), and drop output when a
         *  network burst has queued more than [MAX_BUFFER_MS]. */
        private fun play(pcm: ByteArray) {
            val t = track ?: newTrack().also { track = it; written = 0 }
            val frameBytes = 2 * outChannels
            val buffered = written - (t.playbackHeadPosition.toLong() and 0xffffffffL)
            statPackets++
            trackLevel(pcm)
            statPeak = maxOf(statPeak, peakOf(pcm))
            val now = System.currentTimeMillis()
            if (now - statAt >= 5000) {
                Log.i(TAG, "audio rx: $statPackets pkts/5s, peak ${dbfs(statPeak)} dBFS, buffered ${buffered * 1000 / outRate} ms, " +
                    "underruns $underruns, overflow drops $statOverflow, track state ${t.playState} rate $outRate ch $outChannels ")
                statPackets = 0; statPeak = 0; statOverflow = 0; statAt = now
            }
            val nowMs = android.os.SystemClock.elapsedRealtime()
            // Sit on a low target: a standing buffer above CATCHUP_MS for
            // CATCHUP_AFTER_MS plays 25 % fast (every 4th packet skipped).
            if (buffered > outRate.toLong() * CATCHUP_MS / 1000) {
                if (overSince == 0L) overSince = nowMs
                if (nowMs - overSince >= CATCHUP_AFTER_MS && ++catchupTick % 4 == 0) { statOverflow++; return }
            } else overSince = 0
            if (buffered <= 0) {
                if (nowMs - lastUnderrunAt > UNDERRUN_FORGET_MS) underruns = 0
                val padMs = (PAD_BASE_MS + PAD_STEP_MS * minOf(underruns, 3)) // <= 200 ms, under the cap
                if (written > 0) { underruns++; lastUnderrunAt = nowMs }
                val pad = ByteArray(outRate * padMs / 1000 * frameBytes)
                written += t.write(pad, 0, pad.size, AudioTrack.WRITE_NON_BLOCKING).coerceAtLeast(0) / frameBytes
            } else if (android.os.Build.VERSION.SDK_INT >= 31 && buffered > outRate.toLong() * MAX_BUFFER_MS / 1000) {
                // Skip ahead: drop what is queued (stale), keep this packet.
                // Dropping the newest left the stale audio playing.
                statOverflow++
                try { t.pause(); t.flush(); t.play() } catch (_: Exception) {}
                written = 0
                overSince = 0
            }
            val n = t.write(pcm, 0, pcm.size, AudioTrack.WRITE_NON_BLOCKING)
            if (n < 0) {
                // ERROR_DEAD_OBJECT and friends: the track is gone, the next
                // packet builds a new one. Adding the code to `written` only
                // skewed the jitter maths and left this participant silent.
                Log.w(TAG, "AudioTrack write failed ($n), recreating")
                t.release()
                track = null
                return
            }
            written += n / frameBytes
        }

        private fun newTrack(): AudioTrack = AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build()
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setSampleRate(outRate)
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setChannelMask(if (outChannels == 2) AudioFormat.CHANNEL_OUT_STEREO else AudioFormat.CHANNEL_OUT_MONO)
                    .build()
            )
            .setBufferSizeInBytes(
                outRate * 2 * outChannels *
                    (if (android.os.Build.VERSION.SDK_INT >= 31) BUFFER_MS else LEGACY_BUFFER_MS) / 1000
            )
            .setTransferMode(AudioTrack.MODE_STREAM)
            .build()
            .also {
                // A stream track only starts once this much is queued, and
                // the default is the WHOLE buffer — while the jitter cap
                // above stops writing below that: the track never started and
                // every packet was dropped (measured: 100 % "overflow" drops,
                // total silence). Below API 31 the cap is off instead and a
                // full buffer just makes the non-blocking write come up short.
                if (android.os.Build.VERSION.SDK_INT >= 31) it.setStartThresholdInFrames(outRate * START_MS / 1000)
                it.play()
            }

        fun release() {
            try { track?.stop() } catch (_: Exception) {}
            track?.release()
            try { dec.stop() } catch (_: Exception) {}
            dec.release()
        }

        companion object {
            const val PAD_BASE_MS = 80
            const val PAD_STEP_MS = 40
            /** AudioTrack buffer, start threshold, and jitter cap (API 31+). */
            const val BUFFER_MS = 800
            /** Below API 31 there is no start threshold: the track starts
             *  when its WHOLE buffer is full, so the buffer size is the added
             *  delay (0.8 s with [BUFFER_MS]). Not measured on a device:
             *  raise it if audio breaks up on LTE bursts there. */
            const val LEGACY_BUFFER_MS = 300
            const val START_MS = 60
            const val MAX_BUFFER_MS = 600 // LTE+Tor delivers audio in ~1 s bursts
            const val CATCHUP_MS = 250
            const val CATCHUP_AFTER_MS = 2_000L
            const val UNDERRUN_FORGET_MS = 10_000L

            /** RFC 7845 identification header, mono, 16 kHz input. */
            fun opusHead(): ByteArray = ByteBuffer.allocate(19).order(ByteOrder.LITTLE_ENDIAN).apply {
                put("OpusHead".toByteArray())
                put(1) // version
                put(1) // channels
                putShort(0) // pre-skip
                putInt(SAMPLE_RATE)
                putShort(0) // gain
                put(0) // mapping family
            }.array()

            fun nativeLong(v: Long): ByteBuffer =
                ByteBuffer.allocate(8).order(ByteOrder.nativeOrder()).putLong(v).apply { flip() }
        }
    }

    /**
     * Every encoder knob, set explicitly. Vendor defaults are tuned for
     * recording a video file (B-frames, 1 s keyframes, look-ahead, full QP
     * range, constant frame rate), which is the wrong trade for a call over Tor.
     */
    object VideoTuning {
        /** HEVC first (~30-40 % fewer bits than H.264 at equal quality, hardware
         *  on all three test phones); H.264 only if no hardware HEVC encoder.
         *  AV1 is decode-only in hardware on these phones — a software AV1
         *  encoder at 24 fps would burn the CPU and add latency. */
        val MIME_PREFERENCE = listOf(MediaFormat.MIMETYPE_VIDEO_HEVC, MediaFormat.MIMETYPE_VIDEO_AVC)
        const val MAX_FPS = 24
        const val MIN_FPS = 4
        /** Bitrates for HEVC; H.264 gets [AVC_BITRATE_FACTOR]x. */
        const val START_BITRATE = 180_000
        const val MIN_BITRATE = 40_000
        const val MAX_BITRATE = 320_000
        const val AVC_BITRATE_FACTOR = 1.4
        /** Long GOP: receivers ask for a keyframe (report flag) when they lose
         *  sync, so we do not pay for one every 2 s "just in case". */
        const val KEYFRAME_INTERVAL_S = 10
        /** Where supported, spread intra refresh over this many frames instead
         *  of one big keyframe burst (which stalls a Tor stream). */
        const val INTRA_REFRESH_FRAMES = 48
        /** Minimum gap between keyframes sent on request. */
        const val KEYFRAME_MIN_GAP_MS = 2000L
        /** QP clamp (HEVC/H.264 0..51). Min 22: finer quantisation is invisible
         *  at 480p on a phone and only costs bits. Max 44: coarser turns faces
         *  into mush; drop frames (below) instead. */
        const val QP_MIN = 22
        const val QP_MAX = 44
        /** VRR: mean |ΔY| over a 1/64 luma sample grid, against the last SENT
         *  frame, below this = nothing moved, the frame is not encoded at all.
         *  0-255 scale; 1.5 ignores sensor noise, catches a blink. */
        const val CHANGE_THRESHOLD = 1.5
        /** ...but never longer than this without a frame, so a still scene
         *  still shows up to date (and the encoder's rate control keeps ticking). */
        const val MAX_STILL_MS = 1000L
        /** Luma sampling step for the change detector (every Nth pixel and row). */
        const val SAMPLE_STEP = 8
        /** Congestion control, in units of `callBacklog` (100 ms of queue):
         *  decide every ADAPT_MS, halve bitrate above CUT_AT, pause video at
         *  PAUSE_AT and resume at RESUME_AT. */
        const val ADAPT_MS = 500L
        const val CUT_AT = 4
        const val PAUSE_AT = 15
        const val RESUME_AT = 3
    }

    /** Camera frames (CameraX `ImageAnalysis`) -> HEVC/H.264 -> `callSend`. */
    class VideoEncoder {
        private var codec: MediaCodec? = null
        private var hevc = false
        private var width = 0
        private var height = 0
        private var csd: ByteArray? = null
        private var bitrate = VideoTuning.START_BITRATE
        private var fps = VideoTuning.MAX_FPS
        private var lastFrameNs = 0L
        private var lastAdaptMs = 0L
        private var lastKeyNs = 0L
        private var prevLuma: ByteArray? = null
        private var stillSkips = 0
        private val info = MediaCodec.BufferInfo()
        @Volatile var enabled = true
        /** Congestion pause, see [adapt]. */
        private var paused = false
        /** The encoder could not be created: do not retry on every frame. */
        private var failed = false
        /** A keyframe was asked for inside the minimum gap: send it when the gap ends. */
        private var keyPending = false

        /** Called on the analyzer thread; the caller closes [image]. */
        @Synchronized
        fun encode(image: ImageProxy) {
            if (!enabled || failed) return
            adapt()
            if (paused) return
            val now = System.nanoTime()
            if (now - lastFrameNs < 1_000_000_000L / fps) return
            val c = codec ?: create(image.width, image.height)
            if (image.width != width || image.height != height) { release(); return }
            // At most one on-demand keyframe per KEYFRAME_MIN_GAP_MS: a
            // receiver stuck in a decode loop must not turn the stream into
            // all-keyframes (seen: ~2 Mbps).
            if (P2PLib.callTakeKeyframeRequest()) keyPending = true
            val keyAsked = keyPending && now - lastKeyNs > VideoTuning.KEYFRAME_MIN_GAP_MS * 1_000_000
            if (keyAsked) {
                keyPending = false
                lastKeyNs = now
                c.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_REQUEST_SYNC_FRAME, 0) })
            }
            // VRR: skip frames that did not change enough.
            val luma = sampleLuma(image)
            val stillFor = (now - lastFrameNs) / 1_000_000
            val prev = prevLuma
            if (!keyAsked && prev != null && stillFor < VideoTuning.MAX_STILL_MS &&
                meanAbsDiff(prev, luma) < VideoTuning.CHANGE_THRESHOLD) {
                stillSkips++
                return
            }
            prevLuma = luma
            lastFrameNs = now
            val rotation = image.imageInfo.rotationDegrees
            val idx = c.dequeueInputBuffer(0)
            if (idx >= 0) {
                val dst = c.getInputImage(idx)
                if (dst != null) {
                    copyYuv(image, dst)
                    c.queueInputBuffer(idx, 0, width * height * 3 / 2, now / 1000, 0)
                } else {
                    c.queueInputBuffer(idx, 0, 0, now / 1000, 0)
                }
            }
            drain(c, rotation)
        }

        private fun pickEncoder(w: Int, h: Int): Pair<String, String?> {
            val infos = android.media.MediaCodecList(android.media.MediaCodecList.REGULAR_CODECS).codecInfos
            for (mime in VideoTuning.MIME_PREFERENCE) {
                val hw = infos.firstOrNull { ci ->
                    ci.isEncoder && ci.supportedTypes.any { it.equals(mime, true) } &&
                        !ci.name.startsWith("c2.android.") && !ci.name.startsWith("OMX.google.") &&
                        !ci.name.contains("secure") && !ci.name.endsWith(".cq") &&
                        (android.os.Build.VERSION.SDK_INT < 29 || ci.isHardwareAccelerated) &&
                        ci.getCapabilitiesForType(mime).videoCapabilities.isSizeSupported(w, h)
                }
                if (hw != null) return mime to hw.name
            }
            return MediaFormat.MIMETYPE_VIDEO_AVC to null
        }

        private fun create(w: Int, h: Int): MediaCodec {
            width = w
            height = h
            val (mime, name) = pickEncoder(w, h)
            hevc = mime == MediaFormat.MIMETYPE_VIDEO_HEVC
            if (!hevc) bitrate = (VideoTuning.START_BITRATE * VideoTuning.AVC_BITRATE_FACTOR).toInt()
            val c = if (name != null) MediaCodec.createByCodecName(name) else MediaCodec.createEncoderByType(mime)
            try {
                configureAndStart(c, mime, w, h)
            } catch (e: Exception) {
                c.release()
                failed = true
                throw e
            }
            codec = c
            Log.i(TAG, "Video encoder ${c.name} $mime ${w}x$h accepted=${c.outputFormat}")
            return c
        }

        private fun configureAndStart(c: MediaCodec, mime: String, w: Int, h: Int) {
            val caps = c.codecInfo.getCapabilitiesForType(mime)
            val enc = caps.encoderCapabilities
            // A function, not `MediaFormat(base)`: the copy constructor is API 29+
            // and killed the process on the first camera frame on Android 8-9.
            fun baseFormat() = MediaFormat.createVideoFormat(mime, w, h).apply {
                setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible)
                setInteger(MediaFormat.KEY_BIT_RATE, bitrate)
                // VBR: a still scene may cost almost nothing; CBR would pad it.
                setInteger(MediaFormat.KEY_BITRATE_MODE,
                    if (enc.isBitrateModeSupported(MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR))
                        MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR
                    else MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR)
                setInteger(MediaFormat.KEY_FRAME_RATE, VideoTuning.MAX_FPS)
                setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, VideoTuning.KEYFRAME_INTERVAL_S)
            }
            val base = baseFormat()
            val tuned = baseFormat().apply {
                setInteger(MediaFormat.KEY_OPERATING_RATE, VideoTuning.MAX_FPS)
                setInteger(MediaFormat.KEY_PRIORITY, 0) // real time
                setInteger(MediaFormat.KEY_MAX_B_FRAMES, 0)
                setInteger(MediaFormat.KEY_PREPEND_HEADER_TO_SYNC_FRAMES, 1)
                if (android.os.Build.VERSION.SDK_INT >= 30) setInteger(MediaFormat.KEY_LATENCY, 1)
                if (android.os.Build.VERSION.SDK_INT >= 31) {
                    setInteger(MediaFormat.KEY_VIDEO_QP_MIN, VideoTuning.QP_MIN)
                    setInteger(MediaFormat.KEY_VIDEO_QP_MAX, VideoTuning.QP_MAX)
                }
                if (caps.isFeatureSupported(MediaCodecInfo.CodecCapabilities.FEATURE_IntraRefresh)) {
                    setInteger(MediaFormat.KEY_INTRA_REFRESH_PERIOD, VideoTuning.INTRA_REFRESH_FRAMES)
                }
                val profile = if (hevc) MediaCodecInfo.CodecProfileLevel.HEVCProfileMain
                    else MediaCodecInfo.CodecProfileLevel.AVCProfileHigh
                if (caps.profileLevels.any { it.profile == profile }) setInteger(MediaFormat.KEY_PROFILE, profile)
                setInteger(MediaFormat.KEY_COLOR_RANGE, MediaFormat.COLOR_RANGE_LIMITED)
                setInteger(MediaFormat.KEY_COLOR_STANDARD, MediaFormat.COLOR_STANDARD_BT601_NTSC)
                setInteger(MediaFormat.KEY_COLOR_TRANSFER, MediaFormat.COLOR_TRANSFER_SDR_VIDEO)
            }
            try {
                c.configure(tuned, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            } catch (e: Exception) {
                // An encoder that rejects one of the extras still gets the essentials.
                Log.w(TAG, "Encoder rejected tuned format, using base: ${e.message}")
                c.reset()
                c.configure(base, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            }
            c.start()
        }

        private fun drain(c: MediaCodec, rotation: Int) {
            while (true) {
                val o = c.dequeueOutputBuffer(info, 0)
                if (o == MediaCodec.INFO_TRY_AGAIN_LATER) return
                if (o < 0) continue
                val buf = c.getOutputBuffer(o)!!.apply { position(info.offset); limit(info.offset + info.size) }
                val flags = info.flags
                if (flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0) {
                    csd = ByteArray(info.size).also { buf.get(it) }
                    c.releaseOutputBuffer(o, false)
                    continue
                }
                if (info.size == 0) { c.releaseOutputBuffer(o, false); continue }
                val key = flags and MediaCodec.BUFFER_FLAG_KEY_FRAME != 0
                // Headers are prepended by the encoder too (PREPEND_HEADER...);
                // repeating them is harmless where it is not.
                val head = if (key) csd else null
                // Straight from the codec buffer into the packet.
                val out = ByteBuffer.allocate(6 + (head?.size ?: 0) + info.size)
                    .put(((if (key) 1 else 0) or (if (hevc) 2 else 0)).toByte())
                    .put((rotation / 90).toByte())
                    .putShort(width.toShort())
                    .putShort(height.toShort())
                head?.let { out.put(it) }
                out.put(buf)
                c.releaseOutputBuffer(o, false)
                P2PLib.callSend(KIND_VIDEO, out.array())
            }
        }

        /** Every [VideoTuning.ADAPT_MS]: back off hard when the path queues,
         *  pause video outright when it is seconds deep (audio keeps flowing
         *  and the queue drains), creep back up when it is empty. */
        private fun adapt() {
            val nowMs = System.currentTimeMillis()
            if (nowMs - lastAdaptMs < VideoTuning.ADAPT_MS) return
            lastAdaptMs = nowMs
            val f = if (hevc) 1.0 else VideoTuning.AVC_BITRATE_FACTOR
            val min = (VideoTuning.MIN_BITRATE * f).toInt()
            val max = (VideoTuning.MAX_BITRATE * f).toInt()
            val backlog = P2PLib.callBacklog() // 1 = 100 ms of queue
            val before = bitrate
            if (backlog >= VideoTuning.PAUSE_AT) paused = true
            else if (backlog <= VideoTuning.RESUME_AT) paused = false
            if (backlog > VideoTuning.CUT_AT) {
                bitrate = maxOf(min, bitrate / 2)
                fps = maxOf(VideoTuning.MIN_FPS, fps - 6)
            } else if (backlog <= 1) {
                bitrate = minOf(max, bitrate + (25_000 * f).toInt())
                fps = minOf(VideoTuning.MAX_FPS, fps + 1)
            }
            if (bitrate != before) {
                codec?.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_VIDEO_BITRATE, bitrate) })
            }
            if (stillSkips > 0 || paused) Log.d(TAG, "VRR: skipped $stillSkips still frames, bitrate=$bitrate fps<=$fps paused=$paused backlog=$backlog")
            stillSkips = 0
        }

        @Synchronized
        fun release() {
            codec?.let {
                try { it.stop() } catch (_: Exception) {}
                it.release()
            }
            codec = null
            csd = null
            prevLuma = null
        }

        companion object {
            private fun sampleLuma(src: ImageProxy): ByteArray {
                val p = src.planes[0]
                val b = p.buffer
                val step = VideoTuning.SAMPLE_STEP
                val cols = src.width / step
                val rows = src.height / step
                val out = ByteArray(cols * rows)
                var i = 0
                for (y in 0 until rows) {
                    val ro = y * step * p.rowStride
                    for (x in 0 until cols) out[i++] = b.get(ro + x * step * p.pixelStride)
                }
                return out
            }

            private fun meanAbsDiff(a: ByteArray, b: ByteArray): Double {
                if (a.size != b.size || a.isEmpty()) return Double.MAX_VALUE
                var sum = 0L
                for (i in a.indices) sum += kotlin.math.abs((a[i].toInt() and 0xff) - (b[i].toInt() and 0xff))
                return sum.toDouble() / a.size
            }

            /** YUV_420_888 -> the codec's flexible YUV input image, any strides. */
            fun copyYuv(src: ImageProxy, dst: Image) {
                val w = src.width
                val h = src.height
                for (p in 0 until 3) {
                    val sp = src.planes[p]
                    val dp = dst.planes[p]
                    val pw = if (p == 0) w else w / 2
                    val ph = if (p == 0) h else h / 2
                    val sb = sp.buffer
                    val db = dp.buffer
                    val sps = sp.pixelStride
                    val dps = dp.pixelStride
                    val srs = sp.rowStride
                    val drs = dp.rowStride
                    if (sps == 1 && dps == 1) {
                        val row = ByteArray(pw)
                        for (y in 0 until ph) {
                            sb.position(y * srs); sb.get(row, 0, pw)
                            db.position(y * drs); db.put(row, 0, pw)
                        }
                    } else {
                        // Interleaved chroma: one bulk read per row on each side,
                        // the per-pixel work on plain arrays (per-element
                        // ByteBuffer calls cost a core on the Note 9S). The dst
                        // row is read first so the other plane's interleaved
                        // bytes survive.
                        val sLen = (pw - 1) * sps + 1
                        val dLen = (pw - 1) * dps + 1
                        val sRow = ByteArray(sLen)
                        val dRow = ByteArray(dLen)
                        for (y in 0 until ph) {
                            sb.position(y * srs); sb.get(sRow, 0, sLen)
                            db.position(y * drs); db.get(dRow, 0, dLen)
                            var si = 0
                            var di = 0
                            for (x in 0 until pw) { dRow[di] = sRow[si]; si += sps; di += dps }
                            db.position(y * drs); db.put(dRow, 0, dLen)
                        }
                    }
                }
            }
        }
    }

    /** HEVC/H.264 -> [surface]. Waits for a keyframe (headers inline), asking
     *  the sender for one when it has to wait. */
    private class VideoSink(private val slot: Int, private val surface: Surface, private val onSize: (Int, Int) -> Unit) {
        private var codec: MediaCodec? = null
        private var mime = ""
        private var w = 0
        private var h = 0
        private var rot = 0
        private var pts = 0L
        private var askedAt = 0L
        private var createdAt = -1000L
        private val info = MediaCodec.BufferInfo()

        /** feed() runs on the receive thread, release() on the UI thread. */
        @Synchronized
        fun feed(f: ByteArray, off: Int) {
            if (released || f.size < off + 7) return
            val flags = f[off].toInt()
            val key = flags and 1 != 0
            val m = if (flags and 2 != 0) MediaFormat.MIMETYPE_VIDEO_HEVC else MediaFormat.MIMETYPE_VIDEO_AVC
            val r = (f[off + 1].toInt() and 3) * 90
            val fw = ((f[off + 2].toInt() and 0xff) shl 8) or (f[off + 3].toInt() and 0xff)
            val fh = ((f[off + 4].toInt() and 0xff) shl 8) or (f[off + 5].toInt() and 0xff)
            // The header is the peer's: no vendor decoder is asked for 65535x65535.
            if (fw !in 16..4096 || fh !in 16..4096) return
            if (codec == null || fw != w || fh != h || r != rot || m != mime) {
                if (!key) { askKeyframe(); return }
                // One new decoder a second per slot, whatever the peer's
                // keyframes claim: alternating sizes used to churn hardware
                // decoders at frame rate.
                val now = android.os.SystemClock.elapsedRealtime()
                if (now - createdAt < 1000) return
                createdAt = now
                reset()
                w = fw; h = fh; rot = r; mime = m
                val fmt = MediaFormat.createVideoFormat(mime, w, h).apply {
                    setInteger(MediaFormat.KEY_ROTATION, rot)
                    setInteger(MediaFormat.KEY_PRIORITY, 0)
                }
                // Output each frame as soon as it is decoded instead of holding a
                // reorder window (we never send B-frames). Some vendor decoders
                // (Spreadtrum on the Tab, MTK OMX on the Note 8) reject it, and
                // a rejected instance is unusable even after reset(): start a
                // fresh one and never ask that decoder type again.
                val c = if (android.os.Build.VERSION.SDK_INT >= 30 && mime !in noLowLatency) {
                    try {
                        newDecoder(MediaFormat(fmt).apply { setInteger(MediaFormat.KEY_LOW_LATENCY, 1) })
                    } catch (e: Exception) {
                        // Marked only when the plain format works: a bad size
                        // from the peer or a dead Surface fails both, and used
                        // to switch low latency off for every later call.
                        newDecoder(fmt).also { noLowLatency.add(mime) }
                    }
                } else newDecoder(fmt)
                codec = c
                Log.i(TAG, "Video decoder ${c.name} $mime ${w}x$h (slot $slot)")
                if (rot % 180 == 0) onSize(w, h) else onSize(h, w)
            }
            val c = codec ?: return
            val len = f.size - off - 6
            render(c)
            // Never block the shared receive thread on one decoder: audio and
            // the other participants' video queue up behind it.
            val i = c.dequeueInputBuffer(2_000)
            if (i >= 0) {
                c.getInputBuffer(i)!!.apply { clear(); put(f, off + 6, len) }
                c.queueInputBuffer(i, 0, len, pts, 0)
                pts += 41_000
            }
            render(c)
        }

        private fun newDecoder(fmt: MediaFormat): MediaCodec {
            val c = MediaCodec.createDecoderByType(fmt.getString(MediaFormat.KEY_MIME)!!)
            try {
                c.configure(fmt, surface, null, 0)
                c.start()
            } catch (e: Exception) {
                c.release()
                throw e
            }
            return c
        }

        private fun askKeyframe() {
            val now = System.currentTimeMillis()
            if (now - askedAt < 1000) return
            askedAt = now
            P2PLib.callRequestKeyframe(slot)
        }

        private fun render(c: MediaCodec) {
            while (true) {
                val o = c.dequeueOutputBuffer(info, 0)
                if (o == MediaCodec.INFO_TRY_AGAIN_LATER) break
                if (o >= 0) c.releaseOutputBuffer(o, true)
            }
        }

        fun reset() {
            codec?.let {
                try { it.stop() } catch (_: Exception) {}
                it.release()
            }
            codec = null
            w = 0
        }

        /** After a decode error: start over from the next keyframe. */
        @Synchronized
        fun resync() {
            reset()
            askKeyframe()
        }

        private var released = false

        @Synchronized
        fun release() {
            released = true
            reset()
        }
    }
}
