//! Call media engine — the desktop twin of Android `CallMedia.kt`.
//!
//! Transport and encryption live in the core (`call.rs`); this side only moves
//! opaque frames through `core::call_send` / `core::call_recv`, in exactly the
//! formats the phones use:
//!
//!  - audio (kind 1): `[n][len u16 BE]*n [opus packet]*n`, three 20 ms packets of
//!    16 kHz mono Opus at 12 kbps per bundle (one Tor cell instead of three);
//!  - video (kind 2): `[flags: bit0 key, bit1 hevc][rotation/90][w u16][h u16]`
//!    followed by an Annex-B access unit, parameter sets inline on keyframes;
//!  - state (kind 4): `[flags: bit0 muted, bit1 camera off]`, once a second.
//!
//! Everything media-shaped is GStreamer, which the GNOME runtime ships complete:
//! Opus, VA-API HEVC/H.264 encoders, libav/VA decoders, v4l2 camera, PulseAudio
//! and WebRTC echo cancellation.
//!
//! The encoder is tuned the way `VideoTuning` tunes the phones' — VBR, no
//! B-frames, long GOP with keyframes on request, QP clamp, 24 fps cap, our own
//! VRR (a frame whose luma barely moved is not encoded) and congestion control
//! from `core::call_backlog()`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use gst::prelude::*;
use gstreamer as gst;
use gstreamer_app as gst_app;
use gstreamer_video as gst_video;

use crate::core::{self, KIND_AUDIO, KIND_STATE, KIND_VIDEO};

/// A decoded picture for the UI: `slot` is the remote participant, `None` the
/// local camera preview. Tightly packed RGBA.
pub struct Frame {
    pub slot: Option<u8>,
    pub width: u32,
    pub height: u32,
    pub stride: usize,
    pub rgba: Vec<u8>,
}

pub type FrameSender = async_channel::Sender<Frame>;

/// Same knobs as Android `CallMedia.VideoTuning`.
mod tuning {
    pub const WIDTH: u32 = 640;
    pub const HEIGHT: u32 = 480;
    pub const MAX_FPS: u32 = 24;
    pub const MIN_FPS: u32 = 4;
    /// kbps, HEVC; H.264 gets `AVC_FACTOR` times this.
    pub const START_KBPS: u32 = 180;
    pub const MIN_KBPS: u32 = 40;
    pub const MAX_KBPS: u32 = 320;
    pub const AVC_FACTOR: f64 = 1.4;
    pub const KEYFRAME_INTERVAL_S: u32 = 10;
    pub const KEYFRAME_MIN_GAP_MS: u64 = 2000;
    pub const QP_MIN: u32 = 22;
    pub const QP_MAX: u32 = 44;
    /// Mean |ΔY| (0-255) over a 1/64 luma grid below which nothing moved.
    pub const CHANGE_THRESHOLD: f64 = 1.5;
    pub const MAX_STILL_MS: u64 = 1000;
    pub const SAMPLE_STEP: usize = 8;
    pub const ADAPT_MS: u64 = 500;
    pub const CUT_AT: usize = 4;
    pub const PAUSE_AT: usize = 15;
    pub const RESUME_AT: usize = 3;
}

/// Jitter buffer (ms): where a fresh stream starts playing relative to now,
/// how close to "now" the queue may run before it is re-anchored, and how deep
/// it may grow before packets are dropped (LTE + Tor delivers in ~1 s bursts,
/// same cap as the phones).
const JITTER_START_MS: u64 = 120;
const JITTER_MIN_MS: u64 = 40;
const JITTER_MAX_MS: u64 = 600;
const OPUS_FRAME_MS: u64 = 20;
const PACKETS_PER_BUNDLE: usize = 3;
const STATE_EVERY: Duration = Duration::from_secs(1);

/// Voice-activity proxy, same as Android `AudioSink.trackLevel`: a strided
/// peak against a min-tracking noise floor. Speaking = clearly above the floor
/// and above an absolute minimum; held 400 ms so the tile frame does not flicker.
struct Level {
    noise: Mutex<f32>,
    speaking_until_ms: std::sync::atomic::AtomicU64,
}

impl Level {
    fn track(&self, pcm: &[u8]) {
        // Every 16th S16LE sample.
        let peak = pcm
            .chunks_exact(2)
            .step_by(16)
            .map(|c| i16::from_le_bytes([c[0], c[1]]).unsigned_abs() as f32)
            .fold(0.0f32, f32::max);
        let mut noise = self.noise.lock().unwrap_or_else(|p| p.into_inner());
        *noise = if peak < *noise { peak.max(60.0) } else { *noise + (peak - *noise) * 0.002 };
        if peak > 1500.0 && peak > *noise * 3.2 {
            self.speaking_until_ms.store(crate::util::now_ms() + 400, Ordering::Relaxed);
        }
    }
}

struct AudioLane {
    level: Arc<Level>,
    bin: gst::Bin,
    src: gst_app::AppSrc,
    mixer_pad: gst::Pad,
    next_pts_ns: u64,
}

struct VideoLane {
    pipeline: Option<gst::Pipeline>,
    src: Option<gst_app::AppSrc>,
    hevc: bool,
    width: u16,
    height: u16,
    rotation: u8,
    asked_at: Option<Instant>,
    built_at: Option<Instant>,
}

/// Shared by the receive thread and the UI.
struct Shared {
    running: AtomicBool,
    muted: AtomicBool,
    camera_on: AtomicBool,
    video_call: bool,
    frames: FrameSender,
    playback: Option<gst::Pipeline>,
    audio: Mutex<HashMap<u8, AudioLane>>,
    video: Mutex<HashMap<u8, VideoLane>>,
    camera: Mutex<Option<VideoTx>>,
}

/// Loads GStreamer off the UI thread at start-up. The first `gst::init` after
/// an install or update rebuilds the plugin registry, which took the first
/// video call 30 s+ to show a frame.
pub fn prewarm() {
    let _ = std::thread::Builder::new().name("gst-init".into()).spawn(|| {
        let _ = gst::init();
    });
}

pub struct CallMedia {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl CallMedia {
    /// Starts microphone, playback and (for video calls) the camera.
    pub fn start(video: bool, frames: FrameSender) -> Result<Self, String> {
        gst::init().map_err(|e| format!("GStreamer: {e}"))?;
        // Playback first: its echo probe must exist before the DSP looks it up.
        let playback = build_playback().map_err(|e| log::warn!("call: no audio playback: {e}")).ok();
        let shared = Arc::new(Shared {
            running: AtomicBool::new(true),
            muted: AtomicBool::new(false),
            camera_on: AtomicBool::new(video),
            video_call: video,
            frames,
            playback,
            audio: Mutex::new(HashMap::new()),
            video: Mutex::new(HashMap::new()),
            camera: Mutex::new(None),
        });
        let mut threads = Vec::new();
        {
            let s = shared.clone();
            threads.push(std::thread::Builder::new().name("call-audio-tx".into()).spawn(move || audio_tx(s)).map_err(|e| e.to_string())?);
        }
        {
            let s = shared.clone();
            threads.push(std::thread::Builder::new().name("call-rx".into()).spawn(move || receive(s)).map_err(|e| e.to_string())?);
        }
        let media = CallMedia { shared, threads };
        if video {
            media.set_camera(true);
        }
        Ok(media)
    }

    pub fn set_muted(&self, muted: bool) {
        self.shared.muted.store(muted, Ordering::Relaxed);
    }

    pub fn camera_on(&self) -> bool {
        self.shared.camera_on.load(Ordering::Relaxed)
    }

    /// Off releases the camera device (the LED goes out), on opens it again.
    pub fn set_camera(&self, on: bool) {
        log::info!("call: camera {}", if on { "on" } else { "off" });
        self.shared.camera_on.store(on, Ordering::Relaxed);
        let mut cam = self.shared.camera.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(tx) = cam.take() {
            tx.stop();
        }
        if on {
            match VideoTx::start(self.shared.clone()) {
                Ok(tx) => *cam = Some(tx),
                Err(e) => {
                    log::warn!("call: camera unavailable: {e}");
                    self.shared.camera_on.store(false, Ordering::Relaxed);
                }
            }
        }
    }

    /// True while `slot`'s voice stands clear of its noise floor.
    pub fn is_speaking(&self, slot: u8) -> bool {
        self.shared
            .audio
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&slot)
            .is_some_and(|lane| lane.level.speaking_until_ms.load(Ordering::Relaxed) > crate::util::now_ms())
    }

    /// A participant left: free its decoders.
    pub fn drop_slot(&self, slot: u8) {
        if let Some(lane) = self.shared.audio.lock().unwrap_or_else(|p| p.into_inner()).remove(&slot) {
            remove_audio_lane(&self.shared, lane);
        }
        if let Some(mut lane) = self.shared.video.lock().unwrap_or_else(|p| p.into_inner()).remove(&slot) {
            lane.teardown();
        }
    }
}

impl Drop for CallMedia {
    fn drop(&mut self) {
        self.shared.running.store(false, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        if let Some(tx) = self.shared.camera.lock().unwrap_or_else(|p| p.into_inner()).take() {
            tx.stop();
        }
        for (_, mut lane) in self.shared.video.lock().unwrap_or_else(|p| p.into_inner()).drain() {
            lane.teardown();
        }
        // Not `clear()`: lanes must leave the pipeline and release their mixer pads.
        let lanes: Vec<AudioLane> = self.shared.audio.lock().unwrap_or_else(|p| p.into_inner()).drain().map(|(_, lane)| lane).collect();
        for lane in lanes {
            remove_audio_lane(&self.shared, lane);
        }
        if let Some(p) = &self.shared.playback {
            let _ = p.set_state(gst::State::Null);
        }
    }
}

/// Most live audio / video lanes per call; a group call has far fewer slots.
const MAX_LANES: usize = 16;

/// Microphone, speaker and camera elements of this OS.
#[cfg(not(windows))]
const MIC: &str = "pulsesrc stream-properties=\"props,media.role=phone\"";
#[cfg(not(windows))]
const SPEAKER: &str = "pulsesink name=spk stream-properties=\"props,media.role=phone\"";
#[cfg(not(windows))]
const CAMERA: &str = "v4l2src";
#[cfg(windows)]
const MIC: &str = "wasapi2src low-latency=true";
#[cfg(windows)]
const SPEAKER: &str = "wasapi2sink name=spk low-latency=true";
#[cfg(windows)]
const CAMERA: &str = "mfvideosrc";

fn launch(desc: &str) -> Result<gst::Pipeline, String> {
    gst::parse::launch(desc)
        .map_err(|e| e.to_string())?
        .downcast::<gst::Pipeline>()
        .map_err(|_| "not a pipeline".to_string())
}

/// For pipelines nobody polls: log errors, drop everything else, so the bus
/// never fills up (latency/QoS messages arrive continuously).
fn drain_bus(p: &gst::Pipeline, what: &'static str) {
    if let Some(bus) = p.bus() {
        bus.set_sync_handler(move |_, msg| {
            if let gst::MessageView::Error(e) = msg.view() {
                log::warn!("call: {what}: {}", e.error());
            }
            gst::BusSyncReply::Drop
        });
    }
}

fn has(factory: &str) -> bool {
    gst::ElementFactory::find(factory).is_some()
}

fn first_available<'a>(factories: &[&'a str]) -> Option<&'a str> {
    factories.iter().copied().find(|f| has(f))
}

/// Sets `name` only if this element has it (encoders differ in knobs).
fn try_set(element: &gst::Element, name: &str, value: &str) {
    if element.find_property(name).is_some() {
        element.set_property_from_str(name, value);
    }
}

// ---------------------------------------------------------------- audio

/// Every remote voice mixes into one output, so the echo canceller sees
/// everything the speakers play. A silent live source keeps the mixer (and
/// the canceller's reference) running while nobody talks.
fn build_playback() -> Result<gst::Pipeline, String> {
    let probe = if has("webrtcechoprobe") { "webrtcechoprobe name=echo ! " } else { "" };
    let p = launch(&format!(
        "audiomixer name=mix latency=60000000 ! audioconvert ! audioresample ! \
         audio/x-raw,format=S16LE,rate=48000,channels=1 ! {probe}audioconvert ! \
         {SPEAKER} \
         audiotestsrc wave=silence is-live=true samplesperbuffer=480 ! \
         audio/x-raw,format=S16LE,rate=48000,channels=1 ! queue max-size-time=1000000000 ! mix."
    ))?;
    drain_bus(&p, "playback");
    p.set_state(gst::State::Playing).map_err(|e| e.to_string())?;
    Ok(p)
}

fn audio_tx(shared: Arc<Shared>) {
    let dsp = if has("webrtcdsp") && shared.playback.is_some() && has("webrtcechoprobe") {
        "webrtcdsp probe=echo echo-cancel=true noise-suppression=true gain-control=true ! "
    } else {
        ""
    };
    let desc = |dsp: &str| {
        format!(
            "{MIC} ! audioconvert ! audioresample ! \
             audio/x-raw,format=S16LE,rate=48000,channels=1 ! {dsp}audioconvert ! audioresample ! \
             audio/x-raw,format=S16LE,rate=16000,channels=1 ! \
             opusenc bitrate=12000 frame-size=20 audio-type=voice bandwidth=wideband complexity=10 ! \
             appsink name=out sync=false max-buffers=50 drop=true"
        )
    };
    let pipeline = match launch(&desc(dsp)).and_then(|p| {
        p.set_state(gst::State::Playing).map(|_| p).map_err(|e| e.to_string())
    }) {
        Ok(p) => p,
        Err(e) if !dsp.is_empty() => {
            log::warn!("call: echo cancellation unavailable ({e}), capturing without it");
            match launch(&desc("")).and_then(|p| p.set_state(gst::State::Playing).map(|_| p).map_err(|e| e.to_string())) {
                Ok(p) => p,
                Err(e) => return state_only(&shared, &e),
            }
        }
        Err(e) => return state_only(&shared, &e),
    };
    drain_bus(&pipeline, "microphone");
    // a pipeline missing its appsink (element changed, factory renamed)
    // would turn this worker thread into a live-strip-and-return: the whole
    // microphone silently died with the call still running. Degrade instead —
    // release and hand the loop to `state_only`, which keeps the presence
    // beacon going so the peers still see "me, muted".
    let Some(sink) = pipeline.by_name("out").and_then(|e| e.downcast::<gst_app::AppSink>().ok()) else {
        let _ = pipeline.set_state(gst::State::Null);
        return state_only(&shared, "microphone pipeline has no appsink element");
    };
    let mut bundle: Vec<Vec<u8>> = Vec::with_capacity(PACKETS_PER_BUNDLE);
    let mut state_at = Instant::now() - STATE_EVERY;
    let mut last_flags = u8::MAX;
    let (mut sent, mut log_at) = (0u32, Instant::now());
    while shared.running.load(Ordering::Relaxed) {
        if log_at.elapsed() >= Duration::from_secs(5) {
            log::info!("call: audio tx {sent} bundles/5s, muted={}", shared.muted.load(Ordering::Relaxed));
            (sent, log_at) = (0, Instant::now());
        }
        let flags = state_flags(&shared);
        if flags != last_flags || state_at.elapsed() >= STATE_EVERY {
            core::call_send(KIND_STATE, &[flags]);
            last_flags = flags;
            state_at = Instant::now();
        }
        let Some(sample) = sink.try_pull_sample(gst::ClockTime::from_mseconds(100)) else { continue };
        let Some(buffer) = sample.buffer() else { continue };
        let Ok(map) = buffer.map_readable() else { continue };
        bundle.push(map.as_slice().to_vec());
        if bundle.len() >= PACKETS_PER_BUNDLE {
            // Overflowed bundles (impossible today, see `pack_bundle`) come
            // back empty — skip rather than send a header-less frame.
            let frame = pack_bundle(&bundle);
            if !frame.is_empty() && !shared.muted.load(Ordering::Relaxed) && core::call_send(KIND_AUDIO, &frame) {
                sent += 1;
            }
            bundle.clear();
        }
    }
    let _ = pipeline.set_state(gst::State::Null);
}

/// No microphone: still tell the others we are muted, so they see why.
fn state_only(shared: &Shared, error: &str) {
    log::warn!("call: no microphone: {error}");
    shared.muted.store(true, Ordering::Relaxed);
    while shared.running.load(Ordering::Relaxed) {
        core::call_send(KIND_STATE, &[state_flags(shared)]);
        std::thread::sleep(STATE_EVERY);
    }
}

fn state_flags(shared: &Shared) -> u8 {
    let muted = shared.muted.load(Ordering::Relaxed) as u8;
    let camera_off = (shared.video_call && !shared.camera_on.load(Ordering::Relaxed)) as u8;
    muted | camera_off << 1
}

/// `[n][len u16 BE]*n [packet]*n`
pub fn pack_bundle(packets: &[Vec<u8>]) -> Vec<u8> {
    // the count lives in one header byte, so `as u8` used to truncate
    // silently at >255 packets (impossible for the 3-packet caller, but a
    // header/payload disagreement is still a corrupt frame if that ever
    // changes) — refuse loudly instead.
    if packets.len() > u8::MAX as usize {
        log::warn!("call: {} packets exceed the one-byte bundle header", packets.len());
        return Vec::new();
    }
    let mut out = Vec::with_capacity(1 + packets.len() * 2 + packets.iter().map(Vec::len).sum::<usize>());
    out.push(packets.len() as u8);
    for p in packets {
        out.extend_from_slice(&(p.len() as u16).to_be_bytes());
    }
    for p in packets {
        out.extend_from_slice(p);
    }
    out
}

pub fn unpack_bundle(b: &[u8]) -> Vec<&[u8]> {
    let Some(&n) = b.first() else { return Vec::new() };
    let n = n as usize;
    let mut pos = 1 + n * 2;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let at = 1 + i * 2;
        let Some(len) = b.get(at..at + 2).map(|l| u16::from_be_bytes([l[0], l[1]]) as usize) else { break };
        let Some(pkt) = b.get(pos..pos + len) else { break };
        out.push(pkt);
        pos += len;
    }
    out
}

/// One remote voice: Opus in, 48 kHz mono PCM out to the mixer.
const AUDIO_LANE: &str = "appsrc name=src is-live=true format=time do-timestamp=false \
         caps=\"audio/x-opus,rate=48000,channels=1,channel-mapping-family=0\" ! \
         opusdec plc=true ! audioconvert ! audioresample ! \
         capsfilter caps=\"audio/x-raw,format=S16LE,rate=48000,channels=1\" ! \
         queue max-size-time=1000000000";

fn add_audio_lane(shared: &Shared, slot: u8) -> Option<AudioLane> {
    let playback = shared.playback.as_ref()?;
    let mixer = playback.by_name("mix")?;
    let bin = gst::parse::bin_from_description(
        AUDIO_LANE,
        true,
    )
    .map_err(|e| log::warn!("call: audio lane {slot}: {e}"))
    .ok()?;
    let src = bin.by_name("src")?.downcast::<gst_app::AppSrc>().ok()?;
    playback.add(&bin).ok()?;
    let mixer_pad = mixer.request_pad_simple("sink_%u")?;
    bin.static_pad("src")?.link(&mixer_pad).ok()?;
    bin.sync_state_with_parent().ok()?;
    let level = Arc::new(Level { noise: Mutex::new(400.0), speaking_until_ms: std::sync::atomic::AtomicU64::new(0) });
    {
        let level = level.clone();
        bin.static_pad("src")?.add_probe(gst::PadProbeType::BUFFER, move |_, info| {
            if let Some(gst::PadProbeData::Buffer(buffer)) = &info.data {
                if let Ok(map) = buffer.map_readable() {
                    level.track(map.as_slice());
                }
            }
            gst::PadProbeReturn::Ok
        });
    }
    Some(AudioLane { level, bin: bin.upcast(), src, mixer_pad, next_pts_ns: 0 })
}

fn remove_audio_lane(shared: &Shared, lane: AudioLane) {
    let _ = lane.bin.set_state(gst::State::Null);
    if let Some(p) = &shared.playback {
        let _ = p.remove(&lane.bin);
        if let Some(mixer) = p.by_name("mix") {
            mixer.release_request_pad(&lane.mixer_pad);
        }
    }
}

/// Timestamps each packet onto a steady 20 ms grid ahead of the playback
/// clock: a burst queues up (up to `JITTER_MAX_MS`, then is dropped), a gap
/// re-anchors `JITTER_START_MS` ahead of now.
fn play_audio(shared: &Shared, slot: u8, payload: &[u8]) {
    let Some(playback) = &shared.playback else { return };
    let Some(now) = playback.current_running_time() else { return };
    let now = now.nseconds();
    let mut lanes = shared.audio.lock().unwrap_or_else(|p| p.into_inner());
    if !lanes.contains_key(&slot) {
        // A peer cycling the slot byte must not fan out decoder pipelines.
        if lanes.len() >= MAX_LANES {
            return;
        }
        match add_audio_lane(shared, slot) {
            Some(l) => {
                log::info!("call: audio lane {slot} playing");
                lanes.insert(slot, l);
            }
            None => return,
        }
    }
    let lane = lanes.get_mut(&slot).unwrap();
    for pkt in unpack_bundle(payload) {
        let ms = 1_000_000;
        if lane.next_pts_ns < now + JITTER_MIN_MS * ms {
            lane.next_pts_ns = now + JITTER_START_MS * ms;
        }
        if lane.next_pts_ns > now + JITTER_MAX_MS * ms {
            continue;
        }
        let mut buffer = gst::Buffer::from_slice(pkt.to_vec());
        {
            let b = buffer.get_mut().unwrap();
            b.set_pts(gst::ClockTime::from_nseconds(lane.next_pts_ns));
            b.set_duration(gst::ClockTime::from_mseconds(OPUS_FRAME_MS));
        }
        lane.next_pts_ns += OPUS_FRAME_MS * ms;
        let _ = lane.src.push_buffer(buffer);
    }
}

// ---------------------------------------------------------------- receive

fn receive(shared: Arc<Shared>) {
    while shared.running.load(Ordering::Relaxed) {
        let Some(frame) = core::call_recv(200) else { continue };
        if frame.len() < 3 {
            continue;
        }
        let (kind, slot, payload) = (frame[0], frame[1], &frame[2..]);
        match kind {
            KIND_AUDIO => play_audio(&shared, slot, payload),
            KIND_VIDEO => {
                let mut lanes = shared.video.lock().unwrap_or_else(|p| p.into_inner());
                if !lanes.contains_key(&slot) && lanes.len() >= MAX_LANES {
                    continue;
                }
                let lane = lanes.entry(slot).or_insert_with(VideoLane::new);
                lane.feed(&shared, slot, payload);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- video in

impl VideoLane {
    fn new() -> Self {
        VideoLane { pipeline: None, src: None, hevc: false, width: 0, height: 0, rotation: 0, asked_at: None, built_at: None }
    }

    fn feed(&mut self, shared: &Shared, slot: u8, f: &[u8]) {
        if f.len() < 7 {
            return;
        }
        let key = f[0] & 1 != 0;
        let hevc = f[0] & 2 != 0;
        let rotation = f[1] & 3;
        let width = u16::from_be_bytes([f[2], f[3]]);
        let height = u16::from_be_bytes([f[4], f[5]]);
        if let Some(p) = &self.pipeline {
            let failed = p.bus().and_then(|b| b.pop_filtered(&[gst::MessageType::Error])).map(|m| {
                if let gst::MessageView::Error(e) = m.view() {
                    log::warn!("call: video decode (slot {slot}): {}", e.error());
                }
            });
            if failed.is_some() {
                self.teardown();
            }
        }
        let changed = self.pipeline.is_none() || hevc != self.hevc || width != self.width || height != self.height || rotation != self.rotation;
        if changed {
            if !key {
                self.ask_keyframe(slot);
                return;
            }
            // The sender picks these bits per frame; without a floor it could
            // make this side build a decoder pipeline on every keyframe.
            if self.built_at.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
                return;
            }
            self.built_at = Some(Instant::now());
            self.teardown();
            match build_decoder(shared, slot, hevc, rotation) {
                Ok((p, src)) => {
                    self.pipeline = Some(p);
                    self.src = Some(src);
                    (self.hevc, self.width, self.height, self.rotation) = (hevc, width, height, rotation);
                }
                Err(e) => {
                    log::warn!("call: no {} decoder: {e}", if hevc { "HEVC" } else { "H.264" });
                    return;
                }
            }
        }
        if let Some(src) = &self.src {
            let mut buffer = gst::Buffer::from_slice(f[6..].to_vec());
            if !key {
                buffer.get_mut().unwrap().set_flags(gst::BufferFlags::DELTA_UNIT);
            }
            if src.push_buffer(buffer).is_err() {
                self.teardown();
                self.ask_keyframe(slot);
            }
        }
    }

    fn ask_keyframe(&mut self, slot: u8) {
        if self.asked_at.map_or(true, |t| t.elapsed() >= Duration::from_secs(1)) {
            self.asked_at = Some(Instant::now());
            core::call_request_keyframe(slot);
        }
    }

    fn teardown(&mut self) {
        if let Some(p) = self.pipeline.take() {
            let _ = p.set_state(gst::State::Null);
        }
        self.src = None;
    }
}

fn build_decoder(shared: &Shared, slot: u8, hevc: bool, rotation: u8) -> Result<(gst::Pipeline, gst_app::AppSrc), String> {
    let (codec, parse, decoders) = if hevc {
        ("h265", "h265parse", ["vah265dec", "d3d11h265dec", "avdec_h265", ""])
    } else {
        ("h264", "h264parse", ["vah264dec", "d3d11h264dec", "avdec_h264", "openh264dec"])
    };
    let decoder = first_available(&decoders[..decoders.iter().position(|d| d.is_empty()).unwrap_or(decoders.len())])
        .ok_or("no decoder element")?;
    // Android sends the sensor rotation (clockwise degrees / 90).
    let flip = match rotation {
        1 => "videoflip video-direction=90r ! ",
        2 => "videoflip video-direction=180 ! ",
        3 => "videoflip video-direction=90l ! ",
        _ => "",
    };
    let p = launch(&format!(
        "appsrc name=src is-live=true format=time do-timestamp=true \
         caps=\"video/x-{codec},stream-format=byte-stream,alignment=au\" ! {parse} ! video/x-{codec},width=(int)[16,4096],height=(int)[16,4096] ! {decoder} ! \
         videoconvert ! video/x-raw,format=RGBA ! {flip}appsink name=out sync=false max-buffers=2 drop=true \
         caps=\"video/x-raw,format=RGBA\""
    ))?;
    let src = p.by_name("src").and_then(|e| e.downcast::<gst_app::AppSrc>().ok()).ok_or("appsrc")?;
    let sink = p.by_name("out").and_then(|e| e.downcast::<gst_app::AppSink>().ok()).ok_or("appsink")?;
    attach_frame_sink(&sink, Some(slot), shared.frames.clone());
    p.set_state(gst::State::Playing).map_err(|e| e.to_string())?;
    log::info!("call: video decoder {decoder} for slot {slot}");
    Ok((p, src))
}

/// Every decoded RGBA frame goes to the UI thread.
fn attach_frame_sink(sink: &gst_app::AppSink, slot: Option<u8>, frames: FrameSender) {
    sink.set_callbacks(
        gst_app::AppSinkCallbacks::builder()
            .new_sample(move |sink| {
                let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let (Some(buffer), Some(caps)) = (sample.buffer(), sample.caps()) else { return Ok(gst::FlowSuccess::Ok) };
                let Ok(info) = gst_video::VideoInfo::from_caps(caps) else { return Ok(gst::FlowSuccess::Ok) };
                let Ok(map) = buffer.map_readable() else { return Ok(gst::FlowSuccess::Ok) };
                let stride = info.stride()[0] as usize;
                // Caps and buffer can disagree (renegotiation, truncated frame):
                // a panic here would unwind through the C callback and abort.
                let Some(pixels) = map.as_slice().get(..stride * info.height() as usize) else {
                    return Ok(gst::FlowSuccess::Ok);
                };
                let _ = frames.try_send(Frame {
                    slot,
                    width: info.width(),
                    height: info.height(),
                    stride,
                    rgba: pixels.to_vec(),
                });
                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );
}

// ---------------------------------------------------------------- video out

struct Encoder {
    factory: &'static str,
    hevc: bool,
    /// Bitrate property is in bit/s rather than kbit/s.
    bps: bool,
}

/// Hardware HEVC first (the phones decode it in hardware and it needs ~30 %
/// fewer bits), hardware H.264 next, software H.264 last.
fn pick_encoder() -> Option<Encoder> {
    const LIST: [Encoder; 8] = [
        Encoder { factory: "vah265enc", hevc: true, bps: false },
        Encoder { factory: "vah265lpenc", hevc: true, bps: false },
        Encoder { factory: "vah264enc", hevc: false, bps: false },
        Encoder { factory: "vah264lpenc", hevc: false, bps: false },
        // Windows: Media Foundation (hardware where the GPU has it).
        Encoder { factory: "mfh265enc", hevc: true, bps: false },
        Encoder { factory: "mfh264enc", hevc: false, bps: false },
        Encoder { factory: "x264enc", hevc: false, bps: false },
        Encoder { factory: "openh264enc", hevc: false, bps: true },
    ];
    LIST.into_iter().find(|e| has(e.factory))
}

struct VideoTx {
    pipeline: gst::Pipeline,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// Decides, per camera frame, whether the encoder gets it.
struct Gate {
    fps: u32,
    paused: bool,
    last_sent: Option<Instant>,
    prev_luma: Vec<u8>,
    force: bool,
    still_skips: u32,
    /// Frames admitted since the last adapt step (see `encoder_kbps`).
    admitted: u32,
}

/// The encoder divides its bitrate by the frame rate of its caps, but the gate
/// drops frames behind its back (frame cap, congestion, VRR): at 6 of 30 fps
/// each frame got a fifth of its bits (measured with vah265enc: 70 KB vs
/// 153 KB for the same frames). Scale the bitrate we give it by caps fps /
/// frames actually admitted, so the bits per frame match `target`.
fn encoder_kbps(target: u32, caps_fps: f64, admitted_fps: f64) -> u32 {
    let scale = (caps_fps / admitted_fps.max(1.0)).clamp(1.0, 8.0);
    (target as f64 * scale) as u32
}

impl VideoTx {
    fn start(shared: Arc<Shared>) -> Result<Self, String> {
        let enc = pick_encoder().ok_or("no H.264/HEVC encoder (VA-API, x264 or OpenH264)")?;
        let (codec, parse) = if enc.hevc { ("h265", "h265parse") } else { ("h264", "h264parse") };
        let (w, h) = (tuning::WIDTH, tuning::HEIGHT);
        // Development/testing: e.g. TYPEON_CAMERA_SRC="videotestsrc is-live=true pattern=ball".
        let camera = std::env::var("TYPEON_CAMERA_SRC").unwrap_or_else(|_| CAMERA.into());
        // One source element and its properties, nothing more: a `!` would
        // splice arbitrary elements (file or network sinks) into the pipeline.
        let source = camera.split_whitespace().next();
        if camera.contains('!') || !matches!(source, Some("v4l2src" | "videotestsrc" | "pipewiresrc" | "mfvideosrc")) {
            return Err("TYPEON_CAMERA_SRC must be one v4l2src, videotestsrc, pipewiresrc or mfvideosrc element".into());
        }
        let pipeline = launch(&format!(
            "{camera} ! videoconvert ! videoscale ! videorate max-rate={fps} drop-only=true ! \
             video/x-raw,format=NV12,width={w},height={h},pixel-aspect-ratio=1/1 ! tee name=t \
             t. ! queue leaky=downstream max-size-buffers=2 ! {factory} name=enc ! {parse} config-interval=-1 ! \
             video/x-{codec},stream-format=byte-stream,alignment=au ! appsink name=out sync=false max-buffers=8 \
             t. ! queue leaky=downstream max-size-buffers=1 ! videorate max-rate=12 drop-only=true ! videoconvert ! \
             videoscale ! video/x-raw,format=RGBA,width=240,height=180 ! appsink name=preview sync=false max-buffers=1 drop=true",
            fps = tuning::MAX_FPS,
            factory = enc.factory,
        ))?;
        let encoder = pipeline.by_name("enc").ok_or("encoder")?;
        let factor = if enc.hevc { 1.0 } else { tuning::AVC_FACTOR };
        let kbps = move |k: u32| (k as f64 * factor) as u32;
        let set_bitrate = {
            let encoder = encoder.clone();
            let bps = enc.bps;
            move |k: u32| try_set(&encoder, "bitrate", &(if bps { k * 1000 } else { k }).to_string())
        };
        set_bitrate(kbps(tuning::START_KBPS));
        let gop = (tuning::MAX_FPS * tuning::KEYFRAME_INTERVAL_S).to_string();
        let (qp_min, qp_max) = (tuning::QP_MIN.to_string(), tuning::QP_MAX.to_string());
        let knobs: Vec<(&str, &str)> = match enc.factory {
            f if f.starts_with("va") => vec![
                ("rate-control", "vbr"),
                ("key-int-max", &gop),
                ("b-frames", "0"),
                ("ref-frames", "1"),
                ("min-qp", &qp_min),
                ("max-qp", &qp_max),
                ("target-usage", "7"),
            ],
            "x264enc" => vec![
                ("tune", "zerolatency"),
                ("speed-preset", "veryfast"),
                ("key-int-max", &gop),
                ("bframes", "0"),
                ("qp-min", &qp_min),
                ("qp-max", &qp_max),
            ],
            f if f.starts_with("mf") => vec![
                ("low-latency", "true"),
                ("bframes", "0"),
                ("gop-size", &gop),
                ("qp-min", &qp_min),
                ("qp-max", &qp_max),
            ],
            _ => vec![("rate-control", "bitrate"), ("gop-size", &gop)],
        };
        for (name, value) in knobs {
            try_set(&encoder, name, value);
        }
        let gate = Arc::new(Mutex::new(Gate {
            fps: tuning::MAX_FPS,
            paused: false,
            last_sent: None,
            prev_luma: Vec::new(),
            force: true,
            still_skips: 0,
            admitted: 0,
        }));
        {
            let gate = gate.clone();
            let pad = encoder.static_pad("sink").ok_or("encoder pad")?;
            pad.add_probe(gst::PadProbeType::BUFFER, move |pad, info| {
                let Some(gst::PadProbeData::Buffer(buffer)) = &info.data else { return gst::PadProbeReturn::Ok };
                let mut g = gate.lock().unwrap_or_else(|p| p.into_inner());
                if admit(&mut g, pad, buffer) { gst::PadProbeReturn::Ok } else { gst::PadProbeReturn::Drop }
            });
        }
        let preview = pipeline.by_name("preview").and_then(|e| e.downcast::<gst_app::AppSink>().ok()).ok_or("preview")?;
        attach_frame_sink(&preview, None, shared.frames.clone());
        let out = pipeline.by_name("out").and_then(|e| e.downcast::<gst_app::AppSink>().ok()).ok_or("appsink")?;
        pipeline.set_state(gst::State::Playing).map_err(|e| e.to_string())?;
        log::info!("call: video encoder {} {}x{}", enc.factory, w, h);

        let running = Arc::new(AtomicBool::new(true));
        let thread = {
            let running = running.clone();
            let hevc = enc.hevc;
            let bus = pipeline.bus();
            let enc_sink = encoder.static_pad("sink");
            let pipe = pipeline.clone();
            std::thread::Builder::new()
                .name("call-video-tx".into())
                .spawn(move || {
                    let mut bitrate = kbps(tuning::START_KBPS);
                    let (min, max) = (kbps(tuning::MIN_KBPS), kbps(tuning::MAX_KBPS));
                    let mut adapt_at = Instant::now();
                    let mut admitted_fps = tuning::MAX_FPS as f64;
                    let mut applied = bitrate;
                    let mut key_at: Option<Instant> = None;
                    while running.load(Ordering::Relaxed) && shared.running.load(Ordering::Relaxed) {
                        if let Some(m) = bus.as_ref().and_then(|b| b.pop_filtered(&[gst::MessageType::Error])) {
                            if let gst::MessageView::Error(e) = m.view() {
                                log::warn!("call: camera/encoder: {}", e.error());
                            }
                            // Release the device and tell the UI: left Playing,
                            // the LED stayed on and peers saw a frozen tile.
                            shared.camera_on.store(false, Ordering::Relaxed);
                            let _ = pipe.set_state(gst::State::Null);
                            break;
                        }
                        // On request, at most one keyframe per KEYFRAME_MIN_GAP_MS.
                        if core::call_take_keyframe_request()
                            && key_at.map_or(true, |t| t.elapsed() >= Duration::from_millis(tuning::KEYFRAME_MIN_GAP_MS))
                        {
                            key_at = Some(Instant::now());
                            gate.lock().unwrap_or_else(|p| p.into_inner()).force = true;
                            out.send_event(gst_video::UpstreamForceKeyUnitEvent::builder().all_headers(true).build());
                        }
                        if adapt_at.elapsed() >= Duration::from_millis(tuning::ADAPT_MS) {
                            let dt = adapt_at.elapsed().as_secs_f64();
                            adapt_at = Instant::now();
                            let backlog = core::call_backlog();
                            let mut g = gate.lock().unwrap_or_else(|p| p.into_inner());
                            admitted_fps = admitted_fps * 0.6 + std::mem::take(&mut g.admitted) as f64 / dt * 0.4;
                            if backlog >= tuning::PAUSE_AT {
                                g.paused = true;
                            } else if backlog <= tuning::RESUME_AT {
                                g.paused = false;
                            }
                            if backlog > tuning::CUT_AT {
                                bitrate = (bitrate / 2).max(min);
                                g.fps = g.fps.saturating_sub(6).max(tuning::MIN_FPS);
                            } else if backlog <= 1 {
                                bitrate = (bitrate + kbps(25)).min(max);
                                g.fps = (g.fps + 1).min(tuning::MAX_FPS);
                            }
                            if g.still_skips > 0 || g.paused {
                                log::debug!("call: VRR skipped {} still frames, {} kbps, <= {} fps, paused={}", g.still_skips, bitrate, g.fps, g.paused);
                            }
                            g.still_skips = 0;
                            drop(g);
                            let caps_fps = enc_sink.as_ref()
                                .and_then(|p| p.current_caps())
                                .and_then(|c| gst_video::VideoInfo::from_caps(&c).ok())
                                .map(|i| i.fps())
                                .filter(|f| f.numer() > 0 && f.denom() > 0)
                                .map_or(tuning::MAX_FPS as f64, |f| f.numer() as f64 / f.denom() as f64);
                            let want = encoder_kbps(bitrate, caps_fps, admitted_fps);
                            // Not on every jitter of the frame count: 10 %.
                            if want.abs_diff(applied) * 10 > applied {
                                applied = want;
                                set_bitrate(applied);
                                log::debug!("call: encoder {} kbps (target {}, {:.1} of {:.0} fps)", applied, bitrate, admitted_fps, caps_fps);
                            }
                        }
                        let Some(sample) = out.try_pull_sample(gst::ClockTime::from_mseconds(100)) else { continue };
                        let Some(buffer) = sample.buffer() else { continue };
                        let Ok(map) = buffer.map_readable() else { continue };
                        if map.is_empty() {
                            continue;
                        }
                        let key = !buffer.flags().contains(gst::BufferFlags::DELTA_UNIT);
                        let mut packet = Vec::with_capacity(6 + map.len());
                        packet.push(key as u8 | (hevc as u8) << 1);
                        packet.push(0); // a desktop camera is upright
                        packet.extend_from_slice(&(w as u16).to_be_bytes());
                        packet.extend_from_slice(&(h as u16).to_be_bytes());
                        packet.extend_from_slice(map.as_slice());
                        core::call_send(KIND_VIDEO, &packet);
                    }
                })
                .map_err(|e| e.to_string())?
        };
        Ok(VideoTx { pipeline, running, thread: Some(thread) })
    }

    fn stop(mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

/// Frame-rate cap, congestion pause and VRR: a frame whose luma barely moved
/// since the last one sent is not encoded at all (but never longer than
/// `MAX_STILL_MS`, so a still picture stays current).
fn admit(g: &mut Gate, pad: &gst::Pad, buffer: &gst::Buffer) -> bool {
    if g.paused {
        return false;
    }
    let now = Instant::now();
    let since = g.last_sent.map(|t| now.duration_since(t));
    if !g.force && since.is_some_and(|d| d < Duration::from_millis(1000 / g.fps as u64)) {
        return false;
    }
    let luma = pad
        .current_caps()
        .and_then(|c| gst_video::VideoInfo::from_caps(&c).ok())
        .and_then(|info| sample_luma(&info, buffer));
    if let Some(luma) = luma {
        let still = !g.force
            && since.is_some_and(|d| d < Duration::from_millis(tuning::MAX_STILL_MS))
            && mean_abs_diff(&g.prev_luma, &luma) < tuning::CHANGE_THRESHOLD;
        if still {
            g.still_skips += 1;
            return false;
        }
        g.prev_luma = luma;
    }
    g.force = false;
    g.last_sent = Some(now);
    g.admitted += 1;
    true
}

fn sample_luma(info: &gst_video::VideoInfo, buffer: &gst::Buffer) -> Option<Vec<u8>> {
    let map = buffer.map_readable().ok()?;
    let data = map.as_slice();
    let (stride, offset) = (info.stride()[0] as usize, info.offset()[0]);
    let step = tuning::SAMPLE_STEP;
    let (cols, rows) = (info.width() as usize / step, info.height() as usize / step);
    let mut out = Vec::with_capacity(cols * rows);
    for y in 0..rows {
        let row = offset + y * step * stride;
        for x in 0..cols {
            out.push(*data.get(row + x * step)?);
        }
    }
    Some(out)
}

fn mean_abs_diff(a: &[u8], b: &[u8]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return f64::MAX;
    }
    let sum: u64 = a.iter().zip(b).map(|(x, y)| (*x as i32 - *y as i32).unsigned_abs() as u64).sum();
    sum as f64 / a.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_budget_follows_admitted_frames() {
        assert_eq!(encoder_kbps(180, 24.0, 24.0), 180, "every frame admitted: no change");
        assert_eq!(encoder_kbps(180, 24.0, 6.0), 720, "a quarter admitted: four times the bitrate");
        assert_eq!(encoder_kbps(40, 30.0, 0.0), 320, "capped at 8x");
        assert_eq!(encoder_kbps(180, 24.0, 30.0), 180, "never below the target");
    }

    #[test]
    fn bundle_round_trip_matches_android_layout() {
        let packets = vec![vec![1, 2, 3], vec![], vec![9; 300]];
        let b = pack_bundle(&packets);
        assert_eq!(&b[..7], &[3, 0, 3, 0, 0, 1, 44]);
        let back: Vec<Vec<u8>> = unpack_bundle(&b).into_iter().map(<[u8]>::to_vec).collect();
        assert_eq!(back, packets);
        assert!(unpack_bundle(&b[..5]).is_empty(), "truncated bundle yields nothing past the cut");
    }

    #[test]
    fn pipelines_parse() {
        gst::init().unwrap();
        gst::parse::bin_from_description(AUDIO_LANE, true).expect("audio lane");
    }

    #[test]
    fn vrr_diff() {
        assert_eq!(mean_abs_diff(&[10, 20], &[12, 16]), 3.0);
        assert_eq!(mean_abs_diff(&[], &[]), f64::MAX);
    }
}
