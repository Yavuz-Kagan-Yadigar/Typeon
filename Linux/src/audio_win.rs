//! Voice-message recording on Windows: same API as `audio.rs`, but GStreamer
//! (already shipped for calls) instead of ffmpeg, which has no usable default
//! microphone input on Windows.
//!
//! Output is the same Opus-in-Ogg as on Linux. Stopping sends EOS and waits
//! for it to reach the sink, so oggmux writes its final page — the Windows
//! equivalent of ffmpeg's `q`.

use gstreamer as gst;
use gstreamer::prelude::*;
use std::path::PathBuf;

/// A capture in progress.
pub struct Recording {
    pipeline: gst::Pipeline,
    path: PathBuf,
    started_at: u64,
}

const ELEMENTS: [&str; 6] = ["wasapi2src", "audioconvert", "audioresample", "opusenc", "oggmux", "filesink"];

/// Whether voice messages are possible at all on this machine.
pub fn is_available() -> bool {
    gst::init().is_ok() && ELEMENTS.iter().all(|f| gst::ElementFactory::find(f).is_some())
}

impl Recording {
    /// Starts capturing to a temporary file.
    pub fn start() -> Result<Self, String> {
        gst::init().map_err(|e| format!("GStreamer: {e}"))?;
        let path = crate::data_directory()
            .join("attachments/plain_cache")
            .join(format!("voice-{}.ogg", crate::util::now_ms()));
        // Forward slashes: the launch parser treats backslashes as escapes.
        let location = path.to_string_lossy().replace('\\', "/");
        // Mono speech at 24 kbit/s, like the Linux ffmpeg command.
        let desc = format!(
            "wasapi2src ! audioconvert ! audioresample ! audio/x-raw,channels=1,rate=48000 ! \
             opusenc bitrate=24000 audio-type=voice ! oggmux ! filesink location=\"{location}\""
        );
        let pipeline = gst::parse::launch(&desc)
            .map_err(|e| e.to_string())?
            .downcast::<gst::Pipeline>()
            .map_err(|_| "not a pipeline".to_string())?;
        pipeline.set_state(gst::State::Playing).map_err(|_| "recording failed — is a microphone connected?".to_string())?;
        let started_at = crate::util::now_ms();
        // Hard cap: a recording nobody stops must not run forever (ffmpeg `-t 600`).
        let weak = pipeline.downgrade();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(600));
            if let Some(p) = weak.upgrade() {
                p.send_event(gst::event::Eos::new());
            }
        });
        Ok(Self { pipeline, path, started_at })
    }

    /// Milliseconds captured so far — drives the on-screen timer.
    pub fn elapsed_ms(&self) -> u64 {
        crate::util::now_ms().saturating_sub(self.started_at)
    }

    /// Finishes the recording and returns the finished file plus its duration.
    /// Blocking: waits for the Ogg trailer. Call it off the main thread.
    pub fn finish(self) -> Result<(PathBuf, u32), String> {
        let duration_ms = self.elapsed_ms().min(600_000) as u32;
        self.pipeline.send_event(gst::event::Eos::new());
        let mut error = None;
        if let Some(bus) = self.pipeline.bus() {
            match bus.timed_pop_filtered(gst::ClockTime::from_seconds(5), &[gst::MessageType::Eos, gst::MessageType::Error]) {
                Some(msg) => {
                    if let gst::MessageView::Error(e) = msg.view() {
                        error = Some(e.error().to_string());
                    }
                }
                None => error = Some("recording did not finish".to_string()),
            }
        }
        let _ = self.pipeline.set_state(gst::State::Null);
        if let Some(error) = error {
            let _ = std::fs::remove_file(&self.path);
            return Err(error);
        }
        let size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if size == 0 {
            let _ = std::fs::remove_file(&self.path);
            return Err("nothing was recorded".to_string());
        }
        Ok((self.path.clone(), duration_ms))
    }

    /// Throws the recording away.
    pub fn cancel(self) {
        let _ = self.pipeline.set_state(gst::State::Null);
        let _ = std::fs::remove_file(&self.path);
    }
}
