//! Voice-message recording.
//!
//! GTK has no capture API, so this drives `ffmpeg`, which is present on
//! essentially every desktop and speaks to PipeWire through its PulseAudio
//! compatibility layer. The output is Opus in an Ogg container: small (a
//! minute of speech is tens of KB), and playable by Android's `MediaPlayer`,
//! which matters because the phone is the other end of every one of these.
//!
//! Stopping is done by writing `q` to ffmpeg's stdin rather than killing it.
//! A signal — or worse, SIGKILL — leaves the container without its trailer,
//! and a truncated Ogg is exactly the kind of file that plays back here and
//! fails on the phone. `q` makes ffmpeg finalise properly.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// A capture in progress.
pub struct Recording {
    child: Child,
    path: PathBuf,
    started_at: u64,
}

/// Whether voice messages are possible at all on this machine.
pub fn is_available() -> bool {
    Command::new("ffmpeg")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

impl Recording {
    /// Starts capturing to a temporary file.
    pub fn start() -> Result<Self, String> {
        // Inside the 0700 data directory, not the shared `$TMPDIR`. The core
        // empties `plain_cache` at every start, which also removes a
        // recording a crash left behind.
        let path = crate::data_directory()
            .join("attachments/plain_cache")
            .join(format!("voice-{}.ogg", crate::util::now_ms()));

        let child = Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel", "error",
                // PipeWire answers on the Pulse socket; ALSA would grab the
                // device exclusively and fight whatever else is using it.
                "-f", "pulse",
                "-i", "default",
                // Mono at a voice bitrate: this is speech, not music, and the
                // file crosses a phone's data connection.
                "-ac", "1",
                "-c:a", "libopus",
                "-b:a", "24k",
                "-application", "voip",
                "-y",
            ])
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("could not start ffmpeg: {error}"))?;

        Ok(Self {
            child,
            path,
            started_at: crate::util::now_ms(),
        })
    }

    /// Milliseconds captured so far — drives the on-screen timer.
    pub fn elapsed_ms(&self) -> u64 {
        crate::util::now_ms().saturating_sub(self.started_at)
    }

    /// Finishes the recording and returns the finished file plus its duration.
    ///
    /// Blocking: it waits for ffmpeg to write the Ogg trailer. Call it off the
    /// main thread.
    pub fn finish(mut self) -> Result<(PathBuf, u32), String> {
        let duration_ms = self.elapsed_ms() as u32;

        if let Some(stdin) = self.child.stdin.as_mut() {
            // Ignore the error: if ffmpeg already exited the pipe is closed,
            // and `wait` below reports what actually happened.
            let _ = stdin.write_all(b"q\n");
            let _ = stdin.flush();
        }
        // Dropping stdin sends EOF, which also makes ffmpeg stop if the write
        // above did not land.
        drop(self.child.stdin.take());

        let output = self
            .child
            .wait_with_output()
            .map_err(|error| format!("ffmpeg did not finish: {error}"))?;

        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let detail = detail.trim();
            let _ = std::fs::remove_file(&self.path);
            return Err(if detail.is_empty() {
                "recording failed — is a microphone connected?".to_string()
            } else {
                detail.lines().last().unwrap_or(detail).to_string()
            });
        }

        let size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if size == 0 {
            let _ = std::fs::remove_file(&self.path);
            return Err("nothing was recorded".to_string());
        }

        Ok((self.path.clone(), duration_ms))
    }

    /// Throws the recording away.
    pub fn cancel(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.path);
    }
}
