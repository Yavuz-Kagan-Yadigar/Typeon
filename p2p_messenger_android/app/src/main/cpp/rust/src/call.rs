//! Voice/video calls, 1:1 and group, over a direct connection or the server.
//!
//! Three deliberately separate parts:
//!
//! - **Signalling** (`MessageContent::Call`) rides the normal ratchet path
//!   (`send_message_content`), so a ring reaches the peer over gossipsub OR the
//!   store-and-forward server, whichever works right now.
//! - **Media** never touches the core lock or the poll loop. Kotlin encodes
//!   (MediaCodec Opus / H.264) and hands opaque frames to `media_send`, which
//!   encrypts once and pushes into per-link channels. Tokio tasks drain those
//!   into long-lived libp2p streams (libp2p-stream). Connection tasks run on
//!   the tokio runtime, so bytes keep moving while the poll thread is busy or
//!   waiting. A request/response per frame would cost a substream and a
//!   multistream round trip per 60 ms audio packet — over Tor that is +1 RTT.
//! - **Path** per target device: a direct stream when we hold a live
//!   connection to it, otherwise the server relay stream (`RELAY_PROTOCOL`)
//!   addressed to `relay_mailbox_id(pair_key)`: an id only the sender and
//!   that receiver compute, which the receiver registers for the call
//!   (`relay_listen_keys`). The server pushes it to the target only if the
//!   target is connected at that moment; nothing is stored.
//!
//! Packet: `[ver=1][stream_id 8][seq u64 BE]` then ChaCha20-Poly1305 over
//! `[kind][sent_ms u32 BE][payload]` (`sent_ms` = wall clock mod 2^32, only for
//! the one-way delay estimate in the stats), header as AAD, nonce = `stream_id[..4] || seq`. Every
//! participant picks a fresh random key + stream id per call and ships them
//! inside the ratchet (Invite/Accept), so the server relays ciphertext only.
//! Each receiver gets its own key (`pair_key`): with one key per sender, any
//! group member could seal packets as any other member.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use futures::{AsyncReadExt as _, AsyncWriteExt as _, StreamExt as _};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;
use libp2p::{PeerId, StreamProtocol};
use log::{info, warn};
use rand::RngCore as _;
use zeroize::Zeroizing;

use crate::packet::{CallAction, MessageContent};
use crate::{current_time_ms, server_seal, P2PCore, OptionGroupExt as _, RUNTIME};

const KIND_AUDIO: u8 = 1;
const KIND_VIDEO: u8 = 2;

pub const MEDIA_PROTOCOL: StreamProtocol = StreamProtocol::new("/typeon/media/1.0.0");
pub const RELAY_PROTOCOL: StreamProtocol = StreamProtocol::new(crate::server_proto::RELAY_PROTOCOL);

/// Largest frame accepted from the wire. A 480p keyframe is ~20-60 KB.
pub const MAX_FRAME: usize = 256 * 1024;
/// Frames queued per link before new ones are dropped (~1-2 s of audio +
/// video). A filling queue is the congestion signal Kotlin reads through
/// `media_backlog` to lower the video frame rate and bitrate.
pub const LINK_QUEUE: usize = 48;
/// Queue depth above which a frame of that kind is dropped instead of queued.
/// The link is one ordered stream, so whatever is queued is delay for the
/// audio behind it: video yields first (a 40 KB keyframe is seconds on Tor),
/// audio keeps ~1 s at most. Reports and state use the whole queue.
const VIDEO_QUEUE_MAX: usize = 6;
const AUDIO_QUEUE_MAX: usize = 16;
/// A receiver-reported standing queue (ms) above which audio is held back at
/// the sender, and below which it resumes. The backlog lives in the Tor/TCP
/// pipe (hundreds of cells in flight), invisible to the local queue depth;
/// only not sending drains it. State and report packets keep flowing.
const AUDIO_HOLD_ABOVE_MS: u32 = 400;
const AUDIO_HOLD_BELOW_MS: u32 = 150;
/// Received frames waiting for Kotlin. ~1 s of a 3-way video call: a slow
/// decoder must shed old frames, never let them pile up (256 here once meant
/// 4-5 s of delay on a phone decoding two videos).
const INBOX_MAX: usize = 64;
/// Ring timeout, both directions.
const RING_TIMEOUT_MS: u64 = 45_000;
/// Every participant sends a state packet each second, even muted with the
/// camera off: this long with nothing from anyone means the others are gone
/// (app killed, device off, network lost) and never got to send a Hangup.
const MEDIA_LOST_MS: u64 = 30_000;
/// An Invite older than this (store-and-forward delivered it late) no longer rings.
const INVITE_MAX_AGE_MS: u64 = 60_000;
/// Bound on a group invite's participant list (C10).
const MAX_INVITE_PARTICIPANTS: usize = 1024;
const REOPEN_BACKOFF_MS: u64 = 3_000;
const OPEN_TIMEOUT: Duration = Duration::from_secs(20);
/// Inbound media streams one peer may hold at once (one is normal, a second
/// overlaps it while the peer reopens).
const MAX_INBOUND_PER_PEER: u8 = 4;
/// How long an inbound stream may stay open before its peer is a call target.
const INBOUND_GRACE: Duration = Duration::from_secs(5);

/// Receiver -> sender report, see `media_on_packet`. Never reaches Kotlin.
/// Payload `[target stream id 8][queue ms u16][flags u8]`, flag bit 0 =
/// "send me a keyframe" (RTCP PLI's job): lets the encoder run a long GOP
/// instead of paying for a keyframe every 2 s just in case someone lost one.
const KIND_REPORT: u8 = 3;
const REPORT_EVERY_MS: u64 = 500;
/// Sender -> everyone: `[flags u8]`, bit 0 muted, bit 1 camera off. Sent by
/// Kotlin on change and once a second (a muted sender sends no audio, so
/// silence alone cannot tell "muted" from "lost"). Never reaches Kotlin.
const KIND_STATE: u8 = 4;
/// A report older than this no longer counts as congestion.
const REPORT_TTL_MS: u64 = 3_000;
/// Keyframe requests honoured at most this often, whoever asks: a
/// participant setting the flag on every report would otherwise keep our
/// encoder in keyframe-per-frame mode.
const KEYFRAME_MIN_MS: u64 = 1_000;

const HEADER_LEN: usize = 17;
const TAG_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Wire framing (shared with typeon-server)
// ---------------------------------------------------------------------------

/// `[u16 mailbox len][mailbox][u32 len][data]` — see `server_proto::RELAY_PROTOCOL`.
/// Direct streams use the same framing with an empty mailbox.
pub fn encode_frame(mailbox: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + mailbox.len() + data.len());
    out.extend_from_slice(&(mailbox.len() as u16).to_be_bytes());
    out.extend_from_slice(mailbox);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Reads one frame: `(mailbox, data)`.
pub async fn read_frame<R: futures::AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut len2 = [0u8; 2];
    r.read_exact(&mut len2).await?;
    // A mailbox id is 64 hex characters. The length went straight into an
    // allocation: 64 KiB per stream for six header bytes.
    let mailbox_len = u16::from_be_bytes(len2) as usize;
    if mailbox_len > 128 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "mailbox too long"));
    }
    let mut mailbox = vec![0u8; mailbox_len];
    r.read_exact(&mut mailbox).await?;
    let mut len4 = [0u8; 4];
    r.read_exact(&mut len4).await?;
    let n = u32::from_be_bytes(len4) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    // Grows with the bytes that arrive: a declared length alone allocates nothing.
    let mut data = Vec::new();
    futures::AsyncReadExt::take(&mut *r, n as u64).read_to_end(&mut data).await?;
    if data.len() != n {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok((mailbox, data))
}

/// Drains `rx` into `w`. One `write_all` per already-framed buffer, so a small
/// audio packet leaves as one Tor cell instead of three.
pub async fn pump_writes<W: futures::AsyncWrite + Unpin>(mut w: W, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) {
    while let Some(buf) = rx.recv().await {
        // A peer that stopped reading must not park this task (and the substream) forever.
        let sent = tokio::time::timeout(Duration::from_secs(5), async { w.write_all(&buf).await?; w.flush().await }).await;
        if !matches!(sent, Ok(Ok(()))) {
            break;
        }
    }
    let _ = w.close().await;
}

// ---------------------------------------------------------------------------
// Packet crypto
// ---------------------------------------------------------------------------

fn nonce_for(sid: &[u8; 8], seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&sid[..4]);
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// The key this device seals with for one receiver: HKDF-SHA256 of the call's
/// master key (which never leaves this device) and the receiver's fingerprint.
/// The receiver gets it inside the ratchet and cannot compute anyone else's.
fn pair_key(master: &[u8; 32], receiver_fp: &str) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, master)
        .expand_multi_info(&[&b"typeon-call-pair-v1"[..], receiver_fp.as_bytes()], &mut key[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn seal_packet(key: &[u8; 32], sid: &[u8; 8], seq: u64, kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + 1 + payload.len() + TAG_LEN);
    out.push(1);
    out.extend_from_slice(sid);
    out.extend_from_slice(&seq.to_be_bytes());
    let mut pt = Vec::with_capacity(5 + payload.len());
    pt.push(kind);
    pt.extend_from_slice(&(current_time_ms() as u32).to_be_bytes());
    pt.extend_from_slice(payload);
    let ct = ChaCha20Poly1305::new(key.into())
        .encrypt(Nonce::from_slice(&nonce_for(sid, seq)), Payload { msg: &pt, aad: &out })
        .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
    out.extend_from_slice(&ct);
    out
}

/// `(stream_id, seq)` of a packet that is long enough to be one.
fn packet_header(packet: &[u8]) -> Option<([u8; 8], u64)> {
    if packet.len() < HEADER_LEN + 1 + TAG_LEN || packet[0] != 1 {
        return None;
    }
    let sid: [u8; 8] = packet[1..9].try_into().ok()?;
    let seq = u64::from_be_bytes(packet[9..17].try_into().ok()?);
    Some((sid, seq))
}

fn open_packet(key: &[u8; 32], sid: &[u8; 8], seq: u64, packet: &[u8]) -> Option<Vec<u8>> {
    let pt = ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(&nonce_for(sid, seq)),
            Payload { msg: &packet[HEADER_LEN..], aad: &packet[..HEADER_LEN] },
        )
        .ok()?;
    if pt.len() < 5 { None } else { Some(pt) }
}

// ---------------------------------------------------------------------------
// Media state — a process-wide static, deliberately NOT inside `P2PCore`
// ---------------------------------------------------------------------------

struct Remote {
    fp: String,
    slot: u8,
    key: Zeroizing<[u8; 32]>,
    /// Peer-chosen, so not unique: `Media.remotes` is keyed by `fp`.
    sid: [u8; 8],
    max_seq: u64,
    /// Bit `i` = `max_seq - i` was accepted. Two links (direct + relay during
    /// a switch) can deliver the same packet, and a replay must not play twice.
    seen: u64,
    last_rx_ms: u64,
    /// Monotonic twin of `last_rx_ms` for the lost-call timeout: a wall-clock
    /// step must not end a call.
    last_rx: Option<Instant>,
    /// One-way delay samples (receive time - sender's `sent_ms`). Absolute
    /// values carry the clock difference between the phones; `ewma - min` does
    /// not, and is the queue building up somewhere on the path.
    delay_ewma: f64,
    delay_min: f64,
    samples: u64,
    last_report_ms: u64,
    /// Our decoder for this sender lost sync (dropped frame, late join):
    /// ask for a keyframe in the next report.
    want_keyframe: bool,
    /// Last `KIND_STATE` flags from this sender.
    muted: bool,
    video_off: bool,
}

impl Remote {
    fn new(fp: &str, slot: u8, key: [u8; 32], sid: [u8; 8]) -> Self {
        Remote {
            fp: fp.to_string(), slot, key: Zeroizing::new(key), sid, max_seq: 0, seen: 0, last_rx_ms: 0, last_rx: None,
            delay_ewma: 0.0, delay_min: 0.0, samples: 0, last_report_ms: 0, want_keyframe: false,
            muted: false, video_off: false,
        }
    }
    fn is_new(&self, seq: u64) -> bool {
        seq > self.max_seq || (self.max_seq - seq < 64 && self.seen & (1 << (self.max_seq - seq)) == 0)
    }
    fn queue_ms(&self) -> u32 {
        (self.delay_ewma - self.delay_min).max(0.0) as u32
    }
    fn record_delay(&mut self, delay: f64) {
        if self.samples == 0 {
            self.delay_ewma = delay;
            self.delay_min = delay;
        } else {
            self.delay_ewma = self.delay_ewma * 0.9 + delay * 0.1;
            self.delay_min = self.delay_min.min(delay);
        }
        self.samples += 1;
    }
    fn record(&mut self, seq: u64) {
        if seq > self.max_seq {
            self.seen = u32::try_from(seq - self.max_seq).ok().and_then(|d| self.seen.checked_shl(d)).unwrap_or(0);
            self.max_seq = seq;
        }
        if self.max_seq - seq < 64 {
            self.seen |= 1 << (self.max_seq - seq);
        }
        self.last_rx_ms = current_time_ms();
        self.last_rx = Some(Instant::now());
    }
}

struct Target {
    /// Live connection to this device, refreshed every poll by `media_supervise`.
    peer: Option<PeerId>,
    /// `relay_mailbox_id(key)` — the relay address.
    mailbox: Vec<u8>,
    /// `pair_key` for this device: what we seal its copy of a frame with.
    key: Zeroizing<[u8; 32]>,
    /// Its audio copy held back, see [`AUDIO_HOLD_ABOVE_MS`]: decided by
    /// this device's own report, so one slow receiver mutes nobody else.
    audio_hold: bool,
    /// A server its frames reached us through: both are connected there, so
    /// our copy goes to that one server instead of to every one we use.
    relay_via: Option<PeerId>,
}

struct Link {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    id: u64,
}

#[derive(Default)]
struct Media {
    active: bool,
    /// Bumped on every start/stop so a link opened for a previous call never
    /// registers into the next one.
    generation: u64,
    /// Master key: only `pair_key` uses it, it is never sent.
    key: Zeroizing<[u8; 32]>,
    sid: [u8; 8],
    seq: u64,
    /// By device fingerprint. A stream id is peer-chosen: keyed by it, one
    /// group member could take another member's id and lock them out.
    remotes: HashMap<String, Remote>,
    next_slot: u8,
    targets: HashMap<String, Target>,
    direct: HashMap<PeerId, Link>,
    relays: HashMap<PeerId, Link>,
    /// Peer -> no new open attempt before this (ms): an open in flight
    /// (`OPEN_TIMEOUT`) or the `REOPEN_BACKOFF_MS` after a failed one.
    opening: HashMap<PeerId, u64>,
    /// Open inbound streams per peer (`MAX_INBOUND_PER_PEER`).
    inbound: HashMap<PeerId, u8>,
    next_link_id: u64,
    inbox: VecDeque<Vec<u8>>,
    sent: u64,
    received: u64,
    /// Outgoing copies dropped on a full link queue.
    dropped: u64,
    /// Received frames dropped because Kotlin fell behind (`INBOX_MAX`).
    rx_dropped: u64,
    via_direct: u64,
    via_relay: u64,
    /// Reporter device fingerprint -> (queue ms it sees on OUR stream, when).
    /// Tor/yamux buffer hundreds of KB inside the stream, so our own link
    /// queue stays empty while seconds pile up on the path — only the far
    /// end can see that.
    reports: HashMap<String, (u32, u64)>,
    /// A receiver asked us for a keyframe; Kotlin takes it via `media_take_keyframe_request`.
    keyframe_asked: bool,
    /// When `keyframe_asked` was last set (`KEYFRAME_MIN_MS`).
    keyframe_at: u64,
    /// Encrypted media bytes queued out (per copy) / accepted in.
    bytes_out: u64,
    bytes_in: u64,
}

lazy_static::lazy_static! {
    static ref MEDIA: Mutex<Media> = Mutex::new(Media::default());
    static ref INBOX_READY: Condvar = Condvar::new();
    /// `(call id, sender)` of the last Hangup for a call we did not have:
    /// only that sender's Invite for it is then dropped (a Hangup that
    /// overtook its Invite), not one from another group member.
    static ref EARLY_HANGUP: Mutex<Option<(String, String)>> = Mutex::new(None);
}

fn media() -> MutexGuard<'static, Media> {
    MEDIA.lock().unwrap_or_else(|p| p.into_inner())
}

fn media_start(key: [u8; 32], sid: [u8; 8]) {
    let mut m = media();
    let generation = m.generation + 1;
    let next_link_id = m.next_link_id;
    *m = Media { active: true, generation, key: Zeroizing::new(key), sid, next_link_id, ..Default::default() };
}

/// Dropping the links closes their channels, which ends the writer tasks and
/// closes the streams (the server then forgets our relay link).
fn media_stop() {
    let mut m = media();
    let generation = m.generation + 1;
    let next_link_id = m.next_link_id;
    *m = Media { generation, next_link_id, ..Default::default() };
    drop(m);
    INBOX_READY.notify_all();
}

/// See `wipe_all_local_state`.
pub(crate) fn drop_media() {
    media_stop();
}

fn media_add_remote(fp: &str, key: &[u8], sid: &[u8]) {
    let (Ok(key), Ok(sid)) = (<[u8; 32]>::try_from(key), <[u8; 8]>::try_from(sid)) else { return };
    let mut m = media();
    if !m.active || m.remotes.get(fp).map_or(false, |r| r.sid == sid && *r.key == key) {
        return;
    }
    // A re-key keeps the device's slot (Kotlin holds one decoder per slot,
    // and a fresh slot per Accept would wrap into someone else's).
    let slot = match m.remotes.get(fp) {
        Some(r) => r.slot,
        // The next slot nobody holds. The bare counter wrapped after 256
        // joins (a participant alternating Hangup and Accept) into a slot in
        // use, and its frames were shown as the other participant's.
        None => {
            let from = m.next_slot;
            let Some(s) = (0..=u8::MAX).map(|i| from.wrapping_add(i)).find(|s| !m.remotes.values().any(|r| r.slot == *s)) else { return };
            m.next_slot = s.wrapping_add(1);
            s
        }
    };
    let mut remote = Remote::new(fp, slot, key, sid);
    // Same key again (a repeated Accept with another stream id): keep the
    // replay window, or `seq` would count from 1 again under that key.
    if let Some(old) = m.remotes.get(fp).filter(|r| *r.key == key) {
        remote.max_seq = old.max_seq;
        remote.seen = old.seen;
    }
    m.remotes.insert(fp.to_string(), remote);
    let send_key = pair_key(&m.key, fp);
    let mailbox = server_seal::relay_mailbox_id(&send_key[..]).into_bytes();
    m.targets.insert(fp.to_string(), Target { peer: None, mailbox, key: send_key, audio_hold: false, relay_via: None });
}

/// The keys the call's remotes seal our media with. Each gives the relay
/// address its sender writes to (`server_seal::relay_mailbox_id`), which this
/// device registers at its servers while the call runs.
pub(crate) fn relay_listen_keys() -> Vec<Vec<u8>> {
    media().remotes.values().map(|r| r.key.to_vec()).collect()
}

fn media_remove_remote(fp: &str) {
    let mut m = media();
    m.remotes.remove(fp);
    m.targets.remove(fp);
}

fn media_slot_of(fp: &str) -> Option<u8> {
    media().remotes.get(fp).map(|r| r.slot)
}

/// `(muted, camera off)` as last announced by `fp`.
fn media_flags_of(fp: &str) -> (bool, bool) {
    media().remotes.get(fp).map(|r| (r.muted, r.video_off)).unwrap_or_default()
}

fn media_last_rx(fp: &str) -> u64 {
    media().remotes.get(fp).map(|r| r.last_rx_ms).unwrap_or(0)
}

/// Time since the last packet from `fp`, on the monotonic clock.
fn media_rx_age(fp: &str) -> Option<Duration> {
    media().remotes.get(fp).and_then(|r| r.last_rx).map(|t| t.elapsed())
}

fn media_stats() -> serde_json::Value {
    let m = media();
    serde_json::json!({
        "sent": m.sent, "received": m.received, "dropped": m.dropped, "rx_dropped": m.rx_dropped,
        "via_direct": m.via_direct, "via_relay": m.via_relay,
        "direct_links": m.direct.len(), "relay_links": m.relays.len(),
        "backlog": backlog_of(&m),
        "tx_queue_ms": reported_queue(&m),
        "rx_queue_ms": m.remotes.values().map(|r| r.queue_ms()).max().unwrap_or(0),
        "rx_delay_ms": m.remotes.values().map(|r| r.delay_ewma as i64).max().unwrap_or(0),
        "bytes_out": m.bytes_out, "bytes_in": m.bytes_in,
    })
}

/// Congestion signal for Kotlin, in "frames": the deepest local link queue,
/// or the worst queueing delay a receiver reports on our stream (100 ms = 1).
fn backlog_of(m: &Media) -> usize {
    let local = m.direct.values().chain(m.relays.values()).map(|l| LINK_QUEUE - l.tx.capacity()).max().unwrap_or(0);
    local.max(reported_queue(m) as usize / 100)
}

fn reported_queue(m: &Media) -> u32 {
    let now = current_time_ms();
    m.reports.values().filter(|(_, at)| now.saturating_sub(*at) < REPORT_TTL_MS).map(|(q, _)| *q).max().unwrap_or(0)
}

fn depth_max(kind: u8) -> usize {
    match kind {
        KIND_VIDEO => VIDEO_QUEUE_MAX,
        KIND_REPORT | KIND_STATE => LINK_QUEUE,
        _ => AUDIO_QUEUE_MAX,
    }
}

/// Encrypts one frame and queues it for every call participant. Never blocks:
/// a full link queue drops the frame (live media, late = useless).
pub fn media_send(kind: u8, payload: &[u8]) -> bool {
    media_send_to(kind, payload, None)
}

/// `media_send`, to the one device `only` when given (a report is about
/// that sender's stream only).
fn media_send_to(kind: u8, payload: &[u8], only: Option<&str>) -> bool {
    use tokio::sync::mpsc::error::TrySendError;
    let mut m = media();
    if !m.active || m.targets.is_empty() || payload.len() > MAX_FRAME - 64 {
        return false;
    }
    if kind == KIND_AUDIO {
        let now = current_time_ms();
        let Media { targets, reports, .. } = &mut *m;
        for (fp, t) in targets.iter_mut() {
            let q = reports.get(fp).filter(|(_, at)| now.saturating_sub(*at) < REPORT_TTL_MS).map_or(0, |(q, _)| *q);
            if t.audio_hold && q < AUDIO_HOLD_BELOW_MS {
                t.audio_hold = false;
            } else if !t.audio_hold && q > AUDIO_HOLD_ABOVE_MS {
                t.audio_hold = true;
            }
        }
        let held = m.targets.values().filter(|t| t.audio_hold).count();
        if held == m.targets.len() {
            return false;
        }
    }
    m.seq += 1;
    let targets: Vec<(Option<PeerId>, Option<PeerId>, Vec<u8>, Vec<u8>)> = m
        .targets
        .iter()
        .filter(|(fp, t)| (kind != KIND_AUDIO || !t.audio_hold) && only.map_or(true, |o| o == fp.as_str()))
        .map(|(_, t)| (t.peer, t.relay_via, t.mailbox.clone(), seal_packet(&t.key, &m.sid, m.seq, kind, payload)))
        .collect();
    let mut any = false;
    for (peer, relay_via, mailbox, packet) in targets {
        if let Some(p) = peer {
            let res = m.direct.get(&p).map(|l| {
                if LINK_QUEUE - l.tx.capacity() >= depth_max(kind) { Err(TrySendError::Full(Vec::new())) }
                else { l.tx.try_send(encode_frame(&[], &packet)) }
            });
            match res {
                Some(Ok(())) => { m.via_direct += 1; m.bytes_out += packet.len() as u64; any = true; continue; }
                Some(Err(TrySendError::Full(_))) => { m.dropped += 1; continue; }
                Some(Err(TrySendError::Closed(_))) => { m.direct.remove(&p); }
                None => {}
            }
        }
        // The server its frames came through, else every relay link: a
        // server without a listener for the mailbox drops the frame while
        // `try_send` still succeeds.
        let servers: Vec<PeerId> = match relay_via.filter(|s| m.relays.contains_key(s)) {
            Some(s) => vec![s],
            None => m.relays.keys().copied().collect(),
        };
        let frame = encode_frame(&mailbox, &packet);
        let mut relayed = false;
        for s in servers {
            let l = &m.relays[&s];
            let r = if LINK_QUEUE - l.tx.capacity() >= depth_max(kind) { Err(TrySendError::Full(Vec::new())) } else { l.tx.try_send(frame.clone()) };
            match r {
                Ok(()) => { m.bytes_out += packet.len() as u64; relayed = true; }
                Err(TrySendError::Full(_)) => { m.dropped += 1; }
                Err(TrySendError::Closed(_)) => { m.relays.remove(&s); }
            }
        }
        if relayed {
            m.via_relay += 1;
            any = true;
        }
    }
    if any {
        m.sent += 1;
    }
    any
}

/// Largest per-link queue depth, in frames (0..=`LINK_QUEUE`).
pub fn media_backlog() -> usize {
    backlog_of(&media())
}

fn media_on_packet(packet: &[u8]) {
    media_on_packet_via(packet, None)
}

/// Any packet from any link (direct, inbound, relay) ends up here. `via`:
/// the server of a relay link.
fn media_on_packet_via(packet: &[u8], via: Option<PeerId>) {
    let Some((sid, seq)) = packet_header(packet) else { return };
    let mut m = media();
    if !m.active {
        return;
    }
    // Several remotes may claim one stream id; the AEAD key says whose it is.
    let Some((fp, pt)) = m
        .remotes
        .values()
        .filter(|r| r.sid == sid && r.is_new(seq))
        .find_map(|r| open_packet(&r.key, &sid, seq, packet).map(|pt| (r.fp.clone(), pt)))
    else {
        return;
    };
    let now = current_time_ms();
    let sent_ms = u32::from_be_bytes([pt[1], pt[2], pt[3], pt[4]]);
    // A hostile `sent_ms` must not skew the EWMA beyond +-10 min.
    let delay = ((now as u32).wrapping_sub(sent_ms) as i32 as f64).clamp(-600_000.0, 600_000.0);
    if let Some(server) = via {
        if let Some(t) = m.targets.get_mut(&fp) {
            t.relay_via = Some(server);
        }
    }
    let Some(r) = m.remotes.get_mut(&fp) else { return };
    let slot = r.slot;
    r.record(seq);
    r.record_delay(delay);
    if pt[0] == KIND_STATE {
        if let Some(&flags) = pt.get(5) {
            r.muted = flags & 1 != 0;
            r.video_off = flags & 2 != 0;
        }
        return;
    }
    if pt[0] == KIND_REPORT {
        if pt.len() >= 5 + 10 && pt[5..13] == m.sid {
            let q = u16::from_be_bytes([pt[13], pt[14]]) as u32;
            m.reports.insert(fp.clone(), (q, now));
            if pt.len() >= 16 && pt[15] & 1 != 0 && now.saturating_sub(m.keyframe_at) >= KEYFRAME_MIN_MS {
                m.keyframe_asked = true;
                m.keyframe_at = now;
            }
        }
        return;
    }
    let report = (r.want_keyframe || now.saturating_sub(r.last_report_ms) >= REPORT_EVERY_MS).then(|| {
        r.last_report_ms = now;
        let mut p = sid.to_vec();
        p.extend_from_slice(&(r.queue_ms().min(u16::MAX as u32) as u16).to_be_bytes());
        p.push(r.want_keyframe as u8);
        r.want_keyframe = false;
        p
    });
    let mut out = Vec::with_capacity(pt.len() - 3);
    out.push(pt[0]);
    out.push(slot);
    out.extend_from_slice(&pt[5..]);
    m.received += 1;
    m.bytes_in += packet.len() as u64;
    if m.inbox.len() >= INBOX_MAX {
        // After a Tor stall frames arrive in a burst: shed the oldest video
        // first (costs a frozen picture until the next keyframe), audio last.
        // Without video, the oldest frame of the same sender: one flooding
        // participant must not push out the others' audio.
        let victim = m
            .inbox
            .iter()
            .position(|f| f[0] == KIND_VIDEO)
            .or_else(|| m.inbox.iter().position(|f| f[1] == slot))
            .unwrap_or(0);
        if let Some(f) = m.inbox.remove(victim) {
            if f[0] == KIND_VIDEO {
                // The decoder now has a hole; get it a fresh keyframe.
                m.remotes.values_mut().filter(|r| r.slot == f[1]).for_each(|r| r.want_keyframe = true);
            }
        }
        m.rx_dropped += 1;
    }
    m.inbox.push_back(out);
    drop(m);
    INBOX_READY.notify_one();
    if let Some(p) = report {
        media_send_to(KIND_REPORT, &p, Some(fp.as_str()));
    }
}

/// Kotlin's decoder for `slot` cannot decode until the next keyframe.
pub fn media_request_keyframe(slot: u8) {
    media().remotes.values_mut().filter(|r| r.slot == slot).for_each(|r| r.want_keyframe = true);
}

/// Some receiver asked for a keyframe since the last call.
pub fn media_take_keyframe_request() -> bool {
    std::mem::take(&mut media().keyframe_asked)
}

/// Next received frame as `[kind][slot][payload]`, or `None` after `timeout_ms`.
pub fn media_recv(timeout_ms: u64) -> Option<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut m = media();
    loop {
        if let Some(p) = m.inbox.pop_front() {
            return Some(p);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        m = match INBOX_READY.wait_timeout(m, deadline - now) {
            Ok((g, _)) => g,
            Err(p) => p.into_inner().0,
        };
    }
}

/// Opens the links the call needs and is missing. Called from the poll loop;
/// the opening itself happens on tokio.
fn media_supervise(control: &libp2p_stream::Control, peers: Vec<(String, Option<PeerId>)>, servers: Vec<PeerId>) {
    let now = current_time_ms();
    let mut m = media();
    if !m.active {
        return;
    }
    for (fp, peer) in peers {
        if let Some(t) = m.targets.get_mut(&fp) {
            t.peer = peer;
        }
    }
    let mut wanted: Vec<(PeerId, bool)> = m
        .targets
        .values()
        .filter_map(|t| t.peer)
        .filter(|p| !m.direct.contains_key(p))
        .map(|p| (p, false))
        .collect();
    wanted.extend(servers.into_iter().filter(|p| !m.relays.contains_key(p)).map(|p| (p, true)));
    for (peer, relay) in wanted {
        if m.opening.get(&peer).map_or(false, |until| now < *until) {
            continue;
        }
        m.opening.insert(peer, now + OPEN_TIMEOUT.as_millis() as u64 + REOPEN_BACKOFF_MS);
        let control = control.clone();
        let generation = m.generation;
        RUNTIME.spawn(open_link(control, peer, relay, generation));
    }
}

async fn open_link(mut control: libp2p_stream::Control, peer: PeerId, relay: bool, generation: u64) {
    let what = if relay { "sunucu" } else { "doğrudan" };
    let proto = if relay { RELAY_PROTOCOL } else { MEDIA_PROTOCOL };
    let opened = match tokio::time::timeout(OPEN_TIMEOUT, control.open_stream(peer, proto)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("zaman aşımı".to_string()),
    };
    let stream = match opened {
        Ok(s) => s,
        Err(e) => {
            warn!("Arama akışı açılamadı ({}, {}): {}", what, crate::log_id(&peer), e);
            let mut m = media();
            if m.generation == generation {
                m.opening.insert(peer, current_time_ms() + REOPEN_BACKOFF_MS);
            }
            return;
        }
    };
    let (mut rd, wr) = stream.split();
    let (tx, rx) = tokio::sync::mpsc::channel(LINK_QUEUE);
    let id = {
        let mut m = media();
        if !m.active || m.generation != generation {
            return;
        }
        m.next_link_id += 1;
        let id = m.next_link_id;
        let link = Link { tx, id };
        if relay { m.relays.insert(peer, link); } else { m.direct.insert(peer, link); }
        m.opening.remove(&peer);
        id
    };
    info!("Arama akışı açıldı ({}, {})", what, crate::log_id(&peer));
    tokio::spawn(pump_writes(wr, rx));
    // Relay links carry the server's pushes back to us; on a direct outbound
    // link the read only notices the peer closing it.
    // Bounded wait: after the call ends a silent link (a direct one never
    // carries anything back) must not keep this task and the stream until
    // the far end closes it. A wait that times out has read nothing, unless
    // one frame took that long, which a live link does not.
    let via = relay.then_some(peer);
    'link: loop {
        // The same future survives a timeout: dropping it mid-frame would eat
        // part of a header and desync the next read.
        let mut next = Box::pin(read_frame(&mut rd));
        let frame = loop {
            match tokio::time::timeout(Duration::from_millis(MEDIA_LOST_MS), &mut next).await {
                Ok(r) => break r,
                Err(_) if media().generation != generation => break 'link,
                Err(_) => {}
            }
        };
        let Ok((_, data)) = frame else { break };
        if media().generation != generation {
            break;
        }
        media_on_packet_via(&data, via);
    }
    let mut m = media();
    let map = if relay { &mut m.relays } else { &mut m.direct };
    if map.get(&peer).map(|l| l.id) == Some(id) {
        map.remove(&peer);
    }
    // A link that opened and closed is not reopened on the very next sweep.
    if m.generation == generation {
        m.opening.insert(peer, current_time_ms() + REOPEN_BACKOFF_MS);
    }
    info!("Arama akışı kapandı ({}, {})", what, crate::log_id(&peer));
}

/// Reads media frames peers push to us over direct streams. Registered once
/// per swarm (`start_network`).
pub(crate) fn spawn_media_acceptor(control: &mut libp2p_stream::Control) {
    let mut incoming = match control.accept(MEDIA_PROTOCOL) {
        Ok(i) => i,
        Err(e) => { warn!("Arama akışı dinleyicisi kurulamadı: {}", e); return; }
    };
    RUNTIME.spawn(async move {
        while let Some((peer, mut stream)) = incoming.next().await {
            // Outside a call nobody has a reason to push media: drop the
            // stream instead of parking a reader (and up to MAX_FRAME) on it.
            let generation = {
                let mut m = media();
                if !m.active {
                    continue;
                }
                let open = m.inbound.entry(peer).or_insert(0);
                if *open >= MAX_INBOUND_PER_PEER {
                    continue;
                }
                *open += 1;
                m.generation
            };
            // Ends with the call, and on a silent stream: every participant
            // sends a state packet each second.
            // Only from a device in the call. `Target::peer` is filled by the
            // next poll turn, so a stream that arrives first gets
            // `INBOUND_GRACE` in total, however little it sends.
            tokio::spawn(async move {
                let idle = Duration::from_millis(MEDIA_LOST_MS);
                let opened = Instant::now();
                loop {
                    let wait = {
                        let m = media();
                        if m.generation != generation {
                            break;
                        }
                        if m.targets.values().any(|t| t.peer == Some(peer)) {
                            idle
                        } else {
                            match INBOUND_GRACE.checked_sub(opened.elapsed()) {
                                Some(left) => left,
                                None => break,
                            }
                        }
                    };
                    let Ok(Ok((_, data))) = tokio::time::timeout(wait, read_frame(&mut stream)).await else { break };
                    media_on_packet(&data);
                }
                let mut m = media();
                if m.generation == generation {
                    let left = m.inbound.get(&peer).map_or(0, |n| n.saturating_sub(1));
                    if left == 0 {
                        m.inbound.remove(&peer);
                    } else {
                        m.inbound.insert(peer, left);
                    }
                }
            });
        }
    });
}

// ---------------------------------------------------------------------------
// Call session (signalling) — lives in `P2PCore.call`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallPhase {
    Outgoing,
    Incoming,
    Active,
}

pub(crate) struct CallSession {
    call_id: String,
    group_id: Option<String>,
    video: bool,
    phase: CallPhase,
    /// The device that rang us (Incoming) or the 1:1 callee (Outgoing); empty
    /// for an outgoing group call.
    peer_fp: String,
    /// Devices this call signals to: 1:1 the peer, group every other member's
    /// active device.
    invited: Vec<String>,
    /// Remote media keys learned so far, kept while still ringing so a group
    /// member who answered before us is wired up the moment we answer.
    keys: HashMap<String, (Zeroizing<Vec<u8>>, Vec<u8>)>,
    /// Devices currently in the call (media flows to/from these).
    joined: HashSet<String>,
    /// Master key, see `pair_key`.
    my_key: Zeroizing<[u8; 32]>,
    my_sid: [u8; 8],
    started_at: u64,
    connected_at: u64,
    /// Monotonic twins of the two above, for the timeouts.
    started: Instant,
    connected: Option<Instant>,
    /// Stream ids of participants that left: a replayed Accept must not add
    /// them back with a fresh replay window.
    retired: HashSet<Vec<u8>>,
}

impl CallSession {
    fn new(call_id: String, group_id: Option<String>, video: bool, phase: CallPhase, peer_fp: String, invited: Vec<String>) -> Self {
        let mut my_key = Zeroizing::new([0u8; 32]);
        let mut my_sid = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut my_key[..]);
        rand::rngs::OsRng.fill_bytes(&mut my_sid);
        CallSession {
            call_id, group_id, video, phase, peer_fp, invited,
            keys: HashMap::new(), joined: HashSet::new(),
            my_key, my_sid, started_at: current_time_ms(), connected_at: 0,
            started: Instant::now(), connected: None, retired: HashSet::new(),
        }
    }
}

fn noop() -> serde_json::Value {
    serde_json::json!({"type": "noop"})
}

static LAST_CALL_SIG: Mutex<String> = Mutex::new(String::new());

impl P2PCore {
    pub(crate) fn start_call(&mut self, peer_fp: String, video: bool) -> Result<String, String> {
        if self.call.is_some() {
            return Err("Zaten bir arama sürüyor".to_string());
        }
        // Ring EVERY active device of the contact: the chat's key is the
        // lowest fingerprint, which can be a long-dead old phone (seen on
        // device: the invite went only there and nothing rang). First to
        // answer wins, see the Accept arm.
        let invited: Vec<String> = self.fanout_targets(&peer_fp).into_iter().filter(|fp| self.ratchets.contains_key(fp)).collect();
        if invited.is_empty() {
            return Err("Bu kişiyle oturum yok".to_string());
        }
        let call_id = uuid::Uuid::new_v4().to_string();
        let s = CallSession::new(call_id.clone(), None, video, CallPhase::Outgoing, peer_fp, invited);
        media_start(*s.my_key, s.my_sid);
        self.call = Some(s);
        self.call_broadcast(CallAction::Invite);
        info!("Arama başlatıldı: {} video={}", &call_id[..8], video);
        Ok(call_id)
    }

    pub(crate) fn start_group_call(&mut self, group_id: String, video: bool) -> Result<String, String> {
        if self.call.is_some() {
            return Err("Zaten bir arama sürüyor".to_string());
        }
        let invited = self.group_call_devices(&group_id)?;
        if invited.is_empty() {
            return Err("Aranabilecek üye yok".to_string());
        }
        let call_id = uuid::Uuid::new_v4().to_string();
        let s = CallSession::new(call_id.clone(), Some(group_id), video, CallPhase::Outgoing, String::new(), invited);
        media_start(*s.my_key, s.my_sid);
        self.call = Some(s);
        self.call_broadcast(CallAction::Invite);
        info!("Grup araması başlatıldı: {} video={}", &call_id[..8], video);
        Ok(call_id)
    }

    pub(crate) fn accept_call(&mut self) -> Result<(), String> {
        let s = self.call.as_mut().ok_or("Arama yok")?;
        if s.phase != CallPhase::Incoming {
            return Err("Cevaplanacak arama yok".to_string());
        }
        s.phase = CallPhase::Active;
        s.connected_at = current_time_ms();
        s.connected = Some(Instant::now());
        media_start(*s.my_key, s.my_sid);
        for fp in &s.joined {
            if let Some((k, sid)) = s.keys.get(fp) {
                media_add_remote(fp, k, sid);
            }
        }
        // Register the relay addresses now (bkz. `relay_listen_keys`).
        self.server_sweep_at = 0;
        self.call_broadcast(CallAction::Accept);
        Ok(())
    }

    /// Reject while ringing, hang up otherwise.
    pub(crate) fn end_call(&mut self) {
        self.end_call_with("local");
    }

    /// `end_call`, with the reason `call_state_json` reports afterwards.
    fn end_call_with(&mut self, reason: &str) {
        let Some(s) = self.call.take() else { return };
        let (action, to) = if s.phase == CallPhase::Incoming {
            (CallAction::Reject, vec![s.peer_fp.clone()])
        } else {
            (CallAction::Hangup, s.invited.clone())
        };
        for fp in to {
            self.call_signal(&fp, &s, action);
        }
        media_stop();
        self.last_call_end = Some((s.call_id, reason.to_string()));
    }

    fn group_call_devices(&self, group_id: &str) -> Result<Vec<String>, String> {
        let me = self.my_identity_id().ok_or("Kimlik yok")?;
        let group = self.groups.get(group_id).cloned_group()?;
        // All devices of every member (see `start_call` for why not one).
        Ok(group
            .other_members(&me)
            .iter()
            .flat_map(|id| self.active_devices_for_identity(id))
            .filter(|fp| self.device_recently_seen(fp))
            .collect())
    }

    fn call_broadcast(&mut self, action: CallAction) {
        let Some(s) = self.call.take() else { return };
        for fp in &s.invited {
            self.call_signal(fp, &s, action);
        }
        self.call = Some(s);
    }

    fn call_signal(&mut self, fp: &str, s: &CallSession, action: CallAction) {
        let with_keys = matches!(action, CallAction::Invite | CallAction::Accept);
        let keys = with_keys.then(|| (pair_key(&s.my_key, fp).to_vec(), s.my_sid.to_vec()));
        // C10: a group invite names everyone rung, so callees connect to each
        // other even when each thinks the other is stale.
        let participants = if action == CallAction::Invite && s.group_id.is_some() { s.invited.clone() } else { Vec::new() };
        self.send_call_signal(fp, &s.call_id, s.group_id.clone(), s.video, action, keys, participants);
    }

    #[allow(clippy::too_many_arguments)]
    fn send_call_signal(&mut self, fp: &str, call_id: &str, group_id: Option<String>, video: bool, action: CallAction, keys: Option<(Vec<u8>, Vec<u8>)>, participants: Vec<String>) {
        let (media_key, stream_id) = keys.unwrap_or_default();
        let content = MessageContent::Call {
            call_id: call_id.to_string(),
            action,
            group_id,
            video,
            media_key,
            stream_id,
            sent_at_ms: current_time_ms(),
            participants,
        };
        self.call_signal_sending = true;
        let sent = self.send_message_content(fp.to_string(), &content, None);
        self.call_signal_sending = false;
        if let Err(e) = sent {
            warn!("Arama sinyali gönderilemedi ({:?} -> {}): {}", action, &fp[..8.min(fp.len())], e);
        }
    }

    /// `receive_message` arm for `MessageContent::Call`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_call_signal(
        &mut self,
        peer_fp: &str,
        sender_identity_id: &str,
        call_id: String,
        action: CallAction,
        group_id: Option<String>,
        video: bool,
        media_key: Vec<u8>,
        stream_id: Vec<u8>,
        sent_at_ms: u64,
        participants: Vec<String>,
    ) -> serde_json::Value {
        let now = current_time_ms();
        let keys_ok = media_key.len() == 32 && stream_id.len() == 8;
        let is_member = |core: &P2PCore, gid: &str| {
            core.groups.get(gid).map_or(false, |g| g.members.iter().any(|m| m.identity_id == sender_identity_id))
        };
        // `call_id` is the peer's string: bound it, and never byte-slice it (a
        // multi-byte char at the cut panics inside `poll_events`).
        if call_id.len() > 64 {
            return noop();
        }
        info!("Arama sinyali: {:?} arama={} kimden={}", action, call_id.chars().take(8).collect::<String>(), peer_fp.chars().take(8).collect::<String>());
        match action {
            CallAction::Invite => {
                // ponytail: the age compares two devices' clocks, so a caller
                // more than a minute behind never rings and one ahead can ring
                // late. A clock-free age needs the server to stamp how long it
                // held the item (`MailItem` carries none).
                // Not from the future either: a `sent_at_ms` far ahead passed
                // the age test for good, and a held invite rang whenever it
                // was delivered.
                if !keys_ok || sent_at_ms == 0 || now.abs_diff(sent_at_ms) > INVITE_MAX_AGE_MS {
                    return noop();
                }
                // The call already ended here; also a Hangup that overtook its
                // Invite (two envelopes, two paths).
                let early_hangup = EARLY_HANGUP
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .as_ref()
                    .map_or(false, |(id, fp)| *id == call_id && fp == peer_fp);
                if early_hangup || self.last_call_end.as_ref().map_or(false, |(id, _)| *id == call_id) {
                    return noop();
                }
                // 1:1 rings only from a contact (a group co-member with a
                // pairwise session is not one).
                if group_id.is_none() && !self.identity_to_contact.contains_key(sender_identity_id) {
                    return noop();
                }
                if let Some(gid) = &group_id {
                    if !is_member(self, gid) {
                        return noop();
                    }
                }
                let current = self.call.as_ref().map(|s| {
                    let glare = s.phase == CallPhase::Outgoing
                        && s.group_id.is_none()
                        && group_id.is_none()
                        && s.invited.iter().any(|f| f == peer_fp);
                    // The device ringing us called again: it cancelled the old
                    // call and that Hangup is late or lost.
                    let redial = s.phase == CallPhase::Incoming && s.peer_fp == peer_fp;
                    (s.call_id.clone(), glare, redial)
                });
                if let Some((ours, glare, redial)) = current {
                    if ours == call_id {
                        return noop();
                    }
                    if redial {
                        self.call = None;
                        self.last_call_end = Some((ours, "remote".to_string()));
                    } else if !glare {
                        self.send_call_signal(peer_fp, &call_id, group_id, video, CallAction::Busy, None, Vec::new());
                        return noop();
                    } else {
                        // Both called each other at once. Busy from both ended
                        // both calls; instead the lower call id wins on both
                        // sides: its caller ignores the other Invite, the other
                        // side drops its own call and rings for this one.
                        if ours < call_id {
                            return noop();
                        }
                        self.end_call();
                    }
                }
                let mut invited = match &group_id {
                    Some(gid) => self.group_call_devices(gid).unwrap_or_default(),
                    None => Vec::new(),
                };
                // C10: also every device the caller rang that is an active
                // device of a member here (stale or not); never mine.
                if let Some(gid) = &group_id {
                    let own = self.get_active_own_device_fingerprint().unwrap_or_default();
                    let me = self.my_identity_id().unwrap_or_default();
                    let member_devices: HashSet<String> = self.groups.get(gid)
                        .map(|g| g.other_members(&me).iter().flat_map(|id| self.active_devices_for_identity(id)).collect())
                        .unwrap_or_default();
                    for fp in participants.into_iter().take(MAX_INVITE_PARTICIPANTS) {
                        if fp != own && member_devices.contains(&fp) && !invited.contains(&fp) {
                            invited.push(fp);
                        }
                    }
                }
                if !invited.iter().any(|f| f == peer_fp) {
                    invited.push(peer_fp.to_string());
                }
                let mut s = CallSession::new(call_id.clone(), group_id.clone(), video, CallPhase::Incoming, peer_fp.to_string(), invited);
                s.keys.insert(peer_fp.to_string(), (Zeroizing::new(media_key), stream_id));
                s.joined.insert(peer_fp.to_string());
                self.call = Some(s);
                let name = self.call_title();
                serde_json::json!({
                    "type": "call", "action": "invite", "call_id": call_id,
                    "peer": self.canonical_peer_key(peer_fp), "group_id": group_id,
                    "video": video, "name": name,
                })
            }
            CallAction::Accept => {
                if !keys_ok {
                    return noop();
                }
                let group = self.call.as_ref().and_then(|s| s.group_id.clone());
                let member = group.as_deref().map_or(false, |gid| is_member(self, gid));
                let Some(s) = self.call.as_mut() else { return noop() };
                if s.call_id != call_id || s.retired.contains(&stream_id) {
                    return noop();
                }
                if !s.invited.iter().any(|f| f == peer_fp) {
                    if !member {
                        return noop();
                    }
                    s.invited.push(peer_fp.to_string());
                }
                let was_active = s.phase == CallPhase::Active;
                let new_key = s.keys.insert(peer_fp.to_string(), (Zeroizing::new(media_key.clone()), stream_id.clone())).is_none();
                s.joined.insert(peer_fp.to_string());
                // Group: a joiner we never sent our key to (it was missing
                // from our invited list, or its Accept reached us before the
                // Invite did on its side) would hear nothing from us. Answer a
                // first-seen key once; the reply carries a known key back, so
                // it stops there.
                let reply = (was_active && new_key && s.group_id.is_some())
                    .then(|| (s.call_id.clone(), s.group_id.clone(), s.video, (pair_key(&s.my_key, peer_fp).to_vec(), s.my_sid.to_vec())));
                let mut stop_ringing = Vec::new();
                if s.phase == CallPhase::Outgoing {
                    s.phase = CallPhase::Active;
                    s.connected_at = now;
                    s.connected = Some(Instant::now());
                    // 1:1 rang several devices of one person: answered on
                    // this one, silence the others.
                    if s.group_id.is_none() {
                        stop_ringing = s.invited.iter().filter(|f| *f != peer_fp).cloned().collect();
                        s.invited = vec![peer_fp.to_string()];
                        s.peer_fp = peer_fp.to_string();
                    }
                }
                if s.phase == CallPhase::Active {
                    media_add_remote(peer_fp, &media_key, &stream_id);
                    self.server_sweep_at = 0;
                }
                if !stop_ringing.is_empty() {
                    let (cid, video) = (s.call_id.clone(), s.video);
                    for fp in stop_ringing {
                        self.send_call_signal(&fp, &cid, None, video, CallAction::Hangup, None, Vec::new());
                    }
                }
                if let Some((cid, gid, video, keys)) = reply {
                    self.send_call_signal(peer_fp, &cid, gid, video, CallAction::Accept, Some(keys), Vec::new());
                }
                serde_json::json!({"type": "call", "action": "accept", "call_id": call_id, "peer": self.canonical_peer_key(peer_fp)})
            }
            CallAction::Reject | CallAction::Busy | CallAction::Hangup => {
                let Some(s) = self.call.as_mut() else {
                    // Cancelled before its Invite got here: see the Invite arm.
                    if action == CallAction::Hangup {
                        *EARLY_HANGUP.lock().unwrap_or_else(|p| p.into_inner()) = Some((call_id, peer_fp.to_string()));
                    }
                    return noop();
                };
                if s.call_id != call_id {
                    return noop();
                }
                let was_invited = s.invited.iter().any(|f| f == peer_fp);
                if let Some((_, sid)) = s.keys.remove(peer_fp) {
                    s.retired.insert(sid);
                }
                s.joined.remove(peer_fp);
                media_remove_remote(peer_fp);
                if action != CallAction::Hangup {
                    s.invited.retain(|f| f != peer_fp);
                }
                let over = match (&s.group_id, s.phase) {
                    // 1:1 rings every device of the contact: one that is busy
                    // leaves the others ringing, a Reject is the person's answer.
                    (None, CallPhase::Outgoing) => was_invited && (action != CallAction::Busy || s.invited.is_empty()),
                    // Only the device we talk to (or that rang us) ends it,
                    // not another device of the same contact.
                    (None, _) => s.peer_fp == peer_fp,
                    // The ring ends when the caller gives up before we answer.
                    // Others already talking: keep ringing, we can still join.
                    (Some(_), CallPhase::Incoming) => s.peer_fp == peer_fp && s.joined.is_empty(),
                    (Some(_), CallPhase::Outgoing) => s.invited.is_empty(),
                    (Some(_), CallPhase::Active) => s.joined.is_empty(),
                };
                // The caller gave up while it rang here.
                let missed = over && action == CallAction::Hangup && s.phase == CallPhase::Incoming && s.group_id.is_none();
                if over {
                    if let Some(s) = self.call.take() {
                        // Devices still ringing for this call hear from nobody
                        // else that it is over.
                        if s.phase != CallPhase::Incoming {
                            for fp in s.invited.iter().filter(|f| *f != peer_fp) {
                                self.call_signal(fp, &s, CallAction::Hangup);
                            }
                        }
                    }
                    media_stop();
                    let reason = match action {
                        CallAction::Reject => "rejected",
                        CallAction::Busy => "busy",
                        _ => "remote",
                    };
                    self.last_call_end = Some((call_id.clone(), reason.to_string()));
                }
                if missed {
                    // The callee had no trace of it: a row in the chat, and
                    // `missed` for the notification.
                    let id = uuid::Uuid::new_v4().to_string();
                    let _ = self.archive_message(peer_fp, "received", "\u{1F4DE} Missed call".as_bytes(), Some(&id), None, None, None, crate::current_time_ms());
                }
                serde_json::json!({
                    "type": "call", "action": format!("{:?}", action).to_lowercase(),
                    "call_id": call_id, "peer": self.canonical_peer_key(peer_fp), "ended": over, "missed": missed,
                })
            }
        }
    }

    /// Ring timeouts + link upkeep. Every poll turn; cheap when idle.
    pub(crate) fn call_sweep(&mut self) {
        self.call_sweep_inner();
        // H140: a `call_state` event whenever phase/participants change, so
        // the UI need not poll for transitions (the timer/media stats still
        // come from `callState`).
        let sig = match &self.call {
            Some(s) => {
                let mut j: Vec<&String> = s.joined.iter().collect();
                j.sort();
                format!("{}|{:?}|{:?}|{}", s.call_id, s.phase, j, s.invited.len())
            }
            None => format!("idle|{:?}", self.last_call_end),
        };
        let mut last = LAST_CALL_SIG.lock().unwrap_or_else(|p| p.into_inner());
        if *last != sig {
            *last = sig;
            drop(last);
            let mut v: serde_json::Value = serde_json::from_str(&self.call_state_json()).unwrap_or_default();
            v["type"] = serde_json::json!("call_state");
            self.attachment_events.push(v.to_string());
        }
    }

    fn call_sweep_inner(&mut self) {
        let Some(s) = &self.call else { return };
        let now = current_time_ms();
        let ringing_too_long = s.started.elapsed() > Duration::from_millis(RING_TIMEOUT_MS);
        match s.phase {
            CallPhase::Outgoing if ringing_too_long => {
                info!("Arama cevapsız kaldı");
                self.end_call_with("no_answer");
                return;
            }
            CallPhase::Incoming if ringing_too_long => {
                let s = self.call.take().expect("checked above");
                self.last_call_end = Some((s.call_id, "missed".to_string()));
                return;
            }
            CallPhase::Incoming => return,
            CallPhase::Active => {
                let quiet = s.connected.map(|c| {
                    s.joined.iter().filter_map(|fp| media_rx_age(fp)).chain([c.elapsed()]).min().unwrap_or_default()
                });
                if quiet.map_or(false, |q| q > Duration::from_millis(MEDIA_LOST_MS)) {
                    info!("Arama koptu: {} sn boyunca kimseden medya gelmedi", MEDIA_LOST_MS / 1000);
                    self.end_call_with("lost");
                    return;
                }
            }
            _ => {}
        }
        let Some(control) = &self.stream_control else { return };
        // Test knob, debug builds only: an empty `call_force_relay` file in
        // the app files dir sends all media through the server even when a
        // direct link exists.
        let force_relay = cfg!(debug_assertions)
            && self
            .app_files_dir
            .as_ref()
            .map_or(false, |d| std::path::Path::new(d).join("call_force_relay").exists());
        let peers: Vec<(String, Option<PeerId>)> = s
            .joined
            .iter()
            .map(|fp| {
                let p = self
                    .device_to_peer_id
                    .get(fp)
                    .copied()
                    .filter(|p| !force_relay && self.swarm.as_ref().map_or(false, |sw| sw.is_connected(p)));
                (fp.clone(), p)
            })
            .collect();
        if now.saturating_sub(self.call_stats_logged_at) >= 5_000 {
            self.call_stats_logged_at = now;
            info!("Arama medyası: {}", media_stats());
        }
        media_supervise(control, peers, self.ready_server_peers());
    }

    fn call_title(&self) -> String {
        let Some(s) = &self.call else { return String::new() };
        match &s.group_id {
            Some(gid) => self.groups.get(gid).map(|g| g.name.clone()).unwrap_or_else(|| gid.chars().take(8).collect()),
            None => self.device_display_name(&s.peer_fp),
        }
    }

    fn device_display_name(&self, fp: &str) -> String {
        self.known_remote_devices
            .get(fp)
            .and_then(|d| self.identity_to_contact.get(&d.identity_id))
            .and_then(|cid| self.contacts.get(cid))
            .map(|c| c.display_name.clone())
            .unwrap_or_else(|| fp.chars().take(8).collect())
    }

    pub(crate) fn call_state_json(&self) -> String {
        let Some(s) = &self.call else {
            let (last_call_id, reason) = self.last_call_end.clone().unwrap_or_default();
            return serde_json::json!({"state": "idle", "last_call_id": last_call_id, "reason": reason}).to_string();
        };
        let mut fps: Vec<&String> = s.invited.iter().collect();
        fps.extend(s.joined.iter().filter(|f| !s.invited.contains(f)));
        let participants: Vec<serde_json::Value> = fps
            .into_iter()
            .map(|fp| serde_json::json!({
                "fp": fp,
                "peer": self.canonical_peer_key(fp),
                "name": self.device_display_name(fp),
                "joined": s.joined.contains(fp),
                "slot": media_slot_of(fp),
                "last_rx_ms": media_last_rx(fp),
                "muted": media_flags_of(fp).0,
                "video_off": media_flags_of(fp).1,
                "direct": self.device_to_peer_id.get(fp).map_or(false, |p| self.swarm.as_ref().map_or(false, |sw| sw.is_connected(p))),
            }))
            .collect();
        let phase = match s.phase {
            CallPhase::Outgoing => "outgoing",
            CallPhase::Incoming => "incoming",
            CallPhase::Active => "active",
        };
        serde_json::json!({
            "state": phase, "call_id": s.call_id, "group_id": s.group_id, "video": s.video,
            "peer": if s.peer_fp.is_empty() { String::new() } else { self.canonical_peer_key(&s.peer_fp) },
            "name": self.call_title(), "started_at": s.started_at, "connected_at": s.connected_at,
            "now": current_time_ms(), "participants": participants, "media": media_stats(),
        })
        .to_string()
    }
}

// ---------------------------------------------------------------------------
// JNI
// ---------------------------------------------------------------------------

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|s| s.into()).unwrap_or_else(|_| {
        let _ = env.exception_clear();
        String::new()
    })
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_startCall<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer: JString<'local>, video: jboolean) -> jstring {
    let peer = jstr(&mut env, &peer);
    let out = match crate::catch_panic(move || {
        let _guard = RUNTIME.enter();
        crate::core_lock().start_call(peer, video != 0)
    }) {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    };
    crate::safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_startGroupCall<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, video: jboolean) -> jstring {
    let group_id = jstr(&mut env, &group_id);
    let out = match crate::catch_panic(move || {
        let _guard = RUNTIME.enter();
        crate::core_lock().start_group_call(group_id, video != 0)
    }) {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    };
    crate::safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_acceptCall<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jboolean {
    let r = crate::catch_panic(|| {
        let _guard = RUNTIME.enter();
        crate::core_lock().accept_call()
    });
    matches!(r, Ok(Ok(()))) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_endCall<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jboolean {
    let r = crate::catch_panic(|| {
        let _guard = RUNTIME.enter();
        crate::core_lock().end_call()
    });
    r.is_ok() as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_callState<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let out = crate::catch_panic(|| crate::core_lock().call_state_json()).unwrap_or_else(|_| "{\"state\":\"idle\"}".to_string());
    crate::safe_new_jstring(&mut env, out)
}

/// No core lock: the audio/video threads call this 20-40 times a second.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_callSend<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, kind: jint, data: JByteArray<'local>) -> jboolean {
    let bytes = crate::jbytearray_to_vec(&mut env, &data);
    crate::catch_panic(move || media_send(kind.clamp(0, 255) as u8, &bytes)).unwrap_or(false) as jboolean
}

/// `[kind][slot][payload]` or null on timeout. No core lock.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_callRecv<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, timeout_ms: jint) -> jni::sys::jbyteArray {
    match crate::catch_panic(move || media_recv(timeout_ms.max(0) as u64)) {
        Ok(Some(frame)) => crate::bytes_to_jbytearray(&mut env, &frame),
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_callRequestKeyframe<'local>(_env: JNIEnv<'local>, _class: JClass<'local>, slot: jint) {
    let _ = crate::catch_panic(move || media_request_keyframe(slot.clamp(0, 255) as u8));
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_callTakeKeyframeRequest<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jboolean {
    crate::catch_panic(media_take_keyframe_request).unwrap_or(false) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_callBacklog<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jint {
    crate::catch_panic(media_backlog).unwrap_or(0) as jint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_round_trip_and_tamper() {
        let key = [7u8; 32];
        let sid = [1, 2, 3, 4, 5, 6, 7, 8];
        let p = seal_packet(&key, &sid, 42, 2, b"frame");
        let (s, seq) = packet_header(&p).unwrap();
        assert_eq!((s, seq), (sid, 42));
        assert_eq!(&open_packet(&key, &sid, seq, &p).unwrap()[5..], b"frame");
        let mut bad = p.clone();
        bad[10] ^= 1; // header is AAD
        let (s2, seq2) = packet_header(&bad).unwrap();
        assert!(open_packet(&key, &s2, seq2, &bad).is_none());
        assert!(open_packet(&[8u8; 32], &sid, seq, &p).is_none());
    }

    #[test]
    fn every_receiver_gets_its_own_key() {
        let master = [7u8; 32];
        assert_eq!(*pair_key(&master, "bob"), *pair_key(&master, "bob"));
        assert_ne!(*pair_key(&master, "bob"), *pair_key(&master, "carol"));
        assert_ne!(*pair_key(&master, "bob"), master);
        // What we seal for bob opens with bob's key only.
        let sid = [1u8; 8];
        let p = seal_packet(&pair_key(&master, "bob"), &sid, 1, 1, b"x");
        assert!(open_packet(&pair_key(&master, "bob"), &sid, 1, &p).is_some());
        assert!(open_packet(&pair_key(&master, "carol"), &sid, 1, &p).is_none());
    }

    #[test]
    fn frame_round_trip() {
        let f = encode_frame(b"mb_1", b"data");
        let (mb, d) = futures::executor::block_on(read_frame(&mut futures::io::Cursor::new(f))).unwrap();
        assert_eq!((mb.as_slice(), d.as_slice()), (&b"mb_1"[..], &b"data"[..]));
    }

    #[test]
    fn replay_window() {
        let mut r = Remote::new("", 0, [0; 32], [0; 8]);
        assert!(r.is_new(5));
        r.record(5);
        assert!(!r.is_new(5));
        assert!(r.is_new(4)); // late but unseen
        r.record(200);
        assert!(!r.is_new(100)); // too old
        // 64 late packets after 300 must not push 300 out of the window.
        r.record(300);
        for seq in 237..300 {
            assert!(r.is_new(seq));
            r.record(seq);
        }
        r.record(301);
        assert!(!r.is_new(300) && !r.is_new(237) && !r.is_new(236));
    }

    #[test]
    fn send_recv_through_the_static() {
        media_start([3u8; 32], [9u8; 8]);
        // Talk to ourselves: our own stream id as a remote.
        media_add_remote("self", &[3u8; 32], &[9u8; 8]);
        let packet = seal_packet(&[3u8; 32], &[9u8; 8], 1, 1, b"opus");
        media_on_packet(&packet);
        media_on_packet(&packet); // duplicate dropped
        assert_eq!(media_recv(0).unwrap(), b"\x01\x00opus");
        assert!(media_recv(0).is_none());
        // A receiver reporting 700 ms of queue on our stream is congestion.
        let mut report = [9u8; 8].to_vec();
        report.extend_from_slice(&700u16.to_be_bytes());
        report.push(1); // keyframe please
        media_on_packet(&seal_packet(&[3u8; 32], &[9u8; 8], 5, KIND_REPORT, &report));
        assert!(media_recv(0).is_none(), "reports never reach Kotlin");
        assert_eq!(media_backlog(), 7);
        assert!(media_take_keyframe_request());
        assert!(!media_take_keyframe_request());
        media_on_packet(&seal_packet(&[3u8; 32], &[9u8; 8], 6, KIND_STATE, &[1]));
        assert_eq!(media_flags_of("self"), (true, false));
        assert!(media_recv(0).is_none(), "state never reaches Kotlin");
        // A second device claiming the same stream id does not lock the first
        // out: the key decides.
        media_add_remote("thief", &[4u8; 32], &[9u8; 8]);
        // The relay address of a direction comes from that direction's key.
        assert!(relay_listen_keys().contains(&vec![3u8; 32]));
        let m = media();
        assert_eq!(m.targets["self"].mailbox, server_seal::relay_mailbox_id(&pair_key(&m.key, "self")[..]).into_bytes());
        assert_ne!(m.targets["self"].mailbox, m.targets["thief"].mailbox);
        drop(m);
        media_on_packet(&seal_packet(&[3u8; 32], &[9u8; 8], 7, 1, b"mine"));
        assert_eq!(media_recv(0).unwrap(), b"\x01\x00mine");
        // A re-key keeps the slot.
        media_add_remote("self", &[5u8; 32], &[8u8; 8]);
        assert_eq!(media_slot_of("self"), Some(0));
        media_stop();
        media_on_packet(&seal_packet(&[3u8; 32], &[9u8; 8], 2, 1, b"x"));
        assert!(media_recv(0).is_none());
    }
}
