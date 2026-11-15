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
//!   addressed to `key_bound_mailbox_id(pair_key)`: an id only the sender and
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
use crate::{current_time_ms, mono_ms, P2PCore, OptionGroupExt as _, RUNTIME};

mod media_link;
mod signalling;
pub(crate) use media_link::*;
pub use media_link::media_send;
pub use media_link::media_backlog;
pub use media_link::media_request_keyframe;
pub use media_link::media_request_avc;
pub use media_link::media_take_avc_request;
pub use media_link::media_take_keyframe_request;
pub use media_link::media_recv;

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
/// A hold lasts at most this long. It re-arms only once the report drops below `AUDIO_HOLD_BELOW_MS`
/// (a stale baseline must not mute a call).
const AUDIO_HOLD_MAX_MS: u64 = 5_000;
/// Received frames waiting for Kotlin. ~1 s of a 3-way video call: a slow
/// decoder must shed old frames, never let them pile up (256 here once meant
/// 4-5 s of delay on a phone decoding two videos).
const INBOX_MAX: usize = 64;
/// Ring timeout, both directions.
const RING_TIMEOUT_MS: u64 = 45_000;
/// how long and how often a running group call rings absent members again.
const REINVITE_FOR_MS: u64 = 5 * 60_000;
const REINVITE_EVERY_MS: u64 = 30_000;
/// After `REINVITE_FOR_MS` the caller keeps inviting, this rarely, so absent
/// members still see the call running ("Attend" in the group chat).
const REINVITE_LATE_EVERY_MS: u64 = 120_000;
/// A group call offer with no Invite for this long is gone.
const OFFER_TTL_MS: u64 = 150_000;
/// What is left of an offer once its inviter hung up.
const OFFER_HANGUP_GRACE_MS: u64 = 40_000;
/// Every participant sends a state packet each second, even muted with the
/// camera off: this long with nothing from anyone means the others are gone
/// (app killed, device off, network lost) and never got to send a Hangup.
const MEDIA_LOST_MS: u64 = 30_000;
/// An Invite older than this (store-and-forward delivered it late) no longer rings.
const INVITE_MAX_AGE_MS: u64 = 60_000;
/// Bound on a group invite's participant list.
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
    /// Link the last frame came over (`None` direct, else the relay server).
    /// A route change re-baselines `delay_min`.
    via: Option<PeerId>,
    last_report_ms: u64,
    /// Our decoder for this sender lost sync (dropped frame, late join):
    /// ask for a keyframe in the next report.
    want_keyframe: bool,
    /// Our decoder cannot take this sender's HEVC: every report asks for H.264.
    want_avc: bool,
    /// Last `KIND_STATE` flags from this sender.
    muted: bool,
    video_off: bool,
}

impl Remote {
    fn new(fp: &str, slot: u8, key: [u8; 32], sid: [u8; 8]) -> Self {
        Remote {
            fp: fp.to_string(), slot, key: Zeroizing::new(key), sid, max_seq: 0, seen: 0, last_rx_ms: 0, last_rx: None,
            delay_ewma: 0.0, delay_min: 0.0, samples: 0, via: None, last_report_ms: 0, want_keyframe: false, want_avc: false,
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
    /// `server_client::key_bound_mailbox_id(key)` — the relay address.
    mailbox: Vec<u8>,
    /// `pair_key` for this device: what we seal its copy of a frame with.
    key: Zeroizing<[u8; 32]>,
    /// Its audio copy held back, see [`AUDIO_HOLD_ABOVE_MS`]: decided by
    /// this device's own report, so one slow receiver mutes nobody else.
    audio_hold: bool,
    /// `mono_ms` the hold began; `hold_disarmed`: released by `AUDIO_HOLD_MAX_MS`.
    hold_at: u64,
    hold_disarmed: bool,
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
    /// A receiver cannot decode our HEVC; Kotlin takes it via `media_take_avc_request`.
    avc_asked: bool,
    /// When `keyframe_asked` was last set (`KEYFRAME_MIN_MS`).
    keyframe_at: u64,
    /// Encrypted media bytes queued out (per copy) / accepted in.
    bytes_out: u64,
    bytes_in: u64,
}

lazy_static::lazy_static! {
    static ref MEDIA: Mutex<Media> = Mutex::new(Media::default());
    static ref INBOX_READY: Condvar = Condvar::new();
    /// `(call id, sender)` of the last Hangups for calls we did not have:
    /// only that sender's Invite for it is then dropped (a Hangup that
    /// overtook its Invite), not one from another group member. A few, not
    /// one: two overtaken Hangups in a group let the first Invite ring.
    static ref EARLY_HANGUP: Mutex<VecDeque<(String, String)>> = Mutex::new(VecDeque::new());
    /// Group id -> the last Invite of a group call running there, rung or
    /// not: what "Attend" joins (`start_group_call`).
    static ref GROUP_OFFERS: Mutex<HashMap<String, GroupOffer>> = Mutex::new(HashMap::new());
}

pub(crate) struct GroupOffer {
    call_id: String,
    video: bool,
    peer_fp: String,
    media_key: Zeroizing<Vec<u8>>,
    stream_id: Vec<u8>,
    participants: Vec<String>,
    at: Instant,
}

fn group_offers() -> MutexGuard<'static, HashMap<String, GroupOffer>> {
    GROUP_OFFERS.lock().unwrap_or_else(|p| p.into_inner())
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
    /// Last group Invite we sent, see `call_sweep_inner`.
    last_invite: Instant,
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
            started: Instant::now(), connected: None, retired: HashSet::new(), last_invite: Instant::now(),
        }
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

/// 0 = no call running in the group (or I am in it), 1 = voice, 2 = video.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_groupCallOffer<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>) -> jint {
    let group_id = jstr(&mut env, &group_id);
    crate::catch_panic(move || crate::core_lock_read().group_call_offer(&group_id)).unwrap_or(0)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_callState<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let out = crate::catch_panic(|| crate::core_lock_read().call_state_json()).unwrap_or_else(|_| "{\"state\":\"idle\"}".to_string());
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
pub extern "system" fn Java_com_p2p_messenger_P2PLib_callRequestAvc<'local>(_env: JNIEnv<'local>, _class: JClass<'local>, slot: jint) {
    let _ = crate::catch_panic(move || media_request_avc(slot.clamp(0, 255) as u8));
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_callTakeAvcRequest<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jboolean {
    crate::catch_panic(media_take_avc_request).unwrap_or(false) as jboolean
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
mod tests;
