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
//!   addressed to the target's `p2p_msg_<fp>` mailbox, which every client
//!   already registers. The server pushes it to the target only if the target
//!   is connected at that moment; nothing is stored.
//!
//! Packet: `[ver=1][stream_id 8][seq u64 BE]` then ChaCha20-Poly1305 over
//! `[kind][sent_ms u32 BE][payload]` (`sent_ms` = wall clock mod 2^32, only for
//! the one-way delay estimate in the stats), header as AAD, nonce = `stream_id[..4] || seq`. Every
//! participant picks a fresh random key + stream id per call and ships them
//! inside the ratchet (Invite/Accept), so the server relays ciphertext only.
//! One key per sender (not per pair) lets a group sender encrypt a frame once
//! and fan the same bytes out to everyone.

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

use crate::packet::{CallAction, MessageContent};
use crate::{current_time_ms, server_seal, P2PCore, OptionGroupExt as _, RUNTIME};

const KIND_VIDEO: u8 = 2;

pub const MEDIA_PROTOCOL: StreamProtocol = StreamProtocol::new("/typeon/media/1.0.0");
pub const RELAY_PROTOCOL: StreamProtocol = StreamProtocol::new(crate::server_proto::RELAY_PROTOCOL);

/// Largest frame accepted from the wire. A 480p keyframe is ~20-60 KB.
pub const MAX_FRAME: usize = 256 * 1024;
/// Frames queued per link before new ones are dropped (~1-2 s of audio +
/// video). A filling queue is the congestion signal Kotlin reads through
/// `media_backlog` to lower the video frame rate and bitrate.
pub const LINK_QUEUE: usize = 48;
/// Received frames waiting for Kotlin. ~1 s of a 3-way video call: a slow
/// decoder must shed old frames, never let them pile up (256 here once meant
/// 4-5 s of delay on a phone decoding two videos).
const INBOX_MAX: usize = 64;
/// Ring timeout, both directions.
const RING_TIMEOUT_MS: u64 = 45_000;
/// An Invite older than this (store-and-forward delivered it late) no longer rings.
const INVITE_MAX_AGE_MS: u64 = 60_000;
const REOPEN_BACKOFF_MS: u64 = 3_000;
const OPEN_TIMEOUT: Duration = Duration::from_secs(20);

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
    let mut mailbox = vec![0u8; u16::from_be_bytes(len2) as usize];
    r.read_exact(&mut mailbox).await?;
    let mut len4 = [0u8; 4];
    r.read_exact(&mut len4).await?;
    let n = u32::from_be_bytes(len4) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut data = vec![0u8; n];
    r.read_exact(&mut data).await?;
    Ok((mailbox, data))
}

/// Drains `rx` into `w`. One `write_all` per already-framed buffer, so a small
/// audio packet leaves as one Tor cell instead of three.
pub async fn pump_writes<W: futures::AsyncWrite + Unpin>(mut w: W, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) {
    while let Some(buf) = rx.recv().await {
        if w.write_all(&buf).await.is_err() || w.flush().await.is_err() {
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
    key: [u8; 32],
    max_seq: u64,
    /// Recently accepted sequence numbers — two links (direct + relay during a
    /// switch) can deliver the same packet, and a replay must not play twice.
    recent: VecDeque<u64>,
    last_rx_ms: u64,
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
    fn new(fp: &str, slot: u8, key: [u8; 32]) -> Self {
        Remote {
            fp: fp.to_string(), slot, key, max_seq: 0, recent: VecDeque::new(), last_rx_ms: 0,
            delay_ewma: 0.0, delay_min: 0.0, samples: 0, last_report_ms: 0, want_keyframe: false,
            muted: false, video_off: false,
        }
    }
    fn is_new(&self, seq: u64) -> bool {
        seq > self.max_seq || (seq + 64 > self.max_seq && !self.recent.contains(&seq))
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
        self.max_seq = self.max_seq.max(seq);
        if self.recent.len() >= 64 {
            self.recent.pop_front();
        }
        self.recent.push_back(seq);
        self.last_rx_ms = current_time_ms();
    }
}

struct Target {
    /// Live connection to this device, refreshed every poll by `media_supervise`.
    peer: Option<PeerId>,
    /// `server_mailbox_id("p2p_msg_<fp>")` — the relay address.
    mailbox: Vec<u8>,
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
    key: [u8; 32],
    sid: [u8; 8],
    seq: u64,
    remotes: HashMap<[u8; 8], Remote>,
    next_slot: u8,
    targets: HashMap<String, Target>,
    direct: HashMap<PeerId, Link>,
    relays: HashMap<PeerId, Link>,
    /// Peer -> last open attempt (ms), for `REOPEN_BACKOFF_MS`.
    opening: HashMap<PeerId, u64>,
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
    /// Reporter stream id -> (queue ms it sees on OUR stream, when).
    /// Tor/yamux buffer hundreds of KB inside the stream, so our own link
    /// queue stays empty while seconds pile up on the path — only the far
    /// end can see that.
    reports: HashMap<[u8; 8], (u32, u64)>,
    /// A receiver asked us for a keyframe; Kotlin takes it via `media_take_keyframe_request`.
    keyframe_asked: bool,
    /// Encrypted media bytes queued out (per copy) / accepted in.
    bytes_out: u64,
    bytes_in: u64,
}

lazy_static::lazy_static! {
    static ref MEDIA: Mutex<Media> = Mutex::new(Media::default());
    static ref INBOX_READY: Condvar = Condvar::new();
}

fn media() -> MutexGuard<'static, Media> {
    MEDIA.lock().unwrap_or_else(|p| p.into_inner())
}

fn media_start(key: [u8; 32], sid: [u8; 8]) {
    let mut m = media();
    let generation = m.generation + 1;
    let next_link_id = m.next_link_id;
    *m = Media { active: true, generation, key, sid, next_link_id, ..Default::default() };
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
    if !m.active || m.remotes.contains_key(&sid) {
        return;
    }
    m.remotes.retain(|_, r| r.fp != fp);
    let slot = m.next_slot;
    m.next_slot = m.next_slot.wrapping_add(1);
    m.remotes.insert(sid, Remote::new(fp, slot, key));
    let mailbox = server_seal::server_mailbox_id(&format!("p2p_msg_{}", fp)).into_bytes();
    m.targets.insert(fp.to_string(), Target { peer: None, mailbox });
}

fn media_remove_remote(fp: &str) {
    let mut m = media();
    m.remotes.retain(|_, r| r.fp != fp);
    m.targets.remove(fp);
}

fn media_slot_of(fp: &str) -> Option<u8> {
    media().remotes.values().find(|r| r.fp == fp).map(|r| r.slot)
}

/// `(muted, camera off)` as last announced by `fp`.
fn media_flags_of(fp: &str) -> (bool, bool) {
    media().remotes.values().find(|r| r.fp == fp).map(|r| (r.muted, r.video_off)).unwrap_or_default()
}

fn media_last_rx(fp: &str) -> u64 {
    media().remotes.values().find(|r| r.fp == fp).map(|r| r.last_rx_ms).unwrap_or(0)
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

/// Encrypts one frame and queues it for every call participant. Never blocks:
/// a full link queue drops the frame (live media, late = useless).
pub fn media_send(kind: u8, payload: &[u8]) -> bool {
    use tokio::sync::mpsc::error::TrySendError;
    let mut m = media();
    if !m.active || m.targets.is_empty() || payload.len() > MAX_FRAME - 64 {
        return false;
    }
    m.seq += 1;
    let packet = seal_packet(&m.key, &m.sid, m.seq, kind, payload);
    let targets: Vec<(Option<PeerId>, Vec<u8>)> = m.targets.values().map(|t| (t.peer, t.mailbox.clone())).collect();
    let mut any = false;
    for (peer, mailbox) in targets {
        if let Some(p) = peer {
            let res = m.direct.get(&p).map(|l| l.tx.try_send(encode_frame(&[], &packet)));
            match res {
                Some(Ok(())) => { m.via_direct += 1; m.bytes_out += packet.len() as u64; any = true; continue; }
                Some(Err(TrySendError::Full(_))) => { m.dropped += 1; continue; }
                Some(Err(TrySendError::Closed(_))) => { m.direct.remove(&p); }
                None => {}
            }
        }
        let servers: Vec<PeerId> = m.relays.keys().copied().collect();
        let frame = encode_frame(&mailbox, &packet);
        for s in servers {
            match m.relays[&s].tx.try_send(frame.clone()) {
                Ok(()) => { m.via_relay += 1; m.bytes_out += packet.len() as u64; any = true; break; }
                Err(TrySendError::Full(_)) => { m.dropped += 1; break; }
                Err(TrySendError::Closed(_)) => { m.relays.remove(&s); }
            }
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

/// Any packet from any link (direct, inbound, relay) ends up here.
fn media_on_packet(packet: &[u8]) {
    let Some((sid, seq)) = packet_header(packet) else { return };
    let mut m = media();
    if !m.active {
        return;
    }
    let Some(remote) = m.remotes.get(&sid) else { return };
    if !remote.is_new(seq) {
        return;
    }
    let Some(pt) = open_packet(&remote.key, &sid, seq, packet) else { return };
    let slot = remote.slot;
    let now = current_time_ms();
    let sent_ms = u32::from_be_bytes([pt[1], pt[2], pt[3], pt[4]]);
    let delay = (now as u32).wrapping_sub(sent_ms) as i32 as f64;
    let Some(r) = m.remotes.get_mut(&sid) else { return };
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
            m.reports.insert(sid, (q, now));
            if pt.len() >= 16 && pt[15] & 1 != 0 {
                m.keyframe_asked = true;
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
        let victim = m.inbox.iter().position(|f| f[0] == KIND_VIDEO).unwrap_or(0);
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
        media_send(KIND_REPORT, &p);
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
        if m.opening.get(&peer).map_or(false, |t| now.saturating_sub(*t) < REOPEN_BACKOFF_MS) {
            continue;
        }
        m.opening.insert(peer, now);
        let control = control.clone();
        let generation = m.generation;
        RUNTIME.spawn(open_link(control, peer, relay, generation));
    }
}

async fn open_link(mut control: libp2p_stream::Control, peer: PeerId, relay: bool, generation: u64) {
    let what = if relay { "sunucu" } else { "doğrudan" };
    let proto = if relay { RELAY_PROTOCOL } else { MEDIA_PROTOCOL };
    let stream = match tokio::time::timeout(OPEN_TIMEOUT, control.open_stream(peer, proto)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => { warn!("Arama akışı açılamadı ({}, {}): {}", what, peer, e); return; }
        Err(_) => { warn!("Arama akışı açılamadı ({}, {}): zaman aşımı", what, peer); return; }
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
    info!("Arama akışı açıldı ({}, {})", what, peer);
    tokio::spawn(pump_writes(wr, rx));
    // Relay links carry the server's pushes back to us; on a direct outbound
    // link the read only notices the peer closing it.
    while let Ok((_, data)) = read_frame(&mut rd).await {
        media_on_packet(&data);
    }
    let mut m = media();
    let map = if relay { &mut m.relays } else { &mut m.direct };
    if map.get(&peer).map(|l| l.id) == Some(id) {
        map.remove(&peer);
    }
    info!("Arama akışı kapandı ({}, {})", what, peer);
}

/// Reads media frames peers push to us over direct streams. Registered once
/// per swarm (`start_network`).
pub(crate) fn spawn_media_acceptor(control: &mut libp2p_stream::Control) {
    let mut incoming = match control.accept(MEDIA_PROTOCOL) {
        Ok(i) => i,
        Err(e) => { warn!("Arama akışı dinleyicisi kurulamadı: {}", e); return; }
    };
    RUNTIME.spawn(async move {
        while let Some((_peer, mut stream)) = incoming.next().await {
            tokio::spawn(async move {
                while let Ok((_, data)) = read_frame(&mut stream).await {
                    media_on_packet(&data);
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
    keys: HashMap<String, (Vec<u8>, Vec<u8>)>,
    /// Devices currently in the call (media flows to/from these).
    joined: HashSet<String>,
    my_key: [u8; 32],
    my_sid: [u8; 8],
    started_at: u64,
    connected_at: u64,
}

impl CallSession {
    fn new(call_id: String, group_id: Option<String>, video: bool, phase: CallPhase, peer_fp: String, invited: Vec<String>) -> Self {
        let mut my_key = [0u8; 32];
        let mut my_sid = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut my_key);
        rand::rngs::OsRng.fill_bytes(&mut my_sid);
        CallSession {
            call_id, group_id, video, phase, peer_fp, invited,
            keys: HashMap::new(), joined: HashSet::new(),
            my_key, my_sid, started_at: current_time_ms(), connected_at: 0,
        }
    }
}

fn noop() -> serde_json::Value {
    serde_json::json!({"type": "noop"})
}

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
        media_start(s.my_key, s.my_sid);
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
        media_start(s.my_key, s.my_sid);
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
        media_start(s.my_key, s.my_sid);
        for fp in &s.joined {
            if let Some((k, sid)) = s.keys.get(fp) {
                media_add_remote(fp, k, sid);
            }
        }
        self.call_broadcast(CallAction::Accept);
        Ok(())
    }

    /// Reject while ringing, hang up otherwise.
    pub(crate) fn end_call(&mut self) {
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
        self.last_call_end = Some((s.call_id, "local".to_string()));
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
        let keys = with_keys.then(|| (s.my_key.to_vec(), s.my_sid.to_vec()));
        self.send_call_signal(fp, &s.call_id, s.group_id.clone(), s.video, action, keys);
    }

    fn send_call_signal(&mut self, fp: &str, call_id: &str, group_id: Option<String>, video: bool, action: CallAction, keys: Option<(Vec<u8>, Vec<u8>)>) {
        let (media_key, stream_id) = keys.unwrap_or_default();
        let content = MessageContent::Call {
            call_id: call_id.to_string(),
            action,
            group_id,
            video,
            media_key,
            stream_id,
            sent_at_ms: current_time_ms(),
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
    ) -> serde_json::Value {
        let now = current_time_ms();
        let keys_ok = media_key.len() == 32 && stream_id.len() == 8;
        let is_member = |core: &P2PCore, gid: &str| {
            core.groups.get(gid).map_or(false, |g| g.members.iter().any(|m| m.identity_id == sender_identity_id))
        };
        info!("Arama sinyali: {:?} arama={} kimden={}", action, &call_id[..8.min(call_id.len())], &peer_fp[..8.min(peer_fp.len())]);
        match action {
            CallAction::Invite => {
                if !keys_ok || (sent_at_ms > 0 && now.saturating_sub(sent_at_ms) > INVITE_MAX_AGE_MS) {
                    return noop();
                }
                if let Some(gid) = &group_id {
                    if !is_member(self, gid) {
                        return noop();
                    }
                }
                if let Some(s) = &self.call {
                    if s.call_id != call_id {
                        self.send_call_signal(peer_fp, &call_id, group_id, video, CallAction::Busy, None);
                    }
                    return noop();
                }
                let mut invited = match &group_id {
                    Some(gid) => self.group_call_devices(gid).unwrap_or_default(),
                    None => Vec::new(),
                };
                if !invited.iter().any(|f| f == peer_fp) {
                    invited.push(peer_fp.to_string());
                }
                let mut s = CallSession::new(call_id.clone(), group_id.clone(), video, CallPhase::Incoming, peer_fp.to_string(), invited);
                s.keys.insert(peer_fp.to_string(), (media_key, stream_id));
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
                if s.call_id != call_id {
                    return noop();
                }
                if !s.invited.iter().any(|f| f == peer_fp) {
                    if !member {
                        return noop();
                    }
                    s.invited.push(peer_fp.to_string());
                }
                s.keys.insert(peer_fp.to_string(), (media_key.clone(), stream_id.clone()));
                s.joined.insert(peer_fp.to_string());
                let mut stop_ringing = Vec::new();
                if s.phase == CallPhase::Outgoing {
                    s.phase = CallPhase::Active;
                    s.connected_at = now;
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
                }
                if !stop_ringing.is_empty() {
                    let (cid, video) = (s.call_id.clone(), s.video);
                    for fp in stop_ringing {
                        self.send_call_signal(&fp, &cid, None, video, CallAction::Hangup, None);
                    }
                }
                serde_json::json!({"type": "call", "action": "accept", "call_id": call_id, "peer": self.canonical_peer_key(peer_fp)})
            }
            CallAction::Reject | CallAction::Busy | CallAction::Hangup => {
                let Some(s) = self.call.as_mut() else { return noop() };
                if s.call_id != call_id {
                    return noop();
                }
                s.joined.remove(peer_fp);
                media_remove_remote(peer_fp);
                if action != CallAction::Hangup {
                    s.invited.retain(|f| f != peer_fp);
                }
                let over = match (&s.group_id, s.phase) {
                    (None, _) => true,
                    // The ring ends when the caller gives up before we answer.
                    (Some(_), CallPhase::Incoming) => s.peer_fp == peer_fp,
                    (Some(_), CallPhase::Outgoing) => s.invited.is_empty(),
                    (Some(_), CallPhase::Active) => s.joined.is_empty(),
                };
                if over {
                    self.call = None;
                    media_stop();
                    let reason = match action {
                        CallAction::Reject => "rejected",
                        CallAction::Busy => "busy",
                        _ => "remote",
                    };
                    self.last_call_end = Some((call_id.clone(), reason.to_string()));
                }
                serde_json::json!({
                    "type": "call", "action": format!("{:?}", action).to_lowercase(),
                    "call_id": call_id, "peer": self.canonical_peer_key(peer_fp), "ended": over,
                })
            }
        }
    }

    /// Ring timeouts + link upkeep. Every poll turn; cheap when idle.
    pub(crate) fn call_sweep(&mut self) {
        let Some(s) = &self.call else { return };
        let now = current_time_ms();
        let ringing_too_long = now.saturating_sub(s.started_at) > RING_TIMEOUT_MS;
        match s.phase {
            CallPhase::Outgoing if ringing_too_long => {
                info!("Arama cevapsız kaldı");
                self.end_call();
                if let Some((_, r)) = self.last_call_end.as_mut() {
                    *r = "no_answer".to_string();
                }
                return;
            }
            CallPhase::Incoming if ringing_too_long => {
                let s = self.call.take().expect("checked above");
                self.last_call_end = Some((s.call_id, "missed".to_string()));
                return;
            }
            CallPhase::Incoming => return,
            _ => {}
        }
        let Some(control) = &self.stream_control else { return };
        // Test knob: an empty `call_force_relay` file in the app files dir
        // sends all media through the server even when a direct link exists.
        let force_relay = self
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
    env.get_string(s).map(|s| s.into()).unwrap_or_default()
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
    crate::catch_panic(move || media_send(kind as u8, &bytes)).unwrap_or(false) as jboolean
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
    let _ = crate::catch_panic(move || media_request_keyframe(slot as u8));
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
    fn frame_round_trip() {
        let f = encode_frame(b"mb_1", b"data");
        let (mb, d) = futures::executor::block_on(read_frame(&mut futures::io::Cursor::new(f))).unwrap();
        assert_eq!((mb.as_slice(), d.as_slice()), (&b"mb_1"[..], &b"data"[..]));
    }

    #[test]
    fn replay_window() {
        let mut r = Remote::new("", 0, [0; 32]);
        assert!(r.is_new(5));
        r.record(5);
        assert!(!r.is_new(5));
        assert!(r.is_new(4)); // late but unseen
        r.record(200);
        assert!(!r.is_new(100)); // too old
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
        media_stop();
        media_on_packet(&seal_packet(&[3u8; 32], &[9u8; 8], 2, 1, b"x"));
        assert!(media_recv(0).is_none());
    }
}
