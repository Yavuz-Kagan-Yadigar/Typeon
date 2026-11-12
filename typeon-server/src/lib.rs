//! Typeon server: a BLIND store-and-forward mailbox.
//!
//! ## Why it exists
//!
//! Nothing else in the app does store-and-forward (see the section on
//! store-and-forward in the README and SECURITY.md). libp2p Circuit Relay v2 builds a live circuit
//! only while both peers are connected and stores nothing. The `p2p_msg_<fp>` gossipsub topic is a
//! naming scheme, not a storage service. Durability therefore rests entirely on the SENDER
//! (`awaiting_confirmation`, retries for up to 2 days). This server fills that gap.
//!
//! ## What the server cannot see
//!
//! - Message content: envelopes are already end-to-end encrypted, AND sealed once more with
//!   `server_seal::seal_envelope`. Without the second seal, `MessagePacketHeader.sender_device_fingerprint`
//!   would be readable in clear.
//! - History: encrypted with a key derived from `archive_key`.
//! - File content: encrypted with `file_key`. The server stores and serves the chunks as they are.
//! - Identities: mailbox and bucket ids are blinded with HKDF. Enrollment (`Enroll`) uses a fresh Ed25519
//!   pair made for this server, not the device's identity key.
//!
//! ## What it can see (documented in SECURITY.md)
//!
//! Size, timing and volume, and which `PeerId` registered which mailbox. That is the contact graph
//! among ITS OWN users. Hiding it would need an anonymous credential per mailbox plus separate circuits,
//! which is out of scope.

pub mod store;

/// JNI shell of the Android server app. Compiled for Android only.
#[cfg(target_os = "android")]
mod jni;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature as MlDsaSignature,
    Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};
use futures::StreamExt as _;
use libp2p::request_response::{self, ProtocolSupport, ResponseChannel};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, noise, relay, tcp, yamux, PeerId, StreamProtocol, Swarm};
use log::{debug, error, info, warn};
use rand::RngCore;
use sha2::{Digest, Sha256};

use p2p_messenger::attachments::{self, FileChunkRequest, FileChunkResponse};
use p2p_messenger::call::{encode_frame, pump_writes, read_frame, LINK_QUEUE, RELAY_PROTOCOL};
use p2p_messenger::server_proto::{
    self, MailItem, ServerErrorCode, ServerLimits, ServerRequest, ServerResponse, MAX_DEPOSIT_BYTES,
    MAX_FETCH_BATCH_BYTES, MAX_FETCH_BATCH_ITEMS, SERVER_PROTOCOL, SERVER_PROTOCOL_VERSION,
};

use store::{Enrollment, EnrollmentState, Store};

/// Attachment protocol id. The SAME protocol clients already speak. The server registers it with
/// `ProtocolSupport::Inbound`, so a server-held attachment is just another source peer to a client. The
/// client's whole download state machine runs unchanged.
const FILE_TRANSFER_PROTOCOL: &str = "/p2pmessenger/filexfer/1.0.0";

/// Fixed port that libp2p must listen on while Tor is on. The onion service bridges incoming streams here
/// (same reason as `TOR_LIBP2P_PORT` in the core, but for the server's own port).
const TOR_LIBP2P_PORT: u16 = 42612;

/// Sweep intervals.
const SWEEP_INTERVAL_MS: u64 = 60_000;
/// A `Notify` (or inline `Push`) that drew no `Fetch` is sent again after this long. Before, it was sent once.
/// Mail lost on a sleeping phone then waited for the client's own safety poll, which had to run every 30 s
/// and kept the LTE radio on.
const NOTIFY_RESEND_MS: u64 = 20_000;

/// Maximum requests per connection per minute. Unlike the quota, this is an INSTANT limit. Its purpose is to
/// stop one peer from using up the server's disk and CPU alone.
const RATE_WINDOW_MS: u64 = 60_000;
/// File-chunk requests per peer per `RATE_WINDOW_MS` (see `serve_chunk`). Tor carries about one 256 KiB chunk
/// a second. 10 per second is far above a real download and caps one peer at about 2.5 MiB/s of disk reads.
const CHUNKS_PER_MINUTE: u32 = 600;
/// Blobs (files on disk) one enrollment may hold. Bytes have their own quota. A heavy month of attachments
/// (`blob_ttl_ms`) stays far below this.
const MAX_BLOBS_PER_ENROLLMENT: i64 = 10_000;
/// Minimum quota charged for a `BlobPut` chunk: its row, even when no new bytes are stored.
const BLOB_CHUNK_MIN_CHARGE: u64 = 64;

/// Call-media relay budget per client: bytes per `RELAY_WINDOW_MS`. About 6.7 Mbit/s, several times a 480p
/// video call, so it only stops a flood. Relay frames skip `check_rate`. A call sends about 30 frames per second,
/// which alone would use up `requests_per_minute`.
const RELAY_BYTES_PER_WINDOW: usize = 8 * 1024 * 1024;
const RELAY_WINDOW_MS: u64 = 10_000;
/// How long the summed store size is reused (see `total_budget_exceeded`). The total budget is therefore a
/// soft ceiling: it can overshoot by what arrives within one 5-second cache window.
const TOTAL_CACHE_MS: u64 = 5_000;
/// What a sender may relay per window to a listener that sends nothing back. Enough for the once-a-second
/// state packets that start a call.
const RELAY_COLD_BYTES_PER_WINDOW: usize = 64 * 1024;

/// Largest item `notify_owner_of` pushes inline (`ServerRequest::Push`). Messages and call signals are about
/// 8 to 15 KB. Larger items use the Fetch path.
const PUSH_INLINE_MAX: usize = 64 * 1024;

pub fn now_ms() -> i64 {
    // No unwrap: a clock before 1970 must not kill the server loop.
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// Monotonic milliseconds since process start. Rate windows and sweep pacing use this, not the wall clock,
/// because a corrected phone clock would otherwise freeze them.
fn mono_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// A wall-clock step larger than this is not trusted at once. The TTL sweep waits `CLOCK_JUMP_HOLD_MS` first.
/// (A clock set a month ahead once deleted all mail and blobs in one sweep.)
const CLOCK_JUMP_MS: i64 = 24 * 60 * 60 * 1000;
const CLOCK_JUMP_HOLD_MS: u64 = 60 * 60 * 1000;

/// Inbound connection caps. Every client arrives from 127.0.0.1 through the onion bridge and PeerIds are free,
/// so only a total cap stops a connection flood.
const MAX_INBOUND_CONNECTIONS: u32 = 512;
const MAX_CONNECTIONS_PER_PEER: u32 = 8;
/// A connected peer without an active enrollment is cut after this long. Otherwise it held one of the
/// `MAX_INBOUND_CONNECTIONS` slots indefinitely.
const UNENROLLED_GRACE_MS: u64 = 60_000;
/// What one relayed frame is charged on top of its payload (encoding, queue slot, loop over `live_interest`).
/// See `RelayEvent::Frame`.
const RELAY_FRAME_OVERHEAD: usize = 64;
/// `BlobFinish` hashes running at once. Each reads a whole blob from disk.
const MAX_HASH_JOBS: usize = 4;
/// Repeated `BlobFinish` requests waiting on one running hash.
const MAX_HASH_WAITERS: usize = 8;
/// Call-relay streams open at once, server-wide. A stream from a peer that is not enrolled ends at once. An
/// enrolled peer holds one.
const MAX_RELAY_STREAMS: usize = 256;
/// Of those, one per peer at a time. A call holds one stream, and the rest wait out a replace.
const MAX_RELAY_STREAMS_PER_PEER: usize = 4;
/// `Enroll` and `Rebind` hybrid signature checks per `RATE_WINDOW_MS`, server-wide. ML-DSA-87 is the expensive
/// step, and PeerIds are free, so only a global pool bounds the CPU. Each peer gets `ENROLL_VERIFIES_PER_PEER`.
/// ponytail: many fresh PeerIds can still drain the pool for one window (mail is not affected). Add per-invite
/// budgets if that matters.
const ENROLL_VERIFIES_PER_MINUTE: u32 = 120;
/// One peer's share of `ENROLL_VERIFIES_PER_MINUTE`. A device enrolls or rebinds once, so a few retries cover it.
const ENROLL_VERIFIES_PER_PEER: u32 = 4;
/// `Rebind` checks per `RATE_WINDOW_MS`, server-wide, separate from the `Enroll` pool. A flood of bad-signature
/// `Enroll` requests (the join code is public) must not lock enrolled devices out of rebinding. `Rebind` needs
/// a live enrollment first, so fresh PeerIds cannot drain this pool.
const REBIND_VERIFIES_PER_MINUTE: u32 = 120;
/// `Register` proof checks per `RATE_WINDOW_MS`, server-wide: no global cap. A `Register` needs an enrollment
/// bound to one PeerId, so the per-peer share times `max_enrollments` already bounds the CPU. A global pool
/// once let four enrollments lock every other device out of new mailboxes.
const REGISTER_VERIFIES_PER_MINUTE: u32 = u32::MAX;
/// One enrolled peer's share of `REGISTER_VERIFIES_PER_MINUTE`: one full `Register` per window.
const REGISTER_VERIFIES_PER_PEER: u32 = server_proto::MAX_REGISTER_PROOFS as u32;
/// 2026-01-01 UTC. A wall clock before this is wrong (for example, a phone booted with a 1970 or 2020 RTC).
/// No TTL sweep runs on such a clock.
const SANE_WALL_FLOOR_MS: i64 = 1_767_225_600_000;

/// `meta` key: the addresses the running server last advertised, one per line. Management commands read it
/// instead of starting a second server.
const ADVERTISED_ADDRS_KEY: &str = "advertised_addrs";

/// The addresses the running server last advertised (peer id included).
pub fn advertised_addrs(store: &Store) -> Result<Vec<String>, String> {
    let raw = store.meta_get(ADVERTISED_ADDRS_KEY).unwrap_or_default();
    let addrs: Vec<String> = String::from_utf8_lossy(&raw).lines().map(str::to_string).collect();
    if addrs.is_empty() {
        return Err("Sunucunun henüz bir adresi yok — önce `typeon-server run` ile başlatın".to_string());
    }
    Ok(addrs)
}

/// Creates an invite and returns the full invite code. `uses <= 0` means UNLIMITED (see `Store::create_invite`).
/// Needs only the store (see `ADVERTISED_ADDRS_KEY`).
pub fn create_invite(store: &Store, label: &str, uses: i64, ttl_ms: i64) -> Result<String, String> {
    let addrs = advertised_addrs(store)?;
    let mut token = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut token);
    // The token is stored HASHED. Even if the server disk is stolen, unused invites cannot be used.
    let now = now_ms();
    let expires = if ttl_ms <= 0 { 0 } else { now.saturating_add(ttl_ms) };
    store.create_invite(Sha256::digest(token).as_slice(), label, uses, expires, now)?;
    Ok(server_proto::format_server_invite(&addrs, &hex::encode(token)))
}

/// The server's PERMANENT public join code (see `public_join_token`). `rotate`: the old code becomes invalid
/// IMMEDIATELY. Enrolled devices are not affected.
pub fn join_code(store: &Store, rotate: bool) -> Result<String, String> {
    let addrs = advertised_addrs(store)?;
    Ok(server_proto::format_server_invite(&addrs, &public_join_token(store, rotate)?))
}

/// Returns the public join token, creating it if missing. With `rotate`, it first deletes the old one (the old
/// code becomes invalid at once).
///
/// The invite row (unlimited, no expiry) is also guaranteed here. If the operator restores the `data` directory
/// from an old backup, the token may be in `meta` while the invite row is gone. The published code would then
/// silently stop working.
///
/// A free function, because the Android server's JNI layer cannot see `ServerCore` (it lives inside the network
/// task). It uses only `Store`. A second copy of this logic there would drift apart.
pub fn public_join_token(store: &Store, rotate: bool) -> Result<String, String> {
    if rotate {
        if let Some(old) = store.meta_get(PUBLIC_JOIN_TOKEN_KEY) {
            if let Ok(bytes) = hex::decode(String::from_utf8_lossy(&old).trim().as_bytes()) {
                let _ = store.delete_invite(Sha256::digest(&bytes).as_slice());
            }
        }
        store.meta_set(PUBLIC_JOIN_TOKEN_KEY, b"")?;
    }
    let existing = store
        .meta_get(PUBLIC_JOIN_TOKEN_KEY)
        .map(|v| String::from_utf8_lossy(&v).trim().to_string())
        .filter(|v| !v.is_empty());
    let token = match existing {
        Some(t) => t,
        None => {
            let mut raw = [0u8; 20];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            let t = hex::encode(raw);
            store.meta_set(PUBLIC_JOIN_TOKEN_KEY, t.as_bytes())?;
            t
        }
    };
    let raw = hex::decode(&token).map_err(|_| "Katılım jetonu bozuk".to_string())?;
    let hash = Sha256::digest(&raw);
    if store.invite_uses_left(hash.as_slice(), now_ms()) != Some(-1) {
        store.create_invite(hash.as_slice(), PUBLIC_JOIN_LABEL, 0, 0, now_ms())?;
    }
    Ok(token)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `meta` key for the public (permanent) join token. See `ServerCore::join_code`.
const PUBLIC_JOIN_TOKEN_KEY: &str = "public_join_token";
/// Label of the invite row for this token (shown in `invite list`).
const PUBLIC_JOIN_LABEL: &str = "herkese-acik";
/// Maximum NEW enrollments per hour through the public code. See `handle_enroll`.
const MAX_PUBLIC_ENROLLMENTS_PER_HOUR: i64 = 60;
/// Active enrollments the public join code may hold at once. The code never
/// runs out, so without this one leaked code fills every place on the server.
/// A rotated code starts a new count.
const PUBLIC_CODE_MAX_ENROLLMENTS: i64 = 16;
/// Default `ServerConfig::max_enrollments`.
pub const DEFAULT_MAX_ENROLLMENTS: u32 = 64;
/// An active enrollment not seen for this long is removed by `maybe_sweep`.
const ENROLLMENT_IDLE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub data_dir: PathBuf,
    /// Directory for blobs (file attachments). Defaults to `data_dir/blobs`, but can be moved to a SEPARATE
    /// volume (for example an SD card).
    ///
    /// Why separate: blobs are the only large data, while `data_dir` also holds the libp2p identity and the
    /// persistent Tor (arti) state. Moving those to an SD card breaks Tor. arti needs a POSIX permission model for
    /// its key files, which a card mount does not give, and startup fails with `could not read/write persistent
    /// state`. The server would then keep running without the onion service, on a random port, and every enrolled
    /// client would disconnect. So the identity and Tor state ALWAYS stay on internal storage. Only blobs move.
    pub blob_dir: PathBuf,
    /// Serves Circuit Relay v2. The server never runs Kademlia. When disabled, the server only
    /// does mailbox work.
    pub node_mode: bool,
    pub server_name: String,
    pub limits: ServerLimits,
    /// Total disk budget the server may use (see `total_budget_exceeded`). A soft ceiling: it can
    /// overshoot by one 5-second cache window (`TOTAL_CACHE_MS`). `None` means unlimited. The default is
    /// 64 times the per-device quotas. The Android server app derives it from the device's real free space.
    pub total_storage_budget_bytes: Option<u64>,
    /// Maximum active enrollments. A new device is refused above it.
    pub max_enrollments: u32,
}

impl ServerConfig {
    pub fn new(data_dir: PathBuf) -> Self {
        let limits = ServerLimits::default();
        // 64 x (256 MiB mail + 1 GiB archive + 4 GiB blob) = 336 GiB.
        let total = DEFAULT_MAX_ENROLLMENTS as u64
            * (limits.max_mail_bytes + limits.max_archive_bytes + limits.max_blob_bytes);
        ServerConfig {
            blob_dir: data_dir.join("blobs"),
            data_dir,
            node_mode: false,
            server_name: "Typeon Server".to_string(),
            limits,
            total_storage_budget_bytes: Some(total),
            max_enrollments: DEFAULT_MAX_ENROLLMENTS,
        }
    }
}

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
pub struct ServerBehaviour {
    /// Mailbox RPC. `Full` lets the server send `Notify` to clients on its own (see `ServerRequest::Notify`).
    server_rpc: request_response::cbor::Behaviour<ServerRequest, ServerResponse>,
    /// File chunks. `Inbound`: the server only serves them and never requests them.
    file_chunks: request_response::cbor::Behaviour<FileChunkRequest, FileChunkResponse>,
    identify: identify::Behaviour,
    limits: libp2p::connection_limits::Behaviour,
    /// Relay service, enabled in node mode. `Toggle::from(None)` is deliberate: the relay HOP handler
    /// announces the protocol whatever `Config` says. Even a zero-capacity `Behaviour` would advertise
    /// "I am a relay" through identify (the same note as in the core).
    relay: Toggle<relay::Behaviour>,
    /// Call-media relay streams. See `RELAY_PROTOCOL`.
    stream: libp2p_stream::Behaviour,
}

/// Relay stream task to main loop. The loop owns authentication and routing (`live_interest`). The per-stream
/// tasks only move bytes.
enum RelayEvent {
    Open { peer: PeerId, id: u64, tx: tokio::sync::mpsc::Sender<Vec<u8>> },
    Frame { peer: PeerId, mailbox: String, data: Vec<u8> },
    Closed { peer: PeerId, id: u64 },
}

/// Accepts relay streams and turns each into `RelayEvent`s.
///
/// `events` is bounded and awaited. A peer that floods frames is slowed by its own stream, instead of growing
/// a queue in memory.
async fn accept_relay_streams(mut incoming: libp2p_stream::IncomingStreams, events: tokio::sync::mpsc::Sender<RelayEvent>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let live = std::sync::Arc::new(AtomicUsize::new(0));
    let per_peer = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<PeerId, usize>::new()));
    let mut next_id = 0u64;
    while let Some((peer, stream)) = incoming.next().await {
        // Dropping the stream closes it. There is no task and no queue for it.
        if live.load(Ordering::Relaxed) >= MAX_RELAY_STREAMS {
            continue;
        }
        {
            let mut m = per_peer.lock().unwrap_or_else(|e| e.into_inner());
            let n = m.entry(peer).or_insert(0);
            if *n >= MAX_RELAY_STREAMS_PER_PEER {
                continue;
            }
            *n += 1;
        }
        live.fetch_add(1, Ordering::Relaxed);
        next_id += 1;
        let id = next_id;
        let events = events.clone();
        let live = live.clone();
        let per_peer = per_peer.clone();
        tokio::spawn(async move {
            relay_stream(peer, id, stream, events).await;
            live.fetch_sub(1, Ordering::Relaxed);
            let mut m = per_peer.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = m.get_mut(&peer) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&peer);
                }
            }
        });
    }
}

/// One relay stream: frames in become `RelayEvent::Frame`, and the writer queue goes out.
async fn relay_stream(peer: PeerId, id: u64, stream: libp2p::Stream, events: tokio::sync::mpsc::Sender<RelayEvent>) {
    let (mut rd, wr) = futures::AsyncReadExt::split(stream);
    let (tx, rx) = tokio::sync::mpsc::channel(LINK_QUEUE);
    if events.send(RelayEvent::Open { peer, id, tx }).await.is_err() {
        return;
    }
    let mut pump = tokio::spawn(pump_writes(wr, rx));
    loop {
        let frame = tokio::select! {
            // The loop dropped `tx` (not enrolled, revoked, or replaced). Stop reading, or the peer keeps
            // feeding `events`.
            _ = &mut pump => break,
            frame = read_frame(&mut rd) => frame,
        };
        let Ok((mailbox, data)) = frame else { break };
        let Ok(mailbox) = String::from_utf8(mailbox) else { break };
        if events.send(RelayEvent::Frame { peer, mailbox, data }).await.is_err() {
            break;
        }
    }
    let _ = events.send(RelayEvent::Closed { peer, id }).await;
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

/// Per-PeerId state. All connections of one PeerId share it. The challenge is cleared when the last
/// connection closes.
struct ConnState {
    /// Unused `Enroll` challenge issued to this PeerId.
    challenge: Option<Vec<u8>>,
    /// `mono_ms`.
    window_start: u64,
    requests_in_window: u32,
    chunks_in_window: u32,
    /// `mono_ms` of the peer's first open connection. See `UNENROLLED_GRACE_MS`.
    connected_at: u64,
    /// (window start `mono_ms`, checks): this peer's share of the `Enroll`/`Rebind` and `Register` verify pools.
    enroll_verifies: (u64, u32),
    register_verifies: (u64, u32),
}

pub struct ServerCore {
    /// Held for the core's lifetime (flock on `server.lock`).
    _dir_lock: std::fs::File,
    config: ServerConfig,
    store: Store,
    swarm: Swarm<ServerBehaviour>,
    tor: p2p_messenger::tor::TorHandle,
    /// Kept after the connection closes (see `maybe_sweep`). A reconnect must not get a fresh rate budget.
    conns: HashMap<PeerId, ConnState>,
    /// Which mailboxes each enrollment is listening on, for pushing `Notify`. In memory only. It is a live
    /// view of connected peers, not the persistent `mailboxes` table.
    live_interest: HashMap<PeerId, HashSet<String>>,
    /// Peers that owe a `Fetch`, with the `mono_ms` of the last `Notify` sent (0 = send one on the next tick).
    /// One is sent per `NOTIFY_RESEND_MS`, repeated until the peer fetches. See `resend_notifies`.
    notified: HashMap<PeerId, u64>,
    /// `mono_ms` of the last sweep. `None` means sweep on the first tick.
    last_sweep: Option<u64>,
    /// (wall ms, mono ms) pair the wall clock is checked against, and since when (mono ms) it has been off. See
    /// `clock_jumped`.
    clock_anchor: Option<(i64, u64)>,
    clock_off_since: Option<u64>,
    /// Set by `handle_blob_finish`: the request is answered by `finish_blob_hash`, not by the value
    /// `handle_request` returned.
    hash_job: Option<(String, Vec<u8>)>,
    /// Blobs being hashed off the loop, mapped to everyone waiting for the result.
    blob_hashing: HashMap<String, Vec<ResponseChannel<ServerResponse>>>,
    hash_tx: tokio::sync::mpsc::UnboundedSender<HashDone>,
    hash_rx: Option<tokio::sync::mpsc::UnboundedReceiver<HashDone>>,
    pub stats: ServerStats,
    /// See `ServerShared`: a snapshot to read from outside the loop.
    shared: Option<std::sync::Arc<ServerShared>>,
    /// See `set_net_changed_rx` and `notify_network_changed`: Android network-change notice. `run_until` takes
    /// it and listens in `select!`.
    net_changed_rx: Option<tokio::sync::mpsc::UnboundedReceiver<CoreSignal>>,
    /// Taken by `run_until`, which spawns `accept_relay_streams` on it.
    relay_incoming: Option<libp2p_stream::IncomingStreams>,
    /// Authenticated relay links: peer to (stream id, writer queue).
    relay_links: HashMap<PeerId, (u64, tokio::sync::mpsc::Sender<Vec<u8>>)>,
    /// Peer to (window start `mono_ms`, bytes relayed in the window).
    relay_budget: HashMap<PeerId, (u64, usize)>,
    /// (sender, listener) to `mono_ms` of the last frame delivered.
    relay_pairs: HashMap<(PeerId, PeerId), u64>,
    /// An Ack or Cancel removed mail, so `maybe_sweep` recounts the quotas.
    mail_recount_due: bool,
    /// `Store::data_version` at the last revoke scan (see `maybe_sweep`).
    revoke_scan_version: i64,
    /// (`mono_ms` of the read, bytes) for `total_budget_exceeded`.
    total_cache: std::cell::Cell<(u64, u64)>,
    /// (window start `mono_ms`, checks) for `ENROLL_VERIFIES_PER_MINUTE`.
    verify_window: (u64, u32),
    /// Same, for `REGISTER_VERIFIES_PER_MINUTE`.
    register_verify_window: (u64, u32),
    /// Same, for `REBIND_VERIFIES_PER_MINUTE`.
    rebind_verify_window: (u64, u32),
    /// `Rebind` checks per enrollment id (`ENROLL_VERIFIES_PER_PEER` per window). Fresh PeerIds using one id
    /// must not drain the pool above. Keys are existing enrollment ids only.
    rebind_by_enrollment: HashMap<Vec<u8>, (u64, u32)>,
}

/// Server-wide signature check pools. See `verify_budget`.
#[derive(Clone, Copy)]
enum VerifyPool {
    Enroll,
    Rebind,
    Register,
}

/// What the embedding app tells the running loop (Android JNI).
pub enum CoreSignal {
    /// Wi-Fi or cellular changed. See `notify_network_changed`.
    NetworkChanged,
    /// A device was revoked or blocked. Cut its live links now, not at the next sweep tick.
    EnrollmentsChanged,
}

/// (blob id, hash the client claimed, hash of the file, or `None` if unreadable).
type HashDone = (String, Vec<u8>, Option<Vec<u8>>);

/// Snapshot readable from OUTSIDE the main loop.
///
/// Needed by the Android server app. `ServerCore` runs `run()` in its own tokio task, and the UI wants the
/// status every second. A lock on `ServerCore` would stall the loop, so the loop refreshes this cheap copy on
/// every turn instead.
#[derive(Debug, Default)]
pub struct ServerShared {
    pub peer_id: std::sync::Mutex<String>,
    pub addrs: std::sync::Mutex<Vec<String>>,
    pub tor_status: std::sync::Mutex<String>,
    pub stats: std::sync::Mutex<ServerStats>,
}

#[derive(Debug, Default, Clone)]
pub struct ServerStats {
    pub deposits: u64,
    pub fetches: u64,
    pub archive_puts: u64,
    pub blob_chunks_served: u64,
    pub enrollments: u64,
    pub rejected: u64,
    pub relayed: u64,
}


/// See `YAMUX_RECEIVE_WINDOW` in the core. The server's RECEIVE window governs the upload direction
/// (client to server), so this value must be at least as large as the client's. The default is 256 KiB, while
/// a file chunk is 256 KiB plus 16 bytes. Without a larger window, every chunk ends with an extra window update
/// round trip.
fn tuned_yamux() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    #[allow(deprecated)]
    {
        cfg.set_receive_window_size(4 * 1024 * 1024);
        cfg.set_max_buffer_size(8 * 1024 * 1024);
    }
    cfg
}

impl ServerCore {
    pub fn new(config: ServerConfig) -> Result<ServerCore, String> {
        std::fs::create_dir_all(&config.data_dir).map_err(|e| format!("Veri dizini: {e}"))?;
        // The DB holds the libp2p key and the join token: owner only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700));
        }
        std::fs::create_dir_all(&config.blob_dir).map_err(|e| format!("Blob dizini: {e}"))?;
        // Same as `data_dir`. A no-op on FAT/exFAT, which has no modes.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&config.blob_dir, std::fs::Permissions::from_mode(0o700));
        }

        // One process per data dir. A second server on the same DB and Tor state would fight over both. Released
        // when the core is dropped.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(config.data_dir.join("server.lock"))
            .map_err(|e| format!("Kilit dosyası: {e}"))?;
        if lock.try_lock().is_err() {
            return Err(format!(
                "Bu veri dizini ({}) başka bir sunucu işlemi tarafından kullanılıyor",
                config.data_dir.display()
            ));
        }
        let store = Store::open(&config.data_dir.join("typeon_server.db"))?;
        // Rows dated by a wrong clock before a restart (see `clock_jumped` for the same check within one run).
        if now_ms() >= SANE_WALL_FLOOR_MS {
            store.restamp_before(SANE_WALL_FLOOR_MS, now_ms());
        }
        let keypair = load_or_generate_keypair(&store)?;

        // Tor: the server's own onion service, the ONLY way it can be reached (the listener is on loopback only).
        // If Tor cannot start, fail: a server no client can reach would otherwise look like it is running.
        let tor = p2p_messenger::tor::TorHandle::launch(
            &config.data_dir.join("arti_state").to_string_lossy(),
            &config.data_dir.join("arti_cache").to_string_lossy(),
            TOR_LIBP2P_PORT,
        )
        .map_err(|e| format!("Tor başlatılamadı: {e}"))?;
        let node_mode = config.node_mode;

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            // Onion-only. The TCP transport is kept only for incoming onion-bridge connections. Every outgoing
            // TCP (clearnet) dial is rejected with `DialReject`. The server never dials out on its own (store-and-
            // forward works only when clients connect to it, and there is no Tor transport). This also stops kad,
            // autonat or relay behaviour from dialing a peer's real IP over clearnet by accident.
            .with_other_transport(|keypair| {
                use libp2p::core::muxing::StreamMuxerBox;
                use libp2p::core::transport::Transport as _;
                use libp2p::core::upgrade::Version;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    p2p_messenger::tor::DialReject(
                        tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)),
                    )
                    .upgrade(Version::V1Lazy)
                    .authenticate(noise::Config::new(keypair)?)
                    .multiplex(tuned_yamux())
                    .map(|(p, m), _| (p, StreamMuxerBox::new(m))),
                )
            })
            .map_err(|e| e.to_string())?
            .with_behaviour(|keypair| {
                let peer_id = keypair.public().to_peer_id();
                let server_rpc = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(SERVER_PROTOCOL), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_millis(p2p_messenger::server_client_timeout_ms())),
                );
                // 30 s, for the same reason as `file_chunks` in the core. Over Tor, the library's default of 10 s is
                // often too short for a 256 KiB chunk.
                let file_chunks = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(FILE_TRANSFER_PROTOCOL), ProtocolSupport::Inbound)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_millis(p2p_messenger::server_client_timeout_ms())),
                );
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/p2pmessenger/1.0.0".to_string(),
                    keypair.public(),
                )
                // The default of 5 min per client wakes every idle phone's LTE radio.
                .with_interval(Duration::from_secs(3600)));
                let limits = libp2p::connection_limits::Behaviour::new(
                    libp2p::connection_limits::ConnectionLimits::default()
                        .with_max_pending_incoming(Some(MAX_INBOUND_CONNECTIONS))
                        .with_max_established_incoming(Some(MAX_INBOUND_CONNECTIONS))
                        .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER)),
                );
                let relay: Toggle<relay::Behaviour> = if node_mode {
                    // Same limits as a client in node mode.
                    Some(relay::Behaviour::new(peer_id, p2p_messenger::relay_server_config())).into()
                } else {
                    None.into()
                };
                ServerBehaviour { server_rpc, file_chunks, identify, limits, relay, stream: libp2p_stream::Behaviour::new() }
            })
            .map_err(|e| e.to_string())?
            // Same reason as the 600 s value in the core: keep the connection alive during quiet periods, and do
            // not rebuild Tor circuits for nothing.
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(600)))
            .build();

        // Onion-only (see `DialReject`). Bind `127.0.0.1`, not `0.0.0.0`: the listener is on loopback only. The
        // server's onion service bridge connects incoming Tor streams to `127.0.0.1:TOR_LIBP2P_PORT`, so incoming
        // onion traffic works. Direct clearnet connections from the LAN or the internet are NOT accepted, so the
        // server's real IP is never exposed.
        swarm
            .listen_on(format!("/ip4/127.0.0.1/tcp/{}", TOR_LIBP2P_PORT).parse().map_err(|_| "bad multiaddr")?)
            .map_err(|e| e.to_string())?;

        let relay_incoming = swarm.behaviour().stream.new_control().accept(RELAY_PROTOCOL).ok();

        let (hash_tx, hash_rx) = tokio::sync::mpsc::unbounded_channel();
        Ok(ServerCore {
            _dir_lock: lock,
            config,
            store,
            swarm,
            tor,
            conns: HashMap::new(),
            live_interest: HashMap::new(),
            notified: HashMap::new(),
            last_sweep: None,
            clock_anchor: None,
            clock_off_since: None,
            hash_job: None,
            blob_hashing: HashMap::new(),
            hash_tx,
            hash_rx: Some(hash_rx),
            stats: ServerStats::default(),
            shared: None,
            net_changed_rx: None,
            relay_incoming,
            relay_links: HashMap::new(),
            relay_budget: HashMap::new(),
            relay_pairs: HashMap::new(),
            mail_recount_due: false,
            revoke_scan_version: -1,
            total_cache: std::cell::Cell::new((0, 0)),
            verify_window: (0, 0),
            register_verify_window: (0, 0),
            rebind_verify_window: (0, 0),
            rebind_by_enrollment: HashMap::new(),
        })
    }

    /// See `notify_network_changed`. The Android UI sets up a channel in `startServer`, keeps one end here and
    /// the other in `Control`. The `ConnectivityManager` callback pushes to it when the network changes.
    pub fn set_net_changed_rx(&mut self, rx: tokio::sync::mpsc::UnboundedReceiver<CoreSignal>) {
        self.net_changed_rx = Some(rx);
    }

    /// Called from the `run_until` loop when the network interface changes (Wi-Fi drops and returns, or a switch
    /// to cellular). The server is passive (it never dials peers), so the only thing to do is nudge Tor. Circuits
    /// and the onion descriptor should not wait minutes for periodic recovery after a Wi-Fi outage (see
    /// `tor::TorHandle::notify_network_changed`). The libp2p listener is on loopback and stays bound for the
    /// whole process, so no `listen_on` is needed again.
    pub fn notify_network_changed(&self) {
        self.tor.notify_network_changed();
    }

    /// Connects the snapshot read from outside the loop (Android UI).
    pub fn attach_shared(&mut self, shared: std::sync::Arc<ServerShared>) {
        if let Ok(mut p) = shared.peer_id.lock() {
            *p = self.local_peer_id().to_string();
        }
        self.shared = Some(shared);
        self.publish_shared();
    }

    fn publish_shared(&self) {
        // For `create_invite` and `join_code`, which see only the store.
        let addrs = self.invite_addrs().join("\n");
        if self.store.meta_get(ADVERTISED_ADDRS_KEY).as_deref() != Some(addrs.as_bytes()) {
            let _ = self.store.meta_set(ADVERTISED_ADDRS_KEY, addrs.as_bytes());
        }
        let Some(shared) = &self.shared else { return };
        if let Ok(mut a) = shared.addrs.lock() {
            *a = self.advertised_addrs();
        }
        if let Ok(mut t) = shared.tor_status.lock() {
            *t = self.tor_status();
        }
        if let Ok(mut st) = shared.stats.lock() {
            *st = self.stats.clone();
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub fn tor_status(&self) -> String {
        self.tor.status().as_str().to_string()
    }

    /// Advertised address. Onion only: the listener is on loopback (see `new`).
    pub fn advertised_addrs(&self) -> Vec<String> {
        self.tor
            .onion_host()
            .map(|host| format!("/dns/{}/tcp/{}/p2p/{}", host, TOR_LIBP2P_PORT, self.local_peer_id()))
            .into_iter()
            .collect()
    }

    /// Addresses that go into an invite code. Private-network addresses are filtered out: a recipient on another
    /// network cannot reach them, and they leak the server's internal network layout.
    pub fn invite_addrs(&self) -> Vec<String> {
        self.advertised_addrs()
            .into_iter()
            .filter(|a| server_proto::is_onion_server_addr(a))
            .collect()
    }

    // -----------------------------------------------------------------
    // Main loop
    // -----------------------------------------------------------------

    pub async fn run(self) -> Result<(), String> {
        self.run_until(std::future::pending::<()>()).await
    }

    /// Stoppable form of `run`. When `shutdown` completes, the loop ends and `ServerCore` is dropped (swarm,
    /// listeners, onion service).
    ///
    /// The Android server app's `ServerLib` had no way to stop it. `stopService(...)` only released the wake
    /// lock and removed the foreground notification. The Rust core kept running: it still accepted mail, served
    /// blobs, and used battery and disk. The app showed "off" while the server was on. The second half was
    /// worse: `CONTROL` stayed full, so later `startServer` calls did nothing. Changes to node mode, server
    /// name, blob directory or disk budget were then never applied until the process was killed.
    pub async fn run_until(
        mut self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), String> {
        info!("Typeon sunucusu başladı");
        debug!("peer_id={}", self.local_peer_id());
        // The timer and the signal MUST be separate local variables. `tokio::select!` creates the futures of all
        // branches in the same scope, and the swarm branch borrows `self`. Writing them inline would create a
        // second `&mut self` borrow, which does not compile.
        let mut sweep = tokio::time::interval(Duration::from_secs(5));
        let ctrlc = tokio::signal::ctrl_c();
        // See the module note and the comment above. A future that borrows `self` cannot be written inline, so
        // the receiver is moved into a local variable.
        let mut net_changed_rx = self.net_changed_rx.take();
        let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel(LINK_QUEUE);
        let Some(mut hash_rx) = self.hash_rx.take() else {
            return Err("run_until çağrıldı: döngü zaten çalıştırılmış".to_string());
        };
        if let Some(incoming) = self.relay_incoming.take() {
            tokio::spawn(accept_relay_streams(incoming, relay_tx));
        }
        futures::pin_mut!(ctrlc);
        futures::pin_mut!(shutdown);
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.handle_swarm_event(event),
                _ = sweep.tick() => self.maybe_sweep(),
                Some(ev) = relay_rx.recv() => self.handle_relay(ev),
                Some(done) = hash_rx.recv() => self.finish_blob_hash(done),
                // See `notify_network_changed`. If there is no channel, or it has closed, this branch waits forever
                // and never fires.
                Some(signal) = async {
                    match &mut net_changed_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<CoreSignal>>().await,
                    }
                } => match signal {
                    CoreSignal::NetworkChanged => {
                        info!("Ağ değişikliği bildirildi — Tor tazeleniyor");
                        self.notify_network_changed();
                    }
                    CoreSignal::EnrollmentsChanged => self.drop_revoked_peers(),
                },
                _ = &mut shutdown => {
                    info!("Durdurma istendi, kapatılıyor.");
                    return Ok(());
                }
                _ = &mut ctrlc => {
                    info!("Kapatılıyor.");
                    return Ok(());
                }
            }
        }
    }

    fn handle_swarm_event(&mut self, event: SwarmEvent<ServerBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Dinleniyor: {}/p2p/{}", address, self.local_peer_id());
                // An invite code can only be built once an address is known. Refresh the snapshot before waiting.
                self.publish_shared();
            }
            SwarmEvent::ConnectionEstablished { peer_id, num_established, .. } => {
                let now = mono_ms();
                let conn = self.conns.entry(peer_id).or_insert(ConnState {
                    challenge: None,
                    window_start: now,
                    requests_in_window: 0,
                    chunks_in_window: 0,
                    connected_at: now,
                    enroll_verifies: (0, 0),
                    register_verifies: (0, 0),
                });
                if num_established.get() == 1 {
                    conn.connected_at = now;
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                if num_established == 0 {
                    // The rate window and relay budget outlive the connection. `maybe_sweep` drops them once they expire.
                    if let Some(c) = self.conns.get_mut(&peer_id) {
                        c.challenge = None;
                    }
                    self.live_interest.remove(&peer_id);
                    self.notified.remove(&peer_id);
                }
            }
            SwarmEvent::Behaviour(ServerBehaviourEvent::ServerRpc(
                request_response::Event::Message { peer, message },
            )) => {
                if let request_response::Message::Request { request, channel, .. } = message {
                    let response = self.handle_request(peer, request);
                    match self.hash_job.take() {
                        Some((blob_id, enc_sha256)) => self.start_blob_hash(blob_id, enc_sha256, channel),
                        None => {
                            let _ = self.swarm.behaviour_mut().server_rpc.send_response(channel, response);
                        }
                    }
                }
            }
            // A `Push` or `Notify` that did not arrive: the reader still owes a `Fetch`. It is due at once (0), and
            // `resend_notifies` sends it.
            SwarmEvent::Behaviour(ServerBehaviourEvent::ServerRpc(
                request_response::Event::OutboundFailure { peer, .. },
            )) => {
                if self.live_interest.contains_key(&peer) {
                    self.notified.entry(peer).or_insert(0);
                }
            }
            SwarmEvent::Behaviour(ServerBehaviourEvent::FileChunks(
                request_response::Event::Message { peer, message },
            )) => {
                if let request_response::Message::Request { request, channel, .. } = message {
                    self.serve_chunk(peer, request, channel);
                }
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------
    // Request handling
    // -----------------------------------------------------------------

    fn handle_request(&mut self, peer: PeerId, req: ServerRequest) -> ServerResponse {
        if !self.check_rate(peer, false, request_cost(&req)) {
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }

        match req {
            ServerRequest::Hello { version } => self.handle_hello(peer, version),
            ServerRequest::Enroll { version, invite_token, enroll_pk, enroll_pk_pq, challenge, ts_ms, sig, sig_pq } => {
                self.handle_enroll(peer, version, invite_token, enroll_pk, enroll_pk_pq, challenge, ts_ms, sig, sig_pq)
            }
            ServerRequest::Rebind { enrollment_id, ts_ms, sig, sig_pq } => {
                self.handle_rebind(peer, enrollment_id, ts_ms, sig, sig_pq)
            }

            // --- Enrollment is REQUIRED from here on ---
            other => {
                let Some(e) = self.authenticate(peer) else {
                    self.stats.rejected += 1;
                    return ServerResponse::Err(ServerErrorCode::NotEnrolled);
                };
                if e.state == EnrollmentState::Revoked {
                    self.stats.rejected += 1;
                    return ServerResponse::Err(ServerErrorCode::Revoked);
                }
                self.handle_authenticated(peer, &e, other)
            }
        }
    }

    fn handle_hello(&mut self, peer: PeerId, version: u16) -> ServerResponse {
        if version != SERVER_PROTOCOL_VERSION {
            return ServerResponse::Err(ServerErrorCode::Unsupported);
        }
        let mut challenge = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        // Only an ACTIVE enrollment counts as registered.
        //
        // This used to be `.is_some()`, and that locked a revoked device out for good. The client saw
        // `Welcome.enrolled = true`, skipped the `Enroll` step, and every request then returned `Revoked` from
        // `authenticate` (state == Revoked). The user saw "The operator revoked the enrollment" on a freshly added
        // device, and it never recovered. The revoke key also blocks re-enrollment (see `Store::revoke_enrollment`):
        // the client goes to `Enroll` and gets `Revoked` until the operator lifts the block.
        let enrollment_id = self
            .store
            .enrollment_by_peer(&peer.to_string())
            .filter(|e| e.state == EnrollmentState::Active)
            .map(|e| e.enrollment_id);
        let enrolled = enrollment_id.is_some();
        if let Some(c) = self.conns.get_mut(&peer) {
            c.challenge = Some(challenge.clone());
        }
        ServerResponse::Welcome {
            version: SERVER_PROTOCOL_VERSION,
            challenge,
            enrolled,
            enrollment_id,
            limits: self.config.limits.clone(),
            server_name: self.config.server_name.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_enroll(
        &mut self,
        peer: PeerId,
        version: u16,
        invite_token: Vec<u8>,
        enroll_pk: Vec<u8>,
        enroll_pk_pq: Vec<u8>,
        client_challenge: Vec<u8>,
        ts_ms: u64,
        sig: Vec<u8>,
        sig_pq: Vec<u8>,
    ) -> ServerResponse {
        if version != SERVER_PROTOCOL_VERSION {
            return ServerResponse::Err(ServerErrorCode::Unsupported);
        }
        let now = now_ms();
        if (now as u64).abs_diff(ts_ms) > server_proto::ENROLL_MAX_SKEW_MS {
            return ServerResponse::Err(ServerErrorCode::Stale);
        }
        // Cheap gate before the hybrid verify (ML-DSA-87 is the expensive step, and PeerIds are free): no usable
        // invite, no signature check.
        let hash = Sha256::digest(&invite_token);
        if matches!(self.store.invite_uses_left(hash.as_slice(), now), None | Some(0)) {
            return ServerResponse::Err(ServerErrorCode::BadInvite);
        }
        // The challenge is single-use (`take`). Otherwise an observer could capture the signature and replay it.
        // It is random and per connection, so removing it from memory is enough.
        let Some(challenge) = self.conns.get_mut(&peer).and_then(|c| c.challenge.take()) else {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        };
        // The challenge the client signed must be the one WE issued.
        if !ct_eq(&client_challenge, &challenge) {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        if !self.verify_budget(peer, VerifyPool::Enroll, 1) {
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }

        let signing_input = server_proto::enroll_signing_input(
            version,
            &self.local_peer_id().to_string(),
            &peer.to_string(),
            &invite_token,
            &enroll_pk,
            &enroll_pk_pq,
            &challenge,
            ts_ms,
        );
        // HYBRID: both must pass. A classical signature alone would let a harvest-now-break-later attacker forge
        // registrations in the future.
        if !verify_hybrid(&enroll_pk, &enroll_pk_pq, &signing_input, &sig, &sig_pq) {
            // A failed attempt costs one use of a counted invite. Otherwise a leaked code stayed a free verify oracle.
            // The unlimited join code has no uses to spend (`verify_budget` bounds it).
            let _ = self.store.consume_invite(hash.as_slice(), now);
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        // Operator decision: revoke means block. Both block the enrollment KEY, so the same device cannot enroll
        // again even with a new invite. Only a new PeerId with a new key (a reinstall) gets through. This is an
        // operator control, not an absolute ban. The check happens AFTER signature verification. Blocking before the
        // key is proven to belong to this device would let someone block another device by writing its key.
        // The key this PeerId enrolled with before counts too. The device makes its enroll key itself, so a fresh
        // one alone must not lift a block.
        let prev = self.store.enrollment_by_peer(&peer.to_string());
        if self.store.is_key_blocked(&enroll_pk)
            || prev.as_ref().map_or(false, |p| self.store.is_key_blocked(&p.enroll_pk))
        {
            warn!("Engellenen anahtarla kayıt denemesi reddedildi");
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }

        // The Sybil gate for the public (unlimited) join code is NOT the single use of the token. That property was
        // dropped on purpose (see `join_code`). This check replaces it: an unlimited code cannot open new enrollments
        // once the last hour's enrollment count reaches `MAX_PUBLIC_ENROLLMENTS_PER_HOUR`. The window counts ALL
        // enrollments, including those opened with a counted invite. The aim is to limit the server's enrollment
        // rate, not one code. The cap is well above the join rate of a real group, and low for an automated flood.
        // The operator can close the code at once with `rotate_join_code`. The cap is checked BEFORE the counter is
        // consumed, so a refused attempt must not spend the invite's use.
        if self.store.invite_uses_left(hash.as_slice(), now) == Some(-1) {
            let since = now - 60 * 60 * 1000;
            if self.store.count_enrollments_since(since, now) >= MAX_PUBLIC_ENROLLMENTS_PER_HOUR {
                warn!("Herkese açık katılım kodu saatlik tavanı aştı, kayıt reddedildi");
                self.stats.rejected += 1;
                return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
            }
            if !prev.as_ref().map_or(false, |p| p.state == EnrollmentState::Active)
                && self.store.count_active_enrollments_via(hash.as_slice(), now - ENROLLMENT_IDLE_MS) >= PUBLIC_CODE_MAX_ENROLLMENTS
            {
                warn!("Enrollment refused: the public join code holds its maximum number of devices");
                self.stats.rejected += 1;
                return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
            }
        }
        // A PeerId that enrolls again takes no new place.
        if !prev.as_ref().map_or(false, |p| p.state == EnrollmentState::Active)
            && self.store.count_active_enrollments(now - ENROLLMENT_IDLE_MS) >= self.config.max_enrollments as i64
        {
            warn!("Enrollment refused: the server holds its maximum number of devices");
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // If the same PeerId enrolls again (`peer_id` is UNIQUE, insert with `OR REPLACE`), inherit the old identity
        // and quota counters. Otherwise a new `enrollment_id` with zeroed counters would leave the existing
        // mail/archive/blob rows ownerless and reset the quota.
        let enrollment_id = match &prev {
            Some(p) => p.enrollment_id.clone(),
            None => {
                let mut id = vec![0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut id);
                id
            }
        };
        let e = Enrollment {
            enrollment_id: enrollment_id.clone(),
            enroll_pk,
            enroll_pk_pq,
            peer_id: peer.to_string(),
            state: EnrollmentState::Active,
            enrolled_at: prev.as_ref().map_or(now, |p| p.enrolled_at),
            last_seen_at: now,
            bytes_mail: prev.as_ref().map_or(0, |p| p.bytes_mail),
            bytes_archive: prev.as_ref().map_or(0, |p| p.bytes_archive),
            bytes_blob: prev.as_ref().map_or(0, |p| p.bytes_blob),
        };
        // One transaction. A failed insert must not cost the invite its use.
        match self.store.enroll_with_invite(hash.as_slice(), now, &e) {
            Ok(true) => {}
            Ok(false) => return ServerResponse::Err(ServerErrorCode::BadInvite),
            Err(msg) => {
                error!("Kayıt yazılamadı: {msg}");
                return ServerResponse::Err(ServerErrorCode::Internal);
            }
        }
        self.stats.enrollments += 1;
        debug!("Yeni kayıt: {}", hex::encode(&enrollment_id));
        ServerResponse::Enrolled { enrollment_id, limits: self.config.limits.clone() }
    }

    fn handle_rebind(
        &mut self,
        peer: PeerId,
        enrollment_id: Vec<u8>,
        ts_ms: u64,
        sig: Vec<u8>,
        sig_pq: Vec<u8>,
    ) -> ServerResponse {
        let now = now_ms();
        if (now as u64).abs_diff(ts_ms) > server_proto::ENROLL_MAX_SKEW_MS {
            return ServerResponse::Err(ServerErrorCode::Stale);
        }
        // The same single-use challenge as `Enroll`. Without it (and the caller's PeerId) in the signed bytes, a
        // captured Rebind could be replayed to move the enrollment to someone else within the skew window.
        let Some(challenge) = self.conns.get_mut(&peer).and_then(|c| c.challenge.take()) else {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        };
        let Some(existing) = self.store.enrollment_by_id(&enrollment_id) else {
            return ServerResponse::Err(ServerErrorCode::NotEnrolled);
        };
        let per_id = self.rebind_by_enrollment.entry(enrollment_id.clone()).or_insert((0, 0));
        let mut no_pool = (0, 0);
        if !charge_verify(per_id, &mut no_pool, mono_ms(), 1, ENROLL_VERIFIES_PER_PEER, u32::MAX)
            || !self.verify_budget(peer, VerifyPool::Rebind, 1)
        {
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        let input = server_proto::rebind_signing_input(
            &enrollment_id,
            &self.local_peer_id().to_string(),
            &peer.to_string(),
            &challenge,
            ts_ms,
        );
        if !verify_hybrid(&existing.enroll_pk, &existing.enroll_pk_pq, &input, &sig, &sig_pq) {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        // After the signature check, so only the key holder learns the id is revoked.
        if existing.state == EnrollmentState::Revoked {
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }
        // A blocked key cannot rebind either (see `handle_enroll`).
        if self.store.is_key_blocked(&existing.enroll_pk) {
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }
        if let Err(msg) = self.store.rebind_enrollment(&enrollment_id, &peer.to_string(), now) {
            error!("Rebind yazılamadı: {msg}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        ServerResponse::Enrolled { enrollment_id, limits: self.config.limits.clone() }
    }

    /// Resolves the enrollment from the `PeerId` that Noise PROVED. No field the packet CLAIMS is trusted. This
    /// is the same reason the core rate-limits by `PeerId` rather than by `sender_device_fingerprint`.
    fn authenticate(&self, peer: PeerId) -> Option<Enrollment> {
        self.store.enrollment_by_peer(&peer.to_string())
    }

    /// Like `authenticate`, but only for an enrollment the operator has not revoked. Read from the DB every time:
    /// revoke and block arrive over another connection (JNI or CLI) while the peer stays connected.
    fn active(&self, peer: PeerId) -> Option<Enrollment> {
        self.authenticate(peer).filter(|e| e.state == EnrollmentState::Active)
    }

    /// Checks whether `incoming` more bytes would exceed the server's TOTAL disk budget.
    ///
    /// Found during review: the budget was enforced only in `handle_blob_put`. Mail and archive were limited per
    /// record only, so a server with enough records (or just enough users) could use far more than the budget.
    /// Disk-full on a phone or tablet is exactly what this mechanism exists to prevent. Blobs are the largest, but
    /// not the only, consumers: 30-day TTL mail and unlimited archive grow too.
    fn total_budget_exceeded(&self, incoming: usize) -> bool {
        let Some(total_budget) = self.config.total_storage_budget_bytes else {
            return false;
        };
        // The sum reads every mail, archive and blob row: at most once per `TOTAL_CACHE_MS`, with the bytes written
        // since then added on top (`note_total_written`).
        let mono = mono_ms();
        let (mut at, mut total) = self.total_cache.get();
        if at == 0 || mono.saturating_sub(at) > TOTAL_CACHE_MS {
            total = self.store.total_stored_bytes().max(0) as u64;
            at = mono.max(1);
            self.total_cache.set((at, total));
        }
        total.saturating_add(incoming as u64) > total_budget
    }

    /// Adds bytes that were actually written to the cached total. Only written bytes count. A refused or no-op
    /// request would otherwise charge the cache, and one device could block everyone else's writes.
    fn note_total_written(&self, bytes: usize) {
        let (at, total) = self.total_cache.get();
        if at != 0 {
            self.total_cache.set((at, total.saturating_add(bytes as u64)));
        }
    }

    fn handle_authenticated(&mut self, peer: PeerId, e: &Enrollment, req: ServerRequest) -> ServerResponse {
        let now = now_ms();
        // `last_seen_at` is for the operator, not a write per request.
        if now - e.last_seen_at > 60_000 {
            self.store.touch_enrollment(&e.enrollment_id, now);
        }
        let limits = self.config.limits.clone();

        // Each list element costs a query inside the event loop.
        let boxes = limits.max_mailboxes as usize;
        let too_long = match &req {
            ServerRequest::Register { add, drop, proofs } => {
                add.len().max(drop.len()) > boxes || proofs.len() > server_proto::MAX_REGISTER_PROOFS
            }
            ServerRequest::Fetch { cursors, .. } => cursors.len() > boxes,
            ServerRequest::Ack { acks } => acks.len() > boxes,
            ServerRequest::ArchiveProbe { buckets } | ServerRequest::ArchivePurge { buckets } => buckets.len() > boxes,
            ServerRequest::Cancel { seqs, .. } => seqs.len() > boxes,
            ServerRequest::ArchivePut { records, .. } => records.len() > server_proto::MAX_ARCHIVE_PUT_RECORDS,
            _ => false,
        };
        if too_long {
            return ServerResponse::Err(ServerErrorCode::TooLarge);
        }
        // Every mailbox and bucket id the server stores or looks up. Client ids always pass, so a failure means a
        // hostile request.
        let bad_id = match &req {
            ServerRequest::Register { add, drop, .. } => add.iter().chain(drop.iter()).any(|id| !is_safe_id(id)),
            ServerRequest::Fetch { cursors: list, .. } | ServerRequest::Ack { acks: list } => {
                list.iter().any(|(id, _)| !is_safe_id(id))
            }
            ServerRequest::ArchiveProbe { buckets } | ServerRequest::ArchivePurge { buckets } => {
                buckets.iter().any(|id| !is_safe_id(id))
            }
            ServerRequest::Deposit { mailbox: id, .. }
            | ServerRequest::Cancel { mailbox: id, .. }
            | ServerRequest::ArchivePut { bucket: id, .. }
            | ServerRequest::ArchiveFetch { bucket: id, .. } => !is_safe_id(id),
            _ => false,
        };
        if bad_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }

        match req {
            ServerRequest::Register { add, drop, proofs } => {
                // Only a proof for an id in `add` is verified, and only one with a valid signature reaches the store.
                // Each proof is a hybrid verify. Without a server-wide budget, 64 enrollments times 64 proofs would pin
                // the CPU.
                let checks = proofs.iter().filter(|p| add.contains(&p.mailbox)).count() as u32;
                if checks > 0 && !self.verify_budget(peer, VerifyPool::Register, checks) {
                    return ServerResponse::Err(ServerErrorCode::RateLimited);
                }
                let me = self.swarm.local_peer_id().to_string();
                let proved: Vec<(String, Vec<u8>)> = proofs
                    .iter()
                    .filter(|p| add.contains(&p.mailbox))
                    .filter(|p| {
                        let input = server_proto::register_signing_input(&p.mailbox, &e.enrollment_id, &me);
                        verify_hybrid(&p.pk, &p.pk_pq, &input, &p.sig, &p.sig_pq)
                    })
                    .map(|p| (p.mailbox.clone(), server_proto::mailbox_key_hash(&p.pk, &p.pk_pq).to_vec()))
                    .collect();
                // A proof that did not verify is a refusal, not `proof_needed`. The client would send the same bytes again.
                let bad_proof = proofs.iter().filter(|p| add.contains(&p.mailbox)).count().saturating_sub(proved.len());
                let registered = self.store.register_mailboxes_proved(&e.enrollment_id, &add, &drop, &proved, now, limits.max_mailboxes);
                let (refused, unproven) = match registered {
                    Ok((refused, unproven)) => {
                        let (bad, unproven): (Vec<String>, Vec<String>) =
                            unproven.into_iter().partition(|id| proofs.iter().any(|p| &p.mailbox == id));
                        (refused.into_iter().chain(bad).collect::<Vec<String>>(), unproven)
                    }
                    Err(msg) => {
                        error!("Register yazılamadı: {msg}");
                        return ServerResponse::Err(ServerErrorCode::Internal);
                    }
                };
                let interest = self.live_interest.entry(peer).or_default();
                for id in add {
                    if !refused.contains(&id) && !unproven.contains(&id) {
                        interest.insert(id);
                    }
                }
                for id in &drop {
                    interest.remove(id);
                }
                // Every id not named is registered. Each named one says why (see `ServerResponse::Registered`).
                if unproven.is_empty() && refused.is_empty() {
                    return ServerResponse::Ok;
                }
                if !refused.is_empty() {
                    warn!("Register: {} kutu reddedildi (kota, okuyucu sınırı ya da anahtar), {} kanıt doğrulanmadı", refused.len(), bad_proof);
                }
                ServerResponse::Registered { proof_needed: unproven, refused }
            }

            ServerRequest::Deposit { mailbox, sealed } => {
                if sealed.len() > limits.max_item_bytes as usize || sealed.len() > MAX_DEPOSIT_BYTES {
                    return ServerResponse::Err(ServerErrorCode::TooLarge);
                }
                // Depositing into a mailbox that is not registered tells the client "this recipient is not on my
                // server". That sends the traffic straight to gossipsub, so no round trip is wasted on every message.
                if !self.store.mailbox_has_other_reader(&mailbox, &e.enrollment_id) {
                    return ServerResponse::Err(ServerErrorCode::UnknownMailbox);
                }
                // Only this request's own counter. A full blob quota must not stop the device from messaging.
                if e.bytes_mail as u64 > limits.max_mail_bytes {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // See `total_budget_exceeded`. The per-record quota alone does not protect the device's disk.
                if self.total_budget_exceeded(store::mail_row_bytes(&mailbox, &sealed)) {
                    warn!("Toplam disk bütçesi doldu, teslim reddedildi");
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // Per depositor (see `depositor_item_count`). A box full of someone else's deposits must not refuse ours.
                if self.store.depositor_item_count(&mailbox, &e.enrollment_id) >= limits.max_items_per_mailbox as i64 {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                match self.store.deposit(&mailbox, &sealed, &e.enrollment_id, now, limits.mailbox_ttl_ms as i64) {
                    Ok(seq) => {
                        self.note_total_written(store::mail_row_bytes(&mailbox, &sealed));
                        self.stats.deposits += 1;
                        let item = MailItem { mailbox_id: mailbox.clone(), seq, deposited_at_ms: now as u64, sealed };
                        self.notify_owner_of(&mailbox, peer, item);
                        ServerResponse::Deposited { seq }
                    }
                    Err(msg) => {
                        error!("Deposit yazılamadı: {msg}");
                        ServerResponse::Err(ServerErrorCode::Internal)
                    }
                }
            }

            ServerRequest::Fetch { cursors, max_items, max_bytes } => {
                self.notified.remove(&peer);
                let (items, more) = self.store.fetch(
                    &e.enrollment_id,
                    &cursors,
                    // 0 would answer an empty batch with `more` forever.
                    max_items.clamp(1, MAX_FETCH_BATCH_ITEMS),
                    max_bytes.clamp(1, MAX_FETCH_BATCH_BYTES),
                );
                self.stats.fetches += 1;
                ServerResponse::Batch { items, more }
            }

            ServerRequest::Ack { acks } => {
                let mut deleted = 0;
                for (mailbox, seq) in acks {
                    deleted += self.store.ack(&mailbox, seq, &e.enrollment_id).unwrap_or(0);
                }
                if deleted > 0 {
                    // Quota must not only grow. Delivered bytes are charged back to the depositor's account.
                    self.mail_recount_due = true;
                }
                ServerResponse::Ok
            }

            // See `ServerRequest::Cancel`. The sender withdraws its own undelivered packet. The ownership check is in
            // the query itself: `depositor = requester`.
            ServerRequest::Cancel { mailbox, seqs } => {
                let removed = self.store.cancel_own_deposits(&mailbox, &seqs, &e.enrollment_id);
                if removed > 0 {
                    self.mail_recount_due = true;
                    info!("Gönderen {} paketi geri çekti", removed);
                }
                ServerResponse::Ok
            }

            ServerRequest::ArchivePut { bucket, records } => {
                if records.iter().any(|r| r.sealed.len() > MAX_DEPOSIT_BYTES) {
                    return ServerResponse::Err(ServerErrorCode::TooLarge);
                }
                if e.bytes_archive as u64 > limits.max_archive_bytes {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // See `total_budget_exceeded`. Unlike mail, the archive has no TTL: once written it stays until an
                // `ArchivePurge` arrives. It is the largest contributor to the total ceiling.
                let incoming: usize = records.iter().map(store::archive_row_bytes).sum();
                if self.total_budget_exceeded(incoming) {
                    warn!("Toplam disk bütçesi doldu, arşiv yazımı reddedildi");
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                match self.store.archive_put(&bucket, &records, &e.enrollment_id, now) {
                    Ok(_) => {
                        self.note_total_written(incoming);
                        self.stats.archive_puts += 1;
                        ServerResponse::Ok
                    }
                    Err(msg) => {
                        error!("ArchivePut yazılamadı: {msg}");
                        ServerResponse::Err(ServerErrorCode::Internal)
                    }
                }
            }

            ServerRequest::ArchiveProbe { buckets } => {
                ServerResponse::ArchiveProbed { present: self.store.archive_probe(&buckets) }
            }

            ServerRequest::ArchiveFetch { bucket, before_ms, before_id, max_items, max_bytes } => {
                let (records, more) = self.store.archive_fetch(
                    &bucket,
                    before_ms.map(|ms| (ms, before_id.as_deref().unwrap_or(""))),
                    max_items.clamp(1, MAX_FETCH_BATCH_ITEMS),
                    max_bytes.clamp(1, MAX_FETCH_BATCH_BYTES),
                );
                ServerResponse::ArchiveBatch { records, more }
            }

            ServerRequest::ArchivePurge { buckets } => {
                self.store.archive_purge(&buckets);
                ServerResponse::Ok
            }

            // The id is the hash of the uploader's secret (see `server_proto::blob_id_for_upload_secret`). A
            // FileOffer recipient knows only the id, so it cannot claim the blob first.
            ServerRequest::BlobPut { upload_secret, chunk_index, total_chunks, chunk_size, data } => {
                let Some(blob_id) = server_proto::blob_id_for_upload_secret(&upload_secret) else {
                    return ServerResponse::Err(ServerErrorCode::BadDirection);
                };
                self.handle_blob_put(e, &limits, blob_id, chunk_index, total_chunks, chunk_size, data, now)
            }

            ServerRequest::BlobFinish { upload_secret, total_chunks, enc_sha256 } => {
                let Some(blob_id) = server_proto::blob_id_for_upload_secret(&upload_secret) else {
                    return ServerResponse::Err(ServerErrorCode::BadDirection);
                };
                self.handle_blob_finish(e, blob_id, total_chunks, enc_sha256)
            }

            ServerRequest::BlobDelete { upload_secret } => {
                if let Some(blob_id) = server_proto::blob_id_for_upload_secret(&upload_secret) {
                    if self.store.blob_state(&blob_id).map_or(false, |s| s.owner == e.enrollment_id) {
                        self.drop_blob(&blob_id);
                    }
                }
                ServerResponse::Ok
            }

            // Types a client may never send to the server.
            ServerRequest::Hello { .. }
            | ServerRequest::Enroll { .. }
            | ServerRequest::Rebind { .. }
            | ServerRequest::Notify
            | ServerRequest::Push { .. } => ServerResponse::Err(ServerErrorCode::BadDirection),
        }
    }

    // -----------------------------------------------------------------
    // Blobs
    // -----------------------------------------------------------------

    fn blob_path(&self, blob_id: &str) -> PathBuf {
        // `blob_id` comes from the client. It must be checked as hex/alphanumeric BEFORE it is used as a file path.
        // Otherwise `../` could write outside the directory.
        self.config.blob_dir.join(format!("{}.enc", sanitize_id(blob_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_blob_put(
        &mut self,
        e: &Enrollment,
        limits: &ServerLimits,
        blob_id: String,
        chunk_index: u32,
        total_chunks: u32,
        chunk_size: u32,
        data: Vec<u8>,
        now: i64,
    ) -> ServerResponse {
        if !is_safe_id(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if data.len() > server_proto::MAX_BLOB_CHUNK_BYTES
            || chunk_size as u64 + 16 > server_proto::MAX_BLOB_CHUNK_BYTES as u64
        {
            return ServerResponse::Err(ServerErrorCode::TooLarge);
        }
        // Before any row exists: `total_chunks: 0` used to mint a free row per request.
        if chunk_index >= total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // The offset comes from the client's `chunk_index` and `chunk_size`. Left unbounded, a 1-byte chunk at a
        // huge offset would extend the file by terabytes. Only 1 byte would be charged, and on a filesystem without
        // sparse file support the disk would fill. The end of the file must not exceed the device's blob quota.
        let stride = if chunk_size == 0 { attachments::FILE_CHUNK_SIZE as u64 } else { chunk_size as u64 };
        let offset = chunk_index as u64 * (stride + 16);
        if offset + data.len() as u64 > limits.max_blob_bytes {
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Charged: how far this write extends the file, not `data.len()`. A 1-byte chunk at a far offset allocates
        // the whole gap on a volume without sparse files (an SD card), and would cost only 1 byte of quota.
        let path = self.blob_path(&blob_id);
        let file_len = std::fs::metadata(&path).map_or(0, |m| m.len());
        // At least one row's worth: a 0-byte chunk still costs a DB row (and, for a new blob, a file).
        let growth = (offset + data.len() as u64).saturating_sub(file_len).max(BLOB_CHUNK_MIN_CHARGE);
        if e.bytes_blob.max(0) as u64 + growth > limits.max_blob_bytes {
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Quotas used to be applied only per record. The budget is split by a fixed `EXPECTED_DEVICES = 8`, so with
        // 20 devices enrolled the real ceiling was 2.5 times the budget. Disk-full on a tablet is exactly what this
        // mechanism exists to prevent. The total is checked now too.
        if self.total_budget_exceeded(growth as usize) {
            warn!("Toplam disk bütçesi doldu, blob parçası reddedildi");
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Ownership: only the record that started a blob may write to it. A row is created only for an id nobody
        // holds. The second read also covers a first attempt that failed (busy DB), which used to skip this check.
        if self.store.blob_state(&blob_id).is_none() {
            // Bytes are capped above. This caps files (inodes) and rows.
            if self.store.blob_count(&e.enrollment_id) >= MAX_BLOBS_PER_ENROLLMENT {
                return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
            }
            if let Err(msg) = self.store.blob_begin(&blob_id, &e.enrollment_id, total_chunks, now) {
                error!("blob_begin: {msg}");
                return ServerResponse::Err(ServerErrorCode::Internal);
            }
        }
        let Some(state) = self.store.blob_state(&blob_id) else {
            return ServerResponse::Err(ServerErrorCode::Internal);
        };
        if state.owner != e.enrollment_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // A verified blob is final. Another chunk (or a new stride) would let `serve_chunk` hand out bytes the hash
        // never covered.
        if state.complete {
            return ServerResponse::Ok;
        }
        if chunk_index >= state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // The stride is fixed by the first chunk (`blob_set_chunk_size`). Another one would write where `serve_chunk`
        // does not read.
        if (state.chunk_size != 0 || state.received_chunks > 0) && state.chunk_size != chunk_size {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // Same reason while `BlobFinish` is hashing the file.
        if self.blob_hashing.contains_key(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        // Already written: a repeat of the same chunk is idempotent.
        if self.store.blob_has_chunk(&blob_id, chunk_index) {
            return ServerResponse::Ok;
        }

        // Positional write, not an append. Appending required chunks to arrive strictly in order. The client could
        // then send only one chunk at a time, and throughput was limited to chunk/round-trip. A 10 MB upload measured
        // about 12 KB/s over Tor. The `.enc` format has a fixed stride (see `attachments::read_chunk_from_disk`), so
        // writing at an offset is safe.
        use std::io::{Seek, SeekFrom, Write};
        // The stride is stored WITH the blob. `serve_chunk` must read with the same value.
        self.store.blob_set_chunk_size(&blob_id, chunk_size);
        let write = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .and_then(|mut f| {
                f.seek(SeekFrom::Start(offset))?;
                f.write_all(&data)
            });
        if let Err(err) = write {
            error!("Blob yazılamadı: {err}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        // The bytes are on disk, so they are charged even if the bookkeeping below fails. The resent chunk then grows
        // nothing and pays only the minimum. Such a failure over-charges the owner by `growth` until the next sweep's
        // `recount_blob_bytes`.
        self.store.add_blob_bytes(&e.enrollment_id, growth as i64);
        self.note_total_written(growth as usize);
        // An upload in progress is not garbage (see `Store::blobs_to_gc`).
        self.store.blob_touch(&blob_id, now);
        if let Err(msg) = self.store.blob_record_chunk(&blob_id, chunk_index, growth as usize) {
            error!("blob_record_chunk: {msg}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        ServerResponse::Ok
    }

    fn handle_blob_finish(
        &mut self,
        e: &Enrollment,
        blob_id: String,
        total_chunks: u32,
        enc_sha256: Vec<u8>,
    ) -> ServerResponse {
        if !is_safe_id(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // Row gone (swept after a long offline spell): the client starts over.
        let Some(state) = self.store.blob_state(&blob_id) else {
            return ServerResponse::Err(ServerErrorCode::BlobIncomplete);
        };
        if state.owner != e.enrollment_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if state.complete {
            return ServerResponse::Ok;
        }
        // The stored count is the upload's. The client's own number only has to agree with it.
        if total_chunks != state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if state.received_chunks < state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BlobIncomplete);
        }
        if !self.blob_hashing.contains_key(&blob_id) && self.blob_hashing.len() >= MAX_HASH_JOBS {
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        // Placeholder: the caller sees `hash_job` and answers through `start_blob_hash` and `finish_blob_hash` instead.
        self.hash_job = Some((blob_id, enc_sha256));
        ServerResponse::Ok
    }

    /// Hashes the ENCRYPTED bytes on the blocking pool. The server cannot read the content, but it never serves a
    /// truncated upload. A blob can be up to `max_blob_bytes` (GiBs). Inside the event loop it stalled every client
    /// for the duration.
    fn start_blob_hash(&mut self, blob_id: String, enc_sha256: Vec<u8>, channel: ResponseChannel<ServerResponse>) {
        let waiters = self.blob_hashing.entry(blob_id.clone()).or_default();
        if waiters.len() >= MAX_HASH_WAITERS {
            let busy = ServerResponse::Err(ServerErrorCode::RateLimited);
            let _ = self.swarm.behaviour_mut().server_rpc.send_response(channel, busy);
            return;
        }
        waiters.push(channel);
        // A repeated `BlobFinish` waits for the running hash and starts none.
        if waiters.len() > 1 {
            return;
        }
        let path = self.blob_path(&blob_id);
        let tx = self.hash_tx.clone();
        tokio::spawn(async move {
            let hashed = tokio::task::spawn_blocking(move || hash_file_streaming(&path)).await.ok().flatten();
            let _ = tx.send((blob_id, enc_sha256, hashed));
        });
    }

    fn finish_blob_hash(&mut self, (blob_id, enc_sha256, hashed): HashDone) {
        let response = match hashed {
            Some(actual) if actual == enc_sha256 => match self.store.blob_finish(&blob_id, &enc_sha256, now_ms()) {
                Ok(()) => ServerResponse::Ok,
                Err(msg) => {
                    error!("blob_finish: {msg}");
                    ServerResponse::Err(ServerErrorCode::Internal)
                }
            },
            Some(_) => {
                warn!("Blob hash uyuşmuyor, reddedildi: {}…", blob_id.get(..6).unwrap_or(""));
                self.drop_blob(&blob_id);
                ServerResponse::Err(ServerErrorCode::BadHash)
            }
            // Unreadable file: the same finish fails the same way.
            None => {
                warn!("Blob okunamadı, reddedildi: {}…", blob_id.get(..6).unwrap_or(""));
                self.drop_blob(&blob_id);
                ServerResponse::Err(ServerErrorCode::BadHash)
            }
        };
        for channel in self.blob_hashing.remove(&blob_id).unwrap_or_default() {
            let _ = self.swarm.behaviour_mut().server_rpc.send_response(channel, response.clone());
        }
    }

    /// Removes a blob file, then its row and charge. If the file cannot be removed, it keeps its row and charge
    /// (the next GC tries again). Refunding it would let files outside every budget grow.
    fn drop_blob(&self, blob_id: &str) {
        match std::fs::remove_file(self.blob_path(blob_id)) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                warn!("Blob dosyası silinemedi ({}…): {err}", blob_id.get(..6).unwrap_or(""));
            }
            _ => self.store.blob_forget(blob_id),
        }
    }

    /// Serves a file chunk.
    ///
    /// The server counterpart of `serve_chunk_request` in the core. It is deliberately almost identical:
    /// `read_chunk_from_disk` reads the `.enc` file AS IT IS, because the disk format is the wire format. The server
    /// encrypts, decrypts and re-frames nothing.
    fn serve_chunk(
        &mut self,
        peer: PeerId,
        req: FileChunkRequest,
        channel: ResponseChannel<FileChunkResponse>,
    ) {
        // This path is entirely separate from `handle_request`. It is a distinct request_response behaviour, called
        // straight from `handle_swarm_event`, and it sat outside the enrollment check (`authenticate`). As a result,
        // ANY peer speaking this protocol, including an unenrolled stranger connecting in node mode, could fetch chunks
        // as soon as it knew or guessed a `blob_id`. The bytes are encrypted with `file_key`, so content did not leak
        // directly. But the `NotFound`/`Chunk` split answered "does this file exist on the server" as an oracle, and it
        // made a stranger cause unlimited disk and CPU work. The core had the same bug (`may_serve_file_to`), closed in
        // an earlier review. The server counterpart had been missed.
        //
        // Legitimate clients are not affected. `ready_server_peers` (client) uses a server as a source only when it is
        // `connected && enrolled`, so a download always arrives here with an enrolled `PeerId`.
        //
        // Rate limit: its own budget (`CHUNKS_PER_MINUTE`, 10/s), separate from the RPC budget. Tor carries about one
        // chunk a second, so only a request loop reaches it. An enrolled peer over budget gets `Busy` (back off, same
        // source). An unenrolled one gets `NotFound`.
        let enrolled = self.active(peer).is_some();
        if !enrolled || !self.check_rate(peer, true, 1) {
            warn!("Dosya parçası isteği reddedildi (kayıtsız eş ya da hız sınırı)");
            self.stats.rejected += 1;
            let reply = if enrolled { FileChunkResponse::Busy } else { FileChunkResponse::NotFound };
            let _ = self.swarm.behaviour_mut().file_chunks.send_response(channel, reply);
            return;
        }
        let response = if !is_safe_id(&req.file_id) {
            FileChunkResponse::NotFound
        } else {
            match self.store.blob_state(&req.file_id) {
                Some(state) if state.complete => {
                    // Once per download keeps the blob alive. Once per chunk was a DB write for each of thousands of chunks.
                    if req.chunk_index == 0 {
                        self.store.blob_touch(&req.file_id, now_ms());
                    }
                    // This branch used to call `read_chunk_from_disk` with a fixed 256 KiB stride. `handle_blob_put`
                    // takes the stride FROM THE CLIENT (`BlobPut.chunk_size`) and writes by it. The moment the two
                    // diverged, every blob was read from the wrong offsets. That is the same bug that had spoiled a
                    // speed measurement. The stride is now stored with the blob.
                    match attachments::read_chunk_from_disk_with(
                        &self.blob_path(&req.file_id),
                        req.chunk_index,
                        state.chunk_size as usize,
                    ) {
                        Ok(Some(data)) => {
                            self.stats.blob_chunks_served += 1;
                            FileChunkResponse::Chunk { data }
                        }
                        _ => FileChunkResponse::NotFound,
                    }
                }
                // A partial upload is NEVER served. When the client sees `NotFound`, it switches to another source
                // immediately (see `handle_chunk_response`, which deliberately does not retry).
                _ => FileChunkResponse::NotFound,
            }
        };
        let _ = self.swarm.behaviour_mut().file_chunks.send_response(channel, response);
    }

    // -----------------------------------------------------------------
    // Push (Notify) and sweep
    // -----------------------------------------------------------------

    /// If a CONNECTED peer is listening on the mailbox, tells it "mail is waiting".
    ///
    /// Without this the client would have to poll with `Fetch` constantly, which means battery drain on a phone.
    /// The payload is not carried here. The client runs `Fetch` in its own cycle, so cursor logic stays intact.
    fn notify_owner_of(&mut self, mailbox: &str, depositor: PeerId, item: MailItem) {
        let targets: Vec<PeerId> = self
            .live_interest
            .iter()
            .filter(|(peer, boxes)| **peer != depositor && boxes.contains(mailbox))
            .map(|(peer, _)| *peer)
            .collect();
        for peer in targets {
            // Revoked or blocked while connected: nothing more is pushed.
            let Some(reader) = self.active(peer) else { continue };
            // See `ServerRequest::Push`. Inline only when nothing older is pending for this reader, so the client
            // cannot skip an item.
            let inline = item.sealed.len() <= PUSH_INLINE_MAX
                && self.store.unacked_for(mailbox, &reader.enrollment_id) == 1;
            // One `Notify` until the peer fetches. A deposit flood would otherwise wake the reader's radio once per item.
            if !inline {
                if self.notified.contains_key(&peer) {
                    continue;  // `resend_notifies` repeats it
                }
                self.notified.insert(peer, mono_ms());
            }
            let req = if inline { ServerRequest::Push { item: item.clone() } } else { ServerRequest::Notify };
            self.swarm.behaviour_mut().server_rpc.send_request(&peer, req);
        }
    }

    /// Repeats the `Notify` of every connected reader that has not fetched since its last one (see
    /// `NOTIFY_RESEND_MS`). Called every tick (5 s).
    fn resend_notifies(&mut self) {
        let now = mono_ms();
        let due: Vec<PeerId> = self.notified.iter()
            .filter(|(_, sent)| now.saturating_sub(**sent) >= NOTIFY_RESEND_MS)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in due {
            if self.active(peer).is_none() || !self.swarm.is_connected(&peer) {
                self.notified.remove(&peer);
                continue;
            }
            self.notified.insert(peer, now);
            debug!("Notify yinelendi (Fetch gelmedi): {peer}");
            self.swarm.behaviour_mut().server_rpc.send_request(&peer, ServerRequest::Notify);
        }
    }

    /// Call-media relay (see `RELAY_PROTOCOL`). Forwards a frame to every OTHER connected client listening on the
    /// frame's mailbox. Only enrolled, non-revoked clients get a link. Everyone else's frames are ignored.
    fn handle_relay(&mut self, ev: RelayEvent) {
        match ev {
            RelayEvent::Open { peer, id, tx } => match self.active(peer) {
                Some(_) => {
                    debug!("Arama rölesi açıldı: {peer}");
                    self.relay_links.insert(peer, (id, tx));
                }
                // Dropping `tx` ends the writer, which closes the stream.
                _ => self.stats.rejected += 1,
            },
            RelayEvent::Closed { peer, id } => {
                if self.relay_links.get(&peer).map(|(i, _)| *i) == Some(id) {
                    self.relay_links.remove(&peer);
                    debug!("Arama rölesi kapandı: {peer}");
                }
            }
            RelayEvent::Frame { peer, mailbox, data } => {
                if !self.relay_links.contains_key(&peer) {
                    return;
                }
                let now = mono_ms();
                let budget = self.relay_budget.entry(peer).or_insert((now, 0));
                if now.saturating_sub(budget.0) > RELAY_WINDOW_MS {
                    *budget = (now, 0);
                }
                // Each frame also pays its overhead. An empty frame is refused: free empty frames filled a call's writer queue.
                if data.is_empty() {
                    self.stats.rejected += 1;
                    return;
                }
                budget.1 += data.len() + RELAY_FRAME_OVERHEAD;
                if budget.1 > RELAY_BYTES_PER_WINDOW {
                    self.stats.rejected += 1;
                    return;
                }
                let cold_bytes = budget.1;
                let frame = encode_frame(&[], &data);
                let targets: Vec<PeerId> = self
                    .live_interest
                    .iter()
                    .filter(|(target, boxes)| **target != peer && boxes.contains(&mailbox))
                    .map(|(target, _)| *target)
                    .collect();
                for target in targets {
                    // A call sends both ways. Until the target has sent this peer a frame, only the first few packets
                    // pass, so a client cannot flood a call it is not part of.
                    let mutual = self.relay_pairs.get(&(target, peer)).map_or(false, |t| now.saturating_sub(*t) <= RELAY_WINDOW_MS);
                    if !mutual && cold_bytes > RELAY_COLD_BYTES_PER_WINDOW {
                        self.stats.rejected += 1;
                        continue;
                    }
                    if let Some((_, tx)) = self.relay_links.get(&target) {
                        if tx.try_send(frame.clone()).is_ok() {
                            self.stats.relayed += 1;
                            self.relay_pairs.insert((peer, target), now);
                        }
                    }
                }
            }
        }
    }

    /// `chunk`: a file-chunk request, counted against `CHUNKS_PER_MINUTE` instead of the RPC limit. `cost`: see `request_cost`.
    fn check_rate(&mut self, peer: PeerId, chunk: bool, cost: u32) -> bool {
        let limit = self.config.limits.requests_per_minute;
        let now = mono_ms();
        let entry = self.conns.entry(peer).or_insert(ConnState {
            challenge: None,
            window_start: now,
            requests_in_window: 0,
            chunks_in_window: 0,
            connected_at: now,
            enroll_verifies: (0, 0),
            register_verifies: (0, 0),
        });
        if now.saturating_sub(entry.window_start) > RATE_WINDOW_MS {
            entry.window_start = now;
            entry.requests_in_window = 0;
            entry.chunks_in_window = 0;
        }
        if chunk {
            entry.chunks_in_window += 1;
            return entry.chunks_in_window <= CHUNKS_PER_MINUTE;
        }
        entry.requests_in_window = entry.requests_in_window.saturating_add(cost);
        entry.requests_in_window <= limit
    }

    /// Charges `checks` to the peer's share and to `pool`'s server-wide window. `Enroll` and `Rebind` share the
    /// per-peer share, not the pool.
    fn verify_budget(&mut self, peer: PeerId, pool: VerifyPool, checks: u32) -> bool {
        let now = mono_ms();
        let conn = self.conns.entry(peer).or_insert(ConnState {
            challenge: None,
            window_start: now,
            requests_in_window: 0,
            chunks_in_window: 0,
            connected_at: now,
            enroll_verifies: (0, 0),
            register_verifies: (0, 0),
        });
        match pool {
            VerifyPool::Register => charge_verify(&mut conn.register_verifies, &mut self.register_verify_window, now, checks, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE),
            VerifyPool::Enroll => charge_verify(&mut conn.enroll_verifies, &mut self.verify_window, now, checks, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE),
            VerifyPool::Rebind => charge_verify(&mut conn.enroll_verifies, &mut self.rebind_verify_window, now, checks, ENROLL_VERIFIES_PER_PEER, REBIND_VERIFIES_PER_MINUTE),
        }
    }

    /// Configured blob directory. The Android server app can move it to external storage.
    pub fn blob_dir(&self) -> &PathBuf {
        &self.config.blob_dir
    }

    /// Data directory (identity, Tor state, SQLite). It may be separate from the blob directory.
    pub fn data_dir(&self) -> &PathBuf {
        &self.config.data_dir
    }

    /// `true` while the wall clock is more than `CLOCK_JUMP_MS` away from where the monotonic clock says it should be.
    /// After `CLOCK_JUMP_HOLD_MS` the new time is accepted as real, and a forward step moves the stored deadlines
    /// with it (`Store::shift_deadlines`). Either clock may have been the wrong one, so nothing expires because of
    /// the step itself.
    fn clock_jumped(&mut self, now: i64, mono: u64) -> bool {
        let (wall0, mono0) = *self.clock_anchor.get_or_insert((now, mono));
        let expected = wall0 + (mono - mono0) as i64;
        if (now - expected).abs() <= CLOCK_JUMP_MS {
            self.clock_off_since = None;
            return false;
        }
        if mono - *self.clock_off_since.get_or_insert(mono) < CLOCK_JUMP_HOLD_MS {
            return true;
        }
        if now > expected {
            warn!("Sistem saati {} sn ileri alındı — süreler kaydırıldı", (now - expected) / 1000);
            self.store.shift_deadlines(now - expected, expected);
        }
        self.clock_anchor = Some((now, mono));
        self.clock_off_since = None;
        false
    }

    /// A device revoked or blocked while connected loses its pushes and its call-relay link, not only its RPCs.
    /// Runs at once on `CoreSignal::EnrollmentsChanged` (Android) and on every 5 s tick. The tick covers revokes
    /// made from the CLI, a separate process.
    fn drop_revoked_peers(&mut self) {
        let peers: HashSet<PeerId> = self.live_interest.keys().chain(self.relay_links.keys()).copied().collect();
        let gone: Vec<PeerId> = peers.into_iter().filter(|p| self.active(*p).is_none()).collect();
        for peer in gone {
            self.live_interest.remove(&peer);
            self.relay_links.remove(&peer);
        }
    }

    fn maybe_sweep(&mut self) {
        // Another connection (the CLI) committed since the last scan, or this is the first tick.
        let version = self.store.data_version();
        if version != self.revoke_scan_version {
            self.revoke_scan_version = version;
            self.drop_revoked_peers();
        }
        // Once per tick, not once per Ack: the recount rewrites every enrollment.
        if std::mem::take(&mut self.mail_recount_due) {
            self.store.recount_mail_bytes();
        }
        self.resend_notifies();
        let mono = mono_ms();
        // Every tick, not only every sweep. A peer that is not enrolled used to hold its slot for up to two sweeps
        // (60 to 120 s).
        // ponytail: not in node mode, where strangers are served on purpose (Kad, circuit relay). There the connection
        // cap is still the one flood guard.
        if !self.config.node_mode {
            let idle: Vec<PeerId> = self
                .conns
                .iter()
                .filter(|(p, c)| mono.saturating_sub(c.connected_at) > UNENROLLED_GRACE_MS && self.swarm.is_connected(p))
                .map(|(p, _)| *p)
                .filter(|p| self.active(*p).is_none())
                .collect();
            for peer in idle {
                let _ = self.swarm.disconnect_peer_id(peer);
            }
        }
        if self.last_sweep.map_or(false, |t| mono - t < SWEEP_INTERVAL_MS) {
            return;
        }
        self.last_sweep = Some(mono);
        self.publish_shared();

        let swarm = &self.swarm;
        self.conns.retain(|p, c| swarm.is_connected(p) || mono - c.window_start <= RATE_WINDOW_MS);
        self.relay_budget.retain(|_, b| mono - b.0 <= RELAY_WINDOW_MS);
        self.relay_pairs.retain(|_, t| mono - *t <= RELAY_WINDOW_MS);


        let now = now_ms();
        if self.clock_jumped(now, mono) {
            warn!("Sistem saati sıçradı — TTL süpürmesi bekletiliyor");
            return;
        }
        // Tracked above even while wrong, so the step to the right time is seen and the deadlines move with it.
        if now < SANE_WALL_FLOOR_MS {
            warn!("Sistem saati geçersiz — TTL süpürmesi atlandı");
            return;
        }
        let slept = self.store.sleep_idle_enrollments(now - ENROLLMENT_IDLE_MS);
        let removed = self.store.sweep_expired_mail(now) + slept;
        let archived = self.store.sweep_expired_archive(now);
        if archived > 0 {
            info!("Süpürmede {archived} arşiv kaydı (13 ay) silindi");
        }
        if removed > 0 {
            info!("Süpürmede {removed} teslim öğesi silindi");
            self.store.recount_mail_bytes();
        }
        for blob_id in self.store.blobs_to_gc(now, self.config.limits.blob_ttl_ms as i64) {
            self.drop_blob(&blob_id);
        }
        self.store.recount_blob_bytes();
        self.store.incremental_vacuum();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The libp2p identity is persistent: the `PeerId` must NOT change across restarts, or every distributed invite
/// code would become invalid.
/// Hashes a file with SHA-256 without loading it fully into memory.
fn hash_file_streaming(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().to_vec())
}

fn load_or_generate_keypair(store: &Store) -> Result<libp2p::identity::Keypair, String> {
    if let Some(bytes) = store.meta_get("libp2p_key") {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return Ok(kp);
        }
        warn!("Kayıtlı libp2p anahtarı okunamadı, yenisi üretiliyor");
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let encoded = kp.to_protobuf_encoding().map_err(|e| e.to_string())?;
    store.meta_set("libp2p_key", &encoded)?;
    Ok(kp)
}

/// Hybrid signature verification, with the same contract as the core's `verify_hybrid_signature`: BOTH must pass,
/// and a missing part is rejected.
fn verify_hybrid(pk: &[u8], pk_pq: &[u8], message: &[u8], sig: &[u8], sig_pq: &[u8]) -> bool {
    if sig.is_empty() || sig_pq.is_empty() {
        return false;
    }
    if !verify_ed25519(pk, message, sig) {
        return false;
    }
    let Ok(pk_encoded): Result<&EncodedVerifyingKey<MlDsa87>, _> = pk_pq.try_into() else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa87>::decode(pk_encoded);
    let Ok(sig_encoded): Result<&EncodedSignature<MlDsa87>, _> = sig_pq.try_into() else {
        return false;
    };
    let Some(parsed) = MlDsaSignature::<MlDsa87>::decode(sig_encoded) else {
        return false;
    };
    vk.verify(message, &parsed).is_ok()
}

/// Cost of a request against `ServerLimits.requests_per_minute`: one, plus one per 8 list elements (each is a query
/// on the event loop). An `ArchivePut` also pays one per 64 KiB of record bytes. A `MailboxProof` is a hybrid verify,
/// and so is `Enroll` and `Rebind`.
fn request_cost(req: &ServerRequest) -> u32 {
    let n = match req {
        ServerRequest::Enroll { .. } | ServerRequest::Rebind { .. } => return 30,
        ServerRequest::Register { add, drop, proofs } => add.len() + drop.len() + 64 * proofs.len(),
        ServerRequest::Fetch { cursors: list, .. } | ServerRequest::Ack { acks: list } => list.len(),
        ServerRequest::Cancel { seqs, .. } => seqs.len(),
        // Bytes count too. The codec caps a request at 1 MiB, so 16 extra units per full request keeps count-only
        // cheating (few big records) priced.
        ServerRequest::ArchivePut { records, .. } => {
            records.len() + records.iter().map(|r| r.sealed.len()).sum::<usize>() / (64 * 1024) * 8
        }
        ServerRequest::ArchiveProbe { buckets } | ServerRequest::ArchivePurge { buckets } => buckets.len(),
        _ => 0,
    };
    1u32.saturating_add(u32::try_from(n / 8).unwrap_or(u32::MAX))
}

/// Constant-time byte comparison. The challenge is a per-connection secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn verify_ed25519(pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let Ok(pk_bytes): Result<[u8; 32], _> = pubkey.try_into() else { return false };
    let Ok(sig_bytes): Result<[u8; 64], _> = sig.try_into() else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else { return false };
    // Strict, as the client verifies: a non-canonical signature passed here and failed there.
    vk.verify_strict(message, &Signature::from_bytes(&sig_bytes)).is_ok()
}

/// Checks identifiers before they are used as file paths.
///
/// `blob_id` and `file_id` come from the client. Embedded in a path unchecked, `../../` could read or write outside
/// the data directory.
///
/// No upper-case letters: on a case-insensitive blob volume (FAT/exFAT SD card), `AB12` and `ab12` are one file but
/// two DB rows, so a second uploader overwrote the first one's blob. Client ids are lowercase hex and UUIDs.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(128)
        .collect()
}

/// Charges `checks` to a peer's share and to the server-wide pool. Each is a (window start `mono_ms`, checks) over
/// `RATE_WINDOW_MS`. A refused charge costs nothing, so a peer over its share cannot drain the pool for others.
fn charge_verify(peer: &mut (u64, u32), pool: &mut (u64, u32), now: u64, checks: u32, peer_limit: u32, pool_limit: u32) -> bool {
    for w in [&mut *peer, &mut *pool] {
        if w.0 == 0 || now.saturating_sub(w.0) > RATE_WINDOW_MS {
            *w = (now.max(1), 0);
        }
    }
    if peer.1.saturating_add(checks) > peer_limit || pool.1.saturating_add(checks) > pool_limit {
        return false;
    }
    peer.1 += checks;
    pool.1 += checks;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_peer_cannot_drain_the_verify_pool() {
        let mut pool = (0, 0);
        let (mut a, mut b) = ((0, 0), (0, 0));
        let now = 1_000;
        // Peer A sends full Registers: only its share passes.
        assert!(charge_verify(&mut a, &mut pool, now, 64, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE));
        for _ in 0..100 {
            assert!(!charge_verify(&mut a, &mut pool, now, 64, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE));
        }
        // Peer B still gets its own full share.
        assert!(charge_verify(&mut b, &mut pool, now, 64, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE));
        // The window rolls over: A is served again.
        assert!(charge_verify(&mut a, &mut pool, now + RATE_WINDOW_MS + 1, 64, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE));
        // Enroll pool: an unknown peer gets only a small share.
        let (mut epool, mut u, mut v) = ((0, 0), (0, 0), (0, 0));
        for _ in 0..ENROLL_VERIFIES_PER_PEER {
            assert!(charge_verify(&mut u, &mut epool, now, 1, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE));
        }
        assert!(!charge_verify(&mut u, &mut epool, now, 1, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE));
        assert!(charge_verify(&mut v, &mut epool, now, 1, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE));
        // The pool itself still caps the total.
        let mut full = (now, ENROLL_VERIFIES_PER_MINUTE);
        assert!(!charge_verify(&mut (0, 0), &mut full, now, 1, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE));
    }

    /// Enrolled peers cannot be locked out of `Register` proofs by the number of other enrolled peers.
    #[test]
    fn register_has_no_global_pool() {
        let mut pool = (0, 0);
        for _ in 0..64 {
            let mut peer = (0, 0);
            assert!(charge_verify(&mut peer, &mut pool, 1_000, 64, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE));
        }
    }

    #[test]
    fn unsafe_ids_are_rejected_before_touching_the_filesystem() {
        assert!(is_safe_id("bl_abc123"));
        assert!(is_safe_id("550e8400-e29b-41d4-a716-446655440000"));
        // Directory escape.
        assert!(!is_safe_id("../../etc/passwd"));
        assert!(!is_safe_id("a/b"));
        assert!(!is_safe_id("a\\b"));
        assert!(!is_safe_id(".."));
        assert!(!is_safe_id(""));
        assert!(!is_safe_id(&"x".repeat(129)));
        assert!(!is_safe_id("BL_ABC123"), "case-insensitive volumes: one file, two rows");
    }

    #[test]
    fn sanitize_strips_path_separators() {
        assert_eq!(sanitize_id("../evil"), "evil");
        assert_eq!(sanitize_id("ok_id-1"), "ok_id-1");
    }

    #[test]
    fn ed25519_verification_rejects_malformed_input() {
        assert!(!verify_ed25519(&[0u8; 10], b"msg", &[0u8; 64]));
        assert!(!verify_ed25519(&[0u8; 32], b"msg", &[0u8; 10]));
    }
}
