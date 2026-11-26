//! Typeon server: a BLIND store-and-forward mailbox.
//!
//! ## Why it exists
//!
//! Nothing else in the app does store-and-forward (see the section on
//! store-and-forward in the README and SECURITY.md). libp2p Circuit Relay v2 builds a live circuit
//! only while both peers are connected and stores nothing. Durability therefore rests entirely on the SENDER
//! (`awaiting_confirmation`, retries for up to 7 days). This server fills that gap.
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
//! Size, timing and volume, and which enrollment reads which mailbox. Each device reads only its own inbound
//! boxes, and deposits arrive anonymously (throwaway PeerId, own Tor circuit, a per-box deposit secret), so the
//! server does not see who writes to whom. Timing can still hint at it; SECURITY.md lists the leaks.

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
use libp2p::{identify, noise, relay, yamux, PeerId, StreamProtocol, Swarm};
use log::{debug, error, info, warn};
use rand::RngCore;
use sha2::{Digest, Sha256};

use p2p_messenger::attachments;
use p2p_messenger::call::{encode_frame, pump_writes, read_frame, LINK_QUEUE, RELAY_PROTOCOL};
use p2p_messenger::server_proto::{
    self, MailItem, ServerErrorCode, ServerLimits, ServerRequest, ServerResponse, MAX_DEPOSIT_BYTES,
    MAX_FETCH_BATCH_BYTES, MAX_FETCH_BATCH_ITEMS, SERVER_PROTOCOL, SERVER_PROTOCOL_VERSION,
};

use store::{Enrollment, EnrollmentState, Store};

mod config;
mod handlers;
mod blobs;
mod relay_streams;
mod limits;
mod sweep;
use config::*;
pub use config::advertised_addrs;
pub use config::create_invite;
pub use config::join_code;
pub use config::public_join_token;
use relay_streams::*;
use limits::*;

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
/// File-chunk requests per peer per `RATE_WINDOW_MS` (see `serve_blob_get`). Tor carries about one 256 KiB chunk
/// a second. 10 per second is far above a real download and caps one peer at about 2.5 MiB/s of disk reads.
const CHUNKS_PER_MINUTE: u32 = 600;
/// Blobs (files on disk) one enrollment may hold. Bytes have their own quota. A heavy month of attachments
/// (`blob_ttl_ms`) stays far below this.
const MAX_BLOBS_PER_ENROLLMENT: i64 = 10_000;
/// Minimum quota charged for a `BlobPut` chunk: its row, even when no new bytes are stored.
const BLOB_CHUNK_MIN_CHARGE: u64 = 64;
/// How many strides past the current file end a `BlobPut` may write. Covers the client's upload pipeline
/// (`BLOB_WINDOW_MAX` = 40). Further out is refused, so one request cannot charge (or zero-fill) gigabytes.
const BLOB_PUT_AHEAD_CHUNKS: u64 = 64;
/// One box may hold at most `max_mail_bytes / MAIL_BOX_SHARE` unacknowledged. A box whose sender keeps sending while
/// the reader is away then costs the reader only this share of its quota, not its mail in every other box.
const MAIL_BOX_SHARE: u64 = 8;
/// What one box may take per `DEPOSIT_WINDOW_MS`, acknowledged or not, from all (anonymous) depositors together.
const DEPOSIT_BYTES_PER_BOX_WINDOW: u64 = 16 * 1024 * 1024;
/// Deposits (repeats included) one box takes per `DEPOSIT_WINDOW_MS`. A real conversation stays far below it; a client
/// stuck re-depositing (the old one-a-second handshake storm) hits it within the window.
const DEPOSITS_PER_BOX_WINDOW: u32 = 1_200;
const DEPOSIT_WINDOW_MS: u64 = 60 * 60 * 1000;
/// One anonymous connection (PeerId) takes at most this share of a box's window, so one holder of a shared deposit
/// secret (a group member, anyone with a shown QR code) cannot use up the box for every other sender alone.
/// ponytail: PeerIds are free, so `PEER_SHARE_OF_BOX_WINDOW` connections still can; only the global anonymous budget
/// (`ANON_BUCKET_CAP`) bounds that.
const PEER_SHARE_OF_BOX_WINDOW: u64 = 4;
/// Boxes one anonymous connection may deposit into within its lifetime (bounds its `ConnState.anon_boxes`).
const MAX_ANON_BOXES_PER_PEER: usize = 512;
/// Global token bucket for anonymous requests (`Deposit`, `Cancel`), from all connections together: burst size and
/// refill per ms (20 a second). Refilled on access, no timer.
const ANON_BUCKET_CAP: f64 = 3_000.0;
const ANON_REFILL_PER_MS: f64 = 0.02;
/// Global token bucket for `BlobGet`, from all connections together: burst size and refill per ms (20 chunks a
/// second, about 5 MiB/s of disk reads at most). Separate from `ANON_BUCKET_CAP`, so downloads never stop mail.
const CHUNK_BUCKET_CAP: f64 = 2_400.0;
const CHUNK_REFILL_PER_MS: f64 = 0.02;
/// Archive and blob writes stop at `budget - budget / MAIL_RESERVE_DIVISOR`. The rest stays for mail, so a full
/// archive or blob store does not stop store-and-forward.
const MAIL_RESERVE_DIVISOR: u64 = 10;

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

/// Milliseconds since boot, counting suspend (`CLOCK_BOOTTIME`, read from `/proc/uptime`). `Instant` stops during
/// suspend, so against the wall clock every suspended hour looked like a clock step. Falls back to `mono_ms`.
fn boot_ms() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map_or_else(mono_ms, |secs| (secs * 1000.0) as u64)
}

/// A wall-clock step larger than this is not trusted at once. The TTL sweep waits `CLOCK_JUMP_HOLD_MS` first.
/// (A clock set a month ahead once deleted all mail and blobs in one sweep.)
const CLOCK_JUMP_MS: i64 = 24 * 60 * 60 * 1000;
const CLOCK_JUMP_HOLD_MS: u64 = 60 * 60 * 1000;

/// Inbound connection caps. Every client arrives from 127.0.0.1 through the onion bridge and PeerIds are free,
/// so only a total cap stops a connection flood.
const MAX_INBOUND_CONNECTIONS: u32 = 512;
const MAX_CONNECTIONS_PER_PEER: u32 = 8;
/// Request streams per connection and protocol, inbound and outbound together (libp2p default 100). Each inbound one
/// buffers up to the codec cap (1 MiB) before any enrollment check. Well above the clients' upload and download
/// windows (40 chunks each) plus the other requests and the server's own pushes.
const MAX_STREAMS_PER_CONNECTION: usize = 64;
/// A connected peer without an active enrollment is cut after this long. Otherwise it held one of the
/// `MAX_INBOUND_CONNECTIONS` slots indefinitely.
const UNENROLLED_GRACE_MS: u64 = 60_000;
/// Hard cap on an unenrolled (anonymous deposit) connection, deposits or not. A client's burst is over in seconds.
const UNENROLLED_MAX_LIFETIME_MS: u64 = 5 * 60_000;
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
/// `Register` proof checks per `RATE_WINDOW_MS`, server-wide: no global cap (only the per-peer share below). A `Register` needs an enrollment
/// bound to one PeerId, so the per-peer share times `max_enrollments` already bounds the CPU. A global pool
/// once let four enrollments lock every other device out of new mailboxes.
const REGISTER_VERIFIES_PER_MINUTE: u32 = u32::MAX;
/// One enrolled peer's share of `REGISTER_VERIFIES_PER_MINUTE`: one full `Register` per window.
const REGISTER_VERIFIES_PER_PEER: u32 = server_proto::MAX_REGISTER_PROOFS as u32;
/// Lower sanity bound for the wall clock: 1 January 2026, UTC. A clock before this is wrong (for example a phone
/// booted with a 1970 or 2020 RTC). No TTL sweep runs on such a clock.
const SANE_WALL_FLOOR_MS: i64 = 1_767_225_600_000;

/// `meta` key: the addresses the running server last advertised, one per line. Management commands read it
/// instead of starting a second server.
const ADVERTISED_ADDRS_KEY: &str = "advertised_addrs";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `meta` key for the public join token (3-day lifetime). See `ServerCore::join_code`.
const PUBLIC_JOIN_TOKEN_KEY: &str = "public_join_token";
/// Label of the invite row for this token (shown in `invite list`).
const PUBLIC_JOIN_LABEL: &str = "herkese-acik";
/// Maximum NEW enrollments per hour through the public code. See `handle_enroll`.
const MAX_PUBLIC_ENROLLMENTS_PER_HOUR: i64 = 60;
/// Lifetime of the public join code. Unlimited uses, but a leaked code dies by
/// itself; `public_join_token` then makes a new one.
const PUBLIC_CODE_TTL_MS: i64 = 3 * 24 * 60 * 60 * 1000;
/// Default `ServerConfig::max_enrollments`.
pub const DEFAULT_MAX_ENROLLMENTS: u32 = 16;
/// An active enrollment not seen for this long is put to sleep by `maybe_sweep` (its reader rows go, the row stays).
/// `Store::prune_dead_rows` deletes the row once it has been idle for `ARCHIVE_TTL_MS` and owns nothing.
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
    /// `DEFAULT_MAX_ENROLLMENTS` times the per-device quotas. Set it with `apply_storage_budget`. The Android server
    /// app derives it from the device's real free space.
    pub total_storage_budget_bytes: Option<u64>,
    /// Maximum active enrollments. A new device is refused above it.
    pub max_enrollments: u32,
}

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
pub struct ServerBehaviour {
    /// Mailbox RPC. `Full` lets the server send `Notify` to clients on its own (see `ServerRequest::Notify`).
    server_rpc: request_response::cbor::Behaviour<ServerRequest, ServerResponse>,
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
    /// `mono_ms` of its last anonymous request (`Deposit`, `Cancel`). An anonymous connection counts as idle from here.
    last_anon_at: u64,
    /// (window start `mono_ms`, checks): this peer's share of the `Enroll`/`Rebind` and `Register` verify pools.
    enroll_verifies: (u64, u32),
    register_verifies: (u64, u32),
    /// This peer's own per-box deposit windows (see `PEER_SHARE_OF_BOX_WINDOW`).
    anon_boxes: HashMap<String, (u64, u64, u32)>,
}

impl ConnState {
    fn new(now: u64) -> Self {
        ConnState {
            challenge: None,
            window_start: now,
            requests_in_window: 0,
            chunks_in_window: 0,
            connected_at: now,
            last_anon_at: 0,
            enroll_verifies: (0, 0),
            register_verifies: (0, 0),
            anon_boxes: HashMap::new(),
        }
    }
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
    /// Peers that owe a `Fetch`: (`mono_ms` of the last `Notify` sent, 0 = send one on the next tick; unanswered
    /// resends). Repeated with a doubling pause until the peer fetches. See `resend_notifies`.
    notified: HashMap<PeerId, (u64, u32)>,
    /// Mailbox to (window start `mono_ms`, bytes deposited, deposits). See `DEPOSIT_BYTES_PER_BOX_WINDOW` and
    /// `DEPOSITS_PER_BOX_WINDOW`.
    deposit_window: HashMap<String, (u64, u64, u32)>,
    /// (`mono_ms` of the last refill, tokens): see `ANON_BUCKET_CAP`.
    anon_bucket: (u64, f64),
    /// See `CHUNK_BUCKET_CAP`.
    chunk_bucket: (u64, f64),
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
/// status every second. A lock on `ServerCore` would stall the loop, so the loop copies into this cheap snapshot
/// only at attach, on a listen-address change, and on each sweep tick (about once a minute).
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
            .map_err(|e| format!("Lock file: {e}"))?;
        if lock.try_lock().is_err() {
            return Err(format!(
                "This data directory ({}) is in use by another server process",
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
        let (tor, onion_listen) = p2p_messenger::tor::TorHandle::launch(
            &config.data_dir.join("arti_state").to_string_lossy(),
            &config.data_dir.join("arti_cache").to_string_lossy(),
            TOR_LIBP2P_PORT,
        )
        .map_err(|e| format!("Tor could not be started: {e}"))?;
        let node_mode = config.node_mode;
        let listen_addr = onion_listen.listen_addr();

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            // Onion-only. The only transport is `OnionListen`: inbound onion streams reach the swarm in-process,
            // with no socket any local app could connect to. It cannot dial, so the server never dials out (store-
            // and-forward works only when clients connect to it). This also stops kad, autonat or relay behaviour
            // from dialing a peer's real IP over clearnet by accident.
            .with_other_transport(move |keypair| {
                use libp2p::core::muxing::StreamMuxerBox;
                use libp2p::core::transport::Transport as _;
                use libp2p::core::upgrade::Version;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    libp2p::core::transport::timeout::TransportTimeout::with_ingoing_timeout(
                        onion_listen
                            .upgrade(Version::V1Lazy)
                            .authenticate(noise::Config::new(keypair)?)
                            .multiplex(tuned_yamux())
                            .map(|(p, m), _| (p, StreamMuxerBox::new(m))),
                        Duration::from_secs(p2p_messenger::tor::INBOUND_UPGRADE_SECS),
                    ),
                )
            })
            .map_err(|e| e.to_string())?
            .with_behaviour(|keypair| {
                let peer_id = keypair.public().to_peer_id();
                let server_rpc = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(SERVER_PROTOCOL), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_millis(p2p_messenger::server_client_timeout_ms()))
                        .with_max_concurrent_streams(MAX_STREAMS_PER_CONNECTION),
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
                ServerBehaviour { server_rpc, identify, limits, relay, stream: libp2p_stream::Behaviour::new() }
            })
            .map_err(|e| e.to_string())?
            // Keeps the connection alive through quiet periods and avoids rebuilding Tor circuits for nothing. The
            // client core uses 1800 s (network/mod.rs).
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(600)))
            .build();

        // The listen address is only a label (see `tor::OnionListen`); no socket is bound, so neither the LAN nor
        // a local app can connect, and the server's real IP is never exposed.
        swarm.listen_on(listen_addr).map_err(|e| e.to_string())?;

        let relay_incoming = match swarm.behaviour().stream.new_control().accept(RELAY_PROTOCOL) {
            Ok(incoming) => Some(incoming),
            Err(e) => {
                error!("Call relay protocol could not be registered, relay is off: {e}");
                None
            }
        };

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
            deposit_window: HashMap::new(),
            anon_bucket: (mono_ms(), ANON_BUCKET_CAP),
            chunk_bucket: (mono_ms(), CHUNK_BUCKET_CAP),
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
    /// `tor::TorHandle::notify_network_changed`). The libp2p listen address is only a label (see `tor::OnionListen`),
    /// so no `listen_on` is needed again.
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

    /// For the self-update check (`p2p_messenger::update`), which rides the server's own Tor client.
    pub fn tor_client(&self) -> p2p_messenger::update::Tor {
        self.tor.client.clone()
    }

    pub fn tor_status(&self) -> String {
        self.tor.status().as_str().to_string()
    }

    /// Advertised address. Onion only: no socket is bound (see `new`).
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
        info!("Typeon server started");
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
            return Err("run_until called: loop already ran".to_string());
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
                        info!("Network change reported — refreshing Tor");
                        self.notify_network_changed();
                    }
                    CoreSignal::EnrollmentsChanged => self.drop_revoked_peers(),
                },
                _ = &mut shutdown => {
                    info!("Stop requested, shutting down.");
                    return Ok(());
                }
                _ = &mut ctrlc => {
                    info!("Shutting down.");
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
                let conn = self.conns.entry(peer_id).or_insert_with(|| ConnState::new(now));
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
                    self.notified.entry(peer).or_insert((0, 0));
                }
            }
            _ => {}
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

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_join_code_expires_and_renews() {
        let s = Store::open_in_memory().unwrap();
        let t1 = public_join_token(&s, false).unwrap();
        assert_eq!(public_join_token(&s, false).unwrap(), t1, "same code while valid");
        let h1 = Sha256::digest(hex::decode(&t1).unwrap());
        // Age the code past its lifetime.
        s.create_invite(h1.as_slice(), PUBLIC_JOIN_LABEL, 0, 1, 0).unwrap();
        let t2 = public_join_token(&s, false).unwrap();
        assert_ne!(t2, t1, "expired code is replaced");
        assert_eq!(s.invite_uses_left(h1.as_slice(), 0), None, "old invite row deleted");
        let h2 = Sha256::digest(hex::decode(&t2).unwrap());
        assert_eq!(s.invite_uses_left(h2.as_slice(), now_ms() + PUBLIC_CODE_TTL_MS - 60_000), Some(-1));
        assert_eq!(s.invite_uses_left(h2.as_slice(), now_ms() + PUBLIC_CODE_TTL_MS + 60_000), None);
    }

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

    /// Per-box deposit rate: the count stops a re-deposit loop (repeats count too), the bytes stop a junk flood, and
    /// the window rolls over.
    #[test]
    fn a_box_takes_only_so_many_deposits_per_window() {
        let mut win = (1_000, 0, 0);
        for _ in 0..DEPOSITS_PER_BOX_WINDOW {
            assert!(box_window_admit(&mut win, 1_000, 10, 1).is_ok());
        }
        assert_eq!(box_window_admit(&mut win, 1_000, 10, 1), Err(ServerErrorCode::RateLimited));
        assert!(box_window_admit(&mut win, 1_000 + DEPOSIT_WINDOW_MS + 1, 10, 1).is_ok(), "a new window");
        win.1 = DEPOSIT_BYTES_PER_BOX_WINDOW;
        assert_eq!(box_window_admit(&mut win, 1_000 + DEPOSIT_WINDOW_MS + 1, 1, 1), Err(ServerErrorCode::QuotaExceeded));
        // Another box has its own window.
        let mut other = (1_000, 0, 0);
        assert!(box_window_admit(&mut other, 1_000, 10, 1).is_ok());
        // One connection's share stops it well before the box is full for everyone else.
        let (mut peer, mut boxw) = ((1_000, 0, 0), (1_000, 0, 0));
        let mut admitted = 0;
        while box_window_admit(&mut peer, 1_000, 10, PEER_SHARE_OF_BOX_WINDOW).is_ok() {
            assert!(box_window_admit(&mut boxw, 1_000, 10, 1).is_ok());
            admitted += 1;
        }
        assert_eq!(admitted as u64, DEPOSITS_PER_BOX_WINDOW as u64 / PEER_SHARE_OF_BOX_WINDOW);
        let mut next_peer = (1_000, 0, 0);
        assert!(box_window_admit(&mut next_peer, 1_000, 10, PEER_SHARE_OF_BOX_WINDOW).is_ok());
        assert!(box_window_admit(&mut boxw, 1_000, 10, 1).is_ok(), "another sender still gets in");
    }

    /// The global anonymous bucket: a burst up to the cap, then refill by elapsed time only.
    #[test]
    fn the_anonymous_bucket_refills_by_time() {
        let mut b = (0, ANON_BUCKET_CAP);
        for _ in 0..ANON_BUCKET_CAP as u32 {
            assert!(anon_bucket_take(&mut b, 0));
        }
        assert!(!anon_bucket_take(&mut b, 0));
        assert!(anon_bucket_take(&mut b, (1.0 / ANON_REFILL_PER_MS) as u64 + 1), "one token back after its time");
        assert!(!anon_bucket_take(&mut b, (1.0 / ANON_REFILL_PER_MS) as u64 + 1));
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
