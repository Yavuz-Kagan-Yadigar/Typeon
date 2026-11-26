//! Client side of the server (store-and-forward) option.
//!
//! The logic is an `impl P2PCore` in its own child module, like the other topic
//! modules. Child modules can see the private fields of `P2PCore`, so no extra
//! visibility layer is needed.
//!
//! ## Design
//!
//! The reliability machinery (`awaiting_confirmation`, `pending_envelopes`,
//! `pending_durable_retries`, `MessageContent::Ack`) is unchanged. Only the carrier
//! changes: `try_publish_raw_via` sends direct or to the server. So this file has no
//! retry loop of its own.
//!
//! ## Black-hole rule
//!
//! A server saying "stored" is not delivery. Only the peer's `Ack` ends the retries, so a
//! faulty or hostile server that acknowledges deposits and delivers nothing cannot
//! swallow messages: the direct path keeps trying.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signer as _, SigningKey};
use ml_dsa::{
    Generate as MlDsaGenerate, KeyExport as _, Keypair as MlDsaKeypair, MlDsa87,
    Signature as MlDsaSignature, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey,
};
use libp2p::{request_response, Multiaddr, PeerId};
use log::{error, info, warn};
use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::packet::NetworkEnvelope;
use crate::server_proto::{
    self, ArchiveRecord, ServerErrorCode, ServerLimits, ServerRequest, ServerResponse, MAX_DEPOSIT_BYTES,
    MAX_FETCH_BATCH_BYTES, MAX_FETCH_BATCH_ITEMS, SERVER_PROTOCOL_VERSION,
};
use crate::server_seal;
use crate::{current_time_ms, extract_peer_id, mono_ms, P2PCore};

mod connection;
mod mailbox;
mod archive;
mod blobs;
mod anon;
pub(crate) use mailbox::*;
pub(crate) use anon::AnonConn;
use archive::*;

/// Full scan interval, a safety net for when the server pushes nothing.
///
/// Normally mail is fetched when the server sends `Push` or `Notify`. In radio saver mode the sweep runs only inside the radio window, so the
/// real cadence is this interval or the next window, whichever is later. A server without the resend (`NOTIFY_RESEND_MS` in typeon-server)
/// must not get a longer interval: one lost `Notify` would then delay all mail by that much (observed: a call invite arrived 4 minutes late).
pub(crate) const SERVER_FETCH_SWEEP_INTERVAL_MS: u64 = 5 * 60 * 1000;

/// Interval for the server connection and registration status scan.
pub(crate) const SERVER_SWEEP_INTERVAL_MS: u64 = 15_000;

/// How long a "already deposited to this server" mark is remembered (see
/// `P2PCore.server_deposited`). It must cover the retry window (7 days) and stay below
/// the server's mailbox TTL. A 12 h value deposited each unacked message again twice a
/// day. The map is bounded by `MAX_SERVER_DEPOSIT_MEMORY`. A new enrollment clears its
/// marks (`forget_server_cursors`), and a regenerated message clears its own.
pub(crate) const SERVER_DEPOSIT_MEMORY_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Upper bound of `server_deposited`. When full, the oldest entries are dropped.
pub(crate) const MAX_SERVER_DEPOSIT_MEMORY: usize = 4096;

/// A mailbox that answered `UnknownMailbox` is not asked again for this long.
///
/// The "recipient is not on my server" answer must not cost one round trip per
/// message. It is not permanent either: the recipient may enroll tomorrow. Ten minutes
/// was too long: right after a key rotation the recipient may not have registered its
/// new mailbox yet, and a single `UnknownMailbox` then cut the server path to that peer
/// for 10 minutes.
pub(crate) const SERVER_UNKNOWN_MAILBOX_TTL_MS: u64 = 60 * 1000;
/// Each further `UnknownMailbox` for the same mailbox doubles the pause, up to this.
/// Measured on a device: a phone never enrolled on this server held six unconfirmed messages. A retry every 2 minutes re-deposited them over Tor,
/// and kept the LTE radio busy 60-75 % of the night.
pub(crate) const SERVER_UNKNOWN_MAILBOX_MAX_TTL_MS: u64 = 60 * 60 * 1000;

/// How long a server that answered with a quota or rate-limit error gets no new deposits.
///
/// Observed failure: the server answered every `Deposit` with `QuotaExceeded`, and the client re-deposited the same 15 KB handshake every poll
/// turn (about once a second), forever, to three mailboxes. With no backoff, a single quota error turned all store-and-forward traffic of that
/// device into a permanent busy loop.
pub(crate) const SERVER_DEPOSIT_BACKOFF_MS: u64 = 5 * 60 * 1000;
/// Each further refused or unanswered deposit doubles the backoff, up to this.
pub(crate) const SERVER_DEPOSIT_BACKOFF_MAX_MS: u64 = 30 * 60 * 1000;
/// Pages requested for one conversation at most, over all its buckets (64 records each, see
/// `ServerInflight::ArchiveFetch`). A server that never ends a bucket, or ends each bucket just
/// before the cap, stops here.
const ARCHIVE_FETCH_MAX_PAGES: u32 = 4096;

/// IDs the server refused (`Registered.refused`) are offered again after this. A reader
/// cap or a full mailbox can clear.
pub(crate) const SERVER_REFUSED_RETRY_MS: u64 = 6 * 60 * 60 * 1000;

/// A fetched item that does not open, or fails processing, holds its mailbox cursor
/// (no Ack, so the server keeps it) for this long, then it is passed over. It can open
/// once an earlier item in the same mailbox is processed (the rotation that brings its
/// key can arrive in the same batch). An item still failing after this will never open.
/// Must stay below `INBOUND_DEDUP_WINDOW_MS` (10 min): the items after a held one are
/// fetched again, and they must still be deduplicated.
pub(crate) const SERVER_HOLD_GRACE_MS: u64 = 5 * 60 * 1000;
/// Fetch that retries a held item. A failed packet is remembered for 30 s by
/// `process_incoming_envelope`, and a retry inside that window would count as done.
pub(crate) const SERVER_HOLD_REFETCH_MS: u64 = 45_000;
/// Items passed over in a row in one mailbox before its later failing items are passed at once (see
/// `ServerRuntime.hold_strikes`). Junk deposits then cost one grace period each only twice.
pub(crate) const SERVER_HOLD_MAX_STRIKES: u32 = 2;

/// Maximum records in one archive upload batch.
pub(crate) const SERVER_ARCHIVE_BATCH: usize = 50;
/// Upload queue cap (RAM and table). When exceeded, the oldest entries are dropped. The
/// local archive keeps them; only their server copy is lost.
pub(crate) const MAX_SERVER_ARCHIVE_QUEUE: usize = 10_000;

/// A server that answers `Internal` to this many blob backoff rounds in a row (about 3 h) loses the head upload. The
/// direct peer path still serves the file.
pub(crate) const MAX_BLOB_INTERNAL_FAILURES: u32 = 12;

/// An upload stays on its server while that server routes and is ready again within this time. Moving it restarts it
/// from chunk 0, so a short Tor drop must not move it.
pub(crate) const BLOB_SERVER_MOVE_MS: u64 = 30 * 60 * 1000;

/// Start of the `last_error` text shown when the server's mailbox cap is reached.
const TOO_MANY_MAILBOXES: &str = "Too many mailboxes for this server";

/// Number of file chunks in flight at once (the pipeline depth).
///
/// Why it matters: with one chunk in flight, throughput is `chunk size / round-trip time`,
/// whatever the bandwidth. Measured over Tor: a 10 MB upload ran at about 12 KB/s. With
/// 256 KiB chunks and a 1 s round trip, 6 parallel requests raise the ceiling to about
/// 1.5 MB/s.
///
/// This is not fixed. The window adapts to the path between `BLOB_WINDOW_MIN` and `BLOB_WINDOW_MAX` (see `BLOB_RTT_GROW_FACTOR`).
pub(crate) const BLOB_WINDOW_START: usize = 4;
pub(crate) const BLOB_WINDOW_MIN: usize = 2;
pub(crate) const BLOB_WINDOW_MAX: usize = 40;

/// The round-trip time above which the window stops growing.
///
/// Measured per path, because the right depth differs on LAN, Tor and relays. With a fixed window of 16 over Tor, the average round trip was 24 s. Requests hit the 30 s
/// protocol timeout, retries ate the bandwidth, and throughput fell from about 180 KB/s to about 50 KB/s. The cause is bufferbloat: 16 x 256 KiB = 4 MB queued on one
/// Tor circuit of about 200 KB/s, so the last chunk waited more than 20 s.
///
/// The bottleneck is bandwidth, not latency, so more parallelism makes it worse. The window must keep the bytes in flight small enough that the queueing delay stays
/// below the timeout.
///
/// The threshold is relative, not absolute: it is compared against the smallest round trip seen (`PendingBlobUpload.rtt_min`). A fixed value pinned the window to its
/// floor on a slow Tor circuit (round trip 15.6 s, window stuck at 2, 33 KB/s). The queue-delay test is "round trip more than twice the best measured on this path",
/// which holds at any path speed.
pub(crate) const BLOB_RTT_GROW_FACTOR: u64 = 2;
/// If the round trip exceeds this, the window does not grow, whatever the queue-delay test
/// says. We are then close to `BLOB_REQUEST_TIMEOUT_MS` (90 s), and a timed-out chunk halves
/// the window.
///
/// This ceiling only prevents approaching the timeout. Rate control is the job of the
/// queue-delay test (see `BLOB_RTT_GROW_FACTOR`).
///
/// An absolute ceiling caused three failures in this file:
///   1. A 6 s first version pinned the window at the floor on a Tor circuit with 12-15 s round trips (33 KB/s).
///   2. Lowering it to 12 s repeated the error (270 to 95 KB/s).
///   3. Raising the chunk size from 256 to 512 KiB doubled the round trip, and the 20 s ceiling
///      pinned the window at 2 again.
/// All three have one cause: the round trip depends on both the path and the CHUNK SIZE, so a fixed
/// millisecond threshold is always wrong for one of them.
///
/// So the ceiling is now a fraction of `BLOB_REQUEST_TIMEOUT_MS` (90 s). It stays out of the way
/// unless a timeout is really near, whatever the chunk size.
pub(crate) const BLOB_REQUEST_TIMEOUT_MS: u64 = 90_000;
pub(crate) const BLOB_RTT_CEILING_MS: u64 = BLOB_REQUEST_TIMEOUT_MS * 4 / 5;
/// Samples below this round trip are measurement noise (local or LAN). Otherwise a very small `rtt_min` would stop growth for no reason.
pub(crate) const BLOB_RTT_FLOOR_MS: u64 = 750;

// ---------------------------------------------------------------------------
// State types
// ---------------------------------------------------------------------------

/// Persistent server record (`servers` table).
#[derive(Debug, Clone)]
pub(crate) struct ServerRecord {
    /// The server's `PeerId`. Primary key.
    pub server_id: String,
    /// All known addresses of the server, comma separated. Onion only (`server_proto::public_server_addrs`);
    /// all are dialed at once and libp2p uses the first to connect.
    pub address: String,
    pub name: String,
    /// A fresh Ed25519 secret key (32 bytes), only for this server.
    ///
    /// The device's identity key is deliberately not used. The server needs only a gate against Sybil
    /// attacks (an invite token) and a revocable handle. Giving it the identity key would let the
    /// operator prove, cryptographically, exactly who is using this server.
    pub enroll_sk: Vec<u8>,
    /// ML-DSA-87 secret key seed (32 bytes) generated for the same purpose, stored in the same way as
    /// `DeviceKeys.sign_sk_mldsa`. The enrollment signature is hybrid, like the rest of the app.
    pub enroll_sk_pq: Vec<u8>,
    pub enrollment_id: Option<Vec<u8>>,
    /// Cleared when enrollment completes. Single use.
    pub token: String,
    pub route_messages: bool,
    /// Keep history on the server. On by default for a newly added server, separate from routing.
    /// The archive is a real backup, not forward secret (see `server_seal::seal_archive_record`).
    pub store_history: bool,
    pub added_at: u64,
}

/// Runtime state of one server (not persisted).
#[derive(Debug, Clone, Default)]
pub(crate) struct ServerRuntime {
    pub peer_id: Option<PeerId>,
    pub connected: bool,
    pub enrolled: bool,
    pub limits: Option<ServerLimits>,
    /// Highest seq per mailbox taken from a batch and processed, not yet acked. See
    /// `commit_server_fetches`.
    pub unacked: HashMap<String, u64>,
    /// A failed `Ack` is not sent again before this time (ms).
    pub ack_retry_at: u64,
    /// Mailbox IDs announced to the server, used to compute the `Register` difference.
    pub registered: HashSet<String>,
    /// IDs the server refused (`Registered.refused`). Not sent again before `refused_retry_at`.
    pub refused: HashSet<String>,
    pub refused_retry_at: u64,
    /// Mailbox -> (seq, first failure ms) of the item holding its cursor. See `SERVER_HOLD_GRACE_MS`.
    pub held: HashMap<String, (u64, u64)>,
    /// Held items passed over after the grace period: skipped, and the cursor moves past them as it does
    /// past an item that opened.
    pub passed: HashSet<(String, u64)>,
    /// SHA-256 of each item handed to `incoming` this turn -> (mailbox, seq, what the box proves about its sender,
    /// fixed when the batch was opened). Used by `server_item_failed` and `server_item_sender`.
    pub taken: HashMap<[u8; 32], (String, u64, ItemCarrier)>,
    pub fetch_due_at: u64,
    pub hello_sent_at: u64,
    pub last_error: Option<String>,
    /// Is a `Fetch` in flight?
    ///
    /// Without this flag, a second `Fetch` with the same cursors could go out, and the server sent the same
    /// envelopes again. Measured on a device: 6 envelopes (about 90 KB) sent twice, 1.1 s apart, over Tor,
    /// for nothing. Cleared on a reply or an error.
    pub fetch_inflight: bool,
    /// See `SERVER_DEPOSIT_BACKOFF_MS`. No new `Deposit` to this server before this time, after a quota or
    /// rate error. `Fetch` and `Ack` are not affected: fetching mail must always continue.
    pub deposit_backoff_until: u64,
    /// Deposits refused or unanswered in a row (exponential backoff).
    pub deposit_failures: u32,
    /// After a refused `ArchivePut` (quota, rate, or server error), no new archive batch before this time
    /// (ms). Kept apart from the deposit backoff, so a full archive never stops message deposits.
    pub archive_backoff_until: u64,
    /// `ArchivePut`s refused in a row (exponential backoff).
    pub archive_failures: u32,
    /// Server unreachable: no new dial before this time (ms). See `server_sweep`.
    pub dial_backoff_until: u64,
    /// Dials since the last successful connection.
    pub dial_attempts: u32,
    /// `Hello`s sent since the last enrollment. Backs off an enrollment the server keeps refusing. See `server_sweep`.
    pub hello_attempts: u32,
    /// A refused `Register`: not sent again before this time (ms).
    pub register_backoff_until: u64,
    /// The purge of a replaced archive key is not sent again before this time (ms).
    pub purge_retry_at: u64,
    /// Last `Notify` received from this server (ms). See `handle_server_push`.
    pub notified_at: u64,
    /// Start of the current `Push` window (ms), and the pushes counted in it.
    pub push_window_at: u64,
    pub push_count: u32,
    /// After a blob request answered `Internal`: no chunk or finish before this time (ms). Kept apart from the deposit
    /// backoff, so a broken blob store does not stop message deposits.
    pub blob_backoff_until: u64,
    /// `Internal` answers to blob requests in a row. At `MAX_BLOB_INTERNAL_FAILURES` the head upload is dropped.
    pub blob_failures: u32,
    /// Since when this server is not connected and enrolled (ms, 0 = ready). See `BLOB_SERVER_MOVE_MS`.
    pub unready_since: u64,
    /// Mailbox -> items passed over in a row after a hold. At `SERVER_HOLD_MAX_STRIKES` a failing item there is passed
    /// at once. A hold that clears (the item opened and was processed) resets it.
    pub hold_strikes: HashMap<String, u32>,
    /// A batch held an item that did not open while it delivered other items of the same mailbox (a rotation notice
    /// may bring its key): fetch again once this turn's items are processed (`commit_server_fetches`).
    pub refetch_now: bool,
    /// `Registered.proof_needed` rounds in a row. Bounded (see the `Registered` arm), so a server that keeps naming
    /// ids cannot make us sign proofs at round-trip speed.
    pub proof_rounds: u32,
    /// The last `Fetch` answer held no item. In radio saver mode a `Notify` then counts once per radio window.
    pub last_fetch_empty: bool,
}

/// What opens the envelopes of one of this device's mailboxes.
#[derive(Clone)]
enum MailboxKey {
    /// The pairing or link secret the mailbox id is made from (`server_seal::open_first_contact`).
    FirstContact(Vec<u8>),
    /// The session's current and previous root keys, and the device at its other end
    /// (`server_seal::open_envelope`).
    Session(Vec<Vec<u8>>, String),
}

/// The carrier of a fetched item, from the box it came from (`MailboxKey`), resolved at fetch time: a handshake
/// processed earlier in the same batch must not change the verdict of a later item.
#[derive(Clone)]
pub(crate) enum ItemCarrier {
    /// A session box: only this device fills it.
    Session(String),
    /// A first-contact box, made from this pairing secret.
    FirstContact(zeroize::Zeroizing<Vec<u8>>),
}

impl std::fmt::Debug for ItemCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self { ItemCarrier::Session(_) => "Session", ItemCarrier::FirstContact(_) => "FirstContact" })
    }
}

/// A server RPC in flight.
#[derive(Debug, Clone)]
pub(crate) enum ServerInflight {
    Hello { server_id: String },
    Enroll { server_id: String },
    Rebind { server_id: String },
    Register { server_id: String, ids: Vec<String>, dropped: Vec<String> },
    /// `message_id`, if any. Used to fall back to the direct path when delivery fails.
    ///
    /// `first_attempt_at`: time of the envelope's FIRST publish attempt. It is kept when the envelope goes back
    /// to the queue after a server error. The earlier code called `publish_envelope`, which stamped the entry
    /// with `current_time_ms()`. Every server round trip then reset the `PENDING_ENVELOPE_TIMEOUT_MS` /
    /// `PENDING_HANDSHAKE_TIMEOUT_MS` clock, so the envelope never expired and the queue cycled forever.
    ///
    /// `dedup_key`: see `deposit_dedup_key`. Used to undo the "already deposited" mark on failure.
    Deposit {
        server_id: String,
        mailbox: String,
        envelope: NetworkEnvelope,
        target_fp: String,
        first_attempt_at: u64,
        dedup_key: String,
        /// Its `Cancel` secret (`server_seal::cancel_secret`), kept with its location once `Deposited`.
        cancel_secret: CancelSecret,
        /// The user cancelled the message while this was in flight. Withdraw the server copy as soon as its
        /// `seq` is known.
        cancelled: bool,
    },
    Fetch { server_id: String },
    /// `acks`: put back in `unacked` when the request fails.
    Ack { server_id: String, acks: Vec<(String, u64)> },
    /// See `ServerRequest::Cancel`. The sender withdraws its own packet (over the anonymous connection, like the
    /// deposit). `key`: its `server_deposit_locations` entry, dropped on the server's answer and kept (retried at the
    /// server sweep) when none came.
    Cancel { server_id: String, key: String },
    /// `records`: `(record_id, rev)` carried by this batch. The queue can change while the request is in
    /// flight, so `Ok` removes only these entries.
    ArchivePut { server_id: String, records: Vec<(String, u64)> },
    /// `bucket_more`: bucket ID, so the older page of the same bucket can be requested when this page comes
    /// back with `more = true`.
    ///
    /// `rest`: buckets of the same conversation still to fetch, one at a time.
    /// `window`: a "Fetch older history" press `(before, after)` by send time. Pages run until they pass
    /// `after`. `next`: conversations of a full restore still to probe, one after another.
    ArchiveFetch {
        server_id: String,
        conv_key: String,
        group: bool,
        bucket_more: Option<String>,
        rest: Vec<String>,
        window: Option<(u64, u64)>,
        next: Vec<(String, bool)>,
        /// The cursor this page was requested from, and the pages of this conversation so far. The next page is
        /// requested only if the server moved strictly past it, and never past `ARCHIVE_FETCH_MAX_PAGES`.
        cursor: Option<(u64, String)>,
        pages: u32,
    },
    /// `window`: a "Fetch older history" press `(before, after)`, and the buckets present in it that reach
    /// it, newest first. `None` means a full restore: every present bucket.
    ArchiveProbe { server_id: String, conv_key: String, group: bool, window: Option<(u64, u64)>, next: Vec<(String, bool)> },
    /// Buckets of replaced archive keys. See `purge_retired_archive`.
    /// `keys`: the `ark_purge` value this run covers. `rest`: buckets not sent yet.
    ArchivePurge { server_id: String, keys: String, rest: Vec<String> },
    BlobPut { server_id: String, blob_id: String, chunk_index: u32, total_chunks: u32, sent_at: u64 },
    BlobFinish { server_id: String, blob_id: String },
}

impl ServerInflight {
    fn server_id(&self) -> &str {
        match self {
            ServerInflight::Hello { server_id }
            | ServerInflight::Enroll { server_id }
            | ServerInflight::Rebind { server_id }
            | ServerInflight::Register { server_id, .. }
            | ServerInflight::Deposit { server_id, .. }
            | ServerInflight::Fetch { server_id }
            | ServerInflight::Ack { server_id, .. }
            | ServerInflight::Cancel { server_id, .. }
            | ServerInflight::ArchivePut { server_id, .. }
            | ServerInflight::ArchiveFetch { server_id, .. }
            | ServerInflight::ArchiveProbe { server_id, .. }
            | ServerInflight::ArchivePurge { server_id, .. }
            | ServerInflight::BlobPut { server_id, .. }
            | ServerInflight::BlobFinish { server_id, .. } => server_id,
        }
    }
}

/// Server events collected while `poll_events` holds the swarm borrow, then processed after it ends. Same
/// pattern as `FileChunkEventLocal`.
pub(crate) enum ServerEventLocal {
    /// The server sent us a request. The only valid kind is `Notify`.
    Request { peer: PeerId, request: ServerRequest, channel: request_response::ResponseChannel<ServerResponse> },
    Response { request_id: request_response::OutboundRequestId, response: ServerResponse },
    OutboundFailure { request_id: request_response::OutboundRequestId },
}

/// An archive record waiting to upload to the server.
#[derive(Debug, Clone)]
pub(crate) struct PendingArchive {
    pub conv_key: String,
    pub record_id: String,
    pub rev: u64,
    pub sent_at_ms: u64,
    /// CBOR-encoded `ArchivedMessage`. Sealing happens at upload time, since the archive key may not be
    /// loaded at queue time.
    pub plaintext: Vec<u8>,
}

/// A file waiting to upload to the server.
#[derive(Debug, Clone)]
pub(crate) struct PendingBlobUpload {
    pub file_id: String,
    /// Proves on the server that this device uploads `file_id` (`server_proto::blob_id_for_upload_secret`).
    pub upload_secret: Vec<u8>,
    pub next_chunk: u32,
    pub total_chunks: u32,
    /// SHA-256 of the whole encrypted file. Sent with `BlobFinish`, so the server never serves a truncated
    /// upload. It is empty while queued and is computed by streaming the `.enc` file after the last chunk is
    /// uploaded (so the file is not read through once more early; attachments can reach 4 GiB).
    /// Chunk indices in flight now (the pipeline, bounded by the blob window). Earlier this was a single
    /// `bool`, so only one chunk could be in flight.
    pub inflight: HashSet<u32>,
    /// Chunks the server has acknowledged.
    pub done: HashSet<u32>,
    /// Adaptive window: grows one step at a time while queue delay is low, and halves on a timeout or
    /// error. A fixed depth was wrong: too small on a LAN, too large on Tor (see `BLOB_RTT_GROW_FACTOR`).
    pub window: usize,
    /// The smallest round trip seen in this transfer: the uncongested base delay of the path. Growth is
    /// judged against it (see `BLOB_RTT_GROW_FACTOR`).
    pub rtt_min: u64,
    /// The one server this upload goes to. Progress restarts if it changes, since chunks spread over two
    /// servers complete on neither.
    pub server_id: Option<String>,
    /// SHA-256 of the `.enc` file, computed once for `BlobFinish` and stored in
    /// `server_blob_uploads.enc_sha256`, so a restart does not hash it again.
    pub enc_sha256: Option<Vec<u8>>,
    /// The hash running on its own thread (up to 4 GiB, off the poll thread). `None` inside means the file
    /// could not be read.
    pub hashing: Option<std::sync::Arc<std::sync::OnceLock<Option<Vec<u8>>>>>,
    /// How many times a `BlobIncomplete` finish sent this upload back to chunk 0.
    /// ponytail: in memory only, a process restart resets it.
    pub restarts: u8,
}

// ---------------------------------------------------------------------------

impl P2PCore {
    // -----------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------

    pub(crate) fn init_server_tables(conn: &rusqlite::Connection) {
        // Same contract as the core's `init_db`: IF NOT EXISTS, and ALTER TABLE errors are ignored.
        let _ = conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS servers (
                server_id      TEXT PRIMARY KEY,
                address        TEXT NOT NULL,
                name           TEXT NOT NULL DEFAULT '',
                enroll_sk      BLOB NOT NULL,
                enrollment_id  BLOB,
                token          TEXT NOT NULL DEFAULT '',
                route_messages INTEGER NOT NULL DEFAULT 1,
                store_history  INTEGER NOT NULL DEFAULT 0,
                added_at       INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS server_cursors (
                server_id  TEXT NOT NULL,
                mailbox_id TEXT NOT NULL,
                last_seq   INTEGER NOT NULL,
                PRIMARY KEY (server_id, mailbox_id)
            );
            CREATE TABLE IF NOT EXISTS server_archived_convs (
                conv_key TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS server_archive_revs (
                conv_key  TEXT NOT NULL,
                record_id TEXT NOT NULL,
                rev       INTEGER NOT NULL,
                PRIMARY KEY (conv_key, record_id)
            );
            CREATE TABLE IF NOT EXISTS server_archive_queue (
                record_id  TEXT PRIMARY KEY,
                conv_key   TEXT NOT NULL,
                rev        INTEGER NOT NULL,
                sent_at_ms INTEGER NOT NULL,
                plaintext  BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS server_blob_uploads (
                file_id      TEXT PRIMARY KEY,
                next_chunk   INTEGER NOT NULL,
                total_chunks INTEGER NOT NULL,
                enc_sha256   BLOB NOT NULL,
                created_at   INTEGER NOT NULL
            );
            "#,
        );
        // Migration pattern of the core: SQLite has no `ADD COLUMN IF NOT EXISTS`, so an error from a column
        // that already exists is ignored.
        let _ = conn.execute("ALTER TABLE servers ADD COLUMN enroll_sk_pq BLOB", []);
        // The server an upload goes to. Without it, every restart started the upload over from chunk 0
        // (see `server_flush_blobs`).
        let _ = conn.execute("ALTER TABLE server_blob_uploads ADD COLUMN server_id TEXT", []);
        // Rows from before upload secrets existed cannot prove their blob any more.
        if conn.execute("ALTER TABLE server_blob_uploads ADD COLUMN upload_secret BLOB", []).is_ok() {
            let _ = conn.execute("DELETE FROM server_blob_uploads", []);
        }
    }

    pub(crate) fn load_servers_from_db(&mut self) {
        self.reconcile_archive_key(false);
        let Some(conn) = &self.db else { return };
        let mut stmt = match conn.prepare(
            "SELECT server_id, address, name, enroll_sk, enrollment_id, CAST(token AS BLOB), route_messages, store_history, added_at, enroll_sk_pq FROM servers",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        // The enrollment secrets and the token are sealed (see `persist_server`). A field that does not open is
        // never read as raw bytes. A row whose enrollment key does not open is skipped and left on disk.
        let open = |raw: Vec<u8>| self.open_local_blob(&raw);
        let loaded: Vec<ServerRecord> = stmt
            .query_map([], |r| {
            let server_id: String = r.get(0)?;
            let Some(enroll_sk) = open(r.get(3)?) else {
                warn!("Could not open server record, skipped: {}", crate::log_id(&server_id));
                return Ok(None);
            };
            Ok(Some(ServerRecord {
                server_id,
                address: r.get(1)?,
                name: r.get(2)?,
                enroll_sk,
                enrollment_id: r.get(4)?,
                token: open(r.get(5)?).and_then(|t| String::from_utf8(t).ok()).unwrap_or_default(),
                route_messages: r.get::<_, i64>(6)? != 0,
                store_history: r.get::<_, i64>(7)? != 0,
                added_at: r.get::<_, i64>(8)? as u64,
                // An empty value means the record is re-enrolled.
                enroll_sk_pq: open(r.get::<_, Option<Vec<u8>>>(9)?.unwrap_or_default()).unwrap_or_default(),
            }))
            })
            .map(|it| it.filter_map(|r| r.ok().flatten()).collect())
            .unwrap_or_default();
        drop(stmt);
        self.servers = loaded;

        // Older rows (created before the server side started filtering) may hold private LAN addresses. See
        // `add_server`. They are cleaned on load and the clean form is written back, or every start would fall
        // back to the LAN.
        let mut cleaned: Vec<ServerRecord> = Vec::new();
        for rec in &self.servers {
            let kept = server_proto::public_server_addrs(rec.address.split(','));
            let joined = kept.join(",");
            if !joined.is_empty() && joined != rec.address {
                let mut r = rec.clone();
                r.address = joined;
                cleaned.push(r);
            }
        }
        for r in cleaned {
            warn!("Local network address removed from server address: {}", crate::log_id(&r.server_id));
            self.persist_server(&r);
            if let Some(slot) = self.servers.iter_mut().find(|s| s.server_id == r.server_id) {
                *slot = r;
            }
        }

        // Prepare `server_rt` HERE, with its `peer_id`. Without it, `note_server_connection` cannot match an
        // incoming connection to any server, and `rt.connected` stays false. Then `server_sweep` keeps finding
        // "not connected" and redials, but libp2p is already connected, so no new `ConnectionEstablished` fires,
        // and the client never registers. This is exactly what happened on a real device: the Linux client was
        // connected to the server and reported "connected but no server" for hours.
        for rec in &self.servers {
            let peer_id = rec
                .address
                .split(',')
                .filter_map(|a| a.trim().parse::<Multiaddr>().ok())
                .find_map(|a| extract_peer_id(&a));
            self.server_rt.entry(rec.server_id.clone()).or_default().peer_id = peer_id;
        }

        // Cursors. Without them, every restart reprocessed the whole mailbox (deduplication would discard it,
        // at a cost in CPU and battery).
        if let Ok(mut stmt) = conn.prepare("SELECT server_id, mailbox_id, last_seq FROM server_cursors") {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?.max(0) as u64))
            }) {
                for (sid, mid, seq) in rows.flatten() {
                    self.server_cursors.insert((sid, mid), seq);
                }
            }
        }
        // Persistent archive queue, so it survives a process kill.
        if let Ok(mut stmt) = conn.prepare(
            "SELECT record_id, conv_key, rev, sent_at_ms, plaintext FROM server_archive_queue ORDER BY created_at",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(PendingArchive {
                    record_id: r.get(0)?,
                    conv_key: r.get(1)?,
                    rev: r.get::<_, i64>(2)? as u64,
                    sent_at_ms: r.get::<_, i64>(3)? as u64,
                    plaintext: r.get(4)?,
                })
            }) {
                // See `queue_archive_record` : rows are sealed with `seal_local_blob`. A row that does not open
                // is dropped (never sent on as raw bytes).
                let raw: Vec<PendingArchive> = rows.flatten().collect();
                let mut opened: Vec<PendingArchive> = raw
                    .into_iter()
                    .filter_map(|mut e| {
                        if let Some(plain) = self.open_local_blob(&e.plaintext) {
                            e.plaintext = plain;
                            return Some(e);
                        }
                        warn!("Could not open archive queue row, skipped: {}", crate::log_id(&e.record_id));
                        let _ = conn.execute("DELETE FROM server_archive_queue WHERE record_id = ?1", params![e.record_id]);
                        None
                    })
                    .collect();
                // Oldest first (`ORDER BY created_at`): over the cap, the head goes.
                let over = opened.len().saturating_sub(MAX_SERVER_ARCHIVE_QUEUE);
                for e in opened.drain(..over) {
                    let _ = conn.execute("DELETE FROM server_archive_queue WHERE record_id = ?1", params![e.record_id]);
                }
                self.server_archive_queue = opened;
            }
        }
        if let Ok(mut stmt) =
            conn.prepare("SELECT file_id, next_chunk, total_chunks, server_id, enc_sha256, upload_secret FROM server_blob_uploads")
        {
            if let Ok(rows) = stmt.query_map([], |r| {
                let next_chunk = r.get::<_, i64>(1)? as u32;
                let enc_sha256: Vec<u8> = r.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default();
                Ok(PendingBlobUpload {
                    file_id: r.get(0)?,
                    upload_secret: r.get::<_, Option<Vec<u8>>>(5)?.unwrap_or_default(),
                    next_chunk,
                    total_chunks: r.get::<_, i64>(2)? as u32,
                    inflight: HashSet::new(),
                    // `done` used to start empty, but `server_flush_blobs` chooses the next chunk only from
                    // `done`/`inflight`. So the `next_chunk` watermark read from disk had no effect, and the WHOLE
                    // file was uploaded again on every start. The server accepted repeats idempotently, so the upload
                    // finished, but it cost gigabytes of pointless Tor traffic. If the app was killed regularly, a
                    // large file might never finish. Chunks below the watermark are known to be on the server:
                    // `advance_blob_upload` moves `next_chunk` only when the whole range 0..n is acknowledged.
                    done: (0..next_chunk).collect(),
                    window: BLOB_WINDOW_START,
                    rtt_min: u64::MAX,
                    server_id: r.get(3)?,
                    enc_sha256: (enc_sha256.len() == 32).then_some(enc_sha256),
                    hashing: None,
                    restarts: 0,
                })
            }) {
                self.server_blob_uploads = rows.flatten().collect();
            }
        }
        if !self.servers.is_empty() {
            info!("{} servers loaded", self.servers.len());
        }
    }

    /// Writes the server record to disk.
    ///
    /// Errors are NOT swallowed. A swallowed error produced this state: the server lived in memory, looked
    /// enrolled, and the UI said "Connected", but the row was not on disk. On the next start the app did not
    /// know the server at all, and envelopes silently fell back to the direct peer path. A silent failure is the
    /// most expensive kind to diagnose.
    fn persist_server(&self, rec: &ServerRecord) {
        let Some(conn) = &self.db else {
            error!("Could not write server record to disk: database not found ({})", crate::log_id(&rec.server_id));
            return;
        };
        // A copy of the database must not be enough to `Rebind` the enrollment or to spend the token. It is
        // sealed, like the archive queue.
        let (Some(enroll_sk), Some(enroll_sk_pq), Some(token)) = (
            self.seal_local_blob(&rec.enroll_sk),
            self.seal_local_blob(&rec.enroll_sk_pq),
            self.seal_local_blob(rec.token.as_bytes()),
        ) else {
            error!("Could not write server record to disk: no local key ({})", crate::log_id(&rec.server_id));
            return;
        };
        let written = conn.execute(
            "INSERT OR REPLACE INTO servers
             (server_id, address, name, enroll_sk, enrollment_id, token, route_messages, store_history, added_at, enroll_sk_pq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                rec.server_id, rec.address, rec.name, enroll_sk, rec.enrollment_id, token,
                rec.route_messages as i64, rec.store_history as i64, rec.added_at as i64, enroll_sk_pq
            ],
        );
        match written {
            Ok(_) => info!("Server record written to disk: {}", crate::log_id(&rec.server_id)),
            Err(e) => error!("Server record NOT written to disk ({}): {}", crate::log_id(&rec.server_id), e),
        }
    }

    fn persist_cursor(&self, server_id: &str, mailbox_id: &str, seq: u64) {
        let Some(conn) = &self.db else { return };
        // If this fails silently, every restart reprocesses the whole mailbox (deduplication catches it, but
        // at a cost in CPU and battery). Forward only: an older Ack confirmed late must not move it back.
        let r = conn.execute(
            "INSERT INTO server_cursors (server_id, mailbox_id, last_seq) VALUES (?1, ?2, ?3)
             ON CONFLICT(server_id, mailbox_id) DO UPDATE SET last_seq = MAX(last_seq, excluded.last_seq)",
            params![server_id, mailbox_id, seq.min(i64::MAX as u64) as i64],
        );
        if let Err(e) = r {
            warn!("Could not write server cursor ({}/{}): {}", crate::log_id(&server_id), mailbox_log_id(mailbox_id), e);
        }
    }

    // -----------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------

    /// Adds a server from an invite code.
    pub(crate) fn add_server(&mut self, invite_code: &str) -> Result<String, String> {
        let invite = server_proto::parse_server_invite(invite_code)?;
        // Private network addresses must never enter the code (the server side filters them). Old invites still
        // carry them, though, and libp2p dials all addresses at once and the LAN wins. Traffic meant "through the
        // server" then silently flowed over the local network. Filter here as well, so pasting an old code does
        // not do this (see `server_proto::public_server_addrs`).
        let addrs = server_proto::public_server_addrs(&invite.addrs);
        if addrs.is_empty() {
            return Err("Invalid invite code: no reachable address (local network address only)".to_string());
        }
        let invite = server_proto::ServerInvite { addrs, token: invite.token };
        let parsed: Vec<Multiaddr> = invite
            .addrs
            .iter()
            .filter_map(|a| a.parse::<Multiaddr>().ok())
            .collect();
        if parsed.is_empty() {
            return Err("Invalid server address".to_string());
        }
        // All addresses must belong to the same server: the `/p2p/<peer_id>` suffix proves it. An address with
        // a different PeerId means a broken code or a merge attempt. Adding it silently would connect to the
        // wrong server.
        let peer_id = extract_peer_id(&parsed[0]).ok_or("Invalid address: must end with /p2p/<peer_id>")?;
        if parsed.iter().any(|a| extract_peer_id(a) != Some(peer_id)) {
            return Err("Invalid invite code: addresses point to different servers".to_string());
        }
        let server_id = peer_id.to_string();

        // A fresh invite for a server already added means "renew my enrollment". It used to be refused outright.
        // When the operator revoked the enrollment, or it never completed, the user's only way out was to remove
        // the server and add it again. But removal also deletes the archive on that server (see `remove_server`),
        // so a user who only wanted to re-enroll lost their history. With a working enrollment the behaviour is
        // unchanged: do not generate new keys for no reason.
        if let Some(existing) = self.servers.iter().find(|s| s.server_id == server_id).cloned() {
            // A fresh token means "re-enroll", and the user asked for it explicitly. We do NOT check whether the
            // enrollment works right now. Checking would bring back the trap being fixed: the client learns a
            // revoked enrollment only by sending a request and getting `Revoked`. If we had refused the new code
            // because the server "already exists", the user would still be stuck.
            //
            // Re-enrolling is safe. Mailboxes are addressed by mailbox ID, not enrollment ID. Cursors stay on the
            // client, and the archive key does not depend on the enrollment (see `archive_root_key`). The SAME token
            // pasted again (a double tap) does nothing.
            if existing.token == invite.token && !invite.token.is_empty() {
                return Err("This server is already added".to_string());
            }
            let mut rec = existing;
            rec.address = invite.addrs.join(",");
            rec.token = invite.token;
            // `enrollment_id` stays. `begin_enrollment` tries the token first and falls back to `Rebind` when the
            // server refuses it. A spent token pasted again must not cost a working enrollment.
            self.persist_server(&rec);
            if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                *r = rec;
            }
            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                rt.enrolled = false;
                rt.hello_sent_at = 0;
                rt.hello_attempts = 0;
                rt.last_error = None;
            }
            for a in parsed {
                self.dial_with_relay_fallback(peer_id, Some(a));
            }
            self.server_sweep_at = 0;
            return Ok(serde_json::json!({ "server_id": server_id }).to_string());
        }

        // Fresh keys for this server only (see `ServerRecord.enroll_sk`). Hybrid, like every signature in the app.
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let signing_pq: MlDsaSigningKey<MlDsa87> = MlDsaGenerate::generate();
        let rec = ServerRecord {
            server_id: server_id.clone(),
            address: invite.addrs.join(","),
            name: String::new(),
            enroll_sk: signing.to_bytes().to_vec(),
            enroll_sk_pq: signing_pq.to_bytes().to_vec(),
            enrollment_id: None,
            token: invite.token,
            route_messages: true,
            // History is on by default, on the first server only: one history server (see `set_server_history`).
            store_history: !self.servers.iter().any(|s| s.store_history),
            added_at: current_time_ms(),
        };
        let history = rec.store_history;
        self.persist_server(&rec);
        self.servers.push(rec);
        if history {
            self.backfill_server_archive();
        }
        self.server_rt.insert(server_id.clone(), ServerRuntime { peer_id: Some(peer_id), ..Default::default() });

        // Connect now, so the user sees the result on the Settings screen. ALL addresses are tried at once. libp2p
        // uses the first to connect, and the LAN naturally beats the onion.
        for a in parsed {
            self.dial_with_relay_fallback(peer_id, Some(a));
        }
        self.server_sweep_at = 0;

        Ok(serde_json::json!({ "server_id": server_id }).to_string())
    }

    /// Removes a server.
    ///
    /// Asks the server to delete our archive before removal. Without that, an encrypted copy of our history would stay on a server we no longer
    /// use, indefinitely. The deletion cannot be PROVED (see SECURITY.md). Not asking, though, would mean choosing to keep it.
    pub(crate) fn remove_server(&mut self, server_id: &str) -> Result<(), String> {
        let Some(idx) = self.servers.iter().position(|s| s.server_id == server_id) else {
            return Err("Server not found".to_string());
        };
        // The purge is one request with no retry. Sent to an unreachable server it is lost, and the sealed archive
        // stays there for good. Turning history off first is the explicit "remove anyway".
        let reachable = self.server_rt.get(server_id).map_or(false, |r| r.connected && r.enrolled);
        if self.servers[idx].store_history && self.archive_root_key.is_some() && !reachable {
            return Err("Server not reachable over network, archive not deleted. Try again when connected, or turn off history storage first".to_string());
        }
        // The row goes first. A failed delete would leave the server gone in memory but back at the next launch.
        let no_servers_left = self.servers.len() == 1;
        if let Some(conn) = &self.db {
            conn.execute("DELETE FROM servers WHERE server_id = ?1", params![server_id])
                .map_err(|e| format!("Could not delete server: {e}"))?;
        }
        // Before `server_archived_convs` is cleared: it lists the conversations deleted since they were archived.
        self.purge_server_archive(server_id);
        if let Some(conn) = &self.db {
            if let Err(e) = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1", params![server_id]) {
                warn!("Could not delete server cursors: {}", e);
            }
            if no_servers_left {
                // The revisions too. No archive is left that they could guard.
                for t in ["server_archived_convs", "server_archive_queue", "server_blob_uploads", "server_archive_revs"] {
                    if let Err(e) = conn.execute(&format!("DELETE FROM {t}"), []) {
                        warn!("Could not delete {}: {}", t, e);
                    }
                }
            }
        }
        // Our mailboxes come off the server too. Otherwise they keep taking mail (and pushing it at us) until the
        // server's own sweep.
        let unregister = self
            .server_rt
            .get(server_id)
            .filter(|r| r.connected && r.enrolled)
            .and_then(|rt| Some((rt.peer_id?, Self::mailbox_cap(rt), rt.registered.iter().cloned().collect::<Vec<String>>())));
        if let Some((peer_id, cap, ids)) = unregister {
            for chunk in ids.chunks(cap) {
                let req = ServerRequest::Register { add: Vec::new(), drop: chunk.to_vec(), proofs: Vec::new() };
                let _ = self.send_server_request(peer_id, req);
            }
        }
        self.servers.remove(idx);
        self.server_rt.remove(server_id);
        self.server_cursors.retain(|(sid, _), _| sid != server_id);
        // Its requests in flight: an answer must not write cursors for a server that is gone. A deposit goes over
        // the direct path instead.
        let stale: Vec<request_response::OutboundRequestId> = self
            .server_inflight
            .iter()
            .filter(|(_, i)| i.server_id() == server_id)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(inflight) = self.server_inflight.remove(&id) {
                self.requeue_failed_deposit(&inflight);
            }
        }
        // Pending archive queue and blob uploads must be cleared too. `server_flush_archive` and
        // `server_flush_blobs` need a connected, enrolled server (and `store_history` on, for the archive). Once the
        // last server is removed, these rows would never drain again and would stay on disk forever.
        if no_servers_left {
            self.server_archive_queue.clear();
            self.server_blob_uploads.clear();
        }
        // No history server left (another server without history may remain): the queue would never drain, and a
        // later switch to history would upload stale copies, edits and deletes included. Same as `set_server_history`.
        if !self.servers.iter().any(|s| s.store_history) {
            self.server_archive_queue.clear();
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM server_archive_queue", []);
            }
        }
        self.server_deposited.retain(|(sid, _), _| sid != server_id);
        Ok(())
    }


    pub(crate) fn set_server_routing(&mut self, server_id: &str, enabled: bool) -> Result<(), String> {
        let Some(rec) = self.servers.iter_mut().find(|s| s.server_id == server_id) else {
            return Err("Server not found".to_string());
        };
        rec.route_messages = enabled;
        let rec = rec.clone();
        self.persist_server(&rec);
        // Uploads go to routing servers only. With none left, the queue never drained and counted as pending work
        // for good.
        if !self.servers.iter().any(|s| s.route_messages) {
            self.server_blob_uploads.clear();
            if let Some(conn) = &self.db {
                if let Err(e) = conn.execute("DELETE FROM server_blob_uploads", []) {
                    warn!("Could not delete blob upload queue: {}", e);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn set_server_history(&mut self, server_id: &str, enabled: bool) -> Result<(), String> {
        if !self.servers.iter().any(|s| s.server_id == server_id) {
            return Err("Server not found".to_string());
        }
        // One history server: the upload queue is global, and a record leaves it on the first `Ok`. With two servers
        // each would hold part of the history.
        let mut changed = Vec::new();
        for s in self.servers.iter_mut() {
            let want = if s.server_id == server_id { enabled } else { s.store_history && !enabled };
            if s.store_history != want {
                s.store_history = want;
                changed.push(s.clone());
            }
        }
        for rec in &changed {
            self.persist_server(rec);
            // History off here (or moved elsewhere): delete what this server holds, as `remove_server` does. Sent once.
            // If the server is unreachable now, it stays.
            if !rec.store_history {
                self.purge_server_archive(&rec.server_id);
            }
        }
        // No history server left: nothing will ever take the queue.
        if !self.servers.iter().any(|s| s.store_history) {
            self.server_archive_queue.clear();
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM server_archive_queue", []);
            }
        }
        // Also when history moves to another server, since that one holds nothing yet.
        if enabled && !changed.is_empty() {
            self.backfill_server_archive();
        }
        Ok(())
    }

    pub(crate) fn list_servers_json(&self) -> String {
        let arr: Vec<serde_json::Value> = self
            .servers
            .iter()
            .map(|s| {
                let rt = self.server_rt.get(&s.server_id);
                serde_json::json!({
                    "server_id": s.server_id,
                    "address": s.address,
                    "name": s.name,
                    "route_messages": s.route_messages,
                    "store_history": s.store_history,
                    "connected": rt.map(|r| r.connected).unwrap_or(false),
                    "enrolled": rt.map(|r| r.enrolled).unwrap_or(false),
                    "last_error": rt.and_then(|r| r.last_error.clone()),
                })
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    }

}

/// A deposit's `Cancel` secret (`server_seal::cancel_secret`): zeroed on drop, never printed.
#[derive(Clone)]
pub(crate) struct CancelSecret(zeroize::Zeroizing<[u8; 32]>);

impl CancelSecret {
    pub(crate) fn new(secret: [u8; 32]) -> Self {
        CancelSecret(zeroize::Zeroizing::new(secret))
    }
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for CancelSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CancelSecret(..)")
    }
}

/// Where a deposit landed (`P2PCore.server_deposit_locations`). `cancelling`: the user withdrew it and the server has
/// not answered the `Cancel` yet. Kept until it does, and sent again at the server sweep.
#[derive(Clone, Debug)]
pub(crate) struct DepositLocation {
    pub(crate) mailbox: String,
    pub(crate) seq: u64,
    pub(crate) cancel: CancelSecret,
    pub(crate) cancelling: bool,
}

/// `server_deposit_locations` / `server_deposited` key: `"mailbox|message_id"` for a `Message` (one entry per target), anything else as it is.
fn location_message_id(key: &str) -> &str {
    key.split_once('|').map_or(key, |(_, mid)| mid)
}

#[cfg(test)]
mod tests;
