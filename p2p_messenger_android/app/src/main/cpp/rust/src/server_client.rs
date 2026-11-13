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
//! changes: `try_publish_raw` tries the server before gossip. So this file has no
//! retry loop of its own.
//!
//! ## Black-hole rule
//!
//! A server saying "stored" does not stop gossip for good. A faulty or hostile server
//! that acknowledges deposits and delivers nothing would otherwise swallow messages
//! indefinitely. See `should_shadow_on_gossipsub`.

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
/// Pages requested from one archive bucket at most (64 records each, see
/// `ServerInflight::ArchiveFetch`). A server that never ends a bucket stops here.
const ARCHIVE_FETCH_MAX_PAGES: u32 = 1024;

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

/// Maximum records in one archive upload batch.
pub(crate) const SERVER_ARCHIVE_BATCH: usize = 50;
/// Upload queue cap (RAM and table). When exceeded, the oldest entries are dropped. The
/// local archive keeps them; only their server copy is lost.
pub(crate) const MAX_SERVER_ARCHIVE_QUEUE: usize = 10_000;

/// Start of the `last_error` text shown when the server's mailbox cap is reached.
const TOO_MANY_MAILBOXES: &str = "Too many mailboxes for this server";

/// Number of file chunks in flight at once (the pipeline depth).
///
/// Why it matters: with one chunk in flight, throughput is `chunk size / round-trip time`,
/// whatever the bandwidth. Measured over Tor: a 10 MB upload ran at about 12 KB/s. With
/// 256 KiB chunks and a 1 s round trip, 6 parallel requests raise the ceiling to about
/// 1.5 MB/s.
///
/// This is not fixed. The window adapts to the path (see `BLOB_RTT_TARGET_MS`).
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
    /// All known addresses of the server, comma separated: onion, plus LAN or public IP if any.
    /// All are dialed at once and libp2p uses the first to connect. When only one address was
    /// stored and it was an onion one, two devices on the same local network still sent all traffic
    /// over Tor (measured: a 10 MB upload at about 12 KB/s).
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
    /// SHA-256 of each item handed to `incoming` this turn -> (mailbox, seq). Used by `server_item_failed`.
    pub taken: HashMap<[u8; 32], (String, u64)>,
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

/// A server RPC in flight.
#[derive(Debug, Clone)]
pub(crate) enum ServerInflight {
    Hello { server_id: String },
    Enroll { server_id: String },
    Rebind { server_id: String },
    Register { server_id: String, ids: Vec<String>, dropped: Vec<String> },
    /// `message_id`, if any. Used to fall back to gossip when delivery fails.
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
        /// The user cancelled the message while this was in flight. Withdraw the server copy as soon as its
        /// `seq` is known.
        cancelled: bool,
    },
    Fetch { server_id: String },
    /// `acks`: put back in `unacked` when the request fails.
    Ack { server_id: String, acks: Vec<(String, u64)> },
    /// See `ServerRequest::Cancel`. The sender withdraws its own packet. No reply handling is needed. The
    /// request is tracked only so an unexpected-reply warning is not logged.
    Cancel { server_id: String },
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
        /// The cursor this page was requested from, and the pages of this bucket so far. The next page is
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
            | ServerInflight::Cancel { server_id }
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
    /// Chunk indices in flight now (the pipeline, see `BLOB_PIPELINE_DEPTH`). Earlier this was a single
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
                warn!("Sunucu kaydı açılamadı, atlandı: {}", crate::log_id(&server_id));
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
            warn!("Sunucu adresinden yerel ağ adresi çıkarıldı: {}", crate::log_id(&r.server_id));
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
                        warn!("Arşiv kuyruğu satırı açılamadı, atlandı: {}", crate::log_id(&e.record_id));
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
            info!("{} sunucu yüklendi", self.servers.len());
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
            error!("Sunucu kaydı diske yazılamadı: veritabanı yok ({})", crate::log_id(&rec.server_id));
            return;
        };
        // A copy of the database must not be enough to `Rebind` the enrollment or to spend the token. It is
        // sealed, like the archive queue.
        let (Some(enroll_sk), Some(enroll_sk_pq), Some(token)) = (
            self.seal_local_blob(&rec.enroll_sk),
            self.seal_local_blob(&rec.enroll_sk_pq),
            self.seal_local_blob(rec.token.as_bytes()),
        ) else {
            error!("Sunucu kaydı diske yazılamadı: yerel anahtar yok ({})", crate::log_id(&rec.server_id));
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
            Ok(_) => info!("Sunucu kaydı diske yazıldı: {}", crate::log_id(&rec.server_id)),
            Err(e) => error!("Sunucu kaydı diske YAZILAMADI ({}): {}", crate::log_id(&rec.server_id), e),
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
            warn!("Sunucu imleci yazılamadı ({}/{}): {}", crate::log_id(&server_id), mailbox_log_id(mailbox_id), e);
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
            return Err("Davet kodunda ulaşılabilir bir adres yok (yalnızca yerel ağ adresi)".to_string());
        }
        let invite = server_proto::ServerInvite { addrs, token: invite.token };
        let parsed: Vec<Multiaddr> = invite
            .addrs
            .iter()
            .filter_map(|a| a.parse::<Multiaddr>().ok())
            .collect();
        if parsed.is_empty() {
            return Err("Geçersiz sunucu adresi".to_string());
        }
        // All addresses must belong to the same server: the `/p2p/<peer_id>` suffix proves it. An address with
        // a different PeerId means a broken code or a merge attempt. Adding it silently would connect to the
        // wrong server.
        let peer_id = extract_peer_id(&parsed[0]).ok_or("Adres bir /p2p/<peer_id> son eki içermeli")?;
        if parsed.iter().any(|a| extract_peer_id(a) != Some(peer_id)) {
            return Err("Davet kodundaki adresler farklı sunuculara işaret ediyor".to_string());
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
                return Err("Bu sunucu zaten ekli".to_string());
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
            return Err("Sunucu bulunamadı".to_string());
        };
        // The purge is one request with no retry. Sent to an unreachable server it is lost, and the sealed archive
        // stays there for good. Turning history off first is the explicit "remove anyway".
        let reachable = self.server_rt.get(server_id).map_or(false, |r| r.connected && r.enrolled);
        if self.servers[idx].store_history && self.archive_root_key.is_some() && !reachable {
            return Err("Sunucuya ulaşılamıyor, arşiv silinemedi. Bağlanınca tekrar deneyin ya da önce geçmiş saklamayı kapatın".to_string());
        }
        // The row goes first. A failed delete would leave the server gone in memory but back at the next launch.
        let no_servers_left = self.servers.len() == 1;
        if let Some(conn) = &self.db {
            conn.execute("DELETE FROM servers WHERE server_id = ?1", params![server_id])
                .map_err(|e| format!("Sunucu silinemedi: {e}"))?;
        }
        // Before `server_archived_convs` is cleared: it lists the conversations deleted since they were archived.
        self.purge_server_archive(server_id);
        if let Some(conn) = &self.db {
            if let Err(e) = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1", params![server_id]) {
                warn!("Sunucu imleçleri silinemedi: {}", e);
            }
            if no_servers_left {
                // The revisions too. No archive is left that they could guard.
                for t in ["server_archived_convs", "server_archive_queue", "server_blob_uploads", "server_archive_revs"] {
                    if let Err(e) = conn.execute(&format!("DELETE FROM {t}"), []) {
                        warn!("{} silinemedi: {}", t, e);
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
        // gossip instead.
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


    /// Every conversation that can have buckets on the server.
    fn archive_conv_keys(&self) -> Vec<String> {
        // The archive key of 1:1 chats is the other side's `identity_id`, not the local `contact_id` (see the
        // `server_archive_bucket` note). Keyed by identity, so the archive stays readable when the other side
        // changes device.
        let mut conv_keys: Vec<String> = self.groups.keys().cloned().collect();
        conv_keys.extend(self.contacts.values().map(|c| c.trusted_identity_id.clone()));
        // And every conversation ever archived: a contact or group deleted since then still has buckets on the server.
        if let Some(conn) = &self.db {
            if let Ok(mut stmt) = conn.prepare("SELECT conv_key FROM server_archived_convs") {
                if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                    conv_keys.extend(rows.flatten());
                }
            }
        }
        conv_keys.sort();
        conv_keys.dedup();
        conv_keys
    }

    /// Requests deletion of our entire archive on the server.
    ///
    /// Buckets are per conversation and per month (see `server_seal::server_archive_bucket`), so to know what to
    /// delete, we generate the last 36 months for every conversation we know. Deleting a bucket that does not exist
    /// is a no-op on the server. Generating an extra ID costs nothing, while missing one would leave archive residue.
    pub(crate) fn purge_server_archive(&mut self, server_id: &str) {
        let conv_keys = self.archive_conv_keys();
        self.purge_archive_convs(server_id, &conv_keys);
    }

    /// One conversation's archive on every server (for a deleted contact), and its queued uploads, which would
    /// otherwise put it back. Best effort: an unreachable server keeps it until its TTL. The `server_archived_convs`
    /// row stays, so a later whole-server purge still covers it.
    pub(crate) fn purge_conv_archive(&mut self, conv_key: &str) {
        self.server_archive_queue.retain(|e| e.conv_key != conv_key);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM server_archive_queue WHERE conv_key = ?1", params![conv_key]);
        }
        let server_ids: Vec<String> = self.servers.iter().map(|s| s.server_id.clone()).collect();
        for sid in server_ids {
            self.purge_archive_convs(&sid, &[conv_key.to_string()]);
        }
    }

    fn purge_archive_convs(&mut self, server_id: &str, conv_keys: &[String]) {
        let Some(ark) = self.archive_root_key else { return };
        let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id) else { return };

        let now = current_time_ms();
        let buckets: Vec<String> = conv_keys.iter().flat_map(|c| archive_buckets(&ark, c, now)).collect();
        if buckets.is_empty() {
            return;
        }
        // One request must not exceed 1 MiB (see the `MAX_DEPOSIT_BYTES` note: the same wire cap applies to every
        // request). 500: the server refuses a list longer than its 512-mailbox cap.
        let cap = self.server_rt.get(server_id).map_or(1, Self::mailbox_cap).min(500);
        for chunk in buckets.chunks(cap) {
            let req = ServerRequest::ArchivePurge { buckets: chunk.to_vec() };
            if self.send_server_request(peer_id, req).is_none() {
                warn!("Arşiv silme isteği gönderilemedi: {}", crate::log_id(server_id));
                return;
            }
        }
    }

    pub(crate) fn set_server_routing(&mut self, server_id: &str, enabled: bool) -> Result<(), String> {
        let Some(rec) = self.servers.iter_mut().find(|s| s.server_id == server_id) else {
            return Err("Sunucu bulunamadı".to_string());
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
                    warn!("Blob yükleme kuyruğu silinemedi: {}", e);
                }
            }
        }
        Ok(())
    }

    /// A queued blob upload that a server can take now: a routing server, connected, enrolled, and not in deposit
    /// backoff.
    pub(crate) fn blob_upload_can_run(&self) -> bool {
        let now = mono_ms();
        !self.server_blob_uploads.is_empty()
            && self.servers.iter().any(|s| {
                s.route_messages
                    && self.server_rt.get(&s.server_id).map_or(false, |r| r.connected && r.enrolled && now >= r.deposit_backoff_until)
            })
    }

    pub(crate) fn set_server_history(&mut self, server_id: &str, enabled: bool) -> Result<(), String> {
        if !self.servers.iter().any(|s| s.server_id == server_id) {
            return Err("Sunucu bulunamadı".to_string());
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

    /// History written while no server stored it was never queued. Queue all local rows, or a restored device
    /// shows a gap up to today. Restarts the paged `maybe_archive_backfill` from the newest row. It runs one slice
    /// per sweep until it reaches the oldest.
    pub(crate) fn backfill_server_archive(&mut self) {
        self.meta_put("ark_backfill", "1");
        self.server_sweep_at = 0;
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

    // -----------------------------------------------------------------
    // Bucket IDs
    // -----------------------------------------------------------------

    /// Every store-and-forward mailbox this device reads: id -> the secret its `Register` proof is made from
    /// (`mailbox_proof`), and the key that opens its envelopes (`MailboxKey`).
    ///
    /// The single source for `Register`, `Fetch`, and opening a batch.
    ///
    /// A first-contact mailbox is made from a pairing secret (`first_contact_secrets`), one mailbox per secret.
    /// Its proof key comes from this device's signing key. Someone who holds the code can compute the id but still
    /// cannot register it.
    fn own_server_mailboxes(&self) -> HashMap<String, (Vec<u8>, MailboxKey)> {
        let mut idx = HashMap::new();
        if let Some(fp) = &self.own_mailbox_topic_fp {
            if let Some(keys) = self.own_device_keys.get(fp) {
                let owner_secret = keys.sign_sk_ed25519.to_bytes().to_vec();
                for secret in self.first_contact_secrets() {
                    idx.insert(server_seal::first_contact_mailbox_id(&secret, fp), (owner_secret.clone(), MailboxKey::FirstContact(secret)));
                }
            }
        }
        for (peer_fp, state) in &self.ratchets {
            let Some((mailbox, secret)) = self.session_mailbox(peer_fp) else { continue };
            // Rotation window: the other side may still seal with the OLD root key if it has not applied our last
            // rotation yet.
            let mut keys = vec![state.root_handle_now()];
            keys.extend(state.prev_root_key.clone());
            idx.insert(mailbox, (secret.to_vec(), MailboxKey::Session(keys, peer_fp.clone())));
        }
        idx
    }

    /// The server mailbox of the session with `peer_fp`, and its proof secret. It is stable, derived from the two
    /// devices' long-term KEM keys (`server_seal::session_mailbox_secret`), not from the rotating root key. The id
    /// is made from the proof key (`key_bound_mailbox_id`).
    /// PROTOCOL BREAK: older clients use a different id.
    fn session_mailbox(&self, peer_fp: &str) -> Option<(String, [u8; 32])> {
        let own_fp = self.own_mailbox_topic_fp.as_ref()?;
        let own = self.own_device_keys.get(own_fp)?;
        let peer = self.known_remote_devices.get(peer_fp).or_else(|| self.own_devices.get(peer_fp))?;
        let secret = server_seal::session_mailbox_secret(&own.kem_sk_x25519, &peer.kem_pubkey_x25519, own_fp, peer_fp).ok()?;
        Some((key_bound_mailbox_id(&secret)?, secret))
    }

    /// The `MailboxProof` of `mailbox` for this enrollment at `server_id`.
    fn mailbox_proof(secret: &[u8], mailbox: &str, enrollment_id: &[u8], server_id: &str) -> Option<server_proto::MailboxProof> {
        let (signing, signing_pq) = mailbox_proof_keys(secret, mailbox)?;
        let input = server_proto::register_signing_input(mailbox, enrollment_id, server_id);
        let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
        Some(server_proto::MailboxProof {
            mailbox: mailbox.to_string(),
            pk: signing.verifying_key().to_bytes().to_vec(),
            pk_pq: signing_pq.verifying_key().encode().to_vec(),
            sig: signing.sign(&input).to_bytes().to_vec(),
            sig_pq: sig_pq.encode().to_vec(),
        })
    }

    /// `Register` for `add`, with a proof for each ID of `prove` (at most `MAX_REGISTER_PROOFS`; the server asks
    /// again for the rest).
    fn send_register(&mut self, server_id: &str, peer_id: PeerId, mut add: Vec<String>, drop: Vec<String>, prove: &[String]) {
        let enrollment_id = self.servers.iter().find(|s| s.server_id == server_id).and_then(|s| s.enrollment_id.clone());
        let proofs: Vec<server_proto::MailboxProof> = match &enrollment_id {
            // Mailbox secrets are fetched only when there is something to prove.
            Some(eid) if !prove.is_empty() => {
                let mut secrets: HashMap<String, Vec<u8>> =
                    self.own_server_mailboxes().into_iter().map(|(id, (secret, _))| (id, secret)).collect();
                secrets.extend(crate::call::relay_listen_keys().into_iter().filter_map(|k| Some((key_bound_mailbox_id(&k)?, k))));
                prove.iter()
                    .take(server_proto::MAX_REGISTER_PROOFS)
                    .filter_map(|id| Self::mailbox_proof(secrets.get(id)?, id, eid, server_id))
                    .collect()
            }
            _ => Vec::new(),
        };
        // An ID that needs a proof and got none (over the cap, or no longer our mailbox) waits for the next sweep.
        // Sent bare, the server would ask for the proof again, endlessly.
        add.retain(|id| !prove.contains(id) || proofs.iter().any(|p| &p.mailbox == id));
        if add.is_empty() && drop.is_empty() {
            return;
        }
        info!("Sunucuya kutu kaydı: +{} -{} (kanıt: {})", add.len(), drop.len(), proofs.len());
        let (ids, dropped) = (add.clone(), drop.clone());
        if let Some(id) = self.send_server_request(peer_id, ServerRequest::Register { add, drop, proofs }) {
            self.server_inflight.insert(id, ServerInflight::Register { server_id: server_id.to_string(), ids, dropped });
        }
    }

    // -----------------------------------------------------------------
    // Sending
    // -----------------------------------------------------------------

    /// Tries to deposit the envelope to every server that is routing and connected.
    ///
    /// `true` means it was deposited to at least one server (the RPC is queued). The caller (`try_publish_raw`)
    /// counts that as sent. The end-to-end guarantee is still the peer's `Ack`.
    pub(crate) fn try_server_deposit(
        &mut self,
        target_fp: &str,
        topic: &str,
        envelope: &NetworkEnvelope,
        bytes: &[u8],
        first_attempt_at: u64,
    ) -> bool {
        if self.servers.is_empty() {
            return false;
        }
        // A first-contact topic names only the public fingerprint. Its mailbox ID needs the pairing secret we hold
        // for the target. With no secret there is no server path (gossip and the direct path still apply).
        //
        // Everything sent to that mailbox (Handshake, IdentityExchange, and a Message before a session exists) is
        // sealed with that secret and, when the target's device record is known, to its KEM keys. The server sees
        // no first-contact identity metadata. A session mailbox is sealed with the session's root key. Otherwise the
        // header's `sender_device_fingerprint` would be readable on the server.
        let sealed = if topic.starts_with("p2p_msg_") {
            let Some(secret) = self.first_contact_secret_for(target_fp) else { return false };
            let mailbox = server_seal::first_contact_mailbox_id(&secret, target_fp);
            let kem = self.known_remote_devices.get(target_fp)
                .filter(|d| d.kem_pubkey_x25519.len() == 32 && d.kem_pubkey_mlkem.len() == 1568)
                .map(|d| (d.kem_pubkey_x25519.as_slice(), d.kem_pubkey_mlkem.as_slice()));
            server_seal::seal_first_contact(&secret, &mailbox, kem, bytes).map(|s| (mailbox, s))
        } else {
            // Only a `Message` goes to a session topic (see `try_publish_raw_via`).
            let NetworkEnvelope::Message(m) = envelope else { return false };
            let Some((mailbox, _)) = self.session_mailbox(target_fp) else { return false };
            let root = self.ratchets.get(target_fp).map(|r| match &r.prev_root_key {
                Some(prev) if m.header.rotation_kyber_ciphertext.is_some() => prev.clone(),
                _ => r.root_handle_now(),
            });
            match root {
                Some(root_key) => server_seal::seal_envelope(&root_key, &mailbox, &m.header.sender_device_fingerprint, bytes).map(|s| (mailbox, s)),
                None => Err("oturum anahtarı yok".to_string()),
            }
        };
        let (mailbox, sealed) = match sealed {
            Ok(v) => v,
            Err(e) => {
                warn!("Zarf mühürlenemedi, sunucu atlanıyor: {}", e);
                return false;
            }
        };

        if sealed.len() > MAX_DEPOSIT_BYTES {
            // Wire cap (see `MAX_DEPOSIT_BYTES`). It is better not to try and to fall back to gossip than to send a
            // silently truncated, corrupt packet.
            warn!("Zarf sunucu tavanını aşıyor ({} bayt), gossipsub'a bırakılıyor", sealed.len());
            return false;
        }

        // See `SERVER_DEPOSIT_BACKOFF_MS`. A server that refused a deposit for quota or rate reasons gets no new
        // deposits for a while. Otherwise every poll turn would produce the same error, a busy loop.
        let now_ms = mono_ms();
        let candidates: Vec<String> = self
            .servers
            .iter()
            .filter(|s| s.route_messages)
            .filter(|s| {
                self.server_rt
                    .get(&s.server_id)
                    .map(|r| r.connected && r.enrolled && now_ms >= r.deposit_backoff_until
                        // The server's own item limit. Over it the answer is TooLarge, which used to back off
                        // every deposit.
                        && r.limits.as_ref().map_or(true, |l| sealed.len() as u64 <= l.max_item_bytes as u64))
                    .unwrap_or(false)
            })
            // "Not on this server" and "mailbox full here" are remembered per server, so one server's answer does not
            // close the others.
            .filter(|s| {
                self.server_unknown_mailboxes
                    .get(&(s.server_id.clone(), mailbox.clone()))
                    .map_or(true, |until| now_ms >= *until)
            })
            .map(|s| s.server_id.clone())
            .collect();
        if candidates.is_empty() {
            // Once a minute. Every retry of every pending packet comes through here.
            static LAST_LOG_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            if now_ms.saturating_sub(LAST_LOG_MS.load(std::sync::atomic::Ordering::Relaxed)) >= 60_000 {
                LAST_LOG_MS.store(now_ms, std::sync::atomic::Ordering::Relaxed);
                info!(
                    "Sunucu atlandı (bu kutu için bağlı+kayıtlı sunucu yok; {} yapılandırılmış)",
                    self.servers.len()
                );
            }
            return false;
        }

        // A `Message` ID is per mailbox. A group text goes to every member under one ID, and the second member's
        // copy was skipped as already done.
        let dedup_key = match envelope {
            NetworkEnvelope::Message(_) => format!("{}|{}", mailbox, deposit_dedup_key(envelope, bytes)),
            _ => deposit_dedup_key(envelope, bytes),
        };
        let mut any = false;
        for server_id in candidates {
            // Already on this server's disk: re-deposit (see `P2PCore.server_deposited`). We still count it as
            // deposited. For the caller the result is the same, and the envelope is on the server.
            if self.already_deposited(&server_id, &dedup_key) {
                any = true;
                continue;
            }
            let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { continue };
            let req = ServerRequest::Deposit { mailbox: mailbox.clone(), sealed: sealed.clone() };
            // The envelope TYPE goes into the log. Without it, a loop of the same two envelopes being deposited
            // forever cannot be traced. On a real device this happened, and the type had to be guessed (handshake?
            // IdentityExchange? DeviceAddNotice?).
            info!(
                "Sunucuya bırakılıyor: kutu={} bayt={} tür={}",
                mailbox_log_id(&mailbox),
                sealed.len(),
                envelope_kind(envelope)
            );
            if let Some(id) = self.send_server_request(peer_id, req) {
                // Mark NOW, before the reply. The reply over Tor takes seconds, and in that window
                // `awaiting_confirmation` deposited the same envelope again (measured on a device: the same message_id
                // twice, 5.7 s apart). If the deposit fails, `handle_server_failure` reverts the mark. The mark is now
                // independent of the envelope type (see `deposit_dedup_key`).
                self.note_server_deposit(&server_id, &dedup_key);
                self.server_inflight.insert(
                    id,
                    ServerInflight::Deposit {
                        server_id,
                        mailbox: mailbox.clone(),
                        envelope: envelope.clone(),
                        target_fp: target_fp.to_string(),
                        first_attempt_at,
                        dedup_key: dedup_key.clone(),
                        cancelled: false,
                    },
                );
                any = true;
            }
        }
        any
    }

    /// See `P2PCore.server_deposited`. Records a successful deposit and bounds the map.
    pub(crate) fn note_server_deposit(&mut self, server_id: &str, dedup_key: &str) {
        let now = current_time_ms();
        self.server_deposited.insert((server_id.to_string(), dedup_key.to_string()), now);
        if self.server_deposited.len() > MAX_SERVER_DEPOSIT_MEMORY {
            self.server_deposited
                .retain(|_, t| now.saturating_sub(*t) < SERVER_DEPOSIT_MEMORY_MS);
            // If still full (all entries recent), drop the oldest.
            if self.server_deposited.len() > MAX_SERVER_DEPOSIT_MEMORY {
                let mut by_age: Vec<((String, String), u64)> =
                    self.server_deposited.iter().map(|(k, v)| (k.clone(), *v)).collect();
                by_age.sort_by_key(|(_, t)| *t);
                let drop_count = by_age.len() - MAX_SERVER_DEPOSIT_MEMORY;
                for (k, _) in by_age.into_iter().take(drop_count) {
                    self.server_deposited.remove(&k);
                }
            }
        }
    }

    /// Has this envelope already been deposited to this server recently?
    fn already_deposited(&self, server_id: &str, dedup_key: &str) -> bool {
        let key = (server_id.to_string(), dedup_key.to_string());
        self.server_deposited
            .get(&key)
            .map(|t| current_time_ms().saturating_sub(*t) < SERVER_DEPOSIT_MEMORY_MS)
            .unwrap_or(false)
    }

    /// Forgets the "already deposited to this server" memory for a `message_id`.
    ///
    /// `already_deposited`
    /// looked only at `message_id`, not at the ciphertext. A regenerated copy (see `retry_unconfirmed_messages` and
    /// `regen_pending_for_peer`) keeps the SAME `message_id` but has a COMPLETELY NEW ciphertext. The old memory
    /// therefore blocked that fresh copy from the server for 12 hours (see `SERVER_DEPOSIT_MEMORY_MS`). The server,
    /// where the recipient could reach it while offline, kept only the OLD copy, which could no longer be decrypted
    /// after a ratchet rotation. The fresh copy went only over gossip, which fails when the recipient is offline.
    /// Clearing the memory on regeneration lets the new ciphertext reach the mailbox. If the recipient gets both
    /// copies, `message_exists_with_id` deduplicates them.
    ///
    /// When a user cancels a pending message, the server copy is also WITHDRAWN.
    /// Before, cancel cleared only the local queue. If the packet had been deposited, it stayed on the server for
    /// 30 days while the recipient was offline and was eventually delivered. So "I changed my mind" had no effect.
    /// The server deletes only the row where `depositor == us`, so this path cannot be used to delete someone else's mail.
    pub(crate) fn cancel_server_deposit(&mut self, message_id: &str) {
        // No location yet for a Deposit still in flight: flag it, and the `Deposited` arm withdraws it.
        for inflight in self.server_inflight.values_mut() {
            if let ServerInflight::Deposit { envelope: NetworkEnvelope::Message(m), cancelled, .. } = inflight {
                if m.header.message_id == message_id {
                    *cancelled = true;
                }
            }
        }
        // Keyed `(server, "mailbox|message_id")`: one entry per target.
        let targets: Vec<(String, String, String, u64)> = self
            .server_deposit_locations
            .iter()
            .filter(|((_, key), _)| location_message_id(key) == message_id)
            .map(|((sid, key), (mailbox, seq))| (sid.clone(), key.clone(), mailbox.clone(), *seq))
            .collect();
        for (server_id, key, mailbox, seq) in targets {
            self.server_deposit_locations.remove(&(server_id.clone(), key));
            let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { continue };
            let req = ServerRequest::Cancel { mailbox, seqs: vec![seq] };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(id, ServerInflight::Cancel { server_id });
            }
        }
    }

    /// Only the "already deposited" marks: the old copy is still on the server, and a cancel must still find it.
    pub(crate) fn forget_server_deposit(&mut self, message_id: &str) {
        self.server_deposited.retain(|(_, key), _| location_message_id(key) != message_id);
    }

    fn send_server_request(&mut self, peer: PeerId, req: ServerRequest) -> Option<request_response::OutboundRequestId> {
        let swarm = self.swarm.as_mut()?;
        Some(swarm.behaviour_mut().server_rpc.send_request(&peer, req))
    }

    // -----------------------------------------------------------------
    // Periodic scan
    // -----------------------------------------------------------------

    /// Connection, registration, subscription and fetch upkeep. `poll_events` calls it every turn and it checks
    /// its own interval (the `reconnect_sweep` pattern).
    pub(crate) fn server_sweep(&mut self) {
        if self.servers.is_empty() {
            return;
        }
        // The head upload's `.enc` hash finished on its thread: only the blob path continues. A forced full sweep
        // each turn did a Register diff, a fetch and archive checks for the whole wait.
        let hashed = self.server_blob_uploads.first()
            .filter(|u| u.hashing.as_ref().is_some_and(|c| c.get().is_some()))
            .and_then(|u| u.server_id.clone());
        if let Some(sid) = hashed {
            if let Some(peer_id) = self.server_rt.get(&sid).and_then(|r| r.peer_id) {
                self.server_flush_blobs(&sid, peer_id);
            }
        }
        // Radio saver (see `RADIO_WINDOW_MS`): only inside the window. New mail still arrives at once as server push
        // over the open connection. `server_sweep_at == 0` means "sweep now" (more mail in the batch, a chunk acked,
        // just connected). The radio is up for that exchange anyway, and waiting cost one whole window per step.
        if !self.radio_window_open && self.server_sweep_at != 0 {
            return;
        }
        let now = mono_ms();
        if now < self.server_sweep_at {
            return;
        }
        self.server_sweep_at = now + SERVER_SWEEP_INTERVAL_MS;
        self.server_unknown_mailboxes.retain(|_, until| now < *until);
        self.resume_archive_rotation();
        self.maybe_archive_backfill();

        // Self-check fix: `server_deposit_locations` was pruned nowhere. Entries were removed only on cancel (`cancel_server_deposit`) or refresh
        // (`forget_server_deposit`), so every normally acknowledged message left an entry behind and the map grew without bound for the life of the
        // process.
        //
        // An entry is only useful while the message is still awaiting confirmation (the only thing a cancel can withdraw). So the rule is simple:
        // drop every entry whose message is not in `awaiting_confirmation`.
        if !self.server_deposit_locations.is_empty() {
            let before = self.server_deposit_locations.len();
            let pending: std::collections::HashSet<String> =
                self.awaiting_confirmation.keys().cloned().collect();
            self.server_deposit_locations.retain(|(_, key), _| pending.contains(location_message_id(key)));
            let dropped = before - self.server_deposit_locations.len();
            if dropped > 0 {
                info!("Sunucu yatırma konumu kaydından {} bayat girdi temizlendi", dropped);
            }
        }

        // Only what the loop reads. A full clone carried both enrollment secret keys through every sweep.
        struct Sweep { server_id: String, address: String, route_messages: bool, store_history: bool, no_creds: bool }
        let records: Vec<Sweep> = self
            .servers
            .iter()
            .map(|s| Sweep {
                server_id: s.server_id.clone(),
                address: s.address.clone(),
                route_messages: s.route_messages,
                store_history: s.store_history,
                no_creds: s.enrollment_id.is_none() && s.token.is_empty(),
            })
            .collect();
        // The same for every server: built once, not per server and per step.
        let own_ids: HashSet<String> = self.own_server_mailboxes().into_keys().collect();
        let mut blobs_flushed = false;
        for rec in records {
            let rt = self.server_rt.entry(rec.server_id.clone()).or_default();
            if rt.peer_id.is_none() {
                rt.peer_id = rec
                    .address
                    .split(',')
                    .filter_map(|a| a.trim().parse::<Multiaddr>().ok())
                    .find_map(|a| extract_peer_id(&a));
            }
            let Some(peer_id) = rt.peer_id else { continue };
            let connected = rt.connected;
            let enrolled = rt.enrolled;
            // Doubles up to 30 min while the server keeps refusing us.
            let hello_stale = now.saturating_sub(rt.hello_sent_at)
                > (SERVER_SWEEP_INTERVAL_MS << rt.hello_attempts.min(7)).min(30 * 60 * 1000);
            // Nothing to enroll with, and the server already said no once.
            let no_credentials = rec.no_creds && rt.last_error.is_some();

            // Ask the swarm: the event-driven `rt.connected` flag may have been missed (see `load_servers_from_db`:
            // if `peer_id` is filled late, `note_server_connection` cannot match it). Redialing a missed connection
            // does NOT help, because libp2p is already connected and raises no new event. So the truth is read from
            // the swarm on every turn.
            let really_connected =
                self.swarm.as_ref().map(|s| s.is_connected(&peer_id)).unwrap_or(false);
            if really_connected && !connected {
                if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                    rt.connected = true;
                }
            }
            let connected = connected || really_connected;

            if !connected {
                // Offline server: back off 15 s, doubling to 30 min. Without it, every sweep (every 15 s) was one more failed onion lookup, and the
                // CPU never idled (measured: 35 dials in 11 minutes on Wi-Fi).
                let Some(rt) = self.server_rt.get_mut(&rec.server_id) else { continue };
                // A legacy record holding only private-network addresses: the server path is onion-only, so do not dial the LAN.
                let addrs = server_proto::public_server_addrs(rec.address.split(','));
                if addrs.is_empty() {
                    rt.last_error = Some("No reachable address. Add the server again with a new invite code".to_string());
                    continue;
                }
                if now < rt.dial_backoff_until { continue; }
                rt.dial_backoff_until = now + (SERVER_SWEEP_INTERVAL_MS << rt.dial_attempts.min(7)).min(30 * 60 * 1000);
                rt.dial_attempts += 1;
                // Not connected: dial EVERY known address at once (see `ServerRecord.address`).
                for a in addrs.iter().filter_map(|a| a.parse::<Multiaddr>().ok()) {
                    self.dial_with_relay_fallback(peer_id, Some(a));
                }
                continue;
            }
            if !enrolled {
                // One enrollment exchange at a time. A second `Welcome` replaced the challenge that the first `Enroll`
                // was signed over.
                let enrolling = self.server_inflight.values().any(|i| {
                    matches!(i, ServerInflight::Hello { .. } | ServerInflight::Enroll { .. } | ServerInflight::Rebind { .. })
                        && i.server_id() == rec.server_id
                });
                if hello_stale && !no_credentials && !enrolling {
                    if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                        rt.hello_sent_at = now;
                        rt.hello_attempts += 1;
                    }
                    if let Some(id) =
                        self.send_server_request(peer_id, ServerRequest::Hello { version: SERVER_PROTOCOL_VERSION })
                    {
                        self.server_inflight.insert(id, ServerInflight::Hello { server_id: rec.server_id.clone() });
                    }
                }
                continue;
            }

            // Registered: send the subscription difference.
            // A server that only stores history gets no mailbox IDs (it would learn one per conversation), and it is
            // not polled for mail that cannot arrive there. The relay addresses of a running call go to every server:
            // any of them may carry the media, and nothing is stored under them.
            let relay_ids: Vec<String> =
                crate::call::relay_listen_keys().iter().filter_map(|k| key_bound_mailbox_id(k)).collect();
            let mut wanted: HashSet<String> = if rec.route_messages { own_ids.clone() } else { HashSet::new() };
            wanted.extend(relay_ids.iter().cloned());
            if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                // A refusal is not permanent: try again after a while.
                if !rt.refused.is_empty() && now >= rt.refused_retry_at {
                    rt.refused.clear();
                }
                wanted.retain(|id| !rt.refused.contains(id));
            }
            // The server refuses a whole list over its mailbox cap. Over it, the relay IDs and then a stable part of
            // the rest are kept (no churn between sweeps). The remainder is reached over the direct path only.
            let cap = self.server_rt.get(&rec.server_id).map_or(1, Self::mailbox_cap);
            let over_cap = wanted.len() > cap;
            if over_cap {
                let total = wanted.len();
                let mut ids: Vec<String> = wanted.into_iter().collect();
                ids.sort_by_key(|id| (!relay_ids.contains(id), id.clone()));
                ids.truncate(cap);
                wanted = ids.into_iter().collect();
                warn!("Sunucu kutu sınırı aşıldı: {} > {} ({})", total, cap, crate::log_id(&rec.server_id));
            }
            if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                let ours = rt.last_error.as_deref().map_or(false, |e| e.starts_with(TOO_MANY_MAILBOXES));
                if over_cap {
                    rt.last_error = Some(format!("{TOO_MANY_MAILBOXES} ({cap}): some chats use the direct path only"));
                } else if ours && rt.refused.is_empty() {
                    rt.last_error = None;
                }
            }
            let (current, register_ok) = self.server_rt.get(&rec.server_id)
                .map(|r| (r.registered.clone(), now >= r.register_backoff_until)).unwrap_or_default();
            let mut add: Vec<String> = wanted.difference(&current).cloned().collect();
            let mut drop: Vec<String> = current.difference(&wanted).cloned().collect();
            add.truncate(cap);
            drop.truncate(cap);
            let register_inflight = self.server_inflight.values()
                .any(|i| matches!(i, ServerInflight::Register { server_id, .. } if *server_id == rec.server_id));
            if register_ok && !register_inflight && (!add.is_empty() || !drop.is_empty()) {
                // A relay address is new with each call, so its proof goes with the first request. The other IDs are
                // mostly ones this enrollment already reads, and the server names the rest (`Registered.proof_needed`).
                let prove: Vec<String> = add.iter().filter(|id| relay_ids.contains(id)).cloned().collect();
                self.send_register(&rec.server_id, peer_id, add, drop, &prove);
            }

            // Safety pull, in case the push was lost.
            let due = self.server_rt.get(&rec.server_id).map(|r| r.fetch_due_at).unwrap_or(0);
            if rec.route_messages && now >= due {
                self.server_fetch(&rec.server_id, peer_id, &own_ids);
            }

            if rec.store_history {
                self.purge_retired_archive(&rec.server_id, peer_id);
                self.server_flush_archive(&rec.server_id, peer_id);
            }
            // One upload server per sweep: the first ready one that routes.
            if rec.route_messages && !blobs_flushed {
                blobs_flushed = true;
                self.server_flush_blobs(&rec.server_id, peer_id);
            }
        }
    }

    fn server_fetch(&mut self, server_id: &str, peer_id: PeerId, own_ids: &HashSet<String>) {
        // Nothing is taken before the storage keys are loaded: a fetched item would wait in `deferred_incoming`,
        // where it can be evicted. Nor while fetched mail waits for its rate budget: the backlog stays one batch.
        if !self.storage_keys_ready() || self.server_mail_deferred() {
            return;
        }
        // If a `Fetch` is already in flight, do not send a second one (see `ServerRuntime.fetch_inflight`).
        if self.server_rt.get(server_id).map(|r| r.fetch_inflight).unwrap_or(false) {
            return;
        }
        // Cursors of mailboxes that are no longer ours (a deleted session or contact).
        let stale: Vec<(String, String)> = self
            .server_cursors
            .keys()
            .filter(|(sid, mb)| sid == server_id && !own_ids.contains(mb))
            .cloned()
            .collect();
        for key in stale {
            self.server_cursors.remove(&key);
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1 AND mailbox_id = ?2", params![key.0, key.1]);
            }
        }
        // The same stable part `server_sweep` registers when over the cap. Refused IDs are skipped there too, or a
        // registered ID past them fell out of every `Fetch`.
        let (cap, refused) = self.server_rt.get(server_id).map_or((1, HashSet::new()), |rt| (Self::mailbox_cap(rt), rt.refused.clone()));
        let mut ids: Vec<&String> = own_ids.iter().filter(|id| !refused.contains(*id)).collect();
        ids.sort();
        ids.truncate(cap);
        let cursors: Vec<(String, u64)> = ids
            .into_iter()
            .map(|mb| {
                let seq = self.server_cursors.get(&(server_id.to_string(), mb.clone())).copied().unwrap_or(0);
                (mb.clone(), seq)
            })
            .collect();
        if cursors.is_empty() {
            return;
        }
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.fetch_due_at = mono_ms() + SERVER_FETCH_SWEEP_INTERVAL_MS;
        }
        let req = ServerRequest::Fetch {
            cursors,
            max_items: MAX_FETCH_BATCH_ITEMS,
            max_bytes: MAX_FETCH_BATCH_BYTES,
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::Fetch { server_id: server_id.to_string() });
            // Set only for a request that actually went out. Set before a failed send, it stayed true, and nothing was
            // fetched until the next reconnect.
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.fetch_inflight = true;
            }
        }
    }

    /// The server's mailbox cap (from the `Welcome`/`Enrolled` limits, or the protocol default before those). A longer
    /// list is refused whole.
    fn mailbox_cap(rt: &ServerRuntime) -> usize {
        rt.limits.as_ref().map_or_else(|| ServerLimits::default().max_mailboxes, |l| l.max_mailboxes).max(1) as usize
    }

    /// Acks what the batches of earlier calls brought, once that mail has gone through `process_incoming_envelope`.
    /// `poll_events` calls this after its incoming loop. `drive_server_sync` calls it too, for the turns before.
    /// Acked before processing, a crash in between would lose the only copy.
    pub(crate) fn commit_server_fetches(&mut self) {
        // Fetched mail still waits for its rate budget. Acked now, a crash before it is processed would lose it.
        if self.server_mail_deferred() {
            return;
        }
        let now = mono_ms();
        // This turn's items were processed. Failures were reported (`server_item_failed`). Held and passed items that
        // the cursor went past are done.
        let cursors = &self.server_cursors;
        // Items still deferred (keys not ready) keep their record, so a later failure can still hold them
        // (`server_item_failed`).
        let deferred: std::collections::HashSet<[u8; 32]> =
            self.deferred_incoming.iter().filter(|(s, _)| s.is_none()).map(|(_, r)| Sha256::digest(r).into()).collect();
        for (sid, rt) in self.server_rt.iter_mut() {
            rt.taken.retain(|d, _| deferred.contains(d));
            let below = |mb: &String, seq: u64| cursors.get(&(sid.clone(), mb.clone())).map_or(true, |c| *c < seq);
            rt.held.retain(|mb, (seq, _)| below(mb, *seq));
            rt.passed.retain(|(mb, seq)| below(mb, *seq));
        }
        let due: Vec<String> = self
            .server_rt
            .iter()
            .filter(|(_, rt)| !rt.unacked.is_empty() && rt.connected && rt.enrolled && now >= rt.ack_retry_at)
            .map(|(sid, _)| sid.clone())
            .collect();
        for sid in due {
            // One Ack in flight per server: a late `Ok` cannot persist an older position after a newer one.
            if self.server_inflight.values().any(|i| matches!(i, ServerInflight::Ack { .. }) && i.server_id() == sid) {
                continue;
            }
            let Some(rt) = self.server_rt.get_mut(&sid) else { continue };
            let Some(peer_id) = rt.peer_id else { continue };
            let cap = Self::mailbox_cap(rt);
            let keys: Vec<String> = rt.unacked.keys().take(cap).cloned().collect();
            let acks: Vec<(String, u64)> = keys.into_iter().filter_map(|k| rt.unacked.remove_entry(&k)).collect();
            match self.send_server_request(peer_id, ServerRequest::Ack { acks: acks.clone() }) {
                Some(id) => {
                    self.server_inflight.insert(id, ServerInflight::Ack { server_id: sid, acks });
                }
                None => self.restage_acks(&sid, acks),
            }
        }
    }

    /// An `Ack` that did not go through: retry after one sweep interval.
    fn restage_acks(&mut self, server_id: &str, acks: Vec<(String, u64)>) {
        let Some(rt) = self.server_rt.get_mut(server_id) else { return };
        for (mailbox, seq) in acks {
            let e = rt.unacked.entry(mailbox).or_insert(0);
            *e = (*e).max(seq);
        }
        rt.ack_retry_at = mono_ms() + SERVER_SWEEP_INTERVAL_MS;
    }

    /// `seq` of `mailbox` did not open, or failed to process. `true`: it holds the mailbox's cursor (not acked, so
    /// the server keeps it). `false`: it has failed for `SERVER_HOLD_GRACE_MS` and is passed over for good.
    pub(crate) fn hold_server_item(&mut self, server_id: &str, mailbox: &str, seq: u64, now: u64) -> bool {
        let Some(rt) = self.server_rt.get_mut(server_id) else { return false };
        let e = rt.held.entry(mailbox.to_string()).or_insert((seq, now));
        // A lower item holds the cursor: this one waits behind it and must not restart that item's timer. Otherwise
        // two failing items would keep resetting each other.
        if seq > e.0 {
            return true;
        }
        if seq < e.0 {
            *e = (seq, now);
        }
        if now.saturating_sub(e.1) < SERVER_HOLD_GRACE_MS {
            return true;
        }
        warn!("Sunucu öğesi {} dk açılamadı/işlenemedi, atlanıyor (kutu={})", SERVER_HOLD_GRACE_MS / 60_000, mailbox_log_id(mailbox));
        rt.held.remove(mailbox);
        rt.passed.insert((mailbox.to_string(), seq));
        false
    }

    /// 5 min, doubling to 30 min while the server keeps refusing or not answering deposits. A `Deposited` resets it.
    fn back_off_deposits(rt: &mut ServerRuntime) {
        rt.deposit_backoff_until = mono_ms()
            + (SERVER_DEPOSIT_BACKOFF_MS << rt.deposit_failures.min(3)).min(SERVER_DEPOSIT_BACKOFF_MAX_MS);
        rt.deposit_failures = rt.deposit_failures.saturating_add(1);
    }

    /// A fetch soon for a held item, not at the next safety sweep.
    fn refetch_held(&mut self, server_id: &str, now: u64) {
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.fetch_due_at = rt.fetch_due_at.min(now + SERVER_HOLD_REFETCH_MS);
        }
    }

    /// `process_incoming_envelope` failed on a fetched item (`raw`, as handed to `incoming`). Its mailbox's cursor
    /// goes back before it, so this turn's Ack does not let the server delete it. It is fetched again
    /// (`hold_server_item`). `poll_events` calls this for each `Err` of a packet with no source peer.
    pub(crate) fn server_item_failed(&mut self, raw: &[u8]) {
        let digest: [u8; 32] = Sha256::digest(raw).into();
        let found = self.server_rt.iter_mut().find_map(|(sid, rt)| rt.taken.remove(&digest).map(|t| (sid.clone(), t)));
        let Some((server_id, (mailbox, seq))) = found else { return };
        let now = mono_ms();
        if !self.hold_server_item(&server_id, &mailbox, seq, now) {
            return;
        }
        let key = (server_id.clone(), mailbox.clone());
        if let Some(c) = self.server_cursors.get_mut(&key) {
            *c = (*c).min(seq - 1);
        }
        if let Some(rt) = self.server_rt.get_mut(&server_id) {
            if let Some(e) = rt.unacked.get_mut(&mailbox) {
                *e = (*e).min(seq - 1);
            }
        }
        self.refetch_held(&server_id, now);
    }

    // -----------------------------------------------------------------
    // Event processing
    // -----------------------------------------------------------------

    /// Called after the `poll_events` swarm borrow is released.
    ///
    /// `incoming`: envelopes fetched from the server are added HERE and go through the normal incoming path
    /// (`process_incoming_envelope`). Signature checks, the `sender_identity_id` binding check, early-packet
    /// buffering and `Ack` generation are reused as they are.
    pub(crate) fn drive_server_sync(
        &mut self,
        events: Vec<ServerEventLocal>,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) -> Vec<(request_response::ResponseChannel<ServerResponse>, ServerResponse)> {
        // What earlier calls staged was processed in their turn: ack it now, even if the caller's own
        // `commit_server_fetches` did not run.
        self.commit_server_fetches();
        let mut replies = Vec::new();
        for evt in events {
            match evt {
                ServerEventLocal::Request { peer, request, channel } => {
                    let resp = self.handle_server_push(peer, request, incoming);
                    replies.push((channel, resp));
                }
                ServerEventLocal::Response { request_id, response } => {
                    if let Some(inflight) = self.server_inflight.remove(&request_id) {
                        self.handle_server_response(inflight, response, incoming);
                    }
                }
                ServerEventLocal::OutboundFailure { request_id } => {
                    if let Some(inflight) = self.server_inflight.remove(&request_id) {
                        self.handle_server_failure(inflight);
                    }
                }
            }
        }
        replies
    }

    /// The only valid request from a server: `Notify`.
    fn handle_server_push(
        &mut self,
        peer: PeerId,
        request: ServerRequest,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) -> ServerResponse {
        match request {
            // The item itself (see `ServerRequest::Push`): run it through the exact `Fetch` path (opening, cursor,
            // ack) as a one-item batch.
            ServerRequest::Push { item } => {
                let sid = self
                    .server_rt
                    .iter()
                    .find(|(_, rt)| rt.peer_id == Some(peer))
                    .map(|(sid, _)| sid.clone());
                let Some(server_id) = sid else {
                    return ServerResponse::Err(ServerErrorCode::BadDirection);
                };
                // Only from a server we are enrolled at, and only once the storage keys are loaded (see `server_fetch`).
                // Otherwise the item stays on the server and comes with the next `Fetch`.
                let enrolled = self.server_rt.get(&server_id).map_or(false, |rt| rt.enrolled);
                if !enrolled {
                    return ServerResponse::Ok;
                }
                if !self.storage_keys_ready() {
                    return self.handle_server_push(peer, ServerRequest::Notify, incoming);
                }
                // 30 per 5 s. Each push costs an open, the processing and an Ack. Over that, the item is left on the
                // server and the push counts as a `Notify` (one fetch per 5 s).
                let now = mono_ms();
                let over = self.server_rt.get_mut(&server_id).map_or(true, |rt| {
                    if now.saturating_sub(rt.push_window_at) >= 5_000 {
                        rt.push_window_at = now;
                        rt.push_count = 0;
                    }
                    rt.push_count += 1;
                    rt.push_count > 30
                });
                if over {
                    return self.handle_server_push(peer, ServerRequest::Notify, incoming);
                }
                // A mailbox held before an earlier item takes its later items in order, from the held item's refetch
                // (not at once: see `SERVER_HOLD_REFETCH_MS`).
                let behind = self.server_rt.get(&server_id)
                    .and_then(|rt| rt.held.get(&item.mailbox_id))
                    .map_or(false, |&(held, _)| item.seq > held);
                if behind {
                    self.refetch_held(&server_id, now);
                    return ServerResponse::Ok;
                }
                // The batch path clears `fetch_inflight`. A real `Fetch` may still be out, so keep its flag.
                let inflight = self.server_rt.get(&server_id).map_or(false, |rt| rt.fetch_inflight);
                self.handle_server_response(
                    ServerInflight::Fetch { server_id: server_id.clone() },
                    ServerResponse::Batch { items: vec![item], more: false },
                    incoming,
                );
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.fetch_inflight = inflight;
                }
                ServerResponse::Ok
            }
            ServerRequest::Notify => {
                // The payload is NOT carried here. We only say "fetch it on the next turn", so the cursor logic stays intact.
                let sid = self
                    .server_rt
                    .iter()
                    .find(|(_, rt)| rt.peer_id == Some(peer))
                    .map(|(sid, _)| sid.clone());
                // One per 5 s. Each `Notify` opens the radio window and forces a sweep, so a server sending them in a row
                // kept the phone fetching without end. A second one within that time is covered by the fetch the first one started.
                let now = mono_ms();
                let sid = sid.filter(|sid| {
                    self.server_rt.get_mut(sid).map_or(false, |rt| {
                        let ok = now.saturating_sub(rt.notified_at) >= 5_000;
                        if ok { rt.notified_at = now; }
                        ok
                    })
                });
                if let Some(sid) = sid {
                    if let Some(rt) = self.server_rt.get_mut(&sid) {
                        rt.fetch_due_at = 0;
                    }
                    self.server_sweep_at = 0;
                    // The radio is up for this push anyway: open the saver window now, so the `Fetch` rides it
                    // (`RADIO_WINDOW_MS`).
                    self.radio_window_at = 0;
                }
                ServerResponse::Ok
            }
            // A "server" trying to deposit mail or open mailboxes on us is using the protocol wrongly.
            _ => ServerResponse::Err(ServerErrorCode::BadDirection),
        }
    }

    /// A new enrollment (a reset server numbers its mail from 1 again): old cursors would skip every new item for good.
    fn forget_server_cursors(&mut self, server_id: &str) {
        self.server_cursors.retain(|(sid, _), _| sid != server_id);
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.unacked.clear();
            rt.refused.clear();
            rt.registered.clear();
            rt.held.clear();
            rt.passed.clear();
        }
        // Its mail is gone with the old enrollment: deposit again.
        self.server_deposited.retain(|(sid, _), _| sid != server_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1", params![server_id]);
        }
    }

    fn handle_server_response(
        &mut self,
        inflight: ServerInflight,
        response: ServerResponse,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) {
        match (inflight, response) {
            // --- Hello ---
            (ServerInflight::Hello { server_id }, ServerResponse::Welcome { version, challenge, enrolled, enrollment_id, limits, server_name }) => {
                let Some(mut rec) = self.servers.iter().find(|s| s.server_id == server_id).cloned() else { return };
                if version != SERVER_PROTOCOL_VERSION {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        // Says which side is behind.
                        rt.last_error = Some(if version < SERVER_PROTOCOL_VERSION {
                            format!("Server protocol {version}, this app speaks {SERVER_PROTOCOL_VERSION}: update the server")
                        } else {
                            format!("Server protocol {version}, this app speaks {SERVER_PROTOCOL_VERSION}: update this app")
                        });
                    }
                    return;
                }
                // The server's id for our enrollment, taken only when we have none, or still hold an invite token (the
                // `Enrolled` answer of that enrollment was lost). A different id is not adopted: it would wipe every cursor
                // on each Hello and let the server choose the id our proofs are made over. A reset server does not know
                // us and answers `enrolled: false`.
                let adopted = match enrollment_id {
                    Some(id) if enrolled && rec.enrollment_id.as_ref() != Some(&id)
                        && (rec.enrollment_id.is_none() || !rec.token.is_empty()) => {
                        rec.enrollment_id = Some(id);
                        true
                    }
                    _ => false,
                };
                if adopted {
                    self.forget_server_cursors(&server_id);
                }
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.limits = Some(limits);
                    rt.enrolled = enrolled;
                    // Enrolled with no id here: the `Enrolled` answer was lost. Mailbox proofs need the id, so only a
                    // fresh invite helps.
                    rt.last_error = (enrolled && rec.enrollment_id.is_none())
                        .then(|| "Enrollment id lost. Add the server again with a new invite code".to_string());
                    if enrolled {
                        rt.hello_attempts = 0;
                    }
                }
                // Shown in the UI and stored: no control characters, bounded length.
                let server_name: String = server_name.chars().filter(|c| !c.is_control()).take(64).collect();
                let spent_token = enrolled && rec.enrollment_id.is_some() && !rec.token.is_empty();
                if (rec.name.is_empty() && !server_name.is_empty()) || spent_token || adopted {
                    if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                        r.enrollment_id = rec.enrollment_id.clone();
                        if r.name.is_empty() {
                            r.name = server_name;
                        }
                        // Not needed while the server knows us. Stored, it only waits to leak.
                        if spent_token {
                            r.token.clear();
                        }
                        let r = r.clone();
                        self.persist_server(&r);
                    }
                }
                if enrolled {
                    // The server already knows us. Trigger the scan now to refresh the subscriptions.
                    self.server_sweep_at = 0;
                    return;
                }
                self.begin_enrollment(&server_id, &challenge);
            }

            // --- Enroll / Rebind ---
            (ServerInflight::Enroll { server_id }, ServerResponse::Enrolled { enrollment_id, limits })
            | (ServerInflight::Rebind { server_id }, ServerResponse::Enrolled { enrollment_id, limits }) => {
                let mut new_enrollment = false;
                if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                    new_enrollment = r.enrollment_id.as_ref() != Some(&enrollment_id);
                    r.enrollment_id = Some(enrollment_id);
                    // The token is single use. Keeping it does no good, and leaking it does harm.
                    r.token.clear();
                    let r = r.clone();
                    self.persist_server(&r);
                }
                // A new enrollment (a reset server numbers its mail from 1 again): old cursors would skip every new
                // item for good.
                if new_enrollment {
                    self.forget_server_cursors(&server_id);
                }
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = true;
                    rt.hello_attempts = 0;
                    rt.limits = Some(limits);
                    rt.registered.clear();
                    rt.last_error = None;
                }
                info!("Sunucuya kaydolundu: {}", crate::log_id(&server_id));
                self.server_sweep_at = 0;
                // Partial downloads can continue from the server's copy.
                self.resume_incomplete_downloads_for(&std::collections::HashSet::new(), true);
            }

            // --- Register ---
            (ServerInflight::Register { server_id, ids, dropped }, ServerResponse::Ok) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    for id in ids {
                        rt.registered.insert(id);
                    }
                    // Dropped IDs were not removed before. The difference was sent as "-1" on every turn (the device
                    // showed "+0 -1" forever).
                    for id in dropped {
                        rt.registered.remove(&id);
                    }
                }
            }

            // The IDs of `ids` that the server did not name are registered. The `proof_needed` ones are sent again with
            // their proofs. The `refused` ones (cap, reader cap, a taken key) wait `SERVER_REFUSED_RETRY_MS`.
            (ServerInflight::Register { server_id, ids, dropped }, ServerResponse::Registered { proof_needed, refused }) => {
                let prove: Vec<String> = proof_needed.into_iter().filter(|id| ids.contains(id)).collect();
                let peer_id = self.server_rt.get(&server_id).and_then(|r| r.peer_id);
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    let refused: Vec<String> = refused.into_iter().filter(|id| ids.contains(id)).collect();
                    for id in ids.into_iter().filter(|id| !prove.contains(id) && !refused.contains(id)) {
                        rt.registered.insert(id);
                    }
                    for id in dropped {
                        rt.registered.remove(&id);
                    }
                    if !refused.is_empty() {
                        warn!("Sunucu {} kutuyu reddetti ({})", refused.len(), crate::log_id(&server_id));
                        rt.last_error = Some(format!("{TOO_MANY_MAILBOXES}: the server refused some, those chats use the direct path only"));
                        rt.refused.extend(refused);
                        rt.refused_retry_at = mono_ms() + SERVER_REFUSED_RETRY_MS;
                    }
                }
                if let Some(peer_id) = peer_id.filter(|_| !prove.is_empty()) {
                    let now: Vec<String> = prove.iter().take(server_proto::MAX_REGISTER_PROOFS).cloned().collect();
                    self.send_register(&server_id, peer_id, now.clone(), Vec::new(), &now);
                }
            }

            // The server answers `Ack`, `ArchivePurge` and `BlobDelete` with a plain `Ok`. If we did not match these
            // explicitly, every confirmation would log an "unexpected reply" warning.
            // The server dropped these items, so the cursor goes to disk now. A crash before this fetches them again
            // (deduplicated). It never skips.
            (ServerInflight::Ack { server_id, acks }, ServerResponse::Ok) => {
                if self.servers.iter().any(|s| s.server_id == server_id) {
                    for (mailbox, seq) in acks {
                        self.persist_cursor(&server_id, &mailbox, seq);
                    }
                }
            }

            // --- Deposit ---
            (ServerInflight::Deposit { mailbox, server_id, envelope, cancelled, .. }, ServerResponse::Deposited { seq }) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.deposit_failures = 0;
                }
                self.server_unknown_streak.remove(&(server_id.clone(), mailbox.clone()));
                info!("Sunucu zarfı sakladı: kutu={} seq={}", mailbox_log_id(&mailbox), seq);
                if cancelled {
                    if let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) {
                        let req = ServerRequest::Cancel { mailbox, seqs: vec![seq] };
                        if let Some(id) = self.send_server_request(peer_id, req) {
                            self.server_inflight.insert(id, ServerInflight::Cancel { server_id });
                        }
                    }
                    return;
                }
                // The "already deposited" mark was set at send time (`try_server_deposit`).
                if let NetworkEnvelope::Message(m) = &envelope {
                    // See `server_deposit_locations`. We store where the packet sits in the mailbox, so it can be withdrawn.
                    self.server_deposit_locations.insert(
                        (server_id.clone(), format!("{}|{}", mailbox, m.header.message_id)),
                        (mailbox.clone(), seq),
                    );
                }
            }

            (ServerInflight::Cancel { .. }, ServerResponse::Ok) => {}

            // --- Fetch ---
            (ServerInflight::Fetch { server_id }, ServerResponse::Batch { items, more }) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.fetch_inflight = false;
                }
                let index: HashMap<String, MailboxKey> =
                    self.own_server_mailboxes().into_iter().map(|(id, (_, key))| (id, key)).collect();
                let mut highest: HashMap<String, u64> = HashMap::new();
                let mut count = 0usize;
                let mut bytes = 0usize;
                // The cursor of a mailbox stops before its first item that does not open (`hold_server_item`). Its later
                // items come with the next fetch. `seen`: mailboxes this batch reached. `blocked`: held in this batch.
                let mut seen: HashSet<String> = HashSet::new();
                let mut blocked: HashSet<String> = HashSet::new();
                let mut held_any = false;
                let now = mono_ms();

                for item in items {
                    let Some(key) = index.get(&item.mailbox_id) else {
                        // Not one of our mailboxes: no cursor, no ack.
                        continue;
                    };
                    // The server numbers mail with a SQLite rowid. A larger seq is bogus and would park the cursor at the top.
                    if item.seq > i64::MAX as u64 || blocked.contains(&item.mailbox_id) {
                        continue;
                    }
                    // At or below the cursor: already taken. A server that sends it again gets no second open and no second processing.
                    if item.seq <= self.server_cursors.get(&(server_id.clone(), item.mailbox_id.clone())).copied().unwrap_or(0) {
                        continue;
                    }
                    let first = seen.insert(item.mailbox_id.clone());
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        if rt.passed.contains(&(item.mailbox_id.clone(), item.seq)) {
                            // Passed over for good: the cursor moves past it, as it does past an item that opened. Otherwise
                            // 64 such items (or one over the batch byte cap) would stop the mailbox and every mailbox after it.
                            let h = highest.entry(item.mailbox_id.clone()).or_insert(0);
                            *h = (*h).max(item.seq);
                            continue;
                        }
                        // A `Fetch` answers from the cursor upward. A held item that is no longer the first of its mailbox is gone.
                        if let Some(&(held, _)) = rt.held.get(&item.mailbox_id) {
                            if first && item.seq > held {
                                rt.held.remove(&item.mailbox_id);
                            }
                        }
                    }
                    // Nothing unsealed is taken from the server. A session mailbox opens with its root key. A first-contact
                    // mailbox opens with its pairing secret and this device's KEM keys.
                    let opened = match key {
                        MailboxKey::Session(root_keys, peer_fp) => root_keys
                            .iter()
                            .find_map(|k| server_seal::open_envelope(k, &item.mailbox_id, peer_fp, &item.sealed).ok()),
                        MailboxKey::FirstContact(secret) => self.own_mailbox_topic_fp.as_ref()
                            .and_then(|fp| self.own_device_keys.get(fp))
                            .and_then(|k| server_seal::open_first_contact(secret, &item.mailbox_id, &k.kem_sk_x25519, &k.kem_sk_mlkem, &item.sealed).ok()),
                    };
                    let Some(raw) = opened else {
                        // Not acked, and the cursor stays before it. An Ack is cumulative and the server deletes what it covers.
                        // Passed over only after `SERVER_HOLD_GRACE_MS`.
                        warn!("Sunucudan gelen zarf açılamadı (kutu={})", mailbox_log_id(&item.mailbox_id));
                        if self.hold_server_item(&server_id, &item.mailbox_id, item.seq, now) {
                            blocked.insert(item.mailbox_id.clone());
                            held_any = true;
                        } else {
                            let h = highest.entry(item.mailbox_id.clone()).or_insert(0);
                            *h = (*h).max(item.seq);
                        }
                        continue;
                    };
                    count += 1;
                    bytes += raw.len();
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.taken.insert(Sha256::digest(&raw).into(), (item.mailbox_id.clone(), item.seq));
                    }
                    // CRITICAL: `None`.
                    //
                    // If the server's `PeerId` were given, `record_peer_id_if_known` would point every contact's
                    // `device_to_peer_id` and `device_last_addr` at the SERVER. `is_peer_connected` would then lie,
                    // `reconnect_sweep` would dial the server forever, and file chunks would be requested from the wrong peer.
                    incoming.push((None, raw));
                    let h = highest.entry(item.mailbox_id.clone()).or_insert(0);
                    *h = (*h).max(item.seq);
                }

                if count > 0 {
                    info!("Sunucudan {} zarf çekildi ({} bayt)", count, bytes);
                }
                // The cursor moves in memory now (no second processing). It goes to disk and to the server (`Ack`) only
                // once `incoming` was processed: `commit_server_fetches`, then the Ack's `Ok`. Forward only: a `Push` of an
                // old seq once moved the cursor back, and everything after it was delivered again.
                let mut advanced = false;
                for (mailbox, seq) in highest {
                    let key = (server_id.clone(), mailbox.clone());
                    if seq > self.server_cursors.get(&key).copied().unwrap_or(0) {
                        self.server_cursors.insert(key, seq);
                        advanced = true;
                        if let Some(rt) = self.server_rt.get_mut(&server_id) {
                            let e = rt.unacked.entry(mailbox).or_insert(0);
                            *e = (*e).max(seq);
                        }
                    }
                }
                // `more` with no progress would be the same `Fetch` again, immediately and for as long as the server says so.
                if more && advanced {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.fetch_due_at = 0;
                    }
                    self.server_sweep_at = 0;
                } else if held_any && count > 0 {
                    // What opened may bring the key of what did not.
                    self.refetch_held(&server_id, now);
                }
            }

            // --- Archive ---
            (ServerInflight::ArchivePut { server_id, records }, ServerResponse::Ok) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.archive_failures = 0;
                    rt.archive_backoff_until = 0;
                }
                self.drop_archive_records(&records);
                // The next batch now, as for mail and chunks (see `server_sweep`). One batch per radio window took the
                // re-upload after a revoke most of an hour.
                if !self.server_archive_queue.is_empty() {
                    self.server_sweep_at = 0;
                }
            }
            (ServerInflight::ArchivePurge { server_id, keys, rest }, ServerResponse::Ok) => {
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { return };
                self.send_archive_purge(peer_id, server_id, keys, rest);
            }
            (ServerInflight::ArchiveProbe { server_id, conv_key, group, window, next }, ServerResponse::ArchiveProbed { mut present }) => {
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else {
                    if let Some((before, _)) = window { self.reopen_fetch_cursor(&conv_key, before) }
                    return;
                };
                // Only buckets this probe asked for, each once. A server listing any number of them would turn each into a fetch over Tor.
                let asked: HashSet<String> = match self.archive_root_key {
                    Some(ark) => archive_buckets(&ark, &conv_key, window.map_or_else(current_time_ms, |(before, _)| before)).into_iter().collect(),
                    None => HashSet::new(),
                };
                let mut seen_bucket: HashSet<String> = HashSet::new();
                present.retain(|b| asked.contains(&b.bucket) && seen_bucket.insert(b.bucket.clone()));
                // A press: the buckets that reach its window, newest first, each read from `before` backwards.
                if let Some((_, after)) = window {
                    present.retain(|b| b.newest_ms >= archive_wire_ms(after));
                    present.sort_by(|a, b| b.newest_ms.cmp(&a.newest_ms));
                }
                let mut wanted: Vec<String> = present.into_iter().map(|b| b.bucket).collect();
                // One bucket in flight per conversation. The `ArchiveBatch` arm asks for the next. All at once meant hundreds
                // of 512 KiB replies over one Tor circuit, and the timeouts were silent.
                if wanted.is_empty() {
                    self.probe_next_conversation(peer_id, server_id, next);
                } else {
                    let bucket = wanted.remove(0);
                    self.send_archive_fetch(peer_id, server_id, conv_key, group, bucket, window.map(|(before, _)| (before, String::new())), wanted, window, next, 0);
                }
            }
            (
                ServerInflight::ArchiveFetch { server_id, conv_key, group, bucket_more, mut rest, window, next, cursor, pages },
                ServerResponse::ArchiveBatch { records, more },
            ) => {
                // The page moves older again. Continue from the last record's timestamp for the next page. Without this,
                // only the first page of a bucket was fetched, and older messages stayed unreachable on the server.
                // Cursor = the page's last record (server order: time, then id, descending).
                let oldest = records.last().map(|r| (r.sent_at_ms, r.record_id.clone()));
                self.merge_server_archive(&conv_key, group, bucket_more.as_deref().unwrap_or(""), records, window);
                // A press: this page went past the window's start, so this bucket and the older ones hold nothing more of it.
                if let (Some((_, after)), Some((oldest_ms, _))) = (window, &oldest) {
                    if *oldest_ms < archive_wire_ms(after) {
                        return;
                    }
                }
                // The server went mid-chain: the next press asks for this window again.
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else {
                    if let Some((before, _)) = window { self.reopen_fetch_cursor(&conv_key, before) }
                    return;
                };
                // A server repeating a page (or never ending a bucket) looped here at round-trip speed. Continue only when
                // the cursor moved strictly older (server order is time, then id, both descending), and only for a bounded
                // number of pages.
                let moved = match (&oldest, &cursor) {
                    (Some(o), Some(c)) => o < c,
                    (Some(_), None) => true,
                    (None, _) => false,
                };
                if more && !moved {
                    warn!("Sunucu arşiv sayfası ilerlemedi, bu kova bırakıldı");
                }
                if let (true, true, Some(bucket), Some(before)) = (more && moved, pages + 1 < ARCHIVE_FETCH_MAX_PAGES, bucket_more, oldest) {
                    self.send_archive_fetch(peer_id, server_id, conv_key, group, bucket, Some(before), rest, window, next, pages + 1);
                } else if !rest.is_empty() {
                    let bucket = rest.remove(0);
                    self.send_archive_fetch(peer_id, server_id, conv_key, group, bucket, None, rest, window, next, 0);
                } else {
                    self.probe_next_conversation(peer_id, server_id, next);
                }
            }

            // --- Blobs ---
            (ServerInflight::BlobPut { blob_id, chunk_index, total_chunks, server_id, sent_at }, ServerResponse::Ok) => {
                // The round trip is measured. It tells whether a transfer is limited by latency or by bandwidth. If latency limits it, a larger window gives speed directly.
                // If bandwidth limits it, a larger window gives nothing, and the fix lies elsewhere (see the single Tor circuit ceiling).
                let rtt = mono_ms().saturating_sub(sent_at);
                self.blob_rtt_sum += rtt;
                self.blob_rtt_count += 1;
                // Grow the window ONLY while queue delay is low. On a fast path it opens up. On a narrow path such as Tor it
                // stops by itself. A fixed depth would be wrong in one of the two cases.
                if let Some(u) = self.server_blob_uploads.iter_mut().find(|u| u.file_id == blob_id) {
                    u.rtt_min = u.rtt_min.min(rtt.max(BLOB_RTT_FLOOR_MS));
                    let queue_ok = rtt <= u.rtt_min.saturating_mul(BLOB_RTT_GROW_FACTOR);
                    if queue_ok && rtt < BLOB_RTT_CEILING_MS && u.window < BLOB_WINDOW_MAX {
                        u.window += 1;
                    }
                }
                if self.blob_rtt_count % 10 == 0 {
                    let (w, inflight) = self
                        .server_blob_uploads
                        .first()
                        .map(|u| (u.window, u.inflight.len()))
                        .unwrap_or((0, 0));
                    info!(
                        "Blob aktarımı: {} parça, ortalama gidiş-dönüş {} ms, pencere {}, havada {}",
                        self.blob_rtt_count,
                        self.blob_rtt_sum / self.blob_rtt_count,
                        w, inflight
                    );
                }
                self.advance_blob_upload(&blob_id, chunk_index, total_chunks, &server_id);
            }
            (ServerInflight::BlobFinish { blob_id, .. }, ServerResponse::Ok) => {
                self.forget_blob_upload(&blob_id);
            }
            (ServerInflight::BlobFinish { server_id, blob_id }, ServerResponse::Err(ServerErrorCode::BlobIncomplete)) => {
                self.restart_blob_upload(&blob_id, &server_id);
            }
            // A refused finish never succeeds with the same bytes. Drop the upload (the direct peer path still serves the
            // file) so it does not block the queue behind it.
            (ServerInflight::BlobFinish { blob_id, .. }, ServerResponse::Err(code))
                if !matches!(code, ServerErrorCode::NotEnrolled | ServerErrorCode::RateLimited | ServerErrorCode::Internal) =>
            {
                warn!("Sunucu blob'u kabul etmedi ({:?}), yükleme bırakıldı: {}", code, blob_id);
                self.finish_blob_upload(&blob_id);
            }

            // --- Errors ---
            (inflight, ServerResponse::Err(code)) => self.handle_server_error(inflight, code),

            // An unexpected match means a protocol mismatch. It is treated as no answer, so the request's own clean-up runs
            // (a `Fetch` would otherwise leave `fetch_inflight` set for good, and an `Ack` would lose its positions).
            (inflight, other) => {
                warn!("Sunucudan beklenmeyen yanıt: {:?} -> {:?}", std::mem::discriminant(&inflight), std::mem::discriminant(&other));
                self.handle_server_failure(inflight);
            }
        }
    }

    fn handle_server_error(&mut self, inflight: ServerInflight, code: ServerErrorCode) {
        let server_id = inflight.server_id().to_string();

        // Delivery guarantee fix: `fetch_inflight` was reset only on a successful `Batch`, in `handle_server_failure`, and
        // in the `other` arm below, not in the `NotEnrolled`, `Revoked` and `UnknownMailbox` arms. A `Fetch` answered with
        // `NotEnrolled` (quite likely if the client's PeerId changed, or another device rebound) left the flag `true` for
        // good. `server_fetch` then returned early every turn, and even after a successful re-registration, no mail was
        // fetched from the server until the app restarted. So an in-flight `Fetch` is reset here, whatever the arm.
        if matches!(inflight, ServerInflight::Fetch { .. }) {
            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                rt.fetch_inflight = false;
            }
        }

        // A refused `Deposit` is NOT on the server, so take back the optimistic "already deposited" mark. Otherwise every
        // retry over the next 12 h would count it as stored. Each arm below blocks this server for the envelope (mailbox
        // TTL, not enrolled, deposit backoff), so this cannot spin.
        if let ServerInflight::Deposit { dedup_key, .. } = &inflight {
            self.server_deposited.remove(&(server_id.clone(), dedup_key.clone()));
        }
        // A spent or expired token never works again. With it gone, the next round falls back to `Rebind`, or stops (see `server_sweep`).
        if matches!((&inflight, &code), (ServerInflight::Enroll { .. }, ServerErrorCode::BadInvite)) {
            if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                r.token.clear();
                let r = r.clone();
                self.persist_server(&r);
            }
        }
        // `Internal` is the server's own trouble (SQLite busy, disk). Dropping on it lost one queued archive record per sweep
        // while it lasted. A chunk over the blob quota gets the same answer every time. Kept, it was sent again every 5 minutes
        // forever, ahead of every later upload, and it blocked message deposits to the server each time.
        let permanent = !matches!(
            code,
            ServerErrorCode::NotEnrolled | ServerErrorCode::Revoked | ServerErrorCode::QuotaExceeded | ServerErrorCode::RateLimited | ServerErrorCode::Internal
        ) || matches!((&inflight, &code), (ServerInflight::BlobPut { .. }, ServerErrorCode::QuotaExceeded));
        if let ServerInflight::Register { .. } = &inflight {
            // Refused (too many mailboxes, a taken ID): not again on each sweep.
            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                rt.register_backoff_until = mono_ms() + SERVER_DEPOSIT_BACKOFF_MS;
            }
        }
        match &inflight {
            // The same chunk gets the same answer. Give the upload up; the direct peer path still serves the file.
            ServerInflight::BlobPut { blob_id, .. } if permanent => {
                warn!("Sunucu parçayı kabul etmedi ({:?}), yükleme bırakıldı: {}", code, blob_id);
                self.finish_blob_upload(blob_id);
            }
            // Drop the head record, or it blocks every record behind it.
            ServerInflight::ArchivePut { records, .. } if permanent => {
                warn!("Sunucu arşiv partisini kabul etmedi ({:?}), ilk kayıt bırakıldı", code);
                self.drop_archive_records(&records[..records.len().min(1)]);
            }
            // The server keeps the IDs it took and names none. The refused ones (over its cap, a full mailbox) would be
            // sent again each backoff, with the whole list, forever. They are taken as done until the next reconnect
            // recomputes the set.
            ServerInflight::Register { ids, dropped, .. } if matches!(code, ServerErrorCode::QuotaExceeded) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.registered.extend(ids.iter().cloned());
                    for id in dropped {
                        rt.registered.remove(id);
                    }
                    rt.last_error = Some(format!("{TOO_MANY_MAILBOXES}: the server refused some, those chats use the direct path only"));
                }
            }
            // Positions the server did not take: again later, unless it will never take them.
            ServerInflight::Ack { acks, .. } => {
                if permanent {
                    warn!("Sunucu Ack'i reddetti ({:?}), {} kutu", code, acks.len());
                } else {
                    self.restage_acks(&server_id, acks.clone());
                }
            }
            _ => {}
        }

        // As in `handle_server_failure`: the caller of a restore already got "OK", and the rest of this conversation's
        // buckets is not requested.
        if let ServerInflight::ArchiveFetch { .. } | ServerInflight::ArchiveProbe { .. } = &inflight {
            warn!("Sunucu geçmiş isteğini reddetti ({:?}), geri yükleme eksik", code);
            self.reopen_fetch_window(&inflight);
            self.attachment_events.push(serde_json::json!({"type": "history_restore_incomplete"}).to_string());
        }

        match code {
            ServerErrorCode::UnknownMailbox => {
                warn!("Sunucu kutuyu tanımıyor (alıcı bu sunucuda değil)");
                if let ServerInflight::Deposit { mailbox, .. } = &inflight {
                    // Deposits in flight together all get this answer, so back off one step per pause.
                    let key = (server_id.clone(), mailbox.clone());
                    let now = mono_ms();
                    if self.server_unknown_mailboxes.get(&key).map_or(true, |until| now >= *until) {
                        let streak = self.server_unknown_streak.entry(key.clone()).or_insert(0);
                        let ttl = (SERVER_UNKNOWN_MAILBOX_TTL_MS << (*streak).min(6)).min(SERVER_UNKNOWN_MAILBOX_MAX_TTL_MS);
                        *streak += 1;
                        self.server_unknown_mailboxes.insert(key, now + ttl);
                    }
                }
                // The recipient is not on this server: fall back to gossip IMMEDIATELY.
                //
                // Delivery fix: this arm used to call `try_publish_raw`, the UNQUEUED raw version, and ignored its result with
                // `let _ =`. If the publish failed at that moment (mesh not yet formed, peer briefly unreachable) the envelope
                // was written nowhere. `Message` types survived through `awaiting_confirmation`, but `Handshake` and
                // `IdentityExchange`, the carriers of pairing and first contact, were dropped silently. Every other error arm
                // already used `requeue_failed_deposit` (`publish_envelope` into `pending_envelopes`). This was the one exception.
                self.requeue_failed_deposit(&inflight);
            }
            ServerErrorCode::NotEnrolled => {
                // A new Hello right away only when this was not the enrollment itself. Otherwise Hello, Welcome, Rebind and
                // NotEnrolled ran at round-trip speed, two signatures per round, past the backoff.
                let enrolling = matches!(inflight, ServerInflight::Hello { .. } | ServerInflight::Enroll { .. } | ServerInflight::Rebind { .. });
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = false;
                    if !enrolling {
                        rt.hello_sent_at = 0;
                    }
                }
                if !enrolling {
                    self.server_sweep_at = 0;
                }
                // The server does not know this enrollment (any more). The ID is useless, as in the Revoked arm.
                if matches!(inflight, ServerInflight::Rebind { .. }) {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.last_error = Some("The server does not know this enrollment. Add it again with a new invite code".to_string());
                    }
                    if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                        r.enrollment_id = None;
                        let r = r.clone();
                        self.persist_server(&r);
                    }
                }
                self.requeue_failed_deposit(&inflight);
            }
            ServerErrorCode::Revoked => {
                warn!("Sunucu kaydımızı iptal etti: {}", crate::log_id(&server_id));
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = false;
                    rt.last_error = Some("The operator revoked this enrollment".to_string());
                }
                // A revoked identity is not worth keeping: if we keep it, the next round tries `Rebind` and gets the same
                // error. If we clear it, the user can enroll cleanly by pasting a new invite code (see `add_server`). If no
                // token is left, nothing is attempted automatically. The error message stays, and the user decides.
                if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                    if r.enrollment_id.is_some() {
                        r.enrollment_id = None;
                        let r = r.clone();
                        self.persist_server(&r);
                    }
                }
                self.requeue_failed_deposit(&inflight);
            }
            // A full mailbox (5000 undelivered items for a device that has not fetched in a week) must stop deposits to THAT mailbox only. The
            // server-wide backoff below would lock the whole account out of the server, call invites included, for as long as the dead mailbox stayed full.
            // ponytail: QuotaExceeded also covers the per-account and disk caps. For those, this retries each mailbox once per backoff instead of once
            // per server, which is bounded by the mailbox count.
            ServerErrorCode::QuotaExceeded if matches!(inflight, ServerInflight::Deposit { .. }) => {
                if let ServerInflight::Deposit { mailbox, .. } = &inflight {
                    // The pause doubles per refusal, like `UnknownMailbox`. A `Deposited` resets the streak.
                    let key = (server_id.clone(), mailbox.clone());
                    let now = mono_ms();
                    if self.server_unknown_mailboxes.get(&key).map_or(true, |until| now >= *until) {
                        let streak = self.server_unknown_streak.entry(key.clone()).or_insert(0);
                        let ttl = (SERVER_DEPOSIT_BACKOFF_MS << (*streak).min(6)).min(SERVER_UNKNOWN_MAILBOX_MAX_TTL_MS);
                        *streak += 1;
                        warn!("Sunucu kutusu dolu, bu kutuya yatırma {} sn durduruldu: {}", ttl / 1000, mailbox_log_id(mailbox));
                        self.server_unknown_mailboxes.insert(key, now + ttl);
                    }
                }
                self.requeue_failed_deposit(&inflight);
            }
            other => {
                warn!("Sunucu hatası: {:?}", other);
                // Any refused `Deposit` backs off too: its mark is gone (see above), so without this the retry would deposit
                // again at once. Deposits (and the blob chunks behind the same gate) only. A refused `Register` or archive
                // request must not stop all message deposits to the server for 5 minutes, again and again.
                let backs_off = matches!(inflight, ServerInflight::Deposit { .. })
                    || (matches!(other, ServerErrorCode::RateLimited)
                        && matches!(inflight, ServerInflight::BlobPut { .. } | ServerInflight::BlobFinish { .. }));
                let register_quota = matches!((&inflight, &other), (ServerInflight::Register { .. }, ServerErrorCode::QuotaExceeded));
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    // The `Register` arm above has a clearer message.
                    if !register_quota {
                        rt.last_error = Some(format!("{:?}", other));
                    }
                    rt.fetch_inflight = false;
                    // See `SERVER_DEPOSIT_BACKOFF_MS`. "Quota or rate error" means "try again a little later", not "try every
                    // second". The backoff stops only deposits. `Fetch` and `Ack` keep running, and draining the mailbox is
                    // exactly what frees the quota.
                    if backs_off {
                        Self::back_off_deposits(rt);
                    }
                    // A full archive quota (or a rate or server error) gets the same answer for a while. Without this, the same
                    // head batch went out again on every sweep. It has its own backoff, so message deposits keep going. A
                    // permanent refusal already dropped the head record above, so the next try is new.
                    if matches!(inflight, ServerInflight::ArchivePut { .. }) && !permanent {
                        rt.archive_backoff_until = mono_ms()
                            + (SERVER_DEPOSIT_BACKOFF_MS << rt.archive_failures.min(3)).min(SERVER_DEPOSIT_BACKOFF_MAX_MS);
                        rt.archive_failures = rt.archive_failures.saturating_add(1);
                    }
                }
                // Quota, rate or size: the right behaviour is the same in all of them. Hand this envelope to gossip. Do not lose the message.
                self.requeue_failed_deposit(&inflight);
            }
        }
    }

    fn handle_server_failure(&mut self, inflight: ServerInflight) {
        if let ServerInflight::Hello { server_id } | ServerInflight::Fetch { server_id } = &inflight {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.hello_sent_at = 0;
                // If no answer came, leaving the flag set would lock fetching for good (see `fetch_inflight`).
                rt.fetch_inflight = false;
                // A lost `Fetch` is retried at the next sweep, not after the rest of the 5-minute safety interval.
                if matches!(inflight, ServerInflight::Fetch { .. }) {
                    rt.fetch_due_at = 0;
                }
            }
        }
        if let ServerInflight::Ack { server_id, acks } = &inflight {
            self.restage_acks(server_id, acks.clone());
        }
        // If the deposit failed, undo the "already deposited" mark. Otherwise the retry path would stay closed (see `server_deposited`).
        if let ServerInflight::Deposit { server_id, dedup_key, .. } = &inflight {
            // Now independent of the envelope type (see `deposit_dedup_key`). Before, only `Message` was reverted, and
            // only `Message` was ever marked.
            self.server_deposited.remove(&(server_id.clone(), dedup_key.clone()));
            // No answer: without a backoff, the retry below deposited again at once (the server still counts as ready), on every request timeout.
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                Self::back_off_deposits(rt);
            }
        }
        // The caller of a restore already got "OK": tell the UI the result is partial.
        if let ServerInflight::ArchiveFetch { .. } | ServerInflight::ArchiveProbe { .. } = &inflight {
            warn!("Sunucu geçmiş isteği yanıtsız kaldı, geri yükleme eksik");
            self.reopen_fetch_window(&inflight);
            self.attachment_events.push(serde_json::json!({"type": "history_restore_incomplete"}).to_string());
        }
        self.requeue_failed_deposit(&inflight);
    }

    fn send_archive_fetch(
        &mut self,
        peer_id: PeerId,
        server_id: String,
        conv_key: String,
        group: bool,
        bucket: String,
        before: Option<(u64, String)>,
        rest: Vec<String>,
        window: Option<(u64, u64)>,
        next: Vec<(String, bool)>,
        pages: u32,
    ) {
        let req = ServerRequest::ArchiveFetch {
            bucket: bucket.clone(),
            before_ms: before.as_ref().map(|b| b.0),
            before_id: before.as_ref().and_then(|b| (!b.1.is_empty()).then(|| b.1.clone())),
            max_items: MAX_FETCH_BATCH_ITEMS,
            max_bytes: MAX_FETCH_BATCH_BYTES,
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(
                id,
                ServerInflight::ArchiveFetch { server_id, conv_key, group, bucket_more: Some(bucket), rest, window, next, cursor: before, pages },
            );
        } else if let Some((before, _)) = window {
            self.reopen_fetch_cursor(&conv_key, before);
        }
    }

    /// A full restore walks its conversations one at a time. Probing all of them at once meant one 512 KiB chain per conversation on one Tor circuit.
    fn probe_next_conversation(&mut self, peer_id: PeerId, server_id: String, mut next: Vec<(String, bool)>) {
        let Some(ark) = self.archive_root_key else { return };
        if next.is_empty() {
            return;
        }
        let (conv_key, group) = next.remove(0);
        let req = ServerRequest::ArchiveProbe { buckets: archive_buckets(&ark, &conv_key, current_time_ms()) };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::ArchiveProbe { server_id, conv_key, group, window: None, next });
        }
    }

    /// Immediately hands an envelope that could not be deposited to the server to gossip.
    fn requeue_failed_deposit(&mut self, inflight: &ServerInflight) {
        if let ServerInflight::Deposit { envelope, target_fp, first_attempt_at, cancelled, .. } = inflight {
            // Withdrawn by the user, or confirmed in the meantime: nothing to resend.
            if *cancelled {
                return;
            }
            let envelope = envelope.clone();
            let target_fp = target_fp.clone();
            // NOT `publish_envelope`: that one queues the entry with `current_time_ms()`, and would reset the envelope's age on
            // every server round trip. See the `first_attempt_at` note of `ServerInflight::Deposit`. This is the second half of the endless queue cycle.
            if let Err(e) = self.publish_envelope_at(&target_fp, &envelope, *first_attempt_at) {
                warn!("Sunucu başarısız oldu, gossipsub da hemen başaramadı (kuyruğa alındı): {}", e);
            }
        }
        if let ServerInflight::BlobPut { blob_id, chunk_index, server_id, .. } = inflight {
            // Drop from the in-flight set. It is requested again on the next turn.
            if let Some(up) = self.server_blob_uploads.iter_mut().find(|u| u.file_id == *blob_id) {
                up.inflight.remove(chunk_index);
                // Timeout or error means the path was overloaded. Halve the window. Backing off is necessary before retries eat
                // the bandwidth and push throughput lower still (measured: with a fixed window of 16, throughput fell from 180 KB/s to about 50 KB/s).
                up.window = (up.window / 2).max(BLOB_WINDOW_MIN);
                warn!("Parça zaman aşımı/hatası — pencere {} yapıldı", up.window);
            }
            // One of the parallel circuits may have died: a dead connection swallows 1/N of the requests. Do not decide on a
            // single event. One timeout on Tor is noise (see `note_bulk_timeout`). Only the server this chunk went to is affected.
            if let Some(p) = self.server_rt.get(server_id).and_then(|r| r.peer_id) {
                self.note_bulk_timeout(p);
            }
        }
    }

    fn begin_enrollment(&mut self, server_id: &str, challenge: &[u8]) {
        let Some(rec) = self.servers.iter().find(|s| s.server_id == server_id).cloned() else { return };
        let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id) else { return };
        let Ok(sk_bytes): Result<[u8; 32], _> = rec.enroll_sk.as_slice().try_into() else {
            error!("Sunucu kayıt anahtarı bozuk: {}", crate::log_id(&server_id));
            return;
        };
        let signing = SigningKey::from_bytes(&sk_bytes);
        let Ok(seed): Result<ml_dsa::Seed, _> = rec.enroll_sk_pq.as_slice().try_into() else {
            // A row may have been saved before server support was added (see the `enroll_sk_pq` migration). The user must add the
            // server with a new invite code. We do NOT silently fall back to the classical signature.
            error!("Sunucu kayıt anahtarının PQ bileşeni yok: {}", crate::log_id(&server_id));
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error =
                    Some("Kayıt anahtarı eski biçimde — sunucuyu yeni bir davet koduyla ekleyin".to_string());
            }
            return;
        };
        let signing_pq = MlDsaSigningKey::<MlDsa87>::from_seed(&seed);
        let ts_ms = current_time_ms();
        let Some(me) = self.swarm.as_ref().map(|s| s.local_peer_id().to_string()) else { return };

        // Already enrolled (the app was reinstalled, the libp2p identity changed): reconnect without spending an invite token.
        // A token wins over the stored ID: the user pasted it to enroll anew. If the server refuses it, it is cleared, and this
        // falls back to `Rebind`.
        if let Some(enrollment_id) = rec.enrollment_id.clone().filter(|_| rec.token.is_empty()) {
            let input = server_proto::rebind_signing_input(&enrollment_id, server_id, &me, challenge, ts_ms);
            let sig = signing.sign(&input).to_bytes().to_vec();
            let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
            let req = ServerRequest::Rebind {
                enrollment_id,
                ts_ms,
                sig,
                sig_pq: sig_pq.encode().to_vec(),
            };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(id, ServerInflight::Rebind { server_id: server_id.to_string() });
            }
            return;
        }

        if rec.token.is_empty() {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error = Some("No invite token. Add the server again with a new code".to_string());
            }
            return;
        }
        let Ok(token_bytes) = hex::decode(&rec.token) else {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error = Some("The invite token is damaged".to_string());
            }
            return;
        };
        let enroll_pk = signing.verifying_key().to_bytes().to_vec();
        let enroll_pk_pq = signing_pq.verifying_key().encode().to_vec();
        let input = server_proto::enroll_signing_input(
            SERVER_PROTOCOL_VERSION,
            server_id,
            &me,
            &token_bytes,
            &enroll_pk,
            &enroll_pk_pq,
            challenge,
            ts_ms,
        );
        let sig = signing.sign(&input).to_bytes().to_vec();
        let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
        let req = ServerRequest::Enroll {
            version: SERVER_PROTOCOL_VERSION,
            invite_token: token_bytes,
            enroll_pk,
            enroll_pk_pq,
            ts_ms,
            sig,
            sig_pq: sig_pq.encode().to_vec(),
            challenge: challenge.to_vec(),
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::Enroll { server_id: server_id.to_string() });
        }
    }

    /// Called by `poll_events` when connecting to or disconnecting from a server.
    pub(crate) fn note_server_connection(&mut self, peer: PeerId, connected: bool) {
        let sid = self
            .server_rt
            .iter()
            .find(|(_, rt)| rt.peer_id == Some(peer))
            .map(|(sid, _)| sid.clone());
        let Some(sid) = sid else { return };
        if let Some(rt) = self.server_rt.get_mut(&sid) {
            rt.connected = connected;
            if connected {
                rt.dial_attempts = 0;
                rt.dial_backoff_until = 0;
                // Timeouts on a lost connection grew the deposit backoff.
                rt.deposit_failures = 0;
                rt.deposit_backoff_until = 0;
                // Subscriptions are still on the server after a reconnect, but our view may be stale. Reset it, so the difference is recomputed.
                rt.registered.clear();
                rt.fetch_due_at = 0;
                rt.hello_sent_at = 0;
            } else {
                rt.enrolled = false;
            }
        }
        self.server_sweep_at = 0;
    }

    /// Is this `PeerId` that of a configured server?
    pub(crate) fn is_server_peer(&self, peer: &PeerId) -> bool {
        self.server_rt.values().any(|rt| rt.peer_id.as_ref() == Some(peer))
    }

    /// The `PeerId` of EVERY configured server (registered or not). See the keepalive filter in `poll_events`.
    pub(crate) fn server_peer_ids(&self) -> Vec<PeerId> {
        self.server_rt.values().filter_map(|rt| rt.peer_id).collect()
    }

    /// The `PeerId`s of connected and registered servers. Added as an alternative source for file downloads.
    pub(crate) fn ready_server_peers(&self) -> Vec<PeerId> {
        self.servers
            .iter()
            .filter_map(|s| {
                let rt = self.server_rt.get(&s.server_id)?;
                if rt.connected && rt.enrolled {
                    rt.peer_id
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Archive (history): upload, fetch, merge
// ---------------------------------------------------------------------------
//
// Why mailbox envelopes cannot serve as history: ratchet message keys are forward secret, and they are deleted after
// use. Skipped keys are limited (`MAX_SKIPPED_KEYS`) and pruned on rotation. An envelope from last week can therefore
// no longer be decrypted by ANYONE, including the intended recipient. A newly linked device never had those keys at all.
// So history is re-encrypted under a SEPARATE, long-lived key.

impl P2PCore {
    /// Loads the root archive key (ARK).
    ///
    /// Not to be confused with `history_key`. That one is per DEVICE, random, and NOT in the recovery file. It only
    /// encrypts the local archive on disk. The ARK belongs to the IDENTITY: every device of the same identity must be able
    /// to read it, so it also goes to sibling devices in `SyncPayload` and into the recovery file.
    pub(crate) fn set_archive_root_key(&mut self, key: &[u8]) -> bool {
        let Ok(k) = <[u8; 32]>::try_from(key) else { return false };
        self.archive_root_key = Some(k);
        self.reconcile_archive_key(true);
        self.server_sweep_at = 0;  // // backfill runs in slices from the sweep
        true
    }

    /// History written while a history server was set but no archive key was loaded was never queued. Queue it once the
    /// key is here. One slice (200 rows) per sweep, newest first, down to the oldest row. The `ark_backfill` marker holds
    /// "<next id bound>,<rows done>" ("1" = not started), so it resumes across sweeps and restarts.
    pub(crate) fn maybe_archive_backfill(&mut self) {
        const SLICE: i64 = 200;
        if self.archive_root_key.is_none() || !self.servers.iter().any(|s| s.store_history) {
            return;
        }
        // Wait for the upload to drain: a full queue drops its oldest entries.
        if self.server_archive_queue.len() >= MAX_SERVER_ARCHIVE_QUEUE / 2 {
            return;
        }
        let Some(marker) = self.meta_str("ark_backfill") else { return };
        let (mut bound, mut done) = marker
            .split_once(',')
            .and_then(|(b, d)| Some((b.parse::<i64>().ok()?, d.parse::<i64>().ok()?)))
            .unwrap_or((i64::MAX, 0));
        let Some(conn) = &self.db else { return };
        let Ok(mut stmt) = conn.prepare(
            "SELECT id, message_id, group_id, peer_device_fingerprint FROM messages \
             WHERE message_id IS NOT NULL AND id < ?1 ORDER BY id DESC LIMIT ?2",
        ) else { return };
        let rows: Vec<(i64, String, Option<String>, String)> = stmt
            .query_map(params![bound, SLICE], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map(|it| it.flatten().collect())
            .unwrap_or_default();
        drop(stmt);
        let n = rows.len() as i64;
        for (id, mid, gid, fp) in rows {
            bound = id;
            self.requeue_archive_row(gid.as_deref(), &fp, &mid);
        }
        done += n;
        if n < SLICE {
            self.meta_del("ark_backfill");
        } else {
            self.meta_put("ark_backfill", &format!("{bound},{done}"));
            self.server_sweep_at = 0;
        }
    }

    pub(crate) fn archive_root_key_bytes(&self) -> Option<Vec<u8>> {
        self.archive_root_key.map(|k| k.to_vec())
    }

    // The archive key state that the core keeps in `app_meta` (hex strings):
    //   ark          the key in force, when the core changed it itself. It wins over the client's key file until the client
    //                loads the same key, which proves the file was written.
    //   ark_retired  SHA-256 of every replaced key (64 hex chars each). Never taken again.
    //   ark_todo     a rotation whose sync to siblings and backfill are not done yet.
    //   ark_purge    replaced keys (comma list) whose buckets are still on the server.

    /// The key the core changed itself (rotation, sibling sync) wins over the one the client loaded. The client stores it on an
    /// event that can be lost.
    fn reconcile_archive_key(&mut self, from_client: bool) {
        let Some(stored) =
            self.meta_str("ark").and_then(|h| hex::decode(h).ok()).and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return;
        };
        if self.archive_root_key == Some(stored) {
            if from_client {
                self.meta_del("ark");
            }
            return;
        }
        self.archive_root_key = Some(stored);
        // The client stores the key on this event.
        self.attachment_events.push(serde_json::json!({"type": "sync"}).to_string());
    }

    fn archive_key_retired(&self, key: &[u8; 32]) -> bool {
        let hash = hex::encode(Sha256::digest(key));
        self.meta_str("ark_retired").map_or(false, |r| r.as_bytes().chunks(64).any(|c| c == hash.as_bytes()))
    }

    /// Stores a key change in one statement, so a crash leaves all of it or none. `rotation`: this device made the new key. It
    /// also syncs and backfills.
    fn persist_archive_key_change(&self, new: &[u8; 32], old: Option<&[u8; 32]>, rotation: bool) {
        let Some(conn) = &self.db else { return };
        let mut retired = self.meta_str("ark_retired").unwrap_or_default();
        let mut purge = self.meta_str("ark_purge").unwrap_or_default();
        if let Some(old) = old {
            retired.push_str(&hex::encode(Sha256::digest(old)));
            if !purge.is_empty() {
                purge.push(',');
            }
            purge.push_str(&hex::encode(old));
        }
        // The old buckets are purged by every device that replaces a key. Only the device that rotated syncs and backfills (`ark_todo`).
        let todo = if rotation { ", ('ark_todo', '1')" } else { "" };
        let head = "INSERT OR REPLACE INTO app_meta (k, v) VALUES ('ark', ?1), ('ark_retired', ?2)";
        let result = if purge.is_empty() {
            conn.execute(&format!("{head}{todo}"), params![hex::encode(new), retired])
        } else {
            conn.execute(&format!("{head}, ('ark_purge', ?3){todo}"), params![hex::encode(new), retired, purge])
        };
        if let Err(e) = result {
            error!("Arşiv anahtarı değişikliği yazılamadı: {}", e);
        }
    }

    /// A revoked device holds the key. The new key is on disk before anything is sent. The rest (sync, backfill, purge of the
    /// old buckets) resumes from `app_meta` after a crash or without network.
    pub(crate) fn rotate_archive_root_key(&mut self) {
        use rand::RngCore;
        let Some(old) = self.archive_root_key else { return };
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        self.persist_archive_key_change(&key, Some(&old), true);
        self.archive_root_key = Some(key);
        self.attachment_events.push(serde_json::json!({"type": "sync"}).to_string());
        self.resume_archive_rotation();
    }

    /// Step 2 of a rotation: the new key goes to the remaining own devices, and the newest local rows are queued again, to be sealed under the new key.
    fn resume_archive_rotation(&mut self) {
        if self.meta_str("ark_todo").is_none() {
            return;
        }
        self.sync_to_siblings();
        if self.servers.iter().any(|s| s.store_history) {
            self.backfill_server_archive();
        }
        self.meta_del("ark_todo");
    }

    /// Step 3 of a rotation: deletes what the server holds under replaced keys. Runs each sweep until the server has confirmed every bucket.
    // ponytail: the buckets of the last 36 months, as `purge_server_archive`.
    fn purge_retired_archive(&mut self, server_id: &str, peer_id: PeerId) {
        let Some(keys) = self.meta_str("ark_purge") else { return };
        let now = current_time_ms();
        if self.server_rt.get(server_id).map_or(false, |r| mono_ms() < r.purge_retry_at)
            || self.server_inflight.values().any(|i| matches!(i, ServerInflight::ArchivePurge { .. }))
        {
            return;
        }
        // No answer or an error: try again after a while, not on each sweep.
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.purge_retry_at = mono_ms() + SERVER_DEPOSIT_BACKOFF_MS;
        }
        let conv_keys = self.archive_conv_keys();
        let mut rest = Vec::new();
        for h in keys.split(',') {
            let Some(old) = hex::decode(h).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else { continue };
            for c in &conv_keys {
                rest.extend(archive_buckets(&old, c, now));
            }
        }
        self.send_archive_purge(peer_id, server_id.to_string(), keys, rest);
    }

    /// One chunk at a time. With nothing left, the replaced keys are dropped.
    fn send_archive_purge(&mut self, peer_id: PeerId, server_id: String, keys: String, mut rest: Vec<String>) {
        if rest.is_empty() {
            // A rotation since this run started added a key: the next sweep purges again.
            if self.meta_str("ark_purge").as_deref() == Some(keys.as_str()) {
                self.meta_del("ark_purge");
            }
            return;
        }
        // 500: the server refuses a list longer than its 512-mailbox cap.
        let cap = self.server_rt.get(&server_id).map_or(1, Self::mailbox_cap).min(500);
        let tail = rest.split_off(rest.len().min(cap));
        let req = ServerRequest::ArchivePurge { buckets: rest };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::ArchivePurge { server_id, keys, rest: tail });
        }
    }

    /// Takes the key a sibling sent. Only the primary device revokes, so only its key replaces one we hold. A replaced key is
    /// never taken again: an older sync can arrive after a newer one. Returns true when the key changed.
    pub(crate) fn adopt_archive_key(&mut self, key: &[u8], from_primary: bool) -> bool {
        let Ok(key) = <[u8; 32]>::try_from(key) else { return false };
        let old = self.archive_root_key;
        if old == Some(key) || (old.is_some() && !from_primary) || self.archive_key_retired(&key) {
            return false;
        }
        self.persist_archive_key_change(&key, old.as_ref(), false);
        self.archive_root_key = Some(key);
        self.server_sweep_at = 0;  // // backfill runs in slices from the sweep
        true
    }

    /// Records `rev` as seen for this record. Returns false when a higher revision was seen before: the record is a rollback
    /// and must not be merged.
    // ponytail: one row per archived message, pruned only with the last server (`remove_server`), bounded like the history itself.
    fn note_archive_rev(&self, conv_key: &str, record_id: &str, rev: u64) -> bool {
        let Some(conn) = &self.db else { return true };
        let rev = rev.min(i64::MAX as u64) as i64;
        let known: i64 = conn
            .query_row(
                "SELECT rev FROM server_archive_revs WHERE conv_key = ?1 AND record_id = ?2",
                params![conv_key, record_id],
                |r| r.get(0),
            )
            .unwrap_or(-1);
        if rev < known {
            return false;
        }
        if rev > known {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_archive_revs (conv_key, record_id, rev) VALUES (?1, ?2, ?3)",
                params![conv_key, record_id, rev],
            );
        }
        true
    }

    /// Is history storage on the server enabled?
    fn history_server(&self) -> Option<String> {
        self.servers
            .iter()
            .find(|s| {
                s.store_history
                    && self.server_rt.get(&s.server_id).map(|r| r.connected && r.enrolled).unwrap_or(false)
            })
            .map(|s| s.server_id.clone())
    }

    /// Called when a local archive row is written. It queues the same row for upload to the server.
    ///
    /// `rev`: an edit or delete uploads with the SAME `record_id` and a higher revision, and the server overwrites the older
    /// copy. That is exactly what the existing `HistorySyncResponse` mechanism cannot do (correct a late Edit in the past).
    pub(crate) fn queue_archive_record(
        &mut self,
        conv_key: &str,
        record_id: &str,
        rev: u64,
        sent_at_ms: u64,
        plaintext: Vec<u8>,
    ) {
        // With no server, or history storage off, nothing is queued. Otherwise a disabled feature would quietly grow the disk.
        if !self.servers.iter().any(|s| s.store_history) {
            return;
        }
        if self.archive_root_key.is_none() {
            // Queued once the key arrives (`maybe_archive_backfill`).
            if self.meta_str("ark_backfill").is_none() {
                self.meta_put("ark_backfill", "1");
            }
            return;
        }
        // The server must not hand back a revision older than this one.
        self.note_archive_rev(conv_key, record_id, rev);
        let entry = PendingArchive {
            conv_key: conv_key.to_string(),
            record_id: record_id.to_string(),
            rev,
            // The bucket comes from this. A peer's clock far ahead put the record where no probe or purge would look.
            sent_at_ms: sent_at_ms.min(current_time_ms()),
            plaintext,
        };
        // This column used to store the message body as PLAINTEXT. Every body in the `messages` table is encrypted with
        // `history_key`, so the at-rest encryption was bypassed for exactly this table. The queue normally drains quickly,
        // but after `remove_server` (no connected history server left) the rows stayed on disk as plaintext indefinitely.
        // If `seal_local_blob` is not available (the key is not loaded yet), the row is not written at all. The copy in
        // memory is still sent in this turn.
        if let Some(conn) = &self.db {
            let _ = conn.execute("INSERT OR IGNORE INTO server_archived_convs (conv_key) VALUES (?1)", params![entry.conv_key]);
        }
        let stored = self.seal_local_blob(&entry.plaintext);
        if let (Some(conn), Some(blob)) = (&self.db, stored) {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_archive_queue (record_id, conv_key, rev, sent_at_ms, plaintext, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![entry.record_id, entry.conv_key, entry.rev as i64, entry.sent_at_ms as i64, blob, current_time_ms() as i64],
            );
        }
        // If an older revision of the same record is waiting in the queue, replace it.
        if let Some(existing) = self.server_archive_queue.iter_mut().find(|e| e.record_id == entry.record_id) {
            *existing = entry;
        } else {
            self.server_archive_queue.push(entry);
            // History server down for a long time: the queue does not grow without end.
            let over = self.server_archive_queue.len().saturating_sub(MAX_SERVER_ARCHIVE_QUEUE);
            if over > 0 {
                warn!("Arşiv kuyruğu dolu, en eski {} kayıt sunucuya gitmeyecek", over);
                self.drop_archive_queue_head(over);
            }
        }
    }

    /// Uploads the queued archive records in batches.
    fn server_flush_archive(&mut self, server_id: &str, peer_id: PeerId) {
        if self.server_archive_queue.is_empty() {
            return;
        }
        let Some(ark) = self.archive_root_key else { return };
        // Quota or rate error: wait (own backoff, see `archive_backoff_until`), not once per sweep.
        if self.server_rt.get(server_id).map_or(false, |r| mono_ms() < r.archive_backoff_until) {
            return;
        }
        // If an `ArchivePut` is already in flight, wait. Sending them in order keeps the server's `rev` comparison predictable.
        if self.server_inflight.values().any(|i| matches!(i, ServerInflight::ArchivePut { .. })) {
            return;
        }

        // One request goes to ONE bucket (a bucket is a conversation plus a period). So we gather the entries that match the
        // bucket of the record at the head of the queue.
        let head = self.server_archive_queue[0].clone();
        let epoch = server_seal::archive_epoch_for(head.sent_at_ms);
        let Ok(bucket) = server_seal::server_archive_bucket(&ark, &head.conv_key, epoch) else { return };

        let mut records = Vec::new();
        let mut consumed = 0usize;
        let mut sealed_bytes = 0usize;
        // Half the wire cap. An oversized request fails as a whole and would be re-sent unchanged.
        let budget = MAX_DEPOSIT_BYTES / 2;
        for entry in self.server_archive_queue.iter() {
            if records.len() >= SERVER_ARCHIVE_BATCH {
                break;
            }
            if entry.conv_key != head.conv_key || server_seal::archive_epoch_for(entry.sent_at_ms) != epoch {
                // A different bucket: this batch ends here. The queue order is kept.
                break;
            }
            // The server sees an ID that only this identity can link to the message. The real ID travels inside the sealed record.
            let wire_id = archive_wire_id(&ark, &entry.conv_key, &entry.record_id);
            match server_seal::seal_archive_record(
                &ark,
                &entry.conv_key,
                &wire_id,
                entry.rev,
                &bucket,
                archive_wire_ms(entry.sent_at_ms),
                &entry.plaintext,
            ) {
                // A record that alone breaks the budget never goes. It leaves with this batch (counted in `consumed`) and is dropped.
                Ok(sealed) if sealed.len() > budget => {
                    warn!("Arşiv kaydı sunucu için çok büyük, atlandı: {} bayt", sealed.len());
                }
                // Checked with this record included. The next batch starts with it.
                Ok(sealed) if sealed_bytes + sealed.len() > budget => break,
                Ok(sealed) => {
                    sealed_bytes += sealed.len();
                    records.push(ArchiveRecord {
                        record_id: wire_id,
                        rev: entry.rev,
                        sent_at_ms: archive_wire_ms(entry.sent_at_ms),
                        sealed,
                    })
                }
                Err(e) => {
                    warn!("Arşiv kaydı mühürlenemedi: {}", e);
                }
            }
            consumed += 1;
        }
        if records.is_empty() {
            // Sealing failed for all of them. Do not let that block the queue.
            self.drop_archive_queue_head(consumed.max(1));
            return;
        }
        // Every consumed entry, including the ones that could not be sealed, leaves with the batch.
        let sent: Vec<(String, u64)> =
            self.server_archive_queue[..consumed].iter().map(|e| (e.record_id.clone(), e.rev)).collect();
        let req = ServerRequest::ArchivePut { bucket, records };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight
                .insert(id, ServerInflight::ArchivePut { server_id: server_id.to_string(), records: sent });
        }
    }

    /// Removes exactly these `(record_id, rev)` entries. An entry edited while its batch was in flight carries a newer `rev` and stays queued.
    fn drop_archive_records(&mut self, records: &[(String, u64)]) {
        for (record_id, rev) in records {
            self.server_archive_queue.retain(|e| !(e.record_id == *record_id && e.rev == *rev));
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "DELETE FROM server_archive_queue WHERE record_id = ?1 AND rev = ?2",
                    params![record_id, *rev as i64],
                );
            }
        }
    }

    fn drop_archive_queue_head(&mut self, count: usize) {
        let n = count.min(self.server_archive_queue.len());
        for entry in self.server_archive_queue.drain(..n) {
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "DELETE FROM server_archive_queue WHERE record_id = ?1",
                    params![entry.record_id],
                );
            }
        }
    }

    /// Asks the server for an older page on "scroll up, show me older".
    ///
    /// This is the THIRD source of the existing multi-source design. `request_older_history` asks the peer,
    /// `request_older_sibling_history` asks my other device, and this asks the server. All three go out in parallel. Replies
    /// are deduplicated by `message_id`, and whichever arrives first fills the gap.
    ///
    /// The window `[after, before)` of a "Fetch older history" press: every page of it, from the buckets that reach it. A
    /// full restore of the same conversation may run alongside it. A full restore respects the history floor. This chain
    /// does not, inside its window.
    /// Returns whether the request went out.
    fn request_older_server_history(&mut self, conv_key: &str, group: bool, before: u64, after: u64) -> bool {
        let Some(ark) = self.archive_root_key else { return false };
        let Some(server_id) = self.history_server() else { return false };
        let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { return false };
        // Monthly buckets (see `server_archive_bucket`): the month of `before` and the months before it.
        let buckets = archive_buckets(&ark, conv_key, before);
        let req = ServerRequest::ArchiveProbe { buckets };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(
                id,
                ServerInflight::ArchiveProbe {
                    server_id,
                    conv_key: conv_key.to_string(),
                    group,
                    window: Some((before, after)),
                    next: Vec::new(),
                },
            );
            return true;
        }
        false
    }

    /// If a press's server chain failed, the cursor goes back up to the window's end. The next press then asks every source for
    /// that window again (rows are deduplicated by id), instead of skipping the server's part of it for good.
    fn reopen_fetch_window(&self, inflight: &ServerInflight) {
        if let ServerInflight::ArchiveProbe { conv_key, window: Some((before, _)), .. }
        | ServerInflight::ArchiveFetch { conv_key, window: Some((before, _)), .. } = inflight
        {
            self.reopen_fetch_cursor(conv_key, *before);
        }
    }

    /// Drops the running "Fetch older history" chains of a conversation (`forget_history_fetch`). Their late pages are then
    /// unexpected and dropped. A full restore chain stays; it respects the history floor.
    pub(crate) fn drop_archive_page_chains(&mut self, conv_key: &str) {
        self.server_inflight.retain(|_, f| !matches!(f,
            ServerInflight::ArchiveProbe { conv_key: c, window: Some(_), .. }
            | ServerInflight::ArchiveFetch { conv_key: c, window: Some(_), .. } if c == conv_key));
    }

    /// The single "fetch older history" action, on user action only. Scrolling up reads the local archive and never comes
    /// here. One press asks every source (the chat peer(s), the own connected devices, the server archive when a history
    /// server and the archive key exist) for the same window: one `HISTORY_FETCH_WINDOW_MS` older than the chat's cursor
    /// (`history_fetch_cursor`), which then moves to the window's start. The cursor never comes from the arriving rows, so
    /// an empty month still moves it, and a backdated row cannot pin it. `chat_key`: the peer device fingerprint, or the group
    /// ID. `_before_ms` (the oldest row on screen) is not used: the cursor is kept here.
    pub(crate) fn fetch_server_history(&mut self, chat_key: &str, is_group: bool, _before_ms: u64) -> Result<(), String> {
        let conv_key = if is_group {
            if !self.groups.contains_key(chat_key) {
                return Err("Grup bulunamadı".to_string());
            }
            chat_key.to_string()
        } else {
            self.identity_id_for_device(chat_key).ok_or("Bu cihazın kimliği bilinmiyor")?
        };
        let before = if is_group {
            self.history_fetch_cursor(&conv_key, "", Some(chat_key))
        } else {
            self.history_fetch_cursor(&conv_key, &self.canonical_peer_key(chat_key), None)
        };
        let after = before.saturating_sub(crate::HISTORY_FETCH_WINDOW_MS);
        // Budget before the requests: a fast answer may already want a follow-up.
        self.history_fetch_pages.insert(conv_key.clone(), crate::HISTORY_FETCH_MAX_PAGES);
        let (b, a) = (before as i64, after as i64);
        // One unreachable source is not an error: the others remain.
        let sent = if is_group {
            let peers = self.request_older_group_history(chat_key, b, a).is_ok();
            self.request_older_sibling_history(None, Some(chat_key), b, a, None).is_ok() | peers
        } else {
            let peer = self.request_older_history(chat_key, b, a).is_ok();
            self.request_older_sibling_history(Some(&conv_key), None, b, a, None).is_ok() | peer
        };
        // Returns false at once without the archive key or a history server.
        let sent = self.request_older_server_history(&conv_key, is_group, before, after) | sent;
        if !sent {
            // Nothing went out: the month stays for the next press.
            self.history_fetch_pages.remove(&conv_key);
            return Err("Geçmiş istenecek kaynağa ulaşılamıyor".to_string());
        }
        self.meta_put(&format!("hfetch:{}", conv_key), &after.to_string());
        Ok(())
    }

    /// Downloads the WHOLE server archive. For a device freshly set up or recovered.
    ///
    /// Why a separate flow: `request_older_server_history` covers "I scrolled up in this chat", so it assumes the chat is
    /// already visible. On a device set up from a recovery file, contacts and groups come back, but NO messages, and the
    /// user has nothing to scroll. This function probes the last 36 months of buckets of every known conversation with ONE
    /// `ArchiveProbe`, and fetches the buckets that hold data.
    ///
    /// `ListArchiveConversations` is deliberately NOT used. Letting the server list our conversations would mean it keeps a
    /// persistent conversation index. We can generate the buckets ourselves, and probing an absent bucket is a no-op on the server.
    pub(crate) fn restore_all_server_history(&mut self) -> Result<u32, String> {
        if self.archive_root_key.is_none() {
            return Err("Kök arşiv anahtarı yok — bu cihaz sunucudaki geçmişi çözemez".to_string());
        }
        let Some(server_id) = self.history_server() else {
            return Err("Geçmiş saklayan, bağlı bir sunucu yok".to_string());
        };
        let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else {
            return Err("Sunucuya bağlı değil".to_string());
        };

        let mut convs: Vec<(String, bool)> = self.groups.keys().map(|g| (g.clone(), true)).collect();
        convs.extend(self.contacts.values().map(|c| (c.trusted_identity_id.clone(), false)));
        if convs.is_empty() {
            return Ok(0);
        }

        let asked = convs.len() as u32;
        self.probe_next_conversation(peer_id, server_id, convs);
        Ok(asked)
    }

    /// Merges an archive page from the server into the LOCAL archive.
    ///
    /// Same rule as the existing `HistorySyncResponse` merge: presence is checked by `message_id`, not by a timestamp threshold
    /// (a timestamp check works in the wrong direction for paginated requests).
    /// `window`: a page of the user's "Fetch older history" press `(before, after)`. Only its rows sent inside the window are kept.
    /// They may come back below the history floor, which then moves down to the oldest row written.
    fn merge_server_archive(&mut self, conv_key: &str, group: bool, bucket: &str, records: Vec<ArchiveRecord>, window: Option<(u64, u64)>) {
        let Some(ark) = self.archive_root_key else { return };
        let mut merged = 0usize;
        let mut opened: Vec<(ArchiveRecord, crate::ArchivedMessage)> = Vec::new();
        for rec in records {
            let plaintext = match server_seal::open_archive_record(
                &ark,
                conv_key,
                &rec.record_id,
                rec.rev,
                bucket,
                rec.sent_at_ms,
                &rec.sealed,
            ) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Sunucu arşiv kaydı çözülemedi: {}", e);
                    continue;
                }
            };
            let archived: crate::ArchivedMessage = match ciborium::from_reader(plaintext.as_slice()) {
                Ok(a) => a,
                Err(e) => {
                    warn!("Sunucu arşiv kaydı ayrıştırılamadı: {}", e);
                    continue;
                }
            };
            opened.push((rec, archived));
        }
        // A press keeps only rows sent inside its window. The server pages by the hour-floored wire time, so a page reaches a
        // little past both ends. Those extra rows belong to the neighbouring windows. Only rows inside the window may come back
        // below the history floor.
        let floor = match window {
            Some((before, after)) => {
                opened.retain(|(_, a)| {
                    let at = if a.sent_at_ms != 0 { a.sent_at_ms } else { a.timestamp };
                    (after..before).contains(&at)
                });
                0
            }
            None => self.history_floor(conv_key),
        };
        let mut oldest_written: Option<u64> = None;
        for (rec, archived) in opened {
            // The wire ID is keyed (`archive_wire_id`). The real ID is inside the sealed record, and it must be the one the wire ID was made from.
            let Some(record_id) = archived.message_id.clone()
                .filter(|mid| archive_wire_id(&ark, conv_key, mid) == rec.record_id)
            else {
                warn!("Sunucu arşiv kaydının kimliği tutmuyor, atlandı");
                continue;
            };
            // Checked after the tag verification: an unauthenticated `rev` must not be stored.
            if !self.note_archive_rev(conv_key, &record_id, rec.rev) {
                warn!("Sunucu arşiv kaydı reddedildi: görülenden eski revizyon");
                continue;
            }
            if self.message_exists_with_id(&record_id) {
                continue;
            }
            // Cleared or pruned by the user (`history_floor`). `conv_key` is the identity ID or group ID the floor is kept under.
            let at = if archived.sent_at_ms != 0 { archived.sent_at_ms } else { archived.timestamp };
            if at < floor {
                continue;
            }
            let result = if group {
                self.archive_group_message(
                    conv_key,
                    archived.sender_identity_id.as_deref().unwrap_or(""),
                    &archived.direction,
                    archived.text.as_bytes(),
                    Some(&record_id),
                    archived.reply_to_message_id.as_deref(),
                    archived.reply_to_preview.as_deref(),
                    archived.reply_to_sender_identity_id.as_deref(),
                    archived.sent_at_ms,
                    archived.author_proof.as_deref(),
                )
            } else {
                // The server archive is keyed by IDENTITY (`conv_key` = identity_id), but the local archive is keyed by DEVICE
                // fingerprint. We write to the other side's current active device. The chat key, as elsewhere
                // (`canonical_device_for_identity`): under another device the rows would be stored where the chat never looks.
                match self.canonical_device_for_identity(conv_key) {
                    Some(fp) => self.archive_message(
                        &fp,
                        &archived.direction,
                        archived.text.as_bytes(),
                        Some(&record_id),
                        archived.status.as_deref(),
                        archived.reply_to_message_id.as_deref(),
                        archived.reply_to_preview.as_deref(),
                        archived.sent_at_ms,
                    ),
                    None => Err("Bu kimliğin aktif cihazı çözülemedi".to_string()),
                }
            };
            match result {
                Ok(()) => {
                    merged += 1;
                    oldest_written = Some(oldest_written.map_or(at, |o| o.min(at)));
                }
                Err(e) => warn!("Sunucu arşiv satırı yazılamadı: {}", e),
            }
        }
        // The user fetched rows back. From the oldest one written on, they are no longer "cleared".
        if let (Some(_), Some(o)) = (window, oldest_written) {
            self.lower_history_floor(conv_key, o);
        }
        if merged > 0 {
            // This event reached NO client. Two separate causes. (a) The type `older_history` /
            // `older_group_history` was chosen, but the contract of those two events requires a `messages` ARRAY, which was not
            // present here. Android's `applyOlderHistory` returned at once if `messages` was missing. (b) The address field was
            // written as `conversation`, but routing looks at `peer` (1:1) and `group_id` (group). Android's `isForThisPeer` filter
            // and Linux's `event_belongs_here` both dropped this event SILENTLY. The result: history restored from the server was
            // written to the DB, but did not appear in the open chat. For the user, history simply was not coming back from the server.
            //
            // Now the bulk-change event `history_backfilled` (both clients know it, meaning "refresh the screen") is published with
            // the correct address field. For 1:1, the server archive is keyed by identity while the local chat key is per device, so
            // the same translation as the `merge` path is applied.
            let mut event = serde_json::json!({
                "type": "history_backfilled", "count": merged, "source": "server"
            });
            if group {
                event["group_id"] = serde_json::json!(conv_key);
            } else if let Some(fp) = self.canonical_device_for_identity(conv_key) {
                event["peer"] = serde_json::json!(fp);
            }
            self.attachment_events.push(event.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// File attachments
// ---------------------------------------------------------------------------
//
// Nothing for DOWNLOADS lives here, on purpose. The server serves the `/p2pmessenger/filexfer/1.0.0` protocol that clients
// already speak, so an attachment on the server is just another source peer. The existing download state machine (sequential
// chunks, `append_verified_chunk`, `alt_source_peer_ids` rotation, `retry_or_give_up_download`, whole-file SHA-256 check)
// runs unchanged. Only UPLOADS are new, because filexfer has no upload verb.

impl P2PCore {
    /// The secret a file's server blob is uploaded with. Its hash (`server_proto::blob_id_for_upload_secret`) is the file ID.
    /// Derived from the local history key and `file_key`. Recipients hold `file_key` but not the history key, so they cannot
    /// claim the blob first. It starts with `tag` (the author tag, `group_msg_tag`), which the ID shows in the clear.
    pub(crate) fn blob_upload_secret(&self, file_key: &[u8; 32], tag: &[u8]) -> Option<Vec<u8>> {
        if tag.len() != server_proto::BLOB_TAG_LEN {
            return None;
        }
        let key = self.history_key.as_ref()?;
        let hash = Sha256::new_with_prefix(b"typeon-blob-upload-v1").chain_update(key).chain_update(file_key).finalize();
        let mut secret = tag.to_vec();
        secret.extend_from_slice(&hash[..server_proto::BLOB_UPLOAD_SECRET_LEN - server_proto::BLOB_TAG_LEN]);
        Some(secret)
    }

    /// Queues an encrypted file for upload to the server.
    pub(crate) fn queue_blob_upload(&mut self, file_id: &str, file_key: &[u8; 32], total_chunks: u32) {
        if !self.servers.iter().any(|s| s.route_messages) {
            return;
        }
        if self.server_blob_uploads.iter().any(|u| u.file_id == file_id) {
            return;
        }
        // The tag is the first 16 hex characters of the ID (`blob_id_for_upload_secret`).
        let Some(tag) = file_id.get(..server_proto::BLOB_TAG_LEN * 2).and_then(|t| hex::decode(t).ok()) else { return };
        let Some(upload_secret) = self.blob_upload_secret(file_key, &tag) else { return };
        // A file ID that is not the hash of this secret (one not made by `begin_outgoing_file`) cannot be uploaded under its own name.
        if server_proto::blob_id_for_upload_secret(&upload_secret).as_deref() != Some(file_id) {
            return;
        }
        let up = PendingBlobUpload {
            file_id: file_id.to_string(),
            upload_secret,
            next_chunk: 0,
            total_chunks,
            // The hash of the encrypted bytes is computed in `sha256_file` at `BlobFinish` time, so the file is not read through
            // once more here. (A struct field existed for it, but was never written, only read from disk and dropped, so it was
            // removed. The `server_blob_uploads.enc_sha256` column stays for schema compatibility, and is written empty.)
            inflight: HashSet::new(),
            done: HashSet::new(),
            window: BLOB_WINDOW_START,
            rtt_min: u64::MAX,
            server_id: None,
            enc_sha256: None,
            hashing: None,
            restarts: 0,
        };
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_blob_uploads (file_id, next_chunk, total_chunks, enc_sha256, created_at, upload_secret)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![up.file_id, up.next_chunk as i64, up.total_chunks as i64, Vec::<u8>::new(), current_time_ms() as i64, up.upload_secret],
            );
        }
        self.server_blob_uploads.push(up);
    }

    /// Uploads the next chunks of the head upload, up to its window in flight.
    fn server_flush_blobs(&mut self, server_id: &str, peer_id: PeerId) {
        // Quota or rate error on a chunk: wait, as `Deposit` does.
        if self.server_rt.get(server_id).map_or(false, |r| mono_ms() < r.deposit_backoff_until) {
            return;
        }
        // Progress counts for one server only (see `PendingBlobUpload.server_id`). After a restart the server is not remembered
        // (`None`): start over, or the chunks could end up split between two servers. The server is stored with the upload, so
        // a restart resumes from the stored watermark at the same server.
        let Some(head) = self.server_blob_uploads.first_mut() else { return };
        if head.server_id.as_deref() != Some(server_id) {
            head.inflight.clear();
            head.done.clear();
            head.next_chunk = 0;
            head.server_id = Some(server_id.to_string());
            let file_id = head.file_id.clone();
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE server_blob_uploads SET server_id = ?2, next_chunk = 0 WHERE file_id = ?1",
                    params![file_id, server_id],
                );
            }
        }
        let Some(up) = self.server_blob_uploads.first().cloned() else { return };
        let Ok(path) = self.enc_path_for(&up.file_id) else { return };

        // Pipeline: up to `BLOB_PIPELINE_DEPTH` chunks may be in flight at once. With one chunk in flight, speed was limited by chunk size / round trip.
        if up.done.len() < up.total_chunks as usize {
            // `.enc` uses FIXED steps; the step is per file (see `file_chunk_size`).
            let chunk_size = self.file_chunk_size(&up.file_id);
            let mut sent = 0usize;
            for idx in 0..up.total_chunks {
                if up.inflight.len() + sent >= up.window {
                    break;
                }
                if up.done.contains(&idx) || up.inflight.contains(&idx) {
                    continue;
                }
                let data = match crate::attachments::read_chunk_from_disk_with(&path, idx, chunk_size) {
                    Ok(Some(d)) => d,
                    _ => {
                        self.finish_blob_upload(&up.file_id);
                        return;
                    }
                };
                let req = ServerRequest::BlobPut {
                    upload_secret: up.upload_secret.clone(),
                    chunk_index: idx,
                    chunk_size: chunk_size as u32,
                    total_chunks: up.total_chunks,
                    data,
                };
                if let Some(id) = self.send_server_request(peer_id, req) {
                    if let Some(u) = self.server_blob_uploads.first_mut() {
                        u.inflight.insert(idx);
                    }
                    self.server_inflight.insert(
                        id,
                        ServerInflight::BlobPut {
                            server_id: server_id.to_string(),
                            blob_id: up.file_id.clone(),
                            chunk_index: idx,
                            total_chunks: up.total_chunks,
                            sent_at: mono_ms(),
                        },
                    );
                    sent += 1;
                }
            }
            return;
        }

        // All chunks are acknowledged: seal. One finish in flight, and the hash (a full read of up to 4 GiB under the core lock)
        // is taken once. ponytail: that single read still stalls the poll loop for a multi-GB file. Hash on a blocking task if it shows.
        let finishing = self
            .server_inflight
            .values()
            .any(|i| matches!(i, ServerInflight::BlobFinish { blob_id, .. } if *blob_id == up.file_id));
        if up.next_chunk >= up.total_chunks && !finishing {
            // The hash runs on its own thread. The sweep comes back for it.
            let hashed = match (&up.enc_sha256, &up.hashing) {
                (Some(h), _) => Some(Some(h.clone())),
                (None, Some(cell)) => cell.get().cloned(),
                (None, None) => {
                    let cell = std::sync::Arc::new(std::sync::OnceLock::new());
                    let (c, p) = (cell.clone(), path.clone());
                    std::thread::spawn(move || {
                        let _ = c.set(sha256_file(&p));
                    });
                    if let Some(u) = self.server_blob_uploads.first_mut() {
                        u.hashing = Some(cell);
                    }
                    None
                }
            };
            let enc_sha256 = match hashed {
                Some(Some(h)) => h,
                // The file cannot be read: abandon the upload. The direct peer path keeps serving it.
                Some(None) => {
                    self.finish_blob_upload(&up.file_id);
                    return;
                }
                // Still hashing: `server_sweep` looks again on each turn.
                None => return,
            };
            if let Some(u) = self.server_blob_uploads.first_mut() {
                u.enc_sha256 = Some(enc_sha256.clone());
                u.hashing = None;
            }
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE server_blob_uploads SET enc_sha256 = ?2 WHERE file_id = ?1",
                    params![up.file_id, enc_sha256],
                );
            }
            let req = ServerRequest::BlobFinish {
                upload_secret: up.upload_secret.clone(),
                total_chunks: up.total_chunks,
                enc_sha256,
            };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(
                    id,
                    ServerInflight::BlobFinish { server_id: server_id.to_string(), blob_id: up.file_id.clone() },
                );
            }
        }
    }

    fn advance_blob_upload(&mut self, file_id: &str, chunk_index: u32, _total: u32, server_id: &str) {
        // A late `Ok` from a server the upload has since left does not count.
        if let Some(up) = self
            .server_blob_uploads
            .iter_mut()
            .find(|u| u.file_id == file_id && u.server_id.as_deref() == Some(server_id))
        {
            up.inflight.remove(&chunk_index);
            up.done.insert(chunk_index);
            // `next_chunk` is now the watermark of contiguously acknowledged chunks. If the process dies, the upload resumes from
            // here. Chunks are acknowledged out of order in the pipeline, so "highest + 1" would be WRONG: a gap in between would
            // be silently skipped. It moves forward only from the last watermark: `done` only grows (a reset also sets `next_chunk`
            // to 0), so nothing below it can be missing.
            let mut watermark = up.next_chunk;
            while up.done.contains(&watermark) {
                watermark += 1;
            }
            up.next_chunk = watermark;
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE server_blob_uploads SET next_chunk = ?2 WHERE file_id = ?1",
                    params![file_id, watermark as i64],
                );
            }
        }
        // Refill the window without waiting: the blob path only, not a full sweep per acknowledged chunk. Only for the server the
        // head upload goes to (`server_flush_blobs` would move it to this one).
        let head_here = self.server_blob_uploads.first().is_some_and(|u| u.server_id.as_deref() == Some(server_id));
        if let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id).filter(|_| head_here) {
            self.server_flush_blobs(server_id, peer_id);
        }
    }

    /// The server lost the upload (swept while we were offline, or chunks missing): send every chunk again. Gives up after a few
    /// rounds, so a server that keeps losing it cannot loop the upload forever.
    fn restart_blob_upload(&mut self, file_id: &str, server_id: &str) {
        const MAX_BLOB_RESTARTS: u8 = 3;
        let Some(up) = self
            .server_blob_uploads
            .iter_mut()
            .find(|u| u.file_id == file_id && u.server_id.as_deref() == Some(server_id))
        else {
            return;
        };
        if up.restarts >= MAX_BLOB_RESTARTS {
            warn!("Sunucu blob'u tekrar tekrar kaybetti, yükleme bırakıldı: {}", file_id);
            self.finish_blob_upload(file_id);
            return;
        }
        up.restarts += 1;
        up.inflight.clear();
        up.done.clear();
        up.next_chunk = 0;
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE server_blob_uploads SET next_chunk = 0 WHERE file_id = ?1", params![file_id]);
        }
        self.server_sweep_at = 0;
    }

    /// Gives an upload up. Chunks already on a server are deleted there (`BlobDelete`), or they hold its quota until the 24 h sweep.
    pub(crate) fn finish_blob_upload(&mut self, file_id: &str) {
        let started = self.server_blob_uploads.iter().find(|u| u.file_id == file_id).and_then(|u| {
            u.server_id.clone().filter(|_| !u.done.is_empty() || !u.inflight.is_empty()).map(|sid| (sid, u.upload_secret.clone()))
        });
        if let Some((peer_id, upload_secret)) =
            started.and_then(|(sid, secret)| self.server_rt.get(&sid).and_then(|r| r.peer_id).map(|p| (p, secret)))
        {
            let _ = self.send_server_request(peer_id, ServerRequest::BlobDelete { upload_secret });
        }
        self.forget_blob_upload(file_id);
    }

    /// Drops an upload from the queue (done, or given up).
    fn forget_blob_upload(&mut self, file_id: &str) {
        self.server_blob_uploads.retain(|u| u.file_id != file_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM server_blob_uploads WHERE file_id = ?1", params![file_id]);
        }
    }
}

/// The archive buckets of one conversation: the month of `newest_ms` and the 35 before it. Purge, scroll-up and full restore must agree on this window.
fn archive_buckets(ark: &[u8; 32], conv_key: &str, newest_ms: u64) -> Vec<String> {
    let newest = server_seal::archive_epoch_for(newest_ms);
    (newest.saturating_sub(35)..=newest)
        .rev()
        .filter_map(|epoch| server_seal::server_archive_bucket(ark, conv_key, epoch).ok())
        .collect()
}

/// The `sent_at_ms` the server sees, floored to the hour (same epoch as the exact time). Restore orders by the time inside the sealed record.
fn archive_wire_ms(sent_at_ms: u64) -> u64 {
    sent_at_ms - sent_at_ms % 3_600_000
}

/// The record ID the server sees: keyed with the archive key, so the two ends of a chat (each with its own key) store one message under
/// unrelated IDs. The real ID is inside the sealed record (`ArchivedMessage.message_id`).
fn archive_wire_id(ark: &[u8; 32], conv_key: &str, record_id: &str) -> String {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(conv_key.as_bytes()), ark);
    let info = [b"typeon-archive-record-id:".as_slice(), record_id.as_bytes()].concat();
    let mut out = [0u8; 16];
    // 16 bytes is far below the HKDF output limit, so this cannot fail.
    let _ = hk.expand(&info, &mut out);
    hex::encode(out)
}

/// A mailbox ID is a read capability. Logs show 24 bits of its hash, never a part of the ID itself.
/// The signing keys of a mailbox's `Register` proof (`server_seal::mailbox_proof_seeds`).
fn mailbox_proof_keys(secret: &[u8], mailbox: &str) -> Option<(SigningKey, MlDsaSigningKey<MlDsa87>)> {
    let (seed, seed_pq) = server_seal::mailbox_proof_seeds(secret, mailbox).ok()?;
    let seed_pq: ml_dsa::Seed = seed_pq.as_slice().try_into().ok()?;
    Some((SigningKey::from_bytes(&seed), MlDsaSigningKey::<MlDsa87>::from_seed(&seed_pq)))
}

/// The server ID of a mailbox whose readers all hold `secret` (a session box: the session secret; a call relay box: the pair key).
/// It is a hash of the box's proof key (`server_proto::key_bound_mailbox_id`). The sender, who holds the same secret, computes it too.
/// The server refuses a `Register` from any other key, so knowing the ID does not make a reader.
///
/// Memoized per secret: an ML-DSA-87 key is derived for each, and this runs for every session on each sweep, fetch and deposit.
// ponytail: the memo is dropped whole past 4096 entries. Use an LRU if a device ever holds that many live sessions.
pub(crate) fn key_bound_mailbox_id(secret: &[u8]) -> Option<String> {
    static MEMO: std::sync::Mutex<Option<HashMap<[u8; 32], String>>> = std::sync::Mutex::new(None);
    let tag: [u8; 32] = Sha256::digest(secret).into();
    if let Some(id) = MEMO.lock().ok()?.get_or_insert_with(HashMap::new).get(&tag) {
        return Some(id.clone());
    }
    let (signing, signing_pq) = mailbox_proof_keys(secret, server_proto::KEY_BOUND_MAILBOX_PREFIX)?;
    let hash = server_proto::mailbox_key_hash(&signing.verifying_key().to_bytes(), &signing_pq.verifying_key().encode());
    let id = server_proto::key_bound_mailbox_id(&hash);
    let mut memo = MEMO.lock().ok()?;
    let memo = memo.get_or_insert_with(HashMap::new);
    if memo.len() >= 4096 {
        memo.clear();
    }
    memo.insert(tag, id.clone());
    Some(id)
}

fn mailbox_log_id(id: &str) -> String {
    hex::encode(&Sha256::digest(id.as_bytes())[..3])
}

/// `server_deposit_locations` / `server_deposited` key: `"mailbox|message_id"` for a `Message` (one entry per target), anything else as it is.
fn location_message_id(key: &str) -> &str {
    key.split_once('|').map_or(key, |(_, mid)| mid)
}

/// SHA-256 of a whole file, without holding it in memory (attachments can reach 4 GiB, see `MAX_ATTACHMENT_SIZE`).
fn sha256_file(path: &std::path::Path) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
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

/// Short type name of an envelope, for logging. See `try_server_deposit`.
/// The "have I already deposited this envelope to this server?" key.
///
/// Before this was fixed, `already_deposited` and `note_server_deposit` recognized only the `NetworkEnvelope::Message` arm (`m.header.message_id`)
/// and returned `false` for every other type. `Handshake` and `IdentityExchange` cannot enter `awaiting_confirmation`, so their only safety net was
/// the `pending_envelopes` queue, which is retried on EVERY poll turn. They were re-deposited to the server about once a second. Each was about 15 KB,
/// so the depositor's `bytes_mail` quota (256 MB) filled within a few hours. From then on every server delivery of that device, to ANY peer, got
/// `QuotaExceeded`. Secondary devices were hit hardest, since reaching them almost always goes through a fresh handshake or the server.
///
/// For `Message` the key is still the `message_id` (so the same message re-serialized is also deduplicated). For other types it is a digest of the
/// envelope bytes, which is stable because the queue retries by cloning the same envelope.
pub(crate) fn deposit_dedup_key(envelope: &NetworkEnvelope, bytes: &[u8]) -> String {
    match envelope {
        NetworkEnvelope::Message(m) => m.header.message_id.clone(),
        _ => {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            format!("raw:{}", hex::encode(&hasher.finalize()[..16]))
        }
    }
}

pub(crate) fn envelope_kind(envelope: &NetworkEnvelope) -> String {
    match envelope {
        NetworkEnvelope::Handshake(_) => "Handshake".to_string(),
        NetworkEnvelope::IdentityExchange(_) => "IdentityExchange".to_string(),
        NetworkEnvelope::Message(m) => format!("Message/{}", m.header.message_id.chars().take(8).collect::<String>()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::IdentityExchange;

    fn core_with_meta() -> P2PCore {
        let mut core = P2PCore::new();
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE app_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)").unwrap();
        core.db = Some(conn);
        core
    }

    #[test]
    fn archive_key_rotation_is_durable_and_resumable() {
        let mut core = core_with_meta();
        assert!(!core.set_archive_root_key(&[1u8; 33]));
        assert!(core.set_archive_root_key(&[1u8; 32]));
        core.rotate_archive_root_key();
        let new = core.archive_root_key.unwrap();
        assert_ne!(new, [1u8; 32]);
        // Sync and backfill ran. The old buckets wait for the server.
        assert_eq!(core.meta_str("ark_todo"), None);
        assert_eq!(core.meta_str("ark_purge"), Some(hex::encode([1u8; 32])));
        // The client restarts with the key file it did not rewrite.
        assert!(core.set_archive_root_key(&[1u8; 32]));
        assert_eq!(core.archive_root_key, Some(new));
        // Once it loads the new key, the copy in the DB is removed.
        assert!(core.set_archive_root_key(&new));
        assert_eq!(core.meta_str("ark"), None);
        // The purge is confirmed only for the keys it covered.
        let peer = PeerId::random();
        core.send_archive_purge(peer, "s".into(), "other".into(), Vec::new());
        assert!(core.meta_str("ark_purge").is_some());
        core.send_archive_purge(peer, "s".into(), hex::encode([1u8; 32]), Vec::new());
        assert_eq!(core.meta_str("ark_purge"), None);
    }

    #[test]
    fn only_the_primary_replaces_the_archive_key_and_never_with_a_retired_one() {
        let mut core = core_with_meta();
        assert!(core.adopt_archive_key(&[1u8; 32], false), "none yet: any sibling");
        assert!(!core.adopt_archive_key(&[2u8; 32], false));
        assert!(core.adopt_archive_key(&[2u8; 32], true));
        assert!(!core.adopt_archive_key(&[1u8; 32], true), "an older sync must not bring the old key back");
        assert_eq!(core.archive_root_key, Some([2u8; 32]));
        assert_eq!(core.meta_str("ark_purge"), Some(hex::encode([1u8; 32])), "the old buckets are purged");
        assert_eq!(core.meta_str("ark_todo"), None, "a secondary does not backfill");
    }

    #[test]
    fn an_older_archive_revision_is_refused() {
        let mut core = P2PCore::new();
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE server_archive_revs (conv_key TEXT NOT NULL, record_id TEXT NOT NULL, rev INTEGER NOT NULL, PRIMARY KEY (conv_key, record_id))",
        )
        .unwrap();
        core.db = Some(conn);
        assert!(core.note_archive_rev("c", "m", 5));
        assert!(core.note_archive_rev("c", "m", 5));
        assert!(!core.note_archive_rev("c", "m", 4), "rollback");
        assert!(core.note_archive_rev("c", "m", 6));
        assert!(!core.note_archive_rev("c", "m", 5));
        assert!(core.note_archive_rev("other", "m", 1), "the id is the peer's choice: scoped to the chat");
    }

    #[test]
    fn archive_ids_and_location_keys() {
        let a = archive_wire_id(&[1u8; 32], "c", "m");
        assert_eq!(a, archive_wire_id(&[1u8; 32], "c", "m"));
        assert_ne!(a, archive_wire_id(&[2u8; 32], "c", "m"), "two identities must not share an id");
        assert_ne!(a, "m");
        assert_eq!(location_message_id("mbox|msg-1"), "msg-1");
        assert_eq!(location_message_id("raw:abcd"), "raw:abcd");
    }

    fn ident() -> NetworkEnvelope {
        NetworkEnvelope::IdentityExchange(IdentityExchange {
            identity_id: "id".into(),
            device_fingerprint: "fp".into(),
            device_name: "dev".into(),
            sign_pubkey_ed25519: vec![1, 2, 3],
            sign_pubkey_mldsa: vec![4],
            kem_pubkey_x25519: vec![5],
            kem_pubkey_mlkem: vec![6],
            device_add: None,
            revokes: Vec::new(),
            device_add_signer: None,
            pairing_proof: Vec::new(),
            link_consent: Vec::new(),
            link_consent_pq: Vec::new(),
            prekey: None,
            timestamp: 0,
            signature: Vec::new(),
            signature_pq: Vec::new(),
        })
    }

    /// Root cause: envelopes that were NOT `Message` had no dedup key, so `already_deposited` always returned `false`. The `pending_envelopes` queue
    /// then re-deposited the SAME handshake to the server on every poll turn. Within hours the depositor's quota filled up, and all server delivery
    /// of that device locked up.
    #[test]
    fn non_message_envelopes_have_a_stable_dedup_key() {
        let env = ident();
        let bytes = b"ayni-baytlar";
        assert_eq!(
            deposit_dedup_key(&env, bytes),
            deposit_dedup_key(&env, bytes),
            "ayni zarf ayni anahtari vermeli, yoksa tekilleştirme hic calismaz"
        );
        assert_ne!(
            deposit_dedup_key(&env, bytes),
            deposit_dedup_key(&env, b"baska-baytlar"),
            "farkli zarf farkli anahtar almali, yoksa gercek bir zarf yutulur"
        );
        assert!(deposit_dedup_key(&env, bytes).starts_with("raw:"));
    }
}
