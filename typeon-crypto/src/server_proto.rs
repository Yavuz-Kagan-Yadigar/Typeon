//! Server (store-and-forward) protocol: the wire types shared by client and server.
//!
//! The `pub` is needed because `typeon-server` links this core as a path
//! dependency and uses these types directly. There is one definition, not a
//! second copy to keep in sync.
//!
//! ## What the server is not
//!
//! It is not a libp2p Circuit Relay v2. A relay builds a live circuit while both
//! peers are connected and stores nothing. This server does the opposite: when
//! the recipient is offline it writes the envelope to disk, delivers it when the
//! recipient returns, and keeps it until delivery is acknowledged.
//!
//! ## Two separate stores
//!
//! 1. **Mail**: sealed envelopes. Deleted when the recipient `Ack`s them, and at
//!    most `mailbox_ttl_ms` old.
//! 2. **Archive**: history. Mail envelopes cannot be used here: ratchet message
//!    keys are forward-secret and deleted after use, so last week's envelope
//!    cannot be decrypted today. The archive holds separate records that the
//!    client re-encrypts with its `archive_key` (see
//!    `server_seal::seal_archive_record`).
//!
//! ## Size limit: a hard cap on the wire
//!
//! The CBOR codec of `libp2p-request-response` caps request size at 1 MiB
//! (`cbor.rs`: `REQUEST_SIZE_MAXIMUM`, an associated const that `Behaviour::new`
//! cannot change). It reads with `io.take()`, so an oversized request is cut
//! silently and CBOR decoding then fails. The response cap is 10 MiB.
//!
//! Gossipsub's `max_transmit_size` is also exactly 1 MiB. A `FileOffer` that fits
//! gossipsub (with a large `preview_jpeg`) may not fit in a CBOR `Deposit`. So
//! `MAX_DEPOSIT_BYTES` is well below the cap, and envelopes over it are never
//! tried on the server and go to gossipsub directly.

use serde::{Deserialize, Serialize};

/// Server RPC protocol id. Carried on `request_response::cbor::Behaviour`, as
/// `FILE_TRANSFER_PROTOCOL` and `KEEPALIVE_PROTOCOL` are.
///
/// Both ends register `ProtocolSupport::Full`, so the server can send `Notify`
/// on its own (see `ServerRequest::Notify`). `request_response` only decides
/// which side starts a request, not the direction.
pub const SERVER_PROTOCOL: &str = "/typeon/server/1.0.0";

/// Live call-media relay: one long-lived libp2p stream per client, opened while
/// the client is in a call. Frames are `[u16 mailbox len][mailbox][u32 len][data]`
/// (core `call::encode_frame`). Client to server: "push `data` to whoever is
/// connected and listening on `mailbox`". The mailbox is the target's
/// `key_bound_mailbox_id` for the pair key, registered for the call. The sender
/// is not checked against the readers: the id is the capability, and the receiver
/// registers it. Server to client: the same frame with an empty mailbox.
/// Nothing is stored. A target that is not connected misses the frame, which is
/// correct for live audio and video. `data` is already end-to-end encrypted with
/// a per-call key the server never sees (`MessageContent::Call`).
pub const RELAY_PROTOCOL: &str = "/typeon/relay/1.0.0";

/// Wire format version, exchanged in `Hello`/`Welcome`.
/// 2: `Register` answers `Registered { proof_needed, refused }`.
/// 4: blob requests carry `upload_secret` instead of `blob_id`.
/// 5: session and relay mailbox ids are derived from their proof key
///    (`key_bound_mailbox_id`); the server refuses any other key for them.
/// 6: upload secrets are 24 bytes and start with the file's author tag
///    (`blob_id_for_upload_secret`).
/// 7: the id hashes only the secret bytes after the tag. A group file's tag is
///    made per file (core `group_msg_tag`).
/// 8: archive bucket ids are hashes of per-bucket purge secrets; `ArchivePurge`
///    carries the secrets (`archive_bucket_for_purge_secret`).
pub const SERVER_PROTOCOL_VERSION: u16 = 8;

/// Maximum payload of one `Deposit`. See the size-limit note at the top of the
/// module: the codec's hard limit is 1 MiB, and this leaves room for CBOR framing.
/// Envelopes over this are not tried on the server.
pub const MAX_DEPOSIT_BYTES: usize = 900 * 1024;

/// Maximum size of one `Fetch` response. The codec allows 10 MiB, but the
/// response is decoded inside the roughly 1 Hz `poll_events` cycle, and a large
/// buffer there would stall the loop.
pub const MAX_FETCH_BATCH_BYTES: u32 = 512 * 1024;
pub const MAX_FETCH_BATCH_ITEMS: u32 = 64;

/// Records per `ArchivePut`. The client sends up to 50. Each record costs the
/// server a SELECT and an INSERT inside its single event loop.
pub const MAX_ARCHIVE_PUT_RECORDS: usize = 256;

/// Clock tolerance for `Enroll` and `Rebind` timestamps. A signature outside this
/// window is rejected (`ServerErrorCode::Stale`).
pub const ENROLL_MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// A mailbox address: `key_bound_mailbox_id` of a session or relay box
/// (`mk_<hex16>`), `server_seal::first_contact_mailbox_id` (`mb_<hex16>`), or an
/// archive bucket (`ar_<hex16>`). The server reads only the `mk_` prefix, which
/// makes it check the `Register` proof key.
pub type MailboxId = String;

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerRequest {
    // --- Enrollment ---
    /// First message on a new connection. Answered with `Welcome`.
    Hello { version: u16 },

    /// Enrolls with the operator's invite token.
    ///
    /// These keys are not the device's identity keys. They are a fresh pair made
    /// only for this server. The server needs two things: a gate against Sybil
    /// registrations (the invite token), and a revocable handle. Both are met by
    /// an anonymous key. Sending the device fingerprint or identity id would give
    /// the operator a provable list of who uses the server, even across servers
    /// and after a PeerId change. A keypair is cheap, and that cost is not worth it.
    ///
    /// Signed input: `version || server_peer_id || invite_token || challenge || ts_ms`.
    /// `server_peer_id` must be included. Otherwise a malicious server could
    /// replay the `Enroll` it received against another server and register under
    /// that user. `challenge` binds the signature to the single-use value the
    /// server generated for this connection.
    Enroll {
        version: u16,
        #[serde(with = "serde_bytes")]
        invite_token: Vec<u8>,
        /// Ed25519 public key (32 bytes).
        #[serde(with = "serde_bytes")]
        enroll_pk: Vec<u8>,
        /// ML-DSA-87 public key (2592 bytes). The signature is hybrid like the rest
        /// of the protocol. A classical signature alone would let a
        /// harvest-now-break-later attacker forge registrations in the future.
        /// Confidentiality is unaffected (content encryption does not depend on
        /// this signature), but the rule "every signature is hybrid" would break.
        #[serde(with = "serde_bytes")]
        enroll_pk_pq: Vec<u8>,
        /// The `Welcome.challenge` just received. It is in the signed input
        /// (`enroll_signing_input`). The server treats it as single-use, and it
        /// also binds the signature to this connection. Without it, a captured
        /// signature would still be valid on a fresh connection that gets a new
        /// challenge.
        #[serde(with = "serde_bytes")]
        challenge: Vec<u8>,
        ts_ms: u64,
        /// Ed25519 signature.
        #[serde(with = "serde_bytes")]
        sig: Vec<u8>,
        /// ML-DSA-87 signature over the same bytes. Both must verify.
        #[serde(with = "serde_bytes")]
        sig_pq: Vec<u8>,
    },

    /// Binds an existing record to a new libp2p `PeerId`, for when the app is
    /// reinstalled or `libp2p_identity.key` is lost. `enroll_pk` proves ownership.
    /// It does not consume an invite token. Otherwise a device enrolled with a
    /// single-use invite could not reconnect after one reinstall.
    ///
    /// Signed input: see `rebind_signing_input`. The `Hello` challenge and the
    /// caller's PeerId are part of it, and neither is sent in the request.
    Rebind {
        #[serde(with = "serde_bytes")]
        enrollment_id: Vec<u8>,
        ts_ms: u64,
        #[serde(with = "serde_bytes")]
        sig: Vec<u8>,
        #[serde(with = "serde_bytes")]
        sig_pq: Vec<u8>,
    },

    // --- Mailbox (transit) ---
    /// Declares which mailboxes this client is interested in. Idempotent.
    ///
    /// Two jobs: (a) the server accepts envelopes for these mailboxes and serves
    /// them through `Fetch`, and (b) it can send `Notify` when something arrives.
    /// `drop` removes a generation that is no longer read after rotation.
    ///
    /// A new id needs a `MailboxProof` in `proofs`. Without one, the id comes back
    /// in `Registered.proof_needed` and the client sends it again with a proof. An
    /// id in `Registered.refused` is refused for good (mailbox cap, reader cap, bad
    /// proof, or another key). Sending it again gets the same answer.
    Register {
        add: Vec<MailboxId>,
        drop: Vec<MailboxId>,
        proofs: Vec<MailboxProof>,
    },

    /// Deposits a sealed envelope in a mailbox.
    ///
    /// Quota is charged to the depositor, not the mailbox owner. A spam sender uses
    /// up its own quota, and nobody can fill a victim's mailbox to deny it service.
    Deposit { mailbox: MailboxId, #[serde(with = "serde_bytes")] sealed: Vec<u8> },

    /// Fetches from several mailboxes in one round trip.
    ///
    /// A device with about 50 contacts has about 100 live mailbox ids (current and
    /// one earlier generation). Sending 100 requests every poll cycle would be
    /// wasteful.
    ///
    /// `cursors`: for each mailbox, the highest `seq` already processed. The server
    /// returns exactly the items above it (0 means from the start).
    Fetch {
        cursors: Vec<(MailboxId, u64)>,
        max_items: u32,
        max_bytes: u32,
    },

    /// Acknowledges everything up to `seq` in one mailbox, so the server may delete it.
    /// Cumulative and idempotent. A lost `Ack` causes at most one extra redelivery,
    /// never a gap.
    ///
    /// The client sends it only after the envelope is decrypted and written to the
    /// archive. This is the same rule as `send_ack` in receive.rs, which sends the
    /// ack after `archive_message` succeeds. Acking on a transient failure (full
    /// disk, DB error) would delete a message that is stored nowhere.
    Ack { acks: Vec<(MailboxId, u64)> },

    /// Withdraws the sender's own undelivered packet.
    ///
    /// `Ack` cannot do this, because it requires `depositor != acker`. A sender
    /// that could make the server delete a message before the recipient saw it
    /// could abuse that. The reverse gap was real, though: a message sent by
    /// mistake stayed on the server for 30 days if the recipient was offline, and
    /// the sender had no way to remove it.
    ///
    /// This request closes that gap without enabling abuse. The server deletes
    /// only rows where `depositor == requester`, so you can withdraw only what you
    /// deposited. If the recipient already fetched the packet, it is no longer in
    /// the mailbox and withdrawing it does nothing. Deleting for everyone then
    /// uses the normal "delete" message.
    Cancel { mailbox: MailboxId, seqs: Vec<u64> },

    // --- Archive (history) ---
    /// Loads archive records. `bucket` comes from `server_seal::server_archive_bucket`:
    /// conversation plus month (see that function's note).
    ArchivePut {
        bucket: MailboxId,
        records: Vec<ArchiveRecord>,
    },

    /// Probes which buckets exist and how full they are. A freshly installed device
    /// checks the last 24 to 60 months in one request. The server does not need a
    /// permanent, browsable index of conversations.
    ArchiveProbe { buckets: Vec<MailboxId> },

    /// Pages through one bucket, newest first. `before_ms: None` returns the newest page.
    ///
    /// Server trust: the server can answer with an older revision of a record, or
    /// leave records out. The seal stops forgery, not rollback. Only a device that
    /// keeps its own `record_id`/`rev` state notices (see the known limit in
    /// `server_seal`).
    ArchiveFetch {
        bucket: MailboxId,
        /// Cursor: the last record of the previous page, `(before_ms, before_id)`.
        /// Many records share an hour-coarsened `sent_at_ms`.
        before_ms: Option<u64>,
        #[serde(default)]
        before_id: Option<String>,
        max_items: u32,
        max_bytes: u32,
    },

    /// Deletes this device's history on the server. This is tied to the visible
    /// settings action and to `remove_server`. The app cannot prove the server
    /// actually deleted it. SECURITY.md documents this.
    ///
    /// Carries each bucket's purge secret (64 hex chars), not the bucket id: the id is
    /// a hash of the secret (`archive_bucket_for_purge_secret`), so the server and any
    /// peer that learns an id can read the sealed rows but cannot delete them. Only the
    /// holders of the archive key can.
    ArchivePurge { purge_secrets: Vec<String> },

    // --- Attachment blobs (upload direction only) ---
    /// Uploads one file chunk.
    ///
    /// Downloads are not here. The server registers the `/p2pmessenger/filexfer/1.0.0`
    /// protocol with `ProtocolSupport::Inbound`, the same one clients speak, so a
    /// server-held attachment is just another source peer. The whole client download
    /// state machine (ordered chunks, `append_verified_chunk`, the
    /// `alt_source_peer_ids` rotation, `retry_or_give_up_download`,
    /// `check_stalled_downloads`, whole-file SHA-256) is reused unchanged.
    ///
    /// `data` is read from the `.enc` file on disk as it is. Attachments store the
    /// wire format on disk, so nothing is re-encrypted (see `read_chunk_from_disk`).
    BlobPut {
        /// The uploader's secret. The server stores the blob under
        /// `blob_id_for_upload_secret(upload_secret)`, which is the file id recipients
        /// download by. A recipient knows only that id, so it cannot claim the blob
        /// before the sender uploads it.
        #[serde(with = "serde_bytes")]
        upload_secret: Vec<u8>,
        chunk_index: u32,
        total_chunks: u32,
        /// Part step of this blob, in bytes, without the AEAD tag.
        ///
        /// The server writes chunk `i` at `i * (chunk_size + 16)`. Without this field
        /// the server guessed the step from its own constant. A client using another
        /// size then put every chunk after the first in the wrong place. The file was
        /// corrupted, the hash failed at the end, the blob was rejected, and the
        /// client retried forever. This happened on a real device and invalidated a
        /// speed measurement.
        ///
        /// `#[serde(default)]` with 0 means the legacy 256 KiB, so an old client keeps
        /// working.
        #[serde(default)]
        chunk_size: u32,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },

    /// Finishes an upload and marks the blob servable.
    ///
    /// `enc_sha256` covers the ENCRYPTED bytes. The server can check it without
    /// decrypting, and never serves a truncated upload.
    BlobFinish {
        #[serde(with = "serde_bytes")]
        upload_secret: Vec<u8>,
        total_chunks: u32,
        #[serde(with = "serde_bytes")]
        enc_sha256: Vec<u8>,
    },

    BlobDelete {
        #[serde(with = "serde_bytes")]
        upload_secret: Vec<u8>,
    },

    // --- Server to client (the one request in the reverse direction) ---
    /// "Mail is waiting." The payload is not carried here, and mailbox ids are not
    /// listed. The client replies `Ok` and calls `Fetch` in its next `poll_events`
    /// cycle. Listing ids would let a hostile peer probe for them, and it is not
    /// needed because `Fetch` is cheap.
    Notify,

    /// `Notify` WITH the item, saving the client's `Fetch` round trip (1 to 2 s over
    /// Tor on mobile data, most of a call ring's delay). The server sends it only
    /// when this item is the reader's ONLY unacknowledged one in the mailbox. So
    /// processing it and moving the cursor to its `seq` cannot skip anything.
    /// Otherwise it sends a plain `Notify`.
    Push { item: MailItem },
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerResponse {
    Welcome {
        version: u16,
        /// Single-use `Enroll` signing input (32 random bytes).
        #[serde(with = "serde_bytes")]
        challenge: Vec<u8>,
        enrolled: bool,
        /// The id of this PeerId's active enrollment (with `enrolled`). A client
        /// whose `Enrolled` answer was lost gets it back here.
        #[serde(with = "serde_bytes")]
        enrollment_id: Option<Vec<u8>>,
        limits: ServerLimits,
        server_name: String,
    },
    Enrolled {
        #[serde(with = "serde_bytes")]
        enrollment_id: Vec<u8>,
        limits: ServerLimits,
    },
    /// The envelope was written to disk.
    ///
    /// `try_publish_raw` reports this as "sent". That is a stronger guarantee than
    /// the local success of `gossipsub.publish()`, but it is still not end to end.
    /// The only proof of end-to-end delivery is the recipient's
    /// `MessageContent::Ack` (see `awaiting_confirmation` in lib.rs). So `Deposited`
    /// does not permanently silence the gossipsub path. See
    /// `should_shadow_on_gossipsub` in server_client.rs.
    Deposited { seq: u64 },
    Batch { items: Vec<MailItem>, more: bool },
    ArchiveProbed { present: Vec<BucketStat> },
    ArchiveBatch { records: Vec<ArchiveRecord>, more: bool },
    /// `Register` with ids that were not registered. Every other id of `add` is
    /// registered. `proof_needed`: sent without a `MailboxProof`, so send again with
    /// one. `refused`: over `ServerLimits.max_mailboxes`, over the reader cap, a proof
    /// that did not verify, or a key other than the mailbox's. Do not send these
    /// again. If all ids registered, the reply is a plain `Ok`.
    Registered { proof_needed: Vec<MailboxId>, refused: Vec<MailboxId> },
    Ok,
    Err(ServerErrorCode),
}

/// Proof that the sender of a `Register` owns `mailbox`: a hybrid signature over
/// `register_signing_input` by the mailbox key. Readers derive the key from a
/// secret only they hold (`server_seal::mailbox_proof_seeds`).
///
/// A session or relay mailbox has an id derived from that key (`key_bound_mailbox_id`),
/// so the server takes no other key for it. Knowing the id is not enough to read it.
/// A first-contact mailbox cannot work that way: its proof key belongs to the reading
/// device alone, and the sender, who holds only the pairing code, must still compute
/// the id. There the server keeps each reader's key and accepts at most two readers
/// per key. Another key gets its own slots. A first-come binding would let anyone who
/// knew a first-contact id lock that device out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxProof {
    pub mailbox: MailboxId,
    #[serde(with = "serde_bytes")]
    pub pk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pk_pq: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig_pq: Vec<u8>,
}

/// Proofs per `Register`. Each is about 7.3 KB, and the request cap is 1 MiB
/// (see the `MAX_DEPOSIT_BYTES` note).
pub const MAX_REGISTER_PROOFS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerErrorCode {
    /// This PeerId is not registered. The client must start `Enroll` or `Rebind`.
    NotEnrolled,
    /// Invite token invalid, used up, or expired.
    BadInvite,
    BadSignature,
    /// `ts_ms` is outside the `ENROLL_MAX_SKEW_MS` window.
    Stale,
    /// No one on this server has registered this mailbox.
    ///
    /// The client reads this as "this recipient is not on my server" and sends
    /// traffic for that contact straight to gossipsub for a while (see
    /// `server_unknown_mailboxes` in lib.rs). That avoids a wasted round trip on
    /// every message.
    UnknownMailbox,
    /// The item exceeds `ServerLimits.max_item_bytes`. Retrying with the same bytes
    /// never succeeds. This is a permanent error.
    TooLarge,
    /// Quota full. Not permanent: the user can free space on the server.
    QuotaExceeded,
    RateLimited,
    /// The operator revoked this record.
    Revoked,
    /// Direction error, for example a `Deposit` sent to a client.
    BadDirection,
    Unsupported,
    Internal,
    /// `BlobFinish`: the stored bytes do not hash to `enc_sha256`, or cannot be read.
    /// Deterministic: sending the same finish again never succeeds.
    BadHash,
    /// `BlobFinish`: the server has no complete upload under this id. The half-done
    /// blob was swept, or chunks are missing. Not permanent: the client uploads again
    /// from chunk 0.
    BlobIncomplete,
}

impl ServerErrorCode {
    /// Could this error succeed if the same bytes were retried?
    ///
    /// The caller (`try_publish_raw`) maps this to `PublishFailure::Permanent` or
    /// `Transient`. Misclassifying causes harm both ways: a permanent error treated as
    /// transient is retried for days for nothing, and a transient error treated as
    /// permanent loses a message that could have been recovered. See the
    /// `PublishFailure` docs in types.rs.
    pub fn is_permanent(self) -> bool {
        matches!(
            self,
            ServerErrorCode::TooLarge | ServerErrorCode::Unsupported | ServerErrorCode::BadDirection | ServerErrorCode::BadHash
        )
    }

    /// Should the client rebuild its server relationship after this error?
    pub fn needs_reenroll(self) -> bool {
        matches!(self, ServerErrorCode::NotEnrolled)
    }
}

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

/// One item in a mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailItem {
    /// The mailbox this item came from. The client must advance the cursor of the
    /// right mailbox. One `Fetch` can ask for several mailboxes, so the response
    /// cannot be parsed without this field.
    pub mailbox_id: MailboxId,
    /// The server-assigned sequence number, strictly increasing within the mailbox.
    /// This is what the cursor needs. It counts per mailbox (`mail_seq` table). A
    /// server-global sequence would let any reader estimate the server-wide intake
    /// rate from gaps, so it must not become global again.
    ///
    /// The client advances its cursor (`server_cursors` table) only after processing
    /// the item. The guarantee is at-least-once, not at-most-once. If the process
    /// dies mid-batch, items arrive again. This is deliberate: advancing before
    /// processing would silently lose a message on a crash. A redelivered item is
    /// safe anyway, because the `message_id` dedup and the failure to decrypt an
    /// already-consumed ratchet key absorb it.
    pub seq: u64,
    pub deposited_at_ms: u64,
    /// Output of `server_seal::seal_envelope` or `seal_first_contact`. Opaque to the server.
    #[serde(with = "serde_bytes")]
    pub sealed: Vec<u8>,
}

/// One bucket summary in an `ArchiveProbe` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketStat {
    pub bucket: MailboxId,
    pub count: u32,
    pub oldest_ms: u64,
    pub newest_ms: u64,
}

/// One row of the archive stored on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveRecord {
    /// A stable identity that is the same on every device and at both ends: the
    /// `message_id` for 1:1, `group_message_local_id` for groups. The server dedups
    /// on `(bucket, record_id)`, so the same received message uploaded from N of my
    /// devices costs one row.
    pub record_id: String,
    /// Monotonic revision. An Edit or Delete overwrites the old record
    /// (`edited_at_ms` or `deleted_at_ms`, else `sent_at_ms`). The server applies it
    /// with `WHERE excluded.rev > archive.rev`.
    ///
    /// The existing `HistorySyncResponse` cannot do this: it cannot correct a late
    /// Edit in history.
    pub rev: u64,
    /// Lets the server page backwards without decrypting. The client sends it floored
    /// to the hour (the exact time is inside `sealed`), so the two ends' buckets
    /// cannot be joined by time.
    pub sent_at_ms: u64,
    /// Output of `server_seal::seal_archive_record`.
    #[serde(with = "serde_bytes")]
    pub sealed: Vec<u8>,
}

/// Limits the server advertises.
///
/// The client receives them in `Welcome` and enforces them on its side too. For
/// example, it never sends an envelope over the cap, so no bytes are wasted and no
/// `TooLarge` round trip happens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLimits {
    pub max_item_bytes: u32,
    pub max_mailboxes: u32,
    pub max_items_per_mailbox: u32,
    pub max_mail_bytes: u64,
    pub max_archive_bytes: u64,
    pub max_blob_bytes: u64,
    pub mailbox_ttl_ms: u64,
    pub blob_ttl_ms: u64,
    pub requests_per_minute: u32,
}

impl Default for ServerLimits {
    /// Reasonable defaults for a small group of friends. `typeon-server` reads them
    /// from its config. These values are only a baseline.
    fn default() -> Self {
        ServerLimits {
            // Must stay under the codec's hard 1 MiB limit (see the size-limit note
            // at the top of the module).
            max_item_bytes: MAX_DEPOSIT_BYTES as u32,
            max_mailboxes: 512,
            max_items_per_mailbox: 5_000,
            max_mail_bytes: 256 * 1024 * 1024,
            max_archive_bytes: 1024 * 1024 * 1024,
            max_blob_bytes: 4 * 1024 * 1024 * 1024,
            // 14 days: longer than the sender's give-up time
            // (`TEXT_RETRY_GIVE_UP_MS`, 7 days). This is the real durability limit.
            mailbox_ttl_ms: 14 * 24 * 60 * 60 * 1000,
            blob_ttl_ms: 30 * 24 * 60 * 60 * 1000,
            requests_per_minute: 1_800,
        }
    }
}

// ---------------------------------------------------------------------------
// Invite code
// ---------------------------------------------------------------------------

/// Invite code format. QR and manual entry carry the same text: one canonical
/// string, two ways to enter it.
pub const SERVER_INVITE_SCHEME: &str = "typeon-server:";

/// Result of parsing an invite code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInvite {
    /// All advertised server addresses: onion and, if present, LAN or public IP.
    ///
    /// Why plural: with one address that happened to be onion, two devices on the
    /// same LAN still routed all traffic over Tor. Measured: a 10 MB upload ran at
    /// about 12 KB/s. libp2p already handles several dials to the same `PeerId` (the
    /// first one to connect wins), so giving all of them is a direct speed gain. The
    /// onion address stays in the list, so reachability behind CGNAT is kept.
    pub addrs: Vec<String>,
    pub token: String,
}

/// Parses `typeon-server:<addr>[,<addr>...]#<token>`.
///
/// The token follows `#`. A multiaddr never contains `#`, so the split is
/// unambiguous. The token is carried as an opaque string, exactly as the server
/// generated it. No encoding is assumed.
pub fn parse_server_invite(text: &str) -> Result<ServerInvite, String> {
    let trimmed = text.trim();
    let body = trimmed
        .strip_prefix(SERVER_INVITE_SCHEME)
        .ok_or_else(|| format!("Kod '{}' ile başlamalı", SERVER_INVITE_SCHEME))?;
    let (addr_part, token) = body
        .split_once('#')
        .ok_or("Kodda davet jetonu ('#' sonrası) yok")?;
    // Addresses are separated by commas. A multiaddr contains neither `#` nor `,`, so
    // both splits are unambiguous. Codes with a single address still parse.
    let addrs: Vec<String> = addr_part
        .split(',')
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect();
    if addrs.is_empty() {
        return Err("Kodda sunucu adresi yok".to_string());
    }
    if token.trim().is_empty() {
        return Err("Kodda davet jetonu boş".to_string());
    }
    Ok(ServerInvite { addrs, token: token.trim().to_string() })
}

/// Inverse of `parse_server_invite`. The server app uses it to produce a QR or
/// copyable code. It carries ALL the addresses (see `ServerInvite.addrs`).
pub fn format_server_invite(addrs: &[String], token: &str) -> String {
    let joined = addrs.iter().map(|a| a.trim()).collect::<Vec<_>>().join(",");
    format!("{}{}#{}", SERVER_INVITE_SCHEME, joined, token.trim())
}

/// Signed bytes of the enrollment messages: a tag for the message kind, then every
/// field with its length. Without the lengths, (peer "ab", token "c...") and
/// (peer "a", token "bc...") would produce the same bytes. Without the tag, the
/// same enroll key could sign `Enroll` and `Rebind` in a shared format.
///
/// Protocol break: a client and a server on opposite sides of this change cannot
/// enroll or rebind with each other (`BadSignature`). A device the server already
/// knows by its PeerId does neither, and carries on.
fn signing_input(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = tag.to_vec();
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// The bytes `Enroll.sig` signs. The client and the server both call this same
/// function. Building the signed input by hand in two places is a classic source of
/// mismatch in protocols like this.
///
/// Both enrollment keys and the client's PeerId are signed too. The signature commits
/// to the keys it is verified with and is useless from any other PeerId.
#[allow(clippy::too_many_arguments)]
pub fn enroll_signing_input(
    version: u16,
    server_peer_id: &str,
    client_peer_id: &str,
    invite_token: &[u8],
    enroll_pk: &[u8],
    enroll_pk_pq: &[u8],
    challenge: &[u8],
    ts_ms: u64,
) -> Vec<u8> {
    signing_input(
        b"p2pmsg-v0.4-server-enroll",
        &[
            &version.to_be_bytes(),
            server_peer_id.as_bytes(),
            client_peer_id.as_bytes(),
            invite_token,
            enroll_pk,
            enroll_pk_pq,
            challenge,
            &ts_ms.to_be_bytes(),
        ],
    )
}

/// The bytes `Rebind.sig` signs.
///
/// `client_peer_id` and the `Hello` challenge are signed too. A leaked Rebind is
/// useless from any other PeerId and on any other connection.
pub fn rebind_signing_input(
    enrollment_id: &[u8],
    server_peer_id: &str,
    client_peer_id: &str,
    challenge: &[u8],
    ts_ms: u64,
) -> Vec<u8> {
    signing_input(
        b"p2pmsg-v0.3-server-rebind",
        &[enrollment_id, server_peer_id.as_bytes(), client_peer_id.as_bytes(), challenge, &ts_ms.to_be_bytes()],
    )
}

/// The bytes a `MailboxProof` signs. The enrollment and the server are included, so a
/// proof read off the wire registers nothing for another enrollment or at another
/// server.
pub fn register_signing_input(mailbox: &str, enrollment_id: &[u8], server_peer_id: &str) -> Vec<u8> {
    signing_input(b"p2pmsg-v0.5-server-register", &[mailbox.as_bytes(), enrollment_id, server_peer_id.as_bytes()])
}

/// Prefix of every id made by `key_bound_mailbox_id`. The server checks the
/// `Register` proof key only for these ids.
pub const KEY_BOUND_MAILBOX_PREFIX: &str = "mk_";

/// The hash of a `MailboxProof` key pair, which the server keeps per reader. Both keys
/// have a fixed length once the signature verifies, so plain concatenation is
/// unambiguous.
pub fn mailbox_key_hash(pk: &[u8], pk_pq: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"p2pmsg-v0.7-mailbox-key");
    h.update(pk);
    h.update(pk_pq);
    h.finalize().into()
}

/// The id of a mailbox whose one proof key hashes to `key_hash` (`mailbox_key_hash`).
/// Both ends of a session (or call relay) derive the key from their shared secret, so
/// the sender can compute the id too. The server can then check that a proof is made
/// by the mailbox's own key.
pub fn key_bound_mailbox_id(key_hash: &[u8]) -> String {
    format!("{}{}", KEY_BOUND_MAILBOX_PREFIX, hex::encode(&key_hash[..key_hash.len().min(16)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_id_is_a_safe_hash_of_the_upload_secret() {
        let id = blob_id_for_upload_secret(&[7u8; BLOB_UPLOAD_SECRET_LEN]).unwrap();
        assert_eq!(id.len(), 48);
        assert!(id.starts_with(&"07".repeat(BLOB_TAG_LEN)));
        assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_ne!(id, blob_id_for_upload_secret(&[8u8; BLOB_UPLOAD_SECRET_LEN]).unwrap());
        // The id is not secret. Sent back as a value, it names another blob.
        assert!(blob_id_for_upload_secret(id.as_bytes()).is_none());
        assert!(blob_id_for_upload_secret(&[7u8; 15]).is_none());
        assert!(id.ends_with(&blob_id_hash_hex(&[7u8; BLOB_UPLOAD_SECRET_LEN - BLOB_TAG_LEN])));
    }

    #[test]
    fn register_proof_is_bound_to_mailbox_enrollment_and_server() {
        let base = register_signing_input("mb_a", b"eid", "peer");
        assert_ne!(base, register_signing_input("mb_b", b"eid", "peer"));
        assert_ne!(base, register_signing_input("mb_a", b"eid2", "peer"));
        assert_ne!(base, register_signing_input("mb_a", b"eid", "other"));
    }

    #[test]
    fn invite_carries_every_address() {
        // With one address, and that address onion, two devices on the same LAN still
        // routed all traffic over Tor. The measured gap was over 10x. The code now
        // carries all of them.
        let addrs = vec![
            "/dns/abcdef.onion/tcp/42612/p2p/12D3KooWTest".to_string(),
            "/ip4/192.168.1.5/tcp/42612/p2p/12D3KooWTest".to_string(),
        ];
        let code = format_server_invite(&addrs, "ABC123");
        let parsed = parse_server_invite(&code).expect("ayristirilmali");
        assert_eq!(parsed.addrs, addrs);
        assert_eq!(parsed.token, "ABC123");
    }

    #[test]
    fn single_address_invites_still_parse() {
        let code = "typeon-server:/ip4/1.2.3.4/tcp/1/p2p/12D3KooWTest#TOK";
        let parsed = parse_server_invite(code).expect("ayristirilmali");
        assert_eq!(parsed.addrs.len(), 1);
        assert_eq!(parsed.token, "TOK");
    }

    #[test]
    fn invite_rejects_missing_token_and_wrong_scheme() {
        assert!(parse_server_invite("typeon-server:/ip4/1.2.3.4/tcp/1/p2p/x").is_err());
        assert!(parse_server_invite("/ip4/1.2.3.4/tcp/1/p2p/x#tok").is_err());
        assert!(parse_server_invite("typeon-server:#tok").is_err());
    }

    #[test]
    fn error_permanence_classification() {
        // Permanent: the same bytes never succeed.
        assert!(ServerErrorCode::TooLarge.is_permanent());
        assert!(ServerErrorCode::Unsupported.is_permanent());
        assert!(ServerErrorCode::BadHash.is_permanent());
        // Transient: the user can free space, the limit can reset, or the record can be renewed.
        assert!(!ServerErrorCode::QuotaExceeded.is_permanent());
        assert!(!ServerErrorCode::RateLimited.is_permanent());
        assert!(!ServerErrorCode::UnknownMailbox.is_permanent());
        assert!(!ServerErrorCode::BlobIncomplete.is_permanent());
        assert!(ServerErrorCode::NotEnrolled.needs_reenroll());
    }

    #[test]
    fn deposit_cap_stays_below_the_codec_hard_limit() {
        // Tests the note at the top of the module: libp2p-request-response's CBOR codec
        // truncates requests at 1 MiB. If this constant gets close to that, envelopes
        // start to corrupt silently.
        assert!(MAX_DEPOSIT_BYTES < 1024 * 1024, "codec sert sinirini asamaz");
        assert!(ServerLimits::default().max_item_bytes as usize <= MAX_DEPOSIT_BYTES);
    }

    #[test]
    fn signing_inputs_bind_every_field() {
        #[allow(clippy::too_many_arguments)]
        fn e(v: u16, sp: &str, cp: &str, tok: &[u8], pk: &[u8], pq: &[u8], ch: &[u8], ts: u64) -> Vec<u8> {
            enroll_signing_input(v, sp, cp, tok, pk, pq, ch, ts)
        }
        let base = e(1, "peer", "me", b"tok", b"pk", b"pq", b"chal", 100);
        assert_ne!(base, e(2, "peer", "me", b"tok", b"pk", b"pq", b"chal", 100));
        // The server id must be in the signed input. Otherwise a server could replay an
        // Enroll it received against another server.
        assert_ne!(base, e(1, "other", "me", b"tok", b"pk", b"pq", b"chal", 100));
        assert_ne!(base, e(1, "peer", "thief", b"tok", b"pk", b"pq", b"chal", 100));
        assert_ne!(base, e(1, "peer", "me", b"tok2", b"pk", b"pq", b"chal", 100));
        assert_ne!(base, e(1, "peer", "me", b"tok", b"pk2", b"pq", b"chal", 100));
        assert_ne!(base, e(1, "peer", "me", b"tok", b"pk", b"pq2", b"chal", 100));
        // The challenge must be in the signed input. Otherwise a captured signature
        // would stay valid on a fresh connection.
        assert_ne!(base, e(1, "peer", "me", b"tok", b"pk", b"pq", b"chal2", 100));
        assert_ne!(base, e(1, "peer", "me", b"tok", b"pk", b"pq", b"chal", 101));

        let rb = rebind_signing_input(b"eid", "peer", "me", b"chal", 100);
        assert_ne!(rb, rebind_signing_input(b"eid", "other", "me", b"chal", 100));
        assert_ne!(rb, rebind_signing_input(b"eid2", "peer", "me", b"chal", 100));
        // A replay from another PeerId or on another connection fails.
        assert_ne!(rb, rebind_signing_input(b"eid", "peer", "thief", b"chal", 100));
        assert_ne!(rb, rebind_signing_input(b"eid", "peer", "me", b"chal2", 100));

        // A shifted field boundary is a different message, and an Enroll signature is
        // never a Rebind signature.
        assert_ne!(e(1, "ab", "c", b"t", b"k", b"q", b"chal", 100), e(1, "a", "bc", b"t", b"k", b"q", b"chal", 100));
        assert_ne!(e(1, "p", "m", b"tok", b"k", b"q", b"chal", 100), e(1, "p", "m", b"tokk", b"", b"q", b"chal", 100));
        assert_ne!(rebind_signing_input(b"ei", "dpeer", "me", b"c", 100), rebind_signing_input(b"eid", "peer", "me", b"c", 100));
        assert_ne!(rb[..25], base[..25], "different tags");
    }
}

/// Is `addr` an onion address? A server address is nothing else. Any other kind (an
/// IP, or a DNS name that may resolve to a private address) is refused in invites and
/// server records. The first component decides.
pub fn is_onion_server_addr(addr: &str) -> bool {
    let mut parts = addr.split('/').skip(1);
    match (parts.next(), parts.next()) {
        (Some("dns" | "dns4" | "dns6"), Some(host)) => host.len() > ".onion".len() && host.ends_with(".onion"),
        (Some("onion3"), Some(_)) => true,
        _ => false,
    }
}

/// The addresses worth storing and dialing for a server: the onion ones (see
/// `is_onion_server_addr`). An empty result means this invite cannot be used.
pub fn public_server_addrs<I, S>(addrs: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    addrs
        .into_iter()
        .map(|a| a.as_ref().trim().to_string())
        .filter(|a| is_onion_server_addr(a))
        .collect()
}

/// Largest blob chunk the server accepts, in bytes.
///
/// The chunk size is now chosen per file on the client (see
/// `attachments::FILE_CHUNK_SIZE_V2`), so the server's check cannot be tied to one
/// size. It was: the server checked against the legacy 256 KiB and rejected every
/// 512 KiB chunk with `TooLarge`, so transfers never progressed.
///
/// The cap comes from the hard 1 MiB request limit of the `request_response` CBOR
/// codec (`REQUEST_SIZE_MAXIMUM`; an oversized request is cut silently and decoding
/// fails). 768 KiB leaves room for a 512 KiB chunk, the AEAD tag and CBOR framing,
/// and stays well under the limit.
pub const MAX_BLOB_CHUNK_BYTES: usize = 768 * 1024;

/// Length of a blob upload secret (`BlobPut.upload_secret`): an 8-byte author tag,
/// shown in the id, then 16 secret bytes.
pub const BLOB_UPLOAD_SECRET_LEN: usize = 24;

/// Length of the author tag at the start of an upload secret.
pub const BLOB_TAG_LEN: usize = 8;

/// The blob (file) id an upload secret stands for: 48 lowercase hex characters, the
/// author tag in the clear, then `blob_id_hash_hex` of the rest of the secret. The
/// sender picks the secret, names only this id in its `FileOffer`, and proves ownership
/// to the server with the secret itself. The tag lets a group member check that a file
/// id belongs to the member who offers it (core `group_msg_tag`, derived from the hash
/// part, so it differs per file). The server does not read it. `None` if the secret has
/// the wrong length.
/// The archive bucket id a purge secret deletes (`ar_` + 32 hex chars), or `None` for a
/// malformed secret. `server_seal::server_archive_bucket` builds ids the same way.
pub fn archive_bucket_for_purge_secret(secret_hex: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let secret = hex::decode(secret_hex).ok().filter(|b| b.len() == 32)?;
    let hash = Sha256::new_with_prefix(b"typeon-archive-bucket-v2").chain_update(&secret).finalize();
    Some(format!("ar_{}", hex::encode(&hash[..16])))
}

pub fn blob_id_for_upload_secret(upload_secret: &[u8]) -> Option<String> {
    if upload_secret.len() != BLOB_UPLOAD_SECRET_LEN {
        return None;
    }
    let (tag, rest) = upload_secret.split_at(BLOB_TAG_LEN);
    Some(format!("{}{}", hex::encode(tag), blob_id_hash_hex(rest)))
}

/// The id part after the tag: a hash of the upload secret's bytes after the tag (32 hex
/// characters). Kept separate so the tag can be derived from it.
pub fn blob_id_hash_hex(secret_after_tag: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::new_with_prefix(b"typeon-blob-id-v3").chain_update(secret_after_tag).finalize();
    hex::encode(&hash[..16])
}

#[cfg(test)]
mod onion_addr_tests {
    use super::{is_onion_server_addr, public_server_addrs};

    #[test]
    fn a_server_address_is_onion_or_refused() {
        for onion in ["/dns/abcdef.onion/tcp/42612/p2p/12D3KooW", "/dns4/abcdef.onion/tcp/1", "/onion3/abcdef:42612/p2p/12D3KooW"] {
            assert!(is_onion_server_addr(onion), "{onion}");
        }
        for other in [
            "/ip4/203.0.113.7/tcp/42612/p2p/12D3KooW",
            "/ip4/192.168.1.5/tcp/42612/p2p/12D3KooW",
            "/ip6/2001:db8::1/tcp/1",
            "/dns4/example.org/tcp/1",
            "/dns4/localhost/tcp/1",
            "/dns/.onion/tcp/1",
            "/dns/abcdef.onion./tcp/1",
            "/ip4/10.0.0.1/tcp/1/dns/abcdef.onion",
            "abcdef.onion",
            "",
        ] {
            assert!(!is_onion_server_addr(other), "{other}");
        }
        let kept = public_server_addrs(["/dns4/example.org/tcp/1", " /dns/abcdef.onion/tcp/1 "]);
        assert_eq!(kept, vec!["/dns/abcdef.onion/tcp/1".to_string()]);
    }
}
