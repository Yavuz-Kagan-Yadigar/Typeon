//! Typeon protocol core.
//!
//! Scope: one identity per device, with the Identity / Device split kept so the core can grow to several devices.
//!
//! Modules:
//! - `identity`: Identity and Device model, fingerprints
//! - `packet`: wire packet formats
//! - `ratchet`: hybrid KEM plus Double Ratchet
//! - `contact`: TOFU and safety-number changes
//! - `group`: pairwise group messaging

/// Crypto primitives live in the separate `typeon-crypto` crate, so the same code runs on native targets (Android, Linux, server) and in wasm.
/// This `pub use` keeps the old paths (`crate::packet::...`, `crate::identity::...`, `p2p_messenger::server_proto::...`) working, so callers do not change.
pub use typeon_crypto::{identity, packet, ratchet, server_proto, server_seal};
mod contact;
mod group;
/// `pub`: the `typeon-server` crate serves file attachments with the same types and
/// `read_chunk_from_disk`. The disk format equals the wire format, so the server
/// does not duplicate any encryption or framing code.
pub mod attachments;
/// `pub`: the server also hosts its own onion service. That is how a phone running
/// the server app stays reachable behind CGNAT.
pub mod tor;
pub mod update;

// `server_proto` and `server_seal` now live in `typeon-crypto`. The `pub use` above
// keeps `p2p_messenger::server_proto::...` and `crate::server_seal::...` valid, and
// `typeon-server` uses the same definitions.
/// Client side of the server option: `impl P2PCore` blocks. Like the other topic
/// modules, it is a child module and can see the private fields of `P2PCore`.
pub mod server_client;
/// Voice and video calls: signalling and media streams. See the module docs.
pub mod call;
/// Shared whiteboard per chat: storage, sync and limits. See the module docs.
mod whiteboard;

/// Timeout (ms) for bulk transfer requests. The server must use the same value, or
/// one side gives up before the other.
pub fn server_client_timeout_ms() -> u64 {
    server_client::BLOB_REQUEST_TIMEOUT_MS
}

/// Circuit Relay v2 limits of a node. Client and node mode use the same limits. The
/// relay accepts every peer. A circuit is the fallback connection between two peers
/// whose onion dial failed, so it carries chat, file chunks and call media, not only
/// signalling.
pub fn relay_server_config() -> relay::Config {
    let n = |v: u32| std::num::NonZeroU32::new(v).expect("limit > 0");
    let secs = std::time::Duration::from_secs;
    relay::Config {
        // One per peer that can be reached through this node: 64 enrolled devices
        // (server default), plus half as many again.
        max_reservations: 96,
        // One relay connection per peer. Two covers a reconnect overlap.
        max_reservations_per_peer: 2,
        // Library value. A shorter one means one more radio wake-up per renewal.
        reservation_duration: secs(60 * 60),
        reservation_rate_limiters: Vec::new(),
        // Library values. A circuit is one peer pair, and a chat with 4 contacts
        // behind this relay already needs 4.
        max_circuits: 16,
        max_circuits_per_peer: 4,
        // The client redials at once when a circuit ends. 30 min means one reconnect
        // per long call, not one every 2 min (library default).
        max_circuit_duration: secs(30 * 60),
        // 128 file chunks of 256 KiB, or more voice than 30 min holds. A file goes on
        // after the redial, since downloads resume. Video (about 1 Mbit/s each way)
        // reaches the limit in about 4 min and then reconnects.
        max_circuit_bytes: 32 * 1024 * 1024,
        circuit_src_rate_limiters: Vec::new(),
    }
    // Burst 8, then one per 2 min. This matches the client's reservation retry interval.
    .reservation_rate_per_peer(n(8), secs(120))
    // Every peer arrives from 127.0.0.1 (onion bridge), so "per IP" is one bucket for
    // all peers: 8 full per-peer bursts, refilled at 6 per minute.
    .reservation_rate_per_ip(n(64), secs(10))
    // Library value. Every fallback dial to an offline contact costs one.
    .circuit_src_per_peer(n(30), secs(120))
    // All peers together (see above): 8 per-peer bursts, refilled at 1 per second.
    .circuit_src_per_ip(n(240), secs(1))
}

/// Safe Rust API: the non-JNI counterparts of the JNI exports at the end of this
/// file, without JVM types. Only callers that are not JNI use it, such as the
/// `Linux/` desktop client. The Android side calls the JNI exports directly, so this
/// module is dead code there (see the `api` module docs).
pub mod api;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use android_logger::Config as LogConfig;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, VerifyingKey};
use futures::FutureExt as _;
use futures::StreamExt as _;
use hex;
use hkdf::Hkdf;
use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jboolean, jlong, jobjectArray, jstring};
use jni::JNIEnv;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol as MultiaddrProtocol;
use libp2p::request_response;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, kad, noise, relay, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use log::{debug, error, info, warn};
// Uses the maintained RustCrypto `ml-dsa` and `ml-kem` crates instead of pqcrypto-dilithium and pqcrypto-kyber, which have advisories
// (RUSTSEC-2024-0380, RUSTSEC-2024-0381) and FIPS 204/203 byte incompatibilities (see the Cargo.toml note). The parameter sets are
// ML-KEM-1024 and ML-DSA-87 (NIST category 5), for extra margin. An earlier version used ML-DSA-44 by mistake, and was then moved to
// ML-DSA-65 before the category 5 sets were chosen. See the "Key sizes" note in SECURITY.md.
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Generate as MlDsaGenerate, KeyExport as MlDsaKeyExport, Keypair as MlDsaKeypair, MlDsa87, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey, Signer as MlDsaSigner, VerifyingKey as MlDsaVerifyingKey, Verifier as MlDsaVerifier};
use ratchet::{kyber_pubkey_from_bytes, mlkem_dk_from_bytes, mlkem_dk_to_bytes, mlkem_ek_to_bytes, mlkem_generate};
use rand::rngs::OsRng;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};


use contact::{check_incoming_device, Contact, DeviceCheckOutcome};
use group::{apply_change, validate_group_update, Group, GroupChange, GroupUpdateError};
use identity::{compute_fingerprint, DeviceStatus};
use packet::{
    DeviceAdd, DeviceLinkRequest, DeviceRevoke, GroupMemberDevice, GroupUpdate, HandshakeInit, IdentityExchange,
    MessageContent, MessagePacket, MessagePacketHeader, NetworkEnvelope, QrPacket, SiblingEchoBody,
    SiblingHistoryEntry, SignedPrekey, SyncPayload, SyncedContact, SyncedDevice, SyncedMessage,
};
use ratchet::{DeviceRatchetState, MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, RatchetPublicKeys};
use attachments::{FileChunkRequest, FileChunkResponse};

const DB_NAME: &str = "p2p_messenger.db";
/// Protocol identifier for file attachments. See the module note in attachments.rs.
const FILE_TRANSFER_PROTOCOL: &str = "/p2pmessenger/filexfer/1.0.0";
/// Largest attachment size the user may request. See `prepare_and_send_file`.
const MAX_ATTACHMENT_SIZE: u64 = 4 * 1024 * 1024 * 1024;

lazy_static::lazy_static! {
    static ref RUNTIME: Runtime = tokio::runtime::Runtime::new().expect("tokio runtime could not start (threads/fds exhausted)");
    static ref CORE: Arc<Mutex<P2PCore>> = Arc::new(Mutex::new(P2PCore::new()));
    /// See `wait_for_network_activity`.
    static ref NET_WAKE: tokio::sync::Notify = tokio::sync::Notify::new();
}

// The core is split by topic. Every module sees the crate root (`use super::*`), and
// the root re-exports them, so `crate::name` paths do not change.
mod core_lock;
mod media_unlocked;
mod wire;
mod util;
#[cfg(test)]
mod core_tests;
mod network;
mod types;
mod tuning;
mod db;
mod pairing;
mod devices;
mod sibling_sync;
mod contacts;
mod session;
mod send;
mod receive;
mod archive;
mod persist;
mod group_ops;
mod storage;
mod file_transfer;
mod poll;
mod recovery;
mod jni_exports;
use core_lock::*;
use media_unlocked::*;
pub use wire::*;
pub use util::*;
#[allow(unused_imports)] // only the tests use it from here
use network::*;
pub use types::*;
use tuning::*;
#[allow(unused_imports)] // only the debug-hooks export uses it from here
use db::*;
use recovery::*;
use archive::first_expiry;
pub use jni_exports::*;

/// Every source file of the core. The tests scan them.
#[cfg(test)]
const CORE_SRC: &str = concat!(
    include_str!("lib.rs"),
    include_str!("core_lock.rs"),
    include_str!("media_unlocked.rs"),
    include_str!("wire.rs"),
    include_str!("util.rs"),
    include_str!("core_tests.rs"),
    include_str!("network/mod.rs"),
    include_str!("network/connections.rs"),
    include_str!("network/power.rs"),
    include_str!("network/publish.rs"),
    include_str!("types.rs"),
    include_str!("tuning.rs"),
    include_str!("db.rs"),
    include_str!("pairing.rs"),
    include_str!("devices.rs"),
    include_str!("sibling_sync.rs"),
    include_str!("contacts.rs"),
    include_str!("session.rs"),
    include_str!("send.rs"),
    include_str!("receive.rs"),
    include_str!("archive.rs"),
    include_str!("persist.rs"),
    include_str!("group_ops.rs"),
    include_str!("storage.rs"),
    include_str!("file_transfer.rs"),
    include_str!("poll.rs"),
    include_str!("recovery.rs"),
    include_str!("jni_exports/mod.rs"),
    include_str!("jni_exports/account.rs"),
    include_str!("jni_exports/contacts.rs"),
    include_str!("jni_exports/files.rs"),
    include_str!("jni_exports/groups.rs"),
    include_str!("jni_exports/history.rs"),
    include_str!("jni_exports/linking.rs"),
    include_str!("jni_exports/messages.rs"),
    include_str!("jni_exports/net.rs"),
    include_str!("jni_exports/pruning.rs"),
    include_str!("jni_exports/servers.rs"),
    include_str!("jni_exports/stickers.rs"),
);

struct P2PCore {
    db: Option<Connection>,
    identity: Option<identity::Identity>,
    /// Key: device_fingerprint. A linked secondary device has the primary's
    /// identity_id, so the two values differ.
    own_devices: HashMap<String, DeviceRecord>,
    own_device_keys: HashMap<String, DeviceKeys>,
    /// Public key records of known remote devices, learned through contact exchange or
    /// QR.
    known_remote_devices: HashMap<String, DeviceRecord>,
    /// The last time we sent an `IdentityExchange` reply to a device (see the reply
    /// block at the end of `process_identity_exchange`). The reply was unconditional,
    /// and the other side did the same: A to B produced a reply, which produced
    /// another reply from B to A. Between two paired devices this became an endless
    /// ping-pong, measured on real devices at 60-100 envelopes per second. Each was
    /// also stored on the server, adding thousands of rows in minutes, and it used up
    /// the peer's packet rate limit, which dropped real traffic.
    last_identity_exchange_reply: HashMap<String, u64>,
    contacts: HashMap<String, Contact>, // contact_id -> Contact
    /// identity_id -> contact_id lookup.
    identity_to_contact: HashMap<String, String>,
    /// Ratchet sessions per device pair. Key: the remote device_fingerprint.
    ratchets: HashMap<String, DeviceRatchetState>,
    /// Security fix: replayed handshakes could reset sessions (DoS). Records
    /// (timestamp, classical signature) of handshakes accepted from this device within
    /// the freshness window (`HANDSHAKE_MAX_SKEW_MS`). If an incoming handshake's
    /// signature is already in this set, it is a replay and is rejected, so a live
    /// ratchet cannot be reset. Dedup by content (signature) is sturdier than a
    /// monotonic timestamp: a real re-pairing (fresh ephemeral keys, different
    /// signature) is accepted whatever the clock skew, and only byte-identical copies
    /// are rejected. Old entries are pruned from the window, so the set does not grow
    /// without bound. It lives in memory; after a restart, the freshness window still
    /// rejects old replays.
    recent_handshake_sigs: HashMap<String, Vec<(u64, Vec<u8>)>>,
    /// See `EARLY_PACKET_TTL_MS`. Key: sender device_fingerprint. Value: (time buffered,
    /// packet). Replayed in order by `replay_early_packets` once the handshake completes.
    early_packets: HashMap<String, std::collections::VecDeque<(u64, Option<PeerId>, MessagePacket)>>,
    /// During pairing, A's `HandshakeInit`
    /// could reach B before B processed A's `IdentityExchange`, so A was not yet in
    /// `known_remote_devices`. `process_handshake_init` then dropped the packet as
    /// "Unknown sender device". Early `Message`s were buffered, but handshakes were
    /// not. B then called its own `initiate_handshake_with` and made an initiator
    /// ratchet, while A's was also an initiator. Two incompatible initiators, and no
    /// message could be decrypted. Such a `HandshakeInit` is now buffered and replayed
    /// as soon as `process_identity_exchange` learns the sender device. Key: sender
    /// device_fingerprint. Up to 3 inits per fingerprint, never replaced: the claim is
    /// unverified until replay, so a later junk init must not push out the genuine
    /// one. Its digest stays deduped.
    early_handshakes: HashMap<String, Vec<(u64, Option<PeerId>, HandshakeInit)>>,
    /// See `INBOUND_DEDUP_WINDOW_MS`. Map of `raw bytes hash -> last seen (ms)` for
    /// successfully processed inbound envelopes. Removes byte-identical copies, which
    /// multi-path delivery produces, at the cheapest point, before expensive work such
    /// as signature checks and ratchet decryption.
    recent_inbound_digests: HashMap<u64, (u64, bool)>,
    /// See `reack_if_already_handled`. `message_id -> (device fingerprint that got the
    /// Ack, Ack time in ms)`. In memory, bounded by `RECENTLY_ACKED_MAX_ENTRIES`.
    recently_acked: HashMap<String, (String, u64)>,
    /// Acks to send in this turn, see `flush_outbound_acks`. Peer device fingerprint ->
    /// message_ids.
    outbound_acks: HashMap<String, Vec<String>>,
    /// Batched Ack requests waiting for a reply. If one fails, the packet falls back to
    /// an encrypted packet.
    ack_batches_inflight: HashMap<request_response::OutboundRequestId, (String, Vec<String>)>,
    last_inbound_dedup_prune_at: u64,
    /// See `EARLY_EDIT_DELETE_TTL_MS`. `Edit` and `Delete` packets whose target `Text`
    /// is not yet in the archive. Key: target message id (1:1 `message_id`, or group
    /// `group_message_local_id`). Value: (time buffered, sender peer_fp, sender
    /// sender_identity_id, the packet's own message_id (for the Ack), content). Applied
    /// by `replay_buffered_edits_deletes` once the target `Text` is archived.
    pending_edits_deletes: HashMap<String, Vec<(u64, String, String, String, MessageContent)>>,
    /// `Text`, `FileOffer` and `Reaction` for a group we do not hold yet, keyed by group
    /// id: (time held, source, peer_fp, sender identity, packet id, content, signed send
    /// time). Before this, rows from a removed member or from any contact, for an invented
    /// group id, stayed forever and showed once the group was known.
    unknown_group_held: HashMap<String, Vec<(u64, Option<PeerId>, String, String, String, MessageContent, u64)>>,
    groups: HashMap<String, Group>,
    /// Device-change alerts waiting for the user's decision, not yet accepted or
    /// rejected. Key: new_device_fingerprint.
    pending_device_alerts: HashMap<String, DeviceAlertInfo>,
    /// Pending messages. Messages from a device that is not yet verified or is blocked are not kept. Send and receive stop until the alert
    /// is resolved, so messages from that device are dropped silently until then.
    swarm: Option<Swarm<P2PBehaviour>>,
    /// Handle to the running onion service, when the Tor layer is on (client, service and bridge). `None` means Tor is off. Started in
    /// `start_network` when `tor_enabled` is set. See tor.rs and the "Tor onion" note in SECURITY.md.
    tor: Option<tor::TorHandle>,
    /// Whether the user turned Tor on. Passed to `start_network`, and read by
    /// `tor_status` and `get_node_address`.
    tor_enabled: bool,
    /// Set when the previous Tor status was "ready". It lets `poll_events` detect the NEW transition of Tor to `Ready` (see
    /// `announce_address_to_all_contacts` and the `AddressAnnounce` docs in packet.rs). Reset to `false` in `start_network`, when a new Tor client
    /// and session start. On the transition, our current `.onion` address is sent proactively to every known contact.
    tor_was_ready: bool,
    /// Addresses the swarm really listens on after `start_network` (`SwarmEvent::NewListenAddr`,
    /// see `poll_events`). The `node_address` shown on the QR / "my code" screen is
    /// derived from this. Only relay circuit addresses count. The loopback listener is
    /// never shown.
    own_listen_addrs: Vec<Multiaddr>,
    /// Envelopes that `publish_envelope` could not send. `poll_events` retries the SAME envelope (no new
    /// ratchet step or message_id). After `PENDING_ENVELOPE_TIMEOUT_MS` an entry is marked "Failed" and dropped.
    pending_envelopes: Vec<QueuedEnvelope>,
    /// Message status icons for the UI (see the "delivery status" request). Key:
    /// `MessagePacketHeader.message_id`. Bounded: `set_message_status` clears it at
    /// 10,000 entries.
    message_status: HashMap<String, MessageSendStatus>,
    /// Node mode on: relay service (from the next network start), history-sync help, and
    /// auto-download. Kademlia is always client mode (see `set_node_mode`).
    node_mode_enabled: bool,
    /// Upper limit on total attachment storage. In node mode every offered file is auto-downloaded (see the auto-download note in
    /// `receive_file_offer`), so disk use could grow without bound. Kotlin sets it from the Settings slider with `setHistoryStorageLimitBytes`,
    /// and it is sent again on every `start_network` (see P2PService). The default here is only a safety net until the first setting. When the
    /// limit is exceeded, `enforce_history_storage_limit` deletes the OLDEST completed files first (by created_at, ascending).
    history_storage_limit_bytes: u64,
    /// Plaintext secret bundle handed to Kotlin once, after `createIdentity`. It is taken
    /// by `getPendingSecretBundle` and then becomes `None` (see that function).
    pending_secret_bundle: Option<Vec<u8>>,
    /// Multi-device: the fingerprint of the NEW device that `approve_device_link`
    /// approved. When `process_identity_exchange` sees it, it records the incoming device
    /// as a SIBLING of our own identity, not as a contact. It sets identity_id to ours and
    /// sends `DeviceLinkGrant` (a signed DeviceAdd plus a full sync). Cleared once the
    /// grant is sent.
    pending_link_target: Option<String>,
    /// See `PENDING_LINK_RETRY_HORIZON_MS`. The last time `pending_link_target` was set.
    /// Used to stop the periodic dial and IdentityExchange resend of `reconnect_sweep`
    /// after the horizon.
    pending_link_started_at: u64,
    /// Secondary side: if this device produced a link QR (`build_device_link_request`),
    /// a `DeviceLinkGrant` is accepted only up to this point. Otherwise any paired contact
    /// could sign a grant that binds this device to their identity, wiping our identity and
    /// pulling all our contact, group and archive keys across via sibling sync.
    link_request_open_until: u64,
    /// The nonce in the link QR this device shows (`DeviceLinkRequest.nonce`). A grant
    /// is adopted only when it repeats this value. Empty means no QR is shown.
    link_request_nonce: Vec<u8>,
    /// The first device that proved it read the link code this device shows
    /// (`IdentityExchange.pairing_proof`). The IdentityExchange sent to it carries
    /// `link_consent`.
    link_consent_peer: Option<String>,
    /// Primary side: the nonce of the QR scanned for `pending_link_target`. It is sent
    /// back in the grant.
    pending_link_nonce: Vec<u8>,
    /// This device's prekeys, oldest first. The last one is handed out. Loaded on first
    /// use (`current_own_prekey`), because they are sealed with the local storage key,
    /// which arrives after the database is opened.
    own_prekeys: Vec<OwnPrekey>,
    own_prekeys_loaded: bool,
    /// The newest verified prekey of each known device (`store_peer_prekey`).
    peer_prekeys: HashMap<String, SignedPrekey>,
    /// Devices our pending HandshakeInit went to with prekey id 0, because we held none
    /// of their prekeys. A peer that hands out prekeys refuses such an init as a first
    /// contact. See `process_handshake_init`.
    id0_inits: std::collections::HashSet<String>,
    /// The active own device fingerprint once the swarm runs (set by `start_network` or, for an identity made or
    /// restored later, by `ensure_own_mailbox_subscription`). Names the own server mailbox. No gossip topic exists.
    own_mailbox_topic_fp: Option<String>,
    /// Devices this device started a pairing with and has no ratchet with yet. Key: peer_fp. Value: start
    /// time (ms). Only a marker (no gossip topic): dropped when the ratchet exists or after
    /// `PAIRING_MAILBOX_TTL_MS`.
    pairing_mailbox_subs: HashMap<String, u64>,
    /// The connection a verified IdentityExchange arrived on, per device. Only our
    /// IdentityExchange and Handshake to that device use it. The side that showed its
    /// code has no PeerId mapping yet (the IX maps nothing, see
    /// `process_identity_exchange`), and without gossip its reply had no route except a
    /// server. Dropped once a ratchet exists.
    pairing_reply_peer: HashMap<String, PeerId>,
    /// Multi-device: if THIS device was linked as a secondary to an identity, this is the
    /// signed `DeviceAdd` from the approving (primary) device. It is evidence when we
    /// introduce ourselves to contacts (`DeviceAddNotice`). Persisted in the
    /// `own_device_add` table.
    own_device_add: Option<DeviceAdd>,
    /// Parts of big stickers from my other devices, by sticker id: (arrival time of the
    /// first part in ms, parts). Memory only. A part lost to a restart arrives again with
    /// the next "Fetch stickers".
    sticker_parts: HashMap<String, (u64, Vec<Option<Vec<u8>>>)>,
    /// Multi-device: new device fingerprints announced beforehand by a
    /// `DeviceAddNotice` with a verified signature, whose `IdentityExchange` has not
    /// arrived yet. `evaluate_sender_device` silently accepts a device in this set as an
    /// addition signed by a known active device (NewDeviceViaSignedAdd), without showing
    /// an "unknown device" alert. Value: identity_id.
    verified_device_adds: HashMap<String, String>,
    /// The 256-bit key that encrypts the message history archive. Kotlin keeps a
    /// "history data key" wrapped in the Keystore, unwraps it at startup and loads it here
    /// with `setHistoryKey`. Rust never writes this key to disk; it stays in memory (see
    /// the message history note at the end of the file). While it is `None` (not loaded yet,
    /// or node mode never turned on), messages are not archived, only processed live.
    history_key: Option<[u8; 32]>,
    // --- Server (store-and-forward) option; see the `server_client` module ---
    /// Configured servers (persistent, `servers` table).
    servers: Vec<server_client::ServerRecord>,
    /// Per-server runtime state (connected, registered, which mailboxes were announced).
    /// Not persisted. It is rebuilt on every start.
    server_rt: HashMap<String, server_client::ServerRuntime>,
    /// Server RPCs in flight. If a `Deposit` fails, its envelope falls back to gossip
    /// (see `requeue_failed_deposit`).
    server_inflight: HashMap<request_response::OutboundRequestId, server_client::ServerInflight>,
    /// `(server_id, mailbox_id) -> highest processed seq`. Persistent. Without it, every
    /// restart would reprocess the whole mailbox.
    server_cursors: HashMap<(String, String), u64>,
    /// Mailboxes that answered `UnknownMailbox`, and when they may be asked again. This
    /// stops the "this recipient is not on my server" answer from costing one round trip
    /// per message.
    server_unknown_mailboxes: HashMap<(String, String), u64>,
    /// `UnknownMailbox` answers in a row per mailbox. The next pause doubles (see
    /// `SERVER_UNKNOWN_MAILBOX_MAX_TTL_MS`). A stored deposit resets it.
    server_unknown_streak: HashMap<(String, String), u32>,
    /// Archive records waiting to upload to the server (persistent).
    server_archive_queue: Vec<server_client::PendingArchive>,
    /// Files waiting to upload to the server (persistent).
    server_blob_uploads: Vec<server_client::PendingBlobUpload>,
    server_sweep_at: u64,
    /// Messages successfully deposited on a server: `(server_id, message_id)` -> deposit
    /// time (ms). Why: `awaiting_confirmation` resends the envelope until the end-to-end
    /// `Ack` arrives (up to 7 days). That is right for the gossip path, which stores
    /// nothing. On the server path the envelope already sits on disk. Depositing it again
    /// does not make the recipient more likely to see it. It only resends the same bytes.
    /// Measured on a real device: a queue to a contact identity that no longer existed
    /// (a broken pairing) redeposited two envelopes of 368 KB each about every 20 s. That
    /// was about 40 KB per second of pure waste over Tor, and it filled the server mailbox
    /// and the peer's rate limit, and kept a working chat from loading.
    /// Entries are forgotten after `SERVER_DEPOSIT_MEMORY_MS` (7 days, the message retry
    /// window, which is below the server mailbox TTL). The count is capped at
    /// `MAX_SERVER_DEPOSIT_MEMORY` entries.
    server_deposited: HashMap<(String, String), u64>,
    /// Where a packet landed on a server: `(server, message id)` -> `(mailbox, seq)`.
    /// `cancel_pending_message` uses it to withdraw the copy from the server too (see
    /// `ServerRequest::Cancel`). Without it, a cancelled message stayed on the server
    /// for 30 days while the recipient was offline.
    server_deposit_locations: HashMap<(String, String), (String, u64)>,
    /// Total and count of blob round-trip times, to tell whether a transfer is limited by
    /// latency or by bandwidth (see `server_client` `BLOB_PIPELINE_DEPTH`).
    blob_rtt_sum: u64,
    blob_rtt_count: u64,
    /// Root archive key (ARK). It belongs to the IDENTITY, not the device, unlike
    /// `history_key` (see `set_archive_root_key`).
    archive_root_key: Option<[u8; 32]>,
    /// Key for saving the skipped-message-key cache (see `skipped_keys` in ratchet.rs)
    /// encrypted to disk. It is loaded always, whatever the node mode. Message delivery
    /// needs it, so this is not an optional archive, unlike history_key. Kotlin loads it
    /// with `setSkippedKeyEncryptionKey`.
    skipped_key_encryption_key: Option<[u8; 32]>,
    /// `Context.filesDir`, passed from Kotlin in `initDatabase`. Kept so attachments
    /// (`attachments/`) know where to be written on disk. Everything else already resolves
    /// relative to this directory, as the DB path does.
    app_files_dir: Option<String>,
    /// `device_fingerprint -> PeerId`. Unlike gossip topic unicast, file chunk transfer
    /// (`request_response`) needs a target `PeerId`. This map is filled passively from the
    /// gossip `message.source` of any packet from a device (IdentityExchange, Handshake,
    /// Message, GroupUpdate). See `record_peer_id_if_known`. No separate discovery step is
    /// invented. If the process restarts, a new `PeerId` is made (see `with_new_identity`),
    /// and this map resets as well. At least one packet from the device must arrive before a
    /// file download from it can start.
    device_to_peer_id: HashMap<String, PeerId>,
    /// The one call in progress (ringing or active). See the `call` module.
    call: Option<call::CallSession>,
    /// `(call_id, reason)` of the last call that ended, for the call screen.
    last_call_end: Option<(String, String)>,
    /// Time (ms) of the last periodic media stats log line.
    call_stats_logged_at: u64,
    /// Set while `call::send_call_signal` publishes. The envelope goes to the server AND over the direct link. A "connected" peer can be a
    /// half-open link to a phone that just restarted. The direct copy then dies in a timeout and the ring never arrives.
    call_signal_sending: bool,
    /// Opens the call media streams. Set per swarm in `start_network`.
    stream_control: Option<libp2p_stream::Control>,
    /// `PeerId -> Multiaddr`. Filled from the `ConnectionEstablished` event. Used when a
    /// file download starts, to give `swarm.add_peer_address` an address hint that
    /// `request_response` can dial.
    peer_id_to_addr: HashMap<PeerId, Multiaddr>,
    /// Last working or shared address for a known remote DEVICE, in full
    /// `/ip4/.../tcp/.../p2p/<peer_id>` form. key = device_fingerprint. Unlike
    /// `peer_id_to_addr`, this is PERSISTENT (see the `device_addrs` table). It survives a
    /// restart. The periodic reconnect scan (`reconnect_sweep`) uses it to redial a peer
    /// that dropped, including on a different network where mDNS would not reach. It is
    /// updated at pairing (the rendezvous_node) and on every received packet (the real
    /// address of the current connection).
    device_last_addr: HashMap<String, String>,
    /// Fix for network robustness. Symptom: two devices paired over Tor, on the same LAN. When one switched to mobile data, it could no longer
    /// message the other device on the LAN, but still reached the remote node. `device_last_addr` holds ONE "last working address". When two
    /// devices on the same LAN connect with Tor on, a direct LAN connection usually forms before or instead of the Tor circuit (the same TCP port
    /// listens on 0.0.0.0 even with Tor on; see `start_network` and `TOR_LIBP2P_PORT`). That LAN address is written to `device_last_addr` by
    /// `record_peer_id_if_known`, and it overwrites the known `.onion` address if there was one. The LAN address becomes invalid for good when one
    /// device changes network (Wi-Fi to mobile data). The Tor connection does not depend on the network, but the `.onion` address had already been
    /// overwritten, so `try_reconnect_device` never tried it again. This map stores a known `.onion` address separately from `device_last_addr`,
    /// and no LAN or direct address ever overwrites it (see `remember_onion_addr`). `try_reconnect_device` now tries BOTH, when present, on every
    /// reconnect attempt.
    device_onion_addr: HashMap<String, String>,
    /// Last time `reconnect_sweep` ran. See `RECONNECT_SWEEP_INTERVAL_MS`.
    last_reconnect_sweep_at: u64,
    /// Last flush of `pending_envelopes` (`poll_events`): at most once per second.
    last_pending_flush_at: u64,
    /// Files `resume_incomplete_downloads_for` restarted in this process run.
    auto_resumed_downloads: std::collections::HashSet<String>,
    /// Multi-device: last time we asked sibling devices for a history backfill.
    /// We do not ask more often than `SIBLING_BACKFILL_INTERVAL_MS`.
    last_sibling_backfill_at: u64,
    /// Per sibling: (send time of the unanswered backfill request, send time of the last
    /// answered one). The second is the next watermark.
    sibling_backfill_since: HashMap<String, (u64, u64)>,
    /// Time of the last full `reconnect_all_known_now`. A network callback inside
    /// `NETWORK_CHANGE_DEBOUNCE_MS` only sets `network_change_pending`. `poll_events` runs it
    /// once, when the window ends.
    last_network_change_at: u64,
    network_change_pending: bool,
    /// See `retry_unconfirmed_messages`.
    last_unconfirmed_retry_at: u64,
    /// Device -> when its last HistorySyncRequest was answered (rate limit).
    history_answered_at: HashMap<String, u64>,
    /// Device -> (window start, row bytes sent in HistorySyncResponses since then).
    history_sent_bytes: HashMap<String, (u64, usize)>,
    /// Group `HistorySyncRequest` id -> members that already answered it (one answer each).
    /// Dropped with the request (`forget_history_request`).
    history_answered_by: HashMap<String, std::collections::HashSet<String>>,
    /// See `SIBLING_ROSTER_SYNC_INTERVAL_MS`.
    last_sibling_roster_sync_at: u64,
    /// Used to retry every device that had an address but no live connection, on every
    /// `reconnect_sweep` pass (at most every 15 s), both to the direct address and to all
    /// known relay addresses (see `dial_with_relay_fallback`). It never backed off. A peer
    /// that was gone for good (app uninstalled, address changed completely) was therefore
    /// retried forever, every 15 s plus one extra dial per relay. That woke the radio and
    /// used battery and network traffic for nothing. key = device_fingerprint, value = (time
    /// the next attempt is allowed (ms), consecutive failed attempts). It slows only the
    /// automatic periodic sweep and the send path (`ensure_connected`, where automatic
    /// retries also go). Opening a chat (`ensure_handshake`) and a network change ignore it.
    /// When the connection is made (see the "already connected" arm of `reconnect_sweep`),
    /// the entry is removed, so the next disconnect starts backoff from zero.
    reconnect_backoff: HashMap<String, (u64, u32)>,
    /// Saver mode: the devices that were connected at the last network change
    /// (`reconnect_all_known_now`). Only these get the fast reconnect window.
    fast_reconnect_fps: std::collections::HashSet<String>,
    /// Keepalive state per connected peer: next send time, consecutive failure count, pending request. Before a direct reconnect, three pings are
    /// sent at 2-second intervals. The stabilisation and battery behaviour is described in `KeepAliveState` and `KEEPALIVE_STABILIZE_MS`. A fresh
    /// entry is created on `ConnectionEstablished` and removed on `ConnectionClosed` (see the matching arms in `poll_events`). The connection is closed
    /// and redialed only after `KEEPALIVE_FAILURES_BEFORE_DISCONNECT` consecutive failures. A single late or lost keepalive no longer closes it.
    keepalive_state: HashMap<PeerId, KeepAliveState>,
    /// Events that leave the swarm in the flush at the END of `poll_events` (see the block at
    /// the end of that function) and cannot be handled yet. They are handled at the START of the
    /// NEXT turn, before the fresh events. Why: the swarm is polled only inside `poll_events`.
    /// When a chunk reply was handled and a new request was queued with `send_request`, the
    /// request went out only in the NEXT turn (about 1 s later), so each round trip gained about
    /// 1 s whatever the pipeline window. The short flush turn at the end removes that delay.
    /// Dropping events from that turn would lose a chunk reply, which is a stall, so they are
    /// kept here instead.
    deferred_swarm_events: Vec<libp2p::swarm::SwarmEvent<P2PBehaviourEvent>>,
    /// See `RATE_LIMIT_WINDOW_MS`. Key = the REAL connection identity (`PeerId`, proven by the
    /// Noise handshake and not spoofable). The `sender_device_fingerprint` header field in the
    /// packet is deliberately NOT used, because it is not verified at this point. An attacker
    /// could claim someone else's fingerprint and use up that person's rate quota. Value: (start
    /// of this window, packets counted so far in the window).
    message_rate_limiter: HashMap<PeerId, (u64, u32)>,
    /// Same shape, for served file chunks (see the `FileChunks` request arm).
    chunk_rate_limiter: HashMap<PeerId, (u64, u32)>,
    /// (window start, bytes) of chunks served per (peer, file) per day (`serve_chunk_request_budgeted`).
    chunk_bytes_served: HashMap<(PeerId, String), (u64, u64)>,
    /// (window start, count) for server-delivered mail (`source == None`). It has no peer id to
    /// key `message_rate_limiter` on. Over the budget, it waits in `deferred_incoming`.
    /// `server_fetch` and `commit_server_fetches` hold while that happens.
    server_mail_rate: (u64, u32),
    /// One (window start, count) shared by all non-established peers.
    unknown_peer_rate: (u64, u32),
    /// Packets that cannot be processed in this turn because of the rate limit, but must NOT
    /// be dropped (see `RateVerdict::Defer`). They are handled at the start of the next
    /// `poll_events` turn, before new arrivals, so the order is kept.
    deferred_incoming: std::collections::VecDeque<(Option<PeerId>, Vec<u8>)>,
    /// Fix: a device connected over Tor was never seen in a group it had been invited to. The fan-out loop of `invite_to_group`,
    /// `remove_from_group`, `set_group_avatar` and `delete_group` silently dropped a `GroupUpdate` whenever `resolve_active_device_for_identity`
    /// returned `None` for a member, for example because the device was not yet registered as "active". Tor pairing and handshakes can finish later
    /// than they do on the same LAN. There was no log, no retry, and the function still returned `Ok(())`.
    /// Now each (group_id, identity_id) pair that could not be sent keeps its latest `GroupUpdate` here. `group_sync_sweep` (run by the same periodic
    /// pattern as `reconnect_sweep`) retries it until the device resolves. It is in memory, the same scope as the other retry queues
    /// (`awaiting_confirmation` and `pending_envelopes`), and is cleared when the group is deleted locally (see `remove_group_locally`).
    pending_group_syncs: HashMap<(String, String), GroupUpdate>,
    /// Fix: a group member sometimes could not receive messages, and behaved inconsistently. `pending_group_syncs` above covered this failure class
    /// only for `GroupUpdate` (membership, name, avatar). The same fan-out pattern in `send_group_message`, `edit_group_message` and
    /// `delete_group_message` (skip a member's copy when `resolve_active_device_for_identity` returns `None`) was not covered. When a member's active
    /// device could not be resolved yet (no IdentityExchange had completed with that member since this process started, or the member briefly
    /// dropped out of "active"), messages to that member were lost silently. There was no error and no retry, and the sender never found out, since
    /// the function returned `Ok(...)` as long as at least one other member got a copy. The problem appeared only while that contact's connection or
    /// handshake state was unresolved. The other members, already resolved, were never affected.
    /// key = (group_id, member_identity_id). Value = the message contents not yet sent to that member, IN SEND ORDER. `group_sync_sweep` retries them
    /// periodically (same up-to-20 s interval) until the member resolves. It is a Vec, not a single entry like `pending_group_syncs`: several messages
    /// can go out before the member resolves (for example someone typing fast). All must be kept, in order. Keeping only the LAST one, as with
    /// GroupUpdate (where only the latest state matters), would lose messages here. Capped at `MAX_PENDING_GROUP_MESSAGES_PER_MEMBER` to bound memory:
    /// if a member never resolves for days or weeks, the oldest entries are dropped first.
    /// Fix: if the process dies while a member is unresolved, the queued messages used to be lost. This field was memory-only. Unlike
    /// `pending_durable_retries` (one pending packet each) it had no persistence. Each add and remove is now mirrored to the `pending_group_messages`
    /// SQL table (see `persist_pending_group_message` and `remove_persisted_pending_group_messages`). It is reloaded at app start by
    /// `load_pending_group_messages_from_db`, so the queue survives a process kill and restart.
    pending_group_messages: HashMap<(String, String), Vec<MessageContent>>,
    /// Group texts with a copy that was given up or cancelled: group-wide id -> the content and
    /// the devices that missed it. "Retry" on the bubble sends to those devices only
    /// (`retry_group_message_copies`).
    /// ponytail: memory only, like the failed bubble itself. After a restart the record is gone. Add a
    /// table if the failed state has to survive.
    group_failed_copies: HashMap<String, (MessageContent, Vec<String>)>,
    /// Whiteboard strokes and erases not sent yet, by board. See `whiteboard`.
    wb_outbox: HashMap<String, whiteboard::WbOutbox>,
    /// (board, device) -> when a page from that device was last answered with a digest.
    wb_reply_at: HashMap<(String, String), u64>,
    last_group_sync_sweep_at: u64,
    /// `first_contact_secrets` and the state it was computed from. See there.
    first_contact_cache: std::cell::RefCell<Option<(u64, Vec<Vec<u8>>)>>,
    /// The message `send_message_content_inner` is re-sending right now. If
    /// `regen_pending_for_peer` runs inside that send, it leaves this message out. Otherwise it
    /// would go out twice: once from the regen, once from the outer send.
    regen_skip_id: Option<String>,
    /// When `group_sync_sweep` reads the parked per-device copies again (`park_device_copies`).
    /// 0 means nothing was parked since the last read.
    durable_reload_at: u64,
    /// Time of the last periodic run of `enforce_history_storage_limit`. See
    /// `HISTORY_STORAGE_SWEEP_INTERVAL_MS`.
    last_storage_sweep_at: u64,
    /// Peers confirmed by `identify` to support the relay protocol and directly reachable (see the "Cross-network connectivity" note in SECURITY.md).
    /// They are shared in the QR packet (`QrPacket.known_relays`) and grow organically from `identify::Event::Received`. There is no fixed bootstrap list.
    /// This is the relay-specific form of sharing node addresses. Keeps at most `MAX_KNOWN_RELAYS`. Value: (full multiaddr, last seen or renewed time
    /// in ms). The second field drives LRU eviction (see `record_known_relay`). Before, a RANDOM entry was evicted from the full map (HashMap iteration
    /// order is arbitrary), so the one working relay could be dropped while dead ones stayed.
    known_relay_peers: HashMap<PeerId, (Multiaddr, u64)>,
    /// Until this time after a network change, `reconnect_sweep` runs in fast mode (see
    /// `FAST_RECONNECT_INTERVAL_MS`).
    fast_reconnect_until: u64,
    /// See `ensure_relay_reservations`. Per relay: the `/p2p-circuit` listener we opened, and the
    /// time (ms) of the last attempt.
    relay_listeners: HashMap<PeerId, (libp2p::core::transport::ListenerId, u64)>,
    /// Connection ids of the EXTRA connections opened to a peer (not the first one). See
    /// `BULK_PARALLEL_CONNECTIONS`. When a transfer ends, exactly these are closed.
    /// `disconnect_peer_id` cannot be used, because it closes all of them.
    extra_conns: HashMap<PeerId, Vec<libp2p::swarm::ConnectionId>>,
    /// Dials opened for a bulk transfer, by connection id. Only these become `extra_conns`. A
    /// reconnect dial after a network change is ALSO a second outbound connection. Treating it as
    /// "extra" and closing it kept the dead one alive.
    bulk_dials: HashMap<libp2p::swarm::ConnectionId, PeerId>,
    /// Open connections per peer. See `mark_connection_suspect`: when a new connection to a suspect
    /// peer comes up, the old ones are closed.
    peer_conns: HashMap<PeerId, Vec<libp2p::swarm::ConnectionId>>,
    /// Path quality of each open connection (`conn_path_rank`). Used to keep the better one when a
    /// second connection to the same peer comes up.
    conn_rank: HashMap<libp2p::swarm::ConnectionId, u8>,
    /// Inbound connections (peer, established ms) not yet known to belong to a known peer. See
    /// `sweep_unknown_inbound`.
    unknown_inbound: HashMap<libp2p::swarm::ConnectionId, (PeerId, u64)>,
    /// Consecutive server RPC timeouts per server peer. The server connection has no keepalive. After
    /// a network switch, a silently dead Tor circuit stayed "connected", so every deposit waited 30 s
    /// to fail, and the sweep never redialed.
    server_rpc_timeouts: HashMap<PeerId, u32>,
    /// Envelopes sent over `ENVELOPE_PROTOCOL`, until the peer answers. Value: (target device,
    /// envelope, first attempt, already retried once).
    envelopes_inflight: HashMap<request_response::OutboundRequestId, (String, NetworkEnvelope, u64, bool)>,
    /// Our onion address, as announced to identify (`add_external_address`).
    advertised_onion: Option<String>,
    /// Persisted sessions are loaded (see `initiate_handshake_with`).
    ratchets_loaded: bool,
    /// Onion addresses that peers announced through identify, by PeerId. Applied to
    /// `device_onion_addr` once the PeerId is tied to a device.
    peer_onion_addr: HashMap<PeerId, String>,
    /// Per-peer parallel transfer health. See `BulkHealth`.
    bulk_health: HashMap<PeerId, BulkHealth>,
    /// The last permanent error of `initiate_handshake_with` shown to the user for a peer (for
    /// example "Bad Kyber public key length", meaning corrupt or incompatible key data). The same
    /// error keeps recurring silently on every message, typing indicator and so on. The user is told
    /// only once. See that function's docs.
    handshake_failure_notified: HashMap<String, String>,
    /// The last time a handshake was refreshed for a peer (see `maybe_redo_handshake`). Recovering
    /// from a lost `HandshakeInit` only needs a new handshake, but doing it every turn would churn the
    /// session needlessly. This map enforces `HANDSHAKE_REDO_MIN_INTERVAL_MS`.
    /// The second field of the value is the root key abandoned by the PREVIOUS refresh.
    /// `initiate_handshake_with` does NOT unsubscribe the old topic when it subscribes the new one.
    /// That is deliberate: the other side may still publish on the old topic until it processes the new
    /// handshake. With repeated refreshes these subscriptions would pile up. Same "keep one generation
    /// late" pattern as `maybe_rotate_ratchet`: the previous generation's topic is dropped only at the
    /// next refresh.
    last_handshake_redo: HashMap<String, (u64, Option<Vec<u8>>)>,
    /// Per device: (first failure in the current streak, count). See `note_undecryptable`.
    undecryptable_from: HashMap<String, (u64, u32)>,
    /// Sent `HistorySyncRequest` ids -> (1:1 target identity, group, send time). A
    /// `HistorySyncResponse` is processed only when it matches one of these. Otherwise any
    /// contact could write fake messages into the archive with an unrequested "answer", or cancel
    /// another message's retry through its `request_id`. The fourth field is the request's window
    /// `(before, after)`: `Some` only for a user's "Fetch older history" press, the one answer that
    /// may bring back rows below the history floor, and only inside it.
    outstanding_history_requests: HashMap<String, (Option<String>, Option<String>, u64, Option<(i64, i64)>)>,
    /// Open "Fetch older history" requests to our own devices: (sibling device, before, after) ->
    /// (chat: identity id or group id, sent at). The answer echoes its window. A match is a user fetch
    /// and is consumed.
    sibling_fetch_open: HashMap<(String, i64, i64), (String, u64)>,
    /// Chat -> follow-up pages its presses may still ask for (`HISTORY_FETCH_MAX_PAGES`).
    history_fetch_pages: HashMap<String, u32>,
    /// BLOCKED identities. This is deliberately stricter than `revoke`. Revoke says a device is no longer used, and that person can come back with a
    /// new device. Blocking targets the PERSON. No packet from ANY device of that identity is accepted, no connection is attempted to any of them,
    /// and no "new device" alert is produced. Otherwise a blocked person could flood the user with alerts. The only way out is re-pairing IN PERSON:
    /// unblocking works only with a QR or manual code scan, and no remote packet can do it.
    blocked_identities: std::collections::HashSet<String>,
    /// Identities that sent `AccountDeleted`. No messages are sent to them any more.
    deleted_identities: std::collections::HashSet<String>,
    /// The Kotlin side turns this on when the app is in the background and the screen is off (see `set_power_save`). Effect: for a connection proven
    /// healthy, the keepalive interval widens from 20 s to `KEEPALIVE_POWER_SAVE_INTERVAL_MS`.
    /// Why this matters: after any activity, the cellular radio typically stays in its high-power state for 5-15 s. A probe every 20 s means the
    /// radio almost never gets to idle, for every connected peer. With the screen off, stretching this to 60 s opens long sleep windows without
    /// losing liveness detection.
    power_save: bool,
    /// The active network is metered (Kotlin `setMeteredNetwork`). With `power_save` this is
    /// radio-saver mode (see `RADIO_WINDOW_MS`).
    metered: bool,
    /// Next radio-saver window (ms). `radio_window_open` is this poll turn's verdict, read by the sweeps.
    radio_window_at: u64,
    radio_window_open: bool,
    /// Last `TorHandle::set_dormant` value (see `RADIO_AWAKE_MS`).
    tor_dormant: bool,
    /// Next full Tor wake in radio-saver mode (ms). See `TOR_FULL_WAKE_MS`.
    tor_wake_at: u64,
    /// When power save was last left (ms). Links are re-verified from then on. See the "syncing" status in
    /// `own_connection_status`.
    resync_since: u64,
    /// Ongoing downloads: key = file_id (see `DownloadState`).
    active_downloads: HashMap<String, DownloadState>,
    /// Maps the `OutboundRequestId` returned by `request_response::send_request` to the download it
    /// belongs to. This routes an incoming `Message::Response` to the right `DownloadState` (see the
    /// `FileChunks` arm of `poll_events`). Request id -> (file_id, chunk index). The index is required now:
    /// several chunks are in flight in the pipeline, so the chunk of a reply cannot be derived from
    /// `next_chunk_index`.
    download_request_ids: HashMap<request_response::OutboundRequestId, (String, u32)>,
    /// Events to append to the `Vec<String>` that `poll_events` returns synchronously, from places outside
    /// the body of `poll_events` (for example the file attachment `file_progress`, `file_complete` and
    /// `file_failed` events, and the `"status":"error"` event that `retry_unconfirmed_messages` emits when a
    /// message passes its maximum age). The name is historical, "attachment". It is now a general queue of
    /// deferred events. The `FileChunks` network events are produced inside the `RUNTIME.block_on` block in
    /// `poll_events`, which cannot reach the `results` vector outside it. So they are collected here and moved
    /// into `results` at the end of the loop (same pattern as the retry queue `pending_envelopes`).
    attachment_events: Vec<String>,
    /// (PeerId of a just-revoked own device, mono_ms at which to disconnect it).
    revoked_disconnects: Vec<(PeerId, u64)>,
    /// Delivery guarantee: the key is the message id of the packet we sent (Text, Edit, Delete and HistorySyncRequest packets). `poll_events`
    /// republishes every entry periodically until the peer confirms it (an Ack, or a HistorySyncResponse). See `ACK_RETRY_INITIAL_MS` and
    /// `ACK_RETRY_MAX_MS`. A successful gossip publish is only a local guarantee (see the note on `pending_envelopes` for why that is not enough).
    /// This is the app's only real end-to-end delivery guarantee layer.
    awaiting_confirmation: HashMap<String, PendingConfirmation>,
}

