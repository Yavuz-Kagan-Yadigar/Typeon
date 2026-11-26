//! Timeouts, limits and protocol ids, with the small types they belong to.

use super::*;


/// Time a `pending_envelopes` entry may wait. When it expires the envelope is marked "Failed". Applies to `Message`
/// envelopes that are not tracked in `awaiting_confirmation` (Ack, typing and similar). Tracked messages retry there
/// until confirmed. Handshake and IdentityExchange use `PENDING_HANDSHAKE_TIMEOUT_MS`.
pub(crate) const PENDING_ENVELOPE_TIMEOUT_MS: u64 = 20_000;

/// See `lazy_deposit_held`: the longest a non-urgent packet waits, in radio-saver mode, for an anonymous connection.
pub(crate) const LAZY_DEPOSIT_HOLD_MS: u64 = 30_000;
/// A held packet's queue lifetime is longer by the hold, or it was dropped before it went.
pub(crate) const LAZY_DEPOSIT_MAX_AGE_MS: u64 = LAZY_DEPOSIT_HOLD_MS + PENDING_ENVELOPE_TIMEOUT_MS;

/// One entry of `pending_envelopes`.
pub(crate) struct QueuedEnvelope {
    pub(crate) target: String,
    pub(crate) envelope: NetworkEnvelope,
    /// First publish attempt (ms): the timeout counts from here.
    pub(crate) first_attempt_at: u64,
    /// next retry (ms). The delay grows with the entry's age (1-30 s),
    /// so a Handshake to an offline peer is not sealed and deposited every
    /// second for 5 min. 0 = due now (connection came up).
    pub(crate) next_at: u64,
    /// `deposit_dedup_key`, computed once at enqueue.
    pub(crate) key: Option<String>,
}

impl QueuedEnvelope {
    pub(crate) fn new(target: String, envelope: NetworkEnvelope, first_attempt_at: u64) -> Self {
        let key = ciborium_bytes(&envelope).ok().map(|b| crate::server_client::deposit_dedup_key(&envelope, &b));
        let next_at = pending_retry_at(first_attempt_at, current_time_ms());
        QueuedEnvelope { target, envelope, first_attempt_at, next_at, key }
    }
}

/// retry delay = age / 8, clamped to 1-30 s.
pub(crate) fn pending_retry_at(first_attempt_at: u64, now: u64) -> u64 {
    now + (now.saturating_sub(first_attempt_at) / 8).clamp(1_000, 30_000)
}

/// Queue lifetime for `Handshake` and `IdentityExchange`, which is much longer. These two are `NetworkEnvelope`s, not
/// `MessageContent`, so they cannot enter `awaiting_confirmation`, and this queue is their only retry path. A 20 s lifetime
/// was too short: when the peer is offline, every send fails, `HandshakeInit` is dropped
/// after 20 s and never sent again, while the sender already holds a ratchet. The peer buffers the early packets and waits
/// for a handshake that never arrives.
/// Five minutes covers a peer that comes back within minutes. For longer outages, `maybe_redo_handshake` refreshes the
/// handshake during the retry pass of an unconfirmed message, so the handshake gets the same durability (7 days) as the message.
pub(crate) const PENDING_HANDSHAKE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// Measured on two real devices: with four transport paths open at once (LAN direct, Tor onion, server and gossip), the same envelope arrived
/// two to four times per message. The first copy is processed. Later copies fail to decrypt because the ratchet has moved on, and each logs an
/// error. That happened about three times a minute on both phones, for hours, wasting signature checks and radio time. `process_incoming_envelope`
/// now keeps a 64-bit hash of each successfully processed envelope for this window. Byte-identical copies are dropped silently. A duplicate
/// `Message` still gets its Ack re-sent, which is the purpose of the repeat. Memory: 16 bytes per entry, periodic pruning and a hard cap
/// (`INBOUND_DEDUP_MAX_ENTRIES`).
pub(crate) const INBOUND_DEDUP_WINDOW_MS: u64 = 10 * 60 * 1000;
pub(crate) const INBOUND_DEDUP_MAX_ENTRIES: usize = 8192;

/// See `pairing_mailbox_subs`. If a ratchet is never established (the peer is unreachable for good), the pairing-period
/// mailbox subscription must not stay open forever.
pub(crate) const PAIRING_MAILBOX_TTL_MS: u64 = 15 * 60 * 1000;

/// Minimum time between two handshake refreshes (see `maybe_redo_handshake`). A refresh resets the session (new ephemeral keys,
/// new root key, new mailbox id), so it is not free. For a device that stays offline for hours, one new attempt every ten
/// minutes is the only way out of "my handshake never arrived".
pub(crate) const HANDSHAKE_REDO_MIN_INTERVAL_MS: u64 = 10 * 60 * 1000;

// Keepalive uses a custom request-response protocol (`KeepAliveRequest`, `KeepAliveResponse`, `P2PBehaviour.keepalive`) instead of the
// stock `ping::Behaviour`. The stock one applies a single fixed interval to every connection, regardless of how long the connection
// has been healthy. Cellular radios stay in a high-power state for 5-15 s after any activity, so a fixed 2 s ping keeps the radio
// from ever idling while any peer is connected. This protocol widens the interval to `KEEPALIVE_IDLE_INTERVAL_MS` once a
// connection has stayed healthy for `KEEPALIVE_STABILIZE_MS`. A failure or a new connection drops it back to
// `KEEPALIVE_FAST_INTERVAL_MS` at once, so a new, unproven connection is still probed quickly. Liveness detection does not slow down.
// It only stops over-probing a connection that is already proven and quiet.
/// How long a revoked own device keeps its connection, so the revoke notice sent to it is delivered first (`revoke_own_linked_device`).
pub(crate) const REVOKE_DISCONNECT_DELAY_MS: u64 = 30_000;
pub(crate) const KEEPALIVE_FAILURES_BEFORE_DISCONNECT: u32 = 3;
/// See `server_rpc_timeouts`. Any answered request resets the count, so a busy
/// but alive connection (parallel blob chunks) is not dropped.
pub(crate) const SERVER_RPC_TIMEOUTS_BEFORE_DISCONNECT: u32 = 3;
/// Keepalive interval for a new connection that is not yet stable. Same as the old `ping::Behaviour` interval (two seconds, three tries).
pub(crate) const KEEPALIVE_FAST_INTERVAL_MS: u64 = 2_000;
/// Extended keepalive interval after a connection has stayed healthy for `KEEPALIVE_STABILIZE_MS`. Saves battery (see the constant above).
pub(crate) const KEEPALIVE_IDLE_INTERVAL_MS: u64 = 20_000;
/// Keepalive interval while the screen is off and the app is in the background (see `P2PCore.power_save`). Liveness detection is kept.
/// Only the probe rate of a proven, quiet connection drops. Any failure or new connection still resets it to `KEEPALIVE_FAST_INTERVAL_MS`.
pub(crate) const KEEPALIVE_POWER_SAVE_INTERVAL_MS: u64 = 60_000;
/// Healthy time without interruption after which a connection counts as stable and can be probed less often.
pub(crate) const KEEPALIVE_STABILIZE_MS: u64 = 120_000;
/// Maximum time one keepalive request waits for a reply. The Tor path is the default transport (see `tor.rs`): an onion circuit has
/// about six relay hops, and even a healthy circuit can take over 2 s. At 2 s, three slow but healthy replies in a row
/// (`KEEPALIVE_FAILURES_BEFORE_DISCONNECT`) would happen often over Tor, and the connection would be closed and rebuilt for no reason.
/// Was 6 s, then 4 s: most of that was the two sides waiting for the next poll turn. Polling is now event-driven
/// (`wait_for_network_activity`), and a round trip over Tor measures under 1 s. Went to 10 s because a probe to a phone whose LTE radio
/// is asleep waits for the radio to wake before Tor even starts. At 4 s, live links were declared dead, and every "reconnect" cost a
/// full onion circuit build. That churn kept the device radio awake.
pub(crate) const KEEPALIVE_TIMEOUT_SECS: u64 = 10;

/// Radio-saver window (metered network + screen off, see `P2PCore.metered`):
/// every periodic network job — keepalive probes, server sweep, reconnect
/// sweep — runs together once per window, so the cellular radio wakes once
/// per window instead of never sleeping (each packet keeps LTE up ~10 s).
/// Incoming data still arrives at once over the open links and server push;
/// a direct link that died in between is covered by the server path, so the
/// window length mostly trades wakeups against dead-link detection time.
pub(crate) const RADIO_WINDOW_MS: u64 = 8 * 60 * 1000;
/// Window on an unmetered network: a Wi-Fi wakeup has no LTE-style radio tail.
pub(crate) const RADIO_WINDOW_WIFI_MS: u64 = 4 * 60 * 1000;
/// How long Tor stays non-dormant after a full wake, see `TOR_FULL_WAKE_MS`.
pub(crate) const RADIO_AWAKE_MS: u64 = 30_000;
/// In radio-saver mode, Tor leaves dormant only this often, not at every window. Leaving dormant re-fires arti's periodic tasks. They refill the
/// onion-service circuit pool (12-16 circuits, about 130 KB), and that kept the LTE radio up about 100 s per window (measured: 32 % radio time,
/// 22 mAh/h). The window's own work (keepalive, server poll, redial) runs on existing circuits and builds what it needs on demand. The consensus
/// is valid for 3 h, so a refresh every 45 min keeps it fresh.
pub(crate) const TOR_FULL_WAKE_MS: u64 = 45 * 60 * 1000;
/// See `KeepAliveState.suspect`. If no Ack comes from a live connection within this time, probe the connection.
pub(crate) const ACK_SUSPECT_MS: u64 = 1_500;
pub(crate) const KEEPALIVE_PROTOCOL: &str = "/p2pmessenger/keepalive/1.0.0";
/// Advertised (never preferred) so identify tells peers we decode
/// `KeepAliveResponse.quiet_ms`. Older builds expect a unit response and
/// fail every probe on anything else, then drop the link every ~20 s.
pub(crate) const KEEPALIVE_QUIET_PROTOCOL: &str = "/p2pmessenger/keepalive/1.1.0";
/// Acks travel over this `request-response` protocol. When a live libp2p connection exists to the peer, Acks go in batches per peer
/// through this protocol instead of as ratchet-encrypted `MessageContent::Ack` packets.
/// - Reliable: the peer answers only after it has applied the Acks. If there is no answer (timeout, dropped connection, or an older
///   version that does not know the protocol), the same Acks fall back to an encrypted packet, which the server can hold. Without a
///   connection or a server, the sender's own retry plus `reack_if_already_handled` covers the gap.
/// - Efficient: a few bytes per batch, not a hybrid signature (Ed25519+ML-DSA), AEAD, a ratchet step and a send per Ack.
///   A group fan-out of dozens of Acks becomes one request. Not subject to the rate limit (like `file_chunks`).
/// - Identity: the requester is identified by its Noise-authenticated `PeerId`. `device_to_peer_id` is filled only from packets with
///   a verified signature, so there are no forged Acks.
pub(crate) const ACK_PROTOCOL: &str = "/p2pmessenger/ack/1.0.0";
/// See `start_network`. Maximum time for one connection to be established (dial, Noise, Yamux). The libp2p builder's fixed 10 s was not enough over Tor.
pub(crate) const SWARM_CONNECTION_TIMEOUT_SECS: u64 = 60;
/// Direct delivery to a connected device. A request/response goes over the Noise-authenticated connection itself, and the response
/// proves the peer got the bytes. The server stays as the fallback.
pub(crate) const ENVELOPE_PROTOCOL: &str = "/p2pmessenger/envelope/1.0.0";
/// Largest serialized envelope any path carries.
pub(crate) const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
/// Revokes one `IdentityExchange` or `SyncPayload` carries (about 4.7 KB each, so about 150 KB at most). See `own_revokes_to_send`.
/// Equal to the receiver's cap (the 32 owner-revoke tombstones of a contact): more were sent but never applied.
pub(crate) const REVOKES_PER_PACKET: usize = 32;

/// Swarm events one `poll_events` turn handles in its main drain.
pub(crate) const MAX_SWARM_EVENTS_PER_TURN: u32 = 256;
/// Largest sticker part sent to my other devices inside one `SiblingEcho`
/// (well under `MAX_ENVELOPE_BYTES` and the server's deposit limit); a
/// bigger sticker goes in several parts.
pub(crate) const STICKER_SYNC_MAX_BYTES: usize = 768 * 1024;
/// Upper bound on the parts of one sticker. `MAX_STICKER_BYTES` (4 MiB) in parts of `STICKER_SYNC_MAX_BYTES` needs six.
pub(crate) const STICKER_SYNC_MAX_PARTS: usize = 8;
/// Stickers being put together from parts at once; the oldest is dropped.
pub(crate) const STICKER_PARTS_MAX_PENDING: usize = 16;
pub(crate) const ACK_BATCH_MAX: usize = 256;
pub(crate) const ACK_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Upper bound of `known_relay_peers` (see the field's docs).
pub(crate) const MAX_KNOWN_RELAYS: usize = 10;
/// See `ensure_relay_reservations`. A reservation that never gets a listen address (never accepted) is dropped after this time and requested again.
pub(crate) const RELAY_RESERVATION_RETRY_MS: u64 = 2 * 60 * 1000;

/// Yamux receive window. The default (`DEFAULT_CREDIT`) is 262,144 bytes. A file chunk is `FILE_CHUNK_SIZE + 16` bytes (262,160) because of the AEAD tag, so each chunk
/// exceeds the credit by 16 bytes and the sender waits for a window update before it can send the last 16 bytes. That is an extra round trip per chunk, which can nearly
/// double transfer time over Tor. yamux 0.13's automatic window growth does not help: `request_response` opens a new substream per request, which carries one chunk and
/// closes, so each chunk starts from the initial window. A fixed, generous window is used instead. Setting it required the yamux 0.12 path in the libp2p wrapper, so
/// auto-tuning is not used.
pub(crate) const YAMUX_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
/// Buffer cap per substream. Must not be smaller than the window.
pub(crate) const YAMUX_MAX_BUFFER: usize = 8 * 1024 * 1024;

/// see `YAMUX_RECEIVE_WINDOW`.
pub(crate) fn tuned_yamux() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    #[allow(deprecated)]
    {
        cfg.set_receive_window_size(YAMUX_RECEIVE_WINDOW);
        cfg.set_max_buffer_size(YAMUX_MAX_BUFFER);
    }
    cfg
}


/// Health state of a parallel transfer to one peer. See `manage_bulk_connections` and `note_bulk_timeout`.
#[derive(Default, Debug)]
pub(crate) struct BulkHealth {
    /// Times of recent timeouts. Only those inside `BULK_STRIKE_WINDOW_MS` are kept.
    pub(crate) strikes: Vec<u64>,
    /// Earliest time of the next extra dial.
    pub(crate) next_dial_at: u64,
    /// Current retry wait. Doubles on every drop.
    pub(crate) backoff_ms: u64,
    /// Number of times a circuit was dropped.
    pub(crate) drops: u32,
    /// Time until which parallelism is abandoned, if it was given up.
    pub(crate) giveup_until: u64,
}

/// Number of libp2p connections kept open to one peer while a bulk transfer (file chunks) runs.
/// Why: `request_response` already spreads outgoing requests over the open connections (`ix = request_id % connections.len()`), and
/// `ArtiDialTransport` gives each connection its own Tor circuit. Together, the chunk pipeline spreads over several circuits. The
/// bandwidth of one Tor circuit was the real ceiling measured here.
/// Opened only while a transfer runs and closed when it ends. An onion circuit is expensive to build (about 5-15 s), and an idle
/// extra circuit loads both the Tor network and the battery.
/// The number was chosen by measurement. The same ~14 MB file was transferred between the same pair, alternating variants so both saw
/// the same network conditions. The time was read from the receiver's disk:
///   1 connection  -> median  46 KB/s (n=5, range 23-182)
///   3 connections -> median  90 KB/s (n=7, range 51-204)
///   6 connections -> median 150 KB/s (n=3, range 64-173)
/// Going from 1 to 3 is consistent with the mechanism: with one circuit, speed depends on that circuit's quality (the results are
/// bimodal, 169-182 or 23-46), and with several, a bad circuit is diluted by the others.
/// Going from 3 to 6 was not statistically significant: 6 led five of nine pairs, with heavily overlapping ranges. Since there is no
/// measurable gain, 3 is kept. Six circuits double the Tor load and the battery cost on both phones for the same transfer.
/// Correction: an earlier note here said that five connections were much worse, with the window dropping to 2. That measurement predates
/// dead-circuit recovery. The dial interval was 12 s, so building six circuits ate the first minute of the transfer. The hardened build did
/// not reproduce that collapse. The wrong reason was removed from the code.
pub(crate) const BULK_PARALLEL_CONNECTIONS: usize = 3;
/// Base wait between extra connections to the same peer, so new dials are not stacked while one is in flight. Doubles on each failure
/// (see `BulkHealth.backoff_ms`).
pub(crate) const BULK_DIAL_MIN_INTERVAL_MS: u64 = 6_000;
/// Upper bound of the retry wait.
pub(crate) const BULK_DIAL_MAX_BACKOFF_MS: u64 = 120_000;
/// Timeouts within this window that trigger one circuit drop. A single timeout is normal over Tor. The old recovery code dropped all three
/// circuits at the first timeout, so two healthy circuits went down with one that hiccupped. The way to separate a dead circuit from noise is
/// the count inside the window, not a single event.
pub(crate) const BULK_STRIKE_WINDOW_MS: u64 = 60_000;
pub(crate) const BULK_STRIKES_TO_DROP: usize = 3;
/// After this many drops, parallelism is abandoned for the rest of this transfer. If the path is bad for good, opening and closing circuits
/// (each one 5-15 s, racing with data traffic while it builds) does not help. It makes things worse. Going down to one circuit and moving steadily
/// finishes sooner.
pub(crate) const BULK_MAX_DROPS_BEFORE_GIVEUP: u32 = 3;
/// Wait after parallelism is abandoned, before retrying it.
pub(crate) const BULK_GIVEUP_COOLDOWN_MS: u64 = 300_000;

/// Maximum size of the `contacts` table. The `NewContactTofu` arm of `evaluate_sender_device` is triggered both by the user's own
/// QR or manual pairing, and by a one-sided `IdentityExchange` arriving unexpectedly on the mailbox topic (`p2p_msg_<own_fingerprint>`, always
/// subscribed). The second case needs no local action: the sender only has to know the fingerprint, for example from a shared group,
/// the DHT or a shared relay list. The one-sided QR flow needs this behaviour, so it is kept on purpose. But without a limit,
/// an attacker who can create fresh identities for free could flood the contact list and the database (every record is also written to SQLite).
/// Once the cap is reached, new TOFU records from identities never seen before are dropped silently. Devices of known contacts (
/// `NewDeviceViaSignedAdd` / `UnverifiedNewDeviceAlert`) are not affected. Only brand new contacts stop. 500 is generous for the target
/// audience (groups of friends) and still caps an attacker's cost.
pub(crate) const MAX_CONTACTS: usize = 500;

/// Maximum frequency of sending a mutual `IdentityExchange` reply to one device. See `P2PCore.last_identity_exchange_reply`.
pub(crate) const IDENTITY_EXCHANGE_REPLY_MIN_INTERVAL_MS: u64 = 60_000;

/// Per-device rate limit on incoming packets. The existing limits (`MAX_CONTACTS`, `MAX_EARLY_PACKETS_PER_PEER` and so on) bounded memory growth
/// but did not limit how often a KNOWN device could send. A compromised device could keep sending valid-looking `Text`, `Handshake` or
/// `IdentityExchange` packets and drive CPU (ratchet decryption, hybrid signature checks), disk (archive writes) and battery use. This is the
/// last check against that. `RATE_LIMIT_MAX_PER_WINDOW` is generous enough for normal use (fast typing, bursts, group fan-out), but still
/// limits a real flood.
pub(crate) const RATE_LIMIT_WINDOW_MS: u64 = 10_000;
pub(crate) const RATE_LIMIT_MAX_PER_WINDOW: u32 = 60;
/// all non-established peers together, per `RATE_LIMIT_WINDOW_MS`.
pub(crate) const RATE_LIMIT_MAX_UNKNOWN_TOTAL: u32 = 300;

/// Per-window cap for peers that have an established session.
/// Delivery: the old code did not distinguish known and unknown senders, and a packet over the cap was dropped silently. This caused a real loss
/// pattern in P2P mode. A peer that had been offline for a week came back and published hundreds of queued messages in a row. We accepted six per
/// second and dropped the rest. The messages were not lost (the sender retries until acknowledged), but the retries stretched over hours, since the
/// backoff grew from 5 s to 2 min. In server mode the same packets were injected with `source = None`, so the rate limit never applied. The two
/// modes were asymmetric.
/// Now two things happen. Peers with an established session get a much higher cap (60 per second), and a packet over the cap is not dropped.
/// It is DEFERRED (see `deferred_incoming`).
pub(crate) const RATE_LIMIT_MAX_ESTABLISHED: u32 = 600;

/// Upper bound of the deferred incoming queue, for memory protection. When it is full, the OLDEST entry is dropped. The sender retries it anyway.
pub(crate) const MAX_DEFERRED_INCOMING: usize = 2000;

/// See `rate_verdict`. The three outcomes of the rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RateVerdict {
    /// Process now.
    Allow,
    /// Over the cap, but the sender is a peer with a VERIFIED identity: defer it and process it on the next turn instead of dropping it.
    Defer,
    /// Over the cap and the sender is not recognized. This is the main protection against signature-check cost, and the packet is dropped.
    Drop,
}

/// Upper bound of `pending_device_alerts`, the same pattern as `known_relay_peers` and `early_packets`. The map was unbounded before. An attacker
/// who copies a known contact's identity_id, without a signed DeviceAdd chain, could send "new device" packets with fresh keys over and over and grow
/// the map without limit (memory and disk exhaustion, even if the user never accepts or rejects an alert). When the cap is reached, new alerts are
/// dropped silently. A user with dozens of pending alerts gains nothing from one more, and the per-peer rate limit still applies to the packet.
pub(crate) const MAX_PENDING_DEVICE_ALERTS: usize = 200;

/// `reconnect_sweep` runs at this interval (self-healing reconnect). `poll_events` is called regularly, so no separate timer is needed. The sweep
/// runs only when this interval has elapsed. 15 s reconnects a dropped contact at a reasonable pace without generating needless dial traffic.
pub(crate) const RECONNECT_SWEEP_INTERVAL_MS: u64 = 15_000;
/// see `P2PCore.fast_reconnect_until`.
pub(crate) const FAST_RECONNECT_INTERVAL_MS: u64 = 3_000;
pub(crate) const FAST_RECONNECT_WINDOW_MS: u64 = 60_000;
/// network callbacks closer than this are coalesced into one redial
/// round (flapping LTE/Wi-Fi redialed every contact on every callback).
pub(crate) const NETWORK_CHANGE_DEBOUNCE_MS: u64 = 10_000;

/// A target that has not been seen for this long is treated as probably gone for good (the app was uninstalled or the device was reset). The
/// tablet and a second phone both held hundreds of rows for the same few "ghost" sibling devices, with `last_seen` over three days old, which made
/// device-to-device delivery unreliable. `sibling_active_devices` no longer includes such a target in new sync traffic (see there), and
/// `load_pending_durable_retries_from_db` does not retry sends to it at startup (see there). Neither deletes `known_remote_devices` or
/// `pending_durable_retries` rows. They only stop the useless retry storm. If the device comes back and refreshes `last_seen`, the next turn
/// picks it up normally.
pub(crate) const STALE_PEER_RETRY_HORIZON_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Multi-device: minimum interval between requests for history backfill from sibling devices. Repeatedly asking for the last N messages
/// of every contact or group is wasteful. Duplicates are already removed by `message_id`.
pub(crate) const SIBLING_BACKFILL_INTERVAL_MS: u64 = 30 * 60_000;
/// Chat open asks the siblings for that chat's newest rows at most this often (see `refresh_chat_from_siblings`).
pub(crate) const SIBLING_REFRESH_MIN_MS: u64 = 60_000;
/// the backfill watermark is the requester's clock, the filter the
/// responder's; this much skew between own devices still loses nothing.
pub(crate) const SIBLING_BACKFILL_SINCE_MARGIN_MS: u64 = 10 * 60_000;
/// Maximum messages requested or sent per contact or group during a backfill.
pub(crate) const SIBLING_BACKFILL_PER_CONVERSATION: u32 = 30;
/// Multi-device self-repair: interval at which the device list (roster) is sent again to sibling devices.
/// Reason (real failure): `process_handshake_init` rejects a packet from an unknown sender ("Unknown sender device"). If device B has never learned
/// device C, the two can never establish a session, so C cannot introduce itself to B either. Only a third device that knows both (for example the
/// primary that did the linking) can break that asymmetry. If the single announcement during linking (`DeviceSync`) is missed, as happened, nothing
/// recovered it, and a setup with three or more devices stayed incomplete for good. Now the roster is sent again whenever a link to a sibling comes up,
/// rate-limited by this interval. The load is low: `build_sync_payload` leaves avatars out on purpose (see that function), so only keys and names go.
pub(crate) const SIBLING_ROSTER_SYNC_INTERVAL_MS: u64 = 60 * 60 * 1000;
/// Maximum total records in one `SiblingHistoryResponse`. It must stay well below the 1 MiB envelope limit (`MAX_ENVELOPE_BYTES`).
pub(crate) const SIBLING_BACKFILL_MAX_ENTRIES: usize = 300;
/// `sync_roster_to` skips roster parts a sibling already got; once this long after the last full send, every part goes again.
pub(crate) const ROSTER_RESEND_ALL_MS: u64 = 24 * 60 * 60 * 1000;
/// `journal_sibling_op`: rows kept, and their age limit.
pub(crate) const SIBLING_JOURNAL_MAX_ROWS: usize = 5000;
pub(crate) const SIBLING_JOURNAL_MAX_AGE_MS: u64 = 90 * 24 * 60 * 60 * 1000;
/// `replay_sibling_journal`: operations sent again per backfill answer.
pub(crate) const SIBLING_JOURNAL_REPLAY_MAX: usize = 200;

/// Delivery limit (`MessageTooLarge`, see `PublishFailure`): the total text payload of one `HistorySyncResponse` or `SiblingHistoryResponse` must not
/// exceed this many bytes. A row-count limit alone was not enough, because individual message texts can be arbitrarily long. 300 long messages
/// easily exceed the 1 MiB envelope limit (`MAX_ENVELOPE_BYTES`), before the hybrid signature and ratchet overhead are added. 512 KB leaves room below
/// that limit. The part that is cut off is fetched later by paging.
pub(crate) const HISTORY_SYNC_MAX_TEXT_BYTES: usize = 512 * 1024;
/// See `HISTORY_SYNC_MAX_TEXT_BYTES`. The `limit` field of a request is controlled by the other side, so the row count is limited separately too.
pub(crate) const HISTORY_SYNC_MAX_MESSAGES: u32 = 200;

/// One "Fetch older history" press asks every source for this span: the
/// window `[cursor - HISTORY_FETCH_WINDOW_MS, cursor)` by send time.
pub(crate) const HISTORY_FETCH_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Follow-up pages one "fetch older history" press may request when a source cuts its answer short (`more`), across all sources of the chat.
/// The rest of the window arrives within the same press, and a peer cannot make us ask forever.
// ponytail: shared by all sources. A busy group month with many capped members could run out. Use per-source budgets if that shows up.
pub(crate) const HISTORY_FETCH_MAX_PAGES: u32 = 20;
/// Most held-row tags one press request carries (`HistorySyncRequest.have`, `press_windows`): 4096 x 8 bytes, about 36 KB in CBOR.
pub(crate) const HISTORY_FETCH_HELD_MAX: usize = 4096;
/// Earliest accepted message time: 1 January 2025 UTC. The first cursor of a chat ignores rows stamped before it, such as rows from a device clock stuck at 1970 or a backdated row.
pub(crate) const HISTORY_FETCH_EPOCH_MS: i64 = 1_735_689_600_000;

/// `reconnect_sweep` dials and resends `IdentityExchange` for a pending device link target (`pending_link_target`) on every sweep (at most every 15 s).
/// If the link never completes (the user scanned the QR and gave up, and the devices never met again), this was an unbounded radio and traffic leak
/// until the process restarted. Automatic attempts stop beyond this horizon. If the user still wants the link, they scan the QR again, which refreshes this field.
pub(crate) const PENDING_LINK_RETRY_HORIZON_MS: u64 = 60 * 60 * 1000;

/// See `reconnect_backoff`. Exponential backoff per consecutive failed automatic reconnect: 15 s, 30 s, 60 s, and so on, capped at
/// `RECONNECT_BACKOFF_MAX_MS`. The first few attempts stay fast, since a brief network blip recovers in seconds. A permanently unreachable contact
/// gets attempts that become less and less frequent.
pub(crate) const RECONNECT_BACKOFF_BASE_MS: u64 = RECONNECT_SWEEP_INTERVAL_MS;
pub(crate) const RECONNECT_BACKOFF_MAX_MS: u64 = 10 * 60 * 1000;
/// Radio saver cap: every failed onion dial burns hs-pool circuits (HsDir lookups), and the pool refills itself in the background. So a long-gone
/// peer must not be retried every window. It reconnects to us when it is back. 3 h: at 30 min, four long-offline peers cost 270-410 KB and 40-75 s
/// of LTE radio time per round.
pub(crate) const RECONNECT_BACKOFF_SAVER_MAX_MS: u64 = 3 * 60 * 60 * 1000;

/// Interval of `group_sync_sweep`. See `pending_group_syncs`. Deliberate deviation: a device connected over Tor is also retried for groups it was
/// invited to.
pub(crate) const GROUP_SYNC_SWEEP_INTERVAL_MS: u64 = 20_000;
/// Outside radio saver, a network change force-dials a device heard from
/// within this long (`last_seen` is stamped at most hourly).
pub(crate) const NETWORK_CHANGE_FORCE_SEEN_MS: u64 = 2 * 60 * 60 * 1000;
/// An unchanged own address is announced to contacts again after this long.
pub(crate) const ADDRESS_REANNOUNCE_MS: u64 = 24 * 60 * 60 * 1000;
/// How long a parked per-device copy waits before `group_sync_sweep` resends it.
pub(crate) const DURABLE_PARK_RELOAD_MS: u64 = 60_000;

/// Interval of the periodic self-repair scan for `enforce_history_storage_limit` (see `last_storage_sweep_at`). It is a second safety net beside the
/// immediate check that runs whenever a file completes. For example, after the user lowers the limit, files already stored are trimmed too.
/// Rate-limited, so a full SQL SUM is not run on every `poll_events` turn.
pub(crate) const HISTORY_STORAGE_SWEEP_INTERVAL_MS: u64 = 30_000;

/// Delivery gives no ordering guarantee. The FIRST message of a chat can arrive before the `HandshakeInit` that makes it decryptable. Before, in
/// that case `receive_message` failed with "No ratchet session for sender" and dropped the packet. A DM recovered through the ack retry, but group
/// messages had no retry, so they were lost for good. Such packets are now buffered here and replayed once the handshake completes.
/// The buffer is bounded (memory and DoS protection): at most `MAX_EARLY_PACKETS_PER_PEER` per peer, and entries older than `EARLY_PACKET_TTL_MS` are pruned.
/// This time was a fixed 120 s before, which did not match `EARLY_EDIT_DELETE_TTL_MS` (already raised to `MAX_UNCONFIRMED_AGE_MS` for the same
/// reason). The useful lifetime of a buffered packet should match how long the sender keeps retrying the same message. If the handshake arrives
/// after 120 s (a slow Tor circuit, a queued `HandshakeInit`, or a backlog pulled from the server), the buffer was emptied and messages were dropped
/// for that round. The memory bound does not change: the real limit is the count, `MAX_EARLY_PACKETS_PER_PEER`, not the time.
pub(crate) const EARLY_PACKET_TTL_MS: u64 = MAX_UNCONFIRMED_AGE_MS;
/// See `P2PCore::unproven_fails_blocked`: failed decrypts allowed per unproven direct carrier per window, and the map bound.
pub(crate) const UNPROVEN_FAIL_MAX: u32 = 8;
pub(crate) const UNPROVEN_FAIL_WINDOW_MS: u64 = 60_000;
pub(crate) const UNPROVEN_FAIL_PEERS: usize = 256;
/// see `P2PCore.unknown_group_held`: how long, for how many groups, and how
/// many packets per group content for a group we do not hold is kept.
pub(crate) const UNKNOWN_GROUP_HOLD_TTL_MS: u64 = 30 * 60_000;
pub(crate) const UNKNOWN_GROUP_HOLD_GROUPS: usize = 16;
pub(crate) const UNKNOWN_GROUP_HOLD_PER_GROUP: usize = 64;
/// Size of the buffer for packets that arrive BEFORE the handshake. It was raised from 20 to 200. Twenty was too small exactly where it matters most:
/// a peer that was offline for a long time comes back and sends dozens of queued messages in a row, and the handshake may arrive among or after
/// them. Anything beyond 20 was dropped, oldest first. The loss was not permanent (the sender retries), but it was slow and uneven. Same size as
/// `MAX_PENDING_GROUP_MESSAGES_PER_MEMBER`. The limit counts packets, and each message is small.
pub(crate) const MAX_EARLY_PACKETS_PER_PEER: usize = 200;

/// Delivery gives no ordering guarantee. An `Edit` or `Delete` can reach the other side before the `Text` it targets. The target row was
/// missing, so `message_owned_by_sender` returned `false`, and the packet was acked and rejected for good. When no row exists at all (as opposed
/// to a row owned by someone else), the packet is now buffered and retried once the target `Text` is archived (see `pending_edits_deletes` and
/// `replay_buffered_edits_deletes`).
/// The buffer used to live for `EARLY_PACKET_TTL_MS`, a fixed 120 s. If the target `Text` arrived later (a slow Tor circuit, or the sender's
/// device asleep), the buffer was cleared and the edit or delete was lost for that moment. The original sender keeps resending the same
/// Edit or Delete until acknowledged (exponential backoff, up to `MAX_UNCONFIRMED_AGE_MS`), so the loss was not permanent. The lifetime now equals
/// `MAX_UNCONFIRMED_AGE_MS`, which is aligned with the ratchet rotation window. Beyond that window the `Text` itself is re-encrypted with fresh
/// ciphertext (see `regen_content`), so the buffer and the message's validity period match.
pub(crate) const EARLY_EDIT_DELETE_TTL_MS: u64 = MAX_UNCONFIRMED_AGE_MS;
pub(crate) const MAX_EARLY_EDITS_DELETES_PER_TARGET: usize = 8;

/// See `pending_group_messages`. Maximum number of queued messages for one group member, while that member is unresolved. The oldest is dropped first.
/// Memory protection.
pub(crate) const MAX_PENDING_GROUP_MESSAGES_PER_MEMBER: usize = 200;

/// The onion service's virtual port: the port in our `/dns/<host>.onion/tcp/<port>` address. No local socket uses it; inbound streams
/// reach the swarm in-process (`tor::OnionListen`).
pub(crate) const TOR_LIBP2P_PORT: u16 = 42611;

/// A `HandshakeInit` whose `timestamp` differs from the current time by more than this many milliseconds (ahead or behind) is rejected. This stops
/// replay of old captured handshakes, while tolerating reasonable clock skew between devices. Ten minutes is a generous real-world window for two
/// phones, but not unlimited.
pub(crate) const HANDSHAKE_MAX_SKEW_MS: u64 = 10 * 60 * 1000;
/// How old an init may be: as long as a message is retried, since the server
/// mailbox holds the init for a peer that is off.
pub(crate) const HANDSHAKE_MAX_AGE_MS: u64 = TEXT_RETRY_GIVE_UP_MS;
/// Two inits created this close together (by their own timestamps, not by when
/// they arrive) are one simultaneous handshake. See `process_handshake_init`.
/// Colliding inits are created seconds apart. A real re-handshake comes much
/// later (a redo waits at least `HANDSHAKE_REDO_MIN_INTERVAL_MS`).
pub(crate) const HANDSHAKE_COLLISION_WINDOW_MS: u64 = 90 * 1000;
/// See `note_undecryptable`.
pub(crate) const UNDECRYPTABLE_BEFORE_REHANDSHAKE: u32 = 3;
pub(crate) const UNDECRYPTABLE_WINDOW_MS: u64 = 2 * 60 * 1000;
pub(crate) const UNDECRYPTABLE_REDO_MIN_INTERVAL_MS: u64 = 2 * 60 * 1000;

/// Deliberate deviation (see the "Cross-network connectivity" note in SECURITY.md): manual relay address entry is still in Settings. But two
/// strangers with no shared relay history (two new users on different networks) need to be able to match without any manual setup. So a default
/// bootstrap relay list is embedded in the app, like the default bootstrap nodes of IPFS and BitTorrent clients. In `start_network` each entry is
/// added with the same function as the manual one (`add_known_relay_address`).
/// Setup note: the list starts EMPTY on purpose. A random or non-existent address causes silent failed dials. After a Typeon node is set up with
/// Node mode on and a public IP, paste that device's full onion address from `getNodeAddress()` as a string here (for example
/// "/dns/<host>.onion/tcp/<port>/p2p/12D3Koo..."). A rebuild is needed. Users can still add relays they know in Settings. This list is a starting
/// point for someone who knows no address yet, not a replacement for that.
pub(crate) const DEFAULT_BOOTSTRAP_RELAYS: &[&str] = &[
    // "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWExampleReplaceWithRealAddress",
];

/// Deliberate deviation, reliable delivery: packets that carry `Text`, `Edit`, `Delete` or `HistorySyncRequest` are resent at
/// these intervals until the peer acknowledges them (an `Ack`, or a direct `HistorySyncResponse` for HistorySyncRequest). Exponential backoff,
/// capped at `MAX`. A local send success does not guarantee the peer really received it (see the `awaiting_confirmation` field). So
/// unlike the old `pending_envelopes` queue, there is no upper time limit here. Retries continue until the peer confirms.
pub(crate) const ACK_RETRY_INITIAL_MS: u64 = 15_000;
pub(crate) const ACK_RETRY_MAX_MS: u64 = 120_000;
/// Upper bound of `recently_acked`. Ack and Seen are sent once. Before, they were sent nine times unconditionally (about 10.6 min). A lost Ack is
/// covered by the sender's own retry: even if the recipient cannot decrypt that copy, it finds the message in this map and re-sends the Ack (see
/// `reack_if_already_handled`). The window matches how long the sender keeps retrying the same ciphertext (`MAX_UNCONFIRMED_AGE_MS`). After that the sender
/// re-encrypts and sends fresh anyway.
pub(crate) const RECENTLY_ACKED_MAX_ENTRIES: usize = 8192;
/// Critical: a packet is encrypted against one specific ratchet chain step (see `PendingConfirmation.envelope`, resent AS-IS without re-encryption).
/// If the peer has ALREADY consumed that step (the normal flow), and the session has since gone through a 30-minute DH/KEM rotation
/// (see `ratchet::RATCHET_ROTATION_MS`), the recipient's skipped-key cache for the old chain is cleared entirely (`perform_dh_ratchet` and
/// `apply_rotation`, which is the intended forward-secrecy result). From that point the packet can NEVER be decrypted. "Keep retrying until
/// acknowledged" then means trying something cryptographically impossible, and only makes the recipient log "Decryption failed" forever. This pattern
/// was observed in a long test session, where several messages fell into this state at once. So `awaiting_confirmation` is NOT unbounded. It has an
/// age limit a little below the rotation window (with a safety margin). Past it, the packet is marked "Failed", and the user can resend it manually as a new message.
pub(crate) const MAX_UNCONFIRMED_AGE_MS: u64 = ratchet::RATCHET_ROTATION_MS - 5 * 60 * 1000;

/// Deliberate deviation: plain `Text` messages (1:1 and group fan-out copies) are not marked "Failed" when `MAX_UNCONFIRMED_AGE_MS` (about 25 min)
/// passes. They join the `PendingConfirmation.regen_content` mechanism (see that field). Before, only Edit, Delete and GroupUpdate used it. The
/// message is re-encrypted under a fresh ratchet step and keeps the same `message_id` (see the `message_id_override` of
/// `send_message_content_inner`). The UI bubble and the `awaiting_confirmation` entry keep their identity, so a manual resend creates no new
/// bubble. The retry is not unbounded: `PendingConfirmation.original_sent_at` (the time the message first entered the queue, which stays fixed
/// across regenerations) is checked against this window, and past it the message is given up (see `retry_unconfirmed_messages`). The window is
/// 7 days. This covers a contact who is offline for days, and the server's mail retention (14 days) is longer. `FILE_RETENTION_GRACE_MS` follows
/// this value, so attachments are kept for the same time. A file offer that is still being retried finds its file on disk. On app start (Kotlin
/// `retryAllPendingNow`), everything in this window is retried at once.
pub(crate) const TEXT_RETRY_GIVE_UP_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// See `link_request_open_until`. The grant can arrive late after the primary device scans the QR, because of permanent retry or the server mailbox
/// (for example the secondary was offline, or restarted). The window is written to disk.
/// One hour: while the window is open, any paired contact can attach this device to its own identity with a grant that it signs itself (the device
/// cannot know who scanned its code). Same value as the approver's `PENDING_LINK_RETRY_HORIZON_MS`.
pub(crate) const LINK_REQUEST_WINDOW_MS: u64 = PENDING_LINK_RETRY_HORIZON_MS;
/// How long after this device last produced its own pairing code (QR or
/// typed) a stranger's IdentityExchange may create a contact. Without a
/// window, anyone who knew our fingerprint could fill the contact list at any
/// time, with no action by the user. The UI produces the code each time its
/// screen is shown, which opens the window again.
/// 30 min, not 24 h — a photographed code is a bearer token for the
/// whole window; a delayed (Tor/mailbox) exchange still fits.
pub(crate) const PAIRING_WINDOW_MS: u64 = 30 * 60 * 1000;
/// A pairing code produced again inside this time carries the nonce of the
/// one before (the UI produces the code each time its screen is shown).
pub(crate) const PAIRING_NONCE_REUSE_MS: u64 = 5 * 60 * 1000;
/// Members one GroupUpdate may name (see `process_group_update`).
pub(crate) const MAX_GROUP_MEMBERS: usize = 256;

/// See `DownloadState.last_retry_at`. How long a download can stay silent without any libp2p-level event (no chunk reply and no `OutboundFailure`)
/// before `check_stalled_downloads` requests the SAME chunk again (see `retry_or_give_up_download`). The download used to fail outright here, and now
/// it keeps retrying until `DOWNLOAD_GIVE_UP_TIMEOUT_MS`. Otherwise (especially when both devices are behind NAT, and a TCP dial neither succeeds
/// nor fails cleanly) a download could stay "Downloading" forever.
/// (The constant is `DOWNLOAD_STALL_TIMEOUT_MS`, below.)
/// Number of file chunk requests that may be in flight at once: an ADAPTIVE window (see `DownloadState.window`).
/// With one chunk in flight, throughput is limited to `chunk size / round-trip time`, regardless of bandwidth. Measured on real devices over Tor:
/// about 70 KB/s download, about 12 KB/s upload. But a FIXED depth was also wrong. On the upload path, going from 6 to 16 in-flight 256 KiB chunks
/// dropped throughput from about 180 KB/s to about 50 KB/s. Holding 16 x 256 KiB on a Tor circuit of about 200 KB/s builds up queue delay
/// (bufferbloat), which pushed the round trip to 24 s and ran into the `request_timeout` limit (30 s then, `BLOB_REQUEST_TIMEOUT_MS` now).
/// So the window adapts, roughly AIMD: +1 on each successful chunk while the round trip is under target, halved on a stall.
pub(crate) const DOWNLOAD_WINDOW_START: usize = 4;
pub(crate) const DOWNLOAD_WINDOW_MIN: usize = 2;
/// Wait before a failed chunk request, or one the server answered with "not
/// here yet", is sent again. Not zero: a request that fails at once was a loop
/// at round-trip rate. Not the 105 s stall timer: too long for the user.
pub(crate) const DOWNLOAD_RETRY_DELAY_MS: u64 = 3_000;
pub(crate) const DOWNLOAD_WINDOW_MAX: usize = 40;
/// The growth test is not an absolute threshold. It is relative to the smallest round trip measured on that path (see `DownloadState.rtt_min`). An absolute threshold pinned
/// the window to its floor on a slow Tor circuit (round trip 15.6 s, window stuck at 2). A high-latency path needs the large window. The test is whether the round trip is
/// more than twice the best measured on this path (Vegas-like).
pub(crate) const DOWNLOAD_RTT_GROW_FACTOR: u64 = 2;
/// Above this, the window does not grow whatever the test says. We are then close to the `request_timeout` (`BLOB_REQUEST_TIMEOUT_MS`), and a chunk that
/// times out halves the window.
/// See `server_client::BLOB_RTT_CEILING_MS`. Same reason: the round trip scales with chunk size, so an absolute threshold is wrong, and a fraction of
/// `request_timeout` is correct.
pub(crate) const DOWNLOAD_RTT_CEILING_MS: u64 = server_client::BLOB_REQUEST_TIMEOUT_MS * 4 / 5;
/// Samples below this round trip are measurement noise. Otherwise a very small `rtt_min` would stop growth for no reason.
pub(crate) const DOWNLOAD_RTT_FLOOR_MS: u64 = 750;

/// 105 s: longer than the 90 s chunk request timeout. At the old 45 s a chunk
/// still in flight on a slow Tor path was requested
/// again and counted against its source.
pub(crate) const DOWNLOAD_STALL_TIMEOUT_MS: u64 = server_client::BLOB_REQUEST_TIMEOUT_MS + 15_000;
/// The download keeps trying (retrying the same chunk every `DOWNLOAD_STALL_TIMEOUT_MS` now and then) until this much time passes since the LAST REAL
/// PROGRESS (see `DownloadState.last_progress_at`). Before, a single stall or `OutboundFailure` failed the download immediately, so a brief network blip
/// (a Tor circuit being rebuilt, a short connection drop) forced the user to tap "retry" by hand.
pub(crate) const DOWNLOAD_GIVE_UP_TIMEOUT_MS: u64 = 10 * 60 * 1000;

/// See `enforce_history_storage_limit`. After a file completes, it is protected from storage-limit eviction for at least this long. This is the same
/// value as `TEXT_RETRY_GIVE_UP_MS` (7 days). The reasoning: a `FileOffer` is itself retried for that long, so it is reasonable for a file to still be on
/// disk when a recipient gets the offer late, within that window.
pub(crate) const FILE_RETENTION_GRACE_MS: u64 = TEXT_RETRY_GIVE_UP_MS;

/// Rows stored for a group id this device never got (`unknown_group_has_room`) are dropped after this long.
pub(crate) const UNKNOWN_GROUP_ROWS_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;

/// A non-root founder device waits this long before it acts on a `LeaveGroupRequest`: the root's `Remove` usually reaches it first.
pub(crate) const LEAVE_REQUEST_DEFER_MS: u64 = 2 * 60 * 1000;

/// Automatic restarts of one failed download (`resume_incomplete_downloads_for`) before it waits for a tap. Progress resets the count.
pub(crate) const MAX_AUTO_RESUMES: i64 = 3;

/// Chunk bytes one peer may fetch of one file per day, as a multiple of the file size (`serve_chunk_request_budgeted`).
pub(crate) const CHUNK_SERVE_FILE_MULTIPLE: u64 = 3;
