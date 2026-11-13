//! libp2p wire types (keepalive, ack, envelope) and the combined `P2PBehaviour`.

use super::*;


/// The content of this request/response does not matter. Its only purpose is to check that the connection is still alive.
/// `request_response::cbor` needs the empty struct to serialize and deserialize as CBOR. `#[derive(Serialize, Deserialize)]` provides that
/// without extra fields.
/// `bye`: "I am shutting down, do not dial me until I connect again" (desktop Quit). The receiver parks the device (`parked:{fp}` meta), and
/// `try_reconnect_device` skips it until a new connection from it arrives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeepAliveRequest {
    #[serde(default)]
    pub bye: bool,
}
/// `quiet_ms`: "I am saving radio (metered network, screen off) — do not
/// probe me again for this long". Without it a phone on mobile data could
/// quiet its own timers but every peer's 20-60 s probe still woke its radio.
///
/// Wire: `None` is encoded as CBOR null — byte-identical to the old unit
/// struct, so older peers keep working; the hint is a one-field map, sent
/// only in radio-saver mode. Both forms decode.
#[derive(Debug, Clone, Default)]
pub struct KeepAliveResponse {
    pub quiet_ms: Option<u64>,
}

impl Serialize for KeepAliveResponse {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self.quiet_ms {
            None => s.serialize_unit(),
            Some(q) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("quiet_ms", &q)?;
                m.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for KeepAliveResponse {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Hint { quiet_ms: u64 },
            Other(serde::de::IgnoredAny),
        }
        Ok(match Wire::deserialize(d)? {
            Wire::Hint { quiet_ms } => KeepAliveResponse { quiet_ms: Some(quiet_ms) },
            Wire::Other(_) => KeepAliveResponse { quiet_ms: None },
        })
    }
}

/// Batched delivery acknowledgement. See `ACK_PROTOCOL` / `flush_outbound_acks`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckBatchRequest {
    pub ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckBatchResponse;

/// One envelope (the same bytes a gossipsub publish carries), sent straight to
/// a connected device. See `ENVELOPE_PROTOCOL`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeRequest {
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeResponse;

/// See the `P2PCore.keepalive_state` field docs.
pub(crate) struct KeepAliveState {
    /// The connection may be dead (the network changed, or one of our packets was not acknowledged quickly). It is probed immediately, and
    /// closed on a SINGLE failure. Before, a half-open connection was detected only after 3 consecutive timeouts (about 25-60 s). During that
    /// time, messages were written to a dead socket (measured on the device: on a Wi-Fi to mobile switch, the other side did not notice for 35 s).
    pub(crate) suspect: bool,
    /// When this connection was last established or re-established. It is used ONLY to compute the `KEEPALIVE_STABILIZE_MS` threshold. It is NOT
    /// reset by a successful keepalive. It is reset on reconnection.
    pub(crate) connected_since: u64,
    /// When the next keepalive request will be sent.
    pub(crate) next_due_at: u64,
    /// Number of consecutive failures. See `KEEPALIVE_FAILURES_BEFORE_DISCONNECT`.
    pub(crate) consecutive_failures: u32,
    /// The id of the request in flight, if any. It prevents several keepalive requests from being outstanding on the same connection at once.
    pub(crate) outstanding: Option<request_response::OutboundRequestId>,
    /// Interval chosen at the last successful probe (0 = none yet). An
    /// inbound probe also proves liveness and restarts this interval, so
    /// both sides fall into one schedule — the radio-saver peer's window —
    /// instead of each waking the other's LTE radio on its own clock.
    pub(crate) interval_ms: u64,
    /// Peer advertised `KEEPALIVE_QUIET_PROTOCOL` (can decode `quiet_ms`).
    pub(crate) quiet_capable: bool,
}

// --- libp2p combined behaviour ---
//
// Kademlia (DHT) discovery. The Identify protocol is REQUIRED for Kademlia: it lets Kademlia learn the listen addresses of connected peers
// and add them to the routing table (see docs.rs/libp2p/kad: "the Identify protocol must be manually hooked up to Kademlia").
// Gossipsub carries the message and handshake packets. The relay carries them blindly ("Node/relay carries this packet blindly").
#[derive(NetworkBehaviour)]
pub(crate) struct P2PBehaviour {
    /// Server (store-and-forward) RPC. See the `server_client` module.
    /// `ProtocolSupport::Full`: so the server can send `Notify` to us unprompted. Otherwise the client would have to poll constantly, which on
    /// a phone means direct battery drain.
    pub(crate) server_rpc: request_response::cbor::Behaviour<server_proto::ServerRequest, server_proto::ServerResponse>,
    pub(crate) kad: kad::Behaviour<MemoryStore>,
    pub(crate) identify: identify::Behaviour,
    /// Active connection liveness check. See `KeepAliveRequest` / `KeepAliveState` and the Keepalive arm of `poll_events`. A half-open connection
    /// (libp2p still thinks it is connected, but the other side is actually unreachable) is detected within seconds, by periodic active probes.
    /// It is NOT detected by waiting for a write error, which could take minutes. The stock `libp2p::ping::Behaviour` is NOT used: it applies one
    /// fixed interval to ALL connections. This custom `request_response` protocol instead widens the probe interval once the connection is stable
    /// (see `KEEPALIVE_STABILIZE_MS`), which saves radio and battery.
    pub(crate) keepalive: request_response::cbor::Behaviour<KeepAliveRequest, KeepAliveResponse>,
    /// see `ACK_PROTOCOL`.
    pub(crate) acks: request_response::cbor::Behaviour<AckBatchRequest, AckBatchResponse>,
    /// see `ENVELOPE_PROTOCOL`.
    pub(crate) envelopes: request_response::cbor::Behaviour<EnvelopeRequest, EnvelopeResponse>,
    /// Call media streams (`call::MEDIA_PROTOCOL`, and the server relay) —
    /// long-lived streams driven by tokio tasks, see `call` module docs.
    pub(crate) stream: libp2p_stream::Behaviour,
    /// File attachment chunk transfer. Unlike gossipsub, it sends a request/response (RPC-like) directly to one target `PeerId`. Moving a 4 GB
    /// file over gossipsub (a pub/sub network designed for small, frequent messages) is impractical. See the attachments.rs module note.
    pub(crate) file_chunks: request_response::cbor::Behaviour<FileChunkRequest, FileChunkResponse>,
    /// Connectivity through a relay, for reaching peers that cannot be dialed directly (different network, or behind NAT). This device can use a
    /// relay to reach them. It is always enabled on every device.
    pub(crate) relay_client: relay::client::Behaviour,
    /// Whether this device can act as a relay for OTHER devices. This is the concrete form of node mode's optional
    /// Circuit Relay v2 service.
    ///
    /// `Toggle<_>` is used. Whether it is Some or None is chosen in `start_network` from the `node_mode` passed in. The `Toggle` docs also say the
    /// state can only be chosen at initialization. That matches the existing limit of `set_node_mode` exactly (no live toggle: the change takes
    /// effect at the next `start_network`), so it restricts nothing new.
    ///
    /// Before, this was ALWAYS built as `Some`, regardless of `node_mode`. Capacity was set to zero (`max_reservations` / `max_circuits`), which
    /// disabled it in practice. But libp2p-relay's HOP handler (`behaviour/handler.rs::listen_protocol`) advertises the HOP protocol as a substream
    /// WITHOUT looking at `Config`. So identify reported EVERY device as speaking the "relay HOP protocol", even when `node_mode=false` (see the
    /// `known_relay_peers` / `record_known_relay` filter: `info.protocols.iter().any(|p| *p == relay::HOP_PROTOCOL_NAME)`). As a result, every device in
    /// the fleet, whether or not node mode was on, was recorded as a fake "relay candidate". `dial_with_relay_fallback` dialed some of them and failed
    /// with "Remote reported resource limit exceeded". Real relay candidates (node mode on) had to compete with these fake ones for the fixed
    /// `MAX_KNOWN_RELAYS` capacity. With `Toggle::from(None)` the HOP handler is not registered at all, and identify never reports the protocol. So
    /// `known_relay_peers` now contains ONLY devices that can really serve (`node_mode=true`).
    pub(crate) relay: Toggle<relay::Behaviour>,
    // mDNS, UPnP and dcutr were removed: onion-only transport, loopback-only
    // listener — mDNS beaconed our PeerId on the LAN and UPnP had nothing to map.
}
