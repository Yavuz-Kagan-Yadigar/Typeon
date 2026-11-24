//! Swarm setup, radio and power modes, relays, reconnects, and publish with retry.

use super::*;

mod power;
mod connections;
mod publish;


/// Inbound connection slots for peers unknown to this device.
pub(crate) const MAX_UNKNOWN_INBOUND: usize = 16;
pub(crate) const UNKNOWN_INBOUND_GRACE_MS: u64 = 2 * 60 * 1000;

/// Of the unknown inbound connections `(id, established ms)`: those older
/// than the grace time, and the oldest ones above the slot cap. Closing the
/// newest let a stranger holding the slots shut out a new contact who had just
/// scanned our code.
pub(crate) fn unknown_inbound_to_close<T>(mut held: Vec<(T, u64)>, now: u64) -> Vec<T> {
    held.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
    held.into_iter()
        .enumerate()
        .filter(|(i, (_, at))| *i >= MAX_UNKNOWN_INBOUND || now.saturating_sub(*at) > UNKNOWN_INBOUND_GRACE_MS)
        .map(|(_, (id, _))| id)
        .collect()
}
impl P2PCore {

    /// Maps the sender's device fingerprint to the `PeerId` of the connection the packet arrived on.
    ///
    /// Security precondition: the fingerprint must be trusted. Call this only after
    /// the caller has verified the packet cryptographically (fingerprint derived from
    /// the carried public keys, hybrid signature). Before this rule, every envelope
    /// type set the mapping before verification. An attacker could then poison the
    /// mapping and the reconnect hint (`device_last_addr`) with a forged fingerprint,
    /// even when the packet was rejected later.
    pub(crate) fn record_peer_id_if_known(&mut self, source: Option<PeerId>, device_fingerprint: &str) {
        if let Some(pid) = source {
            // A device keeps one libp2p key. While its mapped PeerId is connected, a packet
            // from another PeerId was relayed or replayed. Never let it replace the mapping.
            if let Some(old) = self.device_to_peer_id.get(device_fingerprint) {
                if *old != pid && self.swarm.as_ref().map_or(false, |s| s.is_connected(old)) {
                    return;
                }
            }
            // Also not while a stored device address names another PeerId. The packet is
            // genuine, but its carrier need not be: a relay that delivered the same bytes
            // must not become the device. A device with a new key says so in its signed,
            // encrypted AddressAnnounce, which replaces the stored address.
            let mut unproven = false;
            if self.device_to_peer_id.get(device_fingerprint) != Some(&pid) {
                let known: Vec<PeerId> = [self.device_last_addr.get(device_fingerprint), self.device_onion_addr.get(device_fingerprint)]
                    .into_iter().flatten()
                    .filter_map(|a| a.parse::<Multiaddr>().ok().and_then(|m| extract_peer_id(&m)))
                    .collect();
                if !known.is_empty() && !known.contains(&pid) {
                    return;
                }
                unproven = known.is_empty();
            }
            // No PeerId is named for the device, so the carrier is unproven. Bind only over a live connection from that PeerId,
            // never to a server or to another identity's device. Store no address from it:
            // the device's own AddressAnnounce supplies that.
            if unproven {
                let my_identity = self.known_remote_devices.get(device_fingerprint).map(|d| d.identity_id.clone());
                let other_identity = self.device_to_peer_id.iter().any(|(f, p)| {
                    *p == pid && f != device_fingerprint
                        && self.known_remote_devices.get(f).map(|d| d.identity_id.clone()) != my_identity
                });
                if self.is_server_peer(&pid)
                    || other_identity
                    || !self.swarm.as_ref().map_or(false, |s| s.is_connected(&pid))
                {
                    return;
                }
            }
            self.device_to_peer_id.insert(device_fingerprint.to_string(), pid);
            if unproven {
                return;
            }
            if let Some(onion) = self.peer_onion_addr.get(&pid).cloned() {
                self.remember_onion_addr(device_fingerprint, &onion);
            }
            // We received a packet from this device. Save the concrete address of the current
            // connection (`peer_id_to_addr`, filled on ConnectionEstablished) as the persistent
            // reconnect hint. The next `reconnect_sweep` then uses the last working address,
            // even if the rendezvous address from pairing is stale. `remember_device_addr`
            // ignores addresses without a `/p2p/<peer_id>` suffix.
            if let Some(addr) = self.peer_id_to_addr.get(&pid).cloned() {
                // An address that already ends in `/p2p/<peer_id>` (our outgoing dials build it
                // that way) is not appended again. A raw `/ip4/.../tcp/...` address from an
                // inbound connection gets the suffix.
                let addr_str = if extract_peer_id(&addr).is_some() {
                    addr.to_string()
                } else {
                    addr.with(MultiaddrProtocol::P2p(pid)).to_string()
                };
                self.remember_device_addr(device_fingerprint, &addr_str);
            }
        }
    }
}

impl P2PCore {

    // --- Network and discovery ---

    pub(crate) fn start_network(&mut self, node_mode: bool, tor_enabled: bool) -> Result<String, String> {
        // Repeat calls in one process (Android restarts the service) would start a second
        // arti on the same state dir and listen twice on the same port.
        if let Some(swarm) = &self.swarm {
            // Node mode and Tor take effect on the next process start.
            if node_mode != self.node_mode_enabled || tor_enabled != self.tor_enabled {
                warn!("start_network: network already running, new settings (node={}, tor={}) take effect on restart", node_mode, tor_enabled);
            }
            return Ok(swarm.local_peer_id().to_string());
        }
        // The node is onion-only (no TCP transport). Without Tor the swarm could dial
        // nothing, and the app would sit offline without an error.
        if !tor_enabled {
            return Err("Tor is off: network runs over Tor only".to_string());
        }
        // The swarm needs the storage keys. The gate opens only after they load. Handshakes
        // built before that could create sessions that cannot be stored, and the two sides
        // would fall out of step. The caller loads the keys and retries.
        if !self.storage_keys_ready() {
            return Err("Storage keys not loaded".to_string());
        }
        // Persistent keypair (PeerId). See `load_or_generate_libp2p_keypair`.
        let app_files_dir = self.app_files_dir.clone().ok_or("initDatabase must be called first")?;
        let keypair = load_or_generate_libp2p_keypair(&app_files_dir);

        // Start the arti onion service (bootstraps in the background). Its inbound streams
        // reach the swarm in-process (`tor::OnionListen`); TOR_LIBP2P_PORT is only the
        // onion service's virtual port. Do not continue without Tor: the node is
        // onion-only, so the swarm could dial nothing. The caller retries.
        let state_dir = format!("{}/arti_state", app_files_dir);
        let cache_dir = format!("{}/arti_cache", app_files_dir);
        let (tor_handle, onion_listen) = tor::TorHandle::launch(&state_dir, &cache_dir, TOR_LIBP2P_PORT)
            .map_err(|e| format!("Tor network failed to start: {}", e))?;
        let tor_client = Some(tor_handle.client.clone());
        let listen_addr = onion_listen.listen_addr();

        // The swarm is built by hand, not with `SwarmBuilder`. libp2p 0.53's `build()`
        // sets a fixed 10 s timeout on every connection and offers no way to change it.
        // Tor onion dials (circuit build plus Noise) and relay circuits routinely exceed
        // that on mobile data; measured on device: constant "Timeout has been reached".
        // The transports: arti onion dial, onion inbound (`OnionListen`), relay client. All
        // use Noise and Yamux, V1Lazy. There is no TCP transport: nothing can dial or
        // accept a clearnet or local socket.
        let local_peer_id = keypair.public().to_peer_id();
        let (relay_transport, relay_client) = relay::client::new(local_peer_id);
        let transport = {
            use libp2p::core::muxing::StreamMuxerBox;
            use libp2p::core::transport::Transport as _;
            use libp2p::core::upgrade::Version;
            let noise_for = |kp: &libp2p::identity::Keypair| noise::Config::new(kp).map_err(|e| e.to_string());
            // Inbound onion streams. A stream must finish Noise and Yamux sooner than an outgoing
            // dial (see `INBOUND_UPGRADE_SECS`), so a stalled stranger frees its bridge slot.
            let onion_in_t = libp2p::core::transport::timeout::TransportTimeout::with_ingoing_timeout(
                onion_listen
                    .upgrade(Version::V1Lazy)
                    .authenticate(noise_for(&keypair)?)
                    .multiplex(tuned_yamux())
                    .map(|(p, m), _| (p, StreamMuxerBox::new(m))),
                std::time::Duration::from_secs(tor::INBOUND_UPGRADE_SECS),
            );
            let tor_t = tor::ArtiDialTransport::new(tor_client.clone())
                .upgrade(Version::V1Lazy)
                .authenticate(noise_for(&keypair)?)
                .multiplex(tuned_yamux())
                .map(|(p, m), _| (p, StreamMuxerBox::new(m)));
            let relay_t = relay_transport
                .upgrade(Version::V1Lazy)
                .authenticate(noise_for(&keypair)?)
                .multiplex(tuned_yamux())
                .map(|(p, m), _| (p, StreamMuxerBox::new(m)));
            let combined = relay_t
                .or_transport(tor_t)
                .or_transport(onion_in_t)
                .map(|out, _| match out {
                    futures::future::Either::Left(futures::future::Either::Left(o)) => o,
                    futures::future::Either::Left(futures::future::Either::Right(o)) => o,
                    futures::future::Either::Right(o) => o,
                });
            libp2p::core::transport::timeout::TransportTimeout::new(
                combined,
                std::time::Duration::from_secs(SWARM_CONNECTION_TIMEOUT_SECS),
            )
            .boxed()
        };
        let keypair_ref = &keypair;
        let behaviour = (|keypair: &libp2p::identity::Keypair, relay_client: relay::client::Behaviour| -> Result<P2PBehaviour, Box<dyn std::error::Error + Send + Sync>> {
                let peer_id = keypair.public().to_peer_id();
                let store = MemoryStore::new(peer_id);
                let kad = kad::Behaviour::new(peer_id, store);
                // Cache 0: identify's address cache would feed every peer's raw listen addresses, including 127.0.0.1, into each dial.
                // Dials then reached our own node ("Unexpected peer ID <self>"). The Identify arm below records the useful non-loopback
                // addresses itself.
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/p2pmessenger/1.0.0".to_string(),
                    keypair.public(),
                ).with_cache_size(0)
                // The default is 5 min per peer, which woke the LTE radio about every 75 s with
                // 3-4 peers. Addresses change rarely; push covers changes.
                .with_interval(std::time::Duration::from_secs(3600)));
                // The library default `request_timeout` (10 s) is too short over Tor for a
                // 256 KiB file chunk (`FILE_CHUNK_SIZE`), so this uses the blob timeout (90 s).
                // `retry_or_give_up_download` re-requests the same chunk at once on an
                // OutboundFailure. Requests are capped at 4 KiB (`FileChunkCodec`).
                let file_chunks: request_response::Behaviour<FileChunkCodec> = request_response::Behaviour::new(
                    [(StreamProtocol::new(FILE_TRANSFER_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_millis(server_client::BLOB_REQUEST_TIMEOUT_MS)),
                );
                // See `P2PBehaviour.relay`. With node mode off, the relay HOP behaviour is fully
                // disabled (`Toggle::from(None)`), not built with zero capacity. libp2p-relay's HOP
                // handler advertises the protocol regardless of Config, so even a zero-capacity
                // behaviour would tell peers via identify that this device is a relay candidate.
                // If node mode is turned on later with `set_node_mode`, relay capacity activates
                // only at the next network restart (see `set_node_mode`).
                let relay: Toggle<relay::Behaviour> = if node_mode {
                    Some(relay::Behaviour::new(peer_id, relay_server_config())).into()
                } else {
                    None.into()
                };
                // See `P2PBehaviour.keepalive` and `KeepAliveState`. Send timing (fast or extended
                // interval) is not set here. It is applied by the "keepalive due" scan in
                // `poll_events`. The stock `ping::Config` would apply one fixed interval to all
                // connections, which this custom protocol avoids. `with_request_timeout` is the
                // longest wait for one reply (see `KEEPALIVE_TIMEOUT_SECS`).
                // One probe in flight per side, plus a `bye`: 8 streams per connection (the library allows 100, in and out together).
                let keepalive: request_response::Behaviour<KeepAliveCodec> = request_response::Behaviour::new(
                    [
                        (StreamProtocol::new(KEEPALIVE_PROTOCOL), request_response::ProtocolSupport::Full),
                        (StreamProtocol::new(KEEPALIVE_QUIET_PROTOCOL), request_response::ProtocolSupport::Full),
                    ],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(KEEPALIVE_TIMEOUT_SECS))
                        .with_max_concurrent_streams(8),
                );
                // See `P2PBehaviour.server_rpc`: `BLOB_REQUEST_TIMEOUT_MS` (90 s). Same reason as
                // `file_chunks`: the library's 10 s default is too short for a large payload over Tor.
                let server_rpc: request_response::Behaviour<ServerRpcCodec> = request_response::Behaviour::new(
                    [(StreamProtocol::new(server_proto::SERVER_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_millis(server_client::BLOB_REQUEST_TIMEOUT_MS)),
                );
                // See `ACK_PROTOCOL`. Over a Tor circuit a round trip can take seconds.
                // A batch over the stream cap fails and falls back to encrypted Ack packets.
                let acks: request_response::Behaviour<AckCodec> = request_response::Behaviour::new(
                    [(StreamProtocol::new(ACK_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(ACK_REQUEST_TIMEOUT_SECS))
                        .with_max_concurrent_streams(32),
                );
                let envelopes = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(ENVELOPE_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(ACK_REQUEST_TIMEOUT_SECS)),
                );
                let stream = libp2p_stream::Behaviour::new();
                Ok(P2PBehaviour { server_rpc, kad, identify, file_chunks, relay_client, relay, keepalive, acks, envelopes, stream })
            })(keypair_ref, relay_client)
            .map_err(|e| e.to_string())?;
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                // Idle timeout, 30 min. The libp2p-swarm default closes a connection with no
                // open protocol substream, and each re-dial costs circuit and handshake traffic.
                // Tor circuit builds are slow, so each drop can cost minutes. The keepalive
                // probes still close a dead connection.
                .with_idle_connection_timeout(std::time::Duration::from_secs(1800)),
        );

        // Always client mode. Kademlia is only the address book behind peer-id dials here,
        // and nothing queries it. In server mode it answered FIND_NODE from any stranger
        // that reached the onion address, with the peer IDs and onion addresses of the
        // user's contacts.
        swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Client));

        let peer_id = *swarm.local_peer_id();

        // The onion inbound listener. Its address is a loopback label with no socket behind
        // it (see `tor::OnionListen`); peers drop loopback addresses.
        swarm.listen_on(listen_addr).map_err(|e| e.to_string())?;

        // No identity yet. `ensure_own_mailbox_subscription` sets it later.
        if let Ok(active_fp) = self.get_active_own_device_fingerprint() {
            self.own_mailbox_topic_fp = Some(active_fp);
        }

        let mut stream_control = swarm.behaviour().stream.new_control();
        call::spawn_media_acceptor(&mut stream_control);
        self.stream_control = Some(stream_control);
        // Set only now. An error return above would leave them changed.
        self.node_mode_enabled = node_mode;
        self.tor_enabled = tor_enabled;
        self.own_listen_addrs.clear();
        self.advertised_onion = None; // new swarm: announce again
        // See `tor_was_ready`. A fresh Tor client and session start, so the "ready"
        // transition is tracked from scratch.
        self.tor_was_ready = false;
        self.swarm = Some(swarm);
        self.tor = Some(tor_handle);
        self.tor_dormant = false;

        // See `server_client`. Connecting to and registering with configured servers
        // happens in the first `server_sweep` round.
        self.server_sweep_at = 0;

        // See `DEFAULT_BOOTSTRAP_RELAYS`. An empty list is a no-op.
        for addr in DEFAULT_BOOTSTRAP_RELAYS {
            if let Err(e) = self.add_known_relay_address(addr) {
                error!("Could not add default bootstrap relay ({}): {}", addr, e);
            }
        }

        Ok(peer_id.to_string())
    }

    /// See `KeepAliveState.suspect`. `dial`: also open a parallel onion connection now.
    /// A late Ack alone is no reason to do so: Tor plus a sleeping radio often take
    /// longer than `ACK_SUSPECT_MS`, so that path only probes. A failed probe of a
    /// suspect closes the connection for the redial.
    pub(crate) fn mark_connection_suspect(&mut self, peer: PeerId, dial: bool) {
        let Some(st) = self.keepalive_state.get_mut(&peer) else { return };
        if st.suspect {
            return;
        }
        st.suspect = true;
        if st.outstanding.is_none() {
            st.next_due_at = 0;
        }
        if !dial {
            return;
        }
        // Open a parallel onion connection without waiting for the probe timeout. If it
        // succeeds, the old connection is closed (see `peer_conns`). Noticing a dead
        // connection and redialing then overlap instead of running in sequence.
        let onion = self.device_to_peer_id.iter()
            .find(|(_, p)| **p == peer)
            .and_then(|(fp, _)| self.device_onion_addr.get(fp))
            .and_then(|a| a.parse::<Multiaddr>().ok());
        if let (Some(addr), Some(swarm)) = (onion, self.swarm.as_mut()) {
            let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
                .addresses(vec![addr])
                .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
                .build();
            let _ = swarm.dial(opts);
        }
    }

    /// Mailbox topic name of a ratchet session. It is derived with HKDF from the session's root key, so
    /// network observers cannot tie it to a device fingerprint (see SECURITY.md). The root key changes at
    /// each DH/KEM rotation (every 30 min, see ratchet.rs), so the topic rotates too.
    ///
    /// Known limit: before any ratchet session exists (the first IdentityExchange and HandshakeInit pair),
    /// `publish.rs` uses the fingerprint-based name `p2p_msg_<fingerprint>` instead. Ongoing conversation
    /// traffic is protected. The first pairing exchange still names the fingerprint.
    ///
    /// The input is `ratchet::root_handle` of a root (`root_handle_now` or `prev_root_key`), never the root itself.
    pub(crate) fn topic_for_root_key(root_key: &[u8]) -> String {
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, root_key);
        let mut topic_id = [0u8; 16];
        hk.expand(b"p2pmsg-v0.1-gossip-topic", &mut topic_id).expect("HKDF expand failed");
        format!("p2p_rt_{}", hex::encode(topic_id))
    }

    /// Completes the device's own mailbox subscription if needed (see `own_mailbox_topic_fp`). `poll_events` calls it every turn. Normally it
    /// does work once on the first turn, and afterwards it is only a comparison. If the identity was created or loaded after `start_network`
    /// (see that field's note), it sets up the subscription here, without a network restart.
    ///
    /// The comparison is by fingerprint, not just a "subscribed" flag. A path such as `import_recovery` can CHANGE the device's active
    /// fingerprint. In that case the new mailbox must be subscribed too.
    pub(crate) fn ensure_own_mailbox_subscription(&mut self) {
        let active_fp = match self.get_active_own_device_fingerprint() {
            Ok(fp) => fp,
            // No identity yet. Pass silently: logging every second would flood logcat. `start_network` already logs it once.
            Err(_) => return,
        };
        if self.own_mailbox_topic_fp.as_deref() == Some(active_fp.as_str()) {
            return;
        }
        if self.swarm.is_some() {
            self.own_mailbox_topic_fp = Some(active_fp);
        }
    }

    /// See `pairing_mailbox_subs`. Subscribe to the peer's mailbox topic during pairing too. Idempotent: no-op if already subscribed, or if a
    /// ratchet already exists.
    pub(crate) fn subscribe_pairing_mailbox(&mut self, peer_fp: &str) {
        if peer_fp.is_empty() { return; }
        if self.ratchets.contains_key(peer_fp) { return; }
        if self.own_mailbox_topic_fp.as_deref() == Some(peer_fp) { return; }
        if self.pairing_mailbox_subs.contains_key(peer_fp) { return; }
        // The entry only marks "a pairing with this device was started" (see the readers of the map).
        if self.swarm.is_some() {
            self.pairing_mailbox_subs.insert(peer_fp.to_string(), current_time_ms());
        }
    }

    /// See `subscribe_pairing_mailbox`. Unsubscribes (the ratchet is established, or the TTL expired).
    pub(crate) fn drop_pairing_mailbox(&mut self, peer_fp: &str) {
        self.pairing_mailbox_subs.remove(peer_fp);
    }

    /// Called every turn from `poll_events`. Drops pairing subscriptions whose ratchet is established or whose TTL expired.
    pub(crate) fn flush_pairing_mailbox_subs(&mut self) {
        let ratchets = &self.ratchets;
        self.pairing_reply_peer.retain(|fp, _| !ratchets.contains_key(fp));
        if self.pairing_mailbox_subs.is_empty() { return; }
        let now = current_time_ms();
        let done: Vec<String> = self.pairing_mailbox_subs.iter()
            .filter_map(|(fp, since)| {
                if self.ratchets.contains_key(fp)
                    || now.saturating_sub(*since) > PAIRING_MAILBOX_TTL_MS
                {
                    Some(fp.clone())
                } else {
                    None
                }
            })
            .collect();
        for fp in done {
            self.drop_pairing_mailbox(&fp);
        }
    }
}
