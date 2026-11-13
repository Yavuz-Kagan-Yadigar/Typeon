//! Swarm setup, radio and power modes, relays, reconnects, and publish with retry.

use super::*;


/// Inbound connection slots for peers unknown to this device.
pub(crate) const MAX_UNKNOWN_INBOUND: usize = 16;
pub(crate) const UNKNOWN_INBOUND_GRACE_MS: u64 = 2 * 60 * 1000;

/// Of the unknown inbound connections `(id, established ms)`: those older
/// than the grace time, and the newest ones above the slot cap.
pub(crate) fn unknown_inbound_to_close<T>(mut held: Vec<(T, u64)>, now: u64) -> Vec<T> {
    held.sort_by_key(|(_, at)| *at);
    held.into_iter()
        .enumerate()
        .filter(|(i, (_, at))| *i >= MAX_UNKNOWN_INBOUND || now.saturating_sub(*at) > UNKNOWN_INBOUND_GRACE_MS)
        .map(|(_, (id, _))| id)
        .collect()
}
impl P2PCore {

    /// Maps the sender's device fingerprint to the gossip `PeerId` of the packet.
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
            // No PeerId is named for the device, so the carrier is unproven. A gossip author
            // is chosen by the publisher. Bind only over a live connection from that PeerId,
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
                warn!("start_network: ağ zaten çalışıyor, yeni ayarlar (node={}, tor={}) yeniden başlatmada geçerli olur", node_mode, tor_enabled);
            }
            return Ok(swarm.local_peer_id().to_string());
        }
        // The node is onion-only (`tor::DialReject` on TCP). Without Tor the swarm could
        // dial nothing, and the app would sit offline without an error.
        if !tor_enabled {
            return Err("Tor kapalı: ağ yalnızca Tor üzerinden çalışır".to_string());
        }
        // The swarm needs the storage keys. The gate opens only after they load. Handshakes
        // built before that could create sessions that cannot be stored, and the two sides
        // would fall out of step. The caller loads the keys and retries.
        if !self.storage_keys_ready() {
            return Err("Depolama anahtarları yüklenmedi".to_string());
        }
        // Persistent keypair (PeerId). See `load_or_generate_libp2p_keypair`.
        let app_files_dir = self.app_files_dir.clone().ok_or("initDatabase önce çağrılmalı")?;
        let keypair = load_or_generate_libp2p_keypair(&app_files_dir);

        // With Tor on, start the arti onion service (bootstraps in the background). It
        // bridges incoming Tor streams to `127.0.0.1:TOR_LIBP2P_PORT`, so libp2p must
        // listen on that fixed port. With Tor off, arti is never created (no runtime cost).
        let tor_handle: Option<tor::TorHandle> = if tor_enabled {
            let state_dir = format!("{}/arti_state", app_files_dir);
            let cache_dir = format!("{}/arti_cache", app_files_dir);
            match tor::TorHandle::launch(&state_dir, &cache_dir, TOR_LIBP2P_PORT) {
                Ok(h) => Some(h),
                // Do not continue without Tor. The node is onion-only, so the swarm could dial
                // nothing and would put a loopback address in the QR code. The caller retries.
                Err(e) => return Err(format!("Tor başlatılamadı: {}", e)),
            }
        } else {
            None
        };
        // Dial client for the dial transport. None when Tor is off; the transport is inert.
        let tor_client = tor_handle.as_ref().map(|h| h.client.clone());
        let listen_port: u16 = if tor_handle.is_some() { TOR_LIBP2P_PORT } else { 0 };

        // The swarm is built by hand, not with `SwarmBuilder`. libp2p 0.53's `build()`
        // sets a fixed 10 s timeout on every connection and offers no way to change it.
        // Tor onion dials (circuit build plus Noise) and relay circuits routinely exceed
        // that on mobile data; measured on device: constant "Timeout has been reached".
        // The transports match what the builder would set up (TCP, arti onion dial, relay
        // client). All use Noise and Yamux, V1Lazy.
        let local_peer_id = keypair.public().to_peer_id();
        let (relay_transport, relay_client) = relay::client::new(local_peer_id);
        let transport = {
            use libp2p::core::muxing::StreamMuxerBox;
            use libp2p::core::transport::Transport as _;
            use libp2p::core::upgrade::Version;
            let noise_for = |kp: &libp2p::identity::Keypair| noise::Config::new(kp).map_err(|e| e.to_string());
            // Onion-only: TCP is kept only for incoming onion-bridge connections. Every outgoing
            // TCP (clearnet) dial is refused, so no peer's real IP is dialed. All egress goes
            // through onion or relay circuits.
            let tcp_t = tor::DialReject(tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)))
                .upgrade(Version::V1Lazy)
                .authenticate(noise_for(&keypair)?)
                .multiplex(tuned_yamux())
                .map(|(p, m), _| (p, StreamMuxerBox::new(m)));
            // With Tor off the client is None, and every dial is refused (see tor.rs).
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
                .or_transport(tcp_t)
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
                // Default 5 min per peer. With 3-4 peers the LTE radio woke about every 75 s.
                // Addresses change rarely; push covers changes.
                .with_interval(std::time::Duration::from_secs(3600)));
                // The library default `request_timeout` (10 s) is often too short over Tor for a
                // 256 KiB file chunk (`FILE_CHUNK_SIZE`), especially on a congested circuit.
                // `retry_or_give_up_download` re-requests the same chunk at once on an
                // OutboundFailure, so a short timeout could retry forever without giving the chunk
                // enough time. 30 s is generous for a typical chunk over Tor, but still detects a
                // dead connection in reasonable time (see `DOWNLOAD_STALL_TIMEOUT_MS`).
                let file_chunks = request_response::cbor::Behaviour::new(
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
                let keepalive = request_response::cbor::Behaviour::new(
                    [
                        (StreamProtocol::new(KEEPALIVE_PROTOCOL), request_response::ProtocolSupport::Full),
                        (StreamProtocol::new(KEEPALIVE_QUIET_PROTOCOL), request_response::ProtocolSupport::Full),
                    ],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(KEEPALIVE_TIMEOUT_SECS)),
                );
                // See `P2PBehaviour.server_rpc`: `BLOB_REQUEST_TIMEOUT_MS` (90 s). Same reason as
                // `file_chunks`: the library's 10 s default is too short for a large payload over Tor.
                let server_rpc = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(server_proto::SERVER_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_millis(server_client::BLOB_REQUEST_TIMEOUT_MS)),
                );
                // See `ACK_PROTOCOL`. Over a Tor circuit a round trip can take seconds.
                let acks = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(ACK_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(ACK_REQUEST_TIMEOUT_SECS)),
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
            // Idle timeout. The libp2p-swarm default closes a connection with no open protocol
            // substream, such as quiet periods between two messages. `reconnect_sweep` would
            // then re-dial each time, adding circuit and handshake traffic. Tor circuit builds
            // are slow, so each drop can cost minutes. Ten minutes keeps the connection alive
            // through normal quiet periods and avoids the reconnect loop.
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                // 30 min. Gossipsub is gone. Its mesh once kept a contact's connection open through
                // the quiet keepalive window (`RADIO_WINDOW_MS`, 8 min), which a dozing phone can
                // overrun. The keepalive probes still close a dead connection.
                .with_idle_connection_timeout(std::time::Duration::from_secs(1800)),
        );

        // Always client mode. Kademlia is only the address book behind peer-id dials here,
        // and nothing queries it. In server mode it answered FIND_NODE from any stranger
        // that reached the onion address, with the peer IDs and onion addresses of the
        // user's contacts.
        swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Client));

        let peer_id = *swarm.local_peer_id();

        // Fixed port. The onion bridge connects here (see TOR_LIBP2P_PORT).
        //
        // Onion-only: listen on 127.0.0.1, not 0.0.0.0. The bridge (`bridge_incoming_stream`)
        // connects to `127.0.0.1:<port>` itself, so incoming onion traffic is unaffected.
        // Direct clearnet connections from LAN or internet are refused, and identify does
        // not advertise an address that peers could dial.
        swarm.listen_on(format!("/ip4/127.0.0.1/tcp/{}", listen_port).parse().map_err(|_| "bad multiaddr")?)
            .map_err(|e| e.to_string())?;

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
        self.tor = tor_handle;
        self.tor_dormant = false;

        // See `server_client`. Connecting to and registering with configured servers
        // happens in the first `server_sweep` round.
        self.server_sweep_at = 0;

        // See `DEFAULT_BOOTSTRAP_RELAYS`. An empty list is a no-op.
        for addr in DEFAULT_BOOTSTRAP_RELAYS {
            if let Err(e) = self.add_known_relay_address(addr) {
                error!("Varsayılan bootstrap röle eklenemedi ({}): {}", addr, e);
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

    /// See `RADIO_WINDOW_MS`. Wi-Fi too: with Tor awake, a night on Wi-Fi woke the CPU about once a second (measured: 64 % of 7 hours with the
    /// screen off).
    pub(crate) fn radio_saver(&self) -> bool {
        self.power_save
    }

    pub(crate) fn radio_window_ms(&self) -> u64 {
        if self.metered { RADIO_WINDOW_MS } else { RADIO_WINDOW_WIFI_MS }
    }

    pub(crate) fn set_metered(&mut self, metered: bool) {
        if self.metered != metered {
            info!("Ölçülü ağ: {}", metered);
        }
        self.metered = metered;
    }

    /// Battery saver. The Kotlin / GTK side turns this on when the app goes to the background and the screen turns off. It does not change network
    /// behaviour; it only lowers the probe rate of healthy, quiet connections (see the `power_save` field note).
    pub(crate) fn set_power_save(&mut self, enabled: bool) {
        if self.power_save == enabled {
            return;
        }
        self.power_save = enabled;
        info!("Güç tasarrufu modu: {}", if enabled { "açık" } else { "kapalı" });
        // On leaving the mode, pull pending probes forward, so liveness is checked as soon
        // as the user opens the screen, not after 60 s.
        if !enabled {
            let now = mono_ms();
            self.resync_since = now;
            for state in self.keepalive_state.values_mut() {
                if state.next_due_at > now + KEEPALIVE_FAST_INTERVAL_MS {
                    state.next_due_at = now + KEEPALIVE_FAST_INTERVAL_MS;
                }
            }
        }
    }

    /// Only stores the flag. In code, node mode means one thing: the device serves as a
    /// relay (`P2PBehaviour.relay`), set in `start_network`. A change takes effect at
    /// the next network start. There is no DHT role. Kademlia always runs in client
    /// mode (server mode answered FIND_NODE with contacts' peer IDs and onions), and no
    /// DHT record is written.
    pub(crate) fn set_node_mode(&mut self, enabled: bool) {
        self.node_mode_enabled = enabled;
    }

    /// Called from the history and attachment storage limit slider in settings. A
    /// lowered limit applies at once, without waiting for the next
    /// `periodic_storage_sweep` round (see `enforce_history_storage_limit`).
    pub(crate) fn set_history_storage_limit_bytes(&mut self, bytes: u64) {
        // Both UIs stop at 32 GB. u64::MAX would make the limit meaningless.
        self.history_storage_limit_bytes = bytes.min(64 << 30);
        self.enforce_history_storage_limit();
    }

    /// The `rendezvous_node` shown on the QR / "my code" screen and carried to the other
    /// side: an address the swarm really listens on (`own_listen_addrs`, see
    /// `poll_events`), plus our PeerId as a `/p2p/<peer_id>` suffix. Without the suffix,
    /// `extract_peer_id` on the other side never finds a PeerId, and a scanned QR
    /// address is silently unusable for `kad.add_address` and `dial` (see
    /// `process_qr_packet`). Prefers the onion address, else a relay circuit address.
    /// `None` while Tor bootstraps. Never the loopback listener: no peer can dial it.
    pub(crate) fn get_node_address(&self) -> Option<String> {
        let swarm = self.swarm.as_ref()?;
        let peer_id = *swarm.local_peer_id();
        // With Tor on and the onion service published, share the .onion address first. It
        // is the only address reachable from every network (CGNAT included) when the other
        // side also runs Tor. Format: `/dns/<host>.onion/tcp/<port>/p2p/<peer_id>` (see
        // tor.rs, ArtiDialTransport `onion_host_port`). The port is arbitrary: the bridge
        // forwards every incoming port to local libp2p (see `bridge_incoming_stream`).
        // TOR_LIBP2P_PORT is used for consistency.
        if let Some(tor) = &self.tor {
            if let Some(onion_host) = tor.onion_host() {
                return Some(format!("/dns/{}/tcp/{}/p2p/{}", onion_host, TOR_LIBP2P_PORT, peer_id));
            }
        }
        // The node is onion-only (Tor is mandatory, see `start_network`). A listen address
        // would leak clearnet and UPnP addresses, and nobody can dial it.
        None
    }

    /// Tor status for the UI: "disabled", "bootstrapping", "ready" or "failed", plus the
    /// .onion host name when ready.
    pub(crate) fn tor_status(&self) -> String {
        match &self.tor {
            None => "disabled".to_string(),
            Some(h) => {
                let st = h.status().as_str();
                match h.onion_host() {
                    Some(host) if h.status() == tor::TorStatus::Ready => format!("{st}|{host}"),
                    _ => st.to_string(),
                }
            }
        }
    }

    /// Whether the core has real work to do. Used for the Android poll-interval choice
    /// (see `nextPollDelayMs` in P2PService).
    ///
    /// Battery: the swarm advances only while `poll_events` runs (`now_or_never`, no
    /// background task). Opening the poll interval blindly would stall the network:
    /// handshakes, Tor circuit builds and mesh upkeep would slow down too. So the
    /// interval follows the core's real state. Busy means:
    ///   * at least one connected peer (an incoming message is possible, keepalive runs),
    ///   * a packet awaiting confirmation (retry timer runs),
    ///   * a file download or upload in progress,
    ///   * an unsent envelope in the queue,
    ///   * server work to deposit or fetch.
    /// If none holds, the only thing left is accepting an inbound connection, which
    /// needs no poll every second.
    pub(crate) fn has_pending_work(&self) -> bool {
        // Battery: a connected peer alone is not busy. A permanently open Tor or server
        // connection kept the wake lock held 24/7 with the screen off and drained 20-40 %
        // per day. Only real pending work keeps the device awake.
        // awaiting_confirmation, pending_envelopes and pending_group_messages are NOT
        // counted. Messages for an offline peer wait for hours and the retry timer handles
        // them. Counting them would hold the CPU awake (measured: wake lock held 15/15 min).
        // An active pairing (TTL 15 min) needs fast polls for the IdentityExchange and
        // Handshake rounds. Without them, pairing stalled in the 60 s waits of deep idle.
        // Server work counts only while connected to a server. While it is unreachable these
        // queues cannot advance, and counting them held the wake lock 24/7 (measured 15/15
        // min). `server_archive_queue` (background sync backlog) is never counted.
        self.pairing_is_fresh()
            || self.downloads_busy() > 0
            // `server_inflight` is not work. The 30 s fetch sweep is sent in the same poll turn the service checks next, so it always read as busy,
            // and no phone reached deep idle (measured: wake lock held 30 of 30 minutes, LTE radio active 93 %). Its reply is a network event that
            // wakes the native wait anyway.
            // Not while the server refuses deposits (quota): the upload then only waits for the backoff. Only with a routing server up, since
            // uploads go nowhere else.
            || self.blob_upload_can_run()
            // A deferred incoming packet means the device is not idle. Otherwise it would drop
            // into the 30 s deep-idle step and delay delivery (see `deferred_incoming`). Not
            // while the core only waits for the storage keys: that wait ends with a call from
            // the app, not with work here, and must not hold the CPU.
            || (!self.deferred_incoming.is_empty() && self.storage_keys_ready())
            || self.call.is_some()
    }

    /// Downloads that moved within the stall timeout and are not waiting for `retry_at`.
    /// A stalled one is probed by `check_stalled_downloads` on the next poll. The answer
    /// is a network event that wakes the native wait, so the wake lock need not be held
    /// between probes.
    pub(crate) fn downloads_busy(&self) -> usize {
        let now = current_time_ms();
        self.active_downloads.values()
            .filter(|s| s.retry_at == 0 && now.saturating_sub(s.last_progress_at) < DOWNLOAD_STALL_TIMEOUT_MS)
            .count()
    }

    /// A pairing counts as work for its first two minutes only. One that never completes
    /// would otherwise hold the wake lock for the whole 15 min TTL.
    pub(crate) fn pairing_is_fresh(&self) -> bool {
        let now = current_time_ms();
        self.pairing_mailbox_subs.values().any(|at| now.saturating_sub(*at) < 2 * 60 * 1000)
    }

    /// Which `has_pending_work` terms are true. Logged when busy, so a phone that never
    /// reaches deep idle says why.
    pub(crate) fn busy_reasons(&self) -> String {
        let mut r = Vec::new();
        if self.pairing_is_fresh() { r.push(format!("pairing={}", self.pairing_mailbox_subs.len())); }
        if self.downloads_busy() > 0 { r.push(format!("downloads={}", self.downloads_busy())); }
        if self.blob_upload_can_run() { r.push(format!("blob_uploads={}", self.server_blob_uploads.len())); }
        if !self.deferred_incoming.is_empty() && self.storage_keys_ready() { r.push(format!("deferred_incoming={}", self.deferred_incoming.len())); }
        if self.call.is_some() { r.push("call".into()); }
        r.join(",")
    }

    /// Raw network signals of THIS device (not the peer) for the chat header status, as
    /// JSON. The Kotlin side builds the human-readable summary (i18n, adjustable later;
    /// see P2PLib.kt). Rust and libp2p cannot tell whether the internet is reachable,
    /// since they have no access to OS interfaces. Kotlin adds that as `has_internet`
    /// via `ConnectivityManager`.
    pub(crate) fn own_connection_status(&self) -> serde_json::Value {
        let connected_peers = self.swarm.as_ref().map(|s| s.connected_peers().count()).unwrap_or(0);
        let busy = self.has_pending_work();
        if busy {
            log::debug!("Çekirdek meşgul: {}", self.busy_reasons());
        }
        // Coming out of power save: true until every link's pulled-forward keepalive probe
        // is answered (the UI shows a spinner). 10 s cap, so a dead link cannot keep it
        // spinning.
        let syncing = self.resync_since != 0
            && mono_ms().saturating_sub(self.resync_since) < 10_000
            && self.keepalive_state.values().any(|s| {
                s.outstanding.is_some() || s.next_due_at <= self.resync_since + KEEPALIVE_FAST_INTERVAL_MS
            });
        serde_json::json!({
            "busy": busy,
            "syncing": syncing,
            "connected_peers": connected_peers,
            "listening": !self.own_listen_addrs.is_empty(),
            "tor_enabled": self.tor_enabled,
            "tor_status": self.tor.as_ref().map(|h| h.status().as_str().to_string()).unwrap_or_else(|| "disabled".to_string()),
            "node_mode": self.node_mode_enabled,
        })
    }

    /// Gossip topic name. It used to be derived directly from the recipient's device fingerprint (`p2p_msg_<fingerprint>`). Any network observer
    /// could then see which fingerprint received a message, and when, without reading it (traffic analysis; see SECURITY.md). After a ratchet
    /// session exists, the topic is a pseudorandom name derived with HKDF from that session's `root_key`. Only the two sides of the session share
    /// that secret, so the name cannot be traced back to the fingerprint. `root_key` changes at each DH/KEM rotation (every 30 min, see ratchet.rs),
    /// so the topic rotates too.
    ///
    /// Known limit: before any ratchet session exists (the first IdentityExchange and HandshakeInit pair) there is no shared secret, so the old
    /// `p2p_msg_<fingerprint>` mailbox topic is used. Ongoing conversation traffic is protected. Only the first pairing exchange stays visible by
    /// fingerprint (documented in SECURITY.md).
    ///
    /// The input is `ratchet::root_handle` of a root (`root_handle_now` or `prev_root_key`), never the root itself.
    /// Since gossipsub was removed, the topic string only names the session's mailbox on the server.
    pub(crate) fn topic_for_root_key(root_key: &[u8]) -> String {
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, root_key);
        let mut topic_id = [0u8; 16];
        hk.expand(b"p2pmsg-v0.1-gossip-topic", &mut topic_id).expect("HKDF expand failed");
        format!("p2p_rt_{}", hex::encode(topic_id))
    }

    /// Adds a candidate to `known_relay_peers` (see SECURITY.md, cross-network connectivity). When `MAX_KNOWN_RELAYS` is full, the least recently
    /// seen entry is evicted. It is an opportunistic cache and is not persisted: each process refills it from what it sees.
    pub(crate) fn record_known_relay(&mut self, peer_id: PeerId, addr: Multiaddr) {
        // LRU eviction: the entry with the oldest last-seen time is removed. (Earlier,
        // `keys().next()` picked an arbitrary entry, and a working relay could be evicted
        // while dead ones stayed.) identify calls this on every encounter, so timestamps
        // refresh naturally.
        if !self.known_relay_peers.contains_key(&peer_id) && self.known_relay_peers.len() >= MAX_KNOWN_RELAYS {
            if let Some(evict) = self.known_relay_peers.iter()
                .min_by_key(|(_, (_, last_seen))| *last_seen)
                .map(|(pid, _)| *pid)
            {
                self.known_relay_peers.remove(&evict);
            }
        }
        if !self.known_relay_peers.contains_key(&peer_id) {
            info!("Röle adayı kaydedildi: {} {}", crate::log_id(&peer_id), addr);
        }
        self.known_relay_peers.insert(peer_id, (addr, current_time_ms()));
    }

    /// Onion address of a configured server (with the `/p2p/<id>` suffix).
    pub(crate) fn server_onion_addr(&self, peer: &PeerId) -> Option<Multiaddr> {
        let id = peer.to_string();
        let rec = self.servers.iter().find(|r| r.server_id == id)?;
        let addr: Multiaddr = rec.address.split(',')
            .map(str::trim)
            .find(|a| a.contains(".onion") || a.contains("/onion3/"))?
            .parse().ok()?;
        Some(if extract_peer_id(&addr).is_some() { addr } else { addr.with(MultiaddrProtocol::P2p(*peer)) })
    }

    /// Requests a Circuit Relay v2 reservation on every known relay (`listen_on
    /// <relay>/p2p-circuit`). Without reservations a device cannot be reached through a
    /// relay: a `/p2p-circuit/p2p/<target>` dial is refused unless the target holds a
    /// reservation there, so two NATed devices could never meet through a relay. An
    /// accepted reservation appears as a circuit address in `swarm.listeners()`. If none
    /// appears and the last try is older than `RELAY_RESERVATION_RETRY_MS`, it is
    /// requested again. The listener disappears when the relay drops, so this retries.
    /// Called from `reconnect_sweep`.
    pub(crate) fn ensure_relay_reservations(&mut self) {
        let Some(swarm) = &mut self.swarm else { return };
        let now = current_time_ms();
        let local = *swarm.local_peer_id();
        // Accepted reservations look like `<relay>/p2p/<relay_id>/p2p-circuit...`. The
        // first /p2p belongs to the relay.
        let active: std::collections::HashSet<PeerId> = swarm.listeners()
            .filter(|a| a.iter().any(|p| matches!(p, MultiaddrProtocol::P2pCircuit)))
            .filter_map(|a| a.iter().find_map(|p| match p { MultiaddrProtocol::P2p(pid) => Some(pid), _ => None }))
            .collect();
        let known = &self.known_relay_peers;
        self.relay_listeners.retain(|pid, (lid, _)| {
            let keep = known.contains_key(pid);
            if !keep { swarm.remove_listener(*lid); }
            keep
        });
        for (pid, (addr, _)) in known {
            // Same reason as `dial_with_relay_fallback`: a reservation on an unconnected relay
            // means a dial to it every RELAY_RESERVATION_RETRY_MS.
            if *pid == local || active.contains(pid) || !swarm.is_connected(pid) { continue; }
            if let Some((lid, at)) = self.relay_listeners.get(pid) {
                if now.saturating_sub(*at) < RELAY_RESERVATION_RETRY_MS { continue; }
                swarm.remove_listener(*lid);
            }
            match swarm.listen_on(addr.clone().with(MultiaddrProtocol::P2pCircuit)) {
                Ok(lid) => {
                    info!("Röle rezervasyonu isteniyor: röle={}", crate::log_id(&pid));
                    self.relay_listeners.insert(*pid, (lid, now));
                }
                Err(e) => warn!("Röle rezervasyonu istenemedi (röle={}): {}", crate::log_id(&pid), e),
            }
        }
    }

    /// Dials a peer directly (`direct_addr`, if any) and, for each known relay candidate,
    /// through a `/p2p-circuit/` address, all at once. libp2p handles several concurrent
    /// dials to one PeerId well: the first success wins and the rest are cancelled.
    /// Compared with "try direct, then the relay on failure", this has lower latency
    /// (the relay attempt starts without waiting for a failed direct timeout) and needs
    /// no separate retry state machine. During a bulk transfer it opens extra connections
    /// to the peers involved and closes them when done (see `BULK_PARALLEL_CONNECTIONS`).
    ///
    /// Called from `poll_events` every turn. It has its own time gate.
    pub(crate) fn manage_bulk_connections(&mut self) {
        // Peers currently in a bulk transfer: the download source, and servers with a
        // pending blob upload.
        let mut want: std::collections::HashSet<PeerId> = self
            .active_downloads
            .values()
            .map(|d| d.peer_id)
            .collect();
        if self.blob_upload_can_run() {
            for p in self.server_peer_ids() {
                want.insert(p);
            }
        }

        let now = mono_ms();
        for peer in &want {
            // Extra connections to a peer we already have one to. `have` assumes that. Without
            // it, an unreachable server or download source was redialed again and again, outside
            // the radio window.
            if !self.swarm.as_ref().map_or(false, |s| s.is_connected(peer)) {
                continue;
            }
            // Dials still in flight count. An onion dial takes 10-30 s. Without this, a new one
            // started every `BULK_DIAL_MIN_INTERVAL_MS` until the first one landed.
            let have = 1 + self.extra_conns.get(peer).map(|v| v.len()).unwrap_or(0)
                + self.bulk_dials.values().filter(|p| *p == peer).count();
            if have >= BULK_PARALLEL_CONNECTIONS {
                continue;
            }
            let h = self.bulk_health.entry(*peer).or_default();
            // Parallelism given up: a single circuit until the cooldown ends.
            if now < h.giveup_until {
                continue;
            }
            if h.giveup_until != 0 && now >= h.giveup_until {
                // Cooldown over: clean slate.
                *h = BulkHealth::default();
            }
            if now < h.next_dial_at {
                continue;
            }
            // Onion address first. `peer_id_to_addr` is filled only for connections we dialed,
            // so a peer that dialed us never got a second connection.
            let onion = self.peer_onion_addr.get(peer).and_then(|a| a.parse::<Multiaddr>().ok());
            let Some(addr) = onion.or_else(|| self.peer_id_to_addr.get(peer).cloned()) else { continue };
            if let Some(h) = self.bulk_health.get_mut(peer) {
                h.next_dial_at = now + BULK_DIAL_MIN_INTERVAL_MS.max(h.backoff_ms);
            }
            // `PeerCondition::Always`: open a NEW connection even when already connected. The
            // default condition ("do not dial if connected") is exactly what is not wanted here.
            let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(*peer)
                .addresses(vec![addr])
                .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
                .build();
            let cid = opts.connection_id();
            if let Some(swarm) = &mut self.swarm {
                match swarm.dial(opts) {
                    Ok(()) => {
                        self.bulk_dials.insert(cid, *peer);
                        info!("Toplu aktarım için fazladan bağlantı açılıyor: peer={} (mevcut {})", crate::log_id(&peer), have)
                    }
                    Err(e) => warn!("Fazladan bağlantı açılamadı: {}", e),
                }
            }
        }

        // Close the extra connections of peers whose bulk transfer ended.
        let stale: Vec<(PeerId, Vec<libp2p::swarm::ConnectionId>)> = self
            .extra_conns
            .iter()
            .filter(|(p, _)| !want.contains(p))
            .map(|(p, v)| (*p, v.clone()))
            .collect();
        for (peer, conns) in stale {
            if let Some(swarm) = &mut self.swarm {
                for cid in &conns {
                    swarm.close_connection(*cid);
                }
            }
            info!("Toplu aktarım bitti, {} fazladan bağlantı kapatılıyor: peer={}", conns.len(), crate::log_id(&peer));
            self.extra_conns.remove(&peer);
            self.bulk_dials.retain(|_, p| *p != peer);
            // Health is per transfer. The next transfer starts from a clean state.
            self.bulk_health.remove(&peer);
        }
    }

    /// Records a chunk timeout and, if needed, lowers parallelism one step (see `BulkHealth`).
    ///
    /// The earlier behaviour closed all extra connections at the first timeout, which was
    /// wrong twice. (a) Over Tor one timeout is noise, not a reason to drop three
    /// circuits. (b) If the path is persistently bad, opening and closing circuits makes
    /// it worse, since each build takes 5-15 s and competes with data traffic.
    ///
    /// Now it steps down. Once enough timeouts pile up in the window, ONE circuit is
    /// dropped (3, then 2, then 1). Each step doubles the retry wait. When the step count
    /// passes the ceiling, parallelism is abandoned for this transfer.
    pub(crate) fn note_bulk_timeout(&mut self, peer: PeerId) {
        let now = mono_ms();
        let h = self.bulk_health.entry(peer).or_default();
        h.strikes.retain(|t| now.saturating_sub(*t) < BULK_STRIKE_WINDOW_MS);
        h.strikes.push(now);
        if h.strikes.len() < BULK_STRIKES_TO_DROP {
            return;
        }
        h.strikes.clear();
        h.drops += 1;
        h.backoff_ms = if h.backoff_ms == 0 {
            BULK_DIAL_MIN_INTERVAL_MS * 2
        } else {
            (h.backoff_ms * 2).min(BULK_DIAL_MAX_BACKOFF_MS)
        };
        h.next_dial_at = now + h.backoff_ms;
        let drops = h.drops;
        if drops >= BULK_MAX_DROPS_BEFORE_GIVEUP {
            h.giveup_until = now + BULK_GIVEUP_COOLDOWN_MS;
            warn!(
                "Paralel aktarım bu eşte {} kez geri çekildi, tek devreye dönülüyor: peer={}",
                drops, crate::log_id(&peer)
            );
            self.drop_extra_connections(peer, "Paralellikten vazgeçildi", usize::MAX);
            return;
        }
        // Drop ONE circuit, not all of them.
        self.drop_extra_connections(peer, "Tekrarlayan parça zaman aşımı", 1);
    }

    /// Closes the extra connections of one peer (see `extra_conns`). Called when a timeout
    /// is seen. A new failure mode comes with parallel circuits: when one dies,
    /// `request_response` keeps spreading requests over the open connections (round-robin),
    /// and 1/N of the requests time out. On a real device this caused a 58 s stall in the
    /// middle of a transfer, and the window fell from 19 to 9. Closing the connection that
    /// carries the dead circuit concentrates traffic on the healthy ones.
    /// `manage_bulk_connections` opens a fresh circuit when the wait is over.
    pub(crate) fn drop_extra_connections(&mut self, peer: PeerId, reason: &str, how_many: usize) {
        let Some(list) = self.extra_conns.get_mut(&peer) else { return };
        if list.is_empty() {
            return;
        }
        // Drop the NEWEST ones. `manage_bulk_connections` opens them in order, so the last one
        // added is the youngest circuit and the likeliest source of the problem. The exact
        // broken circuit is not known: the `OutboundFailure` event of `request_response`
        // carries no `connection_id`, so a failed request cannot be tied to a connection.
        let n = how_many.min(list.len());
        let victims: Vec<libp2p::swarm::ConnectionId> = list.split_off(list.len() - n);
        let remaining = list.len();
        if list.is_empty() {
            self.extra_conns.remove(&peer);
        }
        if let Some(swarm) = &mut self.swarm {
            for cid in &victims {
                swarm.close_connection(*cid);
            }
        }
        warn!(
            "{} — {} fazladan bağlantı kapatıldı ({} kaldı): peer={}",
            reason, victims.len(), remaining, crate::log_id(&peer)
        );
    }


    /// Chunk size of a file, stored per file. A NULL value in the row means the legacy
    /// 256 KiB. The size is stored per file because the `.enc` format uses FIXED steps:
    /// reading an old file with a new step gives garbage. New files use
    /// `FILE_CHUNK_SIZE_V2` (512 KiB).
    pub(crate) fn file_chunk_size(&self, file_id: &str) -> usize {
        self.db
            .as_ref()
            .and_then(|c| {
                c.query_row("SELECT chunk_size FROM files WHERE file_id = ?1", params![file_id], |r| {
                    r.get::<_, Option<i64>>(0)
                })
                .ok()
                .flatten()
            })
            .map(|v| v as usize)
            // Rows stored before `receive_file_offer` checked the size.
            .filter(|v| attachments::chunk_size_ok(*v))
            .unwrap_or(attachments::FILE_CHUNK_SIZE)
    }

    pub(crate) fn dial_with_relay_fallback(&mut self, target_peer_id: PeerId, direct_addr: Option<Multiaddr>) {
        let Some(swarm) = &mut self.swarm else { return };
        if let Some(addr) = direct_addr {
            if let Err(e) = swarm.dial(addr) {
                error!("Doğrudan dial başarısız: {}", e);
            }
        }
        for (relay_peer_id, (relay_addr, _)) in &self.known_relay_peers {
            // Only through a relay we are already connected to. Dialing the circuit address of an unreachable relay first dials the relay. With the
            // server offline, every reconnect to any peer became another failed onion lookup (measured overnight: 444 failed dials to the server,
            // about one per 80 s, with CPU and radio never idle). Connecting to the relay itself is `server_sweep`'s job.
            if *relay_peer_id == target_peer_id || !swarm.is_connected(relay_peer_id) {
                continue;
            }
            let circuit_addr = relay_addr.clone()
                .with(MultiaddrProtocol::P2pCircuit)
                .with(MultiaddrProtocol::P2p(target_peer_id));
            if let Err(e) = swarm.dial(circuit_addr) {
                error!("Röle üzerinden dial başarısız (röle={}): {}", crate::log_id(&relay_peer_id), e);
            }
        }
    }

    /// Self-healing reconnect. Called periodically from `poll_events` (see
    /// `RECONNECT_SWEEP_INTERVAL_MS`). For each known and active remote device with no live
    /// libp2p connection and a persistent address hint (`device_last_addr`), it calls
    /// `try_reconnect_device`.
    ///
    /// This is the broadest network safety net. It grew over time. First came this
    /// periodic scan (before it, reconnecting relied on the QR being rescanned by hand).
    /// Then keepalive (see `P2PBehaviour.keepalive`) and the `ConnectionClosed` event were
    /// added. `poll_events` now triggers `try_reconnect_device` at once through
    /// `connections_lost`, so a disconnect is repaired within seconds, not at the next scan
    /// (up to 15 s). Today this function is a SAFETY NET, not the main recovery. It catches
    /// cases where keepalive or ConnectionClosed missed something, or where the process
    /// started before a connection existed.
    ///
    /// Known limit: if the peer's address changed completely (new public IP, no UPnP
    /// mapping, no shared relay), direct reconnect still fails. Any P2P system without a
    /// central rendezvous has this limit. The scan keeps trying, and connects once an
    /// address refreshes (new QR, relay discovery).
    ///
    /// Covers contact devices, sibling devices and configured servers. The device map
    /// holds only fingerprints of known devices, tied to a PeerId by a verified packet or
    /// by the address in the pairing code.
    pub(crate) fn is_known_peer(&self, peer: &PeerId) -> bool {
        self.is_server_peer(peer) || self.device_to_peer_id.values().any(|p| p == peer)
    }

    /// Inbound connections of unknown peers share at most `MAX_UNKNOWN_INBOUND` slots. Each lasts at most
    /// `UNKNOWN_INBOUND_GRACE_MS`. Each takes a slot of the Tor inbound bridge. Pairing makes a peer known within that time.
    // ponytail: off in node mode, where strangers hold relay reservations on purpose. There the bridge's own slot count is the only cap.
    pub(crate) fn sweep_unknown_inbound(&mut self) {
        if self.unknown_inbound.is_empty() {
            return;
        }
        let mut held: Vec<(libp2p::swarm::ConnectionId, u64)> = Vec::new();
        let mut done: Vec<libp2p::swarm::ConnectionId> = Vec::new();
        for (cid, (peer, at)) in &self.unknown_inbound {
            let open = self.peer_conns.get(peer).map_or(false, |v| v.contains(cid));
            if !open || self.node_mode_enabled || self.is_known_peer(peer) {
                done.push(*cid);
            } else {
                held.push((*cid, *at));
            }
        }
        let close = unknown_inbound_to_close(held, mono_ms());
        for cid in done.iter().chain(&close) {
            self.unknown_inbound.remove(cid);
        }
        if let Some(swarm) = self.swarm.as_mut() {
            for cid in close {
                warn!("Closing an inbound connection of an unknown peer (slot cap or 2 min without pairing)");
                swarm.close_connection(cid);
            }
        }
    }

    pub(crate) fn reconnect_sweep(&mut self) {
        let now = mono_ms();
        // See `fast_reconnect_until`: after a network change, retry every 3 s and ignore
        // backoff. The first tries fail while Tor is not ready yet, and normal backoff would
        // then delay the next try by about 20 s. Radio saver: fast only for the peers in
        // `fast_reconnect_fps`.
        let saver_fast = self.radio_saver() && !self.fast_reconnect_fps.is_empty();
        let fast = now < self.fast_reconnect_until && (!self.radio_saver() || saver_fast);
        // Radio saver: dials (onion circuit builds) only inside the window.
        if !fast && !self.radio_window_open {
            return;
        }
        let interval = if fast { FAST_RECONNECT_INTERVAL_MS } else { RECONNECT_SWEEP_INTERVAL_MS };
        if now.saturating_sub(self.last_reconnect_sweep_at) < interval {
            return;
        }
        let first_sweep_of_minute = self.last_reconnect_sweep_at / 60_000 != now / 60_000;
        self.last_reconnect_sweep_at = now;
        if fast && saver_fast && !self.radio_window_open {
            // Outside the radio window only those peers are dialed. Nothing else of the sweep runs.
            for fp in self.fast_reconnect_fps.clone() {
                self.try_reconnect_device(&fp, false);
            }
            return;
        }
        self.ensure_relay_reservations();

        // The dial and backoff logic lives in `try_reconnect_device`. It is shared with
        // `ensure_connected` and with the immediate reconnect on ping or ConnectionClosed (see
        // `poll_events`), so all of them see the same backoff state, which lowers the risk of
        // a dial storm. Only the "known and active" filter stays here. It is intentionally NOT
        // in `ensure_connected`, so it belongs to this caller.
        let fps: Vec<String> = self.known_remote_devices.values()
            .filter(|d| d.is_active)
            .map(|d| d.device_fingerprint.clone())
            .collect();
        // Not forced even in the fast window. `reconnect_all_known_now` already forced one dial
        // and reset the backoff to 15 s. Forcing every 3 s stacked parallel onion dials to
        // offline peers.
        for fp in fps {
            self.try_reconnect_device(&fp, false);
        }
        // Real-device failure: "QR scanned, nothing happened on either device". The first dial
        // failed with a Tor onion timeout. A pending link target (`pending_link_target`, set by
        // `approve_device_link`) is not yet in `known_remote_devices`, because that needs the
        // mutual IdentityExchange to complete, which is exactly what failed. The loop above
        // never sees this fingerprint, and there was no automatic retry after a failed first
        // dial. `try_reconnect_device` does not require membership in `known_remote_devices`
        // (it reads only `device_last_addr`, written by `remember_device_addr`), so the pending
        // target is also tried here directly. See `PENDING_LINK_RETRY_HORIZON_MS`: it stops
        // unbounded dial and resend for a link that never completes. Behaviour inside that
        // horizon is unchanged.
        let link_within_horizon = current_time_ms().saturating_sub(self.pending_link_started_at) <= PENDING_LINK_RETRY_HORIZON_MS;
        if let Some(fp) = self.pending_link_target.clone().filter(|_| link_within_horizon) {
            self.try_reconnect_device(&fp, false);
            // Also resend the `IdentityExchange`. See the long note in the `connections_established`
            // arm of `poll_events`: the envelope is dropped for good when `PENDING_ENVELOPE_TIMEOUT_MS`
            // expires, and nothing regenerated it. That arm catches the moment the connection is made.
            // This is the general safety net, for a connection made before this process started, or
            // after a mesh break that recovered. If an `IdentityExchange` for this target is already
            // queued, do not add another. Each sweep would add one more copy.
            let already_queued = self.pending_envelopes.iter().any(|q| {
                q.target == fp && matches!(q.envelope, NetworkEnvelope::IdentityExchange(_))
            });
            // Once a minute. A publish that worked leaves nothing queued, so without this every
            // sweep (15 s, 3 s in the fast window) sent a new one.
            if !already_queued && first_sweep_of_minute {
                if let Err(e) = self.send_identity_exchange(&fp) {
                    error!("Bağlanma IdentityExchange'i (periyodik tarama) gönderilemedi, yeniden denenecek: {}", e);
                }
            }
        }
        // Multi-device: periodic history backfill from sibling devices, debounced
        // internally (see SIBLING_BACKFILL_INTERVAL_MS). Catches contact messages missed while
        // offline.
        self.request_sibling_backfill();
    }

    /// Raw gossip publish only. Does not queue or update state. Shared by `publish_envelope`
    /// (first attempt) and the retry loop in `poll_events` (later attempts).
    ///
    /// Reliability: the error is typed now. `MessageTooLarge` (gossipsub `max_transmit_size`
    /// exceeded) is permanent: the same bytes can never succeed, however often they are
    /// retried. Before, every error counted as transient and was retried for up to 2 days,
    /// and the user was never told "failed". Also, while `swarm` did not exist yet, publish
    /// silently returned `Ok(())`, marking messages sent without publishing anything. It now
    /// returns a Transient error honestly, and the retry queues take over.
    ///
    /// `first_attempt_at`: time of this envelope's first publish attempt. The server path
    /// carries it into `ServerInflight::Deposit`, so after a server error the envelope
    /// re-queues with the SAME expiry (see there, and the `timeout` calculation in the
    /// `poll_events` retry loop).
    pub(crate) fn try_publish_raw(
        &mut self,
        target_device_fingerprint: &str,
        envelope: &NetworkEnvelope,
        first_attempt_at: u64,
    ) -> Result<(), PublishFailure> {
        self.try_publish_raw_via(target_device_fingerprint, envelope, first_attempt_at, true)
    }

    /// See `ENVELOPE_PROTOCOL`. `false` = no mapped peer and no swarm. The target is the
    /// mapped PeerId of the device. For an IdentityExchange or Handshake only, it is the
    /// connection the IdentityExchange came in on.
    fn direct_peer_for(&self, fp: &str, envelope: &NetworkEnvelope) -> Option<PeerId> {
        self.device_to_peer_id.get(fp).copied().or_else(|| match envelope {
            NetworkEnvelope::IdentityExchange(_) | NetworkEnvelope::Handshake(_) => self.pairing_reply_peer.get(fp).copied(),
            _ => None,
        })
    }

    pub(crate) fn send_envelope_direct(&mut self, fp: &str, envelope: &NetworkEnvelope, bytes: Vec<u8>, first_attempt_at: u64, retried: bool) -> bool {
        let (Some(pid), Some(swarm)) = (self.direct_peer_for(fp, envelope), self.swarm.as_mut()) else { return false };
        let request_id = swarm.behaviour_mut().envelopes.send_request(&pid, EnvelopeRequest { bytes });
        self.envelopes_inflight.insert(request_id, (fp.to_string(), envelope.clone(), first_attempt_at, retried));
        true
    }

    /// `allow_direct = false`: the `ENVELOPE_PROTOCOL` attempt already failed,
    /// so use gossipsub/server.
    pub(crate) fn try_publish_raw_via(
        &mut self,
        target_device_fingerprint: &str,
        envelope: &NetworkEnvelope,
        first_attempt_at: u64,
        allow_direct: bool,
    ) -> Result<(), PublishFailure> {
        // Blocking is a one-way check. Incoming packets were dropped and no dial was made, but the send path had no check at all:
        // `announce_address_to_all_contacts`, `set_own_profile_picture`, group fan-out and the queue kept sending packets to a blocked
        // contact, which leaked our address and online status.
        //
        // This is the single exit point of all outgoing envelopes (message, edit, delete, ack, handshake, identity, file offer,
        // group update). Returns `Permanent` so the retry queue never takes the envelope.
        if self.is_blocked_device(target_device_fingerprint) {
            return Err(PublishFailure::Permanent(
                "Alıcı engellenmiş — gönderilmedi".to_string(),
            ));
        }
        if self.known_remote_devices.get(target_device_fingerprint)
            .map_or(false, |d| self.deleted_identities.contains(&d.identity_id))
        {
            return Err(PublishFailure::Permanent("Alıcı hesabını sildi — gönderilmedi".to_string()));
        }
        let bytes = ciborium_bytes(envelope).map_err(PublishFailure::Permanent)?;
        // Every path caps at 1 MiB (gossipsub `max_transmit_size`, the cbor
        // request-response default, the server). The direct path has no check
        // of its own: it reported "sent" and the request then failed, again
        // on every retry for days.
        // Headroom: gossipsub measures the whole protobuf frame (topic, seqno,
        // ...) against the cap, so an envelope of exactly 1 MiB never went out.
        if bytes.len() + 4096 > MAX_ENVELOPE_BYTES {
            return Err(PublishFailure::Permanent(format!("Zarf çok büyük ({} bayt)", bytes.len())));
        }
        let mailbox_topic = || format!("p2p_msg_{}", target_device_fingerprint);
        // A ratchet session normally routes by the rotating topic derived from `root_key` (see `topic_for_root_key`). Two exceptions
        // use the mailbox topic (`p2p_msg_<fingerprint>`) instead, because the peer cannot yet derive the rotating topic:
        //
        // 1. `Handshake` and `IdentityExchange` always use the mailbox topic, even when a ratchet record exists. `initiate_handshake_with`
        //    inserts the ratchet into `self.ratchets` before publishing HandshakeInit, so a plain lookup would wrongly pick the rotating
        //    topic. The peer does not have the root key yet and cannot subscribe to it.
        // 2. A `Message` that announces a rotation (`rotation_kyber_ciphertext` set) uses the topic of the previous root key (`prev_root_key`).
        //    The peer cannot learn the new root key before it receives this packet. Ordinary messages use the current `root_key` topic.
        let topic = match envelope {
            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => mailbox_topic(),
            NetworkEnvelope::Message(packet) if packet.header.rotation_kyber_ciphertext.is_some() => {
                match self.ratchets.get(target_device_fingerprint).and_then(|r| r.prev_root_key.as_ref()) {
                    Some(prev_root_key) => Self::topic_for_root_key(prev_root_key),
                    None => mailbox_topic(),
                }
            }
            _ => match self.ratchets.get(target_device_fingerprint) {
                Some(ratchet) => Self::topic_for_root_key(&ratchet.root_handle_now()),
                None => mailbox_topic(),
            },
        };
        // Server path (see `server_client`). Topic choice stays as above. The server uses a blinded form of the same topic string as the
        // mailbox id. So both exceptions above carry over to the server path as well.
        let topic_str = topic;
        // If a live libp2p connection exists (LAN, Tor or relay), try that path first. The server copy is kept only if the envelope is
        // still unacknowledged at the first retry (`ACK_RETRY_INITIAL_MS`). Before, with a server configured, two phones on the same LAN
        // uploaded every message over Tor to the server for the first 30 s (about 15 KB per message plus a Tor round trip).
        // The guarantee is unchanged: without an Ack, the envelope falls back to the server.
        // Handshake, IdentityExchange and rotation announcements always go by both paths (see `should_shadow_on_gossipsub`).
        let direct = self.direct_peer_for(target_device_fingerprint, envelope)
            .map_or(false, |p| self.swarm.as_ref().map_or(false, |s| s.is_connected(&p)));
        let critical = self.call_signal_sending || match envelope {
            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => true,
            NetworkEnvelope::Message(m) => m.header.rotation_kyber_ciphertext.is_some(),
        };
        let unconfirmed_past_first_retry = match envelope {
            NetworkEnvelope::Message(m) => self.awaiting_confirmation.get(&m.header.message_id)
                .map_or(false, |pc| current_time_ms().saturating_sub(pc.first_sent_at) >= ACK_SUSPECT_MS),
            _ => false,
        };
        let mut deposited = (!direct || critical || unconfirmed_past_first_retry)
            && self.try_server_deposit(target_device_fingerprint, &topic_str, envelope, &bytes, first_attempt_at);
        // See `ENVELOPE_PROTOCOL`. Failure falls back to gossipsub/server in
        // `poll_events` (`EnvelopeEventLocal::Failed`).
        if direct && allow_direct && self.send_envelope_direct(target_device_fingerprint, envelope, bytes.clone(), first_attempt_at, false) {
            return Ok(());
        }
        // No direct path, or it failed: the server copy is the delivery
        // (gossipsub is gone, ). Without one the envelope is queued.
        if !deposited && direct {
            deposited = self.try_server_deposit(target_device_fingerprint, &topic_str, envelope, &bytes, first_attempt_at);
        }
        if deposited {
            Ok(())
        } else {
            Err(PublishFailure::Transient("Hedefe bağlantı yok ve sunucu kopyası bırakılamadı".to_string()))
        }
    }

    /// Publishes any envelope (Handshake, IdentityExchange, Message, GroupUpdate, ...) to the peer's gossip topic. Right after the first
    /// connection the gossip mesh may not exist yet, and the publish fails with `InsufficientPeers` or `NoPeersSubscribedToTopic`.
    /// Every failed envelope is queued in `pending_envelopes`. `poll_events` resends the SAME envelope each turn (no re-encryption and
    /// no re-signing). This is one central mechanism for all envelope types, replacing per-caller queues that did not cover
    /// HandshakeInit. For a `Message`, `message_status` is updated too (the UI shows send and error icons from it).
    pub(crate) fn publish_envelope(&mut self, target_device_fingerprint: &str, envelope: &NetworkEnvelope) -> Result<(), String> {
        self.publish_envelope_at(target_device_fingerprint, envelope, current_time_ms())
    }

    /// Adds to `pending_envelopes` unless the same envelope is already queued for this target. Keys are cached per entry, so only
    /// the new one is encoded.
    pub(crate) fn enqueue_pending(&mut self, queued: QueuedEnvelope) {
        let already_queued = queued.key.is_some()
            && self.pending_envelopes.iter().any(|q| q.target == queued.target && q.key == queued.key);
        if !already_queued {
            self.pending_envelopes.push(queued);
        }
    }

    /// Like `publish_envelope`, but the caller sets the envelope's age counter. The server-failure requeue path passes the ORIGINAL
    /// time. See `server_client::requeue_failed_deposit`.
    pub(crate) fn publish_envelope_at(
        &mut self,
        target_device_fingerprint: &str,
        envelope: &NetworkEnvelope,
        first_attempt_at: u64,
    ) -> Result<(), String> {
        match self.try_publish_raw(target_device_fingerprint, envelope, first_attempt_at) {
            Err(PublishFailure::Permanent(e)) => {
                // See `PublishFailure`. A retry can never succeed, so do not queue it. Mark Failed now and notify the UI.
                if let NetworkEnvelope::Message(m) = envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                    self.attachment_events.push(serde_json::json!({
                        "type": "status", "peer": self.canonical_peer_key(target_device_fingerprint),
                        "message_id": m.header.message_id, "status": "error"
                    }).to_string());
                }
                Err(e)
            }
            Err(PublishFailure::Transient(e)) => {
                if let NetworkEnvelope::Message(m) = envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Pending);
                }
                // If the same envelope is already queued for this target, do not add a second copy. Each server round trip
                // left one more copy, and the queue (and the redeposit every second) grew exponentially.
                // `NetworkEnvelope` does not derive `PartialEq` (packets hold raw bytes). So identity uses the deduplication key the
                // server path already uses.
                self.enqueue_pending(QueuedEnvelope::new(target_device_fingerprint.to_string(), envelope.clone(), first_attempt_at));
                Err(e)
            }
            Ok(()) => {
                if let NetworkEnvelope::Message(m) = envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                }
                Ok(())
            }
        }
    }

    /// Like `publish_envelope`: it tries once right away and updates the status the same way. Unlike that function, it keeps
    /// re-sending the packet after the first attempt, even on success, until the peer acknowledges it. There is no upper time limit,
    /// unlike `pending_envelopes`.
    ///
    /// `original_sent_at_override` and `retry_interval_ms_override` are `Some` ONLY when called from a `regen_content` regeneration
    /// (see the age branch of `retry_unconfirmed_messages`). They keep the message's first queue time and the backoff reached so far.
    /// Without them, each 25-minute regeneration reset `retry_interval_ms` to `ACK_RETRY_INITIAL_MS` (15 s). A peer offline for days would
    /// then see a 15 s, 30 s, 60 s, 120 s burst every 25 minutes. A message already at the `ACK_RETRY_MAX_MS` (120 s) ceiling now stays
    /// there across regenerations: a steady, predictable pulse of about two minutes.
    pub(crate) fn publish_with_ack_tracking(
        &mut self,
        target_device_fingerprint: &str,
        message_id: &str,
        envelope: NetworkEnvelope,
        regen_content: Option<MessageContent>,
        original_sent_at_override: Option<u64>,
        retry_interval_ms_override: Option<u64>,
    ) {
        let now = current_time_ms();
        match self.try_publish_raw(target_device_fingerprint, &envelope, now) {
            Ok(()) => {
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                }
            }
            // See `PublishFailure`. A permanent error (for example `MessageTooLarge`) must not enter the acknowledgement queue.
            // Mark it Failed now and notify the UI, since a retry can never succeed.
            Err(PublishFailure::Permanent(e)) => {
                error!("Gönderim KALICI olarak başarısız (yeniden denenmeyecek): {}", e);
                // A refresh of an entry that is already tracked: drop the old
                // entry too, or it stays due and is re-encrypted every turn.
                self.awaiting_confirmation.remove(message_id);
                self.remove_durable_retry(message_id);
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                    self.attachment_events.push(serde_json::json!({
                        "type": "status", "peer": self.canonical_peer_key(target_device_fingerprint),
                        "message_id": m.header.message_id, "status": "error"
                    }).to_string());
                }
                return;
            }
            Err(PublishFailure::Transient(e)) => {
                error!("İlk gönderim denemesi başarısız (onay alınana kadar yeniden denenecek): {}", e);
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Pending);
                }
            }
        }
        // The entry is also written to the encrypted DB, so it survives a process kill. Written by reference before the move
        // into the struct. The real start time is stored, not `now`. Otherwise the 7-day give-up window would reset on every refresh.
        let original_sent_at = original_sent_at_override.unwrap_or(now);
        if let Some(content) = &regen_content {
            self.persist_durable_retry(message_id, target_device_fingerprint, content, original_sent_at);
        }
        let retry_interval_ms = retry_interval_ms_override.unwrap_or(ACK_RETRY_INITIAL_MS);
        self.awaiting_confirmation.insert(message_id.to_string(), PendingConfirmation {
            suspect_probed: false,
            direct_delivered: false,
            // The packet is stamped with the chain generation it was encrypted under.
            chain_stamp: self.chain_stamp_for(target_device_fingerprint),
            peer_device_fingerprint: target_device_fingerprint.to_string(),
            envelope,
            next_retry_at: now + retry_interval_ms,
            retry_interval_ms,
            first_sent_at: now,
            original_sent_at,
            last_attempt_at: now,
            regen_content,
        });
    }

    /// Called from `poll_events`. Re-publishes every due entry of `awaiting_confirmation` (without re-encrypting) and grows the next
    /// retry interval exponentially, capped at `ACK_RETRY_MAX_MS`.
    pub(crate) fn retry_unconfirmed_messages(&mut self) {
        // Revoked devices whose last notice had time to go out.
        if !self.revoked_disconnects.is_empty() {
            let now = mono_ms();
            let (due, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.revoked_disconnects).into_iter().partition(|(_, at)| now >= *at);
            self.revoked_disconnects = keep;
            if let Some(swarm) = &mut self.swarm {
                for (peer, _) in due {
                    let _ = swarm.disconnect_peer_id(peer);
                }
            }
        }
        // `poll_events` calls this every turn. Unlike `reconnect_sweep`, `group_sync_sweep` and `periodic_storage_sweep`, this function
        // had no interval check. With an empty `awaiting_confirmation` map, the usual idle case, the filter, map, collect and sort below
        // still allocated and scanned on every turn.
        if self.awaiting_confirmation.is_empty() {
            return;
        }
        let now = current_time_ms();
        // Runs the scan below (whole map, HKDF per peer, sort) at most once a second, not on every poll turn.
        if now.saturating_sub(self.last_unconfirmed_retry_at) < 1_000 {
            return;
        }
        self.last_unconfirmed_retry_at = now;
        // See `KeepAliveState.suspect`. If a connection we think is alive gives no Ack within `ACK_SUSPECT_MS`, probe it now.
        let mut suspects: Vec<PeerId> = Vec::new();
        let mut early_deposit: Vec<(String, NetworkEnvelope)> = Vec::new();
        for p in self.awaiting_confirmation.values_mut() {
            if !p.suspect_probed && !p.direct_delivered && now.saturating_sub(p.first_sent_at) >= ACK_SUSPECT_MS {
                p.suspect_probed = true;
                early_deposit.push((p.peer_device_fingerprint.clone(), p.envelope.clone()));
                if let Some(pid) = self.device_to_peer_id.get(&p.peer_device_fingerprint) {
                    suspects.push(*pid);
                }
            }
        }
        for pid in suspects {
            self.mark_connection_suspect(pid, false);
        }
        // A packet sent directly but unacknowledged within `ACK_SUSPECT_MS` is also left on the server, without waiting for the first
        // 15 s retry (`ACK_RETRY_INITIAL_MS`). If the sender goes offline meanwhile, the message is on the server. Gossip would not
        // re-send the same bytes anyway (it reports `Duplicate`).
        for (fp, envelope) in early_deposit {
            // Server copy only (`allow_direct = false`). The direct copy is in flight, and `try_publish_raw` already sent the envelope once.
            if self.is_connected_to_device(&fp) && !self.ready_server_peers().is_empty() {
                if let Err(PublishFailure::Transient(e) | PublishFailure::Permanent(e)) = self.try_publish_raw_via(&fp, &envelope, now, false) {
                    warn!("Early server copy for suspect peer {} failed: {}", crate::log_id(&fp), e);
                }
            }
        }
        // Important: `awaiting_confirmation` is a `HashMap`. Rust's std `HashMap` uses a randomly seeded hasher (DoS resistance), so the `.iter()`
        // order has nothing to do with composition order. When several messages queue up while the user is offline, a random order could change on
        // every turn. The requirement is that messages not yet sent are retried in composition order. `original_sent_at` is in every
        // `PendingConfirmation`, so sorting `due_ids` by it is enough. A `BTreeMap` would have touched every `.get`, `.get_mut`, `.remove` and
        // `.insert` call site.
        //
        // Fix: the chain generation stamp (see `PendingConfirmation.chain_stamp`) was checked only for in-order packets. A packet whose generation
        // had changed stayed in retry with ciphertext the peer could no longer decrypt, until its backoff (up to 2 minutes) expired. Refreshing
        // right away on a generation change now works as intended.
        //
        // The stamp is computed once per peer (one HKDF step, `topic_for_root_key`), not once per message.
        let mut stamp_cache: HashMap<String, String> = HashMap::new();
        // Unique first: one String per peer, not one per held message.
        let peers: Vec<String> = self
            .awaiting_confirmation
            .values()
            .map(|p| p.peer_device_fingerprint.as_str())
            .collect::<std::collections::HashSet<&str>>()
            .into_iter()
            .map(str::to_owned)
            .collect();
        for fp in peers {
            if !stamp_cache.contains_key(&fp) {
                let stamp = self.chain_stamp_for(&fp);
                stamp_cache.insert(fp, stamp);
            }
        }
        // Radio saver: retries wait for the window like every other periodic job. They used to run on their own clock (5 s doubling to 120 s), so
        // one connected peer that never acks kept the LTE radio up all the time: an 8 KB envelope re-sent every minute or two, for days (measured:
        // radio 74 % of a 10-minute screen-off run). A packet queued in the last minute is still sent at once.
        let hold_retries = self.radio_saver() && !self.radio_window_open;
        let mut due_ids: Vec<(String, u64)> = self.awaiting_confirmation.iter()
            .filter(|(_, p)| {
                // `next_retry_at == 0`: the peer just connected or subscribed,
                // so the radio is up anyway.
                if hold_retries && p.next_retry_at != 0 && now.saturating_sub(p.original_sent_at) > 60_000 {
                    return false;
                }
                if p.next_retry_at <= now {
                    return true;
                }
                match stamp_cache.get(&p.peer_device_fingerprint) {
                    Some(current) => {
                        !current.is_empty() && !p.chain_stamp.is_empty() && current != &p.chain_stamp
                    }
                    None => false,
                }
            })
            .map(|(id, p)| (id.clone(), p.original_sent_at))
            .collect();
        // `original_sent_at`: `first_sent_at` is reset by every regeneration,
        // which sent a regenerated message to the back of the queue.
        due_ids.sort_by_key(|(_, original_sent_at)| *original_sent_at);
        for (message_id, _) in due_ids {
            let (peer_fp, envelope, first_sent_at, original_sent_at, retry_interval_ms, regen_content, chain_stamp) = match self.awaiting_confirmation.get(&message_id) {
                Some(p) => (
                    p.peer_device_fingerprint.clone(), p.envelope.clone(), p.first_sent_at,
                    p.original_sent_at, p.retry_interval_ms, p.regen_content.clone(), p.chain_stamp.clone(),
                ),
                None => continue,
            };
            // Regenerated earlier in this loop (a rotation or handshake redo
            // of an earlier id re-encrypted every pending packet of the
            // peer): `stamp_cache` is older than that, so it would be sent a
            // second time.
            if first_sent_at >= now {
                continue;
            }
            // Critical (see `MAX_UNCONFIRMED_AGE_MS`): a packet older than this can no longer be decrypted by the peer, because its ratchet
            // has probably gone through a DH/KEM rotation. Resending it only makes the recipient show "Decryption failed" forever.
            // See `PendingConfirmation.chain_stamp`: if the session generation changed, the packet is undecryptable at the peer. Refresh it
            // now instead of waiting for the age limit. The age check remains only as a fallback for the case with no rotation at all.
            // The stamp is computed once per peer (see `stamp_cache`), not once per message.
            let stale_chain = match stamp_cache.get(&peer_fp) {
                Some(current) => !current.is_empty() && !chain_stamp.is_empty() && current != &chain_stamp,
                None => false,
            };
            if stale_chain || now.saturating_sub(first_sent_at) > MAX_UNCONFIRMED_AGE_MS {
                // The real give-up limit is now `original_sent_at` (when the message first entered the queue, stable across refreshes),
                // checked against `TEXT_RETRY_GIVE_UP_MS`. This check runs even when `regen_content` is set. Otherwise a message would be
                // refreshed and retried for days or weeks, and the 7-day limit would mean nothing.
                let give_up_for_real = now.saturating_sub(original_sent_at) > TEXT_RETRY_GIVE_UP_MS;
                // Sync packets are not refreshed: re-encrypting and re-depositing
                // them every ~30 min for 7 days to a device that is switched off
                // cost ~1000 server deposits a day on mobile data. The first
                // deposit stays on the server, and a returning device catches up
                // anyway (sibling backfill, roster on reconnect, next read mark,
                // next digest).
                if matches!(regen_content, Some(
                    MessageContent::SiblingEcho { .. } | MessageContent::ReadStateSync { .. }
                    | MessageContent::DeviceSync(_) | MessageContent::WbDigest { .. })) {
                    info!("Paket {} (senkron -> {}) tazelenmeden bırakıldı", message_id, &peer_fp[..peer_fp.len().min(8)]);
                    self.awaiting_confirmation.remove(&message_id);
                    self.remove_durable_retry(&message_id);
                    continue;
                }
                if !give_up_for_real {
                    // Clone (not move) so `regen_content` is still available below for the give-up event.
                    if let Some(content) = regen_content.clone() {
                        // Messages should be retried for up to about 7 days, even plain Text, until the peer acknowledges them. Resending the same
                        // stale ciphertext is pointless. Instead the original plaintext is re-encrypted with a FRESH ratchet step, keeping the same
                        // `message_id` and `original_sent_at` (see `send_message_content_inner`). The UI bubble and the `awaiting_confirmation` entry
                        // stay continuous. The pending-messages screen lists only Text, so this log line is the only place the other kinds show up.
                        let kind = content.kind();
                        warn!("Paket {} ({} -> {}) onaylanmadan azami yaşı aştı, TAZELENİP AYNI kimlikle yeniden deneniyor",
                            message_id, kind, &peer_fp[..peer_fp.len().min(8)]);
                        if let Err(e) = self.send_message_content_inner(
                            peer_fp.clone(), &content, None,
                            Some(message_id.clone()), Some(original_sent_at), Some(retry_interval_ms),
                        ) {
                            // Fix: the log said "permanently given up", but nothing was given up. The entry stayed due, because
                            // `next_retry_at <= now`, and every `poll_events` turn (once a second) tried to regenerate it again.
                            // That went on for two days, with a ratchet step on every turn. Now the backoff is pushed forward: retries
                            // continue at a reasonable pace, and the `TEXT_RETRY_GIVE_UP_MS` ceiling still applies.
                            error!("Tazeleme gönderim denemesi başarısız, geri çekilme aralığıyla yeniden denenecek: {}", e);
                            if let Some(pending) = self.awaiting_confirmation.get_mut(&message_id) {
                                pending.retry_interval_ms =
                                    (pending.retry_interval_ms * 2).min(ACK_RETRY_MAX_MS);
                                pending.next_retry_at = current_time_ms() + pending.retry_interval_ms;
                                pending.last_attempt_at = current_time_ms();
                                // A stale stamp makes the entry due every turn,
                                // past the backoff just set. Without it the
                                // age path decides.
                                pending.chain_stamp.clear();
                            }
                        }
                        continue;
                    }
                }
                self.awaiting_confirmation.remove(&message_id);
                self.remove_durable_retry(&message_id);
                // Marked failed: the relay copy must not deliver it later.
                self.cancel_server_deposit(&message_id);
                // Types without `regen_content` (for example HistorySyncResponse), and anything past `TEXT_RETRY_GIVE_UP_MS`, are marked
                // Failed. The user can resend them manually.
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                    // Same fix as the Ack arm: resolve the real target from regen_content.
                    if let Some(content) = &regen_content {
                        self.note_group_copy_failed(content, &peer_fp);
                    }
                    let (event_message_id, event_group_id) = match &regen_content {
                        Some(MessageContent::Edit { target_message_id: real_target, group_id, .. }) =>
                            (real_target.clone(), group_id.clone()),
                        Some(MessageContent::Delete { target_message_id: real_target, group_id, .. }) =>
                            (real_target.clone(), group_id.clone()),
                        // As in `cancel_pending_message`: the group bubble is keyed
                        // by the group-wide id. With the packet id and no
                        // `group_id` no screen could match this event.
                        Some(MessageContent::Text { group_id: Some(gid), group_message_local_id, .. }) =>
                            (group_message_local_id.clone().unwrap_or_else(|| m.header.message_id.clone()), Some(gid.clone())),
                        _ => (m.header.message_id.clone(), None),
                    };
                    let mut status_event = serde_json::json!({
                        "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                        "message_id": event_message_id, "status": "error"
                    });
                    if let Some(gid) = event_group_id {
                        status_event["group_id"] = serde_json::Value::String(gid);
                    }
                    self.attachment_events.push(status_event.to_string());
                }
                if give_up_for_real {
                    error!("Paket {} {} ms (TEXT_RETRY_GIVE_UP_MS) boyunca onaylanmadı, KESİN olarak vazgeçiliyor", message_id, TEXT_RETRY_GIVE_UP_MS);
                } else {
                    error!("Paket {} onaylanmadan azami yaşı ({} ms) aştı, vazgeçiliyor (muhtemelen ratchet rotasyonu geçti)", message_id, MAX_UNCONFIRMED_AGE_MS);
                }
                continue;
            }
            match self.try_publish_raw(&peer_fp, &envelope, current_time_ms()) {
                Ok(()) => {
                    if let NetworkEnvelope::Message(m) = &envelope {
                        // A group bubble is keyed by the group-wide id, as in
                        // the give-up arm above; the packet id matched no row.
                        let (row_id, row_group) = match &regen_content {
                            Some(MessageContent::Text { group_id: Some(gid), group_message_local_id: Some(local), .. }) =>
                                (local.clone(), Some(gid.clone())),
                            _ => (m.header.message_id.clone(), None),
                        };
                        // The bubble shows the error mark until told otherwise.
                        let was_failed = self.db.as_ref().map_or(false, |c| c.query_row(
                            "SELECT 1 FROM messages WHERE message_id = ?1 AND status = ?2 AND direction = 'sent'
                               AND (?3 IS NULL OR group_id = ?3)",
                            params![row_id, MessageSendStatus::Failed.as_str(), row_group], |_| Ok(())).is_ok());
                        if was_failed {
                            let mut ev = serde_json::json!({
                                "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                                "message_id": row_id, "status": "sent"
                            });
                            if let Some(gid) = &row_group {
                                ev["group_id"] = serde_json::Value::String(gid.clone());
                                if let Some(conn) = &self.db {
                                    let _ = conn.execute(
                                        "UPDATE messages SET status = 'sent' WHERE message_id = ?1 AND group_id = ?2 AND direction = 'sent' AND status = ?3",
                                        params![row_id, gid, MessageSendStatus::Failed.as_str()],
                                    );
                                }
                            }
                            self.attachment_events.push(ev.to_string());
                        }
                        self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                    }
                }
                // See `PublishFailure`. A permanent error means this envelope can never be published again. Do not let it keep the queue busy.
                Err(PublishFailure::Permanent(e)) => {
                    error!("Bekleyen paket {} KALICI yayın hatasıyla bırakılıyor: {}", message_id, e);
                    self.awaiting_confirmation.remove(&message_id);
                    self.remove_durable_retry(&message_id);
                    if let NetworkEnvelope::Message(m) = &envelope {
                        self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                        self.attachment_events.push(serde_json::json!({
                            "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                            "message_id": m.header.message_id, "status": "error"
                        }).to_string());
                    }
                    continue;
                }
                Err(PublishFailure::Transient(_)) => {
                    // Retried silently on the next turn. It is not marked Failed yet, because the user asked for "keep trying until acknowledged".
                }
            }
            if let Some(pending) = self.awaiting_confirmation.get_mut(&message_id) {
                // The "last attempt" time shown in the pending-messages list in Settings (see `list_pending_messages`).
                pending.last_attempt_at = current_time_ms();
                pending.retry_interval_ms = (pending.retry_interval_ms * 2).min(ACK_RETRY_MAX_MS);
                pending.next_retry_at = current_time_ms() + pending.retry_interval_ms;
            }
        }
    }

    /// Fix for "messages that cross a rotation stay stuck for 25 minutes": a DH or KEM rotation just happened in the session with this peer,
    /// either triggered by us or as a reply to the peer's rotation. Every packet still pending in `awaiting_confirmation` for this peer was
    /// encrypted under the OLD chain and can no longer be decrypted (see `MAX_UNCONFIRMED_AGE_MS`). Before, those packets were resent
    /// unchanged until the 25-minute age limit. Now the rotation takes effect at once. Packets carrying `regen_content` are re-encrypted
    /// under the fresh chain right away, keeping the same `message_id`, `original_sent_at` and backoff. Packets without it (Ack, Seen,
    /// HistorySyncResponse) cannot be regenerated, and losing them is harmless: an unacknowledged original is resent anyway, and a response
    /// is refreshed when the request is retried. They are dropped quietly.
    pub(crate) fn regen_pending_for_peer(&mut self, peer_fp: &str) {
        let mut regen: Vec<(String, MessageContent, u64, u64)> = Vec::new();
        let mut drop_ids: Vec<String> = Vec::new();
        for (id, p) in &self.awaiting_confirmation {
            if p.peer_device_fingerprint != peer_fp || self.regen_skip_id.as_ref() == Some(id) {
                continue;
            }
            if !matches!(p.envelope, NetworkEnvelope::Message(_)) {
                continue;
            }
            match &p.regen_content {
                Some(c) => regen.push((id.clone(), c.clone(), p.original_sent_at, p.retry_interval_ms)),
                None => drop_ids.push(id.clone()),
            }
        }
        if regen.is_empty() && drop_ids.is_empty() {
            return;
        }
        info!(
            "Rotasyon sonrası bekleyenler yenileniyor (peer={}): {} paket taze zincirle yeniden şifreleniyor, {} kurtarılamaz paket bırakılıyor",
            crate::log_id(&peer_fp), regen.len(), drop_ids.len()
        );
        for id in drop_ids {
            // reported like the age arm of `retry_unconfirmed_messages`
            // (FileOffer/ProfileUpdate/HistorySync… cannot be re-encrypted).
            if let Some(NetworkEnvelope::Message(m)) = self.awaiting_confirmation.remove(&id).map(|p| p.envelope) {
                warn!("Rotasyon: yeniden üretilemeyen paket {} bırakıldı (Failed)", crate::log_id(&id));
                self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                self.attachment_events.push(serde_json::json!({
                    "type": "status", "peer": self.canonical_peer_key(&peer_fp), "message_id": m.header.message_id, "status": "error"
                }).to_string());
            }
            self.remove_durable_retry(&id);
        }
        for (id, content, original_sent_at, retry_interval_ms) in regen {
            if let Err(e) = self.send_message_content_inner(
                peer_fp.to_string(), &content, None,
                Some(id.clone()), Some(original_sent_at), Some(retry_interval_ms),
            ) {
                error!("Rotasyon sonrası yeniden şifreleme başarısız (normal yaş-aşımı yolu devralır): {}", e);
                // See `retry_unconfirmed_messages`: or the stale stamp retries it every turn.
                if let Some(pending) = self.awaiting_confirmation.get_mut(&id) {
                    pending.chain_stamp.clear();
                }
            }
        }
    }

    /// Called when the app comes to the foreground (Kotlin `P2PApplication` foreground detection, plus the JNI `retryAllPendingNow`). It pulls
    /// the next retry time (`next_retry_at`) of every pending message forward to now, without waiting for the natural exponential backoff
    /// (up to 120 s). `awaiting_confirmation` holds only entries within `TEXT_RETRY_GIVE_UP_MS` (7 days). Older ones were already removed by
    /// the age branch of `retry_unconfirmed_messages`, so no extra age filter is needed here. The actual send attempt happens on the next
    /// `poll_events` turn (once a second, already driven by Kotlin) through the normal `retry_unconfirmed_messages` path. No network I/O
    /// happens here: only a timestamp moves, which is gentle on the battery.
    pub(crate) fn retry_all_pending_now(&mut self) {
        let now = current_time_ms();
        for pending in self.awaiting_confirmation.values_mut() {
            pending.next_retry_at = now;
        }
    }

    /// Manual "Retry now" for ONE row of the pending-messages list in Settings. Same mechanism as `retry_all_pending_now`, but only for
    /// this message. No send happens here (same battery reason). It only pulls `next_retry_at` to now, and the next `poll_events` turn
    /// (once a second, already running) makes the real attempt.
    pub(crate) fn retry_pending_message_now(&mut self, message_id: &str) -> Result<(), String> {
        let pending = self.awaiting_confirmation.get_mut(message_id).ok_or("Bekleyen mesaj bulunamadı")?;
        pending.next_retry_at = current_time_ms();
        Ok(())
    }

    /// See `PendingMessageSummary`.
    pub(crate) fn list_pending_messages(&self) -> Vec<PendingMessageSummary> {
        self.awaiting_confirmation.iter().filter_map(|(message_id, p)| {
            match &p.regen_content {
                Some(MessageContent::Text { group_id, text, .. }) => Some(PendingMessageSummary {
                    message_id: message_id.clone(),
                    peer_device_fingerprint: p.peer_device_fingerprint.clone(),
                    // See `PendingMessageSummary.device_name`.
                    device_name: self.known_remote_devices.get(&p.peer_device_fingerprint)
                        .map(|d| d.device_name.clone())
                        .unwrap_or_default(),
                    group_id: group_id.clone(),
                    text: text.clone(),
                    original_sent_at: p.original_sent_at,
                    last_attempt_at: p.last_attempt_at,
                }),
                // Edit, Delete and GroupUpdate (and the other kinds without `regen_content`, such as HistorySyncRequest and FileOffer) are not
                // messages the user wrote. The UI has no separate row for them, so they are skipped here.
                _ => None,
            }
        }).collect()
    }

    /// Cancel button for one row of the pending-messages list in Settings. Drops the message permanently, so it is never retried: it is marked
    /// Failed, and the user can resend it from the chat screen through the existing `retryMessage` flow.
    pub(crate) fn cancel_pending_message(&mut self, message_id: &str) -> Result<(), String> {
        let pending = self.awaiting_confirmation.remove(message_id).ok_or("Bekleyen mesaj bulunamadı")?;
        self.remove_durable_retry(message_id);
        // See `cancel_server_deposit`. Cancelling must also withdraw the server copy. Otherwise "I changed my mind" had no effect, and the
        // packet could still be delivered 30 days later.
        self.cancel_server_deposit(message_id);
        if let NetworkEnvelope::Message(m) = &pending.envelope {
            self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
            // Same fix as the Ack arm.
            if let Some(content) = &pending.regen_content {
                self.note_group_copy_failed(content, &pending.peer_device_fingerprint);
            }
            let (event_message_id, event_group_id) = match &pending.regen_content {
                Some(MessageContent::Edit { target_message_id: real_target, group_id, .. }) =>
                    (real_target.clone(), group_id.clone()),
                Some(MessageContent::Delete { target_message_id: real_target, group_id, .. }) =>
                    (real_target.clone(), group_id.clone()),
                // A group text: the bubble is keyed by the group-wide id. Without `group_id` the event would be taken for a 1:1 status.
                Some(MessageContent::Text { group_id: Some(gid), group_message_local_id, .. }) =>
                    (group_message_local_id.clone().unwrap_or_else(|| m.header.message_id.clone()), Some(gid.clone())),
                _ => (m.header.message_id.clone(), None),
            };
            let mut status_event = serde_json::json!({
                "type": "status", "peer": self.canonical_peer_key(&pending.peer_device_fingerprint),
                "message_id": event_message_id, "status": "error"
            });
            if let Some(gid) = event_group_id {
                status_event["group_id"] = serde_json::Value::String(gid);
            }
            self.attachment_events.push(status_event.to_string());
        }
        Ok(())
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
        // No gossip topic any more: the entry only marks "a pairing with this device was started" (see the readers of the map).
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
