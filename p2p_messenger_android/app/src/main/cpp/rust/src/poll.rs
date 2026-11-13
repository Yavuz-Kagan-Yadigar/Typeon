//! `poll_events`, early-packet buffering, rate limiting and incoming envelopes.

use super::*;

impl P2PCore {

    pub(crate) fn poll_events(&mut self) -> Vec<String> {
        lock_watch::phase("swarm_events");
        // a caught panic may have left the core half-updated; tell the
        // frontend once so it can restart the service.
        if CORE_PANICKED.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.attachment_events.push(r#"{"type":"core_panic"}"#.to_string());
        }
        if self.network_change_pending
            && mono_ms().saturating_sub(self.last_network_change_at) >= NETWORK_CHANGE_DEBOUNCE_MS
        {
            self.reconnect_all_known_now();
        }
        {
            let now = mono_ms();
            let saver = self.radio_saver();
            self.radio_window_open = !saver || now >= self.radio_window_at;
            if saver && self.radio_window_open {
                self.radio_window_at = now + self.radio_window_ms();
                // Every window fetches. A sleeping phone can miss the server's Notify (the CPU was suspended), and with the 5-minute
                // fetch sweep a window could pass without one. The radio is up for the window anyway.
                for rt in self.server_rt.values_mut() {
                    rt.fetch_due_at = 0;
                }
                self.server_sweep_at = 0;
                if now >= self.tor_wake_at {
                    self.tor_wake_at = now + TOR_FULL_WAKE_MS;
                }
            }
            // Tor dormant in radio-saver mode; awake RADIO_AWAKE_MS after a
            // full wake (dir refresh, circuit pool) and during calls.
            let dormant = saver
                && self.call.is_none()
                // A transfer needs circuits rebuilt when one breaks.
                && self.active_downloads.is_empty()
                && !self.blob_upload_can_run()
                && now >= (self.tor_wake_at + RADIO_AWAKE_MS).saturating_sub(TOR_FULL_WAKE_MS);
            if dormant != self.tor_dormant {
                if let Some(tor) = &self.tor {
                    tor.set_dormant(dormant);
                    info!("Tor dormant: {}", dormant);
                    self.tor_dormant = dormant;
                }
            }
        }
        self.call_sweep();
        // Prerequisite for reachability: the identity may have been created after the network layer started. See `ensure_own_mailbox_subscription`.
        self.ensure_own_mailbox_subscription();
        // See `pairing_mailbox_subs`. Drop pairing subscriptions whose ratchet is established or whose TTL has passed.
        self.flush_pairing_mailbox_subs();
        // `Option<PeerId>`: with gossipsub `Signed` authenticity (see `start_network`), each incoming message carries the sender's real `PeerId`.
        // This is the SOURCE of the PeerId mapping that file download (`request_response`, see `device_to_peer_id`) needs.
        let mut incoming: Vec<(Option<PeerId>, Vec<u8>)> = Vec::new();
        // `true` = new, `false` = expired; in event order.
        let mut listen_addr_changes: Vec<(Multiaddr, bool)> = Vec::new();
        let mut closed_listener_ids: Vec<libp2p::core::transport::ListenerId> = Vec::new();
        let mut direct_requests: Vec<(PeerId, Vec<u8>, request_response::ResponseChannel<EnvelopeResponse>)> = Vec::new();
        let mut new_peer_addrs: Vec<(PeerId, Multiaddr)> = Vec::new();
        let mut new_peer_onions: Vec<(PeerId, Multiaddr)> = Vec::new();
        // See `known_relay_peers`. When identify reports that a peer speaks the relay protocol, the entry is applied after the loop
        // (`self.record_known_relay`). `self.swarm` is borrowed mutably inside the loop, so `self` cannot be accessed as a whole there
        // (see `new_peer_addrs` for the same pattern).
        let mut new_relay_peers: Vec<(PeerId, Multiaddr)> = Vec::new();
        let mut file_chunk_events: Vec<FileChunkEventLocal> = Vec::new();
        let mut ack_events: Vec<AckEventLocal> = Vec::new();
        // See `server_client::ServerEventLocal`. Same collect-then-process pattern as `file_chunk_events`: `self` is not fully
        // accessible while the swarm is mutably borrowed.
        let mut server_events: Vec<server_client::ServerEventLocal> = Vec::new();
        // Connections that close, either cleanly or as a half-open link that the Ping arm closes explicitly, are collected here.
        // After the loop, a reconnect to the matching device fingerprint is tried at once (see `try_reconnect_device`), without
        // waiting for the next `reconnect_sweep` round (up to 15 s).
        let mut connections_lost: Vec<PeerId> = Vec::new();
        // See `extra_conns`. The swarm borrow prevents writing to `self` here, so the same collect-then-process pattern is used.
        let mut new_extra_conns: Vec<(PeerId, libp2p::swarm::ConnectionId)> = Vec::new();
        let mut closed_conns: Vec<(PeerId, libp2p::swarm::ConnectionId)> = Vec::new();
        let mut failed_dials: Vec<libp2p::swarm::ConnectionId> = Vec::new();
        let mut established_conns: Vec<(PeerId, libp2p::swarm::ConnectionId)> = Vec::new();
        let mut new_conn_ranks: Vec<(libp2p::swarm::ConnectionId, u8)> = Vec::new();
        let mut new_inbound: Vec<(libp2p::swarm::ConnectionId, PeerId)> = Vec::new();
        // (server peer, answered?) — see `server_rpc_timeouts`
        let mut server_rpc_outcomes: Vec<(PeerId, bool)> = Vec::new();
        let mut envelope_events: Vec<EnvelopeEventLocal> = Vec::new();
        // Collected when a connection is established, including reconnects. After the loop, if the peer already has a ratchet session,
        // `resubscribe_ratchet_topic` is called again. Normally this is unnecessary, since gossipsub tells the peer about its
        // subscriptions on each new connection. But Tor circuits (especially ones built over relay or DCUtR) break and rebuild far
        // more often than plain TCP. If the automatic announcement fails silently, the mesh can stay broken for this pair, and an
        // unconfirmed message retries forever (see `awaiting_confirmation`). The call is idempotent and cheap, so it runs on every
        // connection as a safety net.
        let mut connections_established: Vec<PeerId> = Vec::new();
        // Peers that sent a keepalive with `bye` (shutting down): parked below.
        let mut bye_peers: Vec<PeerId> = Vec::new();
        // See `keepalive_state`. The keepalive arm cannot access all of `self` while the swarm borrow is active, so the map is moved out
        // (see the `mem::take` pattern in `pending_envelopes`), updated freely in the loop, and put back afterwards.
        let mut keepalive_state = std::mem::take(&mut self.keepalive_state);
        // A panic in an earlier turn left the map taken out (empty) while the
        // connections live on: watch them again instead of never pinging them.
        if keepalive_state.is_empty() {
            if let Some(swarm) = &self.swarm {
                for peer_id in swarm.connected_peers() {
                    keepalive_state.insert(*peer_id, KeepAliveState {
                        connected_since: mono_ms(),
                        next_due_at: mono_ms() + KEEPALIVE_FAST_INTERVAL_MS,
                        consecutive_failures: 0,
                        outstanding: None,
                        suspect: false,
                        interval_ms: 0,
                        quiet_capable: false,
                    });
                }
            }
        }
        // See the keepalive filter below. It is collected beforehand, because `self` cannot be reached while the swarm is borrowed.
        let server_peers: Vec<PeerId> = self.server_peer_ids();
        // The flag is copied to a local first, because `self` is borrowed through the swarm in the `block_on` below (same pattern as `server_peers`).
        let power_save = self.power_save;
        let saver = self.radio_saver();
        let window_ms = self.radio_window_ms();
        let window_open = self.radio_window_open;
        // See `deferred_swarm_events`. Events that were dropped by the previous turn's flush are processed before the fresh events (arrival order).
        let mut deferred = std::mem::take(&mut self.deferred_swarm_events);
        deferred.reverse(); // `pop()` ile FIFO tüketilebilsin
        if let Some(swarm) = &mut self.swarm {
            RUNTIME.block_on(async {
                // See `KeepAliveState` and `KEEPALIVE_FAST_INTERVAL_MS`. For each connection that is due, and not already awaiting a reply, a fresh
                // keepalive request is sent. The next send time depends on the connection's age: fast while not yet stable, extended once stable.
                // `poll_events` runs about once a second, so the timing is accurate to roughly 1 s. No separate timer is needed.
                let now = mono_ms();
                let due: Vec<PeerId> = keepalive_state.iter()
                    .filter(|(_, s)| s.outstanding.is_none() && now >= s.next_due_at && window_open)
                    .map(|(peer, _)| *peer)
                    // The server does not speak this protocol. Every probe was a wasted round trip (on the same Tor circuit that carries the data),
                    // and the warning "Keepalive not supported" appeared every 20 s. Server liveness is already known from each `Fetch` and `Deposit` reply.
                    .filter(|peer| !server_peers.contains(peer))
                    .collect();
                for peer in due {
                    let request_id = swarm.behaviour_mut().keepalive.send_request(&peer, KeepAliveRequest::default());
                    if let Some(state) = keepalive_state.get_mut(&peer) {
                        state.outstanding = Some(request_id);
                    }
                }
                // A bounded drain: a peer that never lets the swarm go idle
                // kept the core lock in this loop. The rest waits in the
                // swarm (or `deferred`) for the next turn, which starts at once.
                let mut budget = MAX_SWARM_EVENTS_PER_TURN;
                loop {
                    if budget == 0 {
                        break;
                    }
                    budget -= 1;
                    let event = match deferred.pop() {
                        Some(e) => e,
                        None => match swarm.next().now_or_never().flatten() {
                            Some(e) => e,
                            None => break,
                        },
                    };
                    match event {
                        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                            // The real listen address. The `node_address` shown on the QR / "my code" screen comes from here
                            // (see `own_listen_addrs` and `get_node_address`).
                            if address.iter().any(|p| matches!(p, MultiaddrProtocol::P2pCircuit)) {
                                info!("Röle rezervasyonu kabul edildi: {}", address);
                            }
                            listen_addr_changes.push((address, true));
                        }
                        libp2p::swarm::SwarmEvent::ExpiredListenAddr { address, .. } => {
                            listen_addr_changes.push((address, false));
                        }
                        // A closed listener (a dropped relay reservation) reports
                        // its addresses here only, not as `ExpiredListenAddr`.
                        libp2p::swarm::SwarmEvent::ListenerClosed { listener_id, addresses, reason } => {
                            closed_listener_ids.push(listener_id);
                            // The loopback listener the onion bridge feeds: listen
                            // again, or the device stayed unreachable inbound
                            // until restart. A port another app
                            // took fails at once here, so this does not loop.
                            for a in addresses.iter().filter(|a| is_loopback_multiaddr(a)) {
                                warn!("Yerel dinleyici kapandı ({:?}), yeniden açılıyor: {}", reason, a);
                                if let Err(e) = swarm.listen_on(a.clone()) {
                                    error!("Yerel dinleyici yeniden açılamadı ({}): {}", a, e);
                                }
                            }
                            listen_addr_changes.extend(addresses.into_iter().map(|a| (a, false)));
                        }
                        libp2p::swarm::SwarmEvent::ListenerError { error, .. } => {
                            warn!("Dinleyici hatası: {}", error);
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            if info.protocols.iter().any(|p| p.as_ref() == KEEPALIVE_QUIET_PROTOCOL) {
                                if let Some(state) = keepalive_state.get_mut(&peer_id) {
                                    state.quiet_capable = true;
                                }
                            }
                            // See `known_relay_peers` and the "Cross-network connectivity" note in SECURITY.md. If this peer speaks the relay
                            // protocol (Circuit Relay v2 HOP) AND reports at least one listen address, it is recorded as a relay candidate for
                            // reaching unreachable peers later. The first address is copied before `listen_addrs` is consumed (the `kad.add_address` loop below moves it).
                            if info.protocols.iter().any(|p| *p == relay::HOP_PROTOCOL_NAME) {
                                // Loopback is meaningless to the other side. If the relay client is already connected to the relay it uses that connection;
                                // the address is only for a re-dial.
                                if let Some(addr) = info.listen_addrs.iter().find(|a| !is_loopback_multiaddr(a)) {
                                    new_relay_peers.push((peer_id, addr.clone().with(MultiaddrProtocol::P2p(peer_id))));
                                }
                            }
                            // See the `is_dialer()` note at ConnectionEstablished: from an INBOUND connection we cannot learn a dialable address. Identify
                            // carries the peer's OWN listen addresses, which is the right source for the reconnect hint. Loopback is skipped (meaningless to
                            // the peer). A LAN address is preferred, otherwise the first dialable one. `.onion` is deliberately NOT taken here, since it has
                            // its own table (`device_onion_addr`, see AddressAnnounce).
                            if let Some(addr) = info.listen_addrs.iter()
                                .find(|a| is_private_lan_multiaddr(a))
                                .or_else(|| info.listen_addrs.iter()
                                    .find(|a| !is_loopback_multiaddr(a) && !is_onion_multiaddr(a)))
                            {
                                new_peer_addrs.push((peer_id, addr.clone().with(MultiaddrProtocol::P2p(peer_id))));
                            }
                            // Add the addresses learned from Identify to Kademlia. This is the address-learning step that Kademlia cannot do alone.
                            // Not loopback: a peer-id-only dial asks Kademlia for addresses, and 127.0.0.1 would reach our own node.
                            // Not the peer's relay reservation (`/dns/relay.onion/../p2p-circuit`): that address carries the RELAY's id, and the device
                            // would then be bound to the relay.
                            if let Some(addr) = info.listen_addrs.iter().find(|a| {
                                is_onion_multiaddr(a) && !a.iter().any(|p| matches!(p, MultiaddrProtocol::P2pCircuit))
                            }) {
                                new_peer_onions.push((peer_id, addr.clone()));
                                // Only that one address goes to Kademlia, and only
                                // when it names no other peer: every claimed address
                                // was stored, and a peer-id dial then opened Tor
                                // circuits to onion targets the peer chose.
                                let other_peer = addr.iter().any(|p| matches!(p, MultiaddrProtocol::P2p(id) if id != peer_id));
                                if !other_peer {
                                    swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                }
                            }
                        }
                        // DHT peers (the server node) pass on the loopback listen addresses
                        // other clients advertised. Dialing 127.0.0.1 only ever reaches
                        // ourselves, so remove them before a dial uses one.
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, addresses, .. })) => {
                            for a in addresses.iter().filter(|a| is_loopback_multiaddr(a)) {
                                swarm.behaviour_mut().kad.remove_address(&peer, a);
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::ServerRpc(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. } } => {
                                    server_events.push(server_client::ServerEventLocal::Request { peer, request, channel });
                                }
                                request_response::Event::Message { peer, message: request_response::Message::Response { request_id, response } } => {
                                    server_rpc_outcomes.push((peer, true));
                                    server_events.push(server_client::ServerEventLocal::Response { request_id, response });
                                }
                                request_response::Event::OutboundFailure { peer, request_id, error } => {
                                    if matches!(error, request_response::OutboundFailure::Timeout) {
                                        server_rpc_outcomes.push((peer, false));
                                    }
                                    warn!("Sunucu isteği başarısız: {:?}", error);
                                    server_events.push(server_client::ServerEventLocal::OutboundFailure { request_id });
                                }
                                request_response::Event::InboundFailure { error, .. } => {
                                    warn!("Sunucuya yanıt gönderilemedi: {:?}", error);
                                }
                                request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Envelopes(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. } } => {
                                    // Answered below, once the rate limit is known.
                                    direct_requests.push((peer, request.bytes, channel));
                                }
                                request_response::Event::Message { message: request_response::Message::Response { request_id, .. }, .. } => {
                                    envelope_events.push(EnvelopeEventLocal::Delivered { request_id });
                                }
                                request_response::Event::OutboundFailure { request_id, error, .. } => {
                                    envelope_events.push(EnvelopeEventLocal::Failed { request_id, error: error.to_string() });
                                }
                                request_response::Event::InboundFailure { .. } | request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Acks(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                                    ack_events.push(AckEventLocal::Request { peer, ids: request.ids, channel });
                                }
                                request_response::Event::Message { message: request_response::Message::Response { request_id, .. }, .. } => {
                                    ack_events.push(AckEventLocal::Delivered { request_id });
                                }
                                request_response::Event::OutboundFailure { request_id, error, .. } => {
                                    warn!("Toplu Ack isteği başarısız, şifreli pakete düşülüyor: {:?}", error);
                                    ack_events.push(AckEventLocal::Failed { request_id });
                                }
                                request_response::Event::InboundFailure { .. } | request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::FileChunks(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                                    file_chunk_events.push(FileChunkEventLocal::Request { peer, request, channel });
                                }
                                request_response::Event::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                                    file_chunk_events.push(FileChunkEventLocal::Response { request_id, response });
                                }
                                request_response::Event::OutboundFailure { request_id, error, .. } => {
                                    error!("Dosya parça isteği başarısız: {:?}", error);
                                    file_chunk_events.push(FileChunkEventLocal::OutboundFailure { request_id });
                                }
                                request_response::Event::InboundFailure { error, .. } => {
                                    error!("Dosya parça yanıtı gönderilemedi: {:?}", error);
                                }
                                request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        // Diagnostics: `dial()` itself reports only synchronous or immediate errors (see `process_qr_packet`). The real connection attempt
                        // runs asynchronously, and its success or failure shows up here as `ConnectionEstablished` or `OutgoingConnectionError`. Without
                        // logging these, it is impossible to tell why a handshake never completes. Search `adb logcat` for these lines.
                        libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, endpoint, connection_id, num_established, .. } => {
                            info!("libp2p bağlantısı kuruldu: peer={} adres={:?} giden_mi={} bağlantı_sayısı={}", crate::log_id(&peer_id), endpoint.get_remote_address(), endpoint.is_dialer(), num_established);
                            established_conns.push((peer_id, connection_id));
                            new_conn_ranks.push((connection_id, conn_path_rank(endpoint.get_remote_address())));
                            if !endpoint.is_dialer() {
                                new_inbound.push((connection_id, peer_id));
                            }
                            // There must be an `is_dialer()` check here. Without it, a connection from a peer that dialed us could record the wrong
                            // address, which permanently broke reconnection between two devices on the same LAN.
                            //
                            // `get_remote_address()` on an OUTGOING connection gives the address we dialed (dialable and correct). On an INCOMING
                            // connection it gives `send_back_addr`, which is the EPHEMERAL SOURCE PORT the peer used for that TCP session. Nothing
                            // listens on that port, and it disappears when the session ends.
                            //
                            // That address was then stored in `peer_id_to_addr`, and from there `record_peer_id_if_known` wrote it to the
                            // `device_addrs` table as a PERSISTENT reconnect hint. Observed result: A stored `/ip4/192.168.1.103/tcp/55230` for B,
                            // while B listened on 42611. After B restarted, A could never reach it over the LAN, and all traffic fell back to Tor or the server.
                            //
                            // For incoming connections, the peer's real listen address is learned from Identify instead (see the Identify arm below).
                            if endpoint.is_dialer() {
                                new_peer_addrs.push((peer_id, endpoint.get_remote_address().clone()));
                            }
                            // First connection only. An extra one (bulk circuit,
                            // suspect replacement) is not "the peer came back", and
                            // each of them restarted every retry and every failed
                            // download from this peer.
                            if num_established.get() == 1 {
                                connections_established.push(peer_id);
                            }
                            // Every connection after the first is "extra". When the transfer ends, exactly these are closed (see `extra_conns`). Only
                            // connections WE opened count. Extra inbound connections were opened by the other side for its own download. Before this,
                            // the sending side treated them as "no transfer of mine" and closed them during the transfer, so chunk requests failed
                            // with ConnectionClosed.
                            if num_established.get() > 1 && endpoint.is_dialer() {
                                new_extra_conns.push((peer_id, connection_id));
                            }
                            // See `KeepAliveState`. A fresh connection is not yet stable, so it starts on the fast interval (`KEEPALIVE_FAST_INTERVAL_MS`).
                            // `entry().or_insert_with()`: a SECOND connection to the same peer (mDNS direct, Tor and relay can all come up together, see
                            // `dial_with_relay_fallback`) must not reset the existing keepalive history or the stabilisation clock. The peer is already tracked.
                            keepalive_state.entry(peer_id).or_insert_with(|| KeepAliveState {
                                connected_since: mono_ms(),
                                next_due_at: mono_ms() + KEEPALIVE_FAST_INTERVAL_MS,
                                consecutive_failures: 0,
                                outstanding: None,
                                suspect: false,
                                interval_ms: 0,
                                quiet_capable: false,
                            });
                        }
                        libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, connection_id } => {
                            error!("Dial başarısız: peer={:?} hata={}", peer_id.as_ref().map(|p| crate::log_id(p)), error);
                            failed_dials.push(connection_id);
                        }
                        libp2p::swarm::SwarmEvent::IncomingConnectionError { error, send_back_addr, .. } => {
                            error!("Gelen bağlantı başarısız: adres={} hata={}", send_back_addr, error);
                        }
                        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, num_established, connection_id, .. } => {
                            info!("libp2p bağlantısı kapandı: peer={} sebep={:?} kalan_bağlantı={}", crate::log_id(&peer_id), cause, num_established);
                            closed_conns.push((peer_id, connection_id));
                            // See `connections_lost`. Before, this event only logged.
                            //
                            // Multiple connections: this event fires for EVERY connection that closes. Several connections to one peer are
                            // common (mDNS direct, Tor and relay). Before, closing ONE of them removed the keepalive state while the peer was still connected.
                            // A new `ConnectionEstablished` never came for the rest, so the entry was never re-created, and the code redialed for nothing.
                            // A peer counts as truly "lost" only when its LAST connection closes (`num_established == 0`).
                            if num_established == 0 {
                                connections_lost.push(peer_id);
                            }
                        }
                        // Keepalive failures are handled here (see `P2PBehaviour.keepalive`, `KeepAliveState` and `KEEPALIVE_FAILURES_BEFORE_DISCONNECT`).
                        // A timeout or I/O failure suggests a half-open connection, but one missed packet or a momentary delay gives the same result, so it is
                        // not proof on its own. The connection is closed explicitly only after `KEEPALIVE_FAILURES_BEFORE_DISCONNECT` (3) consecutive failures.
                        // That fixes `is_connected()` (and therefore the UI's "Connected" indicator), and it fires the `ConnectionClosed` arm above, which starts
                        // an immediate reconnect. A successful keepalive resets the counter, and if the connection is old enough it widens the send interval.
                        // The consecutive-failure rule is kept this way.
                        //
                        // `UnsupportedProtocols` is a DIFFERENT category. It occurs only when the peer does not know this protocol at all (an older version
                        // without this keepalive). It is not a sign of a half-open connection. This is the same reasoning as the old `ping::Failure::Unsupported`
                        // arm. Forcing a close here caused needless disconnect and reconnect loops on healthy connections. So it is only logged. It does not
                        // count toward the failure counter, and the connection is NOT closed.
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Keepalive(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. } => {
                                    if request.bye {
                                        bye_peers.push(peer);
                                    }
                                    let capable = keepalive_state.get(&peer).is_some_and(|s| s.quiet_capable);
                                    let quiet_ms = (saver && capable).then_some(window_ms);
                                    if swarm.behaviour_mut().keepalive.send_response(channel, KeepAliveResponse { quiet_ms }).is_err() {
                                        debug!("Keepalive answer to {} not sent (channel closed)", peer);
                                    }
                                    if let Some(state) = keepalive_state.get_mut(&peer) {
                                        if !saver && state.outstanding.is_none() && !state.suspect && state.interval_ms > 0 {
                                            state.consecutive_failures = 0;
                                            state.next_due_at = mono_ms() + state.interval_ms;
                                        }
                                    }
                                }
                                request_response::Event::Message { peer, message: request_response::Message::Response { response, .. }, .. } => {
                                    if let Some(state) = keepalive_state.get_mut(&peer) {
                                        state.consecutive_failures = 0;
                                        state.outstanding = None;
                                        state.suspect = false;
                                        let now = mono_ms();
                                        let stabilized = now.saturating_sub(state.connected_since) >= KEEPALIVE_STABILIZE_MS;
                                        // See `power_save` and `KEEPALIVE_POWER_SAVE_INTERVAL_MS`. With the screen off, a proven connection is probed every 60 s,
                                        // which leaves the radio long sleep windows. Radio saver: go straight to the window, with no 2 s "stabilising" probes
                                        // (each one is a radio wake on LTE).
                                        let interval = if saver {
                                            window_ms
                                        } else if !stabilized {
                                            KEEPALIVE_FAST_INTERVAL_MS
                                        } else if power_save {
                                            KEEPALIVE_POWER_SAVE_INTERVAL_MS
                                        } else {
                                            KEEPALIVE_IDLE_INTERVAL_MS
                                        };
                                        // The peer is saving radio: honour it.
                                        // `quiet_ms` is peer-supplied: an honest peer never asks for
                                        // more than `RADIO_WINDOW_MS`. Unclamped, a huge value turned
                                        // keepalive off, and `u64::MAX` wrapped `next_due_at`.
                                        let interval = interval.max(response.quiet_ms.unwrap_or(0).min(RADIO_WINDOW_MS));
                                        // Saver: the window is open for one poll turn. A due
                                        // time of "answer + window" is just after the next
                                        // window, so the peer was probed every second one.
                                        let wait = if saver { interval.saturating_sub(RADIO_AWAKE_MS) } else { interval };
                                        state.next_due_at = now.saturating_add(wait);
                                        state.interval_ms = interval;
                                    }
                                }
                                request_response::Event::OutboundFailure { peer, error, .. } => {
                                    if matches!(error, request_response::OutboundFailure::UnsupportedProtocols) {
                                        warn!("Keepalive desteklenmiyor (bağlantı sağlıklı kabul ediliyor, kapatılMIYOR): peer={}", crate::log_id(&peer));
                                        if let Some(state) = keepalive_state.get_mut(&peer) {
                                            state.outstanding = None;
                                            // Hourly, not never: a peer that upgrades
                                            // within this session is probed again.
                                            state.next_due_at = mono_ms().saturating_add(60 * 60_000);
                                        }
                                    } else if matches!(error, request_response::OutboundFailure::ConnectionClosed)
                                        && swarm.is_connected(&peer)
                                    {
                                        // The probe rode a connection we had just closed (a surplus or a suspect's replacement) while another
                                        // is up. Counting it as a failure made `disconnect_peer_id` kill the fresh connection too. Probe again on the live one.
                                        if let Some(state) = keepalive_state.get_mut(&peer) {
                                            state.outstanding = None;
                                            state.next_due_at = mono_ms() + KEEPALIVE_FAST_INTERVAL_MS;
                                        }
                                    } else if let Some(state) = keepalive_state.get_mut(&peer) {
                                        state.outstanding = None;
                                        state.consecutive_failures += 1;
                                        let limit = if state.suspect { 1 } else { KEEPALIVE_FAILURES_BEFORE_DISCONNECT };
                                        if state.consecutive_failures >= limit {
                                            warn!(
                                                "Keepalive {} kez ardışık başarısız (bağlantı yarı açık kabul ediliyor), kapatılıp yeniden bağlanılacak: peer={} hata={}",
                                                state.consecutive_failures, crate::log_id(&peer), error
                                            );
                                            keepalive_state.remove(&peer);
                                            let _ = swarm.disconnect_peer_id(peer);
                                        } else {
                                            warn!(
                                                "Keepalive başarısız (deneme {}/{}), kısa süre sonra tekrar denenecek: peer={} hata={}",
                                                state.consecutive_failures, KEEPALIVE_FAILURES_BEFORE_DISCONNECT, crate::log_id(&peer), error
                                            );
                                            // Retry right after a failed attempt. Waiting the full `KEEPALIVE_FAST_INTERVAL_MS` or `KEEPALIVE_IDLE_INTERVAL_MS`
                                            // would slow down the consecutive-failure detection for no reason.
                                            state.next_due_at = mono_ms() + KEEPALIVE_FAST_INTERVAL_MS;
                                        }
                                    }
                                }
                                request_response::Event::InboundFailure { peer, error, .. } => {
                                    warn!("Keepalive yanıtı gönderilemedi: peer={} hata={}", crate::log_id(&peer), error);
                                }
                                request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
        // Left over past the budget: first in line next turn.
        deferred.reverse();
        deferred.append(&mut self.deferred_swarm_events);
        self.deferred_swarm_events = deferred;
        // See `keepalive_state`. The local copy worked on during the loop is put back here.
        self.keepalive_state = keepalive_state;
        // The peer said it is going offline: no dials to it until it connects
        // again (cleared in the `connections_established` block below). The
        // source PeerId is noise-authenticated, so a device parks only itself.
        for peer in bye_peers {
            let fps: Vec<String> = self.device_to_peer_id.iter()
                .filter(|(_, p)| **p == peer)
                .map(|(fp, _)| fp.clone())
                .collect();
            for fp in fps {
                info!("Device {} is going offline: not dialed until it connects", crate::log_id(&peer));
                self.meta_put(&format!("parked:{}", fp), "1");
                self.reconnect_backoff.remove(&fp);
            }
        }
        // Second+ outbound connections that are not bulk-transfer dials: reconnect
        // races (onion + LAN + relay at once) or a suspect's parallel dial.
        let mut surplus_dials: std::collections::HashSet<libp2p::swarm::ConnectionId> = std::collections::HashSet::new();
        for (peer, cid) in new_extra_conns {
            if self.bulk_dials.remove(&cid).is_some() {
                self.extra_conns.entry(peer).or_default().push(cid);
            } else {
                surplus_dials.insert(cid);
            }
        }
        for (peer, cid) in &established_conns {
            self.peer_conns.entry(*peer).or_default().push(*cid);
            // A bulk dial that landed as the peer's only connection.
            self.bulk_dials.remove(cid);
        }
        // A failed bulk dial stayed in `bulk_dials` and did not back off: one
        // new Tor dial every `BULK_DIAL_MIN_INTERVAL_MS` for the whole transfer.
        for cid in failed_dials {
            if let Some(peer) = self.bulk_dials.remove(&cid) {
                let h = self.bulk_health.entry(peer).or_default();
                h.backoff_ms = (h.backoff_ms * 2).clamp(BULK_DIAL_MIN_INTERVAL_MS * 2, BULK_DIAL_MAX_BACKOFF_MS);
                h.next_dial_at = mono_ms() + h.backoff_ms;
            }
        }
        self.conn_rank.extend(new_conn_ranks);
        let inbound_at = mono_ms();
        self.unknown_inbound.extend(new_inbound.into_iter().map(|(cid, peer)| (cid, (peer, inbound_at))));
        for (peer, answered) in server_rpc_outcomes {
            if answered {
                self.server_rpc_timeouts.remove(&peer);
                continue;
            }
            let n = self.server_rpc_timeouts.entry(peer).or_insert(0);
            *n += 1;
            if *n >= SERVER_RPC_TIMEOUTS_BEFORE_DISCONNECT {
                warn!("Sunucu {} istekte üst üste yanıt vermedi, bağlantı ölü sayılıp yeniden kuruluyor: {}", n, crate::log_id(&peer));
                self.server_rpc_timeouts.remove(&peer);
                if let Some(swarm) = &mut self.swarm {
                    let _ = swarm.disconnect_peer_id(peer);
                }
            }
        }
        for (peer, cid) in &closed_conns {
            self.conn_rank.remove(cid);
            if let Some(v) = self.peer_conns.get_mut(peer) {
                v.retain(|c| c != cid);
                if v.is_empty() {
                    self.peer_conns.remove(peer);
                }
            }
        }
        // See `mark_connection_suspect`. A new connection to a suspect peer arrived, so the old ones are probably dead. Close them, since gossipsub
        // keeps using the first connection.
        for (peer, cid) in &established_conns {
            let suspect = self.keepalive_state.get(peer).map_or(false, |s| s.suspect);
            let others: Vec<libp2p::swarm::ConnectionId> = self.peer_conns.get(peer)
                .map(|v| v.iter().copied().filter(|c| c != cid).collect())
                .unwrap_or_default();
            if surplus_dials.contains(cid) && !suspect && !others.is_empty() {
                // The existing connection is not in doubt, so one of them goes. Keep the better path. Before this, the new one was always closed: an
                // early relay circuit through the server beat the direct onion connection that came up seconds later, and all traffic took the extra
                // hop and the circuit's limits.
                let rank = |c: &libp2p::swarm::ConnectionId| self.conn_rank.get(c).copied().unwrap_or(0);
                let new_rank = rank(cid);
                let bulk: Vec<libp2p::swarm::ConnectionId> = self.extra_conns.get(peer).cloned().unwrap_or_default();
                let worse: Vec<libp2p::swarm::ConnectionId> = others.iter().copied()
                    .filter(|c| rank(c) < new_rank && !bulk.contains(c))
                    .collect();
                let best_other = others.iter().map(|c| rank(c)).max().unwrap_or(0);
                if let Some(swarm) = &mut self.swarm {
                    if new_rank > best_other {
                        info!("Daha iyi yol kuruldu (seviye {} > {}), {} eski bağlantı kapatılıyor: peer={}", new_rank, best_other, worse.len(), crate::log_id(&peer));
                        for c in &worse {
                            swarm.close_connection(*c);
                        }
                    } else {
                        swarm.close_connection(*cid);
                    }
                }
                continue;
            }
            if suspect && !others.is_empty() {
                info!("Şüpheli bağlantının yerine yenisi kuruldu, {} eski bağlantı kapatılıyor: peer={}", others.len(), crate::log_id(&peer));
                if let Some(swarm) = &mut self.swarm {
                    for c in &others {
                        swarm.close_connection(*c);
                    }
                }
                // The survivor is the peer's only link now, not an "extra" one
                // for `manage_bulk_connections` to close after the transfer.
                self.extra_conns.remove(peer);
                if let Some(st) = self.keepalive_state.get_mut(peer) {
                    st.suspect = false;
                    st.outstanding = None;
                    st.consecutive_failures = 0;
                    st.next_due_at = mono_ms() + KEEPALIVE_FAST_INTERVAL_MS;
                }
            }
        }
        for (peer, cid) in closed_conns {
            if let Some(v) = self.extra_conns.get_mut(&peer) {
                v.retain(|c| *c != cid);
                if v.is_empty() {
                    self.extra_conns.remove(&peer);
                }
            }
        }
        // Direct envelopes: same path as a gossipsub message, with the
        // Noise-proven sender. A packet the rate limit is about to drop gets
        // no answer: the "delivered" reply made the sender skip its early
        // server deposit for a packet nobody processed.
        for (peer, bytes, channel) in direct_requests {
            if self.rate_would_drop(peer) {
                continue;
            }
            incoming.push((Some(peer), bytes));
            // Not while the keys are not loaded: the packet
            // waits, and "delivered" made the sender skip its early server copy.
            if !self.storage_keys_ready() {
                continue;
            }
            if let Some(swarm) = &mut self.swarm {
                let _ = swarm.behaviour_mut().envelopes.send_response(channel, EnvelopeResponse);
            }
        }
        // An expired address goes (a dropped relay reservation) and none is
        // listed twice: the list only grew.
        // a dead relay's listener id no longer blocks a new
        // reservation for `RELAY_RESERVATION_RETRY_MS`.
        if !closed_listener_ids.is_empty() {
            self.relay_listeners.retain(|_, (lid, _)| !closed_listener_ids.contains(lid));
        }
        for (addr, up) in listen_addr_changes {
            self.own_listen_addrs.retain(|a| *a != addr);
            if up {
                self.own_listen_addrs.push(addr);
            }
        }
        // A device added from the other side's IdentityExchange (not from a code) had no onion address. It could reach the peer only through a relay,
        // which first needs its own Tor connection to the server: about 40 s after mobile data came back. Peers now announce their onion address
        // over identify (see `advertised_onion`).
        for (pid, addr) in new_peer_onions {
            // An address that names another peer is not this peer's onion.
            let addr = match extract_peer_id(&addr) {
                Some(p) if p != pid => continue,
                Some(_) => addr,
                None => addr.with(MultiaddrProtocol::P2p(pid)),
            };
            let addr_str = addr.to_string();
            let fps: Vec<String> = self.device_to_peer_id.iter().filter(|(_, p)| **p == pid).map(|(fp, _)| fp.clone()).collect();
            for fp in fps {
                self.remember_onion_addr(&fp, &addr_str);
            }
            self.peer_onion_addr.insert(pid, addr_str);
        }
        if let Some(host) = self.tor.as_ref().and_then(|t| t.onion_host()) {
            let own = format!("/dns/{}/tcp/{}", host, TOR_LIBP2P_PORT);
            if self.advertised_onion.as_deref() != Some(own.as_str()) {
                if let (Ok(addr), Some(swarm)) = (own.parse::<Multiaddr>(), self.swarm.as_mut()) {
                    swarm.add_external_address(addr);
                    self.advertised_onion = Some(own);
                }
            }
        }
        for (pid, addr) in new_peer_addrs {
            if is_loopback_multiaddr(&addr) {
                continue;
            }
            // a peer-supplied clearnet address (identify) no longer
            // replaces the onion address we dialed — the node is onion-only.
            if !is_onion_multiaddr(&addr) && self.peer_id_to_addr.get(&pid).map_or(false, |a| is_onion_multiaddr(a)) {
                continue;
            }
            // Strangers' entries were never removed: past the cap only
            // devices and servers we know are kept.
            if self.peer_id_to_addr.len() >= 4096 && !self.peer_id_to_addr.contains_key(&pid) {
                let known: std::collections::HashSet<PeerId> = self.device_to_peer_id.values().copied().collect();
                let servers: Vec<PeerId> = self.peer_id_to_addr.keys().copied().filter(|p| self.is_server_peer(p)).collect();
                self.peer_id_to_addr.retain(|p, _| known.contains(p) || servers.contains(p));
            }
            self.peer_id_to_addr.insert(pid, addr);
        }
        for (pid, addr) in new_relay_peers {
            // Addresses reported by Identify are from the peer's OWN point of view. A server's LAN address is unreachable from mobile data, and its
            // public IP cannot be reached from the same LAN (hairpin NAT). Both were measured on a device. If the relay is a server we configured, the
            // onion address works from every network. If we are already connected to the relay, libp2p uses that connection, and the address is
            // translated only when we are not connected.
            // Only our servers and proven contact devices. Any stranger that connected and listed HOP would become a relay. Every reconnect target would
            // then be dialled through it (it would see whom we reach, and when), and ten such strangers would push the real server off the list.
            // A contact's device is not included either: it supplied the address itself, and it got a circuit request naming the target each time we
            // reconnected to anybody else. Our own other devices may relay.
            let my_id = self.my_identity_id();
            let own_device = my_id.is_some() && self.device_to_peer_id.iter().any(|(fp, p)| {
                *p == pid && self.known_remote_devices.get(fp).map(|d| &d.identity_id) == my_id.as_ref()
            });
            if !self.is_server_peer(&pid) && !own_device {
                continue;
            }
            let addr = self.server_onion_addr(&pid).unwrap_or(addr);
            self.record_known_relay(pid, addr);
        }
        // See `connections_lost`. For each lost connection, the matching device fingerprint is found (by inverting `device_to_peer_id`), and a reconnect is
        // tried AT ONCE. It is still subject to `reconnect_backoff` (see `try_reconnect_device`), so a connection that drops repeatedly does not cause a dial
        // storm. Only the first drop is retried right away, without waiting for the periodic scan. Only known and ACTIVE devices count (the same filter as
        // `reconnect_sweep`). A peer that has not finished IdentityExchange yet is ignored here. It has its own retry path through `pending_envelopes` and
        // `send_identity_exchange`.
        // If a connection closed and was re-established within one batch (the process was frozen, then the peer redialled), the peer is connected and nothing
        // was lost.
        connections_lost.retain(|p| !self.swarm.as_ref().is_some_and(|s| s.is_connected(p)));
        if !connections_lost.is_empty() {
            // See `keepalive_state`. When the connection is fully closed (the `ConnectionClosed` arm that feeds this Vec), its state is removed too. The next
            // connection starts with a fresh `KeepAliveState` at `ConnectionEstablished`.
            for peer_id in &connections_lost {
                self.keepalive_state.remove(peer_id);
                // Timeouts of the old link must not count against the next one.
                self.server_rpc_timeouts.remove(peer_id);
                // Learned again from identify on the next connection; the
                // device's own copy is in `device_onion_addr`.
                self.peer_onion_addr.remove(peer_id);
            }
            let fps: Vec<String> = self.device_to_peer_id.iter()
                .filter(|(_, pid)| connections_lost.contains(pid))
                .map(|(fp, _)| fp.clone())
                .collect();
            // Radio saver: redial in the next window, not now — on mobile
            // data every onion dial is a burst of circuit builds.
            let redial_now = self.radio_window_open;
            for fp in fps.into_iter().filter(|_| redial_now) {
                match self.known_remote_devices.get(&fp) {
                    Some(rec) if rec.is_active => {
                        self.try_reconnect_device(&fp, false);
                    }
                    _ => {}
                }
            }
        }

        // See `connections_established` (above). For every newly established or re-established connection, when a ratchet session already exists, the gossipsub
        // subscription is triggered again (idempotent, a no-op if already subscribed). This is a safety net against Tor circuit drops silently breaking the mesh.
        if !connections_established.is_empty() {
            // Observed on a phone (Note 9S, mobile data): the only
            // other way to fill `device_to_peer_id` is a packet received over
            // gossipsub. After a fresh pairing over a slow network (Tor/relay),
            // the IdentityExchange and Handshake were deposited to the server
            // before any connection existed. Their gossipsub copies found no
            // peers and were never retried. The relay connection that came up
            // seconds later was then never tied to the contact:
            // `is_connected_to_device` stayed false, the chat showed "Offline",
            // and every message and Ack went via the server even with a live
            // connection. The peer id at the end of the pairing address is the
            // device's own libp2p id (QR/manual code, trusted like the rest of
            // the code). Noise has just proven the connection is that id, so
            // tie them together. A mapping learned from a verified packet is
            // never overwritten.
            let learned: HashMap<String, PeerId> = self.device_last_addr.iter()
                .chain(self.device_onion_addr.iter())
                .filter(|(fp, _)| !self.device_to_peer_id.contains_key(*fp))
                .filter_map(|(fp, addr)| {
                    // The LAST /p2p is the device (a circuit address starts with the relay's).
                    let pid = addr.parse::<Multiaddr>().ok()?.iter()
                        .filter_map(|p| match p { MultiaddrProtocol::P2p(pid) => Some(pid), _ => None })
                        .last()?;
                    connections_established.contains(&pid).then(|| (fp.clone(), pid))
                })
                .collect();
            for (fp, pid) in learned {
                info!("Bağlantı eşleşme adresinden cihaza bağlandı: {} -> {}", &fp[..fp.len().min(8)], crate::log_id(&pid));
                if let Some(onion) = self.peer_onion_addr.get(&pid).cloned() {
                    self.remember_onion_addr(&fp, &onion);
                }
                self.device_to_peer_id.insert(fp, pid);
            }
            let fps: Vec<String> = self.device_to_peer_id.iter()
                .filter(|(_, pid)| connections_established.contains(pid))
                .map(|(fp, _)| fp.clone())
                .collect();
            // A parked device that connects is online again.
            for fp in &fps {
                self.meta_del(&format!("parked:{}", fp));
            }
            // Refresh the subscription FIRST, THEN drain the queue. The order matters: this loop repairs the gossipsub subscription that Tor circuit drops
            // silently broke. If the pending messages were triggered first, the most valuable first attempt would go out to a broken mesh.

            // Reset the retry backoff for this device. Before, nothing reset the backoff when a connection came up. The queue grows exponentially up to
            // `ACK_RETRY_MAX_MS` (120 s), so a sibling device that had been offline stayed in the queue for minutes even though it was connected.
            // A connection being up is the strongest signal for "try now". The interval is also reset to the initial value, since the mesh may still not
            // be ready. If the first attempt fails, the next should come after 15 s, not 120 s.
            let reconnected: std::collections::HashSet<String> = fps.into_iter().collect();
            let now = current_time_ms();
            for pending in self.awaiting_confirmation.values_mut() {
                // at most once per `ACK_RETRY_INITIAL_MS`: a peer that
                // reconnects in a loop got the whole queue on every turn.
                if reconnected.contains(&pending.peer_device_fingerprint)
                    && now.saturating_sub(pending.last_attempt_at) >= ACK_RETRY_INITIAL_MS
                {
                    pending.next_retry_at = 0; // due, and not held (see `hold_retries`)
                    pending.retry_interval_ms = ACK_RETRY_INITIAL_MS;
                }
            }
            // queued envelopes for it are due now too (the 1 s flush
            // gate still applies).
            for queued in self.pending_envelopes.iter_mut() {
                if reconnected.contains(&queued.target) {
                    queued.next_at = 0;
                }
            }
            // Delivery guarantee (see `maybe_redo_handshake`): the peer is BACK, but for a long time none of our packets was acknowledged. We assume the session
            // was never set up on its side, and refresh the handshake. This is the fastest recovery for "the first message written while it was offline". The
            // refresh happens as soon as the peer is online, and does not wait for the 25-minute refresh pass. The function checks both "is there an unconfirmed
            // packet" and the `HANDSHAKE_REDO_MIN_INTERVAL_MS` limit, so it is a no-op on a healthy reconnect.
            for fp in &reconnected {
                self.maybe_redo_handshake(fp);
            }
            // Like the unconfirmed messages, half-finished or failed file downloads from a source that came back are resumed at once. See
            // `resume_incomplete_downloads_for`.
            self.resume_incomplete_downloads_for(&reconnected, false);
            // Self-repair (see `SIBLING_ROSTER_SYNC_INTERVAL_MS`): if the peer that connected is one of my sibling devices, the device list is sent again. If a
            // sibling missed the announcement, the two would never reach each other, because neither recognises the other.
            let sibling_reconnected = self
                .sibling_active_devices()
                .into_iter()
                .any(|fp| reconnected.contains(&fp));
            if sibling_reconnected
                && now.saturating_sub(self.last_sibling_roster_sync_at) >= SIBLING_ROSTER_SYNC_INTERVAL_MS
            {
                self.last_sibling_roster_sync_at = now;
                // The siblings that are connected, not all: see `request_sibling_backfill`.
                let connected: Vec<String> = self.sibling_active_devices().into_iter()
                    .filter(|fp| self.is_connected_to_device(fp)).collect();
                self.sync_roster_to(connected);
            }

            // Observed on a phone: "QR scanned, nothing happened on either device". The connection was eventually made, but the link still did not complete.
            // For a pending link target (`pending_link_target`), the `IdentityExchange` is sent during QR scanning in `approve_device_link`. At that moment
            // there is no connection yet, so it goes into `pending_envelopes`, and its `PENDING_ENVELOPE_TIMEOUT_MS` (20 s) starts counting from the scan. The
            // first dial over Tor can take 10-17 s, and it can time out and be retried. So the envelope expired just as the gossip mesh was forming, and was
            // dropped. No path sent it again, and the link stayed incomplete forever.
            //
            // The loop above cannot see this target: `device_to_peer_id` is filled only when a VERIFIED packet arrives from the device (see
            // `record_peer_id_if_known`), which is exactly what has not happened yet. So the PeerId is resolved here by comparing against the address saved
            // at pairing (`device_last_addr` / `device_onion_addr`). The connection has just been made, so the envelope is sent again. Even if the mesh is
            // not ready yet, this starts the 20 s window at CONNECTION time, not scan time. That is the critical point.
            if let Some(fp) = self.pending_link_target.clone() {
                let link_peer_id = self.device_last_addr.get(&fp)
                    .or_else(|| self.device_onion_addr.get(&fp))
                    .and_then(|a| a.parse::<Multiaddr>().ok())
                    .and_then(|a| extract_peer_id(&a));
                if link_peer_id.map(|p| connections_established.contains(&p)).unwrap_or(false) {
                    if let Err(e) = self.send_identity_exchange(&fp) {
                        error!("Bağlanma IdentityExchange'i (bağlantı kurulduğunda) gönderilemedi, yeniden denenecek: {}", e);
                    }
                }
            }
        }

        // File chunk events. They were collected outside `self.swarm` (see above), so this block can use `&mut self` (state updates) and
        // `self.swarm` (to send replies) separately, one after the other.
        let mut pending_chunk_responses: Vec<(request_response::ResponseChannel<FileChunkResponse>, FileChunkResponse)> = Vec::new();
        for evt in file_chunk_events {
            match evt {
                FileChunkEventLocal::Request { peer, request, channel } => {
                    // Own counter, so a download does not use up the message
                    // budget. 600 chunks per window is 15 MB/s, above any
                    // real transfer; past it the file is refused.
                    let now = mono_ms();
                    let rate = self.chunk_rate_limiter.entry(peer).or_insert((now, 0));
                    if now.saturating_sub(rate.0) > RATE_LIMIT_WINDOW_MS {
                        *rate = (now, 0);
                    }
                    rate.1 += 1;
                    // Over the limit: no answer (the channel is dropped).
                    // The requester sees an `OutboundFailure` and retries;
                    // `NotFound` made it fail the whole download.
                    if rate.1 > RATE_LIMIT_MAX_ESTABLISHED {
                        drop(channel);
                        continue;
                    }
                    let response = self.serve_chunk_request(peer, &request);
                    pending_chunk_responses.push((channel, response));
                }
                FileChunkEventLocal::Response { request_id, response } => {
                    if let Some((file_id, chunk_index)) = self.download_request_ids.remove(&request_id) {
                        self.handle_chunk_response(&file_id, chunk_index, response);
                    }
                }
                FileChunkEventLocal::OutboundFailure { request_id } => {
                    // Before, a single network error (for example a brief Tor circuit drop) failed the download at once. Now the same chunk is retried for up to
                    // `DOWNLOAD_GIVE_UP_TIMEOUT_MS` (10 min).
                    if let Some((file_id, chunk_index)) = self.download_request_ids.remove(&request_id) {
                        // Drop it from the in-flight set. `retry_or_give_up_download` refills the window.
                        if let Some(s) = self.active_downloads.get_mut(&file_id) {
                            s.inflight_chunks.remove(&chunk_index);
                            s.chunk_sent_at.remove(&chunk_index);
                            // Timeout or error means the path is overloaded or dropped: halve the window (see `DOWNLOAD_WINDOW_MIN`).
                            s.window = (s.window / 2).max(DOWNLOAD_WINDOW_MIN);
                            // A source that is gone is asked again ten times
                            // slower: every request to it fails at once, and
                            // at the normal delay that was a dial every 3 s
                            // for the 10 minutes before giving up. Waiting for
                            // `retry_at` does not hold the wake lock (`downloads_busy`).
                            let connected = self.swarm.as_ref().map_or(false, |sw| sw.is_connected(&s.peer_id));
                            s.retry_at = current_time_ms() + if connected { DOWNLOAD_RETRY_DELAY_MS } else { 10 * DOWNLOAD_RETRY_DELAY_MS };
                        }
                        // A dead parallel circuit may be the cause. Do not decide on a single event. Count it (see `note_bulk_timeout`).
                        if let Some(p) = self.active_downloads.get(&file_id).map(|s| s.peer_id) {
                            self.note_bulk_timeout(p);
                        }
                        // Only this one request failed: not `retry_or_give_up_download`,
                        // which threw away every other request in flight (their
                        // answers then matched no id) and counted toward a source
                        // switch. The index is asked for again by the next chunk
                        // answer, or after `DOWNLOAD_RETRY_DELAY_MS` (`retry_at`).
                    }
                }
            }
        }
        if !pending_chunk_responses.is_empty() {
            if let Some(swarm) = &mut self.swarm {
                for (channel, response) in pending_chunk_responses {
                    let _ = swarm.behaviour_mut().file_chunks.send_response(channel, response);
                }
            }
        }

        for evt in envelope_events {
            match evt {
                EnvelopeEventLocal::Delivered { request_id } => {
                    let Some((fp, envelope, _, _)) = self.envelopes_inflight.remove(&request_id) else { continue };
                    if let NetworkEnvelope::Message(m) = &envelope {
                        if let Some(p) = self.awaiting_confirmation.get_mut(&m.header.message_id) {
                            p.direct_delivered = true;
                        }
                    }
                    // A delivered request proves the connection like a keepalive answer does.
                    if let Some(st) = self.device_to_peer_id.get(&fp).and_then(|pid| self.keepalive_state.get_mut(pid)) {
                        st.suspect = false;
                        st.consecutive_failures = 0;
                    }
                }
                EnvelopeEventLocal::Failed { request_id, error } => {
                    let Some((fp, envelope, first_attempt_at, retried)) = self.envelopes_inflight.remove(&request_id) else { continue };
                    // The request rode a connection that just closed (surplus/suspect
                    // replacement) while another one is still up: resend there once.
                    if !retried && self.is_connected_to_device(&fp) {
                        if let Ok(bytes) = ciborium_bytes(&envelope) {
                            if self.send_envelope_direct(&fp, &envelope, bytes, first_attempt_at, true) {
                                continue;
                            }
                        }
                    }
                    warn!("Doğrudan zarf gönderimi başarısız ({}), gossipsub/sunucuya düşülüyor: {}", error, &fp[..fp.len().min(8)]);
                    match self.try_publish_raw_via(&fp, &envelope, first_attempt_at, false) {
                        Err(PublishFailure::Transient(_)) => {
                            // Tracked messages are resent by `retry_unconfirmed_messages`;
                            // queue the rest like `publish_envelope_at` does.
                            let tracked = matches!(&envelope, NetworkEnvelope::Message(m) if self.awaiting_confirmation.contains_key(&m.header.message_id));
                            if !tracked {
                                self.enqueue_pending(QueuedEnvelope::new(fp, envelope, first_attempt_at));
                            }
                        }
                        // Like `publish_with_ack_tracking`: no retry can work.
                        Err(PublishFailure::Permanent(e)) => {
                            error!("Envelope failed permanently after the direct path: {}", e);
                            if let NetworkEnvelope::Message(m) = &envelope {
                                let id = m.header.message_id.clone();
                                self.awaiting_confirmation.remove(&id);
                                self.remove_durable_retry(&id);
                                self.set_message_status(&id, MessageSendStatus::Failed);
                                self.attachment_events.push(serde_json::json!({
                                    "type": "status", "peer": self.canonical_peer_key(&fp), "message_id": id, "status": "error"
                                }).to_string());
                            }
                        }
                        Ok(()) => {}
                    }
                }
            }
        }
        // see `ACK_PROTOCOL`.
        let mut ack_replies: Vec<request_response::ResponseChannel<AckBatchResponse>> = Vec::new();
        for evt in ack_events {
            match evt {
                AckEventLocal::Request { peer, ids, channel } => {
                    let fps: Vec<String> = self.device_to_peer_id.iter()
                        .filter(|(_, p)| **p == peer)
                        .map(|(fp, _)| fp.clone())
                        .collect();
                    // The sender knows our PeerId (from the pairing address) before we know theirs (we learn it only from a packet received over
                    // gossipsub). Replying here told them "delivered" while every Ack was ignored, so our messages stayed unconfirmed and were
                    // retried for minutes. Dropping the channel fails their request, and they fall back to the encrypted Ack. That one also
                    // teaches us their PeerId.
                    if fps.is_empty() {
                        warn!("Toplu Ack tanınmayan peer'dan, yanıtlanmıyor (şifreli Ack'e düşecek): {}", crate::log_id(&peer));
                        drop(channel);
                        continue;
                    }
                    // the sender chunks at ACK_BATCH_MAX; more is a broken peer.
                    if ids.len() > ACK_BATCH_MAX {
                        warn!("Toplu Ack {} kimlik taşıyor, ilk {} uygulanıyor (peer={})", ids.len(), ACK_BATCH_MAX, crate::log_id(&peer));
                    }
                    for id in ids.iter().take(ACK_BATCH_MAX) {
                        let owner = self.awaiting_confirmation.get(id).map(|p| p.peer_device_fingerprint.clone());
                        if let Some(fp) = owner.filter(|o| fps.contains(o)) {
                            if let Some(ev) = self.apply_incoming_ack(&fp, id) {
                                self.attachment_events.push(ev.to_string());
                            }
                        }
                    }
                    info!("Toplu Ack alındı: {} adet (peer={})", ids.len(), crate::log_id(&peer));
                    ack_replies.push(channel);
                }
                AckEventLocal::Delivered { request_id } => {
                    self.ack_batches_inflight.remove(&request_id);
                }
                AckEventLocal::Failed { request_id } => {
                    // back into the queue. `flush_outbound_acks` batches
                    // it again while the peer is connected and falls back to
                    // one packet per ack only without a connection (it fanned
                    // out up to 256 packets on exactly the flaky link).
                    if let Some((fp, ids)) = self.ack_batches_inflight.remove(&request_id) {
                        let queue = self.outbound_acks.entry(fp).or_default();
                        for id in ids {
                            if !queue.contains(&id) {
                                queue.push(id);
                            }
                        }
                    }
                }
            }
        }
        if !ack_replies.is_empty() {
            if let Some(swarm) = &mut self.swarm {
                for channel in ack_replies {
                    let _ = swarm.behaviour_mut().acks.send_response(channel, AckBatchResponse);
                }
            }
        }

        // Server events. They ADD to `incoming` (fetched envelopes), so they must come BEFORE the `for (source, raw) in incoming` drain below. Otherwise every message
        // from the server would be processed one turn (about 1 s) late.
        if !server_events.is_empty() {
            lock_watch::phase("drive_server_sync");
            let replies = self.drive_server_sync(server_events, &mut incoming);
            if let Some(swarm) = &mut self.swarm {
                for (channel, response) in replies {
                    let _ = swarm.behaviour_mut().server_rpc.send_response(channel, response);
                }
            }
        }
        // Connection state. Servers are ordinary libp2p peers too, so their reconnect and backoff logic is shared with `reconnect_sweep`.
        for peer in &connections_established {
            if self.is_server_peer(peer) {
                self.note_server_connection(*peer, true);
            }
        }
        for peer in &connections_lost {
            if self.is_server_peer(peer) {
                self.note_server_connection(*peer, false);
            }
        }
        // See `server_sweep`. Connection, registration, subscription and fetch upkeep. It runs its own interval check (the `reconnect_sweep` pattern).
        lock_watch::phase("server_sweep");
        self.server_sweep();

        // UI events collect in `self.attachment_events` and are taken only at
        // the end: a panic in this turn no longer loses the ones gathered so
        // far, they go out with the next turn.
        // see `DOWNLOAD_STALL_TIMEOUT_MS` — `file_failed` events of this call
        // go out in this turn.
        self.check_stalled_downloads();

        // See `reconnect_sweep`. Periodic (up to every 15 s) automatic reconnect of dropped contacts. It runs its own interval check, so calling it on every
        // poll turn is cheap.
        lock_watch::phase("reconnect_sweep");
        self.sweep_unknown_inbound();
        self.reconnect_sweep();
        // See `pending_group_syncs`. Retries group membership, name and avatar updates periodically (up to every 20 s) while their target device is not yet resolved.
        lock_watch::phase("group_sync_sweep");
        self.group_sync_sweep();
        // Whiteboard: batched strokes and the settling digest, see `whiteboard`.
        self.wb_sweep();
        // See `early_packets`. Buffers whose handshake never arrives are cleared once they expire.
        self.prune_early_packets();
        // See `pending_edits_deletes`. Buffered Edit and Delete packets whose target never arrives are cleared once they expire.
        self.prune_pending_edits_deletes();
        // Held content of unknown groups ages out here too, not only when
        // another such packet arrives.
        let now_wall = current_time_ms();
        self.unknown_group_held.retain(|_, b| {
            b.retain(|e| now_wall.saturating_sub(e.0) <= UNKNOWN_GROUP_HOLD_TTL_MS);
            !b.is_empty()
        });
        // See `message_rate_limiter`. Rate-limit entries of peers that have not sent a packet for a long time are cleared.
        self.prune_rate_limiter();
        // See `HISTORY_STORAGE_SWEEP_INTERVAL_MS`. If the total size of the node-mode attachments exceeds the limit, the oldest files are deleted.
        self.periodic_storage_sweep();

        // See `tor_was_ready` and `announce_address_to_all_contacts`. If Tor reaches Ready in this turn for the first time (bootstrap plus the onion service
        // published, which usually happens minutes after pairing), the current `.onion` address is announced proactively to EVERY known contact. They need it
        // before any connection is made.
        let tor_ready_now = self.tor.as_ref().map(|h| h.status() == tor::TorStatus::Ready).unwrap_or(false);
        if tor_ready_now && !self.tor_was_ready {
            // not the address itself — it is a stable pseudonym and
            // logcat is readable by adb and OEM log collectors.
            info!("Tor Ready durumuna geçti — bilinen kişilere .onion adresi bildiriliyor");
            self.announce_address_to_all_contacts();
        }
        self.tor_was_ready = tor_ready_now;

        // See `pending_envelopes`. Any envelope that could not be sent in the first seconds after a connection (handshake, identity exchange, message, edit,
        // delete, group update, ...) is retried here on every poll turn. `try_publish_raw` is used (the raw version that does NOT queue), because otherwise
        // `publish_envelope` would queue the same entry again on every failed attempt, and the timeout would never fire. For a `Message` envelope, the
        // success or timeout state is reported to the UI as a "status" event through `message_status` (see MessageSendStatus).
        // At most once a second. Before, every turn encoded and published every queued envelope again (a Handshake to an offline peer, for 5 minutes).
        if !self.pending_envelopes.is_empty()
            && mono_ms().saturating_sub(self.last_pending_flush_at) >= 1_000
        {
            let pending = std::mem::take(&mut self.pending_envelopes);
            let now = current_time_ms();
            self.last_pending_flush_at = mono_ms();
            for mut queued in pending {
                // per-entry backoff (see `QueuedEnvelope::next_at`).
                if queued.next_at > now {
                    self.pending_envelopes.push(queued);
                    continue;
                }
                let (peer_fp, envelope, first_attempt_at) = (queued.target.clone(), &queued.envelope, queued.first_attempt_at);
                // A panic here used to lose every envelope after this one
                // (`pending` is already taken out of `self`). Now it costs
                // the one envelope that caused it.
                let published = catch_panic(|| self.try_publish_raw(&peer_fp, envelope, first_attempt_at));
                let Ok(published) = published else {
                    // a Handshake/IdentityExchange has no other carrier
                    // (no `awaiting_confirmation`); it is tried again, later.
                    let handshake_class = matches!(queued.envelope, NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_));
                    if handshake_class && now.saturating_sub(first_attempt_at) <= PENDING_HANDSHAKE_TIMEOUT_MS {
                        error!("Bekleyen zarf yayınlanırken panik, sonra yeniden denenecek (peer={})", crate::log_id(&peer_fp));
                        queued.next_at = pending_retry_at(first_attempt_at, now);
                        self.pending_envelopes.push(queued);
                    } else {
                        error!("Bekleyen zarf yayınlanırken panik, zarf bırakıldı (peer={})", crate::log_id(&peer_fp));
                    }
                    continue;
                };
                match published {
                    Ok(()) => {
                        if let NetworkEnvelope::Message(m) = envelope {
                            self.set_message_status(&m.header.message_id, MessageSendStatus::Sent);
                            self.attachment_events.push(serde_json::json!({
                                "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                                "message_id": m.header.message_id, "status": "sent"
                            }).to_string());
                        }
                    }
                    Err(failure) => {
                        // See `PublishFailure`. A permanent error is dropped at once, without waiting for the timeout, since a retry can never succeed.
                        // See `PENDING_HANDSHAKE_TIMEOUT_MS`. Handshake-class envelopes cannot enter `awaiting_confirmation`, so this queue is their only safety net.
                        // The 20 s timeout broke the delivery guarantee for them.
                        let timeout = match envelope {
                            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => {
                                PENDING_HANDSHAKE_TIMEOUT_MS
                            }
                            NetworkEnvelope::Message(_) => PENDING_ENVELOPE_TIMEOUT_MS,
                        };
                        let give_up = matches!(failure, PublishFailure::Permanent(_))
                            || now.saturating_sub(first_attempt_at) > timeout;
                        if give_up {
                            if let NetworkEnvelope::Message(m) = envelope {
                                // A tracked message stays in `awaiting_confirmation`
                                // and is retried there: not failed yet.
                                if self.awaiting_confirmation.contains_key(&m.header.message_id) {
                                    continue;
                                }
                                self.set_message_status(&m.header.message_id, MessageSendStatus::Failed);
                                self.attachment_events.push(serde_json::json!({
                                    "type": "status", "peer": self.canonical_peer_key(&peer_fp),
                                    "message_id": m.header.message_id, "status": "error"
                                }).to_string());
                            }
                            // Envelopes without a `message_id`, such as Handshake and IdentityExchange, are abandoned the same way. An unbounded queue for a device
                            // that is unreachable forever is not wanted.
                        } else {
                            queued.next_at = pending_retry_at(first_attempt_at, now);
                            self.pending_envelopes.push(queued);
                        }
                    }
                }
            }
        }

        // See `manage_bulk_connections`. Opens extra parallel Tor circuits while a transfer runs, and closes them when it ends.
        self.manage_bulk_connections();

        // Delivery guarantee (see `RateVerdict`): packets deferred from the PREVIOUS turn come first, then those arriving in this turn, so the order is kept.
        // The rate limit is applied here, because a "defer" outcome requires putting the packet back in the queue.
        let mail_was_deferred = self.server_mail_deferred();
        let deferred = std::mem::take(&mut self.deferred_incoming);
        let queued_before = deferred.len();
        lock_watch::phase("incoming_envelopes");
        // Nothing is decrypted before both storage keys are loaded: a packet
        // decrypted without them uses up its ratchet key and cannot be stored
        // (history key) or the session it advances is overwritten (ratchet
        // load). Held as received and processed, in order, once they are there.
        let keys_ready = self.storage_keys_ready();
        let (mut processed, mut rate_dropped) = (0usize, 0usize);
        for (source, raw) in deferred.into_iter().chain(incoming) {
            if !keys_ready {
                self.defer_incoming(source, raw);
                continue;
            }
            if let Some(peer) = source {
                match self.rate_verdict(peer) {
                    RateVerdict::Allow => {}
                    RateVerdict::Defer => {
                        // A known peer that is only sending too fast: do NOT drop it. Leave it for the next turn.
                        self.defer_incoming(Some(peer), raw);
                        continue;
                    }
                    RateVerdict::Drop => {
                        debug!("Hız sınırı aşıldı (tanınmayan eş), paket düşürüldü: peer={}", crate::log_id(&peer));
                        rate_dropped += 1;
                        continue;
                    }
                }
            } else if !self.server_mail_allowed() {
                // not acked at the server until processed (see
                // `commit_server_fetches`), so it waits, it is not dropped.
                self.defer_incoming(None, raw);
                continue;
            }
            processed += 1;
            // A panic costs this one packet, not the rest of this turn's packets
            // and the deferred queue (both were moved out of `self` above).
            match catch_panic(|| self.process_incoming_envelope(source, &raw)).and_then(|r| r) {
                Ok(Some(text)) => self.attachment_events.push(text),
                Ok(None) => {}
                Err(e) => {
                    error!("Gelen paket işlenemedi: {}", e);
                    // covers both the Err result and a caught panic.
                    if source.is_none() {
                        self.server_item_failed(&raw);
                    }
                }
            }
        }
        if rate_dropped > 0 {
            warn!("Hız sınırı: bu turda {} paket düşürüldü", rate_dropped);
        }
        if keys_ready && (queued_before > 0 || !self.deferred_incoming.is_empty()) {
            info!(
                "Gelen kuyruk: {} işlendi ({} önceki turdan), {} bekliyor",
                processed,
                queued_before,
                self.deferred_incoming.len()
            );
        }
        // the held Fetch (see `server_fetch`) goes out now, not at
        // the next radio window.
        if mail_was_deferred && !self.server_mail_deferred() {
            self.server_sweep_at = 0;
        }
        // server Acks go out only now, after this turn processed the
        // fetched items (see `commit_server_fetches`).
        self.commit_server_fetches();

        // See `flush_outbound_acks`. The Acks produced in this turn go out with the final swarm turn below.
        self.flush_outbound_acks();

        // See `awaiting_confirmation`. This is the ONLY real end-to-end delivery guarantee for Text (outside groups), Edit, Delete and HistorySyncRequest. Unlike
        // `pending_envelopes`, it continues indefinitely until the peer acknowledges. After the incoming packets, an Ack read in this turn stops the retry (and
        // the suspect probe) that is due in the same turn.
        lock_watch::phase("retry_unconfirmed");
        self.retry_unconfirmed_messages();

        // See `deferred_swarm_events`. Requests queued in this turn (file chunk requests, server RPCs, acks) do not leave until the swarm is
        // polled once more. Waiting for the next turn added about 1 s to every round trip. The main loop above drains the swarm up to Pending, so this turn almost
        // always returns Pending at once (it only advances the state machine and triggers the write). If an event does arrive here, it is NOT dropped. It is
        // stored and handled first in the next turn.
        if self.swarm.is_some() {
            let mut dropped: Vec<libp2p::swarm::SwarmEvent<P2PBehaviourEvent>> = Vec::new();
            if let Some(swarm) = &mut self.swarm {
                RUNTIME.block_on(async {
                    for _ in 0..16 {
                        match swarm.next().now_or_never().flatten() {
                            Some(e) => dropped.push(e),
                            None => break,
                        }
                    }
                });
            }
            if !dropped.is_empty() {
                self.deferred_swarm_events.extend(dropped);
            }
        }
        // Events queued after the first drain (retry status, a failed
        // download, replayed early packets) go out in this turn too.
        std::mem::take(&mut self.attachment_events)
    }

    /// See `early_packets`. Buffers a packet that arrives before the ratchet exists. Limited to `MAX_EARLY_PACKETS_PER_PEER` per peer (the oldest is dropped),
    /// so a hostile peer cannot consume unbounded memory.
    pub(crate) fn buffer_early_packet(&mut self, sender_fp: String, source: Option<PeerId>, packet: MessagePacket) {
        let now = current_time_ms();
        // the header fingerprint is not verified yet, so the per-peer
        // caps alone let one peer fill memory under many names. Cap the total
        // too, evicting from the largest buffer.
        const MAX_EARLY_PACKET_BYTES_TOTAL: usize = 32 * 1024 * 1024;
        let buf_bytes = |b: &std::collections::VecDeque<(u64, Option<PeerId>, MessagePacket)>| b.iter().map(|(_, _, p)| p.ciphertext.len()).sum::<usize>();
        let mut total = packet.ciphertext.len() + self.early_packets.values().map(buf_bytes).sum::<usize>();
        while total > MAX_EARLY_PACKET_BYTES_TOTAL {
            let Some(fp) = self.early_packets.iter().max_by_key(|(_, b)| buf_bytes(*b)).map(|(k, _)| k.clone()) else { break };
            let Some(b) = self.early_packets.get_mut(&fp) else { break };
            let top = busiest_source(b.iter().map(|(_, s, _)| *s));
            let i = b.iter().position(|(_, s, _)| *s == top).unwrap_or(0);
            total -= b.remove(i).map_or(0, |p| p.2.ciphertext.len());
            if b.is_empty() {
                self.early_packets.remove(&fp);
            }
        }
        let buf = self.early_packets.entry(sender_fp.clone()).or_default();
        // Count and bytes: one packet may be close to 1 MiB.
        const MAX_EARLY_PACKET_BYTES_PER_PEER: usize = 8 * 1024 * 1024;
        let mut bytes = packet.ciphertext.len() + buf.iter().map(|(_, _, p)| p.ciphertext.len()).sum::<usize>();
        while !buf.is_empty() && (buf.len() >= MAX_EARLY_PACKETS_PER_PEER || bytes > MAX_EARLY_PACKET_BYTES_PER_PEER) {
            // Oldest packet of the source that holds the most entries: the
            // fingerprint in the header is not verified yet, so any peer could
            // name a contact's fingerprint and push that contact's packets out.
            let top = busiest_source(buf.iter().map(|(_, s, _)| *s));
            let i = buf.iter().position(|(_, s, _)| *s == top).unwrap_or(0);
            bytes -= buf.remove(i).map_or(0, |p| p.2.ciphertext.len());
        }
        buf.push_back((now, source, packet));
        info!(
            "Ratchet henüz yok (peer={}) — paket tamponlandı, el sıkışma sonrası oynatılacak ({} bekliyor)",
            crate::log_id(&sender_fp),
            buf.len()
        );
    }

    /// After the handshake completes, buffered packets for that peer are processed IN ARRIVAL ORDER. Events produced are appended to `attachment_events`
    /// (poll_events drains it and forwards it to Kotlin).
    pub(crate) fn replay_early_packets(&mut self, sender_fp: &str) {
        let buffered = match self.early_packets.remove(sender_fp) {
            Some(b) if !b.is_empty() => b,
            _ => return,
        };
        info!("El sıkışma tamam (peer={}) — {} tamponlanmış paket oynatılıyor", crate::log_id(&sender_fp), buffered.len());
        for (_, source, packet) in buffered {
            match self.receive_message(source, &packet) {
                Ok(event) => self.attachment_events.push(event),
                Err(e) => error!("Tamponlanmış paket işlenemedi (peer={}): {}", crate::log_id(&sender_fp), e),
            }
        }
    }

    /// Called from `poll_events`. Clears buffered packets of peers whose handshake never arrives, once they expire (see `EARLY_PACKET_TTL_MS`).
    pub(crate) fn prune_early_packets(&mut self) {
        let now = current_time_ms();
        self.early_packets.retain(|_, buf| {
            buf.retain(|(t, _, _)| now.saturating_sub(*t) <= EARLY_PACKET_TTL_MS);
            !buf.is_empty()
        });
        // See `early_handshakes`. If an IdentityExchange never arrives, the buffered handshake goes stale too.
        self.early_handshakes.retain(|_, buf| {
            buf.retain(|(t, _, _)| now.saturating_sub(*t) <= EARLY_PACKET_TTL_MS);
            !buf.is_empty()
        });
    }

    /// See `early_handshakes`. Called as soon as `process_identity_exchange` adds the sender device to `known_remote_devices`. A buffered `HandshakeInit` can now be
    /// processed (its signature can be verified now).
    pub(crate) fn replay_early_handshake(&mut self, sender_fp: &str) {
        let Some(buf) = self.early_handshakes.remove(sender_fp) else { return };
        // Each buffered init in turn: the first one that verifies wins.
        for (_, source, handshake) in buf {
            info!("Tamponlanmış HandshakeInit oynatılıyor (peer={})", crate::log_id(&sender_fp));
            match self.process_handshake_init(source, &handshake) {
                Ok(()) => {
                    self.replay_early_packets(sender_fp);
                    return;
                }
                Err(e) => error!("Tamponlanmış HandshakeInit işlenemedi (peer={}): {}", crate::log_id(&sender_fp), e),
            }
        }
    }

    /// See `message_rate_limiter` and `RATE_LIMIT_WINDOW_MS`. `true` means allow. `false` means the limit is exceeded for this window, and the caller must drop the
    /// packet WITHOUT processing it (no signature check, no ratchet decryption).
    ///
    /// Sibling bursts: a VERIFIED sibling device gets a window cap four times higher. Its PeerId-to-fingerprint mapping is trustworthy because
    /// `device_to_peer_id` is filled only after signature verification, and a fingerprint with our own identity is a sibling. On reconnect, retried messages, sibling
    /// echoes, Acks and backfill all arrive within the same seconds, and can legitimately exceed the 60 per 10 s cap. Dropped packets did arrive eventually via retries,
    /// but the "instant sync on reconnect" goal turned into a crawl window by window. The cap for foreign or ordinary contacts did not change.
    ///
    /// Is this PeerId an identity-verified peer with an established session? The test is deliberately the PeerId proven by the transport layer, not a claim inside the
    /// packet. `device_to_peer_id` is filled only after the signature is verified (see `record_peer_id_if_known`), so an attacker cannot open this path by writing a
    /// familiar fingerprint into the header.
    pub(crate) fn is_established_peer(&self, peer: PeerId) -> bool {
        self.device_to_peer_id.iter().any(|(fp, pid)| {
            *pid == peer
                && self.ratchets.contains_key(fp)
                && self.known_remote_devices.get(fp).map(|d| d.is_active).unwrap_or(false)
        })
    }

    /// The Noise-proven `PeerId` is mapped to an active device we know (no
    /// session needed). Such a peer has its own per-peer cap outside the
    /// shared stranger budget: a few stranger connections used it up and
    /// blocked every IdentityExchange and Handshake.
    pub(crate) fn is_known_device_peer(&self, peer: PeerId) -> bool {
        self.device_to_peer_id.iter().any(|(fp, pid)| {
            *pid == peer && self.known_remote_devices.get(fp).map_or(false, |d| d.is_active)
        })
    }

    /// Whether `rate_verdict` is going to drop this peer's next packet. Does
    /// not count the packet.
    pub(crate) fn rate_would_drop(&self, peer: PeerId) -> bool {
        let now = mono_ms();
        let (start, count) = self.unknown_peer_rate;
        let all_full = now.saturating_sub(start) <= RATE_LIMIT_WINDOW_MS && count >= RATE_LIMIT_MAX_UNKNOWN_TOTAL
            && !self.is_known_device_peer(peer);
        (all_full || self.message_rate_limiter.get(&peer).map_or(false, |(start, count)| {
            now.saturating_sub(*start) <= RATE_LIMIT_WINDOW_MS && *count >= RATE_LIMIT_MAX_PER_WINDOW
        })) && !self.is_established_peer(peer)
    }

    /// See `RATE_LIMIT_MAX_ESTABLISHED`. The three outcomes of the rate limit.
    pub(crate) fn rate_verdict(&mut self, peer: PeerId) -> RateVerdict {
        let established = self.is_established_peer(peer);
        let max_per_window = if established {
            RATE_LIMIT_MAX_ESTABLISHED
        } else {
            RATE_LIMIT_MAX_PER_WINDOW
        };
        let now = mono_ms();
        let entry = self.message_rate_limiter.entry(peer).or_insert((now, 0));
        let within = if now.saturating_sub(entry.0) > RATE_LIMIT_WINDOW_MS {
            *entry = (now, 1);
            true
        } else {
            entry.1 += 1;
            entry.1 <= max_per_window
        };
        if within {
            // peer ids cost nothing, so all non-established peers also
            // share one budget, checked before the packet is decoded. Charged
            // only for packets within the peer's own cap: one peer then takes
            // at most its share, not the whole budget.
            if !established && !self.is_known_device_peer(peer) && !window_allow(&mut self.unknown_peer_rate, RATE_LIMIT_MAX_UNKNOWN_TOTAL) {
                return RateVerdict::Drop;
            }
            RateVerdict::Allow
        } else if established {
            // A known peer is never dropped. It is queued. Not counted here: the deferred packet is counted once, in the turn it is processed.
            entry.1 -= 1;
            RateVerdict::Defer
        } else {
            // Over its own cap and not a device we know: the connection goes
            // (it kept its slot for the whole unknown-peer grace before).
            // Once per window, at the first packet over the cap.
            if entry.1 == max_per_window + 1 && !self.is_known_device_peer(peer) && !self.is_server_peer(&peer) {
                if let Some(swarm) = &mut self.swarm {
                    let _ = swarm.disconnect_peer_id(peer);
                }
            }
            RateVerdict::Drop
        }
    }

    /// budget for server-delivered mail, as much as one established
    /// peer gets (`RATE_LIMIT_MAX_ESTABLISHED` per `RATE_LIMIT_WINDOW_MS`).
    pub(crate) fn server_mail_allowed(&mut self) -> bool {
        window_allow(&mut self.server_mail_rate, RATE_LIMIT_MAX_ESTABLISHED)
    }

    /// Server mail waiting for its rate budget (see `server_mail_allowed`).
    pub(crate) fn server_mail_deferred(&self) -> bool {
        self.deferred_incoming.iter().any(|(s, _)| s.is_none())
    }

    /// See `deferred_incoming`. If the queue is full, the oldest entry is dropped.
    /// See `poll_events` "incoming_envelopes": the history key and sessions are loaded.
    pub(crate) fn storage_keys_ready(&self) -> bool {
        self.history_key.is_some() && self.ratchets_loaded
    }

    pub(crate) fn defer_incoming(&mut self, source: Option<PeerId>, raw: Vec<u8>) {
        // Count and bytes: 2000 packets of up to 1 MiB each were 2 GB.
        const MAX_DEFERRED_INCOMING_BYTES: usize = 32 * 1024 * 1024;
        let mut bytes = raw.len() + self.deferred_incoming.iter().map(|(_, r)| r.len()).sum::<usize>();
        let mut evicted = 0usize;
        while !self.deferred_incoming.is_empty()
            && (self.deferred_incoming.len() >= MAX_DEFERRED_INCOMING || bytes > MAX_DEFERRED_INCOMING_BYTES)
        {
            // Oldest packet of the peer that holds the most entries: one busy
            // peer must not push out the packets of the others.
            let top = busiest_source(self.deferred_incoming.iter().map(|(s, _)| *s));
            let i = self.deferred_incoming.iter().position(|(s, _)| *s == top).unwrap_or(0);
            if let Some((src, dropped)) = self.deferred_incoming.remove(i) {
                bytes -= dropped.len();
                // server mail is not resent by anyone; keep it on the server.
                if src.is_none() {
                    self.server_item_failed(&dropped);
                }
            }
            evicted += 1;
        }
        if evicted > 0 {
            warn!("Ertelenmiş gelen paket kuyruğu doldu, {} girdi düştü (gönderen yeniden deneyecek)", evicted);
        }
        self.deferred_incoming.push_back((source, raw));
    }

    /// Called from `poll_events`. Clears rate-limit entries of peers that have not sent a packet for a long time (memory protection, same pattern as
    /// `prune_early_packets`).
    pub(crate) fn prune_rate_limiter(&mut self) {
        let now = mono_ms();
        self.message_rate_limiter.retain(|_, (window_start, _)| {
            now.saturating_sub(*window_start) <= RATE_LIMIT_WINDOW_MS
        });
        self.chunk_rate_limiter.retain(|_, (window_start, _)| {
            now.saturating_sub(*window_start) <= RATE_LIMIT_WINDOW_MS
        });
    }

    /// See `INBOUND_DEDUP_WINDOW_MS`. Removes byte-identical envelope copies produced by multi-path delivery, without calling `process_incoming_envelope_inner`
    /// (signature verification plus ratchet decryption). For a duplicate `Message`, the Ack is sent again to the sender, since an Ack that never arrived is the
    /// usual reason the sender repeats itself (see the decryption-error arm of `receive_message`, same logic).
    pub(crate) fn process_incoming_envelope(&mut self, source: Option<PeerId>, raw: &[u8]) -> Result<Option<String>, String> {
        let digest = {
            use std::hash::BuildHasher;
            // Per-process random key; `DefaultHasher::new()` is fixed-key.
            static DEDUP_KEY: std::sync::OnceLock<std::collections::hash_map::RandomState> = std::sync::OnceLock::new();
            DEDUP_KEY.get_or_init(std::collections::hash_map::RandomState::new).hash_one(raw)
        };
        let now = current_time_ms();
        // Periodic pruning plus a hard cap. Running `retain` on every envelope would be wasteful.
        if now.saturating_sub(self.last_inbound_dedup_prune_at) > 60_000
            || self.recent_inbound_digests.len() > INBOUND_DEDUP_MAX_ENTRIES
        {
            self.last_inbound_dedup_prune_at = now;
            self.recent_inbound_digests
                .retain(|_, (seen_at, _)| now.saturating_sub(*seen_at) < INBOUND_DEDUP_WINDOW_MS);
            if self.recent_inbound_digests.len() > INBOUND_DEDUP_MAX_ENTRIES {
                // Still over the cap: the older half goes. Clearing it all
                // let a flood make every retried packet be verified again.
                // By count, not by a time cutoff: under a flood the entries
                // share a millisecond and a `> median` test kept none.
                let mut entries: Vec<(u64, (u64, bool))> = self.recent_inbound_digests.drain().collect();
                entries.sort_unstable_by_key(|e| std::cmp::Reverse(e.1 .0));
                entries.truncate(INBOUND_DEDUP_MAX_ENTRIES / 2);
                self.recent_inbound_digests.extend(entries);
            }
        }
        let seen_at = self.recent_inbound_digests.get(&digest).copied();
        if let Some((seen_at, first_ok)) = seen_at {
            if now.saturating_sub(seen_at) < INBOUND_DEDUP_WINDOW_MS {
                // a server item whose first pass failed fails
                // again, so `server_item_failed` holds it once more. An
                // `Ok(None)` here let the server copy be acked and deleted.
                if !first_ok {
                    if source.is_none() {
                        return Err("Aynı zarf az önce işlenemedi".to_string());
                    }
                    return Ok(None);
                }
                // The timestamp is NOT refreshed. The sender retries every 15-120 s, so a window that slid forward would never end.
                // A byte-identical copy of this envelope was already processed within this window (Ok or Err, the result is deterministic).
                // For a `Message`, the Ack is sent to the sender again. Decryption is NOT needed: `MessagePacketHeader` is signed but not encrypted, it carries the
                // `message_id` in clear, and it was already verified on the first pass. The Ack is sent only if the message really IS in the archive, so a message
                // not yet delivered is never acknowledged by mistake.
                // Only after a first pass that succeeded: a failed one may never have verified this header.
                if let Ok(NetworkEnvelope::Message(m)) = NetworkEnvelope::from_cbor(raw) {
                    self.reack_if_already_handled(&m.header);
                }
                return Ok(None);
            }
        }
        let result = self.process_incoming_envelope_inner(source, raw);
        // The result is recorded whether it is Ok or Err. An undecryptable control packet (for example typing or a receipt, which is not in the archive) returns Err from `_inner`.
        // If that Err were not recorded, every redelivery of the same bytes would log the same error again. Identical bytes give the same result, so recording the Err is safe.
        // A packet regenerated by `regen_content` has different ciphertext (a different digest), so it is still delivered.
        // Exception: if `_inner` buffered the packet as an early packet, it returns Ok(None) and the digest is recorded. `replay_early_packets` processes the buffered copy once the handshake completes.
        // Some failures depend on state, for example an IdentityExchange that has not arrived yet. Such a failure is forgotten after 30 s, so a retry of the same bytes is processed again.
        // An IdentityExchange is always the same bytes, so it is remembered for 30 s like any failed packet.
        let short = result.is_err()
            || matches!(NetworkEnvelope::from_cbor(raw), Ok(NetworkEnvelope::IdentityExchange(_)));
        let seen_at = if short { now.saturating_sub(INBOUND_DEDUP_WINDOW_MS - 30_000) } else { now };
        self.recent_inbound_digests.insert(digest, (seen_at, result.is_ok()));
        result
    }

    pub(crate) fn process_incoming_envelope_inner(&mut self, source: Option<PeerId>, raw: &[u8]) -> Result<Option<String>, String> {
        // See `rate_verdict`. Checked at the cheapest point, before expensive work such as signature verification and ratchet decryption. `source: None` (a packet
        // that did not come from a real network connection, such as a buffered replay) is NOT subject to the rate limit, since it was already counted once.
        // The rate limit now lives in the incoming loop of `poll_events`, not here, because a "defer" outcome (see `RateVerdict::Defer`) needs the packet put back in the
        // queue, and that is the loop's job.
        let envelope = NetworkEnvelope::from_cbor(raw)?;
        // See `blocked_identities`. NO packet from a blocked person is processed: no message, no handshake, no identity announcement. No alert is produced either,
        // otherwise the blocked party could flood the user with "new device" alerts.
        let blocked_sender = match &envelope {
            NetworkEnvelope::IdentityExchange(x) => self.is_blocked(&x.identity_id),
            NetworkEnvelope::Handshake(h) => {
                self.is_blocked(&h.sender_identity_id) || self.is_blocked_device(&h.sender_device_fingerprint)
            }
            NetworkEnvelope::Message(m) => {
                self.is_blocked(&m.header.sender_identity_id)
                    || self.is_blocked_device(&m.header.sender_device_fingerprint)
            }
        };
        if blocked_sender {
            return Ok(None);
        }
        match envelope {
            NetworkEnvelope::IdentityExchange(x) => {
                // `record_peer_id_if_known` is NOT called here any more. At this point `x.device_fingerprint` is unverified, only the sender's CLAIM (see the carry-over
                // note in `process_identity_exchange`). The function records it itself, after checking that the fingerprint really derives from the carried public keys.
                self.process_identity_exchange(source, &x)?;
                // A sibling brought back our own revoke: everything is wiped
                // (`self_revoked` is queued by `apply_device_revoke_notice`).
                if self.identity.is_none() {
                    return Ok(None);
                }
                Ok(None)
            }
            NetworkEnvelope::Handshake(h) => {
                let sender_fp = h.sender_device_fingerprint.clone();
                // See the IdentityExchange note above. `process_handshake_init` now records the sender itself, after the signature is verified.
                match self.process_handshake_init(source, &h) {
                    Ok(()) => {}
                    // the state itself, not the error text.
                    Err(e) if !self.known_remote_devices.contains_key(&sender_fp) => {
                        // See `early_handshakes`. The sender's IdentityExchange has not arrived yet. Do NOT drop the packet. Buffer it. Only while we are in an active
                        // pairing with this person, or if the contact is already known (the buffer is unbounded otherwise).
                        let expected = self.pairing_mailbox_subs.contains_key(&sender_fp)
                            || self.identity_to_contact.contains_key(&h.sender_identity_id);
                        // `sender_identity_id` is an unverified claim and each
                        // init is several KB: capped.
                        // And 4 per claimed identity: one known identity id
                        // was enough to take all 64 slots.
                        let same_identity = self.early_handshakes.values().flatten().filter(|(_, _, e)| e.sender_identity_id == h.sender_identity_id).count();
                        // a claim not backed by a pairing in progress or
                        // a device the contact already lists gets 16 of the 64
                        // slots: ~16 known identity ids filled them all and a
                        // real pairing's init was refused.
                        let listed = |fp: &str, id: &str| self.identity_to_contact.get(id)
                            .and_then(|cid| self.contacts.get(cid))
                            .map_or(false, |c| c.find_device(fp).is_some());
                        let vouched = self.pairing_mailbox_subs.contains_key(&sender_fp) || listed(&sender_fp, &h.sender_identity_id);
                        let unvouched = self.early_handshakes.iter()
                            .filter(|(fp, buf)| !self.pairing_mailbox_subs.contains_key(*fp)
                                && !buf.iter().any(|(_, _, e)| listed(fp, &e.sender_identity_id)))
                            .count();
                        let held = self.early_handshakes.get(&sender_fp).map_or(0, |b| b.len());
                        if expected && same_identity < 4 && (vouched || unvouched < 16) && held < 3
                            && (self.early_handshakes.len() < 64 || held > 0)
                        {
                            info!("HandshakeInit erken geldi (peer={}) — IdentityExchange bekleniyor, tamponlandı", crate::log_id(&sender_fp));
                            self.early_handshakes.entry(sender_fp.clone()).or_default().push((current_time_ms(), source, h));
                            return Ok(None);
                        }
                        // Not buffered: an Err, so the dedup forgets it soon (see
                        // `process_incoming_envelope`).
                        return Err(e);
                    }
                    Err(e) => return Err(e),
                }
                // The early packets that arrived BEFORE the handshake are processed now (see `early_packets`). Events go to the `attachment_events` queue, which
                // `poll_events` already drains.
                self.replay_early_packets(&sender_fp);
                Ok(None)
            }
            NetworkEnvelope::Message(m) => {
                let sender_fp = m.header.sender_device_fingerprint.clone();
                // See `early_packets` and `EARLY_PACKET_TTL_MS`. If there is no ratchet yet (the message came before the handshake, since gossipsub gives no ordering
                // guarantee), the packet is NOT dropped. It is buffered and replayed when the handshake arrives. Only KNOWN devices are buffered (an unknown sender was
                // already rejected, and this also keeps the buffer from filling without bound). `source` is buffered together with the packet (see the `early_packets`
                // field note). The signature is not verified yet at this point, so the source is not recorded here. `receive_message` records it itself at replay time,
                // after verification.
                if !self.ratchets.contains_key(&sender_fp) {
                    if let Some(sender) = self.known_remote_devices.get(&sender_fp).filter(|d| d.is_active).cloned() {
                        // The signature first (the keys are known): the
                        // fingerprint in the header is only a claim, and a
                        // stranger with throw-away peer ids filled this
                        // device's buffer and pushed the real packets out.
                        let to_verify = packet_signing_input(m.header.raw(), &m.ciphertext, &self.get_active_own_device_fingerprint()?);
                        verify_hybrid_signature(&to_verify, &m.signature_classical, &m.signature_pq, &sender)?;
                        self.buffer_early_packet(sender_fp, source, m);
                        return Ok(None);
                    }
                }
                // See the notes above. `receive_message` now records it itself, after the signature has been verified.
                let text = self.receive_message(source, &m)?;
                Ok(Some(text))
            }
        }
    }
}
