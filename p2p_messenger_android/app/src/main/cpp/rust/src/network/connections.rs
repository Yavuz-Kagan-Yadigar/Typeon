//! Relays and reservations, bulk connections, dialing, unknown inbound and the reconnect sweep.

use super::*;

impl P2PCore {
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
            info!("Relay candidate recorded: {} {}", crate::log_id(&peer_id), addr);
        }
        self.known_relay_peers.insert(peer_id, (addr, current_time_ms()));
    }

    /// Onion address of a configured server (with the `/p2p/<id>` suffix).
    pub(crate) fn server_onion_addr(&self, peer: &PeerId) -> Option<Multiaddr> {
        let id = peer.to_string();
        let rec = self.servers.iter().find(|r| r.server_id == id)?;
        let addr: Multiaddr = rec.address.split(',')
            .map(str::trim)
            .find(|a| a.contains(".onion"))?
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
                    info!("Relay reservation requested: relay={}", crate::log_id(&pid));
                    self.relay_listeners.insert(*pid, (lid, now));
                }
                Err(e) => warn!("Could not request relay reservation (relay={}): {}", crate::log_id(&pid), e),
            }
        }
    }

    /// During a bulk transfer, opens extra connections to the peers involved and closes
    /// them when done (see `BULK_PARALLEL_CONNECTIONS`).
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
                        info!("Opening extra connection for batch transfer: peer={} (current {})", crate::log_id(&peer), have)
                    }
                    Err(e) => warn!("Could not open extra connection: {}", e),
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
            info!("Batch transfer done, closing {} extra connections: peer={}", conns.len(), crate::log_id(&peer));
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
                "Parallel transfer backed off {} times with this peer, reverting to single connection: peer={}",
                drops, crate::log_id(&peer)
            );
            self.drop_extra_connections(peer, "Parallelism abandoned", usize::MAX);
            return;
        }
        // Drop ONE circuit, not all of them.
        self.drop_extra_connections(peer, "Repeated chunk timeout", 1);
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
            "{} — closed {} extra connections ({} left): peer={}",
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

    /// Dials a peer at `direct_addr` (if any) and, through each connected relay, at a
    /// `/p2p-circuit/` address, all at once. Plain address dials use
    /// `PeerCondition::Always`, so they run beside a peer-id dial already in flight;
    /// the first connection wins.
    pub(crate) fn dial_with_relay_fallback(&mut self, target_peer_id: PeerId, direct_addr: Option<Multiaddr>) {
        let Some(swarm) = &mut self.swarm else { return };
        if let Some(addr) = direct_addr {
            if let Err(e) = swarm.dial(addr) {
                error!("Direct dial failed: {}", e);
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
                error!("Dial via relay failed (relay={}): {}", crate::log_id(&relay_peer_id), e);
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
            .filter(|d| d.is_active && !self.is_blocked(&d.identity_id))
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
                    error!("IdentityExchange could not be sent on connect (periodic scan), will retry: {}", e);
                }
            }
        }
        // Multi-device: periodic history backfill from sibling devices, debounced
        // internally (see SIBLING_BACKFILL_INTERVAL_MS). Catches contact messages missed while
        // offline.
        self.request_sibling_backfill();
    }

}
