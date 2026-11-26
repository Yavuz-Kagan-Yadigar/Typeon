//! Anonymous deposit connections.
//!
//! `Deposit` and `Cancel` never go over the enrollment connection. Each server gets its own short-lived libp2p
//! swarm with a fresh Ed25519 identity (a throwaway PeerId), dialed over its own Tor circuit (`ArtiDialTransport`
//! isolates every dial). The server so sees "some unknown peer deposited into box X", never "enrollment A wrote to
//! box X". The deposit secret of the box is the authorisation (`server_proto::ServerRequest::Deposit`).
//!
//! Battery: nothing here runs on a timer. A connection is opened only when a deposit or cancel is queued, carries
//! everything queued for that server while it is open, and closes after `ANON_IDLE_MS` with nothing in flight, so
//! Tor can go dormant again. `poll_events` drives it (`drive_anon_conns`), and `wait_for_network_activity` wakes on
//! its events.
//!
//! Linkability: deposits that share one connection (one burst) share its PeerId and circuit, so the server can tell
//! they came from one sender. They are not linked to the enrollment, and the next burst has a new PeerId.

use super::*;
use futures::{FutureExt as _, StreamExt as _};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::SwarmEvent;
use libp2p::{StreamProtocol, Swarm};

/// An anonymous connection with nothing in flight is closed after this long.
pub(crate) const ANON_IDLE_MS: u64 = 30_000;
/// libp2p's own idle timeout sits above `ANON_IDLE_MS`, so our close always comes first: a request queued just before
/// our close cannot meet a connection libp2p is already tearing down.
const ANON_SWARM_IDLE_MS: u64 = ANON_IDLE_MS + 15_000;

type AnonBehaviour = request_response::Behaviour<crate::ServerRpcCodec>;
pub(crate) type AnonEvent = SwarmEvent<<AnonBehaviour as libp2p::swarm::NetworkBehaviour>::ToSwarm>;

/// One server's anonymous connection.
pub(crate) struct AnonConn {
    pub(crate) swarm: Swarm<AnonBehaviour>,
    server_peer: PeerId,
    addrs: Vec<Multiaddr>,
    /// The dial goes out in `drive_anon_conns`, inside the runtime.
    pub(crate) dialed: bool,
    connected: bool,
    /// Broken or closed: dropped at the end of this drive, its requests fail.
    dead: bool,
    last_used: u64,
    /// Waiting for the connection.
    queue: Vec<(ServerRequest, ServerInflight)>,
    inflight: HashMap<request_response::OutboundRequestId, ServerInflight>,
    /// Events `wait_for_network_activity` took out of the swarm, handled first on the next drive.
    pub(crate) deferred: Vec<AnonEvent>,
    /// This connection replaces one that broke with work on it. The next break backs off (see `drive_anon_conns`).
    redialed: bool,
}

impl AnonConn {
    pub(crate) fn busy(&self) -> bool {
        !self.queue.is_empty() || !self.inflight.is_empty()
    }

    /// Sends the queue. A connection libp2p already closed is marked dead instead: its queue then goes to a redial.
    fn flush(&mut self) {
        if !self.swarm.is_connected(&self.server_peer) {
            self.dead = true;
            return;
        }
        for (req, inflight) in self.queue.drain(..) {
            let id = self.swarm.behaviour_mut().send_request(&self.server_peer, req);
            self.inflight.insert(id, inflight);
        }
    }
}

impl P2PCore {
    /// Sends `req` to `server_id` over its anonymous connection, opening one if none is open. `false`: no connection
    /// can be made (no Tor, no address); the caller treats the request as not sent.
    pub(super) fn anon_send(&mut self, server_id: &str, req: ServerRequest, inflight: ServerInflight) -> bool {
        if !self.anon_conns.contains_key(server_id) {
            let Some(conn) = self.open_anon_conn(server_id) else { return false };
            self.anon_conns.insert(server_id.to_string(), conn);
        }
        let Some(conn) = self.anon_conns.get_mut(server_id) else { return false };
        conn.last_used = mono_ms();
        conn.queue.push((req, inflight));
        if conn.connected {
            conn.flush();
        }
        true
    }

    /// A new swarm with a fresh identity and only the server RPC (outbound: the server cannot push to it).
    fn open_anon_conn(&self, server_id: &str) -> Option<AnonConn> {
        use libp2p::core::muxing::StreamMuxerBox;
        use libp2p::core::transport::Transport as _;
        use libp2p::core::upgrade::Version;
        let client = self.tor.as_ref()?.client.clone();
        let rec = self.servers.iter().find(|s| s.server_id == server_id)?;
        let server_peer = self.server_rt.get(server_id)?.peer_id?;
        let addrs: Vec<Multiaddr> = server_proto::public_server_addrs(rec.address.split(','))
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect();
        if addrs.is_empty() {
            return None;
        }
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let noise = libp2p::noise::Config::new(&keypair).ok()?;
        let transport = libp2p::core::transport::timeout::TransportTimeout::new(
            crate::tor::ArtiDialTransport::new(Some(client))
                .upgrade(Version::V1Lazy)
                .authenticate(noise)
                .multiplex(crate::tuning::tuned_yamux())
                .map(|(p, m), _| (p, StreamMuxerBox::new(m))),
            std::time::Duration::from_secs(crate::tuning::SWARM_CONNECTION_TIMEOUT_SECS),
        )
        .boxed();
        let behaviour = AnonBehaviour::new(
            [(StreamProtocol::new(server_proto::SERVER_PROTOCOL), request_response::ProtocolSupport::Outbound)],
            request_response::Config::default().with_request_timeout(std::time::Duration::from_millis(BLOB_REQUEST_TIMEOUT_MS)),
        );
        let swarm = Swarm::new(
            transport,
            behaviour,
            keypair.public().to_peer_id(),
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(std::time::Duration::from_millis(ANON_SWARM_IDLE_MS)),
        );
        Some(AnonConn {
            swarm,
            server_peer,
            addrs,
            dialed: false,
            connected: false,
            dead: false,
            last_used: mono_ms(),
            queue: Vec::new(),
            inflight: HashMap::new(),
            deferred: Vec::new(),
            redialed: false,
        })
    }

    /// Dials new connections, takes their events, and closes the idle and broken ones. `poll_events` calls it every
    /// turn; with no connection open it returns at once.
    pub(crate) fn drive_anon_conns(&mut self) {
        if self.anon_conns.is_empty() {
            return;
        }
        // The circuit is built now: Tor must not sleep through it.
        if self.tor_dormant && self.anon_conns.values().any(|c| !c.dialed) {
            if let Some(tor) = &self.tor {
                tor.set_dormant(false);
                self.tor_dormant = false;
            }
        }
        let now = mono_ms();
        let mut done: Vec<(ServerInflight, ServerResponse)> = Vec::new();
        // Requests that got no answer, per server.
        let mut lost: HashMap<String, Vec<ServerInflight>> = HashMap::new();
        let conns = &mut self.anon_conns;
        crate::RUNTIME.block_on(async {
            for (sid, conn) in conns.iter_mut() {
                if !conn.dialed {
                    conn.dialed = true;
                    let opts = DialOpts::peer_id(conn.server_peer).addresses(conn.addrs.clone()).build();
                    if let Err(e) = conn.swarm.dial(opts) {
                        warn!("Anonymous server dial failed: {}", e);
                        conn.dead = true;
                    }
                }
                let mut deferred = std::mem::take(&mut conn.deferred);
                deferred.reverse();
                for _ in 0..MAX_ANON_EVENTS_PER_TURN {
                    let event = match deferred.pop() {
                        Some(e) => e,
                        None => match conn.swarm.next().now_or_never().flatten() {
                            Some(e) => e,
                            None => break,
                        },
                    };
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == conn.server_peer => {
                            conn.connected = true;
                            conn.flush();
                        }
                        SwarmEvent::OutgoingConnectionError { error, .. } if !conn.connected => {
                            warn!("Anonymous server connection failed: {}", error);
                            conn.dead = true;
                        }
                        SwarmEvent::ConnectionClosed { num_established: 0, .. } => conn.dead = true,
                        SwarmEvent::Behaviour(request_response::Event::Message {
                            message: request_response::Message::Response { request_id, response },
                            ..
                        }) => {
                            if let Some(i) = conn.inflight.remove(&request_id) {
                                conn.last_used = now;
                                // It works: a later break may redial once more.
                                conn.redialed = false;
                                done.push((i, response));
                            }
                        }
                        SwarmEvent::Behaviour(request_response::Event::OutboundFailure { request_id, .. }) => {
                            if let Some(i) = conn.inflight.remove(&request_id) {
                                lost.entry(sid.clone()).or_default().push(i);
                            }
                        }
                        _ => {}
                    }
                }
                // Over the budget: the rest waits for the next turn, in order.
                deferred.reverse();
                conn.deferred = deferred;
            }
        });
        // Broken, or idle long enough: closed. A connection that broke with work on it is dialed again once, at once
        // and without a backoff, with its queue; what was in flight goes back through the publish path to that new
        // connection. A second break in a row backs the server off one step, not one step per request.
        let closing: Vec<String> = self
            .anon_conns
            .iter()
            .filter(|(_, c)| c.dead || (!c.busy() && now.saturating_sub(c.last_used) >= ANON_IDLE_MS))
            .map(|(sid, _)| sid.clone())
            .collect();
        let mut back_off: HashSet<String> = HashSet::new();
        let mut redialed_now: HashSet<String> = HashSet::new();
        for sid in closing {
            let Some(mut conn) = self.anon_conns.remove(&sid) else { continue };
            let in_flight: Vec<ServerInflight> = conn.inflight.drain().map(|(_, i)| i).collect();
            let queue = std::mem::take(&mut conn.queue);
            let list = lost.entry(sid.clone()).or_default();
            list.extend(in_flight);
            if !conn.dead || (queue.is_empty() && list.is_empty()) {
                continue;
            }
            if !conn.redialed {
                if let Some(mut fresh) = self.open_anon_conn(&sid) {
                    info!("Anonymous server connection broke, dialing once more");
                    fresh.redialed = true;
                    fresh.queue = queue;
                    redialed_now.insert(sid.clone());
                    self.anon_conns.insert(sid, fresh);
                    continue;
                }
            }
            back_off.insert(sid.clone());
            list.extend(queue.into_iter().map(|(_, i)| i));
        }
        // A request lost on a connection that is still up (its timeout): one step for that server too.
        for (sid, list) in &lost {
            if !redialed_now.contains(sid) && list.iter().any(|i| matches!(i, ServerInflight::Deposit { .. })) {
                back_off.insert(sid.clone());
            }
        }
        // Before the requeue below, so a backed-off server takes none of it.
        for sid in &back_off {
            if let Some(rt) = self.server_rt.get_mut(sid) {
                Self::back_off_deposits(rt);
            }
        }
        let mut no_incoming = Vec::new();
        for (inflight, response) in done {
            self.handle_server_response(inflight, response, &mut no_incoming);
        }
        for inflight in lost.into_values().flatten() {
            self.handle_server_failure_with(inflight, false);
        }
    }

    /// Every deposit and cancel queued or in flight, on any anonymous connection.
    pub(super) fn anon_inflight_mut(&mut self) -> impl Iterator<Item = &mut ServerInflight> {
        self.anon_conns
            .values_mut()
            .flat_map(|c| c.queue.iter_mut().map(|(_, i)| i).chain(c.inflight.values_mut()))
    }

    /// A deposit or cancel is queued or in flight: real work for a bounded time (the dial and request timeouts).
    pub(crate) fn anon_busy(&self) -> bool {
        self.anon_conns.values().any(AnonConn::busy)
    }
}

/// Events taken from one anonymous swarm per `poll_events` turn.
const MAX_ANON_EVENTS_PER_TURN: usize = 64;
