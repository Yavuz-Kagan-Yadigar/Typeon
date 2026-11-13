//! Tor onion service integration, so that devices behind CGNAT can reach each other.
//! Scope of v1: REACHABILITY only (see the SECURITY.md "Tor onion" note). The real IP can still be seen through `identify`. Full anonymity
//! (suppressing identify and also routing outgoing traffic through Tor) is left for v2.
//!
//! Architecture:
//! - **Host (being reachable):** an onion service is started with `arti-client`. Each inbound Tor stream (rendezvous) is bridged to the
//!   local libp2p TCP listener (`127.0.0.1:<port>`). The libp2p swarm therefore sees it as an ordinary inbound TCP connection and does not
//!   need to know that it came over Tor. No separate libp2p listener transport is written.
//! - **Dial (connecting to a peer's .onion):** a separate libp2p `Transport` (`ArtiDialTransport`, below) dials `/onion3/...` addresses
//!   over Tor with `TorClient::connect`.
//!
//! rustls is used instead of native-tls (to avoid openssl). arti's rustls uses `ring`, which this project already cross-compiles
//! (see the note in Cargo.toml).

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorAddr, TorClient};
use futures::future::BoxFuture;
use futures::{AsyncRead, AsyncWrite, StreamExt as _};
use libp2p::core::multiaddr::Protocol;
use libp2p::core::transport::{ListenerId, TransportError, TransportEvent};
use libp2p::{Multiaddr, Transport};
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_proto::stream::IncomingStreamRequest;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::handle_rend_requests;
use tor_rtcompat::tokio::TokioRustlsRuntime;

/// Fixed nickname for the persistent .onion identity. The same nickname gives the same keystore key, so the device keeps the SAME
/// .onion address across restarts (the Tor counterpart of PeerId persistence).
const ONION_NICKNAME: &str = "p2pmsg";

/// Current Tor state, shown in the UI (see `tor_status` in network.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorStatus {
    /// Off (the user did not enable Tor).
    Disabled,
    /// arti is bootstrapping (downloading the Tor network consensus). On first launch this can take several seconds.
    Bootstrapping,
    /// Ready: bootstrap is complete AND the onion service is published, so a .onion address exists.
    Ready,
    /// Failed (bootstrap or onion error). See logcat.
    Failed,
}

impl TorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TorStatus::Disabled => "disabled",
            TorStatus::Bootstrapping => "bootstrapping",
            TorStatus::Ready => "ready",
            TorStatus::Failed => "failed",
        }
    }
}

/// Sets a bootstrap result, except over `Failed`. `Failed` means the inbound bridge ended, and a later bootstrap does not bring it back.
fn set_status(status: &Mutex<TorStatus>, new: TorStatus) {
    let mut s = status.lock().unwrap_or_else(|p| p.into_inner());
    if *s != TorStatus::Failed {
        *s = new;
    }
}

/// Maximum number of inbound onion streams bridged at once. A peer needs one per connection.
const MAX_INBOUND_ONION_STREAMS: usize = 64;
/// Maximum number of inbound streams one rendezvous circuit may hold open. Our dialer opens a fresh circuit per connection, so
/// 8 streams per circuit let 8 circuits fill all 64 slots.
const MAX_STREAMS_PER_CIRCUIT: u32 = 3;
/// A bridged stream that sends nothing for this long is closed. libp2p's dialer speaks first, and a silent stream held its slot
/// for the 60 s upgrade timeout.
const INBOUND_FIRST_BYTE_SECS: u64 = 15;

/// Shared handle to the running Tor layer. The `TorClient` is also used by the dial transport (see `ArtiDialTransport`), hence the `Arc`.
pub struct TorHandle {
    pub client: Arc<TorClient<TokioRustlsRuntime>>,
    status: Arc<Mutex<TorStatus>>,
    onion_addr: Arc<Mutex<Option<String>>>,
    /// Keeps the onion service alive (dropping it stops the service).
    _service: Arc<tor_hsservice::RunningOnionService>,
    /// A `notify_network_changed` retry loop is running.
    rebootstrapping: Arc<std::sync::atomic::AtomicBool>,
}

impl TorHandle {
    /// Current state.
    pub fn status(&self) -> TorStatus {
        *self.status.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The published .onion host name (for example "abcd...xyz.onion"), or None if not computed yet. This is ONLY the host name.
    /// network.rs `get_node_address` builds the full libp2p multiaddr (`/dns/<host>/tcp/<port>/p2p/<peer_id>`).
    pub fn onion_host(&self) -> Option<String> {
        self.onion_addr.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Called when the network interface changes (Wi-Fi drops and comes back, or a switch to cellular).
    /// arti 0.24 has no clean public API for "the network changed, retry NOW". The reactor recovers on its own timers, within minutes.
    /// What this does is call `bootstrap()` again in the background. If already bootstrapped, arti documents this as a no-op. If the bootstrap
    /// state regressed during an outage, it rebuilds it and captures the `.onion` name again. At worst it is a cheap call.
    /// (The client side already re-dials peers on `notifyNetworkChanged`. This is the matching step for refreshing the server's onion.)
    /// Radio saver: `Soft` stops our channel padding (relays already received STOP from `PaddingLevel::Reduced`) and arti's periodic tasks,
    /// so an idle LTE radio can sleep between windows. `false` restarts the tasks.
    pub fn set_dormant(&self, dormant: bool) {
        use arti_client::DormantMode;
        self.client.set_dormant(if dormant { DormantMode::Soft } else { DormantMode::Normal });
    }

    pub fn notify_network_changed(&self) {
        use std::sync::atomic::Ordering;
        // Only one loop at a time. It runs until the bootstrap holds.
        if self.rebootstrapping.swap(true, Ordering::SeqCst) {
            return;
        }
        // Weak reference: the loop ends once the handle (and the swarm) drop the client.
        let client = Arc::downgrade(&self.client);
        let status = self.status.clone();
        let running = self.rebootstrapping.clone();
        tokio::spawn(async move {
            // Retries like the launch loop. Before, one failed attempt left the status at "bootstrapping" until the next network change,
            // even after arti had recovered by itself.
            let mut delay = std::time::Duration::from_secs(2);
            loop {
                let Some(client) = client.upgrade() else { break };
                match client.bootstrap().await {
                    Ok(()) => {
                        set_status(&status, TorStatus::Ready);
                        log::info!("Tor: ağ değişikliği sonrası bootstrap teyit edildi");
                        break;
                    }
                    Err(e) => {
                        set_status(&status, TorStatus::Bootstrapping);
                        log::warn!("Tor: ağ değişikliği sonrası bootstrap henüz tamam değil ({delay:?} sonra yeniden): {e}");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(std::time::Duration::from_secs(60));
                    }
                }
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    /// Starts the Tor layer. It creates the arti client, bootstraps in the background, starts the onion service, and spawns the task that
    /// bridges inbound streams to the local `local_port`. Must be called INSIDE a tokio context (`RUNTIME.enter()` / `block_on` provides it),
    /// because `TokioRustlsRuntime::current()` needs the active tokio handle.
    ///
    /// `state_dir` / `cache_dir`: arti's key store and consensus cache, under the app's private directory. `local_port`: the fixed TCP port
    /// libp2p listens on (see the fixed-port setting in network.rs).
    pub fn launch(state_dir: &str, cache_dir: &str, local_port: u16) -> Result<TorHandle, String> {
        let runtime = TokioRustlsRuntime::current()
            .map_err(|e| format!("TokioRustlsRuntime alınamadı: {e}"))?;

        trim_dir_cache(cache_dir);

        // A power loss mid-write can leave a state file (guards, intro points) that arti refuses on every start, and the onion service then never
        // comes back. That state is a network cache. The onion identity lives in `keystore/`, which is kept. The bad state is set aside once, then
        // startup is tried again.
        // The error decides whether the state may be at fault. An I/O error, a lock still held, or a permission problem is not, and clearing the
        // state for those only threw away the chosen guards.
        use arti_client::{ErrorKind, HasKind};
        let state_suspect = |e: &arti_client::Error| {
            !matches!(e.kind(), ErrorKind::PersistentStateAccessFailed | ErrorKind::LocalResourceAlreadyInUse | ErrorKind::FsPermissions)
        };
        let start = || -> Result<_, (String, bool)> {
            let client = TorClient::with_runtime(runtime.clone())
                .config(client_config(state_dir, cache_dir).map_err(|e| (e, false))?)
                .create_unbootstrapped()
                .map_err(|e| (format!("Arti client: {e}"), state_suspect(&e)))?;
            let nickname: tor_hsservice::HsNickname = ONION_NICKNAME
                .parse()
                .map_err(|e| (format!("Onion nickname: {e}"), false))?;
            // One libp2p connection is one stream, and a redialing peer needs a few. Without this cap, one rendezvous circuit could take all
            // `MAX_INBOUND_ONION_STREAMS` slots (the arti default is 65535).
            let svc_config = OnionServiceConfigBuilder::default()
                .nickname(nickname)
                .max_concurrent_streams_per_circuit(MAX_STREAMS_PER_CIRCUIT)
                .build()
                .map_err(|e| (format!("Onion config: {e}"), false))?;
            let (service, rend_requests) = client
                .launch_onion_service(svc_config)
                .map_err(|e| (format!("Onion service başlatılamadı: {e}"), state_suspect(&e)))?;
            Ok((client, service, rend_requests))
        };
        // Every error kind other than "corrupted data in persistent state" is handled as well. Otherwise another kind of corruption would skip
        // recovery and fail every start. The old state is kept aside and restored if the clean start fails too.
        let (client, service, rend_requests) = match start() {
            Err((e, false)) => return Err(e),
            Err((e, true)) => {
                log::warn!("Tor: start failed, state set aside, retrying once ({e})");
                let dirs = ["state", "hss"].map(|d| std::path::Path::new(state_dir).join(d));
                for dir in &dirs {
                    let bak = dir.with_extension("bak");
                    let _ = std::fs::remove_dir_all(&bak);
                    let _ = std::fs::rename(dir, &bak);
                }
                match start() {
                    Ok(v) => v,
                    Err((e, _)) => {
                        for dir in &dirs {
                            let _ = std::fs::remove_dir_all(dir);
                            let _ = std::fs::rename(dir.with_extension("bak"), dir);
                        }
                        return Err(e);
                    }
                }
            }
            Ok(v) => v,
        };
        let client = Arc::new(client);

        let status = Arc::new(Mutex::new(TorStatus::Bootstrapping));
        let onion_addr = Arc::new(Mutex::new(None::<String>));
        // The launch loop also holds this flag, so a network change does not start a second loop next to it.
        let rebootstrapping = Arc::new(std::sync::atomic::AtomicBool::new(true));

        // Capture the .onion name right away, if it exists.
        if let Some(hsid) = service.onion_name() {
            *onion_addr.lock().unwrap_or_else(|p| p.into_inner()) = Some(hsid.to_string());
        }

        // Background: bootstrap with retries. Before, bootstrap was tried ONCE, and on failure the status stayed `Failed` forever. Only an app restart
        // or a Tor off/on cycle recovered it, so a temporary network problem caused a permanent "Tor not working" state. Now it retries with exponential
        // backoff (starting at 2 s, capped at 60 s) until it SUCCEEDS. `bootstrap()` is idempotent (arti documents a no-op if already bootstrapped),
        // so calling it repeatedly is harmless.
        {
            // Weak reference: dropping the handle ends the loop, instead of retrying every 60 s forever with a dead client.
            let client_bg = Arc::downgrade(&client);
            let status_bg = status.clone();
            let service_bg = Arc::downgrade(&service);
            let onion_bg = onion_addr.clone();
            let running = rebootstrapping.clone();
            tokio::spawn(async move {
                let mut delay = std::time::Duration::from_secs(2);
                loop {
                    let (Some(client_bg), Some(service_bg)) = (client_bg.upgrade(), service_bg.upgrade()) else { break };
                    match client_bg.bootstrap().await {
                        Ok(()) => {
                            // The .onion name is guaranteed to exist after a successful bootstrap.
                            if let Some(hsid) = service_bg.onion_name() {
                                *onion_bg.lock().unwrap_or_else(|p| p.into_inner()) = Some(hsid.to_string());
                            }
                            set_status(&status_bg, TorStatus::Ready);
                            log::info!("Tor: bootstrap tamam, onion service yayında");
                            break;
                        }
                        Err(e) => {
                            // Still retrying: same status as the notify loop.
                            set_status(&status_bg, TorStatus::Bootstrapping);
                            log::error!("Tor bootstrap başarısız ({delay:?} sonra yeniden denenecek): {e}");
                            drop((client_bg, service_bg));
                            tokio::time::sleep(delay).await;
                            delay = (delay * 2).min(std::time::Duration::from_secs(60));
                        }
                    }
                }
                running.store(false, std::sync::atomic::Ordering::SeqCst);
            });
        }

        // Background: bridge inbound onion streams to the local libp2p TCP port.
        {
            let status_br = status.clone();
            tokio::spawn(async move {
                // Anyone who knows the .onion can open streams, and each one costs a task, a socket, and a libp2p upgrade that the swarm
                // sees as 127.0.0.1. Requests over the cap are dropped.
                let slots = Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND_ONION_STREAMS));
                let mut stream_requests = Box::pin(handle_rend_requests(rend_requests));
                while let Some(stream_request) = stream_requests.next().await {
                    let Ok(slot) = slots.clone().try_acquire_owned() else {
                        log::warn!("Tor: gelen akış sınırı dolu, istek düşürüldü");
                        continue;
                    };
                    tokio::spawn(async move {
                        bridge_incoming_stream(stream_request, local_port).await;
                        drop(slot);
                    });
                }
                // The inbound path is gone, so stop reporting Ready.
                *status_br.lock().unwrap_or_else(|p| p.into_inner()) = TorStatus::Failed;
                log::info!("Tor: gelen akış köprüsü sonlandı");
            });
        }

        Ok(TorHandle {
            client,
            status,
            onion_addr,
            _service: service,
            rebootstrapping,
        })
    }
}

/// The arti config.
///
/// Channel padding doubles as the NAT keepalive, so its interval decides the standby cost of a phone on mobile data (each packet keeps
/// LTE awake for about 10 s). Measured on the Note 9S over LTE, half an hour idle:
/// Normal (a cell per idle guard channel every 1.5-9.5 s): 4.4 MB, radio awake 92%, 35 mAh.
/// Reduced (9-14 s): 87%, 33.5 mAh.
/// None: the carrier NAT dropped the idle guard channel. Every peer link died within a minute, and the redials (onion circuit builds)
/// kept the radio up anyway (37 mAh).
/// So: Reduced, with its idle timeout stretched to 225-245 s (see `client_config`; the vendored tor-netdir lifts arti's 60 s cap).
///
/// arti keeps every hourly consensus (about 3.3 MB) for 4 days past expiry, so dir_blobs grows to about 150-330 MB. The retention is a private
/// constant in tor-dirmgr, so before arti opens the cache we keep only the two newest consensuses per flavour (the latest plus one diff base).
/// Best effort.
fn trim_dir_cache(cache_dir: &str) {
    let dir = std::path::Path::new(cache_dir);
    // READ_WRITE without CREATE: if there is no cache yet there is nothing to trim, and arti must create its own schema.
    let Ok(conn) = rusqlite::Connection::open_with_flags(dir.join("dir.sqlite3"), rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) else {
        return;
    };
    let files = (|| -> rusqlite::Result<Vec<String>> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let q = "SELECT filename FROM ExtDocs e WHERE type LIKE 'con%' AND \
                 (SELECT COUNT(*) FROM ExtDocs n WHERE n.type = e.type AND n.created > e.created) >= 2";
        let names: Vec<String> = conn.prepare(q)?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        // Bare file names only. The name comes from a database row, and `..` or an absolute path would delete files outside `dir_blobs`.
        // Rows with other names are kept, so a row and its file are removed together.
        let names: Vec<String> =
            names.into_iter().filter(|f| std::path::Path::new(f).file_name() == Some(std::ffi::OsStr::new(f))).collect();
        let tx = conn.unchecked_transaction()?;
        for n in &names {
            tx.execute("DELETE FROM ExtDocs WHERE filename = ?", [n])?;
        }
        tx.commit()?;
        Ok(names)
    })();
    let files = match files {
        Ok(f) => f,
        Err(e) => {
            log::warn!("Tor dizin önbelleği budanamadı: {e}");
            return;
        }
    };
    for f in &files {
        let _ = std::fs::remove_file(dir.join("dir_blobs").join(f));
    }
    if !files.is_empty() {
        log::info!("Tor dizin önbelleği budandı: {} eski konsensüs silindi", files.len());
    }
}

fn client_config(state_dir: &str, cache_dir: &str) -> Result<arti_client::TorClientConfig, String> {
    let mut config = TorClientConfigBuilder::from_directories(state_dir, cache_dir);
    // The circuit build timeout is learned by measurement in arti. A short value learned on fast Wi-Fi made many circuits give up before
    // completing after a switch to mobile data (on the device: an onion dial timed out after 6 s with "tor operation timed out", and recovery took 20-120 s).
    // Learning stays on. Only the lower bound is set here.
    // 20 s: an extend is budgeted 4/6 of this (3 to 4 hops). At 10 s, the ~6.7 s extend to a slow intro point over LTE timed out every try,
    // and each IPT status change re-uploaded the descriptor to 16 HSDirs (about 130 KB) once a minute.
    config.override_net_params().insert("cbtmintimeout".to_string(), 20_000);
    // 225-245 s: the carrier NAT kept an idle TCP connection to both guards for 290 s (9S over LTE; closed at 300 s). At 45-55 s, the
    // padding cell alone woke the LTE radio once a minute. arti caps the value at 60 s, hence the vendored tor-netdir.
    config.override_net_params().insert("nf_ito_low_reduced".to_string(), 225_000);
    config.override_net_params().insert("nf_ito_high_reduced".to_string(), 245_000);
    // No preemptive exit circuits. The app only dials onion services, but arti keeps circuits for ports 80/443 warm by default, which is
    // pure radio and battery cost.
    config.preemptive_circuits().initial_predicted_ports().clear();
    config.channel().padding(tor_config::PaddingLevel::Reduced);
    config.build().map_err(|e| format!("Arti config: {e}"))
}

/// Accepts one inbound onion stream and bridges it both ways to the local libp2p TCP listener (`127.0.0.1:<local_port>`).
/// `DataStream` implements both tokio and futures AsyncRead/Write, so `tokio::io::copy_bidirectional` can be used directly.
async fn bridge_incoming_stream(stream_request: tor_hsservice::StreamRequest, local_port: u16) {
    // Only BEGIN to our virtual port (the one we publish, = `local_port`) is accepted. Anything else gets DONE, as arti advises, so the
    // rejection looks like any onion service's.
    if !matches!(stream_request.request(), IncomingStreamRequest::Begin(b) if b.port() == local_port) {
        let _ = stream_request.reject(End::new_with_reason(EndReason::DONE)).await;
        return;
    }
    let mut tor_stream = match stream_request.accept(Connected::new_empty()).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Tor: gelen akış kabul edilemedi: {e}");
            return;
        }
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut first = [0u8; 512];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(INBOUND_FIRST_BYTE_SECS), tor_stream.read(&mut first)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return,
    };
    let mut tcp = match tokio::net::TcpStream::connect(("127.0.0.1", local_port)).await {
        Ok(t) => t,
        Err(e) => {
            log::error!("Tor: yerel libp2p portuna ({local_port}) bağlanılamadı: {e}");
            return;
        }
    };
    if tcp.write_all(&first[..n]).await.is_err() {
        return;
    }

    // Copy both ways until the connection closes. DataStream implements tokio AsyncRead/Write (the tor-proto tokio feature).
    if let Err(e) = tokio::io::copy_bidirectional(&mut tor_stream, &mut tcp).await {
        log::debug!("Tor köprü akışı sonlandı: {e}");
    }
}

// ---------------------------------------------------------------------------
// Dial transport: opens a libp2p connection to a peer's `.onion` address.
// ---------------------------------------------------------------------------

/// Extracts (host, port) from a multiaddr of the form `/dns/<host>.onion/tcp/<port>`, ONLY if the host ends in `.onion`. This transport
/// takes responsibility for onion addresses only. For everything else it returns `MultiaddrNotSupported`, and `OrTransport` falls back to the
/// normal TCP path (see the swarm setup in network.rs).
fn onion_host_port(addr: &Multiaddr) -> Option<(String, u16)> {
    let mut it = addr.iter();
    let host = match it.next()? {
        Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) => h.to_string(),
        _ => return None,
    };
    let port = match it.next()? {
        Protocol::Tcp(p) => p,
        _ => return None,
    };
    if host.ends_with(".onion") {
        Some((host, port))
    } else {
        None
    }
}

/// libp2p `DataStream` (arti) wrapper. It converts arti's tokio AsyncRead/Write into the futures AsyncRead/Write that libp2p expects
/// (adapted from libp2p-community-tor provider.rs).
pub struct TorStream {
    inner: DataStream,
}

impl AsyncRead for TorStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        let mut read_buf = ReadBuf::new(buf);
        futures::ready!(TokioAsyncRead::poll_read(Pin::new(&mut self.inner), cx, &mut read_buf))?;
        Poll::Ready(Ok(read_buf.filled().len()))
    }
}

impl AsyncWrite for TorStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        TokioAsyncWrite::poll_write(Pin::new(&mut self.inner), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        TokioAsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        TokioAsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

/// libp2p transport that dials ONLY `.onion` addresses, over Tor. `listen_on` is not supported: inbound connections come through the onion
/// service bridge to the local TCP listener (see `bridge_incoming_stream`).
///
/// `client` is `Option` ON PURPOSE. The transport is added to the swarm even when Tor is off (one swarm setup path, see `start_network` in
/// network.rs). When it is `None`, every dial returns `MultiaddrNotSupported`, which is correct because no `.onion` address exists while Tor is off.
/// That avoids a conditional or double build path.
#[derive(Clone)]
pub struct ArtiDialTransport {
    client: Option<Arc<TorClient<TokioRustlsRuntime>>>,
}

impl ArtiDialTransport {
    pub fn new(client: Option<Arc<TorClient<TokioRustlsRuntime>>>) -> Self {
        ArtiDialTransport { client }
    }
}

impl Transport for ArtiDialTransport {
    type Output = TorStream;
    type Error = std::io::Error;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;
    type ListenerUpgrade = futures::future::Pending<Result<Self::Output, Self::Error>>;

    fn listen_on(&mut self, _id: ListenerId, addr: Multiaddr) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        // Tor off (client is None): we do not take this address, and OrTransport falls back to TCP. Also not taken if it is NOT `.onion`.
        let client = match &self.client {
            Some(c) => c.clone(),
            None => return Err(TransportError::MultiaddrNotSupported(addr)),
        };
        let (host, port) = onion_host_port(&addr).ok_or(TransportError::MultiaddrNotSupported(addr))?;
        let tor_addr = TorAddr::from((host.as_str(), port))
            .map_err(|e| TransportError::Other(std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())))?;
        Ok(Box::pin(async move {
            // EVERY dial gets its own Tor circuit.
            //
            // With the default isolation, arti puts all streams opened through the same `TorClient` on the SAME circuit. One circuit is the measured
            // ceiling in this app: the same 14 MB file, the same code, and the same devices gave 270 KB/s on one circuit and 165 KB/s on another. The
            // bottleneck was the circuit itself. A circuit per connection lets bandwidth add up when bulk transfer opens several connections
            // (see `BULK_PARALLEL_CONNECTIONS`). With a single circuit, parallel connections would gain nothing.
            //
            // This means a circuit per CONNECTION, not per STREAM. A libp2p connection already multiplexes many streams over yamux, so each peer
            // gets a few circuits. This is not the `isolate_every_stream` overhead that arti warns about.
            let mut prefs = arti_client::StreamPrefs::new();
            prefs.set_isolation(arti_client::IsolationToken::new());
            let stream = client
                .connect_with_prefs(tor_addr, &prefs)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            Ok(TorStream { inner: stream })
        }))
    }

    fn dial_as_listener(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.dial(addr)
    }

    fn address_translation(&self, _listen: &Multiaddr, _observed: &Multiaddr) -> Option<Multiaddr> {
        None
    }

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

/// Wrapper that keeps the transport for INBOUND connections only and rejects EVERY `dial`. It is the transport-layer anchor of the onion-only guarantee.
///
/// The TCP transport cannot be removed from the swarm entirely: the onion service bridge (`bridge_incoming_stream`) connects inbound Tor streams to
/// `127.0.0.1:<port>`, so a local TCP listener is required. But an outgoing TCP dial connects directly to a peer's REAL IP (clearnet) and breaks Tor
/// anonymity (deanonymization: a pentest found UPnP and direct SYNs to `:42611`). This wrapper makes TCP listen-only: `listen_on` and inbound
/// streams pass through unchanged, and `dial` / `dial_as_listener` always return `MultiaddrNotSupported`. So all outgoing traffic goes through
/// `ArtiDialTransport` (onion) or the relay (over onion). libp2p can never dial a peer's clearnet address directly, no matter who calls
/// `swarm.dial()` (kad and identify included).
#[derive(Clone)]
pub struct DialReject<T>(pub T);

impl<T> Transport for DialReject<T>
where
    T: Transport + Unpin,
{
    type Output = T::Output;
    type Error = T::Error;
    type Dial = T::Dial;
    type ListenerUpgrade = T::ListenerUpgrade;

    fn listen_on(&mut self, id: ListenerId, addr: Multiaddr) -> Result<(), TransportError<Self::Error>> {
        self.0.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.0.remove_listener(id)
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn dial_as_listener(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn address_translation(&self, listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        self.0.address_translation(listen, observed)
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}

#[cfg(test)]
mod trim_tests {
    #[test]
    fn keeps_two_newest_consensuses() {
        let dir = std::env::temp_dir().join(format!("trim_{}", std::process::id()));
        std::fs::create_dir_all(dir.join("dir_blobs")).unwrap();
        let conn = rusqlite::Connection::open(dir.join("dir.sqlite3")).unwrap();
        conn.execute_batch("CREATE TABLE ExtDocs (digest TEXT PRIMARY KEY, created DATE, expires DATE, type TEXT, filename TEXT);").unwrap();
        for (i, t) in ["con:microdesc"; 4].iter().chain(["other"].iter()).enumerate() {
            let f = format!("f{i}");
            std::fs::write(dir.join("dir_blobs").join(&f), b"x").unwrap();
            conn.execute("INSERT INTO ExtDocs VALUES (?1, ?2, '2099-01-01', ?3, ?1)", rusqlite::params![f, format!("2026-01-0{} 00:00:00", i + 1), t]).unwrap();
        }
        drop(conn);
        super::trim_dir_cache(dir.to_str().unwrap());
        let left: Vec<bool> = (0..5).map(|i| dir.join("dir_blobs").join(format!("f{i}")).exists()).collect();
        assert_eq!(left, [false, false, true, true, true]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
