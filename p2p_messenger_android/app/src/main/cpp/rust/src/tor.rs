//! Tor onion service integration. The node is onion-only: every connection in and out goes over Tor.
//!
//! Architecture:
//! - **Host (being reachable):** an onion service is started with `arti-client`. Each inbound Tor stream (rendezvous) is handed to the
//!   swarm in-process through `OnionListen`, a listen-only libp2p transport fed by a channel. No TCP port is opened, so no other app or
//!   user on this machine can reach the swarm.
//! - **Dial (connecting to a peer's .onion):** a separate libp2p `Transport` (`ArtiDialTransport`, below) dials
//!   `/dns/<host>.onion/tcp/<port>` addresses over Tor with `TorClient::connect`.
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

/// Current Tor state, shown in the UI (see `tor_status` in network/power.rs).
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

/// Sets a bootstrap result, except over `Failed`. `Failed` means the inbound bridge ended. Only its relaunch (see `launch`) leaves it.
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
/// An inbound connection must finish Noise and Yamux within this time after its first byte. Half the outgoing timeout: the
/// rendezvous circuit is already built, and a stream that stalls mid-handshake held its slot for the full 60 s.
pub const INBOUND_UPGRADE_SECS: u64 = 30;
/// Inbound streams waiting for the swarm to take them.
const INBOUND_QUEUE: usize = 16;

/// Shared handle to the running Tor layer. The `TorClient` is also used by the dial transport (see `ArtiDialTransport`), hence the `Arc`.
pub struct TorHandle {
    pub client: Arc<TorClient<TokioRustlsRuntime>>,
    status: Arc<Mutex<TorStatus>>,
    onion_addr: Arc<Mutex<Option<String>>>,
    /// Keeps the onion service alive (dropping it stops the service). The bridge task swaps in a relaunched one.
    _service: Arc<Mutex<Option<Arc<tor_hsservice::RunningOnionService>>>>,
    /// A `notify_network_changed` retry loop is running.
    rebootstrapping: Arc<std::sync::atomic::AtomicBool>,
}

impl TorHandle {
    /// Current state.
    pub fn status(&self) -> TorStatus {
        *self.status.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The published .onion host name (for example "abcd...xyz.onion"), or None if not computed yet. This is ONLY the host name.
    /// `get_node_address` (network/power.rs) builds the full libp2p multiaddr (`/dns/<host>/tcp/<port>/p2p/<peer_id>`).
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
                        log::info!("Tor: bootstrap confirmed after network change");
                        break;
                    }
                    Err(e) => {
                        set_status(&status, TorStatus::Bootstrapping);
                        log::warn!("Tor: bootstrap not complete after network change (retrying in {delay:?}): {e}");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(std::time::Duration::from_secs(60));
                    }
                }
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    /// Starts the Tor layer. It creates the arti client, bootstraps in the background, starts the onion service, and spawns the task that
    /// hands inbound streams to the swarm. Must be called INSIDE a tokio context (`RUNTIME.enter()` / `block_on` provides it),
    /// because `TokioRustlsRuntime::current()` needs the active tokio handle.
    ///
    /// `state_dir` / `cache_dir`: arti's key store and consensus cache, under the app's private directory. `onion_port`: the virtual port
    /// of the onion service (the one in our `.onion` address). The returned `OnionListen` goes into the swarm's transport.
    pub fn launch(state_dir: &str, cache_dir: &str, onion_port: u16) -> Result<(TorHandle, OnionListen), String> {
        let runtime = TokioRustlsRuntime::current()
            .map_err(|e| format!("TokioRustlsRuntime could not be obtained: {e}"))?;

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
            let svc_config = onion_service_config().map_err(|e| (e, false))?;
            let (service, rend_requests) = client
                .launch_onion_service(svc_config)
                .map_err(|e| (format!("Onion service could not be started: {e}"), state_suspect(&e)))?;
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
        let service = Arc::new(Mutex::new(Some(service)));

        let status = Arc::new(Mutex::new(TorStatus::Bootstrapping));
        let onion_addr = Arc::new(Mutex::new(None::<String>));
        // The launch loop also holds this flag, so a network change does not start a second loop next to it.
        let rebootstrapping = Arc::new(std::sync::atomic::AtomicBool::new(true));

        // Capture the .onion name right away, if it exists.
        let name = service.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(|s| s.onion_name());
        if let Some(hsid) = name {
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
                            // Over a bridge, a directory loaded from the cache finishes `bootstrap` before any channel to
                            // a bridge exists. Ready (and the dials it starts) waits until arti can carry traffic.
                            if PT_SETUP.lock().unwrap_or_else(|p| p.into_inner()).is_some() {
                                use futures::StreamExt;
                                let mut events = client_bg.bootstrap_events();
                                while !client_bg.bootstrap_status().ready_for_traffic() {
                                    if events.next().await.is_none() {
                                        break;
                                    }
                                }
                            }
                            // The .onion name is guaranteed to exist after a successful bootstrap.
                            let name = service_bg.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(|s| s.onion_name());
                            if let Some(hsid) = name {
                                *onion_bg.lock().unwrap_or_else(|p| p.into_inner()) = Some(hsid.to_string());
                            }
                            set_status(&status_bg, TorStatus::Ready);
                            log::info!("Tor: bootstrap done, onion service published");
                            break;
                        }
                        Err(e) => {
                            // Still retrying: same status as the notify loop.
                            set_status(&status_bg, TorStatus::Bootstrapping);
                            log::error!("Tor bootstrap failed (retrying in {delay:?}): {e}");
                            drop((client_bg, service_bg));
                            tokio::time::sleep(delay).await;
                            delay = (delay * 2).min(std::time::Duration::from_secs(60));
                        }
                    }
                }
                running.store(false, std::sync::atomic::Ordering::SeqCst);
            });
        }

        // Background: hand inbound onion streams to the swarm (`OnionListen`).
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<TorStream>(INBOUND_QUEUE);
        {
            let status_br = status.clone();
            let client_br = Arc::downgrade(&client);
            let service_br = Arc::downgrade(&service);
            tokio::spawn(async move {
                // Anyone who knows the .onion can open streams, and each one costs a task and a libp2p upgrade. Requests over the cap are
                // dropped. A slot is held until the connection closes.
                let slots = Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND_ONION_STREAMS));
                let mut stream_requests = Box::pin(handle_rend_requests(rend_requests));
                let mut delay = std::time::Duration::from_secs(5);
                loop {
                    while let Some(stream_request) = stream_requests.next().await {
                        let Ok(slot) = slots.clone().try_acquire_owned() else {
                            log::warn!("Tor: incoming stream limit reached, request dropped");
                            continue;
                        };
                        let tx = inbound_tx.clone();
                        tokio::spawn(bridge_incoming_stream(stream_request, onion_port, slot, tx));
                    }
                    // The inbound path is gone, so stop reporting Ready, and launch the service again (same nickname, same .onion).
                    // Before, nothing restarted it, and nobody could dial this device until the process restarted.
                    *status_br.lock().unwrap_or_else(|p| p.into_inner()) = TorStatus::Failed;
                    loop {
                        log::warn!("Tor: incoming stream bridge ended, relaunching the onion service in {delay:?}");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(std::time::Duration::from_secs(600));
                        // The handle was dropped: the network is shut down.
                        let (Some(client), Some(slot)) = (client_br.upgrade(), service_br.upgrade()) else { return };
                        // The old service must be gone before a new one takes its state.
                        drop(slot.lock().unwrap_or_else(|p| p.into_inner()).take());
                        let launched = onion_service_config()
                            .and_then(|cfg| client.launch_onion_service(cfg).map_err(|e| e.to_string()));
                        match launched {
                            Ok((svc, rr)) => {
                                *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(svc);
                                stream_requests = Box::pin(handle_rend_requests(rr));
                                *status_br.lock().unwrap_or_else(|p| p.into_inner()) = TorStatus::Ready;
                                delay = std::time::Duration::from_secs(5);
                                log::info!("Tor: onion service relaunched");
                                break;
                            }
                            Err(e) => log::error!("Tor: onion service relaunch failed: {e}"),
                        }
                    }
                }
            });
        }

        let listen = OnionListen {
            rx: inbound_rx,
            listener: None,
            announced: false,
            addr: format!("/ip4/127.0.0.1/tcp/{onion_port}").parse().map_err(|_| "bad listen label".to_string())?,
        };
        Ok((TorHandle { client, status, onion_addr, _service: service, rebootstrapping }, listen))
    }
}

/// The onion service config. One libp2p connection is one stream, and a redialing peer needs a few. Without the per-circuit cap, one
/// rendezvous circuit could take all `MAX_INBOUND_ONION_STREAMS` slots (the arti default is 65535).
fn onion_service_config() -> Result<tor_hsservice::OnionServiceConfig, String> {
    let nickname: tor_hsservice::HsNickname = ONION_NICKNAME.parse().map_err(|e| format!("Onion nickname: {e}"))?;
    OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .max_concurrent_streams_per_circuit(MAX_STREAMS_PER_CIRCUIT)
        .build()
        .map_err(|e| format!("Onion config: {e}"))
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
            log::warn!("Tor directory cache could not be pruned: {e}");
            return;
        }
    };
    for f in &files {
        let _ = std::fs::remove_file(dir.join("dir_blobs").join(f));
    }
    if !files.is_empty() {
        log::info!("Tor directory cache pruned: {} old consensus files deleted", files.len());
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
    // Bridges: arti picks its guards from these bridges only, so the onion service's intro and rendezvous
    // circuits go through them as well. run_on_startup = false: the PT process starts on the first channel
    // to a bridge, never in Direct mode. Direct (None) adds nothing here.
    if let Some(pt) = PT_SETUP.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        use arti_client::config::pt::TransportConfigBuilder;
        // The first hop runs through the transport (Snowflake: broker, proxy, WebRTC). At 20 s the circuit
        // timeout cut the bridge channel before it opened, over and over (see the vendored tor-chanmgr).
        config.override_net_params().insert("cbtmintimeout".to_string(), 60_000);
        use arti_client::config::{BridgeConfigBuilder, CfgPath};
        for line in &pt.lines {
            let bridge = line.parse::<BridgeConfigBuilder>().map_err(|e| format!("Bridge line: {e}"))?;
            config.bridges().bridges().push(bridge);
        }
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec![pt.protocol.parse::<arti_client::config::PtTransportName>().map_err(|e| format!("Transport name: {e}"))?])
            .path(CfgPath::new_literal(pt.binary.clone()))
            .run_on_startup(false);
        config.bridges().transports().push(transport);
    }
    config.build().map_err(|e| format!("Arti config: {e}"))
}

// ---------------------------------------------------------------------------
// Bridges and pluggable transports (Settings -> Network -> Tor connection).
// ---------------------------------------------------------------------------

/// Tor's built-in Snowflake bridges (bridges.torproject.org moat `builtin`, same as the tor-expert-bundle
/// `pt_config.json`). Domain-fronted broker on CDN77; re-check on each release.
pub const SNOWFLAKE_BRIDGES: &[&str] = &[
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
];

/// PT binary names. lyrebird implements both obfs4 and snowflake (the tor-expert-bundle ships no separate
/// snowflake-client; its `transports.json` maps snowflake -> lyrebird). Android: in `nativeLibraryDir`
/// (the only exec-allowed app path since API 29).
#[cfg(target_os = "android")]
const PT_BINARIES: [(&str, &str); 2] = [("obfs4", "liblyrebird.so"), ("snowflake", "liblyrebird.so")];
#[cfg(windows)]
const PT_BINARIES: [(&str, &str); 2] = [("obfs4", "lyrebird.exe"), ("snowflake", "lyrebird.exe")];
#[cfg(not(any(target_os = "android", windows)))]
const PT_BINARIES: [(&str, &str); 2] = [("obfs4", "lyrebird"), ("snowflake", "lyrebird")];

/// Bridge setup read by `client_config`. `None` = Direct: no bridges, no PT process.
struct PtSetup {
    protocol: &'static str,
    binary: std::path::PathBuf,
    lines: Vec<String>,
}
static PT_SETUP: Mutex<Option<PtSetup>> = Mutex::new(None);

/// The PT binary for `mode` ("obfs4" / "snowflake") in `pt_dir`, or next to the executable when `pt_dir` is empty.
fn pt_binary(mode: &str, pt_dir: &str) -> Option<(&'static str, std::path::PathBuf)> {
    let (protocol, name) = PT_BINARIES.iter().find(|(p, _)| *p == mode)?;
    let dir = if pt_dir.is_empty() {
        std::env::current_exe().ok()?.parent()?.to_path_buf()
    } else {
        std::path::PathBuf::from(pt_dir)
    };
    Some((*protocol, dir.join(name)))
}

/// The PT binary for `mode` is shipped in this build. "direct" is always available.
pub fn pt_available(mode: &str, pt_dir: &str) -> bool {
    mode == "direct" || pt_binary(mode, pt_dir).is_some_and(|(_, p)| p.is_file())
}

/// Checks pasted obfs4 bridge lines, one per line, with or without a leading "Bridge ". Blank and `#` lines
/// are skipped. Returns the lines, or the first bad one ("line N: ...").
pub fn parse_bridge_lines(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bridge = line.parse::<arti_client::config::BridgeConfigBuilder>().map_err(|e| format!("line {}: {e}", i + 1))?;
        if bridge.get_transport() != Some("obfs4") {
            return Err(format!("line {}: not an obfs4 bridge", i + 1));
        }
        bridge.build().map_err(|e| format!("line {}: {e}", i + 1))?;
        out.push(line.to_string());
    }
    if out.is_empty() {
        return Err("no bridge lines".to_string());
    }
    Ok(out)
}

/// Sets how the NEXT `TorHandle::launch` reaches Tor: "direct" (default), "snowflake", or "obfs4" with
/// `bridges`. A missing PT binary is not an error here: arti then cannot connect (fails closed, never
/// falls back to a direct connection the user turned away from).
pub fn set_transport(mode: &str, bridges: &str, pt_dir: &str) -> Result<(), String> {
    let setup = match mode {
        "direct" => None,
        "snowflake" | "obfs4" => {
            let (protocol, binary) = pt_binary(mode, pt_dir).ok_or("no PT directory")?;
            let lines = if mode == "snowflake" {
                SNOWFLAKE_BRIDGES.iter().map(|s| s.to_string()).collect()
            } else {
                parse_bridge_lines(bridges)?
            };
            Some(PtSetup { protocol, binary, lines })
        }
        other => return Err(format!("unknown Tor mode: {other}")),
    };
    *PT_SETUP.lock().unwrap_or_else(|p| p.into_inner()) = setup;
    Ok(())
}

/// Accepts one inbound onion stream and hands it to the swarm (`OnionListen`). `slot` is the bridge slot; it travels with the stream and
/// is freed when the connection closes.
async fn bridge_incoming_stream(
    stream_request: tor_hsservice::StreamRequest,
    onion_port: u16,
    slot: tokio::sync::OwnedSemaphorePermit,
    tx: tokio::sync::mpsc::Sender<TorStream>,
) {
    // Only BEGIN to our virtual port (the one we publish) is accepted. Anything else gets DONE, as arti advises, so the
    // rejection looks like any onion service's.
    if !matches!(stream_request.request(), IncomingStreamRequest::Begin(b) if b.port() == onion_port) {
        let _ = stream_request.reject(End::new_with_reason(EndReason::DONE)).await;
        return;
    }
    let mut tor_stream = match stream_request.accept(Connected::new_empty()).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Tor: incoming stream could not be accepted: {e}");
            return;
        }
    };

    // libp2p's dialer speaks first. A stream that stays silent is dropped before it costs a libp2p upgrade.
    use tokio::io::AsyncReadExt;
    let mut first = [0u8; 512];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(INBOUND_FIRST_BYTE_SECS), tor_stream.read(&mut first)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return,
    };
    // The swarm reads the bytes already taken first.
    let _ = tx.send(TorStream { inner: tor_stream, prefix: first[..n].to_vec(), _slot: Some(slot) }).await;
}

// ---------------------------------------------------------------------------
// Dial transport: opens a libp2p connection to a peer's `.onion` address.
// ---------------------------------------------------------------------------

/// Extracts (host, port) from a multiaddr of the form `/dns/<host>.onion/tcp/<port>`, ONLY if the host ends in `.onion`. This transport
/// takes responsibility for onion addresses only. For everything else it returns `MultiaddrNotSupported`; no other transport dials a
/// non-relay address (see the swarm setup in network/mod.rs).
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
    /// Inbound only: bytes the bridge read before the hand-off, served first.
    prefix: Vec<u8>,
    /// Inbound only: the bridge slot, freed when the connection closes.
    _slot: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl AsyncRead for TorStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        if !self.prefix.is_empty() {
            let n = buf.len().min(self.prefix.len());
            buf[..n].copy_from_slice(&self.prefix[..n]);
            self.prefix.drain(..n);
            return Poll::Ready(Ok(n));
        }
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
/// network/mod.rs). When it is `None`, every dial returns `MultiaddrNotSupported`, which is correct because no `.onion` address exists while Tor is off.
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
        // Tor off (client is None), or not a `.onion` address: not taken. No other transport dials it either.
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
            // Its own task: libp2p drops this future when its dial times out. Dropped mid-way, arti 0.24
            // leaves a half-open channel in its pending map ("'PendingChannelHandle' dropped unexpectedly")
            // and every later request to that relay waits on it for good. With two bridges as the only guards,
            // one such drop stopped all traffic over Snowflake. A detached task runs to its end instead.
            let stream = tokio::spawn(async move { client.connect_with_prefs(tor_addr, &prefs).await })
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            Ok(TorStream { inner: stream, prefix: Vec::new(), _slot: None })
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

/// Listen-only libp2p transport for the onion service: the bridge task (`bridge_incoming_stream`) sends each inbound Tor stream
/// through a channel, and this hands it to the swarm as an inbound connection. It replaces a TCP listener on 127.0.0.1, which every
/// local app could connect to (and read our PeerId and onion address over identify, skipping the bridge limits), and whose fixed port
/// another app could take first.
///
/// `addr` is only a label (`/ip4/127.0.0.1/tcp/<onion port>`): peers drop loopback addresses, and no socket is behind it. `dial`
/// returns `MultiaddrNotSupported`.
pub struct OnionListen {
    rx: tokio::sync::mpsc::Receiver<TorStream>,
    listener: Option<ListenerId>,
    announced: bool,
    addr: Multiaddr,
}

impl OnionListen {
    /// The address to pass to `Swarm::listen_on`.
    pub fn listen_addr(&self) -> Multiaddr {
        self.addr.clone()
    }
}

impl Transport for OnionListen {
    type Output = TorStream;
    type Error = std::io::Error;
    type Dial = futures::future::Pending<Result<Self::Output, Self::Error>>;
    type ListenerUpgrade = futures::future::Ready<Result<Self::Output, Self::Error>>;

    fn listen_on(&mut self, id: ListenerId, addr: Multiaddr) -> Result<(), TransportError<Self::Error>> {
        if addr != self.addr || self.listener.is_some() {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        self.listener = Some(id);
        self.announced = false;
        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        if self.listener == Some(id) {
            self.listener = None;
            true
        } else {
            false
        }
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn dial_as_listener(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn address_translation(&self, _listen: &Multiaddr, _observed: &Multiaddr) -> Option<Multiaddr> {
        None
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let this = self.get_mut();
        let Some(listener_id) = this.listener else { return Poll::Pending };
        if !this.announced {
            this.announced = true;
            return Poll::Ready(TransportEvent::NewAddress { listener_id, listen_addr: this.addr.clone() });
        }
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(stream)) => Poll::Ready(TransportEvent::Incoming {
                listener_id,
                upgrade: futures::future::ready(Ok(stream)),
                local_addr: this.addr.clone(),
                send_back_addr: this.addr.clone(),
            }),
            // `None`: the bridge task ended for good (the Tor handle is gone). Nothing more comes.
            _ => Poll::Pending,
        }
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

#[cfg(test)]
mod bridge_tests {
    use super::*;

    #[test]
    fn bridge_lines() {
        let ok = "Bridge obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";
        let bare = ok.trim_start_matches("Bridge ");
        assert_eq!(parse_bridge_lines(&format!("{ok}\n\n# c\n{bare}\n")).unwrap().len(), 2);
        assert!(parse_bridge_lines("").is_err());
        assert!(parse_bridge_lines("obfs4 nonsense").unwrap_err().starts_with("line 1"));
        assert!(parse_bridge_lines(&format!("{ok}\n192.0.2.1:443 316E643333645F6D79216558614D3931657A5F5F")).unwrap_err().starts_with("line 2"));
        for l in SNOWFLAKE_BRIDGES {
            l.parse::<arti_client::config::BridgeConfigBuilder>().unwrap().build().unwrap();
        }
        assert!(pt_available("direct", ""));
        assert!(!pt_available("obfs4", "/nonexistent"));
    }
}
