//! Tor onion service entegrasyonu (spec dışı, kullanıcı isteği) — CGNAT
//! arkasındaki cihazların birbirine ulaşabilmesi için. v1 kapsamı: SADECE
//! ULAŞILABİLİRLİK (bkz. SECURITY.md "Tor onion" notu) — gerçek IP hâlâ
//! `identify` ile görünebilir; tam anonimlik (identify bastırma + giden
//! trafiği de Tor'dan geçirme) v2'ye bırakıldı.
//!
//! Mimari:
//! - **Host (ulaşılabilir olmak):** `arti-client` ile bir onion service
//!   başlatılır. Gelen her Tor akışı (rendezvous), yerel libp2p TCP
//!   dinleyicisine (`127.0.0.1:<port>`) köprülenir — böylece libp2p swarm'ı
//!   bunu SIRADAN bir gelen TCP bağlantısı gibi görür, Tor'dan geldiğini
//!   bilmesine gerek kalmaz. Ayrı bir libp2p listener transport'u YAZILMAZ.
//! - **Dial (bir peer'in .onion'una bağlanmak):** ayrı bir libp2p
//!   `Transport` (`ArtiDialTransport`, aşağıda) `/onion3/...` adreslerini
//!   `TorClient::connect` ile Tor üzerinden dial eder.
//!
//! native-tls YERİNE rustls (openssl'den kaçınmak için); arti'nin rustls'i
//! `ring` kullanır, o da bu projede zaten cross-compile ediliyor (bkz.
//! Cargo.toml notu).

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

/// Kalıcı .onion kimliği için sabit takma ad (nickname). Aynı ad → aynı
/// keystore anahtarı → cihaz yeniden başlasa bile AYNI .onion adresi
/// (PeerId kalıcılığının Tor karşılığı).
const ONION_NICKNAME: &str = "p2pmsg";

/// Tor'un o anki durumu — UI'de gösterilir (bkz. lib.rs `tor_status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorStatus {
    /// Kapalı (kullanıcı Tor'u açmadı).
    Disabled,
    /// Arti bootstrap ediliyor (Tor ağ konsensüsü indiriliyor) — ilk
    /// açılışta saniyeler sürebilir.
    Bootstrapping,
    /// Hazır: bootstrap tamam VE onion service yayında, .onion adresi var.
    Ready,
    /// Başarısız (bootstrap/onion hatası) — bkz. logcat.
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

/// Inbound onion streams bridged at once. A peer needs one per connection.
const MAX_INBOUND_ONION_STREAMS: usize = 64;
/// Inbound streams one rendezvous circuit may hold open.
const MAX_STREAMS_PER_CIRCUIT: u32 = 8;

/// Çalışan Tor katmanının paylaşılan tutamacı. `TorClient` dial transport'u
/// tarafından da kullanılır (bkz. `ArtiDialTransport`), bu yüzden `Arc`.
pub struct TorHandle {
    pub client: Arc<TorClient<TokioRustlsRuntime>>,
    status: Arc<Mutex<TorStatus>>,
    onion_addr: Arc<Mutex<Option<String>>>,
    /// Onion service'i canlı tutmak için (drop edilirse servis durur).
    _service: Arc<tor_hsservice::RunningOnionService>,
    /// A `notify_network_changed` retry loop is running.
    rebootstrapping: Arc<std::sync::atomic::AtomicBool>,
}

impl TorHandle {
    /// Şu anki durum.
    pub fn status(&self) -> TorStatus {
        *self.status.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Yayındaki .onion host adı (ör. "abcd...xyz.onion") — henüz
    /// hesaplanmadıysa None. Not: bu SADECE host adıdır, tam libp2p
    /// multiaddr'ı lib.rs `get_node_address` oluşturur
    /// (`/dns/<host>/tcp/<port>/p2p/<peer_id>` biçiminde).
    pub fn onion_host(&self) -> Option<String> {
        self.onion_addr.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Ağ arayüzü değiştiğinde (Wi-Fi kopup gelme, hücresele geçiş) çağrılır.
    /// arti 0.24'te "ağ değişti, ŞİMDİ yeniden dene" için temiz bir genel API
    /// yok — reaktör kendi zamanlayıcılarıyla eninde sonunda (dakikalar
    /// içinde) toparlıyor. Burada yaptığımız, arka planda `bootstrap()`'ı
    /// yeniden çağırmak: zaten bootstrap edilmişse arti belgeleri "no-op"
    /// diyor ama bootstrap durumu bir ağ kesintisinde gerilemişse bu onu
    /// yeniden kurar, ve `.onion` adını yeniden yakalar. En kötü ihtimalle
    /// ucuz bir çağrı. (İstemci tarafı `notifyNetworkChanged` zaten peer'lara
    /// yeniden dial ediyor — bu, sunucunun onion'unu tazelemek için AYNI
    /// olayın karşılığı.)
    /// Radio saver: `Soft` stops our channel padding (relays already got
    /// STOP from `PaddingLevel::Reduced`) and arti's periodic tasks, so an
    /// idle LTE radio can sleep between windows. `false` re-fires the tasks.
    pub fn set_dormant(&self, dormant: bool) {
        use arti_client::DormantMode;
        self.client.set_dormant(if dormant { DormantMode::Soft } else { DormantMode::Normal });
    }

    pub fn notify_network_changed(&self) {
        use std::sync::atomic::Ordering;
        // One loop at a time; it runs until the bootstrap holds.
        if self.rebootstrapping.swap(true, Ordering::SeqCst) {
            return;
        }
        // Weak: the loop ends once the handle (and the swarm) drop the client.
        let client = Arc::downgrade(&self.client);
        let status = self.status.clone();
        let running = self.rebootstrapping.clone();
        tokio::spawn(async move {
            // Retries like the launch loop: one failed attempt left the status
            // at "bootstrapping" until the next network change, even after
            // arti recovered by itself.
            let mut delay = std::time::Duration::from_secs(2);
            loop {
                let Some(client) = client.upgrade() else { break };
                match client.bootstrap().await {
                    Ok(()) => {
                        *status.lock().unwrap_or_else(|p| p.into_inner()) = TorStatus::Ready;
                        log::info!("Tor: ağ değişikliği sonrası bootstrap teyit edildi");
                        break;
                    }
                    Err(e) => {
                        *status.lock().unwrap_or_else(|p| p.into_inner()) = TorStatus::Bootstrapping;
                        log::warn!("Tor: ağ değişikliği sonrası bootstrap henüz tamam değil ({delay:?} sonra yeniden): {e}");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(std::time::Duration::from_secs(60));
                    }
                }
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    /// Tor katmanını başlatır: arti client'ı oluşturur, arka planda bootstrap
    /// eder, onion service'i başlatır ve gelen akışları yerel `local_port`'a
    /// köprüleyen görevi spawn eder. TOKIO CONTEXT İÇİNDE çağrılmalı
    /// (`RUNTIME.enter()`/`block_on` sağlar) — `TokioRustlsRuntime::current()`
    /// aktif tokio handle'ını ister.
    ///
    /// `state_dir`/`cache_dir`: arti'nin anahtar deposu + konsensüs önbelleği
    /// (uygulamanın özel dizini altında). `local_port`: libp2p'nin dinlediği
    /// sabit TCP portu (bkz. lib.rs sabit-port ayarı).
    pub fn launch(state_dir: &str, cache_dir: &str, local_port: u16) -> Result<TorHandle, String> {
        let runtime = TokioRustlsRuntime::current()
            .map_err(|e| format!("TokioRustlsRuntime alınamadı: {e}"))?;

        trim_dir_cache(cache_dir);

        // A power loss mid-write leaves a state file (guards, intro points)
        // that arti refuses on every start: the server never came back. That
        // state is a network cache; the onion identity is in `keystore/`,
        // which stays. Cleared once, then one more try.
        let start = || -> Result<_, String> {
            let client = TorClient::with_runtime(runtime.clone())
                .config(client_config(state_dir, cache_dir)?)
                .create_unbootstrapped()
                .map_err(|e| format!("Arti client: {e}"))?;
            let nickname: tor_hsservice::HsNickname = ONION_NICKNAME
                .parse()
                .map_err(|e| format!("Onion nickname: {e}"))?;
            // One libp2p connection = one stream; a peer redialing needs a
            // few. Without this one rendezvous circuit could take all
            // `MAX_INBOUND_ONION_STREAMS` slots (arti default 65535).
            let svc_config = OnionServiceConfigBuilder::default()
                .nickname(nickname)
                .max_concurrent_streams_per_circuit(MAX_STREAMS_PER_CIRCUIT)
                .build()
                .map_err(|e| format!("Onion config: {e}"))?;
            let (service, rend_requests) = client
                .launch_onion_service(svc_config)
                .map_err(|e| format!("Onion service başlatılamadı: {e}"))?;
            Ok((client, service, rend_requests))
        };
        // Any start error, not only arti's "corrupted data in persistent
        // state" text: a wording change or another corruption kind would
        // otherwise skip the recovery and fail every start forever.
        let (client, service, rend_requests) = match start() {
            Err(e) => {
                log::warn!("Tor: start failed, state cleared, retrying once ({e})");
                for dir in ["state", "hss"] {
                    let _ = std::fs::remove_dir_all(std::path::Path::new(state_dir).join(dir));
                }
                start()?
            }
            Ok(v) => v,
        };
        let client = Arc::new(client);

        let status = Arc::new(Mutex::new(TorStatus::Bootstrapping));
        let onion_addr = Arc::new(Mutex::new(None::<String>));
        // Held by the launch loop too, so a network change does not start a
        // second loop next to it.
        let rebootstrapping = Arc::new(std::sync::atomic::AtomicBool::new(true));

        // .onion adını (varsa) hemen yakala.
        if let Some(hsid) = service.onion_name() {
            *onion_addr.lock().unwrap_or_else(|p| p.into_inner()) = Some(hsid.to_string());
        }

        // Arka plan: bootstrap — spec dışı, kullanıcı isteği ("Tor
        // bağlantısını izle ve yeniden dene"): önceden bootstrap TEK
        // seferlik denenir, başarısız olursa `Failed` durumunda SÜRESİZ
        // kalırdı (uygulama yeniden başlamadan/Tor kapatılıp açılmadan asla
        // düzelmezdi — geçici bir ağ sorunu bile kalıcı bir "Tor
        // çalışmıyor" durumuna yol açardı). Artık üstel geri çekilmeyle
        // (2 sn'den başlayıp 60 sn'de tavan yapar) BAŞARILI olana kadar
        // yeniden dener. `bootstrap()` zaten idempotent (arti belgeleri:
        // önceden bootstrap edilmişse no-op) — bu yüzden birden çok kez
        // çağırmak zararsız.
        {
            // Weak: dropping the handle ends the loop instead of retrying
            // every 60 s forever with a dead client.
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
                            // Bootstrap sonrası .onion adı kesinlikle var.
                            if let Some(hsid) = service_bg.onion_name() {
                                *onion_bg.lock().unwrap_or_else(|p| p.into_inner()) = Some(hsid.to_string());
                            }
                            *status_bg.lock().unwrap_or_else(|p| p.into_inner()) = TorStatus::Ready;
                            log::info!("Tor: bootstrap tamam, onion service yayında");
                            break;
                        }
                        Err(e) => {
                            // Still retrying: same status as the notify loop.
                            *status_bg.lock().unwrap_or_else(|p| p.into_inner()) = TorStatus::Bootstrapping;
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

        // Arka plan: gelen onion akışlarını yerel libp2p TCP portuna köprüle.
        {
            let status_br = status.clone();
            tokio::spawn(async move {
                // Anyone who knows the .onion can open streams, and each one
                // costs a task, a socket and a libp2p upgrade that the swarm
                // sees as 127.0.0.1. Over the cap the request is dropped.
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
                // No inbound path any more: do not keep reporting Ready.
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
/// Channel padding doubles as the NAT keepalive, so its interval is the one
/// knob that decides a phone's standby cost on mobile data (each packet keeps
/// LTE awake ~10 s). Measured on the Note 9S on LTE, idle half hour:
/// Normal (a cell per idle guard channel every 1.5-9.5 s) 4.4 MB, radio awake
/// 92 %, 35 mAh; Reduced (9-14 s) 87 %, 33.5 mAh; None — the carrier NAT
/// dropped the idle guard channel, every peer link died within a minute and
/// the redials (onion circuit builds) kept the radio up anyway (37 mAh).
/// So: Reduced, with its idle timeout stretched to 225-245 s (see
/// `client_config`; the vendored tor-netdir lifts arti's 60 s cap).
///
/// arti keeps every hourly consensus (~3.3 MB) until 4 days past expiry, so
/// dir_blobs grows to ~150-330 MB. The retention is a private constant in
/// tor-dirmgr, so before arti opens the cache keep only the two newest
/// consensuses per flavour (the latest plus one diff base). Best effort.
fn trim_dir_cache(cache_dir: &str) {
    let dir = std::path::Path::new(cache_dir);
    // READ_WRITE without CREATE: no cache yet = nothing to trim, and arti
    // must create its own schema.
    let Ok(conn) = rusqlite::Connection::open_with_flags(dir.join("dir.sqlite3"), rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) else {
        return;
    };
    let files = (|| -> rusqlite::Result<Vec<String>> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let q = "SELECT filename FROM ExtDocs e WHERE type LIKE 'con%' AND \
                 (SELECT COUNT(*) FROM ExtDocs n WHERE n.type = e.type AND n.created > e.created) >= 2";
        let names: Vec<String> = conn.prepare(q)?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        // A bare file name only: the name comes from a database file, and
        // `..` or an absolute path would delete outside `dir_blobs`. Rows
        // with other names stay, so row and file go together.
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
    // Devre kurma zaman aşımı arti'de ölçümle öğreniliyor; hızlı Wi-Fi'de
    // öğrenilen kısa değer, mobil veriye geçince devrelerin çoğunu
    // tamamlanmadan terk ettiriyordu (cihazda: ağ değişiminden sonra onion
    // dial'ı 6 sn'de "tor operation timed out", toparlanma 20-120 sn).
    // Öğrenme açık kalıyor, yalnızca alt sınır.
    // 20 s: an extend is budgeted 4/6 of this (3->4 hops). At 10 s the
    // ~6.7 s extend to a slow intro point on LTE timed out every try, and
    // each IPT status change re-uploaded the descriptor to 16 HSDirs
    // (~130 KB) once a minute.
    config.override_net_params().insert("cbtmintimeout".to_string(), 20_000);
    // 225-245 s: the carrier NAT kept an idle TCP connection to both guards
    // for 290 s (9S on LTE, 2026-10-07; closed at 300 s). At 45-55 s the
    // padding cell alone woke the LTE radio once a minute. arti caps the
    // value at 60 s, hence the vendored tor-netdir.
    config.override_net_params().insert("nf_ito_low_reduced".to_string(), 225_000);
    config.override_net_params().insert("nf_ito_high_reduced".to_string(), 245_000);
    // No preemptive exit circuits: the app only ever dials onion services,
    // but arti keeps circuits for ports 80/443 warm by default — pure radio
    // and battery cost.
    config.preemptive_circuits().initial_predicted_ports().clear();
    config.channel().padding(tor_config::PaddingLevel::Reduced);
    config.build().map_err(|e| format!("Arti config: {e}"))
}

/// Tek bir gelen onion akışını kabul edip yerel libp2p TCP dinleyicisine
/// (`127.0.0.1:<local_port>`) çift yönlü köprüler. `DataStream` hem tokio
/// hem futures AsyncRead/Write implement ettiğinden `tokio::io::
/// copy_bidirectional` doğrudan kullanılabilir.
async fn bridge_incoming_stream(stream_request: tor_hsservice::StreamRequest, local_port: u16) {
    // M-11: only BEGIN to our virtual port (the one we publish, = `local_port`).
    // DONE, as arti advises, so the rejection looks like any onion service's.
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

    let mut tcp = match tokio::net::TcpStream::connect(("127.0.0.1", local_port)).await {
        Ok(t) => t,
        Err(e) => {
            log::error!("Tor: yerel libp2p portuna ({local_port}) bağlanılamadı: {e}");
            return;
        }
    };

    // Çift yönlü kopyala — bağlantı kapanana kadar. DataStream tokio
    // AsyncRead/Write implement ediyor (tor-proto tokio feature).
    if let Err(e) = tokio::io::copy_bidirectional(&mut tor_stream, &mut tcp).await {
        log::debug!("Tor köprü akışı sonlandı: {e}");
    }
}

// ---------------------------------------------------------------------------
// Dial transport: bir peer'in `.onion` adresine libp2p bağlantısı açar.
// ---------------------------------------------------------------------------

/// `/dns/<host>.onion/tcp/<port>` biçimindeki bir multiaddr'dan (host, port)
/// çıkarır — SADECE `.onion` ile bitiyorsa. Böylece bu transport yalnızca
/// onion adreslerini üstlenir; diğer her şey için `MultiaddrNotSupported`
/// döner ve `OrTransport` normal TCP yoluna düşer (bkz. lib.rs swarm kurulumu).
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

/// libp2p `DataStream` (arti) sarmalayıcısı — arti'nin tokio AsyncRead/Write'ını
/// libp2p'nin beklediği futures AsyncRead/Write'a çevirir (bkz.
/// libp2p-community-tor provider.rs, birebir uyarlandı).
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

/// SADECE `.onion` adreslerini Tor üzerinden dial eden libp2p transport'u.
/// `listen_on` desteklenmez (gelen bağlantılar onion service köprüsünden,
/// yerel TCP dinleyicisine gelir — bkz. `bridge_incoming_stream`).
///
/// `client` KASITLI OLARAK `Option`: Tor kapalıyken de bu transport swarm'a
/// EKLENİR (tek bir swarm kurulum yolu olsun diye — bkz. lib.rs
/// `start_network`), ama `None` olduğunda her dial `MultiaddrNotSupported`
/// döner (zaten Tor kapalıyken hiç `.onion` adresi de olmaz). Böylece
/// koşullu/çift build yoluna gerek kalmaz.
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
        // Tor kapalı (client None) → bu adresi üstlenmiyoruz; OrTransport TCP
        // yoluna düşer. `.onion` DEĞİLSE de üstlenmiyoruz.
        let client = match &self.client {
            Some(c) => c.clone(),
            None => return Err(TransportError::MultiaddrNotSupported(addr)),
        };
        let (host, port) = onion_host_port(&addr).ok_or(TransportError::MultiaddrNotSupported(addr))?;
        let tor_addr = TorAddr::from((host.as_str(), port))
            .map_err(|e| TransportError::Other(std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())))?;
        Ok(Box::pin(async move {
            // HER dial kendi Tor devresini alır.
            //
            // Varsayılan yalıtımla arti, aynı `TorClient` üzerinden açılan
            // bütün akışları AYNI devrede toplayabiliyor. Tek devre ise bu
            // uygulamada ölçülen gerçek tavan: aynı 14 MB'lık dosya, aynı
            // kod ve aynı cihazlarla bir devrede 270 KB/s, başka bir devrede
            // 165 KB/s gitti — darboğaz devrenin kendisi. Bağlantı başına
            // ayrı devre, toplu aktarımda birden çok bağlantı açıldığında
            // (bkz. `BULK_PARALLEL_CONNECTIONS`) bant genişliğinin gerçekten
            // toplanmasını sağlar; tek devrede paralel bağlantı hiçbir şey
            // kazandırmazdı.
            //
            // Bu, AKIŞ başına değil BAĞLANTI başına devre demek: bir libp2p
            // bağlantısı zaten çok sayıda akışı yamux ile çoğulluyor. Yani
            // eş başına birkaç devre oluyor, arti'nin uyardığı
            // `isolate_every_stream` savurganlığı değil.
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

/// Sarmaladığı transport'u SADECE gelen bağlantılar için bırakan, HER `dial`'ı
/// reddeden sarmalayıcı. Onion-only garantisinin taşıma-katmanı çıpası:
///
/// TCP taşıması swarm'dan tamamen ÇIKARILAMAZ — onion service köprüsü
/// (`bridge_incoming_stream`) gelen Tor akışlarını `127.0.0.1:<port>`'a bağlar,
/// yani yerel bir TCP dinleyicisi gerekir. Ama giden TCP dial'ı bir eşin
/// GERÇEK IP'sine doğrudan (clearnet) bağlanır ve Tor anonimliğini bozar
/// (deanonymization — bkz. defter/pentest 2026-09-23: UPnP + `:42611` direct
/// SYN'ler). Bu sarmalayıcı TCP'yi "yalnızca dinle" yapar: `listen_on`/gelen
/// akış olduğu gibi devreder, `dial`/`dial_as_listener` daima
/// `MultiaddrNotSupported` döner. Böylece çıkışın tamamı `ArtiDialTransport`
/// (onion) veya röle (onion üzerinden) üzerinden gider; libp2p asla bir eşin
/// clearnet adresine doğrudan bağlanamaz — kim `swarm.dial()` çağırırsa
/// çağırsın (kad, identify dahil).
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
