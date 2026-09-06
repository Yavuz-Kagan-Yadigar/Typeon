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
use tor_cell::relaycell::msg::Connected;
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

/// Çalışan Tor katmanının paylaşılan tutamacı. `TorClient` dial transport'u
/// tarafından da kullanılır (bkz. `ArtiDialTransport`), bu yüzden `Arc`.
pub struct TorHandle {
    pub client: Arc<TorClient<TokioRustlsRuntime>>,
    status: Arc<Mutex<TorStatus>>,
    onion_addr: Arc<Mutex<Option<String>>>,
    /// Onion service'i canlı tutmak için (drop edilirse servis durur).
    _service: Arc<tor_hsservice::RunningOnionService>,
}

impl TorHandle {
    /// Şu anki durum.
    pub fn status(&self) -> TorStatus {
        *self.status.lock().unwrap()
    }

    /// Yayındaki .onion host adı (ör. "abcd...xyz.onion") — henüz
    /// hesaplanmadıysa None. Not: bu SADECE host adıdır, tam libp2p
    /// multiaddr'ı lib.rs `get_node_address` oluşturur
    /// (`/dns/<host>/tcp/<port>/p2p/<peer_id>` biçiminde).
    pub fn onion_host(&self) -> Option<String> {
        self.onion_addr.lock().unwrap().clone()
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
    pub fn notify_network_changed(&self) {
        let client = self.client.clone();
        let status = self.status.clone();
        tokio::spawn(async move {
            match client.bootstrap().await {
                Ok(()) => {
                    *status.lock().unwrap() = TorStatus::Ready;
                    log::info!("Tor: ağ değişikliği sonrası bootstrap teyit edildi");
                }
                Err(e) => {
                    *status.lock().unwrap() = TorStatus::Bootstrapping;
                    log::warn!("Tor: ağ değişikliği sonrası bootstrap henüz tamam değil: {e}");
                }
            }
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

        let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .map_err(|e| format!("Arti config: {e}"))?;

        let client = TorClient::with_runtime(runtime)
            .config(config)
            .create_unbootstrapped()
            .map_err(|e| format!("Arti client: {e}"))?;
        let client = Arc::new(client);

        let status = Arc::new(Mutex::new(TorStatus::Bootstrapping));
        let onion_addr = Arc::new(Mutex::new(None::<String>));

        // Onion service'i başlat (bootstrap'ı beklemez — publish, client
        // bootstrap olunca gerçekleşir; .onion adı anahtardan hemen türetilir).
        let nickname: tor_hsservice::HsNickname = ONION_NICKNAME
            .parse()
            .map_err(|e| format!("Onion nickname: {e}"))?;
        let svc_config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()
            .map_err(|e| format!("Onion config: {e}"))?;
        let (service, rend_requests) = client
            .launch_onion_service(svc_config)
            .map_err(|e| format!("Onion service başlatılamadı: {e}"))?;

        // .onion adını (varsa) hemen yakala.
        if let Some(hsid) = service.onion_name() {
            *onion_addr.lock().unwrap() = Some(hsid.to_string());
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
            let client_bg = client.clone();
            let status_bg = status.clone();
            let service_bg = service.clone();
            let onion_bg = onion_addr.clone();
            tokio::spawn(async move {
                let mut delay = std::time::Duration::from_secs(2);
                loop {
                    match client_bg.bootstrap().await {
                        Ok(()) => {
                            // Bootstrap sonrası .onion adı kesinlikle var.
                            if let Some(hsid) = service_bg.onion_name() {
                                *onion_bg.lock().unwrap() = Some(hsid.to_string());
                            }
                            *status_bg.lock().unwrap() = TorStatus::Ready;
                            log::info!("Tor: bootstrap tamam, onion service yayında");
                            break;
                        }
                        Err(e) => {
                            *status_bg.lock().unwrap() = TorStatus::Failed;
                            log::error!("Tor bootstrap başarısız ({delay:?} sonra yeniden denenecek): {e}");
                            tokio::time::sleep(delay).await;
                            delay = (delay * 2).min(std::time::Duration::from_secs(60));
                        }
                    }
                }
            });
        }

        // Arka plan: gelen onion akışlarını yerel libp2p TCP portuna köprüle.
        {
            tokio::spawn(async move {
                let mut stream_requests = Box::pin(handle_rend_requests(rend_requests));
                while let Some(stream_request) = stream_requests.next().await {
                    tokio::spawn(async move {
                        bridge_incoming_stream(stream_request, local_port).await;
                    });
                }
                log::info!("Tor: gelen akış köprüsü sonlandı");
            });
        }

        Ok(TorHandle {
            client,
            status,
            onion_addr,
            _service: service,
        })
    }
}

/// Tek bir gelen onion akışını kabul edip yerel libp2p TCP dinleyicisine
/// (`127.0.0.1:<local_port>`) çift yönlü köprüler. `DataStream` hem tokio
/// hem futures AsyncRead/Write implement ettiğinden `tokio::io::
/// copy_bidirectional` doğrudan kullanılabilir.
async fn bridge_incoming_stream(stream_request: tor_hsservice::StreamRequest, local_port: u16) {
    // Gelen her akışı kabul ediyoruz — onion service'imiz tek amaçlı (yalnızca
    // libp2p trafiği), gelen her istek yerel libp2p portuna köprülenir. (arti
    // "yalnızca BEGIN kabul et" önerir ama bu sadece diğer onion
    // servisleriyle ayırt-edilemezlik içindir; bizim özel protokolümüzde
    // anlamı yok.)
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
