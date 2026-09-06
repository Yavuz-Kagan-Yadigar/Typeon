//! Typeon sunucusu — KÖR bir store-and-forward posta kutusu.
//!
//! ## Neden var
//!
//! Bu uygulamada bugün HİÇBİR yerde store-and-forward YOK (bkz. depo
//! kökündeki `Bagimsiz-AI-Inceleme-Notlari.md` §17): libp2p Circuit Relay v2
//! sadece iki taraf da O ANDA bağlıyken canlı bir devre kurar ve hiçbir şey
//! saklamaz; `p2p_msg_<fp>` gossipsub topic'i de bir depolama servisi değil,
//! bir isimlendirme kuralı. Dayanıklılığın tamamı GÖNDEREN tarafında
//! (`awaiting_confirmation`, 2 güne kadar yeniden deneme). Bu sunucu, o
//! boşluğu dolduruyor.
//!
//! ## Sunucunun göremediği şeyler
//!
//! - Mesaj içeriği: zarflar zaten uçtan uca şifreli, ÜSTELİK
//!   `server_seal::seal_envelope` ile ikinci bir kez mühürlü (aksi halde
//!   `MessagePacketHeader.sender_device_fingerprint` AÇIK okunurdu).
//! - Geçmiş: `archive_key` türevi bir anahtarla şifreli.
//! - Dosya içeriği: `file_key` ile şifreli; sunucu parçaları OLDUĞU GİBİ
//!   depolar ve servis eder.
//! - Kimlikler: kutu/kova kimlikleri HKDF ile körleştirilmiş; kayıt (`Enroll`)
//!   cihazın kimlik anahtarını DEĞİL, bu sunucuya özel taze bir Ed25519
//!   çiftini kullanır.
//!
//! ## Görebildikleri (SECURITY.md'de yazılı)
//!
//! Boyut, zaman, hacim; ve hangi `PeerId`'nin hangi kutuyu kaydettiği —
//! yani KENDİ kullanıcıları arasındaki eş grafiği. Bunu gizlemek, kutu
//! başına anonim kimlik bilgisi + ayrı devre gerektirir; kapsam dışı.

pub mod store;

/// Android sunucu uygulamasının JNI kabuğu — sadece Android'de derlenir.
#[cfg(target_os = "android")]
mod jni;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature as MlDsaSignature,
    Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};
use futures::StreamExt as _;
use libp2p::request_response::{self, ProtocolSupport, ResponseChannel};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{autonat, identify, kad, noise, relay, tcp, yamux, PeerId, StreamProtocol, Swarm};
use libp2p::kad::store::MemoryStore;
use log::{error, info, warn};
use rand::RngCore;
use sha2::{Digest, Sha256};

use p2p_messenger::attachments::{self, FileChunkRequest, FileChunkResponse};
use p2p_messenger::server_proto::{
    self, ServerErrorCode, ServerLimits, ServerRequest, ServerResponse, MAX_DEPOSIT_BYTES,
    MAX_FETCH_BATCH_BYTES, MAX_FETCH_BATCH_ITEMS, SERVER_PROTOCOL, SERVER_PROTOCOL_VERSION,
};

use store::{Enrollment, EnrollmentState, Store};

/// Dosya eki protokol kimliği — istemcilerin ZATEN konuştuğu protokolün
/// AYNISI. Sunucu bunu `ProtocolSupport::Inbound` ile kaydeder, böylece
/// sunucudaki bir ek istemci için sadece "başka bir kaynak eş" olur ve
/// istemcideki bütün indirme durum makinesi hiç değişmeden çalışır.
const FILE_TRANSFER_PROTOCOL: &str = "/p2pmessenger/filexfer/1.0.0";

/// Tor açıkken libp2p'nin dinlemek ZORUNDA olduğu sabit port — onion
/// service gelen akışları buraya köprüler (çekirdekteki `TOR_LIBP2P_PORT`
/// ile aynı gerekçe, ama sunucunun kendi portu).
const TOR_LIBP2P_PORT: u16 = 42612;

/// Süpürme aralıkları.
const SWEEP_INTERVAL_MS: u64 = 60_000;

/// Bir bağlantının dakikada yapabileceği azami istek. Kotanın aksine bu
/// ANLIK bir sınır: amaç, tek bir eşin sunucunun disk/CPU'sunu tek başına
/// tüketmesini engellemek.
const RATE_WINDOW_MS: u64 = 60_000;

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

/// Herkese açık katılım jetonunu döner; yoksa üretir. `rotate` ise ÖNCE
/// eskisini siler (eski kod anında geçersizleşir).
///
/// Davet satırı da (sınırsız, süresiz) burada garanti edilir — operatör
/// `data` dizinini eski bir yedekten geri yüklediğinde jeton `meta`'da
/// olup davet satırı kayıp olabilir; o durumda yayımlanmış kod sessizce
/// çalışmayı bırakırdı.
///
/// Serbest fonksiyon, çünkü Android sunucu uygulamasının JNI katmanında
/// `ServerCore` GÖRÜNMEZ (ağ görevinin içinde) — yalnızca `Store`. Aynı
/// mantığın orada ikinci bir kopyası olsaydı, ikisi sessizce ayrışırdı.
pub fn public_join_token(store: &Store, rotate: bool) -> Result<String, String> {
    if rotate {
        if let Some(old) = store.meta_get(PUBLIC_JOIN_TOKEN_KEY) {
            if let Ok(bytes) = hex::decode(String::from_utf8_lossy(&old).trim().as_bytes()) {
                let _ = store.delete_invite(Sha256::digest(&bytes).as_slice());
            }
        }
        store.meta_set(PUBLIC_JOIN_TOKEN_KEY, b"")?;
    }
    let existing = store
        .meta_get(PUBLIC_JOIN_TOKEN_KEY)
        .map(|v| String::from_utf8_lossy(&v).trim().to_string())
        .filter(|v| !v.is_empty());
    let token = match existing {
        Some(t) => t,
        None => {
            let mut raw = [0u8; 20];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            let t = hex::encode(raw);
            store.meta_set(PUBLIC_JOIN_TOKEN_KEY, t.as_bytes())?;
            t
        }
    };
    let raw = hex::decode(&token).map_err(|_| "Katılım jetonu bozuk".to_string())?;
    let hash = Sha256::digest(&raw);
    if store.invite_uses_left(hash.as_slice()) != Some(-1) {
        store.create_invite(hash.as_slice(), PUBLIC_JOIN_LABEL, 0, 0, now_ms())?;
    }
    Ok(token)
}

// ---------------------------------------------------------------------------
// Yapılandırma
// ---------------------------------------------------------------------------

/// Herkese açık (kalıcı) katılım jetonunun `meta` anahtarı — bkz.
/// `ServerCore::join_code`.
const PUBLIC_JOIN_TOKEN_KEY: &str = "public_join_token";
/// O jetona karşılık gelen davet satırının etiketi (`invite list`'te
/// görünür).
const PUBLIC_JOIN_LABEL: &str = "herkese-acik";
/// Herkese açık kodla saatte açılabilecek azami YENİ kayıt — bkz.
/// `handle_enroll`.
const MAX_PUBLIC_ENROLLMENTS_PER_HOUR: i64 = 60;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub data_dir: PathBuf,
    /// Blobların (dosya ekleri) tutulacağı dizin — varsayılan
    /// `data_dir/blobs`, ama AYRI bir birime (ör. SD kart) alınabilir.
    ///
    /// Neden ayrı: yer kaplayan tek şey bloblar (gerçek testte 504 MB),
    /// ama `data_dir` aynı zamanda libp2p kimliğini ve Tor (arti) kalıcı
    /// durumunu tutuyor. Bunları SD karta taşımak Tor'u BOZUYOR — arti
    /// anahtar dosyaları için POSIX izin modeli istiyor, kart bağlaması
    /// vermiyor ve `could not read/write persistent state` ile açılmıyor.
    /// Sunucu o durumda sessizce onion service'siz, rastgele portta
    /// çalışmaya devam ediyor: kayıtlı bütün istemciler kopuyor. Bu yüzden
    /// kimlik/Tor durumu HER ZAMAN dahili depolamada kalır, yalnızca
    /// bloblar taşınır.
    pub blob_dir: PathBuf,
    pub listen_port: u16,
    pub tor_enabled: bool,
    /// Kad'a Server modunda katıl + Circuit Relay v2 hizmeti ver. Kapalıysa
    /// sunucu SADECE posta kutusu işi yapar.
    pub node_mode: bool,
    pub server_name: String,
    pub limits: ServerLimits,
    /// Sunucunun kullanabileceği TOPLAM disk bütçesi (bkz. defter #23).
    /// `None` = sınırsız (VPS); Android sunucu uygulaması bunu cihazın
    /// gerçek boş alanından türetip veriyor.
    pub total_storage_budget_bytes: Option<u64>,
}

impl ServerConfig {
    pub fn new(data_dir: PathBuf) -> Self {
        ServerConfig {
            blob_dir: data_dir.join("blobs"),
            data_dir,
            listen_port: 0,
            tor_enabled: true,
            node_mode: false,
            server_name: "Typeon Server".to_string(),
            limits: ServerLimits::default(),
            total_storage_budget_bytes: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Davranış
// ---------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
pub struct ServerBehaviour {
    /// Posta kutusu RPC'si. `Full`: sunucunun istemciye kendiliğinden
    /// `Notify` gönderebilmesi için (bkz. `ServerRequest::Notify`).
    server_rpc: request_response::cbor::Behaviour<ServerRequest, ServerResponse>,
    /// Dosya parçaları. `Inbound`: sunucu sadece SERVİS eder, hiç istemez.
    file_chunks: request_response::cbor::Behaviour<FileChunkRequest, FileChunkResponse>,
    identify: identify::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
    autonat: autonat::Behaviour,
    upnp: libp2p::upnp::tokio::Behaviour,
    /// Node modu açıkken röle hizmeti. `Toggle::from(None)` KASITLI:
    /// libp2p-relay'in HOP handler'ı `Config`'e bakmadan protokolü her zaman
    /// duyurur, yani sıfır kapasiteli bir `Behaviour` bile identify üzerinden
    /// "röleyim" yalanını yayardı (çekirdekteki aynı notun karşılığı).
    relay: Toggle<relay::Behaviour>,
}

// ---------------------------------------------------------------------------
// Çekirdek
// ---------------------------------------------------------------------------

/// Bağlantı başına anlık durum.
struct ConnState {
    /// Bu bağlantıya verilmiş, henüz kullanılmamış `Enroll` challenge'ı.
    challenge: Option<Vec<u8>>,
    window_start: u64,
    requests_in_window: u32,
}

pub struct ServerCore {
    config: ServerConfig,
    store: Store,
    swarm: Swarm<ServerBehaviour>,
    tor: Option<p2p_messenger::tor::TorHandle>,
    /// Tor açılamadıysa sebebi — bkz. `tor_status`. Sessiz bırakmak,
    /// sunucuyu ulaşılamaz hâlde "çalışıyor" göstermek demekti.
    tor_error: Option<String>,
    conns: HashMap<PeerId, ConnState>,
    /// Hangi kayıt hangi kutuları dinliyor — `Notify` itmek için. Bellekte:
    /// kalıcı gerçek `mailboxes` tablosunda, bu sadece bağlı eşlerin canlı
    /// görünümü.
    live_interest: HashMap<PeerId, HashSet<String>>,
    last_sweep: u64,
    pub stats: ServerStats,
    /// bkz. `ServerShared` — döngü dışından okunacak anlık görüntü.
    shared: Option<std::sync::Arc<ServerShared>>,
    /// bkz. `set_net_changed_rx` / `notify_network_changed` — Android ağ
    /// değişikliği bildirimi. `run_until` bunu `take()` edip select!'te dinler.
    net_changed_rx: Option<tokio::sync::mpsc::UnboundedReceiver<()>>,
}

/// Ana döngünün DIŞINDAN okunabilen anlık görüntü.
///
/// Android sunucu uygulaması için gerekli: `ServerCore` kendi tokio
/// görevinde `run()` içinde dönerken, arayüz saniyede bir durum sormak
/// istiyor. `ServerCore`'a kilit koymak döngüyü durdururdu; bunun yerine
/// döngü her turda bu ucuz kopyayı tazeliyor.
#[derive(Debug, Default)]
pub struct ServerShared {
    pub peer_id: std::sync::Mutex<String>,
    pub addrs: std::sync::Mutex<Vec<String>>,
    pub tor_status: std::sync::Mutex<String>,
    pub stats: std::sync::Mutex<ServerStats>,
}

#[derive(Debug, Default, Clone)]
pub struct ServerStats {
    pub deposits: u64,
    pub fetches: u64,
    pub archive_puts: u64,
    pub blob_chunks_served: u64,
    pub enrollments: u64,
    pub rejected: u64,
}


/// bkz. çekirdekteki `YAMUX_RECEIVE_WINDOW` — sunucu tarafının ALMA penceresi
/// yükleme yönünü (istemci → sunucu) yönetiyor, yani buradaki değer en az
/// istemcideki kadar bol olmalı. Varsayılan 256 KiB, dosya parçası ise
/// 256 KiB + 16 bayt: her parçanın sonunda gereksiz bir pencere güncellemesi
/// gidiş-dönüşü demekti.
fn tuned_yamux() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    #[allow(deprecated)]
    {
        cfg.set_receive_window_size(4 * 1024 * 1024);
        cfg.set_max_buffer_size(8 * 1024 * 1024);
    }
    cfg
}

impl ServerCore {
    pub fn new(config: ServerConfig) -> Result<ServerCore, String> {
        std::fs::create_dir_all(&config.data_dir).map_err(|e| format!("Veri dizini: {e}"))?;
        std::fs::create_dir_all(&config.blob_dir).map_err(|e| format!("Blob dizini: {e}"))?;

        let store = Store::open(&config.data_dir.join("typeon_server.db"))?;
        let keypair = load_or_generate_keypair(&store)?;

        // Tor: sunucunun kendi onion service'i. Bir TELEFONUN (Android
        // sunucu uygulaması) CGNAT arkasından ulaşılabilir olmasının TEK
        // yolu bu — ne port yönlendirme, ne alan adı, ne TLS sertifikası.
        let mut tor_error: Option<String> = None;
        let tor = if config.tor_enabled {
            let state_dir = config.data_dir.join("arti_state");
            let cache_dir = config.data_dir.join("arti_cache");
            match p2p_messenger::tor::TorHandle::launch(
                &state_dir.to_string_lossy(),
                &cache_dir.to_string_lossy(),
                TOR_LIBP2P_PORT,
            ) {
                Ok(h) => Some(h),
                Err(e) => {
                    // SESSİZ kalmak kabul edilemez: onion service olmadan
                    // sunucu, kayıtlı istemcilerin HİÇBİRİ için ulaşılabilir
                    // değil (hepsi `.onion` adresini kullanıyor) ama arayüz
                    // "çalışıyor" göstermeye devam ediyordu. Gerçek testte
                    // tam olarak bu oldu: veri SD karta taşınınca arti
                    // açılamadı, sunucu rastgele portta Tor'suz kalktı ve
                    // sebep yalnızca logcat'te görünüyordu.
                    error!("Tor başlatılamadı: {e} — Tor'suz devam ediliyor");
                    tor_error = Some(e.to_string());
                    None
                }
            }
        } else {
            None
        };
        let listen_port = if tor.is_some() { TOR_LIBP2P_PORT } else { config.listen_port };
        let node_mode = config.node_mode;

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, tuned_yamux)
            .map_err(|e| e.to_string())?
            .with_behaviour(|keypair| {
                let peer_id = keypair.public().to_peer_id();
                let server_rpc = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(SERVER_PROTOCOL), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_millis(p2p_messenger::server_client_timeout_ms())),
                );
                // 30 sn: çekirdekteki `file_chunks` ile AYNI gerekçe — Tor
                // üzerinden 256 KiB'lik bir parça için kütüphanenin 10 sn'lik
                // varsayılanı çoğu zaman yetersiz.
                let file_chunks = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(FILE_TRANSFER_PROTOCOL), ProtocolSupport::Inbound)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_millis(p2p_messenger::server_client_timeout_ms())),
                );
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/p2pmessenger/1.0.0".to_string(),
                    keypair.public(),
                ));
                let kad = kad::Behaviour::new(peer_id, MemoryStore::new(peer_id));
                let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());
                let upnp = libp2p::upnp::tokio::Behaviour::default();
                let relay: Toggle<relay::Behaviour> = if node_mode {
                    Some(relay::Behaviour::new(peer_id, relay::Config::default())).into()
                } else {
                    None.into()
                };
                ServerBehaviour { server_rpc, file_chunks, identify, kad, autonat, upnp, relay }
            })
            .map_err(|e| e.to_string())?
            // Çekirdekteki 600 sn ile aynı gerekçe: sessiz dönemlerde
            // bağlantıyı canlı tut, Tor devrelerini boşuna yeniden kurma.
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(600)))
            .build();

        swarm
            .behaviour_mut()
            .kad
            .set_mode(Some(if node_mode { kad::Mode::Server } else { kad::Mode::Client }));

        swarm
            .listen_on(format!("/ip4/0.0.0.0/tcp/{}", listen_port).parse().map_err(|_| "bad multiaddr")?)
            .map_err(|e| e.to_string())?;

        Ok(ServerCore {
            tor_error,
            config,
            store,
            swarm,
            tor,
            conns: HashMap::new(),
            live_interest: HashMap::new(),
            last_sweep: 0,
            stats: ServerStats::default(),
            shared: None,
            net_changed_rx: None,
        })
    }

    /// bkz. `notify_network_changed` — Android arayüzü `startServer`'da
    /// bir kanal kurup uçlarından birini burada, diğerini `Control`'de
    /// tutar; `ConnectivityManager` geri çağrısı ağ değiştiğinde iter.
    pub fn set_net_changed_rx(&mut self, rx: tokio::sync::mpsc::UnboundedReceiver<()>) {
        self.net_changed_rx = Some(rx);
    }

    /// Ağ arayüzü değiştiğinde (Wi-Fi kopup gelme, hücresele geçiş)
    /// `run_until` döngüsünden çağrılır. Sunucu pasiftir (peer'lara dial
    /// etmez), o yüzden yapılacak tek şey Tor'u dürtmek: devreler/onion
    /// descriptor bir Wi-Fi kesintisinden sonra periyodik iyileşmeyi
    /// (dakikalar) beklemesin (bkz. `tor::TorHandle::notify_network_changed`).
    /// libp2p dinleyicisi `0.0.0.0` üzerinde, süreç boyunca bağlı kalır —
    /// yeniden `listen_on` gereksiz.
    pub fn notify_network_changed(&self) {
        if let Some(tor) = &self.tor {
            tor.notify_network_changed();
        }
    }

    /// Döngü dışından okunacak anlık görüntüyü bağlar (Android arayüzü).
    pub fn attach_shared(&mut self, shared: std::sync::Arc<ServerShared>) {
        if let Ok(mut p) = shared.peer_id.lock() {
            *p = self.local_peer_id().to_string();
        }
        self.shared = Some(shared);
        self.publish_shared();
    }

    fn publish_shared(&self) {
        let Some(shared) = &self.shared else { return };
        if let Ok(mut a) = shared.addrs.lock() {
            *a = self.advertised_addrs();
        }
        if let Ok(mut t) = shared.tor_status.lock() {
            *t = self.tor_status();
        }
        if let Ok(mut st) = shared.stats.lock() {
            *st = self.stats.clone();
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub fn onion_host(&self) -> Option<String> {
        self.tor.as_ref().and_then(|t| t.onion_host())
    }

    pub fn tor_status(&self) -> String {
        if let Some(err) = &self.tor_error {
            // Arayüz bunu görünce "çalışıyor" değil "ulaşılamaz" göstermeli.
            return format!("error: {err}");
        }
        self.tor
            .as_ref()
            .map(|t| t.status().as_str().to_string())
            .unwrap_or_else(|| "disabled".to_string())
    }

    /// Davet kodları için ilan edilecek adresler — onion varsa ÖNCE o
    /// (CGNAT/ev bağlantısı arkasında çalışan tek adres odur).
    pub fn advertised_addrs(&self) -> Vec<String> {
        let peer = self.local_peer_id();
        let mut out = Vec::new();
        if let Some(host) = self.onion_host() {
            out.push(format!("/dns/{}/tcp/{}/p2p/{}", host, TOR_LIBP2P_PORT, peer));
        }
        for addr in self.swarm.listeners() {
            let s = addr.to_string();
            if s.contains("127.0.0.1") || s.contains("/ip6/::1") {
                continue;
            }
            out.push(format!("{}/p2p/{}", s, peer));
        }
        out
    }

    /// Davet koduna GİRECEK adresler — `advertised_addrs`'ten farkı: ÖZEL
    /// ağ adresleri elenir.
    ///
    /// Neden: davet kodu, başka bir ağdaki bir kişiye gönderilir. Oradan
    /// `192.168.x.x` gibi bir adres zaten ULAŞILAMAZ; koda girmesinin tek
    /// etkisi, sunucunun iç ağ yapısını kodu gören herkese söylemek olur.
    /// Aynı yerel ağdaki iki kişinin yazışması gerçekçi bir senaryo değil,
    /// dolayısıyla bunun bir faydası da yok.
    ///
    /// Geriye kalan — onion ve varsa GENEL IP — gerçekçi kurulumun ta
    /// kendisi: halka açık bir VPS'te çalışan bir sunucuya istemci doğrudan
    /// bağlanır (Tor'a hiç girmeden), erişilemiyorsa onion'a düşer.
    pub fn invite_addrs(&self) -> Vec<String> {
        self.advertised_addrs()
            .into_iter()
            .filter(|a| !is_private_multiaddr(a))
            .collect()
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Yeni bir davet üretir ve tam davet kodunu döner. `uses <= 0` =
    /// SINIRSIZ (bkz. `Store::create_invite`).
    pub fn create_invite(&self, label: &str, uses: i64, ttl_ms: i64) -> Result<String, String> {
        let mut token = [0u8; 20];
        rand::rngs::OsRng.fill_bytes(&mut token);
        // Jeton HASH'lenmiş saklanır: sunucu diski ele geçse bile henüz
        // kullanılmamış davetler kullanılamaz.
        let hash = Sha256::digest(token);
        let hash = hash.as_slice();
        let now = now_ms();
        let expires = if ttl_ms <= 0 { 0 } else { now + ttl_ms };
        self.store.create_invite(hash, label, uses, expires, now)?;

        let token_str = hex::encode(token);
        // Ulaşılabilir BÜTÜN adresler koda girer (onion + varsa genel IP);
        // özel ağ adresleri elenir (bkz. `invite_addrs`). İstemci hepsini
        // aynı anda dial eder, libp2p ilk kuranı kullanır — yani halka açık
        // bir VPS'e doğrudan bağlanılır, olmazsa onion'a düşülür.
        let addrs = self.invite_addrs();
        if addrs.is_empty() {
            return Err("Sunucunun henüz bir dinleme adresi yok (birkaç saniye sonra tekrar deneyin)".to_string());
        }
        Ok(server_proto::format_server_invite(&addrs, &token_str))
    }

    /// Sunucunun KALICI, herkese açık katılım kodu — bir kez yayımlanır,
    /// sınırsız kişi kendi başına katılır.
    ///
    /// Kullanıcı isteği: "tek QR/link ile birden çok kişi katılabilmeli,
    /// server ile etkileşime girmeye gerek kalmadan". `create_invite` bunu
    /// tek başına çözmüyordu, çünkü kod her çağrıda DEĞİŞİYOR ve jeton
    /// hash'li saklandığı için bir daha GÖSTERİLEMİYORDU: operatör kodu
    /// kaybettiği anda tek çıkışı yeni bir kod üretip herkese yeniden
    /// dağıtmaktı.
    ///
    /// Bu yüzden herkese açık jeton `meta` içinde AÇIK saklanır. Hash'leme
    /// tek kullanımlık davetlerde diski ele geçiren saldırganın HENÜZ
    /// KULLANILMAMIŞ bir daveti kullanmasını engellemek içindi; kalıcı
    /// katılım kodu tanımı gereği ZATEN herkese açık (afişte, mesajda,
    /// web sayfasında), yani hash'lemenin koruyacağı bir sır yok — buna
    /// karşılık geri okunabilir olması özelliğin TEMELİ.
    pub fn join_code(&self) -> Result<String, String> {
        let addrs = self.invite_addrs();
        if addrs.is_empty() {
            return Err("Sunucunun henüz bir dinleme adresi yok (birkaç saniye sonra tekrar deneyin)".to_string());
        }
        let token = public_join_token(&self.store, false)?;
        Ok(server_proto::format_server_invite(&addrs, &token))
    }

    /// Herkese açık kodu değiştirir: eskisi ANINDA geçersiz olur (kayıtlı
    /// cihazlar etkilenmez — onların kaydı jetondan bağımsız, bkz.
    /// `handle_rebind`). Operatörün kod sızdığında/istenmeyen katılım
    /// olduğunda tek hamlede kapıyı kapatma yolu.
    pub fn rotate_join_code(&self) -> Result<String, String> {
        let addrs = self.invite_addrs();
        if addrs.is_empty() {
            return Err("Sunucunun henüz bir dinleme adresi yok (birkaç saniye sonra tekrar deneyin)".to_string());
        }
        let token = public_join_token(&self.store, true)?;
        Ok(server_proto::format_server_invite(&addrs, &token))
    }

    // -----------------------------------------------------------------
    // Ana döngü
    // -----------------------------------------------------------------

    pub async fn run(self) -> Result<(), String> {
        self.run_until(std::future::pending::<()>()).await
    }

    /// `run`'un DURDURULABİLİR hâli — `shutdown` tamamlandığında döngü biter
    /// ve `ServerCore` düşürülür (swarm, dinleyiciler, onion service).
    ///
    /// Defter #11: Android sunucu uygulamasının `ServerLib` yüzeyinde
    /// durdurma yoktu. `stopService(...)` yalnızca wake lock'u bırakıp ön
    /// plan bildirimini kaldırıyor; Rust çekirdeği süreçte çalışmaya devam
    /// ediyordu — hâlâ posta kabul ediyor, blob servis ediyor, pil ve disk
    /// harcıyor. Arayüzdeki anahtar "kapalı" gösterirken sunucu açıktı.
    /// İkinci yarısı daha sinsiydi: `CONTROL` dolu olduğu için sonraki
    /// `startServer` çağrıları no-op'tu, yani node modu / sunucu adı / blob
    /// dizini / disk bütçesi değişiklikleri süreç öldürülene kadar HİÇ
    /// uygulanmıyordu.
    pub async fn run_until(
        mut self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), String> {
        info!("Typeon sunucusu başladı: peer_id={}", self.local_peer_id());
        // Zamanlayıcı ve sinyal AYRI yerel değişkenler olmak ZORUNDA:
        // `tokio::select!` bütün dalların future'larını AYNI kapsamda
        // oluşturur, swarm dalı da `self`i ödünç alıyor — bunlar satır içi
        // yazılsaydı ikinci bir `&mut self` ödüncü doğar ve derlenmezdi.
        let mut sweep = tokio::time::interval(Duration::from_secs(5));
        let ctrlc = tokio::signal::ctrl_c();
        // bkz. modül notu / yukarıdaki yorum — `self`i ödünç alan bir arm
        // future'ı satır içinde yazılamaz; alıcıyı bir yerel değişkene alıyoruz.
        let mut net_changed_rx = self.net_changed_rx.take();
        futures::pin_mut!(ctrlc);
        futures::pin_mut!(shutdown);
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.handle_swarm_event(event),
                _ = sweep.tick() => self.maybe_sweep(),
                // bkz. `notify_network_changed` — kanal yoksa/kapandıysa bu
                // dal sonsuza kadar bekler (asla tetiklenmez).
                Some(()) = async {
                    match &mut net_changed_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<()>>().await,
                    }
                } => {
                    info!("Ağ değişikliği bildirildi — Tor tazeleniyor");
                    self.notify_network_changed();
                }
                _ = &mut shutdown => {
                    info!("Durdurma istendi, kapatılıyor.");
                    return Ok(());
                }
                _ = &mut ctrlc => {
                    info!("Kapatılıyor.");
                    return Ok(());
                }
            }
        }
    }

    /// Swarm'ı sınırlı bir süre boyunca döndürür, sonra döner.
    ///
    /// `run` sonsuz döngüsünün yanında buna ihtiyaç var çünkü yönetim
    /// komutları (`invite new`, `address`) bir dinleme adresi GÖRÜNENE kadar
    /// beklemek zorunda: adres olmadan üretilen bir davet kodu kimseye
    /// yaramaz. Tor açıkken onion adresi arti'nin bootstrap'ını bekler.
    pub async fn pump_for(&mut self, duration: Duration) {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return;
            }
            match tokio::time::timeout(remaining, self.swarm.select_next_some()).await {
                Ok(event) => self.handle_swarm_event(event),
                Err(_) => return,
            }
        }
    }

    fn handle_swarm_event(&mut self, event: SwarmEvent<ServerBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Dinleniyor: {}/p2p/{}", address, self.local_peer_id());
                // Davet kodu ancak bir adres bilindikten sonra üretilebilir,
                // bu yüzden anlık görüntüyü beklemeden tazele.
                self.publish_shared();
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.conns.entry(peer_id).or_insert(ConnState {
                    challenge: None,
                    window_start: now_ms() as u64,
                    requests_in_window: 0,
                });
            }
            SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                if num_established == 0 {
                    self.conns.remove(&peer_id);
                    self.live_interest.remove(&peer_id);
                }
            }
            SwarmEvent::Behaviour(ServerBehaviourEvent::ServerRpc(
                request_response::Event::Message { peer, message },
            )) => {
                if let request_response::Message::Request { request, channel, .. } = message {
                    let response = self.handle_request(peer, request);
                    let _ = self.swarm.behaviour_mut().server_rpc.send_response(channel, response);
                }
            }
            SwarmEvent::Behaviour(ServerBehaviourEvent::FileChunks(
                request_response::Event::Message { peer, message },
            )) => {
                if let request_response::Message::Request { request, channel, .. } = message {
                    self.serve_chunk(peer, request, channel);
                }
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------
    // İstek işleme
    // -----------------------------------------------------------------

    fn handle_request(&mut self, peer: PeerId, req: ServerRequest) -> ServerResponse {
        if !self.check_rate(peer) {
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }

        match req {
            ServerRequest::Hello { version } => self.handle_hello(peer, version),
            ServerRequest::Enroll { version, invite_token, enroll_pk, enroll_pk_pq, challenge, ts_ms, sig, sig_pq } => {
                self.handle_enroll(peer, version, invite_token, enroll_pk, enroll_pk_pq, challenge, ts_ms, sig, sig_pq)
            }
            ServerRequest::Rebind { enrollment_id, ts_ms, sig, sig_pq } => {
                self.handle_rebind(peer, enrollment_id, ts_ms, sig, sig_pq)
            }

            // --- buradan sonrası kayıt ZORUNLU ---
            other => {
                let Some(e) = self.authenticate(peer) else {
                    self.stats.rejected += 1;
                    return ServerResponse::Err(ServerErrorCode::NotEnrolled);
                };
                if e.state == EnrollmentState::Revoked {
                    self.stats.rejected += 1;
                    return ServerResponse::Err(ServerErrorCode::Revoked);
                }
                self.handle_authenticated(peer, &e, other)
            }
        }
    }

    fn handle_hello(&mut self, peer: PeerId, version: u16) -> ServerResponse {
        if version != SERVER_PROTOCOL_VERSION {
            return ServerResponse::Err(ServerErrorCode::Unsupported);
        }
        let mut challenge = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        // SADECE etkin kayıt "kayıtlı" sayılır.
        //
        // Daha önce `.is_some()` idi ve bu, iptal edilmiş bir cihazı KALICI
        // olarak kilitliyordu: istemci `Welcome.enrolled = true` görüp
        // `Enroll` adımını atlıyor, ardından gönderdiği HER istek
        // `authenticate` → `state == Revoked` yolundan `Revoked` dönüyordu.
        // Kullanıcıya görünen hâli, taze bir davet koduyla eklediği anda
        // "Operatör kaydı iptal etti" yazısıydı ve hiçbir zaman düzelmiyordu.
        // İptal, o kimlik bilgisini geçersiz kılar — kişiyi sonsuza dek
        // yasaklamaz; operatör yeni bir davet verdiyse yeniden kaydolabilmeli
        // (`handle_enroll` zaten `INSERT OR REPLACE` ile eski satırı değiştirir).
        let enrolled = self
            .store
            .enrollment_by_peer(&peer.to_string())
            .map(|e| e.state == EnrollmentState::Active)
            .unwrap_or(false);
        if let Some(c) = self.conns.get_mut(&peer) {
            c.challenge = Some(challenge.clone());
        }
        ServerResponse::Welcome {
            version: SERVER_PROTOCOL_VERSION,
            challenge,
            enrolled,
            limits: self.config.limits.clone(),
            server_name: self.config.server_name.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_enroll(
        &mut self,
        peer: PeerId,
        version: u16,
        invite_token: Vec<u8>,
        enroll_pk: Vec<u8>,
        enroll_pk_pq: Vec<u8>,
        client_challenge: Vec<u8>,
        ts_ms: u64,
        sig: Vec<u8>,
        sig_pq: Vec<u8>,
    ) -> ServerResponse {
        if version != SERVER_PROTOCOL_VERSION {
            return ServerResponse::Err(ServerErrorCode::Unsupported);
        }
        let now = now_ms();
        if (now - ts_ms as i64).abs() > server_proto::ENROLL_MAX_SKEW_MS as i64 {
            return ServerResponse::Err(ServerErrorCode::Stale);
        }
        // Challenge tek kullanımlık: aksi halde bir gözlemci imzayı yakalayıp
        // başka bir bağlantıda tekrar oynatabilirdi.
        let expected = self.conns.get(&peer).and_then(|c| c.challenge.clone());
        let Some(challenge) = expected else {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        };
        // İstemcinin imzaladığı challenge, BİZİM verdiğimiz olmalı.
        if client_challenge != challenge {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        match self.store.consume_challenge(&challenge, now) {
            Ok(true) => {}
            _ => return ServerResponse::Err(ServerErrorCode::BadSignature),
        }
        if let Some(c) = self.conns.get_mut(&peer) {
            c.challenge = None;
        }

        let signing_input = server_proto::enroll_signing_input(
            version,
            &self.local_peer_id().to_string(),
            &invite_token,
            &challenge,
            ts_ms,
        );
        // HİBRİT: ikisi de geçmeli. Tek başına klasik bir imza,
        // hasat-şimdi-kır-sonra bir saldırgana ileride sahte kayıt üretme
        // imkânı verirdi.
        if !verify_hybrid(&enroll_pk, &enroll_pk_pq, &signing_input, &sig, &sig_pq) {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        // Kullanıcı kararı: ENGEL, iptalden farklı. `revoke` yalnızca mevcut
        // kaydı kapatır ve taze bir davetle geri dönüşe izin verir; engel
        // ise kayıt ANAHTARINA konur, yani aynı cihaz yeni bir davetle bile
        // kaydolamaz. Kontrol imza doğrulandıktan SONRA: anahtarın gerçekten
        // bu cihaza ait olduğu kanıtlanmadan engel uygulamak, başkasının
        // anahtarını yazarak onu engelletmeye yol açardı.
        if self.store.is_key_blocked(&enroll_pk) {
            warn!("Engellenen anahtarla kayıt denemesi reddedildi");
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }

        let hash = Sha256::digest(&invite_token);
        // Herkese açık (sınırsız) katılım kodunun Sybil kapısı, jetonun
        // TEK KULLANIMLIK olması değil — o özellik bilerek bırakıldı (bkz.
        // `join_code`). Yerine geçen kapı bu: sınırsız bir kod, son bir
        // saatte açılmış kayıt sayısı `MAX_PUBLIC_ENROLLMENTS_PER_HOUR`'a
        // ulaştıysa YENİ kayıt açamaz. Pencere BÜTÜN kayıtları sayar
        // (sayılı davetle açılanları da): amaç tek bir kodu değil,
        // sunucunun kayıt hızını sınırlamak. Gerçek bir grubun katılım
        // hızının çok üstünde, otomatik bir kayıt seli için ise düşük;
        // operatör bu sırada `rotate_join_code` ile kodu kapatabilir.
        // Tavan SAYAÇ TÜKETMEDEN önce bakılır: reddedilen bir deneme,
        // davetin kullanım hakkını hiç harcamamalı.
        if self.store.invite_uses_left(hash.as_slice()) == Some(-1) {
            let since = now - 60 * 60 * 1000;
            if self.store.count_enrollments_since(since) >= MAX_PUBLIC_ENROLLMENTS_PER_HOUR {
                warn!("Herkese açık katılım kodu saatlik tavanı aştı, kayıt reddedildi");
                self.stats.rejected += 1;
                return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
            }
        }
        match self.store.consume_invite(hash.as_slice(), now) {
            Ok(true) => {}
            _ => return ServerResponse::Err(ServerErrorCode::BadInvite),
        }

        let mut enrollment_id = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut enrollment_id);
        let e = Enrollment {
            enrollment_id: enrollment_id.clone(),
            enroll_pk,
            enroll_pk_pq,
            peer_id: peer.to_string(),
            state: EnrollmentState::Active,
            enrolled_at: now,
            last_seen_at: now,
            bytes_mail: 0,
            bytes_archive: 0,
            bytes_blob: 0,
        };
        if let Err(msg) = self.store.insert_enrollment(&e) {
            error!("Kayıt yazılamadı: {msg}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        self.stats.enrollments += 1;
        info!("Yeni kayıt: {}", hex::encode(&enrollment_id));
        ServerResponse::Enrolled { enrollment_id, limits: self.config.limits.clone() }
    }

    fn handle_rebind(
        &mut self,
        peer: PeerId,
        enrollment_id: Vec<u8>,
        ts_ms: u64,
        sig: Vec<u8>,
        sig_pq: Vec<u8>,
    ) -> ServerResponse {
        let now = now_ms();
        if (now - ts_ms as i64).abs() > server_proto::ENROLL_MAX_SKEW_MS as i64 {
            return ServerResponse::Err(ServerErrorCode::Stale);
        }
        let Some(existing) = self.store.enrollment_by_id(&enrollment_id) else {
            return ServerResponse::Err(ServerErrorCode::NotEnrolled);
        };
        if existing.state == EnrollmentState::Revoked {
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }
        // Engelli anahtar yeniden bağlanamaz da (bkz. `handle_enroll`).
        if self.store.is_key_blocked(&existing.enroll_pk) {
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }
        let input = server_proto::rebind_signing_input(&enrollment_id, &self.local_peer_id().to_string(), ts_ms);
        if !verify_hybrid(&existing.enroll_pk, &existing.enroll_pk_pq, &input, &sig, &sig_pq) {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        if let Err(msg) = self.store.rebind_enrollment(&enrollment_id, &peer.to_string(), now) {
            error!("Rebind yazılamadı: {msg}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        ServerResponse::Enrolled { enrollment_id, limits: self.config.limits.clone() }
    }

    /// Noise'un KANITLADIĞI `PeerId`'den kaydı çözer. Paketin İDDİA ettiği
    /// hiçbir alana güvenilmez — çekirdeğin hız sınırının bilinçli olarak
    /// `sender_device_fingerprint` yerine `PeerId`'yi kullanmasıyla aynı
    /// gerekçe.
    fn authenticate(&self, peer: PeerId) -> Option<Enrollment> {
        self.store.enrollment_by_peer(&peer.to_string())
    }

    /// Sunucunun TOPLAM disk tavanı (defter #23) — `incoming` bayt daha
    /// yazılırsa bütçe aşılır mı?
    ///
    /// Bu denetimde bulundu: tavan yalnızca `handle_blob_put`'ta
    /// uygulanıyordu. Posta ve arşiv kayıt BAŞINA kotayla sınırlıydı, yani
    /// yeterince kayıt açan (ya da sadece yeterince kalabalık) bir sunucuda
    /// toplam kullanım bütçeyi katbekat aşabiliyordu — ki bu mekanizmanın
    /// var olma sebebi zaten telefonun/tabletin dolan diskiydi. Bloblar en
    /// hacimli olan ama tek olan değil: 30 gün TTL'li posta ve süresiz arşiv
    /// de birikir.
    fn total_budget_exceeded(&self, incoming: usize) -> bool {
        let Some(total_budget) = self.config.total_storage_budget_bytes else {
            return false;
        };
        self.store.total_stored_bytes() as u64 + incoming as u64 > total_budget
    }

    fn handle_authenticated(&mut self, peer: PeerId, e: &Enrollment, req: ServerRequest) -> ServerResponse {
        let now = now_ms();
        self.store.touch_enrollment(&e.enrollment_id, now);
        let limits = self.config.limits.clone();

        match req {
            ServerRequest::Register { add, drop } => {
                if let Err(msg) = self.store.register_mailboxes(&e.enrollment_id, &add, &drop, now, limits.max_mailboxes) {
                    warn!("Register reddedildi: {msg}");
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                let interest = self.live_interest.entry(peer).or_default();
                for id in add {
                    interest.insert(id);
                }
                for id in &drop {
                    interest.remove(id);
                }
                ServerResponse::Ok
            }

            ServerRequest::Deposit { mailbox, sealed } => {
                if sealed.len() > limits.max_item_bytes as usize || sealed.len() > MAX_DEPOSIT_BYTES {
                    return ServerResponse::Err(ServerErrorCode::TooLarge);
                }
                // Kayıtlı olmayan bir kutuya bırakmak, istemciye "bu alıcı
                // benim sunucumda değil" demek — o da trafiği doğrudan
                // gossipsub'a yollar ve her mesajda boşuna gidiş-dönüş
                // ödemez.
                if !self.store.mailbox_is_registered(&mailbox) {
                    return ServerResponse::Err(ServerErrorCode::UnknownMailbox);
                }
                if self.store.quota_exceeded(e, &limits) {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // bkz. `total_budget_exceeded` — kayıt başına kota TEK
                // başına cihazın diskini korumuyor.
                if self.total_budget_exceeded(sealed.len()) {
                    warn!("Toplam disk bütçesi doldu, teslim reddedildi");
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                if self.store.mailbox_item_count(&mailbox) >= limits.max_items_per_mailbox as i64 {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                match self.store.deposit(&mailbox, &sealed, &e.enrollment_id, now, limits.mailbox_ttl_ms as i64) {
                    Ok(seq) => {
                        self.stats.deposits += 1;
                        self.notify_owner_of(&mailbox, peer);
                        ServerResponse::Deposited { seq }
                    }
                    Err(msg) => {
                        error!("Deposit yazılamadı: {msg}");
                        ServerResponse::Err(ServerErrorCode::Internal)
                    }
                }
            }

            ServerRequest::Fetch { cursors, max_items, max_bytes } => {
                let (items, more) = self.store.fetch(
                    &e.enrollment_id,
                    &cursors,
                    max_items.min(MAX_FETCH_BATCH_ITEMS),
                    max_bytes.min(MAX_FETCH_BATCH_BYTES),
                );
                self.stats.fetches += 1;
                ServerResponse::Batch { items, more }
            }

            ServerRequest::Ack { acks } => {
                let mut deleted = 0;
                for (mailbox, seq) in acks {
                    deleted += self.store.ack(&mailbox, seq, &e.enrollment_id).unwrap_or(0);
                }
                if deleted > 0 {
                    // Kota tek yönlü artmamalı — teslim edilen baytlar
                    // bırakanın hesabından düşer.
                    self.store.recount_mail_bytes();
                }
                ServerResponse::Ok
            }

            // bkz. `ServerRequest::Cancel` — gönderen kendi teslim
            // edilmemiş paketini geri çeker. Sahiplik kontrolü sorgunun
            // içinde: `depositor = requester`.
            ServerRequest::Cancel { mailbox, seqs } => {
                let removed = self.store.cancel_own_deposits(&mailbox, &seqs, &e.enrollment_id);
                if removed > 0 {
                    self.store.recount_mail_bytes();
                    info!("Gönderen {} paketi geri çekti", removed);
                }
                ServerResponse::Ok
            }

            ServerRequest::ArchivePut { bucket, records } => {
                if self.store.quota_exceeded(e, &limits) {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // bkz. `total_budget_exceeded` — arşiv, postanın aksine
                // TTL'siz: bir kez yazıldı mı `ArchivePurge` gelene kadar
                // durur, yani toplam tavana en çok yaklaştıran taraf.
                let incoming: usize = records.iter().map(|r| r.sealed.len()).sum();
                if self.total_budget_exceeded(incoming) {
                    warn!("Toplam disk bütçesi doldu, arşiv yazımı reddedildi");
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                match self.store.archive_put(&bucket, &records, &e.enrollment_id, now) {
                    Ok(_) => {
                        self.stats.archive_puts += 1;
                        ServerResponse::Ok
                    }
                    Err(msg) => {
                        error!("ArchivePut yazılamadı: {msg}");
                        ServerResponse::Err(ServerErrorCode::Internal)
                    }
                }
            }

            ServerRequest::ArchiveProbe { buckets } => {
                ServerResponse::ArchiveProbed { present: self.store.archive_probe(&buckets) }
            }

            ServerRequest::ArchiveFetch { bucket, before_ms, max_items, max_bytes } => {
                let (records, more) = self.store.archive_fetch(
                    &bucket,
                    before_ms,
                    max_items.min(MAX_FETCH_BATCH_ITEMS),
                    max_bytes.min(MAX_FETCH_BATCH_BYTES),
                );
                ServerResponse::ArchiveBatch { records, more }
            }

            ServerRequest::ArchivePurge { buckets } => {
                self.store.archive_purge(&buckets, &e.enrollment_id);
                ServerResponse::Ok
            }

            ServerRequest::BlobPut { blob_id, chunk_index, total_chunks, chunk_size, data } => {
                self.handle_blob_put(e, &limits, blob_id, chunk_index, total_chunks, chunk_size, data, now)
            }

            ServerRequest::BlobFinish { blob_id, total_chunks, enc_sha256 } => {
                self.handle_blob_finish(e, blob_id, total_chunks, enc_sha256, now)
            }

            ServerRequest::BlobDelete { blob_id } => {
                if self.store.blob_delete(&blob_id, &e.enrollment_id) {
                    let _ = std::fs::remove_file(self.blob_path(&blob_id));
                }
                ServerResponse::Ok
            }

            // İstemciden sunucuya gelemeyecek türler.
            ServerRequest::Hello { .. }
            | ServerRequest::Enroll { .. }
            | ServerRequest::Rebind { .. }
            | ServerRequest::Notify => ServerResponse::Err(ServerErrorCode::BadDirection),
        }
    }

    // -----------------------------------------------------------------
    // Bloblar
    // -----------------------------------------------------------------

    fn blob_path(&self, blob_id: &str) -> PathBuf {
        // `blob_id` istemciden geliyor — dosya yolu olarak kullanmadan ÖNCE
        // hex/alfanümerik olduğu doğrulanmalı, aksi halde "../" ile dizin
        // dışına yazılabilirdi.
        self.config.blob_dir.join(format!("{}.enc", sanitize_id(blob_id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_blob_put(
        &mut self,
        e: &Enrollment,
        limits: &ServerLimits,
        blob_id: String,
        chunk_index: u32,
        total_chunks: u32,
        chunk_size: u32,
        data: Vec<u8>,
        now: i64,
    ) -> ServerResponse {
        if !is_safe_id(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if data.len() > server_proto::MAX_BLOB_CHUNK_BYTES {
            return ServerResponse::Err(ServerErrorCode::TooLarge);
        }
        if e.bytes_blob as u64 + data.len() as u64 > limits.max_blob_bytes {
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Defter #23: kotalar SADECE kayıt başına uygulanıyordu. Bütçe sabit
        // `EXPECTED_DEVICES = 8`'e bölündüğü için 20 cihaz kaydolduğunda
        // gerçek tavan bütçenin 2,5 katı oluyordu — bu mekanizmanın var olma
        // sebebi zaten tabletin dolan diskiydi. Artık toplam da kontrol
        // ediliyor.
        if self.total_budget_exceeded(data.len()) {
            warn!("Toplam disk bütçesi doldu, blob parçası reddedildi");
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        if let Err(msg) = self.store.blob_begin(&blob_id, &e.enrollment_id, total_chunks, now) {
            error!("blob_begin: {msg}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        // Sahiplik: bir blob'a SADECE onu başlatan kayıt yazabilir.
        if let Some(state) = self.store.blob_state(&blob_id) {
            if state.owner != e.enrollment_id {
                return ServerResponse::Err(ServerErrorCode::BadDirection);
            }
            if chunk_index >= total_chunks.max(state.total_chunks) {
                return ServerResponse::Err(ServerErrorCode::BadDirection);
            }
        }
        // Zaten yazılmış bir parçanın tekrarı — idempotent.
        if self.store.blob_has_chunk(&blob_id, chunk_index) {
            return ServerResponse::Ok;
        }

        // KONUM tabanlı yazma (sona ekleme DEĞİL). Sona ekleme, parçaların
        // kesin olarak sırayla gelmesini şart koşuyordu; yani istemci aynı
        // anda tek parça gönderebiliyor ve hız `parça/gidiş-dönüş` ile
        // sınırlı kalıyordu — Tor üzerinde ölçülen 10 MB yükleme ~12 KB/s.
        // `.enc` formatı sabit adımlı olduğundan (bkz.
        // `attachments::read_chunk_from_disk`) konuma yazmak güvenli.
        use std::io::{Seek, SeekFrom, Write};
        let path = self.blob_path(&blob_id);
        // Adim ISTEMCIDEN gelir (bkz. `ServerRequest::BlobPut.chunk_size`);
        // sunucunun kendi sabitinden tahmin etmesi dosyayi bozuyordu.
        // Adım blob'la birlikte SAKLANIR (defter #06) — `serve_chunk` aynı
        // değerle okumak zorunda, yoksa dosya yanlış ofsetlerden servis
        // edilir.
        self.store.blob_set_chunk_size(&blob_id, chunk_size);
        let stride = if chunk_size == 0 { attachments::FILE_CHUNK_SIZE as u64 } else { chunk_size as u64 };
        let offset = chunk_index as u64 * (stride + 16);
        let write = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .and_then(|mut f| {
                f.seek(SeekFrom::Start(offset))?;
                f.write_all(&data)
            });
        if let Err(err) = write {
            error!("Blob yazılamadı: {err}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        let _ = self.store.blob_record_chunk(&blob_id, chunk_index, data.len());
        self.store.add_blob_bytes(&e.enrollment_id, data.len() as i64);
        ServerResponse::Ok
    }

    fn handle_blob_finish(
        &mut self,
        e: &Enrollment,
        blob_id: String,
        total_chunks: u32,
        enc_sha256: Vec<u8>,
        now: i64,
    ) -> ServerResponse {
        if !is_safe_id(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        let Some(state) = self.store.blob_state(&blob_id) else {
            return ServerResponse::Err(ServerErrorCode::Internal);
        };
        if state.owner != e.enrollment_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if state.received_chunks < total_chunks {
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        // ŞİFRELİ baytların hash'i — sunucu içeriği çözemez ama kırpılmış
        // bir yüklemeyi asla servis etmemeyi garanti edebilir.
        // Defter #07: burası `std::fs::read` ile dosyanın TAMAMINI belleğe
        // alıyordu — varsayılan `max_blob_bytes` 4 GiB, yani sunucu bir
        // telefonda çalışırken herhangi bir kayıtlı istemcinin
        // tetikleyebildiği doğrudan OOM. İstemci tarafındaki karşılığı
        // (`server_client::sha256_file`) zaten 64 KiB'lık tamponla akış
        // hâlinde hash'liyor; aynı desen.
        match hash_file_streaming(&self.blob_path(&blob_id)) {
            Some((actual, len)) => {
                if actual.as_slice() != enc_sha256.as_slice() {
                    warn!("Blob hash uyuşmuyor, reddedildi: {blob_id}");
                    let _ = std::fs::remove_file(self.blob_path(&blob_id));
                    self.store.blob_forget(&blob_id);
                    self.store.add_blob_bytes(&e.enrollment_id, -(len as i64));
                    return ServerResponse::Err(ServerErrorCode::Internal);
                }
            }
            None => return ServerResponse::Err(ServerErrorCode::Internal),
        }
        let _ = self.store.blob_finish(&blob_id, &enc_sha256, now);
        ServerResponse::Ok
    }

    /// Dosya parçası servisi.
    ///
    /// `serve_chunk_request`in (çekirdek) sunucu karşılığı — ve KASITLI
    /// olarak neredeyse aynı: `read_chunk_from_disk` diskteki `.enc`
    /// dosyasından OLDUĞU GİBİ okuyor, çünkü disk formatı = kablo formatı.
    /// Sunucu hiçbir şeyi şifrelemiyor, çözmüyor, yeniden çerçevelemiyor.
    fn serve_chunk(
        &mut self,
        peer: PeerId,
        req: FileChunkRequest,
        channel: ResponseChannel<FileChunkResponse>,
    ) {
        // Bu denetimde bulundu: bu yol `handle_request`'ten TAMAMEN ayrı
        // (ayrı bir request_response davranışı, doğrudan `handle_swarm_event`
        // içinden çağrılıyor) ve orada duran kayıt kontrolünün
        // (`authenticate`) dışındaydı. Sonucu: bu protokolü konuşan HERHANGİ
        // bir eş — hiç kaydolmamış, node modunda bize bağlanan bir yabancı
        // dahil — bir `blob_id` bildiği/denediği anda parça çekebiliyordu.
        // Baytlar `file_key` ile şifreli olduğundan içerik doğrudan
        // sızmıyordu, ama `NotFound`/`Chunk` ayrımı "bu dosya sunucuda var
        // mı" sorusuna bir kâhin (oracle) olarak cevap veriyordu ve
        // yabancıya sınırsız disk/CPU işi yaptırıyordu. Çekirdek
        // tarafındaki AYNI hata (`may_serve_file_to`) önceki denetimde
        // kapatılmıştı; sunucu karşılığı atlanmıştı.
        //
        // Meşru istemciler etkilenmez: `ready_server_peers` (istemci) bir
        // sunucuyu ancak `connected && enrolled` iken kaynak olarak
        // kullanıyor, yani bir indirme buraya her zaman kayıtlı bir
        // `PeerId` ile gelir.
        //
        // Hız sınırı (`check_rate`) burada KASITLI olarak uygulanmıyor:
        // `FileChunkResponse`'ın "rate limited" hâli yok ve istemci
        // `NotFound`'u KALICI bir cevap sayıp başka bir kaynağa geçiyor
        // (bkz. `handle_chunk_response`) — dakikalık RPC bütçesini büyük bir
        // indirmenin binlerce parça isteğiyle paylaştırmak, meşru
        // indirmeleri sessizce böler. Yük koruması kayıt kapısı + kota
        // tarafında.
        let enrolled = self
            .authenticate(peer)
            .map(|e| e.state != EnrollmentState::Revoked)
            .unwrap_or(false);
        if !enrolled {
            warn!("Kayıtsız eşten dosya parçası isteği reddedildi: {peer}");
            self.stats.rejected += 1;
            let _ = self
                .swarm
                .behaviour_mut()
                .file_chunks
                .send_response(channel, FileChunkResponse::NotFound);
            return;
        }
        let response = if !is_safe_id(&req.file_id) {
            FileChunkResponse::NotFound
        } else {
            match self.store.blob_state(&req.file_id) {
                Some(state) if state.complete => {
                    self.store.blob_touch(&req.file_id, now_ms());
                    // Defter #06: burası `read_chunk_from_disk` (sabit 256
                    // KiB adım) çağırıyordu, oysa `handle_blob_put` adımı
                    // İSTEMCİDEN alıp (`BlobPut.chunk_size`) ona göre
                    // yazıyor. İkisi ayrıştığı anda her blob yanlış
                    // ofsetlerden okunurdu — daha önce ölçümü bozan tam o
                    // hata. Adım artık blob'la birlikte saklanıyor.
                    let stride = self.store.blob_chunk_size(&req.file_id).unwrap_or(0) as usize;
                    match attachments::read_chunk_from_disk_with(
                        &self.blob_path(&req.file_id),
                        req.chunk_index,
                        stride,
                    ) {
                        Ok(Some(data)) => {
                            self.stats.blob_chunks_served += 1;
                            FileChunkResponse::Chunk { data }
                        }
                        _ => FileChunkResponse::NotFound,
                    }
                }
                // Yarım kalmış bir yükleme SERVİS EDİLMEZ: istemci
                // `NotFound`'u görünce ANINDA başka bir kaynağa döner
                // (bkz. `handle_chunk_response` — kasıtlı olarak yeniden
                // denenmez).
                _ => FileChunkResponse::NotFound,
            }
        };
        let _ = self.swarm.behaviour_mut().file_chunks.send_response(channel, response);
    }

    // -----------------------------------------------------------------
    // İtme (Notify) ve süpürme
    // -----------------------------------------------------------------

    /// Kutuyu dinleyen BAĞLI bir eş varsa ona "posta var" der.
    ///
    /// Bu olmadan istemcinin sürekli `Fetch` ile yoklaması gerekirdi; bir
    /// telefonda bu doğrudan pil demek. Yük burada taşınmaz — istemci kendi
    /// turunda `Fetch` eder, böylece imleç mantığı bozulmaz.
    fn notify_owner_of(&mut self, mailbox: &str, depositor: PeerId) {
        let targets: Vec<PeerId> = self
            .live_interest
            .iter()
            .filter(|(peer, boxes)| **peer != depositor && boxes.contains(mailbox))
            .map(|(peer, _)| *peer)
            .collect();
        for peer in targets {
            self.swarm.behaviour_mut().server_rpc.send_request(&peer, ServerRequest::Notify);
        }
    }

    fn check_rate(&mut self, peer: PeerId) -> bool {
        let limit = self.config.limits.requests_per_minute;
        let now = now_ms() as u64;
        let entry = self.conns.entry(peer).or_insert(ConnState {
            challenge: None,
            window_start: now,
            requests_in_window: 0,
        });
        if now.saturating_sub(entry.window_start) > RATE_WINDOW_MS {
            entry.window_start = now;
            entry.requests_in_window = 0;
        }
        entry.requests_in_window += 1;
        entry.requests_in_window <= limit
    }

    /// Yapılandırılmış blob dizini — Android sunucu uygulaması bunu harici
    /// bir birime taşıyabiliyor (bkz. defter #24).
    pub fn blob_dir(&self) -> &PathBuf {
        &self.config.blob_dir
    }

    /// Veri dizini (kimlik, Tor durumu, SQLite) — blob dizininden AYRI
    /// olabilir.
    pub fn data_dir(&self) -> &PathBuf {
        &self.config.data_dir
    }

    fn maybe_sweep(&mut self) {
        let now = now_ms();
        if (now as u64).saturating_sub(self.last_sweep) < SWEEP_INTERVAL_MS {
            return;
        }
        self.last_sweep = now as u64;
        self.publish_shared();

        let expired = self.store.sweep_expired_mail(now);
        if expired > 0 {
            info!("Süresi dolan {expired} teslim öğesi silindi");
            self.store.recount_mail_bytes();
        }
        for blob_id in self.store.blobs_to_gc(now, self.config.limits.blob_ttl_ms as i64) {
            let path = self.blob_path(&blob_id);
            if let Ok(meta) = std::fs::metadata(&path) {
                if let Some(state) = self.store.blob_state(&blob_id) {
                    self.store.add_blob_bytes(&state.owner, -(meta.len() as i64));
                }
            }
            let _ = std::fs::remove_file(path);
            self.store.blob_forget(&blob_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Yardımcılar
// ---------------------------------------------------------------------------

/// libp2p kimliği kalıcı: `PeerId` yeniden başlatmalar arasında DEĞİŞMEMELİ,
/// yoksa dağıtılmış her davet kodu geçersiz olurdu.
/// Bir dosyayı belleğe TAMAMEN almadan SHA-256'lar — dönüş (özet, bayt sayısı).
/// bkz. defter #07.
fn hash_file_streaming(path: &std::path::Path) -> Option<(Vec<u8>, u64)> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Some((hasher.finalize().to_vec(), total))
}

fn load_or_generate_keypair(store: &Store) -> Result<libp2p::identity::Keypair, String> {
    if let Some(bytes) = store.meta_get("libp2p_key") {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return Ok(kp);
        }
        warn!("Kayıtlı libp2p anahtarı okunamadı, yenisi üretiliyor");
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let encoded = kp.to_protobuf_encoding().map_err(|e| e.to_string())?;
    store.meta_set("libp2p_key", &encoded)?;
    Ok(kp)
}

/// Hibrit imza doğrulaması — çekirdeğin `verify_hybrid_signature`'ıyla aynı
/// sözleşme: İKİSİ de geçmeli, biri boşsa reddedilir.
fn verify_hybrid(pk: &[u8], pk_pq: &[u8], message: &[u8], sig: &[u8], sig_pq: &[u8]) -> bool {
    if sig.is_empty() || sig_pq.is_empty() {
        return false;
    }
    if !verify_ed25519(pk, message, sig) {
        return false;
    }
    let Ok(pk_encoded): Result<&EncodedVerifyingKey<MlDsa87>, _> = pk_pq.try_into() else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa87>::decode(pk_encoded);
    let Ok(sig_encoded): Result<&EncodedSignature<MlDsa87>, _> = sig_pq.try_into() else {
        return false;
    };
    let Some(parsed) = MlDsaSignature::<MlDsa87>::decode(sig_encoded) else {
        return false;
    };
    vk.verify(message, &parsed).is_ok()
}

fn verify_ed25519(pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let Ok(pk_bytes): Result<[u8; 32], _> = pubkey.try_into() else { return false };
    let Ok(sig_bytes): Result<[u8; 64], _> = sig.try_into() else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else { return false };
    vk.verify(message, &Signature::from_bytes(&sig_bytes)).is_ok()
}

/// Bir multiaddr özel/yerel bir ağa mı işaret ediyor?
///
/// Davet kodundan elenirler (bkz. `invite_addrs`): başka bir ağdaki alıcı
/// için ulaşılamazlar ve sunucunun iç ağ yapısını sızdırırlar.
pub(crate) fn is_private_multiaddr(addr: &str) -> bool {
    // Tek tanım çekirdekte (bkz. `server_proto::is_private_multiaddr`) —
    // istemci de AYNI kuralı uyguluyor, ikisi ayrışmasın.
    server_proto::is_private_multiaddr(addr)
}

/// Kimliklerin dosya yolu olarak kullanılmadan önceki kontrolü.
///
/// `blob_id` ve `file_id` istemciden geliyor. Doğrulanmadan bir yola
/// gömülseydi `../../` ile veri dizini dışına yazma/okuma mümkün olurdu.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(128)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invites_never_carry_private_addresses() {
        // Baska bir agdaki alici icin ulasilamazlar ve ic ag yapisini
        // sizdirirlar. Ayni LAN'da yazismak gercekci bir senaryo degil.
        assert!(is_private_multiaddr("/ip4/192.168.1.103/tcp/42612/p2p/12D3KooW"));
        assert!(is_private_multiaddr("/ip4/10.0.0.5/tcp/42612/p2p/12D3KooW"));
        assert!(is_private_multiaddr("/ip4/172.16.0.9/tcp/42612/p2p/12D3KooW"));
        assert!(is_private_multiaddr("/ip4/127.0.0.1/tcp/42612/p2p/12D3KooW"));
        assert!(is_private_multiaddr("/ip4/169.254.1.1/tcp/42612/p2p/12D3KooW"));
        assert!(is_private_multiaddr("/ip6/fe80::1/tcp/42612/p2p/12D3KooW"));
        assert!(is_private_multiaddr("/ip6/fd00::1/tcp/42612/p2p/12D3KooW"));
        // Gercekci kurulum: onion + genel IP.
        assert!(!is_private_multiaddr("/dns/abc.onion/tcp/42612/p2p/12D3KooW"));
        assert!(!is_private_multiaddr("/ip4/203.0.113.7/tcp/42612/p2p/12D3KooW"));
    }

    #[test]
    fn unsafe_ids_are_rejected_before_touching_the_filesystem() {
        assert!(is_safe_id("bl_abc123"));
        assert!(is_safe_id("550e8400-e29b-41d4-a716-446655440000"));
        // Dizin kacisi.
        assert!(!is_safe_id("../../etc/passwd"));
        assert!(!is_safe_id("a/b"));
        assert!(!is_safe_id("a\\b"));
        assert!(!is_safe_id(".."));
        assert!(!is_safe_id(""));
        assert!(!is_safe_id(&"x".repeat(129)));
    }

    #[test]
    fn sanitize_strips_path_separators() {
        assert_eq!(sanitize_id("../evil"), "evil");
        assert_eq!(sanitize_id("ok_id-1"), "ok_id-1");
    }

    #[test]
    fn ed25519_verification_rejects_malformed_input() {
        assert!(!verify_ed25519(&[0u8; 10], b"msg", &[0u8; 64]));
        assert!(!verify_ed25519(&[0u8; 32], b"msg", &[0u8; 10]));
    }
}
