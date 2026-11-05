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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature as MlDsaSignature,
    Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};
use futures::StreamExt as _;
use libp2p::request_response::{self, ProtocolSupport, ResponseChannel};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, noise, relay, tcp, yamux, PeerId, StreamProtocol, Swarm};
use log::{debug, error, info, warn};
use rand::RngCore;
use sha2::{Digest, Sha256};

use p2p_messenger::attachments::{self, FileChunkRequest, FileChunkResponse};
use p2p_messenger::call::{encode_frame, pump_writes, read_frame, LINK_QUEUE, RELAY_PROTOCOL};
use p2p_messenger::server_proto::{
    self, MailItem, ServerErrorCode, ServerLimits, ServerRequest, ServerResponse, MAX_DEPOSIT_BYTES,
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
/// A `Notify` (or inline `Push`) that drew no `Fetch` is sent again after
/// this long. It used to be sent once: lost on a sleeping phone, all later
/// mail waited for the client's own safety poll, which therefore had to run
/// every 30 s and kept the LTE radio up.
const NOTIFY_RESEND_MS: u64 = 20_000;

/// Bir bağlantının dakikada yapabileceği azami istek. Kotanın aksine bu
/// ANLIK bir sınır: amaç, tek bir eşin sunucunun disk/CPU'sunu tek başına
/// tüketmesini engellemek.
const RATE_WINDOW_MS: u64 = 60_000;
/// File-chunk requests per peer per `RATE_WINDOW_MS` (see `serve_chunk`).
/// Tor carries about one 256 KiB chunk a second; 10/s is far above a real
/// download and caps one peer at ~2.5 MiB/s of disk reads.
const CHUNKS_PER_MINUTE: u32 = 600;
/// Blobs (files on disk) one enrollment may hold; bytes have their own quota.
/// A heavy month of attachments (`blob_ttl_ms`) stays far below it.
const MAX_BLOBS_PER_ENROLLMENT: i64 = 10_000;
/// Least quota a `BlobPut` chunk is charged: its row, even with no new bytes.
const BLOB_CHUNK_MIN_CHARGE: u64 = 64;

/// Call-media relay budget per client: bytes per `RELAY_WINDOW_MS`. ~6.7
/// Mbit/s — several times a 480p video call, so it only stops a flood. Relay
/// frames skip `check_rate`: a call is ~30 frames/s, which alone would eat
/// `requests_per_minute`.
const RELAY_BYTES_PER_WINDOW: usize = 8 * 1024 * 1024;
const RELAY_WINDOW_MS: u64 = 10_000;
/// How long the summed store size is reused, see `total_budget_exceeded`.
/// The total budget is therefore a soft ceiling: it can overshoot by what
/// arrives within one 5 s cache window.
const TOTAL_CACHE_MS: u64 = 5_000;
/// What a sender may relay per window to a listener that sends nothing back:
/// enough for the once-a-second state packets that start a call.
const RELAY_COLD_BYTES_PER_WINDOW: usize = 64 * 1024;

/// Largest item `notify_owner_of` pushes inline (`ServerRequest::Push`).
/// Messages and call signals are ~8-15 KB; big ones keep the Fetch path.
const PUSH_INLINE_MAX: usize = 64 * 1024;

pub fn now_ms() -> i64 {
    // No unwrap: a clock before 1970 must not kill the server loop.
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// Monotonic ms since process start. Rate windows and sweep pacing use this,
/// not the wall clock: a corrected phone clock otherwise freezes them.
fn mono_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// A wall-clock step larger than this is not trusted at once: the TTL sweep
/// waits `CLOCK_JUMP_HOLD_MS` first (a clock set a month ahead deleted all
/// mail and blobs in one sweep).
const CLOCK_JUMP_MS: i64 = 24 * 60 * 60 * 1000;
const CLOCK_JUMP_HOLD_MS: u64 = 60 * 60 * 1000;

/// Inbound connection caps. Every client arrives from 127.0.0.1 through the
/// onion bridge and PeerIds are free, so only a total stops a connection flood.
const MAX_INBOUND_CONNECTIONS: u32 = 512;
const MAX_CONNECTIONS_PER_PEER: u32 = 8;
/// A connected peer without an active enrollment is cut after this long: it
/// otherwise held one of the `MAX_INBOUND_CONNECTIONS` slots for good.
const UNENROLLED_GRACE_MS: u64 = 60_000;
/// `BlobFinish` hashes running at once; each reads a whole blob from disk.
const MAX_HASH_JOBS: usize = 4;
/// Repeated `BlobFinish` requests waiting on one running hash.
const MAX_HASH_WAITERS: usize = 8;
/// Call-relay streams open at once, server-wide. A stream of a peer that is
/// not enrolled ends at once; an enrolled peer holds one.
const MAX_RELAY_STREAMS: usize = 256;
/// Of those, one peer at once (a call holds one; the rest wait out a replace).
const MAX_RELAY_STREAMS_PER_PEER: usize = 4;
/// `Enroll`/`Rebind` hybrid signature checks per `RATE_WINDOW_MS`, server-wide:
/// ML-DSA-87 is the expensive step and PeerIds are free, so only a global pool
/// bounds the CPU. Each peer gets `ENROLL_VERIFIES_PER_PEER` of it.
/// ponytail: many fresh PeerIds still drain the pool for the window (mail is
/// not affected); per-invite budgets if that matters.
const ENROLL_VERIFIES_PER_MINUTE: u32 = 120;
/// One peer's share of `ENROLL_VERIFIES_PER_MINUTE`: a device enrolls or
/// rebinds once, so a few retries cover it.
const ENROLL_VERIFIES_PER_PEER: u32 = 4;
/// `Rebind` checks per `RATE_WINDOW_MS`, server-wide, apart from `Enroll`'s
/// pool: a bad-signature `Enroll` flood (the join code is public) must not
/// lock enrolled devices out of rebinding. `Rebind` needs a live enrollment
/// first, so fresh PeerIds cannot drain this one.
const REBIND_VERIFIES_PER_MINUTE: u32 = 120;
/// `Register` proof checks per `RATE_WINDOW_MS`, server-wide. A pool of its
/// own: a proof flood from enrolled peers cannot starve `Enroll`/`Rebind`.
const REGISTER_VERIFIES_PER_MINUTE: u32 = 256;
/// One enrolled peer's share of `REGISTER_VERIFIES_PER_MINUTE`: one full
/// `Register`, so no single peer holds more than a quarter of the pool.
const REGISTER_VERIFIES_PER_PEER: u32 = server_proto::MAX_REGISTER_PROOFS as u32;
/// 2026-01-01 UTC. A wall clock before this is wrong (phone booted with a
/// 1970/2020 RTC): no TTL sweep runs on it.
const SANE_WALL_FLOOR_MS: i64 = 1_767_225_600_000;

/// `meta` key: the addresses the running server last advertised, one per
/// line. Management commands read it instead of starting a second server.
const ADVERTISED_ADDRS_KEY: &str = "advertised_addrs";

/// The addresses the running server last advertised (peer id included).
pub fn advertised_addrs(store: &Store) -> Result<Vec<String>, String> {
    let raw = store.meta_get(ADVERTISED_ADDRS_KEY).unwrap_or_default();
    let addrs: Vec<String> = String::from_utf8_lossy(&raw).lines().map(str::to_string).collect();
    if addrs.is_empty() {
        return Err("Sunucunun henüz bir adresi yok — önce `typeon-server run` ile başlatın".to_string());
    }
    Ok(addrs)
}

/// Yeni bir davet üretir ve tam davet kodunu döner. `uses <= 0` = SINIRSIZ
/// (bkz. `Store::create_invite`). Needs only the store: see
/// `ADVERTISED_ADDRS_KEY`.
pub fn create_invite(store: &Store, label: &str, uses: i64, ttl_ms: i64) -> Result<String, String> {
    let addrs = advertised_addrs(store)?;
    let mut token = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut token);
    // Jeton HASH'lenmiş saklanır: sunucu diski ele geçse bile henüz
    // kullanılmamış davetler kullanılamaz.
    let now = now_ms();
    let expires = if ttl_ms <= 0 { 0 } else { now.saturating_add(ttl_ms) };
    store.create_invite(Sha256::digest(token).as_slice(), label, uses, expires, now)?;
    Ok(server_proto::format_server_invite(&addrs, &hex::encode(token)))
}

/// Sunucunun KALICI, herkese açık katılım kodu (bkz. `public_join_token`).
/// `rotate`: eski kod ANINDA geçersiz olur; kayıtlı cihazlar etkilenmez.
pub fn join_code(store: &Store, rotate: bool) -> Result<String, String> {
    let addrs = advertised_addrs(store)?;
    Ok(server_proto::format_server_invite(&addrs, &public_join_token(store, rotate)?))
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
    if store.invite_uses_left(hash.as_slice(), now_ms()) != Some(-1) {
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
/// Default `ServerConfig::max_enrollments`.
pub const DEFAULT_MAX_ENROLLMENTS: u32 = 64;
/// An active enrollment not seen for this long is removed by `maybe_sweep`.
const ENROLLMENT_IDLE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

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
    /// Serve Circuit Relay v2 (the server never runs Kademlia). Kapalıysa
    /// sunucu SADECE posta kutusu işi yapar.
    pub node_mode: bool,
    pub server_name: String,
    pub limits: ServerLimits,
    /// Sunucunun kullanabileceği TOPLAM disk bütçesi (bkz. defter #23).
    /// Soft ceiling: it can overshoot by one 5 s cache window (`TOTAL_CACHE_MS`).
    /// `None` = sınırsız; the default is 64 x the per-device quotas. Android
    /// sunucu uygulaması bunu cihazın gerçek boş alanından türetip veriyor.
    pub total_storage_budget_bytes: Option<u64>,
    /// Most active enrollments; a new device is refused above it.
    pub max_enrollments: u32,
}

impl ServerConfig {
    pub fn new(data_dir: PathBuf) -> Self {
        let limits = ServerLimits::default();
        // 64 x (256 MiB mail + 1 GiB archive + 4 GiB blob) = 336 GiB.
        let total = DEFAULT_MAX_ENROLLMENTS as u64
            * (limits.max_mail_bytes + limits.max_archive_bytes + limits.max_blob_bytes);
        ServerConfig {
            blob_dir: data_dir.join("blobs"),
            data_dir,
            node_mode: false,
            server_name: "Typeon Server".to_string(),
            limits,
            total_storage_budget_bytes: Some(total),
            max_enrollments: DEFAULT_MAX_ENROLLMENTS,
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
    limits: libp2p::connection_limits::Behaviour,
    /// Node modu açıkken röle hizmeti. `Toggle::from(None)` KASITLI:
    /// libp2p-relay'in HOP handler'ı `Config`'e bakmadan protokolü her zaman
    /// duyurur, yani sıfır kapasiteli bir `Behaviour` bile identify üzerinden
    /// "röleyim" yalanını yayardı (çekirdekteki aynı notun karşılığı).
    relay: Toggle<relay::Behaviour>,
    /// Call-media relay streams — see `RELAY_PROTOCOL`.
    stream: libp2p_stream::Behaviour,
}

/// Relay stream task -> main loop. The loop owns authentication and routing
/// (`live_interest`); the per-stream tasks only move bytes.
enum RelayEvent {
    Open { peer: PeerId, id: u64, tx: tokio::sync::mpsc::Sender<Vec<u8>> },
    Frame { peer: PeerId, mailbox: String, data: Vec<u8> },
    Closed { peer: PeerId, id: u64 },
}

/// Accepts relay streams and turns each into `RelayEvent`s.
///
/// `events` is bounded and awaited: a peer that floods frames is slowed down
/// by its own stream instead of growing a queue in memory.
async fn accept_relay_streams(mut incoming: libp2p_stream::IncomingStreams, events: tokio::sync::mpsc::Sender<RelayEvent>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let live = std::sync::Arc::new(AtomicUsize::new(0));
    let per_peer = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<PeerId, usize>::new()));
    let mut next_id = 0u64;
    while let Some((peer, stream)) = incoming.next().await {
        // Dropping the stream closes it: no task, no queue for it.
        if live.load(Ordering::Relaxed) >= MAX_RELAY_STREAMS {
            continue;
        }
        {
            let mut m = per_peer.lock().unwrap_or_else(|e| e.into_inner());
            let n = m.entry(peer).or_insert(0);
            if *n >= MAX_RELAY_STREAMS_PER_PEER {
                continue;
            }
            *n += 1;
        }
        live.fetch_add(1, Ordering::Relaxed);
        next_id += 1;
        let id = next_id;
        let events = events.clone();
        let live = live.clone();
        let per_peer = per_peer.clone();
        tokio::spawn(async move {
            relay_stream(peer, id, stream, events).await;
            live.fetch_sub(1, Ordering::Relaxed);
            let mut m = per_peer.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = m.get_mut(&peer) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&peer);
                }
            }
        });
    }
}

/// One relay stream: frames in -> `RelayEvent::Frame`, writer queue out.
async fn relay_stream(peer: PeerId, id: u64, stream: libp2p::Stream, events: tokio::sync::mpsc::Sender<RelayEvent>) {
    let (mut rd, wr) = futures::AsyncReadExt::split(stream);
    let (tx, rx) = tokio::sync::mpsc::channel(LINK_QUEUE);
    if events.send(RelayEvent::Open { peer, id, tx }).await.is_err() {
        return;
    }
    let mut pump = tokio::spawn(pump_writes(wr, rx));
    loop {
        let frame = tokio::select! {
            // The loop dropped `tx` (not enrolled, revoked, replaced):
            // stop reading, or the peer keeps feeding `events`.
            _ = &mut pump => break,
            frame = read_frame(&mut rd) => frame,
        };
        let Ok((mailbox, data)) = frame else { break };
        let Ok(mailbox) = String::from_utf8(mailbox) else { break };
        if events.send(RelayEvent::Frame { peer, mailbox, data }).await.is_err() {
            break;
        }
    }
    let _ = events.send(RelayEvent::Closed { peer, id }).await;
}

// ---------------------------------------------------------------------------
// Çekirdek
// ---------------------------------------------------------------------------

/// PeerId başına anlık durum (bir PeerId'nin bütün bağlantıları paylaşır;
/// challenge son bağlantı kapanınca silinir).
struct ConnState {
    /// Bu PeerId'ye verilmiş, henüz kullanılmamış `Enroll` challenge'ı.
    challenge: Option<Vec<u8>>,
    /// `mono_ms`.
    window_start: u64,
    requests_in_window: u32,
    chunks_in_window: u32,
    /// `mono_ms` of the peer's first open connection, see `UNENROLLED_GRACE_MS`.
    connected_at: u64,
    /// (window start `mono_ms`, checks): this peer's share of the
    /// `Enroll`/`Rebind` and the `Register` verify pools.
    enroll_verifies: (u64, u32),
    register_verifies: (u64, u32),
}

pub struct ServerCore {
    /// Held for the core's lifetime (flock on `server.lock`).
    _dir_lock: std::fs::File,
    config: ServerConfig,
    store: Store,
    swarm: Swarm<ServerBehaviour>,
    tor: p2p_messenger::tor::TorHandle,
    /// Kept after the connection closes (see `maybe_sweep`): a reconnect must
    /// not hand out a fresh rate budget.
    conns: HashMap<PeerId, ConnState>,
    /// Hangi kayıt hangi kutuları dinliyor — `Notify` itmek için. Bellekte:
    /// kalıcı gerçek `mailboxes` tablosunda, bu sadece bağlı eşlerin canlı
    /// görünümü.
    live_interest: HashMap<PeerId, HashSet<String>>,
    /// Peers that owe a `Fetch`, with the `mono_ms` of the last `Notify` sent
    /// (0 = send one on the next tick). One per `NOTIFY_RESEND_MS`, repeated
    /// until the peer fetches: see `resend_notifies`.
    notified: HashMap<PeerId, u64>,
    /// `mono_ms` of the last sweep; `None` = sweep on the first tick.
    last_sweep: Option<u64>,
    /// (wall ms, mono ms) pair the wall clock is checked against, and since
    /// when (mono ms) it has been off: see `clock_jumped`.
    clock_anchor: Option<(i64, u64)>,
    clock_off_since: Option<u64>,
    /// Set by `handle_blob_finish`: the request is answered by
    /// `finish_blob_hash`, not by the value `handle_request` returned.
    hash_job: Option<(String, Vec<u8>)>,
    /// Blobs being hashed off the loop -> everyone waiting for the result.
    blob_hashing: HashMap<String, Vec<ResponseChannel<ServerResponse>>>,
    hash_tx: tokio::sync::mpsc::UnboundedSender<HashDone>,
    hash_rx: Option<tokio::sync::mpsc::UnboundedReceiver<HashDone>>,
    pub stats: ServerStats,
    /// bkz. `ServerShared` — döngü dışından okunacak anlık görüntü.
    shared: Option<std::sync::Arc<ServerShared>>,
    /// bkz. `set_net_changed_rx` / `notify_network_changed` — Android ağ
    /// değişikliği bildirimi. `run_until` bunu `take()` edip select!'te dinler.
    net_changed_rx: Option<tokio::sync::mpsc::UnboundedReceiver<CoreSignal>>,
    /// Taken by `run_until`, which spawns `accept_relay_streams` on it.
    relay_incoming: Option<libp2p_stream::IncomingStreams>,
    /// Authenticated relay links: peer -> (stream id, writer queue).
    relay_links: HashMap<PeerId, (u64, tokio::sync::mpsc::Sender<Vec<u8>>)>,
    /// Peer -> (window start `mono_ms`, bytes relayed in window).
    relay_budget: HashMap<PeerId, (u64, usize)>,
    /// (sender, listener) -> `mono_ms` of the last frame delivered.
    relay_pairs: HashMap<(PeerId, PeerId), u64>,
    /// An Ack or Cancel removed mail: `maybe_sweep` recounts the quotas.
    mail_recount_due: bool,
    /// `Store::data_version` at the last revoke scan (see `maybe_sweep`).
    revoke_scan_version: i64,
    /// (`mono_ms` of the read, bytes) for `total_budget_exceeded`.
    total_cache: std::cell::Cell<(u64, u64)>,
    /// (window start `mono_ms`, checks) for `ENROLL_VERIFIES_PER_MINUTE`.
    verify_window: (u64, u32),
    /// The same for `REGISTER_VERIFIES_PER_MINUTE`.
    register_verify_window: (u64, u32),
    /// The same for `REBIND_VERIFIES_PER_MINUTE`.
    rebind_verify_window: (u64, u32),
}

/// The server-wide signature check pools, see `verify_budget`.
#[derive(Clone, Copy)]
enum VerifyPool {
    Enroll,
    Rebind,
    Register,
}

/// What the embedding app tells the running loop (Android JNI).
pub enum CoreSignal {
    /// Wi-Fi/cellular changed: see `notify_network_changed`.
    NetworkChanged,
    /// A device was revoked or blocked: cut its live links now, not at the
    /// next sweep tick.
    EnrollmentsChanged,
}

/// (blob id, hash the client claimed, hash of the file or `None` if unreadable).
type HashDone = (String, Vec<u8>, Option<Vec<u8>>);

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
    pub relayed: u64,
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
        // The DB holds the libp2p key and the join token: owner only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700));
        }
        std::fs::create_dir_all(&config.blob_dir).map_err(|e| format!("Blob dizini: {e}"))?;
        // Same as `data_dir` (a no-op on FAT/exFAT, which has no modes).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&config.blob_dir, std::fs::Permissions::from_mode(0o700));
        }

        // One process per data dir: a second server on the same DB and Tor state
        // would fight over both. Released when the core is dropped.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(config.data_dir.join("server.lock"))
            .map_err(|e| format!("Kilit dosyası: {e}"))?;
        if lock.try_lock().is_err() {
            return Err(format!(
                "Bu veri dizini ({}) başka bir sunucu işlemi tarafından kullanılıyor",
                config.data_dir.display()
            ));
        }
        let store = Store::open(&config.data_dir.join("typeon_server.db"))?;
        // Rows dated by a wrong clock before a restart (see `clock_jumped`
        // for the same within one run).
        if now_ms() >= SANE_WALL_FLOOR_MS {
            store.restamp_before(SANE_WALL_FLOOR_MS, now_ms());
        }
        let keypair = load_or_generate_keypair(&store)?;

        // Tor: sunucunun kendi onion service'i, ulaşılabilir olmasının TEK
        // yolu (dinleyici yalnızca loopback'te). Açılamazsa hata: Tor'suz bir
        // sunucuya hiçbir istemci ulaşamaz ama "çalışıyor" görünürdü.
        let tor = p2p_messenger::tor::TorHandle::launch(
            &config.data_dir.join("arti_state").to_string_lossy(),
            &config.data_dir.join("arti_cache").to_string_lossy(),
            TOR_LIBP2P_PORT,
        )
        .map_err(|e| format!("Tor başlatılamadı: {e}"))?;
        let node_mode = config.node_mode;

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            // Onion-only (deanon fix, istemciyle AYNI çıpa): TCP taşıması
            // yalnızca gelen onion-köprüsü bağlantıları için tutulur; giden
            // her TCP (clearnet) dial'ı `DialReject` ile reddedilir. Sunucu
            // zaten dışarı dial etmez (store-and-forward yalnızca istemcilerin
            // ona bağlanmasıyla çalışır, tor transport'u da yok) — bu, kad/
            // autonat/relay gibi bir davranışın kazara bir eşin gerçek IP'sine
            // clearnet dial etmesini de kesin olarak engeller.
            .with_other_transport(|keypair| {
                use libp2p::core::muxing::StreamMuxerBox;
                use libp2p::core::transport::Transport as _;
                use libp2p::core::upgrade::Version;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    p2p_messenger::tor::DialReject(
                        tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)),
                    )
                    .upgrade(Version::V1Lazy)
                    .authenticate(noise::Config::new(keypair)?)
                    .multiplex(tuned_yamux())
                    .map(|(p, m), _| (p, StreamMuxerBox::new(m))),
                )
            })
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
                )
                // Default 5 min per client wakes every idle phone's LTE radio.
                .with_interval(Duration::from_secs(3600)));
                let limits = libp2p::connection_limits::Behaviour::new(
                    libp2p::connection_limits::ConnectionLimits::default()
                        .with_max_pending_incoming(Some(MAX_INBOUND_CONNECTIONS))
                        .with_max_established_incoming(Some(MAX_INBOUND_CONNECTIONS))
                        .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER)),
                );
                let relay: Toggle<relay::Behaviour> = if node_mode {
                    // Same limits as a client in node mode.
                    Some(relay::Behaviour::new(peer_id, p2p_messenger::relay_server_config())).into()
                } else {
                    None.into()
                };
                ServerBehaviour { server_rpc, file_chunks, identify, limits, relay, stream: libp2p_stream::Behaviour::new() }
            })
            .map_err(|e| e.to_string())?
            // Çekirdekteki 600 sn ile aynı gerekçe: sessiz dönemlerde
            // bağlantıyı canlı tut, Tor devrelerini boşuna yeniden kurma.
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(600)))
            .build();

        // Onion-only (deanon fix, istemciyle AYNI, bkz. p2p_messenger::tor
        // `DialReject`): `0.0.0.0` DEĞİL `127.0.0.1` — dinleyici yalnızca
        // loopback'te. Sunucunun onion service köprüsü gelen Tor akışlarını
        // zaten `127.0.0.1:TOR_LIBP2P_PORT`'a bağlar, yani gelen onion trafiği
        // etkilenmez; buna karşılık LAN/internetten doğrudan clearnet bağlantı
        // KABUL EDİLMEZ (sunucunun gerçek IP'si ifşa olmaz).
        swarm
            .listen_on(format!("/ip4/127.0.0.1/tcp/{}", TOR_LIBP2P_PORT).parse().map_err(|_| "bad multiaddr")?)
            .map_err(|e| e.to_string())?;

        let relay_incoming = swarm.behaviour().stream.new_control().accept(RELAY_PROTOCOL).ok();

        let (hash_tx, hash_rx) = tokio::sync::mpsc::unbounded_channel();
        Ok(ServerCore {
            _dir_lock: lock,
            config,
            store,
            swarm,
            tor,
            conns: HashMap::new(),
            live_interest: HashMap::new(),
            notified: HashMap::new(),
            last_sweep: None,
            clock_anchor: None,
            clock_off_since: None,
            hash_job: None,
            blob_hashing: HashMap::new(),
            hash_tx,
            hash_rx: Some(hash_rx),
            stats: ServerStats::default(),
            shared: None,
            net_changed_rx: None,
            relay_incoming,
            relay_links: HashMap::new(),
            relay_budget: HashMap::new(),
            relay_pairs: HashMap::new(),
            mail_recount_due: false,
            revoke_scan_version: -1,
            total_cache: std::cell::Cell::new((0, 0)),
            verify_window: (0, 0),
            register_verify_window: (0, 0),
            rebind_verify_window: (0, 0),
        })
    }

    /// bkz. `notify_network_changed` — Android arayüzü `startServer`'da
    /// bir kanal kurup uçlarından birini burada, diğerini `Control`'de
    /// tutar; `ConnectivityManager` geri çağrısı ağ değiştiğinde iter.
    pub fn set_net_changed_rx(&mut self, rx: tokio::sync::mpsc::UnboundedReceiver<CoreSignal>) {
        self.net_changed_rx = Some(rx);
    }

    /// Ağ arayüzü değiştiğinde (Wi-Fi kopup gelme, hücresele geçiş)
    /// `run_until` döngüsünden çağrılır. Sunucu pasiftir (peer'lara dial
    /// etmez), o yüzden yapılacak tek şey Tor'u dürtmek: devreler/onion
    /// descriptor bir Wi-Fi kesintisinden sonra periyodik iyileşmeyi
    /// (dakikalar) beklemesin (bkz. `tor::TorHandle::notify_network_changed`).
    /// libp2p dinleyicisi loopback'te, süreç boyunca bağlı kalır — yeniden
    /// `listen_on` gereksiz.
    pub fn notify_network_changed(&self) {
        self.tor.notify_network_changed();
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
        // For `create_invite` / `join_code`, which see only the store.
        let addrs = self.invite_addrs().join("\n");
        if self.store.meta_get(ADVERTISED_ADDRS_KEY).as_deref() != Some(addrs.as_bytes()) {
            let _ = self.store.meta_set(ADVERTISED_ADDRS_KEY, addrs.as_bytes());
        }
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

    pub fn tor_status(&self) -> String {
        self.tor.status().as_str().to_string()
    }

    /// İlan edilen adres: yalnızca onion (dinleyici loopback'te, bkz. `new`).
    pub fn advertised_addrs(&self) -> Vec<String> {
        self.tor
            .onion_host()
            .map(|host| format!("/dns/{}/tcp/{}/p2p/{}", host, TOR_LIBP2P_PORT, self.local_peer_id()))
            .into_iter()
            .collect()
    }

    /// Davet koduna GİRECEK adresler — özel ağ adresleri elenir: başka bir
    /// ağdaki alıcı için ulaşılamazlar ve sunucunun iç ağ yapısını sızdırırlar.
    pub fn invite_addrs(&self) -> Vec<String> {
        self.advertised_addrs()
            .into_iter()
            .filter(|a| server_proto::is_onion_server_addr(a))
            .collect()
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
        info!("Typeon sunucusu başladı");
        debug!("peer_id={}", self.local_peer_id());
        // Zamanlayıcı ve sinyal AYRI yerel değişkenler olmak ZORUNDA:
        // `tokio::select!` bütün dalların future'larını AYNI kapsamda
        // oluşturur, swarm dalı da `self`i ödünç alıyor — bunlar satır içi
        // yazılsaydı ikinci bir `&mut self` ödüncü doğar ve derlenmezdi.
        let mut sweep = tokio::time::interval(Duration::from_secs(5));
        let ctrlc = tokio::signal::ctrl_c();
        // bkz. modül notu / yukarıdaki yorum — `self`i ödünç alan bir arm
        // future'ı satır içinde yazılamaz; alıcıyı bir yerel değişkene alıyoruz.
        let mut net_changed_rx = self.net_changed_rx.take();
        let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel(LINK_QUEUE);
        let Some(mut hash_rx) = self.hash_rx.take() else {
            return Err("run_until çağrıldı: döngü zaten çalıştırılmış".to_string());
        };
        if let Some(incoming) = self.relay_incoming.take() {
            tokio::spawn(accept_relay_streams(incoming, relay_tx));
        }
        futures::pin_mut!(ctrlc);
        futures::pin_mut!(shutdown);
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.handle_swarm_event(event),
                _ = sweep.tick() => self.maybe_sweep(),
                Some(ev) = relay_rx.recv() => self.handle_relay(ev),
                Some(done) = hash_rx.recv() => self.finish_blob_hash(done),
                // bkz. `notify_network_changed` — kanal yoksa/kapandıysa bu
                // dal sonsuza kadar bekler (asla tetiklenmez).
                Some(signal) = async {
                    match &mut net_changed_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<CoreSignal>>().await,
                    }
                } => match signal {
                    CoreSignal::NetworkChanged => {
                        info!("Ağ değişikliği bildirildi — Tor tazeleniyor");
                        self.notify_network_changed();
                    }
                    CoreSignal::EnrollmentsChanged => self.drop_revoked_peers(),
                },
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

    fn handle_swarm_event(&mut self, event: SwarmEvent<ServerBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Dinleniyor: {}/p2p/{}", address, self.local_peer_id());
                // Davet kodu ancak bir adres bilindikten sonra üretilebilir,
                // bu yüzden anlık görüntüyü beklemeden tazele.
                self.publish_shared();
            }
            SwarmEvent::ConnectionEstablished { peer_id, num_established, .. } => {
                let now = mono_ms();
                let conn = self.conns.entry(peer_id).or_insert(ConnState {
                    challenge: None,
                    window_start: now,
                    requests_in_window: 0,
                    chunks_in_window: 0,
                    connected_at: now,
                    enroll_verifies: (0, 0),
                    register_verifies: (0, 0),
                });
                if num_established.get() == 1 {
                    conn.connected_at = now;
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                if num_established == 0 {
                    // The rate window and relay budget outlive the
                    // connection; `maybe_sweep` drops them once expired.
                    if let Some(c) = self.conns.get_mut(&peer_id) {
                        c.challenge = None;
                    }
                    self.live_interest.remove(&peer_id);
                    self.notified.remove(&peer_id);
                }
            }
            SwarmEvent::Behaviour(ServerBehaviourEvent::ServerRpc(
                request_response::Event::Message { peer, message },
            )) => {
                if let request_response::Message::Request { request, channel, .. } = message {
                    let response = self.handle_request(peer, request);
                    match self.hash_job.take() {
                        Some((blob_id, enc_sha256)) => self.start_blob_hash(blob_id, enc_sha256, channel),
                        None => {
                            let _ = self.swarm.behaviour_mut().server_rpc.send_response(channel, response);
                        }
                    }
                }
            }
            // A `Push` or `Notify` that did not arrive: the reader still owes
            // a `Fetch`. Due at once (0), `resend_notifies` sends it.
            SwarmEvent::Behaviour(ServerBehaviourEvent::ServerRpc(
                request_response::Event::OutboundFailure { peer, .. },
            )) => {
                if self.live_interest.contains_key(&peer) {
                    self.notified.entry(peer).or_insert(0);
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
        if !self.check_rate(peer, false, request_cost(&req)) {
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
        // İptal anahtarı da engeller (bkz. `Store::revoke_enrollment`): istemci
        // `Enroll`'a gider ve operatör engeli kaldırana kadar `Revoked` alır.
        let enrollment_id = self
            .store
            .enrollment_by_peer(&peer.to_string())
            .filter(|e| e.state == EnrollmentState::Active)
            .map(|e| e.enrollment_id);
        let enrolled = enrollment_id.is_some();
        if let Some(c) = self.conns.get_mut(&peer) {
            c.challenge = Some(challenge.clone());
        }
        ServerResponse::Welcome {
            version: SERVER_PROTOCOL_VERSION,
            challenge,
            enrolled,
            enrollment_id,
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
        if (now as u64).abs_diff(ts_ms) > server_proto::ENROLL_MAX_SKEW_MS {
            return ServerResponse::Err(ServerErrorCode::Stale);
        }
        // Cheap gate before the hybrid verify (ML-DSA-87 is the expensive
        // step, and PeerIds are free): no usable invite, no signature check.
        let hash = Sha256::digest(&invite_token);
        if matches!(self.store.invite_uses_left(hash.as_slice(), now), None | Some(0)) {
            return ServerResponse::Err(ServerErrorCode::BadInvite);
        }
        // Challenge tek kullanımlık (`take`): aksi halde bir gözlemci imzayı
        // yakalayıp tekrar oynatabilirdi. Rastgele ve bağlantıya özel, yani
        // bellekten silmek yeter.
        let Some(challenge) = self.conns.get_mut(&peer).and_then(|c| c.challenge.take()) else {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        };
        // İstemcinin imzaladığı challenge, BİZİM verdiğimiz olmalı.
        if !ct_eq(&client_challenge, &challenge) {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        if !self.verify_budget(peer, VerifyPool::Enroll, 1) {
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }

        let signing_input = server_proto::enroll_signing_input(
            version,
            &self.local_peer_id().to_string(),
            &peer.to_string(),
            &invite_token,
            &enroll_pk,
            &enroll_pk_pq,
            &challenge,
            ts_ms,
        );
        // HİBRİT: ikisi de geçmeli. Tek başına klasik bir imza,
        // hasat-şimdi-kır-sonra bir saldırgana ileride sahte kayıt üretme
        // imkânı verirdi.
        if !verify_hybrid(&enroll_pk, &enroll_pk_pq, &signing_input, &sig, &sig_pq) {
            // A failed attempt costs a counted invite one use: a leaked code
            // otherwise stayed a free verify oracle. The unlimited join code
            // has no uses to spend (`verify_budget` bounds it).
            let _ = self.store.consume_invite(hash.as_slice(), now);
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        // Sahip kararı: iptal = engel. İkisi de kayıt ANAHTARINI engeller,
        // yani aynı cihaz yeni bir davetle bile kaydolamaz; yalnızca yeni bir
        // PeerId + yeni anahtar (yeniden kurulum) geçer — kesin bir yasak
        // değil, operatör kontrolü. Kontrol imza doğrulandıktan SONRA: anahtarın gerçekten
        // bu cihaza ait olduğu kanıtlanmadan engel uygulamak, başkasının
        // anahtarını yazarak onu engelletmeye yol açardı.
        // The key this PeerId enrolled with before counts too: the device
        // makes its enroll key itself, a fresh one alone must not lift a block.
        let prev = self.store.enrollment_by_peer(&peer.to_string());
        if self.store.is_key_blocked(&enroll_pk)
            || prev.as_ref().map_or(false, |p| self.store.is_key_blocked(&p.enroll_pk))
        {
            warn!("Engellenen anahtarla kayıt denemesi reddedildi");
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }

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
        if self.store.invite_uses_left(hash.as_slice(), now) == Some(-1) {
            let since = now - 60 * 60 * 1000;
            if self.store.count_enrollments_since(since, now) >= MAX_PUBLIC_ENROLLMENTS_PER_HOUR {
                warn!("Herkese açık katılım kodu saatlik tavanı aştı, kayıt reddedildi");
                self.stats.rejected += 1;
                return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
            }
        }
        // A PeerId that enrolls again takes no new place.
        if !prev.as_ref().map_or(false, |p| p.state == EnrollmentState::Active)
            && self.store.count_active_enrollments(now - ENROLLMENT_IDLE_MS) >= self.config.max_enrollments as i64
        {
            warn!("Enrollment refused: the server holds its maximum number of devices");
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Aynı PeerId yeniden kayıt olursa (`peer_id` UNIQUE, insert
        // `OR REPLACE`) eski kimliği ve kota sayaçlarını devral: yeni bir
        // `enrollment_id` + sıfır sayaç, mevcut mail/arşiv/blob satırlarını
        // sahipsiz bırakıp kotayı sıfırlamanın yolu olurdu.
        let enrollment_id = match &prev {
            Some(p) => p.enrollment_id.clone(),
            None => {
                let mut id = vec![0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut id);
                id
            }
        };
        let e = Enrollment {
            enrollment_id: enrollment_id.clone(),
            enroll_pk,
            enroll_pk_pq,
            peer_id: peer.to_string(),
            state: EnrollmentState::Active,
            enrolled_at: prev.as_ref().map_or(now, |p| p.enrolled_at),
            last_seen_at: now,
            bytes_mail: prev.as_ref().map_or(0, |p| p.bytes_mail),
            bytes_archive: prev.as_ref().map_or(0, |p| p.bytes_archive),
            bytes_blob: prev.as_ref().map_or(0, |p| p.bytes_blob),
        };
        // One transaction: a failed insert must not cost the invite its use.
        match self.store.enroll_with_invite(hash.as_slice(), now, &e) {
            Ok(true) => {}
            Ok(false) => return ServerResponse::Err(ServerErrorCode::BadInvite),
            Err(msg) => {
                error!("Kayıt yazılamadı: {msg}");
                return ServerResponse::Err(ServerErrorCode::Internal);
            }
        }
        self.stats.enrollments += 1;
        debug!("Yeni kayıt: {}", hex::encode(&enrollment_id));
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
        if (now as u64).abs_diff(ts_ms) > server_proto::ENROLL_MAX_SKEW_MS {
            return ServerResponse::Err(ServerErrorCode::Stale);
        }
        // Same single-use challenge as `Enroll`: without it (and the caller's
        // PeerId) in the signed bytes, a captured Rebind moved the enrollment
        // to whoever replayed it within the skew window.
        let Some(challenge) = self.conns.get_mut(&peer).and_then(|c| c.challenge.take()) else {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        };
        let Some(existing) = self.store.enrollment_by_id(&enrollment_id) else {
            return ServerResponse::Err(ServerErrorCode::NotEnrolled);
        };
        if !self.verify_budget(peer, VerifyPool::Rebind, 1) {
            self.stats.rejected += 1;
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        let input = server_proto::rebind_signing_input(
            &enrollment_id,
            &self.local_peer_id().to_string(),
            &peer.to_string(),
            &challenge,
            ts_ms,
        );
        if !verify_hybrid(&existing.enroll_pk, &existing.enroll_pk_pq, &input, &sig, &sig_pq) {
            return ServerResponse::Err(ServerErrorCode::BadSignature);
        }
        // After the signature: only the key holder learns the id is revoked.
        if existing.state == EnrollmentState::Revoked {
            return ServerResponse::Err(ServerErrorCode::Revoked);
        }
        // Engelli anahtar yeniden bağlanamaz da (bkz. `handle_enroll`).
        if self.store.is_key_blocked(&existing.enroll_pk) {
            return ServerResponse::Err(ServerErrorCode::Revoked);
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

    /// `authenticate`, but only an enrollment the operator has not revoked.
    /// Read from the DB each time: revoke and block arrive through another
    /// connection (JNI, CLI) while the peer stays connected.
    fn active(&self, peer: PeerId) -> Option<Enrollment> {
        self.authenticate(peer).filter(|e| e.state == EnrollmentState::Active)
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
        // The sum reads every mail, archive and blob row: at most once per
        // `TOTAL_CACHE_MS`, with what was let in since added on top (a
        // refused write is counted too, which only errs on the full side).
        let mono = mono_ms();
        let (mut at, mut total) = self.total_cache.get();
        if at == 0 || mono.saturating_sub(at) > TOTAL_CACHE_MS {
            total = self.store.total_stored_bytes().max(0) as u64;
            at = mono.max(1);
        }
        let after = total.saturating_add(incoming as u64);
        let exceeded = after > total_budget;
        // Only what is let in counts: refused writes inflated the cache and
        // bounced everyone else near the ceiling.
        self.total_cache.set((at, if exceeded { total } else { after }));
        exceeded
    }

    fn handle_authenticated(&mut self, peer: PeerId, e: &Enrollment, req: ServerRequest) -> ServerResponse {
        let now = now_ms();
        // `last_seen_at` is for the operator, not a write per request.
        if now - e.last_seen_at > 60_000 {
            self.store.touch_enrollment(&e.enrollment_id, now);
        }
        let limits = self.config.limits.clone();

        // Every list costs a query per element inside the event loop.
        let boxes = limits.max_mailboxes as usize;
        let too_long = match &req {
            ServerRequest::Register { add, drop, proofs } => {
                add.len().max(drop.len()) > boxes || proofs.len() > server_proto::MAX_REGISTER_PROOFS
            }
            ServerRequest::Fetch { cursors, .. } => cursors.len() > boxes,
            ServerRequest::Ack { acks } => acks.len() > boxes,
            ServerRequest::ArchiveProbe { buckets } | ServerRequest::ArchivePurge { buckets } => buckets.len() > boxes,
            ServerRequest::Cancel { seqs, .. } => seqs.len() > boxes,
            ServerRequest::ArchivePut { records, .. } => records.len() > server_proto::MAX_ARCHIVE_PUT_RECORDS,
            _ => false,
        };
        if too_long {
            return ServerResponse::Err(ServerErrorCode::TooLarge);
        }
        // Every mailbox/bucket id the server stores or looks up: client ids
        // always pass, so a failing one is a hostile request.
        let bad_id = match &req {
            ServerRequest::Register { add, drop, .. } => add.iter().chain(drop.iter()).any(|id| !is_safe_id(id)),
            ServerRequest::Fetch { cursors: list, .. } | ServerRequest::Ack { acks: list } => {
                list.iter().any(|(id, _)| !is_safe_id(id))
            }
            ServerRequest::ArchiveProbe { buckets } | ServerRequest::ArchivePurge { buckets } => {
                buckets.iter().any(|id| !is_safe_id(id))
            }
            ServerRequest::Deposit { mailbox: id, .. }
            | ServerRequest::Cancel { mailbox: id, .. }
            | ServerRequest::ArchivePut { bucket: id, .. }
            | ServerRequest::ArchiveFetch { bucket: id, .. } => !is_safe_id(id),
            _ => false,
        };
        if bad_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }

        match req {
            ServerRequest::Register { add, drop, proofs } => {
                // Only a proof for an id of `add` is verified, and only one
                // with a valid signature reaches the store.
                // Each proof is a hybrid verify: a server-wide budget, or 64
                // enrollments x 64 proofs pin the CPU.
                let checks = proofs.iter().filter(|p| add.contains(&p.mailbox)).count() as u32;
                if checks > 0 && !self.verify_budget(peer, VerifyPool::Register, checks) {
                    return ServerResponse::Err(ServerErrorCode::RateLimited);
                }
                let me = self.swarm.local_peer_id().to_string();
                let proved: Vec<(String, Vec<u8>)> = proofs
                    .iter()
                    .filter(|p| add.contains(&p.mailbox))
                    .filter(|p| {
                        let input = server_proto::register_signing_input(&p.mailbox, &e.enrollment_id, &me);
                        verify_hybrid(&p.pk, &p.pk_pq, &input, &p.sig, &p.sig_pq)
                    })
                    .map(|p| (p.mailbox.clone(), server_proto::mailbox_key_hash(&p.pk, &p.pk_pq).to_vec()))
                    .collect();
                // A proof that did not verify is a refusal, not `proof_needed`:
                // the client would send the same bytes again.
                let bad_proof = proofs.iter().filter(|p| add.contains(&p.mailbox)).count().saturating_sub(proved.len());
                let registered = self.store.register_mailboxes_proved(&e.enrollment_id, &add, &drop, &proved, now, limits.max_mailboxes);
                let (refused, unproven) = match registered {
                    Ok((refused, unproven)) => {
                        let (bad, unproven): (Vec<String>, Vec<String>) =
                            unproven.into_iter().partition(|id| proofs.iter().any(|p| &p.mailbox == id));
                        (refused.into_iter().chain(bad).collect::<Vec<String>>(), unproven)
                    }
                    Err(msg) => {
                        error!("Register yazılamadı: {msg}");
                        return ServerResponse::Err(ServerErrorCode::Internal);
                    }
                };
                let interest = self.live_interest.entry(peer).or_default();
                for id in add {
                    if !refused.contains(&id) && !unproven.contains(&id) {
                        interest.insert(id);
                    }
                }
                for id in &drop {
                    interest.remove(id);
                }
                // Every id not named is registered; each named one says why
                // (see `ServerResponse::Registered`).
                if unproven.is_empty() && refused.is_empty() {
                    return ServerResponse::Ok;
                }
                if !refused.is_empty() {
                    warn!("Register: {} kutu reddedildi (kota, okuyucu sınırı ya da anahtar), {} kanıt doğrulanmadı", refused.len(), bad_proof);
                }
                ServerResponse::Registered { proof_needed: unproven, refused }
            }

            ServerRequest::Deposit { mailbox, sealed } => {
                if sealed.len() > limits.max_item_bytes as usize || sealed.len() > MAX_DEPOSIT_BYTES {
                    return ServerResponse::Err(ServerErrorCode::TooLarge);
                }
                // Kayıtlı olmayan bir kutuya bırakmak, istemciye "bu alıcı
                // benim sunucumda değil" demek — o da trafiği doğrudan
                // gossipsub'a yollar ve her mesajda boşuna gidiş-dönüş
                // ödemez.
                if !self.store.mailbox_has_other_reader(&mailbox, &e.enrollment_id) {
                    return ServerResponse::Err(ServerErrorCode::UnknownMailbox);
                }
                // Only this request's own counter: a full blob quota must not
                // stop the device from messaging.
                if e.bytes_mail as u64 > limits.max_mail_bytes {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // bkz. `total_budget_exceeded` — kayıt başına kota TEK
                // başına cihazın diskini korumuyor.
                if self.total_budget_exceeded(sealed.len()) {
                    warn!("Toplam disk bütçesi doldu, teslim reddedildi");
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // Per depositor (see `depositor_item_count`): a box full of
                // someone else's deposits must not refuse ours.
                if self.store.depositor_item_count(&mailbox, &e.enrollment_id) >= limits.max_items_per_mailbox as i64 {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                match self.store.deposit(&mailbox, &sealed, &e.enrollment_id, now, limits.mailbox_ttl_ms as i64) {
                    Ok(seq) => {
                        self.stats.deposits += 1;
                        let item = MailItem { mailbox_id: mailbox.clone(), seq, deposited_at_ms: now as u64, sealed };
                        self.notify_owner_of(&mailbox, peer, item);
                        ServerResponse::Deposited { seq }
                    }
                    Err(msg) => {
                        error!("Deposit yazılamadı: {msg}");
                        ServerResponse::Err(ServerErrorCode::Internal)
                    }
                }
            }

            ServerRequest::Fetch { cursors, max_items, max_bytes } => {
                self.notified.remove(&peer);
                let (items, more) = self.store.fetch(
                    &e.enrollment_id,
                    &cursors,
                    // 0 answered an empty batch with `more` forever.
                    max_items.clamp(1, MAX_FETCH_BATCH_ITEMS),
                    max_bytes.clamp(1, MAX_FETCH_BATCH_BYTES),
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
                    self.mail_recount_due = true;
                }
                ServerResponse::Ok
            }

            // bkz. `ServerRequest::Cancel` — gönderen kendi teslim
            // edilmemiş paketini geri çeker. Sahiplik kontrolü sorgunun
            // içinde: `depositor = requester`.
            ServerRequest::Cancel { mailbox, seqs } => {
                let removed = self.store.cancel_own_deposits(&mailbox, &seqs, &e.enrollment_id);
                if removed > 0 {
                    self.mail_recount_due = true;
                    info!("Gönderen {} paketi geri çekti", removed);
                }
                ServerResponse::Ok
            }

            ServerRequest::ArchivePut { bucket, records } => {
                if records.iter().any(|r| r.sealed.len() > MAX_DEPOSIT_BYTES) {
                    return ServerResponse::Err(ServerErrorCode::TooLarge);
                }
                if e.bytes_archive as u64 > limits.max_archive_bytes {
                    return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
                }
                // bkz. `total_budget_exceeded` — arşiv, postanın aksine
                // TTL'siz: bir kez yazıldı mı `ArchivePurge` gelene kadar
                // durur, yani toplam tavana en çok yaklaştıran taraf.
                let incoming: usize = records.iter().map(store::archive_row_bytes).sum();
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

            ServerRequest::ArchiveFetch { bucket, before_ms, before_id, max_items, max_bytes } => {
                let (records, more) = self.store.archive_fetch(
                    &bucket,
                    before_ms.map(|ms| (ms, before_id.as_deref().unwrap_or(""))),
                    max_items.clamp(1, MAX_FETCH_BATCH_ITEMS),
                    max_bytes.clamp(1, MAX_FETCH_BATCH_BYTES),
                );
                ServerResponse::ArchiveBatch { records, more }
            }

            ServerRequest::ArchivePurge { buckets } => {
                self.store.archive_purge(&buckets);
                ServerResponse::Ok
            }

            // The id is the hash of the uploader's secret (see
            // `server_proto::blob_id_for_upload_secret`): a FileOffer recipient
            // knows the id only, so it cannot claim the blob first.
            ServerRequest::BlobPut { upload_secret, chunk_index, total_chunks, chunk_size, data } => {
                let Some(blob_id) = server_proto::blob_id_for_upload_secret(&upload_secret) else {
                    return ServerResponse::Err(ServerErrorCode::BadDirection);
                };
                self.handle_blob_put(e, &limits, blob_id, chunk_index, total_chunks, chunk_size, data, now)
            }

            ServerRequest::BlobFinish { upload_secret, total_chunks, enc_sha256 } => {
                let Some(blob_id) = server_proto::blob_id_for_upload_secret(&upload_secret) else {
                    return ServerResponse::Err(ServerErrorCode::BadDirection);
                };
                self.handle_blob_finish(e, blob_id, total_chunks, enc_sha256)
            }

            ServerRequest::BlobDelete { upload_secret } => {
                if let Some(blob_id) = server_proto::blob_id_for_upload_secret(&upload_secret) {
                    if self.store.blob_state(&blob_id).map_or(false, |s| s.owner == e.enrollment_id) {
                        self.drop_blob(&blob_id);
                    }
                }
                ServerResponse::Ok
            }

            // İstemciden sunucuya gelemeyecek türler.
            ServerRequest::Hello { .. }
            | ServerRequest::Enroll { .. }
            | ServerRequest::Rebind { .. }
            | ServerRequest::Notify
            | ServerRequest::Push { .. } => ServerResponse::Err(ServerErrorCode::BadDirection),
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
        if data.len() > server_proto::MAX_BLOB_CHUNK_BYTES
            || chunk_size as u64 + 16 > server_proto::MAX_BLOB_CHUNK_BYTES as u64
        {
            return ServerResponse::Err(ServerErrorCode::TooLarge);
        }
        // Before any row exists: `total_chunks: 0` minted a free row per request.
        if chunk_index >= total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // Ofset istemcinin `chunk_index`/`chunk_size`'ından geliyor: sınırsız
        // bırakılırsa 1 baytlık bir parça dosyayı terabaytlarca ileriye
        // yazar (kotaya 1 bayt sayılır, seyrek dosya desteklemeyen FS'te
        // disk dolar). Dosyanın sonu cihaz blob kotasını aşamaz.
        let stride = if chunk_size == 0 { attachments::FILE_CHUNK_SIZE as u64 } else { chunk_size as u64 };
        let offset = chunk_index as u64 * (stride + 16);
        if offset + data.len() as u64 > limits.max_blob_bytes {
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Charged: how far this write extends the file, not `data.len()`. A
        // 1-byte chunk at a far offset allocates the whole gap on a volume
        // without sparse files (SD card) and cost 1 byte of quota.
        let path = self.blob_path(&blob_id);
        let file_len = std::fs::metadata(&path).map_or(0, |m| m.len());
        // At least a row's worth: a 0-byte chunk still costs a DB row (and,
        // for a new blob, a file).
        let growth = (offset + data.len() as u64).saturating_sub(file_len).max(BLOB_CHUNK_MIN_CHARGE);
        if e.bytes_blob.max(0) as u64 + growth > limits.max_blob_bytes {
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Defter #23: kotalar SADECE kayıt başına uygulanıyordu. Bütçe sabit
        // `EXPECTED_DEVICES = 8`'e bölündüğü için 20 cihaz kaydolduğunda
        // gerçek tavan bütçenin 2,5 katı oluyordu — bu mekanizmanın var olma
        // sebebi zaten tabletin dolan diskiydi. Artık toplam da kontrol
        // ediliyor.
        if self.total_budget_exceeded(growth as usize) {
            warn!("Toplam disk bütçesi doldu, blob parçası reddedildi");
            return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
        }
        // Sahiplik: bir blob'a SADECE onu başlatan kayıt yazabilir. A row is
        // made only for an id nobody holds; the second read also covers a
        // first one that failed (busy DB), which used to skip this check.
        if self.store.blob_state(&blob_id).is_none() {
            // Bytes are capped above; this caps files (inodes) and rows.
            if self.store.blob_count(&e.enrollment_id) >= MAX_BLOBS_PER_ENROLLMENT {
                return ServerResponse::Err(ServerErrorCode::QuotaExceeded);
            }
            if let Err(msg) = self.store.blob_begin(&blob_id, &e.enrollment_id, total_chunks, now) {
                error!("blob_begin: {msg}");
                return ServerResponse::Err(ServerErrorCode::Internal);
            }
        }
        let Some(state) = self.store.blob_state(&blob_id) else {
            return ServerResponse::Err(ServerErrorCode::Internal);
        };
        if state.owner != e.enrollment_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // A verified blob is final: another chunk (or a new stride)
        // would make `serve_chunk` hand out bytes the hash never covered.
        if state.complete {
            return ServerResponse::Ok;
        }
        if chunk_index >= state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // The stride is fixed by the first chunk (`blob_set_chunk_size`):
        // another one would write where `serve_chunk` does not read.
        if (state.chunk_size != 0 || state.received_chunks > 0) && state.chunk_size != chunk_size {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // Same reason while `BlobFinish` is hashing the file.
        if self.blob_hashing.contains_key(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::RateLimited);
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
        // Adım blob'la birlikte SAKLANIR (defter #06) — `serve_chunk` aynı
        // değerle okumak zorunda.
        self.store.blob_set_chunk_size(&blob_id, chunk_size);
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
        // The bytes are on disk: charged even if the bookkeeping below fails
        // (the resent chunk then grows nothing and pays only the minimum).
        // Such a failure over-charges the owner by `growth` until the next
        // sweep's `recount_blob_bytes`.
        self.store.add_blob_bytes(&e.enrollment_id, growth as i64);
        // An upload in progress is not garbage (see `Store::blobs_to_gc`).
        self.store.blob_touch(&blob_id, now);
        if let Err(msg) = self.store.blob_record_chunk(&blob_id, chunk_index, growth as usize) {
            error!("blob_record_chunk: {msg}");
            return ServerResponse::Err(ServerErrorCode::Internal);
        }
        ServerResponse::Ok
    }

    fn handle_blob_finish(
        &mut self,
        e: &Enrollment,
        blob_id: String,
        total_chunks: u32,
        enc_sha256: Vec<u8>,
    ) -> ServerResponse {
        if !is_safe_id(&blob_id) {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        // Row gone (swept after a long offline spell): the client starts over.
        let Some(state) = self.store.blob_state(&blob_id) else {
            return ServerResponse::Err(ServerErrorCode::BlobIncomplete);
        };
        if state.owner != e.enrollment_id {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if state.complete {
            return ServerResponse::Ok;
        }
        // The stored count is the upload's; the client's own number only has
        // to agree with it.
        if total_chunks != state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BadDirection);
        }
        if state.received_chunks < state.total_chunks {
            return ServerResponse::Err(ServerErrorCode::BlobIncomplete);
        }
        if !self.blob_hashing.contains_key(&blob_id) && self.blob_hashing.len() >= MAX_HASH_JOBS {
            return ServerResponse::Err(ServerErrorCode::RateLimited);
        }
        // Placeholder: the caller sees `hash_job` and answers through
        // `start_blob_hash` / `finish_blob_hash` instead.
        self.hash_job = Some((blob_id, enc_sha256));
        ServerResponse::Ok
    }

    /// Hashes the ŞİFRELİ bytes on the blocking pool — the server cannot read
    /// the content but never serves a truncated upload. Up to `max_blob_bytes`
    /// (GiBs): inside the event loop it stalled every client for the duration.
    fn start_blob_hash(&mut self, blob_id: String, enc_sha256: Vec<u8>, channel: ResponseChannel<ServerResponse>) {
        let waiters = self.blob_hashing.entry(blob_id.clone()).or_default();
        if waiters.len() >= MAX_HASH_WAITERS {
            let busy = ServerResponse::Err(ServerErrorCode::RateLimited);
            let _ = self.swarm.behaviour_mut().server_rpc.send_response(channel, busy);
            return;
        }
        waiters.push(channel);
        // A repeated `BlobFinish` waits for the running hash, it starts none.
        if waiters.len() > 1 {
            return;
        }
        let path = self.blob_path(&blob_id);
        let tx = self.hash_tx.clone();
        tokio::spawn(async move {
            let hashed = tokio::task::spawn_blocking(move || hash_file_streaming(&path)).await.ok().flatten();
            let _ = tx.send((blob_id, enc_sha256, hashed));
        });
    }

    fn finish_blob_hash(&mut self, (blob_id, enc_sha256, hashed): HashDone) {
        let response = match hashed {
            Some(actual) if actual == enc_sha256 => match self.store.blob_finish(&blob_id, &enc_sha256, now_ms()) {
                Ok(()) => ServerResponse::Ok,
                Err(msg) => {
                    error!("blob_finish: {msg}");
                    ServerResponse::Err(ServerErrorCode::Internal)
                }
            },
            Some(_) => {
                warn!("Blob hash uyuşmuyor, reddedildi: {blob_id}");
                self.drop_blob(&blob_id);
                ServerResponse::Err(ServerErrorCode::BadHash)
            }
            // Unreadable file: the same finish fails the same way.
            None => {
                warn!("Blob okunamadı, reddedildi: {blob_id}");
                self.drop_blob(&blob_id);
                ServerResponse::Err(ServerErrorCode::BadHash)
            }
        };
        for channel in self.blob_hashing.remove(&blob_id).unwrap_or_default() {
            let _ = self.swarm.behaviour_mut().server_rpc.send_response(channel, response.clone());
        }
    }

    /// Removes a blob file, then its row and charge. A file that would not go
    /// keeps its row and its charge (the next GC tries again): refunding it
    /// let files outside every budget grow.
    fn drop_blob(&self, blob_id: &str) {
        match std::fs::remove_file(self.blob_path(blob_id)) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                warn!("Blob dosyası silinemedi ({blob_id}): {err}");
            }
            _ => self.store.blob_forget(blob_id),
        }
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
        // Rate limit: its own budget (`CHUNKS_PER_MINUTE`, 10/s), apart from
        // the RPC budget. Tor carries about one chunk a second, so only a
        // request loop reaches it. An enrolled peer over budget gets `Busy`
        // (back off, same source); an unenrolled one `NotFound`.
        let enrolled = self.active(peer).is_some();
        if !enrolled || !self.check_rate(peer, true, 1) {
            warn!("Dosya parçası isteği reddedildi (kayıtsız eş ya da hız sınırı)");
            self.stats.rejected += 1;
            let reply = if enrolled { FileChunkResponse::Busy } else { FileChunkResponse::NotFound };
            let _ = self.swarm.behaviour_mut().file_chunks.send_response(channel, reply);
            return;
        }
        let response = if !is_safe_id(&req.file_id) {
            FileChunkResponse::NotFound
        } else {
            match self.store.blob_state(&req.file_id) {
                Some(state) if state.complete => {
                    // Once per download keeps the blob alive; once per chunk
                    // was a DB write for each of thousands of chunks.
                    if req.chunk_index == 0 {
                        self.store.blob_touch(&req.file_id, now_ms());
                    }
                    // Defter #06: burası `read_chunk_from_disk` (sabit 256
                    // KiB adım) çağırıyordu, oysa `handle_blob_put` adımı
                    // İSTEMCİDEN alıp (`BlobPut.chunk_size`) ona göre
                    // yazıyor. İkisi ayrıştığı anda her blob yanlış
                    // ofsetlerden okunurdu — daha önce ölçümü bozan tam o
                    // hata. Adım artık blob'la birlikte saklanıyor.
                    match attachments::read_chunk_from_disk_with(
                        &self.blob_path(&req.file_id),
                        req.chunk_index,
                        state.chunk_size as usize,
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
    fn notify_owner_of(&mut self, mailbox: &str, depositor: PeerId, item: MailItem) {
        let targets: Vec<PeerId> = self
            .live_interest
            .iter()
            .filter(|(peer, boxes)| **peer != depositor && boxes.contains(mailbox))
            .map(|(peer, _)| *peer)
            .collect();
        for peer in targets {
            // Revoked or blocked while connected: nothing more is pushed.
            let Some(reader) = self.active(peer) else { continue };
            // See `ServerRequest::Push`: inline only when nothing older is
            // pending for this reader, so the client cannot skip an item.
            let inline = item.sealed.len() <= PUSH_INLINE_MAX
                && self.store.unacked_for(mailbox, &reader.enrollment_id) == 1;
            // One `Notify` until the peer fetches: a deposit flood otherwise
            // woke the reader's radio once per item.
            if !inline {
                if self.notified.contains_key(&peer) {
                    continue; // `resend_notifies` repeats it
                }
                self.notified.insert(peer, mono_ms());
            }
            let req = if inline { ServerRequest::Push { item: item.clone() } } else { ServerRequest::Notify };
            self.swarm.behaviour_mut().server_rpc.send_request(&peer, req);
        }
    }

    /// Repeats the `Notify` of every connected reader that has not fetched
    /// since its last one (bkz. `NOTIFY_RESEND_MS`). Called every tick (5 s).
    fn resend_notifies(&mut self) {
        let now = mono_ms();
        let due: Vec<PeerId> = self.notified.iter()
            .filter(|(_, sent)| now.saturating_sub(**sent) >= NOTIFY_RESEND_MS)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in due {
            if self.active(peer).is_none() || !self.swarm.is_connected(&peer) {
                self.notified.remove(&peer);
                continue;
            }
            self.notified.insert(peer, now);
            debug!("Notify yinelendi (Fetch gelmedi): {peer}");
            self.swarm.behaviour_mut().server_rpc.send_request(&peer, ServerRequest::Notify);
        }
    }

    /// Call-media relay (see `RELAY_PROTOCOL`): forwards a frame to every
    /// OTHER connected client listening on the frame's mailbox. Only enrolled,
    /// non-revoked clients get a link; everyone else's frames are ignored.
    fn handle_relay(&mut self, ev: RelayEvent) {
        match ev {
            RelayEvent::Open { peer, id, tx } => match self.active(peer) {
                Some(_) => {
                    debug!("Arama rölesi açıldı: {peer}");
                    self.relay_links.insert(peer, (id, tx));
                }
                // Dropping `tx` ends the writer, which closes the stream.
                _ => self.stats.rejected += 1,
            },
            RelayEvent::Closed { peer, id } => {
                if self.relay_links.get(&peer).map(|(i, _)| *i) == Some(id) {
                    self.relay_links.remove(&peer);
                    debug!("Arama rölesi kapandı: {peer}");
                }
            }
            RelayEvent::Frame { peer, mailbox, data } => {
                if !self.relay_links.contains_key(&peer) {
                    return;
                }
                let now = mono_ms();
                let budget = self.relay_budget.entry(peer).or_insert((now, 0));
                if now.saturating_sub(budget.0) > RELAY_WINDOW_MS {
                    *budget = (now, 0);
                }
                budget.1 += data.len();
                if budget.1 > RELAY_BYTES_PER_WINDOW {
                    self.stats.rejected += 1;
                    return;
                }
                let cold_bytes = budget.1;
                let frame = encode_frame(&[], &data);
                let targets: Vec<PeerId> = self
                    .live_interest
                    .iter()
                    .filter(|(target, boxes)| **target != peer && boxes.contains(&mailbox))
                    .map(|(target, _)| *target)
                    .collect();
                for target in targets {
                    // A call sends both ways. Until the target has sent this
                    // peer a frame, only the first few packets pass, so a
                    // client cannot flood a call it is not part of.
                    let mutual = self.relay_pairs.get(&(target, peer)).map_or(false, |t| now.saturating_sub(*t) <= RELAY_WINDOW_MS);
                    if !mutual && cold_bytes > RELAY_COLD_BYTES_PER_WINDOW {
                        self.stats.rejected += 1;
                        continue;
                    }
                    if let Some((_, tx)) = self.relay_links.get(&target) {
                        if tx.try_send(frame.clone()).is_ok() {
                            self.stats.relayed += 1;
                            self.relay_pairs.insert((peer, target), now);
                        }
                    }
                }
            }
        }
    }

    /// `chunk`: a file-chunk request, counted against `CHUNKS_PER_MINUTE`
    /// instead of the RPC limit. `cost`: see `request_cost`.
    fn check_rate(&mut self, peer: PeerId, chunk: bool, cost: u32) -> bool {
        let limit = self.config.limits.requests_per_minute;
        let now = mono_ms();
        let entry = self.conns.entry(peer).or_insert(ConnState {
            challenge: None,
            window_start: now,
            requests_in_window: 0,
            chunks_in_window: 0,
            connected_at: now,
            enroll_verifies: (0, 0),
            register_verifies: (0, 0),
        });
        if now.saturating_sub(entry.window_start) > RATE_WINDOW_MS {
            entry.window_start = now;
            entry.requests_in_window = 0;
            entry.chunks_in_window = 0;
        }
        if chunk {
            entry.chunks_in_window += 1;
            return entry.chunks_in_window <= CHUNKS_PER_MINUTE;
        }
        entry.requests_in_window = entry.requests_in_window.saturating_add(cost);
        entry.requests_in_window <= limit
    }

    /// Charges `checks` to the peer's share and to `pool`'s server-wide
    /// window. `Enroll` and `Rebind` share the per-peer share, not the pool.
    fn verify_budget(&mut self, peer: PeerId, pool: VerifyPool, checks: u32) -> bool {
        let now = mono_ms();
        let conn = self.conns.entry(peer).or_insert(ConnState {
            challenge: None,
            window_start: now,
            requests_in_window: 0,
            chunks_in_window: 0,
            connected_at: now,
            enroll_verifies: (0, 0),
            register_verifies: (0, 0),
        });
        match pool {
            VerifyPool::Register => charge_verify(&mut conn.register_verifies, &mut self.register_verify_window, now, checks, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE),
            VerifyPool::Enroll => charge_verify(&mut conn.enroll_verifies, &mut self.verify_window, now, checks, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE),
            VerifyPool::Rebind => charge_verify(&mut conn.enroll_verifies, &mut self.rebind_verify_window, now, checks, ENROLL_VERIFIES_PER_PEER, REBIND_VERIFIES_PER_MINUTE),
        }
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

    /// `true` while the wall clock sits more than `CLOCK_JUMP_MS` away from
    /// where the monotonic clock says it should be. After
    /// `CLOCK_JUMP_HOLD_MS` the new time is accepted as the real one, and a
    /// forward step moves the stored deadlines with it
    /// (`Store::shift_deadlines`): either clock may have been the wrong one,
    /// so nothing expires because of the step itself.
    fn clock_jumped(&mut self, now: i64, mono: u64) -> bool {
        let (wall0, mono0) = *self.clock_anchor.get_or_insert((now, mono));
        let expected = wall0 + (mono - mono0) as i64;
        if (now - expected).abs() <= CLOCK_JUMP_MS {
            self.clock_off_since = None;
            return false;
        }
        if mono - *self.clock_off_since.get_or_insert(mono) < CLOCK_JUMP_HOLD_MS {
            return true;
        }
        if now > expected {
            warn!("Sistem saati {} sn ileri alındı — süreler kaydırıldı", (now - expected) / 1000);
            self.store.shift_deadlines(now - expected, expected);
        }
        self.clock_anchor = Some((now, mono));
        self.clock_off_since = None;
        false
    }

    /// A device revoked or blocked while connected loses its pushes and its
    /// call-relay link, not only its RPCs. Runs at once on
    /// `CoreSignal::EnrollmentsChanged` (Android) and on every 5 s tick, which
    /// is what covers a revoke from the CLI, a separate process.
    fn drop_revoked_peers(&mut self) {
        let peers: HashSet<PeerId> = self.live_interest.keys().chain(self.relay_links.keys()).copied().collect();
        let gone: Vec<PeerId> = peers.into_iter().filter(|p| self.active(*p).is_none()).collect();
        for peer in gone {
            self.live_interest.remove(&peer);
            self.relay_links.remove(&peer);
        }
    }

    fn maybe_sweep(&mut self) {
        // Another connection (the CLI) committed since the last scan, or this
        // is the first tick.
        let version = self.store.data_version();
        if version != self.revoke_scan_version {
            self.revoke_scan_version = version;
            self.drop_revoked_peers();
        }
        // Once per tick, not once per Ack: the recount rewrites every enrollment.
        if std::mem::take(&mut self.mail_recount_due) {
            self.store.recount_mail_bytes();
        }
        self.resend_notifies();
        let mono = mono_ms();
        if self.last_sweep.map_or(false, |t| mono - t < SWEEP_INTERVAL_MS) {
            return;
        }
        self.last_sweep = Some(mono);
        self.publish_shared();

        let swarm = &self.swarm;
        self.conns.retain(|p, c| swarm.is_connected(p) || mono - c.window_start <= RATE_WINDOW_MS);
        self.relay_budget.retain(|_, b| mono - b.0 <= RELAY_WINDOW_MS);
        self.relay_pairs.retain(|_, t| mono - *t <= RELAY_WINDOW_MS);

        // ponytail: not in node mode, where strangers are served on purpose
        // (Kad, circuit relay); there the connection cap is still one flood wide.
        if !self.config.node_mode {
            let idle: Vec<PeerId> = self
                .conns
                .iter()
                .filter(|(p, c)| mono.saturating_sub(c.connected_at) > UNENROLLED_GRACE_MS && self.swarm.is_connected(p))
                .map(|(p, _)| *p)
                .filter(|p| self.active(*p).is_none())
                .collect();
            for peer in idle {
                let _ = self.swarm.disconnect_peer_id(peer);
            }
        }

        let now = now_ms();
        if self.clock_jumped(now, mono) {
            warn!("Sistem saati sıçradı — TTL süpürmesi bekletiliyor");
            return;
        }
        // Tracked above even while wrong, so the step to the right time is
        // seen and the deadlines move with it.
        if now < SANE_WALL_FLOOR_MS {
            warn!("Sistem saati geçersiz — TTL süpürmesi atlandı");
            return;
        }
        let slept = self.store.sleep_idle_enrollments(now - ENROLLMENT_IDLE_MS);
        let removed = self.store.sweep_expired_mail(now) + slept;
        let archived = self.store.sweep_expired_archive(now);
        if archived > 0 {
            info!("Süpürmede {archived} arşiv kaydı (13 ay) silindi");
        }
        if removed > 0 {
            info!("Süpürmede {removed} teslim öğesi silindi");
            self.store.recount_mail_bytes();
        }
        for blob_id in self.store.blobs_to_gc(now, self.config.limits.blob_ttl_ms as i64) {
            self.drop_blob(&blob_id);
        }
        self.store.recount_blob_bytes();
        self.store.incremental_vacuum();
    }
}

// ---------------------------------------------------------------------------
// Yardımcılar
// ---------------------------------------------------------------------------

/// libp2p kimliği kalıcı: `PeerId` yeniden başlatmalar arasında DEĞİŞMEMELİ,
/// yoksa dağıtılmış her davet kodu geçersiz olurdu.
/// Bir dosyayı belleğe TAMAMEN almadan SHA-256'lar. bkz. defter #07.
fn hash_file_streaming(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().to_vec())
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

/// What a request costs against `ServerLimits.requests_per_minute`: one, plus
/// one per 8 list elements (each is a query on the event loop; an
/// `ArchivePut` also pays one per 64 KiB of record bytes). A
/// `MailboxProof` is a hybrid verify, an `Enroll`/`Rebind` one too.
fn request_cost(req: &ServerRequest) -> u32 {
    let n = match req {
        ServerRequest::Enroll { .. } | ServerRequest::Rebind { .. } => return 30,
        ServerRequest::Register { add, drop, proofs } => add.len() + drop.len() + 64 * proofs.len(),
        ServerRequest::Fetch { cursors: list, .. } | ServerRequest::Ack { acks: list } => list.len(),
        ServerRequest::Cancel { seqs, .. } => seqs.len(),
        // Bytes count too: the codec caps a request at 1 MiB, so 16 extra
        // units per full request keeps count-only cheating (few big records) priced.
        ServerRequest::ArchivePut { records, .. } => {
            records.len() + records.iter().map(|r| r.sealed.len()).sum::<usize>() / (64 * 1024) * 8
        }
        ServerRequest::ArchiveProbe { buckets } | ServerRequest::ArchivePurge { buckets } => buckets.len(),
        _ => 0,
    };
    1u32.saturating_add(u32::try_from(n / 8).unwrap_or(u32::MAX))
}

/// Constant-time byte compare (the challenge is a per-connection secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn verify_ed25519(pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let Ok(pk_bytes): Result<[u8; 32], _> = pubkey.try_into() else { return false };
    let Ok(sig_bytes): Result<[u8; 64], _> = sig.try_into() else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else { return false };
    // Strict, as the client verifies: a non-canonical signature passed here
    // and failed there.
    vk.verify_strict(message, &Signature::from_bytes(&sig_bytes)).is_ok()
}

/// Kimliklerin dosya yolu olarak kullanılmadan önceki kontrolü.
///
/// `blob_id` ve `file_id` istemciden geliyor. Doğrulanmadan bir yola
/// gömülseydi `../../` ile veri dizini dışına yazma/okuma mümkün olurdu.
///
/// No upper case: on a case-insensitive blob volume (FAT/exFAT SD card) `AB12`
/// and `ab12` are one file but two DB rows, so a second uploader overwrote
/// the first one's blob. Client ids are lower-case hex and UUIDs.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(128)
        .collect()
}

/// Charges `checks` to a peer's share and to the server-wide pool, each a
/// (window start `mono_ms`, checks) over `RATE_WINDOW_MS`. A refused charge
/// costs nothing, so a peer over its share cannot drain the pool for others.
fn charge_verify(peer: &mut (u64, u32), pool: &mut (u64, u32), now: u64, checks: u32, peer_limit: u32, pool_limit: u32) -> bool {
    for w in [&mut *peer, &mut *pool] {
        if w.0 == 0 || now.saturating_sub(w.0) > RATE_WINDOW_MS {
            *w = (now.max(1), 0);
        }
    }
    if peer.1.saturating_add(checks) > peer_limit || pool.1.saturating_add(checks) > pool_limit {
        return false;
    }
    peer.1 += checks;
    pool.1 += checks;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_peer_cannot_drain_the_verify_pool() {
        let mut pool = (0, 0);
        let (mut a, mut b) = ((0, 0), (0, 0));
        let now = 1_000;
        // Peer A hammers with full Registers: only its share passes.
        assert!(charge_verify(&mut a, &mut pool, now, 64, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE));
        for _ in 0..100 {
            assert!(!charge_verify(&mut a, &mut pool, now, 64, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE));
        }
        // Peer B still gets its own full share.
        assert!(charge_verify(&mut b, &mut pool, now, 64, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE));
        // The window rolls over: A is served again.
        assert!(charge_verify(&mut a, &mut pool, now + RATE_WINDOW_MS + 1, 64, REGISTER_VERIFIES_PER_PEER, REGISTER_VERIFIES_PER_MINUTE));
        // Enroll pool: an unknown peer gets only a small share.
        let (mut epool, mut u, mut v) = ((0, 0), (0, 0), (0, 0));
        for _ in 0..ENROLL_VERIFIES_PER_PEER {
            assert!(charge_verify(&mut u, &mut epool, now, 1, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE));
        }
        assert!(!charge_verify(&mut u, &mut epool, now, 1, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE));
        assert!(charge_verify(&mut v, &mut epool, now, 1, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE));
        // The pool itself still caps the total.
        let mut full = (now, ENROLL_VERIFIES_PER_MINUTE);
        assert!(!charge_verify(&mut (0, 0), &mut full, now, 1, ENROLL_VERIFIES_PER_PEER, ENROLL_VERIFIES_PER_MINUTE));
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
        assert!(!is_safe_id("BL_ABC123"), "case-insensitive volumes: one file, two rows");
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
