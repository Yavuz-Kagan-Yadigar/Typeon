//! Typeon — Rust çekirdeği.
//! Description.md "Aşama A" kapsamını hedefler: tek cihaz (1 Identity = 1
//! Device) varsayımıyla test edilir, ama Identity/Device ayrımına göre
//! yazılmıştır (Aşama B'de çoklu cihaza genişletilebilir).
//! Modüller:
//! - `identity`  : bölüm 1 — Identity/Device modeli, fingerprint
//! - `packet`    : bölüm 1.3-1.6, 3.3, 5.2 — ağ paket formatları
//! - `ratchet`   : bölüm 3 — hibrit KEM + Double Ratchet
//! - `contact`   : bölüm 2 — TOFU + güvenlik numarası değişikliği
//! - `group`     : bölüm 5 — pairwise grup mesajlaşma

/// Kripto çekirdeği ayrı bir crate'e (`typeon-crypto`) taşındı — aynı denetlenmiş
/// kod native (Android/Linux/relay) VE tarayıcı (wasm) tarafında çalışsın diye.
/// Bu `pub use`, eski yolları (`crate::packet::…`, `crate::identity::…`,
/// dışarıdan `p2p_messenger::server_proto::…`) OLDUĞU GİBİ korur; çağıran kod
/// değişmez.
pub use typeon_crypto::{identity, packet, ratchet, server_proto, server_seal};
mod contact;
mod group;
/// `pub`: `typeon-server/` sunucu crate'i, dosya eklerini istemcilerin ZATEN
/// konuştuğu protokolle servis ederken BU tipleri ve `read_chunk_from_disk`'i
/// aynen kullanır (disk formatı = kablo formatı olduğundan sunucu tarafında
/// hiçbir şifreleme/çerçeveleme kodu yeniden yazılmaz).
pub mod attachments;
/// `pub`: sunucu da kendi onion service'ini barındırır — bir telefonun
/// (Android sunucu uygulaması) CGNAT arkasından ulaşılabilir olmasının tek
/// yolu bu.
pub mod tor;

// NOT: `server_proto` ve `server_seal` artık `typeon-crypto` crate'inde;
// yukarıdaki `pub use typeon_crypto::{…}` bunları eskisi gibi
// `p2p_messenger::server_proto::…` / `crate::server_seal::…` olarak erişilebilir
// tutar (`typeon-server/` crate'i AYNI tanımları kullanmaya devam eder).
/// Sunucu seçeneğinin istemci tarafı — `impl P2PCore` blokları. Diğer konu
/// modülleri gibi ayrı dosyada; alt modül olduğundan
/// `P2PCore`'un private alanlarını görebiliyor.
pub mod server_client;
/// Voice/video calls — signalling + media streams, see module docs.
pub mod call;
/// Shared whiteboard per chat — storage, sync and limits, see module docs.
mod whiteboard;

/// Toplu aktarım isteklerinin zaman aşımı (ms) — sunucu tarafı da AYNI
/// değeri kullanmalı, yoksa bir uç diğerinden önce vazgeçer.
pub fn server_client_timeout_ms() -> u64 {
    server_client::BLOB_REQUEST_TIMEOUT_MS
}

/// Circuit Relay v2 limits of a node: client node mode and the server use
/// the same ones. The relay is open to every peer. A circuit is the fallback
/// connection between two peers whose onion dial failed, so it carries chat,
/// file chunks and call media, not only signalling.
pub fn relay_server_config() -> relay::Config {
    let n = |v: u32| std::num::NonZeroU32::new(v).expect("limit > 0");
    let secs = std::time::Duration::from_secs;
    relay::Config {
        // One per peer that can be reached through this node: 64 enrolled
        // devices (server default) and half as many again.
        max_reservations: 96,
        // One relay connection per peer; 2 covers a reconnect overlap.
        max_reservations_per_peer: 2,
        // Library value: a shorter one is one more radio wake-up per renewal.
        reservation_duration: secs(60 * 60),
        reservation_rate_limiters: Vec::new(),
        // Library values: a circuit is one peer pair, a chat with 4 contacts
        // behind this relay already needs 4.
        max_circuits: 16,
        max_circuits_per_peer: 4,
        // The client redials at once when a circuit ends; 30 min is one
        // reconnect in a long call, not one every 2 min (library default).
        max_circuit_duration: secs(30 * 60),
        // 128 file chunks of 256 KiB, or more voice than 30 min holds; a file
        // goes on after the redial (downloads resume). Video (~1 Mbit/s both
        // ways) reaches it in about 4 min and reconnects.
        max_circuit_bytes: 32 * 1024 * 1024,
        circuit_src_rate_limiters: Vec::new(),
    }
    // Burst 8, then one per 2 min = the client's reservation retry interval.
    .reservation_rate_per_peer(n(8), secs(120))
    // Every peer arrives from 127.0.0.1 (onion bridge), so "per IP" is one
    // bucket for all: 8 full per-peer bursts, refilled 6 per minute.
    .reservation_rate_per_ip(n(64), secs(10))
    // Library value: every fallback dial to an offline contact costs one.
    .circuit_src_per_peer(n(30), secs(120))
    // All peers together (see above): 8 per-peer bursts, refilled 1 per second.
    .circuit_src_per_ip(n(240), secs(1))
}

/// Saf-Rust API cephesi — bu dosyanın sonundaki JNI export'larının, JVM'e
/// özgü tiplerden arındırılmış birebir karşılıkları. SADECE JNI OLMAYAN
/// çağıranlar (bkz. depo kökündeki `Linux/` masaüstü istemcisi) içindir;
/// Android tarafı eskisi gibi doğrudan JNI export'larını kullanır, bu modül
/// onun için tamamen ölü koddur (bkz. `api` modül dokümantasyonu).
pub mod api;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use android_logger::Config as LogConfig;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, VerifyingKey};
use futures::FutureExt as _;
use futures::StreamExt as _;
use hex;
use hkdf::Hkdf;
use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jboolean, jlong, jobjectArray, jstring};
use jni::JNIEnv;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol as MultiaddrProtocol;
use libp2p::request_response;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, kad, noise, relay, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use log::{debug, error, info, warn};
// NOT: pqcrypto-dilithium/pqcrypto-kyber yerine RustCrypto'nun aktif bakımlı
// ml-dsa/ml-kem crate'lerine geçildi (bkz. Cargo.toml notu — RUSTSEC-2024-0380,
// RUSTSEC-2024-0381, FIPS 204/203 bayt-uyumsuzluğu). Spec "ML-DSA-65"
// istiyordu (bölüm 1.1 tablosu) — önceki kod yanlışlıkla ML-DSA-44 (Dilithium2)
// kullanıyordu; o geçişte MlDsa65'e düzeltilmişti. Daha sonra (bu güvenlik
// denetimi turunda) ekstra marj için NIST Kategori 5'e (ML-KEM-1024/
// ML-DSA-87) yükseltildi — bkz. SECURITY.md "Anahtar boyutları" notu.
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Generate as MlDsaGenerate, KeyExport as MlDsaKeyExport, Keypair as MlDsaKeypair, MlDsa87, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey, Signer as MlDsaSigner, VerifyingKey as MlDsaVerifyingKey, Verifier as MlDsaVerifier};
use ml_kem::{EncodedSizeUser as MlKemEncodedSizeUser, KemCore as MlKemCore, MlKem1024};
use rand::rngs::OsRng;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};


use contact::{check_incoming_device, Contact, DeviceCheckOutcome};
use group::{apply_change, validate_group_update, Group, GroupChange, GroupUpdateError};
use identity::{compute_fingerprint, DeviceStatus};
use packet::{
    DeviceAdd, DeviceLinkRequest, DeviceRevoke, GroupMemberDevice, GroupUpdate, HandshakeInit, IdentityExchange,
    MessageContent, MessagePacket, MessagePacketHeader, NetworkEnvelope, QrPacket, SiblingEchoBody,
    SiblingHistoryEntry, SignedPrekey, SyncPayload, SyncedContact, SyncedDevice, SyncedMessage,
};
use ratchet::{DeviceRatchetState, MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, RatchetPublicKeys};
use attachments::{FileChunkRequest, FileChunkResponse};

const DB_NAME: &str = "p2p_messenger.db";
/// Dosya ekleri protokol kimliği (bkz. attachments.rs modül notu).
const FILE_TRANSFER_PROTOCOL: &str = "/p2pmessenger/filexfer/1.0.0";
/// Kullanıcı tarafından istenen azami dosya eki boyutu (bkz.
/// `prepare_and_send_file`).
const MAX_ATTACHMENT_SIZE: u64 = 4 * 1024 * 1024 * 1024;

lazy_static::lazy_static! {
    static ref RUNTIME: Runtime = tokio::runtime::Runtime::new().expect("tokio runtime could not start (threads/fds exhausted)");
    static ref CORE: Arc<Mutex<P2PCore>> = Arc::new(Mutex::new(P2PCore::new()));
    /// bkz. `wait_for_network_activity`.
    static ref NET_WAKE: tokio::sync::Notify = tokio::sync::Notify::new();
}

// The core is split by topic; every module sees the crate root (`use super::*`)
// and the root re-exports them, so `crate::name` paths are unchanged.
mod core_lock;
mod media_unlocked;
mod wire;
mod util;
#[cfg(test)]
mod core_tests;
mod network;
mod types;
mod tuning;
mod db;
mod pairing;
mod devices;
mod sibling_sync;
mod contacts;
mod session;
mod send;
mod receive;
mod archive;
mod persist;
mod group_ops;
mod storage;
mod file_transfer;
mod poll;
mod recovery;
mod jni_exports;
use core_lock::*;
use media_unlocked::*;
pub use wire::*;
pub use util::*;
#[allow(unused_imports)] // only the tests use it from here
use network::*;
pub use types::*;
use tuning::*;
#[allow(unused_imports)] // only the debug-hooks export uses it from here
use db::*;
use recovery::*;
pub use jni_exports::*;

/// Every source file of the core, for the tests that scan it.
#[cfg(test)]
const CORE_SRC: &str = concat!(
    include_str!("lib.rs"),
    include_str!("core_lock.rs"),
    include_str!("media_unlocked.rs"),
    include_str!("wire.rs"),
    include_str!("util.rs"),
    include_str!("core_tests.rs"),
    include_str!("network.rs"),
    include_str!("types.rs"),
    include_str!("tuning.rs"),
    include_str!("db.rs"),
    include_str!("pairing.rs"),
    include_str!("devices.rs"),
    include_str!("sibling_sync.rs"),
    include_str!("contacts.rs"),
    include_str!("session.rs"),
    include_str!("send.rs"),
    include_str!("receive.rs"),
    include_str!("archive.rs"),
    include_str!("persist.rs"),
    include_str!("group_ops.rs"),
    include_str!("storage.rs"),
    include_str!("file_transfer.rs"),
    include_str!("poll.rs"),
    include_str!("recovery.rs"),
    include_str!("jni_exports.rs"),
);

struct P2PCore {
    db: Option<Connection>,
    identity: Option<identity::Identity>,
    /// key = device_fingerprint. A linked secondary has the primary's
    /// identity_id, so the two differ.
    own_devices: HashMap<String, DeviceRecord>,
    own_device_keys: HashMap<String, DeviceKeys>,
    /// Bilinen uzak cihazların public key kayıtları (contact exchange /
    /// QR üzerinden öğrenilir).
    known_remote_devices: HashMap<String, DeviceRecord>,
    /// Bir cihaza EN SON ne zaman `IdentityExchange` YANITI verdiğimiz
    /// (bkz. `process_identity_exchange` sonundaki karşılıklı-yanıt bloğu).
    /// Neden var: o yanıt koşulsuzdu ve karşı taraf da aynı şeyi yapıyordu —
    /// yani A→B bir yanıt doğuruyor, o yanıt B→A bir yanıt daha doğuruyordu.
    /// İki eşleşmiş cihaz arasında SONSUZ bir ping-pong: gerçek cihazlarda
    /// ölçüldü, saniyede 60-100 zarf, hepsi ayrıca sunucuya da yatırılıyor
    /// (birkaç dakikada binlerce satır) ve karşı tarafın paket hız sınırını
    /// doldurup GERÇEK trafiği düşürüyordu.
    last_identity_exchange_reply: HashMap<String, u64>,
    contacts: HashMap<String, Contact>, // contact_id -> Contact
    /// identity_id -> contact_id hızlı arama.
    identity_to_contact: HashMap<String, String>,
    /// Cihaz-çifti bazlı ratchet oturumları: key = uzak device_fingerprint.
    ratchets: HashMap<String, DeviceRatchetState>,
    /// Spec dışı, güvenlik denetimi düzeltmesi (el sıkışma tekrar oynatma →
    /// oturum sıfırlama DoS'u): bu cihazdan freshness penceresi
    /// (`HANDSHAKE_MAX_SKEW_MS`) içinde KABUL EDİLMİŞ el sıkışmaların
    /// (timestamp, signature_classical) kayıtları. Gelen bir el sıkışmanın
    /// imzası bu sette AYNEN varsa, bu bir tekrar oynatmadır (gossipsub
    /// `Signed` modu ağ gözlemcisinin yakaladığı bir paketi yeniden
    /// yayınlamasına izin verir) ve reddedilir — böylece canlı bir ratchet
    /// SIFIRLANAMAZ. İçerik-tabanlı (imza) dedup, monoton-timestamp'e göre
    /// daha SAĞLAM: gerçek bir yeniden-eşleşme (taze efemeral anahtarlar,
    /// farklı imza) saat kayması ne olursa olsun kabul edilir; yalnızca
    /// bayt-aynısı tekrar reddedilir. Pencereden eski girdiler budanır
    /// (sınırsız büyümez). Bellek-içi; süreç yeniden başlasa da freshness
    /// penceresi çok eski tekrarları zaten reddeder.
    recent_handshake_sigs: HashMap<String, Vec<(u64, Vec<u8>)>>,
    /// bkz.
    /// `EARLY_PACKET_TTL_MS`. key = gönderen device_fingerprint,
    /// value = (tamponlanma zamanı, paket). El sıkışma tamamlanınca
    /// `replay_early_packets` ile sırayla işlenir.
    early_packets: HashMap<String, std::collections::VecDeque<(u64, Option<PeerId>, MessagePacket)>>,
    /// İKİ CİHAZLI TESTTE (2026-09-06) bulundu: eşleşme sırasında A'nın
    /// `HandshakeInit`'i B'ye, B daha A'nın `IdentityExchange`'ini işlemeden
    /// (yani A'yı `known_remote_devices`'a eklemeden) ulaşabiliyor —
    /// `process_handshake_init` "Unknown sender device" ile paketi DÜŞÜRÜYOR
    /// (erken `Message`'lar tamponlanıyor ama `Handshake`'ler değildi). Sonuç:
    /// B kendi `initiate_handshake_with`'ini çağırıp bir INITIATOR ratchet
    /// üretiyor, A'nınki de INITIATOR — iki uyumsuz initiator, hiçbir mesaj
    /// çözülemiyor. Artık böyle bir `HandshakeInit` tamponlanır ve
    /// `process_identity_exchange` gönderen cihazı öğrenir öğrenmez oynatılır.
    /// key = gönderen device_fingerprint. Up to 3 inits per fingerprint,
    /// never replaced: the claim is unverified until replay, so a later junk
    /// init must not push out the genuine one (its digest stays deduped).
    early_handshakes: HashMap<String, Vec<(u64, Option<PeerId>, HandshakeInit)>>,
    /// bkz. `INBOUND_DEDUP_WINDOW_MS` — başarıyla işlenmiş gelen zarfların
    /// `ham bayt hash'i -> son görülme (ms)` haritası. Çok yollu teslimin
    /// ürettiği bayt-aynısı tekrarları, imza doğrulama/ratchet decrypt gibi
    /// pahalı işlemlerden ÖNCE, en ucuz noktada eler.
    recent_inbound_digests: HashMap<u64, (u64, bool)>,
    /// bkz. `reack_if_already_handled` — `message_id -> (Ack'lenen gönderen
    /// cihaz fp, Ack anı ms)`. Bellek-içi, `RECENTLY_ACKED_MAX_ENTRIES` ile sınırlı.
    recently_acked: HashMap<String, (String, u64)>,
    /// bkz. `flush_outbound_acks` — bu turda gönderilecek Ack'ler, eş cihaz fp -> message_id'ler.
    outbound_acks: HashMap<String, Vec<String>>,
    /// Yanıt bekleyen toplu Ack istekleri — başarısız olursa şifreli pakete düşülür.
    ack_batches_inflight: HashMap<request_response::OutboundRequestId, (String, Vec<String>)>,
    last_inbound_dedup_prune_at: u64,
    /// bkz. `EARLY_EDIT_DELETE_TTL_MS` dokümantasyonu — hedef `Text`'i henüz
    /// arşivde bulunamayan `Edit`/`Delete` paketleri. key = hedef mesaj
    /// kimliği (1:1 `message_id`/grup `group_message_local_id`), value =
    /// (tamponlanma zamanı, gönderen peer_fp, gönderen sender_identity_id,
    /// paketin KENDİ message_id'si (Ack için), içerik). Hedef `Text`
    /// arşivlenince `replay_buffered_edits_deletes` ile uygulanır.
    pending_edits_deletes: HashMap<String, Vec<(u64, String, String, String, MessageContent)>>,
    /// Text/FileOffer/Reaction for a group we do not hold yet, by group id:
    /// (held at, source, peer_fp, sender identity, packet id, content,
    /// signed send time). Archived, a removed member's or any contact's rows
    /// for a made-up id stayed for good and showed once the group was known.
    unknown_group_held: HashMap<String, Vec<(u64, Option<PeerId>, String, String, String, MessageContent, u64)>>,
    groups: HashMap<String, Group>,
    /// Kullanıcının onay beklediği, henüz kabul/red edilmemiş cihaz
    /// değişikliği uyarıları (spec 2.2). key = new_device_fingerprint.
    pending_device_alerts: HashMap<String, DeviceAlertInfo>,
    /// Bekleyen mesajlar (henüz doğrulanmamış/bloklu cihazdan geleni
    /// tutmuyoruz — spec "yeni mesaj gönderme/alma durur" der, yani
    /// alert çözülene kadar o cihazdan gelen mesajlar sessizce reddedilir).
    swarm: Option<Swarm<P2PBehaviour>>,
    /// Spec dışı, kullanıcı isteği (bkz. tor.rs / SECURITY.md "Tor onion"):
    /// Tor katmanı açıksa çalışan onion service tutamacı (client + servis +
    /// köprü). `None` = Tor kapalı. `start_network`'te (tor_enabled ise)
    /// başlatılır.
    tor: Option<tor::TorHandle>,
    /// Kullanıcının Tor'u açıp açmadığı — `start_network`'e paramla gelir,
    /// `tor_status`/`get_node_address` tarafından okunur.
    tor_enabled: bool,
    /// Spec dışı, ağ sağlamlığı düzeltmesi (bkz. `announce_address_to_all_contacts`/
    /// `packet.rs` `AddressAnnounce` dokümantasyonu): `poll_events`'in Tor
    /// durumunun `Ready`'e YENİ geçtiğini (önceki turda değil) tespit
    /// edebilmesi için bir önceki turda gözlemlenen "hazır mı" durumu.
    /// `start_network`'te `false`'a sıfırlanır (yeni bir Tor istemcisi/oturumu
    /// başlıyor). Geçiş yakalandığında bilinen HER kişiye o anki `.onion`
    /// adresimiz proaktif olarak gönderilir.
    tor_was_ready: bool,
    /// `start_network` sonrası swarm'ın gerçekten dinlemeye başladığı
    /// adresler (`SwarmEvent::NewListenAddr`, bkz. `poll_events`) — QR/"Kodum"
    /// ekranında gösterilen `node_address` bundan türetilir (yalnız röle
    /// devresi adresleri; loopback dinleyicisi gösterilmez).
    own_listen_addrs: Vec<Multiaddr>,
    /// `publish_envelope` gossipsub publish() başarısız olduğunda (bkz. o
    /// fonksiyonun dokümantasyonu — ilk bağlantıdan sonraki ilk birkaç
    /// saniyede mesh henüz oluşmamış olabilir; HandshakeInit/IdentityExchange/
    /// Message/GroupUpdate FARK ETMEKSİZİN, herhangi bir zarf bundan
    /// etkilenebilir) gönderilecek zarfı burada bekletir. `poll_events` her
    /// turda AYNI zarfı (yeni bir ratchet adımı/message_id tüketmeden)
    /// yeniden göndermeyi dener — bu, TÜM zarf türleri için TEK, merkezi bir
    /// yeniden deneme mekanizmasıdır (önceden her çağıran kendi tip-özel
    /// kuyruğunu tutuyordu, bu hem tekrarlıydı hem de HandshakeInit gibi
    /// bazı zarflar için hiç kapsanmıyordu). Üçüncü alan: ilk deneme
    /// zamanı (ms) — `PENDING_ENVELOPE_TIMEOUT_MS`'i aşarsa kalıcı olarak
    /// "Failed" sayılıp kuyruktan düşürülür (aksi halde asla erişilemeyen
    /// bir cihaz için sonsuza kadar denenir).
    pending_envelopes: Vec<QueuedEnvelope>,
    /// UI'nin mesaj durumu ikonları göstermesi için (bkz. spec dışı
    /// "gönderim durumu" isteği) — key: `MessagePacketHeader.message_id`.
    /// Bounded: `set_message_status` clears it at 10 000 entries.
    message_status: HashMap<String, MessageSendStatus>,
    /// Node modu açık mı: relay service (next network start), history-sync
    /// help, auto-download. Kademlia is always Client (bkz. `set_node_mode`).
    node_mode_enabled: bool,
    /// Spec dışı, kullanıcı isteği: node modu açıkken (bkz.
    /// `receive_file_offer` auto-download notu — SADECE node modu her
    /// teklif edilen dosyayı otomatik indirir, bu yüzden disk kullanımı
    /// sınırsız büyüyebilir) toplam ek (attachment) depolamasının üst
    /// sınırı. Kotlin bunu Ayarlar'daki kaydırıcıdan
    /// `setHistoryStorageLimitBytes` ile ayarlar; her `start_network`'te de
    /// gönderilir (bkz. P2PService), bu yüzden buradaki varsayım sadece
    /// hiç ayarlanmadan önceki ilk an için bir güvenlik ağı. Aşılınca
    /// `enforce_history_storage_limit` EN ESKİ tamamlanmış dosyaları
    /// (created_at artan) sırayla tamamen siler.
    history_storage_limit_bytes: u64,
    /// `createIdentity` sonrası bir kereliğine Kotlin'e teslim edilecek
    /// plaintext secret bundle. `getPendingSecretBundle` çağrıldığında
    /// alınıp `None`'a döner (bkz. o fonksiyonun dokümantasyonu).
    pending_secret_bundle: Option<Vec<u8>>,
    /// Çoklu-cihaz (spec 1.5): `approve_device_link` sırasında, onaylanan
    /// YENİ cihazın fingerprint'i. `process_identity_exchange` bunu görünce
    /// gelen cihazı bir KİŞİ olarak değil, KENDİ kimliğimizin bir KARDEŞ
    /// cihazı olarak kaydeder (identity_id'yi kendi kimliğimize eşitler) ve
    /// `DeviceLinkGrant`'i (imzalı DeviceAdd + tam senkron) gönderir. Grant
    /// gönderilince temizlenir.
    pending_link_target: Option<String>,
    /// bkz. `PENDING_LINK_RETRY_HORIZON_MS` — `pending_link_target`'ın en
    /// son ayarlandığı an; `reconnect_sweep`'in periyodik dial +
    /// IdentityExchange yeniden gönderimini zamanla durdurmak için.
    pending_link_started_at: u64,
    /// İkincil taraf: bu cihaz bir bağlama QR'ı ürettiyse (`build_device_link_request`)
    /// `DeviceLinkGrant` bu ana kadar kabul edilir. Aksi halde eşleşmiş herhangi
    /// bir kişi kendi imzalı grant'iyle bu cihazı kendi kimliğine bağlatıp
    /// (kimliğimizi silip) tüm kişi/grup/arşiv anahtarımızı kardeş senkronuyla
    /// kendine çekebilirdi.
    link_request_open_until: u64,
    /// The nonce in the link QR this device shows (`DeviceLinkRequest.nonce`);
    /// a grant is adopted only when it repeats it. Empty = no QR shown.
    link_request_nonce: Vec<u8>,
    /// The first device that proved it read the link code this device shows
    /// (`IdentityExchange.pairing_proof`): the IdentityExchange sent to it
    /// carries `link_consent`.
    link_consent_peer: Option<String>,
    /// Primary side: the nonce of the QR scanned for `pending_link_target`,
    /// sent back in the grant.
    pending_link_nonce: Vec<u8>,
    /// This device's prekeys, oldest first; the last one is handed out.
    /// Loaded on first use (`current_own_prekey`): they are sealed with the
    /// local storage key, which arrives after the database is opened.
    own_prekeys: Vec<OwnPrekey>,
    own_prekeys_loaded: bool,
    /// The newest verified prekey of each known device (`store_peer_prekey`).
    peer_prekeys: HashMap<String, SignedPrekey>,
    /// Devices our pending HandshakeInit went to with prekey id 0 (we held no
    /// prekey of theirs). A peer that hands out prekeys refuses such an init
    /// as a first contact, bkz. `process_handshake_init`.
    id0_inits: std::collections::HashSet<String>,
    /// Spec dışı, gerçek cihaz hatası düzeltmesi ("QR tarandı, iki cihazda da
    /// hiçbir şey olmadı"; karşı taraf `InsufficientPeers` ile yayın
    /// yapamıyordu): şu an kendi posta kutusu topic'ine (`p2p_msg_<fp>`)
    /// abone OLDUĞUMUZ cihaz fingerprint'i. `None` ise henüz hiç abone
    /// olunmadı.
    /// Neden gerekli: bu abonelik `start_network` içinde BİR KEZ, o an
    /// aktif bir kimlik VARSA yapılıyordu. Ama `P2PService.onStartCommand`
    /// kendi `isRunning` bayrağıyla ağ kurulumunu SÜREÇ BAŞINA BİR KEZE
    /// kilitliyor; servis, kimlik daha OLUŞMADAN başlamışsa (ör. çıkış
    /// yapıldıktan sonraki `exit(0)`'ı izleyen START_STICKY yeniden
    /// başlatması, ya da önceki çalışmadan sağ kalan servis) `start_network`
    /// kimliksiz çalışıyor, abonelik SESSİZCE atlanıyor ve ardından
    /// `createIdentity` + `startNetworkService()` `isRunning` yüzünden
    /// NO-OP oluyordu. Sonuç: swarm canlı, Tor onion servisi çalışıyor,
    /// QR üretilebiliyor (`get_node_address` çalışıyor), gelen bağlantılar
    /// kabul ediliyor — ama cihaz HİÇBİR gossipsub topic'ine abone değil,
    /// dolayısıyla ona hiçbir paket TESLİM EDİLEMİYOR (karşı taraf sonsuza
    /// kadar `InsufficientPeers` alıyor, bkz. libp2p-gossipsub `publish`:
    /// `topic_peers` girdisi yoksa alıcı kümesi boş kalır).
    /// Bu alan sayesinde `ensure_own_mailbox_subscription` (her `poll_events`
    /// turunda) kimlik SONRADAN oluşsa/yüklense bile aboneliği
    /// kendi kendine tamamlar — ağ katmanının yeniden başlatılması GEREKMEZ.
    own_mailbox_topic_fp: Option<String>,
    /// İKİ CİHAZLI GERÇEK TESTTE ÖLÇÜLDÜ (2026-09-06): iki telefon aynı
    /// LAN'da doğrudan bağlıyken bile, taze eşleşmeden sonra `IdentityExchange`
    /// karşı tarafa ~5 DAKİKA ulaşmadı — gossipsub, gönderenin ABONE OLMADIĞI
    /// bir posta kutusu topic'ine ("fanout") güvenilir teslim etmiyor; iş
    /// ancak yavaş Tor/sunucu yolu devreye girince oldu.
    /// Çözüm: eşleşme SÜRESİNCE her iki taraf da KARŞI tarafın posta kutusu
    /// topic'ine (`p2p_msg_<peer_fp>`) de abone olur — böylece ikisi de aynı
    /// topic'te → gerçek gossipsub mesh'i kurulur → `Handshake`/`IdentityExchange`
    /// saniyeler içinde gider. Bir ratchet oturumu kurulunca (artık rotasyonlu
    /// topic kullanılıyor) ya da `PAIRING_MAILBOX_TTL_MS` dolunca abonelik
    /// bırakılır. key = peer_fp, value = abone olunma anı (ms).
    pairing_mailbox_subs: HashMap<String, u64>,
    /// The connection a verified IdentityExchange arrived on, per device.
    /// Only our IdentityExchange and Handshake to that device use it: the
    /// side that showed its code has no PeerId mapping yet (the IX maps
    /// nothing, see `process_identity_exchange`), and without gossipsub its
    /// reply had no path but a server. Dropped once a ratchet exists.
    pairing_reply_peer: HashMap<String, PeerId>,
    /// Çoklu-cihaz: BU cihaz ikincil olarak bir kimliğe bağlandıysa, onaylayan
    /// (birincil) cihazın bize verdiği imzalı `DeviceAdd` — kişilere kendimizi
    /// tanıtırken (`DeviceAddNotice`) kanıt olarak kullanılır. Diske
    /// `own_device_add` tablosunda kalıcı.
    own_device_add: Option<DeviceAdd>,
    /// Parts of big stickers from my other devices, by sticker id: (first
    /// part's arrival ms, parts). Memory only: a part lost to a restart comes
    /// again with the next "Fetch stickers".
    sticker_parts: HashMap<String, (u64, Vec<Option<Vec<u8>>>)>,
    /// Çoklu-cihaz (spec 2.2): imzası doğrulanmış bir `DeviceAddNotice` ile
    /// önceden duyurulmuş, ama henüz `IdentityExchange`'i gelmemiş yeni cihaz
    /// fingerprint'leri. `evaluate_sender_device`, bu sette olan bir cihazı
    /// "bilinen aktif cihazın imzaladığı ekleme" (NewDeviceViaSignedAdd)
    /// olarak sessizce kabul eder — kullanıcıya "tanınmayan cihaz" uyarısı
    /// göstermeden. value = identity_id.
    verified_device_adds: HashMap<String, String>,
    /// Mesaj geçmişi arşivini şifrelemek için kullanılan 256-bit anahtar.
    /// Kotlin, Keystore'da sarılı (wrapped) bir "history data key" tutar,
    /// açılışta çözüp `setHistoryKey` ile buraya yükler — Rust bu anahtarı
    /// diske hiç yazmaz, sadece bellekte tutar (bkz. dosya sonu "mesaj
    /// geçmişi" notu). `None` iken (henüz yüklenmedi veya node modu hiç
    /// açılmadı) mesajlar arşivlenmez, sadece anlık işlenir.
    history_key: Option<[u8; 32]>,
    // --- Sunucu (store-and-forward) seçeneği; bkz. `server_client` modülü ---
    /// Yapılandırılmış sunucular (kalıcı, `servers` tablosu).
    servers: Vec<server_client::ServerRecord>,
    /// Sunucu başına çalışma-zamanı durumu (bağlı mı, kayıtlı mı, hangi
    /// kutular bildirildi) — kalıcı DEĞİL, her açılışta yeniden kurulur.
    server_rt: HashMap<String, server_client::ServerRuntime>,
    /// Havada bekleyen sunucu RPC'leri. Bir `Deposit` başarısız olursa bu
    /// haritadaki zarf gossipsub'a düşürülür (bkz. `requeue_failed_deposit`).
    server_inflight: HashMap<request_response::OutboundRequestId, server_client::ServerInflight>,
    /// `(server_id, mailbox_id) -> işlenmiş en yüksek seq`. KALICI: bu
    /// olmadan her yeniden başlatma bütün kutuyu baştan işlerdi.
    server_cursors: HashMap<(String, String), u64>,
    /// `UnknownMailbox` alınan kutular ve ne zamana kadar sorulmayacakları —
    /// "bu alıcı sunucumda değil" bilgisi mesaj başına bir gidiş-dönüşe mal
    /// olmasın diye.
    server_unknown_mailboxes: HashMap<(String, String), u64>,
    /// `UnknownMailbox` answers in a row per mailbox: the next pause doubles
    /// (see `SERVER_UNKNOWN_MAILBOX_MAX_TTL_MS`); a stored deposit resets it.
    server_unknown_streak: HashMap<(String, String), u32>,
    /// Sunucuya yüklenmeyi bekleyen arşiv kayıtları (kalıcı).
    server_archive_queue: Vec<server_client::PendingArchive>,
    /// Sunucuya yüklenmeyi bekleyen dosyalar (kalıcı).
    server_blob_uploads: Vec<server_client::PendingBlobUpload>,
    server_sweep_at: u64,
    /// Bir sunucuya BAŞARIYLA yatırılmış mesajlar: `(server_id, message_id)`
    /// -> yatırma anı (ms).
    /// Neden var: `awaiting_confirmation` uçtan uca `Ack` gelene kadar zarfı
    /// yeniden gönderir (7 güne kadar). Bu, gossipsub yolu için doğru —
    /// orada hiçbir şey saklanmaz. Ama sunucu yolunda zarf zaten DİSKTE:
    /// yeniden yatırmak alıcının onu görme ihtimalini bir gram artırmaz,
    /// yalnızca aynı baytları tekrar tekrar yollar.
    /// Gerçek cihazda ölçülen sonuç: artık var olmayan bir kimliğe (eski,
    /// eşleşmesi bozulmuş bir kişiye) giden kuyruk, ikisi 368 KB'lık altı
    /// zarfı ~20 saniyede bir yeniden yatırıyordu — Tor bağlantısında
    /// saniyede ~40 KB saf israf, sunucu posta kutusu şişiyor, karşı tarafın
    /// paket hız sınırı doluyor ve ÇALIŞAN sohbet aç kalıyordu.
    /// `SERVER_DEPOSIT_MEMORY_MS` (7 gün = mesajın yeniden deneme penceresi,
    /// sunucu kutu TTL'inin altında) sonra unutulur; tavan
    /// `MAX_SERVER_DEPOSIT_MEMORY` girdide tutulur.
    server_deposited: HashMap<(String, String), u64>,
    /// Bir paketin sunucuda NEREYE düştüğü: `(sunucu, mesaj kimliği)` ->
    /// `(kutu, sıra numarası)`. `cancel_pending_message` bunu kullanarak
    /// sunucudaki kopyayı da geri çekiyor (bkz. `ServerRequest::Cancel`) —
    /// aksi halde kullanıcı mesajı iptal etse bile kopya, alıcı çevrimdışı
    /// olduğu sürece 30 gün sunucuda kalıyordu.
    server_deposit_locations: HashMap<(String, String), (String, u64)>,
    /// Blob parçalarının toplam/adet gidiş-dönüş süresi — aktarımın gecikme
    /// mi bant genişliği mi sınırlı olduğunu ayırt etmek için (bkz.
    /// `server_client` `BLOB_PIPELINE_DEPTH`).
    blob_rtt_sum: u64,
    blob_rtt_count: u64,
    /// Kök arşiv anahtarı (ARK) — KİMLİĞE ait, `history_key`'in aksine
    /// cihaza değil (bkz. `set_archive_root_key`).
    archive_root_key: Option<[u8; 32]>,
    /// Skipped-message-key önbelleğini (bkz. ratchet.rs `skipped_keys`)
    /// diske şifreli kalıcılaştırmak için kullanılan anahtar. Node
    /// modundan BAĞIMSIZ olarak her zaman yüklenir (mesajlaşmanın
    /// güvenilirliği için gerekli — history_key'in aksine bu opsiyonel
    /// bir arşivleme değil). Kotlin `setSkippedKeyEncryptionKey` ile
    /// yükler.
    skipped_key_encryption_key: Option<[u8; 32]>,
    /// `initDatabase`'de Kotlin'den geçirilen `Context.filesDir` — dosya
    /// eklerinin (`attachments/`) diskte nereye yazılacağını bilmek için
    /// saklanır (DB yolu gibi diğer her şey zaten bu dizine göreli).
    app_files_dir: Option<String>,
    /// `device_fingerprint -> PeerId` — gossipsub topic bazlı "unicast"ın
    /// aksine, dosya parça transferi (`request_response`) bir hedef
    /// `PeerId` gerektirir. Bu harita, bir cihazdan gelen HERHANGİ bir
    /// paketten (IdentityExchange/Handshake/Message/GroupUpdate)
    /// öğrenilen gossipsub `message.source`'tan pasif olarak doldurulur
    /// (bkz. `record_peer_id_if_known`) — ayrı bir keşif adımı icat
    /// edilmez. Süreç yeniden başlarsa (yeni `PeerId` üretilir, bkz.
    /// `with_new_identity`) bu harita da doğal olarak sıfırlanır; bir
    /// dosya indirmesi başlatılmadan önce o cihazdan en az bir paket
    /// alınmış olmalı.
    device_to_peer_id: HashMap<String, PeerId>,
    /// The one call in progress (ringing or active) — see `call` module.
    call: Option<call::CallSession>,
    /// `(call_id, reason)` of the last call that ended, for the call screen.
    last_call_end: Option<(String, String)>,
    /// Last periodic media stats log line (ms).
    call_stats_logged_at: u64,
    /// Set while `call::send_call_signal` publishes: the envelope goes to the
    /// server AND the direct link. A "connected" peer can be a half-open link
    /// to a phone that just restarted; the direct copy then dies in a
    /// timeout and the ring never arrives (seen 2026-09-26).
    call_signal_sending: bool,
    /// Opens call media streams; set per swarm in `start_network`.
    stream_control: Option<libp2p_stream::Control>,
    /// `PeerId -> Multiaddr` — `ConnectionEstablished` olayından doldurulur,
    /// dosya indirmesi başlatılırken `swarm.add_peer_address` ile
    /// `request_response`'un dial edebileceği bir adres ipucu vermek için.
    peer_id_to_addr: HashMap<PeerId, Multiaddr>,
    /// bilinen bir uzak CİHAZ için en
    /// son işe yaramış/paylaşılmış adres (`/ip4/.../tcp/.../p2p/<peer_id>`
    /// tam biçimi). key = device_fingerprint. `peer_id_to_addr`'ın aksine
    /// bu KALICIDIR (bkz. `device_addrs` tablosu) ve süreç yeniden başlasa
    /// bile korunur — periyodik yeniden-bağlanma taraması (bkz.
    /// `reconnect_sweep`) bunu kullanarak, mDNS'in yetişemediği (farklı ağ)
    /// KOPMUŞ bir kişiye yeniden bağlanmayı dener. Eşleşme anında
    /// (rendezvous_node) ve her paket alındığında (o an bağlı olunan gerçek
    /// adres) güncellenir.
    device_last_addr: HashMap<String, String>,
    /// Spec dışı, ağ sağlamlığı düzeltmesi ("aynı LAN'da + Tor'la eşleşmiş
    /// birden fazla cihazdan biri mobil veriye geçince, aynı LAN'ı
    /// paylaştığı diğer cihazla artık mesajlaşamıyor, ama uzaktaki 'node'
    /// ile mesajlaşmaya devam edebiliyor" hatası): `device_last_addr` TEK
    /// bir "en son işe yarayan adres" tutar — iki cihaz HEM aynı LAN'da HEM
    /// Tor açıkken karşılıklı bağlandığında, mDNS/doğrudan LAN bağlantısı
    /// tipik olarak Tor devresinden önce/yerine kurulur (aynı TCP portu
    /// Tor açıkken bile normal biçimde 0.0.0.0'da dinliyor, bkz.
    /// `start_network`/`TOR_LIBP2P_PORT` notu) — bu YEREL adres
    /// `record_peer_id_if_known` ile `device_last_addr`'a yazılıp, eşleşme
    /// anında (varsa) bilinen `.onion` adresinin ÜZERİNE yazar. Bu LAN
    /// adresi, cihazlardan biri ağ değiştirince (ör. Wi-Fi→mobil veri)
    /// kalıcı olarak geçersiz kalır — ama Tor bağlantısı AĞ DEĞİŞİKLİĞİNDEN
    /// BAĞIMSIZ olması gerekirken, orijinal `.onion` adresi zaten
    /// üzerine yazılmış olduğundan `try_reconnect_device` bir daha ASLA
    /// denenmiyordu. Bu harita, bilinen bir `.onion` adresini `device_last_addr`'dan
    /// AYRI ve HİÇBİR ZAMAN LAN/doğrudan bir adres tarafından ÜZERİNE
    /// yazılmadan saklar (bkz. `remember_onion_addr`) — `try_reconnect_device`
    /// artık her yeniden bağlanma denemesinde İKİSİNİ DE (varsa) dener.
    device_onion_addr: HashMap<String, String>,
    /// `reconnect_sweep`'in en son çalıştığı an — bkz. `RECONNECT_SWEEP_INTERVAL_MS`.
    last_reconnect_sweep_at: u64,
    /// Last flush of `pending_envelopes` (`poll_events`): at most one a second.
    last_pending_flush_at: u64,
    /// Files `resume_incomplete_downloads_for` restarted in this process run.
    auto_resumed_downloads: std::collections::HashSet<String>,
    /// Çoklu-cihaz (spec 1.7): kardeş cihazlardan en son geçmiş geri-doldurma
    /// istediğimiz an — `SIBLING_BACKFILL_INTERVAL_MS`'den sık istemeyiz.
    last_sibling_backfill_at: u64,
    /// M-68, per sibling: (send time of the unanswered backfill request,
    /// send time of the last answered one). The second is the next watermark.
    sibling_backfill_since: HashMap<String, (u64, u64)>,
    /// last full `reconnect_all_known_now`; a network callback inside
    /// `NETWORK_CHANGE_DEBOUNCE_MS` only sets `network_change_pending`, run
    /// once by `poll_events` when the window ends.
    last_network_change_at: u64,
    network_change_pending: bool,
    /// bkz. `retry_unconfirmed_messages`.
    last_unconfirmed_retry_at: u64,
    /// Device -> when its last HistorySyncRequest was answered (rate limit).
    history_answered_at: HashMap<String, u64>,
    /// Device -> (window start, row bytes sent in HistorySyncResponses since).
    history_sent_bytes: HashMap<String, (u64, usize)>,
    /// Group `HistorySyncRequest` id -> members that already answered it (one
    /// answer each). Dropped with the request (`forget_history_request`).
    history_answered_by: HashMap<String, std::collections::HashSet<String>>,
    /// bkz. `SIBLING_ROSTER_SYNC_INTERVAL_MS`.
    last_sibling_roster_sync_at: u64,
    /// `reconnect_sweep`
    /// önceden HER taramada (≤15 sn'de bir), adresi olan ama bağlı OLMAYAN
    /// her cihaz için — hem doğrudan adrese hem de bilinen tüm röle
    /// adreslerine (üstüne, `dial_with_relay_fallback` bkz.) — sınırsız,
    /// geri çekilmesiz yeniden deniyordu. Kalıcı olarak ulaşılamaz bir
    /// kişi (uygulamayı kaldırmış, adresi tamamen değişmiş) bu yüzden
    /// SÜRESİZ olarak 15 saniyede bir (röle sayısı kadar ek dial'la
    /// birlikte) yeniden deneniyordu — gereksiz radyo uyanmaları/pil
    /// tüketimi ve ağ trafiği. key = device_fingerprint, value =
    /// (bir sonraki denemeye izin verilen an (ms), ardışık başarısız
    /// deneme sayısı). Sadece `reconnect_sweep`'in OTOMATİK/periyodik
    /// taramasını ve gönderim yolunu (`ensure_connected`, otomatik yeniden
    /// denemeler de oradan geçer) yavaşlatır. Opening a chat
    /// (`ensure_handshake`) and a network change ignore it.
    /// Bağlantı kurulduğunda (bkz. `reconnect_sweep` "zaten bağlı" kolu)
    /// ilgili girdi silinir — bir sonraki kopmada geri çekilme sıfırdan
    /// başlar.
    reconnect_backoff: HashMap<String, (u64, u32)>,
    /// Saver mode: the devices that were connected at the last network change
    /// (`reconnect_all_known_now`). Only these get the fast reconnect window.
    fast_reconnect_fps: std::collections::HashSet<String>,
    /// Spec dışı, kullanıcı isteği ("ilk ping başarısız olunca direkt
    /// reconnect denemek yerine 2sn aralıklarla 3 kere ping denesin önce",
    /// sonra pil sağlamlığı düzeltmesi — bkz. `KeepAliveState`/
    /// `KEEPALIVE_STABILIZE_MS`): her bağlı eş için keepalive durumu (bir
    /// sonraki gönderim zamanı, ardışık başarısızlık sayısı, bekleyen
    /// istek). `ConnectionEstablished`'da taze bir girdiyle başlar,
    /// `ConnectionClosed`'da silinir (bkz. `poll_events` ilgili kolları).
    /// Sadece `KEEPALIVE_FAILURES_BEFORE_DISCONNECT`. ardışık başarısızlıkta
    /// bağlantı kapatılıp yeniden bağlanılır — tek seferlik bir gecikmiş/
    /// kaybolmuş keepalive artık bağlantıyı KAPATMIYOR.
    keepalive_state: HashMap<PeerId, KeepAliveState>,
    /// `poll_events`'in SONUNDA yapılan "flush" turunda (bkz. o fonksiyonun
    /// sonundaki blok) swarm'dan çıkan ama artık işlenemeyecek olan olaylar —
    /// bir SONRAKİ turun başında, taze olayların ÖNÜNDE işlenirler.
    /// Neden var: swarm YALNIZCA `poll_events` içinde, o
    /// blokta pollanıyor. Bir parça yanıtı işlenip yeni bir istek
    /// `send_request` ile kuyruğa konduğunda, o istek tele ancak BİR SONRAKİ
    /// turda (≈1 sn sonra) çıkıyordu — yani her gidiş-dönüşe ~1 sn ekleniyor,
    /// boru hattı penceresi ne olursa olsun. Sonda kısa bir flush turu bunu
    /// kaldırıyor; o turda düşen olayları ATMAK ise (bir parça yanıtının
    /// kaybolması = takılma) kabul edilemez, bu yüzden burada saklanıyorlar.
    deferred_swarm_events: Vec<libp2p::swarm::SwarmEvent<P2PBehaviourEvent>>,
    /// bkz. `RATE_LIMIT_WINDOW_MS`
    /// dokümantasyonu. key = GERÇEK bağlantı kimliği (`PeerId` — Noise el
    /// sıkışmasıyla kanıtlanmış, sahtelenemez; paketin KENDİ içindeki
    /// `sender_device_fingerprint` header alanı KASITLI OLARAK
    /// kullanılmıyor, çünkü o alan bu noktada henüz doğrulanmamış — bir
    /// saldırgan başka birinin fingerprint'ini iddia edip o kişinin hız
    /// sınırı kotasını haksız yere tükettirebilirdi). value = (bu
    /// pencerenin başladığı an, pencere içinde şimdiye kadar sayılan paket).
    message_rate_limiter: HashMap<PeerId, (u64, u32)>,
    /// Same shape, for served file chunks (see the `FileChunks` request arm).
    chunk_rate_limiter: HashMap<PeerId, (u64, u32)>,
    /// (window start, count) for server-delivered mail (`source ==
    /// None`), which has no peer id to key `message_rate_limiter` on. Over
    /// the budget it waits in `deferred_incoming`; `server_fetch` and
    /// `commit_server_fetches` hold while it does.
    server_mail_rate: (u64, u32),
    /// one (window start, count) shared by all non-established peers.
    unknown_peer_rate: (u64, u32),
    /// Hız sınırı yüzünden bu turda işlenemeyen ama ATILMAMASI gereken
    /// paketler (bkz. `RateVerdict::Defer`). Bir sonraki `poll_events`
    /// turunda, yeni gelenlerden ÖNCE işlenir — böylece sıra korunur.
    deferred_incoming: std::collections::VecDeque<(Option<PeerId>, Vec<u8>)>,
    /// Spec dışı, hata düzeltmesi ("Tor üzerinden bağlı bir cihaz gruba
    /// davet edilmesine rağmen grubu hiç görmüyor"): `invite_to_group`/
    /// `remove_from_group`/`set_group_avatar`/`delete_group`'un fan-out
    /// döngüsü, `resolve_active_device_for_identity` bir üye için `None`
    /// dönerse (ör. o cihaz henüz "active" olarak kaydedilmemişse — Tor
    /// eşleşmesi/el sıkışması aynı-ağ/mDNS'e göre daha yavaş/rekabetli
    /// tamamlanabiliyor) bu `GroupUpdate`'i ÖNCEDEN sessizce kaybediyordu:
    /// ne log, ne yeniden deneme, fonksiyon yine de `Ok(())` dönüyordu.
    /// Artık gönderilemeyen her (group_id, identity_id) çifti için
    /// gönderilecek `GroupUpdate` burada saklanır; `group_sync_sweep` (bkz.
    /// `reconnect_sweep` AYNI periyodik desen) cihaz çözülebilir hale
    /// gelene kadar periyodik olarak yeniden dener. Bellek-içi (diğer
    /// yeniden deneme kuyrukları — `awaiting_confirmation`/`pending_envelopes`
    /// — ile AYNI kapsam), grup yerelde silinirse temizlenir (bkz.
    /// `remove_group_locally`).
    pending_group_syncs: HashMap<(String, String), GroupUpdate>,
    /// Spec dışı, hata düzeltmesi ("bir grup üyesi mesaj gönderemiyor/
    /// tutarsız çalışıyor"): `pending_group_syncs` yukarısı SADECE
    /// `GroupUpdate` (üyelik/isim/avatar) için bu sınıf hatayı çözdü —
    /// `send_group_message`/`edit_group_message`/`delete_group_message`'ın
    /// AYNI fan-out deseni (`resolve_active_device_for_identity` bir üye
    /// için `None` dönerse o üyenin kopyasını atlamak) hiç kapsanmamıştı:
    /// bir üyenin aktif cihazı henüz çözülemiyorsa (ör. bu süreç
    /// başladığından beri o üyeyle hiç IdentityExchange tamamlanmadı, veya
    /// üye kısa süreliğine "active" işaretinden düştü) o üyeye giden mesaj
    /// SESSİZCE kayboluyordu — ne hata, ne yeniden deneme, gönderen taraf
    /// bile bunu ASLA öğrenmiyordu (fonksiyon diğer üyelere en az bir
    /// kopya ulaştığı sürece `Ok(...)` dönüyordu). Bu, "grupta bir kişiyle
    /// mesajlaşma bazen hiç çalışmıyor" şikayetinin tam olarak eşleştiği
    /// belirtiydi — o kişiyle olan bağlantı/el sıkışma durumu ne zaman
    /// "henüz çözülmedi" durumuna denk gelirse mesaj kaybolurdu, DİĞER
    /// üyelerle (zaten çözülmüş) hiçbir sorun olmazdı.
    /// key = (group_id, member_identity_id), value = o üyeye gönderilmeyi
    /// bekleyen (henüz gönderilememiş) mesaj içerikleri, GÖNDERİM SIRASIYLA
    /// — üye çözülünceye kadar `group_sync_sweep` ile periyodik olarak
    /// (aynı ≤20 sn aralık) yeniden denenir. `pending_group_syncs`'in
    /// aksine bir Vec: birden fazla mesaj, aynı üye çözülmeden ÖNCE art
    /// arda gönderilebilir (ör. hızlı yazan biri), hepsi SIRAYLA
    /// korunmalı — sadece SONUNCUYU tutmak (GroupUpdate'teki gibi, orada
    /// yalnızca "en güncel durum" önemli) burada mesaj kaybına eş değer
    /// olurdu. `MAX_PENDING_GROUP_MESSAGES_PER_MEMBER` ile sınırlı (bellek
    /// koruması — bir üye günler/haftalarca hiç çözülemezse sınırsız
    /// birikmesin diye, en eskisi atılır).
    /// Spec dışı, hata düzeltmesi ("üye hiç çözülemezken süreç ölürse
    /// mesaj sessizce kayboluyor"): önceden bu alan SADECE bellekteydi —
    /// `pending_durable_retries`'in (tek bekleyen paket başına) AKSİNE
    /// hiçbir kalıcılığı yoktu. Artık her ekleme/kaldırma
    /// `pending_group_messages` SQL tablosuna da (bkz. `persist_pending_group_message`/
    /// `remove_persisted_pending_group_messages`) yansıyor, uygulama
    /// açılışında `load_pending_group_messages_from_db` ile geri yükleniyor
    /// — süreç öldürülüp yeniden başlasa bile bu kuyruk hayatta kalır.
    pending_group_messages: HashMap<(String, String), Vec<MessageContent>>,
    /// Group texts with a copy that was given up or cancelled: group-wide id
    /// -> the content and the devices that missed it. "Retry" on the bubble
    /// sends to these only (`retry_group_message_copies`).
    /// ponytail: memory only, like the red bubble itself; after a restart the
    /// record is gone. Add a table if the failed state has to survive.
    group_failed_copies: HashMap<String, (MessageContent, Vec<String>)>,
    /// Whiteboard strokes/erases not sent yet, by board — see `whiteboard`.
    wb_outbox: HashMap<String, whiteboard::WbOutbox>,
    /// (board, device) -> when a page from it was last answered with a digest.
    wb_reply_at: HashMap<(String, String), u64>,
    last_group_sync_sweep_at: u64,
    /// `first_contact_secrets` and the state it was computed from (see there).
    first_contact_cache: std::cell::RefCell<Option<(u64, Vec<Vec<u8>>)>>,
    /// The message `send_message_content_inner` is re-sending right now:
    /// `regen_pending_for_peer` triggered inside that send leaves it out, or
    /// it went out twice (once from the regen, once from the outer send).
    regen_skip_id: Option<String>,
    /// When `group_sync_sweep` reads the parked per-device copies again
    /// (`park_device_copies`); 0 = nothing parked since the last read.
    durable_reload_at: u64,
    /// `enforce_history_storage_limit`'in periyodik taramasının en son
    /// çalıştığı an — bkz. `HISTORY_STORAGE_SWEEP_INTERVAL_MS`.
    last_storage_sweep_at: u64,
    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): röle protokolünü desteklediği `identify` ile
    /// doğrulanmış VE doğrudan erişilebilir (bkz. `dial_with_relay_fallback`)
    /// bilinen peer'lar. QR paketinde paylaşılır (bkz. `QrPacket.known_relays`)
    /// ve `identify::Event::Received`'dan organik olarak büyür — sabit bir
    /// bootstrap listesi hiç var olmadı, bu da spec §4.1'in hiç implemente
    /// edilmemiş "~10 node adresi paylaşımı" fikrinin röle'ye özelleşmiş
    /// hâli. En fazla `MAX_KNOWN_RELAYS` kadar tutulur.
    /// value = (tam multiaddr, en son görülme/yenilenme anı ms) — ikinci
    /// alan LRU tahliyesi için (bkz. `record_known_relay`: önceden dolu
    /// haritadan RASTGELE bir girdi atılıyordu — HashMap iterasyon sırası
    /// keyfidir — yani çalışan tek röle atılıp ölü olanlar tutulabiliyordu).
    known_relay_peers: HashMap<PeerId, (Multiaddr, u64)>,
    /// Ağ değişiminden sonraki bu ana kadar `reconnect_sweep` hızlı modda
    /// (bkz. `FAST_RECONNECT_INTERVAL_MS`).
    fast_reconnect_until: u64,
    /// bkz. `ensure_relay_reservations` — röle başına açtığımız
    /// `/p2p-circuit` dinleyicisi ve son deneme anı (ms).
    relay_listeners: HashMap<PeerId, (libp2p::core::transport::ListenerId, u64)>,
    /// Bir eşe açılmış FAZLADAN bağlantıların kimlikleri (ilki hariç) —
    /// bkz. `BULK_PARALLEL_CONNECTIONS`. Aktarım bitince tam olarak bunlar
    /// kapatılır; `disconnect_peer_id` hepsini kapatacağı için kullanılamaz.
    extra_conns: HashMap<PeerId, Vec<libp2p::swarm::ConnectionId>>,
    /// Dials opened for a bulk transfer, by connection id. Only these become
    /// `extra_conns`: a reconnect dial after a network change is ALSO a second
    /// outbound connection, and closing it as "extra" kept the dead one alive.
    bulk_dials: HashMap<libp2p::swarm::ConnectionId, PeerId>,
    /// Eş başına açık bağlantılar — bkz. `mark_connection_suspect`: şüpheli
    /// bir eşe yeni bağlantı kurulunca eskileri kapatmak için.
    peer_conns: HashMap<PeerId, Vec<libp2p::swarm::ConnectionId>>,
    /// Path quality of each open connection (`conn_path_rank`): used to keep
    /// the better one when a second connection to the same peer comes up.
    conn_rank: HashMap<libp2p::swarm::ConnectionId, u8>,
    /// Inbound connections (peer, established ms) not yet seen to belong to a
    /// known peer — see `sweep_unknown_inbound`.
    unknown_inbound: HashMap<libp2p::swarm::ConnectionId, (PeerId, u64)>,
    /// Consecutive server RPC timeouts per server peer. The server connection has
    /// no keepalive, so after a network switch a silently dead Tor circuit stayed
    /// "connected": every deposit waited 30 s to fail and the sweep never redialed.
    server_rpc_timeouts: HashMap<PeerId, u32>,
    /// Envelopes sent over `ENVELOPE_PROTOCOL`, until the peer answers.
    /// (target device, envelope, first attempt, already retried once)
    envelopes_inflight: HashMap<request_response::OutboundRequestId, (String, NetworkEnvelope, u64, bool)>,
    /// Our onion address as announced to identify (`add_external_address`).
    advertised_onion: Option<String>,
    /// Persisted sessions are loaded (see `initiate_handshake_with`).
    ratchets_loaded: bool,
    /// Onion addresses peers announced over identify, by PeerId. Applied to
    /// `device_onion_addr` once the PeerId is tied to a device.
    peer_onion_addr: HashMap<PeerId, String>,
    /// Eş başına paralel-aktarım sağlık durumu — bkz. `BulkHealth`.
    bulk_health: HashMap<PeerId, BulkHealth>,
    /// `initiate_handshake_with`'in
    /// bir peer için en son kullanıcıya BİLDİRİLMİŞ kalıcı hatası (ör.
    /// "Bad Kyber public key length" — bozuk/uyumsuz anahtar verisi).
    /// Aynı hata tekrar tekrar (her mesaj/typing-indicator/vb. denemesinde)
    /// sessizce oluşmaya devam etse bile kullanıcıya SADECE bir kez
    /// bildirilsin diye — bkz. o fonksiyonun dokümantasyonu.
    handshake_failure_notified: HashMap<String, String>,
    /// bir peer için en son NE ZAMAN
    /// el sıkışma tazelendiği (bkz. `maybe_redo_handshake`) — kaybolmuş bir
    /// `HandshakeInit`'ten kurtulmak için gereken tek şey yeni bir el
    /// sıkışma, ama bunu her turda yapmak oturumu gereksizce çalkalar; bu
    /// harita `HANDSHAKE_REDO_MIN_INTERVAL_MS` kısıtını uygular.
    /// Değerin ikinci alanı: BİR ÖNCEKİ tazelemede terk edilmiş kök anahtar.
    /// `initiate_handshake_with` yeni topic'e abone olurken eskisini
    /// BIRAKMAZ (kasıtlı — karşı taraf yeni el sıkışmayı işleyene kadar
    /// hâlâ eski topic'ten yayın yapıyor olabilir). Tekrarlanabilen bir
    /// tazelemede bu abonelikler birikirdi; `maybe_rotate_ratchet`'teki AYNI
    /// "bir nesil gecikmeli bırak" deseniyle, bir önceki neslin topic'i
    /// ancak bir sonraki tazelemede bırakılır.
    last_handshake_redo: HashMap<String, (u64, Option<Vec<u8>>)>,
    /// Per device: (first failure in the current streak, count). See `note_undecryptable`.
    undecryptable_from: HashMap<String, (u64, u32)>,
    /// Gönderdiğimiz `HistorySyncRequest` id'leri → (1:1 hedef kimlik, grup,
    /// gönderim anı). `HistorySyncResponse` yalnızca bunlardan birine
    /// aitse işlenir: aksi halde herhangi bir kişi istenmemiş bir "yanıtla"
    /// arşive sahte mesaj yazabilir ya da `request_id` üzerinden başka bir
    /// mesajımızın yeniden denemesini iptal edebilirdi.
    /// The fourth field is the request's window `(before, after)`: `Some`
    /// only for a user's "Fetch older history" press, the one answer that
    /// may bring back rows below the history floor, and only inside it.
    outstanding_history_requests: HashMap<String, (Option<String>, Option<String>, u64, Option<(i64, i64)>)>,
    /// Open "Fetch older history" requests to own devices: (sibling device,
    /// before, after) -> (chat: identity id or group id, sent at). The
    /// answer echoes its window; a match is a user fetch and is consumed.
    sibling_fetch_open: HashMap<(String, i64, i64), (String, u64)>,
    /// Chat -> follow-up pages its presses may still ask for
    /// (`HISTORY_FETCH_MAX_PAGES`).
    history_fetch_pages: HashMap<String, u32>,
    /// Kullanıcı kararı (2026-08-27): ENGELLENEN kimlikler.
    /// `revoke`'tan farkı kasıtlı ve keskin: iptal, bir cihazın artık
    /// kullanılmadığını söyler ve o kişi yeni bir cihazla geri gelebilir.
    /// Engelleme ise KİŞİYİ hedefler — o kimliğe ait HİÇBİR cihazdan paket
    /// kabul edilmez, hiçbirine bağlanılmaya çalışılmaz, "yeni cihaz"
    /// uyarısı bile üretilmez (aksi halde engellenen biri uyarı yağdırarak
    /// rahatsız edebilirdi). Tek çıkış yolu YÜZ YÜZE yeniden eşleşme:
    /// engelli listesinden çıkmak yalnızca karekod/manuel kod okutmakla
    /// mümkün, uzaktan gelen hiçbir paket bunu yapamaz.
    blocked_identities: std::collections::HashSet<String>,
    /// `AccountDeleted` gönderen kimlikler: bunlara artık mesaj gönderilmez.
    deleted_identities: std::collections::HashSet<String>,
    /// Pil düzeltmesi (2026-08-28): uygulama arka planda ve ekran kapalıyken
    /// Kotlin tarafı bunu açıyor (bkz. `set_power_save`). Etkisi: kanıtlanmış
    /// şekilde sağlıklı bir bağlantının keepalive aralığı 20 sn'den
    /// `KEEPALIVE_POWER_SAVE_INTERVAL_MS`'e genişliyor.
    /// Neden bu kadar önemli: hücresel radyo herhangi bir aktiviteden sonra
    /// tipik olarak 5-15 sn yüksek güçlü durumda kalıyor. 20 saniyede bir
    /// yoklama, radyonun neredeyse HİÇ boşta kalamaması demek — bağlı her
    /// eş için ayrı ayrı. Ekran kapalıyken bunu 60 saniyeye çekmek,
    /// canlılık tespitini kaybetmeden radyoya uzun uyku pencereleri açıyor.
    power_save: bool,
    /// Active network is metered (Kotlin `setMeteredNetwork`). With
    /// `power_save` this is radio-saver mode, see `RADIO_WINDOW_MS`.
    metered: bool,
    /// Next radio-saver window (ms); `radio_window_open` is this poll turn's
    /// verdict, read by the sweeps.
    radio_window_at: u64,
    radio_window_open: bool,
    /// Last `TorHandle::set_dormant` value, see `RADIO_AWAKE_MS`.
    tor_dormant: bool,
    /// Next full Tor wake in radio-saver mode (ms), see `TOR_FULL_WAKE_MS`.
    tor_wake_at: u64,
    /// When power save was last left (ms); the links are re-verified from
    /// then on, see `own_connection_status` "syncing".
    resync_since: u64,
    /// Devam eden indirmeler: key = file_id (bkz. `DownloadState`).
    active_downloads: HashMap<String, DownloadState>,
    /// `request_response::send_request`'in döndürdüğü `OutboundRequestId`'yi
    /// hangi dosyanın indirmesine ait olduğuna eşler — gelen
    /// `Message::Response` olayını doğru `DownloadState`'e yönlendirmek
    /// için (bkz. poll_events `FileChunks` kolu).
    /// İstek kimliği -> (file_id, parça indeksi). İndeks ARTIK gerekli:
    /// boru hattında aynı anda birden çok parça havada, dolayısıyla gelen
    /// yanıtın hangi parça olduğu `next_chunk_index`'ten çıkarılamaz.
    download_request_ids: HashMap<request_response::OutboundRequestId, (String, u32)>,
    /// `poll_events`'in senkron döndürdüğü `Vec<String>`'e eklenecek,
    /// `poll_events`'in kendi gövdesi DIŞINDAKİ yerlerden (ör. dosya eki
    /// `file_progress`/`file_complete`/`file_failed` olayları VE artık
    /// `retry_unconfirmed_messages`'ın azami yaş aşımında ürettiği
    /// "status":"error" olayı) üretilen olaylar — isim tarihsel olarak
    /// "attachment" ama artık genel bir "ertelenmiş olay" kuyruğu. Dosya
    /// eki olayları özelinde: `FileChunks` ağ olayları `poll_events`
    /// içindeki `RUNTIME.block_on` bloğunda üretildiği için, o bloğun
    /// DIŞINDAKİ `results` vektörüne doğrudan erişemiyor; burada
    /// biriktirilip döngü sonunda `results`'a taşınır (bkz.
    /// `pending_envelopes`'in retry kuyruğuyla aynı desen).
    attachment_events: Vec<String>,
    /// (PeerId of a just-revoked own device, mono_ms to disconnect it).
    revoked_disconnects: Vec<(PeerId, u64)>,
    /// Spec dışı, kullanıcı tarafından istenen güvenilir teslim: key =
    /// gönderilen paketin KENDİ `message_id`'si (Text/Edit/Delete/
    /// HistorySyncRequest paketleri). Karşı taraftan onay (Ack veya
    /// HistorySyncResponse) gelene kadar `poll_events` bu map'teki her
    /// girdiyi periyodik olarak yeniden yayınlar (bkz.
    /// `ACK_RETRY_INITIAL_MS`/`ACK_RETRY_MAX_MS`). `gossipsub.publish()`
    /// başarısı yerel bir garanti olduğundan (bkz. dosya başı not, eski
    /// `pending_envelopes`'in neden yetersiz kaldığı), bu, uygulamanın TEK
    /// gerçek uçtan uca teslim garantisi katmanıdır.
    awaiting_confirmation: HashMap<String, PendingConfirmation>,
}

