//! Typoon — Rust çekirdeği.
//!
//! Description.md "Aşama A" kapsamını hedefler: tek cihaz (1 Identity = 1
//! Device) varsayımıyla test edilir, ama Identity/Device ayrımına göre
//! yazılmıştır (Aşama B'de çoklu cihaza genişletilebilir).
//!
//! Modüller:
//! - `identity`  : bölüm 1 — Identity/Device modeli, fingerprint
//! - `packet`    : bölüm 1.3-1.6, 3.3, 5.2 — ağ paket formatları
//! - `ratchet`   : bölüm 3 — hibrit KEM + Double Ratchet
//! - `contact`   : bölüm 2 — TOFU + güvenlik numarası değişikliği
//! - `group`     : bölüm 5 — pairwise grup mesajlaşma

mod identity;
mod packet;
mod ratchet;
mod contact;
mod group;
mod attachments;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use android_logger::Config as LogConfig;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::FutureExt as _;
use futures::StreamExt as _;
use hex;
use hkdf::Hkdf;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jobjectArray, jstring};
use jni::JNIEnv;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol as MultiaddrProtocol;
use libp2p::request_response;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, dcutr, gossipsub, identify, kad, noise, relay, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use log::{error, info};
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
use group::{apply_change, validate_group_update, Group, GroupChange};
use identity::{compute_fingerprint, DeviceStatus};
use packet::{
    GroupUpdate, HandshakeInit, IdentityExchange, MessageContent, MessagePacket, MessagePacketHeader,
    NetworkEnvelope, QrPacket,
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
    static ref RUNTIME: Runtime = tokio::runtime::Runtime::new().unwrap();
    static ref CORE: Arc<Mutex<P2PCore>> = Arc::new(Mutex::new(P2PCore::new()));
}

/// Her JNI export'u `CORE.lock()` alır — bunu DOĞRUDAN `.unwrap()` etmek
/// (önceki hâli) ciddi bir kırılganlık taşıyordu: `std::sync::Mutex`,
/// kilit TUTULURKEN bir panik olursa kalıcı olarak "poisoned" (zehirli)
/// hâle gelir; `catch_panic` (bkz. dosya sonu, JNI Bindings bölümü) TEK
/// bir JNI çağrısını izbadılasa da, kilidin kendisi zehirlendiğinde
/// SONRAKİ HER `core_lock()` çağrısı (yani gerçekte HER JNI
/// export'u — pollNetwork dahil) ANINDA panikler. Sonuç: TEK bir yerde
/// (ör. bu oturumda eklenen geniş yeni kod yüzeyinden herhangi biri)
/// oluşan TEK bir panik, süreç yeniden başlatılana kadar UYGULAMANIN TÜM
/// ağ/mesajlaşma işlevselliğini SESSİZCE (kullanıcıya hiçbir hata
/// göstermeden — pollNetwork boş sonuç döner, "her şey normal görünür
/// ama hiçbir şey ASLA ilerlemez") kalıcı olarak durdurabilirdi. Bu,
/// "indirme 0B'de sonsuza kadar takılı kalıyor, hiç hata görünmüyor"
/// gibi tam olarak bu türden bir arızayla eşleşen bir belirti üretir.
/// `unwrap_or_else(|poisoned| poisoned.into_inner())` ile zehirlenmeyi
/// YOKSAYIP alttaki veriyi olduğu gibi geri alıyoruz — `catch_panic`
/// zaten her çağrıyı izbadıladığı için, TEK bir başarısız işlemin
/// yarım kalmış bir durum bırakma riski (kabul edilebilir, nadir bir
/// tutarsızlık) her şeyin kalıcı olarak kilitlenmesinden çok daha iyi.
fn core_lock() -> std::sync::MutexGuard<'static, P2PCore> {
    CORE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// --- libp2p birleşik davranış ---
//
// Spec bölüm 4.2: DHT (Kademlia) keşif için. Identify protokolü, Kademlia'nın
// bağlanan peer'ların dinleme adreslerini öğrenip routing tablosuna
// ekleyebilmesi için ZORUNLUDUR (bkz. docs.rs/libp2p/kad: "the Identify
// protocol must be manually hooked up to Kademlia"). Gossipsub, mesaj/
// handshake paketlerinin taşınması için (bölüm 3.3 son not: "Node/relay bu
// paketi kör taşır").
#[derive(NetworkBehaviour)]
struct P2PBehaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    /// Dosya eki parça transferi — gossipsub'un aksine, bir hedef `PeerId`'ye
    /// doğrudan istek/yanıt (RPC benzeri) gönderir. 4GB'a kadar bir dosyayı
    /// gossipsub üzerinden (küçük/sık mesajlar için tasarlanmış bir pub/sub
    /// ağı) taşımak pratik değil — bkz. attachments.rs modül notu.
    file_chunks: request_response::cbor::Behaviour<FileChunkRequest, FileChunkResponse>,
    /// KRİTİK: aynı yerel ağdaki (Wi-Fi) kişileri OTOMATİK yeniden keşfeder
    /// — bkz. dosya sonu "yeniden bağlanma" notu. Önceden bir peer'i
    /// yeniden bulmanın TEK yolu QR/manuel kodu tekrar okutmaktı (o kodun
    /// içindeki `rendezvous_node` adresi tek seferlik bir dial ipucuydu,
    /// hiçbir yerde kalıcı/yeniden keşfedilebilir tutulmuyordu) — bu da
    /// "her tam kapat/aç sonrası tekrar QR okutman gerekiyor" şikayetinin
    /// KÖK sebebiydi (PeerId de her süreç başlangıcında rastgele yeniden
    /// üretiliyordu, bkz. `start_network`'teki kalıcı keypair notu). mDNS,
    /// AYNI yerel ağdaki iki cihazın (tipik ev/ofis Wi-Fi'ı) hiçbir
    /// kullanıcı eylemi olmadan birbirini bulmasını sağlar. WAN (farklı
    /// ağlardaki) yeniden keşif KAPSAM DIŞI bırakıldı — bunun için DHT
    /// tabanlı (spec bölüm 4.2 `DHT_Entry`) bir kayıt/sorgu mekanizması
    /// gerekir, bu oturumun kapsamının ötesinde bir genişleme.
    mdns: libp2p::mdns::tokio::Behaviour,
    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): bu cihazın kendisini, doğrudan dial
    /// edilemeyen (farklı ağ/NAT arkasındaki) peer'lara ULAŞMAK için bir
    /// röle kullanabilmesini sağlar — her cihazda her zaman açık.
    relay_client: relay::client::Behaviour,
    /// Bu cihazın BAŞKALARI için röle GÖREVİ görüp göremeyeceği. Her zaman
    /// derlemeye dahil (libp2p, canlı bir Swarm'da NetworkBehaviour'ları
    /// değiştirmeyi desteklemiyor) ama kapasitesi `start_network`'e geçilen
    /// `node_mode`'a göre ayarlanıyor — Node modu kapalıyken
    /// `max_reservations`/`max_circuits` sıfırlanıyor, yani pratikte hiçbir
    /// isteği kabul etmiyor (bkz. `start_network`). Spec §4.3'ün "Node
    /// modu... isteğe bağlı Circuit Relay v2 hizmeti" ifadesinin gerçek
    /// karşılığı bu alan — önceden hiç implemente edilmemişti.
    relay: relay::Behaviour,
    /// Röle üzerinden kurulan bir bağlantıyı, mümkünse doğrudan bir
    /// bağlantıya yükseltmeye (hole punching) çalışır — başarısız olursa
    /// (ör. simetrik NAT) trafik röle üzerinden akmaya devam eder.
    dcutr: dcutr::Behaviour,
    /// Bu cihazın dışarıdan doğrudan erişilebilir olup olmadığını tespit
    /// eder — şu an sadece bilgi amaçlı (identify/kad'ı besliyor), aktif
    /// bir karar noktası değil.
    autonat: autonat::Behaviour,
    /// Spec dışı, kullanıcı isteği (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): SUNUCUSUZ bir farklı-ağ eşleşme çözümü — ev
    /// router'ının UPnP IGD protokolünü destekleyip desteklemediğini
    /// otomatik dener, destekliyorsa router'dan "şu portu bana yönlendir"
    /// isteğinde bulunur ve gerçekten dışarıdan çevrilebilir bir adres
    /// öğrenir (bkz. `own_external_addr`). Router paneline hiç girmeye,
    /// DDNS/statik IP/VPS'e gerek YOK — ama her router'da açık değildir ve
    /// CGNAT (çoğu mobil veri/bazı ISS'ler) arkasında hiç işe yaramaz —
    /// bu durumlarda sessizce başarısız olur, mevcut davranış (LAN/röle)
    /// değişmeden devam eder.
    upnp: libp2p::upnp::tokio::Behaviour,
}

fn current_time_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

// --- Yerel cihazın secret key'leri (asla ağa/DB'ye çıplak yazılmaz;
// export_recovery yolu hariç, o da şifreli) ---
struct DeviceKeys {
    sign_sk_ed25519: SigningKey,
    #[allow(dead_code)]
    sign_pk_ed25519: VerifyingKey,
    sign_pk_mldsa: MlDsaVerifyingKey<MlDsa87>,
    sign_sk_mldsa: MlDsaSigningKey<MlDsa87>,
    kem_sk_x25519: StaticSecret,
    #[allow(dead_code)]
    kem_pk_x25519: X25519PublicKey,
    kem_pk_mlkem: MlKem1024EncapsulationKey,
    kem_sk_mlkem: MlKem1024DecapsulationKey,
}

/// Bir cihazın tüm secret key'lerini taşıyan, JNI sınırı üzerinden
/// Kotlin'e/Kotlin'den geçirilen paket. Rust bu bloğu ASLA diske yazmaz —
/// diske yazma/okuma sorumluluğu tamamen Kotlin tarafındadır
/// (KeystoreCrypto ile şifrelenip ayrı bir tabloya/dosyaya konur). Bu,
/// "Rust master şifreleme anahtarını hiç görmesin" ilkesini sağlar: Rust
/// sadece plaintext key üretir/tüketir, şifreleme/diske yazma Kotlin'in
/// işidir.
// Spec dışı, güvenlik denetimi düzeltmesi: `Debug` KASITLI OLARAK derive
// edilmiyor — bu struct dört ham secret key baytını taşıyor, `Debug`
// olsaydı ileride biri yanlışlıkla `error!("{:?}", bundle)` gibi bir satır
// eklerse uzun-vadeli kimlik anahtarları düz metin olarak Android logcat'e
// yazılabilirdi. Ayrıca `Drop` ile bellekten çıkarken sıfırlanıyor (bkz.
// Cargo.toml "zeroize" feature notu — tipli `DeviceKeys`/`DeviceRatchetState`
// için bu upstream crate'lerin kendi `ZeroizeOnDrop`'u hallediyor, ama bu
// struct ham `Vec<u8>` kullandığından elle yapılması gerekiyor).
#[derive(Clone, Serialize, Deserialize)]
struct SecretKeyBundle {
    device_fingerprint: String,
    sign_sk_ed25519: Vec<u8>,
    sign_sk_mldsa: Vec<u8>,
    kem_sk_x25519: Vec<u8>,
    kem_sk_mlkem: Vec<u8>,
}

impl Drop for SecretKeyBundle {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.sign_sk_ed25519.zeroize();
        self.sign_sk_mldsa.zeroize();
        self.kem_sk_x25519.zeroize();
        self.kem_sk_mlkem.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceRecord {
    device_fingerprint: String,
    identity_id: String,
    sign_pubkey_ed25519: Vec<u8>,
    sign_pubkey_mldsa: Vec<u8>,
    kem_pubkey_x25519: Vec<u8>,
    kem_pubkey_mlkem: Vec<u8>,
    device_name: String,
    is_active: bool,
    last_seen: u64,
}

/// Bir bağlantı kurulurken tespit edilen "cihaz değişikliği" durumunun
/// Kotlin tarafına iletilecek özeti (spec 2.2 uyarı ekranı).
#[derive(Debug, Clone, Serialize)]
pub struct DeviceAlertInfo {
    pub contact_display_name: String,
    pub identity_id: String,
    pub new_device_fingerprint: String,
    pub known_device_short_codes: Vec<String>,
    pub new_device_short_code: String,
}

/// UI'nin kişi seçici listesi için kullandığı özet.
#[derive(Debug, Clone, Serialize)]
pub struct ContactSummary {
    pub contact_id: String,
    pub display_name: String,
    pub identity_id: String,
    /// None ise: henüz IdentityExchange tamamlanmamış, mesaj gönderilemez.
    pub active_device_fingerprint: Option<String>,
    /// Spec dışı: bu kişinin bize gönderdiği profil fotoğrafı (varsa),
    /// `list_attachments`'taki `preview_hex` ile AYNI hex-encode deseni —
    /// JSON ham ikili taşıyamadığı için.
    pub avatar_hex: Option<String>,
}

/// Yerel şifreli arşivden çözülüp Kotlin'e döndürülen tek bir mesaj.
#[derive(Debug, Clone, Serialize)]
pub struct ArchivedMessage {
    pub direction: String, // "sent" | "received"
    pub text: String,
    pub timestamp: u64,
}

/// Groups tab GUI'sinin liste/detay göstermesi için özet (spec dışı —
/// `list_groups` yoktu, Groups tab'ı hiçbir zaman gerçek grup listesi
/// göstermiyordu).
#[derive(Debug, Clone, Serialize)]
pub struct GroupSummary {
    pub group_id: String,
    pub name: String,
    pub founder_identity_id: String,
    pub is_founder: bool,
    pub member_identity_ids: Vec<String>,
    /// bkz. `ContactSummary.avatar_hex` aynı hex-encode deseni.
    pub avatar_hex: Option<String>,
}

/// Kotlin'e döndürülen, bir sohbetteki dosya eklerinin listesi (bkz.
/// `list_attachments` JNI export).
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentSummary {
    pub file_id: String,
    pub file_name: String,
    pub mime_type: String,
    pub total_size: u64,
    pub direction: String, // "sent" | "received"
    pub status: String,    // "offered" | "downloading" | "complete" | "failed"
    pub bytes_transferred: u64,
    pub created_at: u64,
    /// `file_offer` poll olayındaki "preview_hex" ile AYNI biçim — Kotlin
    /// tarafı geçmişi yeniden kurarken küçük resmi hemen gösterebilsin diye
    /// (indirme beklemeden), bkz. `SimpleChatAdapter.AttachmentInfo`.
    pub preview_hex: Option<String>,
    /// Sesli mesajlar için çalma süresi (milisaniye) — bkz.
    /// `MessageContent::FileOffer.duration_ms`.
    pub duration_ms: Option<u32>,
}

/// Devam eden bir indirmenin bellek-içi durumu (bkz. `download_file`/
/// `request_next_chunk`/attachments.rs modül notu — parçalar HER ZAMAN
/// sırayla (0, 1, 2, ...) istenir, bu yüzden `.enc` dosyasına sadece
/// EKLEME (append) yapılır, seek gerekmez).
struct DownloadState {
    peer_id: PeerId,
    /// Bkz. `P2PCore::peer_for_file` — `file_progress`/`file_complete`/
    /// `file_failed` olaylarının `"peer"` alanını doldurmak için gerekli
    /// (bkz. o alanın eklenmesine yol açan hata: ChatActivity'nin olay
    /// dinleyicisi `"peer"` eşleşmezse olayı SESSİZCE YOK SAYIYOR —
    /// bu alan hiç doldurulmadığı için indirme Rust tarafında tamamen
    /// başarıyla bitse bile UI hiçbir zaman haberdar olmuyordu).
    peer_device_fingerprint: String,
    total_size: u64,
    total_chunks: u32,
    next_chunk_index: u32,
    bytes_done: u64,
    file_key: [u8; 32],
    enc_path: std::path::PathBuf,
    /// Son parçanın alındığı an (hiç parça gelmediyse indirmenin
    /// başladığı an) — bkz. `DOWNLOAD_STALL_TIMEOUT_MS` ve
    /// `check_stalled_downloads`. Bu, TCP dial'ın hiç sonuçlanmadığı
    /// (ne başarı ne açık bir hata — özellikle iki cihaz da NAT arkasında
    /// olduğunda tipik bir durum) senaryoda `request_response`'un KENDİ
    /// hiçbir olay üretmediği durumları yakalamak için gerekli — o
    /// durumda libp2p katmanından ne bir yanıt ne de bir
    /// OutboundFailure/timeout hiç gelmez, indirme aksi hâlde SÜRESİZ
    /// "İndiriliyor" durumunda kalırdı.
    last_progress_at: u64,
}

/// `poll_events`'in `RUNTIME.block_on` bloğu İÇİNDE (swarm borrow'u altında)
/// toplanıp, blok BİTTİKTEN SONRA (self'e serbestçe erişilebilecekken)
/// işlenen dosya-parça olayları — `incoming`/`new_listen_addrs`'in zaten
/// kullandığı "önce topla, sonra işle" deseninin aynısı (bkz. poll_events).
enum FileChunkEventLocal {
    Request { request: FileChunkRequest, channel: request_response::ResponseChannel<FileChunkResponse> },
    Response { request_id: request_response::OutboundRequestId, response: FileChunkResponse },
    OutboundFailure { request_id: request_response::OutboundRequestId },
}

/// Bir gönderilen mesajın ("bizim" mesajımızın) UI'da gösterilecek durumu —
/// spec dışı, kullanıcının istediği gönderim/hata ikonları için.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageSendStatus {
    /// `publish_envelope` henüz başarılı olmadı — `pending_envelopes`'te
    /// bekliyor, `poll_events` yeniden deniyor.
    Pending,
    /// gossipsub publish() başarıyla tamamlandı (bu, karşı tarafın FİİLEN
    /// aldığının garantisi DEĞİLDİR — sadece yerel düğümün mesajı ağa
    /// yayınladığının garantisidir; spec bir teslim onayı/ACK tanımlamıyor).
    Sent,
    /// `PENDING_ENVELOPE_TIMEOUT_MS` boyunca gönderilemedi, vazgeçildi.
    Failed,
}

impl MessageSendStatus {
    fn as_str(self) -> &'static str {
        match self {
            MessageSendStatus::Pending => "pending",
            MessageSendStatus::Sent => "sent",
            MessageSendStatus::Failed => "error",
        }
    }
}

/// Bir zarfın `pending_envelopes`'te ne kadar süre bekleyebileceği — bu
/// süre dolunca kalıcı olarak "Failed" sayılır (bkz. `MessageSendStatus`).
/// SADECE `awaiting_confirmation` kapsamına GİRMEYEN zarf türleri
/// (Handshake, IdentityExchange, GroupUpdate, Ack, HistorySyncResponse,
/// FileOffer) bu sınırlı kuyruğu kullanır — Text/Edit/Delete/
/// HistorySyncRequest artık aşağıdaki `awaiting_confirmation` mekanizması
/// üzerinden SÜRESİZ (karşı taraf onaylayana kadar) yeniden denenir.
const PENDING_ENVELOPE_TIMEOUT_MS: u64 = 20_000;

/// `known_relay_peers` üst sınırı — spec §4.1'in önerdiği "~10, en son
/// görülen/en güvenilir" ölçeğiyle aynı (bkz. o alanın dokümantasyonu).
const MAX_KNOWN_RELAYS: usize = 10;

/// Spec dışı, ağ sağlamlığı düzeltmesi: `reconnect_sweep` bu aralıkta bir
/// çalışır (kendini iyileştiren yeniden-bağlanma). `poll_events` zaten
/// saniyede bir Kotlin tarafından çağrıldığından ayrı bir zamanlayıcıya
/// gerek yok — sadece bu aralık dolduğunda tarama yapılır. 15 sn: kopmuş
/// bir kişiye makul hızda yeniden bağlanır ama gereksiz dial trafiği
/// üretmez.
const RECONNECT_SWEEP_INTERVAL_MS: u64 = 15_000;

/// Spec dışı, güvenlik denetimi düzeltmesi: bir `HandshakeInit`'in
/// `timestamp`'i, o an ile bu kadar milisaniyeden fazla sapıyorsa (ileri
/// VEYA geri) reddedilir — çok eski yakalanmış el sıkışmaların tekrar
/// oynatılmasını engellerken, cihazlar arası makul saat kaymasına (clock
/// skew) tolerans gösterir. 10 dakika: iki telefonun saatleri arasında
/// gerçek dünyada beklenenden bol bir pencere, ama sınırsız değil.
const HANDSHAKE_MAX_SKEW_MS: u64 = 10 * 60 * 1000;

/// Spec dışı, kullanıcı isteği (bkz. SECURITY.md "Cross-network
/// connectivity" notu): manuel röle adresi girişi hâlâ Ayarlar'da mevcut
/// ve kaldırılmadı, ama sıfırdan hiç ortak röle geçmişi olmayan iki
/// YABANCI'nın (ör. farklı ağlardaki iki yeni kullanıcı) hiçbir elle
/// yapılandırma OLMADAN eşleşebilmesi için burada, uygulamaya GÖMÜLÜ
/// varsayılan bir bootstrap röle listesi tutuluyor — tıpkı IPFS/BitTorrent
/// istemcilerinin gömülü varsayılan bootstrap node'ları gibi. `start_network`
/// içinde, her biri Ayarlar'daki manuel ekleme ile AYNI fonksiyon
/// (`add_known_relay_address`) ile eklenir.
///
/// KURULUM NOTU: bu liste kasıtlı olarak BOŞ başlıyor — buraya rastgele/
/// var olmayan bir adres koymak sessizce başarısız dial denemelerine yol
/// açar. Kendi (veya güvendiğiniz birinin) Node modu açık, herkese açık bir
/// IP'de çalışan bir Typoon kopyasını kurduktan sonra, o cihazın
/// `getNodeAddress()`'inin döndürdüğü tam adresi (ör.
/// "/ip4/1.2.3.4/tcp/4001/p2p/12D3Koo...") buraya bir dize olarak ekleyin.
/// Yeniden derleme gerektirir — kullanıcılar yine de Ayarlar'dan kendi
/// bildikleri ek röleleri manuel olarak eklemeye devam edebilir, bu liste
/// onun YERİNE değil, İLK KURULUMDA hiç adres bilmeyen biri için bir
/// başlangıç noktası.
const DEFAULT_BOOTSTRAP_RELAYS: &[&str] = &[
    // "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWExampleReplaceWithRealAddress",
];

/// Spec dışı, kullanıcı tarafından istenen güvenilir teslim: `Text`
/// (grup DIŞI)/`Edit`/`Delete`/`HistorySyncRequest` içerikli paketler,
/// karşı taraftan bir `Ack` (veya HistorySyncRequest için doğrudan
/// `HistorySyncResponse`) alınana kadar bu aralıklarla tekrar tekrar
/// gönderilir — üstel geri çekilme (exponential backoff), `MAX` ile
/// sınırlı. `gossipsub.publish()`'in yerel başarısı, karşı tarafın
/// GERÇEKTEN aldığının garantisi DEĞİLDİR (bkz. `awaiting_confirmation`
/// alanı dokümantasyonu) — bu yüzden eski `pending_envelopes` kuyruğunun
/// aksine burada bir üst zaman sınırı YOK, kullanıcı açıkça "karşı taraf
/// onaylayana kadar sürekli dene" istedi.
const ACK_RETRY_INITIAL_MS: u64 = 5_000;
const ACK_RETRY_MAX_MS: u64 = 120_000;
/// bkz. `PendingConfirmation.retries_remaining` dokümantasyonu — bir
/// `Ack` paketinin (kendisi ayrıca onaylanmadığından) en fazla kaç kez
/// yeniden denenip sonra sessizce bırakılacağı. 5 deneme + üstel geri
/// çekilme (5s, 10s, 20s, 40s, 80s ≈ toplam 2.5 dakika), tek seferlik
/// fire-and-forget'e göre teslimat olasılığını ciddi ölçüde artırır.
const ACK_SELF_MAX_RETRIES: u32 = 5;
/// KRİTİK: bir paket belirli bir ratchet zincir adımına karşı şifrelendi
/// (bkz. `PendingConfirmation.envelope` notu — yeniden şifrelenmeden
/// AYNEN tekrar gönderilir). Karşı taraf o adımı zaten TÜKETTİYSE
/// (normal akış) VE bu peer'le olan oturumda spec 3.2'nin 30 dakikalık
/// DH/KEM rotasyonu bir kez daha gerçekleştiyse (bkz.
/// `ratchet::RATCHET_ROTATION_MS`), alıcının o eski zincire ait
/// skipped-key önbelleği TAMAMEN TEMİZLENİR (`perform_dh_ratchet`/
/// `respond_to_rotation`, forward secrecy'nin istenen/doğru bir sonucu).
/// Bu noktadan sonra o paket ARTIK ASLA çözülemez — "onaylanana kadar
/// sürekli dene" artık kriptografik olarak İMKANSIZ bir şeyi
/// denemektir, sadece alıcıya sonsuza dek "Decryption failed"/
/// "skipped-key cache'te yok" hatası ürettirir (gerçek arıza deseni —
/// uzun bir test oturumunda BİRDEN FAZLA farklı mesajın aynı anda bu
/// duruma düşmesi gözlemlendi). Bu yüzden `awaiting_confirmation`
/// SÜRESİZ değil — rotasyon penceresinin biraz altında (güvenlik payı
/// ile) bir üst yaş sınırı var; aşılırsa paket "Failed" sayılıp
/// bırakılır (kullanıcı isterse manuel olarak yeni bir mesaj olarak
/// tekrar gönderebilir).
const MAX_UNCONFIRMED_AGE_MS: u64 = ratchet::RATCHET_ROTATION_MS - 5 * 60 * 1000;

/// bkz. `DownloadState.last_progress_at` dokümantasyonu — bir indirmenin,
/// hiçbir libp2p-seviyeli olay (ne parça yanıtı, ne `OutboundFailure`)
/// üretmeden bu kadar süre "sessiz" kalabileceği azami süre. Aşılırsa
/// `check_stalled_downloads` indirmeyi başarısız sayar (kullanıcı manuel
/// olarak tekrar deneyebilir) — aksi hâlde (özellikle iki cihaz da NAT
/// arkasındayken, TCP dial'ın ne başarılı olup ne de temiz bir hatayla
/// sonuçlanmadığı durumlarda) indirme SÜRESİZ "İndiriliyor" durumunda
/// takılı kalabilirdi.
const DOWNLOAD_STALL_TIMEOUT_MS: u64 = 45_000;

/// Bkz. `P2PCore.awaiting_confirmation` dokümantasyonu.
/// BİLİNEN SINIR: bu paket, belirli bir ratchet zincir adımına (`ck_send`
/// durumuna) karşı şifrelendi — eğer bu peer'le olan oturum, onay
/// gelmeden ÖNCE bir DH/KEM rotasyonu yaşarsa (spec 3.2, 30 dakikada bir),
/// alıcı tarafın o eski zincire ait skipped-key önbelleği rotasyonda
/// TEMİZLENİR (bkz. ratchet.rs `perform_dh_ratchet`/`respond_to_rotation`
/// notu — bu, forward secrecy'nin doğal/istenen bir sonucu). Böyle bir
/// durumda bu retry artık kalıcı olarak çözülemez hâle gelir — pratikte
/// bu, "mesaj 30+ dakika boyunca hiç onaylanmadı" gibi nadir bir kenar
/// durumu (yaygın "karşı taraf birkaç saniye/dakika erişilemezdi" durumunu
/// ETKİLEMEZ). Tam çözüm (rotasyon algılandığında bekleyen paketleri YENİ
/// zincir altında yeniden şifreleyip AYNI message_id ile göndermek),
/// bilinçli olarak bu turun kapsamı dışında bırakıldı — forward-secrecy
/// mekanizmasıyla etkileşimi dikkatli test gerektirir.
struct PendingConfirmation {
    peer_device_fingerprint: String,
    /// Zaten şifrelenmiş/imzalanmış paket — her yeniden denemede AYNEN
    /// tekrar gönderilir, YENİDEN ŞİFRELENMEZ (ratchet'i tekrar
    /// ilerletmek, karşı tarafın "aynı mantıksal mesaj" olarak
    /// tanımasını imkansız kılardı — bkz. ratchet.rs simetrik zincir
    /// notu).
    envelope: NetworkEnvelope,
    next_retry_at: u64,
    retry_interval_ms: u64,
    /// `None` = karşı taraf onaylayana kadar (bkz. `MAX_UNCONFIRMED_AGE_MS`
    /// dolana kadar) tekrar dener (Text/Edit/Delete/HistorySyncRequest —
    /// kullanıcının açıkça istediği davranış, "sayı" bazında bir üst
    /// sınır yok ama "yaş" bazında var, bkz. o sabitin dokümantasyonu).
    /// `Some(n)` = en fazla `n` kez daha denenir, sonra sessizce vazgeçilir.
    /// SADECE `Ack` paketleri için kullanılır: `Ack`'in kendisi
    /// AYRICA onaylanmıyor (bkz. packet.rs notu — sonsuz "onayı onayla"
    /// döngüsü riski), bu yüzden süresiz deneyemez; ama tek seferlik
    /// fire-and-forget de yetersizdi — bir Ack ağda kaybolursa (aynı
    /// güvenilmezlik, mesajların kendisini neden etkiliyorsa), gönderen
    /// taraf teslimatı ASLA öğrenemez ve orijinal mesajı yeniden
    /// göndermeye devam eder; alıcı taraf ise her seferinde AYNI (artık
    /// kendi ratchet'inde tüketilmiş) mesaj numarasını çözmeye çalışıp
    /// sürekli "Decryption failed"/"skipped-key cache'te yok" hatası
    /// üretir (bkz. bu alanın eklenmesine yol açan gerçek arıza deseni).
    /// Sınırlı birkaç deneme (bkz. `ACK_SELF_MAX_RETRIES`), tek seferlik
    /// göndermeye kıyasla teslimat olasılığını ciddi ölçüde artırırken
    /// sonsuz döngü riskini de önler.
    retries_remaining: Option<u32>,
    /// İlk gönderim denemesinin zamanı — bkz. `MAX_UNCONFIRMED_AGE_MS`.
    first_sent_at: u64,
}

struct P2PCore {
    db: Option<Connection>,
    identity: Option<identity::Identity>,
    /// Aşama A kapsamı: identity_id == device_fingerprint (1 Identity = 1
    /// Device). Bu map yine de device_fingerprint anahtarlı kalır (Aşama
    /// B'de birden fazla cihaz eklenebilsin diye).
    own_devices: HashMap<String, DeviceRecord>,
    own_device_keys: HashMap<String, DeviceKeys>,
    /// Bilinen uzak cihazların public key kayıtları (contact exchange /
    /// QR üzerinden öğrenilir).
    known_remote_devices: HashMap<String, DeviceRecord>,
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
    groups: HashMap<String, Group>,
    /// Kullanıcının onay beklediği, henüz kabul/red edilmemiş cihaz
    /// değişikliği uyarıları (spec 2.2). key = new_device_fingerprint.
    pending_device_alerts: HashMap<String, DeviceAlertInfo>,
    /// Bekleyen mesajlar (henüz doğrulanmamış/bloklu cihazdan geleni
    /// tutmuyoruz — spec "yeni mesaj gönderme/alma durur" der, yani
    /// alert çözülene kadar o cihazdan gelen mesajlar sessizce reddedilir).
    swarm: Option<Swarm<P2PBehaviour>>,
    /// `start_network` sonrası swarm'ın gerçekten dinlemeye başladığı
    /// adresler (`SwarmEvent::NewListenAddr`, bkz. `poll_events`) — QR/"Kodum"
    /// ekranında gösterilen `node_address` bundan türetilir. Bootstrap
    /// sırasında istenen `/ip4/0.0.0.0/tcp/0` (spec dışı, wildcard "her
    /// arayüzde, işletim sistemi seçsin" isteği) BUNUN YERİNE hiçbir zaman
    /// gösterilmemeli — 0.0.0.0/tcp/0 karşı tarafın dial edebileceği somut
    /// bir adres değildir.
    own_listen_addrs: Vec<Multiaddr>,
    /// Spec dışı, kullanıcı isteği (bkz. `P2PBehaviour.upnp` dokümantasyonu):
    /// UPnP ile router üzerinden başarıyla eşlenmiş, gerçekten dışarıdan
    /// (farklı ağdan) çevrilebilir adres — varsa `get_node_address()`
    /// tarafından HER ŞEYDEN ÖNCE tercih edilir (LAN adresinden bile önce,
    /// çünkü LAN adresi başka bir ağdaki biri için tamamen işe yaramaz).
    /// Eşleme süresi dolar/başarısız olursa (`Event::ExpiredExternalAddr`)
    /// temizlenir.
    own_external_addr: Option<Multiaddr>,
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
    pending_envelopes: Vec<(String, NetworkEnvelope, u64)>,
    /// UI'nin mesaj durumu ikonları göstermesi için (bkz. spec dışı
    /// "gönderim durumu" isteği) — key: `MessagePacketHeader.message_id`.
    /// Sınırsız büyümesin diye bir üst sınırı yok şu an (Aşama A kapsamında
    /// pratikte önemli değil) — bilinen küçük bir sınırlama.
    message_status: HashMap<String, MessageSendStatus>,
    /// Node modu açık mı (spec 4.3). Kapalıyken sadece Peer modu: DHT
    /// sorgular/günceller ama routing tablosuna aktif katkı sağlamaz
    /// (kad::Mode::Client). Açıkken kad::Mode::Server.
    node_mode_enabled: bool,
    /// `createIdentity` sonrası bir kereliğine Kotlin'e teslim edilecek
    /// plaintext secret bundle. `getPendingSecretBundle` çağrıldığında
    /// alınıp `None`'a döner (bkz. o fonksiyonun dokümantasyonu).
    pending_secret_bundle: Option<Vec<u8>>,
    /// Mesaj geçmişi arşivini şifrelemek için kullanılan 256-bit anahtar.
    /// Kotlin, Keystore'da sarılı (wrapped) bir "history data key" tutar,
    /// açılışta çözüp `setHistoryKey` ile buraya yükler — Rust bu anahtarı
    /// diske hiç yazmaz, sadece bellekte tutar (bkz. dosya sonu "mesaj
    /// geçmişi" notu). `None` iken (henüz yüklenmedi veya node modu hiç
    /// açılmadı) mesajlar arşivlenmez, sadece anlık işlenir.
    history_key: Option<[u8; 32]>,
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
    /// `PeerId -> Multiaddr` — `ConnectionEstablished` olayından doldurulur,
    /// dosya indirmesi başlatılırken `swarm.add_peer_address` ile
    /// `request_response`'un dial edebileceği bir adres ipucu vermek için.
    peer_id_to_addr: HashMap<PeerId, Multiaddr>,
    /// Spec dışı, ağ sağlamlığı düzeltmesi: bilinen bir uzak CİHAZ için en
    /// son işe yaramış/paylaşılmış adres (`/ip4/.../tcp/.../p2p/<peer_id>`
    /// tam biçimi). key = device_fingerprint. `peer_id_to_addr`'ın aksine
    /// bu KALICIDIR (bkz. `device_addrs` tablosu) ve süreç yeniden başlasa
    /// bile korunur — periyodik yeniden-bağlanma taraması (bkz.
    /// `reconnect_sweep`) bunu kullanarak, mDNS'in yetişemediği (farklı ağ)
    /// KOPMUŞ bir kişiye yeniden bağlanmayı dener. Eşleşme anında
    /// (rendezvous_node) ve her paket alındığında (o an bağlı olunan gerçek
    /// adres) güncellenir.
    device_last_addr: HashMap<String, String>,
    /// `reconnect_sweep`'in en son çalıştığı an — bkz. `RECONNECT_SWEEP_INTERVAL_MS`.
    last_reconnect_sweep_at: u64,
    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): röle protokolünü desteklediği `identify` ile
    /// doğrulanmış VE doğrudan erişilebilir (bkz. `dial_with_relay_fallback`)
    /// bilinen peer'lar. QR paketinde paylaşılır (bkz. `QrPacket.known_relays`)
    /// ve `identify::Event::Received`'dan organik olarak büyür — sabit bir
    /// bootstrap listesi hiç var olmadı, bu da spec §4.1'in hiç implemente
    /// edilmemiş "~10 node adresi paylaşımı" fikrinin röle'ye özelleşmiş
    /// hâli. En fazla `MAX_KNOWN_RELAYS` kadar tutulur.
    known_relay_peers: HashMap<PeerId, Multiaddr>,
    /// Spec dışı, hata ayıklama düzeltmesi: `initiate_handshake_with`'in
    /// bir peer için en son kullanıcıya BİLDİRİLMİŞ kalıcı hatası (ör.
    /// "Bad Kyber public key length" — bozuk/uyumsuz anahtar verisi).
    /// Aynı hata tekrar tekrar (her mesaj/typing-indicator/vb. denemesinde)
    /// sessizce oluşmaya devam etse bile kullanıcıya SADECE bir kez
    /// bildirilsin diye — bkz. o fonksiyonun dokümantasyonu.
    handshake_failure_notified: HashMap<String, String>,
    /// Devam eden indirmeler: key = file_id (bkz. `DownloadState`).
    active_downloads: HashMap<String, DownloadState>,
    /// `request_response::send_request`'in döndürdüğü `OutboundRequestId`'yi
    /// hangi dosyanın indirmesine ait olduğuna eşler — gelen
    /// `Message::Response` olayını doğru `DownloadState`'e yönlendirmek
    /// için (bkz. poll_events `FileChunks` kolu).
    download_request_ids: HashMap<request_response::OutboundRequestId, String>,
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

impl P2PCore {
    fn new() -> Self {
        android_logger::init_once(LogConfig::default().with_max_level(log::LevelFilter::Info));
        // JNI export'ları çağırdığı her `P2PCore` metodunu `catch_panic` ile
        // sarmalıyor (bkz. dosya sonu, JNI Bindings bölümü) — ama panic
        // hook'u burada AYRICA kurmamızın nedeni: stripped release build'de
        // (Cargo.toml `strip = true`) bir panic'in crash_dump'ı sembol
        // içermez, tanı imkansızlaşır (bkz. processQrPacket çökmesi geçmişi).
        // Bu hook, catch_unwind onu yakalamadan ÖNCE (panic sırasında,
        // unwind başlamadan) TAM panic mesajını + dosya/satır bilgisini
        // logcat'e yazar.
        std::panic::set_hook(Box::new(|info| {
            error!("PANIC yakalandı: {}", info);
        }));
        P2PCore {
            db: None,
            identity: None,
            own_devices: HashMap::new(),
            own_device_keys: HashMap::new(),
            known_remote_devices: HashMap::new(),
            contacts: HashMap::new(),
            identity_to_contact: HashMap::new(),
            ratchets: HashMap::new(),
            recent_handshake_sigs: HashMap::new(),
            groups: HashMap::new(),
            pending_device_alerts: HashMap::new(),
            swarm: None,
            own_listen_addrs: Vec::new(),
            own_external_addr: None,
            pending_envelopes: Vec::new(),
            message_status: HashMap::new(),
            node_mode_enabled: false,
            pending_secret_bundle: None,
            history_key: None,
            skipped_key_encryption_key: None,
            app_files_dir: None,
            device_to_peer_id: HashMap::new(),
            peer_id_to_addr: HashMap::new(),
            device_last_addr: HashMap::new(),
            last_reconnect_sweep_at: 0,
            known_relay_peers: HashMap::new(),
            handshake_failure_notified: HashMap::new(),
            active_downloads: HashMap::new(),
            download_request_ids: HashMap::new(),
            attachment_events: Vec::new(),
            awaiting_confirmation: HashMap::new(),
        }
    }

    /// Android'in `std::env::var("ANDROID_DATA")` ile güvenilir biçimde
    /// bilinemeyen, uygulamaya özel yazılabilir dizinini Kotlin tarafından
    /// (`Context.filesDir.absolutePath`) almak zorundayız — bu yüzden DB
    /// açma `new()`'de otomatik değil, Kotlin'in ilk çağrıda geçtiği gerçek
    /// dosya yoluyla `init_db` çağrılmasını bekler (bkz. JNI `initDatabase`).
    fn init_db(&mut self, app_files_dir: &str) -> Result<(), rusqlite::Error> {
        let path = format!("{}/{}", app_files_dir, DB_NAME);
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS identities (id TEXT PRIMARY KEY, primary_device TEXT, avatar_jpeg BLOB);
             CREATE TABLE IF NOT EXISTS own_devices (device_fingerprint TEXT PRIMARY KEY, identity_id TEXT,
                sign_pk_ed25519 BLOB, sign_pk_mldsa BLOB, kem_pk_x25519 BLOB, kem_pk_mlkem BLOB,
                device_name TEXT, is_active INTEGER, last_seen INTEGER);
             CREATE TABLE IF NOT EXISTS contacts (contact_id TEXT PRIMARY KEY, display_name TEXT,
                trusted_identity_id TEXT, known_devices_json TEXT, last_device_change INTEGER, avatar_jpeg BLOB);
             CREATE TABLE IF NOT EXISTS groups (group_id TEXT PRIMARY KEY, founder TEXT, name TEXT,
                version INTEGER, members_json TEXT, created_at INTEGER, avatar_jpeg BLOB);
             CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_device_fingerprint TEXT NOT NULL,
                direction TEXT NOT NULL,
                encrypted_blob BLOB NOT NULL,
                nonce BLOB NOT NULL,
                timestamp INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_device_fingerprint, timestamp);
             CREATE TABLE IF NOT EXISTS skipped_message_keys (
                peer_device_fingerprint TEXT NOT NULL,
                message_number INTEGER NOT NULL,
                encrypted_key BLOB NOT NULL,
                nonce BLOB NOT NULL,
                PRIMARY KEY (peer_device_fingerprint, message_number)
             );
             CREATE TABLE IF NOT EXISTS remote_devices (
                device_fingerprint TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                sign_pk_ed25519 BLOB, sign_pk_mldsa BLOB, kem_pk_x25519 BLOB, kem_pk_mlkem BLOB,
                device_name TEXT, is_active INTEGER, last_seen INTEGER
             );
             CREATE TABLE IF NOT EXISTS ratchet_states (
                peer_device_fingerprint TEXT PRIMARY KEY,
                encrypted_state BLOB NOT NULL,
                nonce BLOB NOT NULL,
                updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                peer_device_fingerprint TEXT NOT NULL,
                direction TEXT NOT NULL,
                file_name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                total_size INTEGER NOT NULL,
                sha256_hex TEXT NOT NULL,
                encrypted_file_key BLOB NOT NULL,
                key_nonce BLOB NOT NULL,
                status TEXT NOT NULL,
                bytes_transferred INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                preview_jpeg BLOB,
                duration_ms INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_files_peer ON files(peer_device_fingerprint, created_at);
             CREATE TABLE IF NOT EXISTS device_addrs (
                device_fingerprint TEXT PRIMARY KEY,
                multiaddr TEXT NOT NULL,
                updated_at INTEGER NOT NULL
             );"
        )?;
        // Spec dışı geçiş (migration): `preview_jpeg` kolonu bu tabloya
        // SONRADAN eklendi — `CREATE TABLE IF NOT EXISTS` zaten var olan
        // bir tabloyu değiştirmez, bu yüzden bu kolon olmadan önceki bir
        // sürümü çalıştırmış cihazlarda elle eklenmesi gerekir. SQLite
        // `ADD COLUMN IF NOT EXISTS` desteklemediğinden, kolon zaten
        // varsa oluşacak hatayı (duplicate column) sessizce yok sayıyoruz.
        let _ = conn.execute("ALTER TABLE files ADD COLUMN preview_jpeg BLOB", []);
        // Aynı geçiş deseni: sesli mesaj süresi, kendi profil fotoğrafımız
        // ve kişilerin bize gönderdiği profil fotoğrafları — hepsi sonradan
        // eklendi.
        let _ = conn.execute("ALTER TABLE files ADD COLUMN duration_ms INTEGER", []);
        let _ = conn.execute("ALTER TABLE identities ADD COLUMN avatar_jpeg BLOB", []);
        let _ = conn.execute("ALTER TABLE contacts ADD COLUMN avatar_jpeg BLOB", []);
        let _ = conn.execute("ALTER TABLE groups ADD COLUMN avatar_jpeg BLOB", []);
        self.db = Some(conn);
        self.app_files_dir = Some(app_files_dir.to_string());
        let _ = std::fs::create_dir_all(format!("{}/attachments/plain_cache", app_files_dir));
        self.load_identity_from_db();
        // Spec dışı düzeltme: `contacts`/`groups` tabloları önceden
        // oluşturuluyor ama hiç yazılıp okunmuyordu — kişiler, gruplar ve
        // bilinen uzak cihaz public key'leri sadece bellekteydi, her süreç
        // yeniden başlatmasında (app güncellemesi dahil) kayboluyordu. Artık
        // her mutasyon noktasında diske yazılıyor (bkz. persist_contact/
        // persist_group/persist_remote_device) — burada açılışta geri
        // yükleniyor. (Ratchet oturumları AYRI olarak, şifreleme anahtarı
        // yüklendiğinde `setSkippedKeyEncryptionKey` içinde geri yüklenir —
        // bkz. load_ratchet_states_from_db.)
        self.load_contacts_from_db();
        self.load_groups_from_db();
        self.load_remote_devices_from_db();
        self.load_device_addrs_from_db();
        Ok(())
    }

    /// Spec dışı, ağ sağlamlığı düzeltmesi: bilinen cihaz adreslerini
    /// (`device_last_addr`) diskten belleğe yükler — süreç yeniden başlasa
    /// bile `reconnect_sweep` kopmuş kişilere (farklı ağdakiler dahil,
    /// mDNS'in yetişemediği) yeniden bağlanmayı deneyebilsin diye.
    fn load_device_addrs_from_db(&mut self) {
        let conn = match &self.db { Some(c) => c, None => return };
        let mut stmt = match conn.prepare("SELECT device_fingerprint, multiaddr FROM device_addrs") {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)));
        if let Ok(rows) = rows {
            for (fp, addr) in rows.flatten() {
                self.device_last_addr.insert(fp, addr);
            }
        }
    }

    /// Spec dışı, ağ sağlamlığı düzeltmesi: bir cihaz için en son işe
    /// yaramış/paylaşılmış adresi hem bellekte hem diskte günceller (bkz.
    /// `device_last_addr`). Adres `.../p2p/<peer_id>` son ekini içermeli
    /// (`reconnect_sweep` PeerId'yi buradan çıkarır) — içermiyorsa yok
    /// sayılır (yeniden bağlanmak için işe yaramaz).
    fn remember_device_addr(&mut self, device_fingerprint: &str, multiaddr: &str) {
        if let Ok(parsed) = multiaddr.parse::<Multiaddr>() {
            if extract_peer_id(&parsed).is_none() {
                return;
            }
        } else {
            return;
        }
        // Değişmediyse diske yazma (gereksiz I/O önle).
        if self.device_last_addr.get(device_fingerprint).map(|a| a.as_str()) == Some(multiaddr) {
            return;
        }
        self.device_last_addr.insert(device_fingerprint.to_string(), multiaddr.to_string());
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO device_addrs (device_fingerprint, multiaddr, updated_at) VALUES (?1, ?2, ?3)",
                params![device_fingerprint, multiaddr, current_time_ms() as i64],
            );
        }
    }

    /// Uygulama yeniden başlatıldığında DB'de kayıtlı identity/device'ın
    /// PUBLIC key kayıtlarını belleğe yükler. Bulunamazsa (ilk açılış)
    /// sessizce hiçbir şey yapmaz — `generate_identity` çağrılmasını
    /// bekler. Secret key'ler burada YÜKLENMEZ — Kotlin, Keystore ile
    /// şifresini çözdüğü `SecretKeyBundle`'ı ayrıca `load_secret_bundle`
    /// ile göndermelidir (uygulama akışı: initDatabase → identity varsa
    /// Kotlin şifreli blob'u okur/çözer → loadSecretBundle çağrılır).
    fn load_identity_from_db(&mut self) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let identity_row: Option<(String, String)> = conn
            .query_row("SELECT id, primary_device FROM identities LIMIT 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .ok();
        let (identity_id, primary_device) = match identity_row {
            Some(v) => v,
            None => return,
        };

        let mut stmt = match conn.prepare(
            "SELECT device_fingerprint, sign_pk_ed25519, sign_pk_mldsa, kem_pk_x25519, kem_pk_mlkem,
                    device_name, is_active, last_seen
             FROM own_devices WHERE identity_id = ?1"
        ) {
            Ok(s) => s,
            Err(e) => { error!("load_identity_from_db prepare failed: {}", e); return; }
        };

        let rows = stmt.query_map(params![identity_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?, row.get::<_, i32>(6)?, row.get::<_, i64>(7)?,
            ))
        });

        let mut device_infos = Vec::new();

        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (fp, sign_pk_ed, sign_pk_mldsa, kem_pk_x, kem_pk_mlkem,
                     device_name, is_active, last_seen) = row;

                self.own_devices.insert(fp.clone(), DeviceRecord {
                    device_fingerprint: fp.clone(),
                    identity_id: identity_id.clone(),
                    sign_pubkey_ed25519: sign_pk_ed,
                    sign_pubkey_mldsa: sign_pk_mldsa,
                    kem_pubkey_x25519: kem_pk_x,
                    kem_pubkey_mlkem: kem_pk_mlkem,
                    device_name: device_name.clone(),
                    is_active: is_active != 0,
                    last_seen: last_seen as u64,
                });
                device_infos.push(identity::DeviceInfo {
                    device_fingerprint: fp,
                    device_name,
                    added_at: last_seen as u64,
                    status: if is_active != 0 { DeviceStatus::Active } else { DeviceStatus::Revoked },
                });
            }
        }

        if !device_infos.is_empty() {
            self.identity = Some(identity::Identity {
                identity_id,
                devices: device_infos,
                primary_device: Some(primary_device),
            });
            info!("Identity DB'den yüklendi (public key'ler) — secret key'ler henüz yüklenmedi, load_secret_bundle bekleniyor");
        }
    }

    // ---------------------------------------------------------------
    // Bölüm 1: Identity/Device
    // ---------------------------------------------------------------

    /// Kimlik + ilk cihazı üretir. DB'ye SADECE public key'ler yazılır.
    /// Secret key'ler dönüş değerinde bir `SecretKeyBundle` (CBOR) olarak
    /// verilir — Rust bunları hiçbir zaman diske yazmaz; çağıran (Kotlin,
    /// JNI export'u üzerinden) bu bloğu Android Keystore ile şifreleyip
    /// kendi sorumluluğunda saklamalıdır (bkz. `KeystoreCrypto.kt`).
    fn generate_identity(&mut self, device_name: String) -> Result<(String, Vec<u8>), String> {
        let mut csprng = OsRng;
        let sign_sk_ed25519 = SigningKey::generate(&mut csprng);
        let sign_pk_ed25519 = sign_sk_ed25519.verifying_key();
        // ML-DSA-87 — spec 1.1 tablosu ML-DSA-65 (NIST Kategori 3) belirtiyordu;
        // güvenlik marjını artırmak için ML-KEM-1024/ML-DSA-87'ye (Kategori 5)
        // yükseltildi (bkz. SECURITY.md "Anahtar boyutları" notu). getrandom
        // feature ile parametresiz üretim, rand_core sürüm çakışmasını
        // bypass eder (bkz. Cargo.toml notu).
        let sign_sk_mldsa: MlDsaSigningKey<MlDsa87> = MlDsaGenerate::generate();
        let sign_pk_mldsa = sign_sk_mldsa.verifying_key().clone();
        let kem_sk_x25519 = StaticSecret::random_from_rng(&mut csprng);
        let kem_pk_x25519 = X25519PublicKey::from(&kem_sk_x25519);
        // X25519 (rand_core 0.6 üzerinden rand 0.8) ve ML-KEM (rand_core
        // 0.6.4) aynı rand_core majör sürümü — aynı OsRng paylaşılabilir.
        let (kem_sk_mlkem, _kem_pk_mlkem_dup) = MlKem1024::generate(&mut csprng);
        let kem_pk_mlkem = kem_sk_mlkem.encapsulation_key().clone();

        let fingerprint_raw = compute_fingerprint(
            sign_pk_ed25519.as_bytes(),
            &sign_pk_mldsa.encode(),
            kem_pk_x25519.as_bytes(),
            &kem_pk_mlkem.as_bytes(),
        );
        let fingerprint_hex = hex::encode(&fingerprint_raw);

        // Aşama A: identity_id == ilk (ve tek) cihazın fingerprint'i.
        let identity_id = fingerprint_hex.clone();
        let device_fingerprint = fingerprint_hex;

        let identity = identity::Identity {
            identity_id: identity_id.clone(),
            devices: vec![identity::DeviceInfo {
                device_fingerprint: device_fingerprint.clone(),
                device_name: device_name.clone(),
                added_at: current_time_ms(),
                status: DeviceStatus::Active,
            }],
            primary_device: Some(device_fingerprint.clone()),
        };

        let record = DeviceRecord {
            device_fingerprint: device_fingerprint.clone(),
            identity_id: identity_id.clone(),
            sign_pubkey_ed25519: sign_pk_ed25519.as_bytes().to_vec(),
            sign_pubkey_mldsa: sign_pk_mldsa.encode().to_vec(),
            kem_pubkey_x25519: kem_pk_x25519.as_bytes().to_vec(),
            kem_pubkey_mlkem: kem_pk_mlkem.as_bytes().to_vec(),
            device_name,
            is_active: true,
            last_seen: current_time_ms(),
        };

        let secret_bundle = SecretKeyBundle {
            device_fingerprint: device_fingerprint.clone(),
            sign_sk_ed25519: sign_sk_ed25519.to_bytes().to_vec(),
            // ML-DSA'nın "secret key" serileştirmesi 32 baytlık bir seed'dir
            // (`KeyExport::to_bytes`) — bu seed'ten `SigningKey::from_seed`
            // ile deterministik olarak aynı anahtar geri üretilir.
            sign_sk_mldsa: sign_sk_mldsa.to_bytes().to_vec(),
            kem_sk_x25519: kem_sk_x25519.to_bytes().to_vec(),
            // ML-KEM'in seed'ten geri üretimi yok (bkz. ratchet.rs notu) —
            // tam serileştirilmiş secret key (`EncodedSizeUser::as_bytes`)
            // saklanır.
            kem_sk_mlkem: kem_sk_mlkem.as_bytes().to_vec(),
        };
        let secret_bundle_bytes = ciborium_bytes(&secret_bundle)?;

        let keys = DeviceKeys {
            sign_sk_ed25519,
            sign_pk_ed25519,
            sign_pk_mldsa,
            sign_sk_mldsa,
            kem_sk_x25519,
            kem_pk_x25519,
            kem_pk_mlkem,
            kem_sk_mlkem,
        };

        if let Some(conn) = &self.db {
            conn.execute(
                "INSERT OR REPLACE INTO identities (id, primary_device) VALUES (?1, ?2)",
                params![identity_id, device_fingerprint],
            ).map_err(|e| e.to_string())?;
            // Sadece PUBLIC key'ler burada yazılıyor — secret key'ler bu
            // bağlantıya hiç yazılmaz (bkz. fonksiyon dokümantasyonu).
            conn.execute(
                "INSERT OR REPLACE INTO own_devices
                 (device_fingerprint, identity_id, sign_pk_ed25519, sign_pk_mldsa, kem_pk_x25519, kem_pk_mlkem,
                  device_name, is_active, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    record.device_fingerprint, record.identity_id,
                    record.sign_pubkey_ed25519, record.sign_pubkey_mldsa,
                    record.kem_pubkey_x25519, record.kem_pubkey_mlkem,
                    record.device_name, record.is_active as i32, record.last_seen as i64,
                ],
            ).map_err(|e| e.to_string())?;
        }

        self.identity = Some(identity);
        self.own_devices.insert(device_fingerprint.clone(), record);
        self.own_device_keys.insert(device_fingerprint, keys);

        Ok((identity_id, secret_bundle_bytes))
    }

    /// Kotlin'in Keystore ile şifresini çözdüğü bir `SecretKeyBundle`'ı
    /// (CBOR) belleğe yükler — uygulama yeniden başlatıldığında,
    /// `load_identity_from_db`'nin doldurduğu PUBLIC key kayıtlarını
    /// tamamlamak için çağrılır. `load_identity_from_db` zaten
    /// `own_devices`/`identity`'yi doldurmuş olmalı; bu fonksiyon sadece
    /// eksik olan `own_device_keys` (secret key'ler) map'ini doldurur.
    fn load_secret_bundle(&mut self, bundle_bytes: &[u8]) -> Result<(), String> {
        let bundle: SecretKeyBundle = ciborium::from_reader(bundle_bytes).map_err(|e| e.to_string())?;

        let record = self.own_devices.get(&bundle.device_fingerprint).cloned()
            .ok_or("Bilinmeyen cihaz — önce load_identity_from_db (public key) çalışmalı")?;

        let sign_sk_ed_bytes: [u8; 32] = bundle.sign_sk_ed25519.as_slice().try_into().map_err(|_| "Bozuk Ed25519 secret key")?;
        let sign_sk_ed25519 = SigningKey::from_bytes(&sign_sk_ed_bytes);
        let sign_pk_ed25519 = sign_sk_ed25519.verifying_key();

        // ML-DSA secret key'i 32 baytlık seed olarak saklanıyor (bkz.
        // generate_identity notu) — `from_seed` ile deterministik üretiliyor.
        let sign_sk_mldsa_seed: ml_dsa::Seed = bundle.sign_sk_mldsa.as_slice().try_into().map_err(|_| "Bozuk ML-DSA secret key")?;
        let sign_sk_mldsa = MlDsaSigningKey::<MlDsa87>::from_seed(&sign_sk_mldsa_seed);
        let sign_pk_mldsa_encoded: EncodedVerifyingKey<MlDsa87> = record.sign_pubkey_mldsa.as_slice().try_into().map_err(|_| "Bozuk ML-DSA public key")?;
        let sign_pk_mldsa = MlDsaVerifyingKey::<MlDsa87>::decode(&sign_pk_mldsa_encoded);

        let kem_sk_x_bytes: [u8; 32] = bundle.kem_sk_x25519.as_slice().try_into().map_err(|_| "Bozuk X25519 secret key")?;
        let kem_sk_x25519 = StaticSecret::from(kem_sk_x_bytes);
        let kem_pk_x25519 = X25519PublicKey::from(&kem_sk_x25519);

        // ML-KEM secret key'i tam serileştirilmiş biçimde saklanıyor (bkz.
        // generate_identity notu — ml-kem'de "seed"ten geri üretim yok).
        let kem_sk_encoded: ml_kem::Encoded<MlKem1024DecapsulationKey> = bundle.kem_sk_mlkem.as_slice().try_into().map_err(|_| "Bozuk Kyber secret key")?;
        let kem_sk_mlkem = MlKem1024DecapsulationKey::from_bytes(&kem_sk_encoded);
        let kem_pk_encoded: ml_kem::Encoded<MlKem1024EncapsulationKey> = record.kem_pubkey_mlkem.as_slice().try_into().map_err(|_| "Bozuk Kyber public key")?;
        let kem_pk_mlkem = MlKem1024EncapsulationKey::from_bytes(&kem_pk_encoded);

        self.own_device_keys.insert(bundle.device_fingerprint.clone(), DeviceKeys {
            sign_sk_ed25519,
            sign_pk_ed25519,
            sign_pk_mldsa,
            sign_sk_mldsa,
            kem_sk_x25519,
            kem_pk_x25519,
            kem_pk_mlkem,
            kem_sk_mlkem,
        });
        Ok(())
    }

    fn get_active_own_device_fingerprint(&self) -> Result<String, String> {
        let identity_id = self.identity.as_ref().ok_or("No identity yet")?.identity_id.clone();
        self.own_devices
            .iter()
            .find(|(_, d)| d.identity_id == identity_id && d.is_active)
            .map(|(fp, _)| fp.clone())
            .ok_or_else(|| "No active own device".to_string())
    }

    /// Base32 kişi kodu (spec 1.2) — UI'de gösterilecek.
    fn identity_code(&self) -> Result<String, String> {
        let id = self.identity.as_ref().ok_or("No identity yet")?;
        identity::format_identity_code(&id.identity_id)
    }

    fn identity_short_code(&self) -> Result<String, String> {
        let id = self.identity.as_ref().ok_or("No identity yet")?;
        let raw = hex::decode(&id.identity_id).map_err(|_| "Bad identity_id")?;
        Ok(identity::format_short_code(&raw))
    }

    // ---------------------------------------------------------------
    // Bölüm 1.3/1.4: QR + manuel eşleşme
    // ---------------------------------------------------------------

    /// Kendi QR paketimizi üretir (spec 1.3 — fingerprint-only karar).
    /// `rendezvous_node`: bilinen bootstrap node adresi (spec bölüm 6.5 —
    /// "tek bilinen node" v0.1 için yeterli).
    fn generate_qr_packet(&self, rendezvous_node: String) -> Result<Vec<u8>, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let device_name = self.own_devices.get(&own_fp).map(|d| d.device_name.clone()).unwrap_or_default();

        // bkz. SECURITY.md "Cross-network connectivity" notu / spec §4.1
        // ("~10 node adresi paylaşımı", önceden hiç implemente edilmemişti):
        // taşıdığımız bilinen röle adaylarından birkaçını da QR'a ekliyoruz
        // — bu sayede karşı taraf, biz doğrudan dial edilemesek bile (farklı
        // ağ/NAT) bizi bir röle üzerinden bulabilir. `known_relay_peers`
        // değerleri zaten TAM adres (`.../p2p/<röle_peer_id>` dahil, bkz.
        // `record_known_relay` çağrı noktaları) — burada tekrar eklemeye
        // gerek yok.
        let known_relays: Vec<String> = self.known_relay_peers.values()
            .take(5)
            .map(|addr| addr.to_string())
            .collect();

        let packet = QrPacket {
            version: QrPacket::CURRENT_VERSION,
            device_name,
            identity_id,
            device_fingerprint: own_fp,
            rendezvous_node,
            known_relays,
        };
        packet.to_cbor()
    }

    /// Spec dışı, kullanıcı isteği: `process_manual_entry`'nin beklediği
    /// `identity_id|device_fingerprint|device_name|rendezvous_node`
    /// formatını (bkz. o fonksiyonun dokümantasyonu) burada, TEK bir yerde
    /// üretir — Kotlin tarafında elle string birleştirmek yerine (format
    /// driftine karşı; ayrıştırıcı ve üretici aynı formatı Rust'ta paylaşır).
    /// UI'de "Kodumu kopyala" düğmesi bunu panoya kopyalar, karşı taraf
    /// "Manuel Ekle" dialoguna yapıştırır — QR taranamayan durumlar için
    /// (ör. ekranlar fiziksel olarak yan yana değil).
    fn generate_manual_add_code(&self, rendezvous_node: &str) -> Result<String, String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let device_name = self.own_devices.get(&own_fp).map(|d| d.device_name.clone()).unwrap_or_default();
        Ok(format!("{}|{}|{}|{}", identity_id, own_fp, device_name, rendezvous_node))
    }

    /// Taranan bir QR'ı (veya manuel girilen aynı formattaki metni, spec
    /// 1.4) işler: TOFU olarak Contact kaydeder, rendezvous node'u swarm'a
    /// bilinen adres olarak ekler, ve karşı tarafın gerçek public key'lerini
    /// indirmek için kendi `IdentityExchange` paketimizi gönderir (spec 1.3:
    /// "fingerprint-only [...] bağlantı kurulunca karşı taraftan indirilir
    /// ve bu fingerprint ile karşılaştırılır").
    fn process_qr_packet(&mut self, cbor_data: &[u8]) -> Result<String, String> {
        let packet = QrPacket::from_cbor(cbor_data)?;
        self.register_contact_from_pairing(
            packet.identity_id.clone(),
            packet.device_fingerprint.clone(),
            packet.device_name,
        )?;

        // bkz. SECURITY.md "Cross-network connectivity" notu: QR'ın taşıdığı
        // röle adaylarını önce kaydediyoruz — böylece hemen aşağıdaki
        // `dial_with_relay_fallback` çağrısı, karşı taraf (`rendezvous_node`)
        // doğrudan erişilemez olsa bile (farklı ağ/NAT) bu adaylardan
        // birinin üzerinden bağlanmayı deneyebilir.
        for relay_str in &packet.known_relays {
            if let Ok(addr) = relay_str.parse::<Multiaddr>() {
                if let Some(relay_peer_id) = extract_peer_id(&addr) {
                    if let Some(swarm) = &mut self.swarm {
                        swarm.behaviour_mut().kad.add_address(&relay_peer_id, addr.clone());
                    }
                    self.record_known_relay(relay_peer_id, addr);
                }
            }
        }

        if let Ok(addr) = packet.rendezvous_node.parse::<Multiaddr>() {
            if let Some(peer_id) = extract_peer_id(&addr) {
                if let Some(swarm) = &mut self.swarm {
                    swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                }
                // bkz. `device_last_addr` — bu adresi kalıcı yeniden-bağlanma
                // ipucu olarak sakla ki ilk dial ANINDA başarısız olsa bile
                // (ör. UPnP henüz eşleşmedi, karşı taraf o an offline)
                // `reconnect_sweep` tekrar denemeye devam etsin.
                self.remember_device_addr(&packet.device_fingerprint, &packet.rendezvous_node);
                // `kad.add_address` sadece bir DHT routing ipucudur —
                // kendi başına hiçbir bağlantı AÇMAZ. QR taramasının
                // asıl amacı iki cihazı doğrudan birbirine bağlamak
                // olduğundan burada açıkça dial ediyoruz (bkz. dosya
                // sonu not: bu olmadan iki cihaz asla gerçek bir libp2p
                // bağlantısı kurmuyordu — ne gossipsub mesajı ne de
                // IdentityExchange karşı tarafa ulaşıyordu). `rendezvous_node`
                // doğrudan erişilemezse (farklı ağ/NAT), yukarıda kaydedilen
                // röle adayları üzerinden de eşzamanlı denenir (bkz.
                // `dial_with_relay_fallback`).
                self.dial_with_relay_fallback(peer_id, Some(addr));
            }
        }

        // `dial()` yukarıda sadece bağlantıyı BAŞLATTI — TCP/noise/gossipsub
        // el sıkışması tamamlanmadan bu publish() neredeyse kesin
        // "InsufficientPeers"/"NoPeersSubscribedToTopic" ile başarısız olur.
        // Bunu ölümcül bir hata olarak yukarı taşımıyoruz: TOFU contact
        // kaydı (register_contact_from_pairing) zaten YUKARIDA tamamlandı —
        // "tarama başarısız" göstermek yanlış olur. `send_identity_exchange`
        // içindeki `publish_envelope` başarısız olursa zaten kendi içinde
        // `pending_envelopes`'e ekleyip `poll_events`'te yeniden dener.
        if let Err(e) = self.send_identity_exchange(&packet.device_fingerprint) {
            error!("IdentityExchange gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
        }
        Ok(packet.identity_id)
    }

    /// Kendi `IdentityExchange` paketimizi karşı tarafa gönderir — spec
    /// 1.3'teki "fingerprint-only QR + bağlantıda public key indirme"
    /// adımını taşır. Her iki taraf da eşleşme sonrası bunu birbirine
    /// gönderdiğinde, ikisi de karşı tarafın gerçek public key'lerini
    /// öğrenmiş ve kendi taraflarında fingerprint'i yeniden hesaplayıp
    /// doğrulamış olur (bkz. `process_identity_exchange`).
    fn send_identity_exchange(&mut self, target_device_fingerprint: &str) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let own_record = self.own_devices.get(&own_fp).ok_or("Missing own device record")?.clone();

        let exchange = IdentityExchange {
            identity_id: own_identity_id,
            device_fingerprint: own_fp,
            device_name: own_record.device_name,
            sign_pubkey_ed25519: own_record.sign_pubkey_ed25519,
            sign_pubkey_mldsa: own_record.sign_pubkey_mldsa,
            kem_pubkey_x25519: own_record.kem_pubkey_x25519,
            kem_pubkey_mlkem: own_record.kem_pubkey_mlkem,
        };
        self.publish_envelope(target_device_fingerprint, &NetworkEnvelope::IdentityExchange(exchange))
    }

    /// Gelen bir `IdentityExchange` paketini işler: taşınan public key'lerden
    /// fingerprint'i YENİDEN HESAPLAR ve paketin `device_fingerprint`
    /// alanıyla eşleştiğini doğrular (spec 1.3 — "bu fingerprint ile
    /// karşılaştırılır"). Eşleşmezse paket reddedilir (sahte/bozuk public
    /// key ima eder). Eşleşirse `known_remote_devices`'a kaydedilir.
    fn process_identity_exchange(&mut self, exchange: &IdentityExchange) -> Result<(), String> {
        let computed = compute_fingerprint(
            &exchange.sign_pubkey_ed25519,
            &exchange.sign_pubkey_mldsa,
            &exchange.kem_pubkey_x25519,
            &exchange.kem_pubkey_mlkem,
        );
        let computed_hex = hex::encode(&computed);
        if computed_hex != exchange.device_fingerprint {
            return Err(format!(
                "IdentityExchange fingerprint uyuşmazlığı: beklenen {}, hesaplanan {}",
                exchange.device_fingerprint, computed_hex
            ));
        }

        // Spec dışı, güvenlik denetimi düzeltmesi: önceden bu fonksiyon
        // `evaluate_sender_device`/spec 2.2 TOFU+uyarı karar ağacına HİÇ
        // girmiyordu — zaten bilinen bir Contact için gelen BEKLENMEYEN
        // yeni bir cihaz, hiçbir "tanınmayan cihaz" uyarısı tetiklenmeden
        // sessizce `known_remote_devices`'a yazılıyordu (bkz. SECURITY.md).
        // Artık `process_qr_packet`/`process_manual_entry` ile AYNI karar
        // ağacından geçiyor: yeni kişi ise TOFU ile eklenir (aşağıdaki
        // `register_contact_from_pairing` çağrısına gerek KALMAZ, bu kolu
        // `evaluate_sender_device` zaten kendi içinde yapar), bilinen bir
        // kişinin BEKLENMEYEN yeni cihazıysa spec 2.2 "BLOKLA" kuralı
        // uygulanır — bu fonksiyon `known_remote_devices`'a HİÇ yazmadan,
        // sessizce döner; kullanıcı `pending_device_alerts`'ten kabul/red
        // etmeden bu cihazdan gelen/bu cihaza giden hiçbir paket işlenmez.
        let outcome = self.evaluate_sender_device(&exchange.identity_id, &exchange.device_fingerprint, false, &exchange.device_name);
        if outcome == DeviceCheckOutcome::UnverifiedNewDeviceAlert {
            return Ok(());
        }

        let now = current_time_ms();
        let record = DeviceRecord {
            device_fingerprint: exchange.device_fingerprint.clone(),
            identity_id: exchange.identity_id.clone(),
            sign_pubkey_ed25519: exchange.sign_pubkey_ed25519.clone(),
            sign_pubkey_mldsa: exchange.sign_pubkey_mldsa.clone(),
            kem_pubkey_x25519: exchange.kem_pubkey_x25519.clone(),
            kem_pubkey_mlkem: exchange.kem_pubkey_mlkem.clone(),
            device_name: exchange.device_name.clone(),
            is_active: true,
            last_seen: now,
        };
        self.persist_remote_device(&record);
        self.known_remote_devices.insert(exchange.device_fingerprint.clone(), record);

        // Karşı taraf da bize aynı paketi gönderdiyse zaten known_remote_devices
        // doldu; ama tek taraflı taranan bir QR senaryosunda (biz taradık,
        // karşı taraf henüz bizim IdentityExchange'imizi görmedi) karşılıklı
        // exchange'i tamamlamak için biz de kendi paketimizi göndeririz.
        let _ = self.send_identity_exchange(&exchange.device_fingerprint);

        // Spec dışı: eşleşme tamamlanır tamamlanmaz kendi profil
        // fotoğrafımızı (VARSA) bu yeni kişiye bir kez göndeririz — daha
        // sonra fotoğraf değişirse `set_own_profile_picture` zaten TÜM
        // kişilere tekrar gönderir, burası SADECE ilk eşleşme anını
        // kapsıyor (her yeniden bağlanışta değil, spam önleme).
        if let Some(avatar) = self.get_own_avatar() {
            let content = MessageContent::ProfileUpdate { avatar_jpeg: Some(avatar) };
            if let Err(e) = self.send_message_content(exchange.device_fingerprint.clone(), &content, None) {
                error!("Eşleşme sonrası ProfileUpdate gönderilemedi: {}", e);
            }
        }

        Ok(())
    }

    /// Spec 1.4: manuel giriş, QR ile aynı bilgiyi taşıyan bir metin/kod
    /// formatı. Burada Base32 kişi kodu + fingerprint + rendezvous adresini
    /// `|` ile ayrılmış tek satır olarak kabul ediyoruz (spec bu formatı
    /// tam belirtmemiş; en basit, insan tarafından elle girilebilir biçim).
    fn process_manual_entry(&mut self, text: &str) -> Result<String, String> {
        let parts: Vec<&str> = text.trim().split('|').collect();
        if parts.len() != 4 {
            return Err("Beklenen format: identity_id|device_fingerprint|device_name|rendezvous_node".to_string());
        }
        let (identity_id, device_fingerprint, device_name, rendezvous_node) =
            (parts[0].to_string(), parts[1].to_string(), parts[2].to_string(), parts[3].to_string());

        self.register_contact_from_pairing(identity_id.clone(), device_fingerprint.clone(), device_name)?;

        if let Ok(addr) = rendezvous_node.parse::<Multiaddr>() {
            if let Some(peer_id) = extract_peer_id(&addr) {
                if let Some(swarm) = &mut self.swarm {
                    swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                }
                // bkz. process_qr_packet'teki aynı not — kalıcı yeniden-
                // bağlanma ipucu olarak sakla.
                self.remember_device_addr(&device_fingerprint, &rendezvous_node);
                // bkz. process_qr_packet'teki aynı dial notu — manuel giriş
                // formatı (spec dışı, 4 alanlı metin) bir röle listesi
                // taşımıyor, ama daha önce QR/identify'dan öğrenilmiş
                // röleler varsa (bkz. `known_relay_peers`) yine de denenir.
                self.dial_with_relay_fallback(peer_id, Some(addr));
            }
        }
        // bkz. process_qr_packet'teki aynı not — publish_envelope kendi
        // içinde yeniden dener, burada sadece logluyoruz.
        if let Err(e) = self.send_identity_exchange(&device_fingerprint) {
            error!("IdentityExchange gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
        }
        Ok(identity_id)
    }

    fn register_contact_from_pairing(&mut self, identity_id: String, device_fingerprint: String, device_name: String) -> Result<(), String> {
        let now = current_time_ms();
        if let Some(contact_id) = self.identity_to_contact.get(&identity_id).cloned() {
            // Zaten bilinen identity — spec 2.2 karar ağacı burada da geçerli
            // olurdu (yeni cihaz mı, bilinen mi); QR/manuel eşleşme akışında
            // basitçe TOFU ekleme davranışıyla devam ediyoruz.
            if let Some(contact) = self.contacts.get_mut(&contact_id) {
                if !contact.is_known_active(&device_fingerprint) {
                    contact.add_device_unverified(device_fingerprint, now);
                }
            }
            if let Some(contact) = self.contacts.get(&contact_id) {
                self.persist_contact(contact);
            }
            return Ok(());
        }

        let contact_id = format!("contact-{}", &identity_id[..16.min(identity_id.len())]);
        let mut contact = Contact::new(contact_id.clone(), device_name, identity_id.clone());
        contact.add_device_unverified(device_fingerprint, now);
        self.identity_to_contact.insert(identity_id, contact_id.clone());
        self.persist_contact(&contact);
        self.contacts.insert(contact_id, contact);
        Ok(())
    }

    /// bkz. dosya başı düzeltme notu: `contacts` tablosu önceden hiç
    /// yazılmıyordu — kişi listesi süreç yeniden başladığında (app
    /// güncellemesi dahil) kayboluyordu. Her mutasyon noktasından
    /// (register_contact_from_pairing, evaluate_sender_device,
    /// accept_pending_device_alert) çağrılır.
    fn persist_contact(&self, contact: &Contact) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let known_devices_json = match serde_json::to_string(&contact.known_devices) {
            Ok(j) => j,
            Err(e) => { error!("Contact known_devices serileştirilemedi: {}", e); return; }
        };
        let _ = conn.execute(
            "INSERT OR REPLACE INTO contacts (contact_id, display_name, trusted_identity_id, known_devices_json, last_device_change, avatar_jpeg)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                contact.contact_id, contact.display_name, contact.trusted_identity_id,
                known_devices_json, contact.last_device_change.map(|v| v as i64), contact.avatar_jpeg,
            ],
        );
    }

    /// Açılışta DB'de kayıtlı tüm kişileri `self.contacts`/
    /// `self.identity_to_contact`'a geri yükler.
    fn load_contacts_from_db(&mut self) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let mut stmt = match conn.prepare(
            "SELECT contact_id, display_name, trusted_identity_id, known_devices_json, last_device_change, avatar_jpeg FROM contacts"
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ))
        });
        let mut loaded = Vec::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (contact_id, display_name, trusted_identity_id, known_devices_json, last_device_change, avatar_jpeg) = row;
                let known_devices: Vec<contact::KnownDevice> = serde_json::from_str(&known_devices_json).unwrap_or_default();
                loaded.push(Contact {
                    contact_id,
                    display_name,
                    trusted_identity_id,
                    known_devices,
                    last_device_change: last_device_change.map(|v| v as u64),
                    avatar_jpeg,
                });
            }
        }
        for contact in loaded {
            self.identity_to_contact.insert(contact.trusted_identity_id.clone(), contact.contact_id.clone());
            self.contacts.insert(contact.contact_id.clone(), contact);
        }
    }

    /// bkz. `persist_contact` dosya başı notu — `known_remote_devices`
    /// (bilinen uzak cihazların PUBLIC key'leri; secret değildir, şifreleme
    /// gerekmez) de aynı sebeple hiç kalıcı değildi. İmza doğrulama ve
    /// yeniden el sıkışma bu kayıtlara bağımlı olduğundan, bunlar
    /// kaybolunca (süreç yeniden başlayınca) var olan bir kişiyle mesajlaşma
    /// bile YENİ bir IdentityExchange'e kadar mümkün değildi.
    fn persist_remote_device(&self, device: &DeviceRecord) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let _ = conn.execute(
            "INSERT OR REPLACE INTO remote_devices
             (device_fingerprint, identity_id, sign_pk_ed25519, sign_pk_mldsa, kem_pk_x25519, kem_pk_mlkem,
              device_name, is_active, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                device.device_fingerprint, device.identity_id,
                device.sign_pubkey_ed25519, device.sign_pubkey_mldsa,
                device.kem_pubkey_x25519, device.kem_pubkey_mlkem,
                device.device_name, device.is_active as i32, device.last_seen as i64,
            ],
        );
    }

    fn load_remote_devices_from_db(&mut self) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let mut stmt = match conn.prepare(
            "SELECT device_fingerprint, identity_id, sign_pk_ed25519, sign_pk_mldsa, kem_pk_x25519, kem_pk_mlkem,
                    device_name, is_active, last_seen FROM remote_devices"
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                row.get::<_, String>(6)?, row.get::<_, i32>(7)?, row.get::<_, i64>(8)?,
            ))
        });
        let mut loaded = Vec::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (fp, identity_id, sign_pk_ed, sign_pk_mldsa, kem_pk_x, kem_pk_mlkem, device_name, is_active, last_seen) = row;
                loaded.push(DeviceRecord {
                    device_fingerprint: fp,
                    identity_id,
                    sign_pubkey_ed25519: sign_pk_ed,
                    sign_pubkey_mldsa: sign_pk_mldsa,
                    kem_pubkey_x25519: kem_pk_x,
                    kem_pubkey_mlkem: kem_pk_mlkem,
                    device_name,
                    is_active: is_active != 0,
                    last_seen: last_seen as u64,
                });
            }
        }
        for device in loaded {
            self.known_remote_devices.insert(device.device_fingerprint.clone(), device);
        }
    }

    // ---------------------------------------------------------------
    // Bölüm 2: TOFU + cihaz değişikliği tespiti
    // ---------------------------------------------------------------

    /// Gelen bir paketin gönderen cihazına spec 2.2 karar ağacını uygular.
    /// `sender_device_known_pubkeys`: bu fonksiyon çağrılmadan önce
    /// karşı taraftan indirilmiş/bilinen olmalı (imza doğrulaması için).
    fn evaluate_sender_device(&mut self, identity_id: &str, device_fingerprint: &str, has_valid_signed_device_add: bool, device_name_hint: &str) -> DeviceCheckOutcome {
        let contact_id = self.identity_to_contact.get(identity_id).cloned();
        let contact = contact_id.as_ref().and_then(|id| self.contacts.get(id));
        let outcome = check_incoming_device(contact, device_fingerprint, has_valid_signed_device_add);

        let now = current_time_ms();
        match outcome {
            DeviceCheckOutcome::NewContactTofu => {
                let _ = self.register_contact_from_pairing(identity_id.to_string(), device_fingerprint.to_string(), device_name_hint.to_string());
            }
            DeviceCheckOutcome::NewDeviceViaSignedAdd => {
                if let Some(cid) = &contact_id {
                    if let Some(c) = self.contacts.get_mut(cid) {
                        c.add_device_via_signed_chain(device_fingerprint.to_string(), now);
                    }
                    if let Some(c) = self.contacts.get(cid) {
                        self.persist_contact(c);
                    }
                }
                // Spec 2.2: "sadece bilgi bildirimi gösterilir" — alarm değil.
                info!("Identity {} yeni bir cihaz ekledi: {}", identity_id, device_fingerprint);
            }
            DeviceCheckOutcome::UnverifiedNewDeviceAlert => {
                let display_name = contact_id
                    .as_ref()
                    .and_then(|cid| self.contacts.get(cid))
                    .map(|c| c.display_name.clone())
                    .unwrap_or_else(|| identity_id.to_string());
                let known_codes: Vec<String> = contact_id
                    .as_ref()
                    .and_then(|cid| self.contacts.get(cid))
                    .map(|c| c.known_devices.iter()
                        .filter_map(|d| hex::decode(&d.device_fingerprint).ok())
                        .map(|raw| identity::format_short_code(&raw))
                        .collect())
                    .unwrap_or_default();
                let new_code = hex::decode(device_fingerprint)
                    .map(|raw| identity::format_short_code(&raw))
                    .unwrap_or_else(|_| device_fingerprint.to_string());

                self.pending_device_alerts.insert(device_fingerprint.to_string(), DeviceAlertInfo {
                    contact_display_name: display_name,
                    identity_id: identity_id.to_string(),
                    new_device_fingerprint: device_fingerprint.to_string(),
                    known_device_short_codes: known_codes,
                    new_device_short_code: new_code,
                });
                // Spec: "BLOKLA (yeni mesaj gönderme/alma durur)" — paket bu
                // cihazdan/bu cihaza işlenmez, `pending_device_alerts`
                // içinde bekler; kullanıcı UI'dan kabul/red etmeli.
            }
            DeviceCheckOutcome::KnownActive => {}
        }
        outcome
    }

    /// Kullanıcı uyarı ekranında "Yeniden doğrula ve kabul et" dediğinde
    /// çağrılır (spec 2.2).
    fn accept_pending_device_alert(&mut self, device_fingerprint: &str) -> Result<(), String> {
        let alert = self.pending_device_alerts.remove(device_fingerprint)
            .ok_or("No pending alert for this device")?;
        let contact_id = self.identity_to_contact.get(&alert.identity_id).cloned()
            .ok_or("Unknown contact")?;
        if let Some(c) = self.contacts.get_mut(&contact_id) {
            c.add_device_unverified(device_fingerprint.to_string(), current_time_ms());
        }
        if let Some(c) = self.contacts.get(&contact_id) {
            self.persist_contact(c);
        }
        Ok(())
    }

    /// Kullanıcı "Reddet" dediğinde (varsayılan davranış — spec 2.2).
    fn reject_pending_device_alert(&mut self, device_fingerprint: &str) {
        self.pending_device_alerts.remove(device_fingerprint);
    }

    fn list_pending_device_alerts(&self) -> Vec<DeviceAlertInfo> {
        self.pending_device_alerts.values().cloned().collect()
    }

    /// UI'nin "kiminle sohbet başlatayım" seçici listesi için bilinen
    /// kişileri döner. Her kişi için, o identity'nin bilinen (Aşama A'da
    /// tek) Active cihaz fingerprint'ini de içerir — sohbet ekranı bu
    /// fingerprint'i `sendMessage`'a hedef olarak geçer.
    fn list_contacts(&self) -> Vec<ContactSummary> {
        self.contacts.values().map(|c| ContactSummary {
            contact_id: c.contact_id.clone(),
            display_name: c.display_name.clone(),
            identity_id: c.trusted_identity_id.clone(),
            active_device_fingerprint: self.resolve_active_device_for_identity(&c.trusted_identity_id),
            avatar_hex: c.avatar_jpeg.as_ref().map(|a| hex::encode(a)),
        }).collect()
    }

    /// Kendi profil fotoğrafımızı (varsa) döner — Ayarlar ekranının mevcut
    /// fotoğrafı gösterebilmesi için.
    fn get_own_avatar(&self) -> Option<Vec<u8>> {
        let conn = self.db.as_ref()?;
        let identity_id = self.identity.as_ref()?.identity_id.clone();
        conn.query_row(
            "SELECT avatar_jpeg FROM identities WHERE id = ?1",
            params![identity_id],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        ).ok().flatten()
    }

    /// Kendi profil fotoğrafımızı ayarlar/kaldırır (`avatar_jpeg: None`) ve
    /// BİLİNEN HER kişiye (P2P'de merkezi bir dizin olmadığı için tek tek)
    /// yeni `MessageContent::ProfileUpdate` gönderir. bkz. packet.rs notu —
    /// bu, otomatik her bağlantıda DEĞİL, sadece kullanıcı fotoğrafı
    /// değiştirdiğinde tetiklenir (spam önleme).
    fn set_own_profile_picture(&mut self, avatar_jpeg: Option<Vec<u8>>) -> Result<(), String> {
        let identity_id = self.identity.as_ref().ok_or("Kimlik yok")?.identity_id.clone();
        if let Some(conn) = &self.db {
            conn.execute(
                "UPDATE identities SET avatar_jpeg = ?1 WHERE id = ?2",
                params![avatar_jpeg, identity_id],
            ).map_err(|e| e.to_string())?;
        }
        let content = MessageContent::ProfileUpdate { avatar_jpeg };
        let peer_fps: Vec<String> = self.contacts.values()
            .flat_map(|c| c.known_devices.iter().map(|d| d.device_fingerprint.clone()))
            .collect();
        for fp in peer_fps {
            if let Err(e) = self.send_message_content(fp.clone(), &content, None) {
                error!("ProfileUpdate gönderilemedi ({}): {}", fp, e);
            }
        }
        Ok(())
    }

    /// Spec dışı, kullanıcı tarafından istenen "sohbeti temizle" (yumuşak
    /// seçenek): sadece yerel mesaj/ek geçmişini (diskteki `.enc` blob'ları
    /// dahil) siler — eşleşme/ratchet oturumu KORUNUR, kişi listede kalır,
    /// sohbet boş başlar. bkz. `delete_contact` (sert seçenek).
    fn clear_chat_history(&mut self, contact_id: &str) -> Result<(), String> {
        let contact = self.contacts.get(contact_id).ok_or("Kişi bulunamadı")?.clone();
        let fingerprints: Vec<String> = contact.known_devices.iter().map(|d| d.device_fingerprint.clone()).collect();
        if let Some(conn) = &self.db {
            for fp in &fingerprints {
                if let Ok(mut stmt) = conn.prepare("SELECT file_id FROM files WHERE peer_device_fingerprint = ?1") {
                    if let Ok(rows) = stmt.query_map(params![fp], |r| r.get::<_, String>(0)) {
                        for file_id in rows.flatten() {
                            if let Ok(path) = self.enc_path_for(&file_id) {
                                let _ = std::fs::remove_file(path);
                            }
                        }
                    }
                }
                let _ = conn.execute("DELETE FROM messages WHERE peer_device_fingerprint = ?1", params![fp]);
                let _ = conn.execute("DELETE FROM files WHERE peer_device_fingerprint = ?1", params![fp]);
            }
        }
        Ok(())
    }

    /// Spec dışı, kullanıcı tarafından istenen "kişiyi sil" (sert seçenek,
    /// UI'da çift onaylı): eşleşme/ratchet oturumu DAHİL her şeyi siler —
    /// yeniden mesajlaşmak için taze bir QR/manuel eşleşme gerekir. bkz.
    /// `clear_chat_history` (yumuşak seçenek, sadece geçmişi siler).
    fn delete_contact(&mut self, contact_id: &str) -> Result<(), String> {
        let contact = self.contacts.remove(contact_id).ok_or("Kişi bulunamadı")?;
        self.identity_to_contact.remove(&contact.trusted_identity_id);
        let fingerprints: Vec<String> = contact.known_devices.iter().map(|d| d.device_fingerprint.clone()).collect();
        for fp in &fingerprints {
            if let Some(state) = self.ratchets.remove(fp) {
                // bkz. `topic_for_root_key` dokümantasyonu — oturum
                // silindiğinde artık dinlenmesine gerek kalmayan topic'ten
                // aboneliği de iptal et (küçük bir hijyen adımı, gizlilik
                // açısından zorunlu değil ama gereksiz aboneliği bırakmamak
                // için).
                self.resubscribe_ratchet_topic(Some(&state.root_key), None);
            }
            self.device_to_peer_id.remove(fp);
            self.device_last_addr.remove(fp);
            self.recent_handshake_sigs.remove(fp);
            self.clear_persisted_skipped_keys(fp);
            self.awaiting_confirmation.retain(|_, pc| &pc.peer_device_fingerprint != fp);
            self.active_downloads.retain(|_, d| &d.peer_device_fingerprint != fp);
        }
        if let Some(conn) = &self.db {
            for fp in &fingerprints {
                if let Ok(mut stmt) = conn.prepare("SELECT file_id FROM files WHERE peer_device_fingerprint = ?1") {
                    if let Ok(rows) = stmt.query_map(params![fp], |r| r.get::<_, String>(0)) {
                        for file_id in rows.flatten() {
                            if let Ok(path) = self.enc_path_for(&file_id) {
                                let _ = std::fs::remove_file(path);
                            }
                        }
                    }
                }
                let _ = conn.execute("DELETE FROM messages WHERE peer_device_fingerprint = ?1", params![fp]);
                let _ = conn.execute("DELETE FROM files WHERE peer_device_fingerprint = ?1", params![fp]);
                let _ = conn.execute("DELETE FROM ratchet_states WHERE peer_device_fingerprint = ?1", params![fp]);
                let _ = conn.execute("DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1", params![fp]);
                let _ = conn.execute("DELETE FROM device_addrs WHERE device_fingerprint = ?1", params![fp]);
            }
            let _ = conn.execute("DELETE FROM contacts WHERE contact_id = ?1", params![contact_id]);
        }
        Ok(())
    }

    /// Spec dışı, güvenlik denetimi düzeltmesi: önceden `Contact::
    /// revoke_device`/`DeviceRecord.is_active` her ikisi de VARDI ama
    /// hiçbir çağıran onları gerçekten `false`/`Revoked` yapmıyordu — bir
    /// cihaz asla iptal edilemiyordu (bkz. SECURITY.md). Bu, `delete_contact`
    /// (kişiyi TAMAMEN siler) ile AYNI temizlik adımlarını yapar ama
    /// kişiyi/geçmişi SİLMEZ — sadece bu TEK cihaz fingerprint'inden
    /// gelecek/giden her şeyi durdurur (`receive_message`/
    /// `process_handshake_init`'teki yeni `is_active` kontrolü sayesinde).
    /// Aynı kişinin BAŞKA bilinen bir cihazı varsa (spec 1.6 çoklu cihaz
    /// senaryosu) o etkilenmez.
    fn revoke_contact_device(&mut self, contact_id: &str, device_fingerprint: &str) -> Result<(), String> {
        let contact = self.contacts.get_mut(contact_id).ok_or("Kişi bulunamadı")?;
        contact.revoke_device(device_fingerprint, current_time_ms());
        if let Some(c) = self.contacts.get(contact_id) {
            self.persist_contact(c);
        }

        if let Some(record) = self.known_remote_devices.get_mut(device_fingerprint) {
            record.is_active = false;
        }
        if let Some(record) = self.known_remote_devices.get(device_fingerprint) {
            self.persist_remote_device(record);
        }

        if let Some(state) = self.ratchets.remove(device_fingerprint) {
            self.resubscribe_ratchet_topic(Some(&state.root_key), None);
        }
        self.device_to_peer_id.remove(device_fingerprint);
        // İptal edilen cihaza artık yeniden bağlanmayı deneme (bkz.
        // reconnect_sweep — zaten is_active=false olduğundan atlanır, ama
        // kalıcı adres ipucunu da temizliyoruz).
        self.device_last_addr.remove(device_fingerprint);
        self.recent_handshake_sigs.remove(device_fingerprint);
        self.clear_persisted_skipped_keys(device_fingerprint);
        self.awaiting_confirmation.retain(|_, pc| pc.peer_device_fingerprint != device_fingerprint);
        self.active_downloads.retain(|_, d| d.peer_device_fingerprint != device_fingerprint);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM ratchet_states WHERE peer_device_fingerprint = ?1", params![device_fingerprint]);
            let _ = conn.execute("DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1", params![device_fingerprint]);
            let _ = conn.execute("DELETE FROM device_addrs WHERE device_fingerprint = ?1", params![device_fingerprint]);
        }
        Ok(())
    }

    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): kullanıcının Ayarlar'dan elle ekleyebileceği,
    /// güvendiği/kendi işlettiği bir röle adresi (ör. sabit IP'li bir VPS,
    /// Node modu açık). Bu, sıfırdan bir kişiyle hiç ortak röle geçmişi
    /// olmayan iki YABANCI'nın ilk kez farklı ağlardan eşleşebilmesini
    /// GARANTİ eden tek yol — organik keşif (identify/QR paylaşımı,
    /// `known_relay_peers`) ancak ağda zaten bilinen bir röle varsa işler.
    fn add_known_relay_address(&mut self, multiaddr: &str) -> Result<(), String> {
        let addr: Multiaddr = multiaddr.trim().parse().map_err(|_| "Geçersiz multiaddr".to_string())?;
        let peer_id = extract_peer_id(&addr).ok_or("Adres bir /p2p/<peer_id> son eki içermeli")?;
        if let Some(swarm) = &mut self.swarm {
            swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
        }
        self.record_known_relay(peer_id, addr);
        Ok(())
    }

    /// Groups tab GUI'sinin listesi için — bkz. `GroupSummary` notu.
    fn list_groups(&self) -> Vec<GroupSummary> {
        let own_identity_id = self.identity.as_ref().map(|i| i.identity_id.clone()).unwrap_or_default();
        self.groups.values().map(|g| GroupSummary {
            group_id: g.group_id.clone(),
            name: g.name.clone(),
            founder_identity_id: g.founder_identity_id.clone(),
            is_founder: g.founder_identity_id == own_identity_id,
            member_identity_ids: g.member_identity_ids(),
            avatar_hex: g.avatar_jpeg.as_ref().map(|a| hex::encode(a)),
        }).collect()
    }

    // ---------------------------------------------------------------
    // Bölüm 3: Hibrit KEM + Double Ratchet
    // ---------------------------------------------------------------

    /// Spec dışı: ChatActivity'nin "bağlanılıyor..." göstergesini ne zaman
    /// gizleyeceğini bilebilmesi için — bir ratchet oturumu var mı.
    fn has_active_session(&self, peer_device_fingerprint: &str) -> bool {
        self.ratchets.contains_key(peer_device_fingerprint)
    }

    /// Spec dışı: GERÇEK canlı bağlantı durumu — `has_active_session`'ın
    /// aksine (o sadece "bir ratchet oturumu kuruldu mu" sorusuna cevap
    /// verir, bir kez kurulunca SÜRESİZ true kalır, kriptografik bir
    /// durumdur, ağ bağlantısından bağımsızdır), bu fonksiyon `Swarm`'ın
    /// KENDİ canlı bağlantı defterine (`is_connected`) bakar. Önceden
    /// ChatActivity'nin durum yazısı `has_active_session`'ı kullanıyordu —
    /// bu yüzden karşı taraf aslında erişilemez olsa bile (ratchet bir kez
    /// kurulduktan sonra) hep "Bağlı" gösteriyordu. `device_to_peer_id`'de
    /// hiç kayıt yoksa (bu süreç boyunca o cihazdan hiç paket alınmadıysa)
    /// `false` döner.
    fn is_peer_connected(&self, peer_device_fingerprint: &str) -> bool {
        let peer_id = match self.device_to_peer_id.get(peer_device_fingerprint) {
            Some(pid) => pid,
            None => return false,
        };
        self.swarm.as_ref().map(|s| s.is_connected(peer_id)).unwrap_or(false)
    }

    /// Spec dışı sağlamlaştırma: kullanıcı bir sohbeti AÇAR açmaz (henüz
    /// mesaj yazmadan) el sıkışmayı proaktif olarak başlatır — önceden
    /// handshake sadece İLK `sendMessage` çağrısında (lazily) tetikleniyordu,
    /// bu da "sohbeti aç, hemen yaz, mesaj git(mesin)" senaryosunda
    /// kullanıcıya hiçbir bağlanma göstergesi olmadan mesaj kaybı riski
    /// yaratıyordu. Zaten bir oturum varsa no-op.
    fn ensure_handshake(&mut self, peer_device_fingerprint: &str) -> Result<(), String> {
        // Spec dışı, ağ sağlamlığı: oturum olsun olmasın, o an CANLI bir
        // bağlantı yoksa hemen yeniden bağlanmayı dene — reconnect_sweep'in
        // bir sonraki turunu (≤15 sn) beklemeden. Sohbet açılışında/mesaj
        // öncesinde en hızlı iyileşme yolu.
        self.ensure_connected(peer_device_fingerprint);
        if self.has_active_session(peer_device_fingerprint) {
            return Ok(());
        }
        self.initiate_handshake_with(peer_device_fingerprint)
    }

    /// Spec dışı, ağ sağlamlığı düzeltmesi: belirtilen cihaza o an CANLI bir
    /// libp2p bağlantısı yoksa VE kalıcı bir adres ipucumuz varsa hemen
    /// (senkron, sweep'i beklemeden) yeniden bağlanmayı başlatır. Bağlıysa
    /// veya adres yoksa no-op. `ensure_handshake` ve mesaj gönderme yolundan
    /// çağrılır — kopmuş bir kişiye anında yeniden bağlanma için.
    fn ensure_connected(&mut self, device_fingerprint: &str) {
        let addr_str = match self.device_last_addr.get(device_fingerprint) {
            Some(a) => a.clone(),
            None => return,
        };
        let parsed = match addr_str.parse::<Multiaddr>() {
            Ok(a) => a,
            Err(_) => return,
        };
        let peer_id = match extract_peer_id(&parsed) {
            Some(p) => p,
            None => return,
        };
        let connected = self.swarm.as_ref().map(|s| s.is_connected(&peer_id)).unwrap_or(false);
        if connected {
            return;
        }
        self.dial_with_relay_fallback(peer_id, Some(parsed));
    }

    fn initiate_handshake_with(&mut self, peer_device_fingerprint: &str) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let peer = self.known_remote_devices.get(peer_device_fingerprint).cloned()
            .ok_or("Unknown peer device; complete key exchange first")?;

        // Spec dışı, hata ayıklama düzeltmesi: `DeviceRatchetState::initiate`
        // burada "Bad Kyber/X25519 public key length" ile başarısız olursa
        // bu KALICI bir hatadır (bozuk/uyumsuz anahtar verisi — ör. bu kayıt
        // Category 3->5 (ML-KEM-768->1024) geçişinden ÖNCE, ya da karşı
        // taraf hâlâ eski bir uygulama sürümüyle eşleşmişken oluşmuş) —
        // network sorunlarının aksine yeniden denemekle ASLA düzelmez.
        // Önceden bu, `send_message_content`'in HER çağrısında (mesaj,
        // typing indicator, profil güncellemesi, geçmiş senkronu — hepsi
        // aynı yoldan geçiyor) sessizce logcat'e yazılıyor, kullanıcı
        // arayüzüne HİÇ yansımıyordu — "bağlanamıyorum" şikayetine hiçbir
        // ipucu vermiyordu. Artık bu peer için İLK KEZ görülüyorsa (veya
        // hata metni değiştiyse) `attachment_events` üzerinden bir kerelik
        // bir olay olarak bildiriliyor (bkz. `handshake_failure_notified`).
        let (state, kyber_ct, own_kyber_pub) = match DeviceRatchetState::initiate(
            &peer.kem_pubkey_x25519,
            &peer.kem_pubkey_mlkem,
        ) {
            Ok(v) => v,
            Err(e) => {
                if self.handshake_failure_notified.get(peer_device_fingerprint) != Some(&e) {
                    self.handshake_failure_notified.insert(peer_device_fingerprint.to_string(), e.clone());
                    self.attachment_events.push(serde_json::json!({
                        "type": "handshake_failed", "peer": peer_device_fingerprint, "error": e
                    }).to_string());
                }
                return Err(e);
            }
        };
        // El sıkışma bu turda başarıyla kuruldu — daha önce bu peer için
        // bildirilmiş kalıcı bir hata varsa artık geçersiz, temizle (ör.
        // kişi silinip yeniden eşleştirildi ve bu sefer anahtar uzunluğu
        // doğru).
        self.handshake_failure_notified.remove(peer_device_fingerprint);

        // KRİTİK: `state.own_x25519_secret`, `DeviceRatchetState::initiate()`
        // içinde ÜRETİLEN TAZE EPHEMERAL secret'tir ve DH hesaplaması zaten
        // BUNUNLA yapıldı (ratchet.rs). Karşı tarafa (HandshakeInit'te)
        // gönderilecek "initiator_x25519_pubkey" da AYNI ephemeral secret'ten
        // türetilmeli — önceden yanlışlıkla `own_keys.kem_sk_x25519`
        // (cihazın UZUN VADELİ kimlik anahtarı, tamamen farklı bir keypair)
        // kullanılıyordu. Bu durumda responder tarafı `respond()` içinde
        // initiator'ın gönderdiği (yanlış/uzun-vadeli) public key'e karşı DH
        // yapıyor, initiator ise kendi tarafında EPHEMERAL secret'le DH
        // yapmış oluyordu — iki taraf asla aynı paylaşılan sırra ulaşamıyor,
        // bu da HER mesajda "Decryption failed" ile sonuçlanıyordu.
        let initiator_x25519_pub = X25519PublicKey::from(&state.own_x25519_secret).as_bytes().to_vec();
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;

        let timestamp = current_time_ms();
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&initiator_x25519_pub);
        to_sign.extend_from_slice(&own_kyber_pub);
        to_sign.extend_from_slice(&kyber_ct);
        to_sign.extend_from_slice(&timestamp.to_be_bytes());
        let sig_classical: Ed25519Signature = own_keys.sign_sk_ed25519.sign(&to_sign);
        let sig_pq: MlDsaSignature<MlDsa87> = own_keys.sign_sk_mldsa.sign(&to_sign);

        let handshake = HandshakeInit {
            sender_identity_id: own_identity_id,
            sender_device_fingerprint: own_fp,
            initiator_x25519_pubkey: initiator_x25519_pub,
            initiator_kyber_pubkey: own_kyber_pub,
            kyber_ciphertext: kyber_ct,
            timestamp,
            signature_classical: sig_classical.to_bytes().to_vec(),
            signature_pq: sig_pq.encode().to_vec(),
        };

        self.resubscribe_ratchet_topic(None, Some(&state.root_key));
        self.ratchets.insert(peer_device_fingerprint.to_string(), state);
        self.persist_ratchet_state(peer_device_fingerprint);
        self.publish_envelope(peer_device_fingerprint, &NetworkEnvelope::Handshake(handshake))
    }

    // NOT: Skipped-key'ler burada (yeni oturum kurulurken) diskten
    // yüklenmiyor çünkü bu YENİ bir el sıkışma — DB'de bu cihaz-çifti için
    // henüz hiçbir skipped-key kaydı olamaz (yeni oturumda mesaj numarası
    // sıfırdan başlar). Skipped-key diske yazma/silme, sadece bir oturum
    // İÇİNDEYKEN (receive_message'ta) gerçekleşir.
    //
    // Ratchet state'in TAMAMI (root_key/ck_send/ck_recv/own+peer anahtarlar/
    // sayaçlar) artık `ratchet_states` tablosuna (skipped_key_encryption_key
    // ile şifreli) kalıcı hale getiriliyor — bkz. `persist_ratchet_state`/
    // `load_ratchet_states_from_db`. Süreç yeniden başladığında (uygulama
    // güncellemesi, arka plan öldürme vb.) `init_db` sonrası
    // `setSkippedKeyEncryptionKey` çağrıldığı an bu oturumlar geri yüklenir
    // — yeniden el sıkışma gerekmez, geçmişte alınan gecikmeli/atlanmış
    // mesaj anahtarları da (skipped_message_keys tablosundan) hâlâ geçerli
    // kalır.

    fn process_handshake_init(&mut self, handshake: &HandshakeInit) -> Result<(), String> {
        let sender = self.known_remote_devices.get(&handshake.sender_device_fingerprint).cloned()
            .ok_or("Unknown sender device; cannot verify signatures")?;
        // Spec dışı, güvenlik denetimi düzeltmesi: önceden `is_active`
        // hiçbir yerde kontrol edilmiyordu — bu alanı hiçbir zaman false
        // yapan bir çağrı yolu da olmadığından pratikte etkisizdi. Artık
        // `revoke_contact_device` gerçekten `false` yapabiliyor VE burada
        // gerçekten uygulanıyor: iptal edilmiş bir cihazdan gelen bir el
        // sıkışma reddedilir.
        if !sender.is_active {
            return Err("Sender device has been revoked".to_string());
        }

        // bkz. receive_message'teki aynı kimlik-bağı düzeltmesi: imza sadece
        // cihazın imzaladığını kanıtlar, header'daki identity_id'nin o cihaza
        // ait olduğunu değil — kayıtlı (TOFU) bağla eşleşmeyi zorunlu kıl.
        if handshake.sender_identity_id != sender.identity_id {
            return Err("HandshakeInit sender_identity_id, kayıtlı cihaz kimliğiyle eşleşmiyor".to_string());
        }

        let mut to_verify = Vec::new();
        to_verify.extend_from_slice(&handshake.initiator_x25519_pubkey);
        to_verify.extend_from_slice(&handshake.initiator_kyber_pubkey);
        to_verify.extend_from_slice(&handshake.kyber_ciphertext);
        to_verify.extend_from_slice(&handshake.timestamp.to_be_bytes());
        verify_hybrid_signature(&to_verify, &handshake.signature_classical, &handshake.signature_pq, &sender)?;

        // Spec dışı, güvenlik denetimi düzeltmesi (el sıkışma tekrar oynatma
        // → oturum sıfırlama DoS'u): gossipsub `Signed` modu, ağdaki bir
        // gözlemcinin YAKALADIĞI geçerli bir `HandshakeInit`'i yeniden
        // yayınlamasına izin verir. Bu fonksiyon (aşağıda) mevcut bir
        // ratchet'i taze bir `respond` state'iyle EZDİĞİ için, böyle bir
        // tekrar canlı bir konuşmayı koparabilirdi. İki katmanlı savunma
        // (bkz. `recent_handshake_sigs` alan notu):
        // (1) freshness penceresi — çok eski/çok ileri timestamp reddedilir
        //     (yakalanmış eski el sıkışmaları eler, saat kaymasına tolerans);
        // (2) içerik dedup — aynı imzalı (bayt-aynısı) el sıkışma pencerede
        //     ikinci kez uygulanmaz. Gerçek bir yeniden-eşleşme taze efemeral
        //     anahtarlar → farklı imza taşıdığından, saat kayması ne olursa
        //     olsun kabul edilir (monoton-timestamp'in re-pair'i kırma riski
        //     olmadan).
        let now = current_time_ms();
        let skew = now.abs_diff(handshake.timestamp);
        if skew > HANDSHAKE_MAX_SKEW_MS {
            return Err(format!(
                "HandshakeInit timestamp'i pencere dışında (sapma {} ms > {} ms) — muhtemel tekrar oynatma, reddedildi",
                skew, HANDSHAKE_MAX_SKEW_MS
            ));
        }
        {
            let seen = self.recent_handshake_sigs.entry(handshake.sender_device_fingerprint.clone()).or_default();
            // Pencereden eski girdileri buda (sınırsız büyümeyi önle).
            seen.retain(|(ts, _)| now.abs_diff(*ts) <= HANDSHAKE_MAX_SKEW_MS);
            if seen.iter().any(|(_, sig)| sig == &handshake.signature_classical) {
                info!(
                    "HandshakeInit yok sayıldı (peer={}) — aynı imza pencerede zaten görüldü (tekrar oynatma/çift paket)",
                    handshake.sender_device_fingerprint
                );
                return Ok(());
            }
        }

        let own_fp = self.get_active_own_device_fingerprint()?;

        // KRİTİK: eşzamanlı el sıkışma çakışması. İki cihaz da (ör. ikisi
        // de uygulamayı yeniden başlatıp aynı sohbeti aynı anda açtığında,
        // `ensure_handshake` ikisinde de `has_active_session == false`
        // bulur) TAM AYNI ANDA birbirine `HandshakeInit` gönderirse: her
        // iki taraf da KENDİ `initiate_handshake_with` çağrısında ÖNCE bir
        // "initiator" ratchet state'i oluşturup `self.ratchets`'e yazar,
        // SONRA karşı taraftan gelen HandshakeInit'i işlerken (burada) bu
        // state'i bir "responder" state'iyle EZER. Sorun: responder modu,
        // KENDİ uzun-vadeli kimlik KEM anahtarını (`own_keys.kem_sk_*`)
        // karşı tarafın EPHEMERAL (geçici, o el sıkışmaya özel) public
        // key'iyle DH/decapsulate eder — iki taraf da bunu yaparsa,
        // türetilen paylaşımlı sırlar birbiriyle UYUŞMAZ (DH'nin simetri
        // özelliği yalnızca "A'nın ephemeral'ı + B'nin kimliği" ile "B'nin
        // kimliği + A'nın ephemeral'ı" ÇAPRAZ eşleştiğinde geçerlidir, iki
        // tarafın da kendi kimliğini kullanması bu simetriyi bozar). Sonuç:
        // TÜM sonraki mesajlar "Decryption failed"/"skipped-key cache'te
        // yok" ile başarısız olur — QR yeniden tarama, çakışmayı kırıp
        // tek taraflı bir el sıkışma zorladığı için "düzeltiyormuş" gibi
        // görünür.
        //
        // Deterministik çözüm: fingerprint'i (hex string, karşılaştırılabilir)
        // KÜÇÜK olan taraf "kanonik initiator" sayılır. Eğer az önce KENDİ
        // (henüz hiç mesaj taşımamış — bkz. `send_message_number`/
        // `recv_message_number` sıfır kontrolü) initiator state'imiz varsa
        // VE bizim fingerprint'imiz karşı tarafınkinden KÜÇÜKSE, bu gelen
        // HandshakeInit'i YOK SAYARIZ (kendi initiator state'imizi koruruz)
        // — karşı taraf (fingerprint'i büyük olan), simetrik olarak BİZİM
        // HandshakeInit'imizi kabul edip doğru responder state'ini üretecektir.
        if let Some(existing) = self.ratchets.get(&handshake.sender_device_fingerprint) {
            let existing_unused = existing.send_message_number == 0 && existing.recv_message_number == 0;
            if existing_unused && own_fp < handshake.sender_device_fingerprint {
                info!(
                    "Eşzamanlı el sıkışma çakışması (peer={}) — kendi initiator state'imiz korunuyor (küçük fingerprint kuralı)",
                    handshake.sender_device_fingerprint
                );
                return Ok(());
            }
        }

        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;

        let state = DeviceRatchetState::respond(
            own_keys.kem_sk_x25519.clone(),
            own_keys.kem_sk_mlkem.clone(),
            &handshake.initiator_x25519_pubkey,
            &handshake.initiator_kyber_pubkey,
            &handshake.kyber_ciphertext,
        )?;

        self.resubscribe_ratchet_topic(None, Some(&state.root_key));
        self.ratchets.insert(handshake.sender_device_fingerprint.clone(), state);
        self.persist_ratchet_state(&handshake.sender_device_fingerprint);
        // Kabul edilen el sıkışmanın imzasını dedup setine ekle (bkz.
        // recent_handshake_sigs) — aynı paketin tekrarı artık yok sayılır.
        self.recent_handshake_sigs
            .entry(handshake.sender_device_fingerprint.clone())
            .or_default()
            .push((handshake.timestamp, handshake.signature_classical.clone()));
        Ok(())
    }

    /// Aktif sohbete girmeden önce/mesaj gönderirken çağrılır. `should_rotate()`
    /// Signal'ın gerçek modelini uyguluyor (bkz. ratchet.rs): 30 dakika
    /// dolmuş VE biz henüz karşı tarafın güncel public key'ine cevap
    /// vermemişsek (`has_responded_to_peer_key == false`) rotasyonu BİZ
    /// tetikleriz. Aksi halde (cevap zaten verilmişse, sıradaki rotasyon
    /// hakkı karşı tarafta) hiçbir şey yapmayız — deterministik bir
    /// "fingerprint küçük olan tetikler" kuralına gerek yok, çünkü
    /// `has_responded_to_peer_key` bayrağı zaten hangi tarafın sırası
    /// geldiğini doğal olarak belirliyor.
    fn maybe_rotate_ratchet(&mut self, peer_device_fingerprint: &str) -> Result<Option<Vec<u8>>, String> {
        let should_rotate = self.ratchets.get(peer_device_fingerprint).map(|s| s.should_rotate()).unwrap_or(false);
        if !should_rotate {
            return Ok(None);
        }
        if let Some(state) = self.ratchets.get_mut(peer_device_fingerprint) {
            let old_root_key = state.root_key.clone();
            let kyber_ct = state.perform_dh_ratchet()?;
            let new_root_key = state.root_key.clone();
            // bkz. `topic_for_root_key` dokümantasyonu — root_key
            // değiştiği için gossipsub topic'i de eskisinden aboneliği
            // iptal edip yenisine abone olarak takip etmeli.
            self.resubscribe_ratchet_topic(Some(&old_root_key), Some(&new_root_key));
            // Biz rotasyonu tetikledik — eski zincire ait diskteki
            // skipped-key'ler de anlamsızlaştı (bkz. receive_message'daki
            // simetrik temizlik respond_to_rotation için).
            self.clear_persisted_skipped_keys(peer_device_fingerprint);
            self.persist_ratchet_state(peer_device_fingerprint);
            return Ok(Some(kyber_ct));
        }
        Ok(None)
    }

    /// `send_message`/`edit_message`/`delete_message`'ın ortak gövdesi —
    /// üçü de aynı ratchet-şifreli `MessagePacket` yolundan geçer, sadece
    /// çözüldükten sonraki `MessageContent` türü farklıdır (bkz. packet.rs
    /// dokümantasyonu — edit/delete de tam uçtan uca şifreli/imzalı olsun
    /// diye ayrı bir zarf yerine bu ortak yol kullanılıyor).
    /// `archive_plaintext`: SADECE düz metin mesajlar için Some — edit/delete
    /// şu an yerel (node modu) arşive yansıtılmıyor (bkz. dosya sonu not).
    /// Başarılıysa bu mesajın `message_id`'sini döner — çağıran taraf
    /// (Kotlin) bunu ileride edit/delete hedefi olarak saklayabilir.
    /// Dönüş: `(message_id, durum_string)` — durum "sent" (hemen
    /// gönderildi) veya "pending" (geçici olarak kuyrukta, arka planda
    /// yeniden denenecek) olabilir. Bkz. `MessageSendStatus`.
    fn send_message_content(&mut self, peer_device_fingerprint: String, content: &MessageContent, archive_plaintext: Option<&[u8]>) -> Result<(String, String), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();

        // Spec dışı, ağ sağlamlığı: gönderim yolunda, karşı tarafa canlı bir
        // bağlantı yoksa hemen yeniden bağlanmayı tetikle — böylece gossipsub
        // publish, bağlantı kurulur kurulmaz (pending_envelopes retry'siyle)
        // başarılı olur, reconnect_sweep'in bir sonraki turunu beklemeden.
        self.ensure_connected(&peer_device_fingerprint);

        if !self.ratchets.contains_key(&peer_device_fingerprint) {
            // `initiate_handshake_with` ratchet state'i publish denemesinden
            // ÖNCE oluşturur (bkz. o fonksiyon) — bu yüzden HandshakeInit'in
            // KENDİ gönderimi (aşağıdaki `publish_envelope` gibi) geçici
            // olarak başarısız olsa bile burada durmuyoruz: state zaten var,
            // asıl mesajı şifreleyip göndermeye devam edebiliriz.
            // HandshakeInit'in kendisi başarısız olduysa `publish_envelope`
            // onu kendi içinde yeniden deneme kuyruğuna zaten ekledi.
            if let Err(e) = self.initiate_handshake_with(&peer_device_fingerprint) {
                error!("Handshake gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
            }
            // KNOWN GAP (aynı önceki tasarımdan miras): handshake ve mesaj
            // ardışık gönderiliyor, gossipsub sıra garantisi vermiyor.
        }

        let rotation_kyber_ciphertext = self.maybe_rotate_ratchet(&peer_device_fingerprint)?;

        let state = self.ratchets.get_mut(&peer_device_fingerprint).ok_or("No ratchet session")?;
        // NOT: `own_ratchet_pubkeys()` rotasyon SONRASI çağrılıyor
        // (maybe_rotate_ratchet zaten çalıştı), bu yüzden rotasyon olduysa
        // burada YENİ public key'ler alınır — karşı tarafın
        // respond_to_rotation'da beklediği tam olarak budur.
        let ratchet_pubkeys = state.own_ratchet_pubkeys();
        let content_bytes = ciborium_bytes(content)?;
        let (ciphertext, message_number, prev_chain_length) = state.encrypt_next(&content_bytes)?;
        // `encrypt_next` her çağrıda ck_send/send_message_number'ı ilerletir
        // — diskteki kopya bayatlamasın diye her mesajda kalıcılaştırıyoruz
        // (rotasyon olduysa `maybe_rotate_ratchet` zaten yukarıda ayrıca
        // yazdı, bu ikinci yazma zararsız/idempotent bir üst kaplama).
        self.persist_ratchet_state(&peer_device_fingerprint);

        let message_id = uuid::Uuid::new_v4().to_string();
        let header = MessagePacketHeader {
            sender_identity_id: own_identity_id,
            sender_device_fingerprint: own_fp.clone(),
            message_id: message_id.clone(),
            ratchet_pubkey: ratchet_pubkeys.to_bytes()?,
            message_number,
            prev_chain_length,
            rotation_kyber_ciphertext,
        };

        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&ciborium_bytes(&header)?);
        to_sign.extend_from_slice(&ciphertext);
        let sig_classical: Ed25519Signature = own_keys.sign_sk_ed25519.sign(&to_sign);
        let sig_pq: MlDsaSignature<MlDsa87> = own_keys.sign_sk_mldsa.sign(&to_sign);

        let packet = MessagePacket {
            header,
            ciphertext,
            signature_classical: sig_classical.to_bytes().to_vec(),
            signature_pq: sig_pq.encode().to_vec(),
        };

        // Spec dışı düzeltme: önceden SADECE node modu açık cihazlarda
        // arşivleniyordu (o zamanki kullanıcı tercihi) — kullanıcı artık
        // açıkça TÜM cihazlarda (node olsun olmasın) kendi sohbet
        // geçmişinin yerelde şifreli kalıcı kılınmasını istedi; node modu
        // artık SADECE "karşı taraflara geçmiş senkronizasyon isteklerinde
        // yardımcı olma" (bkz. HistorySyncRequest) ve DHT routing
        // katılımını etkiliyor, kendi geçmişini SAKLAMA kararını değil.
        // Ağ paketinin kendisi zaten uçtan uca şifreli; bu AYRI bir
        // "dinlenme hâlinde şifreleme" katmanıdır (bkz. archive_message —
        // `history_key` artık node modundan bağımsız her zaman yüklü,
        // bkz. P2PService/MessageHistoryManager).
        if let Some(plaintext) = archive_plaintext {
            let _ = self.archive_message(&peer_device_fingerprint, "sent", plaintext);
        }

        // Spec dışı, kullanıcı tarafından istenen güvenilir teslim:
        // Text (grup DIŞI)/Edit/Delete/HistorySyncRequest, karşı taraftan
        // bir onay (Ack veya HistorySyncResponse) gelene kadar SÜRESİZ
        // yeniden gönderilir (bkz. `awaiting_confirmation` dokümantasyonu)
        // — `gossipsub.publish()`'in yerel başarısı karşı tarafın GERÇEKTEN
        // aldığının garantisi değildir, bu yüzden tek seferlik/zaman
        // sınırlı `publish_envelope`/`pending_envelopes` yetersizdi (bazı
        // mesajlar/düzenlemeler/silmeler hiç karşı tarafa ulaşmadan
        // sessizce "gönderildi" sayılıyordu). Diğer içerik türleri (Ack,
        // HistorySyncResponse, FileOffer, grup mesajları) eski davranışı
        // (tek seferlik, kısa süreli yeniden deneme) korur — Ack zaten
        // kendisi onaylanmıyor (sonsuz döngü riski), grup mesajlarının
        // N-yönlü fan-out'u bu mekanizmayı karmaşıklaştırırdı (bilinen
        // sınır, ileride genişletilebilir).
        // `FileOffer` de dahil: bu paket kaybolursa (aynı ağ
        // güvenilmezliği, bkz. dosya başı not), alıcı bir dosya
        // teklif edildiğini HİÇBİR ZAMAN öğrenemez ve ek balonu hiç
        // görünmez — dosya parça transferinin (request_response,
        // attachments.rs) KENDİ güvenilirliği (chunk-seviyeli yeniden
        // deneme) bu METADATA mesajını kapsamıyordu, ayrı bir sorun.
        let needs_delivery_confirmation = matches!(
            content,
            MessageContent::Text { group_id: None, .. }
                | MessageContent::Edit { .. }
                | MessageContent::Delete { .. }
                | MessageContent::HistorySyncRequest { .. }
                | MessageContent::FileOffer { .. }
                | MessageContent::SaveRequest { .. }
                | MessageContent::SaveApproval { .. }
                | MessageContent::GroupUpdate(_)
        );
        // Ack, kendisi ONAYLANMASA da (bkz. packet.rs notu — sonsuz döngü
        // riski) artık SINIRLI sayıda yeniden dener (bkz.
        // `ACK_SELF_MAX_RETRIES`) — tek seferlik fire-and-forget'in kayıp
        // bir Ack'i asla telafi edememesi, gönderen tarafın orijinal
        // mesajı SÜRESİZ (artık alıcının ratchet'inde tüketilmiş bir
        // mesaj numarasına karşı, dolayısıyla ASLA başarılı olamayacak
        // şekilde) yeniden göndermeye devam etmesine yol açıyordu (bkz.
        // gerçek arıza deseni: sürekli tekrar eden "Decryption failed"/
        // "skipped-key cache'te yok" logları).
        // `Seen`, `Ack` ile AYNI gerekçeyle (sonsuz "onayı onayla" döngüsü
        // riski) kendisi onaylanmaz ama sınırlı sayıda kendi-kendine
        // yeniden dener — bkz. packet.rs `Seen` dokümantasyonu.
        let is_ack_like = matches!(content, MessageContent::Ack { .. } | MessageContent::Seen { .. });
        if needs_delivery_confirmation {
            self.publish_with_ack_tracking(&peer_device_fingerprint, &message_id, NetworkEnvelope::Message(packet), None);
        } else if is_ack_like {
            self.publish_with_ack_tracking(&peer_device_fingerprint, &message_id, NetworkEnvelope::Message(packet), Some(ACK_SELF_MAX_RETRIES));
        } else if let Err(e) = self.publish_envelope(&peer_device_fingerprint, &NetworkEnvelope::Message(packet)) {
            error!("Mesaj gönderimi geçici olarak başarısız (yeniden denenecek): {}", e);
        }
        let status = self.message_status.get(&message_id).copied().unwrap_or(MessageSendStatus::Pending);
        Ok((message_id, status.as_str().to_string()))
    }

    fn send_message(&mut self, peer_device_fingerprint: String, plaintext: String) -> Result<(String, String), String> {
        let content = MessageContent::Text { group_id: None, text: plaintext.clone(), group_message_local_id: None };
        self.send_message_content(peer_device_fingerprint, &content, Some(plaintext.as_bytes()))
    }

    /// Spec dışı: bir mesajı düzenler. `target_message_id`, düzenlenecek
    /// mesajın `MessagePacketHeader.message_id`'sidir (gönderirken dönen
    /// değer). Karşı taraf, bu `message_id`'ye sahip bir mesajı daha önce
    /// gördüyse UI'da güncellemelidir (bkz. ChatActivity).
    fn edit_message(&mut self, peer_device_fingerprint: String, target_message_id: String, new_text: String) -> Result<(String, String), String> {
        let content = MessageContent::Edit { target_message_id, new_text };
        self.send_message_content(peer_device_fingerprint, &content, None)
    }

    /// Spec dışı: bir mesajı siler (karşı tarafa "sil" bildirimi gönderir).
    fn delete_message(&mut self, peer_device_fingerprint: String, target_message_id: String) -> Result<(String, String), String> {
        let content = MessageContent::Delete { target_message_id };
        self.send_message_content(peer_device_fingerprint, &content, None)
    }

    fn receive_message(&mut self, packet: &MessagePacket) -> Result<String, String> {
        let sender = self.known_remote_devices.get(&packet.header.sender_device_fingerprint).cloned()
            .ok_or("Unknown sender device; cannot verify signatures")?;
        // bkz. process_handshake_init aynı notu — güvenlik denetimi
        // düzeltmesi, artık gerçekten uygulanıyor.
        if !sender.is_active {
            return Err("Sender device has been revoked".to_string());
        }

        // Spec dışı, güvenlik denetimi düzeltmesi (kimlik sahteciliği): imza
        // SADECE bu paketi `sender` CİHAZININ imzaladığını kanıtlar —
        // header'daki `sender_identity_id` alanının o cihaza AİT güvenilen
        // Identity olduğunu KANITLAMAZ. Cihaz→Identity bağı eşleşme (TOFU)
        // anında kaydedilir (`DeviceRecord.identity_id`); header'daki
        // değerin bununla eşleştiğini burada zorlamazsak, eşleşmiş bir cihaz
        // header'a BAŞKA bir kişinin identity_id'sini yazıp grup mesajlarında
        // o kişiyi taklit edebilir (bkz. group_message kolu) VEYA bir
        // `ProfileUpdate`'i başka bir kişiye yönlendirip onun avatarını
        // ezebilir (bkz. ProfileUpdate kolu — `identity_to_contact` lookup'ı
        // bu alana güveniyordu). Artık uyuşmazlık paketi tamamen reddediyor.
        if packet.header.sender_identity_id != sender.identity_id {
            return Err("sender_identity_id, imzalayan cihazın kayıtlı kimliğiyle eşleşmiyor".to_string());
        }

        let mut to_verify = Vec::new();
        to_verify.extend_from_slice(&ciborium_bytes(&packet.header)?);
        to_verify.extend_from_slice(&packet.ciphertext);
        verify_hybrid_signature(&to_verify, &packet.signature_classical, &packet.signature_pq, &sender)?;

        // Rotasyon senkronizasyonu (spec 3.2, artık gerçek): gönderen bu
        // mesajla birlikte bir DH/KEM rotasyonu tetiklediyse
        // (rotation_kyber_ciphertext dolu), biz de kendi tarafımızda aynı
        // yeni anahtarları türetmek için respond_to_rotation çağırırız.
        // Boşsa (normal mesaj, rotasyon yok) hiçbir şey yapmayız —
        // ratchet_pubkey zaten her mesajda taşınır ama rotasyon olmadıkça
        // değişmez, bu yüzden onu görmezden gelmek güvenlidir.
        if let Some(ct) = &packet.header.rotation_kyber_ciphertext {
            if let Ok(new_peer_keys) = RatchetPublicKeys::from_bytes(&packet.header.ratchet_pubkey) {
                // `rotated_keys`: rotasyon başarılıysa (eski, yeni) root_key
                // çifti — bu bloktan sonra, `self.ratchets`'in mutable
                // borrow'u tamamen bittikten sonra `self.resubscribe_ratchet_topic`
                // (ki `&mut self`'in TAMAMINI ister) güvenle çağrılabilsin diye
                // ayrı bir adım olarak çıkarıldı.
                let rotated_keys: Option<(Vec<u8>, Vec<u8>)> = if let Some(state) =
                    self.ratchets.get_mut(&packet.header.sender_device_fingerprint)
                {
                    let old_root_key = state.root_key.clone();
                    match state.respond_to_rotation(&new_peer_keys, ct) {
                        Ok(()) => Some((old_root_key, state.root_key.clone())),
                        Err(e) => {
                            error!("Rotasyon senkronizasyonu başarısız: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };
                if let Some((old_root_key, new_root_key)) = rotated_keys {
                    // bkz. `topic_for_root_key` dokümantasyonu — karşı taraf
                    // rotasyonu tetikledi, biz de aynı şekilde gossipsub
                    // topic aboneliğimizi yeni root_key'e taşıyoruz.
                    self.resubscribe_ratchet_topic(Some(&old_root_key), Some(&new_root_key));
                    // Rotasyon başarılıysa eski zincire ait diskteki
                    // skipped-key'ler de anlamsızlaştı — temizle.
                    self.clear_persisted_skipped_keys(&packet.header.sender_device_fingerprint);
                    self.persist_ratchet_state(&packet.header.sender_device_fingerprint);
                }
            }
        }

        let state = self.ratchets.get_mut(&packet.header.sender_device_fingerprint)
            .ok_or("No ratchet session for sender")?;
        let (payload_bytes, skipped_changes) = state.decrypt(&packet.ciphertext, packet.header.message_number)?;
        let content: MessageContent = ciborium::from_reader(payload_bytes.as_slice()).map_err(|e| e.to_string())?;
        // `decrypt` her çağrıda ck_recv/recv_message_number'ı ilerletir —
        // diskteki kopyayı güncel tut (bkz. send_message_content'teki aynı
        // notun karşılığı).
        self.persist_ratchet_state(&packet.header.sender_device_fingerprint);

        // Skipped-key değişikliklerini diske (Keystore ile şifreli) yansıt.
        for (msg_num, key) in &skipped_changes.added {
            if let Err(e) = self.persist_skipped_key(&packet.header.sender_device_fingerprint, *msg_num, key) {
                error!("Skipped-key diske yazılamadı: {}", e);
            }
        }
        for msg_num in &skipped_changes.used {
            self.delete_persisted_skipped_key(&packet.header.sender_device_fingerprint, *msg_num);
        }

        let peer_fp = packet.header.sender_device_fingerprint.clone();
        let sender_identity_id = packet.header.sender_identity_id.clone();
        let message_id = packet.header.message_id.clone();

        // Spec dışı: `pollNetwork`'ün Kotlin tarafına döndürdüğü her satır
        // artık düz metin DEĞİL, `{"type":...}` etiketli bir JSON olayı —
        // bkz. P2PService/ChatActivity. Bu, edit/delete'i aynı String
        // kanalından (JNI imzasını değiştirmeden) taşıyabilmek ve mesajın
        // HANGİ karşı tarafa (peer) ait olduğunu iletebilmek için gerekli —
        // önceden bu bilgi hiç taşınmıyordu (bkz. eski "cross-chat sızıntısı"
        // notu: birden çok sohbet varken gelen her mesaj, o an açık olan
        // HANGİ ChatActivity ise ona ekleniyordu, doğru olanına değil).
        let event = match content {
            MessageContent::Text { group_id: None, text, .. } => {
                // bkz. send_message_content'teki aynı düzeltme notu —
                // artık node modundan bağımsız her cihaz kendi geçmişini
                // yerelde şifreli tutuyor.
                let _ = self.archive_message(&peer_fp, "received", text.as_bytes());
                self.send_ack(&peer_fp, &message_id);
                serde_json::json!({"type": "message", "peer": peer_fp, "message_id": message_id, "text": text})
            }
            MessageContent::Text { group_id: Some(gid), text, group_message_local_id } => {
                // Gerçek grup entegrasyonu: bu, bir grup mesajının pairwise
                // fan-out kopyası — GroupChatActivity'nin doğru sohbete
                // yönlendirebilmesi için `group_id` VE göndericinin
                // `identity_id`'si (bir grupta birden fazla kişi olduğundan
                // "kim gönderdi" bilgisi 1:1'in aksine zorunlu) taşınıyor.
                // `group_message_local_id`: Kotlin bu mesajı "gördü" olarak
                // işaretlerken (bkz. Seen) geri göndermesi gereken kimlik —
                // `message_id` göndericiye anlamsız (bkz. packet.rs notu),
                // sadece bu paylaşılan kimlik her N kopya arasında ortak.
                serde_json::json!({
                    "type": "group_message", "group_id": gid, "peer": peer_fp,
                    "sender_identity_id": sender_identity_id,
                    "message_id": message_id, "text": text,
                    "group_message_local_id": group_message_local_id
                })
            }
            MessageContent::Edit { target_message_id, new_text } => {
                self.send_ack(&peer_fp, &message_id);
                serde_json::json!({"type": "edit", "peer": peer_fp, "message_id": target_message_id, "text": new_text})
            }
            MessageContent::Delete { target_message_id } => {
                self.send_ack(&peer_fp, &message_id);
                serde_json::json!({"type": "delete", "peer": peer_fp, "message_id": target_message_id})
            }
            MessageContent::HistorySyncRequest { limit } => {
                // `load_message_history` zaten `history_key` yüklenmemişse
                // (node modu hiç açılmadıysa) veya bu peer için arşiv yoksa
                // boş liste döner — burada ayrıca `node_mode_enabled`
                // kontrolüne gerek yok. Bu bir orijinal kullanıcı mesajı
                // değil, kontrol paketi — kendi arşivimize TEKRAR yazılmaz
                // (archive_plaintext: None, bkz. send_message_content).
                let history = self.load_message_history(&peer_fp, limit);
                let messages: Vec<(String, String, u64)> = history.into_iter()
                    .map(|m| (m.direction, m.text, m.timestamp))
                    .collect();
                // `request_id`, isteyen tarafın bu yanıtı doğru
                // `awaiting_confirmation` girdisine eşleyip yeniden
                // deneme kuyruğundan çıkarabilmesi için isteğin KENDİ
                // `message_id`'sini taşır (bkz. packet.rs notu).
                let response = MessageContent::HistorySyncResponse { request_id: message_id.clone(), messages };
                if let Err(e) = self.send_message_content(peer_fp.clone(), &response, None) {
                    error!("HistorySyncResponse gönderilemedi: {}", e);
                }
                serde_json::json!({"type": "history_sync_requested", "peer": peer_fp})
            }
            MessageContent::HistorySyncResponse { request_id, messages } => {
                // Bu yanıt geldi — göndericinin (bizim) o isteği artık
                // yeniden denemesine gerek yok (bkz. `awaiting_confirmation`
                // dokümantasyonu).
                self.awaiting_confirmation.remove(&request_id);
                // `messages`'in direction'ı YANITLAYANIN (arşivi tutan
                // node'un) bakış açısıyla geldi — bizim ekranımız için ters
                // çevrilmeli: onların "sent"i bizim "received"imiz, onların
                // "received"i bizim "sent"imiz.
                //
                // Spec dışı düzeltme: senkronla gelen mesajlar önceden
                // SADECE bu ekranın o anki bellek-içi listesine ekleniyordu
                // — kalıcı hiçbir kayıt bırakmıyordu, geçmiş her sohbet
                // açılışında ağdan yeniden çekilmek zorundaydı. Artık HER
                // cihaz (node olsun olmasın, bkz. send_message_content/
                // yukarıdaki Text kolu notu) kendi canlı trafiğini zaten
                // yerelde arşivliyor — burada `latest_archived_timestamp`
                // ile SADECE zaten sahip OLMADIĞIMIZ (daha yeni) mesajlar
                // yazılıyor, aksi halde her sohbet açılışında (artık her
                // zaman senkron denendiği için) aynı satırlar tekrar tekrar
                // eklenip yinelenen kayıtlar oluşurdu.
                let already_have_since = self.latest_archived_timestamp(&peer_fp);
                let flipped: Vec<serde_json::Value> = messages.into_iter().map(|(direction, text, timestamp)| {
                    let our_direction = if direction == "sent" { "received" } else { "sent" };
                    if already_have_since.map(|t| timestamp > t as u64).unwrap_or(true) {
                        let _ = self.archive_message(&peer_fp, our_direction, text.as_bytes());
                    }
                    serde_json::json!({"direction": our_direction, "text": text, "timestamp": timestamp})
                }).collect();
                serde_json::json!({"type": "history_sync", "peer": peer_fp, "messages": flipped})
            }
            MessageContent::FileOffer { group_id, file_id, file_name, mime_type, total_size, file_key, sha256_hex, preview_jpeg, duration_ms } => {
                self.send_ack(&peer_fp, &message_id);
                self.receive_file_offer(&peer_fp, group_id, &file_id, &file_name, &mime_type, total_size, &file_key, &sha256_hex, &preview_jpeg, duration_ms)
            }
            MessageContent::Ack { target_message_id } => {
                // Karşı taraf bizim gönderdiğimiz bir Text/Edit/Delete/
                // HistorySyncRequest'i başarıyla aldı — o paketi artık
                // yeniden denemeyi bırakabiliriz (bkz.
                // `awaiting_confirmation` dokümantasyonu).
                self.awaiting_confirmation.remove(&target_message_id);
                serde_json::json!({"type": "ack", "peer": peer_fp, "message_id": target_message_id})
            }
            MessageContent::Seen { target_message_id, group_message_local_id } => {
                // bkz. packet.rs `Seen` notu — teslim (Ack) değil, GÖRME
                // bildirimi. Kendisi ayrıca onaylanmaz (Ack'le aynı sonsuz
                // döngü gerekçesi).
                serde_json::json!({
                    "type": "seen", "peer": peer_fp,
                    "sender_identity_id": sender_identity_id,
                    "message_id": target_message_id,
                    "group_message_local_id": group_message_local_id
                })
            }
            MessageContent::TypingIndicator { is_typing } => {
                // Kasitli olarak: arsivlenmez, Ack GONDERILMEZ (bkz.
                // packet.rs notu) -- birkac saniyede bayatlayan bir bilgi
                // icin tekrar deneme/onay trafiginin hicbir degeri yok.
                serde_json::json!({"type": "typing", "peer": peer_fp, "is_typing": is_typing})
            }
            MessageContent::ProfileUpdate { avatar_jpeg } => {
                self.send_ack(&peer_fp, &message_id);
                if let Some(cid) = self.identity_to_contact.get(&sender_identity_id).cloned() {
                    if let Some(c) = self.contacts.get_mut(&cid) {
                        c.avatar_jpeg = avatar_jpeg.clone();
                    }
                    if let Some(c) = self.contacts.get(&cid) {
                        self.persist_contact(c);
                    }
                }
                serde_json::json!({
                    "type": "profile_update", "peer": peer_fp,
                    "avatar_hex": avatar_jpeg.as_ref().map(|a| hex::encode(a))
                })
            }
            MessageContent::GroupUpdate(update) => {
                // Spec dışı, güvenlik denetimi düzeltmesi: artık ratchet-
                // şifreli kanaldan geliyor (bkz. packet.rs notu) — bu, DIŞ
                // paketin (`MessagePacket`) zaten hibrit doğrulanmış
                // göndericisi (`sender_identity_id`/`peer_fp`) İLE
                // `update.signed_by`'nin AYNI kişi olması gerekmediği
                // anlamına gelir (ör. kurucu olmayan bir üye de bu paketi
                // pairwise iletebilir, sadece bu kod tabanında henüz
                // relay yok) — asıl yetki kontrolü `process_group_update`
                // içindeki KENDİ (ayrıca hibrit) `update.signature`/
                // `signature_pq` doğrulaması ve `signed_by == founder`
                // kısıtıdır, dış paket imzası sadece taşıma bütünlüğünü
                // garanti eder.
                let group_id = update.group_id.clone();
                match self.process_group_update(&update) {
                    Ok(()) => {
                        self.send_ack(&peer_fp, &message_id);
                        serde_json::json!({"type": "group_updated", "peer": peer_fp, "group_id": group_id})
                    }
                    Err(e) => {
                        error!("GroupUpdate işlenemedi: {}", e);
                        serde_json::json!({"type": "group_update_failed", "peer": peer_fp, "group_id": group_id, "error": e})
                    }
                }
            }
            MessageContent::SaveRequest { file_id, file_name } => {
                // Biz GÖNDERİCİYİZ — karşı taraf (alıcı), indirdiği bu eki
                // kalıcı/paylaşılan bir konuma kaydetmek istiyor, bizim
                // onayımızı bekliyor (kullanıcı tarafından istenen akış).
                self.send_ack(&peer_fp, &message_id);
                serde_json::json!({"type": "save_request", "peer": peer_fp, "file_id": file_id, "file_name": file_name})
            }
            MessageContent::SaveApproval { file_id, approved } => {
                // Biz ALICIYIZ — gönderdiğimiz SaveRequest'e cevap geldi.
                self.send_ack(&peer_fp, &message_id);
                serde_json::json!({"type": "save_response", "peer": peer_fp, "file_id": file_id, "approved": approved})
            }
        };
        Ok(event.to_string())
    }

    /// bkz. `MessageContent::Ack` dokümantasyonu (packet.rs) — Text (grup
    /// dışı)/Edit/Delete/HistorySyncRequest başarıyla işlendiğinde
    /// gönderene geri gönderilir. Fire-and-forget: bu çağrının kendisi
    /// `send_message_content`'in normal (kısa süreli, `pending_envelopes`
    /// tabanlı) yolundan geçer — Ack'in KENDİSİ `awaiting_confirmation`'a
    /// eklenmez (sonsuz döngü riski, bkz. packet.rs notu).
    fn send_ack(&mut self, peer_device_fingerprint: &str, target_message_id: &str) {
        let content = MessageContent::Ack { target_message_id: target_message_id.to_string() };
        if let Err(e) = self.send_message_content(peer_device_fingerprint.to_string(), &content, None) {
            error!("Ack gönderilemedi: {}", e);
        }
    }

    /// Spec dışı, kullanıcı tarafından istenen "görüldü" bildirimi —
    /// `send_ack` ile AYNI desen (bkz. packet.rs `Seen` notu). `Ack`'in
    /// aksine OTOMATİK değil: Kotlin tarafı, mesajı kullanıcıya EKRANDA
    /// gösterdiği anda çağırmalı (bkz. ChatActivity/GroupChatActivity).
    fn send_seen(&mut self, peer_device_fingerprint: &str, target_message_id: &str, group_message_local_id: Option<String>) {
        let content = MessageContent::Seen {
            target_message_id: target_message_id.to_string(),
            group_message_local_id,
        };
        if let Err(e) = self.send_message_content(peer_device_fingerprint.to_string(), &content, None) {
            error!("Görüldü bildirimi gönderilemedi: {}", e);
        }
    }

    /// Spec dışı: "yazıyor..." göstergesi. bkz. `MessageContent::TypingIndicator`
    /// dokümantasyonu (packet.rs) — arşivlenmez, güvenilir teslim
    /// kuyruğuna girmez, fire-and-forget.
    fn send_typing_indicator(&mut self, peer_device_fingerprint: String, is_typing: bool) -> Result<(), String> {
        let content = MessageContent::TypingIndicator { is_typing };
        self.send_message_content(peer_device_fingerprint, &content, None).map(|_| ())
    }

    /// Spec dışı, kullanıcı tarafından istenen akış: bir eki kalıcı/
    /// paylaşılan bir konuma ("İndirilenler/P2P") kaydetmeden önce
    /// göndericiden onay ister.
    fn request_save_approval(&mut self, file_id: String, peer_device_fingerprint: String, file_name: String) -> Result<(), String> {
        let content = MessageContent::SaveRequest { file_id, file_name };
        self.send_message_content(peer_device_fingerprint, &content, None).map(|_| ())
    }

    /// Göndericinin, gelen bir `SaveRequest`'e (kullanıcının Evet/Hayır
    /// dokunuşuyla) cevabı.
    fn respond_to_save_request(&mut self, file_id: String, peer_device_fingerprint: String, approved: bool) -> Result<(), String> {
        let content = MessageContent::SaveApproval { file_id, approved };
        self.send_message_content(peer_device_fingerprint, &content, None).map(|_| ())
    }

    /// Spec dışı: node modu kapalı bir cihazda sohbet ekranı hiç yerel
    /// geçmiş bulamadığında çağrılır (bkz. ChatActivity
    /// `loadHistoryIfAvailable`) — karşı tarafa (chat peer) şifreli bir
    /// `HistorySyncRequest` gönderir. Yanıt asenkron gelir (bir sonraki
    /// `pollNetwork` turunda `{"type":"history_sync",...}` olayı olarak).
    fn request_history_sync(&mut self, peer_device_fingerprint: String, limit: u32) -> Result<(), String> {
        let content = MessageContent::HistorySyncRequest { limit };
        self.send_message_content(peer_device_fingerprint, &content, None).map(|_| ())
    }

    /// Bir mesajı yerel arşive ekler. İki çağıran senaryosu var: (1) canlı
    /// mesaj trafiği — SADECE node modu açıkken çağrılır (kullanıcı
    /// tercihi, bkz. çağıran taraflardaki `node_mode_enabled` kontrolü);
    /// (2) `HistorySyncResponse` — node modu KAPALI cihazlarda da, senkron
    /// yoluyla öğrenilen geçmişi yerelde kalıcı kılmak için çağrılır (bkz.
    /// receive_message notu). `history_key` yüklenmemişse (Kotlin henüz
    /// Keystore'dan çözüp vermemişse) sessizce atlar — arşivleme best-effort,
    /// mesajlaşmanın kendisini asla engellemez.
    fn archive_message(&mut self, peer_device_fingerprint: &str, direction: &str, plaintext: &[u8]) -> Result<(), String> {
        let key = match &self.history_key {
            Some(k) => *k,
            None => return Ok(()), // node modu açık ama key henüz yüklenmedi
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Ok(()),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| "Invalid history key")?;
        let mut nonce_bytes = [0u8; 12];
        {
            use rand::RngCore;
            OsRng.fill_bytes(&mut nonce_bytes);
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext).map_err(|_| "History encryption failed")?;

        conn.execute(
            "INSERT INTO messages (peer_device_fingerprint, direction, encrypted_blob, nonce, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![peer_device_fingerprint, direction, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Bir kişiyle olan mesaj geçmişini çözüp döner (en yeni `limit` mesaj,
    /// eskiden yeniye sıralı). `history_key` yoksa boş liste döner.
    fn load_message_history(&self, peer_device_fingerprint: &str, limit: u32) -> Vec<ArchivedMessage> {
        let key = match &self.history_key {
            Some(k) => *k,
            None => return Vec::new(),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut stmt = match conn.prepare(
            "SELECT direction, encrypted_blob, nonce, timestamp FROM messages
             WHERE peer_device_fingerprint = ?1 ORDER BY timestamp DESC LIMIT ?2"
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map(params![peer_device_fingerprint, limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        });

        let mut results = Vec::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (direction, encrypted_blob, nonce_bytes, timestamp) = row;
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_blob.as_slice()) {
                    if let Ok(text) = String::from_utf8(plaintext) {
                        results.push(ArchivedMessage {
                            direction,
                            text,
                            timestamp: timestamp as u64,
                        });
                    }
                }
            }
        }
        results.reverse(); // eskiden yeniye
        results
    }

    /// Bu peer için yerelde ARŞİVLENMİŞ en yeni mesajın zaman damgası
    /// (arşiv boşsa/DB yoksa `None`). `HistorySyncResponse` işlenirken,
    /// zaten sahip olduğumuz mesajları TEKRAR arşivlememek için kullanılır
    /// (bkz. receive_message notu) — aksi halde her sohbet açılışında
    /// (artık her zaman senkron denendiği için) aynı satırlar yinelenirdi.
    /// `history_key` gerektirmez (sadece zaman damgası okunuyor, şifreli
    /// içerik çözülmüyor).
    fn latest_archived_timestamp(&self, peer_device_fingerprint: &str) -> Option<i64> {
        let conn = self.db.as_ref()?;
        conn.query_row(
            "SELECT MAX(timestamp) FROM messages WHERE peer_device_fingerprint = ?1",
            params![peer_device_fingerprint],
            |row| row.get::<_, Option<i64>>(0),
        ).ok().flatten()
    }

    // ---------------------------------------------------------------
    // Skipped-message-key kalıcılığı (Double Ratchet sıra dışı mesaj
    // desteği) — bkz. ratchet.rs `skipped_keys` alanı dokümantasyonu.
    // ---------------------------------------------------------------

    /// Bir skipped-key'i (bir cihaz-çifti oturumunda atlanmış bir mesaj
    /// numarasına ait anahtar) Keystore'dan yüklenen anahtarla şifreleyip
    /// DB'ye yazar. `ratchet.rs decrypt`'in "Greater" dalında yeni bir
    /// skipped-key üretildiğinde çağrılır. Anahtar yüklenmemişse (Kotlin
    /// henüz `setSkippedKeyEncryptionKey` çağırmadıysa) sessizce atlanır —
    /// bu durumda skipped-key sadece bellekte kalır (eski davranış).
    fn persist_skipped_key(&self, peer_device_fingerprint: &str, message_number: u32, key: &[u8; 32]) -> Result<(), String> {
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return Ok(()),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return Ok(()),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key).map_err(|_| "Invalid skipped-key encryption key")?;
        let mut nonce_bytes = [0u8; 12];
        {
            use rand::RngCore;
            OsRng.fill_bytes(&mut nonce_bytes);
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, key.as_slice()).map_err(|_| "Skipped-key encryption failed")?;

        conn.execute(
            "INSERT OR REPLACE INTO skipped_message_keys (peer_device_fingerprint, message_number, encrypted_key, nonce)
             VALUES (?1, ?2, ?3, ?4)",
            params![peer_device_fingerprint, message_number, encrypted, nonce_bytes.to_vec()],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Bir skipped-key kullanıldığında (mesaj çözüldüğünde) DB'den silinir
    /// — artık tekrar gerekmeyecek (Double Ratchet'in tek-kullanımlık
    /// mesaj anahtarı prensibi diskteki kopya için de geçerli).
    fn delete_persisted_skipped_key(&self, peer_device_fingerprint: &str, message_number: u32) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1 AND message_number = ?2",
                params![peer_device_fingerprint, message_number],
            );
        }
    }

    /// Bir cihaz-çifti oturumu için DB'de kayıtlı (henüz kullanılmamış)
    /// skipped-key'leri çözüp döner. `load_ratchet_states_from_db` tarafından
    /// çağrılır — dönen map, geri yüklenen `DeviceRatchetState.skipped_keys`
    /// alanına atanır.
    fn load_skipped_keys_from_db(&self, peer_device_fingerprint: &str) -> HashMap<u32, [u8; 32]> {
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return HashMap::new(),
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return HashMap::new(),
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&enc_key) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };

        let mut stmt = match conn.prepare(
            "SELECT message_number, encrypted_key, nonce FROM skipped_message_keys WHERE peer_device_fingerprint = ?1"
        ) {
            Ok(s) => s,
            Err(_) => return HashMap::new(),
        };

        let rows = stmt.query_map(params![peer_device_fingerprint], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
        });

        let mut results = HashMap::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (message_number, encrypted_key, nonce_bytes) = row;
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, encrypted_key.as_slice()) {
                    if let Ok(key_bytes) = <[u8; 32]>::try_from(plaintext.as_slice()) {
                        results.insert(message_number, key_bytes);
                    }
                }
            }
        }
        results
    }

    /// Bir cihaz-çifti için diskte kayıtlı TÜM skipped-key'leri siler —
    /// rotasyon olduğunda (`perform_dh_ratchet`/`respond_to_rotation`,
    /// bkz. ratchet.rs) eski zincire ait skipped-key'ler anlamsız kaldığı
    /// için bellekteki `skipped_keys.clear()` ile birlikte diskten de
    /// temizlenmesi gerekir.
    fn clear_persisted_skipped_keys(&self, peer_device_fingerprint: &str) {
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "DELETE FROM skipped_message_keys WHERE peer_device_fingerprint = ?1",
                params![peer_device_fingerprint],
            );
        }
    }

    /// `self.ratchets[peer_device_fingerprint]`'i (varsa) diske şifreli
    /// olarak kalıcılaştırır — aynı `skipped_key_encryption_key` ile
    /// (`persist_skipped_key`'deki AEAD desenini birebir tekrarlar).
    /// `skipped_key_encryption_key` henüz yüklenmemişse (Kotlin
    /// `setSkippedKeyEncryptionKey` çağırmadıysa) sessizce atlar —
    /// arşivleme gibi bu da best-effort'tur, mesajlaşmanın kendisini
    /// engellemez (state bellekte zaten güncel).
    fn persist_ratchet_state(&self, peer_device_fingerprint: &str) {
        let state = match self.ratchets.get(peer_device_fingerprint) {
            Some(s) => s,
            None => return,
        };
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return,
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };

        let persistable = state.to_persistable();
        let plaintext = match ciborium_bytes(&persistable) {
            Ok(b) => b,
            Err(e) => { error!("Ratchet state serileştirilemedi: {}", e); return; }
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&enc_key) {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut nonce_bytes = [0u8; 12];
        {
            use rand::RngCore;
            OsRng.fill_bytes(&mut nonce_bytes);
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = match cipher.encrypt(nonce, plaintext.as_slice()) {
            Ok(e) => e,
            Err(_) => { error!("Ratchet state şifrelenemedi"); return; }
        };

        let _ = conn.execute(
            "INSERT OR REPLACE INTO ratchet_states (peer_device_fingerprint, encrypted_state, nonce, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![peer_device_fingerprint, encrypted, nonce_bytes.to_vec(), current_time_ms() as i64],
        );
    }

    /// Uygulama açılışında (skipped_key_encryption_key yüklendikten sonra
    /// — bkz. JNI `setSkippedKeyEncryptionKey`) DB'de kayıtlı TÜM ratchet
    /// oturumlarını çözüp `self.ratchets`'e geri yükler. Bu, süreç yeniden
    /// başladığında (app güncellemesi, arka plan öldürme) devam eden
    /// sohbetlerin YENİDEN el sıkışma gerektirmeden çalışmaya devam
    /// etmesini sağlar — önceden bu state tamamen bellek-only olduğu için
    /// her süreç yeniden başlatmasında kayboluyordu (bkz. dosya sonu not).
    fn load_ratchet_states_from_db(&mut self) {
        let enc_key = match &self.skipped_key_encryption_key {
            Some(k) => *k,
            None => return,
        };
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let cipher = match ChaCha20Poly1305::new_from_slice(&enc_key) {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut stmt = match conn.prepare(
            "SELECT peer_device_fingerprint, encrypted_state, nonce FROM ratchet_states"
        ) {
            Ok(s) => s,
            Err(_) => return,
        };

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
        });

        let mut loaded: Vec<(String, DeviceRatchetState)> = Vec::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (peer_fp, encrypted, nonce_bytes) = row;
                if nonce_bytes.len() != 12 {
                    continue;
                }
                let nonce = Nonce::from_slice(&nonce_bytes);
                let plaintext = match cipher.decrypt(nonce, encrypted.as_slice()) {
                    Ok(p) => p,
                    Err(_) => { error!("Ratchet state çözülemedi ({}), atlanıyor", peer_fp); continue; }
                };
                let persistable: ratchet::SerializableRatchetState = match ciborium::from_reader(plaintext.as_slice()) {
                    Ok(p) => p,
                    Err(e) => { error!("Ratchet state ayrıştırılamadı ({}): {}", peer_fp, e); continue; }
                };
                let skipped_keys = self.load_skipped_keys_from_db(&peer_fp);
                match DeviceRatchetState::from_persistable(persistable, skipped_keys) {
                    Ok(state) => loaded.push((peer_fp, state)),
                    Err(e) => error!("Ratchet state yeniden oluşturulamadı ({}): {}", peer_fp, e),
                }
            }
        }
        for (peer_fp, state) in loaded {
            self.ratchets.insert(peer_fp, state);
        }
    }

    // ---------------------------------------------------------------
    // Bölüm 5: Grup Mesajlaşma (pairwise)
    // ---------------------------------------------------------------

    fn create_group(&mut self, name: String) -> Result<String, String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group_id = format!("group-{}", hex::encode(&compute_fingerprint(name.as_bytes(), &current_time_ms().to_be_bytes(), b"", b""))[..16].to_string());
        let group = Group::new(group_id.clone(), name, own_identity_id, current_time_ms());
        self.persist_group(&group);
        self.groups.insert(group_id.clone(), group);
        Ok(group_id)
    }

    /// bkz. `persist_contact` dosya başı notu — `groups` tablosu da aynı
    /// şekilde hiç yazılmıyordu.
    fn persist_group(&self, group: &Group) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let members_json = match serde_json::to_string(&group.members) {
            Ok(j) => j,
            Err(e) => { error!("Group members serileştirilemedi: {}", e); return; }
        };
        let _ = conn.execute(
            "INSERT OR REPLACE INTO groups (group_id, founder, name, version, members_json, created_at, avatar_jpeg)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![group.group_id, group.founder_identity_id, group.name, group.version, members_json, group.created_at as i64, group.avatar_jpeg],
        );
    }

    fn load_groups_from_db(&mut self) {
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        let mut stmt = match conn.prepare(
            "SELECT group_id, founder, name, version, members_json, created_at, avatar_jpeg FROM groups"
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
            ))
        });
        let mut loaded = Vec::new();
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (group_id, founder, name, version, members_json, created_at, avatar_jpeg) = row;
                let members: Vec<group::GroupMember> = serde_json::from_str(&members_json).unwrap_or_default();
                loaded.push(Group {
                    group_id,
                    name,
                    founder_identity_id: founder,
                    members,
                    created_at: created_at as u64,
                    version,
                    avatar_jpeg,
                });
            }
        }
        for group in loaded {
            self.groups.insert(group.group_id.clone(), group);
        }
    }

    /// Spec 5.4: kurucu, grup daveti üretir; davet edilen kişi zaten var
    /// olan/kurulmakta olan 1:1 bağlantı üzerinden `GroupUpdate(Add)` alır.
    /// Burada: kurucu tarafında hem `members`'a ekler hem de tüm mevcut +
    /// yeni üyelere `GroupUpdate` pairwise gönderir (spec 5.2).
    fn invite_to_group(&mut self, group_id: &str, new_member_identity_id: &str) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();

        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Sadece kurucu üye ekleyebilir".to_string());
        }
        let new_version = group.version + 1;

        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let change = GroupChange::Add(new_member_identity_id.to_string());
        let update = sign_group_update(group_id, new_version, &change, &group.name, &own_identity_id, &own_fp, own_keys)?;

        // Yerel state'i güncelle.
        if let Some(g) = self.groups.get_mut(group_id) {
            apply_change(g, &change, new_version, current_time_ms());
        }
        if let Some(g) = self.groups.get(group_id) {
            self.persist_group(g);
        }

        // Tüm üyelere (yeni eklenen dahil) pairwise gönder (spec 5.2).
        let targets = self.groups.get(group_id).map(|g| g.member_identity_ids()).unwrap_or_default();
        for member_identity_id in targets {
            if member_identity_id == own_identity_id {
                continue;
            }
            if let Some(peer_fp) = self.resolve_active_device_for_identity(&member_identity_id) {
                // Spec dışı, güvenlik denetimi düzeltmesi: önceden bare/
                // şifrelenmemiş bir NetworkEnvelope::GroupUpdate olarak
                // gönderiliyordu (sadece Ed25519 imzalı, gossipsub'a AÇIK
                // METİN yayılıyordu) — artık diğer her şeyle AYNI hibrit
                // ratchet-şifreli kanaldan gidiyor (bkz. MessageContent::
                // GroupUpdate, needs_delivery_confirmation listesi).
                if let Err(e) = self.send_message_content(peer_fp, &MessageContent::GroupUpdate(update.clone()), None) {
                    error!("GroupUpdate bir üyeye gönderilemedi: {}", e);
                }
            }
        }
        Ok(())
    }

    fn remove_from_group(&mut self, group_id: &str, member_identity_id: &str) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Sadece kurucu üye çıkarabilir".to_string());
        }
        let new_version = group.version + 1;
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let change = GroupChange::Remove(member_identity_id.to_string());
        let update = sign_group_update(group_id, new_version, &change, &group.name, &own_identity_id, &own_fp, own_keys)?;

        // Çıkarılan üyeye ULAŞMADAN önce eski üye listesini al (spec 5.3:
        // çıkarılan üyeye artık GroupUpdate/grup mesajı gönderilmez).
        let remaining_targets: Vec<String> = group.other_members(&own_identity_id)
            .into_iter()
            .filter(|id| id != member_identity_id)
            .collect();

        if let Some(g) = self.groups.get_mut(group_id) {
            apply_change(g, &change, new_version, current_time_ms());
        }
        if let Some(g) = self.groups.get(group_id) {
            self.persist_group(g);
        }
        for member_identity_id in remaining_targets {
            if let Some(peer_fp) = self.resolve_active_device_for_identity(&member_identity_id) {
                // Spec dışı, güvenlik denetimi düzeltmesi: önceden bare/
                // şifrelenmemiş bir NetworkEnvelope::GroupUpdate olarak
                // gönderiliyordu (sadece Ed25519 imzalı, gossipsub'a AÇIK
                // METİN yayılıyordu) — artık diğer her şeyle AYNI hibrit
                // ratchet-şifreli kanaldan gidiyor (bkz. MessageContent::
                // GroupUpdate, needs_delivery_confirmation listesi).
                if let Err(e) = self.send_message_content(peer_fp, &MessageContent::GroupUpdate(update.clone()), None) {
                    error!("GroupUpdate bir üyeye gönderilemedi: {}", e);
                }
            }
        }
        Ok(())
    }

    /// Spec dışı: grup profil fotoğrafını ayarlar/kaldırır. `invite_to_group`/
    /// `remove_from_group` ile AYNI imzalı `GroupUpdate` mekanizmasını
    /// kullanır (`GroupChange::AvatarUpdate`) — "sadece kurucu değiştirebilir"
    /// kısıtı zaten `validate_group_update`'in `NotFounder` kontrolünden
    /// (hem burada gönderen tarafta hem de `process_group_update`'te alıcı
    /// tarafında) geçer, ayrı bir yetki kontrolü icat edilmedi.
    fn set_group_avatar(&mut self, group_id: &str, avatar_jpeg: Option<Vec<u8>>) -> Result<(), String> {
        let own_fp = self.get_active_own_device_fingerprint()?;
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if group.founder_identity_id != own_identity_id {
            return Err("Sadece kurucu profil fotoğrafını değiştirebilir".to_string());
        }
        let new_version = group.version + 1;
        let own_keys = self.own_device_keys.get(&own_fp).ok_or("Missing own keys")?;
        let change = GroupChange::AvatarUpdate(avatar_jpeg);
        let update = sign_group_update(group_id, new_version, &change, &group.name, &own_identity_id, &own_fp, own_keys)?;

        if let Some(g) = self.groups.get_mut(group_id) {
            apply_change(g, &change, new_version, current_time_ms());
        }
        if let Some(g) = self.groups.get(group_id) {
            self.persist_group(g);
        }
        let targets = group.other_members(&own_identity_id);
        for member_identity_id in targets {
            if let Some(peer_fp) = self.resolve_active_device_for_identity(&member_identity_id) {
                // Spec dışı, güvenlik denetimi düzeltmesi: önceden bare/
                // şifrelenmemiş bir NetworkEnvelope::GroupUpdate olarak
                // gönderiliyordu (sadece Ed25519 imzalı, gossipsub'a AÇIK
                // METİN yayılıyordu) — artık diğer her şeyle AYNI hibrit
                // ratchet-şifreli kanaldan gidiyor (bkz. MessageContent::
                // GroupUpdate, needs_delivery_confirmation listesi).
                if let Err(e) = self.send_message_content(peer_fp, &MessageContent::GroupUpdate(update.clone()), None) {
                    error!("GroupUpdate bir üyeye gönderilemedi: {}", e);
                }
            }
        }
        Ok(())
    }

    fn process_group_update(&mut self, update: &GroupUpdate) -> Result<(), String> {
        let signer = self.known_remote_devices.get(&update.signed_by_device).cloned()
            .ok_or("Unknown signer device")?;
        let mut to_verify = Vec::new();
        to_verify.extend_from_slice(update.group_id.as_bytes());
        to_verify.extend_from_slice(&update.new_version.to_be_bytes());
        to_verify.extend_from_slice(&ciborium_bytes(&update.change)?);
        to_verify.extend_from_slice(update.group_name.as_bytes());
        // Artık MessagePacket/HandshakeInit ile AYNI hibrit (Ed25519+ML-DSA)
        // model — bkz. sign_group_update/packet.rs GroupUpdate.signature_pq
        // notu (güvenlik denetimi düzeltmesi).
        verify_hybrid_signature(&to_verify, &update.signature, &update.signature_pq, &signer)
            .map_err(|_| "GroupUpdate signature verification failed".to_string())?;

        // signed_by_device'ın kurucunun bilinen/Active bir cihazı olup
        // olmadığını kontrol et (spec 5.2).
        let signer_is_active = signer.identity_id == update.signed_by && signer.is_active;

        let group_exists = self.groups.contains_key(&update.group_id);
        let group_snapshot = self.groups.get(&update.group_id).cloned();

        // Spec dışı düzeltme: önceden burada boş isimle ("") bir grup
        // oluşturuluyordu — `GroupUpdate` artık her zaman güncel
        // `group_name`'i taşıdığı için (bkz. packet.rs notu), ilk kez
        // görülen bir grup da doğru adla oluşturulabiliyor.
        let default_group = || Group::new(update.group_id.clone(), update.group_name.clone(), update.signed_by.clone(), current_time_ms());
        let group_ref = group_snapshot.unwrap_or_else(default_group);

        validate_group_update(&group_ref, &update.signed_by, signer_is_active, update.new_version)
            .map_err(|e| format!("{:?}", e))?;

        // Gap tespiti: bir veya daha fazla ara güncelleme kaçırıldıysa
        // (ör. Add/Remove) yerel üyelik listesi güncelin gerisinde olabilir —
        // artık kilitlenmiyoruz (bkz. group.rs StaleOrOutOfOrderVersion notu)
        // ama bunu görünür kılıyoruz.
        if group_exists && update.new_version > group_ref.version + 1 {
            error!(
                "GroupUpdate gap (group={}): yerel version {} -> gelen {} (aradaki {} güncelleme kaçırıldı; üyelik listesi eksik olabilir)",
                update.group_id, group_ref.version, update.new_version,
                update.new_version - group_ref.version - 1
            );
        }

        if !group_exists {
            self.groups.insert(update.group_id.clone(), Group::new(update.group_id.clone(), update.group_name.clone(), update.signed_by.clone(), current_time_ms()));
        }
        if let Some(g) = self.groups.get_mut(&update.group_id) {
            apply_change(g, &update.change, update.new_version, current_time_ms());
            // Her güncellemede ismi senkron tut (self-healing) — sadece
            // açık bir Rename değişikliğinde değil.
            g.name = update.group_name.clone();
        }
        if let Some(g) = self.groups.get(&update.group_id) {
            self.persist_group(g);
        }
        Ok(())
    }

    /// Bir Identity için bilinen (ve Aşama A'da tek olan) Active cihaz
    /// fingerprint'ini bulur.
    fn resolve_active_device_for_identity(&self, identity_id: &str) -> Option<String> {
        self.known_remote_devices.values()
            .find(|d| d.identity_id == identity_id && d.is_active)
            .map(|d| d.device_fingerprint.clone())
    }

    /// Dönüş: `group_message_local_id` — bu grup mesajının N üyeye giden
    /// fan-out kopyalarını TEK bir yerel kimlikte birleştiren id (bkz.
    /// packet.rs `Text.group_message_local_id` notu). Kotlin, kendi
    /// optimistic balonunu rastgele bir UUID yerine BUNU `messageId`
    /// olarak kullanmalı — aksi halde dönen "seen" bildirimleri hiçbir
    /// yerel balonla eşleşemez.
    fn send_group_message(&mut self, group_id: &str, plaintext: &str) -> Result<String, String> {
        let own_identity_id = self.identity.as_ref().ok_or("No identity")?.identity_id.clone();
        let group = self.groups.get(group_id).cloned_group()?;
        if !group.is_member(&own_identity_id) {
            return Err("Grup üyesi değilsiniz".to_string());
        }
        // Spec 5.1: her üye için ayrı ayrı, mevcut 1:1 ratchet ile şifrele.
        // `group_id: Some(...)` — gerçek grup entegrasyonu: alıcı tarafın
        // bunu sıradan bir 1:1 mesajdan ayırt edip GroupChatActivity'ye
        // yönlendirebilmesi için (bkz. receive_message notu).
        let local_id = uuid::Uuid::new_v4().to_string();
        let content = MessageContent::Text {
            group_id: Some(group_id.to_string()),
            text: plaintext.to_string(),
            group_message_local_id: Some(local_id.clone()),
        };
        for member_identity_id in group.other_members(&own_identity_id) {
            if let Some(peer_fp) = self.resolve_active_device_for_identity(&member_identity_id) {
                if let Err(e) = self.send_message_content(peer_fp, &content, Some(plaintext.as_bytes())) {
                    error!("Grup mesajı bir üyeye gönderilemedi: {}", e);
                }
            }
        }
        Ok(local_id)
    }

    // ---------------------------------------------------------------
    // Spec dışı: dosya/foto/video/ses ekleri (bkz. attachments.rs modül
    // notu, azami 4GB). Kullanıcı tercihi (bu görüşmede netleştirildi):
    // GÖNDEREN kendi node modu durumundan BAĞIMSIZ olarak gönderdiği
    // dosyanın kendi kopyasını her zaman tutar; ALICI tarafta, node modu
    // açıksa yeni bir dosya teklifi geldiğinde OTOMATİK indirilip
    // saklanır (bkz. receive_message FileOffer kolu), kapalıysa sadece
    // meta veri gösterilir ve indirme kullanıcının "İndir" dokunuşunu
    // bekler — bu, mevcut mesaj geçmişi arşivleme kuralıyla (sadece node
    // modu açıkken yerelde sakla) birebir aynı prensip, dosya baytlarına
    // genişletilmiş hâli.
    // ---------------------------------------------------------------

    fn attachments_dir(&self) -> Result<std::path::PathBuf, String> {
        let base = self.app_files_dir.as_ref().ok_or("initDatabase henüz çağrılmadı")?;
        Ok(std::path::Path::new(base).join("attachments"))
    }

    fn enc_path_for(&self, file_id: &str) -> Result<std::path::PathBuf, String> {
        Ok(self.attachments_dir()?.join(format!("{}.enc", file_id)))
    }

    /// bkz. `P2PCore.device_to_peer_id` alanı dokümantasyonu — herhangi bir
    /// gelen paketin gönderen cihaz fingerprint'i ile o paketin geldiği
    /// gossipsub `PeerId`'sini eşler. `process_incoming_envelope`'un her
    /// zarf türü için çağırdığı ortak bir yardımcı.
    fn record_peer_id_if_known(&mut self, source: Option<PeerId>, device_fingerprint: &str) {
        if let Some(pid) = source {
            self.device_to_peer_id.insert(device_fingerprint.to_string(), pid);
            // Spec dışı, ağ sağlamlığı düzeltmesi: bu cihazdan GERÇEKTEN
            // paket aldık — o an bağlı olduğumuz somut adresi (varsa,
            // `ConnectionEstablished`'ten doldurulan `peer_id_to_addr`)
            // kalıcı yeniden-bağlanma ipucu olarak sakla. Böylece bir
            // sonraki kopmada `reconnect_sweep` en son ÇALIŞAN adresi
            // kullanır (eşleşme anındaki rendezvous adresi bayatladıysa
            // bile). Adres `/p2p/<peer_id>` son eki içermiyorsa
            // `remember_device_addr` onu zaten yok sayar.
            if let Some(addr) = self.peer_id_to_addr.get(&pid).cloned() {
                // Adres zaten `/p2p/<peer_id>` içeriyorsa (giden dial'de
                // öyle kurmuştuk) tekrar ekleme — yoksa (gelen bağlantının
                // ham `/ip4/.../tcp/...` adresi) ekle.
                let addr_str = if extract_peer_id(&addr).is_some() {
                    addr.to_string()
                } else {
                    addr.with(MultiaddrProtocol::P2p(pid)).to_string()
                };
                self.remember_device_addr(device_fingerprint, &addr_str);
            }
        }
    }

    /// `attachment_key` diye AYRI bir anahtar İCAT ETMİYORUZ — bunun yerine
    /// zaten node modundan BAĞIMSIZ her zaman yüklenen
    /// `skipped_key_encryption_key`'i (bkz. o alanın dokümantasyonu) yeniden
    /// kullanıyoruz. Bu, "gönderen kendi node modundan bağımsız dosya
    /// kopyasını tutar" kuralının (dosyanın `file_key`'i her zaman diskte
    /// şifreli saklanabilmeli, node modu kapalı olsa bile) Kotlin tarafında
    /// yeni bir Keystore anahtarı/yaşam-döngüsü sınıfı gerektirmeden
    /// çalışmasını sağlar — aynı KEK, farklı küçük sırları (atlanmış mesaj
    /// anahtarları, ratchet state, şimdi de dosya anahtarları) taze
    /// nonce'larla sarmaya devam ediyor, standart bir uygulama.
    fn wrap_file_key(&self, file_key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let enc_key = self.skipped_key_encryption_key.ok_or("Şifreleme anahtarı henüz yüklenmedi")?;
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key).map_err(|_| "Invalid key")?;
        let mut nonce_bytes = [0u8; 12];
        {
            use rand::RngCore;
            OsRng.fill_bytes(&mut nonce_bytes);
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, file_key.as_slice()).map_err(|_| "File key encryption failed")?;
        Ok((encrypted, nonce_bytes.to_vec()))
    }

    fn unwrap_file_key(&self, encrypted: &[u8], nonce_bytes: &[u8]) -> Result<[u8; 32], String> {
        let enc_key = self.skipped_key_encryption_key.ok_or("Şifreleme anahtarı henüz yüklenmedi")?;
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key).map_err(|_| "Invalid key")?;
        if nonce_bytes.len() != 12 {
            return Err("Bad nonce length".to_string());
        }
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, encrypted).map_err(|_| "File key decryption failed")?;
        plaintext.as_slice().try_into().map_err(|_| "Bad file key length".to_string())
    }

    /// Kullanıcının seçtiği bir dosyayı (Kotlin tarafından zaten yerel bir
    /// yola kopyalanmış olmalı — content:// URI burada işlenmez, bkz.
    /// P2PLib.kt dokümantasyonu) şifreleyip diske yazar, kendi kaydını
    /// `files` tablosuna ekler (sender-always-keeps-copy kuralı, kendi
    /// node modumuzdan BAĞIMSIZ) ve karşı tarafa bir `FileOffer` meta veri
    /// mesajı gönderir. BİLİNEN SINIR: `encrypt_file_to_disk` bounded-
    /// memory'dir ama SENKRONdur — bu çağrı boyunca `CORE` kilidi tutulur,
    /// yani çok büyük (GB mertebesinde) bir dosya için bu süre boyunca
    /// `pollNetwork`/diğer JNI çağrıları gecikebilir (mesajlaşmanın
    /// KENDİSİ bozulmaz, sadece o birkaç saniye/on saniye ertelenir) —
    /// tam asenkron bir mimari (ayrı worker thread + kanal) bu kapsamın
    /// dışında bırakıldı, bkz. proje notları.
    fn prepare_and_send_file(&mut self, peer_device_fingerprint: String, source_path: String, file_name: String, mime_type: String, preview_jpeg: Option<Vec<u8>>, duration_ms: Option<u32>) -> Result<(String, String), String> {
        // `wrap_file_key`'in erken (dosyayı diske şifrelemeden ÖNCE)
        // çağrılması kasıtlı: `skipped_key_encryption_key` henüz
        // yüklenmemişse burada hemen hata dönülür — aksi halde
        // `encrypt_file_to_disk` (potansiyel olarak GB'larca veri
        // işleyen, saniyeler süren bir işlem) tamamlanır ama sonunda
        // anahtar sarmalama başarısız olur, diskte hiçbir DB kaydı
        // olmayan "öksüz" bir `.enc` dosyası kalırdı.
        if self.skipped_key_encryption_key.is_none() {
            return Err("Şifreleme anahtarı henüz yüklenmedi, birazdan tekrar deneyin".to_string());
        }
        // Kullanıcı tarafından istenen azami boyut (4GB) — dosyanın
        // TAMAMINI şifrelemeye başlamadan ÖNCE kontrol edilir, aksi halde
        // aşırı büyük bir dosya için saniyeler/dakikalar süren bir
        // encrypt_file_to_disk çağrısı boşuna çalışıp sonunda reddedilirdi.
        let source_size = std::fs::metadata(&source_path).map(|m| m.len()).map_err(|e| e.to_string())?;
        if source_size > MAX_ATTACHMENT_SIZE {
            return Err(format!(
                "Dosya çok büyük ({} bayt) — azami boyut {} bayt (4GB)",
                source_size, MAX_ATTACHMENT_SIZE
            ));
        }

        let file_id = uuid::Uuid::new_v4().to_string();
        let mut file_key = [0u8; 32];
        {
            use rand::RngCore;
            OsRng.fill_bytes(&mut file_key);
        }

        let _ = std::fs::create_dir_all(self.attachments_dir()?);
        let dest_path = self.enc_path_for(&file_id)?;
        let (total_size, sha256_hex) = attachments::encrypt_file_to_disk(
            std::path::Path::new(&source_path), &dest_path, &file_key,
        )?;

        let (encrypted_key, key_nonce) = self.wrap_file_key(&file_key)?;
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO files
                 (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size,
                  sha256_hex, encrypted_file_key, key_nonce, status, bytes_transferred, created_at, preview_jpeg, duration_ms)
                 VALUES (?1, ?2, 'sent', ?3, ?4, ?5, ?6, ?7, ?8, 'complete', ?5, ?9, ?10, ?11)",
                params![
                    file_id, peer_device_fingerprint, file_name, mime_type, total_size as i64,
                    sha256_hex, encrypted_key, key_nonce, current_time_ms() as i64, preview_jpeg, duration_ms,
                ],
            );
        }

        let content = MessageContent::FileOffer {
            group_id: None,
            file_id: file_id.clone(),
            file_name,
            mime_type,
            total_size,
            file_key,
            sha256_hex,
            preview_jpeg,
            duration_ms,
        };
        let (_, status) = self.send_message_content(peer_device_fingerprint, &content, None)?;
        Ok((file_id, status))
    }

    /// Gelen bir `FileOffer`'ı işler: `files` tablosuna bir alıcı kaydı
    /// ekler (node modu açıksa hemen indirmeyi başlatır — kapalıysa sadece
    /// meta veri görünür kalır, kullanıcı "İndir" demeli).
    fn receive_file_offer(&mut self, peer_fp: &str, group_id: Option<String>, file_id: &str, file_name: &str, mime_type: &str, total_size: u64, file_key: &[u8; 32], sha256_hex: &str, preview_jpeg: &Option<Vec<u8>>, duration_ms: Option<u32>) -> serde_json::Value {
        let auto_download_requested = self.node_mode_enabled;
        // Satır YAZILAMADIYSA (ör. şifreleme anahtarı henüz yüklenmedi),
        // "offered" olarak devam ediyoruz — DB kaydı olmadan "downloading"
        // raporlamak, `download_file`'ın hiçbir zaman bulamayacağı bir
        // dosya için Kotlin tarafında sonsuza kadar takılı bir UI'ye yol
        // açardı (bkz. dosya sonu not).
        let row_written = match self.wrap_file_key(file_key) {
            Ok((encrypted_key, key_nonce)) => {
                let status = if auto_download_requested { "downloading" } else { "offered" };
                let ok = if let Some(conn) = &self.db {
                    conn.execute(
                        "INSERT OR REPLACE INTO files
                         (file_id, peer_device_fingerprint, direction, file_name, mime_type, total_size,
                          sha256_hex, encrypted_file_key, key_nonce, status, bytes_transferred, created_at, preview_jpeg, duration_ms)
                         VALUES (?1, ?2, 'received', ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, ?12)",
                        params![
                            file_id, peer_fp, file_name, mime_type, total_size as i64,
                            sha256_hex, encrypted_key, key_nonce, status, current_time_ms() as i64, preview_jpeg, duration_ms,
                        ],
                    ).is_ok()
                } else {
                    false
                };
                ok
            }
            Err(e) => {
                error!("FileOffer için dosya anahtarı sarmalanamadı: {}", e);
                false
            }
        };

        // Spec dışı düzeltme: önceden burada `download_file`'ın başarısız
        // olması (ör. `device_to_peer_id`'de bu peer henüz yoksa) sadece
        // loglanıyordu — çağıran taraf (Kotlin) her zaman
        // "auto_downloading": true görüyordu ve UI "İndiriliyor" durumunda
        // sonsuza kadar takılı kalıyordu (indirme hiçbir zaman
        // `active_downloads`'a eklenmediği, dolayısıyla hiçbir zaman
        // hata/tamamlanma olayı üretmediği için). Artık gerçek sonucu
        // (`auto_downloading` alanı) doğru raporluyoruz.
        let auto_downloading = row_written && auto_download_requested && {
            match self.download_file(file_id.to_string(), peer_fp.to_string()) {
                Ok(()) => true,
                Err(e) => {
                    error!("Otomatik dosya indirme başlatılamadı (node modu açık): {}", e);
                    if let Some(conn) = &self.db {
                        let _ = conn.execute("UPDATE files SET status = 'failed' WHERE file_id = ?1", params![file_id]);
                    }
                    self.attachment_events.push(serde_json::json!({"type": "file_failed", "peer": peer_fp, "file_id": file_id, "error": e}).to_string());
                    false
                }
            }
        };

        serde_json::json!({
            "type": "file_offer", "peer": peer_fp, "group_id": group_id, "file_id": file_id,
            "file_name": file_name, "mime_type": mime_type, "total_size": total_size,
            "auto_downloading": auto_downloading,
            // Hex-encoded — JSON ham ikili veri taşıyamaz. Küçük bir
            // önizleme (tipik birkaç on KB) için hex'in base64'e göre ~%37
            // daha büyük olması önemsiz; yeni bir bağımlılık eklemekten
            // kaçınmak için mevcut `hex` crate'i kullanılıyor.
            "preview_hex": preview_jpeg.as_ref().map(|p| hex::encode(p)),
            "duration_ms": duration_ms,
        })
    }

    /// Bir dosyanın indirmesini (kullanıcının "İndir" dokunuşu VEYA node
    /// modu açıkken otomatik) başlatır/devam ettirir. Zaten indiriliyorsa
    /// veya tamamlanmışsa no-op.
    fn download_file(&mut self, file_id: String, peer_device_fingerprint: String) -> Result<(), String> {
        info!("download_file çağrıldı: file_id={} peer={}", file_id, peer_device_fingerprint);
        if self.active_downloads.contains_key(&file_id) {
            info!("download_file: {} zaten indiriliyor, no-op", file_id);
            return Ok(());
        }
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let row: Option<(u64, Vec<u8>, Vec<u8>, String)> = conn.query_row(
            "SELECT total_size, encrypted_file_key, key_nonce, status FROM files WHERE file_id = ?1",
            params![file_id],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).ok();
        let (total_size, encrypted_key, key_nonce, status) = row.ok_or("Unknown file_id")?;
        if status == "complete" {
            info!("download_file: {} zaten tamamlanmış, no-op", file_id);
            return Ok(());
        }
        let file_key = self.unwrap_file_key(&encrypted_key, &key_nonce)?;

        let peer_id = *self.device_to_peer_id.get(&peer_device_fingerprint)
            .ok_or("Bu kişiden henüz doğrudan bir paket alınmadı, karşı taraf şu an erişilebilir değil")?;
        let cached_addr = self.peer_id_to_addr.get(&peer_id).cloned();
        info!(
            "download_file: peer_id={} biliniyor, önbellekteki adres={:?}, swarm zaten bağlı mı={}",
            peer_id, cached_addr, self.swarm.as_ref().map(|s| s.is_connected(&peer_id)).unwrap_or(false)
        );
        if let Some(addr) = cached_addr {
            if let Some(swarm) = &mut self.swarm {
                swarm.add_peer_address(peer_id, addr);
            }
        }

        let total_chunks = attachments::total_chunks(total_size);
        let enc_path = self.enc_path_for(&file_id)?;
        let _ = std::fs::create_dir_all(self.attachments_dir()?);
        // Baştan başlıyoruz — kısmi bir önceki deneme varsa üzerine
        // yazılır (bkz. dosya sonu not: süreç yeniden başlarsa kaldığı
        // yerden devam etme desteklenmiyor, baştan indirilir).
        let _ = std::fs::remove_file(&enc_path);

        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET status = 'downloading', bytes_transferred = 0 WHERE file_id = ?1", params![file_id]);
        }

        self.active_downloads.insert(file_id.clone(), DownloadState {
            peer_id,
            peer_device_fingerprint: peer_device_fingerprint.clone(),
            total_size,
            total_chunks,
            next_chunk_index: 0,
            bytes_done: 0,
            file_key,
            enc_path,
            last_progress_at: current_time_ms(),
        });
        self.request_next_chunk(&file_id);
        Ok(())
    }

    /// Bir sonraki parçayı ister — sıra bittiyse (`next_chunk_index >=
    /// total_chunks`) indirmeyi tamamlanmış sayar.
    fn request_next_chunk(&mut self, file_id: &str) {
        let (peer_id, next_index, done) = match self.active_downloads.get(file_id) {
            Some(s) if s.next_chunk_index >= s.total_chunks => (s.peer_id, s.next_chunk_index, true),
            Some(s) => (s.peer_id, s.next_chunk_index, false),
            None => return,
        };
        if done {
            self.finalize_download(file_id);
            return;
        }
        let swarm = match &mut self.swarm {
            Some(s) => s,
            None => return,
        };
        let request_id = swarm.behaviour_mut().file_chunks.send_request(
            &peer_id, FileChunkRequest { file_id: file_id.to_string(), chunk_index: next_index },
        );
        info!("request_next_chunk: file_id={} chunk={} request_id={} gönderildi (kuyruğa alındı)", file_id, next_index, request_id);
        self.download_request_ids.insert(request_id, file_id.to_string());
    }

    /// `file_progress`/`file_complete`/`file_failed` olaylarının `"peer"`
    /// alanını doldurmak için — önce (henüz kaldırılmamışsa)
    /// `active_downloads`'a, yoksa (ör. indirme zaten sonlandırılmışsa)
    /// `files` tablosuna bakar. Bulunamazsa boş string döner (olay yine
    /// de üretilir, sadece Kotlin tarafı eşleştiremez — DB kaydı hiç
    /// yoksa zaten daha büyük bir sorun var demektir).
    fn peer_for_file(&self, file_id: &str) -> String {
        if let Some(state) = self.active_downloads.get(file_id) {
            return state.peer_device_fingerprint.clone();
        }
        self.db.as_ref().and_then(|conn| {
            conn.query_row(
                "SELECT peer_device_fingerprint FROM files WHERE file_id = ?1",
                params![file_id],
                |r| r.get::<_, String>(0),
            ).ok()
        }).unwrap_or_default()
    }

    fn finalize_download(&mut self, file_id: &str) {
        let peer_fp = self.peer_for_file(file_id);
        info!("finalize_download: file_id={} peer={} status='complete' olarak işaretlendi, file_complete olayı üretiliyor", file_id, peer_fp);
        self.active_downloads.remove(file_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET status = 'complete' WHERE file_id = ?1", params![file_id]);
        }
        self.attachment_events.push(serde_json::json!({"type": "file_complete", "peer": peer_fp, "file_id": file_id}).to_string());
    }

    fn fail_download(&mut self, file_id: &str, reason: &str) {
        let peer_fp = self.peer_for_file(file_id);
        self.active_downloads.remove(file_id);
        self.download_request_ids.retain(|_, fid| fid != file_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE files SET status = 'failed' WHERE file_id = ?1", params![file_id]);
        }
        error!("Dosya indirme başarısız ({}): {}", file_id, reason);
        self.attachment_events.push(serde_json::json!({"type": "file_failed", "peer": peer_fp, "file_id": file_id, "error": reason}).to_string());
    }

    /// `poll_events`'ten her turda çağrılır — bkz. `DOWNLOAD_STALL_TIMEOUT_MS`
    /// dokümantasyonu. Bir indirme, hiçbir ilerleme/başarısızlık olayı
    /// üretmeden bu süreyi aşarsa (tipik olarak: TCP dial hiç sonuçlanmadı,
    /// iki cihaz da NAT arkasında ve doğrudan erişilemez) başarısız
    /// sayılır — kullanıcı buton hâlâ görünür durumda kalacağı için tekrar
    /// deneyebilir, ama en azından UI SÜRESİZ "İndiriliyor" göstermez.
    fn check_stalled_downloads(&mut self) {
        let now = current_time_ms();
        let stalled: Vec<String> = self.active_downloads.iter()
            .filter(|(_, s)| now.saturating_sub(s.last_progress_at) > DOWNLOAD_STALL_TIMEOUT_MS)
            .map(|(id, _)| id.clone())
            .collect();
        for file_id in stalled {
            self.fail_download(&file_id, "Bağlantı zaman aşımına uğradı — karşı taraf yanıt vermedi");
        }
    }

    /// `poll_events`'in `FileChunks` olay kolundan çağrılır — gelen bir
    /// parça yanıtını işler.
    fn handle_chunk_response(&mut self, file_id: &str, response: FileChunkResponse) {
        let data = match response {
            FileChunkResponse::Chunk { data } => {
                info!("handle_chunk_response: file_id={} {} bayt alındı", file_id, data.len());
                data
            }
            FileChunkResponse::NotFound => {
                self.fail_download(file_id, "Karşı tarafta bu dosya/parça bulunamadı");
                return;
            }
        };
        let (chunk_index, enc_path, file_key, total_chunks) = match self.active_downloads.get(file_id) {
            Some(s) => (s.next_chunk_index, s.enc_path.clone(), s.file_key, s.total_chunks),
            None => return, // İptal edilmiş/başka nedenle düşmüş bir indirme — sessizce yok say.
        };
        let plaintext_len = match attachments::append_verified_chunk(&enc_path, chunk_index, &data, &file_key) {
            Ok(n) => n,
            Err(e) => { self.fail_download(file_id, &e); return; }
        };

        let mut emit_progress = false;
        if let Some(state) = self.active_downloads.get_mut(file_id) {
            state.bytes_done += plaintext_len as u64;
            state.next_chunk_index += 1;
            state.last_progress_at = current_time_ms();
            // Her ~8 parçada bir (yaklaşık 2MB) veya son parçada ilerleme
            // bildir — her parçada bir olay üretmek (4GB/256KB = 16384 olay)
            // pollNetwork'ün döndürdüğü diziyi gereksiz yere şişirirdi.
            emit_progress = state.next_chunk_index % 8 == 0 || state.next_chunk_index >= total_chunks;
            if emit_progress {
                if let Some(conn) = &self.db {
                    let _ = conn.execute("UPDATE files SET bytes_transferred = ?1 WHERE file_id = ?2", params![state.bytes_done as i64, file_id]);
                }
            }
        }
        if emit_progress {
            if let Some(state) = self.active_downloads.get(file_id) {
                self.attachment_events.push(serde_json::json!({
                    "type": "file_progress", "peer": state.peer_device_fingerprint, "file_id": file_id,
                    "bytes_done": state.bytes_done, "bytes_total": state.total_size
                }).to_string());
            }
        }
        self.request_next_chunk(file_id);
    }

    /// `request_response` isteğinin RESPONDER tarafı — bu cihazın
    /// gönderdiği VEYA tamamen indirip yeniden servis ettiği bir dosyadan
    /// tek bir parça ister.
    fn serve_chunk_request(&self, request: &FileChunkRequest) -> FileChunkResponse {
        info!("serve_chunk_request: file_id={} chunk={} isteği alındı", request.file_id, request.chunk_index);
        let is_complete = self.db.as_ref().and_then(|conn| {
            conn.query_row(
                "SELECT status FROM files WHERE file_id = ?1", params![request.file_id],
                |r| r.get::<_, String>(0),
            ).ok()
        }).map(|s| s == "complete").unwrap_or(false);
        if !is_complete {
            error!("serve_chunk_request: file_id={} status='complete' değil (veya kayıt yok) — NotFound dönülüyor", request.file_id);
            return FileChunkResponse::NotFound;
        }
        let enc_path = match self.enc_path_for(&request.file_id) {
            Ok(p) => p,
            Err(_) => return FileChunkResponse::NotFound,
        };
        match attachments::read_chunk_from_disk(&enc_path, request.chunk_index) {
            Ok(Some(data)) => {
                info!("serve_chunk_request: file_id={} chunk={} {} bayt ile yanıtlanıyor", request.file_id, request.chunk_index, data.len());
                FileChunkResponse::Chunk { data }
            }
            other => {
                error!("serve_chunk_request: file_id={} chunk={} diskten okunamadı: {:?}", request.file_id, request.chunk_index, other.err());
                FileChunkResponse::NotFound
            }
        }
    }

    /// Bir sohbetteki bilinen ekleri listeler (bkz. `listAttachments` JNI
    /// export) — sadece bu süreç boyunca bilinen/DB'ye yazılmış kayıtlar
    /// (node modu kapalıyken teklif edilip hiç indirilmemiş bir dosya,
    /// spec dışı kural gereği zaten DB'ye yazılıyor — bkz.
    /// `receive_file_offer` — bu yüzden restart sonrası da metadata en
    /// azından görünür kalır, sadece yeniden indirme gerekir).
    fn list_attachments(&self, peer_device_fingerprint: &str) -> Vec<AttachmentSummary> {
        let conn = match &self.db {
            Some(c) => c,
            None => return Vec::new(),
        };
        let mut stmt = match conn.prepare(
            "SELECT file_id, file_name, mime_type, total_size, direction, status, bytes_transferred, created_at, preview_jpeg, duration_ms
             FROM files WHERE peer_device_fingerprint = ?1 ORDER BY created_at ASC"
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![peer_device_fingerprint], |r| {
            let preview: Option<Vec<u8>> = r.get(8)?;
            let duration: Option<i64> = r.get(9)?;
            let file_id: String = r.get(0)?;
            let mut status: String = r.get(5)?;
            // `active_downloads` süreç içi bellekte tutulur — süreç
            // öldürülüp yeniden başladığında (ör. tam uygulama kapatma)
            // DB'de "downloading" olarak kalmış ama artık HİÇBİR canlı
            // indirme ilerlemesi almayacak (ve tıklandığında no-op olan,
            // bkz. ChatActivity.onAttachmentClicked) kayıtlar bu şekilde
            // sonsuza dek "İndiriliyor" görünürdü. Gerçekten devam eden bir
            // indirmenin `active_downloads`'da karşılığı OLMALI — yoksa
            // durum aslında "failed" (tekrar denenebilir) kabul edilir.
            if status == "downloading" && !self.active_downloads.contains_key(&file_id) {
                status = "failed".to_string();
            }
            Ok(AttachmentSummary {
                file_id,
                file_name: r.get(1)?,
                mime_type: r.get(2)?,
                total_size: r.get::<_, i64>(3)? as u64,
                direction: r.get(4)?,
                status,
                bytes_transferred: r.get::<_, i64>(6)? as u64,
                created_at: r.get::<_, i64>(7)? as u64,
                preview_hex: preview.map(|p| hex::encode(p)),
                duration_ms: duration.map(|d| d as u32),
            })
        });
        rows.map(|it| it.flatten().collect()).unwrap_or_default()
    }

    /// Tamamlanmış bir ekin düz metin (çözülmüş) kopyasının yolunu döner —
    /// yoksa (ilk açılış) önce diskten çözer. BİLİNEN SINIR:
    /// `decrypt_file_from_disk` senkron/bounded-memory'dir ama büyük bir
    /// dosya için yine de zaman alabilir — Kotlin tarafı bunu ana thread
    /// DIŞINDA çağırmalıdır (bkz. P2PLib.kt dokümantasyonu).
    fn get_attachment_plaintext_path(&self, file_id: &str) -> Result<String, String> {
        info!("get_attachment_plaintext_path çağrıldı: file_id={}", file_id);
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let (encrypted_key, key_nonce, sha256_hex, status, file_name): (Vec<u8>, Vec<u8>, String, String, String) = conn.query_row(
            "SELECT encrypted_file_key, key_nonce, sha256_hex, status, file_name FROM files WHERE file_id = ?1",
            params![file_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).map_err(|e| format!("Unknown file_id ({}): {}", file_id, e))?;
        info!("get_attachment_plaintext_path: file_id={} DB durumu='{}' file_name='{}'", file_id, status, file_name);
        if status != "complete" {
            return Err(format!("Dosya henüz tamamlanmadı (durum: {})", status));
        }
        let file_key = self.unwrap_file_key(&encrypted_key, &key_nonce)?;

        let ext = file_name.rsplit_once('.').map(|(_, e)| format!(".{}", e)).unwrap_or_default();
        let plain_path = self.attachments_dir()?.join("plain_cache").join(format!("{}{}", file_id, ext));
        if !plain_path.exists() {
            let enc_path = self.enc_path_for(file_id)?;
            info!("get_attachment_plaintext_path: {} önbellekte yok, {} adresinden çözülüyor -> {}", plain_path.display(), enc_path.display(), plain_path.display());
            if let Err(e) = attachments::decrypt_file_from_disk(&enc_path, &plain_path, &file_key, &sha256_hex) {
                error!("get_attachment_plaintext_path: decrypt_file_from_disk başarısız (file_id={}): {}", file_id, e);
                return Err(e);
            }
        }
        info!("get_attachment_plaintext_path: file_id={} -> {}", file_id, plain_path.display());
        Ok(plain_path.to_string_lossy().to_string())
    }

    // ---------------------------------------------------------------
    // Bölüm 4: Ağ / Keşif
    // ---------------------------------------------------------------

    fn start_network(&mut self, node_mode: bool) -> Result<String, String> {
        self.node_mode_enabled = node_mode;
        self.own_listen_addrs.clear();

        // KRİTİK: bu artık HER SEFERİNDE rastgele bir keypair (dolayısıyla
        // PeerId) ÜRETMİYOR — bkz. `load_or_generate_libp2p_keypair`
        // dokümantasyonu ve `P2PBehaviour.mdns` alanındaki "yeniden
        // bağlanma" notu.
        let app_files_dir = self.app_files_dir.clone().ok_or("initDatabase önce çağrılmalı")?;
        let keypair = load_or_generate_libp2p_keypair(&app_files_dir);

        let gs_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            // Varsayılan 64KB — `FileOffer` artık spec dışı bir 480p/%85
            // JPEG önizleme kapağı taşıyabiliyor (bkz. packet.rs
            // `preview_jpeg` notu); tipik değeri 64KB'ı zorlayabilir (hibrit
            // imza/ratchet_pubkey ek yükü ile birlikte). 1MB, olağan bir
            // önizlemeyi + zarf ek yükünü rahatça karşılıyor, gerçek dosya
            // baytları zaten AYRI bir protokolden (request_response,
            // attachments.rs) gittiği için bu artış büyük dosyaları
            // etkilemiyor.
            .max_transmit_size(1024 * 1024)
            .build()
            .map_err(|e| e.to_string())?;

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| e.to_string())?
            // bkz. SECURITY.md "Cross-network connectivity" notu — bu
            // cihazın bir röle ÜZERİNDEN dial edebilmesi (relay_client) için
            // gereken transport katmanı. `with_behaviour` closure'ı bundan
            // sonra `(keypair, relay_client)` alır (bkz. libp2p-0.53.2
            // builder.rs `tcp_relay` testi — bu imza doğrudan oradan
            // doğrulandı).
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| e.to_string())?
            .with_behaviour(|keypair, relay_client| {
                let peer_id = keypair.public().to_peer_id();
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                    gs_config,
                )?;
                let store = MemoryStore::new(peer_id);
                let kad = kad::Behaviour::new(peer_id, store);
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/p2pmessenger/1.0.0".to_string(),
                    keypair.public(),
                ));
                let file_chunks = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(FILE_TRANSFER_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default(),
                );
                let mdns = libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer_id)?;
                // bkz. `P2PBehaviour.relay` alan dokümantasyonu — Node modu
                // kapalıyken kapasiteyi SIFIRLIYORUZ (relay::Behaviour
                // yapıldıktan sonra yeniden yapılandırılamıyor, bu yüzden bu
                // karar burada, kuruluş anında verilmeli). Node modu daha
                // sonra `set_node_mode` ile açılırsa, röle GÖREVİ görme
                // kapasitesi bir sonraki ağ yeniden başlatmasına kadar
                // etkinleşmez — kad::Mode'un aksine bu canlı toggle
                // edilemiyor (bkz. `set_node_mode` dokümantasyonu).
                let relay_config = if node_mode {
                    relay::Config::default()
                } else {
                    relay::Config {
                        max_reservations: 0,
                        max_reservations_per_peer: 0,
                        max_circuits: 0,
                        max_circuits_per_peer: 0,
                        ..relay::Config::default()
                    }
                };
                let relay = relay::Behaviour::new(peer_id, relay_config);
                let dcutr = dcutr::Behaviour::new(peer_id);
                let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());
                // bkz. `P2PBehaviour.upnp` dokümantasyonu — `Default` inşası
                // yeterli, kendi kendine gateway aramaya/dinleme
                // adreslerini eşlemeye başlar (bkz. libp2p-upnp
                // `tokio::Behaviour`/`Default` implementasyonu).
                let upnp = libp2p::upnp::tokio::Behaviour::default();
                Ok(P2PBehaviour { gossipsub, kad, identify, file_chunks, mdns, relay_client, relay, dcutr, autonat, upnp })
            })
            .map_err(|e| e.to_string())?
            .build();

        // Spec 4.3: Node modu kapalıyken Client (pasif), açıkken Server
        // (routing tablosuna aktif katkı).
        let mode = if node_mode { kad::Mode::Server } else { kad::Mode::Client };
        swarm.behaviour_mut().kad.set_mode(Some(mode));

        let peer_id = *swarm.local_peer_id();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().map_err(|_| "bad multiaddr")?)
            .map_err(|e| e.to_string())?;

        if let Ok(active_fp) = self.get_active_own_device_fingerprint() {
            let own_topic = gossipsub::IdentTopic::new(format!("p2p_msg_{}", active_fp));
            swarm.behaviour_mut().gossipsub.subscribe(&own_topic).map_err(|e| e.to_string())?;
        }

        // bkz. `topic_for_root_key` dokümantasyonu: `load_ratchet_states_from_db`
        // (init_db sırasında, swarm henüz yokken) diskten yüklenmiş her
        // mevcut oturum için, o oturumun rotasyonlu topic'ine de abone ol —
        // aksi halde bu kişilerden gelen (fingerprint tabanlı posta kutusu
        // ARTIK dinlenmediği için) hiçbir mesaj alınamaz.
        for state in self.ratchets.values() {
            let _ = swarm.behaviour_mut().gossipsub.subscribe(&Self::topic_for_root_key(&state.root_key));
        }

        self.swarm = Some(swarm);

        // bkz. `DEFAULT_BOOTSTRAP_RELAYS` dokümantasyonu — boşsa no-op.
        for addr in DEFAULT_BOOTSTRAP_RELAYS {
            if let Err(e) = self.add_known_relay_address(addr) {
                error!("Varsayılan bootstrap röle eklenemedi ({}): {}", addr, e);
            }
        }

        Ok(peer_id.to_string())
    }

    /// KRİTİK SINIR: Kademlia modu (`kad::Mode`) canlı olarak toggle
    /// edilebiliyor ama röle-sunma KAPASİTESİ (bkz. `P2PBehaviour.relay`
    /// dokümantasyonu) `start_network`'te `relay::Behaviour::new`'e
    /// verilen `Config` ile SABİTLENİYOR — libp2p bunu sonradan yeniden
    /// yapılandırmaya izin vermiyor. Yani Node modu bu fonksiyonla açılırsa
    /// DHT routing katkısı ANINDA etkinleşir ama bu cihazın gerçekten röle
    /// GÖREVİ görmesi (başkalarının rezervasyon/circuit isteklerini kabul
    /// etmesi), ağ bir sonraki `start_network` çağrısına kadar
    /// etkinleşmez. Kabul edilebilir bir sınır: bu ayar zaten nadiren
    /// değiştirilir, ve `node_mode_enabled` her `start_network`'te zaten
    /// okunuyor (bkz. `P2PService`'in kalıcı tercih deposu).
    fn set_node_mode(&mut self, enabled: bool) {
        self.node_mode_enabled = enabled;
        if let Some(swarm) = &mut self.swarm {
            let mode = if enabled { kad::Mode::Server } else { kad::Mode::Client };
            swarm.behaviour_mut().kad.set_mode(Some(mode));
        }
    }

    /// QR/"Kodum" ekranında gösterilecek ve karşı tarafa taşınacak
    /// `rendezvous_node` — swarm'ın gerçekten dinlemeye başladığı bir adres
    /// (`own_listen_addrs`, bkz. `poll_events`) artı kendi PeerId'imiz
    /// (`/p2p/<peer_id>` son eki). Bu son ek olmadan `extract_peer_id`
    /// karşı tarafta hiçbir zaman bir PeerId bulamaz ve taranan QR'ın
    /// adresi `kad.add_address`/`dial` için sessizce kullanılmaz kalır
    /// (bkz. process_qr_packet). `start_network` çağrıldıktan sonra ilk
    /// birkaç `poll_events` turuna kadar `None` dönebilir — henüz hiçbir
    /// dinleme adresi bildirilmemiş demektir.
    ///
    /// Telefonlar genelde Wi-Fi'ye bağlıyken bile mobil veriyi AÇIK tutar —
    /// `0.0.0.0` üzerinde dinlemek `if-watch` aracılığıyla HER aktif arayüz
    /// için ayrı bir `NewListenAddr` üretir (Wi-Fi'nin özel LAN adresi VE
    /// operatörün mobil veri adresi gibi). Aynı Wi-Fi'deki karşı cihaz
    /// SADECE Wi-Fi'nin özel (RFC 1918) adresinden erişilebilir — mobil
    /// veri adresi (genelde CGNAT/public, operatöre ait) asla doğrudan
    /// dial edilemez. Bu yüzden hangi adres ilk raporlandıysa onu almak
    /// YERİNE, önce özel/LAN bir IPv4 adresi arıyoruz.
    fn get_node_address(&self) -> Option<String> {
        let swarm = self.swarm.as_ref()?;
        let peer_id = *swarm.local_peer_id();
        // bkz. `own_external_addr` alanı dokümantasyonu — UPnP ile
        // eşlenmiş, GERÇEKTEN dışarıdan (farklı ağdan) çevrilebilir bir
        // adres varsa HER ŞEYDEN ÖNCE o tercih edilir; LAN adresi başka
        // bir ağdaki biri için tamamen işe yaramaz olurdu.
        let addr = self.own_external_addr.as_ref()
            .or_else(|| self.own_listen_addrs.iter().find(|a| is_private_lan_multiaddr(a)))
            .or_else(|| self.own_listen_addrs.iter().find(|a| !is_loopback_multiaddr(a)))
            .or_else(|| self.own_listen_addrs.first())?;
        Some(format!("{addr}/p2p/{peer_id}"))
    }

    /// Spec dışı, güvenlik denetimi düzeltmesi: gossipsub topic adı önceden
    /// DOĞRUDAN alıcının cihaz fingerprint'inden türetiliyordu
    /// (`p2p_msg_<fingerprint>`) — ağdaki herhangi bir gözlemci, içeriği
    /// okuyamasa bile HANGİ fingerprint'e mesaj gittiğini ve NE ZAMAN
    /// gittiğini doğrudan görebiliyordu (bkz. SECURITY.md "Trafik analizi"
    /// notu). Bir ratchet oturumu KURULDUKTAN SONRA artık bunun yerine, o
    /// oturumun `root_key`'inden HKDF ile türetilen sözde-rastgele bir
    /// topic adı kullanılıyor — bu, sadece o oturumun paylaşılan sırrına
    /// sahip iki tarafın hesaplayabileceği bir değer, fingerprint'ten
    /// GERİYE türetilemez. `root_key` her DH/KEM rotasyonunda (30 dakikada
    /// bir, bkz. ratchet.rs) değiştiğinden, topic adı da otomatik olarak
    /// rotate olur — uzun vadeli bir gözlemci bile "bu iki topic aynı
    /// çifte ait" bağlantısını kuramaz.
    ///
    /// BİLİNEN SINIR: henüz hiçbir ratchet oturumu yokken (ilk eşleşmenin
    /// `IdentityExchange`/`HandshakeInit` çifti) paylaşılacak bir sır da
    /// yok — bu durumda kaçınılmaz olarak eski `p2p_msg_<fingerprint>`
    /// "posta kutusu" topic'ine düşülür (birini tanımadan önce onunla
    /// nasıl bir "rastgele buluşma noktası" paylaşılabilir ki?). Yani bu
    /// düzeltme, bir kişiyle YAPILAN TÜM GERÇEK KONUŞMA trafiğini korur;
    /// sadece BİR KEZLİK ilk eşleşme anı fingerprint üzerinden görünür
    /// kalır (SECURITY.md'de belgelendi).
    fn topic_for_root_key(root_key: &[u8]) -> gossipsub::IdentTopic {
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, root_key);
        let mut topic_id = [0u8; 16];
        hk.expand(b"p2pmsg-v0.1-gossip-topic", &mut topic_id).expect("HKDF expand failed");
        gossipsub::IdentTopic::new(format!("p2p_rt_{}", hex::encode(topic_id)))
    }

    /// `topic_for_root_key` dokümantasyonuna bkz. Bir ratchet oturumu
    /// kurulduğunda/rotasyon geçirdiğinde/silindiğinde çağrılan ortak
    /// abonelik yardımcı fonksiyonu — `old_root_key: Some(..)` ise önce o
    /// topic'ten abonelik iptal edilir (rotasyon/silme), sonra
    /// `new_root_key: Some(..)` ise o topic'e abone olunur (oluşturma/
    /// rotasyon). Swarm henüz başlamamışsa (`self.swarm == None`) sessizce
    /// no-op — `load_ratchet_states_from_db` süreç başlangıcında,
    /// `start_network`'ten ÖNCE çağrıldığı için bu durum normaldir (bkz.
    /// `start_network`'teki toplu abonelik döngüsü).
    fn resubscribe_ratchet_topic(&mut self, old_root_key: Option<&[u8]>, new_root_key: Option<&[u8]>) {
        if let Some(swarm) = &mut self.swarm {
            if let Some(old) = old_root_key {
                let _ = swarm.behaviour_mut().gossipsub.unsubscribe(&Self::topic_for_root_key(old));
            }
            if let Some(new) = new_root_key {
                let _ = swarm.behaviour_mut().gossipsub.subscribe(&Self::topic_for_root_key(new));
            }
        }
    }

    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): `known_relay_peers`'e yeni bir aday ekler,
    /// `MAX_KNOWN_RELAYS` dolmuşsa rastgele bir eskisini atar (gerçek LRU
    /// değil — bu sadece opportunistic bir önbellek, kalıcı da değil,
    /// her süreç kendi görüşüyle yeniden doldurur, bu yüzden hangi girdinin
    /// atıldığı önemli değil, sadece sınırsız büyümemesi önemli).
    fn record_known_relay(&mut self, peer_id: PeerId, addr: Multiaddr) {
        if !self.known_relay_peers.contains_key(&peer_id) && self.known_relay_peers.len() >= MAX_KNOWN_RELAYS {
            if let Some(evict) = self.known_relay_peers.keys().next().cloned() {
                self.known_relay_peers.remove(&evict);
            }
        }
        self.known_relay_peers.insert(peer_id, addr);
    }

    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu): `direct_addr` (varsa) DOĞRUDAN dial edilir VE
    /// (varsa) bilinen HER röle adayı üzerinden `/p2p-circuit/` adresiyle
    /// de AYNI ANDA dial denenir — libp2p aynı `PeerId`'ye birden fazla
    /// eşzamanlı dial denemesini sorunsuz yönetir (ilk başarılı olan
    /// kazanır, diğerleri iptal edilir). Bu, "önce doğrudan dene,
    /// başarısız olursa röleyi dene" sırasına göre daha düşük gecikmeli
    /// (röle denemesi, başarısız bir doğrudan denemenin zaman aşımını
    /// beklemeden hemen başlar) VE daha basit (ayrı bir asenkron
    /// başarısızlık-sonrası-yeniden-dene durum makinesi gerekmiyor).
    /// Röle üzerinden kurulan bağlantı DCUtR tarafından otomatik olarak
    /// doğrudan bağlantıya yükseltilmeye çalışılır (bkz.
    /// `P2PBehaviour.dcutr`); başarısız olursa (ör. simetrik NAT) trafik
    /// röle üzerinden akmaya devam eder — hangisi olursa olsun uygulama
    /// katmanı (gossipsub/ratchet) hiçbir şey bilmez, aynı şekilde çalışır.
    fn dial_with_relay_fallback(&mut self, target_peer_id: PeerId, direct_addr: Option<Multiaddr>) {
        let Some(swarm) = &mut self.swarm else { return };
        if let Some(addr) = direct_addr {
            if let Err(e) = swarm.dial(addr) {
                error!("Doğrudan dial başarısız: {}", e);
            }
        }
        for (relay_peer_id, relay_addr) in &self.known_relay_peers {
            if *relay_peer_id == target_peer_id {
                continue;
            }
            let circuit_addr = relay_addr.clone()
                .with(MultiaddrProtocol::P2pCircuit)
                .with(MultiaddrProtocol::P2p(target_peer_id));
            if let Err(e) = swarm.dial(circuit_addr) {
                error!("Röle üzerinden dial başarısız (röle={}): {}", relay_peer_id, e);
            }
        }
    }

    /// Spec dışı, ağ sağlamlığı düzeltmesi (kendini iyileştiren yeniden
    /// bağlanma): `poll_events`'ten periyodik olarak (bkz.
    /// `RECONNECT_SWEEP_INTERVAL_MS`) çağrılır. Bilinen + aktif her uzak
    /// cihaz için, o an CANLI bir libp2p bağlantısı YOKSA VE kalıcı bir
    /// adres ipucumuz varsa (`device_last_addr`), `dial_with_relay_fallback`
    /// ile yeniden bağlanmayı dener.
    ///
    /// Bu, tek başına en büyük ağ-sağlamlığı kazancıdır — önceden bir kişi
    /// KOPTUĞUNDA (ağ tipi değişimi: Wi-Fi↔mobil veri, uygulama arka planda
    /// öldürülüp yeniden başlatıldığında, karşı taraf kısa süre çevrimdışı
    /// olduğunda) yeniden bağlanmanın TEK yolu mDNS (yalnızca aynı yerel ağ)
    /// veya elle QR yeniden taramaydı; `ConnectionClosed`/
    /// `OutgoingConnectionError` olayları yalnızca loglanıyor, hiçbir
    /// yeniden-dial tetiklemiyordu. Artık her disconnect, bir sonraki
    /// taramada (≤15 sn) otomatik olarak iyileşir — farklı ağdakiler dahil
    /// (röle/DCUtR/UPnP yolları hâlâ geçerliyse).
    ///
    /// BİLİNEN SINIR: karşı tarafın adresi tamamen değiştiyse (yeni public
    /// IP, UPnP eşlemesi yok, ortak röle yok) doğrudan yeniden bağlanma yine
    /// başarısız olur — bu, merkezi bir rendezvous sunucusu olmayan her P2P
    /// sistemin yapısal sınırıdır. Tarama yine de denemeye devam eder;
    /// adres bir şekilde tazelendiğinde (mDNS, yeni QR, röle keşfi) bağlanır.
    fn reconnect_sweep(&mut self) {
        let now = current_time_ms();
        if now.saturating_sub(self.last_reconnect_sweep_at) < RECONNECT_SWEEP_INTERVAL_MS {
            return;
        }
        self.last_reconnect_sweep_at = now;

        // Hedefleri önce topla (immutable borrow'lar), sonra dial et
        // (`dial_with_relay_fallback` `&mut self` ister) — borrow çakışması
        // önleme, dosyadaki diğer örneklerle aynı desen.
        let mut targets: Vec<(PeerId, Multiaddr)> = Vec::new();
        {
            let swarm = match self.swarm.as_ref() {
                Some(s) => s,
                None => return,
            };
            for (fp, addr_str) in &self.device_last_addr {
                match self.known_remote_devices.get(fp) {
                    Some(rec) if rec.is_active => {}
                    _ => continue, // bilinmeyen/iptal edilmiş cihaz — atla
                }
                let addr = match addr_str.parse::<Multiaddr>() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let peer_id = match extract_peer_id(&addr) {
                    Some(p) => p,
                    None => continue,
                };
                if swarm.is_connected(&peer_id) {
                    continue; // zaten bağlı
                }
                targets.push((peer_id, addr));
            }
        }
        for (peer_id, addr) in targets {
            info!("reconnect_sweep: kopmuş peer'a yeniden bağlanılıyor: {}", peer_id);
            self.dial_with_relay_fallback(peer_id, Some(addr));
        }
    }

    /// Sadece ham gossipsub publish — kuyruğa EKLEMEZ, durum güncellemez.
    /// `publish_envelope` (ilk deneme) ve `poll_events`'teki retry döngüsü
    /// (sonraki denemeler) tarafından ortak kullanılır.
    fn try_publish_raw(&mut self, target_device_fingerprint: &str, envelope: &NetworkEnvelope) -> Result<(), String> {
        let bytes = ciborium_bytes(envelope)?;
        let mailbox_topic = || gossipsub::IdentTopic::new(format!("p2p_msg_{}", target_device_fingerprint));
        // Spec dışı, hata ayıklama düzeltmesi (gerçek bir cihazda "hiçbir
        // mesaj gitmiyor da gelmiyor da" olarak rapor edildi): bkz.
        // `topic_for_root_key` dokümantasyonu — bir ratchet oturumu varsa
        // fingerprint yerine paylaşılan sırdan türetilen rotasyonlu topic
        // kullanılır, AMA bunun İKİ istisnası var, ikisi de "karşı taraf bu
        // ANDA hangi topic'i dinliyor olabilir" sorusuna dayanıyor:
        //
        // 1. `Handshake`/`IdentityExchange`: bunlar HER ZAMAN posta kutusu
        //    topic'inden gider, `self.ratchets`'te bu peer için bir kayıt
        //    olsa BİLE. Sebep: `initiate_handshake_with` kendi ratchet
        //    state'ini `self.ratchets`'e, HandshakeInit'i publish etmeden
        //    ÖNCE ekliyor (bkz. o fonksiyon) — bu yüzden `self.ratchets.get`
        //    kontrolü burada "true" dönerdi ve rotasyonlu topic seçilirdi.
        //    Ama karşı taraf bu paketi ALMADAN o rotasyonlu topic'i asla
        //    hesaplayamaz/abone olamaz (root_key'i bilmiyor) — bu, karşı
        //    tarafın HİÇBİR ZAMAN dinlemediği bir topic'e mesaj göndermek
        //    anlamına gelirdi (gerçek üretim hatasıydı, bu düzeltme onu
        //    kapatıyor).
        // 2. `Message` içindeki paket bir rotasyon ANONS EDİYORSA
        //    (`rotation_kyber_ciphertext` dolu): aynı sebepten, karşı taraf
        //    bu paketi almadan yeni root_key'i (dolayısıyla yeni topic'i)
        //    bilemez — bu yüzden rotasyonu tetikleyen tarafın kaydettiği
        //    `prev_root_key`'e (bkz. o alanın dokümantasyonu) karşılık gelen
        //    ESKİ topic kullanılır. Rotasyon içermeyen sıradan `Message`'lar
        //    her zamanki gibi GÜNCEL `root_key`'in topic'ini kullanır.
        let topic = match envelope {
            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => mailbox_topic(),
            NetworkEnvelope::Message(packet) if packet.header.rotation_kyber_ciphertext.is_some() => {
                match self.ratchets.get(target_device_fingerprint).and_then(|r| r.prev_root_key.as_ref()) {
                    Some(prev_root_key) => Self::topic_for_root_key(prev_root_key),
                    None => mailbox_topic(),
                }
            }
            _ => match self.ratchets.get(target_device_fingerprint) {
                Some(ratchet) => Self::topic_for_root_key(&ratchet.root_key),
                None => mailbox_topic(),
            },
        };
        if let Some(swarm) = &mut self.swarm {
            swarm.behaviour_mut().gossipsub.publish(topic, bytes).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Herhangi bir zarfı (Handshake/IdentityExchange/Message/GroupUpdate/...)
    /// bir karşı tarafın gossipsub topic'ine yayınlar. İlk bağlantıdan sonraki
    /// ilk birkaç saniyede gossipsub mesh'i henüz oluşmamış olabilir — bu
    /// durumda publish anında "InsufficientPeers"/"NoPeersSubscribedToTopic"
    /// ile başarısız olur. Bunu MERKEZİ olarak burada ele alıyoruz: başarısız
    /// olan HER zarf `pending_envelopes`'e eklenir, `poll_events` her turda
    /// aynı zarfı (yeniden şifreleme/imzalama YAPMADAN) yeniden göndermeyi
    /// dener. Bu, önceden her çağıranın kendi tip-özel kuyruğunu tutmasından
    /// (ve HandshakeInit'in hiç kapsanmamasından) daha basit ve eksiksiz.
    /// `envelope` bir `Message` ise `message_status` da güncellenir (bkz. o
    /// alanın dokümantasyonu — UI'nin gönderim/hata ikonları için).
    fn publish_envelope(&mut self, target_device_fingerprint: &str, envelope: &NetworkEnvelope) -> Result<(), String> {
        if let Err(e) = self.try_publish_raw(target_device_fingerprint, envelope) {
            if let NetworkEnvelope::Message(m) = envelope {
                self.message_status.insert(m.header.message_id.clone(), MessageSendStatus::Pending);
            }
            self.pending_envelopes.push((target_device_fingerprint.to_string(), envelope.clone(), current_time_ms()));
            return Err(e);
        }
        if let NetworkEnvelope::Message(m) = envelope {
            self.message_status.insert(m.header.message_id.clone(), MessageSendStatus::Sent);
        }
        Ok(())
    }

    /// bkz. `awaiting_confirmation` alanı dokümantasyonu — `publish_envelope`
    /// gibi ilk denemeyi hemen yapar (durumu/aynı şekilde günceller), ama
    /// SONRASINDA da (ilk deneme başarılı olsa BİLE) karşı taraftan bir
    /// onay gelene kadar paketi periyodik olarak yeniden göndermeye devam
    /// eder — `pending_envelopes`'in aksine bir üst zaman sınırı yoktur.
    fn publish_with_ack_tracking(&mut self, target_device_fingerprint: &str, message_id: &str, envelope: NetworkEnvelope, retries_remaining: Option<u32>) {
        let now = current_time_ms();
        match self.try_publish_raw(target_device_fingerprint, &envelope) {
            Ok(()) => {
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.message_status.insert(m.header.message_id.clone(), MessageSendStatus::Sent);
                }
            }
            Err(e) => {
                error!("İlk gönderim denemesi başarısız (onay alınana kadar yeniden denenecek): {}", e);
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.message_status.insert(m.header.message_id.clone(), MessageSendStatus::Pending);
                }
            }
        }
        self.awaiting_confirmation.insert(message_id.to_string(), PendingConfirmation {
            peer_device_fingerprint: target_device_fingerprint.to_string(),
            envelope,
            next_retry_at: now + ACK_RETRY_INITIAL_MS,
            retry_interval_ms: ACK_RETRY_INITIAL_MS,
            retries_remaining,
            first_sent_at: now,
        });
    }

    /// `poll_events`'ten çağrılır — `awaiting_confirmation`'daki, süresi
    /// gelmiş her girdiyi (yeniden şifrelemeden) tekrar yayınlar ve bir
    /// sonraki deneme aralığını üstel olarak büyütür (`ACK_RETRY_MAX_MS`
    /// ile sınırlı).
    fn retry_unconfirmed_messages(&mut self) {
        let now = current_time_ms();
        // KRİTİK: `awaiting_confirmation` bir `HashMap` — Rust'ın std
        // `HashMap`'i her süreçte rastgele tohumlanmış bir hasher
        // kullanır (DoS direnci için), yani `.iter()` sırası KOMPOZİSYON
        // sırasıyla HİÇ ilgili değildir. Kullanıcı çevrimdışıyken art
        // arda birkaç mesaj biriktiyse, bu sıralama olmadan yeniden
        // gönderim sırası her `poll_events` turunda değişebilen, rastgele
        // bir sıraydı — kullanıcı isteği: ilk gönderilemeyen mesajlar
        // BİRİKTİYSE gönderilme (composition) sırasına göre denenmeli.
        // `first_sent_at` zaten her `PendingConfirmation`'da var, bu
        // yüzden `due_ids`'i ona göre sıralamak yeterli (yapıyı
        // `BTreeMap`'e çevirmek gibi daha büyük bir değişikliğe gerek
        // yok — tüm `.get`/`.get_mut`/`.remove`/`.insert` çağrı yerlerini
        // etkilerdi).
        let mut due_ids: Vec<(String, u64)> = self.awaiting_confirmation.iter()
            .filter(|(_, p)| p.next_retry_at <= now)
            .map(|(id, p)| (id.clone(), p.first_sent_at))
            .collect();
        due_ids.sort_by_key(|(_, first_sent_at)| *first_sent_at);
        for (message_id, _) in due_ids {
            let (peer_fp, envelope, retries_remaining, first_sent_at) = match self.awaiting_confirmation.get(&message_id) {
                Some(p) => (p.peer_device_fingerprint.clone(), p.envelope.clone(), p.retries_remaining, p.first_sent_at),
                None => continue,
            };
            // KRİTİK (bkz. `MAX_UNCONFIRMED_AGE_MS` dokümantasyonu): bu yaşı
            // aşan bir paket, karşı tarafın ratchet'i muhtemelen bir DH/KEM
            // rotasyonu yaşadığı için ARTIK KRİPTOGRAFİK OLARAK ÇÖZÜLEMEZ —
            // yeniden göndermeye devam etmek sadece alıcıya sonsuza dek
            // "Decryption failed" ürettirir. Vazgeç, "Failed" olarak
            // işaretle (Text/Edit/Delete/HistorySyncRequest — kullanıcı
            // isterse manuel olarak yeni bir mesaj gönderebilir).
            if now.saturating_sub(first_sent_at) > MAX_UNCONFIRMED_AGE_MS {
                self.awaiting_confirmation.remove(&message_id);
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.message_status.insert(m.header.message_id.clone(), MessageSendStatus::Failed);
                    self.attachment_events.push(serde_json::json!({
                        "type": "status", "peer": peer_fp,
                        "message_id": m.header.message_id, "status": "error"
                    }).to_string());
                }
                error!("Paket {} onaylanmadan azami yaşı ({} ms) aştı, vazgeçiliyor (muhtemelen ratchet rotasyonu geçti)", message_id, MAX_UNCONFIRMED_AGE_MS);
                continue;
            }
            // bkz. `PendingConfirmation.retries_remaining` dokümantasyonu —
            // SINIRLI girdiler (Ack) tükendiğinde sessizce bırakılır, ARTIK
            // yeniden gönderilmez. Sınırsız girdiler (Text/Edit/Delete/
            // HistorySyncRequest) için `retries_remaining` hep `None`,
            // buraya hiç girmez (ama yukarıdaki yaş sınırına hâlâ tabidir).
            if retries_remaining == Some(0) {
                self.awaiting_confirmation.remove(&message_id);
                continue;
            }
            match self.try_publish_raw(&peer_fp, &envelope) {
                Ok(()) => {
                    if let NetworkEnvelope::Message(m) = &envelope {
                        self.message_status.insert(m.header.message_id.clone(), MessageSendStatus::Sent);
                    }
                }
                Err(_) => {
                    // Sessizce bir sonraki turda tekrar denenecek — henüz
                    // "Failed" olarak işaretlemiyoruz, kullanıcı açıkça
                    // "onaylanana kadar sürekli dene" istedi (sınırsız
                    // girdiler için) / sınırlı girdiler zaten kendi
                    // deneme sayacıyla sonlanacak.
                }
            }
            if let Some(pending) = self.awaiting_confirmation.get_mut(&message_id) {
                if let Some(n) = pending.retries_remaining {
                    pending.retries_remaining = Some(n.saturating_sub(1));
                }
                pending.retry_interval_ms = (pending.retry_interval_ms * 2).min(ACK_RETRY_MAX_MS);
                pending.next_retry_at = current_time_ms() + pending.retry_interval_ms;
            }
        }
    }

    fn poll_events(&mut self) -> Vec<String> {
        // `Option<PeerId>` — gossipsub `Signed` authenticity modu (bkz.
        // start_network) her gelen mesajda gönderenin gerçek `PeerId`'sini
        // taşır; bu, dosya eki indirmesi (`request_response`, bkz.
        // `device_to_peer_id`) için gereken PeerId eşlemesinin KAYNAĞI —
        // önceden bu bilgi okunup hemen atılıyordu.
        let mut incoming: Vec<(Option<PeerId>, Vec<u8>)> = Vec::new();
        let mut new_listen_addrs: Vec<Multiaddr> = Vec::new();
        let mut new_peer_addrs: Vec<(PeerId, Multiaddr)> = Vec::new();
        // bkz. `known_relay_peers` alanı dokümantasyonu — identify'dan
        // "bu peer röle protokolünü konuşuyor" öğrenildiğinde doldurulur,
        // döngü bitince (aşağıda `self.record_known_relay` ile) uygulanır
        // (döngü içinde `self.swarm` zaten `&mut` borrow'lu, `self`'in
        // TAMAMINA erişemiyoruz — bkz. dosyadaki aynı desenin diğer
        // örnekleri, ör. `new_peer_addrs`).
        let mut new_relay_peers: Vec<(PeerId, Multiaddr)> = Vec::new();
        // bkz. `own_external_addr` alanı dokümantasyonu — `Some(addr)` yeni
        // bir UPnP eşlemesi, `None` bir eşlemenin süresinin dolduğunu/
        // geçersiz olduğunu belirtir. Sırayla (birden fazla olay aynı
        // pollda gelebilir) döngü bittikten sonra uygulanır.
        let mut upnp_external_addr_updates: Vec<Option<Multiaddr>> = Vec::new();
        let mut file_chunk_events: Vec<FileChunkEventLocal> = Vec::new();
        if let Some(swarm) = &mut self.swarm {
            RUNTIME.block_on(async {
                while let Some(event) = swarm.next().now_or_never().flatten() {
                    match event {
                        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                            // Gerçek dinleme adresi — QR/"Kodum" ekranındaki
                            // `node_address`'in kaynağı budur (bkz.
                            // own_listen_addrs alanı dokümantasyonu ve
                            // get_node_address).
                            new_listen_addrs.push(address);
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                            incoming.push((message.source, message.data));
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            // bkz. `known_relay_peers` alanı dokümantasyonu
                            // (SECURITY.md "Cross-network connectivity"):
                            // bu peer röle (Circuit Relay v2 HOP) protokolünü
                            // konuşuyorsa VE en az bir dinleme adresi
                            // bildiriyorsa, ileride başka bir erişilemez
                            // peer'a ulaşmak için kullanılabilecek bir röle
                            // adayı olarak kaydediyoruz. `listen_addrs`
                            // tüketilmeden (aşağıdaki kad.add_address
                            // döngüsü onu MOVE eder) önce, ilk adresi
                            // kopyalıyoruz.
                            if info.protocols.iter().any(|p| *p == relay::HOP_PROTOCOL_NAME) {
                                if let Some(addr) = info.listen_addrs.first() {
                                    new_relay_peers.push((peer_id, addr.clone().with(MultiaddrProtocol::P2p(peer_id))));
                                }
                            }
                            // Kademlia'ya Identify'dan öğrenilen adresleri
                            // ekle — bölüm 4.2, Kademlia'nın kendiliğinden
                            // yapamadığı adres öğrenme adımı.
                            for addr in info.listen_addrs {
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns_event)) => {
                            // bkz. `P2PBehaviour.mdns` alanı dokümantasyonu —
                            // AYNI yerel ağdaki bir peer keşfedildiğinde,
                            // hiçbir kullanıcı eylemi olmadan otomatik dial
                            // ediyoruz (QR taramasından sonraki `dial()`
                            // çağrısıyla AYNI desen).
                            match mdns_event {
                                libp2p::mdns::Event::Discovered(list) => {
                                    for (peer_id, addr) in list {
                                        info!("mDNS: yerel ağda peer keşfedildi: {} @ {}", peer_id, addr);
                                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                        new_peer_addrs.push((peer_id, addr.clone()));
                                        if !swarm.is_connected(&peer_id) {
                                            if let Err(e) = swarm.dial(addr) {
                                                error!("mDNS keşfinden sonra dial başarısız: {}", e);
                                            }
                                        }
                                    }
                                }
                                libp2p::mdns::Event::Expired(list) => {
                                    for (peer_id, addr) in list {
                                        info!("mDNS: peer artık yerel ağda görünmüyor: {} @ {}", peer_id, addr);
                                    }
                                }
                            }
                        }
                        // bkz. `P2PBehaviour.upnp`/`own_external_addr` alan
                        // dokümantasyonları — sunucusuz farklı-ağ eşleşmesi
                        // BURADA gerçek oluyor: router UPnP ile bir port
                        // eşlemesi kabul ederse `get_node_address()`'in
                        // döneceği adres artık gerçekten dışarıdan
                        // çevrilebilir olur.
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::Upnp(upnp_event)) => {
                            match upnp_event {
                                libp2p::upnp::Event::NewExternalAddr(addr) => {
                                    info!("UPnP: dışarıdan erişilebilir adres eşlendi: {}", addr);
                                    upnp_external_addr_updates.push(Some(addr));
                                }
                                libp2p::upnp::Event::ExpiredExternalAddr(addr) => {
                                    info!("UPnP: adres eşlemesi sona erdi: {}", addr);
                                    upnp_external_addr_updates.push(None);
                                }
                                libp2p::upnp::Event::GatewayNotFound => {
                                    info!("UPnP: router IGD gateway'i bulunamadı (UPnP kapalı/desteklenmiyor olabilir) — LAN/röle adresine devam ediliyor");
                                }
                                libp2p::upnp::Event::NonRoutableGateway => {
                                    info!("UPnP: gateway genel ağa doğrudan açık değil (ör. CGNAT arkasında) — LAN/röle adresine devam ediliyor");
                                }
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2PBehaviourEvent::FileChunks(rr_event)) => {
                            match rr_event {
                                request_response::Event::Message { message: request_response::Message::Request { request, channel, .. }, .. } => {
                                    file_chunk_events.push(FileChunkEventLocal::Request { request, channel });
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
                        // NOT (tanı amaçlı): dial()'ın kendisi SADECE senkron/
                        // anlık hataları (bkz. process_qr_packet) yakalar —
                        // asıl bağlantı denemesi ASENKRON yürür ve
                        // başarılı/başarısız olduğunda buraya
                        // ConnectionEstablished/OutgoingConnectionError olarak
                        // düşer. Bunları loglamadan "handshake neden
                        // tamamlanmıyor" sorusu tamamen kör kalırdı — bkz.
                        // `adb logcat` ile bu satırları arayın.
                        libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            info!("libp2p bağlantısı kuruldu: peer={} adres={:?}", peer_id, endpoint.get_remote_address());
                            new_peer_addrs.push((peer_id, endpoint.get_remote_address().clone()));
                        }
                        libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            error!("Dial başarısız: peer={:?} hata={}", peer_id, error);
                        }
                        libp2p::swarm::SwarmEvent::IncomingConnectionError { error, send_back_addr, .. } => {
                            error!("Gelen bağlantı başarısız: adres={} hata={}", send_back_addr, error);
                        }
                        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            info!("libp2p bağlantısı kapandı: peer={} sebep={:?}", peer_id, cause);
                        }
                        _ => {}
                    }
                }
            });
        }
        self.own_listen_addrs.extend(new_listen_addrs);
        for (pid, addr) in new_peer_addrs {
            self.peer_id_to_addr.insert(pid, addr);
        }
        for (pid, addr) in new_relay_peers {
            self.record_known_relay(pid, addr);
        }
        for update in upnp_external_addr_updates {
            self.own_external_addr = update;
        }

        // Dosya parça olaylarını işle — `self.swarm`'ın dışında toplandı
        // (bkz. yukarısı), böylece burada hem `&mut self` (durum
        // güncellemesi) hem de (yanıt göndermek için) `self.swarm`'a ayrı
        // ayrı erişebiliyoruz (aynı anda ikisi birden mümkün değil).
        let mut pending_chunk_responses: Vec<(request_response::ResponseChannel<FileChunkResponse>, FileChunkResponse)> = Vec::new();
        for evt in file_chunk_events {
            match evt {
                FileChunkEventLocal::Request { request, channel } => {
                    let response = self.serve_chunk_request(&request);
                    pending_chunk_responses.push((channel, response));
                }
                FileChunkEventLocal::Response { request_id, response } => {
                    if let Some(file_id) = self.download_request_ids.remove(&request_id) {
                        self.handle_chunk_response(&file_id, response);
                    }
                }
                FileChunkEventLocal::OutboundFailure { request_id } => {
                    if let Some(file_id) = self.download_request_ids.remove(&request_id) {
                        self.fail_download(&file_id, "Ağ hatası (parça istenemedi)");
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

        let mut results = Vec::new();
        results.append(&mut self.attachment_events);

        // bkz. `awaiting_confirmation` alanı dokümantasyonu — Text (grup
        // dışı)/Edit/Delete/HistorySyncRequest için TEK gerçek uçtan uca
        // teslim garantisi burası; `pending_envelopes`'in aksine karşı
        // taraf onaylayana kadar süresiz devam eder.
        self.retry_unconfirmed_messages();
        // bkz. `DOWNLOAD_STALL_TIMEOUT_MS` dokümantasyonu — bir sonraki
        // turda drenaj edilecek `file_failed` olayları üretebilir (bkz.
        // `fail_download`), bu turun `results`'ına DEĞİL (attachment_events
        // zaten yukarıda drenaj edildi) — kabul edilebilir, en fazla 1
        // saniyelik gecikme.
        self.check_stalled_downloads();

        // bkz. `reconnect_sweep` dokümantasyonu — kopmuş kişilere periyodik
        // (≤15 sn) otomatik yeniden bağlanma. Kendi içinde aralık kontrolü
        // yapar, bu yüzden her poll turunda çağrılması ucuzdur.
        self.reconnect_sweep();

        // bkz. `pending_envelopes` alanı dokümantasyonu: ilk bağlantıdan
        // sonraki ilk birkaç saniyede gönderilemeyen HERHANGİ bir zarfı
        // (handshake, identity exchange, mesaj, edit, delete, grup
        // güncellemesi...) burada, her poll turunda yeniden dener.
        // `try_publish_raw` (kuyruğa EKLEMEYEN ham versiyon) kullanılıyor —
        // aksi halde `publish_envelope` her başarısız denemede AYNI girdiyi
        // tekrar kuyruğa ekler ve zaman aşımı asla işlemezdi. Bir `Message`
        // zarfı ise başarı/zaman aşımı durumunu `message_status` üzerinden
        // UI'ye bir "status" olayıyla bildiriyoruz (bkz. MessageSendStatus).
        if !self.pending_envelopes.is_empty() {
            let pending = std::mem::take(&mut self.pending_envelopes);
            let now = current_time_ms();
            for (peer_fp, envelope, first_attempt_at) in pending {
                match self.try_publish_raw(&peer_fp, &envelope) {
                    Ok(()) => {
                        if let NetworkEnvelope::Message(m) = &envelope {
                            self.message_status.insert(m.header.message_id.clone(), MessageSendStatus::Sent);
                            results.push(serde_json::json!({
                                "type": "status", "peer": peer_fp,
                                "message_id": m.header.message_id, "status": "sent"
                            }).to_string());
                        }
                    }
                    Err(_) => {
                        if now.saturating_sub(first_attempt_at) > PENDING_ENVELOPE_TIMEOUT_MS {
                            if let NetworkEnvelope::Message(m) = &envelope {
                                self.message_status.insert(m.header.message_id.clone(), MessageSendStatus::Failed);
                                results.push(serde_json::json!({
                                    "type": "status", "peer": peer_fp,
                                    "message_id": m.header.message_id, "status": "error"
                                }).to_string());
                            }
                            // Handshake/IdentityExchange gibi message_id'siz
                            // zarflar için de aynı şekilde vazgeçiliyor —
                            // sonsuza kadar erişilemeyen bir cihaz için
                            // sınırsız büyüyen bir kuyruk istemiyoruz.
                        } else {
                            self.pending_envelopes.push((peer_fp, envelope, first_attempt_at));
                        }
                    }
                }
            }
        }

        for (source, raw) in incoming {
            match self.process_incoming_envelope(source, &raw) {
                Ok(Some(text)) => results.push(text),
                Ok(None) => {}
                Err(e) => error!("Gelen paket işlenemedi: {}", e),
            }
        }
        results
    }

    fn process_incoming_envelope(&mut self, source: Option<PeerId>, raw: &[u8]) -> Result<Option<String>, String> {
        let envelope: NetworkEnvelope = ciborium::from_reader(raw).map_err(|e| e.to_string())?;
        match envelope {
            NetworkEnvelope::IdentityExchange(x) => {
                self.record_peer_id_if_known(source, &x.device_fingerprint);
                self.process_identity_exchange(&x)?;
                Ok(None)
            }
            NetworkEnvelope::Handshake(h) => {
                self.record_peer_id_if_known(source, &h.sender_device_fingerprint);
                self.process_handshake_init(&h)?;
                Ok(None)
            }
            NetworkEnvelope::Message(m) => {
                self.record_peer_id_if_known(source, &m.header.sender_device_fingerprint);
                let text = self.receive_message(&m)?;
                Ok(Some(text))
            }
            NetworkEnvelope::GroupInvite(_) | NetworkEnvelope::DeviceAdd(_) | NetworkEnvelope::ReadReceipt(_) | NetworkEnvelope::DeviceRevoke(_) => {
                // Aşama A minimum kapsamı: GroupInvite (davetin kendisi
                // artık MessageContent::GroupUpdate(Add) ile ratchet-şifreli
                // kanaldan taşınıyor, bkz. spec 5.4 + güvenlik denetimi
                // düzeltmesi), DeviceAdd/DeviceRevoke (Aşama B, çoklu cihaz)
                // ve ReadReceipt (Aşama B, spec 1.7.1) için işleme henüz
                // kablolanmadı. Sessizce yok say.
                Ok(None)
            }
        }
    }

    // ---------------------------------------------------------------
    // Kurtarma dosyası (spec 1.8) — Aşama A'da da temel bir sürümü var,
    // tam SyncPayload/çoklu-cihaz entegrasyonu Aşama B.
    // ---------------------------------------------------------------

    fn export_recovery(&self, passphrase: String) -> Result<Vec<u8>, String> {
        let identity = self.identity.as_ref().ok_or("No identity to export")?;

        #[derive(Serialize)]
        struct ExportedDevice {
            device_fingerprint: String,
            sign_sk_ed25519: Vec<u8>,
            sign_sk_mldsa: Vec<u8>,
            kem_sk_x25519: Vec<u8>,
            kem_sk_mlkem: Vec<u8>,
        }
        #[derive(Serialize)]
        struct ExportedIdentity {
            identity_id: String,
            devices: Vec<ExportedDevice>,
        }

        let devices: Vec<ExportedDevice> = self.own_devices.values()
            .filter(|d| d.identity_id == identity.identity_id)
            .filter_map(|d| self.own_device_keys.get(&d.device_fingerprint).map(|k| ExportedDevice {
                device_fingerprint: d.device_fingerprint.clone(),
                sign_sk_ed25519: k.sign_sk_ed25519.to_bytes().to_vec(),
                sign_sk_mldsa: k.sign_sk_mldsa.to_bytes().to_vec(),
                kem_sk_x25519: k.kem_sk_x25519.to_bytes().to_vec(),
                kem_sk_mlkem: k.kem_sk_mlkem.as_bytes().to_vec(),
            }))
            .collect();

        let plaintext = serde_json::to_vec(&ExportedIdentity {
            identity_id: identity.identity_id.clone(),
            devices,
        }).map_err(|e| e.to_string())?;

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let rng = ring::rand::SystemRandom::new();
        use ring::rand::SecureRandom;
        let mut salt = [0u8; 16];
        rng.fill(&mut salt).map_err(|_| "RNG failed")?;
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes).map_err(|_| "RNG failed")?;

        // Spec dışı, güvenlik denetimi düzeltmesi: parola-tabanlı anahtar
        // türetmesi ARTIK Argon2id (memory-hard) — önceden HKDF-SHA256
        // kullanılıyordu, o tek bir HMAC olduğundan bu dosya (TÜM uzun-vadeli
        // secret key'leri taşır) sızarsa zayıf bir parola çevrimdışı
        // saniyeler içinde kırılabilirdi. Parametreler dosyada saklanır ki
        // gelecekteki bir import aynı anahtarı yeniden türetebilsin (format
        // kendini tanımlar, sabit parametrelere bağlı değil). OWASP taban
        // çizgisi: m=19 MiB, t=2, p=1.
        let (m_cost, t_cost, p_cost) = (19_456u32, 2u32, 1u32);
        let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
            .map_err(|e| format!("Argon2 params: {e}"))?;
        let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; 32];
        argon.hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| format!("Argon2 hash: {e}"))?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| "Invalid key")?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).map_err(|_| "Encryption failed")?;

        #[derive(Serialize)]
        struct RecoveryFile {
            /// Anahtar türetme algoritması — import'un ileride HKDF'li eski
            /// dosyalarla Argon2id'li yenileri ayırt edebilmesi için.
            kdf: String,
            argon2_m_cost: u32,
            argon2_t_cost: u32,
            argon2_p_cost: u32,
            ciphertext: Vec<u8>,
            nonce: Vec<u8>,
            salt: Vec<u8>,
        }
        serde_json::to_vec(&RecoveryFile {
            kdf: "argon2id".to_string(),
            argon2_m_cost: m_cost,
            argon2_t_cost: t_cost,
            argon2_p_cost: p_cost,
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            salt: salt.to_vec(),
        }).map_err(|e| e.to_string())
    }
}

// --- Yardımcı fonksiyonlar ---

fn ciborium_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// KRİTİK (bkz. `P2PBehaviour.mdns` alanı dokümantasyonu): önceden HER
/// `start_network` çağrısı (yani her süreç başlangıcı) `Keypair::generate_ed25519()`
/// ile RASTGELE, geçici bir libp2p kimliği (ve dolayısıyla `PeerId`)
/// üretiyordu — bu, "tam kapat/aç sonrası tekrar QR okutman gerekiyor"
/// şikayetinin kök nedenlerinden biriydi: bilinen bir kişinin `PeerId`'si
/// (bkz. `device_to_peer_id`) her süreç yeniden başlatmasında GEÇERSİZ
/// hâle geliyordu, çünkü KARŞI TARAF da kendi PeerId'sini değiştirmişti.
/// Artık bu kimlik `{app_files_dir}/libp2p_identity.key`'e (protobuf
/// kodlamasıyla) kalıcı kılınıyor — bir kez üretilip sonsuza kadar aynı
/// kalıyor. Bu dosya şifrelenmiyor (Android Keystore'un aksine) — bilinçli
/// bir kapsam kararı: bu, uygulamanın E2E mesaj içeriğini koruyan asıl
/// kimlik/oturum anahtarlarından (bkz. IdentityManager) AYRI, sadece ağ
/// katmanı taşıma kimliğidir; sızması mesaj içeriğini DEĞİL, sadece ağ
/// katmanında cihaz kimliğinin taklit edilebilmesini riske atar — zaten
/// uygulamaya özel (app-private) depoda, aynı DB dosyasındaki PUBLIC
/// anahtarlarla aynı güven seviyesinde.
fn load_or_generate_libp2p_keypair(app_files_dir: &str) -> libp2p::identity::Keypair {
    let path = format!("{}/libp2p_identity.key", app_files_dir);
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return kp;
        }
        error!("libp2p_identity.key bozuk/okunamadı, yeni kimlik üretiliyor");
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    match kp.to_protobuf_encoding() {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&path, bytes) {
                error!("libp2p_identity.key yazılamadı (bu süreçte kullanılacak ama kalıcı olmayacak): {}", e);
            }
        }
        Err(e) => error!("libp2p keypair encode edilemedi: {}", e),
    }
    kp
}

fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

/// 127.0.0.1/::1 gibi loopback adresleri, aynı cihaz dışından hiçbir zaman
/// dial edilemez — `get_node_address` bunları QR/rendezvous adresi olarak
/// seçmekten kaçınır (varsa gerçek bir LAN adresi tercih edilir).
fn is_loopback_multiaddr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

/// RFC 1918 özel adres aralığı (10/8, 172.16/12, 192.168/16) — ev/ofis Wi-Fi
/// ağlarının tipik adres biçimi, `Ipv4Addr::is_private()` (stdlib) ile
/// tespit edilir. Mobil operatör adresleri (CGNAT dahil, ör. 100.64/10) bu
/// aralığa GİRMEZ — `get_node_address` bu ayrımı, aynı Wi-Fi'deki karşı
/// cihazın dial edebileceği doğru arayüzü seçmek için kullanır.
fn is_private_lan_multiaddr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_private(),
        _ => false,
    })
}

/// Spec dışı, güvenlik denetimi sertleştirmesi: ÖNCEDEN her iki imza alanı
/// da opsiyoneldi (boşsa o kısım sessizce ATLANIYORDU) — bu, klasik-sadece
/// veya PQ-sadece imzalı bir paketin de kabul edilebilmesi anlamına
/// geliyordu (o an hiçbir çağıran bunu istismar etmiyordu ama fonksiyonun
/// kendisi bunu ZORUNLU kılmıyordu). Artık HER İKİ imza da dolu olmalı —
/// hibrit korumanın "post-kuantum güvenli" iddiasının, gelecekte bir
/// çağıran yanlışlıkla boş bir `sig_pq` geçirse bile sessizce klasiğe
/// düşmeyeceğinden emin olunur.
fn verify_hybrid_signature(message: &[u8], sig_classical: &[u8], sig_pq: &[u8], sender: &DeviceRecord) -> Result<(), String> {
    if sig_classical.is_empty() || sig_pq.is_empty() {
        return Err("Hybrid signature requires both classical and post-quantum components".to_string());
    }
    let pk_bytes: [u8; 32] = sender.sign_pubkey_ed25519.clone().try_into().map_err(|_| "Bad Ed25519 key length")?;
    let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| "Bad Ed25519 key")?;
    let sig_bytes: [u8; 64] = sig_classical.to_vec().try_into().map_err(|_| "Bad signature length")?;
    let sig = Ed25519Signature::from_bytes(&sig_bytes);
    pk.verify(message, &sig).map_err(|_| "Ed25519 verification failed")?;

    let pk_encoded: EncodedVerifyingKey<MlDsa87> = sender.sign_pubkey_mldsa.as_slice().try_into().map_err(|_| "Bad ML-DSA key")?;
    let pk = MlDsaVerifyingKey::<MlDsa87>::decode(&pk_encoded);
    let sig_encoded: EncodedSignature<MlDsa87> = sig_pq.try_into().map_err(|_| "Bad PQ signature")?;
    let sig = MlDsaSignature::<MlDsa87>::decode(&sig_encoded).ok_or("Bad PQ signature")?;
    pk.verify(message, &sig).map_err(|_| "ML-DSA verification failed")?;
    Ok(())
}

fn sign_group_update(
    group_id: &str,
    new_version: u32,
    change: &GroupChange,
    group_name: &str,
    signed_by: &str,
    signed_by_device: &str,
    own_keys: &DeviceKeys,
) -> Result<GroupUpdate, String> {
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(group_id.as_bytes());
    to_sign.extend_from_slice(&new_version.to_be_bytes());
    to_sign.extend_from_slice(&ciborium_bytes(change)?);
    // `group_name` de imzalanan veriye dahil — aksi halde bir relay/node bu
    // alanı sessizce değiştirebilirdi (imza sadece `change`'i koruyordu).
    to_sign.extend_from_slice(group_name.as_bytes());
    // Spec dışı, güvenlik denetimi düzeltmesi: GroupUpdate artık
    // MessagePacket/HandshakeInit ile AYNI hibrit (Ed25519 + ML-DSA)
    // imza modelini kullanıyor — önceden SADECE klasik Ed25519 imzalıydı,
    // bu da kurucu yetkisinin (üye ekleme/çıkarma/yeniden adlandırma/
    // avatar) kuantum-yetenekli bir saldırgan tarafından sahtelenebilir
    // olması anlamına geliyordu.
    let sig_classical: Ed25519Signature = own_keys.sign_sk_ed25519.sign(&to_sign);
    let sig_pq: MlDsaSignature<MlDsa87> = own_keys.sign_sk_mldsa.sign(&to_sign);
    Ok(GroupUpdate {
        group_id: group_id.to_string(),
        new_version,
        change: change.clone(),
        group_name: group_name.to_string(),
        signed_by: signed_by.to_string(),
        signed_by_device: signed_by_device.to_string(),
        signature: sig_classical.to_bytes().to_vec(),
        signature_pq: sig_pq.encode().to_vec(),
    })
}

trait OptionGroupExt {
    fn cloned_group(self) -> Result<Group, String>;
}
impl OptionGroupExt for Option<&Group> {
    fn cloned_group(self) -> Result<Group, String> {
        self.cloned().ok_or_else(|| "Group not found".to_string())
    }
}

// --- JNI Bindings ---

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_initDatabase<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, files_dir: JString<'local>) -> jboolean {
    let path: String = env.get_string(&files_dir).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(|| {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.init_db(&path).map_err(|e| e.to_string())
    });
    match result {
        Ok(Ok(_)) => true as jboolean,
        Ok(Err(e)) => { error!("initDatabase failed: {}", e); false as jboolean }
        Err(e) => { error!("initDatabase panicked: {}", e); false as jboolean }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_createIdentity<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, device_name: JString<'local>) -> jstring {
    let name: String = env.get_string(&device_name).map(|s| s.into()).unwrap_or_else(|_| "Device".to_string());
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        match core.generate_identity(name) {
            Ok((id, bundle_bytes)) => {
                // Kotlin, identity_id'yi aldıktan hemen sonra
                // getPendingSecretBundle() ile ham secret bundle'ı çekip
                // Keystore'da şifreleyip saklamalıdır — bundle burada bellekte
                // tek seferlik tutulur, tekrar okunduğunda temizlenir (bkz.
                // getPendingSecretBundle).
                core.pending_secret_bundle = Some(bundle_bytes);
                Ok(id)
            }
            Err(e) => Err(e),
        }
    });
    match result {
        Ok(Ok(id)) => env.new_string(id).unwrap().into_raw(),
        Ok(Err(e)) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
        Err(e) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
    }
}

/// `createIdentity` sonrası bir kereliğine çağrılacak: az önce üretilen
/// secret key bundle'ını (CBOR, plaintext) döner ve belleğinden siler.
/// Kotlin bunu ALDIĞI ANDA KeystoreCrypto.encrypt ile şifreleyip diske
/// yazmalı, plaintext'i kendi tarafında da elden çıkarmalıdır.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getPendingSecretBundle<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jbyteArray {
    let result = catch_panic(|| {
        let mut core = core_lock();
        core.pending_secret_bundle.take().unwrap_or_default()
    });
    let bundle = result.unwrap_or_else(|e| { error!("getPendingSecretBundle panicked: {}", e); Vec::new() });
    bytes_to_jbytearray(&mut env, &bundle)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_loadSecretBundle<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, bundle_bytes: JByteArray<'local>) -> jboolean {
    let raw = jbytearray_to_vec(&mut env, &bundle_bytes);
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.load_secret_bundle(&raw)
    });
    match result {
        Ok(Ok(_)) => true as jboolean,
        Ok(Err(e)) => { error!("load_secret_bundle failed: {}", e); false as jboolean }
        Err(e) => { error!("load_secret_bundle panicked: {}", e); false as jboolean }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_hasStoredIdentity<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jboolean {
    let result = catch_panic(|| {
        let core = core_lock();
        core.identity.is_some()
    });
    result.unwrap_or(false) as jboolean
}

/// Kotlin'in Keystore ile sarmalanmış (wrapped) bir "history data key"i
/// çözüp buraya yüklemesi için. `key_bytes` tam 32 bayt olmalıdır (256-bit
/// ChaCha20-Poly1305 anahtarı). Rust bu anahtarı diske hiç yazmaz, sadece
/// bellekte tutar — bkz. `history_key` alanı dokümantasyonu.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setHistoryKey<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, key_bytes: JByteArray<'local>) -> jboolean {
    let raw = jbytearray_to_vec(&mut env, &key_bytes);
    let key: [u8; 32] = match raw.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => return false as jboolean,
    };
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.history_key = Some(key);
    });
    result.is_ok() as jboolean
}

/// Skipped-message-key önbelleğinin diske şifreli kalıcılığı için
/// kullanılan anahtarı yükler (bkz. `P2PCore.skipped_key_encryption_key`
/// dokümantasyonu). Node modundan BAĞIMSIZ her zaman yüklenmelidir —
/// `history_key`'in aksine bu opsiyonel bir arşivleme değil, mesajlaşmanın
/// güvenilirliği için gerekli bir mekanizmadır.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setSkippedKeyEncryptionKey<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, key_bytes: JByteArray<'local>) -> jboolean {
    let raw = jbytearray_to_vec(&mut env, &key_bytes);
    let key: [u8; 32] = match raw.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => return false as jboolean,
    };
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.skipped_key_encryption_key = Some(key);
        // Bu anahtar aynı zamanda ratchet state'lerin diskte şifreli
        // kalıcılığı için de kullanılıyor (bkz. persist_ratchet_state) —
        // anahtar yüklenir yüklenmez, önceki süreçten kalan oturumları
        // geri yükle.
        core.load_ratchet_states_from_db();
    });
    result.is_ok() as jboolean
}

/// Bir kişiyle olan yerel şifreli mesaj geçmişini çözüp JSON olarak döner
/// (`List<ArchivedMessage>`). `history_key` yüklenmemişse veya bu kişiyle
/// hiç arşivlenmiş mesaj yoksa boş dizi döner — bu bir hata değildir (node
/// modu hiç açılmamış olabilir, spec dışı kullanıcı tercihi).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getMessageHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, limit: jni::sys::jint) -> jstring {
    let fp: String = env.get_string(&peer_device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock();
        let history = core.load_message_history(&fp, limit.max(0) as u32);
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getMessageHistory panicked: {}", e); "[]".to_string() });
    env.new_string(json).unwrap().into_raw()
}

/// Spec dışı: dosya/foto/video/ses eki gönderir (bkz.
/// `P2PCore::prepare_and_send_file`). `source_path` Kotlin tarafından
/// zaten yerel bir dosya yoluna kopyalanmış olmalı (content:// URI burada
/// işlenmez). BİLİNEN SINIR: senkron bir çağrı — büyük dosyalar için
/// Kotlin tarafı bunu ana thread DIŞINDA (coroutine/Dispatchers.IO)
/// çağırmalıdır, aksi halde ANR riski vardır. Dönüş: `sendMessage` ile
/// aynı JSON biçimi, `message_id` alanı burada `file_id`'dir.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_prepareAndSendFile<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, source_path: JString<'local>, file_name: JString<'local>, mime_type: JString<'local>, preview_jpeg: JByteArray<'local>, duration_ms: jni::sys::jint) -> jstring {
    let target_str: String = env.get_string(&target).map(|s| s.into()).unwrap_or_default();
    let source_str: String = env.get_string(&source_path).map(|s| s.into()).unwrap_or_default();
    let name_str: String = env.get_string(&file_name).map(|s| s.into()).unwrap_or_default();
    let mime_str: String = env.get_string(&mime_type).map(|s| s.into()).unwrap_or_default();
    // `preview_jpeg` foto/video DIŞINDAKİ türler için Kotlin tarafından
    // `null` geçirilir (bkz. P2PLib.kt) — JNI'da bu, alttaki JObject'in
    // null olmasıyla temsil edilir.
    let preview_vec: Option<Vec<u8>> = if preview_jpeg.is_null() {
        None
    } else {
        Some(jbytearray_to_vec(&mut env, &preview_jpeg))
    };
    // `duration_ms`: sesli mesaj DIŞINDAKİ türler için Kotlin -1 geçirir
    // (jint null taşıyamadığından) — burada `Option<u32>`'ye çevrilir.
    let duration_opt: Option<u32> = if duration_ms < 0 { None } else { Some(duration_ms as u32) };
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.prepare_and_send_file(target_str, source_str, name_str, mime_str, preview_vec, duration_opt)
    });
    match result {
        Ok(Ok((file_id, status))) => env.new_string(serde_json::json!({"message_id": file_id, "status": status}).to_string()).unwrap().into_raw(),
        Ok(Err(e)) => { error!("prepare_and_send_file failed: {}", e); env.new_string(format!("Error: {}", e)).unwrap().into_raw() }
        Err(e) => { error!("prepare_and_send_file panicked: {}", e); env.new_string(format!("Error: {}", e)).unwrap().into_raw() }
    }
}

/// Bir dosyanın parçalarını indirmeyi başlatır — BAŞARIYLA döndüyse
/// ("OK") ilerleme/tamamlanma `pollNetwork`'ün `"file_progress"`/
/// `"file_complete"`/`"file_failed"` olaylarıyla bildirilir (bkz.
/// `P2PCore::download_file`). BAŞARISIZSA (`"Error: ..."`) senkron olarak
/// hemen döner — bu durumda `pollNetwork` üzerinden HİÇBİR olay
/// gelmeyecektir (indirme hiç başlamadı: `active_downloads`'a hiç
/// eklenmedi), çağıran taraf bunu KENDİSİ ele almalı (bkz. ChatActivity
/// notu — önceden bu dönüş değeri jboolean'dı ve Kotlin tarafında hiç
/// kontrol edilmiyordu, bu da "İndiriliyor" durumunda sonsuza kadar
/// takılı kalan bir UI'ye yol açıyordu).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_downloadFile<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>, peer_device_fingerprint: JString<'local>) -> jstring {
    let file_id_str: String = env.get_string(&file_id).map(|s| s.into()).unwrap_or_default();
    let fp: String = env.get_string(&peer_device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.download_file(file_id_str, fp)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("download_file failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("download_file panicked: {}", e); format!("Error: {}", e) }
    };
    env.new_string(out).unwrap().into_raw()
}

/// JSON-encoded `List<AttachmentSummary>` — bir sohbetteki bilinen dosya
/// eklerini listeler (bkz. `P2PCore::list_attachments`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listAttachments<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) -> jstring {
    let fp: String = env.get_string(&peer_device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock();
        let list = core.list_attachments(&fp);
        serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listAttachments panicked: {}", e); "[]".to_string() });
    env.new_string(json).unwrap().into_raw()
}

/// Tamamlanmış bir ekin düz metin (çözülmüş) kopyasının mutlak yolunu
/// döner, ya da hata varsa `"Error: ..."`. BİLİNEN SINIR: senkron — büyük
/// dosyalar için Kotlin tarafı ana thread DIŞINDA çağırmalıdır (bkz.
/// `P2PCore::get_attachment_plaintext_path`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getAttachmentPlaintextPath<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>) -> jstring {
    let file_id_str: String = env.get_string(&file_id).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock();
        core.get_attachment_plaintext_path(&file_id_str)
    });
    match result {
        Ok(Ok(path)) => env.new_string(path).unwrap().into_raw(),
        Ok(Err(e)) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
        Err(e) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getIdentityCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock();
        core.identity_code()
    });
    match result {
        Ok(Ok(code)) => env.new_string(code).unwrap().into_raw(),
        Ok(Err(e)) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
        Err(e) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getIdentityShortCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock();
        core.identity_short_code()
    });
    match result {
        Ok(Ok(code)) => env.new_string(code).unwrap().into_raw(),
        Ok(Err(e)) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
        Err(e) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_startNetwork<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, node_mode: jboolean) -> jstring {
    let result = catch_panic(move || {
        // `SwarmBuilder::with_tokio()` (start_network içinde) bir Tokio runtime
        // context'inin thread-local olarak aktif olmasını gerektirir — bu JNI
        // çağrısı ham bir JNI thread'inde çalıştığından, `RUNTIME.enter()` ile
        // context'i elle kurmadan çağırmak panic'e yol açar (bkz. catch_panic
        // dokümantasyonu — JNI çağrıları HERHANGİ bir Java/Kotlin thread'inden
        // gelebilir, bu yüzden context'i HER JNI export'unda ayrı ayrı kurmak
        // gerekir; bir thread'de enter() etmek başka bir thread'i etkilemez).
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.start_network(node_mode != 0)
    });
    match result {
        Ok(Ok(pid)) => env.new_string(pid).unwrap().into_raw(),
        Ok(Err(e)) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
        Err(e) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setNodeMode(_env: JNIEnv, _class: JClass, enabled: jboolean) {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.set_node_mode(enabled != 0);
    });
}

/// Karşı tarafın dial edebileceği gerçek `node_address` (bkz.
/// `P2PCore::get_node_address`). `start_network` sonrası ilk birkaç
/// `pollNetwork` turuna kadar (henüz hiçbir dinleme adresi bildirilmediyse)
/// boş string döner — Kotlin tarafı buna göre "bağlanılıyor" göstermeli,
/// ASLA sabit bir `/ip4/0.0.0.0/tcp/0` yerine koymamalı.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getNodeAddress<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock();
        core.get_node_address().unwrap_or_default()
    });
    let addr = result.unwrap_or_else(|e| { error!("getNodeAddress panicked: {}", e); String::new() });
    env.new_string(addr).unwrap().into_raw()
}

/// Spec dışı: ChatActivity'nin "bağlanılıyor..." göstergesi için — bkz.
/// `P2PCore::has_active_session`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_hasActiveSession<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) -> jboolean {
    let fp: String = env.get_string(&peer_device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock();
        core.has_active_session(&fp)
    });
    result.unwrap_or(false) as jboolean
}

/// Spec dışı: GERÇEK canlı bağlantı durumu (bkz. `P2PCore::is_peer_connected`
/// dokümantasyonu) — `hasActiveSession`'ın aksine bir kez kurulduktan sonra
/// hep `true` kalmaz, `Swarm`'ın o anki bağlantı defterini yansıtır.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_isPeerConnected<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) -> jboolean {
    let fp: String = env.get_string(&peer_device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock();
        core.is_peer_connected(&fp)
    });
    result.unwrap_or(false) as jboolean
}

/// Spec dışı: bir sohbet ekranı açıldığında proaktif olarak el sıkışmayı
/// başlatır — bkz. `P2PCore::ensure_handshake`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_ensureHandshake<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) {
    let fp: String = env.get_string(&peer_device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        if let Err(e) = core.ensure_handshake(&fp) {
            error!("ensure_handshake failed: {}", e);
        }
    });
}

/// Spec dışı: node modu kapalı bir cihazda sohbet ekranı yerel geçmiş
/// bulamadığında çağrılır — bkz. `P2PCore::request_history_sync`. Yanıt
/// asenkron (`pollNetwork` üzerinden `"history_sync"` olayı) geldiği için
/// bu fonksiyon hemen döner, sonuç beklemez.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_requestHistorySync<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, limit: jni::sys::jint) {
    let fp: String = env.get_string(&peer_device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let limit_u32 = limit.max(0) as u32;
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        if let Err(e) = core.request_history_sync(fp, limit_u32) {
            error!("request_history_sync failed: {}", e);
        }
    });
}

/// Spec dışı: kullanıcının bir eki kaydetmeden önce göndericiden onay
/// istemesi (bkz. `P2PCore::request_save_approval`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_requestSaveApproval<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>, peer_device_fingerprint: JString<'local>, file_name: JString<'local>) {
    let file_id_str: String = env.get_string(&file_id).map(|s| s.into()).unwrap_or_default();
    let fp: String = env.get_string(&peer_device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let name_str: String = env.get_string(&file_name).map(|s| s.into()).unwrap_or_default();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        if let Err(e) = core.request_save_approval(file_id_str, fp, name_str) {
            error!("request_save_approval failed: {}", e);
        }
    });
}

/// Spec dışı: göndericinin gelen bir `SaveRequest`'e cevabı (bkz.
/// `P2PCore::respond_to_save_request`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_respondToSaveRequest<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>, peer_device_fingerprint: JString<'local>, approved: jboolean) {
    let file_id_str: String = env.get_string(&file_id).map(|s| s.into()).unwrap_or_default();
    let fp: String = env.get_string(&peer_device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let approved_bool = approved != 0;
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        if let Err(e) = core.respond_to_save_request(file_id_str, fp, approved_bool) {
            error!("respond_to_save_request failed: {}", e);
        }
    });
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_generateQrPacket<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, rendezvous_node: JString<'local>) -> jni::sys::jbyteArray {
    let node: String = env.get_string(&rendezvous_node).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock();
        core.generate_qr_packet(node)
    });
    match result {
        Ok(Ok(bytes)) => bytes_to_jbytearray(&mut env, &bytes),
        Ok(Err(e)) => { error!("generate_qr_packet failed: {}", e); env.new_byte_array(0).unwrap().into_raw() }
        Err(e) => { error!("generate_qr_packet panicked: {}", e); env.new_byte_array(0).unwrap().into_raw() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getManualAddCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, rendezvous_node: JString<'local>) -> jstring {
    let node: String = env.get_string(&rendezvous_node).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock();
        core.generate_manual_add_code(&node)
    });
    let out = match result {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => { error!("generate_manual_add_code failed: {}", e); String::new() }
        Err(e) => { error!("generate_manual_add_code panicked: {}", e); String::new() }
    };
    env.new_string(out).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_processQrPacket<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, data: JByteArray<'local>) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &data);
    let result = catch_panic(move || {
        // bkz. startNetwork notu — bu JNI çağrısı (kamera analiz thread'i
        // gibi) startNetwork'ü çağıran thread'den TAMAMEN FARKLI bir
        // thread'de çalışabilir; `dial()`'ın tetiklediği libp2p executor
        // görevleri için burada da AYRICA bir Tokio context'i gerekir —
        // bu satır olmadan tam olarak bu fonksiyonda yaşanan
        // "there is no reactor running" panic'i tekrarlanırdı.
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.process_qr_packet(&raw)
    });
    match result {
        Ok(Ok(identity_id)) => env.new_string(identity_id).unwrap().into_raw(),
        Ok(Err(e)) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
        Err(e) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_processManualEntry<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, text: JString<'local>) -> jstring {
    let text_str: String = env.get_string(&text).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.process_manual_entry(&text_str)
    });
    match result {
        Ok(Ok(identity_id)) => env.new_string(identity_id).unwrap().into_raw(),
        Ok(Err(e)) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
        Err(e) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
    }
}

/// Dönüş: başarılıysa `{"message_id":"...","status":"sent"|"pending"}`,
/// başarısızsa `"Error: ..."`. `status`, UI'nin gönderim ikonunu (saat/tik)
/// hemen doğru göstermesi için — "pending" ise arka planda otomatik olarak
/// yeniden denenip bir "status" olayıyla (bkz. pollNetwork) güncellenecek.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, msg: JString<'local>) -> jstring {
    let target_str: String = env.get_string(&target).map(|s| s.into()).unwrap_or_default();
    let msg_str: String = env.get_string(&msg).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_message(target_str, msg_str)
    });
    match result {
        Ok(Ok((message_id, status))) => env.new_string(serde_json::json!({"message_id": message_id, "status": status}).to_string()).unwrap().into_raw(),
        Ok(Err(e)) => { error!("send_message failed: {}", e); env.new_string(format!("Error: {}", e)).unwrap().into_raw() }
        Err(e) => { error!("send_message panicked: {}", e); env.new_string(format!("Error: {}", e)).unwrap().into_raw() }
    }
}

/// Bir mesajı düzenler — bkz. `P2PCore::edit_message` dokümantasyonu.
/// Dönüş: `sendMessage` ile aynı JSON biçimi (bu, edit paketinin KENDİ
/// message_id'sidir — UI, düzenlenen ORİJİNAL mesajın id'sini kullanmaya
/// devam etmeli, bkz. ChatActivity).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_editMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, target_message_id: JString<'local>, new_text: JString<'local>) -> jstring {
    let target_str: String = env.get_string(&target).map(|s| s.into()).unwrap_or_default();
    let target_message_id_str: String = env.get_string(&target_message_id).map(|s| s.into()).unwrap_or_default();
    let new_text_str: String = env.get_string(&new_text).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.edit_message(target_str, target_message_id_str, new_text_str)
    });
    match result {
        Ok(Ok((message_id, status))) => env.new_string(serde_json::json!({"message_id": message_id, "status": status}).to_string()).unwrap().into_raw(),
        Ok(Err(e)) => { error!("edit_message failed: {}", e); env.new_string(format!("Error: {}", e)).unwrap().into_raw() }
        Err(e) => { error!("edit_message panicked: {}", e); env.new_string(format!("Error: {}", e)).unwrap().into_raw() }
    }
}

/// Bir mesajı siler — bkz. `P2PCore::delete_message` dokümantasyonu.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deleteMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, target_message_id: JString<'local>) -> jstring {
    let target_str: String = env.get_string(&target).map(|s| s.into()).unwrap_or_default();
    let target_message_id_str: String = env.get_string(&target_message_id).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.delete_message(target_str, target_message_id_str)
    });
    match result {
        Ok(Ok((message_id, status))) => env.new_string(serde_json::json!({"message_id": message_id, "status": status}).to_string()).unwrap().into_raw(),
        Ok(Err(e)) => { error!("delete_message failed: {}", e); env.new_string(format!("Error: {}", e)).unwrap().into_raw() }
        Err(e) => { error!("delete_message panicked: {}", e); env.new_string(format!("Error: {}", e)).unwrap().into_raw() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_pollNetwork<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jobjectArray {
    let result = catch_panic(|| {
        // `poll_events` kendi içinde zaten `RUNTIME.block_on(...)` kullanıyor
        // (bu da context'i kurar) ama tutarlılık için burada da enter ediyoruz.
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.poll_events()
    });
    let texts = result.unwrap_or_else(|e| { error!("pollNetwork panicked: {}", e); Vec::new() });
    strings_to_jobjectarray(&mut env, &texts)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listContacts<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock();
        let contacts = core.list_contacts();
        serde_json::to_string(&contacts).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listContacts panicked: {}", e); "[]".to_string() });
    env.new_string(json).unwrap().into_raw()
}

/// "Yazıyor..." göstergesi gönderir — bkz. `P2PCore::send_typing_indicator`.
/// Kasıtlı olarak sessizce başarısız olabilir (fire-and-forget, `Boolean`
/// dönüşü sadece hata ayıklama için, Kotlin tarafı bunu genelde kontrol
/// etmez).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendTypingIndicator<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, is_typing: jboolean) -> jboolean {
    let target_str: String = env.get_string(&target).map(|s| s.into()).unwrap_or_default();
    let typing = is_typing != 0;
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_typing_indicator(target_str, typing)
    });
    match result {
        Ok(Ok(())) => true as jboolean,
        Ok(Err(e)) => { error!("send_typing_indicator failed: {}", e); false as jboolean }
        Err(e) => { error!("send_typing_indicator panicked: {}", e); false as jboolean }
    }
}

/// "Görüldü" bildirimi gönderir — bkz. `P2PCore::send_seen`. UI, bir
/// mesajı kullanıcıya EKRANDA gösterdiği anda çağırmalı (otomatik değil —
/// bkz. `Ack`'in aksine). `group_message_local_id` 1:1 sohbette null
/// geçilmeli, grup sohbetinde gelen "group_message" olayındaki AYNI
/// değer geri gönderilmeli.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendSeenReceipt<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, target_message_id: JString<'local>, group_message_local_id: JString<'local>) -> jboolean {
    let target_str: String = env.get_string(&target).map(|s| s.into()).unwrap_or_default();
    let target_message_id_str: String = env.get_string(&target_message_id).map(|s| s.into()).unwrap_or_default();
    let local_id: Option<String> = if group_message_local_id.is_null() {
        None
    } else {
        env.get_string(&group_message_local_id).ok().map(|s| s.into())
    };
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_seen(&target_str, &target_message_id_str, local_id);
    });
    result.is_ok() as jboolean
}

/// Kendi profil fotoğrafımızı döner (hiç ayarlanmadıysa boş dizi) — bkz.
/// `P2PCore::get_own_avatar`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getOwnProfilePicture<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jbyteArray {
    let result = catch_panic(|| {
        let core = core_lock();
        core.get_own_avatar().unwrap_or_default()
    });
    let bytes = result.unwrap_or_else(|e| { error!("getOwnProfilePicture panicked: {}", e); Vec::new() });
    bytes_to_jbytearray(&mut env, &bytes)
}

/// Kendi profil fotoğrafımızı ayarlar/kaldırır — bkz.
/// `P2PCore::set_own_profile_picture`. `avatar_jpeg` null ise fotoğraf
/// kaldırılır (tüm kişilere `None` bildirimi gönderilir).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setOwnProfilePicture<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, avatar_jpeg: JByteArray<'local>) -> jstring {
    let avatar_vec: Option<Vec<u8>> = if avatar_jpeg.is_null() {
        None
    } else {
        Some(jbytearray_to_vec(&mut env, &avatar_jpeg))
    };
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.set_own_profile_picture(avatar_vec)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("set_own_profile_picture failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("set_own_profile_picture panicked: {}", e); format!("Error: {}", e) }
    };
    env.new_string(out).unwrap().into_raw()
}

/// Bir sohbetin yerel geçmişini (mesajlar+ekler) temizler, eşleşmeyi
/// KORUR — bkz. `P2PCore::clear_chat_history`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_clearChatHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, contact_id: JString<'local>) -> jstring {
    let contact_id_str: String = env.get_string(&contact_id).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.clear_chat_history(&contact_id_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("clear_chat_history failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("clear_chat_history panicked: {}", e); format!("Error: {}", e) }
    };
    env.new_string(out).unwrap().into_raw()
}

/// Bir kişiyi TAMAMEN siler (eşleşme dahil) — bkz. `P2PCore::delete_contact`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deleteContact<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, contact_id: JString<'local>) -> jstring {
    let contact_id_str: String = env.get_string(&contact_id).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.delete_contact(&contact_id_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("delete_contact failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("delete_contact panicked: {}", e); format!("Error: {}", e) }
    };
    env.new_string(out).unwrap().into_raw()
}

/// Bir kişinin TEK bir cihazını iptal eder (kişiyi/geçmişi SİLMEZ) — bkz.
/// `P2PCore::revoke_contact_device`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_revokeContactDevice<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, contact_id: JString<'local>, device_fingerprint: JString<'local>) -> jstring {
    let contact_id_str: String = env.get_string(&contact_id).map(|s| s.into()).unwrap_or_default();
    let fp_str: String = env.get_string(&device_fingerprint).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.revoke_contact_device(&contact_id_str, &fp_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("revoke_contact_device failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("revoke_contact_device panicked: {}", e); format!("Error: {}", e) }
    };
    env.new_string(out).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_addKnownRelayAddress<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, multiaddr: JString<'local>) -> jstring {
    let multiaddr_str: String = env.get_string(&multiaddr).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.add_known_relay_address(&multiaddr_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("add_known_relay_address failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("add_known_relay_address panicked: {}", e); format!("Error: {}", e) }
    };
    env.new_string(out).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listPendingDeviceAlerts<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock();
        let alerts = core.list_pending_device_alerts();
        serde_json::to_string(&alerts).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listPendingDeviceAlerts panicked: {}", e); "[]".to_string() });
    env.new_string(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_acceptDeviceAlert<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, fingerprint: JString<'local>) -> jboolean {
    let fp: String = env.get_string(&fingerprint).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.accept_pending_device_alert(&fp).is_ok()
    });
    result.unwrap_or(false) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_rejectDeviceAlert(mut _env: JNIEnv, _class: JClass, fingerprint: JString) {
    let fp: String = _env.get_string(&fingerprint).map(|s| s.into()).unwrap_or_default();
    let _ = catch_panic(move || {
        let mut core = core_lock();
        core.reject_pending_device_alert(&fp);
    });
}

/// JSON-encoded List<GroupSummary> — Groups tab GUI'si için.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listGroups<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock();
        let groups = core.list_groups();
        serde_json::to_string(&groups).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listGroups panicked: {}", e); "[]".to_string() });
    env.new_string(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_createGroup<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, name: JString<'local>) -> jstring {
    let name_str: String = env.get_string(&name).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.create_group(name_str)
    });
    match result {
        Ok(Ok(id)) => env.new_string(id).unwrap().into_raw(),
        Ok(Err(e)) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
        Err(e) => env.new_string(format!("Error: {}", e)).unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_inviteToGroup<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, identity_id: JString<'local>) -> jboolean {
    let gid: String = env.get_string(&group_id).map(|s| s.into()).unwrap_or_default();
    let iid: String = env.get_string(&identity_id).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.invite_to_group(&gid, &iid)
    });
    match result {
        Ok(Ok(_)) => true as jboolean,
        Ok(Err(e)) => { error!("invite_to_group failed: {}", e); false as jboolean }
        Err(e) => { error!("invite_to_group panicked: {}", e); false as jboolean }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_removeFromGroup<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, identity_id: JString<'local>) -> jboolean {
    let gid: String = env.get_string(&group_id).map(|s| s.into()).unwrap_or_default();
    let iid: String = env.get_string(&identity_id).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.remove_from_group(&gid, &iid)
    });
    match result {
        Ok(Ok(_)) => true as jboolean,
        Ok(Err(e)) => { error!("remove_from_group failed: {}", e); false as jboolean }
        Err(e) => { error!("remove_from_group panicked: {}", e); false as jboolean }
    }
}

/// Grup profil fotoğrafını ayarlar/kaldırır — bkz. `P2PCore::set_group_avatar`.
/// SADECE kurucu için başarılı olur, aksi halde "Error: ..." döner (bkz.
/// Kotlin tarafının bunu göstermesi gereken bir hata olarak ele alması —
/// `inviteToGroup`/`removeFromGroup`'un aksine burada dönüş `jboolean`
/// DEĞİL `jstring`, çünkü "neden" başarısız olduğu kullanıcıya
/// gösterilmeye değer bir bilgi.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setGroupProfilePicture<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, avatar_jpeg: JByteArray<'local>) -> jstring {
    let gid: String = env.get_string(&group_id).map(|s| s.into()).unwrap_or_default();
    let avatar_vec: Option<Vec<u8>> = if avatar_jpeg.is_null() {
        None
    } else {
        Some(jbytearray_to_vec(&mut env, &avatar_jpeg))
    };
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.set_group_avatar(&gid, avatar_vec)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("set_group_avatar failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("set_group_avatar panicked: {}", e); format!("Error: {}", e) }
    };
    env.new_string(out).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendGroupMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, msg: JString<'local>) -> jstring {
    let gid: String = env.get_string(&group_id).map(|s| s.into()).unwrap_or_default();
    let msg_str: String = env.get_string(&msg).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_group_message(&gid, &msg_str)
    });
    let out = match result {
        Ok(Ok(local_id)) => local_id,
        Ok(Err(e)) => { error!("send_group_message failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("send_group_message panicked: {}", e); format!("Error: {}", e) }
    };
    env.new_string(out).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_exportRecovery<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, pass: JString<'local>) -> jni::sys::jbyteArray {
    let pass_str: String = env.get_string(&pass).map(|s| s.into()).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock();
        core.export_recovery(pass_str)
    });
    match result {
        Ok(Ok(bytes)) => bytes_to_jbytearray(&mut env, &bytes),
        Ok(Err(e)) => { error!("export_recovery failed: {}", e); env.new_byte_array(0).unwrap().into_raw() }
        Err(e) => { error!("export_recovery panicked: {}", e); env.new_byte_array(0).unwrap().into_raw() }
    }
}

// --- JNI yardımcıları ---

/// Rust'ın varsayılan davranışı: bir panic, `extern "system"` (JNI) gibi bir
/// FFI sınırından unwind ederek geçmeye çalışırsa, bunu güvenle
/// yapamayacağı için process'i SESSİZCE `abort()` eder — tüm uygulama
/// çöker (bkz. processQrPacket çökmesi: dial()/gossipsub publish() zincirinde
/// "there is no reactor running" panic'i oluştu ve tüm süreç düştü). Her JNI
/// export'u, çağırdığı `P2PCore` metodunu bu fonksiyonla sarmalar: panic
/// olursa (yukarıdaki `set_hook` sayesinde tam mesajı zaten logcat'e
/// yazılmış olur) process düşmez, `Err(...)` olarak geri döner.
///
/// ÖNEMLİ: `f` kapanışı KESİNLİKLE `env: JNIEnv` yakalamamalı/kullanmamalı.
/// İlk denemede bunu ihlal etmiştik: panic durumunda `env.new_string(...)`
/// hiç çalışmadığından `jstring` olarak `std::ptr::null_mut()` dönüyorduk —
/// bu da Kotlin tarafında `external fun ...: String` (non-null) sözleşmesini
/// bozup ayrı bir `NullPointerException` çökmesine yol açtı (bkz. o oturumun
/// geçmişi). Doğru desen: `catch_panic` SADECE saf Rust mantığını
/// (CORE.lock() + core metodu) çalıştırır; sonucu `env`'e çeviren
/// `new_string`/`bytes_to_jbytearray` çağrıları HER ZAMAN bu fonksiyonun
/// DIŞINDA, panic'ten etkilenmeyen çağıran kodda yapılır — böylece panic
/// olsun olmasın her zaman geçerli bir (non-null) JNI değeri döner.
fn catch_panic<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|payload| {
        // Panic mesajının TAMAMI `set_hook` ile zaten logcat'e yazıldı;
        // burada çağıran tarafa dönecek kısa bir özet üretiyoruz.
        if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "internal panic (bkz. logcat 'PANIC yakalandı')".to_string()
        }
    })
}

fn bytes_to_jbytearray<'local>(env: &mut JNIEnv<'local>, bytes: &[u8]) -> jni::sys::jbyteArray {
    let arr = env.new_byte_array(bytes.len() as i32).unwrap();
    let i8_bytes: Vec<i8> = bytes.iter().map(|&b| b as i8).collect();
    env.set_byte_array_region(&arr, 0, &i8_bytes).unwrap();
    arr.into_raw()
}

fn jbytearray_to_vec<'local>(env: &mut JNIEnv<'local>, data: &JByteArray<'local>) -> Vec<u8> {
    let len = env.get_array_length(data).unwrap_or(0) as usize;
    let mut buf = vec![0i8; len];
    let _ = env.get_byte_array_region(data, 0, &mut buf);
    buf.iter().map(|&b| b as u8).collect()
}

fn strings_to_jobjectarray<'local>(env: &mut JNIEnv<'local>, texts: &[String]) -> jobjectArray {
    let string_class = env.find_class("java/lang/String").unwrap();
    let empty = env.new_string("").unwrap();
    let arr = env.new_object_array(texts.len() as i32, string_class, empty).unwrap();
    for (i, text) in texts.iter().enumerate() {
        let jstr = env.new_string(text).unwrap();
        env.set_object_array_element(&arr, i as i32, jstr).unwrap();
    }
    arr.into_raw()
}

// =====================================================================
// BİLİNEN EKSİKLER / KAPSAM DIŞI (dürüstçe işaretlenmiştir):
//
// NOT: Bu blok, kod geliştikçe güncel tutulmalı. Aşağıdaki maddeler ŞU AN
// hâlâ geçerli olan gerçek sınırlardır — daha önce burada listelenip
// sonradan ÇÖZÜLEN maddeler (GroupUpdate hibrit imzası, rotasyon senkronu,
// skipped-key cache, IdentityExchange'in TOFU akışına girmesi) yanıltıcı
// olmasın diye SİLİNDİ; çözümleri ilgili fonksiyonların/SECURITY.md'nin
// dokümantasyonunda.
//
// 1. Aşama B çoklu-cihaz akışı bu dosyada YOK: `NetworkEnvelope::DeviceAdd`/
//    `DeviceRevoke`/`GroupInvite`/`ReadReceipt` varyantları alınır ama
//    `process_incoming_envelope`'ta SESSİZCE yok sayılır (işleme
//    kablolanmadı). Pratik sonuç: cihaz iptali/eklemesi ağ üzerinden
//    YAYILMAZ — sadece yerel `revoke_contact_device` çalışır. Bir
//    Identity'ye ikinci bir cihaz eklemenin uçtan uca akışı da yok.
// 2. Node modu yalnızca Android'de çalışır — ayrı bir Linux masaüstü/
//    sunucu istemcisi yok (spec 7'deki "önce masaüstünde test" notu bu
//    kod tabanı için geçersiz).
// 3. Kurtarma dosyası (`export_recovery`) yalnızca DIŞA aktarır — karşılık
//    gelen bir içe-aktarma (import) yolu henüz yok (Aşama B). Dosya formatı
//    kendini tanımlar (kdf/parametreler saklanır) ki ileride import
//    eklenebilsin.
// 4. Grup üyelik senkronu "self-healing" değil: bir üye ara güncellemeleri
//    kaçırırsa artık KİLİTLENMİYOR (ileri sıçramalara izin verilir, bkz.
//    validate_group_update) ama kaçırılan Add/Remove'lar için tam durum
//    yeniden-senkronu (founder'dan tüm üyelik listesini çekme) yok —
//    yerel üyelik listesi geçici olarak eksik kalabilir (loglanır).
// =====================================================================
