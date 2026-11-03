//! Sunucu (store-and-forward) seçeneğinin İSTEMCİ tarafı.
//!
//! `lib.rs` zaten 12.8k satır; bu yüzden mantık ayrı bir alt modülde ama
//! `impl P2PCore` olarak — Rust'ta bir tipin inherent impl'i aynı crate'te
//! HERHANGİ bir modülde olabilir ve alt modüller üst modülün private
//! alanlarını görebilir. Yani `P2PCore`'un alanları burada da erişilebilir,
//! yeni bir görünürlük/köprü katmanı gerekmiyor.
//!
//! ## Tasarımın özü
//!
//! Mevcut güvenilirlik makinesi (`awaiting_confirmation`, `pending_envelopes`,
//! `pending_durable_retries`, `MessageContent::Ack`) HİÇ DEĞİŞMİYOR. Sadece
//! TAŞIYICI ilkel değişiyor: `try_publish_raw` gossipsub'a vermeden önce
//! sunucuya bırakmayı deniyor. Bu yüzden bu dosyada tek bir yeniden deneme
//! döngüsü yok — hepsi zaten var.
//!
//! ## Kara delik kuralı (bu dosyadaki en önemli şey)
//!
//! Sunucu "yazdım" dedi diye gossipsub'ı KALICI OLARAK susturmuyoruz.
//! Sustursaydık, kötü niyetli VEYA sadece bozuk bir sunucu mükemmel bir kara
//! delik olurdu: `Deposited` yanıtlar, hiç teslim etmez, gönderen de iki gün
//! boyunca 120 sn'de bir aynı sunucuya yeniden bırakır ve gossipsub hiç
//! denenmez. Bunun yerine bkz. `should_shadow_on_gossipsub`.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signer as _, SigningKey};
use ml_dsa::{
    Generate as MlDsaGenerate, KeyExport as _, Keypair as MlDsaKeypair, MlDsa87,
    Signature as MlDsaSignature, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey,
};
use libp2p::{request_response, Multiaddr, PeerId};
use log::{error, info, warn};
use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::packet::NetworkEnvelope;
use crate::server_proto::{
    self, ArchiveRecord, ServerErrorCode, ServerLimits, ServerRequest, ServerResponse, MAX_DEPOSIT_BYTES,
    MAX_FETCH_BATCH_BYTES, MAX_FETCH_BATCH_ITEMS, SERVER_PROTOCOL_VERSION,
};
use crate::server_seal;
use crate::{current_time_ms, extract_peer_id, mono_ms, P2PCore};

/// Sunucudan hiçbir haber gelmese bile emniyet amaçlı tam tarama aralığı.
///
/// Normalde çekme, sunucunun ittiği `Push`/`Notify` ile tetiklenir. In radio
/// saver mode the sweep itself only runs inside the radio window, so the
/// real cadence is this interval or the next window, whichever is later.
/// A safety net only. New mail comes as `Push`/`Notify` over the open
/// connection, and the server repeats an unanswered `Notify` every 20 s
/// (`NOTIFY_RESEND_MS` in typeon-server) until we fetch; a reconnect fetches
/// at once. At 30 s this poll kept the LTE radio out of idle. It must NOT be
/// raised against a server without the resend: one lost `Notify` then delays
/// all mail by this interval (device test 2026-10-08: a call invite 4 minutes
/// late).
pub(crate) const SERVER_FETCH_SWEEP_INTERVAL_MS: u64 = 5 * 60 * 1000;

/// Sunucu bağlantısı/kayıt durumu tarama aralığı.
pub(crate) const SERVER_SWEEP_INTERVAL_MS: u64 = 15_000;

/// Bir mesajın "bu sunucuya zaten yatırıldı" bilgisinin hatırlanma süresi —
/// bkz. `P2PCore.server_deposited`. As long as a message is retried (7 days),
/// under the server's mailbox TTL: at 12 h each still-unacked message was
/// deposited again twice a day. The map stays bounded by
/// `MAX_SERVER_DEPOSIT_MEMORY`; a new enrollment forgets its marks
/// (`forget_server_cursors`), a regenerated message its own.
pub(crate) const SERVER_DEPOSIT_MEMORY_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// `server_deposited` üst sınırı — dolduğunda en eski girdiler atılır.
pub(crate) const MAX_SERVER_DEPOSIT_MEMORY: usize = 4096;

/// Sıradan bir `Message`'ın SADECE sunucu üzerinden gitmeye devam edeceği
/// süre. Bundan sonrası her yeniden denemede gossipsub'a da kopyalanır —
/// bkz. `should_shadow_on_gossipsub`.
pub(crate) const SERVER_ONLY_GRACE_MS: u64 = 30_000;

/// `UnknownMailbox` alan bir kutuyu bu süre boyunca sunucuya hiç sormayız.
///
/// "Bu alıcı benim sunucumda değil" bilgisi mesaj başına bir gidiş-dönüşe
/// mal olmamalı; ama kalıcı da olmamalı, karşı taraf yarın kaydolabilir.
// 10 dk idi: rotasyondan hemen sonra alıcı yeni kutusunu henüz kaydetmemişken
// (ör. ağ değişiminde sunucudan kopuk) gelen tek bir `UnknownMailbox`, o eşe
// sunucu yolunu 10 dk kapatıyordu — cihazda tam da gerektiği anda görüldü.
pub(crate) const SERVER_UNKNOWN_MAILBOX_TTL_MS: u64 = 60 * 1000;

/// Kota/hız sınırı hatası veren bir sunucuya ne kadar süre YENİ yatırma
/// denenmez.
///
/// Gerçek cihazda ölçülen çöküş (2026-08-29 logcat): sunucu her `Deposit`e
/// `QuotaExceeded` dönüyordu ve istemci, her poll turunda (~1 sn) AYNI 15
/// KB'lık el sıkışmayı yeniden yatırmaya çalışıyordu — saniyede bir, sonsuza
/// dek, üç ayrı kutuya. Geri çekilme olmadan tek bir kota hatası, o cihazın
/// TÜM store-and-forward trafiğini kalıcı bir meşgul döngüsüne çeviriyor.
pub(crate) const SERVER_DEPOSIT_BACKOFF_MS: u64 = 5 * 60 * 1000;
/// Each further refused or unanswered deposit doubles the backoff up to this.
pub(crate) const SERVER_DEPOSIT_BACKOFF_MAX_MS: u64 = 30 * 60 * 1000;

/// Ids the server refused (`Registered.refused`) are offered again after this:
/// a reader cap or a full mailbox can clear.
pub(crate) const SERVER_REFUSED_RETRY_MS: u64 = 6 * 60 * 60 * 1000;

/// A fetched item that did not open, or whose processing failed, holds its
/// mailbox's cursor (no Ack, the server keeps it) for this long; after that it
/// is passed over. It may open once an earlier item was processed (the
/// rotation that brings its key comes in the same batch); one that still
/// fails after this never will. Under `INBOUND_DEDUP_WINDOW_MS` (10 min): the
/// items after a held one are fetched again and must still be deduplicated.
pub(crate) const SERVER_HOLD_GRACE_MS: u64 = 5 * 60 * 1000;
/// The fetch that retries a held item. Over the 30 s a failed packet is
/// remembered by `process_incoming_envelope`: inside it the retry would be
/// taken as done.
pub(crate) const SERVER_HOLD_REFETCH_MS: u64 = 45_000;

/// Bir arşiv yükleme partisinin azami kayıt sayısı.
pub(crate) const SERVER_ARCHIVE_BATCH: usize = 50;
/// Upload queue cap (RAM and table): over it the oldest entries go. The local
/// archive still holds them; only their server copy is lost.
pub(crate) const MAX_SERVER_ARCHIVE_QUEUE: usize = 10_000;

/// Start of the `last_error` shown when the server's mailbox cap is hit.
const TOO_MANY_MAILBOXES: &str = "Too many mailboxes for this server";

/// Aynı anda havada olabilecek dosya parçası sayısı (boru hattı derinliği).
///
/// Neden gerekli: tek parça havadayken aktarım hızı `parça_boyutu /
/// gidiş-dönüş süresi` ile sınırlıdır — bant genişliğinden BAĞIMSIZ olarak.
/// Tor üzerinde ölçüldü: 10 MB'lık bir yükleme ~12 KB/s. 256 KiB'lık parçalar
/// ve ~1 sn'lik bir gidiş-dönüşle 6 paralel istek, tavanı ~1.5 MB/s'ye
/// çıkarır.
///
/// Aynı anda havada olabilecek dosya parçası — SABİT DEĞİL, yola göre
/// kendini ayarlar (bkz. `BLOB_RTT_TARGET_MS`).
pub(crate) const BLOB_WINDOW_START: usize = 4;
pub(crate) const BLOB_WINDOW_MIN: usize = 2;
pub(crate) const BLOB_WINDOW_MAX: usize = 40;

/// Pencerenin BÜYÜMEYİ bırakacağı gidiş-dönüş eşiği.
///
/// Bu sayı ÖLÇÜMLE bulundu, tahminle değil. Sabit 16'lık bir pencereyle Tor
/// üzerinde: ortalama gidiş-dönüş **24 saniye**, istekler 30 sn'lik protokol
/// zaman aşımına takılıyor, yeniden denemeler bant genişliğini yiyor ve hız
/// 180 KB/s'den ~50 KB/s'ye ÇÖKÜYOR. Sebep klasik bufferbloat: 16 × 256 KiB
/// = 4 MB, ~200 KB/s'lik TEK bir Tor devresine tıkılınca kuyruğun sonundaki
/// parça 20+ saniye bekliyor.
///
/// Yani sorun gecikme değil bant genişliğiydi ve paralelliği artırmak
/// ZARARLI. Doğru davranış, havadaki bayt miktarını kuyruk gecikmesi zaman
/// aşımına yaklaşmayacak kadar tutmak — ve bunu yol başına ÖLÇEREK yapmak,
/// çünkü doğru derinlik LAN'da, Tor'da ve röle üzerinde farklı.
///
/// Eşik MUTLAK değil, ölçülen EN KÜÇÜK gidiş-dönüşe göredir (bkz.
/// `PendingBlobUpload.rtt_min`): mutlak bir eşik (ilk sürümde 6 sn) yavaş
/// bir Tor devresinde pencereyi KALICI olarak tabana çiviliyordu — gerçek
/// cihazda ölçüldü: gidiş-dönüş 15.6 sn, pencere 2'de takılı, 33 KB/s. Oysa
/// yüksek gecikmeli bir yol tam da BÜYÜK pencere ister. Kuyruk gecikmesi
/// ölçütü "gidiş-dönüş, o yolda görülen en iyisinin iki katını aştı mı"dır
/// (Vegas benzeri); yol ne kadar yavaş olursa olsun anlamını korur.
pub(crate) const BLOB_RTT_GROW_FACTOR: u64 = 2;
/// Gidiş-dönüş bunu aşarsa, kuyruk gecikmesi ölçütü ne derse desin pencere
/// büyütülmez — `BLOB_REQUEST_TIMEOUT_MS` (90 sn) zaman aşımına yaklaşıyoruz demektir ve
/// zaman aşımına giren bir parça penceremizi yarıya indirir.
///
/// Bu tavan SADECE zaman aşımına yaklaşmayı engellemek içindir; hızı
/// yönetmek kuyruk gecikmesi ölçütünün işi (bkz. `BLOB_RTT_GROW_FACTOR`).
///
/// Tavanın MUTLAK olması bu dosyada üç kez hataya yol açtı:
///   1. 6 sn'lik ilk sürüm, gidiş-dönüşü 12-15 sn olan bir Tor devresinde
///      pencereyi tabana çiviledi (33 KB/s).
///   2. 20 → 12 sn'ye çekmek aynı hatayı tekrarladı (270 → 95 KB/s).
///   3. Parça 256 → 512 KiB'a çıkınca gidiş-dönüş de iki katına çıktı ve
///      20 sn'lik tavan yine anında bağladı (pencere 2'de kaldı).
/// Üçünün ortak sebebi aynı: gidiş-dönüş hem yola hem PARÇA BOYUTUNA bağlı,
/// dolayısıyla sabit bir milisaniye eşiği ikisinden birinde hep yanlış.
///
/// Bu yüzden tavan artık `BLOB_REQUEST_TIMEOUT_MS`un (90 sn) bir ORANI:
/// zaman aşımına gerçekten yaklaşmadıkça büyümeye karışmıyor, parça boyutu
/// ne olursa olsun. Kuyruk gecikmesini yönetmek zaten Vegas ölçütünün işi.
/// Toplu aktarım isteklerinin (blob parçası, dosya parçası) zaman aşımı.
///
/// 30 sn, 256 KiB'lık parçalar için yazılmıştı ve parça 512 KiB'a çıkınca
/// YETMEDİ: yavaş bir Tor devresinde tek bir parça 30 saniyeyi aşıyor, her
/// aşımda pencere yarılanıp KOCA parça baştan gidiyor ve aktarım hiç
/// bitmiyordu (üst üste üç ölçüm TIMEOUT). Zaman aşımı parça boyutuyla
/// birlikte ölçeklenmek zorunda — aksi halde parçayı büyütmek, tam da
/// büyütmenin işe yarayacağı yavaş yollarda aktarımı öldürüyor.
pub(crate) const BLOB_REQUEST_TIMEOUT_MS: u64 = 90_000;
pub(crate) const BLOB_RTT_CEILING_MS: u64 = BLOB_REQUEST_TIMEOUT_MS * 4 / 5;
/// Bunun altındaki gidiş-dönüşler ölçüm gürültüsü sayılır (yerel/LAN) —
/// `rtt_min` çok küçük çıkıp büyümeyi gereksiz yere durdurmasın.
pub(crate) const BLOB_RTT_FLOOR_MS: u64 = 750;

// ---------------------------------------------------------------------------
// Durum tipleri
// ---------------------------------------------------------------------------

/// Kalıcı sunucu kaydı (`servers` tablosu).
#[derive(Debug, Clone)]
pub(crate) struct ServerRecord {
    /// Sunucunun `PeerId`'si — birincil anahtar.
    pub server_id: String,
    /// Sunucunun BÜTÜN bilinen adresleri, virgülle ayrılmış (onion + varsa
    /// LAN/genel IP). Hepsi aynı anda dial edilir — libp2p ilk kuranı
    /// kullanır. Tek adres saklandığında ve o onion olduğunda, aynı yerel
    /// ağdaki iki cihaz bile bütün trafiği Tor'dan geçiriyordu (ölçüldü:
    /// 10 MB yükleme ~12 KB/s).
    pub address: String,
    pub name: String,
    /// SADECE BU SUNUCUYA ÖZEL taze Ed25519 secret key (32 bayt).
    ///
    /// Cihazın kimlik anahtarı KASITLI olarak kullanılmıyor: sunucunun
    /// ihtiyacı olan tek şey Sybil'e karşı bir kapı (davet jetonu) ve iptal
    /// edilebilir bir tutamak. Kimlik anahtarını vermek, operatöre "bu
    /// sunucuyu tam olarak kimler kullanıyor" listesini kriptografik olarak
    /// kanıtlanabilir biçimde hediye ederdi.
    pub enroll_sk: Vec<u8>,
    /// Aynı amaçla üretilmiş ML-DSA-87 secret key TOHUMU (32 bayt) —
    /// `DeviceKeys.sign_sk_mldsa` ile aynı saklama biçimi. Kayıt imzası,
    /// uygulamanın geri kalanıyla aynı şekilde hibrit.
    pub enroll_sk_pq: Vec<u8>,
    pub enrollment_id: Option<Vec<u8>>,
    /// Kayıt tamamlanınca boşaltılır — tek kullanımlık.
    pub token: String,
    pub route_messages: bool,
    /// Geçmişi sunucuda saklama. VARSAYILAN KAPALI ve yönlendirmeden AYRI:
    /// arşiv gerçek bir yedek ve ileri-gizli DEĞİL (bkz.
    /// `server_seal::seal_archive_record`).
    pub store_history: bool,
    pub added_at: u64,
}

/// Bir sunucunun çalışma-zamanı (kalıcı olmayan) durumu.
#[derive(Debug, Clone, Default)]
pub(crate) struct ServerRuntime {
    pub peer_id: Option<PeerId>,
    pub connected: bool,
    pub enrolled: bool,
    pub limits: Option<ServerLimits>,
    /// Highest seq per mailbox taken from a batch and processed, not yet
    /// acked: see `commit_server_fetches`.
    pub unacked: HashMap<String, u64>,
    /// A failed `Ack` is not sent again before this (ms).
    pub ack_retry_at: u64,
    /// Sunucuya bildirilmiş kutu kimlikleri — `Register` farkını hesaplamak
    /// için.
    pub registered: HashSet<String>,
    /// Ids the server refused (`Registered.refused`): not sent again before
    /// `refused_retry_at` (M29).
    pub refused: HashSet<String>,
    pub refused_retry_at: u64,
    /// Mailbox -> (seq, first failure ms) of the item holding its cursor, see
    /// `SERVER_HOLD_GRACE_MS`.
    pub held: HashMap<String, (u64, u64)>,
    /// Held items passed over after the grace: skipped, and the cursor never
    /// goes to their (server-chosen) seq, only to that of an item that opened.
    pub passed: HashSet<(String, u64)>,
    /// SHA-256 of each item handed to `incoming` this turn -> (mailbox, seq),
    /// for `server_item_failed`.
    pub taken: HashMap<[u8; 32], (String, u64)>,
    pub fetch_due_at: u64,
    pub hello_sent_at: u64,
    pub last_error: Option<String>,
    /// Havada bekleyen bir `Fetch` var mı?
    ///
    /// Yoksa aynı imleçlerle İKİNCİ bir `Fetch` gidebiliyordu ve sunucu aynı
    /// zarfları bir kez daha yolluyordu — gerçek cihazda ölçüldü: 6 zarf
    /// (~90 KB) 1.1 saniye arayla iki kez, Tor üzerinden, tamamen boşuna.
    /// Yanıt/hata gelince temizlenir.
    pub fetch_inflight: bool,
    /// bkz. `SERVER_DEPOSIT_BACKOFF_MS` — bu ana kadar bu sunucuya yeni
    /// `Deposit` denenmez (kota/hız hatası sonrası). `Fetch`/`Ack` bundan
    /// ETKİLENMEZ: gelen postayı almaya devam etmek her zaman doğru.
    pub deposit_backoff_until: u64,
    /// Deposits refused or unanswered in a row (exponential backoff).
    pub deposit_failures: u32,
    /// Unreachable server: no new dial before this (ms), see `server_sweep`.
    pub dial_backoff_until: u64,
    /// Dials since the last successful connection.
    pub dial_attempts: u32,
    /// `Hello`s sent since we were last enrolled: backs off an enrollment the
    /// server keeps refusing, see `server_sweep`.
    pub hello_attempts: u32,
    /// A refused `Register`: not sent again before this (ms).
    pub register_backoff_until: u64,
    /// The purge of a replaced archive key is not sent again before this (ms).
    pub purge_retry_at: u64,
    /// Last `Notify` taken from this server (ms), see `handle_server_push`.
    pub notified_at: u64,
    /// Start of the current `Push` window (ms) and the pushes in it.
    pub push_window_at: u64,
    pub push_count: u32,
}

/// What opens the envelopes of one of this device's mailboxes.
#[derive(Clone)]
enum MailboxKey {
    /// The pairing or link secret the mailbox id is made from
    /// (`server_seal::open_first_contact`).
    FirstContact(Vec<u8>),
    /// A session's current and previous root keys and the device at its
    /// other end (`server_seal::open_envelope`).
    Session(Vec<Vec<u8>>, String),
}

/// Havada bekleyen bir sunucu RPC'si.
#[derive(Debug, Clone)]
pub(crate) enum ServerInflight {
    Hello { server_id: String },
    Enroll { server_id: String },
    Rebind { server_id: String },
    Register { server_id: String, ids: Vec<String>, dropped: Vec<String> },
    /// `message_id` varsa, teslim başarısız olursa gossipsub'a düşürmek için.
    ///
    /// `first_attempt_at`: zarfın İLK yayın denemesinin zamanı — sunucu
    /// hatası sonrası kuyruğa geri konurken KORUNUR. Önceden bu yol
    /// `publish_envelope`'u çağırıyor ve o da girdiyi `current_time_ms()`
    /// ile ekliyordu; yani her sunucu gidiş-dönüşü `PENDING_ENVELOPE_TIMEOUT_MS`/
    /// `PENDING_HANDSHAKE_TIMEOUT_MS` sayacını SIFIRLIYOR, zarf hiç
    /// eskimiyor ve kuyruk sonsuza dek dönüyordu.
    ///
    /// `dedup_key`: bkz. `deposit_dedup_key` — başarısızlıkta "zaten
    /// yatırıldı" işaretini geri almak için.
    Deposit {
        server_id: String,
        mailbox: String,
        envelope: NetworkEnvelope,
        target_fp: String,
        first_attempt_at: u64,
        dedup_key: String,
        /// The user cancelled the message while this was in flight: withdraw
        /// the server copy as soon as its `seq` is known.
        cancelled: bool,
    },
    Fetch { server_id: String },
    /// `acks`: staged again in `unacked` when the request fails.
    Ack { server_id: String, acks: Vec<(String, u64)> },
    /// bkz. `ServerRequest::Cancel` — gönderenin kendi paketini geri
    /// çekmesi. Yanıtta yapılacak bir şey yok, sadece "beklenmeyen yanıt"
    /// uyarısı basmasın diye izleniyor.
    Cancel { server_id: String },
    /// `records`: `(record_id, rev)` of what this batch carries. The queue can
    /// change while the request is in flight, so `Ok` removes these and
    /// nothing else.
    ArchivePut { server_id: String, records: Vec<(String, u64)> },
    /// `bucket_more`: bu sayfa `more = true` ile dönerse aynı kovadan
    /// daha eskisini istemek için kovanın kimliği.
    ///
    /// `rest`: buckets of the same conversation still to fetch, one at a time.
    /// `window`: a "Fetch older history" press `(before, after)` by send
    /// time: pages run until they pass `after`. `next`: conversations of a
    /// full restore still to probe, one after the other.
    ArchiveFetch {
        server_id: String,
        conv_key: String,
        group: bool,
        bucket_more: Option<String>,
        rest: Vec<String>,
        window: Option<(u64, u64)>,
        next: Vec<(String, bool)>,
    },
    /// `window`: a "Fetch older history" press `(before, after)`, the
    /// present buckets that reach it, newest first; `None`: full restore,
    /// every present bucket.
    ArchiveProbe { server_id: String, conv_key: String, group: bool, window: Option<(u64, u64)>, next: Vec<(String, bool)> },
    /// The buckets of replaced archive keys, bkz. `purge_retired_archive`.
    /// `keys`: the `ark_purge` value this run covers; `rest`: buckets not sent yet.
    ArchivePurge { server_id: String, keys: String, rest: Vec<String> },
    BlobPut { server_id: String, blob_id: String, chunk_index: u32, total_chunks: u32, sent_at: u64 },
    BlobFinish { server_id: String, blob_id: String },
}

impl ServerInflight {
    fn server_id(&self) -> &str {
        match self {
            ServerInflight::Hello { server_id }
            | ServerInflight::Enroll { server_id }
            | ServerInflight::Rebind { server_id }
            | ServerInflight::Register { server_id, .. }
            | ServerInflight::Deposit { server_id, .. }
            | ServerInflight::Fetch { server_id }
            | ServerInflight::Ack { server_id, .. }
            | ServerInflight::Cancel { server_id }
            | ServerInflight::ArchivePut { server_id, .. }
            | ServerInflight::ArchiveFetch { server_id, .. }
            | ServerInflight::ArchiveProbe { server_id, .. }
            | ServerInflight::ArchivePurge { server_id, .. }
            | ServerInflight::BlobPut { server_id, .. }
            | ServerInflight::BlobFinish { server_id, .. } => server_id,
        }
    }
}

/// `poll_events`'in swarm borrow'u altında toplanıp, borrow bittikten sonra
/// işlenen sunucu olayları — `FileChunkEventLocal` deseninin aynısı.
pub(crate) enum ServerEventLocal {
    /// Sunucu bize istek gönderdi (tek meşru tür: `Notify`).
    Request { peer: PeerId, request: ServerRequest, channel: request_response::ResponseChannel<ServerResponse> },
    Response { request_id: request_response::OutboundRequestId, response: ServerResponse },
    OutboundFailure { request_id: request_response::OutboundRequestId },
}

/// Sunucuya yüklenmeyi bekleyen bir arşiv kaydı.
#[derive(Debug, Clone)]
pub(crate) struct PendingArchive {
    pub conv_key: String,
    pub record_id: String,
    pub rev: u64,
    pub sent_at_ms: u64,
    /// CBOR'lanmış `ArchivedMessage` — mühürleme yükleme anında yapılır
    /// (arşiv anahtarı o an yüklü olmayabilir).
    pub plaintext: Vec<u8>,
}

/// Sunucuya yüklenmeyi bekleyen bir dosya.
#[derive(Debug, Clone)]
pub(crate) struct PendingBlobUpload {
    pub file_id: String,
    /// Proves on the server that this device uploads `file_id`
    /// (`server_proto::blob_id_for_upload_secret`).
    pub upload_secret: Vec<u8>,
    pub next_chunk: u32,
    pub total_chunks: u32,
    /// Şifreli dosyanın tamamının SHA-256'sı — `BlobFinish` ile gönderilir,
    /// sunucu kırpılmış bir yüklemeyi asla servis etmesin diye. Kuyruğa
    /// girerken BOŞ; son parça yüklendikten sonra `.enc` dosyası
    /// akıtılarak hesaplanır (dosyayı erkenden bir kez daha baştan sona
    /// okumamak için — ekler 4 GiB'a kadar olabiliyor).
    /// Şu an havada olan parça indeksleri (boru hattı — bkz.
    /// `BLOB_PIPELINE_DEPTH`). Önceden tek bir `bool`du, yani aynı anda tek
    /// parça gidebiliyordu.
    pub inflight: HashSet<u32>,
    /// Sunucunun onayladığı parçalar.
    pub done: HashSet<u32>,
    /// Uyarlanır pencere: kuyruk gecikmesi düşükken birer birer büyür,
    /// zaman aşımı/hata görülünce YARIYA iner. Sabit bir derinlik yanlış:
    /// LAN'da çok küçük, Tor'da çok büyük kalıyor (bkz. `BLOB_RTT_GROW_FACTOR`).
    pub window: usize,
    /// Bu aktarımda görülen EN KÜÇÜK gidiş-dönüş — yolun kuyruksuz taban
    /// gecikmesi. Büyüme ölçütü buna GÖRE (bkz. `BLOB_RTT_GROW_FACTOR`).
    pub rtt_min: u64,
    /// The one server this upload goes to. Progress restarts when it changes:
    /// chunks spread over two servers complete on neither.
    pub server_id: Option<String>,
    /// SHA-256 of the `.enc` file, hashed once for `BlobFinish` (stored in
    /// `server_blob_uploads.enc_sha256`, so a restart does not hash again).
    pub enc_sha256: Option<Vec<u8>>,
    /// The hash running on its own thread (up to 4 GiB, not on the poll
    /// thread); `None` inside = the file could not be read.
    pub hashing: Option<std::sync::Arc<std::sync::OnceLock<Option<Vec<u8>>>>>,
    /// Times a `BlobIncomplete` finish sent this upload back to chunk 0.
    /// ponytail: in memory only, a process restart resets it.
    pub restarts: u8,
}

// ---------------------------------------------------------------------------

impl P2PCore {
    // -----------------------------------------------------------------
    // Kalıcılık
    // -----------------------------------------------------------------

    pub(crate) fn init_server_tables(conn: &rusqlite::Connection) {
        // Çekirdeğin `init_db` sözleşmesiyle aynı: IF NOT EXISTS + hatası
        // yutulan ALTER TABLE.
        let _ = conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS servers (
                server_id      TEXT PRIMARY KEY,
                address        TEXT NOT NULL,
                name           TEXT NOT NULL DEFAULT '',
                enroll_sk      BLOB NOT NULL,
                enrollment_id  BLOB,
                token          TEXT NOT NULL DEFAULT '',
                route_messages INTEGER NOT NULL DEFAULT 1,
                store_history  INTEGER NOT NULL DEFAULT 0,
                added_at       INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS server_cursors (
                server_id  TEXT NOT NULL,
                mailbox_id TEXT NOT NULL,
                last_seq   INTEGER NOT NULL,
                PRIMARY KEY (server_id, mailbox_id)
            );
            CREATE TABLE IF NOT EXISTS server_archived_convs (
                conv_key TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS server_archive_revs (
                conv_key  TEXT NOT NULL,
                record_id TEXT NOT NULL,
                rev       INTEGER NOT NULL,
                PRIMARY KEY (conv_key, record_id)
            );
            CREATE TABLE IF NOT EXISTS server_archive_queue (
                record_id  TEXT PRIMARY KEY,
                conv_key   TEXT NOT NULL,
                rev        INTEGER NOT NULL,
                sent_at_ms INTEGER NOT NULL,
                plaintext  BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS server_blob_uploads (
                file_id      TEXT PRIMARY KEY,
                next_chunk   INTEGER NOT NULL,
                total_chunks INTEGER NOT NULL,
                enc_sha256   BLOB NOT NULL,
                created_at   INTEGER NOT NULL
            );
            "#,
        );
        // Çekirdeğin geçiş (migration) deseni: SQLite `ADD COLUMN IF NOT
        // EXISTS` desteklemediğinden, kolon zaten varsa oluşacak hatayı
        // sessizce yok sayıyoruz.
        let _ = conn.execute("ALTER TABLE servers ADD COLUMN enroll_sk_pq BLOB", []);
        // The server an upload goes to: without it a restart started every
        // upload over from chunk 0 (see `server_flush_blobs`).
        let _ = conn.execute("ALTER TABLE server_blob_uploads ADD COLUMN server_id TEXT", []);
        // Rows from before upload secrets cannot prove their blob any more.
        if conn.execute("ALTER TABLE server_blob_uploads ADD COLUMN upload_secret BLOB", []).is_ok() {
            let _ = conn.execute("DELETE FROM server_blob_uploads", []);
        }
    }

    pub(crate) fn load_servers_from_db(&mut self) {
        self.reconcile_archive_key(false);
        let Some(conn) = &self.db else { return };
        let mut stmt = match conn.prepare(
            "SELECT server_id, address, name, enroll_sk, enrollment_id, CAST(token AS BLOB), route_messages, store_history, added_at, enroll_sk_pq FROM servers",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        // The enrollment secrets and the token are sealed (see
        // `persist_server`). L-82: a field that does not open is never taken
        // as raw bytes; a row whose enrollment key does not open is skipped
        // (left on disk untouched).
        let open = |raw: Vec<u8>| self.open_local_blob(&raw);
        let loaded: Vec<ServerRecord> = stmt
            .query_map([], |r| {
            let server_id: String = r.get(0)?;
            let Some(enroll_sk) = open(r.get(3)?) else {
                warn!("Sunucu kaydı açılamadı, atlandı: {}", crate::log_id(&server_id));
                return Ok(None);
            };
            Ok(Some(ServerRecord {
                server_id,
                address: r.get(1)?,
                name: r.get(2)?,
                enroll_sk,
                enrollment_id: r.get(4)?,
                token: open(r.get(5)?).and_then(|t| String::from_utf8(t).ok()).unwrap_or_default(),
                route_messages: r.get::<_, i64>(6)? != 0,
                store_history: r.get::<_, i64>(7)? != 0,
                added_at: r.get::<_, i64>(8)? as u64,
                // Boşsa kayıt yenilenir.
                enroll_sk_pq: open(r.get::<_, Option<Vec<u8>>>(9)?.unwrap_or_default()).unwrap_or_default(),
            }))
            })
            .map(|it| it.filter_map(|r| r.ok().flatten()).collect())
            .unwrap_or_default();
        drop(stmt);
        self.servers = loaded;

        // ESKİ satırlarda (sunucu tarafı elemeye başlamadan önce üretilmiş
        // davetlerden) yerel ağ adresleri kalmış olabilir — bkz. `add_server`.
        // Yüklerken temizle ve temiz hâlini diske geri yaz, yoksa her açılışta
        // yeniden LAN'a düşülür.
        let mut cleaned: Vec<ServerRecord> = Vec::new();
        for rec in &self.servers {
            let kept = server_proto::public_server_addrs(rec.address.split(','));
            let joined = kept.join(",");
            if !joined.is_empty() && joined != rec.address {
                let mut r = rec.clone();
                r.address = joined;
                cleaned.push(r);
            }
        }
        for r in cleaned {
            warn!("Sunucu adresinden yerel ağ adresi çıkarıldı: {}", crate::log_id(&r.server_id));
            self.persist_server(&r);
            if let Some(slot) = self.servers.iter_mut().find(|s| s.server_id == r.server_id) {
                *slot = r;
            }
        }

        // `server_rt`i BURADA hazırla — `peer_id` olmadan
        // `note_server_connection` gelen bağlantıyı hiçbir sunucuyla
        // eşleştiremez ve `rt.connected` sonsuza dek false kalır. O hâlde
        // sunucuya BAĞLANMIŞ olmamıza rağmen `server_sweep` hep "bağlı değil"
        // dalına girip yeniden dial eder; libp2p zaten bağlı olduğu için
        // YENİ bir `ConnectionEstablished` doğmaz ve istemci hiç kaydolamaz.
        // Gerçek cihazda görülen tam olarak buydu: Linux istemcisi sunucuya
        // bağlandı ama saatlerce "bağlı+kayıtlı sunucu yok" dedi.
        for rec in &self.servers {
            let peer_id = rec
                .address
                .split(',')
                .filter_map(|a| a.trim().parse::<Multiaddr>().ok())
                .find_map(|a| extract_peer_id(&a));
            self.server_rt.entry(rec.server_id.clone()).or_default().peer_id = peer_id;
        }

        // İmleçler — bunlar OLMADAN her yeniden başlatma tüm kutuyu baştan
        // işlerdi (dedup yutardı ama boşuna CPU/pil).
        if let Ok(mut stmt) = conn.prepare("SELECT server_id, mailbox_id, last_seq FROM server_cursors") {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?.max(0) as u64))
            }) {
                for (sid, mid, seq) in rows.flatten() {
                    self.server_cursors.insert((sid, mid), seq);
                }
            }
        }
        // Süreç ölümünde kaybolmasın diye kalıcı arşiv kuyruğu.
        if let Ok(mut stmt) = conn.prepare(
            "SELECT record_id, conv_key, rev, sent_at_ms, plaintext FROM server_archive_queue ORDER BY created_at",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(PendingArchive {
                    record_id: r.get(0)?,
                    conv_key: r.get(1)?,
                    rev: r.get::<_, i64>(2)? as u64,
                    sent_at_ms: r.get::<_, i64>(3)? as u64,
                    plaintext: r.get(4)?,
                })
            }) {
                // bkz. `queue_archive_record` (#10): satırlar artık
                // `seal_local_blob` ile şifreli. A row that does not open is
                // dropped (L-82: never sent on as raw bytes).
                let raw: Vec<PendingArchive> = rows.flatten().collect();
                let mut opened: Vec<PendingArchive> = raw
                    .into_iter()
                    .filter_map(|mut e| {
                        if let Some(plain) = self.open_local_blob(&e.plaintext) {
                            e.plaintext = plain;
                            return Some(e);
                        }
                        warn!("Arşiv kuyruğu satırı açılamadı, atlandı: {}", crate::log_id(&e.record_id));
                        let _ = conn.execute("DELETE FROM server_archive_queue WHERE record_id = ?1", params![e.record_id]);
                        None
                    })
                    .collect();
                // Oldest first (`ORDER BY created_at`): over the cap the head goes.
                let over = opened.len().saturating_sub(MAX_SERVER_ARCHIVE_QUEUE);
                for e in opened.drain(..over) {
                    let _ = conn.execute("DELETE FROM server_archive_queue WHERE record_id = ?1", params![e.record_id]);
                }
                self.server_archive_queue = opened;
            }
        }
        if let Ok(mut stmt) =
            conn.prepare("SELECT file_id, next_chunk, total_chunks, server_id, enc_sha256, upload_secret FROM server_blob_uploads")
        {
            if let Ok(rows) = stmt.query_map([], |r| {
                let next_chunk = r.get::<_, i64>(1)? as u32;
                let enc_sha256: Vec<u8> = r.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default();
                Ok(PendingBlobUpload {
                    file_id: r.get(0)?,
                    upload_secret: r.get::<_, Option<Vec<u8>>>(5)?.unwrap_or_default(),
                    next_chunk,
                    total_chunks: r.get::<_, i64>(2)? as u32,
                    inflight: HashSet::new(),
                    // Defter #09: `done` eskiden BOŞ kuruluyordu, oysa
                    // `server_flush_blobs` gönderilecek parçayı SADECE
                    // `done`/`inflight`'a bakarak seçiyor — yani diskten
                    // okunan `next_chunk` filigranı hiçbir şeye etki etmiyor
                    // ve dosyanın TAMAMI her açılışta baştan yükleniyordu.
                    // (Sunucu tekrarları idempotent kabul ettiği için sonunda
                    // tamamlanıyordu, ama Tor üzerinden GB'larca gereksiz
                    // trafikle — ve uygulama düzenli öldürülüyorsa büyük bir
                    // dosya hiç bitmeyebilirdi.) Filigrana kadar olan
                    // parçalar KESİN olarak sunucuda: `advance_blob_upload`
                    // `next_chunk`'ı ancak 0..n aralığının tamamı
                    // onaylandığında ilerletiyor.
                    done: (0..next_chunk).collect(),
                    window: BLOB_WINDOW_START,
                    rtt_min: u64::MAX,
                    server_id: r.get(3)?,
                    enc_sha256: (enc_sha256.len() == 32).then_some(enc_sha256),
                    hashing: None,
                    restarts: 0,
                })
            }) {
                self.server_blob_uploads = rows.flatten().collect();
            }
        }
        if !self.servers.is_empty() {
            info!("{} sunucu yüklendi", self.servers.len());
        }
    }

    /// Sunucu kaydını diske yazar.
    ///
    /// Hata YUTULMAZ. Yutulduğunda ortaya çıkan tablo şuydu: sunucu bellekte
    /// yaşıyor, kaydolmuş görünüyor, arayüz "Connected" diyor — ama satır
    /// diskte yok, yani uygulama bir sonraki açılışta sunucuyu HİÇ
    /// tanımıyor ve zarflar sessizce doğrudan-eş yoluna düşüyor. Sessiz
    /// başarısızlık, teşhis edilmesi en pahalı hata türü.
    fn persist_server(&self, rec: &ServerRecord) {
        let Some(conn) = &self.db else {
            error!("Sunucu kaydı diske yazılamadı: veritabanı yok ({})", crate::log_id(&rec.server_id));
            return;
        };
        // A copy of the database must not be enough to `Rebind` the
        // enrollment or to spend the token: sealed like the archive queue.
        let (Some(enroll_sk), Some(enroll_sk_pq), Some(token)) = (
            self.seal_local_blob(&rec.enroll_sk),
            self.seal_local_blob(&rec.enroll_sk_pq),
            self.seal_local_blob(rec.token.as_bytes()),
        ) else {
            error!("Sunucu kaydı diske yazılamadı: yerel anahtar yok ({})", crate::log_id(&rec.server_id));
            return;
        };
        let written = conn.execute(
            "INSERT OR REPLACE INTO servers
             (server_id, address, name, enroll_sk, enrollment_id, token, route_messages, store_history, added_at, enroll_sk_pq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                rec.server_id, rec.address, rec.name, enroll_sk, rec.enrollment_id, token,
                rec.route_messages as i64, rec.store_history as i64, rec.added_at as i64, enroll_sk_pq
            ],
        );
        match written {
            Ok(_) => info!("Sunucu kaydı diske yazıldı: {}", crate::log_id(&rec.server_id)),
            Err(e) => error!("Sunucu kaydı diske YAZILAMADI ({}): {}", crate::log_id(&rec.server_id), e),
        }
    }

    fn persist_cursor(&self, server_id: &str, mailbox_id: &str, seq: u64) {
        let Some(conn) = &self.db else { return };
        // Bunun sessizce başarısız olması, her yeniden başlatmada bütün
        // kutunun baştan işlenmesi demek (dedup yutar ama boşuna CPU/pil).
        // Forward only: an older Ack confirmed late must not move it back.
        let r = conn.execute(
            "INSERT INTO server_cursors (server_id, mailbox_id, last_seq) VALUES (?1, ?2, ?3)
             ON CONFLICT(server_id, mailbox_id) DO UPDATE SET last_seq = MAX(last_seq, excluded.last_seq)",
            params![server_id, mailbox_id, seq.min(i64::MAX as u64) as i64],
        );
        if let Err(e) = r {
            warn!("Sunucu imleci yazılamadı ({}/{}): {}", crate::log_id(&server_id), mailbox_log_id(mailbox_id), e);
        }
    }

    // -----------------------------------------------------------------
    // Kullanıcıya açık API
    // -----------------------------------------------------------------

    /// Davet kodundan bir sunucu ekler.
    pub(crate) fn add_server(&mut self, invite_code: &str) -> Result<String, String> {
        let invite = server_proto::parse_server_invite(invite_code)?;
        // ÖZEL ağ adresleri koda hiç girmemeli (sunucu tarafı eliyor), ama
        // ESKİ davetlerde duruyorlar ve libp2p bütün adresleri aynı anda
        // deneyip LAN'ı kazandırıyor — "sunucu üzerinden" sandığımız trafik
        // sessizce yerel ağdan akıyordu. Burada da eliyoruz ki eski bir kod
        // yapıştırıldığında bile bu olmasın (bkz.
        // `server_proto::public_server_addrs`).
        let addrs = server_proto::public_server_addrs(&invite.addrs);
        if addrs.is_empty() {
            return Err("Davet kodunda ulaşılabilir bir adres yok (yalnızca yerel ağ adresi)".to_string());
        }
        let invite = server_proto::ServerInvite { addrs, token: invite.token };
        let parsed: Vec<Multiaddr> = invite
            .addrs
            .iter()
            .filter_map(|a| a.parse::<Multiaddr>().ok())
            .collect();
        if parsed.is_empty() {
            return Err("Geçersiz sunucu adresi".to_string());
        }
        // Bütün adresler AYNI sunucuya ait olmalı — `/p2p/<peer_id>` son eki
        // bunu kanıtlıyor. Farklı PeerId taşıyan bir adres, ya bozuk bir kod
        // ya da birleştirme denemesidir; sessizce eklemek yanlış sunucuya
        // bağlanmak demek olurdu.
        let peer_id = extract_peer_id(&parsed[0]).ok_or("Adres bir /p2p/<peer_id> son eki içermeli")?;
        if parsed.iter().any(|a| extract_peer_id(a) != Some(peer_id)) {
            return Err("Davet kodundaki adresler farklı sunuculara işaret ediyor".to_string());
        }
        let server_id = peer_id.to_string();

        // Zaten ekli bir sunucu için TAZE bir davet kodu, "kaydımı yenile"
        // demektir. Önceden koşulsuz reddediliyordu; operatör kaydı iptal
        // ettiğinde (ya da kayıt hiç tamamlanmadığında) kullanıcının tek
        // çıkışı sunucuyu KALDIRIP yeniden eklemekti — oysa kaldırma
        // sunucudaki arşivi de siler (bkz. `remove_server`), yani yalnızca
        // yeniden kaydolmak isteyen kullanıcı geçmişini kaybediyordu.
        // Etkin bir kayıt varken ise davranış aynı: gereksiz yere yeni
        // anahtar üretip kaydı bozmayalım.
        if let Some(existing) = self.servers.iter().find(|s| s.server_id == server_id).cloned() {
            // TAZE bir jeton "yeniden kaydol" demektir ve kullanıcı bunu
            // açıkça istemiştir — kaydın şu an çalışıp çalışmadığına BAKMAYIZ.
            // Bakmak, düzeltmek istediğimiz tuzağı geri getirirdi: kayıt
            // iptal edildiğinde istemci bunu ancak sunucuya bir istek gönderip
            // `Revoked` yiyince öğrenir; o ana kadar "zaten ekli" deyip yeni
            // kodu reddetseydik kullanıcı yine sıkışırdı.
            //
            // Yeniden kaydolmak güvenli: posta kutuları kayıt kimliğine değil
            // kutu kimliğine adreslidir, imleçler istemcide durur, arşiv
            // anahtarı da kayıttan bağımsızdır (bkz. `archive_root_key`).
            // AYNI jeton yeniden yapıştırıldıysa (çift dokunuş) bir şey yapma.
            if existing.token == invite.token && !invite.token.is_empty() {
                return Err("Bu sunucu zaten ekli".to_string());
            }
            let mut rec = existing;
            rec.address = invite.addrs.join(",");
            rec.token = invite.token;
            // `enrollment_id` stays: `begin_enrollment` tries the token first
            // and falls back to `Rebind` when the server refuses it (a spent
            // token pasted again must not cost a working enrollment).
            self.persist_server(&rec);
            if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                *r = rec;
            }
            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                rt.enrolled = false;
                rt.hello_sent_at = 0;
                rt.hello_attempts = 0;
                rt.last_error = None;
            }
            for a in parsed {
                self.dial_with_relay_fallback(peer_id, Some(a));
            }
            self.server_sweep_at = 0;
            return Ok(serde_json::json!({ "server_id": server_id }).to_string());
        }

        // Bu sunucuya ÖZEL taze anahtarlar — bkz. `ServerRecord.enroll_sk`.
        // Hibrit: uygulamanın geri kalanındaki her imza gibi.
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let signing_pq: MlDsaSigningKey<MlDsa87> = MlDsaGenerate::generate();
        let rec = ServerRecord {
            server_id: server_id.clone(),
            address: invite.addrs.join(","),
            name: String::new(),
            enroll_sk: signing.to_bytes().to_vec(),
            enroll_sk_pq: signing_pq.to_bytes().to_vec(),
            enrollment_id: None,
            token: invite.token,
            route_messages: true,
            // History on by default, on the first server only: one history
            // server (see `set_server_history`).
            store_history: !self.servers.iter().any(|s| s.store_history),
            added_at: current_time_ms(),
        };
        let history = rec.store_history;
        self.persist_server(&rec);
        self.servers.push(rec);
        if history {
            self.backfill_server_archive();
        }
        self.server_rt.insert(server_id.clone(), ServerRuntime { peer_id: Some(peer_id), ..Default::default() });

        // Hemen bağlan — kullanıcı Ayarlar ekranında sonucu görsün. HEPSİ
        // aynı anda denenir; libp2p ilk kuranı kullanır, LAN doğal olarak
        // onion'ı yener.
        for a in parsed {
            self.dial_with_relay_fallback(peer_id, Some(a));
        }
        self.server_sweep_at = 0;

        Ok(serde_json::json!({ "server_id": server_id }).to_string())
    }

    /// Sunucuyu kaldırır.
    ///
    /// Kaldırmadan ÖNCE sunucudaki arşivimizin silinmesini ister. Bunu
    /// yapmazsak geçmişimizin şifreli kopyası, artık kullanmadığımız bir
    /// sunucuda süresiz kalırdı. Silindiğini KANITLAYAMAYIZ (bkz.
    /// SECURITY.md) — ama istememek, kesinlikle kalmasını seçmek olurdu.
    pub(crate) fn remove_server(&mut self, server_id: &str) -> Result<(), String> {
        let Some(idx) = self.servers.iter().position(|s| s.server_id == server_id) else {
            return Err("Sunucu bulunamadı".to_string());
        };
        // The purge is one request with no retry: sent to an unreachable
        // server it is lost and the sealed archive stays there for good.
        // Turning history off first is the explicit "remove anyway".
        let reachable = self.server_rt.get(server_id).map_or(false, |r| r.connected && r.enrolled);
        if self.servers[idx].store_history && self.archive_root_key.is_some() && !reachable {
            return Err("Sunucuya ulaşılamıyor, arşiv silinemedi. Bağlanınca tekrar deneyin ya da önce geçmiş saklamayı kapatın".to_string());
        }
        // The row first: a failed delete left the server in memory gone and
        // brought it back at the next launch.
        let no_servers_left = self.servers.len() == 1;
        if let Some(conn) = &self.db {
            conn.execute("DELETE FROM servers WHERE server_id = ?1", params![server_id])
                .map_err(|e| format!("Sunucu silinemedi: {e}"))?;
        }
        // L-138: before `server_archived_convs` is cleared — it lists the
        // conversations deleted since they were archived.
        self.purge_server_archive(server_id);
        if let Some(conn) = &self.db {
            if let Err(e) = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1", params![server_id]) {
                warn!("Sunucu imleçleri silinemedi: {}", e);
            }
            if no_servers_left {
                // L-50: the revisions too; no archive is left they could guard.
                for t in ["server_archived_convs", "server_archive_queue", "server_blob_uploads", "server_archive_revs"] {
                    if let Err(e) = conn.execute(&format!("DELETE FROM {t}"), []) {
                        warn!("{} silinemedi: {}", t, e);
                    }
                }
            }
        }
        // Our mailboxes off the server too: they would keep taking mail
        // (and pushing it at us) until the server's sweep.
        let unregister = self
            .server_rt
            .get(server_id)
            .filter(|r| r.connected && r.enrolled)
            .and_then(|rt| Some((rt.peer_id?, Self::mailbox_cap(rt), rt.registered.iter().cloned().collect::<Vec<String>>())));
        if let Some((peer_id, cap, ids)) = unregister {
            for chunk in ids.chunks(cap) {
                let req = ServerRequest::Register { add: Vec::new(), drop: chunk.to_vec(), proofs: Vec::new() };
                let _ = self.send_server_request(peer_id, req);
            }
        }
        self.servers.remove(idx);
        self.server_rt.remove(server_id);
        self.server_cursors.retain(|(sid, _), _| sid != server_id);
        // Its requests in flight: an answer must not write cursors for a
        // server that is gone; a deposit goes over gossipsub instead.
        let stale: Vec<request_response::OutboundRequestId> = self
            .server_inflight
            .iter()
            .filter(|(_, i)| i.server_id() == server_id)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(inflight) = self.server_inflight.remove(&id) {
                self.retry_deposit_over_gossipsub(&inflight);
            }
        }
        // Defter #10: bekleyen arşiv kuyruğu ve blob yüklemeleri de
        // temizlenmeli. `server_flush_archive`/`server_flush_blobs` bağlı ve
        // (arşiv için) `store_history` açık bir sunucu ister — son sunucu
        // kaldırıldığında bu satırlar bir daha ASLA boşalmıyor, yani
        // süresiz olarak diskte kalıyorlardı.
        if no_servers_left {
            self.server_archive_queue.clear();
            self.server_blob_uploads.clear();
        }
        self.server_deposited.retain(|(sid, _), _| sid != server_id);
        Ok(())
    }


    /// Every conversation that can have buckets on the server.
    fn archive_conv_keys(&self) -> Vec<String> {
        // 1:1 sohbetlerin arşiv anahtarı karşı tarafın `identity_id`'si
        // (yerel `contact_id` DEĞİL — bkz. `server_archive_bucket` notu:
        // kimlik bazlı, ki karşı taraf cihaz değiştirdiğinde arşiv okunabilir
        // kalsın).
        let mut conv_keys: Vec<String> = self.groups.keys().cloned().collect();
        conv_keys.extend(self.contacts.values().map(|c| c.trusted_identity_id.clone()));
        // And every conversation ever archived: a contact or group deleted
        // since then left its buckets on the server.
        if let Some(conn) = &self.db {
            if let Ok(mut stmt) = conn.prepare("SELECT conv_key FROM server_archived_convs") {
                if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                    conv_keys.extend(rows.flatten());
                }
            }
        }
        conv_keys.sort();
        conv_keys.dedup();
        conv_keys
    }

    /// Sunucudaki arşivimizin tamamının silinmesini ister.
    ///
    /// Kovalar sohbet + AY bazlı olduğundan (bkz.
    /// `server_seal::server_archive_bucket`) neyi sileceğimizi hesaplamak
    /// için bildiğimiz her sohbetin son 36 ayını üretiyoruz. Var olmayan bir
    /// kovayı silmek sunucuda no-op — bu yüzden fazladan kimlik üretmenin
    /// bir maliyeti yok, eksik üretmenin ise arşiv artığı bırakma maliyeti
    /// var.
    fn purge_server_archive(&mut self, server_id: &str) {
        let Some(ark) = self.archive_root_key else { return };
        let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id) else { return };

        let now = current_time_ms();
        let buckets: Vec<String> = self.archive_conv_keys().iter().flat_map(|c| archive_buckets(&ark, c, now)).collect();
        if buckets.is_empty() {
            return;
        }
        // Tek bir istek 1 MiB'ı aşmasın (bkz. `MAX_DEPOSIT_BYTES` notu — aynı
        // kablo tavanı bütün istekler için geçerli).
        // 500: the server refuses a list longer than its 512 mailbox cap.
        let cap = self.server_rt.get(server_id).map_or(1, Self::mailbox_cap).min(500);
        for chunk in buckets.chunks(cap) {
            let req = ServerRequest::ArchivePurge { buckets: chunk.to_vec() };
            if self.send_server_request(peer_id, req).is_none() {
                warn!("Arşiv silme isteği gönderilemedi: {}", crate::log_id(server_id));
                return;
            }
        }
    }

    pub(crate) fn set_server_routing(&mut self, server_id: &str, enabled: bool) -> Result<(), String> {
        let Some(rec) = self.servers.iter_mut().find(|s| s.server_id == server_id) else {
            return Err("Sunucu bulunamadı".to_string());
        };
        rec.route_messages = enabled;
        let rec = rec.clone();
        self.persist_server(&rec);
        // Uploads go to routing servers only: with none left the queue never
        // drained and counted as pending work for good.
        if !self.servers.iter().any(|s| s.route_messages) {
            self.server_blob_uploads.clear();
            if let Some(conn) = &self.db {
                if let Err(e) = conn.execute("DELETE FROM server_blob_uploads", []) {
                    warn!("Blob yükleme kuyruğu silinemedi: {}", e);
                }
            }
        }
        Ok(())
    }

    /// A queued blob upload that a server can take now: a routing server,
    /// connected, enrolled and not in deposit backoff.
    pub(crate) fn blob_upload_can_run(&self) -> bool {
        let now = mono_ms();
        !self.server_blob_uploads.is_empty()
            && self.servers.iter().any(|s| {
                s.route_messages
                    && self.server_rt.get(&s.server_id).map_or(false, |r| r.connected && r.enrolled && now >= r.deposit_backoff_until)
            })
    }

    pub(crate) fn set_server_history(&mut self, server_id: &str, enabled: bool) -> Result<(), String> {
        if !self.servers.iter().any(|s| s.server_id == server_id) {
            return Err("Sunucu bulunamadı".to_string());
        }
        // One history server: the upload queue is global and a record leaves
        // it on the first `Ok`, so two would each hold a part of the history.
        let mut changed = Vec::new();
        for s in self.servers.iter_mut() {
            let want = if s.server_id == server_id { enabled } else { s.store_history && !enabled };
            if s.store_history != want {
                s.store_history = want;
                changed.push(s.clone());
            }
        }
        for rec in &changed {
            self.persist_server(rec);
            // History off here (or moved away): delete what this server holds,
            // as `remove_server` does. Sent once; unreachable now = it stays.
            if !rec.store_history {
                self.purge_server_archive(&rec.server_id);
            }
        }
        // No history server left: nothing will ever take the queue.
        if !self.servers.iter().any(|s| s.store_history) {
            self.server_archive_queue.clear();
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM server_archive_queue", []);
            }
        }
        // Also when history moves to another server: that one holds nothing yet.
        if enabled && !changed.is_empty() {
            self.backfill_server_archive();
        }
        Ok(())
    }

    /// History written while no server stored it was never queued: queue the
    /// newest rows now, or a restored device shows a gap up to today.
    // ponytail: newest 2000 rows only; page through `messages` if a full
    // backfill is wanted.
    pub(crate) fn backfill_server_archive(&mut self) {
        let Some(conn) = &self.db else { return };
        let Ok(mut stmt) = conn.prepare(
            "SELECT message_id, group_id, peer_device_fingerprint FROM messages \
             WHERE message_id IS NOT NULL ORDER BY id DESC LIMIT 2000",
        ) else { return };
        let rows: Vec<(String, Option<String>, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map(|it| it.flatten().collect())
            .unwrap_or_default();
        drop(stmt);
        for (mid, gid, fp) in rows.into_iter().rev() {
            self.requeue_archive_row(gid.as_deref(), &fp, &mid);
        }
    }

    pub(crate) fn list_servers_json(&self) -> String {
        let arr: Vec<serde_json::Value> = self
            .servers
            .iter()
            .map(|s| {
                let rt = self.server_rt.get(&s.server_id);
                serde_json::json!({
                    "server_id": s.server_id,
                    "address": s.address,
                    "name": s.name,
                    "route_messages": s.route_messages,
                    "store_history": s.store_history,
                    "connected": rt.map(|r| r.connected).unwrap_or(false),
                    "enrolled": rt.map(|r| r.enrolled).unwrap_or(false),
                    "last_error": rt.and_then(|r| r.last_error.clone()),
                })
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    }

    // -----------------------------------------------------------------
    // Kutu kimlikleri
    // -----------------------------------------------------------------

    /// Every store-and-forward mailbox this device reads: id -> the secret
    /// its `Register` proof is made from (`mailbox_proof`), and the key that
    /// opens its envelopes (`MailboxKey`).
    ///
    /// The one source for `Register`, `Fetch` and opening a batch.
    ///
    /// A first-contact mailbox is made from a pairing secret
    /// (`first_contact_secrets`), one mailbox per secret. Its proof key comes
    /// from this device's signing key: a holder of the code computes the id
    /// and still cannot register it.
    fn own_server_mailboxes(&self) -> HashMap<String, (Vec<u8>, MailboxKey)> {
        let mut idx = HashMap::new();
        if let Some(fp) = &self.own_mailbox_topic_fp {
            if let Some(keys) = self.own_device_keys.get(fp) {
                let owner_secret = keys.sign_sk_ed25519.to_bytes().to_vec();
                for secret in self.first_contact_secrets() {
                    idx.insert(server_seal::first_contact_mailbox_id(&secret, fp), (owner_secret.clone(), MailboxKey::FirstContact(secret)));
                }
            }
        }
        for (peer_fp, state) in &self.ratchets {
            let Some((mailbox, secret)) = self.session_mailbox(peer_fp) else { continue };
            // Rotasyon penceresi: karşı taraf son rotasyonumuzu henüz
            // uygulamadıysa hâlâ ESKİ root key ile mühürlüyor olabilir.
            let mut keys = vec![state.root_key.clone()];
            keys.extend(state.prev_root_key.clone());
            idx.insert(mailbox, (secret.to_vec(), MailboxKey::Session(keys, peer_fp.clone())));
        }
        idx
    }

    /// The server mailbox of the session with `peer_fp` and its proof secret:
    /// stable, from the two devices' long-term KEM keys
    /// (`server_seal::session_mailbox`), not from the rotating root key (C2).
    /// PROTOCOL BREAK: older clients use another id.
    fn session_mailbox(&self, peer_fp: &str) -> Option<(String, [u8; 32])> {
        let own_fp = self.own_mailbox_topic_fp.as_ref()?;
        let own = self.own_device_keys.get(own_fp)?;
        let peer = self.known_remote_devices.get(peer_fp).or_else(|| self.own_devices.get(peer_fp))?;
        server_seal::session_mailbox(&own.kem_sk_x25519, &peer.kem_pubkey_x25519, own_fp, peer_fp).ok()
    }

    /// The `MailboxProof` of `mailbox` for this enrollment at `server_id`.
    fn mailbox_proof(secret: &[u8], mailbox: &str, enrollment_id: &[u8], server_id: &str) -> Option<server_proto::MailboxProof> {
        let (seed, seed_pq) = server_seal::mailbox_proof_seeds(secret, mailbox).ok()?;
        let signing = SigningKey::from_bytes(&seed);
        let seed_pq: ml_dsa::Seed = seed_pq.as_slice().try_into().ok()?;
        let signing_pq = MlDsaSigningKey::<MlDsa87>::from_seed(&seed_pq);
        let input = server_proto::register_signing_input(mailbox, enrollment_id, server_id);
        let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
        Some(server_proto::MailboxProof {
            mailbox: mailbox.to_string(),
            pk: signing.verifying_key().to_bytes().to_vec(),
            pk_pq: signing_pq.verifying_key().encode().to_vec(),
            sig: signing.sign(&input).to_bytes().to_vec(),
            sig_pq: sig_pq.encode().to_vec(),
        })
    }

    /// `Register` for `add`, with a proof for each id of `prove` (at most
    /// `MAX_REGISTER_PROOFS`; the server asks again for the rest).
    fn send_register(&mut self, server_id: &str, peer_id: PeerId, mut add: Vec<String>, drop: Vec<String>, prove: &[String]) {
        let enrollment_id = self.servers.iter().find(|s| s.server_id == server_id).and_then(|s| s.enrollment_id.clone());
        let proofs: Vec<server_proto::MailboxProof> = match &enrollment_id {
            // L-65: the mailbox secrets only when there is something to prove.
            Some(eid) if !prove.is_empty() => {
                let mut secrets: HashMap<String, Vec<u8>> =
                    self.own_server_mailboxes().into_iter().map(|(id, (secret, _))| (id, secret)).collect();
                secrets.extend(crate::call::relay_listen_keys().into_iter().map(|k| (server_seal::relay_mailbox_id(&k), k)));
                prove.iter()
                    .take(server_proto::MAX_REGISTER_PROOFS)
                    .filter_map(|id| Self::mailbox_proof(secrets.get(id)?, id, eid, server_id))
                    .collect()
            }
            _ => Vec::new(),
        };
        // An id to prove that got no proof (over the cap, or no longer a
        // mailbox of ours) waits for the next sweep: sent bare, the server
        // asks for its proof again, without end.
        add.retain(|id| !prove.contains(id) || proofs.iter().any(|p| &p.mailbox == id));
        if add.is_empty() && drop.is_empty() {
            return;
        }
        info!("Sunucuya kutu kaydı: +{} -{} (kanıt: {})", add.len(), drop.len(), proofs.len());
        let (ids, dropped) = (add.clone(), drop.clone());
        if let Some(id) = self.send_server_request(peer_id, ServerRequest::Register { add, drop, proofs }) {
            self.server_inflight.insert(id, ServerInflight::Register { server_id: server_id.to_string(), ids, dropped });
        }
    }

    // -----------------------------------------------------------------
    // Gönderim
    // -----------------------------------------------------------------

    /// Bu zarf, sunucu kabul etmiş olsa BİLE gossipsub'a da gitmeli mi?
    ///
    /// Bu fonksiyon, sunucunun bir kara deliğe dönüşmesini engelleyen tek
    /// şey. Üç kural:
    ///
    /// 1. `Handshake`/`IdentityExchange`: HER ZAMAN iki yoldan da. Küçük,
    ///    seyrek ve kaybı telafi edilemez (karşı taraf bizi hiç tanıyamaz).
    /// 2. Rotasyon duyuran `Message`: aynı sebeple her zaman iki yoldan —
    ///    kaybolursa karşı taraf yeni `root_key`'i (dolayısıyla yeni topic'i)
    ///    ASLA öğrenemez ve o çift kalıcı olarak sağır kalır.
    /// 3. Sıradan `Message`: ilk `SERVER_ONLY_GRACE_MS` boyunca sadece
    ///    sunucu; sonrasında her yeniden deneme gossipsub'a da kopyalanır.
    ///    Böylece sansürleyen/bozuk bir sunucu teslimi "30 sn daha yavaş"a
    ///    düşürür, "hiç"e değil.
    ///
    /// Yinelenen teslim güvenli: alıcı `message_id` ile dedup ediyor ve
    /// tüketilmiş bir ratchet anahtarı zaten çözülemiyor.
    pub(crate) fn should_shadow_on_gossipsub(&self, envelope: &NetworkEnvelope) -> bool {
        match envelope {
            NetworkEnvelope::Handshake(_) | NetworkEnvelope::IdentityExchange(_) => true,
            NetworkEnvelope::Message(m) if m.header.rotation_kyber_ciphertext.is_some() => true,
            NetworkEnvelope::Message(m) => self
                .awaiting_confirmation
                .get(&m.header.message_id)
                .map(|pc| current_time_ms().saturating_sub(pc.first_sent_at) > SERVER_ONLY_GRACE_MS)
                .unwrap_or(false),
        }
    }

    /// Zarfı, yönlendirme açık ve bağlı olan sunuculara bırakmayı dener.
    ///
    /// `true` = en az bir sunucuya BIRAKILDI (RPC kuyruğa girdi). Çağıran
    /// (`try_publish_raw`) bunu "sent" sayar; uçtan uca garanti hâlâ karşı
    /// tarafın `Ack`'i.
    pub(crate) fn try_server_deposit(
        &mut self,
        target_fp: &str,
        topic: &str,
        envelope: &NetworkEnvelope,
        bytes: &[u8],
        first_attempt_at: u64,
    ) -> bool {
        if self.servers.is_empty() {
            return false;
        }
        // A first-contact topic names only the public fingerprint: its
        // mailbox id needs the pairing secret we hold for the target. With
        // none there is no server path (gossipsub and the direct path stay).
        //
        // Everything that goes to that mailbox (Handshake, IdentityExchange,
        // a Message before a session) is sealed with that secret, and to the
        // target's KEM keys when its device record is known: the server sees
        // no first-contact identity metadata. A session mailbox is sealed
        // with the session's root key (the header's
        // `sender_device_fingerprint` would be clear on the server).
        let sealed = if topic.starts_with("p2p_msg_") {
            let Some(secret) = self.first_contact_secret_for(target_fp) else { return false };
            let mailbox = server_seal::first_contact_mailbox_id(&secret, target_fp);
            let kem = self.known_remote_devices.get(target_fp)
                .filter(|d| d.kem_pubkey_x25519.len() == 32 && d.kem_pubkey_mlkem.len() == 1568)
                .map(|d| (d.kem_pubkey_x25519.as_slice(), d.kem_pubkey_mlkem.as_slice()));
            server_seal::seal_first_contact(&secret, &mailbox, kem, bytes).map(|s| (mailbox, s))
        } else {
            // Only a `Message` goes to a session topic (bkz. `try_publish_raw_via`).
            let NetworkEnvelope::Message(m) = envelope else { return false };
            let Some((mailbox, _)) = self.session_mailbox(target_fp) else { return false };
            let root = self.ratchets.get(target_fp).map(|r| match &r.prev_root_key {
                Some(prev) if m.header.rotation_kyber_ciphertext.is_some() => prev.clone(),
                _ => r.root_key.clone(),
            });
            match root {
                Some(root_key) => server_seal::seal_envelope(&root_key, &mailbox, &m.header.sender_device_fingerprint, bytes).map(|s| (mailbox, s)),
                None => Err("oturum anahtarı yok".to_string()),
            }
        };
        let (mailbox, sealed) = match sealed {
            Ok(v) => v,
            Err(e) => {
                warn!("Zarf mühürlenemedi, sunucu atlanıyor: {}", e);
                return false;
            }
        };

        if sealed.len() > MAX_DEPOSIT_BYTES {
            // Kablo tavanı (bkz. `MAX_DEPOSIT_BYTES`) — sessizce kırpılıp
            // bozulmasındansa hiç denemeyip gossipsub'a bırakmak doğru.
            warn!("Zarf sunucu tavanını aşıyor ({} bayt), gossipsub'a bırakılıyor", sealed.len());
            return false;
        }

        // bkz. `SERVER_DEPOSIT_BACKOFF_MS` — kota/hız hatası veren sunucuya
        // bir süre YENİ yatırma denenmez (aksi halde her poll turunda aynı
        // hatayı alan bir meşgul döngüsü oluşuyor).
        let now_ms = mono_ms();
        let candidates: Vec<String> = self
            .servers
            .iter()
            .filter(|s| s.route_messages)
            .filter(|s| {
                self.server_rt
                    .get(&s.server_id)
                    .map(|r| r.connected && r.enrolled && now_ms >= r.deposit_backoff_until)
                    .unwrap_or(false)
            })
            // "Not on this server" / "mailbox full here" is remembered per
            // server: one server's answer must not close the others.
            .filter(|s| {
                self.server_unknown_mailboxes
                    .get(&(s.server_id.clone(), mailbox.clone()))
                    .map_or(true, |until| now_ms >= *until)
            })
            .map(|s| s.server_id.clone())
            .collect();
        if candidates.is_empty() {
            // Once a minute: every retry of every pending packet comes here.
            static LAST_LOG_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            if now_ms.saturating_sub(LAST_LOG_MS.load(std::sync::atomic::Ordering::Relaxed)) >= 60_000 {
                LAST_LOG_MS.store(now_ms, std::sync::atomic::Ordering::Relaxed);
                info!(
                    "Sunucu atlandı (bu kutu için bağlı+kayıtlı sunucu yok; {} yapılandırılmış)",
                    self.servers.len()
                );
            }
            return false;
        }

        // A `Message` id is per mailbox: a group text goes to every member
        // under one id, and the second member's copy was skipped as "done".
        let dedup_key = match envelope {
            NetworkEnvelope::Message(_) => format!("{}|{}", mailbox, deposit_dedup_key(envelope, bytes)),
            _ => deposit_dedup_key(envelope, bytes),
        };
        let mut any = false;
        for server_id in candidates {
            // Zaten bu sunucunun diskinde: yeniden yatırma (bkz.
            // `P2PCore.server_deposited`). "Yatırıldı" saymaya devam
            // ediyoruz — çağıran için sonuç aynı, zarf sunucuda duruyor.
            if self.already_deposited(&server_id, &dedup_key) {
                any = true;
                continue;
            }
            let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { continue };
            let req = ServerRequest::Deposit { mailbox: mailbox.clone(), sealed: sealed.clone() };
            // Zarf TÜRÜ log'da: "aynı iki zarf sonsuza dek yeniden
            // yatırılıyor" gibi bir durumda türü bilmeden kök nedeni bulmak
            // imkânsız (gerçek cihazda tam olarak bu yaşandı — türü
            // görene kadar handshake mi, IdentityExchange mi, DeviceAddNotice
            // mi olduğu tahmin edilmeye çalışıldı).
            info!(
                "Sunucuya bırakılıyor: kutu={} bayt={} tür={}",
                mailbox_log_id(&mailbox),
                sealed.len(),
                envelope_kind(envelope)
            );
            if let Some(id) = self.send_server_request(peer_id, req) {
                // HEMEN işaretle, yanıtı beklemeden: yanıt Tor üzerinden
                // saniyeler sonra gelir ve o pencerede `awaiting_confirmation`
                // aynı zarfı bir kez daha yatırıyordu (gerçek cihazda
                // ölçüldü: aynı message_id 5.7 saniye arayla iki kez).
                // Başarısız olursa `handle_server_failure` işareti geri alır.
                // Artık TÜRDEN BAĞIMSIZ — bkz. `deposit_dedup_key`.
                self.note_server_deposit(&server_id, &dedup_key);
                self.server_inflight.insert(
                    id,
                    ServerInflight::Deposit {
                        server_id,
                        mailbox: mailbox.clone(),
                        envelope: envelope.clone(),
                        target_fp: target_fp.to_string(),
                        first_attempt_at,
                        dedup_key: dedup_key.clone(),
                        cancelled: false,
                    },
                );
                any = true;
            }
        }
        any
    }

    /// bkz. `P2PCore.server_deposited` — başarılı bir yatırmayı kaydeder ve
    /// haritayı sınırlar.
    pub(crate) fn note_server_deposit(&mut self, server_id: &str, dedup_key: &str) {
        let now = current_time_ms();
        self.server_deposited.insert((server_id.to_string(), dedup_key.to_string()), now);
        if self.server_deposited.len() > MAX_SERVER_DEPOSIT_MEMORY {
            self.server_deposited
                .retain(|_, t| now.saturating_sub(*t) < SERVER_DEPOSIT_MEMORY_MS);
            // Hâlâ doluysa (hepsi taze), en eskileri at.
            if self.server_deposited.len() > MAX_SERVER_DEPOSIT_MEMORY {
                let mut by_age: Vec<((String, String), u64)> =
                    self.server_deposited.iter().map(|(k, v)| (k.clone(), *v)).collect();
                by_age.sort_by_key(|(_, t)| *t);
                let drop_count = by_age.len() - MAX_SERVER_DEPOSIT_MEMORY;
                for (k, _) in by_age.into_iter().take(drop_count) {
                    self.server_deposited.remove(&k);
                }
            }
        }
    }

    /// Bu zarf bu sunucuya (yakın zamanda) zaten yatırıldı mı?
    fn already_deposited(&self, server_id: &str, dedup_key: &str) -> bool {
        let key = (server_id.to_string(), dedup_key.to_string());
        self.server_deposited
            .get(&key)
            .map(|t| current_time_ms().saturating_sub(*t) < SERVER_DEPOSIT_MEMORY_MS)
            .unwrap_or(false)
    }

    /// Bir `message_id` için "bu sunucuya zaten yatırdım" hafızasını siler.
    ///
    /// Spec dışı, teslim garantisi düzeltmesi ("karşı taraf saatlerce
    /// kapalı, sunucu üzerinden gelsin"): `already_deposited` SADECE
    /// `message_id`'ye bakıyor, ciphertext'e değil. `regen_content`
    /// tazelemesi (bkz. `retry_unconfirmed_messages`/`regen_pending_for_peer`)
    /// AYNI `message_id` ile TAMAMEN YENİ bir ciphertext üretir — eski
    /// hafıza yüzünden bu taze kopya sunucuya 12 saat boyunca (bkz.
    /// `SERVER_DEPOSIT_MEMORY_MS`) HİÇ yatırılmıyordu. Sunucuda, yani karşı
    /// tarafın çevrimdışıyken tek ulaşabileceği yerde, sadece ESKİ (araya
    /// bir ratchet rotasyonu girdiyse artık çözülemeyen) kopya kalıyordu;
    /// taze kopya yalnızca gossipsub'a gidiyordu ve o da tam olarak karşı
    /// taraf çevrimdışıyken işe yaramayan yol. Tazelemede hafızayı silmek,
    /// taze ciphertext'in de kutuya düşmesini sağlar. Alıcı her iki kopyayı
    /// da alsa bile `message_exists_with_id` ile tekilleştirir.
    /// Dış inceleme önerisi (2026-08-27): kullanıcı bekleyen bir mesajı
    /// iptal ettiğinde sunucudaki kopyayı da GERİ ÇEKER.
    ///
    /// Önceden iptal yalnızca yerel kuyruğu temizliyordu; paket sunucuya
    /// bırakılmışsa alıcı çevrimdışı olduğu sürece 30 gün orada duruyor ve
    /// er ya da geç teslim ediliyordu. Yani "vazgeçtim" demenin hiçbir
    /// karşılığı yoktu. Sunucu yalnızca `depositor == biz` olan satırı
    /// siliyor, dolayısıyla bu yol başkasının postasını silmek için
    /// kullanılamaz.
    pub(crate) fn cancel_server_deposit(&mut self, message_id: &str) {
        // No location yet for a Deposit still in flight: flag it, the
        // `Deposited` arm withdraws it.
        for inflight in self.server_inflight.values_mut() {
            if let ServerInflight::Deposit { envelope: NetworkEnvelope::Message(m), cancelled, .. } = inflight {
                if m.header.message_id == message_id {
                    *cancelled = true;
                }
            }
        }
        // Keyed `(server, "mailbox|message_id")`: one per target.
        let targets: Vec<(String, String, String, u64)> = self
            .server_deposit_locations
            .iter()
            .filter(|((_, key), _)| location_message_id(key) == message_id)
            .map(|((sid, key), (mailbox, seq))| (sid.clone(), key.clone(), mailbox.clone(), *seq))
            .collect();
        for (server_id, key, mailbox, seq) in targets {
            self.server_deposit_locations.remove(&(server_id.clone(), key));
            let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { continue };
            let req = ServerRequest::Cancel { mailbox, seqs: vec![seq] };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(id, ServerInflight::Cancel { server_id });
            }
        }
    }

    /// Only the "already deposited" marks: the old copy is still on the
    /// server and a cancel must still find it.
    pub(crate) fn forget_server_deposit(&mut self, message_id: &str) {
        self.server_deposited.retain(|(_, key), _| location_message_id(key) != message_id);
    }

    fn send_server_request(&mut self, peer: PeerId, req: ServerRequest) -> Option<request_response::OutboundRequestId> {
        let swarm = self.swarm.as_mut()?;
        Some(swarm.behaviour_mut().server_rpc.send_request(&peer, req))
    }

    // -----------------------------------------------------------------
    // Periyodik tarama
    // -----------------------------------------------------------------

    /// Bağlantı/kayıt/abonelik/çekme bakımı. `poll_events` her turda çağırır,
    /// kendi aralık kontrolünü kendi yapar (`reconnect_sweep` deseni).
    pub(crate) fn server_sweep(&mut self) {
        if self.servers.is_empty() {
            return;
        }
        // The head upload's `.enc` hash finished on its thread: only the blob
        // path goes on (a forced full sweep every turn did a Register diff,
        // fetch and archive checks for the whole wait).
        let hashed = self.server_blob_uploads.first()
            .filter(|u| u.hashing.as_ref().is_some_and(|c| c.get().is_some()))
            .and_then(|u| u.server_id.clone());
        if let Some(sid) = hashed {
            if let Some(peer_id) = self.server_rt.get(&sid).and_then(|r| r.peer_id) {
                self.server_flush_blobs(&sid, peer_id);
            }
        }
        // Radio saver (see `RADIO_WINDOW_MS`): inside the window only. New
        // mail still arrives at once as server push over the open connection.
        // `server_sweep_at == 0` is an explicit "sweep now" (more mail in the
        // batch, a chunk acked, just connected): the radio is up for that
        // exchange anyway, and waiting cost one whole window per step.
        if !self.radio_window_open && self.server_sweep_at != 0 {
            return;
        }
        let now = mono_ms();
        if now < self.server_sweep_at {
            return;
        }
        self.server_sweep_at = now + SERVER_SWEEP_INTERVAL_MS;
        self.server_unknown_mailboxes.retain(|_, until| now < *until);
        self.resume_archive_rotation();
        self.maybe_archive_backfill();

        // Öz-denetim düzeltmesi (2026-08-28): `server_deposit_locations`
        // HİÇBİR yerde budanmıyordu. Girdi yalnızca iptal (`cancel_server_deposit`)
        // ya da tazeleme (`forget_server_deposit`) sırasında siliniyordu —
        // yani NORMAL şekilde onaylanan her mesaj kalıcı bir girdi bırakıyor
        // ve harita süreç boyunca sınırsız büyüyordu.
        //
        // Kayıt yalnızca mesaj HÂLÂ onay beklerken işe yarıyor (iptal
        // edilebilecek tek şey bekleyen bir mesaj), o yüzden ölçüt basit:
        // `awaiting_confirmation`'da olmayan her kayıt gereksiz.
        if !self.server_deposit_locations.is_empty() {
            let before = self.server_deposit_locations.len();
            let pending: std::collections::HashSet<String> =
                self.awaiting_confirmation.keys().cloned().collect();
            self.server_deposit_locations.retain(|(_, key), _| pending.contains(location_message_id(key)));
            let dropped = before - self.server_deposit_locations.len();
            if dropped > 0 {
                info!("Sunucu yatırma konumu kaydından {} bayat girdi temizlendi", dropped);
            }
        }

        // Only what the loop reads: a full clone carried both enrollment
        // secret keys through every sweep.
        struct Sweep { server_id: String, address: String, route_messages: bool, store_history: bool, no_creds: bool }
        let records: Vec<Sweep> = self
            .servers
            .iter()
            .map(|s| Sweep {
                server_id: s.server_id.clone(),
                address: s.address.clone(),
                route_messages: s.route_messages,
                store_history: s.store_history,
                no_creds: s.enrollment_id.is_none() && s.token.is_empty(),
            })
            .collect();
        // The same for every server: built once, not per server and step.
        let own_ids: HashSet<String> = self.own_server_mailboxes().into_keys().collect();
        let mut blobs_flushed = false;
        for rec in records {
            let rt = self.server_rt.entry(rec.server_id.clone()).or_default();
            if rt.peer_id.is_none() {
                rt.peer_id = rec
                    .address
                    .split(',')
                    .filter_map(|a| a.trim().parse::<Multiaddr>().ok())
                    .find_map(|a| extract_peer_id(&a));
            }
            let Some(peer_id) = rt.peer_id else { continue };
            let connected = rt.connected;
            let enrolled = rt.enrolled;
            // Doubles to 30 min while the server keeps refusing us.
            let hello_stale = now.saturating_sub(rt.hello_sent_at)
                > (SERVER_SWEEP_INTERVAL_MS << rt.hello_attempts.min(7)).min(30 * 60 * 1000);
            // Nothing to enroll with, and the server already said no once.
            let no_credentials = rec.no_creds && rt.last_error.is_some();

            // Swarm'a SOR: olay tabanlı `rt.connected` bayrağı kaçırılmış
            // olabilir (bkz. `load_servers_from_db` — `peer_id` geç dolarsa
            // `note_server_connection` eşleştiremez). Kaçırıldığında yeniden
            // dial etmek İŞE YARAMAZ: libp2p zaten bağlı, yeni bir olay
            // üretmez. Bu yüzden gerçeği her turda swarm'dan doğruluyoruz.
            let really_connected =
                self.swarm.as_ref().map(|s| s.is_connected(&peer_id)).unwrap_or(false);
            if really_connected && !connected {
                if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                    rt.connected = true;
                }
            }
            let connected = connected || really_connected;

            if !connected {
                // Offline server: back off 15 s doubling to 30 min. Without it
                // every sweep (15 s) was one more failed onion lookup, the CPU
                // never idled (9S 2026-09-30: 35 dials in 11 min on Wi-Fi).
                let Some(rt) = self.server_rt.get_mut(&rec.server_id) else { continue };
                // A legacy record holding only private-network addresses: the
                // server path is onion-only, do not dial the LAN.
                let addrs = server_proto::public_server_addrs(rec.address.split(','));
                if addrs.is_empty() {
                    rt.last_error = Some("No reachable address. Add the server again with a new invite code".to_string());
                    continue;
                }
                if now < rt.dial_backoff_until { continue; }
                rt.dial_backoff_until = now + (SERVER_SWEEP_INTERVAL_MS << rt.dial_attempts.min(7)).min(30 * 60 * 1000);
                rt.dial_attempts += 1;
                // Bağlı değiliz: BİLİNEN HER adresi aynı anda dene (bkz.
                // `ServerRecord.address`).
                for a in addrs.iter().filter_map(|a| a.parse::<Multiaddr>().ok()) {
                    self.dial_with_relay_fallback(peer_id, Some(a));
                }
                continue;
            }
            if !enrolled {
                // One enrollment exchange at a time: a second `Welcome`
                // replaced the challenge the first `Enroll` was signed over.
                let enrolling = self.server_inflight.values().any(|i| {
                    matches!(i, ServerInflight::Hello { .. } | ServerInflight::Enroll { .. } | ServerInflight::Rebind { .. })
                        && i.server_id() == rec.server_id
                });
                if hello_stale && !no_credentials && !enrolling {
                    if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                        rt.hello_sent_at = now;
                        rt.hello_attempts += 1;
                    }
                    if let Some(id) =
                        self.send_server_request(peer_id, ServerRequest::Hello { version: SERVER_PROTOCOL_VERSION })
                    {
                        self.server_inflight.insert(id, ServerInflight::Hello { server_id: rec.server_id.clone() });
                    }
                }
                continue;
            }

            // Kayıtlıyız: abonelik farkını gönder.
            // A server that only stores history gets no mailbox ids (it would
            // see one per conversation) and is not polled for
            // mail that cannot arrive there.
            // The relay addresses of a running call go to every server: any
            // of them may carry the media, and nothing is stored under them.
            let relay_ids: Vec<String> =
                crate::call::relay_listen_keys().iter().map(|k| server_seal::relay_mailbox_id(k)).collect();
            let mut wanted: HashSet<String> = if rec.route_messages { own_ids.clone() } else { HashSet::new() };
            wanted.extend(relay_ids.iter().cloned());
            if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                // M29: a refusal is not for good: try again after a while.
                if !rt.refused.is_empty() && now >= rt.refused_retry_at {
                    rt.refused.clear();
                }
                wanted.retain(|id| !rt.refused.contains(id));
            }
            // The server refuses a whole list over its mailbox cap: over it,
            // the relay ids and then a stable part (no churn between sweeps);
            // the rest is reached over the direct path only.
            let cap = self.server_rt.get(&rec.server_id).map_or(1, Self::mailbox_cap);
            let over_cap = wanted.len() > cap;
            if over_cap {
                let total = wanted.len();
                let mut ids: Vec<String> = wanted.into_iter().collect();
                ids.sort_by_key(|id| (!relay_ids.contains(id), id.clone()));
                ids.truncate(cap);
                wanted = ids.into_iter().collect();
                warn!("Sunucu kutu sınırı aşıldı: {} > {} ({})", total, cap, crate::log_id(&rec.server_id));
            }
            if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                let ours = rt.last_error.as_deref().map_or(false, |e| e.starts_with(TOO_MANY_MAILBOXES));
                if over_cap {
                    rt.last_error = Some(format!("{TOO_MANY_MAILBOXES} ({cap}): some chats use the direct path only"));
                } else if ours && rt.refused.is_empty() {
                    rt.last_error = None;
                }
            }
            let (current, register_ok) = self.server_rt.get(&rec.server_id)
                .map(|r| (r.registered.clone(), now >= r.register_backoff_until)).unwrap_or_default();
            let mut add: Vec<String> = wanted.difference(&current).cloned().collect();
            let mut drop: Vec<String> = current.difference(&wanted).cloned().collect();
            add.truncate(cap);
            drop.truncate(cap);
            let register_inflight = self.server_inflight.values()
                .any(|i| matches!(i, ServerInflight::Register { server_id, .. } if *server_id == rec.server_id));
            if register_ok && !register_inflight && (!add.is_empty() || !drop.is_empty()) {
                // A relay address is new with each call: its proof goes with
                // the first request. The other ids are mostly ones this
                // enrollment reads already, and the server names the rest
                // (`Registered.proof_needed`).
                let prove: Vec<String> = add.iter().filter(|id| relay_ids.contains(id)).cloned().collect();
                self.send_register(&rec.server_id, peer_id, add, drop, &prove);
            }

            // Emniyet çekmesi (itme kaybolduysa).
            let due = self.server_rt.get(&rec.server_id).map(|r| r.fetch_due_at).unwrap_or(0);
            if rec.route_messages && now >= due {
                self.server_fetch(&rec.server_id, peer_id, &own_ids);
            }

            if rec.store_history {
                self.purge_retired_archive(&rec.server_id, peer_id);
                self.server_flush_archive(&rec.server_id, peer_id);
            }
            // One upload server per sweep: the first ready one that routes.
            if rec.route_messages && !blobs_flushed {
                blobs_flushed = true;
                self.server_flush_blobs(&rec.server_id, peer_id);
            }
        }
    }

    fn server_fetch(&mut self, server_id: &str, peer_id: PeerId, own_ids: &HashSet<String>) {
        // Nothing is taken before the storage keys are loaded: a fetched
        // item would wait in `deferred_incoming`, where it can be evicted.
        // M-16: nor while fetched mail waits for its rate budget: the
        // backlog stays one batch.
        if !self.storage_keys_ready() || self.server_mail_deferred() {
            return;
        }
        // Zaten havada bir `Fetch` varsa ikincisini gönderme (bkz.
        // `ServerRuntime.fetch_inflight`).
        if self.server_rt.get(server_id).map(|r| r.fetch_inflight).unwrap_or(false) {
            return;
        }
        // Cursors of mailboxes no longer ours (a deleted session or contact).
        let stale: Vec<(String, String)> = self
            .server_cursors
            .keys()
            .filter(|(sid, mb)| sid == server_id && !own_ids.contains(mb))
            .cloned()
            .collect();
        for key in stale {
            self.server_cursors.remove(&key);
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1 AND mailbox_id = ?2", params![key.0, key.1]);
            }
        }
        // The same stable part `server_sweep` registers when over the cap.
        // Refused ids are skipped there too, or a registered id past them
        // fell out of every Fetch.
        let (cap, refused) = self.server_rt.get(server_id).map_or((1, HashSet::new()), |rt| (Self::mailbox_cap(rt), rt.refused.clone()));
        let mut ids: Vec<&String> = own_ids.iter().filter(|id| !refused.contains(*id)).collect();
        ids.sort();
        ids.truncate(cap);
        let cursors: Vec<(String, u64)> = ids
            .into_iter()
            .map(|mb| {
                let seq = self.server_cursors.get(&(server_id.to_string(), mb.clone())).copied().unwrap_or(0);
                (mb.clone(), seq)
            })
            .collect();
        if cursors.is_empty() {
            return;
        }
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.fetch_due_at = mono_ms() + SERVER_FETCH_SWEEP_INTERVAL_MS;
        }
        let req = ServerRequest::Fetch {
            cursors,
            max_items: MAX_FETCH_BATCH_ITEMS,
            max_bytes: MAX_FETCH_BATCH_BYTES,
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::Fetch { server_id: server_id.to_string() });
            // Only for a request that went out: set before, a failed send
            // left it true and nothing was fetched until the next reconnect.
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.fetch_inflight = true;
            }
        }
    }

    /// The server's mailbox cap (`Welcome`/`Enrolled` limits; the protocol
    /// default before those). A longer list is refused whole.
    fn mailbox_cap(rt: &ServerRuntime) -> usize {
        rt.limits.as_ref().map_or_else(|| ServerLimits::default().max_mailboxes, |l| l.max_mailboxes).max(1) as usize
    }

    /// Acks what the batches of earlier calls brought, once that mail went
    /// through `process_incoming_envelope`. `poll_events` calls this after
    /// its incoming loop; `drive_server_sync` calls it too, for the turns
    /// before. Acked before processing, a crash in between lost the only copy.
    pub(crate) fn commit_server_fetches(&mut self) {
        // M-16: fetched mail still waits for its rate budget; acked now, a
        // crash before it is processed would lose it.
        if self.server_mail_deferred() {
            return;
        }
        let now = mono_ms();
        // This turn's items were processed: failures were reported
        // (`server_item_failed`). Held and passed items the cursor went past
        // are done.
        let cursors = &self.server_cursors;
        // H87: items still deferred (keys not ready) keep their record, so a
        // later failure can still hold them (`server_item_failed`).
        let deferred: std::collections::HashSet<[u8; 32]> =
            self.deferred_incoming.iter().filter(|(s, _)| s.is_none()).map(|(_, r)| Sha256::digest(r).into()).collect();
        for (sid, rt) in self.server_rt.iter_mut() {
            rt.taken.retain(|d, _| deferred.contains(d));
            let below = |mb: &String, seq: u64| cursors.get(&(sid.clone(), mb.clone())).map_or(true, |c| *c < seq);
            rt.held.retain(|mb, (seq, _)| below(mb, *seq));
            rt.passed.retain(|(mb, seq)| below(mb, *seq));
        }
        let due: Vec<String> = self
            .server_rt
            .iter()
            .filter(|(_, rt)| !rt.unacked.is_empty() && rt.connected && rt.enrolled && now >= rt.ack_retry_at)
            .map(|(sid, _)| sid.clone())
            .collect();
        for sid in due {
            // One Ack in flight per server: a late `Ok` cannot persist an
            // older position after a newer one.
            if self.server_inflight.values().any(|i| matches!(i, ServerInflight::Ack { .. }) && i.server_id() == sid) {
                continue;
            }
            let Some(rt) = self.server_rt.get_mut(&sid) else { continue };
            let Some(peer_id) = rt.peer_id else { continue };
            let cap = Self::mailbox_cap(rt);
            let keys: Vec<String> = rt.unacked.keys().take(cap).cloned().collect();
            let acks: Vec<(String, u64)> = keys.into_iter().filter_map(|k| rt.unacked.remove_entry(&k)).collect();
            match self.send_server_request(peer_id, ServerRequest::Ack { acks: acks.clone() }) {
                Some(id) => {
                    self.server_inflight.insert(id, ServerInflight::Ack { server_id: sid, acks });
                }
                None => self.restage_acks(&sid, acks),
            }
        }
    }

    /// An `Ack` that did not go through: again after one sweep interval.
    fn restage_acks(&mut self, server_id: &str, acks: Vec<(String, u64)>) {
        let Some(rt) = self.server_rt.get_mut(server_id) else { return };
        for (mailbox, seq) in acks {
            let e = rt.unacked.entry(mailbox).or_insert(0);
            *e = (*e).max(seq);
        }
        rt.ack_retry_at = mono_ms() + SERVER_SWEEP_INTERVAL_MS;
    }

    /// C1: `seq` of `mailbox` did not open or failed to process. `true`: it
    /// holds the mailbox's cursor (not acked, the server keeps it). `false`:
    /// it has failed for `SERVER_HOLD_GRACE_MS` and is passed over for good.
    fn hold_server_item(&mut self, server_id: &str, mailbox: &str, seq: u64, now: u64) -> bool {
        let Some(rt) = self.server_rt.get_mut(server_id) else { return false };
        let e = rt.held.entry(mailbox.to_string()).or_insert((seq, now));
        if e.0 != seq {
            *e = (seq, now);
        }
        if now.saturating_sub(e.1) < SERVER_HOLD_GRACE_MS {
            return true;
        }
        warn!("Sunucu öğesi {} dk açılamadı/işlenemedi, atlanıyor (kutu={})", SERVER_HOLD_GRACE_MS / 60_000, mailbox_log_id(mailbox));
        rt.held.remove(mailbox);
        rt.passed.insert((mailbox.to_string(), seq));
        false
    }

    /// Battery #3: 5 min doubling to 30 min while the server keeps refusing or
    /// not answering deposits; a `Deposited` resets it.
    fn back_off_deposits(rt: &mut ServerRuntime) {
        rt.deposit_backoff_until = mono_ms()
            + (SERVER_DEPOSIT_BACKOFF_MS << rt.deposit_failures.min(3)).min(SERVER_DEPOSIT_BACKOFF_MAX_MS);
        rt.deposit_failures = rt.deposit_failures.saturating_add(1);
    }

    /// A fetch soon for a held item, not at the next safety sweep.
    fn refetch_held(&mut self, server_id: &str, now: u64) {
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.fetch_due_at = rt.fetch_due_at.min(now + SERVER_HOLD_REFETCH_MS);
        }
    }

    /// H14: `process_incoming_envelope` failed on a fetched item (`raw`, as
    /// handed to `incoming`). Its mailbox's cursor goes back before it, so the
    /// Ack of this turn does not let the server delete it; it is fetched again
    /// (`hold_server_item`). Called by `poll_events` for each `Err` of a
    /// packet with no source peer.
    pub(crate) fn server_item_failed(&mut self, raw: &[u8]) {
        let digest: [u8; 32] = Sha256::digest(raw).into();
        let found = self.server_rt.iter_mut().find_map(|(sid, rt)| rt.taken.remove(&digest).map(|t| (sid.clone(), t)));
        let Some((server_id, (mailbox, seq))) = found else { return };
        let now = mono_ms();
        if !self.hold_server_item(&server_id, &mailbox, seq, now) {
            return;
        }
        let key = (server_id.clone(), mailbox.clone());
        if let Some(c) = self.server_cursors.get_mut(&key) {
            *c = (*c).min(seq - 1);
        }
        if let Some(rt) = self.server_rt.get_mut(&server_id) {
            if let Some(e) = rt.unacked.get_mut(&mailbox) {
                *e = (*e).min(seq - 1);
            }
        }
        self.refetch_held(&server_id, now);
    }

    // -----------------------------------------------------------------
    // Olay işleme
    // -----------------------------------------------------------------

    /// `poll_events`'in swarm borrow'u kapandıktan sonra çağrılır.
    ///
    /// `incoming`: sunucudan çekilen zarflar BURAYA eklenir ve mevcut gelen
    /// paket yoluna (`process_incoming_envelope`) girer — imza doğrulama,
    /// `sender_identity_id` bağlama kontrolü, erken-paket tamponlaması ve
    /// `Ack` üretimi olduğu gibi yeniden kullanılır.
    pub(crate) fn drive_server_sync(
        &mut self,
        events: Vec<ServerEventLocal>,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) -> Vec<(request_response::ResponseChannel<ServerResponse>, ServerResponse)> {
        // What earlier calls staged was processed in their turn: ack it now
        // even if the caller's own `commit_server_fetches` did not run.
        self.commit_server_fetches();
        let mut replies = Vec::new();
        for evt in events {
            match evt {
                ServerEventLocal::Request { peer, request, channel } => {
                    let resp = self.handle_server_push(peer, request, incoming);
                    replies.push((channel, resp));
                }
                ServerEventLocal::Response { request_id, response } => {
                    if let Some(inflight) = self.server_inflight.remove(&request_id) {
                        self.handle_server_response(inflight, response, incoming);
                    }
                }
                ServerEventLocal::OutboundFailure { request_id } => {
                    if let Some(inflight) = self.server_inflight.remove(&request_id) {
                        self.handle_server_failure(inflight);
                    }
                }
            }
        }
        replies
    }

    /// Sunucudan gelen tek meşru istek: `Notify`.
    fn handle_server_push(
        &mut self,
        peer: PeerId,
        request: ServerRequest,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) -> ServerResponse {
        match request {
            // The item itself (see `ServerRequest::Push`): run it through the
            // exact `Fetch` path — opening, cursor, ack — as a one-item batch.
            ServerRequest::Push { item } => {
                let sid = self
                    .server_rt
                    .iter()
                    .find(|(_, rt)| rt.peer_id == Some(peer))
                    .map(|(sid, _)| sid.clone());
                let Some(server_id) = sid else {
                    return ServerResponse::Err(ServerErrorCode::BadDirection);
                };
                // Only a server we are enrolled at, and only once the storage
                // keys are loaded (see `server_fetch`): otherwise the item stays
                // on the server and comes with the next Fetch.
                let enrolled = self.server_rt.get(&server_id).map_or(false, |rt| rt.enrolled);
                if !enrolled {
                    return ServerResponse::Ok;
                }
                if !self.storage_keys_ready() {
                    return self.handle_server_push(peer, ServerRequest::Notify, incoming);
                }
                // 30 per 5 s. Each Push costs an open, the processing and an
                // Ack. Over that the item is left on the server and the Push
                // counts as a `Notify` (one fetch per 5 s).
                let now = mono_ms();
                let over = self.server_rt.get_mut(&server_id).map_or(true, |rt| {
                    if now.saturating_sub(rt.push_window_at) >= 5_000 {
                        rt.push_window_at = now;
                        rt.push_count = 0;
                    }
                    rt.push_count += 1;
                    rt.push_count > 30
                });
                if over {
                    return self.handle_server_push(peer, ServerRequest::Notify, incoming);
                }
                // C1: a mailbox held before an earlier item takes its later
                // items in order, from the held item's refetch (not at once:
                // see `SERVER_HOLD_REFETCH_MS`).
                let behind = self.server_rt.get(&server_id)
                    .and_then(|rt| rt.held.get(&item.mailbox_id))
                    .map_or(false, |&(held, _)| item.seq > held);
                if behind {
                    self.refetch_held(&server_id, now);
                    return ServerResponse::Ok;
                }
                // The batch path clears `fetch_inflight`; a real Fetch may
                // still be out, keep its flag.
                let inflight = self.server_rt.get(&server_id).map_or(false, |rt| rt.fetch_inflight);
                self.handle_server_response(
                    ServerInflight::Fetch { server_id: server_id.clone() },
                    ServerResponse::Batch { items: vec![item], more: false },
                    incoming,
                );
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.fetch_inflight = inflight;
                }
                ServerResponse::Ok
            }
            ServerRequest::Notify => {
                // Yükü burada TAŞIMIYORUZ — sadece "bir sonraki turda çek"
                // diyoruz, böylece imleç mantığı bozulmaz.
                let sid = self
                    .server_rt
                    .iter()
                    .find(|(_, rt)| rt.peer_id == Some(peer))
                    .map(|(sid, _)| sid.clone());
                // One per 5 s: each Notify opens the radio window and forces a
                // sweep, so a server sending them in a row kept the phone
                // fetching without end. A second one inside that time is
                // covered by the fetch the first one started.
                let now = mono_ms();
                let sid = sid.filter(|sid| {
                    self.server_rt.get_mut(sid).map_or(false, |rt| {
                        let ok = now.saturating_sub(rt.notified_at) >= 5_000;
                        if ok { rt.notified_at = now; }
                        ok
                    })
                });
                if let Some(sid) = sid {
                    if let Some(rt) = self.server_rt.get_mut(&sid) {
                        rt.fetch_due_at = 0;
                    }
                    self.server_sweep_at = 0;
                    // The radio is up for this push anyway: open the saver
                    // window now so the Fetch rides it (`RADIO_WINDOW_MS`).
                    self.radio_window_at = 0;
                }
                ServerResponse::Ok
            }
            // Bir "sunucu" bize mesaj bırakmaya/kutu açmaya çalışıyorsa
            // protokolü yanlış kullanıyordur.
            _ => ServerResponse::Err(ServerErrorCode::BadDirection),
        }
    }

    /// A new enrollment (a reset server numbers its mail from 1 again): old
    /// cursors would skip every new item for good.
    fn forget_server_cursors(&mut self, server_id: &str) {
        self.server_cursors.retain(|(sid, _), _| sid != server_id);
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.unacked.clear();
            rt.refused.clear();
            rt.registered.clear();
            rt.held.clear();
            rt.passed.clear();
        }
        // Its mail is gone with the old enrollment: deposit again.
        self.server_deposited.retain(|(sid, _), _| sid != server_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1", params![server_id]);
        }
    }

    fn handle_server_response(
        &mut self,
        inflight: ServerInflight,
        response: ServerResponse,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) {
        match (inflight, response) {
            // --- Hello ---
            (ServerInflight::Hello { server_id }, ServerResponse::Welcome { version, challenge, enrolled, enrollment_id, limits, server_name }) => {
                let Some(mut rec) = self.servers.iter().find(|s| s.server_id == server_id).cloned() else { return };
                if version != SERVER_PROTOCOL_VERSION {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        // H105: say which side is behind.
                        rt.last_error = Some(if version < SERVER_PROTOCOL_VERSION {
                            format!("Server protocol {version}, this app speaks {SERVER_PROTOCOL_VERSION}: update the server")
                        } else {
                            format!("Server protocol {version}, this app speaks {SERVER_PROTOCOL_VERSION}: update this app")
                        });
                    }
                    return;
                }
                // The server's id for our enrollment, taken only when we have
                // none or still hold an invite token (the `Enrolled` answer of
                // that enrollment was lost). M37: otherwise a different one is
                // not adopted: it would wipe every cursor on each Hello and let
                // the server choose the id our proofs are made over. A reset
                // server does not know us and answers `enrolled: false`.
                let adopted = match enrollment_id {
                    Some(id) if enrolled && rec.enrollment_id.as_ref() != Some(&id)
                        && (rec.enrollment_id.is_none() || !rec.token.is_empty()) => {
                        rec.enrollment_id = Some(id);
                        true
                    }
                    _ => false,
                };
                if adopted {
                    self.forget_server_cursors(&server_id);
                }
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.limits = Some(limits);
                    rt.enrolled = enrolled;
                    // Enrolled with no id here: the `Enrolled` answer was lost.
                    // Mailbox proofs need the id; only a fresh invite helps.
                    rt.last_error = (enrolled && rec.enrollment_id.is_none())
                        .then(|| "Enrollment id lost. Add the server again with a new invite code".to_string());
                    if enrolled {
                        rt.hello_attempts = 0;
                    }
                }
                // Shown in the UI and stored: no control characters, bounded.
                let server_name: String = server_name.chars().filter(|c| !c.is_control()).take(64).collect();
                let spent_token = enrolled && rec.enrollment_id.is_some() && !rec.token.is_empty();
                if (rec.name.is_empty() && !server_name.is_empty()) || spent_token || adopted {
                    if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                        r.enrollment_id = rec.enrollment_id.clone();
                        if r.name.is_empty() {
                            r.name = server_name;
                        }
                        // Not needed while the server knows us; stored, it only
                        // waits to leak.
                        if spent_token {
                            r.token.clear();
                        }
                        let r = r.clone();
                        self.persist_server(&r);
                    }
                }
                if enrolled {
                    // Sunucu bizi zaten tanıyor; abonelikleri tazelemek için
                    // taramayı hemen tetikle.
                    self.server_sweep_at = 0;
                    return;
                }
                self.begin_enrollment(&server_id, &challenge);
            }

            // --- Enroll / Rebind ---
            (ServerInflight::Enroll { server_id }, ServerResponse::Enrolled { enrollment_id, limits })
            | (ServerInflight::Rebind { server_id }, ServerResponse::Enrolled { enrollment_id, limits }) => {
                let mut new_enrollment = false;
                if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                    new_enrollment = r.enrollment_id.as_ref() != Some(&enrollment_id);
                    r.enrollment_id = Some(enrollment_id);
                    // Jeton tek kullanımlık — sakladığımızda bir faydası yok,
                    // sızması hâlinde zararı var.
                    r.token.clear();
                    let r = r.clone();
                    self.persist_server(&r);
                }
                // A new enrollment (a reset server numbers its mail from 1
                // again): old cursors would skip every new item for good.
                if new_enrollment {
                    self.forget_server_cursors(&server_id);
                }
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = true;
                    rt.hello_attempts = 0;
                    rt.limits = Some(limits);
                    rt.registered.clear();
                    rt.last_error = None;
                }
                info!("Sunucuya kaydolundu: {}", crate::log_id(&server_id));
                self.server_sweep_at = 0;
                // #76: partial downloads can go on from the server's copy.
                self.resume_incomplete_downloads_for(&std::collections::HashSet::new(), true);
            }

            // --- Register ---
            (ServerInflight::Register { server_id, ids, dropped }, ServerResponse::Ok) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    for id in ids {
                        rt.registered.insert(id);
                    }
                    // Düşürülenler çıkarılmıyordu: fark her turda "-1" olarak
                    // yeniden gönderiliyordu (cihazda sürekli "+0 -1").
                    for id in dropped {
                        rt.registered.remove(&id);
                    }
                }
            }

            // The ids of `ids` the server did not name are registered; the
            // `proof_needed` ones go again, with their proofs; the `refused`
            // ones (cap, reader cap, a taken key) wait `SERVER_REFUSED_RETRY_MS`.
            (ServerInflight::Register { server_id, ids, dropped }, ServerResponse::Registered { proof_needed, refused }) => {
                let prove: Vec<String> = proof_needed.into_iter().filter(|id| ids.contains(id)).collect();
                let peer_id = self.server_rt.get(&server_id).and_then(|r| r.peer_id);
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    let refused: Vec<String> = refused.into_iter().filter(|id| ids.contains(id)).collect();
                    for id in ids.into_iter().filter(|id| !prove.contains(id) && !refused.contains(id)) {
                        rt.registered.insert(id);
                    }
                    for id in dropped {
                        rt.registered.remove(&id);
                    }
                    if !refused.is_empty() {
                        warn!("Sunucu {} kutuyu reddetti ({})", refused.len(), crate::log_id(&server_id));
                        rt.last_error = Some(format!("{TOO_MANY_MAILBOXES}: the server refused some, those chats use the direct path only"));
                        rt.refused.extend(refused);
                        rt.refused_retry_at = mono_ms() + SERVER_REFUSED_RETRY_MS;
                    }
                }
                if let Some(peer_id) = peer_id.filter(|_| !prove.is_empty()) {
                    let now: Vec<String> = prove.iter().take(server_proto::MAX_REGISTER_PROOFS).cloned().collect();
                    self.send_register(&server_id, peer_id, now.clone(), Vec::new(), &now);
                }
            }

            // Sunucu `Ack`/`ArchivePurge`/`BlobDelete` için sade `Ok`
            // yanıtlıyor — bunları açıkça karşılamazsak her onay
            // "beklenmeyen yanıt" uyarısı basardı.
            // The server dropped these items: the cursor goes to disk now. A
            // crash before this fetches them again (deduplicated), never skips.
            (ServerInflight::Ack { server_id, acks }, ServerResponse::Ok) => {
                if self.servers.iter().any(|s| s.server_id == server_id) {
                    for (mailbox, seq) in acks {
                        self.persist_cursor(&server_id, &mailbox, seq);
                    }
                }
            }

            // --- Deposit ---
            (ServerInflight::Deposit { mailbox, server_id, envelope, cancelled, .. }, ServerResponse::Deposited { seq }) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.deposit_failures = 0;
                }
                info!("Sunucu zarfı sakladı: kutu={} seq={}", mailbox_log_id(&mailbox), seq);
                if cancelled {
                    if let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) {
                        let req = ServerRequest::Cancel { mailbox, seqs: vec![seq] };
                        if let Some(id) = self.send_server_request(peer_id, req) {
                            self.server_inflight.insert(id, ServerInflight::Cancel { server_id });
                        }
                    }
                    return;
                }
                // The "already deposited" mark was set at send time
                // (`try_server_deposit`).
                if let NetworkEnvelope::Message(m) = &envelope {
                    // bkz. `server_deposit_locations` — geri çekebilmek için
                    // paketin kutuda hangi sırada durduğunu saklıyoruz.
                    self.server_deposit_locations.insert(
                        (server_id.clone(), format!("{}|{}", mailbox, m.header.message_id)),
                        (mailbox.clone(), seq),
                    );
                }
            }

            (ServerInflight::Cancel { .. }, ServerResponse::Ok) => {}

            // --- Fetch ---
            (ServerInflight::Fetch { server_id }, ServerResponse::Batch { items, more }) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.fetch_inflight = false;
                }
                let index: HashMap<String, MailboxKey> =
                    self.own_server_mailboxes().into_iter().map(|(id, (_, key))| (id, key)).collect();
                let mut highest: HashMap<String, u64> = HashMap::new();
                let mut count = 0usize;
                let mut bytes = 0usize;
                // C1: the cursor of a mailbox stops before its first item that
                // does not open (`hold_server_item`); its later items come with
                // the next fetch. `seen`: mailboxes this batch reached;
                // `blocked`: held in this batch.
                let mut seen: HashSet<String> = HashSet::new();
                let mut blocked: HashSet<String> = HashSet::new();
                let mut held_any = false;
                let now = mono_ms();

                for item in items {
                    let Some(key) = index.get(&item.mailbox_id) else {
                        // Not a mailbox of ours: no cursor, no ack.
                        continue;
                    };
                    // The server numbers mail with an SQLite rowid: a larger
                    // seq is bogus and would park the cursor at the top.
                    if item.seq > i64::MAX as u64 || blocked.contains(&item.mailbox_id) {
                        continue;
                    }
                    // At or below the cursor: taken before. A server that sends
                    // it again gets no second open and no second processing.
                    if item.seq <= self.server_cursors.get(&(server_id.clone(), item.mailbox_id.clone())).copied().unwrap_or(0) {
                        continue;
                    }
                    let first = seen.insert(item.mailbox_id.clone());
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        if rt.passed.contains(&(item.mailbox_id.clone(), item.seq)) {
                            continue;
                        }
                        // A Fetch answers from the cursor up: a held item that
                        // is not the first of its mailbox any more is gone.
                        if let Some(&(held, _)) = rt.held.get(&item.mailbox_id) {
                            if first && item.seq > held {
                                rt.held.remove(&item.mailbox_id);
                            }
                        }
                    }
                    // Nothing unsealed is taken from the server: a session's
                    // mailbox opens with its root key, a first-contact mailbox
                    // with its pairing secret and this device's KEM keys.
                    let opened = match key {
                        MailboxKey::Session(root_keys, peer_fp) => root_keys
                            .iter()
                            .find_map(|k| server_seal::open_envelope(k, &item.mailbox_id, peer_fp, &item.sealed).ok()),
                        MailboxKey::FirstContact(secret) => self.own_mailbox_topic_fp.as_ref()
                            .and_then(|fp| self.own_device_keys.get(fp))
                            .and_then(|k| server_seal::open_first_contact(secret, &item.mailbox_id, &k.kem_sk_x25519, &k.kem_sk_mlkem, &item.sealed).ok()),
                    };
                    let Some(raw) = opened else {
                        // Not acked and the cursor stays before it: an Ack is
                        // cumulative and the server deletes what it covers.
                        // Passed over only after `SERVER_HOLD_GRACE_MS`.
                        warn!("Sunucudan gelen zarf açılamadı (kutu={})", mailbox_log_id(&item.mailbox_id));
                        if self.hold_server_item(&server_id, &item.mailbox_id, item.seq, now) {
                            blocked.insert(item.mailbox_id.clone());
                            held_any = true;
                        }
                        continue;
                    };
                    count += 1;
                    bytes += raw.len();
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.taken.insert(Sha256::digest(&raw).into(), (item.mailbox_id.clone(), item.seq));
                    }
                    // KRİTİK: `None`.
                    //
                    // Sunucunun `PeerId`'si verilseydi
                    // `record_peer_id_if_known` her kişi için
                    // `device_to_peer_id`/`device_last_addr`'ı
                    // SUNUCUYA yönlendirirdi — `is_peer_connected`
                    // yalan söyler, `reconnect_sweep` sonsuza dek
                    // sunucuyu dial eder, dosya parçaları yanlış
                    // eşten istenirdi.
                    incoming.push((None, raw));
                    let h = highest.entry(item.mailbox_id.clone()).or_insert(0);
                    *h = (*h).max(item.seq);
                }

                if count > 0 {
                    info!("Sunucudan {} zarf çekildi ({} bayt)", count, bytes);
                }
                // The cursor moves in memory now (no second processing), but
                // goes to disk and to the server (`Ack`) only once `incoming`
                // was processed: `commit_server_fetches`, then the Ack's `Ok`.
                // Forward only: a Push of an old seq moved the cursor back and
                // everything after it was delivered again.
                let mut advanced = false;
                for (mailbox, seq) in highest {
                    let key = (server_id.clone(), mailbox.clone());
                    if seq > self.server_cursors.get(&key).copied().unwrap_or(0) {
                        self.server_cursors.insert(key, seq);
                        advanced = true;
                        if let Some(rt) = self.server_rt.get_mut(&server_id) {
                            let e = rt.unacked.entry(mailbox).or_insert(0);
                            *e = (*e).max(seq);
                        }
                    }
                }
                // `more` with no progress would be the same Fetch again, at once
                // and for as long as the server says so.
                if more && advanced {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.fetch_due_at = 0;
                    }
                    self.server_sweep_at = 0;
                } else if held_any && count > 0 {
                    // What opened may bring the key of what did not.
                    self.refetch_held(&server_id, now);
                }
            }

            // --- Arşiv ---
            (ServerInflight::ArchivePut { records, .. }, ServerResponse::Ok) => {
                self.drop_archive_records(&records);
                // The next batch now, as for mail and chunks (bkz.
                // `server_sweep`): one batch per radio window took the
                // re-upload after a revoke the better part of an hour.
                if !self.server_archive_queue.is_empty() {
                    self.server_sweep_at = 0;
                }
            }
            (ServerInflight::ArchivePurge { server_id, keys, rest }, ServerResponse::Ok) => {
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { return };
                self.send_archive_purge(peer_id, server_id, keys, rest);
            }
            (ServerInflight::ArchiveProbe { server_id, conv_key, group, window, next }, ServerResponse::ArchiveProbed { mut present }) => {
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else {
                    if let Some((before, _)) = window { self.reopen_fetch_cursor(&conv_key, before) }
                    return;
                };
                // A press: the buckets that reach its window, newest first,
                // each read from `before` back.
                if let Some((_, after)) = window {
                    present.retain(|b| b.newest_ms >= archive_wire_ms(after));
                    present.sort_by(|a, b| b.newest_ms.cmp(&a.newest_ms));
                }
                let mut wanted: Vec<String> = present.into_iter().map(|b| b.bucket).collect();
                // One bucket in flight per conversation; the `ArchiveBatch`
                // arm asks for the next. All at once was hundreds of 512 KiB
                // replies over one Tor circuit, and the timeouts were silent.
                if wanted.is_empty() {
                    self.probe_next_conversation(peer_id, server_id, next);
                } else {
                    let bucket = wanted.remove(0);
                    self.send_archive_fetch(peer_id, server_id, conv_key, group, bucket, window.map(|(before, _)| (before, String::new())), wanted, window, next);
                }
            }
            (
                ServerInflight::ArchiveFetch { server_id, conv_key, group, bucket_more, mut rest, window, next },
                ServerResponse::ArchiveBatch { records, more },
            ) => {
                // Sayfa yeniden eskiye geliyor; devamı için son kaydın
                // damgasından geriye devam et. Bu olmadan bir kovadan
                // yalnızca ilk sayfa alınır ve daha eski mesajlar sunucuda
                // erişilemez kalırdı.
                // Cursor = the page's last record (server order: time, id desc).
                let oldest = records.last().map(|r| (r.sent_at_ms, r.record_id.clone()));
                self.merge_server_archive(&conv_key, group, bucket_more.as_deref().unwrap_or(""), records, window);
                // A press: this page went past the window's start, so this
                // bucket and the older ones hold nothing more of it.
                if let (Some((_, after)), Some((oldest_ms, _))) = (window, &oldest) {
                    if *oldest_ms < archive_wire_ms(after) {
                        return;
                    }
                }
                // The server went mid-chain: the next press asks for this window again.
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else {
                    if let Some((before, _)) = window { self.reopen_fetch_cursor(&conv_key, before) }
                    return;
                };
                if let (true, Some(bucket), Some(before)) = (more, bucket_more, oldest) {
                    self.send_archive_fetch(peer_id, server_id, conv_key, group, bucket, Some(before), rest, window, next);
                } else if !rest.is_empty() {
                    let bucket = rest.remove(0);
                    self.send_archive_fetch(peer_id, server_id, conv_key, group, bucket, None, rest, window, next);
                } else {
                    self.probe_next_conversation(peer_id, server_id, next);
                }
            }

            // --- Bloblar ---
            (ServerInflight::BlobPut { blob_id, chunk_index, total_chunks, server_id, sent_at }, ServerResponse::Ok) => {
                // Gidiş-dönüş ölçümü: bir aktarımın GECİKME sınırlı mı yoksa
                // BANT GENİŞLİĞİ sınırlı mı olduğunu ayırt etmenin tek yolu.
                // Gecikme sınırlıysa pencereyi büyütmek doğrudan hız verir;
                // bant genişliği sınırlıysa hiçbir şey vermez ve asıl çare
                // başka yerdedir (bkz. tek Tor devresi tavanı).
                let rtt = mono_ms().saturating_sub(sent_at);
                self.blob_rtt_sum += rtt;
                self.blob_rtt_count += 1;
                // Pencereyi SADECE kuyruk gecikmesi düşükken büyüt. Yol hızlı
                // olduğunda açılır, Tor gibi dar bir yolda kendiliğinden
                // durur — sabit bir derinlik ikisinden birinde hep yanlış.
                if let Some(u) = self.server_blob_uploads.iter_mut().find(|u| u.file_id == blob_id) {
                    u.rtt_min = u.rtt_min.min(rtt.max(BLOB_RTT_FLOOR_MS));
                    let queue_ok = rtt <= u.rtt_min.saturating_mul(BLOB_RTT_GROW_FACTOR);
                    if queue_ok && rtt < BLOB_RTT_CEILING_MS && u.window < BLOB_WINDOW_MAX {
                        u.window += 1;
                    }
                }
                if self.blob_rtt_count % 10 == 0 {
                    let (w, inflight) = self
                        .server_blob_uploads
                        .first()
                        .map(|u| (u.window, u.inflight.len()))
                        .unwrap_or((0, 0));
                    info!(
                        "Blob aktarımı: {} parça, ortalama gidiş-dönüş {} ms, pencere {}, havada {}",
                        self.blob_rtt_count,
                        self.blob_rtt_sum / self.blob_rtt_count,
                        w, inflight
                    );
                }
                self.advance_blob_upload(&blob_id, chunk_index, total_chunks, &server_id);
            }
            (ServerInflight::BlobFinish { blob_id, .. }, ServerResponse::Ok) => {
                self.forget_blob_upload(&blob_id);
            }
            (ServerInflight::BlobFinish { server_id, blob_id }, ServerResponse::Err(ServerErrorCode::BlobIncomplete)) => {
                self.restart_blob_upload(&blob_id, &server_id);
            }
            // A refused finish never succeeds with the same bytes: drop the
            // upload (the direct peer path still serves the file) so it does
            // not block the queue behind it.
            (ServerInflight::BlobFinish { blob_id, .. }, ServerResponse::Err(code))
                if !matches!(code, ServerErrorCode::NotEnrolled | ServerErrorCode::RateLimited | ServerErrorCode::Internal) =>
            {
                warn!("Sunucu blob'u kabul etmedi ({:?}), yükleme bırakıldı: {}", code, blob_id);
                self.finish_blob_upload(&blob_id);
            }

            // --- Hata ---
            (inflight, ServerResponse::Err(code)) => self.handle_server_error(inflight, code),

            // Beklenmeyen eşleşme — protokol uyumsuzluğu.
            // Treated as no answer: the request's own clean-up runs (a Fetch
            // left `fetch_inflight` set for good, an Ack lost its positions).
            (inflight, other) => {
                warn!("Sunucudan beklenmeyen yanıt: {:?} -> {:?}", std::mem::discriminant(&inflight), std::mem::discriminant(&other));
                self.handle_server_failure(inflight);
            }
        }
    }

    fn handle_server_error(&mut self, inflight: ServerInflight, code: ServerErrorCode) {
        let server_id = inflight.server_id().to_string();

        // Teslim garantisi düzeltmesi (defter #08): `fetch_inflight` yalnızca
        // BAŞARILI `Batch`'te, `handle_server_failure`'da ve aşağıdaki `other`
        // kolunda sıfırlanıyordu — `NotEnrolled`/`Revoked`/`UnknownMailbox`
        // kollarında değil. Bir `Fetch`'e `NotEnrolled` dönmesi (istemcinin
        // PeerId'si değiştiyse ya da başka bir cihaz rebind ettiyse gayet
        // olası) bayrağı KALICI olarak `true` bırakıyordu; `server_fetch` her
        // turda erken dönüyor ve yeniden kayıt başarılı olsa bile uygulama
        // yeniden başlatılana kadar sunucudan BİR DAHA HİÇ posta çekilmiyordu.
        // Koda bakmadan, inflight bir `Fetch` ise burada sıfırlanır.
        if matches!(inflight, ServerInflight::Fetch { .. }) {
            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                rt.fetch_inflight = false;
            }
        }

        // A refused Deposit is NOT on the server: take back the optimistic
        // "already deposited" mark, or every retry for the next 12 h counts it
        // as stored. Each arm below blocks this server for the envelope
        // (mailbox TTL, not enrolled, deposit backoff), so this cannot spin.
        if let ServerInflight::Deposit { dedup_key, .. } = &inflight {
            self.server_deposited.remove(&(server_id.clone(), dedup_key.clone()));
        }
        // A spent or expired token never works again. With it gone the next
        // round falls back to `Rebind`, or stops (see `server_sweep`).
        if matches!((&inflight, &code), (ServerInflight::Enroll { .. }, ServerErrorCode::BadInvite)) {
            if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                r.token.clear();
                let r = r.clone();
                self.persist_server(&r);
            }
        }
        // `Internal` is the server's own trouble (SQLite busy, disk): dropping
        // on it lost one queued archive record per sweep while it lasted.
        // A chunk over the blob quota gets the same answer every time: kept,
        // it was sent again every 5 minutes for good, in front of every later
        // upload, and stopped message deposits to the server each time.
        let permanent = !matches!(
            code,
            ServerErrorCode::NotEnrolled | ServerErrorCode::Revoked | ServerErrorCode::QuotaExceeded | ServerErrorCode::RateLimited | ServerErrorCode::Internal
        ) || matches!((&inflight, &code), (ServerInflight::BlobPut { .. }, ServerErrorCode::QuotaExceeded));
        if let ServerInflight::Register { .. } = &inflight {
            // Refused (too many mailboxes, a taken id): not again each sweep.
            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                rt.register_backoff_until = mono_ms() + SERVER_DEPOSIT_BACKOFF_MS;
            }
        }
        match &inflight {
            // The same chunk gets the same answer: give the upload up, the
            // direct peer path still serves the file.
            ServerInflight::BlobPut { blob_id, .. } if permanent => {
                warn!("Sunucu parçayı kabul etmedi ({:?}), yükleme bırakıldı: {}", code, blob_id);
                self.finish_blob_upload(blob_id);
            }
            // Drop the head record, or it blocks every record behind it.
            ServerInflight::ArchivePut { records, .. } if permanent => {
                warn!("Sunucu arşiv partisini kabul etmedi ({:?}), ilk kayıt bırakıldı", code);
                self.drop_archive_records(&records[..records.len().min(1)]);
            }
            // The server keeps the ids it took and names none: the refused
            // ones (over its cap, a full mailbox) would be sent again each
            // backoff, with the whole list, for good. Taken as done until the
            // next reconnect recomputes the set.
            ServerInflight::Register { ids, dropped, .. } if matches!(code, ServerErrorCode::QuotaExceeded) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.registered.extend(ids.iter().cloned());
                    for id in dropped {
                        rt.registered.remove(id);
                    }
                    rt.last_error = Some(format!("{TOO_MANY_MAILBOXES}: the server refused some, those chats use the direct path only"));
                }
            }
            // Positions the server did not take: again later, unless it will
            // never take them.
            ServerInflight::Ack { acks, .. } => {
                if permanent {
                    warn!("Sunucu Ack'i reddetti ({:?}), {} kutu", code, acks.len());
                } else {
                    self.restage_acks(&server_id, acks.clone());
                }
            }
            _ => {}
        }

        // As in `handle_server_failure`: the caller of a restore already got
        // "OK", and the rest of this conversation's buckets is not asked for.
        if let ServerInflight::ArchiveFetch { .. } | ServerInflight::ArchiveProbe { .. } = &inflight {
            warn!("Sunucu geçmiş isteğini reddetti ({:?}), geri yükleme eksik", code);
            self.reopen_fetch_window(&inflight);
            self.attachment_events.push(serde_json::json!({"type": "history_restore_incomplete"}).to_string());
        }

        match code {
            ServerErrorCode::UnknownMailbox => {
                warn!("Sunucu kutuyu tanımıyor (alıcı bu sunucuda değil)");
                if let ServerInflight::Deposit { mailbox, .. } = &inflight {
                    self.server_unknown_mailboxes
                        .insert((server_id.clone(), mailbox.clone()), mono_ms() + SERVER_UNKNOWN_MAILBOX_TTL_MS);
                }
                // Alıcı bu sunucuda yok — ANINDA P2P'ye (gossipsub) düş.
                //
                // Teslim garantisi düzeltmesi ("tek tarafta sunucu varsa
                // P2P'ye fallback olmalı"): burası eskiden `try_publish_raw`
                // çağırıyordu — yani KUYRUĞA ALMAYAN ham sürümü — ve dönüşü
                // de `let _ =` ile yutuluyordu. Yayın o an geçici olarak
                // başarısız olursa (mesh henüz kurulmamış, eş o saniyede
                // erişilemez) zarf HİÇBİR yere yazılmıyordu. `Message`
                // türleri `awaiting_confirmation` sayesinde kurtuluyordu ama
                // `Handshake`/`IdentityExchange` — ki bunlar tam da eşleşmenin
                // ve ilk temasın taşıyıcısı — SESSİZCE düşüyordu. Diğer bütün
                // hata kolları zaten `retry_deposit_over_gossipsub`
                // (`publish_envelope` → `pending_envelopes`) kullanıyordu;
                // tek istisna buydu.
                self.retry_deposit_over_gossipsub(&inflight);
            }
            ServerErrorCode::NotEnrolled => {
                // A new Hello at once only when this was not the enrollment
                // itself: Hello -> Welcome -> Rebind -> NotEnrolled ran at
                // round-trip speed, two signatures a round, past the backoff.
                let enrolling = matches!(inflight, ServerInflight::Hello { .. } | ServerInflight::Enroll { .. } | ServerInflight::Rebind { .. });
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = false;
                    if !enrolling {
                        rt.hello_sent_at = 0;
                    }
                }
                if !enrolling {
                    self.server_sweep_at = 0;
                }
                // The server does not know this enrollment (any more): the id
                // is useless, as in the Revoked arm.
                if matches!(inflight, ServerInflight::Rebind { .. }) {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.last_error = Some("The server does not know this enrollment. Add it again with a new invite code".to_string());
                    }
                    if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                        r.enrollment_id = None;
                        let r = r.clone();
                        self.persist_server(&r);
                    }
                }
                self.retry_deposit_over_gossipsub(&inflight);
            }
            ServerErrorCode::Revoked => {
                warn!("Sunucu kaydımızı iptal etti: {}", crate::log_id(&server_id));
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = false;
                    rt.last_error = Some("The operator revoked this enrollment".to_string());
                }
                // İptal edilmiş kimliği SAKLAMANIN faydası yok, zararı var:
                // elimizde kalırsa bir sonraki tur `Rebind` deneyip aynı
                // hatayı alır. Temizlersek, kullanıcı yeni bir davet kodu
                // yapıştırdığı anda (bkz. `add_server`) temiz bir `Enroll`
                // yapılabilir. Jeton kalmadıysa kendiliğinden bir şey
                // denenmez — hata mesajı durur, kullanıcı karar verir.
                if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                    if r.enrollment_id.is_some() {
                        r.enrollment_id = None;
                        let r = r.clone();
                        self.persist_server(&r);
                    }
                }
                self.retry_deposit_over_gossipsub(&inflight);
            }
            // A full mailbox (5000 undelivered items for a device that has
            // not fetched in a week — seen on device, 2026-09-26) must only
            // stop deposits to THAT mailbox. The server-wide backoff below
            // locked the whole account out of the server, call invites
            // included, for as long as the dead mailbox stayed full.
            // ponytail: QuotaExceeded also covers the per-account and disk
            // caps; for those this retries each mailbox once per backoff
            // instead of once per server — bounded by the mailbox count.
            ServerErrorCode::QuotaExceeded if matches!(inflight, ServerInflight::Deposit { .. }) => {
                if let ServerInflight::Deposit { mailbox, .. } = &inflight {
                    warn!("Sunucu kutusu dolu, bu kutuya yatırma {} sn durduruldu: {}", SERVER_DEPOSIT_BACKOFF_MS / 1000, mailbox_log_id(mailbox));
                    self.server_unknown_mailboxes
                        .insert((server_id.clone(), mailbox.clone()), mono_ms() + SERVER_DEPOSIT_BACKOFF_MS);
                }
                self.retry_deposit_over_gossipsub(&inflight);
            }
            other => {
                warn!("Sunucu hatası: {:?}", other);
                // Any refused Deposit backs off too: its mark is gone (see
                // top), so without this the retry would deposit again at once.
                // Deposits (and the blob chunks behind the same gate) only: a
                // refused Register or archive request stopped all message
                // deposits to the server for 5 minutes, again and again.
                let backs_off = matches!(inflight, ServerInflight::Deposit { .. })
                    || (matches!(other, ServerErrorCode::RateLimited)
                        && matches!(inflight, ServerInflight::BlobPut { .. } | ServerInflight::BlobFinish { .. }));
                let register_quota = matches!((&inflight, &other), (ServerInflight::Register { .. }, ServerErrorCode::QuotaExceeded));
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    // The Register arm above wrote a clearer one.
                    if !register_quota {
                        rt.last_error = Some(format!("{:?}", other));
                    }
                    rt.fetch_inflight = false;
                    // bkz. `SERVER_DEPOSIT_BACKOFF_MS`: kota/hız hatası
                    // "biraz sonra tekrar dene" demek, "saniyede bir tekrar
                    // dene" değil. Geri çekilme SADECE yatırmayı durdurur —
                    // `Fetch`/`Ack` çalışmaya devam eder, hatta kutuyu
                    // boşaltmak kotayı açan şeyin ta kendisidir.
                    if backs_off {
                        Self::back_off_deposits(rt);
                    }
                }
                // Kota/hız/boyut — hepsinde doğru davranış aynı: bu zarfı
                // gossipsub'a ver, mesajı kaybetme.
                self.retry_deposit_over_gossipsub(&inflight);
            }
        }
    }

    fn handle_server_failure(&mut self, inflight: ServerInflight) {
        if let ServerInflight::Hello { server_id } | ServerInflight::Fetch { server_id } = &inflight {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.hello_sent_at = 0;
                // Yanıt gelmediyse bayrağı BIRAKMAK çekmeyi sonsuza dek
                // kilitlerdi (bkz. `fetch_inflight`).
                rt.fetch_inflight = false;
                // A lost Fetch is tried again at the next sweep, not after
                // the rest of the 5-minute safety interval.
                if matches!(inflight, ServerInflight::Fetch { .. }) {
                    rt.fetch_due_at = 0;
                }
            }
        }
        if let ServerInflight::Ack { server_id, acks } = &inflight {
            self.restage_acks(server_id, acks.clone());
        }
        // Yatırma başarısızsa "zaten yatırıldı" işaretini geri al, yoksa
        // yeniden deneme yolu kapanırdı (bkz. `server_deposited`).
        if let ServerInflight::Deposit { server_id, dedup_key, .. } = &inflight {
            // Artık TÜRDEN BAĞIMSIZ (bkz. `deposit_dedup_key`) — önceden
            // yalnızca `Message` geri alınıyordu, ki zaten yalnızca `Message`
            // işaretleniyordu.
            self.server_deposited.remove(&(server_id.clone(), dedup_key.clone()));
            // No answer: without a backoff the retry below deposited again at
            // once (the server still counts as ready), every request timeout.
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                Self::back_off_deposits(rt);
            }
        }
        // The caller of a restore already got "OK": tell the UI it is partial.
        if let ServerInflight::ArchiveFetch { .. } | ServerInflight::ArchiveProbe { .. } = &inflight {
            warn!("Sunucu geçmiş isteği yanıtsız kaldı, geri yükleme eksik");
            self.reopen_fetch_window(&inflight);
            self.attachment_events.push(serde_json::json!({"type": "history_restore_incomplete"}).to_string());
        }
        self.retry_deposit_over_gossipsub(&inflight);
    }

    fn send_archive_fetch(
        &mut self,
        peer_id: PeerId,
        server_id: String,
        conv_key: String,
        group: bool,
        bucket: String,
        before: Option<(u64, String)>,
        rest: Vec<String>,
        window: Option<(u64, u64)>,
        next: Vec<(String, bool)>,
    ) {
        let req = ServerRequest::ArchiveFetch {
            bucket: bucket.clone(),
            before_ms: before.as_ref().map(|b| b.0),
            before_id: before.and_then(|b| (!b.1.is_empty()).then_some(b.1)),
            max_items: MAX_FETCH_BATCH_ITEMS,
            max_bytes: MAX_FETCH_BATCH_BYTES,
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(
                id,
                ServerInflight::ArchiveFetch { server_id, conv_key, group, bucket_more: Some(bucket), rest, window, next },
            );
        } else if let Some((before, _)) = window {
            self.reopen_fetch_cursor(&conv_key, before);
        }
    }

    /// A full restore walks its conversations one at a time: probing all at
    /// once was one 512 KiB chain per conversation on one Tor circuit.
    fn probe_next_conversation(&mut self, peer_id: PeerId, server_id: String, mut next: Vec<(String, bool)>) {
        let Some(ark) = self.archive_root_key else { return };
        if next.is_empty() {
            return;
        }
        let (conv_key, group) = next.remove(0);
        let req = ServerRequest::ArchiveProbe { buckets: archive_buckets(&ark, &conv_key, current_time_ms()) };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::ArchiveProbe { server_id, conv_key, group, window: None, next });
        }
    }

    /// Sunucuya bırakılamamış bir zarfı hemen gossipsub'a verir.
    fn retry_deposit_over_gossipsub(&mut self, inflight: &ServerInflight) {
        if let ServerInflight::Deposit { envelope, target_fp, first_attempt_at, cancelled, .. } = inflight {
            // Withdrawn by the user, or confirmed meanwhile: nothing to resend.
            if *cancelled {
                return;
            }
            let envelope = envelope.clone();
            let target_fp = target_fp.clone();
            // `publish_envelope` DEĞİL: o, girdiyi `current_time_ms()` ile
            // kuyruğa ekler ve zarfın yaşlanma sayacını her sunucu
            // gidiş-dönüşünde sıfırlardı — bkz. `ServerInflight::Deposit`
            // `first_attempt_at` notu (sonsuz kuyruk döngüsünün ikinci
            // yarısı).
            if let Err(e) = self.publish_envelope_at(&target_fp, &envelope, *first_attempt_at) {
                warn!("Sunucu başarısız oldu, gossipsub da hemen başaramadı (kuyruğa alındı): {}", e);
            }
        }
        if let ServerInflight::BlobPut { blob_id, chunk_index, server_id, .. } = inflight {
            // Havadan düş — bir sonraki turda yeniden istenir.
            if let Some(up) = self.server_blob_uploads.iter_mut().find(|u| u.file_id == *blob_id) {
                up.inflight.remove(chunk_index);
                // Zaman aşımı/hata = yolu fazla doldurduk. Pencereyi YARIYA
                // indir; yeniden denemeler bant genişliğini yiyip hızı daha da
                // düşürmeden önce geri çekilmek şart (ölçüldü: sabit 16'lık
                // pencerede hız 180 KB/s'den ~50 KB/s'ye düşüyordu).
                up.window = (up.window / 2).max(BLOB_WINDOW_MIN);
                warn!("Parça zaman aşımı/hatası — pencere {} yapıldı", up.window);
            }
            // Paralel devrelerden biri ölmüş olabilir; ölü bağlantı
            // isteklerin 1/N'ini yutar. Tek olayda karar VERME — Tor'da tek
            // zaman aşımı gürültüdür (bkz. `note_bulk_timeout`).
            // Only the server this chunk went to: the others are fine.
            if let Some(p) = self.server_rt.get(server_id).and_then(|r| r.peer_id) {
                self.note_bulk_timeout(p);
            }
        }
    }

    fn begin_enrollment(&mut self, server_id: &str, challenge: &[u8]) {
        let Some(rec) = self.servers.iter().find(|s| s.server_id == server_id).cloned() else { return };
        let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id) else { return };
        let Ok(sk_bytes): Result<[u8; 32], _> = rec.enroll_sk.as_slice().try_into() else {
            error!("Sunucu kayıt anahtarı bozuk: {}", crate::log_id(&server_id));
            return;
        };
        let signing = SigningKey::from_bytes(&sk_bytes);
        let Ok(seed): Result<ml_dsa::Seed, _> = rec.enroll_sk_pq.as_slice().try_into() else {
            // Sunucu desteği eklenmeden önce kaydedilmiş bir satır olabilir
            // (bkz. `enroll_sk_pq` geçişi). Kullanıcı sunucuyu yeni bir
            // davet koduyla eklemeli — sessizce klasik imzaya DÜŞMÜYORUZ.
            error!("Sunucu kayıt anahtarının PQ bileşeni yok: {}", crate::log_id(&server_id));
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error =
                    Some("Kayıt anahtarı eski biçimde — sunucuyu yeni bir davet koduyla ekleyin".to_string());
            }
            return;
        };
        let signing_pq = MlDsaSigningKey::<MlDsa87>::from_seed(&seed);
        let ts_ms = current_time_ms();
        let Some(me) = self.swarm.as_ref().map(|s| s.local_peer_id().to_string()) else { return };

        // Zaten kayıtlıysak (uygulama yeniden kuruldu, libp2p kimliği
        // değişti) davet jetonu TÜKETMEDEN yeniden bağlan.
        // A token wins over the stored id: the user pasted it to enroll anew.
        // If the server refuses it, it is cleared and this falls to `Rebind`.
        if let Some(enrollment_id) = rec.enrollment_id.clone().filter(|_| rec.token.is_empty()) {
            let input = server_proto::rebind_signing_input(&enrollment_id, server_id, &me, challenge, ts_ms);
            let sig = signing.sign(&input).to_bytes().to_vec();
            let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
            let req = ServerRequest::Rebind {
                enrollment_id,
                ts_ms,
                sig,
                sig_pq: sig_pq.encode().to_vec(),
            };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(id, ServerInflight::Rebind { server_id: server_id.to_string() });
            }
            return;
        }

        if rec.token.is_empty() {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error = Some("No invite token. Add the server again with a new code".to_string());
            }
            return;
        }
        let Ok(token_bytes) = hex::decode(&rec.token) else {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error = Some("The invite token is damaged".to_string());
            }
            return;
        };
        let enroll_pk = signing.verifying_key().to_bytes().to_vec();
        let enroll_pk_pq = signing_pq.verifying_key().encode().to_vec();
        let input = server_proto::enroll_signing_input(
            SERVER_PROTOCOL_VERSION,
            server_id,
            &me,
            &token_bytes,
            &enroll_pk,
            &enroll_pk_pq,
            challenge,
            ts_ms,
        );
        let sig = signing.sign(&input).to_bytes().to_vec();
        let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
        let req = ServerRequest::Enroll {
            version: SERVER_PROTOCOL_VERSION,
            invite_token: token_bytes,
            enroll_pk,
            enroll_pk_pq,
            ts_ms,
            sig,
            sig_pq: sig_pq.encode().to_vec(),
            challenge: challenge.to_vec(),
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::Enroll { server_id: server_id.to_string() });
        }
    }

    /// Bir sunucuya bağlanıldığında/koptuğunda `poll_events` çağırır.
    pub(crate) fn note_server_connection(&mut self, peer: PeerId, connected: bool) {
        let sid = self
            .server_rt
            .iter()
            .find(|(_, rt)| rt.peer_id == Some(peer))
            .map(|(sid, _)| sid.clone());
        let Some(sid) = sid else { return };
        if let Some(rt) = self.server_rt.get_mut(&sid) {
            rt.connected = connected;
            if connected {
                rt.dial_attempts = 0;
                rt.dial_backoff_until = 0;
                // Timeouts of a lost connection grew the deposit backoff.
                rt.deposit_failures = 0;
                rt.deposit_backoff_until = 0;
                // Yeniden bağlanmada abonelikler sunucuda hâlâ duruyor ama
                // bizim görüşümüz bayat olabilir — sıfırla, fark yeniden
                // hesaplansın.
                rt.registered.clear();
                rt.fetch_due_at = 0;
                rt.hello_sent_at = 0;
            } else {
                rt.enrolled = false;
            }
        }
        self.server_sweep_at = 0;
    }

    /// Bu `PeerId` yapılandırılmış bir sunucuya mı ait?
    pub(crate) fn is_server_peer(&self, peer: &PeerId) -> bool {
        self.server_rt.values().any(|rt| rt.peer_id.as_ref() == Some(peer))
    }

    /// YAPILANDIRILMIŞ her sunucunun `PeerId`'si (kayıtlı olsun olmasın) —
    /// bkz. `poll_events` keepalive filtresi.
    pub(crate) fn server_peer_ids(&self) -> Vec<PeerId> {
        self.server_rt.values().filter_map(|rt| rt.peer_id).collect()
    }

    /// Bağlı ve kayıtlı sunucuların `PeerId`'leri — dosya indirmede
    /// alternatif kaynak olarak eklenir.
    pub(crate) fn ready_server_peers(&self) -> Vec<PeerId> {
        self.servers
            .iter()
            .filter_map(|s| {
                let rt = self.server_rt.get(&s.server_id)?;
                if rt.connected && rt.enrolled {
                    rt.peer_id
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Arşiv (geçmiş) — yükleme, çekme, birleştirme
// ---------------------------------------------------------------------------
//
// Neden posta kutusu zarfları geçmiş olarak KULLANILAMAZ: ratchet mesaj
// anahtarları ileri-gizli ve kullanıldıktan sonra siliniyor; atlanmış
// anahtarlar da sınırlı (`MAX_SKIPPED_KEYS`) ve rotasyonda temizleniyor.
// Yani geçen haftanın zarfı bugün HİÇ KİMSE tarafından — hedef alıcı dahil —
// çözülemez, yeni bağlanmış bir cihaz ise o anahtarlara hiç sahip olmadı.
// Geçmiş bu yüzden AYRI ve uzun ömürlü bir anahtarla yeniden şifreleniyor.

impl P2PCore {
    /// Kök arşiv anahtarını (ARK) yükler.
    ///
    /// `history_key` ile karıştırılmamalı: o CİHAZA özel, rastgele ve
    /// kurtarma dosyasında YOK — sadece yerel arşivi diskte şifreliyor. ARK
    /// ise KİMLİĞE ait: aynı kimliğin bütün cihazları okuyabilmeli, bu yüzden
    /// `SyncPayload` ile kardeş cihazlara ve kurtarma dosyasına da girer.
    pub(crate) fn set_archive_root_key(&mut self, key: &[u8]) -> bool {
        let Ok(k) = <[u8; 32]>::try_from(key) else { return false };
        self.archive_root_key = Some(k);
        self.reconcile_archive_key(true);
        self.server_sweep_at = 0; // H56: backfill runs in slices from the sweep
        true
    }

    /// L-137: history written while a history server was set but no archive
    /// key was loaded was never queued; queue it once the key is here.
    /// One slice (200 rows) per sweep; the `ark_backfill` marker holds
    /// "<next id bound>,<rows done>" ("1" = not started), 2000 rows in all.
    pub(crate) fn maybe_archive_backfill(&mut self) {
        const SLICE: i64 = 200;
        const TOTAL: i64 = 2000;
        if self.archive_root_key.is_none() || !self.servers.iter().any(|s| s.store_history) {
            return;
        }
        let Some(marker) = self.meta_str("ark_backfill") else { return };
        let (mut bound, mut done) = marker
            .split_once(',')
            .and_then(|(b, d)| Some((b.parse::<i64>().ok()?, d.parse::<i64>().ok()?)))
            .unwrap_or((i64::MAX, 0));
        let Some(conn) = &self.db else { return };
        let Ok(mut stmt) = conn.prepare(
            "SELECT id, message_id, group_id, peer_device_fingerprint FROM messages \
             WHERE message_id IS NOT NULL AND id < ?1 ORDER BY id DESC LIMIT ?2",
        ) else { return };
        let rows: Vec<(i64, String, Option<String>, String)> = stmt
            .query_map(params![bound, SLICE.min(TOTAL - done)], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map(|it| it.flatten().collect())
            .unwrap_or_default();
        drop(stmt);
        let n = rows.len() as i64;
        for (id, mid, gid, fp) in rows {
            bound = id;
            self.requeue_archive_row(gid.as_deref(), &fp, &mid);
        }
        done += n;
        if n < SLICE || done >= TOTAL {
            self.meta_del("ark_backfill");
        } else {
            self.meta_put("ark_backfill", &format!("{bound},{done}"));
            self.server_sweep_at = 0;
        }
    }

    pub(crate) fn archive_root_key_bytes(&self) -> Option<Vec<u8>> {
        self.archive_root_key.map(|k| k.to_vec())
    }

    // The archive key state the core keeps in `app_meta` (hex strings):
    //   ark          the key in force, when the core changed it itself. It
    //                wins over the client's key file until the client loads
    //                the same key, which proves the file was written.
    //   ark_retired  SHA-256 of every replaced key (64 hex each): never taken again.
    //   ark_todo     a rotation whose sync to siblings and backfill are not done.
    //   ark_purge    replaced keys (comma list) whose buckets are still on the server.

    /// The key the core changed itself (rotation, sibling sync) wins over the
    /// one the client loaded: the client stores it on an event that can be lost.
    fn reconcile_archive_key(&mut self, from_client: bool) {
        let Some(stored) =
            self.meta_str("ark").and_then(|h| hex::decode(h).ok()).and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return;
        };
        if self.archive_root_key == Some(stored) {
            if from_client {
                self.meta_del("ark");
            }
            return;
        }
        self.archive_root_key = Some(stored);
        // The client stores the key on this event.
        self.attachment_events.push(serde_json::json!({"type": "sync"}).to_string());
    }

    fn archive_key_retired(&self, key: &[u8; 32]) -> bool {
        let hash = hex::encode(Sha256::digest(key));
        self.meta_str("ark_retired").map_or(false, |r| r.as_bytes().chunks(64).any(|c| c == hash.as_bytes()))
    }

    /// Stores a key change in one statement: a crash leaves all of it or none.
    /// `rotation`: this device made the new key: it also syncs and backfills.
    fn persist_archive_key_change(&self, new: &[u8; 32], old: Option<&[u8; 32]>, rotation: bool) {
        let Some(conn) = &self.db else { return };
        let mut retired = self.meta_str("ark_retired").unwrap_or_default();
        let mut purge = self.meta_str("ark_purge").unwrap_or_default();
        if let Some(old) = old {
            retired.push_str(&hex::encode(Sha256::digest(old)));
            if !purge.is_empty() {
                purge.push(',');
            }
            purge.push_str(&hex::encode(old));
        }
        // The old buckets are purged by every device that replaces a key; only
        // the device that rotated syncs and backfills (`ark_todo`).
        let todo = if rotation { ", ('ark_todo', '1')" } else { "" };
        let head = "INSERT OR REPLACE INTO app_meta (k, v) VALUES ('ark', ?1), ('ark_retired', ?2)";
        let result = if purge.is_empty() {
            conn.execute(&format!("{head}{todo}"), params![hex::encode(new), retired])
        } else {
            conn.execute(&format!("{head}, ('ark_purge', ?3){todo}"), params![hex::encode(new), retired, purge])
        };
        if let Err(e) = result {
            error!("Arşiv anahtarı değişikliği yazılamadı: {}", e);
        }
    }

    /// A revoked device holds the key. The new key is on disk before anything
    /// is sent; the rest (sync, backfill, purge of the old buckets) is resumed
    /// from `app_meta` after a crash or without network.
    pub(crate) fn rotate_archive_root_key(&mut self) {
        use rand::RngCore;
        let Some(old) = self.archive_root_key else { return };
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        self.persist_archive_key_change(&key, Some(&old), true);
        self.archive_root_key = Some(key);
        self.attachment_events.push(serde_json::json!({"type": "sync"}).to_string());
        self.resume_archive_rotation();
    }

    /// Step 2 of a rotation: the new key to the remaining own devices, and
    /// the newest local rows queued again, to be sealed under the new key.
    fn resume_archive_rotation(&mut self) {
        if self.meta_str("ark_todo").is_none() {
            return;
        }
        self.sync_to_siblings();
        if self.servers.iter().any(|s| s.store_history) {
            self.backfill_server_archive();
        }
        self.meta_del("ark_todo");
    }

    /// Step 3 of a rotation: deletes what the server holds under replaced
    /// keys. Runs each sweep until the server confirmed every bucket.
    // ponytail: the buckets of the last 36 months, as `purge_server_archive`.
    fn purge_retired_archive(&mut self, server_id: &str, peer_id: PeerId) {
        let Some(keys) = self.meta_str("ark_purge") else { return };
        let now = current_time_ms();
        if self.server_rt.get(server_id).map_or(false, |r| mono_ms() < r.purge_retry_at)
            || self.server_inflight.values().any(|i| matches!(i, ServerInflight::ArchivePurge { .. }))
        {
            return;
        }
        // No answer or an error: again after this, not each sweep.
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.purge_retry_at = mono_ms() + SERVER_DEPOSIT_BACKOFF_MS;
        }
        let conv_keys = self.archive_conv_keys();
        let mut rest = Vec::new();
        for h in keys.split(',') {
            let Some(old) = hex::decode(h).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else { continue };
            for c in &conv_keys {
                rest.extend(archive_buckets(&old, c, now));
            }
        }
        self.send_archive_purge(peer_id, server_id.to_string(), keys, rest);
    }

    /// One chunk at a time; with nothing left the replaced keys are dropped.
    fn send_archive_purge(&mut self, peer_id: PeerId, server_id: String, keys: String, mut rest: Vec<String>) {
        if rest.is_empty() {
            // A rotation since this run started added a key: the next sweep
            // purges again.
            if self.meta_str("ark_purge").as_deref() == Some(keys.as_str()) {
                self.meta_del("ark_purge");
            }
            return;
        }
        // 500: the server refuses a list longer than its 512 mailbox cap.
        let cap = self.server_rt.get(&server_id).map_or(1, Self::mailbox_cap).min(500);
        let tail = rest.split_off(rest.len().min(cap));
        let req = ServerRequest::ArchivePurge { buckets: rest };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::ArchivePurge { server_id, keys, rest: tail });
        }
    }

    /// Takes the key a sibling sent. Only the primary device revokes, so only
    /// its key replaces one we hold. A replaced key is never taken again: an
    /// older sync can arrive after a newer one. True when the key changed.
    pub(crate) fn adopt_archive_key(&mut self, key: &[u8], from_primary: bool) -> bool {
        let Ok(key) = <[u8; 32]>::try_from(key) else { return false };
        let old = self.archive_root_key;
        if old == Some(key) || (old.is_some() && !from_primary) || self.archive_key_retired(&key) {
            return false;
        }
        self.persist_archive_key_change(&key, old.as_ref(), false);
        self.archive_root_key = Some(key);
        self.server_sweep_at = 0; // H56: backfill runs in slices from the sweep
        true
    }

    /// Records `rev` as seen for this record. False when a higher revision
    /// was seen before: the record is a rollback and must not be merged.
    // ponytail: one row for each archived message, pruned only with the last
    // server (`remove_server`); bounded like the history itself.
    fn note_archive_rev(&self, conv_key: &str, record_id: &str, rev: u64) -> bool {
        let Some(conn) = &self.db else { return true };
        let rev = rev.min(i64::MAX as u64) as i64;
        let known: i64 = conn
            .query_row(
                "SELECT rev FROM server_archive_revs WHERE conv_key = ?1 AND record_id = ?2",
                params![conv_key, record_id],
                |r| r.get(0),
            )
            .unwrap_or(-1);
        if rev < known {
            return false;
        }
        if rev > known {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_archive_revs (conv_key, record_id, rev) VALUES (?1, ?2, ?3)",
                params![conv_key, record_id, rev],
            );
        }
        true
    }

    /// Sunucuda geçmiş saklama açık mı?
    fn history_server(&self) -> Option<String> {
        self.servers
            .iter()
            .find(|s| {
                s.store_history
                    && self.server_rt.get(&s.server_id).map(|r| r.connected && r.enrolled).unwrap_or(false)
            })
            .map(|s| s.server_id.clone())
    }

    /// Yerel arşive bir satır yazıldığında çağrılır — aynı satırı sunucuya
    /// da yüklemek üzere kuyruğa alır.
    ///
    /// `rev`: düzenleme/silme AYNI `record_id` ile daha yüksek bir revizyon
    /// yükler ve sunucu eskisinin üzerine yazar. Mevcut
    /// `HistorySyncResponse` mekanizmasının yapamadığı şey tam olarak budur
    /// (geç gelen bir Edit'i geçmişte düzeltmek).
    pub(crate) fn queue_archive_record(
        &mut self,
        conv_key: &str,
        record_id: &str,
        rev: u64,
        sent_at_ms: u64,
        plaintext: Vec<u8>,
    ) {
        // Hiç sunucu yoksa/geçmiş saklama kapalıysa kuyruğa hiç girmesin —
        // aksi halde kapalı bir özellik sessizce disk büyütürdü.
        if !self.servers.iter().any(|s| s.store_history) {
            return;
        }
        if self.archive_root_key.is_none() {
            // L-137: queued once the key arrives (`maybe_archive_backfill`).
            if self.meta_str("ark_backfill").is_none() {
                self.meta_put("ark_backfill", "1");
            }
            return;
        }
        // The server must not hand back an older revision than this one.
        self.note_archive_rev(conv_key, record_id, rev);
        let entry = PendingArchive {
            conv_key: conv_key.to_string(),
            record_id: record_id.to_string(),
            rev,
            // The bucket comes from this: a peer's clock far ahead put the
            // record where no probe or purge looks.
            sent_at_ms: sent_at_ms.min(current_time_ms()),
            plaintext,
        };
        // Defter #10: bu kolon eskiden mesaj gövdesini DÜZ METİN yazıyordu —
        // `messages` tablosundaki her gövde `history_key` ile şifreliyken,
        // yereldeki "dinlenme hâlinde şifreleme" tam da bu tablo için
        // baypas ediliyordu. Kuyruk normalde hızla boşalıyor, ama
        // `remove_server` sonrası (artık `store_history` açık bağlı sunucu
        // yok) satırlar SÜRESİZ olarak diskte düz metin kalıyordu.
        // `seal_local_blob` yoksa (anahtar henüz yüklenmedi) satır hiç
        // yazılmaz — bellekteki kopya yine de bu turda gönderilir.
        if let Some(conn) = &self.db {
            let _ = conn.execute("INSERT OR IGNORE INTO server_archived_convs (conv_key) VALUES (?1)", params![entry.conv_key]);
        }
        let stored = self.seal_local_blob(&entry.plaintext);
        if let (Some(conn), Some(blob)) = (&self.db, stored) {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_archive_queue (record_id, conv_key, rev, sent_at_ms, plaintext, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![entry.record_id, entry.conv_key, entry.rev as i64, entry.sent_at_ms as i64, blob, current_time_ms() as i64],
            );
        }
        // Aynı kaydın eski revizyonu kuyrukta bekliyorsa onu değiştir.
        if let Some(existing) = self.server_archive_queue.iter_mut().find(|e| e.record_id == entry.record_id) {
            *existing = entry;
        } else {
            self.server_archive_queue.push(entry);
            // History server down for long: the queue does not grow without end.
            let over = self.server_archive_queue.len().saturating_sub(MAX_SERVER_ARCHIVE_QUEUE);
            if over > 0 {
                warn!("Arşiv kuyruğu dolu, en eski {} kayıt sunucuya gitmeyecek", over);
                self.drop_archive_queue_head(over);
            }
        }
    }

    /// Kuyruktaki arşiv kayıtlarını partiler hâlinde yükler.
    fn server_flush_archive(&mut self, server_id: &str, peer_id: PeerId) {
        if self.server_archive_queue.is_empty() {
            return;
        }
        let Some(ark) = self.archive_root_key else { return };
        // Quota/rate error: wait like `Deposit` does, not once per sweep.
        if self.server_rt.get(server_id).map_or(false, |r| mono_ms() < r.deposit_backoff_until) {
            return;
        }
        // Havada zaten bir ArchivePut varsa bekle — sıralı gitmesi, sunucu
        // tarafındaki `rev` karşılaştırmasını öngörülebilir kılıyor.
        if self.server_inflight.values().any(|i| matches!(i, ServerInflight::ArchivePut { .. })) {
            return;
        }

        // Tek bir istek TEK bir kovaya gider (kova = sohbet + dönem), bu
        // yüzden kuyruğun başındaki kaydın kovasıyla eşleşenleri topluyoruz.
        let head = self.server_archive_queue[0].clone();
        let epoch = server_seal::archive_epoch_for(head.sent_at_ms);
        let Ok(bucket) = server_seal::server_archive_bucket(&ark, &head.conv_key, epoch) else { return };

        let mut records = Vec::new();
        let mut consumed = 0usize;
        let mut sealed_bytes = 0usize;
        // Half the wire cap: an oversized request fails as a whole and would
        // be re-sent unchanged.
        let budget = MAX_DEPOSIT_BYTES / 2;
        for entry in self.server_archive_queue.iter() {
            if records.len() >= SERVER_ARCHIVE_BATCH {
                break;
            }
            if entry.conv_key != head.conv_key || server_seal::archive_epoch_for(entry.sent_at_ms) != epoch {
                // Farklı kova — bu parti burada biter (kuyruk sırası korunur).
                break;
            }
            // The server sees an id that only this identity can link to the
            // message; the real id travels inside the sealed record.
            let wire_id = archive_wire_id(&ark, &entry.conv_key, &entry.record_id);
            match server_seal::seal_archive_record(
                &ark,
                &entry.conv_key,
                &wire_id,
                entry.rev,
                &bucket,
                archive_wire_ms(entry.sent_at_ms),
                &entry.plaintext,
            ) {
                // A record that alone breaks the budget never goes: it leaves
                // with this batch (counted in `consumed`) and is dropped.
                Ok(sealed) if sealed.len() > budget => {
                    warn!("Arşiv kaydı sunucu için çok büyük, atlandı: {} bayt", sealed.len());
                }
                // Checked with this record in: the next batch starts with it.
                Ok(sealed) if sealed_bytes + sealed.len() > budget => break,
                Ok(sealed) => {
                    sealed_bytes += sealed.len();
                    records.push(ArchiveRecord {
                        record_id: wire_id,
                        rev: entry.rev,
                        sent_at_ms: archive_wire_ms(entry.sent_at_ms),
                        sealed,
                    })
                }
                Err(e) => {
                    warn!("Arşiv kaydı mühürlenemedi: {}", e);
                }
            }
            consumed += 1;
        }
        if records.is_empty() {
            // Mühürleme hepsinde başarısız oldu — kuyruğu tıkamasın.
            self.drop_archive_queue_head(consumed.max(1));
            return;
        }
        // Every consumed entry, the unsealable ones too: they leave with the batch.
        let sent: Vec<(String, u64)> =
            self.server_archive_queue[..consumed].iter().map(|e| (e.record_id.clone(), e.rev)).collect();
        let req = ServerRequest::ArchivePut { bucket, records };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight
                .insert(id, ServerInflight::ArchivePut { server_id: server_id.to_string(), records: sent });
        }
    }

    /// Removes exactly these `(record_id, rev)` entries. An entry edited while
    /// its batch was in flight carries a newer `rev` and stays queued.
    fn drop_archive_records(&mut self, records: &[(String, u64)]) {
        for (record_id, rev) in records {
            self.server_archive_queue.retain(|e| !(e.record_id == *record_id && e.rev == *rev));
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "DELETE FROM server_archive_queue WHERE record_id = ?1 AND rev = ?2",
                    params![record_id, *rev as i64],
                );
            }
        }
    }

    fn drop_archive_queue_head(&mut self, count: usize) {
        let n = count.min(self.server_archive_queue.len());
        for entry in self.server_archive_queue.drain(..n) {
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "DELETE FROM server_archive_queue WHERE record_id = ?1",
                    params![entry.record_id],
                );
            }
        }
    }

    /// "Yukarı kaydırdım, daha eskisini göster" için sunucuya sorar.
    ///
    /// Mevcut çok-kaynaklı tasarımın ÜÇÜNCÜ kaynağı: `request_older_history`
    /// karşı tarafa, `request_older_sibling_history` kendi diğer cihazıma
    /// soruyor; bu da sunucuya soruyor. Üçü paralel gider, yanıtlar
    /// `message_id` bazında dedup edilir, hangisi önce dönerse boşluğu o
    /// doldurur.
    ///
    /// The window `[after, before)` of a "Fetch older history" press: every
    /// page of it, from the buckets that reach it. A full restore of the
    /// same conversation may run beside it; it respects the history floor,
    /// this chain does not, inside its window.
    /// Returns whether the request went out.
    fn request_older_server_history(&mut self, conv_key: &str, group: bool, before: u64, after: u64) -> bool {
        let Some(ark) = self.archive_root_key else { return false };
        let Some(server_id) = self.history_server() else { return false };
        let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { return false };
        // Aylık kovalar (bkz. `server_archive_bucket`): `before`'ın ayı ve öncesi.
        let buckets = archive_buckets(&ark, conv_key, before);
        let req = ServerRequest::ArchiveProbe { buckets };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(
                id,
                ServerInflight::ArchiveProbe {
                    server_id,
                    conv_key: conv_key.to_string(),
                    group,
                    window: Some((before, after)),
                    next: Vec::new(),
                },
            );
            return true;
        }
        false
    }

    /// A press's server chain failed: the cursor goes back up to its window's
    /// end, so the next press asks every source for that window again (rows
    /// dedup by id) instead of skipping the server's part of it for good.
    fn reopen_fetch_window(&self, inflight: &ServerInflight) {
        if let ServerInflight::ArchiveProbe { conv_key, window: Some((before, _)), .. }
        | ServerInflight::ArchiveFetch { conv_key, window: Some((before, _)), .. } = inflight
        {
            self.reopen_fetch_cursor(conv_key, *before);
        }
    }

    /// Drops the running "Fetch older history" chains of a conversation
    /// (`forget_history_fetch`): their late pages are then unexpected and
    /// dropped. A full restore chain stays; it respects the history floor.
    pub(crate) fn drop_archive_page_chains(&mut self, conv_key: &str) {
        self.server_inflight.retain(|_, f| !matches!(f,
            ServerInflight::ArchiveProbe { conv_key: c, window: Some(_), .. }
            | ServerInflight::ArchiveFetch { conv_key: c, window: Some(_), .. } if c == conv_key));
    }

    /// The single "fetch older history" action, on a user action only:
    /// scrolling up reads the local archive and never comes here. One press
    /// asks every source (the chat peer(s), the own connected devices, the
    /// server archive when a history server and the archive key exist) for
    /// the same window: one `HISTORY_FETCH_WINDOW_MS` older than the chat's
    /// cursor (`history_fetch_cursor`), which then moves to the window's
    /// start. The cursor never comes from the rows that arrive, so an empty
    /// month still moves it and a backdated row cannot pin it. `chat_key`:
    /// the peer device fingerprint, or the group id. `_before_ms` (the
    /// oldest row on screen) is not used: the cursor is kept here.
    pub(crate) fn fetch_server_history(&mut self, chat_key: &str, is_group: bool, _before_ms: u64) -> Result<(), String> {
        let conv_key = if is_group {
            if !self.groups.contains_key(chat_key) {
                return Err("Grup bulunamadı".to_string());
            }
            chat_key.to_string()
        } else {
            self.identity_id_for_device(chat_key).ok_or("Bu cihazın kimliği bilinmiyor")?
        };
        let before = if is_group {
            self.history_fetch_cursor(&conv_key, "", Some(chat_key))
        } else {
            self.history_fetch_cursor(&conv_key, &self.canonical_peer_key(chat_key), None)
        };
        let after = before.saturating_sub(crate::HISTORY_FETCH_WINDOW_MS);
        // Budget before the requests: a fast answer may already want a follow-up.
        self.history_fetch_pages.insert(conv_key.clone(), crate::HISTORY_FETCH_MAX_PAGES);
        let (b, a) = (before as i64, after as i64);
        // One unreachable source is not an error: the others remain.
        let sent = if is_group {
            let peers = self.request_older_group_history(chat_key, b, a).is_ok();
            self.request_older_sibling_history(None, Some(chat_key), b, a, None).is_ok() | peers
        } else {
            let peer = self.request_older_history(chat_key, b, a).is_ok();
            self.request_older_sibling_history(Some(&conv_key), None, b, a, None).is_ok() | peer
        };
        // Returns false at once without the archive key or a history server.
        let sent = self.request_older_server_history(&conv_key, is_group, before, after) | sent;
        if !sent {
            // Nothing went out: the month stays for the next press.
            self.history_fetch_pages.remove(&conv_key);
            return Err("Geçmiş istenecek kaynağa ulaşılamıyor".to_string());
        }
        self.meta_put(&format!("hfetch:{}", conv_key), &after.to_string());
        Ok(())
    }

    /// Sunucudaki BÜTÜN arşivi indirir — sıfırdan kurulmuş/kurtarılmış bir
    /// cihaz için.
    ///
    /// Neden ayrı bir akış: `request_older_server_history` "bu sohbette
    /// yukarı kaydırdım" durumunu karşılıyor, yani sohbetin zaten görünür
    /// olmasını varsayıyor. Kurtarma dosyasından kurulan bir cihazda ise
    /// kişiler/gruplar geri gelir ama HİÇBİR mesaj yoktur ve kullanıcının
    /// kaydıracağı bir şey de yoktur. Bu fonksiyon, bilinen her sohbetin son
    /// 36 ayının kovalarını TEK bir `ArchiveProbe` ile yoklayıp dolu olanları
    /// çeker.
    ///
    /// `ListArchiveConversations` KASITLI olarak kullanılmıyor: sunucunun
    /// bize sohbet listemizi söylemesi, sunucunun kalıcı bir sohbet dizini
    /// tutması demek olurdu. Kovaları kendimiz üretebiliyoruz, üstelik
    /// var olmayan bir kovayı yoklamak sunucuda no-op.
    pub(crate) fn restore_all_server_history(&mut self) -> Result<u32, String> {
        if self.archive_root_key.is_none() {
            return Err("Kök arşiv anahtarı yok — bu cihaz sunucudaki geçmişi çözemez".to_string());
        }
        let Some(server_id) = self.history_server() else {
            return Err("Geçmiş saklayan, bağlı bir sunucu yok".to_string());
        };
        let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else {
            return Err("Sunucuya bağlı değil".to_string());
        };

        let mut convs: Vec<(String, bool)> = self.groups.keys().map(|g| (g.clone(), true)).collect();
        convs.extend(self.contacts.values().map(|c| (c.trusted_identity_id.clone(), false)));
        if convs.is_empty() {
            return Ok(0);
        }

        let asked = convs.len() as u32;
        self.probe_next_conversation(peer_id, server_id, convs);
        Ok(asked)
    }

    /// Sunucudan gelen arşiv sayfasını YEREL arşive birleştirir.
    ///
    /// Mevcut `HistorySyncResponse` birleştirme kuralının aynısı:
    /// `message_id` bazlı var-olma kontrolü (zaman damgası eşiği DEĞİL —
    /// sayfalama isteklerinde o yanlış yönde çalışır).
    /// `window`: a page of the user's "Fetch older history" press
    /// `(before, after)`. Only its rows sent inside the window are kept; they
    /// may come back below the history floor, which then goes down to the
    /// oldest row written.
    fn merge_server_archive(&mut self, conv_key: &str, group: bool, bucket: &str, records: Vec<ArchiveRecord>, window: Option<(u64, u64)>) {
        let Some(ark) = self.archive_root_key else { return };
        let mut merged = 0usize;
        let mut opened: Vec<(ArchiveRecord, crate::ArchivedMessage)> = Vec::new();
        for rec in records {
            let plaintext = match server_seal::open_archive_record(
                &ark,
                conv_key,
                &rec.record_id,
                rec.rev,
                bucket,
                rec.sent_at_ms,
                &rec.sealed,
            ) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Sunucu arşiv kaydı çözülemedi: {}", e);
                    continue;
                }
            };
            let archived: crate::ArchivedMessage = match ciborium::from_reader(plaintext.as_slice()) {
                Ok(a) => a,
                Err(e) => {
                    warn!("Sunucu arşiv kaydı ayrıştırılamadı: {}", e);
                    continue;
                }
            };
            opened.push((rec, archived));
        }
        // A press keeps only rows sent inside its window (the server pages by
        // the hour-floored wire time, so a page reaches a little past both
        // ends; those rows belong to the neighbouring windows) and only
        // those may come back below the history floor.
        let floor = match window {
            Some((before, after)) => {
                opened.retain(|(_, a)| {
                    let at = if a.sent_at_ms != 0 { a.sent_at_ms } else { a.timestamp };
                    (after..before).contains(&at)
                });
                0
            }
            None => self.history_floor(conv_key),
        };
        let mut oldest_written: Option<u64> = None;
        for (rec, archived) in opened {
            // The wire id is keyed (`archive_wire_id`); the real one is inside
            // the sealed record and must be the one the wire id was made from.
            let Some(record_id) = archived.message_id.clone()
                .filter(|mid| archive_wire_id(&ark, conv_key, mid) == rec.record_id)
            else {
                warn!("Sunucu arşiv kaydının kimliği tutmuyor, atlandı");
                continue;
            };
            // After the tag check: an unauthenticated `rev` must not be stored.
            if !self.note_archive_rev(conv_key, &record_id, rec.rev) {
                warn!("Sunucu arşiv kaydı reddedildi: görülenden eski revizyon");
                continue;
            }
            if self.message_exists_with_id(&record_id) {
                continue;
            }
            // Cleared or pruned by the user (`history_floor`; `conv_key` is
            // the identity id or group id the floor is kept under).
            let at = if archived.sent_at_ms != 0 { archived.sent_at_ms } else { archived.timestamp };
            if at < floor {
                continue;
            }
            let result = if group {
                self.archive_group_message(
                    conv_key,
                    archived.sender_identity_id.as_deref().unwrap_or(""),
                    &archived.direction,
                    archived.text.as_bytes(),
                    Some(&record_id),
                    archived.reply_to_message_id.as_deref(),
                    archived.reply_to_preview.as_deref(),
                    archived.reply_to_sender_identity_id.as_deref(),
                    archived.sent_at_ms,
                    archived.author_proof.as_deref(),
                )
            } else {
                // Sunucu arşivi KİMLİK bazlı (`conv_key` = identity_id) ama
                // yerel arşiv CİHAZ fingerprint'i bazlı — karşı tarafın
                // güncel aktif cihazına yazıyoruz. The chat key, as everywhere
                // else (`canonical_device_for_identity`): under another device
                // the rows were stored where the chat never looks.
                match self.canonical_device_for_identity(conv_key) {
                    Some(fp) => self.archive_message(
                        &fp,
                        &archived.direction,
                        archived.text.as_bytes(),
                        Some(&record_id),
                        archived.status.as_deref(),
                        archived.reply_to_message_id.as_deref(),
                        archived.reply_to_preview.as_deref(),
                        archived.sent_at_ms,
                    ),
                    None => Err("Bu kimliğin aktif cihazı çözülemedi".to_string()),
                }
            };
            match result {
                Ok(()) => {
                    merged += 1;
                    oldest_written = Some(oldest_written.map_or(at, |o| o.min(at)));
                }
                Err(e) => warn!("Sunucu arşiv satırı yazılamadı: {}", e),
            }
        }
        // The user fetched rows back: from the oldest one written on they
        // are not "cleared" any more.
        if let (Some(_), Some(o)) = (window, oldest_written) {
            self.lower_history_floor(conv_key, o);
        }
        if merged > 0 {
            // Bu olay HİÇBİR istemciye ulaşmıyordu (bu denetimde bulundu).
            // İki ayrı sebepten: (a) tür `older_history`/`older_group_history`
            // seçilmişti ama o iki olayın sözleşmesi bir `messages` DİZİSİ
            // taşımak, burada yok — Android `applyOlderHistory` `messages`
            // yoksa hemen dönüyor; (b) daha da temeli, adres alanı
            // `conversation` diye yazılmıştı, oysa yönlendirme `peer`
            // (1:1) / `group_id` (grup) alanlarına bakıyor — Android'in
            // `isForThisPeer` süzgeci ve Linux'un `event_belongs_here`'ı
            // ikisi de bu olayı SESSİZCE atıyordu. Sonuç: sunucudan geri
            // yüklenen geçmiş DB'ye yazılıyor ama açık sohbette
            // görünmüyordu; kullanıcı için "sunucudan geçmiş gelmiyor".
            //
            // Artık "toplu değişiklik oldu, ekranı tazele" anlamındaki
            // `history_backfilled` (her iki istemci de biliyor) DOĞRU
            // adres alanıyla yayınlanıyor. 1:1'de sunucu arşivi KİMLİK
            // bazlı, yerel sohbet anahtarı CİHAZ bazlı — `merge` yolunun
            // kendisiyle AYNI çeviri uygulanır.
            let mut event = serde_json::json!({
                "type": "history_backfilled", "count": merged, "source": "server"
            });
            if group {
                event["group_id"] = serde_json::json!(conv_key);
            } else if let Some(fp) = self.canonical_device_for_identity(conv_key) {
                event["peer"] = serde_json::json!(fp);
            }
            self.attachment_events.push(event.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Dosya ekleri
// ---------------------------------------------------------------------------
//
// İNDİRME yönünde burada hiçbir şey yok, kasıtlı: sunucu istemcilerin ZATEN
// konuştuğu `/p2pmessenger/filexfer/1.0.0` protokolünü servis ediyor, yani
// sunucudaki bir ek sadece "başka bir kaynak eş". Mevcut indirme durum
// makinesi (sıralı parçalar, `append_verified_chunk`, `alt_source_peer_ids`
// rotasyonu, `retry_or_give_up_download`, bütün-dosya SHA-256 kontrolü) hiç
// değişmeden çalışıyor. Sadece YÜKLEME yönü yeni, çünkü filexfer'ın bir
// yükleme fiili yok.

impl P2PCore {
    /// The secret a file's server blob is uploaded with; its hash
    /// (`server_proto::blob_id_for_upload_secret`) is the file id. Derived
    /// from the local history key and `file_key`: recipients hold `file_key`
    /// but not the history key, so they cannot claim the blob first.
    pub(crate) fn blob_upload_secret(&self, file_key: &[u8; 32]) -> Option<Vec<u8>> {
        let key = self.history_key.as_ref()?;
        let hash = Sha256::new_with_prefix(b"typeon-blob-upload-v1").chain_update(key).chain_update(file_key).finalize();
        Some(hash[..server_proto::BLOB_UPLOAD_SECRET_LEN].to_vec())
    }

    /// Şifrelenmiş bir dosyayı sunucuya yüklemek üzere kuyruğa alır.
    pub(crate) fn queue_blob_upload(&mut self, file_id: &str, file_key: &[u8; 32], total_chunks: u32) {
        if !self.servers.iter().any(|s| s.route_messages) {
            return;
        }
        if self.server_blob_uploads.iter().any(|u| u.file_id == file_id) {
            return;
        }
        let Some(upload_secret) = self.blob_upload_secret(file_key) else { return };
        // A file id that is not the hash of this secret (one not made by
        // `begin_outgoing_file`) cannot be uploaded under its own name.
        if server_proto::blob_id_for_upload_secret(&upload_secret).as_deref() != Some(file_id) {
            return;
        }
        let up = PendingBlobUpload {
            file_id: file_id.to_string(),
            upload_secret,
            next_chunk: 0,
            total_chunks,
            // Şifreli baytların hash'i `BlobFinish` anında `sha256_file` ile
            // hesaplanır — burada dosyayı bir kez daha baştan sona okumamak
            // için. (Defter #34: bunun için bir struct alanı vardı ama hiç
            // yazılmıyor, sadece diskten okunup atılıyordu; kaldırıldı.
            // `server_blob_uploads.enc_sha256` kolonu şema uyumu için duruyor
            // ve boş yazılıyor.)
            inflight: HashSet::new(),
            done: HashSet::new(),
            window: BLOB_WINDOW_START,
            rtt_min: u64::MAX,
            server_id: None,
            enc_sha256: None,
            hashing: None,
            restarts: 0,
        };
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_blob_uploads (file_id, next_chunk, total_chunks, enc_sha256, created_at, upload_secret)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![up.file_id, up.next_chunk as i64, up.total_chunks as i64, Vec::<u8>::new(), current_time_ms() as i64, up.upload_secret],
            );
        }
        self.server_blob_uploads.push(up);
    }

    /// Uploads the next chunks of the head upload, up to its window in flight.
    fn server_flush_blobs(&mut self, server_id: &str, peer_id: PeerId) {
        // Quota/rate error on a chunk: wait like `Deposit` does.
        if self.server_rt.get(server_id).map_or(false, |r| mono_ms() < r.deposit_backoff_until) {
            return;
        }
        // Progress counts for one server only (see `PendingBlobUpload.server_id`).
        // After a restart the server is not remembered (`None`): start over,
        // or the chunks could end up split between two servers.
        // The server is stored with the upload, so a restart resumes from
        // the stored watermark at the same server.
        let Some(head) = self.server_blob_uploads.first_mut() else { return };
        if head.server_id.as_deref() != Some(server_id) {
            head.inflight.clear();
            head.done.clear();
            head.next_chunk = 0;
            head.server_id = Some(server_id.to_string());
            let file_id = head.file_id.clone();
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE server_blob_uploads SET server_id = ?2, next_chunk = 0 WHERE file_id = ?1",
                    params![file_id, server_id],
                );
            }
        }
        let Some(up) = self.server_blob_uploads.first().cloned() else { return };
        let Ok(path) = self.enc_path_for(&up.file_id) else { return };

        // Boru hattı: aynı anda `BLOB_PIPELINE_DEPTH` parça havada olabilir.
        // Tek parça havadayken hız `parça/gidiş-dönüş` ile sınırlıydı.
        if up.done.len() < up.total_chunks as usize {
            // `.enc` SABIT ADIMLI; adim dosya basina (bkz. `file_chunk_size`).
            let chunk_size = self.file_chunk_size(&up.file_id);
            let mut sent = 0usize;
            for idx in 0..up.total_chunks {
                if up.inflight.len() + sent >= up.window {
                    break;
                }
                if up.done.contains(&idx) || up.inflight.contains(&idx) {
                    continue;
                }
                let data = match crate::attachments::read_chunk_from_disk_with(&path, idx, chunk_size) {
                    Ok(Some(d)) => d,
                    _ => {
                        self.finish_blob_upload(&up.file_id);
                        return;
                    }
                };
                let req = ServerRequest::BlobPut {
                    upload_secret: up.upload_secret.clone(),
                    chunk_index: idx,
                    chunk_size: chunk_size as u32,
                    total_chunks: up.total_chunks,
                    data,
                };
                if let Some(id) = self.send_server_request(peer_id, req) {
                    if let Some(u) = self.server_blob_uploads.first_mut() {
                        u.inflight.insert(idx);
                    }
                    self.server_inflight.insert(
                        id,
                        ServerInflight::BlobPut {
                            server_id: server_id.to_string(),
                            blob_id: up.file_id.clone(),
                            chunk_index: idx,
                            total_chunks: up.total_chunks,
                            sent_at: mono_ms(),
                        },
                    );
                    sent += 1;
                }
            }
            return;
        }

        // Bütün parçalar onaylandı — mühürle. One finish in flight, and the
        // hash (a full read of up to 4 GiB under the core lock) is taken once.
        // ponytail: that one read still stalls the poll loop for a multi-GB
        // file; hash on a blocking task if it shows.
        let finishing = self
            .server_inflight
            .values()
            .any(|i| matches!(i, ServerInflight::BlobFinish { blob_id, .. } if *blob_id == up.file_id));
        if up.next_chunk >= up.total_chunks && !finishing {
            // The hash runs on its own thread; the sweep comes back for it.
            let hashed = match (&up.enc_sha256, &up.hashing) {
                (Some(h), _) => Some(Some(h.clone())),
                (None, Some(cell)) => cell.get().cloned(),
                (None, None) => {
                    let cell = std::sync::Arc::new(std::sync::OnceLock::new());
                    let (c, p) = (cell.clone(), path.clone());
                    std::thread::spawn(move || {
                        let _ = c.set(sha256_file(&p));
                    });
                    if let Some(u) = self.server_blob_uploads.first_mut() {
                        u.hashing = Some(cell);
                    }
                    None
                }
            };
            let enc_sha256 = match hashed {
                Some(Some(h)) => h,
                // Dosya okunamıyor — yüklemeyi bırak, doğrudan-eş yolu
                // zaten çalışmaya devam ediyor.
                Some(None) => {
                    self.finish_blob_upload(&up.file_id);
                    return;
                }
                // Still hashing: `server_sweep` looks again each turn.
                None => return,
            };
            if let Some(u) = self.server_blob_uploads.first_mut() {
                u.enc_sha256 = Some(enc_sha256.clone());
                u.hashing = None;
            }
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE server_blob_uploads SET enc_sha256 = ?2 WHERE file_id = ?1",
                    params![up.file_id, enc_sha256],
                );
            }
            let req = ServerRequest::BlobFinish {
                upload_secret: up.upload_secret.clone(),
                total_chunks: up.total_chunks,
                enc_sha256,
            };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(
                    id,
                    ServerInflight::BlobFinish { server_id: server_id.to_string(), blob_id: up.file_id.clone() },
                );
            }
        }
    }

    fn advance_blob_upload(&mut self, file_id: &str, chunk_index: u32, _total: u32, server_id: &str) {
        // A late `Ok` from a server the upload has since left does not count.
        if let Some(up) = self
            .server_blob_uploads
            .iter_mut()
            .find(|u| u.file_id == file_id && u.server_id.as_deref() == Some(server_id))
        {
            up.inflight.remove(&chunk_index);
            up.done.insert(chunk_index);
            // `next_chunk` artık BİTİŞİK olarak onaylanmış su seviyesi —
            // süreç ölürse buradan devam edilir. Boru hattında parçalar
            // sırasız onaylandığı için "en yüksek + 1" YANLIŞ olurdu:
            // aradaki bir boşluk sessizce atlanırdı.
            // From the last watermark: `done` only grows (a reset also sets
            // `next_chunk` to 0), so nothing below it can be missing.
            let mut watermark = up.next_chunk;
            while up.done.contains(&watermark) {
                watermark += 1;
            }
            up.next_chunk = watermark;
            if let Some(conn) = &self.db {
                let _ = conn.execute(
                    "UPDATE server_blob_uploads SET next_chunk = ?2 WHERE file_id = ?1",
                    params![file_id, watermark as i64],
                );
            }
        }
        // Pencereyi beklemeden yeniden doldur: the blob path only, not a
        // full sweep per acked chunk. Only for the server the head upload
        // goes to (`server_flush_blobs` would move it to this one).
        let head_here = self.server_blob_uploads.first().is_some_and(|u| u.server_id.as_deref() == Some(server_id));
        if let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id).filter(|_| head_here) {
            self.server_flush_blobs(server_id, peer_id);
        }
    }

    /// The server lost the upload (swept while we were offline, or chunks
    /// missing): send every chunk again. Gives up after a few rounds so a
    /// server that keeps losing it cannot loop the upload for ever.
    fn restart_blob_upload(&mut self, file_id: &str, server_id: &str) {
        const MAX_BLOB_RESTARTS: u8 = 3;
        let Some(up) = self
            .server_blob_uploads
            .iter_mut()
            .find(|u| u.file_id == file_id && u.server_id.as_deref() == Some(server_id))
        else {
            return;
        };
        if up.restarts >= MAX_BLOB_RESTARTS {
            warn!("Sunucu blob'u tekrar tekrar kaybetti, yükleme bırakıldı: {}", file_id);
            self.finish_blob_upload(file_id);
            return;
        }
        up.restarts += 1;
        up.inflight.clear();
        up.done.clear();
        up.next_chunk = 0;
        if let Some(conn) = &self.db {
            let _ = conn.execute("UPDATE server_blob_uploads SET next_chunk = 0 WHERE file_id = ?1", params![file_id]);
        }
        self.server_sweep_at = 0;
    }

    /// Gives an upload up. Chunks already on a server are deleted there
    /// (`BlobDelete`), or they held its quota until the 24 h sweep.
    pub(crate) fn finish_blob_upload(&mut self, file_id: &str) {
        let started = self.server_blob_uploads.iter().find(|u| u.file_id == file_id).and_then(|u| {
            u.server_id.clone().filter(|_| !u.done.is_empty() || !u.inflight.is_empty()).map(|sid| (sid, u.upload_secret.clone()))
        });
        if let Some((peer_id, upload_secret)) =
            started.and_then(|(sid, secret)| self.server_rt.get(&sid).and_then(|r| r.peer_id).map(|p| (p, secret)))
        {
            let _ = self.send_server_request(peer_id, ServerRequest::BlobDelete { upload_secret });
        }
        self.forget_blob_upload(file_id);
    }

    /// Drops an upload from the queue (done, or given up).
    fn forget_blob_upload(&mut self, file_id: &str) {
        self.server_blob_uploads.retain(|u| u.file_id != file_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM server_blob_uploads WHERE file_id = ?1", params![file_id]);
        }
    }
}

/// The archive buckets of one conversation: the month of `newest_ms` and the
/// 35 before it. Purge, scroll-up and full restore must agree on this window.
fn archive_buckets(ark: &[u8; 32], conv_key: &str, newest_ms: u64) -> Vec<String> {
    let newest = server_seal::archive_epoch_for(newest_ms);
    (newest.saturating_sub(35)..=newest)
        .rev()
        .filter_map(|epoch| server_seal::server_archive_bucket(ark, conv_key, epoch).ok())
        .collect()
}

/// M-30: the `sent_at_ms` the server sees, floored to the hour (same epoch
/// as the exact time). Restore orders by the time inside the sealed record.
fn archive_wire_ms(sent_at_ms: u64) -> u64 {
    sent_at_ms - sent_at_ms % 3_600_000
}

/// The record id the server sees: keyed with the archive key, so the two
/// ends of a chat (each with its own key) store one message under unrelated
/// ids. The real id is inside the sealed record (`ArchivedMessage.message_id`).
fn archive_wire_id(ark: &[u8; 32], conv_key: &str, record_id: &str) -> String {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(conv_key.as_bytes()), ark);
    let info = [b"typeon-archive-record-id:".as_slice(), record_id.as_bytes()].concat();
    let mut out = [0u8; 16];
    // 16 bytes is far below the HKDF output limit: cannot fail.
    let _ = hk.expand(&info, &mut out);
    hex::encode(out)
}

/// M38: a mailbox id is a read capability: logs show 24 bits of its hash,
/// never a part of the id itself.
fn mailbox_log_id(id: &str) -> String {
    hex::encode(&Sha256::digest(id.as_bytes())[..3])
}

/// `server_deposit_locations` / `server_deposited` key: `"mailbox|message_id"`
/// for a `Message` (one entry per target), anything else as it is.
fn location_message_id(key: &str) -> &str {
    key.split_once('|').map_or(key, |(_, mid)| mid)
}

/// Bir dosyanın tamamının SHA-256'sı, bellekte tutmadan (ekler 4 GiB'a
/// kadar olabiliyor — `MAX_ATTACHMENT_SIZE`).
fn sha256_file(path: &std::path::Path) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
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

/// Bir zarfın günlüğe yazılacak kısa tür adı — bkz. `try_server_deposit`.
/// Bir zarfın "bu sunucuya zaten yatırdım mı" anahtarı.
///
/// Gerçek cihazda ölçülen hata (2026-08-29): `already_deposited`/
/// `note_server_deposit` YALNIZCA `NetworkEnvelope::Message` kolunu
/// tanıyordu (`m.header.message_id`), diğer her tür için `false` dönüyordu.
/// Yani `Handshake`/`IdentityExchange` — ki bunlar `awaiting_confirmation`'a
/// giremediği için tek dayanakları `pending_envelopes` kuyruğu ve o kuyruk
/// HER poll turunda yeniden deneniyor — sunucuya saniyede bir kez yeniden
/// yatırılıyordu. Her biri ~15 KB: birkaç saat içinde yatıranın
/// `bytes_mail` kotası (256 MB) doluyor ve o andan itibaren o cihazın
/// HERKESE giden bütün sunucu teslimatları `QuotaExceeded` alıyor. Kullanıcı
/// bunu "mesajlar nadir gidiyor, çok gecikme var, kararsız" olarak
/// yaşıyordu; ikincil cihazlar en çok etkileniyordu çünkü onlara ulaşmak
/// neredeyse her zaman ya taze bir el sıkışmadan ya sunucudan geçiyor.
///
/// `Message` için anahtar hâlâ `message_id` (yeniden serileştirilen aynı
/// mesaj da tekilleşsin diye); diğer türler için zarfın baytlarının
/// özeti — kuyruktan aynı zarf birebir klonlanarak yeniden denendiği için
/// kararlı bir anahtar.
pub(crate) fn deposit_dedup_key(envelope: &NetworkEnvelope, bytes: &[u8]) -> String {
    match envelope {
        NetworkEnvelope::Message(m) => m.header.message_id.clone(),
        _ => {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            format!("raw:{}", hex::encode(&hasher.finalize()[..16]))
        }
    }
}

pub(crate) fn envelope_kind(envelope: &NetworkEnvelope) -> String {
    match envelope {
        NetworkEnvelope::Handshake(_) => "Handshake".to_string(),
        NetworkEnvelope::IdentityExchange(_) => "IdentityExchange".to_string(),
        NetworkEnvelope::Message(m) => format!("Message/{}", m.header.message_id.chars().take(8).collect::<String>()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::IdentityExchange;

    fn core_with_meta() -> P2PCore {
        let mut core = P2PCore::new();
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE app_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)").unwrap();
        core.db = Some(conn);
        core
    }

    #[test]
    fn archive_key_rotation_is_durable_and_resumable() {
        let mut core = core_with_meta();
        assert!(!core.set_archive_root_key(&[1u8; 33]));
        assert!(core.set_archive_root_key(&[1u8; 32]));
        core.rotate_archive_root_key();
        let new = core.archive_root_key.unwrap();
        assert_ne!(new, [1u8; 32]);
        // Sync and backfill ran; the old buckets wait for the server.
        assert_eq!(core.meta_str("ark_todo"), None);
        assert_eq!(core.meta_str("ark_purge"), Some(hex::encode([1u8; 32])));
        // The client restarts with the key file it did not rewrite.
        assert!(core.set_archive_root_key(&[1u8; 32]));
        assert_eq!(core.archive_root_key, Some(new));
        // Once it loads the new key, the copy in the DB goes.
        assert!(core.set_archive_root_key(&new));
        assert_eq!(core.meta_str("ark"), None);
        // The purge is confirmed only for the keys it covered.
        let peer = PeerId::random();
        core.send_archive_purge(peer, "s".into(), "other".into(), Vec::new());
        assert!(core.meta_str("ark_purge").is_some());
        core.send_archive_purge(peer, "s".into(), hex::encode([1u8; 32]), Vec::new());
        assert_eq!(core.meta_str("ark_purge"), None);
    }

    #[test]
    fn only_the_primary_replaces_the_archive_key_and_never_with_a_retired_one() {
        let mut core = core_with_meta();
        assert!(core.adopt_archive_key(&[1u8; 32], false), "none yet: any sibling");
        assert!(!core.adopt_archive_key(&[2u8; 32], false));
        assert!(core.adopt_archive_key(&[2u8; 32], true));
        assert!(!core.adopt_archive_key(&[1u8; 32], true), "an older sync must not bring the old key back");
        assert_eq!(core.archive_root_key, Some([2u8; 32]));
        assert_eq!(core.meta_str("ark_purge"), Some(hex::encode([1u8; 32])), "the old buckets are purged");
        assert_eq!(core.meta_str("ark_todo"), None, "a secondary does not backfill");
    }

    #[test]
    fn an_older_archive_revision_is_refused() {
        let mut core = P2PCore::new();
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE server_archive_revs (conv_key TEXT NOT NULL, record_id TEXT NOT NULL, rev INTEGER NOT NULL, PRIMARY KEY (conv_key, record_id))",
        )
        .unwrap();
        core.db = Some(conn);
        assert!(core.note_archive_rev("c", "m", 5));
        assert!(core.note_archive_rev("c", "m", 5));
        assert!(!core.note_archive_rev("c", "m", 4), "rollback");
        assert!(core.note_archive_rev("c", "m", 6));
        assert!(!core.note_archive_rev("c", "m", 5));
        assert!(core.note_archive_rev("other", "m", 1), "the id is the peer's choice: scoped to the chat");
    }

    #[test]
    fn archive_ids_and_location_keys() {
        let a = archive_wire_id(&[1u8; 32], "c", "m");
        assert_eq!(a, archive_wire_id(&[1u8; 32], "c", "m"));
        assert_ne!(a, archive_wire_id(&[2u8; 32], "c", "m"), "two identities must not share an id");
        assert_ne!(a, "m");
        assert_eq!(location_message_id("mbox|msg-1"), "msg-1");
        assert_eq!(location_message_id("raw:abcd"), "raw:abcd");
    }

    fn ident() -> NetworkEnvelope {
        NetworkEnvelope::IdentityExchange(IdentityExchange {
            identity_id: "id".into(),
            device_fingerprint: "fp".into(),
            device_name: "dev".into(),
            sign_pubkey_ed25519: vec![1, 2, 3],
            sign_pubkey_mldsa: vec![4],
            kem_pubkey_x25519: vec![5],
            kem_pubkey_mlkem: vec![6],
            device_add: None,
            revokes: Vec::new(),
            device_add_signer: None,
            pairing_proof: Vec::new(),
            link_consent: Vec::new(),
            link_consent_pq: Vec::new(),
            prekey: None,
            timestamp: 0,
            signature: Vec::new(),
            signature_pq: Vec::new(),
        })
    }

    /// Kök hata (2026-08-29, gerçek cihaz): `Message` OLMAYAN zarflar için
    /// tekilleştirme anahtarı YOKTU, bu yüzden `already_deposited` hep
    /// `false` dönüyor ve `pending_envelopes` kuyruğu her poll turunda AYNI
    /// el sıkışmayı sunucuya yeniden yatırıyordu — saatler içinde bırakanın
    /// kotası doluyor ve o cihazın TÜM sunucu teslimatı kilitleniyordu.
    #[test]
    fn non_message_envelopes_have_a_stable_dedup_key() {
        let env = ident();
        let bytes = b"ayni-baytlar";
        assert_eq!(
            deposit_dedup_key(&env, bytes),
            deposit_dedup_key(&env, bytes),
            "ayni zarf ayni anahtari vermeli, yoksa tekilleştirme hic calismaz"
        );
        assert_ne!(
            deposit_dedup_key(&env, bytes),
            deposit_dedup_key(&env, b"baska-baytlar"),
            "farkli zarf farkli anahtar almali, yoksa gercek bir zarf yutulur"
        );
        assert!(deposit_dedup_key(&env, bytes).starts_with("raw:"));
    }
}
