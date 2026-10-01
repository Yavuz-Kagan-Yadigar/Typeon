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
use crate::{current_time_ms, extract_peer_id, P2PCore};

/// Sunucudan hiçbir haber gelmese bile emniyet amaçlı tam tarama aralığı.
///
/// Normalde çekme, sunucunun ittiği `Notify` ile tetiklenir — bir telefonda
/// 1 Hz'lik `poll_events` turunda sürekli `Fetch` etmek doğrudan pil demek.
/// Bu sabit sadece "itme kaybolursa yine de kendini onarsın" içindir.
/// The server connection has no keepalive: on mobile data it can die silently
/// and then no push arrives. 5 min left a queued message undelivered that long
/// (measured on device); this Fetch doubles as the liveness check.
// ponytail: fixed 60 s poll, a server-side ping would let this go back up if battery matters.
pub(crate) const SERVER_FETCH_SWEEP_INTERVAL_MS: u64 = 30 * 1000;

/// Sunucu bağlantısı/kayıt durumu tarama aralığı.
pub(crate) const SERVER_SWEEP_INTERVAL_MS: u64 = 15_000;

/// Bir mesajın "bu sunucuya zaten yatırıldı" bilgisinin hatırlanma süresi —
/// bkz. `P2PCore.server_deposited`. Sunucunun kutu TTL'i çok daha uzun; bu
/// süre yalnızca haritanın sınırsız büyümesini engelliyor. Süre dolduktan
/// sonra bir yeniden yatırma olabilir; 12 saatte bir tek fazladan kopya,
/// saniyede bir kopyanın yanında yok hükmünde.
pub(crate) const SERVER_DEPOSIT_MEMORY_MS: u64 = 12 * 60 * 60 * 1000;
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

/// Tek bir `poll_events` turunda sunucudan işlenecek azami öğe/bayt.
///
/// Bu sınır ZORUNLU: sunucudan gelen zarflar `source = None` ile enjekte
/// ediliyor (bkz. `drive_server_sync`), yani mevcut `check_rate_limit`
/// (`Some(peer)` şartlı) ONLARA HİÇ UYGULANMIYOR. Sınırsız bırakılsaydı
/// 10.000 mesajlık bir birikim, UI'ın yokladığı tek bir turda çözülmeye
/// çalışılırdı.
pub(crate) const SERVER_MAX_ITEMS_PER_POLL: usize = 200;
pub(crate) const SERVER_MAX_BYTES_PER_POLL: usize = 2 * 1024 * 1024;

/// Bir arşiv yükleme partisinin azami kayıt sayısı.
pub(crate) const SERVER_ARCHIVE_BATCH: usize = 50;

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
/// büyütülmez — 30 sn'lik protokol zaman aşımına yaklaşıyoruz demektir ve
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
/// Bu yüzden tavan artık `request_timeout`un (30 sn) bir ORANI:
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
    /// `Hello`'dan gelen, henüz kullanılmamış challenge.
    pub challenge: Option<Vec<u8>>,
    pub limits: Option<ServerLimits>,
    /// Sunucuya bildirilmiş kutu kimlikleri — `Register` farkını hesaplamak
    /// için.
    pub registered: HashSet<String>,
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
    /// Unreachable server: no new dial before this (ms), see `server_sweep`.
    pub dial_backoff_until: u64,
    /// Dials since the last successful connection.
    pub dial_attempts: u32,
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
    },
    Fetch { server_id: String },
    Ack { server_id: String },
    /// bkz. `ServerRequest::Cancel` — gönderenin kendi paketini geri
    /// çekmesi. Yanıtta yapılacak bir şey yok, sadece "beklenmeyen yanıt"
    /// uyarısı basmasın diye izleniyor.
    Cancel { server_id: String },
    ArchivePut { server_id: String, count: usize },
    /// `bucket_more`: bu sayfa `more = true` ile dönerse aynı kovadan
    /// daha eskisini istemek için kovanın kimliği.
    ArchiveFetch { server_id: String, conv_key: String, group: bool, bucket_more: Option<String> },
    /// `all_buckets`: tam geri yüklemede DOLU olan HER kova çekilir;
    /// sıradan "yukarı kaydır" akışında sadece en yenisi.
    ArchiveProbe { server_id: String, conv_key: String, group: bool, all_buckets: bool },
    BlobPut { server_id: String, blob_id: String, chunk_index: u32, total_chunks: u32, sent_at: u64 },
    BlobFinish { server_id: String, blob_id: String },
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
    }

    pub(crate) fn load_servers_from_db(&mut self) {
        let Some(conn) = &self.db else { return };
        let mut stmt = match conn.prepare(
            "SELECT server_id, address, name, enroll_sk, enrollment_id, token, route_messages, store_history, added_at, enroll_sk_pq FROM servers",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        let loaded: Vec<ServerRecord> = stmt
            .query_map([], |r| {
            Ok(ServerRecord {
                server_id: r.get(0)?,
                address: r.get(1)?,
                name: r.get(2)?,
                enroll_sk: r.get(3)?,
                enrollment_id: r.get(4)?,
                token: r.get(5)?,
                route_messages: r.get::<_, i64>(6)? != 0,
                store_history: r.get::<_, i64>(7)? != 0,
                added_at: r.get::<_, i64>(8)? as u64,
                // Sunucu desteği eklendikten SONRA gelen kolon; eski
                // satırlarda NULL olabilir (bkz. init_server_tables'daki
                // ALTER TABLE). Boşsa kayıt yenilenir.
                enroll_sk_pq: r.get::<_, Option<Vec<u8>>>(9)?.unwrap_or_default(),
            })
            })
            .map(|it| it.filter_map(|r| r.ok()).collect())
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
            warn!("Sunucu adresinden yerel ağ adresi çıkarıldı: {}", r.server_id);
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
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? as u64))
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
                // `seal_local_blob` ile şifreli. Açılamayanlar MİRAS (bu
                // düzeltmeden önce yazılmış) düz metin satırlardır — olduğu
                // gibi kabul edilir, böylece yükseltmede bekleyen arşiv
                // kaydı kaybolmaz. Önce yerel bir Vec'e toplanıyor:
                // `&self` (open_local_blob) ile `&mut self.server_archive_queue`
                // aynı ifadede yaşamasın diye.
                let raw: Vec<PendingArchive> = rows.flatten().collect();
                let opened: Vec<PendingArchive> = raw
                    .into_iter()
                    .map(|mut e| {
                        if let Some(plain) = self.open_local_blob(&e.plaintext) {
                            e.plaintext = plain;
                        }
                        e
                    })
                    .collect();
                self.server_archive_queue = opened;
            }
        }
        if let Ok(mut stmt) =
            conn.prepare("SELECT file_id, next_chunk, total_chunks FROM server_blob_uploads")
        {
            if let Ok(rows) = stmt.query_map([], |r| {
                let next_chunk = r.get::<_, i64>(1)? as u32;
                Ok(PendingBlobUpload {
                    file_id: r.get(0)?,
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
            error!("Sunucu kaydı diske yazılamadı: veritabanı yok ({})", rec.server_id);
            return;
        };
        let written = conn.execute(
            "INSERT OR REPLACE INTO servers
             (server_id, address, name, enroll_sk, enrollment_id, token, route_messages, store_history, added_at, enroll_sk_pq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                rec.server_id, rec.address, rec.name, rec.enroll_sk, rec.enrollment_id, rec.token,
                rec.route_messages as i64, rec.store_history as i64, rec.added_at as i64, rec.enroll_sk_pq
            ],
        );
        match written {
            Ok(_) => info!("Sunucu kaydı diske yazıldı: {}", rec.server_id),
            Err(e) => error!("Sunucu kaydı diske YAZILAMADI ({}): {}", rec.server_id, e),
        }
    }

    fn persist_cursor(&self, server_id: &str, mailbox_id: &str, seq: u64) {
        let Some(conn) = &self.db else { return };
        // Bunun sessizce başarısız olması, her yeniden başlatmada bütün
        // kutunun baştan işlenmesi demek (dedup yutar ama boşuna CPU/pil).
        let r = conn.execute(
            "INSERT OR REPLACE INTO server_cursors (server_id, mailbox_id, last_seq) VALUES (?1, ?2, ?3)",
            params![server_id, mailbox_id, seq as i64],
        );
        if let Err(e) = r {
            warn!("Sunucu imleci yazılamadı ({}/{}): {}", server_id, mailbox_id, e);
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
            // Kayıt baştan yapılacak: eski kimlik (iptal edilmiş olabilir)
            // ile `Rebind` denemek yalnızca aynı hatayı tekrarlardı.
            rec.enrollment_id = None;
            self.persist_server(&rec);
            if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                *r = rec;
            }
            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                rt.enrolled = false;
                rt.hello_sent_at = 0;
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
            store_history: false,
            added_at: current_time_ms(),
        };
        self.persist_server(&rec);
        self.servers.push(rec);
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
        self.purge_server_archive(server_id);
        self.servers.remove(idx);
        self.server_rt.remove(server_id);
        self.server_cursors.retain(|(sid, _), _| sid != server_id);
        // Defter #10: bekleyen arşiv kuyruğu ve blob yüklemeleri de
        // temizlenmeli. `server_flush_archive`/`server_flush_blobs` bağlı ve
        // (arşiv için) `store_history` açık bir sunucu ister — son sunucu
        // kaldırıldığında bu satırlar bir daha ASLA boşalmıyor, yani
        // süresiz olarak diskte kalıyorlardı.
        let no_servers_left = self.servers.is_empty();
        if no_servers_left {
            self.server_archive_queue.clear();
            self.server_blob_uploads.clear();
        }
        self.server_deposited.retain(|(sid, _), _| sid != server_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM servers WHERE server_id = ?1", params![server_id]);
            let _ = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1", params![server_id]);
            if no_servers_left {
                let _ = conn.execute("DELETE FROM server_archive_queue", []);
                let _ = conn.execute("DELETE FROM server_blob_uploads", []);
            }
        }
        Ok(())
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

        // 1:1 sohbetlerin arşiv anahtarı karşı tarafın `identity_id`'si
        // (yerel `contact_id` DEĞİL — bkz. `server_archive_bucket` notu:
        // kimlik bazlı, ki karşı taraf cihaz değiştirdiğinde arşiv okunabilir
        // kalsın).
        let mut conv_keys: Vec<String> = self.groups.keys().cloned().collect();
        conv_keys.extend(self.contacts.values().map(|c| c.trusted_identity_id.clone()));

        let newest_epoch = server_seal::archive_epoch_for(current_time_ms());
        let mut buckets = Vec::new();
        for conv_key in conv_keys {
            for back in 0..36u64 {
                let epoch = newest_epoch.saturating_sub(back);
                if let Ok(b) = server_seal::server_archive_bucket(&ark, &conv_key, epoch) {
                    buckets.push(b);
                }
                if epoch == 0 {
                    break;
                }
            }
        }
        if buckets.is_empty() {
            return;
        }
        // Tek bir istek 1 MiB'ı aşmasın (bkz. `MAX_DEPOSIT_BYTES` notu — aynı
        // kablo tavanı bütün istekler için geçerli).
        for chunk in buckets.chunks(2000) {
            let req = ServerRequest::ArchivePurge { buckets: chunk.to_vec() };
            let _ = self.send_server_request(peer_id, req);
        }
    }

    pub(crate) fn set_server_routing(&mut self, server_id: &str, enabled: bool) -> Result<(), String> {
        let Some(rec) = self.servers.iter_mut().find(|s| s.server_id == server_id) else {
            return Err("Sunucu bulunamadı".to_string());
        };
        rec.route_messages = enabled;
        let rec = rec.clone();
        self.persist_server(&rec);
        Ok(())
    }

    pub(crate) fn set_server_history(&mut self, server_id: &str, enabled: bool) -> Result<(), String> {
        let Some(rec) = self.servers.iter_mut().find(|s| s.server_id == server_id) else {
            return Err("Sunucu bulunamadı".to_string());
        };
        rec.store_history = enabled;
        let rec = rec.clone();
        self.persist_server(&rec);
        Ok(())
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

    /// Bu cihazın DİNLEDİĞİ bütün gossipsub topic adları.
    ///
    /// TEK kaynak: hem `start_network`'teki abonelik döngüsü hem de sunucu
    /// `Register`/`Fetch` buradan besleniyor. İkisinin ayrışması, rotasyon
    /// sırasında sunucudan mesaj kaçırmak demek olurdu — bu yüzden aynı
    /// fonksiyon.
    pub(crate) fn own_mailbox_topics(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(fp) = &self.own_mailbox_topic_fp {
            out.push(format!("p2p_msg_{}", fp));
        }
        for state in self.ratchets.values() {
            out.push(Self::topic_for_root_key(&state.root_key).to_string());
            // Rotasyon penceresi: karşı taraf son rotasyonumuzu henüz
            // uygulamadıysa hâlâ ESKİ topic'e yazıyor olabilir.
            if let Some(prev) = &state.prev_root_key {
                out.push(Self::topic_for_root_key(prev).to_string());
            }
        }
        out
    }

    /// Kutu kimliği -> o kutunun zarflarını açacak `root_key`.
    ///
    /// `None` değer = ilk temas kutusu (mühürsüz çerçeve, bkz.
    /// `server_seal::frame_unsealed`).
    fn mailbox_key_index(&self) -> HashMap<String, Option<Vec<u8>>> {
        let mut idx = HashMap::new();
        if let Some(fp) = &self.own_mailbox_topic_fp {
            idx.insert(server_seal::server_mailbox_id(&format!("p2p_msg_{}", fp)), None);
        }
        for state in self.ratchets.values() {
            idx.insert(
                server_seal::server_mailbox_id(&Self::topic_for_root_key(&state.root_key).to_string()),
                Some(state.root_key.clone()),
            );
            if let Some(prev) = &state.prev_root_key {
                idx.insert(
                    server_seal::server_mailbox_id(&Self::topic_for_root_key(prev).to_string()),
                    Some(prev.clone()),
                );
            }
        }
        idx
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
        let mailbox = server_seal::server_mailbox_id(topic);

        // "Bu alıcı sunucumda değil" bilgisi TTL'li olarak hatırlanır —
        // her mesajda boşuna gidiş-dönüş ödememek için.
        if let Some(until) = self.server_unknown_mailboxes.get(&mailbox) {
            if current_time_ms() < *until {
                info!("Sunucu atlandı (kutu sunucuda kayıtlı değil, TTL sürüyor): {}", mailbox);
                return false;
            }
        }
        self.server_unknown_mailboxes.remove(&mailbox);

        // Mühür: `Message` zarfları oturumun `root_key`'iyle ikinci kez
        // şifrelenir (aksi halde `sender_device_fingerprint` sunucunun
        // veritabanına AÇIK girerdi). İlk temas zarfları mühürlenemez —
        // paylaşılan bir sır yok, bkz. `server_seal` modül notu.
        let sealed = match envelope {
            NetworkEnvelope::Message(m) => {
                let root = if m.header.rotation_kyber_ciphertext.is_some() {
                    self.ratchets.get(target_fp).and_then(|r| r.prev_root_key.clone())
                        .or_else(|| self.ratchets.get(target_fp).map(|r| r.root_key.clone()))
                } else {
                    self.ratchets.get(target_fp).map(|r| r.root_key.clone())
                };
                match root {
                    Some(root_key) => match server_seal::seal_envelope(&root_key, bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Zarf mühürlenemedi, sunucu atlanıyor: {}", e);
                            return false;
                        }
                    },
                    // Ratchet yoksa mühürleyecek anahtar da yok.
                    None => server_seal::frame_unsealed(bytes),
                }
            }
            _ => server_seal::frame_unsealed(bytes),
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
        let now_ms = current_time_ms();
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
            .map(|s| s.server_id.clone())
            .collect();
        if candidates.is_empty() {
            info!(
                "Sunucu atlandı (bağlı+kayıtlı sunucu yok; {} yapılandırılmış)",
                self.servers.len()
            );
            return false;
        }

        let dedup_key = deposit_dedup_key(envelope, bytes);
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
                mailbox,
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
        let targets: Vec<(String, String, u64)> = self
            .server_deposit_locations
            .iter()
            .filter(|((_, mid), _)| mid == message_id)
            .map(|((sid, _), (mailbox, seq))| (sid.clone(), mailbox.clone(), *seq))
            .collect();
        for (server_id, mailbox, seq) in targets {
            self.server_deposit_locations.remove(&(server_id.clone(), message_id.to_string()));
            let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { continue };
            let req = ServerRequest::Cancel { mailbox, seqs: vec![seq] };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(id, ServerInflight::Cancel { server_id });
            }
        }
    }

    pub(crate) fn forget_server_deposit(&mut self, message_id: &str) {
        self.server_deposited.retain(|(_, mid), _| mid != message_id);
        self.server_deposit_locations.retain(|(_, mid), _| mid != message_id);
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
        // Radio saver (see `RADIO_WINDOW_MS`): inside the window only. New
        // mail still arrives at once as server push over the open connection.
        if !self.radio_window_open {
            return;
        }
        let now = current_time_ms();
        if now < self.server_sweep_at {
            return;
        }
        self.server_sweep_at = now + SERVER_SWEEP_INTERVAL_MS;

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
            self.server_deposit_locations.retain(|(_, mid), _| pending.contains(mid));
            let dropped = before - self.server_deposit_locations.len();
            if dropped > 0 {
                info!("Sunucu yatırma konumu kaydından {} bayat girdi temizlendi", dropped);
            }
        }

        let records: Vec<ServerRecord> = self.servers.clone();
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
            let hello_stale = now.saturating_sub(rt.hello_sent_at) > SERVER_SWEEP_INTERVAL_MS;

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
                if now < rt.dial_backoff_until { continue; }
                rt.dial_backoff_until = now + (SERVER_SWEEP_INTERVAL_MS << rt.dial_attempts.min(7)).min(30 * 60 * 1000);
                rt.dial_attempts += 1;
                // Bağlı değiliz: BİLİNEN HER adresi aynı anda dene (bkz.
                // `ServerRecord.address`).
                for a in rec.address.split(',').filter_map(|a| a.trim().parse::<Multiaddr>().ok()) {
                    self.dial_with_relay_fallback(peer_id, Some(a));
                }
                continue;
            }
            if !enrolled {
                if hello_stale {
                    if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                        rt.hello_sent_at = now;
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
            let wanted: HashSet<String> = self
                .own_mailbox_topics()
                .iter()
                .map(|t| server_seal::server_mailbox_id(t))
                .collect();
            let current = self.server_rt.get(&rec.server_id).map(|r| r.registered.clone()).unwrap_or_default();
            let add: Vec<String> = wanted.difference(&current).cloned().collect();
            let drop: Vec<String> = current.difference(&wanted).cloned().collect();
            if !add.is_empty() || !drop.is_empty() {
                info!("Sunucuya kutu kaydı: +{} -{}", add.len(), drop.len());
                let ids = add.clone();
                let dropped = drop.clone();
                if let Some(id) = self.send_server_request(peer_id, ServerRequest::Register { add, drop }) {
                    self.server_inflight
                        .insert(id, ServerInflight::Register { server_id: rec.server_id.clone(), ids, dropped });
                }
            }

            // Emniyet çekmesi (itme kaybolduysa).
            let due = self.server_rt.get(&rec.server_id).map(|r| r.fetch_due_at).unwrap_or(0);
            if now >= due {
                self.server_fetch(&rec.server_id, peer_id);
            }

            if rec.store_history {
                self.server_flush_archive(&rec.server_id, peer_id);
            }
            self.server_flush_blobs(&rec.server_id, peer_id);
        }
    }

    fn server_fetch(&mut self, server_id: &str, peer_id: PeerId) {
        let cursors: Vec<(String, u64)> = self
            .own_mailbox_topics()
            .iter()
            .map(|t| {
                let mb = server_seal::server_mailbox_id(t);
                let seq = self
                    .server_cursors
                    .get(&(server_id.to_string(), mb.clone()))
                    .copied()
                    .unwrap_or(0);
                (mb, seq)
            })
            .collect();
        if cursors.is_empty() {
            return;
        }
        // Zaten havada bir `Fetch` varsa ikincisini gönderme (bkz.
        // `ServerRuntime.fetch_inflight`).
        if self.server_rt.get(server_id).map(|r| r.fetch_inflight).unwrap_or(false) {
            return;
        }
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.fetch_due_at = current_time_ms() + SERVER_FETCH_SWEEP_INTERVAL_MS;
            rt.fetch_inflight = true;
        }
        let req = ServerRequest::Fetch {
            cursors,
            max_items: MAX_FETCH_BATCH_ITEMS,
            max_bytes: MAX_FETCH_BATCH_BYTES,
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::Fetch { server_id: server_id.to_string() });
        }
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

    fn handle_server_response(
        &mut self,
        inflight: ServerInflight,
        response: ServerResponse,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) {
        match (inflight, response) {
            // --- Hello ---
            (ServerInflight::Hello { server_id }, ServerResponse::Welcome { challenge, enrolled, limits, server_name, .. }) => {
                let Some(rec) = self.servers.iter().find(|s| s.server_id == server_id).cloned() else { return };
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.challenge = Some(challenge.clone());
                    rt.limits = Some(limits);
                    rt.enrolled = enrolled;
                    rt.last_error = None;
                }
                if !rec.name.is_empty() || server_name.is_empty() {
                    // isim zaten var
                } else if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                    r.name = server_name;
                    let r = r.clone();
                    self.persist_server(&r);
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
                if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                    r.enrollment_id = Some(enrollment_id);
                    // Jeton tek kullanımlık — sakladığımızda bir faydası yok,
                    // sızması hâlinde zararı var.
                    r.token.clear();
                    let r = r.clone();
                    self.persist_server(&r);
                }
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = true;
                    rt.limits = Some(limits);
                    rt.registered.clear();
                    rt.last_error = None;
                }
                info!("Sunucuya kaydolundu: {}", server_id);
                self.server_sweep_at = 0;
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

            // Sunucu `Ack`/`ArchivePurge`/`BlobDelete` için sade `Ok`
            // yanıtlıyor — bunları açıkça karşılamazsak her onay
            // "beklenmeyen yanıt" uyarısı basardı.
            (ServerInflight::Ack { .. }, ServerResponse::Ok) => {}

            // --- Deposit ---
            (ServerInflight::Deposit { mailbox, server_id, envelope, .. }, ServerResponse::Deposited { seq }) => {
                info!("Sunucu zarfı sakladı: kutu={} seq={}", mailbox, seq);
                // Bu zarf artık sunucunun DİSKİNDE. `awaiting_confirmation`
                // onayı beklerken aynı zarfı tekrar tekrar yatırmanın hiçbir
                // faydası yok — bkz. `server_deposited` alan notu.
                if let NetworkEnvelope::Message(m) = &envelope {
                    self.note_server_deposit(&server_id, &m.header.message_id);
                    // bkz. `server_deposit_locations` — geri çekebilmek için
                    // paketin kutuda hangi sırada durduğunu saklıyoruz.
                    self.server_deposit_locations.insert(
                        (server_id.clone(), m.header.message_id.clone()),
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
                let index = self.mailbox_key_index();
                let mut acks: Vec<(String, u64)> = Vec::new();
                // İmleç (nereden devam edeceğiz) ile silme sınırı (sunucudan
                // neyi sildirmeye HAKKIMIZ var) artık AYRI — bkz. #25.
                let mut highest: HashMap<String, u64> = HashMap::new();
                let mut ack_upto: HashMap<String, u64> = HashMap::new();
                let mut failed_mailboxes: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                let mut count = 0usize;
                let mut bytes = 0usize;

                for item in items {
                    // Tur başına sınır: bu zarflar `source = None` ile
                    // enjekte edildiği için mevcut hız sınırına TABİ DEĞİL.
                    if count >= SERVER_MAX_ITEMS_PER_POLL || bytes >= SERVER_MAX_BYTES_PER_POLL {
                        break;
                    }
                    let Some(key) = index.get(&item.mailbox_id) else {
                        // Artık dinlemediğimiz bir kutu — imleci yine de
                        // ilerlet ki sunucu bunu sonsuza dek geri vermesin.
                        highest.insert(item.mailbox_id.clone(), item.seq);
                        continue;
                    };
                    let opened = match key {
                        Some(root_key) => server_seal::open_envelope(root_key, &item.sealed).ok(),
                        None => server_seal::open_unsealed(&item.sealed).map(|b| b.to_vec()),
                    }
                    .or_else(|| server_seal::open_unsealed(&item.sealed).map(|b| b.to_vec()));

                    match opened {
                        Some(raw) => {
                            count += 1;
                            bytes += raw.len();
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
                            highest.insert(item.mailbox_id.clone(), item.seq);
                            // Bu kutuda henüz açılamayan bir öğeye
                            // rastlamadıysak silme sınırını da ilerlet.
                            if !failed_mailboxes.contains(&item.mailbox_id) {
                                ack_upto.insert(item.mailbox_id.clone(), item.seq);
                            }
                        }
                        None => {
                            // Çözülemedi (ör. rotasyondan çok eski). İmleci
                            // yine de ilerlet: aksi halde bu öğe sonsuza dek
                            // her turda yeniden denenirdi.
                            //
                            // Defter #25: ama `Ack` ile SİLDİRME. `Ack`
                            // sunucudaki kopyayı kalıcı olarak yok ediyor;
                            // burası, teslim edilmiş bir yükü tek yönlü
                            // olarak imha eden tek yerdi. Artık bu kutuda
                            // silme sınırı bu öğeden ÖNCEKİ son başarılı
                            // öğede duruyor — bozuk öğe (ve sonrası) sunucu
                            // TTL'ine kadar duruyor, imleç ilerlediği için
                            // de akış tıkanmıyor.
                            warn!("Sunucudan gelen zarf açılamadı, silinmeden atlanıyor (kutu={})", item.mailbox_id);
                            highest.insert(item.mailbox_id.clone(), item.seq);
                            failed_mailboxes.insert(item.mailbox_id.clone());
                        }
                    }
                }

                if count > 0 {
                    info!("Sunucudan {} zarf çekildi ({} bayt)", count, bytes);
                }
                for (mailbox, seq) in highest {
                    self.server_cursors.insert((server_id.clone(), mailbox.clone()), seq);
                    self.persist_cursor(&server_id, &mailbox, seq);
                }
                // Silme SADECE açılabilmiş öğelere kadar (bkz. #25) —
                // "artık dinlemediğimiz kutu" dalı da `ack_upto`'ya hiç
                // yazmadığı için oradaki öğeler de silinmez.
                for (mailbox, seq) in ack_upto {
                    acks.push((mailbox, seq));
                }

                // DİKKAT: `Ack` burada gönderiliyor ama imleç zaten
                // ilerletildi. Sıralama kasıtlı — `incoming` bu turun
                // sonunda işlenecek ve orada arşivleme başarısız olursa
                // gönderenin `awaiting_confirmation`'ı yine de yeniden
                // deneyecek (uçtan uca garanti orada, sunucuda değil).
                if !acks.is_empty() {
                    if let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) {
                        if let Some(id) = self.send_server_request(peer_id, ServerRequest::Ack { acks }) {
                            self.server_inflight.insert(id, ServerInflight::Ack { server_id: server_id.clone() });
                        }
                    }
                }
                if more {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.fetch_due_at = 0;
                    }
                    self.server_sweep_at = 0;
                }
            }

            // --- Arşiv ---
            (ServerInflight::ArchivePut { count, .. }, ServerResponse::Ok) => {
                self.drop_archive_queue_head(count);
            }
            (ServerInflight::ArchiveProbe { server_id, conv_key, group, all_buckets }, ServerResponse::ArchiveProbed { present }) => {
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { return };
                // "Yukarı kaydır" akışında sadece en yeni dolu kova yeter;
                // tam geri yüklemede dolu olan HEPSİ istenir.
                let wanted: Vec<String> = if all_buckets {
                    present.iter().map(|b| b.bucket.clone()).collect()
                } else {
                    present
                        .iter()
                        .max_by_key(|b| b.newest_ms)
                        .map(|b| vec![b.bucket.clone()])
                        .unwrap_or_default()
                };
                for bucket in wanted {
                    let req = ServerRequest::ArchiveFetch {
                        bucket: bucket.clone(),
                        before_ms: None,
                        max_items: MAX_FETCH_BATCH_ITEMS,
                        max_bytes: MAX_FETCH_BATCH_BYTES,
                    };
                    if let Some(id) = self.send_server_request(peer_id, req) {
                        self.server_inflight.insert(
                            id,
                            ServerInflight::ArchiveFetch {
                                server_id: server_id.clone(),
                                conv_key: conv_key.clone(),
                                group,
                                bucket_more: Some(bucket),
                            },
                        );
                    }
                }
            }
            (
                ServerInflight::ArchiveFetch { server_id, conv_key, group, bucket_more },
                ServerResponse::ArchiveBatch { records, more },
            ) => {
                // Sayfa yeniden eskiye geliyor; devamı için son kaydın
                // damgasından geriye devam et. Bu olmadan bir kovadan
                // yalnızca ilk sayfa alınır ve daha eski mesajlar sunucuda
                // erişilemez kalırdı.
                let oldest = records.iter().map(|r| r.sent_at_ms).min();
                self.merge_server_archive(&conv_key, group, records);
                if let (true, Some(bucket), Some(before_ms)) = (more, bucket_more, oldest) {
                    if let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) {
                        let req = ServerRequest::ArchiveFetch {
                            bucket: bucket.clone(),
                            before_ms: Some(before_ms),
                            max_items: MAX_FETCH_BATCH_ITEMS,
                            max_bytes: MAX_FETCH_BATCH_BYTES,
                        };
                        if let Some(id) = self.send_server_request(peer_id, req) {
                            self.server_inflight.insert(
                                id,
                                ServerInflight::ArchiveFetch {
                                    server_id,
                                    conv_key,
                                    group,
                                    bucket_more: Some(bucket),
                                },
                            );
                        }
                    }
                }
            }

            // --- Bloblar ---
            (ServerInflight::BlobPut { blob_id, chunk_index, total_chunks, server_id, sent_at }, ServerResponse::Ok) => {
                // Gidiş-dönüş ölçümü: bir aktarımın GECİKME sınırlı mı yoksa
                // BANT GENİŞLİĞİ sınırlı mı olduğunu ayırt etmenin tek yolu.
                // Gecikme sınırlıysa pencereyi büyütmek doğrudan hız verir;
                // bant genişliği sınırlıysa hiçbir şey vermez ve asıl çare
                // başka yerdedir (bkz. tek Tor devresi tavanı).
                let rtt = current_time_ms().saturating_sub(sent_at);
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
                self.finish_blob_upload(&blob_id);
            }

            // --- Hata ---
            (inflight, ServerResponse::Err(code)) => self.handle_server_error(inflight, code),

            // Beklenmeyen eşleşme — protokol uyumsuzluğu.
            (inflight, other) => {
                warn!("Sunucudan beklenmeyen yanıt: {:?} -> {:?}", inflight, std::mem::discriminant(&other));
            }
        }
    }

    fn handle_server_error(&mut self, inflight: ServerInflight, code: ServerErrorCode) {
        let server_id = match &inflight {
            ServerInflight::Hello { server_id }
            | ServerInflight::Enroll { server_id }
            | ServerInflight::Rebind { server_id }
            | ServerInflight::Register { server_id, .. }
            | ServerInflight::Deposit { server_id, .. }
            | ServerInflight::Fetch { server_id }
            | ServerInflight::Ack { server_id }
            | ServerInflight::Cancel { server_id }
            | ServerInflight::ArchivePut { server_id, .. }
            | ServerInflight::ArchiveFetch { server_id, .. }
            | ServerInflight::ArchiveProbe { server_id, .. }
            | ServerInflight::BlobPut { server_id, .. }
            | ServerInflight::BlobFinish { server_id, .. } => server_id.clone(),
        };

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

        match code {
            ServerErrorCode::UnknownMailbox => {
                warn!("Sunucu kutuyu tanımıyor (alıcı bu sunucuda değil)");
                if let ServerInflight::Deposit { mailbox, .. } = &inflight {
                    self.server_unknown_mailboxes
                        .insert(mailbox.clone(), current_time_ms() + SERVER_UNKNOWN_MAILBOX_TTL_MS);
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
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = false;
                    rt.hello_sent_at = 0;
                }
                self.server_sweep_at = 0;
                self.retry_deposit_over_gossipsub(&inflight);
            }
            ServerErrorCode::Revoked => {
                warn!("Sunucu kaydımızı iptal etti: {}", server_id);
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = false;
                    rt.last_error = Some("Operatör kaydı iptal etti".to_string());
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
                    warn!("Sunucu kutusu dolu, bu kutuya yatırma {} sn durduruldu: {}", SERVER_DEPOSIT_BACKOFF_MS / 1000, mailbox);
                    self.server_unknown_mailboxes
                        .insert(mailbox.clone(), current_time_ms() + SERVER_DEPOSIT_BACKOFF_MS);
                }
                self.retry_deposit_over_gossipsub(&inflight);
            }
            other => {
                warn!("Sunucu hatası: {:?}", other);
                let backs_off = matches!(
                    other,
                    ServerErrorCode::QuotaExceeded | ServerErrorCode::RateLimited
                );
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.last_error = Some(format!("{:?}", other));
                    rt.fetch_inflight = false;
                    // bkz. `SERVER_DEPOSIT_BACKOFF_MS`: kota/hız hatası
                    // "biraz sonra tekrar dene" demek, "saniyede bir tekrar
                    // dene" değil. Geri çekilme SADECE yatırmayı durdurur —
                    // `Fetch`/`Ack` çalışmaya devam eder, hatta kutuyu
                    // boşaltmak kotayı açan şeyin ta kendisidir.
                    if backs_off {
                        rt.deposit_backoff_until = current_time_ms() + SERVER_DEPOSIT_BACKOFF_MS;
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
            }
        }
        // Yatırma başarısızsa "zaten yatırıldı" işaretini geri al, yoksa
        // yeniden deneme yolu kapanırdı (bkz. `server_deposited`).
        if let ServerInflight::Deposit { server_id, dedup_key, .. } = &inflight {
            // Artık TÜRDEN BAĞIMSIZ (bkz. `deposit_dedup_key`) — önceden
            // yalnızca `Message` geri alınıyordu, ki zaten yalnızca `Message`
            // işaretleniyordu.
            self.server_deposited.remove(&(server_id.clone(), dedup_key.clone()));
        }
        self.retry_deposit_over_gossipsub(&inflight);
    }

    /// Sunucuya bırakılamamış bir zarfı hemen gossipsub'a verir.
    fn retry_deposit_over_gossipsub(&mut self, inflight: &ServerInflight) {
        if let ServerInflight::Deposit { envelope, target_fp, first_attempt_at, .. } = inflight {
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
        if let ServerInflight::BlobPut { blob_id, chunk_index, .. } = inflight {
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
            for p in self.server_peer_ids() {
                self.note_bulk_timeout(p);
            }
        }
    }

    fn begin_enrollment(&mut self, server_id: &str, challenge: &[u8]) {
        let Some(rec) = self.servers.iter().find(|s| s.server_id == server_id).cloned() else { return };
        let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id) else { return };
        let Ok(sk_bytes): Result<[u8; 32], _> = rec.enroll_sk.as_slice().try_into() else {
            error!("Sunucu kayıt anahtarı bozuk: {}", server_id);
            return;
        };
        let signing = SigningKey::from_bytes(&sk_bytes);
        let Ok(seed): Result<ml_dsa::Seed, _> = rec.enroll_sk_pq.as_slice().try_into() else {
            // Sunucu desteği eklenmeden önce kaydedilmiş bir satır olabilir
            // (bkz. `enroll_sk_pq` geçişi). Kullanıcı sunucuyu yeni bir
            // davet koduyla eklemeli — sessizce klasik imzaya DÜŞMÜYORUZ.
            error!("Sunucu kayıt anahtarının PQ bileşeni yok: {}", server_id);
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error =
                    Some("Kayıt anahtarı eski biçimde — sunucuyu yeni bir davet koduyla ekleyin".to_string());
            }
            return;
        };
        let signing_pq = MlDsaSigningKey::<MlDsa87>::from_seed(&seed);
        let ts_ms = current_time_ms();

        // Zaten kayıtlıysak (uygulama yeniden kuruldu, libp2p kimliği
        // değişti) davet jetonu TÜKETMEDEN yeniden bağlan.
        if let Some(enrollment_id) = rec.enrollment_id.clone() {
            let input = server_proto::rebind_signing_input(&enrollment_id, server_id, ts_ms);
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
                rt.last_error = Some("Davet jetonu yok — sunucuyu yeni bir kodla ekleyin".to_string());
            }
            return;
        }
        let Ok(token_bytes) = hex::decode(&rec.token) else {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error = Some("Davet jetonu bozuk".to_string());
            }
            return;
        };
        let input =
            server_proto::enroll_signing_input(SERVER_PROTOCOL_VERSION, server_id, &token_bytes, challenge, ts_ms);
        let sig = signing.sign(&input).to_bytes().to_vec();
        let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
        let req = ServerRequest::Enroll {
            version: SERVER_PROTOCOL_VERSION,
            invite_token: token_bytes,
            enroll_pk: signing.verifying_key().to_bytes().to_vec(),
            enroll_pk_pq: signing_pq.verifying_key().encode().to_vec(),
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
        if key.len() != 32 {
            return false;
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        self.archive_root_key = Some(k);
        true
    }

    pub(crate) fn archive_root_key_bytes(&self) -> Option<Vec<u8>> {
        self.archive_root_key.map(|k| k.to_vec())
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
            return;
        }
        let entry = PendingArchive {
            conv_key: conv_key.to_string(),
            record_id: record_id.to_string(),
            rev,
            sent_at_ms,
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
        }
    }

    /// Kuyruktaki arşiv kayıtlarını partiler hâlinde yükler.
    fn server_flush_archive(&mut self, server_id: &str, peer_id: PeerId) {
        if self.server_archive_queue.is_empty() {
            return;
        }
        let Some(ark) = self.archive_root_key else { return };
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
        for entry in self.server_archive_queue.iter() {
            if records.len() >= SERVER_ARCHIVE_BATCH {
                break;
            }
            if entry.conv_key != head.conv_key || server_seal::archive_epoch_for(entry.sent_at_ms) != epoch {
                // Farklı kova — bu parti burada biter (kuyruk sırası korunur).
                break;
            }
            match server_seal::seal_archive_record(&ark, &entry.conv_key, &entry.record_id, entry.rev, &entry.plaintext)
            {
                Ok(sealed) => records.push(ArchiveRecord {
                    record_id: entry.record_id.clone(),
                    rev: entry.rev,
                    sent_at_ms: entry.sent_at_ms,
                    sealed,
                }),
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
        let count = consumed;
        let req = ServerRequest::ArchivePut { bucket, records };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight
                .insert(id, ServerInflight::ArchivePut { server_id: server_id.to_string(), count });
        }
    }

    fn drop_archive_queue_head(&mut self, count: usize) {
        for _ in 0..count.min(self.server_archive_queue.len()) {
            let entry = self.server_archive_queue.remove(0);
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
    pub(crate) fn request_older_server_history(&mut self, conv_key: &str, group: bool, before_ms: u64) {
        let Some(ark) = self.archive_root_key else { return };
        let Some(server_id) = self.history_server() else { return };
        let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { return };

        // Hangi kovalar var? Sabit bir sohbet kimliği yerine aylık kovalar
        // kullanıldığından (bkz. `server_archive_bucket`), önce son ~36 ayı
        // TEK istekte yokluyoruz.
        let newest_epoch = server_seal::archive_epoch_for(if before_ms == 0 { current_time_ms() } else { before_ms });
        let mut buckets = Vec::new();
        for back in 0..36u64 {
            let epoch = newest_epoch.saturating_sub(back);
            if let Ok(b) = server_seal::server_archive_bucket(&ark, conv_key, epoch) {
                buckets.push(b);
            }
            if epoch == 0 {
                break;
            }
        }
        let req = ServerRequest::ArchiveProbe { buckets };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(
                id,
                ServerInflight::ArchiveProbe {
                    server_id,
                    conv_key: conv_key.to_string(),
                    group,
                    all_buckets: false,
                },
            );
        }
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
        let Some(ark) = self.archive_root_key else {
            return Err("Kök arşiv anahtarı yok — bu cihaz sunucudaki geçmişi çözemez".to_string());
        };
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

        let newest_epoch = server_seal::archive_epoch_for(current_time_ms());
        let mut asked = 0u32;
        for (conv_key, group) in convs {
            let mut buckets = Vec::new();
            for back in 0..36u64 {
                let epoch = newest_epoch.saturating_sub(back);
                if let Ok(b) = server_seal::server_archive_bucket(&ark, &conv_key, epoch) {
                    buckets.push(b);
                }
                if epoch == 0 {
                    break;
                }
            }
            let req = ServerRequest::ArchiveProbe { buckets };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(
                    id,
                    ServerInflight::ArchiveProbe {
                        server_id: server_id.clone(),
                        conv_key,
                        group,
                        // Tam geri yüklemede DOLU olan HER kova çekilir,
                        // sadece en yenisi değil.
                        all_buckets: true,
                    },
                );
                asked += 1;
            }
        }
        Ok(asked)
    }

    /// Sunucudan gelen arşiv sayfasını YEREL arşive birleştirir.
    ///
    /// Mevcut `HistorySyncResponse` birleştirme kuralının aynısı:
    /// `message_id` bazlı var-olma kontrolü (zaman damgası eşiği DEĞİL —
    /// sayfalama isteklerinde o yanlış yönde çalışır).
    fn merge_server_archive(&mut self, conv_key: &str, group: bool, records: Vec<ArchiveRecord>) {
        let Some(ark) = self.archive_root_key else { return };
        let mut merged = 0usize;
        for rec in records {
            if self.message_exists_with_id(&rec.record_id) {
                continue;
            }
            let plaintext =
                match server_seal::open_archive_record(&ark, conv_key, &rec.record_id, rec.rev, &rec.sealed) {
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
            let result = if group {
                self.archive_group_message(
                    conv_key,
                    archived.sender_identity_id.as_deref().unwrap_or(""),
                    &archived.direction,
                    archived.text.as_bytes(),
                    Some(&rec.record_id),
                    archived.reply_to_message_id.as_deref(),
                    archived.reply_to_preview.as_deref(),
                    archived.reply_to_sender_identity_id.as_deref(),
                    archived.sent_at_ms,
                )
            } else {
                // Sunucu arşivi KİMLİK bazlı (`conv_key` = identity_id) ama
                // yerel arşiv CİHAZ fingerprint'i bazlı — karşı tarafın
                // güncel aktif cihazına yazıyoruz.
                match self.resolve_active_device_for_identity(conv_key) {
                    Some(fp) => self.archive_message(
                        &fp,
                        &archived.direction,
                        archived.text.as_bytes(),
                        Some(&rec.record_id),
                        archived.status.as_deref(),
                        archived.reply_to_message_id.as_deref(),
                        archived.reply_to_preview.as_deref(),
                        archived.sent_at_ms,
                    ),
                    None => Err("Bu kimliğin aktif cihazı çözülemedi".to_string()),
                }
            };
            match result {
                Ok(()) => merged += 1,
                Err(e) => warn!("Sunucu arşiv satırı yazılamadı: {}", e),
            }
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
            } else if let Some(fp) = self.resolve_active_device_for_identity(conv_key) {
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
    /// Şifrelenmiş bir dosyayı sunucuya yüklemek üzere kuyruğa alır.
    pub(crate) fn queue_blob_upload(&mut self, file_id: &str, total_chunks: u32) {
        if !self.servers.iter().any(|s| s.route_messages) {
            return;
        }
        if self.server_blob_uploads.iter().any(|u| u.file_id == file_id) {
            return;
        }
        let up = PendingBlobUpload {
            file_id: file_id.to_string(),
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
        };
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO server_blob_uploads (file_id, next_chunk, total_chunks, enc_sha256, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![up.file_id, up.next_chunk as i64, up.total_chunks as i64, Vec::<u8>::new(), current_time_ms() as i64],
            );
        }
        self.server_blob_uploads.push(up);
    }

    /// Sıradaki dosya parçasını yükler. Aynı anda TEK parça havada —
    /// 256 KiB'lık bir parça kablo tavanının (1 MiB) çok altında ama
    /// paralel yükleme, sunucu tarafındaki saf-append yazımı bozardı.
    fn server_flush_blobs(&mut self, server_id: &str, peer_id: PeerId) {
        if self.server_blob_uploads.is_empty() {
            return;
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
                    blob_id: up.file_id.clone(),
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
                            sent_at: current_time_ms(),
                        },
                    );
                    sent += 1;
                }
            }
            return;
        }

        // Bütün parçalar onaylandı — mühürle.
        if up.next_chunk >= up.total_chunks {
            let enc_sha256 = match sha256_file(&path) {
                Some(h) => h,
                None => {
                    // Dosya okunamıyor — yüklemeyi bırak, doğrudan-eş yolu
                    // zaten çalışmaya devam ediyor.
                    self.finish_blob_upload(&up.file_id);
                    return;
                }
            };
            let req = ServerRequest::BlobFinish {
                blob_id: up.file_id.clone(),
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

    fn advance_blob_upload(&mut self, file_id: &str, chunk_index: u32, _total: u32, _server_id: &str) {
        if let Some(up) = self.server_blob_uploads.iter_mut().find(|u| u.file_id == file_id) {
            up.inflight.remove(&chunk_index);
            up.done.insert(chunk_index);
            // `next_chunk` artık BİTİŞİK olarak onaylanmış su seviyesi —
            // süreç ölürse buradan devam edilir. Boru hattında parçalar
            // sırasız onaylandığı için "en yüksek + 1" YANLIŞ olurdu:
            // aradaki bir boşluk sessizce atlanırdı.
            let mut watermark = 0u32;
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
        // Pencereyi beklemeden yeniden doldur.
        self.server_sweep_at = 0;
    }

    fn finish_blob_upload(&mut self, file_id: &str) {
        self.server_blob_uploads.retain(|u| u.file_id != file_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM server_blob_uploads WHERE file_id = ?1", params![file_id]);
        }
    }
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
