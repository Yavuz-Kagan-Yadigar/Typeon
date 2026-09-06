//! Sunucu (store-and-forward) protokolü — istemci ve sunucunun ORTAK kablo
//! tipleri.
//!
//! Bu modül neden `pub`: depo kökündeki `typeon-server/` crate'i bu çekirdeği
//! (`Linux/` masaüstü istemcisinin yaptığı gibi) bir path bağımlılığı olarak
//! linkler ve BU tipleri kullanır. Tek bir tanım var, elle senkron tutulacak
//! ikinci bir kopya YOK — `api` modülünün Linux istemcisi için var olmasıyla
//! aynı gerekçe.
//!
//! ## Sunucu NE DEĞİLDİR
//!
//! Bu bir libp2p Circuit Relay v2 DEĞİLDİR. Röle, iki taraf da O ANDA
//! bağlıyken canlı bir devre kurar ve HİÇBİR ŞEY SAKLAMAZ (bkz. depo
//! kökündeki `Bagimsiz-AI-Inceleme-Notlari.md` §17). Buradaki sunucu bunun
//! tam tersi: alıcı çevrimdışıyken zarfı DİSKE yazar, alıcı geri döndüğünde
//! teslim eder, teslim onaylanana kadar da silmez.
//!
//! ## İki AYRI depo — birleştirmek en büyük tasarım hatası olurdu
//!
//! 1. **Teslim (mail)**: mühürlü zarflar. Alıcı `Ack`'leyince SİLİNİR, en
//!    fazla `mailbox_ttl_ms` yaşar.
//! 2. **Arşiv (archive)**: geçmiş. Teslim zarfları burada KULLANILAMAZ —
//!    ratchet mesaj anahtarları ileri-gizli ve kullanıldıktan sonra
//!    siliniyor, yani geçen haftanın zarfı bugün HİÇ KİMSE tarafından
//!    çözülemez. Arşiv, istemcinin `archive_key` ile YENİDEN şifrelediği
//!    ayrı kayıtlardır (bkz. `server_seal::seal_archive_record`).
//!
//! ## Boyut tavanı — KABLO SEVİYESİNDE SERT SINIR
//!
//! `libp2p-request-response`'un CBOR codec'i istek boyutunu `1 MiB` ile
//! SABİT olarak sınırlar (`cbor.rs`: `REQUEST_SIZE_MAXIMUM`, bir associated
//! const — `Behaviour::new` üzerinden AYARLANAMAZ) ve okumayı `io.take()`
//! ile yapar: tavanı aşan bir istek SESSİZCE KIRPILIR, sonra CBOR çözümü
//! başarısız olur. Yanıt tavanı 10 MiB.
//!
//! Bu, gossipsub'ın `max_transmit_size`'ı (TAM OLARAK 1 MiB) ile birleşince
//! ince bir tuzak yaratıyor: gossipsub'a SIĞAN bir `FileOffer` (büyük bir
//! `preview_jpeg` ile), `Deposit` içine CBOR'lanınca sığmayabilir. Bu yüzden
//! `MAX_DEPOSIT_BYTES` tavanın belirgin şekilde ALTINDA ve aşan zarflar
//! sunucuya HİÇ denenmez, doğrudan gossipsub'a gider.

use serde::{Deserialize, Serialize};

/// Sunucu RPC protokol kimliği. `FILE_TRANSFER_PROTOCOL`/`KEEPALIVE_PROTOCOL`
/// ile aynı desende, `request_response::cbor::Behaviour` üzerinde taşınır.
///
/// İKİ UÇ DA `ProtocolSupport::Full` kaydeder — sunucunun istemciye
/// KENDİLİĞİNDEN `Notify` gönderebilmesi için (bkz. `ServerRequest::Notify`).
/// `request_response` yalnızca istek-BAŞLATAN tarafı belirler, yön değil.
pub const SERVER_PROTOCOL: &str = "/typeon/server/1.0.0";

/// Kablo formatı sürümü — `Hello`/`Welcome` içinde takas edilir.
pub const SERVER_PROTOCOL_VERSION: u16 = 1;

/// Tek bir `Deposit`in azami yükü. Modül başındaki "Boyut tavanı" notuna
/// bakın: codec'in sert sınırı 1 MiB, buradaki pay CBOR enum/alan
/// çerçevelemesi için. Bunu aşan zarf sunucuya DENENMEZ.
pub const MAX_DEPOSIT_BYTES: usize = 900 * 1024;

/// Tek bir `Fetch` yanıtının azami boyutu. Codec 10 MiB'a izin verir ama
/// bu yanıt, ~1 Hz'lik `poll_events` turunun İÇİNDE çözülüp işleniyor —
/// büyük bir yığın, mesaj listesini süren döngüyü doğrudan takar.
pub const MAX_FETCH_BATCH_BYTES: u32 = 512 * 1024;
pub const MAX_FETCH_BATCH_ITEMS: u32 = 64;

/// `Enroll`/`Rebind` zaman damgası toleransı. Bu kadar eski/ileri bir imza
/// reddedilir (`ServerErrorCode::Stale`).
pub const ENROLL_MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// Opak posta kutusu adresi — `server_seal::server_mailbox_id` çıktısı
/// (`mb_<hex16>`) ya da arşiv kovası (`ar_<hex16>`). Sunucu bunu ASLA
/// ayrıştırmaz; kendisi için anlamsız bir dizedir.
pub type MailboxId = String;

// ---------------------------------------------------------------------------
// İstek
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerRequest {
    // --- kayıt (enrollment) ---
    /// Bağlantı açılışında ilk mesaj. Yanıtı `Welcome`.
    Hello { version: u16 },

    /// Operatörün verdiği davet jetonuyla kayıt.
    ///
    /// KRİTİK TASARIM KARARI — bu anahtarlar cihazın KİMLİK anahtarları
    /// DEĞİL, SADECE BU SUNUCU İÇİN üretilmiş taze bir çifttir. Sunucunun
    /// gerçekten ihtiyacı olan iki şey var: Sybil'e karşı bir kapı (davet
    /// jetonu) ve iptal edilebilir bir tutamak. İkisi de anonim bir anahtarla
    /// karşılanıyor. Cihazın `device_fingerprint`'ini/`identity_id`'sini
    /// göndermek, operatöre "bu sunucuyu tam olarak KİMLER kullanıyor"
    /// listesini KRİPTOGRAFİK OLARAK KANITLANABİLİR biçimde hediye ederdi —
    /// üstelik sunucular arasında ve PeerId değişse bile eşleştirilebilir
    /// halde. Bir keypair'in maliyeti buna değmez.
    ///
    /// İmza girdisi:
    /// `version || server_peer_id || invite_token || challenge || ts_ms`.
    /// `server_peer_id`'nin DAHİL olması şart: aksi halde kötü niyetli bir
    /// sunucu, kendisine gelen `Enroll` paketini BAŞKA bir sunucuya karşı
    /// tekrar oynatıp o kullanıcı adına kayıt olabilirdi. `challenge` de
    /// şart: imzayı sunucunun O AN ürettiği tek kullanımlık değere bağlar.
    Enroll {
        version: u16,
        invite_token: Vec<u8>,
        /// Ed25519 public key (32 bayt).
        enroll_pk: Vec<u8>,
        /// ML-DSA-87 public key (2592 bayt). İmza uygulamanın geri kalanıyla
        /// AYNI şekilde HİBRİT: klasik bir imza tek başına, hasat-şimdi-
        /// kır-sonra bir saldırgana ileride sahte kayıt üretme imkânı
        /// verirdi. Gizliliği etkilemezdi (içerik şifrelemesi bu imzaya
        /// bağlı değil) ama depodaki "her imza hibrittir" kuralını bozardı.
        enroll_pk_pq: Vec<u8>,
        /// AZ ÖNCE gelen `Welcome.challenge`. İmza girdisine DAHİL (bkz.
        /// `enroll_signing_input`): sunucu tarafında tek kullanımlık
        /// olmasının yanında, imzayı O BAĞLANTIYA bağlar — aksi halde
        /// yakalanan bir imza, sunucunun yeni bir challenge ürettiği taze
        /// bir bağlantıda hâlâ geçerli olurdu.
        challenge: Vec<u8>,
        ts_ms: u64,
        /// Ed25519 imzası.
        sig: Vec<u8>,
        /// ML-DSA-87 imzası — AYNI baytlar üzerinde. İkisi de doğrulanmalı.
        sig_pq: Vec<u8>,
    },

    /// Var olan bir kaydı YENİ bir libp2p `PeerId`'ye bağla — uygulama
    /// yeniden kurulduğunda/`libp2p_identity.key` kaybolduğunda. `enroll_pk`
    /// sahipliğini kanıtlar, davet jetonu TÜKETMEZ (aksi halde tek
    /// kullanımlık bir davetle kurulan bir cihaz, bir kez yeniden kurulumdan
    /// sonra sunucuya bir daha bağlanamazdı).
    ///
    /// İmza girdisi: `enrollment_id || server_peer_id || ts_ms`.
    Rebind {
        enrollment_id: Vec<u8>,
        ts_ms: u64,
        sig: Vec<u8>,
        sig_pq: Vec<u8>,
    },

    // --- posta kutusu (transit) ---
    /// Hangi kutularla ilgilendiğimizi bildir. İdempotent.
    ///
    /// İki işi birden yapar: (a) sunucu bu kutulara gelen zarfları kabul
    /// eder ve `Fetch`'e servis eder, (b) yeni bir şey düştüğünde `Notify`
    /// ile İTEBİLİR. `drop`, rotasyonda artık dinlenmeyen bir nesil eski
    /// topic'i geri alır.
    Register {
        add: Vec<MailboxId>,
        drop: Vec<MailboxId>,
    },

    /// Mühürlü bir zarfı kutuya bırak.
    ///
    /// Kota, kutunun SAHİBİNE değil BIRAKANA yazılır — bir spam gönderici
    /// kendi kotasını yakar ve kimse bir kurbanın kutusunu doldurup ona
    /// hizmet reddi uygulayamaz.
    Deposit { mailbox: MailboxId, sealed: Vec<u8> },

    /// Birden çok kutudan TEK gidiş-dönüşte çek.
    ///
    /// Neden çoklu: 50 kişilik bir cihazın ~100 canlı kutu kimliği var
    /// (güncel + bir nesil önceki). Her tarama turunda 100 ayrı istek
    /// saçmalık olurdu.
    ///
    /// `cursors`: her kutu için İŞLENMİŞ en yüksek `seq`; sunucu KESİN
    /// OLARAK ondan büyük olanları döner (0 = baştan).
    Fetch {
        cursors: Vec<(MailboxId, u64)>,
        max_items: u32,
        max_bytes: u32,
    },

    /// "Şu kutudaki şu `seq`'e kadar her şeyi işledim, silebilirsin."
    /// Kümülatif ve idempotent — kaybolan bir `Ack` en fazla bir kez
    /// gereksiz yeniden teslime yol açar, ASLA boşluğa yol açmaz.
    ///
    /// KRİTİK: istemci bunu SADECE zarfı çözüp arşive YAZDIKTAN sonra
    /// gönderir — `send_ack`'in `archive_message` başarılıysa gönderilmesiyle
    /// (bkz. lib.rs) BİREBİR aynı gerekçe: disk dolu/DB hatası gibi geçici
    /// bir arızada "aldım" demek, mesajın hiçbir yerde kalıcı olmadığı hâlde
    /// sunucudan silinmesi demek olurdu.
    Ack { acks: Vec<(MailboxId, u64)> },

    /// Dış inceleme önerisi (2026-08-27): GÖNDERENİN, henüz teslim
    /// edilmemiş kendi paketini geri çekmesi.
    ///
    /// `Ack` bunu KASITLI olarak yapamaz: orada `depositor != acker` şartı
    /// var, çünkü bir gönderenin, alıcı görmeden mesajı sunucudan
    /// sildirebilmesi kötüye kullanılabilirdi. Ama tersi de bir açıktı —
    /// yanlışlıkla gönderilen bir mesaj, alıcı çevrimdışıysa 30 gün boyunca
    /// sunucuda ZORLA duruyordu ve gönderenin hiçbir çaresi yoktu.
    ///
    /// Bu ayrı işlem o boşluğu kapatıyor ve kötüye kullanıma açık değil:
    /// sunucu SADECE `depositor == requester` olan satırları siler, yani
    /// yalnızca kendi bıraktığınızı geri çekebilirsiniz. Alıcı paketi
    /// çekmişse zaten kutuda değildir; o durumda geri çekme etkisizdir ve
    /// silme normal "herkesten sil" mesajıyla yapılır.
    Cancel { mailbox: MailboxId, seqs: Vec<u64> },

    // --- arşiv (geçmiş) ---
    /// Geçmiş kayıtlarını yükle. `bucket`, `server_seal::server_archive_bucket`
    /// çıktısı — sohbet + AY bazlı (bkz. o fonksiyonun notu).
    ArchivePut {
        bucket: MailboxId,
        records: Vec<ArchiveRecord>,
    },

    /// "Bu kovalardan hangileri var ve ne kadar dolu?" Sıfırdan kurulan bir
    /// cihaz, son ~24-60 ayın kovasını TEK istekte yoklar; sunucunun
    /// yıllarca izlenebilir KALICI bir sohbet dizini tutması gerekmez.
    ArchiveProbe { buckets: Vec<MailboxId> },

    /// Bir kovadan sayfa (yeniden eskiye). `before_ms: None` = en yeni sayfa.
    ArchiveFetch {
        bucket: MailboxId,
        before_ms: Option<u64>,
        max_items: u32,
        max_bytes: u32,
    },

    /// "Geçmişimi bu sunucudan sil." Ayarlardaki görünür eyleme ve
    /// `remove_server`'a bağlıdır. Sunucunun gerçekten sildiğini
    /// KANITLAYAMAYIZ — bu SECURITY.md'de yazılı.
    ArchivePurge { buckets: Vec<MailboxId> },

    // --- dosya eki blob'ları (SADECE yükleme yönü) ---
    /// Bir dosya parçasını yükle.
    ///
    /// İNDİRME yönü burada YOK: sunucu, istemcilerin ZATEN konuştuğu
    /// `/p2pmessenger/filexfer/1.0.0` protokolünü `ProtocolSupport::Inbound`
    /// ile kaydeder, yani sunucudaki bir ek sadece "başka bir kaynak eş"tir.
    /// Böylece istemcideki TÜM indirme durum makinesi (sıralı parçalar,
    /// `append_verified_chunk`, `alt_source_peer_ids` rotasyonu,
    /// `retry_or_give_up_download`, `check_stalled_downloads`, bütün-dosya
    /// SHA-256 kontrolü) HİÇ DEĞİŞMEDEN yeniden kullanılır.
    ///
    /// `data` diskteki `.enc` dosyasından OLDUĞU GİBİ okunur —
    /// `attachments.rs`'in "disk formatı = kablo formatı" özelliği sayesinde
    /// yeniden şifreleme YOK (bkz. `read_chunk_from_disk`).
    BlobPut {
        blob_id: String,
        chunk_index: u32,
        total_chunks: u32,
        /// Bu blob'un parca ADIMI (bayt, AEAD etiketi HARIC).
        ///
        /// Sunucu parcayi `chunk_index * (chunk_size + 16)` konumuna yaziyor.
        /// Bu alan olmadan sunucu adimi KENDI sabitinden tahmin ediyordu ve
        /// istemci farkli bir boyut kullandigi anda 0'dan sonraki her parca
        /// YANLIS konuma gidiyordu: dosya bozuluyor, bitiste hash tutmuyor,
        /// blob reddediliyor ve istemci sonsuza dek yeniden deniyordu.
        /// Gercek cihazda tam olarak bu oldu ve bir hiz olcumunu de
        /// gecersiz kildi.
        ///
        /// `#[serde(default)]` + 0 = miras 256 KiB, yani guncellenmemis bir
        /// istemci eskisi gibi calisir.
        #[serde(default)]
        chunk_size: u32,
        data: Vec<u8>,
    },

    /// Yüklemeyi tamamla ve blob'u servis edilebilir işaretle.
    ///
    /// `enc_sha256` ŞİFRELİ baytlar üzerindedir — sunucu bunu doğrulayabilir
    /// (içeriği çözemese de) ve kırpılmış bir yüklemeyi asla servis etmez.
    BlobFinish {
        blob_id: String,
        total_chunks: u32,
        enc_sha256: Vec<u8>,
    },

    BlobDelete { blob_id: String },

    // --- sunucu -> istemci (yönü TERS olan tek istek) ---
    /// "Posta var." Yükün KENDİSİ burada taşınmaz ve kutu kimlikleri de
    /// listelenmez: istemci `Ok` yanıtlar ve bir sonraki `poll_events`
    /// turunda `Fetch` eder. Kimlikleri listelemek, kötü niyetli bir eşe
    /// yoklama imkânı verirdi ve zaten gereksiz — `Fetch` ucuz.
    Notify,
}

// ---------------------------------------------------------------------------
// Yanıt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerResponse {
    Welcome {
        version: u16,
        /// Tek kullanımlık `Enroll` imza girdisi (32 bayt rastgele).
        challenge: Vec<u8>,
        enrolled: bool,
        limits: ServerLimits,
        server_name: String,
    },
    Enrolled {
        enrollment_id: Vec<u8>,
        limits: ServerLimits,
    },
    /// Zarf DİSKE yazıldı.
    ///
    /// `try_publish_raw` bunu "sent" olarak raporlar — `gossipsub.publish()`'in
    /// yerel başarısından KESİNLİKLE daha güçlü bir garanti, ama hâlâ uçtan
    /// uca DEĞİL: uçtan uca teslimin tek kanıtı karşı tarafın
    /// `MessageContent::Ack`'idir (bkz. lib.rs `awaiting_confirmation`).
    /// Bu yüzden `Deposited`, gossipsub yolunu KALICI OLARAK susturmaz —
    /// bkz. lib.rs `should_shadow_on_gossipsub` (kara delik kuralı).
    Deposited { seq: u64 },
    Batch { items: Vec<MailItem>, more: bool },
    ArchiveProbed { present: Vec<BucketStat> },
    ArchiveBatch { records: Vec<ArchiveRecord>, more: bool },
    Ok,
    Err(ServerErrorCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerErrorCode {
    /// Bu `PeerId` kayıtlı değil — istemci `Enroll`/`Rebind` başlatmalı.
    NotEnrolled,
    /// Jeton geçersiz/tükendi/süresi doldu.
    BadInvite,
    BadSignature,
    /// `ts_ms`, `ENROLL_MAX_SKEW_MS` penceresi dışında.
    Stale,
    /// Bu sunucuda HİÇ KİMSE bu kutuyu kaydetmemiş.
    ///
    /// İstemci bunu "bu alıcı benim sunucumda değil" diye okur ve o kişiye
    /// giden trafiği bir süre (bkz. lib.rs `server_unknown_mailboxes`)
    /// DOĞRUDAN gossipsub'a yollar — her mesaj başına boşuna bir gidiş-dönüş
    /// ödememek için.
    UnknownMailbox,
    /// Öğe `ServerLimits.max_item_bytes`'ı aşıyor — AYNI baytlarla yeniden
    /// denemek asla başaramaz, KALICI hata.
    TooLarge,
    /// Kota doldu. KALICI DEĞİL: kullanıcı sunucuda yer açabilir.
    QuotaExceeded,
    RateLimited,
    /// Operatör bu kaydı iptal etti.
    Revoked,
    /// Yön hatası — ör. istemciye gelen bir `Deposit`.
    BadDirection,
    Unsupported,
    Internal,
}

impl ServerErrorCode {
    /// Bu hata AYNI baytlarla yeniden denenirse başarabilir mi?
    ///
    /// Çağıran (`try_publish_raw`) bunu `PublishFailure::Permanent` /
    /// `Transient` ayrımına çevirir; yanlış sınıflandırma bu depoda daha önce
    /// gerçek bir hataya yol açmış bir konu (bkz. lib.rs `PublishFailure`
    /// dokümantasyonu — kalıcı bir hatayı geçici saymak 2 gün boyunca boşuna
    /// yeniden denemek, tersi ise kurtarılabilir bir mesajı kaybetmek demek).
    pub fn is_permanent(self) -> bool {
        matches!(
            self,
            ServerErrorCode::TooLarge | ServerErrorCode::Unsupported | ServerErrorCode::BadDirection
        )
    }

    /// İstemci bu hatayı görünce sunucuyla ilişkisini yeniden kurmalı mı?
    pub fn needs_reenroll(self) -> bool {
        matches!(self, ServerErrorCode::NotEnrolled)
    }
}

// ---------------------------------------------------------------------------
// Yardımcı tipler
// ---------------------------------------------------------------------------

/// Posta kutusundaki tek bir öğe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailItem {
    /// Bu öğenin hangi kutudan geldiği — istemci DOĞRU kutunun imlecini
    /// ilerletebilsin diye. Tek bir `Fetch` birden çok kutuyu sorduğundan
    /// bu alan olmadan yanıt ayrıştırılamaz.
    pub mailbox_id: MailboxId,
    /// Sunucunun atadığı, KESİN OLARAK ARTAN sıra numarası (SQLite
    /// AUTOINCREMENT rowid — sunucu genelinde global, dolayısıyla her tek
    /// kutu içinde de artan, ki imlecin ihtiyacı olan tam da bu).
    ///
    /// İstemci imlecini (`server_cursors` tablosu) ancak öğeyi İŞLEDİKTEN
    /// SONRA ilerletir. Yani garanti "en az bir kez"dir, "en fazla bir kez"
    /// DEĞİL — süreç yığının ortasında ölürse öğeler tekrar gelir. Bu
    /// KASITLI: tersi (işlemeden önce ilerletmek) bir çökmede mesajı SESSİZCE
    /// kaybetmek olurdu. Tekrar gelen öğe zaten güvenli: `message_id` dedup'ı
    /// ve tüketilmiş ratchet anahtarının çözülememesi bunu yutar.
    pub seq: u64,
    pub deposited_at_ms: u64,
    /// `server_seal::seal_envelope`/`frame_unsealed` çıktısı — sunucu için opak.
    pub sealed: Vec<u8>,
}

/// `ArchiveProbe` yanıtındaki tek bir kova özeti.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketStat {
    pub bucket: MailboxId,
    pub count: u32,
    pub oldest_ms: u64,
    pub newest_ms: u64,
}

/// Sunucudaki geçmiş arşivinin tek bir satırı.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveRecord {
    /// Bütün cihazlarda ve her iki uçta AYNI olan kararlı kimlik: 1:1'de
    /// `message_id`, grupta `group_message_local_id`. Sunucu
    /// `(bucket, record_id)` üzerinde dedup ettiğinden, aynı alınan mesajı
    /// N cihazımın yüklemesi TEK satıra mal olur.
    pub record_id: String,
    /// Monoton revizyon — Edit/Delete eskisinin ÜZERİNE yazsın diye
    /// (`edited_at_ms`/`deleted_at_ms`, yoksa `sent_at_ms`). Sunucu
    /// `WHERE excluded.rev > archive.rev` ile uygular.
    ///
    /// Bu, mevcut `HistorySyncResponse` mekanizmasının YAPAMADIĞI bir şey:
    /// geç gelen bir Edit'i geçmişte düzeltmek.
    pub rev: u64,
    /// Sunucunun ÇÖZMEDEN yeniden-eskiye sayfalayabilmesi için. Mesajın
    /// duvar saati zamanını sunucuya sızdırır — kabul edilmiş bir bedel,
    /// sunucu zaten `deposited_at_ms`'i görüyor.
    pub sent_at_ms: u64,
    /// `server_seal::seal_archive_record` çıktısı.
    pub sealed: Vec<u8>,
}

/// Sunucunun ilan ettiği sınırlar.
///
/// İstemci bunları `Welcome`'da alır ve KENDİ tarafında da uygular (ör.
/// tavanı aşan bir zarfı sunucuya hiç göndermez) — sunucuya boşuna bayt
/// yollamamak ve `TooLarge` gidiş-dönüşünü hiç yapmamak için.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLimits {
    pub max_item_bytes: u32,
    pub max_mailboxes: u32,
    pub max_items_per_mailbox: u32,
    pub max_mail_bytes: u64,
    pub max_archive_bytes: u64,
    pub max_blob_bytes: u64,
    pub mailbox_ttl_ms: u64,
    pub blob_ttl_ms: u64,
    pub requests_per_minute: u32,
}

impl Default for ServerLimits {
    /// Küçük bir arkadaş grubu için makul varsayılanlar — `typeon-server`
    /// bunları yapılandırmadan okur, buradaki değerler sadece bir taban.
    fn default() -> Self {
        ServerLimits {
            // Modül başındaki "Boyut tavanı" notu — codec'in 1 MiB'lık SERT
            // sınırının altında kalmak zorunlu.
            max_item_bytes: MAX_DEPOSIT_BYTES as u32,
            max_mailboxes: 512,
            max_items_per_mailbox: 5_000,
            max_mail_bytes: 256 * 1024 * 1024,
            max_archive_bytes: 1024 * 1024 * 1024,
            max_blob_bytes: 4 * 1024 * 1024 * 1024,
            // 30 gün: mevcut gönderen-tarafı vazgeçme süresinin
            // (`TEXT_RETRY_GIVE_UP_MS` = 2 gün) çok üstünde — dayanıklılığın
            // asıl sınırı artık burası.
            mailbox_ttl_ms: 30 * 24 * 60 * 60 * 1000,
            blob_ttl_ms: 30 * 24 * 60 * 60 * 1000,
            requests_per_minute: 1_800,
        }
    }
}

// ---------------------------------------------------------------------------
// Davet kodu
// ---------------------------------------------------------------------------

/// Davet kodu şeması. QR ve elle yapıştırma AYNI metni taşır (mevcut
/// `processManualEntry` deseniyle aynı mantık: tek bir kanonik metin, iki
/// giriş yolu).
pub const SERVER_INVITE_SCHEME: &str = "typeon-server:";

/// Davet kodu ayrıştırma sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInvite {
    /// Sunucunun BÜTÜN ilan edilen adresleri — onion VE varsa LAN/genel IP.
    ///
    /// Neden çoğul: tek adres taşındığında ve o adres onion olduğunda, aynı
    /// yerel ağdaki iki cihaz bile bütün trafiği Tor üzerinden geçiriyordu.
    /// Ölçüldü: 10 MB'lık bir dosya ~12 KB/s ile yükleniyordu. libp2p aynı
    /// `PeerId`'ye birden fazla eşzamanlı dial'ı zaten yönetiyor (ilk kuran
    /// kazanır), dolayısıyla hepsini vermek doğrudan hız kazancı — onion da
    /// listede kaldığı için CGNAT arkasındaki ulaşılabilirlik kaybolmuyor.
    pub addrs: Vec<String>,
    pub token: String,
}

impl ServerInvite {
    /// Kayıt için kullanılacak `PeerId`'yi taşıyan ilk adres.
    pub fn first_addr(&self) -> Option<&String> {
        self.addrs.first()
    }
}

/// `typeon-server:<adres>[,<adres>...]#<jeton>` ayrıştırır.
///
/// Jeton `#`'ten SONRA: bir multiaddr asla `#` içermez, bu yüzden ayrım tek
/// anlamlıdır. Jeton opak bir dize olarak taşınır (sunucu ne ürettiyse) —
/// burada bir kodlama varsayımı YOK.
pub fn parse_server_invite(text: &str) -> Result<ServerInvite, String> {
    let trimmed = text.trim();
    let body = trimmed
        .strip_prefix(SERVER_INVITE_SCHEME)
        .ok_or_else(|| format!("Kod '{}' ile başlamalı", SERVER_INVITE_SCHEME))?;
    let (addr_part, token) = body
        .split_once('#')
        .ok_or("Kodda davet jetonu ('#' sonrası) yok")?;
    // Adresler virgülle ayrılır — bir multiaddr ne `#` ne de `,` içerir,
    // dolayısıyla iki ayrım da tek anlamlı. Tek adresli ESKİ kodlar da
    // ayrıştırılmaya devam eder.
    let addrs: Vec<String> = addr_part
        .split(',')
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect();
    if addrs.is_empty() {
        return Err("Kodda sunucu adresi yok".to_string());
    }
    if token.trim().is_empty() {
        return Err("Kodda davet jetonu boş".to_string());
    }
    Ok(ServerInvite { addrs, token: token.trim().to_string() })
}

/// `parse_server_invite`'ın tersi — sunucu uygulaması QR/kopyalanabilir kod
/// üretirken kullanır. BÜTÜN adresleri taşır (bkz. `ServerInvite.addrs`).
pub fn format_server_invite(addrs: &[String], token: &str) -> String {
    let joined = addrs.iter().map(|a| a.trim()).collect::<Vec<_>>().join(",");
    format!("{}{}#{}", SERVER_INVITE_SCHEME, joined, token.trim())
}

/// `Enroll.sig`'in üzerinde hesaplandığı baytlar. İstemci ve sunucu AYNI
/// fonksiyonu çağırır — imza girdisini iki yerde elle kurmak, bu tür
/// protokollerde klasik bir uyumsuzluk kaynağı.
pub fn enroll_signing_input(version: u16, server_peer_id: &str, invite_token: &[u8], challenge: &[u8], ts_ms: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(server_peer_id.as_bytes());
    out.extend_from_slice(invite_token);
    out.extend_from_slice(challenge);
    out.extend_from_slice(&ts_ms.to_be_bytes());
    out
}

/// `Rebind.sig`'in üzerinde hesaplandığı baytlar.
pub fn rebind_signing_input(enrollment_id: &[u8], server_peer_id: &str, ts_ms: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(enrollment_id);
    out.extend_from_slice(server_peer_id.as_bytes());
    out.extend_from_slice(&ts_ms.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_carries_every_address() {
        // Tek adres tasindiginda (ve o onion oldugunda) ayni LAN'daki iki
        // cihaz bile butun trafigi Tor'dan geciriyordu — olculen fark 10x'ten
        // fazlaydi. Kod artik hepsini tasir.
        let addrs = vec![
            "/dns/abcdef.onion/tcp/42612/p2p/12D3KooWTest".to_string(),
            "/ip4/192.168.1.5/tcp/42612/p2p/12D3KooWTest".to_string(),
        ];
        let code = format_server_invite(&addrs, "ABC123");
        let parsed = parse_server_invite(&code).expect("ayristirilmali");
        assert_eq!(parsed.addrs, addrs);
        assert_eq!(parsed.token, "ABC123");
    }

    #[test]
    fn single_address_invites_still_parse() {
        let code = "typeon-server:/ip4/1.2.3.4/tcp/1/p2p/12D3KooWTest#TOK";
        let parsed = parse_server_invite(code).expect("ayristirilmali");
        assert_eq!(parsed.addrs.len(), 1);
        assert_eq!(parsed.token, "TOK");
    }

    #[test]
    fn invite_rejects_missing_token_and_wrong_scheme() {
        assert!(parse_server_invite("typeon-server:/ip4/1.2.3.4/tcp/1/p2p/x").is_err());
        assert!(parse_server_invite("/ip4/1.2.3.4/tcp/1/p2p/x#tok").is_err());
        assert!(parse_server_invite("typeon-server:#tok").is_err());
    }

    #[test]
    fn error_permanence_classification() {
        // Kalıcı: aynı baytlarla asla başaramaz.
        assert!(ServerErrorCode::TooLarge.is_permanent());
        assert!(ServerErrorCode::Unsupported.is_permanent());
        // Geçici: kullanıcı yer açabilir / sınır sıfırlanır / kayıt yenilenir.
        assert!(!ServerErrorCode::QuotaExceeded.is_permanent());
        assert!(!ServerErrorCode::RateLimited.is_permanent());
        assert!(!ServerErrorCode::UnknownMailbox.is_permanent());
        assert!(ServerErrorCode::NotEnrolled.needs_reenroll());
    }

    #[test]
    fn deposit_cap_stays_below_the_codec_hard_limit() {
        // Modül başındaki notun testi: libp2p-request-response'un CBOR
        // codec'i istekleri 1 MiB'da KIRPAR. Bu sabit oraya yaklaşırsa
        // zarflar sessizce bozulmaya başlar.
        assert!(MAX_DEPOSIT_BYTES < 1024 * 1024, "codec sert sinirini asamaz");
        assert!(ServerLimits::default().max_item_bytes as usize <= MAX_DEPOSIT_BYTES);
    }

    #[test]
    fn signing_inputs_bind_every_field() {
        let base = enroll_signing_input(1, "peer", b"tok", b"chal", 100);
        assert_ne!(base, enroll_signing_input(2, "peer", b"tok", b"chal", 100));
        // Sunucu kimliği imzaya dahil olmalı — yoksa bir sunucu, aldigi
        // Enroll'u baska bir sunucuya karsi tekrar oynatabilirdi.
        assert_ne!(base, enroll_signing_input(1, "other", b"tok", b"chal", 100));
        assert_ne!(base, enroll_signing_input(1, "peer", b"tok2", b"chal", 100));
        // Challenge imzaya dahil olmali — yoksa yakalanan bir imza, taze bir
        // baglantida hala gecerli olurdu.
        assert_ne!(base, enroll_signing_input(1, "peer", b"tok", b"chal2", 100));
        assert_ne!(base, enroll_signing_input(1, "peer", b"tok", b"chal", 101));

        let rb = rebind_signing_input(b"eid", "peer", 100);
        assert_ne!(rb, rebind_signing_input(b"eid", "other", 100));
        assert_ne!(rb, rebind_signing_input(b"eid2", "peer", 100));
    }
}

/// Bir multiaddr ÖZEL bir ağ adresi mi?
///
/// Tek tanım, iki taraf: sunucu bunu davet kodundan eleme için, istemci ise
/// kaydettiği/aradığı sunucu adreslerini elemek için kullanır. İki kopya
/// olsaydı biri düzeltilip diğeri unutulurdu — nitekim tam olarak bu oldu:
/// sunucu tarafı elemeye başladıktan sonra da istemcilerde ESKİ davetlerden
/// kalma `192.168.x.x` adresleri duruyordu ve libp2p bütün adresleri aynı
/// anda deneyip LAN'ı kazandırıyordu. Ölçüm o yüzden "Tor" değil LAN
/// ölçüyordu (~1.75 MB/s), oysa aynı yerel ağdaki iki kişinin yazışması
/// gerçekçi bir senaryo değil.
pub fn is_private_multiaddr(addr: &str) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};
    for part in addr.split('/') {
        if let Ok(v4) = part.parse::<Ipv4Addr>() {
            if v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                return true;
            }
        }
        if let Ok(v6) = part.parse::<Ipv6Addr>() {
            // fc00::/7 (unique-local) ve fe80::/10 (link-local) — `std`'de
            // kararlı bir yardımcı yok, önekten bakıyoruz.
            let o = v6.octets();
            if v6.is_loopback()
                || v6.is_unspecified()
                || (o[0] & 0xfe) == 0xfc
                || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80)
            {
                return true;
            }
        }
    }
    false
}

/// Bir sunucu için SAKLANMAYA/aranmaya değer adresler — özel ağ adresleri
/// elenmiş hâli (bkz. `is_private_multiaddr`). Hepsi elendiyse liste boş
/// döner; çağıran bunu "bu davet kullanılamaz" diye okumalı.
pub fn public_server_addrs<I, S>(addrs: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    addrs
        .into_iter()
        .map(|a| a.as_ref().trim().to_string())
        .filter(|a| !a.is_empty() && !is_private_multiaddr(a))
        .collect()
}

/// Sunucunun kabul edeceği EN BÜYÜK blob parçası (bayt).
///
/// Parça boyutu artık istemci tarafında dosya başına seçiliyor (bkz.
/// `attachments::FILE_CHUNK_SIZE_V2`), dolayısıyla sunucunun doğrulaması da
/// TEK bir boyuta çakılı olamaz. Nitekim öyleydi: sunucu miras 256 KiB'a
/// göre kontrol ediyor ve 512 KiB'lık her parçayı `TooLarge` ile
/// reddediyordu — aktarım hiç ilerlemiyordu.
///
/// Tavan `request_response` CBOR codec'inin 1 MiB'lık SERT istek sınırından
/// geliyor (`REQUEST_SIZE_MAXIMUM`; aşılırsa istek sessizce KIRPILIR ve
/// çözümleme başarısız olur). 768 KiB, hem 512 KiB'lık parçaya + AEAD
/// etiketine + CBOR çerçevelemesine rahatça yer bırakıyor hem de sınırın
/// belirgin biçimde altında kalıyor.
pub const MAX_BLOB_CHUNK_BYTES: usize = 768 * 1024;
