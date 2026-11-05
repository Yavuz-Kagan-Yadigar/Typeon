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

/// Live call-media relay: ONE long-lived libp2p stream per client, opened by
/// the client while it is in a call. Frames are `[u16 mailbox len][mailbox]
/// [u32 len][data]` (core `call::encode_frame`). Client -> server: "push
/// `data` to whoever is connected and listening on `mailbox`" (the target's
/// `key_bound_mailbox_id` of the pair key, registered for the call). The sender is
/// not checked against the readers of `mailbox`: the id is its capability,
/// and the receiver registers it, not the sender. Server -> client: the same frame with an empty
/// mailbox. Nothing is stored: a target that is not connected right now
/// simply misses the frame, which is the right thing for live audio/video.
/// `data` is already end-to-end encrypted with a per-call key the server
/// never sees (it travels inside the ratchet, `MessageContent::Call`).
pub const RELAY_PROTOCOL: &str = "/typeon/relay/1.0.0";

/// Kablo formatı sürümü — `Hello`/`Welcome` içinde takas edilir.
/// 2: `Register` answers `Registered { proof_needed, refused }`.
/// 4: blob requests carry `upload_secret` instead of `blob_id`.
/// 5: session and relay mailbox ids are made from their proof key
///    (`key_bound_mailbox_id`); the server refuses any other key for them.
/// 6: upload secrets are 24 bytes and start with the file's author tag
///    (`blob_id_for_upload_secret`).
/// 7: the id hashes only the secret's bytes after the tag (I-42: a group
///    file's tag is then made per file, see core `group_msg_tag`).
pub const SERVER_PROTOCOL_VERSION: u16 = 7;

/// Tek bir `Deposit`in azami yükü. Modül başındaki "Boyut tavanı" notuna
/// bakın: codec'in sert sınırı 1 MiB, buradaki pay CBOR enum/alan
/// çerçevelemesi için. Bunu aşan zarf sunucuya DENENMEZ.
pub const MAX_DEPOSIT_BYTES: usize = 900 * 1024;

/// Tek bir `Fetch` yanıtının azami boyutu. Codec 10 MiB'a izin verir ama
/// bu yanıt, ~1 Hz'lik `poll_events` turunun İÇİNDE çözülüp işleniyor —
/// büyük bir yığın, mesaj listesini süren döngüyü doğrudan takar.
pub const MAX_FETCH_BATCH_BYTES: u32 = 512 * 1024;
pub const MAX_FETCH_BATCH_ITEMS: u32 = 64;

/// Records in one `ArchivePut`. The client sends up to 50; each record costs
/// the server a SELECT + INSERT inside its single event loop.
pub const MAX_ARCHIVE_PUT_RECORDS: usize = 256;

/// `Enroll`/`Rebind` zaman damgası toleransı. Bu kadar eski/ileri bir imza
/// reddedilir (`ServerErrorCode::Stale`).
pub const ENROLL_MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// A mailbox address: `key_bound_mailbox_id` of a session or relay box
/// (`mk_<hex16>`), `server_seal::first_contact_mailbox_id` (`mb_<hex16>`),
/// or an archive bucket (`ar_<hex16>`). The server reads nothing from it
/// except the `mk_` prefix, which makes it check the `Register` proof key.
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
        #[serde(with = "serde_bytes")]
        invite_token: Vec<u8>,
        /// Ed25519 public key (32 bayt).
        #[serde(with = "serde_bytes")]
        enroll_pk: Vec<u8>,
        /// ML-DSA-87 public key (2592 bayt). İmza uygulamanın geri kalanıyla
        /// AYNI şekilde HİBRİT: klasik bir imza tek başına, hasat-şimdi-
        /// kır-sonra bir saldırgana ileride sahte kayıt üretme imkânı
        /// verirdi. Gizliliği etkilemezdi (içerik şifrelemesi bu imzaya
        /// bağlı değil) ama depodaki "her imza hibrittir" kuralını bozardı.
        #[serde(with = "serde_bytes")]
        enroll_pk_pq: Vec<u8>,
        /// AZ ÖNCE gelen `Welcome.challenge`. İmza girdisine DAHİL (bkz.
        /// `enroll_signing_input`): sunucu tarafında tek kullanımlık
        /// olmasının yanında, imzayı O BAĞLANTIYA bağlar — aksi halde
        /// yakalanan bir imza, sunucunun yeni bir challenge ürettiği taze
        /// bir bağlantıda hâlâ geçerli olurdu.
        #[serde(with = "serde_bytes")]
        challenge: Vec<u8>,
        ts_ms: u64,
        /// Ed25519 imzası.
        #[serde(with = "serde_bytes")]
        sig: Vec<u8>,
        /// ML-DSA-87 imzası — AYNI baytlar üzerinde. İkisi de doğrulanmalı.
        #[serde(with = "serde_bytes")]
        sig_pq: Vec<u8>,
    },

    /// Var olan bir kaydı YENİ bir libp2p `PeerId`'ye bağla — uygulama
    /// yeniden kurulduğunda/`libp2p_identity.key` kaybolduğunda. `enroll_pk`
    /// sahipliğini kanıtlar, davet jetonu TÜKETMEZ (aksi halde tek
    /// kullanımlık bir davetle kurulan bir cihaz, bir kez yeniden kurulumdan
    /// sonra sunucuya bir daha bağlanamazdı).
    ///
    /// İmza girdisi: bkz. `rebind_signing_input` (the `Hello` challenge and
    /// the caller's PeerId are part of it, neither travels in the request).
    Rebind {
        #[serde(with = "serde_bytes")]
        enrollment_id: Vec<u8>,
        ts_ms: u64,
        #[serde(with = "serde_bytes")]
        sig: Vec<u8>,
        #[serde(with = "serde_bytes")]
        sig_pq: Vec<u8>,
    },

    // --- posta kutusu (transit) ---
    /// Hangi kutularla ilgilendiğimizi bildir. İdempotent.
    ///
    /// İki işi birden yapar: (a) sunucu bu kutulara gelen zarfları kabul
    /// eder ve `Fetch`'e servis eder, (b) yeni bir şey düştüğünde `Notify`
    /// ile İTEBİLİR. `drop`, rotasyonda artık dinlenmeyen bir nesil eski
    /// topic'i geri alır.
    ///
    /// An id this enrollment does not read yet needs a `MailboxProof` in
    /// `proofs`. Without one the id comes back in `Registered.proof_needed`
    /// and the client sends it again with a proof. An id in
    /// `Registered.refused` is refused for good (mailbox cap, reader cap,
    /// bad proof, other key): sending it again gets the same answer.
    Register {
        add: Vec<MailboxId>,
        drop: Vec<MailboxId>,
        proofs: Vec<MailboxProof>,
    },

    /// Mühürlü bir zarfı kutuya bırak.
    ///
    /// Kota, kutunun SAHİBİNE değil BIRAKANA yazılır — bir spam gönderici
    /// kendi kotasını yakar ve kimse bir kurbanın kutusunu doldurup ona
    /// hizmet reddi uygulayamaz.
    Deposit { mailbox: MailboxId, #[serde(with = "serde_bytes")] sealed: Vec<u8> },

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
    ///
    /// Server trust: the server can answer with an OLDER revision of a
    /// record (or leave records out). The seal stops forgery, not rollback;
    /// only a device that keeps its own `record_id`/`rev` state notices
    /// (see `server_seal` KNOWN LIMIT).
    ArchiveFetch {
        bucket: MailboxId,
        /// Cursor: the last record of the previous page, `(before_ms,
        /// before_id)`; many records share an (hour-coarsened) `sent_at_ms`.
        before_ms: Option<u64>,
        #[serde(default)]
        before_id: Option<String>,
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
        /// The uploader's secret; the server stores the blob under
        /// `blob_id_for_upload_secret(upload_secret)`, which is the file id
        /// recipients download by. A recipient knows only that id, so it
        /// cannot claim the blob before the sender uploads it.
        #[serde(with = "serde_bytes")]
        upload_secret: Vec<u8>,
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
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },

    /// Yüklemeyi tamamla ve blob'u servis edilebilir işaretle.
    ///
    /// `enc_sha256` ŞİFRELİ baytlar üzerindedir — sunucu bunu doğrulayabilir
    /// (içeriği çözemese de) ve kırpılmış bir yüklemeyi asla servis etmez.
    BlobFinish {
        #[serde(with = "serde_bytes")]
        upload_secret: Vec<u8>,
        total_chunks: u32,
        #[serde(with = "serde_bytes")]
        enc_sha256: Vec<u8>,
    },

    BlobDelete {
        #[serde(with = "serde_bytes")]
        upload_secret: Vec<u8>,
    },

    // --- sunucu -> istemci (yönü TERS olan tek istek) ---
    /// "Posta var." Yükün KENDİSİ burada taşınmaz ve kutu kimlikleri de
    /// listelenmez: istemci `Ok` yanıtlar ve bir sonraki `poll_events`
    /// turunda `Fetch` eder. Kimlikleri listelemek, kötü niyetli bir eşe
    /// yoklama imkânı verirdi ve zaten gereksiz — `Fetch` ucuz.
    Notify,

    /// `Notify` WITH the item, saving the client's `Fetch` round trip (1-2 s
    /// over Tor on mobile data — most of a call ring's delay). The server only
    /// sends it when this item is the reader's ONLY unacknowledged one in the
    /// mailbox, so processing it and moving the cursor to its `seq` cannot
    /// skip anything; otherwise it sends a plain `Notify`.
    Push { item: MailItem },
}

// ---------------------------------------------------------------------------
// Yanıt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerResponse {
    Welcome {
        version: u16,
        /// Tek kullanımlık `Enroll` imza girdisi (32 bayt rastgele).
        #[serde(with = "serde_bytes")]
        challenge: Vec<u8>,
        enrolled: bool,
        /// The id of this PeerId's active enrollment (with `enrolled`): a
        /// client whose `Enrolled` answer was lost gets it back here.
        #[serde(with = "serde_bytes")]
        enrollment_id: Option<Vec<u8>>,
        limits: ServerLimits,
        server_name: String,
    },
    Enrolled {
        #[serde(with = "serde_bytes")]
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
    /// `Register` with ids that were not registered; every other id of `add`
    /// is. `proof_needed`: came without a `MailboxProof`, send again with one.
    /// `refused`: over `ServerLimits.max_mailboxes`, over the reader cap, a
    /// proof that did not verify or a key other than the mailbox's: do not
    /// send again. All ids registered = plain `Ok`.
    Registered { proof_needed: Vec<MailboxId>, refused: Vec<MailboxId> },
    Ok,
    Err(ServerErrorCode),
}

/// Proof that the sender of a `Register` owns `mailbox`: a hybrid signature
/// over `register_signing_input` by the mailbox key. The readers derive the
/// key from a secret only they hold (`server_seal::mailbox_proof_seeds`).
///
/// A session or relay mailbox has an id made from that key
/// (`key_bound_mailbox_id`), so the server takes no other key for it: knowing
/// the id is not enough to read it. A first-contact mailbox cannot work that
/// way (its proof key is the reading device's alone, and the sender, who only
/// holds the pairing code, must still compute the id), so there the server
/// keeps each reader's key and takes at most two readers per key; another key
/// gets slots of its own (a first-come binding let anyone who knew a
/// first-contact id lock its device out).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxProof {
    pub mailbox: MailboxId,
    #[serde(with = "serde_bytes")]
    pub pk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pk_pq: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig_pq: Vec<u8>,
}

/// Proofs in one `Register`: each is about 7.3 KB and the request cap is
/// 1 MiB (`MAX_DEPOSIT_BYTES` note).
pub const MAX_REGISTER_PROOFS: usize = 64;

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
    /// `BlobFinish`: the stored bytes do not hash to `enc_sha256` (or cannot
    /// be read). Deterministic — sending the same finish again never works.
    BadHash,
    /// `BlobFinish`: the server has no complete upload under this id (the
    /// half-done blob was swept, or chunks are missing). Not permanent: the
    /// client uploads again from chunk 0.
    BlobIncomplete,
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
            ServerErrorCode::TooLarge | ServerErrorCode::Unsupported | ServerErrorCode::BadDirection | ServerErrorCode::BadHash
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
    /// Sunucunun atadığı, kutu içinde KESİN OLARAK ARTAN sıra numarası
    /// (imlecin ihtiyacı olan tam da bu). It counts per mailbox (the server's
    /// `mail_seq` table): a server-global seq let any reader estimate the
    /// server-wide intake rate from gaps, so it must not become global again.
    ///
    /// İstemci imlecini (`server_cursors` tablosu) ancak öğeyi İŞLEDİKTEN
    /// SONRA ilerletir. Yani garanti "en az bir kez"dir, "en fazla bir kez"
    /// DEĞİL — süreç yığının ortasında ölürse öğeler tekrar gelir. Bu
    /// KASITLI: tersi (işlemeden önce ilerletmek) bir çökmede mesajı SESSİZCE
    /// kaybetmek olurdu. Tekrar gelen öğe zaten güvenli: `message_id` dedup'ı
    /// ve tüketilmiş ratchet anahtarının çözülememesi bunu yutar.
    pub seq: u64,
    pub deposited_at_ms: u64,
    /// `server_seal::seal_envelope`/`seal_first_contact` çıktısı — sunucu için opak.
    #[serde(with = "serde_bytes")]
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
    /// Sunucunun ÇÖZMEDEN yeniden-eskiye sayfalayabilmesi için. M-30: the
    /// client sends it floored to the hour (the exact time is inside
    /// `sealed`), so both ends' buckets are not joinable by time.
    pub sent_at_ms: u64,
    /// `server_seal::seal_archive_record` çıktısı.
    #[serde(with = "serde_bytes")]
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
            // 14 gün: gönderen-tarafı vazgeçme süresinin
            // (`TEXT_RETRY_GIVE_UP_MS` = 7 gün) üstünde — dayanıklılığın
            // asıl sınırı burası.
            mailbox_ttl_ms: 14 * 24 * 60 * 60 * 1000,
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

/// Signed bytes of the enrollment messages: a tag for the kind of message,
/// then every field with its length. Without the lengths, (peer "ab", token
/// "c…") and (peer "a", token "bc…") were the same bytes; without the tag,
/// the one enroll key signed `Enroll` and `Rebind` in a shared format.
///
/// PROTOCOL BREAK (2026-10-07): a client and a server on different sides of
/// this change cannot enroll or rebind with each other (`BadSignature`). A
/// device the server already knows by its peer id does neither, and goes on.
fn signing_input(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = tag.to_vec();
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// `Enroll.sig`'in üzerinde hesaplandığı baytlar. İstemci ve sunucu AYNI
/// fonksiyonu çağırır — imza girdisini iki yerde elle kurmak, bu tür
/// protokollerde klasik bir uyumsuzluk kaynağı.
///
/// Both enrollment keys and the client's PeerId are signed too: the
/// signature commits to the keys it is verified with and is useless from
/// any other PeerId.
#[allow(clippy::too_many_arguments)]
pub fn enroll_signing_input(
    version: u16,
    server_peer_id: &str,
    client_peer_id: &str,
    invite_token: &[u8],
    enroll_pk: &[u8],
    enroll_pk_pq: &[u8],
    challenge: &[u8],
    ts_ms: u64,
) -> Vec<u8> {
    signing_input(
        b"p2pmsg-v0.4-server-enroll",
        &[
            &version.to_be_bytes(),
            server_peer_id.as_bytes(),
            client_peer_id.as_bytes(),
            invite_token,
            enroll_pk,
            enroll_pk_pq,
            challenge,
            &ts_ms.to_be_bytes(),
        ],
    )
}

/// `Rebind.sig`'in üzerinde hesaplandığı baytlar.
///
/// `client_peer_id` and the `Hello` challenge are signed too: a Rebind that
/// leaks is useless from any other PeerId and on any other connection.
pub fn rebind_signing_input(
    enrollment_id: &[u8],
    server_peer_id: &str,
    client_peer_id: &str,
    challenge: &[u8],
    ts_ms: u64,
) -> Vec<u8> {
    signing_input(
        b"p2pmsg-v0.3-server-rebind",
        &[enrollment_id, server_peer_id.as_bytes(), client_peer_id.as_bytes(), challenge, &ts_ms.to_be_bytes()],
    )
}

/// The bytes a `MailboxProof` signs. The enrollment and the server are in
/// it: a proof read off the wire registers nothing for another enrollment
/// or at another server.
pub fn register_signing_input(mailbox: &str, enrollment_id: &[u8], server_peer_id: &str) -> Vec<u8> {
    signing_input(b"p2pmsg-v0.5-server-register", &[mailbox.as_bytes(), enrollment_id, server_peer_id.as_bytes()])
}

/// Start of every id made by `key_bound_mailbox_id`. The server checks the
/// key of a `Register` proof for these ids only.
pub const KEY_BOUND_MAILBOX_PREFIX: &str = "mk_";

/// The hash of a `MailboxProof` key pair that the server keeps per reader.
/// Both keys have a fixed length once the signature verifies, so the plain
/// concatenation is unambiguous.
pub fn mailbox_key_hash(pk: &[u8], pk_pq: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"p2pmsg-v0.7-mailbox-key");
    h.update(pk);
    h.update(pk_pq);
    h.finalize().into()
}

/// The id of a mailbox whose one proof key hashes to `key_hash`
/// (`mailbox_key_hash`). Both ends of a session (or of a call relay) derive
/// the key from the secret they share, so the sender computes the id too,
/// and the server can check that a proof is by the mailbox's own key.
pub fn key_bound_mailbox_id(key_hash: &[u8]) -> String {
    format!("{}{}", KEY_BOUND_MAILBOX_PREFIX, hex::encode(&key_hash[..key_hash.len().min(16)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_id_is_a_safe_hash_of_the_upload_secret() {
        let id = blob_id_for_upload_secret(&[7u8; BLOB_UPLOAD_SECRET_LEN]).unwrap();
        assert_eq!(id.len(), 48);
        assert!(id.starts_with(&"07".repeat(BLOB_TAG_LEN)));
        assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_ne!(id, blob_id_for_upload_secret(&[8u8; BLOB_UPLOAD_SECRET_LEN]).unwrap());
        // The id itself is no secret: sent back as one it names another blob.
        assert!(blob_id_for_upload_secret(id.as_bytes()).is_none());
        assert!(blob_id_for_upload_secret(&[7u8; 15]).is_none());
        assert!(id.ends_with(&blob_id_hash_hex(&[7u8; BLOB_UPLOAD_SECRET_LEN - BLOB_TAG_LEN])));
    }

    #[test]
    fn register_proof_is_bound_to_mailbox_enrollment_and_server() {
        let base = register_signing_input("mb_a", b"eid", "peer");
        assert_ne!(base, register_signing_input("mb_b", b"eid", "peer"));
        assert_ne!(base, register_signing_input("mb_a", b"eid2", "peer"));
        assert_ne!(base, register_signing_input("mb_a", b"eid", "other"));
    }

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
        assert!(ServerErrorCode::BadHash.is_permanent());
        // Geçici: kullanıcı yer açabilir / sınır sıfırlanır / kayıt yenilenir.
        assert!(!ServerErrorCode::QuotaExceeded.is_permanent());
        assert!(!ServerErrorCode::RateLimited.is_permanent());
        assert!(!ServerErrorCode::UnknownMailbox.is_permanent());
        assert!(!ServerErrorCode::BlobIncomplete.is_permanent());
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
        #[allow(clippy::too_many_arguments)]
        fn e(v: u16, sp: &str, cp: &str, tok: &[u8], pk: &[u8], pq: &[u8], ch: &[u8], ts: u64) -> Vec<u8> {
            enroll_signing_input(v, sp, cp, tok, pk, pq, ch, ts)
        }
        let base = e(1, "peer", "me", b"tok", b"pk", b"pq", b"chal", 100);
        assert_ne!(base, e(2, "peer", "me", b"tok", b"pk", b"pq", b"chal", 100));
        // Sunucu kimliği imzaya dahil olmalı — yoksa bir sunucu, aldigi
        // Enroll'u baska bir sunucuya karsi tekrar oynatabilirdi.
        assert_ne!(base, e(1, "other", "me", b"tok", b"pk", b"pq", b"chal", 100));
        assert_ne!(base, e(1, "peer", "thief", b"tok", b"pk", b"pq", b"chal", 100));
        assert_ne!(base, e(1, "peer", "me", b"tok2", b"pk", b"pq", b"chal", 100));
        assert_ne!(base, e(1, "peer", "me", b"tok", b"pk2", b"pq", b"chal", 100));
        assert_ne!(base, e(1, "peer", "me", b"tok", b"pk", b"pq2", b"chal", 100));
        // Challenge imzaya dahil olmali — yoksa yakalanan bir imza, taze bir
        // baglantida hala gecerli olurdu.
        assert_ne!(base, e(1, "peer", "me", b"tok", b"pk", b"pq", b"chal2", 100));
        assert_ne!(base, e(1, "peer", "me", b"tok", b"pk", b"pq", b"chal", 101));

        let rb = rebind_signing_input(b"eid", "peer", "me", b"chal", 100);
        assert_ne!(rb, rebind_signing_input(b"eid", "other", "me", b"chal", 100));
        assert_ne!(rb, rebind_signing_input(b"eid2", "peer", "me", b"chal", 100));
        // A replay from another PeerId or on another connection fails.
        assert_ne!(rb, rebind_signing_input(b"eid", "peer", "thief", b"chal", 100));
        assert_ne!(rb, rebind_signing_input(b"eid", "peer", "me", b"chal2", 100));

        // A shifted field boundary is another message, and an Enroll
        // signature is never a Rebind signature.
        assert_ne!(e(1, "ab", "c", b"t", b"k", b"q", b"chal", 100), e(1, "a", "bc", b"t", b"k", b"q", b"chal", 100));
        assert_ne!(e(1, "p", "m", b"tok", b"k", b"q", b"chal", 100), e(1, "p", "m", b"tokk", b"", b"q", b"chal", 100));
        assert_ne!(rebind_signing_input(b"ei", "dpeer", "me", b"c", 100), rebind_signing_input(b"eid", "peer", "me", b"c", 100));
        assert_ne!(rb[..25], base[..25], "different tags");
    }
}

/// Is `addr` an onion address? A server address is nothing else: any other
/// kind (an IP, or a DNS name that can resolve to a private address) is
/// refused in invites and server records. The first component decides.
pub fn is_onion_server_addr(addr: &str) -> bool {
    let mut parts = addr.split('/').skip(1);
    match (parts.next(), parts.next()) {
        (Some("dns" | "dns4" | "dns6"), Some(host)) => host.len() > ".onion".len() && host.ends_with(".onion"),
        (Some("onion3"), Some(_)) => true,
        _ => false,
    }
}

/// The addresses of a server worth storing and dialing: the onion ones
/// (see `is_onion_server_addr`). An empty result means "this invite cannot
/// be used".
pub fn public_server_addrs<I, S>(addrs: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    addrs
        .into_iter()
        .map(|a| a.as_ref().trim().to_string())
        .filter(|a| is_onion_server_addr(a))
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

/// Length of a blob upload secret (`BlobPut.upload_secret`): an 8-byte
/// author tag, shown in the id, then 16 secret bytes.
pub const BLOB_UPLOAD_SECRET_LEN: usize = 24;

/// Length of the author tag at the start of an upload secret.
pub const BLOB_TAG_LEN: usize = 8;

/// The blob (= file) id an upload secret stands for: 48 lower-case hex
/// characters, the secret's author tag in the clear and then
/// `blob_id_hash_hex` of the secret's other bytes. The sender picks the
/// secret, names only this id in its `FileOffer`, and proves ownership on
/// the server with the secret itself. The tag lets a group member check that
/// a file id belongs to the member who offers it (core `group_msg_tag`, made
/// from the hash part, so it differs per file); the server does not look at
/// it. `None` for a secret of the wrong length.
pub fn blob_id_for_upload_secret(upload_secret: &[u8]) -> Option<String> {
    if upload_secret.len() != BLOB_UPLOAD_SECRET_LEN {
        return None;
    }
    let (tag, rest) = upload_secret.split_at(BLOB_TAG_LEN);
    Some(format!("{}{}", hex::encode(tag), blob_id_hash_hex(rest)))
}

/// The id's part after the tag: a hash of the upload secret's bytes after
/// the tag (32 hex characters). Separate so the tag can be made from it.
pub fn blob_id_hash_hex(secret_after_tag: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::new_with_prefix(b"typeon-blob-id-v3").chain_update(secret_after_tag).finalize();
    hex::encode(&hash[..16])
}

#[cfg(test)]
mod onion_addr_tests {
    use super::{is_onion_server_addr, public_server_addrs};

    #[test]
    fn a_server_address_is_onion_or_refused() {
        for onion in ["/dns/abcdef.onion/tcp/42612/p2p/12D3KooW", "/dns4/abcdef.onion/tcp/1", "/onion3/abcdef:42612/p2p/12D3KooW"] {
            assert!(is_onion_server_addr(onion), "{onion}");
        }
        for other in [
            "/ip4/203.0.113.7/tcp/42612/p2p/12D3KooW",
            "/ip4/192.168.1.5/tcp/42612/p2p/12D3KooW",
            "/ip6/2001:db8::1/tcp/1",
            "/dns4/example.org/tcp/1",
            "/dns4/localhost/tcp/1",
            "/dns/.onion/tcp/1",
            "/dns/abcdef.onion./tcp/1",
            "/ip4/10.0.0.1/tcp/1/dns/abcdef.onion",
            "abcdef.onion",
            "",
        ] {
            assert!(!is_onion_server_addr(other), "{other}");
        }
        let kept = public_server_addrs(["/dns4/example.org/tcp/1", " /dns/abcdef.onion/tcp/1 "]);
        assert_eq!(kept, vec!["/dns/abcdef.onion/tcp/1".to_string()]);
    }
}
