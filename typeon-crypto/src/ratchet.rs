//! Double Ratchet — Description.md bölüm 3.
//!
//! - 3.1: hibrit KEM oturum kurulumu (X25519 + ML-KEM-1024).
//! - 3.2: simetrik ratchet (her mesajda ilerler) + DH/KEM ratchet
//!   (30 dakikada bir yeni X25519+ML-KEM çifti üretilip yeniden anahtar
//!   değişimi yapılır — break-in recovery).
//! - 3.3: her mesaj paketinin taşıdığı `ratchet_pubkey`, `message_number`,
//!   `prev_chain_length` alanları burada üretilir/tüketilir.
//!
//! NOT (kriptografi kütüphanesi geçişi): Bu dosya önceden `pqcrypto-kyber`
//! kullanıyordu — o crate artık bakımsız (RUSTSEC-2024-0381) VE PQClean'in
//! round-3 taslak Kyber implementasyonuna dayanıyordu, gerçek NIST FIPS 203
//! ML-KEM standardıyla bayt-uyumsuz. Şimdi RustCrypto'nun aktif bakımlı
//! `ml-kem` crate'i (gerçek FIPS 203 ML-KEM-1024) kullanılıyor. ml-kem'in
//! `Decapsulate`/`Encapsulate` trait'leri ayrı bir `kem` crate'inden geliyor
//! (bkz. Cargo.toml notu) ve üretim/encapsulate her zaman elle bir
//! `CryptoRngCore` ister — `rand::rngs::OsRng` (rand 0.8) bunun için zaten
//! uyumlu, x25519-dalek ile aynı RNG paylaşılabilir.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext as MlKemCiphertext, EncodedSizeUser, KemCore, MlKem1024};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

pub type MlKem1024DecapsulationKey = ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>;
pub type MlKem1024EncapsulationKey = ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>;

/// Spec 3.2 kararı: DH/KEM ratchet adımı 30 dakikada bir (mesaj sayısından
/// bağımsız, zaman bazlı).
pub const RATCHET_ROTATION_MS: u64 = 30 * 60 * 1000;

/// Bir alıcının, tek bir gönderenden aynı anda en fazla bu kadar "atlanmış"
/// (henüz gelmemiş ama aradaki) mesaj anahtarını önbellekte tutması —
/// bellek tüketimi saldırısına karşı üst sınır (Signal de benzer bir sınır
/// kullanır, tipik değer 1000 civarındadır).
const MAX_SKIPPED_KEYS: usize = 1000;

/// How far one packet may move a receive chain forward. Every step is two
/// HKDF expands done BEFORE the packet is authenticated, so this bounds the
/// CPU a signed-but-bogus `message_number` costs. Of a jump, only the newest
/// `MAX_SKIPPED_KEYS` keys are kept.
// ponytail: a peer that sent more than this many never-delivered packets on
// one chain stays undecryptable until the next rotation or handshake redo.
const MAX_SKIP_AHEAD: u32 = 2_000;

/// The chain a rotation replaced is dropped this long after that rotation,
/// even if no newer one came: a late packet older than this stays unread,
/// and its key no longer waits in memory and on disk.
pub const OLD_RECV_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Bir ratchet adımının hibrit (X25519 + ML-KEM) public key'i, serileştirilmiş
/// halde `MessagePacket.header.ratchet_pubkey` içinde taşınır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetPublicKeys {
    #[serde(with = "serde_bytes")]
    pub x25519_pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kyber_pubkey: Vec<u8>,
}

/// The receive chain a rotation replaced. The peer keeps sending on it until
/// it has seen the rotation, and packets of the two chains arrive in any
/// order, so it stays usable (`decrypt` tries it second) until the next
/// rotation replaces it.
// ponytail: kept for a whole rotation period. To shorten it, cut the chain at
// the peer's `prev_chain_length` once its first new-chain packet arrives.
#[derive(Clone, Serialize, Deserialize)]
pub struct OldRecvChain {
    #[serde(with = "serde_bytes")]
    ck: Vec<u8>,
    next: u32,
    skipped: HashMap<u32, [u8; 32]>,
}

impl Drop for OldRecvChain {
    fn drop(&mut self) {
        self.ck.zeroize();
        self.skipped.values_mut().for_each(Zeroize::zeroize);
    }
}

impl RatchetPublicKeys {
    pub fn to_bytes(&self) -> Result<Vec<u8>, RatchetError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| RatchetError::Encoding(e.to_string()))?;
        Ok(buf)
    }

    /// Parses a peer's header field: bounded in size and nesting, and both
    /// keys checked for their exact length.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RatchetError> {
        // 32 + 1568 key bytes and a few bytes of CBOR framing.
        if data.len() > 2048 {
            return Err(RatchetError::Invalid("Ratchet public key too long"));
        }
        let mut rest = data;
        let keys: Self = ciborium::de::from_reader_with_recursion_limit(&mut rest, 4).map_err(|e| RatchetError::Encoding(e.to_string()))?;
        if !rest.is_empty() {
            return Err(RatchetError::Invalid("Ratchet public key: trailing bytes"));
        }
        if keys.x25519_pubkey.len() != 32 || keys.kyber_pubkey.len() != 1568 {
            return Err(RatchetError::Invalid("Bad ratchet public key length"));
        }
        Ok(keys)
    }
}

/// Bir cihaz-çifti (device-pair) ratchet oturumunun tüm durumu (spec 1.7.1
/// — Identity_A'nın her cihazı, Identity_B'nin her cihazıyla ayrı bir
/// oturum tutar; bu struct tek bir cihaz-çifti oturumunu temsil eder).
#[derive(Clone)]
pub struct DeviceRatchetState {
    pub root_key: Vec<u8>,
    /// Spec dışı, hata ayıklama düzeltmesi (bkz. SECURITY.md "Cross-network
    /// connectivity" bölümündeki gossipsub topic pseudonymization notu):
    /// `perform_dh_ratchet`'in üzerine yazmadan ÖNCEKİ `root_key` değeri.
    /// (Güvenilirlik düzeltmesi: artık `respond_to_rotation` da ayarlıyor —
    /// iki taraf da "bir önceki topic'i bir nesil daha dinle" defteri için
    /// buna ihtiyaç duyuyor, bkz. network.rs resubscribe çağıranları.)
    /// Yayın tarafı kullanımı `perform_dh_ratchet` çağıran (rotasyonu
    /// TETİKLEYEN) tarafta anlamlı — bu, o rotasyonu duyuran mesajın (`rotation_kyber_ciphertext`
    /// dolu olan) hangi gossipsub topic'inden gönderilmesi gerektiğini
    /// belirlemek için network.rs `try_publish_raw`'da kullanılır: karşı taraf bu
    /// mesajı ALANA kadar YENİ `root_key`'i (dolayısıyla yeni topic'i) bilemez
    /// — o yüzden rotasyonu duyuran mesaj hâlâ ESKİ (paylaşılan) topic'ten
    /// gönderilmeli, yoksa karşı taraf o topic'e hiç abone olmadığından mesaj
    /// asla ulaşmaz (gerçek bir üretim hatasıydı — bkz. commit notu).
    ///
    /// fable H-02: holds `root_handle` of the previous root, never the root
    /// itself. With the root, this side's unchanged ratchet secrets and the
    /// announcement in the clear header re-derived the whole current epoch
    /// from stored state.
    pub prev_root_key: Option<Vec<u8>>,
    pub ck_send: Vec<u8>,
    pub ck_recv: Vec<u8>,
    /// Bu tarafın kendi güncel DH/KEM ratchet anahtar çifti (bir sonraki
    /// rotasyonda karşı tarafa gönderilecek yeni public key'in kaynağı).
    pub own_x25519_secret: StaticSecret,
    pub own_kyber_secret: MlKem1024DecapsulationKey,
    /// Karşı taraftan en son alınan ratchet public key'i (rotasyon
    /// tetiklendiğinde bunlara karşı yeni DH/KEM yapılır).
    pub peer_x25519_pubkey: X25519PublicKey,
    pub peer_kyber_pubkey: MlKem1024EncapsulationKey,
    /// Bu yönde gönderilen mesaj sayacı (spec 3.3 `message_number`).
    pub send_message_number: u32,
    /// Karşı taraftan alınan mesaj sayacı — tekrar oynatma / sıra dışı
    /// paket tespiti için.
    pub recv_message_number: u32,
    /// Son DH/KEM ratchet adımından önceki zincir uzunluğu (spec 3.3
    /// `prev_chain_length`).
    pub prev_chain_length: u32,
    pub last_rotation: u64,
    /// Signal'ın gerçek DH-ratchet modeli (bkz. dosya sonu notu): rotasyonu
    /// SADECE "henüz karşı tarafın güncel public key'ine cevap vermemiş"
    /// taraf tetikler — deterministik bir "kim tetikler" kuralı (ör.
    /// fingerprint karşılaştırması) YOKTUR. Bu bayrak, "kendi tarafımda
    /// karşı tarafın en son bildiğim public key'ine karşı zaten bir DH/KEM
    /// adımı yaptım mı" sorusunu cevaplar:
    /// - `true`: karşı tarafın güncel public key'ine karşı zaten yeni bir
    ///   keypair ürettim (perform_dh_ratchet çağırdım veya bu oturum yeni
    ///   kuruldu) — bu durumda BEN rotasyon tetiklemem, sıradaki rotasyon
    ///   hakkı karşı tarafta (o da benim yeni public key'ime cevap vermeli).
    /// - `false`: karşı taraf benden sonra rotasyon yaptı (respond_to_rotation
    ///   çağrıldı) ve ben henüz ONUN yeni public key'ine cevap vermedim —
    ///   30 dakika dolduğunda BEN tetiklerim (perform_dh_ratchet).
    pub has_responded_to_peer_key: bool,
    /// Güvenilirlik düzeltmesi (rotasyon duyurusu kaybı): `perform_dh_ratchet`
    /// tarafından üretilen Kyber ciphertext'i, karşı tarafın rotasyonu
    /// UYGULADIĞI DOĞRULANANA kadar burada saklanır — send.rs
    /// `send_message_content_inner` bu değer doluyken HER giden pakete
    /// rotasyon duyurusunu yeniden ekler. Önceden duyuru SADECE rotasyonu
    /// tetikleyen tek pakette taşınıyordu; o paket güvenilir teslimli
    /// olmayan bir türse (TypingIndicator/Ack) ve kaybolursa, karşı taraf
    /// yeni kök anahtarı ASLA öğrenemiyor ve oturum kalıcı olarak
    /// kopuyordu. Karşı taraftan yeni zincirde bir paket başarıyla
    /// çözüldüğünde (rotasyonu uyguladığının kanıtı) temizlenir; tekrarlanan
    /// duyurular alıcı tarafta idempotenttir (bkz. `respond_to_rotation`
    /// içindeki çift-uygulama koruması).
    pub pending_rotation_ct: Option<Vec<u8>>,
    /// Sıra dışı/gecikmeli gelen mesajlar için "atlanmış mesaj anahtarları"
    /// önbelleği (Signal Double Ratchet'teki standart mekanizma). Bir mesaj
    /// beklenenden yüksek bir `message_number` ile gelirse, aradaki
    /// mesajların anahtarları burada saklanır — böylece o mesajlar daha
    /// sonra (gecikmeli/sırasız) gelirse hâlâ çözülebilir. key = mesaj
    /// numarası. `MAX_SKIPPED_KEYS` ile sınırlanır (bellek/DoS koruması —
    /// kötü niyetli biri çok yüksek bir message_number göndererek sınırsız
    /// bellek tükettiremesin diye). Diske şifreli olarak kalıcılaştırılır
    /// (bkz. archive.rs `persist_skipped_key`/`load_skipped_keys_from_db`) —
    /// süreç yeniden başlasa bile gecikmeli mesajlar çözülebilsin diye
    /// (kapsam sınırı için bkz. lib.rs ilgili not).
    pub skipped_keys: HashMap<u32, [u8; 32]>,
    /// See `OldRecvChain`.
    pub old_recv: Option<OldRecvChain>,
}

/// Spec dışı, güvenlik denetimi düzeltmesi: bu struct'ın (`own_x25519_secret`/
/// `own_kyber_secret` HARİÇ, bkz. Cargo.toml "zeroize" feature notu — onlar
/// zaten kendi crate'lerinin `ZeroizeOnDrop` implementasyonuyla sıfırlanıyor)
/// düz `Vec<u8>` olarak tuttuğu simetrik sırlar (`root_key`/`ck_send`/
/// `ck_recv`) ve atlanmış mesaj anahtarları (`skipped_keys`) önceden normal
/// Rust `drop` ile (üzerine yazmadan) bellekten çıkıyordu — bir oturum
/// rotasyon geçirdiğinde (eski root_key değeri atılır) veya kişi/cihaz
/// silindiğinde/iptal edildiğinde (`self.ratchets.remove`) bu baytlar hâlâ
/// bellekte kalabilirdi. Artık `Drop` ile açıkça sıfırlanıyor.
impl Drop for DeviceRatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.prev_root_key.zeroize();
        self.ck_send.zeroize();
        self.ck_recv.zeroize();
        for key in self.skipped_keys.values_mut() {
            key.zeroize();
        }
    }
}

/// `DeviceRatchetState`'in diske (şifreli) yazılabilir hâli — secret key
/// tipleri (`StaticSecret`/`MlKem1024DecapsulationKey`/...) doğrudan
/// `Serialize` implement etmiyor, bu yüzden hepsi ham bayt dizisine
/// dönüştürülür (aynen `types.rs`'teki `SecretKeyBundle`'ın kendi cihaz
/// anahtarları için yaptığı gibi — bkz. `generate_identity`/
/// `load_secret_bundle`). `skipped_keys` KASITLI OLARAK burada YOK: o
/// zaten ayrı bir tabloda (`skipped_message_keys`) kendi başına kalıcı
/// kılınıyor (bkz. archive.rs `persist_skipped_key`/`load_skipped_keys_from_db`)
/// — burada tekrar taşımak, iki kopyanın birbirinden sapma riskini
/// (data drift) gereksiz yere ekler.
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableRatchetState {
    #[serde(with = "serde_bytes")]
    pub root_key: Vec<u8>,
    /// bkz. `DeviceRatchetState.prev_root_key` dokümantasyonu — süreç bir
    /// rotasyon ANONS EDEN ama henüz karşı tarafça alınmamış bir mesajın
    /// ortasında yeniden başlarsa, `pending_envelopes` kalıcı olmadığından
    /// bu değer kaybolursa yeniden denemeler yanlış topic'e düşebilir; bu
    /// yüzden burada da kalıcı kılınıyor.
    #[serde(with = "serde_bytes")]
    pub prev_root_key: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub ck_send: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ck_recv: Vec<u8>,
    pub own_x25519_secret: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub own_kyber_secret: Vec<u8>,
    pub peer_x25519_pubkey: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub peer_kyber_pubkey: Vec<u8>,
    pub send_message_number: u32,
    pub recv_message_number: u32,
    pub prev_chain_length: u32,
    pub last_rotation: u64,
    pub has_responded_to_peer_key: bool,
    /// bkz. `DeviceRatchetState.pending_rotation_ct` — `#[serde(default)]`:
    /// bu alan eklenmeden önce diske yazılmış eski state kayıtları alanı
    /// içermez, `None` ile geriye dönük uyumlu şekilde yüklenir.
    #[serde(default, with = "serde_bytes")]
    pub pending_rotation_ct: Option<Vec<u8>>,
    #[serde(default)]
    pub old_recv: Option<OldRecvChain>,
}

impl Drop for SerializableRatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.prev_root_key.zeroize();
        self.ck_send.zeroize();
        self.ck_recv.zeroize();
        self.own_x25519_secret.zeroize();
        self.own_kyber_secret.zeroize();
    }
}

impl DeviceRatchetState {
    /// bkz. `SerializableRatchetState` dokümantasyonu. `skipped_keys`
    /// hariç tutulur — çağıran taraf (persist.rs) onu ayrıca yükleyip
    /// dönen değere atamalıdır (bkz. `from_persistable`).
    pub fn to_persistable(&self) -> SerializableRatchetState {
        SerializableRatchetState {
            root_key: self.root_key.clone(),
            prev_root_key: self.prev_root_key.clone(),
            ck_send: self.ck_send.clone(),
            ck_recv: self.ck_recv.clone(),
            own_x25519_secret: self.own_x25519_secret.to_bytes(),
            own_kyber_secret: self.own_kyber_secret.as_bytes().to_vec(),
            peer_x25519_pubkey: *self.peer_x25519_pubkey.as_bytes(),
            peer_kyber_pubkey: self.peer_kyber_pubkey.as_bytes().to_vec(),
            send_message_number: self.send_message_number,
            recv_message_number: self.recv_message_number,
            prev_chain_length: self.prev_chain_length,
            last_rotation: self.last_rotation,
            has_responded_to_peer_key: self.has_responded_to_peer_key,
            pending_rotation_ct: self.pending_rotation_ct.clone(),
            old_recv: self.old_recv.clone(),
        }
    }

    /// `skipped_keys`: diskteki `skipped_message_keys` tablosundan ayrıca
    /// yüklenip buraya geçirilmelidir (bkz. archive.rs
    /// `load_skipped_keys_from_db`) — bu fonksiyon kendisi o tabloya
    /// erişmez (ratchet.rs kripto-only katman, dosya başı notuyla tutarlı).
    pub fn from_persistable(mut s: SerializableRatchetState, skipped_keys: HashMap<u32, [u8; 32]>) -> Result<Self, RatchetError> {
        let mut own_kyber_encoded: ml_kem::Encoded<MlKem1024DecapsulationKey> = s.own_kyber_secret.as_slice()
            .try_into().map_err(|_| "Bozuk kayıtlı Kyber secret key")?;
        let own_kyber_secret = MlKem1024DecapsulationKey::from_bytes(&own_kyber_encoded);
        // The stack copy of the secret key is wiped like `s` itself.
        own_kyber_encoded.as_mut_slice().zeroize();
        Ok(DeviceRatchetState {
            root_key: std::mem::take(&mut s.root_key),
            prev_root_key: s.prev_root_key.take(),
            ck_send: std::mem::take(&mut s.ck_send),
            ck_recv: std::mem::take(&mut s.ck_recv),
            own_x25519_secret: StaticSecret::from(s.own_x25519_secret),
            own_kyber_secret,
            peer_x25519_pubkey: X25519PublicKey::from(s.peer_x25519_pubkey),
            peer_kyber_pubkey: kyber_pubkey_from_bytes(&s.peer_kyber_pubkey)?,
            send_message_number: s.send_message_number,
            recv_message_number: s.recv_message_number,
            prev_chain_length: s.prev_chain_length,
            last_rotation: s.last_rotation,
            has_responded_to_peer_key: s.has_responded_to_peer_key,
            pending_rotation_ct: s.pending_rotation_ct.take(),
            skipped_keys,
            old_recv: s.old_recv.take(),
        })
    }
}

/// `DeviceRatchetState::decrypt` çağrısı sırasında skipped-key
/// önbelleğinde olan değişiklikleri raporlar — çağıran taraf (persist.rs) bu
/// bilgiyle diskteki şifreli kopyayı güncel tutar.
#[derive(Default)]
pub struct SkippedKeyChanges {
    /// Yeni eklenen skipped-key'ler: (message_number, key).
    pub added: Vec<(u32, [u8; 32])>,
    /// Kullanılıp (ya da yer açmak için atılıp) önbellekten ve diskten
    /// silinmesi gereken message_number'lar.
    pub used: Vec<u32>,
    /// The packet's rotation was applied: root key, both chains and the peer
    /// keys changed, and the skipped keys on disk belong to the old chain.
    pub rotated: bool,
    /// The packet was on the chain before the last rotation (`OldRecvChain`).
    /// It does not prove the peer applied our rotation, and `added`/`used`
    /// are empty: that chain's skipped keys live inside the ratchet state.
    pub old_chain: bool,
}

impl Drop for SkippedKeyChanges {
    fn drop(&mut self) {
        self.added.iter_mut().for_each(|(_, key)| key.zeroize());
    }
}

fn set_secret(slot: &mut Vec<u8>, new: Vec<u8>) {
    slot.zeroize();
    *slot = new;
}

/// What a key derivation is bound to: both sides' ratchet public keys and the
/// KEM ciphertext, initiator (of the handshake or of the rotation) first.
/// Every part has a fixed length, so plain concatenation is unambiguous.
fn transcript(init_x25519: &[u8; 32], init_kyber: &[u8], kyber_ct: &[u8], resp_x25519: &[u8; 32], resp_kyber: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [&init_x25519[..], init_kyber, kyber_ct, &resp_x25519[..], resp_kyber] {
        h.update(part);
    }
    h.finalize().into()
}

/// M-198: ratchet failures as values, so callers branch on the kind, not the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetError {
    /// Behind the chain and no skipped key: already decrypted, or evicted.
    KeyNotFound(u32),
    TooManySkipped { gap: u32, limit: u32 },
    /// AEAD tag did not verify.
    DecryptFailed,
    ResponderMustRotate,
    ChainExhausted,
    /// Malformed key, ciphertext or state, or a failed primitive.
    Invalid(&'static str),
    Encoding(String),
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetError::KeyNotFound(n) => write!(f, "Message {} not found in skipped-key cache (already decrypted, or evicted)", n),
            RatchetError::TooManySkipped { gap, limit } => write!(f, "Too many skipped messages (gap {}, limit {})", gap, limit),
            RatchetError::DecryptFailed => f.write_str("Decryption failed"),
            RatchetError::ResponderMustRotate => f.write_str("Responder must rotate before its first send"),
            RatchetError::ChainExhausted => f.write_str("Chain exhausted"),
            RatchetError::Invalid(m) => f.write_str(m),
            RatchetError::Encoding(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for RatchetError {}

impl From<&'static str> for RatchetError {
    fn from(m: &'static str) -> Self {
        RatchetError::Invalid(m)
    }
}

/// `?` into the many `Result<_, String>` callers.
impl From<RatchetError> for String {
    fn from(e: RatchetError) -> Self {
        e.to_string()
    }
}

/// X25519 with a small-order public key gives the same output for every
/// secret: the classical half of the hybrid would silently be a constant.
fn x25519(secret: &StaticSecret, public: &X25519PublicKey) -> Result<x25519_dalek::SharedSecret, RatchetError> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(RatchetError::Invalid("Bad peer X25519 key (small order)"));
    }
    Ok(shared)
}

/// Root/send/recv anahtarlarını HKDF ile türetir. `we_initiated` yön
/// simetrisini garanti eder: initiator'ın send-key'i responder'ın
/// recv-key'ine eşit olur. `transcript` is part of every label (v0.2): the
/// keys depend on who exchanged what, not only on the shared secrets.
fn derive_keys(mut ikm: Vec<u8>, transcript: &[u8; 32], we_initiated: bool) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), RatchetError> {
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    ikm.zeroize();
    let mut keys = [[0u8; 32]; 3];
    let labels: [&[u8]; 3] = [b"p2pmsg-v0.2-root", b"p2pmsg-v0.2-a-to-b", b"p2pmsg-v0.2-b-to-a"];
    for (label, key) in labels.into_iter().zip(keys.iter_mut()) {
        hk.expand_multi_info(&[label, transcript], key).map_err(|_| "HKDF expand failed")?;
    }
    // From slices: `keys.map` copied each key by value into a temporary that
    // nothing wiped.
    let (root_key, key_a, key_b) = (keys[0].to_vec(), keys[1].to_vec(), keys[2].to_vec());
    keys.zeroize();
    Ok(if we_initiated { (root_key, key_a, key_b) } else { (root_key, key_b, key_a) })
}

/// `kem_key_to` header: X25519 public key + ML-KEM-1024 ciphertext.
pub const KEM_HEADER_LEN: usize = 32 + 1568;

/// The key of a hybrid KEM to a device's public KEM keys, without a session:
/// the sender half of `DeviceRatchetState::initiate` (fresh X25519 secret,
/// ML-KEM encapsulation, both shared secrets and the transcript into HKDF),
/// with no ML-KEM key of the sender. Returns the key and the header the
/// recipient needs: `x25519 public (32) || ML-KEM ciphertext`.
pub fn kem_key_to(peer_x25519_pubkey: &[u8], peer_kyber_pubkey: &[u8]) -> Result<([u8; 32], Vec<u8>), RatchetError> {
    let mut csprng = OsRng;
    let own_x25519_secret = StaticSecret::random_from_rng(&mut csprng);
    let own_x25519_bytes = *X25519PublicKey::from(&own_x25519_secret).as_bytes();
    let peer_x25519_bytes: [u8; 32] = peer_x25519_pubkey.try_into().map_err(|_| "Bad peer X25519 key length")?;
    let dh_shared = x25519(&own_x25519_secret, &X25519PublicKey::from(peer_x25519_bytes))?;
    let peer_kyber_pk = kyber_pubkey_from_bytes(peer_kyber_pubkey)?;
    let (kyber_ct, mut kyber_shared) = peer_kyber_pk.encapsulate(&mut csprng).map_err(|_| "Kyber encapsulate failed")?;
    let kyber_ct = kyber_ct.to_vec();
    let ikm = [dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
    kyber_shared.as_mut_slice().zeroize();
    let bound_to = transcript(&own_x25519_bytes, &[], &kyber_ct, &peer_x25519_bytes, &peer_kyber_pk.as_bytes());
    Ok((kem_key(ikm, &bound_to)?, [&own_x25519_bytes[..], &kyber_ct].concat()))
}

/// The recipient half of `kem_key_to` (as `DeviceRatchetState::respond`).
pub fn kem_key_from(own_x25519_secret: &StaticSecret, own_kyber_secret: &MlKem1024DecapsulationKey, header: &[u8]) -> Result<[u8; 32], RatchetError> {
    if header.len() != KEM_HEADER_LEN {
        return Err(RatchetError::Invalid("Bad KEM header length"));
    }
    let (sender_x25519, kyber_ciphertext) = header.split_at(32);
    let sender_x25519_bytes: [u8; 32] = sender_x25519.try_into().map_err(|_| "Bad sender X25519 key length")?;
    let dh_shared = x25519(own_x25519_secret, &X25519PublicKey::from(sender_x25519_bytes))?;
    let ct = kyber_ciphertext_from_bytes(kyber_ciphertext)?;
    let mut kyber_shared = own_kyber_secret.decapsulate(&ct).map_err(|_| "Kyber decapsulate failed")?;
    let ikm = [dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
    kyber_shared.as_mut_slice().zeroize();
    let bound_to = transcript(
        &sender_x25519_bytes, &[], kyber_ciphertext,
        X25519PublicKey::from(own_x25519_secret).as_bytes(), &own_kyber_secret.encapsulation_key().as_bytes(),
    );
    kem_key(ikm, &bound_to)
}

/// `derive_keys` for one key, under a label of its own.
fn kem_key(mut ikm: Vec<u8>, transcript: &[u8; 32]) -> Result<[u8; 32], RatchetError> {
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    ikm.zeroize();
    let mut key = [0u8; 32];
    hk.expand_multi_info(&[b"p2pmsg-v0.5-kem-seal", transcript], &mut key).map_err(|_| "HKDF expand failed")?;
    Ok(key)
}

/// One symmetric ratchet step (spec 3.2): the key of this message and the
/// chain key of the next. The send and the receive side share it, so the two
/// HKDF labels cannot drift apart.
fn chain_step(chain_key: &[u8]) -> Result<([u8; 32], [u8; 32]), RatchetError> {
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut message_key = [0u8; 32];
    let mut next_chain_key = [0u8; 32];
    hk.expand(b"p2pmsg-v0.1-msgkey", &mut message_key).map_err(|_| "HKDF expand failed")?;
    hk.expand(b"p2pmsg-v0.1-chainkey", &mut next_chain_key).map_err(|_| "HKDF expand failed")?;
    Ok((message_key, next_chain_key))
}

impl DeviceRatchetState {
    /// Spec 3.1: ilk bağlantıda çift taraflı hibrit el sıkışma.
    /// `root_key = HKDF( shared_secret_classic || shared_secret_pq, salt="p2pmsg-v0.1" )`
    ///
    /// Initiator tarafı: kendi taze X25519+Kyber çiftini üretir, karşı
    /// tarafın public key'lerine karşı DH+encapsulate yapar. Kyber
    /// ciphertext, `HandshakeInit` paketiyle karşı tarafa taşınmalıdır
    /// (bkz. `crate::packet::HandshakeInit`).
    pub fn initiate(
        peer_x25519_pubkey: &[u8],
        peer_kyber_pubkey: &[u8],
        now_ms: u64,
    ) -> Result<(Self, Vec<u8>, Vec<u8>), RatchetError> {
        // X25519 (x25519-dalek, rand_core 0.6 üzerinden rand 0.8) ve ML-KEM
        // (ml-kem crate'i, rand_core 0.6.4) aynı rand_core majör sürümünü
        // kullanıyor — aynı `OsRng`'u ikisine de geçirebiliriz.
        let mut csprng = OsRng;
        let own_x25519_secret = StaticSecret::random_from_rng(&mut csprng);

        let peer_x25519_bytes: [u8; 32] = peer_x25519_pubkey.try_into().map_err(|_| "Bad peer X25519 key length")?;
        let peer_x25519_pk = X25519PublicKey::from(peer_x25519_bytes);
        let dh_shared = x25519(&own_x25519_secret, &peer_x25519_pk)?;

        // Kendi taze Kyber çiftimizi üret.
        let (own_kyber_secret, own_kyber_ek) = MlKem1024::generate(&mut csprng);
        let own_kyber_public_bytes = own_kyber_ek.as_bytes().to_vec();

        let peer_kyber_pk = kyber_pubkey_from_bytes(peer_kyber_pubkey)?;
        let (kyber_ct, mut kyber_shared) = peer_kyber_pk.encapsulate(&mut csprng).map_err(|_| "Kyber encapsulate failed")?;
        let kyber_ct = kyber_ct.to_vec();

        let ikm = [dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
        kyber_shared.as_mut_slice().zeroize();
        let bound_to = transcript(
            X25519PublicKey::from(&own_x25519_secret).as_bytes(), &own_kyber_public_bytes, &kyber_ct,
            &peer_x25519_bytes, &peer_kyber_pk.as_bytes(),
        );
        let (root_key, ck_send, ck_recv) = derive_keys(ikm, &bound_to, true)?;

        let state = DeviceRatchetState {
            root_key,
            prev_root_key: None,
            ck_send,
            ck_recv,
            own_x25519_secret,
            own_kyber_secret,
            peer_x25519_pubkey: peer_x25519_pk,
            peer_kyber_pubkey: peer_kyber_pk,
            send_message_number: 0,
            recv_message_number: 0,
            prev_chain_length: 0,
            last_rotation: now_ms,
            // Initiator, responder'ın İLK public key'ine karşı zaten
            // DH+encapsulate yaptı — bu "cevap verdim" sayılır. Sıradaki
            // rotasyon hakkı responder'da.
            has_responded_to_peer_key: true,
            pending_rotation_ct: None,
            skipped_keys: HashMap::new(),
            old_recv: None,
        };
        Ok((state, kyber_ct, own_kyber_public_bytes))
    }

    /// Responder tarafı: gelen `HandshakeInit`'teki initiator public key'i
    /// ve Kyber ciphertext'i kullanarak aynı anahtarları türetir.
    ///
    /// Nothing here is random: the same `HandshakeInit` always gives the same
    /// state, and the long-term keys are the only secrets in it. So a
    /// responder never sends on this chain. `should_rotate` is true at once
    /// (`is_fresh_responder`) and the caller rotates before its first send:
    /// a replayed init cannot make it reuse a key and nonce, and only what
    /// the initiator sent before that rotation depends on the long-term keys
    /// alone (the price of a handshake without a round trip).
    pub fn respond(
        own_x25519_secret: StaticSecret,
        own_kyber_secret: MlKem1024DecapsulationKey,
        initiator_x25519_pubkey: &[u8],
        initiator_kyber_pubkey: &[u8],
        kyber_ciphertext: &[u8],
        now_ms: u64,
    ) -> Result<Self, RatchetError> {
        let initiator_x25519_bytes: [u8; 32] = initiator_x25519_pubkey.try_into().map_err(|_| "Bad initiator X25519 key length")?;
        let initiator_x25519_pk = X25519PublicKey::from(initiator_x25519_bytes);
        let dh_shared = x25519(&own_x25519_secret, &initiator_x25519_pk)?;

        let ct = kyber_ciphertext_from_bytes(kyber_ciphertext)?;
        let mut kyber_shared = own_kyber_secret.decapsulate(&ct).map_err(|_| "Kyber decapsulate failed")?;

        let initiator_kyber_pk = kyber_pubkey_from_bytes(initiator_kyber_pubkey)?;

        let ikm = [dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
        kyber_shared.as_mut_slice().zeroize();
        let bound_to = transcript(
            &initiator_x25519_bytes, &initiator_kyber_pk.as_bytes(), kyber_ciphertext,
            X25519PublicKey::from(&own_x25519_secret).as_bytes(), &own_kyber_secret.encapsulation_key().as_bytes(),
        );
        let (root_key, ck_send, ck_recv) = derive_keys(ikm, &bound_to, false)?;

        Ok(DeviceRatchetState {
            root_key,
            prev_root_key: None,
            ck_send,
            ck_recv,
            own_x25519_secret,
            own_kyber_secret,
            peer_x25519_pubkey: initiator_x25519_pk,
            peer_kyber_pubkey: initiator_kyber_pk,
            send_message_number: 0,
            recv_message_number: 0,
            prev_chain_length: 0,
            last_rotation: now_ms,
            // Responder henüz initiator'ın public key'ine cevap vermedi —
            // rotasyonu TETİKLEME hakkı responder'da, ve ilk gönderiminden
            // önce kullanır (bkz. fonksiyon notu, `is_fresh_responder`).
            has_responded_to_peer_key: false,
            pending_rotation_ct: None,
            skipped_keys: HashMap::new(),
            old_recv: None,
        })
    }

    /// Bu tarafın güncel ratchet public key'lerini (karşı tarafa
    /// `MessagePacket.header.ratchet_pubkey` içinde gönderilecek) döner.
    pub fn own_ratchet_pubkeys(&self) -> RatchetPublicKeys {
        RatchetPublicKeys {
            x25519_pubkey: X25519PublicKey::from(&self.own_x25519_secret).as_bytes().to_vec(),
            kyber_pubkey: self.own_kyber_secret.encapsulation_key().as_bytes().to_vec(),
        }
    }

    /// DH/KEM ratchet adımı (spec 3.2): yeni bir X25519+ML-KEM çifti üretir,
    /// karşı tarafın şu an bilinen (son alınan) public key'lerine karşı
    /// yeniden anahtar değişimi yapar, root/send/recv anahtarlarını tazeler.
    /// `prev_chain_length` bir önceki `send_message_number`'a ayarlanır,
    /// `send_message_number` sıfırlanır — spec 3.3'teki alanların anlamı
    /// budur (karşı taraf `prev_chain_length` ile "eski zincirdeki son
    /// mesaj numarası" bilgisini alır).
    ///
    /// Sadece `should_rotate()` true dönerse çağrılmalıdır — bu, Signal'ın
    /// gerçek modeline uygun olarak "ben zaten karşı tarafın güncel
    /// key'ine cevap verdim mi" (`has_responded_to_peer_key`) durumunu da
    /// içerir; deterministik bir "kim tetikler" kuralı YOKTUR, sadece
    /// henüz cevap vermemiş taraf tetikler (bkz. dosya sonu notu).
    ///
    /// Döndürülen Kyber ciphertext, çağıran tarafça bir sonraki
    /// `MessagePacket`'in header'ındaki `ratchet_pubkey` alanıyla BİRLİKTE
    /// karşı tarafa gönderilmelidir (`RatchetPublicKeys` + bu ciphertext).
    /// Karşı taraf bunu aldığında `respond_to_rotation` ile senkronize
    /// olmalıdır.
    pub fn perform_dh_ratchet(&mut self, now_ms: u64) -> Result<Vec<u8>, RatchetError> {
        let mut csprng = OsRng;
        let new_x25519_secret = StaticSecret::random_from_rng(&mut csprng);
        let (new_kyber_secret, new_kyber_ek) = MlKem1024::generate(&mut csprng);

        let dh_shared = x25519(&new_x25519_secret, &self.peer_x25519_pubkey)?;
        let (kyber_ct, mut kyber_shared) = self.peer_kyber_pubkey.encapsulate(&mut csprng).map_err(|_| "Kyber encapsulate failed")?;
        let kyber_ct = kyber_ct.to_vec();

        let ikm = [self.root_key.as_slice(), dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
        kyber_shared.as_mut_slice().zeroize();
        let bound_to = transcript(
            X25519PublicKey::from(&new_x25519_secret).as_bytes(), &new_kyber_ek.as_bytes(), &kyber_ct,
            self.peer_x25519_pubkey.as_bytes(), &self.peer_kyber_pubkey.as_bytes(),
        );
        // Bu fonksiyon her zaman "ben tetikliyorum" anlamına gelir —
        // we_initiated=true.
        let keys = derive_keys(ikm, &bound_to, true)?;

        self.rotate_chains(keys, now_ms);
        self.own_x25519_secret = new_x25519_secret;
        self.own_kyber_secret = new_kyber_secret;
        // Karşı tarafın (rotasyon öncesi) bilinen public key'ine karşı
        // encapsulate ettik — "cevap verdim" sayılır. Sıradaki rotasyon
        // hakkı artık karşı tarafta.
        self.has_responded_to_peer_key = true;
        // bkz. `pending_rotation_ct` alanı — karşı taraf rotasyonu uyguladığı
        // doğrulanana kadar bu duyuru her giden pakete yeniden eklenir.
        self.pending_rotation_ct = Some(kyber_ct.clone());
        Ok(kyber_ct)
    }

    /// What the session topic and the server seal are derived from:
    /// `root_handle(root_key)`, and `prev_root_key` one generation back.
    pub fn root_handle_now(&self) -> Vec<u8> {
        root_handle(&self.root_key)
    }

    /// The part both sides of a rotation share: new root and chains, counters
    /// back to 0. The old root stays one generation (`prev_root_key`: the
    /// announcement still travels on its topic), and so does the old receive
    /// chain with its skipped keys (`OldRecvChain`).
    fn rotate_chains(&mut self, (root_key, ck_send, ck_recv): (Vec<u8>, Vec<u8>, Vec<u8>), now_ms: u64) {
        self.prev_chain_length = self.send_message_number;
        self.send_message_number = 0;
        self.old_recv = Some(OldRecvChain {
            ck: std::mem::replace(&mut self.ck_recv, ck_recv),
            next: self.recv_message_number,
            skipped: std::mem::take(&mut self.skipped_keys),
        });
        self.recv_message_number = 0;
        self.prev_root_key.zeroize();
        let mut old_root = std::mem::replace(&mut self.root_key, root_key);
        self.prev_root_key = Some(root_handle(&old_root));
        old_root.zeroize();
        set_secret(&mut self.ck_send, ck_send);
        self.last_rotation = now_ms;
    }

    /// Alıcı tarafın rotasyona TEPKİ vermesi: karşı taraf `perform_dh_ratchet`
    /// çağırıp bize (a) yeni `ratchet_pubkey`'ini (hem X25519 hem Kyber
    /// public key) VE (b) o rotasyonun ürettiği Kyber ciphertext'ini
    /// (`MessagePacketHeader.rotation_kyber_ciphertext`) gönderdiğinde
    /// çağrılır. Bu, `perform_dh_ratchet`'in "encapsulate" ettiği tarafın
    /// karşılığıdır: biz KENDİ yeni bir keypair üretmeyiz (rotasyonu biz
    /// başlatmadık), sadece karşı tarafın gönderdiği ciphertext'i kendi
    /// (ROTASYON ÖNCESİ, hâlâ geçerli) Kyber secret'ımızla decapsulate
    /// ederiz — bu, spec 3.2'nin "iki taraf da aynı yeni kök anahtarı
    /// türetir" gereksinimini karşılar.
    ///
    /// `new_peer_keys`, karşı tarafın YENİ (rotasyon sonrası) X25519+Kyber
    /// public key çiftidir — hem şimdiki decapsulate'te (X25519 kısmı) hem
    /// de bizim GELECEKTEKİ rotasyonlarımızda (Kyber kısmı,
    /// `perform_dh_ratchet`'in `self.peer_kyber_pubkey`'e karşı encapsulate
    /// etmesi için) kullanılacağından ikisi birden burada güncellenir.
    ///
    /// Dönüş: `Ok(true)` = rotasyon UYGULANDI; `Ok(false)` = bu duyuru
    /// ZATEN uygulanmıştı, hiçbir durum değişmedi (aşağıdaki koruma).
    ///
    /// KRİTİK (çift-uygulama koruması): bu fonksiyon KDF'e mevcut
    /// `root_key`'i katar — AYNI duyuruyu iki kez uygulamak, gönderenin
    /// hiç görmediği bir kök anahtar türetir ve oturumu KALICI olarak
    /// koparırdı. Aynı duyurunun tekrar gelmesi ise kaçınılmaz: gönderenin
    /// `awaiting_confirmation` mekanizması, Ack kaybolduğunda AYNI zarfı
    /// (aynı rotation ciphertext'iyle) yeniden yayınlar; ayrıca
    /// `pending_rotation_ct` yeniden-duyuru mekanizması da (bkz. o alan)
    /// duyuruyu kasıtlı olarak tekrarlar. Karşı tarafın X25519 public
    /// key'i her rotasyonda TAZE ÜRETİLDİĞİ için, gelen key'in kayıtlı
    /// `peer_x25519_pubkey` ile AYNI olması "bu rotasyon zaten uygulandı"
    /// demektir — güvenle yok sayılır.
    ///
    /// Private: nothing here is authenticated. ML-KEM decapsulation never
    /// fails (a ciphertext made for another key gives pseudo-random bytes),
    /// and the guard above only knows the current peer key, so a delayed
    /// announcement of an older rotation would overwrite root and chains with
    /// garbage. `decrypt` runs this on a copy and keeps the result only when
    /// the packet then decrypts on the new chain.
    fn respond_to_rotation(&mut self, new_peer_keys: &RatchetPublicKeys, rotation_kyber_ciphertext: &[u8], now_ms: u64) -> Result<bool, RatchetError> {
        let x25519_bytes: [u8; 32] = new_peer_keys.x25519_pubkey.as_slice().try_into().map_err(|_| "Bad peer X25519 key length")?;
        if x25519_bytes == *self.peer_x25519_pubkey.as_bytes() {
            return Ok(false);
        }
        let new_peer_x25519_pk = X25519PublicKey::from(x25519_bytes);
        let new_peer_kyber_pk = kyber_pubkey_from_bytes(&new_peer_keys.kyber_pubkey)?;

        // DH: KENDİ (rotasyon öncesi, hâlâ geçerli) X25519 secret'ımızla,
        // karşı tarafın YENİ X25519 public key'ine karşı.
        let dh_shared = x25519(&self.own_x25519_secret, &new_peer_x25519_pk)?;

        // KEM: karşı tarafın bize gönderdiği ciphertext'i, KENDİ (rotasyon
        // öncesi, hâlâ geçerli) Kyber secret'ımızla decapsulate ediyoruz —
        // perform_dh_ratchet'teki `self.peer_kyber_pubkey.encapsulate(...)`
        // çağrısının simetriği (karşı taraf BİZİM eski Kyber public
        // key'imize karşı encapsulate etmişti).
        let ct = kyber_ciphertext_from_bytes(rotation_kyber_ciphertext)?;
        let mut kyber_shared = self.own_kyber_secret.decapsulate(&ct).map_err(|_| "Kyber decapsulate failed")?;

        let ikm = [self.root_key.as_slice(), dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
        kyber_shared.as_mut_slice().zeroize();
        let bound_to = transcript(
            &x25519_bytes, &new_peer_kyber_pk.as_bytes(), rotation_kyber_ciphertext,
            X25519PublicKey::from(&self.own_x25519_secret).as_bytes(), &self.own_kyber_secret.encapsulation_key().as_bytes(),
        );
        // Rotasyonu BİZ başlatmadık, karşı taraf başlattı — we_initiated=false.
        let keys = derive_keys(ikm, &bound_to, false)?;

        // `prev_chain_length` = BENİM önceki gönderme zincirimin uzunluğu
        // (defter #33), `perform_dh_ratchet` ile aynı.
        self.rotate_chains(keys, now_ms);
        // Karşı taraf rotasyon yaptıysa bizim MEVCUT public key'imizi
        // biliyor demektir — hâlâ tekrarlanan bir eski duyurumuz varsa
        // artık gereksiz (bkz. `pending_rotation_ct`).
        self.pending_rotation_ct = None;
        // Kendi own_x25519_secret/own_kyber_secret'ımızı DEĞİŞTİRMİYORUZ —
        // rotasyonu biz başlatmadık, kendi anahtar çiftimiz aynı kalır; bir
        // sonraki rotasyonu BİZ başlatırsak (perform_dh_ratchet) o zaman
        // yenileriz. Peer public key'lerinin ikisini de güncelliyoruz (bkz.
        // fonksiyon dokümantasyonu — Kyber tarafı gelecekteki rotasyonlar
        // için gerekli).
        self.peer_x25519_pubkey = new_peer_x25519_pk;
        self.peer_kyber_pubkey = new_peer_kyber_pk;
        // Karşı taraf yeni bir public key üretti, biz henüz BU yeni
        // key'e karşı kendi tarafımızda bir DH/KEM adımı yapmadık —
        // sıradaki rotasyon hakkı bizde (30 dakika dolduğunda BİZ
        // perform_dh_ratchet çağırırız).
        self.has_responded_to_peer_key = false;
        Ok(true)
    }

    /// Spec 3.2: 30 dakika kuralı + Signal'ın gerçek modeli — SADECE henüz
    /// karşı tarafın güncel public key'ine cevap vermemiş taraf (
    /// `has_responded_to_peer_key == false`) rotasyonu tetikleyebilir.
    /// Cevap zaten verilmişse (sıradaki rotasyon hakkı karşı tarafta),
    /// 30 dakika dolmuş olsa bile BİZ tetiklemeyiz — karşı tarafın kendi
    /// mesajıyla (ya da rotasyonuyla) gelmesini bekleriz. Bu, deterministik
    /// bir "kim tetikler" kuralı (ör. fingerprint karşılaştırması) yerine
    /// Signal'ın asimetrik "sırası gelen tetikler" modelini uygular.
    ///
    /// A responder that has not rotated yet does it before its first send,
    /// whatever the clock says (see `respond`).
    pub fn should_rotate(&self, now_ms: u64) -> bool {
        // `saturating_sub`: `last_rotation` gelecekte olabilir (saat geriye
        // gitti, ya da başka bir cihazda ileri saatle üretilmiş kalıcı bir
        // state) — çıplak çıkarma release'de sarar (spurious rotasyon),
        // debug'da panikler. Doygun çıkarma her iki durumu da güvenli kılar.
        // `abs_diff`: a clock set back more than a period also rotates,
        // instead of stalling until it passes `last_rotation` again.
        !self.has_responded_to_peer_key
            && (self.is_fresh_responder() || now_ms.abs_diff(self.last_rotation) > RATCHET_ROTATION_MS)
    }

    /// Still on the chains `respond` derived: no rotation in either direction.
    pub fn is_fresh_responder(&self) -> bool {
        !self.has_responded_to_peer_key && self.prev_root_key.is_none()
    }

    /// Nothing from the peer has decrypted in this session: it may never have
    /// processed our handshake. A rotation resets `recv_message_number`, so
    /// the chain before it counts too. (A state stored before `old_recv`
    /// existed has none: there, any rotation is taken as "heard".)
    pub fn never_heard(&self) -> bool {
        self.recv_message_number == 0
            && match &self.old_recv {
                Some(old) => old.next == 0,
                None => self.prev_root_key.is_none(),
            }
    }

    /// Bir sonraki gönderilecek mesajı şifreler (spec 3.3 `MessagePacket`
    /// alanlarını üretir). Nonce, message_number'dan deterministik türetilir
    /// (aynı chain key altında iki farklı mesaj numarası asla aynı nonce'u
    /// üretmez, bu da AEAD güvenliği için yeterlidir).
    ///
    /// `aad`: the packet's raw header bytes (M-89): the tag binds them, so
    /// the header the receiver acts on is the one the sender encrypted under.
    /// `next_send_numbers` gives the numbers to put in that header first.
    pub fn encrypt_next(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, u32, u32), RatchetError> {
        // The handshake chain of a responder is a function of the
        // HandshakeInit alone (see `respond`): never sent on.
        if self.is_fresh_responder() {
            return Err(RatchetError::ResponderMustRotate);
        }
        let message_number = self.send_message_number;
        // A wrapped counter would repeat a nonce under a live chain key.
        let next_number = message_number.checked_add(1).ok_or(RatchetError::ChainExhausted)?;
        let (mut message_key, mut next_chain_key) = chain_step(&self.ck_send)?;
        set_secret(&mut self.ck_send, next_chain_key.to_vec());
        next_chain_key.zeroize();
        self.send_message_number = next_number;

        let cipher = ChaCha20Poly1305::new_from_slice(&message_key).map_err(|_| "Invalid key")?;
        let nonce = nonce_from_message_number(message_number);
        let ciphertext = cipher.encrypt(&nonce, Payload { msg: plaintext, aad }).map_err(|_| "Encryption failed")?;
        // bkz. `DeviceRatchetState`'in `Drop` notu — bu, tek bir mesaja özel
        // anahtar, kullanıldıktan hemen sonra bellekten (üzerine yazılarak)
        // temizleniyor; fonksiyon dönüşünü beklemiyor.
        message_key.zeroize();

        Ok((ciphertext, message_number, self.prev_chain_length))
    }

    /// `(message_number, prev_chain_length)` the next `encrypt_next` uses.
    pub fn next_send_numbers(&self) -> (u32, u32) {
        (self.send_message_number, self.prev_chain_length)
    }

    /// Gelen bir mesajı çözer. `message_number` paketin header'ından gelir;
    /// `rotation` is the header's `(ratchet_pubkey, rotation_kyber_ciphertext)`
    /// when the packet announces a rotation.
    ///
    /// Three attempts, and the state changes only for the one whose AEAD tag
    /// verifies (bkz. `chain_decrypt`):
    /// 1. a rotation not applied yet: applied to a copy, kept if the packet
    ///    decrypts on the new chain (`SkippedKeyChanges::rotated`);
    /// 2. the current receive chain;
    /// 3. the chain before the last rotation (`SkippedKeyChanges::old_chain`).
    ///
    /// Bu fonksiyon hiçbir disk I/O yapmaz: dönen `SkippedKeyChanges` ile
    /// çağıran taraf (archive.rs) diskteki skipped-key tablosunu günceller.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        message_number: u32,
        rotation: Option<(&RatchetPublicKeys, &[u8])>,
        now_ms: u64,
        aad: &[u8],
    ) -> Result<(Vec<u8>, SkippedKeyChanges), RatchetError> {
        if self.old_recv.is_some() && now_ms.abs_diff(self.last_rotation) > OLD_RECV_MAX_AGE_MS {
            self.old_recv = None;
        }
        if let Some((new_peer_keys, kyber_ct)) = rotation {
            // Checked before the copy: the announcement is repeated on every
            // packet until we answer on the new chain.
            if new_peer_keys.x25519_pubkey != self.peer_x25519_pubkey.as_bytes() {
                let mut candidate = self.clone();
                if let Ok(true) = candidate.respond_to_rotation(new_peer_keys, kyber_ct, now_ms) {
                    let opened = chain_decrypt(
                        &mut candidate.ck_recv, &mut candidate.recv_message_number, &mut candidate.skipped_keys,
                        ciphertext, message_number, aad,
                    );
                    if let Ok((plaintext, mut changes)) = opened {
                        changes.rotated = true;
                        *self = candidate;
                        return Ok((plaintext, changes));
                    }
                }
            }
        }
        let current = chain_decrypt(&mut self.ck_recv, &mut self.recv_message_number, &mut self.skipped_keys, ciphertext, message_number, aad);
        let Err(current_err) = current else { return current };
        if let Some(old) = &mut self.old_recv {
            let old_next = old.next;
            match chain_decrypt(&mut old.ck, &mut old.next, &mut old.skipped, ciphertext, message_number, aad) {
                Ok((plaintext, _)) => {
                    let mut changes = SkippedKeyChanges::default();
                    changes.old_chain = true;
                    return Ok((plaintext, changes));
                }
                // A consumed packet of the old chain: a duplicate, not a
                // diverged session (fable H-03/A-08). The current chain's
                // DecryptFailed counted it toward the 3-strike reset.
                Err(RatchetError::KeyNotFound(n)) if message_number < old_next => return Err(RatchetError::KeyNotFound(n)),
                Err(_) => {}
            }
        }
        // The current chain's error: the caller tells a duplicate
        // (`RatchetError::KeyNotFound`) from a diverged session by it.
        Err(current_err)
    }
}

/// Decrypts on one receive chain (`chain_key`, `next` expected number, its
/// `skipped` keys). Signal Double Ratchet'teki standart mekanizma:
///
/// - `message_number >= next`: zincir o mesaja kadar ilerletilir, aradaki
///   mesajların anahtarları `skipped`'e kaydedilir (en fazla `MAX_SKIP_AHEAD`
///   adım; önbellekte en yeni `MAX_SKIPPED_KEYS` anahtar kalır, daha eskileri
///   atılır — a full cache used to refuse every later out-of-order packet).
/// - `message_number < next`: geç gelen bir mesaj; anahtarı `skipped`'te
///   varsa oradan alınıp silinir, yoksa hata.
///
/// Candidate keys are computed locally and written back only after the AEAD
/// tag verified: a signed packet with a made-up `message_number` and garbage
/// ciphertext must not move the chain.
fn chain_decrypt(
    chain_key: &mut Vec<u8>,
    next: &mut u32,
    skipped: &mut HashMap<u32, [u8; 32]>,
    ciphertext: &[u8],
    message_number: u32,
    aad: &[u8],
) -> Result<(Vec<u8>, SkippedKeyChanges), RatchetError> {
    let mut changes = SkippedKeyChanges::default();
    // The message key and, when the chain advances, (new chain key, new `next`).
    let (mut message_key, mut advance) = if message_number < *next {
        let key = *skipped.get(&message_number).ok_or(RatchetError::KeyNotFound(message_number))?;
        (key, None)
    } else {
        let after = message_number.checked_add(1).ok_or(RatchetError::ChainExhausted)?;
        let gap = message_number - *next;
        if gap > MAX_SKIP_AHEAD {
            return Err(RatchetError::TooManySkipped { gap, limit: MAX_SKIP_AHEAD });
        }
        let mut cursor = chain_key.clone();
        for number in *next..message_number {
            let (mut skipped_key, mut next_chain_key) = chain_step(&cursor)?;
            if message_number - number <= MAX_SKIPPED_KEYS as u32 {
                changes.added.push((number, skipped_key));
            }
            skipped_key.zeroize();
            set_secret(&mut cursor, next_chain_key.to_vec());
            next_chain_key.zeroize();
        }
        let (message_key, mut next_chain_key) = chain_step(&cursor)?;
        set_secret(&mut cursor, next_chain_key.to_vec());
        next_chain_key.zeroize();
        (message_key, Some((cursor, after)))
    };

    let opened = ChaCha20Poly1305::new_from_slice(&message_key)
        .map_err(|_| RatchetError::Invalid("Invalid key"))
        .and_then(|cipher| {
            cipher.decrypt(&nonce_from_message_number(message_number), Payload { msg: ciphertext, aad }).map_err(|_| RatchetError::DecryptFailed)
        });
    message_key.zeroize();
    let plaintext = match opened {
        Ok(plaintext) => plaintext,
        Err(e) => {
            if let Some((cursor, _)) = &mut advance {
                cursor.zeroize();
            }
            return Err(e);
        }
    };

    match advance {
        Some((new_chain_key, after)) => {
            set_secret(chain_key, new_chain_key);
            *next = after;
            for (number, key) in &changes.added {
                skipped.insert(*number, *key);
            }
            // One sort, not a scan of the whole map per evicted key.
            let excess = skipped.len().saturating_sub(MAX_SKIPPED_KEYS);
            if excess > 0 {
                let mut numbers: Vec<u32> = skipped.keys().copied().collect();
                numbers.sort_unstable();
                for oldest in numbers.into_iter().take(excess) {
                    if let Some(mut key) = skipped.remove(&oldest) {
                        key.zeroize();
                    }
                    changes.used.push(oldest);
                }
            }
        }
        None => {
            if let Some(mut key) = skipped.remove(&message_number) {
                key.zeroize();
            }
            changes.used.push(message_number);
        }
    }
    Ok((plaintext, changes))
}

/// Message number'dan deterministik 12-byte nonce türetir (ChaCha20-Poly1305
/// için). Aynı chain key altında her message_number benzersiz olduğundan
/// (spec 3.2 simetrik ratchet ilerlemesi) nonce çakışması oluşmaz.
fn nonce_from_message_number(n: u32) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[8..12].copy_from_slice(&n.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

/// Ham bayt dizisinden bir ML-KEM-1024 EncapsulationKey (public key) ayrıştırır.
/// `EncodedSizeUser::from_bytes` bu implementasyonda infallible'dır (ml-kem
/// public key noktası doğrulaması yapmaz, sadece boy kontrolü `try_into()`
/// ile burada yapılır). `hybrid_array::Array<T,N>` doğrudan `TryFrom<&[u8]>`
/// implement ediyor, bu yüzden `bytes.try_into()` derlenir.
fn kyber_pubkey_from_bytes(bytes: &[u8]) -> Result<MlKem1024EncapsulationKey, RatchetError> {
    let encoded: ml_kem::Encoded<MlKem1024EncapsulationKey> = bytes
        .try_into()
        .map_err(|_| RatchetError::Invalid("Bad Kyber public key length"))?;
    Ok(MlKem1024EncapsulationKey::from_bytes(&encoded))
}

/// Ham bayt dizisinden bir ML-KEM-1024 Ciphertext ayrıştırır.
fn kyber_ciphertext_from_bytes(bytes: &[u8]) -> Result<MlKemCiphertext<MlKem1024>, RatchetError> {
    bytes.try_into().map_err(|_| RatchetError::Invalid("Bad Kyber ciphertext length"))
}

// NOTE: Sıra dışı gelen mesajlar için "skipped message keys" cache'i var
// (`skipped_keys`, bkz. `chain_decrypt`). Rotasyonda önbellek, eski alma
// zinciriyle birlikte `old_recv`'e taşınır ve bir nesil daha kullanılabilir.
// Güncel zincirin önbelleği ayrı bir tabloda, state'in geri kalanı (eski
// zincir dahil) `SerializableRatchetState` olarak diske yazılır — ikisi de
// archive.rs/persist.rs tarafında şifreli (`persist_skipped_key`, `persist_ratchet_state`).
//
// NOTE / [SIGNAL MODELİ]: `perform_dh_ratchet`/`respond_to_rotation` çifti
// Signal'ın GERÇEK asimetrik modelini uyguluyor — deterministik bir
// "fingerprint küçük olan tetikler" kuralı YOK. Bunun yerine her
// `DeviceRatchetState`, `has_responded_to_peer_key` bayrağıyla "sıradaki
// rotasyonu tetikleme hakkı bende mi karşı tarafta mı" bilgisini taşır:
// - İlk el sıkışmada initiator=true (responder'a zaten cevap verdi),
//   responder=false (henüz initiator'a cevap vermedi).
// - `perform_dh_ratchet` çağıran taraf true'ya döner (karşı tarafın key'ine
//   cevap verdi, sıra onda).
// - `respond_to_rotation` çağıran taraf false'a döner (karşı taraf yeni key
//   üretti, henüz ona cevap vermedi, sıra bizde).
// `should_rotate()` = `!has_responded_to_peer_key && 30 dakika doldu`. Bu,
// Signal'ın "sırası gelen taraf tetikler" modelinin doğrudan karşılığı;
// iki taraf da aynı anda tetiklemeye çalışamaz çünkü her an sadece BİR
// tarafın bayrağı `false`'tur.

/// One-way handle of a root key: the gossipsub topic and the server seal key
/// are derived from it, so the previous generation can be kept for those
/// without keeping its root (fable H-02).
pub fn root_handle(root_key: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = vec![0u8; 32];
    hk.expand(b"typeon-root-handle-v1", &mut out).expect("32 bytes is a valid HKDF length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_000_000;

    /// A handshake as the core does it: the responder's long-term KEM keys,
    /// the initiator's fresh ones (`state.own_x25519_secret`, not its identity
    /// key — that mix-up once made every message fail to decrypt).
    /// Returns (initiator, responder).
    fn session() -> (DeviceRatchetState, DeviceRatchetState) {
        let (init, x_secret, kyber_secret) = handshake_init();
        let responder = respond_to(&init, x_secret, kyber_secret);
        (init.0, responder)
    }

    #[test]
    fn kem_key_needs_the_recipient_secrets() {
        let x_secret = StaticSecret::random_from_rng(&mut OsRng);
        let (kyber_secret, kyber_ek) = MlKem1024::generate(&mut OsRng);
        let (key, header) = kem_key_to(X25519PublicKey::from(&x_secret).as_bytes(), &kyber_ek.as_bytes()).unwrap();
        assert_eq!(header.len(), KEM_HEADER_LEN);
        assert_eq!(kem_key_from(&x_secret, &kyber_secret, &header).unwrap(), key);
        let other_x = StaticSecret::random_from_rng(&mut OsRng);
        assert_ne!(kem_key_from(&other_x, &kyber_secret, &header).unwrap(), key);
        let (other_kyber, _) = MlKem1024::generate(&mut OsRng);
        assert_ne!(kem_key_from(&x_secret, &other_kyber, &header).unwrap(), key);
    }

    type Init = (DeviceRatchetState, Vec<u8>, Vec<u8>);

    fn handshake_init() -> (Init, StaticSecret, MlKem1024DecapsulationKey) {
        let x_secret = StaticSecret::random_from_rng(&mut OsRng);
        let (kyber_secret, kyber_ek) = MlKem1024::generate(&mut OsRng);
        let init = DeviceRatchetState::initiate(X25519PublicKey::from(&x_secret).as_bytes(), &kyber_ek.as_bytes(), T0)
            .expect("initiate should succeed");
        (init, x_secret, kyber_secret)
    }

    fn respond_to((initiator, kyber_ct, initiator_kyber_pub): &Init, x_secret: StaticSecret, kyber_secret: MlKem1024DecapsulationKey) -> DeviceRatchetState {
        DeviceRatchetState::respond(
            x_secret, kyber_secret,
            X25519PublicKey::from(&initiator.own_x25519_secret).as_bytes(), initiator_kyber_pub, kyber_ct, T0,
        ).expect("respond should succeed")
    }

    /// `from` rotates and sends `text` with the announcement: (keys, kyber
    /// ciphertext, message ciphertext, message number).
    fn rotate_and_send(from: &mut DeviceRatchetState, text: &[u8]) -> (RatchetPublicKeys, Vec<u8>, Vec<u8>, u32) {
        let kyber_ct = from.perform_dh_ratchet(T0).unwrap();
        let (ciphertext, number, _) = from.encrypt_next(text, b"").unwrap();
        (from.own_ratchet_pubkeys(), kyber_ct, ciphertext, number)
    }

    #[test]
    fn handshake_round_trip_derives_matching_keys() {
        let (mut initiator, mut responder) = session();
        assert_eq!(initiator.root_key, responder.root_key, "root keys must match");
        assert_eq!(initiator.ck_send, responder.ck_recv, "initiator send == responder recv");
        assert_eq!(initiator.ck_recv, responder.ck_send, "initiator recv == responder send");

        let (ciphertext, number, _) = initiator.encrypt_next(b"merhaba", b"").unwrap();
        assert_eq!(responder.decrypt(&ciphertext, number, None, T0, b"").unwrap().0, b"merhaba");
        assert!(responder.encrypt_next(b"x", b"").is_err(), "a fresh responder must rotate first");
        let (keys, kyber_ct, ciphertext, number) = rotate_and_send(&mut responder, b"selam");
        assert_eq!(initiator.decrypt(&ciphertext, number, Some((&keys, &kyber_ct)), T0, b"").unwrap().0, b"selam");
    }

    /// M-89: the header is the AEAD's associated data; another header fails
    /// the tag and leaves the chain where it was.
    #[test]
    fn changed_header_does_not_decrypt() {
        let (mut initiator, mut responder) = session();
        assert_eq!(initiator.next_send_numbers(), (0, 0));
        let (ciphertext, number, _) = initiator.encrypt_next(b"m", b"header").unwrap();
        assert!(responder.decrypt(&ciphertext, number, None, T0, b"header2").is_err());
        assert_eq!(responder.decrypt(&ciphertext, number, None, T0, b"header").unwrap().0, b"m");
    }

    /// Findings 1 and 2: packets of the chain a rotation replaced still
    /// decrypt, on the side that rotated and on the side that followed, in
    /// any order.
    #[test]
    fn old_chain_packets_survive_a_rotation() {
        let (mut b, mut a) = session();
        // A, the responder, leaves the handshake chain first.
        let (keys0, ct0, hello, n_hello) = rotate_and_send(&mut a, b"hello");
        b.decrypt(&hello, n_hello, Some((&keys0, &ct0)), T0, b"").unwrap();
        // Sent by A before it knows of B's rotation.
        let (late_a0, n_a0, _) = a.encrypt_next(b"a0", b"").unwrap();
        let (late_a1, n_a1, _) = a.encrypt_next(b"a1", b"").unwrap();
        // Sent by B on its old chain, overtaken by the rotation packet.
        let (late_b0, n_b0, _) = b.encrypt_next(b"b0", b"").unwrap();
        let (keys, kyber_ct, rotated, n_rot) = rotate_and_send(&mut b, b"b1");

        let (plain, changes) = a.decrypt(&rotated, n_rot, Some((&keys, &kyber_ct)), T0, b"").unwrap();
        assert_eq!(plain, b"b1");
        assert!(changes.rotated && !changes.old_chain);
        assert_eq!(a.root_key, b.root_key);
        let (plain, changes) = a.decrypt(&late_b0, n_b0, None, T0, b"").unwrap();
        assert_eq!(plain, b"b0");
        assert!(changes.old_chain && !changes.rotated && changes.added.is_empty() && changes.used.is_empty());

        // Out of order on the old chain too: the skipped key lives in `old_recv`.
        assert!(b.decrypt(&late_a1, n_a1, None, T0, b"").unwrap().1.old_chain);
        assert_eq!(b.decrypt(&late_a0, n_a0, None, T0, b"").unwrap().0, b"a0");
        assert!(b.decrypt(&late_a0, n_a0, None, T0, b"").is_err(), "a replay must not decrypt twice");

        // The repeated announcement is a no-op, and the new chains work both ways.
        let (ciphertext, number, _) = b.encrypt_next(b"b2", b"").unwrap();
        let (plain, changes) = a.decrypt(&ciphertext, number, Some((&keys, &kyber_ct)), T0, b"").unwrap();
        assert_eq!(plain, b"b2");
        assert!(!changes.rotated);
        let (ciphertext, number, _) = a.encrypt_next(b"a2", b"").unwrap();
        let (plain, changes) = b.decrypt(&ciphertext, number, None, T0, b"").unwrap();
        assert_eq!(plain, b"a2");
        assert!(!changes.old_chain);
    }

    /// fable H-02: after a rotation both sides keep only the handle of the
    /// old root, and the two handles match (topic and server seal agree).
    #[test]
    fn rotation_keeps_only_a_handle_of_the_old_root() {
        let (mut b, mut a) = session();
        let old_root = a.root_key.clone();
        let (keys, kyber_ct, msg, n) = rotate_and_send(&mut a, b"x");
        b.decrypt(&msg, n, Some((&keys, &kyber_ct)), T0, b"").unwrap();
        assert_eq!(a.prev_root_key.as_deref(), Some(root_handle(&old_root).as_slice()));
        assert_eq!(a.prev_root_key, b.prev_root_key);
        assert_ne!(a.prev_root_key.as_deref(), Some(old_root.as_slice()));
        assert_eq!(a.root_handle_now(), b.root_handle_now());
    }

    /// Finding 3: an announcement that does not belong to this state (here: a
    /// rotation made for another session) leaves it untouched.
    #[test]
    fn foreign_rotation_does_not_commit() {
        let (mut b, mut a) = session();
        let (_, mut stranger) = session();
        let (keys, kyber_ct, ciphertext, number) = rotate_and_send(&mut stranger, b"x");
        let root_before = a.root_key.clone();
        assert!(a.decrypt(&ciphertext, number, Some((&keys, &kyber_ct)), T0, b"").is_err());
        assert_eq!(a.root_key, root_before);
        assert!(a.old_recv.is_none());
        let (ciphertext, number, _) = b.encrypt_next(b"still fine", b"").unwrap();
        assert_eq!(a.decrypt(&ciphertext, number, None, T0, b"").unwrap().0, b"still fine");
    }

    /// Finding 4: a long run of never-delivered packets does not kill the
    /// receive direction; the cache keeps the newest keys.
    #[test]
    fn skipped_key_cache_evicts_instead_of_refusing() {
        let (mut a, mut b) = session();
        let mut sent = Vec::new();
        for _ in 0..1500 {
            sent.push(a.encrypt_next(b"m", b"").unwrap());
        }
        let (ciphertext, number, _) = &sent[1400];
        let (_, changes) = b.decrypt(ciphertext, *number, None, T0, b"").unwrap();
        assert_eq!(changes.added.len(), MAX_SKIPPED_KEYS);
        assert_eq!(b.skipped_keys.len(), MAX_SKIPPED_KEYS);
        // One more gap: the oldest key makes room and is reported for deletion.
        let (ciphertext, number, _) = &sent[1402];
        let (_, changes) = b.decrypt(ciphertext, *number, None, T0, b"").unwrap();
        assert_eq!(changes.used, vec![400]);
        assert_eq!(b.skipped_keys.len(), MAX_SKIPPED_KEYS);
        assert!(b.decrypt(&sent[400].0, 400, None, T0, b"").is_err(), "evicted");
        assert_eq!(b.decrypt(&sent[401].0, 401, None, T0, b"").unwrap().0, b"m");

        // A jump past the work limit changes nothing.
        assert!(b.decrypt(b"garbage", 1403 + MAX_SKIP_AHEAD + 1, None, T0, b"").is_err());
        assert_eq!(b.recv_message_number, 1403);
    }

    /// Findings 12 and 13: a replayed HandshakeInit gives the responder the
    /// same state again, so it must rotate before it sends; after that the
    /// two replays share no send key.
    #[test]
    fn responder_rotates_before_its_first_send() {
        let (init, x_secret, kyber_secret) = handshake_init();
        let mut first = respond_to(&init, x_secret.clone(), kyber_secret.clone());
        let mut replayed = respond_to(&init, x_secret, kyber_secret);
        assert_eq!(first.ck_send, replayed.ck_send, "respond() is deterministic");
        assert!(first.should_rotate(T0) && first.is_fresh_responder());
        assert!(!init.0.should_rotate(T0 + 10 * RATCHET_ROTATION_MS), "the initiator waits for its turn");

        first.perform_dh_ratchet(T0).unwrap();
        replayed.perform_dh_ratchet(T0).unwrap();
        assert_ne!(first.ck_send, replayed.ck_send);
        assert!(!first.should_rotate(T0) && !first.is_fresh_responder());
        // Rotating does not count as hearing from the peer (handshake redo).
        assert!(first.never_heard() && init.0.never_heard());
    }

    /// Finding 14: a small-order X25519 key is refused, and the derived keys
    /// depend on the transcript, not only on the shared secrets.
    #[test]
    fn key_derivation_checks_and_binds_its_inputs() {
        let (_, kyber_ek) = MlKem1024::generate(&mut OsRng);
        assert!(DeviceRatchetState::initiate(&[0u8; 32], &kyber_ek.as_bytes(), T0).is_err());

        let ikm = vec![7u8; 64];
        let a = derive_keys(ikm.clone(), &[1u8; 32], true).unwrap();
        assert_ne!(a, derive_keys(ikm.clone(), &[2u8; 32], true).unwrap());
        let b = derive_keys(ikm, &[1u8; 32], false).unwrap();
        assert_eq!((&a.0, &a.1, &a.2), (&b.0, &b.2, &b.1));
    }

    /// A state stored by a version before `serde_bytes` and `old_recv` (byte
    /// fields as CBOR integer arrays) must still load: otherwise the update
    /// drops every session.
    #[test]
    fn stored_state_of_an_older_version_still_loads() {
        #[derive(Serialize)]
        struct OldFormat {
            root_key: Vec<u8>,
            prev_root_key: Option<Vec<u8>>,
            ck_send: Vec<u8>,
            ck_recv: Vec<u8>,
            own_x25519_secret: [u8; 32],
            own_kyber_secret: Vec<u8>,
            peer_x25519_pubkey: [u8; 32],
            peer_kyber_pubkey: Vec<u8>,
            send_message_number: u32,
            recv_message_number: u32,
            prev_chain_length: u32,
            last_rotation: u64,
            has_responded_to_peer_key: bool,
        }
        let (mut a, mut b) = session();
        let (keys, kyber_ct, ciphertext, number) = rotate_and_send(&mut b, b"x");
        a.decrypt(&ciphertext, number, Some((&keys, &kyber_ct)), T0, b"").unwrap();
        let p = a.to_persistable();
        let old = OldFormat {
            root_key: p.root_key.clone(),
            prev_root_key: p.prev_root_key.clone(),
            ck_send: p.ck_send.clone(),
            ck_recv: p.ck_recv.clone(),
            own_x25519_secret: p.own_x25519_secret,
            own_kyber_secret: p.own_kyber_secret.clone(),
            peer_x25519_pubkey: p.peer_x25519_pubkey,
            peer_kyber_pubkey: p.peer_kyber_pubkey.clone(),
            send_message_number: p.send_message_number,
            recv_message_number: p.recv_message_number,
            prev_chain_length: p.prev_chain_length,
            last_rotation: p.last_rotation,
            has_responded_to_peer_key: p.has_responded_to_peer_key,
        };
        let mut old_bytes = Vec::new();
        ciborium::into_writer(&old, &mut old_bytes).unwrap();
        let loaded: SerializableRatchetState = ciborium::from_reader(old_bytes.as_slice()).unwrap();
        let mut restored = DeviceRatchetState::from_persistable(loaded, HashMap::new()).unwrap();
        assert_eq!(restored.root_key, a.root_key);
        assert_eq!(restored.prev_root_key, a.prev_root_key);
        assert!(restored.old_recv.is_none());

        // The current format round-trips with the old chain, and is smaller.
        let mut new_bytes = Vec::new();
        ciborium::into_writer(&p, &mut new_bytes).unwrap();
        assert!(new_bytes.len() < old_bytes.len());
        let loaded: SerializableRatchetState = ciborium::from_reader(new_bytes.as_slice()).unwrap();
        assert!(DeviceRatchetState::from_persistable(loaded, HashMap::new()).unwrap().old_recv.is_some());

        let (ciphertext, number, _) = b.encrypt_next(b"after restart", b"").unwrap();
        assert_eq!(restored.decrypt(&ciphertext, number, None, T0, b"").unwrap().0, b"after restart");
    }

    #[test]
    fn old_chain_expires_and_header_keys_are_bounded() {
        let (mut b, mut a) = session();
        let (keys, kyber_ct, ciphertext, number) = rotate_and_send(&mut a, b"x");
        b.decrypt(&ciphertext, number, Some((&keys, &kyber_ct)), T0, b"").unwrap();
        assert!(b.old_recv.is_some());
        let (ciphertext, number, _) = a.encrypt_next(b"y", b"").unwrap();
        b.decrypt(&ciphertext, number, None, T0 + OLD_RECV_MAX_AGE_MS + 1, b"").unwrap();
        assert!(b.old_recv.is_none());
        assert!(RatchetPublicKeys::from_bytes(&keys.to_bytes().unwrap()).is_ok());
        let short = RatchetPublicKeys { x25519_pubkey: vec![0; 31], kyber_pubkey: keys.kyber_pubkey.clone() };
        assert!(RatchetPublicKeys::from_bytes(&short.to_bytes().unwrap()).is_err());
        assert!(RatchetPublicKeys::from_bytes(&vec![0u8; 4096]).is_err());
    }

    #[test]
    fn counters_do_not_wrap() {
        let (mut a, mut b) = session();
        a.send_message_number = u32::MAX;
        assert!(a.encrypt_next(b"x", b"").is_err());
        assert!(b.decrypt(b"x", u32::MAX, None, T0, b"").is_err());
    }
}
