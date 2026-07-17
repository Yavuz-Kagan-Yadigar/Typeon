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

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext as MlKemCiphertext, EncodedSizeUser, KemCore, MlKem1024};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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

/// Bir ratchet adımının hibrit (X25519 + ML-KEM) public key'i, serileştirilmiş
/// halde `MessagePacket.header.ratchet_pubkey` içinde taşınır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetPublicKeys {
    pub x25519_pubkey: Vec<u8>,
    pub kyber_pubkey: Vec<u8>,
}

impl RatchetPublicKeys {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(data).map_err(|e| e.to_string())
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
    /// SADECE `perform_dh_ratchet` çağıran (rotasyonu TETİKLEYEN) tarafta
    /// anlamlı — bu, o rotasyonu duyuran TEK mesajın (`rotation_kyber_ciphertext`
    /// dolu olan) hangi gossipsub topic'inden gönderilmesi gerektiğini
    /// belirlemek için lib.rs `try_publish_raw`'da kullanılır: karşı taraf bu
    /// mesajı ALANA kadar YENİ `root_key`'i (dolayısıyla yeni topic'i) bilemez
    /// — o yüzden rotasyonu duyuran mesaj hâlâ ESKİ (paylaşılan) topic'ten
    /// gönderilmeli, yoksa karşı taraf o topic'e hiç abone olmadığından mesaj
    /// asla ulaşmaz (gerçek bir üretim hatasıydı — bkz. commit notu).
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
    /// Sıra dışı/gecikmeli gelen mesajlar için "atlanmış mesaj anahtarları"
    /// önbelleği (Signal Double Ratchet'teki standart mekanizma). Bir mesaj
    /// beklenenden yüksek bir `message_number` ile gelirse, aradaki
    /// mesajların anahtarları burada saklanır — böylece o mesajlar daha
    /// sonra (gecikmeli/sırasız) gelirse hâlâ çözülebilir. key = mesaj
    /// numarası. `MAX_SKIPPED_KEYS` ile sınırlanır (bellek/DoS koruması —
    /// kötü niyetli biri çok yüksek bir message_number göndererek sınırsız
    /// bellek tükettiremesin diye). Diske şifreli olarak kalıcılaştırılır
    /// (bkz. lib.rs `persist_skipped_key`/`load_skipped_keys_from_db`) —
    /// süreç yeniden başlasa bile gecikmeli mesajlar çözülebilsin diye
    /// (kapsam sınırı için bkz. lib.rs ilgili not).
    pub skipped_keys: HashMap<u32, [u8; 32]>,
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
/// dönüştürülür (aynen `lib.rs`'teki `SecretKeyBundle`'ın kendi cihaz
/// anahtarları için yaptığı gibi — bkz. `generate_identity`/
/// `load_secret_bundle`). `skipped_keys` KASITLI OLARAK burada YOK: o
/// zaten ayrı bir tabloda (`skipped_message_keys`) kendi başına kalıcı
/// kılınıyor (bkz. lib.rs `persist_skipped_key`/`load_skipped_keys_from_db`)
/// — burada tekrar taşımak, iki kopyanın birbirinden sapma riskini
/// (data drift) gereksiz yere ekler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableRatchetState {
    pub root_key: Vec<u8>,
    /// bkz. `DeviceRatchetState.prev_root_key` dokümantasyonu — süreç bir
    /// rotasyon ANONS EDEN ama henüz karşı tarafça alınmamış bir mesajın
    /// ortasında yeniden başlarsa, `pending_envelopes` kalıcı olmadığından
    /// bu değer kaybolursa yeniden denemeler yanlış topic'e düşebilir; bu
    /// yüzden burada da kalıcı kılınıyor.
    pub prev_root_key: Option<Vec<u8>>,
    pub ck_send: Vec<u8>,
    pub ck_recv: Vec<u8>,
    pub own_x25519_secret: [u8; 32],
    pub own_kyber_secret: Vec<u8>,
    pub peer_x25519_pubkey: [u8; 32],
    pub peer_kyber_pubkey: Vec<u8>,
    pub send_message_number: u32,
    pub recv_message_number: u32,
    pub prev_chain_length: u32,
    pub last_rotation: u64,
    pub has_responded_to_peer_key: bool,
}

impl DeviceRatchetState {
    /// bkz. `SerializableRatchetState` dokümantasyonu. `skipped_keys`
    /// hariç tutulur — çağıran taraf (lib.rs) onu ayrıca yükleyip
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
        }
    }

    /// `skipped_keys`: diskteki `skipped_message_keys` tablosundan ayrıca
    /// yüklenip buraya geçirilmelidir (bkz. lib.rs
    /// `load_skipped_keys_from_db`) — bu fonksiyon kendisi o tabloya
    /// erişmez (ratchet.rs kripto-only katman, dosya başı notuyla tutarlı).
    pub fn from_persistable(s: SerializableRatchetState, skipped_keys: HashMap<u32, [u8; 32]>) -> Result<Self, String> {
        let own_kyber_encoded: ml_kem::Encoded<MlKem1024DecapsulationKey> = s.own_kyber_secret.as_slice()
            .try_into().map_err(|_| "Bozuk kayıtlı Kyber secret key")?;
        Ok(DeviceRatchetState {
            root_key: s.root_key,
            prev_root_key: s.prev_root_key,
            ck_send: s.ck_send,
            ck_recv: s.ck_recv,
            own_x25519_secret: StaticSecret::from(s.own_x25519_secret),
            own_kyber_secret: MlKem1024DecapsulationKey::from_bytes(&own_kyber_encoded),
            peer_x25519_pubkey: X25519PublicKey::from(s.peer_x25519_pubkey),
            peer_kyber_pubkey: kyber_pubkey_from_bytes(&s.peer_kyber_pubkey)?,
            send_message_number: s.send_message_number,
            recv_message_number: s.recv_message_number,
            prev_chain_length: s.prev_chain_length,
            last_rotation: s.last_rotation,
            has_responded_to_peer_key: s.has_responded_to_peer_key,
            skipped_keys,
        })
    }
}

/// `DeviceRatchetState::decrypt` çağrısı sırasında skipped-key
/// önbelleğinde olan değişiklikleri raporlar — çağıran taraf (lib.rs) bu
/// bilgiyle diskteki şifreli kopyayı güncel tutar.
#[derive(Debug, Default)]
pub struct SkippedKeyChanges {
    /// Yeni eklenen skipped-key'ler: (message_number, key).
    pub added: Vec<(u32, [u8; 32])>,
    /// Kullanılıp önbellekten (ve diskten) silinmesi gereken message_number'lar.
    pub used: Vec<u32>,
}

fn current_time_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Root/send/recv anahtarlarını HKDF ile türetir. `we_initiated` yön
/// simetrisini garanti eder: initiator'ın send-key'i responder'ın
/// recv-key'ine eşit olur.
fn derive_keys(ikm: &[u8], we_initiated: bool) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut root_key = [0u8; 32];
    let mut key_a = [0u8; 32];
    let mut key_b = [0u8; 32];
    hk.expand(b"p2pmsg-v0.1-root", &mut root_key).map_err(|_| "HKDF expand failed")?;
    hk.expand(b"p2pmsg-v0.1-a-to-b", &mut key_a).map_err(|_| "HKDF expand failed")?;
    hk.expand(b"p2pmsg-v0.1-b-to-a", &mut key_b).map_err(|_| "HKDF expand failed")?;

    let (send, recv) = if we_initiated { (key_a, key_b) } else { (key_b, key_a) };
    Ok((root_key.to_vec(), send.to_vec(), recv.to_vec()))
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
    ) -> Result<(Self, Vec<u8>, Vec<u8>), String> {
        // X25519 (x25519-dalek, rand_core 0.6 üzerinden rand 0.8) ve ML-KEM
        // (ml-kem crate'i, rand_core 0.6.4) aynı rand_core majör sürümünü
        // kullanıyor — aynı `OsRng`'u ikisine de geçirebiliriz.
        let mut csprng = OsRng;
        let own_x25519_secret = StaticSecret::random_from_rng(&mut csprng);

        let peer_x25519_bytes: [u8; 32] = peer_x25519_pubkey.try_into().map_err(|_| "Bad peer X25519 key length")?;
        let peer_x25519_pk = X25519PublicKey::from(peer_x25519_bytes);
        let dh_shared = own_x25519_secret.diffie_hellman(&peer_x25519_pk);

        // Kendi taze Kyber çiftimizi üret.
        let (own_kyber_secret, _own_kyber_ek) = MlKem1024::generate(&mut csprng);
        let own_kyber_public_bytes = own_kyber_secret.encapsulation_key().as_bytes().to_vec();

        let peer_kyber_pk = kyber_pubkey_from_bytes(peer_kyber_pubkey)?;
        let (kyber_ct, kyber_shared) = peer_kyber_pk.encapsulate(&mut csprng).map_err(|_| "Kyber encapsulate failed")?;

        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(dh_shared.as_bytes());
        ikm.extend_from_slice(kyber_shared.as_slice());
        let (root_key, ck_send, ck_recv) = derive_keys(&ikm, true)?;

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
            last_rotation: current_time_ms(),
            // Initiator, responder'ın İLK public key'ine karşı zaten
            // DH+encapsulate yaptı — bu "cevap verdim" sayılır. Sıradaki
            // rotasyon hakkı responder'da.
            has_responded_to_peer_key: true,
            skipped_keys: HashMap::new(),
        };
        Ok((state, kyber_ct.to_vec(), own_kyber_public_bytes))
    }

    /// Responder tarafı: gelen `HandshakeInit`'teki initiator public key'i
    /// ve Kyber ciphertext'i kullanarak aynı anahtarları türetir.
    pub fn respond(
        own_x25519_secret: StaticSecret,
        own_kyber_secret: MlKem1024DecapsulationKey,
        initiator_x25519_pubkey: &[u8],
        initiator_kyber_pubkey: &[u8],
        kyber_ciphertext: &[u8],
    ) -> Result<Self, String> {
        let initiator_x25519_bytes: [u8; 32] = initiator_x25519_pubkey.try_into().map_err(|_| "Bad initiator X25519 key length")?;
        let initiator_x25519_pk = X25519PublicKey::from(initiator_x25519_bytes);
        let dh_shared = own_x25519_secret.diffie_hellman(&initiator_x25519_pk);

        let ct = kyber_ciphertext_from_bytes(kyber_ciphertext)?;
        let kyber_shared = own_kyber_secret.decapsulate(&ct).map_err(|_| "Kyber decapsulate failed")?;

        let initiator_kyber_pk = kyber_pubkey_from_bytes(initiator_kyber_pubkey)?;

        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(dh_shared.as_bytes());
        ikm.extend_from_slice(kyber_shared.as_slice());
        let (root_key, ck_send, ck_recv) = derive_keys(&ikm, false)?;

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
            last_rotation: current_time_ms(),
            // Responder henüz initiator'ın public key'ine (gelecekteki bir
            // rotasyonda) cevap vermedi — 30 dakika dolduğunda rotasyonu
            // TETİKLEME hakkı responder'da (initiator zaten "cevap verdi"
            // sayıldığı için tetiklemeyecek, bkz. initiate()).
            has_responded_to_peer_key: false,
            skipped_keys: HashMap::new(),
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
    pub fn perform_dh_ratchet(&mut self) -> Result<Vec<u8>, String> {
        let mut csprng = OsRng;
        let new_x25519_secret = StaticSecret::random_from_rng(&mut csprng);
        let (new_kyber_secret, _new_kyber_ek) = MlKem1024::generate(&mut csprng);

        let dh_shared = new_x25519_secret.diffie_hellman(&self.peer_x25519_pubkey);
        let (kyber_ct, kyber_shared) = self.peer_kyber_pubkey.encapsulate(&mut csprng).map_err(|_| "Kyber encapsulate failed")?;

        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(self.root_key.as_slice());
        ikm.extend_from_slice(dh_shared.as_bytes());
        ikm.extend_from_slice(kyber_shared.as_slice());

        // Bu fonksiyon her zaman "ben tetikliyorum" anlamına gelir —
        // we_initiated=true.
        let (new_root, new_send, new_recv) = derive_keys(&ikm, true)?;

        self.prev_chain_length = self.send_message_number;
        self.send_message_number = 0;
        self.recv_message_number = 0;
        // bkz. `prev_root_key` alanı dokümantasyonu — bu rotasyonu ANONS
        // EDEN mesaj hâlâ bu ESKİ değere karşılık gelen gossipsub topic'ten
        // gönderilmeli (karşı taraf henüz YENİ root_key'i bilmiyor).
        self.prev_root_key = Some(std::mem::replace(&mut self.root_key, new_root));
        self.ck_send = new_send;
        self.ck_recv = new_recv;
        self.own_x25519_secret = new_x25519_secret;
        self.own_kyber_secret = new_kyber_secret;
        self.last_rotation = current_time_ms();
        // Karşı tarafın (rotasyon öncesi) bilinen public key'ine karşı
        // encapsulate ettik — "cevap verdim" sayılır. Sıradaki rotasyon
        // hakkı artık karşı tarafta.
        self.has_responded_to_peer_key = true;
        // Eski zincire ait atlanmış anahtarlar artık anlamsız (kök anahtar
        // değişti, farklı bir HKDF zinciri) — temizle.
        self.skipped_keys.clear();
        Ok(kyber_ct.to_vec())
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
    pub fn respond_to_rotation(&mut self, new_peer_keys: &RatchetPublicKeys, rotation_kyber_ciphertext: &[u8]) -> Result<(), String> {
        let x25519_bytes: [u8; 32] = new_peer_keys.x25519_pubkey.as_slice().try_into().map_err(|_| "Bad peer X25519 key length")?;
        let new_peer_x25519_pk = X25519PublicKey::from(x25519_bytes);
        let new_peer_kyber_pk = kyber_pubkey_from_bytes(&new_peer_keys.kyber_pubkey)?;

        // DH: KENDİ (rotasyon öncesi, hâlâ geçerli) X25519 secret'ımızla,
        // karşı tarafın YENİ X25519 public key'ine karşı.
        let dh_shared = self.own_x25519_secret.diffie_hellman(&new_peer_x25519_pk);

        // KEM: karşı tarafın bize gönderdiği ciphertext'i, KENDİ (rotasyon
        // öncesi, hâlâ geçerli) Kyber secret'ımızla decapsulate ediyoruz —
        // perform_dh_ratchet'teki `self.peer_kyber_pubkey.encapsulate(...)`
        // çağrısının simetriği (karşı taraf BİZİM eski Kyber public
        // key'imize karşı encapsulate etmişti).
        let ct = kyber_ciphertext_from_bytes(rotation_kyber_ciphertext)?;
        let kyber_shared = self.own_kyber_secret.decapsulate(&ct).map_err(|_| "Kyber decapsulate failed")?;

        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(self.root_key.as_slice());
        ikm.extend_from_slice(dh_shared.as_bytes());
        ikm.extend_from_slice(kyber_shared.as_slice());

        // Rotasyonu BİZ başlatmadık, karşı taraf başlattı — we_initiate_rotation=false.
        let (new_root, new_send, new_recv) = derive_keys(&ikm, false)?;

        self.prev_chain_length = self.recv_message_number;
        self.send_message_number = 0;
        self.recv_message_number = 0;
        self.root_key = new_root;
        self.ck_send = new_send;
        self.ck_recv = new_recv;
        // Kendi own_x25519_secret/own_kyber_secret'ımızı DEĞİŞTİRMİYORUZ —
        // rotasyonu biz başlatmadık, kendi anahtar çiftimiz aynı kalır; bir
        // sonraki rotasyonu BİZ başlatırsak (perform_dh_ratchet) o zaman
        // yenileriz. Peer public key'lerinin ikisini de güncelliyoruz (bkz.
        // fonksiyon dokümantasyonu — Kyber tarafı gelecekteki rotasyonlar
        // için gerekli).
        self.peer_x25519_pubkey = new_peer_x25519_pk;
        self.peer_kyber_pubkey = new_peer_kyber_pk;
        self.last_rotation = current_time_ms();
        // Karşı taraf yeni bir public key üretti, biz henüz BU yeni
        // key'e karşı kendi tarafımızda bir DH/KEM adımı yapmadık —
        // sıradaki rotasyon hakkı bizde (30 dakika dolduğunda BİZ
        // perform_dh_ratchet çağırırız).
        self.has_responded_to_peer_key = false;
        // Eski zincire ait atlanmış anahtarlar artık anlamsız — temizle.
        self.skipped_keys.clear();
        Ok(())
    }

    /// Spec 3.2: 30 dakika kuralı + Signal'ın gerçek modeli — SADECE henüz
    /// karşı tarafın güncel public key'ine cevap vermemiş taraf (
    /// `has_responded_to_peer_key == false`) rotasyonu tetikleyebilir.
    /// Cevap zaten verilmişse (sıradaki rotasyon hakkı karşı tarafta),
    /// 30 dakika dolmuş olsa bile BİZ tetiklemeyiz — karşı tarafın kendi
    /// mesajıyla (ya da rotasyonuyla) gelmesini bekleriz. Bu, deterministik
    /// bir "kim tetikler" kuralı (ör. fingerprint karşılaştırması) yerine
    /// Signal'ın asimetrik "sırası gelen tetikler" modelini uygular.
    pub fn should_rotate(&self) -> bool {
        // `saturating_sub`: `last_rotation` gelecekte olabilir (saat geriye
        // gitti, ya da başka bir cihazda ileri saatle üretilmiş kalıcı bir
        // state) — çıplak çıkarma release'de sarar (spurious rotasyon),
        // debug'da panikler. Doygun çıkarma her iki durumu da güvenli kılar.
        !self.has_responded_to_peer_key
            && current_time_ms().saturating_sub(self.last_rotation) > RATCHET_ROTATION_MS
    }

    /// Simetrik ratchet ilerlemesi (spec 3.2): her mesajda mesaj anahtarı
    /// HKDF zinciriyle ilerletilir. `ck_send`'i bir sonraki mesaj için
    /// günceller ve o mesaja özel anahtarı döner.
    fn advance_send_chain(&mut self) -> Result<[u8; 32], String> {
        let hk = Hkdf::<Sha256>::new(None, &self.ck_send);
        let mut message_key = [0u8; 32];
        let mut next_chain_key = [0u8; 32];
        hk.expand(b"p2pmsg-v0.1-msgkey", &mut message_key).map_err(|_| "HKDF expand failed")?;
        hk.expand(b"p2pmsg-v0.1-chainkey", &mut next_chain_key).map_err(|_| "HKDF expand failed")?;
        self.ck_send = next_chain_key.to_vec();
        Ok(message_key)
    }

    fn advance_recv_chain(&mut self) -> Result<[u8; 32], String> {
        let hk = Hkdf::<Sha256>::new(None, &self.ck_recv);
        let mut message_key = [0u8; 32];
        let mut next_chain_key = [0u8; 32];
        hk.expand(b"p2pmsg-v0.1-msgkey", &mut message_key).map_err(|_| "HKDF expand failed")?;
        hk.expand(b"p2pmsg-v0.1-chainkey", &mut next_chain_key).map_err(|_| "HKDF expand failed")?;
        self.ck_recv = next_chain_key.to_vec();
        Ok(message_key)
    }

    /// Bir sonraki gönderilecek mesajı şifreler (spec 3.3 `MessagePacket`
    /// alanlarını üretir). Nonce, message_number'dan deterministik türetilir
    /// (aynı chain key altında iki farklı mesaj numarası asla aynı nonce'u
    /// üretmez, bu da AEAD güvenliği için yeterlidir).
    pub fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, u32, u32), String> {
        let mut message_key = self.advance_send_chain()?;
        let message_number = self.send_message_number;
        self.send_message_number += 1;

        let cipher = ChaCha20Poly1305::new_from_slice(&message_key).map_err(|_| "Invalid key")?;
        let nonce = nonce_from_message_number(message_number);
        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| "Encryption failed")?;
        // bkz. `DeviceRatchetState`'in `Drop` notu — bu, tek bir mesaja özel
        // anahtar, kullanıldıktan hemen sonra bellekten (üzerine yazılarak)
        // temizleniyor; fonksiyon dönüşünü beklemiyor.
        message_key.zeroize();

        Ok((ciphertext, message_number, self.prev_chain_length))
    }

    /// Gelen bir mesajı çözer. `message_number`, paketin header'ından gelir.
    /// Üç durum ele alınır (Signal Double Ratchet'teki standart mekanizma):
    ///
    /// 1. `message_number == recv_message_number` (beklenen sıradaki mesaj):
    ///    normal ilerleme, zincir bir adım atar.
    /// 2. `message_number > recv_message_number` (mesaj(lar) atlanmış —
    ///    ör. ağ sırası karıştı, bir önceki mesaj henüz gelmedi ama bu
    ///    geldi): aradaki TÜM mesaj numaraları için anahtar türetilip
    ///    `skipped_keys`'e kaydedilir, `recv_message_number` bu mesajın
    ///    numarasının bir fazlasına atlanır, sonra normal çözülür.
    /// 3. `message_number < recv_message_number` (daha önce "atlanmış"
    ///    sayılan bir mesaj şimdi geç geldi): `skipped_keys`'te varsa
    ///    oradan anahtar alınıp çözülür ve önbellekten silinir; yoksa
    ///    (daha önce zaten çözülmüş veya önbellek dolup atılmışsa) hata
    ///    döner.
    ///
    /// Dönüş değeri, çözülen metnin yanında `SkippedKeyChanges`'i de taşır
    /// — çağıran taraf (lib.rs) bu bilgiyle diskteki (Keystore ile şifreli)
    /// skipped-key tablosunu güncel tutar. Bu fonksiyon kendisi hiçbir disk
    /// I/O yapmaz — ratchet.rs kripto-only katman olarak kalır.
    pub fn decrypt(&mut self, ciphertext: &[u8], message_number: u32) -> Result<(Vec<u8>, SkippedKeyChanges), String> {
        use std::cmp::Ordering;

        let mut changes = SkippedKeyChanges::default();

        let mut message_key = match message_number.cmp(&self.recv_message_number) {
            Ordering::Equal => {
                let key = self.advance_recv_chain()?;
                self.recv_message_number += 1;
                key
            }
            Ordering::Greater => {
                let gap = (message_number - self.recv_message_number) as usize;
                if self.skipped_keys.len() + gap > MAX_SKIPPED_KEYS {
                    return Err(format!(
                        "Too many skipped messages (gap {}, cache would exceed {} entries) — refusing to avoid unbounded memory use",
                        gap, MAX_SKIPPED_KEYS
                    ));
                }
                // Aradaki tüm mesajların anahtarlarını türetip önbelleğe al.
                while self.recv_message_number < message_number {
                    let skipped_key = self.advance_recv_chain()?;
                    self.skipped_keys.insert(self.recv_message_number, skipped_key);
                    changes.added.push((self.recv_message_number, skipped_key));
                    self.recv_message_number += 1;
                }
                // Şimdi tam istenen mesaja geldik.
                let key = self.advance_recv_chain()?;
                self.recv_message_number += 1;
                key
            }
            Ordering::Less => {
                let key = self.skipped_keys.remove(&message_number).ok_or_else(|| {
                    format!(
                        "Message {} not found in skipped-key cache (already decrypted, or evicted)",
                        message_number
                    )
                })?;
                changes.used.push(message_number);
                key
            }
        };

        let cipher = ChaCha20Poly1305::new_from_slice(&message_key).map_err(|_| "Invalid key")?;
        let nonce = nonce_from_message_number(message_number);
        let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| "Decryption failed".to_string())?;
        // bkz. `encrypt_next`'teki aynı not.
        message_key.zeroize();
        Ok((plaintext, changes))
    }
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
fn kyber_pubkey_from_bytes(bytes: &[u8]) -> Result<MlKem1024EncapsulationKey, String> {
    let encoded: ml_kem::Encoded<MlKem1024EncapsulationKey> = bytes
        .try_into()
        .map_err(|_| "Bad Kyber public key length".to_string())?;
    Ok(MlKem1024EncapsulationKey::from_bytes(&encoded))
}

/// Ham bayt dizisinden bir ML-KEM-1024 Ciphertext ayrıştırır.
fn kyber_ciphertext_from_bytes(bytes: &[u8]) -> Result<MlKemCiphertext<MlKem1024>, String> {
    bytes.try_into().map_err(|_| "Bad Kyber ciphertext length".to_string())
}

// NOTE: Sıra dışı gelen mesajlar için "skipped message keys" cache'i var
// (`skipped_keys` alanı, `decrypt`'in üç durumlu mantığı). Bir mesaj
// beklenenden yüksek numarayla gelirse aradaki anahtarlar önbelleğe alınır
// (en fazla `MAX_SKIPPED_KEYS` = 1000 adet — bellek/DoS koruması), daha
// düşük numarayla gelirse önbellekten aranır. Rotasyon olduğunda
// (`perform_dh_ratchet`/`respond_to_rotation`) önbellek temizlenir çünkü
// eski zincire ait anahtarlar yeni kök anahtarla anlamsız kalır. Önbellek
// diske de (Keystore ile şifreli) kalıcılaştırılıyor — bkz. lib.rs
// `persist_skipped_key`/`load_skipped_keys_from_db` — ama BİLİNEN SINIR:
// `DeviceRatchetState`'in TAMAMI (root_key/ck_send/ck_recv) hâlâ bellek-only,
// yani bu kalıcılık sadece "aynı oturum içinde, süreç arka planda canlı
// kalırken" anlamlıdır (bkz. lib.rs initiate_handshake_with sonrası not).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Bir "cihazın" uzun vadeli (identity) X25519 anahtar çiftini simüle
    /// eder — `initiate()`/`respond()`'a geçilen `peer_x25519_pubkey`/
    /// `own_x25519_secret` parametreleri gerçek kodda buradan gelir
    /// (bkz. lib.rs `own_device_keys`/`known_remote_devices`).
    fn fresh_identity_x25519() -> (StaticSecret, Vec<u8>) {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = X25519PublicKey::from(&secret).as_bytes().to_vec();
        (secret, public)
    }

    fn fresh_identity_kyber() -> (MlKem1024DecapsulationKey, Vec<u8>) {
        let (sk, _ek) = MlKem1024::generate(&mut OsRng);
        let pk_bytes = sk.encapsulation_key().as_bytes().to_vec();
        (sk, pk_bytes)
    }

    /// Bu test tam olarak lib.rs'in yapması gereken akışı uyguluyor —
    /// `initiate()`'in döndürdüğü `state.own_x25519_secret`'ten public key
    /// türetilip HandshakeInit'e konuyor (bkz. `initiate_handshake_with`
    /// düzeltmesi: önceden buraya YANLIŞLIKLA cihazın uzun-vadeli identity
    /// anahtarından türetilen bir public key konuyordu, iki taraf farklı
    /// paylaşılan sır türetip HER mesajda "Decryption failed" alıyordu).
    /// Bu test, initiator/responder'ın gerçekten AYNI kök/zincir
    /// anahtarlarına ulaştığını ve karşılıklı şifreleme/çözmenin
    /// çalıştığını doğrular — tam da bu sınıf bir regresyonu yakalamak için.
    #[test]
    fn handshake_round_trip_derives_matching_keys() {
        // "Responder"ın uzun vadeli kimlik anahtarları (initiator bunlara
        // karşı DH+encapsulate yapacak — bkz. initiate()'in ilk iki
        // parametresi).
        let (responder_identity_x25519_secret, responder_identity_x25519_pubkey) = fresh_identity_x25519();
        let (responder_identity_kyber_secret, responder_identity_kyber_pubkey) = fresh_identity_kyber();

        let (initiator_state, kyber_ciphertext, initiator_kyber_pubkey) = DeviceRatchetState::initiate(
            &responder_identity_x25519_pubkey,
            &responder_identity_kyber_pubkey,
        ).expect("initiate should succeed");

        // KRİTİK adım: gerçek initiator_x25519_pubkey, initiate()'in
        // ürettiği TAZE ephemeral secret'ten türetilmeli — lib.rs'teki bug
        // tam olarak burada, başka bir (yanlış) secret kullanıyordu.
        let initiator_x25519_pubkey = X25519PublicKey::from(&initiator_state.own_x25519_secret).as_bytes().to_vec();

        let responder_state = DeviceRatchetState::respond(
            responder_identity_x25519_secret,
            responder_identity_kyber_secret,
            &initiator_x25519_pubkey,
            &initiator_kyber_pubkey,
            &kyber_ciphertext,
        ).expect("respond should succeed");

        // İki taraf da AYNI kök anahtara ulaşmalı; send/recv çiftleri
        // çapraz eşleşmeli (initiator'ın send'i responder'ın recv'i).
        assert_eq!(initiator_state.root_key, responder_state.root_key, "root keys must match");
        assert_eq!(initiator_state.ck_send, responder_state.ck_recv, "initiator send == responder recv");
        assert_eq!(initiator_state.ck_recv, responder_state.ck_send, "initiator recv == responder send");

        // Uçtan uca: initiator -> responder ve responder -> initiator.
        let mut initiator_state = initiator_state;
        let mut responder_state = responder_state;

        let (ciphertext, message_number, _prev_len) = initiator_state.encrypt_next(b"merhaba").unwrap();
        let (plaintext, _changes) = responder_state.decrypt(&ciphertext, message_number).unwrap();
        assert_eq!(plaintext, b"merhaba");

        let (ciphertext2, message_number2, _prev_len2) = responder_state.encrypt_next(b"selam").unwrap();
        let (plaintext2, _changes2) = initiator_state.decrypt(&ciphertext2, message_number2).unwrap();
        assert_eq!(plaintext2, b"selam");
    }
}
