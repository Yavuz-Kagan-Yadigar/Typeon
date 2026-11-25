//! Double Ratchet with a hybrid KEM handshake.
//!
//! - Hybrid KEM session setup (X25519 + ML-KEM-1024).
//! - Symmetric ratchet (advances on every message) plus a DH/KEM ratchet: a fresh
//!   X25519 + ML-KEM pair every 30 minutes, which restores secrecy after a key leak.
//! - `ratchet_pubkey`, `message_number` and `prev_chain_length` (see `packet`) are produced
//!   and consumed here.
//!
//! Crypto library: ML-KEM-1024 (FIPS 203) comes from the RustCrypto `ml-kem` crate (see
//! Cargo.toml). ml-kem draws its randomness from getrandom itself; `OsRng` is passed only
//! to x25519-dalek.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem1024};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

pub type MlKem1024DecapsulationKey = ml_kem::DecapsulationKey1024;
pub type MlKem1024EncapsulationKey = ml_kem::EncapsulationKey1024;
type MlKemCiphertext = ml_kem::Ciphertext<MlKem1024>;

/// New ML-KEM-1024 key pair from the system RNG.
pub fn mlkem_generate() -> (MlKem1024DecapsulationKey, MlKem1024EncapsulationKey) {
    MlKem1024::generate_keypair()
}

/// Stored form of a decapsulation key: the 64-byte seed. A key loaded from the old 3168-byte expanded form has no
/// seed and is written back in that form.
pub fn mlkem_dk_to_bytes(dk: &MlKem1024DecapsulationKey) -> Vec<u8> {
    match dk.to_seed() {
        Some(mut seed) => {
            let bytes = seed.to_vec();
            seed.as_mut_slice().zeroize();
            bytes
        }
        #[allow(deprecated)]
        None => ml_kem::ExpandedKeyEncoding::to_expanded_bytes(dk).to_vec(),
    }
}

/// Reads `mlkem_dk_to_bytes`: a 64-byte seed, or a 3168-byte expanded key written by ml-kem 0.2 (identity keys on
/// disk, recovery files), so an update does not lose the device identity.
pub fn mlkem_dk_from_bytes(bytes: &[u8]) -> Result<MlKem1024DecapsulationKey, RatchetError> {
    if let Ok(seed) = ml_kem::Seed::try_from(bytes) {
        return Ok(MlKem1024DecapsulationKey::from_seed(seed));
    }
    #[allow(deprecated)]
    let expanded = ml_kem::ml_kem_1024::ExpandedDecapsulationKey::try_from(bytes)
        .map_err(|_| RatchetError::Invalid("Bad Kyber secret key length"))?;
    #[allow(deprecated)]
    let dk = <MlKem1024DecapsulationKey as ml_kem::ExpandedKeyEncoding>::from_expanded_bytes(&expanded)
        .map_err(|_| RatchetError::Invalid("Bad Kyber secret key"));
    let mut expanded = expanded;
    expanded.as_mut_slice().zeroize();
    dk
}

/// The 1568-byte encoded public key.
pub fn mlkem_ek_to_bytes(ek: &MlKem1024EncapsulationKey) -> Vec<u8> {
    ek.to_bytes().to_vec()
}

/// Ratchet policy: a DH/KEM ratchet step every 30 minutes (time-based, independent of message count).
pub const RATCHET_ROTATION_MS: u64 = 30 * 60 * 1000;

/// Upper bound on skipped message keys one receiver caches for a single sender. This limits memory
/// use under attack. Signal uses a similar limit, typically around 1000.
const MAX_SKIPPED_KEYS: usize = 1000;

/// How far one packet may advance a receive chain. Each step is two HKDF expansions, done BEFORE the
/// packet is authenticated, so this bounds the CPU cost of a bogus but signed `message_number`. Of a
/// jump, only the newest `MAX_SKIPPED_KEYS` keys are kept.
// ponytail: a peer that sends more than this many undelivered packets on one chain stays
// undecryptable until the next rotation or handshake.
const MAX_SKIP_AHEAD: u32 = 2_000;

/// The chain a rotation replaced is dropped this long after the rotation, even if no newer
/// rotation came. A packet older than this stays unread, and its key is no longer kept in
/// memory or on disk.
pub const OLD_RECV_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// A ratchet step's hybrid (X25519 + ML-KEM) public key, serialized, carried in
/// `MessagePacket.header.ratchet_pubkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetPublicKeys {
    #[serde(with = "serde_bytes")]
    pub x25519_pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kyber_pubkey: Vec<u8>,
}

/// The receive chain a rotation replaced. The peer keeps sending on it until it has seen the
/// rotation. Packets from the two chains can arrive in any order, so the old chain stays usable
/// (`decrypt` tries it second) until the next rotation replaces it, or until the peer's first packet
/// on the new chain says how long the old one was (`close_old_recv`).
#[derive(Clone, Serialize, Deserialize)]
pub struct OldRecvChain {
    #[serde(with = "serde_bytes")]
    ck: Vec<u8>,
    next: u32,
    #[serde(with = "key_map")]
    skipped: HashMap<u32, [u8; 32]>,
}

/// The keys as CBOR byte strings (33 bytes each), not as arrays of 32 integers (up to 64 bytes each): the state with up
/// to 1000 old-chain keys is rewritten after every packet. `ByteBuf` reads either form.
mod key_map {
    use super::*;
    use serde::ser::SerializeMap;

    pub fn serialize<S: serde::Serializer>(keys: &HashMap<u32, [u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(keys.len()))?;
        for (number, key) in keys {
            map.serialize_entry(number, serde_bytes::Bytes::new(key))?;
        }
        map.end()
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<HashMap<u32, [u8; 32]>, D::Error> {
        let raw: HashMap<u32, serde_bytes::ByteBuf> = Deserialize::deserialize(d)?;
        let mut keys = HashMap::with_capacity(raw.len());
        for (number, buf) in raw {
            let mut bytes = buf.into_vec();
            let key = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| <D::Error as serde::de::Error>::custom("skipped key must be 32 bytes"));
            bytes.zeroize();
            keys.insert(number, key?);
        }
        Ok(keys)
    }
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

    /// Parses a peer's header field. Bounds the size and nesting, and checks both keys for their
    /// exact length.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RatchetError> {
        // 32 bytes X25519 + 1568 bytes ML-KEM-1024 key, plus a few bytes of CBOR framing.
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

/// Full state of one device-pair ratchet session. Each device of identity A keeps a separate
/// session with each device of identity B. This struct represents one device-pair session.
#[derive(Clone)]
pub struct DeviceRatchetState {
    pub root_key: Vec<u8>,
    /// The `root_key` as it was before `perform_dh_ratchet` overwrote it. Set by `apply_rotation`
    /// too. Both sides keep it for one generation so that they can keep listening on the previous topic.
    /// The sending side uses it in `perform_dh_ratchet`: the message that announces a rotation
    /// (`rotation_kyber_ciphertext` set) must go out on the OLD shared topic. The peer does not know the
    /// new root key, and so the new topic, until it has received this message. Sending on the new topic
    /// would mean the peer never hears it. `try_publish_raw` in network/publish.rs picks the topic from this.
    ///
    /// Holds the `root_handle` of the previous root, never the root itself. With the root, the unchanged
    /// ratchet secrets and the clear-text announcement would re-derive the whole current epoch from
    /// stored state.
    pub prev_root_key: Option<Vec<u8>>,
    pub ck_send: Vec<u8>,
    pub ck_recv: Vec<u8>,
    /// This side's current DH/KEM ratchet key pair. The source of the next public key sent to the peer
    /// at the next rotation.
    pub own_x25519_secret: StaticSecret,
    pub own_kyber_secret: MlKem1024DecapsulationKey,
    /// The latest ratchet public key received from the peer. A rotation is performed against these.
    pub peer_x25519_pubkey: X25519PublicKey,
    pub peer_kyber_pubkey: MlKem1024EncapsulationKey,
    /// Message counter for this direction (`message_number`).
    pub send_message_number: u32,
    /// Message counter for the receive direction. Used to detect replays and out-of-order packets.
    pub recv_message_number: u32,
    /// Length of the chain before the last DH/KEM ratchet step (`prev_chain_length`).
    pub prev_chain_length: u32,
    pub last_rotation: u64,
    /// Signal's DH-ratchet model (see the note at the end of the file): only a side that has NOT yet
    /// answered the peer's current public key triggers a rotation. There is no deterministic
    /// "who triggers" rule (such as comparing fingerprints). This flag records whether this side has
    /// already performed a DH/KEM step against the peer's latest known public key:
    /// - `true`: this side already generated a new key pair against the peer's current key
    ///   (`perform_dh_ratchet` ran, or the session was just created). This side does NOT trigger a
    ///   rotation. The next rotation right belongs to the peer, which must answer this side's new key.
    /// - `false`: the peer rotated after this side (`apply_rotation` ran) and this side has not yet
    ///   answered its new key. When 30 minutes pass, this side triggers (`perform_dh_ratchet`).
    pub has_responded_to_peer_key: bool,
    /// Ciphertext of the last rotation announcement (Kyber ciphertext from `perform_dh_ratchet`). It is
    /// kept until the peer is seen to have applied the rotation. `send.rs` re-attaches the announcement
    /// to EVERY outgoing packet while this is set, because the packet that triggered the rotation may
    /// not be delivered reliably (TypingIndicator, Ack). Cleared when a packet on the new chain decrypts
    /// (proof the peer applied it). Repeated announcements are idempotent on the receiving side (see
    /// the double-application guard in `derive_rotation`).
    pub pending_rotation_ct: Option<Vec<u8>>,
    /// Cache of skipped message keys, for out-of-order and late packets. This is the standard Signal
    /// Double Ratchet mechanism. If a packet arrives with a `message_number` higher than expected, the
    /// keys of the messages in between are stored here, so those messages can still be decrypted when
    /// they arrive late or out of order. Key = message number. Bounded by `MAX_SKIPPED_KEYS` (memory
    /// and DoS limit, so a malicious sender cannot exhaust memory with a huge `message_number`). Persisted
    /// to disk encrypted (see `persist_skipped_key` and `load_skipped_keys_from_db` in archive.rs), so
    /// late messages still decrypt after a process restart.
    pub skipped_keys: HashMap<u32, [u8; 32]>,
    /// See `OldRecvChain`.
    pub old_recv: Option<OldRecvChain>,
    /// Fixed for the life of the session: derived from the first (hybrid X25519 + ML-KEM) root key at
    /// `initiate`/`respond`, never changed by a rotation. The server mailbox secret is made from it
    /// (`server_seal::session_mailbox_secret`), so the mailbox stays put across rotations and is
    /// still post-quantum: a quantum attacker who knows both devices' public keys cannot derive it.
    pub mailbox_seed: Vec<u8>,
}

/// Symmetric secrets (`root_key`, `ck_send`, `ck_recv`) and skipped message keys (`skipped_keys`) are
/// held as plain `Vec<u8>`. Those bytes are wiped on drop. The secret key types (`own_x25519_secret`,
/// `own_kyber_secret`) are wiped by their own crates' `ZeroizeOnDrop`. The byte buffers are
/// zeroed explicitly in `Drop`, so the bytes do not survive a rotation or the removal of a contact
/// or device (`self.ratchets.remove`).
impl Drop for DeviceRatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.prev_root_key.zeroize();
        self.ck_send.zeroize();
        self.ck_recv.zeroize();
        self.mailbox_seed.zeroize();
        for key in self.skipped_keys.values_mut() {
            key.zeroize();
        }
    }
}

/// Serializable form of `DeviceRatchetState` for encrypted storage. Secret key types (`StaticSecret`,
/// `MlKem1024DecapsulationKey`, ...) do not implement `Serialize`, so each is converted to raw bytes
/// (the same way `SecretKeyBundle` in types.rs stores the device keys; see `generate_identity` and
/// `load_secret_bundle`). `skipped_keys` is deliberately NOT here. It has its own table
/// (`skipped_message_keys`) and is persisted separately (see `persist_skipped_key` and
/// `load_skipped_keys_from_db` in archive.rs). Carrying it twice would risk the two copies drifting apart.
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableRatchetState {
    #[serde(with = "serde_bytes")]
    pub root_key: Vec<u8>,
    /// See `DeviceRatchetState.prev_root_key`. It keeps retries of an announced rotation on the right
    /// topic after a restart, until the peer has received the rotation.
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
    /// See `DeviceRatchetState.pending_rotation_ct`. `#[serde(default)]`: state written before this field
    /// existed has no such key, and it loads as `None`.
    #[serde(default, with = "serde_bytes")]
    pub pending_rotation_ct: Option<Vec<u8>>,
    #[serde(default)]
    pub old_recv: Option<OldRecvChain>,
    /// See `DeviceRatchetState.mailbox_seed`. No default: a state without it cannot find its mailbox,
    /// so it is dropped at load and the session is made again (protocol break).
    #[serde(with = "serde_bytes")]
    pub mailbox_seed: Vec<u8>,
}

impl Drop for SerializableRatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.prev_root_key.zeroize();
        self.ck_send.zeroize();
        self.ck_recv.zeroize();
        self.mailbox_seed.zeroize();
        self.own_x25519_secret.zeroize();
        self.own_kyber_secret.zeroize();
    }
}

impl DeviceRatchetState {
    /// See `SerializableRatchetState`. `skipped_keys` is left out. The caller (persist.rs) loads it
    /// separately and assigns it to the returned value (see `from_persistable`).
    pub fn to_persistable(&self) -> SerializableRatchetState {
        SerializableRatchetState {
            root_key: self.root_key.clone(),
            prev_root_key: self.prev_root_key.clone(),
            ck_send: self.ck_send.clone(),
            ck_recv: self.ck_recv.clone(),
            own_x25519_secret: self.own_x25519_secret.to_bytes(),
            own_kyber_secret: mlkem_dk_to_bytes(&self.own_kyber_secret),
            peer_x25519_pubkey: *self.peer_x25519_pubkey.as_bytes(),
            peer_kyber_pubkey: mlkem_ek_to_bytes(&self.peer_kyber_pubkey),
            send_message_number: self.send_message_number,
            recv_message_number: self.recv_message_number,
            prev_chain_length: self.prev_chain_length,
            last_rotation: self.last_rotation,
            has_responded_to_peer_key: self.has_responded_to_peer_key,
            pending_rotation_ct: self.pending_rotation_ct.clone(),
            old_recv: self.old_recv.clone(),
            mailbox_seed: self.mailbox_seed.clone(),
        }
    }

    /// `skipped_keys`: must be loaded separately from the `skipped_message_keys` table on disk and
    /// passed in here (see `load_skipped_keys_from_db` in archive.rs). This function does not touch
    /// that table itself. ratchet.rs stays a crypto-only layer.
    pub fn from_persistable(mut s: SerializableRatchetState, skipped_keys: HashMap<u32, [u8; 32]>) -> Result<Self, RatchetError> {
        let own_kyber_secret = mlkem_dk_from_bytes(&s.own_kyber_secret)?;
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
            mailbox_seed: std::mem::take(&mut s.mailbox_seed),
        })
    }
}

/// Reports changes to the skipped-key cache made during `DeviceRatchetState::decrypt`. The caller
/// (persist.rs) uses this to keep the encrypted copy on disk up to date.
#[derive(Default)]
pub struct SkippedKeyChanges {
    /// Newly added skipped keys: (message_number, key).
    pub added: Vec<(u32, [u8; 32])>,
    /// Message numbers whose keys were used, or evicted to make room, and must be deleted from the
    /// cache and from disk.
    pub used: Vec<u32>,
    /// The packet's rotation was applied: root key, both chains and the peer keys changed, and the
    /// skipped keys on disk belong to the old chain.
    pub rotated: bool,
    /// The packet was on the chain before the last rotation (`OldRecvChain`). It does not prove the
    /// peer applied our rotation. `added` and `used` are empty: that chain's skipped keys live inside
    /// the ratchet state.
    pub old_chain: bool,
}

impl Drop for SkippedKeyChanges {
    fn drop(&mut self) {
        self.added.iter_mut().for_each(|(_, key)| key.zeroize());
    }
}

/// A rotation computed by `derive_rotation` but not yet applied: (root, send chain, receive chain) and the peer's
/// new public keys. The chain keys are wiped on drop.
struct RotationKeys {
    keys: (Vec<u8>, Vec<u8>, Vec<u8>),
    peer_x25519: X25519PublicKey,
    peer_kyber: MlKem1024EncapsulationKey,
}

impl Drop for RotationKeys {
    fn drop(&mut self) {
        self.keys.0.zeroize();
        self.keys.1.zeroize();
        self.keys.2.zeroize();
    }
}

fn set_secret(slot: &mut Vec<u8>, new: Vec<u8>) {
    slot.zeroize();
    *slot = new;
}

/// What a key derivation is bound to: both sides' ratchet public keys and the KEM ciphertext, with the
/// initiator (of the handshake or of the rotation) first. Every part has a fixed length, so plain
/// concatenation is unambiguous.
fn transcript(init_x25519: &[u8; 32], init_kyber: &[u8], kyber_ct: &[u8], resp_x25519: &[u8; 32], resp_kyber: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [&init_x25519[..], init_kyber, kyber_ct, &resp_x25519[..], resp_kyber] {
        h.update(part);
    }
    h.finalize().into()
}

/// Ratchet failures as values, so callers branch on the kind, not on the message text.
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

/// Lets `?` convert these into the many `Result<_, String>` callers.
impl From<RatchetError> for String {
    fn from(e: RatchetError) -> Self {
        e.to_string()
    }
}

/// X25519 with a small-order public key gives the same output for every secret. The classical half of
/// the hybrid would silently become a constant.
fn x25519(secret: &StaticSecret, public: &X25519PublicKey) -> Result<x25519_dalek::SharedSecret, RatchetError> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(RatchetError::Invalid("Bad peer X25519 key (small order)"));
    }
    Ok(shared)
}

/// Derives the root, send and receive keys with HKDF. `we_initiated` makes the direction symmetric: the
/// initiator's send key equals the responder's receive key. `transcript` is part of every label (v0.2).
/// The keys depend on who exchanged what, not only on the shared secrets.
fn derive_keys(mut ikm: Vec<u8>, transcript: &[u8; 32], we_initiated: bool) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), RatchetError> {
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    ikm.zeroize();
    let mut keys = [[0u8; 32]; 3];
    let labels: [&[u8]; 3] = [b"p2pmsg-v0.2-root", b"p2pmsg-v0.2-a-to-b", b"p2pmsg-v0.2-b-to-a"];
    for (label, key) in labels.into_iter().zip(keys.iter_mut()) {
        hk.expand_multi_info(&[label, transcript], key).map_err(|_| "HKDF expand failed")?;
    }
    // Built from slices: `keys.map` would copy each key by value into a temporary that nothing wiped.
    let (root_key, key_a, key_b) = (keys[0].to_vec(), keys[1].to_vec(), keys[2].to_vec());
    keys.zeroize();
    Ok(if we_initiated { (root_key, key_a, key_b) } else { (root_key, key_b, key_a) })
}

/// Header of `kem_key_to`: X25519 public key (32 bytes) + ML-KEM-1024 ciphertext.
pub const KEM_HEADER_LEN: usize = 32 + 1568;

/// Key of a hybrid KEM to a device's public KEM keys, without a session. This is the sender half of
/// `DeviceRatchetState::initiate`: fresh X25519 secret, ML-KEM encapsulation, both shared secrets and
/// the transcript into HKDF, with no ML-KEM key of the sender. Returns the key and the header the
/// recipient needs: `x25519 public (32) || ML-KEM ciphertext`.
pub fn kem_key_to(peer_x25519_pubkey: &[u8], peer_kyber_pubkey: &[u8]) -> Result<([u8; 32], Vec<u8>), RatchetError> {
    let mut csprng = OsRng;
    let own_x25519_secret = StaticSecret::random_from_rng(&mut csprng);
    let own_x25519_bytes = *X25519PublicKey::from(&own_x25519_secret).as_bytes();
    let peer_x25519_bytes: [u8; 32] = peer_x25519_pubkey.try_into().map_err(|_| "Bad peer X25519 key length")?;
    let dh_shared = x25519(&own_x25519_secret, &X25519PublicKey::from(peer_x25519_bytes))?;
    let peer_kyber_pk = kyber_pubkey_from_bytes(peer_kyber_pubkey)?;
    let (kyber_ct, mut kyber_shared) = peer_kyber_pk.encapsulate();
    let kyber_ct = kyber_ct.to_vec();
    let ikm = [dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
    kyber_shared.as_mut_slice().zeroize();
    let bound_to = transcript(&own_x25519_bytes, &[], &kyber_ct, &peer_x25519_bytes, &peer_kyber_pk.to_bytes());
    Ok((kem_key(ikm, &bound_to)?, [&own_x25519_bytes[..], &kyber_ct].concat()))
}

/// Recipient half of `kem_key_to` (as in `DeviceRatchetState::respond`).
pub fn kem_key_from(own_x25519_secret: &StaticSecret, own_kyber_secret: &MlKem1024DecapsulationKey, header: &[u8]) -> Result<[u8; 32], RatchetError> {
    if header.len() != KEM_HEADER_LEN {
        return Err(RatchetError::Invalid("Bad KEM header length"));
    }
    let (sender_x25519, kyber_ciphertext) = header.split_at(32);
    let sender_x25519_bytes: [u8; 32] = sender_x25519.try_into().map_err(|_| "Bad sender X25519 key length")?;
    let dh_shared = x25519(own_x25519_secret, &X25519PublicKey::from(sender_x25519_bytes))?;
    let ct = kyber_ciphertext_from_bytes(kyber_ciphertext)?;
    let mut kyber_shared = own_kyber_secret.decapsulate(&ct);
    let ikm = [dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
    kyber_shared.as_mut_slice().zeroize();
    let bound_to = transcript(
        &sender_x25519_bytes, &[], kyber_ciphertext,
        X25519PublicKey::from(own_x25519_secret).as_bytes(), &own_kyber_secret.encapsulation_key().to_bytes(),
    );
    kem_key(ikm, &bound_to)
}

/// `derive_keys` for one key, under its own label.
fn kem_key(mut ikm: Vec<u8>, transcript: &[u8; 32]) -> Result<[u8; 32], RatchetError> {
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    ikm.zeroize();
    let mut key = [0u8; 32];
    hk.expand_multi_info(&[b"p2pmsg-v0.5-kem-seal", transcript], &mut key).map_err(|_| "HKDF expand failed")?;
    Ok(key)
}

/// The next chain key only, same value as `chain_step(..).1`.
fn chain_key_step(chain_key: &[u8]) -> Result<[u8; 32], RatchetError> {
    let mut next_chain_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, chain_key)
        .expand(b"p2pmsg-v0.1-chainkey", &mut next_chain_key)
        .map_err(|_| "HKDF expand failed")?;
    Ok(next_chain_key)
}

/// One symmetric ratchet step: the key of this message and the chain key of the next. Send
/// and receive share it, so their two HKDF labels cannot drift apart.
fn chain_step(chain_key: &[u8]) -> Result<([u8; 32], [u8; 32]), RatchetError> {
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut message_key = [0u8; 32];
    let mut next_chain_key = [0u8; 32];
    hk.expand(b"p2pmsg-v0.1-msgkey", &mut message_key).map_err(|_| "HKDF expand failed")?;
    hk.expand(b"p2pmsg-v0.1-chainkey", &mut next_chain_key).map_err(|_| "HKDF expand failed")?;
    Ok((message_key, next_chain_key))
}

impl DeviceRatchetState {
    /// Hybrid, two-way handshake on first contact. `root_key` is HKDF over the classic and PQ
    /// shared secrets, bound to the transcript (see `derive_keys`).
    ///
    /// Initiator: generates a fresh X25519 + ML-KEM pair, then performs DH and encapsulation
    /// against the peer's public keys. The ML-KEM ciphertext must reach the peer in the
    /// `HandshakeInit` packet (see `crate::packet::HandshakeInit`).
    pub fn initiate(
        peer_x25519_pubkey: &[u8],
        peer_kyber_pubkey: &[u8],
        now_ms: u64,
    ) -> Result<(Self, Vec<u8>, Vec<u8>), RatchetError> {
        // X25519 takes its randomness from `OsRng`. ML-KEM draws its own (see the module doc).
        let mut csprng = OsRng;
        let own_x25519_secret = StaticSecret::random_from_rng(&mut csprng);

        let peer_x25519_bytes: [u8; 32] = peer_x25519_pubkey.try_into().map_err(|_| "Bad peer X25519 key length")?;
        let peer_x25519_pk = X25519PublicKey::from(peer_x25519_bytes);
        let dh_shared = x25519(&own_x25519_secret, &peer_x25519_pk)?;

        // Generate a fresh ML-KEM pair for this side.
        let (own_kyber_secret, own_kyber_ek) = mlkem_generate();
        let own_kyber_public_bytes = own_kyber_ek.to_bytes().to_vec();

        let peer_kyber_pk = kyber_pubkey_from_bytes(peer_kyber_pubkey)?;
        let (kyber_ct, mut kyber_shared) = peer_kyber_pk.encapsulate();
        let kyber_ct = kyber_ct.to_vec();

        let ikm = [dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
        kyber_shared.as_mut_slice().zeroize();
        let bound_to = transcript(
            X25519PublicKey::from(&own_x25519_secret).as_bytes(), &own_kyber_public_bytes, &kyber_ct,
            &peer_x25519_bytes, &peer_kyber_pk.to_bytes(),
        );
        let (root_key, ck_send, ck_recv) = derive_keys(ikm, &bound_to, true)?;
        let mailbox_seed = mailbox_seed(&root_key);

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
            // The initiator already did DH and encapsulation against the responder's FIRST public key.
            // That counts as having answered. The next rotation right belongs to the responder.
            has_responded_to_peer_key: true,
            pending_rotation_ct: None,
            skipped_keys: HashMap::new(),
            old_recv: None,
            mailbox_seed,
        };
        Ok((state, kyber_ct, own_kyber_public_bytes))
    }

    /// Responder: derives the same keys from the initiator's public key and ML-KEM ciphertext in the
    /// incoming `HandshakeInit`.
    ///
    /// Nothing here is random. The same `HandshakeInit` always gives the same state, and the long-term
    /// keys are the only secrets in it. So a responder never sends on this chain. `should_rotate` is true
    /// at once (`is_fresh_responder`), and the caller rotates before its first send. A replayed init then
    /// cannot make it reuse a key and nonce. Only what the initiator sent before that rotation depends on
    /// the long-term keys alone. That is the cost of a handshake without a round trip.
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
        let mut kyber_shared = own_kyber_secret.decapsulate(&ct);

        let initiator_kyber_pk = kyber_pubkey_from_bytes(initiator_kyber_pubkey)?;

        let ikm = [dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
        kyber_shared.as_mut_slice().zeroize();
        let bound_to = transcript(
            &initiator_x25519_bytes, &initiator_kyber_pk.to_bytes(), kyber_ciphertext,
            X25519PublicKey::from(&own_x25519_secret).as_bytes(), &own_kyber_secret.encapsulation_key().to_bytes(),
        );
        let (root_key, ck_send, ck_recv) = derive_keys(ikm, &bound_to, false)?;
        let mailbox_seed = mailbox_seed(&root_key);

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
            // The responder has not yet answered the initiator's public key. The right to trigger a
            // rotation is the responder's, and it is used before its first send (see the function note,
            // `is_fresh_responder`).
            has_responded_to_peer_key: false,
            pending_rotation_ct: None,
            skipped_keys: HashMap::new(),
            old_recv: None,
            mailbox_seed,
        })
    }

    /// Returns this side's current ratchet public keys (sent to the peer in
    /// `MessagePacket.header.ratchet_pubkey`).
    pub fn own_ratchet_pubkeys(&self) -> RatchetPublicKeys {
        RatchetPublicKeys {
            x25519_pubkey: X25519PublicKey::from(&self.own_x25519_secret).as_bytes().to_vec(),
            kyber_pubkey: self.own_kyber_secret.encapsulation_key().to_bytes().to_vec(),
        }
    }

        /// DH/KEM ratchet step: generates a new X25519 + ML-KEM pair, performs key exchange against
        /// the peer's latest known public keys, and refreshes the root, send and receive keys.
        /// `prev_chain_length` is set to the previous `send_message_number`, and `send_message_number`
        /// is reset. The peer learns "last message number on the old chain" from `prev_chain_length`.
        ///
        /// Call only when `should_rotate()` is true. That check includes Signal's rule: "have I already
        /// answered the peer's current key" (`has_responded_to_peer_key`). There is no deterministic
        /// "who triggers" rule. Only a side that has not yet answered triggers (see the note at the end
        /// of the file).
        ///
        /// The returned ML-KEM ciphertext must be sent to the peer with the next `MessagePacket`, in its
        /// header `ratchet_pubkey` field (`RatchetPublicKeys` plus this ciphertext). The peer synchronizes
        /// with `derive_rotation` + `apply_rotation` when it receives it.
    pub fn perform_dh_ratchet(&mut self, now_ms: u64) -> Result<Vec<u8>, RatchetError> {
        let mut csprng = OsRng;
        let new_x25519_secret = StaticSecret::random_from_rng(&mut csprng);
        let (new_kyber_secret, new_kyber_ek) = mlkem_generate();

        let dh_shared = x25519(&new_x25519_secret, &self.peer_x25519_pubkey)?;
        let (kyber_ct, mut kyber_shared) = self.peer_kyber_pubkey.encapsulate();
        let kyber_ct = kyber_ct.to_vec();

        let ikm = [self.root_key.as_slice(), dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
        kyber_shared.as_mut_slice().zeroize();
        let bound_to = transcript(
            X25519PublicKey::from(&new_x25519_secret).as_bytes(), &new_kyber_ek.to_bytes(), &kyber_ct,
            self.peer_x25519_pubkey.as_bytes(), &self.peer_kyber_pubkey.to_bytes(),
        );
        // This function always means "this side triggers": we_initiated = true.
        let keys = derive_keys(ikm, &bound_to, true)?;

        self.rotate_chains(keys, now_ms);
        self.own_x25519_secret = new_x25519_secret;
        self.own_kyber_secret = new_kyber_secret;
        // Encapsulated against the peer's previous (pre-rotation) public key. That counts as having answered.
        // The next rotation right is now the peer's.
        self.has_responded_to_peer_key = true;
        // See `pending_rotation_ct`. The announcement is re-attached to every outgoing packet until the peer
        // is seen to have applied the rotation.
        self.pending_rotation_ct = Some(kyber_ct.clone());
        Ok(kyber_ct)
    }

    /// What the session topic and the server seal are derived from: `root_handle(root_key)`, and
    /// `prev_root_key` one generation back.
    pub fn root_handle_now(&self) -> Vec<u8> {
        root_handle(&self.root_key)
    }

    /// The part both sides share in a rotation: new root and chains, counters back to 0. The old root stays
    /// for one generation (`prev_root_key`: the announcement still travels on its topic). The old receive
    /// chain stays too, with its skipped keys (`OldRecvChain`).
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

        /// Receive-side reaction to a rotation. Called when the peer ran `perform_dh_ratchet` and sent us
        /// (a) its new `ratchet_pubkey` (both X25519 and Kyber) and (b) the ciphertext from that rotation
        /// (`MessagePacketHeader.rotation_kyber_ciphertext`). This is the counterpart of the "encapsulate"
        /// side of `perform_dh_ratchet`. We do NOT generate a new key pair, because we did not start the
        /// rotation. We decapsulate the peer's ciphertext with our own (pre-rotation, still valid) Kyber
        /// secret. Both sides then derive the same new root key.
        ///
        /// `new_peer_keys` is the peer's NEW (post-rotation) X25519 + Kyber public key pair. Both parts are
        /// updated here: the X25519 part is used in this decapsulation, and the Kyber part is used by our
        /// future rotations (`perform_dh_ratchet` encapsulates against `self.peer_kyber_pubkey`).
        ///
        /// Returns: `Ok(Some(keys))` = a new rotation, not yet applied. `Ok(None)` = this announcement was ALREADY
        /// applied (guard below).
        ///
        /// Double-application guard: this function mixes the current `root_key` into the KDF. Applying the same
        /// announcement twice would derive a root key the sender never saw, and would break the session for
        /// good. Repeats are unavoidable: the sender's `awaiting_confirmation` mechanism re-sends the SAME
        /// envelope (with the same rotation ciphertext) if an Ack was lost, and `pending_rotation_ct`
        /// deliberately repeats the announcement (see that field). The peer's X25519 public key is freshly
        /// generated at every rotation. So if the incoming key equals the stored `peer_x25519_pubkey`, the
        /// rotation was already applied, and it is safely ignored.
        ///
        /// Nothing here is authenticated by itself. ML-KEM decapsulation never fails (a ciphertext made for
        /// another key gives pseudo-random bytes). The guard above knows only the current peer key. So a
        /// delayed announcement of an older rotation would overwrite the root and chains with garbage. `decrypt`
        /// therefore derives the keys read-only here, tries the packet on the new receive chain, and calls
        /// `apply_rotation` only if it opens. No copy of the whole state is made per announcement.
    fn derive_rotation(&self, new_peer_keys: &RatchetPublicKeys, rotation_kyber_ciphertext: &[u8]) -> Result<Option<RotationKeys>, RatchetError> {
        let x25519_bytes: [u8; 32] = new_peer_keys.x25519_pubkey.as_slice().try_into().map_err(|_| "Bad peer X25519 key length")?;
        if x25519_bytes == *self.peer_x25519_pubkey.as_bytes() {
            return Ok(None);
        }
        let new_peer_x25519_pk = X25519PublicKey::from(x25519_bytes);
        let new_peer_kyber_pk = kyber_pubkey_from_bytes(&new_peer_keys.kyber_pubkey)?;

        // DH: our OWN (pre-rotation, still valid) X25519 secret, against the peer's NEW X25519 public key.
        let dh_shared = x25519(&self.own_x25519_secret, &new_peer_x25519_pk)?;

        // KEM: decapsulate the peer's ciphertext with our OWN (pre-rotation, still valid) Kyber secret. This
        // mirrors the `self.peer_kyber_pubkey.encapsulate(...)` call in `perform_dh_ratchet`. The peer
        // encapsulated against our OLD Kyber public key.
        let ct = kyber_ciphertext_from_bytes(rotation_kyber_ciphertext)?;
        let mut kyber_shared = self.own_kyber_secret.decapsulate(&ct);

        let ikm = [self.root_key.as_slice(), dh_shared.as_bytes().as_slice(), kyber_shared.as_slice()].concat();
        kyber_shared.as_mut_slice().zeroize();
        let bound_to = transcript(
            &x25519_bytes, &new_peer_kyber_pk.to_bytes(), rotation_kyber_ciphertext,
            X25519PublicKey::from(&self.own_x25519_secret).as_bytes(), &self.own_kyber_secret.encapsulation_key().to_bytes(),
        );
        // We did not start this rotation, the peer did: we_initiated = false.
        let keys = derive_keys(ikm, &bound_to, false)?;
        Ok(Some(RotationKeys { keys, peer_x25519: new_peer_x25519_pk, peer_kyber: new_peer_kyber_pk }))
    }

    fn apply_rotation(&mut self, mut rotation: RotationKeys, now_ms: u64) {
        let keys = (
            std::mem::take(&mut rotation.keys.0),
            std::mem::take(&mut rotation.keys.1),
            std::mem::take(&mut rotation.keys.2),
        );
        let new_peer_x25519_pk = rotation.peer_x25519;
        let new_peer_kyber_pk = rotation.peer_kyber.clone();
        // `prev_chain_length` is MY previous send-chain length, as in `perform_dh_ratchet`.
        self.rotate_chains(keys, now_ms);
        // If the peer rotated, it already knows our CURRENT public key. A lingering repeated announcement from
        // an older rotation is no longer needed (see `pending_rotation_ct`).
        self.pending_rotation_ct = None;
        // We do NOT change our own `own_x25519_secret` / `own_kyber_secret`. We did not start the rotation, so
        // our key pair stays the same. We regenerate it only when WE start a rotation (`perform_dh_ratchet`).
        // The peer's public keys are updated in both parts (see the function documentation; the Kyber part is
        // needed for future rotations).
        self.peer_x25519_pubkey = new_peer_x25519_pk;
        self.peer_kyber_pubkey = new_peer_kyber_pk;
        // The peer generated a new public key, and this side has not yet done a DH/KEM step against it. The
        // next rotation right is ours: we call `perform_dh_ratchet` when 30 minutes have passed.
        self.has_responded_to_peer_key = false;
    }

        /// The 30-minute rule, following Signal's model. ONLY a side that has not yet answered the peer's
        /// current public key (`has_responded_to_peer_key == false`) may trigger a rotation. If this side has
        /// already answered (the next rotation right is the peer's), it does not trigger even after 30 minutes.
        /// It waits for the peer's own message or rotation. This is Signal's asymmetric "whose turn it is"
        /// model, not a deterministic rule such as comparing fingerprints.
        ///
        /// A responder that has not rotated yet does so before its first send, whatever the clock says (see `respond`).
    pub fn should_rotate(&self, now_ms: u64) -> bool {
        // `abs_diff`, not a subtraction: `last_rotation` may be ahead of the clock (the clock went back, or a
        // persisted state came from a device with a fast clock). A plain subtraction would wrap in release
        // builds (a spurious rotation) and panic in debug. A clock set back by more than one period also
        // rotates, instead of stalling until it passes `last_rotation` again.
        !self.has_responded_to_peer_key
            && (self.is_fresh_responder() || now_ms.abs_diff(self.last_rotation) > RATCHET_ROTATION_MS)
    }

    /// Still on the chains `respond` derived: no rotation in either direction.
    pub fn is_fresh_responder(&self) -> bool {
        !self.has_responded_to_peer_key && self.prev_root_key.is_none()
    }

    /// Nothing from the peer has decrypted in this session yet, so it may never have processed our handshake. A
    /// rotation resets `recv_message_number`, so the chain before it counts too. (A state stored before `old_recv`
    /// existed has none. There, any rotation counts as "heard".)
    pub fn never_heard(&self) -> bool {
        self.recv_message_number == 0
            && match &self.old_recv {
                Some(old) => old.next == 0,
                None => self.prev_root_key.is_none(),
            }
    }

        /// Encrypts the next outgoing message (produces the `MessagePacket` fields). The nonce is derived
        /// deterministically from `message_number`. Under one chain key, two message numbers never produce the
        /// same nonce, which is enough for AEAD security.
        ///
        /// `aad` is the packet's raw header bytes. The tag binds them, so the header the receiver acts on is the
        /// one the sender encrypted under. `next_send_numbers` gives the numbers to put in that header first.
    pub fn encrypt_next(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, u32, u32), RatchetError> {
        // The responder's handshake chain is a function of `HandshakeInit` alone (see `respond`). It is never sent on.
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
        // See the `Drop` note on `DeviceRatchetState`. This key belongs to one message. It is wiped right after use
        // (overwritten), and the function does not wait for the return.
        message_key.zeroize();

        Ok((ciphertext, message_number, self.prev_chain_length))
    }

    /// Call after a packet opened on the current receive chain (not `SkippedKeyChanges::old_chain`), with its header's
    /// `prev_chain_length`: the peer sent exactly that many packets on the chain the last rotation replaced, and sends
    /// no more there. Keys up to that length are derived (bounded like `chain_decrypt`) and the old chain key is
    /// dropped, so a later leak of the state cannot derive any other key of that chain. Idempotent.
    pub fn close_old_recv(&mut self, prev_chain_length: u32) {
        let Some(old) = &mut self.old_recv else { return };
        if old.ck.is_empty() {
            return;
        }
        let end = prev_chain_length.min(old.next.saturating_add(MAX_SKIP_AHEAD));
        let mut cursor = old.ck.clone();
        let mut ok = true;
        for number in old.next..end {
            if end - number > MAX_SKIPPED_KEYS as u32 {
                match chain_key_step(&cursor) {
                    Ok(mut next_chain_key) => {
                        set_secret(&mut cursor, next_chain_key.to_vec());
                        next_chain_key.zeroize();
                    }
                    Err(_) => { ok = false; break; }
                }
                continue;
            }
            match chain_step(&cursor) {
                Ok((key, mut next_chain_key)) => {
                    old.skipped.insert(number, key);
                    set_secret(&mut cursor, next_chain_key.to_vec());
                    next_chain_key.zeroize();
                }
                Err(_) => { ok = false; break; }
            }
        }
        cursor.zeroize();
        if !ok {
            return;
        }
        let excess = old.skipped.len().saturating_sub(MAX_SKIPPED_KEYS);
        if excess > 0 {
            let mut numbers: Vec<u32> = old.skipped.keys().copied().collect();
            numbers.sort_unstable();
            for oldest in numbers.into_iter().take(excess) {
                if let Some(mut key) = old.skipped.remove(&oldest) {
                    key.zeroize();
                }
            }
        }
        // Closed: only the stored keys open packets now. Every other number reads as spent (`KeyNotFound`).
        old.ck.zeroize();
        old.ck = Vec::new();
        old.next = u32::MAX;
        if old.skipped.is_empty() {
            self.old_recv = None;
        }
    }

    /// Drops the chain the last rotation replaced once it is `OLD_RECV_MAX_AGE_MS` old. Called on receive, on send
    /// and on load, so a session that stops receiving does not keep the old keys forever.
    pub fn expire_old_recv(&mut self, now_ms: u64) {
        if self.old_recv.is_some() && now_ms.abs_diff(self.last_rotation) > OLD_RECV_MAX_AGE_MS {
            self.old_recv = None;
        }
    }

    /// `(message_number, prev_chain_length)` that the next `encrypt_next` uses.
    pub fn next_send_numbers(&self) -> (u32, u32) {
        (self.send_message_number, self.prev_chain_length)
    }

    /// Decrypts an incoming message. `message_number` comes from the packet header. `rotation` is the header's
    /// `(ratchet_pubkey, rotation_kyber_ciphertext)` when the packet announces a rotation.
    ///
    /// Three attempts. State changes only for the attempt whose AEAD tag verifies (see `chain_decrypt`):
    /// 1. A rotation not yet applied: applied only if the packet decrypts on the new chain
    ///    (`SkippedKeyChanges::rotated`).
    /// 2. The current receive chain.
    /// 3. The chain before the last rotation (`SkippedKeyChanges::old_chain`).
    ///
    /// This function does no disk I/O. The caller (archive.rs) uses the returned `SkippedKeyChanges` to update
    /// the skipped-key table on disk.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        message_number: u32,
        rotation: Option<(&RatchetPublicKeys, &[u8])>,
        now_ms: u64,
        aad: &[u8],
    ) -> Result<(Vec<u8>, SkippedKeyChanges), RatchetError> {
        self.expire_old_recv(now_ms);
        // A new peer key was derived and the packet did not open on its chain: the sessions diverged, whatever the current chain says.
        let mut rotation_failed = false;
        if let Some((new_peer_keys, kyber_ct)) = rotation {
            // Checked first: the announcement is repeated on every packet until we answer on the new chain.
            if new_peer_keys.x25519_pubkey != self.peer_x25519_pubkey.as_bytes() {
                // Only the new receive chain is tried; the state is touched only if the packet opens on it.
                if let Ok(Some(rotation)) = self.derive_rotation(new_peer_keys, kyber_ct) {
                    let mut ck_recv = rotation.keys.2.clone();
                    let mut next = 0u32;
                    let mut skipped = HashMap::new();
                    let opened = chain_decrypt(&mut ck_recv, &mut next, &mut skipped, ciphertext, message_number, aad);
                    match opened {
                        Ok((plaintext, mut changes)) => {
                            changes.rotated = true;
                            self.apply_rotation(rotation, now_ms);
                            set_secret(&mut self.ck_recv, ck_recv);
                            self.recv_message_number = next;
                            self.skipped_keys = skipped;
                            return Ok((plaintext, changes));
                        }
                        Err(_) => {
                            rotation_failed = true;
                            ck_recv.zeroize();
                            skipped.values_mut().for_each(|key| key.zeroize());
                        }
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
                // A consumed packet of the old chain: a duplicate, not a diverged session. The current chain's
                // DecryptFailed counts it toward a fresh handshake (see `note_undecryptable`).
                // Not when the packet announced a rotation we could not follow: that is a diverged session.
                Err(RatchetError::KeyNotFound(n)) if message_number < old_next && !rotation_failed => return Err(RatchetError::KeyNotFound(n)),
                Err(_) => {}
            }
        }
        // The error of the current chain. The caller tells a duplicate (`RatchetError::KeyNotFound`) from a
        // diverged session by it.
        if rotation_failed && matches!(current_err, RatchetError::KeyNotFound(_)) {
            return Err(RatchetError::DecryptFailed);
        }
        Err(current_err)
    }
}

/// Decrypts on one receive chain (`chain_key`, the expected `next` number, and its `skipped` keys). The standard
/// Signal Double Ratchet mechanism:
///
/// - `message_number >= next`: the chain is advanced to that message. The keys of the messages in between are
///   stored in `skipped` (at most `MAX_SKIP_AHEAD` steps). The cache keeps the newest `MAX_SKIPPED_KEYS` keys and
///   evicts older ones.
/// - `message_number < next`: a late message. Its key is taken from `skipped` and removed. If it is not there,
///   this is an error.
///
/// Candidate keys are computed locally and written back only after the AEAD tag verifies. A signed packet with a
/// made-up `message_number` and garbage ciphertext must not move the chain.
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
            if message_number - number > MAX_SKIPPED_KEYS as u32 {
                // This key would be evicted at once: advance the chain without deriving it (one HMAC less
                // per step of unauthenticated work).
                let mut next_chain_key = chain_key_step(&cursor)?;
                set_secret(&mut cursor, next_chain_key.to_vec());
                next_chain_key.zeroize();
                continue;
            }
            let (mut skipped_key, mut next_chain_key) = chain_step(&cursor)?;
            changes.added.push((number, skipped_key));
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
            // One sort, not a scan of the whole map for every evicted key.
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

/// Derives a deterministic 12-byte nonce from the message number (for ChaCha20-Poly1305). Under one chain
/// key, every message_number is unique (symmetric ratchet progression), so nonces never collide.
fn nonce_from_message_number(n: u32) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[8..12].copy_from_slice(&n.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

/// Parses a raw ML-KEM-1024 encapsulation key (public key). The length is checked by
/// `ml_kem::Key::try_from`, and `EncapsulationKey::new` rejects what the library refuses.
pub fn kyber_pubkey_from_bytes(bytes: &[u8]) -> Result<MlKem1024EncapsulationKey, RatchetError> {
    let encoded = ml_kem::Key::<MlKem1024EncapsulationKey>::try_from(bytes)
        .map_err(|_| RatchetError::Invalid("Bad Kyber public key length"))?;
    MlKem1024EncapsulationKey::new(&encoded).map_err(|_| RatchetError::Invalid("Bad Kyber public key"))
}

/// Parses a raw byte slice into an ML-KEM-1024 ciphertext.
fn kyber_ciphertext_from_bytes(bytes: &[u8]) -> Result<MlKemCiphertext, RatchetError> {
    bytes.try_into().map_err(|_| RatchetError::Invalid("Bad Kyber ciphertext length"))
}

// NOTE: out-of-order messages use the skipped-message-key cache (`skipped_keys`, see `chain_decrypt`). On a
// rotation, the cache moves with the old receive chain into `old_recv`, and stays usable for one more
// generation. The current chain's cache lives in its own table. The rest of the state, including the old chain,
// is written to disk as `SerializableRatchetState`. Both are encrypted in archive.rs and persist.rs
// (`persist_skipped_key`, `persist_ratchet_state`).
//
// NOTE [SIGNAL MODEL]: the `perform_dh_ratchet` / `apply_rotation` pair implements Signal's real asymmetric
// model. There is no deterministic "the smaller fingerprint triggers" rule. Instead each `DeviceRatchetState`
// carries `has_responded_to_peer_key` to record who holds the right to trigger the next rotation:
// - In the first handshake, initiator = true (it already answered the responder), responder = false (it has not
//   yet answered the initiator).
// - The side that calls `perform_dh_ratchet` sets it to true (it answered the peer's key, and the turn is now the peer's).
// - The side that calls `apply_rotation` sets it to false (the peer generated a new key, this side has not
//   answered it yet, and the turn is ours).
// `should_rotate()` = `!has_responded_to_peer_key && 30 minutes have passed`. This is the direct counterpart of
// Signal's "whoever's turn it is triggers" model. Both sides cannot trigger at once, because at any moment only one
// side's flag is `false`.

/// One-way handle of a root key. The session topic and the server seal key are derived from it, so the previous
/// generation can be kept for those without keeping its root.
pub fn root_handle(root_key: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = vec![0u8; 32];
    hk.expand(b"typeon-root-handle-v1", &mut out).expect("32 bytes is a valid HKDF length");
    out
}

/// `DeviceRatchetState.mailbox_seed` of a session whose first root key is `root_key`. One-way, so the
/// stored seed does not give back the root.
fn mailbox_seed(root_key: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = vec![0u8; 32];
    hk.expand(b"typeon-session-mailbox-seed-v1", &mut out).expect("32 bytes is a valid HKDF length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_000_000;

    #[test]
    fn chain_key_step_matches_chain_step() {
        let ck = [7u8; 32];
        assert_eq!(chain_key_step(&ck).unwrap(), chain_step(&ck).unwrap().1);
    }

    /// A handshake as the core performs it: the responder's long-term KEM keys, and the initiator's fresh ones
    /// (`state.own_x25519_secret`, not its identity key).
    /// Returns (initiator, responder).
    fn session() -> (DeviceRatchetState, DeviceRatchetState) {
        let (init, x_secret, kyber_secret) = handshake_init();
        let responder = respond_to(&init, x_secret, kyber_secret);
        (init.0, responder)
    }

    #[test]
    fn kem_key_needs_the_recipient_secrets() {
        let x_secret = StaticSecret::random_from_rng(&mut OsRng);
        let (kyber_secret, kyber_ek) = mlkem_generate();
        let (key, header) = kem_key_to(X25519PublicKey::from(&x_secret).as_bytes(), &kyber_ek.to_bytes()).unwrap();
        assert_eq!(header.len(), KEM_HEADER_LEN);
        assert_eq!(kem_key_from(&x_secret, &kyber_secret, &header).unwrap(), key);
        let other_x = StaticSecret::random_from_rng(&mut OsRng);
        assert_ne!(kem_key_from(&other_x, &kyber_secret, &header).unwrap(), key);
        let (other_kyber, _) = mlkem_generate();
        assert_ne!(kem_key_from(&x_secret, &other_kyber, &header).unwrap(), key);
    }

    type Init = (DeviceRatchetState, Vec<u8>, Vec<u8>);

    #[test]
    fn mlkem_keys_round_trip_as_seed_and_as_old_expanded_form() {
        let (dk, ek) = mlkem_generate();
        let seed = mlkem_dk_to_bytes(&dk);
        assert_eq!(seed.len(), 64);
        assert_eq!(mlkem_ek_to_bytes(mlkem_dk_from_bytes(&seed).unwrap().encapsulation_key()), mlkem_ek_to_bytes(&ek));
        // A key written by ml-kem 0.2 (expanded, 3168 bytes) still loads, decapsulates, and is written back the same way.
        #[allow(deprecated)]
        let expanded = ml_kem::ExpandedKeyEncoding::to_expanded_bytes(&dk).to_vec();
        assert_eq!(expanded.len(), 3168);
        let old = mlkem_dk_from_bytes(&expanded).unwrap();
        let (ct, shared) = ek.encapsulate();
        assert_eq!(old.decapsulate(&ct), shared);
        assert_eq!(mlkem_dk_to_bytes(&old), expanded);
        assert!(mlkem_dk_from_bytes(&[0u8; 100]).is_err());
        assert_eq!(kyber_pubkey_from_bytes(&mlkem_ek_to_bytes(&ek)).unwrap(), ek);
    }

    fn handshake_init() -> (Init, StaticSecret, MlKem1024DecapsulationKey) {
        let x_secret = StaticSecret::random_from_rng(&mut OsRng);
        let (kyber_secret, kyber_ek) = mlkem_generate();
        let init = DeviceRatchetState::initiate(X25519PublicKey::from(&x_secret).as_bytes(), &kyber_ek.to_bytes(), T0)
            .expect("initiate should succeed");
        (init, x_secret, kyber_secret)
    }

    fn respond_to((initiator, kyber_ct, initiator_kyber_pub): &Init, x_secret: StaticSecret, kyber_secret: MlKem1024DecapsulationKey) -> DeviceRatchetState {
        DeviceRatchetState::respond(
            x_secret, kyber_secret,
            X25519PublicKey::from(&initiator.own_x25519_secret).as_bytes(), initiator_kyber_pub, kyber_ct, T0,
        ).expect("respond should succeed")
    }

    /// `from` rotates and sends `text` with the announcement: (keys, Kyber ciphertext, message ciphertext, message number).
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

    /// The header is the AEAD's associated data. Another header fails the tag and leaves the chain where it was.
    #[test]
    fn changed_header_does_not_decrypt() {
        let (mut initiator, mut responder) = session();
        assert_eq!(initiator.next_send_numbers(), (0, 0));
        let (ciphertext, number, _) = initiator.encrypt_next(b"m", b"header").unwrap();
        assert!(responder.decrypt(&ciphertext, number, None, T0, b"header2").is_err());
        assert_eq!(responder.decrypt(&ciphertext, number, None, T0, b"header").unwrap().0, b"m");
    }

    /// Packets of the chain that a rotation replaced still decrypt, on the side that rotated and on the side that
    /// followed, in any order.
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
        assert!(matches!(b.decrypt(&late_a0, n_a0, None, T0, b""), Err(RatchetError::KeyNotFound(_))), "a replay must not decrypt twice, and reads as a duplicate");

        // The repeated announcement is a no-op, and the new chains work in both directions.
        let (ciphertext, number, _) = b.encrypt_next(b"b2", b"").unwrap();
        let (plain, changes) = a.decrypt(&ciphertext, number, Some((&keys, &kyber_ct)), T0, b"").unwrap();
        assert_eq!(plain, b"b2");
        assert!(!changes.rotated);
        let (ciphertext, number, _) = a.encrypt_next(b"a2", b"").unwrap();
        let (plain, changes) = b.decrypt(&ciphertext, number, None, T0, b"").unwrap();
        assert_eq!(plain, b"a2");
        assert!(!changes.old_chain);
    }

    /// After a rotation, both sides keep only the handle of the old root, and the two handles match (topic and
    /// server seal agree).
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

    /// An announcement that does not belong to this state (here, a rotation made for another session) leaves
    /// it untouched.
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

    /// A long run of undelivered packets does not kill the receive direction. The cache keeps the newest keys.
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
        assert!(matches!(b.decrypt(&sent[400].0, 400, None, T0, b""), Err(RatchetError::KeyNotFound(400))), "evicted");
        assert_eq!(b.decrypt(&sent[401].0, 401, None, T0, b"").unwrap().0, b"m");

        // A jump past the work limit is refused before any key is derived, and changes nothing. The limit itself is what
        // refuses it (a garbage tag alone would also fail, with DecryptFailed).
        assert!(matches!(
            b.decrypt(b"garbage", 1403 + MAX_SKIP_AHEAD + 1, None, T0, b""),
            Err(RatchetError::TooManySkipped { gap, limit: MAX_SKIP_AHEAD }) if gap == MAX_SKIP_AHEAD + 1
        ));
        assert!(matches!(b.decrypt(b"garbage", 1403 + MAX_SKIP_AHEAD, None, T0, b""), Err(RatchetError::DecryptFailed)));
        assert_eq!(b.recv_message_number, 1403);
    }

    /// A replayed HandshakeInit gives the responder the same state again, so it must rotate before it sends. After
    /// that, the two replays share no send key.
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

    /// A small-order X25519 key is refused, and the derived keys depend on the transcript, not only on the shared
    /// secrets.
    #[test]
    fn key_derivation_checks_and_binds_its_inputs() {
        let (_, kyber_ek) = mlkem_generate();
        assert!(DeviceRatchetState::initiate(&[0u8; 32], &kyber_ek.to_bytes(), T0).is_err());

        let ikm = vec![7u8; 64];
        let a = derive_keys(ikm.clone(), &[1u8; 32], true).unwrap();
        assert_ne!(a, derive_keys(ikm.clone(), &[2u8; 32], true).unwrap());
        let b = derive_keys(ikm, &[1u8; 32], false).unwrap();
        assert_eq!((&a.0, &a.1, &a.2), (&b.0, &b.2, &b.1));
    }

    /// Both ends get the same mailbox seed, a rotation keeps it, and it survives a restart. A state stored
    /// without it (older version) is refused, so the session is made again.
    #[test]
    fn mailbox_seed_is_shared_stable_and_required() {
        #[derive(Serialize)]
        struct OldFormat {
            #[serde(with = "serde_bytes")]
            root_key: Vec<u8>,
            #[serde(with = "serde_bytes")]
            prev_root_key: Option<Vec<u8>>,
            #[serde(with = "serde_bytes")]
            ck_send: Vec<u8>,
            #[serde(with = "serde_bytes")]
            ck_recv: Vec<u8>,
            own_x25519_secret: [u8; 32],
            #[serde(with = "serde_bytes")]
            own_kyber_secret: Vec<u8>,
            peer_x25519_pubkey: [u8; 32],
            #[serde(with = "serde_bytes")]
            peer_kyber_pubkey: Vec<u8>,
            send_message_number: u32,
            recv_message_number: u32,
            prev_chain_length: u32,
            last_rotation: u64,
            has_responded_to_peer_key: bool,
        }
        let (mut a, mut b) = session();
        assert_eq!(a.mailbox_seed.len(), 32);
        assert_eq!(a.mailbox_seed, b.mailbox_seed, "both ends must find the same mailbox");
        assert_ne!(a.mailbox_seed, a.root_key);
        let seed = a.mailbox_seed.clone();
        let (keys, kyber_ct, ciphertext, number) = rotate_and_send(&mut b, b"x");
        a.decrypt(&ciphertext, number, Some((&keys, &kyber_ct)), T0, b"").unwrap();
        assert_eq!((&a.mailbox_seed, &b.mailbox_seed), (&seed, &seed), "a rotation must not move the mailbox");

        let p = a.to_persistable();
        let mut bytes = Vec::new();
        ciborium::into_writer(&p, &mut bytes).unwrap();
        let loaded: SerializableRatchetState = ciborium::from_reader(bytes.as_slice()).unwrap();
        let mut restored = DeviceRatchetState::from_persistable(loaded, HashMap::new()).unwrap();
        assert_eq!(restored.mailbox_seed, seed);
        assert!(restored.old_recv.is_some());

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
        assert!(ciborium::from_reader::<SerializableRatchetState, _>(old_bytes.as_slice()).is_err());

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
        assert!(matches!(a.encrypt_next(b"x", b""), Err(RatchetError::ChainExhausted)));
        b.recv_message_number = u32::MAX;
        assert!(matches!(b.decrypt(b"x", u32::MAX, None, T0, b""), Err(RatchetError::ChainExhausted)));
    }

    /// The first packet on the new chain closes the old one at the peer's `prev_chain_length`: the missing
    /// packets of the old chain still open, the old chain key is gone.
    #[test]
    fn old_chain_is_closed_at_prev_chain_length() {
        let (mut b, mut a) = session();
        let (keys0, ct0, hello, n_hello) = rotate_and_send(&mut a, b"hello");
        b.decrypt(&hello, n_hello, Some((&keys0, &ct0)), T0, b"").unwrap();
        let (late_a0, n_a0, _) = a.encrypt_next(b"a0", b"").unwrap();
        let (late_a1, n_a1, _) = a.encrypt_next(b"a1", b"").unwrap();
        let (keys, kyber_ct, rotated, n_rot) = rotate_and_send(&mut b, b"b1");
        a.decrypt(&rotated, n_rot, Some((&keys, &kyber_ct)), T0, b"").unwrap();
        let (a2, n_a2, prev) = a.encrypt_next(b"a2", b"").unwrap();
        assert_eq!(prev, 3, "hello, a0 and a1 were sent on the old chain");
        let (plain, changes) = b.decrypt(&a2, n_a2, None, T0, b"").unwrap();
        assert_eq!(plain, b"a2");
        assert!(!changes.old_chain);
        b.close_old_recv(prev);
        assert!(b.old_recv.as_ref().unwrap().ck.is_empty());
        b.close_old_recv(prev);
        // The kept keys survive a store and reload (byte-string encoding of `OldRecvChain.skipped`).
        let mut bytes = Vec::new();
        ciborium::into_writer(&b.to_persistable(), &mut bytes).unwrap();
        let loaded: SerializableRatchetState = ciborium::from_reader(bytes.as_slice()).unwrap();
        let mut b = DeviceRatchetState::from_persistable(loaded, HashMap::new()).unwrap();
        assert_eq!(b.old_recv.as_ref().unwrap().skipped.len(), 2);
        assert_eq!(b.decrypt(&late_a1, n_a1, None, T0, b"").unwrap().0, b"a1");
        assert_eq!(b.decrypt(&late_a0, n_a0, None, T0, b"").unwrap().0, b"a0");
        assert!(matches!(b.decrypt(&late_a0, n_a0, None, T0, b""), Err(RatchetError::KeyNotFound(_))));
    }

    /// A packet whose rotation announcement does not open on the derived chain reads as a diverged session
    /// (`DecryptFailed`), even when its number is below our receive counter.
    #[test]
    fn failed_rotation_below_the_counter_is_not_a_duplicate() {
        let (mut a, mut b) = session();
        for _ in 0..5 {
            let (c, n, _) = a.encrypt_next(b"m", b"").unwrap();
            b.decrypt(&c, n, None, T0, b"").unwrap();
        }
        let (_, mut stranger) = session();
        let (keys, kyber_ct, ciphertext, _) = rotate_and_send(&mut stranger, b"x");
        assert!(matches!(b.decrypt(&ciphertext, 1, Some((&keys, &kyber_ct)), T0, b""), Err(RatchetError::DecryptFailed)));
        assert!(matches!(b.decrypt(&ciphertext, 1, None, T0, b""), Err(RatchetError::KeyNotFound(1))));
    }
}
