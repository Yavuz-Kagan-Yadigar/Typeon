//! Identity/Device model — Description.md bölüm 1.
//!
//! İki katmanlı kimlik: Identity (kişi) → 1..N Device (cihaz).
//! `identity_id`, ilk cihazın fingerprint'i olarak sabitlenir ve değişmez.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Bir Identity'ye bağlı en fazla kaç Active cihaz olabilir (spec bölüm 1).
pub const MAX_ACTIVE_DEVICES: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_fingerprint: String, // hex-encoded 32 byte fingerprint
    pub device_name: String,
    pub added_at: u64,
    pub status: DeviceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// İlk cihazın fingerprint'i, DEĞİŞMEZ (spec 1.).
    pub identity_id: String,
    pub devices: Vec<DeviceInfo>,
    /// Cihaz ekleme/çıkarma yetkisine sahip cihaz (spec 1.6 — herhangi bir
    /// Active cihaz aslında bu yetkiye sahip, `primary_device` sadece
    /// gösterim amaçlı ilk kurulan cihazı işaretler).
    pub primary_device: Option<String>,
}

/// Public key lengths of a device: Ed25519, ML-DSA-87, X25519, ML-KEM-1024.
pub const DEVICE_KEY_LENS: [usize; 4] = [32, 2592, 32, 1568];

/// Bir cihazın hibrit imza + KEM public key'lerinden fingerprint türetir.
/// `fingerprint = SHA3-256( sign_ed25519 || sign_mldsa || kem_x25519 || kem_mlkem )`
/// (spec 1.2). Ham fingerprint 32 byte, hex olarak döner; gösterim
/// formatları için `format_fingerprint_base32` / `format_short_code`
/// kullanılır.
///
/// The concatenation has no length prefixes (and cannot get them: every
/// existing fingerprint and identity id would change). It is unambiguous only
/// for keys of the right lengths, so any other input is hashed in a second,
/// length-prefixed form whose outer hash input is never as long as a real
/// one. A key set with the same bytes split at other boundaries therefore
/// never has a real device's fingerprint, at every caller that compares.
pub fn compute_fingerprint(
    sign_pubkey_ed25519: &[u8],
    sign_pubkey_mldsa: &[u8],
    kem_pubkey_x25519: &[u8],
    kem_pubkey_mlkem: &[u8],
) -> Vec<u8> {
    let parts = [sign_pubkey_ed25519, sign_pubkey_mldsa, kem_pubkey_x25519, kem_pubkey_mlkem];
    let mut hasher = Sha3_256::new();
    if parts.map(<[u8]>::len) == DEVICE_KEY_LENS {
        parts.iter().for_each(|part| hasher.update(part));
        return hasher.finalize().to_vec();
    }
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let inner = hasher.finalize();
    Sha3_256::new().chain_update(b"p2pmsg-not-a-device-key-set").chain_update(inner).finalize().to_vec()
}

/// Do these four public keys make the device `fingerprint_hex` names? The one
/// check every record that carries a device's keys goes through (see the
/// `keys_match_fingerprint` methods in `packet`): the lengths are right and
/// the keys hash to the fingerprint.
pub fn keys_match_fingerprint(
    fingerprint_hex: &str,
    sign_pubkey_ed25519: &[u8],
    sign_pubkey_mldsa: &[u8],
    kem_pubkey_x25519: &[u8],
    kem_pubkey_mlkem: &[u8],
) -> bool {
    let parts = [sign_pubkey_ed25519, sign_pubkey_mldsa, kem_pubkey_x25519, kem_pubkey_mlkem];
    parts.map(<[u8]>::len) == DEVICE_KEY_LENS
        && hex::encode(compute_fingerprint(sign_pubkey_ed25519, sign_pubkey_mldsa, kem_pubkey_x25519, kem_pubkey_mlkem)) == fingerprint_hex
}

/// Kullanıcıya gösterilen biçim (spec 1.2): Base32, 5'li gruplar, büyük
/// harf. Örnek: `XJ4K2-9QWRT-7YHBM-3ZPLC-VN8DF...` (~52 karakter, 8 grup).
pub fn format_fingerprint_base32(raw: &[u8]) -> String {
    let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, raw);
    let upper = encoded.to_uppercase();
    upper
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

/// Kısa doğrulama kodu (spec 1.2): fingerprint'in ilk 16 baytı, 2 baytlık 8
/// grup, her biri 5 haneli ondalık (00000-65535). The full fingerprint is
/// `format_fingerprint_base32`.
///
/// 16 bytes, 8 groups. At 8 bytes a key set with a victim's code took about
/// 2^64 cheap trials (only the X25519 key has to vary), divided by the number
/// of targets: within reach of a funded attacker.
pub fn format_short_code(raw: &[u8]) -> String {
    raw[..16.min(raw.len())]
        .chunks(2)
        .map(|chunk| format!("{:05}", chunk.iter().fold(0u32, |v, b| (v << 8) | *b as u32)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `identity_id` de aynı Base32 formatında gösterilir (spec 1.2, "Identity
/// kodu" / kişi kodu). `identity_id` zaten hex string olarak saklandığı
/// için burada ham bayta çevrilip yeniden formatlanır.
pub fn format_identity_code(identity_id_hex: &str) -> Result<String, String> {
    let raw = hex::decode(identity_id_hex).map_err(|_| "Bad identity_id hex")?;
    Ok(format_fingerprint_base32(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format_has_dashes() {
        let raw = vec![0u8; 32];
        let formatted = format_fingerprint_base32(&raw);
        assert!(formatted.contains('-'));
        assert!(formatted.chars().all(|c| c.is_ascii_uppercase() || c == '-'));
    }

    #[test]
    fn short_code_has_eight_groups() {
        let raw = vec![1u8; 32];
        let code = format_short_code(&raw);
        assert_eq!(code.split(' ').count(), 8);
        assert_eq!(format_short_code(&[0xff, 0xff, 0, 1, 0x12, 0x34, 0, 0]), "65535 00001 04660 00000");
    }

    /// Finding 15: the same bytes split at other key boundaries must not
    /// give the fingerprint of the real key set.
    #[test]
    fn fingerprint_depends_on_the_key_boundaries() {
        let bytes: Vec<u8> = (0..DEVICE_KEY_LENS.iter().sum::<usize>()).map(|i| (i % 251) as u8).collect();
        let split = |lens: [usize; 4]| {
            let (a, rest) = bytes.split_at(lens[0]);
            let (b, rest) = rest.split_at(lens[1]);
            let (c, d) = rest.split_at(lens[2]);
            assert_eq!(d.len(), lens[3]);
            compute_fingerprint(a, b, c, d)
        };
        let real = split(DEVICE_KEY_LENS);
        assert_eq!(real, Sha3_256::digest(&bytes).to_vec(), "real fingerprints are unchanged");
        assert_ne!(real, split([31, 2593, 32, 1568]));
        assert_ne!(real, split([32, 2592, 33, 1567]));
        assert_ne!(split([31, 2593, 32, 1568]), split([30, 2594, 32, 1568]));
        assert_eq!(real.len(), split([0, 0, 0, 4224]).len());

        let (a, rest) = bytes.split_at(32);
        let (b, rest) = rest.split_at(2592);
        let (c, d) = rest.split_at(32);
        assert!(keys_match_fingerprint(&hex::encode(&real), a, b, c, d));
        assert!(!keys_match_fingerprint(&hex::encode(&real), a, b, d, c));
        let odd = hex::encode(split([31, 2593, 32, 1568]));
        assert!(!keys_match_fingerprint(&odd, &bytes[..31], &bytes[31..2624], c, d), "wrong lengths never match");
    }
}
