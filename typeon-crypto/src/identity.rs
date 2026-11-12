//! Identity and device model.
//!
//! Two layers: an identity (a person) and one or more devices.
//! `identity_id` is the fingerprint of the first device and never changes.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Maximum number of active devices per identity.
pub const MAX_ACTIVE_DEVICES: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_fingerprint: String,  // hex-encoded 32-byte fingerprint
    pub device_name: String,
    pub added_at: u64,
    pub status: DeviceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Fingerprint of the first device. Fixed.
    pub identity_id: String,
    pub devices: Vec<DeviceInfo>,
    /// Device allowed to add and remove devices. Any active device has this
    /// right; `primary_device` only marks the first device set up.
    pub primary_device: Option<String>,
}

/// Public key sizes: Ed25519, ML-DSA-87, X25519, ML-KEM-1024.
pub const DEVICE_KEY_LENS: [usize; 4] = [32, 2592, 32, 1568];

/// Derives a device fingerprint from its hybrid signing and KEM public keys:
/// `SHA3-256(sign_ed25519 || sign_mldsa || kem_x25519 || kem_mlkem)`.
/// Returns 32 bytes as hex. Use `format_fingerprint_base32` or
/// `format_short_code` for display.
///
/// The concatenation has no length prefixes, and adding them would change
/// every existing fingerprint and identity id. It is unambiguous only for keys
/// of the right lengths. Any other input is hashed in a second, length-prefixed
/// form, so a key set whose bytes are split at other boundaries never matches
/// a real device's fingerprint.
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

/// Checks that four public keys match the device fingerprint they claim. Every
/// record that carries a device's keys goes through this check (see
/// `keys_match_fingerprint` in `packet`).
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

/// Display form: Base32 in groups of five, uppercase, e.g.
/// `XJ4K2-9QWRT-7YHBM-3ZPLC-VN8DF...` (about 52 characters, 8 groups).
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

/// Short verification code: the first 16 bytes of the fingerprint as eight
/// groups of two bytes, each shown as a five-digit decimal (00000-65535).
/// The full fingerprint is `format_fingerprint_base32`.
///
/// 128 bits. Do not shorten it: a 64-bit code could be matched by about 2^64
/// cheap key trials, since only the X25519 key has to vary. Inputs shorter than
/// 16 bytes return "" rather than a weaker code.
pub fn format_short_code(raw: &[u8]) -> String {
    if raw.len() < 16 {
        return String::new();
    }
    raw[..16]
        .chunks(2)
        .map(|chunk| format!("{:05}", chunk.iter().fold(0u32, |v, b| (v << 8) | *b as u32)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Shows `identity_id` in the same Base32 format. The id is stored as hex, so
/// it is converted back to bytes first.
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
        let mut raw = [0u8; 16];
        raw[..6].copy_from_slice(&[0xff, 0xff, 0, 1, 0x12, 0x34]);
        assert_eq!(format_short_code(&raw), "65535 00001 04660 00000 00000 00000 00000 00000");
        assert_eq!(format_short_code(&raw[..15]), "", "a short input gives no code, not a weaker one");
    }

    /// The same bytes split at other key boundaries must not produce the
    /// fingerprint of the real key set.
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
