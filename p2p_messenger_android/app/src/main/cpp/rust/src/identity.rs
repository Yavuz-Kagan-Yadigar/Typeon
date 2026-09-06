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

/// Bir cihazın hibrit imza + KEM public key'lerinden fingerprint türetir.
/// `fingerprint = SHA3-256( sign_ed25519 || sign_mldsa || kem_x25519 || kem_mlkem )`
/// (spec 1.2). Ham fingerprint 32 byte, hex olarak döner; gösterim
/// formatları için `format_fingerprint_base32` / `format_short_code`
/// kullanılır.
pub fn compute_fingerprint(
    sign_pubkey_ed25519: &[u8],
    sign_pubkey_mldsa: &[u8],
    kem_pubkey_x25519: &[u8],
    kem_pubkey_mlkem: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(sign_pubkey_ed25519);
    hasher.update(sign_pubkey_mldsa);
    hasher.update(kem_pubkey_x25519);
    hasher.update(kem_pubkey_mlkem);
    hasher.finalize().to_vec()
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

/// Kısa doğrulama kodu (spec 1.2): fingerprint'in ilk 8 baytından türetilen
/// 5 haneli sayı grupları x 4 (Signal "safety number" formatına benzer).
/// Her grup, ilgili 2 bayttan türetilen bir sayının 5 haneye
/// (0-99999 aralığına, mod ile) sıkıştırılmasıyla üretilir.
pub fn format_short_code(raw: &[u8]) -> String {
    let first8 = &raw[..8.min(raw.len())];
    let mut groups = Vec::with_capacity(4);
    for chunk in first8.chunks(2) {
        let val = if chunk.len() == 2 {
            ((chunk[0] as u32) << 8) | chunk[1] as u32
        } else {
            chunk[0] as u32
        };
        // 16-bit değeri 0-99999 aralığına indir, 5 haneli göster.
        groups.push(format!("{:05}", val % 100000));
    }
    groups.join(" ")
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
    fn short_code_has_four_groups() {
        let raw = vec![1u8; 32];
        let code = format_short_code(&raw);
        assert_eq!(code.split(' ').count(), 4);
    }
}
