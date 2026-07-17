//! Güven modeli: TOFU + Güvenlik Numarası Değişikliği — Description.md
//! bölüm 2.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KnownDeviceStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownDevice {
    pub device_fingerprint: String,
    pub verified: bool,
    pub first_seen: u64,
    pub status: KnownDeviceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub contact_id: String, // yerel uuid
    pub display_name: String,
    pub trusted_identity_id: String,
    pub known_devices: Vec<KnownDevice>,
    pub last_device_change: Option<u64>,
    // `ratchet_states` P2PCore seviyesinde (device_fingerprint çifti ->
    // DeviceRatchetState) ayrıca tutulur; Contact struct'ı sadece TOFU
    // kayıtlarını taşır (spec 2.1'deki alan burada da var ama gerçek
    // ratchet state serileştirilemeyen secret key'ler içerdiği için ayrı
    // bir map'te — bkz. lib.rs P2PCore.ratchets).
}

/// Bir bağlantı kurulurken (spec 2.2) `(identity_id, device_fingerprint)`
/// çiftinin ne yapılması gerektiğini belirten sonuç.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCheckOutcome {
    /// identity_id hiç bilinmiyor: TOFU, kaydet, verified=false, devam et.
    NewContactTofu,
    /// Bilinen + Active cihaz: sessizce devam.
    KnownActive,
    /// Yeni cihaz ama geçerli imzalı DeviceAdd ile geldi: sessizce ekle,
    /// sadece bilgi bildirimi göster.
    NewDeviceViaSignedAdd,
    /// Yeni cihaz, imzalı DeviceAdd YOK: BLOKLA, kullanıcıya uyarı göster.
    UnverifiedNewDeviceAlert,
}

impl Contact {
    pub fn new(contact_id: String, display_name: String, trusted_identity_id: String) -> Self {
        Contact {
            contact_id,
            display_name,
            trusted_identity_id,
            known_devices: Vec::new(),
            last_device_change: None,
        }
    }

    pub fn find_device(&self, fingerprint: &str) -> Option<&KnownDevice> {
        self.known_devices.iter().find(|d| d.device_fingerprint == fingerprint)
    }

    pub fn is_known_active(&self, fingerprint: &str) -> bool {
        self.find_device(fingerprint)
            .map(|d| matches!(d.status, KnownDeviceStatus::Active))
            .unwrap_or(false)
    }

    /// TOFU: yeni bir cihazı doğrulanmamış olarak kaydeder (ilk temas
    /// veya alarm ekranında kullanıcı "kabul et" dediğinde çağrılır).
    pub fn add_device_unverified(&mut self, fingerprint: String, now: u64) {
        self.known_devices.push(KnownDevice {
            device_fingerprint: fingerprint,
            verified: false,
            first_seen: now,
            status: KnownDeviceStatus::Active,
        });
        self.last_device_change = Some(now);
    }

    /// İmzalı DeviceAdd zinciriyle gelen yeni cihazı sessizce ekler (spec
    /// 2.2 — kullanıcıya sadece bilgi bildirimi gösterilir, alarm değil).
    pub fn add_device_via_signed_chain(&mut self, fingerprint: String, now: u64) {
        self.known_devices.push(KnownDevice {
            device_fingerprint: fingerprint,
            verified: false,
            first_seen: now,
            status: KnownDeviceStatus::Active,
        });
        self.last_device_change = Some(now);
    }

    pub fn revoke_device(&mut self, fingerprint: &str, now: u64) {
        if let Some(d) = self.known_devices.iter_mut().find(|d| d.device_fingerprint == fingerprint) {
            d.status = KnownDeviceStatus::Revoked;
            self.last_device_change = Some(now);
        }
    }

    pub fn mark_verified(&mut self, fingerprint: &str) {
        if let Some(d) = self.known_devices.iter_mut().find(|d| d.device_fingerprint == fingerprint) {
            d.verified = true;
        }
    }
}

/// Spec 2.2'deki karar ağacını uygular. `has_valid_signed_device_add`,
/// çağıran tarafından önceden hesaplanmış olmalı (bu paket gerçekten
/// bilinen bir Active cihaz tarafından imzalanmış bir DeviceAdd ile mi
/// geldi, yoksa çıplak bir "ben buyum" iddiası mı).
pub fn check_incoming_device(
    contact: Option<&Contact>,
    device_fingerprint: &str,
    has_valid_signed_device_add: bool,
) -> DeviceCheckOutcome {
    match contact {
        None => DeviceCheckOutcome::NewContactTofu,
        Some(c) => {
            if c.is_known_active(device_fingerprint) {
                DeviceCheckOutcome::KnownActive
            } else if has_valid_signed_device_add {
                DeviceCheckOutcome::NewDeviceViaSignedAdd
            } else {
                DeviceCheckOutcome::UnverifiedNewDeviceAlert
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_identity_is_tofu() {
        assert_eq!(check_incoming_device(None, "abc", false), DeviceCheckOutcome::NewContactTofu);
    }

    #[test]
    fn known_active_is_silent() {
        let mut c = Contact::new("c1".into(), "Alice".into(), "id1".into());
        c.add_device_unverified("dev1".into(), 1000);
        assert_eq!(check_incoming_device(Some(&c), "dev1", false), DeviceCheckOutcome::KnownActive);
    }

    #[test]
    fn unsigned_new_device_alerts() {
        let mut c = Contact::new("c1".into(), "Alice".into(), "id1".into());
        c.add_device_unverified("dev1".into(), 1000);
        assert_eq!(
            check_incoming_device(Some(&c), "dev2", false),
            DeviceCheckOutcome::UnverifiedNewDeviceAlert
        );
    }

    #[test]
    fn signed_new_device_is_silent_add() {
        let mut c = Contact::new("c1".into(), "Alice".into(), "id1".into());
        c.add_device_unverified("dev1".into(), 1000);
        assert_eq!(
            check_incoming_device(Some(&c), "dev2", true),
            DeviceCheckOutcome::NewDeviceViaSignedAdd
        );
    }

    #[test]
    fn revoked_device_is_not_known_active() {
        let mut c = Contact::new("c1".into(), "Alice".into(), "id1".into());
        c.add_device_unverified("dev1".into(), 1000);
        c.revoke_device("dev1", 2000);
        assert_eq!(
            check_incoming_device(Some(&c), "dev1", false),
            DeviceCheckOutcome::UnverifiedNewDeviceAlert
        );
    }
}
