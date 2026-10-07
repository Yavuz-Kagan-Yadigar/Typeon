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
    pub first_seen: u64,
    pub status: KnownDeviceStatus,
    /// Bu cihaz yüz yüze QR/manuel eşleşmeyle mi tanındı, yoksa imzalı bir
    /// `DeviceAdd` zinciriyle mi eklendi?
    ///
    /// Defter #31/#32: burada eskiden `verified: bool` vardı ama HER İKİ
    /// ekleme yolu da onu `false` yazıyor ve hiçbir yer okumuyordu; iki
    /// ekleme fonksiyonunun (`add_device_unverified` /
    /// `add_device_via_signed_chain`) gövdeleri de birebir aynıydı, yani
    /// isimlerin ima ettiği ayrım kodda hiç yoktu. Alan artık o ayrımı
    /// GERÇEKTEN taşıyor: `canonical_device_for_identity` ve arayüzün
    /// "doğrulanmadı" uyarısı için anlamlı bir sinyal.
    #[serde(default)]
    pub via_signed_chain: bool,
    /// Revoked by the contact's own signed `DeviceRevoke`, not by the local
    /// user. Such a device never becomes Active again: a stolen device still
    /// shows its code and still holds its old `DeviceAdd`.
    #[serde(default)]
    pub owner_revoked: bool,
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
    /// Spec dışı: bu kişinin bize `MessageContent::ProfileUpdate` ile
    /// gönderdiği en güncel profil fotoğrafı (720p/%85 JPEG). `None` =
    /// hiç göndermedi ya da fotoğrafını kaldırdı.
    #[serde(default)]
    pub avatar_jpeg: Option<Vec<u8>>,
    /// Spec dışı, kullanıcı kararı: bu kişi DOĞRUDAN (QR/manuel eşleşme,
    /// yüz yüze TOFU) mi eklendi — `false`; yoksa bir grup üzerinden
    /// KURUCU KEFALETİYLE mi — `true`? İkincisi daha zayıf bir güven
    /// modelidir (kurucunun sözü), bu yüzden UI'de uyarı gösterilir
    /// (bkz. packet.rs `GroupUpdate.member_devices` güvenlik notu).
    /// `#[serde(default)]` — bu alan olmadan kaydedilmiş eski kişiler
    /// doğrudan eklenmiş (false) sayılır.
    #[serde(default)]
    pub added_via_group: bool,
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
            avatar_jpeg: None,
            added_via_group: false,
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
        self.push_device(fingerprint, now, false);
    }

    /// İmzalı DeviceAdd zinciriyle gelen yeni cihazı sessizce ekler (spec
    /// 2.2 — kullanıcıya sadece bilgi bildirimi gösterilir, alarm değil).
    pub fn add_device_via_signed_chain(&mut self, fingerprint: String, now: u64) {
        self.push_device(fingerprint, now, true);
    }

    fn push_device(&mut self, fingerprint: String, now: u64, via_signed_chain: bool) {
        // A device that is already listed (revoked) is reactivated in place.
        // A second entry stayed hidden behind the revoked one in
        // `find_device`, so the device never became usable and every
        // re-pairing added one more entry.
        if let Some(d) = self.known_devices.iter_mut().find(|d| d.device_fingerprint == fingerprint) {
            if d.owner_revoked {
                return;
            }
            d.status = KnownDeviceStatus::Active;
            d.via_signed_chain = via_signed_chain;
        } else {
            self.known_devices.push(KnownDevice {
                device_fingerprint: fingerprint,
                first_seen: now,
                status: KnownDeviceStatus::Active,
                via_signed_chain,
                owner_revoked: false,
            });
        }
        self.last_device_change = Some(now);
    }

    /// The contact revoked its device with a signed notice (see `owner_revoked`).
    /// A device this side never saw gets an entry too: its old `DeviceAdd`
    /// must not introduce it later.
    pub fn revoke_device_by_owner(&mut self, fingerprint: &str, now: u64) {
        // ponytail: 32 entries. The owner signs each one, so only the contact
        // itself can fill the list.
        if self.find_device(fingerprint).is_none() && self.known_devices.len() < 32 {
            self.known_devices.push(KnownDevice {
                device_fingerprint: fingerprint.to_string(),
                first_seen: now,
                status: KnownDeviceStatus::Revoked,
                via_signed_chain: true,
                owner_revoked: true,
            });
        }
        self.revoke_device(fingerprint, now);
        if let Some(d) = self.known_devices.iter_mut().find(|d| d.device_fingerprint == fingerprint) {
            d.owner_revoked = true;
        }
    }

    pub fn revoke_device(&mut self, fingerprint: &str, now: u64) {
        if let Some(d) = self.known_devices.iter_mut().find(|d| d.device_fingerprint == fingerprint) {
            d.status = KnownDeviceStatus::Revoked;
            self.last_device_change = Some(now);
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
            // A device listed here and not Active was revoked. A replayed
            // signed DeviceAdd must not bring it back without the user.
            } else if has_valid_signed_device_add && c.find_device(device_fingerprint).is_none() {
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
    fn re_adding_a_revoked_device_reactivates_its_entry() {
        let mut c = Contact::new("c1".into(), "Alice".into(), "id1".into());
        c.add_device_unverified("dev1".into(), 1000);
        c.revoke_device("dev1", 2000);
        c.add_device_unverified("dev1".into(), 3000);
        assert_eq!(c.known_devices.len(), 1);
        assert!(c.is_known_active("dev1"));
    }

    #[test]
    fn owner_revoked_device_stays_revoked() {
        let mut c = Contact::new("c1".into(), "Alice".into(), "id1".into());
        c.add_device_unverified("dev1".into(), 1000);
        c.revoke_device_by_owner("dev1", 2000);
        c.add_device_unverified("dev1".into(), 3000);
        c.add_device_via_signed_chain("dev1".into(), 4000);
        assert!(!c.is_known_active("dev1"));
        // Never seen before the revoke: remembered, and it stays out.
        c.revoke_device_by_owner("dev2", 5000);
        c.add_device_via_signed_chain("dev2".into(), 6000);
        assert!(!c.is_known_active("dev2"));
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
