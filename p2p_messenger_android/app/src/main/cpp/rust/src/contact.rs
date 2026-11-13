//! Trust model: TOFU plus change detection for the security number. See the Description.md section 2 for the design.

use serde::{Deserialize, Serialize};

/// Live device entries kept per contact; a contact with a signed DeviceAdd
/// chain could otherwise grow the list without bound.
pub const MAX_KNOWN_DEVICES: usize = 64;

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
    /// Whether this device was recognised through an in-person QR or manual pairing, or added through a signed `DeviceAdd` chain.
    ///
    /// A `verified: bool` field used to exist here. BOTH add paths wrote it as `false`, and nothing ever read it. The two add functions
    /// (`add_device_unverified` / `add_device_via_signed_chain`) also had identical bodies, so the distinction their names implied did not
    /// exist in the code. The field now really carries that distinction. It is the signal for `canonical_device_for_identity` and for the
    /// "not verified" warning in the UI.
    #[serde(default)]
    pub via_signed_chain: bool,
    /// Revoked by the contact's own signed `DeviceRevoke`, not by the local
    /// user. Such a device never becomes Active again: a stolen device still
    /// shows its code and still holds its old `DeviceAdd`.
    #[serde(default)]
    pub owner_revoked: bool,
    /// When it was revoked (local clock): its author proofs on group rows
    /// dated after this are refused. `None` while Active.
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub contact_id: String, // yerel uuid
    pub display_name: String,
    pub trusted_identity_id: String,
    pub known_devices: Vec<KnownDevice>,
    pub last_device_change: Option<u64>,
    // `ratchet_states` is kept at the P2PCore level (a map from (device_fingerprint pair) to DeviceRatchetState). The Contact struct carries
    // only the TOFU records. The real ratchet state holds secret keys that cannot be serialised, so it lives in a separate map
    // (see `P2PCore.ratchets` in lib.rs).
    /// The most recent profile photo this contact sent us in a `MessageContent::ProfileUpdate` (720p, 85% JPEG). `None` means the
    /// contact never sent one, or removed it.
    #[serde(default, with = "serde_bytes")]
    pub avatar_jpeg: Option<Vec<u8>>,
    /// Whether this contact was added DIRECTLY (in-person QR or manual pairing, TOFU): `false`. Or through a group, on the strength of the
    /// FOUNDER'S VOUCH: `true`. The second is a weaker trust model (it rests on the founder's word), so the UI shows a warning for it
    /// (see the security note on `GroupUpdate.member_devices` in packet.rs).
    /// `#[serde(default)]`: contacts saved before this field existed count as added directly (`false`).
    #[serde(default)]
    pub added_via_group: bool,
}

/// The outcome that decides what to do when a connection is set up with an `(identity_id, device_fingerprint)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCheckOutcome {
    /// The identity_id is unknown: TOFU. Save it, set verified=false, and continue.
    NewContactTofu,
    /// Known and ACTIVE device: continue silently.
    KnownActive,
    /// A new device, but it arrived with a valid signed DeviceAdd: add it silently and show an informational notice only.
    NewDeviceViaSignedAdd,
    /// A new device with NO signed DeviceAdd: BLOCK it and show a warning to the user.
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

    /// TOFU: records a new device as unverified. Called on first contact, or when the user accepts on the alarm screen.
    pub fn add_device_unverified(&mut self, fingerprint: String, now: u64) {
        self.push_device(fingerprint, now, false);
    }

    /// Adds a new device that arrives with a signed DeviceAdd chain, silently. The user sees only an informational notice, not an alarm.
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
            // An unverified re-add of a live device does not undo its chain proof.
            if d.status == KnownDeviceStatus::Revoked {
                d.via_signed_chain = via_signed_chain;
            } else {
                d.via_signed_chain |= via_signed_chain;
            }
            d.status = KnownDeviceStatus::Active;
            d.revoked_at = None;
        } else {
            // Owner-revoked tombstones have their own cap (32).
            if self.known_devices.iter().filter(|d| !d.owner_revoked).count() >= MAX_KNOWN_DEVICES {
                // Full: make room by dropping the oldest device the local
                // user revoked. With 64 live devices the new one is refused
                // (logged: it used to vanish without a trace).
                match self.known_devices.iter().enumerate()
                    .filter(|(_, d)| !d.owner_revoked && d.status == KnownDeviceStatus::Revoked)
                    .min_by_key(|(_, d)| d.first_seen)
                    .map(|(i, _)| i)
                {
                    Some(i) => { self.known_devices.remove(i); }
                    None => {
                        log::warn!("Contact {}: device list full ({}), new device not added", self.contact_id, MAX_KNOWN_DEVICES);
                        return;
                    }
                }
            }
            self.known_devices.push(KnownDevice {
                device_fingerprint: fingerprint,
                first_seen: now,
                status: KnownDeviceStatus::Active,
                via_signed_chain,
                owner_revoked: false,
                revoked_at: None,
            });
        }
        self.last_device_change = Some(now);
    }

    /// The contact revoked its device with a signed notice (see `owner_revoked`).
    /// A device this side never saw gets an entry too: its old `DeviceAdd`
    /// must not introduce it later.
    pub fn revoke_device_by_owner(&mut self, fingerprint: &str, now: u64) {
        // ponytail: 32 owner-revoked entries. The owner signs each one, so
        // only the contact itself can fill the list. At the cap the OLDEST
        // tombstone goes: dropping the new one forgot the latest (most
        // likely stolen) device's revoke.
        if self.find_device(fingerprint).is_none() {
            if self.known_devices.iter().filter(|d| d.owner_revoked).count() >= 32 {
                if let Some(i) = self.known_devices.iter().enumerate()
                    .filter(|(_, d)| d.owner_revoked)
                    .min_by_key(|(_, d)| d.first_seen)
                    .map(|(i, _)| i)
                {
                    self.known_devices.remove(i);
                }
            }
            self.known_devices.push(KnownDevice {
                device_fingerprint: fingerprint.to_string(),
                first_seen: now,
                status: KnownDeviceStatus::Revoked,
                via_signed_chain: true,
                owner_revoked: true,
                revoked_at: None,
            });
        }
        self.revoke_device(fingerprint, now);
        if let Some(d) = self.known_devices.iter_mut().find(|d| d.device_fingerprint == fingerprint) {
            d.owner_revoked = true;
        }
    }

    pub fn revoked_at(&self, fingerprint: &str) -> Option<u64> {
        self.find_device(fingerprint).and_then(|d| d.revoked_at)
    }

    pub fn revoke_device(&mut self, fingerprint: &str, now: u64) {
        if let Some(d) = self.known_devices.iter_mut().find(|d| d.device_fingerprint == fingerprint) {
            d.status = KnownDeviceStatus::Revoked;
            d.revoked_at.get_or_insert(now);
            self.last_device_change = Some(now);
        }
    }
}

/// Applies the decision tree from the Description.md section 2.2. `has_valid_signed_device_add` must be computed by the caller in advance:
/// it says whether this packet really came with a DeviceAdd signed by a KNOWN ACTIVE device, or is a bare "it's me" claim.
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
        // Many live devices do not use up the room for revoked ones.
        for i in 0..MAX_KNOWN_DEVICES + 5 {
            c.add_device_unverified(format!("live{i}"), 7000);
        }
        c.revoke_device_by_owner("dev3", 8000);
        assert!(c.find_device("dev3").is_some());
        assert!(c.find_device(&format!("live{}", MAX_KNOWN_DEVICES + 4)).is_none(), "live list is capped");
    }

    #[test]
    fn unverified_re_add_keeps_chain_proof() {
        let mut c = Contact::new("c1".into(), "Alice".into(), "id1".into());
        c.add_device_via_signed_chain("dev1".into(), 1000);
        c.add_device_unverified("dev1".into(), 2000);
        assert!(c.find_device("dev1").unwrap().via_signed_chain);
    }

    #[test]
    fn revoked_at_is_kept_and_cleared_on_readd() {
        let mut c = Contact::new("c".into(), "n".into(), "id".into());
        c.add_device_unverified("dev1".into(), 1000);
        c.revoke_device("dev1", 2000);
        c.revoke_device("dev1", 3000);
        assert_eq!(c.revoked_at("dev1"), Some(2000));
        c.add_device_unverified("dev1".into(), 4000);
        assert_eq!(c.revoked_at("dev1"), None);
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
