//! Wire packet formats carried over the network.

use serde::{Deserialize, Serialize};

/// Element-count limits for collections a peer fills. Decoding stops at the limit, so one byte per element (a
/// `null` in `groups`, an empty string in `mentions`) cannot become tens of MB inside one 1 MiB packet.
mod bounded {
    use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
    use std::marker::PhantomData;

    struct Bounded<T, const N: usize>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a sequence of at most {} items", N)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(N).min(256));
            while let Some(item) = seq.next_element()? {
                if out.len() >= N {
                    return Err(A::Error::custom(format!("more than {} items", N)));
                }
                out.push(item);
            }
            Ok(out)
        }
    }

    fn seq<'de, D: Deserializer<'de>, T: Deserialize<'de>, const N: usize>(d: D) -> Result<Vec<T>, D::Error> {
        d.deserialize_seq(Bounded::<T, N>(PhantomData))
    }
    pub fn seq_256<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
        seq::<D, T, 256>(d)
    }
    pub fn seq_4096<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
        seq::<D, T, 4096>(d)
    }
    pub fn seq_16384<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
        seq::<D, T, 16384>(d)
    }
}

/// Upper bound on a pairing code, which also bounds every field in it (`known_relays`,
/// `rendezvous_node`). A QR code holds about 2.9 KB (see `DeviceLinkRequest`).
const MAX_PAIRING_CODE_BYTES: usize = 4096;

fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// `keys_match_fingerprint()` for every record that carries a device's four
/// public keys next to its fingerprint (see `identity::keys_match_fingerprint`).
macro_rules! impl_keys_match_fingerprint {
    ($($record:ty),*) => {$(
        impl $record {
            pub fn keys_match_fingerprint(&self) -> bool {
                crate::identity::keys_match_fingerprint(
                    &self.device_fingerprint,
                    &self.sign_pubkey_ed25519, &self.sign_pubkey_mldsa,
                    &self.kem_pubkey_x25519, &self.kem_pubkey_mlkem,
                )
            }
        }
    )*};
}
impl_keys_match_fingerprint!(SyncedDevice, GroupMemberDevice, IdentityExchange);

/// Parses a scanned or pasted pairing code. `version` is the version of the
/// parsed value. A version not in `versions` is refused, not read with this
/// version's meaning.
fn pairing_code_from_cbor<T: serde::de::DeserializeOwned>(
    data: &[u8],
    versions: std::ops::RangeInclusive<u8>,
    version: fn(&T) -> u8,
) -> Result<T, String> {
    if data.len() > MAX_PAIRING_CODE_BYTES {
        return Err("Code too long".to_string());
    }
    let mut rest = data;
    let parsed: T = ciborium::from_reader(&mut rest).map_err(|e| e.to_string())?;
    if !rest.is_empty() {
        return Err("Invalid code: trailing bytes".to_string());
    }
    let v = version(&parsed);
    if v > *versions.end() {
        return Err(format!("This code was made by a newer version (v{}): update the app", v));
    }
    if v < *versions.start() {
        return Err(format!("This code was made by an old version (v{}): the other side must update the app", v));
    }
    Ok(parsed)
}

/// Pairing payload carried by the QR code. CBOR-encoded. Full public keys do not
/// fit in a QR code, so the scanner downloads them from the peer after the
/// connection is made and checks them against `fingerprint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrPacket {
    pub version: u8,
    pub device_name: String,
    /// Identity id of the person.
    pub identity_id: String,
    /// Fingerprint of the showing device.
    pub device_fingerprint: String,
    /// One known address that is enough to connect.
    pub rendezvous_node: String,
    /// Full addresses (including `/p2p/<peer_id>`) of a few peers that speak the
    /// Circuit Relay v2 protocol, as known to the showing device. If
    /// `rendezvous_node` is not reachable directly (other network or NAT), the
    /// scanner dials through one of these (`network::dial_with_relay_fallback`).
    /// `#[serde(default)]`: a code without this field parses, with it empty. An older
    /// peer may ignore the field.
    #[serde(default)]
    pub known_relays: Vec<String>,
    /// Random nonce, issued by the device that shows the code. The scanner proves
    /// it read the code by sending `pairing_nonce_proof` in its IdentityExchange.
    /// Not named `nonce`: under that name this packet would also parse as a
    /// `DeviceLinkRequest`, and a contact's code scanned on the "add a device"
    /// screen would be taken as a device to link.
    #[serde(with = "serde_bytes")]
    pub pairing_nonce: Vec<u8>,
}

/// What a device that read a pairing or link code sends in its IdentityExchange
/// (`pairing_proof`): the code's nonce, bound to the sending device. The packet
/// travels unsealed, so the nonce could be taken from the wire and reused by
/// another device without this binding.
pub fn pairing_nonce_proof(nonce: &[u8], sender_device_fingerprint: &str) -> Vec<u8> {
    use sha3::Digest;
    sha3::Sha3_256::new()
        .chain_update(b"typeon-pairing-nonce")
        // Length-prefixed, so the nonce/fingerprint boundary cannot shift.
        .chain_update((nonce.len() as u32).to_be_bytes())
        .chain_update(nonce)
        .chain_update(sender_device_fingerprint.as_bytes())
        .finalize()
        .to_vec()
}

impl QrPacket {
    pub const CURRENT_VERSION: u8 = 3;

    /// CBOR encoding (the raw bytes embedded in the QR code).
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        to_cbor(self)
    }

    /// Only `CURRENT_VERSION` codes are accepted (see `pairing_code_from_cbor`).
    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        pairing_code_from_cbor(data, Self::CURRENT_VERSION..=Self::CURRENT_VERSION, |p: &Self| p.version)
    }
}

/// Device-add notice. The approved device signs it and propagates it
/// (step 4 of device linking).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAdd {
    pub identity_id: String,
    pub new_device_fingerprint: String,
    /// Fingerprint of the approving device.
    pub added_by: String,
    /// Classical (Ed25519) signature over `identity_id || new_device_fingerprint ||
    /// added_by`, made with the approving device's key.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// ML-DSA (post-quantum) signature, in the same hybrid model as MessagePacket
    /// and GroupUpdate (see `verify_hybrid_signature`). Mandatory: the field must
    /// be present, and the verifier rejects an empty one.
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
    /// Hybrid signature of the ADDED device over the same bytes plus a domain tag
    /// (`devices::device_add_consent_bytes`). Without it, one identity's signature
    /// alone could claim any device whose public keys it knew.
    #[serde(default, with = "serde_bytes")]
    pub consent: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    pub consent_pq: Vec<u8>,
}

/// Device revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRevoke {
    pub identity_id: String,
    pub revoked_device_fingerprint: String,
    /// Fingerprint of the revoking device.
    pub revoked_by: String,
    /// Classical signature over `identity_id || revoked_device_fingerprint ||
    /// revoked_by` (see `DeviceAdd.signature`).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Mandatory, as in `DeviceAdd`.
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// Group membership change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupChange {
    Add(String),  // identity id
    Remove(String),  // identity id
    Rename(String),
    /// Group profile photo. Only the founder may change it. This uses the existing
    /// `NotFounder` check of `validate_group_update`, not a new permission
    /// mechanism. `None` removes the photo.
    AvatarUpdate(#[serde(with = "serde_bytes")] Option<Vec<u8>>),
    /// Deletes the group for all members. Unlike the other changes this is not a
    /// field update. On the receiving side the group record is removed entirely
    /// (see the `Delete` arm of `group_ops::process_group_update`). The permission
    /// rule is the same as for the other changes: `validate_group_update` accepts
    /// only the founder's signature (`NotFounder`).
    Delete,
    /// Transfers the founder role to another member. Without it, a group whose founder
    /// lost all devices could never change its members, name or photo again.
    /// The permission rule is unchanged: only the current founder's signature is
    /// valid. The target must already be a member (see `group::apply_change`).
    /// Otherwise the role could pass to someone outside the group and lock it.
    /// Not covered: if the founder is already gone, this does not help. That case
    /// needs a majority vote by the members to appoint a new founder. That would
    /// turn the single-signature scheme into a multi-signature one, which is a
    /// separate design decision.
    TransferFounder(String),
}

/// Proof that a device belongs to an identity, checkable by a party that knows
/// neither. The `DeviceAdd` is signed by the identity's first device (whose
/// fingerprint IS the identity id), and `signer` carries that device's keys.
/// It travels next to a third party's claim "this device belongs to that
/// identity" (group vouching, sibling sync). A first device needs no proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAddProof {
    pub device_add: DeviceAdd,
    pub signer: SyncedDevice,
}

/// A device record that a group member's device has vouched for. The founder
/// vouches for it (see `GroupUpdate.member_devices`). The receiver also checks
/// that `device_fingerprint` is the SHA3-256 of these keys. Records that are not
/// internally consistent are rejected.
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupMemberDevice {
    pub identity_id: String,
    pub device_fingerprint: String,
    pub device_name: String,
    #[serde(with = "serde_bytes")]
    pub sign_pubkey_ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sign_pubkey_mldsa: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kem_pubkey_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kem_pubkey_mlkem: Vec<u8>,
    /// The founder's last known `.onion` address, as a dial hint. Never a clearnet
    /// or UPnP address. If absent, the receiver relies on the relay or server.
    #[serde(default)]
    pub last_addr: Option<String>,
    /// The device's first-contact secret for THIS group (16 bytes), given to the
    /// founder in `MessageContent::FirstContactSecret`. A member that never paired
    /// with the device reaches it through the group's first-contact mailbox on the
    /// server. Only this group's members can fill that mailbox, and it is
    /// registered only while the device is in the group.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    pub first_contact_secret: Vec<u8>,
}

/// Compact, self-verifying evidence of a founder transfer (see
/// `GroupUpdate.founder_chain`).
///
/// Repairs the founder field for a member that missed the transfer.
///
/// `GroupUpdate` carries the group name, the full member list and member keys in
/// every message, so those fields repair themselves (see `members` and
/// `sync_members`). The founder field has no such repair. A member that missed the
/// transfer (its retry window expired while it was offline, or a newer update
/// replaced the transfer in `pending_group_syncs`, which keeps only the LAST update
/// for each member) keeps the old founder and rejects every later update from the
/// new one with `NotFounder`. The chain lets it walk forward to the current founder
/// (`group_ops::heal_founder_chain`).
///
/// Security: this structure is not covered by the outer `GroupUpdate.signature`,
/// and it does not need to be. It carries its own hybrid signature, made over
/// `founder_transfer_signing_input` with a domain separator, so a `GroupUpdate`
/// signature cannot be reused here. An intermediary can delete the list, which
/// leaves the missed-transfer case unrepaired but loses no data. It cannot forge an
/// entry, because the signature must come from the OLD founder's device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FounderTransfer {
    pub group_id: String,
    /// The `GroupUpdate.new_version` the transfer was applied in.
    pub version: u32,
    /// The founder who transferred the role.
    pub from_identity: String,
    /// The member who takes the role.
    pub to_identity: String,
    /// The old founder's device that signed.
    pub signed_by_device: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// Bytes that `FounderTransfer` signs. Length-prefixed. Plain concatenation would
/// let the field boundaries shift, so different (group_id, identity) pairs could
/// produce the same bytes.
pub fn founder_transfer_signing_input(
    group_id: &str,
    version: u32,
    from_identity: &str,
    to_identity: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"p2pmsg-v0.1-founder-transfer");
    out.extend_from_slice(&version.to_be_bytes());
    for field in [group_id, from_identity, to_identity] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUpdate {
    pub group_id: String,
    pub new_version: u32,
    pub change: GroupChange,
    /// The group's current name, carried in every `GroupUpdate` and not only in
    /// `Rename` changes. A member that is added for the first time has no local
    /// `Group` record yet, so `process_group_update` takes the name from the update.
    pub group_name: String,
    /// Full member list after this change, as the founder knows it. Every update
    /// carries it, so a member added later learns the members added before it, and
    /// missed updates heal on their own.
    /// `#[serde(default)]`: a packet without this field parses with an empty list.
    /// The signature covers this field.
    #[serde(default, deserialize_with = "bounded::seq_4096")]
    pub members: Vec<String>,
    /// Members' public keys and last known addresses, vouched for by the founder.
    ///
    /// Group messaging needs every pair of members to hold a ratchet. But members
    /// may have paired only with the founder (A-B and A-C paired, B-C not). In that
    /// case B and C could never send each other messages. This field lets every
    /// member learn the others' keys from the founder.
    ///
    /// Security: this is weaker than face-to-face TOFU with a QR code, because it
    /// relies on the founder's word. A malicious founder could give its own key for
    /// a member and impersonate that member inside the group (a group MITM).
    /// Therefore: (a) the field is covered by the signature, so no intermediary can
    /// change it; (b) the receiver never overwrites keys of a device it ALREADY
    /// knows (see `process_group_update`); (c) entries added this way are marked as not
    /// verified face to face, and the UI warns about them.
    ///
    /// Only the devices new or changed since the founder's previous update are sent
    /// (all of them for a newly added member, and in a reply to
    /// `MessageContent::GroupSyncRequest`).
    #[serde(default, deserialize_with = "bounded::seq_4096")]
    pub member_devices: Vec<GroupMemberDevice>,
    /// For each vouched device that is not its identity's first device: the proof
    /// that it belongs to that identity (see `DeviceAddProof`). Outside the founder's
    /// signature, like `founder_chain`: each proof is signed by itself, and a version
    /// that does not know the field still verifies the update.
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "bounded::seq_4096")]
    pub member_device_proofs: Vec<DeviceAddProof>,
    /// Must be `founder_identity_id`. The receiver checks this.
    pub signed_by: String,
    /// The founder's signing device.
    pub signed_by_device: String,
    /// Classical (Ed25519) signature.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// ML-DSA (post-quantum) signature, hybrid with `signature` as in MessagePacket
    /// and HandshakeInit. Both are required, verified with `verify_hybrid_signature`.
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
    /// Founder transfer chain (see `FounderTransfer`). Every update from the founder
    /// carries the known transfers for the group. A receiver that missed a transfer
    /// walks this chain forward (`group_ops::heal_founder_chain`) and then accepts
    /// the update. `#[serde(default)]`, so it is compatible in both directions with
    /// versions that do not know the field. Not covered by the outer signature,
    /// because each entry carries its own signature.
    #[serde(default, deserialize_with = "bounded::seq_4096")]
    pub founder_chain: Vec<FounderTransfer>,
}

// ---------------------------------------------------------------------------
// Multi-device linking. The new device shows a QR code and the approved device
// scans it. Approval always comes from a device the user already trusts.
// ---------------------------------------------------------------------------

/// Device-add QR code shown by the new device.
///
/// It carries only the device fingerprint, not full public keys. ML-DSA-87
/// (2592 bytes) and ML-KEM-1024 (1568 bytes) together come to about 4.2 KB,
/// which is over the roughly 2.9 KB maximum of a QR code (version 40, lowest
/// error correction, byte mode). No error-correction level fixes that. The
/// pattern matches `QrPacket`: `device_fingerprint` only (SHA3-256, 64 hex
/// characters). The approving device connects to `rendezvous_node` and sends
/// its `IdentityExchange`. The new device replies with its own `IdentityExchange`
/// (see `process_identity_exchange`). The real
/// public keys, and their check against the fingerprint, are learned in that
/// exchange, as in a normal contact pairing (see `process_qr_packet`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLinkRequest {
    pub version: u8,
    pub device_name: String,
    /// Fingerprint of the new device's own provisional key set: the SHA3-256 of
    /// those keys. The approving side recomputes it after it gets the real keys in
    /// `IdentityExchange` and compares (see the struct documentation above).
    pub device_fingerprint: String,
    /// One known address the approving device can connect to (`get_node_address`,
    /// which is the `.onion` address when Tor is on).
    pub rendezvous_node: String,
    /// See `QrPacket.known_relays`. Relay candidates for other networks and NATs.
    #[serde(default)]
    pub known_relays: Vec<String>,
    /// 16 random bytes made for this QR code. The grant must repeat them. Only the
    /// device that scanned the code knows them, so no other device with a session to
    /// the new one can claim it (v3).
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

impl DeviceLinkRequest {
    /// v3 carries `nonce`. Only `CURRENT_VERSION` parses with `from_cbor`. Older
    /// formats are refused.
    pub const CURRENT_VERSION: u8 = 3;
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        to_cbor(self)
    }
    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        pairing_code_from_cbor(data, Self::CURRENT_VERSION..=Self::CURRENT_VERSION, |p: &Self| p.version)
    }
}

/// Public keys of one remote device, carried in the sync payload. The receiver
/// stores them in its `known_remote_devices`, so it can start a ratchet and message
/// that contact right after the first sync. No separate QR pairing is needed.
#[derive(Clone, Serialize, Deserialize)]
pub struct SyncedDevice {
    pub device_fingerprint: String,
    pub device_name: String,
    #[serde(with = "serde_bytes")]
    pub sign_pubkey_ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sign_pubkey_mldsa: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kem_pubkey_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kem_pubkey_mlkem: Vec<u8>,
    pub is_active: bool,
    #[serde(default)]
    pub last_addr: Option<String>,
    /// Hex. The secrets of this device's first-contact mailboxes that the sender
    /// holds (`first_contact_secrets`). Filled only in a `SyncPayload`
    /// (ratchet-encrypted, siblings only). Every device of an identity can then reach
    /// the devices its siblings paired with, and be reached by them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mailbox_secrets: Vec<String>,
}

// Hand-written Debug for the two device records. They carry mailbox capabilities
// (`first_contact_secret`, `mailbox_secrets`), and every type that holds them
// (`GroupUpdate`, `DeviceAddProof`, `SyncedContact`) derives Debug through them.
// Print the name and fingerprint only.
impl std::fmt::Debug for GroupMemberDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupMemberDevice")
            .field("identity_id", &self.identity_id)
            .field("device_fingerprint", &self.device_fingerprint)
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for SyncedDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncedDevice")
            .field("device_fingerprint", &self.device_fingerprint)
            .field("device_name", &self.device_name)
            .field("is_active", &self.is_active)
            .finish_non_exhaustive()
    }
}

/// Serialized form of one contact for cross-device sync (`SyncPayload.contacts`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedContact {
    pub identity_id: String,
    pub display_name: String,
    #[serde(default)]
    pub added_via_group: bool,
    #[serde(default)]
    #[serde(with = "serde_bytes")]
    pub avatar_jpeg: Option<Vec<u8>>,
    pub devices: Vec<SyncedDevice>,
    /// See `DeviceAddProof`: one for each device that is not the contact's first
    /// device.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_proofs: Vec<DeviceAddProof>,
    /// The generation of the user's last pairing with this contact (0 = never,
    /// e.g. added through a group). A sibling whose removal generation is not
    /// newer drops its removed marker and takes the contact again.
    #[serde(default)]
    pub added_at_ms: u64,
}

/// Sync payload. The first connection carries a full copy. It goes to the new
/// device inside `DeviceLinkGrant` (ratchet-encrypted). Later changes are sent to
/// sibling devices again through `MessageContent::DeviceSync`. The merge is
/// idempotent.
#[derive(Clone, Serialize, Deserialize)]
pub struct SyncPayload {
    #[serde(deserialize_with = "bounded::seq_4096")]
    pub contacts: Vec<SyncedContact>,
    /// Serialized `group::Group` records. The receiver adopts them as they are. The
    /// founder's authority is already signed inside the group.
    #[serde(deserialize_with = "bounded::seq_4096")]
    pub groups: Vec<serde_json::Value>,
        /// Other devices of the SAME identity, so that with three or more devices they
        /// learn about each other. The receiver adds them to `known_remote_devices` with
        /// `identity_id` set to its own identity, skipping its own fingerprint.
        /// `#[serde(default)]`, for compatibility with sync payloads that do not have
        /// this field.
    #[serde(default, deserialize_with = "bounded::seq_4096")]
    pub siblings: Vec<SyncedDevice>,
    /// See `DeviceAddProof`: one for each of `siblings` that is not the identity's
    /// first device. A sibling without one is not taken.
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "bounded::seq_4096")]
    pub sibling_proofs: Vec<DeviceAddProof>,
    /// Root archive key (ARK). It decrypts the history stored on the server (see
    /// `server_client::set_archive_root_key` and `server_seal`).
    /// Why it travels here: the ARK belongs to the identity, not to a device. Every
    /// device of the same identity must be able to read the archive on the server.
    /// This payload is already ratchet-encrypted and only goes between sibling devices
    /// (see the `from_sibling` check in the `DeviceSync` arm of `receive_message`). So
    /// no new key-transport mechanism is needed. This is already the point where
    /// long-lived secrets move between devices.
    /// `#[serde(default)]`, for compatibility with older sync payloads.
    #[serde(default)]
    #[serde(with = "serde_bytes")]
    pub archive_root_key: Option<Vec<u8>>,
    /// When the user last changed the account name (ms), stamped by the sending
    /// device. A sync has no order, so the receiver takes the name only from a payload
    /// whose stamp is newer than its own. 0 = a version without the stamp.
    #[serde(default)]
    pub name_changed_at_ms: u64,
    /// Signed revocations of this identity's own devices. A device linked after a
    /// revocation learns about it here and refuses the revoked device's still-valid
    /// `DeviceAdd`. Left out when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "bounded::seq_4096")]
    pub own_revokes: Vec<DeviceRevoke>,
    /// Identities the user blocked on one of this identity's devices. The
    /// receiver blocks them too (only adds: an unblock travels as
    /// `SiblingEchoBody::Blocked`).
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "bounded::seq_4096")]
    pub blocked: Vec<String>,
    /// Groups left, deleted or removed from on the sending device (its
    /// `removed_groups`). The receiver marks those it does not hold, so an old
    /// founder-signed update cannot re-create them there.
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "bounded::seq_4096")]
    pub removed_groups: Vec<String>,
}

/// Top-level packet envelope on the network. The `MessagePacket` header carries the
/// message fields directly. `ratchet_pubkey`, `message_number` and `prev_chain_length`
/// make a real Double Ratchet DH step possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePacketHeader {
    pub sender_identity_id: String,
    pub sender_device_fingerprint: String,
    /// Stable identity of this message (v4 UUID). It does not change with ratchet
    /// rotations. It lets Edit and Delete name the message they target (see
    /// `MessageContent::Edit`/`Delete`). `message_number` resets on a ratchet rotation,
    /// so it cannot serve as a stable identity by itself.
    pub message_id: String,
    /// Current ratchet step public key (hybrid X25519 and ML-KEM, serialized as one
    /// concatenated value).
    #[serde(with = "serde_bytes")]
    pub ratchet_pubkey: Vec<u8>,
    pub message_number: u32,
    pub prev_chain_length: u32,
    /// If set, the sender triggered a DH/KEM rotation with this message. The field
    /// carries the new Kyber ciphertext that the rotation produced. The receiver
    /// decapsulates it and runs `perform_dh_ratchet` on its side too, deriving the same
    /// new keys. See `RatchetPublicKeys` and `perform_dh_ratchet` in ratchet.rs, and
    /// `maybe_rotate_ratchet` in session.rs. If None, this is an ordinary symmetric
    /// chain step with no rotation.
    #[serde(with = "serde_bytes")]
    pub rotation_kyber_ciphertext: Option<Vec<u8>>,
    /// The sender's clock when the packet was made. It is signed with the header, so a
    /// receiver can tell a replayed old packet from one its session should decrypt
    /// (see `note_undecryptable` in session.rs).
    pub sent_at_ms: u64,
}

/// Upper bound on the id strings of a header (identity id, device fingerprint, message id). Real ones are a 64-char
/// hex fingerprint, a UUID or a conversation id; the cap stops a signed header from carrying megabyte keys into
/// the dedup maps and the DB.
pub const MAX_HEADER_ID_LEN: usize = 256;

/// Longest disappearing-message timer (4 weeks).
pub const DISAPPEAR_MAX_SECS: u32 = 4 * 7 * 24 * 3600;

/// How long a received disappearing message that is never opened stays (1 day), or its own timer when that is longer.
pub const DISAPPEAR_UNREAD_SECS: u32 = 24 * 3600;

/// A peer's `expire_secs`, kept only when it is in `1..=DISAPPEAR_MAX_SECS`.
pub fn disappear_secs(v: Option<u32>) -> Option<u32> {
    v.filter(|s| (1..=DISAPPEAR_MAX_SECS).contains(s))
}

/// A `MessagePacketHeader` together with the exact CBOR bytes it travels as. The
/// packet signature and the ratchet AEAD (associated data) cover these bytes and
/// never a re-encoding. A receiver therefore checks what the sender actually made,
/// and acts only on a header that the tag binds to the ciphertext.
#[derive(Debug, Clone)]
pub struct SignedHeader {
    raw: Vec<u8>,
    parsed: MessagePacketHeader,
}

impl SignedHeader {
    pub fn new(header: MessagePacketHeader) -> Result<Self, String> {
        Ok(Self { raw: to_cbor(&header)?, parsed: header })
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

impl std::ops::Deref for SignedHeader {
    type Target = MessagePacketHeader;
    fn deref(&self) -> &MessagePacketHeader {
        &self.parsed
    }
}

impl Serialize for SignedHeader {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.raw)
    }
}

impl<'de> Deserialize<'de> for SignedHeader {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = serde_bytes::ByteBuf::deserialize(deserializer)?.into_vec();
        let mut rest = raw.as_slice();
        let parsed = ciborium::de::from_reader_with_recursion_limit(&mut rest, 4)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        if !rest.is_empty() {
            return Err(serde::de::Error::custom("header: trailing bytes"));
        }
        let header: &MessagePacketHeader = &parsed;
        if [&header.sender_identity_id, &header.sender_device_fingerprint, &header.message_id]
            .iter()
            .any(|field| field.len() > MAX_HEADER_ID_LEN)
        {
            return Err(serde::de::Error::custom("header: id field too long"));
        }
        Ok(Self { raw, parsed })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePacket {
    pub header: SignedHeader,
    /// AEAD (ChaCha20-Poly1305) ciphertext. The nonce is derived from the header
    /// (from `message_number`) and is not carried. After decryption it is CBOR-decoded
    /// as a `MessageContent`.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// Hybrid ML-DSA and Ed25519 signature over the raw header bytes, the ciphertext
    /// and the recipient.
    #[serde(with = "serde_bytes")]
    pub signature_classical: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// One element of `HistorySyncResponse.messages`. See `ArchivedMessage` in types.rs
/// for the local counterpart. The send status is left out: it means nothing to the
/// peer and is sensitive, so it does not travel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedMessage {
    pub direction: String,
    pub text: String,
    pub timestamp: u64,
    /// Set ONLY for group messages. For `direction == "received"` it carries the real
    /// sender (see the `ArchivedMessage.sender_identity_id` note). For "sent" the
    /// sender is the responder itself, which the packet header already tells.
    #[serde(default)]
    pub sender_identity_id: Option<String>,
    /// Lets the receiver skip rows it already has, by message id. Used by
    /// `archive::message_exists_with_id` during an older-page merge
    /// (`before_timestamp.is_some()`).
    #[serde(default)]
    pub message_id: Option<String>,
    /// The sender's send time. Kept in history sync so the receiver can order rows
    /// by SEND time. 0 = unknown (the local archive time is used instead).
    #[serde(default)]
    pub sent_at_ms: u64,
    /// Deleted flag. A receiver that gets the row from scratch (a newly linked
    /// secondary device, or a long backward scroll) archives it as deleted. Versions
    /// without the field read `false` (`#[serde(default)]`).
    #[serde(default)]
    pub is_deleted: bool,
    /// Edited flag. `text` already holds the current edited content (the local archive
    /// is changed in place by `apply_edit_to_archive`). The flag lets the receiver show
    /// the "(edited)" label.
    #[serde(default)]
    pub is_edited: bool,
    /// See `MessageContent::Text.author_proof`. Needed for a group row that the
    /// responder did not write itself.
    #[serde(default)]
    pub author_proof: Option<String>,
    /// Reactions on this row: (reactor identity, emoji, reacted_at_ms).
    #[serde(default, deserialize_with = "bounded::seq_4096")]
    pub reactions: Vec<(String, String, u64)>,
}

/// The real content of `MessagePacket.ciphertext` after decryption. Edit and delete
/// are not a separate packet type or signature flow. They are sent like an ordinary
/// message, with the same ratchet step, so they get the same end-to-end
/// confidentiality and integrity. A relay or node cannot even tell whether a packet is
/// an edit or a new message.
#[derive(Clone, Serialize, Deserialize)]
pub enum MessageContent {
    // The type is recursive (`SiblingEcho` contains `SiblingEchoBody::File.offer`).
    // Parse what a peer sent with `MessageContent::from_cbor`, which bounds the nesting.
    /// `group_id`: if set, this is the pairwise (1:1 ratchet) fan-out copy of a group
    /// message. Without it the receiver cannot tell a group message from an ordinary
    /// 1:1 message (see `receive_message` in receive.rs).
    Text {
        /// Group messages only: the author's signature over the message
        /// (`"<device fingerprint>:<Ed25519 hex>:<ML-DSA hex>"`, see
        /// `group_author_statement` in core). Other members pass it on with the group
        /// history, so a row there cannot be attributed to someone who did not write it.
        #[serde(default)]
        author_proof: Option<String>,
        group_id: Option<String>,
        text: String,
        /// Set only when `group_id` is present. The N pairwise fan-out copies of one
        /// group message each carry a different `MessagePacketHeader.message_id`, since
        /// each has its own ratchet step. This field merges them into one local id. It is
        /// needed for read receipts (see `Seen`). When a recipient sends back "seen", the
        /// sender must know which local bubble that refers to. The per-member message ids
        /// are not known on the sending side. Only the recipient knows the id of its own
        /// copy.
        group_message_local_id: Option<String>,
        /// The sender's local clock (ms, epoch) when the message was written and sent on
        /// its own device. The receiver shows both the local arrival time and the sender's
        /// real send time (for example "10:42 (sent at 10:41)"; see ChatActivity and
        /// SimpleChatAdapter). This value does NOT change when `awaiting_confirmation`
        /// resends the message via `regen_content` (see types.rs). The `MessageContent`
        /// is cloned and encrypted as is, so this field keeps the FIRST write time, which
        /// is the intent. It is not the last retry time. `#[serde(default)]`: old or queued
        /// packets without this field still parse (0 = unknown, and the receiver skips the
        /// bracketed time).
        #[serde(default)]
        sent_at_ms: u64,
        /// Reply target. If this message replies to another, that message's stable id is
        /// here: `MessagePacketHeader.message_id` in 1:1, `group_message_local_id` in groups.
        /// This is the same rule as the `target_message_id` of Edit and Delete (see those).
        /// The receiver looks the id up in its local archive to show the quoted message.
        #[serde(default)]
        reply_to_message_id: Option<String>,
        /// The receiver may never have archived the quoted message locally (it never got
        /// it, or history sync did not run). So the sender also sends a short summary of
        /// that message's text here (see `REPLY_PREVIEW_MAX_CHARS` in the chat screens).
        /// The receiver then does not need to look in its own archive.
        #[serde(default)]
        reply_to_preview: Option<String>,
        /// Meaningful only when `group_id` is present: the `identity_id` of the author of
        /// the quoted message. In 1:1 there is no need, since the peer is the other party.
        /// It lets the receiver show a name such as "reply to Ahmet" in the preview.
        #[serde(default)]
        reply_to_sender_identity_id: Option<String>,
        /// Group messages only: identity ids of the members this message @mentions. The
        /// receiver keeps only current members and marks the row when its own identity id
        /// is listed. The text itself is not parsed.
        #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "bounded::seq_256")]
        mentions: Vec<String>,
        /// Disappearing message: seconds the message stays after it is read. Each device
        /// counts from its OWN read moment on its own clock (the sender's copy from the
        /// send), so delivery delay and clock skew never shorten the viewing time. The
        /// receiver clamps it to `1..=DISAPPEAR_MAX_SECS` (see `disappear_secs`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expire_secs: Option<u32>,
    },
    /// For group messages, `target_message_id` in Reaction, Edit and Delete is the
    /// `Text.group_message_local_id`. The pairwise fan-out copies carry a different
    /// `MessagePacketHeader.message_id` for each member (see the `Text` note), so the
    /// sender can name the target only by this shared local id. Each receiver stores
    /// this value as the `message_id` column of its group archive (see the callers of
    /// `archive_group_message`).
    /// Emoji reaction, long-press on a message.
    /// ONE reaction per person (WhatsApp behavior). A new `Reaction` from the same person
    /// replaces the previous one. An empty `emoji` removes the reaction. So there is no
    /// separate "remove reaction" packet.
    /// `target_message_id`: same rule as `Edit` and `Delete`. In 1:1 it is
    /// `MessagePacketHeader.message_id` (the stable `conv_id`). In groups it is
    /// `Text.group_message_local_id`.
    /// `reacted_at_ms`: same reason as `Edit.edited_at_ms`. The network gives no ordering
    /// guarantee. If two reactions from the same person arrive out of order, the older
    /// one must not overwrite the newer one.
    Reaction {
        target_message_id: String,
        /// Empty string means remove my reaction (see the note above).
        emoji: String,
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        reacted_at_ms: u64,
    },
    Edit {
        target_message_id: String,
        new_text: String,
        #[serde(default)]
        group_id: Option<String>,
        /// As `Text.author_proof`, over the new text.
        #[serde(default)]
        author_proof: Option<String>,
        /// Sender's local time (ms, epoch) when this edit was made. The network gives no
        /// ordering guarantee. Two edits of the same message (for example, a correction
        /// made twice within seconds) can reach the recipient in reverse order. The
        /// recipient compares this stamp with the last stored value, so an older edit
        /// does not overwrite a newer one (see `apply_edit_to_archive` in archive.rs).
        /// Ratchet replay protection already rejects a packet that was replayed from the
        /// network (a consumed message number). This field solves a different problem:
        /// it keeps the final text correct when two legitimate edits from the same sender
        /// arrive out of order. `#[serde(default)]` (0 = unknown): old or queued packets
        /// without this field still parse, and they are applied unconditionally because
        /// there is no order information.
        #[serde(default)]
        edited_at_ms: u64,
    },
    Delete {
        target_message_id: String,
        #[serde(default)]
        group_id: Option<String>,
        /// Group only: the author's signature over the deletion (`GROUP_TOMBSTONE` in
        /// util.rs). Members pass it on with the history.
        #[serde(default)]
        author_proof: Option<String>,
    },
    /// Asks the peer for recent history. A peer with node mode off archives no chat
    /// history (see `archive_message` in archive.rs). With node mode on, the peer has
    /// archived both directions of this conversation, and this request asks that
    /// archive for the last `limit` messages. It travels over the same ratchet-encrypted channel as normal messages, so
    /// no new libp2p connection or protocol is needed, and it stays end to end encrypted.
    HistorySyncRequest {
        limit: u32,
        /// For infinite scroll (older history paging). If set, the requester has run out
        /// of local archive and wants messages OLDER than its oldest loaded one (see
        /// `request_older_history` and `request_older_group_history` in archive.rs). `None`
        /// keeps the existing behavior: on opening the chat, ask for the newest `limit`
        /// messages. Timestamps are each device's own archive time (see the note at
        /// `archive_message`), so this comparison depends on roughly synchronized wall
        /// clocks. Same assumption as the existing sync mechanism.
        #[serde(default)]
        before_timestamp: Option<i64>,
        /// Group history request, if set. The responder then searches the group archive for
        /// this `group_id` instead of its 1:1 archive. Group messages are pairwise fan-out,
        /// so the request can go to any other member. `request_older_group_history` sends it
        /// to every reachable member, and the first to answer fills the gap.
        #[serde(default)]
        group_id: Option<String>,
        /// With `before_timestamp`: the start of the "fetch older history" window
        /// `[after_timestamp, before_timestamp)`, by send time. The responder sends only the
        /// rows inside it.
        #[serde(default)]
        after_timestamp: Option<i64>,
    },
    /// `request_id` is the `MessagePacketHeader.message_id` of the matching
    /// `HistorySyncRequest`. The requester uses it to match this response to its request
    /// and remove the request from the retry queue (`awaiting_confirmation`). `messages` is ordered oldest first. `direction`
    /// is given from the responder's point of view ("sent" or "received"). The requester
    /// must reverse it (see `HistorySyncResponse` in receive.rs `receive_message`).
    HistorySyncResponse {
        request_id: String,
        #[serde(deserialize_with = "bounded::seq_4096")]
        messages: Vec<SyncedMessage>,
        /// See `HistorySyncRequest.group_id`. It mirrors the request, so the response is
        /// merged into the correct local archive (1:1, or which group).
        #[serde(default)]
        group_id: Option<String>,
        /// The responder cut rows from the requested window (row or byte limit). The
        /// requester asks for the older rest of that window.
        #[serde(default)]
        more: bool,
    },
    /// Reliable-delivery ack. A successful local publish only means the packet left this
    /// node, not that the peer received it (see `awaiting_confirmation`). When the recipient
    /// successfully decrypts and processes a `Text` (not group), `Edit`, `Delete` or
    /// `HistorySyncRequest`, it sends this packet back. The sender keeps re-sending the same
    /// packet, without re-encrypting, until it gets this ack. The Ack itself is not
    /// acknowledged, to avoid an endless loop. If it is lost, the sender's retry of the
    /// original packet makes the recipient send a new Ack.
    Ack { target_message_id: String },
    /// File, photo, video or audio attachment metadata. The maximum size is 4 GB. The
    /// packet does not carry the file bytes. It carries small metadata and a fresh AEAD
    /// key for this file (`file_key`), over the normal ratchet-encrypted channel. The
    /// bytes are requested and sent in chunks over a separate libp2p `request_response`
    /// protocol (see `FileChunkRequest` in attachments/mod.rs).
    FileOffer {
        group_id: Option<String>,
        file_id: String,
        file_name: String,
        mime_type: String,
        total_size: u64,
        #[serde(with = "serde_bytes")]
        file_key: [u8; 32],
        sha256_hex: String,
        /// Small JPEG preview cover, made in advance by the sender for photo and video
        /// attachments. It travels in the same
        /// ratchet-encrypted channel as everything else, with no separate message or round
        /// trip, so the receiver can show a preview without downloading the full file. `None`
        /// for other file types, or when no preview could be made. Then only a generic file
        /// icon is shown.
        #[serde(with = "serde_bytes")]
        preview_jpeg: Option<Vec<u8>>,
        /// Playback length in milliseconds, for voice messages. `None` means the length is
        /// unknown or does not apply, for example for an ordinary document.
        duration_ms: Option<u32>,
        /// Caption shown under the attachment bubble. Empty means no caption. It travels in
        /// the same ratchet-encrypted packet. A separate text message would make two bubbles,
        /// their order could change, and the receiver would lose the link between the
        /// attachment and its text.
        #[serde(default)]
        caption: String,
        /// See `Text.reply_to_message_id`. Same meaning, for attachments.
        #[serde(default)]
        reply_to_message_id: Option<String>,
        #[serde(default)]
        reply_to_preview: Option<String>,
        #[serde(default)]
        reply_to_sender_identity_id: Option<String>,
        /// Chunk size of this file, in bytes. New files use `attachments::FILE_CHUNK_SIZE_V2`.
        /// The size must travel with the offer: if the two sides used different steps, the
        /// chunk indices would shift and the file would be corrupted. `None` (an offer from
        /// an older client, `#[serde(default)]`) means `attachments::FILE_CHUNK_SIZE`, 256 KiB.
        #[serde(default)]
        chunk_size: Option<u32>,
        /// The sender's hashes of the encrypted chunks, 32 bytes per entry (see
        /// `attachments::chunk_hashes_of`): SHA-256 over the ciphertext of each group of
        /// `attachments::chunks_per_hash` chunks. Every group member holds `file_key`, so the
        /// chunk AEAD alone does not stop a member from serving forged chunks. This signed
        /// list does, chunk by chunk. An offer whose list has the wrong length is refused.
        #[serde(default, with = "serde_bytes")]
        chunk_hashes: Vec<u8>,
        /// A sticker (JPEG XL, at most 600 px per side). Shown without a bubble frame and
        /// downloaded at once, whatever the node mode.
        #[serde(default)]
        sticker: bool,
        /// Stable sticker identity (`wa:` or `jxl:` plus SHA-256 hex). The receiver reuses a
        /// local copy instead of downloading again.
        #[serde(default)]
        sticker_origin: Option<String>,
        /// See `Text.expire_secs`: a disappearing attachment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expire_secs: Option<u32>,
    },
    /// Typing indicator ("is typing"). It is deliberately not archived, and it does not go
    /// into the retry queue (`awaiting_confirmation`). Retrying an indicator that goes stale
    /// within seconds is pointless. At worst the next keystroke sends a new packet.
    /// `group_id`: for group typing, fanned out via `send_group_typing_indicator`, the same
    /// pattern as Edit and Delete. The event JSON carries `group_id`, so GroupChatActivity
    /// can route it.
    TypingIndicator { is_typing: bool, #[serde(default)] group_id: Option<String> },
    /// Read receipt ("seen"). The same pattern as `Ack` (see `send_seen` and `send_ack` in
    /// send.rs). It travels over the ratchet-encrypted channel, is not acknowledged itself
    /// (to avoid an infinite loop), and is sent once. The reliable path is `ReadStateSync`.
    /// Unlike `Ack`, which means "the packet was decrypted" (delivery), this means "the user
    /// SAW the message on screen". It is not automatic on the receiving side. It fires when
    /// the UI shows the message.
    Seen {
        /// In a 1:1 chat: the real `MessagePacketHeader.message_id` of the seen message. In a
        /// group chat: the id of the receiver's OWN copy. That is meaningless on the sender's
        /// side. See `group_message_local_id`.
        target_message_id: String,
        /// Set ONLY for group messages. See the `Text.group_message_local_id` note. The sender
        /// needs it to find the correct bubble.
        group_message_local_id: Option<String>,
    },
    /// Profile sync: photo and account name. There is no central directory (this is P2P), so
    /// each side sends its profile to every contact that it knows. It does so when a new
    /// pairing completes (see `process_identity_exchange`), and again to all contacts when the
    /// user changes the profile.
    /// This packet is a full snapshot, not a delta. `avatar_jpeg: None` means "the photo was
    /// removed", not "unchanged". So even when `set_display_name` changes only the name, it
    /// also sends the current avatar (and `set_own_profile_picture` sends the current name).
    /// Otherwise a name change would silently delete the photo on the other side.
    ProfileUpdate {
        #[serde(with = "serde_bytes")]
        avatar_jpeg: Option<Vec<u8>>,
        /// The account name, so a change reaches contacts automatically. Without it a contact's
        /// name stays the `device_name` of the first `IdentityExchange`.
        /// `#[serde(default)]`: a packet without this field parses (`None` means "I am
        /// not sending a name", so the receiver keeps its current name). An unknown field in a
        /// packet from a newer version is ignored, because ciborium encodes struct variants as
        /// maps and skips unknown keys.
        #[serde(default)]
        display_name: Option<String>,
    },
    /// Group membership, name and avatar changes. They travel over the ratchet-encrypted
    /// channel (hybrid X25519 and ML-KEM), not as plain envelopes. The inner
    /// `GroupUpdate.signature` and `signature_pq` prove the founder's authority, a second
    /// check independent of the transport layer.
    GroupUpdate(GroupUpdate),
    /// A member (not the founder, see `leave_group` in group_ops.rs) leaves the group on its
    /// own. The permission model stays intact: only the founder changes membership (see the
    /// "NotFounder" check in `validate_group_update`). The leaving member does not sign and
    /// publish a `GroupChange::Remove` itself. It sends this request directly to the founder
    /// over the 1:1 ratchet. When the founder receives it, it runs its own `remove_from_group`,
    /// which already exists and is signed and checked.
    LeaveGroupRequest { group_id: String },
    /// The sender's current best address, sent proactively to every known contact. Without
    /// it, a contact learns a `.onion` address only after a real Tor connection, and on a
    /// shared LAN the direct path is used instead, so a device that switches to mobile
    /// data has no known `.onion` to fall back to. `get_node_address` (network/power.rs)
    /// returns the `.onion` address whenever Tor is open or ready. The packet is sent by
    /// `announce_address_to_all_contacts` (contacts.rs) after `start_network`, when Tor
    /// becomes Ready, and on a network-change notice. The receiver learns the `.onion`
    /// address even if no Tor connection was ever made.
    AddressAnnounce { multiaddr: String },
        /// Multi-device (step 5 of linking, and sync): the approving (existing) device sends
        /// this over the 1:1 ratchet to the new device. `device_add` is the authorization
        /// document the approving device signed. The new device stores it and uses it as
        /// proof when it introduces itself to contacts. `sync` is the first full sync
    /// (contacts and groups). Contact and group data travel over the ratchet-encrypted,
    /// reliably delivered channel.
    DeviceLinkGrant {
        identity_id: String,
        device_add: DeviceAdd,
        sync: SyncPayload,
        /// `DeviceLinkRequest.nonce` of the QR code this grant answers.
        #[serde(default, with = "serde_bytes")]
        nonce: Vec<u8>,
    },
        /// Multi-device (broadcast to contacts): a device was added to this identity. The
        /// receiver verifies `device_add.signature` with the key of a KNOWN active device of
        /// that identity. If valid, it adds the new device (with its full public keys) to both
        /// `known_devices` and `known_remote_devices`. That lets messages fan out to the device
        /// immediately, without waiting for a separate `IdentityExchange`, so routing propagates
        /// even if a contact was offline at pairing time. `device.device_fingerprint` must equal
        /// both `device_add.new_device_fingerprint` and the hash of the keys. The receiver checks both.
    DeviceAddNotice { device_add: DeviceAdd, device: SyncedDevice },
        /// Multi-device: read-state sync between sibling devices. When a chat is read on one
        /// device, the others mark it read too. Otherwise each device would show it unread.
        /// Accepted only if the sender is a device of my own identity.
        /// `conversation_identity_id`: the counterpart's identity for a 1:1 chat. `group_id`:
        /// for a group chat. `read_at_ms`: the read time. Deliberately not queued for reliable
        /// delivery (like Seen and TypingIndicator). It is resent on the next read.
    ReadStateSync {
        #[serde(default)]
        conversation_identity_id: Option<String>,
        #[serde(default)]
        group_id: Option<String>,
        read_at_ms: u64,
    },
        /// Multi-device: signed device revocation, spread to contacts and sibling devices.
        /// The receiver verifies the signature and marks that device `Revoked`.
    DeviceRevokeNotice(DeviceRevoke),
    /// To a group's founder: the sender device's first-contact secret for that group. The
    /// founder forwards it to members in `GroupMemberDevice.first_contact_secret`.
    FirstContactSecret {
        #[serde(with = "serde_bytes")]
        secret: Vec<u8>,
        group_id: String,
    },
    /// To a group's founder: "send me the full group state" (all vouched member devices and
    /// proofs). A `GroupUpdate` carries only the devices new or changed since the founder's
    /// previous update. A member that missed one (version gap, or a member with no known
    /// device) asks for the rest.
    GroupSyncRequest { group_id: String },
        /// Multi-device (delta sync): an existing device resends the current contact and group
        /// state to the OTHER (sibling) devices of its identity, for example after a new contact
        /// is added. The receiver merges idempotently: it never overwrites keys of a known device,
        /// it only adds what is missing. This is the repeatable form of the sync part of
        /// `DeviceLinkGrant`.
    DeviceSync(SyncPayload),
        /// Multi-device: echo of a message, edit or delete I sent, to my sibling devices.
        /// See `SiblingEchoBody`. Accepted only if the sender is a device of my own identity.
    SiblingEcho {
        /// For a 1:1 chat, the counterpart's identity. The receiving sibling maps it to its own
        /// canonical device key. `None` for groups.
        #[serde(default)]
        conversation_identity_id: Option<String>,
        /// The group id for a group chat. `None` for 1:1.
        #[serde(default)]
        group_id: Option<String>,
        body: SiblingEchoBody,
    },
    /// Multi-device: asks a sibling device for recent messages (backfill after a reconnect).
    /// Sent only to a device of my own identity. With no `conversation_identity_id` or
    /// `group_id` it asks for the newest rows of all chats. With one of them it narrows the
    /// request to that chat, and `before_timestamp` asks for messages OLDER than that time
    /// (infinite-scroll paging, same meaning as `HistorySyncRequest`). The optional fields
    /// are `#[serde(default)]`, and `None` for all of them keeps the old behaviour.
    SiblingHistoryRequest {
        per_conversation_limit: u32,
        #[serde(default)]
        conversation_identity_id: Option<String>,
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        before_timestamp: Option<i64>,
        /// Watermark for the unscoped backfill: only rows the responder archived (its
        /// local `timestamp`, ms) at or after this value.
        #[serde(default)]
        since_timestamp: Option<i64>,
        /// Scoped, with `before_timestamp`: the start of the "fetch older history" window
        /// `[after_timestamp, before_timestamp)`.
        #[serde(default)]
        after_timestamp: Option<i64>,
        /// Unscoped backfill: the responder's journal position (`ops_seq` of its last answer)
        /// after which it sends its non-additive sibling operations again. `None`: send none,
        /// only report the current position.
        #[serde(default)]
        ops_since: Option<u64>,
    },
    /// See `SiblingHistoryRequest`. Recent messages from the sibling's archive.
    SiblingHistoryResponse {
        #[serde(deserialize_with = "bounded::seq_4096")]
        entries: Vec<SiblingHistoryEntry>,
        /// The request's window `(before_timestamp, after_timestamp)`, echoed so the requester
        /// can match the response to its open request.
        #[serde(default)]
        window: Option<(i64, i64)>,
        /// Same as `HistorySyncResponse.more`.
        #[serde(default)]
        more: bool,
        /// Unscoped backfill with `since_timestamp`: every row the responder archived in
        /// `[since_timestamp, covered_to)` (its clock) is in this answer. The next request
        /// starts here.
        #[serde(default)]
        covered_to: Option<i64>,
        /// The responder's journal position after the operations it sent again for this
        /// request (see `ops_since`).
        #[serde(default)]
        ops_seq: Option<u64>,
    },
    /// The sender deleted its ACCOUNT (from its last device). Contacts mark the chat as
    /// "account deleted" and stop sending to it. I remove the member from groups I founded.
    /// Sibling devices wipe their local state.
    AccountDeleted {
        #[serde(default)]
        deleted_at_ms: u64,
    },
    /// Voice and video call signalling (see core `call.rs`). Ephemeral, like `TypingIndicator`:
    /// never archived, never acked, never retried. A ring delivered a minute late is worthless,
    /// and the receiver drops stale ones by `sent_at_ms`.
    /// `media_key` and `stream_id` are the SENDER's own media key (32 bytes) and stream id
    /// (8 bytes), carried on `Invite` and `Accept`. They travel inside the ratchet, so the
    /// media streams (which the server may relay) are end-to-end encrypted with keys the
    /// server never sees.
    Call {
        call_id: String,
        action: CallAction,
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        video: bool,
        #[serde(default, with = "serde_bytes")]
        media_key: Vec<u8>,
        #[serde(default, with = "serde_bytes")]
        stream_id: Vec<u8>,
        #[serde(default)]
        sent_at_ms: u64,
        /// Group `Invite` only: the device fingerprints the caller rang. Callees then also
        /// exchange keys with members they think are stale.
        #[serde(default, deserialize_with = "bounded::seq_256")]
        participants: Vec<String>,
    },
    /// Shared whiteboard, one board per 1:1 chat or group. `group_id` or
    /// `conversation_identity_id` names the board the same way `ReadStateSync` names a
    /// conversation: a group id, or (only from my own sibling devices) the contact the 1:1
    /// board belongs to. From a contact, the 1:1 board is simply the sender's.
    /// Live drawing: strokes finished and strokes erased since the last packet. Sent once,
    /// never acked or retried. A lost packet is repaired by `WbDigest`. The author of each
    /// stroke is the packet sender (`WbStroke::author` is ignored here).
    WbOps {
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        conversation_identity_id: Option<String>,
        strokes: Vec<WbStroke>,
        /// 9-byte records: page, then the 8-byte stroke id.
        #[serde(default, with = "serde_bytes")]
        erased: Vec<u8>,
        /// The sender device's signature for each page of `strokes`.
        #[serde(default)]
        sigs: Vec<WbPageSig>,
    },
    /// "This is what my board looks like": pages that hold strokes, each with a stroke count and
    /// a SHA-256 over the page's sorted stroke content hashes. The one reliable whiteboard packet. The receiver pulls the
    /// pages that differ.
    WbDigest {
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        conversation_identity_id: Option<String>,
        pages: Vec<WbPageDigest>,
    },
    /// Asks the sender of a `WbDigest` for whole pages.
    WbPageRequest {
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        conversation_identity_id: Option<String>,
        #[serde(with = "serde_bytes")]
        pages: Vec<u8>,
    },
    /// One whole page. `WbStroke::author` indexes `authors`.
    WbPage {
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        conversation_identity_id: Option<String>,
        page: u8,
        authors: Vec<String>,
        strokes: Vec<WbStroke>,
        /// Erased stroke ids, 8 bytes each.
        #[serde(default, with = "serde_bytes")]
        tombstones: Vec<u8>,
        /// The signature of each device that drew a stroke in `strokes`.
        #[serde(default)]
        sigs: Vec<WbPageSig>,
    },
    /// Asks the sender for a freshly encrypted copy of its pending packet `target_message_id`. Sent when that packet was decrypted
    /// but could not be taken yet (no Ack), or when a copy of it no longer decrypts (its message key is spent). A byte-identical
    /// retry can never decrypt a second time. Not acknowledged, like `Ack`.
    ResendRequest { target_message_id: String },
}

// Debug on these three prints only a name, so keys and message text stay out of logs.
impl std::fmt::Debug for MessageContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

impl std::fmt::Debug for SyncPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncPayload")
    }
}

impl std::fmt::Debug for SiblingEchoBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SiblingEchoBody::Text { .. } => "Text",
            SiblingEchoBody::Edit { .. } => "Edit",
            SiblingEchoBody::Delete { .. } => "Delete",
            SiblingEchoBody::GroupLeft => "GroupLeft",
            SiblingEchoBody::Reaction { .. } => "Reaction",
            SiblingEchoBody::File { .. } => "File",
            SiblingEchoBody::Sticker { .. } => "Sticker",
            SiblingEchoBody::StickerRemoved { .. } => "StickerRemoved",
            SiblingEchoBody::ContactRemoved { .. } => "ContactRemoved",
            SiblingEchoBody::StickersRequest { .. } => "StickersRequest",
            SiblingEchoBody::Blocked { .. } => "Blocked",
            SiblingEchoBody::ContactDeviceRevoked { .. } => "ContactDeviceRevoked",
            SiblingEchoBody::DeviceLeaving => "DeviceLeaving",
        })
    }
}

impl MessageContent {
    /// The variant name, for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Text { .. } => "Text",
            Self::Reaction { .. } => "Reaction",
            Self::Edit { .. } => "Edit",
            Self::Delete { .. } => "Delete",
            Self::HistorySyncRequest { .. } => "HistorySyncRequest",
            Self::HistorySyncResponse { .. } => "HistorySyncResponse",
            Self::Ack { .. } => "Ack",
            Self::FileOffer { .. } => "FileOffer",
            Self::TypingIndicator { .. } => "TypingIndicator",
            Self::Seen { .. } => "Seen",
            Self::ProfileUpdate { .. } => "ProfileUpdate",
            Self::GroupUpdate(_) => "GroupUpdate",
            Self::LeaveGroupRequest { .. } => "LeaveGroupRequest",
            Self::AddressAnnounce { .. } => "AddressAnnounce",
            Self::DeviceLinkGrant { .. } => "DeviceLinkGrant",
            Self::DeviceAddNotice { .. } => "DeviceAddNotice",
            Self::ReadStateSync { .. } => "ReadStateSync",
            Self::DeviceRevokeNotice(_) => "DeviceRevokeNotice",
            Self::FirstContactSecret { .. } => "FirstContactSecret",
            Self::GroupSyncRequest { .. } => "GroupSyncRequest",
            Self::DeviceSync(_) => "DeviceSync",
            Self::SiblingEcho { .. } => "SiblingEcho",
            Self::SiblingHistoryRequest { .. } => "SiblingHistoryRequest",
            Self::SiblingHistoryResponse { .. } => "SiblingHistoryResponse",
            Self::AccountDeleted { .. } => "AccountDeleted",
            Self::Call { .. } => "Call",
            Self::WbOps { .. } => "WbOps",
            Self::WbDigest { .. } => "WbDigest",
            Self::WbPageRequest { .. } => "WbPageRequest",
            Self::WbPage { .. } => "WbPage",
            Self::ResendRequest { .. } => "ResendRequest",
        }
    }

    /// Deepest CBOR nesting accepted in a peer's content. The deepest real case
    /// (`DeviceLinkGrant` -> sync -> group -> founder chain -> signature as a JSON array) needs
    /// about 10 levels.
    const MAX_NESTING: usize = 32;

    /// Parses the decrypted content of a packet. ciborium's own limit (256) would let a contact
    /// nest `SiblingEcho` inside `File.offer` about 60 times. Each level uses several large
    /// visitor frames on the receiving thread's stack, and this happens before any check of who
    /// sent the packet.
    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        let mut rest = data;
        let content = ciborium::de::from_reader_with_recursion_limit(&mut rest, Self::MAX_NESTING).map_err(|e| e.to_string())?;
        if !rest.is_empty() {
            return Err("content: trailing bytes".to_string());
        }
        Ok(content)
    }
}

/// One whiteboard stroke. `points` are little-endian `u16` x,y pairs on the 1600x1000 virtual
/// canvas. The colour is not carried. It follows from the author and `shade` (0 light, 1 base,
/// 2 dark). `width` is the pen width in canvas units. 0 (also what a sender without the field
/// sends) means default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WbStroke {
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    pub page: u8,
    pub shade: u8,
    #[serde(default)]
    pub author: u8,
    #[serde(default)]
    pub width: u8,
    #[serde(with = "serde_bytes")]
    pub points: Vec<u8>,
    /// The device that drew the stroke (raw fingerprint, 32 bytes). Its `WbPageSig` for this page
    /// signs the stroke.
    #[serde(default, with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// One device's hybrid signature (Ed25519 + ML-DSA-87) over every stroke it drew on one page of a
/// board. See `wb_page_statement` in `whiteboard.rs`. A newer one (`at`) replaces the older one
/// for the same device and page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WbPageSig {
    pub page: u8,
    /// Raw device fingerprint, 32 bytes.
    #[serde(with = "serde_bytes")]
    pub device: Vec<u8>,
    /// When it was signed (ms). Increases per device and page.
    pub at: u64,
    /// SHA-256 of each signed stroke, 32 bytes each.
    #[serde(with = "serde_bytes")]
    pub hashes: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig_pq: Vec<u8>,
}

/// See `MessageContent::WbDigest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WbPageDigest {
    pub page: u8,
    pub count: u32,
    pub hash: [u8; 32],
}

/// See `MessageContent::Call`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallAction {
    Invite,
    Accept,
    Reject,
    Hangup,
    Busy,
    /// Sent by the last participant of a group call to every member device: the call is over, drop its "Attend".
    Ended,
    /// To my own other devices only: this device joined the group call. They stop ringing and hide its
    /// "Attend" until this device sends them a Hangup of the call.
    Joined,
}

/// Handshake packet. It carries the hybrid KEM step of the initial handshake. The Kyber
/// ciphertext must reach the peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub sender_identity_id: String,
    pub sender_device_fingerprint: String,
    #[serde(with = "serde_bytes")]
    pub initiator_x25519_pubkey: Vec<u8>,
    /// The Kyber public key the initiator generated for this session. The responder stores it as
    /// the peer's known Kyber public key for the DH/KEM rotation step in ratchet.rs. A ciphertext
    /// alone is not enough: the responder also needs the initiator's public key to trigger its own
    /// rotation.
    #[serde(with = "serde_bytes")]
    pub initiator_kyber_pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kyber_ciphertext: Vec<u8>,
    pub timestamp: u64,
    /// Which of the recipient's keys the initiator encapsulated to: the id of a `SignedPrekey`, or
    /// 0 for the device's long-term KEM keys (no prekey of the recipient was known). Signed with
    /// the rest.
    #[serde(default)]
    pub recipient_prekey_id: u64,
    /// The sender's current prekey, so the recipient can use it for the next handshake in the
    /// other direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_prekey: Option<SignedPrekey>,
    #[serde(with = "serde_bytes")]
    pub signature_classical: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// QR and manual pairing carry only the fingerprint. The connection specification says the
/// peer's real public keys are downloaded when the connection is made and compared with this
/// `fingerprint`. So once the connection is made, each side sends its real public keys and
/// checks them against the fingerprint itself. This packet carries that step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityExchange {
    pub identity_id: String,
    pub device_fingerprint: String,
    pub device_name: String,
    #[serde(with = "serde_bytes")]
    pub sign_pubkey_ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sign_pubkey_mldsa: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kem_pubkey_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kem_pubkey_mlkem: Vec<u8>,
    /// Signed `DeviceAdd` from the primary device, authorizing this device as a SECONDARY
    /// device. Without it, the receiver blocks packets from the unknown device and shows
    /// `UnverifiedNewDeviceAlert`. The silent-accept path (`NewDeviceViaSignedAdd`) needs
    /// the `verified_device_adds` entry, which a separate `DeviceAddNotice` sets. That
    /// notice is an ordinary ratchet message, so an offline contact may get it late.
    /// Carrying the signature here lets the receiver verify it against the primary's
    /// key at once. The checks are those of `apply_device_add_notice` (`verify_device_auth`,
    /// fingerprint and key consistency). An unsigned claim is still rejected.
    #[serde(default)]
    pub device_add: Option<DeviceAdd>,
    /// The signed `DeviceRevoke`s of this identity, so a contact who pairs later also
    /// learns that a device is revoked. Left out when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "bounded::seq_4096")]
    pub revokes: Vec<DeviceRevoke>,
    /// The public keys of the device that signed `device_add`. `identity_id`
    /// is the fingerprint of the identity's first device, so when that device
    /// signed the add, these keys prove the claim to someone who knows
    /// neither device: they hash to `identity_id` and verify the signature.
    /// Without it `identity_id` is only a claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_add_signer: Option<SyncedDevice>,
    /// `pairing_nonce_proof` of the code this device read from the receiver
    /// (pairing code, or link code when the first device answers it). Signed.
    /// A stranger becomes a contact only with it.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "serde_bytes")]
    pub pairing_proof: Vec<u8>,
    /// A device that shows its link code, to the first device that proved it
    /// read the code: this device's half of the `DeviceAdd` (`consent`,
    /// `consent_pq`). Checks against this device's keys; also covered by the
    /// packet signature (`identity_exchange_extras_digest`).
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "serde_bytes")]
    pub link_consent: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "serde_bytes")]
    pub link_consent_pq: Vec<u8>,
    /// This device's current prekey (see `SignedPrekey`). Carries its own
    /// signature; also covered by `identity_exchange_extras_digest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prekey: Option<SignedPrekey>,
    /// Sender's clock (ms) when made. Signed with the recipient's device
    /// fingerprint: a captured packet replays to no other device and
    /// only inside the receiver's freshness window.
    pub timestamp: u64,
    /// Hybrid signature of this device over `identity_exchange_signing_input`.
    /// The fingerprint only says the four keys belong together: without this,
    /// whoever carried the packet (it travels unsealed) could change
    /// `device_name` or `identity_id`, or send the keys of a device it does
    /// not hold. A receiver refuses a packet without it.
    #[serde(default, with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// A short-lived KEM key pair of a device, signed with its long-term signing
/// keys. A handshake encapsulates to it instead of the long-term KEM keys;
/// the device deletes the secret half some weeks after it stops handing the
/// public half out. What an initiator sent before the first reply can then
/// no longer be opened with keys taken from the device later.
/// `id` is the creation time in ms on the owner's clock: unique per device
/// and larger for a newer key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekey {
    pub id: u64,
    #[serde(with = "serde_bytes")]
    pub kem_pubkey_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kem_pubkey_mlkem: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// What the owner of a `SignedPrekey` signs.
pub fn prekey_signing_input(device_fingerprint: &str, id: u64, kem_pubkey_x25519: &[u8], kem_pubkey_mlkem: &[u8]) -> Vec<u8> {
    let mut out = b"p2pmsg-v0.4-prekey".to_vec();
    for field in [device_fingerprint.as_bytes(), kem_pubkey_x25519, kem_pubkey_mlkem] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&id.to_be_bytes());
    out
}

/// The bytes `IdentityExchange.signature` covers. The keys are covered through
/// `device_fingerprint`, and `device_add` and `device_add_signer` prove themselves.
/// `recipient_fp` is the device the packet is for (not carried: the receiver uses its
/// own). `revokes` is covered through `revokes_digest`, so the list cannot be stripped
/// in transit. `extras` is `identity_exchange_extras_digest`, for the same reason.
pub fn identity_exchange_signing_input(
    identity_id: &str,
    device_fingerprint: &str,
    device_name: &str,
    pairing_proof: &[u8],
    recipient_fp: &str,
    timestamp: u64,
    revokes: &[DeviceRevoke],
    extras: &[u8; 32],
) -> Vec<u8> {
    let mut out = b"p2pmsg-v0.7-identity-exchange".to_vec();
    let digest = revokes_digest(revokes);
    for field in [identity_id.as_bytes(), device_fingerprint.as_bytes(), device_name.as_bytes(), pairing_proof, recipient_fp.as_bytes(), &digest[..], &extras[..]] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
}

/// SHA-256 over the CBOR of the fields that prove themselves (`device_add`,
/// `device_add_signer`, `link_consent`, `link_consent_pq`, `prekey`), for
/// `identity_exchange_signing_input`: unsigned, a relay could strip them or
/// put an older self-signed prekey in.
pub fn identity_exchange_extras_digest(ix: &IdentityExchange) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut buf = Vec::new();
    // Serializing plain values into a Vec does not fail.
    let _ = ciborium::into_writer(&(&ix.device_add, &ix.device_add_signer, &ix.link_consent, &ix.link_consent_pq, &ix.prekey), &mut buf);
    let mut h = Sha256::new();
    h.update(b"p2pmsg-ix-extras-v1");
    h.update(&buf);
    h.finalize().into()
}

/// SHA-256 over every field of each revoke, length-prefixed, in list order.
pub fn revokes_digest(revokes: &[DeviceRevoke]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"p2pmsg-revokes-v1");
    h.update((revokes.len() as u32).to_be_bytes());
    for r in revokes {
        for field in [r.identity_id.as_bytes(), r.revoked_device_fingerprint.as_bytes(), r.revoked_by.as_bytes(), &r.signature[..], &r.signature_pq[..]] {
            h.update((field.len() as u32).to_be_bytes());
            h.update(field);
        }
    }
    h.finalize().into()
}

/// Multi-device (message history sync): an echo of a message or action I SENT, to my sibling
/// devices, so an edit or delete made on one device shows on the others too. Received messages
/// already reach every device through fan-out, so echoes are only for my own outgoing actions.
#[derive(Clone, Serialize, Deserialize)]
pub enum SiblingEchoBody {
    Text {
        /// 1:1: `MessagePacketHeader.message_id` (the id of the copy sent to the contact's canonical
        /// device). Group: `group_message_local_id`. My own edits and deletes apply to the same target
        /// on all my devices.
        message_id: String,
        text: String,
        sent_at_ms: u64,
        #[serde(default)]
        reply_to_message_id: Option<String>,
        #[serde(default)]
        reply_to_preview: Option<String>,
        #[serde(default)]
        reply_to_sender_identity_id: Option<String>,
        /// See `MessageContent::Text.expire_secs`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expire_secs: Option<u32>,
    },
    Edit { target_message_id: String, new_text: String, #[serde(default)] edited_at_ms: u64 },
    Delete { target_message_id: String },
    /// This identity left the group (`group_id` of the echo): the sibling
    /// drops it too, without waiting for the founder's update.
    GroupLeft,
    /// See `MessageContent::Reaction`. A reaction I removed, echoed so my other devices show it too.
    Reaction { target_message_id: String, emoji: String, #[serde(default)] reacted_at_ms: u64 },
    /// An attachment I sent (1:1 or group). `offer` is always a `MessageContent::FileOffer`, and the
    /// sibling downloads the file from me with that offer.
    File { offer: Box<MessageContent> },
    /// A sticker added to my sticker store (imported or saved): the JPEG XL bytes. Its id is the
    /// SHA-256 of those bytes. A large sticker travels in several parts (`part` of `parts`, both 0 for
    /// a single piece). `id` (SHA-256 hex of the whole file) names the parts.
    Sticker {
        #[serde(with = "serde_bytes")]
        jxl: Vec<u8>,
        #[serde(default)]
        origin: Option<String>,
        #[serde(default)]
        id: String,
        #[serde(default)]
        part: u8,
        #[serde(default)]
        parts: u8,
    },
    /// Stickers removed from my sticker store (one echo for a multi-select delete).
    StickerRemoved { #[serde(deserialize_with = "bounded::seq_4096")] ids: Vec<String> },
    /// The user deleted this contact (by identity) on one of my devices, with
    /// removal generation `removed_at_ms`. A sibling whose pairing generation is not older keeps it.
    ContactRemoved { identity_id: String, removed_at_ms: u64 },
    /// "Send me your whole sticker store". A linked desktop asks. Only the root device answers, with one
    /// `Sticker` per id that is not in `have`.
    StickersRequest { #[serde(default, deserialize_with = "bounded::seq_16384")] have: Vec<String> },
    /// The user blocked (`blocked`) or unblocked this identity on one of my devices.
    Blocked { identity_id: String, blocked: bool },
    /// The user revoked this contact device, or rejected its "new device" alert, on one of my devices.
    ContactDeviceRevoked { identity_id: String, device_fingerprint: String },
    /// The sending linked device is logging out and erasing itself. The root
    /// revokes exactly that device (the authenticated sender); others ignore it.
    DeviceLeaving,
}

/// Multi-device (history backfill from a sibling): while a device was offline it may have
/// missed messages from contacts (a fan-out copy timed out). On reconnect it asks a sibling
/// device for the last N messages, and the sibling sends them from its archive. Duplicates are
/// dropped by the stable `message_id` (1:1 `conv_id`, group `local_id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiblingHistoryEntry {
    /// For a 1:1 chat, the counterpart's identity. The receiver maps it to its own canonical device.
    /// `None` for groups.
    #[serde(default)]
    pub conversation_identity_id: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    pub direction: String,  // "sent" or "received"
    pub text: String,
    pub message_id: String,
    #[serde(default)]
    pub sender_identity_id: Option<String>,
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
    #[serde(default)]
    pub reply_to_preview: Option<String>,
    #[serde(default)]
    pub reply_to_sender_identity_id: Option<String>,
    /// Send time. Backfilled messages are also ordered by SEND time.
    #[serde(default)]
    pub sent_at_ms: u64,
    /// See `MessageContent::Text.author_proof`.
    #[serde(default)]
    pub author_proof: Option<String>,
    /// An attachment row instead of a text row: always a `MessageContent::FileOffer` (its `file_id` is
    /// `message_id`). The receiver downloads the file from the sibling that sent it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<Box<MessageContent>>,
    /// Reactions on the message: (reactor identity, emoji, reacted_at_ms). An empty emoji is a removal,
    /// kept for its timestamp.
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "bounded::seq_4096")]
    pub reactions: Vec<(String, String, u64)>,
}

/// Envelope for everything received from the network. The variant tells the packet kinds
/// apart. Device add and revoke, group invites and read receipts are not envelope kinds:
/// they are `MessageContent` variants (`DeviceAddNotice`, `DeviceRevokeNotice`,
/// `GroupUpdate(Add)`, `Seen`, `ReadStateSync`) over the ratchet-encrypted channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEnvelope {
    IdentityExchange(IdentityExchange),
    Handshake(HandshakeInit),
    Message(MessagePacket),
}

impl NetworkEnvelope {
    /// Nesting bound for the outer envelope, checked before any signature check.
    const MAX_NESTING: usize = 32;

    /// Strict parse of a received envelope. Trailing bytes would give one signed packet unlimited
    /// encodings (each passes the byte dedup). ciborium's default would let a stranger nest 256 levels.
    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        let mut rest = data;
        let envelope = ciborium::de::from_reader_with_recursion_limit(&mut rest, Self::MAX_NESTING).map_err(|e| e.to_string())?;
        if !rest.is_empty() {
            return Err("envelope: trailing bytes".to_string());
        }
        Ok(envelope)
    }
}

#[cfg(test)]
mod wire_size_tests {
    use super::*;

    /// Byte fields must be encoded as CBOR byte strings. Without `serde_bytes` every byte becomes a
    /// separate integer, and the packet grows about 1.9x.
    #[test]
    fn byte_fields_encode_as_cbor_bytes() {
        let raw: Vec<u8> = (0..=255u8).cycle().take(4000).collect();
        let packet = MessagePacket {
            header: SignedHeader::new(MessagePacketHeader {
                sender_identity_id: String::new(),
                sender_device_fingerprint: String::new(),
                message_id: String::new(),
                ratchet_pubkey: raw.clone(),
                message_number: 0,
                prev_chain_length: 0,
                rotation_kyber_ciphertext: None,
                sent_at_ms: 0,
            }).unwrap(),
            ciphertext: raw.clone(),
            signature_classical: Vec::new(),
            signature_pq: raw.clone(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&NetworkEnvelope::Message(packet.clone()), &mut buf).unwrap();
        assert!(buf.len() < 3 * raw.len() + 512, "packet {} bytes", buf.len());
        let back: NetworkEnvelope = ciborium::from_reader(buf.as_slice()).unwrap();
        match back {
            NetworkEnvelope::Message(m) => {
                assert_eq!(m.ciphertext, raw);
                assert_eq!(m.header.raw(), packet.header.raw());
                assert_eq!(m.header.ratchet_pubkey, raw);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn header_with_oversized_id_is_refused() {
        let header = |message_id: String| MessagePacketHeader {
            sender_identity_id: String::new(),
            sender_device_fingerprint: String::new(),
            message_id,
            ratchet_pubkey: Vec::new(),
            message_number: 0,
            prev_chain_length: 0,
            rotation_kyber_ciphertext: None,
            sent_at_ms: 0,
        };
        let roundtrip = |id: String| {
            let mut buf = Vec::new();
            ciborium::into_writer(&SignedHeader::new(header(id)).unwrap(), &mut buf).unwrap();
            ciborium::from_reader::<SignedHeader, _>(buf.as_slice())
        };
        assert!(roundtrip("m".repeat(MAX_HEADER_ID_LEN)).is_ok());
        assert!(roundtrip("m".repeat(MAX_HEADER_ID_LEN + 1)).is_err());
    }
}

#[cfg(test)]
mod parse_limit_tests {
    use super::*;

    fn qr(version: u8) -> Vec<u8> {
        QrPacket {
            version,
            device_name: "d".into(),
            identity_id: "i".into(),
            device_fingerprint: "f".into(),
            rendezvous_node: "/dns/x.onion/tcp/1".into(),
            known_relays: Vec::new(),
            pairing_nonce: vec![7; 16],
        }.to_cbor().unwrap()
    }

    #[test]
    fn pairing_codes_of_another_version_are_refused() {
        assert!(QrPacket::from_cbor(&qr(2)).is_err(), "a code without a nonce");
        assert!(QrPacket::from_cbor(&qr(QrPacket::CURRENT_VERSION)).is_ok());
        assert!(QrPacket::from_cbor(&qr(QrPacket::CURRENT_VERSION + 1)).unwrap_err().contains("update the app"));
        assert!(QrPacket::from_cbor(&qr(0)).is_err());

        let link = |version| DeviceLinkRequest {
            version, device_name: "d".into(), device_fingerprint: "f".into(),
            rendezvous_node: "/dns/x.onion/tcp/1".into(), known_relays: Vec::new(), nonce: vec![7; 16],
        }.to_cbor().unwrap();
        assert!(DeviceLinkRequest::from_cbor(&link(DeviceLinkRequest::CURRENT_VERSION)).is_ok());
        // Neither encoding reads as the other.
        assert!(DeviceLinkRequest::from_cbor(&qr(DeviceLinkRequest::CURRENT_VERSION)).is_err());
        assert!(QrPacket::from_cbor(&link(QrPacket::CURRENT_VERSION)).is_err());
        assert!(DeviceLinkRequest::from_cbor(&link(1)).is_err());
        assert!(DeviceLinkRequest::from_cbor(&link(DeviceLinkRequest::CURRENT_VERSION + 1)).is_err());

        let mut huge = QrPacket::from_cbor(&qr(QrPacket::CURRENT_VERSION)).unwrap();
        huge.known_relays = vec!["/dns/relay.onion/tcp/1".repeat(10); 40];
        assert!(QrPacket::from_cbor(&huge.to_cbor().unwrap()).is_err());
    }

    #[test]
    fn nested_sibling_echo_is_refused_before_it_is_deep() {
        let offer = MessageContent::FileOffer {
            group_id: None, file_id: "f".into(), file_name: "n".into(), mime_type: "m".into(), total_size: 1,
            file_key: [0; 32], sha256_hex: String::new(), preview_jpeg: None, duration_ms: None,
            caption: String::new(), reply_to_message_id: None, reply_to_preview: None,
            reply_to_sender_identity_id: None, chunk_size: None, chunk_hashes: Vec::new(), sticker: false, sticker_origin: None, expire_secs: None,
        };
        let echo = |inner| MessageContent::SiblingEcho {
            conversation_identity_id: None, group_id: None,
            body: SiblingEchoBody::File { offer: Box::new(inner) },
        };
        let bytes = |content: &MessageContent| to_cbor(content).unwrap();
        // What a sibling actually sends.
        assert!(MessageContent::from_cbor(&bytes(&echo(offer.clone()))).is_ok());
        // The deepest realistic content: a link grant with proofs and a group (more JSON nesting
        // than `group::Group` has).
        let add = DeviceAdd {
            identity_id: "i".into(), new_device_fingerprint: "f".into(), added_by: "a".into(),
            signature: vec![1], signature_pq: vec![2], consent: vec![3], consent_pq: vec![4],
        };
        let device = SyncedDevice {
            device_fingerprint: "f".into(), device_name: "d".into(), sign_pubkey_ed25519: vec![1],
            sign_pubkey_mldsa: vec![2], kem_pubkey_x25519: vec![3], kem_pubkey_mlkem: vec![4],
            is_active: true, last_addr: None, mailbox_secrets: Vec::new(),
        };
        let grant = MessageContent::DeviceLinkGrant {
            nonce: vec![7; 16],
            identity_id: "i".into(),
            device_add: add.clone(),
            sync: SyncPayload {
                contacts: vec![SyncedContact {
                    identity_id: "c".into(), display_name: "n".into(), added_via_group: false, avatar_jpeg: None,
                    devices: vec![device.clone()],
                    device_proofs: vec![DeviceAddProof { device_add: add, signer: device.clone() }],
                    added_at_ms: 0,
                }],
                groups: vec![serde_json::json!({"founder_chain": [{"signature": [1, 2], "x": {"y": {"z": [[1]]}}}]})],
                siblings: vec![device],
                sibling_proofs: Vec::new(),
                archive_root_key: Some(vec![0; 32]),
                name_changed_at_ms: 0,
                own_revokes: Vec::new(),
                blocked: Vec::new(),
                removed_groups: Vec::new(),
            },
        };
        assert!(MessageContent::from_cbor(&bytes(&grant)).is_ok());
        let mut nested = offer;
        for _ in 0..40 {
            nested = echo(nested);
        }
        assert!(MessageContent::from_cbor(&bytes(&nested)).is_err());
    }

    #[test]
    fn content_with_trailing_bytes_is_refused() {
        let mut data = to_cbor(&MessageContent::Ack { target_message_id: "m".into() }).unwrap();
        assert!(MessageContent::from_cbor(&data).is_ok());
        data.push(0);
        assert!(MessageContent::from_cbor(&data).is_err());
    }
}

#[cfg(test)]
mod signing_input_tests {
    use super::*;

    /// Changing any one field changes the signed bytes, and moving bytes across a field boundary does too.
    fn all_distinct(inputs: Vec<Vec<u8>>) {
        for (i, a) in inputs.iter().enumerate() {
            for b in &inputs[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    fn revoke(sig: &[u8]) -> DeviceRevoke {
        DeviceRevoke { identity_id: "id".into(), revoked_device_fingerprint: "fp".into(), revoked_by: "by".into(), signature: sig.to_vec(), signature_pq: vec![1] }
    }

    #[test]
    fn signing_inputs_bind_every_field() {
        all_distinct(vec![
            pairing_nonce_proof(b"ab", "c"), pairing_nonce_proof(b"a", "bc"),
            pairing_nonce_proof(b"ab", "d"), pairing_nonce_proof(b"ax", "c"),
        ]);
        all_distinct(vec![
            founder_transfer_signing_input("g", 1, "a", "b"), founder_transfer_signing_input("g", 2, "a", "b"),
            founder_transfer_signing_input("h", 1, "a", "b"), founder_transfer_signing_input("g", 1, "x", "b"),
            founder_transfer_signing_input("g", 1, "a", "x"), founder_transfer_signing_input("g", 1, "ab", ""),
        ]);
        all_distinct(vec![
            prekey_signing_input("fp", 1, b"x", b"m"), prekey_signing_input("fp", 2, b"x", b"m"),
            prekey_signing_input("fq", 1, b"x", b"m"), prekey_signing_input("fp", 1, b"y", b"m"),
            prekey_signing_input("fp", 1, b"x", b"n"), prekey_signing_input("fp", 1, b"xm", b""),
        ]);
        let r = [revoke(b"s")];
        all_distinct(vec![
            identity_exchange_signing_input("i", "d", "n", b"p", "r", 1, &r, &[0; 32]),
            identity_exchange_signing_input("j", "d", "n", b"p", "r", 1, &r, &[0; 32]),
            identity_exchange_signing_input("i", "e", "n", b"p", "r", 1, &r, &[0; 32]),
            identity_exchange_signing_input("i", "d", "o", b"p", "r", 1, &r, &[0; 32]),
            identity_exchange_signing_input("i", "d", "n", b"q", "r", 1, &r, &[0; 32]),
            identity_exchange_signing_input("i", "d", "n", b"p", "s", 1, &r, &[0; 32]),
            identity_exchange_signing_input("i", "d", "n", b"p", "r", 2, &r, &[0; 32]),
            identity_exchange_signing_input("i", "d", "n", b"p", "r", 1, &[], &[0; 32]),
            identity_exchange_signing_input("i", "d", "n", b"p", "r", 1, &[revoke(b"t")], &[0; 32]),
            identity_exchange_signing_input("i", "d", "n", b"p", "r", 1, &r, &[1; 32]),
            identity_exchange_signing_input("id", "", "n", b"p", "r", 1, &r, &[0; 32]),
        ]);
        assert_ne!(revokes_digest(&[revoke(b"s")]), revokes_digest(&[revoke(b"s"), revoke(b"s")]));
    }

    /// A removed photo travels as `avatar_jpeg: None` and must decode as None, not fail.
    #[test]
    fn profile_update_without_photo_round_trips() {
        for avatar in [None, Some(vec![1u8, 2, 3])] {
            let content = MessageContent::ProfileUpdate { avatar_jpeg: avatar.clone(), display_name: Some("n".into()) };
            let mut bytes = Vec::new();
            ciborium::into_writer(&content, &mut bytes).unwrap();
            match MessageContent::from_cbor(&bytes).unwrap() {
                MessageContent::ProfileUpdate { avatar_jpeg, .. } => assert_eq!(avatar_jpeg, avatar),
                _ => panic!("wrong variant"),
            }
        }
    }

    /// Peer-filled collections stop at their limit while decoding.
    #[test]
    fn collection_counts_are_bounded() {
        let text = |n: usize| MessageContent::Text {
            group_id: Some("g".into()), text: String::new(), group_message_local_id: None, sent_at_ms: 0,
            reply_to_message_id: None, reply_to_preview: None, reply_to_sender_identity_id: None, author_proof: None,
            mentions: vec![String::new(); n], expire_secs: None,
        };
        assert!(MessageContent::from_cbor(&to_cbor(&text(256)).unwrap()).is_ok());
        assert!(MessageContent::from_cbor(&to_cbor(&text(257)).unwrap()).is_err());
    }
}
