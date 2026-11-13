//! Group messaging: membership state and authority checks.
//!
//! Design decision: pairwise, NOT Sender Keys. When a group message is sent, it is encrypted separately for each member with that member's
//! existing 1:1 Double Ratchet session. This module holds the group MEMBERSHIP state and the authority checks. The actual encryption uses the
//! existing 1:1 sessions in `ratchet.rs` (see `send_group_message` in group_ops.rs).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub identity_id: String,
    pub added_at: u64,
    /// Must always be the founder_identity_id. Verified in `apply_update`.
    pub added_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub group_id: String,
    pub name: String,
    pub founder_identity_id: String,
    pub members: Vec<GroupMember>,
    pub created_at: u64,
    /// Increases every time the membership list changes. Used to reject old or repeated `GroupUpdate` packets.
    pub version: u32,
    /// The group profile photo. It changes ONLY through `GroupChange::AvatarUpdate`, so only the founder can change it.
    #[serde(default)]
    pub avatar_jpeg: Option<Vec<u8>>,
    /// The known founder transfers for this group. See `packet::FounderTransfer` for why they are needed. Every `GroupUpdate` the founder sends
    /// carries them. A member who missed a transfer catches up by walking the chain, which advances the local founder. That member is not
    /// permanently cut off from the group.
    #[serde(default)]
    pub founder_chain: Vec<crate::packet::FounderTransfer>,
}

/// Maximum number of entries kept in the founder transfer chain.
///
/// Each entry carries an ML-DSA-87 signature (about 4.6 KB), and the chain travels with EVERY group update. Leaving it unbounded would use up
/// gossipsub's 1 MB packet limit. 8 transfers are more than enough in practice. ACCEPTED LIMIT: a member who misses ALL of more than 8 consecutive
/// transfers cannot repair itself and must be invited to the group again.
pub const MAX_FOUNDER_CHAIN: usize = 8;

impl Group {
    pub fn new(group_id: String, name: String, founder_identity_id: String, now: u64) -> Self {
        Group {
            group_id,
            name,
            founder_identity_id: founder_identity_id.clone(),
            members: vec![GroupMember {
                identity_id: founder_identity_id.clone(),
                added_at: now,
                added_by: founder_identity_id,
            }],
            created_at: now,
            version: 0,
            avatar_jpeg: None,
            founder_chain: Vec::new(),
        }
    }

    /// Adds a new transfer to the chain (removing duplicates) and keeps the last `MAX_FOUNDER_CHAIN` entries. See the note on that constant.
    pub fn push_founder_transfer(&mut self, transfer: crate::packet::FounderTransfer) {
        if self.founder_chain.iter().any(|t| {
            t.version == transfer.version && t.from_identity == transfer.from_identity && t.to_identity == transfer.to_identity
        }) {
            return;
        }
        self.founder_chain.push(transfer);
        self.founder_chain.sort_by_key(|t| t.version);
        if self.founder_chain.len() > MAX_FOUNDER_CHAIN {
            let drop = self.founder_chain.len() - MAX_FOUNDER_CHAIN;
            self.founder_chain.drain(0..drop);
        }
    }

    pub fn is_member(&self, identity_id: &str) -> bool {
        self.members.iter().any(|m| m.identity_id == identity_id)
    }

    pub fn member_identity_ids(&self) -> Vec<String> {
        self.members.iter().map(|m| m.identity_id.clone()).collect()
    }

    /// Sets the member list to the AUTHORITATIVE list from the founder (see `GroupUpdate.members`). The `added_at` of existing members is kept
    /// (so there is no needless change). Members not in the list are removed and new ones are added. This does two things: a member who joins
    /// late gets the FULL membership, and missed updates correct themselves.
    pub fn sync_members(&mut self, identity_ids: &[String], now: u64) {
        let founder = self.founder_identity_id.clone();
        let wanted: std::collections::HashSet<&String> = identity_ids.iter().collect();
        // The founder stays, as in `apply_change(Remove)`.
        self.members.retain(|m| wanted.contains(&m.identity_id) || m.identity_id == founder);
        let mut have: std::collections::HashSet<String> = self.members.iter().map(|m| m.identity_id.clone()).collect();
        for id in identity_ids {
            if have.insert(id.clone()) {
                self.members.push(GroupMember {
                    identity_id: id.clone(),
                    added_at: now,
                    added_by: founder.clone(),
                });
            }
        }
    }

    /// All other members (the send target list), excluding ourselves.
    pub fn other_members(&self, exclude_identity_id: &str) -> Vec<String> {
        self.members
            .iter()
            .map(|m| m.identity_id.clone())
            .filter(|id| id != exclude_identity_id)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupUpdateError {
    /// signed_by does not match founder_identity_id. Only the founder can add or remove members.
    NotFounder,
    /// signed_by_device is not a known, ACTIVE device of the founder.
    UnknownOrRevokedSignerDevice,
    /// new_version must be GREATER than the current version. The old rule required `== version + 1`, but that PERMANENTLY locked out a member
    /// who missed a single update (for example during a network outage): every later update was rejected as "out of order", and the member could
    /// never catch up. Now forward jumps (gaps) are allowed. Only stale or repeated versions (`<= version`) are rejected. When a gap is detected,
    /// the caller logs a warning (see `process_group_update` in group_ops.rs).
    StaleOrOutOfOrderVersion,
    /// new_version is implausibly far ahead. One accepted update at
    /// `u32::MAX` would freeze the group for good: nothing can follow it.
    VersionTooFarAhead,
}

/// Largest forward gap one update may make (missed updates are allowed).
/// 4096: at 2^20 a founder reached `u32::MAX` in 4096 updates.
pub const MAX_VERSION_JUMP: u32 = 1 << 12;

/// The type of change to apply. The canonical definition is `packet::GroupChange` (the network packet format, the `GroupUpdate.change` field).
/// It is re-exported here instead of defined as a second enum with the same name. Otherwise `packet::GroupChange` and `group::GroupChange` would be two
/// different types with the same name, and callers could mix them up by mistake (a type error).
pub use crate::packet::GroupChange;

/// The receiver rejects a `GroupUpdate` if `signed_by != founder_identity_id` [...]. Whether `signed_by_device` is a known, ACTIVE
/// device of the founder is checked separately.
///
/// `is_signer_device_active_for_identity`: the caller (group_ops.rs) determines whether this device_fingerprint really is an ACTIVE device of the
/// `signed_by` identity, by looking at the Contact / known_devices table. This module has no access to crypto or network state, so it takes the
/// result as a parameter.
pub fn validate_group_update(
    group: &Group,
    signed_by_identity: &str,
    signed_by_device_is_active: bool,
    new_version: u32,
) -> Result<(), GroupUpdateError> {
    if signed_by_identity != group.founder_identity_id {
        return Err(GroupUpdateError::NotFounder);
    }
    if !signed_by_device_is_active {
        return Err(GroupUpdateError::UnknownOrRevokedSignerDevice);
    }
    // Forward jumps are allowed (see the `StaleOrOutOfOrderVersion` note). Only stale or repeated versions (equal to or below the current one) are rejected.
    if new_version <= group.version {
        return Err(GroupUpdateError::StaleOrOutOfOrderVersion);
    }
    if new_version > group.version.saturating_add(MAX_VERSION_JUMP) {
        return Err(GroupUpdateError::VersionTooFarAhead);
    }
    Ok(())
}

/// Applies a verified `GroupChange` to the group. Signature verification must already have been done separately, by `validate_group_update`,
/// before this function is called.
pub fn apply_change(group: &mut Group, change: &GroupChange, new_version: u32, now: u64) {
    match change {
        GroupChange::Add(identity_id) => {
            // `added_at` is when the latest add reached us: a member removed
            // and added again (even when we missed the removal) starts over.
            // It limits the group history this member may get from us.
            match group.members.iter_mut().find(|m| m.identity_id == *identity_id) {
                Some(m) => m.added_at = now,
                None => group.members.push(GroupMember {
                    identity_id: identity_id.clone(),
                    added_at: now,
                    added_by: group.founder_identity_id.clone(),
                }),
            }
        }
        GroupChange::Remove(identity_id) => {
            // The founder stays a member: removed, its updates still validated
            // while its messages failed the membership check.
            if *identity_id != group.founder_identity_id {
                group.members.retain(|m| m.identity_id != *identity_id);
            }
        }
        GroupChange::Rename(new_name) => {
            group.name = new_name.clone();
        }
        GroupChange::AvatarUpdate(avatar) => {
            group.avatar_jpeg = avatar.clone();
        }
        // Deleting a group is not a field change applied to the group. The caller (`process_group_update` in group_ops.rs) removes the group record
        // entirely. Nothing to do here (see the GroupChange::Delete note).
        GroupChange::Delete => {}
        GroupChange::TransferFounder(new_founder) => {
            // If the target is not a member, the transfer is ignored. Otherwise authority would pass to someone outside the group and lock it.
            if group.is_member(new_founder) {
                group.founder_identity_id = new_founder.clone();
            }
        }
    }
    group.version = new_version;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_cannot_jump_to_the_end() {
        let group = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        assert!(validate_group_update(&group, "founder1", true, MAX_VERSION_JUMP).is_ok());
        assert_eq!(
            validate_group_update(&group, "founder1", true, u32::MAX),
            Err(GroupUpdateError::VersionTooFarAhead)
        );
    }

    /// A late joiner holds [founder, me]; the update that hands the group to B
    /// also carries the member list with B in it.
    #[test]
    fn transfer_to_a_member_the_same_update_brings() {
        let mut g = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        g.sync_members(&["founder1".to_string(), "b".to_string()], 1001);
        apply_change(&mut g, &GroupChange::TransferFounder("b".into()), 1, 1001);
        assert_eq!(g.founder_identity_id, "b");
    }

    /// the latest add counts, also when the removal was missed.
    #[test]
    fn re_add_restarts_added_at() {
        let mut g = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        apply_change(&mut g, &GroupChange::Add("x".into()), 1, 2000);
        apply_change(&mut g, &GroupChange::Add("x".into()), 3, 5000);
        assert_eq!(g.members.iter().find(|m| m.identity_id == "x").unwrap().added_at, 5000);
    }

    #[test]
    fn founder_can_update() {
        let group = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        assert!(validate_group_update(&group, "founder1", true, 1).is_ok());
    }

    #[test]
    fn non_founder_rejected() {
        let group = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        assert_eq!(
            validate_group_update(&group, "someone_else", true, 1),
            Err(GroupUpdateError::NotFounder)
        );
    }

    #[test]
    fn revoked_signer_device_rejected() {
        let group = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        assert_eq!(
            validate_group_update(&group, "founder1", false, 1),
            Err(GroupUpdateError::UnknownOrRevokedSignerDevice)
        );
    }

    #[test]
    fn stale_version_rejected() {
        // Bring the group to version 3, then a STALE (backdated) update must be rejected.
        let mut group = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        apply_change(&mut group, &GroupChange::Rename("v3".into()), 3, 2000);
        assert_eq!(
            validate_group_update(&group, "founder1", true, 2),
            Err(GroupUpdateError::StaleOrOutOfOrderVersion)
        );
        // An equal version (already applied) is rejected too.
        assert_eq!(
            validate_group_update(&group, "founder1", true, 3),
            Err(GroupUpdateError::StaleOrOutOfOrderVersion)
        );
    }

    /// Regression test (third-member bug). Founder A adds B (v1), then C (v2). C learns the group for the FIRST time from the v2 update, so locally
    /// `Group::new` (founder only) + `Add(C)` is applied. That made C think the membership was [A, C], so it could never send a message to B.
    /// `sync_members` (the authoritative list carried by the update) gives C its FULL membership.
    #[test]
    fn late_joiner_gets_full_membership() {
        let founder = "A".to_string();
        // On C's side: the group is created for the first time (with the founder only).
        let mut c_view = Group::new("g1".into(), "Test".into(), founder.clone(), 1000);
        let change = GroupChange::Add("C".to_string());
        apply_change(&mut c_view, &change, 2, 2000);

        // WITHOUT sync_members, B stays missing. This is the bug itself:
        assert!(!c_view.is_member("B"), "ön koşul: sync'ten önce B bilinmiyor");

        // Set equal to the authoritative list carried by the update.
        c_view.sync_members(&["A".to_string(), "B".to_string(), "C".to_string()], 2000);

        assert!(c_view.is_member("A"));
        assert!(c_view.is_member("B"), "geç katılan üye, kendisinden ÖNCE eklenmiş üyeyi de görmeli");
        assert!(c_view.is_member("C"));
        // C must be able to send group messages to both A and B.
        let targets = c_view.other_members("C");
        assert_eq!(targets.len(), 2);
    }

    /// `sync_members` also drops a removed member. Missed Remove updates correct themselves.
    #[test]
    fn sync_members_drops_removed() {
        let mut g = Group::new("g1".into(), "Test".into(), "A".into(), 1000);
        apply_change(&mut g, &GroupChange::Add("B".into()), 1, 2000);
        apply_change(&mut g, &GroupChange::Add("C".into()), 2, 2000);
        assert!(g.is_member("B"));
        g.sync_members(&["A".to_string(), "C".to_string()], 3000);
        assert!(!g.is_member("B"));
        assert!(g.is_member("C"));
    }

    #[test]
    fn sync_members_keeps_the_founder() {
        let mut g = Group::new("g1".into(), "Test".into(), "A".into(), 1000);
        g.sync_members(&["B".to_string()], 2000);
        assert!(g.is_member("A") && g.is_member("B"));
    }

    /// Recovery proposal: if the founder loses ALL their devices, the group was locked. A transfer hands authority to another MEMBER.
    #[test]
    fn founder_can_hand_over_to_a_member() {
        let mut g = Group::new("g1".into(), "Test".into(), "A".into(), 1000);
        apply_change(&mut g, &GroupChange::Add("B".into()), 1, 2000);
        assert_eq!(g.founder_identity_id, "A");

        apply_change(&mut g, &GroupChange::TransferFounder("B".into()), 2, 3000);
        assert_eq!(g.founder_identity_id, "B", "yetki uyeye gecmeli");
        // Artik yalnizca B imzalayabilir.
        assert!(validate_group_update(&g, "B", true, 3).is_ok());
        assert_eq!(validate_group_update(&g, "A", true, 3), Err(GroupUpdateError::NotFounder));
    }

    /// Authority cannot pass to someone OUTSIDE the group. If it could, the group would be locked for good.
    #[test]
    fn founder_transfer_to_a_non_member_is_ignored() {
        let mut g = Group::new("g1".into(), "Test".into(), "A".into(), 1000);
        apply_change(&mut g, &GroupChange::TransferFounder("Z".into()), 1, 2000);
        assert_eq!(g.founder_identity_id, "A", "uye olmayan yetki alamaz");
        assert_eq!(g.version, 1, "surum yine de ilerlemeli");
    }

    fn transfer(version: u32, from: &str, to: &str) -> crate::packet::FounderTransfer {
        crate::packet::FounderTransfer {
            group_id: "g1".into(),
            version,
            from_identity: from.into(),
            to_identity: to.into(),
            signed_by_device: "dev".into(),
            signature: vec![1],
            signature_pq: vec![2],
        }
    }

    /// See `packet::FounderTransfer`. The chain must stay ordered by version, must not carry the same transfer twice, and must not grow without
    /// bound. Each entry carries an ML-DSA signature (about 4.6 KB), and the chain goes with EVERY group update.
    #[test]
    fn founder_chain_dedupes_sorts_and_is_capped() {
        let mut g = Group::new("g1".into(), "Test".into(), "A".into(), 1000);
        g.push_founder_transfer(transfer(5, "A", "B"));
        g.push_founder_transfer(transfer(5, "A", "B"));
        assert_eq!(g.founder_chain.len(), 1, "ayni devir iki kez girmemeli");

        // Sirasiz eklense de surume gore siralanmali.
        g.push_founder_transfer(transfer(3, "Z", "A"));
        assert_eq!(g.founder_chain[0].version, 3);
        assert_eq!(g.founder_chain[1].version, 5);

        // Ust sinir: en eskiler dusmeli, en yeniler kalmali.
        for v in 10..10 + MAX_FOUNDER_CHAIN as u32 {
            g.push_founder_transfer(transfer(v, "X", &format!("Y{}", v)));
        }
        assert_eq!(g.founder_chain.len(), MAX_FOUNDER_CHAIN);
        assert_eq!(g.founder_chain.first().unwrap().version, 10);
        assert_eq!(
            g.founder_chain.last().unwrap().version,
            10 + MAX_FOUNDER_CHAIN as u32 - 1
        );
    }

    #[test]
    fn forward_version_gap_allowed() {
        // A single missed update must not lock a member out. A forward jump (gap) is accepted (see the StaleOrOutOfOrderVersion note).
        let group = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        assert!(validate_group_update(&group, "founder1", true, 5).is_ok());
    }

    #[test]
    fn add_member_increments_version() {
        let mut group = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        apply_change(&mut group, &GroupChange::Add("member2".into()), 1, 2000);
        assert!(group.is_member("member2"));
        assert_eq!(group.version, 1);
    }

    #[test]
    fn remove_member_excludes_from_other_members() {
        let mut group = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        apply_change(&mut group, &GroupChange::Add("member2".into()), 1, 2000);
        apply_change(&mut group, &GroupChange::Remove("member2".into()), 2, 3000);
        assert!(!group.is_member("member2"));
    }
    #[test]
    fn removing_the_founder_is_ignored() {
        let mut g = Group::new("g".into(), "n".into(), "A".into(), 1);
        g.sync_members(&["A".to_string(), "B".to_string(), "B".to_string()], 2);
        assert_eq!(g.member_identity_ids(), vec!["A".to_string(), "B".to_string()], "no duplicate member");
        apply_change(&mut g, &GroupChange::Remove("A".into()), 2, 3);
        assert!(g.is_member("A") && g.version == 2);
        apply_change(&mut g, &GroupChange::Remove("B".into()), 3, 4);
        assert!(!g.is_member("B"));
    }

}
