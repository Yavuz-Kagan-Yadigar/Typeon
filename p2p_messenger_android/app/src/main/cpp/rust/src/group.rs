//! Grup Mesajlaşma — Description.md bölüm 5.
//!
//! Model kararı (5.1): Sender Keys DEĞİL, pairwise. Grup mesajı gönderilirken
//! her üye için ayrı ayrı mevcut 1:1 Double Ratchet oturumuyla şifrelenir.
//! Bu modül grup ÜYELİK durumunu ve yetki kontrolünü taşır; asıl şifreleme
//! `ratchet.rs`'teki mevcut 1:1 oturumları kullanır (bkz. lib.rs
//! `send_group_message`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub identity_id: String,
    pub added_at: u64,
    /// Her zaman founder_identity_id olmalı (spec 5.2) — doğrulama
    /// `apply_update` içinde yapılır.
    pub added_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub group_id: String,
    pub name: String,
    pub founder_identity_id: String,
    pub members: Vec<GroupMember>,
    pub created_at: u64,
    /// Üyelik listesi her değiştiğinde artar (spec 5.2) — eski/tekrarlanan
    /// GroupUpdate paketlerini reddetmek için kullanılır.
    pub version: u32,
    /// Spec dışı: grup profil fotoğrafı — SADECE `GroupChange::AvatarUpdate`
    /// ile (dolayısıyla SADECE kurucu tarafından) değişir.
    #[serde(default)]
    pub avatar_jpeg: Option<Vec<u8>>,
    /// Bu grup için bilinen kurucu devirleri — bkz.
    /// `packet::FounderTransfer` (neden gerekli olduğu orada). Kurucunun
    /// gönderdiği her `GroupUpdate` bunu taşır; devri kaçıran bir üye
    /// zinciri yürüyerek yerel kurucusunu ilerletir ve gruptan KALICI
    /// olarak kopmaz.
    #[serde(default)]
    pub founder_chain: Vec<crate::packet::FounderTransfer>,
}

/// Kurucu devir zincirinde saklanan azami girdi sayısı.
///
/// Her girdi bir ML-DSA-87 imzası (~4.6 KB) taşıyor ve zincir HER grup
/// güncellemesiyle birlikte gidiyor — sınırsız bırakmak gossipsub'ın 1 MB
/// paket tavanını yiyip bitirirdi. 8 devir, gerçek kullanımda fazlasıyla
/// yeterli. KABUL EDİLEN SINIR: art arda 8'den fazla devrin TAMAMINI
/// kaçıran bir üye kendini onaramaz ve gruba yeniden davet edilmelidir.
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

    /// Zincire yeni bir devir ekler (tekrarları eler) ve son
    /// `MAX_FOUNDER_CHAIN` girdiyi tutar — bkz. o sabitin notu.
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

    /// Spec dışı, hata düzeltmesi (üçüncü üye hatası): üyelik listesini
    /// kurucudan gelen OTORİTER listeye eşitler (bkz. `GroupUpdate.members`).
    /// Var olan üyelerin `added_at`'i korunur (gereksiz değişiklik olmasın),
    /// listede olmayanlar çıkarılır, yeni olanlar eklenir. Bu, hem geç
    /// katılan bir üyenin TAM üyeliği almasını hem de kaçırılan
    /// güncellemelerin kendiliğinden düzelmesini sağlar.
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

    /// Diğer tüm üyeler (mesaj gönderilecek hedef listesi) — kendisi hariç.
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
    /// signed_by, founder_identity_id ile eşleşmiyor (spec 5.2: "sadece
    /// founder_identity_id üye ekleyebilir/çıkarabilir").
    NotFounder,
    /// signed_by_device, kurucunun bilinen/Active bir cihazı değil.
    UnknownOrRevokedSignerDevice,
    /// new_version, mevcut version'dan BÜYÜK olmalı. Eskiden `== version+1`
    /// şart koşuluyordu ama bu, TEK bir güncelleme kaçırıldığında (ağ
    /// kesintisi) o üyeyi KALICI olarak kilitliyordu — sonraki tüm
    /// güncellemeler "sıra dışı" diye reddediliyor ve üye asla yetişemiyordu.
    /// Artık ileri sıçramalara (gap) izin veriliyor (yalnızca stale/tekrar,
    /// yani `<= version`, reddedilir); bir gap tespit edildiğinde çağıran
    /// taraf uyarı loglar (bkz. lib.rs process_group_update).
    StaleOrOutOfOrderVersion,
    /// new_version is implausibly far ahead. One accepted update at
    /// `u32::MAX` would freeze the group for good: nothing can follow it.
    VersionTooFarAhead,
}

/// Largest forward gap one update may make (missed updates are allowed).
/// 4096: at 2^20 a founder reached `u32::MAX` in 4096 updates.
pub const MAX_VERSION_JUMP: u32 = 1 << 12;

/// Uygulanacak değişikliğin türü (spec 5.2 `GroupChange`). Kanonik tanım
/// `packet::GroupChange`'te (ağ paket formatı, `GroupUpdate.change` alanı) —
/// burada aynı ismi ikinci bir enum olarak tanımlamak yerine yeniden
/// export ediliyor, aksi halde `packet::GroupChange`/`group::GroupChange`
/// aynı isimli ama farklı iki tip olur ve çağıranlar yanlışlıkla birini
/// diğeri yerine geçirmeye çalışabilir (tip hatası).
pub use crate::packet::GroupChange;

/// Spec 5.2: "Alıcı taraf, `signed_by == founder_identity_id` değilse
/// `GroupUpdate`'i reddeder [...] `signed_by_device`'ın kurucunun
/// bilinen/Active bir cihazı olması da ayrıca doğrulanır."
///
/// `is_signer_device_active_for_identity`: çağıran taraf (lib.rs), bu
/// device_fingerprint'in gerçekten `signed_by` Identity'sinin Active bir
/// cihazı olup olmadığını Contact/known_devices tablosuna bakarak
/// belirler — bu modül kripto/ağ durumuna erişmediği için sonucu parametre
/// olarak alır.
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
    // İleri sıçramalara izin ver (bkz. `StaleOrOutOfOrderVersion` notu) —
    // sadece stale/tekrar (mevcut version'a eşit veya küçük) reddedilir.
    if new_version <= group.version {
        return Err(GroupUpdateError::StaleOrOutOfOrderVersion);
    }
    if new_version > group.version.saturating_add(MAX_VERSION_JUMP) {
        return Err(GroupUpdateError::VersionTooFarAhead);
    }
    Ok(())
}

/// Doğrulanmış bir `GroupChange`'i gruba uygular (imza doğrulaması
/// `validate_group_update` ile ayrı yapılmış olmalı — bu fonksiyon
/// çağrılmadan önce).
pub fn apply_change(group: &mut Group, change: &GroupChange, new_version: u32, now: u64) {
    match change {
        GroupChange::Add(identity_id) => {
            if !group.is_member(identity_id) {
                group.members.push(GroupMember {
                    identity_id: identity_id.clone(),
                    added_at: now,
                    added_by: group.founder_identity_id.clone(),
                });
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
        // Grup silme, gruba uygulanan bir ALAN değişikliği değil — çağıran
        // (lib.rs `process_group_update`) grup kaydını tamamen kaldırır.
        // Burada yapılacak bir şey yok (bkz. GroupChange::Delete notu).
        GroupChange::Delete => {}
        GroupChange::TransferFounder(new_founder) => {
            // Hedef üye değilse devir yok sayılır — aksi halde grup
            // dışındaki birine yetki geçip grup kilitlenirdi.
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
        // Grubu version 3'e getir, sonra STALE (geriye dönük) bir güncelleme
        // reddedilmeli.
        let mut group = Group::new("g1".into(), "Test".into(), "founder1".into(), 1000);
        apply_change(&mut group, &GroupChange::Rename("v3".into()), 3, 2000);
        assert_eq!(
            validate_group_update(&group, "founder1", true, 2),
            Err(GroupUpdateError::StaleOrOutOfOrderVersion)
        );
        // Eşit version da (zaten uygulanmış) reddedilir.
        assert_eq!(
            validate_group_update(&group, "founder1", true, 3),
            Err(GroupUpdateError::StaleOrOutOfOrderVersion)
        );
    }

    /// Regresyon (üçüncü üye hatası): kurucu A, önce B'yi (v1) sonra C'yi
    /// (v2) ekler. C grubu İLK KEZ v2 güncellemesiyle öğrenir — yani
    /// yerelde `Group::new` (SADECE kurucu) + `Add(C)` uygulanır. Bu, C'nin
    /// üyeliği [A, C] sanmasına ve B'ye hiç mesaj gönderememesine yol
    /// açıyordu. `sync_members` (güncellemenin taşıdığı otoriter liste) ile
    /// C artık TAM üyeliği alır.
    #[test]
    fn late_joiner_gets_full_membership() {
        let founder = "A".to_string();
        // C tarafında: grup ilk kez oluşturuluyor (yalnızca kurucu ile).
        let mut c_view = Group::new("g1".into(), "Test".into(), founder.clone(), 1000);
        let change = GroupChange::Add("C".to_string());
        apply_change(&mut c_view, &change, 2, 2000);

        // sync_members OLMADAN B eksik kalırdı — hatanın ta kendisi:
        assert!(!c_view.is_member("B"), "ön koşul: sync'ten önce B bilinmiyor");

        // Güncellemenin taşıdığı otoriter liste ile eşitle.
        c_view.sync_members(&["A".to_string(), "B".to_string(), "C".to_string()], 2000);

        assert!(c_view.is_member("A"));
        assert!(c_view.is_member("B"), "geç katılan üye, kendisinden ÖNCE eklenmiş üyeyi de görmeli");
        assert!(c_view.is_member("C"));
        // C, grup mesajını hem A'ya hem B'ye gönderebilmeli.
        let targets = c_view.other_members("C");
        assert_eq!(targets.len(), 2);
    }

    /// `sync_members` çıkarılan üyeyi de düşürür (kaçırılmış Remove'lar
    /// kendiliğinden düzelir).
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

    /// Dış inceleme önerisi: kurucu bütün cihazlarını kaybederse grup
    /// kilitleniyordu. Devir, yetkiyi başka bir ÜYEYE geçirir.
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

    /// Yetki grup DIŞINDAKİ birine geçemez — geçseydi grup büsbütün
    /// kilitlenirdi.
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

    /// bkz. `packet::FounderTransfer` — zincir sürüme göre sıralı kalmalı,
    /// aynı devri iki kez taşımamalı ve sınırsız büyümemeli (her girdi
    /// ~4.6 KB'lık bir ML-DSA imzası taşıyor ve HER grup güncellemesiyle
    /// birlikte gidiyor).
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
        // Tek bir güncelleme kaçırıldığında üye kilitlenmemeli — ileri
        // sıçrama (gap) kabul edilir (bkz. StaleOrOutOfOrderVersion notu).
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
