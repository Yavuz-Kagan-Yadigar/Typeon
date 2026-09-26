//! Ağ üzerinde taşınan paket biçimleri — Description.md bölüm 1.3, 1.5,
//! 1.6, 3.3, 5.2.

use serde::{Deserialize, Serialize};

/// QR kodun taşıdığı eşleşme paketi (spec 1.3 — "Karar (v0.1): fingerprint-only
/// QR"). CBOR ile kodlanır (QR kapasitesi kısıtı nedeniyle tam public key'ler
/// taşınmaz — bağlantı kurulunca karşı taraftan indirilir ve bu `fingerprint`
/// ile karşılaştırılır).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrPacket {
    pub version: u8,
    pub device_name: String,
    /// Kişi kimliği (spec 1.3 v0.2 notu: identity_id de taşınır).
    pub identity_id: String,
    /// Bu cihazın kendi fingerprint'i.
    pub device_fingerprint: String,
    /// Bağlanmak için yeterli tek bir bilinen adres.
    pub rendezvous_node: String,
    /// Spec dışı, güvenlik denetimi devamı (bkz. SECURITY.md "Cross-network
    /// connectivity" notu, spec §4.1 "~10 node adresi paylaşımı" — önceden
    /// hiç implemente edilmemişti): QR'ı üreten cihazın bildiği, röle
    /// (Circuit Relay v2) protokolünü konuşan birkaç peer'in TAM adresi
    /// (`.../p2p/<peer_id>` dahil). `rendezvous_node` doğrudan erişilemezse
    /// (farklı ağ/NAT), tarayan taraf bunlardan biri üzerinden bağlanmayı
    /// dener (bkz. lib.rs `dial_with_relay_fallback`). `#[serde(default)]`
    /// — v1 QR'lar (bu alan olmadan üretilmiş) hâlâ ayrıştırılabilsin diye;
    /// CURRENT_VERSION 2'ye yükseltildi ama eski taraf bunu görmezden
    /// gelebilir, alan sadece boş kalır.
    #[serde(default)]
    pub known_relays: Vec<String>,
}

impl QrPacket {
    pub const CURRENT_VERSION: u8 = 2;

    /// CBOR olarak kodlar (QR'a gömülecek ham bayt dizisi).
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }

    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(data).map_err(|e| e.to_string())
    }
}

/// Var olan (onaylı) cihaz tarafından imzalanıp yayılan cihaz ekleme
/// bildirimi (spec 1.5 adım 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAdd {
    pub identity_id: String,
    pub new_device_fingerprint: String,
    /// Onaylayan cihazın fingerprint'i.
    pub added_by: String,
    /// Klasik (Ed25519) imza — `identity_id || new_device_fingerprint ||
    /// added_by` üzerinde, onaylayan cihazın anahtarıyla.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// ML-DSA (post-kuantum) imza — MessagePacket/GroupUpdate ile AYNI hibrit
    /// model (bkz. `verify_hybrid_signature`). `#[serde(default)]`: bu alan
    /// olmadan üretilmiş olası eski/boş paketlerle uyum için.
    #[serde(default)]
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// Cihaz iptali (spec 1.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRevoke {
    pub identity_id: String,
    pub revoked_device_fingerprint: String,
    /// İptali yapan cihazın fingerprint'i.
    pub revoked_by: String,
    /// bkz. `DeviceAdd.signature` — `identity_id || revoked_device_fingerprint
    /// || revoked_by` üzerinde klasik imza.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(default)]
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// Grup üyelik değişikliği (spec 5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupChange {
    Add(String),    // identity_id
    Remove(String), // identity_id
    Rename(String),
    /// Spec disi: grup profil fotografi -- SADECE kurucu degistirebilir
    /// (bu zaten `validate_group_update`'in `NotFounder` kontrolunden
    /// GECER, ayri bir yetki mekanizmasi icat edilmedi). `None` = fotograf
    /// kaldirildi.
    AvatarUpdate(#[serde(with = "serde_bytes")] Option<Vec<u8>>),
    /// Spec dışı, kullanıcı isteği: grubu TÜM üyeler için siler. Diğer
    /// değişikliklerin aksine bu, gruba bir alan güncellemesi değil —
    /// alıcı tarafta grup kaydı tamamen kaldırılır (bkz. lib.rs
    /// `process_group_update` Delete kolu). Yetki, diğerleriyle AYNI
    /// kuraldan gelir: `validate_group_update` yalnızca kurucunun imzasını
    /// kabul eder (`NotFounder`), ayrı bir mekanizma icat edilmedi.
    Delete,
    /// Kurucu yetkisini başka bir üyeye devreder (dış inceleme önerisi,
    /// 2026-08-27): kurucu bütün cihazlarını kaybederse grup aksi halde
    /// KALICI olarak kilitleniyordu — kimse üye ekleyip çıkaramıyor, adı
    /// ya da fotoğrafı değiştiremiyordu; tek çare grubu dağıtıp yeniden
    /// kurmaktı.
    ///
    /// Yetki kuralı diğerleriyle AYNI: yalnızca MEVCUT kurucunun imzası
    /// geçerli. Hedef, grubun üyesi olmak zorunda (bkz. `group::apply_change`)
    /// — aksi halde yetki grup dışında birine geçip grup büsbütün
    /// kilitlenirdi.
    ///
    /// BİLİNÇLİ KAPSAM DIŞI: kurucu ZATEN kaybolduysa bu da işe yaramaz.
    /// O durum için üyelerin çoğunluk oyuyla yeni kurucu ataması gerekir;
    /// bu, tek imzalı doğrulama şemasını çok imzalıya çevirmek demek —
    /// ayrı bir tasarım kararı.
    TransferFounder(String),
}

/// Spec dışı, kullanıcı kararı: bir grup üyesinin, kurucu tarafından
/// kefil olunan cihaz kaydı (bkz. `GroupUpdate.member_devices`). Alıcı,
/// `device_fingerprint`'in bu anahtarların SHA3-256'sı olduğunu ayrıca
/// doğrular (kendi içinde tutarlı olmayan kayıtlar reddedilir).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Kurucunun bildiği son adres — dial ipucu (bkz. lib.rs
    /// `device_last_addr`). Yoksa alıcı mDNS/röle/DHT'ye güvenir.
    #[serde(default)]
    pub last_addr: Option<String>,
}

/// Kurucu yetkisinin devredildiğine dair, KENDİ BAŞINA doğrulanabilir,
/// kompakt bir tanıklık (bkz. `GroupUpdate.founder_chain`).
///
/// NEDEN GEREKLİ — gerçek bir kilitlenme senaryosu: `GroupChange::TransferFounder`
/// yalnızca o güncellemeyi ALAN üyelerde uygulanıyordu. `GroupUpdate` grup
/// adını, TAM üyelik listesini ve üye anahtarlarını her seferinde taşıdığı
/// için bunlar kendi kendini onarıyor (bkz. `members`/`sync_members`) — ama
/// KURUCU alanının böyle bir onarımı YOKTU. Devri kaçıran bir üye
/// (çevrimdışıyken 7 günlük yeniden deneme penceresi dolduysa, ya da
/// `pending_group_syncs` o üye için sadece EN SON güncellemeyi sakladığından
/// devir daha yeni bir güncellemeyle ÜZERİNE YAZILDIYSA) yerel kurucusunu
/// eski kişi sanmaya devam eder; yeni kurucudan gelen her güncelleme
/// `NotFounder` ile REDDEDİLİR ve Ack gönderilmez, yani gönderen 7 gün
/// boyunca boşuna yeniden dener. O üye grup için KALICI olarak kopmuştur:
/// bir daha ne üye değişikliği, ne ad, ne fotoğraf, ne de grup silme alır.
///
/// GÜVENLİK: bu yapı, dış `GroupUpdate.signature`'ın kapsamında DEĞİL —
/// olması da gerekmiyor, çünkü KENDİ hibrit imzasını taşıyor ve
/// `founder_transfer_signing_input` ile alan-ayrımlı (domain-separated)
/// imzalanıyor, yani bir `GroupUpdate` imzası buraya yeniden kullanılamaz.
/// Aracı bir taraf bu listeyi silebilir (sonuç: bugünkü davranışa geri
/// düşülür, kayıp yok) ama uyduramaz (imza ESKİ kurucunun cihazına ait
/// olmak zorunda).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FounderTransfer {
    pub group_id: String,
    /// Devrin uygulandığı `GroupUpdate.new_version`.
    pub version: u32,
    /// Devri yapan (o anki) kurucu.
    pub from_identity: String,
    /// Yetkiyi devralan üye.
    pub to_identity: String,
    /// Eski kurucunun imzalayan cihazı.
    pub signed_by_device: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// `FounderTransfer`'ın imzaladığı baytlar. Uzunluk ön ekli — aksi halde
/// düz birleştirme, alan sınırlarını kaydırarak farklı (grup_id, kimlik)
/// üçlülerinin AYNI baytları üretmesine izin verirdi.
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
    /// Spec dışı: grubun GÜNCEL adı, her `GroupUpdate`'te taşınır (sadece
    /// `Rename` değişikliklerinde değil). Sebep: bir üye ilk kez `Add` ile
    /// eklendiğinde henüz yerel bir `Group` kaydı yoktur — bu alan
    /// olmadan `process_group_update` boş bir isimle ("") bir grup
    /// oluşturuyordu, bu da grup bildirimlerinde/ekranlarında kalıcı olarak
    /// boş başlık göstermeye yol açıyordu (bkz. dosya sonu not).
    pub group_name: String,
    /// Spec dışı, hata düzeltmesi (üçüncü üye hatası): bu değişiklikten
    /// SONRAKİ TAM üyelik listesi (kurucunun otoritesi). Önceden yoktu ve
    /// `process_group_update`, grubu yerelde ilk kez oluştururken
    /// `Group::new` ile SADECE kurucuyu ekleyip üstüne tek bir `change`
    /// uyguluyordu — yani SONRADAN eklenen bir üye, KENDİSİNDEN ÖNCE
    /// eklenmiş üyeleri HİÇ öğrenemiyordu (üçüncü cihaz grubu [kurucu, ben]
    /// olarak görüyor, ikinci üyeye mesaj gönderemiyordu). Artık her
    /// güncelleme tam listeyi taşıyor: geç katılan üye tam üyeliği alır VE
    /// arada kaçırılan güncellemeler de kendiliğinden düzelir (self-healing).
    /// `#[serde(default)]` — bu alan olmadan üretilmiş eski paketler yine
    /// ayrıştırılabilsin diye (ama imza kapsamına dahil olduğundan, karışık
    /// sürümler imza doğrulamasında elenir; tüm cihazlar güncellenmeli).
    #[serde(default)]
    pub members: Vec<String>,
    /// Spec dışı, kullanıcı kararı (grup üyelerinin otomatik tanıştırılması):
    /// üyelerin PUBLIC anahtarları + son bilinen adresleri, KURUCUNUN
    /// kefaletiyle. Pairwise grup mesajlaşması her üye ÇİFTİNİN birbiriyle
    /// ratchet kurabilmesini gerektirir; ama üyeler yalnızca kurucuyla QR
    /// eşleşmesi yapmış olabilir (A↔B, A↔C eşleşmiş ama B↔C eşleşmemiş) —
    /// bu durumda B ve C birbirine HİÇ mesaj gönderemiyordu. Bu alan, her
    /// üyenin diğerlerinin anahtarlarını kurucudan öğrenmesini sağlar.
    ///
    /// GÜVENLİK: bu, QR ile yüz yüze TOFU'dan DAHA ZAYIF bir güven modeli —
    /// kurucunun sözüne güvenilir. Kötü niyetli bir kurucu, bir üye için
    /// KENDİ anahtarını verip o üyeyi taklit edebilir (grup içi MITM).
    /// Bu yüzden: (a) alan imza kapsamındadır (aracılar değiştiremez),
    /// (b) alıcı ZATEN BİLDİĞİ bir cihazın anahtarlarını ASLA bunlarla
    /// EZMEZ (bkz. process_group_update), (c) böyle eklenen kişiler
    /// `verified=false` olarak işaretlenir ve UI'de "grup üzerinden eklendi,
    /// doğrulanmadı" olarak gösterilir.
    #[serde(default)]
    pub member_devices: Vec<GroupMemberDevice>,
    /// founder_identity_id olmalı — alıcı taraf bunu doğrular.
    pub signed_by: String,
    /// Kurucunun hangi cihazı imzaladı.
    pub signed_by_device: String,
    /// Klasik (Ed25519) imza.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Spec dışı: ML-DSA (post-kuantum) imza — önceden bu alan yoktu ve
    /// GroupUpdate SADECE Ed25519 ile korunuyordu (MessagePacket/
    /// HandshakeInit'teki hibrit modelle tutarsızdı, bkz. güvenlik
    /// denetimi). Artık MessagePacket ile AYNI hibrit doğrulama
    /// (`verify_hybrid_signature`, HER İKİ imza da zorunlu) uygulanıyor.
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
    /// Kurucu devir zinciri — bkz. `FounderTransfer` (kilitlenme senaryosu
    /// orada anlatılıyor). Kurucunun gönderdiği HER güncelleme, o gruba
    /// ait bilinen devirleri taşır; devri kaçırmış bir alıcı yerel
    /// kurucusunu bu zinciri yürüyerek ilerletir ve güncellemeyi kabul
    /// eder (bkz. lib.rs `heal_founder_chain`). `#[serde(default)]` —
    /// alanı hiç bilmeyen eski sürümlerle iki yönlü uyumlu; dış imzanın
    /// KAPSAMINDA DEĞİL (her girdi kendi imzasını taşıyor).
    #[serde(default)]
    pub founder_chain: Vec<FounderTransfer>,
}

// ---------------------------------------------------------------------------
// Çoklu-cihaz (spec 1.5/1.7) — ikinci bir cihazı var olan bir Identity'ye
// bağlama akışı. QR'ı YENİ cihaz gösterir, var olan (onaylı) cihaz OKUR
// (spec 1.5 adım 3 — onay her zaman zaten güvenilen cihazdan çıkar).
// ---------------------------------------------------------------------------

/// Yeni cihazın gösterdiği "cihaz ekleme QR'ı" (spec 1.5 adım 2).
///
/// Spec dışı, gerçek cihaz çökmesi düzeltmesi ("com.google.zxing.WriterException:
/// Data too big", `LinkDeviceActivity.encodeBinaryAsQrBitmap`): bu struct
/// ÖNCEDEN tam public key'leri taşıyordu ("QR kapasitesi ~3.3KB sığar"
/// varsayımıyla) — ama ML-DSA-87 (2592 bayt) + ML-KEM-1024 (1568 bayt)
/// public key'leri TEK BAŞINA ~4.2KB'a denk gelir, bir QR kodunun mutlak
/// üst sınırı olan ~2.9KB'ı (versiyon 40, en düşük hata düzeltme, 8-bit bayt
/// modu) HER ZAMAN aşar — hiçbir hata-düzeltme seviyesi ayarı bunu düzeltemez,
/// veri gerçekten sığmıyordu. Şimdi `QrPacket` (bkz. yukarısı, spec 1.3
/// "fingerprint-only QR") ile AYNI desene geçildi: public key'ler QR'da HİÇ
/// taşınmaz, sadece `device_fingerprint` (SHA3-256, 64 hex karakter). Onaylayan
/// cihaz `rendezvous_node`'a bağlanır, kendi `IdentityExchange`'ini gönderir;
/// yeni cihaz bunu alınca KARŞILIKLI kendi `IdentityExchange`'ini geri
/// gönderir (bkz. `process_identity_exchange` içindeki `pending_link_target`
/// kolu) — GERÇEK public key'ler (ve bunlardan yeniden hesaplanan fingerprint
/// doğrulaması) o el sıkışmada öğrenilir, tıpkı normal kişi eşleşmesinde
/// olduğu gibi (bkz. `process_qr_packet` dokümantasyonu, AYNI gerekçe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLinkRequest {
    pub version: u8,
    pub device_name: String,
    /// Yeni cihazın kendi (geçici/provizyonel) fingerprint'i — bu
    /// anahtarların SHA3-256'sı; onaylayan taraf GERÇEK anahtarları
    /// `IdentityExchange` ile aldıktan sonra yeniden hesaplayıp karşılaştırır
    /// (bkz. yukarıdaki struct dokümantasyonu).
    pub device_fingerprint: String,
    /// Onaylayan cihazın bağlanabileceği tek bir bilinen adres
    /// (`get_node_address` — Tor açıksa `.onion`).
    pub rendezvous_node: String,
    /// bkz. `QrPacket.known_relays` — farklı ağ/NAT için röle adayları.
    #[serde(default)]
    pub known_relays: Vec<String>,
}

impl DeviceLinkRequest {
    /// v2: fingerprint-only (bkz. struct dokümantasyonu — v1 tam public
    /// key'ler taşıyordu ve QR kapasitesini aşıyordu, hiçbir zaman
    /// çalışmıyordu). Eski v1 QR'lar artık `from_cbor` ile
    /// ayrıştırılamaz (alanlar kalıcı olarak kaldırıldı) — zararsız, v1
    /// zaten hiçbir gerçek cihazda üretilemiyordu (üretim anında çöküyordu).
    pub const CURRENT_VERSION: u8 = 2;
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }
    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(data).map_err(|e| e.to_string())
    }
}

/// Senkron yükünde (spec 1.7 `SyncPayload`) taşınan tek bir uzak cihazın
/// public anahtarları — alıcı bunları kendi `known_remote_devices`'ına
/// yazar, böylece ilk senkrondan hemen sonra o kişiyle ratchet kurup
/// mesajlaşabilir (kişiyi ayrıca QR ile eşleştirmesine gerek kalmaz).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Bir kişinin, cihazlar arası senkron için serileştirilmiş biçimi
/// (spec 1.7 `SyncPayload.contacts`).
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
}

/// Senkron yükü (spec 1.7). İlk bağlanmada tam kopya olarak taşınır;
/// `DeviceLinkGrant`'in içinde (ratchet-şifreli) yeni cihaza gider, ayrıca
/// `MessageContent::DeviceSync` ile sonraki değişikliklerde kardeş cihazlara
/// yeniden gönderilir (idempotent birleştirme).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPayload {
    pub contacts: Vec<SyncedContact>,
    /// Serileştirilmiş `group::Group` kayıtları — alıcı bunları olduğu gibi
    /// benimser (kurucu otoritesi zaten grup içinde imzalıdır).
    pub groups: Vec<serde_json::Value>,
    /// Çoklu-cihaz (spec 1.7): AYNI kimliğin DİĞER (kardeş) cihazları —
    /// 3+ cihaz senaryosunda cihazların birbirini öğrenmesi için. Alıcı
    /// bunları `identity_id = kendi kimliğim` olacak şekilde
    /// `known_remote_devices`'a ekler (kendi fingerprint'ini atlayarak).
    /// `#[serde(default)]` — bu alan olmadan üretilmiş eski senkron
    /// paketleriyle uyum için.
    #[serde(default)]
    pub siblings: Vec<SyncedDevice>,
    /// Kök arşiv anahtarı (ARK) — sunucuda saklanan geçmişi çözen anahtar
    /// (bkz. lib.rs `set_archive_root_key`, `server_seal`).
    ///
    /// Neden BURADA taşınıyor: ARK cihaza değil KİMLİĞE ait; aynı kimliğin
    /// bütün cihazları sunucudaki arşivi okuyabilmeli. Bu paket zaten
    /// ratchet-şifreli ve zaten SADECE kardeş cihazlar arasında gidiyor
    /// (bkz. receive_message `DeviceSync` kolundaki `from_sibling`
    /// kontrolü), yani yeni bir anahtar taşıma mekanizması icat etmeye
    /// gerek yok — uzun ömürlü sırların cihazlar arasına geçtiği nokta
    /// zaten burası.
    ///
    /// `#[serde(default)]`: bu alan olmadan üretilmiş eski senkron
    /// paketleriyle uyum için.
    #[serde(default)]
    #[serde(with = "serde_bytes")]
    pub archive_root_key: Option<Vec<u8>>,
}

/// Ağ üzerinde taşınan üst-seviye paket zarfı. `MessagePacket` header'ı
/// spec 3.3'teki alanları birebir taşır: `ratchet_pubkey`, `message_number`,
/// `prev_chain_length` gerçek bir Double Ratchet DH adımını mümkün kılar
/// (önceki sürümdeki basitleştirilmiş `Packet`'in aksine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePacketHeader {
    pub sender_identity_id: String,
    pub sender_device_fingerprint: String,
    /// Bu mesajın kararlı, ratchet rotasyonlarından bağımsız kimliği (v4
    /// UUID) — spec dışı, edit/delete'in hangi mesajı hedeflediğini
    /// belirtebilmesi için gerekli (bkz. `MessageContent::Edit`/`Delete`).
    /// `message_number`, ratchet rotasyonunda sıfırlanabildiği için tek
    /// başına kararlı bir kimlik OLAMAZ.
    pub message_id: String,
    /// Güncel ratchet adımının public key'i (X25519 + ML-KEM hibrit,
    /// hibrit anahtarların birleştirilmiş serileştirmesi).
    #[serde(with = "serde_bytes")]
    pub ratchet_pubkey: Vec<u8>,
    pub message_number: u32,
    pub prev_chain_length: u32,
    /// DOLU İSE: gönderen bu mesajla birlikte bir DH/KEM rotasyonu
    /// tetikledi — bu alan, rotasyonun ürettiği YENİ Kyber ciphertext'ini
    /// taşır. Alıcı bunu görünce kendi tarafında da
    /// `perform_dh_ratchet`'i (kendi inisiyatifiyle değil, bu ciphertext'e
    /// karşı decapsulate ederek) çalıştırıp aynı yeni anahtarları türetmeli
    /// — bkz. ratchet.rs `RatchetPublicKeys`/`perform_dh_ratchet`
    /// dokümantasyonu ve lib.rs `maybe_rotate_ratchet`. Boşsa (None), bu
    /// mesaj normal bir simetrik-zincir ilerlemesidir, rotasyon yok.
    #[serde(with = "serde_bytes")]
    pub rotation_kyber_ciphertext: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePacket {
    pub header: MessagePacketHeader,
    /// AEAD (ChaCha20-Poly1305) şifreli içerik; nonce, header'dan
    /// deterministik türetilir (message_number bazlı) — ayrıca taşınmaz.
    /// Çözüldükten sonra bir `MessageContent` olarak CBOR-decode edilir.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// ML-DSA + Ed25519 hibrit imza (header+ciphertext üzerinde).
    #[serde(with = "serde_bytes")]
    pub signature_classical: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// `HistorySyncResponse.messages`'ın tek bir elemanı — bkz. lib.rs
/// `ArchivedMessage` (yerel karşılığı, ekstra `status` alanı hariç: bu ağdan
/// geçtiği için gönderim durumu anlamsız/hassas, taşınmaz).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedMessage {
    pub direction: String,
    pub text: String,
    pub timestamp: u64,
    /// SADECE grup mesajlarında dolu — bkz. `ArchivedMessage.sender_identity_id`
    /// notu, `direction == "received"` iken gerçek göndereni taşır
    /// (`"sent"` iken gönderen zaten YANITLAYANIN kendisidir, paket
    /// başlığından zaten bilinir).
    #[serde(default)]
    pub sender_identity_id: Option<String>,
    /// Var-olma kontrolüyle (mesaj kimliği bazlı) tekrar birleştirmeyi
    /// önlemek için — bkz. lib.rs `message_exists_with_id`, ESKİ SAYFA
    /// (`before_timestamp.is_some()`) birleştirmesinde kullanılır.
    #[serde(default)]
    pub message_id: Option<String>,
    /// Spec dışı, kullanıcı isteği (gönderim-sırası): göndericinin gönderim
    /// anı — geçmiş senkronunda da korunur ki alıcı gösterimi GÖNDERİM
    /// sırasına göre yapabilsin. 0 = bilinmiyor (yerel arşiv zamanına düşülür).
    #[serde(default)]
    pub sent_at_ms: u64,
    /// Spec dışı, hata düzeltmesi ("silinen mesaj geçmiş senkronuyla geri
    /// geliyor"): önceden bu alan yoktu — `is_deleted` yerel arşivde
    /// işaretli olsa bile senkron yanıtı orijinal metni taşıyor ve alıcı
    /// tarafta silinmemiş gibi yeniden arşivleniyordu (bir cihaz hiç
    /// sahip olmadığı bir satırı sıfırdan alırken, ör. yeni bağlanan
    /// ikincil bir cihaz ya da uzun bir kaydırma-geri sayfası). `#[serde(default)]`
    /// eski/karşı sürümle geriye dönük uyumluluk için (eksikse `false`).
    #[serde(default)]
    pub is_deleted: bool,
    /// Spec dışı, hata düzeltmesi ("senkronla gelen düzenlenmiş bir mesaj
    /// '(düzenlendi)' etiketi olmadan görünüyor"): `text` zaten GÜNCEL
    /// (düzenlenmiş) içeriği taşıyor — `apply_edit_to_archive` metni
    /// yerinde değiştiriyor — ama bu bayrak olmadan alıcı tarafın onu
    /// SIFIRDAN, hiç düzenlenmemiş bir mesajmış gibi arşivlemesinden başka
    /// seçeneği yoktu. Veri kaybı yoktu (metin doğruydu), sadece UI
    /// etiketi eksikti.
    #[serde(default)]
    pub is_edited: bool,
}

/// `MessagePacket.ciphertext`'in çözüldükten sonraki gerçek içeriği — spec
/// dışı, mesaj düzenleme/silme desteği için. Edit/delete AYRI bir paket
/// tipi/imza akışı olarak DEĞİL, normal bir mesaj gibi aynı ratchet adımıyla
/// şifrelenip gönderilir (bu yüzden onlar da tam uçtan uca gizlilik/
/// bütünlük korumasına sahip olur — bir relay/node bunun bir düzenleme mi
/// yoksa yeni bir mesaj mı olduğunu bile göremez).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    /// `group_id`: doluysa bu mesaj bir grup mesajının pairwise
    /// (1:1 ratchet üzerinden) fan-out kopyasıdır — spec dışı, "gerçek grup
    /// entegrasyonu" için gerekli. Bu olmadan alıcı taraf, gelen bir grup
    /// mesajını sıradan bir 1:1 mesajdan AYIRT EDEMİYORDU (bkz. lib.rs
    /// receive_message/GroupChatActivity notu) — grup sohbeti diye ayrı bir
    /// yer yoktu, mesajlar göndericinin 1:1 sohbetine karışıyordu.
    Text {
        group_id: Option<String>,
        text: String,
        /// Spec disi: SADECE `group_id.is_some()` iken dolu -- ayni grup
        /// mesajinin N uyeye pairwise fan-out edilen (her biri kendi
        /// ratchet adimiyla FARKLI bir `MessagePacketHeader.message_id`
        /// tasiyan) kopyalarini TEK bir yerel kimlikte birlestirir. Gorulme
        /// bildirimleri (bkz. `Seen`) icin gerekli -- alici tarafin geri
        /// gonderdigi "gorduk" paketini, gonderenin hangi yerel balona ait
        /// oldugunu bulabilmesi icin (per-uye message_id'ler gonderen
        /// tarafta zaten bilinmiyor, sadece alici tarafin KENDI kopyasinin
        /// id'sini bilir).
        group_message_local_id: Option<String>,
        /// Spec dışı, kullanıcı isteği: göndericinin KENDİ cihazında mesajı
        /// yazdığı/gönderdiği andaki yerel saat (ms, epoch) — alıcı tarafın
        /// "10:42 (sent at: 10:41)" gibi hem yerel ALINMA anını HEM DE
        /// göndericinin GERÇEK gönderim anını göstermesi için (bkz.
        /// ChatActivity/SimpleChatAdapter). ÖNEMLİ: bu, `awaiting_confirmation`'ın
        /// `regen_content` mekanizmasıyla (bkz. lib.rs) tazelenip yeniden
        /// gönderilse BİLE değişmez — `MessageContent` klonlanıp AYNEN
        /// yeniden şifreleniyor, bu alan İLK yazılma anını taşımaya devam
        /// eder (istenen tam olarak budur: "ne zaman yazıldı", "ne zaman
        /// son denendi" değil). `#[serde(default)]`: bu alan olmadan
        /// üretilmiş eski/kuyrukta bekleyen paketler yine ayrıştırılabilsin
        /// diye (0 = bilinmiyor, alıcı tarafı bu durumda parantez içi
        /// gösterimi atlar).
        #[serde(default)]
        sent_at_ms: u64,
        /// Spec dışı, kullanıcı isteği (WhatsApp tarzı "sağa kaydırıp
        /// yanıtla"): bu mesaj başka bir mesaja yanıtsa, o mesajın kararlı
        /// kimliği — 1:1'de `MessagePacketHeader.message_id`, grupta
        /// `group_message_local_id` (edit/delete'in `target_message_id`
        /// alanıyla AYNI kural, bkz. `Edit`/`Delete` notu). Alıcı tarafın
        /// yerel arşivinde bu id'yi arayıp "şuraya kaydır" davranışı
        /// uygulayabilmesi için taşınır.
        #[serde(default)]
        reply_to_message_id: Option<String>,
        /// Alıcı, yanıtlanan mesajı YERELİNDE hiç arşivlememiş olabilir
        /// (ör. o mesajı hiç almadı/geçmiş senkronu yapılmadı) — bu yüzden
        /// gönderen taraf, o mesajın metninden kısa bir ÖZET (bkz.
        /// ChatActivity/GroupChatActivity `REPLY_PREVIEW_MAX_CHARS`
        /// kırpması) burada AYRICA gönderir; alıcı tarafın kendi arşivine
        /// bakmasına GEREK KALMAZ, tıpkı Signal/WhatsApp'ın yaptığı gibi.
        #[serde(default)]
        reply_to_preview: Option<String>,
        /// SADECE `group_id.is_some()` iken anlamlı — yanıtlanan mesajı
        /// gönderenin `identity_id`'si (1:1'de göndereni belirtmeye gerek
        /// yok, zaten iki taraftan biri). Alıcı tarafın yanıt önizlemesinde
        /// "Ahmet'e yanıt" gibi bir isim gösterebilmesi için.
        #[serde(default)]
        reply_to_sender_identity_id: Option<String>,
    },
    /// Spec dışı, kullanıcı isteği (grup düzenle/sil): `group_id` doluysa
    /// `target_message_id` aslında `Text.group_message_local_id`'dir —
    /// grup mesajının fan-out kopyaları her üyede FARKLI bir
    /// `MessagePacketHeader.message_id` taşıdığından (bkz. `Text` notu),
    /// gönderen taraf hedefi sadece bu paylaşılan yerel kimlikle
    /// belirtebilir. Alıcı taraf zaten kendi grup arşivinde bu değeri
    /// `message_id` sütunu olarak saklar (bkz. `archive_group_message`
    /// çağıranları), bu yüzden eşleştirme tutarlıdır.
    /// Spec dışı, kullanıcı isteği (WhatsApp tarzı tepkiler): bir mesaja
    /// uzun basıp bırakılan emoji.
    ///
    /// KİŞİ BAŞINA TEK tepki (WhatsApp davranışı): aynı kişiden gelen yeni
    /// bir `Reaction` öncekinin YERİNE geçer, `emoji` BOŞ dize ise tepki
    /// kaldırılır. Bu yüzden ayrı bir "tepkiyi kaldır" paketi yok.
    ///
    /// `target_message_id`: `Edit`/`Delete` ile AYNI kural — 1:1'de
    /// `MessagePacketHeader.message_id` (yani kararlı `conv_id`), grupta
    /// `Text.group_message_local_id`.
    ///
    /// `reacted_at_ms`: `Edit.edited_at_ms` ile aynı gerekçe — gossipsub
    /// sıra garantisi vermez; aynı kişinin hızlıca değiştirdiği iki tepki
    /// ters sırada ulaşırsa ESKİ olan YENİNİN üzerine yazmamalı.
    Reaction {
        target_message_id: String,
        /// Boş dize = "tepkimi kaldır" (bkz. üstteki not).
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
        /// Spec dışı (dış AI incelemesi düzeltmesi — sıra-dışı Edit / "revert"
        /// koruması): bu düzenlemenin ÜRETİLDİĞİ andaki gönderici yerel saati
        /// (ms, epoch). gossipsub sıra garantisi VERMEZ — aynı mesajın iki
        /// ayrı düzenlemesi (ör. kullanıcı saniyeler içinde iki kez düzeltir)
        /// alıcıya TERS sırada ulaşabilir; alıcı, DAHA ESKİ bir düzenlemeyi
        /// DAHA YENİ olanın üzerine yazmasın diye bu damgayı arşivde saklanan
        /// son değerle karşılaştırır (bkz. lib.rs `apply_edit_to_archive`).
        /// Not: ratchet zaten AĞDAN gelen bir REPLAY'i (tüketilmiş mesaj
        /// numarası) reddeder — bu alan farklı bir sorunu, aynı göndericiden
        /// gelen İKİ MEŞRU düzenlemenin sırasız tesliminde son metnin doğru
        /// olmasını çözer. `#[serde(default)]` (0 = bilinmiyor): bu alan
        /// olmadan üretilmiş eski/kuyrukta bekleyen paketler yine
        /// ayrıştırılır ve sıralama bilgisi olmadığından koşulsuz uygulanır
        /// (davranış regresyonu yok).
        #[serde(default)]
        edited_at_ms: u64,
    },
    Delete {
        target_message_id: String,
        #[serde(default)]
        group_id: Option<String>,
    },
    /// Spec dışı: node modu KAPALI cihazlarda sohbet geçmişi hiç
    /// arşivlenmediği için (bkz. lib.rs `archive_message`), o cihazlar için
    /// sohbet ekranı her zaman boş başlıyordu. Karşı taraf (chat peer) node
    /// modu açıksa zaten kendi tarafında bu konuşmanın her iki yönünü de
    /// arşivlemiştir — bu istek, doğrudan o arşivden son `limit` mesajı
    /// ister. Normal mesajlarla AYNI ratchet-şifreli kanaldan taşınır (yeni
    /// bir libp2p bağlantı/protokolüne gerek yok), yani uçtan uca korunur.
    HistorySyncRequest {
        limit: u32,
        /// Spec dışı, kullanıcı isteği (sonsuz kaydırma — eski geçmiş
        /// sayfalama): doluysa, YEREL arşivi tükenen isteyen tarafın en
        /// eski yüklü mesajından DAHA ESKİ mesajlar istenir (bkz. lib.rs
        /// `request_older_history`/`request_older_group_history`). `None`
        /// ise mevcut davranış: sohbet açılışında en YENİ `limit` mesaj
        /// istenir. Zaman damgaları her cihazın KENDİ arşivleme anını
        /// taşıdığından (bkz. `archive_message` notu) bu karşılaştırma
        /// gerçek gönderim anı değil, kabaca senkronize duvar saatine
        /// dayanır — mevcut sync mekanizmasıyla aynı varsayım.
        #[serde(default)]
        before_timestamp: Option<i64>,
        /// Spec dışı: doluysa bu bir GRUP geçmişi isteğidir — yanıtlayan
        /// taraf kendi 1:1 arşivi yerine bu `group_id`'nin grup arşivini
        /// arar. Grup mesajları pairwise fan-out olduğundan istek grubun
        /// HERHANGİ bir başka üyesine gönderilebilir (bkz.
        /// `request_older_group_history` — ulaşılabilir TÜM üyelere
        /// gönderilir, ilk yanıt veren boşluğu doldurur).
        #[serde(default)]
        group_id: Option<String>,
    },
    /// `request_id`: karşılık geldiği `HistorySyncRequest` paketinin
    /// `MessagePacketHeader.message_id`'si — isteyen tarafın, bu yanıtı
    /// ait olduğu isteğe eşleyip yeniden deneme kuyruğundan
    /// (`awaiting_confirmation`) çıkarabilmesi için (bkz. lib.rs
    /// güvenilir teslim notu). `messages`: eskiden yeniye sıralı —
    /// `direction` YANITLAYANIN bakış açısıyla ("sent"/"received")
    /// taşınır; isteyen taraf bunu ters çevirmeli (bkz. lib.rs
    /// receive_message HistorySyncResponse notu).
    HistorySyncResponse {
        request_id: String,
        messages: Vec<SyncedMessage>,
        /// bkz. `HistorySyncRequest.group_id` — isteği yansıtır, yanıtı
        /// doğru yerel arşive (1:1 mi, yoksa hangi grup mu) birleştirmek
        /// için.
        #[serde(default)]
        group_id: Option<String>,
        /// bkz. `HistorySyncRequest.before_timestamp` — dolu ise bu bir
        /// ESKİ SAYFA yanıtıdır: birleştirme mantığı mevcut "en yeniden
        /// daha yeni" eşiği yerine `message_id` bazlı var-olma kontrolü
        /// kullanır (bkz. lib.rs notu — sayfalama isteklerinde zaman
        /// damgası eşiği YANLIŞ yönde çalışırdı).
        #[serde(default)]
        before_timestamp: Option<i64>,
    },
    /// Spec dışı: güvenilir teslim onayı — gossipsub'un `publish()`
    /// başarısı SADECE yerel düğümün paketi ağa yayınladığını garanti
    /// eder, karşı tarafın GERÇEKTEN aldığını DEĞİL (bkz. lib.rs
    /// `awaiting_confirmation` dokümantasyonu). Alıcı taraf, `Text`
    /// (grup DIŞI)/`Edit`/`Delete`/`HistorySyncRequest` içeriğini
    /// başarıyla çözüp işlediğinde bu paketi gönderene geri gönderir;
    /// gönderen taraf bunu alana kadar aynı paketi (yeniden şifrelemeden)
    /// periyodik olarak tekrar yollamaya devam eder. Ack'in KENDİSİ ayrıca
    /// onaylanmaz (sonsuz döngüyü önlemek için) — kaybolursa, göndericinin
    /// asıl paketi tekrar göndermesi alıcının yeni bir Ack denemesi
    /// yapmasına zaten yol açar.
    Ack { target_message_id: String },
    /// Spec dışı: dosya/foto/video/ses eki meta verisi (spec bölüm 6
    /// "dosya transferi v0.1/v0.2 kapsamı DIŞINDA" notunu genişleten,
    /// kullanıcı tarafından istenen bir ek özellik, azami 4GB). Gerçek
    /// bayt içeriği BU paketle TAŞINMAZ — sadece küçük meta veri + bu
    /// dosyaya özel taze bir AEAD anahtarı (`file_key`), normal
    /// ratchet-şifreli mesaj kanalıyla taşınır. Gerçek baytlar ayrı bir
    /// libp2p `request_response` protokolü üzerinden parça parça (chunk)
    /// istenir/gönderilir (bkz. lib.rs/attachments.rs
    /// `FileChunkRequest`/`FileChunkResponse`).
    FileOffer {
        group_id: Option<String>,
        file_id: String,
        file_name: String,
        mime_type: String,
        total_size: u64,
        #[serde(with = "serde_bytes")]
        file_key: [u8; 32],
        sha256_hex: String,
        /// Spec dışı: foto/video ekleri için gönderen tarafın önceden
        /// oluşturduğu küçük bir önizleme kapağı (480p, %85 kalite JPEG —
        /// tipik olarak birkaç on KB). Diğer her şeyle AYNI ratchet-şifreli
        /// kanaldan taşınır (ayrı bir mesaj/round-trip icat edilmez) —
        /// alıcı tarafın TAM dosyayı hiç indirmeden bir önizleme
        /// gösterebilmesi için. `None` ise (dosya türü foto/video değil,
        /// veya önizleme oluşturulamadı) önizleme gösterilmez, sadece
        /// jenerik dosya simgesi.
        #[serde(with = "serde_bytes")]
        preview_jpeg: Option<Vec<u8>>,
        /// Spec disi: sesli mesajlar icin calma suresi (milisaniye).
        /// `None` ise sure bilinmiyor/uygulanamaz (or. siradan bir belge).
        duration_ms: Option<u32>,
        /// Spec dışı, kullanıcı isteği ("fotoğraf/eklenti/ses atarken de bir
        /// mesaj yanıtlanabilmeli ve altına bir yazı yazılabilmeli"):
        /// ek balonunun altında gösterilecek açıklama metni. Boş = yok.
        ///
        /// Ekle BİRLİKTE, aynı ratchet-şifreli pakette taşınıyor — ayrı bir
        /// metin mesajı göndermek iki ayrı balon üretir, sıraları
        /// karışabilir ve alıcıda ek ile yazının ilişkisi kaybolurdu.
        #[serde(default)]
        caption: String,
        /// bkz. `Text.reply_to_message_id` — AYNI anlam, ekler için.
        #[serde(default)]
        reply_to_message_id: Option<String>,
        #[serde(default)]
        reply_to_preview: Option<String>,
        #[serde(default)]
        reply_to_sender_identity_id: Option<String>,
        /// Bu dosyanin parca boyutu (bayt).
        ///
        /// Parca boyutu artik SABIT degil: yeni dosyalar 512 KiB kullaniyor
        /// (bkz. `attachments::FILE_CHUNK_SIZE_V2`), cunku her parca bir
        /// gidis-donus demek ve Tor'da gidis-donus 3-18 saniye. Boyutun
        /// teklifle TASINMASI sart: iki taraf ayni adimi kullanmazsa parca
        /// indeksleri kayar ve dosya bozulur.
        ///
        /// `#[serde(default)]` + `None` = 256 KiB: guncellenmemis bir esten
        /// gelen teklifte bu alan yok ve o aktarim miras boyutla yurur.
        #[serde(default)]
        chunk_size: Option<u32>,
    },
    /// Spec disi: yaziyor... gostergesi. Kasitli olarak Ack gibi
    /// arsivlenmez ve teslim-onayi kuyruguna (`awaiting_confirmation`)
    /// girmez -- birkac saniye icinde eskiyen bir bilgi icin tekrar
    /// denemenin hicbir degeri yok, en kotu ihtimalle bir sonraki
    /// tus vurusu zaten yeni bir paket gonderir.
    ///
    /// `group_id`: for group typing, fanned out via
    /// `send_group_typing_indicator` (same pattern as Edit/Delete). The
    /// event JSON carries `group_id` so GroupChatActivity can route it.
    TypingIndicator { is_typing: bool, #[serde(default)] group_id: Option<String> },
    /// Spec disi, kullanici tarafindan istenen "gorüldu" bildirimi --
    /// `Ack` ile AYNI desen (bkz. lib.rs `send_seen`/`send_ack`): ratchet-
    /// sifreli kanaldan gider, kendisi ayrica onaylanmaz (sonsuz döngü
    /// riski), bir kez gönderilir (güvenilir yol `ReadStateSync`). `Ack`'ten
    /// FARKI: "paket basariyla COZULDU" (teslim) degil, "kullanici EKRANDA
    /// GORDU" anlamina gelir -- alici tarafta otomatik degil, UI mesaji
    /// gosterdiginde tetiklenir.
    Seen {
        /// 1:1 sohbette: gorülen mesajin GERCEK `MessagePacketHeader.
        /// message_id`si. Grup sohbetinde: bu alan alicinin KENDI aldigi
        /// kopyanin id'si (gonderen tarafta anlamli degil, bkz.
        /// `group_message_local_id`).
        target_message_id: String,
        /// SADECE grup mesajlarinda dolu -- bkz. `Text.group_message_local_id`
        /// notu, gonderenin dogru balonu bulabilmesi icin gerekli.
        group_message_local_id: Option<String>,
    },
    /// Spec disi: PROFIL senkronizasyonu -- fotograf ve hesap adi. Merkezi
    /// bir dizin olmadigi icin (P2P), her taraf kendi profilini BILDIGI her
    /// kisiye ayri ayri gonderir -- yeni eslesme tamamlandiginda bir kez
    /// (bkz. process_identity_exchange) ve kullanici profilini
    /// degistirdiginde tum kisilere tekrar.
    ///
    /// Bu paket bir TAM GORUNTU (snapshot), delta degil: `avatar_jpeg:
    /// None` "fotograf kaldirildi" DEMEKTIR, "degismedi" degil. Bu yuzden
    /// `set_display_name` sadece ismi degistirse bile o anki avatari da
    /// gonderir (ve `set_own_profile_picture` o anki ismi) -- aksi halde
    /// isim degisikligi karsi tarafta fotografi sessizce silerdi.
    ProfileUpdate {
        #[serde(with = "serde_bytes")]
        avatar_jpeg: Option<Vec<u8>>,
        /// Kullanici istegi (2026-09-04): hesap adini degistirebilmek ve
        /// degisikligin kisilere OTOMATIK ulasmasi. Onceden bir kisinin
        /// adi, ilk `IdentityExchange`'teki `device_name` ile SABITLENIYOR
        /// ve bir daha asla degismiyordu.
        ///
        /// `#[serde(default)]`: bu alan olmadan uretilmis eski paketler
        /// ayristirilmaya devam eder (`None` = "isim tasimiyorum", yani
        /// alici mevcut ismi KORUR). Yeni surumun eski surume gonderdigi
        /// paketteki fazladan alan da karsida sessizce yok sayilir --
        /// ciborium struct varyantlarini map olarak kodlar ve bilinmeyen
        /// anahtarlari atlar.
        #[serde(default)]
        display_name: Option<String>,
    },
    /// Spec disi, guvenlik denetimi duzeltmesi: grup uyelik/isim/avatar
    /// degisiklikleri ONCEDEN cikta (bare) bir `NetworkEnvelope::GroupUpdate`
    /// olarak, SADECE Ed25519 imzali ve HIC sifrelenmeden gonderiliyordu --
    /// grup avatari/ismi gibi icerik acik metin olarak gossipsub'a
    /// yayilıyordu. Artik digerleriyle AYNI ratchet-sifreli kanaldan
    /// (hibrit X25519+ML-KEM) gidiyor; ic `GroupUpdate.signature`/
    /// `signature_pq` alanlari (kurucu yetkisini kanitlayan, tasima
    /// katmanindan BAGIMSIZ bir ikinci dogrulama) korunuyor.
    GroupUpdate(GroupUpdate),
    /// Spec dışı, kullanıcı isteği: bir üyenin (kurucu HARİÇ, bkz. lib.rs
    /// `leave_group`) gruptan kendi isteğiyle ayrılması. Sadece kurucunun
    /// üyelik değiştirebildiği yetki modeli (bkz. `validate_group_update`
    /// "NotFounder" kontrolü) BOZULMAZ — ayrılan üye bunu doğrudan bir
    /// `GroupChange::Remove` olarak İMZALAYIP yayınlamaz, bunun yerine bu
    /// isteği doğrudan (1:1 ratchet üzerinden) KURUCUYA gönderir; kurucu
    /// bunu alınca kendi `remove_from_group`'unu (zaten var olan, imzalı/
    /// yetkili üye çıkarma yolu) otomatik çağırıp gerçek `GroupChange::Remove`'u
    /// TÜM üyelere dağıtır. Ayrılan üyenin kendi cihazı ise, bu isteği
    /// gönderir göndermez YEREL grup kaydını iyimser (optimistic) olarak
    /// hemen kaldırır — kurucudan gelecek bir onaya beklemeden (zaten
    /// `remove_from_group` çıkarılan üyeye SON GroupUpdate'i göndermez,
    /// bkz. o fonksiyonun notu).
    LeaveGroupRequest { group_id: String },
    /// Spec dışı, ağ sağlamlığı düzeltmesi ("aynı LAN'da + Tor açık birden
    /// fazla cihazdan biri mobil veri+Tor'a geçince kimseye ulaşamıyor,
    /// hepsi offline görünüyor" hatası): göndericinin O ANKİ en iyi/güncel
    /// adresini (bkz. lib.rs `get_node_address` — Tor açık/hazırsa HER ZAMAN
    /// `.onion`) bilinen HER kişiye proaktif olarak bildirir. Önceden bir
    /// kişinin `.onion` adresi SADECE gerçekten Tor üzerinden bir bağlantı
    /// KURULURSA öğreniliyordu (`lib.rs` `record_peer_id_if_known`/
    /// `remember_device_addr`) — ama iki cihaz AYNI LAN'dayken (Tor İKİSİNDE
    /// de açık olsa bile) mDNS/doğrudan bağlantı neredeyse her zaman Tor
    /// devresinden daha hızlı kurulduğundan, Tor bağlantısı ARADA HİÇ
    /// FİİLEN kullanılmıyordu — yani `.onion` adresi hiçbir zaman
    /// öğrenilmemiş oluyordu. Sonra biri ağ değiştirdiğinde geriye
    /// düşülecek bilinen bir `.onion` adresi olmadığından yeniden bağlanma
    /// tamamen başarısız oluyordu. Bu paket, `lib.rs`
    /// `announce_address_to_all_contacts` tarafından üç anda gönderilir:
    /// `start_network` sonrası, Tor durumu "Ready"e GEÇTİĞİNDE (bootstrap +
    /// onion servisi yayına girdiğinde — genelde eşleşmeden DAKİKALAR sonra),
    /// ve bir ağ değişikliği bildiriminde — alıcı taraf gerçek bir Tor
    /// bağlantısı hiç kurulmamış olsa BİLE `.onion` adresini öğrenir.
    AddressAnnounce { multiaddr: String },
    /// Çoklu-cihaz (spec 1.5 adım 5 + 1.7): onaylayan (var olan) cihaz, yeni
    /// cihazla kurulan 1:1 ratchet üzerinden bunu gönderir. `device_add`,
    /// onaylayan cihazın İMZALADIĞI yetki belgesidir (yeni cihaz bunu saklar
    /// ve kişilere kendini tanıtırken kanıt olarak kullanır). `sync`, ilk tam
    /// senkron (kişiler + gruplar). Bare `NetworkEnvelope::DeviceAdd` yerine
    /// BURADA taşınır ki kişi listesi/grup verisi ratchet-şifreli + güvenilir-
    /// teslimli kanaldan gitsin (açık metin gossipsub'a sızmasın).
    DeviceLinkGrant {
        identity_id: String,
        device_add: DeviceAdd,
        sync: SyncPayload,
    },
    /// Çoklu-cihaz (spec 1.5 adım 5, kişilere yayım): "bu kimliğe yeni bir
    /// cihaz eklendi". Alıcı, `device_add.signature`'ı o kimliğin BİLİNEN
    /// AKTİF bir cihazının anahtarıyla doğrular; geçerliyse yeni cihazı
    /// (`device`, TAM public anahtarlarıyla) hem `known_devices`'a hem de
    /// `known_remote_devices`'a ekler — böylece o cihaza HEMEN mesaj fan-out
    /// edilebilir (ayrı bir `IdentityExchange`'in gelmesini BEKLEMEDEN; bu,
    /// bir kişi eşleşme anında çevrimdışıysa bile yönlendirmenin güvenilir
    /// biçimde propagate olmasını sağlar). `device.device_fingerprint`,
    /// `device_add.new_device_fingerprint`'e VE anahtarların hash'ine eşit
    /// olmalı — alıcı ikisini de doğrular.
    DeviceAddNotice { device_add: DeviceAdd, device: SyncedDevice },
    /// Çoklu-cihaz (spec 1.7.1): kardeş cihazlar arası "okundu" durumu
    /// senkronu — bir cihazda bir sohbet okunduğunda, diğer cihazlar da o
    /// sohbeti okunmuş sayar (aksi halde her cihaz ayrı ayrı okunmamış
    /// gösterir). SADECE gönderen kendi kimliğimin bir cihazıysa kabul
    /// edilir. `conversation_identity_id`: 1:1 sohbetin karşı tarafının
    /// kimliği; `group_id`: grup sohbeti. `read_at_ms`: okunma anı.
    /// Kasıtlı olarak güvenilir-teslim kuyruğuna girmez (Seen/TypingIndicator
    /// gibi — bir sonraki okumada yeniden gönderilir).
    ReadStateSync {
        #[serde(default)]
        conversation_identity_id: Option<String>,
        #[serde(default)]
        group_id: Option<String>,
        read_at_ms: u64,
    },
    /// Çoklu-cihaz (spec 1.6): imzalı cihaz iptali — kişilere ve kardeş
    /// cihazlara yayılır. Alıcı imzayı doğrulayıp o cihazı `Revoked` yapar.
    DeviceRevokeNotice(DeviceRevoke),
    /// Çoklu-cihaz (spec 1.7 delta senkron): var olan bir cihaz, kendi
    /// kimliğinin DİĞER (kardeş) cihazlarına güncel kişi/grup durumunu
    /// yeniden gönderir — ör. yeni bir kişi eklendiğinde. Alıcı idempotent
    /// birleştirir (bilinen bir cihazın anahtarlarını ezmez, sadece eksikleri
    /// ekler). `DeviceLinkGrant`'ın senkron kısmının tekrarlanabilir hâli.
    DeviceSync(SyncPayload),
    /// Çoklu-cihaz (spec 1.7): kendi gönderdiğim mesaj/düzenleme/silmenin
    /// kardeş cihazlarıma yankısı — bkz. `SiblingEchoBody`. SADECE gönderen
    /// kendi kimliğimin bir cihazıysa kabul edilir.
    SiblingEcho {
        /// 1:1 sohbette karşı tarafın kimliği (alıcı kardeş kendi kanonik
        /// cihaz anahtarına çevirir); grupta `None`.
        #[serde(default)]
        conversation_identity_id: Option<String>,
        /// Grup sohbetinde grup kimliği; 1:1'de `None`.
        #[serde(default)]
        group_id: Option<String>,
        body: SiblingEchoBody,
    },
    /// Çoklu-cihaz (spec 1.7): kardeş cihazdan son mesajları iste (yeniden
    /// bağlanma geri-doldurması). SADECE kendi kimliğimin cihazına gönderilir.
    ///
    /// Spec dışı, dış inceleme düzeltmesi ("sibling backfill sayfalama
    /// desteklemiyor"): önceden bu istek HER ZAMAN "tüm sohbetler, en
    /// yeni N" anlamına geliyordu — bir cihaz, ulaşılamayan bir KİŞİ
    /// yerine KENDİ diğer cihazından daha eski geçmiş isteyemiyordu (peer
    /// tarafının `HistorySyncRequest.before_timestamp`'i ile aynı
    /// sayfalama burada yoktu). Üç yeni alan (`#[serde(default)]` —
    /// eski/karşı sürümle geriye dönük uyumlu, hepsi `None` ise davranış
    /// TAMAMEN değişmez): `conversation_identity_id`/`group_id` doluysa
    /// istek TEK bir sohbete daralır, `before_timestamp` doluysa o
    /// sohbetin bu zaman damgasından ESKİ mesajları ister (sonsuz kaydırma
    /// sayfalaması, `HistorySyncRequest` ile AYNI anlam).
    SiblingHistoryRequest {
        per_conversation_limit: u32,
        #[serde(default)]
        conversation_identity_id: Option<String>,
        #[serde(default)]
        group_id: Option<String>,
        #[serde(default)]
        before_timestamp: Option<i64>,
    },
    /// bkz. `SiblingHistoryRequest` — kardeşin arşivinden son mesajlar.
    SiblingHistoryResponse { entries: Vec<SiblingHistoryEntry> },
    /// Gönderen HESABINI sildi (son cihazından). Kişiler: sohbeti "hesap
    /// silindi" olarak işaretler, artık mesaj göndermez; kurucusu olduğum
    /// gruplardan üyeyi çıkarırım. Kardeş cihazlar: kendi yerel durumunu siler.
    AccountDeleted {
        #[serde(default)]
        deleted_at_ms: u64,
    },
    /// Voice/video call signalling (see core `call.rs`). Ephemeral like
    /// `TypingIndicator`: never archived, never acked, never retried — a ring
    /// delivered a minute late is worthless, the receiver drops stale ones by
    /// `sent_at_ms`.
    ///
    /// `media_key`/`stream_id` are the SENDER's own media key (32 B) and
    /// stream id (8 B), carried on `Invite`/`Accept`. They travel inside the
    /// ratchet, so the media streams (which the server may relay) are
    /// end-to-end encrypted with keys the server never sees.
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
    },
}

/// See `MessageContent::Call`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallAction {
    Invite,
    Accept,
    Reject,
    Hangup,
    Busy,
}

/// El sıkışma paketi — önceki `HandshakeInit` tasarımı; spec'te ayrı bir
/// paket tipi olarak adlandırılmasa da 3.1'deki hibrit KEM adımını taşımak
/// için gereklidir (Kyber ciphertext'in karşı tarafa ulaşması şart).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub sender_identity_id: String,
    pub sender_device_fingerprint: String,
    #[serde(with = "serde_bytes")]
    pub initiator_x25519_pubkey: Vec<u8>,
    /// Initiator'ın bu oturum için ürettiği Kyber public key'i — responder
    /// bunu, ratchet.rs'teki DH/KEM rotasyon adımında "karşı tarafın bilinen
    /// Kyber public key'i" olarak saklamalıdır (yalnızca Kyber ciphertext
    /// taşımak yeterli değildir; responder'ın kendi rotasyonunu tetikleme
    /// hakkı için initiator'ın public key'ine de ihtiyacı vardır).
    #[serde(with = "serde_bytes")]
    pub initiator_kyber_pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kyber_ciphertext: Vec<u8>,
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
    pub signature_classical: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature_pq: Vec<u8>,
}

/// Spec 1.3: "fingerprint-only [...] bağlantı kurulunca karşı taraftan
/// indirilir ve bu `fingerprint` ile karşılaştırılır". QR/manuel eşleşme
/// sadece fingerprint taşıdığı için, bağlantı kurulunca tarafların gerçek
/// public key'lerini birbirine gönderip kendi fingerprint hesaplamasıyla
/// karşılaştırması gerekir — bu paket o adımı taşır.
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
    /// Spec dışı, hata düzeltmesi (kullanıcı: "özellikle ikincil
    /// cihazlardan gönderilen mesajlar çok sıkıntılı"): bu cihaz bir
    /// İKİNCİL cihazsa, birincil cihazın onu yetkilendiren İMZALI
    /// `DeviceAdd`'i.
    ///
    /// NEDEN GEREKLİ: alıcı taraf, tanımadığı bir cihazdan gelen paketi
    /// spec 2.2 gereği BLOKLAR ve kullanıcıya uyarı gösterir
    /// (`UnverifiedNewDeviceAlert`). "İmzalı zincirle sessizce kabul"
    /// (`NewDeviceViaSignedAdd`) yolu ise yalnızca `verified_device_adds`
    /// haritasına bakıyordu — yani SADECE daha önce ayrı bir
    /// `DeviceAddNotice` ULAŞMIŞSA. O bildirim ratchet üzerinden giden
    /// sıradan bir mesaj: kişi o sırada çevrimdışıysa yeniden deneme
    /// kuyruğunda bekliyor. Sonuç: ikincil cihazın mesajları, kişi
    /// bildirimi alana kadar sessizce bloklanıyordu — cihazda ölçüldü,
    /// kuyrukta 739 teslim edilememiş öğe birikmişti.
    ///
    /// İmzayı tanıtımın KENDİSİYLE taşımak bu bağımlılığı tamamen
    /// kaldırıyor: alıcı, imzayı zaten tanıdığı birincil cihazın
    /// anahtarıyla yerinde doğrulayabiliyor. Güvenlik modeli DEĞİŞMİYOR —
    /// doğrulama `apply_device_add_notice` ile AYNI (`verify_device_auth`
    /// + fingerprint/anahtar tutarlılığı); imzasız bir iddia hâlâ
    /// bloklanıyor.
    ///
    /// `#[serde(default)]`: bu alan olmadan üretilmiş eski paketler
    /// ayrıştırılmaya devam eder (`None` = birincil cihaz ya da eski sürüm).
    #[serde(default)]
    pub device_add: Option<DeviceAdd>,
}

/// Çoklu-cihaz (spec 1.7 mesaj geçmişi senkronu): kendi GÖNDERDİĞİM bir
/// mesajın/işlemin kardeş cihazlarıma "yankısı" — böylece bir cihazda
/// yazdığım mesaj/düzenleme/silme diğer cihazlarımda da görünür. Alınan
/// mesajlar zaten fan-out ile tüm cihazlara ulaştığından yankı SADECE
/// giden (benim) işlemler içindir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SiblingEchoBody {
    Text {
        /// 1:1'de `MessagePacketHeader.message_id` (kişinin kanonik cihazına
        /// giden kopyanın id'si), grupta `group_message_local_id` — kendi
        /// düzenleme/silmelerimin tüm cihazlarımda AYNI hedefe uygulanması için.
        message_id: String,
        text: String,
        sent_at_ms: u64,
        #[serde(default)]
        reply_to_message_id: Option<String>,
        #[serde(default)]
        reply_to_preview: Option<String>,
        #[serde(default)]
        reply_to_sender_identity_id: Option<String>,
    },
    Edit { target_message_id: String, new_text: String, #[serde(default)] edited_at_ms: u64 },
    Delete { target_message_id: String },
    /// bkz. `MessageContent::Reaction` — kendi bıraktığım tepki, diğer
    /// cihazlarımda da görünsün diye.
    Reaction { target_message_id: String, emoji: String, #[serde(default)] reacted_at_ms: u64 },
    /// Kendi gönderdiğim ek (1:1 ya da grup). `offer` her zaman bir
    /// `MessageContent::FileOffer`; kardeş dosyayı bu teklifle benden
    /// indirir. Önceden ekler hiç yankılanmıyordu — telefondan atılan foto
    /// laptopta hiç görünmüyordu.
    File { offer: Box<MessageContent> },
}

/// Çoklu-cihaz (spec 1.7 mesaj geçmişi senkronu — kardeşten geri-doldurma):
/// bir cihaz çevrimdışıyken KİŞİLERDEN gelen mesajları kaçırmış olabilir
/// (fan-out kopyası zaman aşımına uğradı). Yeniden bağlanınca bir kardeş
/// cihazdan son N mesajı ister; kardeş kendi arşivinden bunları gönderir.
/// Kararlı `message_id` (1:1 `conv_id` / grup `local_id`) ile tekrarlar
/// elenir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiblingHistoryEntry {
    /// 1:1 sohbette karşı tarafın kimliği (alıcı kendi kanonik cihazına
    /// çevirir); grupta `None`.
    #[serde(default)]
    pub conversation_identity_id: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    pub direction: String, // "sent" | "received"
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
    /// Gönderim anı — geri-doldurulan mesajlar da GÖNDERİM sırasına otursun.
    #[serde(default)]
    pub sent_at_ms: u64,
}

/// Ağdan gelen her şeyi taşıyan zarf — hangi varyant olduğunu ayırt etmek
/// için kullanılır.
///
/// Spec dışı, temizlik: `DeviceAdd`/`DeviceRevoke`/`GroupInvite`/`ReadReceipt`
/// varyantları (Aşama B taslağından kalan) buradan kaldırıldı — hiçbiri hiçbir
/// yerde ÜRETİLMİYORDU (bkz. eski `process_incoming_envelope` sessiz-yoksay
/// kolu) ve gerçek mekanizmalar tamamen farklı, çalışan bir yoldan gidiyor:
/// cihaz ekleme/iptali `MessageContent::DeviceAddNotice`/`DeviceRevokeNotice`
/// ile (DeviceAdd/DeviceRevoke STRUCT'ları hâlâ kullanılıyor, sadece bu ölü
/// zarf varyantları gitti), grup daveti `MessageContent::GroupUpdate(Add)`
/// ile, okundu bildirimi `MessageContent::Seen`/`ReadStateSync` ile — hepsi
/// ratchet-şifreli kanaldan. Bu ölü kollar dursaydı, ileride biri "spec'teki
/// ReadReceipt'i tamamlıyorum" sanıp bu asla çalışmayan zarfı doldurabilirdi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEnvelope {
    IdentityExchange(IdentityExchange),
    Handshake(HandshakeInit),
    Message(MessagePacket),
}

#[cfg(test)]
mod wire_size_tests {
    use super::*;

    /// Bayt alanları CBOR bayt bloğu olarak gitmeli. `serde_bytes` olmadan her
    /// bayt ayrı bir tam sayı olur ve paket ~1.9 kat büyür (cihazda mesaj
    /// başına ~15 KB ölçüldü).
    #[test]
    fn byte_fields_encode_as_cbor_bytes() {
        let raw: Vec<u8> = (0..=255u8).cycle().take(4000).collect();
        let packet = MessagePacket {
            header: MessagePacketHeader {
                sender_identity_id: String::new(),
                sender_device_fingerprint: String::new(),
                message_id: String::new(),
                ratchet_pubkey: raw.clone(),
                message_number: 0,
                prev_chain_length: 0,
                rotation_kyber_ciphertext: None,
            },
            ciphertext: raw.clone(),
            signature_classical: Vec::new(),
            signature_pq: raw.clone(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&NetworkEnvelope::Message(packet.clone()), &mut buf).unwrap();
        assert!(buf.len() < 3 * raw.len() + 512, "paket {} bayt", buf.len());
        let back: NetworkEnvelope = ciborium::from_reader(buf.as_slice()).unwrap();
        match back {
            NetworkEnvelope::Message(m) => assert_eq!(m.ciphertext, raw),
            _ => panic!(),
        }
    }
}
