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
    pub signature: Vec<u8>,
}

/// Cihaz iptali (spec 1.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRevoke {
    pub identity_id: String,
    pub revoked_device_fingerprint: String,
    /// İptali yapan cihazın fingerprint'i.
    pub revoked_by: String,
    pub signature: Vec<u8>,
}

/// Okundu bildirimi (spec 1.7.1) — normal mesaj trafiğinin parçası olarak
/// şifrelenip imzalanarak gönderilir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadReceipt {
    pub message_id: String,
    pub read_by_identity: String,
    pub read_at: u64,
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
    AvatarUpdate(Option<Vec<u8>>),
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
    pub sign_pubkey_ed25519: Vec<u8>,
    pub sign_pubkey_mldsa: Vec<u8>,
    pub kem_pubkey_x25519: Vec<u8>,
    pub kem_pubkey_mlkem: Vec<u8>,
    /// Kurucunun bildiği son adres — dial ipucu (bkz. lib.rs
    /// `device_last_addr`). Yoksa alıcı mDNS/röle/DHT'ye güvenir.
    #[serde(default)]
    pub last_addr: Option<String>,
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
    pub signature: Vec<u8>,
    /// Spec dışı: ML-DSA (post-kuantum) imza — önceden bu alan yoktu ve
    /// GroupUpdate SADECE Ed25519 ile korunuyordu (MessagePacket/
    /// HandshakeInit'teki hibrit modelle tutarsızdı, bkz. güvenlik
    /// denetimi). Artık MessagePacket ile AYNI hibrit doğrulama
    /// (`verify_hybrid_signature`, HER İKİ imza da zorunlu) uygulanıyor.
    pub signature_pq: Vec<u8>,
}

/// Grup daveti (spec 5.4) — kurucudan davet edilen kişiye, var olan/o an
/// kurulan 1:1 bağlantı üzerinden gönderilir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInvite {
    pub group_id: String,
    pub group_name: String,
    pub founder_identity_id: String,
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
    pub rotation_kyber_ciphertext: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePacket {
    pub header: MessagePacketHeader,
    /// AEAD (ChaCha20-Poly1305) şifreli içerik; nonce, header'dan
    /// deterministik türetilir (message_number bazlı) — ayrıca taşınmaz.
    /// Çözüldükten sonra bir `MessageContent` olarak CBOR-decode edilir.
    pub ciphertext: Vec<u8>,
    /// ML-DSA + Ed25519 hibrit imza (header+ciphertext üzerinde).
    pub signature_classical: Vec<u8>,
    pub signature_pq: Vec<u8>,
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
    },
    Edit { target_message_id: String, new_text: String },
    Delete { target_message_id: String },
    /// Spec dışı: node modu KAPALI cihazlarda sohbet geçmişi hiç
    /// arşivlenmediği için (bkz. lib.rs `archive_message`), o cihazlar için
    /// sohbet ekranı her zaman boş başlıyordu. Karşı taraf (chat peer) node
    /// modu açıksa zaten kendi tarafında bu konuşmanın her iki yönünü de
    /// arşivlemiştir — bu istek, doğrudan o arşivden son `limit` mesajı
    /// ister. Normal mesajlarla AYNI ratchet-şifreli kanaldan taşınır (yeni
    /// bir libp2p bağlantı/protokolüne gerek yok), yani uçtan uca korunur.
    HistorySyncRequest { limit: u32 },
    /// `request_id`: karşılık geldiği `HistorySyncRequest` paketinin
    /// `MessagePacketHeader.message_id`'si — isteyen tarafın, bu yanıtı
    /// ait olduğu isteğe eşleyip yeniden deneme kuyruğundan
    /// (`awaiting_confirmation`) çıkarabilmesi için (bkz. lib.rs
    /// güvenilir teslim notu). `messages`: (direction, text, timestamp)
    /// üçlüleri, eskiden yeniye sıralı — `direction` YANITLAYANIN bakış
    /// açısıyla ("sent"/"received") taşınır; isteyen taraf bunu ters
    /// çevirmeli (bkz. lib.rs receive_message HistorySyncResponse notu).
    HistorySyncResponse { request_id: String, messages: Vec<(String, String, u64)> },
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
        preview_jpeg: Option<Vec<u8>>,
        /// Spec disi: sesli mesajlar icin calma suresi (milisaniye).
        /// `None` ise sure bilinmiyor/uygulanamaz (or. siradan bir belge).
        duration_ms: Option<u32>,
    },
    /// Spec dışı: kullanıcı tarafından istenen "kaydetme onayı" akışı.
    /// Alıcı taraf, indirilmiş bir eki kalıcı/paylaşılan bir konuma
    /// ("İndirilenler/P2P") kopyalamak istediğinde önce göndericiye bu
    /// isteği yollar — gönderici onaylamadan dosya uygulamanın kendi
    /// özel (app-private) alanından ÇIKMAZ.
    SaveRequest { file_id: String, file_name: String },
    /// Göndericinin `SaveRequest`'e cevabı.
    SaveApproval { file_id: String, approved: bool },
    /// Spec disi: yaziyor... gostergesi. Kasitli olarak Ack gibi
    /// arsivlenmez ve teslim-onayi kuyruguna (`awaiting_confirmation`)
    /// girmez -- birkac saniye icinde eskiyen bir bilgi icin tekrar
    /// denemenin hicbir degeri yok, en kotu ihtimalle bir sonraki
    /// tus vurusu zaten yeni bir paket gonderir.
    TypingIndicator { is_typing: bool },
    /// Spec disi, kullanici tarafindan istenen "gorüldu" bildirimi --
    /// `Ack` ile AYNI desen (bkz. lib.rs `send_seen`/`send_ack`): ratchet-
    /// sifreli kanaldan gider, kendisi ayrica onaylanmaz (sonsuz döngü
    /// riski), sinirli sayida kendi-kendine yeniden dener. `Ack`'ten
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
    /// Spec disi: profil fotografi senkronizasyonu. Merkezi bir dizin
    /// olmadigi icin (P2P), her taraf kendi fotografini BILDIGI her
    /// kisiye ayri ayri gonderir -- yeni eslesme tamamlandiginda bir kez
    /// (bkz. process_identity_exchange) ve kullanici fotografini
    /// degistirdiginde tum kisilere tekrar. `None` = fotograf kaldirildi.
    ProfileUpdate { avatar_jpeg: Option<Vec<u8>> },
    /// Spec disi, guvenlik denetimi duzeltmesi: grup uyelik/isim/avatar
    /// degisiklikleri ONCEDEN cikta (bare) bir `NetworkEnvelope::GroupUpdate`
    /// olarak, SADECE Ed25519 imzali ve HIC sifrelenmeden gonderiliyordu --
    /// grup avatari/ismi gibi icerik acik metin olarak gossipsub'a
    /// yayilıyordu. Artik digerleriyle AYNI ratchet-sifreli kanaldan
    /// (hibrit X25519+ML-KEM) gidiyor; ic `GroupUpdate.signature`/
    /// `signature_pq` alanlari (kurucu yetkisini kanitlayan, tasima
    /// katmanindan BAGIMSIZ bir ikinci dogrulama) korunuyor.
    GroupUpdate(GroupUpdate),
}

/// El sıkışma paketi — önceki `HandshakeInit` tasarımı; spec'te ayrı bir
/// paket tipi olarak adlandırılmasa da 3.1'deki hibrit KEM adımını taşımak
/// için gereklidir (Kyber ciphertext'in karşı tarafa ulaşması şart).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub sender_identity_id: String,
    pub sender_device_fingerprint: String,
    pub initiator_x25519_pubkey: Vec<u8>,
    /// Initiator'ın bu oturum için ürettiği Kyber public key'i — responder
    /// bunu, ratchet.rs'teki DH/KEM rotasyon adımında "karşı tarafın bilinen
    /// Kyber public key'i" olarak saklamalıdır (yalnızca Kyber ciphertext
    /// taşımak yeterli değildir; responder'ın kendi rotasyonunu tetikleme
    /// hakkı için initiator'ın public key'ine de ihtiyacı vardır).
    pub initiator_kyber_pubkey: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>,
    pub timestamp: u64,
    pub signature_classical: Vec<u8>,
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
    pub sign_pubkey_ed25519: Vec<u8>,
    pub sign_pubkey_mldsa: Vec<u8>,
    pub kem_pubkey_x25519: Vec<u8>,
    pub kem_pubkey_mlkem: Vec<u8>,
}

/// Ağdan gelen her şeyi taşıyan zarf — hangi varyant olduğunu ayırt etmek
/// için kullanılır.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEnvelope {
    IdentityExchange(IdentityExchange),
    Handshake(HandshakeInit),
    Message(MessagePacket),
    DeviceAdd(DeviceAdd),
    DeviceRevoke(DeviceRevoke),
    GroupInvite(GroupInvite),
    ReadReceipt(ReadReceipt),
}
