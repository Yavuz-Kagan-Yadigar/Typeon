//! Key bundles, device records, summaries and transfer state used by `P2PCore`.

use super::*;


// --- Yerel cihazın secret key'leri (asla ağa/DB'ye çıplak yazılmaz;
// export_recovery yolu hariç, o da şifreli) ---
/// How long a prekey is handed out before a new one is made.
pub(crate) const PREKEY_ROTATE_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// How long its secret half is kept: while it is handed out, plus the time a
/// HandshakeInit made with it can wait for this device (`HANDSHAKE_MAX_AGE_MS`),
/// plus a week for a peer that missed one rotation. After that the secret is
/// deleted, and what was sent to it can no longer be opened from this device.
pub(crate) const PREKEY_KEEP_MS: u64 = PREKEY_ROTATE_MS + HANDSHAKE_MAX_AGE_MS + 7 * 24 * 60 * 60 * 1000;

/// One of this device's prekeys with its secret half (`packet::SignedPrekey`).
pub(crate) struct OwnPrekey {
    pub(crate) signed: SignedPrekey,
    pub(crate) sk_x25519: StaticSecret,
    pub(crate) sk_mlkem: MlKem1024DecapsulationKey,
}

/// `OwnPrekey` as stored (CBOR, sealed with the local storage key).
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredPrekey {
    pub(crate) signed: SignedPrekey,
    #[serde(with = "serde_bytes")]
    pub(crate) sk_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) sk_mlkem: Vec<u8>,
}

pub(crate) struct DeviceKeys {
    pub(crate) sign_sk_ed25519: SigningKey,
    #[allow(dead_code)]
    pub(crate) sign_pk_ed25519: VerifyingKey,
    /// Kardeşleri (`sign_pk_ed25519`/`kem_pk_x25519`) gibi: bu iki AÇIK
    /// anahtar da yalnızca üretim anında fingerprint hesaplamak için
    /// kullanılıyor, sonrasında yetkili kopya `own_devices`
    /// (`DeviceRecord`) içinde duruyor. Struct'ta simetri ve okunabilirlik
    /// için tutuluyorlar; derleyicinin `dead_code` uyarısı bu yüzden
    /// susturuluyor (aynı gerekçe, aynı desen).
    #[allow(dead_code)]
    pub(crate) sign_pk_mldsa: MlDsaVerifyingKey<MlDsa87>,
    pub(crate) sign_sk_mldsa: MlDsaSigningKey<MlDsa87>,
    pub(crate) kem_sk_x25519: StaticSecret,
    #[allow(dead_code)]
    pub(crate) kem_pk_x25519: X25519PublicKey,
    #[allow(dead_code)]
    pub(crate) kem_pk_mlkem: MlKem1024EncapsulationKey,
    pub(crate) kem_sk_mlkem: MlKem1024DecapsulationKey,
}

/// Bir cihazın tüm secret key'lerini taşıyan, JNI sınırı üzerinden
/// Kotlin'e/Kotlin'den geçirilen paket. Rust bu bloğu ASLA diske yazmaz —
/// diske yazma/okuma sorumluluğu tamamen Kotlin tarafındadır
/// (KeystoreCrypto ile şifrelenip ayrı bir tabloya/dosyaya konur). Bu,
/// "Rust master şifreleme anahtarını hiç görmesin" ilkesini sağlar: Rust
/// sadece plaintext key üretir/tüketir, şifreleme/diske yazma Kotlin'in
/// işidir.
// `Debug` KASITLI OLARAK derive
// edilmiyor — bu struct dört ham secret key baytını taşıyor, `Debug`
// olsaydı ileride biri yanlışlıkla `error!("{:?}", bundle)` gibi bir satır
// eklerse uzun-vadeli kimlik anahtarları düz metin olarak Android logcat'e
// yazılabilirdi. Ayrıca `Drop` ile bellekten çıkarken sıfırlanıyor (bkz.
// Cargo.toml "zeroize" feature notu — tipli `DeviceKeys`/`DeviceRatchetState`
// için bu upstream crate'lerin kendi `ZeroizeOnDrop`'u hallediyor, ama bu
// struct ham `Vec<u8>` kullandığından elle yapılması gerekiyor).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SecretKeyBundle {
    pub(crate) device_fingerprint: String,
    #[serde(with = "serde_bytes")]
    pub(crate) sign_sk_ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) sign_sk_mldsa: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_sk_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_sk_mlkem: Vec<u8>,
}

impl Drop for SecretKeyBundle {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.sign_sk_ed25519.zeroize();
        self.sign_sk_mldsa.zeroize();
        self.kem_sk_x25519.zeroize();
        self.kem_sk_mlkem.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct DeviceRecord {
    pub(crate) device_fingerprint: String,
    pub(crate) identity_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) sign_pubkey_ed25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) sign_pubkey_mldsa: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_pubkey_x25519: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_pubkey_mlkem: Vec<u8>,
    pub(crate) device_name: String,
    pub(crate) is_active: bool,
    pub(crate) last_seen: u64,
}

/// Bir bağlantı kurulurken tespit edilen "cihaz değişikliği" durumunun
/// Kotlin tarafına iletilecek özeti (spec 2.2 uyarı ekranı).
// `Deserialize` EKLENDİ (bu ve aşağıdaki beş özet struct'ta): Linux masaüstü
// istemcisi (bkz. `api` modülü) bu tipleri JSON'dan GERİ okur — kendi ayna
// struct'larını tanımlasaydı, buradaki bir alan değişikliği orada sessizce
// kaybolurdu. Android tarafı bu derive'ı hiç kullanmaz.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAlertInfo {
    pub contact_display_name: String,
    pub identity_id: String,
    pub new_device_fingerprint: String,
    pub known_device_short_codes: Vec<String>,
    pub new_device_short_code: String,
}

/// Ayarlar'daki "bekleyen mesajlar" listesi
/// (bkz. `P2PCore::list_pending_messages`) için — `awaiting_confirmation`'da
/// hâlâ onay bekleyen, kullanıcının GERÇEKTEN yazdığı bir sohbet mesajı
/// (Edit/Delete/GroupUpdate gibi dahili paketler DEĞİL, bkz. o fonksiyonun
/// filtresi). `peer_device_fingerprint`/`group_id`, Kotlin tarafının zaten
/// sahip olduğu `listContacts()`/`listGroups()` ile isme çevrilir — burada
/// tekrar bir isim çözümleme mantığı icat edilmiyor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMessageSummary {
    pub message_id: String,
    pub peer_device_fingerprint: String,
    /// hedef CİHAZIN adı (bkz.
    /// `DeviceRecord.device_name`) — kişi/grup adı tek başına HANGİ
    /// cihazın hâlâ onay vermediğini söylemez (pairwise grup fan-out'unda
    /// her `PendingMessageSummary` tek bir üyenin tek bir cihazına karşılık
    /// gelir). Bilinmiyorsa (nadiren — cihaz kaydı silinmiş/iptal edilmiş
    /// olabilir) boş string; Kotlin tarafı bu durumda fingerprint
    /// kısaltmasına düşer.
    pub device_name: String,
    pub group_id: Option<String>,
    pub text: String,
    pub original_sent_at: u64,
    pub last_attempt_at: u64,
}

/// UI'nin kişi seçici listesi için kullandığı özet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactSummary {
    pub contact_id: String,
    pub display_name: String,
    pub identity_id: String,
    /// None ise: henüz IdentityExchange tamamlanmamış, mesaj gönderilemez.
    pub active_device_fingerprint: Option<String>,
    /// bu kişinin bize gönderdiği profil fotoğrafı (varsa),
    /// `list_attachments`'taki `preview_hex` ile AYNI hex-encode deseni —
    /// JSON ham ikili taşıyamadığı için.
    pub avatar_hex: Option<String>,
    /// Spec dışı, kullanıcı kararı (üyelerin otomatik tanıştırılması):
    /// `true` ise bu kişi yüz yüze QR/manuel eşleşmeyle DEĞİL, bir grup
    /// üzerinden KURUCU KEFALETİYLE eklendi — UI "grup üzerinden eklendi,
    /// doğrulanmadı" uyarısı gösterir (bkz. `GroupUpdate.member_devices`
    /// güvenlik notu).
    pub added_via_group: bool,
    /// Kişi hesabını sildi (`AccountDeleted`) — UI mesaj göndermeyi kapatır.
    #[serde(default)]
    pub account_deleted: bool,
}

/// Yerel şifreli arşivden çözülüp Kotlin'e döndürülen tek bir mesaj.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedMessage {
    pub direction: String, // "sent" | "received"
    pub text: String,
    pub timestamp: u64,
    /// GÖSTERİM/
    /// SIRALAMA için etkin zaman — göndericinin gönderim anı (`sent_at_ms`),
    /// bilinmiyorsa yerel `timestamp`'e düşülür. `timestamp` (yerel alınma
    /// anı) sync/sayfalama için ayrıca korunur. Kotlin tarafı balonları
    /// BUNA göre sıralar (gecikmeli teslim edilen bir mesaj, alınma değil
    /// GÖNDERİM sırasındaki yerine oturur).
    pub sent_at_ms: u64,
    /// Spec dışı, hata düzeltmesi ("kaydırılan mesajlar yanlışlıkla
    /// gönderildi gösteriliyor"): gönderim durumu artık gerçekten
    /// kalıcı — `Some("pending"|"sent"|"error")` bir "sent" (bizim
    /// gönderdiğimiz) satır için; alınan mesajlarda anlamsız (`None`).
    /// Eski (bu kolon eklenmeden önce yazılmış) satırlarda da `None` —
    /// Kotlin tarafı `None`'ı "sent" gibi ele alır (geriye dönük en
    /// güvenli varsayım, aksi halde eski satırlar sonsuza dek "pending"
    /// görünürdü).
    pub status: Option<String>,
    /// SADECE grup
    /// mesajlarında dolu — bir grupta birden fazla gönderen olabileceği
    /// için (1:1'in aksine, `direction` tek başına yeterli değil)
    /// GroupChatActivity'nin doğru gönderen adını/avatarını göstermesi
    /// için gerekli.
    pub sender_identity_id: Option<String>,
    /// bu satırın kararlı mesaj kimliği (varsa) — reload
    /// sonrası "seen" eşleşmesi ve durum güncellemeleri için (bkz.
    /// dosya başı "BİLİNEN SINIR" notu — artık kısmen çözüldü).
    pub message_id: Option<String>,
    /// Spec dışı, kullanıcı isteği (WhatsApp tarzı "sağa kaydırıp
    /// yanıtla"): bu mesajın yanıtladığı mesajın kararlı kimliği (1:1'de
    /// `message_id`, grupta `group_message_local_id`) — bkz. packet.rs
    /// `MessageContent::Text.reply_to_message_id` dokümantasyonu.
    pub reply_to_message_id: Option<String>,
    /// Yanıtlanan mesajın (gönderen tarafından gömülen, kırpılmış) metin
    /// özeti — Kotlin tarafı kendi arşivinde ayrıca aramaz.
    pub reply_to_preview: Option<String>,
    /// SADECE grup mesajlarında dolu — yanıtlanan mesajı gönderenin
    /// `identity_id`'si.
    pub reply_to_sender_identity_id: Option<String>,
    /// True if this message was deleted (see apply_delete_to_archive) — the
    /// archived text is stale/meaningless once this is set, Kotlin should
    /// render a deleted placeholder instead.
    pub is_deleted: bool,
    /// True once this message has been edited. Without it the "(edited)"
    /// marker was live-only on BOTH clients: the archive stored the new text
    /// but nothing recorded that it had changed, so reopening a chat quietly
    /// presented an edited message as if it were the original.
    pub is_edited: bool,
    /// The row came from a contact's 1:1 history answer (`mark_synced`).
    #[serde(default)]
    pub via_sync: bool,
    /// bu mesaja bırakılmış tepkilerin hazır
    /// özeti (ör. `"👍2 ❤️"`). Boş dize = tepki yok. Kotlin tarafı bunu
    /// olduğu gibi tepki pill'ine yazar — ayrıca bir sorgu yapmaz (bkz.
    /// `reactions_summary`).
    #[serde(default)]
    pub reactions: String,
    /// "seen mekanizması ve seen pp
    /// bubbles güvenilir değil, özellikle gruplarda"): bu mesajı kimlerin
    /// gördüğü — `reactions` ile AYNI "gömülü özet" deseni (bkz.
    /// `seen_by_json`), `[{"identity_id":..,"seen_at_ms":..}]`. Önceden bu
    /// bilgi HİÇ kalıcı değildi — sadece o an sohbet ekranı açıkken gelen
    /// canlı bir olaydı, kapalıyken/arka plandayken gelen her "görüldü"
    /// bildirimi sonsuza dek kayboluyordu.
    #[serde(default)]
    pub seen_by: String,
    /// Group rows: the author's signature, see `group_author_statement`.
    /// Carried in the server archive so a restored device can still hand
    /// the row on with the group history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_proof: Option<String>,
    /// Group rows: this message @mentions me (local only, see `mentions_me`
    /// column).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mentions_me: bool,
}

/// Groups tab GUI'sinin liste/detay göstermesi için özet (spec dışı —
/// `list_groups` yoktu, Groups tab'ı hiçbir zaman gerçek grup listesi
/// göstermiyordu).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSummary {
    pub group_id: String,
    pub name: String,
    pub founder_identity_id: String,
    pub is_founder: bool,
    pub member_identity_ids: Vec<String>,
    /// bkz. `ContactSummary.avatar_hex` aynı hex-encode deseni.
    pub avatar_hex: Option<String>,
}

/// Kotlin'e döndürülen, bir sohbetteki dosya eklerinin listesi (bkz.
/// `list_attachments` JNI export).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentSummary {
    pub file_id: String,
    pub file_name: String,
    pub mime_type: String,
    pub total_size: u64,
    pub direction: String, // "sent" | "received"
    pub status: String,    // "offered" | "downloading" | "complete" | "failed"
    pub bytes_transferred: u64,
    pub created_at: u64,
    /// `file_offer` poll olayındaki "preview_hex" ile AYNI biçim — Kotlin
    /// tarafı geçmişi yeniden kurarken küçük resmi hemen gösterebilsin diye
    /// (indirme beklemeden), bkz. `SimpleChatAdapter.AttachmentInfo`.
    pub preview_hex: Option<String>,
    /// Sesli mesajlar için çalma süresi (milisaniye) — bkz.
    /// `MessageContent::FileOffer.duration_ms`.
    pub duration_ms: Option<u32>,
    /// SADECE `list_group_attachments`
    /// tarafından doldurulur — grup içinde farklı ekler FARKLI göndericilerden
    /// gelebileceğinden (1:1'in aksine, orada zaten sorgunun kendisi tek bir
    /// peer'e sabit), `download_file`'ın "kimden indirileceğini" bilmesi için
    /// gerekli. `list_attachments` (1:1) için her zaman boş string.
    pub peer_device_fingerprint: String,
    /// SADECE grup eklerinde dolu
    /// — gönderen adını/avatarını göstermek için (bkz. `ArchivedMessage.
    /// sender_identity_id` AYNI gerekçe).
    pub sender_identity_id: Option<String>,
    /// ekle birlikte gönderilen açıklama ve
    /// (varsa) yanıtlanan mesajın bağlamı — sohbet yeniden açıldığında ek
    /// balonu bunları metin mesajlarıyla AYNI biçimde geri kurabilsin diye
    /// arşivden okunuyor (bkz. `files` tablosundaki aynı adlı kolonlar).
    #[serde(default)]
    pub caption: String,
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
    #[serde(default)]
    pub reply_to_preview: Option<String>,
    #[serde(default)]
    pub reply_to_sender_identity_id: Option<String>,
    /// Shown without a bubble frame, see `MessageContent::FileOffer.sticker`.
    #[serde(default)]
    pub sticker: bool,
}

/// Devam eden bir indirmenin bellek-içi durumu (bkz. `download_file`/
/// `request_next_chunk`/attachments.rs modül notu — parçalar HER ZAMAN
/// sırayla (0, 1, 2, ...) istenir, bu yüzden `.enc` dosyasına sadece
/// EKLEME (append) yapılır, seek gerekmez).
pub(crate) struct DownloadState {
    /// `FileOffer.chunk_hashes` of this file (from the `files` row): one
    /// SHA-256 per group of `per_hash` chunks, over their ciphertext.
    pub(crate) chunk_hashes: Vec<u8>,
    /// `attachments::chunks_per_hash` of this file.
    pub(crate) per_hash: u32,
    /// Chunks on disk whose group is not complete yet (only when `per_hash`
    /// > 1): the source that served each and its plaintext length. They move
    /// to `received_chunks` once the group hash matches.
    pub(crate) pending_chunks: std::collections::HashMap<u32, (PeerId, usize)>,
    /// Sources that served a chunk which did not match `chunk_hashes`: not
    /// asked again in this attempt.
    pub(crate) bad_sources: std::collections::HashSet<PeerId>,
    pub(crate) peer_id: PeerId,
    /// Bkz. `P2PCore::peer_for_file` — `file_progress`/`file_complete`/
    /// `file_failed` olaylarının `"peer"` alanını doldurmak için gerekli
    /// (bkz. o alanın eklenmesine yol açan hata: ChatActivity'nin olay
    /// dinleyicisi `"peer"` eşleşmezse olayı SESSİZCE YOK SAYIYOR —
    /// bu alan hiç doldurulmadığı için indirme Rust tarafında tamamen
    /// başarıyla bitse bile UI hiçbir zaman haberdar olmuyordu).
    pub(crate) peer_device_fingerprint: String,
    pub(crate) total_size: u64,
    pub(crate) total_chunks: u32,
    pub(crate) next_chunk_index: u32,
    pub(crate) bytes_done: u64,
    pub(crate) file_key: [u8; 32],
    pub(crate) enc_path: std::path::PathBuf,
    /// Son GERÇEK ilerlemenin (bir parçanın başarıyla alınıp yazıldığı an)
    /// olduğu an (hiç parça gelmediyse indirmenin başladığı an) — bkz.
    /// `DOWNLOAD_GIVE_UP_TIMEOUT_MS`. SADECE `handle_chunk_response`'ta
    /// gerçek veri alındığında güncellenir — `last_retry_at`'ın aksine,
    /// bu alan indirmenin ne kadar süredir hiç İLERLEMEDİĞİNİ (retry
    /// denemeleri SAYILMAZ) izler, "artık pes et" kararı için kullanılır.
    pub(crate) last_progress_at: u64,
    /// en son AYNI PARÇAYI yeniden
    /// istediğimiz an — bkz. `DOWNLOAD_STALL_TIMEOUT_MS`/
    /// `check_stalled_downloads`/`retry_or_give_up_download`. `last_progress_at`'tan
    /// AYRI tutulur: eğer ikisi AYNI alan olsaydı, bir yeniden deneme
    /// GERÇEK ilerleme olmadan bu alanı güncellemeyeceğinden (retry henüz
    /// yanıt almadı), `check_stalled_downloads` HER `poll_events` turunda
    /// (saniyede bir) yeniden tetiklenip aynı parçayı defalarca art arda
    /// isterdi — bu alan sayesinde denemeler `DOWNLOAD_STALL_TIMEOUT_MS`
    /// aralıklarla makul şekilde seyreltilir. TCP dial'ın hiç sonuçlanmadığı
    /// (ne başarı ne açık bir hata — özellikle iki cihaz da NAT arkasında
    /// olduğunda tipik bir durum) senaryoda `request_response`'un KENDİ
    /// hiçbir olay üretmediği durumları yakalamak için gerekli — o durumda
    /// libp2p katmanından ne bir yanıt ne de bir OutboundFailure/timeout
    /// hiç gelmez, indirme aksi hâlde SÜRESİZ "İndiriliyor" durumunda kalırdı.
    pub(crate) last_retry_at: u64,
    /// Spec dışı, dış inceleme düzeltmesi ("kaynak cihaz offline'ken dosya
    /// indirilemiyor, çoklu kaynak yok"): bu bir GRUP dosyasıysa (bkz.
    /// `download_file`), aynı dosyayı zaten TAMAMLAMIŞ olabilecek diğer
    /// üyelerin cihazları — mevcut kaynak tekrar tekrar başarısız/stall
    /// olursa (bkz. `retry_or_give_up_download`/`handle_chunk_response`
    /// `NotFound` kolu) sırayla denenir. Kimin GERÇEKTEN tamamladığını
    /// önceden BİLMİYORUZ (bir "kimde bu dosya var" duyurusu protokolde
    /// yok) — bu yüzden aday sırayla denenip `FileChunkResponse::NotFound`
    /// alınırsa bir sonrakine geçilir (zararsız: `serve_chunk_request`
    /// zaten dosya yoksa ANINDA/ucuz bu yanıtı döner).
    pub(crate) alt_source_peer_ids: std::collections::VecDeque<PeerId>,
    /// Mevcut `peer_id`de GERÇEK ilerleme olmadan kaç kez yeniden denendiği
    /// — bkz. `retry_or_give_up_download`, bir eşiği aşınca (varsa) bir
    /// sonraki adaya geçilir. Kaynak değiştiğinde/gerçek ilerlemede
    /// (bkz. `handle_chunk_response`) sıfırlanır.
    pub(crate) retries_on_current_source: u32,
    /// Şu an havada olan parça indeksleri — boru hattı (bkz.
    /// `DOWNLOAD_PIPELINE_DEPTH`). Önceden aynı anda TEK parça havada
    /// olabiliyordu, yani hız `parça_boyutu / gidiş-dönüş süresi` ile
    /// sınırlıydı; bant genişliği ne olursa olsun. Tor üzerinde ölçülen
    /// gerçek rakam ~70 KB/s'ydi.
    pub(crate) inflight_chunks: std::collections::HashSet<u32>,
    /// Diske YAZILMIŞ parçalar. Boru hattında parçalar sırasız geldiği için
    /// bir sayaç yetmez — hangi indeksin tamamlandığı tek tek tutulmalı.
    /// Only chunks whose group matched `chunk_hashes` are in it.
    pub(crate) received_chunks: std::collections::HashSet<u32>,
    /// Uyarlanır boru hattı penceresi (bkz. `DOWNLOAD_WINDOW_START`) — aynı
    /// anda kaç parçanın havada olabileceği. Başarıda büyür, hatada yarılanır.
    pub(crate) window: usize,
    /// Havadaki her parçanın istendiği an — gidiş-dönüş ölçümü için
    /// (bkz. `DOWNLOAD_RTT_TARGET_MS`). Yanıt/hata gelince silinir.
    pub(crate) chunk_sent_at: std::collections::HashMap<u32, u64>,
    /// Bu indirmede görülen EN KÜÇÜK gidiş-dönüş — yolun kuyruksuz taban
    /// gecikmesi; büyüme ölçütü buna GÖRE (bkz. `DOWNLOAD_RTT_GROW_FACTOR`).
    pub(crate) rtt_min: u64,
    /// İndirmenin başladığı an — yalnızca `finalize_download`'daki verim
    /// ölçüm günlüğü için (uyarlanır pencerenin işe yarayıp yaramadığı
    /// gerçek cihazda ancak böyle görülebiliyor).
    pub(crate) started_at: u64,
    /// `files.chunk_size` of this file, read once (bkz. `file_chunk_size`).
    pub(crate) chunk_size: usize,
    /// Ask for the missing chunks again at this time (0 = not set): a failed
    /// request, or a server that does not have the file yet. See
    /// `DOWNLOAD_RETRY_DELAY_MS`.
    pub(crate) retry_at: u64,
}

/// `poll_events`'in `RUNTIME.block_on` bloğu İÇİNDE (swarm borrow'u altında)
/// toplanıp, blok BİTTİKTEN SONRA (self'e serbestçe erişilebilecekken)
/// işlenen dosya-parça olayları — `incoming`/`new_listen_addrs`'in zaten
/// kullandığı "önce topla, sonra işle" deseninin aynısı (bkz. poll_events).
/// bkz. `ENVELOPE_PROTOCOL` — collected under the swarm borrow, handled after.
pub(crate) enum EnvelopeEventLocal {
    Delivered { request_id: request_response::OutboundRequestId },
    Failed { request_id: request_response::OutboundRequestId, error: String },
}

/// bkz. `ACK_PROTOCOL` — swarm borrow'u altında toplanıp sonra işlenir.
pub(crate) enum AckEventLocal {
    Request { peer: PeerId, ids: Vec<String>, channel: request_response::ResponseChannel<AckBatchResponse> },
    Delivered { request_id: request_response::OutboundRequestId },
    Failed { request_id: request_response::OutboundRequestId },
}

pub(crate) enum FileChunkEventLocal {
    /// `peer`: Noise ile KANITLANMIŞ istekçi — `serve_chunk_request`'in
    /// yetki kontrolü buna dayanıyor (bkz. o fonksiyon). Paketin İDDİA
    /// ettiği hiçbir alan yok, `is_established_peer`/sunucu hız sınırıyla
    /// aynı gerekçe.
    Request { peer: PeerId, request: FileChunkRequest, channel: request_response::ResponseChannel<FileChunkResponse> },
    Response { request_id: request_response::OutboundRequestId, response: FileChunkResponse },
    OutboundFailure { request_id: request_response::OutboundRequestId },
}

/// bkz. `try_publish_raw` — yayın hatasının yeniden denemeye DEĞER olup
/// olmadığını çağıranların ayırt edebilmesi için (güvenilirlik düzeltmesi:
/// önceden `MessageTooLarge` gibi kalıcı hatalar da 2 güne kadar boşuna
/// yeniden deneniyordu).
#[derive(Debug)]
pub(crate) enum PublishFailure {
    /// Geçici (mesh henüz oluşmadı, hiç abone yok, ağ başlatılmadı) —
    /// yeniden denemek anlamlı.
    Transient(String),
    /// Kalıcı — AYNI zarfı yeniden denemek ASLA başaramaz; çağıran hemen
    /// `Failed` sayıp kullanıcıya bildirmeli.
    Permanent(String),
}

/// Bir gönderilen mesajın ("bizim" mesajımızın) UI'da gösterilecek durumu —
/// spec dışı, kullanıcının istediği gönderim/hata ikonları için.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageSendStatus {
    /// `publish_envelope` henüz başarılı olmadı — `pending_envelopes`'te
    /// bekliyor, `poll_events` yeniden deniyor.
    Pending,
    /// gossipsub publish() başarıyla tamamlandı (bu, karşı tarafın FİİLEN
    /// aldığının garantisi DEĞİLDİR — sadece yerel düğümün mesajı ağa
    /// yayınladığının garantisidir; spec bir teslim onayı/ACK tanımlamıyor).
    Sent,
    /// `PENDING_ENVELOPE_TIMEOUT_MS` boyunca gönderilemedi, vazgeçildi.
    Failed,
    /// #85: a device of the peer (any member, in a group) sent the
    /// end-to-end Ack. Between sent and seen; seen lives in `message_seen`.
    Delivered,
}

impl MessageSendStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            MessageSendStatus::Pending => "pending",
            MessageSendStatus::Sent => "sent",
            MessageSendStatus::Failed => "error",
            MessageSendStatus::Delivered => "delivered",
        }
    }
}

/// Bkz. `P2PCore.awaiting_confirmation` dokümantasyonu.
/// BİLİNEN SINIR: bu paket, belirli bir ratchet zincir adımına (`ck_send`
/// durumuna) karşı şifrelendi — eğer bu peer'le olan oturum, onay
/// gelmeden ÖNCE bir DH/KEM rotasyonu yaşarsa (spec 3.2, 30 dakikada bir),
/// alıcı tarafın o eski zincire ait skipped-key önbelleği rotasyonda
/// TEMİZLENİR (bkz. ratchet.rs `perform_dh_ratchet`/`respond_to_rotation`
/// notu — bu, forward secrecy'nin doğal/istenen bir sonucu). Böyle bir
/// durumda bu retry artık kalıcı olarak çözülemez hâle gelir — pratikte
/// bu, "mesaj 30+ dakika boyunca hiç onaylanmadı" gibi nadir bir kenar
/// durumu (yaygın "karşı taraf birkaç saniye/dakika erişilemezdi" durumunu
/// ETKİLEMEZ). Tam çözüm (rotasyon algılandığında bekleyen paketleri YENİ
/// zincir altında yeniden şifreleyip AYNI message_id ile göndermek),
/// bilinçli olarak bu turun kapsamı dışında bırakıldı — forward-secrecy
/// mekanizmasıyla etkileşimi dikkatli test gerektirir.
pub(crate) struct PendingConfirmation {
    /// bkz. `KeepAliveState.suspect` — bu paket için bağlantı bir kez yoklandı mı.
    pub(crate) suspect_probed: bool,
    /// The peer confirmed receiving the bytes over `ENVELOPE_PROTOCOL`. A late
    /// Ack is then only latency (Tor round trips often exceed `ACK_SUSPECT_MS`),
    /// not a dead connection. Without this, every slow Ack marked the connection
    /// suspect: parallel dials, surplus connections closed, in-flight requests
    /// dropped, more slow Acks (device, 2026-09-18).
    pub(crate) direct_delivered: bool,
    /// Bu paketin şifrelendiği ZİNCİR KUŞAĞININ kimliği (kök anahtardan
    /// türetilen, gizli OLMAYAN 16 baytlık topic kimliği — zaten gossipsub
    /// topic adı olarak yayınlanıyor).
    ///
    /// Kullanıcı sorusu (2026-08-27): "25 dakikalık sınır her 30 dakikada bir
    /// sıfırlanıyor mu, yoksa 25/50/75 ile 30/60/90 arasındaki fark sürekli
    /// açılıp senkron bozuluyor mu?"
    ///
    /// Kalıcı bir bozulma YOKTU: tazeleme aslında olay güdümlü. Kendi
    /// rotasyonumuzda `maybe_rotate_ratchet` hemen ardından, karşı tarafın
    /// rotasyonunu öğrendiğimizde de `receive_message` içinde
    /// `regen_pending_for_peer` çalışıyor ve bekleyen her paket taze
    /// zincirle yeniden üretiliyor. 25 dakikalık sayaç yalnızca bir yedekti.
    ///
    /// AMA bir boşluk vardı: rotasyon duyurusu KAYBOLURSA o olay hiç
    /// gerçekleşmiyor ve paket, kendi bağımsız 25 dakikalık sayacı dolana
    /// kadar (en kötü ihtimalle 25 dakika) karşı tarafın artık çözemeyeceği
    /// bir zincirle yeniden denenip duruyordu. Bu damga o boşluğu kapatıyor:
    /// oturumun güncel kuşağı damgadan farklıysa paket ANINDA tazeleniyor,
    /// süre beklenmiyor. Böylece iki saat arasında "fark açılması" diye bir
    /// şey kalmıyor — ölçüt artık süre değil, kuşak eşitliği.
    pub(crate) chain_stamp: String,
    pub(crate) peer_device_fingerprint: String,
    /// Zaten şifrelenmiş/imzalanmış paket — her yeniden denemede AYNEN
    /// tekrar gönderilir, YENİDEN ŞİFRELENMEZ (ratchet'i tekrar
    /// ilerletmek, karşı tarafın "aynı mantıksal mesaj" olarak
    /// tanımasını imkansız kılardı — bkz. ratchet.rs simetrik zincir
    /// notu).
    pub(crate) envelope: NetworkEnvelope,
    pub(crate) next_retry_at: u64,
    pub(crate) retry_interval_ms: u64,
    /// Şu ANKİ deneme DÖNGÜSÜNÜN başladığı an — `regen_content` her
    /// tazelendiğinde (bkz. o alan) YENİ bir değere sıfırlanır (yeni
    /// ciphertext'in kendi 25 dakikalık penceresi başlar). "İlk kuyruğa
    /// girdiği an" için bkz. `original_sent_at` (O SIFIRLANMAZ).
    pub(crate) first_sent_at: u64,
    /// bu mesajın İLK KEZ kuyruğa girdiği an
    /// — `regen_content` tazelemeleri arasında SABİT kalır (bkz.
    /// `first_sent_at`'in aksine). `TEXT_RETRY_GIVE_UP_MS`'nin (7 gün)
    /// ölçtüğü budur — "karşı taraf günlerce çevrimdışı olsa bile mesaj
    /// hâlâ deneniyor mu" sorusunun cevabı, ciphertext'in kaçıncı
    /// rotasyon-döngüsünde olduğuyla değil, mesajın ne zaman
    /// YAZILDIĞIYLA ilgili. Ayrıca Ayarlar'daki bekleyen mesajlar
    /// listesinde (bkz. `list_pending_messages`) kullanıcıya gösterilir.
    pub(crate) original_sent_at: u64,
    /// EN SON gerçek bir gönderim denemesinin
    /// (başarılı olsun olmasın) yapıldığı an — Ayarlar'daki bekleyen
    /// mesajlar listesinde "son deneme: ..." olarak gösterilir. `next_retry_at`
    /// GELECEĞİ (bir sonraki deneme ne zaman) taşır, bu alan GEÇMİŞİ.
    pub(crate) last_attempt_at: u64,
    /// Spec dışı, kullanıcı geri bildirimi ("give up time bazı yerlerde
    /// sorun çıkarabilir, biri 6 saat interneti açmazsa ne olacak?"):
    /// `MAX_UNCONFIRMED_AGE_MS` dolduğunda AYNI (artık muhtemelen
    /// çözülemez) şifreli paketi tekrar göndermenin bir anlamı yok, ama
    /// PES ETMEK de yanlış — bazı içerik türleri için doğru davranış
    /// "orijinal düz metni YENİDEN şifreleyip (taze ratchet adımı, AYNI
    /// message_id ile — bkz. `send_message_content_inner`
    /// `message_id_override`) `TEXT_RETRY_GIVE_UP_MS`'ye kadar denemeye
    /// devam etmek". Kapsamı: Edit/Delete/GroupUpdate (UI'da mesaj başına
    /// görünür bir durum taşımadıklarından message_id değişse de sorun
    /// olmazdı, ama artık AYNI id korunuyor) VE — kullanıcı isteğiyle
    /// artık — sıradan `Text` (1:1 VE grup fan-out kopyaları): AYNI
    /// `message_id` korunduğundan UI balonu/`awaiting_confirmation` girdisi
    /// KESİNTİSİZ aynı kalır, `retryMessage(oldId,newId,status)` (manuel
    /// yeniden gönderim) akışıyla çakışmaz — o hâlâ SADECE gerçekten
    /// "Failed" (7 günü de aşmış) bir mesaj için kullanılabilir.
    pub(crate) regen_content: Option<MessageContent>,
}
