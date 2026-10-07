//! Sunucu yolu için İKİNCİ şifreleme katmanı ve kimlik körleştirme.
//!
//! Bu modül, `server_proto` ile birlikte `typeon-server/` crate'i tarafından
//! da kullanılır — ama sunucu SADECE körleştirme fonksiyonlarının VAR
//! olduğunu bilir, ANAHTARLARI asla görmez. Sunucu tarafında burada
//! kullanılabilen tek şey yoktur: bütün `seal_*`/`open_*` çağrıları istemci
//! tarafındadır. (Modül yine de `pub`, çünkü `server_proto` ile aynı
//! dosyada yaşamaları anlamsız olurdu ve testleri buraya ait.)
//!
//! ## Neden ikinci bir katman gerekiyor
//!
//! `MessagePacketHeader`, `sender_identity_id` ve `sender_device_fingerprint`
//! alanlarını AÇIK taşır (bkz. packet.rs). Gossipsub'da bu kabul edilebilir:
//! topic adı (`p2p_rt_<hkdf(root_key)>`) sözde-anonim olduğundan bir
//! gözlemci "X, opak T topic'ine yayın yaptı" görür, "X → Y" görmez. Ama bir
//! SUNUCU zarfı DİSKE yazıyor ve süresiz saklıyor — orada açık bir gönderen
//! fingerprint'i, sunucu operatörüne tam bir sosyal grafik hediye ederdi.
//!
//! Bu yüzden sunucuya giden her `Message` zarfı, iki tarafın ZATEN paylaştığı
//! `root_key`'den türetilen AYRI bir anahtarla bir kez daha AEAD'lenir.
//! Sunucu opak bayt görür.
//!
//! ## Kapsanmayan (dürüst artık risk)
//!
//! `Handshake` ve `IdentityExchange` MÜHÜRLENEMEZ: bunlar İLK temastır,
//! paylaşılan bir sır henüz yoktur, ve `QrPacket` v2 sadece fingerprint
//! taşır (tam ML-DSA-87 + ML-KEM-1024 public key'leri bir QR'a SIĞMIYOR,
//! bkz. `DeviceLinkRequest` v2 notu) — yani gönderen, alıcının public
//! key'lerine de sahip değildir. Bu zarflar sunucuya OKUNABİLİR ulaşır.
//! Bu, SECURITY.md'nin gossipsub posta kutusu topic'i için ZATEN belgelediği
//! artık riskin aynısıdır ve her yeni kişi başına BİR pakettir.
//!
//! ## Neden nonce rastgele (ratchet'in aksine)
//!
//! `ratchet.rs` nonce'u `message_number`'dan DETERMİNİSTİK türetiyor; orada
//! bu güvenli, çünkü her chain key altında her numara benzersiz. Burada öyle
//! bir sayaç YOK — aynı `root_key` altında keyfi sayıda zarf mühürlenebilir
//! (yeniden denemeler dahil). Sayaçsız determinizm nonce tekrarı = AEAD
//! felaketi demek olurdu, bu yüzden nonce 12 bayt rastgele ve şifre metninin
//! ÖNÜNE eklenir.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

/// Rastgele nonce uzunluğu (ChaCha20-Poly1305).
const NONCE_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Anahtar türetme
// ---------------------------------------------------------------------------

/// `ikm`'den `info` etiketiyle `N` baytlık bir alt anahtar (32) ya da
/// körleştirilmiş kimlik (16) türetir.
///
/// Dönen değer `Zeroizing` DEĞİL — çağıranlar kendi kapsamlarında
/// `zeroize()` çağırır (bu depoda `zeroize`, ratchet/DeviceKeys tarafında
/// aynı elle-çağrı deseniyle kullanılıyor).
fn derive<const N: usize>(ikm: &[u8], info: &[u8]) -> Result<[u8; N], String> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; N];
    hk.expand(info, &mut out).map_err(|_| "HKDF expand failed".to_string())?;
    Ok(out)
}

/// `nonce(12) || ciphertext` under `key`, which is wiped. The one framing of
/// this module (mailbox envelopes and archive records). `aad` is
/// authenticated, not stored: the opener must supply the same bytes.
fn seal(mut key: [u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();
    let mut out = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut out);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&out), Payload { msg: plaintext, aad })
        .map_err(|_| "Mühürlenemedi".to_string())?;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// `seal`'in tersi.
fn open(mut key: [u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();
    if sealed.len() <= NONCE_LEN {
        return Err("Mühürlü veri çok kısa".to_string());
    }
    cipher
        .decrypt(Nonce::from_slice(&sealed[..NONCE_LEN]), Payload { msg: &sealed[NONCE_LEN..], aad })
        .map_err(|_| "Mühür açılamadı (yanlış anahtar veya bozuk veri)".to_string())
}

// ---------------------------------------------------------------------------
// Kimlik körleştirme
// ---------------------------------------------------------------------------

/// Bir gossipsub topic adını sunucu posta kutusu kimliğine çevirir.
///
/// Girdi, `try_publish_raw`'ın ZATEN hesapladığı topic dizesidir —
/// `p2p_rt_<hex>` (ratchet oturumu var) veya `p2p_msg_<fingerprint>`
/// (ilk temas). Körleştirme İKİ nedenle şart:
///
/// 1. `p2p_msg_<fingerprint>` adı, alıcının device fingerprint'ini
///    DOĞRUDAN içerir — sunucu veritabanındaki tablo adlarından kimin
///    posta kutusu olduğu okunabilirdi.
/// 2. `p2p_rt_<hex>` zaten sözde-anonim, ama iki farklı sunucuda AYNI
///    değeri kullanmak, iki sunucunun kayıtlarını birleştirmeyi
///    kolaylaştırırdı. HKDF ayrıca bunları da ayırmaz — ama tek tip bir
///    isimlendirme, sunucunun "bu bir ilk temas kutusu mu, kurulmuş bir
///    oturum kutusu mu" ayrımını YAPAMAMASINI sağlar (uzunluk/önek
///    farkı kalmaz), ki bu tek başına faydalı bir gizlemedir.
///
/// KNOWN LIMIT: the id has no key. A server that knows a fingerprint (every
/// unsealed `Handshake`/`IdentityExchange` it stores names its sender)
/// computes that device's first-contact mailbox id, and so links the sender
/// of a first-contact deposit to its recipient. A keyed id needs a secret
/// both sides hold before first contact, and a fingerprint-only QR carries
/// none. Session mailboxes (`p2p_rt_`) come from the root key and stay blind.
pub fn server_mailbox_id(topic: &str) -> String {
    let id: [u8; 16] = derive(topic.as_bytes(), b"p2pmsg-v0.1-server-mailbox")
        .expect("HKDF expand 16 bayt için asla başarısız olmaz");
    format!("mb_{}", hex::encode(id))
}

/// Arşiv KOVA döngüsü — bir kova bu kadar ms'lik bir pencereyi kapsar (30 gün).
///
/// Neden sabit bir sohbet kimliği DEĞİL de aylık kova: sabit bir kimlik,
/// sunucunun TEK bir ilişkiyi yıllarca izleyebileceği KALICI bir tanıtıcı
/// olurdu. Aylık döndürme, pasif bir sunucu için kovaları birbirine
/// bağlanamaz kılıyor ve maliyeti neredeyse sıfır — üstelik kullanıcı
/// deneyimiyle de örtüşüyor ("daha eskisini yükle" ≈ bir ay geriye git).
///
/// Bedeli dürüstçe: sunucu, AYNI cihazın hangi kovaları yokladığını görür,
/// yani AKTİF bir sunucu için bu bağlanamazlık kaybolur. Gerçek çözüm
/// (kova başına anonim kimlik bilgisi + ayrı devre) kapsam dışı; bkz.
/// SECURITY.md.
pub const ARCHIVE_EPOCH_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Bir zaman damgasının hangi arşiv dönemine düştüğü.
pub fn archive_epoch_for(ts_ms: u64) -> u64 {
    ts_ms / ARCHIVE_EPOCH_MS
}

/// Sohbete özel arşiv anahtarı (CAK) — kök arşiv anahtarından (ARK) türer.
///
/// `conv_key`: 1:1 için karşı tarafın `identity_id`'si, grup için `group_id`.
/// KASITLI olarak `identity_id`, device fingerprint DEĞİL — karşı taraf
/// cihazını değiştirdiğinde (spec §2.2) arşivin okunabilirliği kaybolmasın
/// diye. The two kinds share this key space with no tag (a tag would orphan
/// every stored archive): the caller keeps them apart by format, a group id
/// is `group-<16 hex>` and an identity id 64 hex (lib.rs `process_group_update`).
fn conv_archive_key(archive_root_key: &[u8; 32], conv_key: &str) -> Result<[u8; 32], String> {
    let mut info = Vec::with_capacity(24 + conv_key.len());
    info.extend_from_slice(b"p2pmsg-v0.1-archive-conv");
    info.extend_from_slice(conv_key.as_bytes());
    derive(archive_root_key, &info)
}

/// Sunucu arşivinde bir sohbetin, BELLİ BİR DÖNEMDEKİ körleştirilmiş kova
/// kimliği.
///
/// ARK'a bağlı olduğundan, aynı grup FARKLI kimliklerin arşivinde farklı bir
/// kova alır — sunucu iki kullanıcının aynı grupta olduğunu kova
/// kimliklerinden ANLAYAMAZ.
pub fn server_archive_bucket(archive_root_key: &[u8; 32], conv_key: &str, epoch: u64) -> Result<String, String> {
    let mut cak = conv_archive_key(archive_root_key, conv_key)?;
    let mut info = Vec::with_capacity(26 + 8);
    info.extend_from_slice(b"p2pmsg-v0.1-archive-bucket");
    info.extend_from_slice(&epoch.to_be_bytes());
    let id = derive::<16>(&cak, &info);
    cak.zeroize();
    Ok(format!("ar_{}", hex::encode(id?)))
}

// NOT: Burada bir "blob kimliği körleştirme" fonksiyonu YOK, kasıtlı.
// Sunucudaki dosya ekleri, istemcilerin ZATEN konuştuğu
// `/p2pmessenger/filexfer/1.0.0` protokolüyle servis ediliyor (sunucu onu
// `ProtocolSupport::Inbound` ile kaydeder), yani sunucu sadece "başka bir
// kaynak eş". Bu, istemcideki bütün indirme durum makinesinin HİÇ
// DEĞİŞMEDEN yeniden kullanılmasını sağlıyor — ama `FileChunkRequest`
// `file_id` ile adresleniyor, dolayısıyla blob kimliği `file_id` OLMAK
// ZORUNDA. `file_id` zaten rastgele bir v4 UUID: sunucu için opak ve
// hiçbir sohbetle ilişkilendirilemez, yani ayrı bir körleştirmenin
// kazandıracağı bir şey de yok.

// ---------------------------------------------------------------------------
// Zarf mühürleme (posta kutusu)
// ---------------------------------------------------------------------------

/// Bir `NetworkEnvelope`'ın CBOR baytlarını, oturumun `root_key`'inden
/// türetilen anahtarla mühürler.
///
/// Çıktı: `nonce(12) || ciphertext`.
///
/// The seal is bound to the mailbox it is deposited in and to the device that
/// sent it (`sender_fp`): both ends of a session share the root key and the
/// mailbox, so without that the server could hand a deposit back to its own
/// sender, or move it to the session's other mailbox.
pub fn seal_envelope(root_key: &[u8], mailbox_id: &str, sender_fp: &str, envelope_cbor: &[u8]) -> Result<Vec<u8>, String> {
    seal(derive(root_key, b"p2pmsg-v0.1-server-seal")?, &envelope_aad(mailbox_id, sender_fp), envelope_cbor)
}

/// Neither part contains a 0 byte (`mb_<hex>`, hex fingerprint).
fn envelope_aad(mailbox_id: &str, sender_fp: &str) -> Vec<u8> {
    [mailbox_id.as_bytes(), b"\0", sender_fp.as_bytes()].concat()
}

/// `seal_envelope`'ın tersi.
///
/// Çağıran, ÖNCE güncel `root_key` ile, başarısız olursa `prev_root_key` ile
/// dener — `resubscribe_ratchet_topic`'in topic'ler için uyguladığı "bir
/// nesil geriyi de dinle" kuralının aynısı (karşı taraf bizim son
/// rotasyonumuzu henüz uygulamamış olabilir ve mühür ESKİ root_key'le
/// atılmış olabilir).
///
/// `mailbox_id`: the mailbox the item was fetched from; `sender_fp`: the
/// device at the other end of the session that owns `root_key`.
pub fn open_envelope(root_key: &[u8], mailbox_id: &str, sender_fp: &str, sealed: &[u8]) -> Result<Vec<u8>, String> {
    open(derive(root_key, b"p2pmsg-v0.1-server-seal")?, &envelope_aad(mailbox_id, sender_fp), sealed)
}

/// İlk-temas zarfları (`Handshake`/`IdentityExchange`) için "mühür" —
/// KASITLI OLARAK kimlik dönüşümü, gerçek bir şifreleme DEĞİL.
///
/// Modül başındaki "Kapsanmayan" notuna bakın: bu zarflar için paylaşılan
/// bir sır yoktur. Yine de sunucuya HAM CBOR göndermek yerine tek tip bir
/// çerçeveye sokuyoruz ki sunucunun kod yolu (ve `MailboxItem.sealed`
/// alanının sözleşmesi) tek olsun — sunucu "bu mühürlü mü değil mi" diye
/// bakmak zorunda kalmasın. Baştaki 12 sıfır bayt, `open_envelope`'ın
/// asla başarılı olamayacağı (ve `open_unsealed`'ın tanıyacağı) bir
/// işaretleyicidir.
///
/// Bu fonksiyonun HİÇBİR gizlilik iddiası YOKTUR. Adı bunu yansıtsın diye
/// `seal_` ÖNEKİ KULLANILMADI.
pub fn frame_unsealed(envelope_cbor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NONCE_LEN + envelope_cbor.len());
    out.extend_from_slice(&[0u8; NONCE_LEN]);
    out.extend_from_slice(envelope_cbor);
    out
}

/// `frame_unsealed`'ın tersi. `None` = bu öğe çerçevelenmemiş (yani gerçekten
/// mühürlü). ONLY for a mailbox that has no key (first contact): in a
/// session's mailbox an unsealed item is something the server put there.
pub fn open_unsealed(sealed: &[u8]) -> Option<&[u8]> {
    if sealed.len() > NONCE_LEN && sealed[..NONCE_LEN] == [0u8; NONCE_LEN] {
        Some(&sealed[NONCE_LEN..])
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Arşiv kaydı mühürleme (geçmiş)
// ---------------------------------------------------------------------------

/// Bir arşiv kaydının şifreleme anahtarı — sohbete VE revizyona özel.
///
/// `rev`'in anahtar türetmesine DAHİL olması güvenlik açısından zorunlu.
/// Kayıt kimliği (`record_id`) bir düzenleme/silme sırasında AYNI kalır
/// (sunucunun eskisinin üzerine yazabilmesi için); `rev` anahtara girmeseydi,
/// aynı `record_id`'nin iki farklı revizyonu AYNI anahtarla şifrelenirdi ve
/// sabit bir nonce ile bu doğrudan nonce tekrarı — ChaCha20-Poly1305 için
/// felaket (iki düz metnin XOR'u ve Poly1305 anahtar kurtarımı) olurdu.
/// Revizyon anahtara girince her revizyonun kendi anahtarı olur.
fn archive_record_key(
    archive_root_key: &[u8; 32],
    conv_key: &str,
    record_id: &str,
    rev: u64,
) -> Result<[u8; 32], String> {
    let mut cak = conv_archive_key(archive_root_key, conv_key)?;
    let mut info = Vec::with_capacity(26 + record_id.len() + 8);
    info.extend_from_slice(b"p2pmsg-v0.1-archive-record");
    info.extend_from_slice(record_id.as_bytes());
    info.extend_from_slice(&rev.to_be_bytes());
    let key = derive(&cak, &info);
    cak.zeroize();
    key
}

/// Bir arşiv satırını (CBOR'lanmış `ArchivedMessage`) mühürler.
///
/// Ratchet'in `root_key`'i yerine ARK türevi bir anahtar kullanılmasının
/// sebebi tek cümleyle: ratchet anahtarları İLERİ-GİZLİ ve kullanıldıktan
/// sonra SİLİNİYOR, yani geçen haftanın zarfı bugün ARTIK ÇÖZÜLEMEZ —
/// sunucudaki geçmişin, ratchet'ten BAĞIMSIZ, uzun ömürlü bir anahtarla
/// yeniden şifrelenmesi ŞART.
///
/// Bedeli dürüstçe: bu katman ileri-gizli DEĞİL. ARK bir gün sızarsa, o ana
/// kadar yüklenmiş TÜM geçmiş okunur. Bu yüzden sunucuda geçmiş saklama,
/// mesaj yönlendirmeden AYRI ve VARSAYILAN OLARAK KAPALI bir seçenektir.
/// (Bu, "yeni cihazımda geçmişimi göreyim" ile ileri-gizliliğin matematiksel
/// olarak uzlaşmaz olmasının kaçınılmaz sonucu — Signal SVR ve WhatsApp
/// şifreli yedeği de tam olarak aynı takası yapar.)
///
/// Nonce KASITLI olarak rastgele, deterministik değil: sunucu zaten
/// `(bucket, record_id)` birincil anahtarıyla dedup ediyor, dolayısıyla
/// bayt-eşitliğinden kazanılacak bir şey yok — buna karşılık sabit bir nonce,
/// ileride anahtar türetmesindeki bir hatayı doğrudan nonce tekrarına
/// çevirirdi.
pub fn seal_archive_record(
    archive_root_key: &[u8; 32],
    conv_key: &str,
    record_id: &str,
    rev: u64,
    record_cbor: &[u8],
) -> Result<Vec<u8>, String> {
    seal(archive_record_key(archive_root_key, conv_key, record_id, rev)?, b"", record_cbor)
}

/// `seal_archive_record`'un tersi. `rev`, sunucudan gelen `ArchiveRecord.rev`
/// alanıdır — anahtar türetmesine girdiği için doğru değerle çağrılmalı.
///
/// KNOWN LIMIT: this proves the record was sealed as revision `rev`, not that
/// `rev` is the newest. A server that kept an older revision can serve it,
/// and a device restoring from nothing cannot tell: an edited or deleted
/// message comes back in its old form. Only state the client keeps itself
/// (it skips records it already holds) stands against that.
pub fn open_archive_record(
    archive_root_key: &[u8; 32],
    conv_key: &str,
    record_id: &str,
    rev: u64,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    open(archive_record_key(archive_root_key, conv_key, record_id, rev)?, b"", sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_id_is_stable_and_hides_fingerprint() {
        let fp = "a".repeat(64);
        let topic = format!("p2p_msg_{}", fp);
        let id = server_mailbox_id(&topic);
        assert_eq!(id, server_mailbox_id(&topic), "aynı topic aynı kimliği vermeli");
        assert!(id.starts_with("mb_"));
        assert!(!id.contains(&fp), "fingerprint kutu adında görünmemeli");
        assert_ne!(id, server_mailbox_id("p2p_msg_other"));
    }

    #[test]
    fn envelope_seal_roundtrip() {
        let root_key = [7u8; 32];
        let payload = b"merhaba dunya";
        let sealed = seal_envelope(&root_key, "mb_1", "alice", payload).unwrap();
        assert_ne!(&sealed[12..], payload, "sifreli metin duz metne esit olmamali");
        let opened = open_envelope(&root_key, "mb_1", "alice", &sealed).unwrap();
        assert_eq!(opened, payload);
        // Finding 18: not in another mailbox, and not back to its sender
        // (who would open it as coming from the peer).
        assert!(open_envelope(&root_key, "mb_2", "alice", &sealed).is_err());
        assert!(open_envelope(&root_key, "mb_1", "bob", &sealed).is_err());
    }

    #[test]
    fn envelope_seal_rejects_wrong_key() {
        let sealed = seal_envelope(&[7u8; 32], "mb", "fp", b"gizli").unwrap();
        assert!(open_envelope(&[8u8; 32], "mb", "fp", &sealed).is_err());
    }

    #[test]
    fn envelope_seal_uses_fresh_nonce() {
        let root_key = [7u8; 32];
        let a = seal_envelope(&root_key, "mb", "fp", b"ayni girdi").unwrap();
        let b = seal_envelope(&root_key, "mb", "fp", b"ayni girdi").unwrap();
        assert_ne!(a, b, "ayni duz metin iki kez ayni sifreli metni vermemeli");
    }

    #[test]
    fn unsealed_frame_roundtrip() {
        let payload = b"ilk temas zarfi";
        let framed = frame_unsealed(payload);
        assert_eq!(open_unsealed(&framed), Some(&payload[..]));
        // Gerçek bir mühür, çerçevelenmiş sayılmamalı (nonce rastgele
        // olduğundan 12 sıfır bayt olma olasılığı ihmal edilebilir).
        let sealed = seal_envelope(&[1u8; 32], "mb", "fp", payload).unwrap();
        assert!(open_unsealed(&sealed).is_none());
    }

    #[test]
    fn archive_record_roundtrip() {
        let ark = [3u8; 32];
        let sealed = seal_archive_record(&ark, "conv-a", "msg-1", 7, b"arsiv satiri").unwrap();
        assert_eq!(
            open_archive_record(&ark, "conv-a", "msg-1", 7, &sealed).unwrap(),
            b"arsiv satiri"
        );
        // Her bilesen anahtara girmeli.
        assert!(open_archive_record(&[4u8; 32], "conv-a", "msg-1", 7, &sealed).is_err());
        assert!(open_archive_record(&ark, "conv-b", "msg-1", 7, &sealed).is_err());
        assert!(open_archive_record(&ark, "conv-a", "msg-2", 7, &sealed).is_err());
        assert!(open_archive_record(&ark, "conv-a", "msg-1", 8, &sealed).is_err());
    }

    #[test]
    fn archive_revisions_do_not_share_a_key() {
        // Duzenleme AYNI record_id'yi korur; rev anahtara girmeseydi bu iki
        // sifreleme ayni anahtari kullanirdi. Ayni acma anahtari ikisini de
        // acabiliyorsa nonce tekrari riski geri gelmis demektir.
        let ark = [5u8; 32];
        let v1 = seal_archive_record(&ark, "c", "m", 1, b"ilk hali").unwrap();
        let v2 = seal_archive_record(&ark, "c", "m", 2, b"duzeltilmis hali").unwrap();
        assert!(open_archive_record(&ark, "c", "m", 1, &v2).is_err());
        assert!(open_archive_record(&ark, "c", "m", 2, &v1).is_err());
    }

    #[test]
    fn archive_bucket_rotates_by_epoch_and_binds_to_ark() {
        let ark = [1u8; 32];
        let a = server_archive_bucket(&ark, "conv-x", 600).unwrap();
        assert_eq!(a, server_archive_bucket(&ark, "conv-x", 600).unwrap());
        assert_ne!(a, server_archive_bucket(&ark, "conv-x", 601).unwrap(), "donem degisince kova degismeli");
        assert_ne!(a, server_archive_bucket(&ark, "conv-y", 600).unwrap(), "farkli sohbet farkli kova");
        assert_ne!(a, server_archive_bucket(&[2u8; 32], "conv-x", 600).unwrap(), "farkli ARK farkli kova");
        assert!(a.starts_with("ar_"));
        assert!(!a.contains("conv-x"));
    }

    #[test]
    fn archive_epoch_boundaries() {
        assert_eq!(archive_epoch_for(0), 0);
        assert_eq!(archive_epoch_for(ARCHIVE_EPOCH_MS - 1), 0);
        assert_eq!(archive_epoch_for(ARCHIVE_EPOCH_MS), 1);
    }

}
