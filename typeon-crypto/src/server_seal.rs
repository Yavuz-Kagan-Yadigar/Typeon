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
//! ## First contact
//!
//! `Handshake` and `IdentityExchange` go to a first-contact mailbox, before
//! a session exists. They are sealed with a key from the pairing (or link)
//! secret the mailbox id is made from, and inside that to the recipient
//! device's KEM keys when the sender has them (`seal_first_contact`). The
//! first IdentityExchange after reading a code has only the outer layer: the
//! code carries a fingerprint, not the keys.
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
/// Only for session topics (`p2p_rt_`, from the root key). A first-contact
/// box has no topic id: see `first_contact_mailbox_id`.
pub fn server_mailbox_id(topic: &str) -> String {
    let id: [u8; 16] = derive(topic.as_bytes(), b"p2pmsg-v0.1-server-mailbox")
        .expect("HKDF expand 16 bayt için asla başarısız olmaz");
    format!("mb_{}", hex::encode(id))
}

/// The first-contact mailbox of `device_fingerprint` for the holders of
/// `secret` (the nonce of a pairing or link code). The fingerprint alone,
/// which is public, gives no id.
pub fn first_contact_mailbox_id(secret: &[u8], device_fingerprint: &str) -> String {
    let info = [&b"p2pmsg-v0.5-first-contact-mailbox:"[..], device_fingerprint.as_bytes()].concat();
    let id: [u8; 16] = derive(secret, &info).expect("HKDF expand 16 bayt için asla başarısız olmaz");
    format!("mb_{}", hex::encode(id))
}

/// The relay address of one direction of a call: from the key the sender
/// seals that receiver's media with, which only those two devices hold.
pub fn relay_mailbox_id(pair_key: &[u8]) -> String {
    let id: [u8; 16] = derive(pair_key, b"p2pmsg-v0.5-call-relay-mailbox")
        .expect("HKDF expand 16 bayt için asla başarısız olmaz");
    format!("mb_{}", hex::encode(id))
}

/// Seeds (Ed25519, ML-DSA-87) of the key that signs `Register` for `mailbox`
/// (`server_proto::MailboxProof`). `secret` is what the readers of the box
/// hold and nobody else: the root key of a session box, the pair key of a
/// relay box, a device-only secret for a first-contact box.
pub fn mailbox_proof_seeds(secret: &[u8], mailbox: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let info = |tag: &[u8]| [tag, mailbox.as_bytes()].concat();
    Ok((
        derive(secret, &info(b"p2pmsg-v0.5-mailbox-proof-ed25519:"))?,
        derive(secret, &info(b"p2pmsg-v0.5-mailbox-proof-mldsa:"))?,
    ))
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

/// Seals an envelope for a first-contact mailbox (`Handshake`,
/// `IdentityExchange`, and anything sent before a session exists): the server
/// sees no identity metadata of a first contact.
///
/// Two layers. Outside, always: a key from `secret`, the pairing or link
/// secret the mailbox id is made from (`first_contact_mailbox_id`). Inside,
/// when the sender knows the recipient device's public KEM keys
/// (`recipient_kem`: X25519, ML-KEM-1024): a hybrid KEM to them
/// (`ratchet::kem_key_to`), so the code alone does not open it. Both layers
/// are bound to the mailbox, which is made from the recipient's fingerprint.
///
/// Plaintext of the outer layer: `0 || envelope`, or
/// `1 || KEM header || nonce || ciphertext`.
pub fn seal_first_contact(secret: &[u8], mailbox_id: &str, recipient_kem: Option<(&[u8], &[u8])>, envelope_cbor: &[u8]) -> Result<Vec<u8>, String> {
    let inner = match recipient_kem {
        Some((x25519_pubkey, kyber_pubkey)) => {
            let (key, header) = crate::ratchet::kem_key_to(x25519_pubkey, kyber_pubkey)?;
            let body = seal(key, mailbox_id.as_bytes(), envelope_cbor)?;
            [&[1u8][..], &header[..], &body[..]].concat()
        }
        None => [&[0u8][..], envelope_cbor].concat(),
    };
    seal(derive(secret, b"p2pmsg-v0.5-first-contact-seal")?, mailbox_id.as_bytes(), &inner)
}

/// `seal_first_contact`'s reverse. `own_x25519_secret`/`own_kyber_secret`:
/// the long-term KEM keys of the device the mailbox belongs to.
pub fn open_first_contact(
    secret: &[u8],
    mailbox_id: &str,
    own_x25519_secret: &x25519_dalek::StaticSecret,
    own_kyber_secret: &crate::ratchet::MlKem1024DecapsulationKey,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    let inner = open(derive(secret, b"p2pmsg-v0.5-first-contact-seal")?, mailbox_id.as_bytes(), sealed)?;
    match inner.split_first() {
        Some((&0, envelope)) => Ok(envelope.to_vec()),
        Some((&1, rest)) if rest.len() > crate::ratchet::KEM_HEADER_LEN => {
            let (header, body) = rest.split_at(crate::ratchet::KEM_HEADER_LEN);
            open(crate::ratchet::kem_key_from(own_x25519_secret, own_kyber_secret, header)?, mailbox_id.as_bytes(), body)
        }
        _ => Err("Bilinmeyen ilk temas mührü".to_string()),
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
    bucket: &str,
    sent_at_ms: u64,
    record_cbor: &[u8],
) -> Result<Vec<u8>, String> {
    seal(archive_record_key(archive_root_key, conv_key, record_id, rev)?, &archive_record_aad(bucket, sent_at_ms), record_cbor)
}

/// What the record's tag covers besides the body: the bucket it is stored in
/// (key generation, conversation, month) and the page stamp the server sorts
/// by. The record key already covers `record_id` and `rev`. A record moved to
/// another bucket, or served with another stamp, does not open.
fn archive_record_aad(bucket: &str, sent_at_ms: u64) -> Vec<u8> {
    let mut aad = bucket.as_bytes().to_vec();
    aad.extend_from_slice(&sent_at_ms.to_be_bytes());
    aad
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
    bucket: &str,
    sent_at_ms: u64,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    open(archive_record_key(archive_root_key, conv_key, record_id, rev)?, &archive_record_aad(bucket, sent_at_ms), sealed)
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
    fn first_contact_mailbox_needs_the_secret_and_the_fingerprint() {
        let fp = "a".repeat(64);
        let id = first_contact_mailbox_id(&[7; 16], &fp);
        assert_eq!(id, first_contact_mailbox_id(&[7; 16], &fp));
        assert_ne!(id, first_contact_mailbox_id(&[8; 16], &fp));
        assert_ne!(id, first_contact_mailbox_id(&[7; 16], &"b".repeat(64)));
        assert_ne!(id, server_mailbox_id(&format!("p2p_msg_{}", fp)));
        assert_ne!(mailbox_proof_seeds(&[7; 16], &id).unwrap(), mailbox_proof_seeds(&[8; 16], &id).unwrap());
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
    fn first_contact_seal_roundtrip() {
        use ml_kem::{EncodedSizeUser, KemCore};
        let x_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let x_public = x25519_dalek::PublicKey::from(&x_secret);
        let (kyber_secret, kyber_ek) = ml_kem::MlKem1024::generate(&mut OsRng);
        let kyber_public = kyber_ek.as_bytes();
        let payload = b"ilk temas zarfi";
        for kem in [None, Some((&x_public.as_bytes()[..], &kyber_public[..]))] {
            let sealed = seal_first_contact(&[7; 16], "mb_1", kem, payload).unwrap();
            assert_eq!(open_first_contact(&[7; 16], "mb_1", &x_secret, &kyber_secret, &sealed).unwrap(), payload);
            assert!(open_first_contact(&[8; 16], "mb_1", &x_secret, &kyber_secret, &sealed).is_err());
            assert!(open_first_contact(&[7; 16], "mb_2", &x_secret, &kyber_secret, &sealed).is_err());
        }
        // The KEM layer needs the device's keys, not only the code.
        let sealed = seal_first_contact(&[7; 16], "mb_1", Some((&x_public.as_bytes()[..], &kyber_public[..])), payload).unwrap();
        let (other_kyber, _) = ml_kem::MlKem1024::generate(&mut OsRng);
        assert!(open_first_contact(&[7; 16], "mb_1", &x_secret, &other_kyber, &sealed).is_err());
        // A clear envelope (the format before the seal) does not open.
        let clear = [&[0u8; 12][..], payload].concat();
        assert!(open_first_contact(&[7; 16], "mb_1", &x_secret, &kyber_secret, &clear).is_err());
    }

    #[test]
    fn archive_record_roundtrip() {
        let ark = [3u8; 32];
        let sealed = seal_archive_record(&ark, "conv-a", "msg-1", 7, "ar_x", 5, b"arsiv satiri").unwrap();
        assert_eq!(
            open_archive_record(&ark, "conv-a", "msg-1", 7, "ar_x", 5, &sealed).unwrap(),
            b"arsiv satiri"
        );
        // Her bilesen anahtara girmeli.
        assert!(open_archive_record(&[4u8; 32], "conv-a", "msg-1", 7, "ar_x", 5, &sealed).is_err());
        assert!(open_archive_record(&ark, "conv-b", "msg-1", 7, "ar_x", 5, &sealed).is_err());
        assert!(open_archive_record(&ark, "conv-a", "msg-2", 7, "ar_x", 5, &sealed).is_err());
        assert!(open_archive_record(&ark, "conv-a", "msg-1", 8, "ar_x", 5, &sealed).is_err());
        // The bucket and the page stamp are under the tag too.
        assert!(open_archive_record(&ark, "conv-a", "msg-1", 7, "ar_y", 5, &sealed).is_err());
        assert!(open_archive_record(&ark, "conv-a", "msg-1", 7, "ar_x", 6, &sealed).is_err());
    }

    #[test]
    fn archive_revisions_do_not_share_a_key() {
        // Duzenleme AYNI record_id'yi korur; rev anahtara girmeseydi bu iki
        // sifreleme ayni anahtari kullanirdi. Ayni acma anahtari ikisini de
        // acabiliyorsa nonce tekrari riski geri gelmis demektir.
        let ark = [5u8; 32];
        let v1 = seal_archive_record(&ark, "c", "m", 1, "b", 0, b"ilk hali").unwrap();
        let v2 = seal_archive_record(&ark, "c", "m", 2, "b", 0, b"duzeltilmis hali").unwrap();
        assert!(open_archive_record(&ark, "c", "m", 1, "b", 0, &v2).is_err());
        assert!(open_archive_record(&ark, "c", "m", 2, "b", 0, &v1).is_err());
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
