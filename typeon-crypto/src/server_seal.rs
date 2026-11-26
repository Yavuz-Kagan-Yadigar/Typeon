//! Second encryption layer for the server path, and identity blinding.
//!
//! `server_proto` uses this module, and so does the `typeon-server` crate. The
//! server only has the blinding functions. It never has the keys: every
//! `seal_*` and `open_*` call runs on the client.
//!
//! ## Why a second layer
//!
//! `MessagePacketHeader` carries `sender_identity_id` and
//! `sender_device_fingerprint` in plain text (see packet.rs). That is fine on
//! the direct path, inside the Noise-encrypted peer connection. A server, however, writes
//! envelopes to disk and keeps them. A plain sender fingerprint there would
//! give the operator the full social graph.
//!
//! So every envelope sent to the server is AEAD-sealed once more, with a key
//! derived from the `root_key` both peers already share. The server sees
//! opaque bytes.
//!
//! ## First contact
//!
//! `Handshake` and `IdentityExchange` go to a first-contact mailbox, before a
//! session exists. They are sealed with a key from the pairing (or link)
//! secret that the mailbox id is derived from. Inside that, they are sealed to
//! the recipient device's KEM keys when the sender has them
//! (`seal_first_contact`). The first `IdentityExchange` after reading a code
//! has only the outer layer, because the code carries a fingerprint, not keys.
//!
//! ## Why the nonce is random (unlike the ratchet)
//!
//! `ratchet.rs` derives its nonce deterministically from `message_number`. That
//! is safe there because each message number is unique under a chain key. This
//! module has no such counter: any number of envelopes can be sealed under one
//! `root_key`, including retries. A deterministic nonce here would risk nonce
//! reuse, so the nonce is 12 random bytes prepended to the ciphertext.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

/// Random nonce length (ChaCha20-Poly1305).
const NONCE_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derives a 32-byte subkey from `ikm` with the label `info`, or a 16-byte
/// blinded identity.
///
/// The result is not `Zeroizing`. Callers call `zeroize()` in their own scope,
/// as the ratchet and `DeviceKeys` code does.
fn derive<const N: usize>(ikm: &[u8], info: &[u8]) -> Result<[u8; N], String> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; N];
    hk.expand(info, &mut out).map_err(|_| "HKDF expand failed".to_string())?;
    Ok(out)
}

/// Seals `plaintext` under `key` (wiped afterwards) and returns
/// `nonce(12) || ciphertext`. This is the single framing for mailbox envelopes
/// and archive records. `aad` is authenticated but not stored, so the opener
/// must supply the same bytes.
fn seal(mut key: [u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();
    let mut out = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut out);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&out), Payload { msg: plaintext, aad })
        .map_err(|_| "Could not seal".to_string())?;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Inverse of `seal`.
fn open(mut key: [u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();
    if sealed.len() <= NONCE_LEN {
        return Err("Sealed data too short".to_string());
    }
    cipher
        .decrypt(Nonce::from_slice(&sealed[..NONCE_LEN]), Payload { msg: &sealed[NONCE_LEN..], aad })
        .map_err(|_| "Seal could not be opened (wrong key or corrupt data)".to_string())
}

// ---------------------------------------------------------------------------
// Length padding
// ---------------------------------------------------------------------------

/// Smallest padded plaintext. Acks, receipts and short texts all look the same.
const MIN_PADDED_LEN: usize = 512;
/// AEAD tag added by `seal`.
const TAG_LEN: usize = 16;
/// Largest padded plaintext of a mailbox item: its sealed form still fits `MAX_DEPOSIT_BYTES`.
const ENVELOPE_PAD_CAP: usize = crate::server_proto::MAX_DEPOSIT_BYTES - NONCE_LEN - TAG_LEN;
/// Same for one archive record, whose budget is half the wire cap (`server_client/archive.rs`).
const ARCHIVE_PAD_CAP: usize = crate::server_proto::MAX_DEPOSIT_BYTES / 2 - NONCE_LEN - TAG_LEN;

/// Padmé (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and
/// Communication with PURBs", 2019). Rounds `len` up so that only O(log log len)
/// bits of it remain. The overhead is at most about 12 %, and smaller for big items.
fn padme(len: usize) -> usize {
    if len < 2 {
        return len;
    }
    let e = usize::BITS - 1 - len.leading_zeros(); // floor(log2 len)
    let s = u32::BITS - e.leading_zeros(); // floor(log2 e) + 1
    let mask = (1usize << (e - s)) - 1;
    (len + mask) & !mask
}

/// `plaintext || 0x80 || 0x00..`, padded to the Padmé size (at least
/// `MIN_PADDED_LEN`), but never past `cap` unless the data alone is longer.
fn pad(plaintext: &[u8], cap: usize) -> Vec<u8> {
    let len = plaintext.len() + 1;
    let target = padme(len).max(MIN_PADDED_LEN).min(cap).max(len);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(target, 0);
    out
}

/// Inverse of `pad`.
fn unpad(mut padded: Vec<u8>) -> Result<Vec<u8>, String> {
    let end = padded.iter().rposition(|&b| b != 0).ok_or("Bad padding")?;
    if padded[end] != 0x80 {
        return Err("Bad padding".to_string());
    }
    padded.truncate(end);
    Ok(padded)
}

// ---------------------------------------------------------------------------
// Identity blinding
// ---------------------------------------------------------------------------

/// Secret of the server mailbox that `recipient_fp` reads for mail from
/// `sender_fp` in one session: one box per device and direction. The recipient
/// registers only this box (its inbound one); the sender deposits into it
/// anonymously and never registers it, so the server cannot join the two ends of
/// a pair through a shared box. Both ends can compute it. The box's proof key
/// comes from it (`mailbox_proof_seeds`), the id from that key
/// (`server_proto::key_bound_mailbox_id`), and the deposit secret from it too
/// (`deposit_secret`).
///
/// It comes from the session's `mailbox_seed` (`ratchet::DeviceRatchetState`),
/// which is fixed at the hybrid X25519 + ML-KEM handshake. It does not change
/// with the ratchet: a mailbox derived from the rotating root key would strand
/// mail sealed two rotations earlier. A quantum attacker who knows both
/// devices' public keys cannot derive it, so cannot register as a reader and
/// fetch or ack the mail away. The seal key still comes from the root key
/// (`seal_envelope`). A new handshake moves the mailbox; mail sealed under the
/// old session could not be opened by the new one anyway.
pub fn session_inbox_secret(mailbox_seed: &[u8], recipient_fp: &str, sender_fp: &str) -> Result<[u8; 32], String> {
    if mailbox_seed.len() != 32 {
        return Err("Bad session mailbox seed".to_string());
    }
    let info = [&b"p2pmsg-v9-session-inbox:"[..], recipient_fp.as_bytes(), b"\0", sender_fp.as_bytes()].concat();
    derive(mailbox_seed, &info)
}

/// The deposit secret of `mailbox`, made from the secret both the reader and the
/// depositor hold: the `session_inbox_secret` of a session box, the pairing or link
/// secret of a first-contact box. The reader registers its hash
/// (`server_proto::deposit_verifier`), the depositor presents it with each `Deposit`.
pub fn deposit_secret(box_secret: &[u8], mailbox: &str) -> Result<[u8; 32], String> {
    derive(box_secret, &[&b"p2pmsg-v9-deposit:"[..], mailbox.as_bytes()].concat())
}

/// The cancel secret of one deposit (`ServerRequest::Cancel`), from the box's deposit
/// secret and a per-message key, so the sender recomputes it and stores nothing new.
pub fn cancel_secret(deposit_secret: &[u8], key: &str) -> Result<[u8; 32], String> {
    derive(deposit_secret, &[&b"p2pmsg-v9-cancel:"[..], key.as_bytes()].concat())
}

/// First-contact mailbox of `device_fingerprint` for the holders of `secret`
/// (the nonce of a pairing or link code). The fingerprint alone is public and
/// does not give the id.
pub fn first_contact_mailbox_id(secret: &[u8], device_fingerprint: &str) -> String {
    let info = [&b"p2pmsg-v0.5-first-contact-mailbox:"[..], device_fingerprint.as_bytes()].concat();
    let id: [u8; 16] = derive(secret, &info).expect("HKDF expand for 16 bytes never fails");
    format!("mb_{}", hex::encode(id))
}

/// Seeds (Ed25519, ML-DSA-87) of the key that signs `Register` for `mailbox`
/// (`server_proto::MailboxProof`). `secret` is known only to the readers of the
/// box: the `session_inbox_secret` of a session box (both devices of the
/// pair), the pair key of a relay box, or, for a first-contact box, the reading
/// device's own Ed25519 signing key. Whoever holds the code can compute the id
/// but cannot make the proof. The seeds never open the box's envelopes.
///
/// Key-bound ids (`server_proto::KEY_BOUND_MAILBOX_PREFIX`, session and relay
/// boxes) are derived from these seeds, so they are not mixed in again. Pass
/// the prefix alone to get the seeds before the id is known.
pub fn mailbox_proof_seeds(secret: &[u8], mailbox: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let label = if mailbox.starts_with(crate::server_proto::KEY_BOUND_MAILBOX_PREFIX) { "" } else { mailbox };
    let info = |tag: &[u8]| [tag, label.as_bytes()].concat();
    Ok((
        derive(secret, &info(b"p2pmsg-v0.5-mailbox-proof-ed25519:"))?,
        derive(secret, &info(b"p2pmsg-v0.5-mailbox-proof-mldsa:"))?,
    ))
}

/// Archive bucket period: each bucket covers this many ms (30 days).
///
/// The bucket is monthly rather than a fixed chat id. A fixed id would be a permanent handle that
/// lets the server track one relationship for years. Monthly rotation makes buckets unlinkable for a
/// passive server, at almost no cost, and matches how earlier history is usually loaded, month by month.
///
/// Limit: the server still sees which buckets one device polls, so an active server can link them.
/// A complete solution (per-bucket anonymous credentials plus separate circuits) is out of scope. See SECURITY.md.
pub const ARCHIVE_EPOCH_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Archive period that a timestamp falls into.
pub fn archive_epoch_for(ts_ms: u64) -> u64 {
    ts_ms / ARCHIVE_EPOCH_MS
}

/// Conversation archive key (CAK), derived from the root archive key (ARK).
///
/// `conv_key` is the counterpart's `identity_id` for 1:1 chats and the `group_id` for groups. It is the
/// identity id, not the device fingerprint, so the archive stays readable when the counterpart changes
/// device. Both kinds share this key space with no tag, because a tag would orphan every stored archive.
/// The caller keeps them apart by format: a group id is `group-<16 hex nonce><32 hex tag>`, an identity id is 64 hex
/// (`group_ops::process_group_update`).
fn conv_archive_key(archive_root_key: &[u8; 32], conv_key: &str) -> Result<[u8; 32], String> {
    let mut info = Vec::with_capacity(24 + conv_key.len());
    info.extend_from_slice(b"p2pmsg-v0.1-archive-conv");
    info.extend_from_slice(conv_key.as_bytes());
    derive(archive_root_key, &info)
}

/// Blinded bucket id of one conversation for one period in the server archive.
///
/// The bucket is derived from ARK, so the same group gets different buckets for
/// different identities. The server cannot tell that two users are in the same
/// group from the bucket ids.
///
/// The id is a hash of the bucket's purge secret (see `ServerRequest::ArchivePurge`):
/// knowing the id lets one fetch the sealed rows, only the secret deletes them.
pub fn server_archive_bucket(archive_root_key: &[u8; 32], conv_key: &str, epoch: u64) -> Result<String, String> {
    let secret = server_archive_purge_secret(archive_root_key, conv_key, epoch)?;
    crate::server_proto::archive_bucket_for_purge_secret(&secret).ok_or_else(|| "bad purge secret".to_string())
}

/// The secret that deletes one bucket (64 hex chars). Derived from ARK, so every device of the account has it
/// and the server never sees it until a purge.
pub fn server_archive_purge_secret(archive_root_key: &[u8; 32], conv_key: &str, epoch: u64) -> Result<String, String> {
    let mut cak = conv_archive_key(archive_root_key, conv_key)?;
    let mut info = Vec::with_capacity(26 + 8);
    info.extend_from_slice(b"p2pmsg-v2-archive-purge");
    info.extend_from_slice(&epoch.to_be_bytes());
    let secret = derive::<32>(&cak, &info);
    cak.zeroize();
    let mut secret = secret?;
    let out = hex::encode(secret);
    secret.zeroize();
    Ok(out)
}

// Blob ids are not blinded, on purpose. Attachments are served over the
// `/p2pmessenger/filexfer/1.0.0` protocol that clients already speak. The
// server registers it with `ProtocolSupport::Inbound`, so it acts as one more
// source peer. The whole client download state machine is reused unchanged.
// `FileChunkRequest` is addressed by `file_id`, so the blob id must be the
// `file_id`. That is a random v4 UUID, opaque to the server and not linked to
// any chat, so blinding would add nothing.

// ---------------------------------------------------------------------------
// Envelope sealing (mailbox)
// ---------------------------------------------------------------------------

/// Seals the CBOR bytes of a `NetworkEnvelope` under a key derived from the
/// session `root_key`.
///
/// Output: `nonce(12) || ciphertext`.
///
/// The seal is bound to the mailbox it is deposited in and to the sending
/// device (`sender_fp`). Both ends share the root key and the mailbox, so
/// without this binding the server could return a deposit to its own sender or
/// move it to the session's other mailbox.
pub fn seal_envelope(root_key: &[u8], mailbox_id: &str, sender_fp: &str, envelope_cbor: &[u8]) -> Result<Vec<u8>, String> {
    seal(derive(root_key, b"p2pmsg-v0.1-server-seal")?, &envelope_aad(mailbox_id, sender_fp), &pad(envelope_cbor, ENVELOPE_PAD_CAP))
}

/// Neither part may contain a 0 byte (`mb_<hex>`, hex fingerprint).
fn envelope_aad(mailbox_id: &str, sender_fp: &str) -> Vec<u8> {
    [mailbox_id.as_bytes(), b"\0", sender_fp.as_bytes()].concat()
}

/// Inverse of `seal_envelope`.
///
/// The caller tries the current `root_key` first, then `prev_root_key` if that
/// fails. This is the same "also listen one generation back" rule that
/// `resubscribe_ratchet_topic` applies to topics. The peer may not have applied
/// our latest rotation yet, so the seal may have been made with the old key.
///
/// `mailbox_id` is the mailbox the item was fetched from. `sender_fp` is the
/// device at the other end of the session that owns `root_key`.
pub fn open_envelope(root_key: &[u8], mailbox_id: &str, sender_fp: &str, sealed: &[u8]) -> Result<Vec<u8>, String> {
    unpad(open(derive(root_key, b"p2pmsg-v0.1-server-seal")?, &envelope_aad(mailbox_id, sender_fp), sealed)?)
}

/// Seals an envelope for a first-contact mailbox (`Handshake`,
/// `IdentityExchange`, and anything sent before a session exists). The server
/// sees no identity metadata for a first contact.
///
/// Two layers. The outer layer always uses a key from `secret`, the pairing or
/// link secret that the mailbox id is derived from (`first_contact_mailbox_id`).
/// The inner layer is used when the sender knows the recipient device's public
/// KEM keys (`recipient_kem`: X25519 and ML-KEM-1024): a hybrid KEM to them
/// (`ratchet::kem_key_to`), so the code alone cannot open it. Both layers are
/// bound to the mailbox, which is derived from the recipient's fingerprint.
///
/// Outer plaintext: `0 || envelope`, or `1 || KEM header || nonce || ciphertext`.
pub fn seal_first_contact(secret: &[u8], mailbox_id: &str, recipient_kem: Option<(&[u8], &[u8])>, envelope_cbor: &[u8]) -> Result<Vec<u8>, String> {
    let inner = match recipient_kem {
        Some((x25519_pubkey, kyber_pubkey)) => {
            let (key, header) = crate::ratchet::kem_key_to(x25519_pubkey, kyber_pubkey)?;
            let body = seal(key, mailbox_id.as_bytes(), envelope_cbor)?;
            [&[1u8][..], &header[..], &body[..]].concat()
        }
        None => [&[0u8][..], envelope_cbor].concat(),
    };
    seal(derive(secret, b"p2pmsg-v0.5-first-contact-seal")?, mailbox_id.as_bytes(), &pad(&inner, ENVELOPE_PAD_CAP))
}

/// Inverse of `seal_first_contact`. `own_x25519_secret` and `own_kyber_secret`
/// are the long-term KEM keys of the device that owns the mailbox.
pub fn open_first_contact(
    secret: &[u8],
    mailbox_id: &str,
    own_x25519_secret: &x25519_dalek::StaticSecret,
    own_kyber_secret: &crate::ratchet::MlKem1024DecapsulationKey,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    let inner = unpad(open(derive(secret, b"p2pmsg-v0.5-first-contact-seal")?, mailbox_id.as_bytes(), sealed)?)?;
    match inner.split_first() {
        Some((&0, envelope)) => Ok(envelope.to_vec()),
        Some((&1, rest)) if rest.len() > crate::ratchet::KEM_HEADER_LEN => {
            let (header, body) = rest.split_at(crate::ratchet::KEM_HEADER_LEN);
            open(crate::ratchet::kem_key_from(own_x25519_secret, own_kyber_secret, header)?, mailbox_id.as_bytes(), body)
        }
        _ => Err("Unknown first-contact seal".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Archive record sealing (history)
// ---------------------------------------------------------------------------

/// Encryption key for one archive record. It is specific to the conversation
/// AND the revision.
///
/// `rev` must be part of the key derivation. The `record_id` stays the same
/// across an edit or delete so the server can overwrite the old copy. If `rev`
/// were not in the key, two revisions of one `record_id` would be encrypted
/// under the same key and nonce scheme, and the XOR of the plaintexts and the
/// Poly1305 key could be recovered. With `rev` in the key, each revision has
/// its own key.
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

/// Seals one archive row (CBOR-encoded `ArchivedMessage`).
///
/// The key is derived from ARK, not the ratchet `root_key`, because ratchet
/// keys are forward-secret and deleted after use. Last week's envelope could
/// not be decrypted today. The server's history must therefore be re-encrypted
/// under a long-lived key that is independent of the ratchet.
///
/// The cost: this layer is not forward-secret. If ARK leaks, every archive
/// uploaded so far can be read. Archive storage on the server is therefore a
/// separate, opt-in feature that is off by default. This trade-off is
/// unavoidable: "I want my history on a new device" cannot be reconciled with
/// forward secrecy. Signal SVR and WhatsApp encrypted backups make the same
/// trade.
///
/// The nonce is random, not deterministic. The server already deduplicates by
/// the primary key `(bucket, record_id)`, so byte equality gains nothing. A
/// fixed nonce would turn a future key-derivation bug into direct nonce reuse.
pub fn seal_archive_record(
    archive_root_key: &[u8; 32],
    conv_key: &str,
    record_id: &str,
    rev: u64,
    bucket: &str,
    sent_at_ms: u64,
    record_cbor: &[u8],
) -> Result<Vec<u8>, String> {
    seal(archive_record_key(archive_root_key, conv_key, record_id, rev)?, &archive_record_aad(bucket, sent_at_ms), &pad(record_cbor, ARCHIVE_PAD_CAP))
}

/// Bound with the tag, besides the body: the bucket (key generation,
/// conversation, month) and the page stamp the server sorts by. The record key
/// already covers `record_id` and `rev`. A record moved to another bucket, or
/// served with another stamp, will not open.
fn archive_record_aad(bucket: &str, sent_at_ms: u64) -> Vec<u8> {
    let mut aad = bucket.as_bytes().to_vec();
    aad.extend_from_slice(&sent_at_ms.to_be_bytes());
    aad
}

/// Inverse of `seal_archive_record`. `rev` is `ArchiveRecord.rev` from the
/// server. It is part of the key derivation, so pass the correct value.
///
/// Known limit: this proves the record was sealed as revision `rev`. It does not
/// prove that `rev` is the newest. A server that kept an older revision can
/// serve it, and a device restoring from nothing cannot tell. An edited or
/// deleted message then reappears in its old form. Only state the client keeps
/// itself (it skips records it already holds) guards against this.
pub fn open_archive_record(
    archive_root_key: &[u8; 32],
    conv_key: &str,
    record_id: &str,
    rev: u64,
    bucket: &str,
    sent_at_ms: u64,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    unpad(open(archive_record_key(archive_root_key, conv_key, record_id, rev)?, &archive_record_aad(bucket, sent_at_ms), sealed)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_inbox_is_per_direction_and_per_pair() {
        let (fa, fb) = ("a".repeat(64), "b".repeat(64));
        let to_b = session_inbox_secret(&[1u8; 32], &fb, &fa).unwrap();
        let to_a = session_inbox_secret(&[1u8; 32], &fa, &fb).unwrap();
        assert_ne!(to_a, to_b, "each direction has its own box");
        assert_eq!(to_b, session_inbox_secret(&[1u8; 32], &fb, &fa).unwrap(), "the sender finds the reader's box");
        assert_ne!(to_b, session_inbox_secret(&[2u8; 32], &fb, &fa).unwrap(), "another session, another box");
        assert_ne!(deposit_secret(&to_b, "mk_1").unwrap(), deposit_secret(&to_a, "mk_1").unwrap());
        assert_ne!(cancel_secret(&to_b, "m1").unwrap(), cancel_secret(&to_b, "m2").unwrap());
        // Seeds of a key-bound id do not depend on the id itself.
        assert_eq!(mailbox_proof_seeds(&to_b, "mk_").unwrap(), mailbox_proof_seeds(&to_b, "mk_0123").unwrap());
        assert_ne!(mailbox_proof_seeds(&to_b, "mk_").unwrap(), mailbox_proof_seeds(&to_b, "mb_0123").unwrap());
        assert!(session_inbox_secret(&[1u8; 31], &fa, &fb).is_err());
    }

    #[test]
    fn first_contact_mailbox_needs_the_secret_and_the_fingerprint() {
        let fp = "a".repeat(64);
        let id = first_contact_mailbox_id(&[7; 16], &fp);
        assert_eq!(id, first_contact_mailbox_id(&[7; 16], &fp));
        assert_ne!(id, first_contact_mailbox_id(&[8; 16], &fp));
        assert_ne!(id, first_contact_mailbox_id(&[7; 16], &"b".repeat(64)));
        assert_ne!(mailbox_proof_seeds(&[7; 16], &id).unwrap(), mailbox_proof_seeds(&[8; 16], &id).unwrap());
    }

    #[test]
    fn envelope_seal_roundtrip() {
        let root_key = [7u8; 32];
        let payload = b"merhaba dunya";
        let sealed = seal_envelope(&root_key, "mb_1", "alice", payload).unwrap();
        assert_ne!(&sealed[12..], payload, "ciphertext must not equal plaintext");
        let opened = open_envelope(&root_key, "mb_1", "alice", &sealed).unwrap();
        assert_eq!(opened, payload);
        // Not in another mailbox, and not back to its sender, who would open
        // it as coming from the peer.
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
        assert_ne!(a, b, "same plaintext twice must not give the same ciphertext");
    }

    #[test]
    fn first_contact_seal_roundtrip() {
        use ml_kem::KeyExport;
        let x_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let x_public = x25519_dalek::PublicKey::from(&x_secret);
        let (kyber_secret, kyber_ek) = crate::ratchet::mlkem_generate();
        let kyber_public = kyber_ek.to_bytes();
        let payload = b"ilk temas zarfi";
        for kem in [None, Some((&x_public.as_bytes()[..], &kyber_public[..]))] {
            let sealed = seal_first_contact(&[7; 16], "mb_1", kem, payload).unwrap();
            assert_eq!(open_first_contact(&[7; 16], "mb_1", &x_secret, &kyber_secret, &sealed).unwrap(), payload);
            assert!(open_first_contact(&[8; 16], "mb_1", &x_secret, &kyber_secret, &sealed).is_err());
            assert!(open_first_contact(&[7; 16], "mb_2", &x_secret, &kyber_secret, &sealed).is_err());
        }
        // The KEM layer needs the device's keys, not only the code.
        let sealed = seal_first_contact(&[7; 16], "mb_1", Some((&x_public.as_bytes()[..], &kyber_public[..])), payload).unwrap();
        let (other_kyber, _) = crate::ratchet::mlkem_generate();
        assert!(open_first_contact(&[7; 16], "mb_1", &x_secret, &other_kyber, &sealed).is_err());
        // A clear envelope (the format before sealing) does not open.
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
        // Every component must be bound to the key.
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
        // Revisions keep the same record_id. If rev were not part of the key,
        // both seals would use one key. If one key opens both, nonce reuse is
        // possible again.
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
        assert_ne!(a, server_archive_bucket(&ark, "conv-x", 601).unwrap(), "bucket must change when the period changes");
        let secret = server_archive_purge_secret(&ark, "conv-x", 600).unwrap();
        assert_eq!(crate::server_proto::archive_bucket_for_purge_secret(&secret).as_deref(), Some(a.as_str()));
        assert!(!secret.contains(&a[3..]), "the id must not reveal the secret");
        assert_ne!(a, server_archive_bucket(&ark, "conv-y", 600).unwrap(), "different chat, different bucket");
        assert_ne!(a, server_archive_bucket(&[2u8; 32], "conv-x", 600).unwrap(), "different ARK, different bucket");
        assert!(a.starts_with("ar_"));
        assert!(!a.contains("conv-x"));
    }

    #[test]
    fn archive_epoch_boundaries() {
        assert_eq!(archive_epoch_for(0), 0);
        assert_eq!(archive_epoch_for(ARCHIVE_EPOCH_MS - 1), 0);
        assert_eq!(archive_epoch_for(ARCHIVE_EPOCH_MS), 1);
    }


    #[test]
    fn padme_rounds_up_with_bounded_overhead() {
        let mut last = 0;
        for n in 0..200_000usize {
            let p = padme(n);
            assert!(p >= n && p >= last, "padme must grow and never shrink data: {n}");
            if n >= 256 {
                assert!((p - n) * 100 <= n * 12, "overhead over 12 % at {n}");
            }
            last = p;
        }
    }

    #[test]
    fn padding_roundtrips_all_seal_kinds() {
        let fc_secret = [9u8; 16];
        let x = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let (kyber_sk, _) = crate::ratchet::mlkem_generate();
        for len in [0usize, 1, 100, 511, 512, 1000, 65_537] {
            // Trailing zeros in the data itself must survive.
            let data: Vec<u8> = (0..len).map(|i| if i + 3 >= len { 0 } else { i as u8 | 1 }).collect();
            let s = seal_envelope(&[7u8; 32], "mb", "fp", &data).unwrap();
            assert_eq!(open_envelope(&[7u8; 32], "mb", "fp", &s).unwrap(), data);
            let s = seal_first_contact(&fc_secret, "mb_fc", None, &data).unwrap();
            assert_eq!(open_first_contact(&fc_secret, "mb_fc", &x, &kyber_sk, &s).unwrap(), data);
            let s = seal_archive_record(&[3u8; 32], "conv", "rec", 1, "bk", 5, &data).unwrap();
            assert_eq!(open_archive_record(&[3u8; 32], "conv", "rec", 1, "bk", 5, &s).unwrap(), data);
        }
    }

    #[test]
    fn small_items_share_one_size_and_caps_hold() {
        let size = |n: usize| seal_envelope(&[7u8; 32], "mb", "fp", &vec![1u8; n]).unwrap().len();
        assert!((0..=400).all(|n| size(n) == size(0)), "short items must look alike");
        let max = crate::server_proto::MAX_DEPOSIT_BYTES;
        assert!(size(ENVELOPE_PAD_CAP - 1) <= max, "padding must not push an item past the wire cap");
        let rec = seal_archive_record(&[3u8; 32], "c", "r", 0, "b", 0, &vec![1u8; ARCHIVE_PAD_CAP - 1]).unwrap();
        assert!(rec.len() <= max / 2);
    }

    #[test]
    fn unpad_rejects_bad_input() {
        assert!(unpad(vec![]).is_err());
        assert!(unpad(vec![0; 64]).is_err());
        assert!(unpad(vec![1, 2, 3, 0, 0]).is_err());
        assert_eq!(unpad(vec![1, 0, 0x80, 0, 0]).unwrap(), vec![1, 0]);
    }
}
