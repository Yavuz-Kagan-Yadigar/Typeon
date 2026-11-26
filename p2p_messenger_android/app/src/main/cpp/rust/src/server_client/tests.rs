use super::*;
use crate::packet::IdentityExchange;

fn core_with_meta() -> P2PCore {
    let mut core = P2PCore::new();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE app_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)").unwrap();
    core.db = Some(conn);
    core
}

#[test]
fn archive_key_rotation_is_durable_and_resumable() {
    let mut core = core_with_meta();
    assert!(!core.set_archive_root_key(&[1u8; 33]));
    assert!(core.set_archive_root_key(&[1u8; 32]));
    core.rotate_archive_root_key();
    let new = core.archive_root_key.unwrap();
    assert_ne!(new, [1u8; 32]);
    // Sync and backfill ran. The old buckets wait for the server.
    assert_eq!(core.meta_str("ark_todo"), None);
    assert_eq!(core.meta_str("ark_purge"), Some(hex::encode([1u8; 32])));
    // The client restarts with the key file it did not rewrite.
    assert!(core.set_archive_root_key(&[1u8; 32]));
    assert_eq!(core.archive_root_key, Some(new));
    // Once it loads the new key, the copy in the DB is removed.
    assert!(core.set_archive_root_key(&new));
    assert_eq!(core.meta_str("ark"), None);
    // The purge is confirmed only for the keys it covered.
    let peer = PeerId::random();
    core.send_archive_purge(peer, "s".into(), "other".into(), Vec::new());
    assert!(core.meta_str("ark_purge").is_some());
    core.send_archive_purge(peer, "s".into(), hex::encode([1u8; 32]), Vec::new());
    assert_eq!(core.meta_str("ark_purge"), None);
}

#[test]
fn only_the_primary_replaces_the_archive_key_and_never_with_a_retired_one() {
    let mut core = core_with_meta();
    assert!(core.adopt_archive_key(&[1u8; 32], false), "none yet: any sibling");
    assert!(!core.adopt_archive_key(&[2u8; 32], false));
    assert!(core.adopt_archive_key(&[2u8; 32], true));
    assert!(!core.adopt_archive_key(&[1u8; 32], true), "an older sync must not bring the old key back");
    assert_eq!(core.archive_root_key, Some([2u8; 32]));
    assert_eq!(core.meta_str("ark_purge"), Some(hex::encode([1u8; 32])), "the old buckets are purged");
    assert_eq!(core.meta_str("ark_todo"), None, "a secondary does not backfill");
}

#[test]
fn an_older_archive_revision_is_refused() {
    let mut core = P2PCore::new();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE server_archive_revs (conv_key TEXT NOT NULL, record_id TEXT NOT NULL, rev INTEGER NOT NULL, PRIMARY KEY (conv_key, record_id))",
    )
    .unwrap();
    core.db = Some(conn);
    assert!(core.note_archive_rev("c", "m", 5));
    assert!(core.note_archive_rev("c", "m", 5));
    assert!(!core.note_archive_rev("c", "m", 4), "rollback");
    assert!(core.note_archive_rev("c", "m", 6));
    assert!(!core.note_archive_rev("c", "m", 5));
    assert!(core.note_archive_rev("other", "m", 1), "the id is the peer's choice: scoped to the chat");
}

#[test]
fn archive_ids_and_location_keys() {
    let a = archive_wire_id(&[1u8; 32], "c", "m");
    assert_eq!(a, archive_wire_id(&[1u8; 32], "c", "m"));
    assert_ne!(a, archive_wire_id(&[2u8; 32], "c", "m"), "two identities must not share an id");
    assert_ne!(a, "m");
    assert_eq!(location_message_id("mbox|msg-1"), "msg-1");
    assert_eq!(location_message_id("raw:abcd"), "raw:abcd");
}

fn ident() -> NetworkEnvelope {
    NetworkEnvelope::IdentityExchange(IdentityExchange {
        identity_id: "id".into(),
        device_fingerprint: "fp".into(),
        device_name: "dev".into(),
        sign_pubkey_ed25519: vec![1, 2, 3],
        sign_pubkey_mldsa: vec![4],
        kem_pubkey_x25519: vec![5],
        kem_pubkey_mlkem: vec![6],
        device_add: None,
        revokes: Vec::new(),
        device_add_signer: None,
        pairing_proof: Vec::new(),
        link_consent: Vec::new(),
        link_consent_pq: Vec::new(),
        prekey: None,
        timestamp: 0,
        signature: Vec::new(),
        signature_pq: Vec::new(),
    })
}

/// Root cause: envelopes that were NOT `Message` had no dedup key, so `already_deposited` always returned `false`. The `pending_envelopes` queue
/// then re-deposited the SAME handshake to the server on every poll turn. Within hours the depositor's quota filled up, and all server delivery
/// of that device locked up.
#[test]
fn non_message_envelopes_have_a_stable_dedup_key() {
    let env = ident();
    let bytes = b"ayni-baytlar";
    assert_eq!(
        deposit_dedup_key(&env, bytes),
        deposit_dedup_key(&env, bytes),
        "same envelope must yield the same key, otherwise deduplication never works"
    );
    assert_ne!(
        deposit_dedup_key(&env, bytes),
        deposit_dedup_key(&env, b"baska-baytlar"),
        "different envelopes must yield different keys, otherwise a real envelope gets swallowed"
    );
    assert!(deposit_dedup_key(&env, bytes).starts_with("raw:"));
}

#[test]
fn a_mailbox_that_keeps_failing_loses_its_grace_until_a_hold_clears() {
    let mut core = P2PCore::new();
    core.server_rt.insert("s".into(), ServerRuntime::default());
    let t0 = 1_000_000;
    // First failing item: held for the grace period, then passed (strike 1, 2).
    assert!(core.hold_server_item("s", "mb", 1, t0));
    assert!(!core.hold_server_item("s", "mb", 1, t0 + SERVER_HOLD_GRACE_MS));
    assert!(core.hold_server_item("s", "mb", 2, t0 + SERVER_HOLD_GRACE_MS));
    assert!(!core.hold_server_item("s", "mb", 2, t0 + 2 * SERVER_HOLD_GRACE_MS));
    // Two strikes: the next failure is passed at once.
    assert!(!core.hold_server_item("s", "mb", 3, t0 + 2 * SERVER_HOLD_GRACE_MS));
    // Another mailbox keeps its grace.
    assert!(core.hold_server_item("s", "other", 1, t0));
    // A hold the cursor went past (the item was processed) resets the strikes.
    core.server_rt.get_mut("s").unwrap().held.insert("mb".into(), (4, t0));
    core.server_cursors.insert(("s".into(), "mb".into()), 4);
    core.commit_server_fetches();
    assert!(core.hold_server_item("s", "mb", 5, t0 + 3 * SERVER_HOLD_GRACE_MS));
}

/// A non-urgent packet is held from the server path (no own anonymous circuit) only in radio-saver mode and only for
/// `LAZY_DEPOSIT_HOLD_MS`. With the screen in use, and for other packets, nothing is held.
#[test]
fn a_lazy_deposit_is_held_only_within_its_bound() {
    use crate::packet::{MessagePacket, MessagePacketHeader};
    let mut core = P2PCore::new();
    let packet = |id: &str| NetworkEnvelope::Message(MessagePacket {
        header: crate::packet::SignedHeader::new(MessagePacketHeader {
            sender_identity_id: String::new(), sender_device_fingerprint: String::new(), message_id: id.into(),
            ratchet_pubkey: Vec::new(), message_number: 0, prev_chain_length: 0, rotation_kyber_ciphertext: None, sent_at_ms: 0,
        }).unwrap(),
        ciphertext: Vec::new(),
    });
    core.note_lazy_deposit("seen");
    assert!(!core.lazy_deposit_held(&packet("seen")), "screen in use: nothing is held");
    core.power_save = true;
    core.radio_window_open = false;
    assert!(core.radio_saver());
    assert!(core.lazy_deposit_held(&packet("seen")), "saver: held within its bound");
    assert!(!core.lazy_deposit_held(&packet("text")), "an urgent packet is never held");
    core.lazy_deposits.insert("old".into(), mono_ms().saturating_sub(crate::LAZY_DEPOSIT_HOLD_MS));
    assert!(!core.lazy_deposit_held(&packet("old")), "past its hold it goes");
}
