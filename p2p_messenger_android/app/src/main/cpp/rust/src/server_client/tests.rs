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
