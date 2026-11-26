use super::*;

fn rec(id: &str, rev: u64, ts: u64, body: &[u8]) -> ArchiveRecord {
    ArchiveRecord { record_id: id.to_string(), rev, sent_at_ms: ts, sealed: body.to_vec() }
}

/// Reading a mailbox requires a REGISTERED reader (see `mailbox_readers`). In the real flow `Register` always
/// comes before `Fetch`, and the tests do the same.
fn register(store: &Store, owner: &[u8], mailbox: &str) {
    store
        .register_mailboxes(owner, &[mailbox.to_string()], &[], 0, 100)
        .unwrap();
}

fn enroll(store: &Store, id: &[u8], peer: &str) -> Vec<u8> {
    let e = Enrollment {
        enrollment_id: id.to_vec(),
        enroll_pk: vec![1; 32],
        enroll_pk_pq: vec![2; 32],
        peer_id: peer.to_string(),
        state: EnrollmentState::Active,
        enrolled_at: 0,
        last_seen_at: 0,
        bytes_mail: 0,
        bytes_archive: 0,
        bytes_blob: 0,
    };
    store.insert_enrollment(&e).unwrap();
    id.to_vec()
}

/// Revoke is a block: the key is refused until the operator lifts the block. The revoked row stays, so the
/// PeerId still leads to the blocked key.
#[test]
fn a_revoked_device_is_blocked_until_unblocked() {
    let s = Store::open_in_memory().unwrap();
    let id = enroll(&s, b"oldoldoldoldold1", "peerR");
    assert!(!s.is_key_blocked(&[1u8; 32]));
    s.revoke_enrollment(&id).unwrap();
    let revoked = s.enrollment_by_peer("peerR").unwrap();
    assert_eq!(revoked.state, EnrollmentState::Revoked);
    assert!(s.is_key_blocked(&revoked.enroll_pk));
    // The idle sweep must not remove the row that carries the block.
    s.sleep_idle_enrollments(i64::MAX);
    assert!(s.enrollment_by_peer("peerR").is_some());
    s.unblock_enrollment_key(&revoked.enroll_pk);
    assert!(!s.is_key_blocked(&revoked.enroll_pk));
}

/// Operator decision: an idle enrollment goes to sleep, it is not removed.
#[test]
fn an_idle_enrollment_sleeps_and_rebinds_without_an_invite() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    let b = enroll(&s, b"bbbb", "peerB");
    register(&s, &a, "box");
    register(&s, &a, "shared");
    register(&s, &b, "shared");
    s.deposit("box", b"waiting", &b, 1, 1000).unwrap();
    s.deposit("shared", b"kept", &a, 2, 1000).unwrap();
    s.deposit("shared", b"own", &b, 3, 1000).unwrap();
    s.conn.execute("UPDATE enrollments SET bytes_archive = 7 WHERE enrollment_id = ?1", params![a]).unwrap();
    s.touch_enrollment(&b, 1_000);
    assert_eq!(s.count_active_enrollments(500), 1);
    assert_eq!(s.sleep_idle_enrollments(500), 1, "mail only a sleeper reads goes");
    let row = s.enrollment_by_id(&a).expect("the row stays");
    assert_eq!(row.state, EnrollmentState::Active);
    assert_eq!(row.bytes_archive, 7, "quota counters stay");
    assert!(!s.mailbox_is_registered("box"));
    assert!(s.mailbox_is_registered("shared"), "b still reads it");
    assert_eq!(s.count_active_enrollments(500), 1, "a sleeper holds no place under the cap");
    s.rebind_enrollment(&a, "peerA2", 2_000).unwrap();
    assert_eq!(s.enrollment_by_peer("peerA2").unwrap().enrollment_id, a);
    assert_eq!(s.count_active_enrollments(500), 2, "back awake");
}

#[test]
fn mail_seq_counts_per_mailbox_and_never_resets() {
    let s = Store::open_in_memory().unwrap();
    assert_eq!(s.deposit("mb_1", b"x", b"e", 1, 1000).unwrap(), 1);
    assert_eq!(s.deposit("mb_2", b"y", b"e", 1, 1000).unwrap(), 1, "another box does not move this one");
    assert_eq!(s.deposit("mb_1", b"z", b"e", 1, 1000).unwrap(), 2);
    s.conn.execute("DELETE FROM mail", []).unwrap();
    assert_eq!(s.deposit("mb_1", b"w", b"e", 1, 1000).unwrap(), 3, "an emptied box keeps counting");
}

#[test]
fn deposit_fetch_cursor_never_repeats_or_skips() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.register_mailboxes(&a, &["mb_1".into()], &[], 0, 10).unwrap();

    let s1 = s.deposit("mb_1", b"one", &a, 1, 1000).unwrap();
    let s2 = s.deposit("mb_1", b"two", &a, 2, 1000).unwrap();
    assert!(s2 > s1, "seq must strictly increase");

    let b = enroll(&s, b"bbbb", "peerB");
    register(&s, &b, "mb_1");
    let (items, _) = s.fetch(&b, &[("mb_1".into(), 0)], 10, 4096);
    assert_eq!(items.len(), 2);
    // Advance the cursor. The same items must not arrive again.
    let (again, _) = s.fetch(&b, &[("mb_1".into(), s2)], 10, 4096);
    assert!(again.is_empty(), "processed items must not come back");
    // Continue from the middle. No gap must appear.
    let (mid, _) = s.fetch(&b, &[("mb_1".into(), s1)], 10, 4096);
    assert_eq!(mid.len(), 1);
    assert_eq!(mid[0].sealed, b"two");
}

#[test]
fn unacked_counts_only_what_the_reader_has_not_acked() {
    let s = Store::open_in_memory().unwrap();
    let b = enroll(&s, b"bbbb", "peerB");
    s.register_mailboxes(&b, &["mb_1".into()], &[], 0, 10).unwrap();
    let s1 = s.deposit("mb_1", b"one", &b, 1, 1000).unwrap();
    assert_eq!(s.unacked_for("mb_1", &b), 1, "only the new item: safe to push inline");
    s.deposit("mb_1", b"two", &b, 2, 1000).unwrap();
    assert_eq!(s.unacked_for("mb_1", &b), 2, "an older item is pending: Notify only");
    s.ack("mb_1", s1, &b).unwrap();
    assert_eq!(s.unacked_for("mb_1", &b), 1);
}

#[test]
fn fetch_respects_byte_and_item_caps() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    for i in 0..10 {
        // The bytes differ per deposit: `deposit` now de-duplicates identical copies (see there), and in practice
        // two separate envelopes never have the same ciphertext.
        let mut body = vec![b'x'; 100];
        body[0] = i as u8;
        s.deposit("mb_1", &body, &a, i, 1000).unwrap();
    }
    let b = enroll(&s, b"bbbb", "peerB");
    register(&s, &b, "mb_1");
    let (items, more) = s.fetch(&b, &[("mb_1".into(), 0)], 3, 4096);
    assert_eq!(items.len(), 3);
    assert!(more);
    let (items, more) = s.fetch(&b, &[("mb_1".into(), 0)], 100, 250);
    assert!(items.len() <= 2 && more, "byte cap must be enforced");
}

#[test]
fn a_new_reader_needs_a_proof() {
    // A session box: its id is derived from the one key both ends derive.
    let s = Store::open_in_memory().unwrap();
    let owner = enroll(&s, b"aaaa", "peerA");
    let peer = enroll(&s, b"bbbb", "peerB");
    let squatter = enroll(&s, b"cccc", "peerC");
    let key = [1u8; 32].to_vec();
    let mb = server_proto::key_bound_mailbox_id(&key);
    let id = vec![mb.clone()];
    let proof = |key: &[u8]| vec![(mb.clone(), key.to_vec(), None)];
    // No proof: not registered, reported as unproven.
    assert_eq!(s.register_mailboxes_proved(&owner, &id, &[], &[], 0, 10).unwrap(), (vec![], id.clone()));
    assert!(!s.mailbox_is_registered(&mb));
    assert_eq!(s.register_mailboxes_proved(&owner, &id, &[], &proof(&key), 0, 10).unwrap(), (vec![], vec![]));
    // The same key from another enrollment (the sender derives it too): one reader per key-bound box, refused while
    // the reader is in use.
    assert_eq!(s.register_mailboxes_proved(&peer, &id, &[], &proof(&key), 0, 10).unwrap(), (id.clone(), vec![]));
    // Whoever knows only the id proves it with a key of its own: refused.
    assert_eq!(s.register_mailboxes_proved(&squatter, &id, &[], &proof(&[2u8; 32]), 0, 10).unwrap(), (id.clone(), vec![]));
    let rows = s.conn.query_row("SELECT COUNT(*) FROM mailbox_readers WHERE owner = ?1", params![&squatter], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(rows, 0);
    // A reader registers again without a proof.
    assert_eq!(s.register_mailboxes_proved(&owner, &id, &[], &[], 1, 10).unwrap(), (vec![], vec![]));
}

#[test]
fn a_squatter_key_neither_locks_out_nor_deletes_for_the_real_reader() {
    // A co-member knows a first-contact id (not key-bound) and proves it with a key of its own, on two
    // enrollments, before the device does.
    let s = Store::open_in_memory().unwrap();
    let sq1 = enroll(&s, b"aaaa", "peerA");
    let sq2 = enroll(&s, b"bbbb", "peerB");
    let device = enroll(&s, b"cccc", "peerC");
    let sender = enroll(&s, b"dddd", "peerD");
    let id = vec!["mb_1".to_string()];
    let proof = |key: &[u8]| vec![("mb_1".to_string(), key.to_vec(), None)];
    for sq in [&sq1, &sq2] {
        assert_eq!(s.register_mailboxes_proved(sq, &id, &[], &proof(b"squat"), 0, 10).unwrap(), (vec![], vec![]));
    }
    assert_eq!(s.register_mailboxes_proved(&device, &id, &[], &proof(b"device"), 1, 10).unwrap(), (vec![], vec![]));
    let seq = s.deposit("mb_1", b"to-device", &sender, 2, 1000).unwrap();
    s.ack("mb_1", seq, &sq1).unwrap();
    s.ack("mb_1", seq, &sq2).unwrap();
    let (got, _) = s.fetch(&device, &[("mb_1".into(), 0)], 10, 4096);
    assert_eq!(got.len(), 1, "the squatters' acks do not delete the device's copy");
    s.ack("mb_1", seq, &device).unwrap();
    assert!(s.fetch(&device, &[("mb_1".into(), 0)], 10, 4096).0.is_empty());
}

#[test]
fn a_key_takes_no_third_reader() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    let b = enroll(&s, b"bbbb", "peerB");
    let c = enroll(&s, b"cccc", "peerC");
    let d = enroll(&s, b"eeee", "peerE");
    register(&s, &a, "mb_1");
    register(&s, &b, "mb_1");
    register(&s, &a, "mb_1");
    let id = vec!["mb_1".to_string()];
    // Another key takes its own slots, not the slots of "test-key".
    let other = vec![("mb_1".to_string(), b"other-key".to_vec(), None)];
    assert!(s.register_mailboxes_proved(&d, &id, &[], &other, 0, 100).unwrap().0.is_empty());
    // The same key from a new enrollment (restored device) takes the place of the reader seen longest ago, once
    // that one has been idle long enough.
    let week = READER_EVICT_IDLE_MS;
    s.register_mailboxes(&b, &id, &[], week, 100).unwrap();
    assert_eq!(s.register_mailboxes(&c, &id, &[], week - 1, 100).unwrap(), id, "a, seen at 0, is not idle yet");
    // Its own requests keep a reader alive, not only its Register.
    s.touch_enrollment(&a, 10);
    assert_eq!(s.register_mailboxes(&c, &id, &[], week + 5, 100).unwrap(), id, "a was seen at 10");
    assert!(s.register_mailboxes(&c, &id, &[], week + 10, 100).unwrap().is_empty());
    assert!(s.deposit_owner("mb_1", &test_secret("mb_1"), u64::MAX).is_some_and(|o| o != a), "b and c read it");
    let aa = s.conn.query_row("SELECT COUNT(*) FROM mailbox_readers WHERE owner = ?1", params![&a], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(aa, 0, "a was the stalest reader");
}

#[test]
fn ack_is_cumulative_and_idempotent() {
    let s = Store::open_in_memory().unwrap();
    let sender = enroll(&s, b"send", "peerS");
    let recipient = enroll(&s, b"recv", "peerR");
    register(&s, &recipient, "mb_1");
    let mut last = 0;
    for i in 0..5 {
        // See `fetch_respects_byte_and_item_caps`: the same note applies. Deposits de-duplicate identical bytes,
        // so each round uses different bytes.
        last = s.deposit("mb_1", &[b'x', i as u8], &sender, i, 1000).unwrap();
    }
    assert_eq!(s.ack("mb_1", last, &recipient).unwrap(), 5);
    // A repeated ack is not an error, just zero rows.
    assert_eq!(s.ack("mb_1", last, &recipient).unwrap(), 0);
}

/// See `Store::deposit`. A repeated deposit of identical bytes stores one copy only, so it cannot fill the owner's quota.
#[test]
fn identical_redeposit_is_collapsed_and_does_not_grow_quota() {
    let s = Store::open_in_memory().unwrap();
    let sender = enroll(&s, b"send", "peerS");
    let recipient = enroll(&s, b"recv", "peerR");
    register(&s, &recipient, "mb_1");

    let first = s.deposit("mb_1", b"ayni-el-sikisma", &recipient, 1, 1000).unwrap();
    for i in 2..50 {
        let again = s.deposit("mb_1", b"ayni-el-sikisma", &recipient, i, 1000).unwrap();
        assert_eq!(again, first, "same envelope must map to the same seq");
    }
    assert_eq!(s.mailbox_item_count("mb_1"), 1);

    // The quota must grow by only ONE copy.
    let e = s.enrollment_by_peer("peerR").unwrap();
    assert_eq!(e.bytes_mail as usize, mail_row_bytes("mb_1", b"ayni-el-sikisma"));
    assert_eq!(s.enrollment_by_id(&sender).unwrap().bytes_mail, 0, "the sender pays nothing");

    // Different bytes still get separate rows.
    s.deposit("mb_1", b"baska-zarf", &recipient, 60, 1000).unwrap();
    assert_eq!(s.mailbox_item_count("mb_1"), 2);
}

/// A client that did NOT register the box must be able to neither read nor delete from it. A first-contact box id
/// is guessable, so without access control any enrolled party could fetch the mail and destroy it with `Ack`.
#[test]
fn unregistered_reader_can_neither_fetch_nor_ack() {
    let s = Store::open_in_memory().unwrap();
    let sender = enroll(&s, b"send", "peerS");
    let victim = enroll(&s, b"vict", "peerV");
    let snoop = enroll(&s, b"snoo", "peerN");
    register(&s, &victim, "mb_1");
    let seq = s.deposit("mb_1", b"gizli", &sender, 1, 1000).unwrap();

    let (stolen, _) = s.fetch(&snoop, &[("mb_1".into(), 0)], 10, 4096);
    assert!(stolen.is_empty(), "unregistered client must not read");
    assert_eq!(s.ack("mb_1", seq, &snoop).unwrap(), 0, "unregistered client must not delete");
    assert_eq!(s.mailbox_item_count("mb_1"), 1, "posta yerinde kalmali");

    let (mine, _) = s.fetch(&victim, &[("mb_1".into(), 0)], 10, 4096);
    assert_eq!(mine.len(), 1, "real recipient must still be able to read");
    assert_eq!(s.ack("mb_1", seq, &victim).unwrap(), 1);
}

/// A first-contact box id is derived from the fingerprint, so any enrolled party can register as a reader of it. That
/// reader's `Ack` must not delete the real recipient's mail, and never acknowledging it must not fill the box.
#[test]
fn a_lurking_reader_can_neither_delete_nor_fill_anothers_mail() {
    let s = Store::open_in_memory().unwrap();
    let sender = enroll(&s, b"send", "peerS");
    let victim = enroll(&s, b"vict", "peerV");
    let lurker = enroll(&s, b"lurk", "peerL");
    register(&s, &victim, "mb_fp");
    register(&s, &lurker, "mb_fp");
    let seq = s.deposit("mb_fp", b"handshake", &sender, 1, 1000).unwrap();

    assert_eq!(s.ack("mb_fp", seq, &lurker).unwrap(), 0, "a stranger's ack must not delete");
    let (mine, _) = s.fetch(&victim, &[("mb_fp".into(), 0)], 10, 4096);
    assert_eq!(mine.len(), 1, "recipient must still get its mail");

    // The recipient acks. If the stranger had not acked, the row would stay until the TTL but would not count toward
    // capacity. Here both acked.
    assert_eq!(s.ack("mb_fp", seq, &victim).unwrap(), 1);
    assert_eq!(s.mailbox_item_count("mb_fp"), 0);

    // A stranger that never acks: the row stays, but does not count toward capacity.
    let seq2 = s.deposit("mb_fp", b"handshake-2", &sender, 2, 1000).unwrap();
    // A third reader of the same key is refused: two per key, both in use.
    let third = enroll(&s, b"sile", "peerQ");
    let same_key = vec![("mb_fp".to_string(), b"test-key".to_vec(), None)];
    assert_eq!(s.register_mailboxes_proved(&third, &["mb_fp".to_string()], &[], &same_key, 0, 100).unwrap().0.len(), 1);
    // The lurker is the silent reader here: it has not acked seq2.
    assert_eq!(s.ack("mb_fp", seq2, &victim).unwrap(), 0, "not deleted while a silent reader exists");
    assert_eq!(s.mailbox_usage("mb_fp"), (0, 0), "a row the recipient acked counts neither toward capacity nor bytes");
    assert_eq!(s.ack("mb_fp", seq2, &lurker).unwrap(), 1);
}

/// Re-enrolling must not leave the old reader rows ownerless: that owner could never acknowledge, and the mail would
/// be held until the TTL.
#[test]
fn orphaned_reader_does_not_block_deletion() {
    let s = Store::open_in_memory().unwrap();
    let sender = enroll(&s, b"send", "peerS");
    let reader = enroll(&s, b"read", "peerR");
    register(&s, &reader, "mb_1");
    register(&s, b"gone", "mb_1");
    let seq = s.deposit("mb_1", b"x", &sender, 1, 1000).unwrap();
    assert_eq!(s.ack("mb_1", seq, &reader).unwrap(), 1);
}

/// The stride must be stored with the blob, or `serve_chunk` would read from the wrong offsets.
#[test]
fn blob_remembers_the_chunk_stride_it_was_written_with() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.blob_begin("bl_s", &a, 2, 0).unwrap();
    assert_eq!(s.blob_state("bl_s").unwrap().chunk_size, 0, "unknown at start");
    s.blob_set_chunk_size("bl_s", 512 * 1024);
    assert_eq!(s.blob_state("bl_s").unwrap().chunk_size, 512 * 1024);
    // The first value is FIXED. Later chunks cannot claim a different stride.
    s.blob_set_chunk_size("bl_s", 256 * 1024);
    assert_eq!(s.blob_state("bl_s").unwrap().chunk_size, 512 * 1024);
}

/// A global ceiling must also exist on top of the per-record quota.
#[test]
fn total_stored_bytes_counts_every_kind() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    register(&s, &a, "mb_1");
    assert_eq!(s.total_stored_bytes(), 0);
    s.deposit("mb_1", &vec![b'x'; 100], &a, 1, 1000).unwrap();
    s.archive_put("ar_1", &[rec("m1", 1, 100, &vec![b'y'; 50])], &a, 0).unwrap();
    s.blob_begin("bl_1", &a, 1, 0).unwrap();
    s.blob_record_chunk("bl_1", 0, 25).unwrap();
    // 100 mail + its row + 50 archive + 2 for the record id "m1" + row + 25 blob.
    assert_eq!(s.total_stored_bytes(), 177 + (mail_row_bytes("mb_1", &[]) + ARCHIVE_ROW_OVERHEAD) as i64);
}

/// Only the holder of a deposit's cancel secret can withdraw it (`ServerRequest::Cancel`).
#[test]
fn a_deposit_is_withdrawn_only_with_its_cancel_secret() {
    let s = Store::open_in_memory().unwrap();
    let recipient = enroll(&s, b"recv", "peerR");
    register(&s, &recipient, "mb_1");
    let (mine, theirs) = ([1u8; 32], [2u8; 32]);
    let m = s.deposit_written("mb_1", b"benim", &recipient, &server_proto::cancel_hash(&mine), 1, 1000).unwrap().0;
    let t = s.deposit_written("mb_1", b"baskasinin", &recipient, &server_proto::cancel_hash(&theirs), 2, 1000).unwrap().0;
    assert_eq!(s.cancel_deposit("mb_1", t, &mine), 0, "my secret does not withdraw another item");
    assert_eq!(s.cancel_deposit("mb_1", m, &theirs), 0);
    assert_eq!(s.cancel_deposit("mb_2", m, &mine), 0, "the box is part of the match");
    assert_eq!(s.mailbox_item_count("mb_1"), 2);
    assert_eq!(s.cancel_deposit("mb_1", m, &mine), 1);
    let (left, _) = s.fetch(&recipient, &[("mb_1".into(), 0)], 10, 4096);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].sealed, b"baskasinin");
    // An item stored without a cancel hash cannot be withdrawn at all.
    let bare = s.deposit("mb_1", b"bare", &recipient, 3, 1000).unwrap();
    assert_eq!(s.cancel_deposit("mb_1", bare, &[]), 0);
}

/// The anonymous path: the reader registers its inbound box with a deposit verifier; a depositor with the secret
/// finds the reader (who is charged), one without it gets the same `None` as for an unknown box.
#[test]
fn an_anonymous_deposit_needs_the_deposit_secret_and_is_charged_to_the_reader() {
    let s = Store::open_in_memory().unwrap();
    let reader = enroll(&s, b"read", "peerR");
    let secret = [9u8; 32];
    let proof = vec![("mb_in".to_string(), b"key".to_vec(), Some(server_proto::deposit_verifier(&secret).to_vec()))];
    assert_eq!(s.register_mailboxes_proved(&reader, &["mb_in".to_string()], &[], &proof, 0, 10).unwrap(), (vec![], vec![]));
    assert_eq!(s.deposit_owner("mb_in", &secret, u64::MAX), Some(reader.clone()));
    assert_eq!(s.deposit_owner("mb_in", &[8u8; 32], u64::MAX), None, "a wrong secret");
    assert_eq!(s.deposit_owner("mb_other", &secret, u64::MAX), None, "an unknown box: the same answer");
    // A reader registered without a verifier (a call relay box) takes no deposits.
    let relay = vec![("mb_relay".to_string(), b"key".to_vec(), None)];
    s.register_mailboxes_proved(&reader, &["mb_relay".to_string()], &[], &relay, 0, 10).unwrap();
    assert_eq!(s.deposit_owner("mb_relay", &secret, u64::MAX), None);
    let seq = s.deposit_written("mb_in", b"hello", &reader, &server_proto::cancel_hash(&[1u8; 32]), 1, 1000).unwrap().0;
    let (items, _) = s.fetch(&reader, &[("mb_in".into(), 0)], 10, 4096);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].seq, seq);
    assert_eq!(s.enrollment_by_id(&reader).unwrap().bytes_mail, mail_row_bytes("mb_in", b"hello") as i64, "the reader pays");
    assert_eq!(s.mailbox_usage("mb_in"), (1, mail_row_bytes("mb_in", b"hello") as i64));
    s.ack("mb_in", seq, &reader).unwrap();
    s.recount_mail_bytes();
    assert_eq!(s.enrollment_by_id(&reader).unwrap().bytes_mail, 0, "delivered mail is taken off the reader's quota");
    // A revoked reader takes no deposits.
    s.revoke_enrollment(&reader).unwrap();
    assert_eq!(s.deposit_owner("mb_in", &secret, u64::MAX), None);
}

/// Operator decision: a BLOCK differs from a revoke. If the key is blocked, a fresh invite must not work either.
#[test]
fn blocking_is_keyed_on_the_enrollment_key_not_the_row() {
    let s = Store::open_in_memory().unwrap();
    let key = vec![9u8; 32];
    assert!(!s.is_key_blocked(&key));
    s.block_enrollment_key(&key, 0).unwrap();
    assert!(s.is_key_blocked(&key));
    // Another key is not affected.
    assert!(!s.is_key_blocked(&vec![8u8; 32]));
    s.unblock_enrollment_key(&key);
    assert!(!s.is_key_blocked(&key));
}

#[test]
fn expired_mail_is_swept() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.deposit("mb_1", b"x", &a, 1000, 10).unwrap();
    assert_eq!(s.sweep_expired_mail(1005), 0, "henuz dolmadi");
    assert_eq!(s.sweep_expired_mail(1010), 1);
}

#[test]
fn archive_rows_expire_after_ttl() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"a", "peerA");
    s.archive_put("ar_1", &[rec("m1", 1, 100, b"x")], &a, 1000).unwrap();
    assert_eq!(s.sweep_expired_archive(1000 + ARCHIVE_TTL_MS), 0);
    assert_eq!(s.sweep_expired_archive(1001 + ARCHIVE_TTL_MS), 1);
    assert!(s.archive_fetch("ar_1", None, 10, 65536).0.is_empty());
}

#[test]
fn plain_db_migrates_to_sqlcipher() {
    let dir = std::env::temp_dir().join(format!("typeon_mig_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("typeon_server.db");
    set_db_key(None);
    { let s = Store::open(&p).unwrap(); s.meta_set("k", b"v").unwrap(); }
    set_db_key(Some(parse_hex_db_key(&"ab".repeat(32)).unwrap()));
    let s = Store::open(&p).unwrap();
    assert_eq!(s.meta_get("k").as_deref(), Some(&b"v"[..]));
    drop(s);
    set_db_key(None);
    assert!(Store::open(&p).is_err(), "plain open of an encrypted DB must fail");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Migration (I-48, K-41): an on-disk DB stamped at an older version and missing a later column gets it. A failing
/// `ALTER` fails init and leaves the old stamp, so the next start retries. Opened without `Store::open`, so the global
/// `DB_KEY` of the SQLCipher test cannot race this one.
#[test]
fn old_schema_gets_missing_column_or_stays_unstamped() {
    let dir = std::env::temp_dir().join(format!("typeon_schema_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("old.db");
    let open = || Store { conn: Connection::open(&p).unwrap() };
    let version = |s: &Store| s.conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0)).unwrap();
    let has_chunk_size = |s: &Store| {
        s.conn.query_row("SELECT COUNT(*) FROM pragma_table_info('blobs') WHERE name = 'chunk_size'", [], |r| r.get::<_, i64>(0)).unwrap() == 1
    };
    {
        let s = open();
        s.init_schema().unwrap();
        s.conn.execute_batch("ALTER TABLE blobs DROP COLUMN chunk_size; PRAGMA user_version = 3;").unwrap();
        assert!(!has_chunk_size(&s));
    }
    {
        let s = open();
        s.init_schema().unwrap();
        assert!(has_chunk_size(&s), "the missing column is added");
        assert_eq!(version(&s), SCHEMA_VERSION);
    }
    {
        // Schema init fails on the mail table for a reason other than a duplicate column (a view is not a table).
        let s = open();
        s.conn
            .execute_batch("DROP INDEX IF EXISTS idx_mail_hash; DROP TABLE mail; CREATE VIEW mail AS SELECT 1 AS seq; PRAGMA user_version = 3;")
            .unwrap();
        assert!(s.init_schema().is_err());
        assert_eq!(version(&s), 3, "a failed ALTER does not stamp the schema version");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The reader cap is per proof key. Two different keys on one first-contact box each get `MAX_READERS_PER_KEY`
/// slots. A third reader of either key is refused while the two are in use.
#[test]
fn two_keys_on_one_box_each_take_two_readers() {
    let s = Store::open_in_memory().unwrap();
    let id = vec!["mb_1".to_string()];
    let proof = |key: &[u8]| vec![("mb_1".to_string(), key.to_vec(), None)];
    let owners: Vec<Vec<u8>> = (0..6u8).map(|i| enroll(&s, &[b'a' + i; 4], &format!("peer{i}"))).collect();
    for (i, key) in [&b"key-1"[..], &b"key-2"[..]].into_iter().enumerate() {
        for o in &owners[i * 3..i * 3 + 2] {
            assert_eq!(s.register_mailboxes_proved(o, &id, &[], &proof(key), 0, 10).unwrap(), (vec![], vec![]));
        }
        assert_eq!(s.register_mailboxes_proved(&owners[i * 3 + 2], &id, &[], &proof(key), 0, 10).unwrap().0, id);
    }
    let readers = s.conn.query_row("SELECT COUNT(*) FROM mailbox_readers WHERE mailbox_id = 'mb_1'", [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(readers, 4);
}

#[test]
fn archive_higher_rev_supersedes_lower() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.archive_put("ar_1", &[rec("m1", 1, 100, b"ilk")], &a, 0).unwrap();
    s.archive_put("ar_1", &[rec("m1", 2, 100, b"duzeltilmis")], &a, 0).unwrap();
    let (page, _) = s.archive_fetch("ar_1", None, 10, 65536);
    assert_eq!(page.len(), 1, "same record_id must be one row");
    assert_eq!(page[0].sealed, b"duzeltilmis");

    // A LOWER rev must not restore the old version (out-of-order delivery).
    s.archive_put("ar_1", &[rec("m1", 1, 100, b"ilk")], &a, 0).unwrap();
    let (page, _) = s.archive_fetch("ar_1", None, 10, 65536);
    assert_eq!(page[0].sealed, b"duzeltilmis");
}

#[test]
fn archive_pages_newest_first_and_reports_more() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    let records: Vec<_> = (0..5).map(|i| rec(&format!("m{i}"), 1, 100 + i, b"x")).collect();
    s.archive_put("ar_1", &records, &a, 0).unwrap();

    let (page, more) = s.archive_fetch("ar_1", None, 2, 65536);
    assert_eq!(page.len(), 2);
    assert!(more);
    assert_eq!(page[0].sent_at_ms, 104, "newest first");
    // Paging: from the newest seen to older.
    let (older, _) = s.archive_fetch("ar_1", Some((page[1].sent_at_ms, page[1].record_id.as_str())), 10, 65536);
    assert_eq!(older.len(), 3);
    assert!(older.iter().all(|r| r.sent_at_ms < page[1].sent_at_ms));
}

#[test]
fn archive_probe_only_reports_non_empty_buckets() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.archive_put("ar_full", &[rec("m1", 1, 100, b"x")], &a, 0).unwrap();
    let stats = s.archive_probe(&["ar_full".into(), "ar_empty".into()]);
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].bucket, "ar_full");
}

#[test]
fn an_unlimited_invite_never_runs_out() {
    let s = Store::open_in_memory().unwrap();
    s.create_invite(b"pub", "herkese-acik", 0, 0, 0).unwrap();
    assert_eq!(s.invite_uses_left(b"pub", 0), Some(-1));
    for _ in 0..50 {
        assert!(s.consume_invite(b"pub", 10).unwrap(), "sinirsiz davet tukenmemeli");
    }
    assert_eq!(s.invite_uses_left(b"pub", 0), Some(-1), "sayac azalmamali");
    // The time limit still applies. Unlimited does NOT mean never expiring.
    s.create_invite(b"pub2", "gecici", 0, 100, 0).unwrap();
    assert!(!s.consume_invite(b"pub2", 200).unwrap());
}

#[test]
fn a_deleted_invite_stops_working() {
    let s = Store::open_in_memory().unwrap();
    s.create_invite(b"pub", "herkese-acik", 0, 0, 0).unwrap();
    s.delete_invite(b"pub").unwrap();
    assert!(!s.consume_invite(b"pub", 10).unwrap(), "rotated code must invalidate the old one");
    assert_eq!(s.invite_uses_left(b"pub", 0), None);
}

#[test]
fn invite_uses_are_consumed_exactly_once() {
    let s = Store::open_in_memory().unwrap();
    s.create_invite(b"hash", "test", 1, 0, 0).unwrap();
    assert!(s.consume_invite(b"hash", 10).unwrap());
    assert!(!s.consume_invite(b"hash", 10).unwrap(), "must be single-use");
}

#[test]
fn expired_invite_is_rejected() {
    let s = Store::open_in_memory().unwrap();
    s.create_invite(b"hash", "test", 5, 100, 0).unwrap();
    assert!(!s.consume_invite(b"hash", 200).unwrap());
    assert!(s.consume_invite(b"hash", 50).unwrap());
}

#[test]
fn a_failed_enrollment_does_not_spend_the_invite() {
    let s = Store::open_in_memory().unwrap();
    s.create_invite(b"h", "x", 1, 0, 0).unwrap();
    enroll(&s, b"aaaa", "peerA");
    let e = s.enrollment_by_peer("peerA").unwrap();
    // Make the insert fail: there is no table to write to.
    s.conn.execute_batch("ALTER TABLE enrollments RENAME TO gone").unwrap();
    assert!(s.enroll_with_invite(b"h", 1, &e).is_err());
    s.conn.execute_batch("ALTER TABLE gone RENAME TO enrollments").unwrap();
    assert_eq!(s.invite_uses_left(b"h", 0), Some(1), "the use came back with the rollback");
    assert!(s.enroll_with_invite(b"h", 1, &e).unwrap());
    assert!(!s.enroll_with_invite(b"h", 1, &e).unwrap(), "spent");
}

#[test]
fn an_item_over_the_batch_cap_still_leaves_its_mailbox() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    let b = enroll(&s, b"bbbb", "peerB");
    register(&s, &b, "mb_1");
    s.deposit("mb_1", &[7u8; 600], &a, 1, 1000).unwrap();
    s.deposit("mb_1", b"next", &a, 2, 1000).unwrap();
    let (items, more) = s.fetch(&b, &[("mb_1".into(), 0)], 10, 512);
    assert_eq!(items.len(), 1, "the oversized head goes out alone");
    assert!(more);
    let (items, more) = s.fetch(&b, &[("mb_1".into(), items[0].seq)], 10, 512);
    assert_eq!(items[0].sealed, b"next");
    assert!(!more);
}

#[test]
fn archive_paging_walks_shared_timestamps_and_never_stalls() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.archive_put("ar_1", &[rec("m1", 1, 100, b"a"), rec("m2", 1, 200, b"b"), rec("m3", 1, 200, b"c"), rec("m5", 1, 200, b"e"), rec("m4", 1, 300, b"d")], &a, 0).unwrap();
    // Walk the bucket two at a time, the way the client does.
    let mut seen = Vec::new();
    let mut before: Option<(u64, String)> = None;
    loop {
        let (page, more) = s.archive_fetch("ar_1", before.as_ref().map(|(ms, id)| (*ms, id.as_str())), 2, 65536);
        before = page.last().map(|r| (r.sent_at_ms, r.record_id.clone()));
        seen.extend(page.into_iter().map(|r| r.record_id));
        if !more {
            break;
        }
    }
    seen.sort();
    assert_eq!(seen, ["m1", "m2", "m3", "m4", "m5"], "a page may end inside the ts=200 group");
    // A record over the byte cap is still returned.
    let (page, _) = s.archive_fetch("ar_1", None, 10, 0);
    assert_eq!(page.len(), 1);
}

#[test]
fn archive_charges_the_last_writer_and_any_holder_can_purge() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    let b = enroll(&s, b"bbbb", "peerB");
    s.archive_put("ar_1", &[rec("m1", 1, 100, b"small")], &a, 0).unwrap();
    s.archive_put("ar_1", &[rec("m1", 2, 100, &[0u8; 1000])], &b, 0).unwrap();
    assert_eq!(s.enrollment_by_id(&a).unwrap().bytes_archive, 0);
    assert_eq!(s.enrollment_by_id(&b).unwrap().bytes_archive, 1002 + ARCHIVE_ROW_OVERHEAD as i64, "sealed + record_id + row");
    assert_eq!(s.archive_purge(&["ar_1".to_string()]), 1, "a's purge removes b's row");
    assert_eq!(s.enrollment_by_id(&b).unwrap().bytes_archive, 0);
}

#[test]
fn archive_put_delta_matches_what_put_charges() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    let b = enroll(&s, b"bbbb", "peerB");
    let row = |body: usize| (2 + body + ARCHIVE_ROW_OVERHEAD) as i64;
    let first = [rec("m1", 1, 100, &[0u8; 100]), rec("m2", 1, 100, &[0u8; 10])];
    assert_eq!(s.archive_put_delta("ar_1", &first, &a), (row(100) + row(10), row(100) + row(10)));
    s.archive_put("ar_1", &first, &a, 0).unwrap();
    // The same records again (another device's copy, or a resend): nothing is added.
    assert_eq!(s.archive_put_delta("ar_1", &first, &a), (0, 0));
    // A delete that shrinks a row refunds the writer: the quota check must let it through.
    assert_eq!(s.archive_put_delta("ar_1", &[rec("m1", 2, 100, b"x")], &a), (row(1) - row(100), row(1) - row(100)));
    // Another enrollment overwriting a's row pays the whole row; the total grows only by the difference.
    assert_eq!(s.archive_put_delta("ar_1", &[rec("m2", 2, 100, &[0u8; 20])], &b), (row(20), row(20) - row(10)));
    // In order within one batch: the second copy of m3 at a lower rev is skipped, a higher one replaces the first.
    let batch = [rec("m3", 2, 100, &[0u8; 30]), rec("m3", 1, 100, &[0u8; 50]), rec("m3", 3, 100, &[0u8; 40])];
    assert_eq!(s.archive_put_delta("ar_1", &batch, &a), (row(40), row(40)));
    s.archive_put("ar_1", &batch, &a, 0).unwrap();
    assert_eq!(s.enrollment_by_id(&a).unwrap().bytes_archive, row(100) + row(10) + row(40));
}

#[test]
fn deleting_a_blob_refunds_what_was_charged_and_frees_the_id() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.blob_begin("bl_1", &a, 1, 0).unwrap();
    s.blob_record_chunk("bl_1", 0, 10).unwrap();
    s.add_blob_bytes(&a, 10);
    assert!(!s.blob_delete("bl_1", b"other"), "only the owner");
    assert!(s.blob_delete("bl_1", &a));
    assert_eq!(s.enrollment_by_id(&a).unwrap().bytes_blob, 0);
    assert!(!s.blob_has_chunk("bl_1", 0), "the id can be uploaded again");
}

#[test]
fn rebind_moves_peer_and_frees_the_old_holder() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerOld");
    enroll(&s, b"bbbb", "peerNew");
    s.rebind_enrollment(&a, "peerNew", 5).unwrap();
    let found = s.enrollment_by_peer("peerNew").unwrap();
    assert_eq!(found.enrollment_id, a, "new PeerId must now resolve to a's record");
    // A second displaced holder must not collide with the first one.
    let c = enroll(&s, b"cccc", "peerThird");
    enroll(&s, b"dddd", "peerFourth");
    s.rebind_enrollment(&c, "peerFourth", 6).unwrap();
    assert_eq!(s.enrollment_by_peer("peerFourth").unwrap().enrollment_id, c);
    assert!(s.revoke_enrollment(b"nope").is_err(), "a typo is not a revoke");
}

#[test]
fn mailbox_quota_is_enforced_but_registration_is_idempotent() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.register_mailboxes(&a, &["mb_1".into(), "mb_2".into()], &[], 0, 2).unwrap();
    // The refused id does not cost the batch: `mb_2` stays registered.
    assert_eq!(s.register_mailboxes(&a, &["mb_3".into(), "mb_2".into()], &[], 0, 2).unwrap(), ["mb_3"]);
    // Re-registering an id that is already registered must not hit the quota.
    assert!(s.register_mailboxes(&a, &["mb_1".into()], &[], 1, 2).unwrap().is_empty());
    s.register_mailboxes(&a, &[], &["mb_1".into()], 1, 2).unwrap();
    assert!(!s.mailbox_is_registered("mb_1"));
}

#[test]
fn mail_bytes_are_recounted_after_delivery() {
    // If the quota grew one-way, an active user would get locked out within a few months.
    let s = Store::open_in_memory().unwrap();
    let sender = enroll(&s, b"send", "peerS");
    let recipient = enroll(&s, b"recv", "peerR");
    register(&s, &recipient, "mb_1");
    let seq = s.deposit("mb_1", &vec![b'x'; 500], &recipient, 1, 1000).unwrap();
    assert_eq!(s.enrollment_by_peer("peerR").unwrap().bytes_mail, mail_row_bytes("mb_1", &[0; 500]) as i64);
    assert_eq!(s.enrollment_by_id(&sender).unwrap().bytes_mail, 0);
    s.ack("mb_1", seq, &recipient).unwrap();
    s.recount_mail_bytes();
    assert_eq!(s.enrollment_by_peer("peerR").unwrap().bytes_mail, 0);
}

#[test]
fn blob_is_only_complete_after_every_chunk() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.blob_begin("bl_1", &a, 3, 0).unwrap();
    s.blob_record_chunk("bl_1", 0, 10).unwrap();
    s.blob_record_chunk("bl_1", 1, 10).unwrap();
    assert!(s.blob_finish("bl_1", b"hash", 5).is_err());
    assert!(!s.blob_state("bl_1").unwrap().complete, "eksik yukleme servis edilemez");
    s.blob_record_chunk("bl_1", 2, 10).unwrap();
    s.blob_finish("bl_1", b"hash", 5).unwrap();
    assert!(s.blob_state("bl_1").unwrap().complete);
}

#[test]
fn out_of_order_chunks_are_accepted_and_counted() {
    // Chunks arrive out of order in the pipeline. The server must accept this and must not say 'complete' until all
    // of them have arrived.
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.blob_begin("bl_1", &a, 3, 0).unwrap();
    s.blob_record_chunk("bl_1", 2, 10).unwrap();
    s.blob_record_chunk("bl_1", 0, 10).unwrap();
    assert!(s.blob_finish("bl_1", b"h", 5).is_err());
    assert!(!s.blob_state("bl_1").unwrap().complete, "must not complete with a missing chunk");
    assert_eq!(s.blob_state("bl_1").unwrap().received_chunks, 2);
    s.blob_record_chunk("bl_1", 1, 10).unwrap();
    s.blob_finish("bl_1", b"h", 5).unwrap();
    assert!(s.blob_state("bl_1").unwrap().complete);
    assert!(s.blob_has_chunk("bl_1", 1));
}

#[test]
fn resent_blob_chunk_is_not_counted_twice() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.blob_begin("bl_1", &a, 2, 0).unwrap();
    s.blob_record_chunk("bl_1", 0, 100).unwrap();
    s.blob_record_chunk("bl_1", 0, 100).unwrap();  // Connection dropped, retry.
    assert_eq!(s.blob_state("bl_1").unwrap().byte_len, 100, "resent chunk must not be counted twice");
    s.blob_record_chunk("bl_1", 1, 100).unwrap();
    assert_eq!(s.blob_state("bl_1").unwrap().byte_len, 200);
}

#[test]
fn blob_gc_spares_recently_served_files() {
    let s = Store::open_in_memory().unwrap();
    let a = enroll(&s, b"aaaa", "peerA");
    s.blob_begin("bl_1", &a, 1, 0).unwrap();
    s.blob_record_chunk("bl_1", 0, 10).unwrap();
    s.blob_finish("bl_1", b"h", 0).unwrap();
    assert!(s.blobs_to_gc(500, 1000).is_empty(), "must not be deleted before TTL expires");
    // A file still being downloaded must keep living.
    s.blob_touch("bl_1", 900);
    assert!(s.blobs_to_gc(1500, 1000).is_empty());
    assert_eq!(s.blobs_to_gc(2000, 1000), vec!["bl_1".to_string()]);
}

#[test]
fn a_pruned_box_counter_restarts_above_old_cursors() {
    let s = Store::open_in_memory().unwrap();
    assert_eq!(s.deposit("mb_1", b"x", b"e", 1, 1000).unwrap(), 1);
    assert_eq!(s.deposit("mb_1", b"z", b"e", 1, 1000).unwrap(), 2);
    s.conn.execute("DELETE FROM mail", []).unwrap();
    s.prune_dead_rows(0);
    let left: i64 = s.conn.query_row("SELECT COUNT(*) FROM mail_seq", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 0, "a box with no mail and no reader keeps no counter");
    assert_eq!(s.deposit("mb_1", b"w", b"e", 1, 1000).unwrap(), 3, "never below an old cursor");
}

#[test]
fn ack_many_keeps_the_highest_seq_and_a_repeat_is_not_written() {
    let s = Store::open_in_memory().unwrap();
    let reader = enroll(&s, b"read", "peerR");
    register(&s, &reader, "mb_1");
    let (one, new) = s.deposit_written("mb_1", b"one", &reader, &[], 1, 1000).unwrap();
    assert!(new);
    assert_eq!(s.deposit_written("mb_1", b"one", &reader, &[], 2, 1000).unwrap(), (one, false), "a repeat writes nothing");
    let two = s.deposit("mb_1", b"two", &reader, 3, 1000).unwrap();
    let acks = vec![("mb_1".to_string(), two), ("mb_1".to_string(), one)];
    assert_eq!(s.ack_many(&acks, &reader).unwrap(), 2, "the lower seq after the higher one does not undo it");
    assert_eq!(s.mailbox_usage("mb_1"), (0, 0));
}

/// A row stops counting against its owner once the owner acked it, even while a co-reader that never acks keeps it on
/// disk. A key-bound (session) box takes one reader: the sender, who derives the same key, cannot join as a second.
#[test]
fn an_acked_row_leaves_the_owners_quota_and_a_session_box_has_one_reader() {
    let s = Store::open_in_memory().unwrap();
    let owner = enroll(&s, b"ownr", "peerO");
    let squat = enroll(&s, b"sqat", "peerS");
    // First-contact box: a co-reader with its own key gets in, and never acks.
    register(&s, &owner, "mb_fc");
    let other = vec![("mb_fc".to_string(), b"squat-key".to_vec(), Some(server_proto::deposit_verifier(&test_secret("mb_fc")).to_vec()))];
    assert!(s.register_mailboxes_proved(&squat, &["mb_fc".to_string()], &[], &other, 1, 10).unwrap().0.is_empty());
    let seq = s.deposit("mb_fc", b"hello", &owner, 2, 1000).unwrap();
    s.recount_mail_bytes();
    assert_eq!(s.enrollment_by_id(&owner).unwrap().bytes_mail, mail_row_bytes("mb_fc", b"hello") as i64);
    s.ack("mb_fc", seq, &owner).unwrap();
    s.recount_mail_bytes();
    assert_eq!(s.enrollment_by_id(&owner).unwrap().bytes_mail, 0, "acked by its owner: off the quota");
    assert_eq!(s.mailbox_usage("mb_fc").0, 0);
    // Key-bound box: one reader.
    let key = [7u8; 32];
    let id = vec![server_proto::key_bound_mailbox_id(&key)];
    let proof = vec![(id[0].clone(), key.to_vec(), None)];
    assert!(s.register_mailboxes_proved(&owner, &id, &[], &proof, 0, 10).unwrap().0.is_empty());
    assert_eq!(s.register_mailboxes_proved(&squat, &id, &[], &proof, 1, 10).unwrap().0, id, "the sender is refused");
    // The restore path still works: the same key under a new enrollment replaces a reader idle long enough.
    s.touch_enrollment(&owner, 0);
    let restored = enroll(&s, b"rest", "peerN");
    assert!(s.register_mailboxes_proved(&restored, &id, &[], &proof, READER_EVICT_IDLE_MS, 10).unwrap().0.is_empty());
    let readers = s.conn.query_row("SELECT COUNT(*) FROM mailbox_readers WHERE mailbox_id = ?1", params![id[0]], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(readers, 1);
}

/// The reader charged for a deposit is one with quota room: a co-reader that registered first and filled its own
/// quota does not block the box.
#[test]
fn the_deposit_goes_to_a_reader_with_quota_room() {
    let s = Store::open_in_memory().unwrap();
    let squat = enroll(&s, b"sqat", "peerS");
    let owner = enroll(&s, b"ownr", "peerO");
    let verifier = Some(server_proto::deposit_verifier(&test_secret("mb_fc")).to_vec());
    let id = vec!["mb_fc".to_string()];
    s.register_mailboxes_proved(&squat, &id, &[], &[(id[0].clone(), b"k1".to_vec(), verifier.clone())], 0, 10).unwrap();
    s.register_mailboxes_proved(&owner, &id, &[], &[(id[0].clone(), b"k2".to_vec(), verifier)], 1, 10).unwrap();
    assert_eq!(s.deposit_owner("mb_fc", &test_secret("mb_fc"), 100), Some(squat.clone()), "oldest while it has room");
    s.conn.execute("UPDATE enrollments SET bytes_mail = 101 WHERE enrollment_id = ?1", params![squat]).unwrap();
    assert_eq!(s.deposit_owner("mb_fc", &test_secret("mb_fc"), 100), Some(owner), "full: the next reader");
}

/// A pre-anonymous-deposit DB still stamped 0 is told by its `mail.depositor` column: the old mail tables go, and the
/// quota counters charged for them are recounted.
#[test]
fn a_legacy_mail_table_is_dropped_even_at_user_version_zero() {
    let s = Store { conn: Connection::open_in_memory().unwrap() };
    s.conn
        .execute_batch(
            "CREATE TABLE mail (id INTEGER PRIMARY KEY, seq INTEGER, mailbox_id TEXT, sealed BLOB, byte_len INTEGER,
                                deposited_at_ms INTEGER, expires_at_ms INTEGER, depositor BLOB, sealed_hash BLOB);
             INSERT INTO mail VALUES (1, 1, 'mb_1', x'00', 500, 0, 0, x'01', NULL);
             CREATE TABLE enrollments (enrollment_id BLOB PRIMARY KEY, enroll_pk BLOB NOT NULL, enroll_pk_pq BLOB NOT NULL DEFAULT x'',
                                peer_id TEXT NOT NULL, state TEXT NOT NULL, enrolled_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
                                bytes_mail INTEGER NOT NULL DEFAULT 0, bytes_archive INTEGER NOT NULL DEFAULT 0, bytes_blob INTEGER NOT NULL DEFAULT 0);
             INSERT INTO enrollments VALUES (x'01', x'00', x'', 'p', 'active', 0, 0, 500, 0, 0);
             PRAGMA user_version = 0;",
        )
        .unwrap();
    s.init_schema().unwrap();
    let depositor = s.conn.query_row("SELECT COUNT(*) FROM pragma_table_info('mail') WHERE name = 'depositor'", [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(depositor, 0, "the old table is gone");
    assert_eq!(s.conn.query_row("SELECT bytes_mail FROM enrollments", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
}
