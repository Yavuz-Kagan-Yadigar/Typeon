use super::*;

#[test]
fn packet_round_trip_and_tamper() {
    let key = [7u8; 32];
    let sid = [1, 2, 3, 4, 5, 6, 7, 8];
    let p = seal_packet(&key, &sid, 42, 2, b"frame");
    let (s, seq) = packet_header(&p).unwrap();
    assert_eq!((s, seq), (sid, 42));
    assert_eq!(&open_packet(&key, &sid, seq, &p).unwrap()[5..], b"frame");
    let mut bad = p.clone();
    bad[10] ^= 1; // header is AAD
    let (s2, seq2) = packet_header(&bad).unwrap();
    assert!(open_packet(&key, &s2, seq2, &bad).is_none());
    assert!(open_packet(&[8u8; 32], &sid, seq, &p).is_none());
}

#[test]
fn every_receiver_gets_its_own_key() {
    let master = [7u8; 32];
    assert_eq!(*pair_key(&master, "bob"), *pair_key(&master, "bob"));
    assert_ne!(*pair_key(&master, "bob"), *pair_key(&master, "carol"));
    assert_ne!(*pair_key(&master, "bob"), master);
    // What we seal for bob opens with bob's key only.
    let sid = [1u8; 8];
    let p = seal_packet(&pair_key(&master, "bob"), &sid, 1, 1, b"x");
    assert!(open_packet(&pair_key(&master, "bob"), &sid, 1, &p).is_some());
    assert!(open_packet(&pair_key(&master, "carol"), &sid, 1, &p).is_none());
}

#[test]
fn frame_round_trip() {
    let f = encode_frame(b"mb_1", b"data");
    let (mb, d) = futures::executor::block_on(read_frame(&mut futures::io::Cursor::new(f))).unwrap();
    assert_eq!((mb.as_slice(), d.as_slice()), (&b"mb_1"[..], &b"data"[..]));
}

#[test]
fn replay_window() {
    let mut r = Remote::new("", 0, [0; 32], [0; 8]);
    assert!(r.is_new(5));
    r.record(5);
    assert!(!r.is_new(5));
    assert!(r.is_new(4)); // late but unseen
    r.record(200);
    assert!(!r.is_new(100)); // too old
    // 64 late packets after 300 must not push 300 out of the window.
    r.record(300);
    for seq in 237..300 {
        assert!(r.is_new(seq));
        r.record(seq);
    }
    r.record(301);
    assert!(!r.is_new(300) && !r.is_new(237) && !r.is_new(236));
}

#[test]
fn send_recv_through_the_static() {
    media_start([3u8; 32], [9u8; 8]);
    // Talk to ourselves: our own stream id as a remote.
    media_add_remote("self", &[3u8; 32], &[9u8; 8]);
    let packet = seal_packet(&[3u8; 32], &[9u8; 8], 1, 1, b"opus");
    media_on_packet(&packet);
    media_on_packet(&packet); // duplicate dropped
    assert_eq!(media_recv(0).unwrap(), b"\x01\x00opus");
    assert!(media_recv(0).is_none());
    // A receiver reporting 700 ms of queue on our stream is congestion.
    let mut report = [9u8; 8].to_vec();
    report.extend_from_slice(&700u16.to_be_bytes());
    report.push(1); // keyframe please
    media_on_packet(&seal_packet(&[3u8; 32], &[9u8; 8], 5, KIND_REPORT, &report));
    assert!(media_recv(0).is_none(), "reports never reach Kotlin");
    assert_eq!(media_backlog(), 7);
    assert!(media_take_keyframe_request());
    assert!(!media_take_keyframe_request());
    media_on_packet(&seal_packet(&[3u8; 32], &[9u8; 8], 6, KIND_STATE, &[1]));
    assert_eq!(media_flags_of("self"), (true, false));
    assert!(media_recv(0).is_none(), "state never reaches Kotlin");
    // A second device claiming the same stream id does not lock the first
    // out: the key decides.
    media_add_remote("thief", &[4u8; 32], &[9u8; 8]);
    // The relay address of a direction comes from that direction's key.
    assert!(relay_listen_keys().contains(&vec![3u8; 32]));
    let m = media();
    assert_eq!(m.targets["self"].mailbox, crate::server_client::key_bound_mailbox_id(&pair_key(&m.key, "self")[..]).unwrap().into_bytes());
    assert_ne!(m.targets["self"].mailbox, m.targets["thief"].mailbox);
    drop(m);
    media_on_packet(&seal_packet(&[3u8; 32], &[9u8; 8], 7, 1, b"mine"));
    assert_eq!(media_recv(0).unwrap(), b"\x01\x00mine");
    // A re-key keeps the slot.
    media_add_remote("self", &[5u8; 32], &[8u8; 8]);
    assert_eq!(media_slot_of("self"), Some(0));
    media_stop();
    media_on_packet(&seal_packet(&[3u8; 32], &[9u8; 8], 2, 1, b"x"));
    assert!(media_recv(0).is_none());
}
