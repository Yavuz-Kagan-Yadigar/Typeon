//! Media plane: per-call media keys and remotes, sending, receiving, links and the stream acceptor.

use super::*;

pub(super) fn media() -> MutexGuard<'static, Media> {
    MEDIA.lock().unwrap_or_else(|p| p.into_inner())
}

pub(super) fn media_start(key: &[u8; 32], sid: [u8; 8]) {
    let mut m = media();
    let generation = m.generation + 1;
    let next_link_id = m.next_link_id;
    let floors = keep_floors(&mut m);
    *m = Media { active: true, generation, key: Zeroizing::new(*key), sid, next_link_id, floors, ..Default::default() };
}

/// Dropping the links closes their channels, which ends the writer tasks and
/// closes the streams (the server then forgets our relay link).
pub(super) fn media_stop() {
    let mut m = media();
    let generation = m.generation + 1;
    let next_link_id = m.next_link_id;
    let floors = keep_floors(&mut m);
    *m = Media { generation, next_link_id, floors, ..Default::default() };
    drop(m);
    INBOX_READY.notify_all();
}

/// See `wipe_all_local_state`.
pub(crate) fn drop_media() {
    media_stop();
    media().floors.clear();
}

/// A peer keeps its key, stream id and counter for its whole call session,
/// also while we leave and join again. The highest `seq` seen under each key
/// outlives our remote, so a rejoin does not open a fresh replay window under
/// the same key (a relay could replay the recorded part of the call).
fn keep_floors(m: &mut Media) -> VecDeque<([u8; 32], u64)> {
    let mut floors = std::mem::take(&mut m.floors);
    for r in m.remotes.values() {
        push_floor(&mut floors, &r.key, r.max_seq);
    }
    floors
}

fn push_floor(floors: &mut VecDeque<([u8; 32], u64)>, key: &[u8; 32], max_seq: u64) {
    if max_seq == 0 {
        return;
    }
    let tag = key_tag(key);
    floors.retain(|(t, _)| *t != tag);
    if floors.len() >= 64 {
        floors.pop_front();
    }
    floors.push_back((tag, max_seq));
}

/// Floors are keyed by a hash, so no media key outlives its call in memory.
fn key_tag(key: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(key).into()
}

pub(super) fn media_add_remote(fp: &str, key: &[u8], sid: &[u8]) {
    let (Ok(key), Ok(sid)) = (<[u8; 32]>::try_from(key), <[u8; 8]>::try_from(sid)) else { return };
    let mut m = media();
    if !m.active || m.remotes.get(fp).map_or(false, |r| r.sid == sid && *r.key == key) {
        return;
    }
    // A re-key keeps the device's slot (Kotlin holds one decoder per slot,
    // and a fresh slot per Accept would wrap into someone else's).
    let slot = match m.remotes.get(fp) {
        Some(r) => r.slot,
        // The next slot nobody holds. The bare counter wrapped after 256
        // joins (a participant alternating Hangup and Accept) into a slot in
        // use, and its frames were shown as the other participant's.
        None => {
            let from = m.next_slot;
            let Some(s) = (0..=u8::MAX).map(|i| from.wrapping_add(i)).find(|s| !m.remotes.values().any(|r| r.slot == *s)) else { return };
            m.next_slot = s.wrapping_add(1);
            s
        }
    };
    let mut remote = Remote::new(fp, slot, key, sid);
    // Same key again (a repeated Accept with another stream id): keep the
    // replay window, or `seq` would count from 1 again under that key.
    if let Some(old) = m.remotes.get(fp).filter(|r| *r.key == key) {
        remote.max_seq = old.max_seq;
        remote.seen = old.seen;
    } else if let Some(&(_, floor)) = m.floors.iter().find(|(t, _)| *t == key_tag(&key)) {
        // Everything up to the floor counts as seen.
        remote.max_seq = floor;
        remote.seen = u64::MAX;
    }
    m.remotes.insert(fp.to_string(), remote);
    let send_key = pair_key(&m.key, fp);
    // Never fails (fixed-size seeds); an empty id is refused by the server.
    let mailbox = crate::server_client::key_bound_mailbox_id(&send_key[..]).unwrap_or_default().into_bytes();
    m.targets.insert(fp.to_string(), Target { peer: None, mailbox, key: send_key, audio_hold: false, hold_at: 0, hold_disarmed: false, relay_via: None });
}

/// The keys the call's remotes seal our media with. Each gives the relay
/// address its sender writes to (`server_client::key_bound_mailbox_id`), which this
/// device registers at its servers while the call runs.
pub(crate) fn relay_listen_keys() -> Vec<Vec<u8>> {
    media().remotes.values().map(|r| r.key.to_vec()).collect()
}

pub(super) fn media_remove_remote(fp: &str) {
    let mut m = media();
    if let Some(r) = m.remotes.remove(fp) {
        push_floor(&mut m.floors, &r.key, r.max_seq);
    }
    m.targets.remove(fp);
}

pub(super) fn media_slot_of(fp: &str) -> Option<u8> {
    media().remotes.get(fp).map(|r| r.slot)
}

/// `(muted, camera off)` as last announced by `fp`.
pub(super) fn media_flags_of(fp: &str) -> (bool, bool) {
    media().remotes.get(fp).map(|r| (r.muted, r.video_off)).unwrap_or_default()
}

pub(super) fn media_last_rx(fp: &str) -> u64 {
    media().remotes.get(fp).map(|r| r.last_rx_ms).unwrap_or(0)
}

/// Time since the last packet from `fp` (or since it was added, before its
/// first packet), on the monotonic clock.
pub(super) fn media_rx_age(fp: &str) -> Option<Duration> {
    media().remotes.get(fp).map(|r| r.last_rx.unwrap_or(r.added).elapsed())
}

pub(super) fn media_stats() -> serde_json::Value {
    let m = media();
    serde_json::json!({
        "sent": m.sent, "received": m.received, "dropped": m.dropped, "rx_dropped": m.rx_dropped,
        "via_direct": m.via_direct, "via_relay": m.via_relay,
        "direct_links": m.direct.len(), "relay_links": m.relays.len(),
        "backlog": backlog_of(&m),
        "tx_queue_ms": reported_queue(&m),
        "rx_queue_ms": m.remotes.values().map(|r| r.last_queue).max().unwrap_or(0),
        "rx_delay_ms": m.remotes.values().map(|r| r.delay_ewma as i64).max().unwrap_or(0),
        "bytes_out": m.bytes_out, "bytes_in": m.bytes_in,
    })
}

/// Congestion signal for Kotlin, in "frames": the deepest local link queue,
/// or the worst queueing delay a receiver reports on our stream (100 ms = 1).
pub(super) fn backlog_of(m: &Media) -> usize {
    let local = m.direct.values().chain(m.relays.values()).map(|l| LINK_QUEUE - l.tx.capacity()).max().unwrap_or(0);
    local.max(reported_queue(m) as usize / 100)
}

/// The (lower) median of the fresh reports: the one encoder serves every
/// receiver, so one slow or hostile reporter must not set its quality for all.
/// Its audio is held back per receiver (`Target::audio_hold`).
pub(super) fn reported_queue(m: &Media) -> u32 {
    let now = current_time_ms();
    let mut q: Vec<u32> = m.reports.values().filter(|(_, at)| now.saturating_sub(*at) < REPORT_TTL_MS).map(|(q, _)| *q).collect();
    q.sort_unstable();
    q.get(q.len().saturating_sub(1) / 2).copied().unwrap_or(0)
}

pub(super) fn depth_max(kind: u8) -> usize {
    match kind {
        KIND_VIDEO => VIDEO_QUEUE_MAX,
        KIND_REPORT | KIND_STATE => LINK_QUEUE,
        _ => AUDIO_QUEUE_MAX,
    }
}

/// Encrypts one frame and queues it for every call participant. Never blocks:
/// a full link queue drops the frame (live media, late = useless).
pub fn media_send(kind: u8, payload: &[u8]) -> bool {
    media_send_to(kind, payload, None)
}

/// `media_send`, to the one device `only` when given (a report is about
/// that sender's stream only).
pub(super) fn media_send_to(kind: u8, payload: &[u8], only: Option<&str>) -> bool {
    use tokio::sync::mpsc::error::TrySendError;
    let mut m = media();
    if !m.active || m.targets.is_empty() || payload.len() > MAX_FRAME - 64 {
        return false;
    }
    if kind == KIND_AUDIO {
        let now = current_time_ms();
        let mono = mono_ms();
        let Media { targets, reports, .. } = &mut *m;
        for (fp, t) in targets.iter_mut() {
            let q = reports.get(fp).filter(|(_, at)| now.saturating_sub(*at) < REPORT_TTL_MS).map_or(0, |(q, _)| *q);
            if q < AUDIO_HOLD_BELOW_MS {
                t.hold_disarmed = false;
            }
            if t.audio_hold && (q < AUDIO_HOLD_BELOW_MS || mono.saturating_sub(t.hold_at) >= AUDIO_HOLD_MAX_MS) {
                t.audio_hold = false;
                t.hold_disarmed = q >= AUDIO_HOLD_BELOW_MS;
            } else if !t.audio_hold && !t.hold_disarmed && q > AUDIO_HOLD_ABOVE_MS {
                t.audio_hold = true;
                t.hold_at = mono;
            }
        }
        let held = m.targets.values().filter(|t| t.audio_hold).count();
        if held == m.targets.len() {
            return false;
        }
    }
    m.seq += 1;
    let targets: Vec<(Option<PeerId>, Option<PeerId>, Vec<u8>, Vec<u8>)> = m
        .targets
        .iter()
        .filter(|(fp, t)| (kind != KIND_AUDIO || !t.audio_hold) && only.map_or(true, |o| o == fp.as_str()))
        .map(|(_, t)| (t.peer, t.relay_via, t.mailbox.clone(), seal_packet(&t.key, &m.sid, m.seq, kind, payload)))
        .collect();
    let mut any = false;
    let dropped_before = m.dropped;
    for (peer, relay_via, mailbox, packet) in targets {
        if let Some(p) = peer {
            let res = m.direct.get(&p).map(|l| {
                if LINK_QUEUE - l.tx.capacity() >= depth_max(kind) { Err(TrySendError::Full(Vec::new())) }
                else { l.tx.try_send(encode_frame(&[], &packet)) }
            });
            match res {
                Some(Ok(())) => { m.via_direct += 1; m.bytes_out += packet.len() as u64; any = true; continue; }
                Some(Err(TrySendError::Full(_))) => { m.dropped += 1; continue; }
                Some(Err(TrySendError::Closed(_))) => { m.direct.remove(&p); }
                None => {}
            }
        }
        // The server its frames came through, else every relay link: a
        // server without a listener for the mailbox drops the frame while
        // `try_send` still succeeds.
        let servers: Vec<PeerId> = match relay_via.filter(|s| m.relays.contains_key(s)) {
            Some(s) => vec![s],
            None => m.relays.keys().copied().collect(),
        };
        let frame = encode_frame(&mailbox, &packet);
        let mut relayed = false;
        for s in servers {
            let l = &m.relays[&s];
            let r = if LINK_QUEUE - l.tx.capacity() >= depth_max(kind) { Err(TrySendError::Full(Vec::new())) } else { l.tx.try_send(frame.clone()) };
            match r {
                Ok(()) => { m.bytes_out += packet.len() as u64; relayed = true; }
                Err(TrySendError::Full(_)) => { m.dropped += 1; }
                Err(TrySendError::Closed(_)) => { m.relays.remove(&s); }
            }
        }
        if relayed {
            m.via_relay += 1;
            any = true;
        }
    }
    // A dropped video frame leaves that receiver's decoder with a hole: every
    // later frame is garbage to it until a keyframe (GOP is 10 s).
    let now = current_time_ms();
    if kind == KIND_VIDEO && m.dropped != dropped_before && now.saturating_sub(m.keyframe_at) >= KEYFRAME_MIN_MS {
        m.keyframe_asked = true;
        m.keyframe_at = now;
    }
    if any {
        m.sent += 1;
    }
    any
}

/// Congestion signal in frames, see `backlog_of`.
pub fn media_backlog() -> usize {
    backlog_of(&media())
}

pub(super) fn media_on_packet(packet: &[u8]) {
    media_on_packet_via(packet, None)
}

/// Any packet from any link (direct, inbound, relay) ends up here. `via`:
/// the server of a relay link.
pub(super) fn media_on_packet_via(packet: &[u8], via: Option<PeerId>) {
    let Some((sid, seq)) = packet_header(packet) else { return };
    let mut m = media();
    if !m.active {
        return;
    }
    // Several remotes may claim one stream id; the AEAD key says whose it is.
    let Some((fp, pt)) = m
        .remotes
        .values()
        .filter(|r| r.sid == sid && r.is_new(seq))
        .find_map(|r| open_packet(&r.key, &sid, seq, packet).map(|pt| (r.fp.clone(), pt)))
    else {
        return;
    };
    let now = current_time_ms();
    let sent_ms = u32::from_be_bytes([pt[1], pt[2], pt[3], pt[4]]);
    // A hostile `sent_ms` must not skew the EWMA beyond +-10 min.
    let delay = ((now as u32).wrapping_sub(sent_ms) as i32 as f64).clamp(-600_000.0, 600_000.0);
    if let Some(server) = via {
        if let Some(t) = m.targets.get_mut(&fp) {
            t.relay_via = Some(server);
        }
    }
    let Some(r) = m.remotes.get_mut(&fp) else { return };
    let slot = r.slot;
    r.record(seq);
    if r.via != via {
        r.via = via;
        r.samples = 0;
    }
    r.record_delay(delay);
    if pt[0] == KIND_STATE {
        if let Some(&flags) = pt.get(5) {
            r.muted = flags & 1 != 0;
            r.video_off = flags & 2 != 0;
        }
        return;
    }
    if pt[0] == KIND_REPORT {
        if pt.len() >= 5 + 10 && pt[5..13] == m.sid {
            let q = u16::from_be_bytes([pt[13], pt[14]]) as u32;
            m.reports.insert(fp.clone(), (q, now));
            if pt.len() >= 16 && pt[15] & 2 != 0 {
                m.avc_asked = true;
            }
            if pt.len() >= 16 && pt[15] & 1 != 0 && now.saturating_sub(m.keyframe_at) >= KEYFRAME_MIN_MS {
                m.keyframe_asked = true;
                m.keyframe_at = now;
            }
        }
        return;
    }
    let report = (r.want_keyframe || now.saturating_sub(r.last_report_ms) >= REPORT_EVERY_MS).then(|| {
        r.last_report_ms = now;
        let mut p = sid.to_vec();
        p.extend_from_slice(&(r.take_queue_ms().min(u16::MAX as u32) as u16).to_be_bytes());
        p.push(r.want_keyframe as u8 | (r.want_avc as u8) << 1);
        r.want_keyframe = false;
        p
    });
    let mut out = Vec::with_capacity(pt.len() - 3);
    out.push(pt[0]);
    out.push(slot);
    out.extend_from_slice(&pt[5..]);
    m.received += 1;
    m.bytes_in += packet.len() as u64;
    if m.inbox.len() >= INBOX_MAX {
        // After a Tor stall frames arrive in a burst: shed the oldest video
        // first (costs a frozen picture until the next keyframe), audio last.
        // Without video, the oldest frame of the same sender: one flooding
        // participant must not push out the others' audio.
        let victim = m
            .inbox
            .iter()
            .position(|f| f[0] == KIND_VIDEO)
            .or_else(|| m.inbox.iter().position(|f| f[1] == slot))
            .unwrap_or(0);
        if let Some(f) = m.inbox.remove(victim) {
            if f[0] == KIND_VIDEO {
                // The decoder now has a hole; get it a fresh keyframe.
                m.remotes.values_mut().filter(|r| r.slot == f[1]).for_each(|r| r.want_keyframe = true);
            }
        }
        m.rx_dropped += 1;
    }
    m.inbox.push_back(out);
    drop(m);
    INBOX_READY.notify_one();
    if let Some(p) = report {
        media_send_to(KIND_REPORT, &p, Some(fp.as_str()));
    }
}

/// Kotlin's decoder for `slot` cannot decode until the next keyframe.
pub fn media_request_keyframe(slot: u8) {
    media().remotes.values_mut().filter(|r| r.slot == slot).for_each(|r| r.want_keyframe = true);
}

/// Kotlin's HEVC decoder for `slot` failed before its first frame: ask that
/// sender for H.264 (and a keyframe) in every report from now on.
pub fn media_request_avc(slot: u8) {
    media().remotes.values_mut().filter(|r| r.slot == slot).for_each(|r| {
        r.want_avc = true;
        r.want_keyframe = true;
    });
}

/// Some receiver asked for H.264 since the last call.
pub fn media_take_avc_request() -> bool {
    std::mem::take(&mut media().avc_asked)
}

/// Some receiver asked for a keyframe since the last call.
pub fn media_take_keyframe_request() -> bool {
    std::mem::take(&mut media().keyframe_asked)
}

/// Next received frame as `[kind][slot][payload]`, or `None` after `timeout_ms`.
pub fn media_recv(timeout_ms: u64) -> Option<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut m = media();
    loop {
        if let Some(p) = m.inbox.pop_front() {
            return Some(p);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        m = match INBOX_READY.wait_timeout(m, deadline - now) {
            Ok((g, _)) => g,
            Err(p) => p.into_inner().0,
        };
    }
}

/// Opens the links the call needs and is missing. Called from the poll loop;
/// the opening itself happens on tokio.
pub(super) fn media_supervise(control: &libp2p_stream::Control, peers: Vec<(String, Option<PeerId>)>, servers: Vec<PeerId>) {
    let now = mono_ms();
    let mut m = media();
    if !m.active {
        return;
    }
    for (fp, peer) in peers {
        if let Some(t) = m.targets.get_mut(&fp) {
            t.peer = peer;
        }
    }
    let mut wanted: Vec<(PeerId, bool)> = m
        .targets
        .values()
        .filter_map(|t| t.peer)
        .filter(|p| !m.direct.contains_key(p))
        .map(|p| (p, false))
        .collect();
    wanted.extend(servers.into_iter().filter(|p| !m.relays.contains_key(p)).map(|p| (p, true)));
    for (peer, relay) in wanted {
        if m.opening.get(&peer).map_or(false, |until| now < *until) {
            continue;
        }
        m.opening.insert(peer, now + OPEN_TIMEOUT.as_millis() as u64 + REOPEN_BACKOFF_MS);
        let control = control.clone();
        let generation = m.generation;
        RUNTIME.spawn(open_link(control, peer, relay, generation));
    }
}

pub(super) async fn open_link(mut control: libp2p_stream::Control, peer: PeerId, relay: bool, generation: u64) {
    let what = if relay { "server" } else { "direct" };
    let proto = if relay { RELAY_PROTOCOL } else { MEDIA_PROTOCOL };
    let opened = match tokio::time::timeout(OPEN_TIMEOUT, control.open_stream(peer, proto)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".to_string()),
    };
    let stream = match opened {
        Ok(s) => s,
        Err(e) => {
            warn!("Call stream could not be opened ({}, {}): {}", what, crate::log_id(&peer), e);
            let mut m = media();
            if m.generation == generation {
                m.opening.insert(peer, mono_ms() + REOPEN_BACKOFF_MS);
            }
            return;
        }
    };
    let (mut rd, wr) = stream.split();
    let (tx, rx) = tokio::sync::mpsc::channel(LINK_QUEUE);
    let id = {
        let mut m = media();
        if !m.active || m.generation != generation {
            return;
        }
        m.next_link_id += 1;
        let id = m.next_link_id;
        let link = Link { tx, id };
        if relay { m.relays.insert(peer, link); } else { m.direct.insert(peer, link); }
        m.opening.remove(&peer);
        id
    };
    info!("Call stream opened ({}, {})", what, crate::log_id(&peer));
    tokio::spawn(pump_writes(wr, rx));
    // Relay links carry the server's pushes back to us; on a direct outbound
    // link the read only notices the peer closing it.
    // Bounded wait: after the call ends a silent link (a direct one never
    // carries anything back) must not keep this task and the stream until
    // the far end closes it. A wait that times out has read nothing, unless
    // one frame took that long, which a live link does not.
    let via = relay.then_some(peer);
    'link: loop {
        // The same future survives a timeout: dropping it mid-frame would eat
        // part of a header and desync the next read.
        let mut next = Box::pin(read_frame(&mut rd));
        let frame = loop {
            match tokio::time::timeout(Duration::from_millis(MEDIA_LOST_MS), &mut next).await {
                Ok(r) => break r,
                Err(_) if media().generation != generation => break 'link,
                Err(_) => {}
            }
        };
        let Ok((_, data)) = frame else { break };
        if media().generation != generation {
            break;
        }
        media_on_packet_via(&data, via);
    }
    let mut m = media();
    let map = if relay { &mut m.relays } else { &mut m.direct };
    if map.get(&peer).map(|l| l.id) == Some(id) {
        map.remove(&peer);
    }
    // A link that opened and closed is not reopened on the very next sweep.
    if m.generation == generation {
        m.opening.insert(peer, mono_ms() + REOPEN_BACKOFF_MS);
        link_lost(&mut m);
    }
    info!("Call stream closed ({}, {})", what, crate::log_id(&peer));
}

/// A link that closed mid-call took the frames it had queued or in flight
/// with it (a Tor circuit dying is the usual cause). The decoders on both
/// ends now have holes: ask every sender for a keyframe, and send one.
fn link_lost(m: &mut Media) {
    let now = current_time_ms();
    if now.saturating_sub(m.keyframe_at) >= KEYFRAME_MIN_MS {
        m.keyframe_asked = true;
        m.keyframe_at = now;
    }
    m.remotes.values_mut().for_each(|r| r.want_keyframe = true);
}

/// Reads media frames peers push to us over direct streams. Registered once
/// per swarm (`start_network`).
pub(crate) fn spawn_media_acceptor(control: &mut libp2p_stream::Control) {
    let mut incoming = match control.accept(MEDIA_PROTOCOL) {
        Ok(i) => i,
        Err(e) => { warn!("Call stream listener could not be set up: {}", e); return; }
    };
    RUNTIME.spawn(async move {
        while let Some((peer, mut stream)) = incoming.next().await {
            // Outside a call nobody has a reason to push media: drop the
            // stream instead of parking a reader (and up to MAX_FRAME) on it.
            let generation = {
                let mut m = media();
                if !m.active {
                    continue;
                }
                let open = m.inbound.entry(peer).or_insert(0);
                if *open >= MAX_INBOUND_PER_PEER {
                    continue;
                }
                *open += 1;
                m.generation
            };
            // Ends with the call, and on a silent stream: every participant
            // sends a state packet each second.
            // Only from a device in the call. `Target::peer` is filled by the
            // next poll turn, so a stream that arrives first gets
            // `INBOUND_GRACE` in total, however little it sends.
            tokio::spawn(async move {
                let idle = Duration::from_millis(MEDIA_LOST_MS);
                let opened = Instant::now();
                // Only a call target's stream that ends costs keyframes: any
                // connected peer could open and drop streams in a loop.
                let mut was_target = false;
                loop {
                    let wait = {
                        let m = media();
                        if m.generation != generation {
                            break;
                        }
                        if m.targets.values().any(|t| t.peer == Some(peer)) {
                            was_target = true;
                            idle
                        } else {
                            match INBOUND_GRACE.checked_sub(opened.elapsed()) {
                                Some(left) => left,
                                None => break,
                            }
                        }
                    };
                    let Ok(Ok((_, data))) = tokio::time::timeout(wait, read_frame(&mut stream)).await else { break };
                    media_on_packet(&data);
                }
                let mut m = media();
                if m.generation == generation {
                    if was_target {
                        link_lost(&mut m);
                    }
                    let left = m.inbound.get(&peer).map_or(0, |n| n.saturating_sub(1));
                    if left == 0 {
                        m.inbound.remove(&peer);
                    } else {
                        m.inbound.insert(peer, left);
                    }
                }
            });
        }
    });
}
