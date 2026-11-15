//! Call relay streams.

use super::*;

/// Accepts relay streams and turns each into `RelayEvent`s.
///
/// `events` is bounded and awaited. A peer that floods frames is slowed by its own stream, instead of growing
/// a queue in memory.
pub(super) async fn accept_relay_streams(mut incoming: libp2p_stream::IncomingStreams, events: tokio::sync::mpsc::Sender<RelayEvent>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let live = std::sync::Arc::new(AtomicUsize::new(0));
    let per_peer = std::sync::Arc::new(std::sync::Mutex::new(HashMap::<PeerId, usize>::new()));
    let mut next_id = 0u64;
    while let Some((peer, stream)) = incoming.next().await {
        // Dropping the stream closes it. There is no task and no queue for it.
        if live.load(Ordering::Relaxed) >= MAX_RELAY_STREAMS {
            continue;
        }
        {
            let mut m = per_peer.lock().unwrap_or_else(|e| e.into_inner());
            let n = m.entry(peer).or_insert(0);
            if *n >= MAX_RELAY_STREAMS_PER_PEER {
                continue;
            }
            *n += 1;
        }
        live.fetch_add(1, Ordering::Relaxed);
        next_id += 1;
        let id = next_id;
        let events = events.clone();
        let live = live.clone();
        let per_peer = per_peer.clone();
        tokio::spawn(async move {
            relay_stream(peer, id, stream, events).await;
            live.fetch_sub(1, Ordering::Relaxed);
            let mut m = per_peer.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = m.get_mut(&peer) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&peer);
                }
            }
        });
    }
}

/// One relay stream: frames in become `RelayEvent::Frame`, and the writer queue goes out.
pub(super) async fn relay_stream(peer: PeerId, id: u64, stream: libp2p::Stream, events: tokio::sync::mpsc::Sender<RelayEvent>) {
    let (mut rd, wr) = futures::AsyncReadExt::split(stream);
    let (tx, rx) = tokio::sync::mpsc::channel(LINK_QUEUE);
    if events.send(RelayEvent::Open { peer, id, tx }).await.is_err() {
        return;
    }
    let mut pump = tokio::spawn(pump_writes(wr, rx));
    loop {
        let frame = tokio::select! {
            // The loop dropped `tx` (not enrolled, revoked, or replaced). Stop reading, or the peer keeps
            // feeding `events`.
            _ = &mut pump => break,
            frame = read_frame(&mut rd) => frame,
        };
        let Ok((mailbox, data)) = frame else { break };
        let Ok(mailbox) = String::from_utf8(mailbox) else { break };
        if events.send(RelayEvent::Frame { peer, mailbox, data }).await.is_err() {
            break;
        }
    }
    let _ = events.send(RelayEvent::Closed { peer, id }).await;
}

impl ServerCore {
    /// Call-media relay (see `RELAY_PROTOCOL`). Forwards a frame to every OTHER connected client listening on the
    /// frame's mailbox. Only enrolled, non-revoked clients get a link. Everyone else's frames are ignored.
    pub(super) fn handle_relay(&mut self, ev: RelayEvent) {
        match ev {
            RelayEvent::Open { peer, id, tx } => match self.active(peer) {
                Some(_) => {
                    debug!("Call relay opened: {peer}");
                    self.relay_links.insert(peer, (id, tx));
                }
                // Dropping `tx` ends the writer, which closes the stream.
                _ => self.stats.rejected += 1,
            },
            RelayEvent::Closed { peer, id } => {
                if self.relay_links.get(&peer).map(|(i, _)| *i) == Some(id) {
                    self.relay_links.remove(&peer);
                    debug!("Call relay closed: {peer}");
                }
            }
            RelayEvent::Frame { peer, mailbox, data } => {
                if !self.relay_links.contains_key(&peer) {
                    return;
                }
                let now = mono_ms();
                let budget = self.relay_budget.entry(peer).or_insert((now, 0));
                if now.saturating_sub(budget.0) > RELAY_WINDOW_MS {
                    *budget = (now, 0);
                }
                // Each frame also pays its overhead. An empty frame is refused: free empty frames filled a call's writer queue.
                if data.is_empty() {
                    self.stats.rejected += 1;
                    return;
                }
                budget.1 += data.len() + RELAY_FRAME_OVERHEAD;
                if budget.1 > RELAY_BYTES_PER_WINDOW {
                    self.stats.rejected += 1;
                    return;
                }
                let cold_bytes = budget.1;
                let frame = encode_frame(&[], &data);
                let targets: Vec<PeerId> = self
                    .live_interest
                    .iter()
                    .filter(|(target, boxes)| **target != peer && boxes.contains(&mailbox))
                    .map(|(target, _)| *target)
                    .collect();
                for target in targets {
                    // A call sends both ways. Until the target has sent this peer a frame, only the first few packets
                    // pass, so a client cannot flood a call it is not part of.
                    let mutual = self.relay_pairs.get(&(target, peer)).map_or(false, |t| now.saturating_sub(*t) <= RELAY_WINDOW_MS);
                    if !mutual && cold_bytes > RELAY_COLD_BYTES_PER_WINDOW {
                        self.stats.rejected += 1;
                        continue;
                    }
                    if let Some((_, tx)) = self.relay_links.get(&target) {
                        if tx.try_send(frame.clone()).is_ok() {
                            self.stats.relayed += 1;
                            self.relay_pairs.insert((peer, target), now);
                        }
                    }
                }
            }
        }
    }

}
