//! Server connections: sweep, enrollment, responses, errors, pushes.

use super::*;

impl P2PCore {
    pub(super) fn send_server_request(&mut self, peer: PeerId, req: ServerRequest) -> Option<request_response::OutboundRequestId> {
        let swarm = self.swarm.as_mut()?;
        Some(swarm.behaviour_mut().server_rpc.send_request(&peer, req))
    }

    // -----------------------------------------------------------------
    // Periodic scan
    // -----------------------------------------------------------------

    /// Connection, registration, subscription and fetch upkeep. `poll_events` calls it every turn and it checks
    /// its own interval (the `reconnect_sweep` pattern).
    pub(crate) fn server_sweep(&mut self) {
        if self.servers.is_empty() {
            return;
        }
        // The head upload's `.enc` hash finished on its thread: only the blob path continues. A forced full sweep
        // each turn did a Register diff, a fetch and archive checks for the whole wait.
        let hashed = self.server_blob_uploads.first()
            .filter(|u| u.hashing.as_ref().is_some_and(|c| c.get().is_some()))
            .and_then(|u| u.server_id.clone());
        if let Some(sid) = hashed {
            if let Some(peer_id) = self.server_rt.get(&sid).and_then(|r| r.peer_id) {
                self.server_flush_blobs(&sid, peer_id);
            }
        }
        // Radio saver (see `RADIO_WINDOW_MS`): only inside the window. New mail still arrives at once as server push
        // over the open connection. `server_sweep_at == 0` means "sweep now" (more mail in the batch, a chunk acked,
        // just connected). The radio is up for that exchange anyway, and waiting cost one whole window per step.
        if !self.radio_window_open && self.server_sweep_at != 0 {
            return;
        }
        let now = mono_ms();
        if now < self.server_sweep_at {
            return;
        }
        self.server_sweep_at = now + SERVER_SWEEP_INTERVAL_MS;
        self.server_unknown_mailboxes.retain(|_, until| now < *until);
        self.resume_archive_rotation();
        self.maybe_archive_backfill();

        // Self-check fix: `server_deposit_locations` was pruned nowhere. Entries were removed only on cancel (`cancel_server_deposit`) or refresh
        // (`forget_server_deposit`), so every normally acknowledged message left an entry behind and the map grew without bound for the life of the
        // process.
        //
        // An entry is only useful while the message is still awaiting confirmation (the only thing a cancel can withdraw). So the rule is simple:
        // drop every entry whose message is not in `awaiting_confirmation`.
        if !self.server_deposit_locations.is_empty() {
            let before = self.server_deposit_locations.len();
            let pending: std::collections::HashSet<String> =
                self.awaiting_confirmation.keys().cloned().collect();
            self.server_deposit_locations.retain(|(_, key), _| pending.contains(location_message_id(key)));
            let dropped = before - self.server_deposit_locations.len();
            if dropped > 0 {
                info!("Cleaned {} stale entries from server deposit location record", dropped);
            }
        }

        // Only what the loop reads. A full clone carried both enrollment secret keys through every sweep.
        struct Sweep { server_id: String, address: String, route_messages: bool, store_history: bool, no_creds: bool }
        let records: Vec<Sweep> = self
            .servers
            .iter()
            .map(|s| Sweep {
                server_id: s.server_id.clone(),
                address: s.address.clone(),
                route_messages: s.route_messages,
                store_history: s.store_history,
                no_creds: s.enrollment_id.is_none() && s.token.is_empty(),
            })
            .collect();
        // The same for every server: built once, not per server and per step.
        let own_ids: HashSet<String> = self.own_server_mailboxes().into_keys().collect();
        let mut blobs_flushed = false;
        for rec in records {
            let rt = self.server_rt.entry(rec.server_id.clone()).or_default();
            if rt.peer_id.is_none() {
                rt.peer_id = rec
                    .address
                    .split(',')
                    .filter_map(|a| a.trim().parse::<Multiaddr>().ok())
                    .find_map(|a| extract_peer_id(&a));
            }
            let Some(peer_id) = rt.peer_id else { continue };
            let connected = rt.connected;
            let enrolled = rt.enrolled;
            // Doubles up to 30 min while the server keeps refusing us.
            let hello_stale = now.saturating_sub(rt.hello_sent_at)
                > (SERVER_SWEEP_INTERVAL_MS << rt.hello_attempts.min(7)).min(30 * 60 * 1000);
            // Nothing to enroll with, and the server already said no once.
            let no_credentials = rec.no_creds && rt.last_error.is_some();

            // Ask the swarm: the event-driven `rt.connected` flag may have been missed (see `load_servers_from_db`:
            // if `peer_id` is filled late, `note_server_connection` cannot match it). Redialing a missed connection
            // does NOT help, because libp2p is already connected and raises no new event. So the truth is read from
            // the swarm on every turn.
            let really_connected =
                self.swarm.as_ref().map(|s| s.is_connected(&peer_id)).unwrap_or(false);
            if really_connected && !connected {
                if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                    rt.connected = true;
                }
            }
            let connected = connected || really_connected;
            if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                if connected && enrolled {
                    rt.unready_since = 0;
                } else if rt.unready_since == 0 {
                    rt.unready_since = now;
                }
            }

            if !connected {
                // Offline server: back off 15 s, doubling to 30 min. Without it, every sweep (every 15 s) was one more failed onion lookup, and the
                // CPU never idled (measured: 35 dials in 11 minutes on Wi-Fi).
                let Some(rt) = self.server_rt.get_mut(&rec.server_id) else { continue };
                // A legacy record holding only private-network addresses: the server path is onion-only, so do not dial the LAN.
                let addrs = server_proto::public_server_addrs(rec.address.split(','));
                if addrs.is_empty() {
                    rt.last_error = Some("No reachable address. Add the server again with a new invite code".to_string());
                    continue;
                }
                if now < rt.dial_backoff_until { continue; }
                rt.dial_backoff_until = now + (SERVER_SWEEP_INTERVAL_MS << rt.dial_attempts.min(7)).min(30 * 60 * 1000);
                rt.dial_attempts += 1;
                // Not connected: dial EVERY known address at once (see `ServerRecord.address`).
                for a in addrs.iter().filter_map(|a| a.parse::<Multiaddr>().ok()) {
                    self.dial_with_relay_fallback(peer_id, Some(a));
                }
                continue;
            }
            if !enrolled {
                // One enrollment exchange at a time. A second `Welcome` replaced the challenge that the first `Enroll`
                // was signed over.
                let enrolling = self.server_inflight.values().any(|i| {
                    matches!(i, ServerInflight::Hello { .. } | ServerInflight::Enroll { .. } | ServerInflight::Rebind { .. })
                        && i.server_id() == rec.server_id
                });
                if hello_stale && !no_credentials && !enrolling {
                    if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                        rt.hello_sent_at = now;
                        rt.hello_attempts += 1;
                    }
                    if let Some(id) =
                        self.send_server_request(peer_id, ServerRequest::Hello { version: SERVER_PROTOCOL_VERSION })
                    {
                        self.server_inflight.insert(id, ServerInflight::Hello { server_id: rec.server_id.clone() });
                    }
                }
                continue;
            }

            // Registered: send the subscription difference.
            // A server that only stores history gets no mailbox IDs (it would learn one per conversation), and it is
            // not polled for mail that cannot arrive there. The relay addresses of a running call go to every server:
            // any of them may carry the media, and nothing is stored under them.
            let relay_ids: Vec<String> =
                crate::call::relay_listen_keys().iter().filter_map(|k| key_bound_mailbox_id(k)).collect();
            let mut wanted: HashSet<String> = if rec.route_messages { own_ids.clone() } else { HashSet::new() };
            wanted.extend(relay_ids.iter().cloned());
            if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                // A refusal is not permanent: try again after a while.
                if !rt.refused.is_empty() && now >= rt.refused_retry_at {
                    rt.refused.clear();
                }
                wanted.retain(|id| !rt.refused.contains(id));
            }
            // The server refuses a whole list over its mailbox cap. Over it, the relay IDs and then a stable part of
            // the rest are kept (no churn between sweeps). The remainder is reached over the direct path only.
            let cap = self.server_rt.get(&rec.server_id).map_or(1, Self::mailbox_cap);
            let over_cap = wanted.len() > cap;
            if over_cap {
                let total = wanted.len();
                let mut ids: Vec<String> = wanted.into_iter().collect();
                ids.sort_by_key(|id| (!relay_ids.contains(id), id.clone()));
                ids.truncate(cap);
                wanted = ids.into_iter().collect();
                warn!("Server mailbox limit exceeded: {} > {} ({})", total, cap, crate::log_id(&rec.server_id));
            }
            if let Some(rt) = self.server_rt.get_mut(&rec.server_id) {
                let ours = rt.last_error.as_deref().map_or(false, |e| e.starts_with(TOO_MANY_MAILBOXES));
                if over_cap {
                    rt.last_error = Some(format!("{TOO_MANY_MAILBOXES} ({cap}): some chats use the direct path only"));
                } else if ours && rt.refused.is_empty() {
                    rt.last_error = None;
                }
            }
            let (current, register_ok) = self.server_rt.get(&rec.server_id)
                .map(|r| (r.registered.clone(), now >= r.register_backoff_until)).unwrap_or_default();
            let mut add: Vec<String> = wanted.difference(&current).cloned().collect();
            let mut drop: Vec<String> = current.difference(&wanted).cloned().collect();
            add.truncate(cap);
            drop.truncate(cap);
            let register_inflight = self.server_inflight.values()
                .any(|i| matches!(i, ServerInflight::Register { server_id, .. } if *server_id == rec.server_id));
            if register_ok && !register_inflight && (!add.is_empty() || !drop.is_empty()) {
                // A relay address is new with each call, so its proof goes with the first request. The other IDs are
                // mostly ones this enrollment already reads, and the server names the rest (`Registered.proof_needed`).
                let prove: Vec<String> = add.iter().filter(|id| relay_ids.contains(id)).cloned().collect();
                self.send_register(&rec.server_id, peer_id, add, drop, &prove);
            }

            // Safety pull, in case the push was lost.
            let due = self.server_rt.get(&rec.server_id).map(|r| r.fetch_due_at).unwrap_or(0);
            if rec.route_messages && now >= due {
                self.server_fetch(&rec.server_id, peer_id, &own_ids);
            }

            if rec.store_history {
                self.purge_retired_archive(&rec.server_id, peer_id);
                self.server_flush_archive(&rec.server_id, peer_id);
            }
            // One upload server per sweep: the head upload's own server, or the first ready one that routes when the upload
            // has none or its server is gone or has been down for `BLOB_SERVER_MOVE_MS`.
            if rec.route_messages && !blobs_flushed && self.blob_server_free(&rec.server_id, now) {
                blobs_flushed = true;
                self.server_flush_blobs(&rec.server_id, peer_id);
            }
        }
    }

    // -----------------------------------------------------------------
    // Event processing
    // -----------------------------------------------------------------

    /// Called after the `poll_events` swarm borrow is released.
    ///
    /// `incoming`: envelopes fetched from the server are added HERE and go through the normal incoming path
    /// (`process_incoming_envelope`). Signature checks, the `sender_identity_id` binding check, early-packet
    /// buffering and `Ack` generation are reused as they are.
    pub(crate) fn drive_server_sync(
        &mut self,
        events: Vec<ServerEventLocal>,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) -> Vec<(request_response::ResponseChannel<ServerResponse>, ServerResponse)> {
        // What earlier calls staged was processed in their turn: ack it now, even if the caller's own
        // `commit_server_fetches` did not run.
        self.commit_server_fetches();
        let mut replies = Vec::new();
        for evt in events {
            match evt {
                ServerEventLocal::Request { peer, request, channel } => {
                    let resp = self.handle_server_push(peer, request, incoming);
                    replies.push((channel, resp));
                }
                ServerEventLocal::Response { request_id, response } => {
                    if let Some(inflight) = self.server_inflight.remove(&request_id) {
                        self.handle_server_response(inflight, response, incoming);
                    }
                }
                ServerEventLocal::OutboundFailure { request_id } => {
                    if let Some(inflight) = self.server_inflight.remove(&request_id) {
                        self.handle_server_failure(inflight);
                    }
                }
            }
        }
        replies
    }

    /// The only valid request from a server: `Notify`.
    pub(super) fn handle_server_push(
        &mut self,
        peer: PeerId,
        request: ServerRequest,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) -> ServerResponse {
        match request {
            // The item itself (see `ServerRequest::Push`): run it through the exact `Fetch` path (opening, cursor,
            // ack) as a one-item batch.
            ServerRequest::Push { item } => {
                let sid = self
                    .server_rt
                    .iter()
                    .find(|(_, rt)| rt.peer_id == Some(peer))
                    .map(|(sid, _)| sid.clone());
                let Some(server_id) = sid else {
                    return ServerResponse::Err(ServerErrorCode::BadDirection);
                };
                // Only from a server we are enrolled at, and only once the storage keys are loaded (see `server_fetch`).
                // Otherwise the item stays on the server and comes with the next `Fetch`.
                let enrolled = self.server_rt.get(&server_id).map_or(false, |rt| rt.enrolled);
                if !enrolled {
                    return ServerResponse::Ok;
                }
                if !self.storage_keys_ready() {
                    return self.handle_server_push(peer, ServerRequest::Notify, incoming);
                }
                // 30 per 5 s. Each push costs an open, the processing and an Ack. Over that, the item is left on the
                // server and the push counts as a `Notify` (one fetch per 5 s).
                let now = mono_ms();
                let over = self.server_rt.get_mut(&server_id).map_or(true, |rt| {
                    if now.saturating_sub(rt.push_window_at) >= 5_000 {
                        rt.push_window_at = now;
                        rt.push_count = 0;
                    }
                    rt.push_count += 1;
                    rt.push_count > 30
                });
                if over {
                    return self.handle_server_push(peer, ServerRequest::Notify, incoming);
                }
                // A mailbox held before an earlier item takes its later items in order, from the held item's refetch
                // (not at once: see `SERVER_HOLD_REFETCH_MS`).
                let behind = self.server_rt.get(&server_id)
                    .and_then(|rt| rt.held.get(&item.mailbox_id))
                    .map_or(false, |&(held, _)| item.seq > held);
                if behind {
                    self.refetch_held(&server_id, now);
                    return ServerResponse::Ok;
                }
                // The batch path clears `fetch_inflight`. A real `Fetch` may still be out, so keep its flag.
                let inflight = self.server_rt.get(&server_id).map_or(false, |rt| rt.fetch_inflight);
                self.handle_server_response(
                    ServerInflight::Fetch { server_id: server_id.clone() },
                    ServerResponse::Batch { items: vec![item], more: false },
                    incoming,
                );
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.fetch_inflight = inflight;
                }
                ServerResponse::Ok
            }
            ServerRequest::Notify => {
                // The payload is NOT carried here. We only say "fetch it on the next turn", so the cursor logic stays intact.
                let sid = self
                    .server_rt
                    .iter()
                    .find(|(_, rt)| rt.peer_id == Some(peer))
                    .map(|(sid, _)| sid.clone());
                // One per 5 s. Each `Notify` opens the radio window and forces a sweep, so a server sending them in a row
                // kept the phone fetching without end. A second one within that time is covered by the fetch the first one started.
                let now = mono_ms();
                // Radio saver: after a fetch that found nothing, once per radio window. A server sending `Notify` every
                // 5 s with nothing behind it kept the radio up all night.
                let min_gap = if self.radio_saver() { self.radio_window_ms() } else { 5_000 };
                let sid = sid.filter(|sid| {
                    self.server_rt.get_mut(sid).map_or(false, |rt| {
                        let gap = if rt.last_fetch_empty { min_gap } else { 5_000 };
                        let ok = now.saturating_sub(rt.notified_at) >= gap;
                        if ok { rt.notified_at = now; }
                        ok
                    })
                });
                if let Some(sid) = sid {
                    if let Some(rt) = self.server_rt.get_mut(&sid) {
                        rt.fetch_due_at = 0;
                    }
                    self.server_sweep_at = 0;
                    // The radio is up for this push anyway: open the saver window now, so the `Fetch` rides it
                    // (`RADIO_WINDOW_MS`).
                    self.radio_window_at = 0;
                }
                ServerResponse::Ok
            }
            // A "server" trying to deposit mail or open mailboxes on us is using the protocol wrongly.
            _ => ServerResponse::Err(ServerErrorCode::BadDirection),
        }
    }

    /// A new enrollment (a reset server numbers its mail from 1 again): old cursors would skip every new item for good.
    pub(super) fn forget_server_cursors(&mut self, server_id: &str) {
        self.server_cursors.retain(|(sid, _), _| sid != server_id);
        if let Some(rt) = self.server_rt.get_mut(server_id) {
            rt.unacked.clear();
            rt.refused.clear();
            rt.registered.clear();
            rt.held.clear();
            rt.passed.clear();
            rt.hold_strikes.clear();
        }
        // Its mail is gone with the old enrollment: deposit again.
        self.server_deposited.retain(|(sid, _), _| sid != server_id);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM server_cursors WHERE server_id = ?1", params![server_id]);
        }
    }

    pub(super) fn handle_server_response(
        &mut self,
        inflight: ServerInflight,
        response: ServerResponse,
        incoming: &mut Vec<(Option<PeerId>, Vec<u8>)>,
    ) {
        match (inflight, response) {
            // --- Hello ---
            (ServerInflight::Hello { server_id }, ServerResponse::Welcome { version, challenge, enrolled, enrollment_id, limits, server_name }) => {
                let Some(mut rec) = self.servers.iter().find(|s| s.server_id == server_id).cloned() else { return };
                if version != SERVER_PROTOCOL_VERSION {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        // Says which side is behind.
                        rt.last_error = Some(if version < SERVER_PROTOCOL_VERSION {
                            format!("Server protocol {version}, this app speaks {SERVER_PROTOCOL_VERSION}: update the server")
                        } else {
                            format!("Server protocol {version}, this app speaks {SERVER_PROTOCOL_VERSION}: update this app")
                        });
                    }
                    return;
                }
                // The server's id for our enrollment, taken only when we have none, or still hold an invite token (the
                // `Enrolled` answer of that enrollment was lost). A different id is not adopted: it would wipe every cursor
                // on each Hello and let the server choose the id our proofs are made over. A reset server does not know
                // us and answers `enrolled: false`.
                let adopted = match enrollment_id {
                    Some(id) if enrolled && rec.enrollment_id.as_ref() != Some(&id)
                        && (rec.enrollment_id.is_none() || !rec.token.is_empty()) => {
                        rec.enrollment_id = Some(id);
                        true
                    }
                    _ => false,
                };
                if adopted {
                    self.forget_server_cursors(&server_id);
                }
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.limits = Some(limits);
                    rt.enrolled = enrolled;
                    // Enrolled with no id here: the `Enrolled` answer was lost. Mailbox proofs need the id, so only a
                    // fresh invite helps.
                    rt.last_error = (enrolled && rec.enrollment_id.is_none())
                        .then(|| "Enrollment id lost. Add the server again with a new invite code".to_string());
                    // `hello_attempts` is not reset here: a server that says "enrolled" and then `NotEnrolled` to every
                    // request would loop Hello at round-trip speed. A request that works resets it (`Batch`, `ArchivePut`).
                }
                // Shown in the UI and stored: no control characters, bounded length.
                let server_name: String = server_name.chars().filter(|c| !c.is_control()).take(64).collect();
                let spent_token = enrolled && rec.enrollment_id.is_some() && !rec.token.is_empty();
                if (rec.name.is_empty() && !server_name.is_empty()) || spent_token || adopted {
                    if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                        r.enrollment_id = rec.enrollment_id.clone();
                        if r.name.is_empty() {
                            r.name = server_name;
                        }
                        // Not needed while the server knows us. Stored, it only waits to leak.
                        if spent_token {
                            r.token.clear();
                        }
                        let r = r.clone();
                        self.persist_server(&r);
                    }
                }
                if enrolled {
                    // The server already knows us. Trigger the scan now to refresh the subscriptions.
                    self.server_sweep_at = 0;
                    return;
                }
                self.begin_enrollment(&server_id, &challenge);
            }

            // --- Enroll / Rebind ---
            (ServerInflight::Enroll { server_id }, ServerResponse::Enrolled { enrollment_id, limits })
            | (ServerInflight::Rebind { server_id }, ServerResponse::Enrolled { enrollment_id, limits }) => {
                let mut new_enrollment = false;
                if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                    new_enrollment = r.enrollment_id.as_ref() != Some(&enrollment_id);
                    r.enrollment_id = Some(enrollment_id);
                    // The token is single use. Keeping it does no good, and leaking it does harm.
                    r.token.clear();
                    let r = r.clone();
                    self.persist_server(&r);
                }
                // A new enrollment (a reset server numbers its mail from 1 again): old cursors would skip every new
                // item for good.
                if new_enrollment {
                    self.forget_server_cursors(&server_id);
                }
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = true;
                    rt.hello_attempts = 0;
                    rt.limits = Some(limits);
                    rt.registered.clear();
                    rt.last_error = None;
                }
                info!("Registered with server: {}", crate::log_id(&server_id));
                self.server_sweep_at = 0;
                // Partial downloads can continue from the server's copy.
                self.resume_incomplete_downloads_for(&std::collections::HashSet::new(), true);
            }

            // --- Register ---
            (ServerInflight::Register { server_id, ids, dropped }, ServerResponse::Ok) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.proof_rounds = 0;
                    for id in ids {
                        rt.registered.insert(id);
                    }
                    // Dropped IDs were not removed before. The difference was sent as "-1" on every turn (the device
                    // showed "+0 -1" forever).
                    for id in dropped {
                        rt.registered.remove(&id);
                    }
                }
            }

            // The IDs of `ids` that the server did not name are registered. The `proof_needed` ones are sent again with
            // their proofs. The `refused` ones (cap, reader cap, a taken key) wait `SERVER_REFUSED_RETRY_MS`.
            (ServerInflight::Register { server_id, ids, dropped }, ServerResponse::Registered { proof_needed, refused }) => {
                let prove: Vec<String> = proof_needed.into_iter().filter(|id| ids.contains(id)).collect();
                let peer_id = self.server_rt.get(&server_id).and_then(|r| r.peer_id);
                let mut too_many_rounds = false;
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    // Enough rounds for every id we register (64 proofs each), plus slack. Past that the server keeps
                    // asking for proofs it was given: stop, and let the Register backoff decide the next try.
                    if prove.is_empty() {
                        rt.proof_rounds = 0;
                    } else {
                        rt.proof_rounds += 1;
                        let limit = (Self::mailbox_cap(rt) / server_proto::MAX_REGISTER_PROOFS) as u32 + 2;
                        if rt.proof_rounds > limit {
                            warn!("Server keeps asking for mailbox proofs, paused ({})", crate::log_id(&server_id));
                            rt.proof_rounds = 0;
                            rt.register_backoff_until = mono_ms() + SERVER_DEPOSIT_BACKOFF_MS;
                            too_many_rounds = true;
                        }
                    }
                    let refused: Vec<String> = refused.into_iter().filter(|id| ids.contains(id)).collect();
                    for id in ids.into_iter().filter(|id| !prove.contains(id) && !refused.contains(id)) {
                        rt.registered.insert(id);
                    }
                    for id in dropped {
                        rt.registered.remove(&id);
                    }
                    if !refused.is_empty() {
                        warn!("Server refused {} mailboxes ({})", refused.len(), crate::log_id(&server_id));
                        rt.last_error = Some(format!("{TOO_MANY_MAILBOXES}: the server refused some, those chats use the direct path only"));
                        rt.refused.extend(refused);
                        rt.refused_retry_at = mono_ms() + SERVER_REFUSED_RETRY_MS;
                    }
                }
                if let Some(peer_id) = peer_id.filter(|_| !prove.is_empty() && !too_many_rounds) {
                    let now: Vec<String> = prove.iter().take(server_proto::MAX_REGISTER_PROOFS).cloned().collect();
                    self.send_register(&server_id, peer_id, now.clone(), Vec::new(), &now);
                }
            }

            // The server answers `Ack`, `ArchivePurge` and `BlobDelete` with a plain `Ok`. If we did not match these
            // explicitly, every confirmation would log an "unexpected reply" warning.
            // The server dropped these items, so the cursor goes to disk now. A crash before this fetches them again
            // (deduplicated). It never skips.
            (ServerInflight::Ack { server_id, acks }, ServerResponse::Ok) => {
                if self.servers.iter().any(|s| s.server_id == server_id) {
                    for (mailbox, seq) in acks {
                        self.persist_cursor(&server_id, &mailbox, seq);
                    }
                }
            }

            // --- Deposit ---
            (ServerInflight::Deposit { mailbox, server_id, envelope, cancelled, .. }, ServerResponse::Deposited { seq }) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.deposit_failures = 0;
                }
                self.server_unknown_streak.remove(&(server_id.clone(), mailbox.clone()));
                info!("Server stored envelope: mailbox={} seq={}", mailbox_log_id(&mailbox), seq);
                if cancelled {
                    if let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) {
                        let req = ServerRequest::Cancel { mailbox, seqs: vec![seq] };
                        if let Some(id) = self.send_server_request(peer_id, req) {
                            self.server_inflight.insert(id, ServerInflight::Cancel { server_id });
                        }
                    }
                    return;
                }
                // The "already deposited" mark was set at send time (`try_server_deposit`).
                if let NetworkEnvelope::Message(m) = &envelope {
                    // See `server_deposit_locations`. We store where the packet sits in the mailbox, so it can be withdrawn.
                    self.server_deposit_locations.insert(
                        (server_id.clone(), format!("{}|{}", mailbox, m.header.message_id)),
                        (mailbox.clone(), seq),
                    );
                }
            }

            (ServerInflight::Cancel { .. }, ServerResponse::Ok) => {}

            // --- Fetch ---
            (ServerInflight::Fetch { server_id }, ServerResponse::Batch { items, more }) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.fetch_inflight = false;
                    rt.hello_attempts = 0;
                    rt.last_fetch_empty = items.is_empty();
                }
                let index: HashMap<String, MailboxKey> =
                    self.own_server_mailboxes().into_iter().map(|(id, (_, key))| (id, key)).collect();
                let mut highest: HashMap<String, u64> = HashMap::new();
                let mut count = 0usize;
                let mut bytes = 0usize;
                // The cursor of a mailbox stops before its first item that does not open (`hold_server_item`). Its later
                // items come with the next fetch. `seen`: mailboxes this batch reached. `blocked`: held in this batch.
                let mut seen: HashSet<String> = HashSet::new();
                let mut blocked: HashSet<String> = HashSet::new();
                let mut held_any = false;
                // Mailboxes with an item that opened in this batch (see `ServerRuntime.refetch_now`).
                let mut opened_in: HashSet<String> = HashSet::new();
                let now = mono_ms();

                for item in items {
                    let Some(key) = index.get(&item.mailbox_id) else {
                        // Not one of our mailboxes: no cursor, no ack.
                        continue;
                    };
                    // The server numbers mail with a SQLite rowid. A larger seq is bogus and would park the cursor at the top.
                    if item.seq > i64::MAX as u64 || blocked.contains(&item.mailbox_id) {
                        continue;
                    }
                    // At or below the cursor: already taken. A server that sends it again gets no second open and no second processing.
                    if item.seq <= self.server_cursors.get(&(server_id.clone(), item.mailbox_id.clone())).copied().unwrap_or(0) {
                        continue;
                    }
                    let first = seen.insert(item.mailbox_id.clone());
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        if rt.passed.contains(&(item.mailbox_id.clone(), item.seq)) {
                            // Passed over for good: the cursor moves past it, as it does past an item that opened. Otherwise
                            // 64 such items (or one over the batch byte cap) would stop the mailbox and every mailbox after it.
                            let h = highest.entry(item.mailbox_id.clone()).or_insert(0);
                            *h = (*h).max(item.seq);
                            continue;
                        }
                        // A `Fetch` answers from the cursor upward. A held item that is no longer the first of its mailbox is gone.
                        if let Some(&(held, _)) = rt.held.get(&item.mailbox_id) {
                            if first && item.seq > held {
                                rt.held.remove(&item.mailbox_id);
                            }
                        }
                    }
                    // Nothing unsealed is taken from the server. A session mailbox opens with its root key. A first-contact
                    // mailbox opens with its pairing secret and this device's KEM keys.
                    let opened = match key {
                        MailboxKey::Session(root_keys, peer_fp) => root_keys
                            .iter()
                            .find_map(|k| server_seal::open_envelope(k, &item.mailbox_id, peer_fp, &item.sealed).ok()),
                        MailboxKey::FirstContact(secret) => self.own_mailbox_topic_fp.as_ref()
                            .and_then(|fp| self.own_device_keys.get(fp))
                            .and_then(|k| server_seal::open_first_contact(secret, &item.mailbox_id, &k.kem_sk_x25519, &k.kem_sk_mlkem, &item.sealed).ok()),
                    };
                    let Some(raw) = opened else {
                        warn!("Could not open envelope from server (mailbox={})", mailbox_log_id(&item.mailbox_id));
                        // A first-contact item is sealed to a fixed secret and our fixed KEM keys: one that does not open now
                        // never will. Passed over at once, or junk deposits stalled the mailbox 5 minutes each.
                        let fixed_key = matches!(key, MailboxKey::FirstContact(_))
                            && self.own_mailbox_topic_fp.as_ref().map_or(false, |fp| self.own_device_keys.contains_key(fp));
                        if fixed_key {
                            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                                if rt.held.get(&item.mailbox_id).map_or(false, |&(s, _)| s == item.seq) {
                                    rt.held.remove(&item.mailbox_id);
                                }
                                rt.passed.insert((item.mailbox_id.clone(), item.seq));
                            }
                            let h = highest.entry(item.mailbox_id.clone()).or_insert(0);
                            *h = (*h).max(item.seq);
                            continue;
                        }
                        // Not acked, and the cursor stays before it. An Ack is cumulative and the server deletes what it covers.
                        // Passed over only after `SERVER_HOLD_GRACE_MS`.
                        if self.hold_server_item(&server_id, &item.mailbox_id, item.seq, now) {
                            blocked.insert(item.mailbox_id.clone());
                            held_any = true;
                        } else {
                            let h = highest.entry(item.mailbox_id.clone()).or_insert(0);
                            *h = (*h).max(item.seq);
                        }
                        continue;
                    };
                    count += 1;
                    bytes += raw.len();
                    opened_in.insert(item.mailbox_id.clone());
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.taken.insert(Sha256::digest(&raw).into(), (item.mailbox_id.clone(), item.seq));
                    }
                    // CRITICAL: `None`.
                    //
                    // If the server's `PeerId` were given, `record_peer_id_if_known` would point every contact's
                    // `device_to_peer_id` and `device_last_addr` at the SERVER. `is_peer_connected` would then lie,
                    // `reconnect_sweep` would dial the server forever, and file chunks would be requested from the wrong peer.
                    incoming.push((None, raw));
                    let h = highest.entry(item.mailbox_id.clone()).or_insert(0);
                    *h = (*h).max(item.seq);
                }

                if count > 0 {
                    info!("Fetched {} envelopes from server ({} bytes)", count, bytes);
                }
                // The cursor moves in memory now (no second processing). It goes to disk and to the server (`Ack`) only
                // once `incoming` was processed: `commit_server_fetches`, then the Ack's `Ok`. Forward only: a `Push` of an
                // old seq once moved the cursor back, and everything after it was delivered again.
                let mut advanced = false;
                for (mailbox, seq) in highest {
                    let key = (server_id.clone(), mailbox.clone());
                    if seq > self.server_cursors.get(&key).copied().unwrap_or(0) {
                        self.server_cursors.insert(key, seq);
                        advanced = true;
                        if let Some(rt) = self.server_rt.get_mut(&server_id) {
                            let e = rt.unacked.entry(mailbox).or_insert(0);
                            *e = (*e).max(seq);
                        }
                    }
                }
                // `more` with no progress would be the same `Fetch` again, immediately and for as long as the server says so.
                if more && advanced {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.fetch_due_at = 0;
                    }
                    self.server_sweep_at = 0;
                } else if held_any && count > 0 {
                    // What opened may bring the key of what did not.
                    self.refetch_held(&server_id, now);
                    if blocked.iter().any(|mb| opened_in.contains(mb)) {
                        if let Some(rt) = self.server_rt.get_mut(&server_id) {
                            rt.refetch_now = true;
                        }
                    }
                }
            }

            // --- Archive ---
            (ServerInflight::ArchivePut { server_id, records }, ServerResponse::Ok) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.archive_failures = 0;
                    rt.archive_backoff_until = 0;
                    rt.hello_attempts = 0;
                }
                self.drop_archive_records(&records);
                // The next batch now, as for mail and chunks (see `server_sweep`). One batch per radio window took the
                // re-upload after a revoke most of an hour.
                if !self.server_archive_queue.is_empty() {
                    self.server_sweep_at = 0;
                }
            }
            (ServerInflight::ArchivePurge { server_id, keys, rest }, ServerResponse::Ok) => {
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else { return };
                self.send_archive_purge(peer_id, server_id, keys, rest);
            }
            (ServerInflight::ArchiveProbe { server_id, conv_key, group, window, next }, ServerResponse::ArchiveProbed { mut present }) => {
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else {
                    if let Some((before, _)) = window { self.reopen_fetch_cursor(&conv_key, before) }
                    return;
                };
                // Only buckets this probe asked for, each once. A server listing any number of them would turn each into a fetch over Tor.
                let asked: HashSet<String> = match self.archive_root_key {
                    Some(ark) => archive_buckets(&ark, &conv_key, window.map_or_else(current_time_ms, |(before, _)| before)).into_iter().collect(),
                    None => HashSet::new(),
                };
                let mut seen_bucket: HashSet<String> = HashSet::new();
                present.retain(|b| asked.contains(&b.bucket) && seen_bucket.insert(b.bucket.clone()));
                // A press: the buckets that reach its window, newest first, each read from `before` backwards.
                if let Some((_, after)) = window {
                    present.retain(|b| b.newest_ms >= archive_wire_ms(after));
                    present.sort_by(|a, b| b.newest_ms.cmp(&a.newest_ms));
                }
                let mut wanted: Vec<String> = present.into_iter().map(|b| b.bucket).collect();
                // One bucket in flight per conversation. The `ArchiveBatch` arm asks for the next. All at once meant hundreds
                // of 512 KiB replies over one Tor circuit, and the timeouts were silent.
                if wanted.is_empty() {
                    self.probe_next_conversation(peer_id, server_id, next);
                } else {
                    let bucket = wanted.remove(0);
                    self.send_archive_fetch(peer_id, server_id, conv_key, group, bucket, window.map(|(before, _)| (before, String::new())), wanted, window, next, 0);
                }
            }
            (
                ServerInflight::ArchiveFetch { server_id, conv_key, group, bucket_more, mut rest, window, next, cursor, pages },
                ServerResponse::ArchiveBatch { records, more },
            ) => {
                // The page moves older again. Continue from the last record's timestamp for the next page. Without this,
                // only the first page of a bucket was fetched, and older messages stayed unreachable on the server.
                // Cursor = the page's last record (server order: time, then id, descending).
                let oldest = records.last().map(|r| (r.sent_at_ms, r.record_id.clone()));
                self.merge_server_archive(&conv_key, group, bucket_more.as_deref().unwrap_or(""), records, window);
                // A press: this page went past the window's start, so this bucket and the older ones hold nothing more of it.
                if let (Some((_, after)), Some((oldest_ms, _))) = (window, &oldest) {
                    if *oldest_ms < archive_wire_ms(after) {
                        return;
                    }
                }
                // The server went mid-chain: the next press asks for this window again.
                let Some(peer_id) = self.server_rt.get(&server_id).and_then(|r| r.peer_id) else {
                    if let Some((before, _)) = window { self.reopen_fetch_cursor(&conv_key, before) }
                    return;
                };
                // A server repeating a page (or never ending a bucket) looped here at round-trip speed. Continue only when
                // the cursor moved strictly older (server order is time, then id, both descending), and only for a bounded
                // number of pages.
                let moved = match (&oldest, &cursor) {
                    (Some(o), Some(c)) => o < c,
                    (Some(_), None) => true,
                    (None, _) => false,
                };
                if more && !moved {
                    warn!("Server archive page did not advance, bucket dropped");
                }
                if let (true, true, Some(bucket), Some(before)) = (more && moved, pages + 1 < ARCHIVE_FETCH_MAX_PAGES, bucket_more, oldest) {
                    self.send_archive_fetch(peer_id, server_id, conv_key, group, bucket, Some(before), rest, window, next, pages + 1);
                } else if !rest.is_empty() && pages + 1 < ARCHIVE_FETCH_MAX_PAGES {
                    // The page count runs on over the conversation's buckets.
                    let bucket = rest.remove(0);
                    self.send_archive_fetch(peer_id, server_id, conv_key, group, bucket, None, rest, window, next, pages + 1);
                } else {
                    self.probe_next_conversation(peer_id, server_id, next);
                }
            }

            // --- Blobs ---
            (ServerInflight::BlobPut { blob_id, chunk_index, total_chunks, server_id, sent_at }, ServerResponse::Ok) => {
                // The round trip is measured. It tells whether a transfer is limited by latency or by bandwidth. If latency limits it, a larger window gives speed directly.
                // If bandwidth limits it, a larger window gives nothing, and the fix lies elsewhere (see the single Tor circuit ceiling).
                let rtt = mono_ms().saturating_sub(sent_at);
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.blob_failures = 0;
                }
                self.blob_rtt_sum += rtt;
                self.blob_rtt_count += 1;
                // Grow the window ONLY while queue delay is low. On a fast path it opens up. On a narrow path such as Tor it
                // stops by itself. A fixed depth would be wrong in one of the two cases.
                if let Some(u) = self.server_blob_uploads.iter_mut().find(|u| u.file_id == blob_id) {
                    u.rtt_min = u.rtt_min.min(rtt.max(BLOB_RTT_FLOOR_MS));
                    let queue_ok = rtt <= u.rtt_min.saturating_mul(BLOB_RTT_GROW_FACTOR);
                    if queue_ok && rtt < BLOB_RTT_CEILING_MS && u.window < BLOB_WINDOW_MAX {
                        u.window += 1;
                    }
                }
                if self.blob_rtt_count % 10 == 0 {
                    let (w, inflight) = self
                        .server_blob_uploads
                        .first()
                        .map(|u| (u.window, u.inflight.len()))
                        .unwrap_or((0, 0));
                    info!(
                        "Blob transfer: {} chunks, average round trip {} ms, window {}, in flight {}",
                        self.blob_rtt_count,
                        self.blob_rtt_sum / self.blob_rtt_count,
                        w, inflight
                    );
                }
                self.advance_blob_upload(&blob_id, chunk_index, total_chunks, &server_id);
            }
            (ServerInflight::BlobFinish { server_id, blob_id }, ServerResponse::Ok) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.blob_failures = 0;
                }
                self.forget_blob_upload(&blob_id);
            }
            (ServerInflight::BlobFinish { server_id, blob_id }, ServerResponse::Err(ServerErrorCode::BlobIncomplete)) => {
                self.restart_blob_upload(&blob_id, &server_id);
            }
            // A refused finish never succeeds with the same bytes. Drop the upload (the direct peer path still serves the
            // file) so it does not block the queue behind it.
            (ServerInflight::BlobFinish { blob_id, .. }, ServerResponse::Err(code))
                if !matches!(code, ServerErrorCode::NotEnrolled | ServerErrorCode::RateLimited | ServerErrorCode::Internal) =>
            {
                warn!("Server did not accept blob ({:?}), upload dropped: {}", code, blob_id);
                self.finish_blob_upload(&blob_id);
            }

            // --- Errors ---
            (inflight, ServerResponse::Err(code)) => self.handle_server_error(inflight, code),

            // An unexpected match means a protocol mismatch. It is treated as no answer, so the request's own clean-up runs
            // (a `Fetch` would otherwise leave `fetch_inflight` set for good, and an `Ack` would lose its positions).
            (inflight, other) => {
                warn!("Unexpected response from server: {:?} -> {:?}", std::mem::discriminant(&inflight), std::mem::discriminant(&other));
                self.handle_server_failure(inflight);
            }
        }
    }

    pub(super) fn handle_server_error(&mut self, inflight: ServerInflight, code: ServerErrorCode) {
        let server_id = inflight.server_id().to_string();

        // Delivery guarantee fix: `fetch_inflight` was reset only on a successful `Batch`, in `handle_server_failure`, and
        // in the `other` arm below, not in the `NotEnrolled`, `Revoked` and `UnknownMailbox` arms. A `Fetch` answered with
        // `NotEnrolled` (quite likely if the client's PeerId changed, or another device rebound) left the flag `true` for
        // good. `server_fetch` then returned early every turn, and even after a successful re-registration, no mail was
        // fetched from the server until the app restarted. So an in-flight `Fetch` is reset here, whatever the arm.
        if matches!(inflight, ServerInflight::Fetch { .. }) {
            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                rt.fetch_inflight = false;
            }
        }

        // A refused `Deposit` is NOT on the server, so take back the optimistic "already deposited" mark. Otherwise every
        // retry over the next 12 h would count it as stored. Each arm below blocks this server for the envelope (mailbox
        // TTL, not enrolled, deposit backoff), so this cannot spin.
        if let ServerInflight::Deposit { dedup_key, .. } = &inflight {
            self.server_deposited.remove(&(server_id.clone(), dedup_key.clone()));
        }
        // A spent or expired token never works again. With it gone, the next round falls back to `Rebind`, or stops (see `server_sweep`).
        if matches!((&inflight, &code), (ServerInflight::Enroll { .. }, ServerErrorCode::BadInvite)) {
            if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                r.token.clear();
                let r = r.clone();
                self.persist_server(&r);
            }
        }
        // `Internal` is the server's own trouble (SQLite busy, disk). Dropping on it lost one queued archive record per sweep
        // while it lasted. A chunk over the blob quota gets the same answer every time. Kept, it was sent again every 5 minutes
        // forever, ahead of every later upload, and it blocked message deposits to the server each time.
        let permanent = !matches!(
            code,
            ServerErrorCode::NotEnrolled | ServerErrorCode::Revoked | ServerErrorCode::QuotaExceeded | ServerErrorCode::RateLimited | ServerErrorCode::Internal
        ) || matches!((&inflight, &code), (ServerInflight::BlobPut { .. }, ServerErrorCode::QuotaExceeded));
        if let ServerInflight::Register { .. } = &inflight {
            // Refused (too many mailboxes, a taken ID): not again on each sweep.
            if let Some(rt) = self.server_rt.get_mut(&server_id) {
                rt.register_backoff_until = mono_ms() + SERVER_DEPOSIT_BACKOFF_MS;
            }
        }
        match &inflight {
            // The same chunk gets the same answer. Give the upload up; the direct peer path still serves the file.
            ServerInflight::BlobPut { blob_id, .. } if permanent => {
                warn!("Server did not accept chunk ({:?}), upload dropped: {}", code, blob_id);
                self.finish_blob_upload(blob_id);
            }
            // Drop the head record, or it blocks every record behind it.
            ServerInflight::ArchivePut { records, .. } if permanent => {
                warn!("Server did not accept archive batch ({:?}), first record dropped", code);
                self.drop_archive_records(&records[..records.len().min(1)]);
            }
            // The server keeps the IDs it took and names none. The refused ones (over its cap, a full mailbox) would be
            // sent again each backoff, with the whole list, forever. They are taken as done until the next reconnect
            // recomputes the set.
            ServerInflight::Register { ids, dropped, .. } if matches!(code, ServerErrorCode::QuotaExceeded) => {
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.registered.extend(ids.iter().cloned());
                    for id in dropped {
                        rt.registered.remove(id);
                    }
                    rt.last_error = Some(format!("{TOO_MANY_MAILBOXES}: the server refused some, those chats use the direct path only"));
                }
            }
            // Positions the server did not take: again later, unless it will never take them.
            ServerInflight::Ack { acks, .. } => {
                if permanent {
                    warn!("Server refused Ack ({:?}), {} mailboxes", code, acks.len());
                } else {
                    self.restage_acks(&server_id, acks.clone());
                }
            }
            _ => {}
        }

        // As in `handle_server_failure`: the caller of a restore already got "OK", and the rest of this conversation's
        // buckets is not requested.
        if let ServerInflight::ArchiveFetch { .. } | ServerInflight::ArchiveProbe { .. } = &inflight {
            warn!("Server rejected history request ({:?}), restore incomplete", code);
            self.reopen_fetch_window(&inflight);
            self.attachment_events.push(serde_json::json!({"type": "history_restore_incomplete"}).to_string());
        }

        match code {
            ServerErrorCode::UnknownMailbox => {
                warn!("Server does not know mailbox (recipient not on this server)");
                if let ServerInflight::Deposit { mailbox, .. } = &inflight {
                    // Deposits in flight together all get this answer, so back off one step per pause.
                    let key = (server_id.clone(), mailbox.clone());
                    let now = mono_ms();
                    if self.server_unknown_mailboxes.get(&key).map_or(true, |until| now >= *until) {
                        let streak = self.server_unknown_streak.entry(key.clone()).or_insert(0);
                        let ttl = (SERVER_UNKNOWN_MAILBOX_TTL_MS << (*streak).min(6)).min(SERVER_UNKNOWN_MAILBOX_MAX_TTL_MS);
                        *streak += 1;
                        self.server_unknown_mailboxes.insert(key, now + ttl);
                    }
                }
                // The recipient is not on this server: fall back to the direct path IMMEDIATELY.
                //
                // Delivery fix: this arm used to call `try_publish_raw`, the UNQUEUED raw version, and ignored its result with
                // `let _ =`. If the publish failed at that moment (direct path not ready, peer briefly unreachable) the envelope
                // was written nowhere. `Message` types survived through `awaiting_confirmation`, but `Handshake` and
                // `IdentityExchange`, the carriers of pairing and first contact, were dropped silently. Every other error arm
                // already used `requeue_failed_deposit` (`publish_envelope` into `pending_envelopes`). This was the one exception.
                self.requeue_failed_deposit(&inflight);
            }
            ServerErrorCode::NotEnrolled => {
                // A new Hello right away only when this was not the enrollment itself. Otherwise Hello, Welcome, Rebind and
                // NotEnrolled ran at round-trip speed, two signatures per round, past the backoff.
                let enrolling = matches!(inflight, ServerInflight::Hello { .. } | ServerInflight::Enroll { .. } | ServerInflight::Rebind { .. });
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = false;
                    // `hello_sent_at` is kept: the sweep sends a Hello once the Hello backoff since the last one has run
                    // (at once when that was long ago). Zeroing it let a server answering "enrolled", then `NotEnrolled`,
                    // loop Hello at round-trip speed.
                }
                if !enrolling {
                    self.server_sweep_at = 0;
                }
                // The server does not know this enrollment (any more). The ID is useless, as in the Revoked arm.
                if matches!(inflight, ServerInflight::Rebind { .. }) {
                    if let Some(rt) = self.server_rt.get_mut(&server_id) {
                        rt.last_error = Some("The server does not know this enrollment. Add it again with a new invite code".to_string());
                    }
                    if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                        r.enrollment_id = None;
                        let r = r.clone();
                        self.persist_server(&r);
                    }
                }
                self.requeue_failed_deposit(&inflight);
            }
            ServerErrorCode::Revoked => {
                warn!("Server revoked our registration: {}", crate::log_id(&server_id));
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    rt.enrolled = false;
                    rt.last_error = Some("The operator revoked this enrollment".to_string());
                }
                // A revoked identity is not worth keeping: if we keep it, the next round tries `Rebind` and gets the same
                // error. If we clear it, the user can enroll cleanly by pasting a new invite code (see `add_server`). If no
                // token is left, nothing is attempted automatically. The error message stays, and the user decides.
                if let Some(r) = self.servers.iter_mut().find(|s| s.server_id == server_id) {
                    if r.enrollment_id.is_some() {
                        r.enrollment_id = None;
                        let r = r.clone();
                        self.persist_server(&r);
                    }
                }
                self.requeue_failed_deposit(&inflight);
            }
            // A full mailbox (5000 undelivered items for a device that has not fetched in a week) must stop deposits to THAT mailbox only. The
            // server-wide backoff below would lock the whole account out of the server, call invites included, for as long as the dead mailbox stayed full.
            // ponytail: QuotaExceeded also covers the per-account and disk caps. For those, this retries each mailbox once per backoff instead of once
            // per server, which is bounded by the mailbox count.
            ServerErrorCode::QuotaExceeded if matches!(inflight, ServerInflight::Deposit { .. }) => {
                if let ServerInflight::Deposit { mailbox, .. } = &inflight {
                    // The pause doubles per refusal, like `UnknownMailbox`. A `Deposited` resets the streak.
                    let key = (server_id.clone(), mailbox.clone());
                    let now = mono_ms();
                    if self.server_unknown_mailboxes.get(&key).map_or(true, |until| now >= *until) {
                        let streak = self.server_unknown_streak.entry(key.clone()).or_insert(0);
                        let ttl = (SERVER_DEPOSIT_BACKOFF_MS << (*streak).min(6)).min(SERVER_UNKNOWN_MAILBOX_MAX_TTL_MS);
                        *streak += 1;
                        warn!("Server mailbox full, deposits to this mailbox paused for {} s: {}", ttl / 1000, mailbox_log_id(mailbox));
                        self.server_unknown_mailboxes.insert(key, now + ttl);
                    }
                }
                self.requeue_failed_deposit(&inflight);
            }
            other => {
                warn!("Server error: {:?}", other);
                // Any refused `Deposit` backs off too: its mark is gone (see above), so without this the retry would deposit
                // again at once. Deposits (and the blob chunks behind the same gate) only. A refused `Register` or archive
                // request must not stop all message deposits to the server for 5 minutes, again and again.
                let blob = matches!(inflight, ServerInflight::BlobPut { .. } | ServerInflight::BlobFinish { .. });
                let backs_off = matches!(inflight, ServerInflight::Deposit { .. })
                    || (matches!(other, ServerErrorCode::RateLimited) && blob);
                let mut drop_blob = false;
                let register_quota = matches!((&inflight, &other), (ServerInflight::Register { .. }, ServerErrorCode::QuotaExceeded));
                if let Some(rt) = self.server_rt.get_mut(&server_id) {
                    // The `Register` arm above has a clearer message.
                    if !register_quota {
                        rt.last_error = Some(format!("{:?}", other));
                    }
                    // See `SERVER_DEPOSIT_BACKOFF_MS`. "Quota or rate error" means "try again a little later", not "try every
                    // second". The backoff stops only deposits. `Fetch` and `Ack` keep running, and draining the mailbox is
                    // exactly what frees the quota.
                    if backs_off {
                        Self::back_off_deposits(rt);
                    }
                    // A server error on a chunk or a finish: 15 s doubling to 30 min, one step per round (the chunks in
                    // flight together all get it). Without it the upload was resent every sweep for as long as the fault
                    // lasted, and kept the phone and Tor awake (`blob_upload_can_run`).
                    let now = mono_ms();
                    if blob && matches!(other, ServerErrorCode::Internal) && now >= rt.blob_backoff_until {
                        rt.blob_backoff_until = now + (SERVER_SWEEP_INTERVAL_MS << rt.blob_failures.min(7)).min(SERVER_DEPOSIT_BACKOFF_MAX_MS);
                        rt.blob_failures += 1;
                        if rt.blob_failures >= MAX_BLOB_INTERNAL_FAILURES {
                            rt.blob_failures = 0;
                            drop_blob = true;
                        }
                    }
                    // A full archive quota (or a rate or server error) gets the same answer for a while. Without this, the same
                    // head batch went out again on every sweep. It has its own backoff, so message deposits keep going. A
                    // permanent refusal already dropped the head record above, so the next try is new.
                    if matches!(inflight, ServerInflight::ArchivePut { .. }) && !permanent {
                        rt.archive_backoff_until = mono_ms()
                            + (SERVER_DEPOSIT_BACKOFF_MS << rt.archive_failures.min(3)).min(SERVER_DEPOSIT_BACKOFF_MAX_MS);
                        rt.archive_failures = rt.archive_failures.saturating_add(1);
                    }
                }
                if drop_blob {
                    if let ServerInflight::BlobPut { blob_id, .. } | ServerInflight::BlobFinish { blob_id, .. } = &inflight {
                        warn!("Server kept failing blob requests, upload dropped: {}", blob_id);
                        self.finish_blob_upload(blob_id);
                    }
                }
                // Quota, rate or size: the right behaviour is the same in all of them. Hand this envelope back to the publish queue. Do not lose the message.
                self.requeue_failed_deposit(&inflight);
            }
        }
    }

    pub(super) fn handle_server_failure(&mut self, inflight: ServerInflight) {
        if let ServerInflight::Hello { server_id } | ServerInflight::Fetch { server_id } = &inflight {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.hello_sent_at = 0;
                // If no answer came, leaving the flag set would lock fetching for good (see `fetch_inflight`).
                rt.fetch_inflight = false;
                // A lost `Fetch` is retried at the next sweep, not after the rest of the 5-minute safety interval.
                if matches!(inflight, ServerInflight::Fetch { .. }) {
                    rt.fetch_due_at = 0;
                }
            }
        }
        if let ServerInflight::Ack { server_id, acks } = &inflight {
            self.restage_acks(server_id, acks.clone());
        }
        // If the deposit failed, undo the "already deposited" mark. Otherwise the retry path would stay closed (see `server_deposited`).
        if let ServerInflight::Deposit { server_id, dedup_key, .. } = &inflight {
            // Now independent of the envelope type (see `deposit_dedup_key`). Before, only `Message` was reverted, and
            // only `Message` was ever marked.
            self.server_deposited.remove(&(server_id.clone(), dedup_key.clone()));
            // No answer: without a backoff, the retry below deposited again at once (the server still counts as ready), on every request timeout.
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                Self::back_off_deposits(rt);
            }
        }
        // The caller of a restore already got "OK": tell the UI the result is partial.
        if let ServerInflight::ArchiveFetch { .. } | ServerInflight::ArchiveProbe { .. } = &inflight {
            warn!("Server history request got no response, restore incomplete");
            self.reopen_fetch_window(&inflight);
            self.attachment_events.push(serde_json::json!({"type": "history_restore_incomplete"}).to_string());
        }
        self.requeue_failed_deposit(&inflight);
    }

    pub(super) fn begin_enrollment(&mut self, server_id: &str, challenge: &[u8]) {
        let Some(rec) = self.servers.iter().find(|s| s.server_id == server_id).cloned() else { return };
        let Some(peer_id) = self.server_rt.get(server_id).and_then(|r| r.peer_id) else { return };
        let Ok(sk_bytes): Result<[u8; 32], _> = rec.enroll_sk.as_slice().try_into() else {
            error!("Server enrollment key invalid (corrupt): {}", crate::log_id(&server_id));
            return;
        };
        let signing = SigningKey::from_bytes(&sk_bytes);
        let Ok(seed): Result<ml_dsa::Seed, _> = rec.enroll_sk_pq.as_slice().try_into() else {
            // A row may have been saved before server support was added (see the `enroll_sk_pq` migration). The user must add the
            // server with a new invite code. We do NOT silently fall back to the classical signature.
            error!("Server enrollment key has no PQ component: {}", crate::log_id(&server_id));
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error =
                    Some("Enrollment key is in the old format — add the server again with a new invite code".to_string());
            }
            return;
        };
        let signing_pq = MlDsaSigningKey::<MlDsa87>::from_seed(&seed);
        let ts_ms = current_time_ms();
        let Some(me) = self.swarm.as_ref().map(|s| s.local_peer_id().to_string()) else { return };

        // Already enrolled (the app was reinstalled, the libp2p identity changed): reconnect without spending an invite token.
        // A token wins over the stored ID: the user pasted it to enroll anew. If the server refuses it, it is cleared, and this
        // falls back to `Rebind`.
        if let Some(enrollment_id) = rec.enrollment_id.clone().filter(|_| rec.token.is_empty()) {
            let input = server_proto::rebind_signing_input(&enrollment_id, server_id, &me, challenge, ts_ms);
            let sig = signing.sign(&input).to_bytes().to_vec();
            let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
            let req = ServerRequest::Rebind {
                enrollment_id,
                ts_ms,
                sig,
                sig_pq: sig_pq.encode().to_vec(),
            };
            if let Some(id) = self.send_server_request(peer_id, req) {
                self.server_inflight.insert(id, ServerInflight::Rebind { server_id: server_id.to_string() });
            }
            return;
        }

        if rec.token.is_empty() {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error = Some("No invite token. Add the server again with a new code".to_string());
            }
            return;
        }
        let Ok(token_bytes) = hex::decode(&rec.token) else {
            if let Some(rt) = self.server_rt.get_mut(server_id) {
                rt.last_error = Some("The invite token is damaged".to_string());
            }
            return;
        };
        let enroll_pk = signing.verifying_key().to_bytes().to_vec();
        let enroll_pk_pq = signing_pq.verifying_key().encode().to_vec();
        let input = server_proto::enroll_signing_input(
            SERVER_PROTOCOL_VERSION,
            server_id,
            &me,
            &token_bytes,
            &enroll_pk,
            &enroll_pk_pq,
            challenge,
            ts_ms,
        );
        let sig = signing.sign(&input).to_bytes().to_vec();
        let sig_pq: MlDsaSignature<MlDsa87> = signing_pq.sign(&input);
        let req = ServerRequest::Enroll {
            version: SERVER_PROTOCOL_VERSION,
            invite_token: token_bytes,
            enroll_pk,
            enroll_pk_pq,
            ts_ms,
            sig,
            sig_pq: sig_pq.encode().to_vec(),
            challenge: challenge.to_vec(),
        };
        if let Some(id) = self.send_server_request(peer_id, req) {
            self.server_inflight.insert(id, ServerInflight::Enroll { server_id: server_id.to_string() });
        }
    }

    /// Called by `poll_events` when connecting to or disconnecting from a server.
    pub(crate) fn note_server_connection(&mut self, peer: PeerId, connected: bool) {
        let sid = self
            .server_rt
            .iter()
            .find(|(_, rt)| rt.peer_id == Some(peer))
            .map(|(sid, _)| sid.clone());
        let Some(sid) = sid else { return };
        if let Some(rt) = self.server_rt.get_mut(&sid) {
            rt.connected = connected;
            if connected {
                rt.dial_attempts = 0;
                rt.dial_backoff_until = 0;
                // Timeouts on a lost connection grew the deposit backoff.
                rt.deposit_failures = 0;
                rt.deposit_backoff_until = 0;
                // Subscriptions are still on the server after a reconnect, but our view may be stale. Reset it, so the difference is recomputed.
                rt.registered.clear();
                rt.fetch_due_at = 0;
                rt.hello_sent_at = 0;
            } else {
                rt.enrolled = false;
            }
        }
        self.server_sweep_at = 0;
    }

    /// Is this `PeerId` that of a configured server?
    pub(crate) fn is_server_peer(&self, peer: &PeerId) -> bool {
        self.server_rt.values().any(|rt| rt.peer_id.as_ref() == Some(peer))
    }

    /// The `PeerId` of EVERY configured server (registered or not). See the keepalive filter in `poll_events`.
    pub(crate) fn server_peer_ids(&self) -> Vec<PeerId> {
        self.server_rt.values().filter_map(|rt| rt.peer_id).collect()
    }

    /// The `PeerId`s of connected and registered servers. Added as an alternative source for file downloads.
    pub(crate) fn ready_server_peers(&self) -> Vec<PeerId> {
        self.servers
            .iter()
            .filter_map(|s| {
                let rt = self.server_rt.get(&s.server_id)?;
                if rt.connected && rt.enrolled {
                    rt.peer_id
                } else {
                    None
                }
            })
            .collect()
    }
}
