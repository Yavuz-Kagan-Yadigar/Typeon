//! Call signalling: invites, accept, end, sweep and the call state for the UI.

use super::*;

pub(super) fn noop() -> serde_json::Value {
    serde_json::json!({"type": "noop"})
}

pub(super) static LAST_CALL_SIG: Mutex<String> = Mutex::new(String::new());

/// `(device, call id, message id)` of the last Invite sent per device and call: a re-invite withdraws the
/// previous server copy, so a device that was offline finds one Invite, not one per re-invite.
static LAST_INVITES: Mutex<Vec<(String, String, String)>> = Mutex::new(Vec::new());

impl P2PCore {
    pub(crate) fn start_call(&mut self, peer_fp: String, video: bool) -> Result<String, String> {
        if self.call.is_some() {
            return Err("A call is already in progress".to_string());
        }
        // Ring every active device of the contact. The chat key is the lowest fingerprint, which may belong to an old, dead device, so ringing only that one can leave
        // the call unanswered. The first device to answer wins (see the Accept arm).
        let invited: Vec<String> = self.fanout_targets(&peer_fp).into_iter().filter(|fp| self.ratchets.contains_key(fp)).collect();
        if invited.is_empty() {
            return Err("No session with this contact".to_string());
        }
        let call_id = uuid::Uuid::new_v4().to_string();
        let s = CallSession::new(call_id.clone(), None, video, CallPhase::Outgoing, peer_fp, invited);
        media_start(&s.my_key, s.my_sid);
        self.call = Some(s);
        self.call_broadcast(CallAction::Invite);
        info!("Call started: {} video={}", &call_id[..8], video);
        Ok(call_id)
    }

    pub(crate) fn start_group_call(&mut self, group_id: String, video: bool) -> Result<String, String> {
        // A call already running in this group: join it, never start a second one.
        if let Some(s) = self.call.as_ref().filter(|s| s.phase == CallPhase::Incoming && s.group_id.as_deref() == Some(group_id.as_str())) {
            let id = s.call_id.clone();
            self.accept_call()?;
            return Ok(id);
        }
        if self.call.is_some() {
            return Err("A call is already in progress".to_string());
        }
        let offer = group_offers().remove(&group_id).filter(|o| o.at.elapsed() < Duration::from_millis(OFFER_TTL_MS));
        if let Some(o) = offer {
            let invited = self.group_invited(&group_id, &o.peer_fp, o.participants.clone());
            let mut s = CallSession::new(o.call_id.clone(), Some(group_id.clone()), o.video, CallPhase::Incoming, o.peer_fp.clone(), invited);
            s.keys.insert(o.peer_fp.clone(), (o.media_key.clone(), o.stream_id.clone()));
            s.joined.insert(o.peer_fp.clone());
            let id = o.call_id.clone();
            // Kept: after leaving, "Attend" shows again.
            group_offers().insert(group_id, o);
            self.call = Some(s);
            self.accept_call()?;
            info!("Joined group call {}", id.chars().take(8).collect::<String>());
            return Ok(id);
        }
        let invited = self.group_call_devices(&group_id)?;
        if invited.is_empty() {
            return Err("No members to call".to_string());
        }
        let call_id = uuid::Uuid::new_v4().to_string();
        let s = CallSession::new(call_id.clone(), Some(group_id), video, CallPhase::Outgoing, String::new(), invited);
        media_start(&s.my_key, s.my_sid);
        self.call = Some(s);
        self.call_broadcast(CallAction::Invite);
        // My other devices never get an Invite of it: no "Attend" there either.
        self.silence_siblings(CallAction::Joined);
        info!("Group call started: {} video={}", &call_id[..8], video);
        Ok(call_id)
    }

    pub(crate) fn accept_call(&mut self) -> Result<(), String> {
        let s = self.call.as_mut().ok_or("No call")?;
        if s.phase != CallPhase::Incoming {
            return Err("No call to answer".to_string());
        }
        s.phase = CallPhase::Active;
        s.connected_at = current_time_ms();
        s.connected = Some(Instant::now());
        media_start(&s.my_key, s.my_sid);
        for fp in &s.joined {
            if let Some((k, sid)) = s.keys.get(fp) {
                media_add_remote(fp, k, sid);
            }
        }
        // Register the relay addresses now (see `relay_listen_keys`).
        self.server_sweep_at = 0;
        self.call_broadcast(CallAction::Accept);
        // A group call: siblings also hide its "Attend"; a 1:1 call they only stop ringing.
        let joined = if self.call.as_ref().map_or(false, |s| s.group_id.is_some()) { CallAction::Joined } else { CallAction::Busy };
        self.silence_siblings(joined);
        Ok(())
    }

    /// Answered or rejected here: my other devices that ring for the same
    /// call stop (see the sibling check in the Reject/Busy/Hangup arm).
    fn silence_siblings(&mut self, action: CallAction) {
        let Some((cid, gid, video)) = self.call.as_ref().map(|s| (s.call_id.clone(), s.group_id.clone(), s.video)) else { return };
        for fp in self.sibling_active_devices() {
            self.send_call_signal(&fp, &cid, gid.clone(), video, action, None, Vec::new());
        }
    }

    /// Reject while ringing, hang up otherwise.
    pub(crate) fn end_call(&mut self) {
        self.end_call_with("local");
    }

    /// `end_call`, with the reason `call_state_json` reports afterwards.
    pub(super) fn end_call_with(&mut self, reason: &str) {
        match self.call.as_ref().map(|s| (s.phase, s.group_id.is_some())) {
            Some((CallPhase::Incoming, _)) => self.silence_siblings(CallAction::Busy),
            // Left a group call: my other devices show its "Attend" again.
            Some((CallPhase::Active | CallPhase::Outgoing, true)) => self.silence_siblings(CallAction::Hangup),
            _ => {}
        }
        let Some(s) = self.call.take() else { return };
        let (action, to) = if s.phase == CallPhase::Incoming {
            (CallAction::Reject, vec![s.peer_fp.clone()])
        } else {
            (CallAction::Hangup, s.invited.clone())
        };
        for fp in to {
            self.call_signal(&fp, &s, action);
        }
        media_stop();
        // Left a group call that goes on: "Attend" shows at once, from the
        // keys of someone still in it, not after the next re-invite reaches us.
        if let (Some(gid), "local", CallPhase::Active) = (&s.group_id, reason, s.phase) {
            if s.joined.is_empty() {
                self.group_call_ended(&s);
            } else if let Some((fp, (key, sid))) = s.keys.iter().find(|(fp, _)| s.joined.contains(*fp)) {
                group_offers().insert(gid.clone(), GroupOffer {
                    call_id: s.call_id.clone(), video: s.video, peer_fp: fp.clone(),
                    media_key: key.clone(), stream_id: sid.clone(),
                    participants: s.invited.clone(), at: Instant::now(),
                });
                self.attachment_events.push(serde_json::json!({"type": "group_call_offer", "group_id": gid}).to_string());
            }
        }
        // A group call keeps re-inviting every device not in it; `last_call_end`
        // holds only the latest call, so the next call's end would let it ring again.
        if s.group_id.is_some() {
            never_ring_again(&s.call_id);
        }
        self.last_call_end = Some((s.call_id, reason.to_string()));
    }

    /// The last participant of a group call is gone: every member device drops
    /// its "Attend" (`CallAction::Ended`), mine too.
    fn group_call_ended(&mut self, s: &CallSession) {
        let Some(gid) = s.group_id.clone() else { return };
        // Same devices the re-invite reaches (`call_sweep_inner`): every one that may hold an offer.
        let mut to = s.invited.clone();
        for fp in self.group_call_devices(&gid).unwrap_or_default() {
            if !to.contains(&fp) {
                to.push(fp);
            }
        }
        for fp in to {
            self.send_call_signal(&fp, &s.call_id, Some(gid.clone()), s.video, CallAction::Ended, None, Vec::new());
        }
        // Over for good: a late Accept of it gets a Hangup (see the Accept arm).
        remember_ended(&s.call_id, ENDED);
        if group_offers().remove(&gid).is_some() {
            self.attachment_events.push(serde_json::json!({"type": "group_call_offer", "group_id": gid}).to_string());
        }
    }

    /// What `groupCallOffer` reports for [group_id].
    pub(crate) fn group_call_offer(&self, group_id: &str) -> i32 {
        let offers = group_offers();
        let Some(o) = offers.get(group_id).filter(|o| o.at.elapsed() < Duration::from_millis(OFFER_TTL_MS)) else { return 0 };
        if self.call.as_ref().map_or(false, |s| s.call_id == o.call_id && s.phase != CallPhase::Incoming) {
            return 0;
        }
        if sibling_calls().contains(&o.call_id) {
            return 0;
        }
        if o.video { 2 } else { 1 }
    }

    /// Devices a group call we did not start signals to: every member's
    /// recently seen device, plus every device the caller rang that is an
    /// active device of a member here (stale or not), plus the caller; never mine.
    fn group_invited(&self, gid: &str, caller: &str, participants: Vec<String>) -> Vec<String> {
        let mut invited = self.group_call_devices(gid).unwrap_or_default();
        let own = self.get_active_own_device_fingerprint().unwrap_or_default();
        let me = self.my_identity_id().unwrap_or_default();
        let member_devices: HashSet<String> = self.groups.get(gid)
            .map(|g| g.other_members(&me).iter().flat_map(|id| self.active_devices_for_identity(id)).collect())
            .unwrap_or_default();
        for fp in participants.into_iter().take(MAX_INVITE_PARTICIPANTS) {
            if fp != own && member_devices.contains(&fp) && !invited.contains(&fp) {
                invited.push(fp);
            }
        }
        if !invited.iter().any(|f| f == caller) {
            invited.push(caller.to_string());
        }
        invited
    }

    pub(super) fn group_call_devices(&self, group_id: &str) -> Result<Vec<String>, String> {
        let me = self.my_identity_id().ok_or("No identity")?;
        let group = self.groups.get(group_id).cloned_group()?;
        // All devices of every member (see `start_call` for why not one).
        Ok(group
            .other_members(&me)
            .iter()
            .flat_map(|id| self.active_devices_for_identity(id))
            .filter(|fp| self.device_recently_seen(fp))
            .collect())
    }

    pub(super) fn call_broadcast(&mut self, action: CallAction) {
        let Some(s) = self.call.take() else { return };
        for fp in &s.invited {
            self.call_signal(fp, &s, action);
        }
        self.call = Some(s);
    }

    pub(super) fn call_signal(&mut self, fp: &str, s: &CallSession, action: CallAction) {
        let with_keys = matches!(action, CallAction::Invite | CallAction::Accept);
        let keys = with_keys.then(|| (pair_key(&s.my_key, fp).to_vec(), s.my_sid.to_vec()));
        // a group invite names everyone rung, so callees connect to each
        // other even when each thinks the other is stale.
        let participants = if action == CallAction::Invite && s.group_id.is_some() { s.invited.clone() } else { Vec::new() };
        self.send_call_signal(fp, &s.call_id, s.group_id.clone(), s.video, action, keys, participants);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn send_call_signal(&mut self, fp: &str, call_id: &str, group_id: Option<String>, video: bool, action: CallAction, keys: Option<(Vec<u8>, Vec<u8>)>, participants: Vec<String>) {
        let (media_key, stream_id) = keys.unwrap_or_default();
        let content = MessageContent::Call {
            call_id: call_id.to_string(),
            action,
            group_id,
            video,
            media_key,
            stream_id,
            sent_at_ms: current_time_ms(),
            participants,
        };
        self.call_signal_sending = true;
        let sent = self.send_message_content(fp.to_string(), &content, None);
        self.call_signal_sending = false;
        match sent {
            Err(e) => warn!("Call signal could not be sent ({:?} -> {}): {}", action, &fp[..8.min(fp.len())], e),
            Ok((message_id, _)) if action == CallAction::Invite => {
                let prev = LAST_INVITES.lock().ok().and_then(|mut last| {
                    let prev = last.iter().position(|(f, c, _)| f == fp && c == call_id).map(|i| last.remove(i).2);
                    // ponytail: 64 entries, the oldest dropped; enough for the devices of a few calls.
                    if last.len() >= 64 {
                        last.remove(0);
                    }
                    last.push((fp.to_string(), call_id.to_string(), message_id));
                    prev
                });
                if let Some(prev) = prev {
                    self.cancel_server_deposit(&prev);
                }
            }
            Ok(_) => {}
        }
    }

    /// `receive_message` arm for `MessageContent::Call`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_call_signal(
        &mut self,
        peer_fp: &str,
        sender_identity_id: &str,
        call_id: String,
        action: CallAction,
        group_id: Option<String>,
        video: bool,
        media_key: Vec<u8>,
        stream_id: Vec<u8>,
        sent_at_ms: u64,
        participants: Vec<String>,
    ) -> serde_json::Value {
        let now = current_time_ms();
        let keys_ok = media_key.len() == 32 && stream_id.len() == 8;
        let is_member = |core: &P2PCore, gid: &str| {
            core.groups.get(gid).map_or(false, |g| g.members.iter().any(|m| m.identity_id == sender_identity_id))
        };
        // `call_id` is the peer's string: bound it, and never byte-slice it (a
        // multi-byte char at the cut panics inside `poll_events`).
        if call_id.len() > 64 {
            return noop();
        }
        info!("Arama sinyali: {:?} arama={} kimden={}", action, call_id.chars().take(8).collect::<String>(), peer_fp.chars().take(8).collect::<String>());
        match action {
            CallAction::Invite => {
                // ponytail: the age compares two devices' clocks, so a caller
                // more than a minute behind never rings and one ahead can ring
                // late. A clock-free age needs the server to stamp how long it
                // held the item (`MailItem` carries none).
                // Not from the future either: a `sent_at_ms` far ahead passed
                // the age test for good, and a held invite rang whenever it
                // was delivered.
                if !keys_ok || sent_at_ms == 0 || now.abs_diff(sent_at_ms) > INVITE_MAX_AGE_MS {
                    return noop();
                }
                // 1:1 rings only from a contact (a group co-member with a
                // pairwise session is not one).
                if group_id.is_none() && !self.identity_to_contact.contains_key(sender_identity_id) {
                    return noop();
                }
                if let Some(gid) = &group_id {
                    if !is_member(self, gid) {
                        return noop();
                    }
                    // An Invite after the call's `Ended` brings "Attend" back (the
                    // Ended may have come from a participant that only lost sight of
                    // the others), but never rings: see the `early_hangup` check below.
                    let offer = GroupOffer {
                        call_id: call_id.clone(), video, peer_fp: peer_fp.to_string(),
                        media_key: Zeroizing::new(media_key.clone()), stream_id: stream_id.clone(),
                        participants: participants.clone(), at: Instant::now(),
                    };
                    let changed = group_offers().insert(gid.clone(), offer).map_or(true, |old| old.call_id != call_id);
                    if changed {
                        self.attachment_events.push(serde_json::json!({"type": "group_call_offer", "group_id": gid}).to_string());
                    }
                    // An Invite of the group call I am in: its sender lost me.
                    if self.call.as_ref().map_or(false, |s| s.call_id == call_id && s.phase == CallPhase::Active && s.group_id.as_deref() == Some(gid.as_str())) {
                        return self.rejoin_group_peer(peer_fp, media_key, stream_id);
                    }
                    // My other device is in it: never ring here.
                    if sibling_calls().contains(&call_id) {
                        return noop();
                    }
                }
                // The call already ended here (its offer is kept above); also a Hangup that overtook its
                // Invite (two envelopes, two paths).
                let (caller_hung_up, early_hangup) = EARLY_HANGUP
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .iter()
                    .filter(|(id, _)| *id == call_id)
                    .fold((false, false), |(c, e), (_, fp)| (c || fp == peer_fp, e || fp == peer_fp || fp.is_empty() || fp == ENDED));
                if caller_hung_up {
                    if let Some(gid) = &group_id {
                        group_offers().remove(gid);
                    }
                }
                if early_hangup || self.last_call_end.as_ref().map_or(false, |(id, _)| *id == call_id) {
                    return noop();
                }
                let current = self.call.as_ref().map(|s| {
                    let glare = s.phase == CallPhase::Outgoing
                        && s.group_id.is_none()
                        && group_id.is_none()
                        && s.invited.iter().any(|f| f == peer_fp);
                    // The device ringing us called again: it cancelled the old
                    // call and that Hangup is late or lost.
                    let redial = s.phase == CallPhase::Incoming && s.peer_fp == peer_fp;
                    (s.call_id.clone(), glare, redial)
                });
                if let Some((ours, glare, redial)) = current {
                    if ours == call_id {
                        return noop();
                    }
                    if redial {
                        self.call = None;
                        self.last_call_end = Some((ours, "remote".to_string()));
                    } else if !glare {
                        self.send_call_signal(peer_fp, &call_id, group_id, video, CallAction::Busy, None, Vec::new());
                        return noop();
                    } else {
                        // Both called each other at once. Busy from both ended
                        // both calls; instead the lower call id wins on both
                        // sides: its caller ignores the other Invite, the other
                        // side drops its own call and rings for this one.
                        if ours < call_id {
                            return noop();
                        }
                        self.end_call();
                    }
                }
                let invited = match &group_id {
                    Some(gid) => self.group_invited(gid, peer_fp, participants),
                    None => vec![peer_fp.to_string()],
                };
                let mut s = CallSession::new(call_id.clone(), group_id.clone(), video, CallPhase::Incoming, peer_fp.to_string(), invited);
                s.keys.insert(peer_fp.to_string(), (Zeroizing::new(media_key), stream_id));
                s.joined.insert(peer_fp.to_string());
                self.call = Some(s);
                let name = self.call_title();
                serde_json::json!({
                    "type": "call", "action": "invite", "call_id": call_id,
                    "peer": self.canonical_peer_key(peer_fp), "group_id": group_id,
                    "video": video, "name": name,
                })
            }
            CallAction::Accept => {
                if !keys_ok {
                    return noop();
                }
                if !self.call.as_ref().map_or(false, |s| s.call_id == call_id) {
                    // Joined (from an old offer, or answered late) a call that is
                    // over here: tell the joiner, or it sits in an empty call until
                    // the lost-media timeout. Only when the call is known to be
                    // over, not merely left by this device.
                    let over = match &group_id {
                        None => self.last_call_end.as_ref().map_or(false, |(id, _)| *id == call_id),
                        Some(_) => call_known_over(&call_id),
                    };
                    if over {
                        self.send_call_signal(peer_fp, &call_id, group_id, video, CallAction::Hangup, None, Vec::new());
                    }
                    return noop();
                }
                let group = self.call.as_ref().and_then(|s| s.group_id.clone());
                let member = group.as_deref().map_or(false, |gid| is_member(self, gid));
                let Some(s) = self.call.as_mut() else { return noop() };
                if s.retired.contains(&stream_id) {
                    return noop();
                }
                if !s.invited.iter().any(|f| f == peer_fp) {
                    if !member {
                        return noop();
                    }
                    s.invited.push(peer_fp.to_string());
                }
                let was_active = s.phase == CallPhase::Active;
                let new_key = s.keys.insert(peer_fp.to_string(), (Zeroizing::new(media_key.clone()), stream_id.clone())).is_none();
                s.joined.insert(peer_fp.to_string());
                // Group: a joiner we never sent our key to (it was missing
                // from our invited list, or its Accept reached us before the
                // Invite did on its side) would hear nothing from us. Answer a
                // first-seen key once; the reply carries a known key back, so
                // it stops there.
                let reply = (was_active && new_key && s.group_id.is_some())
                    .then(|| (s.call_id.clone(), s.group_id.clone(), s.video, (pair_key(&s.my_key, peer_fp).to_vec(), s.my_sid.to_vec())));
                let mut stop_ringing = Vec::new();
                if s.phase == CallPhase::Outgoing {
                    s.phase = CallPhase::Active;
                    s.connected_at = now;
                    s.connected = Some(Instant::now());
                    // 1:1 rang several devices of one person: answered on
                    // this one, silence the others.
                    if s.group_id.is_none() {
                        stop_ringing = s.invited.iter().filter(|f| *f != peer_fp).cloned().collect();
                        s.invited = vec![peer_fp.to_string()];
                        s.peer_fp = peer_fp.to_string();
                    }
                }
                if s.phase == CallPhase::Active {
                    media_add_remote(peer_fp, &media_key, &stream_id);
                    self.server_sweep_at = 0;
                }
                if !stop_ringing.is_empty() {
                    let (cid, video) = (s.call_id.clone(), s.video);
                    // Busy, not Hangup: a Hangup there means "the caller gave
                    // up" and logged a false missed call.
                    for fp in stop_ringing {
                        self.send_call_signal(&fp, &cid, None, video, CallAction::Busy, None, Vec::new());
                    }
                }
                if let Some((cid, gid, video, keys)) = reply {
                    self.send_call_signal(peer_fp, &cid, gid, video, CallAction::Accept, Some(keys), Vec::new());
                }
                serde_json::json!({"type": "call", "action": "accept", "call_id": call_id, "peer": self.canonical_peer_key(peer_fp)})
            }
            CallAction::Ended => {
                let Some(gid) = group_id.filter(|g| is_member(self, g)) else { return noop() };
                // Only from a device known to be in the call: the one whose
                // Invite we hold, or one in the call that rings here. Any other
                // member could stop every ring of a running call.
                let (ringing, from_ringing) = self
                    .call
                    .as_ref()
                    .filter(|s| s.call_id == call_id && s.phase == CallPhase::Incoming && s.group_id.as_deref() == Some(gid.as_str()))
                    .map_or((false, false), |s| (true, s.peer_fp == peer_fp || s.joined.contains(peer_fp)));
                let from_offer = group_offers().get(&gid).map_or(false, |o| o.call_id == call_id && o.peer_fp == peer_fp);
                if !from_offer && !from_ringing {
                    return noop();
                }
                remember_ended(&call_id, ENDED);
                let gone = group_offers().get(&gid).map_or(false, |o| o.call_id == call_id);
                if gone {
                    group_offers().remove(&gid);
                    self.attachment_events.push(serde_json::json!({"type": "group_call_offer", "group_id": gid}).to_string());
                }
                // Still ringing here for the call that just ended: stop.
                if ringing {
                    self.call = None;
                    self.last_call_end = Some((call_id.clone(), "remote".to_string()));
                    return serde_json::json!({
                        "type": "call", "action": "hangup", "call_id": call_id,
                        "peer": self.canonical_peer_key(peer_fp), "ended": true, "missed": false,
                    });
                }
                noop()
            }
            CallAction::Reject | CallAction::Busy | CallAction::Hangup | CallAction::Joined => {
                let from_me = self.my_identity_id().as_deref() == Some(sender_identity_id);
                if action == CallAction::Joined && !from_me {
                    return noop();
                }
                // The device that kept the offer alive left. The call may go
                // on without it: the next inviter (`is_call_inviter`) renews
                // the offer within the grace, else it expires then.
                if let (CallAction::Hangup, Some(gid)) = (action, &group_id) {
                    if let Some(o) = group_offers().get_mut(gid).filter(|o| o.call_id == call_id && o.peer_fp == peer_fp) {
                        if let Some(short) = Instant::now().checked_sub(Duration::from_millis(OFFER_TTL_MS - OFFER_HANGUP_GRACE_MS)) {
                            o.at = o.at.min(short);
                        }
                    }
                }
                // My other device answered or rejected this call: stop ringing
                // here, nothing to tell anyone. Never ends a call I am in.
                if from_me {
                    if let Some(gid) = &group_id {
                        let changed = {
                            let mut calls = sibling_calls();
                            let had = calls.contains(&call_id);
                            if action == CallAction::Joined && !had {
                                if calls.len() >= 16 {
                                    calls.pop_front();
                                }
                                calls.push_back(call_id.clone());
                            } else if action == CallAction::Hangup && had {
                                calls.retain(|c| *c != call_id);
                            }
                            had != calls.contains(&call_id)
                        };
                        if changed {
                            self.attachment_events.push(serde_json::json!({"type": "group_call_offer", "group_id": gid}).to_string());
                        }
                    }
                    if !self.call.as_ref().map_or(true, |s| s.call_id == call_id) {
                        return noop();
                    }
                    if self.call.as_ref().map_or(false, |s| s.phase != CallPhase::Incoming) {
                        return noop();
                    }
                    if self.call.take().is_none() {
                        // Invite not here yet: it must not ring later. "" = any sender.
                        remember_ended(&call_id, "");
                        return noop();
                    }
                    // A group call keeps re-inviting: `last_call_end` alone is
                    // replaced by the next call that ends here.
                    if group_id.is_some() {
                        never_ring_again(&call_id);
                    }
                    self.last_call_end = Some((call_id.clone(), "elsewhere".to_string()));
                    return serde_json::json!({
                        "type": "call", "action": "busy", "call_id": call_id,
                        "peer": self.canonical_peer_key(peer_fp), "ended": true, "missed": false,
                    });
                }
                let Some(s) = self.call.as_mut() else {
                    // Cancelled before its Invite got here: see the Invite arm.
                    if action == CallAction::Hangup {
                        remember_ended(&call_id, peer_fp);
                    }
                    return noop();
                };
                if s.call_id != call_id {
                    return noop();
                }
                let was_invited = s.invited.iter().any(|f| f == peer_fp);
                if let Some((_, sid)) = s.keys.remove(peer_fp) {
                    s.retired.insert(sid);
                }
                s.joined.remove(peer_fp);
                media_remove_remote(peer_fp);
                // A group member that left is not rung again (`call_sweep_inner`).
                if action != CallAction::Hangup || s.group_id.is_some() {
                    s.invited.retain(|f| f != peer_fp);
                }
                let over = match (&s.group_id, s.phase) {
                    // 1:1 rings every device of the contact: one that is busy
                    // leaves the others ringing, a Reject is the person's answer.
                    (None, CallPhase::Outgoing) => was_invited && (action != CallAction::Busy || s.invited.is_empty()),
                    // Only the device we talk to (or that rang us) ends it,
                    // not another device of the same contact.
                    (None, _) => s.peer_fp == peer_fp,
                    // The ring ends when the caller gives up before we answer.
                    // Others already talking: keep ringing, we can still join.
                    (Some(_), CallPhase::Incoming) => s.peer_fp == peer_fp && s.joined.is_empty(),
                    (Some(_), CallPhase::Outgoing) => s.invited.is_empty(),
                    (Some(_), CallPhase::Active) => s.joined.is_empty(),
                };
                // The caller gave up while it rang here.
                let missed = over && action == CallAction::Hangup && s.phase == CallPhase::Incoming && s.group_id.is_none();
                if over {
                    if let Some(s) = self.call.take() {
                        // Devices still ringing for this call hear from nobody
                        // else that it is over.
                        if s.phase != CallPhase::Incoming {
                            // A 1:1 call answered (rejected) on one device: the
                            // others did not miss it.
                            let stop = if s.group_id.is_none() { CallAction::Busy } else { CallAction::Hangup };
                            for fp in s.invited.iter().filter(|f| *f != peer_fp) {
                                self.call_signal(fp, &s, stop);
                            }
                        }
                        // Everyone else left: I was the last one. Tell all members.
                        if s.phase == CallPhase::Active && s.group_id.is_some() {
                            self.group_call_ended(&s);
                        }
                    }
                    media_stop();
                    let reason = match action {
                        CallAction::Reject => "rejected",
                        CallAction::Busy => "busy",
                        _ => "remote",
                    };
                    self.last_call_end = Some((call_id.clone(), reason.to_string()));
                }
                if missed {
                    self.log_missed_call(peer_fp);
                }
                serde_json::json!({
                    "type": "call", "action": format!("{:?}", action).to_lowercase(),
                    "call_id": call_id, "peer": self.canonical_peer_key(peer_fp), "ended": over, "missed": missed,
                })
            }
        }
    }

    /// An Invite of the group call I am in, from a device in it that lost me
    /// (it dropped me as silent, or my Accept never reached it): take its key
    /// and answer with mine, so both sides hear each other again.
    fn rejoin_group_peer(&mut self, peer_fp: &str, media_key: Vec<u8>, stream_id: Vec<u8>) -> serde_json::Value {
        let Some(s) = self.call.as_mut() else { return noop() };
        if s.retired.contains(&stream_id) {
            return noop();
        }
        if !s.invited.iter().any(|f| f == peer_fp) {
            s.invited.push(peer_fp.to_string());
        }
        media_add_remote(peer_fp, &media_key, &stream_id);
        s.keys.insert(peer_fp.to_string(), (Zeroizing::new(media_key), stream_id));
        s.joined.insert(peer_fp.to_string());
        let (cid, gid, video) = (s.call_id.clone(), s.group_id.clone(), s.video);
        let keys = (pair_key(&s.my_key, peer_fp).to_vec(), s.my_sid.to_vec());
        self.server_sweep_at = 0;
        self.send_call_signal(peer_fp, &cid, gid, video, CallAction::Accept, Some(keys), Vec::new());
        noop()
    }

    /// The callee's trace of a 1:1 call it missed: a row in the chat, under
    /// the chat key (the caller may be a non-canonical device of the
    /// contact), for the Hangup and for the local ring timeout.
    pub(crate) fn log_missed_call(&mut self, peer_fp: &str) {
        let chat_key = self.canonical_peer_key(peer_fp);
        let id = uuid::Uuid::new_v4().to_string();
        let _ = self.archive_message(&chat_key, "received", "\u{1F4DE} Missed call".as_bytes(), Some(&id), None, None, None, crate::current_time_ms());
    }

    /// Ring timeouts + link upkeep. Every poll turn; cheap when idle.
    pub(crate) fn call_sweep(&mut self) {
        self.call_sweep_inner();
        let expired: Vec<String> = {
            let mut offers = group_offers();
            let gone: Vec<String> = offers.iter().filter(|(_, o)| o.at.elapsed() >= Duration::from_millis(OFFER_TTL_MS)).map(|(g, _)| g.clone()).collect();
            for g in &gone {
                offers.remove(g);
            }
            gone
        };
        for gid in expired {
            self.attachment_events.push(serde_json::json!({"type": "group_call_offer", "group_id": gid}).to_string());
        }
        // a `call_state` event whenever phase/participants change, so
        // the UI need not poll for transitions (the timer/media stats still
        // come from `callState`).
        let sig = match &self.call {
            Some(s) => {
                let mut j: Vec<&String> = s.joined.iter().collect();
                j.sort();
                format!("{}|{:?}|{:?}|{}", s.call_id, s.phase, j, s.invited.len())
            }
            None => format!("idle|{:?}", self.last_call_end),
        };
        let mut last = LAST_CALL_SIG.lock().unwrap_or_else(|p| p.into_inner());
        if *last != sig {
            *last = sig;
            drop(last);
            let mut v: serde_json::Value = serde_json::from_str(&self.call_state_json()).unwrap_or_default();
            v["type"] = serde_json::json!("call_state");
            self.attachment_events.push(v.to_string());
        }
    }

    pub(super) fn call_sweep_inner(&mut self) {
        if let Some(s) = &self.call {
            // the group caller rings members not in the call again, so a
            // device that comes online late still rings (the first Invite
            // is too old by then). Ringing devices drop the repeat (same id).
            let every = if s.started.elapsed() < Duration::from_millis(REINVITE_FOR_MS) { REINVITE_EVERY_MS } else { REINVITE_LATE_EVERY_MS };
            let reinvite = s.phase == CallPhase::Active && s.group_id.is_some()
                && s.last_invite.elapsed() > Duration::from_millis(every)
                && self.is_call_inviter(s);
            if reinvite {
                let mut s = self.call.take().expect("checked above");
                s.last_invite = Instant::now();
                // Also members that rejected or left: it no longer rings
                // there (`last_call_end`), it keeps their "Attend" alive.
                let mut to: Vec<String> = s.invited.clone();
                for fp in s.group_id.as_deref().and_then(|g| self.group_call_devices(g).ok()).unwrap_or_default() {
                    if !to.contains(&fp) {
                        to.push(fp);
                    }
                }
                for fp in to.iter().filter(|f| !s.joined.contains(*f)) {
                    self.call_signal(fp, &s, CallAction::Invite);
                }
                self.call = Some(s);
            }
        }
        // A participant removed from the group, or blocked, while the call
        // runs: membership was checked only at Invite/Accept.
        let not_allowed: Vec<String> = match &self.call {
            Some(s) => s.joined.iter().chain(s.invited.iter()).filter(|fp| {
                let Some(id) = self.known_remote_devices.get(*fp).map(|d| d.identity_id.clone()) else { return false };
                self.is_blocked(&id) || s.group_id.as_ref().map_or(false, |g| {
                    !self.groups.get(g).map_or(false, |g| g.member_identity_ids().contains(&id))
                })
            }).cloned().collect(),
            None => Vec::new(),
        };
        if !not_allowed.is_empty() {
            if self.call.as_ref().map_or(false, |s| s.group_id.is_none()) {
                info!("Call: peer blocked, ending call");
                self.end_call_with("remote");
                return;
            }
            if let Some(s) = self.call.as_mut() {
                for fp in &not_allowed {
                    s.joined.remove(fp);
                    s.invited.retain(|f| f != fp);
                    media_remove_remote(fp);
                }
            }
        }
        // Group call: a participant silent that long (phone died, no Hangup)
        // leaves, or every frame went on being sealed and sent to it for the
        // rest of the call. Its state packets alone arrive every second.
        // A device that never sent anything counts from when it was added.
        // It gets an Invite of the call: a device still in it answers with
        // an Accept (`rejoin_group_peer`), so a path that stalled for a while
        // does not split the call for good.
        // ponytail: a device whose signals arrive but whose media never does
        // cycles drop -> Invite -> Accept every 30 s; fine at that rate.
        let gone: Vec<String> = match self.call.as_mut().filter(|s| s.phase == CallPhase::Active && s.group_id.is_some()) {
            Some(s) => {
                let lost = Duration::from_millis(MEDIA_LOST_MS);
                let gone: Vec<String> = s.joined.iter().filter(|fp| media_rx_age(fp).map_or(false, |a| a > lost)).cloned().collect();
                for fp in &gone {
                    info!("Call: removed participant silent for {} s", MEDIA_LOST_MS / 1000);
                    s.joined.remove(fp);
                    media_remove_remote(fp);
                }
                gone
            }
            None => Vec::new(),
        };
        if !gone.is_empty() {
            let s = self.call.take().expect("checked above");
            for fp in &gone {
                self.call_signal(fp, &s, CallAction::Invite);
            }
            self.call = Some(s);
        }
        let Some(s) = &self.call else { return };
        let now = current_time_ms();
        let ringing_too_long = s.started.elapsed() > Duration::from_millis(RING_TIMEOUT_MS);
        match s.phase {
            CallPhase::Outgoing if ringing_too_long => {
                info!("Call was not answered");
                self.end_call_with("no_answer");
                return;
            }
            CallPhase::Incoming if ringing_too_long => {
                let s = self.call.take().expect("checked above");
                // Our ring timed out first (the caller's Hangup is late or
                // never comes): the same trace as that Hangup.
                if s.group_id.is_none() {
                    self.log_missed_call(&s.peer_fp);
                    self.attachment_events.push(serde_json::json!({
                        "type": "call", "action": "hangup", "call_id": s.call_id,
                        "peer": self.canonical_peer_key(&s.peer_fp), "ended": true, "missed": true,
                    }).to_string());
                }
                if s.group_id.is_some() {
                    never_ring_again(&s.call_id);
                }
                self.last_call_end = Some((s.call_id, "missed".to_string()));
                return;
            }
            CallPhase::Incoming => return,
            CallPhase::Active => {
                let quiet = s.connected.map(|c| {
                    s.joined.iter().filter_map(|fp| media_rx_age(fp)).chain([c.elapsed()]).min().unwrap_or_default()
                });
                if quiet.map_or(false, |q| q > Duration::from_millis(MEDIA_LOST_MS)) {
                    info!("Arama koptu: {} sn boyunca kimseden medya gelmedi", MEDIA_LOST_MS / 1000);
                    self.end_call_with("lost");
                    return;
                }
            }
            _ => {}
        }
        let Some(control) = &self.stream_control else { return };
        // Test knob, debug builds only: an empty `call_force_relay` file in
        // the app files dir sends all media through the server even when a
        // direct link exists.
        let force_relay = cfg!(debug_assertions)
            && self
            .app_files_dir
            .as_ref()
            .map_or(false, |d| std::path::Path::new(d).join("call_force_relay").exists());
        let peers: Vec<(String, Option<PeerId>)> = s
            .joined
            .iter()
            .map(|fp| {
                let p = self
                    .device_to_peer_id
                    .get(fp)
                    .copied()
                    .filter(|p| !force_relay && self.swarm.as_ref().map_or(false, |sw| sw.is_connected(p)));
                (fp.clone(), p)
            })
            .collect();
        if now.saturating_sub(self.call_stats_logged_at) >= 5_000 {
            self.call_stats_logged_at = now;
            info!("Call media: {}", media_stats());
        }
        media_supervise(control, peers, self.ready_server_peers());
    }

    /// One participant of a group call re-invites the absent members: the
    /// lowest device fingerprint in it. When the caller leaves, the next one
    /// takes over, so the call stays visible ("Attend") while anyone is in it.
    fn is_call_inviter(&self, s: &CallSession) -> bool {
        let Ok(own) = self.get_active_own_device_fingerprint() else { return false };
        s.joined.iter().all(|fp| own < *fp)
    }

    pub(super) fn call_title(&self) -> String {
        let Some(s) = &self.call else { return String::new() };
        match &s.group_id {
            Some(gid) => self.groups.get(gid).map(|g| g.name.clone()).unwrap_or_else(|| gid.chars().take(8).collect()),
            None => self.device_display_name(&s.peer_fp),
        }
    }

    pub(super) fn device_display_name(&self, fp: &str) -> String {
        self.known_remote_devices
            .get(fp)
            .and_then(|d| self.identity_to_contact.get(&d.identity_id))
            .and_then(|cid| self.contacts.get(cid))
            .map(|c| c.display_name.clone())
            .unwrap_or_else(|| fp.chars().take(8).collect())
    }

    pub(crate) fn call_state_json(&self) -> String {
        let Some(s) = &self.call else {
            let (last_call_id, reason) = self.last_call_end.clone().unwrap_or_default();
            return serde_json::json!({"state": "idle", "last_call_id": last_call_id, "reason": reason}).to_string();
        };
        let mut fps: Vec<&String> = s.invited.iter().collect();
        fps.extend(s.joined.iter().filter(|f| !s.invited.contains(f)));
        let participants: Vec<serde_json::Value> = fps
            .into_iter()
            .map(|fp| serde_json::json!({
                "fp": fp,
                "peer": self.canonical_peer_key(fp),
                "name": self.device_display_name(fp),
                "joined": s.joined.contains(fp),
                "slot": media_slot_of(fp),
                "last_rx_ms": media_last_rx(fp),
                "muted": media_flags_of(fp).0,
                "video_off": media_flags_of(fp).1,
                "direct": self.device_to_peer_id.get(fp).map_or(false, |p| self.swarm.as_ref().map_or(false, |sw| sw.is_connected(p))),
            }))
            .collect();
        let phase = match s.phase {
            CallPhase::Outgoing => "outgoing",
            CallPhase::Incoming => "incoming",
            CallPhase::Active => "active",
        };
        serde_json::json!({
            "state": phase, "call_id": s.call_id, "group_id": s.group_id, "video": s.video,
            "peer": if s.peer_fp.is_empty() { String::new() } else { self.canonical_peer_key(&s.peer_fp) },
            "name": self.call_title(), "started_at": s.started_at, "connected_at": s.connected_at,
            "now": current_time_ms(), "participants": participants, "media": media_stats(),
        })
        .to_string()
    }
}

/// An Invite of `call_id` from anyone no longer rings here ("" = any sender in
/// `EARLY_HANGUP`); its "Attend" offer is still kept.
fn never_ring_again(call_id: &str) {
    remember_ended(call_id, "");
}

/// Entries of `EARLY_HANGUP`: the oldest goes first, a repeat is not stored
/// twice. Large enough that the Hangups of one busy group call do not push
/// out a call declined here.
const ENDED_MEMORY: usize = 256;

fn remember_ended(call_id: &str, sender: &str) {
    let mut early = EARLY_HANGUP.lock().unwrap_or_else(|p| p.into_inner());
    if early.iter().any(|(id, fp)| id == call_id && fp == sender) {
        return;
    }
    if early.len() >= ENDED_MEMORY {
        early.pop_front();
    }
    early.push_back((call_id.to_string(), sender.to_string()));
}

/// The group call is over (its `Ended` arrived, or this device sent it).
fn call_known_over(call_id: &str) -> bool {
    EARLY_HANGUP.lock().unwrap_or_else(|p| p.into_inner()).iter().any(|(id, fp)| id == call_id && fp == ENDED)
}
