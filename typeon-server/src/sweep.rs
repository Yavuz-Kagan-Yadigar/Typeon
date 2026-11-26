//! Periodic maintenance: clock-jump guard, revoked peers, expiry sweeps.

use super::*;

impl ServerCore {
    /// `true` while the wall clock is more than `CLOCK_JUMP_MS` away from where the monotonic clock says it should be.
    /// After `CLOCK_JUMP_HOLD_MS` the new time is accepted as real, and a forward step moves the stored deadlines
    /// with it (`Store::shift_deadlines`). Either clock may have been the wrong one, so nothing expires because of
    /// the step itself.
    pub(super) fn clock_jumped(&mut self, now: i64, mono: u64) -> bool {
        let (wall0, mono0) = *self.clock_anchor.get_or_insert((now, mono));
        let expected = wall0 + (mono - mono0) as i64;
        if (now - expected).abs() <= CLOCK_JUMP_MS {
            self.clock_off_since = None;
            return false;
        }
        if mono - *self.clock_off_since.get_or_insert(mono) < CLOCK_JUMP_HOLD_MS {
            return true;
        }
        if now > expected {
            warn!("System clock moved {} s forward — timers shifted", (now - expected) / 1000);
            self.store.shift_deadlines(now - expected, expected);
        }
        self.clock_anchor = Some((now, mono));
        self.clock_off_since = None;
        false
    }

    /// A device revoked or blocked while connected loses its pushes and its call-relay link, not only its RPCs.
    /// Runs at once on `CoreSignal::EnrollmentsChanged` (Android) and on every 5 s tick. The tick covers revokes
    /// made from the CLI, a separate process.
    pub(super) fn drop_revoked_peers(&mut self) {
        let peers: HashSet<PeerId> = self.live_interest.keys().chain(self.relay_links.keys()).copied().collect();
        let gone: Vec<PeerId> = peers.into_iter().filter(|p| self.active(*p).is_none()).collect();
        for peer in gone {
            self.live_interest.remove(&peer);
            self.relay_links.remove(&peer);
        }
    }

    pub(super) fn maybe_sweep(&mut self) {
        // Another connection (the CLI) committed since the last scan, or this is the first tick.
        let version = self.store.data_version();
        if version != self.revoke_scan_version {
            self.revoke_scan_version = version;
            self.drop_revoked_peers();
        }
        // Once per tick, not once per Ack: the recount rewrites every enrollment.
        if std::mem::take(&mut self.mail_recount_due) {
            self.store.recount_mail_bytes();
        }
        self.resend_notifies();
        let mono = mono_ms();
        // Every tick, not only every sweep. A peer that is not enrolled used to hold its slot for up to two sweeps
        // (60 to 120 s).
        // ponytail: not in node mode, where strangers are served on purpose (Kad, circuit relay). There the connection
        // cap is still the one flood guard.
        if !self.config.node_mode {
            let idle: Vec<PeerId> = self
                .conns
                .iter()
                .filter(|(p, c)| {
                    (mono.saturating_sub(c.connected_at.max(c.last_anon_at)) > UNENROLLED_GRACE_MS
                        || mono.saturating_sub(c.connected_at) > UNENROLLED_MAX_LIFETIME_MS)
                        && self.swarm.is_connected(p)
                })
                .map(|(p, _)| *p)
                .filter(|p| self.active(*p).is_none())
                .collect();
            for peer in idle {
                let _ = self.swarm.disconnect_peer_id(peer);
            }
        }
        if self.last_sweep.map_or(false, |t| mono - t < SWEEP_INTERVAL_MS) {
            return;
        }
        self.last_sweep = Some(mono);
        self.publish_shared();

        let swarm = &self.swarm;
        self.conns.retain(|p, c| swarm.is_connected(p) || mono - c.window_start <= RATE_WINDOW_MS);
        self.relay_budget.retain(|_, b| mono - b.0 <= RELAY_WINDOW_MS);
        self.relay_pairs.retain(|_, t| mono - *t <= RELAY_WINDOW_MS);
        self.deposit_window.retain(|_, w| mono.saturating_sub(w.0) <= DEPOSIT_WINDOW_MS);


        let now = now_ms();
        if self.clock_jumped(now, boot_ms()) {
            warn!("System clock jumped — TTL sweep deferred");
            return;
        }
        // Tracked above even while wrong, so the step to the right time is seen and the deadlines move with it.
        if now < SANE_WALL_FLOOR_MS {
            warn!("System clock invalid — TTL sweep skipped");
            return;
        }
        let slept = self.store.sleep_idle_enrollments(now - ENROLLMENT_IDLE_MS);
        let removed = self.store.sweep_expired_mail(now) + slept;
        let archived = self.store.sweep_expired_archive(now);
        if archived > 0 {
            info!("Sweep deleted {archived} archive records (13 months)");
        }
        if removed > 0 {
            info!("Sweep deleted {removed} delivery items");
            self.store.recount_mail_bytes();
        }
        for blob_id in self.store.blobs_to_gc(now, self.config.limits.blob_ttl_ms as i64) {
            self.drop_blob(&blob_id);
        }
        self.store.recount_blob_bytes();
        // Enrollments idle this long own nothing any more in the normal case (the archive TTL is the longest).
        self.store.prune_dead_rows(now - store::ARCHIVE_TTL_MS);
        self.store.incremental_vacuum();
    }
}
