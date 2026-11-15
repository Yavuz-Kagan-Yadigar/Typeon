//! Radio saver, metered/power-save/node modes, busy reasons and connection status.

use super::*;

impl P2PCore {
    /// See `RADIO_WINDOW_MS`. Wi-Fi too: with Tor awake, a night on Wi-Fi woke the CPU about once a second (measured: 64 % of 7 hours with the
    /// screen off).
    pub(crate) fn radio_saver(&self) -> bool {
        self.power_save
    }

    pub(crate) fn radio_window_ms(&self) -> u64 {
        if self.metered { RADIO_WINDOW_MS } else { RADIO_WINDOW_WIFI_MS }
    }

    pub(crate) fn set_metered(&mut self, metered: bool) {
        if self.metered != metered {
            info!("Metered network: {}", metered);
        }
        self.metered = metered;
    }

    /// Battery saver. The Kotlin / GTK side turns this on when the app goes to the background and the screen turns off. It does not change network
    /// behaviour; it only lowers the probe rate of healthy, quiet connections (see the `power_save` field note).
    pub(crate) fn set_power_save(&mut self, enabled: bool) {
        if self.power_save == enabled {
            return;
        }
        self.power_save = enabled;
        info!("Power saving mode: {}", if enabled { "on" } else { "off" });
        // On leaving the mode, pull pending probes forward, so liveness is checked as soon
        // as the user opens the screen, not after 60 s.
        if !enabled {
            let now = mono_ms();
            self.resync_since = now;
            for state in self.keepalive_state.values_mut() {
                if state.next_due_at > now + KEEPALIVE_FAST_INTERVAL_MS {
                    state.next_due_at = now + KEEPALIVE_FAST_INTERVAL_MS;
                }
            }
        }
    }

    /// Only stores the flag. In code, node mode means one thing: the device serves as a
    /// relay (`P2PBehaviour.relay`), set in `start_network`. A change takes effect at
    /// the next network start. There is no DHT role. Kademlia always runs in client
    /// mode (server mode answered FIND_NODE with contacts' peer IDs and onions), and no
    /// DHT record is written.
    pub(crate) fn set_node_mode(&mut self, enabled: bool) {
        self.node_mode_enabled = enabled;
    }

    /// Called from the history and attachment storage limit slider in settings. A
    /// lowered limit applies at once, without waiting for the next
    /// `periodic_storage_sweep` round (see `enforce_history_storage_limit`).
    pub(crate) fn set_history_storage_limit_bytes(&mut self, bytes: u64) {
        // Both UIs stop at 32 GB. u64::MAX would make the limit meaningless.
        self.history_storage_limit_bytes = bytes.min(64 << 30);
        self.enforce_history_storage_limit();
    }

    /// The `rendezvous_node` shown on the QR / "my code" screen and carried to the other
    /// side: an address the swarm really listens on (`own_listen_addrs`, see
    /// `poll_events`), plus our PeerId as a `/p2p/<peer_id>` suffix. Without the suffix,
    /// `extract_peer_id` on the other side never finds a PeerId, and a scanned QR
    /// address is silently unusable for `kad.add_address` and `dial` (see
    /// `process_qr_packet`). Prefers the onion address, else a relay circuit address.
    /// `None` while Tor bootstraps. Never the loopback listener: no peer can dial it.
    pub(crate) fn get_node_address(&self) -> Option<String> {
        let swarm = self.swarm.as_ref()?;
        let peer_id = *swarm.local_peer_id();
        // With Tor on and the onion service published, share the .onion address first. It
        // is the only address reachable from every network (CGNAT included) when the other
        // side also runs Tor. Format: `/dns/<host>.onion/tcp/<port>/p2p/<peer_id>` (see
        // tor.rs, ArtiDialTransport `onion_host_port`). The port is arbitrary: the bridge
        // forwards every incoming port to local libp2p (see `bridge_incoming_stream`).
        // TOR_LIBP2P_PORT is used for consistency.
        if let Some(tor) = &self.tor {
            if let Some(onion_host) = tor.onion_host() {
                return Some(format!("/dns/{}/tcp/{}/p2p/{}", onion_host, TOR_LIBP2P_PORT, peer_id));
            }
        }
        // The node is onion-only (Tor is mandatory, see `start_network`). A listen address
        // would leak clearnet and UPnP addresses, and nobody can dial it.
        None
    }

    /// Tor status for the UI: "disabled", "bootstrapping", "ready" or "failed", plus the
    /// .onion host name when ready.
    pub(crate) fn tor_status(&self) -> String {
        match &self.tor {
            None => "disabled".to_string(),
            Some(h) => {
                let st = h.status().as_str();
                match h.onion_host() {
                    Some(host) if h.status() == tor::TorStatus::Ready => format!("{st}|{host}"),
                    _ => st.to_string(),
                }
            }
        }
    }

    /// Whether the core has real work to do. Used for the Android poll-interval choice
    /// (see `nextPollDelayMs` in P2PService).
    ///
    /// Battery: the swarm advances only while `poll_events` runs (`now_or_never`, no
    /// background task). Opening the poll interval blindly would stall the network:
    /// handshakes, Tor circuit builds and mesh upkeep would slow down too. So the
    /// interval follows the core's real state. Busy means:
    ///   * at least one connected peer (an incoming message is possible, keepalive runs),
    ///   * a packet awaiting confirmation (retry timer runs),
    ///   * a file download or upload in progress,
    ///   * an unsent envelope in the queue,
    ///   * server work to deposit or fetch.
    /// If none holds, the only thing left is accepting an inbound connection, which
    /// needs no poll every second.
    pub(crate) fn has_pending_work(&self) -> bool {
        // Battery: a connected peer alone is not busy. A permanently open Tor or server
        // connection kept the wake lock held 24/7 with the screen off and drained 20-40 %
        // per day. Only real pending work keeps the device awake.
        // awaiting_confirmation, pending_envelopes and pending_group_messages are NOT
        // counted. Messages for an offline peer wait for hours and the retry timer handles
        // them. Counting them would hold the CPU awake (measured: wake lock held 15/15 min).
        // An active pairing (TTL 15 min) needs fast polls for the IdentityExchange and
        // Handshake rounds. Without them, pairing stalled in the 60 s waits of deep idle.
        // Server work counts only while connected to a server. While it is unreachable these
        // queues cannot advance, and counting them held the wake lock 24/7 (measured 15/15
        // min). `server_archive_queue` (background sync backlog) is never counted.
        self.pairing_is_fresh()
            || self.downloads_busy() > 0
            // `server_inflight` is not work. The 30 s fetch sweep is sent in the same poll turn the service checks next, so it always read as busy,
            // and no phone reached deep idle (measured: wake lock held 30 of 30 minutes, LTE radio active 93 %). Its reply is a network event that
            // wakes the native wait anyway.
            // Not while the server refuses deposits (quota): the upload then only waits for the backoff. Only with a routing server up, since
            // uploads go nowhere else.
            || self.blob_upload_can_run()
            // A deferred incoming packet means the device is not idle. Otherwise it would drop
            // into the 30 s deep-idle step and delay delivery (see `deferred_incoming`). Not
            // while the core only waits for the storage keys: that wait ends with a call from
            // the app, not with work here, and must not hold the CPU.
            || (!self.deferred_incoming.is_empty() && self.storage_keys_ready())
            || self.call.is_some()
    }

    /// Downloads that moved within the stall timeout and are not waiting for `retry_at`.
    /// A stalled one is probed by `check_stalled_downloads` on the next poll. The answer
    /// is a network event that wakes the native wait, so the wake lock need not be held
    /// between probes.
    pub(crate) fn downloads_busy(&self) -> usize {
        let now = current_time_ms();
        self.active_downloads.values()
            .filter(|s| s.retry_at == 0 && now.saturating_sub(s.last_progress_at) < DOWNLOAD_STALL_TIMEOUT_MS)
            .count()
    }

    /// A pairing counts as work for its first two minutes only. One that never completes
    /// would otherwise hold the wake lock for the whole 15 min TTL.
    pub(crate) fn pairing_is_fresh(&self) -> bool {
        let now = current_time_ms();
        self.pairing_mailbox_subs.values().any(|at| now.saturating_sub(*at) < 2 * 60 * 1000)
    }

    /// Which `has_pending_work` terms are true. Logged when busy, so a phone that never
    /// reaches deep idle says why.
    pub(crate) fn busy_reasons(&self) -> String {
        let mut r = Vec::new();
        if self.pairing_is_fresh() { r.push(format!("pairing={}", self.pairing_mailbox_subs.len())); }
        if self.downloads_busy() > 0 { r.push(format!("downloads={}", self.downloads_busy())); }
        if self.blob_upload_can_run() { r.push(format!("blob_uploads={}", self.server_blob_uploads.len())); }
        if !self.deferred_incoming.is_empty() && self.storage_keys_ready() { r.push(format!("deferred_incoming={}", self.deferred_incoming.len())); }
        if self.call.is_some() { r.push("call".into()); }
        r.join(",")
    }

    /// Raw network signals of THIS device (not the peer) for the chat header status, as
    /// JSON. The Kotlin side builds the human-readable summary (i18n, adjustable later;
    /// see P2PLib.kt). Rust and libp2p cannot tell whether the internet is reachable,
    /// since they have no access to OS interfaces. Kotlin adds that as `has_internet`
    /// via `ConnectivityManager`.
    pub(crate) fn own_connection_status(&self) -> serde_json::Value {
        let connected_peers = self.swarm.as_ref().map(|s| s.connected_peers().count()).unwrap_or(0);
        let busy = self.has_pending_work();
        if busy {
            log::debug!("Core busy: {}", self.busy_reasons());
        }
        // Coming out of power save: true until every link's pulled-forward keepalive probe
        // is answered (the UI shows a spinner). 10 s cap, so a dead link cannot keep it
        // spinning.
        let syncing = self.resync_since != 0
            && mono_ms().saturating_sub(self.resync_since) < 10_000
            && self.keepalive_state.values().any(|s| {
                s.outstanding.is_some() || s.next_due_at <= self.resync_since + KEEPALIVE_FAST_INTERVAL_MS
            });
        serde_json::json!({
            "busy": busy,
            "syncing": syncing,
            "connected_peers": connected_peers,
            "listening": !self.own_listen_addrs.is_empty(),
            "tor_enabled": self.tor_enabled,
            "tor_status": self.tor.as_ref().map(|h| h.status().as_str().to_string()).unwrap_or_else(|| "disabled".to_string()),
            "node_mode": self.node_mode_enabled,
        })
    }

}
