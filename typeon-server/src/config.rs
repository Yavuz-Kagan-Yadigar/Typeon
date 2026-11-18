//! Server configuration plus the invite / join-code / advertised-address helpers.

use super::*;

/// The addresses the running server last advertised (peer id included).
pub fn advertised_addrs(store: &Store) -> Result<Vec<String>, String> {
    let raw = store.meta_get(ADVERTISED_ADDRS_KEY).unwrap_or_default();
    let addrs: Vec<String> = String::from_utf8_lossy(&raw).lines().map(str::to_string).collect();
    if addrs.is_empty() {
        return Err("Server has no address yet — start it first with `typeon-server run`".to_string());
    }
    Ok(addrs)
}

/// Creates an invite and returns the full invite code. `uses <= 0` means UNLIMITED (see `Store::create_invite`).
/// Needs only the store (see `ADVERTISED_ADDRS_KEY`).
pub fn create_invite(store: &Store, label: &str, uses: i64, ttl_ms: i64) -> Result<String, String> {
    let addrs = advertised_addrs(store)?;
    let mut token = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut token);
    // The token is stored HASHED. Even if the server disk is stolen, unused invites cannot be used.
    let now = now_ms();
    let expires = if ttl_ms <= 0 { 0 } else { now.saturating_add(ttl_ms) };
    store.create_invite(Sha256::digest(token).as_slice(), label, uses, expires, now)?;
    Ok(server_proto::format_server_invite(&addrs, &hex::encode(token)))
}

/// The server's public join code (3-day lifetime) (see `public_join_token`). `rotate`: the old code becomes invalid
/// IMMEDIATELY. Enrolled devices are not affected.
pub fn join_code(store: &Store, rotate: bool) -> Result<String, String> {
    let addrs = advertised_addrs(store)?;
    Ok(server_proto::format_server_invite(&addrs, &public_join_token(store, rotate)?))
}

/// Returns the public join token. A new one is made when there is none, when the old one expired
/// (`PUBLIC_CODE_TTL_MS`), when its invite row is gone (for example a `data` restore from an old backup), or
/// with `rotate`. The old invite row is deleted, so the old code stops working at once.
///
/// Unlike every other invite, this token is kept in clear (`meta`), so the CLI and the app can show the code again.
/// A copy of an unkeyed database therefore gives a working join code until it expires or is rotated (at most 3 days).
/// Accepted: the code is public by design; set a DB key to protect it at rest.
///
/// A free function, because the Android server's JNI layer cannot see `ServerCore` (it lives inside the network
/// task). It uses only `Store`. A second copy of this logic there would drift apart.
pub fn public_join_token(store: &Store, rotate: bool) -> Result<String, String> {
    let now = now_ms();
    let old = store
        .meta_get(PUBLIC_JOIN_TOKEN_KEY)
        .and_then(|v| hex::decode(String::from_utf8_lossy(&v).trim().as_bytes()).ok())
        .filter(|raw| !raw.is_empty());
    if let Some(raw) = &old {
        let hash = Sha256::digest(raw);
        if !rotate && store.invite_uses_left(hash.as_slice(), now) == Some(-1) {
            return Ok(hex::encode(raw));
        }
        let _ = store.delete_invite(hash.as_slice());
    }
    let mut raw = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    store.create_invite(Sha256::digest(raw).as_slice(), PUBLIC_JOIN_LABEL, 0, now + PUBLIC_CODE_TTL_MS, now)?;
    let token = hex::encode(raw);
    store.meta_set(PUBLIC_JOIN_TOKEN_KEY, token.as_bytes())?;
    Ok(token)
}

impl ServerConfig {
    pub fn new(data_dir: PathBuf) -> Self {
        let limits = ServerLimits::default();
        // 16 x (256 MiB mail + 1 GiB archive + 4 GiB blob) = 84 GiB.
        let total = DEFAULT_MAX_ENROLLMENTS as u64
            * (limits.max_mail_bytes + limits.max_archive_bytes + limits.max_blob_bytes);
        ServerConfig {
            blob_dir: data_dir.join("blobs"),
            data_dir,
            node_mode: false,
            server_name: "Typeon Server".to_string(),
            limits,
            total_storage_budget_bytes: Some(total),
            max_enrollments: DEFAULT_MAX_ENROLLMENTS,
        }
    }

    /// Sets the total disk budget and splits it over `max_enrollments` (set that first): blob 6/10, archive 3/10,
    /// mail 1/10 of one device's share, never above the defaults. Otherwise the per-device quotas could add up to
    /// several times the budget.
    pub fn apply_storage_budget(&mut self, budget: u64) {
        self.total_storage_budget_bytes = Some(budget);
        let per_device = (budget / self.max_enrollments.max(1) as u64).max(8 * 1024 * 1024);
        let defaults = ServerLimits::default();
        self.limits.max_blob_bytes = (per_device * 6 / 10).min(defaults.max_blob_bytes);
        self.limits.max_archive_bytes = (per_device * 3 / 10).min(defaults.max_archive_bytes);
        self.limits.max_mail_bytes = (per_device / 10).min(defaults.max_mail_bytes);
    }
}

/// The libp2p identity is persistent: the `PeerId` must NOT change across restarts, or every distributed invite
/// code would become invalid.
pub(super) fn load_or_generate_keypair(store: &Store) -> Result<libp2p::identity::Keypair, String> {
    if let Some(bytes) = store.meta_get("libp2p_key") {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return Ok(kp);
        }
        warn!("Stored libp2p key could not be read, generating a new one");
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let encoded = kp.to_protobuf_encoding().map_err(|e| e.to_string())?;
    store.meta_set("libp2p_key", &encoded)?;
    Ok(kp)
}
