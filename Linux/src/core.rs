//! Typed, Rust-idiomatic layer over `p2p_messenger::api`.
//!
//! The façade in the core crate mirrors the Android JNI surface exactly, which
//! means it speaks in JSON strings and `"Error: ..."` prefixes (a JNI boundary
//! cannot carry a `Result`). Everything above this module works with real
//! types instead. The summary structs are the core's OWN types, re-exported —
//! not local copies — so a field added on the protocol side cannot silently go
//! missing here.
//!
//! This is a complete binding layer: every entry point the Android `P2PLib`
//! exposes has a counterpart here, whether or not this client's UI happens to
//! call it today. Pruning the unused ones would make the next feature look like
//! it needs core changes when it does not.
#![allow(dead_code)]

pub use p2p_messenger::{
    ArchivedMessage, AttachmentSummary, ContactSummary, DeviceAlertInfo, GroupSummary,
    PendingMessageSummary,
};
use p2p_messenger::api;
use serde::Deserialize;

/// The façade signals failure with a `"Error: ..."` prefix (JNI convention).
/// Everything above this module wants a `Result`.
fn parse(value: String) -> Result<String, String> {
    match value.strip_prefix("Error: ") {
        Some(message) => Err(message.to_string()),
        None => Ok(value),
    }
}

/// `Ok`-only calls whose success payload is the literal `"OK"`.
fn parse_unit(value: String) -> Result<(), String> {
    parse(value).map(|_| ())
}

fn parse_list<T: for<'de> Deserialize<'de>>(json: String) -> Vec<T> {
    // An "Error: ..." reply or bad JSON is logged, not silently shown as "empty".
    serde_json::from_str(&json).unwrap_or_else(|e| {
        let head: String = if json.starts_with("Error") { json.chars().take(120).collect() } else { String::new() };
        log::warn!("core list reply unparsable ({e}) {head}");
        Vec::new()
    })
}

/// Single-object replies: a bad shape is logged, then shown as the default.
fn parse_or_default<T: for<'de> Deserialize<'de> + Default>(json: String, what: &str) -> T {
    serde_json::from_str(&json).unwrap_or_else(|e| {
        let head: String = json.chars().take(120).collect();
        log::warn!("core {what} reply unparsable ({e}) {head}");
        T::default()
    })
}

/// Result of a send/edit/delete: the stable message id plus the immediate
/// send state (`"sent"` or `"pending"` — pending is retried in the background
/// and later corrected by a `status` event).
#[derive(Debug, Clone, Deserialize)]
pub struct SendReceipt {
    pub message_id: String,
    pub status: String,
}

fn parse_receipt(value: String) -> Result<SendReceipt, String> {
    let json = parse(value)?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

/// One device belonging to *my own* identity (this one, or a linked sibling).
#[derive(Debug, Clone, Deserialize)]
pub struct LinkedDevice {
    pub device_fingerprint: String,
    pub device_name: String,
    pub is_active: bool,
    pub is_this_device: bool,
}

/// This device's own network health, as shown in the header bar.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OwnStatus {
    #[serde(default)]
    pub connected_peers: u32,
    #[serde(default)]
    pub listening: bool,
    #[serde(default)]
    pub tor_enabled: bool,
    #[serde(default)]
    pub tor_status: String,
    #[serde(default)]
    pub node_mode: bool,
}

// --- identity / lifecycle ---

/// `storage_key`: the vault's `skipped_key`. The database is encrypted under it.
pub fn init_database(dir: &str, storage_key: &[u8; 32]) -> bool {
    api::init_database(dir, storage_key)
}

pub fn has_stored_identity() -> bool {
    api::has_stored_identity()
}

pub fn create_identity(device_name: &str) -> Result<String, String> {
    parse(api::create_identity(device_name))
}

pub fn take_pending_secret_bundle() -> Vec<u8> {
    api::get_pending_secret_bundle()
}

pub fn load_secret_bundle(bundle: &[u8]) -> bool {
    api::load_secret_bundle(bundle)
}

pub fn set_history_key(key: &[u8]) -> bool {
    api::set_history_key(key)
}

pub fn set_skipped_key_encryption_key(key: &[u8]) -> bool {
    api::set_skipped_key_encryption_key(key)
}

pub fn identity_code() -> Result<String, String> {
    parse(api::get_identity_code())
}

pub fn identity_short_code() -> Result<String, String> {
    parse(api::get_identity_short_code())
}

pub fn own_identity_id() -> Result<String, String> {
    parse(api::get_own_identity_id())
}

pub fn export_recovery(passphrase: &str) -> Vec<u8> {
    api::export_recovery(passphrase)
}

/// Restores an identity from a recovery file. Same contract as
/// `create_identity`: on success the secret bundle is waiting in
/// `take_pending_secret_bundle` and must be persisted immediately.
///
/// Deliberately slow — the core stretches the passphrase with Argon2id — so
/// call it off the main thread.
pub fn import_recovery(
    file_bytes: &[u8],
    passphrase: &str,
    device_name: &str,
) -> Result<String, String> {
    parse(api::import_recovery(file_bytes, passphrase, device_name))
}

// --- network ---

pub fn start_network(node_mode: bool, tor_enabled: bool) -> Result<String, String> {
    parse(api::start_network(node_mode, tor_enabled))
}

pub fn set_node_mode(enabled: bool) {
    api::set_node_mode(enabled);
}

pub fn set_history_storage_limit_bytes(bytes: u64) {
    api::set_history_storage_limit_bytes(bytes);
}

pub fn node_address() -> String {
    api::get_node_address()
}

pub fn own_status() -> OwnStatus {
    parse_or_default(api::own_connection_status(), "own status")
}

pub fn wait_for_network_activity(timeout_ms: u64) {
    api::wait_for_network_activity(timeout_ms);
}

pub fn poll_network() -> Vec<String> {
    api::poll_network()
}

pub fn notify_network_changed() {
    api::notify_network_changed();
}

/// R-06: drops the core's keepalive ladder and radio-window throttling when
/// the platform says this app is idle (bkz. `P2PCore::set_power_save`).
/// Android feeds this from the app lifecycle; the desktop client had nothing,
/// so it burned radio time like a phone in power-save-off mode.
pub fn set_power_save(enabled: bool) {
    api::set_power_save(enabled);
}

/// R-06: metered (cellular) link or not — the core coalesces its radio
/// windows differently there (bkz. `P2PCore::set_metered`).
pub fn set_metered(metered: bool) {
    api::set_metered(metered);
}

pub fn add_known_relay_address(multiaddr: &str) -> Result<(), String> {
    parse_unit(api::add_known_relay_address(multiaddr))
}

pub fn retry_all_pending_now() {
    api::retry_all_pending_now();
}

// --- pairing / multi-device ---

pub fn generate_qr_packet(rendezvous_node: &str) -> Vec<u8> {
    api::generate_qr_packet(rendezvous_node)
}

pub fn manual_add_code(rendezvous_node: &str) -> String {
    api::get_manual_add_code(rendezvous_node)
}

/// A newly paired contact, as reported by the QR / manual-code flow. The
/// pairing handshake is still in flight when this returns — see the core's
/// `process_qr_packet` note.
#[derive(Debug, Clone, Deserialize)]
pub struct PairedPeer {
    pub identity_id: String,
    pub device_fingerprint: String,
    pub device_name: String,
}

pub fn process_manual_entry(text: &str) -> Result<PairedPeer, String> {
    let json = parse(api::process_manual_entry(text))?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

pub fn process_qr_packet(data: &[u8]) -> Result<PairedPeer, String> {
    let json = parse(api::process_qr_packet(data))?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

/// The device-link QR this (secondary) device shows for the primary to scan.
/// Empty until the swarm has a listen address — poll it.
pub fn build_device_link_request() -> Vec<u8> {
    api::build_device_link_request()
}

/// The short code this device and the approving device both show while
/// linking. Empty for bytes that are not a link request.
pub fn device_link_code(request: &[u8]) -> String {
    api::device_link_code(request)
}

/// True once a primary device has adopted us into its identity.
pub fn is_secondary_device() -> bool {
    api::is_secondary_device()
}

pub fn list_linked_devices() -> Vec<LinkedDevice> {
    parse_list(api::list_linked_devices())
}

pub fn revoke_linked_device(fingerprint: &str) -> Result<(), String> {
    parse_unit(api::revoke_linked_device(fingerprint))
}

pub fn sync_read_state(peer_fingerprint: &str, group_id: &str, read_at_ms: u64) {
    api::sync_read_state(peer_fingerprint, group_id, read_at_ms);
}

// --- contacts ---

pub fn list_contacts() -> Vec<ContactSummary> {
    let mut contacts: Vec<ContactSummary> = parse_list(api::list_contacts());
    // Two contacts with the same name get the head of their identity id, so
    // the lists and the chat header tell them apart. Display only.
    let key = |name: &str| name.trim().to_lowercase();
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for contact in &contacts {
        *counts.entry(key(&contact.display_name)).or_default() += 1;
    }
    for contact in &mut contacts {
        if counts[&key(&contact.display_name)] > 1 {
            let head: String = contact.identity_id.chars().take(6).collect();
            contact.display_name = format!("{} ({})", contact.display_name, head);
        }
    }
    contacts
}

pub fn clear_chat_history(contact_id: &str) -> Result<(), String> {
    parse_unit(api::clear_chat_history(contact_id))
}

pub fn delete_contact(contact_id: &str) -> Result<(), String> {
    parse_unit(api::delete_contact(contact_id))
}

pub fn revoke_contact_device(contact_id: &str, fingerprint: &str) -> Result<(), String> {
    parse_unit(api::revoke_contact_device(contact_id, fingerprint))
}

/// Kullanıcı kararı (2026-08-27): kişiyi kalıcı olarak engeller. `revoke`
/// tek bir cihazı kapatır ve kişi yeni bir cihazla geri gelebilir; engel
/// kimliği hedefler ve yalnızca yüz yüze yeniden eşleşmeyle kalkar.
pub fn block_identity(identity_id: &str) -> Result<(), String> {
    parse_unit(api::block_identity(identity_id))
}

pub fn unblock_identity(identity_id: &str) {
    api::unblock_identity(identity_id);
}

pub fn list_blocked_identities() -> Vec<String> {
    parse_list(api::list_blocked_identities())
}

/// Karşılaştırılacak güvenlik kodu (bkz. `P2PCore::contact_safety_code`).
pub fn contact_safety_code(identity_id: &str) -> String {
    api::contact_safety_code(identity_id)
}

/// Grup üzerinden tanışılmış bir kişiye tam güven verir — "doğrulanmadı"
/// işaretini kaldırır.
pub fn trust_contact(contact_id: &str) -> Result<(), String> {
    parse_unit(api::trust_contact(contact_id))
}

/// Grup yöneticiliğini başka bir üyeye devreder.
pub fn transfer_group_founder(group_id: &str, new_founder_identity_id: &str) -> Result<(), String> {
    parse_unit(api::transfer_group_founder(group_id, new_founder_identity_id))
}

/// This device's account name — what contacts see. Empty when there is no
/// identity yet.
pub fn display_name() -> String {
    api::get_display_name()
}

/// Sends `AccountDeleted` to every contact and sibling; devices notified, or
/// `-1` on failure.
pub fn delete_account() -> i64 {
    api::delete_account()
}

pub fn account_deletion_pending() -> i64 {
    api::account_deletion_pending()
}

/// Renames the account and notifies every known contact automatically
/// (see the core's `set_display_name`). Contacts that are offline pick the
/// change up when they come back, so this returning `Ok` means "queued and
/// encrypted", not "everyone has seen it".
pub fn set_display_name(name: &str) -> Result<(), String> {
    parse_unit(api::set_display_name(name))
}

pub fn set_own_profile_picture(jpeg: Option<Vec<u8>>) -> Result<(), String> {
    parse_unit(api::set_own_profile_picture(jpeg))
}

// --- device-change alerts (TOFU, spec 2.2) ---

pub fn list_pending_device_alerts() -> Vec<DeviceAlertInfo> {
    parse_list(api::list_pending_device_alerts())
}

pub fn accept_device_alert(fingerprint: &str) -> bool {
    api::accept_device_alert(fingerprint)
}

pub fn reject_device_alert(fingerprint: &str) {
    api::reject_device_alert(fingerprint);
}

// --- 1:1 messaging ---

pub fn send_message(
    target: &str,
    text: &str,
    reply_to_id: Option<String>,
    reply_preview: Option<String>,
) -> Result<SendReceipt, String> {
    parse_receipt(api::send_message(target, text, reply_to_id, reply_preview))
}

pub fn edit_message(target: &str, message_id: &str, new_text: &str) -> Result<SendReceipt, String> {
    parse_receipt(api::edit_message(target, message_id, new_text))
}

/// Returns the message's new reaction summary (e.g. "😂2 👍").
pub fn react_to_message(target: &str, message_id: &str, emoji: &str) -> Result<String, String> {
    parse(api::react_to_message(target, message_id, emoji))
}

pub fn react_to_group_message(group_id: &str, local_id: &str, emoji: &str) -> Result<String, String> {
    parse(api::react_to_group_message(group_id, local_id, emoji))
}

pub fn delete_message(target: &str, message_id: &str) -> Result<SendReceipt, String> {
    parse_receipt(api::delete_message(target, message_id))
}

pub fn has_active_session(fingerprint: &str) -> bool {
    api::has_active_session(fingerprint)
}

pub fn is_peer_connected(fingerprint: &str) -> bool {
    api::is_peer_connected(fingerprint)
}

pub fn ensure_handshake(fingerprint: &str) {
    api::ensure_handshake(fingerprint);
}

pub fn send_typing_indicator(target: &str, is_typing: bool) {
    api::send_typing_indicator(target, is_typing);
}

pub fn send_seen_receipt(target: &str, message_id: &str, group_local_id: Option<String>) {
    api::send_seen_receipt(target, message_id, group_local_id);
}

pub fn message_history(fingerprint: &str, limit: u32) -> Vec<ArchivedMessage> {
    parse_list(api::get_message_history(fingerprint, limit))
}

pub fn message_history_before(
    fingerprint: &str,
    before_timestamp: i64,
    limit: u32,
) -> Vec<ArchivedMessage> {
    parse_list(api::get_message_history_before(
        fingerprint,
        before_timestamp,
        limit,
    ))
}

pub fn request_history_sync(fingerprint: &str, limit: u32) {
    api::request_history_sync(fingerprint, limit);
}

// --- groups ---

pub fn list_groups() -> Vec<GroupSummary> {
    parse_list(api::list_groups())
}

pub fn create_group(name: &str) -> Result<String, String> {
    parse(api::create_group(name))
}

pub fn invite_to_group(group_id: &str, identity_id: &str) -> bool {
    api::invite_to_group(group_id, identity_id)
}

pub fn remove_from_group(group_id: &str, identity_id: &str) -> bool {
    api::remove_from_group(group_id, identity_id)
}

pub fn delete_group(group_id: &str) -> Result<(), String> {
    parse_unit(api::delete_group(group_id))
}

pub fn leave_group(group_id: &str) -> Result<(), String> {
    parse_unit(api::leave_group(group_id))
}

/// The founder re-sends the current group state to every member — the fix
/// for a member whose group update never arrived. The core rejects it for
/// anyone but the founder.
pub fn resend_group_to_all(group_id: &str) -> Result<(), String> {
    parse_unit(api::resend_group_to_all(group_id))
}

pub fn set_group_profile_picture(group_id: &str, jpeg: Option<Vec<u8>>) -> Result<(), String> {
    parse_unit(api::set_group_profile_picture(group_id, jpeg))
}

/// Returns the `group_message_local_id` that ties every per-member fan-out
/// copy back to a single bubble.
pub fn send_group_message(
    group_id: &str,
    text: &str,
    reply_to_id: Option<String>,
    reply_preview: Option<String>,
    reply_sender_identity_id: Option<String>,
    mentions: Vec<String>,
) -> Result<String, String> {
    parse(api::send_group_message(
        group_id,
        text,
        reply_to_id,
        reply_preview,
        reply_sender_identity_id,
        mentions,
    ))
}

pub fn edit_group_message(
    group_id: &str,
    local_id: &str,
    new_text: &str,
) -> Result<(), String> {
    parse_unit(api::edit_group_message(group_id, local_id, new_text))
}

pub fn delete_group_message(group_id: &str, local_id: &str) -> Result<(), String> {
    parse_unit(api::delete_group_message(group_id, local_id))
}

pub fn send_group_typing_indicator(group_id: &str, is_typing: bool) {
    api::send_group_typing_indicator(group_id, is_typing);
}

pub fn group_message_history(group_id: &str, limit: u32) -> Vec<ArchivedMessage> {
    parse_list(api::get_group_message_history(group_id, limit))
}

pub fn group_message_history_before(
    group_id: &str,
    before_timestamp: i64,
    limit: u32,
) -> Vec<ArchivedMessage> {
    parse_list(api::get_group_message_history_before(
        group_id,
        before_timestamp,
        limit,
    ))
}

// --- attachments ---

// Caption and reply are wired in the UI (`ui::chat` attachment send paths);
// the core takes them as optional arguments.
pub fn prepare_and_send_file(
    target: &str,
    source_path: &str,
    file_name: &str,
    mime_type: &str,
    preview_jpeg: Option<Vec<u8>>,
    duration_ms: Option<u32>,
    caption: String,
    reply_to_message_id: Option<String>,
    reply_to_preview: Option<String>,
) -> Result<SendReceipt, String> {
    parse_receipt(api::prepare_and_send_file(
        target,
        source_path,
        file_name,
        mime_type,
        preview_jpeg,
        duration_ms,
        caption,
        reply_to_message_id,
        reply_to_preview,
    ))
}

/// Lossless JPEG XL of an RGBA image (see `util::prepare_outgoing`).
pub fn encode_jxl_lossless(rgba: &mut [u8], width: u32, height: u32, has_alpha: bool, out_path: &str) -> Result<(), String> {
    api::encode_jxl_lossless(rgba, width, height, has_alpha, out_path)
}

pub fn prepare_and_send_group_file(
    group_id: &str,
    source_path: &str,
    file_name: &str,
    mime_type: &str,
    preview_jpeg: Option<Vec<u8>>,
    duration_ms: Option<u32>,
    caption: String,
    reply_to_message_id: Option<String>,
    reply_to_preview: Option<String>,
    reply_to_sender_identity_id: Option<String>,
) -> Result<String, String> {
    parse(api::prepare_and_send_group_file(
        group_id,
        source_path,
        file_name,
        mime_type,
        preview_jpeg,
        duration_ms,
        caption,
        reply_to_message_id,
        reply_to_preview,
        reply_to_sender_identity_id,
    ))
}

/// Starts a download. A non-`Ok` return means no `file_*` event will ever
/// arrive for this file — the caller must not leave the row spinning.
pub fn download_file(file_id: &str, peer_fingerprint: &str) -> Result<(), String> {
    parse_unit(api::download_file(file_id, peer_fingerprint))
}

pub fn list_attachments(peer_fingerprint: &str) -> Vec<AttachmentSummary> {
    parse_list(api::list_attachments(peer_fingerprint))
}

/// Without the preview images, for the chat list.
pub fn list_attachments_brief(peer_fingerprint: &str) -> Vec<AttachmentSummary> {
    parse_list(api::list_attachments_brief(peer_fingerprint))
}

pub fn list_group_attachments_brief(group_id: &str) -> Vec<AttachmentSummary> {
    parse_list(api::list_group_attachments_brief(group_id))
}

pub fn list_group_attachments(group_id: &str) -> Vec<AttachmentSummary> {
    parse_list(api::list_group_attachments(group_id))
}

/// The `limit` newest attachments OLDER than `before_ms`, oldest first — the
/// paging counterpart of `list_attachments` (the core keeps the files in
/// their own table, so scrolling up needs a cursor of its own).
pub fn list_attachments_before(
    peer_fingerprint: &str,
    before_ms: u64,
    limit: usize,
) -> Vec<AttachmentSummary> {
    parse_list(api::list_attachments_before(peer_fingerprint, before_ms, limit))
}

/// The group counterpart of `list_attachments_before`.
pub fn list_group_attachments_before(
    group_id: &str,
    before_ms: u64,
    limit: usize,
) -> Vec<AttachmentSummary> {
    parse_list(api::list_group_attachments_before(group_id, before_ms, limit))
}

/// Decrypts a completed attachment to a plaintext file and returns its path.
/// Slow for large files — call it off the GTK main thread.
pub fn attachment_plaintext_path(file_id: &str) -> Result<String, String> {
    parse(api::get_attachment_plaintext_path(file_id))
}

// --- pending (unacknowledged) messages ---

pub fn list_pending_messages() -> Vec<PendingMessageSummary> {
    parse_list(api::list_pending_messages())
}

pub fn cancel_pending_message(message_id: &str) -> bool {
    api::cancel_pending_message(message_id)
}

pub fn retry_pending_message_now(message_id: &str) -> bool {
    api::retry_pending_message_now(message_id)
}

// --- sunucu (store-and-forward) seçeneği ---
//
// bkz. çekirdeğin `server_client` modülü. Rölelerden FARKLI: bir röle hiçbir
// şey saklamaz, sadece iki taraf da o anda bağlıyken canlı bir devre kurar;
// sunucu ise alıcı çevrimdışıyken zarfı diske yazar ve geri döndüğünde
// teslim eder. İçeriği okuyamaz — zarflar uçtan uca şifreli ve ikinci kez
// mühürlü.

#[derive(Debug, Clone, Deserialize)]
pub struct ServerEntry {
    pub server_id: String,
    pub address: String,
    #[serde(default)]
    pub name: String,
    pub route_messages: bool,
    pub store_history: bool,
    pub connected: bool,
    pub enrolled: bool,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// Davet kodundan (`typeon-server:<multiaddr>#<jeton>`) bir sunucu ekler.
pub fn add_server(invite_code: &str) -> Result<(), String> {
    let out = api::add_server(invite_code);
    if let Some(rest) = out.strip_prefix("Error: ") {
        Err(rest.to_string())
    } else {
        Ok(())
    }
}

pub fn remove_server(server_id: &str) -> Result<(), String> {
    parse_unit(api::remove_server(server_id))
}

pub fn list_servers() -> Vec<ServerEntry> {
    parse_list(api::list_servers())
}

pub fn set_server_routing(server_id: &str, enabled: bool) -> Result<(), String> {
    parse_unit(api::set_server_routing(server_id, enabled))
}

/// Geçmişi sunucuda saklama — mesaj yönlendirmeden AYRI ve varsayılan
/// KAPALI. Arşiv gerçek bir yedektir ve ratchet'in aksine ileri-gizli
/// DEĞİLDİR: kök arşiv anahtarı bir gün sızarsa o ana kadar yüklenmiş TÜM
/// geçmiş okunur.
pub fn set_server_history(server_id: &str, enabled: bool) -> Result<(), String> {
    parse_unit(api::set_server_history(server_id, enabled))
}

/// Kök arşiv anahtarını (ARK) çekirdeğe yükler — bkz. `secrets.rs`
/// (`Vault.archive_root_key`). `set_history_key` ile aynı desen ama bu
/// anahtar CİHAZA değil KİMLİĞE aittir.
pub fn set_archive_root_key(key: &[u8]) -> bool {
    api::set_archive_root_key(key)
}

/// One chat's older history from the server archive, for a "fetch history
/// from server" button. Scrolling never asks the server. `chat_key`: the peer
/// device fingerprint, or the group id; `before_timestamp`: the oldest message
/// on screen (ms), 0 = from the newest.
pub fn fetch_server_history(chat_key: &str, is_group: bool, before_timestamp: i64) -> Result<(), String> {
    parse_unit(api::fetch_server_history(chat_key, is_group, before_timestamp))
}

/// Downloads the entire server-side archive — for a device set up from a
/// recovery file or by linking. Returns how many conversations were asked for.
pub fn restore_server_history() -> Result<u32, String> {
    let out = api::restore_server_history();
    if let Some(rest) = out.strip_prefix("Error: ") {
        return Err(rest.to_string());
    }
    out.strip_prefix("OK:")
        .and_then(|n| n.trim().parse().ok())
        .ok_or_else(|| format!("unexpected reply: {out}"))
}

/// The archive root key the core currently holds, if any.
///
/// Needed because the key can arrive *later*, from a sibling device over the
/// encrypted sync channel, long after the vault passphrase is gone from
/// memory — see `secrets::store_archive_key`.
pub fn archive_root_key() -> Option<[u8; 32]> {
    api::archive_root_key().try_into().ok()
}

// --- calls (see `call.rs` in the core) ---

/// Media kinds on the wire, shared with Android `CallMedia`.
pub const KIND_AUDIO: u8 = 1;
pub const KIND_VIDEO: u8 = 2;
pub const KIND_STATE: u8 = 4;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CallParticipant {
    #[serde(default)]
    pub fp: String,
    /// Canonical contact key — matches a contact's active device fingerprint.
    #[serde(default)]
    pub peer: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub joined: bool,
    #[serde(default)]
    pub slot: Option<u8>,
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub video_off: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CallMediaStats {
    #[serde(default)]
    pub direct_links: u32,
    #[serde(default)]
    pub relay_links: u32,
    #[serde(default)]
    pub via_direct: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CallState {
    /// "idle", "outgoing", "incoming" or "active".
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub call_id: String,
    #[serde(default)]
    pub video: bool,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub connected_at: u64,
    #[serde(default)]
    pub now: u64,
    /// Why the last call ended (idle only): "rejected", "busy", "no_answer", ...
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub participants: Vec<CallParticipant>,
    #[serde(default)]
    pub media: Option<CallMediaStats>,
}

/// Rings a 1:1 peer (chat key / device fingerprint). Returns the call id.
pub fn start_call(peer: &str, video: bool) -> Result<String, String> {
    parse(api::start_call(peer, video))
}

pub fn start_group_call(group_id: &str, video: bool) -> Result<String, String> {
    parse(api::start_group_call(group_id, video))
}

pub fn accept_call() -> bool {
    api::accept_call()
}

pub fn end_call() {
    api::end_call()
}

pub fn call_state() -> CallState {
    parse_or_default(api::call_state(), "call state")
}

pub fn call_send(kind: u8, payload: &[u8]) -> bool {
    api::call_send(kind, payload)
}

/// `[kind][slot][payload]`, `None` on timeout.
pub fn call_recv(timeout_ms: u64) -> Option<Vec<u8>> {
    api::call_recv(timeout_ms)
}

pub fn call_request_keyframe(slot: u8) {
    api::call_request_keyframe(slot)
}

pub fn call_take_keyframe_request() -> bool {
    api::call_take_keyframe_request()
}

/// Send queue depth, 1 = 100 ms.
pub fn call_backlog() -> usize {
    api::call_backlog()
}

// --- shared whiteboard (one board per chat: `group_id` "" = the 1:1 with `peer`) ---

/// New stroke ids, 8 bytes each.
pub fn whiteboard_add_stroke(peer: &str, group_id: &str, page: u8, shade: u8, width: u8, points: &[u8]) -> Result<Vec<u8>, String> {
    let hex = parse(api::whiteboard_add_stroke(peer, group_id, page, shade, width, points))?;
    // Not `str` slicing: a non-ASCII reply would panic on a char boundary.
    hex::decode(&hex).map_err(|e| e.to_string())
}

pub fn whiteboard_erase(peer: &str, group_id: &str, ids: &[u8]) -> Result<(), String> {
    parse_unit(api::whiteboard_erase(peer, group_id, ids))
}

pub fn whiteboard_open(peer: &str, group_id: &str) {
    api::whiteboard_open(peer, group_id)
}

pub fn whiteboard_mark_read(peer: &str, group_id: &str, page: u8) {
    api::whiteboard_mark_read(peer, group_id, page)
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WhiteboardParticipant {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WhiteboardInfo {
    #[serde(default)]
    pub pages: u32,
    /// A bit per page.
    #[serde(default)]
    pub unread: u32,
    #[serde(default)]
    pub me: Option<usize>,
    #[serde(default)]
    pub participants: Vec<WhiteboardParticipant>,
}

pub fn whiteboard_info(peer: &str, group_id: &str) -> Result<WhiteboardInfo, String> {
    let json = parse(api::whiteboard_info(peer, group_id))?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

/// Raw page blob, see `api::whiteboard_page`.
pub fn whiteboard_page(peer: &str, group_id: &str, page: u8) -> Vec<u8> {
    api::whiteboard_page(peer, group_id, page)
}

pub fn whiteboard_tick() {
    api::whiteboard_tick()
}
