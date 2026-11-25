//! Pure-Rust API facade for callers that do not go through JNI.
//! This module provides one-to-one counterparts of the JNI exports at the end of the file (`Java_com_p2p_messenger_P2PLib_*`),
//! stripped of JVM-specific types (JNIEnv / JString / JByteArray). The same `catch_panic` + `RUNTIME.enter()` + `core_lock()` order
//! is kept, and so are the return formats: "Error: ..." prefixed error strings, JSON arrays, and `{"message_id":..,"status":..}` objects.
//! Reason: the Linux desktop client (see the `Linux/` directory at the repository root) uses exactly the same core: the same crypto,
//! ratchet, database schema and network protocol. Writing the protocol a second time would let the two apps drift apart silently.
//! Nothing changes for Android: this module is purely an addition. Most JNI exports go directly to `P2PCore`. A few (account, linking,
//! files, messages) call the `api::*` functions below.
//! The Kotlin `P2PLib` documentation (parameter meanings, which calls must not run on the main thread, return formats) applies to every
//! function here as well, and is not repeated.

use crate::{catch_panic, core_lock, RUNTIME};

/// Converts the JNI triple `Ok(Ok(v)) / Ok(Err(e)) / Err(panic)` into one string. Both error paths become the `"Error: ..."` format.
/// See `Java_..._createIdentity` and its siblings, which all repeat this pattern.
fn string_result(result: Result<Result<String, String>, String>) -> String {
    match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: panic: {}", e), // told apart from a declared failure
    }
}

/// For core calls that return `Result<(), String>`: `"OK"` on success.
fn ok_result(result: Result<Result<(), String>, String>) -> String {
    match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: panic: {}", e), // told apart from a declared failure
    }
}

// --- Identity and device ---

/// `storage_key`: the 32-byte local storage key the database is encrypted
/// under. The skipped-key cache has its own key (`set_skipped_key_encryption_key`).
pub fn init_database(files_dir: &str, storage_key: &[u8]) -> bool {
    let key: [u8; 32] = match storage_key.try_into() {
        Ok(k) => k,
        Err(_) => {
            log::error!("init_database: storage key is {} bytes, not 32", storage_key.len());
            return false;
        }
    };
    let key = zeroize::Zeroizing::new(key);
    let path = files_dir.to_string();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.init_db(&path, &key).map_err(|e| e.to_string())
    });
    match result {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            log::error!("init_database failed: {}", e);
            false
        }
        Err(e) => {
            log::error!("init_database panicked: {}", e);
            false
        }
    }
}

pub fn has_stored_identity() -> bool {
    catch_panic(|| crate::core_lock_read().identity.is_some()).unwrap_or(false)
}

pub fn create_identity(device_name: &str) -> String {
    let name = device_name.to_string();
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().create_identity(name)
    }))
}

/// Not a destructive read, see JNI `getPendingSecretBundle`.
pub fn get_pending_secret_bundle() -> Vec<u8> {
    catch_panic(|| crate::core_lock_read().pending_secret_bundle.clone().unwrap_or_default()).unwrap_or_default()
}

/// Wipes the pending secret bundle once the caller has stored it (see `get_pending_secret_bundle`).
pub fn clear_pending_secret_bundle() {
    let _ = catch_panic(|| {
        let mut core = core_lock();
        zeroize::Zeroize::zeroize(&mut core.pending_secret_bundle);
        core.pending_secret_bundle = None;
    });
}

pub fn load_secret_bundle(bundle_bytes: &[u8]) -> bool {
    // Every secret key of the device: wiped when dropped.
    let raw = zeroize::Zeroizing::new(bundle_bytes.to_vec());
    matches!(
        catch_panic(move || {
            let mut core = core_lock();
            let loaded = core.load_secret_bundle(&raw);
            if loaded.is_ok() {
                // Wiped like the JNI twin, not only dropped.
                zeroize::Zeroize::zeroize(&mut core.pending_secret_bundle);
                core.pending_secret_bundle = None;
            }
            loaded
        }),
        Ok(Ok(_))
    )
}

pub fn get_identity_code() -> String {
    string_result(catch_panic(|| crate::core_lock_read().identity_code()))
}

pub fn get_identity_short_code() -> String {
    string_result(catch_panic(|| crate::core_lock_read().identity_short_code()))
}

pub fn get_own_identity_id() -> String {
    string_result(catch_panic(|| crate::core_lock_read().own_identity_id()))
}

/// See Kotlin `setHistoryKey`. A key that is not 32 bytes is refused silently.
pub fn set_history_key(key_bytes: &[u8]) -> bool {
    let key: [u8; 32] = match key_bytes.try_into() {
        Ok(k) => k,
        Err(_) => return false,
    };
    catch_panic(move || {
        core_lock().history_key = Some(key);
    })
    .is_ok()
}

pub fn set_skipped_key_encryption_key(key_bytes: &[u8]) -> bool {
    let key: [u8; 32] = match key_bytes.try_into() {
        Ok(k) => k,
        Err(_) => return false,
    };
    catch_panic(move || {
        core_lock().install_skipped_key(key);
    })
    .is_ok()
}

// --- Network ---

pub fn start_network(node_mode: bool, tor_enabled: bool) -> String {
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.start_network(node_mode, tor_enabled)
    }))
}

pub fn set_node_mode(enabled: bool) {
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_node_mode(enabled);
    });
}

pub fn set_history_storage_limit_bytes(bytes: u64) {
    // See JNI `setHistoryStorageLimitBytes`. 0 means a failed preference read, never a real choice: as a limit it would delete every stored
    // attachment. A `u64` has no negative values, so 0 is the only harmful value.
    if bytes == 0 {
        return;
    }
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_history_storage_limit_bytes(bytes);
    });
}

/// See JNI `setPowerSave`. Enabled while the screen is off or the app is in the background (see `P2PCore::set_power_save`).
pub fn set_power_save(enabled: bool) {
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_power_save(enabled);
    });
}

/// See JNI `setMeteredNetwork`. A metered (cellular) network. Used to combine radio windows (see `P2PCore::set_metered`).
pub fn set_metered(metered: bool) {
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_metered(metered);
    });
}

pub fn get_node_address() -> String {
    catch_panic(|| crate::core_lock_read().get_node_address().unwrap_or_default()).unwrap_or_default()
}

pub fn own_connection_status() -> String {
    catch_panic(|| crate::core_lock_read().own_connection_status().to_string())
        .unwrap_or_else(|_| "{}".to_string())
}

/// See Kotlin `pollNetwork`. Returns a JSON list of the events resolved in each turn.
pub fn poll_network() -> Vec<String> {
    catch_panic(|| {
        let _guard = RUNTIME.enter();
        crate::CORE_DIRTY.store(false, std::sync::atomic::Ordering::SeqCst);
        let started = std::time::Instant::now();
        let out = crate::core_lock_poll().poll_events();
        let took = started.elapsed().as_millis();
        if took > 5_000 {
            log::warn!("poll_events took {} ms", took);
        }
        out
    })
    .unwrap_or_default()
}

/// See core_lock.rs `wait_for_network_activity`. The poll loop calls it instead of sleeping for a fixed interval.
pub fn wait_for_network_activity(timeout_ms: u64) {
    let _ = catch_panic(|| crate::wait_for_network_activity(timeout_ms));
}

pub fn notify_network_changed() {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        core_lock().reconnect_all_known_now();
    });
}

pub fn add_known_relay_address(multiaddr: &str) -> String {
    let addr = multiaddr.to_string();
    ok_result(catch_panic(move || core_lock().add_known_relay_address(&addr)))
}

// --- QR and manual pairing ---

pub fn generate_qr_packet(rendezvous_node: &str) -> Vec<u8> {
    let node = rendezvous_node.to_string();
    match catch_panic(move || core_lock().generate_qr_packet(node)) {
        Ok(Ok(bytes)) => bytes,
        _ => Vec::new(),
    }
}

pub fn get_manual_add_code(rendezvous_node: &str) -> String {
    let node = rendezvous_node.to_string();
    match catch_panic(move || core_lock().generate_manual_add_code(&node)) {
        Ok(Ok(code)) => code,
        _ => String::new(),
    }
}

/// See Kotlin `processQrPacket`. On success returns
/// `{"identity_id":..,"device_fingerprint":..,"device_name":..}`.
pub fn process_qr_packet(data: &[u8]) -> String {
    let raw = data.to_vec();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().process_qr_packet(&raw)
    });
    pairing_result(result)
}

/// see JNI `peekContactQr` — the confirm step's data; changes nothing.
pub fn peek_contact_qr(data: &[u8]) -> String {
    let raw = data.to_vec();
    string_result(catch_panic(move || crate::core_lock_read().peek_qr_packet(&raw).map(|v| v.to_string())))
}

pub fn process_manual_entry(text: &str) -> String {
    let text = text.to_string();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().process_manual_entry(&text)
    });
    pairing_result(result)
}

/// The shared return format of `process_qr_packet` and `process_manual_entry`.
fn pairing_result(result: Result<Result<(String, String, String), String>, String>) -> String {
    match result {
        Ok(Ok((identity_id, device_fingerprint, device_name))) => serde_json::json!({
            "identity_id": identity_id,
            "device_fingerprint": device_fingerprint,
            "device_name": device_name
        })
        .to_string(),
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    }
}

// --- Multi-device ---

/// The link QR is no longer shown: a grant that comes now is refused.
pub fn close_device_link_window() {
    let _ = catch_panic(|| core_lock().set_link_request_open_until(0));
}

pub fn build_device_link_request() -> Vec<u8> {
    match catch_panic(|| core_lock().build_device_link_request()) {
        Ok(Ok(bytes)) => bytes,
        _ => Vec::new(),
    }
}

/// The compare code of a link QR (see `device_link_code`); empty if invalid.
pub fn device_link_code(data: &[u8]) -> String {
    crate::device_link_code(data)
}

// no `approve_device_link` or `import_recovery` here. Desktops are secondary
// devices only: they never add devices or restore a whole account (owner rule).

pub fn list_linked_devices() -> String {
    catch_panic(|| serde_json::Value::Array(crate::core_lock_read().list_linked_devices()).to_string())
        .unwrap_or_else(|_| "[]".to_string())
}

pub fn is_secondary_device() -> bool {
    catch_panic(|| crate::core_lock_read().own_device_add.is_some()).unwrap_or(false)
}

pub fn revoke_linked_device(device_fingerprint: &str) -> String {
    let fp = device_fingerprint.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().revoke_own_linked_device(&fp)
    }))
}

pub fn sync_read_state(peer_device_fingerprint: &str, group_id: &str, read_at_ms: u64) {
    let peer = peer_device_fingerprint.to_string();
    let gid = group_id.to_string();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().sync_read_state(&peer, &gid, read_at_ms);
    });
}

/// Disappearing messages on screen start counting down (see `start_expiry_on_screen`). Local only.
pub fn start_disappear_countdown(peer_device_fingerprint: &str, group_id: &str) {
    let peer = peer_device_fingerprint.to_string();
    let gid = group_id.to_string();
    let _ = catch_panic(move || crate::core_lock_read().start_expiry_on_screen(&peer, &gid));
}

/// The chat's disappearing mode in seconds, 0 = off (see `disappear_mode`). `peer_device_fingerprint` for 1:1, `group_id` for a group.
pub fn disappear_mode(peer_device_fingerprint: &str, group_id: &str) -> u32 {
    let (peer, gid) = (peer_device_fingerprint.to_string(), group_id.to_string());
    catch_panic(move || crate::core_lock_read().disappear_mode(&peer, &gid).unwrap_or(0)).unwrap_or(0)
}

/// Turns the chat's disappearing mode on (`secs`) or off (0).
pub fn set_disappear_mode(peer_device_fingerprint: &str, group_id: &str, secs: u32) {
    let (peer, gid) = (peer_device_fingerprint.to_string(), group_id.to_string());
    let _ = catch_panic(move || crate::core_lock_read().set_disappear_mode(&peer, &gid, secs));
}

// --- Device change warnings ---

pub fn list_pending_device_alerts() -> String {
    json_list(catch_panic(|| {
        serde_json::to_string(&crate::core_lock_read().list_pending_device_alerts())
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

/// See `P2PCore::block_identity`. A permanent block.
pub fn block_identity(identity_id: &str) -> String {
    match catch_panic(|| core_lock().block_identity(identity_id)) {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) | Err(e) => format!("Error: {}", e),
    }
}

/// see `P2PCore::unblock_identity`.
pub fn unblock_identity(identity_id: &str) {
    let _ = catch_panic(|| core_lock().unblock_identity(identity_id));
}

/// Blocked identities as a JSON array.
pub fn list_blocked_identities() -> String {
    catch_panic(|| serde_json::to_string(&crate::core_lock_read().list_blocked_identities()).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|_| "[]".to_string())
}

/// See `P2PCore::contact_safety_code`. The safety code to compare.
pub fn contact_safety_code(identity_id: &str) -> String {
    catch_panic(|| crate::core_lock_read().contact_safety_code(identity_id).unwrap_or_default())
        .unwrap_or_default()
}

/// See `P2PCore::trust_contact`. Full trust for a contact met through a group.
pub fn trust_contact(contact_id: &str) -> String {
    match catch_panic(|| core_lock().trust_contact(contact_id)) {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) | Err(e) => format!("Error: {}", e),
    }
}

/// see `P2PCore::transfer_group_founder`.
pub fn transfer_group_founder(group_id: &str, new_founder_identity_id: &str) -> String {
    match catch_panic(|| core_lock().transfer_group_founder(group_id, new_founder_identity_id)) {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) | Err(e) => format!("Error: {}", e),
    }
}

pub fn accept_device_alert(fingerprint: &str) -> bool {
    let fp = fingerprint.to_string();
    catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().accept_pending_device_alert(&fp).is_ok()
    })
    .unwrap_or(false)
}

pub fn reject_device_alert(fingerprint: &str) {
    let fp = fingerprint.to_string();
    let _ = catch_panic(move || {
        core_lock().reject_pending_device_alert(&fp);
    });
}

// --- Pending (not yet confirmed) messages ---

pub fn retry_all_pending_now() {
    let _ = catch_panic(|| core_lock().retry_all_pending_now());
}

pub fn list_pending_messages() -> String {
    json_list(catch_panic(|| {
        serde_json::to_string(&crate::core_lock_read().list_pending_messages())
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn cancel_pending_message(message_id: &str) -> bool {
    let id = message_id.to_string();
    catch_panic(move || core_lock().cancel_pending_message(&id).is_ok()).unwrap_or(false)
}

pub fn retry_pending_message_now(message_id: &str) -> bool {
    let id = message_id.to_string();
    catch_panic(move || core_lock().retry_pending_message_now(&id).is_ok()).unwrap_or(false)
}

// --- Messaging ---

/// The shared return format of `send_message`, `edit_message` and `delete_message`:
/// `{"message_id":..,"status":"sent"|"pending"}`.
fn send_result(result: Result<Result<(String, String), String>, String>) -> String {
    match result {
        Ok(Ok((message_id, status))) => {
            serde_json::json!({ "message_id": message_id, "status": status }).to_string()
        }
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    }
}

pub fn send_message(
    target_device_fingerprint: &str,
    message: &str,
    reply_to_message_id: Option<String>,
    reply_to_preview: Option<String>,
    expire_secs: Option<u32>,
) -> String {
    let target = target_device_fingerprint.to_string();
    let msg = message.to_string();
    send_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().send_message(target, msg, reply_to_message_id, reply_to_preview, expire_secs)
    }))
}

pub fn react_to_message(target_device_fingerprint: &str, target_message_id: &str, emoji: &str) -> String {
    let (target, id, emoji) = (target_device_fingerprint.to_string(), target_message_id.to_string(), emoji.to_string());
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().react_to_message(target, id, emoji)
    }))
}

pub fn react_to_group_message(group_id: &str, target_message_id: &str, emoji: &str) -> String {
    let (gid, id, emoji) = (group_id.to_string(), target_message_id.to_string(), emoji.to_string());
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().react_to_group_message(gid, id, emoji)
    }))
}

pub fn edit_message(
    target_device_fingerprint: &str,
    target_message_id: &str,
    new_text: &str,
) -> String {
    let target = target_device_fingerprint.to_string();
    let target_id = target_message_id.to_string();
    let text = new_text.to_string();
    send_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().edit_message(target, target_id, text)
    }))
}

pub fn delete_message(target_device_fingerprint: &str, target_message_id: &str) -> String {
    let target = target_device_fingerprint.to_string();
    let target_id = target_message_id.to_string();
    send_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().delete_message(target, target_id)
    }))
}

pub fn has_active_session(peer_device_fingerprint: &str) -> bool {
    let fp = peer_device_fingerprint.to_string();
    catch_panic(move || crate::core_lock_read().has_active_session(&fp)).unwrap_or(false)
}

pub fn is_peer_connected(peer_device_fingerprint: &str) -> bool {
    let fp = peer_device_fingerprint.to_string();
    catch_panic(move || crate::core_lock_read().is_peer_connected(&fp)).unwrap_or(false)
}

pub fn ensure_handshake(peer_device_fingerprint: &str) {
    let fp = peer_device_fingerprint.to_string();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let _ = core_lock().ensure_handshake(&fp);
    });
}

pub fn send_typing_indicator(target_device_fingerprint: &str, is_typing: bool) -> bool {
    let target = target_device_fingerprint.to_string();
    matches!(
        catch_panic(move || {
            let _guard = RUNTIME.enter();
            core_lock().send_typing_indicator(target, is_typing)
        }),
        Ok(Ok(()))
    )
}

pub fn send_group_typing_indicator(group_id: &str, is_typing: bool) -> bool {
    let gid = group_id.to_string();
    matches!(
        catch_panic(move || {
            let _guard = RUNTIME.enter();
            core_lock().send_group_typing_indicator(gid, is_typing)
        }),
        Ok(Ok(()))
    )
}

pub fn send_seen_receipt(
    target_device_fingerprint: &str,
    target_message_id: &str,
    group_message_local_id: Option<String>,
) -> bool {
    let target = target_device_fingerprint.to_string();
    let target_id = target_message_id.to_string();
    // The send's own result, not only whether it panicked.
    catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().send_seen(&target, &target_id, group_message_local_id)
    })
    .unwrap_or(false)
}

pub fn list_contacts() -> String {
    json_list(catch_panic(|| {
        serde_json::to_string(&crate::core_lock_read().list_contacts()).unwrap_or_else(|_| "[]".to_string())
    }))
}

// --- Message history ---

pub fn get_message_history(peer_device_fingerprint: &str, limit: u32) -> String {
    let fp = peer_device_fingerprint.to_string();
    json_list(catch_panic(move || {
        // lock dropped before the JSON is built.
        let h = crate::core_lock_read().load_message_history(&fp, limit.min(crate::MAX_HISTORY_PAGE as u32), None);
        serde_json::to_string(&h)
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn get_message_history_before(
    peer_device_fingerprint: &str,
    before_timestamp: i64,
    limit: u32,
) -> String {
    let fp = peer_device_fingerprint.to_string();
    json_list(catch_panic(move || {
        let h = crate::core_lock_read().load_message_history(&fp, limit.min(crate::MAX_HISTORY_PAGE as u32), Some(before_timestamp));
        serde_json::to_string(&h)
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn get_group_message_history(group_id: &str, limit: u32) -> String {
    let gid = group_id.to_string();
    json_list(catch_panic(move || {
        let h = crate::core_lock_read().load_group_message_history(&gid, limit.min(crate::MAX_HISTORY_PAGE as u32), None);
        serde_json::to_string(&h)
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn get_group_message_history_before(
    group_id: &str,
    before_timestamp: i64,
    limit: u32,
) -> String {
    let gid = group_id.to_string();
    json_list(catch_panic(move || {
        let h = crate::core_lock_read().load_group_message_history(
            &gid,
            limit.min(crate::MAX_HISTORY_PAGE as u32),
            Some(before_timestamp),
        );
        serde_json::to_string(&h)
        .unwrap_or_else(|_| "[]".to_string())
    }))
}

/// rows archived after `after_timestamp` only (see JNI `getMessageHistorySince`).
pub fn get_message_history_since(peer_device_fingerprint: &str, after_timestamp: i64, limit: u32) -> String {
    let fp = peer_device_fingerprint.to_string();
    json_list(catch_panic(move || {
        let h = crate::core_lock_read().load_message_history_since(&fp, after_timestamp, limit.min(crate::MAX_HISTORY_PAGE as u32));
        serde_json::to_string(&h).unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn get_group_message_history_since(group_id: &str, after_timestamp: i64, limit: u32) -> String {
    let gid = group_id.to_string();
    json_list(catch_panic(move || {
        let h = crate::core_lock_read().load_group_message_history_since(&gid, after_timestamp, limit.min(crate::MAX_HISTORY_PAGE as u32));
        serde_json::to_string(&h).unwrap_or_else(|_| "[]".to_string())
    }))
}

/// see JNI `chatListPreviews`.
pub fn chat_list_previews() -> String {
    catch_panic(|| {
        let previews = crate::core_lock_read().chat_list_previews();
        previews.to_string()
    })
    .unwrap_or_else(|_| r#"{"contacts":{},"groups":{}}"#.to_string())
}

pub fn request_history_sync(peer_device_fingerprint: &str, limit: u32) {
    let fp = peer_device_fingerprint.to_string();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let _ = core_lock().request_history_sync(fp, limit.min(crate::MAX_HISTORY_PAGE as u32));
    });
}

/// Chat open: newest rows of this chat from my other devices (see `P2PCore::refresh_chat_from_siblings`).
/// `chat_key`: the peer device fingerprint, or the group id. Rows arrive later as an `older_history` /
/// `older_group_history` event.
pub fn refresh_chat_from_siblings(chat_key: &str, is_group: bool) {
    let key = chat_key.to_string();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().refresh_chat_from_siblings(&key, is_group);
    });
}

// --- File attachments ---

pub fn prepare_and_send_file(
    target_device_fingerprint: &str,
    source_path: &str,
    file_name: &str,
    mime_type: &str,
    preview_jpeg: Option<Vec<u8>>,
    duration_ms: Option<u32>,
    // Also carries the caption shown under the attachment bubble (empty = none) and the context of the message being
    // replied to. Same core path as Android. See `MessageContent::FileOffer`.
    caption: String,
    reply_to_message_id: Option<String>,
    reply_to_preview: Option<String>,
) -> String {
    let target = target_device_fingerprint.to_string();
    let source = source_path.to_string();
    let name = file_name.to_string();
    let mime = mime_type.to_string();
    send_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        // Lock splitting (see `prepare_and_send_file_unlocked` in media_unlocked.rs): encryption runs WITHOUT holding the global lock,
        // so the poll loop and the network are not blocked meanwhile.
        crate::prepare_and_send_file_unlocked(target, source, name, mime, preview_jpeg, duration_ms, caption, reply_to_message_id, reply_to_preview)
    }))
}

pub fn prepare_and_send_group_file(
    group_id: &str,
    source_path: &str,
    file_name: &str,
    mime_type: &str,
    preview_jpeg: Option<Vec<u8>>,
    duration_ms: Option<u32>,
    // Same note as `prepare_and_send_file`.
    caption: String,
    reply_to_message_id: Option<String>,
    reply_to_preview: Option<String>,
    reply_to_sender_identity_id: Option<String>,
) -> String {
    let gid = group_id.to_string();
    let source = source_path.to_string();
    let name = file_name.to_string();
    let mime = mime_type.to_string();
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        // Same lock-splitting note as `prepare_and_send_file`.
        crate::prepare_and_send_group_file_unlocked(gid, source, name, mime, preview_jpeg, duration_ms, caption, reply_to_message_id, reply_to_preview, reply_to_sender_identity_id)
    }))
}

pub fn download_file(file_id: &str, peer_device_fingerprint: &str) -> String {
    let id = file_id.to_string();
    let fp = peer_device_fingerprint.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().download_file(id, fp)
    }))
}

pub fn list_attachments(peer_device_fingerprint: &str) -> String {
    let fp = peer_device_fingerprint.to_string();
    json_list(catch_panic(move || {
        serde_json::to_string(&crate::core_lock_read().list_attachments(&fp))
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

/// Without the preview images, and without marking the core dirty: the chat
/// lists poll this.
pub fn list_attachments_brief(peer_device_fingerprint: &str) -> String {
    let fp = peer_device_fingerprint.to_string();
    json_list(catch_panic(move || {
        serde_json::to_string(&crate::core_lock_read().list_attachments_opt(&fp, false, None, crate::MAX_LISTED_ATTACHMENTS))
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

/// the `limit` newest attachments older than `before_ms`, oldest first.
pub fn list_attachments_before(peer_device_fingerprint: &str, before_ms: u64, limit: usize) -> String {
    let fp = peer_device_fingerprint.to_string();
    json_list(catch_panic(move || {
        serde_json::to_string(&crate::core_lock_read().list_attachments_page(&fp, before_ms, limit))
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn list_group_attachments_before(group_id: &str, before_ms: u64, limit: usize) -> String {
    let gid = group_id.to_string();
    json_list(catch_panic(move || {
        serde_json::to_string(&crate::core_lock_read().list_group_attachments_page(&gid, before_ms, limit))
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn list_group_attachments_brief(group_id: &str) -> String {
    let gid = group_id.to_string();
    json_list(catch_panic(move || {
        serde_json::to_string(&crate::core_lock_read().list_group_attachments_opt(&gid, false, None, crate::MAX_LISTED_ATTACHMENTS))
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn list_group_attachments(group_id: &str) -> String {
    let gid = group_id.to_string();
    json_list(catch_panic(move || {
        serde_json::to_string(&crate::core_lock_read().list_group_attachments(&gid))
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

/// "Hi-res" image: lossless JPEG XL of `rgba` (`width * height` RGBA
/// pixels, not premultiplied; the buffer is changed) to `out_path`.
pub fn encode_jxl_lossless(rgba: &mut [u8], width: u32, height: u32, has_alpha: bool, out_path: &str) -> Result<(), String> {
    catch_panic(move || crate::attachments::encode_jxl_lossless(rgba, width, height, has_alpha, std::path::Path::new(out_path)))?
}

/// animated lossless JPEG XL; see JNI `encodeJxlAnimated` (RGBA frames).
pub fn encode_jxl_animated(frames: &mut [Vec<u8>], width: u32, height: u32, delays_ms: &[u32], has_alpha: bool, out_path: &str) -> Result<(), String> {
    catch_panic(move || crate::attachments::encode_jxl_animated(frames, width, height, delays_ms, has_alpha, std::path::Path::new(out_path)))?
}

/// see JNI `jxlToGif`.
pub fn jxl_to_gif(in_path: &str, out_path: &str) -> Result<(), String> {
    catch_panic(move || crate::attachments::jxl_to_gif(std::path::Path::new(in_path), std::path::Path::new(out_path)))?
}

pub fn get_attachment_plaintext_path(file_id: &str) -> String {
    let id = file_id.to_string();
    string_result(catch_panic(move || {
        // Same lock-splitting note as `prepare_and_send_file`. Decryption runs without the lock.
        crate::attachment_plaintext_path_unlocked(&id)
    }))
}

// --- Group messaging ---

pub fn list_groups() -> String {
    json_list(catch_panic(|| {
        serde_json::to_string(&crate::core_lock_read().list_groups()).unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn create_group(name: &str) -> String {
    let name = name.to_string();
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().create_group(name)
    }))
}

pub fn invite_to_group(group_id: &str, identity_id: &str) -> bool {
    let gid = group_id.to_string();
    let iid = identity_id.to_string();
    matches!(
        catch_panic(move || {
            let _guard = RUNTIME.enter();
            core_lock().invite_to_group(&gid, &iid)
        }),
        Ok(Ok(_))
    )
}

pub fn remove_from_group(group_id: &str, identity_id: &str) -> bool {
    let gid = group_id.to_string();
    let iid = identity_id.to_string();
    matches!(
        catch_panic(move || {
            let _guard = RUNTIME.enter();
            core_lock().remove_from_group(&gid, &iid, true)
        }),
        Ok(Ok(_))
    )
}

pub fn delete_group(group_id: &str) -> String {
    let gid = group_id.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().delete_group(&gid)
    }))
}

/// the founder re-sends the current group state to every member.
pub fn resend_group_to_all(group_id: &str) -> String {
    let gid = group_id.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().resend_group_to_all(&gid)
    }))
}

pub fn leave_group(group_id: &str) -> String {
    let gid = group_id.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().leave_group(&gid)
    }))
}

pub fn set_group_profile_picture(group_id: &str, avatar_jpeg: Option<Vec<u8>>) -> String {
    let gid = group_id.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_group_avatar(&gid, avatar_jpeg)
    }))
}

/// See Kotlin `editGroupMessage`. Sent to ALL reachable members.
/// `target_group_message_local_id` is the id returned by `send_group_message`.
pub fn edit_group_message(
    group_id: &str,
    target_group_message_local_id: &str,
    new_text: &str,
) -> String {
    let gid = group_id.to_string();
    let target = target_group_message_local_id.to_string();
    let text = new_text.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().edit_group_message(gid, target, text)
    }))
}

/// Same note as `edit_group_message`.
pub fn delete_group_message(group_id: &str, target_group_message_local_id: &str) -> String {
    let gid = group_id.to_string();
    let target = target_group_message_local_id.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().delete_group_message(gid, target)
    }))
}

pub fn send_group_message(
    group_id: &str,
    message: &str,
    reply_to_message_id: Option<String>,
    reply_to_preview: Option<String>,
    reply_to_sender_identity_id: Option<String>,
    mentions: Vec<String>,
    expire_secs: Option<u32>,
) -> String {
    let gid = group_id.to_string();
    let msg = message.to_string();
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().send_group_message(
            &gid,
            &msg,
            reply_to_message_id,
            reply_to_preview,
            reply_to_sender_identity_id,
            mentions,
            expire_secs,
        )
    }))
}

// --- Profile photo and deleting chat contacts ---

pub fn get_own_profile_picture() -> Vec<u8> {
    catch_panic(|| crate::core_lock_read().get_own_avatar().unwrap_or_default()).unwrap_or_default()
}

pub fn set_own_profile_picture(avatar_jpeg: Option<Vec<u8>>) -> String {
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_own_profile_picture(avatar_jpeg)
    }))
}

/// The account name. See `P2PCore::own_display_name`.
pub fn get_display_name() -> String {
    catch_panic(|| crate::core_lock_read().own_display_name().unwrap_or_default()).unwrap_or_default()
}

/// `P2PCore::delete_account`. Returns the number of devices notified, or `-1` on error.
pub fn delete_account() -> i64 {
    match catch_panic(|| {
        let _guard = RUNTIME.enter();
        core_lock().delete_account()
    }) {
        Ok(Ok(n)) => n as i64,
        _ => -1,
    }
}

/// Desktop Quit: tells connected peers this device is going offline, so they
/// stop dialing it until it connects again. Blocks briefly while the poll
/// thread sends the requests; call it before the process exits.
pub fn announce_offline() {
    let sent = catch_panic(|| {
        let _guard = RUNTIME.enter();
        core_lock().announce_offline()
    })
    .unwrap_or(0);
    if sent > 0 {
        // Until every goodbye is answered or failed (the poll loop drives the swarm), at most 2.5 s.
        let until = std::time::Instant::now() + std::time::Duration::from_millis(2500);
        while std::time::Instant::now() < until {
            if crate::session::BYE_WAIT.lock().map_or(true, |w| w.is_empty()) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// Logout on a linked device: tells the root this device is leaving, so it
/// revokes it, and waits up to 3 s for the ack. The caller erases regardless.
pub fn announce_leaving() {
    let Some(id) = catch_panic(|| {
        let _guard = RUNTIME.enter();
        core_lock().announce_leaving()
    })
    .ok().flatten() else { return };
    let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < until {
        if !crate::core_lock_read().awaiting_confirmation.contains_key(&id) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Drops the swarm, the Tor handle and the database connection, so the data
/// directory can be erased under a quiet core. The core stays unusable until
/// the process exits.
pub fn shutdown() {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.swarm = None;
        core.tor = None;
        core.db = None;
        // The keys that open the stored data, and the decrypted copies, do not outlive the shutdown.
        {
            use zeroize::Zeroize;
            core.pending_secret_bundle.zeroize();
            core.skipped_key_encryption_key.zeroize();
            core.history_key.zeroize();
            core.archive_root_key.zeroize();
        }
        core.pending_secret_bundle = None;
        core.skipped_key_encryption_key = None;
        core.history_key = None;
        core.archive_root_key = None;
        core.own_device_keys.clear();
        if let Some(dir) = core.app_files_dir.as_deref() {
            let _ = std::fs::remove_dir_all(format!("{}/attachments/plain_cache", dir));
        }
    });
}

/// `P2PCore::account_deletion_pending`.
/// -1 on a panic, NOT 0: 0 means "every notice was delivered" and the caller
/// goes on to wipe the device.
pub fn account_deletion_pending() -> i64 {
    catch_panic(|| crate::core_lock_read().account_deletion_pending()).map(|n| n as i64).unwrap_or(-1)
}

/// `P2PCore::set_display_name`.
pub fn set_display_name(name: &str) -> String {
    let name = name.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_display_name(&name)
    }))
}

pub fn clear_chat_history(contact_id: &str) -> String {
    let id = contact_id.to_string();
    ok_result(catch_panic(move || core_lock().clear_chat_history(&id)))
}

pub fn delete_contact(contact_id: &str) -> String {
    let id = contact_id.to_string();
    ok_result(catch_panic(move || core_lock().delete_contact(&id, true)))
}

pub fn revoke_contact_device(contact_id: &str, device_fingerprint: &str) -> String {
    let id = contact_id.to_string();
    let fp = device_fingerprint.to_string();
    ok_result(catch_panic(move || {
        core_lock().revoke_contact_device(&id, &fp)
    }))
}

// --- Recovery file ---

/// After `export_recovery`: the number of newest messages the file holds when it had to be cut, 0 when complete.
pub fn last_recovery_trimmed() -> usize {
    crate::recovery::RECOVERY_TRIMMED.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn export_recovery(passphrase: &str) -> Vec<u8> {
    // The password protects the long-lived secret keys, so it must not stay in plain heap memory. Our copy is erased on drop. The core's own
    // copy is a separate matter (see `export_recovery` in recovery.rs).
    let pass = zeroize::Zeroizing::new(passphrase.to_string());
    // only the plaintext is built under the core lock; Argon2 runs
    // after the lock is released (it froze every other caller).
    let staged = catch_panic(move || {
        let chats = crate::recovery_chats_unlocked();
        crate::core_lock_read().recovery_plaintext((*pass).clone(), Some(chats))
    });
    // empty on failure (the Linux UI checks that), but logged.
    match staged.and_then(|r| r).and_then(|(plaintext, pass)| crate::seal_recovery_file(&plaintext, &pass)) {
        Ok(file) => file,
        Err(e) => {
            log::error!("export_recovery failed: {e}");
            Vec::new()
        }
    }
}

/// JNI `listReactions`: the stored reactions of a message, for a chat that is opened again.
pub fn list_reactions(target_message_id: &str) -> String {
    let id = target_message_id.to_string();
    json_list(catch_panic(move || crate::core_lock_read().list_reactions(&id)))
}

/// My 5 most used reaction emojis (JSON string array), for the quick-reaction bar.
pub fn top_reactions() -> String {
    json_list(catch_panic(move || crate::core_lock_read().top_reactions()))
}

/// Who has seen a message and when (`[{"identity_id":..,"seen_at_ms":..}]`, first viewer first), for the "seen by" list.
pub fn list_seen_by(message_id: &str) -> String {
    let id = message_id.to_string();
    json_list(catch_panic(move || crate::core_lock_read().seen_by_json(&id)))
}

/// The panic path for calls that return a JSON array: `"[]"`, the same as the `unwrap_or_else(|_| "[]")` pattern on the JNI side.
fn json_list(result: Result<String, String>) -> String {
    result.unwrap_or_else(|_| "[]".to_string())
}

// ---------------------------------------------------------------------------
// Server (store-and-forward) option
// ---------------------------------------------------------------------------
// Server and archive calls. The JNI counterparts are in `jni_exports/servers.rs` and `jni_exports/history.rs`. The two must be kept
// in sync BY HAND (the general rule in this file's module note).

/// Adds a server from an invite code (`typeon-server:<multiaddr>#<token>`). On success returns `{"server_id":".."}`.
pub fn add_server(invite_code: &str) -> String {
    let code = invite_code.to_string();
    match catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().add_server(&code)
    }) {
        Ok(Ok(json)) => json,
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    }
}

pub fn remove_server(server_id: &str) -> String {
    let sid = server_id.to_string();
    ok_result(catch_panic(move || core_lock().remove_server(&sid)))
}

/// `[{server_id, address, name, route_messages, store_history, connected,
/// enrolled, last_error}]`
pub fn list_servers() -> String {
    json_list(catch_panic(|| crate::core_lock_read().list_servers_json()))
}

pub fn set_server_routing(server_id: &str, enabled: bool) -> String {
    let sid = server_id.to_string();
    ok_result(catch_panic(move || core_lock().set_server_routing(&sid, enabled)))
}

/// Server-side history storage. It is SEPARATE from message routing and disabled by default. The archive is a real backup, and unlike the
/// ratchet it is NOT forward secret: if the root archive key ever leaks, ALL history stored up to that point can be read. Forward secrecy
/// and "I want to see my history on a new device" cannot both hold, so this trade-off must be the user's explicit choice.
pub fn set_server_history(server_id: &str, enabled: bool) -> String {
    let sid = server_id.to_string();
    ok_result(catch_panic(move || core_lock().set_server_history(&sid, enabled)))
}

/// One chat's older history from the server archive. For a "fetch history
/// from server" button: nothing else asks the server for a chat's history.
/// `chat_key`: the peer device fingerprint, or the group id; `before_timestamp`:
/// the oldest message on screen (ms), 0 = from the newest. "OK" or "Error: ...";
/// the rows arrive later with a `history_backfilled` event.
pub fn fetch_server_history(chat_key: &str, is_group: bool, before_timestamp: i64) -> String {
    let key = chat_key.to_string();
    ok_result(catch_panic(move || core_lock().fetch_server_history(&key, is_group, before_timestamp.max(0) as u64)))
}

/// Loads the root archive key (ARK). The same pattern as `set_history_key`, but this key belongs to the IDENTITY, not the device: every device
/// of the same identity must be able to read the archive on the server.
pub fn set_archive_root_key(key_bytes: &[u8]) -> bool {
    let key = zeroize::Zeroizing::new(key_bytes.to_vec());
    catch_panic(move || core_lock().set_archive_root_key(&key)).unwrap_or(false)
}

/// Downloads ALL history from the server. Used for a device restored from a recovery file, or a newly installed device after pairing.
/// The difference from `request_older_server_history`: that one serves "I scrolled up in this chat", so it assumes the chat is already visible.
/// On a device set up from scratch, contacts come back but there are no messages yet, and nothing exists for the user to scroll through.
pub fn restore_server_history() -> String {
    match catch_panic(|| core_lock().restore_all_server_history()) {
        Ok(Ok(n)) => format!("OK:{}", n),
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    }
}

/// The root archive key the core currently holds, if any. It exists so the DESKTOP client can persist it to disk: the ARK can arrive LATER
/// from a sibling device via `DeviceSync`, and at that point the client does not have the vault passphrase. Android does not need this,
/// because the key is already produced in a file wrapped by the Keystore.
pub fn archive_root_key() -> Vec<u8> {
    catch_panic(|| crate::core_lock_read().archive_root_key_bytes().unwrap_or_default()).unwrap_or_default()
}

// --- Calls (see `call/`; mirrors the `P2PLib.startCall`.. JNI exports) ---

/// Rings `peer` (a device fingerprint or chat key). Call id or `"Error: .."`.
pub fn start_call(peer: &str, video: bool) -> String {
    let peer = peer.to_string();
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().start_call(peer, video)
    }))
}

pub fn start_group_call(group_id: &str, video: bool) -> String {
    let group_id = group_id.to_string();
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().start_group_call(group_id, video)
    }))
}

pub fn accept_call() -> bool {
    matches!(
        catch_panic(|| {
            let _guard = RUNTIME.enter();
            core_lock().accept_call()
        }),
        Ok(Ok(()))
    )
}

pub fn end_call() {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        core_lock().end_call()
    });
}

/// 0 = no call running in the group (or this device is in it), 1 = voice, 2 = video.
/// `start_group_call` then joins it; changes arrive as `group_call_offer` events.
pub fn group_call_offer(group_id: &str) -> i32 {
    catch_panic(|| crate::core_lock_read().group_call_offer(group_id)).unwrap_or(0)
}

/// `{"state": "idle"|"outgoing"|"incoming"|"active", ...}`.
pub fn call_state() -> String {
    catch_panic(|| crate::core_lock_read().call_state_json()).unwrap_or_else(|_| "{\"state\":\"idle\"}".to_string())
}

/// Media calls take no core lock: the audio/video threads call them often.
pub fn call_send(kind: u8, payload: &[u8]) -> bool {
    let payload = payload.to_vec();
    catch_panic(move || crate::call::media_send(kind, &payload)).unwrap_or(false)
}

/// `[kind][slot][payload]`, or `None` on timeout.
pub fn call_recv(timeout_ms: u64) -> Option<Vec<u8>> {
    catch_panic(move || crate::call::media_recv(timeout_ms)).ok().flatten()
}

pub fn call_request_keyframe(slot: u8) {
    let _ = catch_panic(move || crate::call::media_request_keyframe(slot));
}

pub fn call_take_keyframe_request() -> bool {
    catch_panic(crate::call::media_take_keyframe_request).unwrap_or(false)
}

/// This device's HEVC decoder for `slot` failed: ask that sender for H.264.
pub fn call_request_avc(slot: u8) {
    let _ = catch_panic(move || crate::call::media_request_avc(slot));
}

/// Some receiver asked for H.264 since the last call.
pub fn call_take_avc_request() -> bool {
    catch_panic(crate::call::media_take_avc_request).unwrap_or(false)
}

/// Congestion signal in frames, see `media_backlog`.
pub fn call_backlog() -> usize {
    catch_panic(crate::call::media_backlog).unwrap_or(0)
}

// --- Shared whiteboard (see whiteboard.rs; JNI twins are in its `jni_exports`) ---

/// Returns the new stroke ids as hex (16 digits each) or `"Error: ..."`.
pub fn whiteboard_add_stroke(peer: &str, group_id: &str, page: u8, shade: u8, width: u8, points: &[u8]) -> String {
    let (peer, gid, points) = (peer.to_string(), group_id.to_string(), points.to_vec());
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().wb_add_stroke(&peer, &gid, page, shade, width, &points)
    }))
}

/// `ids`: 8 bytes per erased stroke.
pub fn whiteboard_erase(peer: &str, group_id: &str, ids: &[u8]) -> String {
    let (peer, gid, ids) = (peer.to_string(), group_id.to_string(), ids.to_vec());
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().wb_erase_strokes(&peer, &gid, &ids)
    }))
}

pub fn whiteboard_open(peer: &str, group_id: &str) {
    let (peer, gid) = (peer.to_string(), group_id.to_string());
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().wb_open(&peer, &gid)
    });
}

pub fn whiteboard_mark_read(peer: &str, group_id: &str, page: u8) {
    let (peer, gid) = (peer.to_string(), group_id.to_string());
    let _ = catch_panic(move || core_lock().wb_mark_read(&peer, &gid, page));
}

/// JSON `{"pages","unread","me","participants":[{"id","name"}]}` or `"Error: ..."`.
pub fn whiteboard_info(peer: &str, group_id: &str) -> String {
    let (peer, gid) = (peer.to_string(), group_id.to_string());
    string_result(catch_panic(move || crate::core_lock_read().wb_info(&peer, &gid)))
}

/// Per stroke: id(8) shade(1) author index(1, 255 = left) width(1) count(u16 LE) points.
pub fn whiteboard_page(peer: &str, group_id: &str, page: u8) -> Vec<u8> {
    let (peer, gid) = (peer.to_string(), group_id.to_string());
    catch_panic(move || crate::core_lock_read().wb_page_blob(&peer, &gid, page)).unwrap_or_default()
}

pub fn whiteboard_tick() {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        core_lock().wb_sweep();
    });
}

// --- Stickers (same core paths as the JNI `*Sticker*` exports) ---

/// JSON `[{"id","animated","created_at","favorite"}]`, favorites first.
pub fn list_stickers() -> String {
    catch_panic(|| crate::core_lock_read().list_stickers()).unwrap_or_else(|_| "[]".to_string())
}

/// A viewable copy of a sticker: `.png`, or `.gif` when animated.
pub fn sticker_plain_path(id: &str) -> String {
    let id = id.to_string();
    string_result(catch_panic(move || crate::sticker_plain_path_unlocked(&id)))
}

/// A still sticker from one RGBA frame (at most 600 px a side). Returns its id.
pub fn import_sticker_rgba(rgba: Vec<u8>, width: u32, height: u32) -> String {
    if rgba.len() as u64 != u64::from(width) * u64::from(height) * 4 {
        return "Error: bad sticker size".to_string();
    }
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        crate::import_sticker_frames_unlocked(vec![rgba], width, height, &[0], None)
    }))
}

/// Sends a sticker to a contact device (`peer`) or a group (`group_id`; the
/// other one empty). `reply_to` = (message id, preview, group sender).
/// Returns the attachment's file id.
pub fn send_sticker(peer: &str, group_id: &str, sticker_id: &str, reply_to: Option<(String, String, Option<String>)>) -> String {
    let peer = Some(peer.to_string()).filter(|s| !s.is_empty());
    let gid = Some(group_id.to_string()).filter(|s| !s.is_empty());
    let id = sticker_id.to_string();
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        crate::send_sticker_unlocked(peer, gid, &id, reply_to)
    }))
}

/// Copies a received (downloaded) sticker attachment into my store. Returns the sticker id.
pub fn save_received_sticker(file_id: &str) -> String {
    let id = file_id.to_string();
    string_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        crate::save_received_sticker_unlocked(&id)
    }))
}

/// Removes a sticker from my store and from my other devices.
pub fn delete_sticker(id: &str) -> String {
    let id = id.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().delete_sticker(&id, true)
    }))
}

/// Asks the phone for every sticker this device lacks; they arrive one by
/// one as `stickers_changed` events.
pub fn request_stickers_from_phone() -> String {
    ok_result(catch_panic(|| {
        let _guard = RUNTIME.enter();
        core_lock().request_stickers_from_siblings()
    }))
}

pub fn set_sticker_favorite(id: &str, favorite: bool) -> String {
    let id = id.to_string();
    ok_result(catch_panic(move || core_lock().set_sticker_favorite(&id, favorite)))
}

/// JSON `[{"id","name","stickers":[sticker id]}]`: this device's sticker folders, oldest first.
pub fn list_sticker_folders() -> String {
    catch_panic(|| crate::core_lock_read().list_sticker_folders()).unwrap_or_else(|_| "[]".to_string())
}

/// Returns the new folder's id.
pub fn create_sticker_folder(name: &str) -> String {
    let name = name.to_string();
    string_result(catch_panic(move || core_lock().create_sticker_folder(&name).map(|id| id.to_string())))
}

pub fn rename_sticker_folder(id: i64, name: &str) -> String {
    let name = name.to_string();
    ok_result(catch_panic(move || core_lock().rename_sticker_folder(id, &name)))
}

/// Deletes the folder only; its stickers stay.
pub fn delete_sticker_folder(id: i64) -> String {
    ok_result(catch_panic(move || core_lock().delete_sticker_folder(id)))
}

pub fn add_stickers_to_folder(id: i64, sticker_ids: &[String]) -> String {
    let ids = sticker_ids.to_vec();
    ok_result(catch_panic(move || core_lock().add_stickers_to_folder(id, &ids)))
}

pub fn remove_stickers_from_folder(id: i64, sticker_ids: &[String]) -> String {
    let ids = sticker_ids.to_vec();
    ok_result(catch_panic(move || core_lock().remove_stickers_from_folder(id, &ids)))
}

// --- Storage (this device only, as Android's Settings → Storage) ---

/// See JNI `storageUsage`.
pub fn storage_usage() -> String {
    catch_panic(|| crate::core_lock_read().storage_usage().to_string()).unwrap_or_else(|_| "{}".to_string())
}

/// See JNI `chatPruneStats`; `kind` is "contact" or "group".
pub fn chat_prune_stats(kind: &str, id: &str, before_ms: i64) -> String {
    let (kind, id) = (kind.to_string(), id.to_string());
    catch_panic(move || crate::core_lock_read().chat_prune_stats(&kind, &id, before_ms).to_string()).unwrap_or_else(|_| "{}".to_string())
}

/// Deletes a chat's messages and attachments older than `before_ms` on this device.
pub fn prune_chat_before(kind: &str, id: &str, before_ms: i64) -> String {
    let (kind, id) = (kind.to_string(), id.to_string());
    ok_result(catch_panic(move || core_lock().prune_chat_before(&kind, &id, before_ms)))
}

/// Drops this device's copy of each attachment (downloadable again). The first error, if any.
pub fn remove_local_attachments(file_ids: &[String]) -> String {
    let ids = file_ids.to_vec();
    ok_result(catch_panic(move || {
        let mut core = core_lock();
        let mut first_err = None;
        for id in &ids {
            if let Err(e) = core.remove_local_attachment(id) {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }))
}

/// A JPEG XL attachment as it came, for "Save as JPEG XL".
pub fn attachment_original_path(file_id: &str) -> String {
    let id = file_id.to_string();
    string_result(catch_panic(move || crate::attachment_original_path_unlocked(&id)))
}

/// 1 = sent again to the group devices that missed it, 0 = nothing to send, -1 = failed.
pub fn retry_group_message_copies(group_id: &str, local_id: &str) -> i32 {
    let (gid, lid) = (group_id.to_string(), local_id.to_string());
    match catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().retry_group_message_copies(&gid, &lid)
    }) {
        Ok(Ok(true)) => 1,
        Ok(Ok(false)) => 0,
        _ => -1,
    }
}

/// Hides a revoked sibling from `list_linked_devices`.
pub fn forget_revoked_linked_device(device_fingerprint: &str) -> String {
    let fp = device_fingerprint.to_string();
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().forget_revoked_linked_device(&fp)
    }))
}

/// A sticker's first frame as PNG (cheap preview of an animated one).
pub fn sticker_first_frame(id: &str) -> String {
    let id = id.to_string();
    string_result(catch_panic(move || crate::sticker_first_frame_unlocked(&id)))
}

/// A complete JPEG XL attachment's frames: (width, height, [(RGBA, ms)]).
/// Slow: off the UI thread.
pub fn attachment_jxl_frames(file_id: &str) -> Result<(u32, u32, Vec<(Vec<u8>, u32)>), String> {
    let id = file_id.to_string();
    catch_panic(move || {
        crate::attachment_jxl_frames_unlocked(&id)
    })?
}
