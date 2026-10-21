//! Saf-Rust API cephesi (façade) — JNI'siz çağıranlar için.
//!
//! Bu modül, dosya sonundaki JNI export'larının (`Java_com_p2p_messenger_P2PLib_*`)
//! BİREBİR karşılıklarını, JVM'e özgü tiplerden (JNIEnv/JString/JByteArray)
//! arındırılmış olarak sunar: aynı `catch_panic` + `RUNTIME.enter()` +
//! `core_lock()` sırası, aynı dönüş biçimleri ("Error: ..." önekli hata
//! stringleri, JSON dizileri, `{"message_id":..,"status":..}` nesneleri).
//!
//! GEREKÇE: Linux masaüstü istemcisi (bkz. depo kökündeki `Linux/`) TAM OLARAK
//! aynı çekirdeği (aynı kripto, aynı ratchet, aynı veritabanı şeması, aynı
//! ağ protokolü) kullanır — protokolü ikinci kez yazmak, iki uygulamanın
//! sessizce birbirinden sapması demek olurdu. Android tarafı için HİÇBİR ŞEY
//! değişmez: bu modül tamamen EKLEMEDİR, JNI export'ları olduğu gibi durur ve
//! `api::*` fonksiyonlarını çağırmaz (ikisi de doğrudan `P2PCore`'a gider).
//!
//! Kotlin tarafındaki `P2PLib` dokümantasyonu (parametre anlamları, hangi
//! çağrının ana thread'de yapılmaması gerektiği, dönüş biçimleri) buradaki
//! her fonksiyon için AYNEN geçerlidir — tekrar edilmiyor.

use crate::{catch_panic, core_lock, RUNTIME};

/// JNI tarafındaki `Ok(Ok(v)) / Ok(Err(e)) / Err(panic)` üçlüsünü, her iki
/// hata yolunu da `"Error: ..."` biçimine indirgeyen tek bir string'e çevirir
/// (bkz. `Java_..._createIdentity` ve kardeşleri — hepsi bu deseni tekrar
/// ediyordu).
fn string_result(result: Result<Result<String, String>, String>) -> String {
    match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: panic: {}", e), // M21: told apart from a declared failure
    }
}

/// `Result<(), String>` dönen çekirdek çağrıları için: başarıda `"OK"`.
fn ok_result(result: Result<Result<(), String>, String>) -> String {
    match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: panic: {}", e), // M21: told apart from a declared failure
    }
}

// --- Bölüm 1: Identity/Device ---

/// `storage_key`: the 32-byte local storage key, the same one later handed
/// to `set_skipped_key_encryption_key`. The database is encrypted under it.
pub fn init_database(files_dir: &str, storage_key: &[u8]) -> bool {
    let key: [u8; 32] = match storage_key.try_into() {
        Ok(k) => k,
        Err(_) => return false,
    };
    let key = zeroize::Zeroizing::new(key);
    let path = files_dir.to_string();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.init_db(&path, &key).map_err(|e| e.to_string())
    });
    matches!(result, Ok(Ok(_)))
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

pub fn load_secret_bundle(bundle_bytes: &[u8]) -> bool {
    let raw = bundle_bytes.to_vec();
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

/// bkz. Kotlin `setHistoryKey` — 32 bayt olmayan anahtar sessizce reddedilir.
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

// --- Bölüm 4: Ağ ---

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
    // bkz. JNI `setHistoryStorageLimitBytes`: 0 = a failed pref read, never a
    // choice — as a limit it would delete every stored attachment. `u64`'de
    // "negatif" yok, tek zararlı değer 0.
    if bytes == 0 {
        return;
    }
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_history_storage_limit_bytes(bytes);
    });
}

/// bkz. JNI `setPowerSave` — ekran kapalı/uygulama arka planda iken açılır
/// (bkz. `P2PCore::set_power_save`).
pub fn set_power_save(enabled: bool) {
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_power_save(enabled);
    });
}

/// bkz. JNI `setMeteredNetwork` — ölçülü (hücresel) ağ, radyo-penceresi
/// birleştirmesi için (bkz. `P2PCore::set_metered`).
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

/// bkz. Kotlin `pollNetwork` — her turda çözülen olayların JSON listesi.
pub fn poll_network() -> Vec<String> {
    catch_panic(|| {
        let _guard = RUNTIME.enter();
        crate::CORE_DIRTY.store(false, std::sync::atomic::Ordering::SeqCst);
        let started = std::time::Instant::now();
        let out = crate::core_lock_poll().poll_events();
        let took = started.elapsed().as_millis();
        if took > 5_000 {
            log::warn!("poll_events {} ms sürdü", took);
        }
        out
    })
    .unwrap_or_default()
}

/// bkz. lib.rs `wait_for_network_activity` — poll döngüsü sabit uyku yerine bunu çağırır.
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

// --- Bölüm 1.3/1.4: QR + manuel eşleşme ---

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

/// bkz. Kotlin `processQrPacket` — başarıda
/// `{"identity_id":..,"device_fingerprint":..,"device_name":..}`.
pub fn process_qr_packet(data: &[u8]) -> String {
    let raw = data.to_vec();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().process_qr_packet(&raw)
    });
    pairing_result(result)
}

pub fn process_manual_entry(text: &str) -> String {
    let text = text.to_string();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().process_manual_entry(&text)
    });
    pairing_result(result)
}

/// `process_qr_packet`/`process_manual_entry`'nin ORTAK dönüş biçimi.
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

// --- Çoklu-cihaz (spec 1.5/1.6/1.7) ---

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

pub fn approve_device_link(data: &[u8]) -> String {
    let raw = data.to_vec();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().approve_device_link(&raw)
    });
    match result {
        Ok(Ok((fp, name))) => {
            serde_json::json!({ "device_fingerprint": fp, "device_name": name }).to_string()
        }
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    }
}

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

// --- Bölüm 2.2: Cihaz değişikliği uyarıları ---

pub fn list_pending_device_alerts() -> String {
    json_list(catch_panic(|| {
        serde_json::to_string(&crate::core_lock_read().list_pending_device_alerts())
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

/// bkz. `P2PCore::block_identity` — kalıcı engelleme.
pub fn block_identity(identity_id: &str) -> String {
    match catch_panic(|| core_lock().block_identity(identity_id)) {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) | Err(e) => format!("Error: {}", e),
    }
}

/// bkz. `P2PCore::unblock_identity`.
pub fn unblock_identity(identity_id: &str) {
    let _ = catch_panic(|| core_lock().unblock_identity(identity_id));
}

/// Engellenen kimlikler, JSON dizisi.
pub fn list_blocked_identities() -> String {
    catch_panic(|| serde_json::to_string(&crate::core_lock_read().list_blocked_identities()).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|_| "[]".to_string())
}

/// bkz. `P2PCore::contact_safety_code` — karşılaştırılacak güvenlik kodu.
pub fn contact_safety_code(identity_id: &str) -> String {
    catch_panic(|| crate::core_lock_read().contact_safety_code(identity_id).unwrap_or_default())
        .unwrap_or_default()
}

/// bkz. `P2PCore::trust_contact` — grup üzerinden tanışılana tam güven.
pub fn trust_contact(contact_id: &str) -> String {
    match catch_panic(|| core_lock().trust_contact(contact_id)) {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) | Err(e) => format!("Error: {}", e),
    }
}

/// bkz. `P2PCore::transfer_group_founder`.
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

// --- Bekleyen (onay almamış) mesajlar ---

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

// --- Bölüm 3: Mesajlaşma ---

/// `send_message`/`edit_message`/`delete_message`'ın ORTAK dönüş biçimi:
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
) -> String {
    let target = target_device_fingerprint.to_string();
    let msg = message.to_string();
    send_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().send_message(target, msg, reply_to_message_id, reply_to_preview)
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
    // M-179: the send's own result, not only "did not panic".
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

// --- Mesaj geçmişi ---

pub fn get_message_history(peer_device_fingerprint: &str, limit: u32) -> String {
    let fp = peer_device_fingerprint.to_string();
    json_list(catch_panic(move || {
        // H57: lock dropped before the JSON is built.
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

/// H122: rows archived after `after_timestamp` only (bkz. JNI `getMessageHistorySince`).
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

/// H137: bkz. JNI `chatListPreviews`.
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

pub fn request_older_message_history(
    peer_device_fingerprint: &str,
    before_timestamp: i64,
    limit: u32,
) {
    let fp = peer_device_fingerprint.to_string();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let _ = core_lock().request_older_history(&fp, before_timestamp, limit.min(crate::MAX_HISTORY_PAGE as u32));
    });
}

pub fn request_older_group_message_history(group_id: &str, before_timestamp: i64, limit: u32) {
    let gid = group_id.to_string();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let _ = core_lock().request_older_group_history(&gid, before_timestamp, limit.min(crate::MAX_HISTORY_PAGE as u32));
    });
}

/// bkz. `request_older_message_history` aynı notu — EK olarak, karşı taraf
/// (contact) o an ulaşılamıyorsa bile bu cihazın KENDİ kardeş cihazlarından
/// aynı sayfayı ister (dış inceleme düzeltmesi: "sibling backfill sayfalama
/// desteklemiyordu"). Linux masaüstü istemcisi her zaman İKİNCİL bir cihaz
/// olduğundan (bkz. modül başı notu), bu özellikle önemli bir kaynak —
/// birincil telefon genelde ulaşılabilir olur.
pub fn request_older_sibling_history(peer_device_fingerprint: &str, before_timestamp: i64, limit: u32) {
    let fp = peer_device_fingerprint.to_string();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let _ = core_lock().request_older_sibling_history(Some(&fp), None, before_timestamp, limit.min(crate::MAX_HISTORY_PAGE as u32));
    });
}

/// bkz. `request_older_sibling_history` aynı notu — grup için.
pub fn request_older_sibling_group_history(group_id: &str, before_timestamp: i64, limit: u32) {
    let gid = group_id.to_string();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let _ = core_lock().request_older_sibling_history(None, Some(&gid), before_timestamp, limit.min(crate::MAX_HISTORY_PAGE as u32));
    });
}

// --- Dosya ekleri ---

pub fn prepare_and_send_file(
    target_device_fingerprint: &str,
    source_path: &str,
    file_name: &str,
    mime_type: &str,
    preview_jpeg: Option<Vec<u8>>,
    duration_ms: Option<u32>,
    // Spec dışı, kullanıcı isteği: ek balonunun altında görünecek açıklama
    // (boş = yok) ve — varsa — yanıtlanan mesajın bağlamı. Android tarafıyla
    // AYNI çekirdek yolu; bkz. `MessageContent::FileOffer`.
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
        // Kilit-bölme düzeltmesi (bkz. lib.rs `prepare_and_send_file_unlocked`):
        // şifreleme global kilit TUTULMADAN çalışır — poll döngüsü/ağ bu
        // sırada bloklanmaz.
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
    // bkz. `prepare_and_send_file` aynı not.
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
        // bkz. `prepare_and_send_file` aynı kilit-bölme notu.
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
        serde_json::to_string(&crate::core_lock_read().list_attachments_opt(&fp, false))
            .unwrap_or_else(|_| "[]".to_string())
    }))
}

pub fn list_group_attachments_brief(group_id: &str) -> String {
    let gid = group_id.to_string();
    json_list(catch_panic(move || {
        serde_json::to_string(&crate::core_lock_read().list_group_attachments_opt(&gid, false))
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

pub fn get_attachment_plaintext_path(file_id: &str) -> String {
    let id = file_id.to_string();
    string_result(catch_panic(move || {
        // bkz. `prepare_and_send_file` aynı kilit-bölme notu — çözme kilitsiz.
        crate::attachment_plaintext_path_unlocked(&id)
    }))
}

// --- Bölüm 5: Grup mesajlaşma ---

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

/// bkz. Kotlin `editGroupMessage` — ulaşılabilir TÜM üyelere gider.
/// `target_group_message_local_id`, `send_group_message`'ın döndürdüğü kimlik.
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

/// bkz. `edit_group_message` AYNI notu.
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
        )
    }))
}

// --- Profil fotoğrafı / sohbet-kişi silme ---

pub fn get_own_profile_picture() -> Vec<u8> {
    catch_panic(|| crate::core_lock_read().get_own_avatar().unwrap_or_default()).unwrap_or_default()
}

pub fn set_own_profile_picture(avatar_jpeg: Option<Vec<u8>>) -> String {
    ok_result(catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_own_profile_picture(avatar_jpeg)
    }))
}

/// Hesap adı — bkz. `P2PCore::own_display_name`.
pub fn get_display_name() -> String {
    catch_panic(|| crate::core_lock_read().own_display_name().unwrap_or_default()).unwrap_or_default()
}

/// `P2PCore::delete_account` — bildirim giden cihaz sayısı, hata için `-1`.
pub fn delete_account() -> i64 {
    match catch_panic(|| {
        let _guard = RUNTIME.enter();
        core_lock().delete_account()
    }) {
        Ok(Ok(n)) => n as i64,
        _ => -1,
    }
}

/// `P2PCore::account_deletion_pending`.
///
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
    ok_result(catch_panic(move || core_lock().delete_contact(&id)))
}

pub fn revoke_contact_device(contact_id: &str, device_fingerprint: &str) -> String {
    let id = contact_id.to_string();
    let fp = device_fingerprint.to_string();
    ok_result(catch_panic(move || {
        core_lock().revoke_contact_device(&id, &fp)
    }))
}

// --- Bölüm 1.8: Kurtarma dosyası ---

pub fn export_recovery(passphrase: &str) -> Vec<u8> {
    // bkz. M-23: uzun ömürlü TÜM anahtarları koruyan parola serbest
    // heap'te kalmasın — kopyamız drop'ta siliniyor (çekirdeğin kendi
    // kopyası ayrı bir konu, bkz. lib.rs `export_recovery`).
    let pass = zeroize::Zeroizing::new(passphrase.to_string());
    // M-21: only the plaintext is built under the core lock; Argon2 runs
    // after the lock is released (it froze every other caller).
    let staged = catch_panic(move || crate::core_lock_read().recovery_plaintext((*pass).clone()));
    // M20: empty on failure (the Linux UI checks that), but logged.
    match staged.and_then(|r| r).and_then(|(plaintext, pass)| crate::seal_recovery_file(&plaintext, &pass)) {
        Ok(file) => file,
        Err(e) => {
            log::error!("export_recovery failed: {e}");
            Vec::new()
        }
    }
}

pub fn import_recovery(file_bytes: &[u8], passphrase: &str, device_name: &str) -> String {
    let raw = file_bytes.to_vec();
    // bkz. M-23 aynı notu — bu fonksiyonun parola kopyası da siliniyor.
    let pass = zeroize::Zeroizing::new(passphrase.to_string());
    let name = device_name.to_string();
    // M-21: precheck under the lock, Argon2 + decrypt without it, then the
    // import under the lock again (it repeats the precheck).
    string_result(catch_panic(move || -> Result<String, String> {
        crate::core_lock_read().import_recovery_precheck()?;
        let plaintext = crate::open_recovery_file(&raw, &pass)?;
        let mut core = core_lock();
        let (id, bundle_bytes) = core.import_recovery_plaintext(&plaintext, name)?;
        core.pending_secret_bundle = Some(bundle_bytes);
        Ok(id)
    }))
}

/// JSON dizisi dönen çağrıların panik yolu — JNI tarafındaki
/// `unwrap_or_else(|_| "[]")` deseninin aynısı.
/// JNI `listReactions`: the stored reactions of a message, for a chat that is
/// opened again.
pub fn list_reactions(target_message_id: &str) -> String {
    let id = target_message_id.to_string();
    json_list(catch_panic(move || crate::core_lock_read().list_reactions(&id)))
}

fn json_list(result: Result<String, String>) -> String {
    result.unwrap_or_else(|_| "[]".to_string())
}

// ---------------------------------------------------------------------------
// Sunucu (store-and-forward) seçeneği
// ---------------------------------------------------------------------------
//
// bkz. çekirdeğin `server_client` modülü. Bu fonksiyonların JNI karşılıkları
// `lib.rs`'in sonundadır; ikisi ELLE senkron tutulmalı (bu dosyanın modül
// notundaki genel kural).

/// Davet kodundan (`typeon-server:<multiaddr>#<jeton>`) bir sunucu ekler.
/// Başarıda `{"server_id":".."}`.
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

/// Geçmişi sunucuda saklama — mesaj yönlendirmeden AYRI ve varsayılan
/// KAPALI. Arşiv gerçek bir yedek ve ratchet'in aksine ileri-gizli DEĞİL:
/// kök arşiv anahtarı bir gün sızarsa o ana kadar yüklenmiş TÜM geçmiş
/// okunur. "Yeni cihazımda geçmişimi göreyim" ile ileri-gizlilik matematiksel
/// olarak uzlaşmaz; bu takas kullanıcının açık tercihi olmalı.
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

/// Kök arşiv anahtarını (ARK) yükler. `set_history_key` ile aynı desen ama
/// bu anahtar CİHAZA değil KİMLİĞE ait — aynı kimliğin bütün cihazları
/// sunucudaki arşivi okuyabilmeli.
pub fn set_archive_root_key(key_bytes: &[u8]) -> bool {
    let key = key_bytes.to_vec();
    catch_panic(move || core_lock().set_archive_root_key(&key)).unwrap_or(false)
}

/// Sunucudaki BÜTÜN geçmişi indirir — kurtarma dosyasından ya da cihaz
/// bağlamayla yeni kurulmuş bir cihaz için.
///
/// `request_older_server_history`'den farkı: o, "bu sohbette yukarı
/// kaydırdım" durumunu karşılıyor, yani sohbetin zaten görünür olmasını
/// varsayıyor. Sıfırdan kurulan bir cihazda kişiler geri gelir ama hiç mesaj
/// yoktur ve kullanıcının kaydıracağı bir şey de yoktur.
pub fn restore_server_history() -> String {
    match catch_panic(|| core_lock().restore_all_server_history()) {
        Ok(Ok(n)) => format!("OK:{}", n),
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    }
}

/// Çekirdeğin o an tuttuğu kök arşiv anahtarı (varsa).
///
/// SADECE masaüstü istemcisinin bunu diske kalıcılaştırabilmesi için: ARK bir
/// kardeş cihazdan `DeviceSync` ile SONRADAN gelebiliyor ve o an istemcinin
/// elinde vault parolası olmuyor. Android'de buna gerek yok — anahtar zaten
/// Keystore sarmalı bir dosyada üretiliyor.
pub fn archive_root_key() -> Vec<u8> {
    catch_panic(|| crate::core_lock_read().archive_root_key_bytes().unwrap_or_default()).unwrap_or_default()
}

// --- Calls (see `call.rs`; mirrors the `P2PLib.startCall`.. JNI exports) ---

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

/// `{"state": "idle"|"outgoing"|"incoming"|"active", ...}`.
pub fn call_state() -> String {
    catch_panic(|| core_lock().call_state_json()).unwrap_or_else(|_| "{\"state\":\"idle\"}".to_string())
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

/// Send queue depth in 100 ms units — the congestion signal.
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
    string_result(catch_panic(move || core_lock().wb_info(&peer, &gid)))
}

/// Per stroke: id(8) shade(1) author index(1, 255 = left) width(1) count(u16 LE) points.
pub fn whiteboard_page(peer: &str, group_id: &str, page: u8) -> Vec<u8> {
    let (peer, gid) = (peer.to_string(), group_id.to_string());
    catch_panic(move || core_lock().wb_page_blob(&peer, &gid, page)).unwrap_or_default()
}

pub fn whiteboard_tick() {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        core_lock().wb_sweep();
    });
}
