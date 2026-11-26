//! JNI: network start, status, polling, power and network-change hooks.

use super::*;

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_startNetwork<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, node_mode: jboolean, tor_enabled: jboolean) -> jstring {
    let result = catch_panic(move || {
        // `SwarmBuilder::with_tokio()` (inside `start_network`) needs a Tokio runtime context to be active as a thread-local. This JNI call runs on a raw
        // JNI thread, so calling it without setting up the context by hand with `RUNTIME.enter()` panics (see the `catch_panic` docs: JNI calls can come
        // from any Java/Kotlin thread, so the context must be set up in EVERY JNI export. Entering on one thread does not affect another).
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.start_network(node_mode != 0, tor_enabled != 0)
    });
    match result {
        Ok(Ok(pid)) => safe_new_jstring(&mut env, pid),
        Ok(Err(e)) => safe_new_jstring(&mut env, format!("Error: {}", e)),
        Err(e) => safe_new_jstring(&mut env, format!("Error: {}", e)),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setNodeMode(_env: JNIEnv, _class: JClass, enabled: jboolean) {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.set_node_mode(enabled != 0);
    });
}

/// The `node_address` the other side can dial: onion address only (`/dns/<host>.onion/tcp/<port>/p2p/<peer_id>`, see `P2PCore::get_node_address`).
/// While the onion service is not yet published (Tor still bootstrapping, no network), this returns an empty string. A listen address is NEVER
/// returned. Kotlin must show "connecting" in that case.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getNodeAddress<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.get_node_address().unwrap_or_default()
    });
    let addr = result.unwrap_or_else(|e| { error!("getNodeAddress panicked: {}", e); String::new() });
    safe_new_jstring(&mut env, addr)
}

/// Debug APKs only (`P2PLib` init): a release installs no logger, so nothing reaches logcat.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_enableLogging<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) {
    let _ = catch_panic(|| android_logger::init_once(LogConfig::default().with_max_level(log::LevelFilter::Info)));
}

/// Tor status for the UI. Returns one of: "disabled" | "bootstrapping" | "ready" | "ready|<host>.onion" | "failed".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_torStatus<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.tor_status()
    });
    let out = result.unwrap_or_else(|e| { error!("torStatus panicked: {}", e); "failed".to_string() });
    safe_new_jstring(&mut env, out)
}

/// This device's OWN overall connection status (not the other side's). JSON: `{"connected_peers": N, "listening": bool, "tor_enabled": bool,
/// "tor_status": "...", "node_mode": bool}` (see `P2PCore::own_connection_status`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_ownConnectionStatus<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.own_connection_status().to_string()
    });
    let out = result.unwrap_or_else(|e| { error!("ownConnectionStatus panicked: {}", e); "{}".to_string() });
    safe_new_jstring(&mut env, out)
}

/// For the "connecting..." indicator in ChatActivity. See `P2PCore::has_active_session`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_hasActiveSession<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) -> jboolean {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock_read();
        core.has_active_session(&fp)
    });
    result.unwrap_or(false) as jboolean
}

/// The REAL live connection status (see `P2PCore::is_peer_connected`). Unlike `hasActiveSession`, it does not stay `true` forever once a session has
/// been set up. It mirrors the current connection table of the `Swarm`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_isPeerConnected<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) -> jboolean {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock_read();
        core.is_peer_connected(&fp)
    });
    result.unwrap_or(false) as jboolean
}

/// Starts the handshake proactively when a chat screen opens. See `P2PCore::ensure_handshake`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_ensureHandshake<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        if let Err(e) = core.ensure_handshake(&fp) {
            error!("ensure_handshake failed: {}", e);
        }
    });
}

/// Called when the chat screen finds no local history on a device with node mode off. See `P2PCore::request_history_sync`. The reply arrives
/// asynchronously (a `"history_sync"` event via `pollNetwork`), so this function returns at once without waiting for the result.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_requestHistorySync<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, limit: jni::sys::jint) {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let limit_u32 = limit.clamp(0, MAX_HISTORY_PAGE) as u32;
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        if let Err(e) = core.request_history_sync(fp, limit_u32) {
            error!("request_history_sync failed: {}", e);
        }
    });
}

/// Chat open: see `P2PCore::refresh_chat_from_siblings`. Returns at once; rows come as events.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_refreshChatFromSiblings<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, chat_key: JString<'local>, is_group: jni::sys::jboolean) {
    let key: String = jstr(&mut env, &chat_key).unwrap_or_default();
    let group = is_group != 0;
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().refresh_chat_from_siblings(&key, group);
    });
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_pollNetwork<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jobjectArray {
    let result = catch_panic(|| {
        // `poll_events` already uses `RUNTIME.block_on(...)` itself (which sets up the context). For consistency, it also enters here.
        let _guard = RUNTIME.enter();
        CORE_DIRTY.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut core = core_lock_poll();
        core.poll_events()
    });
    let mut texts = result.unwrap_or_else(|e| { error!("pollNetwork panicked: {}", e); Vec::new() });
    // events of a turn whose array could not be built (Java heap
    // pressure) go out with the next turn instead of being lost.
    static UNDELIVERED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let mut held = UNDELIVERED.lock().unwrap_or_else(|p| p.into_inner());
    if !held.is_empty() {
        let mut all = std::mem::take(&mut *held);
        all.append(&mut texts);
        texts = all;
    }
    let array = strings_to_jobjectarray(&mut env, &texts);
    if array.is_null() && !texts.is_empty() {
        // ponytail: bounded at 4096 events; the oldest go first.
        let excess = texts.len().saturating_sub(4096);
        texts.drain(..excess);
        *held = texts;
        // A pending OutOfMemoryError must not reach Kotlin as a non-null
        // return: an empty array when it can be made.
        let _ = env.exception_clear();
        return strings_to_jobjectarray(&mut env, &[]);
    }
    array
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_addKnownRelayAddress<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, multiaddr: JString<'local>) -> jstring {
    let multiaddr_str: String = jstr(&mut env, &multiaddr).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.add_known_relay_address(&multiaddr_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("add_known_relay_address failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("add_known_relay_address panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// Battery fix: opened when the screen is off and the app is in the background (see `set_power_save`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setPowerSave(mut _env: JNIEnv, _class: JClass, enabled: jboolean) {
    let on = enabled != 0;
    let _ = catch_panic(move || core_lock().set_power_save(on));
}

/// Called by Kotlin when the app comes to the foreground (see the `P2PApplication` foreground detection). See `P2PCore::retry_all_pending_now`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_retryAllPendingNow(_env: JNIEnv, _class: JClass) {
    let _ = catch_panic(|| {
        let mut core = core_lock();
        core.retry_all_pending_now();
    });
}

/// Ends a running `wait_for_network_activity` without taking the core lock.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_wakePoll(_env: JNIEnv, _class: JClass) {
    CORE_DIRTY.store(true, std::sync::atomic::Ordering::SeqCst);
    NET_WAKE.notify_waiters();
}

/// see `wait_for_network_activity`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_waitForNetworkActivity(_env: JNIEnv, _class: JClass, timeout_ms: jlong) {
    let _ = catch_panic(|| wait_for_network_activity(timeout_ms.max(0) as u64));
}

/// Metered (cellular) network or not — with the screen off this is
/// radio-saver mode, see `RADIO_WINDOW_MS`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setMeteredNetwork(_env: JNIEnv, _class: JClass, metered: jboolean) {
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_metered(metered != 0);
    });
}

/// Called from Kotlin on a network interface change (Wi-Fi to cellular, or any default-network change). See `P2PCore::reconnect_all_known_now`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_notifyNetworkChanged(_env: JNIEnv, _class: JClass) {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.reconnect_all_known_now();
    });
}

/// See api `set_tor_transport`. Kotlin calls it right before `startNetwork`, with `nativeLibraryDir` as `ptDir`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setTorTransport<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, mode: JString<'local>, bridges: JString<'local>, pt_dir: JString<'local>) -> jstring {
    let mode = jstr(&mut env, &mode).unwrap_or_default();
    let bridges = jstr(&mut env, &bridges).unwrap_or_default();
    let pt_dir = jstr(&mut env, &pt_dir).unwrap_or_default();
    let out = crate::api::set_tor_transport(&mode, &bridges, &pt_dir);
    safe_new_jstring(&mut env, out)
}

/// See api `validate_bridge_lines`: "OK" or "Error: line N: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_validateBridgeLines<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, text: JString<'local>) -> jstring {
    let text = jstr(&mut env, &text).unwrap_or_default();
    let out = crate::api::validate_bridge_lines(&text);
    safe_new_jstring(&mut env, out)
}

/// See api `tor_transport_available`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_torTransportAvailable<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, mode: JString<'local>, pt_dir: JString<'local>) -> jboolean {
    let mode = jstr(&mut env, &mode).unwrap_or_default();
    let pt_dir = jstr(&mut env, &pt_dir).unwrap_or_default();
    crate::api::tor_transport_available(&mode, &pt_dir) as jboolean
}

/// See api `tor_bridge_in_use`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_torBridgeInUse<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jboolean {
    crate::api::tor_bridge_in_use() as jboolean
}
