//! JNI: store-and-forward server option.

use super::*;

// ---------------------------------------------------------------------------
// Server (store-and-forward) option. See the `server_client` module.
// ---------------------------------------------------------------------------

/// Adds a server from an invite code (`typeon-server:<multiaddr>#<token>`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_addServer<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, invite_code: JString<'local>) -> jstring {
    let code: String = jstr(&mut env, &invite_code).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().add_server(&code)
    });
    let out = coded(result).unwrap_or_else(|e| e);
    safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_removeServer<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, server_id: JString<'local>) -> jstring {
    let sid: String = jstr(&mut env, &server_id).unwrap_or_default();
    let result = catch_panic(move || core_lock().remove_server(&sid));
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    };
    safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listServers<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| core_lock_read().list_servers_json());
    let json = result.unwrap_or_else(|e| {
        error!("listServers: {}", e);
        "[]".to_string()
    });
    safe_new_jstring(&mut env, json)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setServerRouting<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, server_id: JString<'local>, enabled: jboolean) -> jstring {
    let sid: String = jstr(&mut env, &server_id).unwrap_or_default();
    let on = enabled != 0;
    let result = catch_panic(move || core_lock().set_server_routing(&sid, on));
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    };
    safe_new_jstring(&mut env, out)
}

/// Keeping history on the server. Separate from message relaying, and OFF by default. The archive is a real backup, and unlike the ratchet it is NOT
/// forward-secret (see the `server_seal::seal_archive_record` note).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setServerHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, server_id: JString<'local>, enabled: jboolean) -> jstring {
    let sid: String = jstr(&mut env, &server_id).unwrap_or_default();
    let on = enabled != 0;
    let result = catch_panic(move || core_lock().set_server_history(&sid, on));
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    };
    safe_new_jstring(&mut env, out)
}

/// One chat's older history from the server archive, on a user action only
/// (see `server_client::fetch_server_history`). `chat_key`: the peer device
/// fingerprint, or the group id. "OK" or "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_fetchServerHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, chat_key: JString<'local>, is_group: jboolean, before_timestamp: jlong) -> jstring {
    let key: String = jstr(&mut env, &chat_key).unwrap_or_default();
    let group = is_group != 0;
    let result = catch_panic(move || core_lock().fetch_server_history(&key, group, before_timestamp.max(0) as u64));
    let out = match coded(result) {
        Ok(()) => "OK".to_string(),
        Err(e) => e,
    };
    safe_new_jstring(&mut env, out)
}

/// Downloads the WHOLE history from the server. Used for recovery from a recovery file, or for a device freshly set up by linking. Returns how many
/// chats were requested.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_restoreServerHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| core_lock().restore_all_server_history());
    let out = match result {
        Ok(Ok(n)) => format!("OK:{}", n),
        Ok(Err(e)) => format!("Error: {}", e),
        Err(e) => format!("Error: {}", e),
    };
    safe_new_jstring(&mut env, out)
}

/// Loads the root archive key (ARK). Same pattern as `setHistoryKey`, but this key belongs to the IDENTITY, not the device
/// (see `set_archive_root_key`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setArchiveRootKey<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, key_bytes: JByteArray<'local>) -> jboolean {
    let key = zeroize::Zeroizing::new(jbytearray_to_vec(&mut env, &key_bytes));
    let result = catch_panic(move || core_lock().set_archive_root_key(&key));
    result.unwrap_or(false) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_archiveRootKey<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jbyteArray {
    let key = zeroize::Zeroizing::new(catch_panic(|| core_lock_read().archive_root_key_bytes().unwrap_or_default()).unwrap_or_default());
    bytes_to_jbytearray(&mut env, &key)
}
