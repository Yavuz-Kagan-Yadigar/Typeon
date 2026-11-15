//! JNI: storage usage, limits and pruning.

use super::*;

/// For the history/attachment storage limit slider in Settings (100 MB to 32 GB). See `set_history_storage_limit_bytes`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setHistoryStorageLimitBytes(_env: JNIEnv, _class: JClass, bytes: jlong) {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        // 0 or less is a failed pref read, never a choice (the slider starts
        // at 100 MB): as a limit it would delete every stored attachment.
        if bytes <= 0 {
            return;
        }
        let mut core = core_lock();
        core.set_history_storage_limit_bytes(bytes as u64);
    });
}

/// See `P2PCore::storage_usage`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_storageUsage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let json = catch_panic(|| core_lock_read().storage_usage().to_string())
        .unwrap_or_else(|e| { error!("storageUsage panicked: {}", e); "{}".to_string() });
    safe_new_jstring(&mut env, json)
}

/// See `P2PCore::chat_prune_stats`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_chatPruneStats<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, kind: JString<'local>, id: JString<'local>, before_ms: jlong) -> jstring {
    let kind: String = jstr(&mut env, &kind).unwrap_or_default();
    let id: String = jstr(&mut env, &id).unwrap_or_default();
    let json = catch_panic(move || core_lock_read().chat_prune_stats(&kind, &id, before_ms).to_string())
        .unwrap_or_else(|e| { error!("chatPruneStats panicked: {}", e); "{}".to_string() });
    safe_new_jstring(&mut env, json)
}

/// See `P2PCore::prune_chat_before`. "OK" or "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_pruneChatBefore<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, kind: JString<'local>, id: JString<'local>, before_ms: jlong) -> jstring {
    let kind: String = jstr(&mut env, &kind).unwrap_or_default();
    let id: String = jstr(&mut env, &id).unwrap_or_default();
    let result = catch_panic(move || core_lock().prune_chat_before(&kind, &id, before_ms));
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) | Err(e) => { error!("pruneChatBefore: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// Drops this device's copy of each attachment in `file_ids_json` (a JSON
/// array), see `P2PCore::remove_local_attachment`. "OK" or the first "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_removeLocalAttachments<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_ids_json: JString<'local>) -> jstring {
    let ids_json: String = jstr(&mut env, &file_ids_json).unwrap_or_default();
    let result = catch_panic(move || {
        let ids: Vec<String> = serde_json::from_str(&ids_json).map_err(|e| e.to_string())?;
        let mut core = core_lock();
        // One bad id does not stop the rest.
        let mut first_err = None;
        for id in &ids {
            if let Err(e) = core.remove_local_attachment(id) {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) | Err(e) => { error!("removeLocalAttachments: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}
