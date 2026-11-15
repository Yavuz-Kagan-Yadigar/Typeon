//! JNI: contacts, device alerts, blocking and trust.

use super::*;

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listContacts<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        let contacts = core.list_contacts();
        serde_json::to_string(&contacts).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listContacts panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// Clears the local history (messages and attachments) of one chat, but KEEPS the pairing. See `P2PCore::clear_chat_history`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_clearChatHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, contact_id: JString<'local>) -> jstring {
    let contact_id_str: String = jstr(&mut env, &contact_id).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.clear_chat_history(&contact_id_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("clear_chat_history failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("clear_chat_history panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// Deletes a contact COMPLETELY, including the pairing. See `P2PCore::delete_contact`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deleteContact<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, contact_id: JString<'local>) -> jstring {
    let contact_id_str: String = jstr(&mut env, &contact_id).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.delete_contact(&contact_id_str, true)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("delete_contact failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("delete_contact panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// Revokes ONE device of a contact (does NOT delete the contact or its history). See `P2PCore::revoke_contact_device`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_revokeContactDevice<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, contact_id: JString<'local>, device_fingerprint: JString<'local>) -> jstring {
    let contact_id_str: String = jstr(&mut env, &contact_id).unwrap_or_default();
    let fp_str: String = jstr(&mut env, &device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.revoke_contact_device(&contact_id_str, &fp_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("revoke_contact_device failed: {}", e); coded_error(&e) }
        Err(e) => { error!("revoke_contact_device panicked: {}", e); coded_error(&format!("panic: {}", e)) }
    };
    safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listPendingDeviceAlerts<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        let alerts = core.list_pending_device_alerts();
        serde_json::to_string(&alerts).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listPendingDeviceAlerts panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_acceptDeviceAlert<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, fingerprint: JString<'local>) -> jboolean {
    let fp: String = jstr(&mut env, &fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.accept_pending_device_alert(&fp).map_err(|e| error!("accept_pending_device_alert failed: {}", e)).is_ok()
    });
    result.unwrap_or(false) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_rejectDeviceAlert(mut _env: JNIEnv, _class: JClass, fingerprint: JString) {
    let fp: String = jstr(&mut _env, &fingerprint).unwrap_or_default();
    let _ = catch_panic(move || {
        let mut core = core_lock();
        core.reject_pending_device_alert(&fp);
    });
}

/// Blocks a contact (see `block_identity`). Unlike `revoke`, this is persistent. It is lifted only by a face-to-face re-pairing.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_blockIdentity<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, identity_id: JString<'local>) -> jstring {
    let id: String = jstr(&mut env, &identity_id).unwrap_or_default();
    let result = catch_panic(move || core_lock().block_identity(&id));
    match result {
        Ok(Ok(())) => safe_new_jstring(&mut env, "OK"),
        Ok(Err(e)) => safe_new_jstring(&mut env, format!("Error: {}", e)),
        Err(e) => safe_new_jstring(&mut env, format!("Error: {}", e)),
    }
}

/// Lifts a block. The UI must call this only on the user's explicit request. No packet from the network can reach this path.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_unblockIdentity(mut _env: JNIEnv, _class: JClass, identity_id: JString) {
    let id: String = jstr(&mut _env, &identity_id).unwrap_or_default();
    if let Err(e) = catch_panic(move || core_lock().unblock_identity(&id)) {
        error!("unblockIdentity: {}", e);
    }
}

/// Engellenen kimliklerin listesi (JSON dizisi).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listBlockedIdentities<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        serde_json::to_string(&core_lock_read().list_blocked_identities()).unwrap_or_else(|_| "[]".to_string())
    });
    safe_new_jstring(&mut env, result.unwrap_or_else(|e| { error!("listBlockedIdentities panicked: {}", e); "[]".to_string() }))
}

/// The safety code to compare for a contact (see `contact_safety_code`). An empty string if the contact or device cannot be resolved.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_contactSafetyCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, identity_id: JString<'local>) -> jstring {
    let id: String = jstr(&mut env, &identity_id).unwrap_or_default();
    let result = catch_panic(move || core_lock_read().contact_safety_code(&id).unwrap_or_default());
    safe_new_jstring(&mut env, result.unwrap_or_default())
}

/// Gives full trust to a contact met through a group (see `trust_contact`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_trustContact<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, contact_id: JString<'local>) -> jstring {
    let cid: String = jstr(&mut env, &contact_id).unwrap_or_default();
    let result = catch_panic(move || core_lock().trust_contact(&cid));
    match result {
        Ok(Ok(())) => safe_new_jstring(&mut env, "OK"),
        Ok(Err(e)) => safe_new_jstring(&mut env, format!("Error: {}", e)),
        Err(e) => safe_new_jstring(&mut env, format!("Error: {}", e)),
    }
}
