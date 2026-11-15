//! JNI: groups.

use super::*;

/// Hands the group founder role to another member (see `transfer_group_founder`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_transferGroupFounder<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, new_founder: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let nf: String = jstr(&mut env, &new_founder).unwrap_or_default();
    let result = catch_panic(move || core_lock().transfer_group_founder(&gid, &nf));
    let out = coded(result).map_or_else(|e| e, |()| "OK".to_string());
    safe_new_jstring(&mut env, out)
}

/// JSON-encoded `List<GroupSummary>` for the Groups tab UI.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listGroups<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        let groups = core.list_groups();
        serde_json::to_string(&groups).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listGroups panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_createGroup<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, name: JString<'local>) -> jstring {
    let name_str: String = jstr(&mut env, &name).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.create_group(name_str)
    });
    let out = coded(result).unwrap_or_else(|e| e);
    safe_new_jstring(&mut env, out)
}

/// 1 = the failed copies went out again, 0 = nothing recorded for this id
/// (send as a new message), -1 = recorded but nothing could be sent.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_retryGroupMessageCopies<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, local_id: JString<'local>) -> jni::sys::jint {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let lid: String = jstr(&mut env, &local_id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().retry_group_message_copies(&gid, &lid)
    });
    match result {
        Ok(Ok(true)) => 1,
        Ok(Ok(false)) => 0,
        Ok(Err(e)) => { error!("retry_group_message_copies failed: {}", e); -1 }
        Err(e) => { error!("retry_group_message_copies panicked: {}", e); -1 }
    }
}

/// Returns "OK" or "Error: CODE: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_inviteToGroup<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, identity_id: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let iid: String = jstr(&mut env, &identity_id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.invite_to_group(&gid, &iid).map(|_| ())
    });
    let out = coded(result).map_or_else(|e| { error!("invite_to_group failed: {}", e); e }, |()| "OK".to_string());
    safe_new_jstring(&mut env, out)
}

/// Returns "OK" or "Error: CODE: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_removeFromGroup<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, identity_id: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let iid: String = jstr(&mut env, &identity_id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.remove_from_group(&gid, &iid, true).map(|_| ())
    });
    let out = coded(result).map_or_else(|e| { error!("remove_from_group failed: {}", e); e }, |()| "OK".to_string());
    safe_new_jstring(&mut env, out)
}

/// Deletes the group for ALL members (founder only). See `P2PCore::delete_group`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deleteGroup<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.delete_group(&gid)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("delete_group failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("delete_group panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// The founder re-sends the current group state to every member device. See `P2PCore::resend_group_to_all`. "OK" / "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_resendGroupToAll<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().resend_group_to_all(&gid)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("resend_group_to_all failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("resend_group_to_all panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// A member who is NOT the founder leaves the group on its own request. See `P2PCore::leave_group`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_leaveGroup<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.leave_group(&gid)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("leave_group failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("leave_group panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// Sets or removes the group profile picture. See `P2PCore::set_group_avatar`. Succeeds only for the founder. Otherwise it returns "Error: ...".
/// Unlike `inviteToGroup`/`removeFromGroup`, which return a `jboolean`, this returns a `jstring`, because the reason for a failure is worth showing the user.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setGroupProfilePicture<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, avatar_jpeg: JByteArray<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let avatar_vec: Option<Vec<u8>> = if avatar_jpeg.is_null() {
        None
    } else {
        Some(jbytearray_to_vec(&mut env, &avatar_jpeg))
    };
    // a failed copy arrives empty; do not publish an empty picture.
    if avatar_vec.as_ref().is_some_and(|v| v.is_empty()) {
        return safe_new_jstring(&mut env, "Error: empty picture");
    }
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.set_group_avatar(&gid, avatar_vec)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("set_group_avatar failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("set_group_avatar panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendGroupMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, msg: JString<'local>, reply_to_message_id: JString<'local>, reply_to_preview: JString<'local>, reply_to_sender_identity_id: JString<'local>, mentions_json: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let msg_str: String = jstr(&mut env, &msg).unwrap_or_default();
    // JSON array of mentioned identity ids; anything else means none.
    let mentions: Vec<String> = optional_jstring(&mut env, &mentions_json)
        .and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();
    // Same pattern as `optional_jstring` / `sendMessage`.
    let reply_id_opt = optional_jstring(&mut env, &reply_to_message_id);
    let reply_preview_opt = optional_jstring(&mut env, &reply_to_preview);
    let reply_sender_opt = optional_jstring(&mut env, &reply_to_sender_identity_id);
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_group_message(&gid, &msg_str, reply_id_opt, reply_preview_opt, reply_sender_opt, mentions)
    });
    let out = match result {
        Ok(Ok(local_id)) => local_id,
        Ok(Err(e)) => { error!("send_group_message failed: {}", e); coded_error(&e) }
        Err(e) => { error!("send_group_message panicked: {}", e); coded_error(&format!("panic: {}", e)) }
    };
    safe_new_jstring(&mut env, out)
}
