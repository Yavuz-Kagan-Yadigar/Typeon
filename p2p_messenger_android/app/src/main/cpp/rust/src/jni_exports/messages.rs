//! JNI: sending, editing, reacting, deleting, typing, seen, pending queue.

use super::*;

/// Multi-device (1.7.1): when a chat is read, tell the sibling devices it was read. For 1:1, `peerDeviceFingerprint` is set and `groupId` is empty;
/// for a group it is the reverse. Fire-and-forget.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_syncReadState<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, group_id: JString<'local>, read_at_ms: jlong) {
    let peer: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.sync_read_state(&peer, &gid, read_at_ms.max(0) as u64);
    });
}

/// The chat's disappearing mode in seconds, 0 = off (see `disappear_mode`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getDisappearMode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, group_id: JString<'local>) -> jlong {
    let peer: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    catch_panic(move || core_lock_read().disappear_mode(&peer, &gid).unwrap_or(0) as jlong).unwrap_or(0)
}

/// Turns the chat's disappearing mode on (`secs`) or off (0).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setDisappearMode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, group_id: JString<'local>, secs: jlong) {
    let peer: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let secs = u32::try_from(secs).unwrap_or(0);
    let _ = catch_panic(move || core_lock_read().set_disappear_mode(&peer, &gid, secs));
}

/// Disappearing messages on screen start counting down (see `start_expiry_on_screen`). Local only, nothing is sent.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_startDisappearCountdown<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, group_id: JString<'local>) {
    let peer: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let _ = catch_panic(move || core_lock_read().start_expiry_on_screen(&peer, &gid));
}

/// Returns `{"message_id":"...","status":"sent"|"pending"}` on success, or `"Error: ..."`. `status` lets the UI show the send icon (clock or tick)
/// correctly at once. If it is "pending", it will be retried in the background and updated by a "status" event (see pollNetwork).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, msg: JString<'local>, reply_to_message_id: JString<'local>, reply_to_preview: JString<'local>, expire_secs: jlong) -> jstring {
    let target_str: String = jstr(&mut env, &target).unwrap_or_default();
    // Always explicit from Kotlin: 0 = an ordinary message, else the timer (see `MessageContent::Text.expire_secs`).
    // Negative = the chat's mode. So the message matches the bubble Kotlin draws, even if the mode changed meanwhile.
    let expire_secs = u32::try_from(expire_secs).ok();
    let msg_str: String = jstr(&mut env, &msg).unwrap_or_default();
    // See the `optional_jstring` docs: WhatsApp-style reply. If there is no reply, Kotlin passes `null`.
    let reply_id_opt = optional_jstring(&mut env, &reply_to_message_id);
    let reply_preview_opt = optional_jstring(&mut env, &reply_to_preview);
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_message(target_str, msg_str, reply_id_opt, reply_preview_opt, expire_secs)
    });
    match result {
        Ok(Ok((message_id, status))) => safe_new_jstring(&mut env, serde_json::json!({"message_id": message_id, "status": status}).to_string()),
        Ok(Err(e)) => { error!("send_message failed: {}", e); safe_new_jstring(&mut env, coded_error(&e)) }
        Err(e) => { error!("send_message panicked: {}", e); safe_new_jstring(&mut env, coded_error(&format!("panic: {}", e))) }
    }
}

/// Edits a message. See the `P2PCore::edit_message` docs. Returns the same JSON shape as `sendMessage`. This is the edit packet's OWN message_id.
/// The UI should keep using the ORIGINAL message's id (see ChatActivity).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_editMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, target_message_id: JString<'local>, new_text: JString<'local>) -> jstring {
    let target_str: String = jstr(&mut env, &target).unwrap_or_default();
    let target_message_id_str: String = jstr(&mut env, &target_message_id).unwrap_or_default();
    let new_text_str: String = jstr(&mut env, &new_text).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.edit_message(target_str, target_message_id_str, new_text_str)
    });
    match result {
        Ok(Ok((message_id, status))) => safe_new_jstring(&mut env, serde_json::json!({"message_id": message_id, "status": status}).to_string()),
        Ok(Err(e)) => { error!("edit_message failed: {}", e); safe_new_jstring(&mut env, coded_error(&e)) }
        Err(e) => { error!("edit_message panicked: {}", e); safe_new_jstring(&mut env, coded_error(&format!("panic: {}", e))) }
    }
}

/// Adds or removes an emoji reaction on a message. See `P2PCore::react_to_message`. An empty `emoji` removes my own reaction. The return value is
/// the message's CURRENT reaction summary (e.g. `"👍2 ❤️"`), so the caller does not need a second query.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_reactToMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, target_message_id: JString<'local>, emoji: JString<'local>) -> jstring {
    let target_str: String = jstr(&mut env, &target).unwrap_or_default();
    let target_message_id_str: String = jstr(&mut env, &target_message_id).unwrap_or_default();
    let emoji_str: String = jstr(&mut env, &emoji).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.react_to_message(target_str, target_message_id_str, emoji_str)
    });
    match result {
        Ok(Ok(summary)) => safe_new_jstring(&mut env, summary),
        Ok(Err(e)) => { error!("react_to_message failed: {}", e); safe_new_jstring(&mut env, format!("Error: {}", e)) }
        Err(e) => { error!("react_to_message panicked: {}", e); safe_new_jstring(&mut env, format!("Error: {}", e)) }
    }
}

/// See `P2PCore::list_reactions`. Used to fill the "who reacted with what" list when the reaction pill is tapped.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listReactions<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target_message_id: JString<'local>) -> jstring {
    let id: String = jstr(&mut env, &target_message_id).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock_read();
        core.list_reactions(&id)
    });
    let json = result.unwrap_or_else(|e| { error!("list_reactions panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// See `P2PCore::top_reactions`. The emojis of the double-tap quick-reaction bar.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_topReactions<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let json = crate::api::top_reactions();
    safe_new_jstring(&mut env, json)
}

/// See `P2PCore::seen_by_json`. Fills the "who saw it, when" list when the seen avatars are tapped.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listSeenBy<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, message_id: JString<'local>) -> jstring {
    let id: String = jstr(&mut env, &message_id).unwrap_or_default();
    let result = catch_panic(move || core_lock_read().seen_by_json(&id));
    let json = result.unwrap_or_else(|e| { error!("list_seen_by panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// See `reactToMessage`: group counterpart.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_reactToGroupMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, target_message_id: JString<'local>, emoji: JString<'local>) -> jstring {
    let group_id_str: String = jstr(&mut env, &group_id).unwrap_or_default();
    let target_message_id_str: String = jstr(&mut env, &target_message_id).unwrap_or_default();
    let emoji_str: String = jstr(&mut env, &emoji).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.react_to_group_message(group_id_str, target_message_id_str, emoji_str)
    });
    match result {
        Ok(Ok(summary)) => safe_new_jstring(&mut env, summary),
        Ok(Err(e)) => { error!("react_to_group_message failed: {}", e); safe_new_jstring(&mut env, format!("Error: {}", e)) }
        Err(e) => { error!("react_to_group_message panicked: {}", e); safe_new_jstring(&mut env, format!("Error: {}", e)) }
    }
}

/// Deletes a message. See `P2PCore::delete_message`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deleteMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, target_message_id: JString<'local>) -> jstring {
    let target_str: String = jstr(&mut env, &target).unwrap_or_default();
    let target_message_id_str: String = jstr(&mut env, &target_message_id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.delete_message(target_str, target_message_id_str)
    });
    match result {
        Ok(Ok((message_id, status))) => safe_new_jstring(&mut env, serde_json::json!({"message_id": message_id, "status": status}).to_string()),
        Ok(Err(e)) => { error!("delete_message failed: {}", e); safe_new_jstring(&mut env, coded_error(&e)) }
        Err(e) => { error!("delete_message panicked: {}", e); safe_new_jstring(&mut env, coded_error(&format!("panic: {}", e))) }
    }
}

/// See the note on `editMessage`, for group messages (see `P2PCore::edit_group_message`). `targetGroupMessageLocalId` is explained in the GroupChatActivity
/// note: the `messageId` of a sent group message is already this value.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_editGroupMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, target_group_message_local_id: JString<'local>, new_text: JString<'local>) -> jstring {
    let group_id_str: String = jstr(&mut env, &group_id).unwrap_or_default();
    let target_str: String = jstr(&mut env, &target_group_message_local_id).unwrap_or_default();
    let new_text_str: String = jstr(&mut env, &new_text).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.edit_group_message(group_id_str, target_str, new_text_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("edit_group_message failed: {}", e); coded_error(&e) }
        Err(e) => { error!("edit_group_message panicked: {}", e); coded_error(&format!("panic: {}", e)) }
    };
    safe_new_jstring(&mut env, out)
}

/// See the note on `deleteMessage`, for group messages (see `P2PCore::delete_group_message`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deleteGroupMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, target_group_message_local_id: JString<'local>) -> jstring {
    let group_id_str: String = jstr(&mut env, &group_id).unwrap_or_default();
    let target_str: String = jstr(&mut env, &target_group_message_local_id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.delete_group_message(group_id_str, target_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("delete_group_message failed: {}", e); coded_error(&e) }
        Err(e) => { error!("delete_group_message panicked: {}", e); coded_error(&format!("panic: {}", e)) }
    };
    safe_new_jstring(&mut env, out)
}

/// Sends a "typing..." indicator. See `P2PCore::send_typing_indicator`. It may fail silently on purpose (fire-and-forget). The `Boolean` return is for
/// debugging only, and the Kotlin side usually does not check it.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendTypingIndicator<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, is_typing: jboolean) -> jboolean {
    let target_str: String = jstr(&mut env, &target).unwrap_or_default();
    let typing = is_typing != 0;
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_typing_indicator(target_str, typing)
    });
    match result {
        Ok(Ok(())) => true as jboolean,
        Ok(Err(e)) => { error!("send_typing_indicator failed: {}", e); false as jboolean }
        Err(e) => { error!("send_typing_indicator panicked: {}", e); false as jboolean }
    }
}

/// See `sendTypingIndicator`: for group chats (see `P2PCore::send_group_typing_indicator`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendGroupTypingIndicator<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, is_typing: jboolean) -> jboolean {
    let group_id_str: String = jstr(&mut env, &group_id).unwrap_or_default();
    let typing = is_typing != 0;
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_group_typing_indicator(group_id_str, typing)
    });
    match result {
        Ok(Ok(())) => true as jboolean,
        Ok(Err(e)) => { error!("send_group_typing_indicator failed: {}", e); false as jboolean }
        Err(e) => { error!("send_group_typing_indicator panicked: {}", e); false as jboolean }
    }
}

/// Sends a "seen" receipt. See `P2PCore::send_seen`. The UI must call it when a message is actually shown on screen (not automatically, unlike `Ack`).
/// For a 1:1 chat, pass `null` for `group_message_local_id`. For a group chat, send back the SAME value from the "group_message" event.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendSeenReceipt<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, target_message_id: JString<'local>, group_message_local_id: JString<'local>) -> jboolean {
    let target_str: String = jstr(&mut env, &target).unwrap_or_default();
    let target_message_id_str: String = jstr(&mut env, &target_message_id).unwrap_or_default();
    let local_id: Option<String> = if group_message_local_id.is_null() {
        None
    } else {
        jstr(&mut env, &group_message_local_id)
    };
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_seen(&target_str, &target_message_id_str, local_id)
    });
    result.unwrap_or(false) as jboolean
}

/// JSON-encoded `List<PendingMessageSummary>` for the "pending messages" list in Settings (see `P2PCore::list_pending_messages`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listPendingMessages<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        let pending = core.list_pending_messages();
        serde_json::to_string(&pending).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listPendingMessages panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// See `P2PCore::cancel_pending_message`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_cancelPendingMessage(mut env: JNIEnv, _class: JClass, message_id: JString) -> jboolean {
    let id: String = jstr(&mut env, &message_id).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.cancel_pending_message(&id).is_ok()
    });
    result.unwrap_or(false) as jboolean
}

/// See `P2PCore::retry_pending_message_now`: the manual "Retry now" button in the pending messages list in Settings.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_retryPendingMessageNow(mut env: JNIEnv, _class: JClass, message_id: JString) -> jboolean {
    let id: String = jstr(&mut env, &message_id).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.retry_pending_message_now(&id).is_ok()
    });
    result.unwrap_or(false) as jboolean
}
