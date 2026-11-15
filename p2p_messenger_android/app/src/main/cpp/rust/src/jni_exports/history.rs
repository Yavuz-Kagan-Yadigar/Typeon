//! JNI: message history pages and chat list previews.

use super::*;

/// Decrypts the local encrypted message history with a contact and returns it as JSON (`List<ArchivedMessage>`). Returns an empty array if
/// `history_key` is not loaded or there are no archived messages with this contact. That is not an error (node mode may never have been turned on).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getMessageHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, limit: jni::sys::jint) -> jstring {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        // lock dropped before the JSON is built.
        let history = core_lock_read().load_message_history(&fp, limit.clamp(0, MAX_HISTORY_PAGE) as u32, None);
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getMessageHistory panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// only messages archived after `after_timestamp` (the newest
/// `timestamp` the screen holds), newest `limit` of them, oldest first.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getMessageHistorySince<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, after_timestamp: jlong, limit: jni::sys::jint) -> jstring {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let history = core_lock_read().load_message_history_since(&fp, after_timestamp, limit.clamp(0, MAX_HISTORY_PAGE) as u32);
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getMessageHistorySince panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// group twin of `getMessageHistorySince`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getGroupMessageHistorySince<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, after_timestamp: jlong, limit: jni::sys::jint) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let result = catch_panic(move || {
        let history = core_lock_read().load_group_message_history_since(&gid, after_timestamp, limit.clamp(0, MAX_HISTORY_PAGE) as u32);
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getGroupMessageHistorySince panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// `{"contacts":{<identity_id>:{"peer","message","attachment"}}, "groups":{<group_id>:{"message","attachment"}}}`. `message` is an
/// `ArchivedMessage` (no reactions or seen-by), `attachment` an `AttachmentSummary` (no preview). Either may be null.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_chatListPreviews<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let previews = core_lock_read().chat_list_previews();
        previews.to_string()
    });
    let json = result.unwrap_or_else(|e| { error!("chatListPreviews panicked: {}", e); r#"{"contacts":{},"groups":{}}"#.to_string() });
    safe_new_jstring(&mut env, json)
}

/// Call this FIRST when the chat history is scrolled to the top. If the LOCAL archive already has messages older than `before_timestamp`, it returns
/// them (free, no network). If it returns nothing or fewer than the limit, the Kotlin side should ask the other side for the rest over the network
/// with `requestOlderMessageHistory`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getMessageHistoryBefore<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, before_timestamp: jlong, limit: jni::sys::jint) -> jstring {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        // lock dropped before the JSON is built.
        let history = core_lock_read().load_message_history(&fp, limit.clamp(0, MAX_HISTORY_PAGE) as u32, Some(before_timestamp));
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getMessageHistoryBefore panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// See the note on `getMessageHistoryBefore`: same, for the group archive. If nothing is found or the result is empty, Kotlin asks over the network
/// with `requestOlderGroupMessageHistory`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getGroupMessageHistoryBefore<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, before_timestamp: jlong, limit: jni::sys::jint) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let result = catch_panic(move || {
        // lock dropped before the JSON is built.
        let history = core_lock_read().load_group_message_history(&gid, limit.clamp(0, MAX_HISTORY_PAGE) as u32, Some(before_timestamp));
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getGroupMessageHistoryBefore panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// Group counterpart of `getMessageHistory`. Must be called when `GroupChatActivity` opens. Otherwise (previous behaviour) the screen starts empty each
/// time and only shows messages that arrive or are sent while it is open (see `load_group_message_history`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getGroupMessageHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, limit: jni::sys::jint) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let result = catch_panic(move || {
        // lock dropped before the JSON is built.
        let history = core_lock_read().load_group_message_history(&gid, limit.clamp(0, MAX_HISTORY_PAGE) as u32, None);
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getGroupMessageHistory panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}
