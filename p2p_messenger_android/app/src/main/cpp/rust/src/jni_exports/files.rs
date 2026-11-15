//! JNI: sending, downloading and listing attachments.

use super::*;

/// Sends a file, photo, video or audio attachment (see `P2PCore::prepare_and_send_file`). Kotlin must already have copied `source_path` to a local
/// file path (content:// URIs are not handled here). KNOWN LIMIT: this is a synchronous call. For large files, Kotlin must call it OFF the main
/// thread (coroutine / Dispatchers.IO), or there is an ANR risk. Returns the same JSON shape as `sendMessage`. The `message_id` field here is the `file_id`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_prepareAndSendFile<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, source_path: JString<'local>, file_name: JString<'local>, mime_type: JString<'local>, preview_jpeg: JByteArray<'local>, duration_ms: jni::sys::jint, caption: JString<'local>, reply_to_message_id: JString<'local>, reply_to_preview: JString<'local>) -> jstring {
    let target_str: String = jstr(&mut env, &target).unwrap_or_default();
    let source_str: String = jstr(&mut env, &source_path).unwrap_or_default();
    let name_str: String = jstr(&mut env, &file_name).unwrap_or_default();
    let mime_str: String = jstr(&mut env, &mime_type).unwrap_or_default();
    // Kotlin passes `null` for `preview_jpeg` for types other than photo and video (see P2PLib.kt). In JNI this is represented by the underlying
    // JObject being null.
    let preview_vec: Option<Vec<u8>> = if preview_jpeg.is_null() {
        None
    } else {
        Some(jbytearray_to_vec(&mut env, &preview_jpeg))
    };
    // Kotlin passes -1 for `duration_ms` for types other than voice messages (a jint cannot carry null). It is converted to `Option<u32>` here.
    let duration_opt: Option<u32> = if duration_ms < 0 { None } else { Some(duration_ms as u32) };
    // An optional caption and reply context.
    // Kotlin passes "no value" as an EMPTY string (a null JString would need a separate branch in JNI, which is needless complexity for three fields).
    // Empty strings are converted to `None` here.
    let caption_str: String = jstr(&mut env, &caption).unwrap_or_default();
    let reply_id: Option<String> = jstr(&mut env, &reply_to_message_id).filter(|v: &String| !v.is_empty());
    let reply_preview: Option<String> = jstr(&mut env, &reply_to_preview).filter(|v: &String| !v.is_empty());
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        // Lock splitting: the lock is NOT taken here. It is taken in the function's own short phases, so `poll_events` keeps running during encryption
        // (see `prepare_and_send_file_unlocked`).
        prepare_and_send_file_unlocked(target_str, source_str, name_str, mime_str, preview_vec, duration_opt, caption_str, reply_id, reply_preview)
    });
    match result {
        Ok(Ok((file_id, status))) => safe_new_jstring(&mut env, serde_json::json!({"message_id": file_id, "status": status}).to_string()),
        Ok(Err(e)) => { error!("prepare_and_send_file failed: {}", e); safe_new_jstring(&mut env, coded_error(&e)) }
        Err(e) => { error!("prepare_and_send_file panicked: {}", e); safe_new_jstring(&mut env, coded_error(&format!("panic: {}", e))) }
    }
}

/// Starts downloading a file's chunks. If it returns successfully ("OK"), progress and completion are reported through the `"file_progress"`,
/// `"file_complete"` and `"file_failed"` events from `pollNetwork` (see `P2PCore::download_file`). If it FAILS (`"Error: ..."`), it returns
/// synchronously right away, and NO event will come from `pollNetwork` (the download never started, so it was never added to `active_downloads`).
/// The caller must handle that itself (see the ChatActivity note). Before, this return value was a jboolean that Kotlin never checked, which left
/// the UI stuck on "Downloading" forever.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_downloadFile<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>, peer_device_fingerprint: JString<'local>) -> jstring {
    let file_id_str: String = jstr(&mut env, &file_id).unwrap_or_default();
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.download_file(file_id_str, fp)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("download_file failed: {}", e); coded_error(&e) }
        Err(e) => { error!("download_file panicked: {}", e); coded_error(&format!("panic: {}", e)) }
    };
    safe_new_jstring(&mut env, out)
}

/// JSON-encoded `List<AttachmentSummary>`. Lists the known file attachments in a chat (see `P2PCore::list_attachments`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listAttachments<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) -> jstring {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock_read();
        let list = core.list_attachments(&fp);
        serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listAttachments panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// `listAttachments` without the preview images, for the chat list.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listAttachmentsBrief<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) -> jstring {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    safe_new_jstring(&mut env, api::list_attachments_brief(&fp))
}

/// `listAttachmentsBefore(peer, beforeMs, limit)`: one older page.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listAttachmentsBefore<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, before_ms: jni::sys::jlong, limit: jni::sys::jint) -> jstring {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    safe_new_jstring(&mut env, api::list_attachments_before(&fp, before_ms.max(0) as u64, limit.max(0) as usize))
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listGroupAttachmentsBefore<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, before_ms: jni::sys::jlong, limit: jni::sys::jint) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    safe_new_jstring(&mut env, api::list_group_attachments_before(&gid, before_ms.max(0) as u64, limit.max(0) as usize))
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listGroupAttachmentsBrief<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    safe_new_jstring(&mut env, api::list_group_attachments_brief(&gid))
}

/// Group counterpart of `prepareAndSendFile`. See `P2PCore::prepare_and_send_group_file`. Returns `file_id` on success, otherwise `"Error: ..."`.
/// Downloading a completed group attachment, from any member, uses the EXISTING `downloadFile` JNI export. `download_file` already works from the
/// sender's device fingerprint, so no group-specific download mechanism is needed (see the `peer_device_fingerprint` field returned by
/// `list_group_attachments`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_prepareAndSendGroupFile<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, source_path: JString<'local>, file_name: JString<'local>, mime_type: JString<'local>, preview_jpeg: JByteArray<'local>, duration_ms: jni::sys::jint, caption: JString<'local>, reply_to_message_id: JString<'local>, reply_to_preview: JString<'local>, reply_to_sender_identity_id: JString<'local>) -> jstring {
    let group_id_str: String = jstr(&mut env, &group_id).unwrap_or_default();
    let source_str: String = jstr(&mut env, &source_path).unwrap_or_default();
    let name_str: String = jstr(&mut env, &file_name).unwrap_or_default();
    let mime_str: String = jstr(&mut env, &mime_type).unwrap_or_default();
    let preview_vec: Option<Vec<u8>> = if preview_jpeg.is_null() {
        None
    } else {
        Some(jbytearray_to_vec(&mut env, &preview_jpeg))
    };
    let duration_opt: Option<u32> = if duration_ms < 0 { None } else { Some(duration_ms as u32) };
    // See the same note on prepareAndSendFile. An empty string means "none".
    let caption_str: String = jstr(&mut env, &caption).unwrap_or_default();
    let reply_id: Option<String> = jstr(&mut env, &reply_to_message_id).filter(|v: &String| !v.is_empty());
    let reply_preview: Option<String> = jstr(&mut env, &reply_to_preview).filter(|v: &String| !v.is_empty());
    let reply_sender: Option<String> = jstr(&mut env, &reply_to_sender_identity_id).filter(|v: &String| !v.is_empty());
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        // See the same lock-splitting note as prepareAndSendFile.
        prepare_and_send_group_file_unlocked(group_id_str, source_str, name_str, mime_str, preview_vec, duration_opt, caption_str, reply_id, reply_preview, reply_sender)
    });
    match result {
        Ok(Ok(file_id)) => safe_new_jstring(&mut env, file_id),
        Ok(Err(e)) => { error!("prepare_and_send_group_file failed: {}", e); safe_new_jstring(&mut env, coded_error(&e)) }
        Err(e) => { error!("prepare_and_send_group_file panicked: {}", e); safe_new_jstring(&mut env, coded_error(&format!("panic: {}", e))) }
    }
}

/// See the note on `listAttachments`. For group attachments (see `P2PCore::list_group_attachments`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listGroupAttachments<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock_read();
        let list = core.list_group_attachments(&gid);
        serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("listGroupAttachments panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// Returns the absolute path of a decrypted (plaintext) copy of a completed attachment, or `"Error: ..."` on failure. KNOWN LIMIT: synchronous. For
/// large files, Kotlin must call it OFF the main thread (see `P2PCore::get_attachment_plaintext_path`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getAttachmentPlaintextPath<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>) -> jstring {
    let file_id_str: String = jstr(&mut env, &file_id).unwrap_or_default();
    let result = catch_panic(move || {
        // See the same lock-splitting note as prepareAndSendFile. Decryption runs without the lock.
        attachment_plaintext_path_unlocked(&file_id_str)
    });
    match result {
        Ok(Ok(path)) => safe_new_jstring(&mut env, path),
        Ok(Err(e)) => safe_new_jstring(&mut env, format!("Error: {}", e)),
        Err(e) => safe_new_jstring(&mut env, format!("Error: {}", e)),
    }
}

/// See `attachment_original_path_unlocked`. Path or `"Error: ..."`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getAttachmentOriginalPath<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>) -> jstring {
    let file_id_str: String = jstr(&mut env, &file_id).unwrap_or_default();
    match catch_panic(move || attachment_original_path_unlocked(&file_id_str)) {
        Ok(Ok(path)) => safe_new_jstring(&mut env, path),
        Ok(Err(e)) | Err(e) => safe_new_jstring(&mut env, format!("Error: {}", e)),
    }
}
