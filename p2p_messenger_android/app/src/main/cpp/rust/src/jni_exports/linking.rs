//! JNI: contact QR / manual codes and multi-device linking.

use super::*;

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_generateQrPacket<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, rendezvous_node: JString<'local>) -> jni::sys::jbyteArray {
    let node: String = jstr(&mut env, &rendezvous_node).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.generate_qr_packet(node)
    });
    match result {
        Ok(Ok(bytes)) => bytes_to_jbytearray(&mut env, &bytes),
        Ok(Err(e)) => { error!("generate_qr_packet failed: {}", e); bytes_to_jbytearray(&mut env, &[]) }
        Err(e) => { error!("generate_qr_packet panicked: {}", e); bytes_to_jbytearray(&mut env, &[]) }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getManualAddCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, rendezvous_node: JString<'local>) -> jstring {
    let node: String = jstr(&mut env, &rendezvous_node).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.generate_manual_add_code(&node)
    });
    let out = match result {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => { error!("generate_manual_add_code failed: {}", e); String::new() }
        Err(e) => { error!("generate_manual_add_code panicked: {}", e); String::new() }
    };
    safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_processQrPacket<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, data: JByteArray<'local>) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &data);
    let result = catch_panic(move || {
        // See the startNetwork note: this JNI call (like the camera analysis thread) can run on a thread COMPLETELY DIFFERENT from the one that called
        // startNetwork. The libp2p executor tasks triggered by `dial()` also need a Tokio context here, so without this line the same
        // "there is no reactor running" panic that happened in this function would repeat.
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.process_qr_packet(&raw)
    });
    // On success, it returns not a bare identity_id but `{"identity_id":...,"device_fingerprint":...,"device_name":...}` JSON. Kotlin uses
    // `device_fingerprint` to open the new contact's chat screen directly (see the `process_qr_packet` docs and the ChatActivity "Connecting..." indicator).
    match coded(result) {
        Ok((identity_id, device_fingerprint, device_name)) => safe_new_jstring(&mut env, serde_json::json!({
            "identity_id": identity_id, "device_fingerprint": device_fingerprint, "device_name": device_name
        }).to_string()),
        Err(e) => safe_new_jstring(&mut env, e),
    }
}

/// what a scanned contact QR names, for the confirm step before
/// `processQrPacket`. `{"name","short_code","safety_code","identity_id",
/// "device_fingerprint"}` or "Error: CODE: ..."; changes nothing.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_peekContactQr<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, data: JByteArray<'local>) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &data);
    let out = match coded(catch_panic(move || core_lock_read().peek_qr_packet(&raw))) {
        Ok(v) => v.to_string(),
        Err(e) => e,
    };
    safe_new_jstring(&mut env, out)
}

// ---------------------------------------------------------------------------
// Multi-device JNI bridge.
// ---------------------------------------------------------------------------

/// On a secondary device: produces the "add device" QR code (CBOR) that shows this device. This device must first have gone through the normal
/// `createIdentity` + `startNetwork`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_buildDeviceLinkRequest<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jbyteArray {
    let result = catch_panic(|| {
        let mut core = core_lock();
        core.build_device_link_request()
    });
    match result {
        Ok(Ok(bytes)) => bytes_to_jbytearray(&mut env, &bytes),
        Ok(Err(e)) => { error!("build_device_link_request failed: {}", e); bytes_to_jbytearray(&mut env, &[]) }
        Err(e) => { error!("build_device_link_request panicked: {}", e); bytes_to_jbytearray(&mut env, &[]) }
    }
}

/// What a scanned link QR asks for, shown to the user before
/// `approveDeviceLink`. Same return shape, changes nothing.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_peekDeviceLink<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, data: JByteArray<'local>) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &data);
    let out = match catch_panic(move || DeviceLinkRequest::from_cbor(&raw)) {
        Ok(Ok(req)) if is_fingerprint_hex(&req.device_fingerprint) => serde_json::json!({
            "device_fingerprint": req.device_fingerprint,
            "device_name": sanitize_display_name(&req.device_name).unwrap_or_default(),
        }).to_string(),
        Ok(Ok(_)) => coded_error("Invalid device code"),
        Ok(Err(e)) => coded_error(&e),
        Err(e) => coded_error(&format!("panic: {}", e)),
    };
    safe_new_jstring(&mut env, out)
}

/// The short code both devices show while a device is linked, for the user to
/// compare by eye: nine digits from the link QR's device fingerprint and
/// nonce. The new device computes it from the QR it shows, the approving
/// device from the QR it scanned. Empty for a QR that is not a link request.
///
/// Someone who sees the QR and puts a QR of their own in front of the
/// approving device can try nonces until their code matches. Nine digits
/// through a slow KDF make that hours of GPU work per QR instead of a
/// second. A code from values exchanged after the scan does not help: a
/// device in the middle picks its own part after seeing the other side's.
pub(crate) fn device_link_code(request_cbor: &[u8]) -> String {
    let Ok(req) = DeviceLinkRequest::from_cbor(request_cbor) else { return String::new() };
    if req.nonce.len() != 16 || !is_fingerprint_hex(&req.device_fingerprint) {
        return String::new();
    }
    let mut input = req.device_fingerprint.to_ascii_lowercase().into_bytes();
    input.extend_from_slice(&req.nonce);
    let mut out = [0u8; 8];
    // ~0.1 s on a phone; both callers run off the UI thread.
    let iterations = std::num::NonZeroU32::new(100_000).expect("non-zero");
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, iterations, b"typeon-link-code-v2", &input, &mut out);
    let number = u64::from_be_bytes(out) % 1_000_000_000;
    format!("{:03} {:03} {:03}", number / 1_000_000, number / 1000 % 1000, number % 1000)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deviceLinkCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, data: JByteArray<'local>) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &data);
    let out = catch_panic(move || device_link_code(&raw)).unwrap_or_default();
    safe_new_jstring(&mut env, out)
}

/// On the primary device: processes the secondary device's QR (CBOR). It approves, connects, sends the sync, and announces to the contacts. Returns
/// `{"device_fingerprint":...,"device_name":...}` on success, otherwise "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_approveDeviceLink<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, data: JByteArray<'local>) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &data);
    let result = catch_panic(move || {
        // See the `process_qr_packet` note: `dial()` needs a Tokio context.
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.approve_device_link(&raw)
    });
    match coded(result) {
        Ok((fp, name)) => safe_new_jstring(&mut env, serde_json::json!({
            "device_fingerprint": fp, "device_name": name
        }).to_string()),
        Err(e) => safe_new_jstring(&mut env, e),
    }
}

/// The devices of my identity (this device plus its siblings), as a JSON array.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listLinkedDevices<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        serde_json::Value::Array(core.list_linked_devices()).to_string()
    });
    let out = result.unwrap_or_else(|e| { error!("list_linked_devices panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, out)
}

/// Whether this device is linked to an identity as a SECONDARY (i.e. it was approved by another device). Used by the UI to tell "primary" from "linked device".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_isSecondaryDevice<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jboolean {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.own_device_add.is_some()
    });
    result.unwrap_or(false) as jboolean
}

/// Revokes a sibling device. Returns "OK" or "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_revokeLinkedDevice<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, device_fingerprint: JString<'local>) -> jstring {
    let fp: String = jstr(&mut env, &device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.revoke_own_linked_device(&fp)
    });
    let out = coded(result).map_or_else(|e| e, |()| "OK".to_string());
    safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_forgetRevokedLinkedDevice<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, device_fingerprint: JString<'local>) -> jstring {
    let fp: String = jstr(&mut env, &device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.forget_revoked_linked_device(&fp)
    });
    let out = coded(result).map_or_else(|e| e, |()| "OK".to_string());
    safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_processManualEntry<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, text: JString<'local>) -> jstring {
    let text_str: String = jstr(&mut env, &text).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.process_manual_entry(&text_str)
    });
    // See the `processQrPacket` note.
    match coded(result) {
        Ok((identity_id, device_fingerprint, device_name)) => safe_new_jstring(&mut env, serde_json::json!({
            "identity_id": identity_id, "device_fingerprint": device_fingerprint, "device_name": device_name
        }).to_string()),
        Err(e) => safe_new_jstring(&mut env, e),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_closeDeviceLinkWindow(_env: JNIEnv, _class: JClass) {
    api::close_device_link_window();
}
