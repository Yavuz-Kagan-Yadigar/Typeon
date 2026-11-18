//! JNI bindings for the Android client and their helpers.

use super::*;

mod account;
mod history;
mod files;
mod stickers;
mod net;
mod linking;
mod messages;
mod contacts;
mod servers;
mod groups;
mod pruning;
pub use account::*;
pub use history::*;
pub use files::*;
pub use stickers::*;
pub use net::*;
pub use linking::*;
pub use messages::*;
pub use contacts::*;
pub use servers::*;
pub use groups::*;
pub use pruning::*;


#[cfg(test)]
mod device_link_code_tests {
    use super::*;

    #[test]
    fn code_follows_fingerprint_and_nonce_only() {
        let request = |nonce: u8, name: &str| DeviceLinkRequest {
            version: DeviceLinkRequest::CURRENT_VERSION,
            device_name: name.to_string(),
            device_fingerprint: "ab".repeat(32),
            rendezvous_node: String::new(),
            known_relays: Vec::new(),
            nonce: vec![nonce; 16],
        }.to_cbor().unwrap();
        let code = device_link_code(&request(1, "a"));
        assert_eq!(code.len(), 11);
        assert_eq!(code, device_link_code(&request(1, "b")));
        assert_ne!(code, device_link_code(&request(2, "a")));
        assert_eq!(device_link_code(b"not a link request"), "");
    }
}

// --- JNI helpers ---

/// Rust's default behaviour: if a panic tries to unwind across an FFI boundary such as an `extern "system"` (JNI) function, it cannot do that safely, so
/// it silently `abort()`s the process, and the whole app crashes. (That is what happened in a processQrPacket crash: a "there is no reactor running" panic
/// in the dial()/gossipsub publish() chain took the whole process down.) Each JNI export wraps the `P2PCore` method it calls with this function. If a
/// panic happens, the process does not die: it returns `Err(...)`. (The full message was already written to logcat by the `set_hook` above.)
///
/// IMPORTANT: the `f` closure must NEVER capture or use `env: JNIEnv`. In an early attempt this was broken: after a panic `env.new_string(...)` never ran,
/// so `std::ptr::null_mut()` was returned as the `jstring`. That broke the Kotlin contract `external fun ...: String` (non-null) and led to a separate
/// `NullPointerException` crash. The right pattern: `catch_panic` runs ONLY the pure Rust logic (CORE.lock() + the core method). The `new_string`/
/// `bytes_to_jbytearray` calls that turn the result into a `JNIEnv` value ALWAYS happen OUTSIDE this function, in the calling code that the panic does
/// not affect. That way a valid (non-null) JNI value is returned whether or not a panic happened.
pub(crate) fn catch_panic<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    // every export runs inside the runtime context, not only the ones
    // that remembered `RUNTIME.enter()`.
    // Inside `catch_unwind`: a failing lazy runtime init must not unwind into JNI.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _rt = RUNTIME.enter();
        f()
    }))
    .map_err(|payload| {
        CORE_PANICKED.store(true, std::sync::atomic::Ordering::SeqCst);
        // The full panic message was already written to logcat by `set_hook`. Here we produce a short summary to return to the caller.
        if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "internal panic (see logcat 'PANIC caught')".to_string()
        }
    })
}

/// The stable code of a core error message, so the UI can pick a localized text. First match wins; the order matters (e.g. "already" before
/// "contact not found"-style lookups). ponytail: keyed on the message text, so a reworded message can move to INTERNAL; `error_code_tests` pins the main ones.
pub(crate) fn error_code(detail: &str) -> &'static str {
    const TABLE: &[(&str, &[&str])] = &[
        ("INTERNAL", &["panic"]),
        ("LOCKED", &["not loaded", "initdatabase", "db not open", "database not open", "no identity", "identity first"]),
        ("NOT_FOUNDER", &["only the founder"]),
        ("ALREADY", &["already"]),
        ("BLOCKED", &["blocked", "revoked", "deleted their account"]),
        ("TOO_LARGE", &["too large", "too long", "at most", "exceeds the limit", "limit reached"]),
        ("NO_SESSION", &["no ratchet session", "no session", "key exchange", "unknown peer", "could not be resolved"]),
        ("INVALID", &["invalid", "bad ", "cannot be empty", "must be", "must contain", "mismatch", "inconsistent", "unsupported", "corrupt", "in code", "not an rgba"]),
        ("NOT_ALLOWED", &["only the primary", "you cannot", "cannot be", "cannot remove", "cannot leave", "you are not"]),
        ("NETWORK", &["tor is off", "tor failed", "unreachable", "reachable", "not connected", "network address", "could not be sent", "could not send", "network"]),
        ("NOT_FOUND", &["not found", "unknown", "no pending", "is not a member", "no call", "no members", "no chat", "no db", "no sibling", "missing"]),
    ];
    let lower = detail.to_lowercase();
    TABLE.iter()
        .find(|(_, keys)| keys.iter().any(|k| lower.contains(k)))
        .map_or("INTERNAL", |(code, _)| *code)
}

/// "Error: <CODE>: <detail>" (see `error_code`).
pub(crate) fn coded_error(detail: &str) -> String {
    format!("Error: {}: {}", error_code(detail), detail)
}

/// Both error arms of a JNI call's `catch_panic` result as `coded_error`.
pub(crate) fn coded<T>(result: Result<Result<T, String>, String>) -> Result<T, String> {
    match result {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(coded_error(&e)),
        Err(e) => Err(coded_error(&format!("panic: {}", e))),
    }
}

#[cfg(test)]
mod error_code_tests {
    use super::*;

    #[test]
    fn main_messages_get_their_codes() {
        for (msg, code) in [
            ("Only the founder can remove members", "NOT_FOUNDER"),
            ("This contact is already a group member", "ALREADY"),
            ("This contact is blocked", "BLOCKED"),
            ("File too large", "TOO_LARGE"),
            ("Unknown peer device; complete key exchange first", "NO_SESSION"),
            ("Invalid contact code", "INVALID"),
            ("You cannot add your own code as a contact", "NOT_ALLOWED"),
            ("Tor is off: network only works over Tor", "NETWORK"),
            ("Group not found", "NOT_FOUND"),
            ("Unknown file_id", "NOT_FOUND"),
            ("Encryption key not loaded yet", "LOCKED"),
            ("panic: boom", "INTERNAL"),
            ("Group version exhausted", "INTERNAL"),
        ] {
            assert_eq!(error_code(msg), code, "{msg}");
        }
        assert_eq!(coded_error("Group not found"), "Error: NOT_FOUND: Group not found");
    }
}

/// These helpers (`bytes_to_jbytearray` / `strings_to_jobjectarray` / `safe_new_jstring`) used to unwrap the results of JNIEnv calls directly with
/// `.unwrap()`. `catch_panic` protects ONLY the pure Rust logic (see its docs above). These conversion calls ALWAYS run OUTSIDE it, unwrapped. Normally
/// these JNIEnv calls do not fail, but they can when the JVM hits a real OutOfMemoryError (e.g. returning a large message history sync, or the
/// `export_recovery` output, on a low-memory device). In that case the old code panicked, and that panic would unwind across the `extern "system"` (JNI)
/// boundary. That is undefined behaviour, and in practice it silently crashes the PROCESS (a native SIGABRT that Kotlin cannot catch). It is exactly the
/// outcome `catch_panic` tries to prevent, one call frame later.
///
/// Now the error is logged and `std::ptr::null_mut()` is returned instead.
/// NOTE (deliberate, accepted trade-off): the `catch_panic` docs above say returning null breaks the Kotlin contract `external fun ...: String` (not
/// nullable), which leads to a separate `NullPointerException`. But that note was about a NORMAL panic (e.g. a core logic error). `catch_panic` already
/// catches that case, so these helpers are never reached on a panic. The case handled here is different and much rarer: the JNIEnv itself fails because
/// the JVM (the Kotlin side) ran out of memory. At that point the JVM is already unhealthy, and the app will probably crash in some way anyway. The choice
/// is between a silent native abort with undefined behaviour (which may never reach a crash report) and a normal, catchable `NullPointerException` on the
/// Kotlin side (which produces a real stack trace and crash report). The second is clearly the better failure mode.
/// Rows per history call from a frontend: the load, the decrypt and the JSON all run under the core lock.
pub(crate) const MAX_HISTORY_PAGE: jni::sys::jint = 500;
pub(crate) const MAX_LISTED_ATTACHMENTS: usize = 500;
/// The text (history) or preview (attachment list) bytes of one page.
pub(crate) const PAGE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Charges `bytes` to a page read newest first. `true`: stop before this
/// row. Past the budget the rows of the cut millisecond still come, since
/// the next page starts strictly below it.
pub(crate) fn page_bytes_full(budget: &mut usize, cut_at: &mut Option<i64>, cursor: i64, bytes: usize) -> bool {
    if let Some(c) = *cut_at {
        return cursor != c;
    }
    *budget = budget.saturating_sub(bytes);
    if *budget == 0 {
        *cut_at = Some(cursor);
    }
    false
}

/// Rows of a newest-first, limited query, oldest first. A row that cannot be
/// read is logged, not dropped in silence.
pub(crate) fn newest_first_rows<T>(rows: rusqlite::Result<rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>>) -> Vec<T> {
    let mut out: Vec<T> = match rows {
        Ok(it) => it.filter_map(|r| r.map_err(|e| warn!("Attachment row could not be read: {}", e)).ok()).collect(),
        Err(e) => {
            warn!("Attachment list query failed: {}", e);
            Vec::new()
        }
    };
    out.reverse();
    out
}

pub(crate) fn bytes_to_jbytearray<'local>(env: &mut JNIEnv<'local>, bytes: &[u8]) -> jni::sys::jbyteArray {
    // No intermediate copy: these bytes are key material on some paths.
    match env.byte_array_from_slice(bytes) {
        Ok(arr) => arr.into_raw(),
        Err(e) => {
            log::error!("JNI byte_array_from_slice failed (JVM may be under memory pressure): {e}");
            std::ptr::null_mut()
        }
    }
}

pub(crate) fn jbytearray_to_vec<'local>(env: &mut JNIEnv<'local>, data: &JByteArray<'local>) -> Vec<u8> {
    // EMPTY on failure, never a zero-filled buffer of the right length: 32
    // zero bytes pass every key length check and would be installed as a key.
    match env.convert_byte_array(data) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("JNI convert_byte_array failed, returning empty: {e}");
            let _ = env.exception_clear();
            Vec::new()
        }
    }
}

/// A Java `byte[]` of exactly `expect` bytes, copied into a fallible
/// allocation: the frame paths copy up to 96 MB, and a failed allocation
/// aborts the process (no unwind for `catch_panic`). `None`: wrong length,
/// no memory, or a JNI error.
pub(crate) fn jbytearray_exact<'local>(env: &mut JNIEnv<'local>, data: &JByteArray<'local>, expect: u64) -> Option<Vec<u8>> {
    let len = env.get_array_length(data).ok()?.max(0) as u64;
    if len != expect {
        return None;
    }
    let len = usize::try_from(len).ok()?;
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(len).ok()?;
    buf.resize(len, 0);
    // SAFETY: `jbyte` is `i8`, same size and alignment as `u8`; the slice covers `buf` exactly.
    let dst = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut jni::sys::jbyte, len) };
    if env.get_byte_array_region(data, 0, dst).is_err() {
        let _ = env.exception_clear();
        return None;
    }
    Some(buf)
}

/// Converts a `JString` that Kotlin passed as `null` into an `Option<String>`. Added for the WhatsApp-style optional `replyToMessageId` /
/// `replyToPreview` parameters. Same pattern as the `JByteArray.is_null()` check in `prepareAndSendFile`, but for `JString`.
pub(crate) fn optional_jstring<'local>(env: &mut JNIEnv<'local>, s: &JString<'local>) -> Option<String> {
    if s.is_null() {
        None
    } else {
        jstr(env, s)
    }
}

/// `get_string` that clears a pending Java exception on failure (OOM): later
/// JNI calls with an exception pending are undefined.
pub(crate) fn jstr(env: &mut JNIEnv, s: &JString) -> Option<String> {
    match env.get_string(s) {
        Ok(v) => Some(v.into()),
        Err(e) => {
            if !s.is_null() {
                log::error!("JNI get_string failed: {e}");
            }
            let _ = env.exception_clear();
            None
        }
    }
}

/// See `bytes_to_jbytearray`: same reasoning and trade-off.
pub(crate) fn safe_new_jstring<'local>(env: &mut JNIEnv<'local>, s: impl AsRef<str>) -> jstring {
    match env.new_string(s.as_ref()) {
        Ok(js) => js.into_raw(),
        Err(e) => {
            log::error!("JNI new_string failed (JVM may be under memory pressure): {e}");
            std::ptr::null_mut()
        }
    }
}

pub(crate) fn strings_to_jobjectarray<'local>(env: &mut JNIEnv<'local>, texts: &[String]) -> jobjectArray {
    let string_class = match env.find_class("java/lang/String") {
        Ok(c) => c,
        Err(e) => {
            log::error!("JNI find_class(java/lang/String) failed: {e}");
            return std::ptr::null_mut();
        }
    };
    let empty = match env.new_string("") {
        Ok(s) => s,
        Err(e) => {
            log::error!("JNI new_string(\"\") failed: {e}");
            return std::ptr::null_mut();
        }
    };
    let arr = match env.new_object_array(texts.len() as i32, string_class, empty) {
        Ok(a) => a,
        Err(e) => {
            log::error!("JNI new_object_array failed: {e}");
            return std::ptr::null_mut();
        }
    };
    for (i, text) in texts.iter().enumerate() {
        // One bad element fails the whole array: `pollNetwork` then keeps the
        // turn for the next one. An element left "" lost its event for good.
        let jstr = match env.new_string(text) {
            Ok(s) => s,
            Err(e) => {
                log::error!("JNI new_string failed (index {i}): {e}");
                let _ = env.exception_clear();
                return std::ptr::null_mut();
            }
        };
        if let Err(e) = env.set_object_array_element(&arr, i as i32, &jstr) {
            log::error!("JNI set_object_array_element failed (index {i}): {e}");
            let _ = env.exception_clear();
            return std::ptr::null_mut();
        }
        // A burst of events must not fill the local reference table.
        let _ = env.delete_local_ref(jstr);
    }
    arr.into_raw()
}

// =====================================================================
// KNOWN GAPS / OUT OF SCOPE
//
// Keep this block current as the code changes. Only limits that still hold are listed here.
//
// 1. Multi-device linking is implemented: device add and revoke spread over the network as `MessageContent::DeviceAddNotice`/`DeviceRevokeNotice`
//    (over the ratchet-encrypted channel, acked and retried). See `adopt_device_link`, `apply_device_add_notice` and `apply_device_revoke_notice`.
// 2. A Linux desktop client exists: see `Linux/` at the repo root (GTK4). It links this core directly as an rlib through the `api` module, so there is
//    no second protocol implementation. Node mode works there too. Limit: that client can only be a SECONDARY device (linking flow). It cannot create
//    a new identity on its own.
// 3. Every update carries the full member list. On a version gap, or when a member's device is unknown, the member asks the founder for the whole state
//    (`GroupSyncRequest`), and the founder can re-send everything (`resend_group_to_all`).
// =====================================================================

#[cfg(test)]
mod pbkdf2_tests {
    /// RFC 7914 §11 PBKDF2-HMAC-SHA256 test vector, the one `pbkdf2Sha256` JNI uses.
    #[test]
    fn pbkdf2_sha256_matches_rfc7914() {
        let mut out = [0u8; 64];
        ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, std::num::NonZeroU32::new(1).unwrap(), b"salt", b"passwd", &mut out);
        assert_eq!(hex::encode(&out[..8]), "55ac046e56e3089f");
    }
}

