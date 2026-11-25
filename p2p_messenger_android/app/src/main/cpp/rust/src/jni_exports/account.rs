//! JNI: database key, identity, secret bundles, profile, account deletion, recovery, update check.

use super::*;

// --- JNI Bindings ---

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_initDatabaseKeyed<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, files_dir: JString<'local>, key_bytes: JByteArray<'local>) -> jboolean {
    let path: String = jstr(&mut env, &files_dir).unwrap_or_default();
    // a failed string copy is "", which opened "/p2p_messenger.db".
    if path.is_empty() {
        return false as jboolean;
    }
    let raw = zeroize::Zeroizing::new(jbytearray_to_vec(&mut env, &key_bytes));
    let key: [u8; 32] = match raw.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => return false as jboolean,
    };
    let key = zeroize::Zeroizing::new(key);
    let result = catch_panic(|| {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.init_db(&path, &key).map_err(|e| e.to_string())
    });
    match result {
        Ok(Ok(_)) => true as jboolean,
        Ok(Err(e)) => { error!("initDatabase failed: {}", e); false as jboolean }
        Err(e) => { error!("initDatabase panicked: {}", e); false as jboolean }
    }
}

/// Debug builds only: the SQLCipher raw key (64 hex characters) for reading
/// an adb-pulled database. The Kotlin class `DebugDbKey` exists only in the
/// debug source set; the symbol exists only with the `debug-hooks` feature.
#[cfg(feature = "debug-hooks")]
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_DebugDbKey_dbKeyHex<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, key_bytes: JByteArray<'local>) -> jstring {
    let raw = zeroize::Zeroizing::new(jbytearray_to_vec(&mut env, &key_bytes));
    let out = match <[u8; 32]>::try_from(raw.as_slice()) {
        Ok(key) => {
            let key = zeroize::Zeroizing::new(key);
            // `"x'<hex>'"`: the hex digits hold neither quotes nor an `x`.
            db_key_pragma(&key).trim_matches(|c| c == '"' || c == '\'' || c == 'x').to_string()
        }
        Err(_) => String::new(),
    };
    safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_createIdentity<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, device_name: JString<'local>) -> jstring {
    let name: String = jstr(&mut env, &device_name).unwrap_or_else(|| "Device".to_string());
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().create_identity(name)
    });
    match result {
        Ok(Ok(id)) => safe_new_jstring(&mut env, id),
        Ok(Err(e)) => safe_new_jstring(&mut env, format!("Error: {}", e)),
        Err(e) => safe_new_jstring(&mut env, format!("Error: {}", e)),
    }
}

/// The secret key bundle (CBOR, plaintext) made by `createIdentity`. Not a
/// destructive read: if Kotlin fails to encrypt or write it, this was the only
/// copy and the identity could never load again. It stays until
/// `loadSecretBundle` succeeds or the state is wiped (the keys are in core
/// memory for the life of the process anyway).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getPendingSecretBundle<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jbyteArray {
    let result = catch_panic(|| {
        zeroize::Zeroizing::new(core_lock_read().pending_secret_bundle.clone().unwrap_or_default())
    });
    let bundle = result.unwrap_or_else(|e| { error!("getPendingSecretBundle panicked: {}", e); Default::default() });
    bytes_to_jbytearray(&mut env, &bundle)
}

/// Argon2id key of the app password (see Kotlin `Vault`): the key that wraps the vault key, so it decides how
/// fast a rooted attacker who copied the vault file can guess the password offline. Memory-hard, so GPUs gain
/// little. `m_kib` and `t` come from the vault file header; they are bounded so a damaged header cannot ask for
/// gigabytes. Empty array on bad input. Does NOT take the core lock: the lock screen must not wait for network work.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_argon2idKey<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, password: JString<'local>, salt: JByteArray<'local>, m_kib: jni::sys::jint, t: jni::sys::jint) -> jni::sys::jbyteArray {
    let pw = zeroize::Zeroizing::new(jstr(&mut env, &password).unwrap_or_default());
    let salt = jbytearray_to_vec(&mut env, &salt);
    let out = catch_panic(move || app_password_key(pw.as_bytes(), &salt, m_kib, t).unwrap_or_default())
        .unwrap_or_default();
    bytes_to_jbytearray(&mut env, &out[..])
}

/// See `Java_com_p2p_messenger_P2PLib_argon2idKey`. `None` for an empty password or salt (an argument that failed to
/// copy arrives empty) or out-of-range costs.
pub(crate) fn app_password_key(password: &[u8], salt: &[u8], m_kib: i32, t: i32) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    if password.is_empty() || salt.len() < 16 || !(8 * 1024..=256 * 1024).contains(&m_kib) || !(1..=10).contains(&t) {
        return None;
    }
    let params = argon2::Params::new(m_kib as u32, t as u32, 1, Some(32)).ok()?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = zeroize::Zeroizing::new(vec![0u8; 32]);
    argon.hash_password_into(password, salt, &mut out[..]).ok()?;
    Some(out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_loadSecretBundle<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, bundle_bytes: JByteArray<'local>) -> jboolean {
    let raw = zeroize::Zeroizing::new(jbytearray_to_vec(&mut env, &bundle_bytes));
    let result = catch_panic(move || {
        let mut core = core_lock();
        let loaded = core.load_secret_bundle(&raw);
        if loaded.is_ok() {
            // The frontend has it stored: see `getPendingSecretBundle`.
            zeroize::Zeroize::zeroize(&mut core.pending_secret_bundle);
            core.pending_secret_bundle = None;
        }
        loaded
    });
    match result {
        Ok(Ok(_)) => true as jboolean,
        Ok(Err(e)) => { error!("load_secret_bundle failed: {}", e); false as jboolean }
        Err(e) => { error!("load_secret_bundle panicked: {}", e); false as jboolean }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_hasStoredIdentity<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jboolean {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.identity.is_some()
    });
    result.unwrap_or(false) as jboolean
}

/// Loads the "history data key" that Kotlin unwrapped from the Keystore. `key_bytes` must be exactly 32 bytes (a 256-bit ChaCha20-Poly1305 key).
/// Rust never writes this key to disk, it only keeps it in memory. See the `history_key` field docs.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setHistoryKey<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, key_bytes: JByteArray<'local>) -> jboolean {
    let raw = zeroize::Zeroizing::new(jbytearray_to_vec(&mut env, &key_bytes));
    let key: [u8; 32] = match raw.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => return false as jboolean,
    };
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.history_key = Some(key);
    });
    result.is_ok() as jboolean
}

/// Loads the key used to encrypt the skipped-message-key cache on disk (see `P2PCore.skipped_key_encryption_key`). It must always be loaded,
/// regardless of node mode. Unlike `history_key`, this is not optional archiving: it is required for messaging reliability.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setSkippedKeyEncryptionKey<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, key_bytes: JByteArray<'local>) -> jboolean {
    let raw = zeroize::Zeroizing::new(jbytearray_to_vec(&mut env, &key_bytes));
    let key: [u8; 32] = match raw.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => return false as jboolean,
    };
    let result = catch_panic(move || {
        core_lock().install_skipped_key(key);
    });
    result.is_ok() as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getIdentityCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.identity_code()
    });
    // "" when not ready, like `getManualAddCode`: the callers show the value.
    safe_new_jstring(&mut env, result.ok().and_then(Result::ok).unwrap_or_default())
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getIdentityShortCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.identity_short_code()
    });
    safe_new_jstring(&mut env, result.ok().and_then(Result::ok).unwrap_or_default())
}

/// See `P2PCore::own_identity_id`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getOwnIdentityId<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.own_identity_id()
    });
    match result {
        Ok(Ok(id)) => safe_new_jstring(&mut env, id),
        Ok(Err(e)) => safe_new_jstring(&mut env, format!("Error: {}", e)),
        Err(e) => safe_new_jstring(&mut env, format!("Error: {}", e)),
    }
}

/// Returns my own profile picture (an empty array if none was ever set). See `P2PCore::get_own_avatar`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getOwnProfilePicture<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jbyteArray {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.get_own_avatar().unwrap_or_default()
    });
    let bytes = result.unwrap_or_else(|e| { error!("getOwnProfilePicture panicked: {}", e); Vec::new() });
    bytes_to_jbytearray(&mut env, &bytes)
}

/// Sets or removes my own profile picture. See `P2PCore::set_own_profile_picture`. If `avatar_jpeg` is null, the picture is removed (a `None`
/// notice is sent to all contacts).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setOwnProfilePicture<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, avatar_jpeg: JByteArray<'local>) -> jstring {
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
        core.set_own_profile_picture(avatar_vec)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("set_own_profile_picture failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("set_own_profile_picture panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// `P2PCore::delete_account`: the number of devices notified, -1 on error.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deleteAccount<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jint {
    api::delete_account() as jni::sys::jint
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_accountDeletionPending<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jint {
    api::account_deletion_pending() as jni::sys::jint
}

/// Changes this device's account name and automatically notifies EVERY known contact. See `P2PCore::set_display_name`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setDisplayName<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, name: JString<'local>) -> jstring {
    let name_str: String = jstr(&mut env, &name).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.set_display_name(&name_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("set_display_name failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("set_display_name panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// The current account name (empty = no identity). See `P2PCore::own_display_name`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getDisplayName<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| core_lock_read().own_display_name().unwrap_or_default());
    let out = result.unwrap_or_else(|e| { error!("getDisplayName panicked: {}", e); String::new() });
    safe_new_jstring(&mut env, out)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_exportRecovery<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, pass: JString<'local>) -> jni::sys::jbyteArray {
    let pass_str = zeroize::Zeroizing::new(jstr(&mut env, &pass).unwrap_or_default());
    let result = catch_panic(move || {
        // Argon2 runs after the core lock is released.
        let chats = recovery_chats_unlocked();
        let (plaintext, pass) = core_lock_read().recovery_plaintext(pass_str.to_string(), Some(chats))?;
        seal_recovery_file(&plaintext, &pass)
    });
    match result {
        Ok(Ok(bytes)) => bytes_to_jbytearray(&mut env, &bytes),
        Ok(Err(e)) => { error!("export_recovery failed: {}", e); bytes_to_jbytearray(&mut env, &[]) }
        Err(e) => { error!("export_recovery panicked: {}", e); bytes_to_jbytearray(&mut env, &[]) }
    }
}

/// After `exportRecovery`: the number of newest messages the file holds when it had to be cut, 0 when complete.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_lastRecoveryTrimmed<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jint {
    crate::recovery::RECOVERY_TRIMMED.load(std::sync::atomic::Ordering::SeqCst).min(i32::MAX as usize) as jni::sys::jint
}

/// A linked device logging out asks the root to revoke it (`api::announce_leaving`, waits up to 3 s for the ack). No-op on the root.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_announceLeaving<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) {
    crate::api::announce_leaving();
}

/// Counterpart of `exportRecovery`. See the `import_recovery` docs. Same pattern as `createIdentity`: on success it returns `identity_id` and puts the
/// generated secret bundle in `pending_secret_bundle`. The Kotlin side (see `IdentityManager.persistNewIdentity`) must fetch it at once with
/// `getPendingSecretBundle`, encrypt it with the Keystore, and write it to disk, just as for a new identity.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_importRecovery<'local>(
    mut env: JNIEnv<'local>, _class: JClass<'local>,
    file_bytes: JByteArray<'local>, passphrase: JString<'local>, device_name: JString<'local>,
) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &file_bytes);
    let pass_str = zeroize::Zeroizing::new(jstr(&mut env, &passphrase).unwrap_or_default());
    let name: String = jstr(&mut env, &device_name).unwrap_or_else(|| "Device".to_string());
    let result = catch_panic(move || {
        // Argon2 runs without the core lock.
        core_lock_read().import_recovery_precheck()?;
        let plaintext = open_recovery_file(&raw, &pass_str)?;
        let mut core = core_lock();
        let (id, bundle_bytes) = core.import_recovery_plaintext(&plaintext, name)?;
        zeroize::Zeroize::zeroize(&mut core.pending_secret_bundle);
        core.pending_secret_bundle = Some(bundle_bytes);
        Ok::<String, String>(id)
    });
    match result {
        Ok(Ok(id)) => safe_new_jstring(&mut env, id),
        Ok(Err(e)) => safe_new_jstring(&mut env, format!("Error: {}", e)),
        Err(e) => safe_new_jstring(&mut env, format!("Error: {}", e)),
    }
}

/// Self-update (see update.rs). Blocking, network: call off the main thread. Returns the verified APK path,
/// `""` when up to date or checked within the day, or `"Error: ..."`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_checkUpdate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    dir: JString<'local>,
    current: JString<'local>,
    force: jboolean,
) -> jstring {
    let (Some(dir), Some(current)) = (jstr(&mut env, &dir), jstr(&mut env, &current)) else {
        return safe_new_jstring(&mut env, "Error: bad arguments");
    };
    // A panic on fetched data must not unwind into JNI (that aborts the process).
    let out = match catch_panic(move || crate::update::check_blocking(&dir, &current, "typeon-client-{v}.apk", force != 0, false)) {
        Ok(Ok(Some((_, path)))) => path.to_string_lossy().into_owned(),
        Ok(Ok(None)) => String::new(),
        Ok(Err(e)) | Err(e) => format!("Error: {e}"),
    };
    safe_new_jstring(&mut env, out)
}
