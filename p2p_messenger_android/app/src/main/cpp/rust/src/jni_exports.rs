//! JNI bindings for the Android client and their helpers.

use super::*;


// --- JNI Bindings ---

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_initDatabaseKeyed<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, files_dir: JString<'local>, key_bytes: JByteArray<'local>) -> jboolean {
    let path: String = jstr(&mut env, &files_dir).unwrap_or_default();
    // M57: a failed string copy is "", which opened "/p2p_messenger.db".
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
/// debug source set; the symbol exists only with the `debug-hooks` feature (M-168).
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

/// Uygulama kilidi şifresi için PBKDF2-HMAC-SHA256 (bkz. Kotlin `AppLock.derive`).
/// Java `PBKDF2WithHmacSHA256` ile aynı çıktı (şifre UTF-8), ama ring'in
/// assembly SHA-256'sıyla: Tab A8'de 300k iterasyon Java'da 4-8 sn sürüyordu.
/// Çekirdek kilidini ALMAZ — kilit ekranı ağ işlerini beklememeli.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_pbkdf2Sha256<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, password: JString<'local>, salt: JByteArray<'local>, iterations: jni::sys::jint, out_len: jni::sys::jint) -> jni::sys::jbyteArray {
    let pw = zeroize::Zeroizing::new(jstr(&mut env, &password).unwrap_or_default());
    let salt = jbytearray_to_vec(&mut env, &salt);
    let out = catch_panic(move || {
        let mut out = vec![0u8; out_len.clamp(1, 64) as usize];
        // An argument that failed to copy arrives empty: no key from that (a
        // hash of the empty password was stored as the app lock).
        if pw.is_empty() || salt.is_empty() {
            Vec::new()
        } else if let Some(it) = std::num::NonZeroU32::new(iterations.clamp(0, 5_000_000) as u32) {
            // M9: bounded like `out_len` (the app uses 300 000).
            ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, it, &salt, pw.as_bytes(), &mut out);
            out
        } else {
            Vec::new()
        }
    })
    .unwrap_or_default();
    bytes_to_jbytearray(&mut env, &out)
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

/// Kotlin'in Keystore ile sarmalanmış (wrapped) bir "history data key"i
/// çözüp buraya yüklemesi için. `key_bytes` tam 32 bayt olmalıdır (256-bit
/// ChaCha20-Poly1305 anahtarı). Rust bu anahtarı diske hiç yazmaz, sadece
/// bellekte tutar — bkz. `history_key` alanı dokümantasyonu.
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

/// Skipped-message-key önbelleğinin diske şifreli kalıcılığı için
/// kullanılan anahtarı yükler (bkz. `P2PCore.skipped_key_encryption_key`
/// dokümantasyonu). Node modundan BAĞIMSIZ her zaman yüklenmelidir —
/// `history_key`'in aksine bu opsiyonel bir arşivleme değil, mesajlaşmanın
/// güvenilirliği için gerekli bir mekanizmadır.
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

/// Bir kişiyle olan yerel şifreli mesaj geçmişini çözüp JSON olarak döner
/// (`List<ArchivedMessage>`). `history_key` yüklenmemişse veya bu kişiyle
/// hiç arşivlenmiş mesaj yoksa boş dizi döner — bu bir hata değildir (node
/// modu hiç açılmamış olabilir, spec dışı kullanıcı tercihi).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getMessageHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, limit: jni::sys::jint) -> jstring {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        // H57: lock dropped before the JSON is built.
        let history = core_lock_read().load_message_history(&fp, limit.clamp(0, MAX_HISTORY_PAGE) as u32, None);
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getMessageHistory panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// H122: only messages archived after `after_timestamp` (the newest
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

/// H122: group twin of `getMessageHistorySince`.
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

/// H137: `{"contacts":{<identity_id>:{"peer","message","attachment"}},
/// "groups":{<group_id>:{"message","attachment"}}}`; `message` is an
/// `ArchivedMessage` (no reactions/seen-by), `attachment` an
/// `AttachmentSummary` (no preview), either may be null.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_chatListPreviews<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let previews = core_lock_read().chat_list_previews();
        previews.to_string()
    });
    let json = result.unwrap_or_else(|e| { error!("chatListPreviews panicked: {}", e); r#"{"contacts":{},"groups":{}}"#.to_string() });
    safe_new_jstring(&mut env, json)
}

/// Spec dışı, kullanıcı isteği (sonsuz kaydırma): sohbet geçmişinin en
/// üstüne kaydırıldığında ÖNCE burası çağrılmalı — YEREL arşivde zaten
/// `before_timestamp`'ten eski mesaj varsa (ağ gerekmeden, ücretsiz) onları
/// döner. Boş/sınırdan az dönerse Kotlin tarafı `requestOlderMessageHistory`
/// ile karşı taraftan (ağ üzerinden) devamını istemeli.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getMessageHistoryBefore<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, before_timestamp: jlong, limit: jni::sys::jint) -> jstring {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        // H57: lock dropped before the JSON is built.
        let history = core_lock_read().load_message_history(&fp, limit.clamp(0, MAX_HISTORY_PAGE) as u32, Some(before_timestamp));
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getMessageHistoryBefore panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// bkz. `getMessageHistoryBefore` aynı notu — grup arşivi için. Bulunamazsa/
/// boşsa Kotlin `requestOlderGroupMessageHistory` ile ağdan ister.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getGroupMessageHistoryBefore<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, before_timestamp: jlong, limit: jni::sys::jint) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let result = catch_panic(move || {
        // H57: lock dropped before the JSON is built.
        let history = core_lock_read().load_group_message_history(&gid, limit.clamp(0, MAX_HISTORY_PAGE) as u32, Some(before_timestamp));
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getGroupMessageHistoryBefore panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// Spec dışı, hata düzeltmesi (grup geçmişi kalıcılığı): `getMessageHistory`'nin
/// grup karşılığı — `GroupChatActivity` açılışında çağrılmalı, aksi halde
/// (önceki davranış) ekran her açılışta boştan başlar ve sadece o an
/// canlı gelen/giden mesajları gösterir (bkz. `load_group_message_history`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getGroupMessageHistory<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, limit: jni::sys::jint) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let result = catch_panic(move || {
        // H57: lock dropped before the JSON is built.
        let history = core_lock_read().load_group_message_history(&gid, limit.clamp(0, MAX_HISTORY_PAGE) as u32, None);
        serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string())
    });
    let json = result.unwrap_or_else(|e| { error!("getGroupMessageHistory panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, json)
}

/// Spec dışı: dosya/foto/video/ses eki gönderir (bkz.
/// `P2PCore::prepare_and_send_file`). `source_path` Kotlin tarafından
/// zaten yerel bir dosya yoluna kopyalanmış olmalı (content:// URI burada
/// işlenmez). BİLİNEN SINIR: senkron bir çağrı — büyük dosyalar için
/// Kotlin tarafı bunu ana thread DIŞINDA (coroutine/Dispatchers.IO)
/// çağırmalıdır, aksi halde ANR riski vardır. Dönüş: `sendMessage` ile
/// aynı JSON biçimi, `message_id` alanı burada `file_id`'dir.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_prepareAndSendFile<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, source_path: JString<'local>, file_name: JString<'local>, mime_type: JString<'local>, preview_jpeg: JByteArray<'local>, duration_ms: jni::sys::jint, caption: JString<'local>, reply_to_message_id: JString<'local>, reply_to_preview: JString<'local>) -> jstring {
    let target_str: String = jstr(&mut env, &target).unwrap_or_default();
    let source_str: String = jstr(&mut env, &source_path).unwrap_or_default();
    let name_str: String = jstr(&mut env, &file_name).unwrap_or_default();
    let mime_str: String = jstr(&mut env, &mime_type).unwrap_or_default();
    // `preview_jpeg` foto/video DIŞINDAKİ türler için Kotlin tarafından
    // `null` geçirilir (bkz. P2PLib.kt) — JNI'da bu, alttaki JObject'in
    // null olmasıyla temsil edilir.
    let preview_vec: Option<Vec<u8>> = if preview_jpeg.is_null() {
        None
    } else {
        Some(jbytearray_to_vec(&mut env, &preview_jpeg))
    };
    // `duration_ms`: sesli mesaj DIŞINDAKİ türler için Kotlin -1 geçirir
    // (jint null taşıyamadığından) — burada `Option<u32>`'ye çevrilir.
    let duration_opt: Option<u32> = if duration_ms < 0 { None } else { Some(duration_ms as u32) };
    // Spec dışı, kullanıcı isteği: ekle birlikte açıklama ve yanıt bağlamı.
    // Kotlin, "yok" durumunu BOŞ dize olarak geçiriyor (JNI'da null string
    // ayrı bir kol gerektirirdi ve üç alan için gereksiz karmaşa) — boş
    // dizeler burada `None`'a çevriliyor.
    let caption_str: String = jstr(&mut env, &caption).unwrap_or_default();
    let reply_id: Option<String> = jstr(&mut env, &reply_to_message_id).filter(|v: &String| !v.is_empty());
    let reply_preview: Option<String> = jstr(&mut env, &reply_to_preview).filter(|v: &String| !v.is_empty());
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        // Kilit-bölme düzeltmesi: kilit burada DEĞİL, fonksiyonun kendi
        // kısa fazlarında alınır — şifreleme sırasında poll_events çalışmaya
        // devam eder (bkz. `prepare_and_send_file_unlocked`).
        prepare_and_send_file_unlocked(target_str, source_str, name_str, mime_str, preview_vec, duration_opt, caption_str, reply_id, reply_preview)
    });
    match result {
        Ok(Ok((file_id, status))) => safe_new_jstring(&mut env, serde_json::json!({"message_id": file_id, "status": status}).to_string()),
        Ok(Err(e)) => { error!("prepare_and_send_file failed: {}", e); safe_new_jstring(&mut env, coded_error(&e)) }
        Err(e) => { error!("prepare_and_send_file panicked: {}", e); safe_new_jstring(&mut env, coded_error(&format!("panic: {}", e))) }
    }
}

/// Bir dosyanın parçalarını indirmeyi başlatır — BAŞARIYLA döndüyse
/// ("OK") ilerleme/tamamlanma `pollNetwork`'ün `"file_progress"`/
/// `"file_complete"`/`"file_failed"` olaylarıyla bildirilir (bkz.
/// `P2PCore::download_file`). BAŞARISIZSA (`"Error: ..."`) senkron olarak
/// hemen döner — bu durumda `pollNetwork` üzerinden HİÇBİR olay
/// gelmeyecektir (indirme hiç başlamadı: `active_downloads`'a hiç
/// eklenmedi), çağıran taraf bunu KENDİSİ ele almalı (bkz. ChatActivity
/// notu — önceden bu dönüş değeri jboolean'dı ve Kotlin tarafında hiç
/// kontrol edilmiyordu, bu da "İndiriliyor" durumunda sonsuza kadar
/// takılı kalan bir UI'ye yol açıyordu).
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

/// JSON-encoded `List<AttachmentSummary>` — bir sohbetteki bilinen dosya
/// eklerini listeler (bkz. `P2PCore::list_attachments`).
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

/// #80: `listAttachmentsBefore(peer, beforeMs, limit)` — one older page.
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

/// Spec dışı, kullanıcı isteği (grup ekleri): `prepareAndSendFile`'ın grup
/// karşılığı — bkz. `P2PCore::prepare_and_send_group_file`. Dönüş:
/// başarılıysa `file_id`, aksi halde `"Error: ..."`. İndirme, tamamlanmış
/// bir grup ekinin herhangi bir üyesi için MEVCUT `downloadFile` JNI
/// export'u ile yapılır — `download_file` zaten göndericinin cihaz
/// parmak izine göre çalışıyor, gruba özel bir indirme mekanizması
/// gerekmiyor (bkz. `list_group_attachments`'ın döndürdüğü
/// `peer_device_fingerprint` alanı).
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
    // bkz. prepareAndSendFile aynı not — boş dize = "yok".
    let caption_str: String = jstr(&mut env, &caption).unwrap_or_default();
    let reply_id: Option<String> = jstr(&mut env, &reply_to_message_id).filter(|v: &String| !v.is_empty());
    let reply_preview: Option<String> = jstr(&mut env, &reply_to_preview).filter(|v: &String| !v.is_empty());
    let reply_sender: Option<String> = jstr(&mut env, &reply_to_sender_identity_id).filter(|v: &String| !v.is_empty());
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        // bkz. prepareAndSendFile aynı kilit-bölme notu.
        prepare_and_send_group_file_unlocked(group_id_str, source_str, name_str, mime_str, preview_vec, duration_opt, caption_str, reply_id, reply_preview, reply_sender)
    });
    match result {
        Ok(Ok(file_id)) => safe_new_jstring(&mut env, file_id),
        Ok(Err(e)) => { error!("prepare_and_send_group_file failed: {}", e); safe_new_jstring(&mut env, coded_error(&e)) }
        Err(e) => { error!("prepare_and_send_group_file panicked: {}", e); safe_new_jstring(&mut env, coded_error(&format!("panic: {}", e))) }
    }
}

/// bkz. `listAttachments` aynı notu — grup ekleri için (bkz.
/// `P2PCore::list_group_attachments`).
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

/// Tamamlanmış bir ekin düz metin (çözülmüş) kopyasının mutlak yolunu
/// döner, ya da hata varsa `"Error: ..."`. BİLİNEN SINIR: senkron — büyük
/// dosyalar için Kotlin tarafı ana thread DIŞINDA çağırmalıdır (bkz.
/// `P2PCore::get_attachment_plaintext_path`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getAttachmentPlaintextPath<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>) -> jstring {
    let file_id_str: String = jstr(&mut env, &file_id).unwrap_or_default();
    let result = catch_panic(move || {
        // bkz. prepareAndSendFile aynı kilit-bölme notu — çözme kilitsiz.
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

/// `pixels`: a direct ByteBuffer of `width * height` RGBA pixels, not
/// premultiplied (native memory: a 48 MP photo does not fit the Java heap).
/// Writes a lossless JPEG XL to `out_path`. "OK" or "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_encodeJxlLossless<'local>(
    mut env: JNIEnv<'local>, _class: JClass<'local>, bitmap: JObject<'local>,
    has_alpha: jboolean, out_path: JString<'local>,
) -> jstring {
    let out: String = jstr(&mut env, &out_path).unwrap_or_default();
    // Native heap, not the Java one: a direct ByteBuffer on Android is a
    // managed array, and 48 MP of pixels ran the app out of Java memory.
    // L-95: raw pointer code, inside the panic guard too.
    let rgba = catch_panic(|| bitmap_rgba(&env, &bitmap)).ok().flatten();
    let result = match rgba {
        Some((mut rgba, width, height)) => catch_panic(move || {
            attachments::encode_jxl_lossless(&mut rgba, width, height, has_alpha != 0, std::path::Path::new(&out))
        }),
        None => Ok(Err("not an RGBA_8888 bitmap".to_string())),
    };
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) | Err(e) => format!("Error: {}", e),
    };
    safe_new_jstring(&mut env, out)
}

/// H26: an animated image as a lossless animated JPEG XL. `frames`: one
/// `byte[]` per frame of `width * height` RGBA pixels, not premultiplied (what
/// `Bitmap.copyPixelsToBuffer` gives for `ARGB_8888`); `delays_ms` one per
/// frame. At most `MAX_ANIMATION_FRAMES` frames and `MAX_IMAGE_PIXELS` in all.
/// "OK" or "Error: CODE: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_encodeJxlAnimated<'local>(
    mut env: JNIEnv<'local>, _class: JClass<'local>, frames: jni::objects::JObjectArray<'local>,
    width: jni::sys::jint, height: jni::sys::jint, delays_ms: jni::objects::JIntArray<'local>,
    has_alpha: jboolean, out_path: JString<'local>,
) -> jstring {
    let out: String = jstr(&mut env, &out_path).unwrap_or_default();
    let count = env.get_array_length(&frames).unwrap_or(0).max(0) as usize;
    let mut delays = vec![0i32; env.get_array_length(&delays_ms).unwrap_or(0).max(0) as usize];
    let mut pixels: Vec<Vec<u8>> = Vec::new();
    let result = if width < 2 || height < 2 || count > attachments::MAX_ANIMATION_FRAMES || delays.len() != count
        || env.get_int_array_region(&delays_ms, 0, &mut delays).is_err()
    {
        let _ = env.exception_clear();
        Ok(Err("Too many frames or bad sizes".to_string()))
    } else {
        // The Java arrays are copied one by one; the total is capped first.
        let frame_len = width as u64 * height as u64 * 4;
        let mut bad = frame_len.saturating_mul(count as u64) > attachments::MAX_IMAGE_PIXELS * 4;
        for i in 0..count {
            if bad {
                break;
            }
            let Ok(element) = env.get_object_array_element(&frames, i as i32) else { bad = true; break };
            let array = JByteArray::from(element);
            let bytes = jbytearray_to_vec(&mut env, &array);
            let _ = env.delete_local_ref(array);
            bad = bytes.len() as u64 != frame_len;
            pixels.push(bytes);
        }
        if bad {
            let _ = env.exception_clear();
            Ok(Err("Too many frames or bad sizes".to_string()))
        } else {
            let delays: Vec<u32> = delays.iter().map(|&d| d.max(0) as u32).collect();
            catch_panic(move || attachments::encode_jxl_animated(&mut pixels, width as u32, height as u32, &delays, has_alpha != 0, std::path::Path::new(&out)))
        }
    };
    let out = coded(result).map_or_else(|e| e, |()| "OK".to_string());
    safe_new_jstring(&mut env, out)
}

/// H26: an animated JPEG XL as an animated GIF (see `attachments::jxl_to_gif`).
/// `getAttachmentPlaintextPath` already does this for a received one.
/// "OK" or "Error: CODE: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_jxlToGif<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, in_path: JString<'local>, out_path: JString<'local>) -> jstring {
    let src: String = jstr(&mut env, &in_path).unwrap_or_default();
    let dst: String = jstr(&mut env, &out_path).unwrap_or_default();
    let result = catch_panic(move || attachments::jxl_to_gif(std::path::Path::new(&src), std::path::Path::new(&dst)));
    let out = coded(result).map_or_else(|e| e, |()| "OK".to_string());
    safe_new_jstring(&mut env, out)
}

/// Sticker JNI results: the value, or "Error: CODE: ...".
pub(crate) fn sticker_reply(env: &mut JNIEnv, result: Result<Result<String, String>, String>) -> jstring {
    let out = coded(result).unwrap_or_else(|e| e);
    safe_new_jstring(env, out)
}

/// A new sticker from RGBA frames (same layout as `encodeJxlAnimated`; one
/// frame = still). The caller scales to at most 600 px a side first.
/// Returns the sticker id.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_importStickerFrames<'local>(
    mut env: JNIEnv<'local>, _class: JClass<'local>, frames: jni::objects::JObjectArray<'local>,
    width: jni::sys::jint, height: jni::sys::jint, delays_ms: jni::objects::JIntArray<'local>,
    origin: JString<'local>,
) -> jstring {
    let origin = jstr(&mut env, &origin);
    let count = env.get_array_length(&frames).unwrap_or(0).max(0) as usize;
    let mut delays = vec![0i32; env.get_array_length(&delays_ms).unwrap_or(0).max(0) as usize];
    let side = attachments::STICKER_MAX_SIDE as i32;
    // u64: i32 * i32 * 4 cannot overflow it, so no panic before the range checks.
    let frame_len = width.max(0) as u64 * height.max(0) as u64 * 4;
    let mut pixels: Vec<Vec<u8>> = Vec::new();
    let mut bad = width < 1 || height < 1 || width > side || height > side || count == 0
        || count > attachments::MAX_ANIMATION_FRAMES || delays.len() != count
        || (frame_len / 4).saturating_mul(count as u64) > attachments::MAX_IMAGE_PIXELS
        || env.get_int_array_region(&delays_ms, 0, &mut delays).is_err();
    for i in 0..count {
        if bad {
            break;
        }
        let Ok(element) = env.get_object_array_element(&frames, i as i32) else { bad = true; break };
        let array = JByteArray::from(element);
        let bytes = jbytearray_to_vec(&mut env, &array);
        let _ = env.delete_local_ref(array);
        bad = bytes.len() as u64 != frame_len;
        pixels.push(bytes);
    }
    let result = if bad {
        let _ = env.exception_clear();
        Ok(Err("Too many frames or bad sizes".to_string()))
    } else {
        let delays: Vec<u32> = delays.iter().map(|&d| d.max(0) as u32).collect();
        catch_panic(move || import_sticker_frames_unlocked(pixels, width as u32, height as u32, &delays, origin))
    };
    sticker_reply(&mut env, result)
}

/// JSON `[{"id","animated","created_at"}]`, newest first.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listStickers<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let json = catch_panic(|| core_lock_read().list_stickers()).unwrap_or_else(|_| "[]".to_string());
    safe_new_jstring(&mut env, json)
}

/// First frame of a sticker as PNG path, or "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_stickerFirstFrame<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, id: JString<'local>) -> jstring {
    let id: String = jstr(&mut env, &id).unwrap_or_default();
    let result = catch_panic(move || sticker_first_frame_unlocked(&id));
    sticker_reply(&mut env, result)
}

/// First frame of a JPEG XL attachment as PNG path, or "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getAttachmentFirstFrame<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>) -> jstring {
    let file_id: String = jstr(&mut env, &file_id).unwrap_or_default();
    let result = catch_panic(move || attachment_first_frame_unlocked(&file_id));
    sticker_reply(&mut env, result)
}

/// A viewable copy of a sticker: `.png`, or `.gif` when animated.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_stickerPlainPath<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, id: JString<'local>) -> jstring {
    let id: String = jstr(&mut env, &id).unwrap_or_default();
    let result = catch_panic(move || sticker_plain_path_unlocked(&id));
    sticker_reply(&mut env, result)
}

/// True when my store already has a sticker with this origin id.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_hasStickerOrigin<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, origin: JString<'local>) -> jboolean {
    let origin: String = jstr(&mut env, &origin).unwrap_or_default();
    catch_panic(move || core_lock_read().has_sticker_origin(&origin)).unwrap_or(false) as jboolean
}

/// Removes a sticker from my store (and from my other devices). "OK".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deleteSticker<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, id: JString<'local>) -> jstring {
    let id: String = jstr(&mut env, &id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().delete_sticker(&id, true).map(|()| "OK".to_string())
    });
    sticker_reply(&mut env, result)
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setStickerFavorite<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, id: JString<'local>, favorite: jni::sys::jboolean) -> jstring {
    let id: String = jstr(&mut env, &id).unwrap_or_default();
    let result = catch_panic(move || core_lock().set_sticker_favorite(&id, favorite != 0).map(|()| "OK".to_string()));
    sticker_reply(&mut env, result)
}

/// Sends a sticker to a contact device. Returns the attachment's file id.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendSticker<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer: JString<'local>, sticker_id: JString<'local>, reply_to_message_id: JString<'local>, reply_to_preview: JString<'local>) -> jstring {
    let peer: String = jstr(&mut env, &peer).unwrap_or_default();
    let id: String = jstr(&mut env, &sticker_id).unwrap_or_default();
    let reply = sticker_reply_to(&mut env, &reply_to_message_id, &reply_to_preview, None);
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        send_sticker_unlocked(Some(peer), None, &id, reply)
    });
    sticker_reply(&mut env, result)
}

/// Sends a sticker to a group. Returns the attachment's file id.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendGroupSticker<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, sticker_id: JString<'local>, reply_to_message_id: JString<'local>, reply_to_preview: JString<'local>, reply_to_sender_identity_id: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let id: String = jstr(&mut env, &sticker_id).unwrap_or_default();
    let reply = sticker_reply_to(&mut env, &reply_to_message_id, &reply_to_preview, Some(&reply_to_sender_identity_id));
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        send_sticker_unlocked(None, Some(gid), &id, reply)
    });
    sticker_reply(&mut env, result)
}

/// The quote a sticker answers; an empty message id means none.
pub(crate) fn sticker_reply_to(env: &mut JNIEnv, id: &JString, preview: &JString, sender: Option<&JString>) -> Option<(String, String, Option<String>)> {
    let id: String = jstr(env, id).unwrap_or_default();
    if id.is_empty() { return None; }
    let preview: String = jstr(env, preview).unwrap_or_default();
    let sender = sender.and_then(|s| jstr(env, s)).filter(|s: &String| !s.is_empty());
    Some((id, preview, sender))
}

/// Copies a received (downloaded) sticker attachment into my store.
/// Returns the sticker id.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_saveReceivedSticker<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, file_id: JString<'local>) -> jstring {
    let file_id: String = jstr(&mut env, &file_id).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        save_received_sticker_unlocked(&file_id)
    });
    sticker_reply(&mut env, result)
}

/// The pixels of an `ARGB_8888` `android.graphics.Bitmap` (RGBA bytes in
/// memory), copied row by row past its stride. ponytail: one native copy of
/// the image; lock the pixels across the encode if memory gets tight.
#[cfg(target_os = "android")]
pub(crate) fn bitmap_rgba(env: &JNIEnv, bitmap: &JObject) -> Option<(Vec<u8>, u32, u32)> {
    #[repr(C)]
    struct AndroidBitmapInfo { width: u32, height: u32, stride: u32, format: i32, flags: u32 }
    #[link(name = "jnigraphics")]
    extern "C" {
        fn AndroidBitmap_getInfo(env: *mut jni::sys::JNIEnv, bitmap: jni::sys::jobject, info: *mut AndroidBitmapInfo) -> i32;
        fn AndroidBitmap_lockPixels(env: *mut jni::sys::JNIEnv, bitmap: jni::sys::jobject, addr: *mut *mut std::ffi::c_void) -> i32;
        fn AndroidBitmap_unlockPixels(env: *mut jni::sys::JNIEnv, bitmap: jni::sys::jobject) -> i32;
    }
    const RGBA_8888: i32 = 1;
    let (raw_env, raw_bitmap) = (env.get_raw(), bitmap.as_raw());
    let mut info = AndroidBitmapInfo { width: 0, height: 0, stride: 0, format: 0, flags: 0 };
    // SAFETY: a live JNI env and a Bitmap reference of this call; the pixels
    // are read only between lock and unlock.
    unsafe {
        if AndroidBitmap_getInfo(raw_env, raw_bitmap, &mut info) != 0 || info.format != RGBA_8888 {
            return None;
        }
        let (w, h, stride) = (info.width as usize, info.height as usize, info.stride as usize);
        // Checked: `stride * h` can overflow a 32-bit usize (armeabi-v7a).
        let Some(len) = stride.checked_mul(h) else { return None };
        if (w as u64 * h as u64) > attachments::MAX_IMAGE_PIXELS || stride < w.checked_mul(4)? {
            return None;
        }
        // H58: fallible; up to 96 MB, and a failed `with_capacity` aborts
        // the process (no unwind for `catch_panic` to catch).
        let mut rgba = Vec::new();
        if rgba.try_reserve_exact(w * h * 4).is_err() {
            return None;
        }
        let mut addr = std::ptr::null_mut();
        if AndroidBitmap_lockPixels(raw_env, raw_bitmap, &mut addr) != 0 || addr.is_null() {
            return None;
        }
        // H60: unlocked on every exit, a panic included.
        struct Unlock(*mut jni::sys::JNIEnv, jni::sys::jobject);
        impl Drop for Unlock {
            fn drop(&mut self) {
                // SAFETY: the same env/bitmap whose pixels were locked above.
                unsafe { AndroidBitmap_unlockPixels(self.0, self.1); }
            }
        }
        let _unlock = Unlock(raw_env, raw_bitmap);
        let src = std::slice::from_raw_parts(addr as *const u8, len);
        for y in 0..h {
            rgba.extend_from_slice(&src[y * stride..y * stride + w * 4]);
        }
        Some((rgba, info.width, info.height))
    }
}

#[cfg(not(target_os = "android"))]
pub(crate) fn bitmap_rgba(_env: &JNIEnv, _bitmap: &JObject) -> Option<(Vec<u8>, u32, u32)> {
    None
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

/// bkz. `P2PCore::own_identity_id` dokümantasyonu.
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

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_startNetwork<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, node_mode: jboolean, tor_enabled: jboolean) -> jstring {
    let result = catch_panic(move || {
        // `SwarmBuilder::with_tokio()` (start_network içinde) bir Tokio runtime
        // context'inin thread-local olarak aktif olmasını gerektirir — bu JNI
        // çağrısı ham bir JNI thread'inde çalıştığından, `RUNTIME.enter()` ile
        // context'i elle kurmadan çağırmak panic'e yol açar (bkz. catch_panic
        // dokümantasyonu — JNI çağrıları HERHANGİ bir Java/Kotlin thread'inden
        // gelebilir, bu yüzden context'i HER JNI export'unda ayrı ayrı kurmak
        // gerekir; bir thread'de enter() etmek başka bir thread'i etkilemez).
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.start_network(node_mode != 0, tor_enabled != 0)
    });
    match result {
        Ok(Ok(pid)) => safe_new_jstring(&mut env, pid),
        Ok(Err(e)) => safe_new_jstring(&mut env, format!("Error: {}", e)),
        Err(e) => safe_new_jstring(&mut env, format!("Error: {}", e)),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setNodeMode(_env: JNIEnv, _class: JClass, enabled: jboolean) {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.set_node_mode(enabled != 0);
    });
}

/// Spec dışı, kullanıcı isteği: Ayarlar'daki geçmiş/ek depolama sınırı
/// slider'ı (100MB-32GB) için — bkz. `set_history_storage_limit_bytes`.
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

/// Karşı tarafın dial edebileceği `node_address`: yalnızca onion adresi
/// (`/dns/<host>.onion/tcp/<port>/p2p/<peer_id>`, bkz.
/// `P2PCore::get_node_address`). Onion servisi yayında değilken (Tor
/// bootstrap sürerken, ağ yokken) boş string döner — dinleme adresi ASLA
/// döndürülmez; Kotlin tarafı buna göre "bağlanılıyor" göstermeli.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getNodeAddress<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.get_node_address().unwrap_or_default()
    });
    let addr = result.unwrap_or_else(|e| { error!("getNodeAddress panicked: {}", e); String::new() });
    safe_new_jstring(&mut env, addr)
}

/// Spec dışı, kullanıcı isteği (Tor): UI için Tor durumu. Dönüş:
/// "disabled" | "bootstrapping" | "ready" | "ready|<host>.onion" | "failed".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_torStatus<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.tor_status()
    });
    let out = result.unwrap_or_else(|e| { error!("torStatus panicked: {}", e); "failed".to_string() });
    safe_new_jstring(&mut env, out)
}

/// Spec dışı, kullanıcı isteği: BU cihazın genel bağlantı durumu (karşı
/// tarafınki DEĞİL) — JSON: `{"connected_peers": N, "listening": bool,
/// "tor_enabled": bool, "tor_status": "...", "node_mode": bool}` (bkz.
/// `P2PCore::own_connection_status`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_ownConnectionStatus<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.own_connection_status().to_string()
    });
    let out = result.unwrap_or_else(|e| { error!("ownConnectionStatus panicked: {}", e); "{}".to_string() });
    safe_new_jstring(&mut env, out)
}

/// Spec dışı: ChatActivity'nin "bağlanılıyor..." göstergesi için — bkz.
/// `P2PCore::has_active_session`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_hasActiveSession<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) -> jboolean {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock_read();
        core.has_active_session(&fp)
    });
    result.unwrap_or(false) as jboolean
}

/// Spec dışı: GERÇEK canlı bağlantı durumu (bkz. `P2PCore::is_peer_connected`
/// dokümantasyonu) — `hasActiveSession`'ın aksine bir kez kurulduktan sonra
/// hep `true` kalmaz, `Swarm`'ın o anki bağlantı defterini yansıtır.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_isPeerConnected<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) -> jboolean {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let result = catch_panic(move || {
        let core = core_lock_read();
        core.is_peer_connected(&fp)
    });
    result.unwrap_or(false) as jboolean
}

/// Spec dışı: bir sohbet ekranı açıldığında proaktif olarak el sıkışmayı
/// başlatır — bkz. `P2PCore::ensure_handshake`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_ensureHandshake<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>) {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        if let Err(e) = core.ensure_handshake(&fp) {
            error!("ensure_handshake failed: {}", e);
        }
    });
}

/// Spec dışı: node modu kapalı bir cihazda sohbet ekranı yerel geçmiş
/// bulamadığında çağrılır — bkz. `P2PCore::request_history_sync`. Yanıt
/// asenkron (`pollNetwork` üzerinden `"history_sync"` olayı) geldiği için
/// bu fonksiyon hemen döner, sonuç beklemez.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_requestHistorySync<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer_device_fingerprint: JString<'local>, limit: jni::sys::jint) {
    let fp: String = jstr(&mut env, &peer_device_fingerprint).unwrap_or_default();
    let limit_u32 = limit.clamp(0, MAX_HISTORY_PAGE) as u32;
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        if let Err(e) = core.request_history_sync(fp, limit_u32) {
            error!("request_history_sync failed: {}", e);
        }
    });
}

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
        // bkz. startNetwork notu — bu JNI çağrısı (kamera analiz thread'i
        // gibi) startNetwork'ü çağıran thread'den TAMAMEN FARKLI bir
        // thread'de çalışabilir; `dial()`'ın tetiklediği libp2p executor
        // görevleri için burada da AYRICA bir Tokio context'i gerekir —
        // bu satır olmadan tam olarak bu fonksiyonda yaşanan
        // "there is no reactor running" panic'i tekrarlanırdı.
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.process_qr_packet(&raw)
    });
    // Spec dışı, kullanıcı isteği: başarılıysa artık BARE bir identity_id
    // DEĞİL, `{"identity_id":...,"device_fingerprint":...,"device_name":...}`
    // JSON'u — Kotlin tarafı `device_fingerprint`'i kullanarak yeni kişinin
    // sohbet ekranını DOĞRUDAN açabilsin diye (bkz. `process_qr_packet`
    // dokümantasyonu, ChatActivity "Bağlanılıyor..." göstergesi).
    match coded(result) {
        Ok((identity_id, device_fingerprint, device_name)) => safe_new_jstring(&mut env, serde_json::json!({
            "identity_id": identity_id, "device_fingerprint": device_fingerprint, "device_name": device_name
        }).to_string()),
        Err(e) => safe_new_jstring(&mut env, e),
    }
}

/// M129: what a scanned contact QR names, for the confirm step before
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
// Çoklu-cihaz (spec 1.5/1.6/1.7) JNI köprüsü.
// ---------------------------------------------------------------------------

/// İkincil cihazda: bu cihazı gösteren "cihaz ekleme QR'ı"nı (CBOR) üretir.
/// Bu cihaz önce normal `createIdentity` + `startNetwork`'ten geçmiş olmalı.
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
        Ok(Ok(_)) => coded_error("Geçersiz cihaz kodu"),
        Ok(Err(e)) => coded_error(&e),
        Err(e) => coded_error(&format!("panic: {}", e)),
    };
    safe_new_jstring(&mut env, out)
}

/// The short code both devices show while a device is linked, for the user to
/// compare by eye: six digits from the link QR's device fingerprint and
/// nonce. The new device computes it from the QR it shows, the approving
/// device from the QR it scanned. Empty for a QR that is not a link request.
pub(crate) fn device_link_code(request_cbor: &[u8]) -> String {
    use sha2::Digest;
    let Ok(req) = DeviceLinkRequest::from_cbor(request_cbor) else { return String::new() };
    if req.nonce.len() != 16 || !is_fingerprint_hex(&req.device_fingerprint) {
        return String::new();
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"typeon-link-code-v1");
    hasher.update(req.device_fingerprint.to_ascii_lowercase().as_bytes());
    hasher.update(&req.nonce);
    let digest = hasher.finalize();
    let number = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03} {:03}", number / 1000, number % 1000)
}

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
        assert_eq!(code.len(), 7);
        assert_eq!(code, device_link_code(&request(1, "b")));
        assert_ne!(code, device_link_code(&request(2, "a")));
        assert_eq!(device_link_code(b"not a link request"), "");
    }
}

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deviceLinkCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, data: JByteArray<'local>) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &data);
    let out = catch_panic(move || device_link_code(&raw)).unwrap_or_default();
    safe_new_jstring(&mut env, out)
}

/// Birincil cihazda: ikincil cihazın QR'ını (CBOR) işler — onaylar, bağlanır,
/// senkron gönderir, kişilere duyurur. Dönüş: başarılıysa
/// `{"device_fingerprint":...,"device_name":...}`, aksi halde "Error: ...".
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_approveDeviceLink<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, data: JByteArray<'local>) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &data);
    let result = catch_panic(move || {
        // bkz. process_qr_packet notu — dial() için Tokio context gerekli.
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

/// Kimliğimin cihazları (bu cihaz + kardeşler) — JSON dizi.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listLinkedDevices<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        let core = core_lock_read();
        serde_json::Value::Array(core.list_linked_devices()).to_string()
    });
    let out = result.unwrap_or_else(|e| { error!("list_linked_devices panicked: {}", e); "[]".to_string() });
    safe_new_jstring(&mut env, out)
}

/// Bu cihaz, bir kimliğe İKİNCİL olarak mı bağlandı (yani başka bir cihaz
/// tarafından onaylandı mı)? UI'nin "birincil" vs "bağlı cihaz" ayrımı için.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_isSecondaryDevice<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) -> jboolean {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.own_device_add.is_some()
    });
    result.unwrap_or(false) as jboolean
}

/// Bir kardeş cihazı iptal eder (spec 1.6). Dönüş: "OK" veya "Error: ...".
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

/// Çoklu-cihaz (spec 1.7.1): bir sohbet okununca kardeş cihazlara "okundu"
/// bildir. 1:1 için `peerDeviceFingerprint` dolu + `groupId` boş; grup için
/// tersi. Fire-and-forget.
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

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_processManualEntry<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, text: JString<'local>) -> jstring {
    let text_str: String = jstr(&mut env, &text).unwrap_or_default();
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.process_manual_entry(&text_str)
    });
    // bkz. `processQrPacket` aynı notu.
    match coded(result) {
        Ok((identity_id, device_fingerprint, device_name)) => safe_new_jstring(&mut env, serde_json::json!({
            "identity_id": identity_id, "device_fingerprint": device_fingerprint, "device_name": device_name
        }).to_string()),
        Err(e) => safe_new_jstring(&mut env, e),
    }
}

/// Dönüş: başarılıysa `{"message_id":"...","status":"sent"|"pending"}`,
/// başarısızsa `"Error: ..."`. `status`, UI'nin gönderim ikonunu (saat/tik)
/// hemen doğru göstermesi için — "pending" ise arka planda otomatik olarak
/// yeniden denenip bir "status" olayıyla (bkz. pollNetwork) güncellenecek.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_sendMessage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, target: JString<'local>, msg: JString<'local>, reply_to_message_id: JString<'local>, reply_to_preview: JString<'local>) -> jstring {
    let target_str: String = jstr(&mut env, &target).unwrap_or_default();
    let msg_str: String = jstr(&mut env, &msg).unwrap_or_default();
    // bkz. `optional_jstring` dokümantasyonu — WhatsApp tarzı "yanıtla",
    // yanıt verilmiyorsa Kotlin tarafı `null` geçirir.
    let reply_id_opt = optional_jstring(&mut env, &reply_to_message_id);
    let reply_preview_opt = optional_jstring(&mut env, &reply_to_preview);
    let result = catch_panic(move || {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.send_message(target_str, msg_str, reply_id_opt, reply_preview_opt)
    });
    match result {
        Ok(Ok((message_id, status))) => safe_new_jstring(&mut env, serde_json::json!({"message_id": message_id, "status": status}).to_string()),
        Ok(Err(e)) => { error!("send_message failed: {}", e); safe_new_jstring(&mut env, coded_error(&e)) }
        Err(e) => { error!("send_message panicked: {}", e); safe_new_jstring(&mut env, coded_error(&format!("panic: {}", e))) }
    }
}

/// Bir mesajı düzenler — bkz. `P2PCore::edit_message` dokümantasyonu.
/// Dönüş: `sendMessage` ile aynı JSON biçimi (bu, edit paketinin KENDİ
/// message_id'sidir — UI, düzenlenen ORİJİNAL mesajın id'sini kullanmaya
/// devam etmeli, bkz. ChatActivity).
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

/// Spec dışı, kullanıcı isteği: bir mesaja emoji tepkisi bırakır/kaldırır
/// — bkz. `P2PCore::react_to_message`. `emoji` boş dize ise kendi tepkim
/// kaldırılır. Dönen değer, o mesajın GÜNCEL tepki özeti (ör. `"👍2 ❤️"`),
/// böylece çağıran tarafın ayrıca bir sorgu yapması gerekmez.
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

/// bkz. `P2PCore::list_reactions` — tepki pill'ine dokunulduğunda "kim ne
/// attı" listesini doldurmak için.
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

/// bkz. `reactToMessage` — grup karşılığı.
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

/// Bir mesajı siler — bkz. `P2PCore::delete_message` dokümantasyonu.
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

/// bkz. `editMessage` aynı notu — grup mesajları için (bkz.
/// `P2PCore::edit_group_message`). `targetGroupMessageLocalId` — bkz.
/// GroupChatActivity notu, gönderilen grup mesajının `messageId`'si zaten
/// bu değerdir.
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

/// bkz. `deleteMessage` aynı notu — grup mesajları için (bkz.
/// `P2PCore::delete_group_message`).
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

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_pollNetwork<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jobjectArray {
    let result = catch_panic(|| {
        // `poll_events` kendi içinde zaten `RUNTIME.block_on(...)` kullanıyor
        // (bu da context'i kurar) ama tutarlılık için burada da enter ediyoruz.
        let _guard = RUNTIME.enter();
        CORE_DIRTY.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut core = core_lock_poll();
        core.poll_events()
    });
    let texts = result.unwrap_or_else(|e| { error!("pollNetwork panicked: {}", e); Vec::new() });
    strings_to_jobjectarray(&mut env, &texts)
}

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

/// "Yazıyor..." göstergesi gönderir — bkz. `P2PCore::send_typing_indicator`.
/// Kasıtlı olarak sessizce başarısız olabilir (fire-and-forget, `Boolean`
/// dönüşü sadece hata ayıklama için, Kotlin tarafı bunu genelde kontrol
/// etmez).
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

/// bkz. `sendTypingIndicator` aynı notu — grup sohbeti için (bkz.
/// `P2PCore::send_group_typing_indicator`).
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

/// "Görüldü" bildirimi gönderir — bkz. `P2PCore::send_seen`. UI, bir
/// mesajı kullanıcıya EKRANDA gösterdiği anda çağırmalı (otomatik değil —
/// bkz. `Ack`'in aksine). `group_message_local_id` 1:1 sohbette null
/// geçilmeli, grup sohbetinde gelen "group_message" olayındaki AYNI
/// değer geri gönderilmeli.
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

/// Kendi profil fotoğrafımızı döner (hiç ayarlanmadıysa boş dizi) — bkz.
/// `P2PCore::get_own_avatar`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getOwnProfilePicture<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jni::sys::jbyteArray {
    let result = catch_panic(|| {
        let core = core_lock_read();
        core.get_own_avatar().unwrap_or_default()
    });
    let bytes = result.unwrap_or_else(|e| { error!("getOwnProfilePicture panicked: {}", e); Vec::new() });
    bytes_to_jbytearray(&mut env, &bytes)
}

/// Kendi profil fotoğrafımızı ayarlar/kaldırır — bkz.
/// `P2PCore::set_own_profile_picture`. `avatar_jpeg` null ise fotoğraf
/// kaldırılır (tüm kişilere `None` bildirimi gönderilir).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setOwnProfilePicture<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, avatar_jpeg: JByteArray<'local>) -> jstring {
    let avatar_vec: Option<Vec<u8>> = if avatar_jpeg.is_null() {
        None
    } else {
        Some(jbytearray_to_vec(&mut env, &avatar_jpeg))
    };
    // M-178: a failed copy arrives empty; do not publish an empty picture.
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

/// Bu cihazın hesap adını değiştirir ve BİLİNEN HER kişiye otomatik
/// bildirir — bkz. `P2PCore::set_display_name`.
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

/// O anki hesap adı (boş = kimlik yok) — bkz. `P2PCore::own_display_name`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_getDisplayName<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| core_lock_read().own_display_name().unwrap_or_default());
    let out = result.unwrap_or_else(|e| { error!("getDisplayName panicked: {}", e); String::new() });
    safe_new_jstring(&mut env, out)
}

/// Bir sohbetin yerel geçmişini (mesajlar+ekler) temizler, eşleşmeyi
/// KORUR — bkz. `P2PCore::clear_chat_history`.
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

/// Bir kişiyi TAMAMEN siler (eşleşme dahil) — bkz. `P2PCore::delete_contact`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_deleteContact<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, contact_id: JString<'local>) -> jstring {
    let contact_id_str: String = jstr(&mut env, &contact_id).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.delete_contact(&contact_id_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("delete_contact failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("delete_contact panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

/// Bir kişinin TEK bir cihazını iptal eder (kişiyi/geçmişi SİLMEZ) — bkz.
/// `P2PCore::revoke_contact_device`.
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
pub extern "system" fn Java_com_p2p_messenger_P2PLib_addKnownRelayAddress<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, multiaddr: JString<'local>) -> jstring {
    let multiaddr_str: String = jstr(&mut env, &multiaddr).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.add_known_relay_address(&multiaddr_str)
    });
    let out = match result {
        Ok(Ok(())) => "OK".to_string(),
        Ok(Err(e)) => { error!("add_known_relay_address failed: {}", e); format!("Error: {}", e) }
        Err(e) => { error!("add_known_relay_address panicked: {}", e); format!("Error: {}", e) }
    };
    safe_new_jstring(&mut env, out)
}

// ---------------------------------------------------------------------------
// Sunucu (store-and-forward) seçeneği — bkz. `server_client` modülü.
// ---------------------------------------------------------------------------

/// Davet kodundan (`typeon-server:<multiaddr>#<jeton>`) bir sunucu ekler.
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
pub extern "system" fn Java_com_p2p_messenger_P2PLib_closeDeviceLinkWindow(_env: JNIEnv, _class: JClass) {
    api::close_device_link_window();
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

/// Geçmişi sunucuda saklama. Mesaj yönlendirmeden AYRI ve VARSAYILAN
/// KAPALI: arşiv gerçek bir yedek ve ratchet'in aksine ileri-gizli DEĞİL
/// (bkz. `server_seal::seal_archive_record` notu).
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
/// (bkz. `server_client::fetch_server_history`). `chat_key`: the peer device
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

/// Sunucudaki BÜTÜN geçmişi indirir — kurtarma dosyasından ya da cihaz
/// bağlamayla yeni kurulmuş bir cihaz için. Kaç sohbetin sorulduğunu döner.
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

/// Kök arşiv anahtarını (ARK) yükler — `setHistoryKey` ile aynı desen, ama
/// bu anahtar CİHAZA değil KİMLİĞE ait (bkz. `set_archive_root_key`).
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

/// Kullanıcı kararı: kişiyi ENGELLE (bkz. `block_identity`). `revoke`'un
/// aksine kalıcıdır ve yalnızca yüz yüze yeniden eşleşmeyle kalkar.
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

/// Engeli kaldırır. Arayüz bunu yalnızca kullanıcının açık isteğiyle
/// çağırmalı; uzaktan gelen hiçbir paket bu yola erişemez.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_unblockIdentity(mut _env: JNIEnv, _class: JClass, identity_id: JString) {
    let id: String = jstr(&mut _env, &identity_id).unwrap_or_default();
    if let Err(e) = catch_panic(move || core_lock().unblock_identity(&id)) {
        error!("unblockIdentity: {}", e);
    }
}

/// Pil düzeltmesi: ekran kapalı + uygulama arka planda iken açılır
/// (bkz. `set_power_save`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setPowerSave(mut _env: JNIEnv, _class: JClass, enabled: jboolean) {
    let on = enabled != 0;
    let _ = catch_panic(move || core_lock().set_power_save(on));
}

/// Engellenen kimliklerin listesi (JSON dizisi).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_listBlockedIdentities<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>) -> jstring {
    let result = catch_panic(|| {
        serde_json::to_string(&core_lock_read().list_blocked_identities()).unwrap_or_else(|_| "[]".to_string())
    });
    safe_new_jstring(&mut env, result.unwrap_or_else(|e| { error!("listBlockedIdentities panicked: {}", e); "[]".to_string() }))
}

/// Bir kişinin karşılaştırılacak güvenlik kodu (bkz. `contact_safety_code`).
/// Kişi/cihaz çözülemezse boş string.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_contactSafetyCode<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, identity_id: JString<'local>) -> jstring {
    let id: String = jstr(&mut env, &identity_id).unwrap_or_default();
    let result = catch_panic(move || core_lock_read().contact_safety_code(&id).unwrap_or_default());
    safe_new_jstring(&mut env, result.unwrap_or_default())
}

/// Kullanıcı kararı: grup üzerinden tanışılmış bir kişiye TAM güven verir
/// (bkz. `trust_contact`).
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

/// Grup kurucu yetkisini başka bir üyeye devreder (bkz.
/// `transfer_group_founder`).
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_transferGroupFounder<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, new_founder: JString<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let nf: String = jstr(&mut env, &new_founder).unwrap_or_default();
    let result = catch_panic(move || core_lock().transfer_group_founder(&gid, &nf));
    let out = coded(result).map_or_else(|e| e, |()| "OK".to_string());
    safe_new_jstring(&mut env, out)
}

/// Spec dışı, kullanıcı isteği: uygulama ön plana geldiğinde Kotlin
/// tarafından (bkz. `P2PApplication` foreground algılama) çağrılır — bkz.
/// `P2PCore::retry_all_pending_now` dokümantasyonu.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_retryAllPendingNow(_env: JNIEnv, _class: JClass) {
    let _ = catch_panic(|| {
        let mut core = core_lock();
        core.retry_all_pending_now();
    });
}

/// Ends a running `wait_for_network_activity` without taking the core lock.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_wakePoll(_env: JNIEnv, _class: JClass) {
    CORE_DIRTY.store(true, std::sync::atomic::Ordering::SeqCst);
    NET_WAKE.notify_waiters();
}

/// bkz. `wait_for_network_activity`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_waitForNetworkActivity(_env: JNIEnv, _class: JClass, timeout_ms: jlong) {
    let _ = catch_panic(|| wait_for_network_activity(timeout_ms.max(0) as u64));
}

/// Metered (cellular) network or not — with the screen off this is
/// radio-saver mode, see `RADIO_WINDOW_MS`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setMeteredNetwork(_env: JNIEnv, _class: JClass, metered: jboolean) {
    let _ = catch_panic(move || {
        let _guard = RUNTIME.enter();
        core_lock().set_metered(metered != 0);
    });
}

/// Spec dışı, kullanıcı isteği ("connection testing and re-connecting
/// automatically should be better"): Kotlin tarafından (bkz. P2PService
/// genel ağ değişikliği algılama) bir ağ arayüzü değişikliği (Wi-Fi<->
/// hücresel, ya da herhangi bir "varsayılan ağ değişti" olayı)
/// bildirildiğinde çağrılır — bkz. `P2PCore::reconnect_all_known_now`.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_notifyNetworkChanged(_env: JNIEnv, _class: JClass) {
    let _ = catch_panic(|| {
        let _guard = RUNTIME.enter();
        let mut core = core_lock();
        core.reconnect_all_known_now();
    });
}

/// JSON-encoded List<PendingMessageSummary> — Ayarlar'daki "bekleyen
/// mesajlar" listesi için (bkz. `P2PCore::list_pending_messages`).
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

/// bkz. `P2PCore::cancel_pending_message` dokümantasyonu.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_cancelPendingMessage(mut env: JNIEnv, _class: JClass, message_id: JString) -> jboolean {
    let id: String = jstr(&mut env, &message_id).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.cancel_pending_message(&id).is_ok()
    });
    result.unwrap_or(false) as jboolean
}

/// bkz. `P2PCore::retry_pending_message_now` dokümantasyonu — Ayarlar'daki
/// bekleyen mesajlar listesindeki manuel "Şimdi Dene" düğmesi.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_retryPendingMessageNow(mut env: JNIEnv, _class: JClass, message_id: JString) -> jboolean {
    let id: String = jstr(&mut env, &message_id).unwrap_or_default();
    let result = catch_panic(move || {
        let mut core = core_lock();
        core.retry_pending_message_now(&id).is_ok()
    });
    result.unwrap_or(false) as jboolean
}

/// JSON-encoded List<GroupSummary> — Groups tab GUI'si için.
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

/// "OK" or "Error: CODE: ..." (M112; was a Boolean).
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

/// "OK" or "Error: CODE: ..." (M112; was a Boolean).
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

/// Spec dışı, kullanıcı isteği: grubu TÜM üyeler için siler (yalnızca
/// kurucu) — bkz. `P2PCore::delete_group`.
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

/// #81 (H103): the founder re-sends the current group state to every
/// member device — bkz. `P2PCore::resend_group_to_all`. "OK" / "Error: …".
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

/// Spec dışı, kullanıcı isteği: kurucu OLMAYAN bir üye gruptan kendi
/// isteğiyle ayrılır — bkz. `P2PCore::leave_group`.
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

/// Grup profil fotoğrafını ayarlar/kaldırır — bkz. `P2PCore::set_group_avatar`.
/// SADECE kurucu için başarılı olur, aksi halde "Error: ..." döner (bkz.
/// Kotlin tarafının bunu göstermesi gereken bir hata olarak ele alması —
/// `inviteToGroup`/`removeFromGroup`'un aksine burada dönüş `jboolean`
/// DEĞİL `jstring`, çünkü "neden" başarısız olduğu kullanıcıya
/// gösterilmeye değer bir bilgi.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_setGroupProfilePicture<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, group_id: JString<'local>, avatar_jpeg: JByteArray<'local>) -> jstring {
    let gid: String = jstr(&mut env, &group_id).unwrap_or_default();
    let avatar_vec: Option<Vec<u8>> = if avatar_jpeg.is_null() {
        None
    } else {
        Some(jbytearray_to_vec(&mut env, &avatar_jpeg))
    };
    // M-178: a failed copy arrives empty; do not publish an empty picture.
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
    // bkz. `optional_jstring`/`sendMessage` AYNI desen.
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

#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_exportRecovery<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, pass: JString<'local>) -> jni::sys::jbyteArray {
    let pass_str = zeroize::Zeroizing::new(jstr(&mut env, &pass).unwrap_or_default());
    let result = catch_panic(move || {
        // Argon2 runs after the core lock is released (M-21).
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

/// `exportRecovery`'nin karşılığı — bkz. `import_recovery` dokümantasyonu.
/// `createIdentity` ile AYNI kalıp: başarılıysa `identity_id` döner ve
/// üretilen secret bundle'ı `pending_secret_bundle`'a koyar — Kotlin tarafı
/// (bkz. `IdentityManager.persistNewIdentity`) bunu HEMEN `getPendingSecretBundle`
/// ile çekip Keystore'la şifreleyip diske yazmalı, TIPKI yeni kimlik
/// oluşturmadaki gibi.
#[no_mangle]
pub extern "system" fn Java_com_p2p_messenger_P2PLib_importRecovery<'local>(
    mut env: JNIEnv<'local>, _class: JClass<'local>,
    file_bytes: JByteArray<'local>, passphrase: JString<'local>, device_name: JString<'local>,
) -> jstring {
    let raw = jbytearray_to_vec(&mut env, &file_bytes);
    let pass_str = zeroize::Zeroizing::new(jstr(&mut env, &passphrase).unwrap_or_default());
    let name: String = jstr(&mut env, &device_name).unwrap_or_else(|| "Device".to_string());
    let result = catch_panic(move || {
        // Argon2 runs without the core lock (M-21).
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

// --- JNI yardımcıları ---

/// Rust'ın varsayılan davranışı: bir panic, `extern "system"` (JNI) gibi bir
/// FFI sınırından unwind ederek geçmeye çalışırsa, bunu güvenle
/// yapamayacağı için process'i SESSİZCE `abort()` eder — tüm uygulama
/// çöker (bkz. processQrPacket çökmesi: dial()/gossipsub publish() zincirinde
/// "there is no reactor running" panic'i oluştu ve tüm süreç düştü). Her JNI
/// export'u, çağırdığı `P2PCore` metodunu bu fonksiyonla sarmalar: panic
/// olursa (yukarıdaki `set_hook` sayesinde tam mesajı zaten logcat'e
/// yazılmış olur) process düşmez, `Err(...)` olarak geri döner.
///
/// ÖNEMLİ: `f` kapanışı KESİNLİKLE `env: JNIEnv` yakalamamalı/kullanmamalı.
/// İlk denemede bunu ihlal etmiştik: panic durumunda `env.new_string(...)`
/// hiç çalışmadığından `jstring` olarak `std::ptr::null_mut()` dönüyorduk —
/// bu da Kotlin tarafında `external fun ...: String` (non-null) sözleşmesini
/// bozup ayrı bir `NullPointerException` çökmesine yol açtı (bkz. o oturumun
/// geçmişi). Doğru desen: `catch_panic` SADECE saf Rust mantığını
/// (CORE.lock() + core metodu) çalıştırır; sonucu `env`'e çeviren
/// `new_string`/`bytes_to_jbytearray` çağrıları HER ZAMAN bu fonksiyonun
/// DIŞINDA, panic'ten etkilenmeyen çağıran kodda yapılır — böylece panic
/// olsun olmasın her zaman geçerli bir (non-null) JNI değeri döner.
pub(crate) fn catch_panic<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    // M-176: every export runs inside the runtime context, not only the ones
    // that remembered `RUNTIME.enter()`.
    // Inside `catch_unwind`: a failing lazy runtime init must not unwind into JNI.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _rt = RUNTIME.enter();
        f()
    }))
    .map_err(|payload| {
        CORE_PANICKED.store(true, std::sync::atomic::Ordering::SeqCst);
        // Panic mesajının TAMAMI `set_hook` ile zaten logcat'e yazıldı;
        // burada çağıran tarafa dönecek kısa bir özet üretiyoruz.
        if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "internal panic (bkz. logcat 'PANIC yakalandı')".to_string()
        }
    })
}

/// M112: the stable code of a core error message, for the UI to pick a
/// localized text. First match wins; the order matters (e.g. "zaten" before
/// "kişi bulunamadı"-style lookups). ponytail: keyed on the message text, so a
/// reworded message can move to INTERNAL; `error_code_tests` pins the main ones.
pub(crate) fn error_code(detail: &str) -> &'static str {
    const TABLE: &[(&str, &[&str])] = &[
        ("INTERNAL", &["panic"]),
        ("LOCKED", &["henüz yüklenmedi", "anahtarları yüklenmedi", "not loaded", "initdatabase", "db not open", "veritabanı açık değil", "no identity", "kimlik yok", "önce bir kimlik"]),
        ("NOT_FOUNDER", &["sadece kurucu", "only the founder"]),
        ("ALREADY", &["zaten", "already"]),
        ("BLOCKED", &["engellenmiş", "engelli", "iptal edilmiş", "revoked", "hesabını sildi"]),
        ("TOO_LARGE", &["too large", "too long", "çok büyük", "çok uzun", "sınırından büyük", "sınırını aşıyor", "sınırına ulaşıldı", "en fazla"]),
        ("NO_SESSION", &["no ratchet session", "oturum anahtarı yok", "key exchange", "unknown peer device", "aktif cihazı çözülemedi", "bilinmeyen karşı taraf"]),
        ("INVALID", &["geçersiz", "invalid", "bad ", "boş olamaz", "olmalı", "içermeli", "mismatch", "tutarsız", "unsupported", "desteklenmeyen", "bozuk", "kodunda", "kodundaki", "not an rgba"]),
        ("NOT_ALLOWED", &["only the primary", "edemezsiniz", "ekleyemezsiniz", "engelleyemezsiniz", "edilemez", "çıkaramaz", "ayrılamaz", "değilsiniz"]),
        ("NETWORK", &["tor kapalı", "tor başlatılamadı", "ulaşılamıyor", "ulaşılabilir", "bağlı değil", "ağ henüz", "ağ adresi", "could not be sent", "gönderilemedi", "network"]),
        ("NOT_FOUND", &["bulunamadı", "not found", "unknown", "bilinmeyen", "bilinmiyor", "no pending", "üyesi değil", "yok"]),
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
            ("Sadece kurucu üye çıkarabilir", "NOT_FOUNDER"),
            ("Bu kişi zaten grubun üyesi", "ALREADY"),
            ("Bu kişi engellenmiş", "BLOCKED"),
            ("File too large", "TOO_LARGE"),
            ("Unknown peer device; complete key exchange first", "NO_SESSION"),
            ("Geçersiz kişi kodu", "INVALID"),
            ("Kendi kodunuzu kişi olarak ekleyemezsiniz", "NOT_ALLOWED"),
            ("Tor kapalı: ağ yalnızca Tor üzerinden çalışır", "NETWORK"),
            ("Grup bulunamadı", "NOT_FOUND"),
            ("Unknown file_id", "NOT_FOUND"),
            ("Şifreleme anahtarı henüz yüklenmedi", "LOCKED"),
            ("panic: boom", "INTERNAL"),
            ("Grup sürümü tükendi", "INTERNAL"),
        ] {
            assert_eq!(error_code(msg), code, "{msg}");
        }
        assert_eq!(coded_error("Grup bulunamadı"), "Error: NOT_FOUND: Grup bulunamadı");
    }
}

/// Spec dışı, güvenlik/kararlılık denetimi düzeltmesi: bu yardımcılar
/// (`bytes_to_jbytearray`/`strings_to_jobjectarray`/`safe_new_jstring`)
/// önceden JNIEnv çağrılarının dönüşünü doğrudan `.unwrap()` ile açıyordu.
/// `catch_panic` YALNIZCA saf Rust mantığını (yukarıdaki dokümantasyon)
/// korur — bu dönüşüm çağrıları HER ZAMAN onun DIŞINDA, sarmalanmamış
/// çalışır. Normalde bu JNIEnv çağrıları başarısız olmaz, ama JVM'in gerçek
/// bir OutOfMemoryError durumunda (ör. büyük bir mesaj geçmişi senkronu ya
/// da `export_recovery` çıktısını döndürürken, düşük bellekli bir cihazda)
/// başarısız olabilir — bu durumda eski kod `panic!` atardı ve bu panic,
/// `extern "system"` (JNI) sınırını unwind ederek geçmeye çalışır; bu
/// tanımsız davranıştır ve pratikte SÜRECİ SESSİZCE ÇÖKERTİR (native
/// SIGABRT, Kotlin tarafında YAKALANAMAZ) — tam olarak `catch_panic`'in
/// önlemeye çalıştığı sonuç, sadece bir çağrı çerçevesi sonra.
///
/// Şimdi bunun yerine hata loglanıp `std::ptr::null_mut()` dönülüyor.
/// NOT (bilinçli, kabul edilmiş ödünleşim): `catch_panic` dokümantasyonu
/// (yukarıda) null dönmenin Kotlin'in `external fun ...: String` (null
/// OLAMAZ) sözleşmesini bozup ayrı bir `NullPointerException`'a yol
/// açtığını anlatıyor — ama o notun ele aldığı senaryo NORMAL panic
/// (ör. bir core mantığı hatası) içindi, ki `catch_panic` zaten onu YAKALAR
/// ve hiçbir zaman bu yardımcılara panik durumunda ulaşılmaz. Burada ele
/// alınan senaryo tamamen farklı ve çok daha nadir: JNIEnv'in KENDİSİ
/// (yani Kotlin/JVM tarafı) belleği tükettiği için başarısız olması — bu
/// noktada zaten JVM sağlıksız bir durumda, uygulama muhtemelen bir şekilde
/// çökecek. Seçenek, tanımsız davranışla SESSİZ bir native abort (hiçbir
/// zaman crash raporuna düşmeyebilir) ile Kotlin tarafında normal, yakalanabilir
/// bir `NullPointerException` (gerçek bir stack trace + crash raporu üretir)
/// arasında — ikincisi kesin olarak daha iyi bir başarısızlık modu.
/// Rows per history call from a frontend: the load, the decrypt and the JSON
/// all run under the core lock.
pub(crate) const MAX_HISTORY_PAGE: jni::sys::jint = 500;
pub(crate) const MAX_LISTED_ATTACHMENTS: usize = 500;
/// H3: the text (history) or preview (attachment list) bytes of one page.
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
        Ok(it) => it.filter_map(|r| r.map_err(|e| warn!("Ek satırı okunamadı: {}", e)).ok()).collect(),
        Err(e) => {
            warn!("Ek listesi sorgusu başarısız: {}", e);
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
            log::error!("JNI byte_array_from_slice başarısız (JVM bellek baskısı olabilir): {e}");
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
            log::error!("JNI convert_byte_array başarısız, boş dönülüyor: {e}");
            let _ = env.exception_clear();
            Vec::new()
        }
    }
}

/// Spec dışı, kullanıcı isteği (WhatsApp tarzı "yanıtla" — opsiyonel
/// `replyToMessageId`/`replyToPreview` parametreleri): Kotlin tarafından
/// `null` geçirilen bir `JString`'i `Option<String>`'e çevirir — bkz.
/// `prepareAndSendFile`'daki `JByteArray.is_null()` AYNI deseni, `JString`
/// için.
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
                log::error!("JNI get_string başarısız: {e}");
            }
            let _ = env.exception_clear();
            None
        }
    }
}

/// bkz. `bytes_to_jbytearray` dokümantasyonu — aynı gerekçe/ödünleşim.
pub(crate) fn safe_new_jstring<'local>(env: &mut JNIEnv<'local>, s: impl AsRef<str>) -> jstring {
    match env.new_string(s.as_ref()) {
        Ok(js) => js.into_raw(),
        Err(e) => {
            log::error!("JNI new_string başarısız (JVM bellek baskısı olabilir): {e}");
            std::ptr::null_mut()
        }
    }
}

pub(crate) fn strings_to_jobjectarray<'local>(env: &mut JNIEnv<'local>, texts: &[String]) -> jobjectArray {
    let string_class = match env.find_class("java/lang/String") {
        Ok(c) => c,
        Err(e) => {
            log::error!("JNI find_class(java/lang/String) başarısız: {e}");
            return std::ptr::null_mut();
        }
    };
    let empty = match env.new_string("") {
        Ok(s) => s,
        Err(e) => {
            log::error!("JNI new_string(\"\") başarısız: {e}");
            return std::ptr::null_mut();
        }
    };
    let arr = match env.new_object_array(texts.len() as i32, string_class, empty) {
        Ok(a) => a,
        Err(e) => {
            log::error!("JNI new_object_array başarısız: {e}");
            return std::ptr::null_mut();
        }
    };
    for (i, text) in texts.iter().enumerate() {
        // One bad element keeps its "" default: returning null here threw
        // away every event of the poll turn, which are already drained.
        let jstr = match env.new_string(text) {
            Ok(s) => s,
            Err(e) => {
                log::error!("JNI new_string başarısız (dizin {i}): {e}");
                let _ = env.exception_clear();
                continue;
            }
        };
        if let Err(e) = env.set_object_array_element(&arr, i as i32, &jstr) {
            log::error!("JNI set_object_array_element başarısız (dizin {i}): {e}");
            let _ = env.exception_clear();
        }
        // A burst of events must not fill the local reference table.
        let _ = env.delete_local_ref(jstr);
    }
    arr.into_raw()
}

// =====================================================================
// BİLİNEN EKSİKLER / KAPSAM DIŞI (dürüstçe işaretlenmiştir):
//
// NOT: Bu blok, kod geliştikçe güncel tutulmalı. Aşağıdaki maddeler ŞU AN
// hâlâ geçerli olan gerçek sınırlardır — daha önce burada listelenip
// sonradan ÇÖZÜLEN maddeler (GroupUpdate hibrit imzası, rotasyon senkronu,
// skipped-key cache, IdentityExchange'in TOFU akışına girmesi) yanıltıcı
// olmasın diye SİLİNDİ; çözümleri ilgili fonksiyonların/SECURITY.md'nin
// dokümantasyonunda.
//
// 1. (ÇÖZÜLDÜ) Aşama B çoklu-cihaz akışı artık VAR: cihaz ekleme/iptali
//    ağ üzerinden `MessageContent::DeviceAddNotice`/`DeviceRevokeNotice` ile
//    (ratchet-şifreli kanaldan, Ack'lenip yeniden denenerek) yayılır — bkz.
//    `adopt_device_link`/`apply_device_add_notice`/`apply_device_revoke_notice`.
//    Bu maddenin eski hâli, o zaman gerçekten ölü olan (hiç üretilmeyen)
//    `NetworkEnvelope::DeviceAdd`/`DeviceRevoke`/`GroupInvite`/`ReadReceipt`
//    varyantlarını tanımlıyordu — o varyantlar tamamen kaldırıldı (bkz.
//    packet.rs `NetworkEnvelope` notu), gerçek mekanizma zaten farklıydı.
// 2. (ÇÖZÜLDÜ) Artık bir Linux masaüstü istemcisi VAR — bkz. depo kökündeki
//    `Linux/` (GTK4, bu çekirdeği `api` modülü üzerinden rlib olarak
//    doğrudan linkler; protokolün ikinci bir implementasyonu YOK). Node
//    modu orada da çalışır. TEK sınır: o istemci yalnızca İKİNCİL cihaz
//    olabilir (spec 1.5 bağlama akışı) — kendi başına yeni bir kimlik
//    oluşturmaz.
// 3. (ÇÖZÜLDÜ) Her güncelleme tam üye listesini taşır; sürüm boşluğunda
//    ya da cihazı bilinmeyen bir üyede üye kurucudan tam durumu ister
//    (`GroupSyncRequest`), kurucu da tümünü yeniden gönderebilir
//    (`resend_group_to_all`).
// =====================================================================

#[cfg(test)]
mod pbkdf2_tests {
    /// RFC 7914 §11 PBKDF2-HMAC-SHA256 test vector — `pbkdf2Sha256` JNI'sinin kullandığı çağrı.
    #[test]
    fn pbkdf2_sha256_matches_rfc7914() {
        let mut out = [0u8; 64];
        ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, std::num::NonZeroU32::new(1).unwrap(), b"salt", b"passwd", &mut out);
        assert_eq!(hex::encode(&out[..8]), "55ac046e56e3089f");
    }
}
