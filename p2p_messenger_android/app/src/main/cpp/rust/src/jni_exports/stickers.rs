//! JNI: JXL encoding, stickers and bitmap helpers.

use super::*;

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
    // raw pointer code, inside the panic guard too.
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

/// an animated image as a lossless animated JPEG XL. `frames`: one
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

/// an animated JPEG XL as an animated GIF (see `attachments::jxl_to_gif`).
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

/// The pixels of an `ARGB_8888` `android.graphics.Bitmap` (RGBA bytes in memory), copied row by row, skipping the stride. ponytail: one native copy
/// of the image; lock the pixels across the encode if memory gets tight.
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
        // fallible; up to 96 MB, and a failed `with_capacity` aborts
        // the process (no unwind for `catch_panic` to catch).
        let mut rgba = Vec::new();
        if rgba.try_reserve_exact(w * h * 4).is_err() {
            return None;
        }
        let mut addr = std::ptr::null_mut();
        if AndroidBitmap_lockPixels(raw_env, raw_bitmap, &mut addr) != 0 || addr.is_null() {
            return None;
        }
        // unlocked on every exit, a panic included.
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
