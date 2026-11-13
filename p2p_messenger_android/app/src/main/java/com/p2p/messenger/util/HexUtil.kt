package com.p2p.messenger.util

/** Decodes fields that Rust encoded with `hex::encode` (see "preview_hex" and "avatar_hex". Hex was needed because JSON cannot carry raw binary data).
 *
 *  Fails closed: malformed input (an odd number of characters, or non-hex characters) now returns `ByteArray(0)`. The old behaviour, a
 *  StringIndexOutOfBoundsException or silent garbage bytes, is gone. Callers already handle an empty array by falling back to a placeholder (BitmapFactory
 *  returns null, so the avatar or preview falls back). The signatures of about 25 call sites do not need to change. */
fun hexToBytes(hex: String): ByteArray = hexToBytesOrNull(hex) ?: ByteArray(0)

/** What a bare `toInt(16)` parse does NOT do: invalid input yields null instead of a `NumberFormatException`. That exception used to kill an executor thread on
 *  its way up (see WhiteboardPanel). Unlike the `Character.digit` pair above, a lone non-hex character does not come out as silent garbage. */
fun hexToBytesOrNull(hex: String): ByteArray? {
    if (hex.length % 2 != 0) return null
    val result = ByteArray(hex.length / 2)
    for (i in result.indices) {
        val idx = i * 2
        val hi = Character.digit(hex[idx], 16)
        val lo = Character.digit(hex[idx + 1], 16)
        if (hi < 0 || lo < 0) return null
        result[i] = ((hi shl 4) + lo).toByte()
    }
    return result
}
