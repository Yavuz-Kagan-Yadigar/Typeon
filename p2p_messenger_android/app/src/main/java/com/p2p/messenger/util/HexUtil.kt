package com.p2p.messenger.util

/** Decodes hex from Rust (`hex::encode`), for fields such as "preview_hex" and "avatar_hex". JSON cannot carry raw binary data.
 *
 *  Malformed input (an odd number of characters, or non-hex characters) returns `ByteArray(0)`. Callers treat an empty array as "no data"
 *  and show a placeholder. */
fun hexToBytes(hex: String): ByteArray = hexToBytesOrNull(hex) ?: ByteArray(0)

/** Like `hexToBytes`, but returns null for invalid input instead of an empty array. */
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
