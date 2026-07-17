package com.p2p.messenger.util

/** Rust `hex::encode` ile kodlanmış alanları geri çözer (bkz. "preview_hex"/
 *  "avatar_hex" — JSON ham ikili veri taşıyamadığı için bu kodlama gerekti). */
fun hexToBytes(hex: String): ByteArray {
    val result = ByteArray(hex.length / 2)
    for (i in result.indices) {
        val idx = i * 2
        result[i] = ((Character.digit(hex[idx], 16) shl 4) + Character.digit(hex[idx + 1], 16)).toByte()
    }
    return result
}
