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

/** What a bare `toInt(16)` parse does NOT do: invalid input yields null
 *  instead of a `NumberFormatException` (which killed an executor thread on
 *  its way up, bkz. WhiteboardPanel) — and unlike the `Character.digit`
 *  pair above, a lone non-hex char does not come out as silent garbage. */
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
