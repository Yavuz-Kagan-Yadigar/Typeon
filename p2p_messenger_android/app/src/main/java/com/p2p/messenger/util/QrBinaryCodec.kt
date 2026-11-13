package com.p2p.messenger.util

import java.nio.charset.StandardCharsets

/**
 * QR codes carry raw CBOR-encoded bytes, not plain text. ZXing's encoder and decoder APIs are String based. To carry raw bytes losslessly, ISO-8859-1 (Latin-1)
 * is used: in this encoding every byte (0-255) maps to exactly one character. So `bytesToLatin1String(bytes).let { latin1StringToBytes(it) } == bytes` always
 * holds. The same encoding must be used when generating a QR (ContactsFragment "Show my code") and when reading one (QrScanActivity).
 */
object QrBinaryCodec {
    fun bytesToLatin1String(bytes: ByteArray): String =
        String(bytes, StandardCharsets.ISO_8859_1)

    fun latin1StringToBytes(text: String): ByteArray =
        text.toByteArray(StandardCharsets.ISO_8859_1)
}
