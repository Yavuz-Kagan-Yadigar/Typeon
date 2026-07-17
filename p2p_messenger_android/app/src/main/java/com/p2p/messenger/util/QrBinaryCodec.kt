package com.p2p.messenger.util

import java.nio.charset.StandardCharsets

/**
 * QR kodları (spec 1.3) CBOR ile kodlanmış ham baytlar taşır — düz metin
 * değil. ZXing'in encoder/decoder API'leri String tabanlıdır; ham baytları
 * kayıpsız taşımak için ISO-8859-1 (Latin-1) kullanıyoruz: bu kodlamada her
 * bayt (0-255) tam olarak bir karaktere eşlenir, bu yüzden
 * bytesToLatin1String(bytes).let { latin1StringToBytes(it) } == bytes
 * garantisi vardır. QR üretirken (ContactsFragment "Kodumu Göster") ve QR
 * okurken (QrScanActivity) aynı kodlama kullanılmalıdır.
 */
object QrBinaryCodec {
    fun bytesToLatin1String(bytes: ByteArray): String =
        String(bytes, StandardCharsets.ISO_8859_1)

    fun latin1StringToBytes(text: String): ByteArray =
        text.toByteArray(StandardCharsets.ISO_8859_1)
}
