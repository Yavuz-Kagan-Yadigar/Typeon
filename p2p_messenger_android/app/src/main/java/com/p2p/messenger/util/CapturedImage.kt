package com.p2p.messenger.util

/**
 * Spec dışı, kullanıcı isteği ("anlık çekim ... diske kaydedilmeden"):
 * `CameraCaptureActivity` ile onu başlatan sohbet ekranı arasında JPEG
 * baytlarını taşıyan tek seferlik bellek içi kutu.
 *
 * Neden Intent extra DEĞİL: Binder işlem tamponu ~1 MB'lık toplam bir
 * sınıra tabidir (`TransactionTooLargeException`) — birkaç yüz KB'lık bir
 * fotoğraf bunu tek başına aşmasa bile sınırın hemen dibinde çalışmak
 * kırılgan olurdu. Neden geçici DOSYA değil: kullanıcı isteği tam olarak
 * fotoğrafın diske düşmemesi. Bu nesne yalnızca aynı süreç içindeki iki
 * Activity arasında el değiştirdiği için ikisine de gerek yok.
 *
 * `take()` okuduğu değeri AYNI ANDA temizler: aynı fotoğrafın (ör. ekran
 * döndürme sonrası yeniden `onActivityResult`) iki kez gönderilmesini
 * yapısal olarak imkânsız kılar ve baytları bellekte gereksiz yere asılı
 * bırakmaz.
 */
object CapturedImage {
    @Volatile
    private var jpeg: ByteArray? = null

    fun put(bytes: ByteArray) {
        jpeg = bytes
    }

    fun take(): ByteArray? {
        val bytes = jpeg
        jpeg = null
        return bytes
    }
}
