package com.p2p.messenger.util

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import androidx.core.content.IntentCompat

/**
 * Android paylaşım ekranından ("Typeon'a paylaş") gelen ACTION_SEND /
 * ACTION_SEND_MULTIPLE içeriği. MainActivity bekletir; kullanıcı sohbet
 * listesinden bir sohbet seçince hedef sohbet ekranının Intent'ine eklenir
 * ve orada tüketilir (metin → yazı kutusu, dosyalar → ek olarak gönderim).
 */
object ShareIntake {
    const val EXTRA_SHARE = "typeon_share"

    @Volatile
    var pending: Intent? = null

    fun isShare(intent: Intent?): Boolean =
        intent?.action == Intent.ACTION_SEND || intent?.action == Intent.ACTION_SEND_MULTIPLE

    /** Bekleyen paylaşımı (varsa) `target`a ekler ve bekleyeni temizler. */
    fun attachTo(target: Intent): Intent {
        val share = pending ?: return target
        pending = null
        target.putExtra(EXTRA_SHARE, share)
        val uris = uris(share)
        if (uris.isNotEmpty()) {
            // Okuma izni MainActivity'de; sohbet ekranına devredilmesi için.
            target.clipData = ClipData.newRawUri("share", uris[0]).also { c -> uris.drop(1).forEach { c.addItem(ClipData.Item(it)) } }
            target.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return target
    }

    /** Hedef Intent'teki paylaşımı bir kez alır. */
    fun take(target: Intent): Intent? {
        val share = IntentCompat.getParcelableExtra(target, EXTRA_SHARE, Intent::class.java) ?: return null
        target.removeExtra(EXTRA_SHARE)
        return share
    }

    fun text(share: Intent): String? = share.getStringExtra(Intent.EXTRA_TEXT)?.takeIf { it.isNotBlank() }

    fun uris(share: Intent): List<Uri> =
        if (share.action == Intent.ACTION_SEND_MULTIPLE) {
            IntentCompat.getParcelableArrayListExtra(share, Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
        } else {
            listOfNotNull(IntentCompat.getParcelableExtra(share, Intent.EXTRA_STREAM, Uri::class.java))
        }
}
