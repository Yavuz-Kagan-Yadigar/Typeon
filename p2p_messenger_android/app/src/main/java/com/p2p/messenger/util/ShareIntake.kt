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

    /** A share nobody picked a chat for must not ride along with a chat
     *  opened much later. */
    private const val PENDING_TTL_MS = 5 * 60_000L
    private var pendingAt = 0L

    @Volatile
    var pending: Intent? = null
        set(value) {
            field = value
            pendingAt = android.os.SystemClock.elapsedRealtime()
            // Cleared together: one "left without picking a chat" rule.
            if (value == null) forward = null
        }

    /** A message being forwarded (see [Forward]). Kept here, not in an
     *  Intent: a share from another app must not be able to name a file. */
    @Volatile
    var forward: Forward.Pending? = null
        set(value) {
            field = value
            if (value != null) pendingAt = android.os.SystemClock.elapsedRealtime()
        }

    /** The forward handed to the chat screen picked last. */
    private var armed: Forward.Pending? = null
    private const val EXTRA_FORWARD = "typeon_forward"

    fun isShare(intent: Intent?): Boolean =
        intent?.action == Intent.ACTION_SEND || intent?.action == Intent.ACTION_SEND_MULTIPLE

    /** Bekleyen paylaşımı (varsa) `target`a ekler ve bekleyeni temizler. */
    fun attachTo(target: Intent): Intent {
        forward?.let { f ->
            val expired = android.os.SystemClock.elapsedRealtime() - pendingAt > PENDING_TTL_MS
            forward = null
            if (!expired) {
                armed = f
                target.putExtra(EXTRA_FORWARD, true)
            }
            return target
        }
        val share = pending ?: return target
        val expired = android.os.SystemClock.elapsedRealtime() - pendingAt > PENDING_TTL_MS
        pending = null
        if (expired) return target
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

    /** The forward [attachTo] put on `target`, once. */
    fun takeForward(target: Intent): Forward.Pending? {
        if (!target.getBooleanExtra(EXTRA_FORWARD, false)) return null
        target.removeExtra(EXTRA_FORWARD)
        return armed.also { armed = null }
    }

    fun text(share: Intent): String? =
        share.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()?.takeIf { it.isNotBlank() }

    /** The share target is exported: the URIs come from another app and are
     *  opened with OUR identity. Only `content:` from a foreign provider is
     *  accepted, otherwise `file:///data/data/<us>/...` or our own
     *  FileProvider would send the database or the key files to a chat. */
    fun uris(share: Intent): List<Uri> {
        val raw: List<Uri?> = if (share.action == Intent.ACTION_SEND_MULTIPLE) {
            IntentCompat.getParcelableArrayListExtra(share, Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
        } else {
            listOf(IntentCompat.getParcelableExtra(share, Intent.EXTRA_STREAM, Uri::class.java))
        }
        return raw.filterNotNull().filter {
            it.scheme == "content" && it.authority?.substringAfter('@')?.startsWith(OWN_PACKAGE) != true
        }
    }

    private const val OWN_PACKAGE = "com.p2p.messenger"
}
