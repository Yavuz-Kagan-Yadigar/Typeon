package com.p2p.messenger.util

/**
 * A one-shot in-memory box that carries JPEG bytes between `CameraCaptureActivity` and the chat screen that launched it. The photo is never written to disk.
 *
 * Why not an Intent extra: the Binder transaction buffer has a total limit of about 1 MB (`TransactionTooLargeException`). A photo of a few hundred KB would not
 * exceed it alone, but running that close to the limit would be fragile. Why not a temporary FILE: the point is that the photo must not reach the disk. This
 * object only passes between two activities in the same process, so neither needs a file.
 *
 * `take()` clears the value it reads at the same time. That makes sending the same photo twice (for example after a screen rotation redelivers
 * `onActivityResult`) structurally impossible, and it does not keep the bytes in memory any longer than needed.
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
