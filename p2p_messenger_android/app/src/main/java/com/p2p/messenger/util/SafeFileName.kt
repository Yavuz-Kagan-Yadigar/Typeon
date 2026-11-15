package com.p2p.messenger.util

/** A peer-supplied file name made safe for the Downloads folder (1:1 and group chats share it): no path
 *  separators, control or bidi/zero-width characters, no leading dots, at most 200 UTF-8 bytes with the
 *  extension kept and no surrogate pair split. */
fun safeSaveFileName(name: String): String {
    val cleaned = name
        .filter {
            it != '/' && it != '\\' && it != ':' && !it.isISOControl() &&
                // Bidi overrides and zero-width characters disguise the extension.
                Character.getType(it) != Character.FORMAT.toInt()
        }
        .trim()
        .trimStart('.')
        .trim()
    val base = cleaned.ifEmpty { "file" }
    // Cap by UTF-8 bytes (200) at a char boundary; keep the extension.
    if (base.toByteArray().size <= 200) return base
    val dot = base.lastIndexOf('.')
    val ext = if (dot > 0 && base.length - dot <= 16) base.substring(dot) else ""
    var stem = if (ext.isEmpty()) base else base.substring(0, dot)
    while (stem.isNotEmpty() && (stem + ext).toByteArray().size > 200) {
        stem = stem.dropLast(if (stem.length > 1 && Character.isLowSurrogate(stem.last())) 2 else 1)
    }
    return stem.ifEmpty { "file" } + ext
}
