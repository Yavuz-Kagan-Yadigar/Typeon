package com.p2p.messenger.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * An ABSOLUTE timestamp, for example "14:05, 3 Nov". It is not relative (the chat LIST rows in ChatAdapter show "5m ago" instead). This is the ONE shared
 * format used both under EVERY message bubble (see SimpleChatAdapter) and in the "last try"
 * column of the pending-messages list in Settings (see PendingMessagesAdapter). Both must look the same.
 */
fun formatAbsoluteTime(timestampMs: Long): String {
    if (timestampMs <= 0) return ""
    return SimpleDateFormat("HH:mm, d MMM", Locale.getDefault()).format(Date(timestampMs))
}
