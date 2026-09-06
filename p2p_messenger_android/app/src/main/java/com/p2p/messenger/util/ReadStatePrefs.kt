package com.p2p.messenger.util

import android.content.Context

/**
 * Per-conversation "last read" timestamp, used to flag chat list rows as
 * unread. `conversationId` is the peer device fingerprint for 1:1 chats,
 * or `"group:$groupId"` for groups — same convention as
 * `P2PService.activeConversationId`.
 *
 * There's no real per-message unread count (no such signal exists locally
 * or in Rust); this only answers "is there any activity since I last left
 * this conversation" via `markRead`/`lastReadAt`, called from
 * ChatActivity/GroupChatActivity.onPause and ChatsFragment.refreshList.
 */
object ReadStatePrefs {
    private const val PREFS_NAME = "chat_read_state"

    fun markRead(context: Context, conversationId: String) {
        if (conversationId.isEmpty()) return
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putLong(conversationId, System.currentTimeMillis())
            .apply()
    }

    /**
     * Çoklu-cihaz (spec 1.7.1): bir kardeş cihazdan gelen "okundu"
     * senkronunu uygular — `timestamp`, mevcut değerden yeniyse ileri
     * taşınır (asla geri gitmez). bkz. P2PService "read_state_sync" olayı.
     */
    fun markReadAt(context: Context, conversationId: String, timestamp: Long) {
        if (conversationId.isEmpty()) return
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (timestamp > prefs.getLong(conversationId, 0L)) {
            prefs.edit().putLong(conversationId, timestamp).apply()
        }
    }

    fun lastReadAt(context: Context, conversationId: String): Long {
        if (conversationId.isEmpty()) return 0L
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getLong(conversationId, 0L)
    }
}
