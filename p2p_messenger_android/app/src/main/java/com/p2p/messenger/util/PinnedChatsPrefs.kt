package com.p2p.messenger.util

import android.content.Context

/**
 * Pinned conversation ids for the chat list — pinned chats always sort
 * above unpinned ones (see ChatsFragment.refreshList). `conversationId` is
 * the peer device fingerprint for 1:1 chats, or `"group:$groupId"` for
 * groups — same convention as ReadStatePrefs/P2PService.activeConversationId.
 * Multiple chats can be pinned at once (it's a set, not a single slot).
 */
object PinnedChatsPrefs {
    private const val PREFS_NAME = "pinned_chats"
    private const val KEY_PINNED_IDS = "pinned_ids"

    fun isPinned(context: Context, conversationId: String): Boolean {
        if (conversationId.isEmpty()) return false
        return prefs(context).getStringSet(KEY_PINNED_IDS, emptySet())?.contains(conversationId) == true
    }

    fun setPinned(context: Context, conversationId: String, pinned: Boolean) {
        if (conversationId.isEmpty()) return
        val current = prefs(context).getStringSet(KEY_PINNED_IDS, emptySet())?.toMutableSet() ?: mutableSetOf()
        if (pinned) current.add(conversationId) else current.remove(conversationId)
        // A defensive copy — SharedPreferences.Editor.putStringSet must not
        // be given the same mutable set instance returned by a previous get().
        prefs(context).edit().putStringSet(KEY_PINNED_IDS, HashSet(current)).apply()
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
}
