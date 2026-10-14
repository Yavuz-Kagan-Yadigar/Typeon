package com.p2p.messenger.util

/**
 * Two contacts may carry the same display name. Where that happens, the name
 * is shown with the head of the identity id, so the user can tell them apart.
 * Display only: nothing is stored.
 */
object ContactNames {
    private fun key(name: String) = name.trim().lowercase()

    /** The names (as compare keys) that more than one contact carries. */
    fun duplicates(names: List<String>): Set<String> =
        names.groupingBy { key(it) }.eachCount().filterValues { it > 1 }.keys

    fun label(name: String, identityId: String, duplicates: Set<String>): String =
        if (identityId.isNotEmpty() && key(name) in duplicates) "$name (${identityId.take(6)})" else name
}
