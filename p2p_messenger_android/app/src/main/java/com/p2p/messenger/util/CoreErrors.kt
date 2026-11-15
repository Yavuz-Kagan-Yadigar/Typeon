package com.p2p.messenger.util

import android.content.Context
import com.p2p.messenger.R

/** "Error: CODE: detail" from the core -> a localized text. The core's detail is English and goes to the log only:
 *  the screen shows the selected language alone, so an error without a known code gets the generic text. */
fun coreErrorText(ctx: Context, raw: String): String {
    val body = raw.removePrefix("Error:").trim()
    val code = body.substringBefore(':', "").trim()
    val id = when (code) {
        "LOCKED" -> R.string.err_core_locked
        "NOT_FOUNDER" -> R.string.err_core_not_founder
        "ALREADY" -> R.string.err_core_already
        "BLOCKED" -> R.string.err_core_blocked
        "TOO_LARGE" -> R.string.err_core_too_large
        "NO_SESSION" -> R.string.err_core_no_session
        "INVALID" -> R.string.err_core_invalid
        "NOT_ALLOWED" -> R.string.err_core_not_allowed
        "NETWORK" -> R.string.error_network
        "NOT_FOUND" -> R.string.err_core_not_found
        "INTERNAL" -> R.string.err_core_internal
        else -> {
            Log.w("CoreError", body)
            R.string.err_core_internal
        }
    }
    return ctx.getString(id)
}
