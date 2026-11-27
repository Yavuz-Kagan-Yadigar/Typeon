package com.p2p.messenger.util

/** A code or address placed inside translated text, kept left to right (LTR isolate): in an RTL
 *  language the digit groups were drawn in reverse order. Display only: never copy, store or compare the result. */
fun ltr(code: String): String = "\u2066$code\u2069"
