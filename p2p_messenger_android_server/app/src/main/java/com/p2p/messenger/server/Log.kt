package com.p2p.messenger.server

import com.p2p.messenger.server.BuildConfig

/** Logcat only in debug builds: a release writes nothing (peer ids, onion addresses, errors). */
object Log {
    fun v(tag: String, msg: String, tr: Throwable? = null) = if (BuildConfig.DEBUG) android.util.Log.v(tag, msg, tr) else 0
    fun d(tag: String, msg: String, tr: Throwable? = null) = if (BuildConfig.DEBUG) android.util.Log.d(tag, msg, tr) else 0
    fun i(tag: String, msg: String, tr: Throwable? = null) = if (BuildConfig.DEBUG) android.util.Log.i(tag, msg, tr) else 0
    fun w(tag: String, msg: String, tr: Throwable? = null) = if (BuildConfig.DEBUG) android.util.Log.w(tag, msg, tr) else 0
    fun e(tag: String, msg: String, tr: Throwable? = null) = if (BuildConfig.DEBUG) android.util.Log.e(tag, msg, tr) else 0
}
