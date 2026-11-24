package com.p2p.messenger.server

/**
 * The JNI surface of the `typeon-server` Rust core.
 *
 * The same pattern as the client's `P2PLib`: everything crosses as JSON strings, and errors come back with an `"Error: ..."` prefix. This is a separate
 * library (`libtypeon_server.so`). It shares the same protocol types as the client's `libp2p_messenger.so`, but it is a separate crate.
 */
/** The native side answers in English. Show it in the user's language. */
fun serverErrorText(ctx: android.content.Context, raw: String): String {
    val id = when {
        raw.startsWith("Error: internal error") -> R.string.err_internal
        raw.startsWith("Error: previous server still") -> R.string.err_server_closing
        raw.startsWith("Error: server loop did not stop") -> R.string.err_server_loop_stuck
        raw == "Error: server not running" -> R.string.err_server_not_running
        raw.startsWith("Error: server has no reachable address") -> R.string.err_no_address
        raw == "Error: invalid id" -> R.string.err_invalid_id
        raw == "Error: record not found" -> R.string.err_record_not_found
        else -> return raw
    }
    return ctx.getString(id)
}

object ServerLib {
    init {
        System.loadLibrary("typeon_server")
        if (BuildConfig.DEBUG) enableLogging()
    }

    /** Logcat output of the core and arti; never called in a release. */
    private external fun enableLogging()

    /**
     * Starts the server and returns its `peer_id`. A no-op if it is already running, so the foreground service can be restarted with `START_STICKY`.
     *
     * NO Tor parameter. The onion service is always on in this app. It is the only way for a phone behind an operator's NAT to be reachable. Making it optional
     * would be a trap that silently makes the server unreachable.
     */
    external fun startServer(
        dataDir: String,
        nodeMode: Boolean,
        name: String,
        /**
         * The TOTAL disk budget, in bytes, that the server may use.
         *
         * The Rust side's default quotas were written for a VPS: 256 MB of mail per enrolment, plus 1 GB of archive, plus 4 GB of blobs. With five devices that
         * comes to 26 GB. It really happened: during a test, the tablet's 22 GB disk filled up, the server had accumulated 751 MB, and a new install was refused with
         * `INSTALL_FAILED_INSUFFICIENT_STORAGE`. On a phone, the quotas must be derived from the device's REAL free space.
         */
        storageBudgetBytes: Long,
        /** Blob directory. The identity and Tor state always stay in internal storage. */
        blobDir: String
    ): String

    /** SQLCipher raw key (32 bytes) for the server DB. Call before [startServer]. Returns "ok" or "Error: ...". */
    external fun setDbKey(key: ByteArray): String

    /**
     * Really STOPS the server.
     *
     * This did not exist before. `stopService(...)` only released the wake lock and removed the foreground notification. The Rust core kept running in the process.
     * It went on accepting mail, serving blobs and using battery. Also, because `startServer` is a no-op while a core is already running, changes to node mode,
     * blob directory or disk budget were not applied without killing the process. After a stop, `startServer` does a clean setup.
     */
    external fun stopServer(): String

    /** `{running, peer_id, tor, addresses, devices, deposits, fetches, ...}` */
    external fun serverStatus(): String

    /**
     * The server's join code (`typeon-server:<multiaddr>#<token>`). UNLIMITED people join with the same code for 3 days; after that the server makes a new one.
     *
     * The user asked for one QR or link that many people can use, with no interaction with the server needed. The earlier "make a new invite" button did not do
     * that. Each tap made a NEW, single-use code. And because the token is stored hashed, the same code could never be shown again. So the operator had to come
     * to this screen for every new person. (Numbered and time-limited invites live in the headless daemon, through `typeon-server invite new`.)
     *
     * `rotate = true`: the old code becomes invalid AT ONCE, and a new one is returned. Registered devices are not affected (enrolment does not depend on the token).
     *
     * If the server has no address yet, an error is returned. With Tor on, the onion address waits for arti's bootstrap (30 to 60 seconds on the first start).
     */
    external fun joinCode(rotate: Boolean): String

    /** `[{enrollment_id, peer_id, revoked, blocked, bytes_mail, bytes_archive, bytes_blob}]` */
    external fun listDevices(): String

    external fun revokeDevice(enrollmentId: String): String

    /**
     * BLOCKS the enrolment.
     *
     * `revokeDevice` also blocks the enrolment key and rotates the public join code, so both calls end in the same state. This one is the explicit form.
     */
    external fun blockDevice(enrollmentId: String): String

    /** Lifts the block. The device can enrol again with a fresh invite. */
    external fun unblockDevice(enrollmentId: String): String

    /** Total size of the data directory, in bytes, as a string. */
    external fun diskUsage(): String

    /**
     * Called when the network interface changes (Wi-Fi drops and comes back, or a switch to mobile data). See the `ConnectivityManager` callback in `ServerService`.
     * The core re-triggers the Tor bootstrap (idempotently) and refreshes the libp2p listener. So after a Wi-Fi interruption, republishing the onion descriptor
     * does not wait for the periodic recovery (minutes). It is a no-op if the core is not running.
     */
    external fun notifyNetworkChanged()

    /** Self-update check (update.rs). Blocking, network. Verified APK path, "" if nothing to do, or "Error: ...". */
    external fun checkUpdate(dir: String, current: String, force: Boolean): String
}
