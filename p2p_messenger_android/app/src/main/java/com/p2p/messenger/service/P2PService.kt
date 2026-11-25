package com.p2p.messenger.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.*
import com.p2p.messenger.util.Log
import androidx.core.app.NotificationCompat
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.util.NotificationHelper
import com.p2p.messenger.util.ReadStatePrefs
import org.json.JSONObject

class P2PService : Service() {

    companion object {
        private const val TAG = "P2PService"
        const val CHANNEL_ID = "P2PServiceChannel"
        const val NOTIFICATION_ID = 1
        const val PREFS_NAME = "p2p_settings"
        const val KEY_NODE_MODE = "node_mode_enabled"
        /** Byte limit for history and attachment storage in node mode (see Rust `history_storage_limit_bytes`). */
        const val KEY_HISTORY_STORAGE_LIMIT = "history_storage_limit_bytes"
        const val DEFAULT_HISTORY_STORAGE_LIMIT_BYTES = 2L * 1024 * 1024 * 1024

        /** See `pollRunnable` and `nextPollDelayMs`.
         *
         *  Screen-on idle polls stay between 2 s and 3 s: the Rust keepalive schedule (`KEEPALIVE_FAST_INTERVAL_MS` = 2 s) runs inside poll turns, so a longer
         *  wait would slow down detection of half-open connections. */
        private const val POLL_INTERVAL_ACTIVE_MS = 1000L
        private const val POLL_IDLE_STEP_MS = 500L
        /** The interval starts widening only after this many consecutive empty background turns (about 5 s), so a short background wake
         *  (for example the screen locking and unlocking straight away) causes no delay. */
        private const val POLL_IDLE_BACKOFF_THRESHOLD = 5

        /* ---------------- Battery design ----------------
         *
         * This is an architectural observation, not a measurement: the libp2p swarm advances only when `pollNetwork()` is called (on the Rust side with `now_or_never`;
         * no background task runs). So the poll interval directly sets the network's response time, and polling blindly would also slow handshakes, Tor circuit
         * setup and mesh maintenance.
         *
         * The interval therefore depends on THREE real signals: whether a screen is listening, whether the device screen is on, and whether the core has real work
         * (`busy` from `P2PLib.ownConnectionStatus`: a connected peer, an unconfirmed packet, a running download, a queued envelope, server work).
         * If none of them holds, the only thing to do is accept an incoming connection, which does not need a wake-up every second.
         *
         * The main gain is in the NUMBER of wake-ups: with the screen off and nothing happening, about 2,900 a day instead of about 86,400.
         */
        /** Screen on, but no chat screen is listening. */
        private const val POLL_INTERVAL_SCREEN_ON_MS = 2000L
        /** Screen off, but the core has work (a connected peer, a pending message, a running download). An incoming message is seen at most this late. */
        private const val POLL_INTERVAL_SCREEN_OFF_MS = 5000L
        /** Screen off AND the core is completely idle: no connected peer, no pending work. The only thing that can happen is an incoming connection. */
        private const val POLL_INTERVAL_DEEP_IDLE_MS = 30000L
        /** How many consecutive empty turns are waited before entering deep-idle mode (about 1 minute), so a momentary silence does not cause a delay. */
        private const val DEEP_IDLE_AFTER_EMPTY_POLLS = 12
        /** In deep idle the wake lock is RELEASED, so the device can sleep. `Handler.postDelayed` (uptime-based) stops while the device sleeps.
         *  This alarm guarantees a periodic wake-up, even under Doze.
         *
         *  The requested maximum is 3 minutes. It is a REQUEST, not a hard limit: `setAndAllowWhileIdle` needs no special permission, but in deep Doze the OS does not
         *  fire these alarms every 3 minutes (in practice about every 9 minutes). To get the 3 minutes, the app must be exempt from battery optimisation, which the app
         *  asks for in Settings (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`). With the exemption, 3 minutes applies exactly; without it, the system stretches it to about 9 minutes.
         *
         *  This is a delay, not message loss: the sender keeps retrying for 7 days, and the server keeps the message for 14 days if one is available. */
        private const val DOZE_WAKE_INTERVAL_MS = 3 * 60 * 1000L
        /** The longest-lived partial wake lock (see `acquireWakeLock`): the device may sleep even if the core stays busy. */
        private const val WAKE_LOCK_MAX_MS = 10 * 60 * 1000L
        /** First wait between network start attempts (see `startNet`). It grows exponentially afterwards, up to `START_NET_RETRY_MAX_MS`. */
        private const val START_NET_RETRY_INITIAL_MS = 30_000L
        private const val START_NET_RETRY_MAX_MS = 10 * 60 * 1000L
        /** Coalescing of network change events (see `notifyNetworkChangedInBackground`). */
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 2000L
        const val ACTION_WAKE_POLL = "com.p2p.messenger.action.WAKE_POLL"

        /** Registered by UI components (for example ChatActivity) that want to be notified as decrypted messages arrive. Kept simple and static rather than a full
         *  pub-sub bus, since this is a single-process app.
         *
         *  `pollRunnable` runs on its own background `HandlerThread` (see that field's docs), but `addMessageListener` and `removeMessageListener` are still called
         *  from the Activities' `onResume` and `onPause`, that is, from the main thread. A plain `mutableListOf` (ArrayList) is NOT safe here: if one thread iterates
         *  with `forEach` while another calls `add` or `remove`, there is a risk of `ConcurrentModificationException` or corrupted internal state. The poll loop runs
         *  every second, so a chat screen opening or closing at that moment is a real timing window. Reads (every poll turn) are far more frequent than writes (only on
         *  screen changes), so `CopyOnWriteArrayList` fits: writes copy the array, and iteration works on the current snapshot without locking. */
        private val listeners = java.util.concurrent.CopyOnWriteArrayList<(String) -> Unit>()

        /** See `nextPollDelayMs`: the poll loop can widen its interval while idle in the background (gradually and up to a limit, not exponentially). If a screen
         *  (`addMessageListener`) opens in the middle of a widened wait, the already queued delayed `postDelayed` call would delay the new screen's quick turn.
         *  While the service instance runs, that queued call is cancelled and a new turn is triggered at once, so the delay resets as soon as a screen opens. */
        @Volatile
        private var wakePollNow: (() -> Unit)? = null

        /** The Doze alarm's turn, run by [DozeWakeReceiver] on the main thread while the service runs. */
        @Volatile
        private var dozeWake: (() -> Unit)? = null

        fun onDozeAlarm() { dozeWake?.invoke() }

        fun addMessageListener(listener: (String) -> Unit) {
            listeners.add(listener)
            // A chat screen opened: leave power-save mode and run a turn at once, so the user does not feel a delay.
            listenerRemoved?.invoke()
            wakePollNow?.invoke()
        }

        fun removeMessageListener(listener: (String) -> Unit) {
            listeners.remove(listener)
            // The screen may have gone off while this listener was still
            // registered; without this, power save stayed off until the next
            // screen event.
            listenerRemoved?.invoke()
        }

        @Volatile
        private var listenerRemoved: (() -> Unit)? = null

        private val powerSaveExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()

        /** The service is up and polling (see `P2PRetryWorker`). */
        @Volatile
        var alive = false
            private set

        /** True while one of our activities is started (set by P2PApplication). Power save follows this, not just the screen: with the screen on in ANOTHER app,
         *  the service would run at full rate and the LTE radio would never sleep, all of it charged to us (about 1 mAh per minute of screen-on time, measured on a device). */
        @Volatile
        var appVisible = false
            private set

        /** See `onStartCommand`: the microphone service type follows this. */
        @Volatile
        private var callActive = false

        /** #86: a voice recording runs in a chat screen; same microphone type + notification text. */
        @Volatile
        private var recordingActive = false

        fun setCallActive(context: Context, active: Boolean) {
            if (callActive == active) return
            callActive = active
            refreshForeground(context)
        }

        fun setRecordingActive(context: Context, active: Boolean) {
            if (recordingActive == active) return
            recordingActive = active
            refreshForeground(context)
        }

        private fun refreshForeground(context: Context) {
            try {
                androidx.core.content.ContextCompat.startForegroundService(context, Intent(context, P2PService::class.java))
            } catch (e: Exception) {
                Log.w(TAG, "Call state not applied to service: ${e.message}")
            }
        }

        fun setAppVisible(visible: Boolean) {
            if (appVisible == visible) return
            appVisible = visible
            listenerRemoved?.invoke()
            if (visible) wakePollNow?.invoke()
        }

        /**
         * The ID of the conversation shown on screen right now: `peer_device_fingerprint` for 1:1, `"group:$group_id"` for groups. ChatActivity and
         * GroupChatActivity set and clear it in onResume and onPause. If a message belongs to that conversation, NO notification is shown (it is already visible
         * live). For any other conversation, or when no chat is open, a notification is shown.
         *
         * `maybeNotify` now reads this from the background `HandlerThread` of `pollRunnable` (see those fields' docs), while writes come from the Activities' main thread.
         * Without `@Volatile`, a value written on one thread may never become visible to the other (CPU caches and compiler reordering), so a notification that should be
         * suppressed could keep showing briefly. `@Volatile` guarantees that every read sees the latest written value.
         */
        @Volatile
        var activeConversationId: String? = null

        /** Node mode: the user switches it on or off in Settings. */
        fun isNodeModeEnabled(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getBoolean(KEY_NODE_MODE, false)
        }

        fun setNodeModeEnabled(context: Context, enabled: Boolean) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putBoolean(KEY_NODE_MODE, enabled).apply()
                        // If a network is already running, update it live too.
            settingsJni.execute { P2PLib.setNodeMode(enabled) }
        }

        /** Settings JNI calls take the core lock, which a poll turn can hold for seconds: never on the
         *  main thread. One thread keeps them in order, so the last value wins. */
        private val settingsJni = java.util.concurrent.Executors.newSingleThreadExecutor()

        /** The history and attachment storage limit slider in Settings. It matters only while node mode is on (see Rust `enforce_history_storage_limit`),
         *  but the preference is always stored. */
        fun getHistoryStorageLimitBytes(context: Context): Long {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getLong(KEY_HISTORY_STORAGE_LIMIT, DEFAULT_HISTORY_STORAGE_LIMIT_BYTES)
        }

        fun setHistoryStorageLimitBytes(context: Context, bytes: Long) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putLong(KEY_HISTORY_STORAGE_LIMIT, bytes).apply()
                        // If a network is already running, update it live too (if the limit was lowered, the oldest files are deleted at once).
            settingsJni.execute { P2PLib.setHistoryStorageLimitBytes(bytes) }
        }
    }

        // The poll thread reads `isRunning`, and onStartCommand and onDestroy write it on the main thread.
        // `@Volatile` gives visibility.
    @Volatile
    private var isRunning = false

        /* --- Battery design: see the note in the companion object. --- */

    /** Whether the device screen is on. Updated by the ACTION_SCREEN_ON and ACTION_SCREEN_OFF broadcasts. These cannot be received from the manifest,
     *  so they must be registered at run time. */
    @Volatile
    private var screenOn = true

    /** Retry interval for `startNet` (see `startNet`): grows exponentially, up to `START_NET_RETRY_MAX_MS`. */
    private var startNetRetryDelayMs = START_NET_RETRY_INITIAL_MS

    /** Whether the core really has work (see Rust `has_pending_work`). It is not asked on every turn: the query is itself a JNI call that takes the global lock.
     *  It is refreshed sparsely: only while the screen is off, at most every 15 s (see `refreshCoreBusy`). */
    @Volatile
    private var coreBusy = true
    private var lastBusyCheckAt = 0L

    private var screenReceiver: android.content.BroadcastReceiver? = null
    @Volatile private var dozeAlarmSet = false

    /**
     * A fix for Android 14 and later, measured on a real device.
     *
     * Android 14+ stops a `dataSync` foreground service for 'app idle' reasons. Logcat showed it: while a 14 MB file was uploading to the server, the service died,
     * the upload stopped silently with no error, and `pollNetwork` was never called again. The file looked sent to the user, but it had never reached the server.
     *
     * The partial wake lock keeps the CPU awake while a transfer runs. It is NOT enough on its own: the battery optimisation exemption is also needed (see
     * `SettingsFragment`, which asks the user for it; that is the user's choice, not automatic).
     */
    private var wakeLock: android.os.PowerManager.WakeLock? = null
    /** The timeout the held lock was taken with (0 = none). */
    @Volatile private var heldWakeTimeoutMs = 0L
    /** See `observeNetworkChangesForReconnect`: follows ANY default-network change. */
    private var defaultNetworkCallback: ConnectivityManager.NetworkCallback? = null
    // This service runs `P2PLib.pollNetwork()` (JNI: message decryption, ratchet cryptography, DB archiving, file-offer event handling) every second, indefinitely.
    // It is scheduled on its own `HandlerThread`, not on the UI thread's `Handler`. On the UI thread, any poll turn longer than a few hundred milliseconds (a large
    // `HistorySyncResponse`, a group fan-out, a slow SQLite write under disk I/O contention) would block touch input everywhere in the app, because the service
    // outlives the Activities. It would also show an ANR dialog past 5 seconds.
    // This is safe: the `listeners` called from `pollRunnable` already protect their UI parts with their own `runOnUiThread` wrappers (see the ChatActivity and
    // GroupChatActivity `messageListener`), and `maybeNotify` only uses `NotificationManager` and a simple `var` read, so both may be called from any thread.
    private val pollThread = HandlerThread("P2PPollThread").apply { start() }
    private var handler: Handler = Handler(pollThread.looper)
    /** `pollRunnable` used to run at a fixed 1 s, forever. A JNI call every second in the background (Rust poll turn: swarm scan, `reconnect_sweep`,
     *  `retry_unconfirmed_messages`, etc.), even when no chat screen was ever opened, is the main cost in modern power models, because the number of wake-ups
     *  weighs more than the cost of any single one. To reduce it without losing or delaying messages: while ANY screen is listening (`listeners` is non-empty,
     *  the user is interacting with the app right now) the speed never changes (`POLL_INTERVAL_ACTIVE_MS`). In the background, after several consecutive turns
     *  with no event (`consecutiveEmptyPolls`), the interval widens gradually (see `nextPollDelayMs`). A message is never lost. At most it arrives a few seconds
     *  late while idle. A real event (message, ack, etc.) or a screen opening resets the interval to 1 s at once. */
    private var consecutiveEmptyPolls = 0
    /** The time to wait in `waitForNetworkActivity` at the start of the next turn. */
    @Volatile private var pendingWaitMs = 0L
    private val pollRunnable = object : Runnable {
        override fun run() {
            // A debugger or hooking tool in the process: keys are wiped and the process exits (see Vault.checkTamper).
            if (com.p2p.messenger.util.Vault.checkTamper(applicationContext)) return
            if (isRunning) {
                                // See `pendingWaitMs` below: wait for a network event instead of a fixed delay.
                val waitMs = pendingWaitMs
                pendingWaitMs = 0L
                if (waitMs > 0L) {
                    try { P2PLib.waitForNetworkActivity(waitMs) } catch (e: Throwable) {}
                                        // Deep idle holds no lock: the network event woke the CPU, so a short-lived lock is held until the work is done, so no message is missed.
                    acquireWakeLock(20_000L)
                }
                // An uncaught exception here (pollNetwork, a listener, or
                // notify) would skip postDelayed below and permanently stop
                // all polling for the life of the process, so it must not
                // escape this loop. `Throwable`, not `Exception`: an `Error`
                // (OutOfMemoryError, a StackOverflowError from a malformed
                // payload) must not take the poll thread — and with it the
                // whole service — down either.
                try {
                    val messages = P2PLib.pollNetwork()
                    if (messages.any { it.isNotEmpty() }) {
                        consecutiveEmptyPolls = 0
                    } else {
                        consecutiveEmptyPolls++
                    }
                    // One guard per event: the batch is already drained from
                    // the core, so an exception used to lose every event
                    // after it (notification, read sync, remote wipe).
                    for (msg in messages) {
                        if (msg.isEmpty()) continue
                        for (listener in listeners) {
                            try { listener(msg) } catch (e: Throwable) {
                                com.p2p.messenger.util.Log.e("P2PService", "Listener failed", e)
                            }
                        }
                        try { maybeNotify(msg) } catch (e: Throwable) {
                            com.p2p.messenger.util.Log.e("P2PService", "Notify failed", e)
                        }
                    }
                    try { refreshForegroundStatus() } catch (e: Throwable) {
                        com.p2p.messenger.util.Log.e("P2PService", "Status refresh failed", e)
                    }
                } catch (e: Throwable) {
                    com.p2p.messenger.util.Log.e("P2PService", "Poll cycle failed", e)
                } finally {
                                        // After every turn, decide again which stage of power-save we are in.
                    refreshCoreBusy()
                    if (!isRunning) {
                        // onDestroy ran during the blocking wait above: do not
                        // take the wake lock or set the alarm again.
                    } else if (inDeepIdle()) {
                                                // Deep idle: the wake lock is RELEASED so the CPU can really sleep. If the device sleeps, `postDelayed` (uptime-based) stops,
                                                // so an alarm is set that also fires under Doze.
                                                // Without a lock but staying awake: wait for a network event in Rust (incoming bytes wake the CPU, so messages are not delayed).
                                                // The Doze alarm is the backup.
                        releaseWakeLock()
                        scheduleDozeWakeup()
                        pendingWaitMs = nextPollDelayMs()
                        handler.removeCallbacks(this)
                        handler.post(this)
                    } else {
                        acquireWakeLock()
                        cancelDozeWakeup()
                                                // In awake mode the wait happens in Rust: incoming bytes or an outgoing message end the wait at once (each direction used to wait
                                                // for a ~1 s poll turn). The same runnable is removed first, so it is not queued twice.
                        pendingWaitMs = nextPollDelayMs()
                        handler.removeCallbacks(this)
                        handler.post(this)
                    }
                }
            }
        }
    }

    /**
     * The poll interval (see the battery note in the companion object).
     *
     * Order matters: the fastest condition is at the top. If a chat screen is open, nothing changes and the user feels no delay.
     */
    private fun nextPollDelayMs(): Long {
                // 1) The user is looking at a chat right now.
        if (listeners.isNotEmpty()) return POLL_INTERVAL_ACTIVE_MS
                // 2) A new event arrived, or there has not been enough quiet yet: poll every 1 s.
        if (consecutiveEmptyPolls < POLL_IDLE_BACKOFF_THRESHOLD) return POLL_INTERVAL_ACTIVE_MS
        // `appVisible` like `inDeepIdle`: with the screen on in ANOTHER app the
        // loop counted as deep idle but still polled every 2-3 s.
        if (screenOn && appVisible) {
            val idleSteps = consecutiveEmptyPolls - POLL_IDLE_BACKOFF_THRESHOLD
            val delay = POLL_INTERVAL_SCREEN_ON_MS + idleSteps * POLL_IDLE_STEP_MS
            return delay.coerceAtMost(POLL_INTERVAL_SCREEN_ON_MS + POLL_IDLE_STEP_MS * 2)
        }
                // 3) Screen off. If the core has work (a connected peer, a pending message, a running download), it is still polled at a reasonable rate.
        if (coreBusy || consecutiveEmptyPolls < DEEP_IDLE_AFTER_EMPTY_POLLS) {
            return POLL_INTERVAL_SCREEN_OFF_MS
        }
                // 4) Screen off AND the core is completely idle.
        return POLL_INTERVAL_DEEP_IDLE_MS
    }

    /** Whether we are in deep idle: the only state in which the wake lock is released. */
    private fun inDeepIdle(): Boolean =
        !(screenOn && appVisible) && listeners.isEmpty() && !coreBusy &&
            consecutiveEmptyPolls >= DEEP_IDLE_AFTER_EMPTY_POLLS

    /**
     * Refreshes whether the core is busy, sparsely.
     *
     * The query is itself a JNI call that takes the global lock, so it is not done on every turn: only while the screen is off, and at most every 15 seconds.
     * With the screen on we are already on the fast turn, so the answer does not matter then.
     */
    private fun refreshCoreBusy() {
        if (screenOn && appVisible) { coreBusy = true; return }
        val now = android.os.SystemClock.elapsedRealtime()
        if (now - lastBusyCheckAt < 15000L) return
        lastBusyCheckAt = now
        coreBusy = try {
            JSONObject(P2PLib.ownConnectionStatus()).optBoolean("busy", true)
        } catch (e: Exception) {
                        // If we cannot tell, assume BUSY: waking up a bit too often is better than delaying a message by being wrong.
            true
        }
    }

    /**
     * Watches the screen state. The two broadcasts (`ACTION_SCREEN_ON` and `ACTION_SCREEN_OFF`) cannot be received from the manifest, so they must be registered at run time.
     */
    private fun observeScreenState() {
        val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        screenOn = pm.isInteractive
        applyPowerSave()
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON -> {
                        screenOn = true
                        applyPowerSave()
                        // Only when Typeon itself is on screen: a glance at
                        // the clock restarted ~40 s of fast polling under an
                        // indefinite wake lock. `setAppVisible(true)` already
                        // triggers a turn when the app comes to the front.
                        if (appVisible) {
                            coreBusy = true
                            consecutiveEmptyPolls = 0
                            acquireWakeLock()
                            handler.removeCallbacks(pollRunnable)
                            handler.post(pollRunnable)
                        }
                    }
                    Intent.ACTION_SCREEN_OFF -> {
                        screenOn = false
                        lastBusyCheckAt = 0L
                        applyPowerSave()
                    }
                }
            }
        }
        screenReceiver = receiver
        val filter = android.content.IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        try {
                        // API 34+ requires an export flag for broadcast receivers. `ACTION_SCREEN_ON/OFF` are protected system broadcasts, so they are technically exempt.
                        // Stating NOT_EXPORTED explicitly is correct, and it prevents a crash if a non-system action is added later.
            androidx.core.content.ContextCompat.registerReceiver(
                this, receiver, filter,
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
            )
        } catch (e: Exception) {
            Log.w(TAG, "Ekran durumu izlenemedi: ${e.message}")
                        // If registration fails, `screenOn` would stay true and deep idle would NEVER engage: the process would stay awake for its whole lifetime
                        // (lock plus a 1-2 s poll). When the screen state is unknown, the worst assumption is 'off', so deep idle can engage.
            screenOn = false
        }
    }

    /** See Rust `set_power_save`: the liveness check of quiet connections runs every 60 s instead of 20 s, so the radio can sleep longer. */
    private fun applyPowerSave() {
        // Off the caller's thread: the JNI call takes the core lock and the
        // callers are the main thread (screen receiver, every chat onPause).
        // The state is read when the task runs, so the order does not matter.
        powerSaveExecutor.execute {
            val enabled = !(screenOn && appVisible) && listeners.isEmpty()
            try {
                P2PLib.setPowerSave(enabled)
            } catch (e: Exception) {
                Log.w(TAG, "Power saving mode could not be set: ${e.message}")
            }
        }
    }

    /**
     * While in deep idle the wake lock is released, so the device may sleep and `Handler.postDelayed` (uptime-based) stops.
     * This alarm guarantees a periodic wake-up, even under Doze.
     */
    private fun scheduleDozeWakeup() {
        dozeAlarmSet = true
        try {
            val am = getSystemService(Context.ALARM_SERVICE) as android.app.AlarmManager
            // A broadcast, not a service start: an inexact alarm does not
            // exempt a background foreground-service start on Android 12+
            // (only an exact one or the battery exemption does), and a refused
            // start ended the wake-up chain silently. The service already runs.
            val intent = Intent(this, DozeWakeReceiver::class.java)
            val pending = android.app.PendingIntent.getBroadcast(
                this, 0, intent,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
            )
            am.setAndAllowWhileIdle(
                android.app.AlarmManager.ELAPSED_REALTIME_WAKEUP,
                android.os.SystemClock.elapsedRealtime() + DOZE_WAKE_INTERVAL_MS,
                pending
            )
        } catch (e: Exception) {
            Log.w(TAG, "Doze wake alarm could not be set: ${e.message}")
        }
    }

    /** One turn now, from the Doze alarm (see `scheduleDozeWakeup`). */
    private fun onDozeWake() {
        // Timed, and the empty-poll counter is NOT reset: an indefinite
        // lock plus twelve fresh empty turns kept the CPU awake 40-70 s
        // per alarm, a fifth of the night. The turn itself releases the
        // lock as soon as it finds the core still idle.
        acquireWakeLock(20_000L)
        lastBusyCheckAt = 0L
        // The poll thread sits in the native wait (up to 30 s): end it,
        // or the lock runs out before the turn and the CPU sleeps again.
        try { P2PLib.wakePoll() } catch (e: Throwable) { }
        // Armed again here: if the turn still does not run, the next alarm
        // does, and the chain of Doze wake-ups cannot stop.
        scheduleDozeWakeup()
        handler.removeCallbacks(pollRunnable)
        handler.post(pollRunnable)
    }

    private fun cancelDozeWakeup() {
        // Runs every awake turn: without the flag that was two binder calls
        // per turn for an alarm that is almost never set.
        if (!dozeAlarmSet) return
        dozeAlarmSet = false
        try {
            val am = getSystemService(Context.ALARM_SERVICE) as android.app.AlarmManager
            val intent = Intent(this, DozeWakeReceiver::class.java)
            val pending = android.app.PendingIntent.getBroadcast(
                this, 0, intent,
                android.app.PendingIntent.FLAG_NO_CREATE or android.app.PendingIntent.FLAG_IMMUTABLE
            )
            if (pending != null) am.cancel(pending)
        } catch (e: Exception) {
            // yoksay
        }
    }

    /**
     * A fully local notification system that does not depend on Google Play Services or FCM (see the file-header note in NotificationHelper). This service
     * already scans the network every second, so a separate push infrastructure is not needed. New messages, attachments, calls and whiteboard strokes produce
     * a notification. Edit and delete events only update or clear a notification that is already showing. If the related chat is open on screen
     * (activeConversationId matches), the notification is SUPPRESSED, since the message is already visible live.
     */
    private fun maybeNotify(json: String) {
        val obj = try {
            JSONObject(json)
        } catch (e: Exception) {
                        // If this were swallowed silently, a change in the event format would silently turn notifications off, and nobody would know why.
            Log.w(TAG, "Event JSON could not be read: ${e.message}")
            return
        }
        when (obj.optString("type")) {
            "sync", "device_linked" -> com.p2p.messenger.util.ArchiveKeyManager.persistIfNew(applicationContext)
            // the core caught a panic (also a single bad packet): log
            // it only; restarting the service per event would be a DoS lever.
            "pairing_failed" -> {
                Log.w(TAG, "pairing_failed: ${obj.optString("reason")}")
                if (obj.optString("reason") == "contact_limit") android.os.Handler(android.os.Looper.getMainLooper()).post {
                    android.widget.Toast.makeText(applicationContext, R.string.msg_pairing_contact_limit, android.widget.Toast.LENGTH_LONG).show()
                }
            }
            "core_panic" -> Log.e(TAG, "Core caught a panic (see logcat 'PANIC caught')")
            // The restore button already said "loading": say that it stopped short.
            "history_restore_incomplete" -> android.os.Handler(android.os.Looper.getMainLooper()).post {
                android.widget.Toast.makeText(applicationContext, R.string.msg_restore_incomplete, android.widget.Toast.LENGTH_LONG).show()
            }
            "account_deleted" -> NotificationHelper.showAccountDeletedNotification(
                applicationContext, obj.optString("peer"), obj.optString("display_name")
            )
                        // This device was revoked by its own (primary) identity. The Rust core has already deleted the DB tables and attachments and is now inert.
                        // Here the UI-side persistent secrets (the Keystore-wrapped secret bundle file) and the DB file are deleted too, and the app restarts into
                        // onboarding in a CLEAN process. The steps are the same as in `SettingsFragment.performLogout`, for the same reason: delete the files and
                        // start clean, instead of resetting the identity in a live process.
            "self_revoked" -> {
                                // Wipes every Keystore-wrapped key too: the history key, the skipped-key key, and the ARK that decrypts the archive on the server.
                                // Not only `identity_secret.enc`. The point of this branch is 'my device was stolen, I am revoking it remotely', so the keys must go as well.
                                // Shared with the other wipe path: see `util.LocalWipe`.
                com.p2p.messenger.util.LocalWipe.wipe(applicationContext)
                NotificationHelper.showDeviceRevokedNotification(applicationContext)
                com.p2p.messenger.util.AppRestarter.restart(applicationContext)
            }
                        // Multi-device: another of our devices read this conversation, so it counts as read here too (the conversation list then does not show it unread).
                        // Rust raises this event only for a ReadStateSync from a sibling device, and converts the conversation to this device's local key
                        // (the canonical device fingerprint, or "group:<id>").
            "read_state_sync" -> {
                val conv = obj.optString("conversation")
                val readAt = obj.optLong("read_at")
                if (conv.isNotEmpty() && readAt > 0L) {
                    ReadStatePrefs.markReadAt(applicationContext, conv, readAt)
                                        // The conversation was marked read, but the notification stayed in the status bar. Example: you read the chat on the desktop (or on
                                        // the other phone), and this device still shows the notification for the same message. The chat list was already right; only the
                                        // notification stayed behind.
                                        // Compared with `read_at`: a late sync must not remove the notification of a message that arrived after it.
                    NotificationHelper.clearIfReadUpTo(applicationContext, conv, readAt)
                }
            }
            "call" -> if (obj.optString("action") == "invite") {
                com.p2p.messenger.ui.CallActivity.ring(applicationContext, obj.optString("name"), obj.optBoolean("video"))
            } else if (obj.optBoolean("ended")) {
                // Caller gave up while we were only a notification (no
                // full-screen permission, screen on): don't leave it ringing.
                com.p2p.messenger.ui.CallActivity.cancelRing(applicationContext)
                if (obj.optBoolean("missed")) {
                    NotificationHelper.showMessageNotification(applicationContext, obj.optString("peer"), getString(R.string.call_missed), "")
                }
            }
            "message" -> {
                val peer = obj.optString("peer")
                if (peer.isNotEmpty() && activeConversationId != peer) {
                    NotificationHelper.showMessageNotification(applicationContext, peer, shownText(obj, obj.optString("text")), obj.optString("message_id"))
                }
            }
            // A new drawing (not an erase): the core sets "new" only when a stroke from someone else was stored.
            "whiteboard" -> if (obj.optBoolean("new")) {
                val peer = obj.optString("peer")
                val groupId = obj.optString("group_id")
                val conv = if (groupId.isNotEmpty()) "group:$groupId" else peer
                if (conv.isNotEmpty() && activeConversationId != conv) {
                    NotificationHelper.showWhiteboardNotification(applicationContext, peer, groupId)
                }
            }
            "group_message" -> {
                val groupId = obj.optString("group_id")
                if (groupId.isNotEmpty() && activeConversationId != "group:$groupId") {
                    NotificationHelper.showGroupMessageNotification(
                        applicationContext, groupId, obj.optString("sender_identity_id"), shownText(obj, obj.optString("text")),
                        obj.optString("message_id"), mention = obj.optBoolean("mentions_me")
                    )
                }
            }
                        // Edit and delete events, for the notification in the status bar. If a message is deleted or edited while its notification is still unseen in the
                        // background, the notification would stay forever with the old (now invalid) text. Notifications use ONE slot per conversation (see the `show` note),
                        // so we cannot know exactly which message a notification belongs to. A delete therefore clears the notification completely (the safest acceptable
                        // behaviour), while an edit updates it ONLY if a notification for that conversation is still showing. If none is showing, the user has already
                        // seen or dismissed it, and posting a new one for an edit makes no sense.
            "delete" -> {
                val peer = obj.optString("peer")
                if (peer.isNotEmpty()) NotificationHelper.clearIfShowing(applicationContext, peer, obj.optString("message_id"))
            }
                        // A device-alert notification is also posted now (see `NotificationHelper.showDeviceAlertNotification`), not only the in-app dialog. The dialog opens
                        // only when the main screen is in the foreground. This keeps the alert visible when the app is in the background or on another screen.
            "device_alert" -> {
                NotificationHelper.showDeviceAlertNotification(
                    applicationContext,
                    obj.optString("contact_display_name"),
                    obj.optString("device_short_code")
                )
            }
            "group_delete" -> {
                val groupId = obj.optString("group_id")
                if (groupId.isNotEmpty()) NotificationHelper.clearIfShowing(applicationContext, "group:$groupId", obj.optString("message_id"))
            }
            "edit" -> {
                val peer = obj.optString("peer")
                if (peer.isNotEmpty() && activeConversationId != peer) {
                    NotificationHelper.updateMessageNotificationIfShowing(applicationContext, peer, obj.optString("text"))
                }
            }
            "group_edit" -> {
                val groupId = obj.optString("group_id")
                if (groupId.isNotEmpty() && activeConversationId != "group:$groupId") {
                    NotificationHelper.updateGroupMessageNotificationIfShowing(applicationContext, groupId, obj.optString("text"))
                }
            }
                        // Attachments produce notifications too, not only text messages.
            "file_offer" -> {
                val groupId = if (obj.isNull("group_id")) "" else obj.optString("group_id")
                val label = shownText(obj, attachmentNotificationLabel(
                    obj.optString("mime_type", ""), obj.optString("file_name", ""), obj.optBoolean("sticker")
                ))
                if (groupId.isNotEmpty()) {
                    if (activeConversationId != "group:$groupId") {
                        NotificationHelper.showGroupMessageNotification(
                            applicationContext, groupId, obj.optString("sender_identity_id"), label,
                            obj.optString("file_id")
                        )
                    }
                } else {
                    val peer = obj.optString("peer")
                    if (peer.isNotEmpty() && activeConversationId != peer) {
                        NotificationHelper.showMessageNotification(applicationContext, peer, label, obj.optString("file_id"))
                    }
                }
            }
        }
    }

    /** A disappearing message's content never goes into a notification (it would outlive the message there). */
    private fun shownText(obj: JSONObject, text: String): String =
        if (obj.optLong("expire_secs", 0L) > 0) getString(R.string.disappear_notification) else text

    /** Short label for the attachment notification (see `maybeNotify`, 'file_offer'). */
    private fun attachmentNotificationLabel(mimeType: String, fileName: String, sticker: Boolean): String = when {
        sticker -> getString(R.string.lbl_last_sticker)
        mimeType.startsWith("image/") -> getString(R.string.lbl_last_photo)
        mimeType.startsWith("video/") -> getString(R.string.lbl_last_video)
        mimeType.startsWith("audio/") -> getString(R.string.lbl_last_voice)
        fileName.isNotEmpty() -> "📎 $fileName"
        else -> getString(R.string.lbl_last_file)
    }

    private fun foregroundNotification(text: String) = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle(getString(R.string.app_name))
        .setContentText(text)
        .setSmallIcon(R.drawable.ic_notification)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .build()

    /** Last connection text shown in the ongoing notification; null = not checked yet. */
    private var fgStatusText: String? = null
    private var fgStatusCheckedAt = 0L

    /**
     * The ongoing notification follows the real connection state (internet,
     * Tor, store-and-forward server). Piggybacks on a poll turn that runs
     * anyway, at most every 30 s, and re-posts only when the text changed:
     * no extra wakeups.
     */
    private fun refreshForegroundStatus() {
        val now = android.os.SystemClock.elapsedRealtime()
        if (fgStatusText != null && now - fgStatusCheckedAt < 30_000L) return
        fgStatusCheckedAt = now
        val status = com.p2p.messenger.util.ConnectionStatus.current(this)
        val text = if (status.level != com.p2p.messenger.util.ConnectionStatus.Level.CONNECTED) {
            status.text
        } else {
            val servers = try { org.json.JSONArray(P2PLib.listServers()) } catch (e: Exception) { org.json.JSONArray() }
            // Routing servers, not enrolled ones: the core clears `enrolled` when the link drops.
            val routing = (0 until servers.length()).mapNotNull { servers.optJSONObject(it) }.filter { it.optBoolean("route_messages") }
            if (routing.isNotEmpty() && routing.none { it.optBoolean("connected") && it.optBoolean("enrolled") }) getString(R.string.notif_fg_server_down)
            else getString(R.string.notif_fg_text)
        }
        if (text == fgStatusText) return
        fgStatusText = text
        if (recordingActive) return
        try {
            (getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager)
                .notify(NOTIFICATION_ID, foregroundNotification(text))
        } catch (e: Exception) {
            Log.w(TAG, "Status notification not updated: ${e.message}")
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        NotificationHelper.createChannel(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
                // The persistent notification of this foreground service used `ic_launcher_foreground`, a FULL-COLOUR adaptive-icon layer rather than a valid
                // notification silhouette, so the status bar showed the Android logo instead of Typeon. The same error was already fixed for message notifications
                // (see NotificationHelper.kt) by switching to `ic_notification`, but THIS call site was missed. It is the most visible notification, since it shows
                // whenever the app runs.
        val notification = foregroundNotification(
            if (recordingActive) getString(R.string.notif_fg_recording) else fgStatusText ?: getString(R.string.notif_fg_text)
        )

        // See the manifest note: remoteMessaging on API 34+ (no daily cap).
        val baseType =
            if (Build.VERSION.SDK_INT >= 34) android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING
            else android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
        // During a call the service also carries the microphone type: on
        // Android 11+ a service without it records silence as soon as the
        // call screen is not visible (screen off, Back without PiP).
        val micType =
            if ((callActive || recordingActive) && Build.VERSION.SDK_INT >= 30 &&
                checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) == android.content.pm.PackageManager.PERMISSION_GRANTED
            ) android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0
        try {
            androidx.core.app.ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, baseType or micType)
        } catch (e: Exception) {
            // Microphone type refused (started from the background), or the
            // start itself is not allowed: keep running with what we get.
            Log.w(TAG, "startForeground failed: ${e.message}")
            // The retry must NOT depend on the microphone type: a refused
            // start leaves the service without a foreground state, the 5 s
            // contract is missed and the process is killed (RemoteService-
            // Exception) — with the plain type there is still a chance.
            try {
                androidx.core.app.ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, baseType)
            } catch (e2: Exception) {
                Log.w(TAG, "startForeground failed: ${e2.message}")
            }
        }

                // If we came from the Doze wake-up alarm, the service is already running. The only thing to do is run one turn at once (see `scheduleDozeWakeup`).
        if (intent?.action == ACTION_WAKE_POLL && isRunning) {
            onDozeWake()
            return START_STICKY
        }
        if (!isRunning) {
            isRunning = true
            alive = true
            // Only here: on a running service the poll loop owns the lock, and
            // an indefinite one taken by every other start (retry worker, call
            // end, boot receiver) stayed held until the blocking wait returned.
            acquireWakeLock()
                    // Power save: the screen state is the strongest signal for the poll stage (see the note in the companion object).
            observeScreenState()
            BatteryLog.start(this)
                    // Connection testing and automatic reconnecting: see `observeNetworkChangesForReconnect`.
            observeNetworkChangesForReconnect()
                    // Safety net: if the system restarts this service on its own, separately from MainActivity (the process was killed and brought back with START_STICKY),
                    // initDatabase and the secret key load may not have run yet. These calls are idempotent: calling initDatabase again returns at once (P2PLib.initDatabase checks databaseOpen)
                    // and loadIfPresent writes the same values over keys already loaded.
                    // Measured as an ANR on a device (see /data/anr). All six calls below are heavy JNI and SQLite work, and ALL ran on the main thread. The captured stack
                    // showed the main thread inside `SkippedKeyManager.ensureLoaded` → JNI → `fsync()` in uninterruptible disk wait (`state=D`), which gave an
                    // 'Input dispatching timed out' ANR.
                    //
                    // The trigger is frequent: `MainActivity.onResume` calls `startNetworkService()` on every return, and when the process is killed by the OS and brought
                    // back with START_STICKY, this block runs again.
                    //
                    // `handler` is already bound to a separate `HandlerThread` (pollThread) and runs SEQUENTIALLY. Posting init to it and then posting `pollRunnable` right
                    // after guarantees that polling does not run before init. `startForeground` stayed on the main thread, since Android waits for it there within 5 s.
            handler.post { initAndStart() }
            listenerRemoved = { applyPowerSave() }
            wakePollNow = {
                handler.removeCallbacks(pollRunnable)
                handler.post(pollRunnable)
            }
            dozeWake = { if (isRunning) onDozeWake() }
            handler.post(pollRunnable)
        }

        return START_STICKY
    }

    /** Same backoff for every start step that depends on the Keystore or
     *  the database: a transient failure must not end the service. */
    private fun retryStart(step: () -> Unit) {
        val delay = startNetRetryDelayMs
        startNetRetryDelayMs = (startNetRetryDelayMs * 2).coerceAtMost(START_NET_RETRY_MAX_MS)
        handler.postDelayed({ if (isRunning) step() }, delay)
    }

    /** Runs on the poll thread (see `onStartCommand`). */
    private fun initAndStart() {
        // init must never throw out of the HandlerThread (START_STICKY crash loop).
        try {
            if (!com.p2p.messenger.util.Vault.isOpen()) {
                // After a reboot or a process kill: the keys open only with the app password. The prompt brings up the
                // password screen; the start goes on from here once it is entered.
                if (!com.p2p.messenger.util.Vault.exists(applicationContext)) { stopSelf(); return }
                com.p2p.messenger.util.Vault.showUnlockPrompt(applicationContext)
                com.p2p.messenger.util.Vault.whenOpen { handler.post { if (isRunning) initAndStart() } }
                return
            }
            if (!P2PLib.initDatabase(applicationContext.filesDir.absolutePath)) {
                // Database not open (Keystore failure): not the same as
                // "no account", the service stays and tries again.
                com.p2p.messenger.util.KeystoreCrypto.reportKeyFailure(applicationContext)
                retryStart { initAndStart() }
                return
            }
            if (!P2PLib.hasStoredIdentity()) {
                // START_STICKY brought the service back after a logout or
                // a remote wipe: no account, nothing to run. `onDestroy`
                // clears the flags.
                stopSelf()
                return
            }
            com.p2p.messenger.util.SkippedKeyManager.ensureLoaded(applicationContext)
            com.p2p.messenger.util.MessageHistoryManager.ensureHistoryKeyLoaded(applicationContext)
            // The archive root key is never generated here (see ArchiveKeyManager).
            com.p2p.messenger.util.ArchiveKeyManager.loadIfPresent(applicationContext)
            startNet()
            P2PLib.setHistoryStorageLimitBytes(getHistoryStorageLimitBytes(applicationContext))
        } catch (t: Throwable) {
            Log.e(TAG, "Service start error: ${t.message}")
        }
    }

    /** The core returns an error when Tor cannot start: try again with a
     *  backoff (see `retryStart`). Runs on the poll thread. */
    private fun startNet() {
        try {
            // The core refuses to start without its storage keys; a
            // keystore that failed at boot is tried again here.
            com.p2p.messenger.util.SkippedKeyManager.ensureLoaded(applicationContext)
            com.p2p.messenger.util.MessageHistoryManager.ensureHistoryKeyLoaded(applicationContext)
            // The core does not check for its own device keys: without
            // them the network would run but could not sign or decrypt.
            if (!com.p2p.messenger.util.IdentityManager.loadIfPresent(applicationContext)) {
                com.p2p.messenger.util.KeystoreCrypto.reportKeyFailure(applicationContext)
                retryStart { startNet() }
                return
            }
            val nodeMode = isNodeModeEnabled(applicationContext)
            // Tor is mandatory: the core refuses to start without it.
            if (P2PLib.startNetwork(nodeMode, true).startsWith("Error")) {
                retryStart { startNet() }
            } else {
                startNetRetryDelayMs = START_NET_RETRY_INITIAL_MS
                applyMeteredToTor()
            }
        } catch (t: Throwable) {
            // A throw from a retried step would otherwise end the retry chain.
            Log.e(TAG, "Network start error: ${t.message}")
            retryStart { startNet() }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        alive = false
        releaseWakeLock()
        BatteryLog.stop()
        wakePollNow = null
        dozeWake = null
        listenerRemoved = null
        handler.removeCallbacks(pollRunnable)
        cancelDozeWakeup()
        screenReceiver?.let {
            try {
                unregisterReceiver(it)
            } catch (e: Exception) {
            }
        }
        screenReceiver = null
        pollThread.quitSafely()
        defaultNetworkCallback?.let {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(it)
            } catch (e: Exception) {
                // yoksay
            }
        }
        defaultNetworkCallback = null
        networkChangeExecutor.shutdownNow()
    }

    /**
     * See the `wakeLock` field note.
     *
     * One lock object for the service's lifetime, and both functions are `synchronized`: they run on the poll thread and on the main thread (screen receiver,
     * onStartCommand). Creating a new lock per call let a race or an overwrite drop a held lock that nothing ever released again (on a device: three
     * 'Typeon:network' locks held at once, one for 1h42m, the CPU never slept, about 180 mA all night with the screen off).
     *
     * No UNBOUNDED LOCK: when the core reported busy (a running download, a fresh pairing, a queued envelope), the lock used to be held indefinitely. If the other side
     * hung, the download never finished and the lock never ended (a partial wake lock that keeps the device from sleeping). Now it is held for at most
     * WAKE_LOCK_MAX_MS: when the lock fills its window it ends by itself, and the poll loop acquires it again on the next turn.
     */
    @Synchronized
    private fun acquireWakeLock(timeoutMs: Long = 0L) {
        try {
            val lock = wakeLock ?: (getSystemService(Context.POWER_SERVICE) as android.os.PowerManager)
                .newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "Typeon:network")
                .also { it.setReferenceCounted(false); wakeLock = it }
                        // 0 used to mean 'unbounded': the cap applies to it now.
            val wanted = if (timeoutMs > 0L) timeoutMs else WAKE_LOCK_MAX_MS
            if (lock.isHeld) {
                                // A longer lock wins. A shorter request does not shorten a held lock or reduce its expiry.
                if (wanted <= heldWakeTimeoutMs) return
                lock.release()
            }
            heldWakeTimeoutMs = wanted
            lock.acquire(wanted)
            BatteryLog.wakeAcquired(wanted)
        } catch (e: Exception) {
            Log.w(TAG, "Wake lock could not be acquired: ${e.message}")
        }
    }

    @Synchronized
    private fun releaseWakeLock() {
        try {
            wakeLock?.let { if (it.isHeld) { it.release(); BatteryLog.wakeReleased() } }
        } catch (e: Exception) {
                        // If already released, ignore.
        }
        heldWakeTimeoutMs = 0L
    }

    /**
     * This follows ANY default-network change (Wi-Fi to cellular, or the network disappearing and coming
     * back), and tells the Rust side (see `P2PLib.notifyNetworkChanged` and session.rs `reconnect_all_known_now`). Every libp2p connection set up over the OLD
     * network is now an invalid socket on the new interface (the local IP changed). Instead of waiting for the periodic scan (up to 15 s) or a ping (up to about
     * 30 s, interval plus timeout) to notice, a full reconnect turn is triggered at once.
     * `onCapabilitiesChanged` is deliberately NOT listened to: it fires much more often (for example when signal strength metadata changes), and a full reconnect
     * turn each time would waste battery. `onAvailable` and `onLost` (when the default network changes or disappears completely) are reliable enough and a rarer signal.
     */
    private fun observeNetworkChangesForReconnect() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                notifyNetworkChangedInBackground()
            }
            override fun onLost(network: Network) {
                                // Reconnect ONLY when a new default network arrives (`onAvailable`). Dial and Tor attempts made while there is no network fail at once with
                                // 'Network is unreachable', which breaks the arti guard and circuit state and delays recovery on the new network.
            }
        }
        defaultNetworkCallback = callback
        try {
            cm.registerDefaultNetworkCallback(callback)
        } catch (e: Exception) {
                        // If registration fails (for example on a very old or unusual device), it passes silently. The periodic `reconnect_sweep` and `ping` still reach
                        // the same result, only more slowly.
        }
    }

    /** See `P2PLib.setMeteredNetwork`: on a metered network Tor channel padding is reduced, since padding keeps a cellular radio awake. */
    private fun applyMeteredToTor() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            P2PLib.setMeteredNetwork(cm.isActiveNetworkMetered)
        } catch (e: Exception) {
            Log.w(TAG, "Metered state not applied: ${e.message}")
        }
    }

    /** Network change events are queued on ONE thread. Each event used to start its own thread, and all of them waited on the core lock, so they piled up
     *  when the device flipped between WiFi and cellular. */
    private val networkChangeExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()

    /** If a turn is already queued, another is not added: Android reports one network change through several callbacks, and one turn is enough to reconnect all peers. */
    @Volatile private var networkChangePending = false

    /** Runs the JNI call off the main thread. `ConnectivityManager` callbacks are usually called on the main thread, and `notifyNetworkChanged` (which can start
     *  a dial turn) must not block it. */
    private fun notifyNetworkChangedInBackground() {
        if (networkChangePending) return
        networkChangePending = true
        networkChangeExecutor.execute {
            try {
                                // Debounce: wait for the events to settle, then run ONE reconnect turn.
                Thread.sleep(NETWORK_CHANGE_DEBOUNCE_MS)
            } catch (e: InterruptedException) {
                networkChangePending = false
                return@execute
            }
            networkChangePending = false
            applyMeteredToTor()
            try {
                P2PLib.notifyNetworkChanged()
            } catch (e: Exception) {
                // yoksay — periyodik sweep zaten yedek.
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.channel_service_name),
            NotificationManager.IMPORTANCE_LOW
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }
}

/** Target of the Doze wake alarm; not exported. */
class DozeWakeReceiver : android.content.BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = P2PService.onDozeAlarm()
}
