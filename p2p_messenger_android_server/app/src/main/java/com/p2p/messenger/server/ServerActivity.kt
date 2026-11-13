package com.p2p.messenger.server

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import org.json.JSONArray
import org.json.JSONObject

/**
 * The server's single screen: on/off, addresses, the join QR, and the registered devices.
 *
 * Deliberately minimal. This is not a messaging app, it is an infrastructure tool. Everything it shows is something the operator must decide:
 * whether the server is up, what its address is, whom I invited, and whom I am removing.
 */
class ServerActivity : AppCompatActivity() {

    private val handler = Handler(Looper.getMainLooper())
    private lateinit var statusText: TextView
    private lateinit var addressText: TextView
    private lateinit var statsText: TextView
    private lateinit var devicesContainer: LinearLayout
    private lateinit var qrImage: ImageView
    private lateinit var inviteCodeText: TextView
    @Volatile
    private var lastInvite: String? = null

    /** JNI calls hit SQLite and the filesystem: never on the main thread. */
    private val io = java.util.concurrent.Executors.newSingleThreadExecutor()
    private var refreshing = false
    private var tick = 0
    @Volatile
    private var lastDisk = 0L

    /**
     * The raw JSON of the last device list drawn, and the last status and statistics text written. The refresh loop runs every 2 seconds. Tearing down and
     * rebuilding rows when nothing changed made the ScrollView lose focus and jump back to the top of the list (the screen scrolled up by itself).
     */
    private var lastDevicesJson: String? = null
    private var lastStatus: String? = null
    private var lastAddresses: String? = null
    private var lastStats: String? = null

    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshStatus()
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The join code is a bearer token for unlimited enrolments. Keep the QR out of the recents thumbnail and screen recordings. Debuggable builds
        // stay capturable, for adb screenshots.
        if ((applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContentView(R.layout.activity_server)
        // Android 13+: without this the service notification, the only place
        // a start error is shown after a boot, is suppressed.
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 0)
        }

        statusText = findViewById(R.id.status_text)
        addressText = findViewById(R.id.address_text)
        statsText = findViewById(R.id.stats_text)
        devicesContainer = findViewById(R.id.devices_container)
        qrImage = findViewById(R.id.invite_qr)
        inviteCodeText = findViewById(R.id.invite_code)

        val enableSwitch = findViewById<SwitchMaterial>(R.id.switch_enabled)
        enableSwitch.isChecked = ServerService.isEnabled(this)
        enableSwitch.setOnCheckedChangeListener { _, checked ->
            ServerService.setEnabled(this, checked)
            if (checked) {
                startServerService()
                // Without the exemption a background restart of the service
                // is refused on Android 12+ (see ServerService.onStartCommand).
                requestIgnoreBatteryOptimizations(quiet = true)
            } else {
                // The server really stops now. `ServerService.onDestroy` calls `ServerLib.stopServer()`, which ends the Rust loop. The "restart needed" warning is gone.
                stopService(Intent(this, ServerService::class.java))
            }
        }

        val nodeSwitch = findViewById<SwitchMaterial>(R.id.switch_node)
        nodeSwitch.isChecked = ServerService.isNodeMode(this)
        nodeSwitch.setOnCheckedChangeListener { _, checked ->
            ServerService.setNodeMode(this, checked)
            // Node mode can now really be applied. Stopping and starting the server is enough. The process does not need to be killed.
            if (ServerService.isEnabled(this)) {
                restartServerService()
            }
        }

        findViewById<Button>(R.id.btn_new_invite).setOnClickListener { confirmRotateJoinCode() }
        findViewById<Button>(R.id.btn_copy_invite).setOnClickListener { copyInvite() }
        findViewById<Button>(R.id.btn_pin).setOnClickListener { ServerLock.showSettings(this) }
        // Screen off locks at once; leaving the app locks after a short grace (ServerLock).
        androidx.core.content.ContextCompat.registerReceiver(
            this, screenOff, android.content.IntentFilter(Intent.ACTION_SCREEN_OFF),
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
        )
        findViewById<Button>(R.id.btn_battery).setOnClickListener { requestIgnoreBatteryOptimizations() }
        findViewById<Button>(R.id.btn_storage).setOnClickListener { chooseStorage() }
        refreshStorageLabel()

        if (ServerService.isEnabled(this)) {
            startServerService()
        }
    }

    private val screenOff = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) = ServerLock.lockNow()
    }
    private var lockDialog: AlertDialog? = null

    /** Hides the whole screen behind the PIN prompt while locked. */
    private fun guardLock() {
        val content = findViewById<android.view.View>(android.R.id.content)
        if (!ServerLock.isLocked(this)) {
            content.visibility = android.view.View.VISIBLE
            return
        }
        content.visibility = android.view.View.INVISIBLE
        if (lockDialog?.isShowing == true) return
        lockDialog = ServerLock.showUnlock(this) {
            content.visibility = android.view.View.VISIBLE
            // The dialog is gone now, so one poll repaints the hidden screen.
            refreshStatus()
        }
    }

    override fun onResume() {
        super.onResume()
        guardLock()
        handler.post(refreshRunnable)
    }

    override fun onStop() {
        ServerLock.noteLeft()
        super.onStop()
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(refreshRunnable)
    }

    override fun onDestroy() {
        // The delayed restart of `restartServerService` must not fire into a
        // destroyed activity.
        handler.removeCallbacksAndMessages(null)
        try { unregisterReceiver(screenOff) } catch (e: IllegalArgumentException) { }
        lockDialog?.dismiss()
        io.shutdown()
        super.onDestroy()
    }

    /**
     * Runs [work] off the main thread and hands the result to [done] on it.
     * `Throwable`: a library that failed to load is an Error, not an Exception.
     */
    private fun <T> bg(work: () -> T, onError: (Throwable) -> T, done: (T) -> Unit) {
        try {
            io.execute {
                val result = try { work() } catch (e: Throwable) { onError(e) }
                runOnUiThread { if (!isDestroyed) done(result) }
            }
        } catch (e: java.util.concurrent.RejectedExecutionException) {
        // Activity destroyed.
        }
    }

    /**
     * Stops and restarts the server. Configuration changes (node mode, blob directory, disk budget) are read only at `startServer` time, and that call is a
     * no-op while a core is already running.
     */
    private fun restartServerService() {
        stopService(Intent(this, ServerService::class.java))
        handler.postDelayed({ startServerService() }, 600)
    }

    private fun startServerService() {
        try {
            startForegroundService(Intent(this, ServerService::class.java))
        } catch (e: Exception) {
            // Android 12+ refuses this while the app is in the background
            // (the end of a long storage move, the delayed restart).
            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    /** One poll: status, device list and (every fifth time) disk usage. */
    private fun refreshStatus() {
        // PIN lock covers the screen: no polling behind it.
        if (lockDialog?.isShowing == true) return
        if (refreshing) return
        refreshing = true
        val withDisk = tick++ % 5 == 0
        bg({
            val status = JSONObject(ServerLib.serverStatus())
            val running = status.optBoolean("running")
            // Stats every file in the data and blob dirs: not every 2 s.
            if (running && withDisk) lastDisk = ServerLib.diskUsage().toLongOrNull() ?: 0L
            status to (if (running) ServerLib.listDevices() else "[]")
        }, { JSONObject() to "[]" }) { (status, devices) ->
            refreshing = false
            render(status, devices)
        }
    }

    private fun render(json: JSONObject, devices: String) {
        if (!json.optBoolean("running")) {
            // The native side reports running only once init has finished
            // (20+ s): "Stopped" there invited a second toggle.
            val state = when {
                !ServerService.isEnabled(this) -> getString(R.string.state_stopped)
                else -> ServerService.lastError?.let { serverErrorText(this, it) } ?: getString(R.string.notif_starting)
            }
            lastStatus = setTextIfChanged(statusText, state, lastStatus)
            lastAddresses = setTextIfChanged(addressText, "", lastAddresses)
            lastStats = setTextIfChanged(statsText, "", lastStats)
            renderDevices("[]")
            return
        }

        val tor = json.optString("tor")
        lastStatus = setTextIfChanged(statusText, getString(R.string.state_running_fmt, tor), lastStatus)

        val addrs = json.optJSONArray("addresses") ?: JSONArray()
        val addressLabel = if (addrs.length() == 0) {
            // With Tor on, the onion address waits for arti's bootstrap. The first start can take 30 to 60 seconds, and until then no invite code can be made.
            getString(R.string.state_no_address)
        } else {
            (0 until addrs.length()).joinToString("\n") { addrs.optString(it) }
        }
        val addressesChanged = addressLabel != lastAddresses
        lastAddresses = setTextIfChanged(addressText, addressLabel, lastAddresses)

        // The code appears by itself as soon as the address is ready. It is read only if it has not been shown yet, or if the address changed (the code
        // contains the addresses, and an old QR leads to the wrong address). `lastInvite` is cleared when the read fails, so the next poll tries again.
        if (addrs.length() > 0 && (lastInvite == null || addressesChanged)) showJoinCode()

        lastStats = setTextIfChanged(
            statsText,
            getString(
                R.string.stats_fmt,
                json.optInt("devices"),
                json.optLong("deposits"),
                json.optLong("fetches"),
                json.optLong("chunks_served"),
                formatBytes(lastDisk)
            ),
            lastStats
        )

        renderDevices(devices)
    }

    /**
     * Writes the text only if it really changed.
     *
     * `TextView.setText` triggers a new measure and layout pass even with the same text. Re-laying out the whole screen on every poll moved the scroll position.
     * The comparison uses a separate field, not `TextView.getText`. In selectable texts (`textIsSelectable`), getText can fail to equal the String we wrote,
     * because of spans.
     */
    private fun setTextIfChanged(view: TextView, value: String, last: String?): String {
        if (value != last) view.text = value
        return value
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1_073_741_824 -> String.format("%.1f GB", bytes / 1_073_741_824.0)
        bytes >= 1_048_576 -> String.format("%.1f MB", bytes / 1_048_576.0)
        bytes >= 1024 -> String.format("%.1f KB", bytes / 1024.0)
        else -> "$bytes B"
    }

    private fun renderDevices(raw: String) {
        // If the list is the same, do nothing. `removeAllViews` followed by re-adding destroys the row button that has focus. The ScrollView then moves focus to
        // the first focusable view above and scrolls the screen.
        if (raw == lastDevicesJson) return
        lastDevicesJson = raw
        val arr = try {
            JSONArray(raw)
        } catch (e: Exception) {
            JSONArray()
        }
        devicesContainer.removeAllViews()
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val id = obj.optString("enrollment_id")
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, 8, 0, 8)
            }
            row.addView(TextView(this).apply {
                // The enrolment identifier is generated from a fresh key, unrelated to the device's real identity (see the Rust `ServerRequest::Enroll`).
                // The operator cannot learn who is who from it. It can only revoke.
                text = getString(
                    R.string.device_row_fmt,
                    id.take(12),
                    formatBytes(obj.optLong("bytes_mail") + obj.optLong("bytes_archive") + obj.optLong("bytes_blob"))
                )
                textSize = 13f
                if (obj.optBoolean("revoked")) alpha = 0.4f
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })
            val blocked = obj.optBoolean("blocked")
            if (!obj.optBoolean("revoked")) {
                row.addView(Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                    setText(R.string.action_revoke)
                    setOnClickListener { confirmRevoke(id) }
                })
            }
            // The user's decision: block sits NEXT TO revoke. Revoke lets the device come back with a fresh invite. Block does not.
            row.addView(Button(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                setText(if (blocked) R.string.action_unblock else R.string.action_block)
                setOnClickListener { if (blocked) unblock(id) else confirmBlock(id) }
            })
            devicesContainer.addView(row)
        }
    }

    /** Runs one device action off the main thread, then redraws the list. */
    private fun deviceAction(call: () -> String) {
        bg(call, { "Error: ${it.message}" }) { res ->
            if (res.startsWith("Error:")) {
                Toast.makeText(this, serverErrorText(this, res), Toast.LENGTH_LONG).show()
            }
            lastDevicesJson = null
            // Block and revoke rotate the public join code: show the new one
            // on the next poll, not the dead one.
            lastInvite = null
            refreshStatus()
        }
    }

    private fun confirmRevoke(enrollmentId: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.dlg_revoke_title)
            .setMessage(R.string.dlg_revoke_body)
            .setPositiveButton(R.string.action_revoke) { _, _ -> deviceAction { ServerLib.revokeDevice(enrollmentId) } }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Blocking is different from revoking. It is put on the enrolment key, so the device cannot come back even with a fresh invite. That is why it has its own
     * confirmation text.
     */
    private fun confirmBlock(enrollmentId: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.dlg_block_title)
            .setMessage(R.string.dlg_block_body)
            .setPositiveButton(R.string.action_block) { _, _ -> deviceAction { ServerLib.blockDevice(enrollmentId) } }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun unblock(enrollmentId: String) = deviceAction { ServerLib.unblockDevice(enrollmentId) }

    /**
     * Shows the permanent join code (see `ServerLib.joinCode`).
     *
     * The code is redrawn only if it CHANGED. Reading and QR encoding happen off the main thread.
     */
    private fun showJoinCode(rotate: Boolean = false) {
        bg<Pair<String, Bitmap?>>({
            val code = ServerLib.joinCode(rotate)
            code to (if (code.startsWith("Error:") || code == lastInvite) null else encodeQr(code, 900, 900))
        }, { "Error: ${it.message}" to null }) { (code, qr) ->
            if (code.startsWith("Error:")) {
                // While the address is not there yet (Tor is starting), the error is NORMAL. We say so only when the user asks to rotate the code.
                if (rotate) Toast.makeText(this, serverErrorText(this, code), Toast.LENGTH_LONG).show()
                // Retry on the next poll: a failed read on the poll where the
                // address changed otherwise left the old QR up for good.
                lastInvite = null
            } else if (qr != null) {
                lastInvite = code
                qrImage.setImageBitmap(qr)
                inviteCodeText.text = code
            }
        }
    }

    /**
     * Rotating the code is DESTRUCTIVE. The published QR and link die at once, and the code in everyone's hands who has not joined yet stops working. So a
     * confirmation is asked. Unlike the old "make a new invite" button, there is no way back here.
     */
    private fun confirmRotateJoinCode() {
        AlertDialog.Builder(this)
            .setTitle(R.string.action_new_invite)
            .setMessage(R.string.confirm_rotate_join_code)
            .setPositiveButton(R.string.action_new_invite) { _, _ -> showJoinCode(rotate = true) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun copyInvite() {
        val code = lastInvite
        if (code == null) {
            showJoinCode()
            Toast.makeText(this, R.string.msg_no_invite_yet, Toast.LENGTH_SHORT).show()
            return
        }
        // The application's manager: the delayed clear below outlives this
        // activity and must not hold it.
        val clipboard = applicationContext.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val clip = android.content.ClipData.newPlainText("Typeon server invite", code)
        // ClipDescription.EXTRA_IS_SENSITIVE (API 33): no clipboard preview.
        clip.description.extras = android.os.PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
        // The clip cannot be read back from the background or a locked screen
        // (API 29+), so "still ours" is tracked by listening for the next
        // change; the first event is our own set.
        var ownEventPending = true
        var foreignCopy = false
        val listener = android.content.ClipboardManager.OnPrimaryClipChangedListener {
            if (ownEventPending) ownEventPending = false else foreignCopy = true
        }
        clipboard.addPrimaryClipChangedListener(listener)
        clipboard.setPrimaryClip(clip)
        // The join code is a permanent bearer token: drop it from the
        // clipboard after a minute, if nothing else was copied since.
        Handler(Looper.getMainLooper()).postDelayed({
            try {
                clipboard.removePrimaryClipChangedListener(listener)
                if (!foreignCopy) {
                    if (Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip()
                    else clipboard.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
                }
            } catch (_: Exception) {}
        }, 60_000L)
        Toast.makeText(this, R.string.msg_invite_copied, Toast.LENGTH_SHORT).show()
    }

    /**
     * Turns the invite code into a QR.
     *
     * Unlike the client's QRs, there is no `QrBinaryCodec` here. The invite code is plain ASCII text (`typeon-server:...#...`), not CBOR. The server app also
     * shows the same code as copyable text, so this is the single canonical format.
     */
    private fun encodeQr(text: String, width: Int, height: Int): Bitmap {
        val hints = mapOf(EncodeHintType.CHARACTER_SET to "UTF-8")
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, width, height, hints)
        val pixels = IntArray(width * height) { if (matrix[it % width, it / width]) Color.BLACK else Color.WHITE }
        return Bitmap.createBitmap(pixels, width, height, Bitmap.Config.RGB_565)
    }

    /** Shows the selected location and its free space. */
    private fun refreshStorageLabel() {
        val dir = ServerService.blobDir(this)
        val free = try {
            android.os.StatFs(dir.absolutePath).availableBytes
        } catch (e: Throwable) {
            0L
        }
        findViewById<TextView>(R.id.txt_storage_current).text =
            getString(R.string.lbl_storage_desc) + "\n" + dir.absolutePath +
                " — " + (free / (1024 * 1024)) + " MB " + getString(R.string.lbl_free_suffix)
    }

    /**
     * Lets the user pick the blob directory, and moves the BLOBS if needed.
     *
     * An earlier comment here said that the SQLite database, the libp2p identity and the Tor onion state also live in that directory, so moving them was
     * required. That was WRONG. `chooseStorage` moves only the `blobs` directory. `data_dir` is always `context.filesDir` (see `ServerService.dataDir` and
     * `jni.rs`, where only `blob_dir` can be overridden). So the peer id and the .onion address are not affected by this operation at all.
     */
    private fun chooseStorage() {
        val vols = ServerService.storageVolumes(this)
        val current = ServerService.blobDir(this)
        val labels = vols.map { v ->
            val free = try { android.os.StatFs(v.absolutePath).availableBytes } catch (e: Throwable) { 0L }
            // Guessing the label from the path gave wrong results. `getExternalFilesDirs` also returns the internal unit's `Android/data` directory, and that
            // looked like an "SD card". With both showing the same free space, the user could not tell which one to pick. `isExternalStorageRemovable` is the
            // only correct API that tells a removable unit apart.
            val name = when {
                v.absolutePath == filesDir.absolutePath -> getString(R.string.lbl_internal)
                isRemovable(v) -> getString(R.string.lbl_sdcard)
                else -> getString(R.string.lbl_external)
            }
            val mark = if (java.io.File(v, "blobs").absolutePath == current.absolutePath) " ✓" else ""
            "$name$mark\n${free / (1024 * 1024)} MB " + getString(R.string.lbl_free_suffix)
        }.toTypedArray()

        AlertDialog.Builder(this)
            .setTitle(R.string.dlg_storage_title)
            .setItems(labels) { _, which ->
                val target = java.io.File(vols[which], "blobs")
                if (target.absolutePath == current.absolutePath) {
                    Toast.makeText(this, R.string.msg_storage_same, Toast.LENGTH_SHORT).show()
                    return@setItems
                }
                moveStorage(current, target)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }


    private fun isRemovable(dir: java.io.File): Boolean = try {
        android.os.Environment.isExternalStorageRemovable(dir)
    } catch (e: Throwable) {
        false
    }

    private fun moveStorage(from: java.io.File, to: java.io.File) {
        // One move at a time: after a rotation the progress dialog is gone
        // and the storage button could start a second one on the same tree.
        if (!ServerService.moving.compareAndSet(false, true)) {
            Toast.makeText(this, R.string.msg_storage_busy, Toast.LENGTH_SHORT).show()
            return
        }
        val app = applicationContext
        val progress = AlertDialog.Builder(this)
            .setMessage(R.string.dlg_storage_moving)
            .setCancelable(false)
            .show()
        // The service is NOT stopped, only the native core: it stays in the
        // foreground through the copy (the process is not killable half-way)
        // and can bring the core back with the app in the background.
        // files this move created; a failure removes only those, not what was in the target before.
        val created = java.util.concurrent.CopyOnWriteArrayList<java.io.File>()
        Thread {
            val error = try {
                // Queued behind a start that is still initialising, and back
                // only once the native loop has ended: nothing writes to the
                // blob files while they are copied and deleted.
                val stopped = ServerService.core.submit(java.util.concurrent.Callable { ServerLib.stopServer() }).get()
                if (stopped.startsWith("Error:")) throw java.io.IOException(stopped)
                val needed = from.listFiles()?.sumOf { it.length() } ?: 0L
                if (android.os.StatFs(to.parentFile!!.absolutePath).availableBytes < needed) {
                    throw java.io.IOException(getString(R.string.err_storage_no_space))
                }
                copyTree(from, to, created)
                // Saved HERE, between copy and delete, and not in the UI
                // callback: if the activity is gone by then, the setting would
                // still point at the directory that was just emptied.
                ServerService.setBlobDir(app, to)
                deleteTree(from, keepRoot = true)
                null
            } catch (e: Throwable) {
                // Do not leave a partial copy filling the target.
                if (ServerService.blobDir(app).absolutePath != to.absolutePath) created.reversed().forEach { it.delete() }
                e.message ?: getString(R.string.err_unknown)
            } finally {
                ServerService.moving.set(false)
            }
            ServerService.restartCore()
            runOnUiThread {
                if (isDestroyed) return@runOnUiThread
                progress.dismiss()
                refreshStorageLabel()
                val message = if (error == null) getString(R.string.msg_storage_moved)
                else getString(R.string.msg_storage_failed, error)
                Toast.makeText(this, message, Toast.LENGTH_LONG).show()
            }
        }.start()
    }

    private fun copyTree(from: java.io.File, to: java.io.File, created: MutableList<java.io.File>) {
        if (!to.exists() && !to.mkdirs()) throw java.io.IOException(getString(R.string.err_storage_mkdir))
        from.listFiles()?.forEach { child ->
            val dest = java.io.File(to, child.name)
            if (child.isDirectory) {
                copyTree(child, dest, created)
            } else {
                if (!dest.exists()) created.add(dest)
                java.io.FileOutputStream(dest).use { output ->
                    child.inputStream().use { input -> input.copyTo(output, 1 shl 16) }
                    // On disk before the original is deleted.
                    output.fd.sync()
                }
            }
        }
    }

    private fun deleteTree(dir: java.io.File, keepRoot: Boolean) {
        dir.listFiles()?.forEach { child ->
            if (child.isDirectory) deleteTree(child, keepRoot = false) else child.delete()
        }
        if (!keepRoot) dir.delete()
    }

    /**
     * Battery optimisation exemption. A server must always be on by definition, and Android's sleep restrictions undermine that directly. [quiet]: no toast
     * when the app is already exempt.
     */
    private fun requestIgnoreBatteryOptimizations(quiet: Boolean = false) {
        val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        if (pm.isIgnoringBatteryOptimizations(packageName)) {
            if (!quiet) Toast.makeText(this, R.string.msg_battery_already, Toast.LENGTH_SHORT).show()
            return
        }
        try {
            startActivity(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    .setData(Uri.parse("package:$packageName"))
            )
        } catch (e: Exception) {
            // On some ROMs this intent does not exist, and the user does it by hand in the settings.
            Toast.makeText(this, R.string.msg_battery_manual, Toast.LENGTH_LONG).show()
        }
    }
}
