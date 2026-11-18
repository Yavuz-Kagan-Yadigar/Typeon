package com.p2p.messenger.ui

import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray

/**
 * List of messages opened from Settings that have not been acknowledged by the other side yet. Unconfirmed messages are retried
 * automatically with a fresh ratchet step, up to TEXT_RETRY_GIVE_UP_MS (2 days). See lib.rs `awaiting_confirmation` and types.rs
 * `regen_content`. Each row shows the target (contact or group), a text preview, the last retry time, and a "Cancel" button
 * (see network.rs `cancel_pending_message`).
 */
class PendingMessagesActivity : AppCompatActivity() {

    private lateinit var recycler: RecyclerView
    private lateinit var txtEmpty: TextView
    private lateinit var adapter: PendingMessagesAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pending_messages)
        supportActionBar?.title = getString(R.string.title_pending_messages)

        recycler = findViewById(R.id.recyclerPendingMessages)
        txtEmpty = findViewById(R.id.txtNoPendingMessages)
        adapter = PendingMessagesAdapter(
            mutableListOf(),
            onCancel = { item -> cancelPending(item) },
            onRetry = { item -> retryPending(item) }
        )
        recycler.layoutManager = LinearLayoutManager(this)
        recycler.adapter = adapter

        loadPendingMessages()
    }

    /** A message acknowledged or given up while this screen is open. */
    private val listener: (String) -> Unit = { json ->
        if (json.contains("\"type\":\"ack\"") || json.contains("\"type\":\"status\"")) {
            // A burst of acks reloads once: coalesce on the main thread.
            runOnUiThread {
                if (!reloadQueued) {
                    reloadQueued = true
                    reloadHandler.postDelayed({ reloadQueued = false; loadPendingMessages() }, 500)
                }
            }
        }
    }
    private var reloadQueued = false
    private val reloadHandler = android.os.Handler(android.os.Looper.getMainLooper())

    override fun onDestroy() {
        reloadHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    override fun onPause() {
        super.onPause()
        com.p2p.messenger.service.P2PService.removeMessageListener(listener)
    }

    override fun onResume() {
        super.onResume()
        com.p2p.messenger.service.P2PService.addMessageListener(listener)
        // This screen is subscribed to a live event stream. The `listener` reloads the list on an ack or status event, so a row does not go
        // stale when a message is confirmed while this screen is open. See `retry_unconfirmed_messages`. The P2PService poll loop keeps running
        // in the background. Refreshing again on every return to the foreground is simple and enough.
        loadPendingMessages()
    }

    private fun loadPendingMessages() {
        lifecycleScope.launch {
            val items = withContext(Dispatchers.IO) { fetchPendingMessages() }
            adapter.submitList(items)
            txtEmpty.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    /**
     * Turns `peer_device_fingerprint` / `group_id` (see types.rs `PendingMessageSummary`) into a readable name: the core's
     * `contact_name` for a 1:1 row, `listGroups` for a group row.
     */
    private fun fetchPendingMessages(): List<PendingMessagesAdapter.Item> {
        val pendingJson = try {
            JSONArray(P2PLib.listPendingMessages())
        } catch (e: Exception) {
            return emptyList()
        }
        val groupsById = mutableMapOf<String, String>()
        try {
            val groups = JSONArray(P2PLib.listGroups())
            for (i in 0 until groups.length()) {
                val g = groups.getJSONObject(i)
                groupsById[g.optString("group_id")] = g.optString("name")
            }
        } catch (e: Exception) {
        // Name not resolved, so a shortened group_id is shown.
        }

        val result = mutableListOf<PendingMessagesAdapter.Item>()
        for (i in 0 until pendingJson.length()) {
            val obj = pendingJson.optJSONObject(i) ?: continue
            val groupId = if (obj.isNull("group_id")) null else obj.optString("group_id").ifEmpty { null }
            val fp = obj.optString("peer_device_fingerprint")
            val targetName = if (groupId != null) {
                groupsById[groupId] ?: groupId.take(8)
            } else {
                obj.optString("contact_name").ifEmpty { fp.take(8) }
            }
            result.add(
                PendingMessagesAdapter.Item(
                    messageId = obj.optString("message_id"),
                    targetName = targetName,
                    deviceName = obj.optString("device_name"),
                    text = com.p2p.messenger.util.Quote.plain(obj.optString("text")),
                    lastAttemptAtMs = obj.optLong("last_attempt_at")
                )
            )
        }
        // The most recently tried one comes first. That answers "which one is still stuck" most directly.
        result.sortByDescending { it.lastAttemptAtMs }
        return result
    }

    private fun cancelPending(item: PendingMessagesAdapter.Item) {
        lifecycleScope.launch {
            val ok = withContext(Dispatchers.IO) {
                try {
                    P2PLib.cancelPendingMessage(item.messageId)
                } catch (e: Exception) {
                    false
                }
            }
            if (ok) {
                adapter.removeById(item.messageId)
                Toast.makeText(this@PendingMessagesActivity, R.string.msg_pending_message_cancelled, Toast.LENGTH_SHORT).show()
                if (adapter.itemCount == 0) txtEmpty.visibility = View.VISIBLE
            }
        }
    }

    /**
     * The manual "Retry now" button in the pending list. See network.rs `retry_pending_message_now`. It only moves this message's next retry
     * time to NOW. The actual send attempt happens on the next `poll_events` turn, in the background loop that already runs every second. So no
     * separate network I/O happens here, which is good for the battery. The row is NOT removed (unlike Cancel): the message is still pending,
     * only its retry was moved up. On the next `onResume` or refresh, the row will show either as confirmed (gone from the list) or still pending
     * (with the current "last tried" time).
     */
    private fun retryPending(item: PendingMessagesAdapter.Item) {
        lifecycleScope.launch {
            val ok = withContext(Dispatchers.IO) {
                try {
                    P2PLib.retryPendingMessageNow(item.messageId)
                } catch (e: Exception) {
                    false
                }
            }
            if (ok) {
                Toast.makeText(this@PendingMessagesActivity, R.string.msg_pending_message_retrying, Toast.LENGTH_SHORT).show()
            }
        }
    }
}
