package com.p2p.messenger.util

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.ui.ChatActivity
import com.p2p.messenger.ui.GroupChatActivity
import org.json.JSONArray

/**
 * Local notifications for incoming messages. No Google Play Services or FCM is used, and none is needed:
 * this is a privacy-focused P2P app. P2PService already polls the network every second as an always-running
 * foreground service (see P2PService.pollRunnable). So no push notification has to be imitated. When a message
 * really arrives, the service's own loop shows the notification from here. Reliability depends on how often
 * and how regularly that service runs, not on a third-party push system. The foreground service is START_STICKY
 * and runs every second.
 */
object NotificationHelper {
    const val MESSAGE_CHANNEL_ID = "P2PMessagesChannel"
    /** Group @mentions of me, so the user can give them their own sound. */
    const val MENTION_CHANNEL_ID = "P2PMentionsChannel"

    fun createChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(
            MESSAGE_CHANNEL_ID,
            context.getString(R.string.channel_messages_name),
            NotificationManager.IMPORTANCE_HIGH
        ))
        manager.createNotificationChannel(NotificationChannel(
            MENTION_CHANNEL_ID,
            context.getString(R.string.channel_mentions_name),
            NotificationManager.IMPORTANCE_HIGH
        ))
    }

    /** The message that each chat's single slot shows now. See `clearIfShowing`. */
    private val shownMessageId = java.util.concurrent.ConcurrentHashMap<Int, String>()

    /**
     * Notification slots of security alerts. `clearAll` does NOT remove them. For "new device", "my own account
     * was revoked" and "account deleted" alerts, the notification bar is the only trace. They used to be cleared
     * together with the message notifications, so the user could lose the alert before reading it.
     */
    private val securityAlertIds = java.util.concurrent.ConcurrentHashMap.newKeySet<Int>()

    /** `showDeviceAlertNotification` and `showDeviceRevokedNotification` use fixed slots, independent of identity. */
    private val DEVICE_ALERT_NOTIFICATION_ID = "device_alert".hashCode()
    private val SELF_REVOKED_NOTIFICATION_ID = "self_revoked".hashCode()

    /** A delete removes the chat's notification only when the slot shows that message, or when the slot's content is
     *  unknown. Deleting an old, read message used to remove the notification of the unread ones. */
    fun clearIfShowing(context: Context, conversationId: String, messageId: String) {
        for (id in slotIds(conversationId)) {
            val shown = shownMessageId[id]
            if (shown != null && shown != messageId) continue
            shownMessageId.remove(id)
            context.getSystemService(NotificationManager::class.java).cancel(id)
        }
    }

    /** A group has two slots: its messages and its @mentions (`"mention:$groupId"`). So a plain message does not
     *  replace a mention alert. */
    private fun slotIds(conversationId: String): List<Int> =
        if (conversationId.startsWith("group:")) {
            listOf(conversationId.hashCode(), ("mention:" + conversationId.removePrefix("group:")).hashCode())
        } else {
            listOf(conversationId.hashCode())
        }

    fun showMessageNotification(context: Context, peerDeviceFingerprint: String, text: String, messageId: String = "", alert: Boolean = true) {
        val displayName = resolveContactNameByFingerprint(peerDeviceFingerprint) ?: peerDeviceFingerprint.take(8)
        val intent = Intent(context, ChatActivity::class.java).apply {
            putExtra(ChatActivity.EXTRA_PEER_DEVICE_FINGERPRINT, peerDeviceFingerprint)
            putExtra(ChatActivity.EXTRA_PEER_DISPLAY_NAME, displayName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        // The notification title is always the app name ("Typeon"), not the contact or group name. Who sent it, and from
        // where, is in the body, as "{name}: message".
        //
        // With the "show messages in notifications" switch off (see NotificationPrefs), the body carries ONLY the sender.
        // The message text is never written.
        val body = if (NotificationPrefs.showMessageText(context)) "$displayName: $text" else context.getString(R.string.notif_new_message)
        if (messageId.isNotEmpty()) shownMessageId[peerDeviceFingerprint.hashCode()] = messageId
        show(context, peerDeviceFingerprint.hashCode(), context.getString(R.string.app_name), body, intent, alert)
    }

    /** Shown once, when the primary device has revoked this device. The app data is deleted and the app returns to
     *  onboarding. This one-time notification explains WHY. Tapping it opens MainActivity (onboarding). */
    fun showDeviceRevokedNotification(context: Context) {
        val intent = Intent(context, com.p2p.messenger.MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        securityAlertIds.add(SELF_REVOKED_NOTIFICATION_ID)
        show(
            context, SELF_REVOKED_NOTIFICATION_ID,
            context.getString(R.string.app_name),
            context.getString(R.string.device_unlinked_notification),
            intent
        )
    }

    /**
     * "New device" alerts are no longer silent.
     *
     * Before, the alert was only written to the core's pending list. The UI asked for it once a second, and only while
     * the main screen was in the foreground. So if the user was on another screen, or the app was in the background, the
     * alert was never seen, and every message from that person was dropped quietly. Now the alert is also a notification.
     * Tapping it opens the accept, reject or block dialog.
     */
    fun showDeviceAlertNotification(context: Context, contactName: String, shortCode: String) {
        val intent = Intent(context, com.p2p.messenger.MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        securityAlertIds.add(DEVICE_ALERT_NOTIFICATION_ID)
        show(
            context, DEVICE_ALERT_NOTIFICATION_ID,
            context.getString(R.string.title_security_warning_dialog),
            // No contact name while the message text is hidden: the lock screen may show the body. The app shows the name
            // after unlock.
            if (NotificationPrefs.showMessageText(context)) context.getString(R.string.notif_new_device_warning, contactName, shortCode)
            else context.getString(R.string.msg_security_warning),
            intent
        )
    }

    /** A contact deleted their account. A one-time notification with the contact's name. */
    fun showAccountDeletedNotification(context: Context, peerDeviceFingerprint: String, displayName: String) {
        val name = displayName.ifBlank { resolveContactNameByFingerprint(peerDeviceFingerprint) ?: peerDeviceFingerprint.take(8) }
        val intent = Intent(context, ChatActivity::class.java).apply {
            putExtra(ChatActivity.EXTRA_PEER_DEVICE_FINGERPRINT, peerDeviceFingerprint)
            putExtra(ChatActivity.EXTRA_PEER_DISPLAY_NAME, name)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val id = ("deleted:$peerDeviceFingerprint").hashCode()
        securityAlertIds.add(id)
        show(context, id, context.getString(R.string.app_name),
            if (NotificationPrefs.showMessageText(context)) context.getString(R.string.msg_contact_deleted_account, name)
            else context.getString(R.string.notif_contact_deleted_account_hidden), intent)
    }

    fun showGroupMessageNotification(context: Context, groupId: String, senderIdentityId: String, text: String, messageId: String = "", mention: Boolean = false) {
        val groupName = resolveGroupName(groupId) ?: groupId.take(8)
        val senderName = resolveContactNameByIdentity(senderIdentityId) ?: senderIdentityId.take(8)
        val intent = Intent(context, GroupChatActivity::class.java).apply {
            putExtra(GroupChatActivity.EXTRA_GROUP_ID, groupId)
            putExtra(GroupChatActivity.EXTRA_GROUP_NAME, groupName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        // See the `showMessageNotification` note. The title is always the app name, and the body carries the sender
        // (with the group name in brackets). With "show messages" off, the sender and group are visible but the TEXT is not.
        val body = if (NotificationPrefs.showMessageText(context)) {
            "$senderName ($groupName): $text"
        } else {
            context.getString(R.string.notif_new_message)
        }
        if (mention) {
            // Its own slot (see `slotIds`), so a later plain message does not replace it. Opening or reading the group clears
            // both. Hidden text hides who and where too, like the plain group notification.
            val id = ("mention:$groupId").hashCode()
            if (messageId.isNotEmpty()) shownMessageId[id] = messageId
            val shown = NotificationPrefs.showMessageText(context)
            val title = if (shown) context.getString(R.string.notif_mention_title, senderName, groupName) else context.getString(R.string.app_name)
            val mentionBody = if (shown) text else context.getString(R.string.notif_mention_hidden)
            show(context, id, title, mentionBody, intent, channel = MENTION_CHANNEL_ID)
            return
        }
        if (messageId.isNotEmpty()) shownMessageId[("group:$groupId").hashCode()] = messageId
        show(context, ("group:$groupId").hashCode(), context.getString(R.string.app_name), body, intent)
    }

    /**
     * Clears ALL message notifications when the app comes to the foreground or the main screen is entered. The user has
     * opened the app, so they should not stay in the notification bar. Called from `MainActivity.onResume`.
     *
     * SECURITY ALERTS and the foreground service's permanent notification are NOT cleared. For "new device", "my account
     * was revoked" and "account deleted", the notification bar is the only trace. In the previous version they were cleared
     * together with the message notifications, so the user could lose an alert before reading it.
     */
    fun clearAll(context: Context) {
        // Not cancelAll(): that also removes a ringing call's notification, which is the only way to answer when the call
        // screen cannot open itself.
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.activeNotifications
            .filter { it.id != com.p2p.messenger.ui.CallActivity.NOTIFICATION_ID }
            // The foreground service notification is not a message. It is the service's own ongoing slot.
            .filter { it.id != com.p2p.messenger.service.P2PService.NOTIFICATION_ID }
            .filter { !securityAlertIds.contains(it.id) }
            .forEach { manager.cancel(it.tag, it.id) }
    }

    /** A sibling device read [conversationId] up to [readAt]. Its notification is removed, unless a newer message posted it after that. */
    fun clearIfReadUpTo(context: Context, conversationId: String, readAt: Long) {
        val manager = context.getSystemService(NotificationManager::class.java)
        for (id in slotIds(conversationId)) {
            val shown = manager.activeNotifications.firstOrNull { it.id == id } ?: continue
            if (shown.postTime <= readAt) manager.cancel(id)
        }
    }

    /** When a 1:1 chat opens, ONLY that contact's notification is cleared. The ID is computed the same way as in
     *  `showMessageNotification`. It is narrower than `clearAll`. ChatActivity calls it from onResume. */
    fun clearForPeer(context: Context, peerDeviceFingerprint: String) {
        shownMessageId.remove(peerDeviceFingerprint.hashCode()) // no stale mapping
        context.getSystemService(NotificationManager::class.java).cancel(peerDeviceFingerprint.hashCode())
    }

    /** See the `clearForPeer` note. This is for group chats. */
    fun clearForGroup(context: Context, groupId: String) {
        for (id in slotIds("group:$groupId")) {
            shownMessageId.remove(id)
            context.getSystemService(NotificationManager::class.java).cancel(id)
        }
    }

    /** When a message is edited, the notification for that contact is updated with the new text, if one is still on
     *  screen. If none is (the user already saw it and dismissed it), no new notification is created. An edit is not a
     *  "new message" event worth notifying about. See the "edit" branch of P2PService.maybeNotify. */
    fun updateMessageNotificationIfShowing(context: Context, peerDeviceFingerprint: String, newText: String) {
        val id = peerDeviceFingerprint.hashCode()
        if (!isNotificationActive(context, id)) return
        showMessageNotification(context, peerDeviceFingerprint, newText, alert = false)
    }

    /** See `updateMessageNotificationIfShowing`. This is the group version. */
    fun updateGroupMessageNotificationIfShowing(context: Context, groupId: String, newText: String) {
        val id = ("group:$groupId").hashCode()
        if (!isNotificationActive(context, id)) return
        // The sender's name is not carried by the live edit event (see the Rust `group_edit` event). The existing notification
        // already contains the sender name, so a generic label is enough here.
        val groupName = resolveGroupName(groupId) ?: groupId.take(8)
        val intent = Intent(context, GroupChatActivity::class.java).apply {
            putExtra(GroupChatActivity.EXTRA_GROUP_ID, groupId)
            putExtra(GroupChatActivity.EXTRA_GROUP_NAME, groupName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        // See `showGroupMessageNotification`. Same "show messages" rule.
        val body = if (NotificationPrefs.showMessageText(context)) "$groupName: $newText" else context.getString(R.string.notif_new_message)
        show(context, ("group:$groupId").hashCode(), context.getString(R.string.app_name), body, intent, alert = false)
    }

    private fun isNotificationActive(context: Context, notificationId: Int): Boolean {
        val manager = context.getSystemService(NotificationManager::class.java)
        return manager.activeNotifications.any { it.id == notificationId }
    }

    /** Consecutive messages from the same chat share one notification ID (a hash of conversationId). So they update one
     *  notification instead of stacking and filling the notification bar. */
    private fun show(context: Context, notificationId: Int, title: String, text: String, contentIntent: Intent, alert: Boolean = true, channel: String = MESSAGE_CHANNEL_ID) {
        // Tapping the notification opens the app in the normal launcher way, not the specific chat. One back press also
        // leaves it.
        val isChat = contentIntent.component?.className.let {
            it == ChatActivity::class.java.name || it == GroupChatActivity::class.java.name
        }
        val launchIntent = if (isChat) {
            // The package is cleared: with it set, the intent does not equal the one the launcher started the task with. On
            // Android 8 to 10 the system then put a second MainActivity on top of the open chat.
            context.packageManager.getLaunchIntentForPackage(context.packageName)?.setPackage(null) ?: contentIntent
        } else contentIntent
        val pendingIntent = PendingIntent.getActivity(
            context, notificationId, launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        // The whole purpose of this app is end-to-end encryption. Still, notifications showed the decrypted message TEXT
        // with no redaction on the lock screen. The system setting "hide sensitive notification content on the lock screen"
        // could fix that, but only if the user found and turned it on. Relying on a system setting that may be off by default
        // is not enough. So, as Signal does, this sets `VISIBILITY_PRIVATE` plus a `publicVersion` with no content. With the
        // system "hide sensitive content" setting ON, the lock screen shows only "New message" and the sender name. The message
        // TEXT is never shown there.
        // On an unlocked phone, or when this setting is OFF, the behaviour is the same as before: the full preview is shown.
        // No feature was removed. Only an extra protection layer was added for the locked, hidden-content case.
        // The lock screen shows neither the sender nor the text.
        val publicVersion = NotificationCompat.Builder(context, channel)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.notif_new_message))
            .setSmallIcon(R.drawable.ic_notification)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        val notification = NotificationCompat.Builder(context, channel)
            .setContentTitle(title)
            .setContentText(Quote.plain(text))
            .setSmallIcon(R.drawable.ic_notification)
            .setAutoCancel(true)
            // An edit updates the slot silently, instead of ringing again.
            .setOnlyAlertOnce(!alert)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .build()
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.notify(notificationId, notification)
    }

    /** Each notification used to parse the whole contact list (every avatar as hex) on the poll thread, only to read one
     *  name. After a reconnect, 50 queued messages meant 50 to 100 full serialisations. */
    private const val NAME_CACHE_TTL_MS = 30_000L
    private var namesLoadedAt = 0L
    private var namesByFingerprint = emptyMap<String, String>()
    private var namesByIdentity = emptyMap<String, String>()
    private var groupNames = emptyMap<String, String>()

    @Synchronized
    private fun refreshNames() {
        val now = android.os.SystemClock.elapsedRealtime()
        if (namesLoadedAt != 0L && now - namesLoadedAt < NAME_CACHE_TTL_MS) return
        try {
            val byFp = HashMap<String, String>()
            val byId = HashMap<String, String>()
            val contacts = JSONArray(P2PLib.listContacts())
            for (i in 0 until contacts.length()) {
                val obj = contacts.getJSONObject(i)
                val name = obj.optString("display_name")
                byFp[obj.optString("active_device_fingerprint")] = name
                byId[obj.optString("identity_id")] = name
            }
            val groups = HashMap<String, String>()
            val array = JSONArray(P2PLib.listGroups())
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                groups[obj.optString("group_id")] = obj.optString("name")
            }
            namesByFingerprint = byFp
            namesByIdentity = byId
            groupNames = groups
            namesLoadedAt = now
        } catch (e: Exception) {
        }
    }

    /** A name missing from the cache may belong to a contact added since. */
    private fun lookup(key: String, map: () -> Map<String, String>): String? {
        refreshNames()
        map()[key]?.let { return it }
        // Not on every miss: a group member who is not a contact never resolves, and would be retried each time.
        synchronized(this) {
            if (android.os.SystemClock.elapsedRealtime() - namesLoadedAt < 2_000L) return null
            namesLoadedAt = 0L
        }
        refreshNames()
        return map()[key]
    }

    private fun resolveContactNameByFingerprint(peerDeviceFingerprint: String): String? =
        lookup(peerDeviceFingerprint) { namesByFingerprint }

    private fun resolveContactNameByIdentity(identityId: String): String? =
        lookup(identityId) { namesByIdentity }

    private fun resolveGroupName(groupId: String): String? =
        lookup(groupId) { groupNames }
}
