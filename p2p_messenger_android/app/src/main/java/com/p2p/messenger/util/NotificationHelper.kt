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
 * Gelen mesajlar için LOKAL bildirimler — Google Play Services/FCM'ye HİÇ
 * bağımlı değil ve olmamalı da (bu, gizlilik odaklı bir P2P uygulaması).
 * P2PService zaten sürekli çalışan bir foreground service olarak ağı her
 * saniye poll ediyor (bkz. P2PService.pollRunnable) — bu yüzden "push"
 * bildirimini taklit etmeye hiç gerek yok: mesaj gerçekten geldiğinde
 * (P2PService'in kendi sürekli taramasıyla) doğrudan burada bildirim
 * gösteriyoruz. Güvenilirliği, üçüncü taraf bir push altyapısına değil,
 * servisin ne kadar sık/düzenli çalıştığına bağlı — ki bu foreground
 * service zaten START_STICKY ve her saniye çalışıyor.
 */
object NotificationHelper {
    const val MESSAGE_CHANNEL_ID = "P2PMessagesChannel"

    fun createChannel(context: Context) {
        val channel = NotificationChannel(
            MESSAGE_CHANNEL_ID,
            "Mesajlar",
            NotificationManager.IMPORTANCE_HIGH
        )
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    fun showMessageNotification(context: Context, peerDeviceFingerprint: String, text: String) {
        val displayName = resolveContactNameByFingerprint(peerDeviceFingerprint) ?: peerDeviceFingerprint.take(8)
        val intent = Intent(context, ChatActivity::class.java).apply {
            putExtra(ChatActivity.EXTRA_PEER_DEVICE_FINGERPRINT, peerDeviceFingerprint)
            putExtra(ChatActivity.EXTRA_PEER_DISPLAY_NAME, displayName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        show(context, peerDeviceFingerprint.hashCode(), displayName, text, intent)
    }

    fun showGroupMessageNotification(context: Context, groupId: String, senderIdentityId: String, text: String) {
        val groupName = resolveGroupName(groupId) ?: groupId.take(8)
        val senderName = resolveContactNameByIdentity(senderIdentityId) ?: senderIdentityId.take(8)
        val intent = Intent(context, GroupChatActivity::class.java).apply {
            putExtra(GroupChatActivity.EXTRA_GROUP_ID, groupId)
            putExtra(GroupChatActivity.EXTRA_GROUP_NAME, groupName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        show(context, ("group:$groupId").hashCode(), groupName, "$senderName: $text", intent)
    }

    /** Aynı sohbetten gelen ardışık mesajlar aynı bildirim ID'sini paylaşır
     *  (conversationId'nin hash'i) — bu yüzden yığılıp bildirim çubuğunu
     *  doldurmak yerine tek bildirim güncellenir. */
    private fun show(context: Context, notificationId: Int, title: String, text: String, contentIntent: Intent) {
        val pendingIntent = PendingIntent.getActivity(
            context, notificationId, contentIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, MESSAGE_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.notify(notificationId, notification)
    }

    private fun resolveContactNameByFingerprint(peerDeviceFingerprint: String): String? {
        return try {
            val array = JSONArray(P2PLib.listContacts())
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                if (obj.optString("active_device_fingerprint") == peerDeviceFingerprint) {
                    return obj.optString("display_name")
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    private fun resolveContactNameByIdentity(identityId: String): String? {
        return try {
            val array = JSONArray(P2PLib.listContacts())
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                if (obj.optString("identity_id") == identityId) {
                    return obj.optString("display_name")
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    private fun resolveGroupName(groupId: String): String? {
        return try {
            val array = JSONArray(P2PLib.listGroups())
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                if (obj.optString("group_id") == groupId) {
                    return obj.optString("name")
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }
}
