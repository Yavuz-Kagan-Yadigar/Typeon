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

    /** Message each chat's single slot shows now, see `clearIfShowing`. */
    private val shownMessageId = java.util.concurrent.ConcurrentHashMap<Int, String>()

    /**
     * Güvenlik uyarılarının bildirim slotları — `clearAll` bunları SİLMEZ:
     * "yeni cihaz", "kendi hesabım iptal edildi" ve "hesabı silindi"
     * uyarılarının bildirim çubuğundaki tek izi budur; mesaj bildirimleri
     * gibi temizleniyordu, kullanıcı uyarıyı hiç okuyamadan kayboluyordu.
     */
    private val securityAlertIds = java.util.concurrent.ConcurrentHashMap.newKeySet<Int>()

    /** `showDeviceAlertNotification`/`showDeviceRevokedNotification` —
     *  sabit slotlar, kimlikten bağımsız. */
    private val DEVICE_ALERT_NOTIFICATION_ID = "device_alert".hashCode()
    private val SELF_REVOKED_NOTIFICATION_ID = "self_revoked".hashCode()

    /** A delete removes the chat's notification only when the slot shows
     *  that message (or we do not know what it shows): deleting an old, read
     *  message used to remove the notification of the unread ones. */
    fun clearIfShowing(context: Context, conversationId: String, messageId: String) {
        for (id in slotIds(conversationId)) {
            val shown = shownMessageId[id]
            if (shown != null && shown != messageId) continue
            shownMessageId.remove(id)
            context.getSystemService(NotificationManager::class.java).cancel(id)
        }
    }

    /** A group has two slots: its messages and its @mentions (`"mention:$groupId"`),
     *  so a plain message does not replace a mention alert. */
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
        // bildirim başlığı artık kişi/grup adı
        // DEĞİL, her zaman uygulama adı ("Typeon") — kimin/nereden geldiği
        // bilgisi gövdeye ("{isim}: mesaj" biçiminde) taşındı.
        //
        // Spec dışı, kullanıcı isteği (Ayarlar'daki "bildirimlerde mesajları
        // göster" anahtarı, bkz. NotificationPrefs): kapalıyken gövde
        // SADECE göndereni taşır, mesaj metni HİÇ yazılmaz.
        val body = if (NotificationPrefs.showMessageText(context)) "$displayName: $text" else context.getString(R.string.notif_new_message)
        if (messageId.isNotEmpty()) shownMessageId[peerDeviceFingerprint.hashCode()] = messageId
        show(context, peerDeviceFingerprint.hashCode(), context.getString(R.string.app_name), body, intent, alert)
    }

    /** Spec dışı  : bu
     *  cihaz birincil cihaz tarafından iptal edildiğinde (kendi
     *  DeviceRevokeNotice'ını aldı) yerel veri silinip onboarding'e dönülür;
     *  bu, kullanıcıya NEDEN geri döndüğünü açıklayan tek seferlik bildirim.
     *  Dokununca MainActivity (onboarding) açılır. */
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
     * Kullanıcı kararı (2026-08-27): "yeni cihaz" uyarısı artık SESSİZ
     * değil.
     *
     * Önceden bu uyarı yalnızca çekirdekteki bekleyenler listesine
     * yazılıyor, arayüz de sadece ana ekran ÖN PLANDAYKEN saniyede bir
     * sorarak fark ediyordu. Yani kullanıcı başka bir ekrandaysa ya da
     * uygulama arka plandaysa uyarıyı hiç görmüyor, bu arada o kişiden
     * gelen bütün mesajlar sessizce düşüyordu. Artık bildirim olarak da
     * çıkıyor ve dokunulduğunda kabul/reddet/engelle penceresi açılıyor.
     */
    fun showDeviceAlertNotification(context: Context, contactName: String, shortCode: String) {
        val intent = Intent(context, com.p2p.messenger.MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        securityAlertIds.add(DEVICE_ALERT_NOTIFICATION_ID)
        show(
            context, DEVICE_ALERT_NOTIFICATION_ID,
            context.getString(R.string.title_security_warning_dialog),
            // No contact name while message text is hidden: the
            // lock screen may show the body. The app shows it after unlock.
            if (NotificationPrefs.showMessageText(context)) context.getString(R.string.notif_new_device_warning, contactName, shortCode)
            else context.getString(R.string.msg_security_warning),
            intent
        )
    }

    /** Bir kişi hesabını sildi — kişi adıyla tek seferlik bildirim. */
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
        // bkz. `showMessageNotification` aynı notu — başlık her zaman
        // uygulama adı, gövde göndereni (parantez içinde grup adıyla) taşır.
        // "Mesajları göster" kapalıysa gönderen + grup görünür, metin GÖRÜNMEZ.
        val body = if (NotificationPrefs.showMessageText(context)) {
            "$senderName ($groupName): $text"
        } else {
            context.getString(R.string.notif_new_message)
        }
        if (mention) {
            // Its own slot (see `slotIds`): a later plain message must not
            // replace it. Opening/reading the group clears both. Hidden text
            // hides who and where too, like the plain group notification.
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

    /** uygulama ön plana/ana ekrana her
     *  girildiğinde TÜM mesaj bildirimlerini temizler — kullanıcı zaten
     *  uygulamayı açtığından bildirim çubuğunda asılı kalmalarının bir
     *  anlamı yok. `MainActivity.onResume`'dan çağrılır.
     *
     *  GÜVENLİK UYARILARI ve ön plan servisinin kalıcı bildirimi
     *  TEMİZLENMEZ: "yeni cihaz", "hesabım iptal edildi" ve "hesabı silindi"
     *  uyarılarının tek izi bildirim çubuğudur; önceki sürümde hepsi
     *  mesaj bildirimleriyle birlikte siliniyordu — kullanıcı uyarıyı
     *  okumadan kayboluyordu. */
    fun clearAll(context: Context) {
        // Not cancelAll(): that also removed a ringing call's notification,
        // the only way to answer when the call screen could not open itself.
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.activeNotifications
            .filter { it.id != com.p2p.messenger.ui.CallActivity.NOTIFICATION_ID }
            // The foreground service notification is not a message: it is the
            // service's own ongoing slot.
            .filter { it.id != com.p2p.messenger.service.P2PService.NOTIFICATION_ID }
            .filter { !securityAlertIds.contains(it.id) }
            .forEach { manager.cancel(it.tag, it.id) }
    }

    /** Sibling device read [conversationId] up to [readAt]: remove its
     *  notification unless a newer message posted it after that. */
    fun clearIfReadUpTo(context: Context, conversationId: String, readAt: Long) {
        val manager = context.getSystemService(NotificationManager::class.java)
        for (id in slotIds(conversationId)) {
            val shown = manager.activeNotifications.firstOrNull { it.id == id } ?: continue
            if (shown.postTime <= readAt) manager.cancel(id)
        }
    }

    /** belirli bir 1:1 sohbet açıldığında
     *  SADECE o kişiye ait bildirimi temizler (bkz. `showMessageNotification`
     *  AYNI kimlik hesaplaması — `clearAll`'dan daha dar kapsamlı, ChatActivity
     *  onResume'dan çağrılır). */
    fun clearForPeer(context: Context, peerDeviceFingerprint: String) {
        shownMessageId.remove(peerDeviceFingerprint.hashCode()) // no stale mapping
        context.getSystemService(NotificationManager::class.java).cancel(peerDeviceFingerprint.hashCode())
    }

    /** bkz. `clearForPeer` aynı notu — grup sohbeti için. */
    fun clearForGroup(context: Context, groupId: String) {
        for (id in slotIds("group:$groupId")) {
            shownMessageId.remove(id)
            context.getSystemService(NotificationManager::class.java).cancel(id)
        }
    }

    /** Spec dışı, hata düzeltmesi (bkz. P2PService.maybeNotify "edit" kolu):
     *  bir mesaj düzenlendiğinde, o kişi için ekranda HÂLÂ asılı bir
     *  bildirim varsa yeni metinle günceller; yoksa (kullanıcı zaten görüp
     *  kapatmışsa) YENİ bir bildirim oluşturmaz — düzenlemenin kendisi
     *  bildirime değer bir "yeni mesaj" olayı değildir. */
    fun updateMessageNotificationIfShowing(context: Context, peerDeviceFingerprint: String, newText: String) {
        val id = peerDeviceFingerprint.hashCode()
        if (!isNotificationActive(context, id)) return
        showMessageNotification(context, peerDeviceFingerprint, newText, alert = false)
    }

    /** bkz. `updateMessageNotificationIfShowing` aynı notu — grup için. */
    fun updateGroupMessageNotificationIfShowing(context: Context, groupId: String, newText: String) {
        val id = ("group:$groupId").hashCode()
        if (!isNotificationActive(context, id)) return
        // Gönderenin adı canlı düzenleme olayında taşınmıyor (bkz. Rust
        // `group_edit` olayı) — mevcut bildirim zaten gönderen adını
        // içerdiğinden, burada jenerik bir etiket yeterli.
        val groupName = resolveGroupName(groupId) ?: groupId.take(8)
        val intent = Intent(context, GroupChatActivity::class.java).apply {
            putExtra(GroupChatActivity.EXTRA_GROUP_ID, groupId)
            putExtra(GroupChatActivity.EXTRA_GROUP_NAME, groupName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        // bkz. `showGroupMessageNotification` — aynı "mesajları göster" kuralı.
        val body = if (NotificationPrefs.showMessageText(context)) "$groupName: $newText" else context.getString(R.string.notif_new_message)
        show(context, ("group:$groupId").hashCode(), context.getString(R.string.app_name), body, intent, alert = false)
    }

    private fun isNotificationActive(context: Context, notificationId: Int): Boolean {
        val manager = context.getSystemService(NotificationManager::class.java)
        return manager.activeNotifications.any { it.id == notificationId }
    }

    /** Aynı sohbetten gelen ardışık mesajlar aynı bildirim ID'sini paylaşır
     *  (conversationId'nin hash'i) — bu yüzden yığılıp bildirim çubuğunu
     *  doldurmak yerine tek bildirim güncellenir. */
    private fun show(context: Context, notificationId: Int, title: String, text: String, contentIntent: Intent, alert: Boolean = true, channel: String = MESSAGE_CHANNEL_ID) {
        // Kullanıcı isteği: bildirime dokunmak belirli sohbeti değil uygulamayı
        // normal (launcher) şekilde açsın — geri tuşu da tek seferde çıkar.
        val isChat = contentIntent.component?.className.let {
            it == ChatActivity::class.java.name || it == GroupChatActivity::class.java.name
        }
        val launchIntent = if (isChat) {
            // Package cleared: with it set the intent does not equal the one
            // the launcher started the task with, and Android 8-10 then put a
            // second MainActivity on top of the open chat.
            context.packageManager.getLaunchIntentForPackage(context.packageName)?.setPackage(null) ?: contentIntent
        } else contentIntent
        val pendingIntent = PendingIntent.getActivity(
            context, notificationId, launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        // bu uygulamanın TÜM amacı
        // uçtan uca şifreleme olduğu halde, bildirimler çözülmüş mesaj
        // METNİNİ hiçbir kilit ekranı gizleme/redaksiyonu olmadan
        // gösteriyordu. Android'in cihaz genelindeki "kilit ekranında
        // hassas bildirim içeriğini gizle" ayarı bunu KENDİ BAŞINA
        // düzeltebilir, ama SADECE kullanıcı o ayarı elle bulup açtıysa —
        // varsayılan olarak kapalı olabilen bir sistem ayarına güvenmek
        // yerine, Signal'ın yaptığı gibi burada AÇIKÇA `VISIBILITY_PRIVATE`
        // + içerik taşımayan bir `publicVersion` sağlıyoruz: sistem "hassas
        // içeriği gizle" AÇIKSA, kilitli ekranda görünen tek şey "Yeni
        // mesaj" + gönderenin adı olur, mesaj METNİ asla görünmez.
        // Kilidi açık bir telefonda veya bu ayar KAPALIYSA davranış AYNI
        // kalır (tam önizleme hâlâ gösterilir) — hiçbir özellik kaldırılmadı,
        // sadece kilitli+hassas-gizli durumunda ek bir koruma katmanı eklendi.
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
            // An edit updates the slot silently instead of ringing again.
            .setOnlyAlertOnce(!alert)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .build()
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.notify(notificationId, notification)
    }

    /** Every notification parsed the whole contact list (each avatar as
     *  hex) on the poll thread to read one name: 50 queued messages after a
     *  reconnect were 50-100 full serialisations. */
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
        // Not on every miss: a group member who is not a contact never resolves.
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
