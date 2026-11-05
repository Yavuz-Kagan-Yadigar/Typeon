package com.p2p.messenger.server

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat

/**
 * Yeniden başlatmadan sonra sunucuyu geri getirir.
 *
 * İstemcideki `service.BootReceiver` ile AYNI gerekçe, ama sonucu daha ağır:
 * sunucu kapalıyken store-and-forward TAMAMEN durur. Çevrimdışı bir alıcıya
 * gönderilen her mesaj, gönderenin yeniden deneme kuyruğunda bekler ve
 * alıcı P2P olarak ulaşılabilir olana kadar teslim edilemez — yani sunucunun
 * var olma sebebi ortadan kalkar. Telefon gece yeniden başladıysa, kimse
 * uygulamayı elle açana kadar bu böyle sürer.
 *
 * `ACTION_BOOT_COMPLETED`, Android'in ön plan servisi başlatma kısıtlarından
 * AÇIKÇA muaf tuttuğu birkaç yayından biri; bu yüzden buradan başlatmak pil
 * optimizasyonu muafiyetine bağlı değil.
 *
 * `ACTION_MY_PACKAGE_REPLACED` de dinleniyor: uygulama güncellendiğinde süreç
 * öldürülüyor ve servis kendiliğinden geri gelmiyor (bu, release APK'ları
 * kurarken gerçek cihazda gözlemlendi — sunucu kurulumdan sonra kapalı kaldı).
 *
 * Not direct-boot aware (the data is in credential-protected storage): after
 * a reboot the server returns only once the phone has been unlocked — keep
 * the lock screen. Removing it makes the DB key and the enrolment keys
 * readable on a cold-booted device.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {}
            else -> return
        }
        // Kullanıcının açma/kapama anahtarı (bkz. ServerActivity). Kapalıysa
        // açılışta da başlatmıyoruz — "kapalı" kararına saygı.
        if (!ServerService.isEnabled(context)) {
            Log.i("ServerBootReceiver", "Sunucu kullanıcı tarafından kapalı — açılışta başlatılmadı")
            return
        }
        try {
            ContextCompat.startForegroundService(
                context.applicationContext,
                Intent(context.applicationContext, ServerService::class.java)
            )
        } catch (e: Exception) {
            // Doğrudan-önyükleme (direct boot) aşaması ya da OEM kısıtlaması:
            // sessizce geç, kullanıcı uygulamayı açtığında yine başlar.
            Log.w("ServerBootReceiver", "Açılışta sunucu başlatılamadı: ${e.message}")
        }
    }
}
