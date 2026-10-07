package com.p2p.messenger.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat
import com.p2p.messenger.P2PLib

/**
 * Yeniden başlatmadan sonra ağı geri getirir.
 *
 * Bu denetimde bulundu: telefon yeniden başladığında uygulama TAMAMEN ölü
 * kalıyordu — kullanıcı uygulamayı elle açana kadar hiçbir mesaj
 * alınmıyordu. Tek yedek, saatte bir çalışan `P2PRetryWorker`'dı; ama o da
 * ARKA PLANDAN `startForegroundService` çağırıyor ve Android 12+ (API 31)
 * bunu `ForegroundServiceStartNotAllowedException` ile reddediyor —
 * uygulama pil optimizasyonundan muaf değilse. Yani en kötü durumda
 * "gece telefonu yeniden başlattım, sabah hiçbir mesaj gelmemiş".
 *
 * `ACTION_BOOT_COMPLETED`, Android'in ön plan servisi başlatma kısıtlarından
 * AÇIKÇA muaf tuttuğu birkaç yayından biri — bu yüzden buradan başlatmak
 * pil muafiyetine bağlı DEĞİL, her zaman çalışır.
 *
 * `ACTION_MY_PACKAGE_REPLACED` de aynı sebeple dinleniyor: uygulama
 * güncellendiğinde süreç öldürülür ve servis kendiliğinden geri gelmez.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {}
            else -> return
        }
        // Opening the database on the main thread held up every other boot
        // receiver of the process (and can run into the broadcast ANR limit).
        val pending = goAsync()
        val app = context.applicationContext
        Thread {
            try {
                // bkz. P2PRetryWorker aynı notu: süreç yeni doğmuş olabilir,
                // `hasStoredIdentity` DB açılmadan yanlış (false) döner.
                // `initDatabase` idempotent.
                P2PLib.initDatabase(app.filesDir.absolutePath)
                if (P2PLib.hasStoredIdentity()) {
                    ContextCompat.startForegroundService(app, Intent(app, P2PService::class.java))
                }
            } catch (e: Throwable) {
                // Cihaz henüz doğrudan-önyükleme (direct boot) aşamasındaysa
                // veya OEM kısıtlaması varsa: sessizce geç — `P2PRetryWorker`
                // ve kullanıcının uygulamayı açması hâlâ yedek yollar.
                Log.w("BootReceiver", "Açılışta servis başlatılamadı: ${e.message}")
            } finally {
                pending.finish()
            }
        }.start()
    }
}
