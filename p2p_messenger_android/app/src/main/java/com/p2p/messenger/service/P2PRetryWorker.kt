package com.p2p.messenger.service

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.p2p.messenger.P2PLib

/**
 * Spec dışı, kullanıcı isteği ("gönderilemeyen mesajlar/emirler ...
 * arka planda saatte bir denesin"): `P2PService` zaten START_STICKY olduğu
 * için OS tarafından yeniden başlatılması beklenir, ama bazı OEM'lerin
 * agresif pil optimizasyonu bu yeniden başlatmayı saatlerce geciktirebilir.
 * WorkManager (JobScheduler tabanlı — OS bu işi diğer uygulamaların
 * işleriyle TOPLU çalıştırır) burada özel bir AlarmManager/wakelock
 * döngüsünden çok daha bataryayı dostu bir yedek mekanizma sağlıyor.
 *
 * `doWork` sadece servisi (yeniden) başlatmayı DENER — servis zaten
 * çalışıyorsa bu zararsız bir no-op'tur (bkz. `P2PService.onStartCommand`
 * `isRunning` koruması, sadece bildirimi tazeler). Ölmüşse yeniden başlatma
 * `setSkippedKeyEncryptionKey` üzerinden kalıcı yeniden deneme kuyruğunun
 * (bkz. lib.rs `load_pending_durable_retries_from_db`) diskten geri
 * yüklenip tazelenmesini de otomatik olarak tetikler — ayrı bir "şimdi
 * dene" JNI çağrısına gerek yok.
 */
class P2PRetryWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        // KRİTİK: WorkManager, süreç tamamen ölüyken de bu Worker'ı
        // çalıştırmak için süreci YENİDEN BAŞLATABİLİR — bu durumda
        // Rust tarafındaki `identity` alanı henüz DB'den yüklenmemiştir
        // (`initDatabase` hiç çağrılmamış olabilir). `hasStoredIdentity()`
        // bu çağrı olmadan YANLIŞ (false negatif) sonuç verir. `initDatabase`
        // zaten idempotent (bkz. P2PService.onStartCommand notu) — servis
        // zaten çalışıyorsa bu zararsız bir tekrar çağrıdır.
        P2PLib.initDatabase(applicationContext.filesDir.absolutePath)
        if (P2PLib.hasStoredIdentity()) {
            val serviceIntent = Intent(applicationContext, P2PService::class.java)
            // Bu denetimde bulundu: bu çağrı korumasızdı. Android 12+ (API 31)
            // ARKA PLANDAN ön plan servisi başlatmayı reddediyor
            // (`ForegroundServiceStartNotAllowedException`) — bu Worker tam
            // olarak arka planda çalışıyor. Uygulama pil optimizasyonundan
            // MUAFSA izin veriliyor, değilse istisna fırlıyor; WorkManager
            // onu yakalayıp işi "failed" sayıyordu, yani yedek mekanizma
            // sessizce hiç çalışmıyordu. Artık istisna yutuluyor ve iş
            // BAŞARILI dönüyor: periyodik program bozulmasın, bir sonraki
            // turda (ya da kullanıcı uygulamayı açtığında) tekrar denensin.
            // Asıl açılış yolu artık `BootReceiver` (kısıttan muaf).
            try {
                ContextCompat.startForegroundService(applicationContext, serviceIntent)
            } catch (e: Exception) {
                android.util.Log.w("P2PRetryWorker", "Servis arka plandan başlatılamadı: ${e.message}")
            }
        }
        return Result.success()
    }
}
