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
        // The service is polling: nothing to restart, and `initDatabase` plus a
        // service start every hour only woke the core.
        if (P2PService.alive) return Result.success()
        // Database not open is not "no account": try again later.
        if (!P2PLib.initDatabase(applicationContext.filesDir.absolutePath)) return Result.retry()
        if (P2PLib.hasStoredIdentity()) {
            val serviceIntent = Intent(applicationContext, P2PService::class.java)
            // Bu denetimde bulundu: bu çağrı korumasızdı. Android 12+ (API 31)
            // ARKA PLANDAN ön plan servisi başlatmayı reddediyor
            // (`ForegroundServiceStartNotAllowedException`) — bu Worker tam
            // olarak arka planda çalışıyor. Uygulama pil optimizasyonundan
            // MUAFSA izin veriliyor, değilse istisna fırlıyor; WorkManager
            // onu yakalayıp işi "failed" sayıyordu, yani yedek mekanizma
            // sessizce hiç çalışmıyordu. Artık istisna yutuluyor ama iş
            // "BAŞARILI" sayılmıyor: `Result.retry()` ile WorkManager'a
            // durum bildiriliyor (kendi geri çekilme kuralıyla yeniden
            // denenir), periyodik program bozulmuyor. Asıl açılış yolu artık
            // `BootReceiver` (kısıttan muaf).
            try {
                ContextCompat.startForegroundService(applicationContext, serviceIntent)
            } catch (e: Exception) {
                android.util.Log.w("P2PRetryWorker", "Servis arka plandan başlatılamadı: ${e.message}")
                // "Başarılı" demek, bu yedeğin HİÇ çalışmadığını gizliyordu.
                // WorkManager'a durumu bildir: iş kendi geri çekilme
                // (backoff) kuralıyla yeniden denensin.
                return Result.retry()
            }
        }
        return Result.success()
    }
}
