package com.p2p.messenger.util

import android.content.Context
import android.content.Intent
import androidx.appcompat.app.AlertDialog
import com.p2p.messenger.R

/**
 * Spec dışı, kullanıcı isteği: sohbet/ayarlar üst çubuğundaki hızlı "Tor
 * bağlantısını kes/yeniden kur" düğmesi için.
 *
 * Bugün ağ katmanı (özellikle libp2p swarm'a eklenen Tor dial transport'u,
 * bkz. tor.rs `ArtiDialTransport`) CANLI bir süreçte yeniden kurulmayı
 * desteklemiyor — mevcut Ayarlar'daki Tor açma/kapama anahtarı bile sadece
 * tercihi kaydedip kullanıcıdan MANUEL olarak uygulamayı yeniden başlatmasını
 * istiyor (bkz. SettingsFragment `tor_switch`, `R.string.tor_restart_needed`
 * ve SECURITY.md "toggle takes effect on the next network-layer start"
 * notu). Rust tarafında `start_network`'ü canlı bir süreçte GÜVENLE ikinci
 * kez çağırmanın (eski swarm'ın soketlerinin/arka plan görevlerinin
 * (bkz. tor.rs bootstrap yeniden deneme döngüsü) düzgün kapandığından emin
 * olmadan) doğrulanmış bir yolu yok — bu yüzden burada YENİ/doğrulanmamış
 * bir Rust "sıcak yeniden başlatma" mantığı İCAT EDİLMİYOR.
 *
 * Bunun yerine tek güvenli, tamamen zaten var olan yol kullanılıyor:
 * uygulama SÜRECİNİ tamamen kapatıp yeniden başlatmak — bu, kullanıcının
 * uygulamayı Son Uygulamalar'dan kapatıp tekrar açmasıyla BİREBİR AYNI
 * (ve zaten normal her açılışta çalışan, kanıtlanmış) kod yolunu izler:
 * `MainActivity.onCreate` -> `initDatabase`/`loadIfPresent`/
 * `startNetworkService` -> `P2PLib.startNetwork` TEMİZ bir süreçte.
 */
object AppRestarter {
    fun restart(context: Context) {
        val packageManager = context.packageManager
        val intent = packageManager.getLaunchIntentForPackage(context.packageName) ?: return
        val component = intent.component ?: return
        val restartIntent = Intent.makeRestartActivityTask(component)
        // A background start (service path) can be blocked on API 29+; it must
        // not crash the restart, and the exit waits so the task can start (H146).
        try { context.startActivity(restartIntent) } catch (e: Exception) { android.util.Log.w("AppRestarter", "startActivity: ${e.message}") }
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ Runtime.getRuntime().exit(0) }, 400)
    }

    /**
     * Yıkıcı bir işlem olduğundan (tüm süreci kapatır) doğrudan
     * tetiklenmez, önce onay istenir. Hem toolbar düğmesi (bkz.
     * `wireTorReconnectButton`) hem de SettingsFragment'ın üst çubuk menü
     * öğesi bunu paylaşır.
     */
    fun confirmAndRestart(context: Context) {
        AlertDialog.Builder(context)
            .setTitle(R.string.title_tor_reconnect)
            .setMessage(R.string.msg_tor_reconnect)
            .setPositiveButton(R.string.action_reconnect) { _, _ -> restart(context) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
