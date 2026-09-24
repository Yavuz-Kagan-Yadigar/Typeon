package com.p2p.messenger.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.*
import android.util.Log
import androidx.core.app.NotificationCompat
import com.p2p.messenger.P2PLib
import com.p2p.messenger.R
import com.p2p.messenger.util.NotificationHelper
import com.p2p.messenger.util.ReadStatePrefs
import org.json.JSONObject

/** bkz. `P2PService.bindToWifiIfAvailable` dokümantasyonu — transport tipi
 *  TEK BAŞINA yeterli değil, gerçekten doğrulanmış internet erişimi de
 *  gerekli (aksi halde internetsiz bir WiFi'ye yanlışlıkla bağlanıp mobil
 *  veri üzerinden çalışan bir cihazı bağlantısız bırakabiliriz). */
private fun NetworkCapabilities?.isValidatedWifi(): Boolean {
    if (this == null) return false
    return hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
        hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
        hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
}

class P2PService : Service() {

    companion object {
        private const val TAG = "P2PService"
        const val CHANNEL_ID = "P2PServiceChannel"
        const val NOTIFICATION_ID = 1
        const val PREFS_NAME = "p2p_settings"
        const val KEY_NODE_MODE = "node_mode_enabled"
        /** Spec dışı, kullanıcı isteği (Tor onion). */
        const val KEY_TOR_ENABLED = "tor_enabled"
        /** Spec dışı, kullanıcı isteği: node modu için geçmiş/ek depolama
         *  sınırı (bayt) — bkz. Rust `history_storage_limit_bytes`. */
        const val KEY_HISTORY_STORAGE_LIMIT = "history_storage_limit_bytes"
        const val DEFAULT_HISTORY_STORAGE_LIMIT_BYTES = 2L * 1024 * 1024 * 1024

        /** bkz. `pollRunnable`/`nextPollDelayMs` dokümantasyonu.
         *
         *  Boşta tavanı 2sn (önceden 4sn): Rust tarafındaki keepalive
         *  zamanlaması (`KEEPALIVE_FAST_INTERVAL_MS` = 2sn) poll turları
         *  İÇİNDE işletiliyor — tavan 2sn'yi aşarsa arka planda "yarı açık"
         *  bağlantı tespiti tasarlandığından yavaş çalışır. */
        private const val POLL_INTERVAL_ACTIVE_MS = 1000L
        private const val POLL_IDLE_STEP_MS = 500L
        /** Arka planda arka arkaya kaç boş tur geçtikten SONRA aralık
         *  genişlemeye başlar (~5sn) — kısa bir arka plan sıçramasında
         *  (ör. ekran kilitlenip hemen açılması) gecikme yaratmaz. */
        private const val POLL_IDLE_BACKOFF_THRESHOLD = 5

        /* ---------------- Pil düzeltmesi (2026-08-28) ----------------
         *
         * Ölçüm değil, mimari bir gözlem: libp2p swarm'ı YALNIZCA
         * `pollNetwork()` çağrıldığında ilerliyor (Rust tarafında
         * `now_or_never`, arka planda süren bir görev yok). Yani yoklama
         * aralığı doğrudan ağın tepki süresi — körlemesine açmak el
         * sıkışmaları, Tor devresi kurulumunu ve mesh bakımını da yavaşlatır.
         *
         * Bu yüzden aralık artık tek bir sayaca değil, ÜÇ gerçek sinyale
         * birden bakıyor: bir ekran dinliyor mu, cihazın ekranı açık mı, ve
         * çekirdekte gerçekten iş var mı (`P2PLib.getOwnConnectionStatus`
         * içindeki `busy` — bağlı eş, onay bekleyen paket, süren indirme,
         * kuyruktaki zarf, sunucu işi). Hiçbiri yoksa yapılacak tek şey
         * GELEN bir bağlantıyı kabul etmek; o da saniyede bir uyanmayı
         * gerektirmiyor.
         *
         * Asıl kazanç uyanma SAYISINDA: ekran kapalı ve hiçbir şey
         * olmuyorken günde ~86.400 uyanma yerine ~2.900 oluyor.
         */
        /** Ekran açık ama hiçbir sohbet ekranı dinlemiyor. */
        private const val POLL_INTERVAL_SCREEN_ON_MS = 2000L
        /** Ekran kapalı, ama çekirdekte iş var (bağlı eş / bekleyen mesaj /
         *  süren indirme). Gelen mesaj en fazla bu kadar geç görünür. */
        private const val POLL_INTERVAL_SCREEN_OFF_MS = 5000L
        /** Ekran kapalı VE çekirdek tamamen boşta. Bağlı eş yok, bekleyen
         *  iş yok — olabilecek tek şey gelen bir bağlantı. */
        private const val POLL_INTERVAL_DEEP_IDLE_MS = 20000L
        /** Derin boşta moduna geçmeden önce kaç ardışık boş tur beklenir
         *  (~1 dk) — anlık bir sessizlikte moda düşüp gecikme yaratmasın. */
        private const val DEEP_IDLE_AFTER_EMPTY_POLLS = 12
        /** Derin boştayken wake lock BIRAKILIYOR; cihaz uykuya dalarsa
         *  `Handler.postDelayed` (uptime tabanlı) durur. Bu alarm, Doze
         *  altında bile periyodik bir uyanma garantisi veriyor.
         *
         *  Kullanıcı kararı (2026-08-28): en fazla 3 dakika.
         *
         *  DÜRÜST OLMAK GEREKİRSE: bu bir üst sınır değil, bir TALEP.
         *  `setAndAllowWhileIdle` özel izin istemiyor ama işletim sistemi
         *  cihaz DERİN Doze'dayken bu alarmları ~9 dakikada birden sık
         *  ateşlemiyor — 3 yazsak da. Talebin gerçekten 3 dakikada bir
         *  karşılanması için uygulamanın pil optimizasyonundan MUAF olması
         *  gerekiyor; uygulama bunu zaten ayarlardan istiyor
         *  (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`). Muafiyet verilmişse 3
         *  dakika birebir geçerli, verilmemişse sistem ~9 dakikaya çeker.
         *
         *  Bu, mesaj kaybı DEĞİL gecikme: gönderen 7 gün boyunca yeniden
         *  deniyor, sunucu varsa 30 gün tutuyor. */
        private const val DOZE_WAKE_INTERVAL_MS = 3 * 60 * 1000L
        const val ACTION_WAKE_POLL = "com.p2p.messenger.action.WAKE_POLL"

        /** Registered by UI components (e.g. ChatActivity) that want to be
         *  notified as decrypted messages arrive. Kept simple/static rather
         *  than a full pub-sub bus since this is a single-process app.
         *
         *  Spec dışı, kararlılık denetimi düzeltmesi: `pollRunnable` artık
         *  kendi arka plan `HandlerThread`'inde çalışıyor (bkz. o alanın
         *  dokümantasyonu), ama `addMessageListener`/`removeMessageListener`
         *  hâlâ Activity'lerin `onResume`/`onPause`'undan, yani ANA
         *  thread'den çağrılıyor. Düz bir `mutableListOf` (ArrayList) burada
         *  GÜVENLİ DEĞİLDİR — bir thread `forEach` ile üzerinde gezinirken
         *  başka bir thread `add`/`remove` çağırırsa `ConcurrentModificationException`
         *  ya da dahili dizi durumunun bozulması riski var (poll döngüsü
         *  saniyede bir çalıştığından, bir sohbet ekranının açılıp
         *  kapanmasıyla çakışması gerçek bir zamanlama penceresi). Okumalar
         *  (her poll turunda) yazmalardan (yalnızca ekran geçişlerinde) çok
         *  daha sık olduğundan `CopyOnWriteArrayList` tam bu desen için
         *  tasarlanmış: yazmalar dizinin kopyasını alır, okumalar (iterasyon)
         *  hiç kilitlenmeden mevcut anlık görüntü üzerinde güvenle çalışır. */
        private val listeners = java.util.concurrent.CopyOnWriteArrayList<(String) -> Unit>()

        /** bkz. `nextPollDelayMs` dokümantasyonu: poll döngüsü arka planda
         *  boşta beklerken aralığını genişletebilir (üstel değil, kademeli
         *  ve sınırlı) — bir ekran (`addMessageListener`) tam o genişlemiş
         *  bekleme ortasında açılırsa, halihazırda kuyruklanmış GECİKMELİ
         *  `postDelayed` çağrısı bitene kadar (en fazla
         *  aşağıdaki kademelerden biri) yeni ekranın hızlı tur beklentisini
         *  karşılamazdı. Servis örneği çalışırken bu, o kuyruklanmış
         *  çağrıyı iptal edip HEMEN yeni bir tur tetikler — bir ekran
         *  açılır açılmaz gecikme her zaman anında sıfırlanır. */
        @Volatile
        private var wakePollNow: (() -> Unit)? = null

        fun addMessageListener(listener: (String) -> Unit) {
            listeners.add(listener)
            // Bir sohbet ekranı açıldı: güç tasarrufundan ÇIK ve hemen bir
            // tur at — kullanıcı gecikme hissetmesin.
            try {
                P2PLib.setPowerSave(false)
            } catch (e: Exception) {
            }
            wakePollNow?.invoke()
        }

        fun removeMessageListener(listener: (String) -> Unit) {
            listeners.remove(listener)
        }

        /**
         * Spec dışı: şu an EKRANDA açık olan sohbetin kimliği — 1:1 için
         * `peer_device_fingerprint`, grup için `"group:$group_id"`
         * (ChatActivity/GroupChatActivity onResume/onPause'da set/clear
         * eder). Bir mesaj bu konuşmaya aitse bildirim GÖSTERİLMEZ (zaten
         * ekranda canlı görünüyor) — başka HERHANGİ bir konuşmaya aitse
         * (veya hiçbir sohbet açık değilse) bildirim gösterilir.
         *
         * Spec dışı, kararlılık denetimi düzeltmesi: `maybeNotify` artık
         * `pollRunnable`'ın arka plan `HandlerThread`'inden okunuyor
         * (bkz. o alanların dokümantasyonu), yazma ise Activity'lerin ANA
         * thread'inden geliyor. `@Volatile` olmadan bir thread'in yazdığı
         * yeni değer diğer thread'e (CPU önbelleği/derleyici yeniden
         * sıralaması yüzünden) hiç görünmeyebilir/gecikebilir — pratik
         * sonucu, bir sohbet ekranı açılır açılmaz artık gösterilmemesi
         * gereken bir bildirimin kısa bir süre daha görünmeye devam etmesi
         * (çökme riski yok, ama yanlış davranış). `@Volatile` her okumanın
         * en güncel yazılan değeri görmesini garanti eder.
         */
        @Volatile
        var activeConversationId: String? = null

        /** Spec 4.3: Node modu — kullanıcı ayarlardan açıp kapatabilir. */
        fun isNodeModeEnabled(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getBoolean(KEY_NODE_MODE, false)
        }

        fun setNodeModeEnabled(context: Context, enabled: Boolean) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putBoolean(KEY_NODE_MODE, enabled).apply()
            // Zaten çalışan bir ağ varsa canlı olarak da güncelle.
            P2PLib.setNodeMode(enabled)
        }

        /** Spec dışı, kullanıcı isteği (Tor onion) — node modu gibi kalıcı
         *  bir tercih. `setNodeMode`'un aksine CANLI toggle YOK: Tor transport'u
         *  ancak `startNetwork`'te eklenebildiğinden, değişiklik ağ katmanı
         *  yeniden başlayınca geçerli olur (bkz. tor.rs / lib.rs start_network).
         *
         *  Spec dışı, kullanıcı isteği: varsayılan olarak AÇIK — kutudan
         *  çıktığı gibi CGNAT arkasındaki iki cihaz bile hiçbir ayar
         *  değiştirmeden birbirine ulaşabilsin diye (bkz. tor.rs/SECURITY.md
         *  "Tor onion" notu). Bu varsayılan SADECE anahtar hiç yazılmamışsa
         *  (ilk kurulum) geçerli — kullanıcı Ayarlar'dan kapatırsa bu tercih
         *  kalıcı olarak saklanır, bir sonraki açılışta tekrar AÇIK'a dönmez. */
        fun isTorEnabled(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getBoolean(KEY_TOR_ENABLED, true)
        }

        fun setTorEnabled(context: Context, enabled: Boolean) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putBoolean(KEY_TOR_ENABLED, enabled).apply()
        }

        /** Spec dışı, kullanıcı isteği: Ayarlar'daki geçmiş/ek depolama
         *  sınırı slider'ı — sadece node modu açıkken anlamlı (bkz.
         *  Rust `enforce_history_storage_limit`), ama tercih her zaman
         *  kalıcılaştırılır. */
        fun getHistoryStorageLimitBytes(context: Context): Long {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return prefs.getLong(KEY_HISTORY_STORAGE_LIMIT, DEFAULT_HISTORY_STORAGE_LIMIT_BYTES)
        }

        fun setHistoryStorageLimitBytes(context: Context, bytes: Long) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putLong(KEY_HISTORY_STORAGE_LIMIT, bytes).apply()
            // Zaten çalışan bir ağ varsa canlı olarak da güncelle (sınır
            // düşürüldüyse en eski dosyalar hemen silinir).
            P2PLib.setHistoryStorageLimitBytes(bytes)
        }
    }

    // bkz. `pollThread`/`activeConversationId` dokümantasyonu — bu artık
    // arka plan poll thread'inden okunuyor, ana thread'den (onStartCommand/
    // onDestroy) yazılıyor; `@Volatile` görünürlük garantisi için.
    @Volatile
    private var isRunning = false

    /* --- Pil düzeltmesi (2026-08-28): bkz. companion object'teki not. --- */

    /** Cihazın ekranı açık mı. `ACTION_SCREEN_ON/OFF` yayınıyla güncelleniyor
     *  — bu iki yayın manifest'ten dinlenemiyor, çalışma anında kaydedilmek
     *  ZORUNDA. */
    @Volatile
    private var screenOn = true

    /** Çekirdekte gerçekten iş var mı (bkz. Rust `has_pending_work`).
     *  Her turda sormuyoruz: sorgunun kendisi de bir JNI çağrısı ve global
     *  kilit alıyor. Yalnızca boş turlarda, seyrek olarak tazeleniyor. */
    @Volatile
    private var coreBusy = true
    private var lastBusyCheckAt = 0L

    private var screenReceiver: android.content.BroadcastReceiver? = null

    /**
     * Spec dışı, gerçek cihazda ölçülen hata düzeltmesi.
     *
     * Android 14+ `dataSync` ön plan servisini "app idle" gerekçesiyle
     * DURDURUYOR — logcat'te görüldü: 14 MB'lık bir dosya sunucuya
     * yüklenirken servis öldü, yükleme hiçbir hata üretmeden sessizce durdu
     * ve `pollNetwork` bir daha hiç çağrılmadı. Kullanıcıya gönderdiği dosya
     * "gönderildi" görünüyordu ama sunucuya hiç ulaşmamıştı.
     *
     * Kısmi wake lock, aktarım sürerken CPU'nun uykuya dalmasını engeller.
     * Tek başına yeterli DEĞİL (pil optimizasyonu muafiyeti de gerekiyor,
     * bkz. `SettingsFragment` — ama o kullanıcının onayına bağlı, bu değil).
     */
    private var wakeLock: android.os.PowerManager.WakeLock? = null
    @Volatile private var wakeTimed = false
    private var wifiNetworkCallback: ConnectivityManager.NetworkCallback? = null
    /** bkz. `observeNetworkChangesForReconnect` — `wifiNetworkCallback`'ten
     *  (WiFi'ye ÖZEL, sadece süreç bağlama amaçlı) AYRI, HERHANGİ bir
     *  varsayılan ağ değişikliğini izleyen callback. */
    private var defaultNetworkCallback: ConnectivityManager.NetworkCallback? = null
    // Spec dışı, performans/kararlılık denetimi düzeltmesi: bu servis
    // süresiz olarak HER SANİYE `P2PLib.pollNetwork()` (JNI: mesaj çözme,
    // ratchet kriptografisi, DB arşivleme, gossipsub/dosya-teklifi olay
    // işleme) çalıştırıyor. Önceden ana (UI) thread'inin `Handler`'ıyla
    // zamanlanıyordu — bu, birkaç yüz milisaniyeyi aşan HERHANGİ bir poll
    // turunun (büyük bir `HistorySyncResponse`, grup fan-out'u, disk I/O
    // rekabeti altında yavaş bir SQLite yazımı) uygulamanın HER YERİNDE
    // (hangi ekran açık olursa olsun, servis Activity'den bağımsız
    // yaşadığından) dokunma girdisini bloklaması, 5 saniyeyi aşarsa ANR
    // diyaloğu göstermesi anlamına geliyordu. Artık kendi ayrık
    // `HandlerThread`'inde çalışıyor. Bu güvenli: `pollRunnable`'ın
    // çağırdığı `listeners` zaten UI'ya dokunan kısımlarını kendi
    // `runOnUiThread` sarmalayıcılarıyla koruyor (bkz.
    // ChatActivity/GroupChatActivity `messageListener`), `maybeNotify` ise
    // sadece `NotificationManager`/basit bir `var` okuması yapıyor — ikisi
    // de herhangi bir thread'den güvenle çağrılabilir.
    private val pollThread = HandlerThread("P2PPollThread").apply { start() }
    private var handler: Handler = Handler(pollThread.looper)
    /** Spec dışı, pil sağlamlığı düzeltmesi: `pollRunnable` önceden sabit
     *  1sn'de, süresiz olarak çalışıyordu — bu, bir sohbet ekranı asla
     *  açılmasa bile arka planda süresiz her saniye bir JNI çağrısı (Rust
     *  tarafında `poll_events` — swarm taraması, `reconnect_sweep`,
     *  `retry_unconfirmed_messages` vb.) demekti, bu da modern güç
     *  modellerinde asıl maliyeti oluşturan şeydir (uyanma SAYISI, tek bir
     *  uyanmanın maliyetinden çok daha ağır basar). Mesaj kaybı/gecikmesi
     *  YARATMADAN bunu azaltmak için: HERHANGİ bir ekran dinliyorsa
     *  (`listeners` dolu — kullanıcı O AN uygulamayla etkileşimde) hız HİÇ
     *  değişmez (`POLL_INTERVAL_ACTIVE_MS`). Arka planda VE art arda birkaç
     *  tur boyunca hiçbir olay gelmediyse (`consecutiveEmptyPolls`), aralık
     *  kademeli olarak genişler (bkz. `nextPollDelayMs`) — bir
     *  mesaj ASLA kaybolmaz, sadece boşta beklerken en fazla birkaç saniye
     *  ek gecikmeyle teslim edilir. Gerçek bir olay (mesaj/ack/vb.) ya da
     *  bir ekranın tekrar açılması aralığı ANINDA 1sn'ye sıfırlar.
     */
    private var consecutiveEmptyPolls = 0
    /** Bir sonraki turun başında `waitForNetworkActivity` ile beklenecek süre. */
    @Volatile private var pendingWaitMs = 0L
    private val pollRunnable = object : Runnable {
        override fun run() {
            if (isRunning) {
                // bkz. aşağıda `pendingWaitMs`: sabit gecikme yerine ağ olayını bekle.
                val waitMs = pendingWaitMs
                pendingWaitMs = 0L
                if (waitMs > 0L) {
                    try { P2PLib.waitForNetworkActivity(waitMs) } catch (e: Throwable) {}
                    // Derin boşta kilit yok: ağ olayı CPU'yu uyandırdı, işlem
                    // bitene kadar kısa zamanlı kilit tut (mesaj kaçmasın).
                    acquireWakeLock(20_000L)
                }
                // An uncaught exception here (pollNetwork, a listener, or
                // notify) would skip postDelayed below and permanently stop
                // all polling for the life of the process, so it must not
                // escape this loop.
                try {
                    val messages = P2PLib.pollNetwork()
                    if (messages.any { it.isNotEmpty() }) {
                        consecutiveEmptyPolls = 0
                    } else {
                        consecutiveEmptyPolls++
                    }
                    for (msg in messages) {
                        if (msg.isNotEmpty()) {
                            listeners.forEach { it(msg) }
                            maybeNotify(msg)
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.e("P2PService", "Poll cycle failed", e)
                } finally {
                    // Pil düzeltmesi: her turdan sonra hangi kademede
                    // olduğumuza yeniden karar ver.
                    refreshCoreBusy()
                    if (inDeepIdle()) {
                        // Derin boşta: wake lock BIRAKILIYOR, böylece işlemci
                        // gerçekten uyuyabiliyor. Cihaz uykuya dalarsa
                        // `postDelayed` (uptime tabanlı) durur — bu yüzden
                        // Doze altında da ateşleyen bir alarm kuruluyor.
                        // Kilitsiz ama uyanık-bekleyen: Rust'ta ağ olayını bekle
                        // (gelen bayt CPU'yu uyandırır → mesaj gecikmez). Doze
                        // alarmı yedek.
                        releaseWakeLock()
                        scheduleDozeWakeup()
                        pendingWaitMs = nextPollDelayMs()
                        handler.removeCallbacks(this)
                        handler.post(this)
                    } else {
                        acquireWakeLock()
                        cancelDozeWakeup()
                        // Uyanık modda bekleme Rust'ta: gelen bayt ya da giden
                        // mesaj beklemeyi anında bitirir (önceden her yön ~1 sn
                        // poll turunu bekliyordu). Aynı runnable iki kez
                        // kuyruklanmasın diye önce kaldırılıyor.
                        pendingWaitMs = nextPollDelayMs()
                        handler.removeCallbacks(this)
                        handler.post(this)
                    }
                }
            }
        }
    }

    /**
     * Yoklama aralığı — bkz. companion object'teki pil notu.
     *
     * Sıra önemli: en hızlı koşul en üstte. Bir sohbet ekranı açıksa hiçbir
     * şey değişmez, kullanıcı gecikme hissetmez.
     */
    private fun nextPollDelayMs(): Long {
        // 1) Kullanıcı O AN bir sohbete bakıyor.
        if (listeners.isNotEmpty()) return POLL_INTERVAL_ACTIVE_MS
        // 2) Yeni bir olay geldi ya da henüz yeterince sessizlik yok —
        //    eski davranışın aynısı (1sn -> 2sn kademeli).
        if (consecutiveEmptyPolls < POLL_IDLE_BACKOFF_THRESHOLD) return POLL_INTERVAL_ACTIVE_MS
        if (screenOn) {
            val idleSteps = consecutiveEmptyPolls - POLL_IDLE_BACKOFF_THRESHOLD
            val delay = POLL_INTERVAL_SCREEN_ON_MS + idleSteps * POLL_IDLE_STEP_MS
            return delay.coerceAtMost(POLL_INTERVAL_SCREEN_ON_MS + POLL_IDLE_STEP_MS * 2)
        }
        // 3) Ekran kapalı. Çekirdekte iş varsa (bağlı eş, bekleyen mesaj,
        //    süren indirme) hâlâ makul sıklıkta yoklanır.
        if (coreBusy || consecutiveEmptyPolls < DEEP_IDLE_AFTER_EMPTY_POLLS) {
            return POLL_INTERVAL_SCREEN_OFF_MS
        }
        // 4) Ekran kapalı VE çekirdek tamamen boşta.
        return POLL_INTERVAL_DEEP_IDLE_MS
    }

    /** Derin boşta mıyız — wake lock'ın bırakıldığı tek durum. */
    private fun inDeepIdle(): Boolean =
        !screenOn && listeners.isEmpty() && !coreBusy &&
            consecutiveEmptyPolls >= DEEP_IDLE_AFTER_EMPTY_POLLS

    /**
     * Çekirdeğin meşgul olup olmadığını seyrek olarak tazeler.
     *
     * Sorgunun kendisi de bir JNI çağrısı ve global kilit alıyor, o yüzden
     * her turda yapılmıyor: yalnızca ekran kapalıyken ve en fazla 15
     * saniyede bir. Ekran açıkken zaten hızlı turdayız, cevabı önemsiz.
     */
    private fun refreshCoreBusy() {
        if (screenOn) { coreBusy = true; return }
        val now = android.os.SystemClock.elapsedRealtime()
        if (now - lastBusyCheckAt < 15000L) return
        lastBusyCheckAt = now
        coreBusy = try {
            JSONObject(P2PLib.ownConnectionStatus()).optBoolean("busy", true)
        } catch (e: Exception) {
            // Emin olamıyorsak MEŞGUL varsay — yanılıp mesaj geciktirmektense
            // biraz fazla uyanmak yeğ.
            true
        }
    }

    /**
     * Ekran durumunu izler. Bu iki yayın (`ACTION_SCREEN_ON`/`OFF`)
     * manifest'ten dinlenemez, çalışma anında kaydedilmek zorunda.
     */
    private fun observeScreenState() {
        val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        screenOn = pm.isInteractive
        applyPowerSave()
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON -> {
                        screenOn = true
                        coreBusy = true
                        consecutiveEmptyPolls = 0
                        applyPowerSave()
                        // Ekran açıldı: gecikmeyi hemen kapat.
                        acquireWakeLock()
                        handler.removeCallbacks(pollRunnable)
                        handler.post(pollRunnable)
                    }
                    Intent.ACTION_SCREEN_OFF -> {
                        screenOn = false
                        lastBusyCheckAt = 0L
                        applyPowerSave()
                    }
                }
            }
        }
        screenReceiver = receiver
        val filter = android.content.IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        try {
            // API 34+ yayın alıcıları için dışa açıklık bayrağı istiyor.
            // `ACTION_SCREEN_ON/OFF` korumalı sistem yayınları olduğu için
            // teknik olarak muaf, ama açıkça NOT_EXPORTED demek hem doğru
            // hem de ileride bir sistem-dışı eylem eklenirse çökmeyi önler.
            androidx.core.content.ContextCompat.registerReceiver(
                this, receiver, filter,
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
            )
        } catch (e: Exception) {
            Log.w(TAG, "Ekran durumu izlenemedi: ${e.message}")
        }
    }

    /** bkz. Rust `set_power_save` — sessiz bekleyen bağlantıların canlılık
     *  yoklaması 20sn yerine 60sn'de bir yapılır, radyo uzun uyuyabilir. */
    private fun applyPowerSave() {
        val enabled = !screenOn && listeners.isEmpty()
        try {
            P2PLib.setPowerSave(enabled)
        } catch (e: Exception) {
            Log.w(TAG, "Güç tasarrufu modu ayarlanamadı: ${e.message}")
        }
    }

    /**
     * Derin boştayken wake lock bırakıldığı için cihaz uykuya dalabilir ve
     * `Handler.postDelayed` (uptime tabanlı) durur. Bu alarm, Doze altında
     * bile periyodik bir uyanma garantisi veriyor.
     */
    private fun scheduleDozeWakeup() {
        try {
            val am = getSystemService(Context.ALARM_SERVICE) as android.app.AlarmManager
            val intent = Intent(this, P2PService::class.java).setAction(ACTION_WAKE_POLL)
            val pending = android.app.PendingIntent.getService(
                this, 0, intent,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
            )
            am.setAndAllowWhileIdle(
                android.app.AlarmManager.ELAPSED_REALTIME_WAKEUP,
                android.os.SystemClock.elapsedRealtime() + DOZE_WAKE_INTERVAL_MS,
                pending
            )
        } catch (e: Exception) {
            Log.w(TAG, "Doze uyandırma alarmı kurulamadı: ${e.message}")
        }
    }

    private fun cancelDozeWakeup() {
        try {
            val am = getSystemService(Context.ALARM_SERVICE) as android.app.AlarmManager
            val intent = Intent(this, P2PService::class.java).setAction(ACTION_WAKE_POLL)
            val pending = android.app.PendingIntent.getService(
                this, 0, intent,
                android.app.PendingIntent.FLAG_NO_CREATE or android.app.PendingIntent.FLAG_IMMUTABLE
            )
            if (pending != null) am.cancel(pending)
        } catch (e: Exception) {
            // yoksay
        }
    }

    /**
     * Google Play Services/FCM'ye bağımlı OLMAYAN, tamamen lokal bildirim
     * sistemi (bkz. NotificationHelper dosya başı notu) — bu servis zaten
     * her saniye ağı taradığından ayrı bir push altyapısına gerek yok.
     * SADECE gerçek yeni mesajlar ("message"/"group_message") bildirim
     * üretir; edit/delete/status olayları sessizdir. İlgili sohbet ekranda
     * açıksa (activeConversationId eşleşiyorsa) bildirim BASTIRILIR — zaten
     * canlı görünüyor.
     */
    private fun maybeNotify(json: String) {
        val obj = try {
            JSONObject(json)
        } catch (e: Exception) {
            return
        }
        when (obj.optString("type")) {
            "sync", "device_linked" -> com.p2p.messenger.util.ArchiveKeyManager.persistIfNew(applicationContext)
            "account_deleted" -> NotificationHelper.showAccountDeletedNotification(
                applicationContext, obj.optString("peer"), obj.optString("display_name")
            )
            // Spec dışı (dış AI incelemesi düzeltmesi — AI2-G, self-revocation):
            // bu cihaz KENDİ kimliği (birincil cihaz) tarafından iptal edildi.
            // Rust çekirdeği DB tablolarını + ekleri zaten sildi ve artık
            // inert; burada UI tarafındaki KALICI sırrı (Keystore-sarılı
            // secret bundle dosyası) ve DB dosyasını da silip TEMİZ bir
            // süreçte onboarding'e yeniden başlatıyoruz — SettingsFragment.
            // performLogout ile AYNI adımlar (aynı gerekçe: canlı süreçte
            // kimliği sıfırlamak yerine dosyaları silip temiz başlamak).
            "self_revoked" -> {
                // Bu denetimde bulundu: burası `identity_secret.enc` dışındaki
                // Keystore-sarılı anahtarları (geçmiş anahtarı, skipped-key
                // anahtarı ve en önemlisi SUNUCUDAKİ arşivi çözen ARK)
                // bırakıyordu — oysa bu kolun var olma sebebi "cihazım
                // çalındı, uzaktan iptal ediyorum". Tek ortak yola alındı:
                // bkz. `util.LocalWipe`.
                com.p2p.messenger.util.LocalWipe.wipe(applicationContext)
                NotificationHelper.showDeviceRevokedNotification(applicationContext)
                com.p2p.messenger.util.AppRestarter.restart(applicationContext)
            }
            // Çoklu-cihaz (spec 1.7.1): başka bir cihazımız bu sohbeti okudu —
            // burada da okunmuş say (böylece sohbet listesi okunmamış
            // göstermez). Rust bu olayı yalnızca bir kardeş cihazdan gelen
            // ReadStateSync için üretir ve "conversation"ı bu cihazdaki yerel
            // sohbet anahtarına (kanonik cihaz fp'si veya "group:<id>") çevirir.
            "read_state_sync" -> {
                val conv = obj.optString("conversation")
                val readAt = obj.optLong("read_at")
                if (conv.isNotEmpty() && readAt > 0L) {
                    ReadStatePrefs.markReadAt(applicationContext, conv, readAt)
                    // Bu denetimde bulundu: sohbet okunmuş işaretleniyordu ama
                    // bildirim çubuğunda ASILI KALAN bildirim kaldırılmıyordu.
                    // Gerçek senaryo: masaüstünde (ya da öteki telefonda)
                    // sohbeti okuyorsun, bu cihazda aynı mesajın bildirimi
                    // durmaya devam ediyor — "okuduğum şey hâlâ okunmamış
                    // görünüyor". Sohbet listesi zaten düzeliyordu, sadece
                    // bildirim geride kalıyordu.
                    if (conv.startsWith("group:")) {
                        NotificationHelper.clearForGroup(applicationContext, conv.removePrefix("group:"))
                    } else {
                        NotificationHelper.clearForPeer(applicationContext, conv)
                    }
                }
            }
            "message" -> {
                val peer = obj.optString("peer")
                if (peer.isNotEmpty() && activeConversationId != peer) {
                    NotificationHelper.showMessageNotification(applicationContext, peer, obj.optString("text"))
                }
            }
            "group_message" -> {
                val groupId = obj.optString("group_id")
                if (groupId.isNotEmpty() && activeConversationId != "group:$groupId") {
                    NotificationHelper.showGroupMessageNotification(
                        applicationContext, groupId, obj.optString("sender_identity_id"), obj.optString("text")
                    )
                }
            }
            // Spec dışı, hata düzeltmesi ("silinen/düzenlenen mesajın
            // bildirimi bildirim çubuğunda eski haliyle asılı kalıyor"):
            // önceden edit/delete olayları burada hiç ele alınmıyordu — bir
            // mesaj, arkaplandaki bildirimi henüz görülmemişken silinir/
            // düzenlenirse bildirim SONSUZA DEK eski (artık geçersiz/silik)
            // metniyle asılı kalırdı. Bildirimler sohbet başına TEK slotta
            // toplandığından (bkz. `show` notu) hangi TEK mesaja ait olduğunu
            // kesin bilemeyiz — bu yüzden silme bildirimi tamamen temizler
            // (en güvenli/kabul edilebilir davranış), düzenleme ise SADECE
            // o an ekranda asılı bir bildirim varsa güncellenir (yoksa
            // kullanıcı zaten görmüş/kapatmıştır, düzenleme için yeniden
            // bildirim göstermenin bir anlamı yok).
            "delete" -> {
                val peer = obj.optString("peer")
                if (peer.isNotEmpty()) NotificationHelper.clearForPeer(applicationContext, peer)
            }
            // Defter #16: Rust bu olayı hem depolama sınırı tahliyesinde hem
            // de ekli bir mesaj silindiğinde üretiyordu ama HİÇBİR istemci
            // dinlemiyordu — balon "tamamlandı" görünmeye devam ediyor,
            // kullanıcı dokununca dosya yok. Sohbet ekranları bunu
            // `messageListener` üzerinden alıyor; burada sadece bildirim
            // tarafında bir şey yapmıyoruz (kasıtlı), olayın düşmesi yeterli.
            "file_evicted" -> { }
            // Kullanıcı kararı: tanınmayan cihaz uyarısı artık bildirim
            // olarak da çıkıyor (bkz. NotificationHelper.showDeviceAlertNotification).
            // Ana ekran ön plandaysa dialog zaten açılıyor; bu, uygulama
            // arka plandayken veya başka bir ekrandayken uyarının tamamen
            // kaybolmasını engelliyor.
            "device_alert" -> {
                NotificationHelper.showDeviceAlertNotification(
                    applicationContext,
                    obj.optString("contact_display_name"),
                    obj.optString("device_short_code")
                )
            }
            "group_delete" -> {
                val groupId = obj.optString("group_id")
                if (groupId.isNotEmpty()) NotificationHelper.clearForGroup(applicationContext, groupId)
            }
            "edit" -> {
                val peer = obj.optString("peer")
                if (peer.isNotEmpty() && activeConversationId != peer) {
                    NotificationHelper.updateMessageNotificationIfShowing(applicationContext, peer, obj.optString("text"))
                }
            }
            "group_edit" -> {
                val groupId = obj.optString("group_id")
                if (groupId.isNotEmpty() && activeConversationId != "group:$groupId") {
                    NotificationHelper.updateGroupMessageNotificationIfShowing(applicationContext, groupId, obj.optString("text"))
                }
            }
            // Spec dışı, kullanıcı isteği: EKLER de bildirim üretsin —
            // önceden sadece metin mesajları bildirim üretiyordu, biri
            // fotoğraf/dosya gönderdiğinde hiçbir uyarı gelmiyordu.
            "file_offer" -> {
                val groupId = if (obj.isNull("group_id")) "" else obj.optString("group_id")
                val label = attachmentNotificationLabel(
                    obj.optString("mime_type", ""), obj.optString("file_name", "")
                )
                if (groupId.isNotEmpty()) {
                    if (activeConversationId != "group:$groupId") {
                        NotificationHelper.showGroupMessageNotification(
                            applicationContext, groupId, obj.optString("sender_identity_id"), label
                        )
                    }
                } else {
                    val peer = obj.optString("peer")
                    if (peer.isNotEmpty() && activeConversationId != peer) {
                        NotificationHelper.showMessageNotification(applicationContext, peer, label)
                    }
                }
            }
        }
    }

    /** Ek bildirimi için kısa etiket (bkz. `maybeNotify` "file_offer"). */
    private fun attachmentNotificationLabel(mimeType: String, fileName: String): String = when {
        mimeType.startsWith("image/") -> getString(R.string.lbl_last_photo)
        mimeType.startsWith("video/") -> getString(R.string.lbl_last_video)
        mimeType.startsWith("audio/") -> getString(R.string.lbl_last_voice)
        fileName.isNotEmpty() -> "📎 $fileName"
        else -> getString(R.string.lbl_last_file)
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        NotificationHelper.createChannel(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Spec dışı, hata düzeltmesi (kullanıcı: "bildirimde Typeon değil
        // Android logosu görünüyor"): bu SÜREKLİ görünen (ön plan servisi)
        // bildirimi `ic_launcher_foreground` kullanıyordu — TAM RENKLİ bir
        // adaptive-icon katmanı, geçerli bir bildirim siluet DEĞİL. Aynı hata
        // daha önce mesaj bildirimlerinde (bkz. NotificationHelper.kt)
        // `ic_notification`'a geçilerek düzeltilmişti, ama BU çağrı noktası
        // atlanmıştı — ve bu, uygulama çalışırken HER ZAMAN görünen bildirim
        // olduğundan en görünür olanıydı.
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Typeon")
            .setContentText("Secure P2P Connection Active")
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .build()

        startForeground(NOTIFICATION_ID, notification)
        acquireWakeLock()

        // Doze uyandırma alarmından geldiysek servis zaten çalışıyor; tek
        // yapılacak hemen bir tur atmak (bkz. `scheduleDozeWakeup`).
        if (intent?.action == ACTION_WAKE_POLL && isRunning) {
            consecutiveEmptyPolls = 0
            lastBusyCheckAt = 0L
            handler.removeCallbacks(pollRunnable)
            handler.post(pollRunnable)
            return START_STICKY
        }

        if (!isRunning) {
            isRunning = true
            // bkz. `bindToWifiIfAvailable` dokümantasyonu — libp2p soketleri
            // (özellikle UPnP arama) `startNetwork`'ten ÖNCE doğru arayüze
            // (WiFi) bağlanabilsin diye burada, ağ başlamadan hemen önce.
            bindToWifiIfAvailable()
            // Pil düzeltmesi: ekran durumu, yoklama kademesinin en güçlü
            // sinyali (bkz. companion object'teki not).
            observeScreenState()
            // Spec dışı, kullanıcı isteği ("connection testing and
            // re-connecting automatically should be better") — bkz.
            // `observeNetworkChangesForReconnect` dokümantasyonu.
            observeNetworkChangesForReconnect()
            // Güvenlik ağı: sistem bu servisi MainActivity'den bağımsız
            // olarak yeniden başlatırsa (START_STICKY sonrası süreç
            // öldürülüp geri getirilirse), initDatabase VE secret key
            // yükleme hiç çağrılmamış olabilir. Bu çağrılar idempotent —
            // initDatabase zaten açık bir bağlantıyı tekrar açmak
            // zararsızdır (SQLite yeniden CREATE TABLE IF NOT EXISTS
            // çalıştırır), loadIfPresent de zaten yüklenmiş key'lerin
            // üzerine aynı değerleri yazar.
            // Spec dışı, hata düzeltmesi (cihazda ÖLÇÜLEN ANR — bkz.
            // /data/anr izi): aşağıdaki altı çağrının hepsi ağır JNI +
            // SQLite işi ve TAMAMI ANA THREAD'de çalışıyordu. Yakalanan
            // yığın izinde ana thread `SkippedKeyManager.ensureLoaded` ->
            // JNI -> `fsync()` içinde, `state=D` (kesintisiz disk
            // beklemesi) donmuştu; sonuç "Input dispatching timed out"
            // ANR'ı ve kullanıcı gözünde "uygulama çöküyor".
            //
            // Tetikleyici sık: `MainActivity.onResume` her dönüşte
            // `startNetworkService()` çağırıyor ve süreç OS tarafından
            // öldürülüp START_STICKY ile geri getirildiğinde bu blok
            // yeniden çalışıyor.
            //
            // `handler` zaten ayrı bir `HandlerThread`'e (pollThread) bağlı
            // ve SIRALI: init'i ona post edip HEMEN ardından `pollRunnable`ı
            // post etmek, yoklamanın init'ten önce çalışmamasını da
            // kendiliğinden garanti eder. `startForeground` ANA THREAD'de
            // kaldı — Android onu 5 sn içinde orada bekliyor.
            handler.post {
                P2PLib.initDatabase(applicationContext.filesDir.absolutePath)
                if (P2PLib.hasStoredIdentity()) {
                    com.p2p.messenger.util.IdentityManager.loadIfPresent(applicationContext)
                }
            // Node modundan BAĞIMSIZ her zaman yüklenir — mesajlaşmanın
            // güvenilirliği için gerekli (sıra dışı/gecikmeli mesajlar).
                com.p2p.messenger.util.SkippedKeyManager.ensureLoaded(applicationContext)
            // Spec dışı düzeltme: önceden SADECE node modu açıkken
            // yükleniyordu ("canlı mesaj trafiğini arşivleme" kuralı hâlâ
            // node moduna bağlı, bkz. Rust archive_message çağıranları) —
            // ama artık node modu KAPALI cihazlar da `HistorySyncResponse`
            // ile öğrendikleri geçmişi yerelde kalıcı kılmak için bu
            // anahtara ihtiyaç duyuyor (aksi halde uygulama her
            // kapatılıp açıldığında geçmiş "kayboluyormuş" gibi
            // görünüyordu — aslında her seferinde ağdan yeniden
            // çekilmesi gerekiyordu, karşı taraf o an erişilemezse bu
            // başarısız oluyordu).
                com.p2p.messenger.util.MessageHistoryManager.ensureHistoryKeyLoaded(applicationContext)
            // bkz. ArchiveKeyManager — sunucudaki geçmişi çözen kök arşiv
            // anahtarı (ARK). Yoksa burada ÜRETİLMEZ: sonradan bağlanan bir
            // cihaz kendi rastgele anahtarını üretirse yüklediği arşiv diğer
            // cihazlarda okunamaz olurdu; üretim sadece kullanıcı sunucuda
            // geçmiş saklamayı AÇTIĞINDA yapılır (bkz. SettingsFragment).
                com.p2p.messenger.util.ArchiveKeyManager.loadIfPresent(applicationContext)
                val nodeMode = isNodeModeEnabled(applicationContext)
                val torEnabled = isTorEnabled(applicationContext)
                P2PLib.startNetwork(nodeMode, torEnabled)
                P2PLib.setHistoryStorageLimitBytes(getHistoryStorageLimitBytes(applicationContext))
            }
            wakePollNow = {
                handler.removeCallbacks(pollRunnable)
                handler.post(pollRunnable)
            }
            handler.post(pollRunnable)
        }

        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        releaseWakeLock()
        wakePollNow = null
        handler.removeCallbacks(pollRunnable)
        cancelDozeWakeup()
        screenReceiver?.let {
            try {
                unregisterReceiver(it)
            } catch (e: Exception) {
            }
        }
        screenReceiver = null
        pollThread.quitSafely()
        wifiNetworkCallback?.let {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(it)
            } catch (e: Exception) {
                // Zaten kayıtlı değilse (ör. WiFi hiç bağlanmadıysa) sessizce yok say.
            }
        }
        wifiNetworkCallback = null
        defaultNetworkCallback?.let {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(it)
            } catch (e: Exception) {
                // yoksay
            }
        }
        defaultNetworkCallback = null
    }

    /** bkz. `wakeLock` alan notu. */
    private fun acquireWakeLock(timeoutMs: Long = 0L) {
        if (wakeLock?.isHeld == true) {
            // Zamanlı (kısa) kilit varsa ve süresiz istendiyse yükselt.
            if (timeoutMs != 0L || !wakeTimed) return
            releaseWakeLock()
        }
        wakeTimed = timeoutMs != 0L
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
            wakeLock = pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "Typeon:network")
                .also { it.setReferenceCounted(false); if (timeoutMs > 0) it.acquire(timeoutMs) else it.acquire() }
        } catch (e: Exception) {
            Log.w(TAG, "Wake lock alınamadı: ${e.message}")
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let { if (it.isHeld) it.release() }
        } catch (e: Exception) {
            // Zaten bırakılmışsa yok say.
        }
        wakeLock = null
    }

    /**
     * Spec dışı, kullanıcı isteği ("connection testing and re-connecting
     * automatically should be better"): `bindToWifiIfAvailable`'ın
     * WiFi'ye ÖZEL callback'inin aksine, bu HERHANGİ bir "varsayılan ağ"
     * değişikliğini (Wi-Fi<->hücresel geçiş, ağ tamamen kaybolup tekrar
     * kazanılması) yakalar ve Rust tarafına bildirir (bkz.
     * `P2PLib.notifyNetworkChanged`/lib.rs `reconnect_all_known_now`) —
     * ESKİ ağ üzerinden kurulmuş TÜM libp2p bağlantıları yeni arayüzde
     * artık geçersiz soketlerdir (yerel IP değişti), periyodik taramanın
     * (≤15sn) veya `ping`in (≤~25sn, aralık+zaman aşımı) bunu fark
     * etmesini beklemek yerine ANINDA tam bir yeniden bağlanma turu
     * tetiklenir. `onCapabilitiesChanged` KASITLI OLARAK dinlenmiyor —
     * bu çok daha sık (ör. sinyal gücü meta verisi değişince) tetiklenir
     * ve her seferinde tam bir yeniden bağlanma turu pil açısından
     * savurgan olurdu; `onAvailable`/`onLost` (varsayılan ağ TAMAMEN
     * değiştiğinde/kaybolduğunda) yeterince güvenilir VE seyrek bir
     * sinyal.
     */
    private fun observeNetworkChangesForReconnect() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // Spec dışı, hata düzeltmesi ("mobil veri+Tor'a geçen cihaz
                // Tor'a bağlı görünüp yeşil yanıyor ama kimseye ulaşamıyor"):
                // bkz. `refreshWifiBinding` dokümantasyonu — `wifiNetworkCallback`'in
                // KENDİ `onLost`'u, WiFi Android tarafından teknik olarak hâlâ
                // "kayıp" sayılmadığı (ör. sinyal zayıflayıp varsayılan rota
                // sessizce mobil veriye kaydığı, OEM'e özgü "WiFi uykuda" durumları)
                // ARA DURUMLARDA hiç tetiklenmeyebilir — süreç, artık gerçekte
                // kullanılamayan bir WiFi'ye SONSUZA DEK bağlı (`bindProcessToNetwork`)
                // kalabilir: Tor önceden bu WiFi üzerinden zaten "Ready" olmuş
                // olduğundan durum göstergesi yeşil kalmaya devam eder, ama
                // YENİ soketler (başka birinin `.onion`'una devre kurmak dahil)
                // sessizce bu artık ölü arayüzden çıkmaya çalışır. Varsayılan ağ
                // değişikliği bildirimi (bu callback) Android'in genel/güvenilir
                // sinyali olduğundan, bağlamayı da HER SEFERİNDE (WiFi'ye özel
                // callback'in kendi olaylarını beklemeden) doğru duruma göre
                // tazeliyoruz.
                refreshWifiBinding(cm)
                notifyNetworkChangedInBackground()
            }
            override fun onLost(network: Network) {
                refreshWifiBinding(cm)
                // Yeniden bağlanma YALNIZCA yeni varsayılan ağ geldiğinde
                // (`onAvailable`): ağ yokken yapılan dial/Tor denemeleri anında
                // "Network is unreachable" ile düşüyor ve arti'nin guard/devre
                // durumunu bozup yeni ağda toparlanmayı geciktiriyordu.
            }
        }
        defaultNetworkCallback = callback
        try {
            cm.registerDefaultNetworkCallback(callback)
        } catch (e: Exception) {
            // Kayıt başarısız olursa (ör. çok eski/tuhaf bir cihaz) sessizce
            // devam — periyodik `reconnect_sweep`/`ping` hâlâ (daha yavaş
            // ama) aynı sonuca ulaşır.
        }
    }

    /**
     * Spec dışı, hata düzeltmesi (bkz. `observeNetworkChangesForReconnect`
     * `onAvailable`/`onLost` notu): `bindToWifiIfAvailable`/`wifiNetworkCallback`
     * ile AYNI mantık — o an gerçekten doğrulanmış bir WiFi varsa sürece
     * bağlar, yoksa bağlamayı (varsa) serbest bırakır. Tek bir yerde
     * tutuluyor ki hem ilk kurulum hem de varsayılan ağ değişikliği
     * bildirimi AYNI kararı versin.
     */
    private fun refreshWifiBinding(cm: ConnectivityManager) {
        val active = cm.activeNetwork
        val activeCaps = active?.let { cm.getNetworkCapabilities(it) }
        if (activeCaps.isValidatedWifi()) {
            cm.bindProcessToNetwork(active)
        } else {
            cm.bindProcessToNetwork(null)
        }
    }

    /** JNI çağrısını ana thread dışında yapar — `ConnectivityManager`
     *  callback'leri genellikle ana thread'de çağrılır, `notifyNetworkChanged`
     *  (bir dial turu başlatabilir) burada onu bloklamamalı. */
    private fun notifyNetworkChangedInBackground() {
        Thread {
            try {
                P2PLib.notifyNetworkChanged()
            } catch (e: Exception) {
                // yoksay — periyodik sweep zaten yedek.
            }
        }.start()
    }

    /**
     * Spec dışı, hata ayıklama düzeltmesi: gerçek bir cihazda, router'da
     * UPnP açık olmasına rağmen UPnP taraması hep "gateway bulunamadı"
     * döndürdüğü rapor edildi. Kök sebep muhtemelen şu: Android telefonlar
     * genelde WiFi'ye bağlıyken bile mobil veriyi arka planda AÇIK tutar —
     * Rust tarafındaki UPnP arama soketi (igd_next crate'i) `0.0.0.0`'a
     * bind olur, yani HANGİ arayüzden çıkacağını işletim sisteminin
     * varsayılan yönlendirme tablosuna bırakır. Bu, WiFi yerine YANLIŞLIKLA
     * mobil veri üzerinden gönderilebilir — router hiç görmez, "bulunamadı"
     * sonucu WiFi UPnP'siyle hiç ilgisi olmadan ortaya çıkar (aynı sınıf
     * karışıklık teorik olarak libp2p'nin diğer soketlerini de
     * etkileyebilir).
     *
     * `ConnectivityManager.bindProcessToNetwork` bu süreçte AÇILAN TÜM yeni
     * soketleri (Rust tarafındakiler dahil, aynı process'te çalıştıkları
     * için) belirtilen ağa zorlar — WiFi varsa ona bağlanır, WiFi
     * kaybolursa serbest bırakılır (mobil veriye doğal olarak döner, ör.
     * hiç WiFi'si olmayan bir kullanıcı için).
     */
    private fun bindToWifiIfAvailable() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        // Spec dışı, hata ayıklama düzeltmesi: SADECE WiFi transport'u
        // kontrol etmek YETERSİZ — bir cihazın WiFi radyosu açık ve
        // bilinen/kayıtlı bir ağa bağlı olabilir ama o ağın GERÇEK internet
        // erişimi olmayabilir (ör. boşta duran bir ev ağı, portal arkasında
        // kalmış bir misafir ağı). Sadece transport'a bakıp bağlarsak, o an
        // mobil veri üzerinden ÇALIŞAN bir cihazı internetsiz bir WiFi'ye
        // zorlayıp TAMAMEN bağlantısız bırakabiliriz — NET_CAPABILITY_INTERNET
        // + NET_CAPABILITY_VALIDATED (sistem gerçekten "bu ağdan internete
        // çıkabiliyorum" diye doğruladı) ikisi de gerekli. bkz.
        // `refreshWifiBinding` — aynı karar mantığı burada da kullanılıyor.
        refreshWifiBinding(cm)
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            .build()
        // Defter #20: bu iki gövde eskiden KOŞULSUZ `bindProcessToNetwork`
        // çağırıyordu ve `defaultNetworkCallback`'in `refreshWifiBinding`
        // kararıyla yarışıyordu. Varsayılan ağ hücreselken bir Wi-Fi
        // belirirse süreç TÜM trafiği (Tor dahil) Wi-Fi'ye bağlanıyor; ya da
        // `onLost` geçerli bir bağı geri alıyordu — sonuç hangi geri
        // çağrının son geldiğine bağlıydı. Artık tek karar noktası var.
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                refreshWifiBinding(cm)
            }
            override fun onLost(network: Network) {
                refreshWifiBinding(cm)
            }
        }
        wifiNetworkCallback = callback
        try {
            cm.registerNetworkCallback(request, callback)
        } catch (e: Exception) {
            // Kayıt başarısız olursa (ör. çok eski/tuhaf bir cihaz) sessizce
            // devam — süreç varsayılan sistem yönlendirmesini kullanır,
            // bugünkünden daha kötü olmaz.
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "P2P Background Service",
            NotificationManager.IMPORTANCE_LOW
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }
}
