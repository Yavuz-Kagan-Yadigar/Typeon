package com.p2p.messenger.util

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.util.Base64
import com.p2p.messenger.ui.AppLockActivity
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Spec dışı, kullanıcı isteği: uygulamayı açmak için bir şifre.
 *
 * Şifrenin KENDİSİ hiçbir yerde saklanmaz — rastgele bir tuzla (salt)
 * birlikte PBKDF2-HMAC-SHA256 türevi saklanır. Bu, cihaz belleğine erişen
 * birinin şifreyi doğrudan okumasını engeller; yüksek iterasyon sayısı da
 * kaba kuvvet denemesini pahalılaştırır. (Bu kilit, uygulamanın uçtan uca
 * şifrelemesinden BAĞIMSIZ bir katman: kimlik/ratchet anahtarları zaten
 * Android Keystore ile korunuyor — bkz. `KeystoreCrypto` — bu ekran
 * telefonu eline alan birine karşı arayüz düzeyinde bir engel.)
 *
 * Kullanıcı isteği: şifre "asla boş olmamalı" — bu yüzden hem ilk kurulum
 * (bkz. `AppLockActivity` CREATE modu) hem de değiştirme (bkz.
 * SettingsFragment) akışında boş bir değer kabul edilmez ve şifreyi
 * TAMAMEN kaldırmanın bir yolu yoktur.
 */
object AppLock {
    private const val PREFS_NAME = "p2p_settings"
    private const val KEY_SALT = "app_lock_salt"
    private const val KEY_HASH = "app_lock_hash"
    private const val KEY_ITERATIONS = "app_lock_iterations"

    /** GÜVENLİK DENETİMİ DÜZELTMESİ (2026-09-05): eski sabit 120.000'di —
     *  2018 civarı OWASP tavsiyesiydi, modern GPU/ASIC kaba kuvvetine karşı
     *  artık zayıf sayılıyor. Güncel OWASP tavsiyesi PBKDF2-HMAC-SHA256 için
     *  ≥600.000, ama bu her açılışta (bkz. AppLockActivity) hissedilir bir
     *  gecikme yaratır; 300.000 modern bir telefonda hâlâ ~300-500 ms'de
     *  kalıp sözlük saldırısını iki buçuk katına çıkarıyor — kabul edilebilir
     *  bir orta nokta.
     *
     *  Sabiti YÜKSELTMEK eski kurulumları KİLİTLEMEMELİ: hash'i hangi
     *  iterasyon sayısıyla türettiğimiz `KEY_ITERATIONS`'da AYRICA saklanır
     *  (bkz. `setPassword`/`verify`) — eski bir kayıtta bu alan yoksa eski
     *  sabit (120.000) varsayılır, yeni her `setPassword` çağrısı güncel
     *  sabitle yazar. Böylece kullanıcı şifresini bir dahaki DEĞİŞTİRMESİNDE
     *  sessizce güçlendirilmiş olur, mevcut şifresi bozulmaz. */
    private const val ITERATIONS = 300_000
    /** bkz. `ITERATIONS` dokümantasyonu — bu değeri yükseltmeden önce diske
     *  yazılmış kayıtların gerçek iterasyon sayısı. */
    private const val LEGACY_ITERATIONS = 120_000
    private const val KEY_LENGTH_BITS = 256
    const val MIN_PASSWORD_LENGTH = 6

    /** Süreç ömrü boyunca tutulan kilit durumu — DİSKE YAZILMAZ: süreç
     *  öldüğünde (ya da uygulama arka plana düşüp `lock()` çağrıldığında)
     *  şifre yeniden sorulur. */
    @Volatile private var unlocked = false

    /** Kilit ekranı zaten açık/açılmak üzereyken ikinci bir tane
     *  başlatmayı engeller (bkz. `guard` — HER Activity'nin `onStart`'ında
     *  çağrılıyor, art arda birkaç Activity başlarsa üst üste binerdi). */
    @Volatile private var promptShowing = false

    /** bkz. `beginTrustedExcursion` — bu ana kadar (elapsedRealtime) gelen
     *  İLK arka plan geçişi kilitlemeden geçer. Zaman damgası, düz bir
     *  bayrak DEĞİL: bkz. `TRUSTED_EXCURSION_WINDOW_MS`. */
    @Volatile private var excursionValidUntil = 0L

    /**
     * Bir "güvenli çıkış" işaretinin ne kadar süre geçerli olduğu.
     *
     * Kullanıcı raporu (2026-08-29): "bildirime tıklandığında şifresiz bir
     * şekilde açılıyor". Sebep, işaretin SÜRESİZ bir bayrak olmasıydı:
     * `beginTrustedExcursion()` çağrılıp da beklenen dış ekran HİÇ
     * açılmazsa (en somut örnek: Android 13+'ta iki kez reddedilmiş
     * `POST_NOTIFICATIONS` izni — `launch()` sistem diyaloğunu artık
     * GÖSTERMEZ, anında reddeder, uygulama arka plana hiç düşmez) bayrak
     * asılı kalıyor ve SIRADAKİ gerçek arka plan geçişini — yani
     * kullanıcının Home'a basmasını — kilitlemeden geçiriyordu. Uygulama o
     * andan sonra kilitsiz kalıyor, bildirimden açılınca da şifre
     * sorulmuyordu.
     *
     * Zaman penceresi bunu yapısal olarak kapatır: gerçekten başlattığımız
     * bir Activity bizi anında (milisaniyeler içinde) arka plana düşürür;
     * hiç açılmayan bir ekranın işareti ise kendiliğinden geçersizleşir.
     */
    private const val TRUSTED_EXCURSION_WINDOW_MS = 5_000L
    private const val MAX_EXCURSION_MS = 3 * 60_000L
    @Volatile private var excursionLeftAt = 0L

    /** Kullanıcı isteği: arka planda bu süreden uzun kalırsa şifre sorulur
     *  (ekran kilitlenince hemen — bkz. `lockNow`); kısa geçişlerde sorulmaz. */
    private const val BACKGROUND_LOCK_MS = 60_000L
    @Volatile private var backgroundedAt = 0L

    fun hasPassword(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.contains(KEY_HASH) && prefs.contains(KEY_SALT)
    }

    /** `false` döner (ve HİÇBİR ŞEY yazmaz) şifre boşsa — bkz. sınıf notu. */
    fun setPassword(context: Context, password: String): Boolean {
        if (password.isBlank() || password.length < MIN_PASSWORD_LENGTH) return false
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val hash = derive(password, salt, ITERATIONS)
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(KEY_HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
            .putInt(KEY_ITERATIONS, ITERATIONS)
            .apply()
        return true
    }

    /**
     * `MessageDigest.isEqual`: sabit zamanlı karşılaştırma — düz `==`
     * (ya da `contentEquals`) ilk farklı bayta gelince erken çıkar ve
     * teorik olarak zamanlama sızıntısına açıktır.
     */
    fun verify(context: Context, password: String): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saltB64 = prefs.getString(KEY_SALT, null) ?: return false
        val hashB64 = prefs.getString(KEY_HASH, null) ?: return false
        // bkz. `ITERATIONS` dokümantasyonu: bu alan güncel sabit
        // yükseltilmeden ÖNCE yazılmış bir kayıtta yok — o durumda eski
        // (120.000) sabitle türetilmiş olması gerekir, aksi halde her eski
        // kurulumun şifresi bu güncellemeyle KIRILIRDI.
        val iterations = if (prefs.contains(KEY_ITERATIONS)) prefs.getInt(KEY_ITERATIONS, ITERATIONS) else LEGACY_ITERATIONS
        return try {
            val expected = Base64.decode(hashB64, Base64.NO_WRAP)
            val actual = derive(password, Base64.decode(saltB64, Base64.NO_WRAP), iterations)
            MessageDigest.isEqual(expected, actual)
        } catch (e: Exception) {
            false
        }
    }

    private fun derive(password: String, salt: ByteArray, iterations: Int): ByteArray {
        // Native (ring) yol: aynı çıktı, Java'dan kat kat hızlı — Tab A8'de
        // Java ile kilit açma 4-8 sn sürüyordu. Kütüphane yüklenemezse Java.
        try {
            val out = com.p2p.messenger.P2PLib.pbkdf2Sha256(password, salt, iterations, KEY_LENGTH_BITS / 8)
            if (out.size == KEY_LENGTH_BITS / 8) return out
        } catch (e: Throwable) {
        }
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, KEY_LENGTH_BITS)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }

    fun isUnlocked(): Boolean = unlocked

    fun markUnlocked() {
        unlocked = true
        promptShowing = false
    }

    /** Stored, so a force stop does not hand out fresh attempts. Time since
     *  boot, not the wall clock: the user can set that one forward. */
    private const val FREE_ATTEMPTS = 5
    private const val KEY_FAILED_ATTEMPTS = "app_lock_failed_attempts"
    private const val KEY_WAIT_FROM = "app_lock_wait_from_elapsed"
    private const val KEY_WAIT_MS = "app_lock_wait_ms"

    /** Seconds until the next attempt is allowed, 0 = now. */
    fun retryWaitSeconds(context: Context): Int {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val waitMs = prefs.getLong(KEY_WAIT_MS, 0L)
        if (waitMs <= 0L) return 0
        val now = SystemClock.elapsedRealtime()
        var from = prefs.getLong(KEY_WAIT_FROM, 0L)
        if (now < from) {
            // Rebooted: the time since boot started over, so does the wait.
            from = now
            prefs.edit().putLong(KEY_WAIT_FROM, now).commit()
        }
        return ((from + waitMs - now).coerceAtLeast(0L) + 999).div(1000).toInt()
    }

    /** After [FREE_ATTEMPTS] wrong passwords: 30 s, doubling to 16 min. */
    fun noteFailedAttempt(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val failed = prefs.getInt(KEY_FAILED_ATTEMPTS, 0) + 1
        val over = failed - FREE_ATTEMPTS
        val edit = prefs.edit().putInt(KEY_FAILED_ATTEMPTS, failed)
        if (over >= 0) {
            edit.putLong(KEY_WAIT_FROM, SystemClock.elapsedRealtime())
                .putLong(KEY_WAIT_MS, 30_000L shl over.coerceAtMost(5))
        }
        edit.commit()
    }

    fun clearFailedAttempts(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .remove(KEY_FAILED_ATTEMPTS).remove(KEY_WAIT_FROM).remove(KEY_WAIT_MS).apply()
    }

    /**
     * Kullanıcı raporu: "mesaj için dahili dosya seçici ya da kameradan
     * sonra şifre istemesin."
     *
     * Sorun yapısal: sistem dosya seçicisi (SAF/DocumentsUI), çalışma
     * zamanı izin diyaloğu, harici görüntüleyici ve sistem ayar ekranları
     * BAŞKA süreçlerde çalışan Activity'ler — açıldıklarında bizim TÜM
     * Activity'lerimiz `onStop`'a düşer, "başlamış Activity" sayacı 0 olur
     * ve `lock()` tetiklenir. Kullanıcı aslında uygulamadan HİÇ çıkmamıştır;
     * dönüşte şifre sorulması saf bir hata.
     *
     * Bu yüzden dışarıya kontrol devreden HER çağrı noktası (bkz. bu
     * fonksiyonun çağrıldığı yerler) bunu önceden bildirir ve SIRADAKİ tek
     * arka plan geçişi kilitlemez.
     *
     * BİLİNEN SINIR: kullanıcı seçici/izin ekranı açıkken Home'a basarsa
     * bayrak zaten harcanmış olduğundan (bizim Activity'lerimiz o noktada
     * çoktan durmuş, ikinci bir `onStop` gelmez) o dönüşte de şifre
     * sorulmaz — kilit ancak bir SONRAKİ gerçek arka plan geçişinde
     * devreye girer. Bunu kapatmanın tek yolu "hangi Activity'nin öne
     * geçtiğini" sormak olurdu ki Android bunu (haklı olarak) uygulamalara
     * vermiyor. Sık ve görünür bir hata olan yanlış kilitlenmeye karşı
     * bilinçli bir takas.
     */
    fun beginTrustedExcursion() {
        excursionValidUntil = SystemClock.elapsedRealtime() + TRUSTED_EXCURSION_WINDOW_MS
    }

    /** Our screen was covered within the window (a chooser or a dialog of
     *  another app): the excursion holds until our screen comes back, however
     *  long the user takes to pick an app there. */
    @Volatile private var excursionCovered = false

    fun excursionPaused() {
        val validUntil = excursionValidUntil
        if (validUntil != 0L && SystemClock.elapsedRealtime() < validUntil) excursionCovered = true
    }

    /** Our screen is back without the app having left: the excursion ended. */
    fun excursionResumed() {
        excursionCovered = false
    }

    /** bkz. P2PApplication.onActivityStopped — uygulama tamamen arka plana
     *  düştüğünde çağrılır. */
    fun lock() {
        val validUntil = excursionValidUntil
        val covered = excursionCovered
        excursionValidUntil = 0L
        excursionCovered = false
        // `elapsedRealtime`: duvar saati DEĞİL — kullanıcı/şebeke saati
        // değiştirse bile pencere kayamaz.
        if (covered || (validUntil != 0L && SystemClock.elapsedRealtime() < validUntil)) {
            excursionLeftAt = SystemClock.elapsedRealtime()
            return
        }
        backgroundedAt = SystemClock.elapsedRealtime()
    }

    /** Ekran kapandı: bekleme olmadan hemen kilitle. */
    fun lockNow(context: Context?) {
        if (!unlocked) return
        unlocked = false
        if (context == null) return
        val leftAt = excursionLeftAt
        if (leftAt == 0L) {
            purgePlainCache(context)
            return
        }
        // An external viewer may still have a decrypted file open: purge when
        // the user comes back (`guard`), at the latest when the excursion
        // would have timed out anyway.
        purgePending = true
        val app = context.applicationContext
        val wait = (leftAt + MAX_EXCURSION_MS - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            if (purgePending) {
                purgePending = false
                purgePlainCache(app)
            }
        }, wait)
    }

    /** `lockNow` during a trusted excursion: the purge waits for its end. */
    @Volatile private var purgePending = false

    /** Decrypted attachment copies do not outlive the unlocked session. Only
     *  where the lock really engages: a trusted excursion (picker, external
     *  viewer) keeps `unlocked`, so the file it has open stays. */
    private fun purgePlainCache(context: Context) {
        if (!hasPassword(context)) return
        java.io.File(context.filesDir, "attachments/plain_cache").listFiles()?.forEach { it.deleteRecursively() }
    }

    /** Kilit ekranı kullanıcı tarafından kapatıldığında (geri tuşu →
     *  uygulamadan çıkış) bayrağın asılı kalmaması için. */
    fun promptClosed() {
        promptShowing = false
    }

    /**
     * HER Activity'nin `onStart`'ından çağrılır (bkz.
     * P2PApplication.onActivityStarted) — bir bildirimden doğrudan
     * ChatActivity'ye girmek de kilidi atlayamasın diye, sadece
     * MainActivity'de değil.
     *
     * Şifre henüz hiç kurulmamışsa da AYNI ekran açılır (CREATE modunda):
     * kullanıcı isteği gereği şifresiz bir durum kalıcı olamaz.
     */
    fun guard(activity: Activity) {
        // The call screen works like a phone call: answer or decline without
        // the app password. Since the app locks on screen-off the password
        // prompt covered every incoming call. Everything else stays guarded.
        if (activity is AppLockActivity) return
        // Güvenilir gezinti kilidi ertelediyse ve kullanıcı seçiciden Home'a
        // basıp uzun süre sonra döndüyse kilitli açılmalı — aksi halde
        // uygulama süresiz kilitsiz kalırdı.
        val wasUnlocked = unlocked
        val leftAt = excursionLeftAt
        if (leftAt != 0L) {
            excursionLeftAt = 0L
            if (SystemClock.elapsedRealtime() - leftAt > MAX_EXCURSION_MS) unlocked = false
        }
        val bgAt = backgroundedAt
        backgroundedAt = 0L
        if (bgAt != 0L && SystemClock.elapsedRealtime() - bgAt > BACKGROUND_LOCK_MS) unlocked = false
        if ((wasUnlocked && !unlocked) || purgePending) {
            purgePending = false
            purgePlainCache(activity)
        }
        // After the timeouts above: skipping them here let the call screen's
        // own stop renew `backgroundedAt`, so the app opened without the
        // password for a minute after any call.
        if (activity is com.p2p.messenger.ui.CallActivity) return
        // The screen under the prompt is drawn for a moment before the prompt
        // covers it: its content stays hidden until the password is in.
        activity.findViewById<android.view.View>(android.R.id.content)?.visibility =
            if (unlocked) android.view.View.VISIBLE else android.view.View.INVISIBLE
        if (unlocked) return
        // No `promptShowing` short-circuit: an activity started over the prompt
        // (a notification with CLEAR_TOP) finished it and stayed open unlocked.
        // SINGLE_TOP keeps a prompt that is already on top from stacking.
        promptShowing = true
        activity.startActivity(
            Intent(activity, AppLockActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NO_ANIMATION)
        )
    }
}
