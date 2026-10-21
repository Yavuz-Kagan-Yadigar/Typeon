package com.p2p.messenger.server

/**
 * `typeon-server` Rust çekirdeğinin JNI yüzeyi.
 *
 * İstemcinin `P2PLib`'iyle aynı desen: her şey JSON dizesi olarak geçer,
 * hatalar `"Error: ..."` önekiyle döner. Bu ayrı bir kütüphane
 * (`libtypeon_server.so`) — istemcinin `libp2p_messenger.so`'suyla aynı
 * protokol tiplerini paylaşır ama ayrı bir crate'tir.
 */
/** M142: the native side answers in English; show it in the user's language. */
fun serverErrorText(ctx: android.content.Context, raw: String): String {
    val id = when {
        raw.startsWith("Error: internal error") -> R.string.err_internal
        raw.startsWith("Error: previous server still") -> R.string.err_server_closing
        raw.startsWith("Error: server loop did not stop") -> R.string.err_server_loop_stuck
        raw == "Error: server not running" -> R.string.err_server_not_running
        raw.startsWith("Error: server has no reachable address") -> R.string.err_no_address
        raw == "Error: invalid id" -> R.string.err_invalid_id
        raw == "Error: record not found" -> R.string.err_record_not_found
        else -> return raw
    }
    return ctx.getString(id)
}

object ServerLib {
    init {
        System.loadLibrary("typeon_server")
    }

    /**
     * Sunucuyu başlatır, `peer_id` döner. Zaten çalışıyorsa no-op —
     * foreground service `START_STICKY` ile yeniden başlatılabiliyor.
     *
     * Tor parametresi YOK: onion service bu uygulamada her zaman açık. Bir
     * telefonun operatör NAT'ı arkasından ulaşılabilir olmasının tek yolu o;
     * kapatılabilir yapmak, sunucuyu sessizce erişilemez kılan bir ayak
     * kapanı olurdu.
     */
    external fun startServer(
        dataDir: String,
        nodeMode: Boolean,
        name: String,
        /**
         * Sunucunun kullanmasına izin verilen TOPLAM disk bütçesi (bayt).
         *
         * Rust tarafındaki varsayılan kotalar bir VPS için yazılmıştı: kayıt
         * BAŞINA 256 MB posta + 1 GB arşiv + 4 GB blob. Beş cihazla bu 26
         * GB'a çıkıyor ve gerçekten oldu — test sırasında tabletin 22 GB'lık
         * diski doldu, sunucu 751 MB biriktirdi ve yeni kurulum
         * `INSTALL_FAILED_INSUFFICIENT_STORAGE` ile reddedildi. Telefonda
         * kotalar cihazın GERÇEK boş alanından türetilmeli.
         */
        storageBudgetBytes: Long,
        /** Blob dizini — kimlik/Tor durumu HER ZAMAN dahilide kalır. */
        blobDir: String
    ): String

    /**
     * Sunucuyu GERÇEKTEN durdurur (defter #11).
     *
     * Bu yoktu: `stopService(...)` yalnızca wake lock'u bırakıp ön plan
     * bildirimini kaldırıyordu, Rust çekirdeği süreçte çalışmaya devam
     * ediyordu — hâlâ posta kabul ediyor, blob servis ediyor, pil harcıyor.
     * Ayrıca `startServer` zaten çalışan bir çekirdek varken no-op olduğu
     * için node modu / blob dizini / disk bütçesi değişiklikleri de süreç
     * öldürülmeden uygulanmıyordu. Durdurma sonrası `startServer` temiz bir
     * kurulum yapar.
     */
    /** SQLCipher key (64 hex) for the server DB; call before [startServer]. "ok" or "Error: ...". */
    external fun setDbKey(keyHex: String): String

    external fun stopServer(): String

    /** `{running, peer_id, tor, addresses, devices, deposits, fetches, ...}` */
    external fun serverStatus(): String

    /**
     * Sunucunun KALICI katılım kodu (`typeon-server:<multiaddr>#<jeton>`) —
     * bir kez yayımlanır, SINIRSIZ kişi aynı kodla katılır.
     *
     * Kullanıcı isteği (2026-09-04): "tek QR/link ile birden çok kişi
     * katılabilmeli, server ile etkileşime girmeye gerek kalmadan".
     * Önceki "yeni davet üret" düğmesi bunu çözmüyordu — her dokunuşta
     * YENİ ve tek kullanımlık bir kod üretiyor, jetonu hash'li sakladığı
     * için de aynı kodu bir daha gösteremiyordu: her yeni kişi için
     * operatörün bu ekrana gelmesi gerekiyordu. (Sayılı/süreli davetler
     * headless daemon'da `typeon-server invite new` ile duruyor.)
     *
     * `rotate = true`: eski kod ANINDA geçersizleşir, yenisi döner. Kayıtlı
     * cihazlar etkilenmez (kayıt jetondan bağımsız).
     *
     * Sunucunun henüz bir adresi yoksa hata döner — Tor açıkken onion
     * adresi arti'nin bootstrap'ını bekler (ilk açılışta 30-60 sn).
     */
    external fun joinCode(rotate: Boolean): String

    /** `[{enrollment_id, peer_id, revoked, blocked, bytes_mail, bytes_archive, bytes_blob}]` */
    external fun listDevices(): String

    external fun revokeDevice(enrollmentId: String): String

    /**
     * Kaydı ENGELLER (kullanıcı kararı, 2026-08-27).
     *
     * `revokeDevice` de kayıt anahtarını engeller (iptal = engel). Farkı:
     * bu çağrı herkese açık katılım kodunu da yeniler.
     */
    external fun blockDevice(enrollmentId: String): String

    /** Engeli kaldırır; cihaz taze bir davetle yeniden kaydolabilir. */
    external fun unblockDevice(enrollmentId: String): String

    /** Veri dizininin toplam boyutu (bayt, dize olarak). */
    external fun diskUsage(): String

    /**
     * Ağ arayüzü değiştiğinde (Wi-Fi kopup gelme, hücresele geçiş) çağrılır
     * — bkz. `ServerService` `ConnectivityManager` geri çağrısı. Çekirdek
     * Tor bootstrap'ını (idempotent) yeniden tetikler ve libp2p
     * dinleyicisini tazeler; böylece bir Wi-Fi kesintisinden sonra onion
     * descriptor'ın yeniden yayınlanması periyodik iyileşmeyi (dakikalar)
     * beklemez. Çekirdek çalışmıyorsa no-op.
     */
    external fun notifyNetworkChanged()
}
