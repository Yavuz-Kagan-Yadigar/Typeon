package com.p2p.messenger.util

import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

/**
 * Spec dışı, kullanıcı isteği (açıkça, üçüncü kez): klavye açıldığında
 * sohbet onun yüksekliğini telafi etsin ve alttaki mesaj görünür kalsın;
 * klavye kapanınca geri alsın.
 *
 * NEDEN sadece `android:windowSoftInputMode="adjustResize"` YETMİYOR: bu
 * projenin test telefonunda (Redmi Note 8 Pro / Android 16) `adb shell
 * dumpsys window` ile ÖLÇÜLDÜ — `adjustResize` bildirilse bile pencere
 * gerçekte yeniden boyutlanmıyor. Yine de manifeste konması ŞART: aksi
 * halde devreye giren varsayılan `adjustPan` tüm pencereyi kaydırıyor ve
 * bizim eklediğimiz dolguyla üst üste biniyor.
 *
 * ÖLÇÜM KAYNAĞI TEK: `WindowInsetsCompat.Type.ime()`. Yedek olarak
 * `getWindowVisibleDisplayFrame` ("pencerenin klavyeyle örtülmeyen alanı")
 * eklendi ve gerçek cihazda DENENDİ — kaldırıldı: o metrik bu ekranda
 * pencere yüksekliğine göre anlamsız büyük değerler döndürüp düzeni
 * tamamen bozdu (giriş çubuğu ekranın tepesine fırladı). Aynı sınıf
 * heuristikler bu projede daha önce de başarısız olmuştu. Insets tek
 * doğru kaynak; telefonda çalışmamasının sebebi ölçüm değil, eksik
 * `adjustResize` yüzünden pencerenin PAN etmesiydi.
 *
 * KAYDIRMA: "sona atla" DEĞİL. İlk sürüm öyleydi ve cihazda yanlış olduğu
 * görüldü — kullanıcı yukarı kaydırmışken klavyeyi açmak onu istemeden en
 * dibe fırlatıyordu. Doğrusu TELAFİ: liste ne kadar küçüldüyse içerik o
 * kadar kaydırılır; ekranın altındaki mesaj altta kalır, klavye kapanınca
 * (delta negatif) kendiliğinden geri alınır. Ayrıntı ve neden insets
 * deltası KULLANILMADIĞI için `addOnLayoutChangeListener` yorumuna bakın.
 */
object KeyboardInsets {

    fun attach(root: View, recycler: RecyclerView) {
        val basePaddingBottom = root.paddingBottom
        // bkz. aşağıdaki `addOnLayoutChangeListener` notu — insets
        // dağıtıldığında (yerleşim henüz TETİKLENMEDEN) alınan bir
        // an-görüntü: kullanıcı o an listenin dibinde miydi?
        var wasNearBottomBeforeResize = false

        ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
            val navigation = insets.getInsets(WindowInsetsCompat.Type.navigationBars()).bottom
            // Gezinme çubuğu zaten kök dolgusunun bir parçası; yalnızca onu
            // AŞAN kısım klavyeye ait.
            val extra = (ime - navigation).coerceAtLeast(0)
            wasNearBottomBeforeResize = isRecyclerNearBottom(recycler)
            root.setPadding(
                root.paddingLeft,
                root.paddingTop,
                root.paddingRight,
                basePaddingBottom + extra
            )
            insets
        }

        /*
         * Telafiyi, insets deltasından DEĞİL listenin GERÇEK boyut
         * değişiminden türetiyoruz.
         *
         * Önceki sürüm "klavye ne kadar açıldıysa o kadar kaydır" diyordu ve
         * cihazda çalışmadı (kullanıcı ekran görüntüsüyle gösterdi: çubuk
         * yukarı çıkıyor ama liste hiç kaymıyor, alttaki mesajlar kırpılıyor).
         * Sebep zamanlama: dolgu atandığı anda kaydırma miktarı biriktiriliyor,
         * ama araya listenin boyutu HENÜZ değişmemişken tetiklenen bir yerleşim
         * geçişi giriyor; kaydırma orada tüketiliyor ve asıl küçülme
         * gerçekleştiğinde düzen yöneticisi çıpasını geri yükleyip etkiyi
         * siliyordu.
         *
         * Bu sürümde böyle bir "bekleyen miktar" defteri YOK: liste ne zaman
         * N piksel küçülürse içerik tam o anda N piksel kaydırılır (büyürse
         * ters yönde). Bu, tanımı gereği "ekranın altındaki mesaj altta
         * kalsın" demek ve klavyenin açılması/kapanması için ayrı bir kola
         * gerek bırakmıyor.
         */
        recycler.addOnLayoutChangeListener { _, _, top, _, bottom, _, oldTop, _, oldBottom ->
            val previousHeight = oldBottom - oldTop
            // İlk yerleşimde "önceki yükseklik" yok — 0'dan kaydırmak listeyi
            // açılışta sıçratırdı.
            if (previousHeight == 0) return@addOnLayoutChangeListener
            val delta = previousHeight - (bottom - top)
            if (delta == 0) return@addOnLayoutChangeListener
            if (wasNearBottomBeforeResize) {
                // Spec dışı, hata düzeltmesi (kullanıcı: "en altta klavye
                // açılıp kapanınca view yukarı sürükleniyor"): liste
                // BÜYÜRKEN (klavye kapanırken) `LinearLayoutManager` zaten
                // en altta boşluk BIRAKMAMAK için kendiliğinden telafi
                // ediyor — içerik sonunu viewport sonuna göre yeniden
                // çıpalıyor, bizim `scrollBy` çağırmamıza GEREK KALMADAN.
                // Küçülürken (klavye açılırken) bu kendiliğinden telafi
                // YOK — LayoutManager üstteki çıpayı sabit tutup alttaki
                // içeriği sessizce kırpıyor, bu yüzden ORADA piksel
                // deltası gerçekten gerekli (aşağıdaki `else` kolu).
                // Ama en alttayken BÜYÜME tarafında da aynı piksel
                // deltasını uygulamaya devam etmek, LayoutManager'ın KENDİ
                // telafisinin ÜSTÜNE bir kez daha ekleniyor ve listeyi
                // gerçek dipten fazladan yukarı sürüklüyordu — tam da
                // bildirilen hata. En alttayken bu yüzden pikselle
                // uğraşmak yerine doğrudan dibe sabitleniyor —
                // `ChatActivity.onNewIncomingItemAdded` ile AYNI iki
                // geçişli (scrollToPosition + kalan-fark) desen.
                recycler.post {
                    val adapter = recycler.adapter
                    val last = (adapter?.itemCount ?: 0) - 1
                    if (last < 0) return@post
                    recycler.scrollToPosition(last)
                    recycler.post {
                        val lm = recycler.layoutManager as? LinearLayoutManager ?: return@post
                        val view = lm.findViewByPosition(last) ?: return@post
                        val overshoot = view.bottom - (recycler.height - recycler.paddingBottom)
                        if (overshoot != 0) recycler.scrollBy(0, overshoot)
                    }
                }
            } else {
                // `post`: yerleşim sürerken `scrollBy` çağrılamaz
                // (RecyclerView "layout hesaplanırken" reddeder).
                recycler.post { recycler.scrollBy(0, delta) }
            }
        }

        // Dinleyici, kurulmadan ÖNCE gönderilmiş insets'i görmez — ekran
        // klavye AÇIKKEN yeniden oluşturulduysa ilk dolgu hiç uygulanmazdı.
        ViewCompat.requestApplyInsets(root)
    }

    /** bkz. `ChatActivity.isRecyclerNearBottom` — aynı "en alta yakın mı"
     *  tanımı, buraya (genel amaçlı bir util nesnesi olduğundan Activity'ye
     *  bağımlı olmadan) yeniden yazıldı. */
    private fun isRecyclerNearBottom(recycler: RecyclerView): Boolean {
        val adapter = recycler.adapter ?: return true
        if (adapter.itemCount == 0) return true
        val lm = recycler.layoutManager as? LinearLayoutManager ?: return true
        val lastVisible = lm.findLastVisibleItemPosition()
        return lastVisible == RecyclerView.NO_POSITION || lastVisible >= adapter.itemCount - 2
    }
}
