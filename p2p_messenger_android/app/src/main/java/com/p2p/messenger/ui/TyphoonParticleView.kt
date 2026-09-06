package com.p2p.messenger.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.os.SystemClock
import android.util.AttributeSet
import android.view.View
import kotlin.math.cos
import kotlin.math.sin
import kotlin.random.Random

/**
 * Spec dışı, kullanıcı isteği: "son 15 dakikada mesaj olmayan bir sohbete
 * mesaj atıldığında görsel bir particle typhoon efekti" — sonra: "3D gibi
 * olsun, ekranın ÜSTÜNDE GENİŞ altında İNCE, BÜYÜK olsun."
 *
 * Bu yüzden ilk sürümdeki "tek noktadan dışa savrulan sarmal" bırakıldı;
 * yerine gerçek bir HUNİ (kasırga) geometrisi:
 *
 * - Her parçacığın bir YÜKSEKLİĞİ (`h`, 0 = huninin ucu/alt, 1 = ağzı/üst)
 *   ve bir AÇISI var. Yörünge yarıçapı yüksekliğe göre büyüyor
 *   (`FUNNEL_TIP_RADIUS` → `FUNNEL_MOUTH_RADIUS`), yani üstte geniş altta
 *   ince — istenen huni silueti.
 * - 3D hissi PERSPEKTİFTEN geliyor, sahte bir gölgeden değil: yatayda tam
 *   yarıçap, dikeyde `ELLIPSE_SQUASH` ile ezilmiş bir elips çiziliyor
 *   (yukarıdan bakılan bir daire ekranda elips olarak görünür) ve
 *   `sin(angle)` DERİNLİK olarak kullanılıyor: arkadaki (uzaktaki)
 *   parçacıklar hem daha küçük hem daha soluk. Böylece dönme, önden arkaya
 *   geçtiği anlaşılan gerçek bir hacim gibi okunuyor.
 * - Parçacıklar zamanla yükseliyor ve dönüş hızı ucda daha yüksek (gerçek
 *   bir hortumda olduğu gibi), bu da huninin "burulma"sını veriyor.
 *
 * Yine de HAFİF: tek `Paint`, sabit süre, animasyon bitince `GONE` — sürekli
 * çalışan bir animasyon yok.
 */
class TyphoonParticleView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    private companion object {
        /**
         * Parçacık sayısı 110'dan 56'ya indirildi.
         *
         * Kullanıcı "performansı çok düşük ve kasıyor" dedi ve asıl suçlu
         * sayı DEĞİLDİ: her parçacığın izine bir `BlurMaskFilter`
         * uygulanıyordu. O filtre donanım hızlandırmada DESTEKLENMİYOR —
         * kullanıldığı her çizim, sistemi o katman için yazılım
         * rasterleştirmeye düşürür. Kare başına 110 bulanık çizgi, pratikte
         * her karede 110 yazılım geçişi demekti. Filtre tamamen kaldırıldı;
         * "bulanıklık" hissi artık izin KENDİ geometrisinden geliyor (bkz.
         * `TRAIL_SEGMENTS`). Sayının yarıya inmesi ek bir rahatlama.
         */
        const val PARTICLE_COUNT = 56
        const val DURATION_MS = 1900L
        /**
         * İz, tek bir kalın çizgi DEĞİL, uç uca eklenmiş kısa parçalar.
         * Kullanıcı raporu: "motion blur değil çizgi gibi görünüyor;
         * parçacığın başında kalın ve opak, uca gittikçe ince ve şeffaf
         * olsun." Tek `drawLine` bunu yapamaz (tek kalınlık, tek alfa);
         * parçalara bölüp her parçada kalınlığı ve alfayı azaltmak, gerçek
         * bir hız izinin koniklenmesini ve sönmesini veriyor — üstelik
         * `BlurMaskFilter`'dan kat kat ucuz.
         */
        const val TRAIL_SEGMENTS = 6
        /** Huninin ucu (alt) — görünüm genişliğinin oranı olarak. */
        const val FUNNEL_TIP_RADIUS = 0.045f
        /** Huninin ağzı (üst). Kullanıcı "üstte geniş" istedi. */
        const val FUNNEL_MOUTH_RADIUS = 0.46f
        /** Dikey ezme: 1 = daire (tepeden bakış), küçük = daha yatık. */
        const val ELLIPSE_SQUASH = 0.30f
        /** Parçacığın ömrü boyunca kat ettiği toplam dönüş (radyan). */
        const val BASE_SPIN = 7.0f
        /** İzin en uzun hâlinin zaman cinsinden karşılığı — gerçek uzunluk
         *  parçacığın boyutuyla ölçekleniyor (bkz. `Particle.trailSpan`). */
        const val TRAIL_SPAN_MAX = 0.11f
    }

    private class Particle(
        val angle0: Float,
        val height0: Float,
        val rise: Float,
        val spin: Float,
        val size: Float,
        val delay: Float,
        /** Kullanıcı isteği: "izin uzunluğu, rastgele varyasyonlu parçacık
         *  BOYUTUNA göre olsun" — büyük parçacık uzun iz bırakır. */
        val trailSpan: Float,
        val hueShift: Float,
        val satShift: Float,
        val valShift: Float,
        /** Accent'ten türetilmiş nihai renk — her karede yeniden
         *  hesaplamamak için `burst`ta bir kez üretilir. */
        var color: Int = 0,
    )

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)

    private var particles: List<Particle> = emptyList()
    private var startedAt = 0L
    private var tint = 0

    init {
        isClickable = false
        isFocusable = false
    }

    /**
     * Efekti başlatır. Huni GÖRÜNÜMÜN TAMAMINI kaplar (kullanıcı "büyük
     * olsun" dedi) — bu yüzden bir merkez noktası almıyor; çağıran tarafın
     * balon konumunu hesaplamasına gerek yok.
     */
    fun burst(color: Int) {
        tint = color
        val random = Random(SystemClock.uptimeMillis())
        particles = List(PARTICLE_COUNT) {
            // Boyut önce oranı olarak seçiliyor: hem piksel boyutu hem iz
            // uzunluğu AYNI rastgele değerden türesin diye.
            val sizeFraction = random.nextFloat()
            val sizePx = (3.0f + sizeFraction * 6.5f) * resources.displayMetrics.density
            Particle(
                angle0 = random.nextFloat() * 6.2832f,
                // Başlangıç yüksekliği tüm huniye dağılsın ki efekt daha
                // ilk karede dolu görünsün, aşağıdan yavaşça dolmasın.
                height0 = random.nextFloat(),
                rise = 0.25f + random.nextFloat() * 0.55f,
                spin = 0.7f + random.nextFloat() * 0.8f,
                // Kullanıcı isteği: parçacıklar DAHA BÜYÜK.
                size = sizePx,
                trailSpan = TRAIL_SPAN_MAX * (0.35f + 0.65f * sizeFraction),
                delay = random.nextFloat() * 0.2f,
                // Kullanıcı isteği: "yaklaşık accent renginde, biraz
                // varyasyonla". Ton/doygunluk/parlaklık HSV'de hafifçe
                // kaydırılıyor — RGB'de kaydırmak rengi accent ailesinden
                // çıkarıp gri/kirli tonlar üretiyordu.
                hueShift = (random.nextFloat() - 0.5f) * 34f,
                satShift = (random.nextFloat() - 0.5f) * 0.30f,
                valShift = (random.nextFloat() - 0.5f) * 0.34f,
            )
        }
        val hsv = FloatArray(3)
        Color.colorToHSV(color, hsv)
        for (p in particles) {
            p.color = Color.HSVToColor(
                floatArrayOf(
                    (hsv[0] + p.hueShift + 360f) % 360f,
                    (hsv[1] + p.satShift).coerceIn(0.25f, 1f),
                    (hsv[2] + p.valShift).coerceIn(0.35f, 1f),
                )
            )
        }
        startedAt = SystemClock.uptimeMillis()
        visibility = VISIBLE
        postInvalidateOnAnimation()
    }

    // Konum hesabının çıktısı — her parça için bir `PointF` ayırmamak
    // (kare başına yüzlerce nesne) yerine tek bir çift alan.
    private var posX = 0f
    private var posY = 0f
    private var posHeight = 0f

    // İzin noktaları — kare başına parçacık başına dizi ayırmamak için
    // yeniden kullanılıyor. +1: baş nokta da dahil.
    private val trailX = FloatArray(TRAIL_SEGMENTS + 1)
    private val trailY = FloatArray(TRAIL_SEGMENTS + 1)

    /** Parçacığın `t` anındaki ekran konumunu `posX/posY`'ye yazar. */
    private fun computePosition(p: Particle, t: Float, w: Float, h: Float, centerX: Float) {
        val heightFraction = (p.height0 + p.rise * t) % 1f
        // Ucda daha hızlı dönüş — hortumun burulması.
        val angle = p.angle0 + BASE_SPIN * p.spin * (1.6f - heightFraction) * t
        val radius = (FUNNEL_TIP_RADIUS + (FUNNEL_MOUTH_RADIUS - FUNNEL_TIP_RADIUS) * heightFraction) * w
        posHeight = heightFraction
        posX = centerX + cos(angle) * radius
        posY = h - heightFraction * h + sin(angle) * radius * ELLIPSE_SQUASH
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (particles.isEmpty()) return
        val progress = (SystemClock.uptimeMillis() - startedAt).toFloat() / DURATION_MS
        if (progress >= 1f) {
            particles = emptyList()
            visibility = GONE
            return
        }
        val w = width.toFloat()
        val h = height.toFloat()
        if (w <= 0f || h <= 0f) return
        val centerX = w / 2f
        // Tüm efektin genel görünürlüğü: hızlı belirir, yavaş söner.
        val envelope = if (progress < 0.18f) progress / 0.18f else 1f - (progress - 0.18f) / 0.82f

        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND

        for (p in particles) {
            val t = ((progress - p.delay) / (1f - p.delay)).coerceIn(0f, 1f)
            if (t <= 0f) continue

            computePosition(p, t, w, h, centerX)
            var headX = posX
            var headY = posY
            var headHeight = posHeight
            val heightFraction = posHeight

            // `sin(angle)` yerine konumdan türetilen derinlik yaklaşımı
            // kullanmıyoruz — açıyı zaten `computePosition` biliyor; burada
            // yalnızca kabaca ön/arka ayrımı yeterli olduğundan yörüngedeki
            // dikey kayma işareti kullanılıyor.
            val orbitCenterY = h - heightFraction * h
            val depth = ((headY - orbitCenterY) / (ELLIPSE_SQUASH * FUNNEL_MOUTH_RADIUS * w))
                .coerceIn(-1f, 1f)
            val depthScale = 0.55f + 0.45f * (depth + 1f) / 2f
            // Uçlarda (en alt/en üst) yumuşakça sönsün ki huni kesik
            // görünmesin.
            val edgeFade = (1f - kotlin.math.abs(heightFraction - 0.5f) * 1.35f).coerceIn(0f, 1f)
            val headAlpha = 235f * envelope * depthScale * edgeFade
            if (headAlpha <= 1f) continue

            val headWidth = p.size * depthScale
            paint.color = p.color

            // İzin noktalarını önce topla (baştan uca), sonra TERS sırada
            // çiz.
            //
            // Ters sıra şart: her parça yuvarlak uçlu (`Cap.ROUND`) ve
            // parçalar farklı kalınlıkta. Baştan uca çizince kalın parçanın
            // yuvarlak ucu, ondan sonra çizilen ince parçanın üzerinde
            // kalıyor ve iz boyunca "boncuk" gibi şişkinlikler oluşuyordu
            // (cihazda görüldü). Uçtan başa çizince her kalın parça bir
            // öncekinin ucunu ÖRTÜYOR ve geçiş pürüzsüz koniye dönüşüyor.
            trailX[0] = headX
            trailY[0] = headY
            var points = 1
            var previousHeight = headHeight
            for (segment in 1..TRAIL_SEGMENTS) {
                val fraction = segment.toFloat() / TRAIL_SEGMENTS
                val tailT = (t - p.trailSpan * fraction).coerceAtLeast(0f)
                computePosition(p, tailT, w, h, centerX)
                // Yükseklik sarmalandığında (`% 1f`) geçmiş konum huninin
                // öbür ucuna düşer — o parçayı çizmek ekranı boydan boya
                // kesen yanlış bir çizgi üretirdi.
                if (kotlin.math.abs(posHeight - previousHeight) > 0.5f) break
                trailX[points] = posX
                trailY[points] = posY
                previousHeight = posHeight
                points++
            }

            for (i in points - 1 downTo 1) {
                // `i` uca yakınken ince ve şeffaf, başa yaklaştıkça kalın ve
                // opak — kullanıcının istediği koniklik.
                val fraction = i.toFloat() / TRAIL_SEGMENTS
                paint.strokeWidth = headWidth * (1f - fraction) + 0.35f
                paint.alpha = (headAlpha * (1f - fraction)).toInt().coerceIn(0, 255)
                canvas.drawLine(trailX[i - 1], trailY[i - 1], trailX[i], trailY[i], paint)
            }
        }
        postInvalidateOnAnimation()
    }
}
