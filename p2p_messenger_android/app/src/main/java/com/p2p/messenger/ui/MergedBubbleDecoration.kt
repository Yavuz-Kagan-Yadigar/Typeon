package com.p2p.messenger.ui

import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.view.View
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.p2p.messenger.R

/**
 * art arda gelen ve
 * gruplanan mesajlar TEK bir dış hat oluştursun.
 *
 * NEDEN HER BALONUN KENDİ ARKA PLANI YETMİYOR: ilk denemede balonların
 * yalnızca birleşen kenardaki köşe yarıçapını küçültüp aralarındaki boşluğu
 * sıfırlamıştık. Kullanıcının tepkisi net: "hâlâ kendi filetleriyle
 * kalıyorlar". Haklı — çizimindeki birleşmiş şeklin iki ayırt edici özelliği
 * var ve ikisi de tek tek çizilen yuvarlak dikdörtgenlerle ÜRETİLEMEZ:
 *
 *  1. Dış çevre boyunca köşeler yuvarlak, ama SADECE gerçekten dışarıda
 *     kalanlar — iki balonun değdiği kenarda hiçbir köşe yok.
 *  2. Genişlik değişen yerlerde (basamak) İÇBÜKEY (concave) fileto var:
 *     dar balondan geniş olana geçerken hat keskin bir 270° köşe yapmıyor,
 *     içeri doğru yumuşak bir yay çiziyor. Bir dikdörtgenin köşe yarıçapı
 *     kavramı yalnızca DIŞBÜKEY köşeleri tanımlar; içbükey fileto ancak
 *     grubun TAMAMI tek bir `Path` olarak çizilirse var olabilir.
 *
 * Bu yüzden gruplanan balonların kendi arka planı kaldırılıyor (bkz.
 * SimpleChatAdapter — grup üyelerine arka plan ATANMIYOR) ve birleşik şekil
 * burada, listenin ALTINA tek seferde çiziliyor. `ItemDecoration.onDraw`
 * bunun için doğru yer: yerleşim bitmiş, tüm görünür çocukların GERÇEK
 * sınırları elde, ve çizim çocukların ARKASINDA kalıyor.
 *
 * Kaydırarak yanıtlama sırasında satır `translationX` ile kayar — şekil de
 * kaysın diye çeviriler sınırlara dahil ediliyor, aksi halde arka plan
 * yerinde kalıp balon üzerinden kayardı.
 */
class MergedBubbleDecoration(
    private val adapter: SimpleChatAdapter
) : RecyclerView.ItemDecoration() {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val path = Path()
    private val scratch = RectF()
    private val matrix = android.graphics.Matrix()

    // "ekranın en üstündeki balonlar daha açık
    // renk, alttakiler şu anki renginde, arada gradient olsun." Renk artık
    // balonun KENDİ arka planından değil, listenin tamamına gerilmiş dikey
    // bir `LinearGradient`'ten geliyor — bu yüzden bir balonun tonu
    // KAYDIRDIKÇA değişiyor (ekrandaki konumuna bağlı), ki istenen tam
    // buydu. Shader kare başına bir kez, yalnızca yükseklik/renk
    // değiştiğinde yeniden kuruluyor.
    private var mineShader: android.graphics.LinearGradient? = null
    private var theirsShader: android.graphics.LinearGradient? = null
    private var shaderHeight = 0
    private var shaderMine = 0
    private var shaderTheirs = 0

    // --- Çizim yolunda SIFIR tahsis --------------------------------------
    //
    // `onDraw` her karede, kaydırma boyunca çağrılıyor. İlk sürüm her grup
    // için `mutableListOf<RectF>()`, üye başına yeni bir `RectF`, ayrıca
    // `map { it.width() }` ile bir liste daha ayırıyordu; 60 fps'te bu,
    // saniyede yüzlerce kısa ömürlü nesne demek ve doğrudan GC baskısı
    // olarak kaydırmada takılma üretir. Artık ara veriler yeniden kullanılan
    // dizilerde; diziler büyütülmedikçe hiç tahsis yok.
    private var tops = FloatArray(16)
    private var bottoms = FloatArray(16)
    private var widths = FloatArray(16)
    private var lefts = FloatArray(16)
    private var rights = FloatArray(16)
    private var memberCount = 0

    private companion object {
        /** Dış (dışbükey) köşe yarıçapı — tek balonlarınkiyle aynı. */
        const val OUTER_RADIUS_DP = 18f
        /** Basamaklardaki içbükey fileto. Dıştan küçük olması gerekiyor:
         *  eşit olduğunda basamak "erimiş" görünüyor, şekil okunmuyor. */
        const val INNER_RADIUS_DP = 12f
    }

    override fun onDraw(canvas: Canvas, parent: RecyclerView, state: RecyclerView.State) {
        val childCount = parent.childCount
        if (childCount == 0) return
        val density = parent.resources.displayMetrics.density
        val outer = OUTER_RADIUS_DP * density
        val inner = INNER_RADIUS_DP * density
        // Tema renkleri kare boyunca sabit — grup başına yeniden çözmek
        // yerine kare başına bir kez.
        val mineColor = MaterialColors.getColor(parent, com.google.android.material.R.attr.colorPrimaryContainer)
        val theirsColor = MaterialColors.getColor(parent, com.google.android.material.R.attr.colorSurfaceVariant)
        ensureShaders(parent.height, mineColor, theirsColor)

        var index = 0
        // İKİ CİHAZLI GERÇEK TESTTE BULUNDU (2026-09-06, kullanıcı: "bazı
        // mesajların arkaplanları çizilmiyor"): eski atlama koşulu
        // `adapter.isGroupStart(position)` idi. Ama aşağıdaki iç döngü, iki
        // ARDIŞIK balon arasında dikey boşluk görürse (yan sütun —
        // tepki/"görüldü" satırı — balonun kendisinden UZUNSA olur) grubu
        // orada KESİYOR ve kesilen üyeyi ÇİZMEDEN atlıyor. O üye bir "grup
        // başı" değil (adaptör onu önceki mesajla gruplu sayıyor), bu yüzden
        // dış döngü de onu atlıyordu → o mesajın arka planı HİÇ çizilmiyordu.
        // Artık "grup başı mı" yerine "bu konumu daha önce çizdik mi"
        // izleniyor: çizilmemiş her görünür balon mutlaka bir yol buluyor.
        var drawnThroughPosition = RecyclerView.NO_POSITION
        while (index < childCount) {
            val child = parent.getChildAt(index)
            val position = parent.getChildAdapterPosition(child)
            // Yalnızca ÖNCEKİ bir grubun GERÇEKTEN boyadığı konumları atla.
            if (position == RecyclerView.NO_POSITION ||
                (drawnThroughPosition != RecyclerView.NO_POSITION && position <= drawnThroughPosition)
            ) {
                index++
                continue
            }
            // A sticker has no bubble.
            if (adapter.isStickerAt(position)) {
                index++
                continue
            }
            memberCount = 0
            var cursor = index
            var cursorPosition = position
            while (cursor < childCount) {
                val member = parent.getChildAt(cursor)
                if (parent.getChildAdapterPosition(member) != cursorPosition) break
                if (!collectBubble(member)) break
                // Kaydırılan (translationX != 0) satır kendi başına çizilir;
                // aksi halde birleşik şekil tüm grubu birlikte bozar/kaydırır.
                val moved = member.translationX != 0f
                if (moved && memberCount >= 2) {
                    memberCount--
                    break
                }
                // Grup, balonlar GERÇEKTEN bitişik olduğu sürece devam eder.
                // Aradaki HER dikey boşluk (alıntı kutusu, gönderen satırı)
                // birleşik şeklin o boşluğu da doldurmasına yol açıyordu —
                // kullanıcının "alıntılar bozuk" dediği hata buydu. Artık
                // grup orada kesiliyor.
                if (memberCount >= 2 && tops[memberCount - 1] - bottoms[memberCount - 2] > 1f) {
                    memberCount--
                    break
                }
                cursor++
                cursorPosition++
                if (moved) break
                if (!adapter.isGroupedWithNextPublic(cursorPosition - 1)) break
            }
            val isMine = adapter.isMineAt(position)
            paint.shader = if (isMine) mineShader else theirsShader
            if (memberCount >= 2) {
                buildUnionPath(isMine, outer, inner)
                canvas.drawPath(path, paint)
            } else if (memberCount == 1) {
                // TEK balonlar da artık burada çiziliyor. Eskiden kendi
                // drawable arka planlarını kullanıyorlardı, ama bir drawable
                // yalnızca kendi sınırlarını bilir — listenin tamamına
                // gerilmiş gradyandan kendi payına düşen dilimi alamaz.
                // Hepsini tek yerden çizmek, gruplu ve tekli balonların
                // AYNI gradyanı paylaşmasını da garantiliyor.
                buildSinglePath(isMine, outer)
                canvas.drawPath(path, paint)
            }
            paint.shader = null
            if (memberCount >= 1) {
                // Bu turda `position .. position + memberCount - 1` boyandı.
                drawnThroughPosition = position + memberCount - 1
            }
            index = if (cursor > index) cursor else index + 1
        }
    }

    /** Balonun sınırlarını tamponlara yazar; bulunamazsa `false`. */
    private fun collectBubble(itemView: View): Boolean {
        val bubble = bubbleOf(itemView) ?: return false
        var offsetX = 0f
        var offsetY = 0f
        var node: View = bubble
        while (node !== itemView) {
            offsetX += node.left
            offsetY += node.top
            node = node.parent as? View ?: return false
        }
        if (memberCount == tops.size) grow()
        val left = itemView.left + itemView.translationX + offsetX
        val top = itemView.top + itemView.translationY + offsetY
        tops[memberCount] = top
        bottoms[memberCount] = top + bubble.height
        lefts[memberCount] = left
        rights[memberCount] = left + bubble.width
        widths[memberCount] = bubble.width.toFloat()
        memberCount++
        return true
    }

    private fun grow() {
        val size = tops.size * 2
        tops = tops.copyOf(size)
        bottoms = bottoms.copyOf(size)
        widths = widths.copyOf(size)
        lefts = lefts.copyOf(size)
        rights = rights.copyOf(size)
    }

    /** `findViewById` kare başına HER çocuk için çağrılıyordu — sonuç artık
     *  satırın kendi `tag`'inde; görünüm geri dönüştürülse bile o satırın
     *  `layoutBubble`'ı aynı örnek kalır. */
    private fun bubbleOf(itemView: View): View? {
        (itemView.getTag(R.id.layoutBubble) as? View)?.let { return it }
        val found = itemView.findViewById<View>(R.id.layoutBubble) ?: return null
        itemView.setTag(R.id.layoutBubble, found)
        return found
    }

    /**
     * Gradyan shader'ları — yalnızca listenin yüksekliği ya da tema renkleri
     * değiştiğinde yeniden kuruluyor (her karede `LinearGradient` üretmek
     * gereksiz tahsis olurdu).
     *
     * Üst uç: temel rengin beyaza doğru harmanlanmış hâli (kullanıcı "en
     * üstteki balonlar daha AÇIK" dedi). Alt uç: temel rengin kendisi
     * ("alttakiler şu anki renginde").
     */
    private fun ensureShaders(height: Int, mineColor: Int, theirsColor: Int) {
        if (height <= 0) return
        if (height == shaderHeight && mineColor == shaderMine && theirsColor == shaderTheirs) return
        shaderHeight = height
        shaderMine = mineColor
        shaderTheirs = theirsColor
        val lightMine = androidx.core.graphics.ColorUtils.blendARGB(mineColor, android.graphics.Color.WHITE, 0.30f)
        val lightTheirs = androidx.core.graphics.ColorUtils.blendARGB(theirsColor, android.graphics.Color.WHITE, 0.24f)
        mineShader = android.graphics.LinearGradient(
            0f, 0f, 0f, height.toFloat(), lightMine, mineColor, android.graphics.Shader.TileMode.CLAMP
        )
        theirsShader = android.graphics.LinearGradient(
            0f, 0f, 0f, height.toFloat(), lightTheirs, theirsColor, android.graphics.Shader.TileMode.CLAMP
        )
    }

    /**
     * Gruplanmamış TEK bir balonun yolu — `bubble_mine`/`bubble_theirs`
     * drawable'larıyla aynı geometri (üç köşe yuvarlak, "kuyruk" köşesi
     * küçük), ama gradyanla doldurulabilmesi için `Path` olarak.
     */
    private val singleRadii = FloatArray(8)

    private fun buildSinglePath(isMine: Boolean, outer: Float) {
        path.reset()
        val top = tops[0]
        val bottom = bottoms[0]
        val left = lefts[0]
        val right = rights[0]
        val r = minOf(outer, (bottom - top) / 2f, (right - left) / 2f)
        // Kuyruk köşesi: kendi mesajlarımızda alt-sağ, gelenlerde alt-sol.
        val tail = r * 0.22f
        scratch.set(left, top, right, bottom)
        // reused array, no allocation per frame.
        val radii = singleRadii
        radii[0] = r; radii[1] = r; radii[2] = r; radii[3] = r
        radii[4] = if (isMine) tail else r; radii[5] = radii[4]
        radii[6] = if (isMine) r else tail; radii[7] = radii[6]
        path.addRoundRect(scratch, radii, Path.Direction.CW)
    }

    /**
     * Grubun birleşik dış hattını üretir.
     *
     * Yol, "u uzayında" kuruluyor: `u = hizalı kenardan yatay uzaklık`,
     * değişken kenara doğru büyüyor. Böylece kendi mesajlarımız (sağa
     * yaslı) ile gelen mesajlar (sola yaslı) için TEK bir geometri var;
     * aynalama en sonda bir `Matrix` ile yapılıyor. Bunu koordinatların
     * içinde elle yapmayı denedim ve her yayın işaretini ayrı ayrı ters
     * çevirmek gerekiyordu — matris, o hata sınıfını tamamen ortadan
     * kaldırıyor.
     *
     * Hizalı kenar baştan sona düz; yalnızca en üst ve en alt köşesi
     * yuvarlak. Değişken kenarda her genişlik değişiminde İKİ köşe var:
     * biri dışbükey (sıradan yuvarlatma), biri İÇBÜKEY fileto — kullanıcının
     * çizimindeki ayırt edici detay.
     */
    private fun buildUnionPath(isMine: Boolean, outer: Float, inner: Float) {
        path.reset()
        val top = tops[0]
        val bottom = bottoms[memberCount - 1]
        // Yarıçaplar balonun kendisinden büyük olamaz — kısa/dar bir balonda
        // (ör. tek emoji) yay, dikdörtgenin dışına taşıp şekli kendi üstüne
        // katlardı.
        var minHeight = Float.MAX_VALUE
        var minWidth = Float.MAX_VALUE
        var flushLeft = Float.MAX_VALUE
        var flushRight = -Float.MAX_VALUE
        for (i in 0 until memberCount) {
            val h = bottoms[i] - tops[i]
            if (h < minHeight) minHeight = h
            if (widths[i] < minWidth) minWidth = widths[i]
            if (lefts[i] < flushLeft) flushLeft = lefts[i]
            if (rights[i] > flushRight) flushRight = rights[i]
        }
        // The path measures every member from ONE aligned edge. A bubble with
        // a reaction pill or seen avatars beside it starts further in, and its
        // background was drawn shifted: the first ~20 dp of text had none.
        for (i in 0 until memberCount) {
            widths[i] = if (isMine) flushRight - lefts[i] else rights[i] - flushLeft
        }
        val outerR = minOf(outer, minHeight / 2f, minWidth / 2f)
        path.moveTo(outerR, top)
        path.lineTo(widths[0] - outerR, top)
        corner(widths[0] - outerR, top + outerR, outerR, -90f, 90f)   // üst dış köşe

        for (i in 0 until memberCount) {
            val current = widths[i]
            if (i == memberCount - 1) {
                path.lineTo(current, bottom - outerR)
                corner(current - outerR, bottom - outerR, outerR, 0f, 90f)  // alt dış köşe
                break
            }
            val junction = bottoms[i]
            val next = widths[i + 1]
            // Basamak küçükse iki yarıçap da ona göre kısılır; aksi halde
            // birkaç piksellik bir genişlik farkında yaylar birbirinin
            // üstüne binip düğüm oluşturuyordu.
            val step = kotlin.math.abs(next - current)
            val stepOuter = minOf(outerR, step / 2f)
            val stepInner = minOf(inner, step / 2f)
            when {
                next > current + 0.5f -> {
                    // Dar -> geniş: içbükey fileto ile dışa aç.
                    path.lineTo(current, junction - stepInner)
                    corner(current + stepInner, junction - stepInner, stepInner, 180f, -90f)
                    path.lineTo(next - stepOuter, junction)
                    corner(next - stepOuter, junction + stepOuter, stepOuter, -90f, 90f)
                }
                next < current - 0.5f -> {
                    // Geniş -> dar: önce dışbükey köşe, sonra içbükey fileto.
                    path.lineTo(current, junction - stepOuter)
                    corner(current - stepOuter, junction - stepOuter, stepOuter, 0f, 90f)
                    path.lineTo(next + stepInner, junction)
                    corner(next + stepInner, junction + stepInner, stepInner, -90f, -90f)
                }
                // Aynı genişlik: kesintisiz düz kenar, köşe YOK.
            }
        }

        path.lineTo(outerR, bottom)
        corner(outerR, bottom - outerR, outerR, 90f, 90f)   // alt hizalı köşe
        path.lineTo(0f, top + outerR)
        corner(outerR, top + outerR, outerR, 180f, 90f)     // üst hizalı köşe
        path.close()

        // u uzayından ekran koordinatlarına.
        matrix.reset()
        if (isMine) {
            // Sağa yaslı: u, sağ kenardan SOLA doğru ölçülüyor.
            matrix.setScale(-1f, 1f)
            matrix.postTranslate(flushRight, 0f)
        } else {
            matrix.setTranslate(flushLeft, 0f)
        }
        path.transform(matrix)
    }

    /**
     * Merkezi ve açıları AÇIKÇA verilen çeyrek yay.
     *
     * Merkezi uç noktalardan "tahmin etmeyi" denedim ve çalışmadı: iki uçtan
     * eşit uzaklıkta İKİ aday merkez var ve hangisinin seçildiği, köşenin
     * dışbükey mi içbükey mi çizileceğini belirliyor. Yani tahmin, tam da
     * bu şeklin can alıcı ayrımını rastgele bırakıyordu. Artık her köşe
     * kendi merkezini ve dönüş yönünü (`sweep`'in işareti) veriyor:
     * pozitif = saat yönü (dışbükey), negatif = ters (içbükey fileto).
     */
    private fun corner(cx: Float, cy: Float, radius: Float, startAngle: Float, sweep: Float) {
        scratch.set(cx - radius, cy - radius, cx + radius, cy + radius)
        path.arcTo(scratch, startAngle, sweep)
    }
}
